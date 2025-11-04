#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define COMM_LEN 16
#define HASH_MAX 10240
#define MAX_STACK_DEPTH 20

// capturing metadata about slow events
struct event {
  u64 timestamp_ns;
  u32 tgid;
  u32 pid;
  u64 duration_ns;
  u64 size; // payload size for I/O operations
  char comm[COMM_LEN];
  char operation[32];
  u32 kernel_stack_id;
  u32 user_stack_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, HASH_MAX);
  __type(key, u64);
  __type(value, u64);
} start_times SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, 1000);
  __uint(key_size, sizeof(u32));
  __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

static __always_inline void send_event(struct pt_regs *ctx, const char *op,
                                       u64 duration, u64 size) {
  if (duration < 5000000)
    return;

  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  e->timestamp_ns = bpf_ktime_get_ns();
  e->tgid = pid_tgid >> 32;
  e->pid = pid_tgid & 0xFFFFFFFF;

  e->duration_ns = duration;
  __builtin_memcpy(e->operation, op, 32);
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  e->size = size;
  if (ctx) {

    e->kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    e->user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
  } else {
    e->kernel_stack_id = -1;
    e->user_stack_id = -1;
  }

  bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/vfs_read")
int trace_read_enter(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &id, &ts, BPF_ANY);
  return 0;
}

SEC("kretprobe/vfs_read")
int trace_read_exit(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u64 *start_ts = bpf_map_lookup_elem(&start_times, &id);
  if (!start_ts)
    return 0;
  u64 duration = bpf_ktime_get_ns() - (*start_ts);
  s64 size = (s64)PT_REGS_RC(ctx);
  send_event(ctx, "read", duration, size > 0 ? size : 0);
  bpf_map_delete_elem(&start_times, &id);
  return 0;
}

SEC("kprobe/vfs_write")
int trace_write_enter(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &id, &ts, BPF_ANY);
  return 0;
}

SEC("kretprobe/vfs_write")
int trace_write_exit(struct pt_regs *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u64 *start_ts = bpf_map_lookup_elem(&start_times, &id);
  if (!start_ts)
    return 0;
  u64 duration = bpf_ktime_get_ns() - (*start_ts);
  s64 size = (s64)PT_REGS_RC(ctx);
  send_event(ctx, "write", duration, size > 0 ? size : 0);
  bpf_map_delete_elem(&start_times, &id);
  return 0;
}

// blocking I/O
SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_io_start, struct request *rq) {
  u64 req = (u64)rq;
  u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&start_times, &req, &ts, BPF_ANY);
  return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_io_end, struct request *rq) {
  u64 req = (u64)rq;
  u64 *start_ts = bpf_map_lookup_elem(&start_times, &req);
  if (!start_ts)
    return 0;
  u64 duration = bpf_ktime_get_ns() - (*start_ts);
  u64 bytes = BPF_CORE_READ(rq, __data_len);

  send_event(NULL, "disk_io", duration, bytes);
  bpf_map_delete_elem(&start_times, &req);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
