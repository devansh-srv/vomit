#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// pref structs
struct syscall_perf {
  u32 pid;
  u32 tid;
  char comm[16];
  u64 syscall_id;
  u64 duration_ns;
  u64 timestamp;
};

struct io_perf {
  u32 pid;
  char comm[16];
  u64 bytes;
  u64 latency_ns;
  u64 timestamp;
  u8 operation;
};

struct cpu_sample {
  u32 pid;
  char comm[16];
  u32 cpu_id;
  u64 timestamp;
};

// bpf maps -> storing states

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,
         256 * 1024); // this must be 4096k (getconf PAGESIZE)
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, u64);
} syscall_start SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u64);
  __type(value, u64);
} io_start SEC(".maps");

// tracing syscalls
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid(); // first 32 bits are tgid and
  u32 pid = pid_tgid >> 32;                  // next 32 bits are pid
  u64 start_timestamp = bpf_ktime_get_ns();
  bpf_map_update_elem(&syscall_start, &pid, &start_timestamp, BPF_ANY);
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;
  u64 *start_timestamp = bpf_map_lookup_elem(&syscall_start, &pid);
  if (!start_timestamp)
    return 0;

  u64 duration = bpf_ktime_get_ns() - (*start_timestamp);
  bpf_map_delete_elem(&syscall_start, &pid);
  if (duration < 1000000)
    return 0;
  struct syscall_perf *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }
  e->pid = pid;
  e->tid = tid;
  e->timestamp = bpf_ktime_get_ns();
  e->duration_ns = duration;
  e->syscall_id = ctx->id;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// tracing IO operations
SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq) {
  u64 start = bpf_ktime_get_ns();
  u64 req = (u64)rq;
  bpf_map_update_elem(&io_start, &req, &start, BPF_ANY);
  return 0;
}
SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq) {
  u64 req = (u64)rq;
  u64 *start = bpf_map_lookup_elem(&io_start, &req);
  if (!start)
    return 0;
  u64 latency = bpf_ktime_get_ns() - (*start);
  bpf_map_delete_elem(&io_start, &req);
  if (latency < 10000000)
    return 0;
  struct io_perf *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  e->pid = pid_tgid >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->latency_ns = latency;
  e->bytes = BPF_CORE_READ(rq, __data_len);
  e->operation = (BPF_CORE_READ(rq, cmd_flags) & REQ_OP_WRITE) ? 1 : 0;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// CPU profiling
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  struct cpu_sample *e;
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  e->pid = pid_tgid >> 32;
  e->timestamp = bpf_ktime_get_ns();
  e->cpu_id = bpf_get_smp_processor_id();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// read write syscalls detailed monitoring
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
  bpf_printk("read() called by pid %d\n", bpf_get_current_pid_tgid() >> 32);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {

  bpf_printk("write() called by pid %d\n", bpf_get_current_pid_tgid() >> 32);
  return 0;
}
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_printk("Process %s executed\n", comm);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
