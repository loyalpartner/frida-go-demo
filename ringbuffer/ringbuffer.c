//go:build ignore

#include "common.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  u32 pid;
  u8 comm[TASK_COMM_LEN];
  u8 type; // 0 for execve, 1 for exit
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 1 << 24);
  __type(value, struct event);
} events SEC(".maps");

SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx) {
  struct event event = {0};

  event.pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  event.type = 1; // exit

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(
    struct trace_event_raw_sched_process_exec *ctx) {
  struct event event = {0};

  event.pid = bpf_get_current_pid_tgid() >> 32;

  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  event.type = 0; // execve

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

  return 0;
}
