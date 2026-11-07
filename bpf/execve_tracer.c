//go:build ignore

#include "headers/common.h"
#include "headers/bpf_tracing.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct exec_event {
	u32 pid;
	u32 uid;
	u8  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MB ring buffer
	__type(value, struct exec_event);
} exec_events SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = (u32)(id >> 32);
	u32 uid = (u32)bpf_get_current_uid_gid();

	struct exec_event *ev = bpf_ringbuf_reserve(&exec_events, sizeof(struct exec_event), 0);
	if (!ev) {
		return 0;
	}

	ev->pid = pid;
	ev->uid = uid;
	bpf_get_current_comm(&ev->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
