//go:build ignore

#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

#include "headers/common.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

char __license[] SEC("license") = "Dual MIT/GPL";

struct sockaddr_in {
	u16           sin_family;
	__be16        sin_port;
	__be32        sin_addr;
	unsigned char sin_zero[8];
};

struct conn_info {
	u64 start_ts;
	u32 daddr;
	u16 dport;
	u16 pad;
};

struct tcp_event {
	u64 duration_ns;
	u32 pid;
	u32 daddr;
	u16 dport;
	s16 ret_val;
	u8  comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct conn_info);
} start_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct tcp_event);
} tcp_events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct conn_info info = {};
	info.start_ts = bpf_ktime_get_ns();

	void *uaddr_ptr = (void *)PT_REGS_PARM2(ctx);
	if (uaddr_ptr) {
		struct sockaddr_in uaddr = {};
		if (bpf_probe_read_kernel(&uaddr, sizeof(uaddr), uaddr_ptr) == 0) {
			info.daddr = uaddr.sin_addr;
			info.dport = bpf_ntohs(uaddr.sin_port);
		}
	}

	bpf_map_update_elem(&start_map, &pid_tgid, &info, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct conn_info *info = bpf_map_lookup_elem(&start_map, &pid_tgid);
	if (!info) {
		return 0;
	}

	u64 duration_ns = bpf_ktime_get_ns() - info->start_ts;
	long ret = PT_REGS_RC(ctx);

	struct tcp_event *ev = bpf_ringbuf_reserve(&tcp_events, sizeof(struct tcp_event), 0);
	if (ev) {
		ev->duration_ns = duration_ns;
		ev->pid = (u32)(pid_tgid >> 32);
		ev->daddr = info->daddr;
		ev->dport = info->dport;
		ev->ret_val = (s16)ret;
		bpf_get_current_comm(&ev->comm, TASK_COMM_LEN);
		bpf_ringbuf_submit(ev, 0);
	}

	bpf_map_delete_elem(&start_map, &pid_tgid);
	return 0;
}
