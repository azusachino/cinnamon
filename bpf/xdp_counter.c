//go:build ignore

#include "headers/common.h"
#include "headers/bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PROTO_OTHER 0
#define PROTO_TCP   1
#define PROTO_UDP   2
#define PROTO_ICMP  3
#define PROTO_MAX   4

struct pkt_stats {
	__u64 packets;
	__u64 bytes;
};

// Protocol statistics array: index corresponds to PROTO_* constants
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PROTO_MAX);
	__type(key, __u32);
	__type(value, struct pkt_stats);
} proto_stats_map SEC(".maps");

// Top source IP map (LRU hash to automatically prune old entries)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); // IPv4 in network byte order
	__type(value, struct pkt_stats);
} src_ip_map SEC(".maps");

SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 pkt_len = (__u64)(data_end - data);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		__u32 proto_key = PROTO_OTHER;
		struct pkt_stats *s = bpf_map_lookup_elem(&proto_stats_map, &proto_key);
		if (s) {
			__sync_fetch_and_add(&s->packets, 1);
			__sync_fetch_and_add(&s->bytes, pkt_len);
		}
		return XDP_PASS;
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	__u32 proto_key = PROTO_OTHER;
	if (ip->protocol == 6) {        // IPPROTO_TCP
		proto_key = PROTO_TCP;
	} else if (ip->protocol == 17) { // IPPROTO_UDP
		proto_key = PROTO_UDP;
	} else if (ip->protocol == 1) {  // IPPROTO_ICMP
		proto_key = PROTO_ICMP;
	}

	struct pkt_stats *s = bpf_map_lookup_elem(&proto_stats_map, &proto_key);
	if (s) {
		__sync_fetch_and_add(&s->packets, 1);
		__sync_fetch_and_add(&s->bytes, pkt_len);
	}

	__u32 src_ip = ip->saddr;
	struct pkt_stats *src_stats = bpf_map_lookup_elem(&src_ip_map, &src_ip);
	if (!src_stats) {
		struct pkt_stats init_stats = { .packets = 1, .bytes = pkt_len };
		bpf_map_update_elem(&src_ip_map, &src_ip, &init_stats, BPF_ANY);
	} else {
		__sync_fetch_and_add(&src_stats->packets, 1);
		__sync_fetch_and_add(&src_stats->bytes, pkt_len);
	}

	return XDP_PASS;
}
