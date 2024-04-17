//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP  0x0800
#define ETH_P_IP6 0x86dd
#define IP_P_TCP  0x06

// current backend that packets should be sent to
static volatile unsigned char backend_idx = 0;

// define readable names for the setting applied on the userspace side
enum setting {PORT, NO_BACKENDS, OUT_IF};

// settings as provided by the user space program
// each parameter can be accessed via it's index (refer to enum setting above for a complete list of parameters)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(enum setting));
    __uint(value_size, sizeof(u16));
    __uint(max_entries, 3);
} settings SEC(".maps");

// backend list
// each backend is addressed solely by its mac address
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(unsigned char[6]));
    __uint(max_entries, 256);
} backends SEC(".maps");

// socket quadruple identifies a connection
// ports and ips are grouped in order to optimize alignment in memory
struct tcp_session {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// tcp session store
// LRU hash is used in order to prevent overflow of tcp session store
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct tcp_session));
    __uint(value_size, sizeof(unsigned char[6]));
    __uint(max_entries, 1024);
} sessions SEC(".maps");


// force BTF generation
struct tcp_session *unused_tcp_session __attribute__((unused));
// leads to compiler error due to illegal forward reference in C++ code
// enum setting *unused_setting __attribute__((unused));

SEC("xdp")
int xdp_loadbalancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // check whether we're dealing with an IP(v4) packet
    // ignore packet (stop processing) if it's not an IP(v4) packet
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return XDP_PASS;
    }

    // check ip header for validity
    struct iphdr *ip = (void *) (eth + 1);
    if ((void *) (ip + 1) > data_end) {
        // invalid packet -> ignore
        return XDP_PASS;
    }

    // check whether we're dealing with tcp, since we're only doing tcp-loadbalancing
    if (ip->protocol != IP_P_TCP) {
        return XDP_PASS;
    }
    
    // check tcp header for validity
    struct tcphdr *tcp = (void *) (ip + 1);
    if ((void *) (tcp + 1) > data_end) {
        // invalid packet -> ignore
        return XDP_PASS;
    }
    
    const int cfg_port = PORT;
    __be16 *listen_port = (__be16 *)bpf_map_lookup_elem(&settings, &cfg_port);
    if (!listen_port || (*listen_port != __builtin_bswap16(tcp->dest))) {
        return XDP_PASS;
    }

    const int cfg_no_backends = NO_BACKENDS;
    __be16 *no_backends = (__be16 *)bpf_map_lookup_elem(&settings, &cfg_no_backends);
    if (!no_backends) {
        return XDP_PASS;
    }

    const int cfg_out_if_nr = OUT_IF;
    __be16 *out_if = (__be16 *)bpf_map_lookup_elem(&settings, &cfg_out_if_nr);
    if (!out_if) {
        return XDP_PASS;
    }

    // build session key based on source and destination ip and port
    struct tcp_session session = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest
    };

    // chose backend to use
    unsigned char *backend_mac = (unsigned char *)bpf_map_lookup_elem(&sessions, &session);
    if (!backend_mac) {
        u32 idx = (u32)(backend_idx % *no_backends);
        backend_mac = (unsigned char *)bpf_map_lookup_elem(&backends, &idx);
        if (!backend_mac) {
            return XDP_PASS;
        }
        bpf_map_update_elem(&sessions, &session, backend_mac, 0);
        ++backend_idx;
    }

    // set chosen backend's mac as the new target
    __builtin_memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_source));
    __builtin_memcpy(eth->h_dest, backend_mac, sizeof(eth->h_dest));
    
    return bpf_redirect(*out_if, 0);
}
