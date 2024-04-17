
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */

// shared datatypes that are shared between user- and kernelspace
#include "common_types.h" 

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_P_IP  0x0800
#define ETH_P_IP6 0x86dd

// default configurations for IPv4 and IPv6 packets
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(enum ip_type));
	__uint(value_size, sizeof(bool));
} default_config SEC(".maps");

// IPv4 block-/allow-list
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, bool);
} ip4_rules SEC(".maps");

// IPv6 block-/allow-list
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, bool);
} ip6_rules SEC(".maps");

// packets that were passed on
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} processed_packets SEC(".maps");


// force BTF generation
struct in6_addr *unused_in6_addr __attribute__((unused));
struct src_ip_type *unused_src_ip_type __attribute__((unused));
enum xdp_action *unused_xdp_action __attribute__((unused));

/*
 Parts of this function were taken from the ebpf project example repository.
 See the original version here: https://github.com/cilium/ebpf/blob/7fb0b5681c1a17a3fb20413d9ab048f95b700b7e/examples/xdp/xdp.c
 Minor modifications were applied in order to get rid of header dependencies.

 Attempt to parse the IPv4 source address from the packet.
 Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, struct src_ip_type *ip_src_addr) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    // check whether we're dealing with an IP packet (either IPv4 or IPv6)
    // ignore packet (stop processing) if it's not an IP packet
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP) && eth->h_proto != __builtin_bswap16(ETH_P_IP6)) {
        return 0;
    }

    // Return the source IP address in network byte order.
    if (eth->h_proto == __builtin_bswap16(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return 0;
        }
        ip_src_addr->type = IPV4;
        ip_src_addr->ip.ipv4 = (__u32)(ip->saddr);
    } else {
        struct ipv6hdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return 0;
        }
        ip_src_addr->type = IPV6;
        ip_src_addr->ip.ipv6 = ip->saddr;
    }
    return 1;
}

// ip_is_allowed checks whether a given IP should be allowed to pass or not according to the given rules.
// It returns 'true' if packet may pass, 'false' otherwise.
static __always_inline bool ip_is_allowed(struct src_ip_type *ip_src_addr) {
    if(ip_src_addr->type == IPV4) {
        bool *ipv4default = (bool *)bpf_map_lookup_elem(&default_config, &ip_src_addr->type);
        bool *ipv4rule = (bool *)bpf_map_lookup_elem(&ip4_rules, &ip_src_addr->ip.ipv4);

        // explicitly blocked
        if(ipv4rule && !*ipv4rule) {
            ip_src_addr->passed = false;
            return false;
        }

        // explicitly allowed
        if(ipv4rule && *ipv4rule) {
            ip_src_addr->passed = true;
            return true;
        }

        // apply default
        if(ipv4default && *ipv4default) {
            ip_src_addr->passed = true;
            return true;
        }

        ip_src_addr->passed = false;
        return false;
    } else {
        bool *ipv6default = (bool *)bpf_map_lookup_elem(&default_config, &ip_src_addr->type);
        bool *ipv6rule = (bool *)bpf_map_lookup_elem(&ip6_rules, &ip_src_addr->ip.ipv6);

        // explicitly blocked
        if(ipv6rule && !*ipv6rule) {
            ip_src_addr->passed = false;
            return false;
        }

        // explicitly allowed
        if(ipv6rule && *ipv6rule) {
            ip_src_addr->passed = true;
            return true;
        }

        // apply default
        if(ipv6default && *ipv6default) {
            ip_src_addr->passed = true;
            return true;
        }
        ip_src_addr->passed = false;
        return false;
    }
}

// This is the main entrypoint of the program
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    // parse packet and check whether it is an IP packet
    struct src_ip_type src_ip;
    if (!parse_ip_src_addr(ctx, &src_ip)) {
        // Not an IP packet, so ignore it.
        return XDP_PASS;
    }

    // check if packet is allowed to pass
    enum xdp_action action = XDP_DROP;
    if (ip_is_allowed(&src_ip)) {
        action = XDP_PASS;
    }

    // allocate buffer in ring buffer
    struct src_ip_type *ipbuf = {0};
    ipbuf = bpf_ringbuf_reserve(&processed_packets, sizeof(struct src_ip_type), 0);

    // submit message to ring buffer if sufficient memory could be allocated
    if (!ipbuf) {
        bpf_printk("xdp-probe: Failed to reserve memory in ringbuffer. Skipping message.");
    } else {
        bpf_probe_read_kernel(ipbuf, sizeof(struct src_ip_type), &src_ip);
        bpf_ringbuf_submit(ipbuf, 0);
    }


    return action;
}
