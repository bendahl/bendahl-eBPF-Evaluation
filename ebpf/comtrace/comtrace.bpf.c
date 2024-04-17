//go:build ignore
// This example is heavily inspired by Brendan Gregg and his BCC program tcplife
// See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
// See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

struct ip_type {
    __u16 family;
    union {
        __u8 ipv6[16];
        __u8 ipv4[4];
    } ip;
};

// event structure used to push events to userspace
struct tcp_event {
    __u64 ip;
    __u32 pid;
    struct ip_type saddr;
    struct ip_type daddr;
    __u16 lport;
    __u16 dport;
    int newstate;
    int oldstate;
    char comm[TASK_COMM_LEN];
    __u64 bytes_received;
    __u64 bytes_sent;
    __u64 tstamp;
};

// ring buffer to communicate tcp events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096 * 64);
} ip_events SEC(".maps");



// force BTF generation
struct tcp_event *unused_ipv4_data_t __attribute__((unused));

// get process id of current process
static __always_inline __u32 get_current_pid() {
    __u64 id = bpf_get_current_pid_tgid();
	return id >> 32;
}

// kernel data structure as it is passed to the BPF program via the context
struct inet_sock_set_state {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

// Userspace pathname: /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct inet_sock_set_state *sk_state) {
    if(!sk_state) {
        return 0;
    }
    struct tcp_sock *sk = (struct tcp_sock*)sk_state->skaddr;

    // reserve memory in ringbuffer
    struct tcp_event *buf = {0};
    buf = bpf_ringbuf_reserve(&ip_events, sizeof(struct tcp_event), 0);
    if (!buf) {
        bpf_printk("tracepoint/skb/consume_skb: failed to reserve memory in ringbuf");
        return 0;
    }

    bpf_probe_read(&buf->daddr.family, sizeof(buf->daddr.family), &sk_state->family);
    bpf_probe_read(&buf->saddr.family, sizeof(buf->saddr.family), &sk_state->family);
    
    if (sk_state->family == AF_INET) {
        bpf_probe_read(buf->saddr.ip.ipv4, sizeof(buf->saddr.ip.ipv4), &sk_state->saddr);
        bpf_probe_read(buf->daddr.ip.ipv4, sizeof(buf->daddr.ip.ipv4), &sk_state->daddr);
    } else {
        bpf_probe_read(buf->saddr.ip.ipv6, sizeof(buf->saddr.ip.ipv6), &sk_state->saddr_v6);
        bpf_probe_read(buf->daddr.ip.ipv6, sizeof(buf->daddr.ip.ipv6), &sk_state->daddr_v6);
    }

    bpf_probe_read(&buf->dport, sizeof(buf->dport), &sk_state->dport);
    bpf_probe_read(&buf->lport, sizeof(buf->lport), &sk_state->sport);
    bpf_probe_read(&buf->oldstate, sizeof(buf->newstate), &sk_state->oldstate);
    bpf_probe_read(&buf->newstate, sizeof(buf->newstate), &sk_state->newstate);
    bpf_probe_read(&buf->bytes_received, sizeof(buf->bytes_received), &sk->bytes_received);
    bpf_probe_read(&buf->bytes_sent, sizeof(buf->bytes_sent), &sk->bytes_sent);
    buf->tstamp = bpf_ktime_get_ns();

    buf->pid = get_current_pid();
    bpf_get_current_comm(buf->comm, sizeof(buf->comm));

    // submit tcp event to ringbuffer
    bpf_ringbuf_submit(buf, 0);

    return 0;
}