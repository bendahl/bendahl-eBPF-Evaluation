#ifndef COMTRACE_COMMON_TYPES_H
#define COMTRACE_COMMON_TYPES_H

#define TASK_COMM_LEN 16

struct ip_type {
    __u16 family;
    union {
        __u8 ipv6[16];
        __u8 ipv4[4];
    } ip;
};

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


#endif //COMTRACE_COMMON_TYPES_H
