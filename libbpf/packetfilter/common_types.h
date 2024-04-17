#ifndef PACKETFILTER_COMMON_TYPES_H
#define PACKETFILTER_COMMON_TYPES_H

enum ip_type {IPV4, IPV6};

struct src_ip_type {
    bool passed;
    enum ip_type type;
    union {
        struct in6_addr ipv6;
        __u32 ipv4;
    } ip;
};


#endif //PACKETFILTER_COMMON_TYPES_H