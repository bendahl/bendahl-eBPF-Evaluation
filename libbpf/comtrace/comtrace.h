#ifndef COMTRACE_H
#define COMTRACE_H

// C++ standard library headers
#include <iostream>
#include <fstream>
#include <chrono>

// external dependencies
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <CLI/CLI.hpp>
#include<unistd.h>

// generated headers
#include "comtrace.skel.h"

#include "common_types.h"

// connection tuple consisting of source and target ip and port
struct connection {
    std::string saddr;
    std::string daddr;
    uint16_t sport;
    uint16_t dport;
};

// connection meta data that is unique to each connection
struct connectionMeta {
    uint32_t pid;
    std::string comm;
    uint64_t bytesReceived;
    uint64_t bytesSent;
    uint64_t startTs;
    uint64_t endTs;
};

// override '<' operator in order to make connections comparable
bool operator<(const connection& a, const connection& b) {
    return (a.saddr < b.saddr || a.daddr < b.daddr || a.sport < b.sport || a.dport < b.dport);
}

// tcp states
enum tcpState {
    tcpEstablished = 1,
    tcpSynSent,
    tcpSynRecv,
    tcpFinWait1,
    tcpFinWait2,
    tcpTimeWait,
    tcpClose,
    tcpCloseWait,
    tcpLastAck,
    tcpListen,
    tcpClosing,
    tcpNewSynRecv,
};

// ipToStr converts a given ip_type as used in BPF code to a string
std::string ipToStr(ip_type ip) {
    std::string ipStr;
    if (ip.family == AF_INET) {
        char tmpIpStr[INET_ADDRSTRLEN] = {0};
        inet_ntop(ip.family, &ip.ip.ipv4, tmpIpStr, INET_ADDRSTRLEN);
        ipStr = tmpIpStr;
    } else {
        char tmpIpStr[INET6_ADDRSTRLEN] = {0};
        inet_ntop(ip.family, &ip.ip.ipv6, tmpIpStr, INET6_ADDRSTRLEN);
        ipStr = tmpIpStr;
    }
    return ipStr;
}

// handle event updates the connection cache upon receiving events from the BPF program
int handleEvent(void *ctx, void *data, size_t data_sz) {
    auto event = static_cast<tcp_event *>(data);
    auto connections = static_cast<std::map<connection, connectionMeta>*>(ctx);
    if(event->lport == 0) {
        // ignore local-port == 0
        return 0;
    }
    auto key = connection {
        .saddr = ipToStr(event->saddr),
        .daddr = ipToStr(event->daddr),
        .sport = event->lport,
        .dport = event->dport
    };
    connectionMeta meta = {};
    if (connections->count(key) != 0) {
        meta = connections->at(key);
        meta.endTs = event->tstamp;
        meta.bytesReceived = event->bytes_received;
        meta.bytesSent = event->bytes_sent;
        if(event->newstate == tcpSynSent || event->newstate == tcpFinWait1 || event->newstate == tcpLastAck) {
            meta.pid = event->pid;
            meta.comm = event->comm;
        }
    } else {
        meta = connectionMeta {
                .pid = 0,
                .comm = "",
                .bytesReceived = event->bytes_received,
                .bytesSent = event->bytes_sent,
                .endTs = event->tstamp
        };
        // only update startTs if this is a newly opened connection
        // otherwise, we do not know how long this has been opened for
        if(event->newstate < tcpFinWait1) {
            meta.startTs = event->tstamp;
        }
    }

    connections->insert_or_assign(key, meta);

    return 0;
}


#endif //COMTRACE_H
