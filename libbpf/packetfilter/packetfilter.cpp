/*
    This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
    The configuration is done via a yaml-file.
    Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/
#include "packetfilter.h"
#include <iostream>

// This is the main entrypoint to the program
int main() {
    // Read config file
    std::cout << "Starting packet filter" << std::endl;

    auto cfg = readConfigFile();
    // Load BPF program
    auto skel = packetfilter_bpf__open_and_load();
    if (!skel) {
        std::cerr << "failed to open BPF skeleton" << std::endl; 
        return 1;
    }

    // get configured network interface 
    auto getIfResult = getNetworkInterfaceByName(cfg.rules.interface);
    if (!getIfResult.has_value()) {
        std::cerr << "no matching interface found for given interface name \"" << cfg.rules.interface << "\"" << std::endl;
        return 1;
    }
    // attach BPF program to nic
    auto link = bpf_program__attach_xdp(skel->progs.xdp_prog_func, getIfResult.value());
    if (!link) {
        std::cout << "failed to create xdp link" << std::endl;
        return 1;
    }

    // apply ip filter rules
    setIPConfigs(skel, cfg);

    // initialize ring buffer to process incoming events
    auto rb = ring_buffer__new(bpf_map__fd(skel->maps.processed_packets), handlePacketEvent, nullptr, nullptr);
    if (!rb) {
        std::cout << "failed to create ringbuffer" << std::endl;
        return 1;
    }

    // process packets until termination signal is received
    std::cout << "Running packetfilter. Press <CTRL><C> to stop execution." << std::endl;
    while (true) {
        // see https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c for reference
        auto err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            std::cout << "error pulling ringbufffer: " << err << std::endl;
            break;
        }
    }
    
    return 0;
}

