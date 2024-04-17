/*
    This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
    Only TCP packets are handled by this program.
    As a load balancing algorithm, round robin is used.
*/
#include "loadbalancer.h"

// This is the main entrypoint to the program
int main() {
    // parse configuration file to struct
    auto cfg = readConfigFile();
    // Load BPF program
    auto skel = loadbalancer_bpf__open_and_load();
    if (!skel) {
        std::cerr << "failed to open BPF skeleton" << std::endl;
        return 1;
    }

    // get network interface id from its name
    auto getIfResult = getNetworkInterfaceByName(cfg.listenInterface);
    if (!getIfResult.has_value()) {
        std::cerr << "no matching interface found for given interface name \"" << cfg.listenInterface << "\"" << std::endl;
        return 1;
    }
    // attach XDP program to the given nic
    auto link = bpf_program__attach_xdp(skel->progs.xdp_loadbalancer, getIfResult.value());
    if (!link) {
        std::cout << "failed to create xdp link" << std::endl;
        return 1;
    }
    // initialize the BPF settings map
    initSettings(skel, cfg);

    // wait for keypress
    std::cout << "Running loadbalancer. Press any key to stop execution...";
    std::cin.get();
}