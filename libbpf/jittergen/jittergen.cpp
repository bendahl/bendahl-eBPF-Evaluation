#include "jittergen.h"

// This is the main entrypoint to the program
int main() {
    // Read config file
    std::cout << "Starting jittergen" << std::endl;

    // read and parse configuration file
    auto cfg = readConfigFile();
    // Load BPF program
    auto skel = jittergen_bpf__open_and_load();
    if (!skel) {
        std::cerr << "failed to open BPF skeleton" << std::endl;
        return 1;
    }
    auto getIfResult = getNetworkInterfaceByName(cfg.outIf);
    if (!getIfResult.has_value()) {
        std::cerr << "no matching interface found for given interface name \"" << cfg.outIf << "\"" << std::endl;
        return 1;
    }

    // add parent qdisc that honors the skb->tstamp field for sending (egress side) -> in this case FQ (fair queue)
    // original state of qdiscs will be restored when the tchandler goes out of scope
    auto tchandler = std::make_unique<TcHandler>(cfg.outIf);

    // create TC hook on the egress path of the nic
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook,
                        .ifindex = getIfResult.value(), .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts,
                        .handle = 1, .priority = 1);
    auto err = bpf_tc_hook_create(&tc_hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        std::cout << "failed to create TC hook: " << err << std::endl;
        return 1;
    }

    // attach BPF program to the previously created hook
    tc_opts.prog_fd = bpf_program__fd(skel->progs.tc_jittergen);
    err = bpf_tc_attach(&tc_hook, &tc_opts);
    if (err) {
        std::cout << "failed to attach tc program: " << err << std::endl;
    }

    // initialize program settings
    initSettings(skel, cfg);
    
    // wait for keypress
    std::cout << "Press any key to stop execution." << std::endl;
    std::cin.get();

    return 0;
}