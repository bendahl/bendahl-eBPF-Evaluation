/*
    This program implements a simple Linux Security Module (LSM).
    It inhibits using chroot to the host's filesystem root in order 
    to prevent container escapes and privilege escalation.
*/


// C++ standard library headers
#include <iostream>

// external dependencies
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// generated headers
#include "lsmbpf.skel.h"

// get raw pointer to given value
template<typename T>
T *toPtr(T &&value) {
    return &value;
}

int main() {
    // Load BPF program
    auto skel = lsmbpf_bpf__open_and_load();
    if (!skel) {
        std::cerr << "failed to open BPF skeleton" << std::endl; 
        return 1;
    }

    // attach BPF program
    auto lsmlink = bpf_program__attach_lsm(skel->progs.lsm_no_chroot_to_root);
    if (!lsmlink) {
        std::cout << "failed to attach lsm program" << std::endl;
        return 1;
    }

    // based on the official man page of stat
    struct stat file_stat;
    if (stat("/proc/self/ns/pid", &file_stat) == -1) {
        std::cout << "failed to get file info for current pid ns" << std::endl;
        return 1;
    }

    // set BPF program parameters in settings map
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(0), &file_stat.st_ino, 0);
    bpf_map_update_elem(bpf_map__fd(skel->maps.settings), toPtr(1), &file_stat.st_dev, 0);

    // wait for keypress
    std::cout << "Running lsm bpf module. Press any key to stop execution." << std::endl;
    std::cin.get();
    
    return 0;
}

