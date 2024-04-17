#include "vmlinux.h"
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h>
#include  <errno.h>

char __license[] SEC("license") = "Dual MIT/GPL";

enum setting {INODE, DEV};

// Settings regarding the host system are stored in this map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(enum setting));
    __uint(value_size, sizeof(u64));
} settings SEC(".maps");



// This bpf security module is called upon the chroot syscall.
// This syscall may be used to escape a running container in cases where
// a rootful container is run. This is a real risk, since this is the
// default for Docker and other containerization tools.
SEC("lsm/path_chroot")
int BPF_PROG(lsm_no_chroot_to_root, const struct path *path, int ret) {
    // ret is the return value from the previous BPF program
    //or 0 if it's the first hook.
    if (ret != 0) {
        return ret;
    }

    const int CFG_INODE = 0;
    u64 *host_inode = (u64 *)bpf_map_lookup_elem(&settings, &CFG_INODE);
    if (!host_inode) {
        return 0;
    }
    const int CFG_DEV = 1;
    u64 *host_dev = (u64 *)bpf_map_lookup_elem(&settings, &CFG_DEV);
    if (!host_dev) {
        return 0;
    }
 
    // retrieve pid_tgid info of current namespace
    // -> this will fail within a container, due to the fact that we're using device and inode information from the host's file system
    // -> invoking chroot outside of a container will still work, because pids will match
    struct bpf_pidns_info pidnsinfo = {0};
    bpf_get_ns_current_pid_tgid(*host_dev, *host_inode, &pidnsinfo, sizeof(pidnsinfo));

    u32 current_pid = (bpf_get_current_pid_tgid() >> 32);
    if (current_pid != pidnsinfo.pid && !path->mnt->mnt_root->d_iname[2] && __builtin_memcmp("/", path->mnt->mnt_root->d_iname, 1) == 0) {
        return -EPERM;
    }
    return 0;

}