#![no_std]
#![no_main]
#![feature(core_intrinsics)]

use core::mem;

use aya_bpf::{
    bindings::bpf_pidns_info,
    cty::{c_int, c_ulong},
    helpers::{bpf_get_current_pid_tgid, bpf_get_ns_current_pid_tgid},
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
};

use crate::vmlinux::path;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

#[map(name = "SETTINGS")]
static mut SETTINGS: HashMap<u64, u64> = HashMap::<u64, u64>::with_max_entries(2, 0);

// This is the main entrypoint of the BPF program
#[lsm(name = "path_chroot")]
pub fn path_chroot(ctx: LsmContext) -> i32 {
    match try_path_chroot(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_path_chroot(ctx: LsmContext) -> Result<i32, i32> {
    let p = unsafe { ctx.arg::<c_ulong>(0) as *const path };
    let ret: c_int = unsafe { ctx.arg(1) };
    if p.is_null() {
        return Err(1);
    }

    // If previous eBPF LSM program didn't allow the action, return the
    // previous error code.
    if ret != 0 {
        return Err(ret);
    }

    let target_path;
    let target_path_is_root;
    // check whether the target path is the root (`/`)
    unsafe { 
        target_path = (*(*(*p).mnt).mnt_root).d_iname;
        target_path_is_root = target_path[0] == b'/' && target_path[1] == 0;
    };

    let host_inode = unsafe {
        match SETTINGS.get(&0) {
            Some(i) => *i as u64,
            None => return Err(1),
        }
    };

    let host_dev = unsafe {
        match SETTINGS.get(&1) {
            Some(d) => *d as u64,
            None => return Err(1),
        }
    };

    let cur_pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;

    let mut pid_info = bpf_pidns_info { pid: 0, tgid: 0 };
    let pid_info = &mut pid_info as *mut bpf_pidns_info;

    // retrieve pid_tgid info of current namespace
    // -> this will fail within a container, due to the fact that we're using device and inode information from the host's file system
    // -> invoking chroot outside of a container will still work, because pids will match
    let ret = unsafe {
        bpf_get_ns_current_pid_tgid(
            host_dev,
            host_inode,
            pid_info,
            mem::size_of::<bpf_pidns_info>() as u32,
        )
    };

    let mut ns_pid: u32 = 0;
    if ret == 0 {
        ns_pid = (unsafe { *pid_info }).pid;
    }

    // if pids don't match, the current process is running in a different pid-namespace
    if cur_pid != ns_pid && target_path_is_root {
        return Err(1);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
