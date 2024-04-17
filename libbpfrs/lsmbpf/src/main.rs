/*
    This program implements a simple Linux Security Module (LSM).
    It inhibits using chroot to the host's filesystem root in order 
    to prevent container escapes and privilege escalation.
*/
use lsmbpf::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fs, thread};
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use libbpf_rs::MapFlags;

// include generated interface types (skeletons)
#[path = "../lsmbpf.skel.rs"]
mod lsmbpf;

// This is the main entrypoint to the program
fn main() {
    // load lsm module into the kernel
    let skel_builder = LsmbpfSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .expect("lsmbpf skeleton should be opened");
    let mut skel = open_skel.load().expect("lsm skeleton should be loaded");

    // attach lsm module
    let _lsm = skel
        .progs_mut()
        .lsm_no_chroot_to_root()
        .attach_lsm()
        .expect("lsm module should be linked");

    // add interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    // get metadata of current namespace procfile
    let meta = fs::metadata("/proc/self/ns/pid").expect("pid namespace information can be read");
    let inode = meta.ino();
    let device = meta.dev();

    // initialize maps and set configuration values accordingly
    let mut maps = skel.maps_mut();
    maps.settings().update(&0i32.to_ne_bytes(), &inode.to_ne_bytes(), MapFlags::ANY)
        .expect("inode is set");
    maps.settings().update(&1i32.to_ne_bytes(), &device.to_ne_bytes(), MapFlags::ANY)
        .expect("dev is set");

    // wait for CTRL+C
    println!("Running lsm module. Press CTRL+C to stop execution.");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
}
