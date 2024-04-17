/*
This program implements a simple Linux Security Module (LSM).
It inhibits using chroot to the host's filesystem root in order
to prevent container escapes and privilege escalation.
*/
use std::fs;
use std::os::unix::fs::MetadataExt;

use aya::maps::HashMap;
use aya::{programs::Lsm, Btf};
use aya::{include_bytes_aligned, Bpf};

use tokio::signal;

// This is the main entrypoint of the program
// By default tokio is used as an asynchronous runtime
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/lsmbpf"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/lsmbpf"
    ))?;

    // load and attach BPF program
    let program: &mut Lsm = bpf.program_mut("path_chroot").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    program.load("path_chroot", &btf)?;
    program.attach()?;

    // get metadata of current namespace procfile
    let meta = fs::metadata("/proc/self/ns/pid")?;
    let inode = meta.ino();
    let device = meta.dev();
    let mut settings: HashMap<_, u64, u64> = HashMap::try_from(bpf.map_mut("SETTINGS")?)?;
    settings.insert(0, inode, 0)?;
    settings.insert(1, device, 0)?;

    // wait for termination signal
    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
