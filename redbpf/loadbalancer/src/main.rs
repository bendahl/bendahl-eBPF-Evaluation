/*
    This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
    Only TCP packets are handled by this program.
    As a load balancing algorithm, round robin is used.
*/
use std::thread;
use std::num::ParseIntError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use redbpf::{Array, Error, load::Loader};
use serde::{Deserialize, Serialize};
use serde_yaml::from_reader;

// Start configuration section
// This section contains data types that are mapped to the yaml file structure
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(alias = "listenInterface")]
    listen_interface: String,
    tcp_port: u16,
    backends: Vec<String>,
}
// End configuration section


// probe_code loads the BPF program's code as a byte array
fn probe_code() -> &'static [u8] {
    include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/bpf/programs/loadbalancer/loadbalancer.elf"
    ))
}


// This is the main entrypoint to the application.
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        from_reader(f).expect("config file should be valid yaml file in utf8 encoding");
    println!("Listening on interface: {:?}", config.listen_interface);

    // load and attach the BPF program to the network interface specified in the configuration file
    let mut bpf = Loader::load(probe_code()).expect("Program can be loaded into the kernel");
    let pfilter = bpf.xdp_mut("loadbalancer").expect("Loadbalancer is a valid xdp program");
    pfilter.attach_xdp(&config.listen_interface, redbpf::xdp::Flags::Unset).expect("Loadbalancer can be attached correctly");

    // initialize backend BPF map
    let backends = Array::<[u8; 6]>::new(bpf.map("BACKENDS").expect("Backends map exists")).expect("Backends can be loaded");
    init_backends(&config, &backends);

    // initialize settings BPF map
    let settings = Array::<u16>::new(bpf.map("SETTINGS").expect("Settings map exists")).expect("Settings can be loaded");
    apply_rules(&config, &settings).unwrap();

    // adding interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).unwrap();

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
    println!("Exiting...");
}

// apply_rules parses the configuration file and adds the specified rules to the appropriate maps on the BPF side
fn apply_rules(cfg: &Config, settings: &Array<u16>) -> Result<(), Error> {
    settings.set(0, cfg.tcp_port)?;
    let num_backends = cfg.backends.len() as u16;
    settings.set(1, num_backends)?;
    let out_if = get_if_for_name(&cfg.listen_interface)
        .expect("outbound network interface should exist") as u16;
    settings.set(2, out_if)?;

    Ok(())
}

fn get_if_for_name(if_name: &String) -> Option<i32> {
    let interfaces = NetworkInterface::show().expect("network interfaces should exist");
    for net_if in interfaces {
        if &net_if.name == if_name {
            return Some(net_if.index as i32);
        }
    }
    None
}

fn init_backends(cfg: &Config, backends: &Array<[u8; 6]>) {
    let mut i: u32 = 0;
    for backend in &cfg.backends {
        let mac = str_to_mac(backend).expect("mac address can be parsed correctly");
        backends.set(i, mac).expect("backend can be added to map");
        i += 1;
    }
}

fn str_to_mac(mac_str: &String) -> Result<[u8; 6], ParseIntError> {
    let parts = mac_str.split(":");
    let mut mac: [u8; 6] = [0; 6];
    let mut i = 0;
    for part in parts {
        mac[i] = u8::from_str_radix(part, 16).unwrap();
        i += 1;
    }
    Ok(mac)
}


// Ensure that bytes are properly aligned.
// Otherwise, load errors upon loading the bpf program may occur.
// This code was taken from the aya sources.
// See: https://github.com/aya-rs/aya/blob/bcb2972a969f85e8c6c77e1213d89cc8198e8fe7/aya/src/util.rs#L130
#[macro_export]
macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(C)]
        pub struct Aligned<Bytes: ?Sized> {
            pub _align: [u32; 0],
            pub bytes: Bytes,
        }

        static ALIGNED: &Aligned<[u8]> = &Aligned {
            _align: [],
            bytes: *include_bytes!($path),
        };

        &ALIGNED.bytes
    }};
}