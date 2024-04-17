/*
This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
Only TCP packets are handled by this program.
As a load balancing algorithm, round robin is used.
*/
use std::num::ParseIntError;

use anyhow::Context;
use aya::maps::{Array, MapRefMut};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};

use loadbalancer_common::Setting;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Serialize, Deserialize};
use tokio::signal;

// configuration data structure
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(alias = "listenInterface")]
    listen_interface: String,
    tcp_port: u16,
    backends: Vec<String>,
}

// This is the main entrypoint of the program
// By default tokio is used as an asynchronous runtime
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/loadbalancer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/loadbalancer"
    ))?;
    let program: &mut Xdp = bpf.program_mut("loadbalancer").unwrap().try_into()?;
    program.load()?;
    program.attach(&config.listen_interface, 
        XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // populate backend list
    let backends: Array<_, [u8; 6]> = Array::try_from(bpf.map_mut("backends").unwrap())?;
    init_backends(&config, backends);

    // populate program settings
    let settings: Array<_, u16> = Array::try_from(bpf.map_mut("settings").unwrap())?;
    init_settings(&config, settings);

    // initialize backend index
    let mut backend_idx: Array<_, u8> = Array::try_from(bpf.map_mut("backend_idx").unwrap())?;
    backend_idx.set(0, 0, 0).expect("Backend index is initialized correctly");

    // wait for termination signal
    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

// get the network interface id by its name
fn get_if_for_name(if_name: &String) -> Option<i32> {
    let interfaces = NetworkInterface::show().expect("network interfaces should exist");
    for net_if in interfaces {
        if &net_if.name == if_name {
            return Some(net_if.index as i32);
        }
    }
    None
}

// populate backend map
fn init_backends(cfg: &Config, mut backends: Array<MapRefMut, [u8; 6]>) {
    let mut i: u32 = 0;
    for backend in &cfg.backends {
        let mac = str_to_mac(backend).expect("mac address can be parsed correctly");
        backends.set(i, mac, 0).expect("Backend is added correctly to list of backends");
        i += 1;
    }
}

// convert string representation of a mac address to a byte array
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

// populate settings map
fn init_settings(cfg: &Config, mut settings: Array<MapRefMut, u16>) {
    settings.set(Setting::NoBackens as u32, cfg.backends.len() as u16, 0).expect("Number of backends is initialized correctly");
    settings.set(Setting::OutIf as u32, get_if_for_name(&cfg.listen_interface).expect("Outbound interface is determined correclty") as u16, 0).expect("Oubound interface is initialized correctly");
    settings.set(Setting::Port as u32, cfg.tcp_port as u16, 0).expect("Tcp port is set correctly");
}
