/*
    This program implements a simple load balancer, using direct server return (DSR) as a load balancing strategy.
    Only TCP packets are handled by this program.
    As a load balancing algorithm, round robin is used.
*/
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration, num::ParseIntError,
};

use libbpf_rs::MapFlags;
use loadbalancer::*;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

// include generated interface types (skeletons)
#[path = "../loadbalancer.skel.rs"]
mod loadbalancer;

// Configuration parameters
#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(alias = "listenInterface")]
    listen_interface: String,
    tcp_port: u16,
     backends: Vec<String>,
}


// This is the main entrypoint to the program
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");

    let listen_if = get_if_for_name(&config.listen_interface);

    // load xdp program into the kernel
    let skel_builder = LoadbalancerSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .expect("loadbalancer skeleton should be opened");
    let mut skel = open_skel.load().expect("loadbalancer should be loaded");
    let link = skel
        .progs_mut()
        .xdp_loadbalancer()
        .attach_xdp(listen_if.expect("listen interface should exist"))
        .expect("xdp link should be established");
    skel.links = LoadbalancerLinks {
        xdp_loadbalancer: Some(link),
    };

    // add interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    // init BPF maps and process settings
    init_settings(&config, skel.maps_mut());
    init_backends(&config, skel.maps_mut());

    // wait for CTRL+C (termination signal)
    println!("Running loadbalancer. Press CTRL+C to stop execution.");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
}

// get_if_for_name returns the network interface (nic) id related to a given nic
fn get_if_for_name(if_name: &String) -> Option<i32> {
    let interfaces = NetworkInterface::show().expect("network interfaces should exist");
    for net_if in interfaces {
        if &net_if.name == if_name {
            return Some(net_if.index as i32);
        }
    }
    None
}

// init_backends populates the list of backends use within the load balancer implementation
fn init_backends(cfg: &Config, mut maps: LoadbalancerMapsMut) {
    let mut i: u32 = 0;
    for backend in &cfg.backends {
        let mac = str_to_mac(backend).expect("mac address can be parsed correctly");
        maps.backends()
            .update(&i.to_ne_bytes(), &mac, MapFlags::ANY)
            .expect("mac address can be added to backend list");
        i += 1;
    }
}

// str_to_mac converts a given mac address string into its byte representation
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

// unit test to verify that the above str_to_mac function is able to parse a valid mac
#[cfg(test)]
mod tests {
    use crate::str_to_mac;

    #[test]
    fn it_works() {
        let teststr = String::from("ca:fe:ba:be:47:11");
        let mac = str_to_mac(&teststr).unwrap();
        print!("mac is: {:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5],);
    }
}

// init_settings populates the global configuration values that should be passed to the BPF program
fn init_settings(cfg: &Config, mut maps: LoadbalancerMapsMut) {
    maps.settings()
        .update(
            &0_i32.to_ne_bytes(),
            &cfg.tcp_port.to_ne_bytes(),
            MapFlags::ANY,
        )
        .expect("tcp port should be set");

    let num_backends = cfg.backends.len() as u16;
    maps.settings()
        .update(
            &1_i32.to_ne_bytes(),
            &num_backends.to_ne_bytes(),
            MapFlags::ANY,
        )
        .expect("number of backends should be set");

    let out_if = get_if_for_name(&cfg.listen_interface)
        .expect("outbound network interface should exist") as u16;
    maps.settings()
        .update(&2_i32.to_ne_bytes(), &out_if.to_ne_bytes(), MapFlags::ANY)
        .expect("outbound interface should be set");
}
