/*
    This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
    The configuration is done via a yaml-file.
    Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/
use ipnet::{Ipv4Net, Ipv6Net};
use packetfilter::packetfilter_bss_types::{src_ip_type, ip_type};
use plain::Plain;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use libbpf_rs::{MapFlags, RingBufferBuilder};
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use serde::{Deserialize, Serialize};

use packetfilter::*;

// include generated interface types (skeletons)
#[path = "../packetfilter.skel.rs"]
mod packetfilter;


// Start configuration section
// This section contains data types that are mapped to the yaml file structure
#[derive(Debug, Serialize, Deserialize)]
struct IPRules {
    default: String,
    allow: Option<Vec<String>>,
    block: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Rules {
    interface: String,
    ipv4: IPRules,
    ipv6: IPRules,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    rules: Rules,
}
// End configuration section

// required for ::from_bytes()
unsafe impl Plain for src_ip_type {}

// This is the main entrypoint of the program
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");
    println!("Interface: {:?}", config.rules.interface);

    // get network interface id
    let interfaces = NetworkInterface::show().expect("network interfaces should exist");
    let mut net_if_index: Option<i32> = None;
    for net_if in interfaces {
        if net_if.name == config.rules.interface {
            net_if_index = Some(net_if.index as i32);
        }
    }

    // load xdp program into the kernel
    let skel_builder = PacketfilterSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .expect("packetfilter skeleton should be opened");
    let mut skel = open_skel.load().expect("packetfilter should be loaded");
    let link = skel
        .progs_mut()
        .xdp_prog_func()
        .attach_xdp(net_if_index.expect("network interface should exist"))
        .expect("xdp link should be established");
    skel.links = PacketfilterLinks {
        xdp_prog_func: Some(link),
    };

    // initialize ring buffer
    let mut rbbuilder = RingBufferBuilder::new();
    rbbuilder
        .add(skel.maps().processed_packets(), |data| event_handler(data))
        .unwrap();
    let rb = rbbuilder.build().unwrap();

    // add interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    apply_rules(&config, skel.maps_mut());

    println!("Running packetfilter. Press CTRL+C to stop execution.");
    // poll ringbuffer
    while running.load(Ordering::SeqCst) && rb.poll(Duration::from_millis(100)).is_ok() {}
}

// event_handler handles new incoming messages from the kernel BPF program
fn event_handler(data: &[u8]) -> i32 {
    let ipt =
        src_ip_type::from_bytes(data).expect("event can be marshalled to userspace ip_type");
    if ipt.passed {
        println!("Allowed packet for address: {}", get_ip(&ipt));
    } else {
        println!("Blocked packet for address: {}", get_ip(&ipt));
    }
    return 0;
}

// apply_rules parses the configuration file and adds the specified rules to the appropriate maps on the BPF side
fn apply_rules(cfg: &Config, mut maps: PacketfilterMapsMut) {
    if cfg.rules.ipv4.default.to_lowercase() != "block"
        && cfg.rules.ipv4.default.to_lowercase() != "allow"
    {
        panic!("ipv4 default should either be 'allow' or 'block'");
    }

    if cfg.rules.ipv4.default.to_lowercase() == "block" {
        maps.default_config()
            .update(&0_u32.to_ne_bytes(), &0_u8.to_ne_bytes(), MapFlags::ANY)
            .expect("default ipv4 value should be set");
    } else {
        maps.default_config()
            .update(&0_u32.to_ne_bytes(), &1_u8.to_ne_bytes(), MapFlags::ANY)
            .expect("default ipv4 value should be set");
    }

    if cfg.rules.ipv4.allow.is_some() {
        for ip4 in cfg.rules.ipv4.allow.as_ref().unwrap() {
            let ip = Ipv4Net::from_str((ip4.to_owned() + "/24").as_str())
                .expect("ipv4 can be parsed correctly");
            maps.ip4_rules()
                .update(&ip.addr().octets(), &1_u8.to_ne_bytes(), MapFlags::ANY)
                .expect("ipv4 is added correctly to allow list");
        }
    }
    if cfg.rules.ipv4.block.is_some() {
        for ip4 in cfg.rules.ipv4.block.as_ref().unwrap() {
            let ip = Ipv4Net::from_str((ip4.to_owned() + "/24").as_str())
                .expect("ipv4 can be parsed correctly");
            maps.ip4_rules()
                .update(&ip.addr().octets(), &0_u8.to_ne_bytes(), MapFlags::ANY)
                .expect("ipv4 is added correctly to allow list");
        }
    }

    if cfg.rules.ipv6.default.to_lowercase() != "block"
        && cfg.rules.ipv6.default.to_lowercase() != "allow"
    {
        panic!("ipv6 default should either be 'allow' or 'block'");
    }

    if cfg.rules.ipv6.default.to_lowercase() == "block" {
        maps.default_config()
            .update(&1_u32.to_ne_bytes(), &0_u8.to_ne_bytes(), MapFlags::ANY)
            .expect("default ipv6 value should be set");
    } else {
        maps.default_config()
            .update(&1_u32.to_ne_bytes(), &1_u8.to_ne_bytes(), MapFlags::ANY)
            .expect("default ipv6 value should be set");
    }

    if cfg.rules.ipv6.allow.is_some() {
        for ip6 in cfg.rules.ipv6.allow.as_ref().unwrap() {
            let ip = Ipv6Net::from_str((ip6.to_owned() + "/128").as_str())
                .expect("ipv6 can be parsed correctly");
            maps.ip6_rules()
                .update(&ip.addr().octets(), &1_u8.to_ne_bytes(), MapFlags::ANY)
                .expect("ipv6 is added correctly to allow list");
        }
    }

    if cfg.rules.ipv6.block.is_some() {
        for ip6 in cfg.rules.ipv6.block.as_ref().unwrap() {
            let ip = Ipv6Net::from_str((ip6.to_owned() + "/128").as_str())
                .expect("ipv6 can be parsed correctly");
            maps.ip6_rules()
                .update(&ip.addr().octets(), &0_u8.to_ne_bytes(), MapFlags::ANY)
                .expect("ipv6 is added correctly to allow list");
        }
    }
}

// get_ip translates a given IP to its string representation
fn get_ip(ip: &src_ip_type) -> String {
    unsafe {
        if ip.iptype == ip_type::IPV4 {
            return Ipv4Addr::from(ip.ip.ipv4.to_ne_bytes()).to_string();
        }
        return Ipv6Addr::from(ip.ip.ipv6.in6_u.u6_addr8).to_string();
    }
}
