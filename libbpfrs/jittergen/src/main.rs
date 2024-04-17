/*
    This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
    Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/
use libbpf_rs::{self, MapFlags, TC_EGRESS};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use jittergen::*;

// include generated interface types (skeletons)
#[path = "../jittergen.skel.rs"]
mod jittergen;

const ETH_P_IP: u16 = 0x0800;
const IP_P_TCP: u16 = 0x06;
const IP_P_UDP: u16 = 0x11;

// Start configuration section
// This section contains data types that are mapped to the yaml file structure
#[derive(Debug, Serialize, Deserialize)]
enum Protocol {
    #[serde(alias = "tcp")]
    Tcp,
    #[serde(alias = "udp")]
    Udp,
    #[serde(alias = "ip")]
    Ip,
}

#[derive(Debug, Serialize, Deserialize)]
enum Action {
    #[serde(alias = "jitter")]
    Jitter,
    #[serde(alias = "drop")]
    Drop,
    #[serde(alias = "reorder")]
    Reorder,
}

#[derive(Debug, Serialize, Deserialize)]
struct Match {
    percent: u16,
    protocol: Protocol,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jitter {
    #[serde(alias = "minDelayMs")]
    min_delay_ms: u16,
    #[serde(alias = "maxDelayMs")]
    max_delay_ms: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct Reorder {
    #[serde(alias = "delayMs")]
    delay_ms: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(alias = "outIf")]
    out_if: String,
    action: Action,
    #[serde(alias = "match")]
    rules: Match,
    jitter: Jitter,
    reorder: Reorder,
}
// End configuration section


// TcHandler is responsible for setting up and tearing down the qdiscs of the chosen network interface
struct TcHandler {
    interface_name: String,
}

// Implementation of handler creation
impl TcHandler {
    pub fn new(interface_name: String) -> TcHandler {
        println!("Adding new root qdisc 'fq' on interface {}", interface_name);
        _ = Command::new("tc")
            .args([
                "qdisc",
                "add",
                "dev",
                &interface_name.as_str(),
                "root",
                "fq",
            ])
            .output()
            .expect("root qdisc 'fq' is attached to interface");
        println!("Adding new qdisc 'clsact' on interface {}", interface_name);
        _ = Command::new("tc")
            .args(["qdisc", "add", "dev", &interface_name.as_str(), "clsact"])
            .output()
            .expect("'clsact' qdisc is added to new root qdisc on interface");
        Self { interface_name }
    }
}


// When the handler is released, the qdiscs will need to be cleaned-up
impl Drop for TcHandler {
    fn drop(&mut self) {
        println!(
            "removing 'clsact' qdisc from interface {}",
            &self.interface_name.as_str()
        );
        _ = Command::new("tc")
            .args([
                "qdisc",
                "delete",
                "dev",
                &self.interface_name.as_str(),
                "clsact",
            ])
            .output()
            .expect("'clsact' qdisc is removed from interface");
        println!(
            "removing root qdisc from interface {}",
            &self.interface_name.as_str()
        );
        _ = Command::new("tc")
            .args([
                "qdisc",
                "delete",
                "dev",
                &self.interface_name.as_str(),
                "root",
            ])
            .output()
            .expect("root qdisc is removed from interface");
    }
}

// This is the main entrypoint to the program
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");

    // get network interface id
    let interfaces = NetworkInterface::show().expect("network interfaces should exist");
    let mut net_if_index: Option<i32> = None;
    for net_if in interfaces {
        if net_if.name == config.out_if {
            net_if_index = Some(net_if.index as i32);
        }
    }

    // ensure that the qdiscs are set up correclty
    // cleanup will happen automatically upon destruction of the handler
    let _tc = TcHandler::new(config.out_if.clone());

    // load tc program into the kernel
    let skel_builder = JittergenSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .expect("jittergen skeleton should be opened");
    let mut skel = open_skel.load().expect("jittergen should be loaded");

    // attach program to tc egress hook on configured interface
    let mut jittergen_tc_hook = libbpf_rs::TcHook::new(skel.progs().tc_jittergen().fd());
    jittergen_tc_hook
        .ifindex(net_if_index.unwrap())
        .attach_point(TC_EGRESS)
        .attach()
        .expect("tc hook is attached to egress");

    // adding interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    // set rules in BPF map according to config
    apply_rules(&config, skel.maps_mut());

    // wait for CTRL+C (termination signal)
    println!("Running jittergen. Press CTRL+C to stop execution.");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
}

// apply_rules populates the appropriate BPF maps with the settings supplied in the configuration file
fn apply_rules(cfg: &Config, mut maps: JittergenMapsMut) {
    match cfg.action {
        Action::Jitter => {
            maps.settings()
                .update(&0_i32.to_ne_bytes(), &1_u16.to_ne_bytes(), MapFlags::ANY)
                .expect("action jitter is set");
            maps.settings()
                .update(
                    &4_i32.to_ne_bytes(),
                    &cfg.jitter.min_delay_ms.to_ne_bytes(),
                    MapFlags::ANY,
                )
                .expect("min_lat is set");
            maps.settings()
                .update(
                    &5_i32.to_ne_bytes(),
                    &cfg.jitter.max_delay_ms.to_ne_bytes(),
                    MapFlags::ANY,
                )
                .expect("max_lat is set");
        }
        Action::Drop => {
            maps.settings()
                .update(&0_i32.to_ne_bytes(), &2_u16.to_ne_bytes(), MapFlags::ANY)
                .expect("action drop is set");
        }
        Action::Reorder => {
            maps.settings()
                .update(&0_i32.to_ne_bytes(), &3_u16.to_ne_bytes(), MapFlags::ANY)
                .expect("action reorder is set");
            maps.settings()
                .update(
                    &4_i32.to_ne_bytes(),
                    &cfg.reorder.delay_ms.to_ne_bytes(),
                    MapFlags::ANY,
                )
                .expect("min_lat is set to delayMS");
            maps.settings()
                .update(
                    &5_i32.to_ne_bytes(),
                    &cfg.reorder.delay_ms.to_ne_bytes(),
                    MapFlags::ANY,
                )
                .expect("max_lat is set to delayMS");
        }
    }
    maps.settings()
        .update(
            &2_i32.to_ne_bytes(),
            &cfg.rules.port.to_ne_bytes(),
            MapFlags::ANY,
        )
        .expect("port is set");
    maps.settings()
        .update(
            &3_i32.to_ne_bytes(),
            &cfg.rules.percent.to_ne_bytes(),
            MapFlags::ANY,
        )
        .expect("percentage is set");

    match cfg.rules.protocol {
        Protocol::Tcp => {
            maps.settings()
                .update(&1_i32.to_ne_bytes(), &IP_P_TCP.to_ne_bytes(), MapFlags::ANY)
                .expect("protocol TCP is set");
        }
        Protocol::Udp => {
            maps.settings()
                .update(&1_i32.to_ne_bytes(), &IP_P_UDP.to_ne_bytes(), MapFlags::ANY)
                .expect("protocol UDP is set");
        }
        Protocol::Ip => {
            maps.settings()
                .update(&1_i32.to_ne_bytes(), &ETH_P_IP.to_ne_bytes(), MapFlags::ANY)
                .expect("protocol IP is set");
        }
    }
}
