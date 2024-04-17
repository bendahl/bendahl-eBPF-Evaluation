/*
    This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
    The configuration is done via a yaml-file.
    Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::{Context, Ok};
use aya::maps::{Array, HashMap};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{warn};
use serde::{Deserialize, Serialize};
use tokio::signal;

// Start configuration section
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

// This is the main entrypoint of the program -> note that tokio is used 
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");
    println!("Interface: {:?}", config.rules.interface);

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/packetfilter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/packetfilter"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("packetfilter").unwrap().try_into()?;
    program.load()?;
    program.attach(&config.rules.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // populate filter rule BPF maps
    apply_rules(&config, &bpf)?;

    // wait for termination signal
    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

// populate BPF settings maps containing filter rules
fn apply_rules(cfg: &Config, bpf: &Bpf) -> Result<(), anyhow::Error> {
    if cfg.rules.ipv4.default.to_lowercase() != "block"
        && cfg.rules.ipv4.default.to_lowercase() != "allow"
    {
        panic!("ipv4 default should either be 'allow' or 'block'");
    }

    let mut defaults: Array<_, u8> = Array::try_from(bpf.map_mut("default_config")?)?;
    if cfg.rules.ipv4.default.to_lowercase() == "block" {
        defaults.set(0, 0_u8, 0)?;
    } else {
        defaults.set(0, 1_u8, 0)?;
    }

    let mut ipv4_rules = HashMap::try_from(bpf.map_mut("ipv4_rules")?)?;
    if cfg.rules.ipv4.allow.is_some() {
        for ip4 in cfg.rules.ipv4.allow.as_ref().unwrap() {
            let ip = Ipv4Addr::from_str((ip4.to_owned()).as_str())
                .expect("ipv4 can be parsed correctly");
            ipv4_rules.insert(u32::from(ip), 1_u8, 0)?;
        }
    }
    if cfg.rules.ipv4.block.is_some() {
        for ip4 in cfg.rules.ipv4.block.as_ref().unwrap() {
            let ip = Ipv4Addr::from_str((ip4.to_owned()).as_str())
                .expect("ipv4 can be parsed correctly");
            ipv4_rules.insert(u32::from(ip), 0_u8, 0)?;
        }
    }

    if cfg.rules.ipv6.default.to_lowercase() != "block"
        && cfg.rules.ipv6.default.to_lowercase() != "allow"
    {
        panic!("ipv6 default should either be 'allow' or 'block'");
    }

    if cfg.rules.ipv6.default.to_lowercase() == "block" {
        defaults.set(1, 0_u8, 0)?;
    } else {
        defaults.set(1, 1_u8, 0)?;
    }

    let mut ipv6_rules = HashMap::try_from(bpf.map_mut("ipv6_rules")?)?;
    if cfg.rules.ipv6.allow.is_some() {
        for ip6 in cfg.rules.ipv6.allow.as_ref().unwrap() {
            let ip = Ipv6Addr::from_str((ip6.to_owned()).as_str())
                .expect("ipv6 can be parsed correctly");
            ipv6_rules.insert(u128::from(ip), 1_u8, 0)?;
        }
    }
    if cfg.rules.ipv6.block.is_some() {
        for ip6 in cfg.rules.ipv6.block.as_ref().unwrap() {
            let ip = Ipv6Addr::from_str((ip6.to_owned()).as_str())
                .expect("ipv6 can be parsed correctly");
            ipv6_rules.insert(u128::from(ip), 0_u8, 0)?;
        }
    }

    Ok(())
}
