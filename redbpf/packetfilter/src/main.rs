/*
    This program implements a simple XDP-based packet filter that allows/blocks ip packets from predefined source addresses.
    The configuration is done via a yaml-file.
    Filtering rules are stored in BPF maps, so that the BPF program that performs the actual packet filtering can read and apply them.
*/

use serde::{Deserialize, Serialize};
use std::{net::{Ipv6Addr, Ipv4Addr}, str::FromStr, thread};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use redbpf::{load::{Loader, Loaded}, HashMap, Array, Error};
use redbpf::load::LoaderError;

use serde_yaml::from_reader;

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


// probe_code loads the BPF program's code as a byte array
fn probe_code() -> &'static [u8] {
    include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/target/bpf/programs/packetfilter/packetfilter.elf"
    ))
}


// This is the main entrypoint to the application.
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        from_reader(f).expect("config file should be valid yaml file in utf8 encoding");
    println!("Interface: {:?}", config.rules.interface);

    // load bpf program and attach it to the interface specified in the configuration file
    let mut bpf = Loader::load(probe_code()).expect("Program can be loaded into the kernel");
    let pfilter = bpf.xdp_mut("packetfilter").expect("Packetfilter is a valid xdp program");
    pfilter.attach_xdp(&config.rules.interface, redbpf::xdp::Flags::Unset).expect("Packetfilter can be attached correctly");

    // set parameters in BPF map in order to pass those values to the kernel BPF program
    apply_rules(&config, &bpf).unwrap();

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
fn apply_rules(cfg: &Config, bpf: &Loaded) -> Result<(), redbpf::Error> {
    if cfg.rules.ipv4.default.to_lowercase() != "block"
        && cfg.rules.ipv4.default.to_lowercase() != "allow"
    {
        panic!("ipv4 default should either be 'allow' or 'block'");
    }
    let defaults = Array::<u8>::new(bpf.map("DEFAULT_CONFIG").expect("Default map exists")).expect("Defaults can be loaded");
    if cfg.rules.ipv4.default.to_lowercase() == "block" {
        defaults.set(0, 0_u8)?;
    } else {
        defaults.set(0, 1_u8)?;
    }

    let ipv4_rules = HashMap::<u32, u8>::new(bpf.map("IPV4_RULES").expect("IPv4 map exists")).expect("IPv4 rules can be loaded");
    if cfg.rules.ipv4.allow.is_some() {
        for ip4 in cfg.rules.ipv4.allow.as_ref().unwrap() {
            let ip = Ipv4Addr::from_str((ip4.to_owned()).as_str())
                .expect("ipv4 can be parsed correctly");
            ipv4_rules.set(u32::from(ip), 1_u8);
        }
    }
    if cfg.rules.ipv4.block.is_some() {
        for ip4 in cfg.rules.ipv4.block.as_ref().unwrap() {
            let ip = Ipv4Addr::from_str((ip4.to_owned()).as_str())
                .expect("ipv4 can be parsed correctly");
            ipv4_rules.set(u32::from(ip), 0_u8);
        }
    }

    if cfg.rules.ipv6.default.to_lowercase() != "block"
        && cfg.rules.ipv6.default.to_lowercase() != "allow"
    {
        panic!("ipv6 default should either be 'allow' or 'block'");
    }

    if cfg.rules.ipv6.default.to_lowercase() == "block" {
        defaults.set(1, 0_u8)?;
    } else {
        defaults.set(1, 1_u8)?;
    }

    let ipv6_rules = HashMap::<u128, u8>::new(bpf.map("IPV6_RULES").expect("IPv6 map exists")).expect("IPv6 rules can be loaded");

    if cfg.rules.ipv6.allow.is_some() {
        for ip6 in cfg.rules.ipv6.allow.as_ref().unwrap() {
            let ip = Ipv6Addr::from_str((ip6.to_owned()).as_str())
                .expect("ipv6 can be parsed correctly");
            ipv6_rules.set(u128::from(ip), 1_u8);
        }
    }
    if cfg.rules.ipv6.block.is_some() {
        for ip6 in cfg.rules.ipv6.block.as_ref().unwrap() {
            let ip = Ipv6Addr::from_str((ip6.to_owned()).as_str())
                .expect("ipv6 can be parsed correctly");
            ipv6_rules.set(u128::from(ip), 0_u8);
        }
    }

    Ok(())
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