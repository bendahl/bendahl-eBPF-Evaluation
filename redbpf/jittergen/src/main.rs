/*
    This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
    Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/
use std::{fs, thread};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use redbpf::{HashMap, Map};

use serde::{Deserialize, Serialize};
use serde_yaml::from_reader;
use probes::Setting;

// Idea regarding the shared map was taken from this example: https://github.com/foniod/redbpf/blob/main/examples/example-userspace/examples/tc-map-share.rs
const TC_SETTINGS_MAP: &str = "/sys/fs/bpf/tc/globals/settings";

// Note that this example is not functional.
// Loading the code into the kernel failed when the full functionality as defined in the use case definition was implemented.
// The elf file appeared to be corrupted.
fn main() {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        from_reader(f).expect("config file should be valid yaml file in utf8 encoding");
    println!("Using interface: {:?}", config.out_if);

    // add interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).unwrap();
    let bpf_rog = concat!(env!("CARGO_MANIFEST_DIR"), "/target/bpf/programs/jittergen/jittergen.elf");

    // first, ensure that the root qdisc is set to 'fq' in order to enable packet pacing
    let _rqdh = RootQDiscHandler::new(config.out_if.clone(), bpf_rog.to_owned());
    // reference pinned map created by the BPF-Program, which is running in the kernel
    let map = Map::from_pin_file(TC_SETTINGS_MAP).expect("Settings map can be referenced via the file system");
    // load settings map that is created by the kernel BPF-program
    let settings = HashMap::<u16, u16>::new(&map).expect("Settings can be loaded");

    // set rules according to yaml file
    apply_rules(&config, settings);

    println!("Waiting for Ctrl-C...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
    let _ = fs::remove_file(TC_SETTINGS_MAP);
    println!("Exiting...");
}


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


// There is currently no direct support for TC in redbpf.
// Neither the handling of QDiscs nor the loading of tc classifiers/actions is supported.
// Therefore, the only way to handle this situation is to implement TC functionality to correctly load and attach the program.
struct RootQDiscHandler {
    interface_name: String,
}

// Basic QDisc handling functionality is implemented on top of the 'tc' utility.
impl RootQDiscHandler {
    pub fn new(interface_name: String, bpf_program: String) -> RootQDiscHandler {
        println!("Adding new root qdisc 'fq' on interface {}", interface_name);
        _ = Command::new("tc")
            .args([
                "qdisc",
                "add",
                "dev",
                &interface_name,
                "root",
                "fq",
            ])
            .output()
            .expect("root qdisc 'fq' is attached to interface");
        println!("Adding new clsact on interface {}", interface_name);
        _ = Command::new("tc")
            .args([
                "qdisc",
                "add",
                "dev",
                &interface_name,
                "clsact",
            ])
            .output()
            .expect("qdisc 'clsact' is attached to interface");
        println!("Attaching tc program to egress path of interface {}", interface_name);
        _ = Command::new("tc")
            .args([
                "filter",
                "add",
                "dev",
                &interface_name,
                "egress",
                "bpf",
                "direct-action",
                "obj",
                &bpf_program,
                "section",
                "tc_action/jittergen"
            ])
            .output()
            .expect("Program is attached correctly");

        Self { interface_name }
    }
}

// This implementation ensures that all qdiscs created are deleted when the RootQDiscHandler is disposed
impl Drop for RootQDiscHandler {
    fn drop(&mut self) {
        _ = Command::new("tc")
            .args([
                "qdisc",
                "delete",
                "dev",
                &self.interface_name.as_str(),
                "root",
            ])
            .output()
            .expect("clsact qdisc is removed from interface");
        _ = Command::new("tc")
            .args([
                "qdisc",
                "delete",
                "dev",
                &self.interface_name.as_str(),
                "clsact",
            ])
            .output()
            .expect("root qdisc is removed from interface");
    }
}

// apply_rules reads the config file values and sets the configuration values in the predefined map accordingly.
fn apply_rules(cfg: &Config, settings: HashMap<u16, u16>) {
    match cfg.action {
        Action::Jitter => {
            settings
                .set(Setting::Action as u16, 1_u16);
            settings
                .set(Setting::MinLat as u16, cfg.jitter.min_delay_ms);
            settings
                .set(Setting::MaxLat as u16, cfg.jitter.max_delay_ms);
        }
        Action::Drop => {
            settings
                .set(Setting::Action as u16, 2_u16);
        }
        Action::Reorder => {
            settings
                .set(Setting::Action as u16, 3_u16);
            settings
                .set(Setting::MinLat as u16, cfg.reorder.delay_ms);
            settings
                .set(Setting::MaxLat as u16, cfg.reorder.delay_ms);
        }
    }
    settings
        .set(Setting::Port as u16, cfg.rules.port);
    settings
        .set(Setting::Percent as u16, cfg.rules.percent);

    match cfg.rules.protocol {
        Protocol::Tcp => {
            settings
                .set(Setting::Protocol as u16, network_types::ip::IpProto::Tcp as u16);
        }
        Protocol::Udp => {
            settings
                .set(Setting::Protocol as u16, network_types::ip::IpProto::Udp as u16);
        }
        Protocol::Ip => {
            settings
                .set(Setting::Protocol as u16, network_types::eth::EtherType::Ipv4 as u16);
        }
    }
}
