/*
  This program is intended to simulate different network conditions, such as jitter, packet drop and packet reordering.
  Due to various issues regarding the resulting BPF binary, this program is not in a usable state.
*/
use std::process::Command;

use aya::maps::{Array, MapRefMut};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;

use jittergen_common::Setting;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::signal;

// This is the main entrypoint of the program
// By default, tokio is used as an asynchronous runtime
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // read config file
    let f = std::fs::File::open("config.yml")
        .expect("config file should exist in current working directory");
    let config: Config =
        serde_yaml::from_reader(f).expect("config file should be valid yaml file in utf8 encoding");

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/jittergen"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/jittergen"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // first, ensure that the root qdisc is set to 'fq' in order to enable packet pacing
    let _rqdh = RootQDiscHandler::new(config.out_if.clone());

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&config.out_if);
    let program: &mut SchedClassifier = bpf.program_mut("jittergen").unwrap().try_into()?;
    program.load()?;
    program.attach(&config.out_if, TcAttachType::Egress)?;

    //ensure that state is initialized correctly
    let mut state: Array<_, u64> = Array::try_from(bpf.map_mut("state")?)?;
    state.set(0,0,0);

    // populate settings map
    let settings: Array<_, u16> = Array::try_from(bpf.map_mut("settings")?)?;
    apply_rules(&config, settings);

    // wait for termination signal
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

// Start configuration section
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


// The current TC helper functionality contained in Aya does not permit to programmatically change the root qdisc.
// This handler uses the tc command line program under the hood in order to ensure that the root qdisc matches our expectations.
// Upon destruction, it also resets the root qdisc to the default.
// Note that for production purposes it would be preferrable to add this functionality to Aya and the underlying netlink module.
// This change is far beyond the scope of this implementation, however.
struct RootQDiscHandler {
    interface_name: String,
}

// New adds a new root qdisc of type 'Fair Queue' (FQ)
impl RootQDiscHandler {
    pub fn new(interface_name: String) -> RootQDiscHandler {
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
        Self { interface_name }
    }
}

// When the QDiscHandler is dropped, it will cleanup the root qdisc as well
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
            .expect("root qdisc is removed from interface");
    }
}

// populate BPF settings map (matching rules, etc...)
fn apply_rules(cfg: &Config, mut settings: Array<MapRefMut, u16>) {
    match cfg.action {
        Action::Jitter => {
            settings
                .set(Setting::Action as u32, 1_u16, 0)
                .expect("action jitter is set");
            settings
                .set(Setting::MinLat as u32, cfg.jitter.min_delay_ms, 0)
                .expect("min_lat is set");
            settings
                .set(Setting::MaxLat as u32, cfg.jitter.max_delay_ms, 0)
                .expect("max_lat is set");
        }
        Action::Drop => {
            settings
                .set(Setting::Action as u32, 2_u16, 0)
                .expect("action drop is set");
        }
        Action::Reorder => {
            settings
                .set(Setting::Action as u32, 3_u16, 0)
                .expect("action reorder is set");
            settings
                .set(Setting::MinLat as u32, cfg.reorder.delay_ms, 0)
                .expect("min_lat is set to delayMS");
            settings
                .set(Setting::MaxLat as u32, cfg.reorder.delay_ms, 0)
                .expect("max_lat is set to delayMS");
        }
    }
    settings
        .set(Setting::Port as u32, cfg.rules.port, 0)
        .expect("port is set");
    settings
        .set(Setting::Percent as u32, cfg.rules.percent, 0)
        .expect("percentage is set");

    match cfg.rules.protocol {
        Protocol::Tcp => {
            settings
                .set(Setting::Protocol as u32, network_types::ip::IpProto::Tcp as u16, 0)
                .expect("protocol TCP is set");
        }
        Protocol::Udp => {
            settings
                .set(Setting::Protocol as u32, network_types::ip::IpProto::Udp as u16, 0)
                .expect("protocol UDP is set");
        }
        Protocol::Ip => {
            settings
                .set(Setting::Protocol as u32, network_types::eth::EtherType::Ipv4 as u16, 0)
                .expect("protocol IP is set");
        }
    }
}
