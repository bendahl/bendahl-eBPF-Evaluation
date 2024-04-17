/*
This program traces TCP connections and some of their metrics.
It is heavily inspired by the 'tcplife' program, created by Brendan Gregg and the BCC authors
See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
*/
use std::collections::HashMap;
use std::fs::File;
use std::io::{LineWriter, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::{Parser, ArgAction};
use comtrace_common::{TcpEvent, AF_INET};
use crossbeam_channel::{bounded, select, tick, Receiver};
use log::{info, warn};

const TCP_SYN_SENT: i32 = 1;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_LAST_ACK: i32 = 9;


// eBPF program that traces tcp connections
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Duration of the trace in seconds
    #[arg(short, default_value_t = 30)]
    duration: u16,

    // Output file to write the trace log to
    #[arg(short, default_value_t = String::from("tcp_trace.log"))]
    output_file: String,

    // Print captions
    #[arg(short, action = ArgAction::SetFalse)]
    captions: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Args::parse();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/comtrace"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/comtrace"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // load and attach BPF program
    let program: &mut TracePoint = bpf.program_mut("comtrace").unwrap().try_into()?;
    program.load()?;
    program.attach("sock", "inet_sock_set_state")?;

    // initialize event array
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("events")?)?;
    let connections = Arc::new(Mutex::new(HashMap::<Connection, ConnectionMeta>::new()));

    // determine number of cpus
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();

    // use dedicated buffers per cpu 
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        let connections = connections.clone();
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            // loop forever
            loop {
                // process incoming events
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const TcpEvent;
                    let evt = unsafe { ptr.read_unaligned() };
                    let mut connection = connections.lock().unwrap();
                    // ignore local port 0
                    if evt.lport == 0 {
                        continue;
                    }
                    let saddr: IpAddr;
                    let daddr: IpAddr;
                    if evt.family == AF_INET {
                        saddr =
                            IpAddr::from([evt.saddr[0], evt.saddr[1], evt.saddr[2], evt.saddr[3]]);
                        daddr =
                            IpAddr::from([evt.daddr[0], evt.daddr[1], evt.daddr[2], evt.daddr[3]]);
                    } else {
                        saddr = IpAddr::from(evt.saddr);
                        daddr = IpAddr::from(evt.daddr);
                    }

                    let key = Connection {
                        saddr: saddr.to_string(),
                        daddr: daddr.to_string(),
                        sport: evt.lport,
                        dport: evt.dport,
                    };

                    let mut meta = ConnectionMeta::default();
                    if connection.contains_key(&key) {
                        meta = connection.get(&key).unwrap().clone();
                        meta.end_ts = evt.tstamp;
                        meta.bytes_received = evt.bytes_received;
                        meta.bytes_sent = evt.bytes_sent;
                        if evt.newstate == TCP_SYN_SENT
                            || evt.newstate == TCP_FIN_WAIT1
                            || evt.newstate == TCP_LAST_ACK
                        {
                            meta.pid = evt.pid;
                            // ensure that 0 bytes are handled correctly in later formatting by converting to space (0x20)
                            meta.comm = String::from_utf8(
                                evt.comm
                                    .iter()
                                    .map(|&c| if c == 0 { 0x20 } else { c as u8 })
                                    .collect(),
                            )
                            .unwrap();
                        }
                    } else {
                        meta.bytes_received = evt.bytes_received;
                        meta.bytes_sent = evt.bytes_sent;
                        meta.end_ts = evt.tstamp;
                    }
                    // only set startts if this is a newly created connection
                    // otherwise, we do not know how long this connection has been opened for
                    if evt.newstate < TCP_FIN_WAIT1 {
                        meta.start_ts = evt.tstamp;
                    }

                    connection.insert(key, meta);
                }
            }
        });
    }
    info!("Waiting for Ctrl-C or timeout...");

    // wait for termination signal
    let ctrl_c_events = ctrl_channel()?;
    let ticks = tick(Duration::from_secs(args.duration as u64));

    loop {
        select! {
            // timeout received -> terminate
            recv(ticks) -> _ => {
                // timeout reached -> terminate
                break;
            }
            // termination signal received -> terminate
            recv(ctrl_c_events) -> _ => {
                // ctrl+c event received -> terminate
                break;
            }
        }
    }

    info!("Exiting...");

    // write statistics to configured file upon program termination
    let file = File::create(&args.output_file).expect("file can be created");
    let mut file = LineWriter::new(file);
    if args.captions {
        file.write_all(
            format!(
                "{:<10} {:<20} {:<40} {:<14} {:<40} {:<14} {:<10} {:<10} {:<10}\n",
                "PID",
                "COMM",
                "LOCAL_IP",
                "LOCAL_PORT",
                "REMOTE_IP",
                "REMOTE_PORT",
                "RX_BYTES",
                "TX_BYTES",
                "MS",
            )
            .as_bytes(),
        )
        .unwrap();
    }

    let connection = connections.lock().unwrap();
    for (con, meta) in connection.iter() {
        // skip pid 0
        if meta.pid == 0 {
            continue;
        }
        file.write_all(
            format!(
                "{:<10} {:<20} {:<40} {:<14} {:<40} {:<14} {:<10} {:<10} {:<10}\n",
                meta.pid,
                meta.comm.trim(),
                con.saddr,
                con.sport,
                con.daddr,
                con.dport,
                meta.bytes_received,
                meta.bytes_sent,
                (meta.end_ts - meta.start_ts) / 1000000,
            ).as_bytes(),
        ).unwrap();
    }
    Ok(())
}

// Signal handling logic based on: https://rust-cli.github.io/book/in-depth/signals.html
fn ctrl_channel() -> Result<Receiver<()>, ctrlc::Error> {
    let (sender, receiver) = bounded(100);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}

// connection key
#[derive(Hash, Eq, PartialEq, Debug)]
struct Connection {
    saddr: String,
    daddr: String,
    sport: u16,
    dport: u16,
}

// connection meta data (value)
#[derive(Clone)]
struct ConnectionMeta {
    pid: u32,
    comm: String,
    bytes_received: u64,
    bytes_sent: u64,
    start_ts: u64,
    end_ts: u64,
}

// default initialization values of the connection meta data
impl ConnectionMeta {
    fn default() -> ConnectionMeta {
        ConnectionMeta {
            pid: Default::default(),
            comm: Default::default(),
            bytes_received: Default::default(),
            bytes_sent: Default::default(),
            start_ts: Default::default(),
            end_ts: Default::default(),
        }
    }
}
