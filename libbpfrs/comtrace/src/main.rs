/*
    This program traces TCP connections and some of their metrics.
    It is heavily inspired by the 'tcplife' program, created by Brendan Gregg and the BCC authors
    See: https://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html
    See: https://github.com/iovisor/bcc/blob/master/tools/tcplife.py
*/
use std::{
    collections::HashMap,
    fs::File,
    io::{LineWriter, Write},
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use clap::{ArgAction, Parser};
use libbpf_rs::RingBufferBuilder;

use crate::comtrace::comtrace_bss_types::ip_type;
use comtrace::{comtrace_bss_types::tcp_event, *};
use plain::Plain;

// include generated interface types (skeletons)
#[path = "../comtrace.skel.rs"]
mod comtrace;


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

fn main() {
    // read command line arguments
    let args = Args::parse();
    // load bpf program into the kernel
    let skel_builder = ComtraceSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .expect("loadbalancer skeleton should be opened");
    let mut skel = open_skel.load().expect("loadbalancer should be loaded");
    let link = skel
        .progs_mut()
        .inet_sock_set_state()
        .attach_tracepoint("sock", "inet_sock_set_state")
        .expect("trace program should be attached to inte_sock_state");
    skel.links = ComtraceLinks {
        inet_sock_set_state: Some(link),
    };

    // add interrupt handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
        .unwrap();

    // initialize map that caches the recorded connections
    let mut connections: HashMap<Connection, ConnectionMeta> = HashMap::new();

    // initialize ring buffer
    let mut rbbuilder = RingBufferBuilder::new();
    rbbuilder
        .add(skel.maps().ip_events(), |data| {
            event_handler(&mut connections, data)
        })
        .unwrap();
    let rb = rbbuilder.build().unwrap();

    println!(
        "Running tracer for {} seconds. Press CTRL+C to stop execution.",
        args.duration
    );

    // poll ring buffer
    let start_time = Instant::now();
    while running.load(Ordering::SeqCst)
        && rb.poll(Duration::from_millis(500)).is_ok()
        && start_time.elapsed().as_secs() < args.duration.into()
    {}

    // release ring buffer
    drop(rb);

    // write results to the specified file upon program termination
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
    for (con, meta) in &mut connections {
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
            )
                .as_bytes(),
        )
            .unwrap();
    }
    println!("Finished tracing. Log was written to {}", args.output_file);
}

// Start configuration section
// This section contains data types that are mapped to the yaml file structure
#[derive(Hash, Eq, PartialEq, Debug)]
struct Connection {
    saddr: String,
    daddr: String,
    sport: u16,
    dport: u16,
}

#[derive(Clone)]
struct ConnectionMeta {
    pid: u32,
    comm: String,
    bytes_received: u64,
    bytes_sent: u64,
    start_ts: u64,
    end_ts: u64,
}
// End configuration section

// implement default initialization for connection meta data
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

// required for ::from_bytes()
unsafe impl Plain for tcp_event {}

const TCP_SYN_SENT: i32 = 1;
const TCP_FIN_WAIT1: i32 = 4;
const TCP_LAST_ACK: i32 = 9;

// event_handler handles incoming connection events
fn event_handler(connections: &mut HashMap<Connection, ConnectionMeta>, data: &[u8]) -> i32 {
    let event =
        tcp_event::from_bytes(data).expect("event can be marshalled to userspace tcp_event");
    // ignore local-port == 0
    if event.lport == 0 {
        return 0;
    }
    let key = Connection {
        saddr: get_ip(&event.saddr).to_string(),
        daddr: get_ip(&event.daddr).to_string(),
        sport: event.lport,
        dport: event.dport,
    };

    let mut meta = ConnectionMeta::default();
    if connections.contains_key(&key) {
        meta = connections.get(&key).unwrap().clone();
        meta.end_ts = event.tstamp;
        meta.bytes_received = event.bytes_received;
        meta.bytes_sent = event.bytes_sent;
        if event.newstate == TCP_SYN_SENT
            || event.newstate == TCP_FIN_WAIT1
            || event.newstate == TCP_LAST_ACK
        {
            meta.pid = event.pid;
            // ensure that 0 bytes are handled correctly in later formatting by converting to space (0x20)
            meta.comm = String::from_utf8(event.comm.iter().map(|&c| if c == 0 { 0x20 } else { c as u8 }).collect()).unwrap();
        }
    } else {
        meta.bytes_received = event.bytes_received;
        meta.bytes_sent = event.bytes_sent;
        meta.end_ts = event.tstamp;
    }
    // only update timestamp if we're dealing with a new connection
    // otherwise, leave timestamp as-is, since we do not know how long the connection has been opened
    if event.newstate < TCP_FIN_WAIT1 {
        meta.start_ts = event.tstamp;
    }
    connections.insert(key, meta);
    0
}

const AF_INET: u16 = 2;

// get_ip converts a given (BPF) ip type to an actual IpAddr as defined in the standard library
fn get_ip(ip: &ip_type) -> IpAddr {
    unsafe {
        if ip.family == AF_INET {
            return IpAddr::from(ip.ip.ipv4);
        }
        return IpAddr::from(ip.ip.ipv6);
    }
}
