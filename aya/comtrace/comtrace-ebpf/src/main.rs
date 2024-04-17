#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use core::{ffi::c_void};

use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;
use comtrace_common::{TcpEvent, AF_INET};

use vmlinux::tcp_sock;

// PerfEventArray is used in place of RingBuffer here, since Aya does not natively support the RingBuffer yet.
// Since we do not care about the particular order of events, the fact that this is a per-CPU structure is irrelevant
// in the context of this example use case.
#[map(name = "events")]
static mut EVENTS: PerfEventArray<TcpEvent> = PerfEventArray::<TcpEvent>::with_max_entries(256, 0);

// data structure as it is passed to the BPF program by the kernel
#[repr(C)]
struct InetSockSetState {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    skaddr: *const c_void,
    oldstate: i32,
    newstate: i32,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
}

// This is the main entrypoint to the BPF program
#[tracepoint(name = "comtrace")]
pub fn comtrace(ctx: TracePointContext) -> u32 {
    match unsafe { try_comtrace(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[repr(C)]
union ip_buf {
    v6: [u8; 16],
    v4: [u8; 4],
}

// main program logic
unsafe fn try_comtrace(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint inet_sock_set_state called");
    // get socket data structures
    let sk_state = match (ctx.as_ptr() as *const InetSockSetState).as_ref() {
        Some(s) => s,
        None => return Err(1),
    };
    let sk = match ((*sk_state).skaddr as *const tcp_sock).as_ref() {
        Some(s) => s,
        None => return Err(1),
    };

    // extract required information from socket fields
    let mut evt: TcpEvent = Default::default(); 
    evt.family = match bpf_probe_read(&(*sk_state).family) {
        Ok(family) => family,
        Err(_) => return Err(1),
    };

    let mut saddr: ip_buf = ip_buf { v6: Default::default() };
    let mut daddr: ip_buf = ip_buf { v6: Default::default() };
    if evt.family == AF_INET {
        saddr.v4 = match bpf_probe_read(&(*sk_state).saddr) {
            Ok(ip) => ip,
            Err(_) => return Err(1),
        };
        daddr.v4 = match bpf_probe_read(&(*sk_state).daddr) {
            Ok(ip) => ip,
            Err(_) => return Err(1),
        };
    } else {
        saddr.v6 = match bpf_probe_read(&(*sk_state).saddr_v6) {
            Ok(ip) => ip,
            Err(_) => return Err(1),
        };
        daddr.v6 = match bpf_probe_read(&(*sk_state).daddr_v6) {
            Ok(ip) => ip,
            Err(_) => return Err(1),
        };
    }
    evt.saddr = saddr.v6;
    evt.daddr = daddr.v6;


    evt.lport = match bpf_probe_read(&(*sk_state).sport) {
        Ok(s) => s,
        Err(_) => return Err(1),
    };
    evt.dport = match bpf_probe_read(&(*sk_state).dport) {
        Ok(s) => s,
        Err(_) => return Err(1),
    };

    evt.oldstate = match bpf_probe_read(&(*sk_state).oldstate) {
        Ok(s) => s,
        Err(_) => return Err(1),
    };
    evt.newstate = match bpf_probe_read(&(*sk_state).newstate) {
        Ok(s) => s,
        Err(_) => return Err(1),
    };

    evt.bytes_received = match bpf_probe_read(&(*sk).bytes_received) {
        Ok(b) => b,
        Err(_) => return Err(1),
    };

    evt.bytes_sent = match bpf_probe_read(&(*sk).bytes_sent) {
        Ok(b) => b,
        Err(_) => return Err(1),
    };

    // get process id and name
    evt.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    evt.comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Err(1),
    };

    // determine current timestamp
    evt.tstamp = bpf_ktime_get_ns();

    // write event to buffer
    EVENTS.output(&ctx, &evt, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
