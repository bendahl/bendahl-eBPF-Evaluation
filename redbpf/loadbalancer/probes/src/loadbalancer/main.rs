#![no_std]
#![no_main]

use network_types::eth::{EtherType, EthHdr};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use redbpf_probes::maps::{Array, LruHashMap};
use redbpf_probes::xdp::prelude::*;

use probes::Setting;

program!(0xFFFFFFFE, "GPL");

const XDP_REDIRECT: c_uint = 4;

// general program parameters
#[map]
static mut SETTINGS: Array<u16> = Array::<u16>::with_max_entries(3);

// list of backend servers to redirect packets to
#[map]
static mut BACKENDS: Array<[u8; 6]> = Array::<[u8; 6]>::with_max_entries(3);

// current backend index to send packets to
#[map]
static mut BACKEND_IDX: Array<u8> = Array::<u8>::with_max_entries(1);

// tcp session tuple, consisting of source and target ip and port
#[repr(C)]
struct tcp_session {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

// hash map that tracks tcp connection (session) information 
#[map]
static mut SESSIONS: LruHashMap<tcp_session, [u8; 6]> =
    LruHashMap::<tcp_session, [u8; 6]>::with_max_entries(1024);

// This is the main entry point of the BPF program.
#[xdp]
pub fn loadbalancer(ctx: XdpContext) -> XdpResult {
    return unsafe { try_loadbalancer(ctx) };
}

// try_loadbalancer implements the actual load balancing logic
unsafe fn try_loadbalancer(ctx: XdpContext) -> XdpResult {
    let ethhdr_const: *const EthHdr = ctx.ptr_at(ctx.data_start())?;
    let mut ethhdr: *mut EthHdr = ethhdr_const as *mut EthHdr;
    // ingore all non-IPv4 packets
    match (*ethhdr).ether_type {
        EtherType::Ipv4 => (),
        _ => {
            return Ok(XdpAction::Pass);
        }
    }

    let ipv4hdr: *const Ipv4Hdr= ctx.ptr_after(ethhdr)?;
    // ignore all non-TCP traffic
    match (*ipv4hdr).proto {
        IpProto::Tcp => (),
        _ => {
            return Ok(XdpAction::Pass);
        }
    }
    let tcphdr: *const TcpHdr = ctx.ptr_after(ipv4hdr)?;
    let cfg_port = match SETTINGS.get(Setting::Port as u32) {
        Some(value) => value,
        None => {
            return Ok(XdpAction::Pass);
        }
    };

    // check whether port matches the configured listen port
    if cfg_port.to_be() != (*tcphdr).dest {
        return Ok(XdpAction::Pass);
    }
    let no_backends = match SETTINGS.get(Setting::NoBackens as u32) {
        Some(value) => value,
        None => {
            return Ok(XdpAction::Pass);
        }
    };

    let cfg_out_if = match SETTINGS.get(Setting::OutIf as u32) {
        Some(value) => value,
        None => {
            return Ok(XdpAction::Pass);
        }
    };

    let session = tcp_session {
        src_ip: (*ipv4hdr).dst_addr,
        dst_ip: (*ipv4hdr).src_addr,
        src_port: (*tcphdr).source,
        dst_port: (*tcphdr).dest,
    };
    let mut backend_mac = SESSIONS.get(&session);
    if backend_mac.is_some() {
        return redirect(*cfg_out_if as u32, *backend_mac.unwrap(), ethhdr);
    }
    backend_mac = new_backend_mac(no_backends);
    if backend_mac.is_some() {
        (*ethhdr).dst_addr = *backend_mac.unwrap();
        SESSIONS
            .set(&session, &backend_mac.unwrap());
        return redirect(*cfg_out_if as u32, *backend_mac.unwrap(), ethhdr);
    }

    Ok(XdpAction::Pass)
}

#[inline(always)]
unsafe fn redirect(
    out_if: u32,
    dst_mac: [u8; 6],
    ethhdr: *mut EthHdr,
) -> XdpResult {
    let ret = bpf_redirect(out_if, 0) as c_uint;
    match ret {
        XDP_REDIRECT => {
            (*ethhdr).src_addr = (*ethhdr).dst_addr;
            (*ethhdr).dst_addr = dst_mac;
            return Ok(XdpAction::Redirect);
        }
        _ => {
            return Ok(XdpAction::Aborted);
        }
    }
}

// new_backend_mac determines the mac address of the backend to target
#[inline(always)]
unsafe fn new_backend_mac(no_backends: &u16) -> Option<&[u8; 6]> {
    let current_backend_idx = match BACKEND_IDX.get_mut(0) {
        Some(idx) => idx,
        None => return None,
    };

    let chosen_backend_idx = *current_backend_idx as u8 % *no_backends as u8;

    let backend = BACKENDS.get(chosen_backend_idx as u32);
    if backend.is_some() {
        if *current_backend_idx < 255 {
            *current_backend_idx += 1;
        } else {
            *current_backend_idx = 0;
        }
    }
    backend
}
