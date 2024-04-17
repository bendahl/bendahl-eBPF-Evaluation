#![no_std]
#![no_main]

use core::{ffi::c_uint, mem};

use aya_bpf::{
    bindings::xdp_action,
    helpers::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    memcpy,
    programs::XdpContext,
};

use loadbalancer_common::Setting;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

// program settings
#[map(name = "settings")]
static mut SETTINGS: Array<u16> = Array::<u16>::with_max_entries(3, 0);

// list of backends
#[map(name = "backends")]
static mut BACKENDS: Array<[u8; 6]> = Array::<[u8; 6]>::with_max_entries(3, 0);

// currently selected backend index
#[map(name = "backend_idx")]
static mut BACKEND_IDX: Array<u8> = Array::<u8>::with_max_entries(1, 0);

// value that represents an unset backend value
const NO_BACKEND: [u8; 6] = [0, 0, 0, 0, 0, 0];

#[repr(C)]
struct tcp_session {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
}

// LRU cache that holds the tcp sessions
#[map(name = "sessions")]
static mut SESSIONS: LruHashMap<tcp_session, [u8; 6]> =
    LruHashMap::<tcp_session, [u8; 6]>::with_max_entries(1024, 0);

#[xdp(name = "loadbalancer")]
pub fn loadbalancer(ctx: XdpContext) -> u32 {
    match unsafe { try_loadbalancer(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_loadbalancer(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;

    // ingore all non-IPv4 packets
    match (*ethhdr).ether_type {
        EtherType::Ipv4 => (),
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // ignore all non-TCP traffic
    match (*ipv4hdr).proto {
        IpProto::Tcp => (),
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    let cfg_port = match SETTINGS.get(Setting::Port as u32) {
        Some(value) => value.clone(),
        None => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // check whether port matches the configured listen port
    if cfg_port != u16::from_be((*tcphdr).dest) {
        return Ok(xdp_action::XDP_PASS);
    }

    let no_backends = match SETTINGS.get(Setting::NoBackens as u32) {
        Some(value) => value,
        None => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let cfg_out_if = match SETTINGS.get(Setting::OutIf as u32) {
        Some(value) => value,
        None => {
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // create session tuple
    let session = tcp_session {
        src_ip: (*ipv4hdr).src_addr,
        dst_ip: (*ipv4hdr).dst_addr,
        src_port: (*tcphdr).source,
        dst_port: (*tcphdr).dest,
    };
    let backend_mac = match SESSIONS.get(&session) {
        Some(mac) => mac,
        None => new_backend_mac(no_backends),
    };
    if *backend_mac == NO_BACKEND {
        return Ok(xdp_action::XDP_ABORTED);
    }
    // add new TCP session
    match SESSIONS.insert(&session, &backend_mac, 0) {
        Ok(_) => (),
        Err(_) => return Ok(xdp_action::XDP_ABORTED),
    }

    // replace target mac address with the selected backend mac
    memcpy(
        (*ethhdr).src_addr.as_mut_ptr(),
        (*ethhdr).dst_addr.as_mut_ptr(),
        6,
    );
    memcpy(
        (*ethhdr).dst_addr.as_mut_ptr(),
        backend_mac.clone().as_mut_ptr(),
        6,
    );
    return Ok(bpf_redirect(*cfg_out_if as u32, 0) as c_uint);
}

// determine new backend mac for next connection
#[inline(always)]
unsafe fn new_backend_mac(no_backends: &u16) -> &[u8; 6] {
    let current_backend_idx = match BACKEND_IDX.get_ptr_mut(0) {
        Some(idx) => idx,
        None => {
            return &NO_BACKEND;
        }
    };

    let chosen_backend_idx = *current_backend_idx as u8 % *no_backends as u8;

    let backend = match BACKENDS.get(chosen_backend_idx as u32) {
        Some(backend) => {
            *current_backend_idx += 1;
            backend
        }
        None => {
            *current_backend_idx = 0;
            &NO_BACKEND
        }
    };
    backend
}

// For details see: https://aya-rs.dev/book/start/parsing-packets/#getting-packet-data-from-the-context
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(1);
    }

    Ok((start + offset) as *const T)
}

// For destails see: https://github.com/shaneutt/ebpf-rust-udp-loadbalancer-demo/blob/main/demo-ebpf/src/main.rs
#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, u32> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
