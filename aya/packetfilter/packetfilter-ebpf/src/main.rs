#![no_std]
#![no_main]
#![feature(ip_in_core)]
use core::mem;
use core::net::{Ipv4Addr, Ipv6Addr};

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

// default configurations for IPv4 and IPv6 packets
#[map(name = "default_config")]
static mut DEFAULT_CONFIG: Array<u8> = Array::<u8>::with_max_entries(2, 0);

// ipv4 allow-/blocklist
#[map(name = "ipv4_rules")]
static mut IPV4_RULES: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024, 0);

// ipv6 allow-/blocklist
#[map(name = "ipv6_rules")]
static mut IPV6_RULES: HashMap<u128, u8> = HashMap::<u128, u8>::with_max_entries(1024, 0);

// Note that Aya does not currently support the map type RingBuffer. A possible replacement for this data structure
// would be would be a PerfEventArray. However, a PerfEventArray is a per-CPU data structure. This in turn means
// that the events received in userspace may arrive out of order. To keep the chronological order of events,
// additional program logic is required.
// Since the two RingBuffers in the examples are only used to log blocked/allowed packets to userspace, we will
// simply rely on Aya's logging facilities, which use a PerfEventArray to forward log messages to userspace
// under the hood. See this link for details: https://github.com/aya-rs/aya/tree/main/aya-log

#[xdp(name = "packetfilter")]
pub fn packetfilter(ctx: XdpContext) -> u32 {
    match try_packetfilter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_packetfilter(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

            let explicitly_allowed = unsafe { IPV4_RULES.get(&source_addr) };
            let default_allowed = unsafe { DEFAULT_CONFIG.get(0) };

            // explicitly blocked
            if explicitly_allowed.is_some_and(|x| x == &0) {
                info!(&ctx, "exlicitly blocked an ipv4 packet");
                return Ok(xdp_action::XDP_DROP);
            }
            // explicitly allowed
            if explicitly_allowed.is_some_and(|x| x != &0) {
                info!(&ctx, "exlicitly allowed an ipv4 packet");
                return Ok(xdp_action::XDP_PASS);
            }

            //default allowed
            if default_allowed.is_some_and(|x| x != &0) {
                info!(&ctx, "allowed an ipv4 packet");
                return Ok(xdp_action::XDP_PASS);
            }
            info!(&ctx, "dropped an ipv4 packet");
            return Ok(xdp_action::XDP_DROP);
        }
        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
            let ipv6u = u128::from_be_bytes(source_addr);
            let explicitly_allowed = unsafe { IPV6_RULES.get(&ipv6u) };
            let default_allowed = unsafe { DEFAULT_CONFIG.get(1) };

            // explicitly blocked
            if explicitly_allowed.is_some_and(|x| x == &0) {
                info!(&ctx, "exlicitly blocked an ipv6 packet");
                return Ok(xdp_action::XDP_DROP);
            }
            // explicitly allowed
            if explicitly_allowed.is_some_and(|x| x != &0) {
                info!(&ctx, "exlicitly allowed an ipv6 packet");
                return Ok(xdp_action::XDP_PASS);
            }

            //default allowed
            if default_allowed.is_some_and(|x| x != &0) {
                info!(&ctx, "allowed an ipv6 packet");
                return Ok(xdp_action::XDP_PASS);
            }
            info!(&ctx, "dropped an ipv6 packet");
            return Ok(xdp_action::XDP_DROP);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
