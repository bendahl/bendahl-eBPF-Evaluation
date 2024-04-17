#![no_std]
#![no_main]

use network_types::ip::{Ipv4Hdr, Ipv6Hdr};
use redbpf_probes::maps::Array;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

// note that network byte order is big endian
const ETH_P_IP: u16 = 0x0800_u16.to_be();
const ETH_P_IP6: u16 = 0x86DD_u16.to_be();

// default configurations for IPv4 and IPv6 packets
#[map]
static mut DEFAULT_CONFIG: Array<u8> = Array::<u8>::with_max_entries(2);

// ipv4 allow-/blocklist
#[map]
static mut IPV4_RULES: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(1024);

// ipv6 allow-/blocklist
#[map]
static mut IPV6_RULES: HashMap<u128, u8> = HashMap::<u128, u8>::with_max_entries(1024);

// Note that introducing a PerfEventArray to send packet event messages (dropped/passed) to userspace failed.
// The resulting program could not be loaded into the kernel due to invalid elf section information.
// Therefore, this example does not support this feature.
// However, the packetfilter itself is functional and was tested successfully on the included VM.
#[xdp]
pub fn packetfilter(ctx: XdpContext) -> XdpResult {
    let ethhdr = ctx.eth()?;
    match unsafe { (*ethhdr).h_proto as u16 } {
        ETH_P_IP => {
            let ipv4hdr: *const Ipv4Hdr = match unsafe { ctx.ptr_after(ethhdr) } {
                Ok(hdr) => hdr,
                Err(_) => {
                    return Ok(XdpAction::Pass);
                }
            };
            if(ipv4hdr.is_null()) {
                return Ok(XdpAction::Pass);
            }

            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
            let explicitly_allowed = unsafe { IPV4_RULES.get(&source_addr) };
            let default_allowed = unsafe { DEFAULT_CONFIG.get(0) };

            // explicitly blocked
            if explicitly_allowed.is_some() {
                if explicitly_allowed.unwrap() == &0 {
                    return Ok(XdpAction::Drop);
                } else {
                    return Ok(XdpAction::Pass);
                }
            }
            if default_allowed.is_some() {
                if default_allowed.unwrap() == &0 {
                    return Ok(XdpAction::Drop);
                } else {
                    return Ok(XdpAction::Pass);
                }
            }
        }
        ETH_P_IP6 => {
            let ipv6hdr: *const Ipv6Hdr = match unsafe { ctx.ptr_after(ethhdr) } {
                Ok(hdr) => hdr,
                Err(_) => {
                    return Ok(XdpAction::Pass);
                }
            };
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };
            let ipv6u = u128::from_be_bytes(source_addr);
            let explicitly_allowed = unsafe { IPV6_RULES.get(&ipv6u) };
            let default_allowed = unsafe { DEFAULT_CONFIG.get(1) };

            if explicitly_allowed.is_some() {
                if explicitly_allowed.unwrap() == &0 {
                    return Ok(XdpAction::Drop);
                } else {
                    return Ok(XdpAction::Pass);
                }
            }
            if default_allowed.is_some() {
                if default_allowed.unwrap() == &0 {
                    return Ok(XdpAction::Drop);
                } else {
                    return Ok(XdpAction::Pass);
                }
            }
        }
        _ => return Ok(XdpAction::Pass),
    }
    Ok(XdpAction::Pass)
}
