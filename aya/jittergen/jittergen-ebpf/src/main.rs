#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};

use aya_log_ebpf::info;
use jittergen_common::{Setting, DROP, JITTER, REORDER};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// program settings
#[map(name = "settings")]
static mut SETTINGS: Array<u16> = Array::<u16>::with_max_entries(256, 0);

// persist global state of program between calls safely in a map
#[map(name = "state")]
static mut STATE: Array<u64> = Array::<u64>::with_max_entries(1, 0);

// This is the main entrypoint of the BPF program
#[classifier(name = "jittergen")]
pub fn jittergen(ctx: TcContext) -> i32 {
    match try_jittergen(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_jittergen(ctx: TcContext) -> Result<i32, i32> {
    let action = match unsafe { SETTINGS.get(Setting::Action as u32) } {
        Some(value) => value,
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    let protocol = match unsafe { SETTINGS.get(Setting::Protocol as u32) } {
        Some(value) => value,
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    let port = match unsafe { SETTINGS.get(Setting::Port as u32) } {
        Some(value) => value,
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    let percent = match unsafe { SETTINGS.get(Setting::Percent as u32) } {
        Some(value) => value,
        None => {
            return Ok(TC_ACT_OK);
        }
    };

    let min_lat = match unsafe { SETTINGS.get(Setting::MinLat as u32) } {
        Some(value) => value,
        None => &0,
    };

    let max_lat = match unsafe { SETTINGS.get(Setting::MaxLat as u32) } {
        Some(value) => value,
        None => &0,
    };

    let is_match = match packet_is_match(&ctx, &protocol, &port) {
        Ok(value) => value,
        Err(_) => {
            return Ok(TC_ACT_OK);
        }
    };
    if !is_match {
        return Ok(TC_ACT_OK);
    }
    let last_tstamp = match unsafe { STATE.get_ptr_mut(0) } {
        Some(tstamp) => tstamp,
        None => {
            return Ok(TC_ACT_OK);
        }
    };
    let skb = ctx.skb.skb;
    unsafe {
        if *last_tstamp > 0 {
            (*skb).tstamp = (*skb).tstamp + (1000 * 1000);
            *last_tstamp = (*skb).tstamp;
        }

        // only perform action if we're within defined percentage
        let rnd = bpf_get_prandom_u32() % 100;
        if rnd >= *percent as u32 {
            return Ok(TC_ACT_OK);
        }
    }

    // drop packets at specified rate
    if *action == DROP {
        info!(&ctx, "dropping packet");
        return Ok(TC_ACT_SHOT);
    }

    // create jitter
    if *action == JITTER {
        info!(&ctx, "causing jitter");
        return delay_packet(skb, last_tstamp, *min_lat, *max_lat, false, true);
    }

    // reorder specified portion of packets
    if *action == REORDER {
        info!(&ctx, "reordering packets");
        return delay_packet(skb, last_tstamp, *min_lat, *max_lat, true, false);
    }

    Ok(TC_ACT_OK)
}

// delay_packet calculates the desired delay of a packet and adjusts the timestamp accordingly
#[inline(always)]
fn delay_packet(
    sk_buf: *mut __sk_buff,
    last_tstamp: *mut u64,
    min_lat: u16,
    max_lat: u16,
    use_min_lat: bool,
    keep_order: bool,
) -> Result<i32, i32> {
    let mut delay_ms = min_lat;
    if !use_min_lat {
        let rnd = (unsafe { bpf_get_prandom_u32() } % max_lat as u32) as u16;
        delay_ms = if rnd < min_lat { min_lat } else { rnd };
    }
    let delay_ns = (delay_ms as u32 * 1000 * 1000) as u64;

    unsafe {
        let tstamp = bpf_ktime_get_ns();
        if keep_order && tstamp < *last_tstamp {
            (*sk_buf).tstamp = *last_tstamp + delay_ns;
        } else {
            (*sk_buf).tstamp = tstamp + delay_ns;
        }
        *last_tstamp = (*sk_buf).tstamp;
    }

    Ok(TC_ACT_OK)
}

// match packet according to given protocol
#[inline(always)]
fn packet_is_match(ctx: &TcContext, protocol: &u16, port: &u16) -> Result<bool, u32> {
    if *protocol == EtherType::Ipv4 as u16 {
        if ctx.skb.protocol() != EtherType::Ipv4 as u32 {
            return Ok(false);
        }
    } else {
        let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let ether_type = (unsafe { *ethhdr }).ether_type;
        if ether_type != EtherType::Ipv4 {
            return Ok(false);
        }

        let iphdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
        let proto = (unsafe { *iphdr }).proto;
        if proto as u16 != *protocol {
            return Ok(false);
        }

        match proto {
            network_types::ip::IpProto::Udp => {
                let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                if (unsafe { *udphdr }).dest != (*port).to_be() {
                    return Ok(false);
                }
            }
            network_types::ip::IpProto::Tcp => {
                let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                if (unsafe { *tcphdr }).dest != (*port).to_be() {
                    return Ok(false);
                }
            }
            _ => {
                // unsupported protocol -> ignore
                return Ok(false);
            }
        }
    }

    // packet matches criteria
    Ok(true)
}

// For details see: https://aya-rs.dev/book/start/parsing-packets/#getting-packet-data-from-the-context
#[inline(always)]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, u32> {
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
