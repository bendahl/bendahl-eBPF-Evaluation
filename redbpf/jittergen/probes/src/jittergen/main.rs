#![no_std]
#![no_main]

use core::mem;

use network_types::eth::{EtherType, EthHdr};
use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use redbpf_macros::{map, tc_action};
use redbpf_probes::tc::prelude::*;

use probes::Setting;

program!(0xFFFFFFFE, "GPL");

// default configurations for IPv4 and IPv6 packets
//
// As a workaround, this map can also be used to store the last timestamp (state - see below comment).
#[map(link_section = "maps")]
static mut settings: TcHashMap<u16, u16> = TcHashMap::<u16, u16>::with_max_entries(6, TcMapPinning::GlobalNamespace);

// persist global state of program between calls safely in a map
//
// Unfortunately, this does not work. The program cannot be loaded into the kernel. To circumvent this issue,
// it is possible to append the state as a field to the settings map. This is not a very clean approach, however.
// Also, even with this change in place, the actual jitter logic does not work due to further errors occurring upon progam load.
// Therefore, this map is kept to document the intended design.
#[map(link_section = "maps")]
static mut state: HashMap<u8, u64> = HashMap::<u8, u64>::with_max_entries(2);

// Note that this example is not functional.
// Loading the code into the kernel failed when the full functionality as defined in the use case definition was implemented.
// The elf file appeared to be corrupted.
#[tc_action]
pub fn jittergen(skb: SkBuff) -> TcActionResult {
    let skb_ptr = skb.skb as *mut __sk_buff;
    let action = match unsafe { settings.get(&(Setting::Action as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let protocol = match unsafe { settings.get(&(Setting::Protocol as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let port = match unsafe { settings.get(&(Setting::Port as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let percent = match unsafe { settings.get(&(Setting::Percent as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let min_lat = match unsafe { settings.get(&(Setting::MinLat as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let max_lat = match unsafe { settings.get(&(Setting::MaxLat as u16)) } {
        Some(value) => value,
        None => {
            return Ok(TcAction::Ok);
        }
    };

    let is_match = match packet_is_match(&skb, &protocol, &port) {
        Ok(value) => value,
        Err(_) => {
            return Ok(TcAction::Ok);
        }
    };
    if !is_match {
        return Ok(TcAction::Ok);
    }

    unsafe {
        if (*skb_ptr).tstamp > 0 {
            (*skb_ptr).tstamp = (*skb_ptr).tstamp + (1000 * 1000);
            state.set(&0u8, &((*skb_ptr).tstamp as u64));
        }

        // only perform action if we're within defined percentage
        let rnd = bpf_get_prandom_u32() % 100;
        if rnd >= *percent as u32 {
            return Ok(TcAction::Shot);
        }
    }
    //
    // if *action == DROP {
    //     return Ok(TcAction::Shot);
    // }
    //
    // if *action == JITTER {
    //     return delay_packet(skb_ptr,  *min_lat, *max_lat, false, true);
    // }
    //
    // if *action == REORDER {
    //     return delay_packet(skb_ptr, *min_lat, *max_lat, true, false);
    // }

    Ok(TcAction::Ok)
}

#[inline(always)]
fn delay_packet(
    sk_buf: *mut __sk_buff,
    min_lat: u16,
    max_lat: u16,
    use_min_lat: bool,
    keep_order: bool,
) -> TcActionResult {
    let mut delay_ms = min_lat;
    if !use_min_lat {
        let rnd = (unsafe { bpf_get_prandom_u32() } % max_lat as u32) as u16;
        delay_ms = if rnd < min_lat { min_lat } else { rnd };
    }
    let delay_ns = (delay_ms as u32 * 1000 * 1000) as u64;

    unsafe {
        let last_tstamp = match state.get(&0u8) {
            Some(tstamp) => tstamp,
            None => {
                return Ok(TcAction::Ok);
            }
        };
        let tstamp = bpf_ktime_get_ns();
        if keep_order && tstamp < *last_tstamp {
            (*sk_buf).tstamp = *last_tstamp + delay_ns;
        } else {
            (*sk_buf).tstamp = tstamp + delay_ns;
        }
        state.set(&0u8, &((*sk_buf).tstamp))
    }

    Ok(TcAction::Ok)
}

#[inline(always)]
fn packet_is_match(skb: &SkBuff, protocol: &u16, port: &u16) -> Result<bool, u32> {
    if *protocol == EtherType::Ipv4 as u16 {
        if unsafe { (*skb.skb).protocol != EtherType::Ipv4 as __u32 } {
            return Ok(false);
        }
    } else {
        let ethhdr: *const EthHdr = ptr_at(&skb, 0)?;
        let ether_type = (unsafe { *ethhdr }).ether_type;
        if ether_type != EtherType::Ipv4 {
            return Ok(false);
        }

        let iphdr: *const Ipv4Hdr = ptr_at(skb, EthHdr::LEN)?;
        let proto = (unsafe { *iphdr }).proto;
        if proto as u16 != *protocol {
            return Ok(false);
        }

        match proto {
            network_types::ip::IpProto::Udp => {
                let udphdr: *const UdpHdr = ptr_at(skb, EthHdr::LEN + Ipv4Hdr::LEN)?;
                if (unsafe { *udphdr }).dest != (*port).to_be() {
                    return Ok(false);
                }
            }
            network_types::ip::IpProto::Tcp => {
                let tcphdr: *const TcpHdr = ptr_at(skb, EthHdr::LEN + Ipv4Hdr::LEN)?;
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
fn ptr_at<T>(skb: &SkBuff, offset: usize) -> Result<*const T, u32> {
    let start = unsafe { (*skb.skb).data } as usize;
    let end = unsafe { (*skb.skb).data_end } as usize;
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(1);
    }

    Ok((start + offset) as *const T)
}

