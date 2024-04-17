//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>   /* most used helpers: SEC, __always_inline, etc */

char __license[] SEC("license") = "Dual MIT/GPL";

#define ACTION_JITTER 1
#define ACTION_DROP 2
#define ACTION_REORDER 3

#define FEATURE_ACTIVE(feature, flags) (u16) (feature & flags)

const unsigned char IP_P_TCP = 0x06;
const unsigned char IP_P_UDP = 0x11;

const unsigned int time_ms = 1000 * 1000;

enum setting {ACTIONS, PROTOCOL, PORT, PERCENT, MIN_LAT, MAX_LAT};

static volatile unsigned long long last_tstamp = 0;

// queue that holds the actions to be performed on incoming packages
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(enum setting));
	__uint(value_size, sizeof(unsigned short));
    __uint(max_entries, 256);
} settings SEC(".maps");

// force BTF generation
enum setting *unused_setting __attribute__((unused));

/*
	delay_packet will delay a network packet by a given amount of time using the skb's timestamp field to tell the kernel when to send it.
	See https://stackoverflow.com/questions/72554292/how-to-generate-delay-using-ebpf-kernel-program for further information.
	Note that this only works in combination with certain parent qdiscs. One such parent qdisc is FQ (fair queue).

	*skb: The socket buffer structure representing the packet
	*min_lat: Minimum time in ms to delay the packet by
	*max_lat: Maximum time in ms to delay the packet by
	use_min_lat: If set to true (nonzero), the min_lat_value will be used as the lower and upper bound for the delay (delay is constant - no jitter)
	keep_order: If set to true (nonzero), the packet order will be preserved, no reordering will occur
*/
static __always_inline int delay_packet(struct __sk_buff *skb, unsigned short *min_lat, unsigned short *max_lat, int use_min_lat, int keep_order) {

	unsigned short delay_ms = *min_lat;
	if (!use_min_lat) {
		unsigned int rnd = bpf_get_prandom_u32() % *max_lat;
		delay_ms = rnd < *min_lat ? *min_lat : rnd;
	} 

	// 
	unsigned long long delay_ns = (unsigned long long)(delay_ms * time_ms); 
	unsigned long long tstamp = bpf_ktime_get_ns();
	if(keep_order && tstamp < last_tstamp) {
		skb->tstamp = last_tstamp + delay_ns;
	} else {
		skb->tstamp = tstamp + delay_ns;
	}
	last_tstamp = skb->tstamp;

	return TC_ACT_OK;
}

/*
	packet_is_match will check whether a given network packet matches the given criteria.

	*skb: The socket buffer structure representing the packet
	*protocol: The protocol that should be matched
	*port: The port to be matched
	*percent: Approximate percentage of packets that should be processed	
*/
static __always_inline int packet_is_match(struct __sk_buff *skb, unsigned short *protocol, unsigned short *port, unsigned short *percent) {
	// exit early if there's nothing to do
	if(*percent == 0) {
		return 0;
	}

	// If IP packets should be processed, skip furhter header processing (port matching is irrelevant)
	if(*protocol == ETH_P_IP) {
		// we only care about the lower 16 bit of the 32 bit uint here
		if(__builtin_bswap16((unsigned short)skb->protocol) != ETH_P_IP) {
			return 0;
		}
	} else {
		void *data_end = (void *)(long)skb->data_end;
	    void *data     = (void *)(long)skb->data;

		struct ethhdr *eth = data;
		if ((void *)(eth + 1) > data_end) {
			return 0;
		}

		if (__builtin_bswap16(eth->h_proto) != ETH_P_IP) {
			return 0;
		}

		// check ip header for validity
		struct iphdr *ip = (void *) (eth + 1);
		if ((void *) (ip + 1) > data_end) {
			return 0;
		}

		// no byte swapping necessary, since we're only dealing with a single byte -> byte order is not an issue
		if (ip->protocol != (unsigned char)*protocol) {
			return 0;
		}

		// check whether port in tcp-/udp-header matches
		switch(ip->protocol) {
			case IP_P_TCP: {
				struct tcphdr *tcp = (void *) (ip + 1);
				if ((void *) (tcp + 1) > data_end) {
					return 0;
				}
				if (__builtin_bswap16(tcp->dest) != *port) {
					return 0;
				}
				// tcp header matches
				return 1;
			}

			case IP_P_UDP: {
				struct udphdr *udp = (void *) (ip + 1);
				if ((void *) (udp + 1) > data_end) {
					return 0;
				}
				if (__builtin_bswap16(udp->dest) != *port) {
					return 0;
				}
				// udp header matches
				return 1;
			}
			
			// unsupported protocol -> ignore
			default: 
				return 0;
		}
	}

	// protocol is IP -> match
	return 1;
}

// This is the main entrypoint to the program
SEC("tc")
int tc_jittergen(struct __sk_buff *skb) {

	// read config values
	const int cfg_actions = ACTIONS;
	unsigned short *action = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_actions);
	const int cfg_protocol = PROTOCOL;
	unsigned short *protocol = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_protocol);
	const int cfg_port = PORT;
	unsigned short *port = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_port);
	const int cfg_percent = PERCENT;
	unsigned short *percent = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_percent);
	const int cfg_min_lat = MIN_LAT;
	unsigned short *min_lat = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_min_lat);
	const int cfg_max_lat = MAX_LAT;
	unsigned short *max_lat = (unsigned short *)bpf_map_lookup_elem(&settings, &cfg_max_lat);

	if(!protocol || !port || !percent || !action) {
		// matching parameters are not initialized -> stop processing packet
		return TC_ACT_OK;
	}

	if(!packet_is_match(skb, protocol, port, percent)) {
		// packet does not match criteria -> ignore
		return TC_ACT_OK;
	}
	
	if(last_tstamp > 0) {
		skb->tstamp = last_tstamp + (1 * time_ms);
		last_tstamp = skb->tstamp;
	}

	// only perform action if we're within defined percentage
	unsigned int rnd = bpf_get_prandom_u32() % 100;
	if(rnd >= (unsigned int)*percent) {
		return 0;
	}

	switch(*action) {
		case ACTION_DROP:
			// drop packet immediately -> no further processing
			return TC_ACT_SHOT;
		case ACTION_JITTER:
			if(!min_lat || !max_lat) {
				return TC_ACT_OK;
			}
			// delay packet by a fixed amount of time and preserve the packet order
			return delay_packet(skb, min_lat, max_lat, 0, 1);
		case ACTION_REORDER:
			if(!min_lat || !max_lat) {
				return TC_ACT_OK;
			}
			// delay packet by varying amounts of time and do not preserve packet order
			return delay_packet(skb, min_lat, max_lat, 1, 0);
	}

    return TC_ACT_OK;
}



