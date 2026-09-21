// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// Per-IP traffic accounting on a TCX ingress/egress hook.
//
// Every packet seen on the interface is attributed to its source address
// (as tx, i.e. that host's upload) and/or its destination address (as rx,
// that host's download), but only for addresses inside the configured local
// networks. Accounting is direction-agnostic: a packet crosses a given
// device's ingress or egress hook exactly once, so attaching the same code to
// both hooks never double counts.
//
// The program never modifies or drops packets: it always returns TCX_NEXT.

#include "common.h"
#include "bpf_endian.h"
#include "skb.h"

char __license[] SEC("license") = "Dual BSD/GPL";

#define TCX_NEXT -1

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define BPF_NOEXIST 1
#define BPF_F_NO_PREALLOC 1

// Link-layer header length of the attached device: 14 for Ethernet-like
// devices, 0 for L3 devices (tun, ppp, wireguard...). Set by the loader.
volatile const __u32 l2_len = ETH_HLEN;

// IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d) so a single map
// covers both families.
struct addr {
	__u8 b[16];
};

struct counters {
	__u64 rx_bytes;
	__u64 rx_packets;
	__u64 tx_bytes;
	__u64 tx_packets;
};

struct lpm_key {
	__u32 prefixlen;
	__u8 addr[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 16384); // overridden by the loader
	__type(key, struct addr);
	__type(value, struct counters);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u8);
} local_nets SEC(".maps");

struct iphdr_min {
	__u8 ver_ihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__u8 saddr[4];
	__u8 daddr[4];
};

struct ipv6hdr_min {
	__be32 ver_tc_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u8 saddr[16];
	__u8 daddr[16];
};

static __always_inline void account(struct addr *a, int rx, __u64 bytes, __u64 pkts)
{
	struct counters *c = bpf_map_lookup_elem(&stats, a);

	if (!c) {
		struct lpm_key k = {.prefixlen = 128};
		struct counters zero = {};

		__builtin_memcpy(k.addr, a->b, sizeof(k.addr));
		if (!bpf_map_lookup_elem(&local_nets, &k))
			return;
		// Another CPU may win the race; either way the entry exists after.
		bpf_map_update_elem(&stats, a, &zero, BPF_NOEXIST);
		c = bpf_map_lookup_elem(&stats, a);
		if (!c)
			return;
	}

	// Per-CPU values: no atomics needed.
	if (rx) {
		c->rx_bytes += bytes;
		c->rx_packets += pkts;
	} else {
		c->tx_bytes += bytes;
		c->tx_packets += pkts;
	}
}

static __always_inline int handle(struct __sk_buff *skb)
{
	struct addr src = {}, dst = {};
	__u32 off = l2_len;
	__u32 l3_hlen;
	__u8 l4proto;
	__u16 proto;

	if (off) {
		__be16 h;

		if (bpf_skb_load_bytes(skb, 12, &h, sizeof(h)) < 0)
			return TCX_NEXT;
		proto = bpf_ntohs(h);

		// VLAN tags that were not stripped by hardware offload (up to QinQ).
#pragma unroll
		for (int i = 0; i < 2; i++) {
			if (proto != ETH_P_8021Q && proto != ETH_P_8021AD)
				break;
			if (bpf_skb_load_bytes(skb, off + 2, &h, sizeof(h)) < 0)
				return TCX_NEXT;
			proto = bpf_ntohs(h);
			off += 4;
		}
	} else {
		__u8 ver;

		if (bpf_skb_load_bytes(skb, 0, &ver, sizeof(ver)) < 0)
			return TCX_NEXT;
		ver >>= 4;
		proto = ver == 4 ? ETH_P_IP : ver == 6 ? ETH_P_IPV6 : 0;
	}

	if (proto == ETH_P_IP) {
		struct iphdr_min ip;

		if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)) < 0)
			return TCX_NEXT;
		l3_hlen = (ip.ver_ihl & 0x0f) * 4;
		l4proto = ip.protocol;
		src.b[10] = src.b[11] = 0xff;
		dst.b[10] = dst.b[11] = 0xff;
		__builtin_memcpy(&src.b[12], ip.saddr, 4);
		__builtin_memcpy(&dst.b[12], ip.daddr, 4);
	} else if (proto == ETH_P_IPV6) {
		struct ipv6hdr_min ip6;

		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)) < 0)
			return TCX_NEXT;
		// Extension headers are not walked; they only matter for the GSO
		// header estimate below, where missing them is a tiny error.
		l3_hlen = sizeof(ip6);
		l4proto = ip6.nexthdr;
		__builtin_memcpy(src.b, ip6.saddr, 16);
		__builtin_memcpy(dst.b, ip6.daddr, 16);
	} else {
		return TCX_NEXT;
	}

	// skb->len counts L2 bytes (no FCS), same as the interface counters.
	__u64 bytes = skb->len;
	__u64 pkts = 1;
	__u32 segs = skb->gso_segs;

	// GRO/GSO super-packets carry one set of headers for gso_segs wire
	// packets; add the headers of the other segments back.
	if (segs > 1) {
		__u32 hlen = off + l3_hlen;

		if (l4proto == IPPROTO_TCP) {
			__u8 doff;

			if (bpf_skb_load_bytes(skb, hlen + 12, &doff, sizeof(doff)) == 0)
				hlen += (doff >> 4) * 4;
		} else if (l4proto == IPPROTO_UDP) {
			hlen += 8;
		}
		bytes += (__u64)(segs - 1) * hlen;
		pkts = segs;
	}

	account(&src, 0, bytes, pkts);
	account(&dst, 1, bytes, pkts);
	return TCX_NEXT;
}

SEC("tcx/ingress")
int ingress(struct __sk_buff *skb)
{
	return handle(skb);
}

SEC("tcx/egress")
int egress(struct __sk_buff *skb)
{
	return handle(skb);
}
