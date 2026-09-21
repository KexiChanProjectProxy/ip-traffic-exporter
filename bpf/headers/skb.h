/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * UAPI struct __sk_buff as of Linux 6.12 (include/uapi/linux/bpf.h).
 * Copied here so the build does not depend on the host's kernel headers.
 * Only ever appended to upstream, so it is safe for older kernels as long as
 * the program sticks to fields they know about.
 */
#pragma once

#define __bpf_md_ptr(type, name) \
	union {                      \
		type name;               \
		__u64 : 64;              \
	} __attribute__((aligned(8)))

struct bpf_flow_keys;
struct bpf_sock;

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;

	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8 tstamp_type;
	__u32 : 24;
	__u64 hwtstamp;
};
