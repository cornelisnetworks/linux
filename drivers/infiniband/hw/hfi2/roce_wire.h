/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * RoCEv2 wire codec: build and parse Ethernet/IPv4/UDP/BTH/extended-header
 * frames, and compute the RoCEv2 ICRC.  Pure header math, no CSR or DMA
 * access, so it is unit-testable off the hot path.  Stage 1 is IPv4 only;
 * IPv6 is a documented follow-up.
 */
#ifndef _HFI2_ROCE_WIRE_H
#define _HFI2_ROCE_WIRE_H

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <rdma/ib_hdrs.h>
#include <rdma/ib_pack.h>

/* RoCEv2 well-known UDP destination port (IANA). */
#define HFI2_ROCE_UDP_DPORT 4791

/* 24-bit PSN space (BTH). */
#define HFI2_ROCE_PSN_MASK 0xffffffu

/* Fixed header/trailer sizes for the IPv4 RoCEv2 frame we build. */
#define HFI2_ROCE_ETH_HDR_BYTES  sizeof(struct ethhdr)   /* 14 */
#define HFI2_ROCE_IPV4_HDR_BYTES sizeof(struct iphdr)    /* 20 */
#define HFI2_ROCE_UDP_HDR_BYTES  sizeof(struct udphdr)   /* 8  */
#define HFI2_ROCE_BTH_BYTES      12
#define HFI2_ROCE_DETH_BYTES     8
#define HFI2_ROCE_RETH_BYTES     sizeof(struct ib_reth)  /* 16 */
#define HFI2_ROCE_ATOMIC_ETH_BYTES sizeof(struct ib_atomic_eth)
#define HFI2_ROCE_AETH_BYTES     4
#define HFI2_ROCE_ATOMIC_ACK_ETH_BYTES sizeof(__be64)
#define HFI2_ROCE_IMMDT_BYTES    4
#define HFI2_ROCE_IETH_BYTES     4
#define HFI2_ROCE_ICRC_BYTES     4

#define HFI2_ROCE_READ_EXT_BYTES	24
#define HFI2_ROCE_READ_EXT_VERSION	1
#define HFI2_ROCE_READ_EXT_REPLY_WRITE	BIT(0)
#define HFI2_ROCE_READ_EXT_SOFTWARE_PLACE	BIT(1)
#define HFI2_ROCE_READ_EXT_DIRECT_FLAGS	HFI2_ROCE_READ_EXT_REPLY_WRITE
#define HFI2_ROCE_READ_EXT_SOFTWARE_FLAGS \
	(HFI2_ROCE_READ_EXT_REPLY_WRITE | HFI2_ROCE_READ_EXT_SOFTWARE_PLACE)

struct hfi2_roce_read_ext {
	u8 version;
	u8 flags;
	__be16 reserved0;
	__be64 dest_va;
	__be32 dest_rkey;
	__be32 request_id;
	__be32 reserved1;
} __packed;

/*
 * Everything before the BTH for an IPv4 RoCEv2 frame.  The wire codec builds
 * headers starting at the Ethernet header; the BTH sits at this offset.
 */
#define HFI2_ROCE_IPV4_BTH_OFFSET \
	(HFI2_ROCE_ETH_HDR_BYTES + HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES)

#define HFI2_ROCE_NO_VLAN 0xffff

static inline size_t hfi2_roce_ipv4_bth_offset(u16 vlan_id)
{
	return HFI2_ROCE_IPV4_BTH_OFFSET +
		(vlan_id != HFI2_ROCE_NO_VLAN ? VLAN_HLEN : 0);
}

/*
 * Bytes a payload costs beyond itself on the wire: the L3/L4 headers the
 * netdev MTU covers, the BTH, the largest extension header a data packet
 * carries (RETH on a first/only RDMA WRITE), the 4-byte pad, and the ICRC.
 */
#define HFI2_ROCE_L3_ENCAP_BYTES \
	(HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES + \
	 HFI2_ROCE_BTH_BYTES + HFI2_ROCE_RETH_BYTES + 3 + HFI2_ROCE_ICRC_BYTES)

/* Largest payload one built frame can hold (see HFI2_ROCE_TXBUF_SZ). */
#define HFI2_ROCE_MAX_PAYLOAD 8192

/*
 * L2/L3/L4 addressing for one RoCEv2 endpoint pair, resolved from the QP's
 * AH / GID attributes.  All multi-byte fields are host order; the codec
 * converts on the wire.
 */
struct hfi2_roce_wire_addr {
	u8  smac[ETH_ALEN];
	u8  dmac[ETH_ALEN];
	__be32 saddr;           /* IPv4, network order */
	__be32 daddr;           /* IPv4, network order */
	u16 vlan_id;            /* 0xffff = no VLAN */
	u16 udp_sport;          /* per-QP entropy for ECMP */
	u8  traffic_class;      /* DSCP<<2 | ECN, from GRH tclass */
	u8  hop_limit;          /* IPv4 TTL */
	u8  vlan_prio;          /* 802.1Q PCP */
	bool pfc_tag;           /* PFC priority resolved onto an operational VL */
};

/*
 * Parsed view of an inbound IPv4 RoCEv2 frame.  Pointers reference into the
 * caller's buffer (no copy).  @payload/@payload_len cover the IB payload only
 * (transport headers and ICRC excluded).
 */
struct hfi2_roce_wire_rx {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct ib_other_headers *ohdr;   /* BTH + extended headers */
	u8  opcode;
	u16 pkey;                        /* host order */
	u32 dest_qpn;                    /* host order */
	u32 psn;                         /* host order, 24-bit */
	u8  pad_count;
	bool ack_req;
	bool vlan_tagged;
	u16 vlan_id;
	void *payload;
	u32 payload_len;
	u32 icrc;                        /* trailing ICRC as carried, host order */
	u8  eal_end_state;               /* EAL ingress end_state, 0 if none */
};

/*
 * Build the Ethernet+IPv4+UDP header block at @buf for a RoCEv2 frame whose
 * IB portion (BTH through payload, plus the 4 ICRC bytes that EAL will append)
 * is @ib_len_with_icrc bytes.  IP/UDP length fields are pre-sized to include
 * the ICRC per the EAL egress contract.  Builds an 802.1Q header when
 * @addr->vlan_id is not HFI2_ROCE_NO_VLAN.  Returns the BTH offset from the
 * Ethernet header.
 */
size_t hfi2_roce_build_eth_ipv4_udp(void *buf,
				    const struct hfi2_roce_wire_addr *addr,
				    size_t ib_len_with_icrc);

/*
 * Build a 12-byte BTH at @buf.  @opcode is an IB_OPCODE_* value; psn/dest_qpn
 * are host order and masked to 24 bits.
 */
void hfi2_roce_build_bth(void *buf, u8 opcode, u16 pkey, u32 dest_qpn,
			 bool ack_req, bool solicited, u8 pad_count, u32 psn);

/* Build a 16-byte RETH.  All arguments are host order. */
void hfi2_roce_build_reth(void *buf, u64 vaddr, u32 rkey, u32 length);

/* Build a 4-byte AETH (ACK/NAK).  @syndrome is the IB AETH syndrome byte. */
void hfi2_roce_build_aeth(void *buf, u8 syndrome, u32 msn);

/*
 * Compute the RoCEv2 ICRC over a fully built IPv4 frame in @buf.  @frame_len
 * is the total Ethernet frame length EXCLUDING the trailing ICRC.  Returns the
 * ICRC in host order (caller appends as big-endian if inserting in software).
 * Mirrors drivers/infiniband/sw/rxe/rxe_icrc.c.
 */
u32 hfi2_roce_icrc_ipv4(const void *buf, size_t frame_len);

/*
 * Parse an inbound IPv4 RoCEv2 frame starting at the Ethernet header.
 * @len is an upper bound on readable bytes at @buf (the eager buffer may be
 * larger than the frame); the actual extent is taken from the IPv4 total-length
 * field.  EAL strips the ICRC on ingress, so it is absent from the buffer even
 * though the IP/UDP length fields still count it.  Returns 0 on success and
 * fills @out; negative errno if the frame is not a well-formed IPv4/UDP 4791
 * RoCE packet.
 */
int hfi2_roce_parse_ipv4(void *buf, size_t len, struct hfi2_roce_wire_rx *out);

#endif /* _HFI2_ROCE_WIRE_H */
