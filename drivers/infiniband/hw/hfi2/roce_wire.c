// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * RoCEv2 wire codec (IPv4).  See roce_wire.h.  Build/parse routines here are
 * pure header math; the ICRC follows the RoCEv2 invariant-field rules in IB
 * spec A17.3.3, mirroring drivers/infiniband/sw/rxe/rxe_icrc.c so we match
 * soft-RoCE and ConnectX byte-for-byte.
 */

#include <linux/crc32.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/ip.h>

#include "roce_wire.h"

/*
 * Extended-transport-header size for the transport headers between the BTH
 * and the payload of the given opcode.  Anything else has no extended header
 * (BTH-only).
 */
static size_t roce_ext_hdr_len(u8 opcode)
{
	switch (opcode) {
	case IB_OPCODE_UC_RDMA_WRITE_FIRST:
	case IB_OPCODE_UC_RDMA_WRITE_ONLY:
	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
		return HFI2_ROCE_RETH_BYTES;
	case IB_OPCODE_RC_RDMA_READ_REQUEST:
		return HFI2_ROCE_RETH_BYTES;
	case IB_OPCODE_RC_COMPARE_SWAP:
	case IB_OPCODE_RC_FETCH_ADD:
		return HFI2_ROCE_ATOMIC_ETH_BYTES;
	case IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
		return HFI2_ROCE_RETH_BYTES + HFI2_ROCE_IMMDT_BYTES;
	case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
		return HFI2_ROCE_IMMDT_BYTES;
	case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE:
		return HFI2_ROCE_IETH_BYTES;
	case IB_OPCODE_UD_SEND_ONLY:
		return HFI2_ROCE_DETH_BYTES;
	case IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE:
		return HFI2_ROCE_DETH_BYTES + HFI2_ROCE_IMMDT_BYTES;
	case IB_OPCODE_RC_ACKNOWLEDGE:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		return HFI2_ROCE_AETH_BYTES;
	case IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE:
		return HFI2_ROCE_AETH_BYTES + HFI2_ROCE_ATOMIC_ACK_ETH_BYTES;
	default:
		return 0;
	}
}

size_t hfi2_roce_build_eth_ipv4_udp(void *buf,
				    const struct hfi2_roce_wire_addr *addr,
				    size_t ib_len_with_icrc)
{
	struct ethhdr *eth = buf;
	struct iphdr *ip;
	struct udphdr *udp;
	size_t bth_offset = hfi2_roce_ipv4_bth_offset(addr->vlan_id);

	ether_addr_copy(eth->h_dest, addr->dmac);
	ether_addr_copy(eth->h_source, addr->smac);
	if (addr->vlan_id != HFI2_ROCE_NO_VLAN) {
		struct vlan_ethhdr *veth = buf;

		veth->h_vlan_proto = htons(ETH_P_8021Q);
		veth->h_vlan_TCI = htons(((u16)addr->vlan_prio << VLAN_PRIO_SHIFT) |
					(addr->vlan_id & VLAN_VID_MASK));
		veth->h_vlan_encapsulated_proto = htons(ETH_P_IP);
		ip = (struct iphdr *)(veth + 1);
	} else {
		eth->h_proto = htons(ETH_P_IP);
		ip = (struct iphdr *)(eth + 1);
	}
	udp = (struct udphdr *)(ip + 1);

	/*
	 * IB spec A17.3.1: version=4, IHL=5, DF set, protocol=UDP.  Total
	 * length and UDP length include the trailing ICRC (EAL appends the
	 * bytes but expects the length fields to already account for them).
	 */
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = addr->traffic_class;
	ip->tot_len = htons(HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES +
			    ib_len_with_icrc);
	ip->id = 0;
	ip->frag_off = htons(IP_DF);
	ip->ttl = addr->hop_limit;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = addr->saddr;
	ip->daddr = addr->daddr;
	ip->check = 0;
	ip->check = ip_fast_csum((const void *)ip, ip->ihl);

	/* IB spec A17.3.2: dport=4791, UDP checksum 0 (ICRC protects data). */
	udp->source = htons(addr->udp_sport);
	udp->dest = htons(HFI2_ROCE_UDP_DPORT);
	udp->len = htons(HFI2_ROCE_UDP_HDR_BYTES + ib_len_with_icrc);
	udp->check = 0;

	return bth_offset;
}

void hfi2_roce_build_bth(void *buf, u8 opcode, u16 pkey, u32 dest_qpn,
			 bool ack_req, bool solicited, u8 pad_count, u32 psn)
{
	__be32 *bth = buf;
	u32 w0 = ((u32)opcode << IB_BTH_OPCODE_SHIFT) |
		 ((u32)(pad_count & IB_BTH_PAD_MASK) << IB_BTH_PAD_SHIFT) |
		 pkey;

	if (solicited)
		w0 |= IB_BTH_SOLICITED;

	bth[0] = cpu_to_be32(w0);
	bth[1] = cpu_to_be32(dest_qpn & IB_QPN_MASK);
	bth[2] = cpu_to_be32((psn & HFI2_ROCE_PSN_MASK) | (ack_req ? IB_BTH_REQ_ACK : 0));
}

void hfi2_roce_build_reth(void *buf, u64 vaddr, u32 rkey, u32 length)
{
	struct ib_reth *reth = buf;

	put_ib_reth_vaddr(vaddr, reth);
	reth->rkey = cpu_to_be32(rkey);
	reth->length = cpu_to_be32(length);
}

void hfi2_roce_build_aeth(void *buf, u8 syndrome, u32 msn)
{
	__be32 *aeth = buf;

	*aeth = cpu_to_be32(((u32)syndrome << IB_AETH_CREDIT_SHIFT) |
			      (msn & IB_MSN_MASK));
}

/*
 * Compute the ICRC exactly as rxe does: seed with the masked-LRH constant,
 * CRC the IP/UDP headers with mutable fields forced to 0xff, then the BTH
 * (with the reserved QPN bits set), then the remaining transport headers and
 * payload+pad, and finally complement.  We CRC a masked copy of the L3/L4
 * headers so the caller's frame is left intact.
 */
u32 hfi2_roce_icrc_ipv4(const void *buf, size_t frame_len)
{
	const struct ethhdr *eth = buf;
	bool tagged = eth->h_proto == htons(ETH_P_8021Q);
	const struct iphdr *ip = (const void *)buf + HFI2_ROCE_ETH_HDR_BYTES +
		(tagged ? VLAN_HLEN : 0);
	const u8 *bth = (const u8 *)buf + HFI2_ROCE_IPV4_BTH_OFFSET +
		(tagged ? VLAN_HLEN : 0);
	u8 pshdr[HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES +
		 HFI2_ROCE_BTH_BYTES];
	struct iphdr *pip = (struct iphdr *)pshdr;
	struct udphdr *pudp;
	__be32 *pbth;
	size_t l34 = HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES;
	size_t rest_off = HFI2_ROCE_IPV4_BTH_OFFSET + HFI2_ROCE_BTH_BYTES +
		(tagged ? VLAN_HLEN : 0);
	u32 crc;

	/* rxe seed: CRC of 0xffffffff over 8 bytes of masked LRH. */
	crc = 0xdebb20e3;

	memcpy(pshdr, ip, l34);
	pudp = (struct udphdr *)(pshdr + HFI2_ROCE_IPV4_HDR_BYTES);
	pip->ttl = 0xff;
	pip->check = CSUM_MANGLED_0;
	pip->tos = 0xff;
	pudp->check = CSUM_MANGLED_0;

	memcpy(pshdr + l34, bth, HFI2_ROCE_BTH_BYTES);
	pbth = (__be32 *)(pshdr + l34);
	/* Reserved bits around the QPN (bth[1] high byte) are set for ICRC. */
	pbth[1] |= cpu_to_be32(~IB_QPN_MASK);

	crc = crc32_le(crc, pshdr, l34 + HFI2_ROCE_BTH_BYTES);

	/* Remaining transport headers + payload + pad, unmodified. */
	crc = crc32_le(crc, (const u8 *)buf + rest_off, frame_len - rest_off);

	return ~crc;
}

int hfi2_roce_parse_ipv4(void *buf, size_t len, struct hfi2_roce_wire_rx *out)
{
	struct ethhdr *eth = buf;
	struct iphdr *ip;
	struct udphdr *udp;
	struct ib_other_headers *ohdr;
	size_t ib_len, ext_len, ip_total, udp_len, framed, tag = 0;
	u8 opcode;

	memset(out, 0, sizeof(*out));

	if (len < HFI2_ROCE_IPV4_BTH_OFFSET + HFI2_ROCE_BTH_BYTES)
		return -EINVAL;
	ip = (struct iphdr *)(eth + 1);
	/*
	 * One 802.1Q tag: a peer tags a frame too short for the Ethernet
	 * minimum rather than padding it, and a PFC peer tags every frame.
	 * Step over it and parse the rest as if the frame were untagged.
	 */
	if (eth->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veth = buf;

		out->vlan_tagged = true;
		out->vlan_id = ntohs(veth->h_vlan_TCI) & VLAN_VID_MASK;
		if (len < VLAN_HLEN + HFI2_ROCE_IPV4_BTH_OFFSET +
			  HFI2_ROCE_BTH_BYTES ||
		    veth->h_vlan_encapsulated_proto != htons(ETH_P_IP))
			return -EPROTONOSUPPORT;
		ip = (struct iphdr *)(veth + 1);
		tag = VLAN_HLEN;
	} else if (eth->h_proto != htons(ETH_P_IP)) {
		return -EPROTONOSUPPORT;
	}

	if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
		return -EPROTONOSUPPORT;
	if (ip->ihl != 5 || ip_is_fragment(ip))
		return -EINVAL;

	ip_total = ntohs(ip->tot_len);
	if (ip_total < HFI2_ROCE_IPV4_HDR_BYTES + HFI2_ROCE_UDP_HDR_BYTES +
			       HFI2_ROCE_BTH_BYTES + HFI2_ROCE_ICRC_BYTES)
		return -EINVAL;

	udp = (struct udphdr *)(ip + 1);
	udp_len = ntohs(udp->len);
	if (udp->dest != htons(HFI2_ROCE_UDP_DPORT))
		return -EPROTONOSUPPORT;
	if (udp_len != ip_total - HFI2_ROCE_IPV4_HDR_BYTES)
		return -EINVAL;

	ohdr = (struct ib_other_headers *)((u8 *)buf + tag +
					   HFI2_ROCE_IPV4_BTH_OFFSET);
	opcode = ib_bth_get_opcode(ohdr);
	ext_len = roce_ext_hdr_len(opcode);

	/*
	 * Trust the IPv4 total-length field for the packet extent rather than
	 * @len: the eager buffer may be padded, and @len (from the RHF) counts
	 * the EAL ingress header.  IP tot_len covers IP header + UDP + IB, and
	 * per the RoCE wire spec still includes the 4 ICRC bytes -- but EAL has
	 * stripped them from the buffer, so subtract them to get the IB extent
	 * actually present.
	 */
	framed = tag + HFI2_ROCE_ETH_HDR_BYTES + ip_total;
	if (framed > len + HFI2_ROCE_ICRC_BYTES)
		return -EINVAL;
	ib_len = ip_total - HFI2_ROCE_IPV4_HDR_BYTES -
		 HFI2_ROCE_UDP_HDR_BYTES - HFI2_ROCE_ICRC_BYTES;

	out->eth = eth;
	out->ip = ip;
	out->udp = udp;
	out->ohdr = ohdr;
	out->opcode = opcode;
	out->pkey = ib_bth_get_pkey(ohdr);
	out->dest_qpn = ib_bth_get_qpn(ohdr);
	out->psn = ib_bth_get_psn(ohdr) & HFI2_ROCE_PSN_MASK;
	out->pad_count = ib_bth_get_pad(ohdr);
	out->ack_req = ib_bth_get_ackreq(ohdr);
	out->payload = (u8 *)ohdr + HFI2_ROCE_BTH_BYTES + ext_len;
	if (ib_len < HFI2_ROCE_BTH_BYTES + ext_len + out->pad_count)
		return -EINVAL;
	out->payload_len = ib_len - HFI2_ROCE_BTH_BYTES - ext_len -
			   out->pad_count;

	return 0;
}
