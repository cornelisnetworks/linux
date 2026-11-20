// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Debug code
 *
 * pdbg and pvdbg macros are enabled as follows:
 * --------------------------------------------------------------------------
 * # Enable for a specific source file
 * echo 'file <filename>.c +p' > /sys/kernel/debug/dynamic_debug/control
 * # Enable for an entire module
 * echo 'module <module_name> +p' > /sys/kernel/debug/dynamic_debug/control
 *
 * Also, make sure console log level > 7 to allow debug messages.
 *
 */

#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/ptp_classify.h>
#ifndef PTP_GEN_PORT
#define PTP_GEN_PORT 320
#endif

#include "eth_main.h"

#define NEWLINE "\n    "

struct string {
		char    *buf;
		u32     size;
		u32     offset;
};

/**
 *  string_init - Initial dynamic string object
 *  @s: pointer to string object
 *  @buffer: storage for string data
 *  @length: buffer length
 */
static void string_init(struct string *s,
			char *buffer,
			unsigned int length)
{
	s->offset = 0;
	s->size = length;
	s->buf = buffer;
	s->buf[0] = '\0';
}

/**
 * pr_string - print to a string
 * @s: pointer to string object
 * @format: printf format string
 *
 * Returns number of characters printed.
 */
static int pr_string(struct string *s,
		     const char *format,
			...)
{
	int rc;
	va_list args;

	va_start(args, format);
	rc = vscnprintf(s->buf + s->offset, s->size - s->offset, format, args);
	va_end(args);

	s->offset += rc;
	if (s->offset >= s->size)
		s->offset = 0; /* wrap */

	return rc;
}

/**
 * pr_arp - prints ARP details
 * @s: pointer to string object
 * @skb: socket buffer containing ARP
 * @payload: pointer to payload data
 * @plen: payload length
 */
static void pr_arp(struct string *s,
		   struct sk_buff *skb,
		char **payload,
		u32 *plen)
{
	struct arphdr *arp = arp_hdr(skb);
	u8 *arp_ptr = (u8 *)(arp + 1);
	u8 *smac, *dmac;
	__be32 sip, dip;

	if ((u8 *)arp < skb->data ||
	    (u8 *)arp + sizeof(*arp) > skb->data + skb_headlen(skb))
		return;
	if (arp->ar_hln != ETH_ALEN || arp->ar_pln != sizeof(sip) ||
	    (u8 *)(arp + 1) + 2 * (ETH_ALEN + sizeof(sip)) >
		    skb->data + skb_headlen(skb))
		return;

	if (arp->ar_pro != htons(ETH_P_IP))
		return;

	pr_string(s, "%s", NEWLINE);
	switch (arp->ar_op) {
	case htons(ARPOP_REQUEST):
		pr_string(s, "REQUEST: ");
		break;
	case htons(ARPOP_REPLY):
		pr_string(s, "REPLY: ");
		break;
	default:
		pr_string(s, "Unknown ARP op 0x%x: ", arp->ar_op);
		return;
	}

	smac = arp_ptr;
	arp_ptr += arp->ar_hln;
	memcpy(&sip, arp_ptr, arp->ar_pln);
	arp_ptr += arp->ar_pln;
	dmac = arp_ptr;
	arp_ptr += arp->ar_hln;
	memcpy(&dip, arp_ptr, arp->ar_pln);

	pr_string(s, "sMAC %pM sIP %pI4 dMAC %pM dIP %pI4", smac, &sip, dmac, &dip);

	/* no remaining payload for ARP */
	*payload = NULL;
	*plen = 0;
}

/**
 * find_ipv4_payload - calculate offset and length of IPV4 payload
 * @skb: SKB
 * @payload: set to start of payload on return
 * @plen: set to payload length on return
 *
 * Returns 0 on success, else -ERRNO.
 */
static int find_ipv4_payload(struct sk_buff *skb,
			     char **payload,
			     u32 *plen)
{
	struct iphdr *iph;
	u32 ihl;
	u32 ip_len;

	/* must be able to read the fixed IPv4 header first. */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return -EINVAL;
	iph = ip_hdr(skb);
	ihl = ip_hdrlen(skb);

	if (ihl < sizeof(struct iphdr))
		return -EINVAL;

	ip_len = min_t(u32, skb->len, ntohs(iph->tot_len));
	if (ip_len < ihl)
		return -EINVAL;

	*payload = (u8 *)iph + ihl;
	*plen = ip_len - ihl;

	return 0;
}

/**
 * pr_ip - prints IPv4 details
 * @s: pointer to string object
 * @skb: pointer to SKB
 * @payload: pointer to payload data
 * @plen: payload length
 */
static void pr_ip(struct string *s,
		  struct sk_buff *skb,
		  char **payload,
		  u32 *plen)
{
	struct iphdr *iph = ip_hdr(skb);

	if (!iph || iph->version != 4)
		return;

	pr_string(s, "%sIPv4: len %u tot_len %u ID 0x%04x ", NEWLINE, iph->ihl * 4,
		  ntohs(iph->tot_len), ntohs(iph->id));
	pr_string(s, "proto 0x%x csum 0x%04x ", iph->protocol,
		  ntohs((__force __be16)iph->check));
	pr_string(s, "sIP %pI4 dIP %pI4", &iph->saddr, &iph->daddr);

	if (*plen && find_ipv4_payload(skb, payload, plen)) {
		/* Unable to determine payload */
		*payload = NULL;
		*plen = 0;
	}
}

/**
 * find_ipv6_payload - calculate offset and length of payload
 * @skb: SKB
 * @payload: set to start of payload on return
 * @plen: set to payload length on return
 *
 * Return 0 on success, negative otherwise.
 */
static int find_ipv6_payload(struct sk_buff *skb,
			     char **payload,
			     u32 *plen)
{
	struct ipv6hdr *ip6h;
	u32 paylen;

	/* Ensure IPv6 base header is accessible */
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return -EINVAL;
	ip6h = ipv6_hdr(skb);
	paylen = ntohs(ip6h->payload_len);

	if (skb->len < sizeof(struct ipv6hdr))
		return -EINVAL;

	paylen = min_t(u32, paylen, skb->len - sizeof(struct ipv6hdr));
	*payload = (u8 *)ip6h + sizeof(struct ipv6hdr);
	*plen = paylen;

	return 0;
}

/**
 * pr_ipv6 - prints IPv6 details
 * @s: pointer to string object
 * @skb: pointer to SKB
 * @payload: pointer to payload data
 * @plen: payload length
 */
static void pr_ipv6(struct string *s,
		    struct sk_buff *skb,
		char **payload,
		u32 *plen)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);

	if (!skb_network_header(skb) || !skb_network_header_len(skb))
		return;

	if (!iph || iph->version != 6)
		return;

	pr_string(s, "%sIPv6: len %u hop_limit %u ", NEWLINE, ntohs(iph->payload_len),
		  iph->hop_limit);
	pr_string(s, "src IP %pI6 dest IP %pI6", &iph->saddr, &iph->daddr);

	if (*plen && find_ipv6_payload(skb, payload, plen)) {
		*payload = NULL;
		*plen = 0;
	}
}

/**
 * find_vlan_inner_payload_range - calculate offset and length of inner payload
 * @skb: SKB
 * @inner_proto: protocol of encapsulated frame
 * @payload: set to start of payload on return
 * @plen: set to payload length on return
 *
 * Return 0 on success, negative otherwise.
 */
static int find_vlan_inner_payload(struct sk_buff *skb,
				   __be16 *inner_proto,
				char **payload,
				u32 *payload_len)
{
	int depth;
	int off;
	__be16 proto;

	if (!pskb_may_pull(skb, ETH_HLEN))
		return -EINVAL;

	proto = __vlan_get_protocol(skb, skb->protocol, &depth);
	if (!proto)
		return -EINVAL;

	/* Convert 'depth from MAC header' into an offset from skb->data */
	off = (skb_mac_header(skb) + depth) - skb->data;
	if (off < 0 || off > skb->len)
		return -EINVAL;

	*inner_proto  = proto;
	*payload      = skb->data + off;
	*payload_len  = skb->len - off;

	return 0;
}

/**
 * pr_8021q - print VLAN info
 * @s: string pointer
 * @skb: SKB pointer
 */
static void pr_8021q(struct string *s,
		     struct sk_buff *skb,
		char **payload,
		u32 *plen)
{
	u16 tci;
	__be16 proto;
	struct vlan_ethhdr *vlan_hdr = vlan_eth_hdr(skb);

	if (!vlan_hdr)
		return;

	tci = ntohs(vlan_hdr->h_vlan_TCI);
	pr_string(s, "%ssMAC %pM dMAC %pM ", NEWLINE, vlan_hdr->addrs.h_source,
		  vlan_hdr->addrs.h_dest);
	pr_string(s, "VID %u CFI 0x%x PRIO 0x%x encap_proto 0x%04x", tci & VLAN_VID_MASK,
		  tci & VLAN_CFI_MASK, (tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT,
		 ntohs(vlan_hdr->h_vlan_encapsulated_proto));

	if (*plen && find_vlan_inner_payload(skb, &proto, payload, plen)) {
		*payload = NULL;
		*plen = 0;
	}
}

/**
 *
 * Returns 0 on success, else -ERRNO.
 */
static int find_tcp_udp_payload(struct sk_buff *skb,
				char **payload,
				u32 *payload_len)
{
	u32 off = 0;          /* offset from skb->data (Ethernet header start) */
	int depth;
	__be16 proto;
	const struct ethhdr *eth;

	*payload = NULL;
	*payload_len = 0;

	/* Need Ethernet header */
	if (!pskb_may_pull(skb, ETH_HLEN))
		return -EINVAL;

	eth = (const struct ethhdr *)skb_mac_header(skb);
	proto = eth->h_proto;
	off = ETH_HLEN;

	/* Skip up to 2 VLAN tags (802.1Q / 802.1AD QinQ) */
	for (depth = 0; depth < 2; depth++) {
		const struct vlan_hdr *vh;

		if (proto != htons(ETH_P_8021Q) && proto != htons(ETH_P_8021AD))
			break;

		if (!pskb_may_pull(skb, off + VLAN_HLEN))
			return -EINVAL;

		vh = (const struct vlan_hdr *)(skb->data + off);
		proto = vh->h_vlan_encapsulated_proto;
		off += VLAN_HLEN;
	}

	/* ---------------- IPv4 ---------------- */
	if (proto == htons(ETH_P_IP)) {
		const struct iphdr *iph;
		u32 ihl, ip_len, l3_end, l4_off;

		if (!pskb_may_pull(skb, off + sizeof(*iph)))
			return -EINVAL;

		iph = (const struct iphdr *)(skb->data + off);
		if (iph->version != 4)
			return -EINVAL;

		ihl = iph->ihl * 4;
		if (ihl < sizeof(*iph))
			return -EINVAL;

		/* Bound parsing to IPv4 total length (excludes L2) */
		ip_len = ntohs(iph->tot_len);
		if (ip_len < ihl)
			return -EINVAL;

		l3_end = off + ip_len;
		if (l3_end > skb->len)
			return -EINVAL; /* truncated */

		/*
		 * If fragmented and not the first fragment, L4 header isn't present.
		 * (For debug, just reject fragmentation.)
		 */
		if ((ntohs(iph->frag_off) & IP_OFFSET) != 0)
			return -EOPNOTSUPP;

		l4_off = off + ihl;

		if (iph->protocol == IPPROTO_TCP) {
			const struct tcphdr *th;
			u32 thl, pl_off;

			if (!pskb_may_pull(skb, l4_off + sizeof(*th)))
				return -EINVAL;

			th = (const struct tcphdr *)(skb->data + l4_off);
			thl = th->doff * 4;
			if (thl < sizeof(*th))
				return -EINVAL;

			if (!pskb_may_pull(skb, l4_off + thl))
				return -EINVAL;

			pl_off = l4_off + thl;
			if (pl_off > l3_end)
				return -EINVAL;

			*payload = skb->data + pl_off;
			*payload_len = l3_end - pl_off;
			return 0;
		}

		if (iph->protocol == IPPROTO_UDP) {
			const struct udphdr *uh;
			u32 udp_len, pl_off;

			if (!pskb_may_pull(skb, l4_off + sizeof(*uh)))
				return -EINVAL;

			uh = (const struct udphdr *)(skb->data + l4_off);

			/*
			 * UDP length includes header+payload and is authoritative.
			 * Bound it by IPv4 total length to avoid including padding/FCS.
			 */
			udp_len = ntohs(uh->len);
			if (udp_len < sizeof(*uh))
				return -EINVAL;

			if (l4_off + udp_len > l3_end)
				return -EINVAL;

			pl_off = l4_off + sizeof(*uh);
			*payload = skb->data + pl_off;
			*payload_len = udp_len - sizeof(*uh);
			return 0;
		}

		return -EPROTONOSUPPORT;
	}

	/* ---------------- IPv6 ---------------- */
	if (proto == htons(ETH_P_IPV6)) {
#if IS_ENABLED(CONFIG_IPV6)
		const struct ipv6hdr *ip6h;
		u32 paylen, l3_end;
		u8 nexthdr;
		__be16 frag_off = 0;
		int l4_off;

		if (!pskb_may_pull(skb, off + sizeof(*ip6h)))
			return -EINVAL;

		ip6h = (const struct ipv6hdr *)(skb->data + off);
		nexthdr = ip6h->nexthdr;

		/*
		 * Bound parsing to IPv6 payload_len when non-zero.
		 * (Does not attempt to support IPv6 jumbograms in debug code.)
		 */
		paylen = ntohs(ip6h->payload_len);
		if (paylen) {
			l3_end = off + sizeof(*ip6h) + paylen;
			if (l3_end > skb->len)
				return -EINVAL; /* truncated */
		} else {
			/* payload_len == 0 could be jumbogram; for debug, fall back */
			l3_end = skb->len;
		}

		/* Skip IPv6 extension headers to locate L4 */
		l4_off = ipv6_skip_exthdr(skb, off + sizeof(*ip6h),
					  &nexthdr, &frag_off);
		if (l4_off < 0)
			return -EINVAL;

		/* If fragmented, TCP/UDP header may not be present; reject for debug. */
		if (frag_off)
			return -EOPNOTSUPP;

		if (nexthdr == IPPROTO_TCP) {
			const struct tcphdr *th;
			u32 thl, pl_off;

			if (!pskb_may_pull(skb, l4_off + sizeof(*th)))
				return -EINVAL;

			th = (const struct tcphdr *)(skb->data + l4_off);
			thl = th->doff * 4;
			if (thl < sizeof(*th))
				return -EINVAL;

			if (!pskb_may_pull(skb, l4_off + thl))
				return -EINVAL;

			pl_off = l4_off + thl;
			if ((u32)pl_off > l3_end)
				return -EINVAL;

			*payload = skb->data + pl_off;
			*payload_len = l3_end - pl_off;
			return 0;
		}

		if (nexthdr == IPPROTO_UDP) {
			const struct udphdr *uh;
			u32 udp_len, pl_off;

			if (!pskb_may_pull(skb, l4_off + sizeof(*uh)))
				return -EINVAL;

			uh = (const struct udphdr *)(skb->data + l4_off);

			udp_len = ntohs(uh->len);
			if (udp_len < sizeof(*uh))
				return -EINVAL;

			if ((u32)l4_off + udp_len > l3_end)
				return -EINVAL;

			pl_off = l4_off + sizeof(*uh);
			*payload = skb->data + pl_off;
			*payload_len = udp_len - sizeof(*uh);
			return 0;
		}

		return -EPROTONOSUPPORT;
#else
		return -EAFNOSUPPORT;
#endif
	}

	return -EPROTONOSUPPORT;
}

/**
 * pr_transport - prints transport (TCP, UDP, etc.) details
 * @s: pointer to string
 * @skb: point to SKB
 */
static int pr_transport(struct string *s,
			u32 protocol,
			struct sk_buff *skb,
			char **payload,
			u32 *plen)
{
	int rc = 0;

	if (!skb_transport_header_was_set(skb))
		return -EINVAL;

	*payload = NULL;
	*plen = 0;

	pr_string(s, "%s", NEWLINE);
	switch (protocol) {
	case IPPROTO_IP:
	case IPPROTO_TCP: {
		struct tcphdr *tcph = tcp_hdr(skb);

		pr_string(s, "TCP: sPort %u dPort %u len %u window %u csum 0x%04x",
			  ntohs(tcph->source), ntohs(tcph->dest), tcph->doff * 4,
			ntohs(tcph->window), ntohs((__force __be16)tcph->check));
		rc = find_tcp_udp_payload(skb, payload, plen);
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr *udph = udp_hdr(skb);

		pr_string(s, "UDP: sPort %u dPort %u len %u csum 0x%04x",
			  ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len),
			ntohs((__force __be16)udph->check));
		if ((ntohs(udph->source) == PTP_EV_PORT || ntohs(udph->source) == PTP_GEN_PORT)) {
			char *msg_type = "";
			struct ptp_header *ptph = (struct ptp_header *)(((u8 *)udph) + sizeof(*udph));

			switch (ptph->tsmt & 0xf) {
			case PTP_MSGTYPE_SYNC:
				msg_type = "sync";
				break;
			case PTP_MSGTYPE_DELAY_REQ:
				msg_type = "delay req";
				break;
			case PTP_MSGTYPE_PDELAY_REQ:
				msg_type = "pdelay req";
				break;
			case PTP_MSGTYPE_PDELAY_RESP:
				msg_type = "pdelay rsp";
				break;
			case 0x8:
				msg_type = "follow up";
				break;
			case 0x9:
				msg_type = "delay rsp";
				break;
			case 0xb:
				msg_type = "announce";
				break;
			case 0xd:
				msg_type = "management";
				break;
			default:
				msg_type = "unknown";
			}
			pr_string(s, "%sPTP: msg_type %s seq %u", NEWLINE, msg_type,
				  be16_to_cpu(ptph->sequence_id));
			rc = find_tcp_udp_payload(skb, payload, plen);
		}
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr *icmph = icmp_hdr(skb);

		pr_string(s, "ICMP: type %d code %d id %u seq %u",
			  icmph->type, icmph->code, ntohs(icmph->un.echo.id),
			ntohs(icmph->un.echo.sequence));
		break;
	}
	case IPPROTO_IGMP: {
		struct igmphdr *igmph = igmp_hdr(skb);

		pr_string(s, "IGMP: type 0x%02x code 0x%02x group %pI4", igmph->type,
			  igmph->code, &igmph->group);
		break;
	}
	case IPPROTO_RAW:
		break;
	default:
		pr_string(s, "unsupported protocol %u skb->protocol %u", protocol, skb->protocol);
	}

	return rc;
}

/**
 * pr_skb - print SKB info
 * @skb: socket buffer to print
 * @max_plen: max bytes of payload to print (zero for none)
 */
void pr_skb(struct sk_buff *skb,
	    unsigned int max_plen,
	char *buffer,
	unsigned int buffer_len)
{
	char *payload = skb->data;
	u32 payload_len = max_plen;
	struct string _s, *s = &_s;
	struct ethhdr *eth;

	if (!skb || !buffer || !buffer_len)
		return;

	string_init(s, buffer, buffer_len);

	pr_string(s, "SKB %p q_id %u len %u", skb, skb->queue_mapping, skb->len);

	/* Print L2 header */
	eth = eth_hdr(skb);
	if (!eth)
		goto dump;
	pr_string(s, "%ssMAC %pM dMAC %pM protocol 0x%04x ", NEWLINE, eth->h_source,
		  eth->h_dest, ntohs(eth->h_proto));

	/* Show additional L2 detail for specific protocols. */
	switch (ntohs(eth->h_proto)) {
	case ETH_P_1588:
		pr_string(s, "(PTP)");
		break;
	case ETH_P_ARP:
		pr_string(s, "(ARP)");
		pr_arp(s, skb, &payload, &payload_len);
		break;
	case ETH_P_RARP:
		pr_string(s, "(RARP)");
		break;
	case ETH_P_IPV6:
		pr_string(s, "(IPV6 over bluebook)");
		pr_ipv6(s, skb, &payload, &payload_len);
		pr_transport(s, ipv6_hdr(skb)->nexthdr, skb, &payload, &payload_len);
		break;
	case ETH_P_8021Q:
		pr_string(s, "(802.1Q VLAN)");
		pr_8021q(s, skb, &payload, &payload_len);
		break;
	case ETH_P_8021AD:
		pr_string(s, "(802.1ad Service VLAN (QinQ))");
		break;
	case ETH_P_IP:
		pr_string(s, "(IP)");
		pr_ip(s, skb, &payload, &payload_len);
		pr_transport(s, ip_hdr(skb)->protocol, skb, &payload, &payload_len);
		break;
	default:
		pr_string(s, "(unknown protocol 0x%x)", ntohs(eth->h_proto));
	}

dump:
	/* Dump first payload_len bytes of payload data */
	if (payload_len) {
		int i;
		unsigned int length = min_t(unsigned int, skb->len, payload_len);

		length = min_t(unsigned int, length, max_plen);
		for (i = 0; i < length; i++) {
			if (i % 16 == 0)
				pr_string(s, "%s%04x: ", NEWLINE, i);
			pr_string(s, "%02x ", payload[i]);
		}
	}
}

