// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Ethernet frame reception
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/prefetch.h>
#include <linux/unaligned.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/page_pool/helpers.h>

#include "dms.h"
#include "eth_main.h"
#include "dms_roce.h"

#define RX_DROP		1
#define RX_ERROR	2

/*
 * Frames up to this size are copied and their buffer stays posted; longer
 * frames go to the stack in their buffer and a spare is posted in its
 * place (one RcvArray write per frame).
 */
static uint cne_rx_copybreak;

struct timestamp12 {
	u8 sec[6];
	u8 nsec[4];
	u8 fraction[2];
} __packed __aligned(4);

static inline u64 be48_to_cpu(const u8 *p)
{
	return ((u64)p[0] << 40) | ((u64)p[1] << 32) |
		((u64)p[2] << 24) | ((u64)p[3] << 16) |
		((u64)p[4] << 8)  | (u64)p[5];
}

static inline u64 timestamp12_sec(const struct timestamp12 *ts)
{
	return be48_to_cpu(ts->sec);
}

static inline u32 timestamp12_nsec(const struct timestamp12 *ts)
{
	return get_unaligned_be32(ts->nsec);
}

static inline u16 timestamp12_fraction(const struct timestamp12 *ts)
{
	return get_unaligned_be16(ts->fraction);
}

static inline void *hfi2_get_header(struct hfi2_ctxtdata *rcd,
				    __le32 *rhf_addr)
{
	u32 offset = rhf_hdrq_offset(rhf_to_cpu(rhf_addr));

	return (void *)(rhf_addr - rcd->rhf_offset + offset);
}

static u32 cne_rx_hash_seed __read_mostly;

/*
 * cne_rx_flow_hash - software flow hash for RPS/RFS
 * @frame: points to the Ethernet header
 * @frame_len: bytes available at @frame
 * @type: set to the hash type of a non-zero return
 *
 * CYR RSM steers on a 5-bit index (sport[4:0] XOR SMAC[4:0]) into the
 * 32-entry RMT, so distinct flows can still collide onto one context/NAPI
 * CPU; a 4-tuple skb->hash lets RPS/RFS spread them.
 *
 * Return: randomly seeded 4-tuple (L4) hash for unfragmented IPv4 TCP/UDP,
 * 2-tuple (L3) hash for other IPv4, 0 for non-IPv4 or truncated frames.
 */
static u32 cne_rx_flow_hash(const u8 *frame, u32 frame_len,
			    enum pkt_hash_types *type)
{
	u32 l3_off = ETH_HLEN;
	u32 saddr, daddr;
	const u8 *l3;
	u16 etype;
	u32 ihl;
	u8 proto;

	if (frame_len < ETH_HLEN)
		return 0;
	etype = get_unaligned_be16(frame + 12);
	if (etype == ETH_P_8021Q || etype == ETH_P_8021AD) {
		if (frame_len < ETH_HLEN + VLAN_HLEN)
			return 0;
		etype = get_unaligned_be16(frame + 16);
		l3_off += VLAN_HLEN;
	}
	if (etype != ETH_P_IP)
		return 0;

	/* Need the fixed IPv4 header for proto/ihl and the l3+12/+16 reads. */
	if (l3_off + sizeof(struct iphdr) > frame_len)
		return 0;

	net_get_random_once(&cne_rx_hash_seed, sizeof(cne_rx_hash_seed));
	l3 = frame + l3_off;
	proto = l3[9];
	ihl = (l3[0] & 0x0f) * 4;
	saddr = get_unaligned_be32(l3 + 12);
	daddr = get_unaligned_be32(l3 + 16);

	/*
	 * Only an unfragmented TCP/UDP datagram has ports at l3+ihl, and the
	 * 4-byte port read must stay within the frame.
	 */
	if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) &&
	    !(get_unaligned_be16(l3 + 6) & (IP_MF | IP_OFFSET)) &&
	    ihl >= sizeof(struct iphdr) && l3_off + ihl + 4 <= frame_len) {
		*type = PKT_HASH_TYPE_L4;
		return jhash_3words(saddr, daddr, get_unaligned_be32(l3 + ihl),
				    cne_rx_hash_seed ^ proto);
	}

	*type = PKT_HASH_TYPE_L3;
	return jhash_2words(saddr, daddr, cne_rx_hash_seed ^ proto);
}

/*
 * cne_rx_l4_sum - Recover the ones-complement sum of just the L4 segment from
 * @csum, the sum already computed over the whole L2 frame [frame .. skb->len).
 * Subtract the leading L2+L3 headers (offset 0, even) and any trailing bytes
 * beyond the L4 segment (Ethernet padding or FCS at @trail_off), using
 * csum_block_sub() so the trailing region is rotated for its byte offset.
 * This reuses the driver's single payload read instead of scanning it again.
 */
static __wsum cne_rx_l4_sum(const u8 *frame,
			    u32 frame_len,
			    __wsum csum,
			    u32 l4_off,
			    u32 l4_len)
{
	__wsum sum;
	u32 trail_off = l4_off + l4_len;

	sum = csum_sub(csum, csum_partial(frame, l4_off, 0));
	if (frame_len > trail_off) {
		__wsum csum2 = csum_partial(frame + trail_off, frame_len - trail_off, 0);

		sum = csum_block_sub(sum, csum2, trail_off);
	}

	return sum;
}

/*
 * cne_rx_csum_unnecessary - Validate the L4 checksum in software so the stack
 * can skip its own pass.  CYR has no RX checksum offload, but the payload is
 * read once anyway (the copybreak copy or the zero-copy csum_partial), so @csum
 * already holds the ones-complement sum over the whole L2 frame
 * [skb->data .. skb->len).  cne_rx_l4_sum() isolates the L4 segment sum, then
 * it is folded against the transport pseudo-header.  A zero fold means the
 * on-wire checksum is valid, so the caller may set CHECKSUM_UNNECESSARY and the
 * stack will not run __skb_checksum_complete().  Anything not understood -
 * non-IP, stacked VLANs, IPv6 extension headers, fragments, non-TCP/UDP (e.g.
 * SCTP, which uses CRC32c) or a truncated frame - returns false so the caller
 * falls back to CHECKSUM_NONE.  Unlike a HW-supplied folded value there is no
 * csum_unfold() step: csum is our own __wsum.
 *
 * skb->data must still point at the Ethernet header (before eth_type_trans()).
 */
static bool cne_rx_csum_unnecessary(struct sk_buff *skb,
				    __wsum csum)
{
	u8 proto;
	__wsum l4_sum;
	u32 l4_off;
	u32 l4_len;
	u32 l3_off = ETH_HLEN;
	const u8 *frame = skb->data;
	u16 etype;

	if (skb->len < ETH_HLEN)
		return false;
	etype = get_unaligned_be16(frame + 12);
	if (etype == ETH_P_8021Q || etype == ETH_P_8021AD) {
		if (skb->len < ETH_HLEN + VLAN_HLEN)
			return false;
		etype = get_unaligned_be16(frame + 16);
		l3_off += VLAN_HLEN;
	}

	if (etype == ETH_P_IP) {
		const struct iphdr *iph = (const struct iphdr *)(frame + l3_off);
		u32 ihl, tot_len;

		if (l3_off + sizeof(*iph) > skb->len)
			return false;
		ihl = iph->ihl * 4;
		tot_len = ntohs(iph->tot_len);

		/* Fragments carry only part of the L4 segment; let the stack reassemble. */
		if (iph->frag_off & htons(IP_MF | IP_OFFSET))
			return false;
		if (ihl < sizeof(*iph) || tot_len < ihl ||
		    l3_off + tot_len > skb->len)
			return false;
		proto = iph->protocol;
		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
			return false;
		l4_off = l3_off + ihl;
		l4_len = tot_len - ihl;
		l4_sum = cne_rx_l4_sum(frame, skb->len, csum, l4_off, l4_len);
		return !csum_tcpudp_magic(iph->saddr, iph->daddr, l4_len,
					  proto, l4_sum);
	}

	if (etype == ETH_P_IPV6) {
		const struct ipv6hdr *ip6 = (const struct ipv6hdr *)(frame + l3_off);
		u32 payload_len;

		if (l3_off + sizeof(*ip6) > skb->len)
			return false;
		payload_len = ntohs(ip6->payload_len);
		proto = ip6->nexthdr;
		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
			return false;
		l4_off = l3_off + sizeof(*ip6);
		l4_len = payload_len;
		if (l4_off + payload_len > skb->len)
			return false;
		l4_sum = cne_rx_l4_sum(frame, skb->len, csum, l4_off, l4_len);
		return !csum_ipv6_magic(&ip6->saddr, &ip6->daddr, l4_len,
					proto, l4_sum);
	}

	return false;
}

/**
 * cne_bypass_rcv - Receive a bypass frame.
 * @packet: hfi packet received
 */
void cne_bypass_rcv(struct hfi2_packet *packet)
{
	struct hfi2_ctxtdata *rcd = packet->rcd;
	struct hfi2_pportdata *ppd = rcd->ppd;
	struct device *dev = &rcd->dd->pcidev->dev;
	struct net_device *ndev = ppd->ndev;
	struct ether_device *edev = netdev_priv(ndev);
	struct eal_ingress_header *h = (struct eal_ingress_header *)
			hfi2_get_header(rcd, packet->rhf_addr);
	bool ts_present = EAL_INGRESS_GET_TS_PRESENT(h);
	u32 saddr = (EAL_INGRESS_GET_SADDR_23_20(h) << 20) | EAL_INGRESS_GET_SADDR_19_0(h);
	u32 overhead = LRH_16B_BYTES + (ts_present ? CNE_RX_TS_SIZE : 0) +
		       EAL_INGRESS_GET_E(h);
	struct cne_rx_skb *slot;
	struct cne_rx_skb repl;
	struct cne_rx_skb old;
	struct sk_buff *skb;
	void *old_va;
	u32 eager_len;
	u32 copybreak = READ_ONCE(cne_rx_copybreak) ?:
			(device_iommu_mapped(dev) ? 2048 : 1024);
	u32 length = 0;
	u64 sec = 0;
	u32 nsec = 0;
	u16 eth_proto;
	u8 prio = 0;
	u32 reason = 0;
	bool rxcsum = READ_ONCE(ndev->features) & NETIF_F_RXCSUM;
	enum pkt_hash_types hash_type;
	u32 hash;

#if IS_ENABLED(CONFIG_INFINIBAND_HFI2_ROCE)
	hfi2_dms_roce_netdev_track_loss(rcd->dd, h);
#endif

	/*
	 * Drop errored frames before touching the payload: CYR cut-through can
	 * DMA a corrupt frame into the eager buffer, and RHF error status is
	 * final before this handler runs. Mirrors process_receive_bypass().
	 */
	if (unlikely(packet->has_errs)) {
		/* A TID error alone means no eager buffer was free: an overrun */
		if ((packet->err_flags & RHF_ERROR_SMASK) == RHF_TID_ERR) {
			netdev_dbg(ndev, "[RX] no free eager buffer\n");
			/*
			 * The egr index is the last buffer hardware filled.
			 * Release up to it, or a full ring whose tail stopped
			 * off a threshold boundary never drains.
			 */
			packet->updegr = 1;
			reason = RX_DROP;
		} else {
			hfi2_handle_eflags(packet);
			reason = RX_ERROR;
		}
		goto out;
	}

	/* A frame too short for an Ethernet header is malformed */
	if (unlikely(packet->tlen < overhead + ETH_HLEN)) {
		netdev_dbg(ndev, "[RX] runt frame: tlen %u < %u\n",
			   packet->tlen, overhead + ETH_HLEN);
		reason = RX_ERROR;
		goto out;
	}
	length = packet->tlen - overhead;
	eager_len = packet->tlen - LRH_16B_BYTES;

	/* HW posts rcvtid_size-byte slots; never trust a longer RHF length. */
	if (unlikely(eager_len > rcd->egrbufs.rcvtid_size)) {
		if (net_ratelimit())
			netdev_warn(ndev, "[RX] frame %u exceeds buffer %u\n",
				    eager_len, rcd->egrbufs.rcvtid_size);
		reason = RX_ERROR;
		goto out;
	}

	/*
	 * A bypass payload lives only in the eager/SKB buffer.  A frame with
	 * RHF UseEgrBfr clear consumed no eager buffer, so drop it without
	 * touching the ring - reclaiming an unused slot would desync the
	 * posted-slot invariant.
	 */
	if (unlikely(!rhf_use_egr_bfr(packet->rhf))) {
		netdev_dbg(ndev, "[RX] bypass frame without eager buffer\n");
		reason = RX_DROP;
		goto out;
	}

	/*
	 * skbs[] is sized to egrbufs.alloced, which can be smaller than the
	 * RcvArray index range HW can present; cne_rx_skb_at() does not bound
	 * the index. Reject an out-of-range or empty slot before the array
	 * read / old.page deref.
	 */
	if (unlikely(packet->egr_index >= rcd->egrbufs.alloced)) {
		if (net_ratelimit())
			netdev_warn(ndev, "[RX] eager index %u out of range (alloced %u)\n",
				    packet->egr_index, rcd->egrbufs.alloced);
		reason = RX_DROP;
		goto out;
	}
	slot = cne_rx_skb_at(rcd, packet->egr_index);
	old = *slot;
	if (unlikely(!old.page)) {
		if (net_ratelimit())
			netdev_warn(ndev, "[RX] empty eager slot %u\n", packet->egr_index);
		reason = RX_DROP;
		goto out;
	}
	old_va = page_address(old.page) + NET_SKB_PAD;

	/*
	 * The device wrote the eager buffer via streaming DMA; take CPU
	 * ownership before reading the timestamp or payload.  The copybreak
	 * path returns it with dma_sync_single_range_for_device(); the
	 * zero-copy path recycles it via skb_mark_for_recycle().  page_pool
	 * owns the mapping, so sync the driver range explicitly.
	 */
	dma_sync_single_range_for_cpu(dev, page_pool_get_dma_addr(old.page),
				      NET_SKB_PAD, eager_len, DMA_FROM_DEVICE);

	if (unlikely(ts_present)) {
		struct timestamp12 *ts = (struct timestamp12 *)old_va;

		sec = timestamp12_sec(ts);
		nsec = timestamp12_nsec(ts);
		old_va += CNE_RX_TS_SIZE; /* Skip the TS so copy, csum start at L2. */
	}

	eth_proto = ntohs(((struct ethhdr *)old_va)->h_proto);
	if (eth_type_vlan(htons(eth_proto)) && length >= VLAN_ETH_HLEN)
		prio = ntohs(((struct vlan_ethhdr *)old_va)->h_vlan_TCI) >>
		       VLAN_PRIO_SHIFT;
	pinfo(edev, rx_status,
	      "[RX] len %u saddr 0x%06x proto 0x%04x ctxt %d info 0x%05llx type %llu l4 0x%02llx ts %llu.%u\n",
	      packet->tlen, saddr, eth_proto, rcd->ctxt, EAL_INGRESS_GET_CTXT_INFO(h),
	      EAL_INGRESS_GET_TYPE(h), EAL_INGRESS_GET_L4(h), sec, nsec);

#if IS_ENABLED(CONFIG_INFINIBAND_HFI2_ROCE)
	if (hfi2_dms_roce_netdev_match_ipv4(rcd->dd, old_va, length)) {
		skb = napi_alloc_skb(rcd->napi, length);
		if (!skb) {
			dma_sync_single_range_for_device(dev,
						 page_pool_get_dma_addr(old.page),
						 NET_SKB_PAD, eager_len,
						 DMA_FROM_DEVICE);
			reason = RX_DROP;
			goto out;
		}
		skb_put_data(skb, old_va, length);
		dma_sync_single_range_for_device(dev, page_pool_get_dma_addr(old.page),
						 NET_SKB_PAD, eager_len,
						 DMA_FROM_DEVICE);
		hfi2_dms_roce_netdev_enqueue(rcd->dd, skb);
		length = 0;
		goto out;
	}
#endif

	/*
	 * Copy small frames and leave the mapped buffer posted.  Large
	 * frames zero-copy.
	 */
	if (length > copybreak && cne_rx_freelist_pop(rcd, &repl)) {
		/*
		 * Repost the replacement before any head advance so HW always
		 * sees a posted slot, then retire the old mapping.
		 */
		cyr_put_tid_mode1(rcd, packet->egr_index, repl.dma,
				  rcd->egrbufs.rt_size_code, true);
		*slot = repl;
		if (rcd->egrbufs.rcvtids)
			rcd->egrbufs.rcvtids[packet->egr_index].addr =
				page_address(repl.page) + NET_SKB_PAD;

		/*
		 * The slot now points at repl, so old.page is ours to hand up
		 * or return.  napi_build_skb() only allocates the sk_buff head
		 * (the page is already ours), but can still fail; return the
		 * page to the pool in that case.
		 */
		skb = napi_build_skb(page_address(old.page), page_size(old.page));
		if (unlikely(!skb)) {
			page_pool_put_full_page(rcd->egrbufs.pp, old.page, true);
			reason = RX_DROP;
			goto out;
		}
		/* Reserve up to old_va so skb->data starts at the L2 header. */
		skb_reserve(skb, old_va - page_address(old.page));
		skb_mark_for_recycle(skb);
		skb_put(skb, length);

		/*
		 * When RXCSUM is off the stack computes the L4 checksum in
		 * software later, deep in the receive path, over a payload the
		 * CPU never touched; strided prefetches warm it so they overlap
		 * the intervening header/GRO work.
		 */
		if (rxcsum)
			skb->csum = csum_partial(skb->data, skb->len, 0);
		else
			for (int i = 0; i < length; i += L1_CACHE_BYTES)
				prefetch(skb->data + i);
	} else {
		skb = napi_alloc_skb(rcd->napi, length);
		if (!skb) {
			dma_sync_single_range_for_device(dev, page_pool_get_dma_addr(old.page),
							 NET_SKB_PAD, eager_len, DMA_FROM_DEVICE);
			reason = RX_DROP;
			goto out;
		}
		/*
		 * The copybreak path already streams the whole payload through
		 * the CPU.  When RXCSUM is on, fold the checksum into that same
		 * pass with csum_partial_copy_nocheck() so the frame is read
		 * once instead of twice (copy now, csum_partial() later).
		 */
		if (rxcsum)
			skb->csum = csum_partial_copy_nocheck(old_va,
							      skb_put(skb, length),
							      length);
		else
			skb_put_data(skb, old_va, length);

		dma_sync_single_range_for_device(dev,
						 page_pool_get_dma_addr(old.page),
						 NET_SKB_PAD, eager_len,
						 DMA_FROM_DEVICE);
	}

	skb->dev = edev->ndev;
	if (unlikely(ts_present)) {
		struct skb_shared_hwtstamps *skb_ts = skb_hwtstamps(skb);

		memset(skb_ts, 0, sizeof(*skb_ts));
		skb_ts->hwtstamp = ktime_set(sec, nsec);
	}

	/*
	 * CYR has no RX checksum offload.  skb->csum already holds the frame
	 * sum computed during the copy/zero-copy pass, so validate the L4
	 * checksum here and hand the stack CHECKSUM_UNNECESSARY on success: it
	 * then skips __skb_checksum_complete() entirely.
	 */
	if (rxcsum && cne_rx_csum_unnecessary(skb, skb->csum))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else
		skb->ip_summed = CHECKSUM_NONE;

	hash = cne_rx_flow_hash(skb->data, skb->len, &hash_type);
	if (hash)
		skb_set_hash(skb, hash, hash_type);
	skb_record_rx_queue(skb, rcd->vnic_q_idx);
	skb->protocol = eth_type_trans(skb, edev->ndev);

	/* Output packet data if NETIF_MSG_PKTDATA is set, payload data if NETIF_MSG_HW is set. */
	if (netif_msg_pktdata(edev)) {
		char buffer[768];

		skb_reset_network_header(skb);
		skb_set_transport_header(skb, ip_hdrlen(skb));
		pr_skb(skb, netif_msg_hw(edev) ? 32 : 0, buffer, sizeof(buffer));
		pinfo(edev, pktdata, "[RX] %s\n", buffer);
	}

	napi_gro_receive(rcd->napi, skb);

out:
	if (likely(rcd->cne_rxq)) {
		struct cn_rxq *rxq = rcd->cne_rxq;

		u64_stats_update_begin(&rxq->stats->syncp);
		if (!reason) {
			rxq->stats->packets++;
			rxq->stats->bytes += length;
			rxq->stats->prio_packets[prio]++;
			rxq->stats->prio_bytes[prio] += length;
		} else if (reason & RX_DROP) {
			rxq->stats->drops++;
		} else if (reason & RX_ERROR) {
			rxq->stats->errors++;
		}
		u64_stats_update_end(&rxq->stats->syncp);
	}
}

void cne_ulp_fallthrough(struct hfi2_dms *dms,
			 const struct hfi2_dms_ulp_rx *rx)
{
	struct hfi2_devdata *dd = dms->dd;
	struct hfi2_pportdata *ppd;
	struct ether_device *edev;
	struct cn_rxq_stats *st;
	struct net_device *ndev;
	struct sk_buff *skb;
	const void *inline_data = rx->payload[0].base;
	const void *eager_data = rx->payload[1].base;
	u32 inline_len = rx->payload[0].len;
	u32 eager_len = rx->payload[1].len;
	u32 length = inline_len + eager_len;

	if (!rx->is_ethernet || rx->rcv_port >= dd->num_pports) {
		dms->counters.eal_fallthrough_bad_rx_drop++;
		dd_dev_warn_ratelimited
			(dd,
			 "ULP fallthrough frame dropped: invalid rx descriptor (is_ethernet=%d rcv_port=%u)\n",
			 rx->is_ethernet, rx->rcv_port);
		return;
	}

	ppd = &dd->pport[rx->rcv_port];
	/* cne_remove() waits for ULP RX readers before unregistering. */
	rcu_read_lock();
	ndev = rcu_dereference(ppd->ulp_ndev);
	if (!ndev || !netif_running(ndev)) {
		dms->counters.eal_fallthrough_no_netdev_drop++;
		dd_dev_warn_ratelimited
			(dd,
			 "ULP fallthrough frame dropped: no running netdev for rcv_port %u\n",
			 rx->rcv_port);
		goto out;
	}
	edev = netdev_priv(ndev);
	st = &edev->ulp_rx_stats;

	if (unlikely(length < ETH_HLEN ||
		     (!inline_data && inline_len) ||
		     (!eager_data && eager_len))) {
		u64_stats_update_begin(&st->syncp);
		st->drops++;
		u64_stats_update_end(&st->syncp);
		dd_dev_warn_ratelimited(dd, "ULP fallthrough frame dropped: malformed payload\n");
		goto out;
	}

	skb = netdev_alloc_skb(ndev, length);
	if (!skb) {
		u64_stats_update_begin(&st->syncp);
		st->drops++;
		u64_stats_update_end(&st->syncp);
		dd_dev_warn_ratelimited(dd, "ULP fallthrough frame dropped: skb allocation failed\n");
		goto out;
	}

	if (inline_len)
		skb_put_data(skb, inline_data, inline_len);
	if (eager_len)
		skb_put_data(skb, eager_data, eager_len);
	skb->dev = ndev;
	skb->ip_summed = CHECKSUM_NONE;
	if (rx->ingress_timestamp) {
		const struct timestamp12 *ts = rx->ingress_timestamp;
		struct skb_shared_hwtstamps *skb_ts = skb_hwtstamps(skb);

		memset(skb_ts, 0, sizeof(*skb_ts));
		skb_ts->hwtstamp = ktime_set(timestamp12_sec(ts), timestamp12_nsec(ts));
	}
	skb->protocol = eth_type_trans(skb, ndev);
	netif_rx(skb);

	u64_stats_update_begin(&st->syncp);
	st->packets++;
	st->bytes += length;
	u64_stats_update_end(&st->syncp);

out:
	rcu_read_unlock();
}
