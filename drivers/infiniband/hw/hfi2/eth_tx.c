// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Ethernet frame transmission implementation.
 */

#include "eth_main.h"

/*
 * Worst-case SDMA descriptors for one Ethernet frame: one for the PBC, one for
 * the linear head, one per possible page fragment, and one for the trailing
 * quadword-alignment pad (see cne_map_payload()).
 */
#define CNE_TX_DESC_MAX (3 + MAX_SKB_FRAGS)

/**
 * cne_txq_full - can the engine accept one more worst-case frame?
 * @txq: transmit queue whose SDMA engine is checked
 *
 * Returns true when either the descriptor ring lacks worst-case room or the
 * outstanding-packet cap is reached. Checking before the skb is mutated keeps
 * the lossy post-mutation -EBUSY path rare, but queues share an engine when
 * num_txqs > num_sdes (queue i uses engine i % num_sdes), so another queue can
 * still fill the ring between this check and the submit.
 */
static bool cne_txq_full(struct cn_txq *txq)
{
	struct sdma_engine *sde = txq->sde;

	if (sdma_descq_freecnt(sde) < CNE_TX_DESC_MAX)
		return true;
	return sde->dd->sdma_limit_outstanding_pkts &&
	       sdma_pkts_inprocess(sde) >= SDMA_OUTSTANDING_PKT_LIMIT;
}

/**
 * cne_wake_sde_queues - wake every stopped subqueue sharing an SDMA engine
 * @edev: Ethernet device owning the transmit queues
 * @sde: SDMA engine whose sibling queues should be re-evaluated
 *
 * Runs once per completed frame in the cne_sdma_complete() hot path, so it only
 * touches the queues that can actually be blocked on @sde.
 */
static void cne_wake_sde_queues(struct ether_device *edev,
				struct sdma_engine *sde)
{
	int nq = min_t(int, edev->num_txqs, ARRAY_SIZE(edev->txq));
	int first = cne_sde_first_txq(edev, sde);

	if (!READ_ONCE(edev->tx_enabled) || first < 0)
		return;

	/*
	 * Order the descriptor-ring release against the stopped-bit reads;
	 * pairs with smp_mb__after_atomic() in cne_maybe_stop_tx().
	 */
	smp_mb();

	/* Walk only the queues mapped to @sde (see cne_txq_sde_idx()). */
	for (int i = first; i < nq; i += edev->num_sdes) {
		struct cn_txq *txq = edev->txq[i];

		if (txq && txq->sde == sde &&
		    __netif_subqueue_stopped(edev->ndev, txq->q_id) && !cne_txq_full(txq))
			netif_wake_subqueue(edev->ndev, txq->q_id);
	}
}

/**
 * cne_txreq_alloc - Allocate a cn_txreq from the txq's cache
 * @txq: The transmit queue to allocate from
 * @skb: socket buffer the request will carry
 * @gfp: GFP allocation flags (e.g., GFP_ATOMIC for softirq context)
 *
 * Allocates a cn_txreq and increments the cache refcount to keep
 * the cache alive until cne_txreq_free() is called.
 *
 * Returns: Pointer to cn_txreq, or NULL on failure
 *
 * Context: Can be called in atomic context if gfp allows
 */
static inline struct cn_txreq *cne_txreq_alloc(struct cn_txq *txq,
					       struct sk_buff *skb,
					       gfp_t gfp)
{
	struct cn_txreq *txreq;

	if (WARN_ON(!txq->txreq_cache))
		return NULL;

	/* Allocate from the cache */
	txreq = kmem_cache_alloc(txq->txreq_cache, gfp);
	if (!txreq)
		return NULL;

	cne_txq_cache_get(txq);

	txreq->txq = txq;
	txreq->skb = skb;
	txreq->hdr = NULL;

	return txreq;
}

/**
 * cne_txreq_free - Free a cn_txreq back to its cache
 * @txreq: The cn_txreq to free
 *
 * Returns the txreq to the cache and decrements the cache refcount.
 *
 */
static inline void cne_txreq_free(struct cn_txreq *txreq)
{
	struct cn_txq *txq;

	if (WARN_ON(!txreq) || WARN_ON(!txreq->txq))
		return;

	txq = txreq->txq;

	if (txreq->hdr)
		dma_pool_free(txq->hdr_pool, txreq->hdr, txreq->hdr_dma);
	kmem_cache_free(txq->txreq_cache, txreq);
	cne_txq_cache_put(txq);
}

/**
 * cne_sdma_complete - called when SDMA operation finishes processing
 * @txreq: the SDMA request that finished
 * @status: disposition of the SDMA request (SDMA_TXREQ_S_OK, SDMA_TXREQ_S_SENDERROR,
 *		SDMA_TXREQ_S_ABORTED, or SDMA_TXREQ_S_SHUTDOWN)
 */
static void cne_sdma_complete(struct sdma_txreq *txreq,
			      int status)
{
	struct cn_txreq *tx = container_of(txreq, struct cn_txreq, txreq);
	struct cn_txq *txq = tx->txq;
	int q_id = txq->q_id;
	struct ether_device *edev = READ_ONCE(txq->edev);

	if (edev) {
		struct hfi2_devdata *dd = edev->ppd->dd;

		pdbg(edev, tx_done, "[TX] SKB %p q_id %u status %d\n", tx->skb, q_id, status);

		/* Called from hard IRQ context, so IRQs are already disabled. */
		u64_stats_update_begin(&txq->stats->syncp);
		if (likely(status == SDMA_TXREQ_S_OK)) {
			txq->stats->sdma_packets++;
			txq->stats->sdma_bytes += tx->skb->len - LRH_16B_BYTES;
		} else {
			txq->stats->sdma_errors++;
		}
		u64_stats_update_end(&txq->stats->syncp);

		/* Drop the TX path's reference. When a timestamp is in progress
		 * cne_encap_skb() took an extra skb_get(). A frame the engine
		 * sent was consumed, not dropped; keep it out of drop monitors.
		 */
		if (likely(status == SDMA_TXREQ_S_OK))
			dev_consume_skb_any(tx->skb);
		else
			dev_kfree_skb_any(tx->skb);

		/*
		 * BQL completion: release the byte reservation taken by
		 * netdev_tx_sent_queue() in send_sdma(). This is the sole
		 * consumer of the queue's dynamic limit and pairs 1:1 with the
		 * hand-off there (both S_OK and ABORTED land here), so the
		 * accounting stays balanced and the qdisc is re-woken once the
		 * outstanding byte count drops below the limit.  A request
		 * charged before cne_enable_txq() last reset the queue was never
		 * seen by the current DQL; releasing it would trip the BUG_ON in
		 * dql_completed().  Completions and the reset both hold
		 * head_lock, so bql_gen is stable here.
		 */
		if (tx->bql_gen == txq->bql_gen)
			netdev_tx_completed_queue(netdev_get_tx_queue(edev->ndev,
								      q_id),
						  1, tx->bql_bytes);

		/*
		 * netdev_tx_completed_queue() only clears BQL's own XOFF bit; a
		 * subqueue stopped by cne_maybe_stop_tx() (DRV XOFF) stays off
		 * and queued no iowait in the pre-mutation gate path, so wake it.
		 */
		cne_wake_sde_queues(edev, txq->sde);

		if (dd)
			sdma_txclean(dd, txreq);
		else
			pwarn(edev, tx_done, "leaking SDMA desc %p\n", txreq);
	} else {
		/*
		 * Queue detached by cne_free_txq(): the netdev, its stats and
		 * BQL state may be gone.  complete_tx() already cleaned the
		 * descriptors; only the skb is left to release.
		 */
		dev_kfree_skb_any(tx->skb);
	}

	cne_txreq_free(tx);
}

/**
 * cne_encap_skb - encapsulate the Ethernet frame with the EAL encapsulation header
 * @edev: Ethernet device
 * @skb: socket buffer for this frame
 *
 * Return 0 on success.
 */
static int cne_encap_skb(struct ether_device *edev,
			 struct sk_buff *skb)
{
	u32 si = 0;
	u32 length = LSBITS(BYTES2QWORD_ROUND_UP(skb->len), 11);
	u16 protocol = ntohs(skb->protocol);
	bool ipv6 = vlan_get_protocol(skb) == htons(ETH_P_IPV6);
	bool ts_capture = false;
	struct hfi2_pportdata *ppd = edev->ppd;
	struct eal_egress_header *h = (struct eal_egress_header *)skb->data;

	h->q0 = 0;
	h->q1 = 0;
#ifdef CONFIG_PTP_1588_CLOCK
	if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) {
		if (READ_ONCE(edev->ptp_config.tx_type) == HWTSTAMP_TX_ON &&
		    !test_and_set_bit_lock(1, &edev->ptp_in_progress)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
			WRITE_ONCE(edev->ptp_tx_skb, skb_get(skb));
			WRITE_ONCE(edev->ptp_tx_start, get_jiffies_64());
			ts_capture = true;
			EAL_EGRESS_SET_TS_CAPTURE(h, 1);
			EAL_EGRESS_SET_TS_MODE(h, EAL_EGRESS_TS_MODE_12B);
			EAL_EGRESS_SET_TYPE(h, EAL_EGRESS_TYPE_PTP);
			schedule_delayed_work(&edev->ptp_tx_work, 0);
		} else {
			pwarn(edev, tx_queued, "PTP timestamp skipped for SKB %p\n", skb);
		}
	}
#endif
	EAL_EGRESS_SET_E(h, LSBITS((8 - (skb->len & 0x7)), 3));
	EAL_EGRESS_SET_LENGTH(h, length);
	EAL_EGRESS_SET_L2(h, L2TYPE);
	EAL_EGRESS_SET_LT(h, 1);
	EAL_EGRESS_SET_L4(h, EAL_EGRESS_L4_ETH);
	EAL_EGRESS_SET_SLID_23_20(h, 0xf); /* multicast range */
	EAL_EGRESS_SET_DLID_23_20(h, DLID_23_20); /* multicast range (can't be 0) */
	EAL_EGRESS_SET_PKEY(h, ppd->pkeys[0]);
	EAL_EGRESS_SET_IP_VER(h, ipv6 ? EAL_EGRESS_IP_VER_6 : EAL_EGRESS_IP_VER_4);
	switch (protocol) {
	case ETH_P_8021Q:
		EAL_EGRESS_SET_VLAN_TAGS(h, EAL_EGRESS_VLAN_TAGS_1);
		break;
	case ETH_P_8021AD:
		EAL_EGRESS_SET_VLAN_TAGS(h, EAL_EGRESS_VLAN_TAGS_2);
		break;
	default:
		EAL_EGRESS_SET_VLAN_TAGS(h, EAL_EGRESS_VLAN_TAGS_0);
	}

	pdbg(edev, tx_queued, "protocol 0x%x SI %u len %u TS_capture %u\n", protocol, si, length,
	     ts_capture);

	return 0;
}

/**
 * cne_map_payload - map payload
 * @sde: SDMA engine
 * @tx: TX request
 *
 * Return 0 on success, negative value otherwise.
 */
static noinline int cne_map_payload(struct sdma_engine *sde,
				    struct cn_txreq *tx)
{
	int i;
	int  rc = 0;
	struct sk_buff *skb = tx->skb;
	u32 pad = (-skb->len) & 7;
	struct ether_device *edev = (struct ether_device *)tx->txq->edev;

	/* Map the linear part unless cne_build_tx_desc() copied it. */
	if (!tx->hdr) {
		rc = sdma_txadd_kvaddr(sde->dd, &tx->txreq, skb->data,
				       skb_headlen(skb));
		if (unlikely(rc)) {
			netdev_err(edev->ndev, "sdma_txadd_kvaddr failed (%d)\n", rc);
			return rc;
		}
	}

	if (skb_shinfo(skb)->nr_frags)
		pinfo(edev, tx_queued, "Adding %d frags (pages)\n", skb_shinfo(skb)->nr_frags);

	/* Add additional SKB fragments. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		/* combine physically continuous fragments later? */
		rc = sdma_txadd_page(sde->dd, &tx->txreq, skb_frag_page(frag),
				     skb_frag_off(frag), skb_frag_size(frag));
		if (unlikely(rc)) {
			netdev_err(edev->ndev, "sdma_txadd_page failed (%d)\n", rc);
			return rc;
		}
	}

	/*
	 * The frame length must be quadword-aligned on the wire. Supply the
	 * alignment pad from the device's shared zeroed sdma_pad buffer as a
	 * final descriptor. The EAL "E" field already tells the receiver how many
	 * trailing bytes to ignore. cne_build_tx_desc() already sized the txreq
	 * as ALIGN(skb->len, 8), so this pad completes that length.
	 */
	if (pad) {
		rc = sdma_txadd_daddr(sde->dd, &tx->txreq, sde->dd->sdma_pad_phys,
				      pad);
		if (unlikely(rc)) {
			netdev_err(edev->ndev, "sdma_txadd_daddr pad failed (%d)\n", rc);
			return rc;
		}
	}

	return rc;
}

/**
 * cne_build_tx_desc - create SDMA descriptors
 * @sde: SDMA engine
 * @tx: TX request
 * @pbc: Per Buffer Control value
 *
 * Returns 0 on success, negative value otherwise.
 */
static int cne_build_tx_desc(struct sdma_engine *sde,
			     struct cn_txreq *tx,
			     u64 pbc)
{
	int rc = 0;
	u16 hdrbytes = 8;
	u32 headlen = skb_headlen(tx->skb);
	struct ether_device *edev = (struct ether_device *)tx->txq->edev;

	rc = sdma_txinit_ahg(sde->dd, &tx->txreq, 0,
			     hdrbytes + ALIGN(tx->skb->len, 8), 0, 0,
			     NULL, 0, cne_sdma_complete, tx->txq->sc_id);
	if (unlikely(rc)) {
		netdev_err(edev->ndev, "sdma_txinit_ahg failed (%d)\n", rc);
		return rc;
	}

	/*
	 * Send the PBC and the linear part (EAL + L2-L4 headers) as one
	 * premapped descriptor: no IOMMU map/unmap for either.  Map them
	 * separately when the linear part does not fit or no slot is free.
	 * _submit_tx() pads only packets of two or more descriptors, so with
	 * descriptor padding keep a packet that would be just the slot (no
	 * frags, 8-byte aligned) on the mapped path.
	 */
	if (headlen <= CNE_TX_HDR_SLOT - hdrbytes &&
	    (!sde->dd->pad_sdma_desc ||
	     skb_shinfo(tx->skb)->nr_frags || (tx->skb->len & 7)))
		tx->hdr = dma_pool_alloc(tx->txq->hdr_pool, GFP_ATOMIC,
					 &tx->hdr_dma);
	if (tx->hdr) {
		*(__le64 *)tx->hdr = cpu_to_le64(pbc);
		memcpy(tx->hdr + hdrbytes, tx->skb->data, headlen);
		rc = sdma_txadd_daddr(sde->dd, &tx->txreq, tx->hdr_dma,
				      hdrbytes + headlen);
	} else {
		tx->pbc = cpu_to_le64(pbc);
		rc = sdma_txadd_kvaddr(sde->dd, &tx->txreq, &tx->pbc, hdrbytes);
	}
	if (unlikely(rc)) {
		netdev_err(edev->ndev, "sdma_txadd PBC failed (%d)\n", rc);
		return rc;
	}

	/* describe the payload */
	rc = cne_map_payload(sde, tx);

	return rc;
}

/**
 * send_sdma - execute SDMA
 * @edev: Ethernet device
 * @skb: socket buffer
 * @pbc: Per Buffer Control value
 * @txq: TX queue
 *
 * Returns 0 on success, -ERRNO otherwise.
 */
static inline int send_sdma(struct ether_device *edev,
			    struct sk_buff *skb,
			    u64 pbc,
			    struct cn_txq *txq)
{
	int rc;
	unsigned long flags;
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_txreq *tx;
	struct netdev_queue *ndev_q = netdev_get_tx_queue(edev->ndev, txq->q_id);

	if (unlikely(!txq->sde || !sdma_running(txq->sde))) {
		/* Nothing was queued, so the caller must drop the skb. */
		rc = -ENETDOWN;
		goto tx_err;
	}

	tx = cne_txreq_alloc(txq, skb, GFP_ATOMIC);
	if (unlikely(!tx)) {
		rc = -ENOMEM;
		goto tx_err;
	}

	rc = cne_build_tx_desc(txq->sde, tx, pbc);
	if (unlikely(rc))
		goto free_txreq_cache;

	skb_tx_timestamp(skb);

	/*
	 * Reserve the bytes with BQL before the hand-off. Once the txreq is
	 * owned by the engine (rc == 0 or -ECOMM), cne_sdma_complete() releases
	 * them.
	 */
	tx->bql_bytes = skb->len;
	tx->bql_gen = txq->bql_gen;
	netdev_tx_sent_queue(ndev_q, tx->bql_bytes);
	rc = hfi2_sdma_send_txreq(txq->sde, iowait_get_ib_work(&txq->wait),
			     &tx->txreq, txq->pkts_sent);
	/* When -ECOMM, sdma callback will be called with ABORT status */
	if (unlikely(rc && unlikely(rc != -ECOMM)))
		goto free_desc;

	if (!rc) {
		txq->pkts_sent = true;
		iowait_starve_clear(true, &txq->wait);
	}

	return rc;

free_desc:
	/*
	 * Undo the BQL reservation under head_lock, which serializes it with
	 * cne_sdma_complete() releasing bytes on the same queue.
	 */
	write_seqlock_irqsave(&txq->sde->head_lock, flags);
	netdev_tx_completed_queue(ndev_q, 1, tx->bql_bytes);
	write_sequnlock_irqrestore(&txq->sde->head_lock, flags);
	sdma_txclean(dd, &tx->txreq);

free_txreq_cache:
	cne_txreq_free(tx);

tx_err:
	txq->pkts_sent = false;

	return rc;
}

/**
 * cne_maybe_stop_tx - stop the subqueue if the SDMA engine is full
 * @ndev: network device
 * @txq: TX queue
 * @q_idx: queue index
 */
static void cne_maybe_stop_tx(struct net_device *ndev,
			      struct cn_txq *txq,
			      u8 q_idx)
{
	/*
	 * Stop the subqueue before checking the SDMA engine so a concurrent
	 * completion cannot leave the subqueue stopped with no wakeup pending.
	 */
	netif_stop_subqueue(ndev, q_idx);
	/* Pairs with smp_mb() in cne_wake_sde_queues(). */
	smp_mb__after_atomic();
	if (!cne_txq_full(txq))
		netif_start_subqueue(ndev, q_idx);
}

/**
 * cne_tx_timeout_recover - re-evaluate a watchdog-flagged transmit queue
 * @ndev: network device
 * @queue: index of the transmit queue reported hung by the netdev watchdog
 *
 * Restarts the queue's SDMA engine if it has stopped retiring descriptors,
 * then wakes any queue on that engine that has room again.
 */
void cne_tx_timeout_recover(struct net_device *ndev, unsigned int queue)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_txq *txq;

	if (queue >= edev->num_txqs)
		return;
	txq = edev->txq[queue];
	if (!txq || !txq->sde)
		return;
	if (sdma_engine_progress_check(txq->sde))
		netdev_warn(ndev, "TX queue %u: SDMA engine %u stalled, restarting\n",
			    queue, txq->sde->this_idx);
	cne_wake_sde_queues(edev, txq->sde);
}

/**
 * cne_start_xmit - send the specified buffer
 * @skb: socket buffer to send
 * @ndev: network device
 *
 * Returns NETDEV_TX_OK on success, NETDEV_TX_BUSY if not.
 */
netdev_tx_t cne_start_xmit(struct sk_buff *skb,
			   struct net_device *ndev)
{
	int rc = NETDEV_TX_OK;
	u8 q_idx = skb->queue_mapping, vl = 0;
	u32 len_dws;
	u32 pkt_len;
	u64 pbc;
	u16 tci;
	unsigned long flags;
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	struct cn_txq *txq = edev->txq[q_idx];
	bool pfc = READ_ONCE(edev->pfc_enabled);
	u8 prio = skb->priority & 7;

	if (cne_txq_full(txq)) {
		cne_maybe_stop_tx(ndev, txq, q_idx);
		return NETDEV_TX_BUSY;
	}

	/*
	 * PFC classifies by PCP: priority-tag (VID 0) untagged traffic like
	 * ixgbe/i40e, leaving priority 0 and link-local frames untagged.
	 */
	if (pfc && prio && skb->priority != TC_PRIO_CONTROL &&
	    !eth_type_vlan(skb->protocol) && !skb_vlan_tag_present(skb) &&
	    !is_link_local_ether_addr(((struct ethhdr *)skb->data)->h_dest)) {
		skb = vlan_insert_tag_set_proto(skb, htons(ETH_P_8021Q),
						prio << VLAN_PRIO_SHIFT);
		if (!skb)
			goto tx_drop_freed;
	}

	if (skb_cow_head(skb, LRH_16B_BYTES)) {
		netdev_err(ndev, "Insufficient SKB headroom\n");
		goto tx_drop;
	}

	/* Output packet data if NETIF_MSG_PKTDATA is set, payload data if NETIF_MSG_HW is set. */
	if (netif_msg_pktdata(edev)) {
		char buffer[768];

		pr_skb(skb, netif_msg_hw(edev) ? 32 : 0, buffer, sizeof(buffer));
		pinfo(edev, pktdata, "[TX] %s\n", buffer);
	}

	if (pfc && eth_type_vlan(skb->protocol)) {
		/* get VL from VLAN PCP */
		if (!__vlan_get_tag(skb, &tci))
			vl = (tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
		if (ppd->vls_operational)
			vl = min_t(u8, ppd->vls_operational - 1, vl);
	}

	pkt_len = max_t(typeof(skb->len), skb->len, ETH_ZLEN) + LRH_16B_BYTES;

	/* Make room at SKB start for the 16B header. */
	skb_push(skb, LRH_16B_BYTES);

	/*
	 * Pad a runt frame up to ETH_ZLEN with real skb bytes (this content is
	 * on the wire and cannot be described by the 3-bit EAL "E" pad field).
	 */
	if (pkt_len > skb->len) {
		if (skb_padto(skb, pkt_len))
			goto tx_drop_freed;
		skb_put(skb, pkt_len - skb->len);
	}

	/*
	 * Round the on-wire length up to a quadword. SDMA appends the 0-7 byte
	 * pad as a separate descriptor (cne_map_payload), so the skb is not
	 * padded here.
	 */
	pkt_len = ALIGN_UP(pkt_len, 8);

	if (cne_encap_skb(edev, skb)) {
		netdev_err(ndev, "Encapsulation failed\n");
		goto tx_err;
	}
	len_dws = pkt_len >> 2;

	pbc = txq->pbc_template |
	      (((u64)(len_dws + 2) & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT) |
	      (((u64)vl & PBC_VL_MASK) << PBC_VL_SHIFT);

	rc = send_sdma(edev, skb, pbc, txq);
	switch (rc) {
	case 0:
		break;
	case -ECOMM:
		/*
		 * The txreq is on the SDMA flushlist; cne_sdma_complete() will
		 * free the skb asynchronously with an ABORTED status.
		 */
		break;
	case -EBUSY:
		/*
		 * The ring filled between the pre-mutation room check and submit
		 * (a race with other txqs sharing this engine). The skb is
		 * already mutated and cannot be requeued, so drop it and stop the
		 * subqueue; the queued iowait will wake it. This is expected
		 * backpressure under load, so drop silently (counter only).
		 */
		cne_maybe_stop_tx(ndev, txq, q_idx);
		goto tx_busy_drop;
	default:
		goto tx_err;
	}

	return NETDEV_TX_OK;

tx_drop:
	dev_kfree_skb_any(skb);
tx_drop_freed:
	/* skb_padto() and vlan_insert_tag() free the skb on failure. */
	local_irq_save(flags);
	u64_stats_update_begin(&txq->stats->syncp);
	txq->stats->errors++;
	txq->stats->drops++;
	u64_stats_update_end(&txq->stats->syncp);
	local_irq_restore(flags);
	return NETDEV_TX_OK;

tx_busy_drop:
	/* Transient ring-full drop: count it but do not log (see -EBUSY above). */
	local_irq_save(flags);
	u64_stats_update_begin(&txq->stats->syncp);
	txq->stats->drops++;
	u64_stats_update_end(&txq->stats->syncp);
	local_irq_restore(flags);

	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;

tx_err:
	local_irq_save(flags);
	u64_stats_update_begin(&txq->stats->syncp);
	txq->stats->errors++;
	txq->stats->drops++;
	u64_stats_update_end(&txq->stats->syncp);
	local_irq_restore(flags);

	dev_kfree_skb_any(skb);

	/*
	 * Genuine, rare errors (encap/desc build/alloc failures). Always log
	 * them, rate-limited so a burst cannot flood the log.
	 */
	if (net_ratelimit())
		netdev_err(ndev, "start_xmit failed (%d)\n", rc);

	return NETDEV_TX_OK;
}
