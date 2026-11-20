// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

/*
 * This file contains HFI2 support for IPOIB SDMA functionality
 */

#include <linux/log2.h>
#include <linux/circ_buf.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/sched/isolation.h>
#include <linux/topology.h>

#include "sdma.h"
#include "verbs.h"
#include "trace_ibhdrs.h"
#include "ipoib.h"
#include "trace_tx.h"
#include "qp.h"
#include "bulksvc.h"
#include "bulksvc_ipoib.h"
#include "dms_sdma.h"

/* Add a convenience helper */
#define CIRC_ADD(val, add, size) (((val) + (add)) & ((size) - 1))
#define CIRC_NEXT(val, size) CIRC_ADD(val, 1, size)
#define CIRC_PREV(val, size) CIRC_ADD(val, -1, size)

struct ipoib_txparms {
	struct hfi2_devdata        *dd;
	struct rdma_ah_attr        *ah_attr;
	struct hfi2_ibport         *ibp;
	struct hfi2_ipoib_txq      *txq;
	union hfi2_ipoib_flow       flow;
	u32                         dqpn;
	u8                          hdr_dwords;
	u8                          entropy;
	struct sk_buff             *tso_skb;
	u32                         tso_off;
	u16                         tso_len;
	u16                         tso_seg;
	u8                          tso_hlen;
	u8                          tso_pad;
};

static struct ipoib_txreq *
hfi2_txreq_from_idx(struct hfi2_ipoib_circ_buf *r, u32 idx)
{
	return (struct ipoib_txreq *)(r->items + (idx << r->shift));
}

/* Inverse of hfi2_txreq_from_idx(): the ring slot @tx was allocated from. */
static u32 hfi2_txreq_to_idx(struct hfi2_ipoib_circ_buf *r,
			     struct ipoib_txreq *tx)
{
	return (u32)(((char *)tx - (char *)r->items) >> r->shift);
}

static u32 hfi2_ipoib_txreqs(const u64 sent, const u64 completed)
{
	return sent - completed;
}

static u64 hfi2_ipoib_used(struct hfi2_ipoib_txq *txq)
{
	return hfi2_ipoib_txreqs(txq->tx_ring.sent_txreqs,
				 txq->tx_ring.complete_txreqs);
}

/*
 * irqsave: hfi2_ipoib_sdma_wakeup() wakes the queue and is reachable from the
 * SDMA interrupt handler.  spin_lock_bh() is ruled out independently -
 * hfi2_ipoib_sdma_sleep() stops the queue while holding sde->tail_lock.
 */
static void hfi2_ipoib_stop_txq(struct hfi2_ipoib_txq *txq)
{
	unsigned long flags;

	trace_hfi2_txq_stop(txq);
	spin_lock_irqsave(&txq->stop_lock, flags);
	if (atomic_inc_return(&txq->tx_ring.stops) == 1)
		netif_stop_subqueue(txq->priv->netdev, txq->q_idx);
	spin_unlock_irqrestore(&txq->stop_lock, flags);
}

static void hfi2_ipoib_wake_txq(struct hfi2_ipoib_txq *txq)
{
	unsigned long flags;

	trace_hfi2_txq_wake(txq);
	spin_lock_irqsave(&txq->stop_lock, flags);
	if (atomic_dec_and_test(&txq->tx_ring.stops))
		netif_wake_subqueue(txq->priv->netdev, txq->q_idx);
	spin_unlock_irqrestore(&txq->stop_lock, flags);
}

static uint hfi2_ipoib_ring_hwat(struct hfi2_ipoib_txq *txq)
{
	return min_t(uint, txq->priv->netdev->tx_queue_len,
		     txq->tx_ring.max_items - 1);
}

static uint hfi2_ipoib_ring_lwat(struct hfi2_ipoib_txq *txq)
{
	return min_t(uint, txq->priv->netdev->tx_queue_len,
		     txq->tx_ring.max_items) >> 1;
}

/* A TSO skb needs a ring entry per segment, so stop early enough for one. */
static uint hfi2_ipoib_ring_stop(struct hfi2_ipoib_txq *txq)
{
	uint hwat = hfi2_ipoib_ring_hwat(txq);

	if (txq->priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC)
		return hwat - min_t(uint, hwat >> 1, HFI2_IPOIB_TSO_MAX_SEGS);
	return hwat;
}

static void hfi2_ipoib_check_queue_depth(struct hfi2_ipoib_txq *txq)
{
	++txq->tx_ring.sent_txreqs;
	if (hfi2_ipoib_used(txq) >= hfi2_ipoib_ring_stop(txq) &&
	    !atomic_xchg(&txq->tx_ring.ring_full, 1)) {
		trace_hfi2_txq_full(txq);
		hfi2_ipoib_stop_txq(txq);
		/*
		 * Recheck after stopping: a completion may have drained the
		 * ring between setting ring_full and stopping the queue. If
		 * so, clear ring_full and wake the queue to avoid a stall.
		 *
		 * Use atomic_xchg rather than atomic_set so that only one
		 * path (this recheck or check_queue_stopped) clears ring_full
		 * and calls wake_txq.  A plain atomic_set could race with a
		 * concurrent NAPI poll clearing ring_full, causing both paths
		 * to call wake_txq and underflow the stops refcount.
		 */
		if (hfi2_ipoib_used(txq) < hfi2_ipoib_ring_lwat(txq) &&
		    atomic_xchg(&txq->tx_ring.ring_full, 0))
			hfi2_ipoib_wake_txq(txq);
	}
}

static void hfi2_ipoib_check_queue_stopped(struct hfi2_ipoib_txq *txq)
{
	struct net_device *dev = txq->priv->netdev;

	/* If shutting down just return as queue state is irrelevant */
	if (unlikely(dev->reg_state != NETREG_REGISTERED))
		return;

	/*
	 * When the queue has been drained to less than half full it will be
	 * restarted. Check both ring_full and no_desc conditions.
	 *
	 * The no_desc check is a recovery path for a race condition in
	 * hfi2_ipoib_sdma_sleep() where the SDMA completion may run between
	 * setting no_desc and adding to the dmawait list, missing the wakeup.
	 * NAPI poll provides a backup recovery by also clearing no_desc when
	 * descriptors become available.
	 */
	if (hfi2_ipoib_used(txq) < hfi2_ipoib_ring_lwat(txq) &&
	    (atomic_xchg(&txq->tx_ring.ring_full, 0) ||
	     atomic_xchg(&txq->tx_ring.no_desc, 0))) {
		trace_hfi2_txq_xmit_unstopped(txq);
		hfi2_ipoib_wake_txq(txq);
	}

	/*
	 * A short hfi2_sdma_send_txlist() strands the rest of the list, so the wake
	 * above cannot fire.  Queue the flush rather than call it here: the
	 * callers hold sde->tail_lock, which hfi2_ipoib_flush_tx_list()
	 * re-enters.  Leave the queue stopped so dev_watchdog still delivers
	 * it to hfi2_ipoib_tx_timeout() if the flush submits nothing.  The
	 * excluded states recover on their own, and hfisvc needs no test as
	 * neither append to tx_list is reachable in that mode.
	 */
	if (unlikely(__netif_subqueue_stopped(dev, txq->q_idx) &&
		     !list_empty(&txq->tx_list) &&
		     !iowait_sdma_pending(&txq->wait) &&
		     list_empty(&txq->wait.list)))
		iowait_schedule(&txq->wait, system_highpri_wq,
				WORK_CPU_UNBOUND);
}

static void hfi2_ipoib_free_tx(struct ipoib_txreq *tx, int budget)
{
	struct hfi2_ipoib_dev_priv *priv = tx->txq->priv;

	/*
	 * tx->skb may be NULL if the IPoIB layer flushed the TX ring
	 * while NAPI polling was still active. This can happen during
	 * IB_EVENT_PORT_ERR when ipoib_ib_dev_down() is called but
	 * NAPI remains enabled for fast link recovery.
	 */
	if (unlikely(!tx->skb && !tx->txreq.num_desc))
		return;

	if (likely(!tx->sdma_status)) {
		dev_sw_netstats_tx_add(priv->netdev, 1, tx->tx_bytes);
	} else {
		++priv->netdev->stats.tx_errors;
		dd_dev_warn(priv->dd,
			    "%s: Status = 0x%x pbc 0x%llx txq = %d sde = %d\n",
			    __func__, tx->sdma_status,
			    le64_to_cpu(tx->sdma_hdr->pbc), tx->txq->q_idx,
			    /* hfisvc owns no ordinary engine, so sde is NULL */
			    tx->txq->sde ? tx->txq->sde->this_idx : -1);
	}

	if (tx->skb)
		napi_consume_skb(tx->skb, budget);
	tx->skb = NULL;
	sdma_txclean(priv->dd, &tx->txreq);
}

static void hfi2_ipoib_drain_tx_ring(struct hfi2_ipoib_txq *txq)
{
	struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;
	int i;
	struct ipoib_txreq *tx;

	for (i = 0; i < tx_ring->max_items; i++) {
		tx = hfi2_txreq_from_idx(tx_ring, i);
		tx->complete = 0;
		dev_kfree_skb_any(tx->skb);
		tx->skb = NULL;
		sdma_txclean(txq->priv->dd, &tx->txreq);
	}
	tx_ring->head = 0;
	tx_ring->tail = 0;
	tx_ring->complete_txreqs = 0;
	tx_ring->sent_txreqs = 0;
	tx_ring->avail = hfi2_ipoib_ring_hwat(txq);

	/* These refer to txreqs the drain above just reclaimed. */
	txq->hfisvc_napi_pending = 0;

	/* A run still accumulating was never handed over. */
	txq->hfisvc_run_head = NULL;
	txq->hfisvc_run_len = 0;
}

static int hfi2_ipoib_poll_tx_ring(struct napi_struct *napi, int budget)
{
	struct hfi2_ipoib_txq *txq =
		container_of(napi, struct hfi2_ipoib_txq, napi);
	struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;
	u32 head = tx_ring->head;
	/* Pairs with the tail release in the send paths */
	u32 tail = smp_load_acquire(&tx_ring->tail);
	u32 max_tx = tx_ring->max_items;
	int work_done;
	struct ipoib_txreq *tx = hfi2_txreq_from_idx(tx_ring, head);

	trace_hfi2_txq_poll(txq);
	for (work_done = 0; work_done < budget && head != tail; work_done++) {
		/* See hfi2_ipoib_sdma_complete() */
		if (!smp_load_acquire(&tx->complete))
			break;
		tx->complete = 0;
		trace_hfi2_tx_produce(tx, head);
		hfi2_ipoib_free_tx(tx, budget);
		head = CIRC_NEXT(head, max_tx);
		tx =  hfi2_txreq_from_idx(tx_ring, head);
	}
	tx_ring->complete_txreqs += work_done;

	/* Finished freeing tx items so store the head value. */
	smp_store_release(&tx_ring->head, head);

	hfi2_ipoib_check_queue_stopped(txq);

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	return work_done;
}

static void hfi2_ipoib_sdma_complete(struct sdma_txreq *txreq, int status)
{
	struct ipoib_txreq *tx = container_of(txreq, struct ipoib_txreq, txreq);

	trace_hfi2_txq_complete(tx->txq);
	tx->sdma_status = status;
	/* see hfi2_ipoib_poll_tx_ring */
	smp_store_release(&tx->complete, 1);
	napi_schedule_irqoff(&tx->txq->napi);
}

static int hfi2_ipoib_build_ulp_payload(struct ipoib_txreq *tx,
					struct ipoib_txparms *txp)
{
	struct hfi2_devdata *dd = txp->dd;
	struct sdma_txreq *txreq = &tx->txreq;
	struct sk_buff *skb = tx->skb;
	int ret = 0;
	int i;

	if (skb_headlen(skb)) {
		ret = sdma_txadd_kvaddr(dd, txreq, skb->data, skb_headlen(skb));
		if (unlikely(ret))
			return ret;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		ret = sdma_txadd_page(dd,
				      txreq,
				      skb_frag_page(frag),
				      skb_frag_off(frag),
				      skb_frag_size(frag));
		if (unlikely(ret))
			break;
	}

	return ret;
}

/* return hardware send context number from the ipoib txreq */
static u16 ipoib_to_hw_sctxt(struct ipoib_txreq *tx,
			     struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_dev_priv *priv = tx->txq->priv;

	return hfi2_qp_to_send_context(priv->qp, txp->flow.sc5)->hw_context;
}

/* Bytes to append to an @len byte IPoIB payload so it needs no PBC test bit. */
static u32 hfi2_ipoib_test_pad(u32 len, struct rdma_ah_attr *ah_attr)
{
	u32 wire_bytes = 28 + ALIGN(len, 4);

	if (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH)
		wire_bytes += sizeof(struct ib_grh);

	if (likely(!test_len(wire_bytes)))
		return 0;

	return 104 - wire_bytes % 128;
}

/* Map @len bytes of @skb starting at @off, which lies past the headers. */
static int hfi2_ipoib_add_skb_range(struct hfi2_devdata *dd,
				    struct sdma_txreq *txreq,
				    struct sk_buff *skb, u32 off, u32 len)
{
	u32 headlen = skb_headlen(skb);
	int ret;
	int i;

	if (off < headlen) {
		u32 n = min(len, headlen - off);

		ret = sdma_txadd_kvaddr(dd, txreq, skb->data + off, n);
		if (unlikely(ret))
			return ret;
		len -= n;
		off = headlen;
	}
	off -= headlen;

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 size = skb_frag_size(frag);
		u32 n;

		if (off >= size) {
			off -= size;
			continue;
		}
		n = min(len, size - off);
		ret = sdma_txadd_page(dd, txreq, skb_frag_page(frag),
				      skb_frag_off(frag) + off, n);
		if (unlikely(ret))
			return ret;
		len -= n;
		off = 0;
	}

	return len ? -EINVAL : 0;
}

/* Write segment @txp->tso_seg's encap, IPv4 and TCP headers at @h. */
static void hfi2_ipoib_tso_headers(u8 *h, struct ipoib_txparms *txp)
{
	struct sk_buff *skb = txp->tso_skb;
	struct iphdr *iph = (struct iphdr *)(h + skb_network_offset(skb));
	struct tcphdr *th = (struct tcphdr *)(h + skb_transport_offset(skb));
	u32 thlen = txp->tso_hlen - skb_transport_offset(skb);
	u32 seg = txp->tso_seg;
	__wsum csum;

	memcpy(h, skb->data, txp->tso_hlen);

	iph->tot_len = htons(txp->tso_hlen - skb_network_offset(skb) +
			     txp->tso_len);
	iph->id = htons(ntohs(iph->id) + seg);
	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

	th->seq = htonl(ntohl(th->seq) + seg * skb_shinfo(skb)->gso_size);
	if (seg)
		th->cwr = 0;
	if (txp->tso_off + txp->tso_len < skb->len) {
		th->fin = 0;
		th->psh = 0;
	}
	th->check = 0;
	csum = skb_checksum(skb, txp->tso_off, txp->tso_len,
			    csum_partial(th, thlen, 0));
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      thlen + txp->tso_len, IPPROTO_TCP, csum);
}

static int hfi2_ipoib_build_tx_desc(struct ipoib_txreq *tx,
				    struct ipoib_txparms *txp)
{
	struct hfi2_devdata *dd = txp->dd;
	struct sdma_txreq *txreq = &tx->txreq;
	struct hfi2_sdma_header *sdma_hdr = tx->sdma_hdr;
	u16 ib_bytes = sizeof(sdma_hdr->pbc) + (txp->hdr_dwords << 2);
	u16 pkt_bytes = ib_bytes + tx->tx_bytes;
	int ret;

	ret = sdma_txinit(dd, txreq, 0, pkt_bytes, hfi2_ipoib_sdma_complete,
			  ipoib_to_hw_sctxt(tx, txp));
	if (unlikely(ret))
		return ret;

	if (txp->tso_hlen)
		hfi2_ipoib_tso_headers((u8 *)sdma_hdr + ib_bytes, txp);

	/* add pbc + headers */
	ret = sdma_txadd_kvaddr(dd, txreq, sdma_hdr, ib_bytes + txp->tso_hlen);
	if (unlikely(ret))
		return ret;

	if (txp->tso_hlen) {
		ret = hfi2_ipoib_add_skb_range(dd, txreq, txp->tso_skb,
					       txp->tso_off, txp->tso_len);
		/* The header buffer's tail is never written, so it is zero. */
		if (!ret && txp->tso_pad)
			ret = sdma_txadd_kvaddr(dd, txreq,
						(u8 *)sdma_hdr +
						HFI2_IPOIB_TXHDR_SIZE -
						txp->tso_pad, txp->tso_pad);
		return ret;
	}

	/* add the ulp payload */
	return hfi2_ipoib_build_ulp_payload(tx, txp);
}

static void hfi2_ipoib_build_ib_tx_headers(struct ipoib_txreq *tx,
					   struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_dev_priv *priv = tx->txq->priv;
	struct hfi2_sdma_header *sdma_hdr = tx->sdma_hdr;
	struct hfi2_pportdata *ppd = ppd_from_ibp(txp->ibp);
	struct hfi2_devdata *dd = ppd->dd;
	struct rdma_ah_attr *ah_attr = txp->ah_attr;
	struct ib_other_headers *ohdr;
	struct ib_grh *grh;
	u64 pbc;
	u16 dwords;
	u16 slid;
	u16 dlid;
	u16 lrh0;
	u32 bth0;
	u32 sqpn = (u32)(priv->netdev->dev_addr[1] << 16 |
			 priv->netdev->dev_addr[2] << 8 |
			 priv->netdev->dev_addr[3]);
	u16 payload_dwords;
	u8 pad_cnt;

	pad_cnt = -tx->tx_bytes & 3;

	/* Includes ICRC */
	payload_dwords = ((tx->tx_bytes + pad_cnt) >> 2) + SIZE_OF_CRC;

	/* header size in dwords LRH+BTH+DETH = (8+12+8)/4. */
	txp->hdr_dwords = 7;

	if (rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH) {
		grh = &sdma_hdr->hdr.ibh.u.l.grh;
		txp->hdr_dwords +=
			hfi2_make_grh(txp->ibp,
				      grh,
				      rdma_ah_read_grh(ah_attr),
				      txp->hdr_dwords - LRH_9B_DWORDS,
				      payload_dwords);
		lrh0 = HFI2_LRH_GRH;
		ohdr = &sdma_hdr->hdr.ibh.u.l.oth;
	} else {
		lrh0 = HFI2_LRH_BTH;
		ohdr = &sdma_hdr->hdr.ibh.u.oth;
	}

	lrh0 |= (rdma_ah_get_sl(ah_attr) & 0xf) << 4;
	lrh0 |= (txp->flow.sc5 & 0xf) << 12;

	dlid = opa_get_lid(rdma_ah_get_dlid(ah_attr), 9B);
	if (dlid == be16_to_cpu(IB_LID_PERMISSIVE)) {
		slid = be16_to_cpu(IB_LID_PERMISSIVE);
	} else {
		u16 lid = (u16)ppd->lid;

		if (lid) {
			lid |= mk_lid_path_bits(ppd, ah_attr);
			slid = lid;
		} else {
			slid = be16_to_cpu(IB_LID_PERMISSIVE);
		}
	}

	/* Includes ICRC */
	dwords = txp->hdr_dwords + payload_dwords;

	/* Build the lrh */
	sdma_hdr->hdr.hdr_type = HFI2_PKT_TYPE_9B;
	hfi2_make_ib_hdr(&sdma_hdr->hdr.ibh, lrh0, dwords, dlid, slid);

	/* Build the bth */
	bth0 = (IB_OPCODE_UD_SEND_ONLY << 24) | (pad_cnt << 20) | priv->pkey;

	ohdr->bth[0] = cpu_to_be32(bth0);
	ohdr->bth[1] = cpu_to_be32(txp->dqpn);
	ohdr->bth[2] = cpu_to_be32(mask_psn((u32)txp->txq->tx_ring.sent_txreqs));

	/* Build the deth */
	ohdr->u.ud.deth[0] = cpu_to_be32(priv->qkey);
	ohdr->u.ud.deth[1] = cpu_to_be32((txp->entropy <<
					  HFI2_IPOIB_ENTROPY_SHIFT) | sqpn);

	/* Construct the pbc. */
	/*
	 * TODO: determine if sending between VMs on same host,
	 * error if JKR else use loopback port (false => true).
	 */
	pbc = dd->params->create_pbc(ppd, false, pbc_sc4_flag(txp->flow.sc5), 0,
				     sc_to_vlt(ppd, txp->flow.sc5),
				     dwords - SIZE_OF_CRC +
					(sizeof(sdma_hdr->pbc) >> 2),
				     PBC_L2_9B, dlid,
				     ipoib_to_hw_sctxt(tx, txp));
	sdma_hdr->pbc = cpu_to_le64(pbc);
}

static int hfi2_ipoib_aip_prepare_backend(struct ipoib_txreq *tx,
					  struct ipoib_txparms *txp)
{
	struct hfi2_pportdata *ppd = ppd_from_ibp(txp->ibp);
	struct hfi2_ipoib_txq *txq = txp->txq;
	int ret;

	ret = hfi2_ipoib_build_tx_desc(tx, txp);
	if (unlikely(ret))
		return ret;

	if (txq->flow.as_int != txp->flow.as_int) {
		txq->flow.tx_queue = txp->flow.tx_queue;
		txq->flow.sc5 = txp->flow.sc5;
		txq->sde = hfi2_sdma_select_engine_sc(ppd,
						 txp->flow.tx_queue,
						 txp->flow.sc5);
		trace_hfi2_flow_switch(txq);
	}

	return 0;
}

/*
 * Bind the flow to an engine once, while the transmit queue is known: a queue
 * keeps one engine for its lifetime, so a flow never migrates and never
 * stripes per packet.
 */
static int hfi2_ipoib_hfisvc_prepare_backend(struct ipoib_txreq *tx,
					     struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_dev_priv *priv = tx->txq->priv;
	int ret;

	ret = hfi2_ipoib_build_tx_desc(tx, txp);
	if (unlikely(ret))
		return ret;

	tx->hfisvc_engine = txp->txq->q_idx % priv->hfisvc_num_engines;

	return 0;
}

static int hfi2_ipoib_prepare_backend(struct ipoib_txreq *tx,
				      struct ipoib_txparms *txp)
{
	if (tx->txq->priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC)
		return hfi2_ipoib_hfisvc_prepare_backend(tx, txp);

	return hfi2_ipoib_aip_prepare_backend(tx, txp);
}

static struct ipoib_txreq *hfi2_ipoib_send_dma_common(struct net_device *dev,
						      struct sk_buff *skb,
						      struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	struct hfi2_ipoib_txq *txq = txp->txq;
	struct ipoib_txreq *tx;
	struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;
	u32 tail = tx_ring->tail;
	int ret;

	if (unlikely(!tx_ring->avail)) {
		u32 head;

		if (hfi2_ipoib_used(txq) >= hfi2_ipoib_ring_hwat(txq))
			/* This shouldn't happen with a stopped queue */
			return ERR_PTR(-ENOMEM);
		/* See hfi2_ipoib_poll_tx_ring() */
		head = smp_load_acquire(&tx_ring->head);
		tx_ring->avail =
			min_t(u32, hfi2_ipoib_ring_hwat(txq),
			      CIRC_CNT(head, tail, tx_ring->max_items));
	} else {
		tx_ring->avail--;
	}
	tx = hfi2_txreq_from_idx(tx_ring, tail);
	trace_hfi2_txq_alloc_tx(txq);

	/* so that we can test if the sdma descriptors are there */
	tx->txreq.num_desc = 0;
	tx->complete = 0;
	tx->sdma_status = 0;
	tx->txq = txq;
	if (txp->tso_hlen) {
		tx->skb = NULL;
		tx->tx_bytes = txp->tso_hlen + txp->tso_len;
		txp->tso_pad = hfi2_ipoib_test_pad(tx->tx_bytes, txp->ah_attr);
		tx->tx_bytes += txp->tso_pad;
	} else {
		tx->skb = skb;
		tx->tx_bytes = skb->len;
	}
	INIT_LIST_HEAD(&tx->txreq.list);
	INIT_LIST_HEAD(&tx->hfisvc_run);
	tx->hfisvc_group_len = 0;

	hfi2_ipoib_build_ib_tx_headers(tx, txp);

	ret = hfi2_ipoib_prepare_backend(tx, txp);
	if (likely(!ret))
		return tx;

	sdma_txclean(priv->dd, &tx->txreq);

	return ERR_PTR(ret);
}

static int hfi2_ipoib_submit_tx_list(struct net_device *dev,
				     struct hfi2_ipoib_txq *txq)
{
	int ret;
	u16 count_out;

	ret = hfi2_sdma_send_txlist(txq->sde,
			       iowait_get_ib_work(&txq->wait),
			       &txq->tx_list,
			       &count_out);
	if (likely(!ret) || ret == -EBUSY || ret == -ECOMM)
		return ret;

	dd_dev_warn(txq->priv->dd, "cannot send skb tx list, err %d.\n", ret);

	return ret;
}

static int hfi2_ipoib_flush_tx_list(struct net_device *dev,
				    struct hfi2_ipoib_txq *txq)
{
	int ret = 0;

	lockdep_assert_held(&netdev_get_tx_queue(dev, txq->q_idx)->_xmit_lock);

	if (!list_empty(&txq->tx_list)) {
		/* Flush the current list */
		ret = hfi2_ipoib_submit_tx_list(dev, txq);

		if (unlikely(ret))
			if (ret != -EBUSY)
				++dev->stats.tx_carrier_errors;
	}

	return ret;
}

/*
 * Retire a group of egressed packets.  @cookie is the group's first packet and
 * covers @hfisvc_group_len consecutive ring entries; one anchor behind the last
 * of them is enough because packets placed back to back on an engine egress in
 * order.
 *
 * Marking the whole group is safe for hfi2_ipoib_poll_tx_ring(), which walks
 * the ring from its head and stops at the first incomplete entry: a group is a
 * contiguous ring segment, allocated in transmit order from one queue.
 *
 * Do not napi_schedule() here: this runs on the shared bulksvc event thread,
 * so the wake is coalesced into hfi2_ipoib_hfisvc_flush().
 */
static void hfi2_ipoib_hfisvc_complete(void *cookie, int status)
{
	struct ipoib_txreq *tx = cookie;
	struct hfi2_ipoib_txq *txq = tx->txq;
	struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;
	u32 idx = hfi2_txreq_to_idx(tx_ring, tx);
	u16 n = tx->hfisvc_group_len ? tx->hfisvc_group_len : 1;
	u16 i;

	trace_hfi2_txq_complete(txq);

	for (i = 0; i < n; i++) {
		struct ipoib_txreq *t = hfi2_txreq_from_idx(tx_ring, idx);

		t->sdma_status = status ? SDMA_TXREQ_S_SENDERROR :
					  SDMA_TXREQ_S_OK;
		/* see hfi2_ipoib_poll_tx_ring */
		smp_store_release(&t->complete, 1);
		idx = CIRC_NEXT(idx, tx_ring->max_items);
	}

	txq->hfisvc_napi_pending += n;

	/*
	 * Wake the detach waiter only on the last one, and after the stores
	 * above, so a waiter that observes zero sees every completed entry.
	 */
	if (atomic_sub_return(n, &txq->priv->hfisvc_outstanding) == 0)
		wake_up(&txq->priv->hfisvc_drain_wq);
}

/*
 * Record one completion for the @n packets placed from @head.
 *
 * If the anchor cannot be recorded, complete the group inline rather than leak
 * its txreqs, and as sent rather than errored: the packets are in the ring and
 * will egress, only their notification was lost.
 */
static void hfi2_ipoib_hfisvc_anchor_group(struct hfi2_devdata *dd,
					   struct ipoib_txreq *head, u16 n)
{
	int ret;

	if (!n)
		return;

	head->hfisvc_group_len = n;

	ret = hfi2_dms_sdma_anchor(hfi2_bulksvc_primary_dms(dd->bulksvc), head->hfisvc_engine,
				   hfi2_ipoib_hfisvc_complete, head);
	if (unlikely(ret)) {
		dd_dev_warn_ratelimited(dd,
					"ipoib_tx_mode=hfisvc: engine %u anchor failed (%d); completing %u packets inline\n",
					head->hfisvc_engine, ret, n);
		hfi2_ipoib_hfisvc_complete(head, 0);
	}
}

/* Place one packet, leaving the completion to the caller's group anchor. */
static int hfi2_ipoib_hfisvc_place_one(struct hfi2_devdata *dd,
				       struct ipoib_txreq *tx)
{
	struct sdma_txreq *txreq = &tx->txreq;
	int ret;

	if (unlikely(!txreq->num_desc || txreq->num_desc > MAX_DESC)) {
		ret = -EINVAL;
		goto err;
	}

	ret = hfi2_dms_sdma_desc_place(hfi2_bulksvc_primary_dms(dd->bulksvc), tx->hfisvc_engine,
				       txreq->descp, txreq->num_desc,
				       NULL, NULL);
	if (ret == -EAGAIN)
		return ret;
	if (ret)
		goto err;

	/* Balanced in hfi2_ipoib_hfisvc_complete(); detach waits on this. */
	atomic_inc(&tx->txq->priv->hfisvc_outstanding);

	return 0;

err:
	/*
	 * Nothing was placed and no anchor covers this packet, so complete it
	 * here.  It is its own group of one, and the count is taken first so
	 * the completion's decrement stays balanced.
	 */
	tx->hfisvc_group_len = 1;
	atomic_inc(&tx->txq->priv->hfisvc_outstanding);
	hfi2_ipoib_hfisvc_complete(tx, ret);
	return ret;
}

/*
 * Transmit one node's worth of packets.  Runs on the bulksvc event thread.
 *
 * One node covers a run: @tx plus whatever is chained on its @hfisvc_run list,
 * in transmit order.  The descriptors were built in the caller's transmit
 * context and go into the ring verbatim; the doorbell is deferred to the
 * end-of-pass flush.
 *
 * On -EAGAIN the run resumes from the first unplaced packet, reported through
 * @retry, so the handoff can hold it rather than requeueing and reordering it.
 */
static int hfi2_ipoib_hfisvc_egress(void *ctx, struct mpsc_node *node,
				    struct mpsc_node **retry)
{
	struct ipoib_txreq *tx = container_of(node, struct ipoib_txreq,
					      hfisvc_node);
	struct hfi2_ipoib_dev_priv *priv = ctx;
	struct hfi2_devdata *dd = priv->dd;
	int ret;

	struct ipoib_txreq *group = tx;
	u16 placed = 0;

	for (;;) {
		struct ipoib_txreq *next = NULL;

		if (!list_empty(&tx->hfisvc_run)) {
			next = list_first_entry(&tx->hfisvc_run,
						struct ipoib_txreq,
						hfisvc_run);
			/*
			 * Move the remainder off @tx before placing it: once
			 * anchored, its completion may free @tx at any moment.
			 */
			list_del_init(&next->hfisvc_run);
			list_splice_init(&tx->hfisvc_run, &next->hfisvc_run);
		}

		ret = hfi2_ipoib_hfisvc_place_one(dd, tx);
		if (ret == -EAGAIN) {
			/* Not placed, so @tx keeps the run and is retried. */
			if (next) {
				list_splice_init(&next->hfisvc_run,
						 &tx->hfisvc_run);
				list_add(&next->hfisvc_run, &tx->hfisvc_run);
			}
			hfi2_ipoib_hfisvc_anchor_group(dd, group, placed);
			*retry = &tx->hfisvc_node;
			return -EAGAIN;
		}

		if (!ret) {
			placed++;
		} else if (group == tx) {
			/* Failed and self-completed; the group starts after it. */
			group = next;
		} else {
			/* Not covered by the anchor: close the group before it. */
			hfi2_ipoib_hfisvc_anchor_group(dd, group, placed);
			group = next;
			placed = 0;
		}

		if (!next) {
			hfi2_ipoib_hfisvc_anchor_group(dd, group, placed);
			return 0;
		}
		tx = next;
	}
}

/* One NAPI wake per queue the pass completed for, rather than per group. */
static void hfi2_ipoib_hfisvc_flush(void *ctx)
{
	struct hfi2_ipoib_dev_priv *priv = ctx;
	int i;

	for (i = 0; i < priv->netdev->num_tx_queues; i++) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];

		if (!txq->hfisvc_napi_pending)
			continue;

		txq->hfisvc_napi_pending = 0;
		napi_schedule(&txq->napi);
	}
}

/*
 * How long detach waits for placed packets to complete.  Generous: it is a
 * teardown path, and the alternative to waiting is unmapping DMA the engine
 * may still be reading.
 */
#define HFI2_IPOIB_HFISVC_DRAIN_TIMEOUT msecs_to_jiffies(5000)

/* Demote, never fail: on a setup error ib_ipoib drives us with ipoib_send(). */
void hfi2_ipoib_select_tx_mode(struct hfi2_ipoib_dev_priv *priv)
{
	struct hfi2_devdata *dd = priv->dd;

	if (priv->tx_mode != HFI2_IPOIB_TX_MODE_HFISVC)
		return;

	if (!dd->bulksvc) {
		dd_dev_warn(dd,
			    "ipoib_tx_mode=hfisvc: bulksvc is not running; using aip\n");
		goto fallback;
	}

	BUILD_BUG_ON(offsetof(struct hfi2_ipoib_dev_priv, hfisvc_outstanding) / SMP_CACHE_BYTES ==
		     offsetof(struct hfi2_ipoib_dev_priv, tx_mode) / SMP_CACHE_BYTES);
	atomic_set(&priv->hfisvc_outstanding, 0);
	init_waitqueue_head(&priv->hfisvc_drain_wq);
	priv->hfisvc_requested = true;
	return;

fallback:
	priv->tx_mode = HFI2_IPOIB_TX_MODE_AIP;
}

/* An open can precede the DMS resource loan. */
void hfi2_ipoib_hfisvc_latch(struct hfi2_ipoib_dev_priv *priv)
{
	struct hfi2_devdata *dd = priv->dd;
	u8 pidx = priv->ppd->hw_pidx;
	u32 num_sde, data_sde;

	if (!priv->hfisvc_requested)
		return;

	priv->tx_mode = HFI2_IPOIB_TX_MODE_AIP;

	if (!dd->bulksvc) {
		dd_dev_warn(dd, "ipoib_tx_mode=hfisvc: bulksvc is gone; using aip\n");
		return;
	}

	if (pidx >= HFI2_DMS_MAX_PORTS) {
		dd_dev_warn(dd, "ipoib_tx_mode=hfisvc: invalid port %u; using aip\n",
			    priv->port_num);
		return;
	}

	num_sde = dd->bulksvc->prereqs.num_sdma;
	if (!num_sde) {
		dd_dev_warn(dd, "ipoib_tx_mode=hfisvc: no SDMA engines; using aip\n");
		return;
	}
	data_sde = num_sde > 1 ? num_sde - 1 : num_sde;

	priv->hfisvc_port_idx = pidx;
	priv->hfisvc_num_engines =
		(u8)min_t(u32, data_sde, U8_MAX);
	priv->tx_mode = HFI2_IPOIB_TX_MODE_HFISVC;
}

void hfi2_ipoib_hfisvc_attach(struct hfi2_ipoib_dev_priv *priv)
{
	struct hfi2_bulksvc_ipoib_ops ops = {
		.ctx = priv,
		/* Only a full engine ring defers, so one lane per engine. */
		.nlanes = priv->hfisvc_num_engines,
		.egress = hfi2_ipoib_hfisvc_egress,
		.flush = hfi2_ipoib_hfisvc_flush,
	};
	int ret;

	if (priv->tx_mode != HFI2_IPOIB_TX_MODE_HFISVC)
		return;

	ret = hfi2_bulksvc_ipoib_port_register(priv->dd->bulksvc,
					       priv->hfisvc_port_idx, &ops);
	if (ret) {
		dd_dev_warn(priv->dd,
			    "ipoib_tx_mode=hfisvc: cannot attach port %u (%d); using aip\n",
			    priv->port_num, ret);
		priv->tx_mode = HFI2_IPOIB_TX_MODE_AIP;
		return;
	}

	priv->hfisvc_attached = true;

	dd_dev_info(priv->dd,
		    "ipoib_tx_mode=hfisvc active on port %u: %u DMS engines, %u TX queues\n",
		    priv->port_num, priv->hfisvc_num_engines,
		    priv->netdev->num_tx_queues);
}

void hfi2_ipoib_hfisvc_detach(struct hfi2_ipoib_dev_priv *priv)
{
	if (!priv->hfisvc_attached)
		return;

	hfi2_bulksvc_ipoib_port_unregister(priv->dd->bulksvc,
					   priv->hfisvc_port_idx);
	priv->hfisvc_attached = false;

	/*
	 * Detach only stops the event thread from starting new egress.  Packets
	 * already in an engine ring still hold DMA mappings and still owe a
	 * completion, and ndo_stop drains the transmit ring immediately after
	 * this returns -- freeing skbs and unmapping descriptors the engine may
	 * still be reading, and leaving completions to retire ring entries that
	 * have been reused.  Wait for them.
	 *
	 * The event thread retires these, so this cannot be called from it.
	 * The wait is bounded: a placed packet either egresses or is
	 * error-completed when its engine is torn down.
	 */
	if (!wait_event_timeout(priv->hfisvc_drain_wq,
				!atomic_read(&priv->hfisvc_outstanding),
				HFI2_IPOIB_HFISVC_DRAIN_TIMEOUT))
		dd_dev_err(priv->dd,
			   "ipoib_tx_mode=hfisvc: %d transmits outstanding at detach\n",
			   atomic_read(&priv->hfisvc_outstanding));
}

static int hfi2_ipoib_submit_tx(struct hfi2_ipoib_txq *txq,
				struct ipoib_txreq *tx)
{
	int ret;

	ret = hfi2_sdma_send_txreq(txq->sde,
			      iowait_get_ib_work(&txq->wait),
			      &tx->txreq,
			      txq->pkts_sent);
	if (likely(!ret)) {
		txq->pkts_sent = true;
		iowait_starve_clear(txq->pkts_sent, &txq->wait);
	}

	return ret;
}

/*
 * Longest transmit run handed over as one unit.  The cap bounds latency, not
 * throughput: the run's first packet waits for the run to close.
 */
#define HFI2_IPOIB_HFISVC_RUN_MAX 32

/*
 * Enqueue exactly one MPSC node, the run head's; the rest are chained behind
 * it on @hfisvc_run in transmit order.  After this the run belongs to the
 * event thread and must not be touched.
 *
 * A queue's packets all share one engine, so the run never spans two lanes.
 */
static void hfi2_ipoib_hfisvc_run_submit(struct hfi2_ipoib_txq *txq)
{
	struct ipoib_txreq *head = txq->hfisvc_run_head;

	if (!head)
		return;

	txq->hfisvc_run_head = NULL;
	txq->hfisvc_run_len = 0;

	hfi2_bulksvc_ipoib_tx_enqueue(txq->priv->dd->bulksvc,
				      txq->priv->hfisvc_port_idx,
				      head->hfisvc_engine,
				      &head->hfisvc_node);
}

/*
 * Close the run when the stack says no more skbs are coming, when the subqueue
 * has been stopped (nothing further will arrive to close it), or at the cap.
 */
static void hfi2_ipoib_hfisvc_run_add(struct net_device *dev,
				      struct hfi2_ipoib_txq *txq,
				      struct ipoib_txreq *tx, bool more)
{
	INIT_LIST_HEAD(&tx->hfisvc_run);

	if (!txq->hfisvc_run_head)
		txq->hfisvc_run_head = tx;
	else
		list_add_tail(&tx->hfisvc_run,
			      &txq->hfisvc_run_head->hfisvc_run);
	txq->hfisvc_run_len++;

	if (!more || txq->hfisvc_run_len >= HFI2_IPOIB_HFISVC_RUN_MAX ||
	    __netif_subqueue_stopped(dev, txq->q_idx))
		hfi2_ipoib_hfisvc_run_submit(txq);
}

static void hfi2_ipoib_napi_rebind(struct work_struct *work)
{
	struct hfi2_ipoib_txq *txq =
		container_of(work, struct hfi2_ipoib_txq, napi_work);
	struct net_device *dev = txq->priv->netdev;
	int node = READ_ONCE(txq->napi_node);
	cpumask_var_t mask;

	if (node == NUMA_NO_NODE || !zalloc_cpumask_var(&mask, GFP_KERNEL))
		return;
	cpumask_and(mask, cpumask_of_node(node),
		    housekeeping_cpumask(HK_TYPE_KTHREAD));
	/* Turning threaded NAPI off stops the thread under the netdev lock. */
	netdev_lock(dev);
	if (txq->napi.thread && !cpumask_empty(mask) &&
	    !set_cpus_allowed_ptr(txq->napi.thread, mask))
		WRITE_ONCE(txq->napi_bound, txq->napi.thread);
	netdev_unlock(dev);
	free_cpumask_var(mask);
}

/*
 * The TX NAPI thread frees the skbs this queue's sender allocated.  Freeing
 * them on another node makes every later allocation miss, so keep the thread
 * on the sender's node.
 */
static void hfi2_ipoib_napi_follow(struct hfi2_ipoib_txq *txq)
{
	int node = numa_node_id();

	if ((likely(node == txq->napi_node) &&
	     likely(txq->napi.thread == READ_ONCE(txq->napi_bound))) ||
	    !txq->napi.thread || time_before(jiffies, txq->napi_moved + HZ))
		return;
	txq->napi_moved = jiffies;
	WRITE_ONCE(txq->napi_node, node);
	queue_work(system_unbound_wq, &txq->napi_work);
}

static int hfi2_ipoib_send_dma_single(struct net_device *dev,
				      struct sk_buff *skb,
				      struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_txq *txq = txp->txq;
	struct hfi2_ipoib_circ_buf *tx_ring;
	struct ipoib_txreq *tx;
	int ret;

	tx = hfi2_ipoib_send_dma_common(dev, skb, txp);
	if (IS_ERR(tx)) {
		int ret = PTR_ERR(tx);

		dev_kfree_skb_any(skb);

		if (ret == -ENOMEM)
			++dev->stats.tx_errors;
		else
			++dev->stats.tx_carrier_errors;

		return NETDEV_TX_OK;
	}

	tx_ring = &txq->tx_ring;
	trace_hfi2_tx_consume(tx, tx_ring->tail);
	/* consume tx */
	smp_store_release(&tx_ring->tail, CIRC_NEXT(tx_ring->tail, tx_ring->max_items));

	if (txq->priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC) {
		/* Enqueue cannot fail; every outcome arrives via the TX NAPI. */
		trace_sdma_output_ibhdr(txq->priv->dd, &tx->sdma_hdr->hdr,
					ib_is_sc5(txp->flow.sc5), 0);
		/*
		 * Depth first: run_add() closes the run when the subqueue is
		 * stopped, and it is this call that stops it.  A run held
		 * across the stop has nothing in flight to complete it and
		 * nothing arriving to close it.
		 */
		hfi2_ipoib_napi_follow(txq);
		hfi2_ipoib_check_queue_depth(txq);
		hfi2_ipoib_hfisvc_run_add(dev, txq, tx, netdev_xmit_more());
		return NETDEV_TX_OK;
	}

	ret = hfi2_ipoib_submit_tx(txq, tx);
	trace_sdma_output_ibhdr(txq->priv->dd,
				&tx->sdma_hdr->hdr,
				ib_is_sc5(txp->flow.sc5), ret);
	if (likely(!ret)) {
tx_ok:
		hfi2_ipoib_check_queue_depth(txq);
		return NETDEV_TX_OK;
	}

	txq->pkts_sent = false;

	if (ret == -EBUSY || ret == -ECOMM)
		goto tx_ok;

	/* mark complete and kick napi tx */
	hfi2_ipoib_check_queue_depth(txq);
	smp_store_release(&tx->complete, 1);
	napi_schedule(&tx->txq->napi);

	++dev->stats.tx_carrier_errors;

	return NETDEV_TX_OK;
}

static int hfi2_ipoib_send_dma_list(struct net_device *dev,
				    struct sk_buff *skb,
				    struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_txq *txq = txp->txq;
	struct hfi2_ipoib_circ_buf *tx_ring;
	struct ipoib_txreq *tx;

	/* Has the flow change ? */
	if (txq->flow.as_int != txp->flow.as_int) {
		int ret;

		trace_hfi2_flow_flush(txq);
		ret = hfi2_ipoib_flush_tx_list(dev, txq);
		if (unlikely(ret)) {
			if (ret == -EBUSY)
				++dev->stats.tx_dropped;
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
	}
	tx = hfi2_ipoib_send_dma_common(dev, skb, txp);
	if (IS_ERR(tx)) {
		int ret = PTR_ERR(tx);

		dev_kfree_skb_any(skb);

		if (ret == -ENOMEM)
			++dev->stats.tx_errors;
		else
			++dev->stats.tx_carrier_errors;

		return NETDEV_TX_OK;
	}

	tx_ring = &txq->tx_ring;
	trace_hfi2_tx_consume(tx, tx_ring->tail);
	/* consume tx */
	smp_store_release(&tx_ring->tail, CIRC_NEXT(tx_ring->tail, tx_ring->max_items));
	list_add_tail(&tx->txreq.list, &txq->tx_list);

	hfi2_ipoib_check_queue_depth(txq);

	trace_sdma_output_ibhdr(txq->priv->dd,
				&tx->sdma_hdr->hdr,
				ib_is_sc5(txp->flow.sc5), 0);

	if (!netdev_xmit_more() ||
	    __netif_subqueue_stopped(dev, txq->q_idx))
		(void)hfi2_ipoib_flush_tx_list(dev, txq);

	return NETDEV_TX_OK;
}

/* kv: [63:32] hash, [23:16] queue, [15:8] byte, [2:1] assigned, [0] valid */
#define HFI2_IPOIB_FLOW_VALID BIT_ULL(0)
#define HFI2_IPOIB_FLOW_HAS_E BIT_ULL(1)
#define HFI2_IPOIB_FLOW_HAS_Q BIT_ULL(2)

static inline u32 hfi2_ipoib_flow_key(u64 kv)
{
	return (u32)(kv >> 32);
}

static inline u8 hfi2_ipoib_flow_byte(u64 kv)
{
	return (u8)(kv >> 8);
}

static inline u8 hfi2_ipoib_flow_queue(u64 kv)
{
	return (u8)(kv >> 16);
}

static inline u64 hfi2_ipoib_flow_kv(u32 key)
{
	return ((u64)key << 32) | HFI2_IPOIB_FLOW_VALID;
}

static inline u64 hfi2_ipoib_flow_set_byte(u64 kv, u8 byte)
{
	return (kv & ~(0xffULL << 8)) | ((u64)byte << 8) |
	       HFI2_IPOIB_FLOW_VALID | HFI2_IPOIB_FLOW_HAS_E;
}

static inline u64 hfi2_ipoib_flow_set_queue(u64 kv, u8 q)
{
	return (kv & ~(0xffULL << 16)) | ((u64)q << 16) |
	       HFI2_IPOIB_FLOW_VALID | HFI2_IPOIB_FLOW_HAS_Q;
}

/* The peer's RSM takes bucket (e & 15) ^ (e >> 4); b itself is one e. */
static inline u8 hfi2_ipoib_bucket_byte(u32 b)
{
	BUILD_BUG_ON(NUM_NETDEV_MAP_ENTRIES != 16);

	return (u8)(b & (NUM_NETDEV_MAP_ENTRIES - 1));
}

static inline u32 hfi2_ipoib_flow_set_idx(u32 h)
{
	return (h ^ (h >> 16)) & (HFI2_IPOIB_FLOW_SETS - 1);
}

/* Separate counters: a shared one would correlate bucket and queue. */
static u64 hfi2_ipoib_flow_assign(struct hfi2_ipoib_dev_priv *priv, u64 kv,
				  u64 need)
{
	struct hfi2_ipoib_flowtab *ft = &priv->flowtab;
	u32 i;

	lockdep_assert_held(&ft->assign_lock);

	if (need == HFI2_IPOIB_FLOW_HAS_E) {
		i = ft->rr++ & (NUM_NETDEV_MAP_ENTRIES - 1);
		return hfi2_ipoib_flow_set_byte(kv, hfi2_ipoib_bucket_byte(i));
	}

	i = ft->qrr++ % READ_ONCE(priv->netdev->real_num_tx_queues);
	return hfi2_ipoib_flow_set_queue(kv, (u8)i);
}

/*
 * A counter, not a hash, spreads flows evenly; the table keeps each flow's
 * assignment for its life, because moving a live flow reorders it.
 */
static u64 hfi2_ipoib_flow_lookup(struct hfi2_ipoib_dev_priv *priv, u32 h,
				  u64 need)
{
	struct hfi2_ipoib_flowtab *ft = &priv->flowtab;
	unsigned long age = msecs_to_jiffies(HFI2_IPOIB_FLOW_AGE_MS);
	struct hfi2_ipoib_flowset *set;
	unsigned long now = jiffies;
	bool reusable = false;
	unsigned long flags;
	u64 kv;
	int i;

	if (unlikely(!ft->set || !h))
		return 0;

	set = &ft->set[hfi2_ipoib_flow_set_idx(h)];

	for (i = 0; i < HFI2_IPOIB_FLOW_WAYS; i++) {
		kv = READ_ONCE(set->way[i].kv);

		if (!(kv & HFI2_IPOIB_FLOW_VALID)) {
			reusable = true;
			continue;
		}
		if (hfi2_ipoib_flow_key(kv) != h) {
			if (now - READ_ONCE(set->way[i].seen) > age)
				reusable = true;
			continue;
		}

		/* Coarse stamp keeps the shared line read-mostly. */
		if (now - READ_ONCE(set->way[i].seen) > HZ / 4)
			WRITE_ONCE(set->way[i].seen, now);

		if (likely(kv & need))
			return kv;

		/* Admitted by the other path: add this assignment, keep the other. */
		spin_lock_irqsave(&ft->assign_lock, flags);
		kv = set->way[i].kv;
		/* Recycled under us; one stateless packet beats a retry loop. */
		if (unlikely(hfi2_ipoib_flow_key(kv) != h)) {
			kv = 0;
		} else if (!(kv & need)) {
			kv = hfi2_ipoib_flow_assign(priv, kv, need);
			WRITE_ONCE(set->way[i].kv, kv);
		}
		spin_unlock_irqrestore(&ft->assign_lock, flags);
		return kv;
	}

	/* A full set admits nothing until quiet, or a fallen-back flow moves. */
	if (READ_ONCE(set->quar) &&
	    now - READ_ONCE(set->quar_seen) <= age) {
		WRITE_ONCE(set->quar_seen, now);
		return 0;
	}

	if (!reusable) {
		spin_lock_irqsave(&ft->assign_lock, flags);
		set->quar = true;
		set->quar_seen = now;
		spin_unlock_irqrestore(&ft->assign_lock, flags);
		return 0;
	}

	spin_lock_irqsave(&ft->assign_lock, flags);

	/* Re-scan: another cpu may have assigned this flow or taken the way. */
	for (i = 0; i < HFI2_IPOIB_FLOW_WAYS; i++) {
		kv = set->way[i].kv;

		if ((kv & HFI2_IPOIB_FLOW_VALID) &&
		    hfi2_ipoib_flow_key(kv) == h) {
			set->way[i].seen = now;
			if (!(kv & need)) {
				kv = hfi2_ipoib_flow_assign(priv, kv, need);
				WRITE_ONCE(set->way[i].kv, kv);
			}
			spin_unlock_irqrestore(&ft->assign_lock, flags);
			return kv;
		}
	}

	if (set->quar) {
		if (now - set->quar_seen <= age) {
			spin_unlock_irqrestore(&ft->assign_lock, flags);
			return 0;
		}
		set->quar = false;
	}

	for (i = 0; i < HFI2_IPOIB_FLOW_WAYS; i++)
		if (!(set->way[i].kv & HFI2_IPOIB_FLOW_VALID))
			goto admit;

	for (i = 0; i < HFI2_IPOIB_FLOW_WAYS; i++)
		if (now - set->way[i].seen > age)
			goto admit;

	set->quar = true;
	set->quar_seen = now;
	spin_unlock_irqrestore(&ft->assign_lock, flags);
	return 0;

admit:
	kv = hfi2_ipoib_flow_assign(priv, hfi2_ipoib_flow_kv(h), need);

	set->way[i].seen = now;
	WRITE_ONCE(set->way[i].kv, kv);

	spin_unlock_irqrestore(&ft->assign_lock, flags);

	return kv;
}

/* Let the stack segment what this queue cannot: it may have fallen back to aip. */
netdev_features_t hfi2_ipoib_features_check(struct sk_buff *skb,
					    struct net_device *dev,
					    netdev_features_t features)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	/* Forwarding calls this before a queue is picked; all rings match. */
	struct hfi2_ipoib_txq *txq = &priv->txqs[0];

	if (skb_is_gso(skb)) {
		struct rdma_netdev *rn = netdev_priv(dev);
		u32 hlen;
		u32 mss = skb_shinfo(skb)->gso_size;

		if (priv->tx_mode != HFI2_IPOIB_TX_MODE_HFISVC ||
		    !(skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) ||
		    skb_has_frag_list(skb) || !skb_transport_header_was_set(skb) ||
		    !mss || !skb_shinfo(skb)->gso_segs ||
		    skb_shinfo(skb)->gso_segs > hfi2_ipoib_ring_hwat(txq) -
						 hfi2_ipoib_ring_stop(txq))
			return features & ~NETIF_F_GSO_MASK;

		if (skb_transport_offset(skb) > skb_headlen(skb) ||
		    skb_headlen(skb) - skb_transport_offset(skb) < sizeof(struct tcphdr))
			return features & ~NETIF_F_GSO_MASK;
		hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
		if (hlen > HFI2_IPOIB_ENCAP_LEN + 2 * 60 ||
		    skb_headlen(skb) < hlen ||
		    hlen + mss > rn->mtu + HFI2_IPOIB_ENCAP_LEN)
			features &= ~NETIF_F_GSO_MASK;
	}
	return features;
}

u16 hfi2_ipoib_select_queue(struct net_device *dev, struct sk_buff *skb,
			    struct net_device *sb_dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	u64 kv;
	u16 q;

	kv = hfi2_ipoib_flow_lookup(priv, skb_get_hash(skb),
				    HFI2_IPOIB_FLOW_HAS_Q);
	if (!kv)
		return netdev_pick_tx(dev, skb, sb_dev);

	q = hfi2_ipoib_flow_queue(kv);

	if (unlikely(q >= dev->real_num_tx_queues))
		return netdev_pick_tx(dev, skb, sb_dev);

	return q;
}

static u8 hfi2_ipoib_flow_entropy(struct hfi2_ipoib_dev_priv *priv,
				  struct sk_buff *skb, u8 fallback)
{
	u64 kv = hfi2_ipoib_flow_lookup(priv, skb_get_hash(skb),
					HFI2_IPOIB_FLOW_HAS_E);

	return kv ? hfi2_ipoib_flow_byte(kv) : fallback;
}

static u8 hfi2_ipoib_calc_entropy(struct hfi2_ipoib_dev_priv *priv,
				  struct sk_buff *skb)
{
	u8 stateless;

	if (skb_transport_header_was_set(skb)) {
		u8 *hdr = (u8 *)skb_transport_header(skb);

		stateless = (hdr[0] ^ hdr[1] ^ hdr[2] ^ hdr[3]);
	} else {
		stateless = (u8)skb_get_queue_mapping(skb);
	}

	return hfi2_ipoib_flow_entropy(priv, skb, stateless);
}

static int hfi2_ipoib_flowtab_init(struct hfi2_ipoib_dev_priv *priv)
{
	struct hfi2_ipoib_flowtab *ft = &priv->flowtab;

	spin_lock_init(&ft->assign_lock);
	ft->rr = 0;
	ft->qrr = 0;
	ft->set = kvcalloc_node(HFI2_IPOIB_FLOW_SETS, sizeof(*ft->set),
				GFP_KERNEL, priv->dd->node);
	return ft->set ? 0 : -ENOMEM;
}

static void hfi2_ipoib_flowtab_deinit(struct hfi2_ipoib_dev_priv *priv)
{
	kvfree(priv->flowtab.set);
	priv->flowtab.set = NULL;
}

/*
 * Pad a packet whose wire length needs the PBC test bit.  The pad follows the
 * IP datagram, which carries its own length, so the receiver's IP stack trims
 * it.  On error the skb has been freed.
 */
static int hfi2_ipoib_pad_test_len(struct sk_buff *skb,
				   struct rdma_ah_attr *ah_attr)
{
	u32 pad = hfi2_ipoib_test_pad(skb->len, ah_attr);

	if (likely(!pad))
		return 0;

	return skb_put_padto(skb, skb->len + pad);
}

/*
 * Segment a TCPv4 GSO skb straight into ring entries: each segment gets its
 * own copy of the headers and points at its slice of the skb's data, which
 * the last segment owns.  Hand-off runs one segment behind so that, if a
 * segment cannot be built, the skb can still be attached to the one before.
 */
static int hfi2_ipoib_send_tso(struct net_device *dev, struct sk_buff *skb,
			       struct ipoib_txparms *txp)
{
	struct hfi2_ipoib_txq *txq = txp->txq;
	struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;
	struct rdma_netdev *rn = netdev_priv(dev);
	u32 hlen = skb_transport_offset(skb) + tcp_hdrlen(skb);
	u32 mss = skb_shinfo(skb)->gso_size;
	struct ipoib_txreq *prev = NULL;
	struct ipoib_txreq *tx;

	/* PBC, LRH+GRH+BTH+DETH, copied headers, then a test-length pad */
	BUILD_BUG_ON(8 + 28 + sizeof(struct ib_grh) + HFI2_IPOIB_ENCAP_LEN +
		     2 * 60 + 32 > HFI2_IPOIB_TXHDR_SIZE);

	if (unlikely(txq->priv->tx_mode != HFI2_IPOIB_TX_MODE_HFISVC ||
		     !(skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4) ||
		     skb_has_frag_list(skb) || !mss ||
		     hlen > HFI2_IPOIB_ENCAP_LEN + 2 * 60 ||
		     skb_headlen(skb) < hlen ||
		     hlen + mss > rn->mtu + HFI2_IPOIB_ENCAP_LEN))
		goto drop;
	txp->tso_skb = skb;
	txp->tso_hlen = hlen;

	for (txp->tso_off = txp->tso_hlen, txp->tso_seg = 0;
	     txp->tso_off < skb->len;
	     txp->tso_off += txp->tso_len, txp->tso_seg++) {
		txp->tso_len = min(mss, skb->len - txp->tso_off);
		tx = hfi2_ipoib_send_dma_common(dev, skb, txp);
		if (IS_ERR(tx)) {
			if (prev)
				++dev->stats.tx_dropped;
			break;
		}
		/* consume tx */
		smp_store_release(&tx_ring->tail,
				  CIRC_NEXT(tx_ring->tail, tx_ring->max_items));
		hfi2_ipoib_check_queue_depth(txq);
		if (prev)
			hfi2_ipoib_hfisvc_run_add(dev, txq, prev, true);
		prev = tx;
	}

	if (!prev)
		goto drop;

	prev->skb = skb;
	hfi2_ipoib_napi_follow(txq);
	hfi2_ipoib_hfisvc_run_add(dev, txq, prev, netdev_xmit_more());
	return NETDEV_TX_OK;

drop:
	++dev->stats.tx_dropped;
	++dev->stats.tx_errors;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

int hfi2_ipoib_send(struct net_device *dev,
		    struct sk_buff *skb,
		    struct ib_ah *address,
		    u32 dqpn)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	struct ipoib_txparms txp;
	struct rdma_netdev *rn = netdev_priv(dev);

	if (unlikely(!skb_is_gso(skb) &&
		     skb->len > rn->mtu + HFI2_IPOIB_ENCAP_LEN)) {
		dd_dev_warn(priv->dd, "packet len %d (> %d) too long to send, dropping\n",
			    skb->len,
			    rn->mtu + HFI2_IPOIB_ENCAP_LEN);
		++dev->stats.tx_dropped;
		++dev->stats.tx_errors;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	txp.dd = priv->dd;
	txp.ah_attr = &ibah_to_rvtah(address)->attr;

	txp.ibp = to_iport(priv->device, priv->port_num);
	txp.txq = &priv->txqs[skb_get_queue_mapping(skb)];
	txp.dqpn = dqpn;
	txp.flow.sc5 = txp.ibp->sl_to_sc[rdma_ah_get_sl(txp.ah_attr)];
	txp.flow.tx_queue = (u8)skb_get_queue_mapping(skb);
	txp.entropy = hfi2_ipoib_calc_entropy(priv, skb);
	txp.tso_hlen = 0;

	if (skb_is_gso(skb))
		return hfi2_ipoib_send_tso(dev, skb, &txp);

	if (skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb)) {
		++dev->stats.tx_dropped;
		++dev->stats.tx_errors;
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(hfi2_ipoib_pad_test_len(skb, txp.ah_attr))) {
		++dev->stats.tx_dropped;
		++dev->stats.tx_errors;
		return NETDEV_TX_OK;
	}

	/*
	 * hfi2_ipoib_send_dma_list() submits with hfi2_sdma_send_txlist(), which
	 * needs txq->sde and an iowait.  hfisvc has no ordinary engine, so
	 * txq->sde stays NULL; it batches the handoff instead, see
	 * hfi2_ipoib_hfisvc_run_add().
	 */
	if (priv->tx_mode != HFI2_IPOIB_TX_MODE_HFISVC &&
	    (netdev_xmit_more() || !list_empty(&txp.txq->tx_list)))
		return hfi2_ipoib_send_dma_list(dev, skb, &txp);

	return hfi2_ipoib_send_dma_single(dev, skb,  &txp);
}

/*
 * hfi2_ipoib_sdma_sleep - ipoib sdma sleep function
 *
 * This function gets called from hfi2_sdma_send_txreq() when there are not enough
 * sdma descriptors available to send the packet. It adds Tx queue's wait
 * structure to sdma engine's dmawait list to be woken up when descriptors
 * become available.
 */
static int hfi2_ipoib_sdma_sleep(struct sdma_engine *sde,
				 struct iowait_work *wait,
				 struct sdma_txreq *txreq,
				 uint seq,
				 bool pkts_sent)
{
	struct hfi2_ipoib_txq *txq =
		container_of(wait->iow, struct hfi2_ipoib_txq, wait);

	write_seqlock(&sde->waitlock);

	if (likely(txq->priv->netdev->reg_state == NETREG_REGISTERED)) {
		if (sdma_progress(sde, seq, txreq)) {
			write_sequnlock(&sde->waitlock);
			return -EAGAIN;
		}

		if (list_empty(&txreq->list))
			/* came from non-list submit */
			list_add_tail(&txreq->list, &txq->tx_list);
		if (list_empty(&txq->wait.list)) {
			struct hfi2_ibport *ibp = to_iport(txq->priv->device,
							   txq->priv->port_num);

			if (!atomic_xchg(&txq->tx_ring.no_desc, 1)) {
				trace_hfi2_txq_queued(txq);
				hfi2_ipoib_stop_txq(txq);
			}
			ibp->rvp.n_dmawait++;
			iowait_queue(pkts_sent, wait->iow, &sde->dmawait);
		}

		write_sequnlock(&sde->waitlock);

		/*
		 * Check for progress after unlocking. This closes a race
		 * where SDMA completions ran between setting no_desc and
		 * adding to dmawait - the wakeup walked the list before we
		 * were on it. If progress occurred, self-schedule wakeup.
		 */
		if (txq->priv->netdev->reg_state == NETREG_REGISTERED &&
		    sdma_progress(sde, seq, txreq))
			iowait_schedule(&txq->wait, system_highpri_wq,
					WORK_CPU_UNBOUND);

		return -EBUSY;
	}

	write_sequnlock(&sde->waitlock);
	return -EINVAL;
}

/*
 * hfi2_ipoib_sdma_wakeup - ipoib sdma wakeup function
 *
 * This function gets called when SDMA descriptors becomes available and Tx
 * queue's wait structure was previously added to sdma engine's dmawait list.
 *
 * Clear the no_desc stop reason and wake the subqueue here rather than leaving
 * it to the flush work item, which runs on a SCHED_OTHER kworker and can be
 * delayed arbitrarily while the subqueue stays XOFF and the engine sits idle.
 *
 * The flush itself has to stay deferred.  Callers hold sde->head_lock, some
 * hold sde->tail_lock, and sdma_flush() holds sde->waitlock across the
 * callback because it dequeues the waiter afterwards.  Take none of the
 * three: hfi2_ipoib_flush_tx_list() re-enters hfi2_sdma_send_txlist(), which
 * acquires tail_lock.
 *
 * no_desc now has three clearers - here, hfi2_ipoib_flush_txq() and
 * hfi2_ipoib_check_queue_stopped().  All three clear with atomic_xchg() and
 * act only on the 1 -> 0 transition, matching the 0 -> 1 xchg that stops the
 * queue, so @stops sees exactly one decrement per stop no matter how the
 * three interleave.
 */
static void hfi2_ipoib_sdma_wakeup(struct iowait *wait, int reason)
{
	struct hfi2_ipoib_txq *txq =
		container_of(wait, struct hfi2_ipoib_txq, wait);

	trace_hfi2_txq_wakeup(txq);
	if (unlikely(txq->priv->netdev->reg_state != NETREG_REGISTERED))
		return;

	if (atomic_xchg(&txq->tx_ring.no_desc, 0))
		hfi2_ipoib_wake_txq(txq);

	iowait_schedule(wait, system_highpri_wq, WORK_CPU_UNBOUND);
}

static void hfi2_ipoib_flush_txq(struct work_struct *work)
{
	struct iowait_work *ioww =
		container_of(work, struct iowait_work, iowork);
	struct iowait *wait = iowait_ioww_to_iow(ioww);
	struct hfi2_ipoib_txq *txq =
		container_of(wait, struct hfi2_ipoib_txq, wait);
	struct net_device *dev = txq->priv->netdev;
	struct netdev_queue *ndq = netdev_get_tx_queue(dev, txq->q_idx);

	if (unlikely(dev->reg_state != NETREG_REGISTERED))
		return;

	/*
	 * _bh: this is process context, while the sender takes the same lock
	 * from softirq.
	 */
	__netif_tx_lock_bh(ndq);
	if (likely(!hfi2_ipoib_flush_tx_list(dev, txq)))
		if (atomic_xchg(&txq->tx_ring.no_desc, 0))
			hfi2_ipoib_wake_txq(txq);
	__netif_tx_unlock_bh(ndq);
}

int hfi2_ipoib_txreq_init(struct hfi2_ipoib_dev_priv *priv)
{
	struct net_device *dev = priv->netdev;
	u32 tx_ring_size, tx_item_size;
	struct hfi2_ipoib_circ_buf *tx_ring;
	int i, j;

	/*
	 * Ring holds 1 less than tx_ring_size
	 * Round up to next power of 2 in order to hold at least tx_queue_len
	 */
	tx_ring_size = roundup_pow_of_two(dev->tx_queue_len + 1);
	tx_item_size = roundup_pow_of_two(sizeof(struct ipoib_txreq));

	priv->txqs = kcalloc_node(dev->num_tx_queues,
				  sizeof(struct hfi2_ipoib_txq),
				  GFP_KERNEL,
				  priv->dd->node);
	if (!priv->txqs)
		return -ENOMEM;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];

		tx_ring = &txq->tx_ring;
		hfi2_iowait_init(&txq->wait,
			    0,
			    hfi2_ipoib_flush_txq,
			    NULL,
			    NULL,
			    hfi2_ipoib_sdma_sleep,
			    hfi2_ipoib_sdma_wakeup,
			    NULL,
			    NULL);
		txq->priv = priv;
		txq->sde = NULL;
		INIT_LIST_HEAD(&txq->tx_list);
		spin_lock_init(&txq->stop_lock);
		atomic_set(&txq->tx_ring.stops, 0);
		atomic_set(&txq->tx_ring.ring_full, 0);
		atomic_set(&txq->tx_ring.no_desc, 0);
		txq->q_idx = i;
		txq->flow.tx_queue = 0xff;
		txq->flow.sc5 = 0xff;
		txq->pkts_sent = false;
		txq->hfisvc_run_head = NULL;
		txq->hfisvc_run_len = 0;
		txq->napi_node = NUMA_NO_NODE;
		txq->napi_moved = jiffies - HZ;
		INIT_WORK(&txq->napi_work, hfi2_ipoib_napi_rebind);

		netdev_queue_numa_node_write(netdev_get_tx_queue(dev, i),
					     priv->dd->node);

		txq->tx_ring.items =
			kvzalloc_node(array_size(tx_ring_size, tx_item_size),
				      GFP_KERNEL, priv->dd->node);
		if (!txq->tx_ring.items)
			goto free_txqs;

		txq->tx_ring.max_items = tx_ring_size;
		txq->tx_ring.shift = ilog2(tx_item_size);
		txq->tx_ring.avail = hfi2_ipoib_ring_hwat(txq);
		tx_ring = &txq->tx_ring;
		for (j = 0; j < tx_ring_size; j++) {
			hfi2_txreq_from_idx(tx_ring, j)->sdma_hdr =
				kzalloc_node(HFI2_IPOIB_TXHDR_SIZE,
					     GFP_KERNEL, priv->dd->node);
			if (!hfi2_txreq_from_idx(tx_ring, j)->sdma_hdr) {
				while (j--)
					kfree(hfi2_txreq_from_idx(tx_ring, j)->sdma_hdr);
				kvfree(tx_ring->items);
				tx_ring->items = NULL;
				goto free_txqs;
			}
		}

		netif_napi_add_tx(dev, &txq->napi, hfi2_ipoib_poll_tx_ring);
	}

	if (hfi2_ipoib_flowtab_init(priv))
		goto free_txqs;

	return 0;

free_txqs:
	for (i--; i >= 0; i--) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];

		netif_napi_del(&txq->napi);
		tx_ring = &txq->tx_ring;
		for (j = 0; j < tx_ring_size; j++)
			kfree(hfi2_txreq_from_idx(tx_ring, j)->sdma_hdr);
		kvfree(tx_ring->items);
	}

	hfi2_ipoib_flowtab_deinit(priv);
	kfree(priv->txqs);
	priv->txqs = NULL;
	return -ENOMEM;
}

/*
 * Teardown only, so the _xmit_lock is not needed: the caller has already
 * called hfi2_iowait_cancel_work() and iowait_sdma_drain(), and the netdev is
 * either not yet registered or unregistering, so no other accessor of
 * tx_list can still run.  A caller from any other path must hold the
 * _xmit_lock instead.
 */
static void hfi2_ipoib_drain_tx_list(struct hfi2_ipoib_txq *txq)
{
	struct sdma_txreq *txreq;
	struct sdma_txreq *txreq_tmp;

	list_for_each_entry_safe(txreq, txreq_tmp, &txq->tx_list, list) {
		struct ipoib_txreq *tx =
			container_of(txreq, struct ipoib_txreq, txreq);

		list_del(&txreq->list);
		sdma_txclean(txq->priv->dd, &tx->txreq);
		dev_kfree_skb_any(tx->skb);
		tx->skb = NULL;
		txq->tx_ring.complete_txreqs++;
	}

	if (hfi2_ipoib_used(txq))
		dd_dev_warn(txq->priv->dd,
			    "txq %d not empty found %u requests\n",
			    txq->q_idx,
			    hfi2_ipoib_txreqs(txq->tx_ring.sent_txreqs,
					      txq->tx_ring.complete_txreqs));
}

void hfi2_ipoib_txreq_deinit(struct hfi2_ipoib_dev_priv *priv)
{
	int i, j;

	for (i = 0; i < priv->netdev->num_tx_queues; i++) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];
		struct hfi2_ipoib_circ_buf *tx_ring = &txq->tx_ring;

		hfi2_iowait_cancel_work(&txq->wait);
		iowait_sdma_drain(&txq->wait);
		hfi2_ipoib_drain_tx_list(txq);
		cancel_work_sync(&txq->napi_work);
		netif_napi_del(&txq->napi);
		hfi2_ipoib_drain_tx_ring(txq);
		for (j = 0; j < tx_ring->max_items; j++)
			kfree(hfi2_txreq_from_idx(tx_ring, j)->sdma_hdr);
		kvfree(tx_ring->items);
	}

	hfi2_ipoib_flowtab_deinit(priv);
	kfree(priv->txqs);
	priv->txqs = NULL;
}

void hfi2_ipoib_napi_tx_enable(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];

		/*
		 * Reset stop-reason state that may have been latched before
		 * the preceding drain.  hfi2_ipoib_drain_tx_ring() zeroes
		 * the ring counters but intentionally does not touch stops,
		 * ring_full, no_desc, or the netdev XOFF bit.  If any of
		 * these were set when the drain ran, the subqueue remains
		 * permanently stopped after re-enable because no completion
		 * will ever arrive to clear them.
		 *
		 * It is safe to reset here: NAPI is still disabled (no
		 * concurrent poll), the ring was just drained (no in-flight
		 * entries), and no new TX submissions can occur until the
		 * queue is started.
		 */
		atomic_set(&txq->tx_ring.stops, 0);
		atomic_set(&txq->tx_ring.ring_full, 0);
		atomic_set(&txq->tx_ring.no_desc, 0);
		napi_enable(&txq->napi);
	}
}

void hfi2_ipoib_napi_tx_disable(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct hfi2_ipoib_txq *txq = &priv->txqs[i];

		napi_disable(&txq->napi);
		hfi2_ipoib_drain_tx_ring(txq);
	}
}

void hfi2_ipoib_tx_timeout(struct net_device *dev, unsigned int q)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	struct hfi2_ipoib_txq *txq = &priv->txqs[q];
	struct netdev_queue *ndq = netdev_get_tx_queue(dev, q);

	dd_dev_info(priv->dd, "timeout txq %p q %u stopped %u stops %d no_desc %d ring_full %d\n",
		    txq, q,
		    __netif_subqueue_stopped(dev, txq->q_idx),
		    atomic_read(&txq->tx_ring.stops),
		    atomic_read(&txq->tx_ring.no_desc),
		    atomic_read(&txq->tx_ring.ring_full));
	/* hfisvc has no ordinary engine or iowait, so sde and tx_list say
	 * nothing there; dump the state that does move.
	 */
	if (priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC)
		dd_dev_info(priv->dd, "hfisvc engine %u run_len %u napi_pending %u outstanding %d\n",
			    txq->q_idx % priv->hfisvc_num_engines,
			    txq->hfisvc_run_len, txq->hfisvc_napi_pending,
			    atomic_read(&priv->hfisvc_outstanding));
	else
		dd_dev_info(priv->dd, "sde %p engine %u tx_list empty %u sdma_pending %d\n",
			    txq->sde,
			    txq->sde ? txq->sde->this_idx : 0,
			    list_empty(&txq->tx_list),
			    iowait_sdma_pending(&txq->wait));
	dd_dev_info(priv->dd, "flow %x\n", txq->flow.as_int);
	dd_dev_info(priv->dd, "sent %llu completed %llu used %llu\n",
		    txq->tx_ring.sent_txreqs, txq->tx_ring.complete_txreqs,
		    hfi2_ipoib_used(txq));
	dd_dev_info(priv->dd, "tx_queue_len %u max_items %u\n",
		    dev->tx_queue_len, txq->tx_ring.max_items);
	dd_dev_info(priv->dd, "head %u tail %u\n",
		    txq->tx_ring.head, txq->tx_ring.tail);
	dd_dev_info(priv->dd, "wait queued %u\n",
		    !list_empty(&txq->wait.list));

	/* bulksvc completes every txreq it owns; forcing one frees live DMA. */
	if (priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC) {
		napi_schedule(&txq->napi);
		return;
	}

	/*
	 * Recover stranded tx_list entries.
	 *
	 * When check_queue_depth() stops the queue while xmit_more is
	 * true, entries on tx_list are never flushed to SDMA.  No further
	 * xmit calls arrive (queue is stopped), so they strand forever.
	 * Flush them here so SDMA can complete them normally.
	 *
	 * If tx_list is already empty, the entries belong to the engine,
	 * which completes them and drops sdma_busy itself; completing them
	 * here too would underflow sdma_busy and hang iowait_sdma_drain().
	 * Restart the engine if it has stalled; the halt aborts its queue.
	 *
	 * netif_freeze_queues() excludes the sender with __QUEUE_STATE_FROZEN,
	 * not by holding _xmit_lock, and the work item does not test that bit.
	 * Take the lock explicitly, plain variant since this already runs in
	 * the timer softirq.
	 */
	__netif_tx_lock(ndq, smp_processor_id());

	if (!list_empty(&txq->tx_list)) {
		(void)hfi2_ipoib_flush_tx_list(dev, txq);
		napi_schedule(&txq->napi);
	} else if (txq->sde && sdma_engine_progress_check(txq->sde)) {
		dd_dev_warn(priv->dd, "txq %u: SDMA engine %u stalled, restarting\n",
			    q, txq->sde->this_idx);
	}

	__netif_tx_unlock(ndq);
}

