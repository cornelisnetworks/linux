// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Send and receive queue handling
 */

#include <linux/cpu.h>

#include "eth_main.h"

/*
 * CYR SDMA completions are interrupt-coalesced (SDMA_DESC_INTR descriptors or
 * the SDmaIdle backstop), so BQL's dynamic limit auto-tunes down to ~2 jumbo
 * frames for a single flow and then stalls waiting for the coalesced
 * completion + wake round-trip, capping single-thread TX far below line rate.
 * Floor each TX queue's dql min_limit so a single flow always keeps enough
 * bytes in flight to cover the coalescing window; dql still throttles above
 * this floor under multi-flow load (which is what killed the earlier collapse).
 * Tunable in bytes; 0 restores stock BQL behaviour.
 */
static uint cne_tx_bql_min_limit = 1048576;

#define CNE_TX_DRAIN_TIMEOUT	msecs_to_jiffies(1000)

/**
 * cne_sdma_sleep - put SDMA engine to sleep when not enough TX descriptors
 * @sde: SDMA engine
 * @wait: waiter
 * @txreq: TX request
 * @seq: sequence number?
 * @pkts_sent: were packets sent
 *
 * Returns -EAGAIN or -EBUSY
 */
static int cne_sdma_sleep(struct sdma_engine *sde,
			  struct iowait_work *wait,
			  struct sdma_txreq *txreq,
			  uint seq,
			  bool pkts_sent)
{
	struct cn_txq *txq =
		container_of(wait->iow, struct cn_txq, wait);

	pdbg(txq->edev, tx_queued, "SDMA sleep q_id %u sc_id %u\n", txq->q_id, txq->sc_id);

	write_seqlock(&sde->waitlock);
	if (sdma_progress(sde, seq, txreq)) {
		write_sequnlock(&sde->waitlock);
		return -EAGAIN;
	}

	if (list_empty(&txq->wait.list)) {
		iowait_get_priority(wait->iow);
		iowait_queue(pkts_sent, wait->iow, &sde->dmawait);
	}
	write_sequnlock(&sde->waitlock);

	return -EBUSY;
}

/**
 * cne_sdma_wakeup - wake a TX queue waiting for SDMA descriptors
 * @wait: waiter
 * @reason: wakeup reason (SDMA_AVAIL_REASON)
 */
static void cne_sdma_wakeup(struct iowait *wait,
			    int reason)
{
	struct cn_txq *txq =
		container_of(wait, struct cn_txq, wait);
	struct ether_device *edev = READ_ONCE(txq->edev);

	/* Queue already detached by cne_free_txq(). */
	if (!edev)
		return;

	pdbg(edev, tx_queued, "SDMA wakeup q_id %u sc_id %u reason %d\n", txq->q_id,
	     txq->sc_id, reason);

	if (READ_ONCE(edev->tx_enabled) &&
	    __netif_subqueue_stopped(edev->ndev, txq->q_id))
		netif_wake_subqueue(edev->ndev, txq->q_id);
}

/**
 * cne_napi - NAPI poll function
 * @napi: NAPI object
 * @budget: poll budget
 *
 * Processes the queue's receive context only.  TX completions do not go
 * through NAPI: cne_sdma_complete() handles them from the SDMA interrupt.
 *
 * Return: the number of receive queue entries processed, at most @budget.
 */
static int cne_napi(struct napi_struct *napi,
		    int budget)
{
	struct cn_rxq *rxq = container_of(napi, struct cn_rxq, napi);
	struct hfi2_ctxtdata *rcd = rxq->rcd;
	int work_done;

	/*
	 * Netpoll may poll from IRQ context for TX only; there is no work to do
	 * here. This also avoids taking the poll_lock so that it can be shared
	 * with ethtool.
	 */
	if (unlikely(!budget))
		return 0;

	/*
	 * napi_complete_done() lets the next poll start on another CPU
	 * before cne_rcd_eoi_intr() rewrites RcvHdrHead.  Hold the lock
	 * across the whole poll so that poll cannot move the head first.
	 */
	spin_lock(&rxq->poll_lock);
	work_done = rcd->do_interrupt(rcd, budget);

	cne_rx_freelist_refill(rcd);

	/*
	 * Re-arm only if NAPI really completed.  A false return means the
	 * core still owns the poll (napi_defer_hard_irqs/gro_flush_timeout
	 * timer, busy polling, or a missed schedule) and will poll again; the
	 * RcvAvail interrupt stays latched until the poll that does complete.
	 */
	if (work_done < budget && napi_complete_done(napi, work_done))
		cne_rcd_eoi_intr(rcd);
	spin_unlock(&rxq->poll_lock);

	return work_done;
}

/**
 * cne_setup_rx_ctxt - configure the specified RX context
 * @ppd: hfi port data
 * @ctxt: context to configure
 * @entries: requested eager ring size
 *
 * Returns 0 on success, -ERRNO otherwise.
 */
static int cne_setup_rx_ctxt(struct hfi2_pportdata *ppd,
			     struct hfi2_ctxtdata *ctxt, u32 entries)
{
	int rc;
	struct hfi2_devdata *dd = ppd->dd;
	unsigned int rcvctrl_ops;

	ctxt->rhf_rcv_function_map = hfi2_netdev_rhf_rcv_functions;
	ctxt->do_interrupt = &hfi2_handle_receive_interrupt_napi_sp;

	/* Match the RcvHdr queue depth to the eager ring before allocating it. */
	cne_size_netdev_rcvhdrq(ctxt, entries);

	rc = hfi2_create_rcvhdrq(dd, ctxt);
	if (rc)
		goto done;

	rc = cne_setup_eager_skbs(ctxt, entries);
	if (rc)
		goto done;

	clear_rcvhdrtail(ctxt);
	rcvctrl_ops = HFI2_RCVCTRL_CTXT_DIS | HFI2_RCVCTRL_INTRAVAIL_DIS;

	if (!HFI2_CAP_KGET_MASK(ctxt->flags, MULTI_PKT_EGR))
		rcvctrl_ops |= HFI2_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI2_CAP_KGET_MASK(ctxt->flags, NODROP_EGR_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI2_CAP_KGET_MASK(ctxt->flags, NODROP_RHQ_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_RHQ_DROP_ENB;
	if (HFI2_CAP_KGET_MASK(ctxt->flags, DMA_RTAIL))
		rcvctrl_ops |= HFI2_RCVCTRL_TAILUPD_ENB;

	hfi2_rcvctrl(dd, rcvctrl_ops, ctxt);
done:
	return rc;
}

/**
 * cne_alloc_rx_ctxt - allocate RX context
 * @ppd: hfi port data
 * @ctxt: allocated context pointer
 *
 * Returns 0 on success, -ERRNO otherwise.
 */
static int cne_alloc_rx_ctxt(struct hfi2_pportdata *ppd,
			     struct hfi2_ctxtdata **ctxt)
{
	int rc;
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_ctxtdata *_ctxt;

	if (dd->flags & HFI2_FROZEN)
		return -EIO;

	rc = hfi2_create_ctxtdata(ppd, dd->node, DYNAMIC_CONTEXT, &_ctxt);
	if (rc < 0)
		return rc;

	/*
	 * The CYR zero-copy RX ring posts one packet per eager buffer, so it
	 * must not advertise MULTI_PKT_EGR; cne_setup_eager_skbs() WARNs if it
	 * is set.
	 */
	_ctxt->flags = HFI2_CAP_KGET(DMA_RTAIL);
	_ctxt->fast_handler = hfi2_handle_receive_interrupt_napi_fp;
	_ctxt->slow_handler = hfi2_handle_receive_interrupt_napi_sp;
	hfi2_set_seq_cnt(_ctxt, 1);
	_ctxt->is_eth = true;

	hfi2_stats.sps_ctxts++;

	*ctxt = _ctxt;

	return 0;
}

/**
 * cne_dealloc_rx_ctxt - free specified RX context
 * @ppd: hfi port data
 * @ctxt: context to free
 */
static void cne_dealloc_rx_ctxt(struct hfi2_pportdata *ppd,
				struct hfi2_ctxtdata *ctxt)
{
	unsigned int rcvmask = HFI2_RCVCTRL_CTXT_DIS | HFI2_RCVCTRL_TIDFLOW_DIS |
			HFI2_RCVCTRL_INTRAVAIL_DIS | HFI2_RCVCTRL_ONE_PKT_EGR_DIS |
			HFI2_RCVCTRL_NO_RHQ_DROP_DIS | HFI2_RCVCTRL_NO_EGR_DROP_DIS;
	struct hfi2_devdata *dd = ppd->dd;

	flush_wc();

	hfi2_rcvctrl(dd, rcvmask, ctxt);

	if (ctxt->msix_intr != CCE_NUM_MSIX_VECTORS)
		hfi2_msix_free_irq(dd, ctxt->msix_intr);

	ctxt->msix_intr = CCE_NUM_MSIX_VECTORS;
	ctxt->event_flags = 0;
	hfi2_clear_tids(ctxt);
	cne_free_eager_skbs(ctxt);
	hfi2_clear_ctxt_pkey(dd, ctxt->sc);

	hfi2_stats.sps_ctxts--;
	hfi2_free_ctxt(ctxt);
}

/**
 * cne_free_rcvhdrq - free an RX context's RcvHdr and RHE queues
 * @rcd: RX context; it must be disabled
 *
 * Free the RcvHdr queue, its tail page and the RHE queue at the current
 * rcvhdrq_cnt, so that hfi2_create_rcvhdrq() allocates them again.
 */
static void cne_free_rcvhdrq(struct hfi2_ctxtdata *rcd)
{
	struct device *dev = &rcd->dd->pcidev->dev;

	if (rcd->rcvhdrq) {
		dma_free_coherent(dev, rcvhdrq_size(rcd), rcd->rcvhdrq,
				  rcd->rcvhdrq_dma);
		rcd->rcvhdrq = NULL;
	}
	if (hfi2_rcvhdrtail_kvaddr(rcd)) {
		dma_free_coherent(dev, PAGE_SIZE,
				  (void *)hfi2_rcvhdrtail_kvaddr(rcd),
				  rcd->rcvhdrqtailaddr_dma);
		rcd->rcvhdrtail_kvaddr = NULL;
	}
	if (rcd->rheq) {
		dma_free_coherent(dev, rheq_size(rcd), rcd->rheq, rcd->rheq_dma);
		rcd->rheq = NULL;
	}
}

/**
 * cne_rebuild_rx_ring - give a disabled RX queue a ring of a new size
 * @rxq: RX queue; its context and NAPI must be disabled
 * @entries: requested eager ring size
 *
 * The context, its MSI-X vector and NAPI instance are kept.  On failure the
 * queue has no ring (ring_entries is 0) until cne_enable_rxq() builds one.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_rebuild_rx_ring(struct cn_rxq *rxq, u32 entries)
{
	struct hfi2_ctxtdata *rcd = rxq->rcd;
	int rc;

	hfi2_clear_tids(rcd);
	cne_free_eager_skbs(rcd);
	cne_free_rcvhdrq(rcd);
	rxq->ring_entries = 0;

	rc = cne_setup_rx_ctxt(rxq->edev->ppd, rcd, entries);
	if (!rc)
		rxq->ring_entries = entries;

	return rc;
}

/**
 * cne_size_rxqs - set the ring size of the device's RX queues
 * @edev: Ethernet device, stopped
 * @num_qs: number of existing queues to resize, at most edev->num_rxqs
 * @entries: requested eager ring size
 *
 * Rebuilds the ring of each of the first @num_qs queues that was built for
 * a different size or has none, and records @entries for queues allocated
 * later.  On failure those queues are rebuilt at the previous size.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_size_rxqs(struct ether_device *edev, int num_qs, u32 entries)
{
	u32 old = edev->rx_ring_entries;
	int i;
	int rc;

	for (i = 0; i < num_qs; i++) {
		if (edev->rxq[i]->ring_entries == entries)
			continue;
		rc = cne_rebuild_rx_ring(edev->rxq[i], entries);
		if (rc)
			goto rollback;
	}
	edev->rx_ring_entries = entries;

	return 0;

rollback:
	for (; i >= 0; i--)
		if (edev->rxq[i]->ring_entries != old)
			cne_rebuild_rx_ring(edev->rxq[i], old);

	return rc;
}

/**
 * cne_alloc_rxqs - size the RX rings for, and grow to, a number of queues
 * @edev: Ethernet device, stopped
 * @num_qs: total number of queues wanted
 *
 * The ring size is chosen for @num_qs queues by cne_rx_ring_default(), so a
 * budgeted size follows the queue count while cne_rx_ring_entries, if set,
 * is used as is.  Queues below @num_qs are kept and their rings rebuilt if
 * the size changes; queues edev->num_rxqs to @num_qs - 1 are allocated.
 * Queues at and above @num_qs are left to cne_trim_rxqs().  On failure the
 * queues added here are freed and the kept queues get their previous size
 * back.
 *
 * Returns 0 on success, -ERRNO otherwise.
 */
int cne_alloc_rxqs(struct ether_device *edev,
		   int num_qs)
{
	u32 old_entries = edev->rx_ring_entries;
	int first = edev->num_rxqs;
	int i;
	int rc;

	if (num_qs > ARRAY_SIZE(edev->rxq))
		num_qs = ARRAY_SIZE(edev->rxq);

	rc = cne_size_rxqs(edev, min(first, num_qs),
			   cne_rx_ring_default(edev->ppd->dd, num_qs));
	if (rc)
		return rc;

	for (i = first; i < num_qs; i++) {
		rc = cne_alloc_rxq(edev, i, &edev->rxq[i]);
		if (rc)
			goto rollback;
	}
	if (i > first)
		edev->num_rxqs = i;

	return 0;

rollback:
	while (i-- > first)
		cne_free_rxq(edev->rxq[i]);
	cne_size_rxqs(edev, first, old_entries);

	return rc;
}

/**
 * cne_alloc_rxq - allocate RX queue
 * @edev: Ethernet device
 * @idx: index
 * @_rxq: allocated RX queue
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_alloc_rxq(struct ether_device *edev,
		  u32 idx,
		  struct cn_rxq **_rxq)
{
	int rc = 0;
	struct cn_rxq *rxq;
	struct hfi2_pportdata *ppd = edev->ppd;

	rxq = kzalloc(sizeof(*rxq), GFP_KERNEL);
	if (!rxq)
		return -ENOMEM;

	rxq->edev = edev;
	rxq->q_id = idx;

	/* Allocate Ethernet receive context. */
	rc = cne_alloc_rx_ctxt(ppd, &rxq->rcd);
	if (rc)
		goto free_rxq;
	hfi2_rcd_get(rxq->rcd);

	/*
	 * Register NAPI before the eager ring is built so its page_pool is
	 * created with this NAPI for direct recycling.  NAPI stays disabled
	 * until cne_enable_rxq().
	 */
	rxq->rcd->napi = &rxq->napi;
	spin_lock_init(&rxq->poll_lock);
	set_bit(NAPI_STATE_NO_BUSY_POLL, &rxq->napi.state);
	netif_napi_add(edev->ndev, &rxq->napi, cne_napi);

	rc = cne_setup_rx_ctxt(ppd, rxq->rcd, edev->rx_ring_entries);
	if (rc)
		goto dealloc_ctxt;
	rxq->ring_entries = edev->rx_ring_entries;

	rc = msix_eth_request_rcd_irq(rxq->rcd);
	if (rc)
		goto dealloc_ctxt;

	/*
	 * Stash the 0-based netdev RX queue index on the context so the bypass
	 * receive path can tag each skb via skb_record_rx_queue().  This gives
	 * every RX context its own /sys/class/net/<dev>/queues/rx-N dir for
	 * per-context RPS/RFS steering instead of funneling all traffic through
	 * rx-0.
	 */
	rxq->rcd->vnic_q_idx = idx;
	rxq->rc_id = rxq->rcd->ctxt;
	rxq->stats = &edev->rxq_stats[idx];
	rxq->rcd->cne_rxq = rxq;
	pdbg(edev, drv, "rxq %u using receive context %u\n", idx, rxq->rc_id);
	*_rxq = rxq;

	return 0;

dealloc_ctxt:
	/* Destroys the page_pool, so it must precede netif_napi_del(). */
	cne_dealloc_rx_ctxt(ppd, rxq->rcd);
	rxq->rcd->napi = NULL;
	netif_napi_del(&rxq->napi);
	hfi2_rcd_put(rxq->rcd);
	rxq->rcd = NULL;

free_rxq:
	kfree(rxq);

	return rc;
}

/**
 * cne_txq_cache_release - Called when cache refcount reaches zero
 * @kref: Pointer to txreq_cache_refcount in cn_txq
 *
 * This is invoked when:
 * 1. cne_free_txq() has been called (initial reference dropped)
 * 2. All cn_txreq objects have been freed (all object references dropped)
 *
 * At this point it's safe to destroy the kmem_cache.
 */
static void cne_txq_cache_release(struct kref *kref)
{
	struct cn_txq *txq = container_of(kref, struct cn_txq, txreq_cache_refcount);

	if (txq->txreq_cache) {
		dma_pool_destroy(txq->hdr_pool);
		kmem_cache_destroy(txq->txreq_cache);
		txq->txreq_cache = NULL;
		kfree(txq);
	}
}

/**
 * cne_txq_cache_get - Increment cache reference count
 * @txq: The transmit queue
 */
void cne_txq_cache_get(struct cn_txq *txq)
{
	kref_get(&txq->txreq_cache_refcount);
}

/**
 * cne_txq_cache_put - Decrement cache reference count
 * @txq: The transmit queue
 *
 * Called when freeing a cn_txreq. If this is the last reference
 * and cne_free_txq() has been called, the cache is destroyed.
 */
void cne_txq_cache_put(struct cn_txq *txq)
{
	kref_put(&txq->txreq_cache_refcount, cne_txq_cache_release);
}

/**
 * cne_alloc_txqs - grow the device to the specified number of TX queues
 * @edev: Ethernet device
 * @num_qs: total number of queues wanted
 *
 * Allocates queues edev->num_txqs to @num_qs - 1.  Existing queues are
 * kept, and nothing is done if @num_qs is not larger.  On failure only the
 * queues added here are freed.
 *
 * Returns 0 on success, -ERRNO otherwise
 */
int cne_alloc_txqs(struct ether_device *edev,
		   int num_qs)
{
	int first = edev->num_txqs;
	int i;
	int rc = 0;

	if (num_qs > ARRAY_SIZE(edev->txq))
		num_qs = ARRAY_SIZE(edev->txq);

	for (i = first; i < num_qs; i++) {
		rc = cne_alloc_txq(edev, i, &edev->txq[i]);
		if (rc)
			goto rollback;
	}
	if (i > first)
		edev->num_txqs = i;

	return 0;

rollback:
	while (i-- > first)
		cne_free_txq(edev->txq[i]);

	return rc;
}

/**
 * cne_alloc_txq - allocate TX queue
 * @edev: Ethernet device
 * @idx: index used to select TX queue, SDMA engine, etc.
 * @_txq: allocated TX queue
 *
 * Returns 0 on success, error code otherwise
 */
int cne_alloc_txq(struct ether_device *edev,
		  u32 idx,
		  struct cn_txq **_txq)
{
	int rc = 0;
	struct cn_txq *txq;
	struct hfi2_pportdata *ppd = edev->ppd;
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;
	char cache_name[64];

	txq = kzalloc(sizeof(*txq), GFP_KERNEL);
	if (!txq)
		return -ENOMEM;

	txq->edev = edev;
	txq->q_id = idx;
	txq->stats = &edev->txq_stats[idx];

	/* Assign SDMA engine. */
	txq->sde = &dd->per_sdma[cne_txq_sde_idx(edev, idx)];

	/* Allocate a send context */
	txq->sc = hfi2_sc_alloc(ppd, SC_USER, kctxt_hdrqentsize(ppd), dd->node);
	if (!txq->sc) {
		netdev_err(edev->ndev, "send context for queue %u unavailable.\n", idx);
		rc = -ENOMEM;
		goto free_txq;
	}
	hfi2_init_ctxt(txq->sc);
	txq->sc_id = txq->sc->hw_context;

	kref_init(&txq->txreq_cache_refcount);

	/* Allocate TX request cache. */
	snprintf(cache_name, sizeof(cache_name) - 1, "txreq_cache_%u:%u", pdr->pfunit, idx);
	txq->txreq_cache = kmem_cache_create(cache_name, sizeof(struct cn_txreq),
					     0, SLAB_HWCACHE_ALIGN, NULL);
	if (!txq->txreq_cache) {
		netdev_err(edev->ndev, "Failure allocating TX request cache.\n");
		rc = -ENOMEM;
		goto free_sc;
	}

	snprintf(cache_name, sizeof(cache_name) - 1, "cne_txhdr_%u:%u", pdr->pfunit, idx);
	txq->hdr_pool = dma_pool_create(cache_name, &dd->pcidev->dev,
					CNE_TX_HDR_SLOT, CNE_TX_HDR_SLOT, 0);
	if (!txq->hdr_pool) {
		netdev_err(edev->ndev, "Failure allocating TX header pool.\n");
		rc = -ENOMEM;
		goto free_cache;
	}

	hfi2_iowait_init(&txq->wait, 0, NULL, NULL, NULL, cne_sdma_sleep, cne_sdma_wakeup, NULL, NULL);
	atomic_inc(&txq->sde->dmahead_users);

	pdbg(edev, drv, "txq %u using send context %u\n", idx, txq->sc_id);
	*_txq = txq;

	return 0;

free_cache:
	kmem_cache_destroy(txq->txreq_cache);
free_sc:
	hfi2_sc_free(txq->sc);
free_txq:
	kfree(txq);

	return rc;
}

/**
 * cne_disable_rxq - disable interrupts on the specified queue
 * @rxq: queue to disable
 */
void cne_disable_rxq(struct cn_rxq *rxq)
{
	struct hfi2_devdata *dd = rxq->edev->ppd->dd;
	struct hfi2_ctxtdata *rcd = rxq->rcd;

	hfi2_rcvctrl(dd, HFI2_RCVCTRL_CTXT_DIS | HFI2_RCVCTRL_INTRAVAIL_DIS, rcd);

	if (rcd->msix_intr != CCE_NUM_MSIX_VECTORS)
		synchronize_irq(dd->msix_info.msix_entries[rcd->msix_intr].irq);

	napi_synchronize(&rxq->napi);
	napi_disable(&rxq->napi);
}

/**
 * cne_disable_rxqs - disable all RX queues
 * @edev: device to have RX queues disabled
 */
void cne_disable_rxqs(struct ether_device *edev)
{
	if (!edev->rx_enabled)
		return;
	edev->rx_enabled = false;

	hfi2_deinit_eth_rsm(edev->ppd);

	for (int i = 0; i < edev->num_rxqs; i++)
		cne_disable_rxq(edev->rxq[i]);
}

/**
 * cne_disable_txq
 * @txq:
 */
void cne_disable_txq(struct cn_txq *txq)
{
	hfi2_sc_disable(txq->sc);
}

/**
 * cne_disable_txqs
 * @edev: Ethernet device
 */
void cne_disable_txqs(struct ether_device *edev)
{
	int i;

	for (i = 0; i < edev->num_txqs; i++)
		cne_disable_txq(edev->txq[i]);
}

/**
 * cne_enable_rxq - configure and enable the specified RX queue to receive packets.
 * @rxq: the queue to enable
 *
 * The RSM rule that steers Ethernet frames across the receive contexts is
 * installed once per port by hfi2_init_eth_rsm(); see cne_enable_rxqs().
 *
 * A queue left without a ring by a failed resize gets one of
 * edev->rx_ring_entries here, so each open retries the allocation.
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_enable_rxq(struct cn_rxq *rxq)
{
	struct hfi2_pportdata *ppd = rxq->edev->ppd;
	int rc;

	if (!rxq->ring_entries) {
		rc = cne_rebuild_rx_ring(rxq, rxq->edev->rx_ring_entries);
		if (rc)
			return rc;
	}

	napi_enable(&rxq->napi);
	/* HFI2_RCVCTRL_TAILUPD_* needs to be set explicitly */
	hfi2_rcvctrl(ppd->dd, HFI2_RCVCTRL_CTXT_ENB | HFI2_RCVCTRL_INTRAVAIL_ENB |
		     (hfi2_rcvhdrtail_kvaddr(rxq->rcd) ?
		      HFI2_RCVCTRL_TAILUPD_ENB : HFI2_RCVCTRL_TAILUPD_DIS),
		     rxq->rcd);

	return 0;
}

/**
 * cne_rss_build_map - expand the RSS table into receive context numbers
 * @edev: device whose table to expand
 * @map: HFI2_ETH_MAP_ENTRIES-sized output, one hardware context per entry
 *
 * Uses the ethtool -X table when one is set, else round-robin over the
 * active RX queues.  Entries that no longer name an active queue fall back
 * to round-robin.
 */
void cne_rss_build_map(struct ether_device *edev, u16 *map)
{
	u32 n = edev->num_rxqs;
	u32 i, q;

	for (i = 0; i < HFI2_ETH_MAP_ENTRIES; i++) {
		if (edev->rss_indir_valid && edev->rss_indir[i] < n)
			q = edev->rss_indir[i];
		else
			q = ethtool_rxfh_indir_default(i, n);
		map[i] = edev->rxq[q]->rcd->ctxt;
	}
}

/**
 * cne_enable_rxqs - enable all RX queues
 * @edev: device on which to enable queues
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_enable_rxqs(struct ether_device *edev)
{
	int i;
	int rc;
	u16 map[HFI2_ETH_MAP_ENTRIES];

	BUILD_BUG_ON(CN_MAX_QUEUES < HFI2_ETH_MAX_CTXTS);
	BUILD_BUG_ON(HFI2_ETH_MAX_CTXTS > HFI2_ETH_MAP_ENTRIES);
	BUILD_BUG_ON(HFI2_ETH_MAP_ENTRIES & (HFI2_ETH_MAP_ENTRIES - 1));
	BUILD_BUG_ON(ilog2(HFI2_ETH_MAP_ENTRIES) > 8);

	if (WARN_ON(edev->num_rxqs > min(CN_MAX_QUEUES, HFI2_ETH_MAP_ENTRIES)))
		return -EINVAL;

	if (edev->rx_enabled)
		return 0;

	/* cne_rss_build_map() spreads over num_rxqs and needs at least one. */
	if (!edev->num_rxqs)
		return -EINVAL;

	for (i = 0; i < edev->num_rxqs; i++) {
		rc = cne_enable_rxq(edev->rxq[i]);
		if (rc) /* Roll back the queues already enabled */
			goto rollback;
	}

	cne_rss_build_map(edev, map);

	/*
	 * Install the RSM rules.  They hash the L4 source and destination
	 * ports into the RMT block, which maps each entry to a receive
	 * context per the RSS table built above.
	 */
	rc = hfi2_init_eth_rsm(edev->ppd, map, HFI2_ETH_MAP_ENTRIES);
	if (rc)
		goto rollback;

	edev->rx_enabled = true;

	return 0;

rollback:
	while (i--)
		cne_disable_rxq(edev->rxq[i]);

	return rc;
}

/**
 * cne_set_xps_rxqs - steer a TX queue by the socket's recorded RX queue
 * @txq: TX queue whose XPS_RXQS map entry is published
 *
 * The per-CPU XPS map alone does not keep a flow on one TX queue.  Transmits
 * issued from a CPU outside that map (e.g. ACK-clocked sends from NAPI
 * softirq on the RX CPU) fall back to the flow hash, and the stack moves a
 * flow to the newly picked queue whenever skb->ooo_okay is set, i.e. once
 * all of its earlier skbs have been freed.  Here skbs are freed on SDMA
 * completion, which can precede egress, so under link backpressure (PAUSE)
 * a packet on the new queue's engine can overtake one still queued behind
 * the old engine.  TCP sees reordering and sends spurious fast retransmits.
 *
 * The kernel consults the XPS_RXQS map before the CPU map, keyed by the RX
 * queue recorded in the socket (sk_rx_queue_get()).  That value is the same
 * for every context transmitting on a connected TCP flow, and a match ends
 * the lookup, so the TX queues are split among the nrx RX queues: TX queue
 * t serves RX queues t % nrx, t % nrx + num_txqs, ...  With at least as
 * many TX as RX queues, RX queue r owns the disjoint set r, r + nrx, ...
 * and the stack picks one of them by the socket's flow hash; with fewer,
 * each RX queue maps to one TX queue.  Every TX queue carries flows, and
 * the choice does not depend on the sending CPU.  The RSM port hash is
 * symmetric (sport ^ dport), so both directions of a flow use the same RX
 * queue index.  Flows without a recorded RX queue (UDP, unconnected
 * sockets, first packets of a connection) still use the CPU map below.
 *
 * Failure is not fatal: the queue still works, only steering is weaker.
 */
static void cne_set_xps_rxqs(struct cn_txq *txq)
{
	struct ether_device *edev = txq->edev;
	struct net_device *ndev = edev->ndev;
	unsigned int nrx = min_t(unsigned int, edev->num_rxqs, ndev->num_rx_queues);
	unsigned long *mask;
	unsigned int r;
	int rc;

	/* __netif_set_xps_queue() reads num_rx_queues bits for XPS_RXQS */
	mask = bitmap_zalloc(ndev->num_rx_queues, GFP_KERNEL);
	if (!mask) {
		netdev_warn(ndev, "txq %u: no memory for XPS rxqs map\n", txq->q_id);
		return;
	}

	for (r = nrx ? txq->q_id % nrx : 0; r < nrx; r += edev->num_txqs)
		__set_bit(r, mask);

	/* Same locking as the xps_rxqs sysfs store; RTNL is held by cne_open() */
	cpus_read_lock();
	rc = __netif_set_xps_queue(ndev, mask, txq->q_id, XPS_RXQS);
	cpus_read_unlock();
	if (rc)
		netdev_warn(ndev, "txq %u: XPS rxqs map failed (%d)\n", txq->q_id, rc);

	bitmap_free(mask);
}

/**
 * cne_enable_txq - enable the specified TX queue
 * @txq: queue to enable
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_enable_txq(struct cn_txq *txq)
{
	int rc;
	struct ether_device *edev = txq->edev;
	struct hfi2_pportdata *ppd = edev->ppd;
	struct hfi2_devdata *dd = ppd->dd;
	unsigned long flags;
	u64 val;

	rc = hfi2_sc_enable(txq->sc);
	if (rc) {
		netdev_err(edev->ndev, "sc_enable failed (%d)\n", rc);
		return rc;
	}

	val = read_epsc_csr(dd, ppd->hw_pidx, txq->sc_id, dd->params->send_ctxt_check_enable_reg);
	val |= CYR_SEND_CTXT_CHECK_ENABLE_L2_TYPE16BALLOWED_SMASK;
	val &= ~CYR_SEND_CTXT_CHECK_ENABLE_CHECK16BVL_MAPPING_SMASK;
	write_epsc_csr(dd, ppd->hw_pidx, txq->sc_id, dd->params->send_ctxt_check_enable_reg, val);

	val = read_epsc_csr(dd, ppd->hw_pidx, txq->sc_id, CYR_SEND_CTXT_CHECK_L4_0X40_0X7F);
	val |= 1ULL << (0x78 - 0x40);
	write_epsc_csr(dd, ppd->hw_pidx, txq->sc_id, CYR_SEND_CTXT_CHECK_L4_0X40_0X7F, val);

	/*
	 * Requests from before the last stop can still complete (the drain in
	 * cne_stop() is bounded).  Start a new BQL epoch together with the
	 * reset, under the lock completions run under, so cne_sdma_complete()
	 * does not release them against the fresh DQL.
	 */
	write_seqlock_irqsave(&txq->sde->head_lock, flags);
	txq->bql_gen++;
	netdev_tx_reset_queue(netdev_get_tx_queue(edev->ndev, txq->q_id));
	write_sequnlock_irqrestore(&txq->sde->head_lock, flags);
	netdev_queue_set_dql_min_limit(netdev_get_tx_queue(edev->ndev, txq->q_id),
				       cne_tx_bql_min_limit);

	/*
	 * Precompute the PBC bits that are constant for this queue (send
	 * context, DLID, port, L2 type, flags) so cne_start_xmit() only OR's in
	 * the per-packet length and VL instead of rebuilding the whole PBC.
	 * VL and length fields are left zero here and supplied per packet.
	 */
	txq->pbc_template = dd->params->create_pbc(ppd, false, PBC_CREDIT_RETURN, 0, 0, 0,
						   L2TYPE, DLID_23_20 << 20, txq->sc_id);
	txq->pbc_template &= ~PBC_INSERT_BYPASS_ICRC; /* disable ICRC insertion */

	/*
	 * Publish XPS maps.  The RX-queue map keeps a connected flow on one TX
	 * queue (see cne_set_xps_rxqs()).  The CPU map pins this TX queue to the
	 * CPU that services its SDMA engine's completion IRQ and is used for
	 * traffic that has no recorded RX queue.
	 */
	cne_set_xps_rxqs(txq);
	if (txq->sde && txq->sde->cpu >= 0)
		netif_set_xps_queue(edev->ndev, cpumask_of(txq->sde->cpu),
				    txq->q_id);

	return rc;
}

/**
 * cne_enable_txqs - enable all TX queues on specified device
 * @edev: device on which to enable queues
 *
 * Return: 0 on success, or the first failing queue's error after
 * disabling the queues that were already enabled.
 */
int cne_enable_txqs(struct ether_device *edev)
{
	int i, rc;

	for (i = 0; i < edev->num_txqs; i++) {
		rc = cne_enable_txq(edev->txq[i]);
		if (rc) {
			while (i--)
				cne_disable_txq(edev->txq[i]);
			return rc;
		}
	}

	return 0;
}

/**
 * cne_free_rxq - free RX queue
 * @rxq: RX queue to free
 */
void cne_free_rxq(struct cn_rxq *rxq)
{
	struct ether_device *edev = rxq->edev;
	struct hfi2_pportdata *ppd = edev->ppd;

	if (rxq->rcd) {
		rxq->rcd->cne_rxq = NULL;
		cne_dealloc_rx_ctxt(ppd, rxq->rcd);
		rxq->rcd->napi = NULL;
		hfi2_rcd_put(rxq->rcd);
		rxq->rcd = NULL;
	}
	netif_napi_del(&rxq->napi);

	edev->rxq[rxq->q_id] = NULL;
	kfree(rxq);
}

/**
 * cne_trim_rxqs - free RX queues at and above @num_qs
 * @edev: Ethernet device
 * @num_qs: number of queues to keep
 */
void cne_trim_rxqs(struct ether_device *edev, int num_qs)
{
	while (edev->num_rxqs > num_qs) {
		edev->num_rxqs--;
		cne_free_rxq(edev->rxq[edev->num_rxqs]);
	}
}

/**
 * cne_free_rxqs - free all RX queues
 * @edev: Ethernet device
 */
void cne_free_rxqs(struct ether_device *edev)
{
	cne_trim_rxqs(edev, 0);
}

/*
 * Wait up to CNE_TX_DRAIN_TIMEOUT in total for TX queues @first and above
 * to go idle.  Returns the number of queues still busy and stores their
 * outstanding request count in @reqs.
 */
static int cne_wait_txqs(struct ether_device *edev, int first, int *reqs)
{
	unsigned long deadline = jiffies + CNE_TX_DRAIN_TIMEOUT;
	int busy = 0;

	*reqs = 0;
	for (int i = first; i < edev->num_txqs; i++) {
		struct cn_txq *txq = edev->txq[i];
		long left = 0;

		if (!txq)
			continue;

		/* Past the deadline, only poll the remaining queues. */
		if (time_before(jiffies, deadline))
			left = deadline - jiffies;
		if (!wait_event_timeout(txq->wait.wait_dma,
					!iowait_sdma_pending(&txq->wait), left)) {
			busy++;
			*reqs += iowait_sdma_pending(&txq->wait);
		}
	}

	return busy;
}

/**
 * cne_drain_txqs - wait for in-flight SDMA requests on all TX queues
 * @edev: Ethernet device
 *
 * Completions are delivered by the SDMA interrupt, so the wait is bounded
 * to keep a stopped engine from hanging teardown.  The caller must have
 * stopped the stack from submitting new requests.
 */
void cne_drain_txqs(struct ether_device *edev)
{
	int reqs;
	int busy = cne_wait_txqs(edev, 0, &reqs);

	if (busy)
		netdev_warn(edev->ndev,
			    "%d TX queues still have %d SDMA requests pending\n",
			    busy, reqs);
}

/**
 * cne_free_txq - free TX queue
 * @txq: TX queue to free
 *
 * Return: 0 if the queue and its txreq cache were freed.  Otherwise the
 * number of SDMA requests still pending: the queue is detached but keeps
 * its initial cache reference until any pending SDMA requests are later
 * completed.  Late completions drop only their own references and never free
 * the queue, since complete_tx() touches txq->wait after the callback returns and
 * kmem_cache_destroy() may sleep.
 */
int cne_free_txq(struct cn_txq *txq)
{
	int pending;
	u16 q_id = txq->q_id;
	struct ether_device *edev = txq->edev;
	struct sdma_engine *sde = txq->sde;
	unsigned long flags;

	if (txq->sc) {
		hfi2_sc_disable(txq->sc);
		hfi2_sc_free(txq->sc);
		txq->sc = NULL;
	}

	write_seqlock_irqsave(&sde->waitlock, flags);
	if (!list_empty(&txq->wait.list))
		list_del_init(&txq->wait.list);
	write_sequnlock_irqrestore(&sde->waitlock, flags);

	WRITE_ONCE(txq->edev, NULL);
	/* complete_tx() runs under head_lock; none is mid-flight here. */
	write_seqlock_irqsave(&sde->head_lock, flags);
	pending = iowait_sdma_pending(&txq->wait);
	write_sequnlock_irqrestore(&sde->head_lock, flags);

	edev->txq[q_id] = NULL;
	atomic_dec(&sde->dmahead_users);

	if (pending)
		return pending;

	if (txq->txreq_cache)
		cne_txq_cache_put(txq);

	return 0;
}

/**
 * cne_trim_txqs - drain and free TX queues at and above @num_qs
 * @edev: Ethernet device
 * @num_qs: number of queues to keep
 */
void cne_trim_txqs(struct ether_device *edev, int num_qs)
{
	struct hfi2_pportdata *ppd = edev->ppd;
	u32 stuck_sde = 0;
	int leaked = 0;
	int reqs = 0;
	int waiting;

	cne_wait_txqs(edev, num_qs, &waiting);

	while (edev->num_txqs > num_qs) {
		struct cn_txq *txq;
		u32 sde_idx;
		int pending;

		edev->num_txqs--;
		txq = edev->txq[edev->num_txqs];
		sde_idx = txq->sde->this_idx;
		pending = cne_free_txq(txq);
		if (pending) {
			if (!leaked)
				stuck_sde = sde_idx;
			leaked++;
			reqs += pending;
		}
	}

	if (leaked) {
		ppd->eth_leaked_txqs += leaked;
		netdev_warn(edev->ndev,
			    "leaking %d TX queues with %d SDMA requests pending, first on SDMA engine %u (%u leaked since load)\n",
			    leaked, reqs, stuck_sde, ppd->eth_leaked_txqs);
	}
}

/**
 * cne_free_txqs - drain and free all TX queues
 * @edev: Ethernet device
 */
void cne_free_txqs(struct ether_device *edev)
{
	cne_trim_txqs(edev, 0);
}
