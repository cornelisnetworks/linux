// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

/*
 * This file contains HFI2 support for netdev RX functionality
 */

#include "sdma.h"
#include "verbs.h"
#include "netdev.h"
#include "hfi2.h"
#include "chip_cyr.h"
#include "eth_hwi.h"

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <net/page_pool/helpers.h>
#include <rdma/ib_verbs.h>

/*
 * Number of zero-copy RX buffers posted per CYR Ethernet receive context,
 * bounded by the context's RcvArray eager share and RcvHdr queue size.  Each
 * entry pins one RcvArray-sized buffer (9 KB at MTU 9000) plus page_pool
 * headroom, independent of the eager_buffer_size module parameter.  0 sizes
 * the rings from cne_rx_ring_budget_mb instead.
 */
static uint cne_rx_ring_entries;

/*
 * RX throughput drops and PAUSE rises once the RX buffers being written
 * (contexts x ring x slot size) no longer fit the host's cache: the NIC's
 * posted writes then drain more slowly.  The default ring therefore splits a
 * fixed byte budget over every Ethernet RX context of the ASIC.
 */
static uint cne_rx_ring_budget_mb = 36;

#define CNE_RX_RING_AUTO_MIN 256
#define CNE_RX_RING_AUTO_MAX 1024

static uint cne_rx_egr_threshold = 32;

static uint cne_rx_buf_mtu = 9000;

static void hfi2_netdev_rxq_deinit(struct hfi2_netdev_rx *rx);

/*
 * cne_rx_buf_max_mtu - effective MTU the CYR Ethernet RX eager buffers hold.
 */
u32 cne_rx_buf_max_mtu(void)
{
	return min_t(u32, cne_rx_buf_mtu, hfi2_max_mtu);
}

/**
 * cne_rx_slot_bytes - RcvArray RT_Mode 1 slot size for one max-MTU frame
 *
 * Return: slot size in bytes, or a negative value if no slot size fits.
 */
static int cne_rx_slot_bytes(void)
{
	u32 buf_bytes = cne_rx_buf_max_mtu() + 24 + CNE_RX_TS_SIZE + ETH_HLEN +
			VLAN_HLEN + ETH_FCS_LEN;

	return cyr_rcv_array_mode1_size_bytes(buf_bytes);
}

/**
 * cne_asic_pfs - number of physical functions on this device's ASIC
 * @dd: device data
 *
 * All PFs run this driver with the same num_rxqs, so their Ethernet RX
 * rings share one cache and one RX buffer budget.
 *
 * Return: number of PFs with this device's vendor and device ID in its PCI
 * slot, at least 1; 1 for a VF.
 */
static unsigned int cne_asic_pfs(struct hfi2_devdata *dd)
{
	struct pci_dev *pdev = dd->pcidev;
	struct pci_dev *peer;
	unsigned int fn;
	unsigned int n = 0;

	if (dd->is_vf)
		return 1;

	for (fn = 0; fn < 8; fn++) {
		peer = pci_get_slot(pdev->bus,
				    PCI_DEVFN(PCI_SLOT(pdev->devfn), fn));
		if (!peer)
			continue;
		if (peer->vendor == pdev->vendor &&
		    peer->device == pdev->device && !peer->is_virtfn)
			n++;
		pci_dev_put(peer);
	}

	return max(n, 1U);
}

/**
 * cne_rx_ring_default - default zero-copy RX ring size for a CYR Ethernet port
 * @dd: device data
 * @nrxqs: number of RX contexts the port will use
 *
 * Return: cne_rx_ring_entries if set, otherwise cne_rx_ring_budget_mb split
 * over the Ethernet RX contexts of every PF on the ASIC.  The result is an
 * upper bound: cne_setup_eager_skbs() still caps it at the context's RcvArray
 * eager share and RcvHdr queue.
 */
u32 cne_rx_ring_default(struct hfi2_devdata *dd,
			u32 nrxqs)
{
	unsigned int npfs;
	u64 per_ctxt;
	int slot;
	u32 n;

	if (cne_rx_ring_entries)
		return cne_rx_ring_entries;

	slot = cne_rx_slot_bytes();
	if (slot <= 0 || !nrxqs)
		return CNE_RX_RING_AUTO_MIN;

	npfs = cne_asic_pfs(dd);
	per_ctxt = div_u64((u64)cne_rx_ring_budget_mb << 20,
			   (u64)nrxqs * npfs * slot);
	n = clamp_t(u64, per_ctxt, CNE_RX_RING_AUTO_MIN, CNE_RX_RING_AUTO_MAX);
	n = rounddown(n, dd->rcv_entries.group_size);

	dd_dev_info(dd,
		    "Ethernet RX ring %u buffers per context (%u MB over %u contexts x %u PFs, %d B slots)\n",
		    n, cne_rx_ring_budget_mb, nrxqs, npfs, slot);
	return n;
}

/**
 * cne_size_netdev_rcvhdrq - shrink a CYR netdev context's RcvHdr queue
 * @rcd: receive context (must be inspected before hfi2_create_rcvhdrq())
 * @entries: requested eager ring size
 *
 * CYR Ethernet RX runs OnePacketPerEgrBuffer, so every received frame consumes
 * exactly one eager buffer AND writes exactly one RcvHdr entry: the two rings
 * are coupled 1:1 and the eager ring is always the limiter.
 */
void cne_size_netdev_rcvhdrq(struct hfi2_ctxtdata *rcd, u32 entries)
{
	u32 cnt;

	if (!rcd->is_eth || rcd->dd->params->chip_type != CHIP_CYR)
		return;

	cnt = round_up(entries, HDRQ_INCREMENT);
	cnt = clamp_t(u32, cnt, HFI2_MIN_HDRQ_EGRBUF_CNT + HDRQ_INCREMENT,
		      HFI2_MAX_HDRQ_EGRBUF_CNT);
	rcd->rcvhdrq_cnt = cnt;
}

/*
 * cne_alloc_rx_skb - allocate one 64B-aligned RX buffer from page_pool.
 * @rcd: RX context
 * @out: allocated SKB
 * @gfp: allocation flags; GFP_KERNEL from setup, GFP_ATOMIC from NAPI
 *
 * Returns 0 on success, -ERRNO otherwise
 */
static int cne_alloc_rx_skb(struct hfi2_ctxtdata *rcd,
			    struct cne_rx_skb *out, gfp_t gfp)
{
	dma_addr_t dma;
	struct page *page;
	struct ctxt_eager_bufs *egr = &rcd->egrbufs;

	page = page_pool_alloc_pages(egr->pp, gfp | __GFP_NOWARN);
	if (!page)
		return -ENOMEM;

	/*
	 * page_pool maps the whole page from offset 0; the payload starts at
	 * NET_SKB_PAD.
	 */
	dma = page_pool_get_dma_addr(page) + NET_SKB_PAD;
	if (WARN_ON_ONCE(dma & (CYR_RCV_ARRAY_RT_MODE1_ADDR_ALIGN - 1))) {
		page_pool_put_full_page(egr->pp, page, false);
		return -EINVAL;
	}

	out->page = page;
	out->dma = dma;
	out->len = egr->rcvtid_size;

	return 0;
}

/*
 * cne_free_rx_skb -  Return one ring/freelist page to the pool
 * @rcd: RX context
 * @e:
 *
 */
static void cne_free_rx_skb(struct hfi2_ctxtdata *rcd,
			    struct cne_rx_skb *e)
{
	if (e->page) {
		struct ctxt_eager_bufs *egr = &rcd->egrbufs;

		page_pool_put_full_page(egr->pp, e->page, false);
		e->page = NULL;
		e->dma = 0;
		e->len = 0;
	}
}

/**
 * cne_rx_freelist_refill - top the per-context spare freelist back up
 * @rcd: CYR netdev receive context
 *
 * Called at the NAPI poll tail (softirq).  Refills the LIFO of pre-mapped
 * spare pages up to its capacity.
 */
void cne_rx_freelist_refill(struct hfi2_ctxtdata *rcd)
{
	struct ctxt_eager_bufs *egr = &rcd->egrbufs;

	while (egr->free_top < egr->free_count) {
		if (cne_alloc_rx_skb(rcd, &egr->free_stack[egr->free_top],
				     GFP_ATOMIC))
			break;
		egr->free_top++;
	}
}

/**
 * cne_free_eager_skbs - tear down a CYR netdev context's zero-copy RX ring
 * @rcd: CYR netdev receive context
 *
 * Must run only after the context is disabled and hfi2_clear_tids() has
 * invalidated the RcvArray entries.  The leading flush_wc() guarantees those
 * invalidations are posted before any page is returned (invalidate -> flush ->
 * put -> destroy).  Every posted and freelist page is returned to the pool,
 * then the pool is destroyed last so it can reclaim pages still in flight up
 * the stack.  A second call is a no-op.
 */
void cne_free_eager_skbs(struct hfi2_ctxtdata *rcd)
{
	u32 i;
	struct ctxt_eager_bufs *egr = &rcd->egrbufs;

	if (!egr->pp)
		return;

	flush_wc();

	if (egr->skbs) {
		for (i = 0; i < egr->alloced; i++)
			cne_free_rx_skb(rcd, &egr->skbs[i]);
		kfree(egr->skbs);
		egr->skbs = NULL;
	}

	if (egr->free_stack) {
		for (i = 0; i < egr->free_top; i++)
			cne_free_rx_skb(rcd, &egr->free_stack[i]);
		kfree(egr->free_stack);
		egr->free_stack = NULL;
	}
	egr->free_top = 0;
	egr->free_count = 0;
	egr->alloced = 0;
	egr->numbufs = 0;

	page_pool_destroy(egr->pp);
	egr->pp = NULL;
}

/**
 * cne_setup_eager_skbs - build the zero-copy RX ring for a CYR netdev context
 * @rcd: RX context (one packet per egr buffer)
 * @entries: requested eager ring size
 *
 * allocate and map one 64B-aligned buffer per RcvArray eager slot, then post
 * each slot in RT_Mode 1.  RcvArray access must be enabled (set_port_tid_config)
 * before any entry is written.
 *
 * Return: 0, -ENOMEM, or -EINVAL.
 */
int cne_setup_eager_skbs(struct hfi2_ctxtdata *rcd, u32 entries)
{
	struct hfi2_devdata *dd = rcd->dd;
	struct ctxt_eager_bufs *egr = &rcd->egrbufs;
	u32 max_entries, egrtop, nentries, idx;
	struct page_pool_params pp_params = {};
	int size_bytes;
	int size_code;
	int ret;

	BUILD_BUG_ON(NET_SKB_PAD % CYR_RCV_ARRAY_RT_MODE1_ADDR_ALIGN);
	WARN_ON(HFI2_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR));

	size_bytes = cne_rx_slot_bytes();
	if (size_bytes < 0) {
		dd_dev_err(dd, "ctxt%u: no RT_Mode 1 buffer size for MTU %u\n",
			   rcd->ctxt, cne_rx_buf_max_mtu());
		return -EINVAL;
	}

	/* One packet per egr buffer: each slot holds a single max-MTU frame. */
	egr->rcvtid_size = size_bytes;
	/*
	 * @entries is the pinned-memory bound for this ring; the only other
	 * limits are the context's RcvArray eager share and its RcvHdr queue.
	 * The generic eager_buffer_size byte budget (8 MB by default) is
	 * deliberately not applied: at a 9 KB slot it capped the ring at 904
	 * entries whatever was asked for.
	 */
	nentries = min3((u32)egr->count, entries, (u32)rcd->rcvhdrq_cnt);
	/* EgrCnt is programmed in group_size units; drop the partial group. */
	nentries = rounddown(nentries, dd->rcv_entries.group_size);
	if (nentries < 2) {
		dd_dev_err(dd, "ctxt%u: need at least 2 eager buffers, have %u\n",
			   rcd->ctxt, nentries);
		return -EINVAL;
	}

	size_code = cyr_rcv_array_mode1_size_code(egr->rcvtid_size);
	if (size_code < 0) {
		dd_dev_err(dd, "ctxt%u: no RT_Mode 1 size code for %u bytes\n",
			   rcd->ctxt, egr->rcvtid_size);
		return -EINVAL;
	}
	egr->rt_size_code = size_code;

	egr->free_stack = NULL;
	egr->free_top = 0;
	egr->free_count = 0;

	/*
	 * head_frag size backing each page: NET_SKB_PAD headroom, one full RX
	 * buffer, and the trailing skb_shared_info, matching what build_skb()
	 * over the page will assume.  page_pool DMA-maps each page once and
	 * recycles it when the flipped-out SKB is freed, avoiding a fresh
	 * high-order alloc + dma_map per received frame.  pool_size covers the
	 * posted ring, the refill freelist, and pages in flight up the stack.
	 */
	egr->frag_len = SKB_DATA_ALIGN(egr->rcvtid_size + NET_SKB_PAD) +
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	pp_params.order = get_order(egr->frag_len);
	pp_params.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV;
	pp_params.pool_size = 2 * nentries + rounddown_pow_of_two(nentries / 2);
	pp_params.nid = rcd->numa_id;
	pp_params.dev = &dd->pcidev->dev;
	pp_params.dma_dir = DMA_FROM_DEVICE;
	pp_params.max_len = egr->rcvtid_size;
	pp_params.offset = NET_SKB_PAD;
	pp_params.napi = rcd->napi;
	egr->pp = page_pool_create(&pp_params);
	if (IS_ERR(egr->pp)) {
		ret = PTR_ERR(egr->pp);
		egr->pp = NULL;
		return ret;
	}

	egr->skbs = kcalloc_node(nentries, sizeof(*egr->skbs), GFP_KERNEL, rcd->numa_id);
	if (!egr->skbs) {
		ret = -ENOMEM;
		goto bail;
	}

	/* Allocate and map every ring buffer before touching the RcvArray. */
	for (egr->alloced = 0; egr->alloced < nentries; egr->alloced++) {
		ret = cne_alloc_rx_skb(rcd, &egr->skbs[egr->alloced],
				       GFP_KERNEL);
		if (ret)
			goto bail;
		cond_resched();
	}
	egr->numbufs = egr->alloced;
	egr->size = egr->alloced * egr->rcvtid_size;

	/*
	 * The NIC reuses a slot only after RcvEgrIndexHead passes it, and the
	 * head is written every threshold buffers, so a large threshold hands
	 * slots back in big jumps and can leave the ring empty under load.
	 * The freelist is refilled every NAPI poll, which pops at most one
	 * budget of spares, so it needs only a couple of budgets.
	 */
	egr->threshold = rounddown_pow_of_two(clamp_t(u32, cne_rx_egr_threshold,
						      1, egr->alloced / 2));
	egr->free_count = min_t(u32, egr->alloced, 2 * NAPI_POLL_WEIGHT);
	egr->free_stack = kcalloc_node(egr->free_count, sizeof(*egr->free_stack),
				       GFP_KERNEL, rcd->numa_id);
	if (!egr->free_stack) {
		ret = -ENOMEM;
		goto bail;
	}

	for (egr->free_top = 0; egr->free_top < egr->free_count; egr->free_top++) {
		ret = cne_alloc_rx_skb(rcd, &egr->free_stack[egr->free_top],
				       GFP_KERNEL);
		if (ret)
			goto bail;
		cond_resched();
	}

	dd_dev_dbg(dd,
		   "ctxt%u: CYR eager skbs: %u @ %uKB, threshold %u, freelist %u, size code %u\n",
		   rcd->ctxt, egr->alloced, egr->rcvtid_size / 1024,
		   egr->threshold, egr->free_count, egr->rt_size_code);

	max_entries = rcd->rcv_array_groups * dd->rcv_entries.group_size;
	egrtop = roundup(egr->alloced, dd->rcv_entries.group_size);
	rcd->expected_count = max_entries - egrtop;
	if (rcd->expected_count > MAX_TID_PAIR_ENTRIES * 2)
		rcd->expected_count = MAX_TID_PAIR_ENTRIES * 2;
	rcd->expected_base = rcd->eager_base + egrtop;

	dd->params->set_port_tid_config(dd, rcd->ppd->hw_pidx, rcd->ctxt,
			rcd->eager_base, egr->alloced,
			rcd->expected_base, rcd->expected_count);

	/*
	 * Delay between enabling RcvArray access and the first RcvArray write.
	 * Not required on VFs; the VF2PF overhead already covers it.
	 */
	if (!dd->is_vf)
		read_uctxt_csr(dd, rcd->ctxt, dd->params->rcv_hdr_head_reg);

	for (idx = 0; idx < egr->alloced; idx++) {
		cyr_put_tid_mode1(rcd, idx, egr->skbs[idx].dma,
				  egr->rt_size_code, false);
		/* Mirror the mapped VA so get_egrbuf()/packet->ebuf resolves. */
		if (egr->rcvtids)
			egr->rcvtids[idx].addr =
				page_address(egr->skbs[idx].page) + NET_SKB_PAD;
		cond_resched();
	}
	flush_wc();

	return 0;

bail:
	cne_free_eager_skbs(rcd);
	return ret;
}

static int hfi2_netdev_setup_ctxt(struct hfi2_netdev_rx *rx,
				  struct hfi2_ctxtdata *uctxt)
{
	unsigned int rcvctrl_ops;
	struct hfi2_devdata *dd = rx->dd;
	int ret;

	uctxt->rhf_rcv_function_map = hfi2_netdev_rhf_rcv_functions;
	uctxt->do_interrupt = &hfi2_handle_receive_interrupt_napi_sp;

	/* Now allocate the RcvHdr queue and eager buffers. */
	ret = hfi2_create_rcvhdrq(dd, uctxt);
	if (ret)
		goto done;

	ret = hfi2_setup_eagerbufs(uctxt);
	if (ret)
		goto done;

	clear_rcvhdrtail(uctxt);

	rcvctrl_ops = HFI2_RCVCTRL_CTXT_DIS;
	rcvctrl_ops |= HFI2_RCVCTRL_INTRAVAIL_DIS;

	if (!HFI2_CAP_KGET_MASK(uctxt->flags, MULTI_PKT_EGR))
		rcvctrl_ops |= HFI2_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI2_CAP_KGET_MASK(uctxt->flags, NODROP_EGR_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI2_CAP_KGET_MASK(uctxt->flags, NODROP_RHQ_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_RHQ_DROP_ENB;
	if (HFI2_CAP_KGET_MASK(uctxt->flags, DMA_RTAIL))
		rcvctrl_ops |= HFI2_RCVCTRL_TAILUPD_ENB;

	hfi2_rcvctrl(uctxt->dd, rcvctrl_ops, uctxt);
done:
	return ret;
}

static int hfi2_netdev_allocate_ctxt(struct hfi2_pportdata *ppd,
				     struct hfi2_ctxtdata **ctxt)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_ctxtdata *uctxt;
	int ret;

	if (dd->flags & HFI2_FROZEN)
		return -EIO;

	ret = hfi2_create_ctxtdata(ppd, dd->node, DYNAMIC_CONTEXT, &uctxt);
	if (ret < 0) {
		dd_dev_err(dd, "Unable to create ctxtdata, failing open\n");
		return -ENOMEM;
	}

	/* One packet per eager buffer, so a whole buffer can go to the stack. */
	uctxt->flags = HFI2_CAP_KGET(NODROP_RHQ_FULL) |
		HFI2_CAP_KGET(NODROP_EGR_FULL) |
		HFI2_CAP_KGET(DMA_RTAIL);
	/* Netdev contexts are always NO_RDMA_RTAIL */
	uctxt->fast_handler = hfi2_handle_receive_interrupt_napi_fp;
	uctxt->slow_handler = hfi2_handle_receive_interrupt_napi_sp;
	hfi2_set_seq_cnt(uctxt, 1);
	uctxt->is_vnic = true;

	hfi2_stats.sps_ctxts++;

	dd_dev_info(dd, "created netdev context %d\n", uctxt->ctxt);
	*ctxt = uctxt;

	return 0;
}

static void hfi2_netdev_deallocate_ctxt(struct hfi2_pportdata *ppd,
					struct hfi2_ctxtdata *uctxt)
{
	struct hfi2_devdata *dd = ppd->dd;

	flush_wc();

	/*
	 * Disable receive context and interrupt available, reset all
	 * RcvCtxtCtrl bits to default values.
	 */
	hfi2_rcvctrl(dd, HFI2_RCVCTRL_CTXT_DIS |
		     HFI2_RCVCTRL_TIDFLOW_DIS |
		     HFI2_RCVCTRL_INTRAVAIL_DIS |
		     HFI2_RCVCTRL_ONE_PKT_EGR_DIS |
		     HFI2_RCVCTRL_NO_RHQ_DROP_DIS |
		     HFI2_RCVCTRL_NO_EGR_DROP_DIS, uctxt);

	if (uctxt->msix_intr != CCE_NUM_MSIX_VECTORS)
		hfi2_msix_free_irq(dd, uctxt->msix_intr);

	uctxt->msix_intr = CCE_NUM_MSIX_VECTORS;
	uctxt->event_flags = 0;

	hfi2_clear_tids(uctxt);
	hfi2_clear_ctxt_pkey(dd, uctxt->sc);

	hfi2_stats.sps_ctxts--;

	hfi2_free_ctxt(uctxt);
}

static int hfi2_netdev_allot_ctxt(struct hfi2_netdev_rx *rx,
				  struct hfi2_ctxtdata **ctxt)
{
	int rc;
	struct hfi2_devdata *dd = rx->dd;
	struct hfi2_pportdata *ppd = rx->ppd;

	rc = hfi2_netdev_allocate_ctxt(ppd, ctxt);
	if (rc) {
		dd_dev_err(dd, "netdev ctxt alloc failed %d\n", rc);
		return rc;
	}

	rc = hfi2_netdev_setup_ctxt(rx, *ctxt);
	if (rc) {
		dd_dev_err(dd, "netdev ctxt setup failed %d\n", rc);
		hfi2_netdev_deallocate_ctxt(ppd, *ctxt);
		*ctxt = NULL;
	}

	return rc;
}

/**
 * hfi2_num_netdev_contexts - Count of netdev recv contexts to use.
 * @dd: device on which to allocate netdev contexts
 * @available_contexts: count of available receive contexts
 * @cpu_mask: mask of possible cpus to include for contexts
 *
 * Return: count of cpus of @cpu_mask on the device's socket (its node in
 * Ethernet mode) or the remaining available recv contexts for netdev recv
 * context usage up to the maximum of HFI2_MAX_NETDEV_CTXTS.
 * A value of 0 can be returned when acceleration is explicitly turned off,
 * SR-IOV is enabled outside Ethernet mode (AIP and VNIC cannot steer per VF),
 * a memory allocation error occurs or when there are no available contexts.
 *
 */
u32 hfi2_num_netdev_contexts(struct hfi2_devdata *dd, u32 available_contexts,
			     const struct cpumask *cpu_mask)
{
	cpumask_var_t node_cpu_mask;
	unsigned int available_cpus;

	if (!hfi2_is_eth_mode(dd) && (dd->is_sriov || !HFI2_CAP_IS_KSET(AIP)))
		return 0;

	/* Always give user contexts priority over netdev contexts */
	if (available_contexts == 0) {
		dd_dev_info(dd, "No receive contexts available for netdevs.\n");
		return 0;
	}

	if (!zalloc_cpumask_var(&node_cpu_mask, GFP_KERNEL)) {
		dd_dev_err(dd, "Unable to allocate cpu_mask for netdevs.\n");
		return 0;
	}

	cpumask_and(node_cpu_mask, cpu_mask, cpumask_of_node(dd->node));

	available_cpus = cpumask_weight(node_cpu_mask);

	free_cpumask_var(node_cpu_mask);

	if (!hfi2_is_eth_mode(dd))
		return min3(available_cpus, available_contexts,
			    (u32)HFI2_MAX_NETDEV_CTXTS);

	return min3(available_cpus, available_contexts, (u32)HFI2_ETH_MAX_CTXTS);
}

static int hfi2_netdev_rxq_init(struct hfi2_netdev_rx *rx)
{
	int i;
	int rc;
	struct hfi2_devdata *dd = rx->dd;
	struct hfi2_pportdata *ppd = rx->ppd;
	struct net_device *dev = rx->rx_napi;

	rx->num_rx_q = dd->rsrcs.ppr[rx->ppd->hw_pidx].num_netdev_contexts;
	rx->rxq = kcalloc_node(rx->num_rx_q, sizeof(*rx->rxq),
			       GFP_KERNEL, dd->node);

	if (!rx->rxq) {
		ppd_dev_err(ppd, "Unable to allocate netdev queue data\n");
		return (-ENOMEM);
	}

	for (i = 0; i < rx->num_rx_q; i++) {
		struct hfi2_netdev_rxq *rxq = &rx->rxq[i];

		rc = hfi2_netdev_allot_ctxt(rx, &rxq->rcd);
		if (rc)
			goto bail_context_irq_failure;

		hfi2_rcd_get(rxq->rcd);
		rxq->rx = rx;
		rxq->rcd->napi = &rxq->napi;
		ppd_dev_info(ppd, "Setting rcv queue %d napi to context %d\n",
			    i, rxq->rcd->ctxt);
		/*
		 * Disable BUSY_POLL on this NAPI as this is not supported
		 * right now.
		 */
		set_bit(NAPI_STATE_NO_BUSY_POLL, &rxq->napi.state);
		netif_napi_add(dev, &rxq->napi, hfi2_netdev_rx_napi);

		rc = hfi2_ipoib_flip_init(rxq);
		if (rc)
			ppd_dev_warn(ppd,
				     "rxq %d: no receive page pool (%d); payload is copied on this queue\n",
				     i, rc);

		rc = hfi2_msix_netdev_request_rcd_irq(rxq->rcd);
		if (rc)
			goto bail_context_irq_failure;
	}

	return 0;

bail_context_irq_failure:
	ppd_dev_err(ppd, "Unable to allot receive context\n");
	hfi2_netdev_rxq_deinit(rx);
	return rc;
}

static void hfi2_netdev_rxq_deinit(struct hfi2_netdev_rx *rx)
{
	int i;

	for (i = 0; i < rx->num_rx_q; i++) {
		struct hfi2_netdev_rxq *rxq = &rx->rxq[i];

		if (!rxq->rcd)
			continue;

		hfi2_ipoib_flip_deinit(rxq);
		netif_napi_del(&rxq->napi);
		hfi2_netdev_deallocate_ctxt(rx->ppd, rxq->rcd);
		hfi2_rcd_put(rxq->rcd);
		rxq->rcd = NULL;
	}

	kfree(rx->rxq);
	rx->rxq = NULL;
	rx->num_rx_q = 0;
}

static void enable_queues(struct hfi2_netdev_rx *rx)
{
	int i;

	for (i = 0; i < rx->num_rx_q; i++) {
		struct hfi2_netdev_rxq *rxq = &rx->rxq[i];

		dd_dev_info(rx->dd, "enabling queue %d on context %d\n", i,
			    rxq->rcd->ctxt);
		napi_enable(&rxq->napi);
		/* HFI2_RCVCTRL_TAILUPD_* needs to be set explicitly */
		hfi2_rcvctrl(rx->dd,
			     HFI2_RCVCTRL_CTXT_ENB | HFI2_RCVCTRL_INTRAVAIL_ENB |
			     (hfi2_rcvhdrtail_kvaddr(rxq->rcd) ?
			      HFI2_RCVCTRL_TAILUPD_ENB : HFI2_RCVCTRL_TAILUPD_DIS),
			     rxq->rcd);
	}
}

static void disable_queues(struct hfi2_netdev_rx *rx)
{
	int i;

	hfi2_msix_netdev_synchronize_irq(rx->ppd);

	for (i = 0; i < rx->num_rx_q; i++) {
		struct hfi2_netdev_rxq *rxq = &rx->rxq[i];

		dd_dev_info(rx->dd, "disabling queue %d on context %d\n", i,
			    rxq->rcd->ctxt);

		/* wait for napi if it was scheduled */
		hfi2_rcvctrl(rx->dd,
			     HFI2_RCVCTRL_CTXT_DIS | HFI2_RCVCTRL_INTRAVAIL_DIS,
			     rxq->rcd);
		napi_synchronize(&rxq->napi);
		napi_disable(&rxq->napi);
	}
}

/**
 * hfi2_netdev_rx_init - Incrememnts netdevs counter. When called first time,
 * it allocates receive queue data and calls netif_napi_add for each queue.
 *
 * @dd: hfi2 dev data
 */
int hfi2_netdev_rx_init(struct hfi2_pportdata *ppd)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;
	int res = 0;

	mutex_lock(&hfi2_mutex);
	if (rx->netdevs++ == 0) {
		res = hfi2_netdev_rxq_init(rx);
		if (res)
			rx->netdevs--;
	}
	mutex_unlock(&hfi2_mutex);
	return res;
}

/**
 * hfi2_netdev_rx_destroy - Decrements netdevs counter, when it reaches 0
 * napi is deleted and receive queses memory is freed.
 *
 * @dd: hfi2 dev data
 */
int hfi2_netdev_rx_destroy(struct hfi2_pportdata *ppd)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	/* destroy the RX queues only if it is the last netdev going away */
	mutex_lock(&hfi2_mutex);
	if (--rx->netdevs == 0)
		hfi2_netdev_rxq_deinit(rx);
	mutex_unlock(&hfi2_mutex);

	return 0;
}

/**
 * hfi2_alloc_rx - Allocates the rx support structure
 * @dd: hfi2 dev data
 *
 * Allocate the rx structure to support gathering the receive
 * resources and the dummy netdev.
 *
 * Updates ppd struct pointers upon success.
 *
 * Return: 0 (success) -error on failure
 *
 */
int hfi2_alloc_rx(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	struct hfi2_netdev_rx *rx;
	int i;

	dd_dev_info(dd, "hfi2 rx allocating, size %ld\n", sizeof(*rx));

	for (i = 0; i < dd->num_pports; i++) {
		ppd = &dd->pport[i];

		rx = kzalloc_node(sizeof(*rx), GFP_KERNEL, dd->node);

		if (!rx) {
			hfi2_free_rx(dd);
			return -ENOMEM;
		}
		rx->dd = dd;
		rx->ppd = ppd;
		rx->rx_napi = alloc_netdev_dummy(0);
		if (!rx->rx_napi) {
			kfree(rx);
			hfi2_free_rx(dd);
			return -ENOMEM;
		}

		xa_init(&rx->dev_tbl);
		atomic_set(&rx->enabled, 0);
		/* rx->netdevs is already zero from kzalloc */
		ppd->netdev_rx = rx;
	}

	return 0;
}

void hfi2_free_rx(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	int i;

	dd_dev_info(dd, "hfi2 rx freed\n");
	for (i = 0; i < dd->num_pports; i++) {
		ppd = &dd->pport[i];
		/*
		 * hfi2_alloc_rx() populates pport[i].netdev_rx one port at a
		 * time and calls here on partial failure, so entries for the
		 * failing and later ports are still NULL.  Guard the dummy
		 * netdev free (kfree() is already NULL-safe).
		 */
		if (!ppd->netdev_rx)
			continue;
		free_netdev(ppd->netdev_rx->rx_napi);
		kfree(ppd->netdev_rx);
		ppd->netdev_rx = NULL;
	}
}

/**
 * hfi2_netdev_enable_queues - This is napi enable function.
 * It enables napi objects associated with queues.
 * When at least one device has called it it increments atomic counter.
 * Disable function decrements counter and when it is 0,
 * calls napi_disable for every queue.
 *
 * @dd: hfi2 dev data
 */
void hfi2_netdev_enable_queues(struct hfi2_pportdata *ppd)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	if (!rx)
		return;

	if (atomic_fetch_inc(&rx->enabled))
		return;

	mutex_lock(&hfi2_mutex);
	enable_queues(rx);
	mutex_unlock(&hfi2_mutex);
}

void hfi2_netdev_disable_queues(struct hfi2_pportdata *ppd)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	if (!rx)
		return;

	if (atomic_dec_if_positive(&rx->enabled))
		return;

	mutex_lock(&hfi2_mutex);
	disable_queues(rx);
	mutex_unlock(&hfi2_mutex);
}

/**
 * hfi2_netdev_add_data - Registers data with unique identifier
 * to be requested later this is needed for VNIC and IPoIB VLANs
 * implementations.
 * This call is protected by mutex idr_lock.
 *
 * @dd: hfi2 dev data
 * @id: requested integer id up to INT_MAX
 * @data: data to be associated with index
 */
int hfi2_netdev_add_data(struct hfi2_pportdata *ppd, int id, void *data)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	return xa_insert(&rx->dev_tbl, id, data, GFP_NOWAIT);
}

/**
 * hfi2_netdev_remove_data - Removes data with previously given id.
 * Returns the reference to removed entry.
 *
 * @dd: hfi2 dev data
 * @id: requested integer id up to INT_MAX
 */
void *hfi2_netdev_remove_data(struct hfi2_pportdata *ppd, int id)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	return xa_erase(&rx->dev_tbl, id);
}

/**
 * hfi2_netdev_get_data - Gets data with given id
 *
 * @dd: hfi2 dev data
 * @id: requested integer id up to INT_MAX
 */
void *hfi2_netdev_get_data(struct hfi2_pportdata *ppd, int id)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;

	return xa_load(&rx->dev_tbl, id);
}

/**
 * hfi2_netdev_get_first_data - Gets first entry with greater or equal id.
 *
 * @dd: hfi2 dev data
 * @start_id: requested integer id up to INT_MAX
 */
void *hfi2_netdev_get_first_data(struct hfi2_pportdata *ppd, int *start_id)
{
	struct hfi2_netdev_rx *rx = ppd->netdev_rx;
	unsigned long index = *start_id;
	void *ret;

	ret = xa_find(&rx->dev_tbl, &index, UINT_MAX, XA_PRESENT);
	*start_id = (int)index;
	return ret;
}
