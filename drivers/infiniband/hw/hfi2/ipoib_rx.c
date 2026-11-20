// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

#include <net/page_pool/helpers.h>

#include "netdev.h"
#include "ipoib.h"
#include "chip.h"

#define HFI2_IPOIB_SKB_PAD ((NET_SKB_PAD) + (NET_IP_ALIGN))

/* GRO compares hard_header_len bytes at the MAC header to match flows. */
static void hfi2_ipoib_set_hard_header(struct sk_buff *skb)
{
	memset(skb_push(skb, HFI2_IPOIB_PSEUDO_LEN), 0, HFI2_IPOIB_PSEUDO_LEN);
	skb_reset_mac_header(skb);
	skb_pull(skb, HFI2_IPOIB_PSEUDO_LEN + HFI2_IPOIB_ENCAP_LEN);
}

static void copy_ipoib_buf(struct sk_buff *skb, void *data, int size)
{
	skb->protocol = *((__be16 *)data);

	skb_put_data(skb, data, size);
	hfi2_ipoib_set_hard_header(skb);
}

/* Encap + IPv6 + TCP with options, rounded up; also the copybreak. */
#define HFI2_IPOIB_FLIP_HDR 128u

static void flip_post(struct hfi2_netdev_rxq *rxq, u32 idx, void *addr,
		      dma_addr_t dma)
{
	struct hfi2_ctxtdata *rcd = rxq->rcd;

	/* Flush the WC write before the eager head can move onto idx. */
	rcd->dd->params->put_tid(rcd, idx, PT_EAGER, dma, rxq->egr_order, true);
	rcd->egrbufs.rcvtids[idx].addr = addr;
	rcd->egrbufs.rcvtids[idx].dma = dma;
}

/*
 * Runs in slot idx's RHF handler: the hardware has finished with the slot
 * and cannot reuse it until the eager head advances after we return.
 */
struct sk_buff *hfi2_ipoib_flip_skb(struct hfi2_netdev_rxq *rxq,
				    struct hfi2_packet *packet, int size)
{
	struct hfi2_ctxtdata *rcd = rxq->rcd;
	u32 idx = packet->egr_index;
	struct page *old, *new;
	struct sk_buff *skb;
	dma_addr_t new_dma;
	u32 frag_len;

	if (unlikely(!rxq->flip_pp || idx >= rxq->flip_slots))
		return NULL;

	old = rxq->flip_page[idx];

	/* Never hand away a packed buffer; MULTI_PKT_EGR is withheld. */
	if (unlikely(rhf_egr_buf_offset(packet->rhf)))
		return NULL;

	if ((u32)size <= HFI2_IPOIB_FLIP_HDR)
		return NULL;

	/* The context owns its coherent buffers: post a pool page, copy this one. */
	if (!old) {
		new = page_pool_dev_alloc_pages(rxq->flip_pp);
		if (unlikely(!new))
			return NULL;
		rxq->flip_page[idx] = new;
		flip_post(rxq, idx, page_address(new),
			  page_pool_get_dma_addr(new));
		return NULL;
	}

	new = page_pool_dev_alloc_pages(rxq->flip_pp);
	if (unlikely(!new))
		return NULL;

	skb = napi_alloc_skb(&rxq->napi, HFI2_IPOIB_FLIP_HDR);
	if (unlikely(!skb)) {
		page_pool_put_full_page(rxq->flip_pp, new, true);
		return NULL;
	}

	new_dma = page_pool_get_dma_addr(new);

	rxq->flip_page[idx] = new;
	flip_post(rxq, idx, page_address(new), new_dma);
	dma_sync_single_for_cpu(&rcd->dd->pcidev->dev,
				page_pool_get_dma_addr(old), size, DMA_FROM_DEVICE);

	skb_put_data(skb, packet->ebuf, HFI2_IPOIB_FLIP_HDR);
	frag_len = size - HFI2_IPOIB_FLIP_HDR;
	skb_add_rx_frag(skb, 0, old,
			(int)((u8 *)packet->ebuf - (u8 *)page_address(old)) +
			(int)HFI2_IPOIB_FLIP_HDR, (int)frag_len,
			(int)rcd->egrbufs.rcvtid_size);

	skb_mark_for_recycle(skb);

	skb->protocol = *((__be16 *)packet->ebuf);
	hfi2_ipoib_set_hard_header(skb);

	return skb;
}

int hfi2_ipoib_flip_init(struct hfi2_netdev_rxq *rxq)
{
	struct hfi2_ctxtdata *rcd = rxq->rcd;
	struct hfi2_devdata *dd = rcd->dd;
	struct page_pool_params pp = {};
	u32 n = rcd->egrbufs.alloced;
	u16 order;

	if (!n || !rcd->egrbufs.rcvtids)
		return -EINVAL;

	if (!hfi2_rcvbuf_validate(rcd->egrbufs.rcvtid_size, PT_EAGER, &order))
		return -EINVAL;
	rxq->egr_order = order;

	pp.order = get_order(rcd->egrbufs.rcvtid_size);
	/* One ring posted, one up the stack, half a ring of slack. */
	pp.pool_size = 2 * n + n / 2;
	pp.nid = rcd->numa_id;
	pp.dev = &dd->pcidev->dev;
	pp.napi = &rxq->napi;
	pp.dma_dir = DMA_FROM_DEVICE;
	pp.max_len = rcd->egrbufs.rcvtid_size;
	pp.offset = 0;
	pp.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV;

	rxq->flip_pp = page_pool_create(&pp);
	if (IS_ERR(rxq->flip_pp)) {
		int ret = PTR_ERR(rxq->flip_pp);

		rxq->flip_pp = NULL;
		return ret;
	}

	rxq->flip_page = kcalloc_node(n, sizeof(*rxq->flip_page), GFP_KERNEL,
				      rcd->numa_id);
	rxq->flip_orig_addr = kcalloc_node(n, sizeof(*rxq->flip_orig_addr),
					   GFP_KERNEL, rcd->numa_id);
	rxq->flip_orig_dma = kcalloc_node(n, sizeof(*rxq->flip_orig_dma),
					  GFP_KERNEL, rcd->numa_id);
	if (!rxq->flip_page || !rxq->flip_orig_addr || !rxq->flip_orig_dma) {
		hfi2_ipoib_flip_deinit(rxq);
		return -ENOMEM;
	}

	/* Teardown restores these so no RcvArray entry is left on a pool page. */
	for (u32 i = 0; i < n; i++) {
		rxq->flip_orig_addr[i] = rcd->egrbufs.rcvtids[i].addr;
		rxq->flip_orig_dma[i] = rcd->egrbufs.rcvtids[i].dma;
	}
	rxq->flip_slots = n;

	return 0;
}

void hfi2_ipoib_flip_deinit(struct hfi2_netdev_rxq *rxq)
{
	struct hfi2_ctxtdata *rcd = rxq->rcd;

	/* Repoint every slot before releasing any page. */
	if (rxq->flip_page && rcd && rcd->egrbufs.rcvtids) {
		for (u32 i = 0; i < rxq->flip_slots; i++) {
			if (!rxq->flip_page[i])
				continue;
			flip_post(rxq, i, rxq->flip_orig_addr[i],
				  rxq->flip_orig_dma[i]);
		}
		for (u32 i = 0; i < rxq->flip_slots; i++) {
			if (!rxq->flip_page[i])
				continue;
			page_pool_put_full_page(rxq->flip_pp,
						rxq->flip_page[i], false);
			rxq->flip_page[i] = NULL;
		}
	}

	kfree(rxq->flip_page);
	rxq->flip_page = NULL;
	kfree(rxq->flip_orig_addr);
	rxq->flip_orig_addr = NULL;
	kfree(rxq->flip_orig_dma);
	rxq->flip_orig_dma = NULL;
	rxq->flip_slots = 0;

	if (rxq->flip_pp) {
		page_pool_destroy(rxq->flip_pp);
		rxq->flip_pp = NULL;
	}
}

static struct sk_buff *prepare_frag_skb(struct napi_struct *napi, int size)
{
	struct sk_buff *skb;
	int skb_size = SKB_DATA_ALIGN(size + HFI2_IPOIB_SKB_PAD);
	void *frag;

	skb_size += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	skb_size = SKB_DATA_ALIGN(skb_size);
	frag = napi_alloc_frag(skb_size);

	if (unlikely(!frag))
		return napi_alloc_skb(napi, size);

	skb = build_skb(frag, skb_size);

	if (unlikely(!skb)) {
		skb_free_frag(frag);
		return NULL;
	}

	skb_reserve(skb, HFI2_IPOIB_SKB_PAD);
	return skb;
}

struct sk_buff *hfi2_ipoib_prepare_skb(struct hfi2_netdev_rxq *rxq,
				       int size, void *data)
{
	struct napi_struct *napi = &rxq->napi;
	int skb_size = size + HFI2_IPOIB_ENCAP_LEN;
	struct sk_buff *skb;

	/*
	 * For smaller(4k + skb overhead) allocations we will go using
	 * napi cache. Otherwise we will try to use napi frag cache.
	 */
	if (size <= SKB_WITH_OVERHEAD(PAGE_SIZE))
		skb = napi_alloc_skb(napi, skb_size);
	else
		skb = prepare_frag_skb(napi, skb_size);

	if (unlikely(!skb))
		return NULL;

	copy_ipoib_buf(skb, data, size);

	return skb;
}

int hfi2_ipoib_rxq_init(struct net_device *netdev)
{
	struct hfi2_ipoib_dev_priv *ipoib_priv = hfi2_ipoib_priv(netdev);
	struct hfi2_pportdata *ppd = ipoib_priv->ppd;
	int ret;

	ret = hfi2_netdev_rx_init(ppd);
	if (ret)
		return ret;

	hfi2_init_aip_rsm(ppd);

	return ret;
}

void hfi2_ipoib_rxq_deinit(struct net_device *netdev)
{
	struct hfi2_ipoib_dev_priv *ipoib_priv = hfi2_ipoib_priv(netdev);
	struct hfi2_pportdata *ppd = ipoib_priv->ppd;

	hfi2_deinit_aip_rsm(ppd);
	hfi2_netdev_rx_destroy(ppd);
}
