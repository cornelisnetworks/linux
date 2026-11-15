/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

#ifndef HFI2_NETDEV_H
#define HFI2_NETDEV_H

#include "hfi2.h"

#include <linux/netdevice.h>
#include <linux/xarray.h>

/**
 * struct hfi2_netdev_rxq - Receive Queue for HFI
 * Both IPoIB and VNIC netdevices will be working on the rx abstraction.
 * @napi: napi object
 * @rx: ptr to netdev_rx
 * @rcd:  ptr to receive context data
 * @flip_pp: page pool for receive page flip
 * @flip_page: pool page posted per eager slot, NULL until converted
 * @flip_orig_addr: eager buffer set up per slot, restored at teardown
 * @flip_orig_dma: bus address of @flip_orig_addr
 * @flip_slots: length of the flip arrays
 * @egr_order: RcvArray size encoding for re-posts
 */
struct hfi2_netdev_rxq {
	struct napi_struct napi;
	struct hfi2_netdev_rx *rx;
	struct hfi2_ctxtdata *rcd;
	struct page_pool *flip_pp;
	struct page **flip_page;
	void **flip_orig_addr;
	dma_addr_t *flip_orig_dma;
	u32 flip_slots;
	u16 egr_order;
};

/*
 * Number of netdev contexts used. Ensure it is less than or equal to
 * max queues supported by VNIC (HFI2_VNIC_MAX_QUEUE).
 */
#define HFI2_MAX_NETDEV_CTXTS   16

/* Number of NETDEV RSM entries */
#define NUM_NETDEV_MAP_ENTRIES HFI2_MAX_NETDEV_CTXTS

#define HFI2_ETH_MAX_CTXTS 32
#define HFI2_ETH_MAP_ENTRIES 32 /* eth RSM/RMT block width; MUST be pow2, ilog2 <= 8 */

static inline u32 hfi2_map_entries(struct hfi2_devdata *dd)
{
	return hfi2_is_eth_mode(dd) ? HFI2_ETH_MAP_ENTRIES : NUM_NETDEV_MAP_ENTRIES;
}

/**
 * struct hfi2_netdev_rx: data required to setup and run HFI netdev.
 * @rx_napi:	the dummy netdevice to support "polling" the receive contexts
 * @dd:		hfi2_devdata
 * @ppd:	hfi2_pportdata
 * @rxq:	pointer to dummy netdev receive queues.
 * @num_rx_q:	number of receive queues
 * @rmt_start:	first allocated index in the RMT
 * @rmt_entries:	number of RMT entries reserved at @rmt_start
 * @dev_tbl:	netdev table for unique identifier VNIC and IPoIb VLANs.
 * @enabled:	atomic counter of netdevs enabling receive queues.
 *		When 0 NAPI will be disabled.
 * @netdevs:	count of netdev_rx users, protected by hfi2_mutex.
 *		When 0 receive queues will be freed.
 */
struct hfi2_netdev_rx {
	struct net_device *rx_napi;
	struct hfi2_devdata *dd;
	struct hfi2_pportdata *ppd;
	struct hfi2_netdev_rxq *rxq;
	int num_rx_q;
	int rmt_start;
	u32 rmt_entries;
	struct xarray dev_tbl;
	/* count of enabled napi polls */
	atomic_t enabled;
	int netdevs;
};

static inline
int hfi2_netdev_ctxt_count(struct hfi2_pportdata *ppd)
{
	return ppd->netdev_rx->num_rx_q;
}

static inline
struct hfi2_ctxtdata *hfi2_netdev_get_ctxt(struct hfi2_pportdata *ppd, int ctxt)
{
	return ppd->netdev_rx->rxq[ctxt].rcd;
}

static inline
int hfi2_netdev_get_free_rmt_idx(struct hfi2_pportdata *ppd)
{
	return ppd->netdev_rx->rmt_start;
}

static inline
u32 hfi2_netdev_get_rmt_entries(struct hfi2_pportdata *ppd)
{
	return ppd->netdev_rx->rmt_entries;
}

static inline bool is_netdev_cyr(struct hfi2_ctxtdata *rcd)
{
	return rcd->is_eth && rcd->dd->params->chip_type == CHIP_CYR;
}

int cne_setup_eager_skbs(struct hfi2_ctxtdata *rcd, u32 entries);
void cne_free_eager_skbs(struct hfi2_ctxtdata *rcd);
void cne_rx_freelist_refill(struct hfi2_ctxtdata *rcd);
u32 cne_rx_buf_max_mtu(void);
void cne_size_netdev_rcvhdrq(struct hfi2_ctxtdata *rcd, u32 entries);
u32 cne_rx_ring_default(struct hfi2_devdata *dd,
			u32 nrxqs);

/**
 * cne_rx_skb_at - fetch the sk_buff currently posted at an eager index
 * @rcd: CYR netdev receive context
 * @egr_index: eager index == RcvArray slot (one packet per egr buffer)
 *
 */
static inline struct cne_rx_skb *cne_rx_skb_at(struct hfi2_ctxtdata *rcd,
					       u32 egr_index)
{
	return &rcd->egrbufs.skbs[egr_index];
}

/**
 * cne_rx_freelist_pop - take a pre-mapped spare page off the freelist
 * @rcd: CYR netdev receive context
 * @out: filled with a ready {page, dma, len} on success
 *
 * Returns true on success; false when the freelist is empty.  Single-threaded
 * under NAPI, so unlocked.
 */
static inline bool cne_rx_freelist_pop(struct hfi2_ctxtdata *rcd,
				       struct cne_rx_skb *out)
{
	struct ctxt_eager_bufs *egr = &rcd->egrbufs;

	if (!egr->free_top)
		return false;

	*out = egr->free_stack[--egr->free_top];
	return true;
}

u32 hfi2_num_netdev_contexts(struct hfi2_devdata *dd, u32 available_contexts,
			     const struct cpumask *cpu_mask);

void hfi2_netdev_enable_queues(struct hfi2_pportdata *ppd);
void hfi2_netdev_disable_queues(struct hfi2_pportdata *ppd);
int hfi2_netdev_rx_init(struct hfi2_pportdata *ppd);
int hfi2_netdev_rx_destroy(struct hfi2_pportdata *ppd);
int hfi2_alloc_rx(struct hfi2_devdata *dd);
void hfi2_free_rx(struct hfi2_devdata *dd);
int hfi2_netdev_add_data(struct hfi2_pportdata *ppd, int id, void *data);
void *hfi2_netdev_remove_data(struct hfi2_pportdata *ppd, int id);
void *hfi2_netdev_get_data(struct hfi2_pportdata *ppd, int id);
void *hfi2_netdev_get_first_data(struct hfi2_pportdata *ppd, int *start_id);

/* chip.c  */
int hfi2_netdev_rx_napi(struct napi_struct *napi, int budget);

/* ipoib_rx.c */
struct sk_buff *hfi2_ipoib_flip_skb(struct hfi2_netdev_rxq *rxq,
				    struct hfi2_packet *packet, int size);
int hfi2_ipoib_flip_init(struct hfi2_netdev_rxq *rxq);
void hfi2_ipoib_flip_deinit(struct hfi2_netdev_rxq *rxq);

#endif /* HFI2_NETDEV_H */
