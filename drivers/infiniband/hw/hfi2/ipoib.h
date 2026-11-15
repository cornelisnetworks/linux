/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

/*
 * This file contains HFI2 support for IPOIB functionality
 */

#ifndef HFI2_IPOIB_H
#define HFI2_IPOIB_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/atomic.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/if_infiniband.h>

#include "hfi2.h"
#include "iowait.h"
#include "netdev.h"
#include "bulksvc_mpsc.h"

#include <rdma/ib_verbs.h>

#define HFI2_IPOIB_ENTROPY_SHIFT   24

#define HFI2_IPOIB_MAX_TXQS 16U

#define HFI2_IPOIB_TXREQ_NAME_LEN   32

#define HFI2_IPOIB_PSEUDO_LEN 20
#define HFI2_IPOIB_ENCAP_LEN 4

#define HFI2_IPOIB_GSO_MAX_SIZE (256 * 1024)
#define HFI2_IPOIB_TSO_MAX_SEGS 64
#define HFI2_IPOIB_TXHDR_SIZE 256

struct hfi2_ipoib_dev_priv;

union hfi2_ipoib_flow {
	u16 as_int;
	struct {
		u8 tx_queue;
		u8 sc5;
	} __attribute__((__packed__));
};

/**
 * enum hfi2_ipoib_tx_mode - IPoIB transmit backend
 * @HFI2_IPOIB_TX_MODE_AIP: direct hfi2 PIO/SDMA injection
 * @HFI2_IPOIB_TX_MODE_HFISVC: HFIsvc/DMS injection
 */
enum hfi2_ipoib_tx_mode {
	HFI2_IPOIB_TX_MODE_AIP = 0,
	HFI2_IPOIB_TX_MODE_HFISVC,
};

/**
 * struct ipoib_txreq - IPOIB transmit descriptor
 * @txreq: sdma transmit request
 * @sdma_hdr: 9b ib headers
 * @sdma_status: status returned by sdma engine
 * @complete: non-zero implies complete
 * @priv: ipoib netdev private data
 * @txq: txq on which skb was output
 * @skb: skb to send, or NULL on all but the last segment of a TSO skb
 * @tx_bytes: bytes this txreq sends, for the statistics
 * @hfisvc_node: hfisvc only: handoff-queue linkage to the event thread
 * @hfisvc_run: hfisvc only: the rest of this packet's transmit run
 * @hfisvc_group_len: hfisvc only: ring entries this packet's completion covers
 * @hfisvc_engine: hfisvc only: DMS-local SDMA engine index
 */
struct ipoib_txreq {
	struct sdma_txreq           txreq;
	struct hfi2_sdma_header     *sdma_hdr;
	int                         sdma_status;
	int                         complete;
	struct hfi2_ipoib_dev_priv *priv;
	struct hfi2_ipoib_txq      *txq;
	struct sk_buff             *skb;
	u32                         tx_bytes;
	struct mpsc_node            hfisvc_node;
	struct list_head            hfisvc_run;
	u16                         hfisvc_group_len;
	u8                          hfisvc_engine;
};

/**
 * struct hfi2_ipoib_circ_buf - List of items to be processed
 * @items: ring of items each a power of two size
 * @max_items: max items + 1 that the ring can contain
 * @shift: log2 of size for getting txreq
 * @sent_txreqs: count of txreqs posted to sdma
 * @tail: ring tail
 * @stops: count of stops of queue, see hfi2_ipoib_stop_txq()
 * @ring_full: ring has been filled
 * @no_desc: descriptor shortage seen
 * @complete_txreqs: count of txreqs completed by sdma
 * @head: ring head
 */
struct hfi2_ipoib_circ_buf {
	void *items;
	u32 max_items;
	u32 shift;
	/* consumer cache line */
	u64 ____cacheline_aligned_in_smp sent_txreqs;
	u32 avail;
	u32 tail;
	atomic_t stops;
	atomic_t ring_full;
	atomic_t no_desc;
	/* producer cache line */
	u64 ____cacheline_aligned_in_smp complete_txreqs;
	u32 head;
};

/**
 * struct hfi2_ipoib_txq - IPOIB per Tx queue information
 * @priv: private pointer
 * @sde: sdma engine
 * @tx_list: tx request list, protected by the _xmit_lock of the queue's
 *           netdev_queue, except in hfi2_ipoib_drain_tx_list() at teardown
 * @sent_txreqs: count of txreqs posted to sdma
 * @flow: tracks when list needs to be flushed for a flow change
 * @q_idx: ipoib Tx queue index
 * @pkts_sent: indicator packets have been sent from this queue
 * @stop_lock: makes @tx_ring.stops and the subqueue XOFF bit move together
 * @hfisvc_napi_pending: hfisvc only: completions no napi_schedule() has covered
 * @hfisvc_run_head: hfisvc only: first packet of the run being accumulated
 * @hfisvc_run_len: hfisvc only: packets in that run
 * @napi_node: NUMA node the TX NAPI thread is bound to, NUMA_NO_NODE if unbound
 * @napi_moved: jiffies of the last @napi_node change
 * @napi_bound: the TX NAPI thread last bound to @napi_node
 * @napi_work: rebinds the TX NAPI thread to @napi_node
 * @wait: iowait structure
 * @napi: pointer to tx napi interface
 * @tx_ring: ring of ipoib txreqs to be reaped by napi callback
 */
struct hfi2_ipoib_txq {
	struct napi_struct napi;
	struct hfi2_ipoib_dev_priv *priv;
	struct sdma_engine *sde;
	struct list_head tx_list;
	union hfi2_ipoib_flow flow;
	u8 q_idx;
	bool pkts_sent;
	/* see hfi2_ipoib_stop_txq() */
	spinlock_t stop_lock;

	/* Only the event thread touches this, so it needs no atomic. */
	u32 hfisvc_napi_pending;

	/*
	 * Owned by the transmitting context: the stack serialises a txq's xmit
	 * and the run is handed off before xmit returns.  Any other writer -
	 * currently only hfi2_ipoib_tx_timeout() - must hold the _xmit_lock.
	 */
	struct ipoib_txreq *hfisvc_run_head;
	u32 hfisvc_run_len;

	int napi_node;
	unsigned long napi_moved;
	struct task_struct *napi_bound;
	struct work_struct napi_work;

	struct iowait wait;

	struct hfi2_ipoib_circ_buf ____cacheline_aligned_in_smp tx_ring;
};

/* 4 x 16B ways fill a cache line; 256 sets hold 1024 flows in 32 KB. */
#define HFI2_IPOIB_FLOW_WAYS 4
#define HFI2_IPOIB_FLOW_SETS 256
#define HFI2_IPOIB_FLOW_AGE_MS 10000

struct hfi2_ipoib_flowent {
	u64 kv;
	unsigned long seen;
};

struct hfi2_ipoib_flowset {
	struct hfi2_ipoib_flowent way[HFI2_IPOIB_FLOW_WAYS];
	bool quar;
	unsigned long quar_seen;
} ____cacheline_aligned_in_smp;

struct hfi2_ipoib_flowtab {
	struct hfi2_ipoib_flowset *set;
	/* taken to admit or assign a flow; a complete hit is lock-free */
	spinlock_t assign_lock;
	u32 rr;
	u32 qrr;
};

struct hfi2_ipoib_dev_priv {
	struct hfi2_devdata *dd;
	struct hfi2_pportdata *ppd;
	struct net_device   *netdev;
	struct ib_device    *device;
	struct hfi2_ipoib_txq *txqs;
	const struct net_device_ops *netdev_ops;
	struct rvt_qp *qp;
	u32 qkey;
	u16 pkey;
	u16 pkey_index;
	u8 port_num;
	enum hfi2_ipoib_tx_mode tx_mode;
	bool hfisvc_requested;
	/* hfisvc mode only, latched at ndo_open */
	u8 hfisvc_port_idx;
	u8 hfisvc_num_engines;
	bool hfisvc_attached;

	/* Writable copy of the ULP's ethtool ops, which lack channel ops */
	struct ethtool_ops ethtool_ops;

	struct hfi2_ipoib_flowtab flowtab;
	/* Writable copy of the ULP's ops, to add our hooks to */
	struct net_device_ops live_ops;

	/*
	 * hfisvc only: placed packets not yet completed.  Detach drains the
	 * ring only at zero, as a later completion would retire reused entries.
	 * Written per packet, so it gets a cache line of its own.
	 */
	atomic_t hfisvc_outstanding ____cacheline_aligned_in_smp;
	wait_queue_head_t hfisvc_drain_wq;
};

/* hfi2 ipoib rdma netdev's private data structure */
struct hfi2_ipoib_rdma_netdev {
	struct rdma_netdev rn;  /* keep this first */
	/* followed by device private data */
	struct hfi2_ipoib_dev_priv dev_priv;
};

static inline struct hfi2_ipoib_dev_priv *
hfi2_ipoib_priv(const struct net_device *dev)
{
	return &((struct hfi2_ipoib_rdma_netdev *)netdev_priv(dev))->dev_priv;
}

int hfi2_ipoib_send(struct net_device *dev,
		    struct sk_buff *skb,
		    struct ib_ah *address,
		    u32 dqpn);

/*
 * hfisvc mode.  _select_tx_mode() picks the backend at rdma_netdev setup.
 * At ndo_open _latch() and _attach() settle hfisvc or aip and bind the
 * transmit handoff; _detach() unbinds it at ndo_stop.
 */
void hfi2_ipoib_select_tx_mode(struct hfi2_ipoib_dev_priv *priv);
void hfi2_ipoib_hfisvc_latch(struct hfi2_ipoib_dev_priv *priv);
void hfi2_ipoib_hfisvc_attach(struct hfi2_ipoib_dev_priv *priv);
void hfi2_ipoib_hfisvc_detach(struct hfi2_ipoib_dev_priv *priv);

int hfi2_ipoib_txreq_init(struct hfi2_ipoib_dev_priv *priv);
void hfi2_ipoib_txreq_deinit(struct hfi2_ipoib_dev_priv *priv);

int hfi2_ipoib_rxq_init(struct net_device *dev);
void hfi2_ipoib_rxq_deinit(struct net_device *dev);

void hfi2_ipoib_napi_tx_enable(struct net_device *dev);
void hfi2_ipoib_napi_tx_disable(struct net_device *dev);

struct sk_buff *hfi2_ipoib_prepare_skb(struct hfi2_netdev_rxq *rxq,
				       int size, void *data);

int hfi2_ipoib_rn_get_params(struct ib_device *device,
			     u32 port_num,
			     enum rdma_netdev_t type,
			     struct rdma_netdev_alloc_params *params);

void hfi2_ipoib_tx_timeout(struct net_device *dev, unsigned int q);

u16 hfi2_ipoib_select_queue(struct net_device *dev, struct sk_buff *skb,
			    struct net_device *sb_dev);
netdev_features_t hfi2_ipoib_features_check(struct sk_buff *skb,
					    struct net_device *dev,
					    netdev_features_t features);

#endif /* _IPOIB_H */
