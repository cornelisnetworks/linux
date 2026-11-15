/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright (c) 2026, Cornelis Networks
 */

#ifndef _MAIN_H_
#define _MAIN_H_

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/pkt_sched.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/ctype.h>
#include <linux/linkmode.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/u64_stats_sync.h>
#include <net/ip.h>
#include <net/devlink.h>

#include "hfi2.h"
#include "sdma.h"
#include "chip_cyr.h"
#include "netdev.h"

#include "eth_hwi.h"

#if IS_ENABLED(CONFIG_INFINIBAND_HFI2_ROCE)
bool hfi2_dms_roce_netdev_match_ipv4(struct hfi2_devdata *dd,
					 const void *frame, u32 len);
void hfi2_dms_roce_netdev_enqueue(struct hfi2_devdata *dd,
					  struct sk_buff *skb);
#endif

#define CNHWI_CSR_CYR_PF_CSR_BASE_ADDRESS 0xD0000

struct ether_device;

#define CNE_IFNAME "cne"
#define ALIGN_UP(p, s) ((__typeof__(p))(((uintptr_t)(p) + ((s) - 1)) & ~((s) - 1)))
#define LSBITS(value, num_bits) (((u64)(value)) & ((((u64)1) << (num_bits)) - 1))

#define L2TYPE 2
#define DLID_23_20 0xf
#ifndef BYTES2QWORD_ROUND_UP
#define BYTES2QWORD_ROUND_UP(nbytes) (((nbytes) >> 3) + (((nbytes) & 7) != 0))
#endif

#define CN_MAX_VFS	7

struct cn_vf {
	u8	mac[ETH_ALEN];
	u8	pf_set_mac;
	u16	vid;
	u8	qos;
	bool	spoofchk;
	bool	trusted;
};

/*
 * Maximum number of TX/RX queues (and CN6000 Ethernet RX contexts) a single
 * net_device can drive.  Sized to match HFI2_ETH_MAX_CTXTS so the RSM/RMT
 * steering block (HFI2_ETH_MAP_ENTRIES) can spread flows across every queue.
 */
#define CN_MAX_QUEUES	32

/*
 * Per-packet DMA slot holding the PBC and a copy of the frame headers, so
 * both reach the SDMA engine as one premapped descriptor.  Slots are
 * 256-byte aligned so that descriptor never crosses a 256-byte boundary.
 */
#define CNE_TX_HDR_SLOT	256

/*
 * Per-queue software counters located in struct ether_device so that they
 * outlive transient queues to preserve netdev total stats.  Each slot gets
 * its own cache line so queues on different CPUs don't false-share.
 */
struct cn_txq_stats {
	u64			sdma_packets;
	u64			sdma_bytes;
	u64			sdma_errors;
	u64			errors;
	u64			drops;
	struct u64_stats_sync	syncp;
} ____cacheline_aligned_in_smp;

/* Single NAPI writer per queue */
struct cn_rxq_stats {
	u64			packets;
	u64			bytes;
	u64			errors;
	u64			drops;
	/* Indexed by 802.1Q PCP, untagged frames count as priority 0 */
	u64			prio_packets[RXE_NUM_DATA_VL];
	u64			prio_bytes[RXE_NUM_DATA_VL];
	struct u64_stats_sync	syncp;
} ____cacheline_aligned_in_smp;

struct cn_txq {
	struct ether_device	*edev;
	u16			q_id;
	u32			sc_id;
	struct send_context	*sc;
	struct sdma_engine	*sde;
	struct iowait		wait;
	struct kmem_cache	*txreq_cache;
	struct kref		txreq_cache_refcount;
	struct dma_pool		*hdr_pool;	/* CNE_TX_HDR_SLOT slots */
	struct sdma_txreq	stx;
	bool			pkts_sent;
	/* BQL epoch, bumped with each netdev_tx_reset_queue() */
	u32			bql_gen;
	u64			pbc_template;
	struct cn_txq_stats	*stats;
};

struct cn_rxq {
	struct ether_device	*edev;
	u16			q_id;
	u32			rc_id;
	struct hfi2_ctxtdata	*rcd;
	u32			ring_entries;
	struct napi_struct	napi;
	/* serializes cne_napi() polls and cne_set_coalesce() */
	spinlock_t		poll_lock;
	struct cn_rxq_stats	*stats;
};

/*
 * The OmegaCORE MAC MIB and RS-FEC counters run with PM_TICK latching
 * disabled. Software latches and clears the MAC counters on demand and
 * the RS-FEC counters clear on read, so each fold adds exactly the counts
 * since the previous fold. ethtool readers fold before reporting, and a
 * background poll keeps the hardware counters from saturating between reads.
 */
struct cn_rmon_accum {
	struct mutex		lock; /* protects all running totals below */
	struct delayed_work	work;
	/* rmon running totals */
	u64			undersize_pkts;
	u64			oversize_pkts;
	u64			fragments;
	u64			jabbers;
	u64			hist[ETHTOOL_RMON_HIST_MAX];
	u64			hist_tx[ETHTOOL_RMON_HIST_MAX];
	/* eth-mac running totals */
	u64			frames_tx_ok;
	u64			frames_rx_ok;
	u64			fcs_errors;
	u64			alignment_errors;
	u64			octets_tx_ok;
	u64			octets_rx_ok;
	u64			mcast_tx_ok;
	u64			bcast_tx_ok;
	u64			mcast_rx_ok;
	u64			bcast_rx_ok;
	/* eth-ctrl running totals: PAUSE + PFC frame counts only */
	u64			mac_ctrl_frames_tx;
	u64			mac_ctrl_frames_rx;
	/* PFC-only subset of the mac_ctrl_frames counters */
	u64			pfc_frames_tx;
	u64			pfc_frames_rx;
	/* PAUSE-counter subset of the mac_ctrl_frames counters */
	u64			pause_frames_tx;
	u64			pause_frames_rx;
	/* XON/XOFF split of the PAUSE counters */
	u64			pause_xon_tx;
	u64			pause_xon_rx;
	u64			pause_xoff_tx;
	u64			pause_xoff_rx;
	/* fec running totals */
	u64			fec_corrected_blocks;
	u64			fec_uncorrectable_blocks;
	u64			fec_corrected_bits;
};

/*
 * Snapshot of the CRK_EAL_PRF RoCEv2 telemetry counters. These counters are
 * only reachable over the CPORT mailbox.
 *
 * @expires bounds how much mailbox traffic a caller can generate: a request
 * arriving inside the window is answered from this snapshot rather than
 * re-reading the CPORT mailbox.
 */
struct cn_rocev2_snapshot {
	struct mutex		lock; /* serializes access to RoCEv2 counters */
	unsigned long		expires; /* jiffies: when the snapshot goes stale */
	u64			pkts_rcvd;
	u64			ooo_pkts_rcvd;
	u64			rift_entry_mismatch;
};

struct ether_device {
	struct net_device		*ndev;
	struct pci_dev			*pdev;
	u8				num_txqs;
	struct cn_txq			*txq[CN_MAX_QUEUES];
	u8				num_rxqs;
	struct cn_rxq			*rxq[CN_MAX_QUEUES];
	/* eager ring size for the current RX queue count */
	u32				rx_ring_entries;
	struct cn_txq_stats		txq_stats[CN_MAX_QUEUES];
	struct cn_rxq_stats		rxq_stats[CN_MAX_QUEUES];
	/* The bulksvc worker, not a NAPI queue, owns these counters. */
	struct cn_rxq_stats		ulp_rx_stats;
	struct hfi2_pportdata           *ppd;
	unsigned int			num_vfs;
	struct cn_vf			vf[CN_MAX_VFS];
#ifdef CONFIG_PTP_1588_CLOCK
	struct ptp_clock		*ptp_clock;
	struct ptp_clock_info		ptp_info;
	struct mutex			ptp_lock;
	struct hwtstamp_config		ptp_config;
	struct sk_buff			*ptp_tx_skb;
	struct delayed_work		ptp_tx_work;
	u64				ptp_tx_start;
	u64				ptp_last_tod;
	unsigned long			ptp_in_progress;
	u32				ptp_period_adj;
#endif
	u8				pfc_enabled;
	u32				msg_enable;
	struct cn_rmon_accum		rmon_accum;
	u8				first_sde;
	u8				num_sdes;
	bool				rx_enabled;
	u8				rss_indir[HFI2_ETH_MAP_ENTRIES];
	bool				rss_indir_valid;
	bool				tx_enabled;
	struct cn_rocev2_snapshot	rocev2;
};

/*
 * TX queue i uses SDMA engine first_sde + i % num_sdes, so the queues on
 * engine e are e - first_sde, plus multiples of num_sdes.  Keep both
 * directions of the mapping here.
 */
static inline u32 cne_txq_sde_idx(const struct ether_device *edev, u32 q_idx)
{
	return edev->first_sde + q_idx % edev->num_sdes;
}

/* First TX queue on @sde, or -1 if @sde carries no queue of @edev. */
static inline int cne_sde_first_txq(const struct ether_device *edev,
				    const struct sdma_engine *sde)
{
	int first = sde->this_idx - edev->first_sde;

	return first >= 0 && first < edev->num_sdes ? first : -1;
}

struct cn_txreq {
	struct sdma_txreq       txreq;
	struct cn_txq		*txq;
	struct sk_buff		*skb;
	__le64                  pbc;
	u8			*hdr;		/* hdr_pool slot, or NULL */
	dma_addr_t		hdr_dma;
	unsigned int		bql_bytes;	/* bytes charged to BQL */
	u32			bql_gen;	/* txq->bql_gen when charged */
};

/* Module parameters */
extern int debug;
extern uint num_rxqs;
extern uint num_txqs;
extern uint num_sdes;
extern int max_vlans;
extern u32 tod_period_adj;

#define perror(edev, type, fmt, args...) netif_err(edev, type, edev->ndev, fmt, ##args)
#define pwarn(edev, type, fmt, args...) netif_warn(edev, type, edev->ndev, fmt, ##args)
#define pinfo(edev, type, fmt, args...) netif_info(edev, type, edev->ndev, fmt, ##args)
#ifdef CONFIG_DYNAMIC_DEBUG
#define pdbg(edev, type, fmt, args...) netif_dbg(edev, type, edev->ndev, fmt, ##args)
#define pvdbg(edev, type, fmt, args...) netif_vdbg(edev, type, edev->ndev, fmt, ##args)
void pr_skb(struct sk_buff *skb, unsigned int payload_len, char *buffer, unsigned int buffer_len);
#else
#define pdbg(edev, type, fmt, args...) { if (0) netif_dbg(edev, type, edev->ndev, fmt, ##args); }
#define pvdbg(edev, type, fmt, args...) { if (0) netif_vdbg(edev, type, edev->ndev, fmt, ##args); }
#define pr_skb(skb, payload_len, buffer, buffer_len) \
	{ if (0) pr_debug("%p%u%s%zu", skb, payload_len, buffer, buffer_len); }
#endif

int cne_alloc_rxq(struct ether_device *edev, u32 idx, struct cn_rxq **rxq);
int cne_alloc_rxqs(struct ether_device *edev, int num_qs);
int cne_alloc_txq(struct ether_device *edev, u32 num_qs, struct cn_txq **txq);
int cne_alloc_txqs(struct ether_device *edev, int num_qs);
void cne_bypass_rcv(struct hfi2_packet *pkt);
void cne_disable_rxq(struct cn_rxq *rxq);
void cne_disable_rxqs(struct ether_device *edev);
void cne_disable_txq(struct cn_txq *txq);
void cne_disable_txqs(struct ether_device *edev);
void cne_drain_txqs(struct ether_device *edev);
int cne_enable_rxq(struct cn_rxq *rxq);
int cne_enable_rxqs(struct ether_device *edev);
void cne_rss_build_map(struct ether_device *edev, u16 *map);
int cne_enable_txq(struct cn_txq *txq);
int cne_enable_txqs(struct ether_device *edev);
void cne_free_rxq(struct cn_rxq *rxq);
void cne_free_rxqs(struct ether_device *edev);
void cne_trim_rxqs(struct ether_device *edev, int num_qs);
int cne_free_txq(struct cn_txq *txq);
void cne_free_txqs(struct ether_device *edev);
void cne_trim_txqs(struct ether_device *edev, int num_qs);
u32 cne_max_txqs(struct hfi2_pportdata *ppd, struct net_device *ndev);
u32 cne_max_rxqs(struct hfi2_pportdata *ppd);
int cne_init_ethtool(struct net_device *ndev);
void cne_destroy_ethtool(struct net_device *ndev);
int cne_open(struct net_device *ndev);
int cne_probe(struct hfi2_pportdata *ppd);
int cne_query_link_status(struct net_device *ndev, u64 *status);
void cne_update_link_state(struct hfi2_pportdata *ppd);
#ifdef CONFIG_PTP_1588_CLOCK
void cne_ptp_init(struct ether_device *edev);
int cne_ptp_get_ts_config(struct net_device *ndev, struct ifreq *r);
int cne_ptp_set_ts_config(struct net_device *ndev, struct ifreq *r);
void cne_ptp_stop(struct ether_device *edev);
#endif
int cne_disable_sriov(struct ether_device *edev);
int cne_enable_sriov(struct ether_device *edev, int num_vfs, bool reinit);
int cne_get_vf_config(struct net_device *ndev, int vf, struct ifla_vf_info *ivf);
void cne_remove(struct net_device *ndev);
int cne_set_vf_mac(struct net_device *ndev, int vf, u8 *mac);
int cne_set_vf_spoofchk(struct net_device *ndev, int vf, bool setting);
int cne_set_vf_trust(struct net_device *ndev, int vf, bool setting);
int cne_set_vf_vlan(struct net_device *ndev, int vf, u16 vlan, u8 qos, __be16 proto);
netdev_tx_t cne_start_xmit(struct sk_buff *skb, struct net_device *ndev);
void cne_tx_timeout_recover(struct net_device *ndev, unsigned int queue);
int cne_stop(struct net_device *ndev);

void cne_set_pause_enabled(struct net_device *ndev, u8 enable_bitmask);
void cne_txq_cache_get(struct cn_txq *txq);
void cne_txq_cache_put(struct cn_txq *txq);

void cne_eal_set_pause_config(struct ether_device *edev, bool use_pfc);

void cne_dcb_init(struct net_device *ndev);
void cne_dcb_set_classic(struct ether_device *edev, bool tx_pause);
void cne_dcb_set_defaults(struct net_device *ndev);
u64 cne_eal_get_rx_pause_config(struct net_device *ndev);
u64 cne_eal_rbuf_pause_cntr_vl(struct net_device *ndev, u8 vl_idx);

void cne_rmon_init(struct ether_device *edev);
void cne_rmon_start(struct ether_device *edev);
void cne_rmon_stop(struct ether_device *edev);

#endif /* _MAIN_H */
