/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * Internal RoCE prototypes for the hfi2 driver.
 *
 * On CN6000 (Twain Creek), an hfi2 PF can be configured at boot to
 * present itself as either an OPA HCA or as a network controller with
 * RoCE riding on top. The RoCE registration path lives entirely inside
 * hfi2.ko; see requirements_roce_ib_device.md for the design rationale.
 */
#ifndef _HFI2_ROCE_H
#define _HFI2_ROCE_H

#include <linux/if_ether.h>
#include <linux/types.h>

#include "dms_roce.h"
#include "verbs.h"

struct hfi2_devdata;
struct net_device;
struct ib_device;
struct ib_qp_attr;
struct ib_qp_init_attr;
struct ib_udata;
struct ib_qp;
struct rdma_ah_attr;
struct hfi2_roce_wire_addr;
struct rvt_ah;
struct rvt_dev_info;
struct rvt_qp;
struct rvt_swqe;
struct rvt_qpn_table;

#ifdef CONFIG_INFINIBAND_HFI2_ROCE

/*
 * Advertised GID-table length.  The IB core owns the GID table; this
 * bounds sgid_index in add_gid/check_ah and sets props->gid_tbl_len.
 */
#define HFI2_ROCE_GID_TBL_LEN 128

/*
 * Per-QP private state when the underlying hfi2 device is in CN6000
 * Ethernet/RoCE mode.  Allocated by hfi2_roce_qp_priv_alloc() and
 * stored in qp->priv.
 *
 * Layout note: @common MUST be the first member, mirroring the
 * layout of struct hfi2_qp_priv (see verbs.h).  Only this @common
 * prefix aliases safely between the two priv structs.  Shared bulksvc
 * paths use @flavor to select the matching private layout.  Do NOT cast
 * qp->priv and read fields beyond @common without first checking it.
 *
 * Many fields here are populated lazily at modify_qp(RTR) time and
 * consumed by post_send and RoCEv2 wire formatting.
 */
struct hfi2_qp_priv_roce {
	struct hfi2_qp_priv_common common;        /* MUST be first */
	struct rvt_qp *owner;

	/* Latched at modify_qp(INIT->RTR / RTR->RTS). */
	u32 dest_qpn;                             /* IB_QP_DEST_QPN */
	u32 dest_psn;                             /* IB_QP_RQ_PSN (their RQ) */
	u32 src_psn;                              /* IB_QP_SQ_PSN (our SQ) */
	u32 qkey;                                 /* IB_QP_QKEY (UD only) */
	u8  dmac[ETH_ALEN];                       /* resolved DMAC */
	u8  smac[ETH_ALEN];                       /* our port MAC */
	__be32 saddr;                             /* our source IPv4 (from sgid) */
	__be32 daddr;                             /* peer IPv4 (from dgid) */
	u16 vlan_id;                              /* 0xffff = no VLAN */
	u16 udp_sport;                            /* RoCEv2 UDP source port */
	u8  traffic_class;                        /* GRH TClass */
	u8  hop_limit;                            /* GRH HopLimit */
	u8  sgid_index;                           /* index into IB-core GID tbl */
	bool av_valid;                            /* address resolved at RTR */
	u8  pcp;                                  /* tag PCP and PBC VL */
	bool pfc_tag;                             /* PFC: tag every frame */
	/*
	 * Whether this QP's path MTU matches the device placement stride, and
	 * so whether it may be hardware-accelerated at all.  Latched when
	 * IB_QP_PATH_MTU is applied; false leaves the QP on the software path.
	 */
	bool stride_ok;

	/*
	 * DMS_RoCE per-QP binding.  Stores resolved device/port handles
	 * directly (see dms_roce.h) instead of the OPA-style downcast of
	 * qp->priv that bulksvc's OPA qp_info does -- that downcast is unsafe
	 * for a RoCE priv, which aliases OPA only on @common.  NULL until
	 * qp_priv_alloc binds it; freed in qp_priv_free.
	 */
	struct hfi2_dms_roce_qp *roce_qp;

	/*
	 * bulksvc command-queue registration for this QP.  Created and linked
	 * into verbs_state.qp_infos in qp_priv_alloc so the hfisvc post_send
	 * path (bulksvc_on_cmd_uverbs_post_send -> qp_from_number) can find a
	 * RoCE QP by number; mirrors the OPA priv's bulksvc_qp_info binding.
	 * NULL when bulksvc is not loaned.
	 */
	struct hfi2_bulksvc_qp_info *bulksvc_qp_info;
};

static inline struct hfi2_qp_priv_roce *to_roce_priv(struct rvt_qp *qp)
{
	WARN_ON_ONCE(((struct hfi2_qp_priv_common *)qp->priv)->flavor !=
		     HFI2_QP_PRIV_ROCE);
	return (struct hfi2_qp_priv_roce *)qp->priv;
}

/**
 * hfi2_register_roce_ib_device - Register a RoCE-capable IB device.
 * @dd: hfi2 device, in Ethernet mode (hfi2_is_eth_mode(dd) == true)
 *
 * Performs the ETH-mode equivalent of hfi2_register_ib_device(): builds
 * a minimal rdmavt device with RoCE link-layer reporting and the
 * mandatory address-handle / GID callbacks, then registers it with the
 * IB core. Must only be called when ppd->ndev has been populated by
 * cne_probe().
 *
 * Return: 0 on success, negative errno on failure.
 */
int hfi2_register_roce_ib_device(struct hfi2_devdata *dd);

/**
 * hfi2_unregister_roce_ib_device - Tear down the RoCE IB device.
 * @dd: hfi2 device previously registered via hfi2_register_roce_ib_device()
 */
void hfi2_unregister_roce_ib_device(struct hfi2_devdata *dd);

/**
 * hfi2_roce_refresh_netdev - Re-bind the RoCE ib_device to ppd->ndev.
 * @dd: hfi2 device in Ethernet mode, ib_device already registered
 *
 * Called from the reinit path (hfi2_init(dd, 1)) after cne_probe()
 * recreates ppd->ndev, so the RoCE ib_device tracks the new netdev
 * instead of holding a stale reference to the freed one.
 *
 * Return: 0 on success, negative errno on failure.
 */
int hfi2_roce_refresh_netdev(struct hfi2_devdata *dd);

/**
 * hfi2_roce_disable - leave an Ethernet PF with no RoCE device
 * @dd: hfi2 device in Ethernet mode, without bulksvc
 *
 * Clears the EAL state that classifies UDP 4791 as RoCEv2, so those frames
 * reach the network stack like any other UDP (and a software RoCE device on
 * the netdev, if any, can use them).
 */
void hfi2_roce_disable(struct hfi2_devdata *dd);

bool hfi2_roce_sw_rx_ipv4_match(struct hfi2_devdata *dd, __be32 ipv4);

/*
 * RoCE-flavoured rvt driver_f hooks.  Definitions live in
 * roce_verbs.c.  These are wired into rdi->driver_f from
 * roce_main.c when registering an Ethernet-mode hfi2 device.
 */

/* AH validation / setup. */
int hfi2_roce_check_ah(struct ib_device *ibdev,
		       struct rdma_ah_attr *ah_attr);
void hfi2_roce_notify_new_ah(struct ib_device *ibdev,
			     struct rdma_ah_attr *ah_attr,
			     struct rvt_ah *ah);
int hfi2_roce_resolve_ah(struct hfi2_devdata *dd,
			 struct rdma_ah_attr *attr, u16 udp_sport,
			 struct hfi2_roce_wire_addr *addr);

/* QP-state-machine hooks (called by rdmavt). */
int hfi2_roce_check_modify_qp(struct rvt_qp *qp, struct ib_qp_attr *attr,
			      int attr_mask, struct ib_udata *udata);
void hfi2_roce_modify_qp(struct rvt_qp *qp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata);
int hfi2_roce_setup_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe,
			bool *call_send);
void hfi2_roce_notify_qp_reset(struct rvt_qp *qp);
void hfi2_roce_refresh_priority(struct rvt_qp *qp);
void hfi2_roce_notify_error_qp(struct rvt_qp *qp);
void hfi2_roce_flush_qp_waiters(struct rvt_qp *qp);
void hfi2_roce_stop_send_queue(struct rvt_qp *qp);
void hfi2_roce_quiesce_qp(struct rvt_qp *qp);
void hfi2_roce_notify_restart_rc(struct rvt_qp *qp, u32 psn, int wait);
unsigned int hfi2_roce_free_all_qps(struct rvt_dev_info *rdi);

/* Per-QP private state. */
void *hfi2_roce_qp_priv_alloc(struct rvt_dev_info *rdi, struct rvt_qp *qp);
int hfi2_roce_qp_priv_init(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			   struct ib_qp_init_attr *init_attr);
void hfi2_roce_qp_priv_free(struct rvt_dev_info *rdi, struct rvt_qp *qp);

/* OPA_MTU_8192 is the only accepted non-IB RoCE path-MTU extension. */
bool hfi2_roce_mtu_8192_available(const struct hfi2_devdata *dd,
				  const struct net_device *ndev);
int hfi2_roce_mtu_to_path_mtu(u32 mtu);
u32 hfi2_roce_mtu_from_qp(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			  u32 pmtu);
int hfi2_roce_get_pmtu_from_attr(struct rvt_dev_info *rdi, struct rvt_qp *qp,
				 struct ib_qp_attr *attr);

/* Send-engine entry point.  Stub until DMS_RoCE lands. */
void hfi2_roce_do_send_from_rvt(struct rvt_qp *qp);
bool hfi2_roce_schedule_send(struct rvt_qp *qp);
bool hfi2_roce_schedule_send_no_lock(struct rvt_qp *qp);

#else /* !CONFIG_INFINIBAND_HFI2_ROCE */

static inline int hfi2_register_roce_ib_device(struct hfi2_devdata *dd)
{
	return 0;
}

static inline void hfi2_unregister_roce_ib_device(struct hfi2_devdata *dd)
{
}

static inline int hfi2_roce_refresh_netdev(struct hfi2_devdata *dd)
{
	return 0;
}

static inline void hfi2_roce_disable(struct hfi2_devdata *dd)
{
}

static inline bool hfi2_roce_sw_rx_ipv4_match(struct hfi2_devdata *dd,
						       __be32 ipv4)
{
	return false;
}

#endif /* CONFIG_INFINIBAND_HFI2_ROCE */

#endif /* _HFI2_ROCE_H */
