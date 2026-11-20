// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * RoCE-flavoured rvt driver_f hooks for hfi2 in CN6000 Ethernet mode.
 *
 * This file provides RoCE-side implementations of the per-driver
 * callbacks rdmavt invokes through rvt_dev_info.driver_f.  The OPA
 * versions live in qp.c / verbs.c / ruc.c / rc.c; we keep RoCE
 * separate rather than branching every callback because the two
 * modes differ in non-trivial ways (MTU enums, AH semantics,
 * AHG/TID-RDMA/OPFN are OPA-only, etc.).
 *
 * The send-engine entry point (hfi2_roce_do_send_from_rvt) hands the
 * QP to DMS_RoCE, which builds RoCEv2 frames and PIOs them out the
 * bulksvc send context.
 */

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_verbs.h>
#include "rvt.h"
#include "rvt_qp.h"

#include "bulksvc.h"
#include "bulksvc_verbs.h"
#include "dms_roce.h"
#include "hfi2.h"
#include "qp.h"
#include "roce.h"
#include "roce_pasid.h"
#include "roce_wire.h"
#include "verbs.h"

/* ------------------------------------------------------------------------- */
/* Address-handle hooks                                                      */
/* ------------------------------------------------------------------------- */

/**
 * hfi2_roce_check_ah - validate an AH attr for the RoCE path
 * @ibdev: IB device (Ethernet mode)
 * @ah_attr: caller-supplied AH attributes
 *
 * RoCE AHs are GRH-only (no LRH/LID/SC/VL); enforce that and the
 * standard sanity checks.  The IB core has already validated the
 * GID index against the GID table by the time we get here, so we
 * mostly just refuse OPA-only constructions.
 */
int hfi2_roce_check_ah(struct ib_device *ibdev,
		       struct rdma_ah_attr *ah_attr)
{
	const struct ib_global_route *grh;

	if (rdma_ah_get_ah_flags(ah_attr) & ~IB_AH_GRH)
		return -EINVAL;
	if (!(rdma_ah_get_ah_flags(ah_attr) & IB_AH_GRH))
		return -EINVAL;

	grh = rdma_ah_read_grh(ah_attr);
	if (grh->sgid_index >= HFI2_ROCE_GID_TBL_LEN)
		return -EINVAL;
	/* SL is the Ethernet priority (PCP). */
	if (rdma_ah_get_sl(ah_attr) > 7)
		return -EINVAL;

	return 0;
}

/**
 * hfi2_roce_notify_new_ah - finalise AH state after the IB core has
 *                           filled in the public bits
 * @ibdev: IB device
 * @ah_attr: caller-supplied attributes
 * @ah: rvt_ah being initialized
 *
 * RoCE has nothing equivalent to OPA's SC->VL mapping or 9B/16B LRH
 * decision; everything we need lives in the GRH and the user's AH
 * attributes.  log_pmtu defaults to the netdev MTU so UD checks
 * in setup_wqe behave sensibly.
 */
void hfi2_roce_notify_new_ah(struct ib_device *ibdev,
			     struct rdma_ah_attr *ah_attr,
			     struct rvt_ah *ah)
{
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_pportdata *ppd = &dd->pport[HFI2_PORT_IDX];
	struct net_device *ndev = ppd->ndev;
	int mtu;

	mtu = ndev ? iboe_get_mtu(ndev->mtu) : IB_MTU_1024;
	mtu = ib_mtu_enum_to_int(mtu);
	ah->log_pmtu = (mtu > 0) ? ilog2(mtu) : 10; /* 1024B */
	ah->vl = 0;
}

/* ------------------------------------------------------------------------- */
/* QP-state-machine hooks                                                    */
/* ------------------------------------------------------------------------- */

/*
 * The PCP a QP with AH @sl uses in PFC mode: the SL if non-zero, else the DCB
 * APP priority for UDP 4791 (the highest one if several entries exist), else
 * 0.  Returns false when the port is not in PFC mode.  Both values are cached
 * by eth_dcb.c under RTNL; the APP table itself takes a BH lock and cannot be
 * read under the QP locks.  A VF sees the PFC mode as of its probe.
 */
static bool hfi2_roce_resolve_pcp(struct hfi2_pportdata *ppd, u8 sl, u8 *pcp)
{
	if (!READ_ONCE(ppd->roce_pfc_on))
		return false;
	*pcp = sl ? sl : READ_ONCE(ppd->roce_pfc_prio);
	return true;
}

/*
 * In PFC mode the PCP is also the PBC VL, so it must name an operational VL.
 * Checked here, where the modify can still fail, rather than in
 * hfi2_roce_check_ah(), which also validates AHs that carry no port state.
 */
static bool hfi2_roce_sl_ok(struct rvt_qp *qp, u8 sl)
{
	struct hfi2_pportdata *ppd =
		&dd_from_ibdev(qp->ibqp.device)->pport[HFI2_PORT_IDX];
	u8 pcp;

	return !hfi2_roce_resolve_pcp(ppd, sl, &pcp) ||
	       pcp < ppd->vls_operational;
}

/**
 * hfi2_roce_check_modify_qp - pre-flight validation of a modify_qp
 * @qp: QP being modified
 * @attr: requested attributes
 * @attr_mask: which attributes are valid in @attr
 * @udata: user data (unused)
 *
 * There is no SC/VL mapping to enforce as the OPA path does, but the
 * placement stride is per-VF while path_mtu is per-QP, so a QP asking for an
 * MTU other than roce_vrma_mtu can never be accelerated.  Refuse it here
 * instead: the alternative is a QP that completes this transition and then
 * fails its first RDMA with IBV_WC_REM_INV_REQ_ERR, which reports a remote
 * protocol error for what is really a local configuration conflict.
 *
 * The size compared is hfi2_roce_get_pmtu_from_attr()'s, the same one rdmavt
 * then latches into qp->pmtu and modify_qp claims the stride with.  It also
 * handles path_mtu=OPA_MTU_8192, which is outside enum ib_mtu.  rdmavt calls
 * this hook and get_pmtu_from_attr under the same QP locks.
 */
int hfi2_roce_check_modify_qp(struct rvt_qp *qp, struct ib_qp_attr *attr,
			      int attr_mask, struct ib_udata *udata)
{
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_ibport *ibp;
	int pmtu;

	if ((attr_mask & IB_QP_AV) &&
	    !hfi2_roce_sl_ok(qp, rdma_ah_get_sl(&attr->ah_attr)))
		return -EINVAL;
	if ((attr_mask & (IB_QP_STATE | IB_QP_DEST_QPN)) ==
	    (IB_QP_STATE | IB_QP_DEST_QPN) &&
	    attr->qp_state == IB_QPS_RTR &&
	    hfi2_dms_roce_hwp_mode(dd) &&
	    (attr->dest_qp_num & HFI2_ROCE_QPN_ALIAS_BIT)) {
		dd_dev_warn_ratelimited(dd,
					"roce: QP %u: dest QPN 0x%x uses bit 23 reserved for hardware-mode answers\n",
					qp->ibqp.qp_num, attr->dest_qp_num);
		return -EINVAL;
	}
	if (!(attr_mask & IB_QP_PATH_MTU))
		return 0;

	/*
	 * Check the path MTU the QP will actually use, which is the request
	 * capped to what the netdev can carry - the value modify_qp later
	 * claims the stride with - not the raw request.  An invalid request
	 * is left for rdmavt to refuse.
	 */
	pmtu = hfi2_roce_get_pmtu_from_attr(ib_to_rvt(qp->ibqp.device), qp,
					    attr);
	if (pmtu < 0 || !hfi2_dms_roce_stride_conflict(qp, pmtu))
		return 0;

	ibp = to_iport(qp->ibqp.device, qp->port_num);
	dd_dev_warn_ratelimited(dd_from_ppd(ppd_from_ibp(ibp)),
				"roce: QP %u rejected: path MTU %d differs from roce_vrma_mtu, the one path MTU hardware placement supports on this device\n",
				qp->ibqp.qp_num, pmtu);
	return -EINVAL;
}

/**
 * hfi2_roce_modify_qp - latch RoCE-specific state on a QP transition
 * @qp: QP being modified
 * @attr: requested attributes
 * @attr_mask: which attributes are valid in @attr
 * @udata: user data (unused)
 *
 * Called by rdmavt after the public state machine has accepted the
 * transition.  We latch dest QPN / PSNs / GRH attrs into the RoCE
 * private state so the eventual post_send/wire path has everything
 * it needs without re-reading qp->remote_ah_attr.  DMAC resolution
 * and UDP source port computation are deferred to the wire layer.
 */
/**
 * hfi2_roce_resolve_ah - resolve L2/L3 addressing from a RoCE AH
 *
 * Stage 1 is IPv4-only: pull the source IPv4 from the local GID at
 * grh->sgid_index, the destination IPv4 from grh->dgid, the DMAC from
 * the RoCE AH (the IB core neighbour-resolves it into roce.dmac), and
 * the SMAC + UDP source port from the bound netdev and caller.
 */
int hfi2_roce_resolve_ah(struct hfi2_devdata *dd,
			 struct rdma_ah_attr *ah, u16 udp_sport,
			 struct hfi2_roce_wire_addr *addr)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(ah);
	const struct ib_gid_attr *sgid_attr = grh->sgid_attr;
	struct net_device *ndev;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} saddr, daddr;

	if (!sgid_attr ||
	    rdma_gid_attr_network_type(sgid_attr) != RDMA_NETWORK_IPV4)
		return -EINVAL;

	rdma_gid2ip((struct sockaddr *)&saddr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&daddr, &grh->dgid);
	if (saddr.sa.sa_family != AF_INET || daddr.sa.sa_family != AF_INET)
		return -EINVAL;
	ndev = ib_device_get_netdev(&dd->verbs_dev.rdi.ibdev,
					      HFI2_PORT_IDX + 1);
	if (!ndev)
		return -EINVAL;
	dev_put(ndev);

	if (rdma_read_gid_l2_fields(sgid_attr, &addr->vlan_id, addr->smac))
		return -EINVAL;

	addr->saddr = saddr.sin.sin_addr.s_addr;
	addr->daddr = daddr.sin.sin_addr.s_addr;
	ether_addr_copy(addr->dmac, rdma_ah_retrieve_dmac(ah));
	addr->udp_sport = udp_sport;
	addr->traffic_class = grh->traffic_class;
	/*
	 * A VLAN header carries the PFC priority, as for RC (roce_tx_pcp()):
	 * the PCP is also the PBC VL, so one with no operational VL is not
	 * PFC-tagged and falls back to VL0.
	 */
	addr->pfc_tag = hfi2_roce_resolve_pcp(&dd->pport[HFI2_PORT_IDX],
					      rdma_ah_get_sl(ah),
					      &addr->vlan_prio) &&
			addr->vlan_prio < dd->pport[HFI2_PORT_IDX].vls_operational;
	if (!addr->pfc_tag)
		addr->vlan_prio = 0;
	addr->hop_limit = grh->hop_limit ? grh->hop_limit : 64;
	return 0;
}

static void hfi2_roce_resolve_av(struct rvt_qp *qp,
				 struct hfi2_qp_priv_roce *priv)
{
	const struct ib_global_route *grh = rdma_ah_read_grh(&qp->remote_ah_attr);
	u16 sport = rdma_flow_label_to_udp_sport(grh->flow_label);
	struct hfi2_roce_wire_addr addr;
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);

	priv->av_valid = !hfi2_roce_resolve_ah(dd, &qp->remote_ah_attr, sport,
					       &addr);
	if (!priv->av_valid) {
		dd_dev_err(dd, "roce: only IPv4 GIDs supported in stage 1\n");
		return;
	}
	priv->saddr = addr.saddr;
	priv->daddr = addr.daddr;
	ether_addr_copy(priv->dmac, addr.dmac);
	ether_addr_copy(priv->smac, addr.smac);
	priv->vlan_id = addr.vlan_id;
	priv->udp_sport = addr.udp_sport;
	priv->traffic_class = addr.traffic_class;
	priv->hop_limit = addr.hop_limit;
}

/*
 * Latch the Ethernet priority and the port PFC mode with the AV, checked by
 * hfi2_roce_check_modify_qp().  hfi2_roce_refresh_priority() later follows
 * PFC and APP changes at message boundaries.  A PFC or APP change between
 * that check and here that leaves no VL for the PCP leaves the AV
 * unresolved instead.
 */
static void hfi2_roce_set_priority(struct rvt_qp *qp,
				   struct hfi2_qp_priv_roce *priv)
{
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_pportdata *ppd = &dd->pport[HFI2_PORT_IDX];
	u8 pcp = 0;

	priv->pfc_tag = hfi2_roce_resolve_pcp(ppd,
					      rdma_ah_get_sl(&qp->remote_ah_attr),
					      &pcp);
	priv->pcp = pcp;
	if (priv->pfc_tag && pcp >= ppd->vls_operational) {
		dd_dev_warn_ratelimited(dd, "roce: QP %u PCP %u has no VL\n",
					qp->ibqp.qp_num, pcp);
		priv->av_valid = false;
	}
}

/**
 * hfi2_roce_refresh_priority - pick up a PFC or APP priority change
 * @qp: QP at a message boundary
 *
 * The caller has checked that @qp is not part-way through sending a
 * message, so every frame of a message keeps one PCP and VL.  Frames
 * already built for SDMA keep their own headers.  An AV that failed its VL
 * check stays unresolved, and a PCP with no operational VL keeps the old
 * state.
 * Frames of consecutive messages may then sit on different VLs and reorder;
 * RC recovers through a sequence NAK and go-back-N.  Caller holds s_lock.
 */
void hfi2_roce_refresh_priority(struct rvt_qp *qp)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);
	struct hfi2_pportdata *ppd =
		&dd_from_ibdev(qp->ibqp.device)->pport[HFI2_PORT_IDX];
	u8 pcp = 0;
	bool on;

	lockdep_assert_held(&qp->s_lock);
	if (!priv->av_valid)
		return;
	on = hfi2_roce_resolve_pcp(ppd, rdma_ah_get_sl(&qp->remote_ah_attr),
				   &pcp);
	if (on == priv->pfc_tag && pcp == priv->pcp)
		return;
	if (on && pcp >= ppd->vls_operational)
		return;
	priv->pfc_tag = on;
	priv->pcp = pcp;
	if (priv->roce_qp) {
		priv->roce_qp->tx_middle_prefix_valid = false;
		priv->roce_qp->resp_middle_valid = false;
	}
}

void hfi2_roce_modify_qp(struct rvt_qp *qp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);

	lockdep_assert_held(&qp->s_lock);
	if ((attr_mask & IB_QP_STATE) && attr->qp_state == IB_QPS_RTR &&
	    qp->ibqp.qp_type == IB_QPT_RC && priv->roce_qp) {
		priv->roce_qp->tomb_recv_seen = true;
		priv->roce_qp->tomb_recv_active = true;
	}
	if (attr_mask & IB_QP_AV) {
		const struct ib_global_route *grh;

		grh = rdma_ah_read_grh(&qp->remote_ah_attr);
		priv->sgid_index   = grh->sgid_index;
		priv->traffic_class = grh->traffic_class;
		priv->hop_limit    = grh->hop_limit;
		hfi2_roce_resolve_av(qp, priv);
		hfi2_roce_set_priority(qp, priv);
		/* Cached MIDDLE headers hold the old addressing and tag. */
		if (priv->roce_qp) {
			priv->roce_qp->tx_middle_prefix_valid = false;
			priv->roce_qp->resp_middle_valid = false;
		}
	}
	/*
	 * rdmavt has already latched qp->pmtu by the time it calls us, so this
	 * is the first point where the QP's final path MTU is known, so check
	 * it against the device stride here rather than at bind.
	 */
	if (attr_mask & IB_QP_PATH_MTU)
		priv->stride_ok = hfi2_dms_roce_claim_stride(qp, qp->pmtu);
	if (attr_mask & IB_QP_DEST_QPN)
		priv->dest_qpn = attr->dest_qp_num;
	/* Mask to the RoCEv2 24-bit PSN space, matching rdmavt's psn_modify_mask. */
	if (attr_mask & IB_QP_RQ_PSN)
		priv->dest_psn = attr->rq_psn & 0xffffff;
	if (attr_mask & IB_QP_SQ_PSN)
		priv->src_psn = attr->sq_psn & 0xffffff;
	if (attr_mask & IB_QP_QKEY)
		priv->qkey = attr->qkey;
}

/**
 * hfi2_roce_setup_wqe - per-WQE final validation before insertion
 * @qp: QP the WQE was posted on
 * @wqe: the WQE rdmavt has just built
 * @call_send: out: whether to schedule a send right away
 *
 * RoCE equivalent of hfi2_setup_wqe().  We skip the OPA-specific
 * bulksvc/TID-RDMA setup and the SC/VL plumbing.  Length checks
 * mirror the OPA path; the link-state gate uses netdev carrier
 * since there is no OPA host_link_state on this PF.
 */
int hfi2_roce_setup_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe,
			bool *call_send)
{
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_pportdata *ppd = &dd->pport[HFI2_PORT_IDX];

	hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
	switch (qp->ibqp.qp_type) {
	case IB_QPT_RC:
	case IB_QPT_UC:
		if (wqe->length > 0x80000000U)
			return -EINVAL;
		if (wqe->length > qp->pmtu)
			*call_send = false;
		break;
	case IB_QPT_GSI:
	case IB_QPT_UD: {
		struct rvt_ah *ah = rvt_get_swqe_ah(wqe);

		if (wqe->length > (1U << ah->log_pmtu))
			return -EINVAL;
		break;
	}
	default:
		break;
	}

	if (!ppd->ndev || !netif_carrier_ok(ppd->ndev))
		return -EINVAL;
	if (wqe->wr.send_flags & RVT_SEND_REG_MR_DEFERRED)
		return hfi2_roce_kmr_setup_reg(qp, wqe);
	if (wqe->wr.opcode == IB_WR_LOCAL_INV &&
	    !(wqe->wr.send_flags & RVT_SEND_COMPLETION_ONLY))
		return hfi2_roce_setup_local_inv(qp, wqe);

	return 0;
}

void hfi2_roce_notify_qp_reset(struct rvt_qp *qp)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);
	struct hfi2_bulksvc_qp_info *qpi = priv->bulksvc_qp_info;

	hfi2_dms_roce_reset_read_state(qp);
	hfi2_dms_roce_reset_qp(priv->roce_qp);

	/*
	 * Nothing OPA-flavoured (no AHG, no OPFN, no TID-RDMA, no
	 * kern-exp-rcv state) to clear on RoCE.  rdmavt has already
	 * reset the public QP state.
	 */
	if (qpi) {
		qpi->n_dispatched_unacked = 0;
		qpi->last_dispatched_class = OPCLASS_NONE;
		qpi->rvt_rdma_ops_sched = 0;
		qpi->bts_path_inflight_bts = 0;
		qpi->bulksvc_gated = false;
		if (qpi->gate_retry_pending) {
			qpi->gate_retry_pending = false;
			atomic_dec(&qpi->verbs_state->gate_retry_pending_count[qpi->lane]);
		}
		memset(&qpi->chain_tail_handle, 0,
		       sizeof(qpi->chain_tail_handle));
	}

	qp->r_adefered = 0;
}

void hfi2_roce_notify_error_qp(struct rvt_qp *qp)
{
	hfi2_dms_roce_reset_read_state(qp);
	/*
	 * Mirror OPA's notify_error_qp(): dequeue only so rdmavt's following
	 * schedule_send() can drain the ERROR SQ through the RoCE worker.
	 * rdmavt completes the receive WQEs in error next and the consumer may
	 * reuse them, so RX helper copies into them must land first.
	 */
	hfi2_dms_roce_dequeue_qp(to_roce_priv(qp)->roce_qp);
	hfi2_dms_roce_rx_helpers_wait_qp(to_roce_priv(qp)->roce_qp);
}

void hfi2_roce_flush_qp_waiters(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	hfi2_dms_roce_dequeue_qp(to_roce_priv(qp)->roce_qp);
}

void hfi2_roce_stop_send_queue(struct rvt_qp *qp)
{
	hfi2_dms_roce_cancel_qp(to_roce_priv(qp)->roce_qp);
}

void hfi2_roce_quiesce_qp(struct rvt_qp *qp)
{
	hfi2_dms_roce_quiesce_qp(to_roce_priv(qp)->roce_qp);
}

void hfi2_roce_notify_restart_rc(struct rvt_qp *qp, u32 psn, int wait)
{
	/*
	 * Fired from rvt_rc_timeout() (retry) with the s_lock held.  DMS_RoCE
	 * builds requests straight off the QP cursors instead of pre-building
	 * txreqs.  hfi2_dms_roce_restart() defers the rewind while any accepted
	 * SDMA batch still owns local state, then the worker resumes the same
	 * request-lane emitter epoch after consuming the final callback.  It also
	 * applies retry-count exhaustion like OPA's hfi2_restart_rc().
	 */
	(void)wait;
	hfi2_dms_roce_restart(qp, psn);
}

unsigned int hfi2_roce_free_all_qps(struct rvt_dev_info *rdi)
{
	/*
	 * rdmavt asks how many QPs are still attached at unregister
	 * time.  We do not currently keep an OPA-style ibport_data
	 * QP-table on the RoCE side, so report none.  rdmavt's own
	 * QP table is freed after this returns.
	 */
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Per-QP private state                                                      */
/* ------------------------------------------------------------------------- */

void *hfi2_roce_qp_priv_alloc(struct rvt_dev_info *rdi, struct rvt_qp *qp)
{
	struct hfi2_qp_priv_roce *priv;
	struct hfi2_devdata *dd = container_of(rdi, struct hfi2_devdata,
					       verbs_dev.rdi);

	priv = kzalloc_node(sizeof(*priv), GFP_KERNEL, rdi->dparms.node);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	priv->common.flavor = HFI2_QP_PRIV_ROCE;
	priv->owner = qp;
	priv->vlan_id = HFI2_ROCE_NO_VLAN;

	/*
	 * Bind to DMS_RoCE.  Unlike the OPA qp_info, this stores resolved
	 * device/port handles directly, so bulksvc never downcasts a RoCE
	 * priv to the OPA layout (see roce.h / dms_roce.h).
	 */
	priv->roce_qp = hfi2_dms_roce_qp_bind(qp);
	if (!priv->roce_qp) {
		kfree(priv);
		return ERR_PTR(-ENOMEM);
	}

	priv->bulksvc_qp_info = NULL;

	if (dd->bulksvc &&
	    dd->bulksvc->backend == HFI2_BULKSVC_BACKEND_OPA_DMS) {
		if (WARN_ON(qp->ibqp.qp_num >= (1 << 24))) {
			hfi2_dms_roce_qp_unbind(priv->roce_qp);
			kfree(priv);
			return ERR_PTR(-EINVAL);
		}

		priv->bulksvc_qp_info =
			hfi2_bulksvc_qp_info_create(&dd->bulksvc->verbs_state,
						    (struct hfi2_qp_priv *)priv);
		if (!priv->bulksvc_qp_info) {
			hfi2_dms_roce_qp_unbind(priv->roce_qp);
			kfree(priv);
			return ERR_PTR(-ENOMEM);
		}

		priv->bulksvc_qp_info->owner = qp;
		priv->bulksvc_qp_info->ppd = &dd->pport[HFI2_PORT_IDX];

		mutex_lock(&dd->bulksvc->verbs_state.qp_infos_lock);
		list_add_tail(&priv->bulksvc_qp_info->node,
			      &dd->bulksvc->verbs_state.qp_infos);
		mutex_unlock(&dd->bulksvc->verbs_state.qp_infos_lock);
	}

	return priv;
}

int hfi2_roce_qp_priv_init(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			   struct ib_qp_init_attr *init_attr)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);

	(void)rdi;
	(void)init_attr;
	/* rdmavt assigns s_max_sge before this hook sizes the TX snapshot. */
	return hfi2_dms_roce_qp_init(priv->roce_qp);
}

void hfi2_roce_qp_priv_free(struct rvt_dev_info *rdi, struct rvt_qp *qp)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);

	if (priv->bulksvc_qp_info) {
		struct hfi2_bulksvc_verbs_state *vs =
			priv->bulksvc_qp_info->verbs_state;

		mutex_lock(&vs->qp_infos_lock);
		list_del_init(&priv->bulksvc_qp_info->node);
		mutex_unlock(&vs->qp_infos_lock);

		priv->bulksvc_qp_info->qp_priv = NULL;
		priv->bulksvc_qp_info->owner = NULL;
		hfi2_bulksvc_qp_info_put(priv->bulksvc_qp_info);
		priv->bulksvc_qp_info = NULL;
	}

	hfi2_dms_roce_qp_unbind(priv->roce_qp);
	kfree(priv);
}

/* ------------------------------------------------------------------------- */
/* MTU handling                                                              */
/* ------------------------------------------------------------------------- */

/**
 * hfi2_roce_mtu_to_path_mtu - convert byte count back to IB MTU enum
 * @mtu: MTU in bytes
 *
 * The 8192-byte RoCE extension uses OPA_MTU_8192 because it is the existing
 * shared enum-6 definition. OPA_MTU_10240 cannot round-trip through rdmavt's
 * power-of-two log_pmtu representation, so it is intentionally not encoded.
 */
int hfi2_roce_mtu_to_path_mtu(u32 mtu)
{
	if (mtu == 8192)
		return (enum ib_mtu)OPA_MTU_8192;
	if (mtu >= 4096)
		return IB_MTU_4096;
	if (mtu >= 2048)
		return IB_MTU_2048;
	if (mtu >= 1024)
		return IB_MTU_1024;
	if (mtu >= 512)
		return IB_MTU_512;
	return IB_MTU_256;
}

/**
 * hfi2_roce_mtu_from_qp - byte-count for the QP's negotiated path MTU
 *
 * rdmavt passes back the value hfi2_roce_get_pmtu_from_attr() returned,
 * which is already a byte count, so this is a pass-through.  Decoding it
 * as an ib_mtu enum a second time fails for every legal size and lands on
 * a 1024-byte fallback.
 */
u32 hfi2_roce_mtu_from_qp(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			  u32 pmtu)
{
	return pmtu;
}

/**
 * hfi2_roce_get_pmtu_from_attr - validate the requested path MTU
 *
 * Returns the requested IB MTU enum as a byte count, capped at what the
 * netdev MTU and the per-QP TX frame buffer can carry once RoCEv2 encap
 * is accounted for.
 */
int hfi2_roce_get_pmtu_from_attr(struct rvt_dev_info *rdi, struct rvt_qp *qp,
				 struct ib_qp_attr *attr)
{
	struct hfi2_devdata *dd = dd_from_ibdev(&rdi->ibdev);
	struct net_device *ndev;
	int requested;
	u32 cap = HFI2_ROCE_MAX_PAYLOAD;
	u32 netdev_mtu;

	ndev = ib_device_get_netdev(&rdi->ibdev, qp->port_num);
	if (!ndev)
		return -ENODEV;

	netdev_mtu = READ_ONCE(ndev->mtu);
	if (netdev_mtu <= HFI2_ROCE_L3_ENCAP_BYTES) {
		dev_put(ndev);
		return -EINVAL;
	}

	if (attr->path_mtu == (enum ib_mtu)OPA_MTU_8192) {
		if (qp->ibqp.qp_type != IB_QPT_RC ||
		    !hfi2_roce_mtu_8192_available(dd, ndev)) {
			dev_put(ndev);
			return -EINVAL;
		}
		dev_put(ndev);
		return 8192;
	}

	requested = ib_mtu_enum_to_int(attr->path_mtu);
	if (requested < 0) {
		dev_put(ndev);
		return -EINVAL;
	}
	cap = min_t(u32, cap, netdev_mtu - HFI2_ROCE_L3_ENCAP_BYTES);
	dev_put(ndev);

	if (cap < ib_mtu_enum_to_int(IB_MTU_256))
		return -EINVAL;
	return min_t(u32, (u32)requested, rounddown_pow_of_two(cap));
}

/* ------------------------------------------------------------------------- */
/* Send-engine entry point                                                   */
/* ------------------------------------------------------------------------- */

/**
 * hfi2_roce_do_send_from_rvt - rdmavt's driver_f.do_send hook
 *
 * Hand the QP send queue to DMS_RoCE, which builds RoCE frames and PIOs
 * them through the bulksvc-loaned send context.
 */
void hfi2_roce_do_send_from_rvt(struct rvt_qp *qp)
{
	hfi2_dms_roce_kick_send(qp);
}

bool hfi2_roce_schedule_send(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	if (qp->state == IB_QPS_RESET)
		return false;

	return hfi2_dms_roce_enqueue(qp);
}

bool hfi2_roce_schedule_send_no_lock(struct rvt_qp *qp)
{
	if (qp->state == IB_QPS_RESET)
		return false;

	return hfi2_dms_roce_enqueue(qp);
}
