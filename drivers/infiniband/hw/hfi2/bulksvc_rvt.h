/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */

#ifndef DEF_HFI2_BULKSVC_RVT_H
#define DEF_HFI2_BULKSVC_RVT_H

#include "rvt_qp.h"
#include "bulksvc.h"

/* use bulksvc if size exceeds this */
#define BULKSVC_VERBS_MIN_SEGMENT_SIZE BIT(11) /* 2K Bytes */

/*
 * Driver-private send flag: the BTS hotpath already routed this WR to
 * rdmavt, so hfi2_setup_wqe() must not convert it to IB_WR_BULKSVC_*.
 * rdmavt uses IB_SEND_RESERVED_START and the bit above it.
 */
#define HFI2_SEND_NO_BULKSVC RVT_SEND_DRIVER_START

/* called in post_send routine
 * check if wqe can be used for bts, if so change op code */ 
bool hfi2_setup_bulksvc_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe);
// Is it possible to get cq reference in this fn?  How do we know what cq to use?

/*
 * Hand a WQE off to BTS from the rdmavt SQ walker.
 *
 * Called in general IB iowait routine when building rc reqs; adds
 * useful info to tx_list for the bts wait routine to pick up.
 *
 * Must be called with qp->s_lock held.
 *
 * Returns:
 *   0        on success (a BTS cmd was queued; qp_info->
 *            rvt_rdma_ops_sched has been incremented).
 *   -ENOMEM  cmd allocation failed.
 *   -EAGAIN  SQ back-pressure gate is closed
 *            (rvt_rdma_ops_sched >= bulksvc_sq_gate_high);
 *            qp_info->bulksvc_gated is now true and the gate will be
 *            released from ordering_deliver_one when the count drops
 *            to bulksvc_sq_gate_low.
 *
 * On any non-zero return the caller (hfi2_make_rc_req) must 'goto
 * bail' without advancing s_cur/s_tail so the WQE is retried later.
 */
int verbs_bulksvc_enqueue(struct hfi2_qp_priv *qpriv, struct verbs_txreq *tx,
			  struct rvt_swqe *wqe);
/* called from qp_schedule when BTS_PENDING bit is set */
bool hfi2_schedule_bts_send(struct rvt_qp *qp);

/* called by iowait func for BTS */
void _hfi2_do_bts_send(struct work_struct *work);
bool __hfi2_do_bts_send(struct iowait_work *w, bool in_thread);

/* notification from verbs stack of mr reg/dereg */
int verbs_bulksvc_reg_mr(struct hfi2_bulksvc *svc, struct rvt_mregion *mr);
void verbs_bulksvc_dereg_mr(struct hfi2_bulksvc *svc, struct rvt_mregion *mr);

/* rdmavt mr_priv hooks: per-MR scratch lifetime tied to rvt_mregion. */
void *verbs_bulksvc_mr_priv_alloc(struct hfi2_bulksvc *svc,
				  struct rvt_mregion *mr);
void verbs_bulksvc_mr_priv_free(struct hfi2_bulksvc *svc,
				struct rvt_mregion *mr);

/*
 * rdmavt notify_mr_pages_set hook: per-page pin/dma_map work in
 * sleepable context, off the BTS thread.  Called from
 * rvt_map_mr_sg (FastReg cycle) and rvt_reg_user_mr (user MR).
 */
int verbs_bulksvc_notify_mr_pages_set(struct hfi2_bulksvc *svc,
				      struct rvt_mregion *mr);

struct bts_verbs_mr_record;

void bts_verbs_mr_record_get(struct bts_verbs_mr_record * const rec);
void bts_verbs_mr_record_put(struct bts_verbs_mr_record * const rec);

/*
 * Release a blocked mr_priv_free destroy barrier for a queued MR_DEREG
 * cmd discarded by the teardown drain without running its BTS handler.
 */
void verbs_bulksvc_mr_dereg_cmd_discarded(struct rvt_mregion *mr);

/* Deliver one verbs cmpl synchronously on the BTS thread; drops the
 * caller's cmpl ref.
 */
void hfi2_bts_deliver_verbs_cmpl(struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_verbs_cmpl *cmpl);

#endif /* DEF_HFI2_BULKSVC_RVT_H */
