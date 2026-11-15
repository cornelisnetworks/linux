/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#include <linux/workqueue.h>
#include "qp.h"
#include "opfn.h"
#include "bulksvc.h"
#include "bulksvc_rvt.h"
#include "bulksvc_verbs.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/*** TEMP THINGS UNTIL API IS DEFINED ***/
int verbs_bulksvc_reg_mr(struct hfi2_bulksvc *svc, struct rvt_mregion *mr)
{
	if (WARN_ON(!svc || !mr || !mr->pd)) {
		pr_err("%s:%d:%s() bulksvc: Invalid svc or mr\n",
		       __FILE__, __LINE__, __func__);
		return -EINVAL;
	}

	struct hfi2_bulksvc_verbs_cmd * const cmd =
		hfi2_bulksvc_verbs_cmd_mr_reg_create(svc, mr);

	if (WARN_ON(!cmd)) {
		pr_err("%s:%d:%s() bulksvc: Failed to create MR reg cmd\n",
		       __FILE__, __LINE__, __func__);
		return -ENOMEM;
	}

	atomic_inc(&svc->verbs_state.cmd_queue.depth);
	mpsc_enqueue(&svc->verbs_state.cmd_queue.mpsc, &cmd->mpsc_node);

	hfi2_bulksvc_schedule(svc);
	return 0;
}

void verbs_bulksvc_dereg_mr(struct hfi2_bulksvc *svc, struct rvt_mregion *mr)
{
	struct hfi2_bulksvc_verbs_cmd * const cmd =
		hfi2_bulksvc_verbs_cmd_mr_dereg_create(svc, mr);

	if (WARN_ON(!cmd)) {
		pr_err("%s:%d:%s() bulksvc: Failed to create MR dereg cmd\n",
		       __FILE__, __LINE__, __func__);
		return;
	}

	atomic_inc(&svc->verbs_state.cmd_queue.depth);
	mpsc_enqueue(&svc->verbs_state.cmd_queue.mpsc, &cmd->mpsc_node);

	hfi2_bulksvc_schedule(svc);
}

static int bts_on_verbs_rdma_op(struct hfi2_bulksvc_verbs_cmd *cmd)
{
	if (!cmd) {
		printk(KERN_ERR "vBTS called with no cmd\n");
		return -EINVAL;
	}
	if (WARN_ON(cmd->op != HFI2_BULKSVC_VERBS_CMD_OP_RDMA)) {
		printk(KERN_ERR "vBTS called with non-RDMA cmd op %u\n", cmd->op);
		return -EINVAL;
	}
	struct verbs_txreq *tx = cmd->rdma.txreq;
	if (!tx || !tx->qp || !tx->qp->priv) {
		printk(KERN_ERR "vBTS called with no tx or qp priv\n");
		return -EINVAL;
	}
	enum ib_qp_type const qptype = tx->qp->ibqp.qp_type;
	if (qptype != IB_QPT_RC) {
		printk(KERN_ERR "vBTS called with non-RC qp type %d\n", qptype);
		return -EINVAL;
	}
	if (!tx->wqe) {
		printk(KERN_ERR "vBTS called with no wqe\n");
		return -EINVAL;
	}
	// Checked above that qptype is RC
	enum ib_wr_opcode const opcode = tx->wqe->wr.opcode;
	if (!ib_wr_opcode_is_hfi2_bulksvc(opcode)) {
		printk(KERN_ERR "vBTS called with non-BULKSVC opcode %d\n",
		       opcode);
		// TODO
		return -EINVAL;
	}

	struct hfi2_bulksvc *svc = container_of(cmd->rdma.qp_info->verbs_state,
						struct hfi2_bulksvc,
						verbs_state);
	/* the QP's own lane runs its BTS state; see hfi2_bulksvc_qp_info */
	u32 const lane = cmd->rdma.qp_info->lane;
	struct hfi2_bulksvc_mpsc_verbs_cmd_queue *const cmd_queue =
		svc->lanes[lane].cmdq;

	atomic_inc(&cmd_queue->depth);
	mpsc_enqueue(&cmd_queue->mpsc, &cmd->mpsc_node);
	hfi2_bulksvc_schedule_lane(svc, lane);

	return 0;
}

/*** ACTUAL THINGS ***/
static bool bulksvc_negotiation_check(struct rvt_qp *qp)
{
	struct hfi2_qp_priv *qpriv = qp->priv;

	if (!hfi2_opfn_dms_negotiated(qp))
		return false;

	return !!rcu_access_pointer(qpriv->dms.remote);
}

/*
 * lkey 0 is the reserved DMA MR (rvt_get_dma_mr) used by kernel ULPs
 * like IPoIB, it has no pinned page list, until bulksvc can register
 * the lkey 0 MR, it must reject all WQE's which use it
 */
static bool bulksvc_wqe_uses_dma_mr(const struct rvt_swqe *wqe)
{
	int i;

	for (i = 0; i < wqe->wr.num_sge; i++) {
		const struct rvt_mregion *mr = wqe->sg_list[i].mr;

		if (!mr || mr->lkey == 0)
			return true;
	}
	return false;
}

/* STEP 1: Recognize this wqe is eligble for BTS */
/* return true if this wqe opcode has been changed to use bulksvc */
/* this function is comparable to setup_tid_rdma_wqe */
bool hfi2_setup_bulksvc_wqe(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct hfi2_qp_priv *qpriv;
	struct hfi2_pportdata *ppd;
	struct hfi2_devdata *dd;
	enum ib_wr_opcode new_opcode;
	u32 new_lpsn;
	/*
	 * The length gate is intentionally independent of the OPFN DMS
	 * negotiation check below: size eligibility and peer capability
	 * are orthogonal admission conditions.
	 */
	if (wqe->length < BULKSVC_VERBS_MIN_SEGMENT_SIZE)
		return false;
	switch (wqe->wr.opcode) {
	case IB_WR_RDMA_READ:
		if (wqe->rdma_wr.rkey == 0)
			return false;
		new_opcode = IB_WR_BULKSVC_READ;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_RDMA_WRITE:
		if (wqe->rdma_wr.rkey == 0)
			return false;
		new_opcode = IB_WR_BULKSVC_WRITE;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		if (wqe->rdma_wr.rkey == 0)
			return false;
		new_opcode = IB_WR_BULKSVC_WRITE_WITH_IMM;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_SEND:
		if (!bulksvc_verbs_send_rcv)
			return false;
		if (!hfi2_bts_send_offload_ok(qp))
			return false;
		new_opcode = IB_WR_BULKSVC_SEND;
		new_lpsn = wqe->psn - 1;
		break;
	case IB_WR_SEND_WITH_IMM:
		if (!bulksvc_verbs_send_rcv)
			return false;
		if (!hfi2_bts_send_offload_ok(qp))
			return false;
		new_opcode = IB_WR_BULKSVC_SEND_WITH_IMM;
		new_lpsn = wqe->psn - 1;
		break;
	default:
		return false;
	}

	qpriv = (struct hfi2_qp_priv *)qp->priv;
	/* IB packets only */
	if (qpriv->hdr_type != HFI2_PKT_TYPE_9B)
		return false;

	/* reserved DMA MR (lkey 0) buffers can't be resolved by DMS */
	if (bulksvc_wqe_uses_dma_mr(wqe))
		return false;

	ppd = qpriv->rcd->ppd;

	/* bulksvc supported on both sides check */
	if (!bulksvc_negotiation_check(qp))
		return false;
	/* is bulksvc ready to go */
	dd = ppd->dd;
	if (!dd->bulksvc)
		return false;

	wqe->wr.opcode = new_opcode;
	wqe->lpsn = new_lpsn;
	qp->s_ssn--; /* peer won't give us an MSN update so don't count this ssn */

	return true;
}

/*
 * STEP 2: Silently remove this entry from the standard verbs processing
 * store any data we may need to give to BTS
 * called from normal IB verbs processing
 *
 * See bulksvc_rvt.h for the full contract (lockdep / return values /
 * caller obligations on non-zero return).
 */
int verbs_bulksvc_enqueue(struct hfi2_qp_priv *qpriv, struct verbs_txreq *tx,
			  struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = qpriv->owner;

	lockdep_assert_held(&qp->s_lock);

	/* SQ back-pressure gate: park walker if pipeline is full. */
	if (qpriv->bulksvc_qp_info->rvt_rdma_ops_sched >=
	    READ_ONCE(bulksvc_sq_gate_high)) {
		qpriv->bulksvc_qp_info->bulksvc_gated = true;
		return -EAGAIN;
	}

	qpriv->bulksvc_qp_info->rvt_rdma_ops_sched++;
	/* txreq is more or less a shell around our wqe, grab extra kref
	 * since we will be dropping it in make_rc_req
	 */
	/* this kref should be dropped when handed to BTS in _hfi2_do_bts_send */
	hfi2_get_txreq(tx);
	tx->wqe = wqe; // wqe is what we really will need later

	tx->bts_cmd = hfi2_bulksvc_verbs_cmd_rdma_create(
		qpriv->bulksvc_qp_info->ordering.svc,
		qpriv->bulksvc_qp_info, qp, tx);
	if (!tx->bts_cmd) {
		printk(KERN_ERR "vBTS failed to allocate cmd\n");
		hfi2_put_txreq(tx);
		qpriv->bulksvc_qp_info->rvt_rdma_ops_sched--;
		return -ENOMEM;
	}

	list_add_tail(&tx->txreq.list,
		      &qpriv->s_iowait.wait[IOWAIT_BTS_SE].tx_head);

	hfi2_iowait_set_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);

	/* try to send now */
	if (__hfi2_do_bts_send(&qpriv->s_iowait.wait[IOWAIT_BTS_SE], true))
		hfi2_iowait_clear_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
	/* else immediate send failed, just leave PENDING flag */
	return 0;

	// /* Ideally we set the flag above and iowait see's it and
	//  * calls our function in hfi2_qp_schedule.
	//  * My understanding is apparently wrong, if we return here
	//  * nothing happens.
	//  * So do what we expected to happen in another thread here.
	//  * and figure this crap out later. Maybe we skip all this
	//  * iowait stuff and hand to bts here
	//  */
	// int ret;
	// qp->s_flags &= ~RVT_S_BUSY;
	// if (hfi2_iowait_flag_set(&qpriv->s_iowait, IOWAIT_PENDING_BTS)) {
	// 	ret = hfi2_schedule_bts_send(qp);
	// 	if (ret)
	// 		hfi2_iowait_clear_flag(&qpriv->s_iowait, IOWAIT_PENDING_BTS);
	// }
}

static bool _hfi2_schedule_bts_send(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	struct hfi2_qp_priv *priv = qp->priv;
	struct hfi2_ibport *ibp =
		to_iport(qp->ibqp.device, qp->port_num);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct hfi2_devdata *dd = ppd->dd;

	if ((dd->flags & HFI2_SHUTDOWN))
		return true;

	return iowait_bts_schedule(&priv->s_iowait, dd->hfi2_wq,
				   priv->s_sde ?
				   priv->s_sde->cpu :
				   cpumask_first(cpumask_of_node(dd->node)));
}

/* called by iowait functions */
bool hfi2_schedule_bts_send(struct rvt_qp *qp)
{
	lockdep_assert_held(&qp->s_lock);
	if (qp->state == IB_QPS_RESET)
		return false;
	if (hfi2_send_ok(qp)) {
		/*
		 * The following call returns true if the wq is not on the
		 * queue and false if the wq is already on the queue before
		 * this call. Either way, the qp will be on the queue when the
		 * call returns.
		 */
		_hfi2_schedule_bts_send(qp);
		return true;
	}
	if (qp->s_flags & HFI2_S_ANY_WAIT_IO)
		hfi2_iowait_set_flag(&((struct hfi2_qp_priv *)qp->priv)->s_iowait,
				IOWAIT_PENDING_BTS);

	return false;
}

/* STEP 4: Hand to BTS */
/* returns true if list item handled false if not */
bool __hfi2_do_bts_send(struct iowait_work *w, bool in_thread)
{
	struct sdma_txreq *txreq = iowait_get_txhead(w);
	struct verbs_txreq *tx;
	unsigned long flags;
	struct rvt_qp *qp;

	if (!txreq) {
		printk(KERN_ERR "vBTS scheduled us but empty list\n");
		return true;
	}

	tx = container_of(txreq, struct verbs_txreq, txreq);
	qp = tx->qp;
	if (!qp) {
		printk(KERN_ERR "vBTS scheduled request with no qp\n");
		hfi2_put_txreq(tx);
		return true;
	}

	if (!tx->bts_cmd) {
		printk(KERN_ERR "vBTS scheduled with no bts cmd\n");
		hfi2_put_txreq(tx);
		return true;
	}

	if(!bts_on_verbs_rdma_op(tx->bts_cmd)) {
		hfi2_put_txreq(tx);
		return true; /* success case */
	}

	if (!in_thread)
		spin_lock_irqsave(&qp->s_lock, flags);
	list_add_tail(&tx->txreq.list, &w->tx_head);
	if (!in_thread)
		spin_unlock_irqrestore(&qp->s_lock, flags);
	hfi2_iowait_set_flag(w->iow, IOWAIT_PENDING_BTS);
	return false;
}

/* called from iowait schedule */
void _hfi2_do_bts_send(struct work_struct *work)
{
	struct iowait_work *w = container_of(work, struct iowait_work, iowork);

	__hfi2_do_bts_send(w, false);
}

static void bts_rdma_complete(struct hfi2_bulksvc_verbs_cmpl *cmpl)
{
	struct hfi2_bulksvc_verbs_cmd *cmd = cmpl->cmd.bts_cmd;
	struct hfi2_bulksvc_qp_info *qp_info = cmd->rdma.qp_info;
	struct verbs_txreq *tx = cmd->rdma.txreq;
	struct hfi2_qp_priv *priv = qp_info->qp_priv;
	struct rvt_qp *qp = priv->owner;
	struct hfi2_ibport *ibp =
		to_iport(qp->ibqp.device, qp->port_num);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct hfi2_devdata *dd = ppd->dd;

	if ((dd->flags & HFI2_SHUTDOWN))
		return;

	/* tuck rc code in for reference later */
	tx->bts_rc = cmpl->cmd.status;

	unsigned long flags;

	spin_lock_irqsave(&qp->s_lock, flags);

	/*
	 * If the QP has already transitioned to ERR or RESET,
	 * rvt_clear_mr_refs() has already walked the send ring,
	 * released MR references via rvt_put_qp_swqe(), and posted
	 * flush CQEs for every remaining WQE.  Calling
	 * rvt_send_complete() again would double-put the MR percpu_ref
	 * (one put per SGE), causing a refcount underflow and
	 * use-after-free when the MR is later accessed.
	 *
	 * Skip the completion — the flush path owns WQE cleanup.
	 */
	if (qp->state == IB_QPS_ERR || qp->state == IB_QPS_RESET)
		goto unlock;

	rvt_send_complete(tx->qp, tx->wqe, tx->bts_rc, RVT_QP_LOCK_STATE_S);
	if (priv->s_flags & HFI2_S_TID_WAIT_INTERLCK &&
		!priv->bulksvc_qp_info->rvt_rdma_ops_sched) {

		priv->s_flags &= ~HFI2_S_TID_WAIT_INTERLCK;
		hfi2_schedule_send(qp);
	}
unlock:
	spin_unlock_irqrestore(&qp->s_lock, flags);
}

static void bts_access_complete(struct hfi2_bulksvc_verbs_cmpl *cmpl)
{
	struct hfi2_ibdev *verbs_dev;
	struct rvt_qp *qp;
	struct rvt_dev_info *rdi;
	struct hfi2_devdata *dd;
	struct ib_qp *ibqp;
	struct ib_wc wc;
	unsigned long r_lock_flags;
	int ret;

	if (WARN_ON(!cmpl) || WARN_ON(cmpl->type != HFI2_BULKSVC_VERBS_CMPL_TYPE_ACCESS)) {
		pr_err("bts_access_complete called with invalid cmpl\n");
		return;
	}

	qp = cmpl->access.qp;

	ibqp = &qp->ibqp;

	spin_lock_irqsave(&qp->r_lock, r_lock_flags);

	ret = rvt_get_rwqe(qp, true);
	if (ret <= 0) {
		spin_unlock_irqrestore(&qp->r_lock, r_lock_flags);

		rdi = ib_to_rvt(ibqp->device);
		verbs_dev = container_of(rdi, struct hfi2_ibdev, rdi);
		dd = container_of(verbs_dev, struct hfi2_devdata, verbs_dev);
		if (ret < 0)
			dd_dev_err(dd, "bulksvc: Error getting rwqe\n");
		else
			dd_dev_dbg(dd, "bulksvc: No rwqe's available\n");

		return;
	}
	if (!__test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags)) {
		spin_unlock_irqrestore(&qp->r_lock, r_lock_flags);
		return;
	}

	wc.wr_id = qp->r_wr_id;

	spin_unlock_irqrestore(&qp->r_lock, r_lock_flags);

	wc.status = (cmpl->access.status == 0) ? IB_WC_SUCCESS
						: IB_WC_GENERAL_ERR;

	if (cmpl->access.flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) {
		wc.opcode = IB_WC_RECV_RDMA_WITH_IMM;
		wc.wc_flags = IB_WC_WITH_IMM;
		wc.ex.imm_data = cmpl->access.user_immdt_be;
	} else {
		wc.opcode = IB_WC_RECV;
	}

	wc.qp = &qp->ibqp;
	wc.src_qp = cmpl->access.qp->remote_qpn;
	wc.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX;
	wc.vendor_err = 0;
	wc.pkey_index = 0;
	wc.dlid_path_bits = 0;
	wc.port_num = 0;
	rvt_recv_cq(qp, &wc, !!(cmpl->access.flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED), RVT_QP_LOCK_STATE_NONE);
}

/*
 * Deliver one verbs cmpl synchronously on the BTS thread.  Producers
 * build the cmpl and pass it straight here; lock-ordering vs qp->s_lock
 * holds because producers drop qp->s_lock before calling us.  Must not
 * pin/unpin, dma_(un)map, kvfree, or allocate with reclaim-permitting
 * GFP - the MR_REG-failure page-set teardown is already queued onto
 * svc->mr_unmap_wq, so nothing sleepable runs here.
 */
void hfi2_bts_deliver_verbs_cmpl(struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_verbs_cmpl *cmpl)
{
	if (WARN_ON(!svc || !cmpl))
		return;

	switch (cmpl->type) {
	case HFI2_BULKSVC_VERBS_CMPL_TYPE_CMD:
		switch (cmpl->cmd.bts_cmd->op) {
		case HFI2_BULKSVC_VERBS_CMD_OP_RDMA:
			bts_rdma_complete(cmpl);
			break;

		/* MR_REG/MR_DEREG page-set teardown happens elsewhere. */
		case HFI2_BULKSVC_VERBS_CMD_OP_MR_REG:
		case HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG:
			break;
		}
		break;
	case HFI2_BULKSVC_VERBS_CMPL_TYPE_ACCESS:
		bts_access_complete(cmpl);
		break;
	}

	hfi2_bulksvc_verbs_cmpl_put(cmpl);
}
