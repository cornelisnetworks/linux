// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 */

#include <linux/slab.h>

#include "dms_opfn.h"
#include "verbs.h"
#include "qp.h"
#include "bulksvc.h"

u64 hfi2_dms_opfn_encode(const struct hfi2_dms_opfn_params *p)
{
	return
		(((u64)p->version & DMS_OPFN_VER_MASK) <<
			DMS_OPFN_VER_SHIFT) |
		(((u64)p->flags & DMS_OPFN_FLAGS_MASK) <<
			DMS_OPFN_FLAGS_SHIFT) |
		(((u64)p->lane & HFI2_DMS_LANE_SEL_MASK) <<
			DMS_OPFN_LANE_SHIFT);
}

void hfi2_dms_opfn_decode(u64 val, struct hfi2_dms_opfn_params *p)
{
	p->version = (val >> DMS_OPFN_VER_SHIFT) & DMS_OPFN_VER_MASK;
	p->flags = (val >> DMS_OPFN_FLAGS_SHIFT) & DMS_OPFN_FLAGS_MASK;
	p->lane = (val >> DMS_OPFN_LANE_SHIFT) & HFI2_DMS_LANE_SEL_MASK;
	p->reserved = 0;
}

bool hfi2_dms_opfn_request(struct rvt_qp *qp, u64 *data)
{
	struct hfi2_qp_priv *priv = qp->priv;
	struct hfi2_dms_opfn_params local = {
		.version = DMS_OPFN_VERSION,
		.flags = ibpd_to_rvtpd(qp->ibqp.pd)->user ?
				0 : DMS_OPFN_VER_PD_UNSAFE,
		.lane = priv->bulksvc_qp_info->lane,
	};

	*data = hfi2_dms_opfn_encode(&local);
	return true;
}

/*
 * Install (when @params is non-NULL) or clear (when @params is NULL) the
 * negotiated remote DMS parameters. This is the single writer of
 * priv->dms.remote: it snapshots @params into a fresh allocation, publishes
 * it with rcu_assign_pointer(), and retires the previous value with
 * kfree_rcu() so the lockless BTS admit gate (which only NULL-tests the
 * pointer) stays safe against concurrent readers. Returns false only when the
 * allocation for a non-NULL @params fails, in which case the remote is left
 * cleared (the QP simply stays on the RC path). The caller must hold
 * priv->opfn.lock.
 */
bool hfi2_dms_set_remote(struct rvt_qp *qp,
			 const struct hfi2_dms_opfn_params *params)
{
	struct hfi2_qp_priv *priv = qp->priv;
	struct hfi2_dms_opfn_params *remote, *old;
	bool ret = true;

	old = rcu_dereference_protected(priv->dms.remote,
					lockdep_is_held(&priv->opfn.lock));
	if (!params) {
		RCU_INIT_POINTER(priv->dms.remote, NULL);
		goto free;
	}

	remote = kzalloc(sizeof(*remote), GFP_ATOMIC);
	if (!remote) {
		RCU_INIT_POINTER(priv->dms.remote, NULL);
		ret = false;
		goto free;
	}

	remote->version = params->version;
	remote->flags = params->flags;
	remote->lane = params->lane;
	remote->reserved = params->reserved;
	rcu_assign_pointer(priv->dms.remote, remote);

free:
	if (old)
		kfree_rcu(old, rcu);
	return ret;
}

bool hfi2_dms_opfn_reply(struct rvt_qp *qp, u64 data)
{
	struct hfi2_qp_priv *priv = qp->priv;
	struct hfi2_dms_opfn_params remote;

	data &= ~0xfULL;
	if (!data) {
		/*
		 * Empty payload means the peer does not support DMS. Return
		 * true (negotiation complete) with remote NULL so the OPFN
		 * completed bit is set and re-negotiation does not retry;
		 * BTS offload stays off and RC is used. Mirrors
		 * tid_rdma_conn_reply.
		 */
		(void)hfi2_dms_set_remote(qp, NULL);
		return true;
	}

	hfi2_dms_opfn_decode(data, &remote);
	/*
	 * Only bulksvc hosts request DMS, but any host parses the reply.  The
	 * rcu_assign_pointer() in set_remote() orders peer_lane before the
	 * transfers it admits.
	 */
	if (priv->bulksvc_qp_info)
		WRITE_ONCE(priv->bulksvc_qp_info->peer_lane, remote.lane);
	return hfi2_dms_set_remote(qp, &remote);
}

bool hfi2_dms_opfn_response(struct rvt_qp *qp, u64 *data)
{
	struct hfi2_ibdev *dev = to_idev(qp->ibqp.device);
	struct hfi2_devdata *dd = dd_from_dev(dev);
	bool ret;

	ret = hfi2_dms_opfn_reply(qp, *data);
	*data = 0;
	if (ret && dd->bulksvc)
		(void)hfi2_dms_opfn_request(qp, data);
	return ret;
}

void hfi2_dms_opfn_error(struct rvt_qp *qp)
{
	struct hfi2_devdata *dd = dd_from_dev(to_idev(qp->ibqp.device));

	(void)hfi2_dms_set_remote(qp, NULL);
	/*
	 * hfi2_opfn_conn_error() invokes this for every set completed bit on RC QP
	 * reset, which includes normal QP teardown -- not just genuine
	 * negotiation errors. Log at debug level so routine teardown does not
	 * flood the kernel log with misleading "failed" warnings.
	 */
	dd_dev_dbg(dd, "DMS OPFN connection cleared on QP %u\n",
		   qp->ibqp.qp_num);
}

bool hfi2_opfn_dms_negotiated(struct rvt_qp *qp)
{
	struct hfi2_qp_priv *priv = qp->priv;

	return !!(READ_ONCE(priv->opfn.completed) & OPFN_MASK(DMS));
}
