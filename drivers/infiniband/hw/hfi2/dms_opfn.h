/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 */
#ifndef HFI2_DMS_OPFN_H
#define HFI2_DMS_OPFN_H

/*
 * DMS OPFN capability negotiation.
 *
 * OPFN wire word: bits[3:0] = capcode, bits[63:4] = 60-bit payload.
 * DMS v1 payload: bits[7:4] = version, bits[15:8] = flags.
 * bits[18:16] = DMS lane of the advertising QP, which its peer targets.
 *
 * RCU pointer pattern mirrors tid_rdma_qp_params (tid_rdma.h:74-78).
 */

#include <linux/build_bug.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include "rvt_qp.h"

/* Payload bit positions within bits[63:4] (capcode stripped) */
#define DMS_OPFN_VER_SHIFT	4
#define DMS_OPFN_VER_MASK	0xfU
#define DMS_OPFN_FLAGS_SHIFT	8
#define DMS_OPFN_FLAGS_MASK	0xffU
#define DMS_OPFN_LANE_SHIFT	16

/*
 * DMS OPFN capability flags (payload bits[15:8]).
 *
 * DMS_OPFN_VER_PD_UNSAFE: advertising QP is a kernel PD, unsafe as a SEND
 * landing target (may post lkey-0 recv buffers DMS cannot resolve).
 */
#define DMS_OPFN_VER_PD_UNSAFE	(1U << 0)

/* Current DMS OPFN protocol version. v2 adds the flags byte semantics. */
#define DMS_OPFN_VERSION	2

/*
 * First version whose flags byte carries DMS_OPFN_VER_PD_UNSAFE. Distinct from
 * DMS_OPFN_VERSION so later bumps do not disable the SEND PD-safety gate. It
 * must never exceed the advertised version or the gate can never engage.
 */
#define DMS_OPFN_VER_PD_FLAG	2
static_assert(DMS_OPFN_VER_PD_FLAG <= DMS_OPFN_VERSION,
	      "PD-flag version must not exceed the advertised OPFN version");

struct hfi2_dms_opfn_params {
	struct rcu_head rcu;
	u8  version;
	u8  flags;
	u8  lane;
	u16 reserved;
};

struct hfi2_dms_qp_params {
	struct hfi2_dms_opfn_params        local;
	struct hfi2_dms_opfn_params __rcu *remote;
};

u64 hfi2_dms_opfn_encode(const struct hfi2_dms_opfn_params *p);
void hfi2_dms_opfn_decode(u64 val, struct hfi2_dms_opfn_params *p);
bool hfi2_dms_opfn_request(struct rvt_qp *qp, u64 *data);
bool hfi2_dms_opfn_response(struct rvt_qp *qp, u64 *data);
bool hfi2_dms_opfn_reply(struct rvt_qp *qp, u64 data);
void hfi2_dms_opfn_error(struct rvt_qp *qp);
bool hfi2_dms_set_remote(struct rvt_qp *qp,
			 const struct hfi2_dms_opfn_params *params);
bool hfi2_opfn_dms_negotiated(struct rvt_qp *qp);

#endif /* HFI2_DMS_OPFN_H */
