/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * SRIOV support
 */

#ifndef _VF2PF_H
#define _VF2PF_H

#include <linux/if_link.h>

#include "hfi2.h"

#define VF2PF_SI_ALL	(-1)
#define VF2PF_VERSION	1	/* 1-255 */
#define VF2PF_SYNC_RETRIES	5	/* replay attempts after the first */
#define VF2PF_SYNC_RETRY_MS	1000

int vf2pf_early_init(struct hfi2_devdata *dd);
int vf2pf_init(struct hfi2_devdata *dd);
int vf2pf_prep(struct hfi2_devdata *dd);
void vf2pf_deinit(struct hfi2_devdata *dd);
int vf2pf_init_irq(struct hfi2_devdata *dd);
void vf2pf_deinit_irq(struct hfi2_devdata *dd);
int vf2pf_num_ctxts(struct hfi2_devdata *dd);
int vf2pf_num_irq(struct hfi2_devdata *dd);
int vf2pf_probe_si(struct hfi2_devdata *dd);
void vf2pf_init_sysfs(struct hfi2_devdata *dd, struct device *class_dev);
int vf2pf_sysfs_emit_at(struct hfi2_devdata *dd, char *buf, int at);
void vf2pf_set_si_enables(struct hfi2_devdata *dd, int si, u64 *csrs,
			  void (*si_enables)(struct hfi2_devdata *dd,
					     u64 *csrs, u32 start, u32 end));

/*
 * Add vf2pf_* methods here, to request actions from PF0
 */
int vf2pf_get_config(struct hfi2_devdata *dd, struct hfi2_devrsrcs *out, int si);
int vf2pf_get_eth_config(struct hfi2_devdata *dd, u16 vf, struct ifla_vf_info *ivf, u8 *pf_set_mac);
int vf2pf_assign_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *vfr);
int vf2pf_free_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *vfr);
int vf2pf_priv_reg_op(struct hfi2_devdata *dd, int pidx, u32 ctxt, int type,
		      enum preg_op op, u64 arg);
u64 pf0_read_csr(struct hfi2_devdata *dd, enum csr_type type, u32 off,
		 u16 ctxt, u8 pidx_eng);
u64 pf0_rctxt_ctrl_op(struct hfi2_devdata *dd, u16 ctxt, unsigned int op);
void vf2pf_tid_config(struct hfi2_devdata *dd, int pidx, u16 ctxt,
		      u32 eager_base, u16 alloced,
		      u32 expected_base, u32 expected_count);
int vf2pf_init_rxe_rsm(struct hfi2_devdata *dd);
int vf2pf_get_qp_map(struct hfi2_devdata *dd, int pidx, u16 idx, u16 *rcd_idx);
int pf2vf_push_vport_guid(struct hfi2_pportdata *ppd, unsigned long si_mask);
int pf2vf_vport_mad(struct hfi2_pportdata *ppd, u8 si, struct opa_smp *smp);
int pf2vf_push_vport_pkeys(struct hfi2_pportdata *ppd, unsigned long si_mask);
void pf2vf_notify_portcfg(struct hfi2_pportdata *ppd, unsigned long si_mask);
int vf_apply_portcfg(struct hfi2_devdata *dd, u8 pidx);
void vf_apply_portcfg_work(struct work_struct *work);
int vf2pf_send_only_mad(struct hfi2_devdata *dd, u8 sb, const void *mad, int len);
int vf2pf_send_recv_mad(struct hfi2_devdata *dd, u8 sb, const void *mad, int len,
			void *omad, size_t *omad_len, long to);
void vf2pf_ready(struct hfi2_devdata *dd);
int vf2pf_vport_change(struct hfi2_devdata *dd, u8 pidx, u16 flags1,
		       u32 flags2);
int pf2vf_vport_lid_to_si(struct hfi2_pportdata *ppd, u32 lid);
void pf2vf_vport_clear(struct hfi2_devdata *dd, u8 si);
int pf2vf_push_umad(struct hfi2_pportdata *ppd, bool is16B, u8 si,
		    void *payload, int len);
int pf2vf_push_mcast(struct hfi2_pportdata *ppd, struct hfi2_packet *packet);

#endif /* _VF2PF_H */
