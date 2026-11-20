/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * Internal defs for SRIOV support for VFs making requests to PF0.
 */

#ifndef _VF2PF_INT_H
#define _VF2PF_INT_H

#include "vf2pf.h"

/*
 * This selects the loopback port implementation for
 * VF-PF communication in SRIOV.
 */
#define HFI_VF2PF_LOOPBACK

enum {
	VF2PF_OP_PING = 0,
	VF2PF_GET_CFG,
	VF2PF_GET_ETH_CFG,
	VF2PF_ASGN_RES,
	VF2PF_FREE_RES,
	VF2PF_PREG_OP,
	VF2PF_RCSR_OP,
	VF2PF_RCCTRL_OP,
	VF2PF_TIDCFG_OP,
	VF2PF_RXERSM_OP,
	VF2PF_QPMAP_OP,
	VF2PF_STOP,
	VF2PF_MAD_SNDRCV,
	VF2PF_MAD_SND,
	VF2PF_READY,
	VF2PF_VPORT_CHG,
	VF2PF_GET_PORTCFG,
	/* PF0 Ops must start here*/
	PF0_PUSH_UMAD,
	PF0_PUSH_MCAST,
	PF0_VPORT_MAD,
	PF0_VPORT_GUIDS,
	PF0_PORTCFG_CHG,

	VF2PF_OP_LAST		/* must be last */
};
#define VF2PF_OP_RESP   0x80
static_assert(VF2PF_OP_LAST <= VF2PF_OP_RESP, "VF2PF_OP_LAST too large");

#define VF2PF_HDR_VERSION ((VF2PF_VERSION << 8) | VF2PF_OP_LAST)

/*
 * prefix area of 'msg' object to 'send', return from 'msg_alloc'.
 * must be qword multiple (following element aligned u64).
 */
struct vf2pf_prefix {
	u8 type;
	u8 poll_cnt;
	u8 wsi;		/* target SI while on dd->vf2pf_waiters */
	u8 _pad[5];
	union {
		wait_queue_head_t wait;	/* for sending requests */
		struct semaphore sema;	/* for sending MAD requests */
		struct {		/* for recvd requests */
			struct work_struct work;
			struct hfi2_devdata *dd;
			u32 len;
		};
	};
	struct list_head wnode;	/* on dd->vf2pf_waiters while waiting */
};

#define VF2PF_PFX_TYPE_RESP    0
#define VF2PF_PFX_TYPE_WAIT    1
#define VF2PF_PFX_TYPE_SEMA    2

struct vf2pf_hdr {
	u8 op;		/* response is ored with VF2PF_OP_RESP */
	u8 si;		/* sender SI - from */
	u16 len;	/* payload length, bytes (based on op) */
	s16 status;	/* -errno or 0 - valid on response */
	u16 tid;	/* tid for matching resp */
	u32 seq;	/* monotonic sequence number */
	u16 ver;	/* VF2PF header version */
	u16 sz;		/* bytes allocated for this message */
} __packed;

struct vf2pf_ping_msg {
	struct vf2pf_hdr hdr;
	u8 data[256];
};

struct vf2pf_getcfg_msg {
	struct vf2pf_hdr hdr;
	u8 si;
	struct hfi2_devrsrcs rsrcs;
	u64 base_guid;
	u64 revision;
	u8 hfi2_id;
	u8 icode;
	u16 irev;
	u64 cport_ver;
};

struct vf2pf_asgnrs_msg {
	struct vf2pf_hdr hdr;
	struct hfi2_devrsrcs rsrcs;
};

struct vf2pf_pregop_msg {
	struct vf2pf_hdr hdr;
	u64 arg;
	u32 ctxt;
	s32 type;
	u8 op;
	u8 pidx;
};

struct vf2pf_readcsr_msg {
	struct vf2pf_hdr hdr;
	u32 off;
	u64 reg;
};

struct vf2pf_rcctrl_msg {
	struct vf2pf_hdr hdr;
	u16 ctxt;
	int op;
	u64 reg;
};

struct vf2pf_tidcfg_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u16 ctxt;
	u16 alloced;
	u32 egr_base;
	u32 exp_base;
	u32 exp_cnt;
};

struct vf2pf_qpmap_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u16 idx;
	u16 res;
};

struct pf0_pushumad_msg {
	struct vf2pf_hdr hdr;
	u8 is16B;
	u8 pidx;
	u8 _pad[6];
	u8 data[36 + sizeof(struct opa_smp)]; /* largest possible raw size */
};

struct pf0_pushmc_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[5];
	u16 datoff;
	u64 rhf;
	u8 pkt[];
};

struct pf0_vportmad_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[7];
	struct opa_smp smp;
};

struct pf0_vportguids_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[7];
	u64 node_guid;
	u64 port_guid;
};

struct vf2pf_vport_chg_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad;
	u16 flags1;	/* OPA_VPORT_LOCAL_CHG_FLAGS1_* */
	u32 flags2;	/* OPA_VPORT_LOCAL_CHG_FLAGS2_* */
};

struct vf2pf_get_portcfg_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[3];
};

struct vf2pf_portcfg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[3];
	u32 generation;
	u8 sc2vl[OPA_MAX_VLS];
	u8 sl2sc[OPA_MAX_SLS];
	u8 sc2sl[OPA_MAX_SLS];
	u16 mtu[OPA_MAX_VLS];
	u32 ibmtu;
	u32 ibmaxlen;
	u8 vls_operational;
	u8 actual_vls_operational;
	u8 sm_sl;
	u8 subnet_timeout;
	u8 _pad2[4];
	__be64 gid_prefix;
	u16 link_width_active;
	u16 link_speed_active;
	u32 sm_lid;
	u32 lid_block_mask;
	u8 neighbor_type;
	u8 _pad3[3];
	u32 sm_trap_qp;
	u32 _pad4;
};

struct pf0_portcfg_chg_msg {
	struct vf2pf_hdr hdr;
	u8 pidx;
	u8 _pad[3];
	u32 generation;
};

static_assert(sizeof(((struct hfi2_pportdata *)0)->vld[0].mtu) ==
	      sizeof(((struct vf2pf_portcfg *)0)->mtu[0]),
	      "vf2pf per-VL MTU size mismatch");
static_assert(sizeof(struct vf2pf_portcfg) % sizeof(u64) == 0,
	      "vf2pf port configuration must be qword aligned");

/* allocate full size MAD always */
struct vf2pf_mad {
	struct vf2pf_hdr hdr;
	u8 sb;
	u8 _pad[7];
	struct opa_smp mad; /* contains result MAD if requested */
};

struct vf2pf_get_ethcfg_msg {
	struct vf2pf_hdr hdr;
	u16 vf;
	u16 vlan;
	u8 qos;
	u8 spoofchk;
	u8 trusted;
	u8 pf_set_mac;
	u64 mac;
};

#define VF2PF_MAD_OVERHEAD	sizeof(u64)

struct vf2pf_devops {
	int num_ctxts;
	int num_irq;
	int (*init)(struct hfi2_devdata *dd, u8 si);
	void (*deinit)(struct hfi2_devdata *dd, u8 si);
	int (*send)(struct hfi2_devdata *dd, u8 si, void *msg);
	void *(*msg_alloc)(struct hfi2_devdata *dd, struct vf2pf_hdr **msg, u32 len);
	u16 (*set_tid)(struct hfi2_devdata *dd, void *tok);
	void *(*get_tid)(struct hfi2_devdata *dd, u16 tid);
	struct vf2pf_hdr *(*get_msg)(struct hfi2_devdata *dd, void *buf);
	int (*probe_si)(struct hfi2_devdata *dd);
	void (*init_sysfs)(struct hfi2_devdata *dd, struct device *class_dev);
	int (*sysfs_emit_at)(struct hfi2_devdata *dd, char *buf, int at);
	int (*init_irq)(struct hfi2_devdata *dd);
	void (*deinit_irq)(struct hfi2_devdata *dd);
	int (*rcv_wait)(struct hfi2_devdata *dd, void *buf, long timeout);
	void (*set_si_enables)(struct hfi2_devdata *dd, int si, u64 *csrs,
			       void (*si_enables)(struct hfi2_devdata *dd,
						  u64 *csrs, u32 start, u32 end));
};

#define VF2PF_INIT_ALL	((u8)-1)

/* call-outs from implementations to vf2pf main */
void vf2pf_rcv_msg(struct hfi2_devdata *dd, struct vf2pf_hdr *hdr, void *msg);
void vf2pf_rsp_msg(struct hfi2_devdata *dd, void *buf, u32 buf_len);

#endif /* _VF2PF_INT_H */
