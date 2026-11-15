/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * DMS_RoCE: the RoCEv2 software backend used by bulksvc in CN6000 Ethernet
 * mode.  It implements the Stage 1.5 RC SEND, plain-WRITE, and READ wire
 * paths, reliability, ingress validation, and PIO retry.  RKEY/RIF direct
 * placement remains Stage 2.
 *
 * Threading: driver_f send callbacks enqueue a QP; the bulksvc event worker
 * exclusively owns RX, private PIO, and transport-state mutation. The runq
 * lock protects membership only, including one QP reference per member.
 */
#ifndef _HFI2_DMS_ROCE_H
#define _HFI2_DMS_ROCE_H

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/cache.h>
#include <linux/completion.h>
#include <linux/if_ether.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include <rdma/ib_verbs.h>
#include "rvt_mr.h"

#include "roce_pasid.h"

#ifndef HFI2_DMS_ROCE_INJECT
#define HFI2_DMS_ROCE_INJECT 0
#endif

#include "chip.h"
#include "dms.h"
#include "eth_hwi.h"

struct seq_file;
struct task_struct;
struct eal_ingress_header;
struct hfi2_devdata;
struct hfi2_bulksvc;
struct hfi2_bulksvc_verbs_source;
struct hfi2_bulksvc_verbs_source_segment;
struct hfi2_dms_page;
struct hfi2_roce_pasid;
struct hfi2_roce_pasid_bind;
struct iommu_domain;
struct scatterlist;
struct hfi2_dms;
struct hfi2_ctxtdata;
struct hfi2_dms_roce;
struct hfi2_dms_roce_qp;
struct send_context;
struct rvt_qp;
struct rvt_swqe;

#define HFI2_DMS_ROCE_RCD_COUNT 2
#define HFI2_DMS_ROCE_RX_HELPER_MAX 8
#define HFI2_DMS_ROCE_RX_HELPER_RING_SIZE 4096
#define HFI2_DMS_ROCE_RX_HELPER_RING_MASK \
	(HFI2_DMS_ROCE_RX_HELPER_RING_SIZE - 1)
#define HFI2_DMS_ROCE_RX_USRHEAD_FIFO_SIZE 256
#define HFI2_DMS_ROCE_RX_DEP_BITS 14
#define HFI2_DMS_ROCE_RX_CLAIM_BATCH 4
/* A wait this long means the helpers are not running; see drain_to(). */
#define HFI2_DMS_ROCE_RX_HELPER_STALL_NS NSEC_PER_MSEC
#define HFI2_DMS_ROCE_RIF_ARM_SCAN_SLOW_NS (20 * NSEC_PER_USEC)
#define HFI2_DMS_ROCE_TOMBSTONES 1024
#define HFI2_DMS_ROCE_NETDEV_RX_QUEUE_LEN 1024
#define HFI2_DMS_ROCE_NETDEV_RX_BUDGET 256

/*
 * The RX worker fills every field but @done_seq; the helper that claims the
 * entry writes @done_seq once the copy is in memory.  Cacheline alignment
 * keeps two helpers finishing neighbouring entries from sharing a line.
 */
struct hfi2_dms_roce_rx_copy_desc {
	const void *src;
	struct rvt_mregion *mr;
	/* Sequence that must be copied first (same destination), 0 for none. */
	u64 dep;
	u64 done_seq;
	union {
		void *kaddr;
		struct rvt_seg dmabuf_do;
	} dst;
	u32 len;
	int err;
	bool dmabuf_do;
} ____cacheline_aligned_in_smp;

/*
 * Single-producer, multi-consumer copy queue.  Entries are numbered from 1;
 * entry @seq lives in ring[@seq & mask].  The worker fills entries up to
 * @submitted and publishes @head; helpers claim entries in sequence order by
 * advancing @claim, copy them, and stamp @done_seq; the worker retires the
 * done prefix in order (@retired), dropping the MR holds.  A fence is just a
 * value of @submitted: it is satisfied once @retired reaches it.
 */
struct hfi2_dms_roce_rx_queue {
	struct hfi2_dms_roce_rx_copy_desc *ring;
	/* Last entry each destination page hash slot was given; worker only. */
	u64 *dep_tbl;
	u64 submitted ____cacheline_aligned_in_smp;
	u64 retired;
	/* Published producer index, polled by idle helpers. */
	u64 head ____cacheline_aligned_in_smp;
	/*
	 * Set while the worker is in a receive pass and will publish more
	 * entries without waiting on the helpers; cleared before any wait.
	 */
	u32 filling;
	/* Last entry claimed by any helper. */
	atomic64_t claim ____cacheline_aligned_in_smp;
	/* Helpers asleep; read by the worker's kick. */
	atomic_t sleepers ____cacheline_aligned_in_smp;
};

/* Per-helper thread and statistics; only the helper writes the counters. */
struct hfi2_dms_roce_rx_helper {
	struct hfi2_dms_roce_rx_queue *q;
	struct task_struct *task;
	int cpu;
	u32 count;
	u64 copies;
	u64 bytes;
	u64 verify_bad;
	u64 wakeups;
	u64 dep_waits;
} ____cacheline_aligned_in_smp;

struct hfi2_dms_roce_rx_usrhead {
	u32 rhqoff;
	u32 etail;
	u64 fence;
	u8 updegr;
	u32 npkts;
};

/*
 * rx_rcd_state packs (consumed << 32 | head), head in the low half like
 * rcd->head itself; see hfi2_dms_roce_rx_mark().
 */
static inline u64 roce_rx_state_pack(u32 consumed, u32 head)
{
	return ((u64)consumed << 32) | head;
}

static inline u32 roce_rx_state_consumed(u64 state)
{
	return state >> 32;
}

static inline u32 roce_rx_state_head(u64 state)
{
	return (u32)state;
}

struct hfi2_dms_roce_rx_mark {
	u32 target[HFI2_DMS_ROCE_RCD_COUNT];
	bool valid[HFI2_DMS_ROCE_RCD_COUNT];
};

/*
 * Plain TX counters belong to the worker; posting CPUs use atomics.
 * Allocator telemetry is protected by sc->alloc_lock.
 */
struct hfi2_dms_roce_stats {
	u64 tx_pkts;     /* frames handed to PIO */
	u64 tx_bytes;    /* payload bytes transmitted */
	u64 tx_pio_fail; /* PIO buffer alloc / ctx-down failures */
	u64 tx_pio_refresh;     /* successful hardware-free counter reads */
	u64 tx_pio_eagain;      /* credit refreshes still short of one frame */
	u64 tx_pio_resync;      /* fill/free reset after the context restarted */
	u64 tx_pio_outstanding_high; /* maximum outstanding 64-byte blocks */
	u64 tx_header_ns;       /* SEND/WRITE header construction time */
	u64 tx_payload_copy_ns; /* SEND/WRITE payload copy or gather time */
	u64 tx_pio_write_ns;    /* PBC/header/pad MMIO write time */
	u64 tx_pio_fence_ns;    /* MMIO publication fence time */
	u64 tx_pio_fences;      /* MMIO publication fences issued */
	u64 tx_pio_credit_returns; /* packets requesting forced credit return */
	u64 tx_worker_turns;    /* QP send-engine turns entered */
	u64 tx_turn_next_wqe;   /* turns that went on to the QP's next WQE */
	u64 tx_resp_yield;      /* send turns granted while a response was pending */
	u64 tx_worker_iters;    /* send-engine loop iterations across turns */
	u64 tx_sdma_arm_try;    /* bundle emissions attempted by the SDMA arm */
	u64 tx_sdma_inline;     /* one-packet requests copied into the command page */
	u64 tx_sdma_middle_cached; /* MIDDLE command pages copied from the request image */
	u64 tx_read_resp_middle_cached; /* response MIDDLE pages copied from the image */
	u64 tx_sdma_copy_fallback;
	u64 tx_dmabuf_copy;
	u64 rx_dmabuf_copy;
	u64 rx_helper_dmabuf;
	u64 rx_helper_dmabuf_err;
	u64 atomic_dmabuf_nak;
	u64 tx_vlan_tagged;     /* frames sent with any 802.1Q header */
	u64 tx_runt_tagged;     /* runt frames sent with a priority tag */
	u64 tx_pfc_tagged;      /* frames sent with a PFC priority tag */
	u64 rx_hwp_read_resp_drop;
	u64 tx_sdma_read_req;   /* READ REQUESTs emitted by the SDMA arm */
	u64 tx_atomic_req;
	u64 tx_atomic_ack;
	u64 tx_order_gate_atomic;
	u64 tx_order_gate_inv;
	u64 tx_sdma_read_req_decline; /* READ SDMA attempts that did not emit */
	u64 tx_sdma_read_req_hold_wait; /* READ deferred behind an undrained bundle */
	u64 tx_sdma_read_req_error; /* READ bundles that failed in SDMA */
	u64 tx_sdma_ack;        /* responder ACK/NAKs emitted through SDMA */
	u64 tx_sdma_ack_stall;  /* responder ACK/NAKs deferred for SDMA capacity */
	u64 tx_sdma_resp_error; /* responder SDMA bundles that failed */
	u64 tx_sdma_read_resp;  /* READ reply packets emitted through SDMA */
	u64 tx_sdma_read_resp_stall; /* READ reply SDMA attempts deferred */
	u64 tx_sdma_resp_abandon; /* responder xfers released for restart/reset */
	u64 tx_ack_behind_resp; /* ACK/NAK held behind an owed READ reply */
	u64 rx_read_resp_slast_lag; /* READ completed at s_acked while s_last lagged */
	u64 rx_read_resp_implicit_ack; /* requests retired by a READ reply */
	u64 rx_read_resp_stale; /* READ reply older than every request */
	u64 rx_read_resp_restart; /* READs restarted for a response gap */
	u64 rx_read_resp_seq_drop; /* out-of-sequence responses behind a latched gap */
	u64 rx_read_resp_skip_resend; /* READ completed while s_cur was resending it */
	u64 tx_read_resp_alias;
	u64 tx_read_resp_alias_skip;
	u64 tx_hwp_read_resp_bug;
	u64 tx_read_as_write;
	u64 hwp_rd_sw_multi_sge;
	u64 hwp_rd_sw_no_pasid;
	u64 hwp_rd_sw_mr_too_big;
	u64 hwp_rd_sw_no_ikey;
	u64 hwp_rd_sw_misaligned;
	u64 hwp_rd_sw_other;
	u64 hwp_rd_win_reads;
	u64 hwp_rd_win_bytes;
	u64 hwp_rd_win_busy;
	u64 hwp_rd_win_map_err;
	u64 hwp_rd_win_misaligned;
	u64 hwp_rd_win_too_big;
	u64 hwp_rd_win_rotations;
	u64 hwp_rd_win_busy_active;
	u64 hwp_rd_win_busy_quarantine;
	u64 hwp_rd_win_busy_exhausted;
	u64 hwp_rd_win_key_err;
	u64 hwp_rd_win_phys_err;
	u64 hwp_rd_win_iommu_err;
	u64 hwp_rd_win_iommu_nomem;
	u64 hwp_rd_win_iommu_exists;
	u64 hwp_rd_win_install_full;
	u64 hwp_rd_win_install_err;
	u64 hwp_rd_win_donor_serialize;
	u64 hwp_rd_win_donor_reg_mr;
	/* Donor completions run outside the bulksvc lane. */
	atomic64_t hwp_rd_win_donor_queued;
	atomic64_t hwp_rd_win_donor_ready;
	atomic64_t hwp_rd_win_donor_cancelled;
	atomic64_t hwp_rd_win_donor_map_err;
	atomic64_t hwp_rd_win_donor_zapped;
	atomic64_t hwp_rd_win_donor_zap_err;
	/* Failed READ placement drain attempts; the work runs off the lane. */
	atomic64_t hwp_cleanup_drain_err;
	u64 hwp_pool_enabled;
	u64 tx_read_as_write_pkts;
	u64 rx_read_as_write;
	u64 rx_read_as_write_placed;
	u64 rx_read_as_write_fallback_drop;
	u64 rif_read_alias_invalidate;
	u64 rx_internal_key_on_base;
	u64 internal_rkey_install;
	u64 internal_rkey_install_fail;
	atomic64_t internal_rkey_exhausted;
	u64 reserved_read_resp_alias[4];
	u64 rx_alias_bad_opcode;
	u64 rx_answer_on_base;
	u64 reserved_rif_arm_alias;
	u64 tx_worker_packets;  /* packets completed across worker turns */
	u64 tx_send_wqe;        /* SEND WQEs drained from the SQ */
	u64 tx_ud_pkts;         /* UD/GSI frames emitted */
	u64 tx_ud_sdma;         /* UD/GSI frames transmitted via SDMA */
	u64 tx_acks;            /* AETH ACK frames emitted (responder) */
	u64 tx_ack_deferred;    /* ACK/NAK held for retry after a PIO refusal */
	u64 tx_ack_dropped;     /* held ACK/NAK displaced by a newer one */
	u64 tx_send_state_drop; /* send engine ran with work pending - a pending
				 * response or an unsent WQE - but QP state,
				 * address validity or RVT_S_BUSY gated it
				 */
	u64 tx_flush_wqe;       /* send WQEs retired by the QP-ERROR flush */
	u64 rx_rcd_packets[HFI2_DMS_ROCE_RCD_COUNT];
	u64 rx_rcd_empty_polls[HFI2_DMS_ROCE_RCD_COUNT];
	u64 rx_rcd_budget_limited[HFI2_DMS_ROCE_RCD_COUNT];
	u64 qp_rcd_bindings[HFI2_DMS_ROCE_RCD_COUNT];
	u64 rx_wrong_rcd;       /* QP arrived on an RCD other than its immutable binding */
	u64 rx_rhe_drop;        /* bypass frames rejected by the RHE gate */
	u64 rx_rhe_last_reason; /* most recent RHE reason word */
	u64 rx_bypass;          /* bypass frames handed to DMS_RoCE */
	atomic64_t rx_netdev_diverted;
	atomic64_t rx_netdev_dropped;
	u64 rx_test_drop;       /* parsed RX frames dropped by test injection */
	u64 rx_vrma_protocol_error; /* reports that errored the QP */
	u64 rx_parse_err;       /* frames rejected by the wire parser */
	u64 rx_no_qp;           /* DestQPN with no matching RoCE QP */
	u64 rx_ud_pkts;         /* UD/GSI frames delivered */
	u64 rx_ud_drop;         /* UD/GSI frames with unsupported opcode */
	u64 rx_ud_qkey_drop;    /* UD/GSI frames with mismatched Q_Key */
	u64 rx_ud_no_rwqe;      /* UD/GSI frames without a receive WQE */
	u64 rx_ud_too_long;     /* UD/GSI frames exceeding the receive WQE */
	u64 rx_no_backend;      /* RoCE QP bound before the backend existed */
	u64 rx_bad_pkey;        /* BTH P_Key rejected for the selected QP */
	u64 rx_pkey_drop;       /* BTH P_Key rejected before QP lookup */
	u64 rx_qp_state_drop;   /* frame rejected because the QP cannot receive */
	u64 rx_invalid_av;      /* frame rejected before the QP AV is resolved */
	u64 rx_bad_peer;        /* source/destination IP rejected for the selected QP */
	u64 rx_unhandled_opcode; /* parsed valid-QP frames rejected by opcode dispatch */
	u64 rx_send;            /* inbound SEND packets processed */
	u64 rx_send_psn_drop;   /* SEND dropped: PSN != r_psn (per packet) */
	u64 rx_send_rnr;        /* SEND rejected: no receive WQE */
	u64 rx_send_nak_seq;    /* PSN-sequence NAKs emitted for SEND */
	u64 rx_send_inv;        /* SEND_WITH_INV rkeys invalidated */
	u64 rx_send_inv_fail;   /* SEND_WITH_INV rkey invalidation failures */
	u64 rx_write_psn_drop;  /* WRITE dropped: PSN != r_psn (per packet) */
	u64 rx_write_nak_seq;   /* PSN-sequence NAK episodes for WRITE */
	u64 rx_write_gap_retry;
	/*
	 * Malformed-burst rejections, one counter per invariant.  Counted at
	 * the rejection site rather than beside the NAK: roce_send_ack() only
	 * counts tx_acks when the PIO succeeds, so a rejection whose NAK could
	 * not be transmitted would otherwise be indistinguishable from no
	 * rejection at all.
	 */
	u64 rx_burst_first_live;      /* FIRST while a fragmented op is live */
	u64 rx_burst_orphan;          /* MIDDLE/LAST with no preceding FIRST */
	u64 rx_burst_short_middle;    /* MIDDLE payload is not exactly PMTU */
	u64 rx_burst_overlong;        /* fragment overruns the latched length */
	u64 rx_burst_middle_completes; /* MIDDLE would complete the length */
	u64 rx_burst_last_mismatch;   /* LAST misses the latched length */
	u64 rx_read_state_drop; /* READ dropped: responder QP not receive-ready */
	u64 rx_read_dup_drop;   /* READ dropped: stale duplicate, no response owed */
	u64 rx_atomic_req;
	u64 rx_atomic_dup;
	u64 rx_atomic_ack;
	u64 rx_recv_cqe;        /* IB_WC_RECV completions posted */
	u64 rx_write_imm_cqe;   /* IB_WC_RECV_RDMA_WITH_IMM completions posted */
	u64 rx_write_imm_rnr;   /* WRITE with immediate refused: no receive WQE */
	u64 rx_helper_copies[HFI2_DMS_ROCE_RX_HELPER_MAX];
	u64 rx_helper_bytes[HFI2_DMS_ROCE_RX_HELPER_MAX];
	u64 rx_helper_cpu_small;
	u64 rx_helper_cpu_nonkernel;
	u64 rx_helper_cpu_skb;  /* copied inline: source is a diverted SKB */
	u64 rx_helper_full_waits;
	u64 rx_helper_drains;
	u64 rx_helper_stalls;   /* waits that took over from stalled helpers */
	u64 rx_helper_ack_drains; /* ACK/NAK held until helper copies landed */
	u64 rx_helper_usrhead_deferred;
	u64 rx_helper_usrhead_spin;
	u64 rx_helper_verify_bad;
	u64 rx_helper_wakeups;
	u64 rx_helper_deps;
	u64 rx_helper_dep_waits;
	u64 rx_qp_lock_holds;
	u64 rx_ack;             /* inbound ACK/NAK packets processed */
	u64 rx_ack_completed;   /* send WQEs retired by ACK/NAK PSN */
	u64 rx_ack_nak_seq;     /* requester PSN-sequence NAKs consumed */
	u64 rx_ack_rnr;         /* requester RNR NAKs consumed */
	u64 rx_ack_fatal;       /* requester class-B fatal NAKs consumed */
	u64 retry_restart;      /* retry-timer restarts */
	u64 retry_rx_defer;     /* restarts deferred behind unread RX reports */
	u64 retry_exhausted;    /* QPs errored after retries exhausted */
	u64 retry_rnr_exhausted; /* QPs errored after RNR retries exhausted */
	u64 stride_mismatch;    /* QPs declined: path MTU differs from the latched stride */
	u64 stride_unsupported; /* QPs declined: path MTU has no rocev2_mtu encoding */
	/*
	 * A write to a bucket this function does not own is silently ignored,
	 * so an arm that never landed is indistinguishable from an arm never
	 * attempted unless both are counted separately.
	 */
	u64 rif_arm;            /* RIF entries written */
	u64 rif_arm_hw_busy;    /* valid hardware-owned buckets skipped by arm */
	u64 rif_arm_read_err;   /* arms aborted after an unreadable RIF bucket */
	u64 rif_arm_hw_scan_reads; /* config-bus qword reads under rif_mutex */
	u64 rif_arm_scan_slow;  /* IRQ-off arm scans exceeding 20 us */
	u64 rif_arm_scan_wall_slow; /* wall-clock arm scans exceeding 20 us */
	u64 rif_arm_deferred;   /* arms staged for the bulksvc continuation */
	u64 rif_arm_pending;    /* callers waiting for a staged arm */
	u64 rif_arm_cancelled;  /* staged arms cancelled before continuation */
	u64 rif_arm_ack_held;   /* ACK/NAK attempts held for this QP's arm */
	u64 reserved_rif_arm_read_held;
	u64 rif_arm_ack_inline; /* held ACK/NAK sent at arm publication */
	u64 rif_arm_completed; /* continuations, including failure/cancellation */
	u64 rif_arm_latency_ns; /* total stage-to-publication time */
	u64 rif_arm_latency_max_ns;
	u64 rif_arm_latency_slow; /* continuations taking more than 20 us */
	/*
	 * Arm and invalidate refuse malformed input for different reasons and
	 * mean different things, so they count separately.  Sharing one
	 * counter made a non-zero value unattributable: a reject beside
	 * rif_arm == 0 could be a malformed arm that never reached hardware,
	 * or a malformed invalidate, which has nothing to do with arming.
	 * Observed for real on opx-gen-008 before this was split.
	 */
	u64 rif_arm_reject;     /* arms refused before any CSR write */
	u64 rif_invalidate_reject; /* invalidates refused before any CSR write */
	/*
	 * The RIF comparand is {VF, QP} and carries no bucket, so two armed
	 * entries for one QP are an ambiguous match rather than two usable
	 * entries.  Refusing the second is a decline, not an error.
	 */
	u64 rif_arm_exclusive;  /* arms refused: the QP already holds an entry */
	u64 rif_row_full;       /* arms refused: no free bucket in the QP's row */
	/*
	 * Two distinguishable ways the PASID trust edge refuses an arm.  They
	 * are separate counters because they mean different things: a mismatch
	 * is a software defect that would have placed into a foreign address
	 * space, while a dead mm is an ordinary race with process exit.  A
	 * shared counter would make the defect indistinguishable from the race
	 * - the same mistake rif_arm_reject once made with invalidate.
	 */
	u64 rif_arm_pasid_mismatch; /* arms refused: entry PASID != bound PASID */
	u64 rif_arm_dead_mm;    /* arms refused: the address space is gone */
	/*
	 * R_Key installs.  Every decline is its own counter for the same reason
	 * the RIF declines are: they mean different things and a shared counter
	 * makes a defect indistinguishable from a capacity limit.
	 */
	u64 rkey_install;       /* R_Key entries written */
	u64 rkey_install_reject; /* installs refused: malformed entry */
	u64 rkey_row_full;      /* installs refused: no free bucket in the row */
	u64 rkey_too_long;      /* installs refused: region exceeds the 24-bit
				 * length field (gate H15).  A distinct counter
				 * because this one is a hard hardware ceiling
				 * rather than pressure - it will never clear by
				 * waiting, and clamping it would place short.
				 */
	u64 rkey_pasid_mismatch; /* installs refused: entry PASID != bound PASID */
	u64 rkey_dead_mm;       /* installs refused: the address space is gone */
	u64 rkey_invalidate;    /* R_Key entries cleared */
	u64 rkey_invalidate_reject; /* invalidates refused: unknown or unowned */
	/*
	 * MR eligibility, decided once at registration.  Two counters rather
	 * than one because the two declines are permanent for different
	 * reasons and a reader needs to tell them apart: a kernel MR has no
	 * placement mechanism at all on this hardware, while an oversized user
	 * MR has one it cannot address.  Neither will ever become eligible by
	 * waiting, which is what distinguishes both from the pressure counters
	 * above.
	 */
	u64 mr_eligible;        /* MRs that may be hardware-placed */
	u64 mr_ineligible_sw_rx; /* MRs declined: roce_by_software, no hw placement */
	u64 mr_ineligible_kernel; /* MRs declined: no umem, so no address space */
	u64 mr_ineligible_length; /* MRs declined: beyond the 24-bit R_Key length */
	u64 kmr_pasid_mapped;   /* kernel FastReg MRs mapped to a PASID domain */
	u64 kmr_pasid_skip_iova; /* translated kernel FastReg MRs without hardware-FIRST */
	u64 kmr_pasid_err;      /* kernel FastReg PASID-domain allocation/map failures */
	atomic64_t kmr_donor_mapped;
	atomic64_t kmr_donor_skip_iova;
	atomic64_t kmr_donor_skip_pool;
	atomic64_t kmr_donor_err;
	atomic64_t kmr_donor_dmabuf_mapped;
	atomic64_t kmr_donor_dmabuf_busy;
	atomic64_t kmr_donor_dmabuf_err;
	atomic64_t kmr_donor_flushes;
	atomic64_t kmr_donor_windows_free;
	/*
	 * An eligible MR that no peer may touch.  Separate from the
	 * ineligible counters because the MR is perfectly placeable - it
	 * simply has no remote access flags, so an R_Key entry for it could
	 * only ever fail validation while occupying a way in a 16-way row.
	 * Counted so mr_eligible minus rkey_install is always attributable;
	 * an unexplained gap between them is the shape a real install bug
	 * would take.
	 */
	u64 rkey_no_remote_access;
	u64 rif_invalidate;     /* RIF entries cleared */
	u64 rif_invalidate_read_err; /* invalidates skipped: RIF recheck unreadable */
	u64 rif_readback_fail;  /* armed entries that did not read back */
	/*
	 * Ingress classification.  The Type 0 and Type 1 header overlays share
	 * every field position and differ only in meaning, so Type is read
	 * first and the RoCEv2 accessors are used only when it says RoCEv2.
	 */
	u64 rx_type_not_roce;   /* ingress Type is not RoCEv2 */
	u64 rx_l4_eth;          /* L4 0x78, on-load delivery */
	u64 rx_l4_excptn;       /* L4 0x79, exception report */
	u64 rx_l4_vrma;         /* L4 0x7A, VRMA placement report */
	u64 rx_l4_tid;          /* L4 0x7C, TID placement report */
	u64 rx_l4_unknown;      /* L4 outside the documented set */
	/* End_state is an enumeration; every other value is reserved. */
	u64 rx_end_state_ok;
	u64 rx_end_state_first_err;
	u64 rx_end_state_middle_oo;
	u64 rx_end_state_middle_no_qp;
	u64 rx_end_state_last_err;
	u64 rx_end_state_reserved;
	u64 rx_vrma_reports;   /* Type-5 placement reports consumed */
	u64 rx_vrma_placed_packets; /* reports whose payload hardware placed */
	u64 rx_vrma_placed_bytes; /* payload bytes placed by hardware */
	u64 rx_vrma_trimmed;   /* reports whose payload hardware discarded */
	u64 rx_vrma_zero_write; /* zero-length WRITE ONLYs acknowledged */
	u64 rx_vrma_bad_opcode; /* placement reports with unsupported opcode */
	u64 reserved_rrsp_placement[12];
	u64 read_write_bad_report; /* private WRITE reply placement rejected */
	u64 rx_rrsp_first_diverted;
	u64 rrsp_first_retry;
	u64 rrsp_first_giveup;
	u64 reserved_rrsp_state[3];
	u64 reserved_h33_park[3];
	u64 h15_arm_ok;        /* software-armed RIF entries for an oversized MR */
	u64 h15_arm_fail;      /* arm declined: no free bucket or PASID mismatch */
	u64 h15_stale_first;   /* FIRSTs that found an armed entry left over */
	u64 rif_release;       /* software-armed entries retired */
	u64 rif_release_foreign; /* retire skipped: bucket now another QP's */
	u64 rx_vrma_overrun;   /* reports placed past the WRITE's RETH length */
	u64 h15_nak;           /* post-arm NAKs sent to replay a burst */
	u64 h15_straggler_drop; /* pre-arm software-path WRITE packets dropped */
	u64 h15_arm_reclaim;   /* arms that found a bucket after a row reclaim */
	u64 h15_arm_nak;       /* FIRSTs NAKed because no bucket could be armed */
	/* roce_last_by_software (EAL_ROCEV2_CFG bit 2) */
	u64 rx_lbs_adopt;       /* hardware-placed FIRSTs taken over by software */
	u64 rx_lbs_adopt_skip;  /* FIRST reports not adopted: PSN or state */
	u64 rx_lbs_hdr_short;   /* FIRST report too short to carry the RETH */
	u64 rx_lbs_rkey_err;    /* adopted RETH failed the R_Key check */
	u64 rx_lbs_middle;      /* MIDDLE reports credited to an adopted burst */
	u64 rx_lbs_last;        /* software LASTs completing an adopted burst */
	u64 rx_lbs_trim;        /* trimmed reports while the QP held an entry */
	u64 rx_lbs_adopt_dup;   /* replayed FIRST adopted as the burst in progress */
	u64 rx_lbs_dup_report;  /* replayed packets placed behind r_psn */
	u64 tx_replay_resume;   /* replays resumed mid-WRITE at the NAKed PSN */
	u64 rx_lbs_orphan;      /* placed report with no burst: dropped, NAKed */
	u64 rif_lbs_inval;      /* hardware-created entries invalidated */
	u64 rif_lbs_early;      /* ... before the LAST, at the final MIDDLE */
	u64 rif_lbs_cache_hit;  /* found at the remembered bucket */
	u64 rif_lbs_scan;       /* row scans */
	u64 rif_lbs_scan_miss;  /* row scans that found no entry for the QP */
	u64 rif_lbs_multi;      /* row scans that found more than one */
	/*
	 * roce_rif_reclaim: an eligible WRITE FIRST hardware diverted with
	 * end_state 0x01 (row full, or a stale entry of this QP), and what the
	 * row scan freed so the requester's resend takes the hardware path.
	 */
	u64 rx_first_diverted;  /* diverted FIRSTs considered for reclaim */
	u64 rx_first_reclaim_nak; /* ... NAKed at their own PSN after a reclaim */
	u64 rif_reclaim_scan;   /* row scans */
	u64 rif_reclaim_none;   /* scans that freed nothing */
	u64 rif_reclaim_giveup; /* fatal exhaustion of the FIRST retry budget */
	u64 rif_reclaim_live;   /* valid entries left alone as live */
	u64 reserved_rif_reclaim_rrsp;
	u64 rif_reclaim_own;    /* freed: this QP's own leftover entry */
	u64 rif_reclaim_dead;   /* freed: owner gone or not receiving */
	u64 rif_reclaim_recovering; /* freed: RECOVERING, never heals */
	u64 rif_reclaim_idle;   /* freed: IDLE the owner does not track */
	u64 rif_reclaim_unlatched; /* freed: INITIALIZING, owner not in a burst */
	u64 rif_reclaim_finished; /* freed: RUNNING, owner past end_psn */
	/*
	 * A placement report that software could not credit because its burst
	 * accounting was not active.  rx_vrma_length_error covers three
	 * distinct causes and both of its siblings are guarded on
	 * vrma_write_active, so an inactive burst is indistinguishable from a
	 * genuine length violation without this.
	 */
	u64 rx_vrma_no_burst;
	u64 reserved_h33_interlocks[8];
	u64 rx_vrma_bad_pkey;  /* placement reports rejected by P_Key */
	u64 rx_vrma_bad_pasid; /* placement reports whose PASID has no live MR */
	u64 rx_vrma_va_mismatch; /* reports whose placement VA disagrees with RC state */
	u64 rx_vrma_length_error; /* placed-byte accounting violates burst state */
	u64 rx_vrma_nak_seq;   /* sequence-NAK episodes from end_state 0x02 */
	u64 rx_vrma_last_ack;  /* one controlled-peer ACK emitted per accepted LAST */
	u64 rx_vrma_ack_req;   /* ACKs for hardware-placed packets asking for one */
	u64 rx_vrma_middle_fast; /* MIDDLE reports taken by the fast path */
	u64 rx_vrma_dup;       /* reports for packets behind r_psn (resends) */
	u64 rx_vrma_ahead;     /* reports ahead of r_psn */
	u64 rx_write_imm_resume; /* WRITE with immediate completed by a resent LAST */
	u64 rif_invalidate_hw;  /* PASID teardown: entries found by table scan */
	atomic64_t rif_pasid_rows_scanned; /* targeted teardown rows */
	atomic64_t rif_pasid_late_rows; /* new row bits found after a scan/drain */
	atomic64_t rif_pasid_full_sweep; /* complete-table fallback teardowns */
	atomic64_t rif_pasid_track_enomem; /* failed row-tracking allocations */
	/* Loss reasons, serialized with the generation under rows_lock. */
	u64 rif_pasid_loss_rhe;
	u64 rif_pasid_loss_ovfl;
	u64 rif_pasid_loss_bypass;
	u64 rif_pasid_loss_netdev;
	u64 rif_pasid_loss_report;
	u64 sdma_admission_stall; /* bundles refused by a local/engine budget */
	/* sdma_admission_stall split by the first budget that refused it */
	u64 sdma_stall_qp_holds;  /* QP lane already holds BUNDLE_MAX bundles */
	u64 sdma_stall_eng_bundle; /* engine bundle budget exhausted */
	u64 sdma_stall_eng_desc;  /* engine descriptor budget exhausted */
	u64 sdma_stall_eng_page;  /* engine command-page budget exhausted */
	u64 sdma_page_stall;      /* command-page pool empty before admission */
	u64 sdma_batch_stall;     /* warmed batch-node pool empty before commit */
	u64 sdma_park;            /* QPs parked until an SDMA cookie drains */
	u64 sdma_wake;            /* parked QPs returned to the run queue */
	u64 sdma_wake_skipped;    /* parked QPs left parked: no room yet */
	u64 sdma_commit_accepted; /* batches transferred to common SDMA */
	u64 sdma_callback_ok;     /* successful callbacks consumed by the worker */
	u64 sdma_callback_error;  /* negative non-shutdown callbacks consumed */
	u64 sdma_callback_shutdown; /* accepted work error-completed at teardown */
	u64 sdma_context_mismatch; /* batch refused before a wrong CYR SC stamp */
	u64 bundle_packets_1_4;
	u64 bundle_packets_5_16;
	u64 bundle_packets_17_32;
	u64 bundle_packets_33_64;
	u64 bundle_packets_65_128;
	u64 bundle_packets_129_256;
	u64 bundle_packets_257_512;
	u64 bundle_packets_total;
	u64 bundle_descriptors_total;
	u32 bundle_packets_max;
	u32 bundle_descriptors_max;
	u32 admitted_descriptors_current;
	u32 admitted_descriptors_high_water;
	u64 s_lock_hold_max_ns;
	u64 s_lock_hold_over_100us;
	u64 s_lock_hold_samples;     /* worker turns whose s_lock hold was timed */
#if HFI2_DMS_ROCE_INJECT
	u64 sdma_retire_ack_first; /* ACK observed before last local callback */
	u64 sdma_retire_callback_first; /* last local callback observed before ACK */
	u64 inject_fail;        /* staged frames the emitter could not send */
	u64 sdma_inject_preaccept_shutdown; /* one-shot LOCAL abort before commit */
	u64 sdma_inject_callback_error; /* one COMMITTED callback forced negative */
	u64 sdma_inject_hold_for_ack; /* one PUBLISHED callback held for its ACK */
	u64 emitter_epoch_open; /* request lane opened an emitter epoch */
	u64 emitter_epoch_close; /* request lane reached wire quiescence */
	u64 emitter_live_switch_reject; /* opposite forced mode met a live lane */
	u64 emitter_idle_switch_accept; /* forced mode opened after a close */
#endif
};

/*
 * Responder READ responses share the existing rdmavt s_ack_queue, which owns
 * the MR reference.  This cursor only records the packetization progress
 * while that entry is retained: release/advance happens after LAST/ONLY PIO
 * succeeds, never when the packet is merely built.
 */
struct hfi2_dms_roce_read_cursor {
	struct rvt_sge_state ss;
	u32 psn;
	u32 off;
	u8 ack_index;
	bool valid;
};

struct hfi2_dms_roce_read_response {
	u32 next_psn;
	u32 wqe_index;
	bool active;
	bool write_reply;
	/* restarted for a gap; ignore the old stream until one packet is in sequence */
	bool restart_latched;
	bool restart_pending;
	u32 restart_psn;
	u32 restart_wqe_index;
	/* Drain an unplaceable DIRECT train before replaying the same capability. */
	u32 first_psn;
	u8 first_tries;
	bool first_diverted;
	bool first_retry_pending;
	bool first_replaying;
};

struct hfi2_dms_roce_read_meta {
	u64 vaddr;
	u32 psn;
	u32 rkey;
	u32 length;
	u64 dest_va;
	u32 dest_rkey;
	bool reply_write;
	bool software_place;
};

#if HFI2_DMS_ROCE_INJECT

#define HFI2_DMS_ROCE_INJECT_RING 8

/*
 * One hand-specified frame for the burst-conformance emitter.
 *
 * @local_qpn is a QP *number*, never a pointer: the command is staged by a
 * debugfs write and consumed later on the bulksvc worker, and a QP destroyed
 * in that window would leave a stale pointer behind.  The worker resolves the
 * number under RCU and holds a reference across emission.
 */
struct hfi2_dms_roce_inject_cmd {
	u32 local_qpn;
	u32 dest_qpn;
	u32 psn;
	u32 rkey;
	u32 reth_len;
	u32 payload_len;
	u32 msn;
	u64 vaddr;
	u8 opcode;
	u8 syndrome;
	bool ack_req;
};

#endif /* HFI2_DMS_ROCE_INJECT */

/*
 * No QP owns this bucket.  QP 0 is reserved by the RoCE personality
 * (qpn_res_start = 0), so it can never be a legitimate owner and is safe as
 * the sentinel.
 */
#define HFI2_ROCE_RIF_NO_OWNER 0u

/*
 * No R_Key owns this bucket.  R_Key 0 is not a legal key: rvt_alloc_lkey()
 * forces a non-zero value (rdmavt/mr.c, "make sure lkey is never zero"), and
 * rvt_invalidate_rkey() rejects 0 outright, so it is safe as a sentinel for
 * the same reason QP 0 is on the RIF side.
 */
#define HFI2_ROCE_RKEY_NO_OWNER 0u

/*
 * The EAL R_Key row is R_Key[8:0] (eth_hwi.h), so bit 8 moves the
 * internal key to row ^ 256.  RoCE fixes rdmavt's lkey table at 16 bits
 * (roce_main.c), putting each live MR's unique slot in key[31:16].
 * FastReg changes only key[7:0], so it cannot map a public key to its
 * internal key.  Internal-key detection uses the residency map, not this bit.
 */
#define HFI2_ROCE_RKEY_INTERNAL_MARK	BIT(8)

/*
 * One RIF entry, in the terms software computes rather than the register
 * layout.  Assembling this separately from the register encoding keeps the
 * arithmetic - which is ours and can be silently wrong - reviewable apart
 * from the field placement, which is transcription.
 *
 * @bucket is an output of the arm path, not an input: hardware has no
 * free-bucket search, so software chooses the bucket from its occupancy map.
 */
/*
 * R_Key length is in bytes.  Supply the full 32-bit key: hardware uses [8:0]
 * for the row and [31:9] for the comparand.  The installer chooses the bucket;
 * hardware performs no free-bucket search.  Internal keys admit private replies.
 */
struct hfi2_dms_roce_rkey_entry {
	u64 start_vaddr;
	u32 length;
	u32 rkey;
	u32 pasid;
	u8 permissions;
	bool internal;
	u8 bucket;
};

struct hfi2_dms_roce_rif_entry {
	u64 start_vaddr;
	u32 start_psn;
	u32 end_psn;
	u32 next_psn;
	u32 pasid;
	u32 qpn;
	u8 bucket;
	u8 next_psn_state;
};

/*
 * Dormant SDMA ownership represents only the future producer's finite
 * resources.  Item 2 deliberately creates neither an SDMA batch nor packet:
 * a later producer must provision caps and open admission before it can use
 * this ledger.
 */
#define HFI2_DMS_ROCE_SDMA_BUNDLE_PACKET_MAX 512
/*
 * Bundles in flight per QP lane and per engine are module parameters
 * (roce_sdma_qp_bundles, roce_sdma_engine_bundles); these are their
 * ceilings, which size the per-QP cookie array and the warm batch pool.
 */
#define HFI2_DMS_ROCE_SDMA_QP_BUNDLE_LIMIT 16
#define HFI2_DMS_ROCE_SDMA_COOKIE_COUNT \
	(2 * HFI2_DMS_ROCE_SDMA_QP_BUNDLE_LIMIT)
#define HFI2_DMS_ROCE_SDMA_ENGINE_BUNDLE_LIMIT 64
#define HFI2_DMS_ROCE_SDMA_ENGINE_PAGE_CAP 1024
#define HFI2_DMS_ROCE_SDMA_BATCH_NODE_DESCRIPTOR_CAP 128

enum hfi2_dms_roce_sdma_cookie_state {
	HFI2_DMS_ROCE_SDMA_COOKIE_LOCAL,
	HFI2_DMS_ROCE_SDMA_COOKIE_HELD,
	HFI2_DMS_ROCE_SDMA_COOKIE_COMMITTED,
	HFI2_DMS_ROCE_SDMA_COOKIE_PUBLISHED,
	HFI2_DMS_ROCE_SDMA_COOKIE_CONSUMED,
};

#if HFI2_DMS_ROCE_INJECT
enum hfi2_dms_roce_sdma_retire_order {
	HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_NONE,
	HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_ACK_FIRST,
	HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_CALLBACK_FIRST,
};
#endif

/* PIO and SDMA have no cross-engine ordering within one RC request lane. */
enum hfi2_dms_roce_emitter {
	HFI2_DMS_ROCE_EMITTER_UNSET,
	HFI2_DMS_ROCE_EMITTER_PIO,
	HFI2_DMS_ROCE_EMITTER_SDMA,
};

#if HFI2_DMS_ROCE_INJECT
enum hfi2_dms_roce_inject_emitter {
	HFI2_DMS_ROCE_INJECT_EMITTER_AUTO,
	HFI2_DMS_ROCE_INJECT_EMITTER_PIO,
	HFI2_DMS_ROCE_INJECT_EMITTER_SDMA,
};
#endif

#define HFI2_DMS_ROCE_SDMA_ENGINE_NONE U8_MAX
#define HFI2_DMS_ROCE_RESP_ACK_INDEX U32_MAX

enum hfi2_dms_roce_lane {
	HFI2_DMS_ROCE_LANE_REQUEST,
	HFI2_DMS_ROCE_LANE_RESPONDER,
};

enum hfi2_dms_roce_replay_action {
	HFI2_DMS_ROCE_REPLAY_NONE,
	HFI2_DMS_ROCE_REPLAY_SEND,
	HFI2_DMS_ROCE_REPLAY_RNR,
	HFI2_DMS_ROCE_REPLAY_EXHAUSTED,
};

struct hfi2_dms_roce_sdma_xfer {
	struct hfi2_dms_roce_qp *rqp;
	u32 wqe_index;
	u32 wqe_generation;
	u32 first_psn;
	u32 last_psn;
	u32 epoch;
	u16 local_holds;
	u8 lane;
	u8 port_idx;
	enum ib_wr_opcode opcode;
	struct rvt_mregion *mr;
	struct hfi2_bulksvc_verbs_source *source;
	/*
	 * Per-transfer because callbacks can run after tx_length describes a
	 * later WQE; using the QP field here can poison a valid header-only xfer.
	 */
	bool needs_source;
	bool copy_fallback;
	bool active;
	bool abandoned;
	bool wire_acked;
#if HFI2_DMS_ROCE_INJECT
	bool local_done;
	enum hfi2_dms_roce_sdma_retire_order retire_order;
#endif
	bool terminal;
	bool retired;
	bool displaced;		/* not in its home slot */
};

struct hfi2_dms_roce_sdma_cookie {
	struct list_head done_node;
	struct hfi2_dms_roce_qp *rqp;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct rvt_qp *qp;
	u16 bundle_count;
	u16 descriptor_count;
	u16 page_count;
	u8 lane;
	u8 engine_idx;
	int done_status;
	enum hfi2_dms_roce_sdma_cookie_state state;
	bool active;
	bool local_hold;
	bool terminal;
	bool xfer_new;
	bool ack_hold;
#if HFI2_DMS_ROCE_INJECT
	bool hold_for_ack;
#endif
	struct hfi2_dms_page *pages[HFI2_DMS_ROCE_SDMA_BUNDLE_PACKET_MAX];
};

struct hfi2_dms_roce_sdma_engine {
	u16 bundle_cap;
	u16 descriptor_cap;
	u16 page_cap;
	u16 bundle_used;
	u16 descriptor_used;
	u16 page_used;
	u16 bundle_high_water;
	u16 descriptor_high_water;
	u16 page_high_water;
	u64 bundle_admit_count;
	u64 descriptor_admit_count;
	u64 page_admit_count;
};

/*
 * The window key is never exposed to an application.  @slot reserves a live
 * rdmavt lkey and @rkey is its internal-key transform after generation rotation.
 */
enum hfi2_dms_roce_hwp_backend {
	HFI2_ROCE_HWP_PAGING,
	HFI2_ROCE_HWP_DONOR,
};

/* A deferred mapper must relinquish its extent before FREE permits reuse. */
enum hfi2_dms_roce_hwp_state {
	HFI2_ROCE_HWP_FREE,
	HFI2_ROCE_HWP_MAP_PENDING,
	HFI2_ROCE_HWP_READY,
	HFI2_ROCE_HWP_ACTIVE,
	HFI2_ROCE_HWP_RETIRING,
	HFI2_ROCE_HWP_ZAP_PENDING,
};

struct hfi2_dms_roce_hwp_window {
	struct list_head quarantine;
	enum hfi2_dms_roce_hwp_state state;
	struct hfi2_dms_roce_qp *owner;
	struct page **pages;
	u64 epoch;
	u32 wqe_index;
	u32 wqe_psn;
	u32 nr_pages;
	struct hfi2_roce_kmr_async request;
	struct hfi2_dms_roce_hwp_pool *pool;
	struct completion idle;
	int status;
	bool cancelled;
	bool busy;
	struct ib_mr *slot;
	u64 iova;
	u64 map_iova;
	u32 rkey;
	u32 generation;
	u32 mapped_len;
	u64 acquired_ns;
	u64 released_ns;
	s8 rkey_bucket;
	bool mapped;
	bool in_use;
	bool exhausted;
};

struct hfi2_dms_roce_fence_stats {
	atomic64_t hwp_cleanup_fenced;
	atomic64_t hwp_cleanup_fence_fail;
};

struct hfi2_dms_roce_hwp_pool {
	enum hfi2_dms_roce_hwp_backend backend;
	struct hfi2_roce_kmr_donor *donor;
	struct hfi2_roce_pasid *token;
	struct hfi2_roce_kmr_reservation reservation;
	struct iommu_domain *domain;
	struct hfi2_roce_pasid pasid;
	struct hfi2_dms_roce *roce;
	struct ib_pd *pd;
	struct hfi2_dms_roce_hwp_window *windows;
	struct list_head quarantine;
	struct delayed_work quarantine_work;
	spinlock_t lock; /* quarantine, allocation and donor-worker handoff */
	u64 iova_base;
	u32 win_bytes;
	u32 win_count;
	u32 next;
	/* Pool telemetry shares the allocator lock, including workqueue updates. */
	u32 active;
	u32 pending;
	u32 active_high;
	u32 pending_high;
	u64 acquired;
	u64 released;
	u64 reaped;
	u64 hold_ns;
	u64 hold_max_ns;
	u64 quarantine_ns;
	u64 quarantine_max_ns;
	bool attached;
	bool enabled;
	bool stopping;
	bool quiesced;
};

struct hfi2_dms_roce_tombs {
	/* rif_mutex owns tombstone identity and FIFO age, including CSR eviction. */
	struct {
		u64 sequence;
		u32 qpn;
		u32 psn;
		u8 bucket;
	} tombstones[HFI2_DMS_ROCE_TOMBSTONES];
	u64 sequence;
	DECLARE_BITMAP(rows, EAL_RIF_TABLE_ROWS);
	/* QPN reuse can precede the old QP's final unbind; rif_mutex owns this map. */
	struct xarray qps;
	struct hfi2_roce_pasid pasid;
	u64 armed;
	u64 cleared_reuse;
	u64 evicted;
	u64 arm_fail;
};

/* Posting CPUs can run inline sends concurrently on different QPs. */
struct hfi2_dms_roce_inline_stats {
	atomic64_t tx_pkts;
	atomic64_t tx_bytes;
	atomic64_t tx_pio_fail;
	atomic64_t tx_header_ns;
	atomic64_t tx_payload_copy_ns;
	atomic64_t tx_pio_write_ns;
	atomic64_t tx_pio_fence_ns;
	atomic64_t tx_pio_fences;
	atomic64_t tx_pio_credit_returns;
	atomic64_t tx_vlan_tagged;
	atomic64_t tx_runt_tagged;
	atomic64_t tx_pfc_tagged;
	atomic64_t tx_atomic_req;
	atomic64_t tx_send_wqe;
};

struct hfi2_dms_roce {
	struct hfi2_devdata *dd;
	struct hfi2_bulksvc *svc;

	struct send_context *sc;      /* PIO send context for RoCE egress */
	struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT];
	u8 next_rx_rcd;
	u64 pbc_template;

	struct hfi2_dms_roce_stats stats;
	atomic_t pio_fail_attempts;
	u64 pio_attempts;		/* credit-return cadence, under sc->alloc_lock */

	/* Queue membership only; inline TX does not consume worker queues. */
	spinlock_t runq_lock ____cacheline_aligned_in_smp;
	struct list_head runq;
	struct list_head pio_waitq;
	struct list_head sdma_waitq;	/* QPs stalled on SDMA capacity */
	/* Worker-only membership, with one QP reference per entry. */
	struct list_head read_restart;
	u16 sdma_qp_bundles;		/* bundles in flight per QP lane */
	bool pio_intr_armed;
	unsigned long pio_last_fill;	/* sc->fill after our last frame */
	bool pio_ctx_stopped;		/* worker saw the context stopped */
	bool pio_restarted;		/* restart seen, parked QPs not yet requeued */
	u8 reserved_emitter_warned;
	bool active;
	bool initialized;
	u8 reserved_hwp_read_alias;
	bool hwp_mode;
	u8 reserved_rrsp_arm;
	bool mtu_8192_capable;
	struct hfi2_dms_roce_hwp_pool hwp_pool;
	struct sk_buff_head netdev_rxq;

	/*
	 * The bulksvc worker owns done-list publication and consumption;
	 * teardown takes over only after the worker has been quiesced.
	 */
	struct list_head sdma_done;
	spinlock_t sdma_cancel_lock; /* protects reset-to-worker requests */
	struct list_head sdma_cancel;
	struct hfi2_dms_roce_sdma_engine sdma_engines[TXE_NUM_SDMA_ENGINES];
	atomic_t sdma_local_holds;
	/* QPs whose request lane is assigned to each engine (least-loaded pick) */
	atomic_t sdma_engine_qps[TXE_NUM_SDMA_ENGINES];
	u8 sdma_engine_count;
	bool sdma_admission_closed;

	/*
	 * Placement stride, in bytes, latched from the first QP to reach RTR.
	 * EAL_ROCEV2_CFG.rocev2_mtu is per-VF while path_mtu is per-QP, so one
	 * QP's MTU becomes the whole device's stride and any later QP that
	 * disagrees cannot be accelerated (gate H25).  Zero means unprogrammed.
	 * Serialized by @stride_lock, which is only ever taken on the modify_qp
	 * path - never from the bulksvc worker or any packet path.
	 */
	spinlock_t stride_lock;
	u32 stride_bytes;

	/*
	 * rif_mutex owns complete config-read/WDATA transactions, with IRQs on.
	 * rif_lock protects only metadata and the cross-context pending queue.
	 * Never acquire the mutex under a spinlock.  Its owner may briefly take
	 * rif_lock -> rows_lock, but must drop both before touching hardware.
	 */
	struct mutex rif_mutex;
	struct task_struct *rif_task;
	spinlock_t rif_lock;
	struct list_head rif_pending;
	u32 *rif_invalidations;
	unsigned long *rif_dirty;
	/* rif_lock guards the exact count; idle pollers read it without scanning. */
	u32 rif_dirty_count;
	/*
	 * Software-arm owners per [row][bucket], guarded by rif_lock.  Enforces
	 * one entry per {VF, QP} and selects WDATA2's bucket.  Hardware-created
	 * entries are absent: scan hardware before using a map-free bucket.
	 * Consequently rif_row_full undercounts hardware-FIRST row pressure.
	 */
	u32 *rif_owner;
	/*
	 * The PASID armed into each [row][bucket], valid only where rif_owner
	 * is not HFI2_ROCE_RIF_NO_OWNER.  Parallel to @rif_owner and guarded by
	 * the same @rif_lock.
	 *
	 * It exists because teardown asks a question no other state can answer:
	 * "which rows name this PASID?"  rif_owner records the QP, and the
	 * entry's PASID is write-only from software's point of view - PIO
	 * cannot be read, and the config-bus readback cannot observe
	 * hardware-driven state (see hfi2_dms_roce_rif_readback()).  Without
	 * this array the mmu_notifier release callback could not find the rows
	 * it is required to invalidate before the address space dies, and the
	 * ordering the design mandates would be unimplementable rather than
	 * merely unimplemented.
	 */
	u32 *rif_pasid;
	/*
	 * Per-PASID bitmap of RIF rows that software armed or that a consumed
	 * placement report named.  @rows_lock guards records and the loss generation;
	 * records predating a loss require full scans.  Lock order is rkey_lock ->
	 * rif_lock -> rows_lock, with either table lock also allowed alone before
	 * rows_lock.  Never acquire a table lock or do MMIO while holding rows_lock.
	 * Overflow samples use rif_mutex, separate from hot RX updates.
	 */
	spinlock_t rows_lock;
	struct xarray rif_pasid_rows;
	u64 rif_pasid_loss_gen;
	u64 rif_pasid_hdr_overflow[HFI2_DMS_ROCE_RCD_COUNT];

	/*
	 * Which R_Key owns each [row][bucket], or HFI2_ROCE_RKEY_NO_OWNER, and
	 * the PASID installed alongside it.  Same two reasons as rif_owner:
	 * the PIO write names a bucket in WDATA2 so software must choose one,
	 * and teardown has to find every row carrying a dying PASID.  Guarded
	 * by @rkey_lock.
	 *
	 * 512 x 16 x 4 B = 32 KiB each.
	 *
	 * Unlike the RIF table there is no hardware-FIRST divergence here: the
	 * R_Key table is only ever written by software, so this map is exact
	 * rather than a lower bound.
	 */
	spinlock_t rkey_lock;
	u32 *rkey_owner;
	u32 *rkey_pasid;
	u8 *rkey_internal;
	/*
	 * Per RCD: the header queue head offset after the consumed packets
	 * (low 32 bits) and the packets consumed (high 32 bits), published
	 * together so a reader gets a consistent pair.  Written by the
	 * primary lane worker only.
	 *
	 * The head half deliberately duplicates rcd->head.  It could live in
	 * struct hfi2_ctxtdata by widening that field (head is already the
	 * low half here to make that easy), but that would glue RoCE state
	 * into a structure shared by the whole driver for almost no
	 * technical gain, so it is kept here.
	 */
	u64 rx_rcd_state[HFI2_DMS_ROCE_RCD_COUNT];
	struct hfi2_dms_roce_tombs *tombs;

	/* Worker-produced copy queues, one SPSC ring per helper kthread. */
	struct hfi2_dms_roce_rx_queue rx_q;
	struct hfi2_dms_roce_rx_helper rx_helpers[HFI2_DMS_ROCE_RX_HELPER_MAX];
	struct hfi2_dms_roce_rx_usrhead
		rx_usrhead[HFI2_DMS_ROCE_RCD_COUNT][HFI2_DMS_ROCE_RX_USRHEAD_FIFO_SIZE];
	u8 rx_helper_count;
	/* CPUs the helpers are bound to; read-only while they run. */
	struct cpumask rx_helper_mask;
	/* Set while the RX poll consumes a diverted SKB; worker only. */
	bool rx_copy_sync;
	/* QP whose r_lock/s_lock the RX poll holds across packets, if any. */
	struct rvt_qp *rx_locked_qp;
	unsigned long rx_locked_rflags;
	unsigned long rx_locked_sflags;
	u32 rx_locked_pkts;
	u8 rx_usrhead_head[HFI2_DMS_ROCE_RCD_COUNT];
	u8 rx_usrhead_tail[HFI2_DMS_ROCE_RCD_COUNT];

#if HFI2_DMS_ROCE_INJECT
	struct dentry *rif_dentry;
	struct dentry *rif_dump_dentry;
	struct dentry *rif_loss_inject_dentry;
	struct hfi2_dms_roce_rif_entry rif_last_readback;
	int rif_last_readback_rc;
	struct hfi2_dms_roce_rkey_entry rkey_last;
	int rkey_last_rc;
#endif

#if HFI2_DMS_ROCE_INJECT
	spinlock_t inject_lock;
	struct hfi2_dms_roce_inject_cmd inject_ring[HFI2_DMS_ROCE_INJECT_RING];
	u32 inject_head;
	u32 inject_tail;
	struct dentry *inject_dentry;
#endif
	struct hfi2_dms_roce_fence_stats fence_stats;
	/* Joins quarantine and teardown unmaps, never the bulksvc lane. */
	struct mutex hwp_unmap_mutex;
	struct hfi2_dms_roce_inline_stats inline_stats;
	/* rows_lock invalidates the worker's scalar cache on record removal. */
	u64 rif_pasid_rows_gen;
	u64 rx_row_gen;
	u32 rx_row_pasid;
	u32 rx_row;
};

/*
 * Per-QP RoCE binding.  Allocated in the RoCE qp_priv_alloc path and pointed
 * to by hfi2_qp_priv_roce.  Stores the resolved port/device handles DMS_RoCE
 * needs directly, instead of the OPA-style downcast of qp->priv to
 * hfi2_qp_priv that bulksvc's OPA qp_info does (that downcast is unsafe for a
 * RoCE priv -- see roce.h).
 */
struct hfi2_dms_roce_qp {
	struct rvt_qp *qp;
	struct hfi2_devdata *dd;
	u8 port_idx;                  /* index into dd->pport */

	/*
	 * Send-side TX scratch.  @roce is the per-device backend that owns the
	 * bulksvc send context; latched at bind so the TX path avoids a
	 * dd->bulksvc walk per packet.  @txbuf holds one built frame (EAL
	 * egress header + Eth/IP/UDP/BTH/payload) before PIO.
	 */
	struct hfi2_dms_roce *roce;
	u8 rcd_idx;
	struct hfi2_ctxtdata *rcd;
	struct hfi2_dms_roce_read_cursor read_cursor;
	struct hfi2_dms_roce_read_response read_response;
	struct hfi2_dms_roce_read_meta *read_meta;
	unsigned long *read_write_wqes;
	unsigned long *read_software_wqes;
	struct hfi2_dms_roce_hwp_window **read_hwp_windows;
	/* Retained across software retries until success or error cleanup. */
	u32 *read_internal_keys;
	u64 hwp_epoch;
	u32 hwp_donor_holds; /* s_lock: serialize READs until donor zap completes */
	struct delayed_work hwp_cleanup_work;
	struct completion hwp_cleanup_idle;
	/* Cleanup-work timestamps; not shared with the bulksvc lane. */
	unsigned long hwp_cleanup_start_j;
	unsigned long hwp_cleanup_warn_j;
	bool hwp_cleanup_pending;
	bool hwp_error_pending;
	bool hwp_fencing;
	u32 hwp_error_index;
	enum ib_wc_status hwp_error_status;
	u32 hwp_fence_pasid;
	u8 *txbuf;
	size_t txbuf_sz;
	u8 *ackbuf;
	size_t ackbuf_sz;

	/* Responder ACK/NAK the PIO path refused; all three under qp->s_lock. */
	u32 ack_psn;
	u8 ack_syndrome;
	bool ack_pending;
	/*
	 * A response turn leaves this set to grant the next eligible turn to the
	 * send queue.  hfi2_dms_roce_do_send() touches it only under qp->s_lock.
	 */
	bool resp_yield_send;

	/*
	 * Future SDMA ownership ledger.  It is unbound and zeroed today because
	 * Item 2 has no producer; a held @cookie ref prevents QP unbind from
	 * freeing @rqp until the single worker consumes completion publication.
	 */
	struct completion sdma_local_zero;
	struct completion sdma_cancel_done;
	u16 sdma_local_holds;
	u16 sdma_req_holds;
	u16 sdma_resp_holds;
	/* Holds on request bundles a wire ACK can retire, never READ REQUESTs. */
	u16 sdma_ack_holds;
	struct hfi2_dms_roce_sdma_xfer *sdma_xfers;
	struct hfi2_dms_roce_sdma_cookie *sdma_cookies;
	/*
	 * Bundle page scratch.  Owned by the single bulksvc worker that runs
	 * roce_sdma_send_bundle() for this QP, so it needs no serialisation;
	 * it lives here rather than on the stack because a BUNDLE_PACKET_MAX
	 * array would put kilobytes of frame in the send path.
	 */
	struct hfi2_dms_page **sdma_command_pages;
	struct hfi2_bulksvc_verbs_source *sdma_sources;
	struct hfi2_bulksvc_verbs_source_segment *sdma_source_segments;
	u32 sdma_xfer_count;
	u32 sdma_xfer_displaced;	/* active xfers outside their home slot */
	bool sdma_admission_stopped;
	bool sdma_cancel_requested;
	/*
	 * One copied arm per QP.  The worker finishes it before polling another
	 * packet; no receive-buffer pointer crosses the QP unlock boundary.
	 * rif_lock guards queue/cancellation; s_lock guards continuation state.
	 */
	struct list_head rif_node;
	struct completion rif_idle;
	struct hfi2_dms_roce_rif_entry rif_entry;
	struct rvt_mregion *rif_mr;
	struct hfi2_roce_pasid *rif_token;
	u32 rif_epoch;
	u32 rif_pending_epoch;
	u32 reserved_rif_wqe_idx;
	u32 rif_payload;
	u32 rif_length;
	u64 rif_arm_start_ns;
	u8 rif_cleanup;
	bool rif_reclaim;
	int rif_stage_error;
	u8 rif_arm_kind;
	bool rif_queued;
	bool rif_busy;
	bool rif_cancelled;
	u8 reserved_rif_read_ready;
	bool rif_read_cleanup;
	bool rif_tomb_reclaim;
	bool rif_nak_pending;
	u32 rif_nak_psn;

	u8 reserved_rrsp_arm[20];
	struct list_head sdma_cancel_node;

	enum hfi2_dms_roce_emitter request_emitter;
	enum hfi2_dms_roce_emitter resp_emitter;
	u8 request_engine_idx;
	/* request_engine_idx is counted in roce->sdma_engine_qps[] */
	bool request_engine_counted;
	u32 request_epoch;
	u32 resp_generation;
	bool request_sdma_accepted;
	bool replay_pending;
	bool replay_rewound;
	u32 replay_psn;
	/*
	 * The WQE the replay PSN was named against.  A deferred replay runs
	 * later, from the SDMA completion path, by which time s_acked may have
	 * advanced past that WQE - and a PSN that fell inside it can fall
	 * inside a different WQE's range instead.  Seeking to the derived byte
	 * offset in the wrong WQE writes plausible bytes to the wrong address,
	 * so record the identity and re-validate before seeking.
	 */
	enum hfi2_dms_roce_replay_action replay_action;
	u32 replay_rnr_aeth;
	/*
	 * A PSN-error NAK names a packet inside the oldest WRITE: resume the
	 * rebuilt WQE there rather than at its FIRST (resume_wqe_idx/psn,
	 * valid while resume_pending).
	 */
	bool resume_pending;
	u32 resume_wqe_idx;
	u32 resume_psn;
	u32 order_pending;

	struct rvt_sge_state tx_ss;
	struct rvt_sge *tx_sges;
	struct rvt_mregion **tx_mrs;
	u32 tx_max_sge;
	u8 tx_num_mrs;
	enum ib_wr_opcode tx_opcode;
	u32 tx_length;
	u64 tx_remote_addr;
	u32 tx_rkey;
	__be32 tx_imm_data;
	u32 tx_invalidate_rkey;
	bool tx_solicited;
	u32 tx_pmtu;
	u32 tx_wqe_idx;
	u32 tx_off;
	u32 tx_psn;
	bool tx_middle_prefix_valid; /* §5.4.1: txbuf holds the burst MIDDLE prefix */
	bool tx_in_progress;

	bool tomb_bound;
	bool hw_write_seen;
	u32 tomb_r_psn;
	u64 vrma_next_va;
	u32 vrma_length;
	u32 vrma_first_psn;
	u32 vrma_placed;
	u32 vrma_pasid;
	bool vrma_write_active;
	bool tomb_recv_seen;
	bool tomb_recv_active;
	struct {
		u64 first_va;
		u32 first_psn;
		u32 length;
		u32 pasid;
		bool active;
	} write_gap;
	/* Software-armed bucket, or -1 after retirement. */
	s16 h15_bucket;
	u8 reserved_h33_interlocks[23];
	bool restart_rx_deferred;
	u32 h15_pasid;
	bool h15_armed;        /* this QP's entry was armed by the H15 path */
	bool h15_drop_sw;      /* drop pre-arm WRITE stragglers until the replay lands */
	bool hwp_rx_blocked;
	/*
	 * Last RX helper queue sequence carrying this QP's payload.  Written
	 * by the worker under r_lock; an ACK and an error flush wait for it.
	 */
	u64 rx_helper_fence;
	/*
	 * roce_last_by_software: a burst whose FIRST hardware placed and whose
	 * LAST software will finish (lbs_burst), whether the RIF entry
	 * hardware created for it may still be valid (lbs_entry), and the
	 * bucket it was last found in (lbs_bucket, -1 = unknown).
	 */
	bool lbs_burst;
	bool lbs_entry;
	s16 lbs_bucket;
	/* PSN and RETH VA of the WRITE FIRST software last accepted */
	u32 lbs_first_psn;
	u64 lbs_first_va;
	/* roce_rif_reclaim: FIRST PSN last NAKed after a reclaim, and tries */
	u32 reclaim_psn;
	u8 reclaim_tries;
	/*
	 * A hardware-placed LAST of a WRITE with immediate found no receive
	 * WQE.  Its payload is in memory and r_psn still names it; the resent
	 * LAST only has to deliver the immediate.  imm_rnr_len is the message
	 * length the completion reports.
	 */
	bool imm_rnr_pending;
	u32 imm_rnr_len;

	struct completion tx_idle;
	/* Serializes worker/cancel state with run-list membership changes. */
	spinlock_t tx_state_lock;
	bool tx_worker_active;
	bool tx_cancelled;
	struct list_head runq_node;
	struct list_head read_restart_node;
	struct list_head pio_wait_node;
	struct list_head sdma_wait_node;
	bool runq_queued;
	bool pio_wait_queued;
	bool sdma_wait_queued;
	bool sdma_stalled;	/* worker-only: last turn stopped on SDMA */
	bool donor_waiting;	/* s_lock: callback owns the next request wake */
	bool donor_stalled;	/* worker-only: no independent runnable work */

	/*
	 * SDMA MIDDLE command-page image: PBC, EAL egress header, Eth..BTH and
	 * the qword zero tail, valid for one request.  Only BTH PSN varies.
	 */
	bool tx_middle_cmd_valid;
	bool tx_middle_cmd_vlan;
	u8 tx_middle_cmd_hdr;	/* header bytes after the PBC */
	u8 tx_middle_cmd_pad;	/* zero tail after the payload */
	u8 tx_middle_cmd[96] __aligned(8);

	/*
	 * The same image for the WRITE MIDDLE packets of one READ response
	 * sent as WRITE, keyed by its ack slot, generation and first PSN.
	 */
	bool resp_middle_valid;
	bool resp_middle_alias;
	u8 resp_middle_ack_index;
	u8 resp_middle_hdr;
	u8 resp_middle_pad;
	u32 resp_middle_generation;
	u32 resp_middle_psn;
	u8 resp_middle_cmd[96] __aligned(8);
	struct hfi2_dms_roce_read_target {
		struct hfi2_roce_pasid *pasid;
		u64 va;
	} *read_targets;
	struct rvt_mregion *h15_mr;
	struct hfi2_roce_pasid *h15_token;
	struct rvt_mregion *hwp_rx_mr;
	struct hfi2_roce_pasid *hwp_rx_pasid;
	bool hwp_fence_required;
	bool hwp_cleanup_counted;
	bool tx_resched;
	u32 tx_ss_off; /* tx_ss may lag tx_off after SDMA gather. */
};

enum hfi2_roce_fence_outcome {
	HFI2_ROCE_FENCE_BEGIN,
	HFI2_ROCE_FENCE_DONE,
	HFI2_ROCE_FENCE_ABORT,
};

#ifdef CONFIG_INFINIBAND_HFI2_ROCE

/*
 * Initialise / tear down the per-device RoCE backend.  Called from the bulksvc
 * loan path (after the DMS loan is set up) and teardown, only when
 * hfi2_is_eth_mode(dd).  Idempotent-safe against a NULL/!active backend.
 */
int hfi2_dms_roce_init(struct hfi2_bulksvc *svc,
		       struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT],
		       struct send_context *sc);
void hfi2_dms_roce_teardown_begin(struct hfi2_bulksvc *svc);
void hfi2_dms_roce_teardown_drain(struct hfi2_bulksvc *svc);
void hfi2_dms_roce_teardown_finish(struct hfi2_bulksvc *svc);
void hfi2_dms_roce_detach_hw(struct hfi2_bulksvc *svc);
void hfi2_dms_roce_quiesce_internal_mrs(struct rvt_dev_info *rdi);
void hfi2_dms_roce_release_internal_mrs(struct rvt_dev_info *rdi);
void hfi2_dms_roce_hwp_pool_start(struct hfi2_dms_roce *roce);

#define HFI2_ROCE_TXBUF_DEFAULT_SZ 4608
#define HFI2_ROCE_TXBUF_8192_SZ 8704

/*
 * Separate from @txbuf so an ACK built on the receive path cannot overwrite a
 * data frame the send path staged but has not emitted: EAL recomputes the
 * ICRC, so such a frame would reach the wire looking valid.
 */
#define HFI2_ROCE_ACKBUF_SZ 128

/* Per-QP bind/unbind.  Bind resolves and stores the port/device handles. */
struct hfi2_dms_roce_qp *hfi2_dms_roce_qp_bind(struct rvt_qp *qp);
int hfi2_dms_roce_qp_init(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_qp_unbind(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_reset_qp(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_dequeue_qp(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_rx_helpers_wait_qp(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_cancel_qp(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_quiesce_qp(struct hfi2_dms_roce_qp *rqp);
void hfi2_dms_roce_drain(struct hfi2_dms_roce *roce);
void hfi2_dms_roce_pio_available(struct hfi2_dms_roce *roce);
void hfi2_dms_roce_sdma_publish_done(void *cookie, int status);

void hfi2_dms_roce_sdma_note_ack(struct hfi2_dms_roce_sdma_xfer *xfer);
void hfi2_dms_roce_reset_read_state(struct rvt_qp *qp);
void
hfi2_dms_roce_clear_wqe_read_write_reply(struct rvt_qp *qp,
					 const struct rvt_swqe *wqe);
bool hfi2_dms_roce_claim_stride(struct rvt_qp *qp, u32 pmtu);
bool hfi2_dms_roce_stride_conflict(struct rvt_qp *qp, int pmtu);

int hfi2_dms_roce_rif_arm(struct hfi2_dms_roce *roce,
			  const struct hfi2_dms_roce_rif_entry *entry,
			  const struct hfi2_roce_pasid *pasid);
int hfi2_dms_roce_rif_invalidate(struct hfi2_dms_roce *roce, u32 qpn, u8 bucket);
void hfi2_dms_roce_rif_pasid_activate(struct hfi2_dms_roce *roce, u32 pasid);
void hfi2_dms_roce_rif_pasid_deactivate(struct hfi2_dms_roce *roce, u32 pasid);
void hfi2_dms_roce_fence_qps(struct hfi2_dms_roce *roce, u32 pasid,
			     enum hfi2_roce_fence_outcome outcome);
bool hfi2_dms_roce_hwp_mode(struct hfi2_devdata *dd);
int hfi2_dms_roce_rif_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid,
				       bool full_sweep, unsigned long *scanned);
int hfi2_dms_roce_rif_pasid_finish(struct hfi2_dms_roce *roce, u32 pasid,
				   unsigned long *scanned, int drain_ret);
void hfi2_dms_roce_rx_mark(struct hfi2_dms_roce *roce,
				   struct hfi2_dms_roce_rx_mark *mark);
int hfi2_dms_roce_wait_rx(struct hfi2_dms_roce *roce,
			  const struct hfi2_dms_roce_rx_mark *mark);
bool hfi2_dms_roce_mr_eligible(struct hfi2_devdata *dd, bool has_mm,
			       bool has_pinned_dmabuf, bool has_donor, size_t length);
bool hfi2_dms_roce_last_by_software(void);
u32 hfi2_dms_roce_hdr_suppress(void);
u8 hfi2_dms_roce_rkey_permissions(int access_flags);
int hfi2_dms_roce_rkey_install(struct hfi2_dms_roce *roce,
			       const struct hfi2_dms_roce_rkey_entry *entry,
			       const struct hfi2_roce_pasid *pasid);
int hfi2_dms_roce_rkey_invalidate(struct hfi2_dms_roce *roce, u32 rkey,
				  u8 bucket);
bool hfi2_dms_roce_rkey_is_internal(struct hfi2_dms_roce *roce, u32 rkey);
int hfi2_dms_roce_rkey_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid);
int hfi2_dms_roce_rkey_readback(struct hfi2_dms_roce *roce, u32 rkey, u8 bucket,
				struct hfi2_dms_roce_rkey_entry *out);
int hfi2_dms_roce_rif_readback(struct hfi2_dms_roce *roce, u32 qpn, u8 bucket,
			       struct hfi2_dms_roce_rif_entry *out);

int hfi2_dms_roce_do_send(struct rvt_qp *qp);
bool hfi2_dms_roce_enqueue(struct rvt_qp *qp);
void hfi2_dms_roce_kick_send(struct rvt_qp *qp);
bool hfi2_dms_roce_sdma_busy(struct hfi2_dms_roce *roce);
int hfi2_dms_roce_poll(struct hfi2_dms_roce *roce, ktime_t now);

void hfi2_dms_roce_rx_bypass(struct hfi2_dms_roce *roce, u8 rcd_idx,
			     const struct eal_ingress_header *ih,
			     void *frame, u32 len);
void hfi2_dms_roce_netdev_track_loss(struct hfi2_devdata *dd,
				     const struct eal_ingress_header *ih);
bool hfi2_dms_roce_netdev_match_ipv4(struct hfi2_devdata *dd,
					 const void *frame, u32 len);
void hfi2_dms_roce_netdev_enqueue(struct hfi2_devdata *dd,
					  struct sk_buff *skb);

/*
 * Retry-timer restart hook.  Rewinds the send cursor to the first unacked
 * WQE (or errors the QP if retries are exhausted).  Called from
 * hfi2_roce_notify_restart_rc under r_lock+s_lock.
 */
void hfi2_dms_roce_restart(struct rvt_qp *qp, u32 psn);

/* Dump the bring-up counters to a debugfs seq_file. */
void hfi2_dms_roce_stats_print(struct hfi2_devdata *dd, struct seq_file *s);

#else /* !CONFIG_INFINIBAND_HFI2_ROCE */

static inline int
hfi2_dms_roce_init(struct hfi2_bulksvc *svc,
		   struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT],
		   struct send_context *sc)
{
	return 0;
}

static inline void hfi2_dms_roce_teardown_begin(struct hfi2_bulksvc *svc)
{
}

static inline void hfi2_dms_roce_teardown_drain(struct hfi2_bulksvc *svc)
{
}

static inline void hfi2_dms_roce_teardown_finish(struct hfi2_bulksvc *svc)
{
}

static inline void hfi2_dms_roce_detach_hw(struct hfi2_bulksvc *svc)
{
}

static inline void
hfi2_dms_roce_quiesce_internal_mrs(struct rvt_dev_info *rdi)
{
}

static inline void
hfi2_dms_roce_release_internal_mrs(struct rvt_dev_info *rdi)
{
}

static inline void
hfi2_dms_roce_hwp_pool_start(struct hfi2_dms_roce *roce)
{
}

static inline struct hfi2_dms_roce_qp *hfi2_dms_roce_qp_bind(struct rvt_qp *qp)
{
	return NULL;
}

static inline int hfi2_dms_roce_qp_init(struct hfi2_dms_roce_qp *rqp)
{
	return 0;
}

static inline void hfi2_dms_roce_qp_unbind(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void hfi2_dms_roce_reset_qp(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void hfi2_dms_roce_dequeue_qp(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void
hfi2_dms_roce_rx_helpers_wait_qp(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void hfi2_dms_roce_cancel_qp(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void hfi2_dms_roce_quiesce_qp(struct hfi2_dms_roce_qp *rqp)
{
}

static inline void hfi2_dms_roce_drain(struct hfi2_dms_roce *roce)
{
}

static inline void hfi2_dms_roce_pio_available(struct hfi2_dms_roce *roce)
{
}

static inline void hfi2_dms_roce_sdma_publish_done(void *cookie, int status)
{
}

static inline int hfi2_dms_roce_sdma_commit(struct hfi2_dms_roce_sdma_cookie *cookie,
					    struct hfi2_dms_sdma_batch *batch,
					    u8 engine_idx)
{
	return -EOPNOTSUPP;
}

static inline void
hfi2_dms_roce_sdma_abort_uncommitted(struct hfi2_dms_roce_sdma_cookie *cookie,
				     int status)
{
}

static inline void hfi2_dms_roce_sdma_note_ack(struct hfi2_dms_roce_sdma_xfer *xfer)
{
}

static inline void hfi2_dms_roce_reset_read_state(struct rvt_qp *qp)
{
}

static inline void
hfi2_dms_roce_clear_wqe_read_write_reply(struct rvt_qp *qp,
					 const struct rvt_swqe *wqe)
{
}

static inline bool hfi2_dms_roce_claim_stride(struct rvt_qp *qp, u32 pmtu)
{
	return false;
}

static inline bool hfi2_dms_roce_stride_conflict(struct rvt_qp *qp, int pmtu)
{
	return false;
}

struct hfi2_dms_roce_rif_entry;

static inline int
hfi2_dms_roce_rif_arm(struct hfi2_dms_roce *roce,
		      const struct hfi2_dms_roce_rif_entry *entry,
		      const struct hfi2_roce_pasid *pasid)
{
	return -EOPNOTSUPP;
}

static inline void
hfi2_dms_roce_rif_pasid_activate(struct hfi2_dms_roce *roce, u32 pasid)
{
}

static inline void
hfi2_dms_roce_rif_pasid_deactivate(struct hfi2_dms_roce *roce, u32 pasid)
{
}

static inline void
hfi2_dms_roce_fence_qps(struct hfi2_dms_roce *roce, u32 pasid,
			enum hfi2_roce_fence_outcome outcome)
{
}

static inline bool hfi2_dms_roce_hwp_mode(struct hfi2_devdata *dd)
{
	return false;
}

static inline int
hfi2_dms_roce_rif_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid,
				   bool full_sweep, unsigned long *scanned)
{
	return 0;
}

static inline int
hfi2_dms_roce_rif_pasid_finish(struct hfi2_dms_roce *roce, u32 pasid,
			       unsigned long *scanned, int drain_ret)
{
	return 0;
}

static inline void hfi2_dms_roce_rx_mark(
	struct hfi2_dms_roce *roce, struct hfi2_dms_roce_rx_mark *mark)
{
}

static inline int hfi2_dms_roce_wait_rx(
	struct hfi2_dms_roce *roce, const struct hfi2_dms_roce_rx_mark *mark)
{
	return 0;
}

static inline bool hfi2_dms_roce_mr_eligible(struct hfi2_devdata *dd,
					     bool has_mm, bool has_pinned_dmabuf,
					     bool has_donor, size_t length)
{
	return false;
}

static inline bool hfi2_dms_roce_last_by_software(void)
{
	return false;
}

static inline u32 hfi2_dms_roce_hdr_suppress(void)
{
	return 0;
}

static inline u8 hfi2_dms_roce_rkey_permissions(int access_flags)
{
	return 0;
}

static inline int
hfi2_dms_roce_rkey_install(struct hfi2_dms_roce *roce,
			   const struct hfi2_dms_roce_rkey_entry *entry,
			   const struct hfi2_roce_pasid *pasid)
{
	return -EOPNOTSUPP;
}

static inline int hfi2_dms_roce_rkey_invalidate(struct hfi2_dms_roce *roce,
						u32 rkey, u8 bucket)
{
	return 0;
}

static inline bool
hfi2_dms_roce_rkey_is_internal(struct hfi2_dms_roce *roce, u32 rkey)
{
	return false;
}

static inline int
hfi2_dms_roce_rkey_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid)
{
	return 0;
}

static inline int
hfi2_dms_roce_rkey_readback(struct hfi2_dms_roce *roce, u32 rkey, u8 bucket,
			    struct hfi2_dms_roce_rkey_entry *out)
{
	return -EOPNOTSUPP;
}

static inline int hfi2_dms_roce_rif_invalidate(struct hfi2_dms_roce *roce,
					       u32 qpn, u8 bucket)
{
	return -EOPNOTSUPP;
}

static inline int hfi2_dms_roce_rif_readback(struct hfi2_dms_roce *roce,
					     u32 qpn, u8 bucket,
					     struct hfi2_dms_roce_rif_entry *out)
{
	return -EOPNOTSUPP;
}

static inline int hfi2_dms_roce_do_send(struct rvt_qp *qp)
{
	return 0;
}

static inline bool hfi2_dms_roce_enqueue(struct rvt_qp *qp)
{
	return false;
}

static inline void hfi2_dms_roce_kick_send(struct rvt_qp *qp)
{
}

static inline bool hfi2_dms_roce_sdma_busy(struct hfi2_dms_roce *roce)
{
	return false;
}

static inline int hfi2_dms_roce_poll(struct hfi2_dms_roce *roce, ktime_t now)
{
	return 0;
}

static inline void hfi2_dms_roce_rx_bypass(struct hfi2_dms_roce *roce,
					   u8 rcd_idx,
					   const struct eal_ingress_header *ih,
					   void *frame, u32 len)
{
}

static inline void
hfi2_dms_roce_netdev_track_loss(struct hfi2_devdata *dd,
				const struct eal_ingress_header *ih)
{
}

static inline bool hfi2_dms_roce_netdev_match_ipv4(struct hfi2_devdata *dd,
							    const void *frame, u32 len)
{
	return false;
}

static inline void hfi2_dms_roce_netdev_enqueue(struct hfi2_devdata *dd,
							  struct sk_buff *skb)
{
	consume_skb(skb);
}

static inline void hfi2_dms_roce_restart(struct rvt_qp *qp, u32 psn)
{
}

static inline void hfi2_dms_roce_stats_print(struct hfi2_devdata *dd,
					     struct seq_file *s)
{
}

#endif /* CONFIG_INFINIBAND_HFI2_ROCE */

#endif /* _HFI2_DMS_ROCE_H */
