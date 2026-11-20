/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#ifndef DEF_HFI2_BULKSVC_VERBS_H
#define DEF_HFI2_BULKSVC_VERBS_H

#include "bulksvc_mpsc.h"

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "dms.h"

struct hfi2_bulksvc;
struct bts_verbs_mr_record;
struct bts_verbs_pageset;
struct rvt_mregion;
struct rvt_sge;

struct bts_verbs_pageset *
bts_verbs_pageset_create(struct hfi2_bulksvc *svc, struct rvt_mregion *mr);
void bts_verbs_pageset_get(struct bts_verbs_pageset *pageset);
void bts_verbs_pageset_put(struct bts_verbs_pageset *pageset);

#ifdef CONFIG_INFINIBAND_HFI2_ROCE
struct hfi2_bulksvc_verbs_source_segment {
	struct bts_verbs_pageset *pageset;
	u64 page_offset;
	u64 stream_offset;
	u64 length;
};

struct hfi2_bulksvc_verbs_source {
	struct hfi2_dms_page_provider provider;
	struct hfi2_bulksvc_verbs_source_segment *segments;
	u32 num_segments;
	u64 length;
};

int hfi2_bulksvc_verbs_source_provider_init(struct hfi2_bulksvc_verbs_source *source,
					    struct hfi2_bulksvc_verbs_source_segment *segments,
					    u32 segment_cap, const struct rvt_sge *sges,
					    u32 num_sge);
void hfi2_bulksvc_verbs_source_provider_release(struct hfi2_bulksvc_verbs_source *source);
#endif

/* Max DMS lanes (independent DMS instances) per device; see bulksvc_num_lanes. */
#define HFI2_BULKSVC_MAX_LANES 8

/*
 * Cross-path gate kill switch.  When true (default) class transitions
 * between rdmavt RC and BTS on the same QP are serialized; setting
 * to false bypasses the gate predicate but leaves bookkeeping intact.
 */
extern bool bulksvc_path_gate;

/* Runtime gate for routing verbs SEND through the BTS offload. */
extern bool bulksvc_verbs_send_rcv;

/*
 * True when a verbs SEND on @qp may be offloaded to DMS: the remote peer has
 * negotiated the PD-flag OPFN version and advertised a userspace PD, so its
 * recv buffers will be DMS-resolvable (not lkey 0).
 */
bool hfi2_bts_send_offload_ok(struct rvt_qp *qp);

enum hfi2_bulksvc_verbs_write_flags {
	HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT = (1 << 0),
	HFI2_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED = (1 << 1),
	HFI2_BULKSVC_VERBS_WRITE_FLAGS_SEND = HFI2_DMS_WRITE_START_FLAG_EXT_DEST,
};

struct hfi2_bulksvc_verbs_rdma_cmd {
	struct hfi2_bulksvc_qp_info *qp_info;
	struct rvt_qp* qp;
	struct verbs_txreq* txreq;
};

struct hfi2_bulksvc_verbs_mr_reg_cmd {
	struct rvt_mregion *mr;
	u32 key;
	/* Snapshot of rvt_mregion fields captured at enqueue time.
	 * These fields can be overwritten by rvt_map_mr_sg/rvt_fast_reg_mr
	 * before bulksvc processes this command, so we must not read them
	 * from the live mr pointer during deferred processing.
	 */
	u64 user_base;
	size_t length;
	int access_flags;
};

struct hfi2_bulksvc_verbs_mr_dereg_cmd {
	struct rvt_mregion *mr;
	u32 failed_count;
	u32 key;
};

enum verbs_ordered_wr_type {
	ORDERED_WR_RDMAVT,
	ORDERED_WR_HOTPATH,
};

/* Sentinel for verbs_ordered_wr.ring_slot: "this WR never entered the
 * inflight ring" (deferred, errored before add, or flushed at teardown). */
#define VERBS_INFLIGHT_NO_SLOT		U32_MAX

struct verbs_ordered_wr {
	struct list_head node;
	u64 seq;
	enum verbs_ordered_wr_type type;
	/*
	 * Inflight-ring slot this WR occupies, stamped by verbs_inflight_add.
	 * Completion/removal index the ring by THIS value, not by seq & mask:
	 * seq advances on paths that never add to the ring (on_err_pre_ord,
	 * deferred-WR flush at teardown), so it must not be used as the ring
	 * index.  VERBS_INFLIGHT_NO_SLOT means the WR was never added.
	 */
	u32 ring_slot;
};

enum hfi2_bulksvc_verbs_cmd_op {
	HFI2_BULKSVC_VERBS_CMD_OP_RDMA,
	HFI2_BULKSVC_VERBS_CMD_OP_MR_REG,
	HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG
};

struct hfi2_bulksvc_verbs_cmd {
	/* Links the cmd into the lock-free producer queue (cmd_queue). */
	struct mpsc_node mpsc_node;
	struct kref refcount;
	/* kmem_cache this cmd was allocated from, for the kref destroy fn. */
	struct kmem_cache *cache;
	enum hfi2_bulksvc_verbs_cmd_op op;
	union {
		struct hfi2_bulksvc_verbs_rdma_cmd rdma;
		struct hfi2_bulksvc_verbs_mr_reg_cmd mr_reg;
		struct hfi2_bulksvc_verbs_mr_dereg_cmd mr_dereg;
	};

	/* Per-WR ordering state — used by verbs ordering middleware */
	struct verbs_ordered_wr ord_wr;

};

/*
 * Lock-free MPSC cmd queue.  @depth is a diagnostic-only count maintained
 * by the real-cmd enqueue/dequeue sites (not inside the mpsc helpers, so
 * the consumer's stub re-link doesn't perturb it); it may lag the true
 * queue depth by a cmd or two, which is fine for bulksvc_dbg.
 */
struct hfi2_bulksvc_mpsc_verbs_cmd_queue {
	struct mpsc_queue mpsc;
	atomic_t depth;
};

enum hfi2_bulksvc_verbs_cmpl_type {
	HFI2_BULKSVC_VERBS_CMPL_TYPE_CMD,
	HFI2_BULKSVC_VERBS_CMPL_TYPE_ACCESS,
};

struct hfi2_bulksvc_verbs_cmpl {
	struct kref refcount;
	/* kmem_cache this cmpl was allocated from, for the kref destroy fn. */
	struct kmem_cache *cache;

	enum hfi2_bulksvc_verbs_cmpl_type type;

	union {
		struct {
			struct hfi2_bulksvc_verbs_cmd *bts_cmd;
			u32 status;
		} cmd;
		struct {
			struct rvt_qp* qp;
			u32 lkey;
			__be32 user_immdt_be;
			u16 flags;
			int status;
		} access;
	};
};

/*
 * Verbs ordering middleware state — embedded per-QP.
 * Sequences WRs at submit time and reorders completions so CQ entries
 * are delivered in submit order even when DMS completes out of order.
 */
struct hfi2_bulksvc_verbs_ordering {
	struct hfi2_bulksvc *svc;
	/* DMS lane this QP submits to, cancels on and counts against */
	struct hfi2_dms *dms;
	u64 next_issue_seq;
	u64 next_deliver_seq;
	struct list_head pending;
};

/*
 * Maximum number of concurrent WRITE_WITH_IMM WRs tracked for
 * target-side recv CQ aggregation.  The WR index is encoded in 8 bits
 * of the DMS order_key (bits [55:48]), so the table wraps at 256
 * entries.  If more than 256 WRITE_WITH_IMM WRs are concurrently
 * in flight on a single QP, index aliasing will corrupt multi-SGE
 * aggregation tracking.  In practice, DMS rift limits constrain
 * concurrent transfers well below this threshold.
 */
#define BTS_VERBS_RX_WR_TABLE_SIZE	256

#define BTS_VERBS_INFLIGHT_BITS	5
#define BTS_VERBS_MAX_INFLIGHT	(1 << BTS_VERBS_INFLIGHT_BITS)
#define BTS_VERBS_INFLIGHT_MASK	(BTS_VERBS_MAX_INFLIGHT - 1)

/* Max SGEs a single WQE may carry (all coalesced into one DMS op). */
#define BTS_VERBS_MAX_SGE_PER_WR	255

/* Per-WR go-back-N replay budget: attempts before terminal give-up. */
#define BTS_VERBS_RETRY_COUNT	3

/* SQ back-pressure watermarks; see module params in bulksvc_verbs.c. */
extern unsigned int bulksvc_sq_gate_high;
extern unsigned int bulksvc_sq_gate_low;
extern unsigned int bulksvc_poll_max_per_iter;

enum verbs_inflight_state {
	INFLIGHT_EMPTY = 0,
	INFLIGHT_ACTIVE,
	INFLIGHT_COMPLETED,
	INFLIGHT_AWAITING_REPLAY,
};

/*
 * GBN replay generation, carried to the receiver in order_key[31:24] -- the
 * always-zero high byte of qp_num (capped < 1<<24 by RVT_QPN_MAX), so it
 * crosses the wire with no DMS format change.  The receiver drops a
 * completion whose generation is older than the last it recorded for that
 * wr_seq, so a stale orphan cannot clobber a fresher replay.  Sourced from
 * per-WR replay_gen (bumped on EVERY capture, including cohort siblings swept
 * in by cancel_others) so each replayed WR carries a strictly-newer generation
 * than its own orphaned attempt -- not from the retry budget, which siblings
 * do not consume.
 */
#define GBN_ORDER_KEY_GEN_BITS	8
#define GBN_ORDER_KEY_GEN_SHIFT	24
#define GBN_ORDER_KEY_GEN_SIZE	BIT_ULL(GBN_ORDER_KEY_GEN_BITS)
#define GBN_ORDER_KEY_GEN_MASK	(GBN_ORDER_KEY_GEN_SIZE - 1)
static_assert(GBN_ORDER_KEY_GEN_SHIFT + GBN_ORDER_KEY_GEN_BITS <= 32,
	      "GBN replay generation field must fit within order_key[31:0]");

struct verbs_gbn_replay {
	/* claimed provider: exactly one of {pageset, multiseg} non-NULL */
	struct bts_verbs_pageset *pageset;
	struct verbs_multiseg_ctx *multiseg;
	u64 rbuf_start_offset;
	/* re-issue scalars (mirror struct bts_submit_req inputs) */
	u32 remote_lid;
	union hfi2_dms_key dms_key;
	u64 remote_addr;
	u32 size;
	u32 remote_qpn;			/* WRITE_WITH_IMM dest qpn for re-pack */
	bool solicited;			/* IB_SEND_SOLICITED for re-pack */
	__be32 imm_data;
	bool is_read;
	bool is_send;
	bool is_imm;
	/* original wire order_key; seq preserved, gen re-stamped at replay */
	u64 order_key;
	/* Owning ref held across the parked window (exactly one set). */
	struct hfi2_bulksvc_verbs_cmd *cmd;
	struct direct_rdma_sge_info *sge_info;
};

struct verbs_inflight_wr {
	enum verbs_inflight_state state;
	/* One DMS op per WQE: a single handle, HANDLE_NONE when unoccupied. */
	struct hfi2_dms_transfer_handle handle;
	struct verbs_gbn_replay replay;	/* per-WR GBN cohort record */
	u8 replay_attempts;		/* GBN retry budget consumed; bumped only on arm/widen */
	u8 replay_gen;			/* wire generation nonce; bumped on every capture */
	u32 issue_cursor;		/* inflight cursor at submit; window membership */
	bool held_for_ordering; /* Parked out-of-order wr awaiting predecessor's GBN replay. */
};

enum verbs_deferred_wr_path {
	DEFERRED_PATH_RDMAVT,
	/* Userspace-admitted WR; replay destination re-decided at retry. */
	DEFERRED_PATH_HOTPATH,
};

/*
 * Deferred WR — captures ALL state needed to retry submission later.
 * Two flavors: rdmavt (re-submits via bulksvc_on_qp_cmd) and hotpath
 * (re-submits via bulksvc_verbs_hotpath_send_one).
 */
struct verbs_deferred_wr {
	struct list_head list;       /* qp_info->deferred_wrs linkage */

	enum verbs_deferred_wr_path path;
	union {
		/* rdmavt path: the cmd holds all WR state via txreq->wqe */
		struct {
			struct hfi2_bulksvc *svc;
			struct hfi2_bulksvc_verbs_cmd *cmd;
		} rdmavt;

		/* Snapshot of a userspace ib_send_wr, replayable via either
		 * the bts hotpath or rvt_post_send.  RDMA opcodes use
		 * remote_addr/rkey; atomics also use compare_add/swap. */
		struct {
			struct hfi2_bulksvc *svc;
			struct rvt_qp *qp;       /* ref held */
			enum ib_wc_status flush_status;
			u64 wr_id;
			u32 opcode;
			int send_flags;
			__be32 imm_data;
			u64 remote_addr;
			u32 rkey;
			u64 compare_add;
			u64 swap;
			u32 num_sge;
			struct ib_sge sges[];    /* flexible array */
		} hotpath;
	};
};

/*
 * Dispatch class for the cross-path gate.  RDMAVT covers all non-BULKSVC
 * RC opcodes (including TID RDMA); BTS covers IB_WR_BULKSVC_*.
 */
enum hfi2_qp_opclass {
	OPCLASS_NONE = 0,
	OPCLASS_RDMAVT,
	OPCLASS_BTS,
};

struct hfi2_bulksvc_qp_info {
	// Held by the hfi2_qp_priv, as well as active dms ops
	struct kref refcount;
	struct list_head node;

	u32 rvt_rdma_ops_sched; /* n ops in DMS from rvt, protected by s_lock */

	/* bts-path admit gate state.  Count of bts->bts dispatches in
	 * flight; bts->rdmavt fallback is tracked via qp->s_head/s_last
	 * (SQ drain).  Protected by qp->s_lock. */
	u32 bts_path_inflight_bts;

	/* Shared cross-path counters used by the rdmavt-side gate in
	 * hfi2_make_rc_req.  Bumped/dec'd from both sides so the rdmavt
	 * gate sees bts in flight.  bts-side admit does NOT consult these
	 * (uses bts_path_inflight_bts above).  TODO: split per-side once
	 * make_rc_req is converted to a path-local gate. */
	u32 n_dispatched_unacked;
	enum hfi2_qp_opclass last_dispatched_class;

	struct hfi2_qp_priv *qp_priv;

	/*
	 * Flavor-agnostic back-pointers.  qp_priv above aliases the OPA
	 * hfi2_qp_priv layout and MUST NOT be dereferenced for ->owner or
	 * ->rcd when the owning QP is a RoCE QP (whose hfi2_qp_priv_roce
	 * places @owner at a different offset and has no @rcd at all).
	 * Both OPA and RoCE qp_priv_alloc set @owner directly after create.
	 * RoCE also binds @ppd there because it is single-port; OPA publishes
	 * @ppd after qp->port_num becomes valid and updates it on port changes.
	 * Bulksvc consumers read @owner / @ppd here instead of chasing
	 * qp_priv->owner / qp_priv->rcd->ppd.
	 */
	struct rvt_qp *owner;
	struct hfi2_pportdata *ppd;

	struct hfi2_bulksvc_verbs_state* verbs_state;

	/*
	 * Owning DMS lane.  The send-side BTS state (ordering, inflight
	 * ring, deferred_wrs, GBN) is touched only by that lane's worker,
	 * and rdmavt-path BTS cmds go to that lane's cmdq.  The receive-side
	 * state (rx_wr_table, rx_next_deliver_seq, rx_expected_send_seq) is
	 * touched by the lane the peer QP's traffic lands on: this lane, or
	 * with OPFN opted out the peer's lane modulo our lane count.  Either
	 * is fixed for the connection's life, so still one worker.
	 */
	u32 lane;
	/*
	 * Lane every transfer targets, so each round trip runs on one worker
	 * per host and keeps its halt-poll window warm: the peer QP's lane,
	 * learned in DMS OPFN before any transfer is admitted, or ours with
	 * OPFN opted out.
	 */
	u32 peer_lane;

	struct hfi2_bulksvc_verbs_ordering ordering;

	/* DMS chain tail for parent/child transfer ordering. */
	struct hfi2_dms_transfer_handle chain_tail_handle;

	/*
	 * Per-WR sequence counter for target-side recv ordering.
	 * The low 8 bits index rx_wr_table[] for multi-SGE aggregation.
	 * Cannot reuse the QP PSN because PSN increments per-packet
	 * (MTU fragmentation), not per-WR.
	 */
	u16 tx_wr_seq;

	struct rx_wr_tracker {
		u8 rx_generation;	/* GBN: order_key[31:24] gen of last accepted retire; drop older (stale orphan) */
		bool rx_generation_valid; /* rx_generation holds a real value for the CURRENT wr_seq occupant */
		bool rx_ready;
		__be32 rx_immdt_be;
		u16 rx_flags;
		struct rvt_qp *rx_qp;
		u32 rx_lkey;
		int rx_status;
	} rx_wr_table[BTS_VERBS_RX_WR_TABLE_SIZE];

	u16 rx_next_deliver_seq;
	u16 tx_send_seq;
	u16 rx_expected_send_seq;

	struct verbs_inflight_wr *inflight_ring;
	u32 inflight_size;	/* runtime ring capacity (power of 2) */
	u32 inflight_mask;	/* inflight_size - 1, for index wrapping */
	u32 inflight_head;	/* next slot to submit into */
	u32 inflight_tail;	/* oldest un-retired slot */
	atomic64_t inflight_full_deferrals;

	bool inflight_cancel_walk; /* Tells us that a cancel walk is in progress */

	bool bulksvc_gated;	/* SQ-walker parked; see bulksvc_sq_gate_high. Protected by qp->s_lock. */
	struct list_head deferred_wrs;
	bool retry_in_progress;

	/*
	 * Go-back-N window control.  One replay window per QP at a time, over
	 * the inflight slots in [gbn_window_base, gbn_window_head).
	 */
	bool gbn_window_active;		/* a replay window is armed/draining */
	u32 held_count;			/* held-for-ordering slots parked in the ring */
	bool gbn_replaying;		/* re-submitting a window; suppress inline re-arm */
	u32 gbn_drain_remaining;	/* cohort completions still outstanding */
	u32 gbn_window_base;		/* cohort start; lowest failed cursor this episode */
	u32 gbn_window_head;		/* cohort end, exclusive */
	/*
	 * Suffix-replay boundary.  Only WRs at/after the lowest failed cursor are
	 * cancelled and replayed; the older prefix [tail, base) is left in flight
	 * to complete normally.
	 */
	bool gbn_anchor_valid;		/* a live prefix exists; chain first replay onto it */
	u32 gbn_anchor_cursor;		/* issue_cursor of the last prefix WR (base - 1) */
	bool gbn_stop_replay;		/* live-prefix drop errored the QP; stop replaying */

	/*
	 * Set under qp->s_lock from do_rc_completion's dec-to-zero to
	 * tell the BTS thread that this QP may have gate-deferred WRs
	 * to retry.  Cleared from the BTS thread (also under s_lock).
	 */
	bool gate_retry_pending;

	/*
	 * QP reset/destroy latched a forced reap of parked GBN records whose
	 * claimed trackers will never complete to drop the owning rvt_get_qp.
	 * Set under qp->s_lock at reset, cleared by the BTS thread.
	 */
	bool gbn_teardown_pending;

	/*
	 * Scratch list_head used by hfi2_bulksvc_poll_gate_retries() to
	 * stage QPs to drain after dropping qp_infos_lock.  Touched only
	 * by the BTS thread.
	 */
	struct list_head gate_retry_drain_node;

	/*
	 * Scratch list_head used by hfi2_bulksvc_poll_gbn_teardown()
	 * to stage QPs for the forced parked-slot reap after dropping
	 * qp_infos_lock.  Touched only by the BTS thread.
	 */
	struct list_head gbn_teardown_drain_node;
};


struct hfi2_bulksvc_lane;
int hfi2_bulksvc_lane_poll_mr_ops(struct hfi2_bulksvc_lane *l);
void hfi2_bulksvc_lane_mr_teardown(struct hfi2_bulksvc_lane *l);

struct hfi2_bulksvc_verbs_state {
	struct mutex qp_infos_lock;
	struct list_head qp_infos;

	/* MR-record lookup goes through rdi->lkey_table (driver_priv). */

	struct hfi2_bulksvc_mpsc_verbs_cmd_queue cmd_queue;

	atomic64_t ring_full_deferrals;

	/*
	 * Number of QPs with gate_retry_pending set, per owning DMS lane
	 * (qp_info->lane).  Atomic so the rdmavt-side wake doesn't have to
	 * acquire qp_infos_lock; each lane's BTS poll uses its own entry as
	 * an O(1) early-out, so one lane's pending QPs do not make every
	 * lane scan qp_infos.
	 */
	atomic_t gate_retry_pending_count[HFI2_BULKSVC_MAX_LANES];

	/*
	 * Number of QPs with gbn_teardown_pending set, per owning lane.
	 * Atomic so the reset-side latch avoids qp_infos_lock; the BTS poll
	 * uses it as an O(1) early-out.
	 */
	atomic_t gbn_teardown_pending_count[HFI2_BULKSVC_MAX_LANES];
};

/*
 * Verbs SEND target landing.  resolve_send_dest pops one RWQE on the
 * destination QP (named by dms_key.access) and builds a DMS destination page
 * provider over the recv scatter list; send_dest_complete posts the recv CQE
 * and releases the latched page sets.  cmpl_ctx is opaque to dms.c, which
 * stashes it on the rx tracker and hands it back at completion.  Both run on
 * the BTS thread.  These implement the generic dms->ext_dest
 * resolve/complete contract (see enum hfi2_dms_ext_dest_status and the
 * hfi2_dms_ext_dest_*_fn typedefs in dms.h).
 */
enum hfi2_dms_ext_dest_status
hfi2_bulksvc_verbs_resolve_send_dest(struct hfi2_dms *dms,
				     union hfi2_dms_key dms_key,
				     u64 imm_data, u64 order_key, u16 flags,
				     u32 xfer_size,
				     struct hfi2_dms_page_provider *provider_out,
				     u64 *rbuf_start_offset_out,
				     void **cmpl_ctx_out);

void hfi2_bulksvc_verbs_send_dest_complete(struct hfi2_dms *dms,
					   void *cmpl_ctx, int status);

int hfi2_bulksvc_verbs_state_init(struct hfi2_bulksvc_verbs_state *state);

/* Per-bulksvc cmd/cmpl slab caches.  Init before any cmd/cmpl alloc;
 * destroy after the verbs queues are drained.
 */
int hfi2_bulksvc_verbs_caches_init(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_verbs_caches_destroy(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_verbs_state_teardown(struct hfi2_bulksvc_verbs_state *state);

int hfi2_bulksvc_poll_verbs_cmds(struct hfi2_bulksvc * const svc,
				 struct hfi2_bulksvc_mpsc_verbs_cmd_queue *cmdq);
int hfi2_bulksvc_poll_gate_retries(struct hfi2_bulksvc * const svc, u32 lane);
int hfi2_bulksvc_poll_gbn_teardown(struct hfi2_bulksvc * const svc, u32 lane);

struct hfi2_bulksvc_qp_info* hfi2_bulksvc_qp_info_create(struct hfi2_bulksvc_verbs_state* verbs_state, struct hfi2_qp_priv *qp_priv);
void hfi2_bulksvc_qp_info_set_lane(struct hfi2_bulksvc_qp_info *qp_info,
				   struct rvt_qp *qp);
void hfi2_bulksvc_qp_info_get(struct hfi2_bulksvc_qp_info *qp_info);
void hfi2_bulksvc_qp_info_put(struct hfi2_bulksvc_qp_info *qp_info);

struct hfi2_bulksvc_verbs_cmd * hfi2_bulksvc_verbs_cmd_rdma_create(
				 struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_qp_info *qp_info,
				 struct rvt_qp* qp,
				 struct verbs_txreq *txreq);
struct hfi2_bulksvc_verbs_cmd * hfi2_bulksvc_verbs_cmd_mr_reg_create(
				 struct hfi2_bulksvc *svc,
				 struct rvt_mregion *mr);
struct hfi2_bulksvc_verbs_cmd *
hfi2_bulksvc_verbs_cmd_mr_dereg_create(struct hfi2_bulksvc *svc,
				       struct rvt_mregion *mr);

void hfi2_bulksvc_verbs_cmd_get(struct hfi2_bulksvc_verbs_cmd *);
void hfi2_bulksvc_verbs_cmd_put(struct hfi2_bulksvc_verbs_cmd *);
void hfi2_bulksvc_verbs_cmpl_put(struct hfi2_bulksvc_verbs_cmpl *cmpl);

int hfi2_bulksvc_verbs_dms_reg_client_id(struct hfi2_dms* dms);
void hfi2_bulksvc_verbs_release_client_id(struct hfi2_dms* dms);

void bulksvc_on_cmd_uverbs_post_send(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_uverbs_post_send const * const cmd,
	size_t cmd_bytes);

#endif
