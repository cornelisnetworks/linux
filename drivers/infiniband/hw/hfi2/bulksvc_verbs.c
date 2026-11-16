#include "hfi2.h"
#include "qp.h"
#include <linux/dma-buf.h>
#include "rvt_qp.h"
#include "verbs_txreq.h"

#include "bulksvc.h"
#include "bulksvc_rvt.h"
#include "opfn.h"
#include "dms.h"
#include "trace_dms.h"

#include "bulksvc_verbs.h"
#include "roce.h"
#include "roce_pasid.h"

static bool bulksvc_qp_is_roce(struct rvt_qp *qp)
{
#ifdef CONFIG_INFINIBAND_HFI2_ROCE
	struct hfi2_qp_priv_common *c = qp->priv;

	return c->flavor == HFI2_QP_PRIV_ROCE;
#else
	return false;
#endif
}

static struct hfi2_bulksvc_qp_info *bulksvc_qp_info_of(struct rvt_qp *qp)
{
#ifdef CONFIG_INFINIBAND_HFI2_ROCE
	if (bulksvc_qp_is_roce(qp))
		return ((struct hfi2_qp_priv_roce *)qp->priv)->bulksvc_qp_info;
#endif
	return ((struct hfi2_qp_priv *)qp->priv)->bulksvc_qp_info;
}

static void bulksvc_release_bts_gate(struct rvt_qp *qp)
{
	struct hfi2_qp_priv *qpriv;

	if (bulksvc_qp_is_roce(qp))
		return;

	qpriv = qp->priv;
	if (qpriv->s_flags & HFI2_S_BTS_GATE) {
		qpriv->s_flags &= ~HFI2_S_BTS_GATE;
		hfi2_schedule_send(qp);
	}
}

static unsigned int bulksvc_verbs_max_inflight = BTS_VERBS_MAX_INFLIGHT;
/*
 * Default 32 is sufficient for typical Lustre/BTS workloads where
 * message sizes are large (64K+) and DMS transfer latency is the
 * bottleneck.  Monitor ring_full_deferrals via debugfs to detect
 * if the ring is too small for a given workload.  Must be a power
 * of 2, minimum 4, maximum 256 (limited by rx_wr_table size).
 */

bool bulksvc_path_gate = true;

bool bulksvc_verbs_send_rcv = true;

/*
 * SQ back-pressure gate watermarks.
 *
 * Valid configurations:
 *   - HIGH > 0 (HIGH==0 would latch the gate closed permanently:
 *     unsigned 'count >= 0' is always true, verbs_bulksvc_enqueue
 *     would return -EAGAIN before the inc, and the LOW release path
 *     in ordering_deliver_one would be unreachable).
 *   - LOW <= HIGH.  Equal disables hysteresis (gate fires and
 *     releases at the same point) and is a documented stress-tuning
 *     mode.  LOW > HIGH is rejected.
 *   - HIGH >= bulksvc_verbs_max_inflight effectively disables the
 *     gate (the existing verbs_inflight_full deferral catches the
 *     WR first); this is the documented "disable the gate" knob and
 *     is not rejected.
 *
 * Both are 0644 (runtime-writable via sysfs); set callbacks enforce
 * the invariants on every write.
 */
unsigned int bulksvc_sq_gate_high = 30;
unsigned int bulksvc_sq_gate_low = 16;

static __maybe_unused int bulksvc_sq_gate_high_set(const char *val, const struct kernel_param *kp)
{
	unsigned int v;
	int ret;

	ret = kstrtouint(val, 0, &v);
	if (ret)
		return ret;
	if (v == 0)
		return -EINVAL;
	if (v < READ_ONCE(bulksvc_sq_gate_low))
		return -EINVAL;
	WRITE_ONCE(bulksvc_sq_gate_high, v);
	return 0;
}

static __maybe_unused int bulksvc_sq_gate_low_set(const char *val, const struct kernel_param *kp)
{
	unsigned int v;
	int ret;

	ret = kstrtouint(val, 0, &v);
	if (ret)
		return ret;
	if (v > READ_ONCE(bulksvc_sq_gate_high))
		return -EINVAL;
	WRITE_ONCE(bulksvc_sq_gate_low, v);
	return 0;
}

static __maybe_unused const struct kernel_param_ops bulksvc_sq_gate_high_ops = {
	.set = bulksvc_sq_gate_high_set,
	.get = param_get_uint,
};

static __maybe_unused const struct kernel_param_ops bulksvc_sq_gate_low_ops = {
	.set = bulksvc_sq_gate_low_set,
	.get = param_get_uint,
};



/* Cap on cmds drained per poll_verbs_cmds invocation; 0 = unlimited. */
unsigned int bulksvc_poll_max_per_iter = 100;

/*
 * Per-WR go-back-N replay budget: number of replay attempts before a WR is
 * given up and its error completion surfaced. SENDs are excluded from the replay budget.
 * The retry count is sent over the wire through the 8-bit order_key[31:24] generation.
 */
static unsigned int bulksvc_gbn_max_retries = BTS_VERBS_RETRY_COUNT;

static __maybe_unused int bulksvc_gbn_max_retries_set(const char *val, const struct kernel_param *kp)
{
	unsigned int v;
	int ret;

	ret = kstrtouint(val, 0, &v);
	if (ret)
		return ret;
	if (v > GBN_ORDER_KEY_GEN_MASK)
		return -EINVAL;
	WRITE_ONCE(bulksvc_gbn_max_retries, v);
	return 0;
}

static __maybe_unused const struct kernel_param_ops bulksvc_gbn_max_retries_ops = {
	.set = bulksvc_gbn_max_retries_set,
	.get = param_get_uint,
};


#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define VERBS_CLIENT_ID_START (((1 << 8) - 1) << 24)


// TODO partition by some notion of "client"
// #define VERBS_PD_TO_CLIENT_ID(id) (VERBS_CLIENT_ID_START + id)
#define VERBS_PD_TO_CLIENT_ID(id) (VERBS_CLIENT_ID_START)

static int verbs_host_mr_memcpy_fn(struct hfi2_dms_mr *mr, u64 offset, u64 size, void *data, const bool is_read);

/*
 * Immutable page set for one registration cycle.  page_provider.provider_ctx
 * points at &dms_mr; DMS reads dma_list/pages live for a whole transfer,
 * so the set must outlive every op and the DMS access that latched it -
 * including across a notify_mr_pages_set that swaps in a new set.  Each
 * in-flight op cookie and the access hold a kref; the last put queues the
 * sleepable teardown to mr_unmap_wq (never inline on the BTS thread).
 * Carries dd/svc by value so it can outlive its bts_verbs_mr_record.
 */
struct bts_verbs_pageset {
	struct kref refcount;
	struct hfi2_dms_mr dms_mr;	/* page_provider.provider_ctx target */
	void **vaddrs;			/* per-page kaddr; dmabuf vmap if DMABUF */
	enum rvt_mem_type mem_type;
	struct dma_buf *dmabuf;		/* if mem_type == RVT_MEM_DMABUF */
	void *dma_buf_do_priv;		/* if mem_type == RVT_MEM_DMABUF_DO */
	u32 npages_dma_mapped;
	struct hfi2_devdata *dd;
	struct hfi2_bulksvc *svc;
	struct work_struct unmap_work;
};

struct bts_lane_mr_rep;

struct bts_verbs_mr_record {
	struct kref refcount;
	/* Lookups read mr->driver_priv under rcu_read_lock() and then
	 * kref_get_unless_zero(); the record must outlive that read section.
	 */
	struct rcu_head rcu;
	u32 client_id;
	u32 rkey;
	struct rvt_mregion *rvt_mr;
	struct hfi2_devdata *dd;
	struct hfi2_bulksvc *svc;
	bool registered;
	/* Swapped (never mutated in place) per cycle by notify_mr_pages_set
	 * (single writer); read by WR dispatch via get_current.
	 */
	struct bts_verbs_pageset __rcu *cur_pageset;
	/* The set the live DMS access references; holds one ref from reg,
	 * dropped in the unregister callback.  BTS-thread only.
	 */
	struct bts_verbs_pageset *access_pageset;
	/* Single-shot barrier for mr_priv_free's FastReg-without-LOCAL_INV
	 * path; armed and consumed exactly once.
	 */
	spinlock_t destroy_lock;
	bool destroy_pending;
	struct completion destroy_done;
	/*
	 * MR_DEREG command for mr_priv_free's still-registered path,
	 * allocated by mr_priv_alloc, which may sleep.  The dereg then
	 * cannot fail to allocate, so the lane replicas always get released.
	 */
	struct hfi2_bulksvc_verbs_cmd *destroy_cmd;
	/*
	 * Replicas of the access on the secondary DMS lanes.  Primary
	 * lane BTS thread only.
	 */
	struct bts_lane_mr_rep *lane_rep[HFI2_BULKSVC_MAX_LANES];
	/*
	 * Live replicas.  A replica is freed only after its lane has
	 * unregistered the access, i.e. every transfer using it has completed
	 * or been cancelled, so mr_priv_free waits for 0 (svc->lane_reps_wq)
	 * before rdmavt may release the pages.  Only once the lane workers
	 * have exited is the wait cut short: the lane DMS instances are then
	 * torn down with their accesses instead.
	 */
	atomic_t lane_reps_live;
};

static struct bts_verbs_mr_record *bts_verbs_mr_record_alloc(
	struct hfi2_devdata *dd, struct hfi2_bulksvc *svc,
	struct rvt_mregion *rvt_mr);

static struct bts_verbs_pageset *bts_verbs_pageset_alloc(
	struct hfi2_devdata *dd, struct hfi2_bulksvc *svc);
static int bts_verbs_pageset_pin_and_map(
	struct bts_verbs_pageset *ps, struct rvt_mregion *rvt_mr);
void bts_verbs_pageset_get(struct bts_verbs_pageset *ps);
void bts_verbs_pageset_put(struct bts_verbs_pageset *ps);

/* Take a ref on the record's current page set, or NULL. */
static struct bts_verbs_pageset *
bts_verbs_pageset_get_current(struct bts_verbs_mr_record *rec)
{
	struct bts_verbs_pageset *ps;

	rcu_read_lock();
	ps = rcu_dereference(rec->cur_pageset);
	if (ps && !kref_get_unless_zero(&ps->refcount))
		ps = NULL;
	rcu_read_unlock();
	return ps;
}

void bts_verbs_mr_record_get(struct bts_verbs_mr_record * const mr_record);
void bts_verbs_mr_record_put(struct bts_verbs_mr_record * const mr_record);
static void bts_verbs_mr_destroy_barrier_arm(struct bts_verbs_mr_record *rec);
static void bts_verbs_mr_destroy_barrier_wait(struct bts_verbs_mr_record *rec);
static void bts_verbs_mr_destroy_barrier_signal(struct bts_verbs_mr_record *rec);
static int verbs_pin_range(void *provider_ctx, unsigned int from_page,
			   unsigned int npages, bool writable);
static inline struct hfi2_dms_page_provider
verbs_mr_page_provider(struct bts_verbs_pageset *ps);

struct verbs_src_segment {
	/*
	 * The counted page set (not the mr_record) is what the multiseg
	 * provider reads: dms_mr (with dma_list/region_offset) lives in the
	 * page set in the 3f61ed90 refcounted model.  Held until completion.
	 */
	struct bts_verbs_pageset *pageset;
	u64 base_byte_offset;	/* byte offset of SGE within its MR's pages */
	u64 wqe_byte_offset;	/* logical byte offset of segment within WQE */
	u64 byte_length;
};

struct verbs_multiseg_ctx {
	u32 nsegs;
	u64 total_bytes;
	struct verbs_src_segment segs[];
};

static inline struct hfi2_dms_page_provider
verbs_multiseg_page_provider(struct verbs_multiseg_ctx *ctx);

/*
 * One DMS transfer per WQE: convert_wqe_to_page_provider() resolves every
 * SGE of a WQE into a single hfi2_dms_page_provider plus its kref-counted
 * backing (a lone page set when the WQE collapses to one contiguous run,
 * else a multiseg ctx).  Direction selects the source-gather vs the
 * dest-scatter provider and the coalesce/eligibility rules.
 */
enum verbs_pp_dir { VERBS_PP_SOURCE, VERBS_PP_DEST };

/*
 * Resolver closure: takes ONE counted page-set ref into seg->pageset; fills
 * seg->base_byte_offset (byte offset of the SGE within its MR's pages) and
 * seg->byte_length.  Does NOT set wqe_byte_offset (the helper computes that
 * after coalescing).  Returns 0 or -errno.  On error it MUST NOT leave a
 * ref in seg->pageset.
 */
typedef int (*verbs_resolve_seg_fn)(void *rctx, u32 idx,
				    struct verbs_src_segment *seg);

struct verbs_pp_result {
	struct hfi2_dms_page_provider provider;
	/* Exactly one of {pageset, multiseg} is non-NULL on success, mirroring
	 * the cookie union so existing teardown branches work unchanged.
	 */
	struct bts_verbs_pageset *pageset;
	struct verbs_multiseg_ctx *multiseg;
	u64 total_bytes;
	u64 rbuf_start_offset;
};

static int convert_wqe_to_page_provider(struct hfi2_bulksvc *svc, u32 num_sge,
					enum verbs_pp_dir dir, gfp_t gfp,
					verbs_resolve_seg_fn resolve, void *rctx,
					struct verbs_pp_result *out);

/*
 * The @mr_offset argument that initiator hfi2_dms_{read,write}_data submits
 * expect: single_mr_resolve_start maps it back to a logical byte offset via
 * user.addr, so legacy single-SGE submits always passed user.addr+ubo.
 * Multiseg providers ignore mr_offset (resolve_start returns 0), so report 0.
 * For a collapsed single seg the encoding of out->rbuf_start_offset differs by
 * direction (SOURCE already stores user.addr+ubo; DEST stores base ==
 * region_offset+ubo), so translate per direction to reproduce user.addr+ubo
 * byte-for-byte.
 */
static inline u64 verbs_pp_submit_mr_offset(const struct verbs_pp_result *out,
					    enum verbs_pp_dir dir)
{
	if (out->multiseg)
		return 0;
	if (dir == VERBS_PP_SOURCE)
		return out->rbuf_start_offset;
	return out->pageset->dms_mr.user.addr +
	       (out->rbuf_start_offset - out->pageset->dms_mr.region_offset);
}

/*
 * O(1) lookup of the BTS per-MR record via rdmavt's RCU lkey table.
 *
 * UAF safety: the WR hot path holds no rvt_mregion percpu_ref, so the
 * record could be freed after rcu_read_unlock.  We kref_get_unless_zero
 * inside the read section; the caller MUST bts_verbs_mr_record_put on
 * every exit path (including after handing a fresh ref to a cookie).
 */
static struct bts_verbs_mr_record *
bulksvc_verbs_find_mr_record(struct rvt_dev_info *rdi, struct ib_pd *pd,
			     u32 lkey)
{
	struct rvt_lkey_table *rkt = &rdi->lkey_table;
	struct bts_verbs_mr_record *rec = NULL;
	struct rvt_mregion *mr;

	if (lkey == 0)
		return NULL;

	rcu_read_lock();
	mr = rcu_dereference(rkt->table[lkey >> rkt->shift]);
	if (mr && READ_ONCE(mr->lkey_published) &&
	    !mr->driver_internal && !atomic_read(&mr->lkey_invalid) &&
	    mr->lkey == lkey && (!pd || mr->pd == pd)) {
		rec = READ_ONCE(mr->driver_priv);
		if (rec && !kref_get_unless_zero(&rec->refcount))
			rec = NULL;
	}
	rcu_read_unlock();

	return rec;
}

static struct hfi2_bulksvc_verbs_cmpl* hfi2_bulksvc_verbs_cmd_cmpl_create(
				 struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_verbs_cmd *cmd,
				 u32 status);
static struct hfi2_bulksvc_verbs_cmpl* hfi2_bulksvc_verbs_access_cmpl_create(
				struct hfi2_bulksvc *svc,
				struct rvt_qp* qp,
				u32 lkey,
				__be32 user_immdt_be,
				u16 flags,
				int status);

static void bts_send_cq(struct rvt_qp *qp, u64 wr_id, u32 byte_len,
			enum ib_wr_opcode wr_opcode, int wr_send_flags,
			enum ib_wc_status status);
static void bts_send_cq_locked(struct rvt_qp *qp, u64 wr_id, u32 byte_len,
			       enum ib_wr_opcode wr_opcode, int wr_send_flags,
			       enum ib_wc_status status);

struct direct_rdma_sge_info {
	u32 remaining_wr_sges;
	enum ib_wc_status status;
	struct verbs_ordered_wr ord_wr;
	struct hfi2_bulksvc_verbs_ordering *ord;
	struct rvt_qp *qp;
	u64 wr_id;
	enum ib_wr_opcode wr_opcode;
	u32 byte_len;
	int wr_send_flags;
	/* GBN replay: hotpath re-issue scalars captured at submit. */
	u64 remote_addr;
	union hfi2_dms_key dms_key;
	u16 remote_lid;
	u32 num_sge;
	u32 remote_qpn;
	bool is_send;
	bool is_imm;
	bool solicited;
	__be32 user_imm_be;
};

struct direct_rdma_cmpl_cookie {
	struct bts_verbs_pageset *pageset;
	/* An aggregated multi-SGE SEND owns its page sets here instead of
	 * @pageset; exactly one of {pageset, multiseg} is set.
	 */
	struct verbs_multiseg_ctx *multiseg;
	struct direct_rdma_sge_info *sge_info;
	u64 rbuf_start_offset;		/* stashed at submit for GBN replay capture */
	u64 order_key;			/* stashed at submit for GBN replay capture */
};

/*
 * Deliver a verbs-side completion to the rdmavt connector.
 *
 * BTS thread only.  Direct dispatch — no queue, no lock.  See
 * hfi2_bts_deliver_verbs_cmpl() in bulksvc_rvt.c for the rationale
 * and the lock-ordering argument vs qp->s_lock.
 */
static void deliver_bts_rvt_cmpl(
	struct hfi2_bulksvc* const svc,
	struct hfi2_bulksvc_verbs_cmpl * const cmpl)
{
	if (WARN_ON(!cmpl || !svc)) {
		pr_err("%s:%d:%s() invalid cmpl or verbs_state\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}
	hfi2_bts_deliver_verbs_cmpl(svc, cmpl);
}


///
/// Handle QP commands in the bulksvc thread
///

struct qp_rdma_cmpl_cookie {
	struct hfi2_bulksvc* svc;
	struct hfi2_bulksvc_verbs_cmd* cmd;
	/* Single-SGE path latches one page set here; the multiseg gather
	 * path latches one page set per segment inside @multiseg instead.
	 * Exactly one of {pageset, multiseg} is set per cookie.
	 */
	struct bts_verbs_pageset* pageset;
	struct verbs_multiseg_ctx *multiseg;
	u32 *remaining_wr_sges;
	u64 rbuf_start_offset;		/* stashed at submit for GBN replay capture */
	u64 order_key;			/* stashed at submit for GBN replay capture */
};

/* Cookie for the DMS unregister completion callback. */
struct verbs_mr_unreg_cookie {
	struct hfi2_bulksvc *svc;
	struct bts_verbs_mr_record *mr_record;
	struct hfi2_bulksvc_verbs_cmd *cmd;
};

static void ordering_insert_pending(struct hfi2_bulksvc_verbs_ordering *ord,
				    struct verbs_ordered_wr *wr)
{
	struct verbs_ordered_wr *pos;

	list_for_each_entry(pos, &ord->pending, node) {
		if (wr->seq < pos->seq) {
			list_add_tail(&wr->node, &pos->node);
			return;
		}
	}
	list_add_tail(&wr->node, &ord->pending);
}

static void ordering_deliver_one(struct verbs_ordered_wr *wr,
				 struct hfi2_bulksvc *svc)
{
	if (wr->type == ORDERED_WR_RDMAVT) {
		struct hfi2_bulksvc_verbs_cmd *cmd =
			container_of(wr, struct hfi2_bulksvc_verbs_cmd, ord_wr);
		struct rvt_qp *qp = cmd->rdma.txreq->qp;
		struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
		struct hfi2_bulksvc_qp_info *qp_info = bulksvc_qp_info_of(qp);
		unsigned long flags;

		spin_lock_irqsave(&qp->s_lock, flags);
		/*
		 * Skip dec on zero: post-reset cancellations land here.
		 * notify_qp_reset() zeroes rvt_rdma_ops_sched while in-flight
		 * retires are still in flight (same shape as the
		 * n_dispatched_unacked retire below).  Underflow would wrap to
		 * U32_MAX and latch the gate closed forever — this counter is
		 * load-bearing for dispatch.
		 */
		if (qp_info->rvt_rdma_ops_sched == 0) {
			/* skip dec */
		} else {
			qp_info->rvt_rdma_ops_sched -= 1;
		}
		/* SQ back-pressure release: wake parked walker at LOW. */
		if (qp_info->bulksvc_gated &&
		    qp_info->rvt_rdma_ops_sched <=
				READ_ONCE(bulksvc_sq_gate_low)) {
			qp_info->bulksvc_gated = false;
			rdi->driver_f.schedule_send(qp);
		}
		bool drained_to_zero = false;
		/* Skip dec on zero: post-reset cancellations land here. */
		if (qp_info->n_dispatched_unacked == 0) {
			/* skip dec */
		} else if (--qp_info->n_dispatched_unacked == 0) {
			qp_info->last_dispatched_class = OPCLASS_NONE;
			bulksvc_release_bts_gate(qp);
			drained_to_zero = true;
		}
		spin_unlock_irqrestore(&qp->s_lock, flags);

		/* Wake BTS thread for gate-deferred WRs on this QP. */
		if (drained_to_zero &&
		    !list_empty(&qp_info->deferred_wrs) &&
		    !qp_info->gate_retry_pending) {
			qp_info->gate_retry_pending = true;
			atomic_inc(&qp_info->verbs_state->gate_retry_pending_count[qp_info->lane]);
			hfi2_bulksvc_schedule_lane(svc, qp_info->lane);
		}

		deliver_bts_rvt_cmpl(svc,
			hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd,
				cmd->rdma.txreq->bts_rc));
		hfi2_bulksvc_verbs_cmd_put(cmd);
	} else {
		struct direct_rdma_sge_info *info =
			container_of(wr, struct direct_rdma_sge_info, ord_wr);
		unsigned long flags;
		struct hfi2_bulksvc_qp_info *qp_info;

		qp_info = bulksvc_qp_info_of(info->qp);

		/* Hotpath retire: post the CQE and dec bts-side local + shared
		 * counters under one s_lock hold.
		 * Dec-to-zero on local wakes deferred_wrs drain; dec-to-zero
		 * on shared clears HFI2_S_BTS_GATE for the rdmavt-side gate. */
		spin_lock_irqsave(&info->qp->s_lock, flags);
		bool drained_to_zero = false;

		bts_send_cq_locked(info->qp, info->wr_id, info->byte_len,
				   info->wr_opcode, info->wr_send_flags,
				   info->status);

		if (WARN_ON_ONCE(qp_info->bts_path_inflight_bts == 0)) {
			/* skip dec */
		} else if (--qp_info->bts_path_inflight_bts == 0) {
			drained_to_zero = true;
		}

		if (qp_info->n_dispatched_unacked == 0) {
			/* skip dec: post-reset cancellations land here */
		} else if (--qp_info->n_dispatched_unacked == 0) {
			qp_info->last_dispatched_class = OPCLASS_NONE;
			bulksvc_release_bts_gate(info->qp);
		}
		spin_unlock_irqrestore(&info->qp->s_lock, flags);

		if (drained_to_zero &&
		    !list_empty(&qp_info->deferred_wrs) &&
		    !qp_info->gate_retry_pending) {
			qp_info->gate_retry_pending = true;
			atomic_inc(&qp_info->verbs_state->gate_retry_pending_count[qp_info->lane]);
			hfi2_bulksvc_schedule_lane(svc, qp_info->lane);
		}

		rvt_put_qp(info->qp);
		kmem_cache_free(svc->verbs_sge_cache, info);
	}
}

static bool verbs_ordered_wr_succeeded(const struct verbs_ordered_wr *wr)
{
	if (wr->type == ORDERED_WR_RDMAVT) {
		const struct hfi2_bulksvc_verbs_cmd *cmd =
			container_of(wr, struct hfi2_bulksvc_verbs_cmd, ord_wr);

		return cmd->rdma.txreq->bts_rc == IB_WC_SUCCESS;
	}

	const struct direct_rdma_sge_info *si =
		container_of(wr, struct direct_rdma_sge_info, ord_wr);

	return si->status == IB_WC_SUCCESS;
}

/*
 * Transition @qp to IB_QPS_ERR from the BTS worker thread (outside r/s locks)
 * and dispatch IB_EVENT_QP_LAST_WQE_REACHED if needed.
 */
static void verbs_error_qp(struct rvt_qp *qp, enum ib_wc_status err)
{
	int lastwqe;

	if (!qp)
		return;
	lastwqe = rvt_error_qp(qp, err, RVT_QP_LOCK_STATE_NONE);
	if (lastwqe && qp->ibqp.event_handler) {
		struct ib_event ev = {
			.device = qp->ibqp.device,
			.element.qp = &qp->ibqp,
			.event = IB_EVENT_QP_LAST_WQE_REACHED,
		};

		qp->ibqp.event_handler(&ev, qp->ibqp.qp_context);
	}
}

/*
 * An OOO completion is impossible in health (chaining enforces CQE order), so a
 * held successor whose predecessor instead retires SUCCESS in order -- no
 * failure, no replay -- is a fatal ordering violation: error the QP rather than
 * deliver the successor as if it were in order.  Held slots are reaped on the
 * ULP's RESET (verbs_gbn_teardown_drain).  Lock context matches
 * verbs_gbn_replay_drop's rvt_error_qp (caller holds no r/s lock).
 */
static void ordering_check_held_violation(struct hfi2_bulksvc_verbs_ordering *ord,
					  struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_qp_info *qp_info =
		container_of(ord, struct hfi2_bulksvc_qp_info, ordering);

	if (!qp_info->held_count || qp_info->gbn_window_active)
		return;
	if (qp_info->gbn_stop_replay)
		return;

	WARN_ON_ONCE(1);
	qp_info->ordering.dms->counters.held_for_ordering_faulted++;
	verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);
	qp_info->gbn_stop_replay = true;
}

static void ordering_retire(struct hfi2_bulksvc_verbs_ordering *ord,
			    struct verbs_ordered_wr *wr,
			    struct hfi2_bulksvc *svc)
{
	bool wr_ok;

	if (wr->seq != ord->next_deliver_seq) {
		ord->dms->counters.cqe_tx_out_of_order++;
		ordering_insert_pending(ord, wr);
		return;
	}

	wr_ok = verbs_ordered_wr_succeeded(wr);

	ord->next_deliver_seq++;
	ordering_deliver_one(wr, svc);

	/* In-order SUCCESS with held successors and no window is fatal. */
	if (wr_ok)
		ordering_check_held_violation(ord, svc);

	while (!list_empty(&ord->pending)) {
		struct verbs_ordered_wr *p =
			list_first_entry(&ord->pending,
					 struct verbs_ordered_wr, node);
		if (p->seq != ord->next_deliver_seq)
			break;
		list_del_init(&p->node);
		ord->next_deliver_seq++;
		ordering_deliver_one(p, svc);
	}
}

static inline void verbs_ordering_retire_wr(
				struct hfi2_bulksvc_verbs_ordering *ord,
				struct hfi2_bulksvc_verbs_cmd *cmd,
				struct hfi2_bulksvc *svc)
{
	cmd->ord_wr.type = ORDERED_WR_RDMAVT;
	hfi2_bulksvc_verbs_cmd_get(cmd);
	ordering_retire(ord, &cmd->ord_wr, svc);
}

static void
bulksvc_on_verbs_mr_accessed(union hfi2_dms_completion_cookie *cookie,
			     u16 flags, u64 imm_data, u64 order_key,
			     int status);

static void verbs_inflight_remove(struct hfi2_bulksvc_qp_info *qp_info,
				  u32 ring_slot);
static void verbs_inflight_cancel_others(struct hfi2_bulksvc_qp_info *qp_info,
					 struct hfi2_dms *dms,
					 u32 failing_slot);
static void verbs_deferred_retry(struct hfi2_bulksvc_qp_info *qp_info);
static void verbs_deferred_free(struct verbs_deferred_wr *def);
static void verbs_gbn_window_replay(struct hfi2_bulksvc_qp_info *qp_info);
static u64 verbs_gbn_replay_mr_offset(const struct verbs_gbn_replay *rep);
static void verbs_gbn_replay_fill_pp_result(const struct verbs_gbn_replay *rep,
					    struct verbs_pp_result *out);
static void bulksvc_direct_cmd_rdma_complete(
	union hfi2_dms_completion_cookie * const cookie, int status);

/*
 * The DMS NACK handler translates each err_type to an errno; map those
 * back onto the IBA wc.status codes that ULPs branch on.  Unmapped
 * errnos fall back to IB_WC_GENERAL_ERR (the previous behaviour).
 *
 * -EMSGSIZE  (TRANSFER_SIZE_VIOLATION) corresponds to NAK code 1 on the
 *            wire and surfaces as IB_WC_REM_INV_REQ_ERR on the
 *            use_bulksvc=N path (rc.c, NAK syndrome 1).
 * -EBUSY     (ACCESS_BUSY) post-retry-exhaustion is the closest spec
 *            analog of a permanent responder-resource failure; bare-wire
 *            RC retries it transparently and would not surface a CQE at
 *            all.  REM_OP_ERR is the least-bad approximation here.
 */
static enum ib_wc_status dms_status_to_wc_status(int status)
{
	if (status == 0)
		return IB_WC_SUCCESS;

	switch (status) {
	case -EACCES:
	case -EINVAL:
		return IB_WC_REM_ACCESS_ERR;
	case -EMSGSIZE:
		return IB_WC_REM_INV_REQ_ERR;
	case -ENOMEM:
	case -EBUSY:
	case -EPROTO:
		return IB_WC_REM_OP_ERR;
	default:
		return IB_WC_GENERAL_ERR;
	}
}

/*
 * A retryable root error: fast-fail makes the initiator tracker cancel with
 * -ETIMEDOUT, and the sibling cancel walk forces -ECANCELED.  Both are
 * capture-eligible; non-retryable errors take the normal terminal path.
 */
static bool gbn_armable(int status)
{
	return status == -ETIMEDOUT || status == -ECANCELED;
}

/*
 * True when the slot is parked with a valid replay record, ready to be
 * replayed.
 */
static bool verbs_gbn_slot_awaiting_replay(struct hfi2_bulksvc_qp_info *qp_info,
				    u32 ring_slot)
{
	struct verbs_inflight_wr *inf;

	if (ring_slot == VERBS_INFLIGHT_NO_SLOT)
		return false;
	inf = &qp_info->inflight_ring[ring_slot & qp_info->inflight_mask];
	return inf->state == INFLIGHT_AWAITING_REPLAY;
}

/*
 * Classify a completion: NONE (retire normally), CAPTURE (absorb/arm a GBN
 * window), or HOLD (park a successful out-of-order READ/WRITE for the
 * predecessor's coming replay).  HOLD is reached only in the no-window tail,
 * after every window/awaiting-replay case returns, so a replayed WR is never
 * re-classified as a fresh hold.
 */
enum verbs_gbn_action {
	GBN_ACTION_NONE = 0,
	GBN_ACTION_CAPTURE,
	GBN_ACTION_HOLD,
};

static enum verbs_gbn_action
verbs_gbn_classify(struct hfi2_bulksvc_qp_info *qp_info,
		   u32 ring_slot, u64 seq, int status, bool is_send)
{
	struct verbs_inflight_wr *inf;

	/*
	 * Health-protocol mode: GBN never captures or replays; every failing
	 * WR takes its ordinary terminal path so DMS health recovery owns
	 * retransmission.
	 */
	if (!hfi2_dms_fast_fail_enabled())
		return GBN_ACTION_NONE;
	/*
	 * A synchronous completion fired mid re-submit must NOT re-enter
	 * capture/arm; a replayed WR that fails inline takes the ordinary
	 * terminal path this once and is re-caught by a fresh window on its
	 * next natural failure after gbn_replaying clears.
	 */
	if (qp_info->gbn_replaying)
		return GBN_ACTION_NONE;
	if (verbs_gbn_slot_awaiting_replay(qp_info, ring_slot))
		return GBN_ACTION_CAPTURE;
	if (ring_slot == VERBS_INFLIGHT_NO_SLOT)
		return GBN_ACTION_NONE;
	inf = &qp_info->inflight_ring[ring_slot & qp_info->inflight_mask];
	if (inf->state != INFLIGHT_ACTIVE)
		return GBN_ACTION_NONE;
	if (is_send) {
		/*
		 * SEND is a passenger only: it may ride an existing window as a
		 * cohort member [base, head) but never arms one, and never holds
		 * (it rides the independent go-back-1 health protocol).
		 */
		if (!qp_info->gbn_window_active)
			return GBN_ACTION_NONE;
		if (!gbn_armable(status))
			return GBN_ACTION_NONE;
		if ((u32)(inf->issue_cursor - qp_info->gbn_window_base) <
		    (u32)(qp_info->gbn_window_head - qp_info->gbn_window_base))
			return GBN_ACTION_CAPTURE;
		return GBN_ACTION_NONE;
	}
	if (qp_info->gbn_window_active) {
		/*
		 * Only members of the armed cohort [base, head) may be
		 * captured while a window drains.
		 */
		if ((u32)(inf->issue_cursor - qp_info->gbn_window_base) <
		    (u32)(qp_info->gbn_window_head - qp_info->gbn_window_base))
			return GBN_ACTION_CAPTURE;

		/* Capture a new base if failing WR is lower than the current base. */
		if ((u32)(inf->issue_cursor - qp_info->inflight_tail) <
		    (u32)(qp_info->gbn_window_base - qp_info->inflight_tail))
			return gbn_armable(status) ? GBN_ACTION_CAPTURE
						   : GBN_ACTION_NONE;

		qp_info->ordering.dms->counters.gbn_intercept_declined++;
		return GBN_ACTION_NONE;
	}
	if (gbn_armable(status))
		return GBN_ACTION_CAPTURE;
	/* Success + out-of-order, no window: hold for the predecessor's replay. */
	if (!status && seq != qp_info->ordering.next_deliver_seq)
		return GBN_ACTION_HOLD;
	return GBN_ACTION_NONE;
}

/*
 * Move the cookie's already-built, already-pinned page provider into the
 * slot's replay record and NULL the cookie pointers so the completion handler
 * frees nothing.  Exactly one of {multiseg, pageset} is set.
 */
static void verbs_gbn_claim_provider(struct verbs_gbn_replay *rep,
				     struct bts_verbs_pageset **cookie_pageset,
				     struct verbs_multiseg_ctx **cookie_multiseg)
{
	rep->pageset = *cookie_pageset;
	rep->multiseg = *cookie_multiseg;
	*cookie_pageset = NULL;
	*cookie_multiseg = NULL;
}

/*
 * Free a parked record's claimed page provider.  Pure memory release
 * (bts_verbs_pageset_put defers the unmap to a workqueue), so this is safe
 * in any context; there is no live tracker.
 */
static void verbs_gbn_free_provider(struct verbs_gbn_replay *rep)
{
	if (rep->multiseg) {
		u32 seg;

		for (seg = 0; seg < rep->multiseg->nsegs; seg++)
			bts_verbs_pageset_put(rep->multiseg->segs[seg].pageset);
		kfree(rep->multiseg);
	} else if (rep->pageset) {
		bts_verbs_pageset_put(rep->pageset);
	}
	rep->multiseg = NULL;
	rep->pageset = NULL;
}

/*
 * True while a claimed page set can still service a copy.  A device-only set
 * keeps its pin state alive by reference, but the pages themselves are
 * unpinned eagerly when the MR is unregistered, so the set can outlive the
 * mappings a replay would walk.
 */
static bool verbs_gbn_pageset_live(struct bts_verbs_pageset *ps)
{
	if (!ps)
		return false;
	if (ps->mem_type != RVT_MEM_DMABUF_DO)
		return true;
	return hfi2_dmabuf_iomem_table_live(ps->dma_buf_do_priv);
}

/*
 * A replay reuses the provider pinned at submit, so it must not be re-issued
 * once that memory is gone: the copy would read a torn-down mapping.
 */
static bool verbs_gbn_replay_provider_live(struct verbs_gbn_replay *rep)
{
	if (rep->multiseg) {
		for (u32 seg = 0; seg < rep->multiseg->nsegs; seg++)
			if (!verbs_gbn_pageset_live(rep->multiseg->segs[seg].pageset))
				return false;
		return true;
	}
	return verbs_gbn_pageset_live(rep->pageset);
}

/*
 * Start window replay once the cohort has fully drained -- but only if we are
 * not nested inside a synchronous cancel walk (verbs_inflight_cancel_others
 * fires sibling completions inline).
 */
static void verbs_gbn_try_replay(struct hfi2_bulksvc_qp_info *qpi)
{
	if (!qpi->gbn_window_active || qpi->gbn_drain_remaining != 0)
		return;
	if (qpi->inflight_cancel_walk)
		return;
	/*
	 * Re-entry guard: window_replay resubmits WRs that can complete
	 * inline and re-enter this path; gbn_replaying is held across the
	 * replay loop, so bail rather than recurse into a nested replay.
	 */
	if (qpi->gbn_replaying)
		return;
	verbs_gbn_window_replay(qpi);
}

/*
 * Capture one fast-fail-cancelled WR into the per-QP replay window.
 *
 * One-shot per slot: a slot already parked AWAITING_REPLAY is not re-captured
 * (no double decrement).  The first capture ARMS the window over the live
 * cohort [tail, head) and -- since the arming (failing) WR enters here and
 * skips the normal terminal path that would have cancelled siblings -- drives
 * verbs_inflight_cancel_others() exactly once to generate the siblings'
 * -ECANCELED completions.  Those nest synchronously and re-enter here; the
 * last one drives drain to 0 but replay is deferred past the walk by
 * verbs_gbn_try_replay().
 */
static void verbs_gbn_capture(struct hfi2_bulksvc_qp_info *qpi,
			      u32 ring_slot,
			      struct bts_verbs_pageset **cookie_pageset,
			      struct verbs_multiseg_ctx **cookie_multiseg,
			      struct hfi2_bulksvc_verbs_cmd *cmd,
			      struct direct_rdma_sge_info *sge_info,
			      u64 rbuf_start_offset, u64 order_key,
			      bool is_read, bool is_send, bool hold_only)
{
	u32 slot = ring_slot & qpi->inflight_mask;
	struct verbs_inflight_wr *inf = &qpi->inflight_ring[slot];
	struct verbs_gbn_replay *rep = &inf->replay;
	bool did_arm = false;
	bool did_widen = false;

	if (inf->state == INFLIGHT_AWAITING_REPLAY)
		return;
	if (inf->state != INFLIGHT_ACTIVE)
		return;

	if (is_send && !qpi->gbn_window_active) {
		WARN_ON_ONCE(1);
		return;
	}

	if (hold_only) {
		/* Passive park only: no arm/cohort/cancel/replay; handle is
		 * already recycled so there is nothing to cancel.
		 */
	} else if (!qpi->gbn_window_active && !is_send) {
		u32 new_base = inf->issue_cursor;
		u32 cur;
		u32 cohort = 0;

		/*
		 * Suffix arm.  base is the FAILING WR's issue_cursor.  WRs
		 * prior to it are left in flight and complete via their normal
		 * completion path; the failing WR and everything after it is
		 * captured into a replay record and replayed.
		 *
		 * The drain COUNTS the whole live ring [tail, head) and is
		 * decremented as completions arrive.  When it reaches zero the
		 * replay is triggered.
		 */
		for (cur = qpi->inflight_tail; cur != qpi->inflight_head;
		     cur++) {
			struct verbs_inflight_wr *cinf =
				&qpi->inflight_ring[cur & qpi->inflight_mask];

			if (cinf->state == INFLIGHT_ACTIVE)
				cohort++;
		}
		qpi->gbn_window_active = true;
		qpi->gbn_window_base = new_base;
		qpi->gbn_window_head = qpi->inflight_head;
		qpi->gbn_drain_remaining = cohort;
		if (new_base != qpi->inflight_tail) {
			qpi->gbn_anchor_valid = true;
			qpi->gbn_anchor_cursor = new_base - 1;
			qpi->ordering.dms->counters.gbn_suffix_prefix_spared +=
				(u32)(new_base - qpi->inflight_tail);
		} else {
			qpi->gbn_anchor_valid = false;
		}
		qpi->ordering.dms->counters.gbn_windows_armed++;
		did_arm = true;
	} else if (!is_send &&
		   (u32)(inf->issue_cursor - qpi->inflight_tail) <
			   (u32)(qpi->gbn_window_base - qpi->inflight_tail)) {
		/* Backward widening. For an older WR that fast-fails. */
		qpi->gbn_window_base = inf->issue_cursor;
		if (qpi->gbn_window_base != qpi->inflight_tail) {
			qpi->gbn_anchor_valid = true;
			qpi->gbn_anchor_cursor = qpi->gbn_window_base - 1;
		} else {
			qpi->gbn_anchor_valid = false;
		}
		did_widen = true;
	}

	verbs_gbn_claim_provider(rep, cookie_pageset, cookie_multiseg);
	qpi->ordering.dms->counters.gbn_provider_claimed++;
	rep->cmd = cmd;
	rep->sge_info = sge_info;
	rep->is_read = is_read;
	/*
	 * Re-derive all the attributes necessary for resubmission on either
	 * the hotpath or rdmavt path.
	 */
	rep->rbuf_start_offset = rbuf_start_offset;
	rep->order_key = order_key;
	if (cmd) {
		struct verbs_txreq *txreq = cmd->rdma.txreq;
		struct rvt_qp *cqp = cmd->rdma.qp_info->owner;
		u32 client_id =
			VERBS_PD_TO_CLIENT_ID(cqp->ibqp.pd->res.id);
		u32 opcode = txreq->wqe->wr.opcode;

		rep->remote_lid = cqp->remote_ah_attr.opa.dlid;
		if (is_send) {
			/*
			 * A SEND carries no remote rkey/addr -- those WQE union
			 * bytes alias ex.imm_data.  Routing is by destination
			 * QPN in dms_key.access with remote_addr 0, mirroring
			 * bulksvc_on_qp_cmd_send / the hotpath submit.
			 */
			rep->remote_addr = 0;
			rep->dms_key = (union hfi2_dms_key){
				.access = txreq->qp->remote_qpn,
				.client = 0,
			};
		} else {
			rep->remote_addr = txreq->wqe->rdma_wr.remote_addr;
			rep->dms_key = (union hfi2_dms_key){
				.access = txreq->wqe->rdma_wr.rkey,
				.client = client_id,
			};
		}
		rep->size = txreq->wqe->length;
		rep->remote_qpn = txreq->qp->remote_qpn;
		rep->is_send = is_send;
		rep->is_imm = (opcode == IB_WR_BULKSVC_WRITE_WITH_IMM ||
			       opcode == IB_WR_BULKSVC_SEND_WITH_IMM);
		rep->solicited =
			!!(txreq->wqe->wr.send_flags & IB_SEND_SOLICITED);
		rep->imm_data = txreq->wqe->wr.ex.imm_data;
	} else if (sge_info) {
		rep->remote_lid = sge_info->remote_lid;
		rep->remote_addr = sge_info->remote_addr;
		rep->dms_key = sge_info->dms_key;
		rep->size = sge_info->byte_len;
		rep->remote_qpn = sge_info->remote_qpn;
		rep->is_send = sge_info->is_send;
		rep->is_imm = sge_info->is_imm;
		rep->solicited = sge_info->solicited;
		rep->imm_data = sge_info->user_imm_be;
	}
	if (!hold_only && !WARN_ON_ONCE(qpi->gbn_drain_remaining == 0))
		qpi->gbn_drain_remaining--;

	inf->replay_gen++;

	WARN_ON_ONCE(!is_send &&
		     inf->replay_gen >= (GBN_ORDER_KEY_GEN_MASK / 2));

	/*
	 * replay_attempts is the budget of times a WR may be the ROOT failure
	 * that arms or widens a window.
	 */
	if (did_arm || did_widen)
		inf->replay_attempts++;

	inf->held_for_ordering = hold_only;
	inf->state = INFLIGHT_AWAITING_REPLAY;

	if (hold_only) {
		inf->handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		qpi->held_count++;
		qpi->ordering.dms->counters.held_for_ordering_armed++;
		return;
	}

	/*
	 * The failing WR skipped the normal terminal path, so nothing
	 * cancelled its siblings; drive the cancel here.  On a widen this
	 * re-drives it over the newly-lowered [base, head); cancel_others is
	 * base-aware and skips already-parked slots, and this slot is now
	 * AWAITING_REPLAY so it is skipped too.  The resulting -ECANCELED
	 * completions nest and are swallowed above.
	 */
	if (did_arm || did_widen) {
		WARN_ON_ONCE(inf->handle.value == 0);
		verbs_inflight_cancel_others(qpi, qpi->ordering.dms, slot);
	}

	verbs_gbn_try_replay(qpi);
}

static void
verbs_ordering_complete(union hfi2_dms_completion_cookie *cookie, int status)
{
	struct qp_rdma_cmpl_cookie * const rdma_cookie =
		(struct qp_rdma_cmpl_cookie *)cookie;
	struct hfi2_bulksvc_verbs_cmd * const cmd = rdma_cookie->cmd;
	struct hfi2_bulksvc * const svc = rdma_cookie->svc;
	struct hfi2_bulksvc_verbs_ordering *ord =
		&cmd->rdma.qp_info->ordering;

	bool is_read =
		(cmd->rdma.txreq->wqe->wr.opcode == IB_WR_BULKSVC_READ);
	bool is_send =
		(cmd->rdma.txreq->wqe->wr.opcode == IB_WR_BULKSVC_SEND ||
		 cmd->rdma.txreq->wqe->wr.opcode == IB_WR_BULKSVC_SEND_WITH_IMM);

	enum verbs_gbn_action gbn_act =
		verbs_gbn_classify(cmd->rdma.qp_info, cmd->ord_wr.ring_slot,
				   cmd->ord_wr.seq, status, is_send);

	if (gbn_act != GBN_ACTION_NONE) {
		verbs_gbn_capture(cmd->rdma.qp_info, cmd->ord_wr.ring_slot,
				  &rdma_cookie->pageset, &rdma_cookie->multiseg,
				  cmd, NULL,
				  rdma_cookie->rbuf_start_offset,
				  rdma_cookie->order_key, is_read, is_send,
				  gbn_act == GBN_ACTION_HOLD);
		return;
	}

	if (status && !cmd->rdma.txreq->bts_rc)
		cmd->rdma.txreq->bts_rc = dms_status_to_wc_status(status);

	if (status && status != -ECANCELED &&
	    !cmd->rdma.qp_info->inflight_cancel_walk)
		verbs_inflight_cancel_others(cmd->rdma.qp_info,
					     cmd->rdma.qp_info->ordering.dms,
					     cmd->ord_wr.ring_slot);

	if (rdma_cookie->multiseg) {
		u32 seg;

		for (seg = 0; seg < rdma_cookie->multiseg->nsegs; seg++)
			bts_verbs_pageset_put(rdma_cookie->multiseg->segs[seg].pageset);
		kfree(rdma_cookie->multiseg);
	} else {
		bts_verbs_pageset_put(rdma_cookie->pageset);
		if (rdma_cookie->remaining_wr_sges) {
			if (--(*rdma_cookie->remaining_wr_sges) > 0) {
				hfi2_bulksvc_verbs_cmd_put(cmd);
				return;
			}
			kfree(rdma_cookie->remaining_wr_sges);
		}
	}

	verbs_inflight_remove(cmd->rdma.qp_info, cmd->ord_wr.ring_slot);

	verbs_ordering_retire_wr(ord, cmd, svc);
	verbs_deferred_retry(cmd->rdma.qp_info);
	hfi2_bulksvc_verbs_cmd_put(cmd);
}

static void
verbs_ordering_notify(union hfi2_dms_completion_cookie *cookie, u16 flags,
		      u64 imm_data, u64 order_key, int status)
{
	bulksvc_on_verbs_mr_accessed(cookie, flags, imm_data, order_key, status);
}

static int
verbs_ordering_submit_read(struct hfi2_bulksvc_verbs_ordering *ord,
			   enum hfi2_dms_fabric_port_idx port_idx,
			   u32 src_lid, union hfi2_dms_key dms_key,
			   u64 key_offset_or_vaddr, u32 size,
			   struct hfi2_dms_page_provider page_provider,
			   u64 mr_offset,
			   u16 flags, u64 submit_flags, u64 imm_data,
			   struct hfi2_dms_completion completion,
			   u64 order_key,
			   struct hfi2_dms_transfer_handle parent_handle,
			   struct hfi2_dms_transfer_handle *out_handle)
{
	return hfi2_dms_read_data(ord->dms, port_idx, src_lid,
				  dms_key, key_offset_or_vaddr, size,
				  page_provider, mr_offset, flags, submit_flags, imm_data,
				  completion, order_key, parent_handle, out_handle);
}

static int
verbs_ordering_submit_write(struct hfi2_bulksvc_verbs_ordering *ord,
			    enum hfi2_dms_fabric_port_idx port_idx,
			    u32 dest_lid, union hfi2_dms_key dms_key,
			    u64 remote_offset, u32 size,
			    struct hfi2_dms_page_provider page_provider,
			    u64 mr_offset,
			    u16 flags, u64 submit_flags, u64 imm_data,
			    struct hfi2_dms_completion completion,
			    u64 order_key,
			    struct hfi2_dms_transfer_handle parent_handle,
			    struct hfi2_dms_transfer_handle *out_handle)
{
	return hfi2_dms_write_data(ord->dms, port_idx, dest_lid,
				   dms_key, remote_offset, size,
				   page_provider, mr_offset, flags, submit_flags, imm_data,
				   completion, order_key, parent_handle, out_handle);
}

/*
 * Sequence numbers are u64 (ordering.next_issue_seq) but inflight
 * ring operations use u32 casts.  This is safe because the ring
 * can hold at most inflight_size entries, so the u32 low bits
 * are always sufficient to distinguish in-flight slots.  The u64
 * width exists for the ordering layer's lifetime-unique sequences.
 */
static u32 verbs_inflight_depth(struct hfi2_bulksvc_qp_info *qp_info)
{
	return (qp_info->inflight_head - qp_info->inflight_tail) &
		(2 * qp_info->inflight_size - 1);
}

static bool verbs_inflight_full(struct hfi2_bulksvc_qp_info *qp_info)
{
	return verbs_inflight_depth(qp_info) >= qp_info->inflight_size;
}

/*
 * Append a WR to the inflight ring.  Stamps the slot it used into @ow so
 * completion/removal index the ring by the actual slot, NOT by ord_wr.seq.
 * The seq is the ordering-layer sequence and advances on paths that never
 * add to the ring (on_err_pre_ord, deferred-WR flush), so it must not be
 * the ring index.  On rejection (ring full) @ow->ring_slot is left as the
 * caller's sentinel and nothing is added.
 */
static int
verbs_inflight_add(struct hfi2_bulksvc_qp_info *qp_info,
		   struct verbs_ordered_wr *ow,
		   u32 num_sge)
{
	u32 slot;
	struct verbs_inflight_wr *inf;

	if (verbs_inflight_full(qp_info))
		return -ENOMEM;

	slot = qp_info->inflight_head & qp_info->inflight_mask;
	inf = &qp_info->inflight_ring[slot];
	if (WARN_ON_ONCE(num_sge > hfi2_max_sges))
		return -EINVAL;
	inf->state = INFLIGHT_ACTIVE;
	inf->handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	memset(&inf->replay, 0, sizeof(inf->replay));
	inf->replay_attempts = 0;
	inf->replay_gen = 0;
	inf->issue_cursor = qp_info->inflight_head;
	inf->held_for_ordering = false;
	qp_info->inflight_head++;
	ow->ring_slot = slot;
	return 0;
}

static void verbs_inflight_complete(struct hfi2_bulksvc_qp_info *qp_info,
				    u32 ring_slot)
{
	struct verbs_inflight_wr *inf = &qp_info->inflight_ring[ring_slot];

	/*
	 * A WR older than the lowest failed cursor [tail, base) was counted into
	 * the cohort at arm but left un-cancelled, so its normal completion
	 * decrements the drain here.
	 */
	if (qp_info->gbn_window_active &&
	    inf->state == INFLIGHT_ACTIVE &&
	    (u32)(inf->issue_cursor - qp_info->inflight_tail) <
	    (u32)(qp_info->gbn_window_base - qp_info->inflight_tail)) {
		if (!WARN_ON_ONCE(qp_info->gbn_drain_remaining == 0))
			qp_info->gbn_drain_remaining--;
	}
	inf->state = INFLIGHT_COMPLETED;
}

static void verbs_inflight_drain(struct hfi2_bulksvc_qp_info *qp_info)
{
	if (qp_info->inflight_cancel_walk)
		return;

	while (qp_info->inflight_tail != qp_info->inflight_head) {
		u32 slot = qp_info->inflight_tail & qp_info->inflight_mask;

		if (qp_info->inflight_ring[slot].state != INFLIGHT_COMPLETED)
			break;
		qp_info->inflight_ring[slot].handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		qp_info->inflight_ring[slot].state = INFLIGHT_EMPTY;
		qp_info->inflight_tail++;
	}
	/*
	 * Since everything is completed we know longer need to track this handle.
	 * Next op will have nothing to race against, also their are a finite number
	 * of handles, best to not risk collisions with other QPs
	 */
	if (qp_info->inflight_tail == qp_info->inflight_head)
		qp_info->chain_tail_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
}

/*
 * Retire a WR's ring slot.  @ring_slot must be the value stamped by
 * verbs_inflight_add (ord_wr.ring_slot).  VERBS_INFLIGHT_NO_SLOT means the
 * WR never entered the ring (deferred/errored-before-add/flushed) -- a
 * no-op, which is exactly what makes the ring immune to seq advancing past
 * inflight_head.
 */
static void verbs_inflight_remove(struct hfi2_bulksvc_qp_info *qp_info,
				  u32 ring_slot)
{
	if (ring_slot == VERBS_INFLIGHT_NO_SLOT)
		return;
	verbs_inflight_complete(qp_info, ring_slot);
	verbs_inflight_drain(qp_info);
	verbs_gbn_try_replay(qp_info);
}

/* Fatal-error sibling flush (BTS-driven). */
static void verbs_inflight_cancel_others(struct hfi2_bulksvc_qp_info *qp_info,
					 struct hfi2_dms *dms,
					 u32 failing_slot)
{
	/* Capture head/tail snapshots for go-back-n scenario. */
	u32 tail = qp_info->gbn_window_active ?
			   qp_info->gbn_window_base : qp_info->inflight_tail;
	u32 head = qp_info->gbn_window_active ?
			   qp_info->gbn_window_head : qp_info->inflight_head;

	bool suffix_scoped = (qp_info->gbn_window_active &&
			      tail != qp_info->inflight_tail);

	dms->counters.bts_inflight_cancel_events++;
	qp_info->inflight_cancel_walk = true;

	/*
	 * Walk newest->oldest (head-1 .. tail).  Cohort WRs are serially
	 * chained, so the near-head members are parked/idle while the near-base
	 * member is the one actively transmitting; cancelling from the idle end
	 * inward freezes those slots before an upstream completion can release.
	 */
	for (u32 cur = head; cur != tail; ) {
		u32 slot = (--cur) & qp_info->inflight_mask;
		struct verbs_inflight_wr *inf = &qp_info->inflight_ring[slot];

		if (inf->state == INFLIGHT_ACTIVE) {
			bool is_failing = (slot == failing_slot);

			/* One handle per WR; the failing slot retires via its
			 * own completion, so skip it here. */
			if (!is_failing && inf->handle.value != 0) {
				int rc = hfi2_dms_cancel_tracker_by_handle(
					dms, inf->handle, -ECANCELED);
				if (rc == 0) {
					dms->counters.bts_inflight_cancel_siblings++;
				} else if (rc == -ENOENT) {
					/*
					 * Sibling's tracker already retired; its
					 * own real completion will arrive and drive
					 * capture/replay (armable) or normal retire
					 * (in-order success).
					 */
					dms->counters.bts_inflight_cancel_already_gone++;
				} else {
					WARN_ON_ONCE(1);
					dms->counters.bts_inflight_cancel_failed++;
				}
			}

		}
	}

	/*
	 * No live prefix survives (no window, or window base at the ring
	 * tail): the whole ring is cancelled, so reset the chain anchor to
	 * NONE and the first replay starts a fresh chain.
	 */
	if (!suffix_scoped)
		qp_info->chain_tail_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;

	qp_info->inflight_cancel_walk = false;
	verbs_inflight_drain(qp_info);
}

/*
 * Resolve one rvt_sge to a counted page set + byte offset within the MR.
 *
 * Contract (b): on success returns a *counted page set* ref in
 * @pageset_out (caller hands it straight into segs[].pageset /
 * cookie->pageset and releases it once in verbs_ordering_complete).  The
 * transient mr_record lookup ref is taken and dropped entirely inside
 * this function - callers never see an mr_record.  This keeps the two
 * call sites (multiseg build loop and per-SGE fallback) free of any
 * mr_record bookkeeping in the pageset model.
 */
static int verbs_resolve_sge(struct hfi2_bulksvc * const svc,
			     struct rvt_sge const * const sge,
			     struct bts_verbs_pageset **pageset_out,
			     u64 *user_base_offset_out)
{
	struct rvt_mregion * const mr = sge->mr;
	struct bts_verbs_mr_record *mr_record;
	struct bts_verbs_pageset *ps;
	struct rvt_dev_info *rdi;
	u32 const sge_size = sge->sge_length;
	u64 user_base_offset = 0;

	if (WARN_ON(!mr || !mr->pd)) {
		pr_err("No mregion associated with rdma op\n");
		return -ENOENT;
	}

	/* O(1) RCU lkey-table lookup; returns a held ref we must drop. */
	rdi = ib_to_rvt(mr->pd->device);
	mr_record = bulksvc_verbs_find_mr_record(rdi, mr->pd, mr->lkey);
	if (!mr_record || !READ_ONCE(mr_record->registered)) {
		if (mr_record)
			bts_verbs_mr_record_put(mr_record);
		dd_dev_err_ratelimited(svc->dd, "%s:%d:%s() verbs RDMA OP trying to use unknown/unregistered MR\n",
				       __FILENAME__, __LINE__, __func__);
		return -ENOENT;
	}

	if (mr->page_shift) {
		user_base_offset = ((sge->m * RVT_SEGSZ) + sge->n) *
			(1 << mr->page_shift);
	} else {
		int m, n;

		for (int i = 0; i < sge->m * RVT_SEGSZ + sge->n; i++) {
			m = i / RVT_SEGSZ;
			n = i % RVT_SEGSZ;
			user_base_offset += mr->map[m]->segs[n].length;
		}
	}
	user_base_offset += mr->map[sge->m]->segs[sge->n].length - sge->mem.length;
	user_base_offset -= mr->offset;

	if (WARN_ON(user_base_offset > mr->length)) {
		pr_err("%s:%d:%s(): Calculated local offset %llu is larger than mr size %u\n",
		       __FILENAME__, __LINE__, __func__,
		       (unsigned long long)user_base_offset, sge_size);
		bts_verbs_mr_record_put(mr_record);
		return -EINVAL;
	}
	if (sge_size > mr->length - user_base_offset) {
		pr_err("%s:%d:%s(): Can't write %u bytes to mr with len %zu, offset %llu\n",
		       __FILENAME__, __LINE__, __func__, sge_size, mr->length,
		       (unsigned long long)user_base_offset);
		bts_verbs_mr_record_put(mr_record);
		return -EINVAL;
	}

	/* Latch the current page set, then drop the mr_record ref: the
	 * page set carries its own kref and is what survives in the cookie.
	 */
	ps = bts_verbs_pageset_get_current(mr_record);
	bts_verbs_mr_record_put(mr_record);
	if (WARN_ON_ONCE(!ps))
		return -ENOENT;

	*pageset_out = ps;
	*user_base_offset_out = user_base_offset;
	return 0;
}

/* Resolver for rdmavt-path WQEs (txreq sg_list of rvt_sge). */
struct verbs_rdmavt_rctx {
	struct hfi2_bulksvc *svc;
	struct rvt_sge *sg_list;
	u32 lane;
};

/*
 * Secondary lane: the MR_REG cmd for @lkey's MR is drained by the primary
 * lane, so unlike on the primary lane (one FIFO for reg and RDMA cmds) it
 * may not have run yet.  Wait, bounded, for the primary lane to register
 * it; an lkey without an MR record has nothing to wait for.  Returns the
 * registered record with a ref, or NULL.
 */
static struct bts_verbs_mr_record *
verbs_lane_wait_mr_registered(struct rvt_dev_info *rdi, struct ib_pd *pd,
			      u32 lkey)
{
	ktime_t const deadline = ktime_add_us(ktime_get(), 2000);
	struct bts_verbs_mr_record *rec;

	do {
		rec = bulksvc_verbs_find_mr_record(rdi, pd, lkey);
		if (!rec || READ_ONCE(rec->registered))
			return rec;
		bts_verbs_mr_record_put(rec);
		cpu_relax();
	} while (ktime_before(ktime_get(), deadline));
	return NULL;
}

static int verbs_rdmavt_resolve_seg(void *rctx, u32 idx,
				    struct verbs_src_segment *seg)
{
	struct verbs_rdmavt_rctx *c = rctx;
	struct rvt_mregion *mr = c->sg_list[idx].mr;
	struct bts_verbs_mr_record *rec;
	struct bts_verbs_pageset *ps;
	u64 ubo;
	int rc;

	if (c->lane != HFI2_BULKSVC_PRIMARY_LANE && mr && mr->pd) {
		rec = verbs_lane_wait_mr_registered(ib_to_rvt(mr->pd->device),
						    mr->pd, mr->lkey);
		if (rec)
			bts_verbs_mr_record_put(rec);
	}
	rc = verbs_resolve_sge(c->svc, &c->sg_list[idx], &ps, &ubo);
	if (rc)
		return rc;
	seg->pageset = ps;
	seg->base_byte_offset = ps->dms_mr.region_offset + ubo;
	seg->byte_length = c->sg_list[idx].sge_length;
	return 0;
}

/*
 * Resolver for hotpath WQEs (ib_sge from a uverbs post_send).  This is the
 * single home of the rkey-cache + try/drain/retry/fail MR lookup: the lookup
 * ref is cached in @cached_mr so SGEs sharing an lkey reuse it, and the caller
 * drops it exactly once after the helper returns (success or error).
 */
struct verbs_hotpath_rctx {
	struct hfi2_bulksvc *svc;
	u32 lane;
	struct rvt_dev_info *rdi;
	struct ib_pd *pd;
	struct ib_sge *sg_list;
	struct bts_verbs_mr_record *cached_mr;
};

static int verbs_hotpath_resolve_seg(void *rctx, u32 idx,
				     struct verbs_src_segment *seg)
{
	struct verbs_hotpath_rctx *c = rctx;
	struct ib_sge *sge = &c->sg_list[idx];
	struct bts_verbs_mr_record *mr = c->cached_mr;
	struct bts_verbs_pageset *ps;
	u32 verbs_cmds = 0;
	u64 ubo;

	if (!mr || mr->rkey != sge->lkey) {
		if (mr)
			bts_verbs_mr_record_put(mr);
		mr = bulksvc_verbs_find_mr_record(c->rdi, c->pd, sge->lkey);
	}

	/*
	 * A uverbs WR can overtake the MR-reg cmd that established its MR.
	 * MPSC FIFO order guarantees the reg cmd is queued ahead of us but may
	 * not be drained yet; drain reentrantly (we are the single consumer)
	 * before failing the WR.
	 *
	 * A pass that drains exactly bulksvc_poll_max_per_iter did not empty
	 * the queue, so the MR-reg cmd may still be buried; keep draining until
	 * the MR resolves or a pass drains fewer than the cap (queue emptied).
	 */
	if (c->lane != HFI2_BULKSVC_PRIMARY_LANE &&
	    (!mr || !READ_ONCE(mr->registered))) {
		if (mr)
			bts_verbs_mr_record_put(mr);
		mr = verbs_lane_wait_mr_registered(c->rdi, c->pd, sge->lkey);
	} else if (!mr || !READ_ONCE(mr->registered)) {
		unsigned int cap = READ_ONCE(bulksvc_poll_max_per_iter);

		if (mr) {
			bts_verbs_mr_record_put(mr);
			mr = NULL;
		}

		do {
			verbs_cmds = hfi2_bulksvc_poll_verbs_cmds(c->svc,
								  &c->svc->verbs_state.cmd_queue);
			mr = bulksvc_verbs_find_mr_record(c->rdi, c->pd,
							  sge->lkey);
			if (mr && READ_ONCE(mr->registered))
				break;
			if (mr) {
				bts_verbs_mr_record_put(mr);
				mr = NULL;
			}
		} while (cap && verbs_cmds == cap);
	}

	c->cached_mr = mr;	/* publish for next idx + caller cleanup */
	if (!mr || !READ_ONCE(mr->registered)) {
		dd_dev_warn_ratelimited(c->svc->dd,
					"%s:%d:%s verbs RDMA OP trying to use %s MR %u, extra_cmds_found = %u\n",
					__FILENAME__, __LINE__, __func__,
					mr && !READ_ONCE(mr->registered) ? "unreg'd" : "unknown",
					sge->lkey, verbs_cmds);
		return -ENOENT;
	}

	ps = bts_verbs_pageset_get_current(mr);
	if (!ps)
		return -ENOENT;

	ubo = sge->addr - ps->dms_mr.user.addr;
	if ((u64)sge->length + ubo > ps->dms_mr.user.len) {
		bts_verbs_pageset_put(ps);
		return -EINVAL;
	}

	seg->pageset = ps;
	seg->base_byte_offset = ps->dms_mr.region_offset + ubo;
	seg->byte_length = sge->length;
	return 0;
}

/*
 * Resolver for verbs SEND target landing: the popped RWQE's scatter list is
 * the first SGE inline in r_sge.sge and the remainder in r_sge.sg_list[].
 */
struct verbs_send_dest_rctx {
	struct hfi2_bulksvc *svc;
	struct rvt_sge_state *rss;
};

static int verbs_send_dest_resolve_seg(void *rctx, u32 idx,
				       struct verbs_src_segment *seg)
{
	struct verbs_send_dest_rctx *c = rctx;
	struct rvt_sge const *sge = (idx == 0) ?
		&c->rss->sge : &c->rss->sg_list[idx - 1];
	struct bts_verbs_pageset *ps;
	u64 ubo;
	int rc;

	rc = verbs_resolve_sge(c->svc, sge, &ps, &ubo);
	if (rc)
		return rc;
	seg->pageset = ps;
	seg->base_byte_offset = ps->dms_mr.region_offset + ubo;
	seg->byte_length = sge->sge_length;
	return 0;
}

/*
 * Shared SEND/WRITE/READ submission descriptor.
 *
 * One of these is built by each adapter (rdmavt on_qp command path or the
 * uverbs hotpath) and handed to bts_verbs_submit_one(), which performs the
 * single per-WQE DMS submission that is identical across all three opcode
 * families: it packs the SEND/WRITE_WITH_IMM imm/flags, builds one DMS page
 * provider for the whole WQE via convert_wqe_to_page_provider(), threads the
 * op onto the per-QP DMS chain, and issues exactly one hfi2_dms_{read,write}
 * op.  Everything that genuinely differs between paths -- the deferral/ring
 * admission decision, the concrete completion-cookie layout, the completion
 * function, and the path-local counters -- stays in the adapter.
 *
 * The completion (fn + cookie) is owned by the adapter; the adapter fills the
 * cookie's path-specific stable fields (e.g. the rdmavt cmd ref or the hotpath
 * sge_info) up front and points cookie_pageset/cookie_multiseg
 * at the matching cookie fields.  The core writes the provider backing and the
 * inflight handle index into those slots before the DMS submit, so the cookie
 * is fully populated even if the op completes inline.
 */
struct bts_submit_req {
	struct hfi2_bulksvc *svc;
	struct hfi2_bulksvc_verbs_ordering *ord;
	struct hfi2_bulksvc_qp_info *qp_info;
	struct verbs_inflight_wr *inf;

	u32 remote_lid;
	union hfi2_dms_key dms_key;
	u64 remote_addr;
	/*
	 * Explicit transfer size, or 0 to derive it from the built provider's
	 * total_bytes.  WRITE/READ pass their known WQE length here; SEND
	 * passes 0 so the aggregated source-gather length is used.  In every
	 * path the two are numerically equal (provider total_bytes == sum of
	 * SGE lengths == wqe length), so this only selects which source the
	 * core reads from.
	 */
	u32 size;
	u32 num_sge;
	gfp_t gfp;

	/* Opcode classification, drives flag/imm packing and gather direction. */
	bool is_read;
	bool is_send;
	bool is_imm;		/* WRITE_WITH_IMM or SEND_WITH_IMM */
	bool solicited;
	u32 remote_qpn;
	__be32 user_imm_be;	/* wr.ex.imm_data, big-endian on the wire */

	/* Per-WQE provider resolver (rdmavt rvt_sge vs hotpath ib_sge). */
	verbs_resolve_seg_fn resolve;
	void *rctx;

	/* Adapter-owned completion; core writes the provider/handle into the
	 * cookie via the binding pointers below.
	 */
	struct hfi2_dms_completion *completion;
	struct bts_verbs_pageset **cookie_pageset;
	struct verbs_multiseg_ctx **cookie_multiseg;
	u64 *cookie_rbuf_start_offset;	/* GBN replay needs the single-seg offset */
	u64 *cookie_order_key;		/* GBN replay needs the original order_key */

	bool is_replay;	/* GBN replay indicator flag. */
	const struct verbs_gbn_replay *replay_slot;
	u64 replay_order_key;	/* GBN replay submission needs to save the original order key. */
};

/*
 * Pack the DMS write imm_data + flags for the initiator side of a SEND,
 * SEND_WITH_IMM, or WRITE_WITH_IMM.  READ and plain WRITE carry neither, so
 * both outputs stay zero.  SEND routes via dms_key.access; only
 * WRITE_WITH_IMM carries destination qpn in imm_data[55:32].  This is the
 * single home of the wire packing shared by both submission paths.
 */
static int bts_submit_pack_flags(const struct bts_submit_req *req,
				 u16 *flags_out, u64 *imm_out)
{
	u16 flags = 0;
	u64 imm = 0;
	bool const needs_qpn_imm = (!req->is_read && req->is_imm);

	if (needs_qpn_imm && WARN_ON(req->remote_qpn >= (1 << 24)))
		return -EINVAL;

	if (req->is_send) {
		flags = HFI2_BULKSVC_VERBS_WRITE_FLAGS_SEND;
		if (req->is_imm) {
			flags |= HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT;
			imm |= be32_to_cpu(req->user_imm_be);
		}
	} else if (req->is_imm) {	/* WRITE_WITH_IMM */
		flags = HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT;
		imm = be32_to_cpu(req->user_imm_be);
		imm |= (u64)(req->remote_qpn & ((1 << 24) - 1)) << 32;
		/* One DMS op now carries the whole WQE. */
		imm |= 1ull << 56;
	}

	if (needs_qpn_imm && req->solicited)
		flags |= HFI2_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED;

	*flags_out = flags;
	*imm_out = imm;
	return 0;
}

/* Free the provider backing built by convert_wqe_to_page_provider(). */
static void bts_submit_free_provider(struct verbs_pp_result *out)
{
	if (out->multiseg) {
		u32 s;

		for (s = 0; s < out->multiseg->nsegs; ++s)
			bts_verbs_pageset_put(out->multiseg->segs[s].pageset);
		kfree(out->multiseg);
	} else if (out->pageset) {
		bts_verbs_pageset_put(out->pageset);
	}
}

/*
 * Shared SEND/WRITE/READ submission core.  Packs the wire imm/flags, builds
 * the one-op-per-WQE provider, threads the op onto the per-QP DMS chain, and
 * issues a single hfi2_dms_{read,write} via the ordering wrappers.  On success
 * the cookie binding slots are populated, the chain tail advances, and the
 * inflight slot's handle count grows by one.  On any failure no provider ref
 * leaks and the cookie's provider slots are cleared; the adapter owns the
 * remaining cookie ref (e.g. the rdmavt cmd ref) and its error retirement.
 */
static int bts_verbs_submit_one(struct bts_submit_req *req)
{
	enum verbs_pp_dir const dir = req->is_read ? VERBS_PP_DEST :
						     VERBS_PP_SOURCE;
	struct verbs_inflight_wr * const inf = req->inf;
	struct verbs_pp_result out;
	struct hfi2_dms_transfer_handle *out_handle;
	struct hfi2_dms_transfer_handle wqe_parent;
	enum hfi2_dms_fabric_port_idx port_idx;
	struct hfi2_bulksvc_qp_info *qp_info;
	struct rvt_qp *qp;
	struct hfi2_pportdata *ppd;
	u16 flags;
	u64 imm_data, order_key, qp_num, local_lid, mr_offset;
	u32 xfer_size;
	int rc;

	qp_info = req->qp_info;
	qp = qp_info->owner;
	ppd = READ_ONCE(qp_info->ppd);
	local_lid = ppd->lid;
	qp_num = qp->ibqp.qp_num;
	port_idx = ppd->hw_pidx;

	if (WARN_ON_ONCE(req->is_replay &&
			 (req->cookie_pageset || req->resolve || req->num_sge)))
		return -EINVAL;

	rc = bts_submit_pack_flags(req, &flags, &imm_data);
	if (rc)
		return rc;

	/* Replay mode does not rederive page provider, order_key, and mr_offset. */
	if (req->is_replay) {
		verbs_gbn_replay_fill_pp_result(req->replay_slot, &out);
		order_key = req->replay_order_key;
		mr_offset = verbs_gbn_replay_mr_offset(req->replay_slot);
	} else {
		u16 seq_bits = req->is_send ? qp_info->tx_send_seq :
			       (req->is_imm ? qp_info->tx_wr_seq : 0);
		order_key = ((u64)seq_bits << 48) |
			    (local_lid << 32) | qp_num;
		order_key |= (u64)(inf->replay_gen & GBN_ORDER_KEY_GEN_MASK)
			     << GBN_ORDER_KEY_GEN_SHIFT;

		rc = convert_wqe_to_page_provider(req->svc, req->num_sge, dir,
						  req->gfp, req->resolve,
						  req->rctx, &out);
		if (rc)
			return rc;
		mr_offset = verbs_pp_submit_mr_offset(&out, dir);

		/* Publish the built provider/key so the completion (or a future
		 * GBN capture) can retrieve them; a replay caller owns its cookie.
		 */
		*req->cookie_pageset = out.pageset;
		*req->cookie_multiseg = out.multiseg;
		if (req->cookie_rbuf_start_offset)
			*req->cookie_rbuf_start_offset = out.rbuf_start_offset;
		if (req->cookie_order_key)
			*req->cookie_order_key = order_key;
	}

	xfer_size = req->size ? req->size : (u32)out.total_bytes;

	out_handle = &inf->handle;
	wqe_parent = qp_info->chain_tail_handle;

	/*
	 * Per-submission policy bits (see enum hfi2_dms_submit_flags). Ordered
	 * transfers always set PARK_ON_PARENT_ERROR; FAST_FAIL (and the replay
	 * count) are added only in GBN mode, where FAST_FAIL makes initiator
	 * trackers cancel instead of replaying so the verbs layer owns retry.
	 * In health mode the flag is omitted so DMS runs in-place recovery.
	 */
	u64 submit_flags = HFI2_DMS_SUBMIT_PARK_ON_PARENT_ERROR;
	/*
	 * SENDs keep fast_fail OFF: the health protocol owns SEND recovery, and
	 * a SEND must never fast-fail/arm a GBN window (it may only ride one as
	 * a passenger via a sibling cancel).
	 */
	if (hfi2_dms_fast_fail_enabled() && !req->is_send) {
		submit_flags |= HFI2_DMS_SUBMIT_FAST_FAIL;
		submit_flags = hfi2_dms_submit_flags_set_stale_shift(submit_flags,
								     inf->replay_attempts);
	}
	/*
	 * Read peer_lane after the admit gate's dms.remote load; pairs with
	 * the rcu_assign_pointer() in hfi2_dms_set_remote().
	 */
	smp_rmb();
	submit_flags = hfi2_dms_submit_flags_set_target_lane(submit_flags,
							     READ_ONCE(qp_info->peer_lane));

	trace_verbs_dms_submit(qp_num, req->is_read, req->is_send,
			       req->is_imm, xfer_size, req->num_sge);

	if (req->is_read)
		rc = verbs_ordering_submit_read(req->ord, port_idx,
			req->remote_lid, req->dms_key, req->remote_addr,
			xfer_size, out.provider, mr_offset,
			0, submit_flags,
			0, *req->completion, order_key, wqe_parent, out_handle);
	else
		rc = verbs_ordering_submit_write(req->ord, port_idx,
			req->remote_lid, req->dms_key, req->remote_addr,
			xfer_size, out.provider, mr_offset,
			flags, submit_flags, imm_data, *req->completion,
			order_key, wqe_parent, out_handle);
	if (rc < 0) {
		pr_err("%s:%d:%s() Could not initiate DMS op: %d\n",
		       __FILENAME__, __LINE__, __func__, rc);
		/* A replay will be freed by the parked slot handler (verbs_gbn_replay_drop). */
		if (!req->is_replay) {
			bts_submit_free_provider(&out);
			*req->cookie_pageset = NULL;
			*req->cookie_multiseg = NULL;
		}
		return rc;
	}

	qp_info->chain_tail_handle = *out_handle;
	if (!req->is_replay) {
		if (req->is_send)
			qp_info->tx_send_seq++;
		else if (req->is_imm)
			qp_info->tx_wr_seq++;
	}
	return 0;
}

/*
 * Retire one parked GBN slot terminally: free the provider, post an error
 * CQE, and wipe the record.  Used when the replay budget is spent or a
 * re-submit fails.
 *
 * TODO: no wire-level "erroring, will not replay" notice is sent to the
 * peer.  A dropped WRITE_WITH_IMM leaves the receiver's rx_next_deliver ring
 * stalled at this wr_seq; it currently unwinds only via QP teardown/timeout.
 * A follow-on change should signal the peer to release the stalled slot.
 */
static void verbs_gbn_replay_drop(struct hfi2_bulksvc_qp_info *qp_info,
				  struct verbs_inflight_wr *inf)
{
	struct hfi2_bulksvc *svc = qp_info->ordering.svc;
	struct verbs_gbn_replay *rep = &inf->replay;
	bool live_prefix = qp_info->gbn_window_active &&
			   qp_info->gbn_window_base != qp_info->inflight_tail;

	if (live_prefix) {
		verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);
		qp_info->ordering.dms->counters.gbn_drop_qp_errored++;
		/* QP is ERR now: stop re-submitting; drop the rest of the window. */
		qp_info->gbn_stop_replay = true;
	}

	verbs_gbn_free_provider(rep);
	if (rep->cmd) {
		struct hfi2_bulksvc_verbs_cmd *cmd = rep->cmd;
		struct hfi2_bulksvc_verbs_ordering *ord =
			&cmd->rdma.qp_info->ordering;

		cmd->rdma.txreq->bts_rc = IB_WC_GENERAL_ERR;
		inf->state = INFLIGHT_COMPLETED;
		verbs_ordering_retire_wr(ord, cmd, svc);
		hfi2_bulksvc_verbs_cmd_put(cmd);
	} else if (rep->sge_info) {
		struct direct_rdma_sge_info *si = rep->sge_info;

		si->status = IB_WC_GENERAL_ERR;
		inf->state = INFLIGHT_COMPLETED;
		ordering_retire(si->ord, &si->ord_wr, si->ord->svc);
	}
	memset(rep, 0, sizeof(*rep));
	qp_info->ordering.dms->counters.gbn_wrs_dropped++;
}

/*
 * Recompute the initiator mr_offset for a replayed WR from the retained
 * provider, mirroring verbs_pp_submit_mr_offset() exactly.  Multiseg ignores
 * mr_offset (resolve_start returns 0).  For a collapsed single seg the offset
 * encoding differs by direction: a READ scatters into the DEST buffer (report
 * user.addr + (rbuf_start_offset - region_offset)); a WRITE gathers from the
 * SOURCE (report rbuf_start_offset verbatim, which already encodes user.addr).
 */
static u64 verbs_gbn_replay_mr_offset(const struct verbs_gbn_replay *rep)
{
	if (rep->multiseg)
		return 0;
	if (rep->is_read)
		return rep->pageset->dms_mr.user.addr +
		       (rep->rbuf_start_offset -
			rep->pageset->dms_mr.region_offset);
	return rep->rbuf_start_offset;
}

/*
 * Replay-mode counterpart to convert_wqe_to_page_provider(): rebuild a
 * verbs_pp_result from already-pinned memory.
 */
static void verbs_gbn_replay_fill_pp_result(const struct verbs_gbn_replay *rep,
					    struct verbs_pp_result *out)
{
	out->pageset = rep->pageset;
	out->multiseg = rep->multiseg;
	out->provider = rep->multiseg ?
		verbs_multiseg_page_provider(rep->multiseg) :
		verbs_mr_page_provider(rep->pageset);
	out->total_bytes = rep->size;
	out->rbuf_start_offset = rep->rbuf_start_offset;
}

/*
 * Go-back-N drain consumer: once the cohort has drained, walk the window
 * [base, head) and, per parked slot, re-submit the retained WR (bypassing
 * convert_wqe_to_page_provider() -- the provider is already pinned) or, once
 * the replay budget is spent, drop it terminally.  On a successful re-submit
 * the provider and owner ref migrate to the new WR's cookie (freed on its
 * completion); on failure they are freed here.  gbn_replaying is held across
 * the loop so a synchronous completion during a re-submit takes the ordinary
 * terminal path instead of re-capturing.
 */
static void verbs_gbn_window_replay(struct hfi2_bulksvc_qp_info *qp_info)
{
	struct hfi2_bulksvc *svc = qp_info->ordering.svc;
	struct rvt_qp *qp = qp_info->owner;
	u32 cur;

	qp_info->gbn_replaying = true;

	/*
	 * Chain the first replayed WR onto the last surviving prefix WR (via the
	 * anchor cursor captured at arm), or onto NONE if that slot has since
	 * recycled or no prefix survives.  chain_tail_handle then carries forward.
	 */
	if (qp_info->gbn_anchor_valid) {
		u32 aslot = qp_info->gbn_anchor_cursor & qp_info->inflight_mask;
		struct verbs_inflight_wr *ainf =
			&qp_info->inflight_ring[aslot];

		if (ainf->state == INFLIGHT_ACTIVE &&
		    ainf->issue_cursor == qp_info->gbn_anchor_cursor &&
		    ainf->handle.value != 0)
			qp_info->chain_tail_handle = ainf->handle;
		else
			qp_info->chain_tail_handle =
				HFI2_DMS_TRANSFER_HANDLE_NONE;
	}

	for (cur = qp_info->gbn_window_base; cur != qp_info->gbn_window_head;
	     cur++) {
		u32 slot = cur & qp_info->inflight_mask;
		struct verbs_inflight_wr *inf = &qp_info->inflight_ring[slot];
		struct verbs_gbn_replay *rep = &inf->replay;
		struct hfi2_bulksvc_verbs_ordering *ord;
		struct bts_submit_req req;
		u64 order_key;
		int rc;

		if (inf->state != INFLIGHT_AWAITING_REPLAY)
			continue;

		/* Held slot absorbed into this window: clear the hold marker. */
		if (inf->held_for_ordering) {
			inf->held_for_ordering = false;
			qp_info->held_count--;
			qp_info->ordering.dms->counters.held_for_ordering_replayed++;
		}

		if (qp_info->gbn_stop_replay || qp->state != IB_QPS_RTS) {
			verbs_gbn_replay_drop(qp_info, inf);
			continue;
		}

		/* Budget exhausted: give up on this slot, surface an error. */
		if (inf->replay_attempts >= READ_ONCE(bulksvc_gbn_max_retries)) {
			verbs_gbn_replay_drop(qp_info, inf);
			continue;
		}

		/*
		 * MR unregistered under the parked window: the pin is gone, so
		 * surface an error rather than replaying against memory that is
		 * no longer mapped.
		 */
		if (!verbs_gbn_replay_provider_live(rep)) {
			qp_info->ordering.dms->counters.gbn_drop_mr_gone++;
			verbs_gbn_replay_drop(qp_info, inf);
			continue;
		}

		/*
		 * Reuse the original order_key so a WRITE_WITH_IMM replay keeps the
		 * same tx_wr_seq (order_key[63:48]); a fresh seq would leave a
		 * permanent gap in the peer's rx_next_deliver ring.  Only the
		 * generation (order_key[31:24]) is re-stamped for the receiver's
		 * staleness guard.  Mask-CLEAR the old generation before setting
		 * the current one.
		 */
		order_key = (rep->order_key &
			     ~((u64)GBN_ORDER_KEY_GEN_MASK << GBN_ORDER_KEY_GEN_SHIFT)) |
			    ((u64)(inf->replay_gen & GBN_ORDER_KEY_GEN_MASK)
			     << GBN_ORDER_KEY_GEN_SHIFT);

		ord = rep->cmd ? &rep->cmd->rdma.qp_info->ordering :
				 rep->sge_info->ord;

		req = (struct bts_submit_req){
			.svc = svc,
			.ord = ord,
			.qp_info = qp_info,
			.inf = inf,
			.remote_lid = rep->remote_lid,
			.dms_key = rep->dms_key,
			.remote_addr = rep->remote_addr,
			.size = rep->size,
			.is_read = rep->is_read,
			.is_send = rep->is_send,
			.is_imm = rep->is_imm,
			.solicited = rep->solicited,
			.remote_qpn = rep->remote_qpn,
			.user_imm_be = rep->imm_data,
			.is_replay = true,
			.replay_slot = rep,
			.replay_order_key = order_key,
		};

		/* Reset the slot for reuse; the original ord_wr.seq is preserved. */
		inf->handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		inf->state = INFLIGHT_ACTIVE;

		if (rep->cmd) {
			struct hfi2_dms_completion completion = {
				.fn = verbs_ordering_complete,
				.cookie = {},
			};
			struct qp_rdma_cmpl_cookie *ck =
				(struct qp_rdma_cmpl_cookie *)&completion.cookie;

			ck->svc = svc;
			ck->cmd = rep->cmd;
			ck->pageset = rep->pageset;
			ck->multiseg = rep->multiseg;
			ck->remaining_wr_sges = NULL;
			ck->rbuf_start_offset = rep->rbuf_start_offset;
			ck->order_key = order_key;

			req.completion = &completion;
			rc = bts_verbs_submit_one(&req);
		} else {
			struct hfi2_dms_completion completion = {
				.fn = bulksvc_direct_cmd_rdma_complete,
				.cookie = {},
			};
			struct direct_rdma_cmpl_cookie *ck =
				(struct direct_rdma_cmpl_cookie *)
					&completion.cookie;

			ck->sge_info = rep->sge_info;
			ck->pageset = rep->pageset;
			ck->multiseg = rep->multiseg;
			ck->rbuf_start_offset = rep->rbuf_start_offset;
			ck->order_key = order_key;

			req.completion = &completion;
			rc = bts_verbs_submit_one(&req);
		}

		if (rc >= 0) {
			qp_info->ordering.dms->counters.gbn_wrs_replayed++;
			/* Provider + owner ref belong to the new cookie now; wipe. */
			memset(rep, 0, sizeof(*rep));
		} else {
			/* Core did not consume the provider: free + retire. */
			verbs_gbn_replay_drop(qp_info, inf);
		}
	}

	qp_info->gbn_window_active = false;
	qp_info->gbn_window_base = 0;
	qp_info->gbn_window_head = 0;
	qp_info->gbn_anchor_valid = false;
	qp_info->gbn_anchor_cursor = 0;
	qp_info->gbn_stop_replay = false;
	qp_info->gbn_replaying = false;
	verbs_inflight_drain(qp_info);
	/* Retry any deferred WRs that were held back by the GBN window. */
	verbs_deferred_retry(qp_info);
}

static void bulksvc_on_qp_cmd_rdma_helper(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	struct hfi2_bulksvc_qp_info * const qp_info = cmd->rdma.qp_info;
	struct verbs_txreq * const txreq = cmd->rdma.txreq;

	u16 const remote_lid = qp_info->owner->remote_ah_attr.opa.dlid;

	int err_rc = 0;
	txreq->bts_rc = 0;

	if (WARN_ON(!qp_info->owner->ibqp.pd)) {
		pr_err("%s:%d:%s() invalid qp_info->owner->ibqp.pd\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}

	if (WARN_ON(!txreq->wqe)) {
		pr_err("%s:%d:%s() invalid txreq->wqe\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}
	if (WARN_ON(!txreq->wqe->rdma_wr.wr.sg_list)) {
		pr_err("%s:%d:%s() invalid txreq->wqe->rdma_wr.wr.sg_list\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}

	u32 const remote_client_id = VERBS_PD_TO_CLIENT_ID(qp_info->owner->ibqp.pd->res.id);
	u32 const access_key = txreq->wqe->rdma_wr.rkey;
	union hfi2_dms_key const dms_key = { .access = access_key, .client = remote_client_id };

	u32 const num_sge = txreq->wqe->rdma_wr.wr.num_sge;
	if (WARN_ON(num_sge >= 256)) {
		// We only use 8 bits on the wire, impose a cap on num_sges
		pr_err("%s:%d:%s() num_sge %u is too large, max 255 supported\n",
		       __FILENAME__, __LINE__, __func__, num_sge);
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}
	u32 const rdma_opcode = txreq->wqe->wr.opcode;
	u64 remote_addr = txreq->wqe->rdma_wr.remote_addr;
	u32 const size = txreq->wqe->length;

	/*
	 * Strict FIFO: if any WR is deferred, all subsequent WRs on this QP
	 * are also deferred to preserve post order.  Ring-full back-pressure
	 * is folded in here: when the inflight ring is full we defer (rather
	 * than fail the WR) so the deferred-retry path drains it later.
	 *
	 * While a GBN window is active, defer ALL new work so
	 * the cohort [base, gbn_window_head) is the entire in-flight set until
	 * replay completes.
	 */
	if ((!qp_info->retry_in_progress &&
	     !list_empty(&qp_info->deferred_wrs)) ||
	    qp_info->gbn_window_active ||
	    verbs_inflight_full(qp_info)) {
		struct verbs_deferred_wr *def;

		if (verbs_inflight_full(qp_info)) {
			atomic64_inc(&qp_info->inflight_full_deferrals);
			atomic64_inc(&qp_info->verbs_state->ring_full_deferrals);
		}

		/*
		 * Deferral ref ownership (rdmavt path):
		 *   - cmd_get() here takes a deferral ref (refcount 1→2)
		 *   - return skips done: label, so original caller ref is NOT put
		 *   - On retry: re-enters helper, hits done: (puts caller ref),
		 *     then deferred_free puts deferral ref.  Balanced.
		 *   - On flush: ordering_retire puts net-zero refs,
		 *     explicit cmd_put drops caller ref, deferred_free drops
		 *     deferral ref.  Balanced.
		 */
		/* BTS thread: GFP_NOWAIT - do not enter reclaim. */
		def = kzalloc_node(sizeof(*def),
				   GFP_NOWAIT | __GFP_NOWARN,
				   svc->dd->node);
		if (!def) {
			err_rc = -ENOMEM;
			goto on_err_pre_ord;
		}
		INIT_LIST_HEAD(&def->list);
		def->path = DEFERRED_PATH_RDMAVT;
		def->rdmavt.svc = svc;
		hfi2_bulksvc_verbs_cmd_get(cmd);
		def->rdmavt.cmd = cmd;
		list_add_tail(&def->list, &qp_info->deferred_wrs);
		return;
	}

	struct hfi2_bulksvc_verbs_ordering *ord = &qp_info->ordering;

	cmd->ord_wr.seq = ord->next_issue_seq++;
	cmd->ord_wr.type = ORDERED_WR_RDMAVT;
	INIT_LIST_HEAD(&cmd->ord_wr.node);
	/* Reset slot before re-add (cmd is reused across deferred retries). */
	cmd->ord_wr.ring_slot = VERBS_INFLIGHT_NO_SLOT;

	/*
	 * Preallocate inflight tracking before any DMS submit so that
	 * the WR is tracked before any sub-transfer can complete
	 * asynchronously.  Fail the WR if tracking cannot be installed.
	 */
	if (verbs_inflight_add(qp_info, &cmd->ord_wr, num_sge)) {
		err_rc = -ENOMEM;
		goto on_err_pre_ord;
	}

	bool const is_write_imm =
		(rdma_opcode == IB_WR_BULKSVC_WRITE_WITH_IMM);

	bool const is_write = (rdma_opcode == IB_WR_BULKSVC_WRITE ||
			       rdma_opcode == IB_WR_BULKSVC_WRITE_WITH_IMM);
	bool const is_read = (rdma_opcode == IB_WR_BULKSVC_READ);

	if (is_write || is_read) {
		struct verbs_rdmavt_rctx rctx = {
			.svc = svc,
			.sg_list = txreq->wqe->sg_list,
			.lane = qp_info->lane,
		};
		struct hfi2_dms_completion completion = {
			.fn = verbs_ordering_complete,
			.cookie = {},
		};
		struct qp_rdma_cmpl_cookie * const cookie =
			(struct qp_rdma_cmpl_cookie *) &completion.cookie;
		struct verbs_inflight_wr *inf;
		struct bts_submit_req req;
		int rc;

		WARN_ON_ONCE(cmd->ord_wr.ring_slot == VERBS_INFLIGHT_NO_SLOT);
		inf = &qp_info->inflight_ring[cmd->ord_wr.ring_slot];

		/*
		 * The cookie's stable fields are set before the core runs so
		 * the inline-completion path sees a fully formed cookie; the
		 * cmd ref the cookie owns is taken here and dropped by the core
		 * (via on_err) only when submission fails.
		 */
		cookie->svc = svc;
		cookie->pageset = NULL;
		cookie->multiseg = NULL;
		cookie->remaining_wr_sges = NULL;
		hfi2_bulksvc_verbs_cmd_get(cmd);
		cookie->cmd = cmd;

		req = (struct bts_submit_req){
			.svc = svc,
			.ord = ord,
			.qp_info = qp_info,
			.inf = inf,
			.remote_lid = remote_lid,
			.dms_key = dms_key,
			.remote_addr = remote_addr,
			.size = size,
			.num_sge = num_sge,
			.gfp = GFP_KERNEL,
			.is_read = is_read,
			.is_send = false,
			.is_imm = is_write_imm,
			.solicited =
				!!(txreq->wqe->wr.send_flags & IB_SEND_SOLICITED),
			.remote_qpn = txreq->qp->remote_qpn,
			.user_imm_be = txreq->wqe->wr.ex.imm_data,
			.resolve = verbs_rdmavt_resolve_seg,
			.rctx = &rctx,
			.completion = &completion,
			.cookie_pageset = &cookie->pageset,
			.cookie_multiseg = &cookie->multiseg,
			.cookie_rbuf_start_offset = &cookie->rbuf_start_offset,
			.cookie_order_key = &cookie->order_key,
		};

		rc = bts_verbs_submit_one(&req);
		if (rc < 0) {
			hfi2_bulksvc_verbs_cmd_put(cmd);
			cookie->cmd = NULL;
			err_rc = rc;
			goto on_err;
		}

		goto done;
	}

	goto done;

on_err:
	verbs_inflight_remove(qp_info, cmd->ord_wr.ring_slot);
	txreq->bts_rc = IB_WC_GENERAL_ERR;
	verbs_ordering_retire_wr(ord, cmd, svc);
	verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);


done:
	hfi2_bulksvc_verbs_cmd_put(cmd);
	return;

on_err_pre_ord:
	{
		struct hfi2_bulksvc_verbs_ordering *eord = &qp_info->ordering;

		cmd->ord_wr.seq = eord->next_issue_seq++;

		cmd->ord_wr.type = ORDERED_WR_RDMAVT;
		INIT_LIST_HEAD(&cmd->ord_wr.node);
		txreq->bts_rc = IB_WC_GENERAL_ERR;
		verbs_ordering_retire_wr(eord, cmd, svc);
		verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);
		hfi2_bulksvc_verbs_cmd_put(cmd);
	}
}

static void bulksvc_on_qp_cmd_read(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

static void bulksvc_on_qp_cmd_write(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

static void bulksvc_on_qp_cmd_write_with_imm(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	bulksvc_on_qp_cmd_rdma_helper(svc, cmd);
}

/*
 * Verbs SEND initiator (rdmavt path): emit a SEND-flagged WRITE_START per
 * source SGE with dms_key.access carrying remote_qpn and remote_offset 0
 * (a SEND has no remote rkey/addr - those bytes alias ex.imm_data).
 * Threaded through the per-QP DMS chain exactly like a WRITE so submission
 * order is serialized; the target resolves the destination QPN from
 * dms_key.access.
 */
static void bulksvc_on_qp_cmd_send(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	struct hfi2_bulksvc_qp_info * const qp_info = cmd->rdma.qp_info;
	struct verbs_txreq * const txreq = cmd->rdma.txreq;

	u16 const remote_lid = qp_info->owner->remote_ah_attr.opa.dlid;

	int err_rc = 0;

	txreq->bts_rc = 0;

	if (WARN_ON(!txreq->wqe || !txreq->wqe->wr.sg_list)) {
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}

	u32 const num_sge = txreq->wqe->wr.num_sge;

	if (WARN_ON(num_sge >= 256)) {
		err_rc = -EINVAL;
		goto on_err_pre_ord;
	}
	u32 const rdma_opcode = txreq->wqe->wr.opcode;

	union hfi2_dms_key const dms_key = {
		.access = txreq->qp->remote_qpn,
		.client = 0,
	};

	/*
	 * Strict FIFO + ring-full back-pressure, identical to the RDMA
	 * helper: defer behind any already-deferred WR, or when the ring
	 * is full, so the deferred-retry path drains it later.
	 */
	if ((!qp_info->retry_in_progress &&
	     !list_empty(&qp_info->deferred_wrs)) ||
	    qp_info->gbn_window_active ||
	    verbs_inflight_full(qp_info)) {
		struct verbs_deferred_wr *def;

		if (verbs_inflight_full(qp_info)) {
			atomic64_inc(&qp_info->inflight_full_deferrals);
			atomic64_inc(&qp_info->verbs_state->ring_full_deferrals);
		}

		def = kzalloc_node(sizeof(*def),
				   GFP_NOWAIT | __GFP_NOWARN,
				   svc->dd->node);
		if (!def) {
			err_rc = -ENOMEM;
			goto on_err_pre_ord;
		}
		INIT_LIST_HEAD(&def->list);
		def->path = DEFERRED_PATH_RDMAVT;
		def->rdmavt.svc = svc;
		hfi2_bulksvc_verbs_cmd_get(cmd);
		def->rdmavt.cmd = cmd;
		list_add_tail(&def->list, &qp_info->deferred_wrs);
		return;
	}

	struct hfi2_bulksvc_verbs_ordering *ord = &qp_info->ordering;

	cmd->ord_wr.seq = ord->next_issue_seq++;
	cmd->ord_wr.type = ORDERED_WR_RDMAVT;
	INIT_LIST_HEAD(&cmd->ord_wr.node);
	cmd->ord_wr.ring_slot = VERBS_INFLIGHT_NO_SLOT;

	if (verbs_inflight_add(qp_info, &cmd->ord_wr, num_sge)) {
		err_rc = -ENOMEM;
		goto on_err_pre_ord;
	}

	bool const is_send_imm =
		(rdma_opcode == IB_WR_BULKSVC_SEND_WITH_IMM);

	struct hfi2_dms_completion completion = {
		.fn = verbs_ordering_complete,
		.cookie = {},
	};
	struct qp_rdma_cmpl_cookie * const cookie =
		(struct qp_rdma_cmpl_cookie *) &completion.cookie;
	struct verbs_rdmavt_rctx rctx = {
		.svc = svc,
		.sg_list = txreq->wqe->sg_list,
		.lane = qp_info->lane,
	};
	struct verbs_inflight_wr *inf;
	struct bts_submit_req req;
	int rc;

	WARN_ON_ONCE(cmd->ord_wr.ring_slot == VERBS_INFLIGHT_NO_SLOT);
	inf = &qp_info->inflight_ring[cmd->ord_wr.ring_slot];

	cookie->svc = svc;
	cookie->pageset = NULL;
	cookie->multiseg = NULL;
	cookie->remaining_wr_sges = NULL;
	hfi2_bulksvc_verbs_cmd_get(cmd);
	cookie->cmd = cmd;

	/*
	 * A SEND has no remote rkey/addr (those bytes alias ex.imm_data);
	 * dms_key.access carries destination QPN and remote_addr 0 selects the
	 * target SEND-flag landing branch.  size 0 makes the core use the
	 * aggregated source-gather length.
	 */
	req = (struct bts_submit_req){
		.svc = svc,
		.ord = ord,
		.qp_info = qp_info,
		.inf = inf,
		.remote_lid = remote_lid,
		.dms_key = dms_key,
		.remote_addr = 0,
		.size = 0,
		.num_sge = num_sge,
		.gfp = GFP_KERNEL,
		.is_read = false,
		.is_send = true,
		.is_imm = is_send_imm,
		.solicited =
			!!(txreq->wqe->wr.send_flags & IB_SEND_SOLICITED),
		.remote_qpn = txreq->qp->remote_qpn,
		.user_imm_be = txreq->wqe->wr.ex.imm_data,
		.resolve = verbs_rdmavt_resolve_seg,
		.rctx = &rctx,
		.completion = &completion,
		.cookie_pageset = &cookie->pageset,
		.cookie_multiseg = &cookie->multiseg,
		.cookie_order_key = &cookie->order_key,
	};

	rc = bts_verbs_submit_one(&req);
	if (rc < 0) {
		hfi2_bulksvc_verbs_cmd_put(cmd);
		cookie->cmd = NULL;
		err_rc = rc;
		goto on_err;
	}

	goto done;

on_err:
	verbs_inflight_remove(qp_info, cmd->ord_wr.ring_slot);
	txreq->bts_rc = IB_WC_GENERAL_ERR;
	verbs_ordering_retire_wr(ord, cmd, svc);
	verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);

done:
	hfi2_bulksvc_verbs_cmd_put(cmd);
	return;

on_err_pre_ord:
	{
		struct hfi2_bulksvc_verbs_ordering *eord = &qp_info->ordering;

		cmd->ord_wr.seq = eord->next_issue_seq++;
		cmd->ord_wr.type = ORDERED_WR_RDMAVT;
		INIT_LIST_HEAD(&cmd->ord_wr.node);
		txreq->bts_rc = IB_WC_GENERAL_ERR;
		verbs_ordering_retire_wr(eord, cmd, svc);
		verbs_error_qp(qp_info->owner, IB_WC_WR_FLUSH_ERR);
		hfi2_bulksvc_verbs_cmd_put(cmd);
	}
}

static void bulksvc_on_qp_cmd(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	struct hfi2_bulksvc_qp_info* qp_info = cmd->rdma.qp_info;
	struct verbs_txreq *txreq = cmd->rdma.txreq;
	if (WARN_ON(!qp_info || !txreq || !txreq->wqe)) {
		struct hfi2_bulksvc_verbs_cmpl *cmpl =
			hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -EINVAL);
		if (cmpl)
			deliver_bts_rvt_cmpl(svc, cmpl);
		hfi2_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	switch (txreq->wqe->wr.opcode) {
	case IB_WR_BULKSVC_READ:
		bulksvc_on_qp_cmd_read(svc, cmd);
		break;
	case IB_WR_BULKSVC_WRITE:
		bulksvc_on_qp_cmd_write(svc, cmd);
		break;
	case IB_WR_BULKSVC_WRITE_WITH_IMM:
		bulksvc_on_qp_cmd_write_with_imm(svc, cmd);
		break;
	case IB_WR_BULKSVC_SEND:
	case IB_WR_BULKSVC_SEND_WITH_IMM:
		bulksvc_on_qp_cmd_send(svc, cmd);
		break;
	default:
		pr_err("%s:%d:%s() unknown qp cmd opcode %u\n",
		       __FILENAME__, __LINE__, __func__,
		       txreq->wqe->wr.opcode);
		{
			struct hfi2_bulksvc_verbs_cmpl *cmpl =
				hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -EINVAL);
			if (cmpl)
				deliver_bts_rvt_cmpl(svc, cmpl);
			hfi2_bulksvc_verbs_cmd_put(cmd);
		}
		break;
	}
}

///
/// Handle MR notifications in the bulksvc thread
///

struct verbs_mr_accessed_cookie {
	struct hfi2_bulksvc* svc;
	struct hfi2_dms *dms;	/* the lane that registered this access */
	u32 lkey;
};

static void rx_ordering_deliver_slot(struct hfi2_bulksvc *svc,
				     struct rx_wr_tracker *t)
{
	deliver_bts_rvt_cmpl(svc,
		hfi2_bulksvc_verbs_access_cmpl_create(svc,
			t->rx_qp, t->rx_lkey, t->rx_immdt_be, t->rx_flags,
			t->rx_status));
	t->rx_ready = false;
	t->rx_generation_valid = false;
}

static void rx_ordering_drain(struct hfi2_bulksvc_qp_info *qp_info,
			      struct hfi2_bulksvc *svc)
{
	while (true) {
		u8 idx = (u8)qp_info->rx_next_deliver_seq;
		struct rx_wr_tracker *t = &qp_info->rx_wr_table[idx];

		if (!t->rx_ready)
			break;
		qp_info->rx_next_deliver_seq++;
		rx_ordering_deliver_slot(svc, t);
	}
}

static void rx_ordering_retire(struct hfi2_bulksvc_qp_info *qp_info,
			       struct hfi2_bulksvc *svc, struct hfi2_dms *rx_dms,
			       u16 wr_seq, u8 gen, struct rvt_qp *qp, u32 lkey,
			       __be32 immdt_be, u16 flags, int status)
{
	u8 idx = (u8)wr_seq;
	struct rx_wr_tracker *t = &qp_info->rx_wr_table[idx];

	/*
	 * Duplicate of an already-delivered wr_seq: a WRITE_WITH_IMM replayed
	 * after ACK loss.  The watermark is already past it (CQE posted, DMS
	 * re-sent the ACK), so suppress the re-delivery -- a second CQE would
	 * hang the peer recv-CQ.
	 *
	 * Keyed on the watermark, not generation: a replayed cohort passenger
	 * can carry gen == 0, so gen is not a reliable "is this a replay" signal.
	 * A not-yet-delivered WR sits at the watermark (seq_behind == 0) and
	 * falls through to deliver.
	 */
	u16 seq_behind = qp_info->rx_next_deliver_seq - wr_seq;

	if (seq_behind != 0 && seq_behind < 0x8000) {
		rx_dms->counters.gbn_rx_dup_suppressed++;
		return;
	}

	/*
	 * GBN staleness guard.  A sender go-back-N replay re-issues the same
	 * wr_seq with a higher generation (order_key[31:24]); the original
	 * (now orphaned) transfer's completion may still arrive later.  While
	 * the slot is un-delivered (rx_ready) for a given occupant, keep only
	 * the newest generation so a stale orphan cannot overwrite a fresher
	 * replay.  Wrap-safe u8 compare: accept gen not older than the
	 * recorded one.  Once delivered/drained the slot is free for its next
	 * wr_seq occupant, so a not-yet-valid slot always accepts.
	 */
	if (t->rx_generation_valid &&
	    (u8)(gen - t->rx_generation) & 0x80) {
		rx_dms->counters.gbn_rx_stale_dropped++;
		return;
	}
	t->rx_generation = gen;
	t->rx_generation_valid = true;

	/*
	 * A GBN-cancelled attempt (armable status: -ETIMEDOUT fast-fail or
	 * -ECANCELED sibling cancel) will be replayed with the same wr_seq and
	 * a higher generation.  Do NOT ready/drain the slot: advancing
	 * rx_next_deliver_seq past this wr_seq would strand the replay, which
	 * then lands in a slot the drain cursor has already passed.  Record the
	 * generation above (so a later stale orphan is still rejected) but stall
	 * the ring here until the replay retires this wr_seq.  A NON-armable
	 * error is terminal (no replay coming) and must fall through to deliver
	 * its error completion like any other op -- stalling it would hang the
	 * ring forever.
	 */
	/*
	 * Only stall for a pending GBN replay when GBN owns retransmit.  In
	 * health mode (or after a runtime flip to it) no replay is coming, so
	 * an armable status must fall through to deliver its completion rather
	 * than stranding the slot and hanging the ordering ring.  Read live so
	 * a mid-flight flip drains the slot.
	 */
	if (hfi2_dms_fast_fail_enabled() && gbn_armable(status))
		return;

	if (wr_seq != qp_info->rx_next_deliver_seq)
		rx_dms->counters.cqe_rx_out_of_order++;

	t->rx_qp = qp;
	t->rx_lkey = lkey;
	t->rx_immdt_be = immdt_be;
	t->rx_flags = flags;
	t->rx_status = status;
	t->rx_ready = true;

	rx_ordering_drain(qp_info, svc);
}

static void bulksvc_on_verbs_mr_accessed (
	union hfi2_dms_completion_cookie * const cookie, u16 flags, u64 imm_data, u64 order_key, int status)
{
	if (WARN_ON(!cookie)) {
		pr_err("%s:%d:%s() invalid cookie\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}

	struct verbs_mr_accessed_cookie * const accessed_cookie =
		(struct verbs_mr_accessed_cookie *)cookie;

	if (WARN_ON(!accessed_cookie->svc)) {
		pr_err("%s:%d:%s() invalid svc\n",
			__FILENAME__, __LINE__, __func__);
		return;
	}

	struct hfi2_bulksvc_verbs_state * const verbs_state = &accessed_cookie->svc->verbs_state;

	if (flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) {
		u32 const qpn = (u32)(imm_data >> 32) & ((1 << 24) - 1);
		__be32 immdt = cpu_to_be32((u32)imm_data);

		struct hfi2_bulksvc_qp_info *qp_info = NULL;
		struct hfi2_bulksvc_qp_info *pos;
		mutex_lock(&verbs_state->qp_infos_lock);
		list_for_each_entry(pos, &verbs_state->qp_infos, node) {
			if (!pos->owner)
				continue;
			if (pos->owner->ibqp.qp_num == qpn) {
				qp_info = pos;
				break;
			}
		}
		mutex_unlock(&verbs_state->qp_infos_lock);
		if (!qp_info) {
			pr_err("Cannot route immediate data to unknown QP num %u\n", qpn);
			goto done;
		}

		if (!qp_info->owner)
			goto done;
		struct rvt_qp *qp = qp_info->owner;

		if (order_key == HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED) {
			deliver_bts_rvt_cmpl(accessed_cookie->svc,
				hfi2_bulksvc_verbs_access_cmpl_create(
					accessed_cookie->svc,
					qp, accessed_cookie->lkey, immdt,
					flags, status));
		} else {
			u16 const wr_seq = (u16)((order_key >> 48) & 0xFFFF);
			u8 const gen = (order_key >> GBN_ORDER_KEY_GEN_SHIFT) &
				       GBN_ORDER_KEY_GEN_MASK;

			rx_ordering_retire(qp_info, accessed_cookie->svc,
					   accessed_cookie->dms, wr_seq, gen, qp,
					   accessed_cookie->lkey,
					   immdt, flags, status);
		}
	}

done:
	return;
}

/*
 * Verbs MR replication into the secondary DMS lanes, so any lane can
 * serve as the RDMA target for an rkey.  Each rep holds its own page-set
 * ref, dropped when the rep is freed.
 *
 * The primary lane's BTS thread allocates one rep per lane at MR_REG,
 * records it in mr_record->lane_rep[] and enqueues its reg node on the
 * lane's MPSC.  At MR_DEREG, or a re-reg without dereg, it takes the rep
 * out of lane_rep[] and enqueues the rep's second embedded node, so dereg
 * never allocates.  After the reg node is enqueued the primary lane only
 * reads lane_rep[k] and enqueues that dereg node; the lane worker owns
 * the registration, the mr_replicas linkage and the free.  Enqueues stop
 * once the primary lane's worker has stopped; at teardown
 * hfi2_bulksvc_lane_mr_teardown() then frees whatever is left.
 */
struct bts_lane_mr_node {
	struct mpsc_node mn;
	bool dereg;
	struct bts_lane_mr_rep *rep;
};

struct bts_lane_mr_rep {
	struct bts_lane_mr_node reg_node;
	struct bts_lane_mr_node dereg_node;
	struct list_head link;		/* on lane->mr_replicas */
	struct hfi2_bulksvc_lane *lane;
	struct bts_verbs_mr_record *rec;	/* holds a record ref */
	struct bts_verbs_pageset *ps;
	union hfi2_dms_key key;
	u32 lkey;
	bool registered;
};

static void bts_lane_mr_rep_free(struct bts_lane_mr_rep *rep)
{
	struct bts_verbs_mr_record *rec = rep->rec;

	list_del(&rep->link);
	bts_verbs_pageset_put(rep->ps);
	if (atomic_dec_and_test(&rec->lane_reps_live))
		wake_up_all(&rep->lane->svc->lane_reps_wq);
	kfree(rep);
	bts_verbs_mr_record_put(rec);
}

/*
 * Allocate one rep per secondary lane, all or nothing, before the primary
 * lane registers the access, so a GFP_NOWAIT failure fails MR_REG instead
 * of leaving lanes without the rkey.  (Lane registration itself only fails
 * on access pool exhaustion, which the lane logs.)  On failure the caller
 * frees the partial set with bts_lanes_free_reps().
 */
static int bts_lanes_alloc_reps(struct hfi2_bulksvc *svc,
				struct bts_lane_mr_rep **reps)
{
	for (u32 k = 0; k < svc->num_lanes; k++) {
		if (bulksvc_lane_is_primary(&svc->lanes[k]))
			continue;
		/* BTS thread: GFP_NOWAIT - do not enter reclaim. */
		reps[k] = kzalloc_node(sizeof(*reps[k]),
				       GFP_NOWAIT | __GFP_NOWARN, svc->dd->node);
		if (!reps[k])
			return -ENOMEM;
	}
	return 0;
}

static void bts_lanes_free_reps(struct hfi2_bulksvc *svc,
				struct bts_lane_mr_rep **reps)
{
	for (u32 k = 0; k < svc->num_lanes; k++)
		kfree(reps[k]);
}

static void bts_lanes_replicate_reg(struct hfi2_bulksvc *svc,
				    struct bts_verbs_mr_record *mr_record,
				    struct bts_verbs_pageset *ps,
				    union hfi2_dms_key dms_key,
				    struct bts_lane_mr_rep **reps)
{
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_bulksvc_lane *l = &svc->lanes[k];
		struct bts_lane_mr_rep *rep = reps[k];

		if (bulksvc_lane_is_primary(l))
			continue;
		/* Re-reg without dereg (see the access_pageset WARN in the caller). */
		if (WARN_ON_ONCE(mr_record->lane_rep[k])) {
			mpsc_enqueue(&l->mr_ops,
				     &mr_record->lane_rep[k]->dereg_node.mn);
			mr_record->lane_rep[k] = NULL;
		}
		rep->reg_node.rep = rep;
		rep->dereg_node.rep = rep;
		rep->dereg_node.dereg = true;
		INIT_LIST_HEAD(&rep->link);
		rep->lane = l;
		bts_verbs_mr_record_get(mr_record);
		atomic_inc(&mr_record->lane_reps_live);
		rep->rec = mr_record;
		bts_verbs_pageset_get(ps);
		rep->ps = ps;
		rep->key = dms_key;
		rep->lkey = mr_record->rkey;
		mr_record->lane_rep[k] = rep;
		mpsc_enqueue(&l->mr_ops, &rep->reg_node.mn);
		hfi2_bulksvc_schedule_lane(svc, k);
	}
}

static void bts_lanes_replicate_dereg(struct hfi2_bulksvc *svc,
				      struct bts_verbs_mr_record *mr_record)
{
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct bts_lane_mr_rep *rep = mr_record->lane_rep[k];

		if (bulksvc_lane_is_primary(&svc->lanes[k]) || !rep)
			continue;
		mr_record->lane_rep[k] = NULL;
		mpsc_enqueue(&svc->lanes[k].mr_ops, &rep->dereg_node.mn);
		hfi2_bulksvc_schedule_lane(svc, k);
	}
}

static void bts_lane_mr_unreg_done(union hfi2_dms_completion_cookie *cookie,
				   int status)
{
	bts_lane_mr_rep_free(*(struct bts_lane_mr_rep **)cookie);
}

static void bts_lane_mr_reg(struct hfi2_bulksvc_lane *l,
			    struct bts_lane_mr_rep *rep)
{
	struct hfi2_dms_access_completion completion = {
		.fn = verbs_ordering_notify,
		.cookie = {},
	};
	struct verbs_mr_accessed_cookie *cookie =
		(struct verbs_mr_accessed_cookie *)&completion.cookie;
	int rc;

	cookie->svc = l->svc;
	cookie->dms = l->dms;
	cookie->lkey = rep->lkey;
	list_add_tail(&rep->link, &l->mr_replicas);
	rc = hfi2_dms_register_access(l->dms, verbs_mr_page_provider(rep->ps),
				      0, rep->ps->dms_mr.user.len, rep->key,
				      completion, HFI2_DMS_ACCESS_TYPE_PERSISTENT,
				      NULL);
	if (rc < 0) {
		dd_dev_err_ratelimited(l->svc->dd,
				       "bulksvc lane %u: register MR lkey 0x%x failed %d\n",
				       l->idx, rep->lkey, rc);
		return;
	}
	rep->registered = true;
}

static void bts_lane_mr_dereg(struct hfi2_bulksvc_lane *l,
			      struct bts_lane_mr_rep *rep)
{
	struct hfi2_dms_completion unreg = {
		.fn = bts_lane_mr_unreg_done,
		.cookie = {},
	};
	int rc;

	if (!rep->registered) {
		bts_lane_mr_rep_free(rep);
		return;
	}
	rep->registered = false;
	*(struct bts_lane_mr_rep **)&unreg.cookie = rep;
	rc = hfi2_dms_unregister_access(l->dms, rep->key, unreg);
	/* rc == 0: the callback owns rep (may already have fired inline). */
	if (rc != 0)
		bts_lane_mr_rep_free(rep);
}

int hfi2_bulksvc_lane_poll_mr_ops(struct hfi2_bulksvc_lane *l)
{
	struct mpsc_node *mn;
	int n = 0;

	while ((mn = mpsc_dequeue(&l->mr_ops))) {
		struct bts_lane_mr_node *node =
			container_of(mn, struct bts_lane_mr_node, mn);

		if (node->dereg)
			bts_lane_mr_dereg(l, node->rep);
		else
			bts_lane_mr_reg(l, node->rep);
		n++;
	}
	return n;
}

/*
 * Lane worker stopped and lane DMS uninit'd: drop every rep and its page-set
 * ref (none on the primary lane).
 */
void hfi2_bulksvc_lane_mr_teardown(struct hfi2_bulksvc_lane *l)
{
	struct bts_lane_mr_rep *rep, *tmp;
	struct mpsc_node *mn;

	/*
	 * Nothing is freed while draining: a dereg node is embedded in the same
	 * rep as its (possibly still queued) reg node.  Unprocessed reg nodes
	 * join mr_replicas, then every rep is freed exactly once below.
	 */
	while (!mpsc_is_empty(&l->mr_ops)) {
		struct bts_lane_mr_node *node;

		mn = mpsc_dequeue(&l->mr_ops);
		if (!mn)
			continue;
		node = container_of(mn, struct bts_lane_mr_node, mn);
		if (!node->dereg)
			list_add_tail(&node->rep->link, &l->mr_replicas);
	}
	list_for_each_entry_safe(rep, tmp, &l->mr_replicas, link)
		bts_lane_mr_rep_free(rep);
}

static void bulksvc_on_verbs_cmd_mr_reg(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	if (WARN_ON(cmd->op != HFI2_BULKSVC_VERBS_CMD_OP_MR_REG)) {
		struct hfi2_bulksvc_verbs_cmpl *cmpl;

		pr_err("%s:%d:%s() invalid cmd op %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->op);
		cmpl = hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -EINVAL);
		if (cmpl)
			deliver_bts_rvt_cmpl(svc, cmpl);
		hfi2_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	struct hfi2_bulksvc_verbs_mr_reg_cmd *mr_reg_cmd = &cmd->mr_reg;

	/* The set was pinned/dma_mapped at notify_mr_pages_set time; set the
	 * key-dependent dms_mr fields and register the DMS access here.
	 */
	struct bts_verbs_mr_record * const mr_record =
		mr_reg_cmd->mr->driver_priv;
	struct bts_verbs_pageset *ps =
		mr_record ? bts_verbs_pageset_get_current(mr_record) : NULL;

	if (WARN_ON(!mr_record) || WARN_ON(!ps) ||
	    WARN_ON(!ps->vaddrs) || WARN_ON(!ps->dms_mr.dma_list)) {
		pr_err("%s:%d:%s() bulksvc: MR record not pinned at reg time\n",
		       __FILENAME__, __LINE__, __func__);
		bts_verbs_pageset_put(ps);
		deliver_bts_rvt_cmpl(svc,
			hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -EINVAL));
		hfi2_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	mr_record->client_id = VERBS_PD_TO_CLIENT_ID(pd_id);
	mr_record->rkey = mr_reg_cmd->key;

	/* MPSC FIFO + the SQ s_last==s_cur local-op gate guarantee any prior
	 * registration's dereg ran (clearing access_pageset) before this reg.
	 * A non-NULL slot here means a re-reg without an intervening dereg
	 * (a misbehaving ULP); drop the stale ref to avoid a leak.
	 */
	if (WARN_ON_ONCE(mr_record->access_pageset)) {
		bts_verbs_pageset_put(mr_record->access_pageset);
		mr_record->access_pageset = NULL;
	}

	struct hfi2_dms_mr * const dms_mr = &ps->dms_mr;

	dms_mr->region_offset = dms_mr->user.addr & (PAGE_SIZE - 1);
	dms_mr->mode = mr_reg_cmd->access_flags & IB_UVERBS_ACCESS_ZERO_BASED ?
		HFI2_DMS_MR_MODE_OFFSET : HFI2_DMS_MR_MODE_VADDR;

	struct hfi2_dms_access_completion completion = {
		.fn = verbs_ordering_notify,
		.cookie = {},
	};
	struct verbs_mr_accessed_cookie * cookie =
		(struct verbs_mr_accessed_cookie *) &completion.cookie;
	cookie->svc = svc;
	cookie->dms = hfi2_bulksvc_primary_dms(svc);
	cookie->lkey = mr_record->rkey;

	union hfi2_dms_key const dms_key = {
		.client = mr_record->client_id,
		.access = mr_record->rkey,
	};
	struct bts_lane_mr_rep *reps[HFI2_BULKSVC_MAX_LANES] = {};
	int rc = bts_lanes_alloc_reps(svc, reps);

	if (!rc)
		rc = hfi2_dms_register_access(hfi2_bulksvc_primary_dms(svc),
					      verbs_mr_page_provider(ps), 0,
					      ps->dms_mr.user.len, dms_key,
					      completion,
					      HFI2_DMS_ACCESS_TYPE_PERSISTENT,
					      NULL);

	if (rc < 0) {
		pr_err("%s:%d:%s() bulksvc: Failed to register DMS data\n",
		       __FILENAME__, __LINE__, __func__);
		bts_lanes_free_reps(svc, reps);
		/* No access; drop our lookup ref (cur_pageset's ref stays). */
		bts_verbs_pageset_put(ps);
	} else {
		/* Park the access's ref for the unregister callback to drop. */
		mr_record->access_pageset = ps;
		WRITE_ONCE(mr_record->registered, true);
		bts_lanes_replicate_reg(svc, mr_record, ps, dms_key, reps);
	}
	deliver_bts_rvt_cmpl(svc,
		hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, rc));
	hfi2_bulksvc_verbs_cmd_put(cmd);
}

/*
 * DMS unregister completion; fires once when the access has drained.
 * Drops the access's page-set ref (the set frees once cur_pageset and
 * any in-flight op refs are also gone).
 */
static void on_verbs_mr_unregister_complete(
	union hfi2_dms_completion_cookie *cookie, int status)
{
	struct verbs_mr_unreg_cookie *unreg =
		(struct verbs_mr_unreg_cookie *)cookie;
	struct bts_verbs_mr_record *rec = unreg->mr_record;
	struct bts_verbs_pageset *ps = rec->access_pageset;

	rec->access_pageset = NULL;
	bts_verbs_pageset_put(ps);
	bts_verbs_mr_destroy_barrier_signal(rec);

	deliver_bts_rvt_cmpl(unreg->svc,
		hfi2_bulksvc_verbs_cmd_cmpl_create(unreg->svc, unreg->cmd, status));
	hfi2_bulksvc_verbs_cmd_put(unreg->cmd);
}

static void bulksvc_on_verbs_cmd_mr_dereg(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_verbs_cmd * const cmd)
{
	struct rvt_mregion * const rvt_mr = cmd->mr_dereg.mr;

	if (WARN_ON(!rvt_mr)) {
		struct hfi2_bulksvc_verbs_cmpl *cmpl;

		pr_err("%s:%d:%s() invalid MR in dereg cmd\n",
		       __FILENAME__, __LINE__, __func__);
		cmpl = hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -EINVAL);
		if (cmpl)
			deliver_bts_rvt_cmpl(svc, cmpl);
		hfi2_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	struct bts_verbs_mr_record * const mr_record = rvt_mr->driver_priv;

	if (WARN_ON(!mr_record) || !mr_record->registered) {
		pr_err("%s:%d:%s() MR to deregister not registered\n",
		       __FILENAME__, __LINE__, __func__);
		/* Two QPs deregging the same rkey: the first owns the access and
		 * its page-set ref; nothing to drop here.
		 */
		deliver_bts_rvt_cmpl(svc,
			hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd, -ENOENT));
		hfi2_bulksvc_verbs_cmd_put(cmd);
		return;
	}

	u32 const dms_client_id = mr_record->client_id;
	union hfi2_dms_key const dms_key = {
		.client = dms_client_id,
		.access = mr_record->rkey,
	};

	/* Clear registered first: an in-flight WR-helper either already
	 * submitted its SGE (rvt_sge refs keep the record alive) or sees the
	 * cleared flag and bails.  access_pageset is dropped by the callback.
	 */
	WRITE_ONCE(mr_record->registered, false);
	bts_lanes_replicate_dereg(svc, mr_record);

	struct hfi2_dms_completion unreg = {
		.fn = on_verbs_mr_unregister_complete,
		.cookie = {},
	};
	struct verbs_mr_unreg_cookie *unreg_cookie =
		(struct verbs_mr_unreg_cookie *)&unreg.cookie;
	unreg_cookie->svc = svc;
	unreg_cookie->mr_record = mr_record;
	unreg_cookie->cmd = cmd;

	int rc = hfi2_dms_unregister_access(hfi2_bulksvc_primary_dms(svc), dms_key, unreg);
	if (rc == 0) {
		/* Callback owns the cmd ref + access_pageset (may fire inline). */
		return;
	}

	/* Callback won't fire (-EALREADY or hard error); we cleared
	 * registered so this record owns access_pageset - drop it here.
	 */
	if (mr_record->access_pageset) {
		bts_verbs_pageset_put(mr_record->access_pageset);
		mr_record->access_pageset = NULL;
	}
	bts_verbs_mr_destroy_barrier_signal(mr_record);
	if (rc != -EALREADY)
		pr_err("%s:%d:%s() Failed to deregister MR from DMS: %d\n",
		       __FILENAME__, __LINE__, __func__, rc);
	deliver_bts_rvt_cmpl(svc,
		hfi2_bulksvc_verbs_cmd_cmpl_create(svc, cmd,
						   rc == -EALREADY ? 0 : rc));
	hfi2_bulksvc_verbs_cmd_put(cmd);
}

/* Drain the verbs cmd queue @cmdq of one DMS lane on that lane's worker. */
int hfi2_bulksvc_poll_verbs_cmds(struct hfi2_bulksvc * const svc,
				 struct hfi2_bulksvc_mpsc_verbs_cmd_queue *cmdq)
{
	int processed = 0;
	unsigned int cap = READ_ONCE(bulksvc_poll_max_per_iter);

	/* Drain up to the per-iter cap; capped cmds stay in the MPSC for
	 * the next poll, preserving posted order (a fair FIFO).
	 */
	while (!cap || processed < cap) {
		struct hfi2_bulksvc_verbs_cmd *cmd;
		struct mpsc_node *mn;

		mn = mpsc_dequeue(&cmdq->mpsc);
		if (!mn) {
			if (!mpsc_is_empty(&cmdq->mpsc))
				continue;
			break;
		}

		cmd = container_of(mn, struct hfi2_bulksvc_verbs_cmd,
				   mpsc_node);
		atomic_dec(&cmdq->depth);
		processed += 1;
		switch (cmd->op) {
		case HFI2_BULKSVC_VERBS_CMD_OP_RDMA:
			bulksvc_on_qp_cmd(svc, cmd);
			break;
		case HFI2_BULKSVC_VERBS_CMD_OP_MR_REG:
			bulksvc_on_verbs_cmd_mr_reg(svc, cmd);
			break;
		case HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG:
			bulksvc_on_verbs_cmd_mr_dereg(svc, cmd);
			break;
		}
	}
	return processed;
}

/*
 * Release the QP-owned ref(s) behind one pending ordered WR, silently (no
 * CQE).  RDMAVT entries drop the cmd kref; hotpath entries drop the
 * rvt_get_qp and free the sge_info.  Caller must unlink @ow first.
 */
static void verbs_ordered_wr_reap(struct verbs_ordered_wr *ow)
{
	if (ow->type == ORDERED_WR_RDMAVT) {
		struct hfi2_bulksvc_verbs_cmd *cmd =
			container_of(ow, struct hfi2_bulksvc_verbs_cmd, ord_wr);
		hfi2_bulksvc_verbs_cmd_put(cmd);
	} else {
		struct direct_rdma_sge_info *hp =
			container_of(ow, struct direct_rdma_sge_info, ord_wr);
		rvt_put_qp(hp->qp);
		kmem_cache_free(hp->ord->svc->verbs_sge_cache, hp);
	}
}

/*
 * Force GBN control state terminal (so no late completion replays),
 * then walk the inflight ring, ordering.pending, and deferred list.
 */
static void verbs_gbn_teardown_drain(struct hfi2_bulksvc_qp_info *qp_info,
				     struct hfi2_bulksvc *svc)
{
	u32 i;

	/*
	 * Terminal GBN control state, set before any cancel below.
	 * gbn_replaying forces verbs_gbn_classify() to GBN_ACTION_NONE for
	 * every completion driven during teardown, so a cancelled inflight op
	 * completes-and-releases instead of re-capturing into a replay slot.
	 */
	qp_info->gbn_replaying = true;
	qp_info->gbn_window_active = false;
	qp_info->gbn_drain_remaining = 0;
	qp_info->gbn_window_base = 0;
	qp_info->gbn_window_head = 0;
	qp_info->gbn_anchor_valid = false;
	qp_info->gbn_anchor_cursor = 0;
	qp_info->gbn_stop_replay = false;
	qp_info->held_count = 0;

	/*
	 * Reap live INFLIGHT_ACTIVE slots first. Each holds an outstanding DMS
	 * op whose cookie owns the QP/cmd reference; the ref is released only
	 * when the op completes. Cancelling by handle drives that completion
	 * (verbs_ordering_complete) synchronously, releasing the ref through the
	 * normal path with the pageset freed exactly once -- a direct ref-drop
	 * would free a buffer SDMA still owns and leave the late completion to
	 * run on freed state. The inflight_cancel_walk guard keeps the nested
	 * completion from re-driving drain/replay/cancel-others while we walk;
	 * walk newest->oldest so a nested retire cannot invalidate an unvisited
	 * slot. -ENOENT means the op already retired via its own completion:
	 * take no action (dropping a ref here would double-free).
	 */
	qp_info->inflight_cancel_walk = true;
	for (u32 cur = qp_info->inflight_head; cur != qp_info->inflight_tail;) {
		u32 slot = (--cur) & qp_info->inflight_mask;
		struct verbs_inflight_wr *inf = &qp_info->inflight_ring[slot];
		int rc;

		if (inf->state != INFLIGHT_ACTIVE || inf->handle.value == 0)
			continue;

		rc = hfi2_dms_cancel_tracker_by_handle(qp_info->ordering.dms, inf->handle,
						       -ECANCELED);
		if (rc == 0) {
			qp_info->ordering.dms->counters.gbn_teardown_active_cancelled++;
		} else if (rc == -ENOENT) {
			qp_info->ordering.dms->counters.gbn_teardown_active_already_gone++;
		} else {
			WARN_ON_ONCE(1);
			qp_info->ordering.dms->counters.gbn_teardown_active_cancel_failed++;
		}
	}
	qp_info->inflight_cancel_walk = false;

	for (i = 0; i < qp_info->inflight_size; i++) {
		struct verbs_inflight_wr *inf = &qp_info->inflight_ring[i];
		struct verbs_gbn_replay *rep = &inf->replay;

		if (inf->state != INFLIGHT_AWAITING_REPLAY)
			continue;

		/* Silent terminal drop: like verbs_gbn_replay_drop, minus the CQE/retire. */
		verbs_gbn_free_provider(rep);
		if (rep->cmd) {
			hfi2_bulksvc_verbs_cmd_put(rep->cmd);
		} else if (rep->sge_info) {
			rvt_put_qp(rep->sge_info->qp);
			kmem_cache_free(svc->verbs_sge_cache, rep->sge_info);
		}
		inf->state = INFLIGHT_COMPLETED;
		memset(rep, 0, sizeof(*rep));
		qp_info->ordering.dms->counters.gbn_teardown_freed++;
	}

	/* Advance the tail past the now-COMPLETED slots. */
	verbs_inflight_drain(qp_info);

	/*
	 * Reap ordering.pending: a window mid-replay re-submits WRs via
	 * verbs_ordering_submit_*() into ordering.pending (each owning a
	 * cmd kref or a hotpath sge_info + rvt_get_qp), NOT back into the
	 * inflight ring.  Their delivery completions never arrive after
	 * RESET, so drop the refs here (silent -- no CQE/deliver) or
	 * rvt_destroy_qp hangs.  Unlink before put so the idempotent
	 * destroy-time sweep (bulksvc_qp_info_destroy) sees an empty list.
	 */
	while (!list_empty(&qp_info->ordering.pending)) {
		struct verbs_ordered_wr *ow =
			list_first_entry(&qp_info->ordering.pending,
					 struct verbs_ordered_wr, node);

		list_del_init(&ow->node);
		verbs_ordered_wr_reap(ow);
		qp_info->ordering.dms->counters.gbn_teardown_freed++;
	}

	/*
	 * Reap deferred WRs the same way: with ordering.pending now empty,
	 * verbs_deferred_retry's flush could drain most, but entries stalled
	 * on ring/hazard state (not seq-gating) would remain -- free them
	 * directly to drop their cmd/qp refs.
	 */
	while (!list_empty(&qp_info->deferred_wrs)) {
		struct verbs_deferred_wr *def =
			list_first_entry(&qp_info->deferred_wrs,
					 struct verbs_deferred_wr, list);

		list_del(&def->list);
		verbs_deferred_free(def);
		qp_info->ordering.dms->counters.gbn_teardown_freed++;
	}

	/*
	 * qp_info survives a bare QP reset (RESET->INIT->RTS reuse), so
	 * restore gbn_replaying here or it stays latched true and pins
	 * verbs_gbn_classify() to GBN_ACTION_NONE for the qp_info's life,
	 * silently disabling GBN fast-fail on every reused QP.
	 */
	qp_info->gbn_replaying = false;
}

int hfi2_bulksvc_poll_gbn_teardown(struct hfi2_bulksvc * const svc, u32 lane)
{
	struct hfi2_bulksvc_verbs_state *vs = &svc->verbs_state;
	struct hfi2_bulksvc_qp_info *qpi, *next_qpi;
	LIST_HEAD(to_drain);
	int processed = 0;

	if (atomic_read(&vs->gbn_teardown_pending_count[lane]) == 0)
		return 0;

	mutex_lock(&vs->qp_infos_lock);
	list_for_each_entry(qpi, &vs->qp_infos, node) {
		struct rvt_qp *qp;
		unsigned long flags;
		bool pending;

		if (!qpi->owner || qpi->lane != lane)
			continue;
		qp = qpi->owner;

		spin_lock_irqsave(&qp->s_lock, flags);
		pending = qpi->gbn_teardown_pending;
		if (pending)
			qpi->gbn_teardown_pending = false;
		spin_unlock_irqrestore(&qp->s_lock, flags);
		if (!pending)
			continue;

		atomic_dec(&vs->gbn_teardown_pending_count[lane]);
		hfi2_bulksvc_qp_info_get(qpi);
		list_add_tail(&qpi->gbn_teardown_drain_node, &to_drain);
	}
	mutex_unlock(&vs->qp_infos_lock);

	list_for_each_entry_safe(qpi, next_qpi, &to_drain,
				 gbn_teardown_drain_node) {
		list_del_init(&qpi->gbn_teardown_drain_node);
		verbs_gbn_teardown_drain(qpi, svc);
		hfi2_bulksvc_qp_info_put(qpi);
		processed++;
	}
	return processed;
}

int hfi2_bulksvc_poll_gate_retries(struct hfi2_bulksvc * const svc, u32 lane)
{
	struct hfi2_bulksvc_verbs_state *vs = &svc->verbs_state;
	struct hfi2_bulksvc_qp_info *qpi, *next_qpi;
	LIST_HEAD(to_drain);
	int processed = 0;

	if (atomic_read(&vs->gate_retry_pending_count[lane]) == 0)
		return 0;

	mutex_lock(&vs->qp_infos_lock);
	list_for_each_entry(qpi, &vs->qp_infos, node) {
		struct rvt_qp *qp;
		unsigned long flags;
		bool pending;

		if (!qpi->owner || qpi->lane != lane)
			continue;
		qp = qpi->owner;

		spin_lock_irqsave(&qp->s_lock, flags);
		pending = qpi->gate_retry_pending;
		if (pending)
			qpi->gate_retry_pending = false;
		spin_unlock_irqrestore(&qp->s_lock, flags);
		if (!pending)
			continue;

		atomic_dec(&vs->gate_retry_pending_count[lane]);
		hfi2_bulksvc_qp_info_get(qpi);
		list_add_tail(&qpi->gate_retry_drain_node, &to_drain);
	}
	mutex_unlock(&vs->qp_infos_lock);

	list_for_each_entry_safe(qpi, next_qpi, &to_drain,
				 gate_retry_drain_node) {
		list_del_init(&qpi->gate_retry_drain_node);
		verbs_deferred_retry(qpi);
		hfi2_bulksvc_qp_info_put(qpi);
		processed++;
	}
	return processed;
}

///
/// Resource initialization and cleanup
///

struct hfi2_bulksvc_qp_info* hfi2_bulksvc_qp_info_create(struct hfi2_bulksvc_verbs_state* verbs_state, struct hfi2_qp_priv *qp_priv)
{
	unsigned int ring_size = bulksvc_verbs_max_inflight;

	if (WARN_ON(!qp_priv)) {
		return NULL;
	}

	/* Validate and round up to power of 2, clamp to [4, 256] */
	if (ring_size < 4)
		ring_size = 4;
	if (ring_size > 256)
		ring_size = 256;
	ring_size = roundup_pow_of_two(ring_size);

	struct hfi2_bulksvc_qp_info* res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate qp info\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	kref_init(&res->refcount);
	INIT_LIST_HEAD(&res->node);

	res->qp_priv = qp_priv;
	res->verbs_state = verbs_state;
	res->owner = NULL;
	res->ppd = NULL;

	res->tx_wr_seq = 0;
	memset(res->rx_wr_table, 0, sizeof(res->rx_wr_table));
	res->rx_next_deliver_seq = 0;
	res->tx_send_seq = 0;
	res->rx_expected_send_seq = 0;


	res->rvt_rdma_ops_sched = 0;
	res->bts_path_inflight_bts = 0;
	res->n_dispatched_unacked = 0;
	res->last_dispatched_class = OPCLASS_NONE;

	res->ordering.svc = container_of(verbs_state,
					 struct hfi2_bulksvc, verbs_state);
	res->lane = HFI2_BULKSVC_PRIMARY_LANE;
	res->ordering.dms = hfi2_bulksvc_primary_dms(res->ordering.svc);
	res->ordering.next_issue_seq = 0;
	res->ordering.next_deliver_seq = 0;
	INIT_LIST_HEAD(&res->ordering.pending);
	res->chain_tail_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;

	BUILD_BUG_ON(BTS_VERBS_MAX_INFLIGHT > BTS_VERBS_RX_WR_TABLE_SIZE);
	WARN_ON(hfi2_max_sges > BTS_VERBS_MAX_SGE_PER_WR);
	if (WARN_ON(ring_size > BTS_VERBS_RX_WR_TABLE_SIZE))
		ring_size = BTS_VERBS_RX_WR_TABLE_SIZE;

	res->inflight_size = ring_size;
	res->inflight_mask = ring_size - 1;
	res->inflight_ring = kvcalloc(ring_size, sizeof(*res->inflight_ring),
				      GFP_KERNEL);
	if (!res->inflight_ring) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate inflight ring\n",
		       __FILENAME__, __LINE__, __func__);
		kfree(res);
		return NULL;
	}
	memset(res->inflight_ring, 0,
	       res->inflight_size * sizeof(*res->inflight_ring));

	res->inflight_head = 0;
	res->inflight_tail = 0;
	atomic64_set(&res->inflight_full_deferrals, 0);
	INIT_LIST_HEAD(&res->deferred_wrs);
	res->retry_in_progress = false;
	res->gbn_window_active = false;
	res->gbn_drain_remaining = 0;
	res->gbn_window_base = 0;
	res->gbn_window_head = 0;
	res->gbn_anchor_valid = false;
	res->gbn_anchor_cursor = 0;
	res->gbn_stop_replay = false;
	res->gate_retry_pending = false;
	INIT_LIST_HEAD(&res->gate_retry_drain_node);
	res->gbn_teardown_pending = false;
	INIT_LIST_HEAD(&res->gbn_teardown_drain_node);
	res->bulksvc_gated = false;

	return res;
}

/*
 * Bind a QP to the DMS lane of the user client (process) that created it,
 * so its hotpath posts, DMS completions and gate/GBN work all run on that
 * lane's worker.  Kernel QPs stay on the primary lane.
 */
void hfi2_bulksvc_qp_info_set_lane(struct hfi2_bulksvc_qp_info *qp_info,
				   struct rvt_qp *qp)
{
	struct hfi2_bulksvc *svc = qp_info->ordering.svc;
	struct ib_pd *pd = qp->ibqp.pd;
	u32 lane = HFI2_BULKSVC_PRIMARY_LANE;

	if (pd && pd->uobject && pd->uobject->context) {
		struct rvt_ucontext *uctx =
			container_of(pd->uobject->context,
				     struct rvt_ucontext, ibucontext);
		struct hfi2_filedata *fd = uctx->priv;
		struct hfi2_bulksvc_user_info *ui =
			fd ? hfi2_fd_bulksvc_info(fd) : NULL;

		if (ui)
			lane = ui->lane;
	}
	qp_info->lane = lane;
	qp_info->peer_lane = lane;
	qp_info->ordering.dms = svc->lanes[lane].dms;
}

void hfi2_bulksvc_qp_info_get(struct hfi2_bulksvc_qp_info *qp_info)
{
	kref_get(&qp_info->refcount);
}

static void bulksvc_qp_info_destroy(struct kref* info_refcount)
{
	struct hfi2_bulksvc_qp_info* info = container_of(info_refcount, struct hfi2_bulksvc_qp_info, refcount);
	struct verbs_ordered_wr *ow, *ow_tmp;

	list_for_each_entry_safe(ow, ow_tmp,
				 &info->ordering.pending, node) {
		list_del_init(&ow->node);
		verbs_ordered_wr_reap(ow);
	}

	{
		struct verbs_deferred_wr *def, *def_tmp;

		list_for_each_entry_safe(def, def_tmp,
					 &info->deferred_wrs, list) {
			list_del(&def->list);
			verbs_deferred_free(def);
		}
	}

	/* Balance verbs-state counter if a wake raced teardown. */
	if (info->gate_retry_pending) {
		info->gate_retry_pending = false;
		atomic_dec(&info->verbs_state->gate_retry_pending_count[info->lane]);
	}
	/* Same, for a latched-but-unrun GBN teardown reap. */
	if (info->gbn_teardown_pending) {
		info->gbn_teardown_pending = false;
		atomic_dec(&info->verbs_state->gbn_teardown_pending_count[info->lane]);
	}

	WARN_ON(info->inflight_head != info->inflight_tail);

	mutex_lock(&info->verbs_state->qp_infos_lock);
	list_del(&info->node);
	mutex_unlock(&info->verbs_state->qp_infos_lock);

	for (u32 i = 0; i < info->inflight_size; i++)
		WARN_ON_ONCE(info->inflight_ring[i].handle.value != 0);
	kvfree(info->inflight_ring);
	kfree(info);
}

void hfi2_bulksvc_qp_info_put(struct hfi2_bulksvc_qp_info *qp_info)
{
	kref_put(&qp_info->refcount, bulksvc_qp_info_destroy);
}

/*
 * Allocate a cmd/cmpl from the per-svc slab cache.  GFP_NOWAIT so we
 * never enter reclaim (some callers are atomic, and the BTS thread is
 * on the receiving end of reclaim via WQ_MEM_RECLAIM); on @dd->node;
 * failure is propagated as -ENOMEM and surfaces as a failed WR/CQE.
 */
static struct hfi2_bulksvc_verbs_cmd *
__bts_verbs_cmd_cache_alloc(struct hfi2_bulksvc *svc, gfp_t gfp)
{
	struct hfi2_bulksvc_verbs_cmd *cmd;

	if (WARN_ON(!svc || !svc->verbs_cmd_cache))
		return NULL;

	cmd = kmem_cache_alloc_node(svc->verbs_cmd_cache, gfp | __GFP_ZERO,
				    svc->dd->node);
	if (cmd)
		cmd->cache = svc->verbs_cmd_cache;
	return cmd;
}

static struct hfi2_bulksvc_verbs_cmd *
bts_verbs_cmd_cache_alloc(struct hfi2_bulksvc *svc)
{
	return __bts_verbs_cmd_cache_alloc(svc, GFP_NOWAIT | __GFP_NOWARN);
}

static struct hfi2_bulksvc_verbs_cmpl *
bts_verbs_cmpl_cache_alloc(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_verbs_cmpl *cmpl;

	if (WARN_ON(!svc || !svc->verbs_cmpl_cache))
		return NULL;

	cmpl = kmem_cache_alloc_node(svc->verbs_cmpl_cache,
				     GFP_NOWAIT | __GFP_NOWARN | __GFP_ZERO,
				     svc->dd->node);
	if (cmpl)
		cmpl->cache = svc->verbs_cmpl_cache;
	return cmpl;
}

struct hfi2_bulksvc_verbs_cmd* hfi2_bulksvc_verbs_cmd_rdma_create(
				 struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_qp_info *qp_info,
				 struct rvt_qp* qp,
				 struct verbs_txreq *txreq)
{
	struct hfi2_bulksvc_verbs_cmd *cmd = bts_verbs_cmd_cache_alloc(svc);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmd->op = HFI2_BULKSVC_VERBS_CMD_OP_RDMA;
	INIT_LIST_HEAD(&cmd->ord_wr.node);
	cmd->ord_wr.seq = 0;
	cmd->ord_wr.type = ORDERED_WR_RDMAVT;
	/* No ring slot until verbs_inflight_add stamps one; keeps the
	 * pre-add error/flush retire paths from removing a bogus slot. */
	cmd->ord_wr.ring_slot = VERBS_INFLIGHT_NO_SLOT;

	kref_init(&cmd->refcount);

	hfi2_get_txreq(txreq);
	cmd->rdma.txreq = txreq;
	rvt_get_qp(qp);
	cmd->rdma.qp = qp;
	hfi2_bulksvc_qp_info_get(qp_info);
	cmd->rdma.qp_info = qp_info;
	return cmd;
}

struct hfi2_bulksvc_verbs_cmd * hfi2_bulksvc_verbs_cmd_mr_reg_create(
				 struct hfi2_bulksvc *svc,
				 struct rvt_mregion *mr)
{
	struct hfi2_bulksvc_verbs_cmd *cmd = bts_verbs_cmd_cache_alloc(svc);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmd->op = HFI2_BULKSVC_VERBS_CMD_OP_MR_REG;
	kref_init(&cmd->refcount);

	rvt_get_mr(mr);
	cmd->mr_reg.mr = mr;
	/* Currently in user thread, but once scheduled, mr fields can
	 * be overwritten by rvt_map_mr_sg/rvt_fast_reg_mr before bulksvc
	 * processes this command. Snapshot all needed fields by value.
	 */
	cmd->mr_reg.key = mr->lkey;
	cmd->mr_reg.user_base = mr->user_base;
	cmd->mr_reg.length = mr->length;
	cmd->mr_reg.access_flags = mr->access_flags;

	return cmd;
}

static void bts_verbs_cmd_mr_dereg_init(struct hfi2_bulksvc_verbs_cmd *cmd,
					struct rvt_mregion *mr)
{
	cmd->op = HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG;
	kref_init(&cmd->refcount);
	rvt_get_mr(mr);
	cmd->mr_dereg.mr = mr;
	/* Currently in user thread, but once scheduled, the mr->lkey can
	 * be overwritten in rvt_fast_reg_mr so save key explicitly here
	 */
	cmd->mr_dereg.key = mr->lkey;
}

struct hfi2_bulksvc_verbs_cmd * hfi2_bulksvc_verbs_cmd_mr_dereg_create(
				 struct hfi2_bulksvc *svc,
				 struct rvt_mregion *mr)
{
	struct hfi2_bulksvc_verbs_cmd *cmd = bts_verbs_cmd_cache_alloc(svc);
	if (!cmd) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs cmd\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	bts_verbs_cmd_mr_dereg_init(cmd, mr);
	return cmd;
}

void hfi2_bulksvc_verbs_cmd_get(struct hfi2_bulksvc_verbs_cmd *cmd)
{
	kref_get(&cmd->refcount);
}

static void hfi2_bulksvc_verbs_cmd_destroy(struct kref *refcount)
{
	struct hfi2_bulksvc_verbs_cmd *cmd =
		container_of(refcount, struct hfi2_bulksvc_verbs_cmd, refcount);

	switch (cmd->op) {
	case HFI2_BULKSVC_VERBS_CMD_OP_RDMA:
		hfi2_bulksvc_qp_info_put(cmd->rdma.qp_info);
		rvt_put_qp(cmd->rdma.qp);
		hfi2_put_txreq(cmd->rdma.txreq);
		break;
	case HFI2_BULKSVC_VERBS_CMD_OP_MR_REG:
		rvt_put_mr(cmd->mr_reg.mr);
		break;
	case HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG:
		rvt_put_mr(cmd->mr_dereg.mr);
		break;
	default:
		pr_err("%s:%d:%s() bulksvc: Unknown cmd op %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->op);
		break;
	}
	kmem_cache_free(cmd->cache, cmd);
}

void hfi2_bulksvc_verbs_cmd_put(struct hfi2_bulksvc_verbs_cmd *cmd)
{
	kref_put(&cmd->refcount, hfi2_bulksvc_verbs_cmd_destroy);
}

struct hfi2_bulksvc_verbs_cmpl* hfi2_bulksvc_verbs_cmd_cmpl_create(
				 struct hfi2_bulksvc *svc,
				 struct hfi2_bulksvc_verbs_cmd *cmd,
				 u32 status)
{
	struct hfi2_bulksvc_verbs_cmpl *cmpl = bts_verbs_cmpl_cache_alloc(svc);
	if (!cmpl) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs completion\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmpl->type = HFI2_BULKSVC_VERBS_CMPL_TYPE_CMD;
	cmpl->cmd.bts_cmd = cmd;
	hfi2_bulksvc_verbs_cmd_get(cmpl->cmd.bts_cmd);
	cmpl->cmd.status = status;
	kref_init(&cmpl->refcount);
	return cmpl;
}

struct hfi2_bulksvc_verbs_cmpl* hfi2_bulksvc_verbs_access_cmpl_create(
				struct hfi2_bulksvc *svc,
				struct rvt_qp* qp,
				u32 lkey,
				__be32 user_immdt_be,
				u16 flags,
				int status)
{
	struct hfi2_bulksvc_verbs_cmpl *cmpl = bts_verbs_cmpl_cache_alloc(svc);
	if (!cmpl) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate verbs completion\n",
		       __FILENAME__, __LINE__, __func__);
		return NULL;
	}
	cmpl->type = HFI2_BULKSVC_VERBS_CMPL_TYPE_ACCESS;
	rvt_get_qp(qp);
	cmpl->access.qp = qp;
	cmpl->access.lkey = lkey;
	cmpl->access.user_immdt_be = user_immdt_be;
	cmpl->access.flags = flags;
	cmpl->access.status = status;
	kref_init(&cmpl->refcount);
	return cmpl;
}

static void hfi2_bulksvc_verbs_cmpl_destroy(struct kref *refcount)
{
	struct hfi2_bulksvc_verbs_cmpl *cmpl =
		container_of(refcount, struct hfi2_bulksvc_verbs_cmpl, refcount);
	switch (cmpl->type) {
	case HFI2_BULKSVC_VERBS_CMPL_TYPE_CMD:
		hfi2_bulksvc_verbs_cmd_put(cmpl->cmd.bts_cmd);
		break;
	case HFI2_BULKSVC_VERBS_CMPL_TYPE_ACCESS:
		rvt_put_qp(cmpl->access.qp);
		break;
	}
	kmem_cache_free(cmpl->cache, cmpl);
}

void hfi2_bulksvc_verbs_cmpl_put(struct hfi2_bulksvc_verbs_cmpl *cmpl)
{
	kref_put(&cmpl->refcount, hfi2_bulksvc_verbs_cmpl_destroy);
}

/*
 * rdmavt mr_priv_alloc hook.  Allocates the record in its blank state;
 * pages/dma_list/dms_mr are populated later (notify_mr_pages_set and
 * the BTS reg handler).
 */
void *verbs_bulksvc_mr_priv_alloc(struct hfi2_bulksvc *svc,
				  struct rvt_mregion *mr)
{
	struct bts_verbs_mr_record *rec;

	if (WARN_ON(!svc || !mr))
		return ERR_PTR(-EINVAL);

	rec = bts_verbs_mr_record_alloc(svc->dd, svc, mr);
	if (!rec)
		return ERR_PTR(-ENOMEM);

	rec->destroy_cmd = __bts_verbs_cmd_cache_alloc(svc, GFP_KERNEL);
	if (!rec->destroy_cmd) {
		bts_verbs_mr_record_put(rec);
		return ERR_PTR(-ENOMEM);
	}

	return rec;
}

/*
 * rdmavt notify_mr_pages_set hook.  Sleepable (verbs caller's thread).
 * Pins a fresh set and swaps it in - never mutates an existing set, so
 * any holder of the prior set keeps reading it until its refs drop.
 */
int verbs_bulksvc_notify_mr_pages_set(struct hfi2_bulksvc *svc,
				      struct rvt_mregion *mr)
{
	struct bts_verbs_mr_record *rec;
	struct bts_verbs_pageset *old, *ps;
	int rc;

	if (WARN_ON(!svc || !mr))
		return -EINVAL;

	rec = mr->driver_priv;
	if (WARN_ON(!rec))
		return -EINVAL;

	ps = bts_verbs_pageset_alloc(rec->dd, svc);
	if (!ps)
		return -ENOMEM;

	rc = bts_verbs_pageset_pin_and_map(ps, rec->rvt_mr);
	if (rc) {
		bts_verbs_pageset_put(ps);	/* frees the blank set */
		return rc;
	}

	/* Single writer (verbs core serialises map/reg/dereg per ib_mr). */
	old = rcu_dereference_protected(rec->cur_pageset, 1);
	rcu_assign_pointer(rec->cur_pageset, ps);
	if (old)
		bts_verbs_pageset_put(old);	/* drop prior reg-time ref */

	return 0;
}

/* Discarded dereg cmd (teardown drain) - release a blocked destroy
 * barrier so mr_priv_free can't hang waiting for a handler that won't run.
 */
void verbs_bulksvc_mr_dereg_cmd_discarded(struct rvt_mregion *mr)
{
	struct bts_verbs_mr_record *rec;

	if (WARN_ON(!mr))
		return;
	rec = mr->driver_priv;
	if (!rec)
		return;

	bts_verbs_mr_destroy_barrier_signal(rec);
}

/*
 * rdmavt mr_priv_free hook.  Sleepable, after rvt_check_refs() drained
 * the percpu_ref.  A still-registered MR (FastReg destroyed without a
 * trailing LOCAL_INV) is deregged through the BTS thread; we wait on the
 * destroy barrier and for the lane replicas to be released, then drop the
 * reg-time set ref and the record ref.  At teardown the BTS thread is gone,
 * so drop everything inline.
 */
void verbs_bulksvc_mr_priv_free(struct hfi2_bulksvc *svc,
				struct rvt_mregion *mr)
{
	struct bts_verbs_mr_record *rec = mr->driver_priv;
	struct hfi2_bulksvc_verbs_cmd *cmd;
	struct bts_verbs_pageset *ps;

	if (!rec)
		return;

	cmd = rec->destroy_cmd;
	rec->destroy_cmd = NULL;

	if (READ_ONCE(svc->stop_scheduling)) {
		kmem_cache_free(cmd->cache, cmd);
		/* No callback will run; drop the access and reg-time refs inline
		 * (release queues to mr_unmap_wq, or unmaps inline if gone).
		 */
		if (rec->access_pageset) {
			bts_verbs_pageset_put(rec->access_pageset);
			rec->access_pageset = NULL;
		}
		ps = rcu_dereference_protected(rec->cur_pageset, 1);
		RCU_INIT_POINTER(rec->cur_pageset, NULL);
		bts_verbs_pageset_put(ps);
		WRITE_ONCE(mr->driver_priv, NULL);
		bts_verbs_mr_record_put(rec);
		return;
	}

	if (READ_ONCE(rec->registered)) {
		bts_verbs_cmd_mr_dereg_init(cmd, mr);
		bts_verbs_mr_destroy_barrier_arm(rec);
		atomic_inc(&svc->verbs_state.cmd_queue.depth);
		mpsc_enqueue(&svc->verbs_state.cmd_queue.mpsc, &cmd->mpsc_node);
		hfi2_bulksvc_schedule(svc);
		bts_verbs_mr_destroy_barrier_wait(rec);
	} else {
		kmem_cache_free(cmd->cache, cmd);
	}

	/*
	 * Wait until every lane has unregistered its replica, i.e. each
	 * transfer using it has completed or been cancelled.  Returning
	 * earlier would let rdmavt unpin pages a lane still has an access
	 * on, so there is no timeout.  Like the primary lane's unregister,
	 * this does not wait for SDMA descriptors that a cancelled transfer
	 * already put on an engine.
	 */
	while (!wait_event_timeout(svc->lane_reps_wq,
				   !atomic_read(&rec->lane_reps_live) ||
				   READ_ONCE(svc->worker_exited),
				   10 * HZ))
		dd_dev_warn_ratelimited(svc->dd,
					"bts: MR lkey 0x%x still waiting for %d lane replicas\n",
					rec->rkey,
					atomic_read(&rec->lane_reps_live));

	ps = rcu_dereference_protected(rec->cur_pageset, 1);
	RCU_INIT_POINTER(rec->cur_pageset, NULL);
	bts_verbs_pageset_put(ps);

	WRITE_ONCE(mr->driver_priv, NULL);
	bts_verbs_mr_record_put(rec);
}

/* Per-svc verbs cmd/cmpl slab caches; name carries the unit number for
 * /proc/slabinfo.
 */
int hfi2_bulksvc_verbs_caches_init(struct hfi2_bulksvc *svc)
{
	char name[32];

	if (WARN_ON(!svc || !svc->dd))
		return -EINVAL;

	snprintf(name, sizeof(name), "hfi2_bts_verbs_cmd_%d", svc->dd->unit);
	svc->verbs_cmd_cache = kmem_cache_create(name,
			sizeof(struct hfi2_bulksvc_verbs_cmd),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (!svc->verbs_cmd_cache)
		return -ENOMEM;

	snprintf(name, sizeof(name), "hfi2_bts_verbs_cmpl_%d", svc->dd->unit);
	svc->verbs_cmpl_cache = kmem_cache_create(name,
			sizeof(struct hfi2_bulksvc_verbs_cmpl),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (!svc->verbs_cmpl_cache) {
		kmem_cache_destroy(svc->verbs_cmd_cache);
		svc->verbs_cmd_cache = NULL;
		return -ENOMEM;
	}

	snprintf(name, sizeof(name), "hfi2_bts_verbs_sge_%d", svc->dd->unit);
	svc->verbs_sge_cache = kmem_cache_create(name,
						 sizeof(struct direct_rdma_sge_info),
						 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!svc->verbs_sge_cache) {
		kmem_cache_destroy(svc->verbs_cmpl_cache);
		svc->verbs_cmpl_cache = NULL;
		kmem_cache_destroy(svc->verbs_cmd_cache);
		svc->verbs_cmd_cache = NULL;
		return -ENOMEM;
	}

	return 0;
}

void hfi2_bulksvc_verbs_caches_destroy(struct hfi2_bulksvc *svc)
{
	if (!svc)
		return;

	/* Caches must be empty here (teardown drains the queues first);
	 * kmem_cache_destroy WARNs otherwise.
	 */
	kmem_cache_destroy(svc->verbs_sge_cache);
	svc->verbs_sge_cache = NULL;
	if (svc->verbs_cmpl_cache) {
		kmem_cache_destroy(svc->verbs_cmpl_cache);
		svc->verbs_cmpl_cache = NULL;
	}
	if (svc->verbs_cmd_cache) {
		kmem_cache_destroy(svc->verbs_cmd_cache);
		svc->verbs_cmd_cache = NULL;
	}
}

int hfi2_bulksvc_verbs_state_init(struct hfi2_bulksvc_verbs_state *state)
{
	mutex_init(&state->qp_infos_lock);
	INIT_LIST_HEAD(&state->qp_infos);

	atomic64_set(&state->ring_full_deferrals, 0);
	for (u32 k = 0; k < HFI2_BULKSVC_MAX_LANES; k++) {
		atomic_set(&state->gate_retry_pending_count[k], 0);
		atomic_set(&state->gbn_teardown_pending_count[k], 0);
	}

	mpsc_init(&state->cmd_queue.mpsc);
	atomic_set(&state->cmd_queue.depth, 0);

	return 0;
}



int hfi2_bulksvc_verbs_dms_reg_client_id(struct hfi2_dms* dms)
{
	int rc = hfi2_dms_create_client_key(dms, VERBS_CLIENT_ID_START,
					    NULL, NULL);

	if (rc) {
		pr_err("Failed to create DMS client key for verbs %u\n",
			   VERBS_CLIENT_ID_START);
		return rc;
	}

	dms->ext_dest.resolve = hfi2_bulksvc_verbs_resolve_send_dest;
	dms->ext_dest.complete = hfi2_bulksvc_verbs_send_dest_complete;

	return 0;
}

void hfi2_bulksvc_verbs_release_client_id(struct hfi2_dms* dms)
{
	hfi2_dms_release_client_key(dms, VERBS_CLIENT_ID_START);
}

static int verbs_pin_range(void *provider_ctx, unsigned int from_page,
			   unsigned int npages, bool writable)
{
	struct hfi2_dms_mr *dms_mr = provider_ctx;
	struct bts_verbs_pageset *ps =
		container_of(dms_mr, struct bts_verbs_pageset, dms_mr);

	(void)writable; /* verbs MRs are pre-pinned bidirectional. */

	if (WARN_ON_ONCE(!ps))
		return -EFAULT;
	if (WARN_ON_ONCE(!ps->dms_mr.dma_list))
		return -EFAULT;
	if (from_page >= ps->dms_mr.npages_total ||
	    npages > ps->dms_mr.npages_total - from_page)
		return -EINVAL;

	return 0;
}

/* Single-MR verbs host copy: the concrete kmap_atomic mover keyed on the
 * provider's MR (provider_ctx is &ps->dms_mr).
 */
static int verbs_single_mr_memcpy(struct hfi2_dms_page_provider const *pp,
				  u64 byte_offset, u64 size, void *data,
				  bool is_read)
{
	if (WARN_ON_ONCE(!pp || !pp->provider_ctx))
		return -EFAULT;
	return verbs_host_mr_memcpy_fn(pp->provider_ctx, byte_offset, size,
				       data, is_read);
}

/* Tidset runs for a verbs MR: one run; verbs_pin_range only bounds-checks. */
static int verbs_mr_get_runs(struct hfi2_dms_page_provider const *pp,
			     u64 byte_offset, u64 max_bytes, bool writable,
			     struct hfi2_dms_run *runs, u32 max_runs)
{
	return hfi2_dms_single_mr_get_runs(pp, byte_offset, max_bytes, writable,
					   runs, max_runs, verbs_pin_range);
}

/*
 * Pack bytes [@off, @off + @len) of @ps, in the page set's byte coordinate,
 * into @w.  Kernel memory is read through the direct map, which is permanent
 * because hfi2 builds only for 64-bit architectures without highmem, and its
 * pages are checked before the first store, so a bad page writes nothing.
 * dma-buf memory has no direct CPU path here and is copied with
 * verbs_host_mr_memcpy_fn() through a HFI2_DMS_PIO_BOUNCE_BYTES stack buffer.
 * Verbs page sets are pinned for their lifetime, so this never sleeps on a
 * pin.  With @w NULL, only check what can be checked before a store.
 * Returns 0 or -errno; on error some of the range may be in @w, but none of
 * it when the page set is kernel memory.
 */
static int verbs_pageset_pio_check(struct bts_verbs_pageset *ps, u64 off,
				   u64 len)
{
	struct hfi2_dms_mr *const mr = &ps->dms_mr;
	u64 i;

	if (WARN_ON(off > mr->extended_vaddr.len ||
		    len > mr->extended_vaddr.len - off))
		return -EINVAL;
	if (!len || ps->mem_type != RVT_MEM_KERNEL)
		return 0;

	if (WARN_ON_ONCE(!ps->vaddrs))
		return -EFAULT;
	for (i = off / PAGE_SIZE; i <= (off + len - 1) / PAGE_SIZE; i++)
		if (WARN_ON_ONCE(!ps->vaddrs[i]))
			return -EFAULT;
	return 0;
}

static int verbs_pageset_pio_wr(struct bts_verbs_pageset *ps,
				struct hfi2_dms_pio_wr *w, u64 off, u64 len)
{
	struct hfi2_dms_mr *const mr = &ps->dms_mr;
	int ret;

	BUILD_BUG_ON(IS_ENABLED(CONFIG_HIGHMEM));

	ret = verbs_pageset_pio_check(ps, off, len);
	if (ret || !len || !w)
		return ret;

	if (ps->mem_type != RVT_MEM_KERNEL) {
		u8 bounce[HFI2_DMS_PIO_BOUNCE_BYTES] __aligned(sizeof(u64));

		while (len) {
			u32 const n = min_t(u64, len, sizeof(bounce));

			ret = verbs_host_mr_memcpy_fn(mr, off, n, bounce, true);
			if (ret)
				return ret;
			hfi2_dms_pio_wr_bytes(w, bounce, n);
			off += n;
			len -= n;
		}
		return 0;
	}

	while (len) {
		u64 const offset_in_page = off % PAGE_SIZE;
		u32 const n = min_t(u64, len, PAGE_SIZE - offset_in_page);

		hfi2_dms_pio_wr_bytes(w, (u8 *)ps->vaddrs[off / PAGE_SIZE] +
				      offset_in_page, n);
		off += n;
		len -= n;
	}
	return 0;
}

/*
 * Close a verbs pio_write: write the final partial qword, or end a failed one
 * with hfi2_dms_pio_wr_fail(), which writes nothing more when nothing was
 * stored yet.
 */
static int verbs_pio_wr_close(struct hfi2_dms_pio_wr *w, void __iomem *dest,
			      u64 len, int ret)
{
	if (ret)
		return hfi2_dms_pio_wr_fail(w, dest, len, ret);
	hfi2_dms_pio_wr_finish(w);
	return 0;
}

/* Single-MR verbs pio_write (the page_provider contract). */
static int verbs_single_mr_pio_write(struct hfi2_dms_page_provider const *pp,
				     u64 byte_offset, u64 len,
				     void __iomem *dest)
{
	struct hfi2_dms_pio_wr w = { .dest = dest };
	struct hfi2_dms_mr *mr = pp->provider_ctx;
	int ret = -EFAULT;

	if (!WARN_ON_ONCE(!mr))
		ret = verbs_pageset_pio_wr(container_of(mr,
							struct bts_verbs_pageset,
							dms_mr),
					   &w, byte_offset, len);
	return verbs_pio_wr_close(&w, dest, len, ret);
}

/* Caller must hold a page-set ref for the lifetime of any tracker
 * built from this provider (provider_ctx points into the set).
 */
static inline struct hfi2_dms_page_provider
verbs_mr_page_provider(struct bts_verbs_pageset *ps)
{
	return (struct hfi2_dms_page_provider) {
		.pin_range = verbs_pin_range,
		.next_src_run = hfi2_dms_single_mr_next_src_run,
		.memcpy = verbs_single_mr_memcpy,
		.pio_write = verbs_single_mr_pio_write,
		.get_runs = verbs_mr_get_runs,
		.resolve_start = hfi2_dms_single_mr_resolve_start,
		.promote = NULL,
		.provider_ctx = &ps->dms_mr,
		.length = ps->dms_mr.user.len,
		.p2p_flush = ps->mem_type == RVT_MEM_DMABUF ||
			ps->mem_type == RVT_MEM_DMABUF_DO,
	};
}

/* Page-run iterator that walks the WQE's SGEs as one logical byte stream,
 * for the source gather (the tidset load uses get_runs); each run is
 * bounded by a single segment so the DMA pages are contiguous within one MR's
 * dma_list.  In the refcounted model the dma_list lives in the per-segment
 * page set, not the mr_record.
 */
static int verbs_multiseg_next_src_run(struct hfi2_dms_page_provider const *pp,
				       u64 byte_offset, u64 max_bytes,
				       struct hfi2_dms_run *run)
{
	struct verbs_multiseg_ctx const *ctx = pp->provider_ctx;
	struct verbs_src_segment const *seg;
	u64 intra, mr_byte;
	u32 i;

	if (WARN_ON_ONCE(!ctx || !run))
		return -EFAULT;
	if (byte_offset >= ctx->total_bytes || max_bytes == 0)
		return -EINVAL;

	for (i = 0; i < ctx->nsegs; ++i) {
		seg = &ctx->segs[i];
		if (byte_offset < seg->wqe_byte_offset + seg->byte_length)
			break;
	}
	if (WARN_ON_ONCE(i == ctx->nsegs))
		return -EINVAL;

	intra = byte_offset - seg->wqe_byte_offset;
	mr_byte = seg->base_byte_offset + intra;
	*run = (struct hfi2_dms_run){
		.dma_pages = &seg->pageset->dms_mr.dma_list[mr_byte / PAGE_SIZE],
		.page_offset = mr_byte & (PAGE_SIZE - 1),
		.run_bytes = min_t(u64, seg->byte_length - intra, max_bytes),
	};
	return 0;
}

static int verbs_multiseg_pin_range(void *provider_ctx, unsigned int from_page,
				    unsigned int npages, bool writable)
{
	/* Multi-segment buffers are pre-pinned at registration. */
	(void)provider_ctx;
	(void)from_page;
	(void)npages;
	(void)writable;
	return 0;
}

/*
 * Tidset runs for a multi-segment buffer: one run per segment, from the
 * segment holding @byte_offset, in a single walk. Already pinned at
 * registration, so @writable needs no action.
 */
static int verbs_multiseg_get_runs(struct hfi2_dms_page_provider const *pp,
				   u64 byte_offset, u64 max_bytes, bool writable,
				   struct hfi2_dms_run *runs, u32 max_runs)
{
	struct verbs_multiseg_ctx const *ctx = pp->provider_ctx;
	u32 n = 0;
	u32 i;

	(void)writable;
	if (WARN_ON_ONCE(!ctx || !runs || !max_runs))
		return -EFAULT;
	if (byte_offset >= ctx->total_bytes || max_bytes == 0)
		return -EINVAL;

	for (i = 0; i < ctx->nsegs; ++i)
		if (byte_offset < ctx->segs[i].wqe_byte_offset +
				  ctx->segs[i].byte_length)
			break;
	if (WARN_ON_ONCE(i == ctx->nsegs))
		return -EINVAL;

	for (; i < ctx->nsegs && n < max_runs && max_bytes; ++i) {
		struct verbs_src_segment const *seg = &ctx->segs[i];
		u64 const intra = byte_offset - seg->wqe_byte_offset;
		u64 const mr_byte = seg->base_byte_offset + intra;
		u64 const len = min_t(u64, seg->byte_length - intra, max_bytes);

		if (!len)	/* empty segment */
			continue;
		runs[n++] = (struct hfi2_dms_run){
			.dma_pages = &seg->pageset->dms_mr.dma_list[mr_byte / PAGE_SIZE],
			.page_offset = mr_byte & (PAGE_SIZE - 1),
			.run_bytes = len,
		};
		byte_offset += len;
		max_bytes -= len;
	}
	return n;
}

static int verbs_multiseg_resolve_start(struct hfi2_dms_page_provider const *pp,
					u64 mr_offset, u32 size,
					u64 *byte_offset_out)
{
	(void)pp;
	(void)mr_offset;
	(void)size;
	*byte_offset_out = 0;
	return 0;
}

/* Multi-segment host copy: walk the WQE's segment list by 0-based logical
 * offset and move @size bytes between @data and the per-segment MRs;
 * @is_read picks the direction.  Subsumes the former latch_read/latch_write
 * pair so the seg-walk lives once.
 */
static int verbs_multiseg_memcpy(struct hfi2_dms_page_provider const *pp,
				 u64 byte_offset, u64 size, void *data,
				 bool is_read)
{
	struct verbs_multiseg_ctx const *ctx = pp->provider_ctx;
	u8 *cdata = data;
	u32 i = 0;

	if (WARN_ON_ONCE(!ctx || !data))
		return -EFAULT;
	if (byte_offset >= ctx->total_bytes ||
	    size > ctx->total_bytes - byte_offset)
		return -EINVAL;

	while (size > 0) {
		struct verbs_src_segment const *seg;
		u64 intra, chunk;
		int ret;

		for (; i < ctx->nsegs; ++i) {
			seg = &ctx->segs[i];
			if (byte_offset < seg->wqe_byte_offset + seg->byte_length)
				break;
		}
		if (WARN_ON_ONCE(i == ctx->nsegs))
			return -EINVAL;

		intra = byte_offset - seg->wqe_byte_offset;
		chunk = min_t(u64, size, seg->byte_length - intra);
		ret = verbs_host_mr_memcpy_fn(&seg->pageset->dms_mr,
					      seg->base_byte_offset + intra,
					      chunk, cdata, is_read);
		if (ret < 0)
			return ret;

		byte_offset += chunk;
		cdata += chunk;
		size -= chunk;
	}
	return 0;
}

/*
 * Multi-segment verbs pio_write: walk the WQE's segments in stream order and
 * pack them into one qword stream, so a qword that straddles two segments is
 * completed across them.  Each segment is read as verbs_pageset_pio_wr()
 * reads its page set: kernel pages directly, dma-buf through a bounce chunk.
 */
static int verbs_multiseg_pio_write(struct hfi2_dms_page_provider const *pp,
				    u64 byte_offset, u64 len,
				    void __iomem *dest)
{
	struct verbs_multiseg_ctx const *ctx = pp->provider_ctx;
	struct hfi2_dms_pio_wr w = { .dest = dest };
	u64 const total = len;
	int ret = 0;
	u32 i = 0;

	if (WARN_ON_ONCE(!ctx) || byte_offset > ctx->total_bytes ||
	    len > ctx->total_bytes - byte_offset)
		return -EINVAL;

	/* Two passes: check every segment, then write; see @pio_write. */
	for (int pass = 0; pass < 2 && !ret; pass++) {
		u64 off = byte_offset;
		u64 left = len;

		for (i = 0; !ret && left; ) {
			struct verbs_src_segment const *seg;
			u64 intra, chunk;

			for (; i < ctx->nsegs; ++i) {
				seg = &ctx->segs[i];
				if (off < seg->wqe_byte_offset + seg->byte_length)
					break;
			}
			if (WARN_ON_ONCE(i == ctx->nsegs)) {
				ret = -EINVAL;
				break;
			}

			intra = off - seg->wqe_byte_offset;
			chunk = min_t(u64, left, seg->byte_length - intra);
			ret = verbs_pageset_pio_wr(seg->pageset, pass ? &w : NULL,
						   seg->base_byte_offset + intra,
						   chunk);
			off += chunk;
			left -= chunk;
		}
	}
	return verbs_pio_wr_close(&w, dest, total, ret);
}

static inline bool verbs_multiseg_is_p2p(const struct verbs_multiseg_ctx *ctx)
{
	u32 i;

	for (i = 0; i < ctx->nsegs; i++) {
		enum rvt_mem_type t = ctx->segs[i].pageset->mem_type;

		if (t == RVT_MEM_DMABUF || t == RVT_MEM_DMABUF_DO)
			return true;
	}
	return false;
}

static inline struct hfi2_dms_page_provider
verbs_multiseg_page_provider(struct verbs_multiseg_ctx *ctx)
{
	return (struct hfi2_dms_page_provider) {
		.pin_range = verbs_multiseg_pin_range,
		.next_src_run = verbs_multiseg_next_src_run,
		.memcpy = verbs_multiseg_memcpy,
		.pio_write = verbs_multiseg_pio_write,
		.get_runs = verbs_multiseg_get_runs,
		.resolve_start = verbs_multiseg_resolve_start,
		.promote = NULL,
		.provider_ctx = ctx,
		.length = ctx->total_bytes,
		.p2p_flush = verbs_multiseg_is_p2p(ctx),
	};
}

/*
 * Fuse physically-abutting adjacent segments in place, dropping the absorbed
 * segment's duplicate page-set ref.  Two segments fuse only when they latched
 * the same page set (pointer equality => same MR backing) and the kept
 * segment's MR byte range ends exactly where the next one begins.  A DEST
 * fuse additionally requires the join to fall on a qword boundary so the TID
 * landing plane stays qword-aligned; SOURCE has no such constraint.  Returns
 * the surviving segment count; segs[0..ret) hold the fused layout.
 */
static u32 verbs_coalesce_segs(struct verbs_src_segment *segs, u32 n,
			       enum verbs_pp_dir dir)
{
	u32 w = 0, r;

	for (r = 1; r < n; r++) {
		struct verbs_src_segment *keep = &segs[w];
		u64 keep_end = keep->base_byte_offset + keep->byte_length;
		bool abut = keep->pageset == segs[r].pageset &&
			    keep_end == segs[r].base_byte_offset;
		bool qw_ok = dir == VERBS_PP_SOURCE ||
			     (keep_end & 0x7) == 0;

		if (abut && qw_ok) {
			keep->byte_length += segs[r].byte_length;
			bts_verbs_pageset_put(segs[r].pageset);
		} else {
			segs[++w] = segs[r];
		}
	}
	return w + 1;
}

static int convert_wqe_to_page_provider(struct hfi2_bulksvc *svc, u32 num_sge,
					enum verbs_pp_dir dir, gfp_t gfp,
					verbs_resolve_seg_fn resolve, void *rctx,
					struct verbs_pp_result *out)
{
	struct verbs_multiseg_ctx *ctx = NULL;
	struct verbs_src_segment single_seg;
	struct verbs_src_segment *segs;
	u32 nsegs, i;
	u64 wqe_off;
	int rc;

	(void)svc;
	memset(out, 0, sizeof(*out));

	if (WARN_ON_ONCE(num_sge == 0))
		return -EINVAL;

	if (num_sge == 1) {
		segs = &single_seg;
	} else {
		ctx = kzalloc(struct_size(ctx, segs, num_sge), gfp);
		if (!ctx)
			return -ENOMEM;
		segs = ctx->segs;
	}

	for (i = 0; i < num_sge; i++) {
		rc = resolve(rctx, i, &segs[i]);
		if (rc) {
			while (i-- > 0)
				bts_verbs_pageset_put(segs[i].pageset);
			kfree(ctx);
			return rc;
		}
	}

	nsegs = (num_sge == 1) ? 1 : verbs_coalesce_segs(segs, num_sge, dir);

	wqe_off = 0;
	out->total_bytes = 0;
	for (i = 0; i < nsegs; i++) {
		segs[i].wqe_byte_offset = wqe_off;
		wqe_off += segs[i].byte_length;
		out->total_bytes += segs[i].byte_length;
	}

	/*
	 * After coalescing a multi-segment DEST, a surviving interior segment
	 * may have no qword-aligned middle at all. _tidset_enable lands such a
	 * segment entirely through the tidset bounce page, so no per-SGE
	 * fallback is required.
	 */

	if (nsegs == 1) {
		out->pageset = segs[0].pageset;
		out->provider = verbs_mr_page_provider(out->pageset);
		out->rbuf_start_offset = (dir == VERBS_PP_SOURCE) ?
			(out->pageset->dms_mr.user.addr +
			 (segs[0].base_byte_offset -
			  out->pageset->dms_mr.region_offset)) :
			segs[0].base_byte_offset;
		kfree(ctx);	/* NULL when num_sge==1 stack path */
		return 0;
	}

	ctx->nsegs = nsegs;
	ctx->total_bytes = out->total_bytes;
	out->multiseg = ctx;
	out->provider = verbs_multiseg_page_provider(ctx);
	out->rbuf_start_offset = 0;
	return 0;
}

#ifdef CONFIG_INFINIBAND_HFI2_ROCE
/*
 * RoCE-only: the SDMA bundle emitter in dms_roce.c reads the page set
 * DMA list directly, so the provider lives next to the private
 * bts_verbs_pageset definition but is not built for OPA-only kernels.
 */
static int verbs_source_next_run(const struct hfi2_dms_page_provider *provider,
				 u64 offset, u64 max_bytes,
				 struct hfi2_dms_run *run)
{
	struct hfi2_bulksvc_verbs_source *source = provider->provider_ctx;
	u32 i;

	if (!source || !run || !max_bytes || offset >= source->length)
		return -EINVAL;
	for (i = 0; i < source->num_segments; i++) {
		struct hfi2_bulksvc_verbs_source_segment *seg =
			&source->segments[i];
		u64 within;

		if (offset >= seg->stream_offset + seg->length)
			continue;
		within = seg->page_offset + offset - seg->stream_offset;
		*run = (struct hfi2_dms_run) {
			.dma_pages = &seg->pageset->dms_mr.dma_list[within / PAGE_SIZE],
			.page_offset = within & (PAGE_SIZE - 1),
			.run_bytes = min_t(u64, max_bytes,
					      seg->length - (offset - seg->stream_offset)),
		};
		return 0;
	}
	return -EINVAL;
}

/*
 * Find the segment holding stream byte @offset; return its index, or
 * source->num_segments if none.  @i is where to start looking.
 */
static u32 verbs_source_seg(const struct hfi2_bulksvc_verbs_source *source,
			    u64 offset, u32 i)
{
	for (; i < source->num_segments; i++)
		if (offset < source->segments[i].stream_offset +
			     source->segments[i].length)
			break;
	return i;
}

static int verbs_source_memcpy(const struct hfi2_dms_page_provider *provider,
			       u64 offset, u64 size, void *data, bool is_read)
{
	struct hfi2_bulksvc_verbs_source *source = provider->provider_ctx;
	u8 *cdata = data;
	u32 i = 0;

	if (WARN_ON_ONCE(!source || !data))
		return -EFAULT;
	if (offset > source->length || size > source->length - offset)
		return -EINVAL;

	while (size) {
		struct hfi2_bulksvc_verbs_source_segment *seg;
		u64 within, chunk;
		int ret;

		i = verbs_source_seg(source, offset, i);
		if (WARN_ON_ONCE(i == source->num_segments))
			return -EINVAL;
		seg = &source->segments[i];
		within = offset - seg->stream_offset;
		chunk = min_t(u64, size, seg->length - within);
		ret = verbs_host_mr_memcpy_fn(&seg->pageset->dms_mr,
					      seg->page_offset + within, chunk,
					      cdata, is_read);
		if (ret < 0)
			return ret;
		offset += chunk;
		cdata += chunk;
		size -= chunk;
	}
	return 0;
}

static int verbs_source_pio_write(const struct hfi2_dms_page_provider *provider,
				  u64 offset, u64 len, void __iomem *dest)
{
	struct hfi2_bulksvc_verbs_source *source = provider->provider_ctx;
	struct hfi2_dms_pio_wr w = { .dest = dest };
	u64 const total = len;
	int ret = 0;
	u32 i = 0;

	if (WARN_ON_ONCE(!source) || offset > source->length ||
	    len > source->length - offset)
		return -EINVAL;

	/* Two passes: check every segment, then write; see @pio_write. */
	for (int pass = 0; pass < 2 && !ret; pass++) {
		u64 off = offset;
		u64 left = len;

		for (i = 0; !ret && left; ) {
			struct hfi2_bulksvc_verbs_source_segment *seg;
			u64 within, chunk;

			i = verbs_source_seg(source, off, i);
			if (WARN_ON_ONCE(i == source->num_segments)) {
				ret = -EINVAL;
				break;
			}
			seg = &source->segments[i];
			within = off - seg->stream_offset;
			chunk = min_t(u64, left, seg->length - within);
			ret = verbs_pageset_pio_wr(seg->pageset, pass ? &w : NULL,
						   seg->page_offset + within,
						   chunk);
			off += chunk;
			left -= chunk;
		}
	}
	return verbs_pio_wr_close(&w, dest, total, ret);
}

int hfi2_bulksvc_verbs_source_provider_init(struct hfi2_bulksvc_verbs_source *source,
					    struct hfi2_bulksvc_verbs_source_segment *segments,
					    u32 segment_cap, const struct rvt_sge *sges,
					    u32 num_sge)
{
	u64 stream_offset = 0;
	u32 i;

	if (!source || !segments || !sges || !num_sge || num_sge > segment_cap)
		return -EINVAL;
	*source = (struct hfi2_bulksvc_verbs_source) {
		.segments = segments,
	};
	memset(segments, 0, num_sge * sizeof(*segments));

	for (i = 0; i < num_sge; i++) {
		const struct rvt_sge *sge = &sges[i];
		struct hfi2_roce_mr_priv *mr_priv;
		struct hfi2_bulksvc_verbs_source_segment *seg;
		u64 page_offset;
		unsigned long flags;

		if (!sge->sge_length)
			continue;
		if (!sge->mr || !sge->mr->driver_priv)
			goto err;
		seg = &segments[source->num_segments];
		mr_priv = sge->mr->driver_priv;
		spin_lock_irqsave(&mr_priv->pageset_lock, flags);
		seg->pageset = mr_priv->pageset;
		if (seg->pageset)
			bts_verbs_pageset_get(seg->pageset);
		spin_unlock_irqrestore(&mr_priv->pageset_lock, flags);
		if (!seg->pageset)
			goto err;
		page_offset = (u64)sge->m * RVT_SEGSZ + sge->n;
		page_offset *= PAGE_SIZE;
		page_offset += offset_in_page(sge->mem.vaddr);
		seg->page_offset = page_offset;
		seg->stream_offset = stream_offset;
		seg->length = sge->sge_length;
		stream_offset += seg->length;
		source->num_segments++;
	}

	if (!source->num_segments)
		return -EINVAL;
	source->length = stream_offset;
	source->provider = (struct hfi2_dms_page_provider) {
		.next_src_run = verbs_source_next_run,
		.memcpy = verbs_source_memcpy,
		.pio_write = verbs_source_pio_write,
		.provider_ctx = source,
		.length = source->length,
	};
	return 0;

err:
	hfi2_bulksvc_verbs_source_provider_release(source);
	return -ENOENT;
}

void hfi2_bulksvc_verbs_source_provider_release(struct hfi2_bulksvc_verbs_source *source)
{
	struct hfi2_bulksvc_verbs_source_segment *segments;
	u32 i;

	if (!source)
		return;
	segments = source->segments;
	for (i = 0; i < source->num_segments; i++)
		bts_verbs_pageset_put(segments[i].pageset);
	*source = (struct hfi2_bulksvc_verbs_source) {
		.segments = segments,
	};
}
#endif /* CONFIG_INFINIBAND_HFI2_ROCE */

/*
 * Verbs SEND target-landing context.  Carries the popped RWQE's wr_id +
 * the latched recv page set (its kref anchors the dest buffer for the
 * async RTT) from WRITE_START handling to rx-tracker completion, where the
 * recv CQE is posted and the ref released.  BTS-thread only.
 */
struct bts_verbs_send_dest {
	struct hfi2_bulksvc *svc;
	struct rvt_qp *qp;		/* rvt_get_qp ref held */
	/* Single-SGE recv latches one page set in @pageset; a multi-SGE recv
	 * latches one page set per segment inside @multiseg.  Exactly one is
	 * set (kzalloc leaves the other NULL); the teardown keys on @multiseg.
	 */
	struct bts_verbs_pageset *pageset;
	struct verbs_multiseg_ctx *multiseg;
	u64 wr_id;
	u32 byte_len;
	__be32 user_immdt_be;		/* big-endian SEND_WITH_IMM immediate */
	u16 flags;
};

/* Post a recv CQE for a popped-but-failed SEND landing (pop-last tail
 * already advanced); mirrors the success fill in send_dest_complete.
 */
static void verbs_send_dest_post_err_cqe(struct rvt_qp *qp, u64 wr_id,
					 bool solicited,
					 enum ib_wc_status status)
{
	struct ib_wc wc = {
		.wr_id = wr_id,
		.status = status,
		.opcode = IB_WC_RECV,
		.qp = &qp->ibqp,
		.src_qp = qp->remote_qpn,
		.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX,
		.sl = rdma_ah_get_sl(&qp->remote_ah_attr),
	};

	rvt_recv_cq(qp, &wc, solicited, RVT_QP_LOCK_STATE_NONE);
}

enum hfi2_dms_ext_dest_status
hfi2_bulksvc_verbs_resolve_send_dest(struct hfi2_dms *dms,
				     union hfi2_dms_key dms_key,
				     u64 imm_data, u64 order_key, u16 flags,
				     u32 xfer_size,
				     struct hfi2_dms_page_provider *provider_out,
				     u64 *rbuf_start_offset_out,
				     void **cmpl_ctx_out)
{
	/*
	 * Runs on the lane the peer QP's traffic lands on, which may not be
	 * qp_info->lane; see the receive-side note there.
	 */
	struct hfi2_bulksvc *svc = dms->dd->bulksvc;
	struct hfi2_bulksvc_verbs_state *verbs_state = &svc->verbs_state;
	u32 const qpn = dms_key.access;
	u16 const send_seq = (u16)((order_key >> 48) & 0xFFFF);
	bool const solicited =
		!!(flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED);
	struct bts_verbs_send_dest *ctx;
	struct hfi2_bulksvc_qp_info *pos;
	struct hfi2_bulksvc_qp_info *qp_info = NULL;
	struct rvt_qp *qp = NULL;
	unsigned long r_flags;
	int ret;

	/*
	 * Route to the destination QP (named by dms_key.access).  Pin the QP
	 * with rvt_get_qp() while still holding qp_infos_lock: qp_priv_free()
	 * removes the qp_info from this list under the same lock and
	 * rvt_destroy_qp() then drops the last QP reference, so taking the
	 * reference after releasing the lock races teardown and can pin a
	 * freed rvt_qp.  This mirrors the drain path's lifetime discipline.
	 */
	mutex_lock(&verbs_state->qp_infos_lock);
	list_for_each_entry(pos, &verbs_state->qp_infos, node) {
		if (!pos->owner)
			continue;
		if (pos->owner->ibqp.qp_num == qpn) {
			qp = pos->owner;
			qp_info = pos;
			rvt_get_qp(qp);
			break;
		}
	}
	mutex_unlock(&verbs_state->qp_infos_lock);
	if (!qp)
		return HFI2_DMS_EXT_DEST_DROP;

	/*
	 * Check the SEND sequence number against the expected value per-QP.
	 * seq <  expected: replay of an already-consumed SEND
	 * seq >  expected: RNR so the initiator retries
	 * seq == expected: the next in-order SEND
	 */
	{
		s16 const seq_gap = (s16)(send_seq - qp_info->rx_expected_send_seq);

		if (unlikely(seq_gap != 0)) {
			dd_dev_warn_ratelimited(svc->dd,
						"DMS_DIAG: SEND seq gap qpn=%u expected=%u received=%u\n",
						qpn, qp_info->rx_expected_send_seq, send_seq);
			rvt_put_qp(qp);
			return seq_gap < 0 ? HFI2_DMS_EXT_DEST_ALREADY_DELIVERED
					    : HFI2_DMS_EXT_DEST_RNR;
		}
	}

	/* Pre-pop alloc (pop-last): the only NACK-able failure that must
	 * precede rvt_get_rwqe is this allocation.
	 */
	ctx = kzalloc_node(sizeof(*ctx), GFP_ATOMIC, svc->dd->node);
	if (!ctx) {
		rvt_put_qp(qp);
		return HFI2_DMS_EXT_DEST_NOMEM;
	}

	spin_lock_irqsave(&qp->r_lock, r_flags);
	ret = rvt_get_rwqe(qp, false);
	if (ret == 0) {
		spin_unlock_irqrestore(&qp->r_lock, r_flags);
		rvt_put_qp(qp);
		kfree(ctx);
		return HFI2_DMS_EXT_DEST_RNR;
	}
	if (ret < 0) {
		/* init_sge already advanced the tail AND posted an
		 * IB_WC_LOC_PROT_ERR recv CQE; do not post a second one.
		 */
		spin_unlock_irqrestore(&qp->r_lock, r_flags);
		rvt_put_qp(qp);
		kfree(ctx);
		return HFI2_DMS_EXT_DEST_CONSUMED;
	}
	if (!__test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags)) {
		spin_unlock_irqrestore(&qp->r_lock, r_flags);
		rvt_put_qp(qp);
		kfree(ctx);
		return HFI2_DMS_EXT_DEST_DROP;
	}

	ctx->wr_id = qp->r_wr_id;

	qp_info->rx_expected_send_seq = send_seq + 1;

	/* A SEND cannot span recv WQEs: the whole aggregated message must
	 * fit the single popped RWQE; the RWQE is already consumed, so an
	 * over-length message posts a length-error recv CQE.
	 */
	if (xfer_size > qp->r_len) {
		rvt_put_ss(&qp->r_sge);
		verbs_send_dest_post_err_cqe(qp, ctx->wr_id, solicited,
					     IB_WC_LOC_LEN_ERR);
		spin_unlock_irqrestore(&qp->r_lock, r_flags);
		rvt_put_qp(qp);
		kfree(ctx);
		return HFI2_DMS_EXT_DEST_CONSUMED;
	}

	/*
	 * One DMS landing per SEND WQE: scatter the aggregated payload across
	 * the popped RWQE's recv SGEs via convert_wqe_to_page_provider.  A
	 * contiguous recv list collapses to a single zero-alloc dest provider;
	 * a discontiguous one builds a multiseg dest ctx.  r_lock is held and
	 * the RWQE is already popped, so every resolve failure past this point
	 * must post an error recv CQE (pop-last rule) and return CONSUMED.
	 *
	 * r_sge holds the first SGE inline in .sge and the rest in .sg_list[];
	 * the resolver reads them read-only (no rvt cursor mutation), so the
	 * SGEs stay intact across the resolve loop.
	 */
	{
		struct verbs_send_dest_rctx rctx = {
			.svc = svc,
			.rss = &qp->r_sge,
		};
		struct verbs_pp_result out;

		ret = convert_wqe_to_page_provider(svc, qp->r_sge.num_sge,
			VERBS_PP_DEST, GFP_ATOMIC,
			verbs_send_dest_resolve_seg, &rctx, &out);
		if (ret < 0) {
			rvt_put_ss(&qp->r_sge);
			verbs_send_dest_post_err_cqe(qp, ctx->wr_id,
				solicited, IB_WC_LOC_PROT_ERR);
			spin_unlock_irqrestore(&qp->r_lock, r_flags);
			rvt_put_qp(qp);
			kfree(ctx);
			return HFI2_DMS_EXT_DEST_CONSUMED;
		}

		/* The provider references only the latched page sets, not
		 * r_sge, so drop the init_sge percpu_ref now; the per-segment
		 * krefs anchor the buffers for the async RTT.
		 */
		rvt_put_ss(&qp->r_sge);
		spin_unlock_irqrestore(&qp->r_lock, r_flags);

		ctx->svc = svc;
		ctx->qp = qp;
		ctx->pageset = out.pageset;
		ctx->multiseg = out.multiseg;
		ctx->byte_len = xfer_size;
		ctx->flags = flags;
		ctx->user_immdt_be =
			(flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) ?
			cpu_to_be32((u32)imm_data) : cpu_to_be32(0);

		*provider_out = out.provider;
		*rbuf_start_offset_out = out.rbuf_start_offset;
		*cmpl_ctx_out = ctx;
		return HFI2_DMS_EXT_DEST_OK;
	}
}

/*
 * TODO: terminal give-up is not signalled to the peer.  When the
 * initiator exhausts its retry budget it errors only its own QP;
 * a receiver stalled on this wr_seq then waits for a replay that
 * never arrives.  Needs a peer-notify so the receiver can flush
 * the stalled wr_seq and error its QP too.
 */
void hfi2_bulksvc_verbs_send_dest_complete(struct hfi2_dms *dms,
					   void *cmpl_ctx, int status)
{
	struct bts_verbs_send_dest *ctx = cmpl_ctx;
	struct rvt_qp *qp;

	if (WARN_ON_ONCE(!ctx))
		return;
	qp = ctx->qp;

	/*
	 * GBN: a cancelled/errored SEND access posts NO recv CQE.  The RWQE was
	 * already popped at resolve time (pop-last), so a suppressed CQE leaves
	 * that receive WQE consumed with no completion; the sender replays this
	 * wr_seq (a fresh completion delivers it) or terminally errors the QP.
	 * Delivering here would double-post the recv CQE on replay.  Still
	 * release the provider/QP ref/ctx that this completion owns.
	 */
	if (status < 0) {
		if (ctx->multiseg) {
			for (u32 i = 0; i < ctx->multiseg->nsegs; i++)
				bts_verbs_pageset_put(ctx->multiseg->segs[i].pageset);
			kfree(ctx->multiseg);
		} else if (ctx->pageset) {
			bts_verbs_pageset_put(ctx->pageset);
		}
		rvt_put_qp(qp);
		kfree(ctx);
		return;
	}

	struct ib_wc wc = {
		.wr_id = ctx->wr_id,
		.status = (status == 0) ? IB_WC_SUCCESS : IB_WC_GENERAL_ERR,
		.qp = &qp->ibqp,
		.src_qp = qp->remote_qpn,
		.byte_len = ctx->byte_len,
		.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX,
		.sl = rdma_ah_get_sl(&qp->remote_ah_attr),
	};

	/* Both send and send_imm use IB_WC_RECV opcode */
	wc.opcode = IB_WC_RECV;
	if (ctx->flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_IMMDT) {
		wc.wc_flags = IB_WC_WITH_IMM;
		wc.ex.imm_data = ctx->user_immdt_be;
	}

	rvt_recv_cq(qp, &wc,
		    !!(ctx->flags & HFI2_BULKSVC_VERBS_WRITE_FLAGS_SOLICITED),
		    RVT_QP_LOCK_STATE_NONE);

	/* Release the per-segment page sets for a multi-SGE recv, else the
	 * single latched page set; resolve sets exactly one shape.
	 */
	if (ctx->multiseg) {
		for (u32 i = 0; i < ctx->multiseg->nsegs; i++)
			bts_verbs_pageset_put(ctx->multiseg->segs[i].pageset);
		kfree(ctx->multiseg);
	} else if (ctx->pageset) {
		bts_verbs_pageset_put(ctx->pageset);
	}
	rvt_put_qp(qp);
	kfree(ctx);
}

/*
 * Allocate a blank record bound to @rvt_mr (from hfi2_mr_priv_alloc); it
 * lives for the rvt_mregion's full lifetime.  The page set is allocated
 * separately by notify_mr_pages_set.
 */
static struct bts_verbs_mr_record *bts_verbs_mr_record_alloc(
	struct hfi2_devdata *dd, struct hfi2_bulksvc *svc,
	struct rvt_mregion *rvt_mr)
{
	if (WARN_ON(!rvt_mr))
		return NULL;

	struct bts_verbs_mr_record * const mr_record =
		kzalloc(sizeof(*mr_record), GFP_KERNEL);
	if (!mr_record)
		return NULL;

	mr_record->dd = dd;
	mr_record->svc = svc;
	/*
	 * Back-pointer only - we do not take an rvt_get_mr() ref.  The
	 * record's lifetime is bound to the rvt_mregion's by rdmavt's
	 * mr_priv_alloc/mr_priv_free contract: alloc fires before any
	 * other code can reach this MR, free fires only after
	 * rvt_check_refs() has drained the percpu_ref.  Taking a ref
	 * here would deadlock rvt_check_refs.
	 */
	mr_record->rvt_mr = rvt_mr;
	mr_record->registered = false;
	RCU_INIT_POINTER(mr_record->cur_pageset, NULL);
	spin_lock_init(&mr_record->destroy_lock);
	mr_record->destroy_pending = false;
	init_completion(&mr_record->destroy_done);
	kref_init(&mr_record->refcount);

	return mr_record;
}

static void bts_verbs_pageset_unmap_work(struct work_struct *work)
{
	struct bts_verbs_pageset *ps =
		container_of(work, struct bts_verbs_pageset, unmap_work);
	struct hfi2_dms_mr * const dms_mr = &ps->dms_mr;

	if (ps->npages_dma_mapped && dms_mr->dma_list) {
		for (u32 i = 0; i < ps->npages_dma_mapped; i++)
			dma_unmap_page(&ps->dd->pcidev->dev, dms_mr->dma_list[i],
				       PAGE_SIZE, DMA_BIDIRECTIONAL);
	}
	if (ps->mem_type == RVT_MEM_DMABUF_DO) {
		/* do_is_nvidia, not the dma_buf: it may already be freed. */
		hfi2_dmabuf_iomem_table_put(ps->dma_buf_do_priv);
	}
	kvfree(dms_mr->dma_list);
	kvfree(ps->vaddrs);
	kfree(ps);
}

/*
 * Page-set kref release.  The last ref may be dropped on the BTS thread
 * (an op completing inline), so it must NOT dma_unmap here; it only
 * queues the sleepable teardown to mr_unmap_wq.
 */
static void bts_verbs_pageset_release(struct kref *refcount)
{
	struct bts_verbs_pageset *ps =
		container_of(refcount, struct bts_verbs_pageset, refcount);

	if (WARN_ON_ONCE(!ps->svc || !ps->svc->mr_unmap_wq)) {
		/* No wq (teardown corner): caller is sleepable, unmap inline. */
		bts_verbs_pageset_unmap_work(&ps->unmap_work);
		return;
	}
	INIT_WORK(&ps->unmap_work, bts_verbs_pageset_unmap_work);
	queue_work(ps->svc->mr_unmap_wq, &ps->unmap_work);
}

void bts_verbs_pageset_get(struct bts_verbs_pageset *ps)
{
	kref_get(&ps->refcount);
}

void bts_verbs_pageset_put(struct bts_verbs_pageset *ps)
{
	if (ps)
		kref_put(&ps->refcount, bts_verbs_pageset_release);
}

static struct bts_verbs_pageset *bts_verbs_pageset_alloc(
	struct hfi2_devdata *dd, struct hfi2_bulksvc *svc)
{
	struct bts_verbs_pageset *ps = kzalloc(sizeof(*ps), GFP_KERNEL);

	if (!ps)
		return NULL;
	ps->dd = dd;
	ps->svc = svc;
	kref_init(&ps->refcount);
	return ps;
}

struct bts_verbs_pageset *
bts_verbs_pageset_create(struct hfi2_bulksvc *svc, struct rvt_mregion *mr)
{
	struct bts_verbs_pageset *ps;
	int ret;

	if (!svc || !mr)
		return ERR_PTR(-EINVAL);
	ps = bts_verbs_pageset_alloc(svc->dd, svc);
	if (!ps)
		return ERR_PTR(-ENOMEM);
	ret = bts_verbs_pageset_pin_and_map(ps, mr);
	if (ret) {
		bts_verbs_pageset_put(ps);
		return ERR_PTR(ret);
	}
	return ps;
}

/*
 * Pin and dma_map rvt_mr->map[] into a fresh page set.  Sleepable
 * (notify_mr_pages_set), not the BTS thread.  Leaves the key/access
 * dms_mr fields to bulksvc_on_verbs_cmd_mr_reg.  On error @ps is left
 * blank (release frees the empty arrays).
 */
static int bts_verbs_pageset_pin_and_map(
	struct bts_verbs_pageset *ps, struct rvt_mregion *rvt_mr)
{
	struct hfi2_devdata * const dd = ps->dd;
	struct hfi2_dms_mr * const dms_mr = &ps->dms_mr;

	if (WARN_ON(ps->vaddrs || dms_mr->dma_list))
		return -EINVAL;

	for (u64 i = 0; i < rvt_mr->mapsz; ++i) {
		if (!rvt_mr->map[i]) {
			pr_err("%s:%d:%s() bulksvc: Invalid map at index %llu\n",
			       __FILENAME__, __LINE__, __func__, i);
			return -EINVAL;
		}
	}

	u64 const user_base = rvt_mr->user_base;
	size_t const length = rvt_mr->length;

	dms_mr->extended_vaddr.addr = user_base & ~(PAGE_SIZE - 1);
	u64 const extension_down = user_base - dms_mr->extended_vaddr.addr;
	u64 const len_extended_down = length + extension_down;
	u64 const len_extended_down_up =
		(len_extended_down + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	dms_mr->extended_vaddr.len = len_extended_down_up;

	dms_mr->user.addr = user_base;
	dms_mr->user.len = length;
	dms_mr->region_offset = user_base & (PAGE_SIZE - 1);

	dms_mr->npages_total = dms_mr->extended_vaddr.len >> PAGE_SHIFT;

	/*
	 * dmabuf memory is already cpu-addressable through the rdmavt vmap
	 * and its dma handles are provided by rdmavt, so we neither
	 * virt_to_page nor dma_map it here.
	 */
	ps->mem_type = rvt_mr->map[0]->segs[0].type;
	if (ps->mem_type == RVT_MEM_DMABUF) {
		ps->dmabuf = rvt_mr->map[0]->segs[0].seg_dmabuf.dmabuf;
	} else if (ps->mem_type == RVT_MEM_DMABUF_DO) {
		ps->dma_buf_do_priv = rvt_mr->map[0]->segs[0].seg_dmabuf_do.priv;
		ps->dmabuf = rvt_mr->map[0]->segs[0].seg_dmabuf_do.dmabuf;
		{
			hfi2_dmabuf_iomem_table_get(ps->dma_buf_do_priv);
		}
	}

	/* vaddrs[]/dma_list[] live on dd->node (the BTS poll path). */
	ps->vaddrs = kvcalloc_node(dms_mr->npages_total,
				   sizeof(void *), GFP_KERNEL,
				   dd->node);
	if (!ps->vaddrs) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate mr vaddrs array\n",
		       __FILENAME__, __LINE__, __func__);
		return -ENOMEM;
	}

	for (u32 i = 0; i < dms_mr->npages_total; i++) {
		u32 const m = i / RVT_SEGSZ;
		u32 const s = i % RVT_SEGSZ;

		if (WARN_ON((m * RVT_SEGSZ) + s >= rvt_mr->max_segs))
			goto bail_vaddrs;

		if (rvt_mr->map[m]->segs[s].length != PAGE_SIZE) {
			pr_err("%s:%d:%s() bulksvc: Unexpected segment length %zu at map %u seg %u\n",
				__FILENAME__, __LINE__, __func__,
				rvt_mr->map[m]->segs[s].length, m, s);
			goto bail_vaddrs;
		}

		ps->vaddrs[i] = rvt_mr->map[m]->segs[s].vaddr;
	}

	dms_mr->dma_list = kvcalloc_node(dms_mr->npages_total,
					 sizeof(dma_addr_t), GFP_KERNEL,
					 dd->node);
	if (!dms_mr->dma_list) {
		pr_err("%s:%d:%s() bulksvc: Failed to allocate dma list\n",
		       __FILENAME__, __LINE__, __func__);
		goto bail_vaddrs;
	}

	for (u32 i = 0; i < dms_mr->npages_total; i++) {
		struct page *page;

		u32 const m = i / RVT_SEGSZ;
		u32 const s = i % RVT_SEGSZ;

		/*
		 * npages_dma_mapped counts only pages this driver DMA-maps
		 * (RVT_MEM_KERNEL). dmabuf handles are owned by rdmavt and are
		 * never counted here, so teardown does not dma_unmap them.
		 */
		switch (ps->mem_type) {
		case RVT_MEM_DMABUF:
			/* rdmavt already provides dma handles for dmabuf. */
			dms_mr->dma_list[i] =
				rvt_mr->map[m]->segs[s].seg_dmabuf.dma_addr;
			break;
		case RVT_MEM_DMABUF_DO:
			dms_mr->dma_list[i] =
				rvt_mr->map[m]->segs[s].seg_dmabuf_do.dma_addr;
			break;
		case RVT_MEM_KERNEL:
		default:
			page = virt_to_page(ps->vaddrs[i]);
			if (WARN_ON(!page)) {
				pr_err("%s:%d:%s() bulksvc: Failed to get page for addr %p\n",
				       __FILENAME__, __LINE__, __func__,
				       ps->vaddrs[i]);
				goto bail_dma;
			}

			dms_mr->dma_list[i] = dma_map_page(&dd->pcidev->dev,
				page, 0, PAGE_SIZE,
				DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(&dd->pcidev->dev,
						       dms_mr->dma_list[i]))) {
				pr_err("%s:%d:%s() bulksvc: Failed to map page %u for addr %lx\n",
				       __FILENAME__, __LINE__, __func__, i,
				       dms_mr->extended_vaddr.addr +
						((unsigned long)i << PAGE_SHIFT));
				goto bail_dma;
			}
			ps->npages_dma_mapped = i + 1;
			break;
		}
	}

	return 0;

bail_dma:
	for (u32 j = 0; j < ps->npages_dma_mapped; j++)
		dma_unmap_page(&dd->pcidev->dev, dms_mr->dma_list[j],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
	ps->npages_dma_mapped = 0;
	kvfree(dms_mr->dma_list);
	dms_mr->dma_list = NULL;
bail_vaddrs:
	kvfree(ps->vaddrs);
	ps->vaddrs = NULL;
	return -ENOMEM;
}

/*
 * Single-shot destroy barrier used only by mr_priv_free's FastReg-
 * without-LOCAL_INV path: arm, drive the dereg, wait.  arm/wait run on
 * mr_priv_free's thread, signal on the BTS thread; destroy_lock makes the
 * {arm, signal} pair race-free so a signal before the wait isn't lost.
 */
static void bts_verbs_mr_destroy_barrier_arm(struct bts_verbs_mr_record *rec)
{
	unsigned long flags;

	spin_lock_irqsave(&rec->destroy_lock, flags);
	reinit_completion(&rec->destroy_done);
	rec->destroy_pending = true;
	spin_unlock_irqrestore(&rec->destroy_lock, flags);
}

/*
 * Wait for the dereg signal, but bounded.  The signal can be missed only on
 * teardown corner cases; without a bound the destroying task would block in
 * D-state forever.  On timeout, warn and proceed -- the caller then drops its
 * refs inline, which is safe at teardown.
 */
#define BTS_VERBS_MR_DESTROY_TIMEOUT	(10 * HZ)
static void bts_verbs_mr_destroy_barrier_wait(struct bts_verbs_mr_record *rec)
{
	if (!wait_for_completion_timeout(&rec->destroy_done,
					 BTS_VERBS_MR_DESTROY_TIMEOUT))
		WARN_ONCE(1, "bts: MR destroy barrier timed out; dereg signal missed\n");
}

/* Signal the barrier iff armed; consumes the arm exactly once. */
static void bts_verbs_mr_destroy_barrier_signal(struct bts_verbs_mr_record *rec)
{
	unsigned long flags;
	bool signal;

	if (!rec)
		return;
	spin_lock_irqsave(&rec->destroy_lock, flags);
	signal = rec->destroy_pending;
	rec->destroy_pending = false;
	spin_unlock_irqrestore(&rec->destroy_lock, flags);
	if (signal)
		complete(&rec->destroy_done);
}

void bts_verbs_mr_record_get(struct bts_verbs_mr_record * const mr_record)
{
	kref_get(&mr_record->refcount);
}

static void bts_verbs_mr_record_destroy(struct kref *refcount)
{
	struct bts_verbs_mr_record * const mr_record =
		container_of(refcount, struct bts_verbs_mr_record, refcount);
	struct bts_verbs_pageset *ps =
		rcu_dereference_protected(mr_record->cur_pageset, 1);

	/* The record's current page set (if any) should already have had
	 * its reg-time ref dropped by mr_priv_free; the WARN is a safety net.
	 */
	if (WARN_ON_ONCE(ps))
		bts_verbs_pageset_put(ps);

	kfree_rcu(mr_record, rcu);
}

void bts_verbs_mr_record_put(struct bts_verbs_mr_record * const mr_record)
{
	kref_put(&mr_record->refcount, bts_verbs_mr_record_destroy);
}

/*
 * Per post_send lookup: RCU hash lookup instead of a mutex + list walk.
 * Returns the QP with a reference held, or NULL.
 */
static struct rvt_qp *qp_from_number(struct hfi2_bulksvc *svc, u64 app_context)
{
	struct hfi2_devdata *dd = svc->dd;
	struct hfi2_bulksvc_qp_info *qp_info;
	struct rvt_qp *qp;

	if (app_context <= 1 || app_context > U32_MAX)
		return NULL;

	rcu_read_lock();
	qp = rvt_lookup_qpn(&dd->verbs_dev.rdi, &dd->pport->ibport_data.rvp,
			    app_context);
	if (qp) {
		qp_info = bulksvc_qp_info_of(qp);
		if (qp_info && qp_info->owner == qp)
			rvt_get_qp(qp);
		else
			qp = NULL;
	}
	rcu_read_unlock();
	return qp;
}

static void bts_send_cq_locked(struct rvt_qp *qp, u64 wr_id, u32 byte_len,
			       enum ib_wr_opcode wr_opcode, int wr_send_flags,
			       enum ib_wc_status status)
{
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct ib_wc w = {
		.wr_id = wr_id,
		.status = status,
		.opcode = rdi->wc_opcode[wr_opcode],
		.qp = &qp->ibqp,
		.byte_len = byte_len
	};

	lockdep_assert_held(&qp->s_lock);

	/* taken from rvt_qp_complete_swqe */
	if (!(qp->s_flags & RVT_S_SIGNAL_REQ_WR) ||
	    (wr_send_flags & IB_SEND_SIGNALED) ||
	    status != IB_WC_SUCCESS)
		rvt_send_cq(qp, &w, true, RVT_QP_LOCK_STATE_S);
}

static void bts_send_cq(struct rvt_qp *qp, u64 wr_id, u32 byte_len,
			enum ib_wr_opcode wr_opcode, int wr_send_flags,
			enum ib_wc_status status)
{
	unsigned long lflags;

	spin_lock_irqsave(&qp->s_lock, lflags);
	bts_send_cq_locked(qp, wr_id, byte_len, wr_opcode, wr_send_flags,
			   status);
	spin_unlock_irqrestore(&qp->s_lock, lflags);
}

/*
 * SEND offload is safe only if the remote peer is a userspace PD; a kernel PD
 * may land the SEND in an lkey-0 recv buffer DMS cannot resolve.
 * Pre-flag or no-DMS peers are treated as unsafe (default-safe for interop).
 */
bool hfi2_bts_send_offload_ok(struct rvt_qp *qp)
{
	struct hfi2_qp_priv *qpriv = qp->priv;
	struct hfi2_dms_opfn_params *remote;
	bool ok;

	rcu_read_lock();
	remote = rcu_dereference(qpriv->dms.remote);
	ok = remote &&
	     remote->version >= DMS_OPFN_VER_PD_FLAG &&
	     !(remote->flags & DMS_OPFN_VER_PD_UNSAFE);
	rcu_read_unlock();

	return ok;
}

/*
 * Mirror the kernel-verbs admit gate (bulksvc_negotiation_check): a WQE may
 * use the DMS hotpath only when DMS OPFN negotiation completed AND the peer
 * positively advertised DMS (dms.remote != NULL). A completed negotiation does
 * not by itself imply dms.remote is set -- an OPFN-capable peer that declines
 * DMS replies with an empty payload, which sets the completed bit but leaves
 * dms.remote NULL. Gate on both so the uverbs and kernel-verbs paths agree.
 */
static bool bts_dms_negotiated(struct rvt_qp *qp)
{
	struct hfi2_qp_priv *qpriv;

	if (bulksvc_qp_is_roce(qp))
		return false;

	qpriv = qp->priv;
	if (!hfi2_opfn_dms_negotiated(qp))
		return false;

	return !!rcu_access_pointer(qpriv->dms.remote);
}

/*
 * TODO - this function must check if the wqe can be passed to DMS
 * and put on the wire now. Things to keep in mind:
 * 1. is the wqe bts-able - see hfi2_setup_bulksvc_wqe
 * 2. is anything else going through rdmavt? must respect
 *    verbs ordering
 */
static bool can_bts_hotpath(struct rvt_qp *qp, struct ib_send_wr *wr)
{
	bool const is_send = (wr->opcode == IB_WR_SEND ||
			      wr->opcode == IB_WR_SEND_WITH_IMM);
	struct hfi2_qp_priv *qpriv = qp->priv;

	if (wr->opcode != IB_WR_RDMA_READ &&
	    wr->opcode != IB_WR_RDMA_WRITE &&
	    wr->opcode != IB_WR_RDMA_WRITE_WITH_IMM &&
	    !is_send)
		return false;
	/* SEND offload is gated; when off, SEND stays standard RC. */
	if (is_send && !READ_ONCE(bulksvc_verbs_send_rcv))
		return false;
	if (!bts_dms_negotiated(qp))
		return false;
	if (is_send && !hfi2_bts_send_offload_ok(qp))
		return false;
	/*
	 * An RDMA op targeting the peer's reserved DMA MR (rkey 0) cannot be
	 * resolved by DMS on the responder; keep it on standard RC.
	 */
	if (!is_send && rdma_wr(wr)->rkey == 0)
		return false;
	/*
	 * TODO: DMS should be able to handle ordering this completion.
	 * for now only rdmavt can do this. This will make hotpath block
	 * until rdmavt is done, hurting perf.
	 */
	if (wr->num_sge == 0 || wr->sg_list[0].length == 0)
		return false;
	/* IB packets only */
	if (qpriv->hdr_type != HFI2_PKT_TYPE_9B)
		return false;
	/* no loopbacks */
	if (ppd_same_lid(qpriv->rcd->ppd,
			 rdma_ah_get_dlid(&qp->remote_ah_attr)))
		return false;

	return true;
}

static void bulksvc_direct_cmd_rdma_complete(
	union hfi2_dms_completion_cookie * const cookie, int status)
{
	struct direct_rdma_cmpl_cookie * const d_rdma_cookie =
		(struct direct_rdma_cmpl_cookie *)cookie;
	struct direct_rdma_sge_info *sge_info = d_rdma_cookie->sge_info;
	struct hfi2_bulksvc_qp_info *qp_info =
		bulksvc_qp_info_of(sge_info->qp);
	bool const is_read = (sge_info->wr_opcode == IB_WR_RDMA_READ);

	enum verbs_gbn_action gbn_act =
		verbs_gbn_classify(qp_info, sge_info->ord_wr.ring_slot,
				   sge_info->ord_wr.seq, status,
				   sge_info->is_send);

	/* Only the final segment owns the ordering slot; a hold is valid only then. */
	if (gbn_act == GBN_ACTION_HOLD && sge_info->remaining_wr_sges != 1)
		gbn_act = GBN_ACTION_NONE;

	if (gbn_act != GBN_ACTION_NONE) {
		verbs_gbn_capture(qp_info,
				  sge_info->ord_wr.ring_slot,
				  &d_rdma_cookie->pageset,
				  &d_rdma_cookie->multiseg, NULL, sge_info,
				  d_rdma_cookie->rbuf_start_offset,
				  d_rdma_cookie->order_key, is_read,
				  sge_info->is_send,
				  gbn_act == GBN_ACTION_HOLD);
		return;
	}

	if (d_rdma_cookie->multiseg) {
		u32 seg;

		for (seg = 0; seg < d_rdma_cookie->multiseg->nsegs; seg++)
			bts_verbs_pageset_put(d_rdma_cookie->multiseg->segs[seg].pageset);
		kfree(d_rdma_cookie->multiseg);
	} else {
		bts_verbs_pageset_put(d_rdma_cookie->pageset);
	}

	if (sge_info->status == IB_WC_SUCCESS && status != 0)
		sge_info->status = dms_status_to_wc_status(status);

	if (status && status != -ECANCELED && !qp_info->inflight_cancel_walk)
		verbs_inflight_cancel_others(qp_info, sge_info->ord->dms,
					     sge_info->ord_wr.ring_slot);

	sge_info->remaining_wr_sges--;
	if (sge_info->remaining_wr_sges > 0)
		return;

	verbs_inflight_remove(qp_info, sge_info->ord_wr.ring_slot);
	ordering_retire(sge_info->ord, &sge_info->ord_wr, sge_info->ord->svc);
	verbs_deferred_retry(qp_info);
}


/* more or less a re-use of bulksvc_on_qp_cmd_rdma_helper
 * but suited towards working with struct ib_send_wr and
 * different completion handler
 * TODO unify some dup code here
 */
static int bulksvc_verbs_hotpath_send_one(struct hfi2_bulksvc *svc,
				   struct rvt_qp *qp,
				   struct ib_send_wr *wr)
{
	struct ib_rdma_wr *rdma_wr = container_of(wr, struct ib_rdma_wr, wr);
	u16 const remote_lid = qp->remote_ah_attr.opa.dlid;
	bool const is_send = (wr->opcode == IB_WR_SEND ||
			      wr->opcode == IB_WR_SEND_WITH_IMM);

	struct direct_rdma_sge_info *sge_info = NULL;
	struct verbs_hotpath_rctx rctx = {};
	int err_rc = 0;

	if (WARN_ON(!qp->ibqp.pd)) {
		pr_err("%s:%d:%s() invalid qp->ibqp.pd\n",
		       __FILENAME__, __LINE__, __func__);
		err_rc = -EINVAL;
		goto on_err;
	}

	if (WARN_ON(!wr->sg_list) || WARN_ON(!wr->num_sge)) {
		pr_err("%s:%d:%s() invalid wr->sg_list, num_sge %u\n",
		       __FILENAME__, __LINE__, __func__, wr->num_sge);
		err_rc = -EINVAL;
		goto on_err;
	}

	/* SEND has no remote rkey/addr (those bytes alias ex.imm_data); carry
	 * destination QPN in dms_key.access so the target takes the SEND-flag
	 * landing branch without imm_data[55:32] routing.
	 */
	u32 const remote_client_id = VERBS_PD_TO_CLIENT_ID(qp->ibqp.pd->res.id);
	u64 const hp_remote_addr = is_send ? 0 : rdma_wr->remote_addr;
	union hfi2_dms_key const dms_key = is_send ?
		(union hfi2_dms_key){
			.access = qp->remote_qpn,
			.client = 0,
		} :
		(union hfi2_dms_key){
			.access = rdma_wr->rkey,
			.client = remote_client_id,
		};

	u32 const num_sge = wr->num_sge;
	if (WARN_ON(num_sge >= 256)) {
		pr_err("%s:%d:%s() num_sge %u is too large, max 255 supported\n",
		       __FILENAME__, __LINE__, __func__, num_sge);
		err_rc = -EINVAL;
		goto on_err;
	}

	{
		struct hfi2_bulksvc_qp_info *hz_qpi =
			bulksvc_qp_info_of(qp);

		/*
		 * Strict FIFO + ring-full back-pressure.  When the inflight
		 * ring is full we defer (rather than fail) so the deferred-
		 * retry path drains it later; matches the rdmavt admit site.
		 */
		if ((!hz_qpi->retry_in_progress &&
		     !list_empty(&hz_qpi->deferred_wrs)) ||
		    hz_qpi->gbn_window_active ||
		    verbs_inflight_full(hz_qpi)) {
			struct verbs_deferred_wr *def;

			if (verbs_inflight_full(hz_qpi)) {
				atomic64_inc(&hz_qpi->inflight_full_deferrals);
				atomic64_inc(&hz_qpi->verbs_state->ring_full_deferrals);
			}

			/* BTS thread: GFP_NOWAIT - do not enter reclaim. */
			def = kzalloc_node(struct_size(def, hotpath.sges, num_sge),
					   GFP_NOWAIT | __GFP_NOWARN,
					   svc->dd->node);
			if (!def) {
				err_rc = -ENOMEM;
				goto on_err;
			}
			INIT_LIST_HEAD(&def->list);
			def->path = DEFERRED_PATH_HOTPATH;
			def->hotpath.svc = svc;
			/*
			 * Do NOT rvt_get_qp here — the caller
			 * (bulksvc_on_cmd_uverbs_post_send) already holds a
			 * ref that we inherit. The deferred_free path will
			 * release it.
			 */
			def->hotpath.qp = qp;
			def->hotpath.wr_id = wr->wr_id;
			def->hotpath.opcode = wr->opcode;
			def->hotpath.send_flags = wr->send_flags;
			def->hotpath.imm_data = wr->ex.imm_data;
			def->hotpath.remote_addr = rdma_wr->remote_addr;
			def->hotpath.rkey = rdma_wr->rkey;
			def->hotpath.num_sge = num_sge;
			memcpy(def->hotpath.sges, wr->sg_list,
			       num_sge * sizeof(struct ib_sge));
			list_add_tail(&def->list, &hz_qpi->deferred_wrs);
			/* -EAGAIN: WR parked on deferred_wrs (not submitted).
			 * Caller must undo its admit-side counter bumps and
			 * NOT put the qp ref (inherited by the snapshot). */
			return -EAGAIN;
		}
	}

	/* BTS thread: GFP_NOWAIT - do not enter reclaim. */
	sge_info = kmem_cache_zalloc(svc->verbs_sge_cache,
				     GFP_NOWAIT | __GFP_NOWARN);
	if (!sge_info) {
		pr_err_ratelimited("%s:%d:%s() failed to allocate sge_info\n",
				   __FILENAME__, __LINE__, __func__);
		err_rc = -ENOMEM;
		goto on_err;
	}

	{
		struct hfi2_bulksvc_qp_info *hp_qp_info =
			bulksvc_qp_info_of(qp);

		INIT_LIST_HEAD(&sge_info->ord_wr.node);
		sge_info->ord_wr.seq = hp_qp_info->ordering.next_issue_seq++;
		sge_info->ord_wr.type = ORDERED_WR_HOTPATH;
		/* No ring slot until verbs_inflight_add stamps one. */
		sge_info->ord_wr.ring_slot = VERBS_INFLIGHT_NO_SLOT;
		sge_info->ord = &hp_qp_info->ordering;
		sge_info->qp = qp;
		sge_info->wr_id = wr->wr_id;
		sge_info->wr_opcode = wr->opcode;
		sge_info->wr_send_flags = wr->send_flags;
		/*
		 * GBN replay capture source: mirror the bts_submit_req inputs
		 * so a cancelled hotpath WR can be re-packed and re-issued
		 * verbatim without re-walking the (now consumed) ib_send_wr.
		 * hp_is_imm_seq derives is_imm; remote_addr is is_send-masked.
		 */
		sge_info->remote_addr = hp_remote_addr;
		sge_info->dms_key = dms_key;
		sge_info->remote_lid = remote_lid;
		sge_info->num_sge = num_sge;
		sge_info->remote_qpn = qp->remote_qpn;
		sge_info->is_send = is_send;
		sge_info->is_imm =
			(wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
			 wr->opcode == IB_WR_SEND_WITH_IMM);
		sge_info->solicited = !!(wr->send_flags & IB_SEND_SOLICITED);
		sge_info->user_imm_be = wr->ex.imm_data;
	}

	u32 const rdma_opcode = wr->opcode;
	u64 remote_addr = hp_remote_addr;

	struct hfi2_bulksvc_qp_info *ok_qpi =
		bulksvc_qp_info_of(qp);
	bool const hp_is_imm_seq =
		(rdma_opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
		 rdma_opcode == IB_WR_SEND_WITH_IMM);

	/*
	 * Sum the SGE lengths in 64-bit and reject a WQE whose total exceeds
	 * U32_MAX before it truncates into the u32 transfer size.
	 */
	u64 total_wqe_len = 0;

	for (u32 sge_idx = 0; sge_idx < num_sge; ++sge_idx)
		total_wqe_len += wr->sg_list[sge_idx].length;

	if (unlikely(total_wqe_len > U32_MAX)) {
		pr_err("%s:%d:%s() total WQE length %llu exceeds U32_MAX; SGE-length sum overflows 32-bit transfer size\n",
		       __FILENAME__, __LINE__, __func__, total_wqe_len);
		err_rc = -EINVAL;
		goto on_err;
	}
	sge_info->byte_len = (u32)total_wqe_len;

	if (unlikely(verbs_inflight_add(ok_qpi, &sge_info->ord_wr, num_sge))) {
		err_rc = -ENOMEM;
		goto on_err;
	}

	struct rvt_dev_info * const rdi = ib_to_rvt(qp->ibqp.device);
	struct verbs_inflight_wr *hp_inf =
		&ok_qpi->inflight_ring[sge_info->ord_wr.ring_slot];
	bool const hp_is_read = (rdma_opcode == IB_WR_RDMA_READ);

	/*
	 * find_mr_record returns a held ref (UAF protection); the resolver
	 * caches it across SGEs sharing an lkey in rctx.cached_mr, and we drop
	 * it exactly once after the helper returns (success or error).
	 */
	rctx = (struct verbs_hotpath_rctx){
		.svc = svc,
		.lane = ok_qpi->lane,
		.rdi = rdi,
		.pd = qp->ibqp.pd,
		.sg_list = wr->sg_list,
		.cached_mr = NULL,
	};

	{
		struct hfi2_dms_completion completion = {
			.fn = bulksvc_direct_cmd_rdma_complete,
			.cookie = {},
		};
		struct direct_rdma_cmpl_cookie *cookie =
			(struct direct_rdma_cmpl_cookie *) &completion.cookie;
		struct bts_submit_req req;
		int rc;

		cookie->sge_info = sge_info;
		cookie->pageset = NULL;
		cookie->multiseg = NULL;

		req = (struct bts_submit_req){
			.svc = svc,
			.ord = sge_info->ord,
			.qp_info = ok_qpi,
			.inf = hp_inf,
			.remote_lid = remote_lid,
			.dms_key = dms_key,
			.remote_addr = remote_addr,
			.size = sge_info->byte_len,
			.num_sge = num_sge,
			.gfp = GFP_NOWAIT | __GFP_NOWARN,
			.is_read = hp_is_read,
			.is_send = is_send,
			.is_imm = hp_is_imm_seq,
			.solicited = !!(wr->send_flags & IB_SEND_SOLICITED),
			.remote_qpn = qp->remote_qpn,
			.user_imm_be = wr->ex.imm_data,
			.resolve = verbs_hotpath_resolve_seg,
			.rctx = &rctx,
			.completion = &completion,
			.cookie_pageset = &cookie->pageset,
			.cookie_multiseg = &cookie->multiseg,
			.cookie_rbuf_start_offset = &cookie->rbuf_start_offset,
			.cookie_order_key = &cookie->order_key,
		};

		rc = bts_verbs_submit_one(&req);
		if (unlikely(rc < 0)) {
			err_rc = rc;
			goto on_err;
		}

		sge_info->remaining_wr_sges = 1;
		if (rctx.cached_mr)
			bts_verbs_mr_record_put(rctx.cached_mr);
		return err_rc;
	}

on_err:
	if (rctx.cached_mr)
		bts_verbs_mr_record_put(rctx.cached_mr);
	if (sge_info) {
		struct hfi2_bulksvc_qp_info *err_qpi =
			bulksvc_qp_info_of(qp);

		verbs_inflight_remove(err_qpi, sge_info->ord_wr.ring_slot);
		err_qpi->ordering.next_issue_seq--;
		kmem_cache_free(svc->verbs_sge_cache, sge_info);
	}
	return err_rc;
}

static void verbs_deferred_free(struct verbs_deferred_wr *def)
{
	if (def->path == DEFERRED_PATH_RDMAVT)
		hfi2_bulksvc_verbs_cmd_put(def->rdmavt.cmd);
	else if (def->path == DEFERRED_PATH_HOTPATH)
		rvt_put_qp(def->hotpath.qp);
	kfree(def);
}

static bool verbs_qp_is_send_capable(struct hfi2_bulksvc_qp_info *qp_info)
{
	if (!qp_info->owner)
		return false;
	return READ_ONCE(qp_info->owner->state) == IB_QPS_RTS;
}

static void verbs_deferred_flush_rdmavt(struct hfi2_bulksvc_qp_info *qp_info,
					struct verbs_deferred_wr *def)
{
	struct hfi2_bulksvc_verbs_cmd *cmd = def->rdmavt.cmd;
	struct hfi2_bulksvc *svc = def->rdmavt.svc;
	struct hfi2_bulksvc_verbs_ordering *ord = &qp_info->ordering;

	/*
	 * Deferred rdmavt WRs were deferred before the normal post path
	 * assigns cmd->ord_wr.seq.  Assign the ordering sequence here so
	 * the flush retires this WR with a valid, unique sequence.
	 */
	cmd->ord_wr.seq = ord->next_issue_seq++;
	cmd->rdma.txreq->bts_rc = IB_WC_WR_FLUSH_ERR;
	verbs_ordering_retire_wr(ord, cmd, svc);

	/*
	 * Drop the original caller ref that was never put because
	 * deferral returned before reaching the done: label in
	 * bulksvc_on_qp_cmd_rdma_helper().  The deferral-owned ref
	 * is released by verbs_deferred_free() after we return.
	 */
	hfi2_bulksvc_verbs_cmd_put(cmd);
}

/*
 * Flush a deferred hotpath WR during QP error/teardown.
 *
 * Safe to advance next_deliver_seq directly because error/teardown flushes
 * all deferred WRs in strict FIFO order after all in-flight transfers
 * have completed (QP is no longer RTS, ordering.pending is empty).
 * Must NOT be called while earlier issued ops remain undelivered.
 */
static void verbs_deferred_flush_hotpath(struct hfi2_bulksvc_qp_info *qp_info,
					 struct verbs_deferred_wr *def)
{
	enum ib_wc_status status = def->hotpath.flush_status ?
		def->hotpath.flush_status : IB_WC_WR_FLUSH_ERR;
	u64 seq = qp_info->ordering.next_issue_seq++;
	u32 byte_len = 0;
	u32 s;

	if (status != IB_WC_WR_FLUSH_ERR) {
		for (s = 0; s < def->hotpath.num_sge; s++)
			byte_len += def->hotpath.sges[s].length;
	}

	bts_send_cq(def->hotpath.qp, def->hotpath.wr_id, byte_len,
		    def->hotpath.opcode, def->hotpath.send_flags,
		    status);
	qp_info->ordering.next_deliver_seq = seq + 1;
}

/*
 * Flush all deferred WRs on @qp_info in FIFO order once all previously
 * issued BTS transfers have delivered.  If in-flight BTS ops are still
 * outstanding (next_deliver_seq < next_issue_seq), leave deferred_wrs
 * intact for the final in-flight completion's verbs_deferred_retry()
 * call to drain in posted order.
 */
static void verbs_deferred_flush_all(struct hfi2_bulksvc_qp_info *qp_info)
{
	if (qp_info->ordering.next_deliver_seq <
	    qp_info->ordering.next_issue_seq)
		return;

	while (!list_empty(&qp_info->deferred_wrs)) {
		struct verbs_deferred_wr *head =
			list_first_entry(&qp_info->deferred_wrs,
					 struct verbs_deferred_wr, list);

		list_del(&head->list);
		if (head->path == DEFERRED_PATH_RDMAVT)
			verbs_deferred_flush_rdmavt(qp_info, head);
		else
			verbs_deferred_flush_hotpath(qp_info, head);
		verbs_deferred_free(head);
	}
}

/*
 * Re-submit deferred WRs whose hazards have cleared.
 *
 * Called after removing a blocker from inflight_wrs. Strict FIFO: only
 * the head of the deferred list is checked; if still blocked we stop.
 *
 * For rdmavt retries we re-enter bulksvc_on_qp_cmd_rdma_helper() which
 * re-checks the deferred list. The per-qp retry_in_progress flag prevents
 * livelock by telling the helper to skip the deferred-non-empty check.
 */
static void verbs_deferred_retry(struct hfi2_bulksvc_qp_info *qp_info)
{
	if (qp_info->inflight_cancel_walk)
		return;
	/*
	 * All work is deferred during an active GBN window, requiring
	 * any function calls to reset the gate_retry_pending flag. */
	if (qp_info->gbn_window_active) {
		if (!list_empty(&qp_info->deferred_wrs) &&
		    !qp_info->gate_retry_pending) {
			qp_info->gate_retry_pending = true;
			atomic_inc(&qp_info->verbs_state->gate_retry_pending_count[qp_info->lane]);
		}
		return;
	}

	while (!list_empty(&qp_info->deferred_wrs)) {
		struct verbs_deferred_wr *head;

		if (unlikely(!verbs_qp_is_send_capable(qp_info))) {
			if (!(ib_rvt_state_ops[READ_ONCE(qp_info->owner->state)] &
			      RVT_PROCESS_SEND_OK))
				verbs_deferred_flush_all(qp_info);
			break;
		}

		head = list_first_entry(&qp_info->deferred_wrs,
					struct verbs_deferred_wr, list);
		list_del(&head->list);

		/* Unified hotpath retry.  Reconstruct a stack ib_send_wr,
		 * re-run the bts-side admit gate, dispatch to bts hotpath
		 * (bts-able opcode) or rvt_post_send (everything else).
		 * Strict FIFO: if the head blocks, reinstate and stop. */
		if (head->path == DEFERRED_PATH_RDMAVT) {
			u32 r_op =
				head->rdmavt.cmd->rdma.txreq->wqe->wr.opcode;
			bool is_send = (r_op == IB_WR_BULKSVC_SEND ||
					r_op == IB_WR_BULKSVC_SEND_WITH_IMM);

			if (verbs_inflight_full(qp_info)) {
				list_add(&head->list, &qp_info->deferred_wrs);
				break;
			}

			qp_info->retry_in_progress = true;
			if (is_send)
				bulksvc_on_qp_cmd_send(head->rdmavt.svc,
						       head->rdmavt.cmd);
			else
				bulksvc_on_qp_cmd_rdma_helper(head->rdmavt.svc,
							      head->rdmavt.cmd);
			qp_info->retry_in_progress = false;
			verbs_deferred_free(head);
			continue;
		}

		{
			struct rvt_qp *hp_qp = head->hotpath.qp;
			struct hfi2_bulksvc_qp_info *hp_qi =
				bulksvc_qp_info_of(hp_qp);
			struct ib_rdma_wr rdma_wr = {};
			struct ib_atomic_wr atomic_wr = {};
			struct ib_send_wr swr = {
				.next = NULL,
				.wr_id = head->hotpath.wr_id,
				.sg_list = head->hotpath.sges,
				.num_sge = head->hotpath.num_sge,
				.opcode = head->hotpath.opcode,
				.send_flags = head->hotpath.send_flags,
				.ex.imm_data = head->hotpath.imm_data,
			};
			struct ib_send_wr *wr;
			bool bts_able;
			unsigned long hp_flags;
			bool gate_ok = false;
			bool qp_bad_state = false;

			switch (head->hotpath.opcode) {
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
			case IB_WR_RDMA_READ:
				rdma_wr.wr = swr;
				rdma_wr.remote_addr = head->hotpath.remote_addr;
				rdma_wr.rkey = head->hotpath.rkey;
				wr = &rdma_wr.wr;
				break;
			case IB_WR_ATOMIC_CMP_AND_SWP:
			case IB_WR_ATOMIC_FETCH_AND_ADD:
				atomic_wr.wr = swr;
				atomic_wr.remote_addr = head->hotpath.remote_addr;
				atomic_wr.rkey = head->hotpath.rkey;
				atomic_wr.compare_add = head->hotpath.compare_add;
				atomic_wr.swap = head->hotpath.swap;
				wr = &atomic_wr.wr;
				break;
			default:
				wr = &swr;
				break;
			}

			bts_able = can_bts_hotpath(hp_qp, wr);

			if (bts_able && verbs_inflight_full(hp_qi)) {
				list_add(&head->list, &qp_info->deferred_wrs);
				break;
			}

			/* Mirror of the admit-site cross-traffic gate in
			 * bulksvc_on_cmd_uverbs_post_send. */
			spin_lock_irqsave(&hp_qp->s_lock, hp_flags);
			if (unlikely(!(ib_rvt_state_ops[hp_qp->state] &
				       RVT_PROCESS_SEND_OK) ||
				     (bts_able &&
				      hp_qp->state != IB_QPS_RTS))) {
				qp_bad_state = true;
			} else if (bts_able) {
				bool sq_drained =
					READ_ONCE(hp_qp->s_head) == hp_qp->s_last;

				gate_ok = !bulksvc_path_gate || sq_drained;
				if (gate_ok) {
					hp_qi->bts_path_inflight_bts += 1;
					hp_qi->n_dispatched_unacked++;
					hp_qi->last_dispatched_class =
						OPCLASS_BTS;
				}
			} else {
				gate_ok = !bulksvc_path_gate ||
					hp_qi->bts_path_inflight_bts == 0;
			}
			if (!qp_bad_state && !gate_ok &&
			    !qp_info->gate_retry_pending) {
				struct hfi2_bulksvc_verbs_state *vs =
					qp_info->verbs_state;

				qp_info->gate_retry_pending = true;
				atomic_inc(&vs->gate_retry_pending_count[qp_info->lane]);
			}
			spin_unlock_irqrestore(&hp_qp->s_lock, hp_flags);

			if (unlikely(qp_bad_state)) {
				list_add(&head->list, &qp_info->deferred_wrs);
				if (!(ib_rvt_state_ops[READ_ONCE(hp_qp->state)] &
				      RVT_PROCESS_SEND_OK))
					verbs_deferred_flush_all(qp_info);
				break;
			}

			if (!gate_ok) {
				list_add(&head->list, &qp_info->deferred_wrs);
				hfi2_bulksvc_schedule_lane(head->hotpath.svc,
							   qp_info->lane);
				break;
			}

			if (bts_able) {
				int hp_ret;

				rvt_get_qp(hp_qp);
				hp_qi->retry_in_progress = true;
				hp_ret = bulksvc_verbs_hotpath_send_one(
					head->hotpath.svc, hp_qp, wr);
				hp_qi->retry_in_progress = false;
				if (hp_ret) {
					spin_lock_irqsave(&hp_qp->s_lock, hp_flags);
					if (!WARN_ON_ONCE(hp_qi->bts_path_inflight_bts == 0))
						hp_qi->bts_path_inflight_bts -= 1;
					if (WARN_ON_ONCE(hp_qi->n_dispatched_unacked == 0)) {
						/* skip dec */
					} else if (--hp_qi->n_dispatched_unacked == 0) {
						hp_qi->last_dispatched_class =
							OPCLASS_NONE;
						bulksvc_release_bts_gate(hp_qp);
					}
					spin_unlock_irqrestore(&hp_qp->s_lock, hp_flags);
					/* -EAGAIN: snapshot inherited our qp ref. */
					if (hp_ret != -EAGAIN) {
						struct hfi2_devdata *dd =
							head->hotpath.svc->dd;

						rvt_put_qp(hp_qp);
						dd_dev_err_ratelimited(dd,
								       "bts: hotpath send (deferred replay) rc %d\n",
								       hp_ret);
						head->hotpath.flush_status =
							IB_WC_GENERAL_ERR;
						list_add(&head->list,
							 &qp_info->deferred_wrs);
						verbs_error_qp(hp_qp,
							       IB_WC_WR_FLUSH_ERR);
						verbs_deferred_flush_all(qp_info);
						break;
					}
				}
			} else {
				/* Non-bts-able replay: rdmavt side owns its own
				 * counter accounting via make_rc_req. */
				const struct ib_send_wr *bad_wr = NULL;
				int rv;

				wr->send_flags |= HFI2_SEND_NO_BULKSVC;
				rv = rvt_post_send(&hp_qp->ibqp, wr, &bad_wr);

				if (rv) {
					enum ib_qp_state cur_state =
						READ_ONCE(hp_qp->state);
					enum ib_wc_status wc_st =
						(ib_rvt_state_ops[cur_state] &
						 RVT_FLUSH_SEND) ?
						IB_WC_WR_FLUSH_ERR :
						IB_WC_GENERAL_ERR;

					dd_dev_err_ratelimited(
						head->hotpath.svc->dd,
						"bts: rdmavt post send (deferred replay) rc %d\n",
						rv);
					head->hotpath.flush_status = wc_st;
					list_add(&head->list,
						 &qp_info->deferred_wrs);
					verbs_error_qp(hp_qp,
						       IB_WC_WR_FLUSH_ERR);
					verbs_deferred_flush_all(qp_info);
					break;
				}
			}
		}

		verbs_deferred_free(head);
	}
}

/*
 * Snapshot a userspace ib_send_wr onto a verbs_deferred_wr for replay.
 * Pulls parent ib_rdma_wr / ib_atomic_wr tail fields via container_of.
 * Caller's qp ref passes to the returned snapshot.
 */
static struct verbs_deferred_wr *
snapshot_uverbs_wr_onto_deferred(struct hfi2_bulksvc *svc,
				 struct rvt_qp *qp,
				 struct ib_send_wr *wr)
{
	struct verbs_deferred_wr *def;
	u32 num_sge = wr->num_sge;

	/* BTS thread: GFP_NOWAIT - do not enter reclaim. */
	def = kzalloc_node(struct_size(def, hotpath.sges, num_sge),
			   GFP_NOWAIT | __GFP_NOWARN,
			   svc->dd->node);
	if (!def)
		return NULL;

	INIT_LIST_HEAD(&def->list);
	def->path = DEFERRED_PATH_HOTPATH;
	def->hotpath.svc = svc;
	def->hotpath.qp = qp;
	def->hotpath.wr_id = wr->wr_id;
	def->hotpath.opcode = wr->opcode;
	def->hotpath.send_flags = wr->send_flags;
	def->hotpath.imm_data = wr->ex.imm_data;
	def->hotpath.num_sge = num_sge;
	if (num_sge)
		memcpy(def->hotpath.sges, wr->sg_list,
		       num_sge * sizeof(struct ib_sge));

	switch (wr->opcode) {
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
	case IB_WR_RDMA_READ: {
		struct ib_rdma_wr *rw = container_of(wr, struct ib_rdma_wr, wr);

		def->hotpath.remote_addr = rw->remote_addr;
		def->hotpath.rkey = rw->rkey;
		break;
	}
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD: {
		struct ib_atomic_wr *aw =
			container_of(wr, struct ib_atomic_wr, wr);

		def->hotpath.remote_addr = aw->remote_addr;
		def->hotpath.rkey = aw->rkey;
		def->hotpath.compare_add = aw->compare_add;
		def->hotpath.swap = aw->swap;
		break;
	}
	default:
		/* SEND-class: no remote_addr/rkey/atomic fields. */
		break;
	}

	/* hazard.* stays zero; retry recomputes the footprint, and the
	 * in-order guard defers everything behind a non-empty
	 * deferred_wrs regardless of hazard. */
	return def;
}

void bulksvc_on_cmd_uverbs_post_send(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_uverbs_post_send const * const cmd)
{
	enum ib_wc_status first_err_status = IB_WC_GENERAL_ERR;
	const struct ib_send_wr *bad_wr = NULL;
	bool lane_mismatch = false;
	u64 qpn = cmd->app_context;
	struct ib_uverbs_sge *sge;
	enum ib_qp_state qp_state;
	unsigned long s_flags;
	struct rvt_qp *qp;
	int state_ops;
	int ret;
	u16 i;

	qp = qp_from_number(svc, qpn);
	if (!qp) {
		dd_dev_err(svc->dd, "QP #%llu not found\n", cmd->app_context);
		return;
	}
	if (qp->ibqp.qp_type != IB_QPT_RC) {
		dd_dev_err(svc->dd, "Cannot ioctl bypass non RC qp's\n");
		rvt_put_qp(qp);
		return;
	}

	struct hfi2_bulksvc_qp_info *qp_info = bulksvc_qp_info_of(qp);
	u8 *ptr = (u8 *)cmd->wrs;

	/* A QP's BTS state belongs to one lane; only that lane may post. */
	if (unlikely(qp_info->lane != user_info->lane)) {
		dd_dev_err_ratelimited(svc->dd,
				       "bts: QP %llu lane %u posted from lane %u\n",
				       qpn, qp_info->lane, user_info->lane);
		lane_mismatch = true;
		i = 0;
		ret = -EINVAL;
		goto post_errs;
	}

	if (unlikely(!verbs_qp_is_send_capable(qp_info))) {
		spin_lock_irqsave(&qp->s_lock, s_flags);
		state_ops = ib_rvt_state_ops[qp->state];
		spin_unlock_irqrestore(&qp->s_lock, s_flags);
		if (!(state_ops & RVT_PROCESS_SEND_OK)) {
			first_err_status = (state_ops & RVT_FLUSH_SEND) ?
				IB_WC_WR_FLUSH_ERR : IB_WC_GENERAL_ERR;
			i = 0;
			goto post_errs;
		}
	}

	for (i = 0; i < cmd->num_wrs; i ++) {
		struct ib_rdma_wr rdma_wr;
		struct ib_atomic_wr atomic_wr;
		struct ib_uverbs_send_wr *user_wr;

		user_wr = (struct ib_uverbs_send_wr *)ptr;
		sge = (struct ib_uverbs_sge *)(ptr + sizeof(*user_wr));

		struct ib_send_wr *wr;
		struct ib_send_wr swr = {
			.next = NULL,
			.wr_id = user_wr->wr_id,
			.sg_list = (struct ib_sge *)sge,
			.num_sge = user_wr->num_sge,
			.opcode = user_wr->opcode,
			.send_flags = user_wr->send_flags,
			.ex.imm_data = user_wr->ex.imm_data
		};
		if (user_wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
		    user_wr->opcode == IB_WR_RDMA_WRITE ||
		    user_wr->opcode == IB_WR_RDMA_READ) {
			rdma_wr.wr = swr;
			rdma_wr.remote_addr =  user_wr->wr.rdma.remote_addr;
			rdma_wr.rkey = user_wr->wr.rdma.rkey;

			wr = &rdma_wr.wr;
		} else if (user_wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP ||
			   user_wr->opcode == IB_WR_ATOMIC_FETCH_AND_ADD) {
			atomic_wr.wr = swr,
			atomic_wr.remote_addr = user_wr->wr.atomic.remote_addr;
			atomic_wr.compare_add = user_wr->wr.atomic.compare_add;
			atomic_wr.swap = user_wr->wr.atomic.swap;
			atomic_wr.rkey = user_wr->wr.atomic.rkey;

			wr = &atomic_wr.wr;
		} else {
			wr = &swr;
		}

		/* In-order guard: once anything is on deferred_wrs, append
		 * subsequent WRs in posted order.  Dispatch destination is
		 * re-decided at retry time. */
		if (!list_empty(&qp_info->deferred_wrs)) {
			struct verbs_deferred_wr *def;

			if (unlikely(!verbs_qp_is_send_capable(qp_info))) {
				int cur_ops =
					ib_rvt_state_ops[READ_ONCE(qp->state)];

				if (!(cur_ops & RVT_PROCESS_SEND_OK)) {
					first_err_status =
						(cur_ops & RVT_FLUSH_SEND) ?
						IB_WC_WR_FLUSH_ERR :
						IB_WC_GENERAL_ERR;
					goto post_errs;
				}
			}

			rvt_get_qp(qp); /* deferred entry's ref */
			def = snapshot_uverbs_wr_onto_deferred(svc, qp, wr);
			if (!def) {
				rvt_put_qp(qp);
				ret = -ENOMEM;
				goto post_errs;
			}
			list_add_tail(&def->list, &qp_info->deferred_wrs);
			ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
			continue;
		}

		/* bts-side cross-traffic gate:
		 *   bts-able WR: admit when SQ drained (no rdmavt fallback
		 *     in flight); else defer.
		 *   non-bts-able WR: admit when bts_path_inflight_bts == 0;
		 *     else defer (retire of last bts wakes the retry). */
		ulong flags;
		bool can_send_hotpath = false;
		bool gate_defer = false;
		bool qp_bad_state = false;
		bool bts_able;

		spin_lock_irqsave(&qp->s_lock, flags);
		{
			qp_state = qp->state;
			state_ops = ib_rvt_state_ops[qp_state];
			bts_able = can_bts_hotpath(qp, wr);

			if (unlikely(!(state_ops & RVT_PROCESS_SEND_OK))) {
				qp_bad_state = true;
				first_err_status =
					(state_ops & RVT_FLUSH_SEND) ?
					IB_WC_WR_FLUSH_ERR : IB_WC_GENERAL_ERR;
			} else if (bts_able && qp_state == IB_QPS_RTS) {
				/* READ_ONCE: s_head advance is monotonic; a
				 * stale read still defers safely. */
				bool sq_drained =
					READ_ONCE(qp->s_head) == qp->s_last;

				if (!bulksvc_path_gate || sq_drained) {
					can_send_hotpath = true;
					qp_info->bts_path_inflight_bts += 1;
					/* Shared: see ordering_deliver_one. */
					qp_info->n_dispatched_unacked++;
					qp_info->last_dispatched_class =
						OPCLASS_BTS;
				} else {
					gate_defer = true;
				}
			} else if (bts_able) {
				/* IB_QPS_SQD: defer hotpath until RTS or ERR. */
				gate_defer = true;
			} else {
				if (bulksvc_path_gate &&
				    qp_info->bts_path_inflight_bts > 0)
					gate_defer = true;
				/* else: fall through to rvt_post_send;
				 * make_rc_req owns the bump on dispatch. */
			}
		}
		spin_unlock_irqrestore(&qp->s_lock, flags);

		if (unlikely(qp_bad_state))
			goto post_errs;

		if (unlikely(gate_defer)) {
			struct verbs_deferred_wr *def;

			rvt_get_qp(qp); /* deferred entry's ref */
			def = snapshot_uverbs_wr_onto_deferred(svc, qp, wr);
			if (!def) {
				rvt_put_qp(qp);
				ret = -ENOMEM;
				goto post_errs;
			}
			list_add_tail(&def->list, &qp_info->deferred_wrs);
			ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
			continue;
		}

		if (likely(can_send_hotpath)) {
			rvt_get_qp(qp);
			ret = bulksvc_verbs_hotpath_send_one(svc, qp, wr);
			if (unlikely(ret)) {
				/*
				 * Roll back admit-side counter bumps. On
				 * -EAGAIN the snapshot inherited our qp ref.
				 */
				spin_lock_irqsave(&qp->s_lock, flags);
				if (!WARN_ON_ONCE(qp_info->bts_path_inflight_bts == 0))
					qp_info->bts_path_inflight_bts -= 1;
				if (WARN_ON_ONCE(qp_info->n_dispatched_unacked == 0)) {
					/* skip dec */
				} else if (--qp_info->n_dispatched_unacked == 0) {
					qp_info->last_dispatched_class =
						OPCLASS_NONE;
					bulksvc_release_bts_gate(qp);
				}
				spin_unlock_irqrestore(&qp->s_lock, flags);

				if (ret != -EAGAIN) {
					rvt_put_qp(qp);
					dd_dev_err(svc->dd,
						   "bts: hotpath post send rc %d\n",
						   ret);
					first_err_status = IB_WC_GENERAL_ERR;
					goto post_errs;
				}
			}
		} else {
			wr->send_flags |= HFI2_SEND_NO_BULKSVC;
			ret = rvt_post_send(&qp->ibqp, wr, &bad_wr);
			if (unlikely(ret)) {
				int cur_ops =
					ib_rvt_state_ops[READ_ONCE(qp->state)];

				/* we need to post errors to cq */
				dd_dev_err(svc->dd, "bts: rdmavt post send rc %d\n", ret);
				first_err_status =
					(cur_ops & RVT_FLUSH_SEND) ?
					IB_WC_WR_FLUSH_ERR : IB_WC_GENERAL_ERR;
				goto post_errs;
			}
		}

		ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
	}

	rvt_put_qp(qp);
	return;
post_errs:
	if (unlikely(lane_mismatch)) {
		for (; i < cmd->num_wrs; i++) {
			struct ib_uverbs_send_wr *user_wr =
				(struct ib_uverbs_send_wr *)ptr;
			u32 byte_len = 0;

			sge = (struct ib_uverbs_sge *)(ptr + sizeof(*user_wr));
			for (int s = 0; s < user_wr->num_sge; s++) {
				byte_len += sge->length;
				sge++;
			}
			bts_send_cq(qp, user_wr->wr_id, byte_len,
				    user_wr->opcode, user_wr->send_flags,
				    IB_WC_GENERAL_ERR);
			ptr += sizeof(*user_wr) +
			       (user_wr->num_sge * sizeof(*sge));
		}
		rvt_put_qp(qp);
		return;
	}

	/*
	 * Transition the QP to IB_QPS_ERR on any post-acceptance failure
	 * (or when already in a non-send-capable state with RVT_POST_SEND_OK)
	 * and flush any previously deferred WRs before completing the
	 * remaining WRs in this batch in strict posted order.
	 */
	if (ib_rvt_state_ops[READ_ONCE(qp->state)] &
	    (RVT_PROCESS_SEND_OK | RVT_POST_SEND_OK))
		verbs_error_qp(qp, IB_WC_WR_FLUSH_ERR);

	verbs_deferred_flush_all(qp_info);

	for (u16 err_idx = i; err_idx < cmd->num_wrs; err_idx++) {
		enum ib_wc_status st = (err_idx == i) ?
			first_err_status :
			((first_err_status == IB_WC_WR_FLUSH_ERR ||
			  READ_ONCE(qp->state) == IB_QPS_ERR) ?
			 IB_WC_WR_FLUSH_ERR : first_err_status);
		struct ib_uverbs_send_wr *user_wr =
			(struct ib_uverbs_send_wr *)ptr;
		u32 byte_len = 0;

		sge = (struct ib_uverbs_sge *)(ptr + sizeof(*user_wr));
		if (st != IB_WC_WR_FLUSH_ERR) {
			for (int s = 0; s < user_wr->num_sge; s++)
				byte_len += sge[s].length;
		}

		if (!list_empty(&qp_info->deferred_wrs) ||
		    qp_info->ordering.next_deliver_seq <
		    qp_info->ordering.next_issue_seq) {
			struct ib_send_wr swr = {
				.next = NULL,
				.wr_id = user_wr->wr_id,
				.sg_list = (struct ib_sge *)sge,
				.num_sge = user_wr->num_sge,
				.opcode = user_wr->opcode,
				.send_flags = user_wr->send_flags,
				.ex.imm_data = user_wr->ex.imm_data,
			};
			struct ib_rdma_wr rdma_wr = { .wr = swr };
			struct ib_atomic_wr atomic_wr = { .wr = swr };
			struct ib_send_wr *wr = &swr;
			struct verbs_deferred_wr *def;

			if (user_wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM ||
			    user_wr->opcode == IB_WR_RDMA_WRITE ||
			    user_wr->opcode == IB_WR_RDMA_READ) {
				rdma_wr.remote_addr =
					user_wr->wr.rdma.remote_addr;
				rdma_wr.rkey = user_wr->wr.rdma.rkey;
				wr = &rdma_wr.wr;
			} else if (user_wr->opcode ==
				   IB_WR_ATOMIC_CMP_AND_SWP ||
				   user_wr->opcode ==
				   IB_WR_ATOMIC_FETCH_AND_ADD) {
				atomic_wr.remote_addr =
					user_wr->wr.atomic.remote_addr;
				atomic_wr.compare_add =
					user_wr->wr.atomic.compare_add;
				atomic_wr.swap = user_wr->wr.atomic.swap;
				atomic_wr.rkey = user_wr->wr.atomic.rkey;
				wr = &atomic_wr.wr;
			}

			rvt_get_qp(qp);
			def = snapshot_uverbs_wr_onto_deferred(svc, qp, wr);
			if (def) {
				def->hotpath.flush_status = st;
				list_add_tail(&def->list,
					      &qp_info->deferred_wrs);
				ptr += sizeof(*user_wr) +
				       (user_wr->num_sge * sizeof(*sge));
				continue;
			}
			rvt_put_qp(qp);
		} else {
			u64 seq = qp_info->ordering.next_issue_seq++;

			qp_info->ordering.next_deliver_seq = seq + 1;
		}

		bts_send_cq(qp, user_wr->wr_id, byte_len, user_wr->opcode,
			    user_wr->send_flags, st);
		ptr += sizeof(*user_wr) + (user_wr->num_sge * sizeof(*sge));
	}
	verbs_deferred_flush_all(qp_info);
	rvt_put_qp(qp);
}

static int verbs_host_mr_memcpy_fn(struct hfi2_dms_mr *mr, u64 offset, u64 size, void *data, const bool is_read)
{
	u8 *cdata = (u8 *)data;

	if (WARN_ON(!mr))
		return -EINVAL;

	if (WARN_ON(offset > mr->extended_vaddr.len || size > mr->extended_vaddr.len - offset))
		return -EINVAL;

	struct bts_verbs_pageset *ps = container_of(mr, struct bts_verbs_pageset, dms_mr);
	enum dma_data_direction dir = is_read ? DMA_FROM_DEVICE : DMA_TO_DEVICE;

	/*
	 * Device-accessible-only memory has no kernel addressable pointer, so
	 * hand the copy to the lower-level driver which uses P2P ioremap.
	 */
	if (ps->mem_type == RVT_MEM_DMABUF_DO) {
		u64 page_index = offset / PAGE_SIZE;
		u64 offset_in_page = offset % PAGE_SIZE;
		struct rvt_dev_info *rdi = &ps->dd->verbs_dev.rdi;
		struct rvt_seg dma_mem, local_mem;
		int ret;

		dma_mem.type = RVT_MEM_DMABUF_DO;
		dma_mem.seg_dmabuf_do.priv = ps->dma_buf_do_priv;
		dma_mem.seg_dmabuf_do.dmabuf = ps->dmabuf;
		dma_mem.vaddr = ps->vaddrs[page_index] + offset_in_page;
		local_mem = rvt_to_kseg(data, size);
		dma_mem.length = size;
		if (is_read)
			ret = rdi->driver_f.dmabuf_memcpy(local_mem, dma_mem);
		else
			ret = rdi->driver_f.dmabuf_memcpy(dma_mem, local_mem);

		return ret;
	}

	while (size > 0) {
		u64 page_index = offset / PAGE_SIZE;
		u64 offset_in_page = offset % PAGE_SIZE;
		u64 to_copy = min_t(u64, size, PAGE_SIZE - offset_in_page);
		void *kaddr;

		if (ps->mem_type == RVT_MEM_DMABUF) {
			kaddr = ps->vaddrs[page_index];
			dma_buf_begin_cpu_access(ps->dmabuf, dir);
		} else {
			kaddr = kmap_local_page(virt_to_page(ps->vaddrs[page_index]));
		}

		if (is_read)
			memcpy(cdata, kaddr + offset_in_page, to_copy);
		else
			memcpy(kaddr + offset_in_page, cdata, to_copy);

		if (ps->mem_type == RVT_MEM_DMABUF)
			dma_buf_end_cpu_access(ps->dmabuf, dir);
		else
			kunmap_local(kaddr);

		size -= to_copy;
		offset += to_copy;
		cdata += to_copy;
	}
	return 0;
}
