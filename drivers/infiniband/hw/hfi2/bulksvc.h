/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */
#ifndef DEF_HFI2_BULKSVC_H
#define DEF_HFI2_BULKSVC_H

#include "hfi2.h"
#include "dms.h"
#include "dms_roce.h"
#include "bulksvc_ipoib.h"
#include "bulksvc_user.h"
#include "bulksvc_verbs.h"
#include <linux/completion.h>
#include <linux/irqreturn.h>
#include <linux/kref.h>

#define HFI2_BULKSVC_PORT_LUT_SIZE 4

/*
 * Enable the RoCE, UET, net and eal_test stub peers and their registration.
 * With the flag off, the Ethernet eal_test receive context is not allocated.
 * EAL ingress interception and drop counters, the ULP netdev receive path
 * with its RCU netdev pointer, and ulp_rx_stats accounting remain compiled.
 * They act only on frames reaching the control RCD; in Ethernet mode that
 * RCD exists only when the eal_test context is allocated.
 */
#define HFI2_BULKSVC_ULP_STUBS (0)

#if HFI2_BULKSVC_ULP_STUBS
#define HFI2_BULKSVC_EAL_RCD_IDX HFI2_DMS_ROCE_RCD_COUNT
#endif

struct rsm_map_table;
struct seq_file;
/* Defined in bulksvc_ulp.h under HFI2_BULKSVC_ULP_STUBS; forward-declared here so the
 * pointer members below do not depend on include ordering.
 */
struct hfi2_bulksvc_ulp_state;

/*
 * mmu_notifier .release drain request.  2-ref kref so a timed-out
 * waiter can drop its ref without dangling the bulksvc-thread ref.
 */
struct hfi2_bulksvc_mmu_sync_drain {
	struct kref refcount;
	struct hfi2_bulksvc_user_info *user_info;
	struct completion done;
};

void hfi2_bulksvc_mmu_sync_drain_put(struct hfi2_bulksvc_mmu_sync_drain *sd);

extern uint bulksvc_user_queue_size_pages_log2;

/* requirements defined prior to resource allocation */
struct hfi2_bulksvc_requirements {
	u32 num_sdma;
	u32 credits_per_sdma;
	u32 num_send_ctxs; /* are these per port? */
	u32 num_rcv_ctxs;
};

/* per port resources */
struct hfi2_bulksvc_pp_rsrc {
	u32 rcd_len;
	struct hfi2_ctxtdata **rcd; /* sized to  prereqs.num_rctxts */
};

/* resources given to the service.
 * do not free these structures.
 */
struct hfi2_bulksvc_resource_loan {
	/* sized to prereqs.num_sdma, allocation implies ownership */
	struct sdma_engine **sde_arr;
	struct hfi2_bulksvc_pp_rsrc *pp; /* sized to num_ports */
};

/*
 * A PF has exactly one bulksvc transport backend. Native DMS owns OPA
 * protocol state and SDMA; DMS_RoCE drives only the explicitly loaned ETH
 * resources and must not make the native DMS object live by accident.
 */
enum hfi2_bulksvc_backend {
	HFI2_BULKSVC_BACKEND_OPA_DMS,
	HFI2_BULKSVC_BACKEND_ETH_ROCE,
};

enum hfi2_bulksvc_event_type {
  BULKSVC_EVENT_TYPE_SDMA = 0,
  BULKSVC_EVENT_TYPE_USER_INFO_ADD,
  BULKSVC_EVENT_TYPE_USER_INFO_RELEASE,
  BULKSVC_EVENT_TYPE_MMU_SYNC_DRAIN,
};

struct hfi2_bulksvc_event {
  enum hfi2_bulksvc_event_type type;
  union {
	struct hfi2_bulksvc_user_info *user_info;
	struct hfi2_bulksvc_mmu_sync_drain *sync_drain;
  };
} __attribute__((packed, aligned(64)));

struct hfi2_bulksvc_event_entry {
	struct hfi2_bulksvc_event event;
	struct list_head list;
};

enum hfi2_bulksvc_event_work_outcome {
	HFI2_BULKSVC_EVENT_WORK_IDLE,
	HFI2_BULKSVC_EVENT_WORK_SATURATED,
	HFI2_BULKSVC_EVENT_WORK_STOPPED,
};

struct hfi2_bulksvc_closeout_stats {
	u64 idle;
	u64 saturated;
	u64 stopped;
	u64 eoi_issued;
	u64 rx_race_reschedule;
};

/*
 * Proactive pin lists of one DMS lane: the pin entries of the user clients
 * whose DMS state lives on that lane (hfi2_bulksvc_user_pins()).  Touched
 * only by that lane's worker; the bulksvc_dbg producer reads the counters
 * without locking.
 */
struct hfi2_bulksvc_pin_lists {
	struct list_head pin_speculative;
	struct list_head pin_active;
	u32 speculative_count;
	u32 active_count;
	u64 pages_pinned_inline;
	u64 pages_pinned_proactive;
	u64 inline_pin_count;
	u64 proactive_pin_ops;
	u64 proactive_pin_failures;
};

/*
 * The primary lane also runs the svc-wide work: verbs MR registration (its
 * cmdq is the verbs cmd queue), the IPoIB / ULP / RoCE pollers, the debug
 * info producer and the doorbell re-arm.
 */
#define HFI2_BULKSVC_PRIMARY_LANE 0

/*
 * One DMS lane: a DMS instance with its own ctrl/data receive context pair
 * (bulksvc rcd[2k] / rcd[2k + 1] of each port) and the ctrl context's PIO
 * send context, driven by its own worker on its own CPU.  The one DMS RSM
 * rule steers a control packet to the lane its lane selector names (see
 * HFI2_DMS_LANE_SEL_* in dms.h).  A lane's DMS state is touched only by
 * that lane's worker (DMS is single threaded), except: the SDMA rev
 * (bulksvc_rev_work_fn()) stops every lane's worker and then polls the
 * primary lane's DMS itself, the bulksvc_dbg producer on the primary lane
 * reads every lane's counters without locking (debug output only), and
 * debugfs packet_drop writes every lane's drop rules (atomics and
 * WRITE_ONCE()).
 */
struct hfi2_bulksvc_lane {
	struct hfi2_bulksvc *svc;
	struct hfi2_dms *dms;		/* allocated by hfi2_bulksvc_init() */
	u32 idx;
	int cpu;			/* CPU of the worker and of the rcd IRQs */
	bool dms_up;			/* hfi2_dms_init() succeeded */
	struct work_struct work;	/* on svc->event_workq */
	/*
	 * Adaptive halt-poll spin window (ns), owned by the lane worker.
	 * Grows on a spin that catches work, shrinks on an idle spin.
	 * Bounded by the bulksvc_halt_poll_ns module param.
	 */
	unsigned int halt_poll_ns;
	/*
	 * verbs cmds this lane's worker consumes (any producer): the verbs
	 * cmd queue (MR reg/dereg and the RDMA cmds of its QPs) on the
	 * primary lane, rdma_cmds on the others.
	 */
	struct hfi2_bulksvc_mpsc_verbs_cmd_queue *cmdq;
	/* rdmavt-path BTS RDMA cmds of this lane's QPs; not the primary lane */
	struct hfi2_bulksvc_mpsc_verbs_cmd_queue rdma_cmds;
	/*
	 * Verbs MR replication so a secondary lane can act as an RDMA
	 * target: the primary lane produces REG/DEREG ops, this lane's worker
	 * consumes.  Unused on the primary lane.
	 */
	struct mpsc_queue mr_ops;
	struct list_head mr_replicas;	/* lane-worker only */
	/*
	 * The lane polls the user clients whose bit is set in client_bits
	 * (one bit per dirty-notify bit; see
	 * hfi2_bulksvc_user_info_bind_locked()).
	 */
	unsigned long *client_bits;
	u32 nr_clients;			/* bound clients, under user_info_lock */
	/* events of this lane (any producer, this lane's worker consumes) */
	spinlock_t event_lock;
	struct list_head event_queue;
	struct hfi2_bulksvc_pin_lists pins;
};

struct hfi2_bulksvc {
	/*
	 * CL0: read-mostly; hfi2_bulksvc_schedule_lane() reads it from IRQ
	 * context. Per-lane cpu/work live in struct hfi2_bulksvc_lane.
	 */
	bool stop_scheduling;
	/* runs every lane's worker */
	struct workqueue_struct *event_workq;
	struct hfi2_devdata *dd; /* pointer to device setting up the service */
	enum hfi2_bulksvc_backend backend;
	bool roce_by_software;
	int doorbell_msix_intr;

	/*
	 * CL1: per-pass polling state: the dirty-bitmap group, hot members
	 * first, all worker-read.  Dirty bitmap notification enables
	 * O(active_clients) polling.
	 */
	struct {
		unsigned long *bitmap;          /* page_address(page) */
		struct hfi2_bulksvc_user_info **client_map; /* bit index -> user_info */
		unsigned int num_bitmap_qwords;
		unsigned int max_clients;       /* PAGE_SIZE * BITS_PER_BYTE */
		struct page *page;              /* single page backing the bitmap */
		unsigned long *allocated;       /* kernel-only: which bits are assigned */
	} dirty_notify ____cacheline_aligned_in_smp;

	/* Cold configuration/registration state from here down. */
	struct hfi2_bulksvc_requirements prereqs ____cacheline_aligned_in_smp;
	struct hfi2_bulksvc_resource_loan rsrc;
	/*
	 * NULL unless hfi2_is_eth_mode(dd).  Heap-allocated by
	 * hfi2_dms_roce_init() so OPA-mode devices (including JKR/CN5000)
	 * pay for a bare pointer instead of the full backend + stats
	 * struct.  See dms_roce.h.
	 */
	struct hfi2_dms_roce *dms_roce;
	struct mmu_rb_handler *mmu_handler;

	/* SDMA read-path warm-up: run once, deferred to rev_work. */
	bool rev_done;
	struct work_struct rev_work;
	bool worker_exited;
	struct completion worker_exited_done;
	/* MR lane replicas released, or worker_exited; see mr_priv_free */
	wait_queue_head_t lane_reps_wq;

	struct hrtimer progress_timer;
	ktime_t timer_interval;

	bool user_state_initialized;
	bool verbs_state_initialized;
	bool verbs_caches_initialized;
	bool sdma_quiesce_failed;
	bool doorbell_irq_allocated;
	bool roce_rsm_programmed;
	struct hfi2_bulksvc_closeout_stats closeout_stats;

	struct mutex user_info_lock;
	struct list_head user_infos;

	struct hfi2_bulksvc_verbs_state verbs_state;

	/* Slab caches for the high-frequency verbs cmd/cmpl control objects
	 * (replaces kzalloc(GFP_ATOMIC) under qp->s_lock on the post_send path).
	 */
	struct kmem_cache *verbs_cmd_cache;
	struct kmem_cache *verbs_cmpl_cache;
	struct kmem_cache *verbs_sge_cache;

	int first_rsm_rule;
	int first_rsm_index;
	/*
	 * The VRMA rule.  It matches L4 == 0x7A and carries its own
	 * bypass_hdr_size and its own PacketType, and it points at the same
	 * map-table slot and receive context as the on-load rule: a promoted
	 * VRMA frame and an on-load frame are two encapsulations of the same
	 * RoCE traffic and belong on the same poller.
	 */
	int vrma_rsm_rule;
#if HFI2_BULKSVC_ULP_STUBS
	int eth_rsm_rule;
	int eth_rsm_index;
	bool eal_test_dstport_armed;
#endif

	/* DMS lanes (bulksvc_num_lanes); [0, num_lanes) are live */
	u32 num_lanes;
	struct hfi2_bulksvc_lane lanes[HFI2_BULKSVC_MAX_LANES];
	/* num_lanes > 1: per loaned SDMA engine, shared by every lane's DMS */
	struct hfi2_dms_sde_share *sde_share;
	/* backing of every lane's client_bits */
	unsigned long *lane_client_bits;

	atomic_t last_client_key;

	enum hfi2_dms_fabric_port_idx port_lut[HFI2_BULKSVC_PORT_LUT_SIZE];

	// If 0, nothing to do.  If 1, bulksvc should replace with an owning char* to debug output buffer
	atomic64_t debug_info_buf_ptr;

	/* In-flight Phase B (deferred user_info destroy) works.  Teardown
	 * blocks on the wq until this drains to 0 so svc isn't freed
	 * underneath a pending Phase B.
	 */
	atomic_t pending_user_info_destroys;
	wait_queue_head_t pending_user_info_destroys_wq;

	/*
	 * Deferred MR page-set teardown.  Queued from the BTS thread to do
	 * the sleepable dma_unmap / kvfree off-thread (normal dereg drain
	 * and the rare MR_REG-failure path).  Each work carries the dd and
	 * page/dma arrays by value, so it outlives its bts_verbs_mr_record.
	 * A private wq gives us destroy_workqueue() as the teardown sync
	 * primitive without a waiter+atomic vs kfree(svc) UAF window.
	 */
	struct workqueue_struct *mr_unmap_wq;

	/* Per-port IPoIB transmit handoff.  See bulksvc_ipoib.h. */
	struct hfi2_bulksvc_ipoib_port ipoib[HFI2_DMS_MAX_PORTS];

	/* Ports registered above; zero unless ipoib_tx_mode=hfisvc is in use. */
	u8 ipoib_registered;

#if HFI2_BULKSVC_ULP_STUBS
	/* Per-instance DMS ULP stub state; allocated in _init, freed in _teardown. */
	struct hfi2_bulksvc_ulp_state *roce_ulp;
	struct hfi2_bulksvc_ulp_state *uet_ulp;
	struct hfi2_bulksvc_ulp_state *net_ulp;
	struct hfi2_bulksvc_ulp_state *eal_test_ulp;
#endif
};

void hfi2_bulksvc_closeout_stats_print(struct hfi2_bulksvc *svc,
					   struct seq_file *s);

static inline bool hfi2_bulksvc_is_opa(const struct hfi2_bulksvc *svc)
{
	return svc->backend == HFI2_BULKSVC_BACKEND_OPA_DMS;
}

static inline bool bulksvc_lane_is_primary(const struct hfi2_bulksvc_lane *l)
{
	return l->idx == HFI2_BULKSVC_PRIMARY_LANE;
}

/* DMS of the primary lane: verbs MR registration, IPoIB, ULPs, RoCE. */
static inline struct hfi2_dms *hfi2_bulksvc_primary_dms(const struct hfi2_bulksvc *svc)
{
	return svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].dms;
}

/*
 * DMS instance holding a user client's DMS state: its client key, its
 * hfisvc accesses and initiator trackers (user_info->lane).
 */
static inline struct hfi2_dms *
hfi2_bulksvc_user_dms(const struct hfi2_bulksvc_user_info *user_info)
{
	return user_info->svc->lanes[user_info->lane].dms;
}

/* Proactive pin lists of a user client's DMS lane. */
static inline struct hfi2_bulksvc_pin_lists *
hfi2_bulksvc_user_pins(const struct hfi2_bulksvc_user_info *user_info)
{
	return &user_info->svc->lanes[user_info->lane].pins;
}

/* setup data structures, define requirements */
int hfi2_bulksvc_init(struct hfi2_devdata *dd);

/* loan sdma's/contexts to the service */
int hfi2_bulksvc_loan_resources(struct hfi2_devdata *dd);

/* Disable bulksvc, return (or free) all resources to the hfi2 device */
void hfi2_bulksvc_teardown(struct hfi2_devdata *dd);

/* Stop the bulksvc thread before verbs_txreq_exit.  Resource teardown
 * (DMS, SDE, rcd) is left for hfi2_bulksvc_teardown.
 */
void hfi2_bulksvc_quiesce_thread(struct hfi2_devdata *dd);

/* Drain verbs cmds/cmpls left after the bulksvc thread is stopped. */
void hfi2_bulksvc_drain_verbs_queues(struct hfi2_devdata *dd);

/* Process events left queued after the bulksvc thread is stopped. */
void hfi2_bulksvc_flush_event_queue(struct hfi2_bulksvc *svc);

/* sdma irq handler */
void bulksvc_sdma_irq(struct hfi2_devdata *dd, struct sdma_engine *sde);

/* Wake the primary lane's worker */
void hfi2_bulksvc_schedule(struct hfi2_bulksvc *svc);

/* Wake the worker of DMS lane @lane */
void hfi2_bulksvc_schedule_lane(struct hfi2_bulksvc *svc, u32 lane);

/* Wake the lane polling a user client (doorbell / sync cmd). */
void hfi2_bulksvc_schedule_user(struct hfi2_bulksvc_user_info *user_info);

/* CPU for the IRQ of a bulksvc receive context: its DMS lane's CPU */
int hfi2_bulksvc_rcd_irq_cpu(struct hfi2_ctxtdata *rcd);

/* Receive IRQ of a bulksvc receive context: wake its DMS lane's worker */
void hfi2_bulksvc_rcd_wake(struct hfi2_ctxtdata *rcd);

/* Run the SDMA read-path warm-up once, when bulksvc and the link are both up. */
void hfi2_bulksvc_rev_maybe_fire(struct hfi2_devdata *dd);

/* RoCE receive placed entirely by software for this device. */
bool hfi2_bulksvc_roce_by_software(const struct hfi2_devdata *dd);
int hfi2_bulksvc_roce_placement_unavailable(struct hfi2_devdata *dd,
					    const char *reason);

/* Whether `hfi2_bulksvc_doorbell` is required to be invoked */
bool hfi2_bulksvc_requires_doorbell(struct hfi2_bulksvc *svc);

/* called during rsm init but before loan_resources */
void bulksvc_rsm_reserve(struct hfi2_devdata *dd, struct rsm_map_table *rmt);

/* bulksvc rsm init */
int bulksvc_rsm_init(struct hfi2_bulksvc *svc);

int hfi2_bulksvc_enqueue_user_event(struct hfi2_bulksvc_user_info *user_info,
				    struct hfi2_bulksvc_event_entry *entry);
int hfi2_bulksvc_user_pin_range(struct hfi2_bulksvc *svc, void *mr_record,
			       unsigned int from_page,
			       unsigned int npages,
			       bool writable);
void hfi2_bulksvc_pin_entry_unlink(struct hfi2_bulksvc_pin_lists *pins,
				   struct hfi2_bulksvc_proactive_pin_entry *entry);

/* Bulksvc doorbell handlers */
irqreturn_t hfi2_bulksvc_doorbell_interrupt(int irq, void *data);
irqreturn_t hfi2_bulksvc_doorbell_interrupt_thr(int irq, void *data);

/* 
 * Collects bulksvc info into human-readable output, must be called from bulksvc thread.  Will 
 * be called if debug_info_buf_ptr == 1
 */
char* hfi2_bulksvc_prepare_debug_info(struct hfi2_bulksvc *svc);

int hfi2_bulksvc_dirty_bit_alloc_locked(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_dirty_bit_free_locked(struct hfi2_bulksvc *svc, int bit);

void hfi2_bulksvc_user_info_bind_locked(struct hfi2_bulksvc_user_info *user_info);
void hfi2_bulksvc_user_info_unbind_locked(struct hfi2_bulksvc_user_info *user_info);

/*
 * A client key names the client's DMS lane in bits 29:27: key = lane << 27 |
 * id.  An hfisvc RDMA initiator takes the target lane of the lane selector
 * (see dms.h) from the target client key, so the transfer's control packets
 * reach the lane holding the target access.  Bits 31:30 stay clear, so a
 * client key never collides with the verbs client id (0xFF000000).
 */
#define HFI2_BULKSVC_CLIENT_KEY_LANE_SHIFT	27
#define HFI2_BULKSVC_CLIENT_KEY_ID_MASK \
	((1u << HFI2_BULKSVC_CLIENT_KEY_LANE_SHIFT) - 1)

static inline u32 hfi2_bulksvc_client_key_make(u32 id, u32 lane)
{
	return ((lane & HFI2_DMS_LANE_SEL_MASK) <<
		HFI2_BULKSVC_CLIENT_KEY_LANE_SHIFT) |
	       (id & HFI2_BULKSVC_CLIENT_KEY_ID_MASK);
}

static inline u32 hfi2_bulksvc_client_key_lane(u32 client_key)
{
	return (client_key >> HFI2_BULKSVC_CLIENT_KEY_LANE_SHIFT) &
	       HFI2_DMS_LANE_SEL_MASK;
}

#endif          /* DEF_HFI2_BULKSVC_H */
