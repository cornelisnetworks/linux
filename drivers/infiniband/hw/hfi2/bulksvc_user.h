/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#ifndef DEF_HFI2_BULKSVC_USER_H
#define DEF_HFI2_BULKSVC_USER_H

#include <linux/cache.h>
#include <linux/iosys-map.h>
#include <linux/types.h>
#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/pfn.h>
#include <linux/xarray.h>

#include <rdma/hfi2-abi.h>

#include "dms.h"
#include "mem_region.h"

struct hfi2_bulksvc_user_info;
struct hfi2_bulksvc;

/**
 * proactive pin list entry - Common node for the speculative/active
 * proactive-pin lists.
 *
 * Embed this in any object that participates in proactive pinning.
 * The worker of the owner's DMS lane is the sole user of both lists (the
 * lane's struct hfi2_bulksvc_pin_lists); no locking is required.
 *
 * @node: list_head linked into either pin_speculative or pin_active
 *        (mutually exclusive, or neither).
 * @hfi2_mr: backing memory region. process_proactive_pins reads
 *           hfi2_mr->pin_bitmap and hfi2_mr->npages_total.
 * @owner: user_info that owns this entry for accounting purposes.
 * @region_offset_bytes: byte offset of the user virtual address from
 *        the page-aligned base (vaddr & (PAGE_SIZE - 1)). Used by
 *        process_proactive_pins to decide whether to add a spill page
 *        on the first chunk.
 * @pin_range: callback invoked by process_proactive_pins to pin one
 *             chunk. May sleep (GUP/dma_map_page) but must not take
 *             any bulksvc-internal lock.
 * @on_speculative_pin_list: true iff @node is on its lane's pin_speculative.
 * @on_active_pin_list: true iff @node is on its lane's pin_active.
 */
struct hfi2_bulksvc_proactive_pin_entry {
	struct list_head node;
	struct hfi2_mem_region *hfi2_mr;
	struct hfi2_bulksvc_user_info *owner;
	u64 region_offset_bytes;
	int (*pin_range)(struct hfi2_bulksvc *svc,
			 struct hfi2_bulksvc_proactive_pin_entry *entry,
			 unsigned int from_page, unsigned int npages,
			 bool writable);
	bool on_speculative_pin_list;
	bool on_active_pin_list;
};

/*
 * Memory backing a queue slot: the user-mapped ctrl page and queue
 * buffer, plus the registration/mmap metadata describing them.
 * Referenced only at queue create/mmap/destroy. Allocated on a slot's
 * first use, retained across slot recycle, freed at client teardown.
 */
struct hfi2_bulksvc_queue_backing {
	struct hfi2_bulksvc_queue_info queue_info;
	struct hfi2_bulksvc_queue_ctrl *ctrl;
	u8 *queue_buf;
};

struct hfi2_bulksvc_queue_record {
	/*
	 * One cacheline: the fields the worker touches per polling visit.
	 * The userspace-shared head/tail atomics live in a separate
	 * vmalloc_user control page, so the shadows need no isolation here.
	 */
	bool active;
	u32 idx_mask;
	atomic64_t *head;
	atomic64_t *tail;
	u64 head_shadow; /* cmdq consumer  */
	u64 tail_shadow; /* cmplq producer */
	u8 *queue_buf_magic;

	/* CQ-targeted commands whose completions have not reached the ring. */
	u32 inflight;
	u32 max_inflight;

	struct hfi2_bulksvc_queue_backing *backing;
} ____cacheline_aligned_in_smp;

#define BULKSVC_USER_MAX_NUM_CMPLQS 16
#define BULKSVC_USER_MAX_NUM_CMDQS 16
#define BULKSVC_USER_MAX_NUM_CNTR_PAGES 16

#define CNTR_VALUE_SIZE		8U /* 64-Bit counter values*/
#define CNTR_SLOT_SIZE      (2 * CNTR_VALUE_SIZE) /* value + error */
#define CNTRS_PER_PAGE      (PAGE_SIZE / CNTR_SLOT_SIZE)
#define BULKSVC_USER_MAX_NUM_CNTRS (BULKSVC_USER_MAX_NUM_CNTR_PAGES * CNTRS_PER_PAGE)

struct bulksvc_cntr_page {
    void   *kaddr;
    u16     used;       /* number of allocated slots */
    u16     page_id;    /* index within the pool */
};

/* Initial and maximum ring capacity per counter (power-of-two capacities). */
#define TRIG_RING_INIT_CAP         64U
#define TRIG_RING_MAX_CAP        4096U

/* Max command size = 2 lines based on assert in client libray */
#define BULKSVC_TRIG_CMD_MAX_SIZE (2 * CACHELINE_SIZE)

/* Triggered-ops support: entry */
struct bulksvc_trig_cmd_entry {
    u8 cmd_bytes[BULKSVC_TRIG_CMD_MAX_SIZE];
    u64 target_value;
};

/* Helper to get the command pointer from a trigger entry */
static inline struct hfi2_bulksvc_cmd *trig_entry_cmd(struct bulksvc_trig_cmd_entry *ent)
{
    return (struct hfi2_bulksvc_cmd *)ent->cmd_bytes;
}

/* Triggered-ops support: per-counter ring */
struct bulksvc_cntr_trig_ring {
	struct bulksvc_trig_cmd_entry *buf;
	u32 cap;   /* capacity, power of two */
	u32 head;  /* monotonic head index */
	u32 tail;  /* monotonic tail index */
};

/*
 * Counter storage is a demand-allocated directory of fixed blocks:
 * addresses must stay stable once handed out (completions retain cntr
 * pointers), so blocks are never freed or moved until client teardown.
 * A full population costs 64 block allocations instead of one eager
 * 416KB array per client.
 */
#define BULKSVC_CNTR_BLOCK_SHIFT 6
#define BULKSVC_CNTR_BLOCK_SIZE  BIT(BULKSVC_CNTR_BLOCK_SHIFT) /* cntrs per block */
#define BULKSVC_CNTR_BLOCK_MASK  (BULKSVC_CNTR_BLOCK_SIZE - 1)
#define BULKSVC_CNTR_NUM_BLOCKS \
	(BULKSVC_USER_MAX_NUM_CNTRS / BULKSVC_CNTR_BLOCK_SIZE)

struct hfi2_bulksvc_cntr {
	bool active;
	struct hfi2_bulksvc_cntr_info cntr_info;

	/* Slot location */
	u16 page_id;      /* Which page */
	u16 slot_idx;     /* 0..CNTRS_PER_PAGE-1 within that page */
	u32 value_offset; /* Byte offset within page for value (slot_idx * 16) */
	u32 error_offset; /* Byte offset within page for error (value_ofs * 16) */
	void *page_kaddr; /* Cached kaddr for faster writes */
	
	/* Triggered operations ring for this counter */
	struct bulksvc_cntr_trig_ring trig_ring;

};

struct hfi2_bulksvc_cmpl {
 	enum hfi2_bulksvc_flags type;
 	union {
		struct hfi2_bulksvc_queue_record *cmplq_record;
		struct hfi2_bulksvc_cntr *cntr;
	};
};

enum hfi2_bulksvc_mr_type {
	HFI2_BULKSVC_MR_TYPE_HOST,
	HFI2_BULKSVC_MR_TYPE_DMABUF,
};

enum hfi2_bulksvc_fixup_cpu_mapping_type {
	HFI2_BULKSVC_FIXUP_CPU_MAPPING_NONE,
	HFI2_BULKSVC_FIXUP_CPU_MAPPING_VMAP,
};

struct hfi2_bulksvc_user_mr_record {
	struct list_head list_entry;
	struct kref refcount; // Can have multiple outstanding transactions
	u32 user_handle;

	enum hfi2_bulksvc_mr_type mr_type;
	union {
		struct {
			struct hfi2_mem_region *hfi2_mr;
		};
		struct {
			struct dma_buf *dma_buf;
			struct dma_buf_attachment *dma_buf_attachment;
			struct sg_table *sg_table;
			enum hfi2_bulksvc_fixup_cpu_mapping_type fixup_mapping_type;

			union {
				struct iosys_map vmap;
			} fixup_mapping;
		};
	} mem_region;

	struct hfi2_dms_mr dms_mr;
};

struct hfi2_bulksvc_ephemeral_mr {
	struct hfi2_mem_region *hfi2_mr;
	struct hfi2_bulksvc_user_info *user_info;
	struct hfi2_bulksvc_proactive_pin_entry pin_entry;
	struct list_head deferred_free_node;
	struct hfi2_dms_mr dms_mr;
};

struct hfi2_bulksvc_user_mr_record_ext {
	struct hfi2_bulksvc_user_mr_record mr_record;
	struct hfi2_bulksvc_user_info *pin_owner;
	struct hfi2_bulksvc_proactive_pin_entry pin_entry;
};

struct hfi2_bulksvc_user_mr_access_record {
	struct list_head list_entry;
	u64 app_context;
	u32 access_key;
	u32 cmplq_id;
	struct hfi2_bulksvc_user_mr_record *mr_record;
	struct hfi2_bulksvc_user_info *user_info;
	u32 client_key;
	/*
	 * Notification target captured at enable time so the async notify
	 * callback (on_dma_access_notify) routes per-access notifications to
	 * the user-requested completion target (CQ or CNTR) rather than
	 * hardcoding CQ via the primary enable cmplq_id.
	 */
	u64 notify_app_context;
	u32 notify_cmpl_id;
	__u64 notify_flags;
};

union hfi2_bulksvc_userctxt_cmd_data {
	u64 raw;
	struct {
		struct dma_buf *dmabuf;
	} dmabuf_open;
};

struct hfi2_bulksvc_userctxt_cmd_entry {
	struct list_head node;
	union hfi2_bulksvc_userctxt_cmd_data data;
	struct hfi2_bulksvc_cmd cmd; // variably-sized
};

/*
 * One parked completion: the 64-byte CQ entry plus its target CQ record.
 */
struct hfi2_bulksvc_overflow_entry {
	struct hfi2_bulksvc_cmplq_entry cmplq_entry;
	struct hfi2_bulksvc_queue_record *cmplq_record;
};

/*
 * Ordered by the worker's poll sequence (see the CLn groups below).
 * kzalloc of this size lands in a size-aligned slab bucket, so the
 * cacheline boundaries hold.
 */
struct hfi2_bulksvc_user_info {
	/* CL0: inspected on every poll pass. */
	u32 num_inflight;
	u32 max_inflight;
	u32 num_completion_overflows; /* entries in the overflow array */
	u32 completion_overflows_size; /* size of the overflow array */
	int dirty_bit; /* index in dirty_notify bitmap, -1 if none */
	u32 client_key;
	u8 num_cmdqs;  /* number of cmdq records in use */
	u8 num_cmplqs; /* number of cmplq records in use */
	/* Both set/read on the bulksvc thread only at MMU_SYNC_DRAIN.
	 * shutting_down: rejects further user-cmd dispatch.
	 * mm_releasing: per-tracker completion callbacks skip the cmplq post.
	 */
	bool shutting_down;
	bool mm_releasing;
	u32 eph_mr_deferred_count;
	/*
	 * Deferred free list for ephemeral MRs. Serviced at the end of
	 * poll_single_client(). Bulksvc service thread is the sole producer
	 * (in on_rdma_va_complete) and sole consumer (end of poll_single_client),
	 * so no locking is needed.
	 */
	struct list_head eph_mr_deferred_free;
	struct hfi2_bulksvc *svc;
	/*
	 * DMS lane that polls this client and holds its DMS state, events,
	 * pin lists and verbs QPs.  Set before USER_INFO_ADD, then fixed.
	 */
	u32 lane;
	u32 eph_mr_drain_rate;

	/* CL1: dispatch-time lookup state. */
	/* shared overflow stack for all completions */
	struct hfi2_bulksvc_overflow_entry *completion_overflows ____cacheline_aligned_in_smp;
	struct hfi2_bulksvc_cntr **cntr_blocks; /* demand-allocated 64-cntr blocks */
	u64 num_cntrs; /* number of counters in use */
	/*
	 * Counters whose trigger rings hold deferred fireable entries.
	 * One bit per counter id; worker-thread-only (event_workq), no
	 * locking. Replaces an O(num_cntrs) scan per poll pass.
	 */
	unsigned long *trig_dirty_bitmap;
	/*
	 * Non-owning command-dispatch indices over the MR/access lists
	 * below.  Entries are stored at insert (list_add) and erased at
	 * unlink (list_del) -- never from async teardown callbacks, which
	 * may run after the same key has been re-registered.  Ownership
	 * stays with the kref/lists.
	 */
	struct xarray mr_by_handle;
	struct xarray access_by_key;

	/* CL2: process-context command handoff (lock taken every pass). */
	/* list of hfi2_bulksvc_userctxt_cmd_entry */
	struct list_head userctxt_cmdq ____cacheline_aligned_in_smp;
	struct mutex userctxt_cmdq_lock;

	/*
	 * CL3: registration/lifetime. refcount is also get/put atomically
	 * per DMS op, so this line is written on the data path.
	 */
	struct mutex queue_records_lock ____cacheline_aligned_in_smp;
	// Held by the user file handle, as well as active dms ops
	struct kref refcount;
	u32 next_user_mr_handle;
	/*
	 * Latched when an xa_store into the matching index fails.  Until
	 * then every live record is indexed, so an xa_load miss is final
	 * and lookups never scan the lists.
	 */
	bool mr_index_incomplete;
	bool access_index_incomplete;
	struct list_head list_entry;
	/* Teardown/debug enumeration; command dispatch uses the xarrays. */
	struct list_head user_mr_list;
	struct list_head active_access_list;

	/* Hot queue arrays: one cacheline per record; slot memory via ->backing. */
	struct hfi2_bulksvc_queue_record
		cmdq_records[BULKSVC_USER_MAX_NUM_CMDQS] ____cacheline_aligned_in_smp;
	struct hfi2_bulksvc_queue_record
		cmplq_records[BULKSVC_USER_MAX_NUM_CMPLQS];

	/* Cold: counters, registration, teardown. */
	struct bulksvc_cntr_page cntr_pages[BULKSVC_USER_MAX_NUM_CNTR_PAGES];
	u8 num_cntr_pages; /* number of mempages of counters in use */

	struct mmu_rb_handler *mmu;

	struct mm_struct *user_mm;

	/* Phase B work; embedded so it outlives the rest of user_info. */
	struct work_struct deferred_destroy_work;

	u32 eph_mr_create_fail;
	u32 eph_mr_pin_fail;
	u32 eph_mr_dispatch_fail;
};

/* Counter-id -> record through the demand-allocated block directory.
 * Callers must have validated id < num_cntrs (the owning block is then
 * guaranteed allocated).
 */
static inline struct hfi2_bulksvc_cntr *
bulksvc_cntr_at(struct hfi2_bulksvc_user_info *info, u64 cntr_id)
{
	return &info->cntr_blocks[cntr_id >> BULKSVC_CNTR_BLOCK_SHIFT]
			[cntr_id & BULKSVC_CNTR_BLOCK_MASK];
}

// Must be called from a user context
struct hfi2_bulksvc_user_info* hfi2_bulksvc_user_info_create(struct hfi2_filedata *fdata);

void hfi2_bulksvc_user_info_get(struct hfi2_bulksvc_user_info* info);
void hfi2_bulksvc_user_info_put(struct hfi2_bulksvc_user_info* info);
void hfi2_bulksvc_user_info_abort(struct hfi2_bulksvc_user_info *info);
void hfi2_bulksvc_user_info_begin_teardown(struct hfi2_bulksvc_user_info *info);

/*
 * Drop HOST hfi2_mr refs and NULL the pointers.  Lane worker only (or
 * with lanes stopped); caller must have cancelled all trackers
 * referencing these MRs first.
 */
void hfi2_bulksvc_user_info_drop_host_mrs(struct hfi2_bulksvc_user_info *info);

/* Cancel @info's initiator transfers, by local MR owner. */
void hfi2_bulksvc_user_info_cancel_dms_trackers(
	struct hfi2_bulksvc_user_info *info);

void hfi2_bulksvc_user_info_drain_ephemeral_mrs(
	struct hfi2_bulksvc_user_info *info);

struct hfi2_bulksvc_lane;
int hfi2_bulksvc_poll_user_cmds(struct hfi2_bulksvc_lane *l);
bool bulksvc_user_diag_access(void *ctx, u32 access_key);
void bulksvc_user_info_destroy(struct hfi2_bulksvc_user_info* info);
void hfi2_bulksvc_queue_destroy(struct hfi2_bulksvc_queue_record *rec);

static inline bool hfi2_bulksvc_mr_span_ok(u64 vaddr, u64 len)
{
	u64 end;

	return !check_add_overflow(vaddr, len, &end) &&
	       end <= ALIGN_DOWN(U64_MAX, PAGE_SIZE) &&
	       PFN_UP(end) - PFN_DOWN(vaddr) <= UINT_MAX;
}

static inline u64 hfi2_bulksvc_get_caps(void)
{
	u64 caps = HFI2_BULKSVC_CAPS_ALL;

	if (!HFI2_CAP_IS_KSET(DMABUF))
		caps &= ~HFI2_BULKSVC_CAP_DMA_BUF;

	return caps;
}

#endif /* DEF_HFI2_BULKSVC_USER_H */
