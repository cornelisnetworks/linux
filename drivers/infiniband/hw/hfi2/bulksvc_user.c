#include "bulksvc_user.h"
#include "bulksvc_verbs.h" // to call post_send handler
#include "bulksvc.h"
#include "dms.h"
#include "mem_region.h"
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/ratelimit.h>
#include <linux/sched/mm.h>
#include <linux/mmap_lock.h>
#include <linux/libfdt_env.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define BULKSVC_EPH_MR_DRAIN_MIN  16U
#define BULKSVC_EPH_MR_DRAIN_STEP 16U

/*
 * The record is exactly the worker's per-visit polling set: one cacheline.
 * The userspace-shared head/tail atomics live in a separate vmalloc_user
 * control page; the slot's backing memory hangs off ->backing.
 */
static_assert(offsetof(struct hfi2_bulksvc_queue_record, backing) +
	      sizeof(void *) <= SMP_CACHE_BYTES,
	      "queue_record polling fields must fit in one cache line");
static_assert(sizeof(struct hfi2_bulksvc_queue_record) == SMP_CACHE_BYTES,
	      "queue_record must be exactly one cache line");

static_assert(offsetof(struct hfi2_bulksvc_user_info, eph_mr_drain_rate) +
	      sizeof(u32) <= SMP_CACHE_BYTES,
	      "user_info every-pass poll fields must fit in one cache line");
#ifdef CONFIG_SMP
static_assert(offsetof(struct hfi2_bulksvc_user_info, completion_overflows) ==
	      SMP_CACHE_BYTES,
	      "user_info dispatch-lookup group must start cache line 1");
/* Debug lock variants grow the xarray, mutex and spinlock members. */
#if !defined(CONFIG_DEBUG_MUTEXES) && !defined(CONFIG_DEBUG_LOCK_ALLOC) &&  !defined(CONFIG_DEBUG_SPINLOCK)
static_assert(offsetof(struct hfi2_bulksvc_user_info, userctxt_cmdq) ==
	      2 * SMP_CACHE_BYTES,
	      "user_info handoff group must start cache line 2");
static_assert(offsetof(struct hfi2_bulksvc_user_info, queue_records_lock) ==
	      3 * SMP_CACHE_BYTES,
	      "user_info lifetime group must start cache line 3");
static_assert(offsetof(struct hfi2_bulksvc_user_info, cmdq_records) ==
	      5 * SMP_CACHE_BYTES,
	      "user_info queue arrays must start cache line 5");
#endif
#endif

// mr_record management
static struct hfi2_bulksvc_user_mr_record *
user_mr_record_create_metadata(struct hfi2_bulksvc_user_info *user_info,
			       uintptr_t vaddr, u64 len, u64 flags,
			       u32 hmem_iface, u32 hmem_device,
			       union hfi2_bulksvc_userctxt_cmd_data *cmd_data);
int hfi2_bulksvc_user_pin_range(struct hfi2_bulksvc *svc, void *mr,
			       unsigned int from_page,
			       unsigned int npages,
			       bool writable);
static void user_mr_record_destroy(struct hfi2_bulksvc_user_mr_record *mr_record);
static void user_mr_record_get(struct hfi2_bulksvc_user_mr_record *mr_record);
static void user_mr_record_put(struct hfi2_bulksvc_user_mr_record *mr_record);
static struct hfi2_bulksvc_user_mr_record *
lookup_user_mr_record(struct hfi2_bulksvc_user_info *user_info,
		 u32 user_handle);
static int validate_mr_access(struct hfi2_bulksvc_user_mr_record *mr, u64 offset, u32 len);
static int user_pin_range(void *ctx, unsigned int from_page,
			  unsigned int npages, bool writable);
static int user_mr_proactive_pin_range(
	struct hfi2_bulksvc *svc,
	struct hfi2_bulksvc_proactive_pin_entry *entry,
	unsigned int from_page, unsigned int npages,
	bool writable);
static void user_mr_promote(void *ctx);
static int ephemeral_pin_range(void *ctx, unsigned int from_page,
			       unsigned int npages, bool writable);
static int ephemeral_mr_proactive_pin_range(
	struct hfi2_bulksvc *svc,
	struct hfi2_bulksvc_proactive_pin_entry *entry,
	unsigned int from_page, unsigned int npages,
	bool writable);
static void ephemeral_mr_promote(void *ctx);
static struct hfi2_bulksvc_ephemeral_mr *
ephemeral_mr_create_va(struct hfi2_bulksvc_user_info *user_info,
		      uintptr_t vaddr, u64 len);
static void ephemeral_mr_put(struct hfi2_bulksvc_ephemeral_mr *eph_mr);
static void ephemeral_mr_destroy(struct hfi2_bulksvc_ephemeral_mr *eph_mr);
static u32 ephemeral_mr_drain_deferred(struct hfi2_bulksvc_user_info *user_info,
				       u32 max_drain);

static inline struct hfi2_bulksvc_user_mr_record_ext *
user_mr_record_ext(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	return container_of(mr_record, struct hfi2_bulksvc_user_mr_record_ext,
			    mr_record);
}

// For use as dms function pointers
static int dms_mr_host_memcpy(struct hfi2_dms_mr *mr, u64 offset, u64 size,
			      void *data, const bool is_read);
static int dms_ephemeral_mr_host_memcpy(struct hfi2_dms_mr *mr,
				       u64 offset, u64 size,
				       void *data, const bool is_read);
static int dms_mr_dmabuf_memcpy(struct hfi2_dms_mr *mr, u64 offset, u64 size,
				void *data, const bool is_read);
static int dms_mr_host_pio_write(struct hfi2_dms_mr *mr, u64 offset, u64 len,
				 void __iomem *dest);
static int dms_ephemeral_mr_host_pio_write(struct hfi2_dms_mr *mr, u64 offset,
					   u64 len, void __iomem *dest);

/* Single-MR user host copy: dispatch to the per-MR-type concrete mover
 * bound on the dms_mr (host pages / dmabuf vmap / nvidia).  provider_ctx
 * is &mr_record->dms_mr.
 */
static int user_mr_memcpy(struct hfi2_dms_page_provider const *pp,
			  u64 byte_offset, u64 size, void *data, bool is_read)
{
	struct hfi2_dms_mr *dms_mr;
	struct hfi2_bulksvc_user_mr_record *mr_record;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx))
		return -EFAULT;
	dms_mr = pp->provider_ctx;
	mr_record = container_of(dms_mr, struct hfi2_bulksvc_user_mr_record,
				 dms_mr);
	if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF) {
		return dms_mr_dmabuf_memcpy(dms_mr, byte_offset, size, data,
					    is_read);
	}
	return dms_mr_host_memcpy(dms_mr, byte_offset, size, data, is_read);
}

/* Tidset runs for a user MR: one run, demand-pinned by user_pin_range. */
static int user_mr_get_runs(struct hfi2_dms_page_provider const *pp,
			    u64 byte_offset, u64 max_bytes, bool writable,
			    struct hfi2_dms_run *runs, u32 max_runs)
{
	return hfi2_dms_single_mr_get_runs(pp, byte_offset, max_bytes, writable,
					   runs, max_runs, user_pin_range);
}

/*
 * Single-MR user pio_write; provider_ctx is &mr_record->dms_mr.  Host pages
 * are written straight to PIO.  dma-buf memory, NVIDIA included, has no
 * direct CPU path here, so it is copied through user_mr_memcpy() in bounce
 * chunks.
 */
static int user_mr_pio_write(struct hfi2_dms_page_provider const *pp,
			     u64 byte_offset, u64 len, void __iomem *dest)
{
	struct hfi2_bulksvc_user_mr_record *mr_record;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx))
		return -EFAULT;
	mr_record = container_of((struct hfi2_dms_mr *)pp->provider_ctx,
				 struct hfi2_bulksvc_user_mr_record, dms_mr);
	if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF)
		return hfi2_dms_pio_write_bounce(pp, byte_offset, len, dest);

	return dms_mr_host_pio_write(pp->provider_ctx, byte_offset, len, dest);
}

static bool user_mr_is_p2p_dmabuf(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	return mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF &&
		(
		 (mr_record->mem_region.fixup_mapping_type ==
		  HFI2_BULKSVC_FIXUP_CPU_MAPPING_VMAP &&
		  mr_record->mem_region.fixup_mapping.vmap.is_iomem));
}

static inline struct hfi2_dms_page_provider
user_mr_page_provider(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	return (struct hfi2_dms_page_provider) {
		.pin_range = user_pin_range,
		.next_src_run = hfi2_dms_single_mr_next_src_run,
		.memcpy = user_mr_memcpy,
		.pio_write = user_mr_pio_write,
		.get_runs = user_mr_get_runs,
		.resolve_start = hfi2_dms_single_mr_resolve_start,
		.promote = user_mr_promote,
		.owner = hfi2_dms_single_mr_owner,
		.provider_ctx = &mr_record->dms_mr,
		.length = mr_record->dms_mr.user.len,
		.p2p_flush = user_mr_is_p2p_dmabuf(mr_record),
	};
}

/* Single-MR ephemeral host copy: the demand-pinning host mover keyed on
 * the provider's dms_mr (provider_ctx is &eph_mr->dms_mr).
 */
static int ephemeral_mr_memcpy(struct hfi2_dms_page_provider const *pp,
			       u64 byte_offset, u64 size, void *data,
			       bool is_read)
{
	if (WARN_ON_ONCE(!pp || !pp->provider_ctx))
		return -EFAULT;
	return dms_ephemeral_mr_host_memcpy(pp->provider_ctx, byte_offset,
					    size, data, is_read);
}

/* Tidset runs for an ephemeral MR: one run, demand-pinned by
 * ephemeral_pin_range (which also publishes the dma_list alias).
 */
static int ephemeral_mr_get_runs(struct hfi2_dms_page_provider const *pp,
				 u64 byte_offset, u64 max_bytes, bool writable,
				 struct hfi2_dms_run *runs, u32 max_runs)
{
	return hfi2_dms_single_mr_get_runs(pp, byte_offset, max_bytes, writable,
					   runs, max_runs, ephemeral_pin_range);
}

/* Single-MR ephemeral host direct PIO write; provider_ctx is &eph_mr->dms_mr. */
static int ephemeral_mr_pio_write(struct hfi2_dms_page_provider const *pp,
				  u64 byte_offset, u64 len, void __iomem *dest)
{
	if (WARN_ON_ONCE(!pp || !pp->provider_ctx))
		return -EFAULT;
	return dms_ephemeral_mr_host_pio_write(pp->provider_ctx, byte_offset,
					       len, dest);
}

static inline struct hfi2_dms_page_provider
ephemeral_mr_page_provider(struct hfi2_bulksvc_ephemeral_mr *eph_mr)
{
	return (struct hfi2_dms_page_provider) {
		.pin_range = ephemeral_pin_range,
		.next_src_run = hfi2_dms_single_mr_next_src_run,
		.memcpy = ephemeral_mr_memcpy,
		.pio_write = ephemeral_mr_pio_write,
		.get_runs = ephemeral_mr_get_runs,
		.resolve_start = hfi2_dms_single_mr_resolve_start,
		.promote = ephemeral_mr_promote,
		.owner = hfi2_dms_single_mr_owner,
		.provider_ctx = &eph_mr->dms_mr,
		.length = eph_mr->dms_mr.user.len,
	};
}

// mr_access_record management
static struct hfi2_bulksvc_user_mr_access_record *
user_mr_access_record_create_and_insert(struct hfi2_bulksvc_user_info *user_info,
		 u32 access_key, u64 app_context, u32 cmplq_id,
		 u64 notify_app_context, u32 notify_cmpl_id, __u64 notify_flags,
		 struct hfi2_bulksvc_user_mr_record *mr_record);
static void user_mr_access_record_destroy(struct hfi2_bulksvc_user_mr_access_record *access_record);
static void user_mr_access_record_destroy_and_remove(struct hfi2_bulksvc_user_mr_access_record *access_record);
static struct hfi2_bulksvc_user_mr_access_record *
lookup_user_mr_access_record(struct hfi2_bulksvc_user_info *user_info,
		 u32 access_key);

static void pin_entry_promote(struct hfi2_bulksvc_proactive_pin_entry *entry)
{
	struct hfi2_bulksvc_pin_lists *pins;

	if (!entry || !entry->on_speculative_pin_list ||
	    !entry->owner || !entry->owner->svc)
		return;

	pins = hfi2_bulksvc_user_pins(entry->owner);
	list_move_tail(&entry->node, &pins->pin_active);
	entry->on_speculative_pin_list = false;
	entry->on_active_pin_list = true;
	pins->speculative_count--;
	pins->active_count++;
}

static void user_mr_promote(void *ctx)
{
	struct hfi2_dms_mr *dms_mr = ctx;
	struct hfi2_bulksvc_user_mr_record *mr_record;

	if (!dms_mr)
		return;
	mr_record = container_of(dms_mr, struct hfi2_bulksvc_user_mr_record,
				 dms_mr);
	pin_entry_promote(&user_mr_record_ext(mr_record)->pin_entry);
}

// Fire a command
static void bulksvc_on_user_cmd(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd const * const cmd,
	union hfi2_bulksvc_userctxt_cmd_data *userctxt_data);

static struct hfi2_bulksvc_queue_record *
get_cmplq_record(struct hfi2_bulksvc *svc,
		 struct hfi2_bulksvc_user_info *user_info, u32 cmplq_id);

static inline u8 _port_to_port_idx(struct hfi2_bulksvc *svc, u8 port)
{
	return svc->port_lut[port & HFI2_BULKSVC_CMD_FLAG_PORT_MASK];
}

struct hfi2_bulksvc_user_info* hfi2_bulksvc_user_info_create(struct hfi2_filedata *fd)
{
	if (!fd || !fd->dd || !fd->dd->bulksvc ||
	    !hfi2_bulksvc_is_opa(fd->dd->bulksvc))
		return NULL;

	pr_debug("hfi2: bulksvc enabled, creating user info\n");

	/* Allocate on the bulksvc thread's NUMA node. */
	int const node = fd->dd->node;
	struct hfi2_bulksvc_user_info *bulksvc_user_info =
		kzalloc_node(sizeof(*bulksvc_user_info), GFP_KERNEL, node);
	if (!bulksvc_user_info)
		return NULL;

	/* Counter storage is demand-allocated in blocks; only the small
	 * directory and the trigger-dirty bitmap are eager.
	 */
	bulksvc_user_info->cntr_blocks =
		kcalloc_node(BULKSVC_CNTR_NUM_BLOCKS,
			     sizeof(*bulksvc_user_info->cntr_blocks),
			     GFP_KERNEL, node);
	if (!bulksvc_user_info->cntr_blocks) {
		kfree(bulksvc_user_info);
		return NULL;
	}
	bulksvc_user_info->trig_dirty_bitmap =
		kcalloc_node(BITS_TO_LONGS(BULKSVC_USER_MAX_NUM_CNTRS),
			     sizeof(unsigned long), GFP_KERNEL, node);
	if (!bulksvc_user_info->trig_dirty_bitmap) {
		kfree(bulksvc_user_info->cntr_blocks);
		kfree(bulksvc_user_info);
		return NULL;
	}

	u64 const max_cmds_per_queue = (1 << bulksvc_user_queue_size_pages_log2) * PAGE_SIZE / CACHELINE_SIZE;

	INIT_LIST_HEAD(&bulksvc_user_info->userctxt_cmdq);
	mutex_init(&bulksvc_user_info->userctxt_cmdq_lock);

	u64 num_overflow = 2 * max(BULKSVC_USER_MAX_NUM_CMDQS, BULKSVC_USER_MAX_NUM_CMPLQS) * max_cmds_per_queue;
	struct hfi2_bulksvc_overflow_entry *overflows =
		kmalloc_array_node(num_overflow, sizeof(*overflows),
				   GFP_KERNEL, node);
	if (!overflows) {
		kfree(bulksvc_user_info->trig_dirty_bitmap);
		kfree(bulksvc_user_info->cntr_blocks);
		kfree(bulksvc_user_info);
		return NULL;
	}

	bulksvc_user_info->completion_overflows_size = num_overflow;
	bulksvc_user_info->completion_overflows = overflows;

	bulksvc_user_info->svc = fd->dd->bulksvc;

	/* freed when user context is freed */
	int rc = init_bulksvc_mmu(bulksvc_user_info);
	if (rc) {
		dd_dev_err(fd->dd,
				"Failed to create bulsvc pinnned mem handler %d\n",
				rc);
		kfree(bulksvc_user_info->completion_overflows);
		kfree(bulksvc_user_info->trig_dirty_bitmap);
		kfree(bulksvc_user_info->cntr_blocks);
		kfree(bulksvc_user_info);
		return NULL;
	}

	mutex_init(&bulksvc_user_info->queue_records_lock);

	bulksvc_user_info->num_cmplqs = 0;
	bulksvc_user_info->num_cmdqs = 0;
	bulksvc_user_info->num_cntrs = 0;
	bulksvc_user_info->max_inflight = num_overflow + max_cmds_per_queue;

	bulksvc_user_info->client_key = atomic_inc_return(&fd->dd->bulksvc->last_client_key);
	pr_debug("assigned client key %u\n", bulksvc_user_info->client_key);

	mmgrab(current->mm);
	bulksvc_user_info->user_mm = current->mm;

	bulksvc_user_info->next_user_mr_handle = 0;

	INIT_LIST_HEAD(&bulksvc_user_info->active_access_list);
	INIT_LIST_HEAD(&bulksvc_user_info->user_mr_list);
	xa_init(&bulksvc_user_info->mr_by_handle);
	xa_init(&bulksvc_user_info->access_by_key);
	INIT_LIST_HEAD(&bulksvc_user_info->eph_mr_deferred_free);
	bulksvc_user_info->eph_mr_deferred_count = 0;
	bulksvc_user_info->eph_mr_drain_rate = BULKSVC_EPH_MR_DRAIN_MIN;

	bulksvc_user_info->dirty_bit = -1;
	bulksvc_user_info->lane = HFI2_BULKSVC_PRIMARY_LANE;

	kref_init(&bulksvc_user_info->refcount);

	return bulksvc_user_info;
}

static void bulksvc_user_info_event_release(struct kref *ref)
{
	struct hfi2_bulksvc_user_info *info;

	info = container_of(ref, struct hfi2_bulksvc_user_info, refcount);
	struct hfi2_bulksvc_event_entry *event_entry;

	event_entry = kzalloc(sizeof(*event_entry), GFP_KERNEL);
	if (!event_entry) {
		pr_err("Failed to allocate bulksvc event entry, leaking user info\n");
		return;
	}
	event_entry->event.type = BULKSVC_EVENT_TYPE_USER_INFO_RELEASE;
	event_entry->event.user_info = info;
	if (hfi2_bulksvc_enqueue_user_event(info, event_entry)) {
		pr_err("Failed to enqueue bulksvc user info release event, leaking user info\n");
		kfree(event_entry);
		return;
	}

}

/*
 * DMS completion-cookie overlays.  Each union aliases the 64-byte
 * `union hfi2_dms_completion_cookie` (the `dms` member) with an
 * anonymous struct of per-site fields.  Instantiate as
 * `= { .dms = {{0}} }` then assign named fields — the explicit `.dms`
 * designator picks the full-width member as the active union subobject
 * so modern GCC zero-fills all 64 bytes.  Recover in callbacks via
 * `container_of(cookie, union foo, dms)`.
 */

union dma_access_teardown_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc_user_mr_access_record *access_record;
	};
};
static_assert(sizeof(union dma_access_teardown_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_access_teardown_complete(union hfi2_dms_completion_cookie *cookie, int status);

static void bulksvc_user_info_free(struct hfi2_bulksvc_user_info *info)
{
	struct hfi2_bulksvc *svc = info->svc;

	if (info->mmu)
		uninit_bulksvc_mmu(info);

	/* Free trigger-ring storage, then the counter blocks themselves. */
	for (u64 i = 0; i < info->num_cntrs; ++i) {
		struct hfi2_bulksvc_cntr *cntr = bulksvc_cntr_at(info, i);

		kfree(cntr->trig_ring.buf);
		cntr->trig_ring.buf = NULL;
		cntr->trig_ring.cap = 0;
		cntr->trig_ring.head = 0;
		cntr->trig_ring.tail = 0;
	}
	info->num_cntrs = 0;
	for (u32 b = 0; b < BULKSVC_CNTR_NUM_BLOCKS; ++b)
		kfree(info->cntr_blocks[b]);
	kfree(info->cntr_blocks);
	kfree(info->trig_dirty_bitmap);

	for (u8 i = 0; i < info->num_cntr_pages; ++i) {
	if (info->cntr_pages[i].kaddr) {
		vfree(info->cntr_pages[i].kaddr);
		info->cntr_pages[i].kaddr = NULL;
	}
	}
	info->num_cntr_pages = 0;

	for (int i = 0; i < BULKSVC_USER_MAX_NUM_CMPLQS; i++)
		hfi2_bulksvc_queue_destroy(&info->cmplq_records[i]);
	for (int i = 0; i < BULKSVC_USER_MAX_NUM_CMDQS; i++)
		hfi2_bulksvc_queue_destroy(&info->cmdq_records[i]);

	mutex_lock(&info->userctxt_cmdq_lock);
	struct hfi2_bulksvc_userctxt_cmd_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &info->userctxt_cmdq, node) {
		list_del(&entry->node);
		dd_dev_dbg(svc->dd, "Sync command unhandled at user info teardown.  user %d, op %d\n", info->client_key, entry->cmd.hdr.op);
		if (entry->cmd.hdr.op == HFI2_BULKSVC_CMD_MR_OPEN &&
			entry->cmd.payld->mr_open.hmem_iface == HFI2_HFISVC_HMEM_IFACE_DMABUF &&
			entry->data.dmabuf_open.dmabuf && !IS_ERR(entry->data.dmabuf_open.dmabuf)) {
			dma_buf_put(entry->data.dmabuf_open.dmabuf);
		}
		kfree(entry);
	}
	mutex_unlock(&info->userctxt_cmdq_lock);

	kfree(info->completion_overflows);

	/*
	 * All MR releases and access teardown callbacks that consult the
	 * indices have drained by this point (pending destroys are
	 * counted); the xarrays hold only non-owning pointers.
	 */
	xa_destroy(&info->mr_by_handle);
	xa_destroy(&info->access_by_key);

	mmdrop(info->user_mm);
	info->user_mm = NULL;

	dd_dev_dbg(svc->dd,
		   "%s:%d:%s() bulksvc: Destroyed user info %u\n",
		   __FILENAME__, __LINE__, __func__, info->client_key);

	kfree(info);
}

/*
 * Phase A on the bulksvc thread drained DMS accesses and released the key.
 * Run the slow MMU unregister on system_unbound_wq so its SRCU wait does
 * not serialize other clients' release drains on the bulksvc thread.
 */
static void deferred_user_info_destroy_work(struct work_struct *work)
{
	struct hfi2_bulksvc_user_info *info =
		container_of(work, struct hfi2_bulksvc_user_info,
			     deferred_destroy_work);
	struct hfi2_bulksvc *svc = info->svc;

	bulksvc_user_info_free(info);
	if (atomic_dec_and_test(&svc->pending_user_info_destroys))
		wake_up(&svc->pending_user_info_destroys_wq);
}

void bulksvc_user_info_destroy(struct hfi2_bulksvc_user_info* info)
{
	pr_debug("destroying user info\n");

	struct hfi2_bulksvc_user_mr_access_record *access_record;
	struct hfi2_bulksvc_user_mr_access_record *tmp_access;

	list_for_each_entry_safe(access_record, tmp_access, &info->active_access_list, list_entry) {
		dd_dev_dbg(info->svc->dd, "%s:%d:%s() bulksvc: Lingering user MR access %u: %p \n",
			   __FILENAME__, __LINE__, __func__, access_record->access_key, access_record);

		list_del_init(&access_record->list_entry);
		xa_cmpxchg(&info->access_by_key, access_record->access_key,
			   access_record, NULL, GFP_ATOMIC);
		access_record->user_info = NULL;

		u32 saved_access_key = access_record->access_key;
		u32 saved_client_key = access_record->client_key;
		union dma_access_teardown_cookie tc = { .dms = {{0}} };
		tc.access_record = access_record;
		int rc = hfi2_dms_unregister_access(hfi2_bulksvc_user_dms(info),
			(union hfi2_dms_key){.access = saved_access_key, .client = saved_client_key},
			(struct hfi2_dms_completion) {
				.fn = on_access_teardown_complete,
				.cookie = tc.dms,
			});
		if (rc == -EALREADY) {
			/*
			 * Prior disable callback already owns cleanup.
			 * Do NOT destroy -- would double-free.
			 */
			dd_dev_dbg(info->svc->dd,
				   "bulksvc: access %u unregister already in progress\n",
				   saved_access_key);
		} else if (rc < 0) {
			dd_dev_dbg(info->svc->dd,
				   "%s:%d:%s() bulksvc: Failed to unregister lingering user MR access %u: %d\n",
				   __FILENAME__, __LINE__, __func__,
				   saved_access_key, rc);
			user_mr_access_record_destroy(access_record);
		}
		/* rc == 0: callback owns cleanup */
	}

	/* Client-key release force-cancels the transfers this client
	 * serves as a target, which fires deferred access teardown
	 * callbacks.  Those callbacks drop access-owned MR references
	 * and may invoke hfi2_mmu_rb_release() -- so the MR/MMU
	 * substrate must still be alive at this point.
	 *
	 * Initiator transfers each hold a user_info reference, so none are
	 * in flight here; only the target side needs cancelling.
	 */
	hfi2_dms_release_client_key(hfi2_bulksvc_user_dms(info), info->client_key);

	/* Now safe to drop remaining MR refs -- all access-owned refs drained above */
	struct hfi2_bulksvc_user_mr_record *mr_record;
	struct hfi2_bulksvc_user_mr_record *tmp_mr;
	list_for_each_entry_safe(mr_record, tmp_mr, &info->user_mr_list, list_entry) {
		dd_dev_dbg(info->svc->dd, "%s:%d:%s() bulksvc: Lingering user MR %u: %p \n",
			   __FILENAME__, __LINE__, __func__, mr_record->user_handle, mr_record);
		user_mr_record_put(mr_record);
	}

	/* Drain any pending ephemeral MR teardowns on the bulksvc thread
	 * before Phase B; this releases hfi2_mem_region refs which may
	 * invoke hfi2_mmu_rb_release callbacks, so MMU substrate must
	 * still be alive.  Phase B (deferred_user_info_destroy_work) is
	 * what tears down the MMU.
	 */
	if (!list_empty(&info->eph_mr_deferred_free))
		ephemeral_mr_drain_deferred(info, 0);

	/* Phase B: defer the slow tail off the bulksvc thread.
	 * pending_user_info_destroys is incremented by the
	 * USER_INFO_RELEASE handler before calling this function and
	 * decremented at the tail of deferred_user_info_destroy_work,
	 * so quiesce_thread's wait_event sees a balanced counter.
	 */
	INIT_WORK(&info->deferred_destroy_work, deferred_user_info_destroy_work);
	queue_work(system_unbound_wq, &info->deferred_destroy_work);
}

void hfi2_bulksvc_queue_destroy(struct hfi2_bulksvc_queue_record *rec)
{
	if (rec->queue_buf_magic) {
		vunmap(rec->queue_buf_magic);
		rec->queue_buf_magic = NULL;
	}
	if (rec->backing) {
		if (rec->backing->ctrl) {
			vfree(rec->backing->ctrl);
			rec->backing->ctrl = NULL;
		}
		if (rec->backing->queue_buf) {
			vfree(rec->backing->queue_buf);
			rec->backing->queue_buf = NULL;
		}
		kfree(rec->backing);
		rec->backing = NULL;
	}
	rec->head = NULL;
	rec->tail = NULL;
}

void hfi2_bulksvc_user_info_drop_host_mrs(struct hfi2_bulksvc_user_info *info)
{
	struct hfi2_bulksvc_user_mr_record_ext *ext;
	struct hfi2_bulksvc_user_mr_record *mr_record;

	if (!info)
		return;

	list_for_each_entry(mr_record, &info->user_mr_list, list_entry) {
		if (mr_record->mr_type != HFI2_BULKSVC_MR_TYPE_HOST)
			continue;
		if (!mr_record->mem_region.hfi2_mr)
			continue;
		ext = user_mr_record_ext(mr_record);
		/* The proactive pin entry borrows hfi2_mr. */
		hfi2_bulksvc_pin_entry_unlink(hfi2_bulksvc_user_pins(info),
					      &ext->pin_entry);
		ext->pin_entry.hfi2_mr = NULL;
		mr_record->dms_mr.dma_list = NULL;
		hfi2_mem_region_put(mr_record->mem_region.hfi2_mr);
		mr_record->mem_region.hfi2_mr = NULL;
	}
}

void hfi2_bulksvc_user_info_cancel_dms_trackers(
	struct hfi2_bulksvc_user_info *info)
{
	if (!info || !info->svc)
		return;

	hfi2_dms_cancel_trackers_for_owner(hfi2_bulksvc_user_dms(info), info);
}

void hfi2_bulksvc_user_info_drain_ephemeral_mrs(
	struct hfi2_bulksvc_user_info *info)
{
	if (!list_empty(&info->eph_mr_deferred_free))
		ephemeral_mr_drain_deferred(info, 0);
}

void hfi2_bulksvc_user_info_get(struct hfi2_bulksvc_user_info* info)
{
	kref_get(&info->refcount);
}
void hfi2_bulksvc_user_info_put(struct hfi2_bulksvc_user_info* info)
{
	kref_put(&info->refcount, bulksvc_user_info_event_release);
}

/* Only for private clients before USER_INFO_ADD, with no reserved dirty bit. */
void hfi2_bulksvc_user_info_abort(struct hfi2_bulksvc_user_info *info)
{
	bulksvc_user_info_free(info);
}

/**
 * hfi2_bulksvc_user_info_begin_teardown - Invalidate command queues on file close
 * @info: The user info structure to tear down
 *
 * Synchronously invalidates command queues to prevent worker thread from
 * reading user memory after process exit. Must be called before
 * hfi2_bulksvc_user_info_put().
 */
void hfi2_bulksvc_user_info_begin_teardown(struct hfi2_bulksvc_user_info *info)
{
	int i;

	if (!info)
		return;

	if (info->svc) {
		WRITE_ONCE(info->svc->dirty_notify.client_map[info->dirty_bit], NULL);
		clear_bit(info->dirty_bit, info->svc->dirty_notify.bitmap);
	}

	/* Invalidate all command queues to stop worker thread.  Release pairs
	 * with smp_load_acquire(&rec->active) in poll_single_client(), matching
	 * the publish/un-publish semantics on the ioctl release path.
	 */
	for (i = 0; i < BULKSVC_USER_MAX_NUM_CMDQS; i++) {
		if (info->cmdq_records[i].active)
			smp_store_release(&info->cmdq_records[i].active, false);
	}

	/* Clear pending sync commands from ioctl path */
	mutex_lock(&info->userctxt_cmdq_lock);
	struct hfi2_bulksvc_userctxt_cmd_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &info->userctxt_cmdq, node) {
		list_del(&entry->node);
		/* Release dma_buf if this is a DMABUF MR_OPEN command */
		if (entry->cmd.hdr.op == HFI2_BULKSVC_CMD_MR_OPEN &&
		    entry->cmd.payld->mr_open.hmem_iface == HFI2_HFISVC_HMEM_IFACE_DMABUF &&
		    entry->data.dmabuf_open.dmabuf && !IS_ERR(entry->data.dmabuf_open.dmabuf)) {
			dma_buf_put(entry->data.dmabuf_open.dmabuf);
		}
		kfree(entry);
	}
	mutex_unlock(&info->userctxt_cmdq_lock);
}

static struct hfi2_bulksvc_queue_record *
get_cmplq_record(struct hfi2_bulksvc *svc,
		 struct hfi2_bulksvc_user_info *user_info, u32 cmplq_id)
{
	struct hfi2_bulksvc_queue_record *cmplq_record;

	if (!user_info)
		return NULL;

	if (cmplq_id >= user_info->num_cmplqs) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid cmplq id %u\n",
			   __FILENAME__, __LINE__, __func__, cmplq_id);
		return NULL;
	}

	cmplq_record = &user_info->cmplq_records[cmplq_id];
	if (!cmplq_record->active) {
		dd_dev_err(svc->dd, "%s:%d:%s() cmplq record %u not active\n",
			   __FILENAME__, __LINE__, __func__, cmplq_id);
		return NULL;
	}
	return cmplq_record;
}

static struct hfi2_bulksvc_cntr *
get_cntr(struct hfi2_bulksvc *svc,
		struct hfi2_bulksvc_user_info *user_info, u32 cntr_id)
{
	BUILD_BUG_ON(CNTR_VALUE_SIZE % 8 != 0);
	BUILD_BUG_ON(CNTR_SLOT_SIZE % 8 != 0);
	struct hfi2_bulksvc_cntr *cntr;
	if (cntr_id >= user_info->num_cntrs) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid cntr id %u\n",
			   __FILENAME__, __LINE__, __func__, cntr_id);
		return NULL;
	}

	cntr = bulksvc_cntr_at(user_info, cntr_id);
	if (!cntr->active) {
		dd_dev_err(svc->dd, "%s:%d:%s() cntr %u not active\n",
			   __FILENAME__, __LINE__, __func__, cntr_id);
		return NULL;
	}

	return cntr;
}

static struct hfi2_bulksvc_cmpl get_cmpl(struct hfi2_bulksvc *svc,
		struct hfi2_bulksvc_user_info *user_info, u32 cmpl_id, __u64 flags)
{
	struct  hfi2_bulksvc_cmpl dest = { 0 };

	/* No completion requested: treat UINT32_MAX as "none". */
	if (cmpl_id == UINT32_MAX) {
		return (struct hfi2_bulksvc_cmpl){ .type = 0 };
	}

	/*
	 * Interpret completion, prefer CNTR if both are set (should not happen).
	 */
	if (flags & HFI2_BULKSVC_CMPL_CNTR) {
		dest.type = HFI2_BULKSVC_CMPL_CNTR;
		dest.cntr = get_cntr(svc, user_info, cmpl_id);
	} else if (flags & HFI2_BULKSVC_CMPL_CQ) {
		dest.type = HFI2_BULKSVC_CMPL_CQ;
		dest.cmplq_record = get_cmplq_record(svc, user_info, cmpl_id);
	} else {
		/* Default to CQ completion if neither bit is set. Preserves legacy semantics. */
		dest.type = HFI2_BULKSVC_CMPL_CQ;
		dest.cmplq_record = get_cmplq_record(svc, user_info, cmpl_id);
	}

	return dest;
}

static inline bool cmpl_has_ptr(const struct hfi2_bulksvc_cmpl *c)
{
	switch (c->type) {
	case HFI2_BULKSVC_CMPL_CQ:
		return c->cmplq_record != NULL;
	case HFI2_BULKSVC_CMPL_CNTR:
		return c->cntr != NULL;
	default:
		/* No completion requested; trivially OK. */
		return true;
	}
}

/* Return the completion queue targeted by a command, if any. */
static struct hfi2_bulksvc_queue_record *
bulksvc_cmd_cmplq_target(struct hfi2_bulksvc *svc,
			 struct hfi2_bulksvc_user_info *user_info,
			 struct hfi2_bulksvc_cmd const *cmd)
{
	u32 cmpl_id;
	__u64 flags;

	switch (cmd->hdr.op) {
	case HFI2_BULKSVC_CMD_REG_DMA_BUFFER:
		cmpl_id = cmd->payld[0].register_dma_buffer.cmpl_id;
		flags = cmd->payld[0].register_dma_buffer.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_VA:
		cmpl_id = cmd->payld[0].rdma_read_va.cmpl_id;
		flags = cmd->payld[0].rdma_read_va.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_VA_TRIGGERED:
		cmpl_id = cmd->payld[0].rdma_read_va_triggered.rdma_read_va.cmpl_id;
		flags = cmd->payld[0].rdma_read_va_triggered.rdma_read_va.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ:
		cmpl_id = cmd->payld[0].rdma_read.cmpl_id;
		flags = cmd->payld[0].rdma_read.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_TRIGGERED:
		cmpl_id = cmd->payld[0].rdma_read_triggered.rdma_read.cmpl_id;
		flags = cmd->payld[0].rdma_read_triggered.rdma_read.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_WRITE:
		cmpl_id = cmd->payld[0].rdma_write.cmpl_id;
		flags = cmd->payld[0].rdma_write.flags;
		break;
	case HFI2_BULKSVC_CMD_RDMA_WRITE_TRIGGERED:
		cmpl_id = cmd->payld[0].rdma_write_triggered.rdma_write.cmpl_id;
		flags = cmd->payld[0].rdma_write_triggered.rdma_write.flags;
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_ONCE:
		cmpl_id = cmd->payld[0].dma_access_once.cmpl_id;
		flags = cmd->payld[0].dma_access_once.flags;
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_ENABLE:
		cmpl_id = cmd->payld[0].dma_access_enable.cmpl_id;
		flags = cmd->payld[0].dma_access_enable.flags;
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_DISABLE:
		cmpl_id = cmd->payld[0].dma_access_disable.cmpl_id;
		flags = cmd->payld[0].dma_access_disable.flags;
		break;
	case HFI2_BULKSVC_CMD_MR_OPEN:
		cmpl_id = cmd->payld[0].mr_open.cmpl_id;
		flags = cmd->payld[0].mr_open.flags;
		break;
	case HFI2_BULKSVC_CMD_MR_CLOSE:
		cmpl_id = cmd->payld[0].mr_close.cmpl_id;
		flags = cmd->payld[0].mr_close.flags;
		break;
	case HFI2_BULKSVC_CMD_CNTR_ADD:
		cmpl_id = cmd->payld[0].cntr_add.cmpl_id;
		flags = cmd->payld[0].cntr_add.flags;
		break;
	case HFI2_BULKSVC_CMD_CNTR_SET:
		cmpl_id = cmd->payld[0].cntr_set.cmpl_id;
		flags = cmd->payld[0].cntr_set.flags;
		break;
	default:
		return NULL;
	}

	if (cmpl_id == UINT32_MAX || (flags & HFI2_BULKSVC_CMPL_CNTR))
		return NULL;

	return get_cmplq_record(svc, user_info, cmpl_id);
}

/* Ensure capacity of a ring; grow (doubling) if full. */
static int ensure_ring_capacity(struct bulksvc_cntr_trig_ring *r)
{
	if (!r->cap) {
		r->cap = TRIG_RING_INIT_CAP;
		r->buf = kcalloc(r->cap, sizeof(*r->buf), GFP_KERNEL);
		if (!r->buf) {
			r->cap = 0;
			return -ENOMEM;
		}
		return 0;
	}

	u32 count = r->tail - r->head;
	if (count < r->cap)
		return 0; /* not full */

	if (r->cap >= TRIG_RING_MAX_CAP) {
		/* At max capacity; refuse to grow further. */
		return -ENOSPC;
	}

	/* Grow (double) capacity, preserving FIFO order. */
	u32 old_cap = r->cap;
	u32 new_cap = r->cap << 1;
	struct bulksvc_trig_cmd_entry *nb =
		kcalloc(new_cap, sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;

	u32 mask_old = old_cap - 1;
	for (u32 i = 0; i < count; ++i) {
		nb[i] = r->buf[(r->head + i) & mask_old];
	}

	kfree(r->buf);
	r->buf = nb;
	r->cap = new_cap;
	r->head = 0;
	r->tail = count;

	return 0;
}

/* Append a trigger entry to a given counter ring. */
static int enqueue_trigger_cmd(struct bulksvc_cntr_trig_ring *r,
			       const struct hfi2_bulksvc_cmd *cmd_copy,
			       u32 target_value)
{
	int rc = ensure_ring_capacity(r);
	if (rc)
		return rc;

	u32 mask = r->cap - 1;
	struct bulksvc_trig_cmd_entry *ent = &r->buf[r->tail & mask];

	size_t cmd_size = (size_t)cmd_copy->hdr.num_blocks * CACHELINE_SIZE;
	if (cmd_size > BULKSVC_TRIG_CMD_MAX_SIZE) {
		pr_err("%s: command too large (%zu bytes)\n", __func__, cmd_size);
		return -EINVAL;
	}
	
	memcpy(ent->cmd_bytes, cmd_copy, cmd_size);
	ent->target_value = target_value;
	r->tail++;
	return 0;
}

/* Helper to ensure power-of-two capacity */
#define IS_POW2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

/*
 * Cap on how many triggered commands a single invocation of
 * process_triggers_for_cntr() will dispatch.  Without this cap, a counter
 * update that satisfies many queued triggers (e.g. a windowed test that
 * pre-posts N triggered ops and then bumps the trigger counter by N) fires
 * the whole batch inline, bypassing the existing inflight / completion-
 * overflow back-pressure enforced by poll_single_client().  That bypass
 * causes the per-client overflow stack to fill and silently drop completions
 * (see enqueue_overflow_completion()), which manifests in userspace as
 * "CQ: unexpected context X, expected Y" cascades during teardown.
 */
#define BULKSVC_MAX_TRIGGERS_PER_CALL 64U

/* Execute and remove any triggers whose target_value <= new_value for this counter. */
static void process_triggers_for_cntr(struct hfi2_bulksvc *svc,
				      struct hfi2_bulksvc_user_info *user_info,
				      struct hfi2_bulksvc_cntr *cntr, u64 new_value)
{
	struct bulksvc_cntr_trig_ring *r = &cntr->trig_ring;
	if (!r->cap || !r->buf)
		return;

	u32 count = r->tail - r->head;
	if (count == 0)
		return;

	u32 mask = r->cap - 1;
	u32 kept = 0;
	u32 fired = 0;
	bool back_pressure = false;

	for (u32 i = 0; i < count; ++i) {
		u32 idx = (r->head + i) & mask;
		struct bulksvc_trig_cmd_entry *ent = &r->buf[idx];

		bool fireable = (new_value >= ent->target_value);

		/*
		 * Preserve FIFO order after the first deferred fireable entry.
		 * Deferred entries are revisited through the dirty-bit poll.
		 */
		if (fireable && !back_pressure) {
			if (fired >= BULKSVC_MAX_TRIGGERS_PER_CALL ||
			    user_info->num_inflight >= user_info->max_inflight ||
			    user_info->num_completion_overflows >
				(user_info->completion_overflows_size / 2)) {
				back_pressure = true;
			}
		}

		if (fireable && !back_pressure) {
			/* This trigger fires now. Execute and drop it. */
			user_info->num_inflight++;
			fired++;
			bulksvc_on_user_cmd(svc, user_info, trig_entry_cmd(ent), NULL);
		} else {
			/* Keep it; compact in-place toward head. */
			if (kept != i) {
				u32 widx = (r->head + kept) & mask;
				r->buf[widx] = *ent;
			}
			kept++;
		}
	}

	/* Update tail to reflect compaction; head remains unchanged. */
	r->tail = r->head + kept;

	/*
	 * If we deferred any fireable triggers due to back-pressure, ask the
	 * poll loop to revisit this client.  poll_single_client() will drain
	 * pending completion overflows and release inflight slots, then retry
	 * dirty counters directly -- so deferred triggers are dispatched even
	 * when userspace has already issued its final counter bump and no
	 * future cntr_add() would re-enter process_triggers_for_cntr().
	 */
	if (back_pressure) {
		__set_bit(cntr->cntr_info.cntr_id,
			  user_info->trig_dirty_bitmap);
		if (user_info->dirty_bit >= 0)
			set_bit(user_info->dirty_bit,
				user_info->svc->dirty_notify.bitmap);
	} else {
		__clear_bit(cntr->cntr_info.cntr_id,
			    user_info->trig_dirty_bitmap);
	}
}

static int cntr_add(struct hfi2_bulksvc_user_info *user_info,
	            struct hfi2_bulksvc_cntr *cntr, bool value, u64 amount)
{
	if (!cntr) {
		pr_err("%s:%d:%s() invalid cntr at increment\n",
		       __FILENAME__, __LINE__, __func__);
		return -EINVAL;
	}

	u8 *base = (u8 *)cntr->page_kaddr;
	u64 new_value = 0;

	if (value) {
		u64 *value_addr = (u64 *)(base + cntr->value_offset);
		WRITE_ONCE(*value_addr, READ_ONCE(*value_addr) + amount);
		new_value = READ_ONCE(*value_addr);
	} else {
		u64 *error_addr = (u64 *)(base + cntr->error_offset);
		WRITE_ONCE(*error_addr, READ_ONCE(*error_addr) + amount);
	}

	/* Fire triggers on VALUE updates only. */
	if (value)
		process_triggers_for_cntr(user_info->svc, user_info, cntr, new_value);

	return 0;
}

/* Decrement num_inflight when delivering a completion when necessary */
static inline void decrement_num_inflight(struct hfi2_bulksvc_user_info *user_info,
			__u32 completion_type)
{
	if (completion_type != HFI2_HFISVC_CQ_ENTRY_TYPE_NOTIFY) {
		if (!user_info->num_inflight) {
			pr_err("%s:%d:%s() wrapping num_inflight\n",
				__FILENAME__, __LINE__, __func__);
		}
		user_info->num_inflight--;
	}
}

static inline void decrement_cmplq_inflight(struct hfi2_bulksvc_queue_record *cmplq_record,
					    __u32 completion_type)
{
	if (!cmplq_record || completion_type == HFI2_HFISVC_CQ_ENTRY_TYPE_NOTIFY)
		return;
	if (!cmplq_record->inflight) {
		pr_err("%s:%d:%s() wrapping cmplq inflight\n",
		       __FILENAME__, __LINE__, __func__);
		return;
	}
	cmplq_record->inflight--;
}

static void enqueue_overflow_completion(struct hfi2_bulksvc_user_info *user_info,
			struct hfi2_bulksvc_queue_record *cmplq_record,
			struct hfi2_bulksvc_cmplq_entry *cmpl)
{
	if (user_info->num_completion_overflows >= user_info->completion_overflows_size) {
		dd_dev_err_ratelimited(user_info->svc->dd,
			   "Completion overflow queue overflow, dropping completion\n");
		return;
	}
	u32 idx = user_info->num_completion_overflows;
	user_info->completion_overflows[idx] = (struct hfi2_bulksvc_overflow_entry) {
		.cmplq_entry = *cmpl,
		.cmplq_record = cmplq_record,
	};
	user_info->num_completion_overflows++;

	/* Mark dirty so poll_user_cmds() revisits this client to drain. */
	if (user_info->dirty_bit >= 0)
		set_bit(user_info->dirty_bit, user_info->svc->dirty_notify.bitmap);
}

static __always_inline int try_give_completion(struct hfi2_bulksvc_user_info *user_info,
					       struct hfi2_bulksvc_queue_record *cmplq_record,
					       struct hfi2_bulksvc_cmplq_entry *cmpl)
{
	u32 mask;
	u64 cmplq_head, cmplq_tail;
	struct hfi2_bulksvc_cmplq_entry *entry;

	if (unlikely(!cmplq_record)) {
		pr_err("%s:%d:%s() invalid dma buffer op info\n",
		       __FILENAME__, __LINE__, __func__);
		return -EINVAL;
	}

	mask = cmplq_record->idx_mask;
	/*
	 * head_shadow lags real userspace head; staleness can only over-
	 * report fullness, never under-report.  Refresh from the shared
	 * page only when the cached value says the ring is full.
	 */
	cmplq_head = cmplq_record->head_shadow;
	cmplq_tail = cmplq_record->tail_shadow;
	if (unlikely(cmplq_tail - cmplq_head >= mask)) {
		cmplq_head = atomic64_read_acquire(cmplq_record->head);
		cmplq_record->head_shadow = cmplq_head;
		if (cmplq_tail - cmplq_head >= mask) {
			pr_debug("%s:%d:%s() cmplq full\n",
			       __FILENAME__, __LINE__, __func__);
			return -ENOSPC;
		}
	}

	entry = &((union hfi2_bulksvc_upd *)
		cmplq_record->queue_buf_magic)[cmplq_tail & mask].cmplq_entry;

	*entry = *cmpl;

	cmplq_record->tail_shadow = cmplq_tail + 1;
	atomic64_set_release(cmplq_record->tail, cmplq_record->tail_shadow);

	decrement_num_inflight(user_info, cmpl->type);
	decrement_cmplq_inflight(cmplq_record, cmpl->type);
	return 0;
}

static __always_inline void give_completion(struct hfi2_bulksvc_user_info *user_info,
					    struct hfi2_bulksvc_cmpl cmpl,
					    __u64 app_context,
					    int status,
					    enum hfi2_bulksvc_cq_entry_type completion_type,
					    union hfi2_bulksvc_cmplq_entry_type_data type_data)
{
	/*
	 * mm is releasing: cmplq backing pages and counter pages are
	 * user-mm-backed and gone, skip the post for every completion type.
	 */
	if (user_info && user_info->mm_releasing)
		return;

	if (cmpl.type == HFI2_BULKSVC_CMPL_CQ) {
		struct hfi2_bulksvc_cmplq_entry cmplq_entry = { 0 };

		cmplq_entry.app_context = app_context;
		cmplq_entry.type = completion_type;
		cmplq_entry.status = status;
		cmplq_entry.type_data = type_data;

		int ret = try_give_completion(user_info, cmpl.cmplq_record,
					      &cmplq_entry);
		if (unlikely(ret == -ENOSPC)) {
			/* Keep the credit until overflow retry lands the completion. */
			enqueue_overflow_completion(user_info,
						    cmpl.cmplq_record,
						    &cmplq_entry);
		}
	} else if (cmpl.type == HFI2_BULKSVC_CMPL_CNTR) {
		if (!status)
			cntr_add(user_info, cmpl.cntr, true, 1);
		else
			cntr_add(user_info, cmpl.cntr, false, 1);

		decrement_num_inflight(user_info, completion_type);
	} else {
		/* No completion requested, just decrement num_inflight */
		decrement_num_inflight(user_info, completion_type);
	}
}



static void user_mr_record_destroy(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	if (mr_record) {
		if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF) {
			struct dma_buf *db = mr_record->mem_region.dma_buf;
			struct dma_buf_attachment *at =
				mr_record->mem_region.dma_buf_attachment;
			struct sg_table *sgt = mr_record->mem_region.sg_table;
			enum hfi2_bulksvc_fixup_cpu_mapping_type fixup =
				mr_record->mem_region.fixup_mapping_type;

			if (fixup == HFI2_BULKSVC_FIXUP_CPU_MAPPING_VMAP) {
				struct iosys_map *vmap =
					&mr_record->mem_region.fixup_mapping.vmap;

				/* Mirror the AMD/other open path: vunmap, unmap and
				 * unpin together under one reservation lock.
				 */
				dma_resv_lock(db->resv, NULL);
				if (vmap->vaddr_iomem) {
					dma_buf_vunmap(db, vmap);
					vmap->vaddr_iomem = NULL;
				}
				if (sgt) {
					dma_buf_unmap_attachment(at, sgt,
								 DMA_BIDIRECTIONAL);
					mr_record->mem_region.sg_table = NULL;
				}
				dma_buf_unpin(at);
				dma_resv_unlock(db->resv);
			}

			// This is only allocated for the dmabuf variant, in host variant it is a
			// weak ref to the hfi2_mem_region one
			kvfree(mr_record->dms_mr.dma_list);
			mr_record->dms_mr.dma_list = NULL;

			if (at) {
				dma_buf_detach(db, at);
				mr_record->mem_region.dma_buf_attachment = NULL;
			}
			if (db) {
				dma_buf_put(db);
				mr_record->mem_region.dma_buf = NULL;
			}
		} else if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_HOST) {
			if (mr_record->mem_region.hfi2_mr) {
				hfi2_mem_region_put(mr_record->mem_region.hfi2_mr);
				mr_record->mem_region.hfi2_mr = NULL;
			}
		}
		kfree(mr_record);
	}
}

/* Should not fire: dma_buf_pin() holds the buffer immovable for the MR's life. */
static void hfi2_bulksvc_dmabuf_move_notify(struct dma_buf_attachment *attach)
{
	WARN_RATELIMIT(1,
		       "hfi2 bulksvc: unexpected move_notify on pinned dma-buf attachment\n");
}

static const struct dma_buf_attach_ops hfi2_bulksvc_dmabuf_attach_ops = {
	.allow_peer2peer = true,
	.invalidate_mappings = hfi2_bulksvc_dmabuf_move_notify,
};

/**
 * Import/attach DMA memory and render per-page DMA addresses into
 * @umr->dms_mr->dma_list[].
 *
 * Returns: 0 on success, non-zero on error.
 */
static int user_mr_map_dma_buf(struct hfi2_bulksvc_user_info *uinfo, struct hfi2_bulksvc_user_mr_record *umr,
			       uintptr_t vaddr, u64 len, u32 hmem_iface, u32 hmem_device,
			       union hfi2_bulksvc_userctxt_cmd_data *cmd_data)
{
	struct hfi2_dms_mr *dms_mr;
	struct dma_buf *dmabuf;
	struct scatterlist *sg;
	const u64 begin_aligned_down = ALIGN_DOWN(vaddr, PAGE_SIZE);
	const u64 end_aligned_up = ALIGN(vaddr + len, PAGE_SIZE);
	const u64 extended_input_len = end_aligned_up - begin_aligned_down;
	const u64 num_pages = extended_input_len / PAGE_SIZE;
	u64 mapping_pages = 0;
	int ret;
	int i;

	/* Step 1: import and attach memory */
	umr->mr_type = HFI2_BULKSVC_MR_TYPE_DMABUF;

	if (WARN_ON(!cmd_data)) {
		pr_err("%s:%d:%s() ERROR: cmd_data is NULL for dma buf MR\n", __FILENAME__, __LINE__, __func__);
		goto error_cleanup;
	} else if (WARN_ON(!cmd_data->dmabuf_open.dmabuf)) {
		pr_err("%s:%d:%s() ERROR: cmd_data->dmabuf is NULL for dma buf MR, mr_open for dmabuf must be done through sync cmdq\n", __FILENAME__, __LINE__, __func__);
		goto error_cleanup;
	} else if (WARN_ON(extended_input_len < len)) {
		dd_dev_err(uinfo->svc->dd, "Unexpected result of extending user buffer to page size, extended len %llu, orig len %llu\n", extended_input_len, len);
		goto error_cleanup;
	}

	umr->mem_region.dma_buf = cmd_data->dmabuf_open.dmabuf;
	cmd_data->dmabuf_open.dmabuf = NULL;
	dmabuf = umr->mem_region.dma_buf;
	if (IS_ERR_OR_NULL(umr->mem_region.dma_buf)) {
		pr_err("%s:%d:%s() ERROR: dma_buf_get returned error %pE for fd %u\n",
		       __FILENAME__, __LINE__, __func__, umr->mem_region.dma_buf,
		       hmem_device);
		umr->mem_region.dma_buf = NULL;
		goto error_cleanup;
	}

	if (extended_input_len > dmabuf->size) {
		dd_dev_err_ratelimited(uinfo->svc->dd,
				       "dma_buf MR len %llu exceeds dma_buf size %zu\n",
				       extended_input_len, dmabuf->size);
		goto error_cleanup;
	}

	{ /* generic device-only attach path */
		/*
		 * AMD/other: attach as a dynamic importer advertising peer2peer,
		 * then pin so the exporter keeps the buffer in VRAM and hands
		 * back PCIe peer addresses.  Pin, map and vmap together under the
		 * reservation lock so dma_list[] and the fixup mapping reflect an
		 * immovable placement.
		 */
		umr->mem_region.dma_buf_attachment =
			dma_buf_dynamic_attach(dmabuf,
					       &uinfo->svc->dd->pcidev->dev,
					       &hfi2_bulksvc_dmabuf_attach_ops, umr);
		if (IS_ERR_OR_NULL(umr->mem_region.dma_buf_attachment)) {
			pr_err("%s:%d:%s() ERROR: dma_buf_dynamic_attach returned error %pE for fd %u\n",
			       __FILENAME__, __LINE__, __func__,
			       umr->mem_region.dma_buf_attachment, hmem_device);
			umr->mem_region.dma_buf_attachment = NULL;
			goto error_cleanup;
		}

		dma_resv_lock(dmabuf->resv, NULL);

		ret = dma_buf_pin(umr->mem_region.dma_buf_attachment);
		if (ret) {
			dma_resv_unlock(dmabuf->resv);
			pr_err("%s:%d:%s() ERROR: dma_buf_pin returned %d for fd %u\n",
			       __FILENAME__, __LINE__, __func__, ret, hmem_device);
			goto error_cleanup;
		}

		umr->mem_region.sg_table =
			dma_buf_map_attachment(umr->mem_region.dma_buf_attachment,
					       DMA_BIDIRECTIONAL);
		if (IS_ERR_OR_NULL(umr->mem_region.sg_table)) {
			dma_buf_unpin(umr->mem_region.dma_buf_attachment);
			dma_resv_unlock(dmabuf->resv);
			pr_err("%s:%d:%s() ERROR: dma_buf_map_attachment returned error %pE for fd %u\n",
			       __FILENAME__, __LINE__, __func__,
			       umr->mem_region.sg_table, hmem_device);
			umr->mem_region.sg_table = NULL;
			goto error_cleanup;
		}

		ret = dma_buf_vmap(dmabuf, &umr->mem_region.fixup_mapping.vmap);
		if (ret) {
			umr->mem_region.fixup_mapping.vmap.vaddr_iomem = NULL;
			dma_buf_unmap_attachment(umr->mem_region.dma_buf_attachment,
						 umr->mem_region.sg_table,
						 DMA_BIDIRECTIONAL);
			umr->mem_region.sg_table = NULL;
			dma_buf_unpin(umr->mem_region.dma_buf_attachment);
			dma_resv_unlock(dmabuf->resv);
			dd_dev_err(uinfo->svc->dd, "dma_buf_vmap failed for fd %u: %d\n",
				   hmem_device, ret);
			goto error_cleanup;
		}
		umr->mem_region.fixup_mapping_type = HFI2_BULKSVC_FIXUP_CPU_MAPPING_VMAP;

		dma_resv_unlock(dmabuf->resv);
	}

	/* Step 2: render per-page DMA mappings into dma_list[] */
	dms_mr = &umr->dms_mr;
	dms_mr->npages_total = num_pages;
	dms_mr->dma_list = kvmalloc_array(num_pages, sizeof(dma_addr_t),
					  GFP_KERNEL | __GFP_NOWARN);
	if (!dms_mr->dma_list)
		goto error_cleanup;

	for_each_sgtable_dma_sg(umr->mem_region.sg_table, sg, i) {
		const u32 sg_len = sg_dma_len(sg);
		const dma_addr_t sg_addr = sg_dma_address(sg);
		const u64 sgl_num_pages = sg_len / PAGE_SIZE;

		if (mapping_pages >= num_pages)
			break;

		if (sg_len % PAGE_SIZE != 0) {
			dd_dev_err(uinfo->svc->dd,
				   "Unexpected non-page-sized sg entry in dma_buf mapping: len %u, dma addr 0x%llx\n",
				   sg_len, sg_addr);
			goto error_cleanup;
		}

		for (u32 sgl_page_idx = 0; sgl_page_idx < sgl_num_pages &&
		     mapping_pages < num_pages; ++sgl_page_idx) {
			dms_mr->dma_list[mapping_pages] = sg_addr +
							  (sgl_page_idx * PAGE_SIZE);
			++mapping_pages;
		}
	}

	if (mapping_pages != num_pages) {
		dd_dev_err(uinfo->svc->dd, "dma_buf mapping smaller than expected: mapping pages %llu, total pages %llu\n",
			   mapping_pages, num_pages);
		goto error_cleanup;
	}

	dms_mr->extended_vaddr.addr = begin_aligned_down;
	dms_mr->extended_vaddr.len = extended_input_len;

	return 0;
error_cleanup:
	return -EFAULT;
}

int hfi2_bulksvc_user_pin_range(struct hfi2_bulksvc *svc, void *mr,
			       unsigned int from_page,
			       unsigned int npages,
			       bool writable)
{
	struct hfi2_bulksvc_user_mr_record *mr_record = mr;
	struct hfi2_mem_region *hfi2_mr;
	int ret;

	if (WARN_ON(!mr_record))
		return -EINVAL;
	if (mr_record->mr_type != HFI2_BULKSVC_MR_TYPE_HOST)
		return 0;

	hfi2_mr = mr_record->mem_region.hfi2_mr;
	if (WARN_ON(!hfi2_mr))
		return -EINVAL;

	ret = hfi2_mem_region_pin_range(svc->dd, hfi2_mr, from_page, npages,
					writable);
	if (ret < 0)
		return ret;

	mr_record->dms_mr.dma_list = hfi2_mr->dma_list;

	return 0;
}

static int user_pin_range(void *ctx, unsigned int from_page,
			  unsigned int npages, bool writable)
{
	struct hfi2_dms_mr *dms_mr = ctx;
	struct hfi2_bulksvc_user_mr_record *mr_record =
		container_of(dms_mr, struct hfi2_bulksvc_user_mr_record,
			     dms_mr);
	struct hfi2_bulksvc_user_mr_record_ext *ext;
	struct hfi2_mem_region *hfi2_mr;
	struct hfi2_bulksvc *svc;
	unsigned int last_needed;
	int ret;

	if (WARN_ON_ONCE(!mr_record))
		return -EFAULT;
	if (!npages)
		return -EINVAL;
	if (unlikely(from_page > UINT_MAX - npages))
		return -EFAULT;

	last_needed = from_page + npages;

	if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF) {
		if (last_needed > mr_record->dms_mr.npages_total)
			return -EINVAL;
		return 0;
	}

	hfi2_mr = mr_record->mem_region.hfi2_mr;
	if (!hfi2_mr)
		return -EFAULT;
	if (last_needed > hfi2_mr->npages_total)
		return -EINVAL;

	if (hfi2_mem_region_range_pinned(hfi2_mr, from_page, npages))
		return 0;

	ext = user_mr_record_ext(mr_record);
	if (WARN_ON_ONCE(!ext->pin_owner) || WARN_ON_ONCE(!ext->pin_owner->svc))
		return -EFAULT;
	svc = ext->pin_owner->svc;

	ret = hfi2_bulksvc_user_pin_range(svc, mr_record, from_page, npages,
					  writable);
	if (ret < 0) {
		dd_dev_warn(svc->dd, "DMS_DIAG: PIN_RANGE inline pin FAILED ret=%d from=%u n=%u total=%u pinned=%u\n",
			    ret, from_page, npages, hfi2_mr->npages_total,
			    hfi2_mr->npages_pinned);
		return ret;
	}

	hfi2_bulksvc_user_pins(ext->pin_owner)->pages_pinned_inline += npages;
	hfi2_bulksvc_user_pins(ext->pin_owner)->inline_pin_count++;

	return 0;
}

static int user_mr_proactive_pin_range(
	struct hfi2_bulksvc *svc,
	struct hfi2_bulksvc_proactive_pin_entry *entry,
	unsigned int from_page, unsigned int npages,
	bool writable)
{
	struct hfi2_bulksvc_user_mr_record_ext *ext =
		container_of(entry, struct hfi2_bulksvc_user_mr_record_ext,
			     pin_entry);

	return hfi2_bulksvc_user_pin_range(svc, &ext->mr_record,
					  from_page, npages, writable);
}

static int ephemeral_pin_range(void *ctx, unsigned int from_page,
			       unsigned int npages, bool writable)
{
	struct hfi2_dms_mr *dms_mr = ctx;
	struct hfi2_bulksvc_ephemeral_mr *eph_mr =
		container_of(dms_mr, struct hfi2_bulksvc_ephemeral_mr, dms_mr);
	struct hfi2_mem_region *hfi2_mr;
	unsigned int last_needed;
	int ret;

	struct hfi2_devdata *dd;

	if (WARN_ON_ONCE(!eph_mr))
		return -EFAULT;
	if (WARN_ON_ONCE(!eph_mr->user_info || !eph_mr->user_info->svc))
		return -EFAULT;
	if (!npages)
		return -EINVAL;
	if (unlikely(from_page > UINT_MAX - npages))
		return -EFAULT;

	dd = eph_mr->user_info->svc->dd;
	hfi2_mr = eph_mr->hfi2_mr;
	if (!hfi2_mr)
		return -EFAULT;

	last_needed = from_page + npages;
	if (last_needed > hfi2_mr->npages_total)
		return -EINVAL;

	if (hfi2_mem_region_range_pinned(hfi2_mr, from_page, npages))
		return 0;

	ret = hfi2_mem_region_pin_range(dd, hfi2_mr, from_page, npages,
					writable);
	if (ret < 0) {
		eph_mr->user_info->eph_mr_pin_fail++;
		dd_dev_warn_ratelimited(dd,
			"DMS_DIAG: ephemeral pin_range failed ret=%d from_page=%u npages=%u\n",
			ret, from_page, npages);
		return ret;
	}

	/* Preserve the alias the demand-pin used to publish so single-MR
	 * next_src_run reads live DMA addresses, not a stale/NULL list.
	 */
	eph_mr->dms_mr.dma_list = hfi2_mr->dma_list;

	return 0;
}

static int ephemeral_mr_proactive_pin_range(
	struct hfi2_bulksvc *svc,
	struct hfi2_bulksvc_proactive_pin_entry *entry,
	unsigned int from_page, unsigned int npages,
	bool writable)
{
	struct hfi2_bulksvc_ephemeral_mr *eph_mr =
		container_of(entry, struct hfi2_bulksvc_ephemeral_mr, pin_entry);

	return hfi2_mem_region_pin_range(svc->dd, eph_mr->hfi2_mr,
					 from_page, npages, writable);
}

static void ephemeral_mr_promote(void *ctx)
{
	struct hfi2_dms_mr *dms_mr = ctx;
	struct hfi2_bulksvc_ephemeral_mr *eph_mr;

	if (!dms_mr)
		return;
	eph_mr = container_of(dms_mr, struct hfi2_bulksvc_ephemeral_mr, dms_mr);
	pin_entry_promote(&eph_mr->pin_entry);
}

static struct hfi2_bulksvc_ephemeral_mr *
ephemeral_mr_create_va(struct hfi2_bulksvc_user_info *user_info,
		      uintptr_t vaddr, u64 len)
{
	struct hfi2_bulksvc_ephemeral_mr *eph_mr;
	struct hfi2_mem_region *hfi2_mr;

	eph_mr = kzalloc_node(sizeof(*eph_mr), GFP_KERNEL,
			      user_info->svc->dd->node);
	if (!eph_mr) {
		dd_dev_warn_ratelimited(user_info->svc->dd,
			"DMS_DIAG: ephemeral_mr_create_va: kzalloc failed vaddr=0x%lx len=%llu\n",
			(unsigned long)vaddr, (u64)len);
		return NULL;
	}

	hfi2_mr = hfi2_mem_region_create_unpinned(user_info->mmu, vaddr, len);
	if (!hfi2_mr) {
		dd_dev_warn_ratelimited(user_info->svc->dd,
			"DMS_DIAG: ephemeral_mr_create_va: region_create_unpinned failed vaddr=0x%lx len=%llu\n",
			(unsigned long)vaddr, (u64)len);
		goto error_free_eph;
	}

	eph_mr->hfi2_mr = hfi2_mr;
	eph_mr->user_info = user_info;
	INIT_LIST_HEAD(&eph_mr->deferred_free_node);
	eph_mr->dms_mr.dma_list = hfi2_mr->dma_list;
	eph_mr->dms_mr.extended_vaddr.addr = hfi2_mr->rb.addr;
	eph_mr->dms_mr.extended_vaddr.len = hfi2_mr->rb.len;
	eph_mr->dms_mr.npages_total = hfi2_mr->npages_total;
	eph_mr->dms_mr.user.addr = vaddr;
	eph_mr->dms_mr.user.len = len;
	eph_mr->dms_mr.region_offset =
		(u64)vaddr - ALIGN_DOWN((u64)vaddr, PAGE_SIZE);
	eph_mr->dms_mr.mode = HFI2_DMS_MR_MODE_OFFSET;
	eph_mr->dms_mr.owner = user_info;

	INIT_LIST_HEAD(&eph_mr->pin_entry.node);
	eph_mr->pin_entry.hfi2_mr = hfi2_mr;
	eph_mr->pin_entry.owner = user_info;
	eph_mr->pin_entry.region_offset_bytes = eph_mr->dms_mr.region_offset;
	eph_mr->pin_entry.pin_range = ephemeral_mr_proactive_pin_range;
	eph_mr->pin_entry.on_speculative_pin_list = false;
	eph_mr->pin_entry.on_active_pin_list = false;

	list_add_tail(&eph_mr->pin_entry.node,
		      &hfi2_bulksvc_user_pins(user_info)->pin_speculative);
	eph_mr->pin_entry.on_speculative_pin_list = true;
	hfi2_bulksvc_user_pins(user_info)->speculative_count++;

	return eph_mr;

error_free_eph:
	kfree(eph_mr);
	return NULL;
}

static void ephemeral_mr_destroy(struct hfi2_bulksvc_ephemeral_mr *eph_mr)
{
	if (!eph_mr)
		return;

	if (eph_mr->hfi2_mr) {
		hfi2_mem_region_put(eph_mr->hfi2_mr);
		eph_mr->hfi2_mr = NULL;
	}
	kfree(eph_mr);
}

static void ephemeral_mr_put(struct hfi2_bulksvc_ephemeral_mr *eph_mr)
{
	struct hfi2_bulksvc_user_info *user_info;

	if (!eph_mr)
		return;

	user_info = eph_mr->user_info;
	if (!user_info) {
		ephemeral_mr_destroy(eph_mr);
		return;
	}

	/*
	 * Unlink from svc-wide pin lists BEFORE queueing onto the
	 * deferred-free list. The deferred-free drain can free eph_mr
	 * while process_proactive_pins is still walking the pin lists;
	 * removing our node first prevents the worker from dereferencing
	 * a freed object. Same pattern as user_mr_record_destroy_and_remove.
	 */
	if (WARN_ON_ONCE(!list_empty(&eph_mr->deferred_free_node)))
		return;

	hfi2_bulksvc_pin_entry_unlink(hfi2_bulksvc_user_pins(user_info),
				      &eph_mr->pin_entry);

	list_add_tail(&eph_mr->deferred_free_node,
		      &user_info->eph_mr_deferred_free);
	user_info->eph_mr_deferred_count++;

	if (user_info->dirty_bit >= 0 &&
	    !user_info->mm_releasing &&
	    !user_info->shutting_down)
		set_bit(user_info->dirty_bit,
			user_info->svc->dirty_notify.bitmap);
}

static u32 ephemeral_mr_drain_deferred(struct hfi2_bulksvc_user_info *user_info,
				       u32 max_drain)
{
	struct hfi2_bulksvc_ephemeral_mr *eph_mr, *tmp;
	u32 drained = 0;

	list_for_each_entry_safe(eph_mr, tmp,
				 &user_info->eph_mr_deferred_free,
				 deferred_free_node) {
		if (max_drain && drained >= max_drain)
			break;
		list_del(&eph_mr->deferred_free_node);
		user_info->eph_mr_deferred_count--;
		ephemeral_mr_destroy(eph_mr);
		drained++;
	}
	return drained;
}

static u32 ephemeral_mr_drain_adaptive(struct hfi2_bulksvc_user_info *user_info)
{
	u32 deferred_max = user_info->max_inflight / 2;
	u32 drain_max = user_info->max_inflight * 2;
	u32 rate = user_info->eph_mr_drain_rate;
	u32 drained = ephemeral_mr_drain_deferred(user_info, rate);

	if (user_info->eph_mr_deferred_count > deferred_max)
		user_info->eph_mr_drain_rate =
			min(rate + BULKSVC_EPH_MR_DRAIN_STEP, drain_max);
	else if (drained < rate)
		user_info->eph_mr_drain_rate =
			max(rate - BULKSVC_EPH_MR_DRAIN_STEP,
			    BULKSVC_EPH_MR_DRAIN_MIN);

	return drained;
}

static struct hfi2_bulksvc_user_mr_record *
user_mr_record_create_metadata(struct hfi2_bulksvc_user_info *user_info,
			       uintptr_t vaddr, u64 len, u64 flags,
			       u32 hmem_iface, u32 hmem_device,
			       union hfi2_bulksvc_userctxt_cmd_data *cmd_data)
{
	struct hfi2_bulksvc_user_mr_record_ext *mr_record_ext;
	struct hfi2_bulksvc_user_mr_record *mr_record;
	int node = user_info && user_info->svc
		   ? user_info->svc->dd->node
		   : NUMA_NO_NODE;
	int ret;

	if (!hfi2_bulksvc_mr_span_ok(vaddr, len)) {
		pr_err_ratelimited("%s: invalid MR vaddr 0x%lx len %llu\n",
				   __func__, vaddr, len);
		return NULL;
	}

	mr_record_ext = kzalloc_node(sizeof(*mr_record_ext), GFP_KERNEL, node);
	if (!mr_record_ext)
		return NULL;

	mr_record = &mr_record_ext->mr_record;

	switch (hmem_iface) {
	case HFI2_HFISVC_HMEM_IFACE_SYSTEM: {
		struct hfi2_dms_mr *dms_mr;
		struct hfi2_mem_region *hfi2_mr;

		mr_record->mr_type = HFI2_BULKSVC_MR_TYPE_HOST;
		hfi2_mr = hfi2_mem_region_create_unpinned(user_info->mmu, vaddr, len);
		if (!hfi2_mr) {
			pr_err("%s:%d:%s() ERROR: Failed to create unpinned memory region\n",
			       __FILENAME__, __LINE__, __func__);
			goto error_cleanup;
		}

		mr_record->mem_region.hfi2_mr = hfi2_mr;
		dms_mr = &mr_record->dms_mr;
		dms_mr->dma_list = hfi2_mr->dma_list;
		dms_mr->extended_vaddr.addr = hfi2_mr->rb.addr;
		dms_mr->extended_vaddr.len = hfi2_mr->rb.len;
		dms_mr->npages_total = hfi2_mr->npages_total;
		break;
	}
	case HFI2_HFISVC_HMEM_IFACE_DMABUF:
		ret = user_mr_map_dma_buf(user_info, mr_record, vaddr, len,
					  hmem_iface, hmem_device, cmd_data);
		if (ret)
			goto error_cleanup;
		break;
	default:
		pr_err("%s:%d:%s() ERROR: Unsupported hmem iface %u\n",
		       __FILENAME__, __LINE__, __func__, hmem_iface);
		goto error_cleanup;
	}

	mr_record->dms_mr.user.addr = vaddr;
	mr_record->dms_mr.user.len = len;
	mr_record->dms_mr.region_offset =
		(u64)vaddr - ALIGN_DOWN((u64)vaddr, PAGE_SIZE);
	if (flags & HFI2_BULKSVC_MR_FLAG_MODE_VADDR)
		mr_record->dms_mr.mode = HFI2_DMS_MR_MODE_VADDR;
	else
		mr_record->dms_mr.mode = HFI2_DMS_MR_MODE_OFFSET;

	mr_record_ext->pin_owner = user_info;
	INIT_LIST_HEAD(&mr_record_ext->pin_entry.node);
	mr_record_ext->pin_entry.hfi2_mr = mr_record->mem_region.hfi2_mr;
	mr_record_ext->pin_entry.owner = user_info;
	mr_record_ext->pin_entry.region_offset_bytes =
		mr_record->dms_mr.region_offset;
	mr_record_ext->pin_entry.pin_range = user_mr_proactive_pin_range;
	mr_record_ext->pin_entry.on_speculative_pin_list = false;
	mr_record_ext->pin_entry.on_active_pin_list = false;
	/* Gate on the internal mr_type rather than the UAPI hmem_iface
	 * value: HFI2_BULKSVC_MR_TYPE_HOST is the right gate for any
	 * iface backed by FOLL_PIN'd host pages (today: only IFACE_SYSTEM,
	 * but a future GPU iface using host-page staging would also set
	 * MR_TYPE_HOST).
	 */
	mr_record->dms_mr.owner = user_info;

	if (mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_HOST) {
		list_add_tail(&mr_record_ext->pin_entry.node,
			      &hfi2_bulksvc_user_pins(user_info)->pin_speculative);
		mr_record_ext->pin_entry.on_speculative_pin_list = true;
		hfi2_bulksvc_user_pins(user_info)->speculative_count++;
	}

	mr_record->user_handle = user_info->next_user_mr_handle++;
	kref_init(&mr_record->refcount);

	list_add_tail(&mr_record->list_entry, &user_info->user_mr_list);
	/*
	 * Index insert must not fail registration after the record is
	 * already published on the list; on allocation failure latch this
	 * client onto list-scan lookups.  xa_store of a live handle cannot
	 * collide: handles are monotonically assigned and erased at
	 * list_del time.
	 */
	if (xa_err(xa_store(&user_info->mr_by_handle, mr_record->user_handle,
			    mr_record, GFP_KERNEL))) {
		WRITE_ONCE(user_info->mr_index_incomplete, true);
		pr_warn("%s:%d:%s() mr_by_handle index insert failed for handle %u; lookups fall back to list scan\n",
			__FILENAME__, __LINE__, __func__, mr_record->user_handle);
	}

	return mr_record;

error_cleanup:
	user_mr_record_destroy(mr_record);
	return NULL;
}

static void user_mr_record_destroy_and_remove(struct kref* ref)
{
	struct hfi2_bulksvc_user_mr_record *mr_record = container_of(ref, struct hfi2_bulksvc_user_mr_record, refcount);
	struct hfi2_bulksvc_user_mr_record_ext *ext = user_mr_record_ext(mr_record);

	hfi2_bulksvc_pin_entry_unlink(hfi2_bulksvc_user_pins(ext->pin_owner),
				      &ext->pin_entry);

	/*
	 * Erase the index entry only if it still refers to this record:
	 * final release can run after the same handle value was never
	 * reused (handles are monotonic), but guard with cmpxchg anyway
	 * so a future reuse policy cannot silently drop a live entry.
	 */
	xa_cmpxchg(&ext->pin_owner->mr_by_handle, mr_record->user_handle,
		   mr_record, NULL, GFP_ATOMIC);
	list_del(&mr_record->list_entry);
	user_mr_record_destroy(mr_record);
}

static void user_mr_record_get(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	kref_get(&mr_record->refcount);
}

static void user_mr_record_put(struct hfi2_bulksvc_user_mr_record *mr_record)
{
	kref_put(&mr_record->refcount, user_mr_record_destroy_and_remove);
}

static struct hfi2_bulksvc_user_mr_record *
lookup_user_mr_record(struct hfi2_bulksvc_user_info *user_info,
		 u32 user_handle)
{
	struct hfi2_bulksvc_user_mr_record *result;

	result = xa_load(&user_info->mr_by_handle, user_handle);
	if (likely(result) || likely(!READ_ONCE(user_info->mr_index_incomplete)))
		return result;

	/* An index insert failed (see registration); scan the list. */
	list_for_each_entry(result, &user_info->user_mr_list, list_entry) {
		if (result->user_handle == user_handle) {
			return result;
		}
	}
	return NULL;
}

static struct hfi2_bulksvc_user_mr_access_record *
user_mr_access_record_create_and_insert(struct hfi2_bulksvc_user_info *user_info,
		 u32 access_key, u64 app_context, u32 cmplq_id,
		 u64 notify_app_context, u32 notify_cmpl_id, __u64 notify_flags,
		 struct hfi2_bulksvc_user_mr_record *mr_record)
{
	struct hfi2_bulksvc_user_mr_access_record *access_record;

	access_record = kzalloc(sizeof(*access_record), GFP_KERNEL);
	if (!access_record) {
		pr_err("%s:%d:%s() ERROR: Failed to allocate memory for access_record\n", __FILENAME__, __LINE__, __func__);
		return NULL;
	}

	access_record->access_key = access_key;
	access_record->app_context = app_context;
	access_record->cmplq_id = cmplq_id;
	access_record->notify_app_context = notify_app_context;
	access_record->notify_cmpl_id = notify_cmpl_id;
	access_record->notify_flags = notify_flags;
	access_record->mr_record = mr_record;
	access_record->user_info = user_info;
	access_record->client_key = user_info->client_key;

	list_add_tail(&access_record->list_entry, &user_info->active_access_list);
	if (xa_err(xa_store(&user_info->access_by_key, access_key,
			    access_record, GFP_KERNEL))) {
		WRITE_ONCE(user_info->access_index_incomplete, true);
		pr_warn("%s:%d:%s() access_by_key index insert failed for key %u; lookups fall back to list scan\n",
			__FILENAME__, __LINE__, __func__, access_key);
	}

	// Currently all long-lived access records hold an owning reference to the MR record
	user_mr_record_get(mr_record);

	return access_record;
}

/*
 * Destroy access record without list removal.
 * Caller must have already unlinked from active_access_list.
 */
static void user_mr_access_record_destroy(struct hfi2_bulksvc_user_mr_access_record *access_record)
{
	user_mr_record_put(access_record->mr_record);
	kfree(access_record);
}

/* Destroy access record and remove from active_access_list. */
static void user_mr_access_record_destroy_and_remove(struct hfi2_bulksvc_user_mr_access_record *access_record)
{
	if (access_record->user_info)
		xa_cmpxchg(&access_record->user_info->access_by_key,
			   access_record->access_key, access_record, NULL,
			   GFP_ATOMIC);
	list_del(&access_record->list_entry);
	user_mr_access_record_destroy(access_record);
}

static struct hfi2_bulksvc_user_mr_access_record *
lookup_user_mr_access_record(struct hfi2_bulksvc_user_info *user_info,
		 u32 access_key)
{
	struct hfi2_bulksvc_user_mr_access_record *result;

	result = xa_load(&user_info->access_by_key, access_key);
	if (likely(result) ||
	    likely(!READ_ONCE(user_info->access_index_incomplete)))
		return result;

	/* An index insert failed (see creation); scan the list. */
	list_for_each_entry(result, &user_info->active_access_list, list_entry) {
		if (result->access_key == access_key) {
			return result;
		}
	}
	return NULL;
}

static int validate_mr_access(struct hfi2_bulksvc_user_mr_record *mr, u64 offset, u32 len)
{
	u64 region_start;
	u64 region_end;

	if (mr->dms_mr.mode == HFI2_DMS_MR_MODE_VADDR) {
		region_start = mr->dms_mr.user.addr;
		if (check_add_overflow(region_start, (u64)mr->dms_mr.user.len, &region_end))
			return -1;
	} else if (mr->dms_mr.mode == HFI2_DMS_MR_MODE_OFFSET) {
		region_start = 0;
		region_end = mr->dms_mr.user.len;
	} else {
		pr_err("%s:%d:%s() invalid mr mode %d\n",
		       __FILENAME__, __LINE__, __func__, mr->dms_mr.mode);
		return -1;
	}

	if (offset < region_start || offset > region_end)
		return -1;
	if (len > region_end - offset)
		return -1;
	return 0;
}

///
/// ONE-TIME USE TRANSACTION
///

union reg_dma_buffer_cmpl_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc_user_info *user_info;
		struct hfi2_bulksvc_cmpl cmpl;
		u64 app_context;
		u32 access_key;
		struct hfi2_bulksvc_user_mr_record *mr_record;
	};
};
static_assert(sizeof(union reg_dma_buffer_cmpl_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_registered_dma_buffer_completed_transact(union hfi2_dms_completion_cookie *cookie, u16 flags, u64 imm_data, u64 order_key, int status)
{
	union reg_dma_buffer_cmpl_cookie *reg_cookie =
		container_of(cookie, union reg_dma_buffer_cmpl_cookie, dms);

	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	type_data.type_default.access_key = reg_cookie->access_key;
	give_completion(reg_cookie->user_info, reg_cookie->cmpl, reg_cookie->app_context, 
		status, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);

	user_mr_record_put(reg_cookie->mr_record); // one-time
	hfi2_bulksvc_user_info_put(reg_cookie->user_info);

}

static void bulksvc_on_cmd_reg_dma_buffer(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_reg_dma_buffer const * const cmd)
{
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_user_mr_record *mr_record;
	u64 offset;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	mr_record = user_mr_record_create_metadata(user_info, cmd->vaddr,
						    cmd->size_bytes, cmd->flags,
						    HFI2_HFISVC_HMEM_IFACE_SYSTEM,
						    0, NULL);
	if (!mr_record) {
		union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

		dd_dev_err(svc->dd, "%s:%d:%s() failed to create user dma buffer metadata\n",
			   __FILENAME__, __LINE__, __func__);

		type_data.type_default.access_key = cmd->access_key;
		give_completion(user_info, cmpl, cmd->app_context, -EFAULT,
				HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);
		return;
	}

	/*
	 * Normalize offset to be relative to the MR base.
	 * VADDR mode: cmd->vaddr is the absolute virtual address;
	 * subtract the MR base to get a relative offset.
	 * OFFSET mode: offset is 0 (whole buffer).
	 *
	 * register_access validates offset + size against
	 * page_provider.length which is the user buffer length,
	 * so offset must be relative.
	 */
	if (cmd->flags & HFI2_BULKSVC_MR_FLAG_MODE_VADDR) {
		offset = cmd->vaddr - mr_record->dms_mr.user.addr;
	} else {
		offset = 0;
	}

	hfi2_bulksvc_user_info_get(user_info);
	union reg_dma_buffer_cmpl_cookie c = { .dms = {{0}} };
	c.user_info = user_info;
	c.cmpl = cmpl;
	c.app_context = cmd->app_context;
	c.access_key = cmd->access_key;
	c.mr_record = mr_record;
	int rc = hfi2_dms_register_access(hfi2_bulksvc_user_dms(user_info),
		user_mr_page_provider(mr_record), offset,
		cmd->size_bytes,
		(union hfi2_dms_key) { .access = cmd->access_key, .client = user_info->client_key },
		(struct hfi2_dms_access_completion) {
			.fn = on_registered_dma_buffer_completed_transact,
			.cookie = c.dms,
		}, HFI2_DMS_ACCESS_TYPE_EPHEMERAL, NULL);
	if (rc < 0) {
		union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

		dd_dev_warn(svc->dd, "DMS_DIAG: REG_DMA_BUFFER register_access FAILED rc=%d access_key=%u client_key=%u size=%u offset=%llu\n",
			    rc, cmd->access_key, user_info->client_key,
			    cmd->size_bytes, offset);
		type_data.type_default.access_key = cmd->access_key;
		give_completion(user_info, cmpl, cmd->app_context, (u32)rc,
				HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);

		user_mr_record_put(mr_record);
		hfi2_bulksvc_user_info_put(user_info);
	}
	return;
}

///
/// MANAGE LONG-LIVED MEMORY REGION
///

static void bulksvc_on_cmd_mr_open(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_mr_open const * const cmd,
	union hfi2_bulksvc_userctxt_cmd_data * const userctxt_data)
{
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_user_mr_record *mr_record;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	mr_record = user_mr_record_create_metadata(user_info, cmd->vaddr,
				    cmd->len, cmd->flags,
				    cmd->hmem_iface,
				    cmd->hmem_device,
				    userctxt_data);

	__u32 status;
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	if (!mr_record) {
		dd_dev_err_ratelimited(svc->dd,
				       "DMS_DIAG: MR_OPEN FAILED vaddr=0x%llx len=%llu hmem=%u\n",
				       (u64)cmd->vaddr, cmd->len, cmd->hmem_iface);
		status = -EFAULT;
		type_data.type_mr.mr_key = 0;
	} else {
		status = 0;
		type_data.type_mr.mr_key = mr_record->user_handle;
	}

	give_completion(user_info, cmpl, cmd->app_context, status,
			HFI2_HFISVC_CQ_ENTRY_TYPE_MR, type_data);

	return;
}

static void bulksvc_on_cmd_mr_close(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_mr_close const * const cmd)
{
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_user_mr_record *mr;
	__u32 status;
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	mr = lookup_user_mr_record(user_info, cmd->mr_key);
	if (mr) {
		struct hfi2_bulksvc_user_mr_record_ext *ext = user_mr_record_ext(mr);

		hfi2_bulksvc_pin_entry_unlink(hfi2_bulksvc_user_pins(user_info),
					      &ext->pin_entry);
		user_mr_record_put(mr);
		status = 0;
	} else {
		status = -EINVAL;
	}

	type_data.type_mr.mr_key = cmd->mr_key;

	give_completion(user_info, cmpl, cmd->app_context, status, HFI2_HFISVC_CQ_ENTRY_TYPE_MR, type_data);
}

///
/// GRANT ACCESS TO MEMORY REGION ONCE
///

union dma_access_once_cmpl_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc_user_info *user_info;
		struct hfi2_bulksvc_cmpl cmpl;
		struct hfi2_bulksvc_user_mr_record *mr_record;
		u64 app_context;
		u32 access_key;
	};
};
static_assert(sizeof(union dma_access_once_cmpl_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_dma_access_once_complete(union hfi2_dms_completion_cookie *cookie, u16 flags, u64 imm_data, u64 order_key, int status)
{
	union dma_access_once_cmpl_cookie *dma_cookie =
		container_of(cookie, union dma_access_once_cmpl_cookie, dms);

	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	type_data.type_default.access_key = dma_cookie->access_key;

	give_completion(dma_cookie->user_info, dma_cookie->cmpl, dma_cookie->app_context, status, 
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);

	user_mr_record_put(dma_cookie->mr_record); // one-time
	hfi2_bulksvc_user_info_put(dma_cookie->user_info);
}

static void bulksvc_on_cmd_dma_access_once(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_dma_access_once const * const cmd)
{
	struct hfi2_bulksvc_cmpl cmpl;
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	__u32 status = -EINVAL;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	type_data.type_default.access_key = cmd->access_key;

	struct hfi2_bulksvc_user_mr_record* mr_record = lookup_user_mr_record(user_info, cmd->mr_key);

	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto compl_error;
	}
	if (0 != validate_mr_access(mr_record, cmd->offset, cmd->len)) {
		pr_err("%s:%d:%s() invalid MR access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->offset, cmd->len);
		goto compl_error;
	}

	hfi2_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	union dma_access_once_cmpl_cookie c = { .dms = {{0}} };
	c.user_info = user_info;
	c.cmpl = cmpl;
	c.mr_record = mr_record;
	c.app_context = cmd->app_context;
	c.access_key = cmd->access_key;

	struct hfi2_dms_page_provider pp = user_mr_page_provider(mr_record);
	/*
	 * hfi2_dms_register_access() bounds the access against
	 * page_provider.length (= mr->dms_mr.user.len) in relative
	 * coordinates, so VADDR-mode cmd->offset must be normalized
	 * to an MR-relative offset.  validate_mr_access() above has
	 * already confirmed cmd->offset is within
	 * [user.addr, user.addr + user.len] in VADDR mode, so the
	 * subtraction cannot underflow.
	 */
	u64 register_offset;

	if (mr_record->dms_mr.mode == HFI2_DMS_MR_MODE_VADDR)
		register_offset = cmd->offset - mr_record->dms_mr.user.addr;
	else
		register_offset = cmd->offset;

	dd_dev_dbg(svc->dd, "DMA_ACCESS_ONCE: mr_key=%u offset=%llu register_offset=%llu len=%u pp.length=%llu pp.region_offset=%llu\n",
		   cmd->mr_key, cmd->offset, register_offset, cmd->len,
		   pp.length, mr_record->dms_mr.region_offset);
	int rc = hfi2_dms_register_access(hfi2_bulksvc_user_dms(user_info), pp,
		register_offset, cmd->len,
		(union hfi2_dms_key) {
			.client = user_info->client_key,
			.access = cmd->access_key,
		},
		(struct hfi2_dms_access_completion) {
			.fn = on_dma_access_once_complete,
			.cookie = c.dms,
		},
		HFI2_DMS_ACCESS_TYPE_EPHEMERAL, NULL);

	if (rc < 0) {
		dd_dev_err(svc->dd, "DMA_ACCESS_ONCE: register_access FAILED rc=%d offset=%llu register_offset=%llu len=%u pp.length=%llu\n",
			   rc, cmd->offset, register_offset, cmd->len, pp.length);
		status = (u32)rc;
		user_mr_record_put(mr_record);
		hfi2_bulksvc_user_info_put(user_info);
		goto compl_error;
	}
	dd_dev_dbg(svc->dd, "DMA_ACCESS_ONCE: registered access_key=%u client_key=%u\n",
		   cmd->access_key, user_info->client_key);

	return;

compl_error:
	give_completion(user_info, cmpl, cmd->app_context, status, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);
	return;
}

///
/// GRANT ACCESS TO MEMORY REGION ONGOING
///

union dma_access_notify_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc *svc;
		struct hfi2_bulksvc_user_mr_access_record *access_record;
	};
};
static_assert(sizeof(union dma_access_notify_cookie) == sizeof(union hfi2_dms_completion_cookie));

union dma_access_disable_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc *svc;
		struct hfi2_bulksvc_user_mr_access_record *access_record;
		u64 app_context;
		u32 access_key;
		/*
		 * cmpl_id/flags captured from the disable command at submission
		 * so the async callback routes the completion to the user's
		 * chosen target (CQ or CNTR) instead of hardcoding CQ via the
		 * enable-time cmplq_id stored on access_record.
		 */
		u32 cmpl_id;
		__u64 flags;
	};
};
static_assert(sizeof(union dma_access_disable_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_access_disable_complete(union hfi2_dms_completion_cookie *cookie, int status)
{
	union dma_access_disable_cookie *dc =
		container_of(cookie, union dma_access_disable_cookie, dms);
	struct hfi2_bulksvc_user_mr_access_record *access_record = dc->access_record;
	struct hfi2_bulksvc_user_info *user_info = access_record->user_info;

	if (user_info) {
		struct hfi2_bulksvc_cmpl cmpl =
			get_cmpl(dc->svc, user_info, dc->cmpl_id, dc->flags);

		if (cmpl_has_ptr(&cmpl)) {
			union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

			type_data.type_default.access_key = dc->access_key;
			give_completion(user_info, cmpl, dc->app_context, status,
					HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
					type_data);
		}
	}

	user_mr_access_record_destroy(access_record);
}

/* DMA_ACCESS_DISABLE completion for a target access_key that has no
 * access_record -- an EPHEMERAL (DMA_ACCESS_ONCE/REG_DMA_BUFFER) registration
 * never allocates one. See bulksvc_on_cmd_dma_access_disable().
 */
union dma_access_cancel_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc *svc;
		struct hfi2_bulksvc_user_info *user_info;
		u64 app_context;
		u32 access_key;
		u32 cmpl_id;
		__u64 flags;
	};
};

static_assert(sizeof(union dma_access_cancel_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_access_cancel_complete(union hfi2_dms_completion_cookie *cookie, int status)
{
	union dma_access_cancel_cookie *cc =
		container_of(cookie, union dma_access_cancel_cookie, dms);
	struct hfi2_bulksvc_cmpl cmpl = get_cmpl(cc->svc, cc->user_info, cc->cmpl_id, cc->flags);

	if (cmpl_has_ptr(&cmpl)) {
		union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

		type_data.type_default.access_key = cc->access_key;
		give_completion(cc->user_info, cmpl, cc->app_context, status,
				HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);
	}

	hfi2_bulksvc_user_info_put(cc->user_info);
}

static void on_access_teardown_complete(union hfi2_dms_completion_cookie *cookie, int status)
{
	union dma_access_teardown_cookie *tc =
		container_of(cookie, union dma_access_teardown_cookie, dms);

	user_mr_access_record_destroy(tc->access_record);
}

static void on_dma_access_notify(union hfi2_dms_completion_cookie *cookie, u16 flags, u64 imm_data, u64 order_key, int status)
{
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	struct hfi2_bulksvc_cmpl cmpl;

	union dma_access_notify_cookie *access_cookie =
		container_of(cookie, union dma_access_notify_cookie, dms);
	struct hfi2_bulksvc_user_mr_access_record *access_record = access_cookie->access_record;

	if (access_record == NULL) {
		pr_err("%s:%d:%s() ERROR: access_record is NULL in notify\n", __FILENAME__, __LINE__, __func__);
		return;
	}

	struct hfi2_bulksvc_user_info *user_info = access_record->user_info;

	/*
	 * Only deliver a notification when the user explicitly selected a target
	 * (CQ or CNTR) at enable time. A flags==0 target must NOT fall through to
	 * get_cmpl()'s default-CQ behavior, which would post a TYPE_NOTIFY entry
	 * with app_context 0 and corrupt the user's CQ stream (STL-75231).
	 */
	if (access_record->notify_cmpl_id == (u32)-1 ||
	    !(access_record->notify_flags &
	      (HFI2_BULKSVC_CMPL_CQ | HFI2_BULKSVC_CMPL_CNTR)))
		return;

	cmpl = get_cmpl(access_cookie->svc, user_info,
			access_record->notify_cmpl_id,
			access_record->notify_flags);
	if (!cmpl_has_ptr(&cmpl))
		return;

	type_data.type_notify.access_key = access_record->access_key;
	type_data.type_notify.flags = flags;
	type_data.type_notify.imm_data = imm_data;

	give_completion(user_info, cmpl,
			access_record->notify_app_context,
			status, HFI2_HFISVC_CQ_ENTRY_TYPE_NOTIFY, type_data);
}

static void bulksvc_on_cmd_dma_access_enable(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_dma_access_enable const * const cmd)
{
	int rc;
	struct hfi2_bulksvc_cmpl cmpl;
	__u32 status = -EINVAL;
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };
	type_data.type_default.access_key = cmd->access_key;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	struct hfi2_bulksvc_user_mr_record *mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto exit;
	}

	struct hfi2_bulksvc_user_mr_access_record *access_record =
		lookup_user_mr_access_record(user_info, cmd->access_key);

	if (access_record) {
		pr_err("%s:%d:%s() access key %u already exists\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key);
		status = -EEXIST;
		goto exit;
	}

	access_record = user_mr_access_record_create_and_insert(user_info,
		cmd->access_key, cmd->app_context, cmd->cmpl_id,
		cmd->notification_app_context, cmd->notification_cmpl_id,
		cmd->notification_flags, mr_record);
	if (!access_record) {
		pr_err("%s:%d:%s() failed to create access record for key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key);
		status = -ENOMEM;
		goto exit;
	}

	union dma_access_notify_cookie notify_cookie = { .dms = {{0}} };
	notify_cookie.svc = svc;
	notify_cookie.access_record = access_record;
	struct hfi2_dms_access_completion notification = {
		.fn = on_dma_access_notify,
		.cookie = notify_cookie.dms,
	};

	union hfi2_dms_key const dms_key = {
		.client = user_info->client_key,
		.access = cmd->access_key,
	};
	rc = hfi2_dms_register_access(hfi2_bulksvc_user_dms(user_info),
				      user_mr_page_provider(mr_record),
				      cmd->offset, cmd->len, dms_key,
				      notification, HFI2_DMS_ACCESS_TYPE_PERSISTENT,
				      NULL);

	if (rc < 0) {
		pr_err("%s:%d:%s() failed to enable DMA access for key %u: %d\n",
		       __FILENAME__, __LINE__, __func__, cmd->access_key, rc);
		user_mr_access_record_destroy_and_remove(access_record);
	}

	status = rc;

exit:
	give_completion(user_info, cmpl, cmd->app_context, status,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);
	return;
}

static void bulksvc_on_cmd_dma_access_disable(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_dma_access_disable const * const cmd)
{
	int rc;
	struct hfi2_bulksvc_cmpl cmpl;
	__u32 status = -EINVAL;
	union hfi2_bulksvc_cmplq_entry_type_data type_data = { 0 };

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	type_data.type_default.access_key = cmd->access_key;

	union hfi2_dms_key const dms_key = {
		.client = user_info->client_key,
		.access = cmd->access_key,
	};

	struct hfi2_bulksvc_user_mr_access_record *access_record =
		lookup_user_mr_access_record(user_info, cmd->access_key);
	if (!access_record) {
		/* No access_record => try this as a cancel of an
		 * outstanding EPHEMERAL registration, which never allocates one.
		 */
		union dma_access_cancel_cookie cc = { .dms = {{0}} };

		cc.svc = svc;
		cc.user_info = user_info;
		cc.app_context = cmd->app_context;
		cc.access_key = cmd->access_key;
		cc.cmpl_id = cmd->cmpl_id;
		cc.flags = cmd->flags;
		/* Callback may fire on any bulksvc thread iteration, not
		 * necessarily inline -- pin user_info for its lifetime.
		 */
		hfi2_bulksvc_user_info_get(user_info);
		rc = hfi2_dms_unregister_access(hfi2_bulksvc_user_dms(user_info), dms_key,
						(struct hfi2_dms_completion) {
							.fn = on_access_cancel_complete,
							.cookie = cc.dms,
						});

		if (rc == 0)
			return; /* callback owns the completion + user_info ref */

		hfi2_bulksvc_user_info_put(user_info);
		if (rc == -EALREADY) {
			status = -EALREADY;
		} else {
			pr_err("%s:%d:%s() invalid access key %u\n",
			       __FILENAME__, __LINE__, __func__, cmd->access_key);
			status = -EINVAL;
		}
		goto exit;
	}

	/* Unlink before unregister so destroy loop won't double-unregister;
	 * erase the index at the same point so a re-registered key cannot
	 * be shadowed by this dying record.
	 */
	list_del_init(&access_record->list_entry);
	xa_cmpxchg(&user_info->access_by_key, cmd->access_key,
		   access_record, NULL, GFP_ATOMIC);

	union dma_access_disable_cookie dc = { .dms = {{0}} };
	dc.svc = svc;
	dc.access_record = access_record;
	dc.app_context = cmd->app_context;
	dc.access_key = cmd->access_key;
	dc.cmpl_id = cmd->cmpl_id;
	dc.flags = cmd->flags;
	rc = hfi2_dms_unregister_access(hfi2_bulksvc_user_dms(user_info),
					dms_key,
					(struct hfi2_dms_completion) {
						.fn = on_access_disable_complete,
						.cookie = dc.dms,
					});

	if (rc == 0)
		return; /* callback owns completion + record cleanup */

	if (rc == -EALREADY) {
		/*
		 * Unregister already in progress (disable-vs-destroy race).
		 * The first accepted callback still owns access_record
		 * cleanup -- do NOT destroy here.  Report success to user.
		 */
		status = 0;
	} else {
		/* Hard error -- record already unlinked, destroy directly */
		user_mr_access_record_destroy(access_record);
		status = rc;
	}

exit:
	give_completion(user_info, cmpl, cmd->app_context, status,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, type_data);
	return;
}

///
/// INITIATED MEMORY REGION RDMA TRANSACTION
///

union initiated_mr_rdma_transact_completion_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc_user_info *user_info;
		struct hfi2_bulksvc_cmpl cmpl;
		u64 app_context;
		struct hfi2_bulksvc_user_mr_record *mr_record;
	};
};
static_assert(sizeof(union initiated_mr_rdma_transact_completion_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_mr_rdma_transact_complete(union hfi2_dms_completion_cookie *cookie, int status)
{
	union initiated_mr_rdma_transact_completion_cookie *mr_transact_cookie =
		container_of(cookie, union initiated_mr_rdma_transact_completion_cookie, dms);

	give_completion(mr_transact_cookie->user_info, mr_transact_cookie->cmpl, mr_transact_cookie->app_context,
			status, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, (union hfi2_bulksvc_cmplq_entry_type_data){0});

	user_mr_record_put(mr_transact_cookie->mr_record);
	hfi2_bulksvc_user_info_put(mr_transact_cookie->user_info);
}

static void bulksvc_on_cmd_rdma_read(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_rdma_read const * const cmd)
{
	u32 const target_lane = hfi2_bulksvc_client_key_lane(cmd->client_key);
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_user_mr_record *mr_record;
	u8 port_idx;
	u8 port;
	int rc = -EINVAL;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	port = (cmd->flags >> HFI2_BULKSVC_CMD_FLAG_PORT_SHIFT) & HFI2_BULKSVC_CMD_FLAG_PORT_MASK;
	port_idx = _port_to_port_idx(svc, port);

	mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record) {
		pr_err("%s:%d:%s() invalid MR key %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key);
		goto compl_error;
	}
	if (0 != validate_mr_access(mr_record, cmd->mr_offset, cmd->len_bytes)) {
		pr_err("%s:%d:%s() invalid MR access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->mr_offset, cmd->len_bytes);
		goto compl_error;
	}

	hfi2_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	/* Initiator-side promote: this rank is starting an RDMA-READ
	 * targeted at its own MR.  Complementary to the bilateral
	 * page_provider.promote callback that fires on the responder
	 * when a remote-initiated transfer hits this rank's MR via an
	 * access lookup.  See user_mr_promote (idempotent).
	 */
	user_mr_promote(&mr_record->dms_mr);

	union initiated_mr_rdma_transact_completion_cookie c = { .dms = {{0}} };
	c.user_info = user_info;
	c.cmpl = cmpl;
	c.app_context = cmd->app_context;
	c.mr_record = mr_record;
	rc = hfi2_dms_read_data(
		hfi2_bulksvc_user_dms(user_info), port_idx, cmd->lid,
		(union hfi2_dms_key) { .access = cmd->access_key, .client = cmd->client_key },
		cmd->remote_offset, cmd->len_bytes,
		user_mr_page_provider(mr_record), cmd->mr_offset,
		cmd->flags, hfi2_dms_submit_flags_set_target_lane(0, target_lane),
		cmd->imm_data,
		(struct hfi2_dms_completion) {
			.fn = on_mr_rdma_transact_complete,
			.cookie = c.dms,
		},
		HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED,
		HFI2_DMS_TRANSFER_HANDLE_NONE, NULL);

	if (rc < 0) {
		pr_err("Could not initiate RDMA read: %d\n", rc);
		user_mr_record_put(mr_record);
		hfi2_bulksvc_user_info_put(user_info);
		goto compl_error;
	}

	return;

compl_error:
	give_completion(user_info, cmpl, cmd->app_context, (u32)rc, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});
}

/*
 * Drain any triggers whose target_value is already satisfied by the
 * counter's current VALUE.  Triggered-op cmd handlers must call this
 * after a successful enqueue_trigger_cmd(), otherwise an op posted
 * against an already-satisfied counter sits in the ring until some
 * unrelated future cntr_add releases it -- by then the userspace
 * caller has moved on, and the orphan completion lands in a different
 * test's CQ as "unexpected context X, expected Y".
 *
 * process_triggers_for_cntr() already handles back-pressure (inflight
 * caps, completion-overflow), so this is safe to invoke from the cmd
 * handler context.
 */
static inline void dispatch_satisfied_triggers(struct hfi2_bulksvc *svc,
		struct hfi2_bulksvc_user_info *user_info,
		struct hfi2_bulksvc_cntr *cntr)
{
	u8 *base = (u8 *)cntr->page_kaddr;
	u64 *value_addr = (u64 *)(base + cntr->value_offset);
	u64 cur_value = READ_ONCE(*value_addr);

	process_triggers_for_cntr(svc, user_info, cntr, cur_value);
}

static void bulksvc_on_cmd_rdma_read_triggered(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd const * const ucmd)
{
	const struct hfi2_bulksvc_cmd_rdma_read_triggered * const cmd = 
		&ucmd->payld[0].rdma_read_triggered;
	int rc = -EINVAL;

	/* Validate completion id early to avoid leaking in flight slots in 
	 * process_triggers_for_cntr() if the completion id is invalid. 
	 */
	struct hfi2_bulksvc_cmpl cmpl = get_cmpl(svc, user_info, cmd->rdma_read.cmpl_id, cmd->rdma_read.flags);
	if (!cmpl_has_ptr(&cmpl)) {
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	/* Validate counter id */
	struct hfi2_bulksvc_cntr *cntr = get_cntr(svc, user_info, cmd->trigger_cntr_id);
	if (!cntr)
		goto compl_error;

	union {
		struct hfi2_bulksvc_cmd cmd;
		u8 bytes[BULKSVC_TRIG_CMD_MAX_SIZE];  /* 128B */
	} copy;

	memset(&copy, 0, sizeof(copy));
	copy.cmd.hdr.op = HFI2_BULKSVC_CMD_RDMA_READ;
	copy.cmd.hdr.num_blocks = ((sizeof(struct hfi2_bulksvc_cmd_hdr) + \
		sizeof(struct hfi2_bulksvc_cmd_rdma_read) + \
		(CACHELINE_SIZE - 1)) / CACHELINE_SIZE);

	copy.cmd.payld[0].rdma_read = cmd->rdma_read;

	if (!IS_POW2(cntr->trig_ring.cap) && cntr->trig_ring.cap != 0) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid ring capacity %u for cntr %u\n",
			   __FILENAME__, __LINE__, __func__, cntr->trig_ring.cap, 
			   cmd->trigger_cntr_id);
		goto compl_error;
	}

	rc = enqueue_trigger_cmd(&cntr->trig_ring, &copy.cmd, cmd->target_value);
	if (rc) {
		dd_dev_err(svc->dd, "%s:%d:%s() trigger ring full for cntr %u; dropping cmd\n",
			   __FILENAME__, __LINE__, __func__, cmd->trigger_cntr_id);
		goto compl_error;
	}

	/* The CQ credit remains reserved while the command is parked. */
	decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);

	dispatch_satisfied_triggers(svc, user_info, cntr);

	return;

compl_error:

	give_completion(user_info, cmpl,  cmd->rdma_read.app_context, (u32)rc, 
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});

	return;
}

static void bulksvc_on_cmd_rdma_write(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_rdma_write const * const cmd)
{
	u32 const target_lane = hfi2_bulksvc_client_key_lane(cmd->client_key);
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_user_mr_record *mr_record;
	u8 port_idx;
	u8 port;
	int rc = -EINVAL;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	port = (cmd->flags >> HFI2_BULKSVC_CMD_FLAG_PORT_SHIFT) & HFI2_BULKSVC_CMD_FLAG_PORT_MASK;
	port_idx = _port_to_port_idx(svc, port);

	mr_record = lookup_user_mr_record(user_info, cmd->mr_key);
	if (!mr_record || validate_mr_access(mr_record, cmd->mr_offset, cmd->len_bytes) < 0) {
		pr_err("%s:%d:%s() invalid MR key %u or access for key %u, offset %llu, len %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->mr_key, cmd->mr_key, cmd->mr_offset, cmd->len_bytes);
		goto compl_error;
	}

	hfi2_bulksvc_user_info_get(user_info);
	user_mr_record_get(mr_record);

	/* Initiator-side promote: this rank is starting an RDMA-WRITE
	 * sourced from its own MR.  Complementary to the bilateral
	 * page_provider.promote callback that fires on the responder
	 * when a remote-initiated transfer targets this rank's MR via
	 * an access lookup.  See user_mr_promote (idempotent).
	 */
	user_mr_promote(&mr_record->dms_mr);

	union initiated_mr_rdma_transact_completion_cookie c = { .dms = {{0}} };
	c.user_info = user_info;
	c.cmpl = cmpl;
	c.app_context = cmd->app_context;
	c.mr_record = mr_record;
	rc = hfi2_dms_write_data(hfi2_bulksvc_user_dms(user_info), port_idx,
				 cmd->lid,
				 (union hfi2_dms_key) {
					.access = cmd->access_key,
					.client = cmd->client_key
				 },
				 cmd->remote_offset, cmd->len_bytes,
				 user_mr_page_provider(mr_record), cmd->mr_offset,
				 (u16)cmd->flags,
				 hfi2_dms_submit_flags_set_target_lane(0, target_lane),
				 cmd->imm_data,
				 (struct hfi2_dms_completion) {
					.fn = on_mr_rdma_transact_complete,
					.cookie = c.dms,
				 },
				 HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED,
				 HFI2_DMS_TRANSFER_HANDLE_NONE, NULL);

	if (rc < 0) {
		dd_dev_warn(svc->dd, "DMS_DIAG: RDMA_WRITE initiate FAILED rc=%d lid=%u len=%u mr_key=%u\n",
			    rc, cmd->lid, cmd->len_bytes, cmd->mr_key);
		user_mr_record_put(mr_record);
		hfi2_bulksvc_user_info_put(user_info);
		goto compl_error;
	}

	return;

compl_error:
	give_completion(user_info, cmpl, cmd->app_context, (u32)rc, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});
}


static void bulksvc_on_cmd_rdma_write_triggered(struct hfi2_bulksvc * const svc,
					    struct hfi2_bulksvc_user_info * const user_info,
					    struct hfi2_bulksvc_cmd const * const ucmd)
{
	const struct hfi2_bulksvc_cmd_rdma_write_triggered * const cmd =
		&ucmd->payld[0].rdma_write_triggered;

	int rc = -EINVAL;

	/* Validate completion id early to avoid leaking in flight slots in 
	 * process_triggers_for_cntr() if the completion id is invalid. 
	 */
	struct hfi2_bulksvc_cmpl cmpl = get_cmpl(svc, user_info, cmd->rdma_write.cmpl_id, cmd->rdma_write.flags);
	if (!cmpl_has_ptr(&cmpl)) {
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	/* Validate counter id */
	struct hfi2_bulksvc_cntr *cntr = get_cntr(svc, user_info, cmd->trigger_cntr_id);
	if (!cntr)
		goto compl_error;

	/* Prepare and enqueue a sanitized copy */
	union {
		struct hfi2_bulksvc_cmd cmd;
		u8 bytes[BULKSVC_TRIG_CMD_MAX_SIZE];  /* 128B */
	} copy;

	memset(&copy, 0, sizeof(copy));
	copy.cmd.hdr.op = HFI2_BULKSVC_CMD_RDMA_WRITE;
	copy.cmd.hdr.num_blocks = ((sizeof(struct hfi2_bulksvc_cmd_hdr) + \
		sizeof(struct hfi2_bulksvc_cmd_rdma_write) + \
		(CACHELINE_SIZE - 1)) / CACHELINE_SIZE);

	copy.cmd.payld[0].rdma_write = cmd->rdma_write;

	if (!IS_POW2(cntr->trig_ring.cap) && cntr->trig_ring.cap != 0) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid ring capacity %u for cntr %u\n",
			   __FILENAME__, __LINE__, __func__, cntr->trig_ring.cap,
			   cmd->trigger_cntr_id);
		goto compl_error;
	}

	rc = enqueue_trigger_cmd(&cntr->trig_ring, &copy.cmd, cmd->target_value);
	if (rc) {
		dd_dev_err(svc->dd, "%s:%d:%s() trigger ring full for cntr %u; dropping cmd\n",
			   __FILENAME__, __LINE__, __func__, cmd->trigger_cntr_id);
		goto compl_error;
	}

	/* The CQ credit remains reserved while the command is parked. */
	decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);

	dispatch_satisfied_triggers(svc, user_info, cntr);

	return;

compl_error:

	give_completion(user_info, cmpl, cmd->rdma_write.app_context, (u32)rc,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});

	return;
}

///
/// INITIATED VA RDMA TRANSACTION
///

union rdma_va_completion_cookie {
	union hfi2_dms_completion_cookie dms;
	struct {
		struct hfi2_bulksvc_user_info *user_info;
		struct hfi2_bulksvc_cmpl cmpl;
		u64 app_context;
		struct hfi2_bulksvc_ephemeral_mr *eph_mr;
	};
};
static_assert(sizeof(union rdma_va_completion_cookie) == sizeof(union hfi2_dms_completion_cookie));

static void on_rdma_va_complete(
	union hfi2_dms_completion_cookie * const cookie, int status)
{
	union rdma_va_completion_cookie * const read_cookie =
		container_of(cookie, union rdma_va_completion_cookie, dms);

	give_completion(read_cookie->user_info, read_cookie->cmpl, read_cookie->app_context, status, 
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT, (union hfi2_bulksvc_cmplq_entry_type_data){0});

	ephemeral_mr_put(read_cookie->eph_mr); // Implicitly one-time

	hfi2_bulksvc_user_info_put(read_cookie->user_info);
}

static void bulksvc_on_cmd_rdma_read_va(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_rdma_read_va const * const cmd)
{
	u32 const target_lane = hfi2_bulksvc_client_key_lane(cmd->client_key);
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_ephemeral_mr *eph_mr;
	u64 mr_offset;
	u8 port_idx;
	u8 port;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	hfi2_bulksvc_user_info_get(user_info);

	eph_mr = ephemeral_mr_create_va(user_info,
					cmd->vaddr,
					cmd->len_bytes);
	if (!eph_mr) {
		user_info->eph_mr_create_fail++;

		dd_dev_err(svc->dd, "%s:%d:%s() failed to create ephemeral user memory region metadata\n",
			   __FILENAME__, __LINE__, __func__);

		give_completion(user_info, cmpl, cmd->app_context, (u32)-EFAULT,
				HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
				(union hfi2_bulksvc_cmplq_entry_type_data){0});
		hfi2_bulksvc_user_info_put(user_info);
		return;
	}
	mr_offset = cmd->vaddr - eph_mr->dms_mr.user.addr;
	port = (cmd->flags >> HFI2_BULKSVC_CMD_FLAG_PORT_SHIFT) & HFI2_BULKSVC_CMD_FLAG_PORT_MASK;
	port_idx = _port_to_port_idx(svc, port);

	union rdma_va_completion_cookie c = { .dms = {{0}} };
	c.user_info = user_info;
	c.cmpl = cmpl;
	c.app_context = cmd->app_context;
	c.eph_mr = eph_mr;
	int rc = hfi2_dms_read_data(hfi2_bulksvc_user_dms(user_info), port_idx, cmd->lid,
		(union hfi2_dms_key) { .access = cmd->access_key, .client = cmd->client_key },
		cmd->remote_offset, cmd->len_bytes,
		ephemeral_mr_page_provider(eph_mr), mr_offset,
		cmd->flags, hfi2_dms_submit_flags_set_target_lane(0, target_lane),
		cmd->imm_data,
		(struct hfi2_dms_completion) {
			.fn = on_rdma_va_complete,
			.cookie = c.dms,
		},
		HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED,
		HFI2_DMS_TRANSFER_HANDLE_NONE, NULL);
	if (rc < 0) {
		user_info->eph_mr_dispatch_fail++;

		dd_dev_warn(svc->dd, "DMS_DIAG: RDMA_READ_VA initiate FAILED rc=%d lid=%u len=%u\n",
			    rc, cmd->lid, cmd->len_bytes);
		give_completion(user_info, cmpl, cmd->app_context, (u32)rc,
				HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
				(union hfi2_bulksvc_cmplq_entry_type_data){0});
		ephemeral_mr_put(eph_mr);
		hfi2_bulksvc_user_info_put(user_info);
	}
}

static void bulksvc_on_cmd_rdma_read_va_triggered(struct hfi2_bulksvc * const svc,
					      struct hfi2_bulksvc_user_info * const user_info,
					      struct hfi2_bulksvc_cmd const * const ucmd)
{
	const struct hfi2_bulksvc_cmd_rdma_read_va_triggered * const cmd =
		&ucmd->payld[0].rdma_read_va_triggered;

	int rc = -EINVAL;

	/* Validate completion id early to avoid leaking in flight slots in 
	 * process_triggers_for_cntr() if the completion id is invalid. 
	 */
	struct hfi2_bulksvc_cmpl cmpl = get_cmpl(svc, user_info, cmd->rdma_read_va.cmpl_id, cmd->rdma_read_va.flags);
	if (!cmpl_has_ptr(&cmpl)) {
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	/* Validate counter id */
	struct hfi2_bulksvc_cntr *cntr = get_cntr(svc, user_info, cmd->trigger_cntr_id);
	if (!cntr)
		goto compl_error;

	/* Prepare and enqueue a sanitized copy */
	union {
		struct hfi2_bulksvc_cmd cmd;
		u8 bytes[BULKSVC_TRIG_CMD_MAX_SIZE];  /* 128B */
	} copy;

	memset(&copy, 0, sizeof(copy));
	copy.cmd.hdr.op = HFI2_BULKSVC_CMD_RDMA_READ_VA;
	copy.cmd.hdr.num_blocks = ((sizeof(struct hfi2_bulksvc_cmd_hdr) + \
		sizeof(struct hfi2_bulksvc_cmd_rdma_read_va) + \
		(CACHELINE_SIZE - 1)) / CACHELINE_SIZE);

	copy.cmd.payld[0].rdma_read_va = cmd->rdma_read_va;

	if (!IS_POW2(cntr->trig_ring.cap) && cntr->trig_ring.cap != 0) {
		dd_dev_err(svc->dd, "%s:%d:%s() invalid ring capacity %u for cntr %u\n",
			   __FILENAME__, __LINE__, __func__, cntr->trig_ring.cap,
			   cmd->trigger_cntr_id);
		goto compl_error;
	}

	rc = enqueue_trigger_cmd(&cntr->trig_ring, &copy.cmd, cmd->target_value);
	if (rc) {
		dd_dev_err(svc->dd, "%s:%d:%s() trigger ring full for cntr %u; dropping cmd\n",
			   __FILENAME__, __LINE__, __func__, cmd->trigger_cntr_id);
		goto compl_error;
	}

	/* The CQ credit remains reserved while the command is parked. */
	decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);

	dispatch_satisfied_triggers(svc, user_info, cntr);

	return;

compl_error:

	give_completion(user_info, cmpl, cmd->rdma_read_va.app_context, (u32)rc,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});

	return;
}

static void bulksvc_on_cmd_cntr_add(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_cntr_add const * const cmd)
{
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_cntr *cntr;
	int status = -EINVAL;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	cntr = get_cntr(svc, user_info, cmd->cntr_id);
	if (!cntr)
		goto give_compl;

	if (cmd->flags & HFI2_BULKSVC_CNTR_VALUE)
		cntr_add(user_info, cntr, true, cmd->amount);
	if (cmd->flags & HFI2_BULKSVC_CNTR_ERROR)
		cntr_add(user_info, cntr, false, cmd->amount);

	status = 0;

give_compl:
	give_completion(user_info, cmpl, cmd->app_context, (u32)status,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});
}

static void bulksvc_on_cmd_cntr_set(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd_cntr_set const * const cmd)
{
	struct hfi2_bulksvc_cmpl cmpl;
	struct hfi2_bulksvc_cntr *cntr;
	int status = -EINVAL;

	cmpl = get_cmpl(svc, user_info, cmd->cmpl_id, cmd->flags);
	if (!cmpl_has_ptr(&cmpl)) {
		pr_err("%s:%d:%s() invalid cmpl id %u\n",
		       __FILENAME__, __LINE__, __func__, cmd->cmpl_id);
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		return;
	}

	cntr = get_cntr(svc, user_info, cmd->cntr_id);
	if (!cntr)
		goto give_compl;

	u8 *base = (u8 *)cntr->page_kaddr;

	if (cmd->flags & HFI2_BULKSVC_CNTR_VALUE) {
		u64 *value_addr = (u64 *)(base + cntr->value_offset);
		WRITE_ONCE(*value_addr, (u64)cmd->value);

		process_triggers_for_cntr(user_info->svc, user_info, cntr, (u64)cmd->value);
	}

	if (cmd->flags & HFI2_BULKSVC_CNTR_ERROR) {
		u64 *error_addr = (u64 *)(base + cntr->error_offset);
		WRITE_ONCE(*error_addr, (u64)cmd->value);
	}

	status = 0;

give_compl:
	give_completion(user_info, cmpl, cmd->app_context, (u32)status,
			HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
			(union hfi2_bulksvc_cmplq_entry_type_data){0});
}

static void bulksvc_on_user_cmd(struct hfi2_bulksvc * const svc,
	struct hfi2_bulksvc_user_info * const user_info,
	struct hfi2_bulksvc_cmd const * const cmd,
	union hfi2_bulksvc_userctxt_cmd_data *userctxt_data)
{
	if (WARN_ON(userctxt_data && userctxt_data->raw != 0 && cmd->hdr.op != HFI2_BULKSVC_CMD_MR_OPEN)) {
		dd_dev_err(svc->dd, "%s:%d:%s() unexpected userctxt_data for cmd op %u\n",
			   __FILENAME__, __LINE__, __func__, cmd->hdr.op);
		return;
	}

	switch (cmd->hdr.op) {
	case HFI2_BULKSVC_CMD_REG_DMA_BUFFER:
		bulksvc_on_cmd_reg_dma_buffer(svc, user_info,
					      &cmd->payld[0].register_dma_buffer);
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_VA:
		bulksvc_on_cmd_rdma_read_va(svc, user_info,
					    &cmd->payld[0].rdma_read_va);
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_VA_TRIGGERED:
		bulksvc_on_cmd_rdma_read_va_triggered(svc, user_info, cmd);
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ:
		bulksvc_on_cmd_rdma_read(svc, user_info,
					 &cmd->payld[0].rdma_read);
		break;
	case HFI2_BULKSVC_CMD_RDMA_READ_TRIGGERED:
		bulksvc_on_cmd_rdma_read_triggered(svc, user_info, cmd);
		break;
	case HFI2_BULKSVC_CMD_RDMA_WRITE:
		bulksvc_on_cmd_rdma_write(svc, user_info,
					  &cmd->payld[0].rdma_write);
		break;
	case HFI2_BULKSVC_CMD_RDMA_WRITE_TRIGGERED:
		bulksvc_on_cmd_rdma_write_triggered(svc, user_info, cmd);
		break;
	case HFI2_BULKSVC_CMD_MR_OPEN:
		bulksvc_on_cmd_mr_open(svc, user_info, &cmd->payld[0].mr_open, userctxt_data);
		break;
	case HFI2_BULKSVC_CMD_MR_CLOSE:
		bulksvc_on_cmd_mr_close(svc, user_info,
					&cmd->payld[0].mr_close);
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_ONCE:
		bulksvc_on_cmd_dma_access_once(svc, user_info,
					       &cmd->payld[0].dma_access_once);
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_ENABLE:
		bulksvc_on_cmd_dma_access_enable(svc, user_info,
						 &cmd->payld[0].dma_access_enable);
		break;
	case HFI2_BULKSVC_CMD_DMA_ACCESS_DISABLE:
		bulksvc_on_cmd_dma_access_disable(svc, user_info,
						  &cmd->payld[0].dma_access_disable);
		break;
	case HFI2_BULKSVC_CMD_CNTR_ADD:
		bulksvc_on_cmd_cntr_add(svc, user_info, &cmd->payld[0].cntr_add);
		break;
	case HFI2_BULKSVC_CMD_CNTR_SET:
		bulksvc_on_cmd_cntr_set(svc, user_info, &cmd->payld[0].cntr_set);
		break;
	case HFI2_BULKSVC_CMD_UVERBS_POST_SEND:
		bulksvc_on_cmd_uverbs_post_send(svc, user_info,
						&cmd->payld[0].uverbs_post_send);
		/* completion will come through rvt not us so try_complete wont be called */
		decrement_num_inflight(user_info, HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT);
		break;

	default:
		dd_dev_err(svc->dd, "%s:%d:%s() unknown bulksvc cmd op %u\n",
			   __FILENAME__, __LINE__, __func__, cmd->hdr.op);
		/* TODO enqueue failure somehow */
		break;
	}
}

/*
 * hfi2_dms_client_diag_access_fn impl. Read-only: must not advance
 * head_shadow, poll_single_client() alone owns draining the ring.
 */
bool bulksvc_user_diag_access(void *ctx, u32 access_key)
{
	struct hfi2_bulksvc_user_info *user_info = ctx;
	/* Pairs with the smp_store_release() in create_bulksvc_queue(). */
	u8 num_cmdqs = smp_load_acquire(&user_info->num_cmdqs);

	for (int i = 0; i < num_cmdqs; i++) {
		struct hfi2_bulksvc_queue_record *rec = &user_info->cmdq_records[i];

		/* Pairs with the smp_store_release() in create_bulksvc_queue(). */
		if (!smp_load_acquire(&rec->active))
			continue;

		u64 tail = atomic64_read_acquire(rec->tail);
		u64 head = rec->head_shadow;

		while (head < tail) {
			struct hfi2_bulksvc_cmd const *cmd =
				(struct hfi2_bulksvc_cmd const *)
				(rec->queue_buf_magic +
				 ((head & rec->idx_mask) * CACHELINE_SIZE));

			if ((head + cmd->hdr.num_blocks) > tail)
				break;

			switch (cmd->hdr.op) {
			case HFI2_BULKSVC_CMD_REG_DMA_BUFFER:
				if (cmd->payld[0].register_dma_buffer.access_key == access_key)
					return true;
				break;
			case HFI2_BULKSVC_CMD_DMA_ACCESS_ONCE:
				if (cmd->payld[0].dma_access_once.access_key == access_key)
					return true;
				break;
			case HFI2_BULKSVC_CMD_DMA_ACCESS_ENABLE:
				if (cmd->payld[0].dma_access_enable.access_key == access_key)
					return true;
				break;
			default:
				break;
			}

			head += cmd->hdr.num_blocks;
		}
	}

	return false;
}

static int poll_single_client(struct hfi2_bulksvc *svc,
			      struct hfi2_bulksvc_user_info *user_info)
{
	int processed = 0;

	if (!list_empty(&user_info->eph_mr_deferred_free)) {
		processed += ephemeral_mr_drain_adaptive(user_info);
		if (!list_empty(&user_info->eph_mr_deferred_free) &&
		    user_info->dirty_bit >= 0)
			set_bit(user_info->dirty_bit, svc->dirty_notify.bitmap);
	}

	/* Pins dropped; don't dispatch against freed MRs. */
	if (user_info->shutting_down)
		return processed;

	while (user_info->num_completion_overflows > 0) {
		u32 stack_top = user_info->num_completion_overflows - 1;
		struct hfi2_bulksvc_overflow_entry *oe =
			&user_info->completion_overflows[stack_top];
		int rc = try_give_completion(user_info, oe->cmplq_record,
					     &oe->cmplq_entry);
		if (rc == -EINVAL || rc == 0) {
			user_info->num_completion_overflows--;
			processed += 1;
		} else {
			break;
		}
	}

	bool too_many_inflight = user_info->num_inflight >= user_info->max_inflight;
	bool completions_overflowing = user_info->num_completion_overflows >
				       (user_info->completion_overflows_size / 2);
	/* Any residual overflow requires another drain pass. */
	if (too_many_inflight || completions_overflowing ||
	    user_info->num_completion_overflows > 0) {
		set_bit(user_info->dirty_bit, svc->dirty_notify.bitmap);
		return processed;
	}

	/*
	 * Back-pressure has cleared.  Retry counters that previously deferred
	 * fireable triggers; without this, deferred triggers starve when
	 * userspace has issued its final counter bump (no future cntr_add()
	 * would re-enter process_triggers_for_cntr()).  Each retry re-arms
	 * trig_dirty and the client dirty_bit if it back-pressures again.
	 */
	for (u64 i = find_first_bit(user_info->trig_dirty_bitmap,
				    user_info->num_cntrs);
	     i < user_info->num_cntrs;
	     i = find_next_bit(user_info->trig_dirty_bitmap,
			       user_info->num_cntrs, i + 1)) {
		struct hfi2_bulksvc_cntr *cntr = bulksvc_cntr_at(user_info, i);

		if (!cntr->active)
			continue;

		dispatch_satisfied_triggers(svc, user_info, cntr);
		processed += 1;

		if (user_info->num_inflight >= user_info->max_inflight)
			break;
	}

	u8 num_cmdqs_snapshot = smp_load_acquire(&user_info->num_cmdqs);

	bool handled_any = true;
	mutex_lock(&user_info->userctxt_cmdq_lock);
	while (user_info->num_inflight < user_info->max_inflight && handled_any) {
		handled_any = false;
		for (int cmdq_index = 0; cmdq_index < num_cmdqs_snapshot; ++cmdq_index) {
			struct hfi2_bulksvc_queue_record *rec =
				&user_info->cmdq_records[cmdq_index];
			/*
			 * Acquire pairs with the create_bulksvc_queue release.
			 * Read tail under the same active=true observation as
			 * head_shadow so both are from the same slot generation
			 * even if a release/recycle occurs concurrently.
			 */
			if (!smp_load_acquire(&rec->active))
				continue;

			const u64 tail_cached = atomic64_read_acquire(rec->tail);
			u64 head = rec->head_shadow;
			if (head >= tail_cached)
				continue;

			struct hfi2_bulksvc_cmd const * const next_cmd =
				(struct hfi2_bulksvc_cmd const * const)
				(rec->queue_buf_magic +
				 ((head & rec->idx_mask) * CACHELINE_SIZE));

			if ((head + next_cmd->hdr.num_blocks) > tail_cached)
				continue;

			/*
			 * If the target has no inflight credits, leave this cmdq's
			 * head unadvanced and continue servicing the other cmdqs.
			 */
			struct hfi2_bulksvc_queue_record *target =
				bulksvc_cmd_cmplq_target(svc, user_info, next_cmd);
			if (target && target->inflight >= target->max_inflight) {
				if (user_info->dirty_bit >= 0)
					set_bit(user_info->dirty_bit,
						svc->dirty_notify.bitmap);
				continue;
			}
			if (target)
				target->inflight += 1;

			user_info->num_inflight += 1;
			bulksvc_on_user_cmd(svc, user_info, next_cmd, NULL);
			head += next_cmd->hdr.num_blocks;
			rec->head_shadow = head;

			processed += 1;
			handled_any = true;
		}
		if (!list_empty(&user_info->userctxt_cmdq)) {
			struct hfi2_bulksvc_userctxt_cmd_entry *entry =
				list_first_entry(&user_info->userctxt_cmdq,
						 struct hfi2_bulksvc_userctxt_cmd_entry,
						 node);

			struct hfi2_bulksvc_queue_record *target =
				bulksvc_cmd_cmplq_target(svc, user_info, &entry->cmd);
			if (target && target->inflight >= target->max_inflight) {
				if (user_info->dirty_bit >= 0)
					set_bit(user_info->dirty_bit,
						svc->dirty_notify.bitmap);
			} else {
				if (target)
					target->inflight += 1;

				user_info->num_inflight += 1;
				bulksvc_on_user_cmd(svc, user_info, &entry->cmd, &entry->data);
				if (entry->cmd.hdr.op == HFI2_BULKSVC_CMD_MR_OPEN &&
				    entry->cmd.payld->mr_open.hmem_iface ==
				    HFI2_HFISVC_HMEM_IFACE_DMABUF) {
					struct dma_buf *db;
					db = entry->data.dmabuf_open.dmabuf;
					if (!IS_ERR_OR_NULL(db))
						dma_buf_put(db);
				}

				list_del(&entry->node);
				kfree(entry);

				processed += 1;
				handled_any = true;
			}
		}
	}

	for (int cmdq_index = 0; cmdq_index < num_cmdqs_snapshot; ++cmdq_index) {
		struct hfi2_bulksvc_queue_record *rec =
			&user_info->cmdq_records[cmdq_index];

		/* Acquire pairs with the create_bulksvc_queue release. */
		if (!smp_load_acquire(&rec->active))
			continue;
		/*
		 * A cmdq never produces completions, so its tail_shadow is
		 * free to track the last head value this thread published.
		 * Comparing against it avoids re-reading the shared head
		 * atomic (owned by the userspace producer's cacheline) just
		 * to discover whether we consumed anything since last pass.
		 */
		if (rec->tail_shadow != rec->head_shadow) {
			atomic64_set_release(rec->head, rec->head_shadow);
			rec->tail_shadow = rec->head_shadow;
		}
	}

	/*
	 * No unconditional cmplq head refresh here: try_give_completion()
	 * refreshes from the shared page when its cached head indicates a
	 * full ring, which is the only case where staleness matters
	 * (staleness can only over-report fullness, never corrupt).
	 */
	mutex_unlock(&user_info->userctxt_cmdq_lock);

	if (user_info->num_inflight >= user_info->max_inflight ||
	    !list_empty(&user_info->eph_mr_deferred_free))
		set_bit(user_info->dirty_bit, svc->dirty_notify.bitmap);

	return processed;
}

/*
 * Poll the clients bound to lane @l (l->client_bits), on that lane's
 * worker.  Only this lane's dirty bits are consumed, so another lane's
 * survive.  A client's add/release events run on this lane too, never
 * during a pass.
 */
int hfi2_bulksvc_poll_user_cmds(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc *svc = l->svc;
	unsigned long *bitmap = svc->dirty_notify.bitmap;
	unsigned int num_qwords = READ_ONCE(svc->dirty_notify.num_bitmap_qwords);
	int processed = 0;

	for (unsigned int w = 0; w < num_qwords; w++) {
		unsigned long const mask = READ_ONCE(l->client_bits[w]);
		unsigned long dirty;

		if (!(READ_ONCE(bitmap[w]) & mask))
			continue;
		dirty = atomic_long_fetch_andnot(mask,
						 (atomic_long_t *)&bitmap[w]) & mask;

		while (dirty) {
			int bit = __ffs(dirty);
			struct hfi2_bulksvc_user_info *user_info;

			dirty &= ~(1UL << bit);
			user_info = READ_ONCE(svc->dirty_notify.client_map[w * BITS_PER_LONG +
									   bit]);
			if (unlikely(!user_info))
				continue;
			processed += poll_single_client(svc, user_info);
		}
	}

	return processed;
}

static int pages_memcpy(struct page **pages, u64 offset, u64 size,
			void *data, const bool is_read)
{
	u8 *cdata = data;

	while (size > 0) {
		u64 page_index = offset / PAGE_SIZE;
		u64 offset_in_page = offset % PAGE_SIZE;
		u64 to_copy = min_t(u64, size, PAGE_SIZE - offset_in_page);
		u8 *kaddr;

		/* Fail safe if the page was not pinned before access. */
		if (WARN_ON_ONCE(!pages[page_index]))
			return -EFAULT;

		kaddr = kmap_local_page(pages[page_index]);

		if (is_read)
			memcpy(cdata, kaddr + offset_in_page, to_copy);
		else
			memcpy(kaddr + offset_in_page, cdata, to_copy);

		kunmap_local(kaddr);

		size -= to_copy;
		offset += to_copy;
		cdata += to_copy;
	}

	return 0;
}

static int dms_mr_host_memcpy(struct hfi2_dms_mr *mr, u64 offset, u64 size, void *data, const bool is_read)
{
	struct hfi2_bulksvc_user_mr_record *mr_record;
	struct hfi2_bulksvc_user_mr_record_ext *ext;
	struct hfi2_mem_region *hfi2_mr;
	unsigned int from_page;
	unsigned int npages;
	int ret;

	if (WARN_ON(mr == NULL))
		return -EINVAL;
	if (WARN_ON(offset > mr->extended_vaddr.len ||
		    size > mr->extended_vaddr.len - offset))
		return -EINVAL;
	if (!size)
		return 0;

	mr_record = container_of(mr, struct hfi2_bulksvc_user_mr_record, dms_mr);
	hfi2_mr = mr_record->mem_region.hfi2_mr;
	if (WARN_ON(!hfi2_mr))
		return -EFAULT;

	ext = user_mr_record_ext(mr_record);
	if (WARN_ON_ONCE(!ext->pin_owner) || WARN_ON_ONCE(!ext->pin_owner->svc))
		return -EFAULT;

	/* Make sure the range is pinned before accessing it. */
	from_page = offset / PAGE_SIZE;
	npages = DIV_ROUND_UP(offset + size, PAGE_SIZE) - from_page;
	ret = hfi2_mem_region_pin_range(ext->pin_owner->svc->dd, hfi2_mr,
					from_page, npages, !is_read);
	if (ret < 0)
		return ret;

	return pages_memcpy(hfi2_mr->pages, offset, size, data, is_read);
}

static int dms_ephemeral_mr_host_memcpy(struct hfi2_dms_mr *mr, u64 offset,
				       u64 size, void *data,
				       const bool is_read)
{
	struct hfi2_bulksvc_ephemeral_mr *eph_mr;
	unsigned int from_page;
	unsigned int npages;
	int ret;

	if (WARN_ON(!mr))
		return -EINVAL;
	if (WARN_ON(offset > mr->extended_vaddr.len ||
		    size > mr->extended_vaddr.len - offset))
		return -EINVAL;

	eph_mr = container_of(mr, struct hfi2_bulksvc_ephemeral_mr, dms_mr);
	if (WARN_ON_ONCE(!eph_mr->user_info || !eph_mr->user_info->svc))
		return -EFAULT;

	from_page = offset / PAGE_SIZE;
	npages = DIV_ROUND_UP(offset + size, PAGE_SIZE) - from_page;
	ret = hfi2_mem_region_pin_range(eph_mr->user_info->svc->dd,
					eph_mr->hfi2_mr, from_page, npages,
					!is_read);
	if (ret < 0) {
		eph_mr->user_info->eph_mr_pin_fail++;
		dd_dev_warn_ratelimited(eph_mr->user_info->svc->dd,
			"DMS_DIAG: ephemeral memcpy demand-pin failed ret=%d offset=%llu size=%llu\n",
			ret, offset, size);
		return ret;
	}

	return pages_memcpy(eph_mr->hfi2_mr->pages, offset, size, data, is_read);
}

/* Pages one eager PIO payload can span (PIO max plus one page of offset). */
#define BULKSVC_PIO_WRITE_MAX_PAGES \
	(DIV_ROUND_UP(SCS_BULKSVC_CREDITS * PIO_BLOCK_SIZE, PAGE_SIZE) + 1)

/*
 * Write [@offset, @offset + @len) of @pages to PIO at @dest as packed qwords,
 * zero-padding the last partial qword (the page_provider pio_write contract).
 * Pages are reached through the kernel direct map, which is permanent because
 * hfi2 builds only for 64-bit architectures without highmem.  The caller
 * holds a reference on every page in the range, so none can be freed during
 * the copy.
 */
static void pages_pio_write(struct page **pages, u64 offset, u64 len,
			    void __iomem *dest)
{
	struct hfi2_dms_pio_wr w = { .dest = dest };

	BUILD_BUG_ON(IS_ENABLED(CONFIG_HIGHMEM));

	while (len > 0) {
		u64 page_index = offset / PAGE_SIZE;
		u64 offset_in_page = offset % PAGE_SIZE;
		u32 n = min_t(u64, len, PAGE_SIZE - offset_in_page);

		hfi2_dms_pio_wr_bytes(&w,
				      (u8 *)page_address(pages[page_index]) +
				      offset_in_page, n);
		offset += n;
		len -= n;
	}
	hfi2_dms_pio_wr_finish(&w);
}

/*
 * pio_write for a host memory region.  A CPU copy to PIO needs only the
 * kernel address of each source page and a reference that keeps the page
 * from being freed for the length of the copy; it does not need the region
 * pinned for DMA.
 *
 * If the range is already pinned (the pin bitmap; the usual case for a
 * reused buffer) the region's pages[] already hold references, so copy from
 * them.  Otherwise take a short-term reference on each page of the range
 * with get_user_pages_remote() on the owning address space, copy, and drop
 * the references.  That path does not pin the pages long term, account them
 * against the pinned-memory limit, DMA-map them or mark them in the region's
 * pin bitmap.  Every page is looked up before the first PIO store, so a
 * failure writes nothing, as the pio_write contract requires.  May sleep
 * (mmap lock, page fault-in); the send context just waits meanwhile.
 */
static int mem_region_pio_write(struct hfi2_mem_region *hfi2_mr, u64 offset,
				u64 len, void __iomem *dest)
{
	struct page *pages[BULKSVC_PIO_WRITE_MAX_PAGES];
	unsigned int const first = offset / PAGE_SIZE;
	unsigned int const npages = DIV_ROUND_UP(offset + len, PAGE_SIZE) -
				    first;
	struct mm_struct *mm = hfi2_mr->rb.handler->mn.mm;
	int locked = 1;
	long got;

	if (unlikely(first > hfi2_mr->npages_total ||
		     npages > hfi2_mr->npages_total - first))
		return -EINVAL;

	if (hfi2_mem_region_range_pinned(hfi2_mr, first, npages)) {
		pages_pio_write(hfi2_mr->pages, offset, len, dest);
		return 0;
	}

	if (WARN_ON_ONCE(npages > ARRAY_SIZE(pages)))
		return -EINVAL;
	if (!mmget_not_zero(mm))
		return -EFAULT;

	mmap_read_lock(mm);
	got = get_user_pages_remote(mm, hfi2_mr->rb.addr +
					    (unsigned long)first * PAGE_SIZE,
					    npages, 0, pages, &locked);
	if (locked)
		mmap_read_unlock(mm);
	mmput_async(mm);

	if (got != npages) {
		if (got > 0)
			release_pages(pages, got);
		return got < 0 ? got : -EFAULT;
	}

	pages_pio_write(pages, offset - (u64)first * PAGE_SIZE, len, dest);
	release_pages(pages, npages);
	return 0;
}

/* pio_write for a user host MR. */
static int dms_mr_host_pio_write(struct hfi2_dms_mr *mr, u64 offset, u64 len,
				 void __iomem *dest)
{
	struct hfi2_bulksvc_user_mr_record *mr_record;
	struct hfi2_mem_region *hfi2_mr;

	if (WARN_ON(!mr))
		return -EINVAL;
	if (WARN_ON(offset > mr->extended_vaddr.len ||
		    len > mr->extended_vaddr.len - offset))
		return -EINVAL;
	if (!len)
		return 0;

	mr_record = container_of(mr, struct hfi2_bulksvc_user_mr_record, dms_mr);
	if (WARN_ON_ONCE(mr_record->mr_type == HFI2_BULKSVC_MR_TYPE_DMABUF))
		return -EINVAL;
	hfi2_mr = mr_record->mem_region.hfi2_mr;
	if (WARN_ON(!hfi2_mr))
		return -EFAULT;

	return mem_region_pio_write(hfi2_mr, offset, len, dest);
}

/* pio_write for an ephemeral host MR. */
static int dms_ephemeral_mr_host_pio_write(struct hfi2_dms_mr *mr, u64 offset,
					   u64 len, void __iomem *dest)
{
	struct hfi2_bulksvc_ephemeral_mr *eph_mr;

	if (WARN_ON(!mr))
		return -EINVAL;
	if (WARN_ON(offset > mr->extended_vaddr.len ||
		    len > mr->extended_vaddr.len - offset))
		return -EINVAL;
	if (!len)
		return 0;

	eph_mr = container_of(mr, struct hfi2_bulksvc_ephemeral_mr, dms_mr);
	if (WARN_ON_ONCE(!eph_mr->hfi2_mr))
		return -EFAULT;

	return mem_region_pio_write(eph_mr->hfi2_mr, offset, len, dest);
}

static int dms_mr_dmabuf_memcpy(struct hfi2_dms_mr *mr, u64 offset, u64 size, void *data, const bool is_read)
{
	if (WARN_ON(!mr) || WARN_ON(!data)) {
		return -EINVAL;
	}

	struct hfi2_bulksvc_user_mr_record *mr_record = container_of(mr, struct hfi2_bulksvc_user_mr_record, dms_mr);
	if (WARN_ON(mr_record->mr_type != HFI2_BULKSVC_MR_TYPE_DMABUF)) {
		pr_err("dms_mr_dmabuf_memcpy called on unexpected mr_type %d\n", mr_record->mr_type);
		return -EINVAL;
	}
	if (WARN_ON(mr_record->mem_region.fixup_mapping_type != HFI2_BULKSVC_FIXUP_CPU_MAPPING_VMAP)) {
		pr_err("dms_mr_dmabuf_memcpy called on unexpected fixup_mapping_type %d\n", mr_record->mem_region.fixup_mapping_type);
		return -EINVAL;
	}

	int rc = dma_buf_begin_cpu_access(mr_record->mem_region.dma_buf, is_read ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	if (WARN_ON(rc != 0)) {
		pr_err("dma_buf_begin_cpu_access failed: %d\n", rc);
		return rc;
	}

	u8 *cdata = (u8 *)data;
	int copy_rc = 0;

	if (mr_record->mem_region.fixup_mapping.vmap.is_iomem) {
		/*
		 * Device memory may be several non-contiguous chunks while the
		 * vmap is a single linear ioremap that assumes one contiguous
		 * range, so vaddr + offset is wrong past the first chunk. Copy
		 * per-page through dma_list[] (the scattered addresses SDMA
		 * uses) instead.
		 */
		u64 pos = offset;
		u64 remaining = size;

		while (remaining) {
			u64 pgidx = pos / PAGE_SIZE;
			u64 pgoff = pos & (PAGE_SIZE - 1);
			u64 to_cpy = min_t(u64, PAGE_SIZE - pgoff, remaining);
			void __iomem *ipa;

			if (WARN_ON(pgidx >= mr->npages_total)) {
				copy_rc = -EFAULT;
				break;
			}

			ipa = ioremap(mr->dma_list[pgidx], PAGE_SIZE);
			if (WARN_ON(!ipa)) {
				copy_rc = -ENOMEM;
				break;
			}

			if (is_read)
				memcpy_fromio(cdata, ipa + pgoff, to_cpy);
			else
				memcpy_toio(ipa + pgoff, cdata, to_cpy);

			iounmap(ipa);
			cdata += to_cpy;
			pos += to_cpy;
			remaining -= to_cpy;
		}
	} else {
		/*
		 * Host memory: vmap stitches the pages into one contiguous
		 * kernel range, so a linear vaddr + offset copy is safe.
		 */
		u8 *vaddr = (u8 *)mr_record->mem_region.fixup_mapping.vmap.vaddr;

		if (is_read)
			memcpy(cdata, vaddr + offset, size);
		else
			memcpy(vaddr + offset, cdata, size);
	}

	rc = dma_buf_end_cpu_access(mr_record->mem_region.dma_buf, is_read ? DMA_FROM_DEVICE : DMA_TO_DEVICE);
	if (WARN_ON(rc != 0)) {
		pr_err("dma_buf_end_cpu_access failed: %d\n", rc);
		return rc;
	}

	return copy_rc;
}
