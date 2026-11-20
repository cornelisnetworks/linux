// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2026 - Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/overflow.h>
#include <linux/scatterlist.h>
#include <linux/dma-buf.h>
#include <linux/dma-resv.h>

#include "hfi2.h"
#include "dmabuf_core.h"

static unsigned long dmabuf_pin_limit = 1024;

static unsigned int dmabuf_cache_entries = 16;

static unsigned long dmabuf_cache_size = 1024;

/*
 * No recovery is possible: the exporter may relocate as soon as this returns,
 * which a transfer already holding DMA addresses cannot survive.
 */
static void hfi2_dmabuf_move_notify(struct dma_buf_attachment *attach)
{
	struct hfi2_dmabuf_pin *pin = attach->importer_priv;

	if (pin)
		atomic64_inc(&pin->ctx->n_faults);

	WARN_RATELIMIT(1,
		       "hfi2: unexpected move_notify on pinned dma-buf attachment\n");
}

static const struct dma_buf_attach_ops hfi2_dmabuf_attach_ops = {
	.allow_peer2peer = true,
	.invalidate_mappings = hfi2_dmabuf_move_notify,
};

static void dmabuf_pin_destroy(struct work_struct *work)
{
	struct hfi2_dmabuf_pin *pin =
		container_of(work, struct hfi2_dmabuf_pin, cleanup_work);
	struct hfi2_dmabuf_ctx *ctx = pin->ctx;

	dma_resv_lock(pin->db->resv, NULL);
	dma_buf_unmap_attachment(pin->dba, pin->sgt, HFI2_DMABUF_DIR);
	dma_buf_unpin(pin->dba);
	dma_resv_unlock(pin->db->resv);

	dma_buf_detach(pin->db, pin->dba);
	dma_buf_put(pin->db);

	atomic64_inc(&ctx->n_unpin);
	kfree(pin);

	/* Must follow every use of ctx. */
	if (atomic_dec_and_test(&ctx->n_destroy_pending))
		wake_up(&ctx->destroy_wq);
}

/*
 * Do not use execute_in_process_context(): it only defers when in_interrupt(),
 * which is false in the threaded SDMA IRQ that drops the final reference, so
 * the teardown would run inline and sleep on the reservation lock.
 *
 * bytes_pinned drops here, not in the deferred teardown, so that
 * dmabuf_cache_reclaim() sees the budget free on return.
 */
static void dmabuf_pin_release(struct kref *ref)
{
	struct hfi2_dmabuf_pin *pin =
		container_of(ref, struct hfi2_dmabuf_pin, ref);

	atomic64_sub(pin->bytes, &pin->ctx->bytes_pinned);

	atomic_inc(&pin->ctx->n_destroy_pending);
	INIT_WORK(&pin->cleanup_work, dmabuf_pin_destroy);
	schedule_work(&pin->cleanup_work);
}

void hfi2_dmabuf_pin_put(void *ptr)
{
	struct hfi2_dmabuf_pin *pin = ptr;

	kref_put(&pin->ref, dmabuf_pin_release);
}

/*
 * Never compare fd numbers: an fd may be closed and recycled for an unrelated
 * buffer while this pin still holds a reference to the original.
 */
bool hfi2_dmabuf_pin_covers(struct hfi2_dmabuf_pin *pin, struct dma_buf *db,
			    u64 bo_offset, size_t len)
{
	u64 end;

	if (!pin || pin->db != db)
		return false;

	if (check_add_overflow(bo_offset, (u64)len, &end))
		return false;

	return end <= db->size;
}

/* Resolves @fd to a buffer object first, for the reason above. */
bool hfi2_dmabuf_pin_matches_fd(struct hfi2_dmabuf_pin *pin, int fd,
				u64 bo_offset, size_t len)
{
	struct dma_buf *db;
	bool match;

	if (!pin || fd < 0)
		return false;

	db = dma_buf_get(fd);
	if (IS_ERR(db))
		return false;

	match = hfi2_dmabuf_pin_covers(pin, db, bo_offset, len);
	dma_buf_put(db);

	return match;
}

/* The cache holds a reference on every listed entry, so kref_get() is safe. */
static struct hfi2_dmabuf_pin *dmabuf_cache_lookup(struct hfi2_dmabuf_ctx *ctx,
						   struct dma_buf *db,
						   u64 bo_offset, size_t len)
{
	struct hfi2_dmabuf_pin *pin;
	unsigned long flags;

	spin_lock_irqsave(&ctx->cache_lock, flags);

	list_for_each_entry(pin, &ctx->cache_lru, cache_link) {
		if (!hfi2_dmabuf_pin_covers(pin, db, bo_offset, len))
			continue;

		kref_get(&pin->ref);
		list_move(&pin->cache_link, &ctx->cache_lru);
		spin_unlock_irqrestore(&ctx->cache_lock, flags);
		atomic64_inc(&ctx->n_hits);
		return pin;
	}

	spin_unlock_irqrestore(&ctx->cache_lock, flags);
	return NULL;
}

/* Caller drops the references outside the lock. Returns bytes unlisted. */
static u64 dmabuf_cache_evict_locked(struct hfi2_dmabuf_ctx *ctx,
				     struct list_head *doomed, u64 want_bytes)
{
	unsigned int depth = READ_ONCE(dmabuf_cache_entries);
	u64 byte_limit = (u64)READ_ONCE(dmabuf_cache_size) << 20;
	u64 freed = 0;

	lockdep_assert_held(&ctx->cache_lock);

	while (!list_empty(&ctx->cache_lru)) {
		struct hfi2_dmabuf_pin *victim;

		if (ctx->cache_count <= depth &&
		    (!byte_limit || ctx->cache_bytes <= byte_limit) &&
		    freed >= want_bytes)
			break;

		victim = list_last_entry(&ctx->cache_lru,
					 struct hfi2_dmabuf_pin, cache_link);
		list_move(&victim->cache_link, doomed);
		ctx->cache_count--;
		ctx->cache_bytes -= victim->bytes;
		freed += victim->bytes;
	}

	return freed;
}

static void dmabuf_cache_release_list(struct hfi2_dmabuf_ctx *ctx,
				      struct list_head *doomed)
{
	struct hfi2_dmabuf_pin *pin;
	struct hfi2_dmabuf_pin *tmp;

	list_for_each_entry_safe(pin, tmp, doomed, cache_link) {
		list_del_init(&pin->cache_link);
		atomic64_inc(&ctx->n_evictions);
		hfi2_dmabuf_pin_put(pin);
	}
}

/* Only idle pins free bytes; a pin a request still holds keeps its reference. */
static u64 dmabuf_cache_reclaim(struct hfi2_dmabuf_ctx *ctx, u64 want_bytes)
{
	LIST_HEAD(doomed);
	unsigned long flags;
	u64 freed;

	spin_lock_irqsave(&ctx->cache_lock, flags);
	freed = dmabuf_cache_evict_locked(ctx, &doomed, want_bytes);
	spin_unlock_irqrestore(&ctx->cache_lock, flags);

	dmabuf_cache_release_list(ctx, &doomed);

	return freed;
}

static void dmabuf_cache_insert(struct hfi2_dmabuf_ctx *ctx,
				struct hfi2_dmabuf_pin *pin)
{
	unsigned int depth = READ_ONCE(dmabuf_cache_entries);
	u64 byte_limit = (u64)READ_ONCE(dmabuf_cache_size) << 20;
	LIST_HEAD(doomed);
	unsigned long flags;

	if (!depth)
		return;

	/* Caching this would evict every other entry on its way back out. */
	if (byte_limit && pin->bytes > byte_limit)
		return;

	spin_lock_irqsave(&ctx->cache_lock, flags);

	if (!list_empty(&pin->cache_link)) {
		spin_unlock_irqrestore(&ctx->cache_lock, flags);
		return;
	}

	kref_get(&pin->ref);
	list_add(&pin->cache_link, &ctx->cache_lru);
	ctx->cache_count++;
	ctx->cache_bytes += pin->bytes;

	dmabuf_cache_evict_locked(ctx, &doomed, 0);

	spin_unlock_irqrestore(&ctx->cache_lock, flags);

	dmabuf_cache_release_list(ctx, &doomed);
}

void hfi2_dmabuf_cache_drain(struct hfi2_dmabuf_ctx *ctx)
{
	struct hfi2_dmabuf_pin *pin;
	struct hfi2_dmabuf_pin *tmp;
	LIST_HEAD(doomed);
	unsigned long flags;

	spin_lock_irqsave(&ctx->cache_lock, flags);
	list_splice_init(&ctx->cache_lru, &doomed);
	ctx->cache_count = 0;
	ctx->cache_bytes = 0;
	spin_unlock_irqrestore(&ctx->cache_lock, flags);

	list_for_each_entry_safe(pin, tmp, &doomed, cache_link) {
		list_del_init(&pin->cache_link);
		hfi2_dmabuf_pin_put(pin);
	}
}

/* Consumes the caller's reference on @db. */
static struct hfi2_dmabuf_pin *pin_dmabuf_range(struct hfi2_dmabuf_ctx *ctx,
						struct dma_buf *db,
						u64 bo_offset, size_t len,
						const char *what)
{
	struct hfi2_dmabuf_pin *pin;
	bool charged = false;
	u64 end;
	u64 limit;
	long wait_ret;
	int ret;

	if (check_add_overflow(bo_offset, (u64)len, &end) || end > db->size) {
		dd_dev_dbg(ctx->dd,
			   "%s: dmabuf range out of bounds: offset=0x%llx len=%zu size=%zu\n",
			   what, bo_offset, len, db->size);
		ret = -EINVAL;
		goto put_dmabuf;
	}

	/*
	 * dmabuf_pin_limit is a soft eviction watermark, not a hard admission
	 * cap. dma_buf_map_attachment() has no partial form, so a mapping always
	 * spans the whole buffer object, and the pin cache is one-pin-per-BO
	 * (hfi2_dmabuf_pin_covers() matches any sub-range of the same BO). A
	 * single multi-GiB GPU buffer therefore charges its whole db->size and
	 * can exceed the limit on its very first pin. Treating that as -ENOMEM
	 * false-fails a legitimate large mapping, which the OPX provider turns
	 * into a hard abort().
	 *
	 * Keep charging db->size so bytes_pinned continues to drive cache
	 * eviction pressure, but on over-limit shed idle cached pins via
	 * dmabuf_cache_reclaim() and then admit the pin regardless. The limit
	 * pushes the cache back toward the budget instead of rejecting a pin a
	 * live transfer needs.
	 */
	limit = (u64)READ_ONCE(dmabuf_pin_limit) << 20;
	if (limit) {
		if (atomic64_add_return(db->size, &ctx->bytes_pinned) > limit)
			dmabuf_cache_reclaim(ctx, db->size);
		charged = true;
	}

	pin = kzalloc(sizeof(*pin), GFP_KERNEL);
	if (!pin) {
		ret = -ENOMEM;
		goto uncharge;
	}

	pin->db = db;
	pin->ctx = ctx;
	pin->bytes = db->size;
	kref_init(&pin->ref);
	INIT_LIST_HEAD(&pin->cache_link);

	pin->dba = dma_buf_dynamic_attach(db, &ctx->dd->pcidev->dev,
					  &hfi2_dmabuf_attach_ops, pin);
	if (IS_ERR_OR_NULL(pin->dba)) {
		ret = IS_ERR(pin->dba) ? PTR_ERR(pin->dba) : -ENOMEM;
		dd_dev_dbg(ctx->dd, "%s: dma_buf_dynamic_attach failed %d\n",
			   what, ret);
		goto free_pin;
	}

	dma_resv_lock(db->resv, NULL);

	ret = dma_buf_pin(pin->dba);
	if (ret) {
		dma_resv_unlock(db->resv);
		dd_dev_dbg(ctx->dd, "%s: dma_buf_pin failed %d\n", what, ret);
		goto detach;
	}

	pin->sgt = dma_buf_map_attachment(pin->dba, HFI2_DMABUF_DIR);
	if (IS_ERR_OR_NULL(pin->sgt)) {
		ret = IS_ERR(pin->sgt) ? PTR_ERR(pin->sgt) : -ENOMEM;
		dma_buf_unpin(pin->dba);
		dma_resv_unlock(db->resv);
		dd_dev_dbg(ctx->dd, "%s: dma_buf_map_attachment failed %d\n",
			   what, ret);
		goto detach;
	}

	/*
	 * The scatterlist is valid but its contents may not be: the exporter
	 * migrates asynchronously, and a dynamic attachment does not get the
	 * wait that dma_buf_map_attachment() performs for static ones. Wait
	 * uninterruptibly and unbounded, as ib_umem_dmabuf_map_pages() does:
	 * the exporter contract is that migration signals the reservation's
	 * KERNEL fences in bounded time.
	 */
	wait_ret = dma_resv_wait_timeout(db->resv, DMA_RESV_USAGE_KERNEL, false,
					 MAX_SCHEDULE_TIMEOUT);
	if (wait_ret <= 0) {
		/* Returns jiffies remaining, which does not fit in an int. */
		ret = wait_ret ? (int)wait_ret : -ETIMEDOUT;
		dma_buf_unmap_attachment(pin->dba, pin->sgt, HFI2_DMABUF_DIR);
		dma_buf_unpin(pin->dba);
		dma_resv_unlock(db->resv);
		dd_dev_dbg(ctx->dd, "%s: dmabuf migration wait failed %d\n",
			   what, ret);
		goto detach;
	}

	dma_resv_unlock(db->resv);

	if (!charged)
		atomic64_add(pin->bytes, &ctx->bytes_pinned);
	atomic64_inc(&ctx->n_pin);

	return pin;

detach:
	dma_buf_detach(db, pin->dba);
free_pin:
	kfree(pin);
uncharge:
	if (charged)
		atomic64_sub(db->size, &ctx->bytes_pinned);
put_dmabuf:
	dma_buf_put(db);
	return ERR_PTR(ret);
}

struct hfi2_dmabuf_pin *hfi2_dmabuf_pin_get(struct hfi2_dmabuf_ctx *ctx, int fd,
					    u64 bo_offset, size_t len,
					    const char *what)
{
	struct hfi2_dmabuf_pin *pin;
	struct dma_buf *db;
	bool from_cache;

	/* fd 0 is legal. */
	if (fd < 0) {
		dd_dev_dbg(ctx->dd, "%s: invalid dmabuf fd %d\n", what, fd);
		return ERR_PTR(-EINVAL);
	}

	db = dma_buf_get(fd);
	if (IS_ERR(db)) {
		dd_dev_dbg(ctx->dd, "%s: dma_buf_get(%d) failed (%pe)\n", what,
			   fd, db);
		return ERR_CAST(db);
	}

	/*
	 * Held across the miss so that a second caller racing on the same
	 * dma_buf waits for this pin and then finds it, rather than creating a
	 * duplicate mapping of the same buffer object.
	 */
	mutex_lock(&ctx->miss_lock);

	pin = dmabuf_cache_lookup(ctx, db, bo_offset, len);
	from_cache = pin;
	if (pin) {
		dma_buf_put(db);
	} else {
		pin = pin_dmabuf_range(ctx, db, bo_offset, len, what);
		if (IS_ERR(pin)) {
			mutex_unlock(&ctx->miss_lock);
			return pin;
		}
	}

	if (!from_cache)
		dmabuf_cache_insert(ctx, pin);

	mutex_unlock(&ctx->miss_lock);

	return pin;
}

void hfi2_dmabuf_ctx_init(struct hfi2_dmabuf_ctx *ctx, struct hfi2_devdata *dd)
{
	ctx->dd = dd;
	atomic_set(&ctx->n_destroy_pending, 0);
	init_waitqueue_head(&ctx->destroy_wq);
	mutex_init(&ctx->miss_lock);
	spin_lock_init(&ctx->cache_lock);
	INIT_LIST_HEAD(&ctx->cache_lru);
	ctx->cache_count = 0;
	ctx->cache_bytes = 0;
	atomic64_set(&ctx->bytes_pinned, 0);
	atomic64_set(&ctx->n_pin, 0);
	atomic64_set(&ctx->n_unpin, 0);
	atomic64_set(&ctx->n_faults, 0);
	atomic64_set(&ctx->n_hits, 0);
	atomic64_set(&ctx->n_evictions, 0);
}

void hfi2_dmabuf_ctx_fini(struct hfi2_dmabuf_ctx *ctx)
{
	if (!ctx->dd)
		return;

	hfi2_dmabuf_cache_drain(ctx);

	/*
	 * Pin references are released before the last adapter drains, so work
	 * may be queued. Queued work dereferences ctx, so the wait cannot be
	 * abandoned; it is bounded only to report progress. dmabuf_pin_destroy()
	 * blocks on the exporter's dma_resv, which this driver does not own, so
	 * a stalled exporter is otherwise an unobservable hang in close().
	 */
	while (!wait_event_timeout(ctx->destroy_wq,
				   !atomic_read(&ctx->n_destroy_pending),
				   HFI2_DMABUF_DESTROY_WAIT))
		dd_dev_warn(ctx->dd,
			    "waiting for %d dma-buf teardown(s) to complete\n",
			    atomic_read(&ctx->n_destroy_pending));

	WARN_ON(atomic64_read(&ctx->bytes_pinned));

	mutex_destroy(&ctx->miss_lock);
	ctx->dd = NULL;
}
