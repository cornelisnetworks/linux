/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2026 - Cornelis Networks, Inc.
 */

#ifndef _HFI2_DMABUF_CORE_H
#define _HFI2_DMABUF_CORE_H

#include <linux/types.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/dma-buf.h>
#include <linux/printk.h>

struct device;
struct dma_buf;
struct dma_buf_attachment;
struct hfi2_devdata;
struct sg_table;

/*
 * Mapped bidirectionally so one mapping can serve both a send, which reads the
 * buffer, and an expected receive, which writes it.
 */
#define HFI2_DMABUF_DIR DMA_BIDIRECTIONAL

/* Teardown blocks on an exporter-owned dma_resv; re-warn rather than hang. */
#define HFI2_DMABUF_DESTROY_WAIT (30 * HZ)

/*
 * Bound on the device-only teardown drain below.
 */
#define HFI2_DO_COPY_DRAIN_US 100000

/*
 * Wait for copies that passed a device-only liveness check to finish, so the
 * mappings they latched are not torn down underneath them.  The copy paths are
 * bounded and never sleep, so this normally returns without waiting; every
 * caller is a sleepable teardown path (they go on to iounmap and unpin).
 *
 * Returns false if the count did not reach zero, meaning the caller must leave
 * the mappings alone -- leaking them is recoverable, freeing memory a copy is
 * still reading is not.
 */
static inline bool hfi2_drain_copies(atomic_t *copies, const char *what)
{
	unsigned int us = 0;

	while (atomic_read(copies) != 0) {
		if (us >= HFI2_DO_COPY_DRAIN_US) {
			pr_err_ratelimited("hfi2: %s: %d copies still in flight after %u us; leaking mappings\n",
					   what, atomic_read(copies), us);
			return false;
		}
		usleep_range(10, 20);
		us += 10;
	}
	return true;
}

/*
 * Device-only dma-buf test: an exporter that cannot vmap its buffer cannot
 * provide a CPU mapping, so the buffer can only be reached by device copies.
 */
static inline bool hfi2_dmabuf_is_device_only(struct dma_buf *dmabuf)
{
	return dmabuf && !dmabuf->ops->vmap;
}


/*
 * One mapping of one buffer object, shared by every hfi2 facility that names
 * that buffer. Reference-counted: the cache holds one, and each in-flight user
 * holds one.
 *
 * The mapping always spans the whole buffer object, since
 * dma_buf_map_attachment() has no partial form. A caller's [bo_offset, len)
 * bounds its walk, not the mapping, so any pin serves every valid range.
 */
struct hfi2_dmabuf_pin {
	struct dma_buf *db;
	struct dma_buf_attachment *dba;
	struct sg_table *sgt;
	struct hfi2_dmabuf_ctx *ctx;
	struct kref ref;
	struct work_struct cleanup_work;
	u64 bytes;			/* always db->size */
	struct list_head cache_link;	/* empty when not cached */
};

/*
 * Per-file dma-buf pinning state. Owned by hfi2_filedata rather than by either
 * adapter, so a buffer pinned for a send is found by an expected receive of the
 * same buffer, and charged once.
 */
struct hfi2_dmabuf_ctx {
	struct hfi2_devdata *dd;

	atomic_t n_destroy_pending;
	wait_queue_head_t destroy_wq;

	atomic64_t bytes_pinned;

	/*
	 * Serializes the whole cache-miss sequence: lookup, budget reservation,
	 * pin creation and insertion. The sequence sleeps in the exporter, so
	 * cache_lock cannot cover it, and without this two callers racing on one
	 * dma_buf each miss the lookup and each create a pin.
	 */
	struct mutex miss_lock;

	/* Each cached entry holds a kref. Never taken from interrupt context. */
	spinlock_t cache_lock;
	struct list_head cache_lru;	/* most recently used first */
	unsigned int cache_count;
	u64 cache_bytes;

	atomic64_t n_pin;
	atomic64_t n_unpin;
	atomic64_t n_faults;
	atomic64_t n_hits;
	atomic64_t n_evictions;
};

void hfi2_dmabuf_ctx_init(struct hfi2_dmabuf_ctx *ctx, struct hfi2_devdata *dd);
void hfi2_dmabuf_ctx_fini(struct hfi2_dmabuf_ctx *ctx);

/*
 * Get a mapping covering [@bo_offset, @bo_offset + @len) of the buffer object
 * named by @fd, from the cache when possible.
 *
 * Consumes nothing; on success the caller owns a reference and must release it
 * with hfi2_dmabuf_pin_put().
 *
 * @what is used only for diagnostics, to name the caller in log messages.
 *
 * @return pin on success, ERR_PTR() on failure.
 */
struct hfi2_dmabuf_pin *hfi2_dmabuf_pin_get(struct hfi2_dmabuf_ctx *ctx, int fd,
					    u64 bo_offset, size_t len,
					    const char *what);

void hfi2_dmabuf_pin_put(void *ptr);

bool hfi2_dmabuf_pin_covers(struct hfi2_dmabuf_pin *pin, struct dma_buf *db,
			    u64 bo_offset, size_t len);

bool hfi2_dmabuf_pin_matches_fd(struct hfi2_dmabuf_pin *pin, int fd,
				u64 bo_offset, size_t len);

/* Drop every idle cached mapping. In-flight users keep their references. */
void hfi2_dmabuf_cache_drain(struct hfi2_dmabuf_ctx *ctx);

#endif /* _HFI2_DMABUF_CORE_H */
