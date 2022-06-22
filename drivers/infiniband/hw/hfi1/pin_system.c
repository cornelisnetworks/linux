// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2022 - Cornelis Networks, Inc.
 */

#include <linux/types.h>

#include "hfi.h"
#include "common.h"
#include "device.h"
#include "pinning.h"
#include "mmu_rb.h"
#include "sdma.h"
#include "user_sdma.h"
#include "trace.h"

static bool sdma_rb_filter(struct mmu_rb_node *node, unsigned long addr,
			   unsigned long len);
static int sdma_rb_insert(void *arg, struct mmu_rb_node *mnode);
static int sdma_rb_evict(void *arg, struct mmu_rb_node *mnode, void *arg2,
			 bool *stop);
static void sdma_rb_remove(void *arg, struct mmu_rb_node *mnode);
static int sdma_rb_invalidate(void *arg, struct mmu_rb_node *mnode);

static struct mmu_rb_ops sdma_rb_ops = { .filter = sdma_rb_filter,
					 .insert = sdma_rb_insert,
					 .evict = sdma_rb_evict,
					 .remove = sdma_rb_remove,
					 .invalidate = sdma_rb_invalidate };

static int add_system_pages_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   u32 *pkt_remaining);

static int init_system_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct hfi1_devdata *dd = pq->dd;
	struct mmu_rb_handler **handler = (struct mmu_rb_handler **)
		&PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM);
	int ret;

	ret = hfi1_mmu_rb_register(pq, &sdma_rb_ops, dd->pport->hfi1_wq,
				   handler);
	if (ret)
		dd_dev_err(dd,
			   "[%u:%u] Failed to register system memory DMA support with MMU: %d\n",
			   pq->ctxt, pq->subctxt, ret);
	return ret;
}

static void free_system_pinning_interface(struct hfi1_user_sdma_pkt_q *pq)
{
	struct mmu_rb_handler *handler =
		PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM);

	if (handler)
		hfi1_mmu_rb_unregister(handler);
}

static u32 sdma_cache_evict(struct hfi1_user_sdma_pkt_q *pq, u32 npages)
{
	struct evict_data evict_data;
	struct mmu_rb_handler *handler =
		PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM);

	evict_data.cleared = 0;
	evict_data.target = npages;
	hfi1_mmu_rb_evict(handler, &evict_data);
	return evict_data.cleared;
}

static void unpin_vector_pages(struct mm_struct *mm, struct page **pages,
			       unsigned int start, unsigned int npages)
{
	hfi1_release_user_pages(mm, pages + start, npages, false);
	kfree(pages);
}

static void free_system_node(struct sdma_mmu_node *node)
{
	if (node->npages) {
		unpin_vector_pages(mm_from_sdma_node(node), node->pages, 0,
				   node->npages);
		atomic_sub(node->npages, &node->pq->n_locked);
	}
	kfree(node);
}

static inline void acquire_node(struct sdma_mmu_node *node)
{
	atomic_inc(&node->refcount);
	WARN_ON(atomic_read(&node->refcount) < 0);
}

static inline void release_node(struct mmu_rb_handler *handler,
				struct sdma_mmu_node *node)
{
	atomic_dec(&node->refcount);
	WARN_ON(atomic_read(&node->refcount) < 0);
}

static struct sdma_mmu_node *find_system_node(struct mmu_rb_handler *handler,
					      unsigned long start,
					      unsigned long end)
{
	struct mmu_rb_node *rb_node;
	struct sdma_mmu_node *node;
	unsigned long flags;

	spin_lock_irqsave(&handler->lock, flags);
	rb_node = hfi1_mmu_rb_get_first(handler, start, (end - start));
	if (!rb_node) {
		handler->misses++;
		spin_unlock_irqrestore(&handler->lock, flags);
		return NULL;
	}
	handler->hits++;
	node = container_of(rb_node, struct sdma_mmu_node, rb);
	acquire_node(node);
	spin_unlock_irqrestore(&handler->lock, flags);

	return node;
}

static int pin_system_pages(struct user_sdma_request *req,
			    uintptr_t start_address, size_t length,
			    struct sdma_mmu_node *node, int npages)
{
	struct hfi1_user_sdma_pkt_q *pq = req->pq;
	int pinned, cleared;
	struct page **pages;

	pages = kcalloc(npages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

retry:
	if (!hfi1_can_pin_pages(pq->dd, current->mm, atomic_read(&pq->n_locked),
				npages)) {
		SDMA_DBG(req, "Evicting: nlocked %u npages %u",
			 atomic_read(&pq->n_locked), npages);
		cleared = sdma_cache_evict(pq, npages);
		if (cleared >= npages)
			goto retry;
	}

	SDMA_DBG(req, "Acquire user pages start_address %lx node->npages %u npages %u",
		 start_address, node->npages, npages);
	pinned = hfi1_acquire_user_pages(current->mm, start_address, npages, 0,
					 pages);

	if (pinned < 0) {
		kfree(pages);
		SDMA_DBG(req, "pinned %d", pinned);
		return pinned;
	}
	if (pinned != npages) {
		unpin_vector_pages(current->mm, pages, node->npages, pinned);
		SDMA_DBG(req, "npages %u pinned %d", npages, pinned);
		return -EFAULT;
	}
	node->rb.addr = start_address;
	node->rb.len = length;
	node->pages = pages;
	node->npages = npages;
	atomic_add(pinned, &pq->n_locked);
	SDMA_DBG(req, "done. pinned %d", pinned);
	return 0;
}

static int add_system_pinning(struct user_sdma_request *req,
			      struct sdma_mmu_node **node_p,
			      unsigned long start, unsigned long len)

{
	struct hfi1_user_sdma_pkt_q *pq = req->pq;
	struct sdma_mmu_node *node;
	int ret;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->pq = pq;
	ret = pin_system_pages(req, start, len, node, PFN_DOWN(len));
	if (ret == 0) {
		ret = hfi1_mmu_rb_insert(PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM), &node->rb);
		if (ret)
			free_system_node(node);
		else
			*node_p = node;

		return ret;
	}

	kfree(node);
	return ret;
}

static int get_system_cache_entry(struct user_sdma_request *req,
				  struct sdma_mmu_node **node_p,
				  size_t req_start, size_t req_len)
{
	struct hfi1_user_sdma_pkt_q *pq = req->pq;
	u64 start = ALIGN_DOWN(req_start, PAGE_SIZE);
	u64 end = PFN_ALIGN(req_start + req_len);
	struct mmu_rb_handler *handler =
		PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM);
	int ret;

	if ((end - start) == 0) {
		SDMA_DBG(req,
			 "Request for empty cache entry req_start %lx req_len %lx start %llx end %llx",
			 req_start, req_len, start, end);
		return -EINVAL;
	}

	SDMA_DBG(req, "req_start %lx req_len %lu", req_start, req_len);

	while (1) {
		struct sdma_mmu_node *node =
			find_system_node(handler, start, end);
		u64 prepend_len = 0;

		SDMA_DBG(req, "node %p start %llx end %llu", node, start, end);
		if (!node) {
			ret = add_system_pinning(req, node_p, start,
						 end - start);
			if (ret == -EEXIST) {
				/*
				 * Another execution context has inserted a
				 * conficting entry first.
				 */
				continue;
			}
			return ret;
		}

		if (node->rb.addr <= start) {
			/*
			 * This entry covers at least part of the region. If it doesn't extend
			 * to the end, then this will be called again for the next segment.
			 */
			*node_p = node;
			return 0;
		}

		SDMA_DBG(req, "prepend: node->rb.addr %lx, node->refcount %d",
			 node->rb.addr, atomic_read(&node->refcount));
		prepend_len = node->rb.addr - start;

		/*
		 * This node will not be returned, instead a new node
		 * will be. So release the reference.
		 */
		release_node(handler, node);

		/* Prepend a node to cover the beginning of the allocation */
		ret = add_system_pinning(req, node_p, start, prepend_len);
		if (ret == -EEXIST) {
			/* Another execution context has inserted a conficting entry first. */
			continue;
		}
		return ret;
	}
}

static int add_mapping_to_sdma_packet(struct user_sdma_request *req,
				      struct user_sdma_txreq *tx,
				      struct sdma_mmu_node *cache_entry,
				      size_t start,
				      size_t from_this_cache_entry)
{
	struct hfi1_user_sdma_pkt_q *pq = req->pq;
	unsigned int page_offset;
	unsigned int from_this_page;
	size_t page_index;
	void *ctx;
	int ret;

	/*
	 * Because the cache may be more fragmented than the memory that is being accessed,
	 * it's not strictly necessary to have a descriptor per cache entry.
	 */

	while (from_this_cache_entry) {
		page_index = PFN_DOWN(start - cache_entry->rb.addr);

		if (page_index >= cache_entry->npages) {
			SDMA_DBG(req,
				 "Request for page_index %zu >= cache_entry->npages %u",
				 page_index, cache_entry->npages);
			return -EINVAL;
		}

		page_offset = start - ALIGN_DOWN(start, PAGE_SIZE);
		from_this_page = PAGE_SIZE - page_offset;

		if (from_this_page < from_this_cache_entry) {
			ctx = NULL;
		} else {
			/*
			 * In the case they are equal the next line has no practical effect,
			 * but it's better to do a register to register copy than a conditional
			 * branch.
			 */
			from_this_page = from_this_cache_entry;
			ctx = cache_entry;
		}

		ret = sdma_txadd_page(pq->dd, ctx, &tx->txreq,
				      cache_entry->pages[page_index],
				      page_offset, from_this_page);
		if (ret) {
			/*
			 * When there's a failure, the entire request is freed by
			 * user_sdma_send_pkts().
			 */
			SDMA_DBG(req,
				 "sdma_txadd_page failed %d page_index %lu page_offset %u from_this_page %u",
				 ret, page_index, page_offset, from_this_page);
			return ret;
		}
		start += from_this_page;
		from_this_cache_entry -= from_this_page;
	}
	return 0;
}

static int add_system_iovec_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   size_t from_this_iovec)
{
	struct mmu_rb_handler *handler =
		PINNING_STATE(req->pq, HFI1_MEMINFO_TYPE_SYSTEM);

	while (from_this_iovec > 0) {
		struct sdma_mmu_node *cache_entry;
		size_t from_this_cache_entry;
		size_t start;
		int ret;

		start = (uintptr_t)iovec->iov.iov_base + iovec->offset;
		ret = get_system_cache_entry(req, &cache_entry, start,
					     from_this_iovec);
		if (ret) {
			SDMA_DBG(req, "pin system segment failed %d", ret);
			return ret;
		}

		from_this_cache_entry = cache_entry->rb.len - (start - cache_entry->rb.addr);
		if (from_this_cache_entry > from_this_iovec)
			from_this_cache_entry = from_this_iovec;

		ret = add_mapping_to_sdma_packet(req, tx, cache_entry, start,
						 from_this_cache_entry);
		if (ret) {
			/*
			 * We're guaranteed that there will be no descriptor
			 * completion callback that releases this node
			 * because only the last descriptor referencing it
			 * has a context attached, and a failure means the
			 * last descriptor was never added.
			 */
			release_node(handler, cache_entry);
			SDMA_DBG(req, "add system segment failed %d", ret);
			return ret;
		}

		iovec->offset += from_this_cache_entry;
		from_this_iovec -= from_this_cache_entry;
	}

	return 0;
}

static int add_system_pages_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   u32 *pkt_data_remaining)
{
	size_t remaining_to_add = *pkt_data_remaining;
	/*
	 * Walk through iovec entries, ensure the associated pages
	 * are pinned and mapped, add data to the packet until no more
	 * data remains to be added or the iovec entry type changes.
	 */
	while ((remaining_to_add > 0) &&
	       (iovec->type == HFI1_MEMINFO_TYPE_SYSTEM)) {
		struct user_sdma_iovec *cur_iovec;
		size_t from_this_iovec;
		int ret;

		cur_iovec = iovec;
		from_this_iovec = iovec->iov.iov_len - iovec->offset;

		if (from_this_iovec > remaining_to_add) {
			from_this_iovec = remaining_to_add;
		} else {
			/* The current iovec entry will be consumed by this pass. */
			req->iov_idx++;
			iovec++;
		}

		ret = add_system_iovec_to_sdma_packet(req, tx, cur_iovec,
						      from_this_iovec);
		if (ret)
			return ret;

		remaining_to_add -= from_this_iovec;
	}
	*pkt_data_remaining = remaining_to_add;

	return 0;
}

static void system_descriptor_complete(struct hfi1_devdata *dd,
				       struct sdma_desc *descp)
{
	switch (sdma_mapping_type(descp)) {
	case SDMA_MAP_SINGLE:
		dma_unmap_single(&dd->pcidev->dev, sdma_mapping_addr(descp),
				 sdma_mapping_len(descp), DMA_TO_DEVICE);
		break;
	case SDMA_MAP_PAGE:
		dma_unmap_page(&dd->pcidev->dev, sdma_mapping_addr(descp),
			       sdma_mapping_len(descp), DMA_TO_DEVICE);
		break;
	}

	if (descp->pinning_ctx) {
		struct sdma_mmu_node *node = descp->pinning_ctx;

		release_node(node->rb.handler, node);
	}
}

static void add_system_stats(const struct mmu_rb_node *rb_node, void *arg)
{
	struct sdma_mmu_node *node =
		container_of(rb_node, struct sdma_mmu_node, rb);
	struct hfi1_pin_stats *stats = arg;

	stats->cache_entries++;
	stats->total_refcounts += atomic_read(&node->refcount);
	stats->total_bytes += node->rb.len;
}

static int get_system_stats(struct hfi1_user_sdma_pkt_q *pq, int index,
			    struct hfi1_pin_stats *stats)
{
	struct mmu_rb_handler *handler =
		PINNING_STATE(pq, HFI1_MEMINFO_TYPE_SYSTEM);
	unsigned long next = 0;

	if (index == -1) {
		stats->index = 1;
		return 0;
	}

	if (index != 0)
		return -EINVAL;

	stats->id = 0;
	while (next != ~0UL) {
		unsigned long flags;

		spin_lock_irqsave(&handler->lock, flags);
		/* Take stats on 100 nodes at a time.
		 * This is a balance between time/cost of the operation and
		 * the latency of other operations waiting for the lock.
		 */
		next = hfi1_mmu_rb_for_n(handler, next, 100, add_system_stats,
					 stats);
		spin_unlock_irqrestore(&handler->lock, flags);
		/* This is to allow the lock to be acquired from other places. */
		ndelay(100);
	}

	stats->hits = handler->hits;
	stats->misses = handler->misses;
	stats->internal_evictions = handler->internal_evictions;
	stats->external_evictions = handler->external_evictions;

	return 0;
};

static struct pinning_interface system_pinning_interface = {
	.init = init_system_pinning_interface,
	.free = free_system_pinning_interface,
	.add_to_sdma_packet = add_system_pages_to_sdma_packet,
	.descriptor_complete = system_descriptor_complete,
	.get_stats = get_system_stats,
};

void register_system_pinning_interface(void)
{
	register_pinning_interface(HFI1_MEMINFO_TYPE_SYSTEM,
				   &system_pinning_interface);
	pr_info("%s System memory DMA support enabled\n", class_name());
}

void deregister_system_pinning_interface(void)
{
	deregister_pinning_interface(HFI1_MEMINFO_TYPE_SYSTEM);
}

static bool sdma_rb_filter(struct mmu_rb_node *node, unsigned long addr,
			   unsigned long len)
{
	return (bool)(node->addr == addr);
}

static int sdma_rb_insert(void *arg, struct mmu_rb_node *mnode)
{
	struct sdma_mmu_node *node =
		container_of(mnode, struct sdma_mmu_node, rb);

	atomic_inc(&node->refcount);
	return 0;
}

/*
 * Return 1 to remove the node from the rb tree and call the remove op.
 *
 * Called with the rb tree lock held.
 */
static int sdma_rb_evict(void *arg, struct mmu_rb_node *mnode, void *evict_arg,
			 bool *stop)
{
	struct sdma_mmu_node *node =
		container_of(mnode, struct sdma_mmu_node, rb);
	struct evict_data *evict_data = evict_arg;

	/* is this node still being used? */
	if (atomic_read(&node->refcount))
		return 0; /* keep this node */

	/* this node will be evicted, add its pages to our count */
	evict_data->cleared += node->npages;

	/* have enough pages been cleared? */
	if (evict_data->cleared >= evict_data->target)
		*stop = true;

	return 1; /* remove this node */
}

static void sdma_rb_remove(void *arg, struct mmu_rb_node *mnode)
{
	struct sdma_mmu_node *node =
		container_of(mnode, struct sdma_mmu_node, rb);

	free_system_node(node);
}

static int sdma_rb_invalidate(void *arg, struct mmu_rb_node *mnode)
{
	struct sdma_mmu_node *node =
		container_of(mnode, struct sdma_mmu_node, rb);

	if (!atomic_read(&node->refcount))
		return 1;
	return 0;
}
