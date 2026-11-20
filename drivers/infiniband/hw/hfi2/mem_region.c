// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 - Cornelis Networks, Inc.
 */

#include "mem_region.h"

#include "hfi2.h"
#include "common.h"
#include "mmu_rb.h"
#include "bulksvc.h"
#include "trace.h"

/* this is all very similar to sdma_rb_ops / pin_system */

static bool bulksvc_rb_filter(struct mmu_rb_node *node, unsigned long addr,
			       unsigned long len)
{
	return (bool)(node->addr == addr) && (node->len == len);
}
static int bulksvc_rb_evict(void *arg, struct mmu_rb_node *mnode, void *arg2,
			 bool *stop)
{
	struct hfi2_bulksvc_user_info *uinfo = arg;
	struct hfi2_bulksvc *svc = (uinfo && uinfo->svc) ? uinfo->svc : NULL;

	if (svc)
		dd_dev_err(svc->dd, "bulksvc nodes are being evicted, refusing...\n");
	return 0;
}

static void bulksvc_rb_remove(void *arg, struct mmu_rb_node *mnode)
{
	struct hfi2_mem_region *e = container_of(mnode, struct hfi2_mem_region,
						 rb);
	struct hfi2_bulksvc_user_info *uinfo = arg;
	struct hfi2_devdata *dd = uinfo->svc->dd;
	unsigned long i;

	dd_dev_dbg(dd,
		   "DMS: rb_remove mr=[0x%lx+0x%lx] pinned=%u/%u\n",
		   e->rb.addr, e->rb.len,
		   e->npages_pinned, e->npages_total);

	if (e->npages_total > 0 && e->pin_bitmap &&
	    bitmap_full(e->pin_bitmap, e->npages_total)) {
		for (i = 0; i < e->npages_total; i++)
			dma_unmap_page(&dd->pcidev->dev, e->dma_list[i],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
		hfi2_release_user_pages(mnode->handler->mn.mm, e->pages,
				       e->npages_total, true);
	} else if (e->pin_bitmap) {
		unsigned long run_start = 0, run_len;

		for_each_set_bit(i, e->pin_bitmap, e->npages_total)
			dma_unmap_page(&dd->pcidev->dev, e->dma_list[i],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
		while (run_start < e->npages_total) {
			run_start = find_next_bit(e->pin_bitmap,
						  e->npages_total, run_start);
			if (run_start >= e->npages_total)
				break;
			run_len = find_next_zero_bit(e->pin_bitmap,
						     e->npages_total,
						     run_start) - run_start;
			hfi2_release_user_pages(mnode->handler->mn.mm,
						&e->pages[run_start],
						run_len, true);
			run_start += run_len;
		}
	}
	kvfree(e->pin_bitmap);
	kvfree(e->dma_list);
	kvfree(e->pages);
	kfree(e);
}

/*
 * Have the bulksvc lane cancel trackers, set shutting_down and drop HOST
 * MR refs before the generic rb-tree drain.  No user_info ref is held
 * here and the lane's cancel pass may queue its release, so do not touch
 * user_mr_list or other lane-owned state after the wait.
 */
#define MMU_RB_SYNC_DRAIN_TIMEOUT_MS 30000

static void bulksvc_rb_sync_drain(void *arg)
{
	struct hfi2_bulksvc_user_info *user_info = arg;
	struct hfi2_bulksvc *svc;
	struct hfi2_bulksvc_event_entry *ev;
	struct hfi2_bulksvc_mmu_sync_drain *sd;
	unsigned long remaining;

	if (WARN_ON(!user_info || !user_info->svc))
		return;

	svc = user_info->svc;

	dd_dev_dbg(svc->dd, "sync_drain: MMU for client %u releasing\n", user_info->client_key);
	/* 2-ref kref: waiter + bulksvc thread.  GFP_KERNEL is safe;
	 * exit_mmap has dropped mmap_lock before invoking .release.
	 */
	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		dd_dev_err(svc->dd,
			   "sync_drain: alloc failed for client %u; pins may leak past exit_mmap\n",
			   user_info->client_key);
		return;
	}
	sd->user_info = user_info;
	init_completion(&sd->done);
	kref_init(&sd->refcount);
	kref_get(&sd->refcount);

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev) {
		dd_dev_err(svc->dd,
			   "sync_drain: event alloc failed for client %u; pins may leak past exit_mmap\n",
			   user_info->client_key);
		hfi2_bulksvc_mmu_sync_drain_put(sd);
		hfi2_bulksvc_mmu_sync_drain_put(sd);
		return;
	}

	ev->event.type = BULKSVC_EVENT_TYPE_MMU_SYNC_DRAIN;
	ev->event.sync_drain = sd;

	if (hfi2_bulksvc_enqueue_user_event(user_info, ev)) {
		dd_dev_err(svc->dd,
			   "sync_drain: enqueue failed for client %u\n",
			   user_info->client_key);
		kfree(ev);
		hfi2_bulksvc_mmu_sync_drain_put(sd);
		hfi2_bulksvc_mmu_sync_drain_put(sd);
		return;
	}

	remaining = wait_for_completion_timeout(&sd->done,
			msecs_to_jiffies(MMU_RB_SYNC_DRAIN_TIMEOUT_MS));
	if (!remaining) {
		WARN(1, "sync_drain: client %u timed out after %dms; bulksvc thread wedged?\n",
		     user_info->client_key, MMU_RB_SYNC_DRAIN_TIMEOUT_MS);
		hfi2_bulksvc_mmu_sync_drain_put(sd);
		return;
	}

	hfi2_bulksvc_mmu_sync_drain_put(sd);
}

static struct mmu_rb_ops bulksvc_rb_ops = {
	.filter = bulksvc_rb_filter,
	/* called when rb_node is removed from list */
	.remove = bulksvc_rb_remove,
	.evict = bulksvc_rb_evict,
	.sync_drain = bulksvc_rb_sync_drain,
};

int init_bulksvc_mmu(struct hfi2_bulksvc_user_info *uinfo)
{
	struct hfi2_bulksvc *svc;
	int ret = 0;

	if (!uinfo)
		return -1;

	svc = uinfo->svc;
	if (!svc)
		return -1;

	/* this should set up an rb_tree and notifier mechanism */
	ret = hfi2_mmu_rb_register(uinfo, &bulksvc_rb_ops,
				   svc->dd->hfi2_wq,
				   &uinfo->mmu);

	return ret;
}

int uninit_bulksvc_mmu(struct hfi2_bulksvc_user_info *uinfo)
{
	if (uinfo->mmu)
		hfi2_mmu_rb_unregister(uinfo->mmu);
	uinfo->mmu = NULL;

	return 0;
}

static struct hfi2_mem_region *find_system_node(struct mmu_rb_handler *handler,
					      unsigned long start,
					      unsigned long end);

struct hfi2_mem_region *hfi2_mem_region_create_unpinned(struct mmu_rb_handler *handler,
							uintptr_t vaddr,
							u64 len)
{
	struct hfi2_mem_region *e;
	struct hfi2_mem_region *existing;
	struct hfi2_bulksvc_user_info *uinfo = handler->ops_arg;
	struct hfi2_devdata *dd = uinfo && uinfo->svc ? uinfo->svc->dd : NULL;
	int node = dd ? dd->node : NUMA_NO_NODE;
	uintptr_t start = ALIGN_DOWN(vaddr, PAGE_SIZE);
	uintptr_t end = PFN_ALIGN(vaddr + len);
	u64 aligned_len = end - start;
	unsigned int npages = PFN_DOWN(aligned_len);
	int ret;

	existing = find_system_node(handler, start, end);
	if (existing)
		return existing;

	e = kzalloc_node(sizeof(*e), GFP_KERNEL, node);
	if (!e)
		return NULL;

	kref_init(&e->rb.refcount);
	kref_get(&e->rb.refcount);

	e->rb.handler = handler;
	e->rb.addr = start;
	e->rb.len = aligned_len;

	e->pages = kvcalloc_node(npages, sizeof(*e->pages),
				 GFP_KERNEL | __GFP_NOWARN, node);
	if (!e->pages)
		goto free_mem_region;

	e->dma_list = kvcalloc_node(npages, sizeof(*e->dma_list),
				    GFP_KERNEL | __GFP_NOWARN, node);
	if (!e->dma_list)
		goto free_pages;

	e->pin_bitmap = kvcalloc_node(BITS_TO_LONGS(npages),
				      sizeof(unsigned long),
				      GFP_KERNEL | __GFP_NOWARN, node);
	if (!e->pin_bitmap)
		goto free_dma_list;

	e->npages_total = npages;
	e->npages_pinned = 0;

	ret = hfi2_mmu_rb_insert(handler, &e->rb);
	if (ret) {
		if (dd)
			dd_dev_warn_ratelimited(dd, "DMS_DIAG: create_unpinned: mmu_rb_insert FAILED ret=%d addr=0x%lx len=0x%llx npages=%u\n",
				ret, start, aligned_len, npages);
		goto free_bitmap;
	}

	return e;

free_bitmap:
free_dma_list:
	kvfree(e->pin_bitmap);
	kvfree(e->dma_list);
free_pages:
	kvfree(e->pages);
free_mem_region:
	kfree(e);
	return NULL;
}

int hfi2_mem_region_pin_range(struct hfi2_devdata *dd,
			      struct hfi2_mem_region *mr,
			      unsigned int from_page,
			      unsigned int npages,
			      bool writable)
{
	unsigned int last = from_page + npages;
	struct mm_struct *mm;
	unsigned int run_start;
	unsigned int run_end;
	unsigned int i;
	uintptr_t addr;
	int pinned;

	if (!dd || !mr)
		return -EINVAL;

	if (from_page > mr->npages_total)
		return -EINVAL;
	if (npages > (mr->npages_total - from_page))
		return -EINVAL;
	if (!npages)
		return 0;

	/* Fast path: entire range already pinned */
	if (hfi2_mem_region_range_pinned(mr, from_page, npages))
		return 0;

	mm = mr->rb.handler->mn.mm;

	/*
	 * Scan the bitmap for contiguous runs of unpinned pages and
	 * pin each run in a single bulk hfi2_acquire_user_pages call.
	 * Common case (first pin of the range): one run covering all
	 * pages, identical cost to the old contiguous approach.
	 */
	run_start = find_next_zero_bit(mr->pin_bitmap, last, from_page);
	while (run_start < last) {
		unsigned int run_len;

		run_end = find_next_bit(mr->pin_bitmap, last, run_start);
		run_len = run_end - run_start;

		addr = mr->rb.addr + ((uintptr_t)run_start * PAGE_SIZE);
		/*
		 * @writable selects the GUP direction.  RDMA-WRITE source
		 * buffers and RDMA-READ-response source buffers can legally
		 * back read-only VMAs; pinning those FOLL_WRITE fails GUP.
		 * Receive-side targets MUST pin writable: GUP without
		 * FOLL_WRITE can return COW/shared pages whose physical
		 * addresses are valid but unsafe for device writes, causing
		 * MCE under concurrent first-touch.
		 */
		pinned = hfi2_acquire_user_pages(mm, addr, run_len, writable,
						 &mr->pages[run_start]);
		if (pinned < 0) {
			dd_dev_warn_ratelimited(dd, "DMS_DIAG: pin_range: acquire_pages FAILED ret=%d addr=0x%lx run_len=%u\n",
				pinned, (unsigned long)addr, run_len);
			return pinned;
		}
		if (pinned != run_len) {
			dd_dev_warn_ratelimited(dd, "DMS_DIAG: pin_range: partial pin got=%d wanted=%u addr=0x%lx\n",
				pinned, run_len, (unsigned long)addr);
			hfi2_release_user_pages(mm, &mr->pages[run_start],
						pinned, false);
			return -EFAULT;
		}

		for (i = run_start; i < run_end; i++) {
			mr->dma_list[i] = dma_map_page(&dd->pcidev->dev,
						       mr->pages[i], 0,
						       PAGE_SIZE,
						       DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(&dd->pcidev->dev,
						       mr->dma_list[i])))
				goto unmap_run;
		}

		bitmap_set(mr->pin_bitmap, run_start, run_len);
		mr->npages_pinned += run_len;

		run_start = find_next_zero_bit(mr->pin_bitmap, last, run_end);
	}

	return 0;

unmap_run:
	/* Undo DMA mappings for pages already mapped in this run */
	while (i-- > run_start) {
		dma_unmap_page(&dd->pcidev->dev, mr->dma_list[i],
			       PAGE_SIZE, DMA_BIDIRECTIONAL);
		mr->dma_list[i] = 0;
	}
	hfi2_release_user_pages(mm, &mr->pages[run_start],
				run_end - run_start, false);
	return -EIO;
}

bool hfi2_mem_region_range_pinned(struct hfi2_mem_region *mr,
				  unsigned int from_page,
				  unsigned int npages)
{
	unsigned int last = from_page + npages;

	if (!mr->pin_bitmap || last > mr->npages_total)
		return false;

	return find_next_zero_bit(mr->pin_bitmap, last, from_page) >= last;
}

/*
 * kref from kref_get() in here will be transferred to the struct
 * user_sdma_txreq to which the retval struct hfi2_mem_region* is being used for.
 */
static struct hfi2_mem_region *find_system_node(struct mmu_rb_handler *handler,
					      unsigned long start,
					      unsigned long end)
{
	struct mmu_rb_node *rb_node;
	unsigned long flags;

	spin_lock_irqsave(&handler->lock, flags);
	rb_node = hfi2_mmu_rb_search(handler, start, (end - start));
	if (!rb_node) {
		handler->misses++;
		spin_unlock_irqrestore(&handler->lock, flags);
		return NULL;
	}

	/* This kref will become the user_sdma_request's kref */
	kref_get(&rb_node->refcount);
	handler->hits++;
	spin_unlock_irqrestore(&handler->lock, flags);

	return container_of(rb_node, struct hfi2_mem_region, rb);
}

/* behaviour is exactly the same as add_system_pinning */
struct hfi2_mem_region *hfi2_mem_region_pin(struct mmu_rb_handler *handler,
				    uintptr_t vaddr, u64 len)
{
	struct hfi2_devdata *dd;
	struct hfi2_mem_region *e;
	uintptr_t start = ALIGN_DOWN(vaddr, PAGE_SIZE);
	uintptr_t end = PFN_ALIGN(vaddr + len);
	u64 aligned_len = end - start;
	unsigned int npages = PFN_DOWN(aligned_len);
	int ret;

	dd = ((struct hfi2_bulksvc_user_info *)handler->ops_arg)->svc->dd;

	e = find_system_node(handler, start, end);
	if (e && e->rb.len == aligned_len)
		return e;
	if (e) {
		dd_dev_warn_ratelimited(dd, "hfi2_mem_region_pin: found existing %p for vaddr %lx len %llu but wrong length! - (start, end) This: (%lx, %lx) MR: (%lx %lx)\n",
			e, vaddr, aligned_len, start, end,
			e->rb.addr, e->rb.addr + e->rb.len);
		hfi2_mem_region_put(e);
	}

	e = hfi2_mem_region_create_unpinned(handler, vaddr, len);
	if (!e)
		return NULL;

	/* Legacy hfi2_mem_region_pin() retains the original always-writable
	 * semantics; callers that need a read-only pin go through the
	 * page_provider path with writable=false.
	 */
	ret = hfi2_mem_region_pin_range(dd, e, 0, npages, true);
	if (ret) {
		dd_dev_warn_ratelimited(dd, "hfi2_mem_region_pin: could not pin vaddr %lx len %llu start %lx end %lx ret %d\n",
			vaddr, aligned_len, start, end, ret);
		hfi2_mem_region_put(e);
		return NULL;
	}

	return e;
}


