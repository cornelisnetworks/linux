// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

/*
 * PASID ownership for RoCE direct placement.
 *
 * Hardware places inbound RDMA WRITE payload straight into a userspace buffer.
 * The only translation control in either EAL table is the entry's PASID field,
 * so every placement write is a PASID-tagged TLP resolved in the PASID table.
 * That makes "which PASID does this MR's memory live under" a correctness
 * question with no second chance: no encapsulation-header field carries the
 * R_Key, so a placement performed against the wrong PASID is attributable only
 * to a VA and a PASID, neither of which identifies the entry that produced it.
 * The check is at install time or it does not happen at all.
 *
 * Keyed on owning_mm, not on the uverbs fd.  A per-fd handle is memory-safe -
 * the IOMMU core dedups a repeat (dev, mm) bind - but it cannot express one fd
 * spanning two mm's, which SCM_RIGHTS fd-passing and fork(2) without CLOEXEC
 * both produce.  In that case an MR registered by the receiving process binds
 * current->mm while the fd still holds the opener's handle, and the entry would
 * be armed to place into a foreign address space.
 *
 * The device reports PASID but neither ATS nor PRI, so a translation miss can
 * never be recovered: there is no page request, no response and no retry.
 * Pages must therefore already be pinned when a placement TLP arrives, and
 * both ODP and SVA demand paging are foreclosed.  ib_umem_get() pins with
 * FOLL_LONGTERM, which is what makes this safe.
 *
 * Binding can legitimately fail - Intel VT-d refuses SVA on a device without
 * ATS, and an IOMMU may be disabled entirely - so a failure here must degrade
 * to software placement rather than fail the MR.
 */

#include <linux/anon_inodes.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/iommu.h>
#include <linux/iommufd.h>
#include <linux/iova.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/sched/mm.h>
#include <linux/scatterlist.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <rdma/ib_umem.h>

#include "hfi2.h"
#include "eth_hwi.h"
/* For struct hfi2_bulksvc; dms_roce.h only forward-declares it. */
#include "bulksvc.h"
#include "dms_roce.h"
#include "eth_hwi.h"
#include "roce_pasid.h"
#include "verbs.h"

/*
 * rdmavt hands the MR hooks a bare struct rvt_mregion, which carries no umem
 * and therefore no owning_mm.  The mm is reachable only by walking back to the
 * enclosing struct rvt_mr, whose definition lives in a header rdmavt keeps
 * private.  This is the first hw/ driver to include it.
 *
 * The walk is safe because rvt_mregion is declared "must be last" in rvt_mr and
 * every rvt_mregion in the tree is embedded in one - rvt_init_mregion() is
 * called from exactly two places, both on &mr->mr.
 */
#include "rvt_mr_internal.h"

#if HFI2_DMS_ROCE_INJECT
static bool roce_inject_fence_enoent;
#endif

/*
 * Reaching the RoCE backend from the device.  Deliberately tolerant of a
 * missing backend: the map outlives it, because a backend switch tears
 * dms_roce down while MRs and their bindings remain registered.
 */
static struct hfi2_dms_roce *pasid_roce(struct hfi2_devdata *dd)
{
	if (!dd || !dd->bulksvc)
		return NULL;

	return dd->bulksvc->dms_roce;
}

static int pasid_quiesce_hardware(struct hfi2_roce_pasid *pasid,
				  struct hfi2_devdata *dd, const char *reason);

#define HFI2_ROCE_KMR_IOVA_BASE	SZ_4G
#define HFI2_ROCE_KMR_FLUSH_MS	10
#define HFI2_ROCE_KMR_ASYNC_BUDGET	32
#define HFI2_ROCE_PASID_QUARANTINE_MS 1000
#define HFI2_ROCE_KMR_PASID_IOVA_BASE	BIT_ULL(32)

enum hfi2_roce_kmr_window_type {
	HFI2_ROCE_KMR_WINDOW_FASTREG,
	HFI2_ROCE_KMR_WINDOW_DMABUF,
};

struct hfi2_roce_kmr_window {
	struct list_head list;
	refcount_t refs;
	unsigned long pfn;
	unsigned long npages;
	unsigned long release_jiffies;
	unsigned long va;
	unsigned long len;
	enum hfi2_roce_kmr_window_type type;
};

enum hfi2_roce_kmr_request_type {
	HFI2_ROCE_KMR_REQUEST_MAP_DMABUF,
	HFI2_ROCE_KMR_REQUEST_ZAP_DMABUF,
};

struct hfi2_roce_kmr_request {
	struct list_head list;
	struct completion done;
	struct sg_table *sgt;
	unsigned long va;
	unsigned long len;
	enum hfi2_roce_kmr_request_type type;
	int status;
};

struct hfi2_roce_kmr_retained {
	struct list_head list;
	struct page **pages;
	u32 count;
};

struct hfi2_roce_kmr_donor {
	struct hfi2_devdata *dd;
	struct mm_struct *mm;
	struct hfi2_roce_pasid_bind *bind;
	struct file *file;
	struct task_struct *worker;
	struct completion ready;
	struct iova_domain iovad;
	struct list_head flush;
	struct list_head requests;
	struct list_head async;
	struct list_head retained;
	spinlock_t flush_lock;		/* protects flush */
	spinlock_t requests_lock;	/* protects requests */
	wait_queue_head_t waitq;
	unsigned long base;
	unsigned long size;
	int status;
	bool stopping;
	refcount_t users;
	struct completion unused;
};

/*
 * One descriptor per registration rather than a fixed pool: each sits in
 * quarantine after release, so any pool smaller than the registration rate
 * times the quarantine runs dry, and an MR left without a window cannot be
 * hardware-placed.
 */
static struct hfi2_roce_kmr_window *
hfi2_roce_kmr_alloc_window(struct hfi2_roce_kmr_donor *donor)
{
	struct hfi2_roce_kmr_window *window;

	if (!donor || READ_ONCE(donor->stopping))
		return NULL;
	window = kmalloc_node(sizeof(*window), GFP_ATOMIC | __GFP_NOWARN,
			      donor->dd->node);
	if (window)
		refcount_set(&window->refs, 1);
	return window;
}

static void hfi2_roce_kmr_release_window(struct hfi2_roce_kmr_donor *donor,
					 struct hfi2_roce_kmr_window *window)
{
	unsigned long flags;

	if (!window || !refcount_dec_and_test(&window->refs))
		return;
	if (!donor || READ_ONCE(donor->stopping)) {
		kfree(window);
		return;
	}

	spin_lock_irqsave(&donor->flush_lock, flags);
	window->release_jiffies = jiffies;
	list_add_tail(&window->list, &donor->flush);
	spin_unlock_irqrestore(&donor->flush_lock, flags);
}

static int hfi2_roce_kmr_zap_dmabuf(struct hfi2_roce_kmr_donor *donor,
				     struct hfi2_roce_kmr_request *request)
{
	struct vm_area_struct *vma;
	int ret = 0;

	mmap_read_lock(donor->mm);
	vma = vma_lookup(donor->mm, request->va);
	if (!vma || request->va < vma->vm_start ||
	    request->len > vma->vm_end - request->va)
		ret = -ENOENT;
	else
		zap_special_vma_range(vma, request->va, request->len);
	mmap_read_unlock(donor->mm);

	return ret;
}

int hfi2_roce_kmr_reserve(struct hfi2_devdata *dd, unsigned long len,
			  struct hfi2_roce_kmr_reservation *reservation)
{
	struct hfi2_roce_kmr_donor *donor = dd->roce_kmr_donor;
	struct iova *extent;

	if (!donor || !len || !IS_ALIGNED(len, PAGE_SIZE) ||
	    READ_ONCE(donor->stopping) || !READ_ONCE(donor->bind->common.live))
		return -ENODEV;
	extent = alloc_iova(&donor->iovad, len >> PAGE_SHIFT,
			    ((donor->base + donor->size) >> PAGE_SHIFT) - 1, false);
	if (!extent)
		return -ENOSPC;
	refcount_inc(&donor->users);
	reservation->donor = donor;
	reservation->token = &donor->bind->common;
	reservation->extent = extent;
	reservation->va = extent->pfn_lo << PAGE_SHIFT;
	reservation->len = len;
	return 0;
}

void hfi2_roce_kmr_unreserve(struct hfi2_roce_kmr_reservation *reservation)
{
	struct hfi2_roce_kmr_donor *donor = reservation->donor;

	if (!donor)
		return;
	if (!reservation->poisoned)
		__free_iova(&donor->iovad, reservation->extent);
	memset(reservation, 0, sizeof(*reservation));
	if (refcount_dec_and_test(&donor->users))
		complete(&donor->unused);
}

int hfi2_roce_kmr_retain_pages(struct hfi2_roce_kmr_reservation *reservation,
			       struct page **pages, u32 count)
{
	struct hfi2_roce_kmr_retained *retained;

	reservation->poisoned = true;
	retained = kmalloc(sizeof(*retained), GFP_KERNEL);
	if (!retained)
		return -ENOMEM;
	retained->pages = pages;
	retained->count = count;
	list_add_tail(&retained->list, &reservation->donor->retained);
	dd_dev_warn(reservation->donor->dd,
		    "RoCE donor: permanently retaining %u unsafe READ pages\n", count);
	return 0;
}

int hfi2_roce_kmr_queue(struct hfi2_roce_kmr_reservation *reservation,
			struct hfi2_roce_kmr_async *request)
{
	struct hfi2_roce_kmr_donor *donor = reservation->donor;
	unsigned long flags;

	if (!donor)
		return -ENODEV;
	spin_lock_irqsave(&donor->requests_lock, flags);
	if (donor->stopping) {
		spin_unlock_irqrestore(&donor->requests_lock, flags);
		return -ESHUTDOWN;
	}
	list_add_tail(&request->list, &donor->async);
	spin_unlock_irqrestore(&donor->requests_lock, flags);
	wake_up_all(&donor->waitq);
	return 0;
}

static bool hfi2_roce_kmr_range(struct hfi2_roce_kmr_reservation *reservation,
				unsigned long va, unsigned long len)
{
	return va >= reservation->va && len <= reservation->len &&
		va - reservation->va <= reservation->len - len;
}

/* PFNs come from retained CPU pages. */
int hfi2_roce_kmr_map_pages(struct hfi2_roce_kmr_reservation *reservation,
			    unsigned long va, struct page **pages, u32 count)
{
	struct hfi2_roce_kmr_donor *donor = reservation->donor;
	struct vm_area_struct *vma;
	unsigned long len = (unsigned long)count << PAGE_SHIFT;
	u32 i;
	int ret = 0;

	if (WARN_ON_ONCE(current != donor->worker) ||
	    !hfi2_roce_kmr_range(reservation, va, len))
		return -EINVAL;
	mmap_write_lock(donor->mm);
	vma = vma_lookup(donor->mm, va);
	if (!vma || len > vma->vm_end - va) {
		ret = -EINVAL;
		goto unlock;
	}
	for (i = 0; i < count; i++) {
		ret = remap_pfn_range(vma, va + ((unsigned long)i << PAGE_SHIFT),
				      page_to_pfn(pages[i]), PAGE_SIZE, vma->vm_page_prot);
		if (ret)
			break;
	}
	if (ret)
		zap_special_vma_range(vma, va, len);
unlock:
	mmap_write_unlock(donor->mm);
	return ret;
}

int hfi2_roce_kmr_zap_pages(struct hfi2_roce_kmr_reservation *reservation,
			    unsigned long va, unsigned long len)
{
	struct hfi2_roce_kmr_request request = { .va = va, .len = len };
	struct hfi2_roce_kmr_donor *donor = reservation->donor;

	if (WARN_ON_ONCE(current != donor->worker) ||
	    !hfi2_roce_kmr_range(reservation, va, len))
		return -EINVAL;
	return hfi2_roce_kmr_zap_dmabuf(donor, &request);
}

static int hfi2_roce_kmr_request_sync(struct hfi2_roce_kmr_donor *donor,
				       struct hfi2_roce_kmr_request *request)
{
	unsigned long flags;
	int ret;

	if (!donor)
		return -ENODEV;

	init_completion(&request->done);
	INIT_LIST_HEAD(&request->list);
	spin_lock_irqsave(&donor->requests_lock, flags);
	if (READ_ONCE(donor->stopping)) {
		spin_unlock_irqrestore(&donor->requests_lock, flags);
		return -ESHUTDOWN;
	}
	list_add_tail(&request->list, &donor->requests);
	spin_unlock_irqrestore(&donor->requests_lock, flags);
	wake_up_all(&donor->waitq);
	wait_for_completion(&request->done);
	ret = request->status;

	return ret;
}

static int hfi2_roce_kmr_map_dmabuf_sync(struct hfi2_roce_kmr_donor *donor,
					  unsigned long va, unsigned long len,
					  struct sg_table *sgt)
{
	struct hfi2_roce_kmr_request request = {
		.sgt = sgt,
		.va = va,
		.len = len,
		.type = HFI2_ROCE_KMR_REQUEST_MAP_DMABUF,
	};

	return hfi2_roce_kmr_request_sync(donor, &request);
}

static int hfi2_roce_kmr_zap_dmabuf_sync(struct hfi2_roce_kmr_donor *donor,
					  unsigned long va, unsigned long len)
{
	struct hfi2_roce_kmr_request request = {
		.va = va,
		.len = len,
		.type = HFI2_ROCE_KMR_REQUEST_ZAP_DMABUF,
	};

	return hfi2_roce_kmr_request_sync(donor, &request);
}

static void hfi2_roce_kmr_release_dmabuf(struct hfi2_roce_mr_priv *priv,
					  struct hfi2_devdata *dd)
{
	struct hfi2_roce_kmr_donor *donor = dd->roce_kmr_donor;
	struct hfi2_roce_kmr_window *window = priv->donor_window;
	struct hfi2_dms_roce *roce = pasid_roce(dd);
	int ret;

	if (!window)
		return;

	priv->donor_window = NULL;
	priv->donor_dmabuf_va = 0;
	priv->donor_dmabuf_len = 0;
	priv->donor_window_live = false;
	if (!donor || READ_ONCE(donor->stopping)) {
		kfree(window);
		return;
	}

	/* PTEs must not retain GPU PFNs past dma-buf unpin; VMA reuse is delayed. */
	ret = hfi2_roce_kmr_zap_dmabuf_sync(donor, window->va, window->len);
	if (ret) {
		if (roce)
			atomic64_inc(&roce->stats.kmr_donor_dmabuf_err);
		dd_dev_warn_ratelimited(dd,
					"RoCE dma-buf donor VMA 0x%lx+0x%lx zap failed: %d\n",
					window->va, window->len, ret);
	}
	hfi2_roce_kmr_release_window(donor, window);
}

int hfi2_roce_kmr_donor_init(struct hfi2_devdata *dd)
{
	if (hfi2_roce_kmr_donor_enabled)
		dd_dev_warn(dd, "RoCE KMR donor disabled: mm_alloc unavailable or not exported\n");
	return 0;
}

void hfi2_roce_kmr_donor_exit(struct hfi2_devdata *dd)
{
	struct hfi2_roce_kmr_donor *donor = dd->roce_kmr_donor;
	struct hfi2_roce_kmr_retained *retained, *tmp;
	struct hfi2_roce_kmr_request *request;
	unsigned long flags;

	if (!donor)
		return;

	/* Pool requests and reservations must drain while the donor still runs. */
	if (pasid_roce(dd))
		hfi2_dms_roce_release_internal_mrs(&dd->verbs_dev.rdi);
	dd->roce_kmr_donor = NULL;
	WRITE_ONCE(donor->stopping, true);
	if (refcount_dec_and_test(&donor->users))
		complete(&donor->unused);
	wait_for_completion(&donor->unused);
	spin_lock_irqsave(&donor->requests_lock, flags);
	while (!list_empty(&donor->requests)) {
		request = list_first_entry(&donor->requests,
					   struct hfi2_roce_kmr_request, list);
		list_del_init(&request->list);
		request->status = -ESHUTDOWN;
		complete(&request->done);
	}
	spin_unlock_irqrestore(&donor->requests_lock, flags);
	wake_up_all(&donor->waitq);
	kthread_stop(donor->worker);
	put_task_struct(donor->worker);
	flush_delayed_fput();
	/* Unrevoked pages keep their references; only the bookkeeping goes. */
	list_for_each_entry_safe(retained, tmp, &donor->retained, list) {
		list_del(&retained->list);
		kfree(retained->pages);
		kfree(retained);
	}
	kfree(donor);
}

/*
 * Hardware placement (roce_by_software=0) must cover kernel FastReg MRs too,
 * or kernel ULP WRITEs would hang.  Refuse the probe rather than fall back
 * silently: the operator asked for hardware placement and should learn it is
 * not available.
 */
int hfi2_roce_kmr_placement_init(struct hfi2_devdata *dd)
{
	if (hfi2_bulksvc_roce_by_software(dd))
		return 0;
	if (hfi2_roce_kmr_pasid_enabled)
		return 0;
	return hfi2_bulksvc_roce_placement_unavailable(dd,
						       "kernel MRs need roce_kmr_pasid=1");
}

/*
 * Drive every hardware table entry naming this binding's PASID to invalid.
 *
 * Ordering is the whole point and it is not negotiable: invalidate the rows,
 * flush the posted writes, wait for prior placement reports, and only then let
 * the caller release the SVA binding. Unbinding while an entry can still place
 * lets the IOMMU dismantle the PASID page tables while the device may write
 * through them.
 */
static int pasid_quiesce_hardware(struct hfi2_roce_pasid *pasid,
				  struct hfi2_devdata *dd, const char *reason)
{
	DECLARE_BITMAP(scanned, EAL_RIF_TABLE_ROWS);
	struct hfi2_dms_roce *roce = pasid_roce(dd);
	struct hfi2_dms_roce_rx_mark mark;
	int rkeys, rifs, late_rifs, drain_ret, post_drain_ret;
	int ret = 0;

	if (!roce)
		return pasid->quiesce_failed ? -EIO : 0;

	/*
	 * Stop arms and revoke keys before scanning RIF rows. Drain on both
	 * sides and reconcile late row bits before removing the record.
	 */
	hfi2_dms_roce_rif_pasid_deactivate(roce, pasid->pasid);
	rkeys = hfi2_dms_roce_rkey_invalidate_pasid(roce, pasid->pasid);
	if (hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		ret = -EIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	drain_ret = hfi2_dms_roce_wait_rx(roce, &mark);
	rifs = hfi2_dms_roce_rif_invalidate_pasid(roce, pasid->pasid,
						  drain_ret != 0, scanned);
	if (hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		ret = -EIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	post_drain_ret = hfi2_dms_roce_wait_rx(roce, &mark);
	late_rifs = hfi2_dms_roce_rif_pasid_finish(roce, pasid->pasid,
						   scanned, post_drain_ret);
	if (rifs >= 0 && late_rifs > 0)
		rifs += late_rifs;
	if (rkeys > 0 || rifs > 0)
		dd_dev_info(dd,
			    "RoCE PASID %u: invalidated %d R_Key and %d RIF entries on %s\n",
			    pasid->pasid, rkeys > 0 ? rkeys : 0,
			    rifs > 0 ? rifs : 0, reason);
	if (drain_ret)
		dd_dev_warn(dd,
			    "RoCE PASID %u: receive drain failed (%d) on %s\n",
			    pasid->pasid, drain_ret, reason);
	if (post_drain_ret)
		dd_dev_warn(dd,
			    "RoCE PASID %u: post-invalidate receive drain failed (%d) on %s\n",
			    pasid->pasid, post_drain_ret, reason);
	if (rkeys < 0 || rifs < 0 || late_rifs < 0 || drain_ret || post_drain_ret)
		ret = -EIO;
	if (ret)
		WRITE_ONCE(pasid->quiesce_failed, true);
	return READ_ONCE(pasid->quiesce_failed) ? -EIO : 0;
}

/*
 * mmu_notifier .release, not mmu_interval_notifier .invalidate.
 *
 * Three properties decide it.  This fires exactly once, at exit_mmap(), rather
 * than on every VMA change - an interval notifier would invalidate hardware
 * state on ordinary munmap and reclaim churn.  It may sleep, which draining
 * hardware requires and which a non-blockable .invalidate cannot promise.  And
 * it runs strictly before __mmdrop(), where mm_pasid_drop() frees the PASID for
 * reuse, so the window in which a valid entry could name a recycled PASID
 * never opens.
 *
 * hfi2 already relies on the same callback for the same reason in mmu_rb.c.
 */
static void pasid_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct hfi2_roce_pasid_bind *bind =
		container_of(mn, struct hfi2_roce_pasid_bind, notifier);

	if (!READ_ONCE(bind->common.live))
		return;

	/*
	 * Publish the death of the address space before touching hardware, so
	 * an arm racing this teardown declines rather than installing an entry
	 * we are in the middle of tearing down.  Readers take rif_lock, whose
	 * acquire pairs with the release implied by the spin_lock in the sweep
	 * below.
	 */
	WRITE_ONCE(bind->common.live, false);

	pasid_quiesce_hardware(&bind->common, bind->dd,
			       "address-space teardown");
}

static const struct mmu_notifier_ops pasid_notifier_ops = {
	.release = pasid_notifier_release,
};

static void pasid_quarantine_work(struct work_struct *work);

void hfi2_roce_pasid_map_init(struct hfi2_devdata *dd)
{
	xa_init(&dd->roce_pasid_map);
	xa_init(&dd->roce_mr_pasid_map);
	xa_init(&dd->roce_pasid_blocked);
	mutex_init(&dd->roce_pasid_mutex);
	atomic64_set(&dd->roce_pasid_quarantined, 0);
	spin_lock_init(&dd->roce_pasid_quarantine_lock);
	INIT_LIST_HEAD(&dd->roce_pasid_quarantine);
	INIT_DELAYED_WORK(&dd->roce_pasid_quarantine_work,
			  pasid_quarantine_work);
	dd->roce_pasid_quarantine_stopping = false;
	atomic64_set(&dd->roce_mr_pasid_sva_count, 0);
	atomic64_set(&dd->roce_mr_pasid_map_count, 0);
	atomic64_set(&dd->roce_mr_pasid_dmabuf_count, 0);
	atomic_set(&dd->roce_dmabuf_donor_warned, 0);
}

/*
 * EAL RIF entries created by hardware are not tracked by software and the HAS
 * defines no flush or aging control. Hold every PASID for one second, far
 * beyond RHF after-DMA latency, before allocator reuse can expose it to stale
 * placement.
 */
static void pasid_quarantine_release(struct hfi2_devdata *dd, bool force)
{
	struct hfi2_roce_pasid_map *map, *tmp;
	LIST_HEAD(release);
	unsigned long flags, next = 0;

	spin_lock_irqsave(&dd->roce_pasid_quarantine_lock, flags);
	list_for_each_entry_safe(map, tmp, &dd->roce_pasid_quarantine,
				 quarantine) {
		unsigned long expires = map->quarantine_release_jiffies +
			msecs_to_jiffies(HFI2_ROCE_PASID_QUARANTINE_MS);

		if (force || time_after_eq(jiffies, expires)) {
			list_move_tail(&map->quarantine, &release);
			continue;
		}
		if (!next || time_before(expires, next))
			next = expires;
	}
	if (READ_ONCE(dd->roce_pasid_quarantine_stopping))
		next = 0;
	spin_unlock_irqrestore(&dd->roce_pasid_quarantine_lock, flags);

	list_for_each_entry_safe(map, tmp, &release, quarantine) {
		iommu_free_global_pasid(map->common.pasid);
		list_del(&map->quarantine);
		kfree(map);
	}

	if (next) {
		unsigned long delay;

		delay = time_after(next, jiffies) ? next - jiffies : 1;
		mod_delayed_work(system_wq, &dd->roce_pasid_quarantine_work,
				 delay);
	}
}

static void pasid_quarantine_work(struct work_struct *work)
{
	struct hfi2_devdata *dd =
		container_of(to_delayed_work(work), struct hfi2_devdata,
			     roce_pasid_quarantine_work);

	pasid_quarantine_release(dd, false);
}

static void pasid_map_free(struct hfi2_roce_pasid_map *map);

static void pasid_bind_unbind(struct hfi2_roce_pasid_bind *bind)
{
	mmu_notifier_unregister(&bind->notifier, bind->owning_mm);
	if (!bind->handle)
		return;
	if (READ_ONCE(bind->common.quiesce_failed) && !bind->fence_pin) {
		/* The SVA domain pins mm_count until unbind; retain only that pin. */
		mmgrab(bind->owning_mm);
		dd_dev_warn(bind->dd,
			    "RoCE PASID %u: retaining mm-count pin after unproven revocation\n",
			    bind->common.pasid);
	}
	iommu_sva_unbind_device(bind->handle);
	bind->handle = NULL;
}

int hfi2_roce_pasid_fence(struct hfi2_devdata *dd,
			  struct hfi2_roce_pasid *pasid,
			  struct iommu_domain *domain, bool *attached)
{
	struct hfi2_roce_pasid_bind *bind;
	struct hfi2_roce_pasid_map *map;
	unsigned long index;
	int ret = -ENOENT;

	might_sleep();
	if (!pasid || !pasid->pasid || pasid->pasid == IOMMU_PASID_INVALID ||
	    !dd->pcidev || !dd->pcidev->dev.iommu_group)
		return -ENODEV;
	mutex_lock(&dd->roce_pasid_mutex);
	if (pasid->fenced) {
		ret = 0;
		goto unlock;
	}
	ret = xa_err(xa_store(&dd->roce_pasid_blocked, pasid->pasid,
			      xa_mk_value(1), GFP_KERNEL));
	if (ret)
		goto unlock;
	WRITE_ONCE(pasid->quiesce_failed, true);
	WRITE_ONCE(pasid->live, false);
	if (domain) {
		if (!attached || !*attached) {
			ret = -ENOENT;
			goto failed;
		}
		goto begin;
	}
	xa_for_each(&dd->roce_mr_pasid_map, index, map) {
		if (&map->common != pasid)
			continue;
		if (!map->domain || !map->attached) {
			ret = -ENOENT;
			goto failed;
		}
		domain = map->domain;
		attached = &map->attached;
		goto begin;
	}
	xa_for_each(&dd->roce_pasid_map, index, bind) {
		if (&bind->common != pasid)
			continue;
		/* Keep the dead-mm tombstone and PASID alive after the last MR. */
		if (!bind->fence_pin) {
			refcount_inc(&bind->refs);
			mmgrab(bind->owning_mm);
			bind->fence_pin = true;
		}
		if (!bind->handle || refcount_read(&bind->handle->users) != 1) {
			ret = -EBUSY;
			goto failed;
		}
		goto begin;
	}
	ret = -ENOENT;
	goto failed;
begin:
	hfi2_dms_roce_fence_qps(pasid_roce(dd), pasid->pasid, HFI2_ROCE_FENCE_BEGIN);
#if HFI2_DMS_ROCE_INJECT
	if (xchg(&roce_inject_fence_enoent, false)) {
		dd_dev_warn(dd, "RoCE PASID %u: injecting fence ENOENT after begin\n",
			    pasid->pasid);
		ret = -ENOENT;
		goto failed;
	}
#endif
	if (domain) {
		iommu_detach_device_pasid(domain, &dd->pcidev->dev, pasid->pasid);
		*attached = false;
	} else {
		iommu_sva_unbind_device(bind->handle);
		bind->handle = NULL;
	}
	/* Donor release acquires this only after translated DMA has drained. */
	smp_store_release(&pasid->fenced, true);
	hfi2_dms_roce_rkey_invalidate_pasid(pasid_roce(dd), pasid->pasid);
	hfi2_dms_roce_fence_qps(pasid_roce(dd), pasid->pasid, HFI2_ROCE_FENCE_DONE);
	atomic64_inc(&dd->roce_pasid_quarantined);
	dd_dev_warn_ratelimited(dd, "RoCE PASID %u fenced and permanently quarantined\n",
				pasid->pasid);
	ret = 0;
	goto unlock;
failed:
	hfi2_dms_roce_fence_qps(pasid_roce(dd), pasid->pasid, HFI2_ROCE_FENCE_ABORT);
unlock:
	mutex_unlock(&dd->roce_pasid_mutex);
	return ret;
}

/*
 * Called on device teardown.  By construction the map should already be empty:
 * rdma_core drains every uobject before dealloc_ucontext(), so every MR - and
 * therefore every reference - is gone before the device goes away.  A non-empty
 * map means a reference was leaked, which is worth saying out loud rather than
 * silently cleaning up, because the leak would otherwise only surface as an
 * IOMMU warning at some later unrelated moment.
 */
void hfi2_roce_pasid_map_exit(struct hfi2_devdata *dd)
{
	struct hfi2_roce_pasid_map *map;
	struct hfi2_roce_pasid_bind *bind;
	unsigned long index;

	/*
	 * At device teardown, dms_roce has already disabled direct placement,
	 * drained in-flight traffic and destroyed the hardware-table state.  A
	 * survivor here is an MR rdmavt deliberately leaked after its reference
	 * timeout.  Reclaim only its IOMMU objects; a per-PASID hardware sweep is
	 * both too late and unnecessary after the global backend teardown.
	 */
	WRITE_ONCE(dd->roce_pasid_quarantine_stopping, true);
	cancel_delayed_work_sync(&dd->roce_pasid_quarantine_work);
	xa_for_each(&dd->roce_mr_pasid_map, index, map) {
		dd_dev_err(dd,
			   "RoCE PASID %u mapping still present at device teardown (IOVA 0x%llx length %zu) - leaked MR reference\n",
			   map->common.pasid, map->iova, map->length);
		pasid_map_free(map);
	}
	pasid_quarantine_release(dd, true);
	xa_destroy(&dd->roce_mr_pasid_map);

	xa_for_each(&dd->roce_pasid_map, index, bind) {
		if (!bind->fence_pin)
			dd_dev_err(dd,
				   "RoCE PASID %u still bound at device teardown (refs %u) - leaked MR reference\n",
				   bind->common.pasid, refcount_read(&bind->refs));

		/*
		 * xa_erase(), not __xa_erase(): the double-underscore form
		 * requires the caller to already hold xa_lock, and this loop
		 * holds nothing.  It cannot: the calls below sleep.  xa_for_each
		 * takes and releases RCU per step rather than across the body,
		 * and documents that modifying the array during iteration is
		 * safe, so taking the lock inside xa_erase() is correct here.
		 * Hardware placement is already globally disabled here, so the
		 * remaining work is notifier/SVA ownership cleanup only.
		 */
		pasid_bind_unbind(bind);
		xa_erase(&dd->roce_pasid_map, index);
		kfree_rcu(bind, rcu);
	}

	xa_destroy(&dd->roce_pasid_map);
	xa_destroy(&dd->roce_pasid_blocked);
}

static struct hfi2_roce_pasid_bind *pasid_bind_alloc(struct hfi2_devdata *dd,
						     struct mm_struct *mm)
{
	struct hfi2_roce_pasid_bind *bind;
	int ret;

	bind = kzalloc_node(sizeof(*bind), GFP_KERNEL, dd->node);
	if (!bind)
		return ERR_PTR(-ENOMEM);

	bind->dd = dd;
	bind->owning_mm = mm;
	bind->common.live = true;
	refcount_set(&bind->refs, 1);

	bind->handle = iommu_sva_bind_device(&dd->pcidev->dev, mm);
	if (IS_ERR(bind->handle)) {
		ret = PTR_ERR(bind->handle);
		kfree(bind);
		return ERR_PTR(ret);
	}

	bind->common.pasid = iommu_sva_get_pasid(bind->handle);
	if (bind->common.pasid == IOMMU_PASID_INVALID ||
	    xa_load(&dd->roce_pasid_blocked, bind->common.pasid)) {
		iommu_sva_unbind_device(bind->handle);
		kfree(bind);
		return ERR_PTR(-EINVAL);
	}

	bind->notifier.ops = &pasid_notifier_ops;
	ret = mmu_notifier_register(&bind->notifier, mm);
	if (ret) {
		iommu_sva_unbind_device(bind->handle);
		kfree(bind);
		return ERR_PTR(ret);
	}

	return bind;
}

/* Sleepable; returns a held binding or an ERR_PTR for software fallback. */
static struct hfi2_roce_pasid_bind *pasid_get(struct hfi2_devdata *dd,
					      struct mm_struct *mm)
{
	struct hfi2_roce_pasid_bind *bind, *raced;
	unsigned long key;

	if (!dd || !mm)
		return ERR_PTR(-EINVAL);

	might_sleep();

	key = (unsigned long)mm;

again:
	/*
	 * Fast path.  xa_load is RCU-safe, and a hit can only be upgraded to a
	 * reference if the entry is still alive - refcount_inc_not_zero
	 * distinguishes "somebody else holds this" from "the last put is
	 * running concurrently and this memory is about to go".
	 */
	rcu_read_lock();
	bind = xa_load(&dd->roce_pasid_map, key);
	if (bind && refcount_inc_not_zero(&bind->refs)) {
		rcu_read_unlock();
		return bind;
	}
	rcu_read_unlock();

	/*
	 * Bind outside the lock, because it sleeps.  That admits a race where
	 * two registrations for the same mm both bind; xa_cmpxchg resolves it
	 * and the loser is unwound.  Binding twice is harmless - the IOMMU core
	 * dedups a repeat (dev, mm) bind and hands back the same handle with an
	 * extra reference - so the loser's unbind drops exactly what it added.
	 */
	bind = pasid_bind_alloc(dd, mm);
	if (IS_ERR(bind))
		return bind;

	raced = xa_cmpxchg(&dd->roce_pasid_map, key, NULL, bind, GFP_KERNEL);
	if (xa_is_err(raced)) {
		int ret = xa_err(raced);

		pasid_bind_unbind(bind);
		kfree(bind);
		return ERR_PTR(ret);
	}

	if (raced) {
		/*
		 * Someone installed theirs first.  Discard ours and look again
		 * rather than adopt @raced: it was returned outside RCU, so it
		 * may already be on its way to being freed, and the lookup is
		 * the only place a reference can be taken safely.
		 */
		pasid_bind_unbind(bind);
		kfree(bind);
		cond_resched();
		goto again;
	}

	return bind;
}

struct hfi2_roce_pasid_bind *hfi2_roce_pasid_get(struct hfi2_devdata *dd,
						 struct mm_struct *mm)
{
	struct hfi2_roce_pasid_bind *bind;

	if (!dd || !mm)
		return ERR_PTR(-EINVAL);
	mutex_lock(&dd->roce_pasid_mutex);
	bind = pasid_get(dd, mm);
	mutex_unlock(&dd->roce_pasid_mutex);
	return bind;
}

/**
 * hfi2_roce_pasid_put - drop one MR's reference to a binding
 * @bind: binding to release, or NULL
 *
 * On the last reference this performs the mandated teardown order:
 * invalidate every hardware entry naming the PASID, drain what is in flight,
 * then unbind SVA and free.  Doing it in any other order lets the IOMMU
 * dismantle a page table the device still believes it may write through.
 *
 * Context: sleepable only.  mmu_notifier_unregister() and
 * iommu_sva_unbind_device() both sleep.
 */
void hfi2_roce_pasid_put(struct hfi2_roce_pasid_bind *bind)
{
	struct hfi2_devdata *dd;

	if (!bind)
		return;

	might_sleep();

	dd = bind->dd;

	mutex_lock(&dd->roce_pasid_mutex);
	if (!refcount_dec_and_test(&bind->refs)) {
		mutex_unlock(&dd->roce_pasid_mutex);
		return;
	}

	/*
	 * Remove from the map before releasing, so a concurrent get() cannot
	 * find an entry whose teardown has started.  A get() that already has
	 * the pointer is excluded by refcount_inc_not_zero having failed.
	 */
	xa_erase(&dd->roce_pasid_map, (unsigned long)bind->owning_mm);
	mutex_unlock(&dd->roce_pasid_mutex);

	/*
	 * Ordering, in the only sequence that is safe:
	 *
	 *   1. stop new arms       - live = false
	 *   2. invalidate rows     - hardware can no longer start a placement
	 *   3. drain               - in-flight placements complete
	 *   4. unregister notifier - no release callback can now run
	 *   5. unbind SVA          - the PASID may be freed and recycled
	 *
	 * Steps 1-3 are skipped when the notifier already ran, which is the
	 * ordinary case for a process that exited while MRs were registered:
	 * exit_mm() precedes exit_files(), so the address space dies first and
	 * .release has already quiesced the hardware.
	 */
	if (READ_ONCE(bind->common.live)) {
		WRITE_ONCE(bind->common.live, false);
		pasid_quiesce_hardware(&bind->common, bind->dd,
				       "last SVA reference");
	}

	pasid_bind_unbind(bind);
	/* hfi2_roce_pasid_get() may still be reading it under RCU. */
	kfree_rcu(bind, rcu);
}

/*
 * FastReg and LOCAL_INV cannot release PASIDs in atomic context.
 * Bind at user registration and release through mr_priv_free.
 */

static struct hfi2_devdata *mr_priv_dd(struct rvt_dev_info *rdi)
{
	return dd_from_dev(dev_from_rdi(rdi));
}

/*
 * The mm this MR's memory belongs to, or NULL if it has none.
 *
 * A DMA MR from rvt_get_dma_mr() has no umem or PASID and remains ineligible:
 * rif_pasid is the only translation control in either EAL table, so a
 * dma_map_page() address cannot be a placement target.  Kernel FastReg MRs are
 * different: roce_kmr_pasid or the donor path binds a PASID-backed window, so
 * their placement eligibility follows that window rather than the absence of
 * umem.
 */
static struct rvt_mr *mr_container(struct rvt_mregion *mr)
{
	return container_of(mr, struct rvt_mr, mr);
}

static struct mm_struct *mr_owning_mm(struct rvt_mregion *mr)
{
	struct rvt_mr *rmr = mr_container(mr);

	if (!rmr->umem)
		return NULL;

	return rmr->umem->owning_mm;
}

static bool mr_is_pinned_dmabuf(struct rvt_mregion *mr)
{
	struct rvt_mr *rmr = mr_container(mr);
	struct ib_umem *umem = rmr->umem;

	return umem && umem->is_dmabuf && to_ib_umem_dmabuf(umem)->pinned;
}

static bool mr_is_kernel_fastreg(struct rvt_mregion *mr)
{
	struct rvt_mr *rmr = mr_container(mr);

	return !rmr->umem && mr->max_segs && !ibpd_to_rvtpd(mr->pd)->user;
}

static void hfi2_roce_kmr_release_mr_window(struct hfi2_roce_mr_priv *priv,
					    struct hfi2_devdata *dd)
{
	struct hfi2_roce_kmr_donor *donor = dd->roce_kmr_donor;
	struct hfi2_roce_kmr_window *window;
	unsigned long flags;

	if (!priv)
		return;

	spin_lock_irqsave(&priv->pageset_lock, flags);
	window = priv->donor_window;
	priv->donor_generation++;
	priv->donor_window = NULL;
	priv->donor_iova = 0;
	priv->kmr_iova_delta = 0;
	priv->donor_dmabuf_va = 0;
	priv->donor_dmabuf_len = 0;
	priv->donor_window_live = false;
	priv->pasid = NULL;
	priv->sva = NULL;
	priv->pasid_type = HFI2_ROCE_PASID_NONE;
	priv->pasid_ref_held = false;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	hfi2_roce_kmr_release_window(donor, window);
}

struct hfi2_roce_kmr_reg {
	struct hfi2_roce_kmr_donor *donor;
	struct hfi2_roce_kmr_window *window;
	struct rvt_mregion *mr;
	u64 generation;
	u64 local_generation;
	struct hfi2_roce_pasid_map *map;
	u64 offset;
	u64 iova;
	u64 donor_iova;
	size_t length;
	unsigned long npages;
	u32 key;
	int access;
	bool published;
	unsigned long pfns[];
};

static int hfi2_roce_kmr_set_pte(pte_t *pte, unsigned long addr, void *data)
{
	struct hfi2_roce_kmr_reg *reg = data;
	unsigned long page = (addr - (reg->donor_iova & PAGE_MASK)) >> PAGE_SHIFT;

	if (WARN_ON_ONCE(!pte_none(ptep_get(pte))))
		return -EEXIST;
	if (WARN_ON_ONCE(page >= reg->npages))
		return -EINVAL;

	set_pte_at(reg->donor->mm, addr, pte,
		   pte_mkspecial(pfn_pte(reg->pfns[page], PAGE_SHARED)));
	return 0;
}

static int hfi2_roce_kmr_map_dmabuf_mr(struct hfi2_roce_kmr_donor *donor,
					struct rvt_mregion *mr,
					struct hfi2_roce_mr_priv *priv)
{
	struct rvt_mr *rmr = mr_container(mr);
	struct ib_umem *umem = rmr->umem;
	struct iommu_domain *domain;
	struct hfi2_roce_kmr_window *window;
	unsigned long va;
	unsigned long len;
	u64 map_end;
	int ret;

	if (!donor || !donor->bind || !READ_ONCE(donor->bind->common.live) ||
	    !umem || mr->offset != ib_umem_offset(umem) ||
	    !to_ib_umem_dmabuf(umem)->pinned ||
	    !to_ib_umem_dmabuf(umem)->sgt)
		return -EOPNOTSUPP;
	if (!mr->length || mr->offset != (mr->iova & ~PAGE_MASK) ||
	    check_add_overflow(mr->iova & ~PAGE_MASK, (u64)mr->length, &map_end) ||
	    map_end > ULONG_MAX - (PAGE_SIZE - 1))
		return -EOVERFLOW;

	domain = iommu_get_domain_for_dev(&donor->dd->pcidev->dev);
	if (!domain || domain->type != IOMMU_DOMAIN_IDENTITY)
		return -EOPNOTSUPP;

	/* map_end is relative to the page holding mr->iova. */
	va = mr->iova & PAGE_MASK;
	len = PAGE_ALIGN((unsigned long)map_end);

	window = hfi2_roce_kmr_alloc_window(donor);
	if (!window)
		return -ENOMEM;

	ret = hfi2_roce_kmr_map_dmabuf_sync(donor, va, len,
					    &umem->sgt_append.sgt);
	if (ret) {
		kfree(window);
		return ret;
	}

	window->va = va;
	window->len = len;
	window->type = HFI2_ROCE_KMR_WINDOW_DMABUF;
	priv->donor_window = window;
	priv->donor_dmabuf_va = va;
	priv->donor_dmabuf_len = len;
	priv->donor_window_live = true;
	return 0;
}

static int hfi2_roce_kmr_map_mr(struct hfi2_roce_kmr_donor *donor,
				 struct rvt_mregion *mr,
				 struct hfi2_roce_mr_priv *priv)
{
	struct hfi2_roce_kmr_window *window;
	unsigned long npages;
	unsigned long pfn;
	unsigned long flags;
	struct rvt_mr *rmr = mr_container(mr);
	u64 len;
	u64 offset;

	if (!donor || !donor->bind || !READ_ONCE(donor->bind->common.live))
		return -EOPNOTSUPP;
	offset = mr->iova & ~PAGE_MASK;
	if (!mr->length || mr->page_shift != PAGE_SHIFT ||
	    check_add_overflow(offset, (u64)mr->length, &len) ||
	    len > SIZE_MAX - (PAGE_SIZE - 1))
		return -EINVAL;

	npages = DIV_ROUND_UP(len, PAGE_SIZE);
	window = hfi2_roce_kmr_alloc_window(donor);
	if (!window)
		return -ENOMEM;

	pfn = alloc_iova_fast(&donor->iovad, npages,
			      (donor->base + donor->size - PAGE_SIZE) >> PAGE_SHIFT,
			      false);
	if (!pfn) {
		kfree(window);
		return -ENOSPC;
	}

	window->pfn = pfn;
	window->npages = npages;
	window->type = HFI2_ROCE_KMR_WINDOW_FASTREG;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->donor_generation++;
	priv->donor_iova = (pfn << PAGE_SHIFT) + offset;
	rmr->ibmr.iova = priv->donor_iova;
	mr->iova = priv->donor_iova;
	mr->user_base = priv->donor_iova;
	priv->donor_window = window;
	priv->donor_window_live = true;
	priv->pasid = &donor->bind->common;
	priv->sva = donor->bind;
	priv->pasid_type = HFI2_ROCE_PASID_DONOR;
	priv->pasid_ref_held = true;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	return 0;
}

int hfi2_roce_kmr_setup_reg(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct rvt_mregion *mr = &to_imr(wqe->reg_wr.mr)->mr;
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_roce_kmr_reg *reg;
	unsigned long flags, len, npages, i;
	int ret = -EINVAL;

	spin_lock_irqsave(&priv->pageset_lock, flags);
	if (!mr->length || mr->page_shift != PAGE_SHIFT ||
	    check_add_overflow((unsigned long)mr->offset, mr->length, &len) ||
	    len > ULONG_MAX - (PAGE_SIZE - 1))
		goto unlock;
	if (priv->pasid_type == HFI2_ROCE_PASID_DONOR &&
	    (!dd->roce_kmr_donor || !priv->donor_window_live ||
	     !priv->donor_window ||
	     len > priv->donor_window->npages << PAGE_SHIFT))
		goto unlock;
	npages = DIV_ROUND_UP(len, PAGE_SIZE);
	if (npages > mr->max_segs)
		goto unlock;
	reg = kmalloc_node(struct_size(reg, pfns, npages), GFP_ATOMIC,
			   dd->node);
	if (!reg) {
		ret = -ENOMEM;
		goto unlock;
	}
	for (i = 0; i < npages; i++) {
		struct rvt_seg *seg = &mr->map[i / RVT_SEGSZ]->segs[i % RVT_SEGSZ];

		if (seg->type != RVT_MEM_KERNEL || !seg->vaddr ||
		    seg->length != PAGE_SIZE || !virt_addr_valid(seg->vaddr)) {
			kfree(reg);
			goto unlock;
		}
		reg->pfns[i] = virt_to_phys(seg->vaddr) >> PAGE_SHIFT;
	}
	reg->donor = dd->roce_kmr_donor;
	reg->window = priv->pasid_type == HFI2_ROCE_PASID_DONOR ?
		priv->donor_window : NULL;
	reg->mr = mr;
	reg->generation = priv->donor_generation;
	reg->local_generation = priv->local_generation;
	reg->map = priv->pasid_type == HFI2_ROCE_PASID_MAP ? priv->map : NULL;
	reg->offset = mr->offset;
	reg->iova = mr->iova;
	reg->donor_iova = priv->donor_iova;
	reg->length = mr->length;
	reg->npages = npages;
	reg->key = wqe->reg_wr.key;
	reg->access = wqe->reg_wr.access;
	reg->published = false;
	if (reg->window)
		refcount_inc(&reg->window->refs);
	rvt_get_mr(mr);
	wqe->priv = reg;
	priv->deferred_registers++;
	ret = 0;
unlock:
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	return ret;
}

static int hfi2_roce_map_reg_pages(struct hfi2_roce_kmr_reg *reg);
static void mr_rkey_revoke_locked(struct hfi2_roce_mr_priv *priv,
				  struct hfi2_devdata *dd);

int hfi2_roce_kmr_map_reg(struct rvt_swqe *wqe)
{
	struct hfi2_roce_kmr_reg *reg = wqe->priv;
	struct hfi2_roce_kmr_donor *donor = reg->donor;
	struct hfi2_roce_mr_priv *priv = reg->mr->driver_priv;
	unsigned long flags;
	int ret;

	might_sleep();
	spin_lock_irqsave(&priv->pageset_lock, flags);
	ret = priv->donor_generation != reg->generation ||
		priv->donor_window != reg->window ||
		priv->hardware_generation > reg->local_generation ? -ESTALE : 0;
	if (!ret) {
		mr_rkey_revoke_locked(priv, dd_from_ibdev(wqe->reg_wr.mr->device));
		if (reg->map)
			ret = hfi2_roce_map_reg_pages(reg);
	}
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (ret || !reg->window)
		return ret;
	if (READ_ONCE(donor->stopping) || !READ_ONCE(donor->bind->common.live))
		return -ENODEV;
	/* The SWQE holds the window until this walk and any partial map finish. */
	mmap_read_lock(donor->mm);
	ret = apply_to_page_range(donor->mm, reg->donor_iova & PAGE_MASK,
				  reg->npages << PAGE_SHIFT,
				  hfi2_roce_kmr_set_pte, reg);
	mmap_read_unlock(donor->mm);
	return ret;
}

void hfi2_roce_kmr_cleanup_reg(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct hfi2_roce_kmr_reg *reg = wqe->priv;
	struct hfi2_roce_mr_priv *priv = reg->mr->driver_priv;
	unsigned long flags;

	wqe->priv = NULL;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->deferred_registers--;
	/* A discarded registration must not invalidate a later FastReg cycle. */
	if (!reg->published && priv->donor_generation == reg->generation &&
	    priv->local_generation == reg->local_generation &&
	    priv->donor_window == reg->window)
		atomic_set(&reg->mr->lkey_invalid, 1);
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	hfi2_roce_kmr_release_window(reg->donor, reg->window);
	rvt_put_mr(reg->mr);
	kfree(reg);
}

static void pasid_map_free(struct hfi2_roce_pasid_map *map)
{
	struct device *dev;
	bool quarantine;
	size_t unmapped;
	unsigned long flags;

	if (!map)
		return;

	dev = &map->dd->pcidev->dev;
	mutex_lock(&map->dd->roce_pasid_mutex);
	quarantine = map->tracked;
	if (map->tracked) {
		xa_erase(&map->dd->roce_mr_pasid_map, (unsigned long)map);
		map->tracked = false;
	}
	spin_lock_irqsave(&map->map_lock, flags);
	if (map->domain && map->length) {
		unmapped = iommu_unmap(map->domain, map->iova, map->length);
		if (unmapped != map->length)
			dd_dev_err(map->dd,
				   "RoCE PASID %u: unmapped %zu of %zu bytes\n",
				   map->common.pasid, unmapped, map->length);
	}
	spin_unlock_irqrestore(&map->map_lock, flags);
	if (map->domain && map->attached) {
		iommu_detach_device_pasid(map->domain, dev, map->common.pasid);
		map->attached = false;
	}
	mutex_unlock(&map->dd->roce_pasid_mutex);
	if (READ_ONCE(map->common.quiesce_failed)) {
		dd_dev_warn(map->dd,
			    "RoCE PASID %u: retaining allocator reservation after unproven revocation\n",
			    map->common.pasid);
		if (map->domain)
			iommu_domain_free(map->domain);
		kfree(map);
		return;
	}
	if (quarantine && map->common.pasid != IOMMU_PASID_INVALID) {
		unsigned long flags;
		bool schedule;

		/* RIF entries hardware creates cannot be individually invalidated. */
		if (map->domain)
			iommu_domain_free(map->domain);
		map->domain = NULL;
		map->quarantine_release_jiffies = jiffies;
		spin_lock_irqsave(&map->dd->roce_pasid_quarantine_lock, flags);
		schedule = list_empty(&map->dd->roce_pasid_quarantine);
		list_add_tail(&map->quarantine,
			      &map->dd->roce_pasid_quarantine);
		spin_unlock_irqrestore(&map->dd->roce_pasid_quarantine_lock, flags);
		if (schedule &&
		    !READ_ONCE(map->dd->roce_pasid_quarantine_stopping))
			schedule_delayed_work(&map->dd->roce_pasid_quarantine_work,
				      msecs_to_jiffies(
				      HFI2_ROCE_PASID_QUARANTINE_MS));
		return;
	}
	if (map->common.pasid != IOMMU_PASID_INVALID)
		iommu_free_global_pasid(map->common.pasid);
	if (map->domain)
		iommu_domain_free(map->domain);
	kfree(map);
}

static int pasid_map_dmabuf(struct iommu_domain *domain, u64 iova,
			    struct sg_table *sgt, size_t map_length, int prot,
			    size_t *mapped_out)
{
	struct scatterlist *sg;
	size_t mapped = 0;
	int i, ret;

	if (!sgt->sgl)
		return -EINVAL;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		size_t len = sg_dma_len(sg);

		if (!len || !IS_ALIGNED(sg_dma_address(sg), PAGE_SIZE) ||
		    !IS_ALIGNED(len, PAGE_SIZE) || len > map_length - mapped)
			return -EINVAL;
		ret = iommu_map(domain, iova + mapped, sg_dma_address(sg), len,
				prot, GFP_KERNEL);
		if (ret)
			return ret;
		mapped += len;
		*mapped_out = mapped;
	}

	return mapped == map_length ? 0 : -EINVAL;
}

static struct hfi2_roce_pasid_map *
pasid_map_alloc_user(struct hfi2_devdata *dd, struct rvt_mregion *mr)
{
	struct rvt_mr *rmr = mr_container(mr);
	struct hfi2_roce_pasid_map *map;
	struct ib_umem *umem = rmr->umem;
	struct iommu_domain *default_domain;
	struct device *dev = &dd->pcidev->dev;
	struct sg_table *sgt;
	size_t map_length;
	ssize_t mapped;
	u64 map_end;
	int prot = IOMMU_READ | IOMMU_WRITE;
	int ret;

	if (!umem || mr->offset != ib_umem_offset(umem))
		return ERR_PTR(-EOPNOTSUPP);
	if (umem->is_dmabuf &&
	    (!to_ib_umem_dmabuf(umem)->pinned ||
	     !to_ib_umem_dmabuf(umem)->sgt))
		return ERR_PTR(-EOPNOTSUPP);
	if (mr->iova < mr->offset ||
	    check_add_overflow((u64)mr->offset, (u64)mr->length, &map_end) ||
	    map_end > SIZE_MAX - (PAGE_SIZE - 1))
		return ERR_PTR(-EOVERFLOW);
	map_length = PAGE_ALIGN((size_t)map_end);

	map = kzalloc_node(sizeof(*map), GFP_KERNEL, dd->node);
	if (!map)
		return ERR_PTR(-ENOMEM);

	map->dd = dd;
	spin_lock_init(&map->map_lock);
	map->common.pasid = IOMMU_PASID_INVALID;
	INIT_LIST_HEAD(&map->quarantine);
	/* Map the page containing the raw RETH start address. */
	map->iova = mr->iova - mr->offset;
	if (!IS_ALIGNED(map->iova, PAGE_SIZE)) {
		ret = -EINVAL;
		goto err_free;
	}

	if (umem->is_dmabuf) {
		default_domain = iommu_get_domain_for_dev(dev);
		if (!default_domain ||
		    default_domain->type != IOMMU_DOMAIN_IDENTITY) {
			ret = -EOPNOTSUPP;
			goto err_free;
		}
	}

	map->domain =
		iommu_paging_domain_alloc_flags(dev, IOMMU_HWPT_ALLOC_PASID);
	if (IS_ERR(map->domain)) {
		ret = PTR_ERR(map->domain);
		map->domain = NULL;
		goto err_free;
	}

	map->common.pasid = iommu_alloc_global_pasid(dev);
	if (map->common.pasid == IOMMU_PASID_INVALID) {
		ret = -ENOSPC;
		goto err_free;
	}

	ret = iommu_attach_device_pasid(map->domain, dev, map->common.pasid,
					NULL);
	if (ret)
		goto err_free;
	map->attached = true;

	if (umem->is_dmabuf) {
		if (mr->map[0]->segs[0].type == RVT_MEM_DMABUF_DO)
			prot |= IOMMU_MMIO;
		ret = pasid_map_dmabuf(map->domain, map->iova,
				      &umem->sgt_append.sgt, map_length, prot,
				      &map->length);
		if (ret)
			goto err_free;
	} else {
		sgt = &umem->sgt_append.sgt;
		mapped = iommu_map_sg(map->domain, map->iova, sgt->sgl,
				      sgt->orig_nents, IOMMU_READ | IOMMU_WRITE,
				      GFP_KERNEL);
		if (mapped != map_length) {
			ret = mapped < 0 ? (int)mapped : -EIO;
			if (mapped > 0) {
				map->length = mapped;
				dd_dev_err(dd,
					   "RoCE PASID %u: short IOMMU map %zd of %zu bytes\n",
					   map->common.pasid, mapped, map_length);
			}
			goto err_free;
		}
	}

	map->length = map_length;
	map->common.live = true;
	ret = xa_insert(&dd->roce_mr_pasid_map, (unsigned long)map, map,
			GFP_KERNEL);
	if (ret)
		goto err_free;
	map->tracked = true;
	hfi2_dms_roce_rif_pasid_activate(pasid_roce(dd), map->common.pasid);
	return map;

err_free:
	pasid_map_free(map);
	return ERR_PTR(ret);
}

static void pasid_map_kernel_unmap(struct hfi2_roce_pasid_map *map)
{
	lockdep_assert_held(&map->map_lock);
	if (map->length)
		iommu_unmap(map->domain, map->iova, map->length);
	map->iova = 0;
	map->length = 0;
}

static int pasid_map_kernel_pages(struct hfi2_roce_pasid_map *map,
				  struct rvt_mregion *mr)
{
	u64 map_iova = HFI2_ROCE_KMR_PASID_IOVA_BASE;
	u64 map_end;
	size_t map_length;
	u32 page_count;
	u32 i;
	int ret;

	if (mr->page_shift != PAGE_SHIFT || !mr->length ||
	    check_add_overflow(map_iova, (u64)mr->offset, &map_end) ||
	    check_add_overflow(map_end, (u64)mr->length - 1, &map_end))
		return -EOVERFLOW;
	if (map_iova < map->domain->geometry.aperture_start ||
	    map_end > map->domain->geometry.aperture_end)
		return -ERANGE;
	map_length = PAGE_ALIGN(mr->offset + mr->length);
	page_count = map_length >> PAGE_SHIFT;
	if (page_count > mr->max_segs)
		return -EINVAL;

	pasid_map_kernel_unmap(map);
	map->iova = map_iova;
	for (i = 0; i < page_count; i++) {
		struct rvt_seg *seg = &mr->map[i / RVT_SEGSZ]->segs[i % RVT_SEGSZ];
		phys_addr_t phys;

		if (seg->type != RVT_MEM_KERNEL ||
		    !virt_addr_valid(seg->vaddr) ||
		    !IS_ALIGNED((unsigned long)seg->vaddr, PAGE_SIZE)) {
			ret = -EINVAL;
			goto err_unmap;
		}

		phys = virt_to_phys(seg->vaddr);
		ret = iommu_map(map->domain, map_iova + (i * PAGE_SIZE), phys,
				PAGE_SIZE, IOMMU_READ | IOMMU_WRITE, GFP_ATOMIC);
		if (ret)
			goto err_unmap;
		map->length += PAGE_SIZE;
	}

	return 0;

err_unmap:
	pasid_map_kernel_unmap(map);
	return ret;
}

static int hfi2_roce_map_reg_pages(struct hfi2_roce_kmr_reg *reg)
{
	struct hfi2_roce_pasid_map *map = reg->map;
	u64 end;
	unsigned long i;
	int ret;

	if (READ_ONCE(map->common.quiesce_failed))
		return -EIO;
	if (check_add_overflow((u64)HFI2_ROCE_KMR_PASID_IOVA_BASE,
			       (u64)(reg->npages << PAGE_SHIFT) - 1, &end) ||
	    map->domain->geometry.aperture_start > HFI2_ROCE_KMR_PASID_IOVA_BASE ||
	    end > map->domain->geometry.aperture_end)
		return -ERANGE;
	spin_lock(&map->map_lock);
	WRITE_ONCE(map->common.live, false);
	pasid_map_kernel_unmap(map);
	map->iova = HFI2_ROCE_KMR_PASID_IOVA_BASE;
	for (i = 0; i < reg->npages; i++) {
		ret = iommu_map(map->domain, map->iova + (i << PAGE_SHIFT),
				(phys_addr_t)reg->pfns[i] << PAGE_SHIFT, PAGE_SIZE,
				IOMMU_READ | IOMMU_WRITE, GFP_ATOMIC);
		if (ret) {
			pasid_map_kernel_unmap(map);
			spin_unlock(&map->map_lock);
			return ret;
		}
		map->length += PAGE_SIZE;
	}
	spin_unlock(&map->map_lock);
	return 0;
}

static struct hfi2_roce_pasid_map *
pasid_map_alloc_kernel(struct hfi2_devdata *dd)
{
	struct hfi2_roce_pasid_map *map;
	struct device *dev = &dd->pcidev->dev;
	int ret;

	map = kzalloc_node(sizeof(*map), GFP_KERNEL, dd->node);
	if (!map)
		return ERR_PTR(-ENOMEM);

	map->dd = dd;
	spin_lock_init(&map->map_lock);
	map->kernel_mr = true;
	map->common.pasid = IOMMU_PASID_INVALID;
	INIT_LIST_HEAD(&map->quarantine);

	map->domain =
		iommu_paging_domain_alloc_flags(dev, IOMMU_HWPT_ALLOC_PASID);
	if (IS_ERR(map->domain)) {
		ret = PTR_ERR(map->domain);
		map->domain = NULL;
		goto err_free;
	}

	map->common.pasid = iommu_alloc_global_pasid(dev);
	if (map->common.pasid == IOMMU_PASID_INVALID) {
		ret = -ENOSPC;
		goto err_free;
	}

	ret = iommu_attach_device_pasid(map->domain, dev, map->common.pasid,
					NULL);
	if (ret)
		goto err_free;
	map->attached = true;

	ret = xa_insert(&dd->roce_mr_pasid_map, (unsigned long)map, map,
			GFP_KERNEL);
	if (ret)
		goto err_free;
	map->tracked = true;
	hfi2_dms_roce_rif_pasid_activate(pasid_roce(dd), map->common.pasid);
	return map;

err_free:
	pasid_map_free(map);
	return ERR_PTR(ret);
}

/*
 * Clear this MR's R_Key entry, at most once.
 *
 * Revocation is not an optimisation.  A stale entry keeps a region
 * hardware-validatable after the MR describing it is gone, and hardware
 * populates a RIF entry from it on the next FIRST - so the window is not
 * "until someone notices" but "until the key is reused", after which the
 * placement lands in whatever region inherited it.
 *
 * It may run from LOCAL_INV under qp->s_hlock.  Take the saved identity
 * before issuing the non-sleeping CSR write so later MR release is a no-op.
 */
static void mr_rkey_revoke_locked(struct hfi2_roce_mr_priv *priv,
				  struct hfi2_devdata *dd)
{
	struct hfi2_dms_roce *roce;
	s8 bucket, internal_bucket;
	u32 rkey, internal_rkey;

	lockdep_assert_held(&priv->pageset_lock);
	bucket = priv->rkey_bucket;
	rkey = priv->rkey;
	internal_bucket = priv->internal_rkey_bucket;
	internal_rkey = priv->internal_rkey;
	priv->rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	priv->rkey = 0;
	priv->internal_rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	WRITE_ONCE(priv->internal_rkey, 0);
	roce = pasid_roce(dd);
	if (roce) {
		if (bucket != HFI2_ROCE_MR_NO_BUCKET)
			hfi2_dms_roce_rkey_invalidate(roce, rkey, (u8)bucket);
		if (internal_bucket != HFI2_ROCE_MR_NO_BUCKET)
			hfi2_dms_roce_rkey_invalidate(roce, internal_rkey,
						      (u8)internal_bucket);
	}
}

static void mr_rkey_uninstall(struct hfi2_roce_mr_priv *priv,
			      struct hfi2_devdata *dd)
{
	unsigned long flags;

	if (!priv)
		return;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->donor_generation++;
	mr_rkey_revoke_locked(priv, dd);
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
}

static bool mr_read_key_rotate(struct hfi2_roce_mr_priv *priv,
			       struct hfi2_dms_roce *roce, u32 *key)
{
	int ret;

	if (!priv->read_key_slot) {
		priv->read_key_disabled = true;
		return false;
	}
	ret = rvt_rotate_internal_mr_key(priv->read_key_slot, key,
					 RVT_INTERNAL_MR_KEY_NO_WRAP);
	if (!ret)
		return true;
	priv->read_key_disabled = true;
	if (ret == -EOVERFLOW)
		atomic64_inc(&roce->stats.internal_rkey_exhausted);
	return false;
}

void hfi2_roce_revoke_read_key(struct hfi2_devdata *dd, struct rvt_mregion *mr,
			       u32 key)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_dms_roce *roce = pasid_roce(dd);
	struct hfi2_dms_roce_rkey_entry entry = {};
	struct ib_mr *slot = NULL;
	unsigned long flags;
	bool allocate;
	int bucket;

	if (!priv || !roce)
		return;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	allocate = priv->internal_rkey == key && !priv->read_key_slot &&
		   !priv->read_key_disabled;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (allocate) {
		slot = rvt_alloc_internal_mr(mr->pd);
		if (IS_ERR(slot))
			slot = NULL;
	}
	spin_lock_irqsave(&priv->pageset_lock, flags);
	/* The advertised key is the epoch: a sibling error must not rotate twice. */
	if (priv->internal_rkey != key ||
	    priv->internal_rkey_bucket == HFI2_ROCE_MR_NO_BUCKET)
		goto unlock;
	hfi2_dms_roce_rkey_invalidate(roce, key, priv->internal_rkey_bucket);
	hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG);
	priv->internal_rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	WRITE_ONCE(priv->internal_rkey, 0);
	if (!priv->read_key_slot) {
		priv->read_key_slot = slot;
		slot = NULL;
	}
	/* Never reuse a capability, including across FastReg cycles. */
	if (!mr_read_key_rotate(priv, roce, &entry.rkey))
		goto unlock;
	entry.start_vaddr = priv->read_key_iova;
	entry.length = priv->read_key_length;
	entry.pasid = priv->pasid->pasid;
	entry.permissions = EAL_RKEY_PERMISSION_WRITE;
	entry.internal = true;
	bucket = hfi2_dms_roce_rkey_install(roce, &entry, priv->pasid);
	if (bucket >= 0) {
		priv->internal_rkey_bucket = bucket;
		WRITE_ONCE(priv->internal_rkey, entry.rkey);
	}
unlock:
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (slot) {
		rvt_unpublish_internal_mr(slot);
		rvt_free_internal_mr(slot);
	}
}

/*
 * Install this MR's R_Key entry, so hardware can validate an inbound RETH
 * against it on a FIRST packet and place without software in the path.
 *
 * A failure here is never fatal to the MR.  Every reason the installer can
 * decline - a full row, a length the field cannot describe, a backend that is
 * not up - costs hardware-FIRST for this region and nothing else: software
 * still validates the FIRST and arms the RIF entry itself, and MIDDLEs are
 * still hardware-placed, because 4.5.2.5.13.3 never consults this table.
 */
static void mr_rkey_install(struct hfi2_roce_mr_priv *priv,
			    struct hfi2_devdata *dd, struct rvt_mregion *mr)
{
	struct hfi2_dms_roce_rkey_entry entry = {};
	struct hfi2_dms_roce *roce;
	int bucket;

	lockdep_assert_held(&priv->pageset_lock);
	roce = pasid_roce(dd);
	if (!roce)
		return;

	/* R_Key has no placement base distinct from the consumer's RETH VA. */
	if (priv->kmr_iova_delta)
		return;

	/*
	 * H15 lets an oversized MR past the eligibility gate so it can bind a
	 * PASID for the software-armed RIF entry, but the R_Key entry's length
	 * field is still 24 bits: entry.length = (u32)mr->length below would
	 * silently truncate and hardware would bounds-check against the wrong
	 * region.  Decline here instead - the MR keeps its PASID and gets no
	 * R_Key, which is exactly the state the software arm expects.
	 */
	if (mr->length > EAL_RKEY_LENGTH_MAX)
		return;

	/*
	 * start_vaddr is mr->iova, the IB address an inbound RETH.vaddr is
	 * compared against - not user_base, which is where the region happens
	 * to live in the registering process.  Hardware bounds-checks
	 * [start_vaddr, start_vaddr + length), so the two must be the same
	 * address space the peer will name.
	 */
	entry.start_vaddr = mr->iova;
	entry.length = (u32)mr->length;
	entry.rkey = mr->lkey;
	entry.pasid = priv->pasid->pasid;

	entry.permissions = hfi2_dms_roce_rkey_permissions(mr->access_flags);

	/*
	 * A region no peer may touch is not worth a public bucket.  Its local-write
	 * permission can still qualify it for the private reply-write key below.
	 *
	 * The R_Key is not bound to a QPN, and RUNNING RIF placement does not
	 * enforce the response length.  Software detects an overrun only after
	 * DMA; enable READ-as-WRITE only between trusted peers in the same mode.
	 */
	if (!entry.permissions) {
		roce->stats.rkey_no_remote_access++;
	} else {
		bucket = hfi2_dms_roce_rkey_install(roce, &entry, priv->pasid);
		if (bucket < 0) {
			dd_dev_dbg(dd,
				   "RoCE MR rkey 0x%x: R_Key install declined (%d), software-FIRST\n",
				   entry.rkey, bucket);
		} else {
			priv->rkey = entry.rkey;
			priv->rkey_bucket = (s8)bucket;
		}
	}

	if (!hfi2_dms_roce_hwp_mode(dd) || priv->read_key_disabled ||
	    !(mr->access_flags & IB_ACCESS_LOCAL_WRITE))
		return;

	if (priv->read_key_slot) {
		if (!mr_read_key_rotate(priv, roce, &entry.rkey))
			return;
	} else {
		entry.rkey ^= HFI2_ROCE_RKEY_INTERNAL_MARK;
	}
	entry.permissions = EAL_RKEY_PERMISSION_WRITE;
	entry.internal = true;
	bucket = hfi2_dms_roce_rkey_install(roce, &entry, priv->pasid);
	if (bucket < 0) {
		roce->stats.internal_rkey_install_fail++;
		dd_dev_dbg(dd,
			   "RoCE MR rkey 0x%x: internal write R_Key install declined (%d)\n",
			   entry.rkey, bucket);
		return;
	}
	priv->read_key_iova = entry.start_vaddr;
	priv->read_key_length = entry.length;
	priv->internal_rkey_bucket = (s8)bucket;
	WRITE_ONCE(priv->internal_rkey, entry.rkey);
	roce->stats.internal_rkey_install++;
}

int hfi2_roce_kmr_publish_reg(struct rvt_qp *qp, struct rvt_swqe *wqe,
			      int status)
{
	struct hfi2_roce_kmr_reg *reg = wqe->priv;
	struct hfi2_roce_mr_priv *priv = reg->mr->driver_priv;
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_dms_roce *roce = pasid_roce(dd);
	struct rvt_mregion snapshot = {
		.iova = reg->iova,
		.length = reg->length,
		.lkey = reg->key,
		.access_flags = reg->access,
	};
	unsigned long flags;

	spin_lock_irqsave(&priv->pageset_lock, flags);
	if (priv->donor_generation != reg->generation ||
	    priv->donor_window != reg->window ||
	    priv->hardware_generation > reg->local_generation) {
		status = -ESTALE;
		goto unlock;
	}
	mr_rkey_revoke_locked(priv, dd);
	if (status) {
		if (priv->local_generation == reg->local_generation)
			atomic_set(&reg->mr->lkey_invalid, 1);
		if (roce)
			atomic64_inc(&roce->stats.kmr_donor_err);
		goto unlock;
	}
	priv->hardware_generation = reg->local_generation;
	if (reg->map) {
		priv->kmr_iova_delta = reg->map->iova + reg->offset - reg->iova;
		WRITE_ONCE(reg->map->common.live, true);
	} else {
		priv->kmr_iova_delta = reg->window ? reg->donor_iova - reg->iova : 0;
	}
	if (priv->kmr_iova_delta) {
		if (roce)
			atomic64_inc(&roce->stats.kmr_donor_skip_iova);
	} else if (priv->pasid) {
		mr_rkey_install(priv, dd, &snapshot);
	}
	reg->published = true;
	if (roce)
		atomic64_inc(&roce->stats.kmr_donor_mapped);
unlock:
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	return status;
}

/*
 * Release the binding at most once.  Safe to call repeatedly, which is what
 * makes it safe to call from more than one teardown path.
 *
 * The R_Key entry goes first and the ordering is the same one the
 * address-space teardown uses: hardware creates a RIF entry from an R_Key hit,
 * so an entry left valid can produce placements after the PASID behind it is
 * released.
 *
 * Context: sleepable only.
 */
static void mr_pasid_release(struct hfi2_roce_mr_priv *priv,
			     struct hfi2_devdata *dd)
{
	if (!priv || !priv->pasid_ref_held)
		return;

	mr_rkey_uninstall(priv, dd);

	priv->pasid_ref_held = false;
	if (priv->pasid_type == HFI2_ROCE_PASID_SVA) {
		hfi2_roce_pasid_put(priv->sva);
	} else if (priv->pasid_type == HFI2_ROCE_PASID_MAP) {
		WRITE_ONCE(priv->map->common.live, false);
		pasid_quiesce_hardware(&priv->map->common, dd,
				       "MR deregistration");
		pasid_map_free(priv->map);
	} else if (priv->pasid_type == HFI2_ROCE_PASID_DONOR) {
		hfi2_roce_kmr_release_mr_window(priv, dd);
	} else if (priv->pasid_type == HFI2_ROCE_PASID_DONOR_DMABUF) {
		hfi2_roce_kmr_release_dmabuf(priv, dd);
	}
	priv->pasid = NULL;
	priv->sva = NULL;
	priv->map = NULL;
	priv->pasid_type = HFI2_ROCE_PASID_NONE;
}

void *hfi2_roce_mr_priv_alloc(struct rvt_dev_info *rdi, struct rvt_mregion *mr)
{
	struct hfi2_roce_mr_priv *priv;

	priv = kzalloc_node(sizeof(*priv), GFP_KERNEL, mr_priv_dd(rdi)->node);
	if (!priv)
		return ERR_PTR(-ENOMEM);

	/*
	 * Not left zeroed.  Bucket 0 is a LEGAL bucket, so a zeroed field makes
	 * an MR that never installed anything indistinguishable from one
	 * holding the first way of row 0, and its teardown would go on to
	 * invalidate an entry belonging to somebody else.
	 *
	 * Measured before this was fixed: two MRs per device reached teardown
	 * this way on an ordinary regression run.  They were caught one layer
	 * down, by hfi2_dms_roce_rkey_invalidate() rejecting rkey 0 as the
	 * no-owner sentinel - but only because priv->rkey happened to be zero
	 * too.  That is containment by coincidence, not by design.
	 */
	priv->rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	priv->internal_rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	spin_lock_init(&priv->pageset_lock);

	if (hfi2_roce_kmr_pasid_enabled &&
	    (!hfi2_roce_kmr_donor_enabled || !mr_priv_dd(rdi)->roce_kmr_donor) &&
	    !hfi2_bulksvc_roce_by_software(mr_priv_dd(rdi)) &&
	    mr_is_kernel_fastreg(mr)) {
		struct hfi2_devdata *dd = mr_priv_dd(rdi);
		struct hfi2_roce_pasid_map *map = pasid_map_alloc_kernel(dd);

		if (IS_ERR(map)) {
			if (pasid_roce(dd))
				pasid_roce(dd)->stats.kmr_pasid_err++;
		} else {
			priv->pasid = &map->common;
			priv->map = map;
			priv->pasid_type = HFI2_ROCE_PASID_MAP;
			priv->pasid_ref_held = true;
		}
	}

	return priv;
}

void hfi2_roce_mr_priv_free(struct rvt_dev_info *rdi, struct rvt_mregion *mr)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_devdata *dd = mr_priv_dd(rdi);
	struct bts_verbs_pageset *pageset;
	unsigned long flags;

	if (!priv)
		return;

	/*
	 * The only release point that is both sleepable and guaranteed to see
	 * every MR that reached mr_priv_alloc.  rvt_dereg_mr() can skip it when
	 * rvt_check_refs() times out, but that path deliberately leaks the
	 * whole MR to avoid a use-after-free, so a binding leaked with it is
	 * consistent with rdmavt's own choice rather than a new defect - and
	 * hfi2_roce_pasid_map_exit() reports it at device teardown.
	 */
	mr_pasid_release(priv, dd);
	if (priv->read_key_slot) {
		rvt_unpublish_internal_mr(priv->read_key_slot);
		rvt_free_internal_mr(priv->read_key_slot);
	}
	spin_lock_irqsave(&priv->pageset_lock, flags);
	pageset = priv->pageset;
	priv->pageset = NULL;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	bts_verbs_pageset_put(pageset);
	hfi2_dmabuf_do_unreg(dd, mr);
	mr->driver_priv = NULL;
	kfree(priv);
}

/* FastReg reserves its IOVA here but defers sleepable donor PTE work. */
int hfi2_roce_notify_mr_pages_set(struct rvt_dev_info *rdi,
				  struct rvt_mregion *mr)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_devdata *dd = mr_priv_dd(rdi);
	struct hfi2_roce_pasid_map *map;
	struct hfi2_roce_pasid_bind *bind;
	struct bts_verbs_pageset *old, *pageset;
	struct rvt_mr *rmr = mr_container(mr);
	struct mm_struct *mm;
	bool dmabuf;
	unsigned long flags;
	int ret;

	if (!priv)
		return 0;
	if (mr->driver_internal)
		return 0;

	if (mr_is_kernel_fastreg(mr) && hfi2_roce_kmr_donor_enabled &&
	    dd->roce_kmr_donor) {
		if (priv->pasid_type == HFI2_ROCE_PASID_DONOR) {
			mr_rkey_uninstall(priv, dd);
			hfi2_roce_kmr_release_mr_window(priv, dd);
		}
		if (!hfi2_dms_roce_mr_eligible(dd, false, false, true, mr->length))
			return 0;
		ret = hfi2_roce_kmr_map_mr(dd->roce_kmr_donor, mr, priv);
		if (ret) {
			if (pasid_roce(dd)) {
				if (ret == -ENOSPC)
					atomic64_inc(&pasid_roce(dd)->stats.kmr_donor_skip_pool);
				else
					atomic64_inc(&pasid_roce(dd)->stats.kmr_donor_err);
			}
			if (ret == -ENOSPC)
				dd_dev_warn_ratelimited(dd,
							"RoCE kernel MR of %zu bytes: roce_kmr_donor_gb=%u GiB IOVA space exhausted; raise it (max %u) or use roce_by_software=1\n",
							mr->length, hfi2_roce_kmr_donor_gb,
							HFI2_ROCE_KMR_DONOR_GB_MAX);
			/* access_flags arrive with REG_MR, after this hook. */
			return ret;
		}
		return 0;
	}

	ret = hfi2_dmabuf_do_pin(dd, mr);
	if (ret)
		return ret;

	if (mr_is_kernel_fastreg(mr)) {
		/* Select the mapped base; REG_MR translates later consumer IOVA changes. */
		if (priv->pasid_type == HFI2_ROCE_PASID_MAP && priv->map &&
		    priv->map->kernel_mr) {
			u64 iova = HFI2_ROCE_KMR_PASID_IOVA_BASE +
				   (mr->iova & ~PAGE_MASK);

			rmr->ibmr.iova = iova;
			mr->iova = iova;
			mr->user_base = iova;
		}
		return 0;
	}

	mr_pasid_release(priv, dd);
	pageset = bts_verbs_pageset_create(dd->bulksvc, mr);
	if (IS_ERR(pageset))
		pageset = NULL;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	old = priv->pageset;
	priv->pageset = pageset;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	bts_verbs_pageset_put(old);
	if (!pageset)
		return 0;

	/*
	 * The MR-lifetime half of the eligibility ladder; the ordering argument
	 * and the counters live with the helper in dms_roce.c.  @mm is passed
	 * as a presence test rather than a pointer because the helper only asks
	 * whether an address space exists - it has no use for which one, and
	 * taking the pointer would invite a future reader to dereference it
	 * outside the lifetime rules that govern it here.  A pinned dma-buf
	 * has no address space and takes a driver PASID map instead.
	 */
	dmabuf = rmr->umem && rmr->umem->is_dmabuf;
	mm = mr_owning_mm(mr);
	if (!hfi2_dms_roce_mr_eligible(dd, !!mm,
					   mr_is_pinned_dmabuf(mr), false,
					   mr->length))
		return 0;

	if (dmabuf) {
		map = pasid_map_alloc_user(dd, mr);
		if (!IS_ERR(map)) {
			priv->pasid = &map->common;
			priv->map = map;
			priv->pasid_type = HFI2_ROCE_PASID_MAP;
			atomic64_inc(&dd->roce_mr_pasid_map_count);
			atomic64_inc(&dd->roce_mr_pasid_dmabuf_count);
		} else if (dd->roce_kmr_donor) {
			ret = hfi2_roce_kmr_map_dmabuf_mr(dd->roce_kmr_donor, mr, priv);
			if (!ret) {
				priv->pasid = &dd->roce_kmr_donor->bind->common;
				priv->sva = dd->roce_kmr_donor->bind;
				priv->pasid_type = HFI2_ROCE_PASID_DONOR_DMABUF;
				if (pasid_roce(dd))
					atomic64_inc(&pasid_roce(dd)->stats
						     .kmr_donor_dmabuf_mapped);
			} else {
				if (pasid_roce(dd)) {
					if (ret == -EBUSY)
						atomic64_inc(&pasid_roce(dd)->stats
							     .kmr_donor_dmabuf_busy);
					else
						atomic64_inc(&pasid_roce(dd)->stats
							     .kmr_donor_dmabuf_err);
				}
				dd_dev_dbg(dd,
					   "RoCE dma-buf MR lkey 0x%x: PASID map %ld, donor map %d; software placement\n",
					   mr->lkey, PTR_ERR(map), ret);
				if (atomic_cmpxchg(&dd->roce_dmabuf_donor_warned, 0, 1) == 0)
					dd_dev_warn_ratelimited(dd,
						"RoCE GPU WRITE targets require the KMR donor or AMD IOMMU paging-domain PASID support\n");
				return 0;
			}
		} else {
			dd_dev_dbg(dd,
				   "RoCE dma-buf MR lkey 0x%x: PASID map %ld; software placement\n",
				   mr->lkey, PTR_ERR(map));
			if (atomic_cmpxchg(&dd->roce_dmabuf_donor_warned, 0, 1) == 0)
				dd_dev_warn_ratelimited(dd,
					"RoCE GPU WRITE targets require the KMR donor or AMD IOMMU paging-domain PASID support\n");
			return 0;
		}
	} else {
		/*
		 * mmu_notifier_register() requires the caller to keep mm_users
		 * from reaching zero for the duration, and says the mm should be
		 * current->mm or pinned with get_task_mm().  The umem's
		 * reference does NOT satisfy that: ib_umem_get() takes mmgrab()
		 * - mm_count, which keeps the mm_struct allocated - and
		 * deliberately not mmget(), which would block process exit
		 * (core/umem.c:204-205).
		 *
		 * The equality is what makes the bind safe, and it holds by
		 * construction: rvt_reg_user_mr() sets owning_mm = current->mm
		 * in ib_umem_get() and reaches this hook in the same thread a
		 * few frames later.  The FastReg caller, rvt_map_mr_sg(), never
		 * has a umem at all - mr->umem is assigned in exactly one place
		 * in rdmavt - so it is turned away by the NULL check above and
		 * never arrives here.
		 *
		 * Checked rather than assumed, because the assumption is
		 * invisible at the call site and a future caller that violates
		 * it would produce a use-after-free in the notifier rather than
		 * anything diagnosable.
		 */
		if (WARN_ON_ONCE(mm != current->mm))
			return 0;

		bind = hfi2_roce_pasid_get(dd, mm);
		if (!IS_ERR(bind)) {
			priv->pasid = &bind->common;
			priv->sva = bind;
			priv->pasid_type = HFI2_ROCE_PASID_SVA;
			atomic64_inc(&dd->roce_mr_pasid_sva_count);
		} else {
			map = pasid_map_alloc_user(dd, mr);
			if (IS_ERR(map)) {
				dd_dev_dbg(dd,
					   "RoCE MR lkey 0x%x: SVA bind %ld, PASID map %ld; software placement\n",
					   mr->lkey, PTR_ERR(bind), PTR_ERR(map));
				return 0;
			}
			priv->pasid = &map->common;
			priv->map = map;
			priv->pasid_type = HFI2_ROCE_PASID_MAP;
			atomic64_inc(&dd->roce_mr_pasid_map_count);
		}
	}

	priv->pasid_ref_held = true;

	spin_lock_irqsave(&priv->pageset_lock, flags);
	mr_rkey_install(priv, dd, mr);
	spin_unlock_irqrestore(&priv->pageset_lock, flags);

	return 0;
}

u64 hfi2_roce_kmr_translate_iova(const struct hfi2_roce_mr_priv *priv,
				  u64 iova)
{
	return iova + priv->kmr_iova_delta;
}

int hfi2_roce_fast_reg_mr(struct rvt_dev_info *rdi, struct rvt_mregion *mr,
			  unsigned int *reg_flags)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_devdata *dd = mr_priv_dd(rdi);
	unsigned long flags;
	bool ordered;

	if (WARN_ON_ONCE(!reg_flags))
		return -EINVAL;
	*reg_flags = 0;
	if (WARN_ON_ONCE(!priv))
		return -EINVAL;
	/* Local SGEs name the consumer IOVA; offset still names the backing byte. */
	if (mr_is_kernel_fastreg(mr))
		mr->user_base = mr->iova;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->local_generation++;
	ordered = priv->deferred_invalidates || priv->deferred_registers;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (priv->pasid_type != HFI2_ROCE_PASID_DONOR && !ordered)
		return hfi2_roce_notify_register_mr(rdi, mr);

	/* An older SQ invalidate owns revocation until its successor can publish. */
	if (!ordered)
		mr_rkey_uninstall(priv, dd);
	if (!mr_is_kernel_fastreg(mr) ||
	    (priv->pasid_type == HFI2_ROCE_PASID_DONOR && !dd->roce_kmr_donor))
		return -EINVAL;
	*reg_flags = RVT_SEND_REG_MR_DEFERRED;
	return 0;
}

struct hfi2_roce_local_inv {
	struct rvt_mregion *mr;
	struct hfi2_roce_kmr_window *window;
	struct hfi2_roce_kmr_donor *donor;
	struct hfi2_roce_pasid_map *map;
	u64 generation;
	u64 local_generation;
	bool executed;
};

int hfi2_roce_setup_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct hfi2_roce_local_inv *inv;
	struct hfi2_roce_mr_priv *priv;
	struct rvt_mregion *mr;
	u32 key = wqe->wr.ex.invalidate_rkey;
	unsigned long flags;
	int ret = -EINVAL;

	if (!key)
		return -EINVAL;
	inv = kzalloc(sizeof(*inv), GFP_ATOMIC);
	if (!inv)
		return -ENOMEM;
	rcu_read_lock();
	mr = rcu_dereference(rdi->lkey_table.table[key >> rdi->lkey_table.shift]);
	if (!rvt_tryget_mr(mr))
		goto unlock;
	if (mr->driver_internal || mr->lkey != key || mr->pd != qp->ibqp.pd)
		goto put;
	priv = mr->driver_priv;
	if (!priv)
		goto put;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	inv->mr = mr;
	inv->window = priv->pasid_type == HFI2_ROCE_PASID_DONOR ?
		priv->donor_window : NULL;
	inv->donor = mr_priv_dd(rdi)->roce_kmr_donor;
	inv->map = priv->map && priv->map->kernel_mr ? priv->map : NULL;
	inv->generation = priv->donor_generation;
	inv->local_generation = priv->local_generation;
	if (inv->window)
		refcount_inc(&inv->window->refs);
	priv->deferred_invalidates++;
	atomic_set(&mr->lkey_invalid, 1);
	wqe->priv = inv;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	rcu_read_unlock();
	return 0;
put:
	rvt_put_mr(mr);
unlock:
	rcu_read_unlock();
	kfree(inv);
	return ret;
}

int hfi2_roce_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct hfi2_roce_local_inv *inv = wqe->priv;
	struct hfi2_roce_mr_priv *priv = inv->mr->driver_priv;
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	unsigned long flags;
	int ret = 0;

	/* Invalidate the saved hardware epoch, never the next post-time lkey. */
	spin_lock_irqsave(&priv->pageset_lock, flags);
	if (priv->donor_generation != inv->generation ||
	    priv->hardware_generation > inv->local_generation) {
		ret = -ESTALE;
	} else {
		mr_rkey_revoke_locked(priv, dd);
		if (inv->map) {
			spin_lock(&inv->map->map_lock);
			WRITE_ONCE(inv->map->common.live, false);
			pasid_map_kernel_unmap(inv->map);
			spin_unlock(&inv->map->map_lock);
		}
	}
	inv->executed = true;
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (ret)
		return ret;
	if (inv->window) {
		struct vm_area_struct *vma;
		unsigned long va = inv->window->pfn << PAGE_SHIFT;
		unsigned long len = inv->window->npages << PAGE_SHIFT;

		mmap_read_lock(inv->donor->mm);
		vma = vma_lookup(inv->donor->mm, va);
		if (!vma || va < vma->vm_start || len > vma->vm_end - va)
			ret = -EINVAL;
		else
			zap_special_vma_range(vma, va, len);
		mmap_read_unlock(inv->donor->mm);
	}
	return ret;
}

void hfi2_roce_cleanup_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe)
{
	struct hfi2_roce_local_inv *inv = wqe->priv;
	struct hfi2_roce_mr_priv *priv = inv->mr->driver_priv;
	unsigned long flags;

	wqe->priv = NULL;
	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->deferred_invalidates--;
	if (!inv->executed && priv->donor_generation == inv->generation &&
	    priv->hardware_generation <= inv->local_generation) {
		mr_rkey_revoke_locked(priv, dd_from_ibdev(qp->ibqp.device));
		if (inv->map)
			WRITE_ONCE(inv->map->common.live, false);
	}
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	hfi2_roce_kmr_release_window(inv->donor, inv->window);
	rvt_put_mr(inv->mr);
	kfree(inv);
}

int hfi2_roce_notify_register_mr(struct rvt_dev_info *rdi,
				 struct rvt_mregion *mr)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	struct hfi2_devdata *dd = mr_priv_dd(rdi);
	struct hfi2_dms_roce *roce = pasid_roce(dd);
	struct hfi2_roce_pasid_map *map;
	unsigned long flags;
	int ret;

	if (!priv)
		return 0;

	if (priv->pasid_type == HFI2_ROCE_PASID_DONOR) {
		mr_rkey_uninstall(priv, dd);
		/* Ordinary registration has no deferred SQ entry. */
		return -EOPNOTSUPP;
	}

	if (priv->pasid_type != HFI2_ROCE_PASID_MAP || !priv->map ||
	    !priv->map->kernel_mr) {
		/*
		 * No donor window or PASID map (e.g. pasid_map_alloc_kernel()
		 * failed): under hardware placement a WRITE to it would never
		 * finish.
		 */
		if ((dd->roce_kmr_donor || hfi2_roce_kmr_pasid_enabled) &&
		    mr_is_kernel_fastreg(mr) &&
		    (mr->access_flags & IB_ACCESS_REMOTE_WRITE) &&
		    !hfi2_bulksvc_roce_by_software(dd)) {
			atomic_set(&mr->lkey_invalid, 1);
			return -EFAULT;
		}
		return 0;
	}
	map = priv->map;
	if (READ_ONCE(map->common.quiesce_failed)) {
		mr_rkey_uninstall(priv, dd);
		return -EIO;
	}

	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->donor_generation++;
	mr_rkey_revoke_locked(priv, dd);
	spin_lock(&map->map_lock);
	WRITE_ONCE(map->common.live, false);
	pasid_map_kernel_unmap(map);
	ret = pasid_map_kernel_pages(map, mr);
	if (ret) {
		spin_unlock(&map->map_lock);
		spin_unlock_irqrestore(&priv->pageset_lock, flags);
		goto map_fail;
	}
	priv->kmr_iova_delta = map->iova + mr->offset - mr->iova;
	WRITE_ONCE(map->common.live, true);
	if (priv->kmr_iova_delta && roce)
		roce->stats.kmr_pasid_skip_iova++;
	mr_rkey_install(priv, dd, mr);
	priv->hardware_generation = priv->local_generation;
	spin_unlock(&map->map_lock);
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (roce)
		roce->stats.kmr_pasid_mapped++;
	return 0;

map_fail:
	if (roce) {
		if (ret == -ERANGE)
			roce->stats.kmr_pasid_skip_iova++;
		else
			roce->stats.kmr_pasid_err++;
	}
	/* As for the donor: NAK a peer WRITE rather than let it retry forever. */
	if (mr->access_flags & IB_ACCESS_REMOTE_WRITE) {
		atomic_set(&mr->lkey_invalid, 1);
		return ret;
	}
	return 0;
}

/*
 * LOCAL_INV reaches this from rvt_invalidate_rkey() under rcu_read_lock() and
 * qp->s_hlock.  R_Key revocation is spinlock/MMIO-only, so revoke it here;
 * the sleepable MR release later observes the consumed bucket and does nothing.
 */
void hfi2_roce_notify_unregister_mr(struct rvt_dev_info *rdi,
				    struct rvt_mregion *mr)
{
	struct hfi2_roce_mr_priv *priv = mr->driver_priv;
	unsigned long flags;
	bool donor;

	if (!priv)
		return;

	spin_lock_irqsave(&priv->pageset_lock, flags);
	priv->donor_generation++;
	mr_rkey_revoke_locked(priv, mr_priv_dd(rdi));
	donor = priv->pasid_type == HFI2_ROCE_PASID_DONOR;
	if (priv->map && priv->map->kernel_mr) {
		spin_lock(&priv->map->map_lock);
		WRITE_ONCE(priv->map->common.live, false);
		pasid_map_kernel_unmap(priv->map);
		spin_unlock(&priv->map->map_lock);
	}
	spin_unlock_irqrestore(&priv->pageset_lock, flags);
	if (donor)
		hfi2_roce_kmr_release_mr_window(priv, mr_priv_dd(rdi));
}
