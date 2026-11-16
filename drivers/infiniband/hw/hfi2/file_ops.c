// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 * Copyright(c) 2015-2020 Intel Corporation.
 */

#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/sched/mm.h>
#include <linux/bitmap.h>
#include <linux/dma-buf.h>
#include <linux/dma-direct.h>

#include <rdma/ib.h>
#include <rdma/ib_verbs.h>

#include <rdma/hfi2-abi.h>
#include "hfi2.h"
#include "affinity.h"
#include "pio.h"
#include "common.h"
#include "trace.h"
#include "mmu_rb.h"
#include "user_sdma.h"
#include "user_exp_rcv.h"
#include "pinning.h"
#include "file_ops.h"
#include "uverbs.h"
#include "bulksvc.h"

#undef pr_fmt
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

#define SEND_CTXT_HALT_TIMEOUT 1000 /* msecs */

/*
 * File operation functions
 */
static void init_subctxts(struct hfi2_ctxtdata *uctxt,
			  const struct hfi2_assign_ctxt_cmd *uinfo);
static int init_user_ctxt(struct hfi2_filedata *fd,
			  struct hfi2_ctxtdata *uctxt);
static void user_init(struct hfi2_ctxtdata *uctxt);
static int setup_base_ctxt(struct hfi2_filedata *fd,
			   struct hfi2_ctxtdata *uctxt);
static int setup_subctxt(struct hfi2_ctxtdata *uctxt);

static int find_sub_ctxt(struct hfi2_filedata *fd,
			 const struct hfi2_assign_ctxt_cmd *uinfo);
static int allocate_ctxt(struct hfi2_filedata *fd,
			 const struct hfi2_assign_ctxt_cmd *uinfo,
			 struct hfi2_ctxtdata **cd);
static void deallocate_ctxt(struct hfi2_ctxtdata *uctxt);



struct hfi2_filedata *hfi2_alloc_filedata(struct hfi2_devdata *dd)
{
	struct hfi2_filedata *fd;

	/* The real work is performed later in assign_ctxt() */

	fd = kzalloc_obj(*fd, GFP_KERNEL);

	if (!fd || init_srcu_struct(&fd->pq_srcu))
		goto nomem;
	kref_init(&fd->kref);
	spin_lock_init(&fd->pq_rcu_lock);
	spin_lock_init(&fd->tid_lock);
	spin_lock_init(&fd->invalid_lock);
	INIT_LIST_HEAD(&fd->eager_mmap_entries);
	mutex_init(&fd->mmap_entries_lock);
	mutex_init(&fd->eager_mmap_entries_lock);
	mutex_init(&fd->bulksvc_init_lock);
	fd->dd = dd;
	hfi2_dmabuf_ctx_init(&fd->dmabuf_ctx, dd);
	/* no port yet */
	fd->ppd = NULL;
	return fd;
nomem:
	kfree(fd);
	return NULL;
}



ssize_t hfi2_do_write_iter(struct hfi2_filedata *fd, struct iov_iter *from)
{
	struct hfi2_user_sdma_pkt_q *pq;
	struct hfi2_user_sdma_comp_q *cq = fd->cq;
	int done = 0, reqs = 0;
	unsigned long dim = from->nr_segs;
	int idx;

	if (!HFI2_CAP_IS_KSET(SDMA))
		return -EINVAL;
	if (!iter_is_iovec(from))
		return -EINVAL;
	idx = srcu_read_lock(&fd->pq_srcu);
	pq = srcu_dereference(fd->pq, &fd->pq_srcu);
	if (!cq || !pq) {
		srcu_read_unlock(&fd->pq_srcu, idx);
		return -EIO;
	}

	trace_hfi2_sdma_request(fd->dd,
				fd->uctxt ? fd->uctxt->ctxt :
				(fd->sc ? fd->sc->hw_context : 0),
				fd->subctxt, dim);

	if (atomic_read(&pq->n_reqs) == pq->n_max_reqs) {
		srcu_read_unlock(&fd->pq_srcu, idx);
		return -ENOSPC;
	}

	while (dim) {
		const struct iovec *iov = iter_iov(from);
		int ret;
		unsigned long count = 0;

		ret = hfi2_user_sdma_process_request(
			fd, (struct iovec *)(iov + done), dim, &count);
		if (ret) {
			/*
			 * Do not clobber a positive count of already
			 * accepted/queued requests with this failure.
			 */
			if (!reqs)
				reqs = ret;
			break;
		}
		dim -= count;
		done += count;
		reqs++;
	}

	srcu_read_unlock(&fd->pq_srcu, idx);
	return reqs;
}

static inline void mmap_cdbg(u16 ctxt, u16 subctxt, u8 type, u8 mapio,
			     bool vmalloc, bool dma, u64 memaddr, void *memvirt,
			     dma_addr_t memdma, ssize_t memlen,
			     struct vm_area_struct *vma)
{
	hfi2_cdbg(
		PROC,
		"%u:%u type:%u io/vm/dma:%d/%d/%d, addr:0x%llx, len:%lu(%lu), flags:0x%lx",
		ctxt, subctxt, type, mapio, vmalloc, dma,
		memaddr ?: (u64)memvirt, memlen, vma->vm_end - vma->vm_start,
		vma->vm_flags);
}

int hfi2_do_mmap(struct hfi2_filedata *fd, u8 type, struct vm_area_struct *vma,
		 struct rdma_user_mmap_entry *rdma_entry,
		 struct ib_ucontext *ucontext)
{
	struct hfi2_user_mmap_entry *entry = to_hfi2_mmap(rdma_entry);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_devdata *dd;
	unsigned long flags;
	u64 memaddr = entry->address;
	void *memvirt = entry->memvirt;
	dma_addr_t memdma = entry->memdma;
	bool dma = entry->dma;
	bool vmalloc = entry->vmalloc;
	u8 mapio = 0;
	ssize_t memlen = rdma_entry->npages * PAGE_SIZE;
	int ret = 0;
	u16 ctxt;
	u16 subctxt;

	/*
	 * Bulksvc mappings (doorbell, queue pages, cntr pages, dirty
	 * bitmap) are per-fd, not per-context, and a bulksvc-only client
	 * may have no receive context at all.  Accept them without one;
	 * every other type requires an assigned context.
	 */
	if (!uctxt && !(type >= BULKSVC_FAST_DOORBELL &&
			type <= BULKSVC_CNTR_PAGE_LAST)) {
		ret = -EINVAL;
		goto done;
	}
	if (!(vma->vm_flags & VM_SHARED)) {
		ret = -EINVAL;
		goto done;
	}
	dd = fd->dd;
	ctxt = uctxt ? uctxt->ctxt : 0;
	subctxt = fd->subctxt;

	/*
	 * vm_pgoff is used as a buffer selector cookie.  Always mmap from
	 * the beginning.
	 */
	vma->vm_pgoff = 0;
	flags = vma->vm_flags;

	switch (type) {
	case PIO_BUFS:
	case PIO_BUFS_SOP:
		flags &= ~VM_MAYREAD;
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
		mapio = 1;
		break;
	case PIO_CRED:
		if (flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		flags &= ~VM_MAYWRITE;
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		break;
	case RCV_RHEQ:
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		flags &= ~VM_MAYWRITE;
		break;
	case RCV_HDRQ:
		break;
	case RCV_EGRBUF:
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		if (vma->vm_flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		flags &= ~VM_MAYWRITE;
		break;
	case UREGS:
		flags |= VM_DONTCOPY | VM_DONTEXPAND;
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		mapio = 1;
		break;
	case EVENTS:
		flags |= VM_DONTEXPAND;
		break;
	case STATUS:
		if (flags & VM_WRITE) {
			ret = -EPERM;
			goto done;
		}
		flags &= ~VM_MAYWRITE;
		flags |= VM_DONTEXPAND;
		break;
	case RTAIL:
		if (!HFI2_CAP_IS_USET(DMA_RTAIL)) {
			ret = -EINVAL;
			goto done;
		}
		if ((flags & VM_WRITE) || !hfi2_rcvhdrtail_kvaddr(uctxt)) {
			ret = -EPERM;
			goto done;
		}
		flags &= ~VM_MAYWRITE;
		break;
	case SUBCTXT_UREGS:
		flags |= VM_DONTEXPAND;
		break;
	case SUBCTXT_RCV_HDRQ:
		flags |= VM_DONTEXPAND;
		break;
	case SUBCTXT_EGRBUF:
		flags |= VM_DONTEXPAND;
		flags &= ~VM_MAYWRITE;
		break;
	case SDMA_COMP:
		if (!fd->cq) {
			ret = -EFAULT;
			goto done;
		}
		flags |= VM_DONTEXPAND;
		break;
	case BULKSVC_FAST_DOORBELL:
		/* MMIO doorbell page: uncached, not for read(). */
		flags &= ~VM_MAYREAD;
		flags |= VM_IO | VM_DONTEXPAND;
		mapio = 1;
		break;
	case BULKSVC_CMPLQ_CTRL0 ... BULKSVC_QUEUE_TYPES_LAST:
	case BULKSVC_CNTR_PAGE_FIRST ... BULKSVC_CNTR_PAGE_LAST:
		/* vmalloc-backed pages shared with userspace. */
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		if (type >= BULKSVC_CNTR_PAGE_FIRST &&
		    type <= BULKSVC_CNTR_PAGE_LAST) {
			/* counters are read-only from userspace */
			if (vma->vm_flags & VM_WRITE) {
				ret = -EPERM;
				goto done;
			}
			flags &= ~VM_MAYWRITE;
		}
		flags |= VM_DONTEXPAND;
		vmalloc = true;
		break;
	case BULKSVC_DIRTY_BITMAP:
		/* single writable kernel page; remapped by address. */
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		memaddr = virt_to_phys(memvirt);
		flags |= VM_DONTEXPAND;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if ((vma->vm_end - vma->vm_start) != memlen) {
		hfi2_cdbg(PROC, "%u:%u Memory size mismatch %lu:%lu",
			  ctxt, fd->subctxt,
			  (vma->vm_end - vma->vm_start), memlen);
		ret = -EINVAL;
		goto done;
	}

	vm_flags_reset(vma, flags);
	mmap_cdbg(ctxt, subctxt, type, mapio, vmalloc, dma, memaddr, memvirt,
		  memdma, memlen, vma);
	if (vmalloc) {
		if (!memvirt) {
			ret = -EINVAL;
			goto done;
		}
		ret = rdma_user_mmap_vmalloc(ucontext, vma, memvirt, rdma_entry);
	} else if (dma) {
		ret = dma_mmap_coherent(&dd->pcidev->dev, vma, memvirt, memdma,
					memlen);
		if (!ret)
			ret = rdma_user_mmap_entry_associate_vma(ucontext, vma,
							 rdma_entry);
	} else if (mapio) {
		ret = rdma_user_mmap_io(ucontext, vma, PFN_DOWN(memaddr),
					memlen, vma->vm_page_prot, rdma_entry);
	} else if (memvirt) {
		ret = remap_pfn_range(vma, vma->vm_start,
				      PFN_DOWN(__pa(memvirt)), memlen,
				      vma->vm_page_prot);
	} else {
		ret = remap_pfn_range(vma, vma->vm_start, PFN_DOWN(memaddr),
				      memlen, vma->vm_page_prot);
	}
done:
	return ret;
}



void hfi2_filedata_release(struct kref *kref)
{
	struct hfi2_filedata *fdata = container_of(kref, struct hfi2_filedata,
						   kref);

	cleanup_srcu_struct(&fdata->pq_srcu);
	kfree(fdata);
}

void hfi2_dealloc_filedata(struct hfi2_filedata *fdata)
{
	struct hfi2_ctxtdata *uctxt = fdata->uctxt;
	struct hfi2_devdata *dd = fdata->dd;
	unsigned long flags, *ev;


	/* Begin bulksvc teardown FIRST, before any other cleanup */
	if (fdata->bulksvc_user_info)
		hfi2_bulksvc_user_info_begin_teardown(fdata->bulksvc_user_info);
	if (fdata->send_only) {
		struct send_context *sc = fdata->sc;
		/*
		 * Send-only contexts have no hfi2_ctxtdata and skip the
		 * normal teardown below.  hfi2_sc_free() handles all hardware
		 * cleanup via SC_CHK_FREE_OP, which zeros the check_enable,
		 * partition_key, and opcode registers (including SRIOV
		 * hfi2_loopback mirrors).  The explicit SC_CHK_ADJ_OP and
		 * hfi2_clear_ctxt_pkey() calls in the normal path are
		 * belt-and-suspenders for the window between hfi2_sc_disable()
		 * and hfi2_sc_free(); no such window exists here.
		 */
		if (sc) {
			flush_wc();
			hfi2_user_sdma_free_queues(fdata, NULL);
			if (dd->sc_events)
				dd->sc_events[sc->sw_index] = 0;
			clear_bit(sc->sw_index, dd->sc_events_bitmap);
			hfi2_clear_ctxt_jkey(dd, sc, HFI2_NO_RCV_CTXT);
			hfi2_sc_free(sc);
		}
		fdata->sc = NULL;
		fdata->send_only = false;
		if (fdata->ppd) {
			mutex_lock(&hfi2_mutex);
			atomic_dec(&fdata->ppd->num_send_only_ctxts);
			mutex_unlock(&hfi2_mutex);
		}
		goto done;
	}
	if (!uctxt)
		goto done;

	hfi2_cdbg(PROC, "closing ctxt %u:%u", uctxt->ctxt, fdata->subctxt);

	flush_wc();
	/* drain user sdma queue */
	hfi2_user_sdma_free_queues(fdata, uctxt);

	/* clean up rcv side */
	hfi2_user_exp_rcv_free(fdata);

	/*
	 * fdata->uctxt is used in the above cleanup.  It is not ready to be
	 * removed until here.
	 */
	fdata->uctxt = NULL;
	hfi2_rcd_put(uctxt);

	/*
	 * Clear any left over, unhandled events so the next process that
	 * gets this context doesn't get confused.
	 */
	if (dd->events) {
		ev = dd->events + uctxt_offset(uctxt) + fdata->subctxt;
		*ev = 0;
	}

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	__clear_bit(fdata->subctxt, uctxt->in_use_ctxts);
	if (!bitmap_empty(uctxt->in_use_ctxts, HFI2_MAX_SHARED_CTXTS)) {
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		goto done;
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	/*
	 * Disable receive context and interrupt available, reset all
	 * RcvCtxtCtrl bits to default values.
	 */
	hfi2_rcvctrl(
		dd,
		HFI2_RCVCTRL_CTXT_DIS | HFI2_RCVCTRL_TIDFLOW_DIS |
			HFI2_RCVCTRL_INTRAVAIL_DIS | HFI2_RCVCTRL_TAILUPD_DIS |
			HFI2_RCVCTRL_ONE_PKT_EGR_DIS |
			HFI2_RCVCTRL_NO_RHQ_DROP_DIS |
			HFI2_RCVCTRL_NO_EGR_DROP_DIS | HFI2_RCVCTRL_URGENT_DIS,
		uctxt);
	/* Clear the context's J_KEY */
	hfi2_clear_ctxt_jkey(dd, uctxt->sc, uctxt->ctxt);
	/*
	 * If a send context is allocated, reset context integrity
	 * checks to default and disable the send context.
	 */
	if (uctxt->sc) {
		hfi2_sc_disable(uctxt->sc);
		hfi2_priv_reg_op(dd, uctxt->sc->ppd->hw_pidx,
				 uctxt->sc->hw_context, uctxt->sc->type,
				 SC_CHK_ADJ_OP, 0);
	}

	hfi2_free_ctxt_rcv_groups(uctxt);
	hfi2_clear_ctxt_pkey(dd, uctxt->sc);

	uctxt->event_flags = 0;

	deallocate_ctxt(uctxt);
done:
	if (fdata->bulksvc_user_info) {
		hfi2_bulksvc_user_info_put(fdata->bulksvc_user_info);
		fdata->bulksvc_user_info = NULL;
	}
	hfi2_dmabuf_ctx_fini(&fdata->dmabuf_ctx);
	kref_put(&fdata->kref, hfi2_filedata_release);
}

/**
 * complete_subctxt - complete sub-context info
 * @fd: valid filedata pointer
 *
 * Sub-context info can only be set up after the base context
 * has been completed.  This is indicated by the clearing of the
 * HFI2_CTXT_BASE_UINIT bit.
 *
 * Wait for the bit to be cleared, and then complete the subcontext
 * initialization.
 *
 */
static int complete_subctxt(struct hfi2_filedata *fd)
{
	int ret;
	unsigned long flags;

	/*
	 * sub-context info can only be set up after the base context
	 * has been completed.
	 */
	ret = wait_event_interruptible(fd->uctxt->wait,
				       !test_bit(HFI2_CTXT_BASE_UNINIT,
						 &fd->uctxt->event_flags));

	if (test_bit(HFI2_CTXT_BASE_FAILED, &fd->uctxt->event_flags))
		ret = -ENOMEM;

	/* Finish the sub-context init */
	if (!ret)
		ret = init_user_ctxt(fd, fd->uctxt);

	if (ret) {
		int last;

		spin_lock_irqsave(&fd->dd->uctxt_lock, flags);
		__clear_bit(fd->subctxt, fd->uctxt->in_use_ctxts);
		last = bitmap_empty(fd->uctxt->in_use_ctxts,
				    HFI2_MAX_SHARED_CTXTS);
		spin_unlock_irqrestore(&fd->dd->uctxt_lock, flags);
		hfi2_rcd_put(fd->uctxt);

		/*
		 * When last is true this was the last reference to fd->uctxt.
		 * No new references to uctxt will be taken. So this task
		 * must free uctxt.
		 */
		if (last)
			deallocate_ctxt(fd->uctxt);
		fd->uctxt = NULL;
	}

	return ret;
}

int hfi2_do_assign_ctxt(struct hfi2_filedata *fd,
			const struct hfi2_assign_ctxt_cmd *uinfo)
{
	struct hfi2_ctxtdata *uctxt = NULL;
	int ret;
	u8 pidx = uinfo->port - 1;
	u8 kdeth_rcv_hdr = uinfo->kdeth_rcvhdrsz;

	if (fd->uctxt)
		return -EINVAL;

	if (uinfo->subctxt_cnt > HFI2_MAX_SHARED_CTXTS)
		return -EINVAL;

	/* check, then assign port ASAP */
	if (pidx >= fd->dd->num_pports)
		return -EINVAL;
	fd->ppd = fd->dd->pport + pidx;

	/* verify kdeth receive header size */
	if (kdeth_rcv_hdr == 0) /* change to default size */
		kdeth_rcv_hdr = DEFAULT_RCVHDRSIZE;
	if (kdeth_rcv_hdr < 2 || kdeth_rcv_hdr > 31) /* valid HW range */
		return -EINVAL;

	/*
	 * Acquire the mutex to protect against multiple creations of what
	 * could be a shared base context.
	 */
	mutex_lock(&hfi2_mutex);
	/*
	 * Get a sub context if available  (fd->uctxt will be set).
	 * ret < 0 error, 0 no context, 1 sub-context found
	 */
	ret = find_sub_ctxt(fd, uinfo);

	/*
	 * Allocate a base context if context sharing is not required or a
	 * sub context wasn't found.
	 */
	if (!ret) {
		ret = allocate_ctxt(fd, uinfo, &uctxt);
		if (ret == 0) {
			/* override - must be done before setup_base_ctxt() */
			uctxt->kdeth_rcv_hdr = kdeth_rcv_hdr;
		}
	}

	mutex_unlock(&hfi2_mutex);

	/* Depending on the context type, finish the appropriate init */
	switch (ret) {
	case 0:
		ret = setup_base_ctxt(fd, uctxt);
		if (ret)
			deallocate_ctxt(uctxt);
		break;
	case 1:
		ret = complete_subctxt(fd);
		break;
	default:
		break;
	}

	return ret;
}



/**
 * match_ctxt - match context
 * @fd: valid filedata pointer
 * @uinfo: user info to compare base context with
 * @uctxt: context to compare uinfo to.
 *
 * Compare the given context with the given information to see if it
 * can be used for a sub context.
 */
static int match_ctxt(struct hfi2_filedata *fd,
		      const struct hfi2_assign_ctxt_cmd *uinfo,
		      struct hfi2_ctxtdata *uctxt)
{
	struct hfi2_devdata *dd = fd->dd;
	unsigned long flags;
	u16 subctxt;

	/* Skip dynamically allocated kernel contexts */
	if (uctxt->sc && (uctxt->sc->type == SC_KERNEL))
		return 0;

	/* Skip ctxt if it doesn't match the requested one */
	if (memcmp(uctxt->uuid, uinfo->uuid, sizeof(uctxt->uuid)) ||
	    uctxt->jkey != generate_jkey(current_uid()) ||
	    uctxt->subctxt_id != uinfo->subctxt_id ||
	    uctxt->subctxt_cnt != uinfo->subctxt_cnt)
		return 0;

	/* Verify the sharing process matches the base */
	if (uctxt->userversion != uinfo->userversion)
		return -EINVAL;

	/* Find an unused sub context */
	spin_lock_irqsave(&dd->uctxt_lock, flags);
	if (bitmap_empty(uctxt->in_use_ctxts, HFI2_MAX_SHARED_CTXTS)) {
		/* context is being closed, do not use */
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		return 0;
	}

	subctxt =
		find_first_zero_bit(uctxt->in_use_ctxts, HFI2_MAX_SHARED_CTXTS);
	if (subctxt >= uctxt->subctxt_cnt) {
		spin_unlock_irqrestore(&dd->uctxt_lock, flags);
		return -EBUSY;
	}

	fd->subctxt = subctxt;
	__set_bit(fd->subctxt, uctxt->in_use_ctxts);
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	fd->uctxt = uctxt;
	hfi2_rcd_get(uctxt);

	return 1;
}

/**
 * find_sub_ctxt - fund sub-context
 * @fd: valid filedata pointer
 * @uinfo: matching info to use to find a possible context to share.
 *
 * The hfi2_mutex must be held when this function is called.  It is
 * necessary to ensure serialized creation of shared contexts.
 *
 * Return:
 *    0      No sub-context found
 *    1      Subcontext found and allocated
 *    errno  EINVAL (incorrect parameters)
 *           EBUSY (all sub contexts in use)
 */
static int find_sub_ctxt(struct hfi2_filedata *fd,
			 const struct hfi2_assign_ctxt_cmd *uinfo)
{
	struct hfi2_ctxtdata *uctxt;
	struct hfi2_devdata *dd = fd->dd;
	struct hfi2_pportdata *ppd = fd->ppd;
	struct hfi2_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	u16 i;
	int ret;

	if (!uinfo->subctxt_cnt)
		return 0;

	for (i = pr->first_dyn_alloc_ctxt;
	     i < pr->rcv_context_base + pr->num_rcv_contexts; i++) {
		uctxt = hfi2_rcd_get_by_index(dd, i);
		if (uctxt) {
			ret = match_ctxt(fd, uinfo, uctxt);
			hfi2_rcd_put(uctxt);
			/* value of != 0 will return */
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int allocate_ctxt(struct hfi2_filedata *fd,
			 const struct hfi2_assign_ctxt_cmd *uinfo,
			 struct hfi2_ctxtdata **rcd)
{
	struct hfi2_devdata *dd = fd->dd;
	struct hfi2_pportdata *ppd = fd->ppd;
	struct hfi2_ctxtdata *uctxt;
	int ret, numa;

	if (dd->flags & HFI2_FROZEN) {
		/*
		 * Pick an error that is unique from all other errors
		 * that are returned so the user process knows that
		 * it tried to allocate while the SPC was frozen.  It
		 * it should be able to retry with success in a short
		 * while.
		 */
		return -EIO;
	}

	if (!ppd->freectxts)
		return -EBUSY;

	/*
	 * Allocate context memory on the device's NUMA node.  Per-process
	 * CPU affinity is not enforced by the driver -- user space
	 * (sched_setaffinity, taskset) is responsible.
	 */
	numa = dd->node;
	ret = hfi2_create_ctxtdata(ppd, numa, DYNAMIC_CONTEXT, &uctxt);
	if (ret < 0) {
		dd_dev_err(dd, "user ctxtdata allocation failed\n");
		return ret;
	}
	hfi2_cdbg(PROC, "[%u:%u] pid %u assigned to NUMA %u", uctxt->ctxt,
		  fd->subctxt, current->pid, uctxt->numa_id);

	/*
	 * Allocate and enable a PIO send context.
	 */
	uctxt->sc = hfi2_sc_alloc(ppd, SC_USER, uctxt->rcvhdrqentsize, numa);
	if (!uctxt->sc) {
		ret = -ENOMEM;
		goto ctxdata_free;
	}
	hfi2_cdbg(PROC, "allocated send context %u(%u)", uctxt->sc->sw_index,
		  uctxt->sc->hw_context);
	ret = hfi2_sc_enable(uctxt->sc);
	if (ret)
		goto ctxdata_free;

	/*
	 * Setup sub context information if the user-level has requested
	 * sub contexts.
	 * This has to be done here so the rest of the sub-contexts find the
	 * proper base context.
	 * NOTE: _set_bit() can be used here because the context creation is
	 * protected by the mutex (rather than the spin_lock), and will be the
	 * very first instance of this context.
	 */
	__set_bit(0, uctxt->in_use_ctxts);
	if (uinfo->subctxt_cnt)
		init_subctxts(uctxt, uinfo);
	uctxt->userversion = uinfo->userversion;
	uctxt->flags = hfi2_cap_mask; /* save current flag state */
	init_waitqueue_head(&uctxt->wait);
	strscpy(uctxt->comm, current->comm, sizeof(uctxt->comm));
	memcpy(uctxt->uuid, uinfo->uuid, sizeof(uctxt->uuid));
	uctxt->jkey = generate_jkey(current_uid());
	hfi2_stats.sps_ctxts++;
	ppd->freectxts--;

	*rcd = uctxt;

	return 0;

ctxdata_free:
	hfi2_free_ctxt(uctxt);
	return ret;
}

static void deallocate_ctxt(struct hfi2_ctxtdata *uctxt)
{
	mutex_lock(&hfi2_mutex);
	hfi2_stats.sps_ctxts--;
	uctxt->ppd->freectxts++;
	mutex_unlock(&hfi2_mutex);

	hfi2_free_ctxt(uctxt);
}

static void init_subctxts(struct hfi2_ctxtdata *uctxt,
			  const struct hfi2_assign_ctxt_cmd *uinfo)
{
	uctxt->subctxt_cnt = uinfo->subctxt_cnt;
	uctxt->subctxt_id = uinfo->subctxt_id;
	set_bit(HFI2_CTXT_BASE_UNINIT, &uctxt->event_flags);
}

static int setup_subctxt(struct hfi2_ctxtdata *uctxt)
{
	int ret = 0;
	u16 num_subctxts = uctxt->subctxt_cnt;

	uctxt->subctxt_uregbase = vmalloc_user(PAGE_SIZE);
	if (!uctxt->subctxt_uregbase)
		return -ENOMEM;

	/* We can take the size of the RcvHdr Queue from the master */
	uctxt->subctxt_rcvhdr_base =
		vmalloc_user(rcvhdrq_size(uctxt) * num_subctxts);
	if (!uctxt->subctxt_rcvhdr_base) {
		ret = -ENOMEM;
		goto bail_ureg;
	}

	uctxt->subctxt_rcvegrbuf =
		vmalloc_user(uctxt->egrbufs.size * num_subctxts);
	if (!uctxt->subctxt_rcvegrbuf) {
		ret = -ENOMEM;
		goto bail_rhdr;
	}

	return 0;

bail_rhdr:
	vfree(uctxt->subctxt_rcvhdr_base);
	uctxt->subctxt_rcvhdr_base = NULL;
bail_ureg:
	vfree(uctxt->subctxt_uregbase);
	uctxt->subctxt_uregbase = NULL;

	return ret;
}

static void user_init(struct hfi2_ctxtdata *uctxt)
{
	unsigned int rcvctrl_ops = 0;

	/* initialize poll variables... */
	uctxt->urgent = 0;
	uctxt->urgent_poll = 0;

	/*
	 * Now enable the ctxt for receive.
	 * For chips that are set to DMA the tail register to memory
	 * when they change (and when the update bit transitions from
	 * 0 to 1.  So for those chips, we turn it off and then back on.
	 * This will (very briefly) affect any other open ctxts, but the
	 * duration is very short, and therefore isn't an issue.  We
	 * explicitly set the in-memory tail copy to 0 beforehand, so we
	 * don't have to wait to be sure the DMA update has happened
	 * (chip resets head/tail to 0 on transition to enable).
	 */
	if (hfi2_rcvhdrtail_kvaddr(uctxt))
		clear_rcvhdrtail(uctxt);

	/* Setup J_KEY before enabling the context */
	hfi2_set_ctxt_jkey(uctxt->dd, uctxt->sc, uctxt->ctxt, uctxt->flags, uctxt->jkey);

	rcvctrl_ops = HFI2_RCVCTRL_CTXT_ENB;
	rcvctrl_ops |= HFI2_RCVCTRL_URGENT_ENB;
	if (HFI2_CAP_UGET_MASK(uctxt->flags, HDRSUPP))
		rcvctrl_ops |= HFI2_RCVCTRL_TIDFLOW_ENB;
	/*
	 * Ignore the bit in the flags for now until proper
	 * support for multiple packet per rcv array entry is
	 * added.
	 */
	if (!HFI2_CAP_UGET_MASK(uctxt->flags, MULTI_PKT_EGR))
		rcvctrl_ops |= HFI2_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI2_CAP_UGET_MASK(uctxt->flags, NODROP_EGR_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI2_CAP_UGET_MASK(uctxt->flags, NODROP_RHQ_FULL))
		rcvctrl_ops |= HFI2_RCVCTRL_NO_RHQ_DROP_ENB;
	/*
	 * The RcvCtxtCtrl.TailUpd bit has to be explicitly written.
	 * We can't rely on the correct value to be set from prior
	 * uses of the chip or ctxt. Therefore, add the rcvctrl op
	 * for both cases.
	 */
	if (HFI2_CAP_UGET_MASK(uctxt->flags, DMA_RTAIL))
		rcvctrl_ops |= HFI2_RCVCTRL_TAILUPD_ENB;
	else
		rcvctrl_ops |= HFI2_RCVCTRL_TAILUPD_DIS;
	hfi2_rcvctrl(uctxt->dd, rcvctrl_ops, uctxt);
}

static int init_user_ctxt(struct hfi2_filedata *fd, struct hfi2_ctxtdata *uctxt)
{
	int ret;

	ret = hfi2_user_sdma_alloc_queues(uctxt, fd);
	if (ret)
		return ret;

	ret = hfi2_user_exp_rcv_init(fd, uctxt);
	if (ret)
		hfi2_user_sdma_free_queues(fd, uctxt);

	return ret;
}

static int setup_base_ctxt(struct hfi2_filedata *fd,
			   struct hfi2_ctxtdata *uctxt)
{
	struct hfi2_devdata *dd = uctxt->dd;
	int ret = 0;

	hfi2_init_ctxt(uctxt->sc);

	/* Now allocate the RcvHdr queue and eager buffers. */
	ret = hfi2_create_rcvhdrq(dd, uctxt);
	if (ret)
		goto done;

	ret = hfi2_setup_eagerbufs(uctxt);
	if (ret)
		goto done;

	/* If sub-contexts are enabled, do the appropriate setup */
	if (uctxt->subctxt_cnt)
		ret = setup_subctxt(uctxt);
	if (ret)
		goto done;

	ret = hfi2_alloc_ctxt_rcv_groups(uctxt);
	if (ret)
		goto done;

	ret = init_user_ctxt(fd, uctxt);
	if (ret) {
		hfi2_free_ctxt_rcv_groups(uctxt);
		goto done;
	}

	user_init(uctxt);

	/* Now that the context is set up, the fd can get a reference. */
	fd->uctxt = uctxt;
	hfi2_rcd_get(uctxt);

done:
	if (uctxt->subctxt_cnt) {
		/*
		 * On error, set the failed bit so sub-contexts will clean up
		 * correctly.
		 */
		if (ret)
			set_bit(HFI2_CTXT_BASE_FAILED, &uctxt->event_flags);

		/*
		 * Base context is done (successfully or not), notify anybody
		 * using a sub-context that is waiting for this completion.
		 */
		clear_bit(HFI2_CTXT_BASE_UNINIT, &uctxt->event_flags);
		wake_up(&uctxt->wait);
	}

	return ret;
}

/*
 * Find all user contexts in use, and set the specified bit in their
 * event mask.
 * See also find_ctxt() for a similar use, that is specific to send buffers.
 */
int hfi2_set_uevent_bits(struct hfi2_pportdata *ppd, const int evtbit)
{
	struct hfi2_ctxtdata *uctxt;
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	u16 ctxt;

	if (!dd->events)
		return -EINVAL;

	for (ctxt = pr->first_dyn_alloc_ctxt;
	     ctxt < pr->rcv_context_base + pr->num_rcv_contexts; ctxt++) {
		uctxt = hfi2_rcd_get_by_index(dd, ctxt);
		if (uctxt) {
			unsigned long *evs;
			int i;
			/*
			 * subctxt_cnt is 0 if not shared, so do base
			 * separately, first, then remaining subctxt, if any
			 */
			evs = dd->events + uctxt_offset(uctxt);
			set_bit(evtbit, evs);
			for (i = 1; i < uctxt->subctxt_cnt; i++)
				set_bit(evtbit, evs + i);
			hfi2_rcd_put(uctxt);
		}
	}

	return 0;
}

/**
 * hfi2_set_sc_uevent_bits - set event bits for send-only contexts on a port
 * @ppd: the port
 * @bit: the event bit to set
 *
 * Set the specified event bit for all active send-only contexts belonging
 * to the given port. Uses the sc_events_bitmap to identify which slots
 * are in use. Called from hard IRQ context (FROZEN, LINKDOWN) — uses
 * atomic bit ops.
 */
void hfi2_set_sc_uevent_bits(struct hfi2_pportdata *ppd, int bit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u32 num_sc = dd->num_send_contexts;
	unsigned long flags;
	int i;

	if (!dd->sc_events)
		return;

	spin_lock_irqsave(&dd->sc_lock, flags);
	for (i = 0; i < num_sc; i++) {
		struct send_context *sc;

		if (!test_bit(i, dd->sc_events_bitmap))
			continue;
		sc = dd->send_contexts[i].sc;
		if (sc && sc->ppd == ppd)
			set_bit(bit, &dd->sc_events[i]);
	}
	spin_unlock_irqrestore(&dd->sc_lock, flags);
}

/**
 * hfi2_manage_rcvq - manage a context's receive queue
 * @uctxt: the context
 * @subctxt: the sub-context
 * @start_stop: action to carry out
 *
 * start_stop == 0 disables receive on the context, for use in queue
 * overflow conditions.  start_stop==1 re-enables, to be used to
 * re-init the software copy of the head register
 */
int hfi2_manage_rcvq(struct hfi2_ctxtdata *uctxt, u16 subctxt, int start_stop)
{
	struct hfi2_devdata *dd = uctxt->dd;
	unsigned int rcvctrl_op;

	if (subctxt)
		return 0;

	/* atomically clear receive enable ctxt. */
	if (start_stop) {
		/*
		 * On enable, force in-memory copy of the tail register to
		 * 0, so that protocol code doesn't have to worry about
		 * whether or not the chip has yet updated the in-memory
		 * copy or not on return from the system call. The chip
		 * always resets it's tail register back to 0 on a
		 * transition from disabled to enabled.
		 */
		if (hfi2_rcvhdrtail_kvaddr(uctxt))
			clear_rcvhdrtail(uctxt);
		rcvctrl_op = HFI2_RCVCTRL_CTXT_ENB;
	} else {
		rcvctrl_op = HFI2_RCVCTRL_CTXT_DIS;
	}
	hfi2_rcvctrl(dd, rcvctrl_op, uctxt);
	/* always; new head should be equal to new tail; see above */

	return 0;
}

/*
 * clear the event notifier events for this context.
 * User process then performs actions appropriate to bit having been
 * set, if desired, and checks again in future.
 */
int hfi2_user_event_ack(struct hfi2_ctxtdata *uctxt, u16 subctxt,
			unsigned long events)
{
	int i;
	struct hfi2_devdata *dd = uctxt->dd;
	unsigned long *evs;

	if (!dd->events)
		return 0;

	evs = dd->events + uctxt_offset(uctxt) + subctxt;

	for (i = 0; i <= _HFI2_MAX_EVENT_BIT; i++) {
		if (!test_bit(i, &events))
			continue;
		clear_bit(i, evs);
	}
	return 0;
}

/*
 * Clear event notifier events for a send-only context.
 * Uses sc_events array indexed by sc->sw_index instead of
 * the per-receive-context events array.
 */
unsigned long hfi2_build_runtime_flags(unsigned long flags, bool use_mn)
{
	unsigned long rflags;

	rflags = (((flags >> HFI2_CAP_MISC_SHIFT) &
		   HFI2_CAP_MISC_MASK) << HFI2_CAP_USER_SHIFT) |
		 HFI2_CAP_UGET_MASK(flags, MASK) |
		 HFI2_CAP_KGET_MASK(flags, K2U);
	/* adjust flag if this fd is not able to cache */
	if (!use_mn)
		rflags |= HFI2_CAP_TID_UNMAP;
	return rflags;
}

int user_sc_event_ack(struct hfi2_filedata *fd, unsigned long events)
{
	struct hfi2_devdata *dd = fd->dd;
	int i;

	if (!dd->sc_events)
		return 0;
	for (i = 0; i <= _HFI2_MAX_EVENT_BIT; i++) {
		if (test_bit(i, &events))
			clear_bit(i, &dd->sc_events[fd->sc->sw_index]);
	}
	return 0;
}

int hfi2_user_set_ctxt_pkey(struct hfi2_ctxtdata *uctxt, u16 pkey)
{
	struct hfi2_pportdata *ppd = uctxt->ppd;
	struct hfi2_devdata *dd = uctxt->dd;
	int i;

	if (!HFI2_CAP_IS_USET(PKEY_CHECK))
		return -EPERM;

	if (pkey == LIM_MGMT_P_KEY || pkey == FULL_MGMT_P_KEY)
		return -EINVAL;

	for (i = 0; i < dd->params->pkey_table_size; i++)
		if (pkey == ppd->pkeys[i])
			return hfi2_set_ctxt_pkey(dd, uctxt->sc, pkey);

	return -ENOENT;
}

int user_sc_set_ctxt_pkey(struct send_context *sc, u16 pkey)
{
	int i;
	struct hfi2_pportdata *ppd = sc->ppd;
	struct hfi2_devdata *dd = sc->dd;

	if (!HFI2_CAP_IS_USET(PKEY_CHECK))
		return -EPERM;

	if (pkey == LIM_MGMT_P_KEY || pkey == FULL_MGMT_P_KEY)
		return -EINVAL;

	for (i = 0; i < dd->params->pkey_table_size; i++)
		if (pkey == ppd->pkeys[i])
			return hfi2_set_ctxt_pkey(dd, sc, pkey);

	return -ENOENT;
}

/**
 * hfi2_ctxt_reset - Reset a user context (normal or send-only)
 * @fd: valid hfi2_filedata
 */
int hfi2_ctxt_reset(struct hfi2_filedata *fd)
{
	struct send_context *sc;
	struct hfi2_devdata *dd;
	int ret = 0;

	if (!fd || !fd->dd)
		return -EINVAL;

	sc = fd->send_only ? fd->sc : (fd->uctxt ? fd->uctxt->sc : NULL);
	if (!sc)
		return -EINVAL;
	dd = fd->dd;

	/*
	 * There is no protection here. User level has to guarantee that
	 * no one will be writing to the send context while it is being
	 * re-initialized.  If user level breaks that guarantee, it will
	 * break it's own context and no one else's.
	 */

	/*
	 * Wait until the interrupt handler has marked the context as
	 * halted or frozen. Report error if we time out.
	 */
	wait_event_interruptible_timeout(
		sc->halt_wait, (sc->flags & (SCF_HALTED | SCF_LINK_DOWN)),
		msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
	if (!(sc->flags & (SCF_HALTED | SCF_LINK_DOWN)))
		return -ENOLCK;

	/*
	 * If the send context was halted due to a Freeze, wait until the
	 * device has been "unfrozen" before resetting the context.
	 */
	if (sc->flags & SCF_FROZEN) {
		wait_event_interruptible_timeout(
			dd->event_queue, !(READ_ONCE(dd->flags) & HFI2_FROZEN),
			msecs_to_jiffies(SEND_CTXT_HALT_TIMEOUT));
		if (dd->flags & HFI2_FROZEN)
			return -ENOLCK;

		if (dd->flags & HFI2_FORCED_FREEZE)
			/*
			 * Don't allow context reset if we are into
			 * forced freeze
			 */
			return -ENODEV;

		hfi2_sc_disable(sc);
		ret = hfi2_sc_enable(sc);
		if (!fd->send_only)
			hfi2_rcvctrl(dd, HFI2_RCVCTRL_CTXT_ENB, fd->uctxt);
	} else {
		ret = hfi2_sc_restart(sc);
	}
	if (!ret)
		hfi2_sc_return_credits(sc);

	return ret;
}

/* expects stats is already zeroed with memtype and index filled in */
int hfi2_get_pinning_stats(struct hfi2_filedata *fd,
			   struct hfi2_pin_stats *stats)
{
	struct hfi2_user_sdma_pkt_q *pq;
	int lockidx;
	int ret;

	if (!pinning_type_supported(stats->memtype))
		return -EINVAL;

	lockidx = srcu_read_lock(&fd->pq_srcu);
	pq = srcu_dereference(fd->pq, &fd->pq_srcu);
	if (pq)
		ret = hfi2_pinning_interfaces[stats->memtype].get_stats(
			pq, stats->index, stats);
	else
		ret = -EIO;
	srcu_read_unlock(&fd->pq_srcu, lockidx);
	return ret;
}



/* expects stats is already zeroed with memtype and index filled in */








// module_param in bulksvc.c
extern uint bulksvc_user_queue_size_pages_log2;
static void remove_bulksvc_mmap_entry(struct hfi2_filedata *fd, u8 type)
{
	struct rdma_user_mmap_entry *entry;

	mutex_lock(&fd->mmap_entries_lock);
	entry = fd->mmap_entries[type];
	fd->mmap_entries[type] = NULL;
	mutex_unlock(&fd->mmap_entries_lock);
	if (entry)
		rdma_user_mmap_entry_remove(entry);
}

int create_bulksvc_queue(struct ib_ucontext *ucontext,
			 struct hfi2_filedata *fd, struct hfi2_devdata *dd,
			 struct hfi2_bulksvc_user_info *const info,
			 bool is_cmplq, struct hfi2_bulksvc_queue_info **output_info)
{
	struct hfi2_bulksvc_queue_record *records, *rec;
	struct hfi2_bulksvc_queue_backing *backing;
	struct page **pages;
	u8 *num, max, ctrl_type, buf_type;
	u32 block_size, nr_pages, i;
	int slot, ret = 0;
	bool first;

	*output_info = NULL;
	mutex_lock(&info->queue_records_lock);
	records = is_cmplq ? info->cmplq_records : info->cmdq_records;
	num = is_cmplq ? &info->num_cmplqs : &info->num_cmdqs;
	max = is_cmplq ? BULKSVC_USER_MAX_NUM_CMPLQS : BULKSVC_USER_MAX_NUM_CMDQS;
	for (slot = 0; slot < max; slot++)
		if (!records[slot].active)
			break;
	if (slot == max) {
		ret = -ENOSPC;
		goto out;
	}
	rec = &records[slot];
	backing = rec->backing;
	first = !backing;
	if (first) {
		backing = kzalloc(sizeof(*backing), GFP_KERNEL);
		if (!backing) {
			ret = -ENOMEM;
			goto out;
		}
		backing->queue_info.queue_id = slot;
		backing->queue_info.queue_ctrl_mmap_size = PAGE_SIZE;
		backing->queue_info.queue_buffer_mmap_size =
			(1U << bulksvc_user_queue_size_pages_log2) * PAGE_SIZE;
		backing->ctrl = vmalloc_user(PAGE_SIZE);
		backing->queue_buf = vmalloc_user(backing->queue_info.queue_buffer_mmap_size);
		if (!backing->ctrl || !backing->queue_buf) {
			ret = -ENOMEM;
			goto free_backing;
		}
		nr_pages = backing->queue_info.queue_buffer_mmap_size / PAGE_SIZE;
		pages = kmalloc_array(2 * nr_pages, sizeof(*pages), GFP_KERNEL);
		if (!pages) {
			ret = -ENOMEM;
			goto free_backing;
		}
		for (i = 0; i < 2 * nr_pages; i++)
			pages[i] = vmalloc_to_page(backing->queue_buf + (i % nr_pages) * PAGE_SIZE);
		rec->queue_buf_magic = vmap(pages, 2 * nr_pages, 0, PAGE_KERNEL);
		kfree(pages);
		if (!rec->queue_buf_magic) {
			ret = -ENOMEM;
			goto free_backing;
		}
	} else {
		backing->ctrl->head = 0;
		backing->ctrl->tail = 0;
	}
	ctrl_type = (is_cmplq ? BULKSVC_CMPLQ_CTRL0 : BULKSVC_CMDQ_CTRL0) + slot;
	buf_type = (is_cmplq ? BULKSVC_CMPLQ_BUF0 : BULKSVC_CMDQ_BUF0) + slot;
	ret = hfi2_mmap_entry_insert(ucontext, fd, ctrl_type, PAGE_SIZE, 0,
				    backing->ctrl, 0, &backing->queue_info.queue_ctrl_mmap_token);
	if (ret)
		goto free_backing;
	ret = hfi2_mmap_entry_insert(ucontext, fd, buf_type,
				    backing->queue_info.queue_buffer_mmap_size, 0,
				    backing->queue_buf, 0,
				    &backing->queue_info.queue_buffer_mmap_token);
	if (ret) {
		remove_bulksvc_mmap_entry(fd, ctrl_type);
		goto free_backing;
	}
	if (first)
		rec->backing = backing;
	block_size = is_cmplq ? sizeof(union hfi2_bulksvc_upd) : HFI2_BULKSVC_CACHELINE_SIZE;
	rec->idx_mask = backing->queue_info.queue_buffer_mmap_size / block_size - 1;
	rec->head = (atomic64_t *)&backing->ctrl->head;
	rec->tail = (atomic64_t *)&backing->ctrl->tail;
	rec->inflight = 0;
	rec->max_inflight = is_cmplq ? rec->idx_mask : 0;
	rec->tail_shadow = 0;
	rec->head_shadow = 0;
	*output_info = &backing->queue_info;
	smp_store_release(&rec->active, true);
	if (slot >= *num)
		smp_store_release(num, slot + 1);
	goto out;

free_backing:
	if (first) {
		if (rec->queue_buf_magic) {
			vunmap(rec->queue_buf_magic);
			rec->queue_buf_magic = NULL;
		}
		vfree(backing->ctrl);
		vfree(backing->queue_buf);
		kfree(backing);
	}
out:
	mutex_unlock(&info->queue_records_lock);
	return ret;
}

int release_bulksvc_queue_slot(struct hfi2_filedata *fd,
			  struct hfi2_bulksvc_user_info *bulksvc_user_info,
			  bool is_cmplq, u32 queue_id)
{
	struct hfi2_devdata *dd = fd->dd;
	struct hfi2_bulksvc_queue_record *queue_rec;
	u8 const max_queues = is_cmplq ? BULKSVC_USER_MAX_NUM_CMPLQS :
					 BULKSVC_USER_MAX_NUM_CMDQS;
	u8 ctrl_type, buf_type;
	struct rdma_user_mmap_entry *entry;
	int rc = 0;

	if (queue_id >= max_queues) {
		dd_dev_err(dd, "invalid bulksvc queue id %u for release\n",
			   queue_id);
		return -EINVAL;
	}

	ctrl_type = (is_cmplq ? BULKSVC_CMPLQ_CTRL0 : BULKSVC_CMDQ_CTRL0) +
		    queue_id;
	buf_type = (is_cmplq ? BULKSVC_CMPLQ_BUF0 : BULKSVC_CMDQ_BUF0) +
		   queue_id;

	mutex_lock(&bulksvc_user_info->queue_records_lock);

	queue_rec = is_cmplq ? &bulksvc_user_info->cmplq_records[queue_id] :
			       &bulksvc_user_info->cmdq_records[queue_id];

	if (!queue_rec->active) {
		dd_dev_err(dd, "bulksvc %s queue %u is not active\n",
			   is_cmplq ? "completion" : "command", queue_id);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * State-only release: flip active so poll_single_client skips this
	 * slot and create_bulksvc_queue can recycle it.  The control page and
	 * queue buffer stay allocated; the next create on this slot zeroes
	 * head/tail before republishing active=true. Memory teardown only
	 * occurs on the full teardown path (user close).  Symmetric release
	 * with the smp_store_release(true) in create_bulksvc_queue keeps the
	 * publish/un-publish semantics consistent for the polling CPU.
	 */
	smp_store_release(&queue_rec->active, false);

	/* Drop this queue pair's mmap entries; userspace can no longer map. */
	mutex_lock(&fd->mmap_entries_lock);
	entry = fd->mmap_entries[ctrl_type];
	fd->mmap_entries[ctrl_type] = NULL;
	if (entry)
		rdma_user_mmap_entry_remove(entry);
	entry = fd->mmap_entries[buf_type];
	fd->mmap_entries[buf_type] = NULL;
	if (entry)
		rdma_user_mmap_entry_remove(entry);
	mutex_unlock(&fd->mmap_entries_lock);

	dd_dev_dbg(dd, "released bulksvc %s queue with id %u\n",
		   is_cmplq ? "completion" : "command", queue_id);

out:
	mutex_unlock(&bulksvc_user_info->queue_records_lock);
	return rc;
}

static int ensure_cntr_page(struct hfi2_bulksvc_user_info *const bulksvc_user_info)
{
	struct bulksvc_cntr_page *p;
	void *kaddr;

	/* Allocate first page or new page if the last is full. */
	if (!bulksvc_user_info->num_cntr_pages ||
	    bulksvc_user_info->cntr_pages[bulksvc_user_info->num_cntr_pages - 1].used >=
		    CNTRS_PER_PAGE) {
		if (bulksvc_user_info->num_cntr_pages ==
		    BULKSVC_USER_MAX_NUM_CNTR_PAGES) {
			dd_dev_err(bulksvc_user_info->svc->dd,
				   "tried to get bulksvc cntr page, but no more are allowed\n");
			return -ENOSPC;
		}
		kaddr = vmalloc_user(PAGE_SIZE);
		if (!kaddr)
			return -ENOMEM;

		p = &bulksvc_user_info->cntr_pages[bulksvc_user_info->num_cntr_pages];
		p->kaddr = kaddr;
		p->used = 0;
		p->page_id = bulksvc_user_info->num_cntr_pages;
		bulksvc_user_info->num_cntr_pages++;
	}

	return 0;
}

static int alloc_cntr_slot(struct hfi2_bulksvc_user_info *const bulksvc_user_info,
			   u8 *page_id, u32 *cntr_value_offset,
			   u32 *cntr_error_offset)
{
	struct bulksvc_cntr_page *p;
	u32 slot_idx;
	u32 base;
	int rc;

	rc = ensure_cntr_page(bulksvc_user_info);
	if (rc)
		return rc;

	p = &bulksvc_user_info->cntr_pages[bulksvc_user_info->num_cntr_pages - 1];
	slot_idx = p->used++;	/* reserves a slot for this cntr */
	base = slot_idx * CNTR_SLOT_SIZE;

	*page_id = p->page_id;
	*cntr_value_offset = base;
	*cntr_error_offset = base + CNTR_VALUE_SIZE;

	return 0;
}

int create_bulksvc_cntr(struct ib_ucontext *ucontext,
			struct hfi2_filedata *fd,
			struct hfi2_devdata *dd,
			struct hfi2_bulksvc_user_info *const bulksvc_user_info,
			struct hfi2_bulksvc_cntr_info **output_info)
{
	int rc = 0;

	mutex_lock(&bulksvc_user_info->queue_records_lock);

	*output_info = NULL;

	if (bulksvc_user_info->num_cntrs >= BULKSVC_USER_MAX_NUM_CNTRS) {
		rc = -ENOSPC;
		dd_dev_err(dd, "tried to get bulksvc cntr, but no more are available\n");
		goto out;
	}

	u8 page_id;
	u32 cntr_value_offset, cntr_error_offset;

	rc = alloc_cntr_slot(bulksvc_user_info, &page_id, &cntr_value_offset, &cntr_error_offset);
	if (rc) {
		dd_dev_err(dd, "tried to alloc bulksvc cntr slot, but there was an error\n");
		goto out;
	}

	struct bulksvc_cntr_page *pg = &bulksvc_user_info->cntr_pages[page_id];

	u32 block = bulksvc_user_info->num_cntrs >> BULKSVC_CNTR_BLOCK_SHIFT;
	struct hfi2_bulksvc_cntr *cntr;

	if (!bulksvc_user_info->cntr_blocks[block]) {
		bulksvc_user_info->cntr_blocks[block] =
			kcalloc(BULKSVC_CNTR_BLOCK_SIZE, sizeof(*cntr), GFP_KERNEL);
		if (!bulksvc_user_info->cntr_blocks[block]) {
			pg->used--;
			rc = -ENOMEM;
			goto out;
		}
	}
	cntr = bulksvc_cntr_at(bulksvc_user_info, bulksvc_user_info->num_cntrs);

	memset(cntr, 0, sizeof(*cntr));
	cntr->active = true;
	cntr->page_id = page_id;
	cntr->value_offset = cntr_value_offset;
	cntr->error_offset = cntr_error_offset;
	cntr->page_kaddr = pg->kaddr;

	/* Fill out UAPI-visible info */
	cntr->cntr_info.cntr_id = bulksvc_user_info->num_cntrs;

	u8 cntr_page_type = BULKSVC_CNTR_PAGE0 + page_id;

	mutex_lock(&fd->mmap_entries_lock);
	if (fd->mmap_entries[cntr_page_type]) {
		cntr->cntr_info.cntr_value_mmap_token =
			rdma_user_mmap_get_offset(fd->mmap_entries[cntr_page_type]);
		mutex_unlock(&fd->mmap_entries_lock);
	} else {
		mutex_unlock(&fd->mmap_entries_lock);
		rc = hfi2_mmap_entry_insert(ucontext, fd, cntr_page_type, PAGE_SIZE,
					    0, pg->kaddr, 0,
					    &cntr->cntr_info.cntr_value_mmap_token);
		if (rc) {
			pg->used--;
			goto out;
		}
	}
	cntr->cntr_info.cntr_error_mmap_token =
		cntr->cntr_info.cntr_value_mmap_token;

	cntr->cntr_info.cntr_value_offset = cntr_value_offset;
	cntr->cntr_info.cntr_error_offset = cntr_error_offset;
	cntr->cntr_info.cntr_slot_size = CNTR_SLOT_SIZE;

	/* Ensure counter slot starts from zero. */
	memset(pg->kaddr + cntr_value_offset, 0, CNTR_SLOT_SIZE);

	/* Return the info to userspace */
	*output_info = &cntr->cntr_info;

	/* Publish the new counter slot */
	bulksvc_user_info->num_cntrs++;

out:
	mutex_unlock(&bulksvc_user_info->queue_records_lock);
	return rc;
}



int init_bulksvc_client(struct ib_ucontext *ucontext,
			struct hfi2_filedata *fd, struct hfi2_bulksvc_client_init *out,
			struct hfi2_bulksvc_user_info **info_out)
{
	struct hfi2_bulksvc_user_info *info;
	struct hfi2_bulksvc_event_entry *event;
	struct hfi2_bulksvc *svc = fd->dd->bulksvc;
	int bit, ret;

	lockdep_assert_held(&fd->bulksvc_init_lock);
	*info_out = NULL;
	if (!svc)
		return -EINVAL;
	if (!hfi2_bulksvc_is_opa(svc))
		return -EOPNOTSUPP;
	if (!fd->dd->params->cce_int_force_reg)
		return -EINVAL;
	if (hfi2_fd_bulksvc_info(fd))
		return -EALREADY;
	info = hfi2_bulksvc_user_info_create(fd);
	if (!info)
		return -ENOMEM;
	mutex_lock(&svc->user_info_lock);
	bit = hfi2_bulksvc_dirty_bit_alloc_locked(svc);
	if (bit < 0) {
		mutex_unlock(&svc->user_info_lock);
		hfi2_bulksvc_user_info_abort(info);
		return -ENOSPC;
	}
	info->dirty_bit = bit;
	hfi2_bulksvc_user_info_bind_locked(info);
	mutex_unlock(&svc->user_info_lock);

	ret = hfi2_mmap_entry_insert(ucontext, fd, BULKSVC_FAST_DOORBELL, PAGE_SIZE,
				    fd->dd->bar_maps[0].physaddr +
				    fd->dd->params->cce_int_force_reg,
				    NULL, 0, &out->fast_doorbell);
	if (ret)
		goto abort;
	ret = hfi2_mmap_entry_insert(ucontext, fd, BULKSVC_DIRTY_BITMAP, PAGE_SIZE,
				    0, page_address(svc->dirty_notify.page), 0,
				    &out->dirty_bitmap_mmap_token);
	if (ret)
		goto remove_doorbell;
	event = kzalloc(sizeof(*event), GFP_KERNEL);
	if (!event) {
		ret = -ENOMEM;
		goto remove_bitmap;
	}
	event->event.type = BULKSVC_EVENT_TYPE_USER_INFO_ADD;
	event->event.user_info = info;
	ret = hfi2_bulksvc_enqueue_user_event(info, event);
	if (ret) {
		kfree(event);
		goto remove_bitmap;
	}
	out->client_key = info->client_key;
	out->flags = hfi2_bulksvc_requires_doorbell(svc) ? HFI2_HFISVC_CLIENT_FLAG_DOORBELL : 0;
	out->fast_doorbell_mmap_size = PAGE_SIZE;
	out->dirty_bitmap_mmap_size = PAGE_SIZE;
	out->dirty_bitmap_bit = bit;
	*info_out = info;
	return 0;

remove_bitmap:
	remove_bulksvc_mmap_entry(fd, BULKSVC_DIRTY_BITMAP);
remove_doorbell:
	remove_bulksvc_mmap_entry(fd, BULKSVC_FAST_DOORBELL);
abort:
	mutex_lock(&svc->user_info_lock);
	hfi2_bulksvc_user_info_unbind_locked(info);
	hfi2_bulksvc_dirty_bit_free_locked(svc, bit);
	mutex_unlock(&svc->user_info_lock);
	hfi2_bulksvc_user_info_abort(info);
	return ret;
}

int do_bulksvc_synccmd(struct hfi2_filedata *fd, struct hfi2_bulksvc_cmd *cmd)
{
	struct hfi2_bulksvc_userctxt_cmd_entry *entry;
	struct hfi2_bulksvc_user_info *info = hfi2_fd_bulksvc_info(fd);
	u64 size_to_alloc = sizeof(*entry) - sizeof(entry->cmd) +
		(cmd->hdr.num_blocks * HFI2_BULKSVC_CACHELINE_SIZE);
	u64 vaddr;
	u64 len;
	int ret;

	if (!info || !cmd->hdr.num_blocks)
		return -EINVAL;

	entry = kzalloc(size_to_alloc, GFP_KERNEL);
	if (!entry) {
		pr_err("failed to allocate bulksvc synccmd entry\n");
		return -ENOMEM;
	}

	memcpy(&entry->cmd, cmd, (cmd->hdr.num_blocks * HFI2_BULKSVC_CACHELINE_SIZE));
	/* Currently only accept dma buf mr_opens */
	if (entry->cmd.hdr.op != HFI2_BULKSVC_CMD_MR_OPEN ||
	    entry->cmd.payld->mr_open.hmem_iface != HFI2_HFISVC_HMEM_IFACE_DMABUF) {
		pr_err_ratelimited("unsupported bulksvc synccmd op or hmem iface, op %d iface %d\n",
		       entry->cmd.hdr.op, entry->cmd.payld->mr_open.hmem_iface);
		kfree(entry);
		return -EINVAL;
	}

	vaddr = entry->cmd.payld->mr_open.vaddr;
	len = entry->cmd.payld->mr_open.len;
	if (!hfi2_bulksvc_mr_span_ok(vaddr, len)) {
		kfree(entry);
		return -EINVAL;
	}
	entry->data.dmabuf_open.dmabuf = dma_buf_get(entry->cmd.payld->mr_open.hmem_device);
	if (IS_ERR(entry->data.dmabuf_open.dmabuf)) {
		ret = (int)PTR_ERR(entry->data.dmabuf_open.dmabuf);
		dd_dev_err_ratelimited(fd->dd, "Invalid hmem_device fd %d, %d\n",
				       entry->cmd.payld->mr_open.hmem_device, ret);
		kfree(entry);
		return ret;
	}


	mutex_lock(&info->userctxt_cmdq_lock);
	list_add_tail(&entry->node, &info->userctxt_cmdq);
	mutex_unlock(&info->userctxt_cmdq_lock);

	set_bit(info->dirty_bit,
		info->svc->dirty_notify.bitmap);
	hfi2_bulksvc_schedule_user(info);

	return 0;
}
