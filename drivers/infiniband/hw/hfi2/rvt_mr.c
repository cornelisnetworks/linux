// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2016 Intel Corporation.
 */

#include <linux/dma-resv.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/dma-buf.h>
#include <rdma/ib_umem.h>
#include <rdma/iter.h>
#include "rvt.h"
#include "rvt_vt.h"
#include "rvt_mr_internal.h"
#include "trace_rvt.h"

MODULE_IMPORT_NS("DMA_BUF");

/**
 * rvt_driver_mr_init - Init MR resources per driver
 * @rdi: rvt dev struct
 *
 * Do any intilization needed when a driver registers with rdmavt.
 *
 * Return: 0 on success or errno on failure
 */
int rvt_driver_mr_init(struct rvt_dev_info *rdi)
{
	unsigned int lkey_table_size = rdi->dparms.lkey_table_size;
	unsigned int lk_tab_size;
	int i;

	/*
	 * The top hfi1_lkey_table_size bits are used to index the
	 * table.  The lower 8 bits can be owned by the user (copied from
	 * the LKEY).  The remaining bits act as a generation number or tag.
	 */
	if (!lkey_table_size)
		return -EINVAL;

	spin_lock_init(&rdi->lkey_table.lock);

	/* ensure generation is at least 4 bits */
	if (lkey_table_size > RVT_MAX_LKEY_TABLE_BITS) {
		rvt_pr_warn(rdi, "lkey bits %u too large, reduced to %u\n",
			    lkey_table_size, RVT_MAX_LKEY_TABLE_BITS);
		rdi->dparms.lkey_table_size = RVT_MAX_LKEY_TABLE_BITS;
		lkey_table_size = rdi->dparms.lkey_table_size;
	}
	rdi->lkey_table.max = 1 << lkey_table_size;
	rdi->lkey_table.shift = 32 - lkey_table_size;
	lk_tab_size = rdi->lkey_table.max * sizeof(*rdi->lkey_table.table);
	rdi->lkey_table.table = (struct rvt_mregion __rcu **)
			       vmalloc_node(lk_tab_size, rdi->dparms.node);
	if (!rdi->lkey_table.table)
		return -ENOMEM;

	RCU_INIT_POINTER(rdi->dma_mr, NULL);
	for (i = 0; i < rdi->lkey_table.max; i++)
		RCU_INIT_POINTER(rdi->lkey_table.table[i], NULL);

	rdi->mr_dereg_wq = alloc_workqueue("rdmavt-mr-dereg", WQ_UNBOUND, 0);
	if (!rdi->mr_dereg_wq) {
		vfree(rdi->lkey_table.table);
		rdi->lkey_table.table = NULL;
		return -ENOMEM;
	}

	rdi->dparms.props.max_mr = rdi->lkey_table.max;
	return 0;
}

/**
 * rvt_mr_exit - clean up MR
 * @rdi: rvt dev structure
 *
 * called when drivers have unregistered or perhaps failed to register with us
 */
void rvt_mr_exit(struct rvt_dev_info *rdi)
{
	if (rdi->dma_mr)
		rvt_pr_err(rdi, "DMA MR not null!\n");

	/*
	 * Deferred kernel MR frees are queued from rcu_work, whose work in
	 * turn queues rvt_mr_free_rcu() with call_rcu(): wait for the grace
	 * periods that queue the work, drain the work, then wait again for
	 * the callbacks it queued, before the module text can go away.
	 */
	rcu_barrier();
	destroy_workqueue(rdi->mr_dereg_wq);
	rcu_barrier();
	vfree(rdi->lkey_table.table);
}

static void rvt_free_mregion_maps(struct rvt_mregion *mr)
{
	int i = mr->mapsz;

	mr->mapsz = 0;
	while (i)
		kfree(mr->map[--i]);
}

/* Allocate the counters and take the initial reference. */
int rvt_mr_refs_init(struct rvt_mregion *mr)
{
	mr->refs = alloc_percpu_gfp(struct rvt_mref, GFP_KERNEL);
	if (!mr->refs)
		return -ENOMEM;
	this_cpu_inc(mr->refs->gets);
	return 0;
}

void rvt_mr_refs_free(struct rvt_mregion *mr)
{
	free_percpu(mr->refs);
}

/*
 * References outstanding.  Puts are summed before gets, see struct rvt_mref;
 * the sums are 64-bit and the result is the difference modulo 2^32, which is
 * exact while fewer than 2^32 references are held.  A concurrent get can only
 * make the result too large, never too small.
 */
static u32 rvt_mr_refs(struct rvt_mregion *mr)
{
	u64 gets = 0, puts = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		puts += READ_ONCE(per_cpu_ptr(mr->refs, cpu)->puts);
	smp_mb(); /* all puts are read before any get */
	for_each_possible_cpu(cpu)
		gets += READ_ONCE(per_cpu_ptr(mr->refs, cpu)->gets);
	return (u32)(gets - puts);
}

void rvt_mr_put_slow(struct rvt_mregion *mr)
{
	if (!rvt_mr_refs(mr) && !atomic_xchg(&mr->done, 1))
		complete(&mr->comp);
}

static void rvt_deinit_mregion(struct rvt_mregion *mr)
{
	/* No grace period: only for an MR that was never published. */
	WARN_ON_ONCE(READ_ONCE(mr->dying));
	rvt_free_mregion_maps(mr);
	rvt_mr_refs_free(mr);
}

/* Stop new references and drop the initial one. */
void rvt_mr_kill(struct rvt_mregion *mr)
{
	WRITE_ONCE(mr->dying, 1);
	smp_mb(); /* pairs with the barriers in rvt_tryget_mr()/rvt_put_mr() */
	rvt_put_mr(mr);
}

/*
 * rkt->table[] and dma_mr are dereferenced under rcu_read_lock() before
 * rvt_tryget_mr(), and some readers (roce_rkey_is_dmabuf_do()) read mr->map[]
 * without a reference: the counters, the maps and the rvt_mr must outlive
 * those readers.
 */
static void rvt_mr_free_rcu(struct rcu_head *head)
{
	struct rvt_mr *mr = container_of(head, struct rvt_mr, rcu);

	rvt_free_mregion_maps(&mr->mr);
	rvt_mr_refs_free(&mr->mr);
	kfree(mr);
}

static int rvt_init_mregion(struct rvt_mregion *mr, struct ib_pd *pd,
			    int count)
{
	int m, i = 0;
	struct rvt_dev_info *dev = ib_to_rvt(pd->device);

	mr->mapsz = 0;
	m = (count + RVT_SEGSZ - 1) / RVT_SEGSZ;
	for (; i < m; i++) {
		mr->map[i] = kzalloc_node(sizeof(*mr->map[0]), GFP_KERNEL,
					  dev->dparms.node);
		if (!mr->map[i])
			goto bail;
		mr->mapsz++;
	}
	atomic_set(&mr->lkey_invalid, 1);
	init_completion(&mr->comp);
	atomic_set(&mr->done, 0);
	mr->dying = 0;
	/* count returning the ptr to user */
	if (rvt_mr_refs_init(mr))
		goto bail;

	mr->pd = pd;
	mr->max_segs = count;
	return 0;
bail:
	rvt_deinit_mregion(mr);
	return -ENOMEM;
}

/**
 * rvt_alloc_lkey - allocate an lkey
 * @mr: memory region that this lkey protects
 * @dma_region: 0->normal key, 1->restricted DMA key
 *
 * Returns 0 if successful, otherwise returns -errno.
 *
 * Increments mr reference count as required.
 *
 * Sets the lkey field mr for non-dma regions.
 *
 */
static int rvt_alloc_lkey(struct rvt_mregion *mr, int dma_region)
{
	unsigned long flags;
	u32 r;
	u32 n;
	int ret = 0;
	struct rvt_dev_info *dev = ib_to_rvt(mr->pd->device);
	struct rvt_lkey_table *rkt = &dev->lkey_table;

	rvt_get_mr(mr);
	spin_lock_irqsave(&rkt->lock, flags);

	/* special case for dma_mr lkey == 0 */
	if (dma_region) {
		struct rvt_mregion *tmr;

		tmr = rcu_access_pointer(dev->dma_mr);
		if (!tmr) {
			mr->lkey_published = 1;
			/* Insure published written first */
			rcu_assign_pointer(dev->dma_mr, mr);
			rvt_get_mr(mr);
		}
		goto success;
	}

	/* Find the next available LKEY */
	r = rkt->next;
	n = r;
	for (;;) {
		if (!rcu_access_pointer(rkt->table[r]))
			break;
		r = (r + 1) & (rkt->max - 1);
		if (r == n)
			goto bail;
	}
	rkt->next = (r + 1) & (rkt->max - 1);
	/*
	 * Make sure lkey is never zero which is reserved to indicate an
	 * unrestricted LKEY.
	 */
	rkt->gen++;
	/*
	 * The generation fills every bit below the table index, so the low
	 * key bits change with every registration instead of being 0 for
	 * every MR.  CN6000 EAL picks the R_Key table row from key[8:0].  A
	 * ULP that calls ib_inc_rkey() still owns the low byte afterwards:
	 * rvt_fast_reg_mr() compares only bits [31:8].
	 */
	mr->lkey = (r << (32 - dev->dparms.lkey_table_size)) |
		(((1u << (32 - dev->dparms.lkey_table_size)) - 1) & rkt->gen);
	/*
	 * Key 0 means "kernel virtual address" to rvt_rkey_ok() and
	 * rvt_lkey_ok().  The consumer owns the low byte and FastReg ULPs
	 * advance it on every registration (rpcrdma: ib_update_fast_reg_key()
	 * with ++key), so it wraps through 0 every 256 registrations.  Keep
	 * bits [31:8] non-zero so no consumer byte can turn the key into 0;
	 * otherwise a peer's READ of such an MR dereferences its raw IOVA.
	 */
	if (!(mr->lkey & ~0xffu))
		mr->lkey |= 0x100;
	mr->lkey_published = 1;
	/* Insure published written first */
	rcu_assign_pointer(rkt->table[r], mr);
success:
	spin_unlock_irqrestore(&rkt->lock, flags);
out:
	return ret;
bail:
	rvt_put_mr(mr);
	spin_unlock_irqrestore(&rkt->lock, flags);
	ret = -ENOMEM;
	goto out;
}

/**
 * rvt_free_lkey - free an lkey
 * @mr: mr to free from tables
 */
static void rvt_free_lkey(struct rvt_mregion *mr)
{
	unsigned long flags;
	u32 lkey = mr->lkey;
	u32 r;
	struct rvt_dev_info *dev = container_of(mr, struct rvt_mr, mr)->rdi;
	struct rvt_lkey_table *rkt = &dev->lkey_table;
	int freed = 0;

	spin_lock_irqsave(&rkt->lock, flags);
	if (!lkey) {
		if (mr->lkey_published) {
			mr->lkey_published = 0;
			/* insure published is written before pointer */
			rcu_assign_pointer(dev->dma_mr, NULL);
			rvt_put_mr(mr);
		}
	} else {
		if (!mr->lkey_published)
			goto out;
		r = lkey >> (32 - dev->dparms.lkey_table_size);
		mr->lkey_published = 0;
		/* insure published is written before pointer */
		rcu_assign_pointer(rkt->table[r], NULL);
	}
	freed++;
out:
	spin_unlock_irqrestore(&rkt->lock, flags);
	if (freed)
		rvt_mr_kill(mr);
}

static int rvt_check_refs(struct rvt_mregion *mr, const char *t);


static struct rvt_mr *__rvt_alloc_mr(int count, struct ib_pd *pd, bool driver_internal)
{
	struct rvt_dev_info *rdi = ib_to_rvt(pd->device);
	struct rvt_mr *mr;
	int rval = -ENOMEM;
	int m;

	if (unlikely(count < 0))
		return ERR_PTR(-EINVAL);

	/* Allocate struct plus pointers to first level page tables. */
	m = (count + RVT_SEGSZ - 1) / RVT_SEGSZ;
	mr = kzalloc_flex(*mr, mr.map, m);
	if (!mr)
		goto bail;

	rval = rvt_init_mregion(&mr->mr, pd, count);
	if (rval)
		goto bail;

	mr->rdi = rdi;
	mr->mr.driver_internal = driver_internal;

	if (!driver_internal && rdi->driver_f.mr_priv_alloc) {
		void *priv = rdi->driver_f.mr_priv_alloc(rdi, &mr->mr);

		if (IS_ERR(priv)) {
			rval = PTR_ERR(priv);
			goto bail_mregion;
		}
		mr->mr.driver_priv = priv;
	}

	/*
	 * ib_reg_phys_mr() will initialize mr->ibmr except for
	 * lkey and rkey.
	 */
	rval = rvt_alloc_lkey(&mr->mr, 0);
	if (rval)
		goto bail_priv;
	mr->ibmr.lkey = mr->mr.lkey;
	mr->ibmr.rkey = mr->mr.lkey;
done:
	return mr;

bail_priv:
	if (!driver_internal && rdi->driver_f.mr_priv_free)
		rdi->driver_f.mr_priv_free(rdi, &mr->mr);
bail_mregion:
	rvt_deinit_mregion(&mr->mr);
bail:
	kfree(mr);
	mr = ERR_PTR(rval);
	goto done;
}

/**
 * rvt_get_dma_mr - get a DMA memory region
 * @pd: protection domain for this memory region
 * @acc: access flags
 *
 * Return: the memory region on success, otherwise returns an errno.
 */
struct ib_mr *rvt_get_dma_mr(struct ib_pd *pd, int acc)
{
	struct rvt_dev_info *rdi = ib_to_rvt(pd->device);
	struct rvt_mr *mr;
	struct ib_mr *ret;
	int rval;

	if (ibpd_to_rvtpd(pd)->user)
		return ERR_PTR(-EPERM);

	mr = kzalloc_obj(*mr);
	if (!mr) {
		ret = ERR_PTR(-ENOMEM);
		goto bail;
	}

	rval = rvt_init_mregion(&mr->mr, pd, 0);
	if (rval) {
		ret = ERR_PTR(rval);
		goto bail;
	}

	mr->rdi = rdi;

	if (rdi->driver_f.mr_priv_alloc) {
		void *priv = rdi->driver_f.mr_priv_alloc(rdi, &mr->mr);

		if (IS_ERR(priv)) {
			ret = ERR_PTR(PTR_ERR(priv));
			goto bail_mregion;
		}
		mr->mr.driver_priv = priv;
	}

	rval = rvt_alloc_lkey(&mr->mr, 1);
	if (rval) {
		ret = ERR_PTR(rval);
		goto bail_priv;
	}

	mr->mr.access_flags = acc;
	ret = &mr->ibmr;

	atomic_set(&mr->mr.lkey_invalid, 0);
done:
	return ret;

bail_priv:
	if (rdi->driver_f.mr_priv_free)
		rdi->driver_f.mr_priv_free(rdi, &mr->mr);
bail_mregion:
	rvt_deinit_mregion(&mr->mr);
bail:
	kfree(mr);
	goto done;
}

/**
 * rvt_reg_user_mr - register a userspace memory region
 * @pd: protection domain for this memory region
 * @start: starting userspace address
 * @length: length of region to register
 * @virt_addr: associated virtual address
 * @mr_access_flags: access flags for this memory region
 * @dmah: dma handle
 * @udata: unused by the driver
 *
 * Return: the memory region on success, otherwise returns an errno.
 */
/* Shared user-MR register path; umem lifetime owned by caller (released on error). */
static struct ib_mr *_reg_user_mr(struct rvt_dev_info *rdi,
				  struct ib_pd *pd, u64 start,
				  u64 length, u64 virt_addr,
				  struct ib_umem *umem,
				  struct iosys_map *vmap,
				  int mr_access_flags)
{
	struct dma_buf *dmabuf = NULL;
	enum rvt_mem_type mem_type;
	struct ib_block_iter biter;
	struct rvt_mr *mr;
	struct ib_mr *ret;
	u64 offset;
	int m, n;

	if (!umem->iova) {
		/*
		 * A bug in ib_uverbs:
		 *  dmabuf umems don't set iova and things like
		 *  ib_umem_num_pages and rdma_umem_for_each_dma_block
		 *  uses it to determine number of pages.
		 */
		umem->iova = umem->address;
	}
	n = ib_umem_num_pages(umem);

	mr = __rvt_alloc_mr(n, pd, false);
	if (IS_ERR(mr))
		return ERR_CAST(mr);

	mr->mr.user_base = start;
	mr->mr.iova = virt_addr;
	mr->mr.length = length;
	mr->mr.offset = ib_umem_offset(umem);
	mr->mr.access_flags = mr_access_flags;
	if (umem->is_dmabuf && vmap && iosys_map_is_set(vmap)) {
		mem_type = RVT_MEM_DMABUF;
		dmabuf = to_ib_umem_dmabuf(umem)->attach->dmabuf;
		mr->mr.vmap = *vmap;
	} else if (umem->is_dmabuf) {
		mem_type = RVT_MEM_DMABUF_DO;
		dmabuf = to_ib_umem_dmabuf(umem)->attach->dmabuf;
		iosys_map_clear(&mr->mr.vmap);
	} else {
		mem_type = RVT_MEM_KERNEL;
	}

	mr->umem = umem;
	mr->mr.page_shift = PAGE_SHIFT;
	m = 0;
	n = 0;
	offset = 0;

	rdma_umem_for_each_dma_block(umem, &biter, PAGE_SIZE) {
		dma_addr_t daddr = rdma_block_iter_dma_address(&biter);
		void *vaddr;

		switch (mem_type) {
		case RVT_MEM_DMABUF:
			/*
			 * vmap spans the whole dmabuf, umem->address contains
			 * offset into where MR starts
			 */
			vaddr = vmap->vaddr + ALIGN_DOWN(umem->address, PAGE_SIZE) + offset;
			mr->mr.map[m]->segs[n].seg_dmabuf.dmabuf = dmabuf;
			mr->mr.map[m]->segs[n].seg_dmabuf.dma_addr = daddr;
			trace_hfi2_rvt_map_dmabuf(&mr->mr, m, n, vaddr, daddr);
			break;
		case RVT_MEM_DMABUF_DO:
			/* vaddr will hold umem MR offset only */
			vaddr = (void *)offset;
			mr->mr.map[m]->segs[n].seg_dmabuf_do.dmabuf = dmabuf;
			mr->mr.map[m]->segs[n].seg_dmabuf_do.dma_addr = daddr;
			/* anything else will be handled in driver callback */
			break;
		case RVT_MEM_KERNEL:
		default:
			vaddr = ib_virt_dma_to_ptr(daddr);
			break;
		}

		mr->mr.map[m]->segs[n].type = mem_type;
		mr->mr.map[m]->segs[n].vaddr = vaddr;
		mr->mr.map[m]->segs[n].length = PAGE_SIZE;
		trace_hfi2_rvt_mr_user_seg(&mr->mr, m, n, vaddr, PAGE_SIZE);
		if (++n == RVT_SEGSZ) {
			m++;
			n = 0;
		}
		offset += PAGE_SIZE;
	}

	/*
	 * Page-set is now fully established in mr->map[].  Give the
	 * driver a chance to pin / DMA-map the pages in sleepable
	 * context, before the MR is advertised via notify_register_mr.
	 */
	if (rdi->driver_f.notify_mr_pages_set) {
		int rc = rdi->driver_f.notify_mr_pages_set(rdi, &mr->mr);

		if (rc) {
			ret = ERR_PTR(rc);
			goto bail_inval;
		}
	}

	/* tell driver about new mr and key */
	if (rdi->driver_f.notify_register_mr) {
		if (rdi->driver_f.notify_register_mr(rdi, &mr->mr)) {
			ret = ERR_PTR(-EINVAL);
			goto bail_inval;
		}
	}

	atomic_set(&mr->mr.lkey_invalid, 0);
	return &mr->ibmr;

bail_inval:
	rvt_free_lkey(&mr->mr);
	rvt_put_mr(&mr->mr); /* will set completion if last */
	/* References still held after the timeout: leak the MR, as dereg does. */
	if (rvt_check_refs(&mr->mr, __func__))
		return ret;
	if (rdi->driver_f.mr_priv_free)
		rdi->driver_f.mr_priv_free(rdi, &mr->mr);
	call_rcu(&mr->rcu, rvt_mr_free_rcu);
	return ret;
}

/**
 * rvt_reg_user_mr - register a userspace memory region
 * @pd: protection domain for this memory region
 * @start: starting userspace address
 * @length: length of region to register
 * @virt_addr: associated virtual address
 * @mr_access_flags: access flags for this memory region
 * @udata: unused by the driver
 *
 * Return: the memory region on success, otherwise returns an errno.
 */
struct ib_mr *rvt_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
			      u64 virt_addr, int mr_access_flags,
			      struct ib_dmah *dmah,
			      struct ib_udata *udata)
{
	struct rvt_dev_info *rdi = ib_to_rvt(pd->device);
	struct ib_umem *umem;
	struct ib_mr *ret;

	if (dmah)
		return ERR_PTR(-EOPNOTSUPP);

	if (length == 0)
		return ERR_PTR(-EINVAL);

	if (length > rdi->dparms.props.max_mr_size)
		return ERR_PTR(-EINVAL);

	umem = ib_umem_get_va(pd->device, start, length, mr_access_flags);
	if (IS_ERR(umem))
		return ERR_CAST(umem);

	ret = _reg_user_mr(rdi, pd, start, length, virt_addr, umem,
			   NULL, mr_access_flags);
	if (IS_ERR(ret))
		ib_umem_release(umem);

	return ret;
}

/**
 * rvt_reg_user_mr_dmabuf - register a userspace dmabuf memory region
 * @pd: protection domain for this memory region
 * @offset: offset into the dmabuf where the region starts
 * @length: length of region to register
 * @virt_addr: associated virtual address
 * @fd: the dmabuf file descriptor
 * @mr_access_flags: access flags for this memory region
 * @attrs: uverbs attribute bundle
 *
 * Since the underlying drivers expect MR memory to be kernel-addressable,
 * vmap the dmabuf and mark the segments RVT_MEM_DMABUF so the verbs layer
 * fences CPU access with dma_buf_[begin,end]_cpu_access.
 *
 * Return: the memory region on success, otherwise returns an errno.
 */
struct ib_mr *rvt_reg_user_mr_dmabuf(struct ib_pd *pd, u64 offset,
				     u64 length, u64 virt_addr,
				     int fd, int mr_access_flags,
				     struct ib_dmah *dmah,
				     struct uverbs_attr_bundle *attrs)
{
	struct rvt_dev_info *rdi = ib_to_rvt(pd->device);
	struct ib_umem_dmabuf *umem_dmabuf;
	struct ib_mr *ret;
	struct iosys_map vmap;

	if (dmah)
		return ERR_PTR(-EOPNOTSUPP);

	if (WARN_ON_ONCE(!rdi->pdev))
		return ERR_PTR(-EINVAL);

	if (fd < 0)
		return ERR_PTR(-EBADF);

	if (length > rdi->dparms.props.max_mr_size || length == 0)
		return ERR_PTR(-EINVAL);

	umem_dmabuf = ib_umem_dmabuf_get_pinned_with_dma_device(pd->device,
								&rdi->pdev->dev,
								offset, length,
								fd, mr_access_flags);
	if (IS_ERR(umem_dmabuf)) {
		rvt_pr_warn(rdi, "Failed (%ld) to pin dmabuf for fd %d\n",
			    PTR_ERR(umem_dmabuf), fd);
		return ERR_CAST(umem_dmabuf);
	}

	if (!umem_dmabuf->attach->dmabuf->ops->vmap) {
		/*
		 * this will be device-accessible only (RVT_MEM_DMABUF_DO),
		 * low-level driver must export functions for interacting
		 */
		if (!rdi->driver_f.dmabuf_memcpy) {
			rvt_pr_warn(rdi, "Unsupported dmabuf MR type, fd %d\n",
				    fd);
			ib_umem_release(&umem_dmabuf->umem);
			return ERR_PTR(-EOPNOTSUPP);
		}
		/* signal to _reg_user_mr that this RVT_MEM_DMABUF_DO */
		iosys_map_clear(&vmap);
	} else {
		ret = ERR_PTR(dma_buf_vmap_unlocked(umem_dmabuf->attach->dmabuf, &vmap));
		if (IS_ERR(ret)) {
			rvt_pr_warn(rdi, "Failed to vmap dmabuf %ld\n", PTR_ERR(ret));
			ib_umem_release(&umem_dmabuf->umem);
			return ret;
		}
		/*
		 * A vmap backed by iomem (e.g. GPU VRAM under peer2peer) is
		 * not safe for a linear vaddr + offset memcpy: the device
		 * memory may be several non-contiguous physical chunks. Drop
		 * the vmap and treat it as device-only (RVT_MEM_DMABUF_DO) so
		 * the low-level driver services copies per-page instead.
		 */
		if (vmap.is_iomem) {
			dma_buf_vunmap_unlocked(umem_dmabuf->attach->dmabuf,
						&vmap);
			iosys_map_clear(&vmap);
			if (!rdi->driver_f.dmabuf_memcpy) {
				rvt_pr_warn(rdi,
					    "Unsupported iomem dmabuf MR type, fd %d\n",
					    fd);
				ib_umem_release(&umem_dmabuf->umem);
				return ERR_PTR(-EOPNOTSUPP);
			}
		}
	}

	ret = _reg_user_mr(rdi, pd, virt_addr, length, virt_addr,
			   &umem_dmabuf->umem, &vmap, mr_access_flags);
	if (IS_ERR(ret)) {
		if (iosys_map_is_set(&vmap))
			dma_buf_vunmap_unlocked(umem_dmabuf->attach->dmabuf, &vmap);
		ib_umem_release(&umem_dmabuf->umem);
	} else {
		umem_dmabuf->private = container_of(ret, struct rvt_mr, ibmr);
	}

	return ret;
}

/**
 * rvt_dereg_clean_qp_cb - callback from iterator
 * @qp: the qp
 * @v: the mregion (as u64)
 *
 * This routine fields the callback for all QPs and
 * for QPs in the same PD as the MR will call the
 * rvt_qp_mr_clean() to potentially cleanup references.
 */
static void rvt_dereg_clean_qp_cb(struct rvt_qp *qp, u64 v)
{
	struct rvt_mregion *mr = (struct rvt_mregion *)v;

	/* skip PDs that are not ours */
	if (mr->pd != qp->ibqp.pd)
		return;
	rvt_qp_mr_clean(qp, mr->lkey);
}

/**
 * rvt_dereg_clean_qps - find QPs for reference cleanup
 * @mr: the MR that is being deregistered
 *
 * This routine iterates RC QPs looking for references
 * to the lkey noted in mr.
 */
static void rvt_dereg_clean_qps(struct rvt_mregion *mr)
{
	struct rvt_dev_info *rdi = ib_to_rvt(mr->pd->device);

	rvt_qp_iter(rdi, (u64)mr, rvt_dereg_clean_qp_cb);
}

static int rvt_wait_for_refs(struct rvt_mregion *mr,
			     struct rvt_dev_info *rdi, const char *t)
{
	unsigned long timeout;

	timeout = wait_for_completion_timeout(&mr->comp, 5 * HZ);
	if (timeout)
		return 0;

	rvt_pr_err(rdi, "%s timeout mr %p lkey %x refcount %u\n",
		   t, mr, mr->lkey, rvt_mr_refs(mr));
	return -EBUSY;
}

/**
 * rvt_check_refs - check references
 * @mr: the megion
 * @t: the caller identification
 *
 * This routine checks MRs holding a reference during
 * when being de-registered.
 *
 * If the count is non-zero, the code calls a clean routine then
 * waits for the timeout for the count to zero.
 */
static int rvt_check_refs(struct rvt_mregion *mr, const char *t)
{
	unsigned long timeout;
	struct rvt_dev_info *rdi = ib_to_rvt(mr->pd->device);

	if (mr->lkey) {
		/* avoid dma mr */
		rvt_dereg_clean_qps(mr);
		/* rvt_tryget_mr() fails once killed; caller frees via call_rcu(). */
	}

	timeout = wait_for_completion_timeout(&mr->comp, 5 * HZ);
	if (!timeout) {
		rvt_pr_err(rdi,
			   "%s timeout mr %p pd %p lkey %x refcount %u\n",
			   t, mr, mr->pd, mr->lkey,
			   rvt_mr_refs(mr));
		rvt_get_mr(mr);
		return -EBUSY;
	}
	return 0;
}

/**
 * rvt_mr_has_lkey - is MR
 * @mr: the mregion
 * @lkey: the lkey
 */
bool rvt_mr_has_lkey(struct rvt_mregion *mr, u32 lkey)
{
	return mr && lkey == mr->lkey;
}

/**
 * rvt_ss_has_lkey - is mr in sge tests
 * @ss: the sge state
 * @lkey: the lkey
 *
 * This code tests for an MR in the indicated
 * sge state.
 */
bool rvt_ss_has_lkey(struct rvt_sge_state *ss, u32 lkey)
{
	int i;
	bool rval = false;

	if (!ss->num_sge)
		return rval;
	/* first one */
	rval = rvt_mr_has_lkey(ss->sge.mr, lkey);
	/* any others */
	for (i = 0; !rval && i < ss->num_sge - 1; i++)
		rval = rvt_mr_has_lkey(ss->sg_list[i].mr, lkey);
	return rval;
}

static void rvt_dereg_mr_work(struct work_struct *work)
{
	struct rcu_work *rwork = to_rcu_work(work);
	struct rvt_mr *mr = container_of(rwork, struct rvt_mr, dereg_work);
	struct rvt_dev_info *rdi = mr->rdi;

	if (rvt_wait_for_refs(&mr->mr, rdi, __func__)) {
		rvt_get_mr(&mr->mr);
		return;
	}

	if (rdi->driver_f.mr_priv_free)
		rdi->driver_f.mr_priv_free(rdi, &mr->mr);
	/* A put that lost the completion race may still read the counters. */
	call_rcu(&mr->rcu, rvt_mr_free_rcu);
}

/**
 * rvt_dereg_mr - unregister and free a memory region
 * @ibmr: the memory region to free
 * @udata: unused by the driver
 *
 * Note that this is called to free MRs created by rvt_get_dma_mr()
 * or rvt_reg_user_mr().
 *
 * Returns 0 on success.
 */
int rvt_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct rvt_mr *mr = to_imr(ibmr);
	struct rvt_dev_info *rdi;
	int ret;

	rdi = ib_to_rvt(mr->mr.pd->device);

	/* unregister with driver if previously registered */
	if (!mr->mr.driver_internal && mr->mr.lkey != 0 && mr->mr.user_base &&
	    (!atomic_read(&mr->mr.lkey_invalid) || rdi->driver_f.fast_reg_mr) &&
	    rdi->driver_f.notify_unregister_mr)
		rdi->driver_f.notify_unregister_mr(rdi, &mr->mr);

	rvt_free_lkey(&mr->mr);

	rvt_put_mr(&mr->mr); /* will set completion if last */
	if (!mr->mr.driver_internal && !mr->umem &&
	    rdi->dparms.async_kernel_mr_dereg) {
		if (mr->mr.lkey)
			rvt_dereg_clean_qps(&mr->mr);
		/*
		 * Drain after a grace period, so that lookups which use the MR
		 * without a reference have left the read-side section.
		 */
		INIT_RCU_WORK(&mr->dereg_work, rvt_dereg_mr_work);
		queue_rcu_work(rdi->mr_dereg_wq, &mr->dereg_work);
		return 0;
	}

	ret = rvt_check_refs(&mr->mr, __func__);
	if (ret)
		return ret;

	if (!mr->mr.driver_internal && rdi->driver_f.mr_priv_free)
		rdi->driver_f.mr_priv_free(rdi, &mr->mr);

	/*  only RVT_MEM_DMABUF MR's will not have vmap */
	if (mr->umem && mr->umem->is_dmabuf && iosys_map_is_set(&mr->mr.vmap))
		dma_buf_vunmap_unlocked(to_ib_umem_dmabuf(mr->umem)->attach->dmabuf,
					&mr->mr.vmap);
	ib_umem_release(mr->umem);
	call_rcu(&mr->rcu, rvt_mr_free_rcu);
	return 0;
}

/**
 * rvt_alloc_mr - Allocate a memory region usable with the
 * @pd: protection domain for this memory region
 * @mr_type: mem region type
 * @max_num_sg: Max number of segments allowed
 *
 * Return: the memory region on success, otherwise return an errno.
 */
struct ib_mr *rvt_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			   u32 max_num_sg)
{
	struct rvt_mr *mr;

	if (mr_type != IB_MR_TYPE_MEM_REG)
		return ERR_PTR(-EINVAL);

	mr = __rvt_alloc_mr(max_num_sg, pd, false);
	if (IS_ERR(mr))
		return ERR_CAST(mr);

	/* key is not valid until registered */
	atomic_set(&mr->mr.lkey_invalid, 1);

	return &mr->ibmr;
}

struct ib_mr *rvt_alloc_internal_mr(struct ib_pd *pd)
{
	struct rvt_mr *mr;

	mr = __rvt_alloc_mr(0, pd, true);
	if (IS_ERR(mr))
		return ERR_CAST(mr);

	/* Reserve a private key slot without admitting normal verbs accesses. */
	mr->mr.internal_generation = 0;
	atomic_set(&mr->mr.lkey_invalid, 0);
	return &mr->ibmr;
}

void rvt_unpublish_internal_mr(struct ib_mr *ibmr)
{
	struct rvt_mr *mr;

	if (!ibmr)
		return;
	mr = to_imr(ibmr);
	if (WARN_ON_ONCE(!mr->mr.driver_internal))
		return;
	rvt_free_lkey(&mr->mr);
}

void rvt_free_internal_mr(struct ib_mr *ibmr)
{
	struct rvt_mr *mr;

	if (!ibmr)
		return;
	mr = to_imr(ibmr);
	if (WARN_ON_ONCE(!mr->mr.driver_internal))
		return;
	/* Internal keys cannot enter an SGE; only lookup references can remain. */
	rvt_free_lkey(&mr->mr);
	rvt_put_mr(&mr->mr);
	wait_for_completion(&mr->mr.comp);
	/* A put that lost the completion race may still read the counters. */
	call_rcu(&mr->rcu, rvt_mr_free_rcu);
}

int rvt_rotate_internal_mr_key(struct ib_mr *ibmr, u32 *key,
			       enum rvt_internal_mr_key_policy policy)
{
	struct rvt_mr *mr = to_imr(ibmr);
	struct rvt_lkey_table *rkt;
	unsigned long flags;
	u32 generation_mask;
	u32 next;

	if (!key || !mr->mr.driver_internal || !mr->mr.lkey || mr->umem)
		return -EINVAL;
	if (policy != RVT_INTERNAL_MR_KEY_NO_WRAP &&
	    policy != RVT_INTERNAL_MR_KEY_WRAP_AFTER_DRAIN)
		return -EINVAL;
	rkt = &mr->rdi->lkey_table;
	generation_mask = (1U << rkt->shift) - 1;
	spin_lock_irqsave(&rkt->lock, flags);
	next = mr->mr.internal_generation + 1;
	if (next > generation_mask) {
		if (policy == RVT_INTERNAL_MR_KEY_NO_WRAP) {
			spin_unlock_irqrestore(&rkt->lock, flags);
			return -EOVERFLOW;
		}
		next = 1;
	}
	mr->mr.internal_generation = next;
	*key = (mr->mr.lkey & ~generation_mask) | next;
	spin_unlock_irqrestore(&rkt->lock, flags);
	return 0;
}

/**
 * rvt_set_page - page assignment function called by ib_sg_to_pages
 * @ibmr: memory region
 * @addr: dma address of mapped page
 *
 * Return: 0 on success
 */
static int rvt_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct rvt_mr *mr = to_imr(ibmr);
	u32 ps = 1 << mr->mr.page_shift;
	u32 mapped_segs = mr->mr.length >> mr->mr.page_shift;
	int m, n;

	if (unlikely(mapped_segs == mr->mr.max_segs))
		return -ENOMEM;

	m = mapped_segs / RVT_SEGSZ;
	n = mapped_segs % RVT_SEGSZ;
	mr->mr.map[m]->segs[n].type = RVT_MEM_KERNEL;
	mr->mr.map[m]->segs[n].vaddr = (void *)addr;
	mr->mr.map[m]->segs[n].length = ps;
	mr->mr.length += ps;
	trace_hfi2_rvt_mr_page_seg(&mr->mr, m, n, (void *)addr, ps);

	return 0;
}

/**
 * rvt_map_mr_sg - map sg list and set it the memory region
 * @ibmr: memory region
 * @sg: dma mapped scatterlist
 * @sg_nents: number of entries in sg
 * @sg_offset: offset in bytes into sg
 *
 * Overwrite rvt_mr length with mr length calculated by ib_sg_to_pages.
 *
 * Return: number of sg elements mapped to the memory region
 */
int rvt_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
		  int sg_nents, unsigned int *sg_offset)
{
	struct rvt_mr *mr = to_imr(ibmr);
	struct rvt_dev_info *rdi = ib_to_rvt(ibmr->device);
	int ret;

	mr->mr.length = 0;
	mr->mr.page_shift = PAGE_SHIFT;
	ret = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, rvt_set_page);
	if (ret < 0)
		return ret;
	mr->mr.user_base = ibmr->iova;
	mr->mr.iova = ibmr->iova;
	mr->mr.offset = ibmr->iova - (u64)mr->mr.map[0]->segs[0].vaddr;
	mr->mr.length = (size_t)ibmr->length;
	trace_hfi2_rvt_map_mr_sg(ibmr, sg_nents, sg_offset);

	/* FastReg callers may be atomic; defer sleepable page mapping. */
	if (ret >= 0 && rdi->driver_f.notify_mr_pages_set) {
		int rc = rdi->driver_f.notify_mr_pages_set(rdi, &mr->mr);

		if (rc) {
			/* Unwind the FastReg mapping state on hook failure. */
			mr->mr.length = 0;
			mr->mr.iova = 0;
			mr->mr.user_base = 0;
			mr->mr.offset = 0;
			return rc;
		}
	}

	return ret;
}

/* reg_flags reports ordered driver work independently of the 0/-errno result. */
int rvt_fast_reg_mr(struct rvt_qp *qp, struct ib_mr *ibmr, u32 key,
		    int access, unsigned int *reg_flags)
{
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct rvt_mr *mr = to_imr(ibmr);
	int ret;

	if (reg_flags)
		*reg_flags = 0;
	if (qp->ibqp.pd != mr->mr.pd)
		return -EACCES;

	/* not applicable to dma MR or user MR */
	if (!mr->mr.lkey || mr->umem)
		return -EINVAL;

	if ((key & 0xFFFFFF00) != (mr->mr.lkey & 0xFFFFFF00))
		return -EINVAL;

	ibmr->lkey = key;
	ibmr->rkey = key;
	mr->mr.lkey = key;
	mr->mr.access_flags = access;
	mr->mr.iova = ibmr->iova;
	atomic_set(&mr->mr.lkey_invalid, 0);
	if (!rdi->driver_f.fast_reg_mr) {
		/* Legacy FastReg deliberately ignores the notification result. */
		if (rdi->driver_f.notify_register_mr)
			rdi->driver_f.notify_register_mr(rdi, &mr->mr);
		return 0;
	}
	if (WARN_ON_ONCE(!reg_flags)) {
		ret = -EINVAL;
		goto invalidate;
	}
	ret = rdi->driver_f.fast_reg_mr(rdi, &mr->mr, reg_flags);
	if (WARN_ON_ONCE(ret > 0))
		ret = -EINVAL;
	if (WARN_ON_ONCE((*reg_flags & ~RVT_SEND_REG_MR_DEFERRED) ||
			 (ret && *reg_flags)))
		ret = -EINVAL;
	if (!ret && (*reg_flags & RVT_SEND_REG_MR_DEFERRED) &&
	    WARN_ON_ONCE(!rdi->driver_f.setup_wqe ||
			 !rdi->driver_f.cleanup_reg_mr))
		ret = -EINVAL;
	if (!ret)
		return 0;

invalidate:
	if (reg_flags)
		*reg_flags = 0;
	atomic_set(&mr->mr.lkey_invalid, 1);
	/* Revoke partial hardware publication as well as the software key. */
	if (rdi->driver_f.notify_unregister_mr)
		rdi->driver_f.notify_unregister_mr(rdi, &mr->mr);
	return ret;
}

/**
 * rvt_invalidate_rkey - invalidate an MR rkey
 * @qp: queue pair associated with the invalidate op
 * @rkey: rkey to invalidate
 *
 * Returns 0 on success.
 */
int rvt_invalidate_rkey(struct rvt_qp *qp, u32 rkey)
{
	struct rvt_dev_info *dev = ib_to_rvt(qp->ibqp.device);
	struct rvt_lkey_table *rkt = &dev->lkey_table;
	struct rvt_mregion *mr;

	if (rkey == 0)
		return -EINVAL;

	rcu_read_lock();
	mr = rcu_dereference(
		rkt->table[(rkey >> (32 - dev->dparms.lkey_table_size))]);
	/*
	 * notify_unregister_mr() takes its own reference on @mr, so @mr must
	 * not already be on its way out of rvt_dereg_mr().
	 */
	if (unlikely(!rvt_tryget_mr(mr)))
		goto bail;
	if (unlikely(mr->driver_internal || mr->lkey != rkey ||
		     qp->ibqp.pd != mr->pd))
		goto bail_put;

	if ((!atomic_read(&mr->lkey_invalid) || dev->driver_f.fast_reg_mr) &&
	    dev->driver_f.notify_unregister_mr)
		dev->driver_f.notify_unregister_mr(dev, mr);

	atomic_set(&mr->lkey_invalid, 1);
	rvt_put_mr(mr);
	rcu_read_unlock();
	return 0;

bail_put:
	rvt_put_mr(mr);
bail:
	rcu_read_unlock();
	return -EINVAL;
}

/**
 * rvt_sge_adjacent - is isge compressible
 * @last_sge: last outgoing SGE written
 * @sge: SGE to check
 *
 * If adjacent will update last_sge to add length.
 *
 * Return: true if isge is adjacent to last sge
 */
static inline bool rvt_sge_adjacent(struct rvt_sge *last_sge,
				    struct ib_sge *sge)
{
	if (last_sge && sge->lkey == last_sge->mr->lkey &&
	    ((uint64_t)(last_sge->mem.vaddr + last_sge->mem.length) == sge->addr)) {
		if (sge->lkey) {
			if (unlikely((sge->addr - last_sge->mr->user_base +
			      sge->length > last_sge->mr->length)))
				return false; /* overrun, caller will catch */
		} else {
			last_sge->mem.length += sge->length;
		}
		last_sge->sge_length += sge->length;
		trace_hfi2_rvt_sge_adjacent(last_sge, sge);
		return true;
	}
	return false;
}

/**
 * rvt_lkey_ok - check IB SGE for validity and initialize
 * @rkt: table containing lkey to check SGE against
 * @pd: protection domain
 * @isge: outgoing internal SGE
 * @last_sge: last outgoing SGE written
 * @sge: SGE to check
 * @acc: access flags
 *
 * Check the IB SGE for validity and initialize our internal version
 * of it.
 *
 * Increments the reference count when a new sge is stored.
 *
 * Return: 0 if compressed, 1 if added , otherwise returns -errno.
 */
int rvt_lkey_ok(struct rvt_lkey_table *rkt, struct rvt_pd *pd,
		struct rvt_sge *isge, struct rvt_sge *last_sge,
		struct ib_sge *sge, int acc)
{
	struct rvt_mregion *mr;
	struct rvt_seg *mr_seg;
	unsigned int n, m;
	size_t off;

	/*
	 * We use LKEY == zero for kernel virtual addresses
	 * (see rvt_get_dma_mr()).
	 */
	if (sge->lkey == 0) {
		struct rvt_dev_info *dev = ib_to_rvt(pd->ibpd.device);

		if (pd->user)
			return -EINVAL;
		if (rvt_sge_adjacent(last_sge, sge))
			return 0;
		rcu_read_lock();
		mr = rcu_dereference(dev->dma_mr);
		if (!rvt_tryget_mr(mr))
			goto bail;
		rcu_read_unlock();

		isge->mr = mr;
		isge->mem.type = RVT_MEM_KERNEL;
		isge->mem.vaddr = (void *)sge->addr;
		isge->mem.length = sge->length;
		isge->sge_length = sge->length;
		isge->m = 0;
		isge->n = 0;
		goto ok;
	}
	if (rvt_sge_adjacent(last_sge, sge))
		return 0;
	rcu_read_lock();
	mr = rcu_dereference(rkt->table[sge->lkey >> rkt->shift]);
	if (!rvt_tryget_mr(mr))
		goto bail;
	if (!READ_ONCE(mr->lkey_published))
		goto bail_unref;

	if (unlikely(mr->driver_internal || atomic_read(&mr->lkey_invalid) ||
		     mr->lkey != sge->lkey || mr->pd != &pd->ibpd))
		goto bail_unref;

	off = sge->addr - mr->user_base;
	if (unlikely(sge->addr < mr->user_base ||
		     off > mr->length || sge->length > mr->length - off ||
		     (mr->access_flags & acc) != acc))
		goto bail_unref;
	rcu_read_unlock();

	off += mr->offset;
	if (mr->page_shift) {
		/*
		 * page sizes are uniform power of 2 so no loop is necessary
		 * entries_spanned_by_off is the number of times the loop below
		 * would have executed.
		 */
		size_t entries_spanned_by_off;

		entries_spanned_by_off = off >> mr->page_shift;
		off -= (entries_spanned_by_off << mr->page_shift);
		m = entries_spanned_by_off / RVT_SEGSZ;
		n = entries_spanned_by_off % RVT_SEGSZ;
	} else {
		m = 0;
		n = 0;
		while (off >= mr->map[m]->segs[n].length) {
			off -= mr->map[m]->segs[n].length;
			n++;
			if (n >= RVT_SEGSZ) {
				m++;
				n = 0;
			}
		}
	}
	isge->mr = mr;
	mr_seg = &mr->map[m]->segs[n];
	isge->mem.type = mr_seg->type;
	if (mr_seg->type == RVT_MEM_DMABUF) {
		isge->mem.seg_dmabuf.dmabuf = mr_seg->seg_dmabuf.dmabuf;
		isge->mem.seg_dmabuf.dma_addr =
			mr_seg->seg_dmabuf.dma_addr + off;
	} else if (mr_seg->type == RVT_MEM_DMABUF_DO) {
		isge->mem.seg_dmabuf_do.dmabuf = mr_seg->seg_dmabuf_do.dmabuf;
		isge->mem.seg_dmabuf_do.dma_addr =
			mr_seg->seg_dmabuf_do.dma_addr + off;
		isge->mem.seg_dmabuf_do.priv = mr_seg->seg_dmabuf_do.priv;
	}
	isge->mem.vaddr = mr_seg->vaddr + off;
	isge->mem.length = mr_seg->length - off;
	isge->sge_length = sge->length;
	isge->m = m;
	isge->n = n;
ok:
	trace_hfi2_rvt_sge_new(isge, sge);
	return 1;
bail_unref:
	rvt_put_mr(mr);
bail:
	rcu_read_unlock();
	return -EINVAL;
}

/**
 * rvt_rkey_ok - check the IB virtual address, length, and RKEY
 * @qp: qp for validation
 * @sge: SGE state
 * @len: length of data
 * @vaddr: virtual address to place data
 * @rkey: rkey to check
 * @acc: access flags
 *
 * Return: 1 if successful, otherwise 0.
 *
 * increments the reference count upon success
 */
int rvt_rkey_ok(struct rvt_qp *qp, struct rvt_sge *sge,
		u32 len, u64 vaddr, u32 rkey, int acc)
{
	struct rvt_dev_info *dev = ib_to_rvt(qp->ibqp.device);
	struct rvt_lkey_table *rkt = &dev->lkey_table;
	struct rvt_mregion *mr;
	struct rvt_seg *mr_seg;
	unsigned int n, m;
	size_t off;

	/*
	 * We use RKEY == zero for kernel virtual addresses
	 * (see rvt_get_dma_mr()).
	 */
	rcu_read_lock();
	if (rkey == 0) {
		struct rvt_pd *pd = ibpd_to_rvtpd(qp->ibqp.pd);
		struct rvt_dev_info *rdi = ib_to_rvt(pd->ibpd.device);

		if (pd->user)
			goto bail;
		mr = rcu_dereference(rdi->dma_mr);
		if (!rvt_tryget_mr(mr))
			goto bail;
		rcu_read_unlock();

		sge->mr = mr;
		sge->mem.type = RVT_MEM_KERNEL;
		sge->mem.vaddr = (void *)vaddr;
		sge->mem.length = len;
		sge->sge_length = len;
		sge->m = 0;
		sge->n = 0;
		goto ok;
	}

	mr = rcu_dereference(rkt->table[rkey >> rkt->shift]);
	if (!rvt_tryget_mr(mr))
		goto bail;
	/* insure mr read is before test */
	if (!READ_ONCE(mr->lkey_published))
		goto bail_unref;
	if (unlikely(mr->driver_internal || atomic_read(&mr->lkey_invalid) ||
		     mr->lkey != rkey || qp->ibqp.pd != mr->pd))
		goto bail_unref;

	off = vaddr - mr->iova;
	if (unlikely(!len || vaddr < mr->iova || off > mr->length ||
		     len > mr->length - off ||
		     (mr->access_flags & acc) == 0))
		goto bail_unref;

	/* atomic access to only device-accessible memory is not supported */
	if (unlikely(acc & IB_ACCESS_REMOTE_ATOMIC &&
		     mr->map[0]->segs[0].type == RVT_MEM_DMABUF_DO)) {
		rvt_pr_warn(ib_to_rvt(mr->pd->device),
			    "Cannot atomically access device only mem QP %u\n",
			    qp->ibqp.qp_num);
		goto bail_unref;
	}
	rcu_read_unlock();

	off += mr->offset;
	if (mr->page_shift) {
		/*
		 * page sizes are uniform power of 2 so no loop is necessary
		 * entries_spanned_by_off is the number of times the loop below
		 * would have executed.
		 */
		size_t entries_spanned_by_off;

		entries_spanned_by_off = off >> mr->page_shift;
		off -= (entries_spanned_by_off << mr->page_shift);
		m = entries_spanned_by_off / RVT_SEGSZ;
		n = entries_spanned_by_off % RVT_SEGSZ;
	} else {
		m = 0;
		n = 0;
		while (off >= mr->map[m]->segs[n].length) {
			off -= mr->map[m]->segs[n].length;
			n++;
			if (n >= RVT_SEGSZ) {
				m++;
				n = 0;
			}
		}
	}
	sge->mr = mr;
	mr_seg = &mr->map[m]->segs[n];
	sge->mem.type = mr_seg->type;
	if (mr_seg->type == RVT_MEM_DMABUF) {
		sge->mem.seg_dmabuf.dmabuf = mr_seg->seg_dmabuf.dmabuf;
		sge->mem.seg_dmabuf.dma_addr =
			mr_seg->seg_dmabuf.dma_addr + off;
	} else if (mr_seg->type == RVT_MEM_DMABUF_DO) {
		sge->mem.seg_dmabuf_do.dmabuf = mr_seg->seg_dmabuf_do.dmabuf;
		sge->mem.seg_dmabuf_do.dma_addr =
			mr_seg->seg_dmabuf_do.dma_addr + off;
		sge->mem.seg_dmabuf_do.priv = mr_seg->seg_dmabuf_do.priv;
	}
	sge->mem.vaddr = mr_seg->vaddr + off;
	sge->mem.length = mr_seg->length - off;
	sge->sge_length = len;
	sge->m = m;
	sge->n = n;
ok:
	return 1;
bail_unref:
	rvt_put_mr(mr);
bail:
	rcu_read_unlock();
	return 0;
}

void rvt_update_sge(struct rvt_sge_state *ss, u32 length, bool release)
{
	struct rvt_sge *sge = &ss->sge;

	sge->mem.vaddr += length;
	if (sge->mem.type == RVT_MEM_DMABUF)
		sge->mem.seg_dmabuf.dma_addr += length;
	else if (sge->mem.type == RVT_MEM_DMABUF_DO)
		sge->mem.seg_dmabuf_do.dma_addr += length;

	sge->mem.length -= length;
	sge->sge_length -= length;
	if (sge->sge_length == 0) {
		if (release)
			rvt_put_mr(sge->mr);
		if (--ss->num_sge)
			*sge = *ss->sg_list++;
	} else if (sge->mem.length == 0 && sge->mr->lkey) {
		if (unlikely(++sge->n >= RVT_SEGSZ)) {
			if (++sge->m >= sge->mr->mapsz)
				return;
			sge->n = 0;
		}
		sge->mem = sge->mr->map[sge->m]->segs[sge->n];
	}
}
