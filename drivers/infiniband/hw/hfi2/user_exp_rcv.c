// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 * Copyright(c) 2015-2018 Intel Corporation.
 */
#include <asm/page.h>
#include <linux/string.h>

#include "mmu_rb.h"
#include "user_exp_rcv.h"
#include "trace.h"

static void cacheless_tid_rb_remove(struct hfi2_filedata *fdata,
				    struct tid_rb_node *tnode);
static int program_rcvarray(struct hfi2_filedata *fd,
			    struct tid_user_buf *tbuf,
			    u32 grp_idx, u8 alloc_mask,
			    u32 *tidlist, unsigned int *tididx,
			    struct hfi2_page_iter *iter,
			    unsigned int *pmapped);
static int unprogram_rcvarray(struct hfi2_filedata *fd, u32 tidinfo);
static void __clear_tid_node(struct hfi2_filedata *fd,
			     struct tid_rb_node *node);
static void clear_tid_node(struct hfi2_filedata *fd, struct tid_rb_node *node);

/*
 * Initialize context and file private data needed for Expected
 * receive caching. This needs to be done after the context has
 * been configured with the eager/expected RcvEntry counts.
 */
int hfi2_user_exp_rcv_init(struct hfi2_filedata *fd,
			   struct hfi2_ctxtdata *uctxt)
{
	int ret = 0;

	fd->entry_to_rb = kcalloc(uctxt->expected_count,
				  sizeof(*fd->entry_to_rb), GFP_KERNEL);
	if (!fd->entry_to_rb)
		return -ENOMEM;

	if (!HFI2_CAP_UGET_MASK(uctxt->flags, TID_UNMAP)) {
		fd->invalid_tid_idx = 0;
		fd->invalid_tids = kcalloc(uctxt->expected_count,
					   sizeof(*fd->invalid_tids),
					   GFP_KERNEL);
		if (!fd->invalid_tids) {
			kfree(fd->entry_to_rb);
			fd->entry_to_rb = NULL;
			return -ENOMEM;
		}
		fd->use_mn = true;
	}

	/*
	 * PSM does not have a good way to separate, count, and
	 * effectively enforce a limit on RcvArray entries used by
	 * subctxts (when context sharing is used) when TID caching
	 * is enabled. To help with that, we calculate a per-process
	 * RcvArray entry share and enforce that.
	 * If TID caching is not in use, PSM deals with usage on its
	 * own. In that case, we allow any subctxt to take all of the
	 * entries.
	 *
	 * Make sure that we set the tid counts only after successful
	 * init.
	 */
	spin_lock(&fd->tid_lock);
	if (uctxt->subctxt_cnt && fd->use_mn) {
		u16 remainder;

		fd->tid_limit = uctxt->expected_count / uctxt->subctxt_cnt;
		remainder = uctxt->expected_count % uctxt->subctxt_cnt;
		if (remainder && fd->subctxt < remainder)
			fd->tid_limit++;
	} else {
		fd->tid_limit = uctxt->expected_count;
	}
	spin_unlock(&fd->tid_lock);

	return ret;
}

void hfi2_user_exp_rcv_free(struct hfi2_filedata *fd)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	u32 rcventry;

	mutex_lock(&uctxt->exp_mutex);
	if (fd->entry_to_rb) {
		for (rcventry = 0; rcventry < uctxt->expected_count;
		     rcventry++) {
			struct tid_rb_node *node =
				xchg(&fd->entry_to_rb[rcventry], NULL);

			if (!node || node->rcventry != rcventry)
				continue;

			node->ops->unregister_notify(node);
			clear_tid_node(fd, node);
		}
	}
	mutex_unlock(&uctxt->exp_mutex);

	kfree(fd->invalid_tids);
	fd->invalid_tids = NULL;

	kfree(fd->entry_to_rb);
	fd->entry_to_rb = NULL;
}

static struct tid_user_buf_ops *bufops[HFI2_MAX_MEMINFO_ENTRIES];
static struct tid_node_ops *nodeops[HFI2_MAX_MEMINFO_ENTRIES];

/*
 * Register TID memory-pinning implementation for @type memory.
 *
 * @type one of the HFI2_MEMINFO_TYPE* defines found in hfi2_ioctl.h
 * @op Buffer ops to register
 * @nops Node ops to register
 *
 * @return 0 on success, non-zero on error
 */
int hfi2_register_tid_ops(u16 type, struct tid_user_buf_ops *op,
			  struct tid_node_ops *nops)
{
	if (type >= HFI2_MAX_MEMINFO_ENTRIES)
		return -EINVAL;
	bufops[type] = op;
	nodeops[type] = nops;
	return 0;
}

void hfi2_deregister_tid_ops(u16 type)
{
	if (type >= HFI2_MAX_MEMINFO_ENTRIES)
		return;
	bufops[type] = NULL;
	nodeops[type] = NULL;
}

static struct tid_user_buf_ops *get_bufops(u16 type)
{
	if (type >= HFI2_MAX_MEMINFO_ENTRIES)
		return NULL;
	return bufops[type];
}

static struct tid_node_ops *get_nodeops(u16 type)
{
	if (type >= HFI2_MAX_MEMINFO_ENTRIES)
		return NULL;
	return nodeops[type];
}

int hfi2_tid_user_buf_init(u16 pset_size, unsigned long vaddr,
			   unsigned long length, bool notify,
			   struct tid_user_buf_ops *ops, u16 type,
			   struct tid_user_buf *tbuf)
{
	tbuf->vaddr = vaddr;
	tbuf->length = length;
	tbuf->use_mn = notify;
	tbuf->psets = kcalloc(pset_size, sizeof(*tbuf->psets), GFP_KERNEL);
	if (!tbuf->psets)
		return -ENOMEM;
	tbuf->ops = ops;
	tbuf->type = type;
	return 0;
}

void hfi2_tid_user_buf_free(struct tid_user_buf *tbuf)
{
	kfree(tbuf->psets);
	tbuf->psets = NULL;
}

/**
 * create_user_buf - create user buf for @memtype, store at @*ubuf
 * @fd: filedata pointer
 * @memtype: memory type (one of HFI2_MEMINFO_TYPE* defines)
 * @tinfo: TID info from user
 * @allow_unaligned: whether unaligned buffers are permitted
 * @ubuf: output pointer for the created user buffer
 *
 * Return: 0 on success, non-zero on failure.
 */
static int create_user_buf(struct hfi2_filedata *fd, u16 memtype,
			   struct hfi2_tid_info_v3 *tinfo,
			   bool allow_unaligned,
			   struct tid_user_buf **ubuf)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct tid_user_buf_ops *ops;
	int ret;

	ops = get_bufops(memtype);
	if (!ops)
		return -EINVAL;

	if (tinfo->length == 0)
		return -EINVAL;

	ret = ops->init(uctxt->expected_count, fd->use_mn, tinfo->vaddr,
			tinfo->length, allow_unaligned, tinfo->context, ubuf);
	if (ret)
		return ret;

	return 0;
}

static int page_array_iter_next(struct hfi2_page_iter *piter)
{
	struct page_array_iter *iter =
		container_of(piter, struct page_array_iter, common);

	if (!iter->tbuf->psets || !iter->tbuf->n_psets)
		return -EINVAL;

	iter->setidx++;

	return (iter->setidx < iter->tbuf->n_psets);
}

static void page_array_iter_free(struct hfi2_page_iter *piter)
{
	struct page_array_iter *iter =
		container_of(piter, struct page_array_iter, common);

	kfree(iter);
}

static struct hfi2_page_iter_ops page_array_iter_ops = {
	.next = page_array_iter_next,
	.free = page_array_iter_free
};

static struct hfi2_page_iter *tid_user_buf_iter_begin(struct tid_user_buf *tbuf)
{
	struct page_array_iter *iter;

	if (!tbuf->psets || !tbuf->n_psets)
		return ERR_PTR(-EINVAL);

	iter = kzalloc_obj(*iter, GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	iter->common.ops = &page_array_iter_ops;
	iter->tbuf = tbuf;

	return &iter->common;
}

static struct hfi2_page_iter *create_dma_iter(struct tid_user_buf *tbuf)
{
	if (tbuf->ops->iter_begin)
		return tbuf->ops->iter_begin(tbuf);

	return tid_user_buf_iter_begin(tbuf);
}

/*
 * Get number of TID-ready pinned-pagesets for @tbuf using hfi2_page_iter.
 *
 * @return >= 0 for number of pagesets, < 0 on error.
 */
static int pagesets_iter(struct tid_user_buf *tbuf, int cap)
{
	struct hfi2_page_iter *iter;
	int p = 0;
	int ret;

	iter = create_dma_iter(tbuf);
	if (IS_ERR(iter))
		return PTR_ERR(iter);

	while (true) {
		if (p >= cap)
			break;
		p++;
		ret = iter->ops->next(iter);
		if (ret < 0)
			goto bail;
		else if (!ret)
			break;
	}
	ret = p;
bail:
	iter->ops->free(iter);
	return ret;
}

/*
 * Get number of TID-ready pinned-pagesets for @tbuf.
 *
 * Each pageset is a physically contiguous range of pages and:
 * - Starts on a 4KiB-aligned address.
 * - Length is power-of-two in range [4KiB,2MiB].
 *
 * @cap hint on how many pagesets can be returned.
 *
 * @return >= 0 number of pagesets, < 0 on error.
 */
static int pagesets(struct tid_user_buf *tbuf, int cap)
{
	int ret;

	if (tbuf->ops->find_phys_blocks) {
		ret = tbuf->ops->find_phys_blocks(tbuf, cap);
		if (ret)
			return (ret < 0 ? ret : -EFAULT);

		return tbuf->n_psets;
	}

	/* No find_phys_blocks(); count using iterator */
	return pagesets_iter(tbuf, cap);
}

/*
 * RcvArray entry allocation for Expected Receives uses the two-level fractal
 * "meet-in-the-middle" bitmap allocator (`rcd->meta_map[4]` + `rcd->tid_map[256]`)
 * and the 256-byte combinational decision-table automaton (APA / LUT)
 * `hfi2_tid_seg_tab[]` (see `exp_rcv.c` and `exp_rcv_tab.S`):
 *
 *   1. The user buffer is decomposed into physically contiguous power-of-two
 *      page sets (`pageset_count`).
 *   2. For each complete set of 8 pagesets (`ngroups = pageset_count / 8`),
 *      `hfi2_tid_alloc_full_group()` claims an empty 8-slot group (`0x00 -> 0xFF`)
 *      growing left-to-right from group 0, while recording the index of the
 *      first partially occupied group encountered (`first_partial`).
 *   3. For the remaining pagesets:
 *      - Normal tail (`ngroups == 0`, remainder 1..7): `hfi2_tid_alloc_partial_group()`
 *        scans right-to-left from the highest group index using `hfi2_tid_seg_tab[]`
 *        (placing even counts at the bottom of the even-aligned window, odd
 *        counts at the top, and single slots via the "Flash Right / Flash Left"
 *        sign bit to preserve `TIDCTRL = 3` hardware pairs).
 *      - Collision / "meet in the middle" (`ngroups > 0` when full groups run
 *        out): `hfi2_tid_alloc_from_left()` continues forward left-to-right from
 *        `first_partial`, draining all free slots (`~old -> 0xFF`) in each
 *        partial group without table lookups until the final `< 8` remainder.
 */
int hfi2_user_exp_rcv_setup(struct hfi2_filedata *fd,
			    struct hfi2_tid_info_v3 *tinfo,
			    bool allow_unaligned, bool do_tidcnt_check)
{
	int ret = 0, pinned;
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_devdata *dd = uctxt->dd;
	/*
	 * mapped and mapped_pages are implementation-sized pages, not
	 * EXP_TID_ADDR_SIZE-sized.
	 */
	unsigned int ngroups, pageset_count, tididx = 0, mapped,
					     mapped_pages = 0;

	struct tid_user_buf *tidbuf;
	struct hfi2_page_iter *iter;
	u32 *tidlist = NULL;
	unsigned int psets;
	u16 memtype = (tinfo->flags & HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_MASK);

	trace_hfi2_exp_tid_update(uctxt->ctxt, fd->subctxt, tinfo);

	ret = create_user_buf(fd, memtype, tinfo, allow_unaligned, &tidbuf);
	if (ret)
		return ret;

	pinned = tidbuf->ops->pin_pages(fd, tidbuf);
	if (pinned <= 0) {
		dd_dev_warn_ratelimited(dd,
					"%s: Failed to pin %lu bytes (%d)\n",
					__func__, tidbuf->length, pinned);
		incr_cntr64(&dd->exp_rcv_pin_fail);
		ret = (pinned < 0) ? pinned : -ENOSPC;
		goto fail_free;
	}

	/* Cannot program TIDs for < EXP_TID_ADDR_SIZE pages */
	if (tidbuf->ops->page_size(tidbuf) < EXP_TID_ADDR_SIZE) {
		ret = -EOPNOTSUPP;
		goto fail_unpin;
	}

	/* Find sets of physically contiguous pages */
	ret = pagesets(tidbuf, pinned);
	if (ret < 0)
		goto fail_unpin;
	psets = (unsigned int)ret;

	/* Reserve the number of expected tids to be used. */
	spin_lock(&fd->tid_lock);
	if (fd->tid_used + psets > fd->tid_limit)
		pageset_count = fd->tid_limit - fd->tid_used;
	else
		pageset_count = psets;
	fd->tid_used += pageset_count;
	spin_unlock(&fd->tid_lock);

	if (!pageset_count) {
		ret = -ENOSPC;
		goto fail_unreserve;
	}

	ngroups = pageset_count / dd->rcv_entries.group_size;
	tidlist = kcalloc(pageset_count, sizeof(*tidlist), GFP_KERNEL);
	if (!tidlist) {
		ret = -ENOMEM;
		goto fail_unreserve;
	}

	tididx = 0;
	iter = create_dma_iter(tidbuf);
	if (IS_ERR(iter)) {
		ret = PTR_ERR(iter);
		goto fail_unreserve;
	} else if (!iter) {
		ret = -EFAULT;
		goto fail_unreserve;
	}

	mutex_lock(&uctxt->exp_mutex);
	/*
	 * First step: allocate and program complete 8-slot groups from the
	 * left side of meta_map. Record the first partial group encountered
	 * so that if full groups run out ("meet in the middle"), we continue
	 * forward left-to-right harvesting partial groups rather than
	 * reversing direction.
	 */
	{
		int first_partial = -1;

		while (ngroups) {
			int grp_idx = hfi2_tid_alloc_full_group(uctxt,
								&first_partial);

			if (grp_idx < 0)
				break;

			ret = program_rcvarray(fd, tidbuf, (u32)grp_idx, 0xFF,
					       tidlist, &tididx, iter, &mapped);
			mapped_pages += mapped;
			if (ret < 0) {
				hfi2_cdbg(TID,
					  "Failed to program RcvArray group %d",
					  ret);
				goto unlock;
			}

			ngroups--;
		}

		/*
		 * Second step:
		 * - If all full groups were satisfied (ngroups == 0), allocate
		 *   any remaining small tail (1..7 slots) from the right side
		 *   of meta_map (bidirectional stack growth).
		 * - If full groups ran out mid-request (ngroups > 0, "meet in
		 *   the middle"), continue moving forward left-to-right from
		 *   first_partial, sweeping whatever slots remain until the
		 *   request is satisfied or the context is exhausted.
		 */
		if (ngroups && first_partial >= 0) {
			u32 cur_g = (u32)first_partial;

			while (tididx < pageset_count) {
				u32 rem = pageset_count - tididx;
				u8 alloc_mask = 0;
				int grp_idx = hfi2_tid_alloc_from_left(uctxt,
								       cur_g,
								       rem,
								       &alloc_mask);

				if (grp_idx < 0)
					break;
				cur_g = (u32)grp_idx;

				ret = program_rcvarray(fd, tidbuf,
						       (u32)grp_idx,
						       alloc_mask, tidlist,
						       &tididx, iter, &mapped);
				mapped_pages += mapped;
				if (ret < 0) {
					hfi2_cdbg(TID,
						  "Failed to program RcvArray entries %d",
						  ret);
					goto unlock;
				}
			}
		} else {
			while (tididx < pageset_count) {
				u8 need = min_t(unsigned int,
						pageset_count - tididx,
						dd->rcv_entries.group_size);
				u8 alloc_mask = 0;
				int grp_idx =
					hfi2_tid_alloc_partial_group(uctxt,
								     need,
								     &alloc_mask);

				if (grp_idx < 0)
					break;

				ret = program_rcvarray(fd, tidbuf,
						       (u32)grp_idx,
						       alloc_mask, tidlist,
						       &tididx, iter, &mapped);
				mapped_pages += mapped;
				if (ret < 0) {
					hfi2_cdbg(TID,
						  "Failed to program RcvArray entries %d",
						  ret);
					goto unlock;
				}
			}
		}
	}
unlock:
	mutex_unlock(&uctxt->exp_mutex);

	iter->ops->free(iter);

	/*
	 * mapped_pages is based on implementation page size, not expected
	 * receive addressing.
	 *
	 * E.g. if implementation uses 64KiB pages and expected receive
	 * addressing is based on 4KiB, for 128KiB of mapped memory,
	 * mapped_pages=2 not mapped_pages=32.
	 */
	hfi2_cdbg(TID, "total mapped: tidpairs:%u pages:%u (%d)", tididx,
		  mapped_pages, ret);

	/* fail if nothing was programmed, set error if none provided */
	if (tididx == 0) {
		if (ret >= 0)
			ret = -ENOSPC;
		goto fail_unreserve;
	}

	/* adjust reserved tid_used to actual count */
	spin_lock(&fd->tid_lock);
	fd->tid_used -= pageset_count - tididx;
	spin_unlock(&fd->tid_lock);

	/* unpin all pages not covered by a TID */
	tidbuf->ops->unpin_pages(fd, tidbuf, mapped_pages,
				 pinned - mapped_pages);

	/* check for an invalidate during setup */
	if (tidbuf->ops->invalidated(tidbuf)) {
		ret = -EBUSY;
		goto fail_unprogram;
	}

	/* verify claimed incoming TID buffer has enough entries for result */
	if (do_tidcnt_check && tinfo->tidcnt < tididx) {
		ret = -ENOSPC;
		goto fail_unprogram;
	}

	tinfo->tidcnt = tididx;
	/* Should never happen but detect if somehow implementation pinned too many pages */
	if (check_mul_overflow(mapped_pages, tidbuf->ops->page_size(tidbuf),
			       &tinfo->length)) {
		ret = -EFAULT;
		goto fail_unprogram;
	}

	if (copy_to_user(u64_to_user_ptr(tinfo->tidlist), tidlist,
			 sizeof(tidlist[0]) * tididx)) {
		ret = -EFAULT;
		goto fail_unprogram;
	}

	tidbuf->ops->unnotify(tidbuf);
	tidbuf->ops->free(tidbuf);
	kfree(tidlist);
	return 0;

fail_unprogram:
	/* unprogram, unmap, and unpin all allocated TIDs directly
	 * using the kernel tidlist pointer, bypassing the user-copy
	 * path in hfi2_user_exp_rcv_clear which would fail SMAP.
	 */
	mutex_lock(&uctxt->exp_mutex);
	for (unsigned int i = 0; i < tididx; i++)
		unprogram_rcvarray(fd, tidlist[i]);
	spin_lock(&fd->tid_lock);
	fd->tid_used -= tididx;
	spin_unlock(&fd->tid_lock);
	mutex_unlock(&uctxt->exp_mutex);
	pinned = 0; /* nothing left to unpin */
	pageset_count = 0; /* nothing left reserved */
fail_unreserve:
	spin_lock(&fd->tid_lock);
	fd->tid_used -= pageset_count;
	spin_unlock(&fd->tid_lock);
fail_unpin:
	tidbuf->ops->unnotify(tidbuf);
	if (pinned > 0)
		tidbuf->ops->unpin_pages(fd, tidbuf, 0, pinned);
fail_free:
	tidbuf->ops->free(tidbuf);
	kfree(tidlist);
	return ret;
}

int hfi2_user_exp_rcv_clear(struct hfi2_filedata *fd,
			    struct hfi2_tid_info *tinfo)
{
	int ret = 0;
	u32 *tidinfo;
	unsigned int tididx;

	if (unlikely(tinfo->tidcnt > fd->tid_used))
		return -EINVAL;

	tidinfo = memdup_array_user(u64_to_user_ptr(tinfo->tidlist),
					    tinfo->tidcnt, sizeof(tidinfo[0]));
	if (IS_ERR(tidinfo))
		return PTR_ERR(tidinfo);

	for (tididx = 0; tididx < tinfo->tidcnt; tididx++) {
		ret = unprogram_rcvarray(fd, tidinfo[tididx]);
		if (ret) {
			hfi2_cdbg(TID, "Failed to unprogram rcv array %d", ret);
			break;
		}
	}
	spin_lock(&fd->tid_lock);
	fd->tid_used -= tididx;
	spin_unlock(&fd->tid_lock);
	tinfo->tidcnt = tididx;

	kfree(tidinfo);
	return ret;
}

int hfi2_user_exp_rcv_invalid(struct hfi2_filedata *fd,
			      struct hfi2_tid_info *tinfo, bool do_tidcnt_check)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	unsigned long *ev =
		uctxt->dd->events + (uctxt_offset(uctxt) + fd->subctxt);
	u32 *array;
	int ret = 0;

	if (!fd->invalid_tids)
		return -EINVAL;

	/*
	 * copy_to_user() can sleep, which will leave the invalid_lock
	 * locked and cause the MMU notifier to be blocked on the lock
	 * for a long time.
	 * Copy the data to a local buffer so we can release the lock.
	 */
	array = kcalloc(uctxt->expected_count, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -EFAULT;

	spin_lock(&fd->invalid_lock);
	if (do_tidcnt_check && tinfo->tidcnt < fd->invalid_tid_idx) {
		ret = -ENOSPC;
	} else if (fd->invalid_tid_idx) {
		memcpy(array, fd->invalid_tids,
		       sizeof(*array) * fd->invalid_tid_idx);
		memset(fd->invalid_tids, 0,
		       sizeof(*fd->invalid_tids) * fd->invalid_tid_idx);
		tinfo->tidcnt = fd->invalid_tid_idx;
		fd->invalid_tid_idx = 0;
		/*
		 * Reset the user flag while still holding the lock.
		 * Otherwise, PSM can miss events.
		 */
		clear_bit(_HFI2_EVENT_TID_MMU_NOTIFY_BIT, ev);
	} else {
		tinfo->tidcnt = 0;
	}
	spin_unlock(&fd->invalid_lock);

	if (ret == 0 && tinfo->tidcnt) {
		if (copy_to_user((void __user *)tinfo->tidlist, array,
				 sizeof(*array) * tinfo->tidcnt))
			ret = -EFAULT;
	}
	kfree(array);

	return ret;
}

/*
 * Convert @node's implementation-defined npages to number of
 * EXP_TID_ADDR_SIZE pages.
 *
 * @return number of EXP_TID_ADDR_SIZE pages
 */
static unsigned int node_npages(const struct tid_rb_node *node)
{
	/* Underflow/overflow protection here depends on other places enforcing that:
	 *   page_shift >= EXP_TID_ADDR_SHIFT
	 *   node->npages * (1 << page_shift) <= MAX_EXPECTED_BUFFER
	 */
	return (node->npages << node->page_shift) >> EXP_TID_ADDR_SHIFT;
}

/*
 * DMA-map and program single TID entry for physically contiguous pinned page
 * range.
 *
 * @fd
 * @tbuf
 * @rcventry
 * @iter
 * @onode out node. Undefined on error.
 *
 * @return 0 on success, non-zero on error.
 */
/*
 * DMA-map and program single TID entry for physically contiguous pinned page
 * range.
 *
 * @fd
 * @tbuf
 * @rcventry
 * @grp
 * @iter
 * @onode out node. Undefined on error.
 *
 * @return 0 on success, non-zero on error.
 */
static int set_rcvarray_entry(struct hfi2_filedata *fd,
			      struct tid_user_buf *tbuf,
			      u32 rcventry,
			      struct hfi2_page_iter *iter,
			      struct tid_rb_node **onode)
{
	struct tid_node_ops *nodeops = get_nodeops(tbuf->type);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_devdata *dd = uctxt->dd;
	struct tid_rb_node *node;
	int ret;

	if (WARN_ON(!nodeops))
		return -EINVAL;

	node = nodeops->init(fd, tbuf, rcventry, iter);
	if (IS_ERR(node))
		return PTR_ERR(node);

	if (node->use_mn) {
		ret = node->ops->register_notify(node);
		if (ret)
			goto out_unmap;
	}
	/* RcvArray entry requires EXP_TID_ADDR_SIZE page-size npages */
	dd->params->put_tid(uctxt, rcventry, PT_EXPECTED, node->dma_addr,
			    ilog2(node_npages(node)) + 1, false);

	trace_hfi2_exp_tid_reg(uctxt->ctxt, fd->subctxt, rcventry,
			       node_npages(node), node->vaddr, node->phys,
			       node->dma_addr, node->type);
	*onode = node;
	return 0;
out_unmap:
	hfi2_cdbg(TID, "Failed to insert RB node %u 0x%lx, 0x%lx %d",
		  node->rcventry, node->vaddr, node->phys, ret);

	node->ops->dma_unmap(node);
	node->ops->free(node);

	return -EFAULT;
}

/**
 * program_rcvarray() - program an RcvArray group with receive buffers
 * @fd: filedata pointer
 * @tbuf: pointer to struct tid_user_buf that has the user buffer starting
 *	  virtual address, buffer length, page pointers, pagesets (array of
 *	  struct tid_pageset holding information on physically contiguous
 *	  chunks from the user buffer), and other fields.
 * @grp_idx: RcvArray group index (0..255)
 * @alloc_mask: bitmask of slots within @grp_idx allocated for programming
 * @tidlist: the array of u32 elements when the information about the
 *           programmed RcvArray entries is to be encoded.
 * @tididx: starting offset into tidlist
 * @iter
 * @pmapped: (output parameter) number of implementation pages programmed into the RcvArray
 * @iter: iterator for the user buffer pagesets
 *           entries.
 *
 * Return:
 * -EINVAL if @alloc_mask is empty,
 * -ENOMEM or -EFAULT on error from set_rcvarray_entry(), or
 * number of RcvArray entries programmed.
 */
static int program_rcvarray(struct hfi2_filedata *fd,
			    struct tid_user_buf *tbuf,
			    u32 grp_idx, u8 alloc_mask,
			    u32 *tidlist, unsigned int *tididx,
			    struct hfi2_page_iter *iter,
			    unsigned int *pmapped)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	u32 grp_size = uctxt->dd->rcv_entries.group_size;
	u32 grp_base = grp_idx * grp_size;
	u32 start = __ffs(alloc_mask);
	u32 end = __fls(alloc_mask) + 1;
	u16 count = hweight8(alloc_mask);
	u8 unprogrammed = alloc_mask;
	u16 idx = 0;
	u32 useidx;
	int mapped = 0;
	int ret = 0;

	if (unlikely(!alloc_mask))
		return -EINVAL;

	for (useidx = 0; useidx < start; useidx++)
		uctxt->dd->params->rcv_array_wc_fill(uctxt, grp_base + useidx,
						     PT_EXPECTED);

	if (likely(count == end - start)) {
		for (; useidx < end; useidx++) {
			struct tid_rb_node *node;
			u32 rcventry = grp_base + useidx;

			ret = set_rcvarray_entry(fd, tbuf, rcventry, iter,
						 &node);
			if (ret)
				goto err_release;
			mapped += node->npages;

			tidlist[(*tididx)++] =
				create_tid(rcventry, node_npages(node));
			/* Pairs with xchg() in unprogram_rcvarray() */
			smp_store_release(&fd->entry_to_rb[rcventry], node);
			unprogrammed &= ~BIT(useidx);
			idx++;

			ret = iter->ops->next(iter);
			if (ret < 0) {
				goto err_release;
			} else if (!ret && idx < count) {
				ret = -EFAULT;
				goto err_release;
			}
		}
	} else {
		for (; useidx < end; useidx++) {
			struct tid_rb_node *node;
			u32 rcventry = grp_base + useidx;

			if (!(alloc_mask & BIT(useidx))) {
				uctxt->dd->params->rcv_array_wc_fill(uctxt,
								     rcventry,
								     PT_EXPECTED);
				continue;
			}

			ret = set_rcvarray_entry(fd, tbuf, rcventry, iter,
						 &node);
			if (ret)
				goto err_release;
			mapped += node->npages;

			tidlist[(*tididx)++] =
				create_tid(rcventry, node_npages(node));
			/* Pairs with xchg() in unprogram_rcvarray() */
			smp_store_release(&fd->entry_to_rb[rcventry], node);
			unprogrammed &= ~BIT(useidx);
			idx++;

			ret = iter->ops->next(iter);
			if (ret < 0) {
				goto err_release;
			} else if (!ret && idx < count) {
				ret = -EFAULT;
				goto err_release;
			}
		}
	}

	for (; useidx < grp_size; useidx++)
		uctxt->dd->params->rcv_array_wc_fill(uctxt, grp_base + useidx,
						     PT_EXPECTED);

	*pmapped = mapped;
	return idx;

err_release:
	if (unprogrammed)
		hfi2_tid_free_group_mask(uctxt, grp_idx, unprogrammed);
	*pmapped = mapped;
	return ret;
}

static int unprogram_rcvarray(struct hfi2_filedata *fd, u32 tidinfo)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_devdata *dd = uctxt->dd;
	struct tid_rb_node *node;
	u32 tidctrl = EXP_TID_GET(tidinfo, CTRL);
	u32 tididx = EXP_TID_GET(tidinfo, IDX) << 1, rcventry;

	if (tidctrl == 0x3 || tidctrl == 0x0)
		return -EINVAL;

	rcventry = tididx + (tidctrl - 1);

	if (rcventry >= uctxt->expected_count) {
		dd_dev_err(dd,
			   "Invalid RcvArray entry (%u) index for ctxt %u\n",
			   rcventry, uctxt->ctxt);
		return -EINVAL;
	}

	node = xchg(&fd->entry_to_rb[rcventry], NULL);
	if (!node || node->rcventry != rcventry)
		return -EBADF;

	node->ops->unregister_notify(node);
	cacheless_tid_rb_remove(fd, node);

	return 0;
}

static void __clear_tid_node(struct hfi2_filedata *fd, struct tid_rb_node *node)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;

	mutex_lock(&node->invalidate_mutex);
	if (node->freed)
		goto done;
	node->freed = true;

	trace_hfi2_exp_tid_unreg(uctxt->ctxt, fd->subctxt, node->rcventry,
				 node_npages(node), node->vaddr, node->phys,
				 node->dma_addr, node->type);

	/* Make sure device has seen the write before pages are unpinned */
	uctxt->dd->params->put_tid(uctxt, node->rcventry, PT_EXPECTED, 0, 0,
				   true);

	node->ops->unpin_pages(fd, node);
done:
	mutex_unlock(&node->invalidate_mutex);
}

static void clear_tid_node(struct hfi2_filedata *fd, struct tid_rb_node *node)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;

	__clear_tid_node(fd, node);
	hfi2_tid_free_slot(uctxt, node->rcventry);
	node->ops->free(node);
}

/**
 * hfi2_user_exp_rcv_invalidate - Unprogram TID for @node, updating user TID
 * invalidation events when @node->fdata->use_mn is true.
 * @node: TID rb node to unprogram
 */
void hfi2_user_exp_rcv_invalidate(struct tid_rb_node *node)
{
	struct hfi2_filedata *fdata = node->fdata;
	struct hfi2_ctxtdata *uctxt = fdata->uctxt;

	trace_hfi2_exp_tid_inval(uctxt->ctxt, fdata->subctxt, node->vaddr,
				 node->rcventry, node_npages(node),
				 node->dma_addr, node->type);

	/* clear the hardware rcvarray entry */
	__clear_tid_node(fdata, node);

	/* User TID invalidation events not in use, nothing else to do */
	if (!node->use_mn)
		return;

	spin_lock(&fdata->invalid_lock);
	if (fdata->invalid_tid_idx < uctxt->expected_count) {
		/* In-memory TIDs requires EXP_TID_ADDR_SIZE page-size npages */
		fdata->invalid_tids[fdata->invalid_tid_idx] =
			create_tid(node->rcventry, node_npages(node));
		if (!fdata->invalid_tid_idx) {
			unsigned long *ev;

			/*
			 * hfi2_set_uevent_bits() sets a user event flag
			 * for all processes. Because calling into the
			 * driver to process TID cache invalidations is
			 * expensive and TID cache invalidations are
			 * handled on a per-process basis, we can
			 * optimize this to set the flag only for the
			 * process in question.
			 */
			ev = uctxt->dd->events +
			     (uctxt_offset(uctxt) + fdata->subctxt);
			set_bit(_HFI2_EVENT_TID_MMU_NOTIFY_BIT, ev);
		}
		fdata->invalid_tid_idx++;
	}
	spin_unlock(&fdata->invalid_lock);
}

static void cacheless_tid_rb_remove(struct hfi2_filedata *fdata,
				    struct tid_rb_node *tnode)
{
	WRITE_ONCE(fdata->entry_to_rb[tnode->rcventry], NULL);
	clear_tid_node(fdata, tnode);
}
