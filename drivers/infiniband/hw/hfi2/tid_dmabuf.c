// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2026 - Cornelis Networks, Inc.
 */

/*
 * Expected receive DMA-BUF uses vaddr byte offsets and context[31:0] fds;
 * pinning removes invalidation state/callbacks while node refs retain its pin.
 */

#include <linux/kref.h>
#include <linux/scatterlist.h>
#include <linux/dma-buf.h>

#include "hfi2.h"
#include "common.h"
#include "user_exp_rcv.h"
#include "dmabuf_core.h"
#include "trace.h"

static struct tid_user_buf_ops dmabuf_bufops;
static struct tid_node_ops dmabuf_nodeops;

struct dmabuf_tid_user_buf {
	struct tid_user_buf common;

	/*
	 * Reference on the shared mapping, taken in pin_pages() and dropped
	 * when the last node reference releases the buf. NULL until
	 * pin_pages() succeeds.
	 */
	struct hfi2_dmabuf_pin *pin;

	/* Only used for tracing */
	struct hfi2_filedata *fd;

	/* From hfi2_tid_info_v3.context bits 0-31 */
	int dmabuf_fd;

	/* common.vaddr is the same value; typed u64 for the core API */
	u64 bo_offset;

	/* common.length rounded up to a whole number of TID-sized pages */
	size_t mapped_len;

	struct kref ref;
};

/*
 * Advance over [bo_offset, bo_offset + mapped_len) of the buffer object. Every
 * produced range starts EXP_TID_ADDR_SIZE-aligned and has a power-of-two
 * length in [EXP_TID_ADDR_SIZE, MAX_EXPECTED_BUFFER].
 *
 * No lock is needed: the buf holds a pin reference, so the scatterlist cannot
 * be torn down or relocated while an iterator exists.
 */
struct dmabuf_page_iter {
	struct hfi2_page_iter common;
	struct dmabuf_tid_user_buf *buf;

	/* Current mapped segment; NULL at end of iteration */
	struct scatterlist *sg;

	unsigned int offset;

	/* BO offset corresponding to (sg, offset); mirrors amd iter->va */
	unsigned long va;

	size_t remaining;
};

/*
 * Length of the TID-compatible range at the iterator's current position.
 * Zero only at end of iteration.
 */
static unsigned int dmabuf_iter_len(struct dmabuf_page_iter *iter)
{
	size_t len;

	if (!iter->sg || !iter->remaining)
		return 0;

	len = min_t(size_t, sg_dma_len(iter->sg) - iter->offset,
		    iter->remaining);
	len = min_t(size_t, len, MAX_EXPECTED_BUFFER);

	return rounddown_pow_of_two(len);
}

static dma_addr_t dmabuf_iter_dma_addr(struct dmabuf_page_iter *iter)
{
	return sg_dma_address(iter->sg) + iter->offset;
}

/*
 * @return 1 if the iterator is valid after advancing, 0 at end, < 0 on a
 * range that preflight should have rejected.
 */
static int dmabuf_page_iter_next(struct hfi2_page_iter *diter)
{
	struct dmabuf_page_iter *iter =
		container_of(diter, struct dmabuf_page_iter, common);
	unsigned int adv;

	adv = dmabuf_iter_len(iter);
	if (!adv)
		return -EINVAL;

	iter->offset += adv;
	iter->va += adv;
	iter->remaining -= adv;

	if (iter->offset >= sg_dma_len(iter->sg)) {
		iter->offset = 0;
		iter->sg = sg_next(iter->sg);
	}

	if (!iter->remaining)
		return 0;

	/* preflight_sgt() walked this same sequence; neither can happen. */
	if (WARN_ON_ONCE(!iter->sg))
		return -EFAULT;
	if (WARN_ON_ONCE(!IS_ALIGNED(dmabuf_iter_dma_addr(iter),
				     EXP_TID_ADDR_SIZE)))
		return -EFAULT;

	return 1;
}

static void dmabuf_page_iter_free(struct hfi2_page_iter *diter)
{
	struct dmabuf_page_iter *iter =
		container_of(diter, struct dmabuf_page_iter, common);

	kfree(iter);
}

static struct hfi2_page_iter_ops dmabuf_page_iter_ops = {
	.next = dmabuf_page_iter_next,
	.free = dmabuf_page_iter_free
};

static int dmabuf_seek(struct sg_table *sgt, u64 bo_offset,
		       struct scatterlist **out_sg, unsigned int *out_offset)
{
	struct scatterlist *sg;
	u64 skip = bo_offset;
	unsigned int i;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		unsigned int dma_len = sg_dma_len(sg);

		if (skip < dma_len) {
			*out_sg = sg;
			*out_offset = (unsigned int)skip;
			return 0;
		}
		skip -= dma_len;
	}

	return -EFAULT;
}

static struct hfi2_page_iter *dmabuf_page_iter_begin(struct tid_user_buf *tbuf)
{
	struct dmabuf_tid_user_buf *dbuf =
		container_of(tbuf, struct dmabuf_tid_user_buf, common);
	struct dmabuf_page_iter *iter;
	int ret;

	if (!dbuf->pin)
		return ERR_PTR(-EINVAL);

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return ERR_PTR(-ENOMEM);

	iter->common.ops = &dmabuf_page_iter_ops;
	iter->buf = dbuf;
	iter->va = dbuf->bo_offset;
	iter->remaining = dbuf->mapped_len;

	ret = dmabuf_seek(dbuf->pin->sgt, dbuf->bo_offset, &iter->sg,
			  &iter->offset);
	if (ret) {
		kfree(iter);
		return ERR_PTR(ret);
	}

	return &iter->common;
}

/*
 * Walk the scatterlist over the whole requested range and validate every entry
 * before any TID is programmed, so a violation cannot leave a request
 * half-programmed. A conforming exporter always passes: dma_buf_map_attachment()
 * guarantees PAGE_SIZE-aligned addresses and lengths, and PAGE_SIZE >=
 * EXP_TID_ADDR_SIZE everywhere hfi2 builds.
 *
 * @return -EOPNOTSUPP for a nonconforming scatterlist, -EFAULT for a mapping
 * that ends before covering the range.
 */
static int preflight_sgt(struct sg_table *sgt, u64 bo_offset, size_t len)
{
	struct scatterlist *sg;
	unsigned int offset;
	size_t remaining = len;
	int ret;

	ret = dmabuf_seek(sgt, bo_offset, &sg, &offset);
	if (ret)
		return ret;

	while (remaining) {
		unsigned int dma_len;
		size_t chunk;

		if (!sg)
			return -EFAULT;

		/* SG_CHAIN is not walked by for_each_sgtable_dma_sg() peers */
		if (sg_is_chain(sg))
			return -EOPNOTSUPP;

		dma_len = sg_dma_len(sg);
		if (offset >= dma_len)
			return -EOPNOTSUPP;

		if (!IS_ALIGNED(sg_dma_address(sg) + offset,
				EXP_TID_ADDR_SIZE))
			return -EOPNOTSUPP;

		chunk = min_t(size_t, dma_len - offset, remaining);

		/*
		 * The greedy power-of-two split only terminates on
		 * EXP_TID_ADDR_SIZE boundaries, so every segment must both
		 * start and end on one.
		 */
		if (!IS_ALIGNED(chunk, EXP_TID_ADDR_SIZE))
			return -EOPNOTSUPP;

		remaining -= chunk;
		offset = 0;
		sg = sg_next(sg);
	}

	return 0;
}

/* TID node code */

struct dmabuf_tid_node {
	struct tid_rb_node common;
	struct dmabuf_tid_user_buf *buf;
};

static void dmabuf_user_buf_kref_cb(struct kref *ref);

static struct tid_rb_node *dmabuf_node_init(struct hfi2_filedata *fd,
					    struct tid_user_buf *tbuf,
					    u32 rcventry,
					    struct tid_group *grp,
					    struct hfi2_page_iter *diter)
{
	struct dmabuf_page_iter *iter =
		container_of(diter, struct dmabuf_page_iter, common);
	struct dmabuf_tid_user_buf *dbuf = iter->buf;
	struct dmabuf_tid_node *node;
	unsigned int len;

	len = dmabuf_iter_len(iter);
	if (!len)
		return ERR_PTR(-EINVAL);

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return ERR_PTR(-ENOMEM);

	kref_get(&dbuf->ref);
	node->buf = dbuf;

	mutex_init(&node->common.invalidate_mutex);
	node->common.fdata = fd;
	node->common.grp = grp;
	node->common.ops = &dmabuf_nodeops;
	node->common.rcventry = rcventry;
	node->common.npages = len >> EXP_TID_ADDR_SHIFT;
	node->common.page_shift = EXP_TID_ADDR_SHIFT;

	/* No CPU physical address; user_exp_rcv only uses it for tracing. */
	node->common.phys = 0;
	node->common.dma_addr = dmabuf_iter_dma_addr(iter);
	node->common.vaddr = iter->va;
	node->common.use_mn = dbuf->common.use_mn;
	node->common.type = HFI2_MEMINFO_TYPE_DMABUF;

	return &node->common;
}

static void dmabuf_node_free(struct tid_rb_node *tnode)
{
	struct dmabuf_tid_node *node =
		container_of(tnode, struct dmabuf_tid_node, common);

	kref_put(&node->buf->ref, dmabuf_user_buf_kref_cb);
	kfree(node);
}

/*
 * No-op: the pin holds the buffer object immovable, so there is no
 * invalidation to be notified of. See the header comment.
 */
static int dmabuf_node_register_notify(struct tid_rb_node *node)
{
	return 0;
}

static void dmabuf_node_unregister_notify(struct tid_rb_node *node)
{
}

/* No-op: the buf's single mapping is unmapped when its last node releases. */
static void dmabuf_node_dma_unmap(struct tid_rb_node *node)
{
}

/* No-op: partial unpinning is not supported; see dmabuf_unpin_pages(). */
static void dmabuf_node_unpin_pages(struct hfi2_filedata *fd,
				    struct tid_rb_node *node)
{
}

static struct tid_node_ops dmabuf_nodeops = {
	.init = dmabuf_node_init,
	.free = dmabuf_node_free,
	.register_notify = dmabuf_node_register_notify,
	.unregister_notify = dmabuf_node_unregister_notify,
	.dma_unmap = dmabuf_node_dma_unmap,
	.unpin_pages = dmabuf_node_unpin_pages
};

/* TID user-buf code */

static int dmabuf_user_buf_init(u16 expected_count,
				bool notify,
				unsigned long vaddr,
				unsigned long length,
				bool allow_unaligned,
				u64 context,
				struct tid_user_buf **tbuf)
{
	struct dmabuf_tid_user_buf *dbuf;
	int ret;

	/*
	 * vaddr is a byte offset into the buffer object, which carries no page
	 * phase to recover, so allow_unaligned does not apply. TID hardware
	 * still requires EXP_TID_ADDR_SIZE alignment.
	 */
	if (!IS_ALIGNED(vaddr, EXP_TID_ADDR_SIZE))
		return -EINVAL;

	dbuf = kzalloc(sizeof(*dbuf), GFP_KERNEL);
	if (!dbuf)
		return -ENOMEM;
	kref_init(&dbuf->ref);
	*tbuf = &dbuf->common;

	ret = hfi2_tid_user_buf_init(expected_count, vaddr, length, notify,
				&dmabuf_bufops, HFI2_MEMINFO_TYPE_DMABUF,
				*tbuf);
	if (ret)
		goto fail;

	dbuf->dmabuf_fd = (int)(context &
				HFI2_TID_UPDATE_V3_CONTEXT_DMABUF_FD_MASK);
	dbuf->bo_offset = vaddr;
	/* TIDs cover whole EXP_TID_ADDR_SIZE pages. */
	dbuf->mapped_len = ALIGN(length, EXP_TID_ADDR_SIZE);

	return 0;

fail:
	/* No need to do kref_put(), no outside dbuf->ref holders */
	hfi2_tid_user_buf_free(&dbuf->common);
	kfree(dbuf);
	return ret;
}

static void dmabuf_user_buf_kref_cb(struct kref *ref)
{
	struct dmabuf_tid_user_buf *dbuf =
		container_of(ref, struct dmabuf_tid_user_buf, ref);

	if (dbuf->pin) {
		trace_unpin_recv_mem(dbuf->fd, HFI2_MEMINFO_TYPE_DMABUF, 0,
				     dbuf, dbuf->common.vaddr,
				     dbuf->common.length, 0,
				     dbuf->mapped_len);
		hfi2_dmabuf_pin_put(dbuf->pin);
	}

	hfi2_tid_user_buf_free(&dbuf->common);
	kfree(dbuf);
}

static void dmabuf_user_buf_free(struct tid_user_buf *tbuf)
{
	struct dmabuf_tid_user_buf *dbuf =
		container_of(tbuf, struct dmabuf_tid_user_buf, common);

	kref_put(&dbuf->ref, dmabuf_user_buf_kref_cb);
}

static unsigned int dmabuf_page_size(struct tid_user_buf *tbuf)
{
	/*
	 * The mapping has no single native page size; segments are only
	 * guaranteed PAGE_SIZE-aligned. Present the TID granule: npages and
	 * page_shift throughout this file are in the same units.
	 */
	return EXP_TID_ADDR_SIZE;
}

/*
 * Take a reference on the shared mapping and validate that it can be
 * presented as TID pagesets.
 *
 * @return number of EXP_TID_ADDR_SIZE pages on success, < 0 on error.
 */
static int dmabuf_pin_pages(struct hfi2_filedata *fd,
			    struct tid_user_buf *tbuf)
{
	struct dmabuf_tid_user_buf *dbuf =
		container_of(tbuf, struct dmabuf_tid_user_buf, common);
	struct hfi2_dmabuf_pin *pin;
	size_t npages;
	int ret;

	dbuf->fd = fd;

	npages = dbuf->mapped_len >> EXP_TID_ADDR_SHIFT;
	if (!npages || npages > type_max(int)) {
		ret = -EINVAL;
		goto fail;
	}

	pin = hfi2_dmabuf_pin_get(&fd->dmabuf_ctx, dbuf->dmabuf_fd,
				  dbuf->bo_offset, dbuf->mapped_len,
				  "expected receive");
	if (IS_ERR(pin)) {
		ret = PTR_ERR(pin);
		goto fail;
	}

	ret = preflight_sgt(pin->sgt, dbuf->bo_offset, dbuf->mapped_len);
	if (ret) {
		hfi2_dmabuf_pin_put(pin);
		goto fail;
	}

	dbuf->pin = pin;

	trace_pin_recv_mem(fd, HFI2_MEMINFO_TYPE_DMABUF, tbuf->vaddr,
			   tbuf->length, (int)npages, 0, dbuf,
			   sg_dma_address(pin->sgt->sgl), dbuf->mapped_len);

	return (int)npages;

fail:
	trace_pin_recv_mem(fd, HFI2_MEMINFO_TYPE_DMABUF, tbuf->vaddr,
			   tbuf->length, ret, 0, dbuf, 0, 0);

	return ret;
}

/*
 * No-op: partial unpinning is not supported. The mapping reference drops
 * when the last node releases the buf.
 */
static void dmabuf_unpin_pages(struct hfi2_filedata *fd,
			       struct tid_user_buf *tbuf,
			       unsigned int pageidx,
			       unsigned int npages)
{
}

/* The pin holds the buffer object immovable; never invalidated. */
static bool dmabuf_invalidated(struct tid_user_buf *tbuf)
{
	return false;
}

static void dmabuf_unnotify(struct tid_user_buf *tbuf)
{
}

static struct tid_user_buf_ops dmabuf_bufops = {
	.init = dmabuf_user_buf_init,
	.free = dmabuf_user_buf_free,
	.page_size = dmabuf_page_size,
	.pin_pages = dmabuf_pin_pages,
	.unpin_pages = dmabuf_unpin_pages,
	.find_phys_blocks = NULL,
	.invalidated = dmabuf_invalidated,
	.unnotify = dmabuf_unnotify,
	.iter_begin = dmabuf_page_iter_begin
};

/* Cannot fail: HFI2_MEMINFO_TYPE_DMABUF < HFI2_MAX_MEMINFO_ENTRIES. */
void hfi2_tid_dmabuf_init(void)
{
	hfi2_register_tid_ops(HFI2_MEMINFO_TYPE_DMABUF, &dmabuf_bufops,
			 &dmabuf_nodeops);

	/*
	 * HFI2_CAP_DMABUF is shared with the user-SDMA dma-buf backend,
	 * which already set it in hfi2_pin_dmabuf_init().
	 */
}

void hfi2_tid_dmabuf_free(void)
{
	hfi2_deregister_tid_ops(HFI2_MEMINFO_TYPE_DMABUF);
}
