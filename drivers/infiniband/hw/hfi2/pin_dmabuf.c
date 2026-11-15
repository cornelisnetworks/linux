// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2026 - Cornelis Networks, Inc.
 */

#include <linux/types.h>
#include <linux/scatterlist.h>
#include <linux/dma-buf.h>

#include "hfi2.h"
#include "common.h"
#include "pinning.h"
#include "sdma.h"
#include "user_sdma.h"
#include "dmabuf_core.h"
#include "trace.h"

/* Send-side adapter: converts shared dma-buf core mappings into SDMA descriptors. */

static unsigned int count_dmabuf_descs(struct sg_table *sgt, u64 bo_offset,
				       size_t len)
{
	struct scatterlist *sg;
	unsigned int ndesc = 0;
	u64 skip = bo_offset;
	size_t remaining = len;
	unsigned int i;

	for_each_sgtable_dma_sg(sgt, sg, i) {
		unsigned int dma_len = sg_dma_len(sg);

		if (skip >= dma_len) {
			skip -= dma_len;
			continue;
		}

		ndesc++;
		remaining -= min_t(size_t, dma_len - skip, remaining);
		skip = 0;
		if (!remaining)
			return ndesc;
	}

	return 0;
}

static int add_dmabuf_range_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct hfi2_dmabuf_pin *pin,
					   u64 bo_offset, size_t len)
{
	struct scatterlist *sg;
	u64 skip = bo_offset;
	size_t remaining = len;
	unsigned int i;
	int ret;

	for_each_sgtable_dma_sg(pin->sgt, sg, i) {
		unsigned int dma_len = sg_dma_len(sg);
		unsigned int from_this_sg;

		if (skip >= dma_len) {
			skip -= dma_len;
			continue;
		}

		from_this_sg = min_t(size_t, dma_len - skip, remaining);

		/* Cannot truncate: remaining is bounded by the MTU. */
		ret = sdma_txadd_daddr(pin->ctx->dd, &tx->txreq,
				       sg_dma_address(sg) + skip,
				       (u16)from_this_sg);
		if (ret) {
			SDMA_DBG(req, "dmabuf txadd_daddr failed %d", ret);
			return ret;
		}

		skip = 0;
		remaining -= from_this_sg;
		if (!remaining)
			return 0;
	}

	SDMA_DBG(req, "dmabuf mapping short by %zu bytes", remaining);
	return -EINVAL;
}

static int add_dmabuf_iovec_to_sdma_packet(struct hfi2_dmabuf_ctx *ctx,
					   struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   size_t from_this_iovec)
{
	struct user_sdma_pinref *mru;
	struct hfi2_dmabuf_pin *pin = NULL;
	unsigned int ndesc;
	int avail;
	u64 bo_offset;
	int fd;
	int ret;

	fd = (int)iovec->context;
	bo_offset = (u64)(uintptr_t)iovec->iov.iov_base + iovec->offset;

	SDMA_DBG(req, "dmabuf fd=%d offset=0x%llx len=%zu", fd, bo_offset,
		 from_this_iovec);

	/*
	 * Compare buffer objects, not fd numbers: fd reuse can select an
	 * unrelated buffer between iovecs.
	 */
	mru = hfi2_user_sdma_mru_ref(tx, HFI2_MEMINFO_TYPE_DMABUF);
	pin = mru ? mru->ptr : NULL;
	if (pin && hfi2_dmabuf_pin_matches_fd(pin, fd, bo_offset,
					      from_this_iovec)) {
		hfi2_user_sdma_touch_ref(tx, mru);
	} else {
		pin = hfi2_dmabuf_pin_get(ctx, fd, bo_offset, from_this_iovec,
					  "user sdma");
		if (IS_ERR(pin))
			return PTR_ERR(pin);

		/* Before reading the sgt, so it cannot be torn down under us. */
		ret = hfi2_user_sdma_add_ref(tx, pin, HFI2_MEMINFO_TYPE_DMABUF);
		if (ret) {
			hfi2_dmabuf_pin_put(pin);
			return ret;
		}
	}

	/*
	 * do_coalesce() rejects SDMA_MAP_NONE and a packet cannot continue into
	 * another txreq, so an overlong list can only be refused. Check before
	 * emitting anything.
	 */
	ndesc = count_dmabuf_descs(pin->sgt, bo_offset, from_this_iovec);
	if (!ndesc) {
		SDMA_DBG(req, "dmabuf mapping does not cover requested range");
		return -EINVAL;
	}

	avail = (int)tx->txreq.desc_limit - (int)tx->txreq.num_desc -
		(int)tx->txreq.desc_margin;
	if (avail <= 0 || ndesc > (unsigned int)avail) {
		SDMA_DBG(req,
			 "dmabuf range needs %u descriptors, only %d available (fragmented buffer; reduce fragsize)",
			 ndesc, avail);
		return -EINVAL;
	}

	ret = add_dmabuf_range_to_sdma_packet(req, tx, pin, bo_offset,
					      from_this_iovec);
	if (ret)
		return ret;

	iovec->offset += from_this_iovec;

	return 0;
}

static int add_dmabuf_pages_to_sdma_packet(struct user_sdma_request *req,
					   struct user_sdma_txreq *tx,
					   struct user_sdma_iovec *iovec,
					   u32 *pkt_data_remaining)
{
	struct hfi2_dmabuf_ctx *ctx = &req->pq->fd->dmabuf_ctx;
	size_t remaining_to_add = *pkt_data_remaining;

	while ((remaining_to_add > 0) &&
	       (iovec->type == HFI2_MEMINFO_TYPE_DMABUF)) {
		struct user_sdma_iovec *cur_iovec;
		size_t from_this_iovec;
		int ret;

		cur_iovec = iovec;
		from_this_iovec = iovec->iov.iov_len - iovec->offset;
		if (from_this_iovec > remaining_to_add) {
			from_this_iovec = remaining_to_add;
		} else {
			req->iov_idx++;
			iovec++;
		}

		ret = add_dmabuf_iovec_to_sdma_packet(ctx, req, tx, cur_iovec,
						      from_this_iovec);
		if (ret)
			return ret;

		remaining_to_add -= from_this_iovec;
	}
	*pkt_data_remaining = remaining_to_add;

	return 0;
}

/*
 * The mapping state lives in hfi2_filedata for the life of the file, so the
 * per-packet-queue hooks only have to mark the memory type supported.
 */
static int init_dmabuf_pinning_interface(struct hfi2_user_sdma_pkt_q *pq)
{
	PINNING_STATE(pq, HFI2_MEMINFO_TYPE_DMABUF) = pq->fd;
	return 0;
}

static void free_dmabuf_pinning_interface(struct hfi2_user_sdma_pkt_q *pq)
{
	PINNING_STATE(pq, HFI2_MEMINFO_TYPE_DMABUF) = NULL;
}

static int get_dmabuf_stats(struct hfi2_user_sdma_pkt_q *pq, int index,
			    struct hfi2_pin_stats *stats)
{
	struct hfi2_dmabuf_ctx *ctx;

	stats->memtype = HFI2_MEMINFO_TYPE_DMABUF;
	if (!PINNING_STATE(pq, HFI2_MEMINFO_TYPE_DMABUF))
		return 0;

	if (index == -1) {
		stats->index = 1;
		return 0;
	}

	if (index != 0)
		return -EINVAL;

	ctx = &pq->fd->dmabuf_ctx;
	stats->total_bytes = atomic64_read(&ctx->bytes_pinned);
	stats->cache_entries = READ_ONCE(ctx->cache_count);
	stats->total_refcounts = atomic64_read(&ctx->n_pin) -
				 atomic64_read(&ctx->n_unpin);
	stats->hits = atomic64_read(&ctx->n_hits);
	stats->misses = atomic64_read(&ctx->n_pin);
	stats->internal_evictions = atomic64_read(&ctx->n_evictions);
	stats->external_evictions = atomic64_read(&ctx->n_faults);

	return 0;
}

static struct pinning_interface dmabuf_pinning_interface = {
	.init = init_dmabuf_pinning_interface,
	.free = free_dmabuf_pinning_interface,
	.add_to_sdma_packet = add_dmabuf_pages_to_sdma_packet,
	.put = hfi2_dmabuf_pin_put,
	.get_stats = get_dmabuf_stats,
};

void hfi2_pin_dmabuf_init(void)
{
	hfi2_register_pinning_interface(HFI2_MEMINFO_TYPE_DMABUF,
				   &dmabuf_pinning_interface);

	/* HFI2_CAP_K2U only exports bits already set in hfi2_cap_mask. */
	HFI2_CAP_KSET(DMABUF);
}

void hfi2_pin_dmabuf_free(void)
{
	hfi2_deregister_pinning_interface(HFI2_MEMINFO_TYPE_DMABUF);
}
