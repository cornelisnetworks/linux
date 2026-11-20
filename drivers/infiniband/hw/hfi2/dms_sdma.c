// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2025 Cornelis Networks.
 */

#include "dms_sdma.h"
#include "dms.h"
#include "sdma.h"
#include "sdma_defs.h"
#include "sdma_txreq.h"
#include "pio.h"
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/slab.h>

/*
 * DMS SDMA layer.  A caller builds a batch of physically-contiguous
 * fragments; commit() splices the built node list onto the target engine's
 * pending list (no descriptor copy), and the poll step drains it into the
 * HW ring and fires completions as descriptors egress.  Single-threaded:
 * everything here is touched only by the DMS poll context -- no locks --
 * except the HW ring itself when several lanes share the engines
 * (dms->sde_share): ring accesses then take hfi2_dms_sde_lock().
 */

/*
 * Doorbell run pad granule, taken from the platform (dd->pad_sdma_desc:
 * 32 on AMD, 0 on Intel) rather than hardcoded per chip.  A zero granule
 * pads nothing -- the pad arithmetic below handles that as a no-op.
 *
 * A single descriptor moves at most SDMA_DESC_MAX_BYTES (14-bit count).
 */
static u32 _granule(const struct hfi2_dms *dms)
{
	return dms->dd ? (u32)dms->dd->pad_sdma_desc : 0;
}

/* Round @n up to the submission granule; @gran == 0 means no padding. */
static u32 _granule_pad(u32 gran, u32 n)
{
	return gran ? roundup(n, gran) - n : 0;
}

#define SDMA_DESC_MAX_BYTES		((1U << JKR_SDMA_DESC1_BYTE_COUNT_WIDTH) - 1)

/* JKR errata: a descriptor must not cross a 256-byte boundary unless it is
 * a whole multiple of 256 bytes.  CYR has no alignment errata.
 */
#define HFI2_DMS_SDMA_PAYLOAD_ALIGN	256


enum hfi2_dms_sdma_batch_state {
	HFI2_DMS_SDMA_BATCH_FREE,
	HFI2_DMS_SDMA_BATCH_HELD,
	HFI2_DMS_SDMA_BATCH_PENDING,
};

/*
 * struct hfi2_dms_sdma_batch - one node of a batch's descriptor node list,
 *	recycled through the per-DMS free-list.  The caller's batch handle is
 *	the head node; emit() chains further nodes via @ring.
 * @link: membership linkage -- on the free-list, the per-DMS held list, or
 *	the target engine's pending list (a node is on exactly one)
 * @ring: circular list stitching all nodes of one batch together (the head
 *	node's @ring is the anchor)
 * @dms: owning DMS instance
 * @is_jkr: chip is JKR (drives the 256B errata split)
 * @ndesc: descriptors written in @descs
 * @place: drain cursor -- descriptors of this node already copied to the
 *	HW ring (for packet-granular partial drain across poll passes)
 * @done_fn: completion callback identity, copied to each node so held and
 *	committed batches can be selected consistently; the tail identity is
 *	copied to the completion FIFO when its final descriptor is placed
 * @cookie: completion callback argument (same identity on every node)
 * @descs: the emitted descriptors (host-order; blitted into the ring at
 *	drain)
 */
struct hfi2_dms_sdma_batch {
	struct list_head link;
	struct list_head ring;
	struct hfi2_dms *dms;
	bool is_jkr;
	bool nowait;
	u8 port_idx;
	u32 ndesc;
	u32 place;
	enum hfi2_dms_sdma_batch_state state;
	hfi2_dms_sdma_done_fn done_fn;
	void *cookie;
	struct sdma_desc descs[HFI2_DMS_SDMA_NODE_DESCS];
};

/*
 * struct hfi2_dms_sdma_completion - one placed-but-not-yet-egressed commit.
 * @done_fn: caller completion callback
 * @cookie: caller callback argument
 * @anchor_seq: MONOTONIC descriptor sequence number one past this commit's
 *	final descriptor.  The commit has egressed once the engine's
 *	head sequence reaches it.  See _seq_head() for why this is a
 *	sequence and not a ring index.
 */
struct hfi2_dms_sdma_completion {
	hfi2_dms_sdma_done_fn done_fn;
	void *cookie;
	u64 anchor_seq;
	int status;
};

/*
 * struct hfi2_dms_sdma_completion_fifo - per-engine completion ring.
 * @entries: ring of pending completions, sized to the HW descriptor depth
 * @cnt: capacity (== sde->descq_cnt)
 * @head: oldest pending entry
 * @nr: number of pending entries
 * @tail_seq: monotonic count of descriptors this layer has placed into the
 *	engine's ring.  Resynced from the observed ring tail on every use, so
 *	it stays correct even though the DMS injector places descriptors on
 *	the same loaned engine without going through this layer.
 * @tail_ring: ring index @tail_seq corresponds to (the resync reference).
 *	Neither is used when the engine is shared by several lanes
 *	(dms->sde_share): the shared placed-descriptor count replaces them.
 *
 * A commit that egresses with no completion recorded never returns its
 * cookie.  Overflow is prevented by construction -- @cnt matches the ring
 * depth, every recorded entry owns at least one un-egressed descriptor, and
 * the poll step retires before the placement step -- but the last two depend
 * on caller behaviour and on the call order in bulksvc_lane_once(), neither
 * checkable here, so _completion_push() reports failure and its callers
 * propagate it.
 */
struct hfi2_dms_sdma_completion_fifo {
	struct hfi2_dms_sdma_completion *entries;
	u32 cnt;
	u32 head;
	u32 nr;
	u64 tail_seq;
	u32 tail_ring;
};

/* ---------------------------------------------------------------------- */
/* Descriptor field stamping (chip-dispatched for byte-count/phys_addr).  */
/* ---------------------------------------------------------------------- */

static void _desc_set(struct sdma_desc *desc, dma_addr_t paddr,
		      u32 bytes, bool is_jkr)
{
	*desc = (struct sdma_desc){0};
	if (is_jkr) {
		jkr_sdma_qw_set_byte_count(&desc->qw[0], bytes);
		jkr_sdma_qw_set_phy_addr(&desc->qw[0], paddr);
	} else {
		cyr_sdma_qw_set_byte_count(&desc->qw[0], bytes);
		cyr_sdma_qw_set_phy_addr(&desc->qw[0], paddr);
	}
}

/* ---------------------------------------------------------------------- */
/* Batch lifecycle.                                                       */
/* ---------------------------------------------------------------------- */

/*
 * Pop a node off the per-DMS free-list, growing the pool by one if it is
 * empty (kept forever after -- high-water mark, so the data path allocates
 * at most once per new high-water, never per inject).  The returned node
 * is zeroed of per-use state (ndesc/place/completion) and its ring anchor
 * initialized to a single-node ring.  Returns NULL only on -ENOMEM growth
 * failure.
 */
static struct hfi2_dms_sdma_batch *_node_get(struct hfi2_dms *dms, u8 port_idx)
{
	struct hfi2_dms_sdma_batch *b;

	if (list_empty(&dms->sdma_batch_free)) {
		b = kzalloc_node(sizeof(*b), GFP_KERNEL, dms->numa_node);
		if (!b) {
			dms->allocation_stats.sdma_batch_growth_failures++;
			return NULL;
		}
		dms->allocation_stats.sdma_batch_growth_allocs++;
		list_add(&b->link, &dms->sdma_batch_free);
	}

	b = list_first_entry(&dms->sdma_batch_free,
			     struct hfi2_dms_sdma_batch, link);
	list_del(&b->link);

	INIT_LIST_HEAD(&b->ring);
	b->dms = dms;
	b->is_jkr = dms->chip_type == CHIP_JKR;
	b->nowait = false;
	b->port_idx = port_idx;
	b->ndesc = 0;
	b->place = 0;
	b->state = HFI2_DMS_SDMA_BATCH_FREE;
	b->done_fn = NULL;
	b->cookie = NULL;

	return b;
}

struct hfi2_dms_sdma_batch *hfi2_dms_sdma_batch_new(struct hfi2_dms *dms,
						    u8 port_idx)
{
	struct hfi2_dms_sdma_batch *b;

	if (WARN_ON_ONCE(!dms))
		return NULL;

	if (WARN_ON_ONCE(port_idx >= HFI2_DMS_MAX_PORTS))
		return NULL;

	b = _node_get(dms, port_idx);
	if (!b)
		return NULL;

	/* Head node linked onto the held list until commit/abort. */
	b->state = HFI2_DMS_SDMA_BATCH_HELD;
	list_add_tail(&b->link, &dms->sdma_held);

	return b;
}

struct hfi2_dms_sdma_batch *
hfi2_dms_sdma_batch_new_nowait(struct hfi2_dms *dms, u8 port_idx)
{
	struct hfi2_dms_sdma_batch *b;

	if (WARN_ON_ONCE(!dms) ||
	    WARN_ON_ONCE(port_idx >= HFI2_DMS_MAX_PORTS) ||
	    list_empty(&dms->sdma_batch_free))
		return NULL;

	b = list_first_entry(&dms->sdma_batch_free,
			     struct hfi2_dms_sdma_batch, link);
	list_del(&b->link);
	INIT_LIST_HEAD(&b->ring);
	b->dms = dms;
	b->is_jkr = dms->chip_type == CHIP_JKR;
	b->nowait = true;
	b->port_idx = port_idx;
	b->ndesc = 0;
	b->place = 0;
	b->state = HFI2_DMS_SDMA_BATCH_HELD;
	b->done_fn = NULL;
	b->cookie = NULL;
	list_add_tail(&b->link, &dms->sdma_held);
	return b;
}

/*
 * Return an entire batch node ring to the free-list.  @head is the batch
 * handle; the caller has already unlinked @head from whatever membership
 * list (held / pending) held it.  Every node -- head and any chained
 * nodes -- goes back to the pool for reuse.
 */
static void _batch_release(struct hfi2_dms_sdma_batch *head)
{
	struct hfi2_dms_sdma_batch *n, *tmp;

	list_for_each_entry_safe(n, tmp, &head->ring, ring) {
		list_del(&n->ring);
		n->state = HFI2_DMS_SDMA_BATCH_FREE;
		list_add(&n->link, &head->dms->sdma_batch_free);
	}
	head->state = HFI2_DMS_SDMA_BATCH_FREE;
	list_add(&head->link, &head->dms->sdma_batch_free);
}

/*
 * Emit one descriptor into the batch, chaining a fresh node onto the ring
 * when the tail node fills (so a batch has no descriptor cap).  Returns the
 * written descriptor slot (so the caller can retroactively stamp SOP/EOP
 * on the first/last of a fragment that may straddle a node seam), or NULL
 * on -ENOMEM if a new node is needed and the pool cannot grow.
 */
static struct sdma_desc *_batch_put(struct hfi2_dms_sdma_batch *head,
				    dma_addr_t paddr, u32 bytes)
{
	struct hfi2_dms_sdma_batch *tail;
	struct sdma_desc *desc;

	/* Tail node is the last on the ring, or the head if the ring is empty. */
	tail = list_empty(&head->ring) ? head :
		list_last_entry(&head->ring, struct hfi2_dms_sdma_batch, ring);

	if (tail->ndesc == HFI2_DMS_SDMA_NODE_DESCS) {
		struct hfi2_dms_sdma_batch *n;

		if (head->nowait) {
			if (list_empty(&head->dms->sdma_batch_free))
				return NULL;
			n = list_first_entry(&head->dms->sdma_batch_free,
					     struct hfi2_dms_sdma_batch, link);
			list_del(&n->link);
			n->dms = head->dms;
			n->is_jkr = head->is_jkr;
			n->nowait = true;
			n->port_idx = head->port_idx;
			n->ndesc = 0;
			n->place = 0;
			n->state = HFI2_DMS_SDMA_BATCH_FREE;
			n->done_fn = head->done_fn;
			n->cookie = head->cookie;
			INIT_LIST_HEAD(&n->ring);
		} else {
			n = _node_get(head->dms, head->port_idx);
		}
		if (!n)
			return NULL;
		/* The held-batch tag is inherited if emit grows the node ring. */
		n->done_fn = head->done_fn;
		n->cookie = head->cookie;
		n->nowait = head->nowait;
		list_del_init(&n->ring);
		list_add_tail(&n->ring, &head->ring);
		tail = n;
	}

	desc = &tail->descs[tail->ndesc++];
	_desc_set(desc, paddr, bytes, tail->is_jkr);

	return desc;
}

static u32 dms_sdma_fragment_group_bytes(const struct hfi2_dms *dms,
					 u64 phys, u32 remaining)
{
	u32 group = remaining;

	if (dms->chip_type == CHIP_JKR) {
		u64 offset = phys & (PAGE_SIZE - 1);

		if (offset & (HFI2_DMS_SDMA_PAYLOAD_ALIGN - 1)) {
			group = HFI2_DMS_SDMA_PAYLOAD_ALIGN -
				(u32)(offset & (HFI2_DMS_SDMA_PAYLOAD_ALIGN - 1));
			group = min(group, remaining);
		} else {
			group = min_t(u32, remaining, PAGE_SIZE - (u32)offset);
			if (group >= HFI2_DMS_SDMA_PAYLOAD_ALIGN)
				group &= ~(HFI2_DMS_SDMA_PAYLOAD_ALIGN - 1);
		}
	}

	return min_t(u32, group, SDMA_DESC_MAX_BYTES);
}

u32 hfi2_dms_sdma_fragment_desc_count(struct hfi2_dms *dms, dma_addr_t paddr,
				      u32 len)
{
	u64 phys = paddr;
	u32 remaining = len;
	u32 count = 0;

	if (!dms)
		return 0;
	while (remaining) {
		u32 group = dms_sdma_fragment_group_bytes(dms, phys, remaining);

		phys += group;
		remaining -= group;
		count++;
	}
	return count;
}

u32 hfi2_dms_sdma_run_desc_count(const struct hfi2_dms *dms, u32 real_descs)
{
	return real_descs + _granule_pad(_granule(dms), real_descs);
}

int hfi2_dms_sdma_batch_emit(struct hfi2_dms_sdma_batch *b, dma_addr_t paddr,
			     u32 len, enum hfi2_dms_sdma_desc_type type)
{
	u32 flags = (u32)type;
	u64 sop = flags & HFI2_DMS_SDMA_DESC_TYPE_SOP;
	u64 eop = flags & HFI2_DMS_SDMA_DESC_TYPE_EOP;
	struct sdma_desc *first = NULL;
	struct sdma_desc *last = NULL;
	u64 phys = paddr;
	u32 remaining = len;

	if (WARN_ON_ONCE(!b))
		return -EINVAL;

	/* A zero-length fragment is legal and emits no descriptors. */
	if (len == 0)
		return 0;

	/*
	 * CYR has no alignment errata: a CYR descriptor moves the whole
	 * physically-contiguous fragment in one descriptor.  The caller
	 * composes packets within the hardware byte-count limit, so no split
	 * is needed here.  JKR: a single descriptor must not cross a 256B
	 * boundary unless it is a whole 256B multiple, so split @len into
	 * groups clamped to the next 256B boundary (unaligned start) or to
	 * the page end rounded down to a 256B multiple (aligned start).  A
	 * fragment is already physically contiguous, so the physical address
	 * simply advances by each group's byte count; no page-index array or
	 * page-layout assumption is needed.  Track the first/last emitted
	 * descriptor by pointer because a fragment can straddle a node seam.
	 */
	while (remaining) {
		u32 grp = dms_sdma_fragment_group_bytes(b->dms, phys, remaining);

		last = _batch_put(b, phys, grp);
		if (!last)
			return -ENOMEM;
		if (!first)
			first = last;

		phys += grp;
		remaining -= grp;
	}

	/* Stamp SOP on the fragment's first descriptor, EOP on its last. */
	if (first) {
		first->qw[1] |= sop;
		last->qw[1] |= eop;

		/*
		 * CYR routes SDMA egress by the send context's BAR index,
		 * carried in the descriptor's 2-bit SendCtxtExtension field
		 * (ctxt_bar_idx(hw_context)).  Stamp it on every EOP at emit
		 * time so each packet in a multi-packet run is covered, not
		 * just the run's final descriptor.  JKR ignores the field
		 * (its send contexts are always in BAR 0), so skip it there.
		 */
		if (eop && !b->is_jkr) {
			struct send_context *sc =
				b->dms->port_sctxts[b->port_idx];

			/*
			 * A NULL slot for a chosen port is a driver-init bug:
			 * the EOP would keep SendCtxtExtension=0 and CYR egress
			 * on a non-BAR-0 port would misroute.  WARN so it is
			 * observable; the batch is already partly placed, so
			 * continue rather than unwind mid-emit.
			 */
			if (!WARN_ON_ONCE(!sc))
				cyr_sdma_qw_set_send_ctxt_extension(last->qw,
								    sc->hw_context);
		}
	}

	return 0;
}

u32 hfi2_dms_sdma_batch_ndesc(const struct hfi2_dms_sdma_batch *b)
{
	const struct hfi2_dms_sdma_batch *n;
	u32 ndesc;

	if (!b)
		return 0;
	ndesc = b->ndesc;
	list_for_each_entry(n, &b->ring, ring)
		ndesc += n->ndesc;
	return ndesc;
}

void hfi2_dms_sdma_batch_abort(struct hfi2_dms_sdma_batch *b)
{
	if (!b || WARN_ON_ONCE(b->state != HFI2_DMS_SDMA_BATCH_HELD))
		return;

	list_del(&b->link);
	_batch_release(b);
}

bool hfi2_dms_sdma_batch_is_held(const struct hfi2_dms_sdma_batch *b)
{
	return b && b->state == HFI2_DMS_SDMA_BATCH_HELD;
}

int hfi2_dms_sdma_batch_tag(struct hfi2_dms_sdma_batch *b,
			    hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sdma_batch *n;

	if (WARN_ON_ONCE(!b || b->state != HFI2_DMS_SDMA_BATCH_HELD))
		return -EINVAL;
	if (WARN_ON_ONCE(b->done_fn &&
			 (b->done_fn != done || b->cookie != cookie)))
		return -EINVAL;

	b->done_fn = done;
	b->cookie = cookie;
	list_for_each_entry(n, &b->ring, ring) {
		if (WARN_ON_ONCE(n->done_fn &&
				 (n->done_fn != done || n->cookie != cookie)))
			return -EINVAL;
		n->done_fn = done;
		n->cookie = cookie;
	}
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Completion FIFO.                                                       */
/* ---------------------------------------------------------------------- */

static struct hfi2_dms_sdma_completion_fifo *
_completion_fifo_get(struct hfi2_dms *dms, u8 engine_idx,
		     struct sdma_engine *sde)
{
	struct hfi2_dms_sdma_completion_fifo *fifo;

	fifo = dms->sde_rsrcs[engine_idx].sdma_completion_fifo;
	if (fifo)
		return fifo;

	if (!sde || !sde->descq_cnt)
		return NULL;

	fifo = kzalloc_node(sizeof(*fifo), GFP_KERNEL, dms->numa_node);
	if (!fifo)
		return NULL;
	fifo->cnt = sde->descq_cnt;
	fifo->entries = kcalloc_node(fifo->cnt, sizeof(*fifo->entries),
				     GFP_KERNEL, dms->numa_node);
	if (!fifo->entries) {
		kfree(fifo);
		return NULL;
	}
	fifo->tail_ring = sde->descq_tail;
	fifo->tail_seq = sde->descq_cnt;
	dms->sde_rsrcs[engine_idx].sdma_completion_fifo = fifo;
	return fifo;
}

static int _completion_fifo_setup(struct hfi2_dms *dms, u8 engine_idx,
				  struct sdma_engine *sde)
{
	struct hfi2_dms_sdma_completion_fifo *fifo;
	int ret = -ENOMEM;

	if (!sde || !sde->descq_cnt) {
		ret = -EINVAL;
		goto fail;
	}

	fifo = kzalloc_node(sizeof(*fifo), GFP_KERNEL, dms->numa_node);
	if (!fifo)
		goto fail;

	fifo->cnt = sde->descq_cnt;
	fifo->entries = kcalloc_node(fifo->cnt, sizeof(*fifo->entries),
				     GFP_KERNEL, dms->numa_node);
	if (!fifo->entries) {
		kfree(fifo);
		goto fail;
	}

	fifo->tail_ring = sde->descq_tail;
	fifo->tail_seq = sde->descq_cnt;
	dms->sde_rsrcs[engine_idx].sdma_completion_fifo = fifo;
	dms->allocation_stats.sdma_completion_fifo_setup_allocs++;
	dms->allocation_stats.sdma_completion_fifo_engine_allocs[engine_idx]++;
	return 0;

fail:
	dms->allocation_stats.sdma_completion_fifo_setup_failures++;
	dms->allocation_stats.sdma_completion_fifo_engine_failures[engine_idx]++;
	return ret;
}

/*
 * Resync @fifo->tail_seq to the engine's current ring tail and return it.
 *
 * WHY SEQUENCES INSTEAD OF RING INDICES.  The previous design anchored a
 * completion at a ring INDEX and retired it with a position test: "is this
 * index outside the occupied region (head, tail]?".  A ring index repeats
 * every descq_cnt descriptors, so that test cannot distinguish "not yet
 * egressed" from "egressed a whole lap ago".  Once a single poll pass places
 * enough descriptors to lap the ring, placement re-buries the oldest anchor
 * before it can retire; retirement is in order, so the entire FIFO stalls
 * while placement keeps pushing, until nr hits cnt, completions are dropped,
 * the ULP's txreqs are never freed and the netdev queue times out.  This was
 * masked while every packet was padded to 32 descriptors (64 packets/pass ==
 * exactly one lap); with real 3-4 descriptor packets a 256-packet pass fills
 * half the ring and two passes lap it.
 *
 * A monotonic descriptor count never repeats, so the comparison is exact.
 * The tail sequence is not simply "the number of descriptors we wrote": the
 * DMS injector places its own descriptors on the same loaned engine without
 * passing through this layer.  Deriving the delta from the observed ring tail
 * instead accounts for those too.
 */
static u64 _seq_tail(struct hfi2_dms_sdma_completion_fifo *fifo,
		     struct sdma_engine *sde)
{
	u32 mask = sde->descq_cnt - 1;	/* descq_cnt is a power of two */
	u32 ring = sde->descq_tail;

	fifo->tail_seq += (ring - fifo->tail_ring) & mask;
	fifo->tail_ring = ring;

	return fifo->tail_seq;
}

/*
 * The engine's head expressed on the same monotonic scale.
 *
 * The occupied span (head_ring, tail_ring] is always shorter than the ring --
 * placement is gated on free space -- so the modulo distance from head to
 * tail is unambiguous, and head_seq = tail_seq - that distance.
 */
static u64 _seq_head(struct hfi2_dms_sdma_completion_fifo *fifo,
		     struct sdma_engine *sde)
{
	u32 mask = sde->descq_cnt - 1;	/* descq_cnt is a power of two */
	u64 tail_seq = _seq_tail(fifo, sde);
	u32 inflight = (fifo->tail_ring - READ_ONCE(sde->descq_head)) & mask;

	return tail_seq - inflight;
}

/*
 * Shared engines (lanes > 1, dms->sde_share set): other lanes place on the
 * same ring, so the ring tail no longer advances only for this DMS and a
 * tail delta can exceed one lap between two looks.  The engine's shared
 * placed-descriptor count is the sequence there, kept in step by
 * _tail_publish().  Callers hold hfi2_dms_sde_lock().
 */
static u64 _seq_tail_dms(struct hfi2_dms *dms, u8 engine_idx,
			 struct hfi2_dms_sdma_completion_fifo *fifo,
			 struct sdma_engine *sde)
{
	if (dms->sde_share)
		return dms->sde_share[engine_idx].seq;
	return _seq_tail(fifo, sde);
}

static u64 _seq_head_dms(struct hfi2_dms *dms, u8 engine_idx,
			 struct hfi2_dms_sdma_completion_fifo *fifo,
			 struct sdma_engine *sde)
{
	if (!dms->sde_share)
		return _seq_head(fifo, sde);
	return hfi2_dms_sde_head_seq(dms, engine_idx, sde->descq_tail,
				     READ_ONCE(sde->descq_head),
				     sde->descq_cnt);
}

/* Advance the ring tail (not the CSR) to @tail; see _seq_tail_dms(). */
static void _tail_publish(struct hfi2_dms *dms, u8 engine_idx,
			  struct sdma_engine *sde, u32 tail)
{
	if (dms->sde_share)
		hfi2_dms_sde_seq_advance(dms, engine_idx, sde->descq_tail, tail,
					 sde->descq_cnt);
	sde->descq_tail = tail;
}

/*
 * Shared engines count every lane's descriptors: the shared sequence is the
 * engine's, not this DMS's.  Callers hold hfi2_dms_sde_lock().
 */
static void _ring_residency_refresh(struct hfi2_dms *dms, u8 engine_idx,
				    struct hfi2_dms_sdma_completion_fifo *fifo,
				    struct sdma_engine *sde, u64 head_seq)
{
	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];
	u64 tail_seq = _seq_tail_dms(dms, engine_idx, fifo, sde);
	u64 resident = tail_seq - head_seq;

	if (WARN_ON_ONCE(resident >= sde->descq_cnt)) {
		rsrc->ring_resident_current = 0;
		return;
	}

	rsrc->ring_resident_current = resident;
	if (rsrc->ring_resident_high_water < resident)
		rsrc->ring_resident_high_water = resident;
}

/* Returns false if the FIFO is full; see the invariant in its struct doc. */
static u32 _completion_poll(struct hfi2_dms *dms, u8 engine_idx);

static bool
_completion_push(struct hfi2_dms_sdma_completion_fifo *fifo,
		 hfi2_dms_sdma_done_fn done, void *cookie,
		 u64 anchor_seq)
{
	struct hfi2_dms_sdma_completion *slot;

	if (WARN_ON_ONCE(fifo->nr >= fifo->cnt))
		return false;

	slot = &fifo->entries[(fifo->head + fifo->nr) % fifo->cnt];
	slot->done_fn = done;
	slot->cookie = cookie;
	slot->anchor_seq = anchor_seq;
	slot->status = 0;
	fifo->nr++;

	return true;
}

/* ---------------------------------------------------------------------- */
/* Commit: place the batch into the HW ring + doorbell.                   */
/* ---------------------------------------------------------------------- */

static bool _engine_teardown_active(struct hfi2_dms *dms, u8 engine_idx)
{
	if (engine_idx >= dms->num_engines)
		return false;

	return dms->sde_rsrcs[engine_idx].sdma_teardown_active;
}

/* Write one descriptor (qw pair) into the ring at *@tail and wrap. */
static void _ring_put(struct sdma_engine *sde, u32 *tail,
		      u64 qw0, u64 qw1)
{
	sde->descq[*tail].qw[0] = cpu_to_le64(qw0);
	sde->descq[*tail].qw[1] = cpu_to_le64(qw1);
	if (++(*tail) == sde->descq_cnt)
		*tail = 0;
}

/*
 * The open run: descriptors desc_place() has placed but not yet padded.  With
 * shared engines it is the engine's, not this DMS's, so whichever lane next
 * appends to the ring or writes its tail CSR pads it first.  Callers hold
 * hfi2_dms_sde_lock().
 */
static u32 *_run_descs(struct hfi2_dms *dms, u8 engine_idx)
{
	if (dms->sde_share)
		return &dms->sde_share[engine_idx].run_descs;
	return &dms->sde_rsrcs[engine_idx].sdma_run_descs;
}

/*
 * A pad must sit inside a packet, so it goes before the run's final EOP.
 * Nothing is appended behind an open run before it is padded, so that EOP
 * is the last descriptor in the ring, and the slots were reserved by
 * desc_place().
 */
static void _pad_run_to_granule(struct hfi2_dms *dms, u8 engine_idx,
				struct sdma_engine *sde)
{
	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];
	u32 *run = _run_descs(dms, engine_idx);
	const u32 gran = _granule(dms);
	u32 pad, tail, last;
	u64 save_qw0, save_qw1;
	struct sdma_desc z;

	if (!gran || !*run)
		return;

	/* A shared engine's run may be another lane's. */
	if (WARN_ON_ONCE(!dms->sde_share && !rsrc->sdma_doorbell_pending)) {
		*run = 0;
		return;
	}

	pad = _granule_pad(gran, *run);
	*run = 0;
	if (!pad)
		return;

	if (WARN_ON_ONCE(sde->descq_cnt % gran))
		return;

	tail = sde->descq_tail;
	last = (tail == 0 ? sde->descq_cnt : tail) - 1;
	save_qw0 = sde->descq[last].qw[0];
	save_qw1 = sde->descq[last].qw[1];
	tail = last;

	_desc_set(&z, dms->zero_page.phys_addr, 0,
		  dms->chip_type == CHIP_JKR);
	while (pad--)
		_ring_put(sde, &tail, z.qw[0], 0);
	_ring_put(sde, &tail, save_qw0, save_qw1);
	_tail_publish(dms, engine_idx, sde, tail);
}

/*
 * Node walk: the descriptors of a batch are spread across its node ring
 * (head node, then each chained node in @ring order).  These helpers walk
 * that logical sequence.  A batch's drain cursor is (node, node->place):
 * node->place counts descriptors of THIS node already copied to the ring,
 * so a batch resumes mid-list across poll passes.
 */

/* First node of a batch = the head. */
static struct hfi2_dms_sdma_batch *
_node_first(struct hfi2_dms_sdma_batch *head)
{
	return head;
}

/* Next node after @n within batch @head, or NULL at the end. */
static struct hfi2_dms_sdma_batch *
_node_next(struct hfi2_dms_sdma_batch *head, struct hfi2_dms_sdma_batch *n)
{
	if (list_empty(&head->ring))
		return NULL;			/* single-node batch */
	if (n == head)
		return list_first_entry(&head->ring,
					struct hfi2_dms_sdma_batch, ring);
	if (list_is_last(&n->ring, &head->ring))
		return NULL;
	return list_next_entry(n, ring);
}

/*
 * Drain as many whole packets of batch @head as fit the engine's ring,
 * resuming from the batch's saved cursor.  Copies real descriptors into
 * the ring, applies the platform's doorbell-run pad (granule from
 * dd->pad_sdma_desc; 32 on AMD, 0 on Intel) to each drained run's final
 * packet, stamps HEAD_TO_HOST + Last on the run's physically-final
 * descriptor (re-stamping CYR SendCtxtExtension there too when padding
 * relocated Last onto a zero pad descriptor), and advances the doorbell
 * iff at least one whole packet was placed.
 *
 * Returns 1 when the batch is fully drained; the caller records a success
 * completion and recycles it.  The existing error path also returns 1 if
 * earlier packets were placed but the next packet can never fit the ring:
 * the unplaced remainder is discarded and the completion reports success.
 * Current callers submit one packet or repeat identical packet geometry.
 * Mixed-size error propagation is tracked in wfr-linux-devel issue #1064.
 * Returns 0 on temporary ring pressure; the batch stays pending and resumes
 * next poll.  Returns -E2BIG for a permanently oversized packet when none
 * of the batch was placed; the caller fails it immediately.  The run pad
 * follows the final real descriptor, with Last relocated onto the final
 * pad, so padding never splits a packet's descriptor sequence.
 *
 * *@doorbelled is set true if this call advanced the ring tail past >= 1
 * whole packet (so the caller rings the doorbell once for the whole poll).
 */
/*
 * Logical descriptor cursor within a batch's node list: (node, off).
 * Walking it in order visits the batch's descriptors head-node-first, then
 * each chained node.  A NULL node means end-of-batch.
 */
struct _cursor {
	struct hfi2_dms_sdma_batch *node;
	u32 off;
};

/* Advance a cursor by one descriptor, crossing node seams. */
static void _cursor_inc(struct hfi2_dms_sdma_batch *head, struct _cursor *c)
{
	if (++c->off == c->node->ndesc) {
		c->node = _node_next(head, c->node);
		c->off = 0;
	}
}

/* The descriptor a cursor points at. */
static struct sdma_desc *_cursor_desc(struct _cursor *c)
{
	return &c->node->descs[c->off];
}

/*
 * Free descriptors in the ring, measured from the caller's in-progress tail.
 *
 * sdma_descq_freecnt() reads sde->descq_tail, but _drain_pending() advances a
 * LOCAL tail across the batches of one pass and publishes it to the struct only
 * once, after the loop.  Every batch after the first would therefore be told the
 * ring still had the free space it had at the start of the pass, and placement
 * would eventually lap descq_head and overwrite descriptors the engine had not
 * yet read -- the engine then fetches a run whose byte counts no longer match
 * the PBC it already has, and halts with SDMA_LENGTH_MISMATCH_ERR.
 *
 * Measure from @tail instead, so each batch sees the space left by its
 * predecessors in the same pass.  descq_head is only refreshed once per pass
 * (in _completion_poll), so this stays conservative: a stale head can only make
 * the count read lower, never higher.
 */
static u32 _ring_freecnt(struct sdma_engine *sde, u32 tail)
{
	u32 mask = sde->descq_cnt - 1;
	u32 inprocess = (sde->descq_cnt + tail - READ_ONCE(sde->descq_head)) &
			mask;

	return sde->descq_cnt - 1 - inprocess;
}

static int _drain_batch(struct sdma_engine *sde,
			struct hfi2_dms_sdma_batch *head, u64 zero_qw0,
			bool is_jkr, u32 gran, u32 *tail, bool *doorbelled)
{
	u32 freecnt = _ring_freecnt(sde, *tail);
	struct _cursor cur;		/* resume point (first undrained desc) */
	struct _cursor scan;		/* whole-packet scan cursor */
	struct _cursor eop;		/* final EOP of the accepted prefix */
	u32 run_real = 0;		/* real descs in the accepted prefix */
	u32 pkt_real = 0;		/* real descs in the packet being scanned */
	bool have_prefix = false;
	bool placed_any;
	bool run_padded;
	u32 pad;

	/* Resume at the first node with descriptors still to place. */
	cur.node = _node_first(head);
	while (cur.node && cur.node->place == cur.node->ndesc)
		cur.node = _node_next(head, cur.node);
	if (!cur.node)
		return 1;		/* nothing left (shouldn't happen) */
	cur.off = cur.node->place;
	/*
	 * Earlier packets of this batch already in the ring still reference
	 * its buffers, so only a batch with nothing placed can be failed and
	 * completed at once.
	 */
	placed_any = cur.node != _node_first(head) || cur.off;

	/*
	 * PHASE 1 -- accept the largest whole-packet prefix whose padded
	 * RUN footprint fits the ring.  The granule applies to the whole
	 * doorbell run, not per packet, so pad is computed once over the
	 * accepted prefix's real-descriptor count.  Because pad (< gran)
	 * only ever grows the footprint by up to gran-1, we test fit
	 * against roundup(run_real + pkt, gran) as each candidate packet is
	 * added.  A zero granule (the Intel default) pads nothing.
	 */
	scan = cur;
	while (scan.node) {
		bool is_eop;
		u32 cand_real;
		u32 cand_run;

		pkt_real++;
		is_eop = is_jkr ?
			jkr_sdma_qw_get_last_desc((u64 *)&_cursor_desc(&scan)->qw[0]) :
			cyr_sdma_qw_get_last_desc((u64 *)&_cursor_desc(&scan)->qw[0]);

		if (!is_eop) {
			_cursor_inc(head, &scan);
			continue;
		}

		/* Candidate prefix = accepted prefix + this whole packet. */
		cand_real = run_real + pkt_real;
		cand_run = cand_real + _granule_pad(gran, cand_real);

		/*
		 * A single packet whose padded run cannot fit the usable ring
		 * can never be placed -- fail the batch rather than wedge the
		 * pending list forever, or drop the rest of a batch whose
		 * earlier packets are already in the ring.
		 */
		if (!have_prefix &&
		    WARN_ON_ONCE(cand_run > sde->descq_cnt - 1))
			return placed_any ? 1 : -E2BIG;

		if (cand_run > freecnt)
			break;		/* this packet does not fit; stop */

		/* Accept this packet into the prefix. */
		run_real = cand_real;
		eop = scan;		/* remember the accepted final EOP */
		have_prefix = true;
		pkt_real = 0;
		_cursor_inc(head, &scan);
	}

	/* Not even one whole packet fits (or none complete yet): defer. */
	if (!have_prefix)
		return 0;

	pad = _granule_pad(gran, run_real);
	run_padded = pad != 0;

	/*
	 * PHASE 2 -- copy the accepted prefix into the ring verbatim, then
	 * relocate the run's terminal EOP onto the pad tail.  A pad descriptor
	 * is only legal interior to a packet (SOP..EOP), never between packets,
	 * so the pad cannot follow the run's final EOP.  Instead: write every
	 * real descriptor as authored (interior packet EOPs untouched), clear
	 * Last on the run's final descriptor, append the pad, and let the stamp
	 * block below set Last + HEAD_TO_HOST on the final pad.  This is packet-
	 * type agnostic: multi-descriptor data, lone SOP_EOP, and any packet
	 * whose final descriptors must stay contiguous all pad the same way, and
	 * the pad never splits a packet's descriptor sequence.
	 */
	{
		struct _cursor c = cur;
		bool at_eop;

		for (;;) {
			struct sdma_desc *d = _cursor_desc(&c);

			at_eop = (c.node == eop.node && c.off == eop.off);

			if (at_eop && pad) {
				struct sdma_desc r = *d;

				if (is_jkr)
					jkr_sdma_qw_clear_last_desc(&r.qw[0]);
				else
					cyr_sdma_qw_clear_last_desc(&r.qw[0]);
				_ring_put(sde, tail, r.qw[0], r.qw[1]);
				while (pad) {
					_ring_put(sde, tail, zero_qw0, 0);
					pad--;
				}
			} else {
				_ring_put(sde, tail, d->qw[0], d->qw[1]);
			}

			c.node->place++;
			if (at_eop)
				break;
			_cursor_inc(head, &c);
		}
		WARN_ON_ONCE(pad);
	}

	*doorbelled = true;

	/*
	 * Stamp Last + HEAD_TO_HOST on the run's physically-final ring
	 * descriptor (the final pad for a padded run, else the EOP itself).
	 * *tail points one past it.  The CYR SendCtxtExtension field is
	 * stamped per EOP at emit time (hfi2_dms_sdma_batch_emit()), which
	 * is sufficient when pad==0 -- the EOP IS the physically-final
	 * descriptor.  When pad>0, LastDesc has just been relocated onto a
	 * zero pad descriptor built from @zero_qw0, which carries no
	 * SendCtxtExtension bits.  Per CYR HAS Table 7-15, HW samples
	 * SendCtxtExtension only from the descriptor carrying SdmaLastDesc,
	 * so the extension must be re-stamped on that pad descriptor here,
	 * using this batch's own port identity (JKR has no such field).
	 */
	{
		u32 last = (*tail == 0 ? sde->descq_cnt : *tail) - 1;
		u64 *qw = (u64 *)&sde->descq[last].qw[0];

		if (is_jkr) {
			jkr_sdma_qw_set_last_desc(qw);
		} else {
			cyr_sdma_qw_set_last_desc(qw);

			if (run_padded) {
				struct send_context *sc =
					head->dms->port_sctxts[head->port_idx];

				/*
				 * Mirror the emit-time NULL handling: a
				 * missing send context is a driver-init bug,
				 * so WARN and leave the extension at 0
				 * rather than unwind mid-drain.
				 */
				if (!WARN_ON_ONCE(!sc))
					cyr_sdma_qw_set_send_ctxt_extension(qw, sc->hw_context);
			}
		}
		qw[1] |= SDMA_DESC1_HEAD_TO_HOST_FLAG;
	}

	/* Fully drained iff the accepted EOP was the batch's last descriptor. */
	{
		struct _cursor nxt = eop;

		_cursor_inc(head, &nxt);
		return !nxt.node;
	}
}

int hfi2_dms_sdma_batch_commit(struct hfi2_dms_sdma_batch *b, u8 engine_idx,
			       hfi2_dms_sdma_done_fn done, void *cookie)
{
	int ret;

	if (WARN_ON_ONCE(!b))
		return -EINVAL;

	if (WARN_ON_ONCE(engine_idx >= b->dms->num_engines)) {
		ret = -EINVAL;
		goto out_free;
	}

	/* A batch with no descriptors is a caller bug; discard it. */
	if (!b->ndesc) {
		ret = -EINVAL;
		goto out_free;
	}

	if (_engine_teardown_active(b->dms, engine_idx)) {
		ret = -ESHUTDOWN;
		goto out_free;
	}

	/*
	 * Stamp the completion identity on the TAIL node -- it holds the
	 * batch's final descriptor, so drain copies {done,cookie} into the
	 * per-engine completion FIFO exactly when that descriptor lands in
	 * the ring.  Splice the batch's whole node ring onto the engine's
	 * pending list (O(1) relink, no descriptor copy); the poll step
	 * drains it packet-by-packet as ring space allows.
	 */
	{
		struct hfi2_dms_sdma_batch *tail = list_empty(&b->ring) ? b :
			list_last_entry(&b->ring, struct hfi2_dms_sdma_batch,
						ring);
		struct list_head *pending =
			&b->dms->sde_rsrcs[engine_idx].sdma_pending;

		ret = hfi2_dms_sdma_batch_tag(b, done, cookie);
		if (ret)
			goto out_free;
		WARN_ON_ONCE(tail->done_fn != done || tail->cookie != cookie);

		list_del(&b->link);			/* off the held list */
		b->state = HFI2_DMS_SDMA_BATCH_PENDING;
		list_add_tail(&b->link, pending);	/* onto engine pending */
	}

	return 0;

out_free:
	list_del(&b->link);
	_batch_release(b);
	return ret;
}

/* ---------------------------------------------------------------------- */
/* Poll step: fire completions for egressed commits.                      */
/* ---------------------------------------------------------------------- */

static u32 _completion_poll(struct hfi2_dms *dms, u8 engine_idx)
{
	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];
	struct hfi2_dms_sdma_completion_fifo *fifo;
	struct sdma_engine *sde;
	u64 head_seq;
	u32 fired = 0;

	fifo = rsrc->sdma_completion_fifo;
	if (!fifo || !fifo->nr)
		return 0;

	sde = dms->sdma_engines[engine_idx];
	if (WARN_ON_ONCE(!sde))
		return 0;

	/* sdma_gethead_dma() ends in its own smp_wmb(); we add none. */
	hfi2_dms_sde_lock(dms, engine_idx);
	sdma_gethead_dma(sde);
	head_seq = _seq_head_dms(dms, engine_idx, fifo, sde);
	_ring_residency_refresh(dms, engine_idx, fifo, sde, head_seq);
	hfi2_dms_sde_unlock(dms, engine_idx);

	while (fifo->nr) {
		struct hfi2_dms_sdma_completion *slot =
			&fifo->entries[fifo->head];

		if (head_seq < slot->anchor_seq)
			break;	/* oldest not yet egressed -> FIFO-stop */

		{
			hfi2_dms_sdma_done_fn done = slot->done_fn;
			void *cookie = slot->cookie;
			int status = slot->status;

			fifo->head = (fifo->head + 1) % fifo->cnt;
			fifo->nr--;
			fired++;
			if (done)
				done(cookie, status);
		}
	}

	return fired;
}

/*
 * Error-complete every outstanding commit on @engine_idx with @status<0
 * (no egress test -- the engine is known halted).  This sweeps BOTH:
 *
 *   - the pending batch list: committed-but-not-yet-fully-drained batches
 *     whose descriptors never reached the ring.  Fire the tail node's
 *     completion and recycle the whole node ring.
 *
 *   - the completion FIFO: batches already placed and awaiting egress.
 *
 * When @free is set (teardown) the FIFO itself is freed.  Returns the
 * number of completions fired.
 */
static u32 _error_complete(struct hfi2_dms *dms, u8 engine_idx, int status,
			   bool free)
{
	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];
	struct hfi2_dms_sdma_completion_fifo *fifo;
	struct hfi2_dms_sdma_batch *head, *tmp;
	u32 fired = 0;

	/* The engine is halted; detach every pending batch before callbacks. */
	{
		LIST_HEAD(error_pending);

		list_splice_init(&rsrc->sdma_pending, &error_pending);
		list_for_each_entry_safe(head, tmp, &error_pending, link) {
			struct hfi2_dms_sdma_batch *tnode = list_empty(&head->ring) ?
				head : list_last_entry(&head->ring,
						       struct hfi2_dms_sdma_batch, ring);
			hfi2_dms_sdma_done_fn done = tnode->done_fn;
			void *cookie = tnode->cookie;

			list_del(&head->link);
			_batch_release(head);
			fired++;
			if (done)
				done(cookie, status);
		}
	}

	fifo = rsrc->sdma_completion_fifo;
	if (!fifo)
		return fired;

	while (fifo->nr) {
		struct hfi2_dms_sdma_completion *slot =
			&fifo->entries[fifo->head];
		hfi2_dms_sdma_done_fn done = slot->done_fn;
		void *cookie = slot->cookie;

		fifo->head = (fifo->head + 1) % fifo->cnt;
		fifo->nr--;
		fired++;
		if (done)
			done(cookie, status);
	}

	if (free) {
		kfree(fifo->entries);
		kfree(fifo);
		rsrc->sdma_completion_fifo = NULL;
	}

	return fired;
}

/*
 * Drain the engine's pending batch list into the HW ring, oldest first,
 * one whole packet at a time as ring space allows.  A batch that fully
 * drains this pass has its completion recorded (tail node's {done,cookie}
 * anchored on the monotonic descriptor sequence one past its final
 * descriptor -- see _seq_head) and is returned to the pool; a
 * partially-drained batch stays at the head of the pending list and
 * resumes next poll.  The doorbell is rung once, at
 * the end, iff at least one whole packet was placed.
 */
static void _drain_pending(struct hfi2_dms *dms, u8 engine_idx,
			   struct sdma_engine *sde)
{
	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];
	struct hfi2_dms_sdma_completion_fifo *fifo;
	bool is_jkr = dms->chip_type == CHIP_JKR;
	u32 gran = _granule(dms);
	bool doorbelled = false;
	u64 base_seq;
	u32 base_tail;
	u32 tail;
	u64 zero_qw0;

	if (list_empty(&rsrc->sdma_pending))
		return;

	fifo = _completion_fifo_get(dms, engine_idx, sde);
	if (!fifo)
		return;

	/* Pre-build a zero-length pad descriptor's qw[0] (byte_count 0). */
	{
		struct sdma_desc z;

		_desc_set(&z, dms->zero_page.phys_addr, 0, is_jkr);
		zero_qw0 = z.qw[0];
	}

	/*
	 * Snapshot the monotonic descriptor sequence the ring tail currently
	 * stands at.  A batch's completion anchor is that base plus the
	 * descriptors placed ahead of it in this pass -- exact, and immune to
	 * the ring-index wrap that a position test cannot see (see _seq_head).
	 *
	 * Each anchor's ring delta, (tail - base_tail), is masked with
	 * (descq_cnt - 1), but the mask is a no-op here by construction: the
	 * engine's head is frozen for this entire pass (it is only advanced by
	 * _completion_poll(), which the caller runs BEFORE _drain_pending), and
	 * _ring_freecnt() upper-bounds each batch's accepted run below the ring
	 * depth, so the UNMASKED (tail - base_tail) accumulated across the pass
	 * is always < descq_cnt and never wraps. Do not reorder drain relative
	 * to completion-polling without revisiting this invariant.  With shared
	 * engines the lock held for the pass keeps other lanes from moving the
	 * head or tail meanwhile, and the head is refreshed here: hfi2_dms_poll()
	 * only refreshes it for a lane with header sets in flight, and
	 * _completion_poll() only with completions pending, so a lane whose
	 * first batch is still partially placed would otherwise never see the
	 * ring drain.
	 */
	hfi2_dms_sde_lock(dms, engine_idx);
	/* Batches go behind the open run, so its pad must be emitted first. */
	_pad_run_to_granule(dms, engine_idx, sde);
	if (dms->sde_share)
		sdma_gethead_dma(sde);
	base_seq = _seq_tail_dms(dms, engine_idx, fifo, sde);
	base_tail = sde->descq_tail;
	tail = base_tail;

	/*
	 * Oldest-first: successful completions stay in commit order on this
	 * engine, and a partially-placed batch blocks later ones.  Rejected
	 * never-placed batches are error-completed immediately and can
	 * overtake earlier successes still waiting in the completion FIFO.
	 * Stop at the first batch that cannot fully drain this pass.
	 */
	while (!list_empty(&rsrc->sdma_pending)) {
		struct hfi2_dms_sdma_batch *head =
			list_first_entry(&rsrc->sdma_pending,
					 struct hfi2_dms_sdma_batch, link);
		struct hfi2_dms_sdma_batch *tnode;
		int drain;

		drain = _drain_batch(sde, head, zero_qw0, is_jkr, gran, &tail,
				     &doorbelled);
		if (drain < 0) {
			/*
			 * A packet larger than the usable ring can never
			 * drain.  None of it reached the ring, so complete
			 * the owner once with the error rather than
			 * reporting success.  Commit stamped the completion
			 * identity on the tail node, as for teardown.
			 */
			tnode = list_empty(&head->ring) ? head :
				list_last_entry(&head->ring,
						struct hfi2_dms_sdma_batch,
						ring);
			if (tnode->done_fn)
				tnode->done_fn(tnode->cookie, drain);
			list_del(&head->link);
			_batch_release(head);
			continue;
		}
		if (!drain)
			break;	/* ring full mid-batch; resume next poll */

		/*
		 * Fully drained: the tail node's completion identity is now
		 * anchored one descriptor past this batch's final descriptor.
		 * Record it, unlink, recycle.
		 */
		tnode = list_empty(&head->ring) ? head :
			list_last_entry(&head->ring,
					struct hfi2_dms_sdma_batch, ring);
		/* Already in the ring: nothing to back out to, so just WARN. */
		(void)_completion_push(fifo, tnode->done_fn, tnode->cookie,
				       base_seq +
				       ((tail - base_tail) &
					(sde->descq_cnt - 1)));

		list_del(&head->link);
		_batch_release(head);
	}

	if (doorbelled) {
		/*
		 * This tail also covers anything desc_place() left unpublished
		 * on this engine, so do not ring twice.
		 */
		u64 head_seq;

		_tail_publish(dms, engine_idx, sde, tail);
		smp_wmb(); /* order desc writes before the tail-CSR update */
		writeq(sde->descq_tail, sde->tail_csr);
		rsrc->sdma_doorbell_pending = false;
		head_seq = _seq_head_dms(dms, engine_idx, fifo, sde);
		_ring_residency_refresh(dms, engine_idx, fifo, sde, head_seq);
	}
	hfi2_dms_sde_unlock(dms, engine_idx);
}

u32 hfi2_dms_sdma_drain_and_complete(struct hfi2_dms *dms, u8 engine_idx)
{
	struct sdma_engine *sde;
	u32 fired;

	struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[engine_idx];

	if (rsrc->sdma_teardown_active)
		return 0;

	/*
	 * Shared engines: skip an engine this lane has nothing queued or in
	 * flight on, so a poll pass does not touch the engine state other
	 * lanes are writing.  The running check below still runs before this
	 * lane places anything on the engine.
	 */
	if (dms->sde_share && list_empty(&rsrc->sdma_pending) &&
	    (!rsrc->sdma_completion_fifo || !rsrc->sdma_completion_fifo->nr))
		return 0;

	/*
	 * A DMS-loaned engine can be halted asynchronously by the SDMA error
	 * IRQ (hfi2_sdma_engine_error() in sdma.c), which sets no state in this
	 * layer -- this poll step is the only observer.  If it is not
	 * running, error-complete every outstanding commit (status<0) and
	 * gate new placement rather than firing clean completions.
	 */
	sde = dms->sdma_engines[engine_idx];
	if (WARN_ON_ONCE(!sde))
		return 0;

	if (!__sdma_running(sde)) {
		dms->sde_rsrcs[engine_idx].sdma_teardown_active = true;
		return _error_complete(dms, engine_idx, -ESHUTDOWN, false);
	}

	/*
	 * Retire first, then place.
	 *
	 * Completion anchors are monotonic descriptor sequence numbers, so
	 * retirement is order-exact and no longer depends on this ordering for
	 * correctness (see _seq_head()).  The order is still worth keeping:
	 * retiring first frees ring space and ULP transmit slots before this
	 * pass tries to use them, and packets placed by this pass cannot have
	 * egressed yet, so examining them now would find nothing.
	 */
	fired = _completion_poll(dms, engine_idx);

	/* Place as many pending packets as now fit. */
	_drain_pending(dms, engine_idx, sde);

	return fired;
}

/* ---------------------------------------------------------------------- */
/* One-shot submit wrappers.                                              */
/* ---------------------------------------------------------------------- */

int hfi2_dms_sdma_frag_submit(struct hfi2_dms *dms, u8 engine_idx,
			      u8 port_idx,
			      const struct hfi2_dms_sdma_frag *frags,
			      u32 nfrags, hfi2_dms_sdma_done_fn done,
			      void *cookie)
{
	struct hfi2_dms_sdma_batch *b;
	u32 i;
	int ret;

	if (WARN_ON_ONCE(!frags || !nfrags))
		return -EINVAL;

	b = hfi2_dms_sdma_batch_new(dms, port_idx);
	if (!b)
		return -ENOMEM;

	for (i = 0; i < nfrags; i++) {
		ret = hfi2_dms_sdma_batch_emit(b, frags[i].paddr, frags[i].len,
					       frags[i].type);
		if (ret) {
			hfi2_dms_sdma_batch_abort(b);
			return ret;
		}
	}

	return hfi2_dms_sdma_batch_commit(b, engine_idx, done, cookie);
}

/*
 * See dms_sdma.h for the contract.  No generation fixup is needed here:
 * _submit_tx() ORs a generation counter into qw[1] because ordinary engines
 * validate it, but hfi2_dms_common_init() calls hfi2_sdma_disable_gen_check() on
 * every engine DMS loans.
 */
int hfi2_dms_sdma_desc_place(struct hfi2_dms *dms, u8 engine_idx,
			     const struct sdma_desc *descs, u32 ndesc,
			     hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sde_rsrc *rsrc;
	struct hfi2_dms_sdma_completion_fifo *fifo;
	struct sdma_engine *sde;
	u32 gran, npad;
	u32 *run;
	u32 tail;
	u32 i;

	if (WARN_ON_ONCE(!dms || !descs || !ndesc ||
			 engine_idx >= dms->num_engines))
		return -EINVAL;

	rsrc = &dms->sde_rsrcs[engine_idx];
	if (rsrc->sdma_teardown_active)
		return -ESHUTDOWN;

	/* Jumping ahead of queued batches would egress out of commit order. */
	if (unlikely(!list_empty(&rsrc->sdma_pending)))
		return -EAGAIN;

	sde = dms->sdma_engines[engine_idx];
	if (WARN_ON_ONCE(!sde))
		return -EINVAL;

	fifo = _completion_fifo_get(dms, engine_idx, sde);
	if (!fifo)
		return -ENOMEM;

	/*
	 * Refuse while the FIFO is full even when @done is NULL: the anchor
	 * that will cover this packet needs a slot too, and after the first
	 * _ring_put() there is no backing out.
	 */
	if (unlikely(fifo->nr >= fifo->cnt))
		return -EAGAIN;

	hfi2_dms_sde_lock(dms, engine_idx);
	/* Reserve the pad this packet would owe if it closed the run. */
	run = _run_descs(dms, engine_idx);
	gran = _granule(dms);
	npad = _granule_pad(gran, *run + ndesc);

	tail = sde->descq_tail;
	if (ndesc + npad > _ring_freecnt(sde, tail)) {
		/*
		 * The head is refreshed once per poll pass, so a "full" ring is
		 * usually a stale head.  Re-read it, as _sdma_engine_acquire().
		 */
		sdma_gethead_dma(sde);
		if (ndesc + npad > _ring_freecnt(sde, tail)) {
			hfi2_dms_sde_unlock(dms, engine_idx);
			return -EAGAIN;
		}
	}

	/* Completion watches the DMA'd head, so the EOP must write it back. */
	for (i = 0; i < ndesc; i++) {
		bool last = (i == ndesc - 1);

		_ring_put(sde, &tail, descs[i].qw[0],
			  last ? (descs[i].qw[1] | SDMA_DESC1_HEAD_TO_HOST_FLAG)
			       : descs[i].qw[1]);
	}
	*run += ndesc;

	/*
	 * Anchor the completion one descriptor past this packet.  The tail CSR
	 * is left for the flush, but any earlier tail write on this engine (the
	 * DMS injector, a drain, or another lane sharing the engine, which pads
	 * the run first) starts the packet sooner; it is complete in the ring,
	 * so that is harmless.  A pad inserted later goes before the run's last
	 * EOP, and the head only moves at EOPs, so the anchor still retires
	 * with that EOP.
	 */
	_tail_publish(dms, engine_idx, sde, tail);
	if (done)
		/* Cannot fail: room was checked above. */
		_completion_push(fifo, done, cookie,
				 _seq_tail_dms(dms, engine_idx, fifo, sde));
	else
		/* keep the sequence in step */
		_seq_tail_dms(dms, engine_idx, fifo, sde);
	hfi2_dms_sde_unlock(dms, engine_idx);
	rsrc->sdma_doorbell_pending = true;

	return 0;
}

/*
 * Record one completion against everything placed on @engine_idx so far.  The
 * anchor is the engine's current tail, so it retires only once every descriptor
 * placed before it has egressed.  On -EAGAIN nothing is recorded and the
 * caller still owns those packets' completion.
 */
int hfi2_dms_sdma_anchor(struct hfi2_dms *dms, u8 engine_idx,
			 hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sdma_completion_fifo *fifo;
	struct sdma_engine *sde;

	if (WARN_ON_ONCE(!dms || !done || engine_idx >= dms->num_engines))
		return -EINVAL;

	sde = dms->sdma_engines[engine_idx];
	if (WARN_ON_ONCE(!sde))
		return -EINVAL;

	fifo = _completion_fifo_get(dms, engine_idx, sde);
	if (!fifo)
		return -ENOMEM;

	hfi2_dms_sde_lock(dms, engine_idx);
	if (!_completion_push(fifo, done, cookie,
			      _seq_tail_dms(dms, engine_idx, fifo, sde))) {
		hfi2_dms_sde_unlock(dms, engine_idx);
		return -EAGAIN;
	}
	hfi2_dms_sde_unlock(dms, engine_idx);

	return 0;
}

/* See dms_sdma.h. */
void hfi2_dms_sdma_close_run(struct hfi2_dms *dms, u8 engine_idx)
{
	if (!dms->sde_share)
		return;

	lockdep_assert_held(&dms->sde_share[engine_idx].lock);
	_pad_run_to_granule(dms, engine_idx, dms->sdma_engines[engine_idx]);
}

u32 hfi2_dms_sdma_ring_resident_current(const struct hfi2_dms *dms,
					 u8 engine_idx)
{
	const struct hfi2_dms_sde_rsrc *rsrc;

	if (!dms || !dms->sde_rsrcs || engine_idx >= dms->num_engines)
		return 0;

	rsrc = &dms->sde_rsrcs[engine_idx];
	return READ_ONCE(rsrc->ring_resident_current);
}

u32 hfi2_dms_sdma_ring_resident_high_water(const struct hfi2_dms *dms,
					    u8 engine_idx)
{
	const struct hfi2_dms_sde_rsrc *rsrc;

	if (!dms || !dms->sde_rsrcs || engine_idx >= dms->num_engines)
		return 0;

	rsrc = &dms->sde_rsrcs[engine_idx];
	return READ_ONCE(rsrc->ring_resident_high_water);
}

void hfi2_dms_sdma_doorbell_all(struct hfi2_dms *dms)
{
	u32 i;

	if (WARN_ON_ONCE(!dms))
		return;

	for (i = 0; i < dms->num_engines; i++) {
		struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[i];
		struct hfi2_dms_sdma_completion_fifo *fifo;
		struct sdma_engine *sde;
		u64 head_seq;

		if (!rsrc->sdma_doorbell_pending)
			continue;

		sde = dms->sdma_engines[i];
		if (WARN_ON_ONCE(!sde)) {
			rsrc->sdma_doorbell_pending = false;
			continue;
		}
		fifo = _completion_fifo_get(dms, i, sde);
		if (!fifo)
			continue;

		hfi2_dms_sde_lock(dms, i);
		/* Pad while still pending, and before the barrier. */
		_pad_run_to_granule(dms, i, sde);
		rsrc->sdma_doorbell_pending = false;
		smp_wmb(); /* order desc writes before the tail-CSR update */
		writeq(sde->descq_tail, sde->tail_csr);
		head_seq = _seq_head_dms(dms, i, fifo, sde);
		_ring_residency_refresh(dms, i, fifo, sde, head_seq);
		hfi2_dms_sde_unlock(dms, i);
	}
}

int hfi2_dms_sdma_desc_submit(struct hfi2_dms *dms, u8 engine_idx,
			      u8 port_idx,
			      const struct sdma_desc *descs, u32 ndesc,
			      hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sdma_batch *b;
	u32 i;

	if (WARN_ON_ONCE(!descs || !ndesc))
		return -EINVAL;

	/*
	 * Advanced path: caller-built descriptors go in verbatim, with no
	 * fragment splitting and no SOP/EOP stamping (the caller already
	 * framed them).  Load them into a batch's nodes -- copying a full
	 * descriptor per slot (not just paddr/bytes), so the caller's flags
	 * are preserved -- then commit through the same node/pending path.
	 */
	b = hfi2_dms_sdma_batch_new(dms, port_idx);
	if (!b)
		return -ENOMEM;

	for (i = 0; i < ndesc; i++) {
		struct hfi2_dms_sdma_batch *tail;

		tail = list_empty(&b->ring) ? b :
			list_last_entry(&b->ring, struct hfi2_dms_sdma_batch,
					ring);

		if (tail->ndesc == HFI2_DMS_SDMA_NODE_DESCS) {
			struct hfi2_dms_sdma_batch *n = _node_get(dms,
								  b->port_idx);

			if (!n) {
				hfi2_dms_sdma_batch_abort(b);
				return -ENOMEM;
			}
			list_del_init(&n->ring);
			list_add_tail(&n->ring, &b->ring);
			tail = n;
		}

		tail->descs[tail->ndesc++] = descs[i];
	}

	return hfi2_dms_sdma_batch_commit(b, engine_idx, done, cookie);
}

/* ---------------------------------------------------------------------- */
/* Lifecycle.                                                             */
/* ---------------------------------------------------------------------- */

int hfi2_dms_sdma_setup(struct hfi2_dms *dms)
{
	u32 batch_pool;
	u32 i;

	if (WARN_ON_ONCE(!dms || !dms->sde_rsrcs || !dms->sdma_engines ||
			 !dms->num_engines))
		return -EINVAL;

	INIT_LIST_HEAD(&dms->sdma_held);
	INIT_LIST_HEAD(&dms->sdma_batch_free);

	for (i = 0; i < dms->num_engines; i++) {
		INIT_LIST_HEAD(&dms->sde_rsrcs[i].sdma_pending);
		dms->sde_rsrcs[i].sdma_completion_fifo = NULL;
		dms->sde_rsrcs[i].sdma_teardown_active = false;
		dms->sde_rsrcs[i].ring_resident_current = 0;
		dms->sde_rsrcs[i].ring_resident_high_water = 0;
		dms->sde_rsrcs[i].sdma_doorbell_pending = false;
	}

	batch_pool = HFI2_DMS_SDMA_BATCH_POOL_MIN;
	if (dms->num_engines &&
	    !_completion_fifo_get(dms, dms_reserved_engine_idx(dms),
				  dms->sdma_engines[dms_reserved_engine_idx(dms)]))
		return -ENOMEM;

	for (i = 0; i < batch_pool; i++) {
		struct hfi2_dms_sdma_batch *b;

		b = kzalloc_node(sizeof(*b), GFP_KERNEL, dms->numa_node);
		if (!b)
			break;
		dms->allocation_stats.sdma_batch_setup_allocs++;
		list_add(&b->link, &dms->sdma_batch_free);
	}

	return 0;
}

int hfi2_dms_sdma_warm_reserve(struct hfi2_dms *dms, u32 batch_nodes)
{
	struct hfi2_dms_sdma_batch *batch;
	u32 free_batches = 0;
	u32 i;
	int ret;

	if (!dms || !dms->sdma_batch_free.next)
		return -EINVAL;

	for (i = 0; i < dms->num_engines; i++) {
		if (dms->sde_rsrcs[i].sdma_completion_fifo)
			continue;
		ret = _completion_fifo_setup(dms, i, dms->sdma_engines[i]);
		if (ret)
			return ret;
	}

	list_for_each_entry(batch, &dms->sdma_batch_free, link)
		free_batches++;
	while (free_batches < batch_nodes) {
		batch = kzalloc_node(sizeof(*batch), GFP_KERNEL, dms->numa_node);
		if (!batch) {
			dms->allocation_stats.sdma_batch_setup_failures++;
			return -ENOMEM;
		}
		dms->allocation_stats.sdma_batch_setup_allocs++;
		list_add(&batch->link, &dms->sdma_batch_free);
		free_batches++;
	}

	return 0;
}

bool hfi2_dms_sdma_capacity_ready(struct hfi2_dms *dms, u32 batch_nodes,
				  u32 pages, u32 completion_slots,
				  u32 ring_descriptors)
{
	struct hfi2_dms_sdma_batch *batch;
	struct hfi2_dms_page *page;
	u32 free_batches = 0;
	u32 free_pages = 0;
	u32 i;

	if (!dms || !dms->num_engines || !dms->sde_rsrcs || !dms->sdma_engines ||
	    !dms->sdma_batch_free.next || !dms->dms_pages.free.next)
		return false;

	list_for_each_entry(batch, &dms->sdma_batch_free, link)
		free_batches++;
	list_for_each_entry(page, &dms->dms_pages.free, link)
		free_pages++;
	if (dms->dms_pages.total_pages < pages || free_batches < batch_nodes ||
	    free_pages < pages)
		return false;

	for (i = 0; i < dms->num_engines; i++) {
		struct hfi2_dms_sdma_completion_fifo *fifo =
			dms->sde_rsrcs[i].sdma_completion_fifo;

		if (!fifo || !fifo->entries ||
		    fifo->cnt != dms->sdma_engines[i]->descq_cnt ||
		    fifo->cnt < completion_slots ||
		    !dms->sdma_engines[i]->descq_cnt ||
		    dms->sdma_engines[i]->descq_cnt - 1 <= ring_descriptors)
			return false;
	}

	return true;
}

static void _lifecycle_heads_init(struct hfi2_dms *dms)
{
	/*
	 * An early common-init failure can arrive before setup initialized these
	 * heads.  A zeroed head is not an empty list, so make both valid before
	 * either shutdown phase walks them.
	 */
	if (!dms->sdma_held.next)
		INIT_LIST_HEAD(&dms->sdma_held);
	if (!dms->sdma_batch_free.next)
		INIT_LIST_HEAD(&dms->sdma_batch_free);
}

bool hfi2_dms_sdma_shutdown(struct hfi2_dms *dms)
{
	bool quiesced = true;
	int i;

	if (WARN_ON_ONCE(!dms))
		return false;

	_lifecycle_heads_init(dms);
	if (!dms->sde_rsrcs)
		return true;

	for (i = 0; i < dms->num_engines; ++i)
		dms->sde_rsrcs[i].sdma_teardown_active = true;

	for (i = 0; i < dms->num_engines; ++i) {
		int ret = 0;

		if (!dms->hw_released)
			ret = hfi2_sdma_engine_quiesce(dms->sdma_engines[i]);
		if (ret) {
			quiesced = false;
			dd_dev_err(dms->dd,
				   "DMS SDMA engine %d halt not confirmed: %d; retaining DMA state\n",
				   i, ret);
			WARN_ON_ONCE(1);
			continue;
		}
		_error_complete(dms, (u8)i, -ESHUTDOWN, false);
	}

	return quiesced;
}

bool hfi2_dms_sdma_destroy(struct hfi2_dms *dms)
{
	struct hfi2_dms_sdma_batch *b, *tmp;
	int i;

	if (WARN_ON_ONCE(!dms))
		return false;

	_lifecycle_heads_init(dms);
	if (dms->sde_rsrcs) {
		for (i = 0; i < dms->num_engines; ++i) {
			dms->sde_rsrcs[i].sdma_teardown_active = true;
			_error_complete(dms, (u8)i, -ESHUTDOWN, false);
		}
	}

	/* Discard uncommitted held batches; their owners never transferred them. */
	list_for_each_entry_safe(b, tmp, &dms->sdma_held, link) {
		list_del(&b->link);
		_batch_release(b);
	}

	if (dms->sde_rsrcs) {
		for (i = 0; i < dms->num_engines; ++i) {
			struct hfi2_dms_sdma_completion_fifo *fifo =
				dms->sde_rsrcs[i].sdma_completion_fifo;

			if (!fifo)
				continue;
			WARN_ON_ONCE(fifo->nr);
			kfree(fifo->entries);
			kfree(fifo);
			dms->sde_rsrcs[i].sdma_completion_fifo = NULL;
		}
	}

	/* Free the recycling pool only after every callback owner has drained. */
	list_for_each_entry_safe(b, tmp, &dms->sdma_batch_free, link) {
		list_del(&b->link);
		kfree(b);
	}
	return true;
}
