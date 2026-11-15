/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2025 Cornelis Networks.
 *
 */
#ifndef _HFI2_DMS_SDMA_H
#define _HFI2_DMS_SDMA_H

#include <linux/types.h>

/*
 * DMS SDMA layer -- protocol-agnostic lowest-layer SDMA
 * descriptor-ring capability for the HFI2 DMS component.
 *
 * A caller hands us physically-contiguous fragments {paddr, len, type}.
 * emit() converts each fragment into one or more HW descriptors (the JKR
 * 256B/page split; CYR emits one descriptor per fragment), stamping
 * SOP/EOP from @type.  commit() only splices the built batch onto the
 * target engine's pending list; the per-engine poll step
 * (drain_and_complete()) later places whole packets into the HW ring,
 * appends the platform doorbell pad, rings the doorbell, and fires each
 * completion once the hardware egresses the run.
 * Single-threaded poll model: no locks, no atomics.  When several DMS
 * lanes share the engines (dms->sde_share), only the HW ring accesses are
 * serialized, per engine, with hfi2_dms_sde_lock().
 *
 * This header exposes the public API surface only.  The batch handle is
 * opaque and defined in dms_sdma.c.
 */

/* Forward declarations -- avoid pulling dms.h / sdma_txreq.h into this header.
 * desc_submit() takes only a POINTER to struct sdma_desc, so an incomplete
 * type suffices here; the definition arrives via sdma_txreq.h in the .c file.
 */
struct hfi2_dms;
struct sdma_desc;

#define HFI2_DMS_SDMA_NODE_DESCS 128
#define HFI2_DMS_SDMA_BATCH_POOL_MIN 8

/**
 * hfi2_dms_sdma_done_fn - completion callback for a submitted batch
 * @cookie: opaque caller context supplied at commit/submit time
 * @status: 0 on success, negative errno on failure
 */
typedef void (*hfi2_dms_sdma_done_fn)(void *cookie, int status);

/**
 * enum hfi2_dms_sdma_desc_type - packet-framing role of an emitted fragment
 * @HFI2_DMS_SDMA_DESC_TYPE_MID: interior fragment (neither SOP nor EOP)
 * @HFI2_DMS_SDMA_DESC_TYPE_SOP: opens a packet
 * @HFI2_DMS_SDMA_DESC_TYPE_EOP: closes a packet
 * @HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP: a whole single-fragment packet
 *
 * The values are the actual JKR/CYR descriptor qw[1] SOP/EOP flag bits
 * (identical bit positions on both chips), so @type OR's straight onto a
 * descriptor with no per-chip dispatch.
 */
enum hfi2_dms_sdma_desc_type {
	HFI2_DMS_SDMA_DESC_TYPE_MID = 0,
	HFI2_DMS_SDMA_DESC_TYPE_SOP = 1U << 31,
	HFI2_DMS_SDMA_DESC_TYPE_EOP = 1U << 30,
	HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP =
		HFI2_DMS_SDMA_DESC_TYPE_SOP | HFI2_DMS_SDMA_DESC_TYPE_EOP,
};

/**
 * struct hfi2_dms_sdma_frag - a single physically-contiguous fragment
 * @paddr: physical (DMA) address of the fragment
 * @len: length of the fragment in bytes
 * @type: packet-framing role (SOP/MID/EOP/SOP_EOP)
 */
struct hfi2_dms_sdma_frag {
	dma_addr_t paddr;
	u32 len;
	enum hfi2_dms_sdma_desc_type type;
};

/* Opaque batch handle; defined in dms_sdma.c. */
struct hfi2_dms_sdma_batch;

/*
 * Per-DMS layer lifecycle.  setup() initializes the held-batch list and
 * per-engine state.  shutdown() first confirms each engine halted, then
 * error-completes outstanding commits while keeping all common storage live so
 * asynchronous owners can consume the published callbacks.  A failed halt
 * retains DMA-visible state rather than publishing a premature completion.
 * destroy() discards uncommitted batches and frees completion/batch storage
 * only after shutdown confirms every engine.
 * The caller owns the dms->sde_rsrcs array.
 */
int hfi2_dms_sdma_setup(struct hfi2_dms *dms);
int hfi2_dms_sdma_warm_reserve(struct hfi2_dms *dms, u32 batch_nodes);
/*
 * Check the common substrate against protocol-neutral warm inventory.  The
 * completion FIFO holds completion records, while descriptor capacity belongs
 * to its paired hardware ring; those capacities are deliberately separate.
 */
bool hfi2_dms_sdma_capacity_ready(struct hfi2_dms *dms, u32 batch_nodes,
				  u32 pages, u32 completion_slots,
				  u32 ring_descriptors);
bool hfi2_dms_sdma_shutdown(struct hfi2_dms *dms);
bool hfi2_dms_sdma_destroy(struct hfi2_dms *dms);

/*
 * Batch primitive (core interface).
 *
 * batch_new() allocates an engine-agnostic batch and links it onto a
 * per-DMS "held" list so teardown can find it even if the caller yields
 * before commit/abort.  The concrete target engine is chosen at commit().
 * Returns NULL on allocation failure.
 *
 * batch_emit() converts one physically-contiguous fragment into one or
 * more descriptors (JKR: 256B-boundary + 4096B-page split; CYR: split
 * only on the per-descriptor byte-count cap, no alignment errata) and
 * stamps SOP/EOP from @type onto the first/last descriptor the fragment
 * produces.  The caller is responsible for well-formed packet framing
 * (exactly one SOP..EOP per packet, or one SOP_EOP for a single-fragment
 * packet) AND for packet/payload sizing (e.g. staying within a receiver's
 * TID-set capacity) -- this layer knows only per-descriptor and
 * descriptor-ring hardware limits, never receiver or packet policy.
 * Returns 0, or a negative errno.
 */
struct hfi2_dms_sdma_batch *hfi2_dms_sdma_batch_new(struct hfi2_dms *dms,
						    u8 port_idx);
/* Atomic producer variant: free-list-only, with no pool growth. */
struct hfi2_dms_sdma_batch *
hfi2_dms_sdma_batch_new_nowait(struct hfi2_dms *dms, u8 port_idx);
int hfi2_dms_sdma_batch_emit(struct hfi2_dms_sdma_batch *b, dma_addr_t paddr,
			     u32 len, enum hfi2_dms_sdma_desc_type type);
u32 hfi2_dms_sdma_fragment_desc_count(struct hfi2_dms *dms, dma_addr_t paddr,
				      u32 len);
/* Physical descriptor footprint of one doorbelled run, including its pad. */
u32 hfi2_dms_sdma_run_desc_count(const struct hfi2_dms *dms,
				 u32 real_descs);
/* Descriptors emitted so far into a held batch, across all its nodes. */
u32 hfi2_dms_sdma_batch_ndesc(const struct hfi2_dms_sdma_batch *b);

/*
 * Associate a held batch with its eventual completion before the caller can
 * emit or abort it.  The tag is copied to every node, so both the held head
 * and committed tail carry the same identity.  A pre-commit abort never
 * invokes @done; its owner must unwind the cookie directly.
 */
bool hfi2_dms_sdma_batch_is_held(const struct hfi2_dms_sdma_batch *b);
int hfi2_dms_sdma_batch_tag(struct hfi2_dms_sdma_batch *b,
			    hfi2_dms_sdma_done_fn done, void *cookie);

/*
 * batch_commit() binds the concrete target engine (@engine_idx is an
 * absolute engine index chosen by the caller; engine selection is caller
 * policy, not this layer's) and splices the built batch onto that engine's
 * pending list.  It does NOT touch the HW ring: descriptor placement, the
 * platform doorbell pad, the HEAD_TO_HOST + Last stamp, the doorbell, and
 * the completion record all happen later in the poll step
 * (drain_and_complete()).  The batch is consumed before return either way.
 *
 * Returns 0 once the batch is queued; -ESHUTDOWN if the engine is tearing
 * down; -EINVAL on a degenerate/empty batch or bad @engine_idx.  On ANY
 * non-zero return @done is never called.  Unlike a classic pool API the
 * caller does NOT abort after a failed commit -- commit consumes the batch
 * on every path.
 */
int hfi2_dms_sdma_batch_commit(struct hfi2_dms_sdma_batch *b, u8 engine_idx,
			       hfi2_dms_sdma_done_fn done, void *cookie);
void hfi2_dms_sdma_batch_abort(struct hfi2_dms_sdma_batch *b);

/*
 * Flat one-shot submit (thin wrapper over the batch primitive): emit every
 * fragment in @frags (each carrying its own SOP/MID/EOP/SOP_EOP @type) and
 * commit to @engine_idx.  Returns 0 or a negative errno; on failure @done
 * is never called.
 */
int hfi2_dms_sdma_frag_submit(struct hfi2_dms *dms, u8 engine_idx,
			      u8 port_idx,
			      const struct hfi2_dms_sdma_frag *frags,
			      u32 nfrags, hfi2_dms_sdma_done_fn done,
			      void *cookie);

/*
 * Advanced one-shot submit: place @ndesc caller-built descriptors verbatim.
 * No fragment splitting and no SOP/EOP stamping -- the caller has already
 * produced valid descriptors (correct SOP/EOP, byte counts, addresses).
 * The layer still appends the JKR 32-pad, stamps the terminal
 * HEAD_TO_HOST + Last, rings the doorbell, and tracks completion.  Returns
 * 0 or a negative errno; on failure @done is never called.
 */
int hfi2_dms_sdma_desc_submit(struct hfi2_dms *dms, u8 engine_idx,
			      u8 port_idx,
			      const struct sdma_desc *descs, u32 ndesc,
			      hfi2_dms_sdma_done_fn done, void *cookie);

/*
 * Copy @ndesc ring-ready descriptors straight into the engine's HW ring, for
 * callers that already hold correct FIRST/LAST framing, byte counts and
 * addresses.  No splitting, no stamping, no batch node.
 *
 * Bulksvc event thread only: advances sde->descq_tail and the completion FIFO
 * with no lock beyond hfi2_dms_sde_lock() for shared engines.
 *
 * The doorbell, not this call, pads the run to the platform granule.  On an
 * engine shared by several lanes, another lane's next append or tail write
 * pads it too (see hfi2_dms_sdma_close_run()).
 *
 * The tail CSR is NOT written: call hfi2_dms_sdma_doorbell_all() once at the
 * end of the poll pass.  Any other tail write on the engine (including one
 * by another lane sharing it) may start the placed packets earlier.
 *
 * @done may be NULL to record no completion, letting a caller place several
 * packets and anchor them once with hfi2_dms_sdma_anchor(), which it must do
 * before considering them accounted for.
 *
 * Returns 0, -EAGAIN if the run does not fit, a batch is queued ahead of it,
 * or the completion FIFO is full (nothing written in any case), -ESHUTDOWN,
 * -EINVAL or -ENOMEM.  On any non-zero return @done is never called.
 */
int hfi2_dms_sdma_desc_place(struct hfi2_dms *dms, u8 engine_idx,
			     const struct sdma_desc *descs, u32 ndesc,
			     hfi2_dms_sdma_done_fn done,
			     void *cookie);

/*
 * Record one completion against everything placed on @engine_idx so far, for
 * callers that placed with @done == NULL.  At least one descriptor must have
 * been placed since the caller's previous anchor.  Bulksvc event thread only.
 *
 * Returns 0, or -EAGAIN if the completion FIFO is full; nothing is recorded in
 * that case and @done is never called.
 */
int hfi2_dms_sdma_anchor(struct hfi2_dms *dms, u8 engine_idx,
			 hfi2_dms_sdma_done_fn done, void *cookie);

/*
 * Publish every engine's deferred ring tail (see desc_place()).  Call once at
 * the end of a poll pass; a no-op for engines with nothing pending.  Bulksvc
 * event thread only, and device-wide: a per-port caller publishes other ports'
 * tails too, which is safe since their descriptors are already written.
 */
void hfi2_dms_sdma_doorbell_all(struct hfi2_dms *dms);

/*
 * Pad engine @engine_idx's open desc_place() run, whichever lane placed it,
 * so that descriptors appended next start on a granule boundary.  For the
 * DMS injector, which appends to the ring outside this layer.  A no-op
 * unless the engine is shared by several lanes; then the caller holds
 * hfi2_dms_sde_lock() and must pad before checking the ring's free count.
 */
void hfi2_dms_sdma_close_run(struct hfi2_dms *dms, u8 engine_idx);

/*
 * Snapshot one engine's hardware-visible descriptor occupancy and its high
 * water mark.  The worker owns updates; READ_ONCE makes debugfs reads safe.
 */
u32 hfi2_dms_sdma_ring_resident_current(const struct hfi2_dms *dms,
					 u8 engine_idx);
u32 hfi2_dms_sdma_ring_resident_high_water(const struct hfi2_dms *dms,
					    u8 engine_idx);

/*
 * Per-engine poll step.
 *
 * Checks engine liveness (a DMS-loaned engine can halt asynchronously via
 * the SDMA error IRQ, which sets no state in this layer, so this is the
 * only observer): if dead it error-completes every outstanding commit
 * (status<0) and returns.  Otherwise it refreshes the DMA'd head and fires
 * the completion callback for every commit whose descriptors have egressed
 * (oldest-first, FIFO-stop).  Returns the number of completions fired.
 */
u32 hfi2_dms_sdma_drain_and_complete(struct hfi2_dms *dms, u8 engine_idx);

#endif /* _HFI2_DMS_SDMA_H */
