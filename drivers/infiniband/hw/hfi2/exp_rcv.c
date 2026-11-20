// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 * Copyright(c) 2017 Intel Corporation.
 *
 * Dual-Ended Fractal Bitmap & Decision-Table Allocator for Expected Receive
 * (TID) RcvArray Entries.
 *
 * Architectural Overview:
 * -----------------------
 * Expected Receive RcvArray entries (up to 2048 slots per context, grouped into
 * 256 8-slot Write-Combining cache line groups) are managed without linked lists
 * or dynamic heap allocations using a 288-byte two-level structure embedded in
 * `struct hfi2_ctxtdata`:
 *   1. `u8 tid_map[256]` (256 bytes = 4 cache lines): 1 byte per 8-slot group
 *      (bit = 1 occupied, bit = 0 free; 0x00 = empty group, 0xFF = full group).
 *   2. `atomic64_t meta_map[4]` (32 bytes = 0.5 cache line): 1 bit per group
 *      (0 = group has at least one free slot `tid_map[g] != 0xFF`, 1 = group is
 *      full or permanently out-of-bounds `tid_map[g] == 0xFF`).
 *
 * Level-1 "Meet-in-the-Middle" Growth Across Groups (`meta_map[4]`):
 *   - Complete 8-slot groups (`hfi2_tid_alloc_full_group`) grow left-to-right
 *     (indices 0 -> 255) via `__ffs64(~meta_map[i])` (`tzcnt`).
 *   - Partial tail requests of 1..7 slots (`hfi2_tid_alloc_partial_group`) grow
 *     right-to-left (indices 255 -> 0) via `__fls(~meta_map[i])` (`bsr`/`lzcnt`).
 *   - Segregating full groups on the left from fragmented partial groups on the
 *     right keeps the full-group zone contiguous and allows partially freed
 *     interior groups to self-heal back to 0x00 without compaction.
 *   - If a large multi-group request exhausts all empty 8-slot groups and
 *     collides with the fragmented zone ("meet in the middle"), allocation does
 *     not reverse direction; `hfi2_tid_alloc_from_left()` continues moving
 *     forward left-to-right from `first_partial`, draining all free bits
 *     (`~old`) from each partial group (turning it into 0xFF) and only
 *     consulting `hfi2_tid_seg_tab[]` when the final remainder is smaller than
 *     the group's free slot count.
 *
 * Level-2 Fractal "Meet-in-the-Middle" Growth Inside Each Byte (`tid_map[g]`):
 *   To maximize hardware `TIDCTRL = 3` pair fusion (which requires consecutive
 *   even/odd slots `(2k, 2k+1)`), intra-group placement is driven by the
 *   256-byte combinational decision-table automaton (APA / LUT)
 *   `hfi2_tid_seg_tab[]` (defined in `exp_rcv_tab.S`), encoded in 3-bit octal
 *   trigrams (`0FLP`: `flash_right << 7 | best_len << 3 | best_pos`):
 *   - Within an even-aligned free window `[pos .. pos + len - 1]`:
 *       * Even requests (`need = 2, 4, 6`) are placed at the bottom of the
 *         window (`start = pos`), advancing `pos` by an even count so the
 *         remaining window base stays even.
 *       * Odd requests (`need = 3, 5, 7`) are placed at the top of the window
 *         (`start = pos + len - need`), leaving the even lower boundary `pos`
 *         untouched and isolating the single unpaired slot at the upper edge.
 *       * Single-slot requests (`need = 1`) use the sign bit (`0200` octal,
 *         "Flash Right / Flash Left") to claim the least valuable ("cheapest")
 *         orphan bit (`__ffs(~old)` when `(s8)entry < 0`, else `__fls(~old)`).
 */

#include "exp_rcv.h"
#include "trace.h"

/**
 * hfi2_exp_tid_group_init - initialize rcd expected receive bitmap state
 * @rcd: the receive context
 *
 * Marks all 256 groups as full/unavailable (0xFF) until
 * hfi2_alloc_ctxt_rcv_groups() opens the context's valid [0 .. ngroups - 1]
 * range. Groups >= ngroups remain permanently marked 1 in meta_map as
 * zero-cost boundary sentinels.
 */
void hfi2_exp_tid_group_init(struct hfi2_ctxtdata *rcd)
{
	memset(rcd->meta_map, 0xFF, sizeof(rcd->meta_map));
	memset(rcd->tid_map, 0xFF, sizeof(rcd->tid_map));
}

/**
 * hfi2_alloc_ctxt_rcv_groups - enable expected receive groups in bitmap
 * @rcd: the context to initialize
 */
int hfi2_alloc_ctxt_rcv_groups(struct hfi2_ctxtdata *rcd)
{
	u32 grp_size = rcd->dd->rcv_entries.group_size;
	u32 ngroups;

	if (WARN_ON_ONCE(grp_size != EXP_TID_GROUP_SIZE))
		return -EINVAL;

	ngroups = rcd->expected_count / grp_size;
	if (WARN_ON_ONCE(ngroups > EXP_TID_MAX_GROUPS))
		ngroups = EXP_TID_MAX_GROUPS;

	memset(rcd->tid_map, 0, ngroups);
	bitmap_clear((unsigned long *)rcd->meta_map, 0, ngroups);
	return 0;
}

/**
 * hfi2_free_ctxt_rcv_groups - reset expected receive bitmap and clear HW TIDs
 * @rcd: the context to free
 */
void hfi2_free_ctxt_rcv_groups(struct hfi2_ctxtdata *rcd)
{
	hfi2_exp_tid_group_init(rcd);
	hfi2_clear_tids(rcd);
}

/**
 * hfi2_tid_meta_mark_full - set group @g full bit in meta_map with race recheck
 * @rcd: the receive context
 * @g: group index (0..255)
 *
 * Sets bit @g in meta_map and rechecks tid_map[@g] so that if a concurrent
 * free cleared a slot in @g just before atomic64_or(), the meta_map bit does
 * not remain stuck at 1.
 */
static inline void hfi2_tid_meta_mark_full(struct hfi2_ctxtdata *rcd, u32 g)
{
	u32 word = g >> 6;
	u64 mask = BIT_ULL(g & 63);

	atomic64_or(mask, &rcd->meta_map[word]);
	if (unlikely(READ_ONCE(rcd->tid_map[g]) != 0xFF))
		atomic64_andnot(mask, &rcd->meta_map[word]);
}

/**
 * hfi2_tid_alloc_full_group - allocate a complete 8-slot group from the left
 * @rcd: the receive context
 * @first_partial: optional in/out cursor recording the lowest-indexed partial
 *                 group (`tid_map[g] != 0`) encountered during the left-to-right
 *                 scan, so that if full groups are exhausted ("meet in the
 *                 middle"), the caller can continue forward from that exact
 *                 group without rescanning from 0.
 *
 * Return: group index (0..255) on success, or -ENOSPC if no full group is free.
 */
int hfi2_tid_alloc_full_group(struct hfi2_ctxtdata *rcd, int *first_partial)
{
	u32 i;

	for (i = 0; i < EXP_TID_META_WORDS; i++) {
		u64 avail = ~atomic64_read(&rcd->meta_map[i]);

		while (avail) {
			u32 bit = __ffs64(avail);
			u32 g = (i << 6) + bit;
			u8 old = READ_ONCE(rcd->tid_map[g]);

			if (likely(old == 0)) {
				if (likely(try_cmpxchg(&rcd->tid_map[g],
						       &old, 0xFF))) {
					hfi2_tid_meta_mark_full(rcd, g);
					return (int)g;
				}
			}
			if (unlikely(old == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			else if (first_partial && *first_partial < 0)
				*first_partial = (int)g;

			avail &= avail - 1;
		}
	}

	return -ENOSPC;
}

static bool hfi2_tid_try_drain_group(struct hfi2_ctxtdata *rcd, u32 g,
				     u32 rem, u8 *old, u8 *alloc_mask)
{
	do {
		u8 free_bits, nfree, mask, new_map;

		if (unlikely(*old == 0xFF))
			return false;

		free_bits = *old ^ 0xFF;
		nfree = hweight8(free_bits);

		if (rem >= nfree) {
			mask = free_bits;
			new_map = 0xFF;
		} else {
			u8 entry = hfi2_tid_seg_tab[*old];
			u8 len = (entry >> 3) & 017;
			u8 pos = entry & 07;
			u8 take = min_t(u8, (u8)rem, len);
			u8 start;

			if (!take)
				return false;
			if (take == 1)
				start = ((s8)entry < 0) ?
					__ffs(free_bits) : __fls(free_bits);
			else
				start = (take & 1) ? (pos + len - take) : pos;

			mask = (u8)(((1U << take) - 1U) << start);
			new_map = *old | mask;
		}

		if (likely(try_cmpxchg(&rcd->tid_map[g], old, new_map))) {
			if (unlikely(new_map == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			*alloc_mask = mask;
			return true;
		}
	} while (1);
}

/**
 * hfi2_tid_alloc_from_left - continue forward left-to-right harvesting partial
 *                            groups when full groups run out ("meet in the middle")
 * @rcd: the receive context
 * @start_g: group index where the left-to-right scan first met a partial group
 * @rem: total remaining slots needed by the caller
 * @alloc_mask: output bitmask of slots claimed in the returned group
 *
 * When a large allocation exhausts all empty 8-slot groups and collides with
 * the fragmented zone:
 *   - As long as @rem >= the total number of free bits in group `g`
 *     (`hweight8(~old)`), we drain ALL free slots in `g` (`mask = ~old`)
 *     without consulting `hfi2_tid_seg_tab[]`, turning `tid_map[g]` into 0xFF.
 *   - Only when @rem is smaller than the free slots in `g` (< 8) do we consult
 *     `hfi2_tid_seg_tab[]` to carve an even-aligned window for the final tail.
 *
 * Return: group index (0..255) on success with *alloc_mask set, or -ENOSPC.
 */
int hfi2_tid_alloc_from_left(struct hfi2_ctxtdata *rcd, u32 start_g,
			     u32 rem, u8 *alloc_mask)
{
	u32 i;

	if (start_g >= EXP_TID_MAX_GROUPS || !rem)
		return -ENOSPC;

	for (i = start_g >> 6; i < EXP_TID_META_WORDS; i++) {
		u64 avail = ~atomic64_read(&rcd->meta_map[i]);

		if (i == (start_g >> 6))
			avail &= ~0ULL << (start_g & 63);

		while (avail) {
			u32 bit = __ffs64(avail);
			u32 g = (i << 6) + bit;
			u8 old = READ_ONCE(rcd->tid_map[g]);

			if (hfi2_tid_try_drain_group(rcd, g, rem, &old,
						     alloc_mask))
				return (int)g;

			if (unlikely(old == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			avail &= avail - 1;
		}
	}

	return -ENOSPC;
}

static bool hfi2_tid_try_fit_group(struct hfi2_ctxtdata *rcd, u32 g,
				   u8 need, u8 *old, u8 *alloc_mask)
{
	u8 req_code = need << 3;

	do {
		u8 entry = hfi2_tid_seg_tab[*old];
		u8 pos, len, start, mask, new_map;

		if ((entry & 0177) < req_code)
			return false;

		pos = entry & 07;
		len = (entry >> 3) & 017;
		if (need == 1)
			start = ((s8)entry < 0) ?
				__ffs(*old ^ 0xFF) : __fls(*old ^ 0xFF);
		else
			start = (need & 1) ? (pos + len - need) : pos;

		mask = (u8)(((1U << need) - 1U) << start);
		new_map = *old | mask;

		if (likely(try_cmpxchg(&rcd->tid_map[g], old, new_map))) {
			if (unlikely(new_map == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			*alloc_mask = mask;
			return true;
		}
	} while (1);
}

/**
 * hfi2_tid_alloc_partial_group - allocate up to @need slots from the right
 * @rcd: the receive context
 * @need: requested number of slots (1..EXP_TID_GROUP_SIZE; 8 is valid and
 *        encoded as 0100 octal -> mask 0xFF)
 * @alloc_mask: output bitmask of slots claimed within the returned group
 *
 * Scans meta_map[3..0] right-to-left (high to low group index) using the APA
 * decision table `hfi2_tid_seg_tab[]`.
 *
 * If no single group has a contiguous window of length >= @need, Pass 2 falls
 * back to draining all free slots (`~old`) from the rightmost group when
 * `need >= hweight8(~old)` or carving its largest window so the caller can
 * satisfy the remainder in a subsequent call.
 *
 * Return: group index (0..255) on success with *alloc_mask set, or -ENOSPC.
 */
int hfi2_tid_alloc_partial_group(struct hfi2_ctxtdata *rcd, u8 need,
				 u8 *alloc_mask)
{
	int i;

	/* Pass 1: greedy right-to-left search for a group fitting all @need */
	for (i = EXP_TID_META_WORDS - 1; i >= 0; i--) {
		unsigned long avail = ~atomic64_read(&rcd->meta_map[i]);

		while (avail) {
			u32 bit = __fls(avail);
			u32 g = (i << 6) + bit;
			u8 old = READ_ONCE(rcd->tid_map[g]);

			if (hfi2_tid_try_fit_group(rcd, g, need, &old,
						   alloc_mask))
				return (int)g;

			if (unlikely(old == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			avail &= ~BIT_ULL(bit);
		}
	}

	/*
	 * Pass 2: no single group can hold @need in one contiguous window;
	 * drain all free bits from the rightmost group if @need >= nfree, or
	 * take its largest contiguous window.
	 */
	for (i = EXP_TID_META_WORDS - 1; i >= 0; i--) {
		unsigned long avail = ~atomic64_read(&rcd->meta_map[i]);

		while (avail) {
			u32 bit = __fls(avail);
			u32 g = (i << 6) + bit;
			u8 old = READ_ONCE(rcd->tid_map[g]);

			if (hfi2_tid_try_drain_group(rcd, g, need, &old,
						     alloc_mask))
				return (int)g;

			if (unlikely(old == 0xFF))
				hfi2_tid_meta_mark_full(rcd, g);
			avail &= ~BIT_ULL(bit);
		}
	}

	return -ENOSPC;
}
