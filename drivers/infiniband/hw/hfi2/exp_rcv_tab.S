/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 *
 * Combinational decision-table automaton (Asynchronous Potential Automaton /
 * LUT) for Expected Receive (TID) 8-slot RcvArray group allocation.
 *
 * Background & Theory of Operation:
 * ---------------------------------
 * Each RcvArray group consists of 8 hardware slots tracked by a single occupancy
 * byte `tid_map[g]` (bit = 1 occupied, bit = 0 free). Consecutive even/odd
 * slots (2k, 2k+1) form a hardware TID pair that can be fused into a single
 * `TIDCTRL = 3` descriptor, cutting CTS wire metadata in half and allowing SDMA
 * engines to cross physical page-set boundaries within one packet.
 *
 * Rather than scanning bits at runtime with loops and branches, `hfi2_tid_seg_tab`
 * implements a 256-entry combinational decision-table automaton (APA / LUT) in
 * `.rodata` (256 bytes = 4 L1d cache lines) that maps any 8-bit group occupancy
 * mask `mask` (0..255) in 1 cycle to an octal-structured byte `0FLP` organized
 * in 3-bit trigrams (reminiscent of PDP-11 instruction fields or UTF-8 prefix
 * coding):
 *
 *   Bit layout:  [  7  | 6   5   4   3 | 2   1   0 ]
 *                [ FLG | best_len(0..8)| best_pos  ]
 *
 *   - Bits 0..2 (`best_pos`, octal 00..07):
 *     Even starting bit index (0, 2, 4, 6) of the longest contiguous run of
 *     free (0) bits in `mask`. If no even bit is free (`best_len == 0`) but at
 *     least one odd bit is free (`mask != 0xFF`), encodes the highest free odd
 *     bit (1, 3, 5, 7) with `best_len = 1`.
 *
 *   - Bits 3..6 (`best_len`, octal 000..0100):
 *     Length (0..8) of that contiguous free window. Testing whether group `g`
 *     can satisfy a request of `need` slots reduces to a single comparison:
 *     `(entry & 0177) >= (need << 3)`.
 *
 *   - Bit 7 (`flash_right`, octal 0200, sign bit `(s8)entry < 0`):
 *     Direction of the "Flash" heuristic for single-slot (`need == 1`) requests.
 *     "Flash" denotes the position of the least valuable ("cheapest") free TID
 *     candidate whose consumption causes zero or minimal damage to hardware
 *     pair grouping:
 *       * `flash_right == 0` (sign bit 0, positive, "Flash Left"):
 *         No free bits exist to the right (lower bit indices `< best_pos`) of
 *         the main window. A single-TID request should take the highest free
 *         bit (`__fls(~mask)`), nibbling the odd upper edge of the window while
 *         preserving its even lower boundary `best_pos`.
 *       * `flash_right == 1` (sign bit 1, negative, "Flash Right"):
 *         At least one isolated orphan bit or smaller sub-window exists to the
 *         right of `best_pos` (e.g., `mask = 0b00001101` -> table entry `0244`
 *         octal: `flash_right = 1, best_len = 4, best_pos = 4`). A single-TID
 *         request inspects the sign of `entry` and takes `__ffs(~mask)` (bit 1),
 *         consuming the isolated right-hand orphan and leaving the 4-bit even
 *         window [4..7] (two full hardware pairs) completely intact.
 *
 * Because this file emits only `.rodata` bytes using standard GAS `.rept`
 * directives and contains no CPU instructions, it is architecture-independent.
 */

	.section .rodata, "a", @progbits
	.balign 64
	.globl hfi2_tid_seg_tab
	.type hfi2_tid_seg_tab, @object
hfi2_tid_seg_tab:
	.set mask, 0
	.rept 256
		.set best_len, 0
		.set best_pos, 0
		.set pos, 0
		.rept 4
			.set cur_len, 0
			.set stop, 0
			.set bit, pos
			.rept (8 - pos)
				.if !stop && !((mask >> bit) & 1)
					.set cur_len, cur_len + 1
				.else
					.set stop, 1
				.endif
				.set bit, bit + 1
			.endr
			.if cur_len > best_len
				.set best_len, cur_len
				.set best_pos, pos
			.endif
			.set pos, pos + 2
		.endr

		/*
		 * If all even slots are occupied (best_len == 0) but the byte
		 * is not 0xFF, expose the highest free odd orphan slot with
		 * length 1 so single-TID (need == 1) requests can claim it.
		 */
		.if (best_len == 0) && (mask != 0xff)
			.set odd_bit, 1
			.rept 4
				.if !((mask >> odd_bit) & 1)
					.set best_len, 1
					.set best_pos, odd_bit
				.endif
				.set odd_bit, odd_bit + 2
			.endr
		.endif

		/*
		 * Set the sign bit (0200 octal, "Flash Right") if any free bit
		 * exists to the right (below best_pos) of the main window.
		 */
		.set flash_right, 0
		.if ((~mask) & ((1 << best_pos) - 1)) != 0
			.set flash_right, 0200
		.endif

		.byte (flash_right | (best_len << 3) | best_pos)
		.set mask, mask + 1
	.endr
	.size hfi2_tid_seg_tab, 256
