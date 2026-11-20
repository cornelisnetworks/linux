/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2017 Intel Corporation.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_EXP_RCV_H
#define _HFI2_EXP_RCV_H
#include "hfi2.h"

#define EXP_TID_TIDLEN_MASK   0x7FFULL
#define EXP_TID_TIDLEN_SHIFT  0
#define EXP_TID_TIDCTRL_MASK  0x3ULL
#define EXP_TID_TIDCTRL_SHIFT 20
#define EXP_TID_TIDIDX_MASK   0x3FFULL
#define EXP_TID_TIDIDX_SHIFT  22

/* Expected buffer entry (TID) addressing supported by the hardware */
#define EXP_TID_ADDR_SHIFT    12
#define EXP_TID_ADDR_SIZE     BIT(EXP_TID_ADDR_SHIFT)

#define EXP_TID_GET(tid, field)	\
	(((tid) >> EXP_TID_TID##field##_SHIFT) & EXP_TID_TID##field##_MASK)

#define EXP_TID_SET(field, value)			\
	(((value) & EXP_TID_TID##field##_MASK) <<	\
	 EXP_TID_TID##field##_SHIFT)
#define EXP_TID_CLEAR(tid, field) ({					\
		(tid) &= ~(EXP_TID_TID##field##_MASK <<			\
			   EXP_TID_TID##field##_SHIFT);			\
		})
#define EXP_TID_RESET(tid, field, value) do {				\
		EXP_TID_CLEAR(tid, field);				\
		(tid) |= EXP_TID_SET(field, (value));			\
	} while (0)

/*
 * Define fields in the KDETH header so we can update the header
 * template.
 */
#define KDETH_OFFSET_SHIFT        0
#define KDETH_OFFSET_MASK         0x7fff
#define KDETH_OM_SHIFT            15
#define KDETH_OM_MASK             0x1
#define KDETH_TID_SHIFT           16
#define KDETH_TID_MASK            0x3ff
#define KDETH_TIDCTRL_SHIFT       26
#define KDETH_TIDCTRL_MASK        0x3
#define KDETH_INTR_SHIFT          28
#define KDETH_INTR_MASK           0x1
#define KDETH_SH_SHIFT            29
#define KDETH_SH_MASK             0x1
#define KDETH_KVER_SHIFT          30
#define KDETH_KVER_MASK           0x3
#define KDETH_JKEY_SHIFT          0x0
#define KDETH_JKEY_MASK           0xff
#define KDETH_HCRC_UPPER_SHIFT    16
#define KDETH_HCRC_UPPER_MASK     0xff
#define KDETH_HCRC_LOWER_SHIFT    24
#define KDETH_HCRC_LOWER_MASK     0xff

#define KDETH_GET(val, field)						\
	(((le32_to_cpu((val))) >> KDETH_##field##_SHIFT) & KDETH_##field##_MASK)
#define KDETH_SET(dw, field, val) do {					\
		u32 dwval = le32_to_cpu(dw);				\
		dwval &= ~(KDETH_##field##_MASK << KDETH_##field##_SHIFT); \
		dwval |= (((u32)(val) & KDETH_##field##_MASK) << \
			  KDETH_##field##_SHIFT);			\
		dw = cpu_to_le32(dwval);				\
	} while (0)

#define KDETH_RESET(dw, field, val) ({ dw = 0; KDETH_SET(dw, field, val); })

/* KDETH OM multipliers and switch over point */
#define KDETH_OM_SMALL     4
#define KDETH_OM_SMALL_SHIFT     2
#define KDETH_OM_LARGE     64
#define KDETH_OM_LARGE_SHIFT     6
#define KDETH_OM_MAX_SIZE  (1 << ((KDETH_OM_LARGE / KDETH_OM_SMALL) + 1))

#define EXP_TID_GROUP_SHIFT   RCV_SHIFT
#define EXP_TID_GROUP_SIZE    RCV_INCREMENT
#define EXP_TID_MAX_GROUPS    ((MAX_TID_PAIR_ENTRIES * 2U) / EXP_TID_GROUP_SIZE)
#define EXP_TID_META_WORDS    (EXP_TID_MAX_GROUPS / 64U)

static_assert(EXP_TID_GROUP_SIZE == 8U);
static_assert(EXP_TID_MAX_GROUPS == 256U);

extern const u8 hfi2_tid_seg_tab[256];

static inline u32 create_tid(u32 rcventry, u32 npages)
{
	u32 pair = rcventry & ~0x1;

	return EXP_TID_SET(IDX, pair >> 1) |
		EXP_TID_SET(CTRL, 1 << (rcventry - pair)) |
		EXP_TID_SET(LEN, npages);
}

/**
 * hfi2_tid_free_group_mask - atomically release a mask of slots in group @g
 * @rcd: the receive context
 * @g: group index (0..255)
 * @clear_mask: non-zero mask of slots (bits 0..7) to mark free (0)
 *
 * Clears @clear_mask bits in @rcd->tid_map[@g] and then unconditionally clears
 * bit @g in @rcd->meta_map so that even if a concurrent allocator raced to fill
 * the remaining bits of @g to 0xFF, @meta_map[@g] never remains stuck at 1
 * while @tid_map[@g] has free slots.
 */
static inline u8 hfi2_tid_free_group_mask(struct hfi2_ctxtdata *rcd,
					  u32 g, u8 clear_mask)
{
	u8 old = READ_ONCE(rcd->tid_map[g]);

	WARN_ON_ONCE((old & clear_mask) != clear_mask);
	do {
	} while (!try_cmpxchg(&rcd->tid_map[g], &old,
			      old & (clear_mask ^ 0xFF)));

	atomic64_andnot(BIT_ULL(g & 63), &rcd->meta_map[g >> 6]);
	return old & (clear_mask ^ 0xFF);
}

static inline void hfi2_tid_free_slot(struct hfi2_ctxtdata *rcd, u32 rcventry)
{
	hfi2_tid_free_group_mask(rcd, rcventry >> EXP_TID_GROUP_SHIFT,
				 BIT(rcventry & (EXP_TID_GROUP_SIZE - 1)));
}

int hfi2_alloc_ctxt_rcv_groups(struct hfi2_ctxtdata *rcd);
void hfi2_free_ctxt_rcv_groups(struct hfi2_ctxtdata *rcd);
void hfi2_exp_tid_group_init(struct hfi2_ctxtdata *rcd);
int hfi2_tid_alloc_full_group(struct hfi2_ctxtdata *rcd, int *first_partial);
int hfi2_tid_alloc_from_left(struct hfi2_ctxtdata *rcd, u32 start_g,
			     u32 rem, u8 *alloc_mask);
int hfi2_tid_alloc_partial_group(struct hfi2_ctxtdata *rcd, u8 need,
				 u8 *alloc_mask);

#endif /* _HFI2_EXP_RCV_H */
