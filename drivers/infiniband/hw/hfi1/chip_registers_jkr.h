/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks
 */

#ifndef _CHIP_REGISTERS_JKR_H
#define _CHIP_REGISTERS_JKR_H

/*
 * Definitions in this file were generated from the spec document.
 */

/* top level block offsets */
#define JKR_CCE     0x0000000
#define JKR_MCTXT   0x0200000
#define JKR_ASIC    0x0400000
#define JKR_MISC    0x0500000
#define JKR_RXE     0x1000000
#define JKR_TXE     0x1800000

#define JKR_SEND_CONTEXTS (JKR_TXE + 0x000000300010)
#define JKR_SEND_DMA_ENGINES (JKR_TXE + 0x000000300018)
#define JKR_SEND_PIO_MEM_SIZE (JKR_TXE + 0x000000300020)
#define JKR_SEND_DMA_MEM_SIZE (JKR_TXE + 0x000000300028)

#endif /* _CHIP_REGISTERS_JKR_H */
