/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 */

#ifndef _CHIP_JKR_H
#define _CHIP_JKR_H

#include "chip_registers_jkr.h"

/* items not defined in the generated register file */
#define JKR_PIO_SEND (JKR_TXE + JKR_TXE_PIO_SEND_OFFSET)
#define JKR_RCV_ARRAY (JKR_RXE + JKR_RXE_RCV_ARRAY_EGR_OFFSET)

/*
 * The JKR BAR space is not split up by the RcvArray.  To maintain
 * compatibility with WFR, arbitrarily split the BAR space at some
 * page-aligned spot. Use JKR_RXE - the start of the RXE block.
 */
#define JKR_BAR0_SIZE (128 * 1024 * 1024)	/* 128 MB */
#define JKR_KREG1_SIZE JKR_RXE
#define JKR_KREG2_OFFSET JKR_RXE
#define JKR_KREG2_SIZE (JKR_PIO_SEND - JKR_RXE)

#define JKR_RCV_ARRAY_SIZE (64 * 1024 * 1024)	/* 64 MB */

#endif /* _CHIP_JKR_H */
