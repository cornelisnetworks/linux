/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 */

#ifndef _CHIP_CYR_H
#define _CHIP_CYR_H

#include "chip_registers_cyr.h"

/* items not defined in the generated register file */
#define CYR_PIO_SEND (CYR_TXE + CYR_C_TXE_PIO_SEND_OFFSET)
#define CYR_RCV_ARRAY CYR_C_RXE_RCV_ARRAY_EGR_BASE
#define CYR_RCV_ARRAY_EGR_RT_MODE0_BUF_SIZE_SHIFT 46

/*
 * RcvArray entry RT_Mode 1 (cacheline mode), added on CYR so the Ethernet
 * driver can post 64-byte aligned sk_buff payloads instead of 4KB pages.
 * Entry layout: [63] RT_WriteEnable, [62] RT_Mode, [57:6] address = PA[57:6]
 * (identity mapped, no shift), [5:4] ignored, [3:0] size code.
 */
#define CYR_RCV_ARRAY_RT_MODE_SMASK		0x4000000000000000ull
#define CYR_RCV_ARRAY_RT_MODE1_ADDR_SMASK	0x03ffffffffffffc0ull
#define CYR_RCV_ARRAY_RT_MODE1_BUF_SIZE_MASK	0xfull
#define CYR_RCV_ARRAY_RT_BUF_SIZE_INVALID	0x0
/* address bits [5:0] have no home in a mode 1 entry: DMA must be 64B aligned */
#define CYR_RCV_ARRAY_RT_MODE1_ADDR_ALIGN	64

/*
 * RT_Mode 1 buffer size codes.  Codes 1-7 are Ethernet-shaped sizes and codes
 * 8-F are powers of two; the ladder is deliberately non-monotonic (4096 bytes
 * is code 0x8, not 0x4), so map byte sizes with a table, never with ilog2().
 */
enum cyr_rcv_array_mode1_size {
	CYR_RT_MODE1_SZ_1536	= 0x1,
	CYR_RT_MODE1_SZ_2048	= 0x2,
	CYR_RT_MODE1_SZ_3072	= 0x3,
	CYR_RT_MODE1_SZ_4608	= 0x4,
	CYR_RT_MODE1_SZ_6144	= 0x5,
	CYR_RT_MODE1_SZ_9216	= 0x6,
	CYR_RT_MODE1_SZ_10240	= 0x7,
	CYR_RT_MODE1_SZ_4096	= 0x8,
	CYR_RT_MODE1_SZ_8192	= 0x9,
	CYR_RT_MODE1_SZ_16384	= 0xa,
	CYR_RT_MODE1_SZ_32768	= 0xb,
	CYR_RT_MODE1_SZ_65536	= 0xc,
	CYR_RT_MODE1_SZ_131072	= 0xd,
	CYR_RT_MODE1_SZ_262144	= 0xe,
	CYR_RT_MODE1_SZ_2097152	= 0xf,
};

/* RcvArray access shifts */
#define CYR_RCV_ARRAY_EGR_TID_SELECT_SHIFT 25
#define CYR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT 17
#define CYR_RCV_ARRAY_CSR_INDEX_SHIFT 3

/*
 * The CYR BAR space is not split up by the RcvArray.  To maintain
 * compatibility with WFR, arbitrarily split the BAR space at some
 * page-aligned spot. Use CYR_RXE - the start of the RXE block.
 */
#define CYR_BAR0_SIZE (128 * 1024 * 1024)	/* 128 MB */
#define CYR_KREG1_SIZE CYR_RXE
#define CYR_KREG2_OFFSET CYR_RXE
#define CYR_KREG2_SIZE (CYR_PIO_SEND - CYR_RXE)

#define CYR_RCV_ARRAY_SIZE (64 * 1024 * 1024)	/* 64 MB */

/* cclock tick time, in picoseconds per tick: 1/speed * 10^12  */
#define CYR_ASIC_CCLOCK_PS 602	/* 1660.15625 MHz */

/* max number of eager entries per context */
#define CYR_MAX_EAGER_ENTRIES 16384

/* Number of PKey entries in the CYR HW */
#define CYR_MAX_PKEY_VALUES 1024
/* number of SendCtxtCtrl.CtxtBase bits in the CYR HW */
#define CYR_PIO_BASE_BITS 18

/* register strides not derived from the spec */
#define CYR_C_RXE_IPRC_STRIDE 8
#define CYR_C_TXE_TCTXT_STRIDE 8
#define CYR_C_TXE_SDMACFG_STRIDE 8
#define CYR_C_TXE_EPSC_STRIDE 8

void cyr_init_other(struct hfi2_devdata *dd);

/* Specific IRQ sources */
#define CYR_ASIC_ERR_INT		2
#define CYR_MCTXT_CPORT_TO_PCIE_INT	4	/* part of CYR_IS_GENERAL_ERR_START/END */

/* interrupt source starts */
#define CYR_IS_GENERAL_ERR_START     0
#define CYR_IS_FLR_START             8
#define CYR_IS_PORT_START            16
#define CYR_IS_VARIOUS_START         32
#define CYR_IS_SDMAENG_ERR_START     48
#define CYR_IS_SDMA_START            64
#define CYR_IS_SDMA_PROGRESS_START   80
#define CYR_IS_SDMA_IDLE_START       96
#define CYR_IS_RCVAVAIL_START        112
#define CYR_IS_RCVURGENT_START       432
#define CYR_IS_SENDCREDIT_START      752
#define CYR_IS_PBC_START             1472
#define CYR_IS_SENDCTXT_ERR_START    2192
#define CYR_IS_PIO_ERR_START         2912
#define CYR_IS_SDMA_ERR_SI_START     2921
#define CYR_IS_CSR_ERR_START         2930
#define CYR_IS_RESERVED_START        2939
#define CYR_IS_TABLE_NUM             2944

/* derived interrupt source values */
#define CYR_IS_GENERAL_ERR_END       (CYR_IS_FLR_START - 1)
#define CYR_IS_FLR_END               (CYR_IS_PORT_START - 1)
#define CYR_IS_PORT_END              (CYR_IS_VARIOUS_START - 1)
#define CYR_IS_VARIOUS_END           (CYR_IS_SDMAENG_ERR_START - 1)
#define CYR_IS_SDMAENG_ERR_END       (CYR_IS_SDMA_START - 1)
#define CYR_IS_SDMA_END              (CYR_IS_SDMA_PROGRESS_START - 1)
#define CYR_IS_SDMA_PROGRESS_END     (CYR_IS_SDMA_IDLE_START - 1)
#define CYR_IS_SDMA_IDLE_END         (CYR_IS_RCVAVAIL_START - 1)
#define CYR_IS_RCVAVAIL_END          (CYR_IS_RCVURGENT_START - 1)
#define CYR_IS_RCVURGENT_END         (CYR_IS_SENDCREDIT_START - 1)
#define CYR_IS_SENDCREDIT_END        (CYR_IS_PBC_START - 1)
#define CYR_IS_PBC_END               (CYR_IS_SENDCTXT_ERR_START - 1)
#define CYR_IS_SENDCTXT_ERR_END      (CYR_IS_PIO_ERR_START - 1)
#define CYR_IS_PIO_ERR_END           (CYR_IS_SDMA_ERR_SI_START - 1)
#define CYR_IS_SDMA_ERR_SI_END       (CYR_IS_CSR_ERR_START - 1)
#define CYR_IS_CSR_ERR_END           (CYR_IS_RESERVED_START - 1)
#define CYR_IS_RESERVED_END          (CYR_IS_TABLE_NUM - 1)

/* last interrupt */
#define CYR_IS_LAST_SOURCE CYR_IS_RESERVED_END

/* bulksvc doorbells: Port0Int6/Port0Int7 within the IS_PORT range */
#define CYR_IS_DOORBELL0		(CYR_IS_PORT_START + 6)
#define CYR_IS_DOORBELL1		(CYR_IS_PORT_START + 7)

extern const struct hfi2_is_table cyr_is_table[];
extern const struct gi_enable_entry cyr_gi_enable_table[];
extern const struct flag_data cyr_egress_err_info_data;

/* SendEgressErrInfo bits that correspond to a PortXmitDiscard counter */
#define CYR_PORT_DISCARD_EGRESS_ERRS \
	(CYR_SEND_EGRESS_ERR_INFO_TOO_LONG_PACKET_ERR9B_SMASK \
	| CYR_SEND_EGRESS_ERR_INFO_VL_MAPPING_ERR9B_SMASK \
	| CYR_SEND_EGRESS_ERR_INFO_VL_ERR9B_SMASK)

int cyr_find_used_resources(struct hfi2_devdata *dd);
void cyr_read_guid(struct hfi2_devdata *dd);
int cyr_early_per_chip_init(struct hfi2_devdata *dd);
int cyr_mid_per_chip_init(struct hfi2_devdata *dd);
void cyr_put_tid(struct hfi2_ctxtdata *rcd, u32 index,
		 u32 type, unsigned long pa, u16 order, bool flush);
void cyr_put_tid_mode1(struct hfi2_ctxtdata *rcd, u32 index,
		       dma_addr_t dma_addr, u8 size_code, bool flush);
int cyr_rcv_array_mode1_size_code(u32 bytes);
int cyr_rcv_array_mode1_size_bytes(u32 bytes);
void cyr_rcv_array_wc_fill(struct hfi2_ctxtdata *rcd, u32 index, u32 type);
void cyr_set_port_tid_config(struct hfi2_devdata *dd, int pidx, u16 ctxt,
			     u32 eager_base, u16 alloced,
			     u32 expected_base, u32 expected_count);
void cyr_update_rcv_hdr_size(struct hfi2_devdata *dd, u8 pidx, u16 ctxt, u32 size);
bool cyr_check_synth_status(struct hfi2_devdata *dd);
void cyr_update_synth_status(struct hfi2_devdata *dd);
void cyr_set_pio_integrity(struct hfi2_devdata *dd, u32 pidx, u32 ctxt, int type,
			   enum spi_cmds cmd);
void cyr_read_link_quality(struct hfi2_pportdata *ppd, u8 *link_quality);
void cyr_set_rheq_addr(struct hfi2_devdata *dd, u16 ctxt, u64 dma_addr);
void cyr_handle_link_bounce(struct work_struct *work);
void cyr_enable_rcv_context(struct hfi2_devdata *dd, u8 pidx, u16 ctxt, bool enable);

#endif /* _CHIP_CYR_H */
