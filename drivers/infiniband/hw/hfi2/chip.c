// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright(c) 2021 - 2026 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 *
 * CSR access, interrupt configuration and dispatch, CCE/RSM/context
 * tables, counters, thermal handling and chip initialization.  Split
 * out of the former monolithic chip.c; link management lives in
 * chip_link.c and send/receive context setup in chip_ctxt.c.
 */

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>

#include "hfi2.h"
#include "file_ops.h"
#include "affinity.h"
#include "trace.h"
#include "mad.h"
#include "pio.h"
#include "sdma.h"
#include "eprom.h"
#include "efivar.h"
#include "platform.h"
#include "debugfs.h"
#include "fault.h"
#include "netdev.h"
#include "chip_registers_jkr.h"
#include "chip_gen.h"
#include "vf2pf.h"
#include "sriov.h"
#include "bulksvc.h"
#include "eth_main.h"

uint ctxt_mode;


uint hfi2_num_vls = HFI2_MAX_VLS_SUPPORTED;

/*
 * Default time to aggregate two 10K packets from the idle state
 * (timer not running). The timer starts at the end of the first packet,
 * so only the time for one 10K packet and header plus a bit extra is needed.
 * 10 * 1024 + 64 header byte = 10304 byte
 * 10304 byte / 12.5 GB/s = 824.32ns
 */
uint hfi2_rcv_intr_timeout = (824 + 16); /* 16 is for coalescing interrupt */

uint hfi2_rcv_intr_count = 16; /* same as qib */

ushort hfi2_link_crc_mask = SUPPORTED_CRCS;

uint hfi2_loopback;

static int sdma_yield = 1000; /* how often to yield when in thrd intr handler */

static int rcvwcb = -1; /* RcvIportCtrl.RcvWcb setting */

/* Other driver tunables */
uint hfi2_rcv_intr_dynamic = 1; /* enable dynamic mode for rcv int mitigation*/
ushort hfi2_crc_14b_sideband = 1;
static uint use_flr = 1;
uint hfi2_quick_linkup; /* skip LNI */


/* Send Error Consequences */
#define SEC_WRITE_DROPPED 0x1
#define SEC_PACKET_DROPPED 0x2
#define SEC_SC_HALTED 0x4 /* per-context only */
#define SEC_SPC_FREEZE 0x8 /* per-HFI only */

#define DEFAULT_KRCVQS 2
#define MIN_KERNEL_KCTXTS 2
#define FIRST_KERNEL_KCTXT 1

/*
 * RSM types
 */
#define RSM_TYPE_FECN 0
#define RSM_TYPE_VNIC 1
#define RSM_TYPE_AIP 2
#define RSM_TYPE_VERBS 3
#define RSM_TYPE_MAD_RSP 4
#define RSM_TYPE_MAD_ACTION 5
#define RSM_TYPE_BULKSVC 6
#define RSM_TYPE_ETHERNET 7
#define RSM_TYPE_DEPRECATED 1

/* Bit offset into the GUID which carries HFI id information */
#define GUID_HFI_INDEX_SHIFT 39

/* RSM fields for Verbs */
#define QW_SHIFT 6ull
/* QPN[7..1] */
#define QPN_WIDTH 7ull

/* LRH.BTH: QW 0, OFFSET 48 - for match */
#define LRH_BTH_QW 0ull
#define LRH_BTH_BIT_OFFSET 48ull
#define LRH_BTH_OFFSET(off) ((LRH_BTH_QW << QW_SHIFT) | (off))
#define LRH_BTH_MATCH_OFFSET LRH_BTH_OFFSET(LRH_BTH_BIT_OFFSET)
#define LRH_BTH_SELECT
#define LRH_BTH_MASK 3ull
#define LRH_BTH_VALUE 2ull

/* LRH.SC[3..0] QW 0, OFFSET 56 - for match */
#define LRH_SC_QW 0ull
#define LRH_SC_BIT_OFFSET 56ull
#define LRH_SC_OFFSET(off) ((LRH_SC_QW << QW_SHIFT) | (off))
#define LRH_SC_MATCH_OFFSET LRH_SC_OFFSET(LRH_SC_BIT_OFFSET)
#define LRH_SC_MASK 128ull
#define LRH_SC_VALUE 0ull

/* SC[n..0] QW 0, OFFSET 60 - for select */
#define LRH_SC_SELECT_OFFSET ((LRH_SC_QW << QW_SHIFT) | (60ull))

/* QPN[m+n:1] QW 1, OFFSET 1 */
#define QPN_SELECT_OFFSET ((1ull << QW_SHIFT) | (1ull))

/* RSM fields for AIP */
/* LRH.BTH above is reused for this rule */

/* BTH.DESTQP: QW 1, OFFSET 16 for match */
#define BTH_DESTQP_QW 1ull
#define BTH_DESTQP_BIT_OFFSET 16ull
#define BTH_DESTQP_OFFSET(off) ((BTH_DESTQP_QW << QW_SHIFT) | (off))
#define BTH_DESTQP_MATCH_OFFSET BTH_DESTQP_OFFSET(BTH_DESTQP_BIT_OFFSET)
#define BTH_DESTQP_MASK 0xFFull
#define BTH_DESTQP_VALUE 0x81ull

/* DETH.SQPN: QW 1 Offset 56 for select */
/* We use 8 most significant Soure QPN bits as entropy fpr AIP */
#define DETH_AIP_SQPN_QW 3ull
#define DETH_AIP_SQPN_BIT_OFFSET 56ull
#define DETH_AIP_SQPN_OFFSET(off) ((DETH_AIP_SQPN_QW << QW_SHIFT) | (off))
#define DETH_AIP_SQPN_SELECT_OFFSET \
	DETH_AIP_SQPN_OFFSET(DETH_AIP_SQPN_BIT_OFFSET)

/* L4_TYPE QW 1, OFFSET 0 - for match */
#define L4_TYPE_QW 1ull
#define L4_TYPE_BIT_OFFSET 0ull
#define L4_TYPE_OFFSET(off) ((L4_TYPE_QW << QW_SHIFT) | (off))
#define L4_TYPE_MATCH_OFFSET L4_TYPE_OFFSET(L4_TYPE_BIT_OFFSET)
#define L4_16B_TYPE_MASK 0xFFull
#define L4_16B_ETH_VALUE 0x78ull

/* 16B VESWID - for select */
#define L4_16B_HDR_VESWID_OFFSET ((2 << QW_SHIFT) | (16ull))
/* 16B ENTROPY - for select */
#define L2_16B_ENTROPY_OFFSET ((1 << QW_SHIFT) | (32ull))

/* RSM fields for CN Ethernet */
/*
 * CN Ethernet 16B bypass frames carry the encapsulated Ethernet frame at a
 * fixed 16-byte offset (the 16B L2 header).  For an untagged IPv4/L4 frame the
 * source port sits at Ethernet-frame byte 34 (14B Ethernet + 20B IPv4), i.e.
 * hfi2_packet byte 16 + 34 = 50, which is RSM QW 6, bit 16.  We use it as a
 * poor-man's RSS entropy source to spread flows across the reserved netdev
 * receive contexts.  TENTATIVE: this single fixed offset is only correct for
 * untagged IPv4/L4; a VLAN tag shifts it +4 and IPv6 shifts it +20, so mixed
 * traffic hashes sub-optimally.  Validate against the real wire format.
 */
#define ETH_IP_SPORT_QW 6ull
#define ETH_IP_SPORT_BIT_OFFSET 16ull
#define ETH_IP_SPORT_SELECT_OFFSET \
	((ETH_IP_SPORT_QW << QW_SHIFT) | (ETH_IP_SPORT_BIT_OFFSET))

/*
 * CN Ethernet 16B SLID field aliases the source MAC (SLID[19:0] == SMAC[19:0])
 * at hfi2_packet bit 0. Unlike ETH_IP_SPORT above, this offset is fixed regardless
 * of VLAN tagging or L3 protocol, so it is a stable RSS entropy source.
 */
#define ETH_SMAC_QW 0ull
#define ETH_SMAC_BIT_OFFSET 0ull
#define ETH_SMAC_SELECT_OFFSET \
	((ETH_SMAC_QW << QW_SHIFT) | (ETH_SMAC_BIT_OFFSET))

/* defines to build power on SC2VL table */
#define SC2VL_VAL(num, sc0, sc0val, sc1, sc1val, sc2, sc2val, sc3, sc3val, \
		  sc4, sc4val, sc5, sc5val, sc6, sc6val, sc7, sc7val)      \
	(((u64)(sc0val) << SEND_SC2VLT##num##_SC##sc0##_SHIFT) |           \
	 ((u64)(sc1val) << SEND_SC2VLT##num##_SC##sc1##_SHIFT) |           \
	 ((u64)(sc2val) << SEND_SC2VLT##num##_SC##sc2##_SHIFT) |           \
	 ((u64)(sc3val) << SEND_SC2VLT##num##_SC##sc3##_SHIFT) |           \
	 ((u64)(sc4val) << SEND_SC2VLT##num##_SC##sc4##_SHIFT) |           \
	 ((u64)(sc5val) << SEND_SC2VLT##num##_SC##sc5##_SHIFT) |           \
	 ((u64)(sc6val) << SEND_SC2VLT##num##_SC##sc6##_SHIFT) |           \
	 ((u64)(sc7val) << SEND_SC2VLT##num##_SC##sc7##_SHIFT))


/* all CceStatus sub-block TXE pause bits */
#define ALL_TXE_PAUSE                                                    \
	(CCE_STATUS_TXE_PIO_PAUSED_SMASK | CCE_STATUS_TXE_PAUSED_SMASK | \
	 CCE_STATUS_SDMA_PAUSED_SMASK)
/* all CceStatus sub-block RXE pause bits */
#define ALL_RXE_PAUSE CCE_STATUS_RXE_PAUSED_SMASK

/*
 * CCE Error flags.
 */
static const struct flag_table cce_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("CceCsrParityErr",
			   CCE_ERR_STATUS_CCE_CSR_PARITY_ERR_SMASK),
	/* 1*/
	FLAG_ENTRY0("CceCsrReadBadAddrErr",
		    CCE_ERR_STATUS_CCE_CSR_READ_BAD_ADDR_ERR_SMASK),
	/* 2*/
	FLAG_ENTRY0("CceCsrWriteBadAddrErr",
		    CCE_ERR_STATUS_CCE_CSR_WRITE_BAD_ADDR_ERR_SMASK),
	/* 3*/
	FLAG_ENTRY0("CceTrgtAsyncFifoParityErr",
		    CCE_ERR_STATUS_CCE_TRGT_ASYNC_FIFO_PARITY_ERR_SMASK),
	/* 4*/
	FLAG_ENTRY0("CceTrgtAccessErr",
		    CCE_ERR_STATUS_CCE_TRGT_ACCESS_ERR_SMASK),
	/* 5*/
	FLAG_ENTRY0("CceRspdDataParityErr",
		    CCE_ERR_STATUS_CCE_RSPD_DATA_PARITY_ERR_SMASK),
	/* 6*/
	FLAG_ENTRY0("CceCli0AsyncFifoParityErr",
		    CCE_ERR_STATUS_CCE_CLI0_ASYNC_FIFO_PARITY_ERR_SMASK),
	/* 7*/
	FLAG_ENTRY0("CceCsrCfgBusParityErr",
		    CCE_ERR_STATUS_CCE_CSR_CFG_BUS_PARITY_ERR_SMASK),
	/* 8*/
	FLAG_ENTRY0("CceCli2AsyncFifoParityErr",
		    CCE_ERR_STATUS_CCE_CLI2_ASYNC_FIFO_PARITY_ERR_SMASK),
	/* 9*/
	FLAG_ENTRY0(
		"CceCli1AsyncFifoPioCrdtParityErr",
		CCE_ERR_STATUS_CCE_CLI1_ASYNC_FIFO_PIO_CRDT_PARITY_ERR_SMASK),
	/*10*/
	FLAG_ENTRY0("CceCli1AsyncFifoPioCrdtParityErr",
		    CCE_ERR_STATUS_CCE_CLI1_ASYNC_FIFO_SDMA_HD_PARITY_ERR_SMASK),
	/*11*/
	FLAG_ENTRY0("CceCli1AsyncFifoRxdmaParityError",
		    CCE_ERR_STATUS_CCE_CLI1_ASYNC_FIFO_RXDMA_PARITY_ERROR_SMASK),
	/*12*/
	FLAG_ENTRY0("CceCli1AsyncFifoDbgParityError",
		    CCE_ERR_STATUS_CCE_CLI1_ASYNC_FIFO_DBG_PARITY_ERROR_SMASK),
	/*13*/
	FLAG_ENTRY0("PcicRetryMemCorErr",
		    CCE_ERR_STATUS_PCIC_RETRY_MEM_COR_ERR_SMASK),
	/*14*/
	FLAG_ENTRY0("PcicRetryMemCorErr",
		    CCE_ERR_STATUS_PCIC_RETRY_SOT_MEM_COR_ERR_SMASK),
	/*15*/
	FLAG_ENTRY0("PcicPostHdQCorErr",
		    CCE_ERR_STATUS_PCIC_POST_HD_QCOR_ERR_SMASK),
	/*16*/
	FLAG_ENTRY0("PcicPostHdQCorErr",
		    CCE_ERR_STATUS_PCIC_POST_DAT_QCOR_ERR_SMASK),
	/*17*/
	FLAG_ENTRY0("PcicPostHdQCorErr",
		    CCE_ERR_STATUS_PCIC_CPL_HD_QCOR_ERR_SMASK),
	/*18*/
	FLAG_ENTRY0("PcicCplDatQCorErr",
		    CCE_ERR_STATUS_PCIC_CPL_DAT_QCOR_ERR_SMASK),
	/*19*/
	FLAG_ENTRY0("PcicNPostHQParityErr",
		    CCE_ERR_STATUS_PCIC_NPOST_HQ_PARITY_ERR_SMASK),
	/*20*/
	FLAG_ENTRY0("PcicNPostDatQParityErr",
		    CCE_ERR_STATUS_PCIC_NPOST_DAT_QPARITY_ERR_SMASK),
	/*21*/
	FLAG_ENTRY0("PcicRetryMemUncErr",
		    CCE_ERR_STATUS_PCIC_RETRY_MEM_UNC_ERR_SMASK),
	/*22*/
	FLAG_ENTRY0("PcicRetrySotMemUncErr",
		    CCE_ERR_STATUS_PCIC_RETRY_SOT_MEM_UNC_ERR_SMASK),
	/*23*/
	FLAG_ENTRY0("PcicPostHdQUncErr",
		    CCE_ERR_STATUS_PCIC_POST_HD_QUNC_ERR_SMASK),
	/*24*/
	FLAG_ENTRY0("PcicPostDatQUncErr",
		    CCE_ERR_STATUS_PCIC_POST_DAT_QUNC_ERR_SMASK),
	/*25*/
	FLAG_ENTRY0("PcicCplHdQUncErr",
		    CCE_ERR_STATUS_PCIC_CPL_HD_QUNC_ERR_SMASK),
	/*26*/
	FLAG_ENTRY0("PcicCplDatQUncErr",
		    CCE_ERR_STATUS_PCIC_CPL_DAT_QUNC_ERR_SMASK),
	/*27*/
	FLAG_ENTRY0("PcicTransmitFrontParityErr",
		    CCE_ERR_STATUS_PCIC_TRANSMIT_FRONT_PARITY_ERR_SMASK),
	/*28*/
	FLAG_ENTRY0("PcicTransmitBackParityErr",
		    CCE_ERR_STATUS_PCIC_TRANSMIT_BACK_PARITY_ERR_SMASK),
	/*29*/
	FLAG_ENTRY0("PcicReceiveParityErr",
		    CCE_ERR_STATUS_PCIC_RECEIVE_PARITY_ERR_SMASK),
	/*30*/
	FLAG_ENTRY0("CceTrgtCplTimeoutErr",
		    CCE_ERR_STATUS_CCE_TRGT_CPL_TIMEOUT_ERR_SMASK),
	/*31*/ FLAG_ENTRY0("LATriggered", CCE_ERR_STATUS_LA_TRIGGERED_SMASK),
	/*32*/
	FLAG_ENTRY0("CceSegReadBadAddrErr",
		    CCE_ERR_STATUS_CCE_SEG_READ_BAD_ADDR_ERR_SMASK),
	/*33*/
	FLAG_ENTRY0("CceSegWriteBadAddrErr",
		    CCE_ERR_STATUS_CCE_SEG_WRITE_BAD_ADDR_ERR_SMASK),
	/*34*/
	FLAG_ENTRY0("CceRcplAsyncFifoParityErr",
		    CCE_ERR_STATUS_CCE_RCPL_ASYNC_FIFO_PARITY_ERR_SMASK),
	/*35*/
	FLAG_ENTRY0("CceRxdmaConvFifoParityErr",
		    CCE_ERR_STATUS_CCE_RXDMA_CONV_FIFO_PARITY_ERR_SMASK),
	/*36*/
	FLAG_ENTRY0("CceMsixTableCorErr",
		    CCE_ERR_STATUS_CCE_MSIX_TABLE_COR_ERR_SMASK),
	/*37*/
	FLAG_ENTRY0("CceMsixTableUncErr",
		    CCE_ERR_STATUS_CCE_MSIX_TABLE_UNC_ERR_SMASK),
	/*38*/
	FLAG_ENTRY0("CceIntMapCorErr",
		    CCE_ERR_STATUS_CCE_INT_MAP_COR_ERR_SMASK),
	/*39*/
	FLAG_ENTRY0("CceIntMapUncErr",
		    CCE_ERR_STATUS_CCE_INT_MAP_UNC_ERR_SMASK),
	/*40*/
	FLAG_ENTRY0("CceMsixCsrParityErr",
		    CCE_ERR_STATUS_CCE_MSIX_CSR_PARITY_ERR_SMASK),
	/*41-63 reserved*/
};

/*
 * Misc Error flags
 */
#define MES(text) MISC_ERR_STATUS_MISC_##text##_ERR_SMASK
static const struct flag_table misc_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("CSR_PARITY", MES(CSR_PARITY)),
	/* 1*/ FLAG_ENTRY0("CSR_READ_BAD_ADDR", MES(CSR_READ_BAD_ADDR)),
	/* 2*/ FLAG_ENTRY0("CSR_WRITE_BAD_ADDR", MES(CSR_WRITE_BAD_ADDR)),
	/* 3*/ FLAG_ENTRY0("SBUS_WRITE_FAILED", MES(SBUS_WRITE_FAILED)),
	/* 4*/ FLAG_ENTRY0("KEY_MISMATCH", MES(KEY_MISMATCH)),
	/* 5*/ FLAG_ENTRY0("FW_AUTH_FAILED", MES(FW_AUTH_FAILED)),
	/* 6*/ FLAG_ENTRY0("EFUSE_CSR_PARITY", MES(EFUSE_CSR_PARITY)),
	/* 7*/ FLAG_ENTRY0("EFUSE_READ_BAD_ADDR", MES(EFUSE_READ_BAD_ADDR)),
	/* 8*/ FLAG_ENTRY0("EFUSE_WRITE", MES(EFUSE_WRITE)),
	/* 9*/ FLAG_ENTRY0("EFUSE_DONE_PARITY", MES(EFUSE_DONE_PARITY)),
	/*10*/ FLAG_ENTRY0("INVALID_EEP_CMD", MES(INVALID_EEP_CMD)),
	/*11*/ FLAG_ENTRY0("MBIST_FAIL", MES(MBIST_FAIL)),
	/*12*/ FLAG_ENTRY0("PLL_LOCK_FAIL", MES(PLL_LOCK_FAIL))
};

/*
 * TXE PIO Error flags and consequences
 */
static const struct flag_table pio_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY("PioWriteBadCtxt", SEC_WRITE_DROPPED,
			  SEND_PIO_ERR_STATUS_PIO_WRITE_BAD_CTXT_ERR_SMASK),
	/* 1*/
	FLAG_ENTRY("PioWriteAddrParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_WRITE_ADDR_PARITY_ERR_SMASK),
	/* 2*/
	FLAG_ENTRY("PioCsrParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_CSR_PARITY_ERR_SMASK),
	/* 3*/
	FLAG_ENTRY("PioSbMemFifo0", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_SB_MEM_FIFO0_ERR_SMASK),
	/* 4*/
	FLAG_ENTRY("PioSbMemFifo1", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_SB_MEM_FIFO1_ERR_SMASK),
	/* 5*/
	FLAG_ENTRY("PioPccFifoParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PCC_FIFO_PARITY_ERR_SMASK),
	/* 6*/
	FLAG_ENTRY("PioPecFifoParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PEC_FIFO_PARITY_ERR_SMASK),
	/* 7*/
	FLAG_ENTRY("PioSbrdctlCrrelParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_SBRDCTL_CRREL_PARITY_ERR_SMASK),
	/* 8*/
	FLAG_ENTRY("PioSbrdctrlCrrelFifoParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_SBRDCTRL_CRREL_FIFO_PARITY_ERR_SMASK),
	/* 9*/
	FLAG_ENTRY("PioPktEvictFifoParityErr", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PKT_EVICT_FIFO_PARITY_ERR_SMASK),
	/*10*/
	FLAG_ENTRY("PioSmPktResetParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_SM_PKT_RESET_PARITY_ERR_SMASK),
	/*11*/
	FLAG_ENTRY("PioVlLenMemBank0Unc", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK0_UNC_ERR_SMASK),
	/*12*/
	FLAG_ENTRY("PioVlLenMemBank1Unc", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK1_UNC_ERR_SMASK),
	/*13*/
	FLAG_ENTRY("PioVlLenMemBank0Cor", 0,
		   SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK0_COR_ERR_SMASK),
	/*14*/
	FLAG_ENTRY("PioVlLenMemBank1Cor", 0,
		   SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK1_COR_ERR_SMASK),
	/*15*/
	FLAG_ENTRY("PioCreditRetFifoParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_CREDIT_RET_FIFO_PARITY_ERR_SMASK),
	/*16*/
	FLAG_ENTRY("PioPpmcPblFifo", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PPMC_PBL_FIFO_ERR_SMASK),
	/*17*/
	FLAG_ENTRY("PioInitSmIn", 0,
		   SEND_PIO_ERR_STATUS_PIO_INIT_SM_IN_ERR_SMASK),
	/*18*/
	FLAG_ENTRY("PioPktEvictSmOrArbSm", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PKT_EVICT_SM_OR_ARB_SM_ERR_SMASK),
	/*19*/
	FLAG_ENTRY("PioHostAddrMemUnc", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_HOST_ADDR_MEM_UNC_ERR_SMASK),
	/*20*/
	FLAG_ENTRY("PioHostAddrMemCor", 0,
		   SEND_PIO_ERR_STATUS_PIO_HOST_ADDR_MEM_COR_ERR_SMASK),
	/*21*/
	FLAG_ENTRY("PioWriteDataParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_WRITE_DATA_PARITY_ERR_SMASK),
	/*22*/
	FLAG_ENTRY("PioStateMachine", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_STATE_MACHINE_ERR_SMASK),
	/*23*/
	FLAG_ENTRY("PioWriteQwValidParity", SEC_WRITE_DROPPED | SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_WRITE_QW_VALID_PARITY_ERR_SMASK),
	/*24*/
	FLAG_ENTRY("PioBlockQwCountParity", SEC_WRITE_DROPPED | SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_BLOCK_QW_COUNT_PARITY_ERR_SMASK),
	/*25*/
	FLAG_ENTRY("PioVlfVlLenParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_VLF_VL_LEN_PARITY_ERR_SMASK),
	/*26*/
	FLAG_ENTRY("PioVlfSopParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_VLF_SOP_PARITY_ERR_SMASK),
	/*27*/
	FLAG_ENTRY("PioVlFifoParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_VL_FIFO_PARITY_ERR_SMASK),
	/*28*/
	FLAG_ENTRY("PioPpmcBqcMemParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PPMC_BQC_MEM_PARITY_ERR_SMASK),
	/*29*/
	FLAG_ENTRY("PioPpmcSopLen", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PPMC_SOP_LEN_ERR_SMASK),
	/*30-31 reserved*/
	/*32*/
	FLAG_ENTRY("PioCurrentFreeCntParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_CURRENT_FREE_CNT_PARITY_ERR_SMASK),
	/*33*/
	FLAG_ENTRY("PioLastReturnedCntParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_LAST_RETURNED_CNT_PARITY_ERR_SMASK),
	/*34*/
	FLAG_ENTRY("PioPccSopHeadParity", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PCC_SOP_HEAD_PARITY_ERR_SMASK),
	/*35*/
	FLAG_ENTRY("PioPecSopHeadParityErr", SEC_SPC_FREEZE,
		   SEND_PIO_ERR_STATUS_PIO_PEC_SOP_HEAD_PARITY_ERR_SMASK),
	/*36-63 reserved*/
};

/* TXE PIO errors that cause an SPC freeze */
#define ALL_PIO_FREEZE_ERR                                              \
	(SEND_PIO_ERR_STATUS_PIO_WRITE_ADDR_PARITY_ERR_SMASK |          \
	 SEND_PIO_ERR_STATUS_PIO_CSR_PARITY_ERR_SMASK |                 \
	 SEND_PIO_ERR_STATUS_PIO_SB_MEM_FIFO0_ERR_SMASK |               \
	 SEND_PIO_ERR_STATUS_PIO_SB_MEM_FIFO1_ERR_SMASK |               \
	 SEND_PIO_ERR_STATUS_PIO_PCC_FIFO_PARITY_ERR_SMASK |            \
	 SEND_PIO_ERR_STATUS_PIO_PEC_FIFO_PARITY_ERR_SMASK |            \
	 SEND_PIO_ERR_STATUS_PIO_SBRDCTL_CRREL_PARITY_ERR_SMASK |       \
	 SEND_PIO_ERR_STATUS_PIO_SBRDCTRL_CRREL_FIFO_PARITY_ERR_SMASK | \
	 SEND_PIO_ERR_STATUS_PIO_PKT_EVICT_FIFO_PARITY_ERR_SMASK |      \
	 SEND_PIO_ERR_STATUS_PIO_SM_PKT_RESET_PARITY_ERR_SMASK |        \
	 SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK0_UNC_ERR_SMASK |       \
	 SEND_PIO_ERR_STATUS_PIO_VL_LEN_MEM_BANK1_UNC_ERR_SMASK |       \
	 SEND_PIO_ERR_STATUS_PIO_CREDIT_RET_FIFO_PARITY_ERR_SMASK |     \
	 SEND_PIO_ERR_STATUS_PIO_PPMC_PBL_FIFO_ERR_SMASK |              \
	 SEND_PIO_ERR_STATUS_PIO_PKT_EVICT_SM_OR_ARB_SM_ERR_SMASK |     \
	 SEND_PIO_ERR_STATUS_PIO_HOST_ADDR_MEM_UNC_ERR_SMASK |          \
	 SEND_PIO_ERR_STATUS_PIO_WRITE_DATA_PARITY_ERR_SMASK |          \
	 SEND_PIO_ERR_STATUS_PIO_STATE_MACHINE_ERR_SMASK |              \
	 SEND_PIO_ERR_STATUS_PIO_WRITE_QW_VALID_PARITY_ERR_SMASK |      \
	 SEND_PIO_ERR_STATUS_PIO_BLOCK_QW_COUNT_PARITY_ERR_SMASK |      \
	 SEND_PIO_ERR_STATUS_PIO_VLF_VL_LEN_PARITY_ERR_SMASK |          \
	 SEND_PIO_ERR_STATUS_PIO_VLF_SOP_PARITY_ERR_SMASK |             \
	 SEND_PIO_ERR_STATUS_PIO_VL_FIFO_PARITY_ERR_SMASK |             \
	 SEND_PIO_ERR_STATUS_PIO_PPMC_BQC_MEM_PARITY_ERR_SMASK |        \
	 SEND_PIO_ERR_STATUS_PIO_PPMC_SOP_LEN_ERR_SMASK |               \
	 SEND_PIO_ERR_STATUS_PIO_CURRENT_FREE_CNT_PARITY_ERR_SMASK |    \
	 SEND_PIO_ERR_STATUS_PIO_LAST_RETURNED_CNT_PARITY_ERR_SMASK |   \
	 SEND_PIO_ERR_STATUS_PIO_PCC_SOP_HEAD_PARITY_ERR_SMASK |        \
	 SEND_PIO_ERR_STATUS_PIO_PEC_SOP_HEAD_PARITY_ERR_SMASK)

/*
 * TXE SDMA Error flags
 */
static const struct flag_table sdma_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("SDmaRpyTagErr",
			   SEND_DMA_ERR_STATUS_SDMA_RPY_TAG_ERR_SMASK),
	/* 1*/
	FLAG_ENTRY0("SDmaCsrParityErr",
		    SEND_DMA_ERR_STATUS_SDMA_CSR_PARITY_ERR_SMASK),
	/* 2*/
	FLAG_ENTRY0("SDmaPcieReqTrackingUncErr",
		    SEND_DMA_ERR_STATUS_SDMA_PCIE_REQ_TRACKING_UNC_ERR_SMASK),
	/* 3*/
	FLAG_ENTRY0("SDmaPcieReqTrackingCorErr",
		    SEND_DMA_ERR_STATUS_SDMA_PCIE_REQ_TRACKING_COR_ERR_SMASK),
	/*04-63 reserved*/
};

/* TXE SDMA errors that cause an SPC freeze */
#define ALL_SDMA_FREEZE_ERR                              \
	(SEND_DMA_ERR_STATUS_SDMA_RPY_TAG_ERR_SMASK |    \
	 SEND_DMA_ERR_STATUS_SDMA_CSR_PARITY_ERR_SMASK | \
	 SEND_DMA_ERR_STATUS_SDMA_PCIE_REQ_TRACKING_UNC_ERR_SMASK)

/*
 * TXE Egress Error flags
 */
#define SEES(text) SEND_EGRESS_ERR_STATUS_##text##_ERR_SMASK
static const struct flag_table egress_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("TxPktIntegrityMemCorErr",
			   SEES(TX_PKT_INTEGRITY_MEM_COR)), /* WFR */
	/* 1*/
	FLAG_ENTRY0("TxPktIntegrityMemUncErr",
		    SEES(TX_PKT_INTEGRITY_MEM_UNC)), /* WFR */
	/* 2 reserved */
	/* 3*/
	FLAG_ENTRY0("TxEgressFifoUnderrunOrParityErr",
		    SEES(TX_EGRESS_FIFO_UNDERRUN_OR_PARITY)),
	/* 4*/ FLAG_ENTRY0("TxLinkdownErr", SEES(TX_LINKDOWN)),
	/* 5*/
	FLAG_ENTRY0("TxIncorrectLinkStateErr", SEES(TX_INCORRECT_LINK_STATE)),
	/* 6 reserved */
	/* 7*/
	FLAG_ENTRY0("TxPioLaunchIntfParityErr",
		    SEES(TX_PIO_LAUNCH_INTF_PARITY)),
	/* 8*/
	FLAG_ENTRY0("TxSdmaLaunchIntfParityErr",
		    SEES(TX_SDMA_LAUNCH_INTF_PARITY)),
	/* 9-10 reserved */
	/*11*/
	FLAG_ENTRY0("TxSbrdCtlStateMachineParityErr",
		    SEES(TX_SBRD_CTL_STATE_MACHINE_PARITY)),
	/*12*/ FLAG_ENTRY0("TxIllegalVLErr", SEES(TX_ILLEGAL_VL)),
	/*13*/ FLAG_ENTRY0("TxLaunchCsrParityErr", SEES(TX_LAUNCH_CSR_PARITY)), /* WFR */
	/*14*/ FLAG_ENTRY0("TxSbrdCtlCsrParityErr", SEES(TX_SBRD_CTL_CSR_PARITY)),
	/*15*/ FLAG_ENTRY0("TxConfigParityErr", SEES(TX_CONFIG_PARITY)),
	/*16*/
	FLAG_ENTRY0("TxSdma0DisallowedPacketErr",
		    SEES(TX_SDMA0_DISALLOWED_PACKET)),
	/*17*/
	FLAG_ENTRY0("TxSdma1DisallowedPacketErr",
		    SEES(TX_SDMA1_DISALLOWED_PACKET)),
	/*18*/
	FLAG_ENTRY0("TxSdma2DisallowedPacketErr",
		    SEES(TX_SDMA2_DISALLOWED_PACKET)),
	/*19*/
	FLAG_ENTRY0("TxSdma3DisallowedPacketErr",
		    SEES(TX_SDMA3_DISALLOWED_PACKET)),
	/*20*/
	FLAG_ENTRY0("TxSdma4DisallowedPacketErr",
		    SEES(TX_SDMA4_DISALLOWED_PACKET)),
	/*21*/
	FLAG_ENTRY0("TxSdma5DisallowedPacketErr",
		    SEES(TX_SDMA5_DISALLOWED_PACKET)),
	/*22*/
	FLAG_ENTRY0("TxSdma6DisallowedPacketErr",
		    SEES(TX_SDMA6_DISALLOWED_PACKET)),
	/*23*/
	FLAG_ENTRY0("TxSdma7DisallowedPacketErr",
		    SEES(TX_SDMA7_DISALLOWED_PACKET)),
	/*24*/
	FLAG_ENTRY0("TxSdma8DisallowedPacketErr",
		    SEES(TX_SDMA8_DISALLOWED_PACKET)),
	/*25*/
	FLAG_ENTRY0("TxSdma9DisallowedPacketErr",
		    SEES(TX_SDMA9_DISALLOWED_PACKET)),
	/*26*/
	FLAG_ENTRY0("TxSdma10DisallowedPacketErr",
		    SEES(TX_SDMA10_DISALLOWED_PACKET)),
	/*27*/
	FLAG_ENTRY0("TxSdma11DisallowedPacketErr",
		    SEES(TX_SDMA11_DISALLOWED_PACKET)),
	/*28*/
	FLAG_ENTRY0("TxSdma12DisallowedPacketErr",
		    SEES(TX_SDMA12_DISALLOWED_PACKET)),
	/*29*/
	FLAG_ENTRY0("TxSdma13DisallowedPacketErr",
		    SEES(TX_SDMA13_DISALLOWED_PACKET)),
	/*30*/
	FLAG_ENTRY0("TxSdma14DisallowedPacketErr",
		    SEES(TX_SDMA14_DISALLOWED_PACKET)),
	/*31*/
	FLAG_ENTRY0("TxSdma15DisallowedPacketErr",
		    SEES(TX_SDMA15_DISALLOWED_PACKET)),
	/*32*/
	FLAG_ENTRY0("TxLaunchFifo0UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO0_UNC_OR_PARITY)),
	/*33*/
	FLAG_ENTRY0("TxLaunchFifo1UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO1_UNC_OR_PARITY)),
	/*34*/
	FLAG_ENTRY0("TxLaunchFifo2UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO2_UNC_OR_PARITY)),
	/*35*/
	FLAG_ENTRY0("TxLaunchFifo3UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO3_UNC_OR_PARITY)),
	/*36*/
	FLAG_ENTRY0("TxLaunchFifo4UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO4_UNC_OR_PARITY)),
	/*37*/
	FLAG_ENTRY0("TxLaunchFifo5UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO5_UNC_OR_PARITY)),
	/*38*/
	FLAG_ENTRY0("TxLaunchFifo6UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO6_UNC_OR_PARITY)),
	/*39*/
	FLAG_ENTRY0("TxLaunchFifo7UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO7_UNC_OR_PARITY)),
	/*40*/
	FLAG_ENTRY0("TxLaunchFifo8UncOrParityErr",
		    SEES(TX_LAUNCH_FIFO8_UNC_OR_PARITY)),
	/*41*/
	FLAG_ENTRY0("TxCreditReturnParityErr", SEES(TX_CREDIT_RETURN_PARITY)),
	/*42*/ FLAG_ENTRY0("TxSbHdrUncErr", SEES(TX_SB_HDR_UNC)),
	/*43*/ FLAG_ENTRY0("TxReadSdmaMemoryUncErr", SEES(TX_READ_SDMA_MEMORY_UNC)),
	/*44*/ FLAG_ENTRY0("TxReadPioMemoryUncErr", SEES(TX_READ_PIO_MEMORY_UNC)),
	/*45*/ FLAG_ENTRY0("TxEgressFifoUncErr", SEES(TX_EGRESS_FIFO_UNC)),
	/*46*/ FLAG_ENTRY0("TxHcrcInsertionErr", SEES(TX_HCRC_INSERTION)),
	/*47*/ FLAG_ENTRY0("TxCreditReturnVLErr", SEES(TX_CREDIT_RETURN_VL)),
	/*48*/ FLAG_ENTRY0("TxLaunchFifo0CorErr", SEES(TX_LAUNCH_FIFO0_COR)),
	/*49*/ FLAG_ENTRY0("TxLaunchFifo1CorErr", SEES(TX_LAUNCH_FIFO1_COR)),
	/*50*/ FLAG_ENTRY0("TxLaunchFifo2CorErr", SEES(TX_LAUNCH_FIFO2_COR)),
	/*51*/ FLAG_ENTRY0("TxLaunchFifo3CorErr", SEES(TX_LAUNCH_FIFO3_COR)),
	/*52*/ FLAG_ENTRY0("TxLaunchFifo4CorErr", SEES(TX_LAUNCH_FIFO4_COR)),
	/*53*/ FLAG_ENTRY0("TxLaunchFifo5CorErr", SEES(TX_LAUNCH_FIFO5_COR)),
	/*54*/ FLAG_ENTRY0("TxLaunchFifo6CorErr", SEES(TX_LAUNCH_FIFO6_COR)),
	/*55*/ FLAG_ENTRY0("TxLaunchFifo7CorErr", SEES(TX_LAUNCH_FIFO7_COR)),
	/*56*/ FLAG_ENTRY0("TxLaunchFifo8CorErr", SEES(TX_LAUNCH_FIFO8_COR)),
	/*57*/ FLAG_ENTRY0("TxCreditOverrunErr", SEES(TX_CREDIT_OVERRUN)),
	/*58*/ FLAG_ENTRY0("TxSbHdrCorErr", SEES(TX_SB_HDR_COR)),
	/*59*/ FLAG_ENTRY0("TxReadSdmaMemoryCorErr", SEES(TX_READ_SDMA_MEMORY_COR)),
	/*60*/ FLAG_ENTRY0("TxReadPioMemoryCorErr", SEES(TX_READ_PIO_MEMORY_COR)),
	/*61*/ FLAG_ENTRY0("TxEgressFifoCorErr", SEES(TX_EGRESS_FIFO_COR)),
	/*62*/
	FLAG_ENTRY0("TxReadSdmaMemoryCsrUncErr",
		    SEES(TX_READ_SDMA_MEMORY_CSR_UNC)), /* WFR */
	/*63*/
	FLAG_ENTRY0("TxReadPioMemoryCsrUncErr",
		    SEES(TX_READ_PIO_MEMORY_CSR_UNC)), /* WFR */
};

/*
 * TXE Egress Error Info flags
 */
#define SEEI(text) SEND_EGRESS_ERR_INFO_##text##_ERR_SMASK
static const struct flag_table wfr_egress_err_info_flags[] = {
	/* 0*/ FLAG_ENTRY0("Reserved", 0ull),
	/* 1*/ FLAG_ENTRY0("VLErr", SEEI(VL)),
	/* 2*/ FLAG_ENTRY0("JobKeyErr", SEEI(JOB_KEY)),
	/* 3*/ FLAG_ENTRY0("JobKeyErr", SEEI(JOB_KEY)),
	/* 4*/ FLAG_ENTRY0("PartitionKeyErr", SEEI(PARTITION_KEY)),
	/* 5*/ FLAG_ENTRY0("SLIDErr", SEEI(SLID)),
	/* 6*/ FLAG_ENTRY0("OpcodeErr", SEEI(OPCODE)),
	/* 7*/ FLAG_ENTRY0("VLMappingErr", SEEI(VL_MAPPING)),
	/* 8*/ FLAG_ENTRY0("RawErr", SEEI(RAW)),
	/* 9*/ FLAG_ENTRY0("RawIPv6Err", SEEI(RAW_IPV6)),
	/*10*/ FLAG_ENTRY0("GRHErr", SEEI(GRH)),
	/*11*/ FLAG_ENTRY0("BypassErr", SEEI(BYPASS)),
	/*12*/ FLAG_ENTRY0("KDETHPacketsErr", SEEI(KDETH_PACKETS)),
	/*13*/ FLAG_ENTRY0("NonKDETHPacketsErr", SEEI(NON_KDETH_PACKETS)),
	/*14*/ FLAG_ENTRY0("TooSmallIBPacketsErr", SEEI(TOO_SMALL_IB_PACKETS)),
	/*15*/
	FLAG_ENTRY0("TooSmallBypassPacketsErr", SEEI(TOO_SMALL_BYPASS_PACKETS)),
	/*16*/ FLAG_ENTRY0("PbcTestErr", SEEI(PBC_TEST)),
	/*17*/ FLAG_ENTRY0("BadPktLenErr", SEEI(BAD_PKT_LEN)),
	/*18*/ FLAG_ENTRY0("TooLongIBPacketErr", SEEI(TOO_LONG_IB_PACKET)),
	/*19*/
	FLAG_ENTRY0("TooLongBypassPacketsErr", SEEI(TOO_LONG_BYPASS_PACKETS)),
	/*20*/
	FLAG_ENTRY0("PbcStaticRateControlErr", SEEI(PBC_STATIC_RATE_CONTROL)),
	/*21*/ FLAG_ENTRY0("BypassBadPktLenErr", SEEI(BAD_PKT_LEN)),
};
const struct flag_data hfi2_wfr_egress_err_info_data = {
	.table = wfr_egress_err_info_flags,
	.size = ARRAY_SIZE(wfr_egress_err_info_flags),
};

/* TXE Egress errors that cause an SPC freeze */
#define ALL_TXE_EGRESS_FREEZE_ERR                                              \
	(SEES(TX_EGRESS_FIFO_UNDERRUN_OR_PARITY) |                             \
	 SEES(TX_PIO_LAUNCH_INTF_PARITY) | SEES(TX_SDMA_LAUNCH_INTF_PARITY) |  \
	 SEES(TX_SBRD_CTL_STATE_MACHINE_PARITY) | SEES(TX_LAUNCH_CSR_PARITY) | \
	 SEES(TX_SBRD_CTL_CSR_PARITY) | SEES(TX_CONFIG_PARITY) |               \
	 SEES(TX_LAUNCH_FIFO0_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO1_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO2_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO3_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO4_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO5_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO6_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO7_UNC_OR_PARITY) |                                 \
	 SEES(TX_LAUNCH_FIFO8_UNC_OR_PARITY) | SEES(TX_CREDIT_RETURN_PARITY))

/*
 * TXE Send error flags
 */
#define SES(name) SEND_ERR_STATUS_SEND_##name##_ERR_SMASK
static const struct flag_table send_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("SendCsrParityErr", SES(CSR_PARITY)),
	/* 1*/ FLAG_ENTRY0("SendCsrReadBadAddrErr", SES(CSR_READ_BAD_ADDR)),
	/* 2*/ FLAG_ENTRY0("SendCsrWriteBadAddrErr", SES(CSR_WRITE_BAD_ADDR))
};

/*
 * TXE Send Context Error flags and consequences
 */
static const struct flag_table sc_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY("InconsistentSop", SEC_PACKET_DROPPED | SEC_SC_HALTED,
			  SEND_CTXT_ERR_STATUS_PIO_INCONSISTENT_SOP_ERR_SMASK),
	/* 1*/
	FLAG_ENTRY("DisallowedPacket", SEC_PACKET_DROPPED | SEC_SC_HALTED,
		   SEND_CTXT_ERR_STATUS_PIO_DISALLOWED_PACKET_ERR_SMASK),
	/* 2*/
	FLAG_ENTRY("WriteCrossesBoundary", SEC_WRITE_DROPPED | SEC_SC_HALTED,
		   SEND_CTXT_ERR_STATUS_PIO_WRITE_CROSSES_BOUNDARY_ERR_SMASK),
	/* 3*/
	FLAG_ENTRY("WriteOverflow", SEC_WRITE_DROPPED | SEC_SC_HALTED,
		   SEND_CTXT_ERR_STATUS_PIO_WRITE_OVERFLOW_ERR_SMASK),
	/* 4*/
	FLAG_ENTRY("WriteOutOfBounds", SEC_WRITE_DROPPED | SEC_SC_HALTED,
		   SEND_CTXT_ERR_STATUS_PIO_WRITE_OUT_OF_BOUNDS_ERR_SMASK),
	/* 5-63 reserved*/
};

/*
 * RXE Receive Error flags
 */
#define RXES(name) RCV_ERR_STATUS_RX_##name##_ERR_SMASK
static const struct flag_table rxe_err_status_flags[] = {
	/* 0*/ FLAG_ENTRY0("RxDmaCsrCorErr", RXES(DMA_CSR_COR)),
	/* 1*/ FLAG_ENTRY0("RxCrkIntfParityErr", RXES(DC_INTF_PARITY)),
	/* 2*/ FLAG_ENTRY0("RxRcvHdrUncErr", RXES(RCV_HDR_UNC)),
	/* 3*/ FLAG_ENTRY0("RxRcvHdrCorErr", RXES(RCV_HDR_COR)),
	/* 4*/ FLAG_ENTRY0("RxRcvDataUncErr", RXES(RCV_DATA_UNC)),
	/* 5*/ FLAG_ENTRY0("RxRcvDataCorErr", RXES(RCV_DATA_COR)),
	/* 6*/ FLAG_ENTRY0("RxRcvQpMapTableUncErr", RXES(RCV_QP_MAP_TABLE_UNC)),
	/* 7*/ FLAG_ENTRY0("RxRcvQpMapTableCorErr", RXES(RCV_QP_MAP_TABLE_COR)),
	/* 8*/ FLAG_ENTRY0("RxRcvCsrParityErr", RXES(RCV_CSR_PARITY)),
	/* 9*/ FLAG_ENTRY0("RxCrkSopEopParityErr", RXES(DC_SOP_EOP_PARITY)),
	/*10*/ FLAG_ENTRY0("RxDmaFlagUncErr", RXES(DMA_FLAG_UNC)),
	/*11*/ FLAG_ENTRY0("RxDmaFlagCorErr", RXES(DMA_FLAG_COR)),
	/*12*/ FLAG_ENTRY0("RxRcvFsmEncodingErr", RXES(RCV_FSM_ENCODING)),
	/*13*/ FLAG_ENTRY0("RxRbufFreeListUncErr", RXES(RBUF_FREE_LIST_UNC)),
	/*14*/ FLAG_ENTRY0("RxRbufFreeListCorErr", RXES(RBUF_FREE_LIST_COR)),
	/*15*/
	FLAG_ENTRY0("RxRbufLookupDesRegUncErr", RXES(RBUF_LOOKUP_DES_REG_UNC)),
	/*16*/
	FLAG_ENTRY0("RxRbufLookupDesRegUncCorErr",
		    RXES(RBUF_LOOKUP_DES_REG_UNC_COR)),
	/*17*/ FLAG_ENTRY0("RxRbufLookupDesUncErr", RXES(RBUF_LOOKUP_DES_UNC)),
	/*18*/ FLAG_ENTRY0("RxRbufLookupDesCorErr", RXES(RBUF_LOOKUP_DES_COR)),
	/*19*/
	FLAG_ENTRY0("RxRbufBlockListReadUncErr",
		    RXES(RBUF_BLOCK_LIST_READ_UNC)),
	/*20*/
	FLAG_ENTRY0("RxRbufBlockListReadCorErr",
		    RXES(RBUF_BLOCK_LIST_READ_COR)),
	/*21*/
	FLAG_ENTRY0("RxRbufCsrQHeadBufNumParityErr",
		    RXES(RBUF_CSR_QHEAD_BUF_NUM_PARITY)),
	/*22*/
	FLAG_ENTRY0("RxRbufCsrQEntCntParityErr",
		    RXES(RBUF_CSR_QENT_CNT_PARITY)),
	/*23*/
	FLAG_ENTRY0("RxRbufCsrQNextBufParityErr",
		    RXES(RBUF_CSR_QNEXT_BUF_PARITY)),
	/*24*/
	FLAG_ENTRY0("RxRbufCsrQVldBitParityErr",
		    RXES(RBUF_CSR_QVLD_BIT_PARITY)),
	/*25*/
	FLAG_ENTRY0("RxRbufCsrQHdPtrParityErr", RXES(RBUF_CSR_QHD_PTR_PARITY)),
	/*26*/
	FLAG_ENTRY0("RxRbufCsrQTlPtrParityErr", RXES(RBUF_CSR_QTL_PTR_PARITY)),
	/*27*/
	FLAG_ENTRY0("RxRbufCsrQNumOfPktParityErr",
		    RXES(RBUF_CSR_QNUM_OF_PKT_PARITY)),
	/*28*/
	FLAG_ENTRY0("RxRbufCsrQEOPDWParityErr", RXES(RBUF_CSR_QEOPDW_PARITY)),
	/*29*/ FLAG_ENTRY0("RxRbufCtxIdParityErr", RXES(RBUF_CTX_ID_PARITY)),
	/*30*/ FLAG_ENTRY0("RxRBufBadLookupErr", RXES(RBUF_BAD_LOOKUP)),
	/*31*/ FLAG_ENTRY0("RxRbufFullErr", RXES(RBUF_FULL)),
	/*32*/ FLAG_ENTRY0("RxRbufEmptyErr", RXES(RBUF_EMPTY)),
	/*33*/ FLAG_ENTRY0("RxRbufFlRdAddrParityErr", RXES(RBUF_FL_RD_ADDR_PARITY)),
	/*34*/ FLAG_ENTRY0("RxRbufFlWrAddrParityErr", RXES(RBUF_FL_WR_ADDR_PARITY)),
	/*35*/
	FLAG_ENTRY0("RxRbufFlInitdoneParityErr", RXES(RBUF_FL_INITDONE_PARITY)),
	/*36*/
	FLAG_ENTRY0("RxRbufFlInitWrAddrParityErr",
		    RXES(RBUF_FL_INIT_WR_ADDR_PARITY)),
	/*37*/ FLAG_ENTRY0("RxRbufNextFreeBufUncErr", RXES(RBUF_NEXT_FREE_BUF_UNC)),
	/*38*/ FLAG_ENTRY0("RxRbufNextFreeBufCorErr", RXES(RBUF_NEXT_FREE_BUF_COR)),
	/*39*/ FLAG_ENTRY0("RxLookupDesPart1UncErr", RXES(LOOKUP_DES_PART1_UNC)),
	/*40*/
	FLAG_ENTRY0("RxLookupDesPart1UncCorErr",
		    RXES(LOOKUP_DES_PART1_UNC_COR)),
	/*41*/
	FLAG_ENTRY0("RxLookupDesPart2ParityErr", RXES(LOOKUP_DES_PART2_PARITY)),
	/*42*/ FLAG_ENTRY0("RxLookupRcvArrayUncErr", RXES(LOOKUP_RCV_ARRAY_UNC)),
	/*43*/ FLAG_ENTRY0("RxLookupRcvArrayCorErr", RXES(LOOKUP_RCV_ARRAY_COR)),
	/*44*/ FLAG_ENTRY0("RxLookupCsrParityErr", RXES(LOOKUP_CSR_PARITY)),
	/*45*/ FLAG_ENTRY0("RxHqIntrCsrParityErr", RXES(HQ_INTR_CSR_PARITY)),
	/*46*/ FLAG_ENTRY0("RxHqIntrFsmErr", RXES(HQ_INTR_FSM)),
	/*47*/ FLAG_ENTRY0("RxRbufDescPart1UncErr", RXES(RBUF_DESC_PART1_UNC)),
	/*48*/ FLAG_ENTRY0("RxRbufDescPart1CorErr", RXES(RBUF_DESC_PART1_COR)),
	/*49*/ FLAG_ENTRY0("RxRbufDescPart2UncErr", RXES(RBUF_DESC_PART2_UNC)),
	/*50*/ FLAG_ENTRY0("RxRbufDescPart2CorErr", RXES(RBUF_DESC_PART2_COR)),
	/*51*/ FLAG_ENTRY0("RxDmaHdrFifoRdUncErr", RXES(DMA_HDR_FIFO_RD_UNC)),
	/*52*/ FLAG_ENTRY0("RxDmaHdrFifoRdCorErr", RXES(DMA_HDR_FIFO_RD_COR)),
	/*53*/ FLAG_ENTRY0("RxDmaDataFifoRdUncErr", RXES(DMA_DATA_FIFO_RD_UNC)),
	/*54*/ FLAG_ENTRY0("RxDmaDataFifoRdCorErr", RXES(DMA_DATA_FIFO_RD_COR)),
	/*55*/ FLAG_ENTRY0("RxRbufDataUncErr", RXES(RBUF_DATA_UNC)),
	/*56*/ FLAG_ENTRY0("RxRbufDataCorErr", RXES(RBUF_DATA_COR)),
	/*57*/ FLAG_ENTRY0("RxDmaCsrParityErr", RXES(DMA_CSR_PARITY)),
	/*58*/ FLAG_ENTRY0("RxDmaEqFsmEncodingErr", RXES(DMA_EQ_FSM_ENCODING)),
	/*59*/ FLAG_ENTRY0("RxDmaDqFsmEncodingErr", RXES(DMA_DQ_FSM_ENCODING)),
	/*60*/ FLAG_ENTRY0("RxDmaCsrUncErr", RXES(DMA_CSR_UNC)),
	/*61*/ FLAG_ENTRY0("RxCsrReadBadAddrErr", RXES(CSR_READ_BAD_ADDR)),
	/*62*/ FLAG_ENTRY0("RxCsrWriteBadAddrErr", RXES(CSR_WRITE_BAD_ADDR)), /* WFR */
	/*63*/ FLAG_ENTRY0("RxCsrParityErr", RXES(CSR_PARITY)) /* WFR */
};

/* RXE errors that will trigger an SPC freeze */
#define ALL_RXE_FREEZE_ERR                                           \
	(RCV_ERR_STATUS_RX_RCV_QP_MAP_TABLE_UNC_ERR_SMASK |          \
	 RCV_ERR_STATUS_RX_RCV_CSR_PARITY_ERR_SMASK |                \
	 RCV_ERR_STATUS_RX_DMA_FLAG_UNC_ERR_SMASK |                  \
	 RCV_ERR_STATUS_RX_RCV_FSM_ENCODING_ERR_SMASK |              \
	 RCV_ERR_STATUS_RX_RBUF_FREE_LIST_UNC_ERR_SMASK |            \
	 RCV_ERR_STATUS_RX_RBUF_LOOKUP_DES_REG_UNC_ERR_SMASK |       \
	 RCV_ERR_STATUS_RX_RBUF_LOOKUP_DES_REG_UNC_COR_ERR_SMASK |   \
	 RCV_ERR_STATUS_RX_RBUF_LOOKUP_DES_UNC_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_RBUF_BLOCK_LIST_READ_UNC_ERR_SMASK |      \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QHEAD_BUF_NUM_PARITY_ERR_SMASK | \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QENT_CNT_PARITY_ERR_SMASK |      \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QNEXT_BUF_PARITY_ERR_SMASK |     \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QVLD_BIT_PARITY_ERR_SMASK |      \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QHD_PTR_PARITY_ERR_SMASK |       \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QTL_PTR_PARITY_ERR_SMASK |       \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QNUM_OF_PKT_PARITY_ERR_SMASK |   \
	 RCV_ERR_STATUS_RX_RBUF_CSR_QEOPDW_PARITY_ERR_SMASK |        \
	 RCV_ERR_STATUS_RX_RBUF_CTX_ID_PARITY_ERR_SMASK |            \
	 RCV_ERR_STATUS_RX_RBUF_BAD_LOOKUP_ERR_SMASK |               \
	 RCV_ERR_STATUS_RX_RBUF_FULL_ERR_SMASK |                     \
	 RCV_ERR_STATUS_RX_RBUF_EMPTY_ERR_SMASK |                    \
	 RCV_ERR_STATUS_RX_RBUF_FL_RD_ADDR_PARITY_ERR_SMASK |        \
	 RCV_ERR_STATUS_RX_RBUF_FL_WR_ADDR_PARITY_ERR_SMASK |        \
	 RCV_ERR_STATUS_RX_RBUF_FL_INITDONE_PARITY_ERR_SMASK |       \
	 RCV_ERR_STATUS_RX_RBUF_FL_INIT_WR_ADDR_PARITY_ERR_SMASK |   \
	 RCV_ERR_STATUS_RX_RBUF_NEXT_FREE_BUF_UNC_ERR_SMASK |        \
	 RCV_ERR_STATUS_RX_LOOKUP_DES_PART1_UNC_ERR_SMASK |          \
	 RCV_ERR_STATUS_RX_LOOKUP_DES_PART1_UNC_COR_ERR_SMASK |      \
	 RCV_ERR_STATUS_RX_LOOKUP_DES_PART2_PARITY_ERR_SMASK |       \
	 RCV_ERR_STATUS_RX_LOOKUP_RCV_ARRAY_UNC_ERR_SMASK |          \
	 RCV_ERR_STATUS_RX_LOOKUP_CSR_PARITY_ERR_SMASK |             \
	 RCV_ERR_STATUS_RX_HQ_INTR_CSR_PARITY_ERR_SMASK |            \
	 RCV_ERR_STATUS_RX_HQ_INTR_FSM_ERR_SMASK |                   \
	 RCV_ERR_STATUS_RX_RBUF_DESC_PART1_UNC_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_RBUF_DESC_PART1_COR_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_RBUF_DESC_PART2_UNC_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_DMA_HDR_FIFO_RD_UNC_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_DMA_DATA_FIFO_RD_UNC_ERR_SMASK |          \
	 RCV_ERR_STATUS_RX_RBUF_DATA_UNC_ERR_SMASK |                 \
	 RCV_ERR_STATUS_RX_DMA_CSR_PARITY_ERR_SMASK |                \
	 RCV_ERR_STATUS_RX_DMA_EQ_FSM_ENCODING_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_DMA_DQ_FSM_ENCODING_ERR_SMASK |           \
	 RCV_ERR_STATUS_RX_DMA_CSR_UNC_ERR_SMASK |                   \
	 RCV_ERR_STATUS_RX_CSR_PARITY_ERR_SMASK)

#define RXE_FREEZE_ABORT_MASK                              \
	(RCV_ERR_STATUS_RX_DMA_CSR_UNC_ERR_SMASK |         \
	 RCV_ERR_STATUS_RX_DMA_HDR_FIFO_RD_UNC_ERR_SMASK | \
	 RCV_ERR_STATUS_RX_DMA_DATA_FIFO_RD_UNC_ERR_SMASK)

/*
 * DCC Error Flags
 */

/*
 * LCB error flags
 */

/*
 * DC8051 Error Flags
 */

/*
 * DC8051 Information Error flags
 *
 * Flags in DC8051_DBG_ERR_INFO_SET_BY_8051.ERROR field.
 */

/*
 * DC8051 Information Host Information flags
 *
 * Flags in DC8051_DBG_ERR_INFO_SET_BY_8051.HOST_MSG field.
 */

static u32 chip_to_opa_lstate(struct hfi2_devdata *dd, u32 chip_lstate);
int hfi2_set_physical_link_state(struct hfi2_devdata *dd, u64 state);
void hfi2_read_vc_remote_phy(struct hfi2_devdata *dd, u8 *power_management,
			       u8 *continuous);
void hfi2_read_vc_remote_fabric(struct hfi2_devdata *dd, u8 *vau, u8 *z,
				  u8 *vcu, u16 *vl15buf, u8 *crc_sizes);
void hfi2_read_vc_remote_link_width(struct hfi2_devdata *dd,
				      u8 *remote_tx_rate, u16 *link_widths);
void hfi2_read_vc_local_link_mode(struct hfi2_devdata *dd, u8 *misc_bits,
				    u8 *flag_bits, u16 *link_widths);
void hfi2_read_remote_device_id(struct hfi2_devdata *dd, u16 *device_id,
				  u8 *device_rev);
void hfi2_read_local_lni(struct hfi2_devdata *dd, u8 *enable_lane_rx);
int hfi2_read_tx_settings(struct hfi2_devdata *dd, u8 *enable_lane_tx,
			    u8 *tx_polarity_inversion,
			    u8 *rx_polarity_inversion, u8 *max_rate);
static void handle_qsfp_int(struct hfi2_devdata *dd, u32 source, u64 reg);
void hfi2_handle_dcc_err(struct hfi2_devdata *dd, unsigned int context,
			   u64 err_status);
void hfi2_handle_lcb_err(struct hfi2_devdata *dd, unsigned int context,
			   u64 err_status);
void hfi2_handle_8051_interrupt(struct hfi2_devdata *dd, u32 unused, u64 reg);
static void handle_cce_err(struct hfi2_devdata *dd, u32 unused, u64 reg);
static void handle_misc_err(struct hfi2_devdata *dd, u32 unused, u64 reg);
static void handle_txe_err(struct hfi2_devdata *dd, u32 unused, u64 reg);
void hfi2_set_partition_keys(struct hfi2_pportdata *ppd);
int hfi2_do_8051_command(struct hfi2_devdata *dd, u32 type, u64 in_data,
			   u64 *out_data);
int hfi2_read_idle_sma(struct hfi2_devdata *dd, u64 *data);
static int thermal_init(struct hfi2_devdata *dd);

int hfi2_wait_phys_link_offline_substates(struct hfi2_pportdata *ppd,
					    int msecs);
int hfi2_wait_logical_linkstate(struct hfi2_pportdata *ppd, u32 state,
				  int msecs);
void hfi2_log_physical_state(struct hfi2_pportdata *ppd, u32 state);
int hfi2_wait_physical_linkstate(struct hfi2_pportdata *ppd, u32 state,
				   int msecs);
int hfi2_wait_phys_link_out_of_offline(struct hfi2_pportdata *ppd, int msecs);
void hfi2_read_planned_down_reason_code(struct hfi2_devdata *dd, u8 *pdrrc);
void hfi2_read_link_down_reason(struct hfi2_devdata *dd, u8 *ldr);
void hfi2_dc_shutdown(struct hfi2_devdata *dd);
void hfi2_dc_start(struct hfi2_devdata *dd);
static int qos_rmt_entries(unsigned int n_krcv_queues, unsigned int *mp,
			   unsigned int *np);
void hfi2_clear_full_mgmt_pkey(struct hfi2_pportdata *ppd);
int hfi2_wait_link_transfer_active(struct hfi2_devdata *dd, int wait_ms);

void hfi2_clear_full_mgmt_pkey(struct hfi2_pportdata *ppd)
{
	if (ppd->pkeys[2] != 0) {
		ppd->pkeys[2] = 0;
		(void)hfi2_set_ib_cfg(ppd, HFI2_IB_CFG_PKEYS, 0);
		hfi2_event_pkey_change(ppd->dd, ppd->port);
	}
}
void clear_rsm_rule(struct hfi2_devdata *dd, int rule_index);
void hfi2_wait_for_freeze_status(struct hfi2_devdata *dd, int freeze);
void hfi2_rxe_freeze(struct hfi2_devdata *dd);
void hfi2_rxe_kernel_unfreeze(struct hfi2_devdata *dd);



/*
 * Table of the "misc" grouping of error interrupts.  Each entry refers to
 * another register containing more information.
 */
#define NUM_MISC_ERRS (IS_GENERAL_ERR_END + 1 - IS_GENERAL_ERR_START)
#define NUM_VARIOUS (IS_VARIOUS_END + 1 - IS_VARIOUS_START)

static const struct err_reg_info misc_errs[NUM_MISC_ERRS] = {
	EE_N(CCE_ERR, handle_cce_err, "CceErr"),
	EE_I(WFR_RCV_ERR, hfi2_handle_rxe_err, "RxeErr"),
	EE_N(MISC_ERR, handle_misc_err, "MiscErr"),
	{}, /* reserved */
	EE_N(WFR_SEND_PIO_ERR, hfi2_handle_pio_err, "PioErr"),
	EE_N(WFR_SEND_DMA_ERR, hfi2_handle_sdma_err, "SDmaErr"),
	EE_E(WFR_SEND_EGRESS_ERR, hfi2_handle_egress_err, "EgressErr"),
	EE_N(WFR_SEND_ERR, handle_txe_err, "TxeErr")
	/* the rest are reserved */
};

/*
 * Index into the Various section of the interrupt sources
 * corresponding to the Critical Temperature interrupt.
 */
#define TCRIT_INT_SOURCE 4

/*
 * SDMA error interrupt entry - refers to another register containing more
 * information.
 */
static const struct err_reg_info sdma_eng_err =
	EE_S(WFR_SEND_DMA_ENG_ERR, hfi2_handle_sdma_eng_err, "SDmaEngErr");

static const struct err_reg_info various_err[NUM_VARIOUS] = {
	{}, /* PbcInt */
	{}, /* GpioAssertInt */
	EE_N(ASIC_QSFP1, handle_qsfp_int, "QSFP1"),
	EE_N(ASIC_QSFP2, handle_qsfp_int, "QSFP2"),
	{}, /* TCritInt */
	/* the rest are reserved */
};

/*
 * The DC encoding of mtu_cap for 10K MTU in the DCC_CFG_PORT_CONFIG
 * register can not be derived from the MTU value because 10K is not
 * a power of 2. Therefore, we need a constant. Everything else can
 * be calculated.
 */
#define DCC_CFG_PORT_MTU_CAP_10240 7





/* ======================================================================== */

/* return true if this is WFR chip revision a */
int hfi2_is_ax(struct hfi2_devdata *dd)
{
	int chip_rev_minor;

	if (dd->params->chip_type != CHIP_WFR)
		return 0;

	chip_rev_minor = (dd->revision >> CCE_REVISION_CHIP_REV_MINOR_SHIFT) &
			 CCE_REVISION_CHIP_REV_MINOR_MASK;
	return (chip_rev_minor & 0xf0) == 0;
}

/* return true if this is WFR chip revision b or not WFR */
int hfi2_is_bx(struct hfi2_devdata *dd)
{
	int chip_rev_minor;

	if (dd->params->chip_type != CHIP_WFR)
		return 1;

	chip_rev_minor = (dd->revision >> CCE_REVISION_CHIP_REV_MINOR_SHIFT) &
			 CCE_REVISION_CHIP_REV_MINOR_MASK;
	return (chip_rev_minor & 0xF0) == 0x10;
}

/* return true is kernel urg disabled for rcd */
bool hfi2_is_urg_masked(struct hfi2_ctxtdata *rcd)
{
	u64 mask;
	u32 is = rcd->dd->params->is_rcvurgent_start + rcd->ctxt;
	u8 bit = is % 64;

	mask = hfi2_read_csr(rcd->dd, rcd->dd->params->cce_int_mask_reg +
					      (8 * (is / 64)));
	return !(mask & BIT_ULL(bit));
}

/*
 * Append string s to buffer buf.  Arguments curp and len are the current
 * position and remaining length, respectively.
 *
 * return 0 on success, 1 on out of room
 */
static int append_str(char *buf, char **curp, int *lenp, const char *s)
{
	char *p = *curp;
	int len = *lenp;
	int result = 0; /* success */
	char c;

	/* add a comma, if first in the buffer */
	if (p != buf) {
		if (len == 0) {
			result = 1; /* out of room */
			goto done;
		}
		*p++ = ',';
		len--;
	}

	/* copy the string */
	while ((c = *s++) != 0) {
		if (len == 0) {
			result = 1; /* out of room */
			goto done;
		}
		*p++ = c;
		len--;
	}

done:
	/* write return values */
	*curp = p;
	*lenp = len;

	return result;
}

/*
 * Using the given flag table, print a comma separated string into
 * the buffer.  End in '*' if the buffer is too short.
 */
char *hfi2_flag_string(char *buf, int buf_len, u64 flags,
			 const struct flag_table *table, int table_size)
{
	char extra[32];
	char *p = buf;
	int len = buf_len;
	int no_room = 0;
	int i;

	/* make sure there is at least 2 so we can form "*" */
	if (len < 2)
		return "";

	len--; /* leave room for a nul */
	for (i = 0; i < table_size; i++) {
		if (flags & table[i].flag) {
			no_room = append_str(buf, &p, &len, table[i].str);
			if (no_room)
				break;
			flags &= ~table[i].flag;
		}
	}

	/* any undocumented bits left? */
	if (!no_room && flags) {
		snprintf(extra, sizeof(extra), "bits 0x%llx", flags);
		no_room = append_str(buf, &p, &len, extra);
	}

	/* add * if ran out of room */
	if (no_room) {
		/* may need to back up to add space for a '*' */
		if (len == 0)
			--p;
		*p++ = '*';
	}

	/* add final nul - space already allocated above */
	*p = 0;
	return buf;
}

/* first 8 CCE error interrupt source names */
static const char *const cce_misc_names[] = {
	"CceErrInt", /* 0 */
	"RxeErrInt", /* 1 */
	"MiscErrInt", /* 2 */
	"Reserved3", /* 3 */
	"PioErrInt", /* 4 */
	"SDmaErrInt", /* 5 */
	"EgressErrInt", /* 6 */
	"TxeErrInt" /* 7 */
};

/*
 * Return the miscellaneous error interrupt name.
 */
static char *is_misc_err_name(char *buf, size_t bsize, unsigned int source)
{
	if (source < ARRAY_SIZE(cce_misc_names))
		strscpy_pad(buf, cce_misc_names[source], bsize);
	else
		snprintf(buf, bsize, "Reserved%u",
			 source + IS_GENERAL_ERR_START);

	return buf;
}

/*
 * Return the SDMA engine error interrupt name.
 */
char *hfi2_is_sdma_eng_err_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "SDmaEngErrInt%u", source);
	return buf;
}

/*
 * Return the send context error interrupt name.
 */
char *hfi2_is_sendctxt_err_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "SendCtxtErrInt%u", source);
	return buf;
}

static const char *const various_names[] = { "PbcInt", "GpioAssertInt",
					     "Qsfp1Int", "Qsfp2Int",
					     "TCritInt" };

/*
 * Return the various interrupt name.
 */
static char *is_various_name(char *buf, size_t bsize, unsigned int source)
{
	if (source < ARRAY_SIZE(various_names))
		strscpy_pad(buf, various_names[source], bsize);
	else
		snprintf(buf, bsize, "Reserved%u", source + IS_VARIOUS_START);
	return buf;
}

/*
 * Return the DC interrupt name.
 */
static char *is_dc_name(char *buf, size_t bsize, unsigned int source)
{
	static const char *const dc_int_names[] = {
		"common", "lcb", "8051", "lbm" /* local block merge */
	};

	if (source < ARRAY_SIZE(dc_int_names))
		snprintf(buf, bsize, "dc_%s_int", dc_int_names[source]);
	else
		snprintf(buf, bsize, "DCInt%u", source);
	return buf;
}

static const char *const sdma_int_names[] = {
	"SDmaInt",
	"SdmaIdleInt",
	"SdmaProgressInt",
};

/*
 * Return the SDMA engine interrupt name.
 */
char *hfi2_is_sdma_eng_name(char *buf, size_t bsize, unsigned int source)
{
	/* what interrupt */
	unsigned int what = source / TXE_NUM_SDMA_ENGINES;
	/* which engine */
	unsigned int which = source % TXE_NUM_SDMA_ENGINES;

	if (likely(what < 3))
		snprintf(buf, bsize, "%s%u", sdma_int_names[what], which);
	else
		snprintf(buf, bsize, "Invalid SDMA interrupt %u", source);
	return buf;
}

/*
 * Return the receive available interrupt name.
 */
char *hfi2_is_rcv_avail_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "RcvAvailInt%u", source);
	return buf;
}

/*
 * Return the receive urgent interrupt name.
 */
char *hfi2_is_rcv_urgent_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "RcvUrgentInt%u", source);
	return buf;
}

/*
 * Return the send credit interrupt name.
 */
char *hfi2_is_send_credit_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "SendCreditInt%u", source);
	return buf;
}

/*
 * Return the reserved interrupt name.
 */
static char *is_reserved_name(char *buf, size_t bsize, unsigned int source)
{
	snprintf(buf, bsize, "Reserved%u", source + IS_RESERVED_START);
	return buf;
}

static char *cce_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, cce_err_status_flags,
			   ARRAY_SIZE(cce_err_status_flags));
}

static char *rxe_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, rxe_err_status_flags,
			   ARRAY_SIZE(rxe_err_status_flags));
}

static char *misc_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, misc_err_status_flags,
			   ARRAY_SIZE(misc_err_status_flags));
}

static char *pio_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, pio_err_status_flags,
			   ARRAY_SIZE(pio_err_status_flags));
}

static char *sdma_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, sdma_err_status_flags,
			   ARRAY_SIZE(sdma_err_status_flags));
}

static char *egress_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, egress_err_status_flags,
			   ARRAY_SIZE(egress_err_status_flags));
}

static char *egress_err_info_string(struct hfi2_devdata *dd, char *buf,
				    int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags,
			   dd->params->egress_err_info_data->table,
			   dd->params->egress_err_info_data->size);
}

static char *send_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, send_err_status_flags,
			   ARRAY_SIZE(send_err_status_flags));
}

static void handle_cce_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];
	int i = 0;

	/*
	 * For most these errors, there is nothing that can be done except
	 * report or record it.
	 */
	dd_dev_info(dd, "CCE Error: %s\n",
		    cce_err_status_string(buf, sizeof(buf), reg));

	if ((reg & CCE_ERR_STATUS_CCE_CLI2_ASYNC_FIFO_PARITY_ERR_SMASK) &&
	    hfi2_is_ax(dd)) {
		/* this error requires a manual drop into SPC freeze mode */
		/* then a fix up */
		hfi2_start_freeze_handling(dd, FREEZE_SELF);
	}

	for (i = 0; i < NUM_CCE_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i)) {
			incr_cntr64(&dd->cce_err_status_cnt[i]);
			/* maintain a counter over all cce_err_status errors */
			incr_cntr64(&dd->sw_cce_err_status_aggregate);
		}
	}
}

/*
 * Check counters for receive errors that do not have an interrupt
 * associated with them.
 */
static void do_rcverr_timer(struct work_struct *work)
{
	struct hfi2_devdata *dd =
		container_of(work, struct hfi2_devdata, rcverr_work);
	struct hfi2_pportdata *ppd;
	u32 cur_ovfl_cnt;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		ppd = &dd->pport[pidx];
		cur_ovfl_cnt =
			hfi2_read_port_cntr(ppd, C_RCV_OVF, CNTR_INVALID_VL);

		if (ppd->rcv_ovfl_cnt < cur_ovfl_cnt &&
		    ppd->port_error_action & OPA_PI_MASK_EX_BUFFER_OVERRUN) {
			ppd_dev_info(ppd, "%s: PortErrorAction bounce\n",
				     __func__);
			hfi2_set_link_down_reason(
				ppd,
				OPA_LINKDOWN_REASON_EXCESSIVE_BUFFER_OVERRUN, 0,
				OPA_LINKDOWN_REASON_EXCESSIVE_BUFFER_OVERRUN);
			queue_work(ppd->link_wq, &ppd->link_bounce_work);
		}
		ppd->rcv_ovfl_cnt = cur_ovfl_cnt;
	}
}

#define RCVERR_CHECK_TIME 10
static void update_rcverr_timer(struct timer_list *t)
{
	struct hfi2_devdata *dd = timer_container_of(dd, t, rcverr_timer);

	/* avoid timer interrupt context CSR access when simulating */
	if (dd->icode == ICODE_FUNCTIONAL_SIMULATOR)
		queue_work(dd->update_cntr_wq, &dd->rcverr_work);
	else
		do_rcverr_timer(&dd->rcverr_work);
	mod_timer(&dd->rcverr_timer, jiffies + HZ * RCVERR_CHECK_TIME);
}

void hfi2_handle_rxe_err(struct hfi2_devdata *dd, u32 pidx, u64 reg)
{
	struct hfi2_pportdata *ppd = &dd->pport[pidx];
	char buf[96];
	int i = 0;

	ppd_dev_info(ppd, "Receive Error: %s\n",
		     rxe_err_status_string(buf, sizeof(buf), reg));

	if (reg & ALL_RXE_FREEZE_ERR) {
		int flags = 0;

		/*
		 * Freeze mode recovery is disabled for the errors
		 * in RXE_FREEZE_ABORT_MASK
		 */
		if (hfi2_is_ax(dd) && (reg & RXE_FREEZE_ABORT_MASK))
			flags = FREEZE_ABORT;

		hfi2_start_freeze_handling(dd, flags);
	}

	for (i = 0; i < NUM_RCV_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i))
			incr_cntr64(&dd->rcv_err_status_cnt[i]);
	}
}

static void handle_misc_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];
	int i = 0;

	dd_dev_info(dd, "Misc Error: %s",
		    misc_err_status_string(buf, sizeof(buf), reg));
	for (i = 0; i < NUM_MISC_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i))
			incr_cntr64(&dd->misc_err_status_cnt[i]);
	}
}

void hfi2_handle_pio_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];
	int i = 0;

	dd_dev_info(dd, "PIO Error: %s\n",
		    pio_err_status_string(buf, sizeof(buf), reg));

	if (reg & ALL_PIO_FREEZE_ERR)
		hfi2_start_freeze_handling(dd, 0);

	for (i = 0; i < NUM_SEND_PIO_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i))
			incr_cntr64(&dd->send_pio_err_status_cnt[i]);
	}
}

void hfi2_handle_sdma_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];
	int i = 0;

	dd_dev_info(dd, "SDMA Error: %s\n",
		    sdma_err_status_string(buf, sizeof(buf), reg));

	if (reg & ALL_SDMA_FREEZE_ERR)
		hfi2_start_freeze_handling(dd, 0);

	for (i = 0; i < NUM_SEND_DMA_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i))
			incr_cntr64(&dd->send_dma_err_status_cnt[i]);
	}
}

static inline void __count_port_discards(struct hfi2_pportdata *ppd)
{
	incr_cntr64(&ppd->port_xmit_discards);
}

static void count_port_inactive(struct hfi2_pportdata *ppd)
{
	__count_port_discards(ppd);
}

static u64 egress_err_info(struct hfi2_pportdata *ppd, bool hfi2_loopback)
{
	struct hfi2_devdata *dd = ppd->dd;
	u8 pidx = hfi2_loopback ? loopback_pidx(ppd) : ppd->hw_pidx;

	/* read err source first */
	u64 src = read_eport_csr(dd, pidx,
				 dd->params->send_egress_err_source_reg);
	u64 info =
		read_eport_csr(dd, pidx, dd->params->send_egress_err_info_reg);
	char buf[96];

	/* clear down all observed info as quickly as possible after read */
	write_eport_csr(dd, pidx, dd->params->send_egress_err_info_reg, info);

	ppd_dev_info(
		ppd,
		"%s Egress Error Info: 0x%llx, %s Egress Error Src 0x%llx\n",
		hfi2_loopback ? "LB" : "FC", info,
		egress_err_info_string(dd, buf, sizeof(buf), info), src);
	return info;
}

/*
 * We have had a "disallowed packet" error during egress. Determine the
 * integrity check which failed, and update relevant error counter, etc.
 *
 * Note that the SEND_EGRESS_ERR_INFO register has only a single
 * bit of state per integrity check, and so we can miss the reason for an
 * egress error if more than one packet fails the same integrity check
 * since we cleared the corresponding bit in SEND_EGRESS_ERR_INFO.
 */
static void handle_send_egress_err_info(struct hfi2_pportdata *ppd, int vl)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 info = egress_err_info(ppd, false);

	if (dd->loopback_enabled)
		info |= egress_err_info(ppd, true);

	/* Eventually add other counters for each bit */
	if (info & dd->params->port_discard_egress_errs) {
		int weight, i;

		/*
		 * Count all applicable bits as individual errors and
		 * attribute them to the packet that triggered this handler.
		 * This may not be completely accurate due to limitations
		 * on the available hardware error information.  There is
		 * a single information register and any number of error
		 * packets may have occurred and contributed to it before
		 * this routine is called.  This means that:
		 * a) If multiple packets with the same error occur before
		 *    this routine is called, earlier packets are missed.
		 *    There is only a single bit for each error type.
		 * b) Errors may not be attributed to the correct VL.
		 *    The driver is attributing all bits in the info register
		 *    to the packet that triggered this call, but bits
		 *    could be an accumulation of different packets with
		 *    different VLs.
		 * c) A single error packet may have multiple counts attached
		 *    to it.  There is no way for the driver to know if
		 *    multiple bits set in the info register are due to a
		 *    single packet or multiple packets.  The driver assumes
		 *    multiple packets.
		 */
		weight = hweight64(info & dd->params->port_discard_egress_errs);
		for (i = 0; i < weight; i++) {
			__count_port_discards(ppd);
			if (vl >= 0 && vl < TXE_NUM_DATA_VL)
				incr_cntr64(&ppd->port_xmit_discards_vl[vl]);
			else if (vl == 15)
				incr_cntr64(
					&ppd->port_xmit_discards_vl[C_VL_15]);
		}
	}
}

/*
 * Input value is a bit position within the SEND_EGRESS_ERR_STATUS
 * register. Does it represent a 'port inactive' error?
 */
static inline int port_inactive_err(int posn)
{
	return (posn >= ilog2(SEES(TX_LINKDOWN)) &&
		posn <= ilog2(SEES(TX_INCORRECT_LINK_STATE)));
}

/*
 * Input value is a bit position within the SEND_EGRESS_ERR_STATUS
 * register. Does it represent a 'disallowed packet' error?
 */
static inline int disallowed_pkt_err(int posn)
{
	return (posn >= ilog2(SEES(TX_SDMA0_DISALLOWED_PACKET)) &&
		posn <= ilog2(SEES(TX_SDMA15_DISALLOWED_PACKET)));
}

/*
 * Input value is a bit position of one of the SDMA engine disallowed
 * packet errors.  Return which engine.  Use of this must be guarded by
 * disallowed_pkt_err().
 */
static inline int disallowed_pkt_engine(int posn)
{
	return posn - ilog2(SEES(TX_SDMA0_DISALLOWED_PACKET));
}

/*
 * Translate an SDMA engine to a VL.  Return -1 if the tranlation cannot
 * be done.
 */
static int engine_to_vl(struct hfi2_pportdata *ppd, int engine)
{
	struct sdma_vl_map *m;
	int vl;

	/* range check */
	if (engine < 0 || engine >= TXE_NUM_SDMA_ENGINES)
		return -1;

	rcu_read_lock();
	m = rcu_dereference(ppd->sdma_map);
	vl = m->engine_to_vl[engine];
	rcu_read_unlock();

	return vl;
}

/*
 * Translate the send context (sofware index) into a VL.  Return -1 if the
 * translation cannot be done.
 */
static int sc_to_vl(struct hfi2_devdata *dd, int sw_index)
{
	struct send_context_info *sci;
	struct send_context *sc;
	int i;

	sci = &dd->send_contexts[sw_index];

	/* there is no information for user (PSM) and ack contexts */
	if ((sci->type != SC_KERNEL) && (sci->type != SC_VL15))
		return -1;

	sc = sci->sc;
	if (!sc)
		return -1;
	if (sc->ppd->vld[15].sc == sc)
		return 15;
	for (i = 0; i < hfi2_num_vls; i++)
		if (sc->ppd->vld[i].sc == sc)
			return i;

	return -1;
}

void hfi2_handle_egress_err(struct hfi2_devdata *dd, u32 pidx, u64 reg)
{
	struct hfi2_pportdata *ppd = &dd->pport[pidx];
	u64 reg_copy = reg;
	char buf[96];
	bool err_info_avail = true; /* info available on first call only */

	if (reg & ALL_TXE_EGRESS_FREEZE_ERR)
		hfi2_start_freeze_handling(dd, 0);
	else if (hfi2_is_ax(dd) &&
		 (reg & SEND_EGRESS_ERR_STATUS_TX_CREDIT_RETURN_VL_ERR_SMASK))
		hfi2_start_freeze_handling(dd, 0);

	while (reg_copy) {
		int posn = fls64(reg_copy);
		/* fls64() returns a 1-based offset, we want it zero based */
		int shift = posn - 1;
		u64 mask = 1ULL << shift;

		if (port_inactive_err(shift)) {
			count_port_inactive(ppd);
		} else if (err_info_avail && disallowed_pkt_err(shift)) {
			int vl =
				engine_to_vl(ppd, disallowed_pkt_engine(shift));

			handle_send_egress_err_info(ppd, vl);
			err_info_avail = false;
		}
		incr_cntr64(&dd->send_egress_err_status_cnt[shift]);
		reg_copy &= ~mask;
	}

	if (reg)
		ppd_dev_info(ppd, "Egress Error: %s\n",
			     egress_err_status_string(buf, sizeof(buf), reg));
}

static void handle_txe_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];
	int i = 0;

	dd_dev_info(dd, "Send Error: %s\n",
		    send_err_status_string(buf, sizeof(buf), reg));

	for (i = 0; i < NUM_SEND_ERR_STATUS_COUNTERS; i++) {
		if (reg & (1ull << i))
			incr_cntr64(&dd->send_err_status_cnt[i]);
	}
}

/*
 * The maximum number of times the error clear down will loop before
 * blocking a repeating error.  This value is arbitrary.
 */
#define MAX_CLEAR_COUNT 20

/* helper for hfi2_interrupt_clear_down() register read */
static u64 read_icd_csr(struct hfi2_devdata *dd, enum icd_type type, u32 idx,
			u32 reg)
{
	switch (type) {
	case ICD_NORMAL:
		return hfi2_read_csr(dd, reg);
	case ICD_SDMA:
		return read_sdma_csr(dd, idx, reg);
	case ICD_INGRESS:
		return read_iport_csr(dd, idx, reg);
	case ICD_EGRESS:
		return read_eport_csr(dd, idx, reg);
	}
	return 0;
}

/* helper for hfi2_interrupt_clear_down() register write */
static void write_icd_csr(struct hfi2_devdata *dd, enum icd_type type, u32 idx,
			  u32 reg, u64 value)
{
	switch (type) {
	case ICD_NORMAL:
		hfi2_write_csr(dd, reg, value);
		return;
	case ICD_SDMA:
		write_sdma_csr(dd, idx, reg, value);
		return;
	case ICD_INGRESS:
		write_iport_csr(dd, idx, reg, value);
		return;
	case ICD_EGRESS:
		write_eport_csr(dd, idx, reg, value);
		return;
	}
}

/*
 * Clear and handle an error register.  All error interrupts are funneled
 * through here to have a central location to correctly handle single-
 * or multi-shot errors.
 *
 * The error register info indicates the type of access needed for the error
 * register.  The idx is an indexer for the error register.
 *
 * If the handler loops too many times, assume that something is wrong
 * and can't be fixed, so mask the error bits.
 */
void hfi2_interrupt_clear_down(struct hfi2_devdata *dd, u32 idx,
			       const struct err_reg_info *eri)
{
	u64 reg;
	u32 count;

	/* read in a loop until no more errors are seen */
	count = 0;
	while (1) {
		reg = read_icd_csr(dd, eri->type, idx, eri->status);
		if (reg == 0)
			break;
		write_icd_csr(dd, eri->type, idx, eri->clear, reg);
		if (likely(eri->handler))
			eri->handler(dd, idx, reg);
		count++;
		if (count > MAX_CLEAR_COUNT) {
			u64 mask;

			dd_dev_err(dd, "Repeating %s bits 0x%llx - masking\n",
				   eri->desc, reg);
			/*
			 * Read-modify-write so any other masked bits
			 * remain masked.
			 */
			mask = read_icd_csr(dd, eri->type, idx, eri->mask);
			mask &= ~reg;
			write_icd_csr(dd, eri->type, idx, eri->mask, mask);
			break;
		}
	}
}

/*
 * CCE block "misc" interrupt.  Source is < 16.
 */
static void is_misc_err_int(struct hfi2_devdata *dd, unsigned int source)
{
	const struct err_reg_info *eri = &misc_errs[source];

	if (eri->handler) {
		hfi2_interrupt_clear_down(dd, 0, eri);
	} else {
		dd_dev_err(dd, "Unexpected misc interrupt (%u) - reserved\n",
			   source);
	}
}

static char *send_context_err_status_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, sc_err_status_flags,
			   ARRAY_SIZE(sc_err_status_flags));
}

/*
 * Send context error interrupt.
 *
 * All send context errors cause the send context to halt.  The normal
 * clear-down mechanism cannot be used because we cannot clear the
 * error bits until several other long-running items are done first.
 * This is OK because with the context halted, nothing else is going
 * to happen on it anyway.
 */
void hfi2_is_sendctxt_err_int(struct hfi2_devdata *dd, unsigned int hw_context)
{
	struct send_context_info *sci;
	struct send_context *sc;
	char flags[96];
	u64 status;
	u32 sw_index;
	int i = 0;
	unsigned long irq_flags;

	sw_index = dd->hw_to_sw[hw_context];
	if (sw_index >= dd->num_send_contexts) {
		dd_dev_err(dd, "out of range sw index %u for send context %u\n",
			   sw_index, hw_context);
		return;
	}
	sci = &dd->send_contexts[sw_index];
	spin_lock_irqsave(&dd->sc_lock, irq_flags);
	sc = sci->sc;
	if (!sc) {
		dd_dev_err(dd, "%s: context %u(%u): no sc?\n", __func__,
			   sw_index, hw_context);
		spin_unlock_irqrestore(&dd->sc_lock, irq_flags);
		return;
	}

	/* tell the software that a halt has begun */
	hfi2_sc_stop(sc, SCF_HALTED);

	/*
	 * All per-send context errors will halt the context and no more
	 * errors can be generated.  Calling hfi2_interrupt_clear_down() to handle
	 * repeating errors is not needed.  The per-context error status
	 * register is cleared when the context is re-enabled.
	 */
	status = read_sctxt_csr(dd, hw_context,
				dd->params->send_ctxt_err_status_reg);

	dd_dev_info(dd, "Send Context %u(%u) Error: %s\n", sw_index, hw_context,
		    send_context_err_status_string(flags, sizeof(flags),
						   status));

	if (status & SEND_CTXT_ERR_STATUS_PIO_DISALLOWED_PACKET_ERR_SMASK)
		handle_send_egress_err_info(sc->ppd, sc_to_vl(dd, sw_index));

	/*
	 * Automatically restart halted kernel contexts out of interrupt
	 * context.  User contexts must ask the driver to restart the context.
	 */
	if (sc->type != SC_USER)
		queue_work(dd->hfi2_wq, &sc->halt_work);
	spin_unlock_irqrestore(&dd->sc_lock, irq_flags);

	/*
	 * Update the counters for the corresponding status bits.
	 * Note that these particular counters are aggregated over all
	 * contexts.
	 */
	for (i = 0; i < NUM_SEND_CTXT_ERR_STATUS_COUNTERS; i++) {
		if (status & (1ull << i))
			incr_cntr64(&dd->sw_ctxt_err_status_cnt[i]);
	}
}

void hfi2_handle_sdma_eng_err(struct hfi2_devdata *dd, unsigned int source,
			      u64 status)
{
	struct sdma_engine *sde;
	int i = 0;

	if (!sdma_engine_initialized(dd, source)) {
		dd_dev_err(dd, "%s: engine %u out of range\n", __func__,
			   source);
		return;
	}
	sde = &dd->per_sdma[source];
#ifdef CONFIG_HFI2_SDMA_VERBOSITY
	dd_dev_err(sde->dd, "CONFIG SDMA(%u) %s:%d %s()\n", sde->this_idx,
		   slashstrip(__FILE__), __LINE__, __func__);
	dd_dev_err(sde->dd, "CONFIG SDMA(%u) source: %u status 0x%llx\n",
		   sde->this_idx, source, (unsigned long long)status);
#endif
	sde->err_cnt++;
	hfi2_sdma_engine_error(sde, status);

	/*
	 * Update the counters for the corresponding status bits.
	 * Note that these particular counters are aggregated over
	 * all 16 DMA engines.
	 */
	for (i = 0; i < NUM_SEND_DMA_ENG_ERR_STATUS_COUNTERS; i++) {
		if (status & (1ull << i))
			incr_cntr64(&dd->sw_send_dma_eng_err_status_cnt[i]);
	}
}

/*
 * CCE block SDMA error interrupt.  Source is < 16.
 */
static void is_sdma_eng_err_int(struct hfi2_devdata *dd, unsigned int source)
{
	if (!sdma_engine_initialized(dd, source)) {
		dd_dev_err(dd, "%s: engine %u out of range\n", __func__,
			   source);
		goto clear_down; /* must not access sde, but must clear intr */
	}
#ifdef CONFIG_HFI2_SDMA_VERBOSITY
	struct sdma_engine *sde = &dd->per_sdma[source];

	dd_dev_err(dd, "CONFIG SDMA(%u) %s:%d %s()\n", sde->this_idx,
		   slashstrip(__FILE__), __LINE__, __func__);
	dd_dev_err(dd, "CONFIG SDMA(%u) source: %u\n", sde->this_idx, source);
	hfi2_sdma_dumpstate(sde);
#endif
clear_down:
	hfi2_interrupt_clear_down(dd, source, &sdma_eng_err);
}

/*
 * CCE block "various" interrupt.  Source is < 8.
 */
static void is_various_int(struct hfi2_devdata *dd, unsigned int source)
{
	const struct err_reg_info *eri = &various_err[source];

	/*
	 * TCritInt cannot go through hfi2_interrupt_clear_down()
	 * because it is not a second tier interrupt. The handler
	 * should be called directly.
	 */
	if (source == TCRIT_INT_SOURCE)
		hfi2_handle_temp_err(dd);
	else if (eri->handler)
		hfi2_interrupt_clear_down(dd, 0, eri);
	else
		dd_dev_info(dd, "%s: Unimplemented/reserved interrupt %d\n",
			    __func__, source);
}

static void handle_qsfp_int(struct hfi2_devdata *dd, u32 src_ctx, u64 reg)
{
	/* src_ctx is always zero */
	struct hfi2_pportdata *ppd = dd->pport;
	unsigned long flags;
	u64 qsfp_int_mgmt = (u64)(QSFP_HFI0_INT_N | QSFP_HFI0_MODPRST_N);

	if (reg & QSFP_HFI0_MODPRST_N) {
		if (!hfi2_qsfp_mod_present(ppd)) {
			ppd_dev_info(ppd, "%s: QSFP module removed\n",
				     __func__);

			ppd->driver_link_ready = 0;
			/*
			 * Cable removed, reset all our information about the
			 * cache and cable capabilities
			 */

			spin_lock_irqsave(&ppd->qsfp_info.qsfp_lock, flags);
			/*
			 * We don't set cache_refresh_required here as we expect
			 * an interrupt when a cable is inserted
			 */
			ppd->qsfp_info.cache_valid = 0;
			ppd->qsfp_info.reset_needed = 0;
			ppd->qsfp_info.limiting_active = 0;
			spin_unlock_irqrestore(&ppd->qsfp_info.qsfp_lock,
					       flags);
			/* Invert the ModPresent pin now to detect plug-in */
			hfi2_write_csr(dd,
				       dd->hfi2_id ? ASIC_QSFP2_INVERT :
						     ASIC_QSFP1_INVERT,
				       qsfp_int_mgmt);

			if ((ppd->offline_disabled_reason >
			     HFI2_ODR_MASK(
				     OPA_LINKDOWN_REASON_LOCAL_MEDIA_NOT_INSTALLED)) ||
			    (ppd->offline_disabled_reason ==
			     HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NONE)))
				ppd->offline_disabled_reason = HFI2_ODR_MASK(
					OPA_LINKDOWN_REASON_LOCAL_MEDIA_NOT_INSTALLED);

			if (ppd->host_link_state == HLS_DN_POLL) {
				/*
				 * The link is still in POLL. This means
				 * that the normal link down processing
				 * will not happen. We have to do it here
				 * before turning the DC off.
				 */
				queue_work(ppd->link_wq, &ppd->link_down_work);
			}
		} else {
			ppd_dev_info(ppd, "%s: QSFP module inserted\n",
				     __func__);

			spin_lock_irqsave(&ppd->qsfp_info.qsfp_lock, flags);
			ppd->qsfp_info.cache_valid = 0;
			ppd->qsfp_info.cache_refresh_required = 1;
			spin_unlock_irqrestore(&ppd->qsfp_info.qsfp_lock,
					       flags);

			/*
			 * Stop inversion of ModPresent pin to detect
			 * removal of the cable
			 */
			qsfp_int_mgmt &= ~(u64)QSFP_HFI0_MODPRST_N;
			hfi2_write_csr(dd,
				       dd->hfi2_id ? ASIC_QSFP2_INVERT :
						     ASIC_QSFP1_INVERT,
				       qsfp_int_mgmt);

			ppd->offline_disabled_reason =
				HFI2_ODR_MASK(OPA_LINKDOWN_REASON_TRANSIENT);
		}
	}

	if (reg & QSFP_HFI0_INT_N) {
		ppd_dev_info(ppd, "%s: Interrupt received from QSFP module\n",
			     __func__);
		spin_lock_irqsave(&ppd->qsfp_info.qsfp_lock, flags);
		ppd->qsfp_info.check_interrupt_flags = 1;
		spin_unlock_irqrestore(&ppd->qsfp_info.qsfp_lock, flags);
	}

	/* Schedule the QSFP work only if there is a cable attached. */
	if (hfi2_qsfp_mod_present(ppd))
		queue_work(ppd->link_wq, &ppd->qsfp_info.qsfp_work);
}


/*
 * Clear first, then set.  This allows for multi-bit fields to be set.
 */

/*
 * Steps needed to handle active PIO and SDMA when a link goes down.  Not
 * called at interrupt time.
 *
 * This is an alternative to an SPC freeze for link down.  It depends on the
 * hardware ability to flush packets when in the wrong link state.  WFR does
 * not have this feature and should continue to perform an SPC freeze on link
 * down.
 */

/**
 * hfi2_update_xmit_counters - update PortXmitWait/PortVlXmitWait
 * counters.
 * @ppd: info of physical Hfi port
 * @link_width: new link width after link up or downgrade
 *
 * Update the PortXmitWait and PortVlXmitWait counters after
 * a link up or downgrade event to reflect a link width change.
 */

/* return the neighbor link down reason string */

/*
 * TX block send credit interrupt.
 */
void hfi2_is_send_credit_int(struct hfi2_devdata *dd, unsigned int source)
{
	hfi2_sc_group_release_update(dd, source);
}

/*
 * TX block SDMA interrupt.  Source is < 48.
 *
 * SDMA interrupts are grouped by type:
 *
 *	 0 -  N-1 = SDma
 *	 N - 2N-1 = SDmaProgress
 *	2N - 3N-1 = SDmaIdle
 */
void hfi2_is_sdma_eng_int(struct hfi2_devdata *dd, unsigned int source)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	/* what interrupt */
	unsigned int what = source / TXE_NUM_SDMA_ENGINES;
	/* which engine */
	unsigned int which = source % TXE_NUM_SDMA_ENGINES;

#ifdef CONFIG_HFI2_SDMA_VERBOSITY
	dd_dev_err(dd, "CONFIG SDMA(%u) %s:%d %s()\n", which,
		   slashstrip(__FILE__), __LINE__, __func__);
#endif

	if (likely(what < 3 && which >= dr->first_sdma_engine &&
		   which < dr->last_sdma_engine)) {
#ifdef CONFIG_HFI2_SDMA_VERBOSITY
		hfi2_sdma_dumpstate(&dd->per_sdma[which]);
#endif
		hfi2_sdma_engine_interrupt(&dd->per_sdma[which],
					   1ull << source);
	} else {
		/* should not happen */
		/* TODO: still need to clear-down? */
		dd_dev_err(dd, "Invalid SDMA interrupt 0x%x\n", source);
	}
}

/**
 * hfi2_is_rcv_avail_int() - User receive context available IRQ handler
 * @dd: valid dd
 * @source: logical IRQ source (offset from IS_RCVAVAIL_START)
 *
 * RX block receive available interrupt.
 *
 * This is the general interrupt handler for user (PSM) receive contexts,
 * and can only be used for non-threaded IRQs.
 */
void hfi2_is_rcv_avail_int(struct hfi2_devdata *dd, unsigned int source)
{
	struct hfi2_ctxtdata *rcd;

	rcd = hfi2_rcd_get_by_index(dd, source);
	if (rcd) {
		hfi2_handle_user_interrupt(rcd);
		hfi2_rcd_put(rcd);
		return; /* OK */
	}
	dd_dev_err(
		dd,
		"unexpected dataless receive available context interrupt %u\n",
		source);
}

/**
 * hfi2_is_rcv_urgent_int() - User receive context urgent IRQ handler
 * @dd: valid dd
 * @source: logical IRQ source (offset from IS_RCVURGENT_START)
 *
 * RX block receive urgent interrupt.
 *
 * NOTE: kernel receive contexts specifically do NOT enable this IRQ.
 */
void hfi2_is_rcv_urgent_int(struct hfi2_devdata *dd, unsigned int source)
{
	struct hfi2_ctxtdata *rcd;

	rcd = hfi2_rcd_get_by_index(dd, source);
	if (rcd) {
		hfi2_handle_user_interrupt(rcd);
		hfi2_rcd_put(rcd);
		return; /* OK */
	}
	dd_dev_err(dd,
		   "unexpected dataless receive urgent context interrupt %u\n",
		   source);
}

/*
 * Reserved range interrupt.  Should not be called in normal operation.
 */
static void is_reserved_int(struct hfi2_devdata *dd, unsigned int source)
{
	char name[64];

	dd_dev_err(dd, "unexpected %s interrupt\n",
		   is_reserved_name(name, sizeof(name), source));
}

const struct hfi2_is_table hfi2_is_table[] = {
	/*
	 * start		 end
	 *				name func		interrupt func
	 */
	{ IS_GENERAL_ERR_START, IS_GENERAL_ERR_END, is_misc_err_name,
	  is_misc_err_int },
	{ IS_SDMAENG_ERR_START, IS_SDMAENG_ERR_END, hfi2_is_sdma_eng_err_name,
	  is_sdma_eng_err_int },
	{ IS_SENDCTXT_ERR_START, IS_SENDCTXT_ERR_END, hfi2_is_sendctxt_err_name,
	  hfi2_is_sendctxt_err_int },
	{ IS_SDMA_START, IS_SDMA_IDLE_END, hfi2_is_sdma_eng_name,
	  hfi2_is_sdma_eng_int },
	{ IS_VARIOUS_START, IS_VARIOUS_END, is_various_name, is_various_int },
	{ IS_DC_START, IS_DC_END, is_dc_name, hfi2_is_dc_int },
	{ IS_RCVAVAIL_START, IS_RCVAVAIL_END, hfi2_is_rcv_avail_name,
	  hfi2_is_rcv_avail_int },
	{ IS_RCVURGENT_START, IS_RCVURGENT_END, hfi2_is_rcv_urgent_name,
	  hfi2_is_rcv_urgent_int },
	{ IS_SENDCREDIT_START, IS_SENDCREDIT_END, hfi2_is_send_credit_name,
	  hfi2_is_send_credit_int },
	{ IS_RESERVED_START, IS_RESERVED_END, is_reserved_name,
	  is_reserved_int },
	{ 0, 0, 0, 0 } /* terminator */
};

/*
 * General interrupt sources to enable.  This is all sources but SDMA
 * (SdmaEngErr, Sdma, SdmaProgress, SdmaIdle), and Receive (RcvAvail,
 * RcvUrgent).
 */
const struct gi_enable_entry hfi2_wfr_gi_enable_table[] = {
	{ IS_GENERAL_ERR_START, IS_GENERAL_ERR_END },
	{ IS_SENDCTXT_ERR_START, IS_SENDCTXT_ERR_END },
	{ IS_VARIOUS_START, IS_VARIOUS_END },
	{ IS_DC_START, IS_DC_END },
	{ IS_SENDCREDIT_START, IS_SENDCREDIT_END },
	{ 1, 0 } /* terminator */
};

uint flr_interrupt_delay = FLR_INTERRUPT_DELAY_DEFAULT;

void hfi2_flr_isr(struct hfi2_devdata *dd, unsigned int source)
{
	unsigned int si = source + 1;
	/* FLR source 0 corresponds to VF SI 1. */
	if (si > CHIP_SW(dd, C_CCE_NUM_VFS))
		return;

	/* Record the SI and defer the rebuild. */
	atomic_or(1 << si, &dd->rsrcs.flr_pending);
	mod_delayed_work(dd->hfi2_wq, &dd->flr_work,
			 msecs_to_jiffies(flr_interrupt_delay));
}

/*
 * Interrupt source interrupt - called when the given source has an interrupt.
 * Source is a bit index into an array of 64-bit integers.
 */
static void is_interrupt(struct hfi2_devdata *dd, unsigned int source)
{
	const struct hfi2_is_table *entry;

	/* avoids a double compare by walking the table in-order */
	for (entry = &dd->params->is_table[0]; entry->is_name; entry++) {
		if (source <= entry->end) {
			trace_hfi2_interrupt(dd, entry, source);
			entry->is_int(dd, source - entry->start);
			return;
		}
	}
	/* fell off the end */
	dd_dev_err(dd, "invalid interrupt source %u\n", source);
}

void write_csr_single_bit(const struct hfi2_devdata *dd, u32 offset, u64 value)
{
	if (!value) {
		hfi2_write_csr(dd, offset, 0);
		return;
	}

	while (value) {
		u64 bit = value & -value;

		hfi2_write_csr(dd, offset, bit);
		value &= ~bit;
	}
}

/**
 * hfi2_general_interrupt -  General interrupt handler
 * @irq: MSIx IRQ vector
 * @data: hfi2 devdata
 *
 * This is able to correctly handle all non-threaded interrupts.  Receive
 * context DATA IRQs are threaded and are not supported by this handler.
 *
 */
irqreturn_t hfi2_general_interrupt(int irq, void *data)
{
	struct hfi2_devdata *dd = data;
	u64 regs[LARGEST_NUM_INT_CSRS];
	u64 mask;
	u32 bit;
	u32 num_int_csrs = dd->params->num_int_csrs;
	u32 cce_int_clear_reg = dd->params->cce_int_clear_reg;
	u32 cce_int_status_reg = dd->params->cce_int_status_reg;
	u32 cce_msix_int_granted_reg = dd->params->cce_msix_int_granted_reg;
	int i;
	irqreturn_t handled = IRQ_NONE;

	this_cpu_inc(*dd->int_counter);

	/* phase 1: scan and clear all handled interrupts */
	for (i = 0; i < num_int_csrs; i++) {
		/* create mask from hw masked and remapped */
		mask = dd->gi_mask[i].cce_int_mask & dd->gi_mask[i].remap;
		if (mask == 0) {
			regs[i] = 0; /* used later */
			continue;
		}
		regs[i] = hfi2_read_csr(dd, cce_int_status_reg + (8 * i)) &
			  mask;
		/* only clear if anything is set */
		if (regs[i]) {
			write_csr_single_bit(dd, cce_int_clear_reg + (8 * i), regs[i]);
			handled = IRQ_HANDLED;
		}
	}

	if (handled == IRQ_HANDLED) {
		for_each_set_bit(bit, (unsigned long *)&regs[0], num_int_csrs * 64)
			is_interrupt(dd, bit);
	} else {
		hfi2_write_csr(dd, cce_msix_int_granted_reg, 0x1);
	}

	return handled;
}

static inline void __hfi2_sde_eoi_intr(struct sdma_engine *sde, u32 off,
				       u64 status)
{
	struct hfi2_devdata *dd = sde->dd;

	/* clear the interrupt(s) *after* handling them */
	hfi2_write_csr(dd, dd->params->cce_int_clear_reg + off, status);
	if (hfi2_sdma_work_pending(sde))
		hfi2_write_csr(dd, dd->params->cce_int_force_reg + off,
			       sde->int_mask);
}



/*
 * Force a 0->1 transition on the given interrupt number.
 *
 * Caller is responsible for any complications that might
 * arise from other concurrent activity.
 */
void hfi2_force_intr(struct hfi2_devdata *dd, u16 nr)
{
	u32 reg = (nr / 64) * 8;
	u64 bit = 1ull << (nr % 64);

	/* clear bit first, to be sure it is off */
	hfi2_write_csr(dd, dd->params->cce_int_clear_reg + reg, bit);
	/* force the above write on the chip */
	hfi2_read_csr(dd, dd->params->cce_int_clear_reg + reg);

	hfi2_write_csr(dd, dd->params->cce_int_force_reg + reg, bit);
}

/*
 * Clear the receive interrupt.  Use a read of the interrupt clear CSR
 * to insure that the write completed.  This does NOT guarantee that
 * queued DMA writes to memory from the chip are pushed.
 */
static inline void clear_recv_intr(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_devdata *dd = rcd->dd;
	u32 addr = dd->params->cce_int_clear_reg + (8 * rcd->ireg);

	hfi2_write_csr(dd, addr, rcd->imask);
	flush_csr_write(dd);
}

/* force the receive interrupt */
void hfi2_force_recv_intr(struct hfi2_ctxtdata *rcd)
{
	hfi2_write_csr(rcd->dd,
		       rcd->dd->params->cce_int_force_reg + (8 * rcd->ireg),
		       rcd->imask);
}

/*
 * Return the receive sequence from the given RHF.  This routine is intended
 * to be called without a previously determined chip type, so it needs to
 * check the chip type to correctly extract the RHF field.  Hence "slow".
 */
u32 hfi2_slow_rhf_rcv_seq(struct hfi2_ctxtdata *rcd, u64 rhf)
{
	if (rcd->dd->params->chip_type == CHIP_WFR)
		return wfr_rhf_rcv_seq(rhf);
	return jkr_rhf_rcv_seq(rhf);
}

static bool hfi2_packet_present(struct hfi2_ctxtdata *rcd)
{
	if (likely(!rcd->rcvhdrtail_kvaddr)) {
		u32 seq = hfi2_slow_rhf_rcv_seq(rcd,
						rhf_to_cpu(get_rhf_addr(rcd)));

		return !last_rcv_seq(rcd, seq);
	}
	return hfi2_rcd_head(rcd) != get_rcvhdrtail(rcd);
}

/*
 * Return non-zero if a packet is present.
 *
 * This routine is called when rechecking for packets after the RcvAvail
 * interrupt has been cleared down.  First, do a quick check of memory for
 * a packet present.  If not found, use an expensive CSR read of the context
 * tail to determine the actual tail.  The CSR read is necessary because there
 * is no method to push pending DMAs to memory other than an interrupt and we
 * are trying to determine if we need to force an interrupt.
 */
bool hfi2_rcd_packet_present(struct hfi2_ctxtdata *rcd)
{
	u32 tail;

	if (hfi2_packet_present(rcd))
		return 1;

	/* fall back to a CSR read, correct indpendent of DMA_RTAIL */
	tail = (u32)read_uctxt_csr(rcd->dd, rcd->ctxt,
				   rcd->dd->params->rcv_hdr_tail_reg);
	return hfi2_rcd_head(rcd) != tail;
}

/*
 * Common code for receive contexts interrupt handlers.
 * Update traces, increment kernel IRQ counter and
 * setup ASPM when needed.
 */
static void receive_interrupt_common(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_devdata *dd = rcd->dd;

	trace_hfi2_receive_interrupt(dd, rcd);
	this_cpu_inc(*dd->int_counter);
}

/*
 * __hfi2_rcd_eoi_intr() - Make HW issue receive interrupt
 * when there are packets present in the queue. When calling
 * with interrupts enabled please use hfi2_rcd_eoi_intr.
 *
 * @rcd: valid receive context
 */
static void __hfi2_rcd_eoi_intr(struct hfi2_ctxtdata *rcd)
{
	if (!rcd->rcvhdrq)
		return;
	clear_recv_intr(rcd);
	if (hfi2_rcd_packet_present(rcd))
		hfi2_force_recv_intr(rcd);
}

/**
 * hfi2_rcd_eoi_intr() - End of Interrupt processing action
 *
 * @rcd: Ptr to hfi2_ctxtdata of receive context
 *
 *  Hold IRQs so we can safely clear the interrupt and
 *  recheck for a packet that may have arrived after the previous
 *  check and the interrupt clear.  If a packet arrived, force another
 *  interrupt. This routine can be called at the end of receive packet
 *  processing in interrupt service routines, interrupt service thread
 *  and softirqs
 */
void hfi2_rcd_eoi_intr(struct hfi2_ctxtdata *rcd)
{
	unsigned long flags;

	local_irq_save(flags);
	__hfi2_rcd_eoi_intr(rcd);
	local_irq_restore(flags);
}

void cne_rcd_eoi_intr(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_devdata *dd = rcd->dd;
	unsigned long flags;
	u32 cnt;

	if (!is_netdev_cyr(rcd)) {
		hfi2_rcd_eoi_intr(rcd);
		return;
	}

	local_irq_save(flags);
	if (!rcd->rcvhdrq)
		goto out;

	/*
	 * No flush read after the clear.  The RcvHdrHead write below makes
	 * the hardware re-evaluate RcvAvailInt, and the clear cannot be
	 * overtaken by an interrupt that a later write raises (HAS 14.6.3.2).
	 * The force write below is a CCE write too, ordered behind the clear.
	 */
	hfi2_write_csr(dd, dd->params->cce_int_clear_reg + (8 * rcd->ireg),
		       rcd->imask);

	cnt = min_t(u32, dd->rcv_intr_count, RCV_HDR_HEAD_COUNTER_MASK);
	hfi2_update_usrhead_ctxt(dd, rcd->ctxt, hfi2_rcd_head(rcd), cnt, 0, 0);

	/* memory only: a positive answer is exact */
	if (hfi2_packet_present(rcd))
		hfi2_force_recv_intr(rcd);
out:
	local_irq_restore(flags);
}


/**
 * hfi2_netdev_rx_napi - napi poll function to move eoi inline
 * @napi: pointer to napi object
 * @budget: netdev budget
 */
int hfi2_netdev_rx_napi(struct napi_struct *napi, int budget)
{
	struct hfi2_netdev_rxq *rxq =
		container_of(napi, struct hfi2_netdev_rxq, napi);
	struct hfi2_ctxtdata *rcd = rxq->rcd;
	int work_done = 0;

	work_done = rcd->do_interrupt(rcd, budget);

	if (work_done < budget) {
		napi_complete_done(napi, work_done);
		hfi2_rcd_eoi_intr(rcd);
	}

	return work_done;
}

/* Receive packet napi handler for netdevs AIP  */
irqreturn_t hfi2_receive_context_interrupt_napi(int irq, void *data)
{
	struct hfi2_ctxtdata *rcd = data;

	receive_interrupt_common(rcd);

	if (likely(rcd->napi)) {
		if (likely(napi_schedule_prep(rcd->napi)))
			__napi_schedule_irqoff(rcd->napi);
		else if (!is_netdev_cyr(rcd))
			__hfi2_rcd_eoi_intr(rcd);
	} else {
		WARN_ONCE(1, "Napi IRQ handler without napi set up ctxt=%d\n",
			  rcd->ctxt);
		__hfi2_rcd_eoi_intr(rcd);
	}

	return IRQ_HANDLED;
}

/* Receive IRQ handler for bulksvc DMS lane contexts */
irqreturn_t hfi2_receive_context_interrupt_bulksvc(int irq, void *data)
{
	struct hfi2_ctxtdata *rcd = data;

	receive_interrupt_common(rcd);
	hfi2_bulksvc_rcd_wake(rcd);

	return IRQ_HANDLED;
}

/*
 * Receive packet IRQ handler.  This routine expects to be on its own IRQ.
 * This routine will try to handle packets immediately (latency), but if
 * it finds too many, it will invoke the thread handler (bandwitdh).  The
 * chip receive interrupt is *not* cleared down until this or the thread (if
 * invoked) is finished.  The intent is to avoid extra interrupts while we
 * are processing packets anyway.
 */
irqreturn_t hfi2_receive_context_interrupt(int irq, void *data)
{
	struct hfi2_ctxtdata *rcd = data;
	int disposition;

	receive_interrupt_common(rcd);

	/* receive interrupt remains blocked while processing packets */
	disposition = rcd->do_interrupt(rcd, 0);

	/*
	 * Too many packets were seen while processing packets in this
	 * IRQ handler.  Invoke the handler thread.  The receive interrupt
	 * remains blocked.
	 */
	if (disposition == RCV_PKT_LIMIT)
		return IRQ_WAKE_THREAD;

	__hfi2_rcd_eoi_intr(rcd);
	return IRQ_HANDLED;
}

/*
 * Receive packet thread handler.  This expects to be invoked with the
 * receive interrupt still blocked.
 */
irqreturn_t hfi2_receive_context_thread(int irq, void *data)
{
	struct hfi2_ctxtdata *rcd = data;

	/* receive interrupt is still blocked from the IRQ handler */
	(void)rcd->do_interrupt(rcd, 1);

	hfi2_rcd_eoi_intr(rcd);

	return IRQ_HANDLED;
}

/* ========================================================================= */



void hfi2_wfr_set_port_tid_config(struct hfi2_devdata *dd, int pidx, u16 ctxt,
				  u32 eager_base, u16 alloced,
				  u32 expected_base, u32 expected_count)
{
	u64 reg;

	/* set eager count and base index */
	reg = ((u64)(alloced >> RCV_SHIFT) << RCV_EGR_CTRL_EGR_CNT_SHIFT) |
	      ((eager_base >> RCV_SHIFT) << RCV_EGR_CTRL_EGR_BASE_INDEX_SHIFT);
	write_rctxt_csr(dd, ctxt, dd->params->rcv_egr_ctrl_reg, reg);

	/*
	 * Set TID (expected) count and base index.
	 * rcd->expected_count is set to individual RcvArray entries,
	 * not pairs, and the CSR takes a pair-count in groups of
	 * four, so divide by 8.
	 */
	reg = ((u64)(expected_count >> RCV_SHIFT)
	       << RCV_TID_CTRL_TID_PAIR_CNT_SHIFT) |
	      ((expected_base >> RCV_SHIFT)
	       << RCV_TID_CTRL_TID_BASE_INDEX_SHIFT);
	write_rctxt_csr(dd, ctxt, dd->params->rcv_tid_ctrl_reg, reg);
	/* WFR does not have a port tid count */
}

/* RcvArray base address */
static inline u8 __iomem *rcvarray_base(struct hfi2_devdata *dd, u32 ctxt)
{
	return dd->bar_maps[ctxt_bar_idx(ctxt)].rcvarray_wc;
}

/*
 * Update a TID entry of a given receive context.
 *
 * @rcd	  Receive context being updated.
 * @index When type is PT_EAGER or PT_EXPECTED, index is the index into the
 *	  receive array _relative_ to how the context is set up.  Otherwise
 *	  it is a raw index.
 * @pa	  Physical DMA address.  If invalidating, this should be zero.
 * @order Order of map.  If invalidating, this should be zero.
 * @flush Forced flush.  Otherwise, will flush on eager or on 32-byte boundary.
 */
void hfi2_wfr_put_tid(struct hfi2_ctxtdata *rcd, u32 index, u32 type,
		      unsigned long pa, u16 order, bool flush)
{
	struct hfi2_devdata *dd = rcd->dd;
	u8 __iomem *base = rcvarray_base(dd, rcd->ctxt);
	u64 reg;

	if (!(dd->flags & HFI2_PRESENT))
		return;

	if (type == PT_EAGER)
		index += rcd->eager_base;
	else if (type == PT_EXPECTED)
		index += rcd->expected_base;
	trace_hfi2_put_tid(dd, index, type, pa, order);

#define RT_ADDR_SHIFT 12 /* 4KB kernel address boundary */
	reg = RCV_ARRAY_RT_WRITE_ENABLE_SMASK |
	      (u64)order << RCV_ARRAY_RT_BUF_SIZE_SHIFT |
	      ((pa >> RT_ADDR_SHIFT) & RCV_ARRAY_RT_ADDR_MASK)
		      << RCV_ARRAY_RT_ADDR_SHIFT;
	trace_hfi2_write_rcvarray(base + (index * 8), reg);
	writeq(reg, base + (index * 8));

	if (type == PT_EAGER || flush || (index & 3) == 3)
		flush_wc();
}

/*
 * Write an "no-op" RcvArray entry.
 *
 * Called by the TID registration code to write to unused/unneeded RcvArray
 * entries to fill out a write-combining buffer line.  The HFI will ignore this
 * write to the RcvArray entry.
 */
void hfi2_wfr_rcv_array_wc_fill(struct hfi2_ctxtdata *rcd, u32 index, u32 type)
{
	struct hfi2_devdata *dd = rcd->dd;

	/*
	 * Doing the WC fill writes only makes sense if the device is
	 * present and the RcvArray has been mapped as WC memory.
	 */
	if (dd->flags & HFI2_PRESENT) {
		if (type == PT_EAGER)
			index += rcd->eager_base;
		else if (type == PT_EXPECTED)
			index += rcd->expected_base;

		writeq(0, rcvarray_base(dd, rcd->ctxt) + (index * 8));
		if ((index & 3) == 3)
			flush_wc();
	}
}



/*
 * Write an "no-op" RcvArray entry.
 *
 * Called by the TID registration code to write to unused/unneeded RcvArray
 * entries to fill out a write-combining buffer line.  The HFI will ignore this
 * write to the RcvArray entry.
 */

static void wfr_init_tids(struct hfi2_devdata *dd)
{
	const u64 reg = RCV_ARRAY_RT_WRITE_ENABLE_SMASK;
	u32 num_rcv;
	u32 i;

	num_rcv = chip_rcv_array_count(dd);
	for (i = 0; i < num_rcv; i++) {
		/* WFR RcvArray addressing is not ctxt relative, just use 0 */
		writeq(reg, rcvarray_base(dd, 0) + (i * 8));
		if ((i & 3) == 3)
			flush_wc();
	}
}
void hfi2_clear_tids(struct hfi2_ctxtdata *rcd)
{
	u32 i;

	for (i = 0; i < rcd->egrbufs.alloced; i++)
		rcd->dd->params->put_tid(rcd, i, PT_EAGER, 0, 0, false);

	for (i = 0; i < rcd->expected_count; i++)
		rcd->dd->params->put_tid(rcd, i, PT_EXPECTED, 0, 0, false);
}

static const char *const ib_cfg_name_strings[] = {
	"HFI2_IB_CFG_LIDLMC",	     "HFI2_IB_CFG_LWID_DG_ENB",
	"HFI2_IB_CFG_LWID_ENB",	     "HFI2_IB_CFG_LWID",
	"HFI2_IB_CFG_SPD_ENB",	     "HFI2_IB_CFG_SPD",
	"HFI2_IB_CFG_RXPOL_ENB",     "HFI2_IB_CFG_LREV_ENB",
	"HFI2_IB_CFG_LINKLATENCY",   "HFI2_IB_CFG_HRTBT",
	"HFI2_IB_CFG_OP_VLS",	     "HFI2_IB_CFG_VL_HIGH_CAP",
	"HFI2_IB_CFG_VL_LOW_CAP",    "HFI2_IB_CFG_OVERRUN_THRESH",
	"HFI2_IB_CFG_PHYERR_THRESH", "HFI2_IB_CFG_LINKDEFAULT",
	"HFI2_IB_CFG_PKEYS",	     "HFI2_IB_CFG_MTU",
	"HFI2_IB_CFG_LSTATE",	     "HFI2_IB_CFG_VL_HIGH_LIMIT",
	"HFI2_IB_CFG_PMA_TICKS",     "HFI2_IB_CFG_PORT"
};

const char *hfi2_ib_cfg_name(int which)
{
	if (which < 0 || which >= ARRAY_SIZE(ib_cfg_name_strings))
		return "invalid";
	return ib_cfg_name_strings[which];
}

int hfi2_get_ib_cfg(struct hfi2_pportdata *ppd, int which)
{
	int val = 0;

	switch (which) {
	case HFI2_IB_CFG_LWID_ENB: /* allowed Link-width */
		val = ppd->link_width_enabled;
		break;
	case HFI2_IB_CFG_LWID: /* currently active Link-width */
		val = ppd->link_width_active;
		break;
	case HFI2_IB_CFG_SPD_ENB: /* allowed Link speeds */
		val = ppd->link_speed_enabled;
		break;
	case HFI2_IB_CFG_SPD: /* current Link speed */
		val = ppd->link_speed_active;
		break;

	case HFI2_IB_CFG_RXPOL_ENB: /* Auto-RX-polarity enable */
	case HFI2_IB_CFG_LREV_ENB: /* Auto-Lane-reversal enable */
	case HFI2_IB_CFG_LINKLATENCY:
		goto unimplemented;

	case HFI2_IB_CFG_OP_VLS:
		val = ppd->actual_vls_operational;
		break;
	case HFI2_IB_CFG_VL_HIGH_CAP: /* VL arb high priority table size */
		val = VL_ARB_HIGH_PRIO_TABLE_SIZE;
		break;
	case HFI2_IB_CFG_VL_LOW_CAP: /* VL arb low priority table size */
		val = VL_ARB_LOW_PRIO_TABLE_SIZE;
		break;
	case HFI2_IB_CFG_OVERRUN_THRESH: /* IB overrun threshold */
		val = ppd->overrun_threshold;
		break;
	case HFI2_IB_CFG_PHYERR_THRESH: /* IB PHY error threshold */
		val = ppd->phy_error_threshold;
		break;
	case HFI2_IB_CFG_LINKDEFAULT: /* IB link default (sleep/poll) */
		val = HLS_DEFAULT;
		break;

	case HFI2_IB_CFG_HRTBT: /* Heartbeat off/enable/auto */
	case HFI2_IB_CFG_PMA_TICKS:
	default:
unimplemented:
		if (HFI2_CAP_IS_KSET(PRINT_UNIMPL))
			ppd_dev_info(ppd, "%s: which %s: not implemented\n",
				     __func__, hfi2_ib_cfg_name(which));
		break;
	}

	return val;
}

/*
 * The largest MAD packet size.
 */
#define MAX_MAD_PACKET 2048

/*
 * Return the maximum header bytes that can go on the _wire_
 * for this device. This count includes the ICRC which is
 * not part of the packet held in memory but it is appended
 * by the HW.
 * This is dependent on the device's receive header entry size.
 * HFI allows this to be set per-receive context, but the
 * driver presently enforces a global value.
 */
u32 hfi2_lrh_max_header_bytes(struct hfi2_pportdata *ppd)
{
	/*
	 * The maximum non-payload (MTU) bytes in LRH.PktLen are
	 * the Receive Header Entry Size minus the PBC (or RHF) size
	 * plus one DW for the ICRC appended by HW.
	 *
	 * hdrqentsize is in DW.
	 *
	 * Use this port's kernel contexts' receive header entry size.
	 */
	return (kctxt_hdrqentsize(ppd) - 2 /*PBC/RHF*/ + 1 /*ICRC*/) << 2;
}

/* set what to accept in the port hardware */
static void set_dlid_lmc(struct hfi2_pportdata *ppd, u32 mask, u32 lid)
{
	u64 c1 = hfi2_read_csr(ppd->dd, DCC_CFG_PORT_CONFIG1);

	c1 &= ~(DCC_CFG_PORT_CONFIG1_TARGET_DLID_SMASK |
		DCC_CFG_PORT_CONFIG1_DLID_MASK_SMASK);
	c1 |= ((lid & DCC_CFG_PORT_CONFIG1_TARGET_DLID_MASK)
	       << DCC_CFG_PORT_CONFIG1_TARGET_DLID_SHIFT) |
	      ((mask & DCC_CFG_PORT_CONFIG1_DLID_MASK_MASK)
	       << DCC_CFG_PORT_CONFIG1_DLID_MASK_SHIFT);
	hfi2_write_csr(ppd->dd, DCC_CFG_PORT_CONFIG1, c1);
}

/* set maximum MTU for the port */
void hfi2_wfr_set_port_max_mtu(struct hfi2_pportdata *ppd, u32 maxvlmtu)
{
	u64 config;
	u32 dcmtu;

	/* Adjust maximum MTU for the port in DC */
	dcmtu = maxvlmtu == 10240 ? DCC_CFG_PORT_MTU_CAP_10240 :
				    (ilog2(maxvlmtu >> 8) + 1);
	config = hfi2_read_csr(ppd->dd, DCC_CFG_PORT_CONFIG);
	config &= ~DCC_CFG_PORT_CONFIG_MTU_CAP_SMASK;
	config |= ((u64)dcmtu & DCC_CFG_PORT_CONFIG_MTU_CAP_MASK)
		  << DCC_CFG_PORT_CONFIG_MTU_CAP_SHIFT;
	hfi2_write_csr(ppd->dd, DCC_CFG_PORT_CONFIG, config);
}

/*
 * Set Send Length
 * @ppd: per port data
 *
 * Set the MTU by limiting how many DWs may be sent.  The SendLenCheck*
 * registers compare against LRH.PktLen, so use the max bytes included
 * in the LRH.
 *
 * This routine changes all VL values except VL15, which it maintains at
 * the same value.
 */
void hfi2_set_send_length(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u32 maxvlmtu = ppd->vld[15].mtu;
	int i, j;
	u32 thres;

	/* per-vl send contexts are not present if port is not available */
	if (!port_available_ppd(ppd))
		return;

	for (i = 0; i < ppd->vls_supported; i++) {
		if (ppd->vld[i].mtu > maxvlmtu)
			maxvlmtu = ppd->vld[i].mtu;
	}

	/* only WFR needs to write SendLenCheckn */
	if (dd->params->chip_type == CHIP_WFR) {
		u32 max_hb = hfi2_lrh_max_header_bytes(ppd);
		u64 len1 = 0;
		u64 len2 = (((ppd->vld[15].mtu + max_hb) >> 2) &
			    SEND_LEN_CHECK1_LEN_VL15_MASK)
			   << SEND_LEN_CHECK1_LEN_VL15_SHIFT;

		for (i = 0; i < ppd->vls_supported; i++) {
			if (i <= 3)
				len1 |= (((ppd->vld[i].mtu + max_hb) >> 2) &
					 SEND_LEN_CHECK0_LEN_VL0_MASK)
					<< ((i % 4) *
					    SEND_LEN_CHECK0_LEN_VL1_SHIFT);
			else
				len2 |= (((ppd->vld[i].mtu + max_hb) >> 2) &
					 SEND_LEN_CHECK1_LEN_VL4_MASK)
					<< ((i % 4) *
					    SEND_LEN_CHECK1_LEN_VL5_SHIFT);
		}
		write_eport_csr(dd, ppd->hw_pidx,
				dd->params->send_len_check0_reg, len1);
		write_eport_csr(dd, ppd->hw_pidx,
				dd->params->send_len_check1_reg, len2);
	}
	/* adjust kernel credit return thresholds based on new MTUs */
	/* all kernel receive contexts have the same hdrqentsize */
	for (i = 0; i < ppd->vls_supported; i++) {
		thres = min(hfi2_sc_percent_to_threshold(ppd->vld[i].sc, 50),
			    hfi2_sc_mtu_to_threshold(ppd->vld[i].sc,
						     ppd->vld[i].mtu,
						     kctxt_hdrqentsize(ppd)));
		for (j = 0; j < INIT_SC_PER_VL; j++)
			hfi2_sc_set_cr_threshold(
				hfi2_pio_select_send_context_vl(ppd, j, i),
				thres);
	}
	thres = min(hfi2_sc_percent_to_threshold(ppd->vld[15].sc, 50),
		    hfi2_sc_mtu_to_threshold(ppd->vld[15].sc, ppd->vld[15].mtu,
					     kctxt_hdrqentsize(ppd)));
	hfi2_sc_set_cr_threshold(ppd->vld[15].sc, thres);

	dd->params->set_port_max_mtu(ppd, maxvlmtu);
}

void hfi2_set_lidlmc(struct hfi2_pportdata *ppd)
{
	int i;
	u64 sreg = 0;
	u64 kreg;
	struct hfi2_devdata *dd = ppd->dd;
	u32 mask = ppd->lid_mask;
	u32 kmask = mask;
	u32 lid;

	/*
	 * PF0's kernel and VL15 contexts also send GMP replies from vPort LIDs
	 * (hfi2_ud_slid()), so let their SLID check cover the FM's vPort block.
	 * User contexts and VFs keep the exact physical/vPort LID check.
	 */
	if (!dd->is_vf && dd->params->chip_type != CHIP_WFR)
		kmask &= ppd->lid_block_mask;

	/*
	 * Program 0 in CSR if port lid is extended. This prevents
	 * 9B packets being sent out for large lids.
	 */
	lid = (ppd->lid >= be16_to_cpu(IB_MULTICAST_LID_BASE)) ? 0 : ppd->lid;
	if (ppd->hfi2_snoop.mode_flag)
		ppd_dev_info(ppd, "Set lid/lmc while snooping");

	/*
	 * Iterate over all the send contexts for this port and set their SLID
	 * check.
	 */
	if (dd->params->chip_type == CHIP_WFR) {
		/* set port hardware */
		set_dlid_lmc(ppd, mask, lid);

		sreg = ((mask & SEND_CTXT_CHECK_SLID_MASK_MASK)
			<< SEND_CTXT_CHECK_SLID_MASK_SHIFT) |
		       (((lid & mask) & SEND_CTXT_CHECK_SLID_VALUE_MASK)
			<< SEND_CTXT_CHECK_SLID_VALUE_SHIFT);
		kreg = sreg;
	} else {
		sreg = ((u64)(mask & JKR_SEND_CTXT_CHECK_SLID_MASK_MASK)
			<< JKR_SEND_CTXT_CHECK_SLID_MASK_SHIFT) |
		       (lid & mask & JKR_SEND_CTXT_CHECK_SLID_VALUE_MASK) |
		       BIT_ULL(63); /* PermissiveSlidAllowed */
		kreg = ((u64)(kmask & JKR_SEND_CTXT_CHECK_SLID_MASK_MASK)
			<< JKR_SEND_CTXT_CHECK_SLID_MASK_SHIFT) |
		       (lid & kmask & JKR_SEND_CTXT_CHECK_SLID_VALUE_MASK) |
		       BIT_ULL(63);
	}

	for (i = 0; i < dd->num_send_contexts; i++) {
		struct send_context *sc = dd->send_contexts[i].sc;
		u64 reg;

		if (!sc)
			continue;
		if (sc->ppd != ppd)
			continue;

		reg = (sc->type == SC_KERNEL || sc->type == SC_VL15) ?
		      kreg : sreg;

		hfi2_cdbg(LINKVERB, "SendContext[%d].SLID_CHECK = 0x%x", i,
			  (u32)reg);
		hfi2_priv_reg_op(dd, ppd->hw_pidx, sc->hw_context, sc->type,
				 SC_CHK_SLID_OP, reg);
	}

	/* Now we have to do the same thing for the sdma engines */
	hfi2_sdma_update_lmc(dd, mask, lid);
}



/*
 * Write the given fabric manager table.
 */
int hfi2_fm_set_table(struct hfi2_pportdata *ppd, int which, void *t)
{
	int ret = 0;
	struct vl_arb_cache *vlc;

	switch (which) {
	case FM_TBL_VL_HIGH_ARB:
		vlc = hfi2_vl_arb_lock_cache(ppd, HI_PRIO_TABLE);
		if (hfi2_vl_arb_match_cache(vlc, t)) {
			hfi2_vl_arb_unlock_cache(ppd, HI_PRIO_TABLE);
			break;
		}
		hfi2_vl_arb_set_cache(vlc, t);
		hfi2_vl_arb_unlock_cache(ppd, HI_PRIO_TABLE);
		ret = hfi2_set_vl_weights(
			ppd, ppd->dd->params->send_high_priority_list_reg,
			VL_ARB_HIGH_PRIO_TABLE_SIZE, t);
		break;
	case FM_TBL_VL_LOW_ARB:
		vlc = hfi2_vl_arb_lock_cache(ppd, LO_PRIO_TABLE);
		if (hfi2_vl_arb_match_cache(vlc, t)) {
			hfi2_vl_arb_unlock_cache(ppd, LO_PRIO_TABLE);
			break;
		}
		hfi2_vl_arb_set_cache(vlc, t);
		hfi2_vl_arb_unlock_cache(ppd, LO_PRIO_TABLE);
		ret = hfi2_set_vl_weights(
			ppd, ppd->dd->params->send_low_priority_list_reg,
			VL_ARB_LOW_PRIO_TABLE_SIZE, t);
		break;
	case FM_TBL_BUFFER_CONTROL:
		ret = hfi2_set_buffer_control(ppd, t);
		break;
	case FM_TBL_SC2VLNT:
		hfi2_set_sc2vlnt(ppd->dd, t);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

/*
 * Disable all data VLs.
 *
 * Return 0 if disabled, non-zero if the VLs cannot be disabled.
 */
static int disable_data_vls(struct hfi2_pportdata *ppd)
{
	if (hfi2_is_ax(ppd->dd))
		return 1;

	hfi2_pio_send_control(ppd, PSC_DATA_VL_DISABLE);

	return 0;
}

/*
 * hfi2_open_fill_data_vls() - the counterpart to hfi2_stop_drain_data_vls().
 * Just re-enables all data VLs (the "fill" part happens
 * automatically - the name was chosen for symmetry with
 * hfi2_stop_drain_data_vls()).
 *
 * Return 0 if successful, non-zero if the VLs cannot be enabled.
 */
int hfi2_open_fill_data_vls(struct hfi2_pportdata *ppd)
{
	if (hfi2_is_ax(ppd->dd))
		return 1;

	hfi2_pio_send_control(ppd, PSC_DATA_VL_ENABLE);

	return 0;
}

/*
 * drain_data_vls() - assumes that disable_data_vls() has been called,
 * wait for occupancy (of per-VL FIFOs) for all contexts, and SDMA
 * engines to drop to 0.
 */
static void drain_data_vls(struct hfi2_devdata *dd)
{
	hfi2_sc_wait(dd);
	hfi2_sdma_wait(dd);
	pause_for_credit_return(dd);
}

/*
 * hfi2_stop_drain_data_vls() - disable, then drain all per-VL fifos.
 *
 * Use hfi2_open_fill_data_vls() to resume using data VLs.  This pair is
 * meant to be used like this:
 *
 * hfi2_stop_drain_data_vls(dd);
 * // do things with per-VL resources
 * hfi2_open_fill_data_vls(dd);
 */
int hfi2_stop_drain_data_vls(struct hfi2_pportdata *ppd)
{
	int ret;

	ret = disable_data_vls(ppd);
	if (ret == 0)
		drain_data_vls(ppd->dd);

	return ret;
}

/*
 * Convert a nanosecond time to a cclock count.  No matter how slow
 * the cclock, a non-zero ns will always have a non-zero result.
 */
u32 hfi2_ns_to_cclock(struct hfi2_devdata *dd, u32 ns)
{
	u32 cclocks;

	/* simulation pretends to be ASIC */
	cclocks = (ns * 1000) / dd->params->asic_cclock_ps;
	if (ns && !cclocks) /* if ns nonzero, must be at least 1 */
		cclocks = 1;
	return cclocks;
}

/*
 * Convert a cclock count to nanoseconds. No matter how slow
 * the cclock, a non-zero cclocks will always have a non-zero result.
 */
u32 hfi2_cclock_to_ns(struct hfi2_devdata *dd, u32 cclocks)
{
	u32 ns;

	/* simulation pretends to be ASIC */
	ns = (cclocks * dd->params->asic_cclock_ps) / 1000;
	if (cclocks && !ns)
		ns = 1;
	return ns;
}

/*
 * Dynamically adjust the receive interrupt timeout for a context based on
 * incoming packet rate.
 *
 * NOTE: Dynamic adjustment does not allow hfi2_rcv_intr_count to be zero.
 */






/*
 * Read the counters from the table, store the values read into results.
 */
static void read_counters(struct hfi2_devdata *dd,
			  const struct cntr_entry *table, int table_size,
			  void *context, u64 *results)
{
	const struct cntr_entry *entry;
	u64 val;
	int i, j;

	/* fill in each counter from the table */
	for (i = 0; i < table_size; i++) {
		entry = &table[i];
		hfi2_cdbg(CNTR, "reading %s", entry->name);
		if (entry->flags & CNTR_DISABLED) {
			/* Nothing */
			hfi2_cdbg(CNTR, "\tDisabled");
			continue;
		}

		if (entry->flags & CNTR_VL) {
			hfi2_cdbg(CNTR, "\tPer VL");
			for (j = 0; j < C_VL_COUNT; j++) {
				val = entry->rw_cntr(entry, context, j,
						     CNTR_MODE_R, 0);
				hfi2_cdbg(CNTR, "\t\tRead 0x%llx for %d", val,
					  j);
				results[entry->offset + j] = val;
			}
		} else if (entry->flags & CNTR_PBC_TEST) {
			for (j = 0; j < HFI2_PBC_TEST_NCNTR; j++)
				results[entry->offset + j] =
					entry->rw_cntr(entry, context, j,
						       CNTR_MODE_R, 0);
		} else if (entry->flags & CNTR_SDMA) {
			hfi2_cdbg(CNTR, "\tPer SDMA Engine");
			for (j = 0; j < dd->num_sdma; j++) {
				if (!sdma_engine_initialized(dd, j))
					continue;
				val = entry->rw_cntr(entry, context, j,
						     CNTR_MODE_R, 0);
				hfi2_cdbg(CNTR, "\t\tRead 0x%llx for %d", val, j);
				results[entry->offset + j] = val;
			}
		} else if (entry->flags & CNTR_OVF) {
			hfi2_cdbg(CNTR, "\tPer ctxt");
			for (j = 0; j < dd->num_rcd; j++) {
				if (test_bit(j, dd->ovf_disabled))
					continue;
				val = entry->rw_cntr(entry, context, j,
						     CNTR_MODE_R, 0);
				hfi2_cdbg(CNTR, "\t\tRead 0x%llx for %d", val,
					  j);
				results[entry->offset + dd->ovf_offset[j]] =
					val;
			}
		} else {
			val = entry->rw_cntr(entry, context, CNTR_INVALID_VL,
					     CNTR_MODE_R, 0);
			results[entry->offset] = val;
			hfi2_cdbg(CNTR, "\tRead 0x%llx", val);
		}
	}
}

/*
 * Return device counter names or updated counter values.  Return buffer size.
 * Used by sysfs and verbs.
 */
u32 hfi2_read_cntrs(struct hfi2_devdata *dd, char **namep, u64 **cntrp)
{
	if (namep) {
		*namep = dd->cntrnames;
		return dd->cntrnameslen;
	}
	if (dd->is_vf)
		goto skip;
	read_counters(dd, hfi2_shared_dev_cntrs, SHARED_DEV_CNTR_LAST, dd,
		      dd->cntrs);
	read_counters(dd, dd->params->chip_dev_cntrs,
		      dd->params->chip_num_dev_cntrs, dd, dd->cntrs);
skip:
	*cntrp = dd->cntrs;
	return dd->ndevcntrs * sizeof(u64);
}

/*
 * Return port counter names or updated counter values.  Return buffer size.
 * Used by sysfs and verbs.
 */
u32 hfi2_read_portcntrs(struct hfi2_pportdata *ppd, char **namep, u64 **cntrp)
{
	struct hfi2_devdata *dd = ppd->dd;

	if (namep) {
		*namep = dd->portcntrnames;
		return dd->portcntrnameslen;
	}

	read_counters(dd, hfi2_shared_port_cntrs, SHARED_PORT_CNTR_LAST, ppd,
		      ppd->cntrs);
	read_counters(dd, dd->params->chip_port_cntrs,
		      dd->params->chip_num_port_cntrs, ppd, ppd->cntrs);

	*cntrp = ppd->cntrs;
	return dd->nportcntrs * sizeof(u64);
}

void hfi2_free_cntrs(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	int i;

	if (dd->synth_stats_timer.function)
		timer_delete_sync(&dd->synth_stats_timer);
	if (dd->rcverr_timer.function)
		timer_delete_sync(&dd->rcverr_timer);
	cancel_work_sync(&dd->update_cntr_work);
	cancel_work_sync(&dd->rcverr_work);
	ppd = (struct hfi2_pportdata *)(dd + 1);
	for (i = 0; i < dd->num_pports; i++, ppd++) {
		kfree(ppd->cntrs);
		kfree(ppd->scntrs);
		free_percpu(ppd->ibport_data.rvp.rc_acks);
		free_percpu(ppd->ibport_data.rvp.rc_qacks);
		free_percpu(ppd->ibport_data.rvp.rc_delayed_comp);
		ppd->cntrs = NULL;
		ppd->scntrs = NULL;
		ppd->ibport_data.rvp.rc_acks = NULL;
		ppd->ibport_data.rvp.rc_qacks = NULL;
		ppd->ibport_data.rvp.rc_delayed_comp = NULL;
	}
	kfree(dd->portcntrnames);
	dd->portcntrnames = NULL;
	kfree(dd->cntrs);
	dd->cntrs = NULL;
	kfree(dd->scntrs);
	dd->scntrs = NULL;
	kfree(dd->cntrnames);
	dd->cntrnames = NULL;
	if (dd->update_cntr_wq) {
		destroy_workqueue(dd->update_cntr_wq);
		dd->update_cntr_wq = NULL;
	}
}

static u64 read_dev_port_cntr(struct hfi2_devdata *dd, struct cntr_entry *entry,
			      u64 *psval, void *context, int vl)
{
	u64 val;
	u64 sval = *psval;

	if (entry->flags & CNTR_DISABLED) {
		dd_dev_err(dd, "Counter %s not enabled", entry->name);
		return 0;
	}

	hfi2_cdbg(CNTR, "cntr: %s vl %d psval 0x%llx", entry->name, vl, *psval);

	val = entry->rw_cntr(entry, context, vl, CNTR_MODE_R, 0);

	/* If its a synthetic counter there is more work we need to do */
	if (entry->flags & CNTR_SYNTH) {
		if (sval == CNTR_MAX) {
			/* No need to read already saturated */
			return CNTR_MAX;
		}

		if (entry->flags & CNTR_32BIT) {
			/* 32bit counters can wrap multiple times */
			u64 upper = sval >> 32;
			u64 lower = (sval << 32) >> 32;

			if (lower > val) { /* hw wrapped */
				if (upper == CNTR_32BIT_MAX)
					val = CNTR_MAX;
				else
					upper++;
			}

			if (val != CNTR_MAX)
				val = (upper << 32) | val;

		} else {
			/* If we rolled we are saturated */
			if ((val < sval) || (val > CNTR_MAX))
				val = CNTR_MAX;
		}
	}

	*psval = val;

	hfi2_cdbg(CNTR, "\tNew val=0x%llx", val);

	return val;
}

static u64 write_dev_port_cntr(struct hfi2_devdata *dd,
			       struct cntr_entry *entry, u64 *psval,
			       void *context, int vl, u64 data)
{
	u64 val;

	if (entry->flags & CNTR_DISABLED) {
		dd_dev_err(dd, "Counter %s not enabled", entry->name);
		return 0;
	}

	hfi2_cdbg(CNTR, "cntr: %s vl %d psval 0x%llx", entry->name, vl, *psval);

	if (entry->flags & CNTR_SYNTH) {
		*psval = data;
		if (entry->flags & CNTR_32BIT) {
			val = entry->rw_cntr(entry, context, vl, CNTR_MODE_W,
					     (data << 32) >> 32);
			val = data; /* return the full 64bit value */
		} else {
			val = entry->rw_cntr(entry, context, vl, CNTR_MODE_W,
					     data);
		}
	} else {
		val = entry->rw_cntr(entry, context, vl, CNTR_MODE_W, data);
	}

	*psval = val;

	hfi2_cdbg(CNTR, "\tNew val=0x%llx", val);

	return val;
}

u64 hfi2_read_dev_cntr(struct hfi2_devdata *dd, int index, int vl)
{
	struct cntr_entry *entry;
	u64 *sval;

	if (index < SHARED_DEV_CNTR_LAST) {
		entry = &hfi2_shared_dev_cntrs[index];
	} else {
		index -= dd->params->chip_dev_cntr_first;
		if (index < 0 || index >= dd->params->chip_num_dev_cntrs) {
			dd_dev_err(dd, "%s: invalid dev counter index 0x%x\n",
				   __func__,
				   index + dd->params->chip_dev_cntr_first);
			return 0;
		}
		entry = &dd->params->chip_dev_cntrs[index];
	}
	sval = dd->scntrs + entry->offset;

	if (vl != CNTR_INVALID_VL)
		sval += vl;

	return read_dev_port_cntr(dd, entry, sval, dd, vl);
}

u64 hfi2_write_dev_cntr(struct hfi2_devdata *dd, int index, int vl, u64 data)
{
	struct cntr_entry *entry;
	u64 *sval;

	if (index < SHARED_DEV_CNTR_LAST) {
		entry = &hfi2_shared_dev_cntrs[index];
	} else {
		index -= dd->params->chip_dev_cntr_first;
		if (index < 0 || index >= dd->params->chip_num_dev_cntrs) {
			dd_dev_err(dd, "%s: invalid dev counter index 0x%x\n",
				   __func__,
				   index + dd->params->chip_dev_cntr_first);
			return 0;
		}
		entry = &dd->params->chip_dev_cntrs[index];
	}
	sval = dd->scntrs + entry->offset;

	if (vl != CNTR_INVALID_VL)
		sval += vl;

	return write_dev_port_cntr(dd, entry, sval, dd, vl, data);
}

/* return the counter entry for the given index, or NULL if invalid */
static struct cntr_entry *get_port_entry(struct hfi2_devdata *dd, int index,
					 const char *caller)
{
	if (index < SHARED_PORT_CNTR_LAST)
		return &hfi2_shared_port_cntrs[index];

	index -= dd->params->chip_port_cntr_first;
	if (index < 0 || index >= dd->params->chip_num_port_cntrs) {
		dd_dev_err(dd, "%s: invalid port counter index 0x%x\n", caller,
			   index + dd->params->chip_port_cntr_first);
		return NULL;
	}
	return &dd->params->chip_port_cntrs[index];
}

/*
 * Counters may be indexed by vl or (indirectly) context number.
 *
 * Return the actual index for this counter, as determined by parameter
 * in_index and counter type.
 */
static int get_port_entry_index(struct hfi2_devdata *dd,
				struct cntr_entry *entry, int in_index)
{
	int out_index = 0;

	if (entry->flags & CNTR_OVF) {
		if (in_index >= 0 && in_index < dd->num_rcd) {
			/* vl is really a context # */
			out_index = dd->ovf_offset[in_index];
		} else {
			dd_dev_err(dd, "bad ovl ctxt %d\n", in_index);
		}
	} else {
		if (in_index != CNTR_INVALID_VL)
			out_index = in_index;
	}
	return out_index;
}

u64 hfi2_read_port_cntr(struct hfi2_pportdata *ppd, int index, int vl)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct cntr_entry *entry;
	u64 *sval;

	entry = get_port_entry(dd, index, __func__);
	if (!entry)
		return 0;
	sval = ppd->scntrs + entry->offset;

	sval += get_port_entry_index(dd, entry, vl);

	if (entry->flags & CNTR_DISABLED) {
		/* skip disabled contexts */
		return 0;
	}

	return read_dev_port_cntr(dd, entry, sval, ppd, vl);
}

u64 hfi2_write_port_cntr(struct hfi2_pportdata *ppd, int index, int vl,
			 u64 data)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct cntr_entry *entry;
	u64 *sval;

	entry = get_port_entry(dd, index, __func__);
	if (!entry)
		return 0;
	sval = ppd->scntrs + entry->offset;

	sval += get_port_entry_index(dd, entry, vl);

	if (entry->flags & CNTR_DISABLED) {
		/* skip disabled contexts */
		return 0;
	}

	return write_dev_port_cntr(dd, entry, sval, ppd, vl, data);
}

/*
 * Perform a WFR specific check on whether to update synthetic counters.
 */
bool hfi2_wfr_check_synth_status(struct hfi2_devdata *dd)
{
	struct wfr_synth_data *sd = &dd->synth_data.wfr;
	u64 cur_tx;
	u64 cur_rx;
	u64 total_flits;
	bool update = false;

	/*
	 * Rather than keep beating on the CSRs pick a minimal set that we can
	 * check to watch for potential roll over. We can do this by looking at
	 * the number of flits sent/recv. If the total flits exceeds 32bits then
	 * we have to iterate all the counters and update.
	 */
	cur_rx = hfi2_read_dev_cntr(dd, C_DC_RCV_FLITS, CNTR_INVALID_VL);
	cur_tx = hfi2_read_dev_cntr(dd, C_DC_XMIT_FLITS, CNTR_INVALID_VL);

	hfi2_cdbg(CNTR,
		  "[%d] curr tx=0x%llx rx=0x%llx :: last tx=0x%llx rx=0x%llx",
		  dd->unit, cur_tx, cur_rx, sd->last_tx, sd->last_rx);

	if ((cur_tx < sd->last_tx) || (cur_rx < sd->last_rx)) {
		/*
		 * May not be strictly necessary to update but it won't hurt and
		 * simplifies the logic here.
		 */
		update = true;
		hfi2_cdbg(CNTR, "[%d] Tripwire counter rolled, updating",
			  dd->unit);
	} else {
		total_flits = (cur_tx - sd->last_tx) + (cur_rx - sd->last_rx);
		hfi2_cdbg(CNTR, "[%d] total flits 0x%llx limit 0x%llx",
			  dd->unit, total_flits, (u64)CNTR_32BIT_MAX);
		if (total_flits >= CNTR_32BIT_MAX) {
			hfi2_cdbg(CNTR, "[%d] 32bit limit hit, updating",
				  dd->unit);
			update = true;
		}
	}

	return update;
}

void hfi2_wfr_update_synth_status(struct hfi2_devdata *dd)
{
	struct wfr_synth_data *sd = &dd->synth_data.wfr;

	/*
	 * We want the value in the register. The goal is to keep track
	 * of the number of "ticks" not the counter value. In other
	 * words if the register rolls we want to notice it and go ahead
	 * and force an update.
	 */
	sd->last_tx = hfi2_read_dev_cntr(dd, C_DC_XMIT_FLITS, CNTR_INVALID_VL);
	sd->last_rx = hfi2_read_dev_cntr(dd, C_DC_RCV_FLITS, CNTR_INVALID_VL);

	hfi2_cdbg(CNTR, "[%d] setting last tx/rx to 0x%llx 0x%llx", dd->unit,
		  sd->last_tx, sd->last_rx);
}

static void do_update_synth_timer(struct work_struct *work)
{
	bool update;
	int i;
	struct hfi2_pportdata *ppd;
	struct hfi2_devdata *dd =
		container_of(work, struct hfi2_devdata, update_cntr_work);

	update = dd->params->check_synth_status(dd);

	if (update) {
		hfi2_cdbg(CNTR, "[%d] Updating dd and ppd counters", dd->unit);
		read_counters(dd, hfi2_shared_dev_cntrs, SHARED_DEV_CNTR_LAST,
			      dd, dd->scntrs);
		read_counters(dd, dd->params->chip_dev_cntrs,
			      dd->params->chip_num_dev_cntrs, dd, dd->scntrs);
		ppd = (struct hfi2_pportdata *)(dd + 1);
		for (i = 0; i < dd->num_pports; i++, ppd++) {
			read_counters(dd, hfi2_shared_port_cntrs,
				      SHARED_PORT_CNTR_LAST, ppd, ppd->scntrs);
			read_counters(dd, dd->params->chip_port_cntrs,
				      dd->params->chip_num_port_cntrs, ppd,
				      ppd->scntrs);
		}
		dd->params->update_synth_status(dd);
	} else {
		hfi2_cdbg(CNTR, "[%d] No update necessary", dd->unit);
	}
}

static void update_synth_timer(struct timer_list *t)
{
	struct hfi2_devdata *dd = timer_container_of(dd, t, synth_stats_timer);

	queue_work(dd->update_cntr_wq, &dd->update_cntr_work);
	mod_timer(&dd->synth_stats_timer, jiffies + HZ * SYNTH_CNT_TIME);
}

static const char bit_type_32[] = ",32";
static const int bit_type_32_sz = 3;
#define C_MAX_NAME 16 /* 15 chars + one for /0 */

/*
 * Calculate and return the indexed name size.  Keep in sync with
 * copy_indexed_name().
 */
static size_t size_indexed_name(const char *raw_name, int flags, int idx)
{
	char name[C_MAX_NAME];
	size_t sz;

	snprintf(name, C_MAX_NAME, "%s%d", raw_name, idx);
	/* +1 for newline */
	sz = strlen(name) + 1;
	/* add ",32" for 32-bit counters */
	if (flags & CNTR_32BIT)
		sz += bit_type_32_sz;

	return sz;
}

/*
 * Copy indexed name into p.  Advance and return p.  Keep in sync with
 * size_indexed_name().
 */
static char *copy_indexed_name(char *p, const char *raw_name, int flags,
			       int idx)
{
	char name[C_MAX_NAME];

	snprintf(name, C_MAX_NAME, "%s%d", raw_name, idx);
	memcpy(p, name, strlen(name));
	p += strlen(name);
	/* counter is 32 bits */
	if (flags & CNTR_32BIT) {
		memcpy(p, bit_type_32, bit_type_32_sz);
		p += bit_type_32_sz;
	}
	*p++ = '\n';

	return p;
}

/*
 * Calculate and return the single name size.  Keep in sync with
 * copy_single_name().
 */
static size_t size_single_name(const char *raw_name, int flags)
{
	size_t sz;

	/* +1 for newline */
	sz = strlen(raw_name) + 1;
	/* add ",32" for 32-bit counters */
	if (flags & CNTR_32BIT)
		sz += bit_type_32_sz;

	return sz;
}

/*
 * Copy single name into p.  Advance and return p.  Keep in sync with
 * size_single_name().
 */
static char *copy_single_name(char *p, const char *raw_name, int flags)
{
	memcpy(p, raw_name, strlen(raw_name));
	p += strlen(raw_name);
	/* counter is 32 bits */
	if (flags & CNTR_32BIT) {
		memcpy(p, bit_type_32, bit_type_32_sz);
		p += bit_type_32_sz;
	}
	*p++ = '\n';

	return p;
}

/*
 * Walk through the table, increasing the calculated number of counters and
 * name size.
 */
static void size_cntr_names(struct hfi2_devdata *dd, struct cntr_entry *table,
			    int table_size, size_t *countp, size_t *szp)
{
	u32 sdma_engines = chip_sdma_engines(dd);
	u32 num_rcv = chip_rcv_contexts(dd);
	size_t count;
	size_t sz;
	int i, j;
	u16 ovf_offset;

	count = *countp; /* need current count */
	sz = 0;
	ovf_offset = 0;
	for (i = 0; i < table_size; i++) {
		if (table[i].flags & CNTR_DISABLED) {
			hfi2_dbg_early("\tSkipping %s\n", table[i].name);
			continue;
		}

		table[i].offset = count;
		if (table[i].flags & CNTR_VL) {
			for (j = 0; j < C_VL_COUNT; j++) {
				sz += size_indexed_name(table[i].name,
							table[i].flags,
							vl_from_idx(j));
				count++;
			}
		} else if (table[i].flags & CNTR_PBC_TEST) {
			for (j = 0; j < HFI2_PBC_TEST_NCNTR; j++) {
				sz += size_indexed_name(table[i].name,
							table[i].flags, j);
				count++;
			}
		} else if (table[i].flags & CNTR_SDMA) {
			for (j = 0; j < sdma_engines; j++) {
				sz += size_indexed_name(table[i].name,
							table[i].flags, j);
				count++;
			}
		} else if (table[i].flags & CNTR_OVF) {
			for (j = 0; j < num_rcv; j++) {
				if (test_bit(j, dd->ovf_disabled))
					continue;
				dd->ovf_offset[j] = ovf_offset;
				sz += size_indexed_name(table[i].name,
							table[i].flags, j);
				count++;
				ovf_offset++;
			}
		} else {
			sz += size_single_name(table[i].name, table[i].flags);
			count++;
		}
	}

	/* return updated sizes */
	*countp = count;
	*szp += sz;
}

/*
 * Fill the counter names into p.  Return p's final value.
 */
static char *fill_cntr_names(struct hfi2_devdata *dd, struct cntr_entry *table,
			     int table_size, char *p)
{
	u32 sdma_engines = chip_sdma_engines(dd);
	u32 num_rcv = chip_rcv_contexts(dd);
	int i, j;

	for (i = 0; i < table_size; i++) {
		if (table[i].flags & CNTR_DISABLED) {
			/* Nothing */
		} else if (table[i].flags & CNTR_VL) {
			for (j = 0; j < C_VL_COUNT; j++) {
				p = copy_indexed_name(p, table[i].name,
						      table[i].flags,
						      vl_from_idx(j));
			}
		} else if (table[i].flags & CNTR_PBC_TEST) {
			for (j = 0; j < HFI2_PBC_TEST_NCNTR; j++)
				p = copy_indexed_name(p, table[i].name,
						      table[i].flags, j);
		} else if (table[i].flags & CNTR_SDMA) {
			for (j = 0; j < sdma_engines; j++) {
				p = copy_indexed_name(p, table[i].name,
						      table[i].flags, j);
			}
		} else if (table[i].flags & CNTR_OVF) {
			for (j = 0; j < num_rcv; j++) {
				if (test_bit(j, dd->ovf_disabled))
					continue;
				p = copy_indexed_name(p, table[i].name,
						      table[i].flags, j);
			}
		} else {
			p = copy_single_name(p, table[i].name, table[i].flags);
		}
	}

	return p;
}

static int init_cntrs(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i, j;
	size_t sz;
	struct hfi2_pportdata *ppd;
	char *p;

	/* set up the stats timers; the add_timer calls are done at the end */
	timer_setup(&dd->synth_stats_timer, update_synth_timer, 0);
	timer_setup(&dd->rcverr_timer, update_rcverr_timer, 0);
	INIT_WORK(&dd->update_cntr_work, do_update_synth_timer);
	INIT_WORK(&dd->rcverr_work, do_rcverr_timer);
	/* Assume the hardware counter has been reset */
	for (i = 0; i < dd->num_pports; i++)
		dd->pport[i].rcv_ovfl_cnt = 0;

	/***********************/
	/* per device counters */
	/***********************/

	/* size names and determine how many we have */
	dd->ndevcntrs = 0;
	sz = 0;
	size_cntr_names(dd, hfi2_shared_dev_cntrs, SHARED_DEV_CNTR_LAST,
			&dd->ndevcntrs, &sz);
	size_cntr_names(dd, dd->params->chip_dev_cntrs,
			dd->params->chip_num_dev_cntrs, &dd->ndevcntrs, &sz);

	/* allocate space for the counter values */
	dd->cntrs = kcalloc(dd->ndevcntrs + hfi2_num_driver_cntrs, sizeof(u64),
			    GFP_KERNEL);
	if (!dd->cntrs)
		goto bail;

	dd->scntrs = kcalloc(dd->ndevcntrs, sizeof(u64), GFP_KERNEL);
	if (!dd->scntrs)
		goto bail;

	/* allocate space for the counter names */
	dd->cntrnameslen = sz;
	dd->cntrnames = kmalloc(sz, GFP_KERNEL);
	if (!dd->cntrnames)
		goto bail;

	/* fill in the names */
	p = fill_cntr_names(dd, hfi2_shared_dev_cntrs, SHARED_DEV_CNTR_LAST,
			    dd->cntrnames);
	fill_cntr_names(dd, dd->params->chip_dev_cntrs,
			dd->params->chip_num_dev_cntrs, p);

	/*********************/
	/* per port counters */
	/*********************/

	/*
	 * Go through the counters for the overflows and disable the ones we
	 * don't need. This varies based on platform so we need to do it
	 * dynamically here.
	 */
	bitmap_fill(dd->ovf_disabled, MAX_RCV_CTXTS);
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->num_rcv_contexts; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			clear_bit(ctxt, dd->ovf_disabled);
		}
	}

	/* size port counter names and determine how many we have */
	dd->nportcntrs = 0;
	sz = 0;
	size_cntr_names(dd, hfi2_shared_port_cntrs, SHARED_PORT_CNTR_LAST,
			&dd->nportcntrs, &sz);
	size_cntr_names(dd, dd->params->chip_port_cntrs,
			dd->params->chip_num_port_cntrs, &dd->nportcntrs, &sz);

	/* allocate space for the counter names */
	dd->portcntrnameslen = sz;
	dd->portcntrnames = kmalloc(sz, GFP_KERNEL);
	if (!dd->portcntrnames)
		goto bail;

	/* fill in port cntr names */
	p = fill_cntr_names(dd, hfi2_shared_port_cntrs, SHARED_PORT_CNTR_LAST,
			    dd->portcntrnames);
	fill_cntr_names(dd, dd->params->chip_port_cntrs,
			dd->params->chip_num_port_cntrs, p);

	/* allocate per port storage for counter values */
	ppd = (struct hfi2_pportdata *)(dd + 1);
	for (i = 0; i < dd->num_pports; i++, ppd++) {
		ppd->cntrs = kcalloc(dd->nportcntrs, sizeof(u64), GFP_KERNEL);
		if (!ppd->cntrs)
			goto bail;

		ppd->scntrs = kcalloc(dd->nportcntrs, sizeof(u64), GFP_KERNEL);
		if (!ppd->scntrs)
			goto bail;
	}

	/* CPU counters need to be allocated and zeroed */
	if (hfi2_init_cpu_counters(dd))
		goto bail;

	dd->update_cntr_wq = alloc_ordered_workqueue("hfi2_update_cntr_%d",
						     WQ_MEM_RECLAIM, dd->unit);
	if (!dd->update_cntr_wq)
		goto bail;

	mod_timer(&dd->synth_stats_timer, jiffies + HZ * SYNTH_CNT_TIME);
	mod_timer(&dd->rcverr_timer, jiffies + HZ * RCVERR_CHECK_TIME);
	return 0;
bail:
	hfi2_free_cntrs(dd);
	return -ENOMEM;
}

static u32 chip_to_opa_lstate(struct hfi2_devdata *dd, u32 chip_lstate)
{
	switch (chip_lstate) {
	case LSTATE_DOWN:
		return IB_PORT_DOWN;
	case LSTATE_INIT:
		return IB_PORT_INIT;
	case LSTATE_ARMED:
		return IB_PORT_ARMED;
	case LSTATE_ACTIVE:
		return IB_PORT_ACTIVE;
	default:
		dd_dev_err(
			dd,
			"Unknown logical state 0x%x, reporting IB_PORT_DOWN\n",
			chip_lstate);
		return IB_PORT_DOWN;
	}
}

u32 hfi2_chip_to_opa_pstate(struct hfi2_devdata *dd, u32 chip_pstate)
{
	/* look at the HFI meta-states only */
	switch (chip_pstate & 0xf0) {
	case PLS_DISABLED:
		return IB_PORTPHYSSTATE_DISABLED;
	case PLS_OFFLINE:
		return OPA_PORTPHYSSTATE_OFFLINE;
	case PLS_POLLING:
		return IB_PORTPHYSSTATE_POLLING;
	case PLS_CONFIGPHY:
		return IB_PORTPHYSSTATE_TRAINING;
	case PLS_LINKUP:
		return IB_PORTPHYSSTATE_LINKUP;
	case PLS_PHYTEST:
		return IB_PORTPHYSSTATE_PHY_TEST;
	default:
		dd_dev_err(dd, "Unexpected chip physical state of 0x%x\n",
			   chip_pstate);
		return IB_PORTPHYSSTATE_DISABLED;
	}
}

const char *hfi2_opa_pstate_name(u32 pstate)
{
	static const char *const port_physical_names[] = {
		"PHYS_NOP",
		"reserved1",
		"PHYS_POLL",
		"PHYS_DISABLED",
		"PHYS_TRAINING",
		"PHYS_LINKUP",
		"PHYS_LINK_ERR_RECOVER",
		"PHYS_PHY_TEST",
		"reserved8",
		"PHYS_OFFLINE",
		"PHYS_GANGED",
		"PHYS_TEST",
	};
	if (pstate < ARRAY_SIZE(port_physical_names))
		return port_physical_names[pstate];
	return "unknown";
}

/**
 * hfi2_update_statusp - Update userspace status flag
 * @ppd: Port data structure
 * @state: port state information
 *
 * Actual port status is determined by the host_link_state value
 * in the ppd.
 *
 * host_link_state MUST be updated before updating the user space
 * statusp.
 */
void hfi2_update_statusp(struct hfi2_pportdata *ppd, u32 state)
{
	/*
	 * Set port status flags in the page mapped into userspace
	 * memory. Do it here to ensure a reliable state - this is
	 * the only function called by all state handling code.
	 * Always set the flags due to the fact that the cache value
	 * might have been changed explicitly outside of this
	 * function.
	 */
	if (ppd->statusp) {
		switch (state) {
		case IB_PORT_DOWN:
		case IB_PORT_INIT:
			*ppd->statusp &=
				~(HFI2_STATUS_IB_CONF | HFI2_STATUS_IB_READY);
			break;
		case IB_PORT_ARMED:
			*ppd->statusp |= HFI2_STATUS_IB_CONF;
			break;
		case IB_PORT_ACTIVE:
			*ppd->statusp |= HFI2_STATUS_IB_READY;
			break;
		}
	}
	ppd_dev_info(ppd, "logical state changed to %s (0x%x)\n",
		     ib_port_state_to_str(state), state);
}

/**
 * wait_logical_linkstate - wait for an IB link state change to occur
 * @ppd: port device
 * @state: the state to wait for
 * @msecs: the number of milliseconds to wait
 *
 * Wait up to msecs milliseconds for IB link state change to occur.
 * For now, take the easy polling route.
 * Returns 0 if state reached, otherwise -ETIMEDOUT.
 */
int hfi2_wait_logical_linkstate(struct hfi2_pportdata *ppd, u32 state,
				  int msecs)
{
	unsigned long timeout;
	u32 new_state;

	timeout = jiffies + msecs_to_jiffies(msecs);
	while (1) {
		new_state = chip_to_opa_lstate(
			ppd->dd, hfi2_read_logical_state(ppd->dd));
		if (new_state == state)
			break;
		if (time_after(jiffies, timeout)) {
			ppd_dev_err(ppd,
				    "timeout waiting for link state 0x%x\n",
				    state);
			return -ETIMEDOUT;
		}
		msleep(20);
	}

	return 0;
}

void hfi2_log_state_transition(struct hfi2_pportdata *ppd, u32 state)
{
	u32 ib_pstate = hfi2_chip_to_opa_pstate(ppd->dd, state);

	ppd_dev_info(ppd, "physical state changed to %s (0x%x), phy 0x%x\n",
		     hfi2_opa_pstate_name(ib_pstate), ib_pstate, state);
}

/*
 * Read the physical hardware link state and check if it matches host
 * drivers anticipated state.
 */
void hfi2_log_physical_state(struct hfi2_pportdata *ppd, u32 state)
{
	u32 read_state = hfi2_read_physical_state(ppd->dd);

	if (read_state == state) {
		hfi2_log_state_transition(ppd, state);
	} else {
		ppd_dev_err(ppd, "anticipated phy link state 0x%x, read 0x%x\n",
			    state, read_state);
	}
}

/*
 * wait_physical_linkstate - wait for an physical link state change to occur
 * @ppd: port device
 * @state: the state to wait for
 * @msecs: the number of milliseconds to wait
 *
 * Wait up to msecs milliseconds for physical link state change to occur.
 * Returns 0 if state reached, otherwise -ETIMEDOUT.
 */
int hfi2_wait_physical_linkstate(struct hfi2_pportdata *ppd, u32 state,
				   int msecs)
{
	u32 read_state;
	unsigned long timeout;

	timeout = jiffies + msecs_to_jiffies(msecs);
	while (1) {
		read_state = hfi2_read_physical_state(ppd->dd);
		if (read_state == state)
			break;
		if (time_after(jiffies, timeout)) {
			ppd_dev_err(ppd,
				    "timeout waiting for phy link state 0x%x\n",
				    state);
			return -ETIMEDOUT;
		}
		usleep_range(1950, 2050); /* sleep 2ms-ish */
	}

	hfi2_log_state_transition(ppd, state);
	return 0;
}

/*
 * wait_phys_link_offline_quiet_substates - wait for any offline substate
 * @ppd: port device
 * @msecs: the number of milliseconds to wait
 *
 * Wait up to msecs milliseconds for any offline physical link
 * state change to occur.
 * Returns 0 if at least one state is reached, otherwise -ETIMEDOUT.
 */
int hfi2_wait_phys_link_offline_substates(struct hfi2_pportdata *ppd,
					    int msecs)
{
	u32 read_state;
	unsigned long timeout;

	timeout = jiffies + msecs_to_jiffies(msecs);
	while (1) {
		read_state = hfi2_read_physical_state(ppd->dd);
		if ((read_state & 0xF0) == PLS_OFFLINE)
			break;
		if (time_after(jiffies, timeout)) {
			ppd_dev_err(
				ppd,
				"timeout waiting for phy link offline.quiet substates. Read state 0x%x, %dms\n",
				read_state, msecs);
			return -ETIMEDOUT;
		}
		usleep_range(1950, 2050); /* sleep 2ms-ish */
	}

	hfi2_log_state_transition(ppd, read_state);
	return read_state;
}

/*
 * wait_phys_link_out_of_offline - wait for any out of offline state
 * @ppd: port device
 * @msecs: the number of milliseconds to wait
 *
 * Wait up to msecs milliseconds for any out of offline physical link
 * state change to occur.
 * Returns 0 if at least one state is reached, otherwise -ETIMEDOUT.
 */
int hfi2_wait_phys_link_out_of_offline(struct hfi2_pportdata *ppd, int msecs)
{
	u32 read_state;
	unsigned long timeout;

	timeout = jiffies + msecs_to_jiffies(msecs);
	while (1) {
		read_state = hfi2_read_physical_state(ppd->dd);
		if ((read_state & 0xF0) != PLS_OFFLINE)
			break;
		if (time_after(jiffies, timeout)) {
			ppd_dev_err(
				ppd,
				"timeout waiting for phy link out of offline. Read state 0x%x, %dms\n",
				read_state, msecs);
			return -ETIMEDOUT;
		}
		usleep_range(1950, 2050); /* sleep 2ms-ish */
	}

	hfi2_log_state_transition(ppd, read_state);
	return read_state;
}

void hfi2_init_ctxt(struct send_context *sc)
{
	if (sc) {
		hfi2_priv_reg_op(sc->dd, sc->ppd->hw_pidx, sc->hw_context,
				 sc->type, SC_CHK_INIT_OP, 0);
	}
}

int hfi2_tempsense_rd(struct hfi2_devdata *dd, struct hfi2_temp *temp)
{
	int ret = 0;
	u64 reg;

	if (dd->icode != ICODE_RTL_SILICON) {
		if (HFI2_CAP_IS_KSET(PRINT_UNIMPL))
			dd_dev_info(dd, "%s: tempsense not supported by HW\n",
				    __func__);
		return -EINVAL;
	}

	if (dd->params->chip_type != CHIP_WFR)
		return -EINVAL;

	reg = hfi2_read_csr(dd, ASIC_STS_THERM);
	temp->curr = ((reg >> ASIC_STS_THERM_CURR_TEMP_SHIFT) &
		      ASIC_STS_THERM_CURR_TEMP_MASK);
	temp->lo_lim = ((reg >> ASIC_STS_THERM_LO_TEMP_SHIFT) &
			ASIC_STS_THERM_LO_TEMP_MASK);
	temp->hi_lim = ((reg >> ASIC_STS_THERM_HI_TEMP_SHIFT) &
			ASIC_STS_THERM_HI_TEMP_MASK);
	temp->crit_lim = ((reg >> ASIC_STS_THERM_CRIT_TEMP_SHIFT) &
			  ASIC_STS_THERM_CRIT_TEMP_MASK);
	/* triggers is a 3-bit value - 1 bit per trigger. */
	temp->triggers = (u8)((reg >> ASIC_STS_THERM_LOW_SHIFT) & 0x7);

	return ret;
}

/* ========================================================================= */

/**
 * read_mod_write() - Calculate the IRQ register index and set/clear the bits
 * @dd: valid devdata
 * @src: IRQ source to determine register index from
 * @bits: the bits to set or clear
 * @set: true == set the bits, false == clear the bits
 *
 */
static void read_mod_write(struct hfi2_devdata *dd, u16 src, u64 bits, bool set)
{
	unsigned long flags;
	u64 reg;
	u16 idx = src / BITS_PER_REGISTER;
	u32 cce_int_mask_reg = dd->params->cce_int_mask_reg + (8 * idx);

	spin_lock_irqsave(&dd->irq_src_lock, flags);
	reg = hfi2_read_csr(dd, cce_int_mask_reg);
	if (set) {
		reg |= bits;
		dd->gi_mask[idx].cce_int_mask |= bits;
	} else {
		reg &= ~bits;
		dd->gi_mask[idx].cce_int_mask &= ~bits;
	}
	hfi2_write_csr(dd, cce_int_mask_reg, reg);
	spin_unlock_irqrestore(&dd->irq_src_lock, flags);
}

/**
 * hfi2_set_intr_bits() - Enable/disable a range (one or more) IRQ sources
 * @dd: valid devdata
 * @first: first IRQ source to set/clear
 * @last: last IRQ source (inclusive) to set/clear
 * @set: true == set the bits, false == clear the bits
 *
 * If first == last, set the exact source.
 */
int hfi2_set_intr_bits(struct hfi2_devdata *dd, u16 first, u16 last, bool set)
{
	u64 bits = 0;
	u64 bit;
	u16 src;

	if (last > dd->params->is_last_source)
		return -EINVAL;
	if (last < first)
		return -ERANGE;

	for (src = first; src <= last; src++) {
		bit = src % BITS_PER_REGISTER;
		/* wrapped to next register? */
		if (!bit && bits) {
			read_mod_write(dd, src - 1, bits, set);
			bits = 0;
		}
		bits |= BIT_ULL(bit);
	}
	read_mod_write(dd, last, bits, set);

	return 0;
}

/*
 * Clear all interrupt sources on the chip.
 */
void hfi2_clear_all_interrupts(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i;
	u32 cce_int_clear_reg = dd->params->cce_int_clear_reg;

	for (i = 0; i < dd->params->num_int_csrs; i++)
		hfi2_write_csr(dd, cce_int_clear_reg + (8 * i), ~(u64)0);

	hfi2_write_csr(dd, dd->params->csr_err_clear_reg, ~(u64)0);
	hfi2_write_csr(dd, dd->params->send_pio_err_clear_reg, ~(u64)0);
	hfi2_write_csr(dd, dd->params->send_dma_err_clear_reg, ~(u64)0);
	for (i = dr->c.first_send_context; i < dr->c.last_send_context; i++)
		write_sctxt_csr(dd, i, dd->params->send_ctxt_err_clear_reg,
				~(u64)0);
	for (i = dr->first_sdma_engine; i < dr->last_sdma_engine; i++)
		write_sdma_csr(dd, i, dd->params->send_dma_eng_err_clear_reg,
			       ~(u64)0);

	if (dd->params->chip_type == CHIP_WFR) {
		/* CPORT is initializing these */
		hfi2_write_csr(dd, CCE_ERR_CLEAR, ~(u64)0);
		for (i = 0; i < dd->num_pports; i++) {
			write_iport_csr(dd, i, dd->params->rcv_err_clear_reg,
					~(u64)0);
			write_eport_csr(dd, i,
					dd->params->send_egress_err_clear_reg,
					~(u64)0);
		}

		/* only WFR has these blocks */
		hfi2_write_csr(dd, MISC_ERR_CLEAR, ~(u64)0);
		hfi2_write_csr(dd, DCC_ERR_FLG_CLR, ~(u64)0);
		hfi2_write_csr(dd, DC_LCB_ERR_CLR, ~(u64)0);
		hfi2_write_csr(dd, DC_DC8051_ERR_CLR, ~(u64)0);
	}
}

/*
 * Remap the interrupt source from the general handler to the given MSI-X
 * interrupt.
 */
void hfi2_remap_intr(struct hfi2_devdata *dd, unsigned int isrc, int msix_intr)
{
	u64 reg;
	unsigned int m, n;

	/* clear from the handled mask of the general interrupt */
	m = isrc / 64;
	n = isrc % 64;
	if (likely(m < dd->params->num_int_csrs)) {
		dd->gi_mask[m].remap &= ~((u64)1 << n);
	} else {
		dd_dev_err(dd, "remap interrupt err\n");
		return;
	}

	/* direct the chip source to the given MSI-X interrupt */
	m = isrc / 8;
	n = isrc % 8;
	reg = hfi2_read_csr(dd, dd->params->cce_msix_int_map_vec_reg + (8 * m));
	reg &= ~((u64)0xff << (8 * n));
	reg |= ((u64)msix_intr & 0xff) << (8 * n);
	hfi2_write_csr(dd, dd->params->cce_msix_int_map_vec_reg + (8 * m), reg);
}

void hfi2_remap_sdma_interrupts(struct hfi2_devdata *dd, int engine, int *msix_intr)
{
	/*
	 * SDMA engine interrupt sources grouped by type, rather than
	 * engine.  Per-engine interrupts are as follows:
	 *	SDMA
	 *	SDMAProgress
	 *	SDMAIdle
	 */
	hfi2_remap_intr(dd, dd->params->is_sdma_start + engine, msix_intr[0]);
	hfi2_remap_intr(dd, dd->params->is_sdma_progress_start + engine,
			msix_intr[1]);
	hfi2_remap_intr(dd, dd->params->is_sdma_idle_start + engine,
			msix_intr[2]);
}

/*
 * Set the general handler to accept all interrupts, remap all
 * chip interrupts back to MSI-X 0.
 */
void hfi2_reset_interrupts(struct hfi2_devdata *dd)
{
	int i;
	u32 cce_int_mask_reg = dd->params->cce_int_mask_reg;

	/* all interrupts handled by the general handler */
	for (i = 0; i < dd->params->num_int_csrs; i++) {
		dd->gi_mask[i].remap = ~(u64)0;
		dd->gi_mask[i].cce_int_mask =
			hfi2_read_csr(dd, cce_int_mask_reg + (8 * i));
	}

	/* all chip interrupts map to MSI-X 0 */
	for (i = 0; i < dd->params->num_int_map_csrs; i++)
		hfi2_write_csr(
			dd, dd->params->cce_msix_int_map_vec_reg + (8 * i), 0);
}

/**
 * set_up_interrupts() - Initialize the IRQ resources and state
 * @dd: valid devdata
 *
 */
static int set_up_interrupts(struct hfi2_devdata *dd)
{
	int ret;

	/* mask all interrupts */
	hfi2_set_intr_bits(dd, 0, dd->params->is_last_source, false);

	/* clear all pending interrupts */
	hfi2_clear_all_interrupts(dd);

	/* reset general handler mask, chip MSI-X mappings */
	hfi2_reset_interrupts(dd);

	/* ask for MSI-X interrupts */
	ret = hfi2_msix_initialize(dd);
	if (ret)
		return ret;

	ret = hfi2_msix_early_request_irqs(dd);
	if (ret)
		hfi2_msix_clean_up_interrupts(dd);

	return ret;
}

static int late_set_up_interrupts(struct hfi2_devdata *dd)
{
	int ret;

	ret = hfi2_msix_request_irqs(dd);
	if (ret)
		hfi2_msix_clean_up_interrupts(dd);

	return ret;
}

/*
 * Reduce the total per-port user receive context counts by the given amount.
 *
 * Return 0 if success, -EINVAL if there is not enough extra.
 */
static int reduce_ctxts(struct hfi2_devdata *dd, u32 *counts, int amount)
{
	const u32 count_min = 0; /* do not allow count to go below this value */
	int pidx;

	/* remove one at a time, round robin */
	while (amount > 0) {
		bool adjusted = false;

		for (pidx = 0; pidx < dd->num_pports && amount > 0; pidx++) {
			if (counts[pidx] > count_min) {
				counts[pidx]--;
				amount--;
				adjusted = true;
			}
		}

		if (!adjusted)
			return -EINVAL;
	}

	return 0;
}

static int reduce_rcv_ctxts(struct hfi2_devdata *dd, u32 *counts, int amount,
			    const char *why)
{
	int ret = reduce_ctxts(dd, counts, amount);

	if (ret) {
		dd_dev_err(
			dd,
			"Cannot reduce user receive contexts requested by %d [%s]\n",
			amount, why);
	}
	return ret;
}

/* return true if the fabric is reachable on the card */
/* this function does not range validate pidx */
static bool hardware_pidx_available(struct hfi2_devdata *dd, int pidx)
{
	/* only need to check JKR */
	if (dd->params->chip_type != CHIP_JKR)
		return true;

	/* dual port JKR has all ports available */
	if (dd->pcidev->subsystem_device == PCI_SUBDEVICE_CN5000_DUAL_PORT ||
	    dd->pcidev->subsystem_device == PCI_SUBDEVICE_CN5000_DUAL_PORT_PS)
		return true;

	/* port swapped single port JKR only uses the first port */
	if (dd->pcidev->subsystem_device ==
		    PCI_SUBDEVICE_CN5000_SINGLE_PORT_PS &&
	    pidx == 0)
		return true;

	/* single port JKR only uses the second port */
	if (dd->pcidev->subsystem_device == PCI_DEVICE_ID_CORNELIS_CN5000 &&
	    pidx == 1)
		return true;

	return false;
}

/*
 * Decide how to divide resources between ports.  Resources include
 * receive contexts, RSM table, RcvArray, and send contexts.
 *
 * User context resources may be asymmetric across ports.
 *
 * Receive contexts allocated in order at each port base:
 *	Control context
 *	Kernel contexts
 *	Dynamic context pool (user and netdev)
 *
 * These fields are set:
 *
 * dd->rsrcs.ppr[*]:
 *   num_rcv_contexts	  - number of contexts being used for this port
 *   n_krcv_queues	  - number of kernel contexts for each port
 *			      (includes control context)
 *   num_netdev_contexts  - number of reserved netdev contexts for each port
 *   num_user_conexts	  - number of user contexts for this port
 *   rcv_context_base	  - first context for this port
 *   first_dyn_alloc_ctxt - first dynamically allocated (user) context for
 *			    this port
 * dd:
 *   rcv_entries	  - details on RcvArray entries for each port
 *   num_send_contexts	  - number of PIO send contexts being used
 * ppd:
 *   freectxts		  - number of free user contexts for this port
 *   rcv_array_base	  - first RcvArray entry for this port
 */
static int set_up_context_variables(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_bulksvc *svc = dd->bulksvc;
	u32 num_bulksvc_contexts[LARGEST_NUM_PORTS];
	u32 def_bulksvc_contexts = svc ? svc->prereqs.num_rcv_ctxs : 0;
	u32 num_bulksvc = 0;
	u32 num_kernel_contexts[LARGEST_NUM_PORTS];
	u32 num_netdev_contexts[LARGEST_NUM_PORTS];
	u32 def_kernel_contexts;
	u32 def_netdev_contexts;
	u32 num_usr_ctxts;
	u32 num_netdev;
	u32 num_kctxts;
	int ret;
	int pidx;
	int base;
	int rmt_count;
	int rcv_pool_count;
	int total_netdev;
	int rcvarray_avail;
	int max_eager_allowed;
	int total_groups;
	int over;
	char *limited;
	u32 total_rcv;
	u32 n_usr_ctxts[LARGEST_NUM_PORTS];
	u32 send_contexts = dr->c.last_send_context - dr->c.first_send_context;
	u32 rcv_contexts = dr->c.last_rcv_context - dr->c.first_rcv_context;
	bool recalculated = false;

	/*
	 * Calculate the default number of per-port kernel receive contexts.
	 *
	 * hfi2_n_krcvqs is the sum of module parameter kernel receive contexts,
	 * hfi2_krcvqs[].  It does not include the control context, so add that.
	 */
	if (hfi2_n_krcvqs)
		def_kernel_contexts = hfi2_n_krcvqs + 1;
	else
		def_kernel_contexts = DEFAULT_KRCVQS + 1;

	def_netdev_contexts = hfi2_num_netdev_contexts(
		dd, HFI2_MAX_NETDEV_CTXTS, cpu_online_mask);

	/* obtain requested user context numbers from module parameters */
	num_usr_ctxts = 0;
	num_netdev = 0;
	num_kctxts = 0;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		int count = hfi2_get_num_user_contexts(dd, pidx);
		/*
		 * Per-port user contexts defaults to negative if unset in
		 * the module parameter.
		 * - unavailable ports always have zero user contexts no
		 *   matter what the parameter says
		 * - default to 1 user context per real (non-HT) CPU core
		 */
		if (!hardware_pidx_available(dd, pidx))
			count = 0;
		if (count < 0)
			count = num_online_cpus();
		n_usr_ctxts[pidx] = hfi2_is_eth_mode(dd) ? min(8, count) : count;

		/* no user contexts implies no port */
		if (count == 0) {
			num_kernel_contexts[pidx] = 0;
			num_netdev_contexts[pidx] = 0;
			num_bulksvc_contexts[pidx] = 0;
		} else {
			num_kernel_contexts[pidx] = def_kernel_contexts;
			num_netdev_contexts[pidx] = hfi2_is_eth_mode(dd) && num_rxqs ?
				num_rxqs : def_netdev_contexts;
			num_bulksvc_contexts[pidx] = def_bulksvc_contexts;
			num_netdev += num_netdev_contexts[pidx];
			num_bulksvc += def_bulksvc_contexts;
			num_kctxts += def_kernel_contexts;
		}
		num_usr_ctxts += n_usr_ctxts[pidx];
	}
	if (num_bulksvc && (rcv_contexts < num_kctxts + num_usr_ctxts + num_bulksvc)) {
		dd_dev_warn(dd, "DISABLING BULKSVC: not enough(%d) rcv_ctxts, need %d kctxts"
				" + %d usr_ctxts + %d bulksvc ctxts."
				" Reduce num_user_contexts to enable bulksvc\n",
				rcv_contexts, num_kctxts, num_usr_ctxts, num_bulksvc);
		for (pidx = 0; pidx < dd->num_pports; pidx++)
			num_bulksvc_contexts[pidx] = 0;
		num_bulksvc = 0;
		hfi2_bulksvc_teardown(dd);
	}
	if (rcv_contexts <
	    num_kctxts + num_usr_ctxts + num_bulksvc + num_netdev) {
		if (hfi2_is_eth_mode(dd)) {
			u32 need = (num_kctxts + num_usr_ctxts + num_bulksvc + num_netdev) -
				rcv_contexts;

			for (pidx = 0; need && num_usr_ctxts && pidx < dd->num_pports; pidx++) {
				u32 reclaim = min_t(u32, need, n_usr_ctxts[pidx]);

				dd_dev_warn(dd, "Disabling %u user contexts\n", reclaim);
				num_usr_ctxts -= reclaim;
				need -= reclaim;
				n_usr_ctxts[pidx] -= reclaim;
			}
			for (pidx = 0; need && num_netdev && pidx < dd->num_pports; pidx++) {
				u32 reclaim = min_t(u32, need, num_netdev_contexts[pidx]);

				dd_dev_warn(dd, "Disabling %u netdev contexts\n", reclaim);
				need -= reclaim;
				num_netdev -= reclaim;
				num_netdev_contexts[pidx] -= reclaim;
			}
			if (need) {
				dd_dev_warn(dd, "Not enough RX contexts.  Need %u more\n", need);
				return -ENOSPC;
			}
		} else {
			u32 need = (num_kctxts + num_usr_ctxts + num_bulksvc + num_netdev) -
				rcv_contexts;

			for (pidx = 0; pidx < dd->num_pports; pidx++) {
				u32 trim = min_t(u32, need, num_netdev_contexts[pidx]);

				need -= trim;
				num_netdev -= trim;
				num_netdev_contexts[pidx] -= trim;
			}
			dd_dev_warn(dd, "Reduced netdev contexts to %u on small configuration\n",
				    num_netdev);
		}
	}

do_recalc:
	/*
	 * Adjust the counts given a global max.
	 */
	total_rcv = 0;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		total_rcv += num_kernel_contexts[pidx] +
			     num_netdev_contexts[pidx] + n_usr_ctxts[pidx] +
			     num_bulksvc_contexts[pidx];
	}

	if (rcv_contexts < total_rcv) {
		over = total_rcv - rcv_contexts;
		ret = reduce_rcv_ctxts(dd, n_usr_ctxts, over,
				       "available receive contexts");
		if (ret)
			return -EINVAL;
		/* total_rcv is no longer valid */
		total_rcv = rcv_contexts;
	}

	/*
	 * RMT entries are allocated as follows:
	 * 1. QOS (0 to 128 entries)
	 * 2. FECN (num_kernel_context - 1 [a] + num_user_contexts +
	 *          num_netdev_contexts [b])
	 * 3. netdev (NUM_NETDEV_MAP_ENTRIES)
	 *
	 * Notes:
	 * [a] Kernel contexts (except control) are included in FECN if kernel
	 *     TID_RDMA is active.
	 * [b] Netdev and user contexts are randomly allocated from the same
	 *     context pool, so FECN must cover all contexts in the pool.
	 */
	rmt_count = 0;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		/* no RMT used if port is not available */
		if (num_kernel_contexts[pidx] == 0)
			continue;
		rmt_count += (hfi2_dev_tid_rdma(dd) ?
				      (num_kernel_contexts[pidx] - 1) :
				      0) +
			     n_usr_ctxts[pidx] + num_netdev_contexts[pidx] +
			     hfi2_map_entries(dd) + num_bulksvc_contexts[pidx] +
			     qos_rmt_entries(num_kernel_contexts[pidx] - 1,
					     NULL, NULL);
	}

	if (rmt_count > dd->params->rsm_map_table_entries) {
		over = rmt_count - dd->params->rsm_map_table_entries;
		ret = reduce_rcv_ctxts(dd, n_usr_ctxts, over,
				       "available RMT entries");
		if (ret)
			return -EINVAL;
	}

	/*
	 * For each port, the first N are kernel contexts, the rest are
	 * user/netdev contexts
	 */

	dd_dev_info(dd, "rcv contexts: avail %d\n", rcv_contexts);
	base = dr->c.first_rcv_context;
	total_rcv = 0; /* recalculate */
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_pportdata *ppd = &dd->pport[pidx];
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];
		int extra_sctxts = hfi2_get_num_extra_send_contexts(dd, pidx);

		pr->num_extra_send_contexts = extra_sctxts < 0 ? 0 : extra_sctxts;
		pr->n_krcv_queues = num_kernel_contexts[pidx];
		pr->num_netdev_contexts = num_netdev_contexts[pidx];
		pr->num_rcv_contexts = num_kernel_contexts[pidx] +
				       num_netdev_contexts[pidx] +
				       n_usr_ctxts[pidx] + num_bulksvc_contexts[pidx];
		pr->num_bulksvc_contexts = num_bulksvc_contexts[pidx];
		pr->num_user_contexts = n_usr_ctxts[pidx];
		pr->rcv_context_base = base;
		ppd->freectxts = pr->num_user_contexts;
		pr->first_bulksvc_alloc_ctxt = pr->rcv_context_base + num_kernel_contexts[pidx];
		pr->first_dyn_alloc_ctxt = pr->first_bulksvc_alloc_ctxt +
					   num_bulksvc_contexts[pidx];
		ppd_dev_info(
			ppd,
			"  rcv ctxts: base %d, used %d (kernel %d, netdev %u, user %u)\n",
			pr->rcv_context_base, pr->num_rcv_contexts,
			pr->n_krcv_queues, pr->num_netdev_contexts,
			pr->num_user_contexts);

		base += pr->num_rcv_contexts;
		total_rcv += pr->num_rcv_contexts;
	}

	/*
	 * Receive array allocation:
	 *   Avoid first N RcvArray entries.
	 *
	 *   All RcvArray entries are divided into groups of 8. This
	 *   is required by the hardware and will speed up writes to
	 *   consecutive entries by using write-combining of the entire
	 *   cacheline.
	 *
	 *   The number of groups are evenly divided among all contexts.
	 */
	dd->rcv_entries.group_size = RCV_INCREMENT;
	rcvarray_avail = dr->c.last_rcvarray_entry - dr->c.first_rcvarray_entry;
	total_groups = rcvarray_avail / dd->rcv_entries.group_size;
	if (total_rcv)
		dd->rcv_entries.ngroups = total_groups / total_rcv;
	else
		dd->rcv_entries.ngroups = 0; /* alternate: total_groups */
	max_eager_allowed = dd->params->max_eager_entries * 2;
	if (dd->rcv_entries.ngroups * dd->rcv_entries.group_size >
	    max_eager_allowed) {
		dd->rcv_entries.ngroups =
			max_eager_allowed / dd->rcv_entries.group_size;
		limited = " (limited by max eager entries)";
	} else {
		limited = "";
	}
	dd_dev_info(dd, "RcvArray per-context groups %u%s, unused groups %u\n",
		    dd->rcv_entries.ngroups, limited,
		    total_groups - (dd->rcv_entries.ngroups * total_rcv));

	base = dr->c.first_rcvarray_entry;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];

		pr->rcv_array_base = base;
		base += pr->num_rcv_contexts *
			(dd->rcv_entries.ngroups * dd->rcv_entries.group_size);
	}

	/*
	 * PIO send contexts
	 */
	ret = hfi2_init_sc_pools_and_sizes(dd);
	if (ret < 0)
		return ret;
	dd->num_send_contexts = ret;

	dd_dev_info(
		dd,
		"send contexts: avail %d, used %d (kernel %d, ack %d, user %d, vl15 %d)\n",
		send_contexts, dd->num_send_contexts,
		dd->sc_sizes[SC_KERNEL].count, dd->sc_sizes[SC_ACK].count,
		dd->sc_sizes[SC_USER].count, dd->sc_sizes[SC_VL15].count);

	/*
	 * There may be less PIO user send contexts available than user
	 * receive contexts.  If so, reduce the requested user receive
	 * context count and go back to re-calculate the resources.
	 */
	rcv_pool_count = 0;
	total_netdev = 0;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];

		rcv_pool_count +=
			pr->num_netdev_contexts + pr->num_user_contexts;
		total_netdev += pr->num_netdev_contexts;
	}

	if (rcv_pool_count > dd->sc_sizes[SC_USER].count) {
		const char *action = recalculated ? "fail" : "recalculating";

		dd_dev_info(dd, "too many user rc %d vs sc %d - %s",
			    rcv_pool_count, dd->sc_sizes[SC_USER].count,
			    action);
		if (recalculated)
			return -EINVAL;

		/* netdev is required, enforce that many in the pool */
		if (dd->sc_sizes[SC_USER].count < total_netdev) {
			dd_dev_err(
				dd,
				"more pool rcv contexts required than available\n");
			return -EINVAL;
		}

		over = rcv_pool_count - dd->sc_sizes[SC_USER].count;
		ret = reduce_rcv_ctxts(dd, n_usr_ctxts, over,
				       "available send contexts");
		if (ret)
			return -EINVAL;
		dd_dev_info(dd, "reducing requested receive contexts by %d",
			    over);
		recalculated = true;
		goto do_recalc;
	}

	return 0;
}

/*
 * Set the device/port partition key table. The MAD code
 * will ensure that, at least, the partial management
 * partition key is present in the table.
 */
void hfi2_set_partition_keys(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = 0;
	unsigned int i;

	/* cport controls setting the hardware pkey table on later hardware */
	if (dd->params->chip_type != CHIP_WFR)
		return;

	ppd_dev_info(ppd, "Setting partition keys\n");
	for (i = 0; i < hfi2_get_npkeys(dd); i++) {
		reg |= (ppd->pkeys[i] & RCV_PARTITION_KEY_PARTITION_KEY_A_MASK)
		       << ((i % 4) * RCV_PARTITION_KEY_PARTITION_KEY_B_SHIFT);
		/* Each register holds 4 PKey values. */
		if ((i % 4) == 3) {
			write_iport_csr(dd, ppd->hw_pidx,
					dd->params->rcv_partition_key_reg +
						((i - 3) * 2),
					reg);
			reg = 0;
		}
	}

	/* Always enable HW pkeys check when pkeys table is set */
	hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_PARTITION_KEY_ENABLE_SMASK);
}

/*
 * These CSRs and memories are uninitialized on reset and must be
 * written before reading to set the ECC/parity bits.
 *
 * NOTE: All user context CSRs that are not mmaped write-only
 * (e.g. the TID flows) must be initialized even if the driver never
 * reads them.
 */
static void write_uninitialized_csrs_and_memories(struct hfi2_devdata *dd)
{
	u32 num_qp_table_regs = dd->params->qp_map_table_entries /
				dd->params->qp_map_table_entries_per_csr;
	int i, j;

	/* CceIntMap */
	for (i = 0; i < dd->params->num_int_map_csrs; i++)
		hfi2_write_csr(
			dd, dd->params->cce_msix_int_map_vec_reg + (8 * i), 0);

	/* SendCtxtCreditReturnAddr */
	for (i = 0; i < chip_send_contexts(dd); i++)
		write_sctxt_csr(
			dd, i, dd->params->send_ctxt_credit_return_addr_reg, 0);

	/* PIO Send buffers */
	/* SDMA Send buffers */
	/*
	 * These are not normally read, and (presently) have no method
	 * to be read, so are not pre-initialized
	 */

	/* RcvHdrAddr */
	/* RcvHdrTailAddr */
	/* RcvTidFlowTable */
	for (i = 0; i < chip_rcv_contexts(dd); i++) {
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_addr_reg, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_tail_addr_reg, 0);
		for (j = 0; j < RXE_NUM_TID_FLOWS; j++)
			write_uctxt_csr(dd, i,
					dd->params->rcv_tid_flow_table_reg +
						(8 * j),
					0);
	}

	/* RcvArray */
	wfr_init_tids(dd);

	/* RcvQPMapTable */
	for (i = 0; i < dd->num_pports; i++) {
		for (j = 0; j < num_qp_table_regs; j++) {
			u32 off = dd->params->rcv_qp_map_table_reg + (8 * j);

			write_iport_csr(dd, i, off, 0);
		}
	}
}

/*
 * Use the ctrl_bits in CceCtrl to clear the status_bits in CceStatus.
 */
static void clear_cce_status(struct hfi2_devdata *dd, u64 status_bits,
			     u64 ctrl_bits)
{
	unsigned long timeout;
	u64 reg;

	/* is the condition present? */
	reg = hfi2_read_csr(dd, CCE_STATUS);
	if ((reg & status_bits) == 0)
		return;

	/* clear the condition */
	hfi2_write_csr(dd, CCE_CTRL, ctrl_bits);

	/* wait for the condition to clear */
	timeout = jiffies + msecs_to_jiffies(CCE_STATUS_TIMEOUT);
	while (1) {
		reg = hfi2_read_csr(dd, CCE_STATUS);
		if ((reg & status_bits) == 0)
			return;
		if (time_after(jiffies, timeout)) {
			dd_dev_err(
				dd,
				"Timeout waiting for CceStatus to clear bits 0x%llx, remaining 0x%llx\n",
				status_bits, reg & status_bits);
			return;
		}
		udelay(1);
	}
}

/* set CCE CSRs to chip reset defaults */
static void reset_cce_csrs(struct hfi2_devdata *dd)
{
	int i;
	u32 cce_int_clear_reg = dd->params->cce_int_clear_reg;
	u32 cce_int_mask_reg = dd->params->cce_int_mask_reg;

	/* CCE_REVISION read-only */
	/* CCE_REVISION2 read-only */
	/* CCE_CTRL - bits clear automatically */
	/* CCE_STATUS read-only, use CceCtrl to clear */
	clear_cce_status(dd, ALL_FROZE, CCE_CTRL_SPC_UNFREEZE_SMASK);
	clear_cce_status(dd, ALL_TXE_PAUSE, CCE_CTRL_TXE_RESUME_SMASK);
	clear_cce_status(dd, ALL_RXE_PAUSE, CCE_CTRL_RXE_RESUME_SMASK);
	for (i = 0; i < CCE_NUM_SCRATCH; i++)
		hfi2_write_csr(dd, CCE_SCRATCH + (8 * i), 0);
	/* CCE_ERR_STATUS read-only */
	hfi2_write_csr(dd, CCE_ERR_MASK, 0);
	hfi2_write_csr(dd, CCE_ERR_CLEAR, ~0ull);
	/* CCE_ERR_FORCE leave alone */
	for (i = 0; i < CCE_NUM_32_BIT_COUNTERS; i++)
		hfi2_write_csr(dd, CCE_COUNTER_ARRAY32 + (8 * i), 0);
	hfi2_write_csr(dd, CCE_DC_CTRL, CCE_DC_CTRL_RESETCSR);
	/* CCE_PCIE_CTRL leave alone */
	for (i = 0; i < CCE_NUM_MSIX_VECTORS; i++) {
		hfi2_write_csr(dd, CCE_MSIX_TABLE_LOWER + (0x10 * i), 0);
		hfi2_write_csr(dd, CCE_MSIX_TABLE_UPPER + (0x10 * i),
			       CCE_MSIX_TABLE_UPPER_RESETCSR);
	}
	for (i = 0; i < CCE_NUM_MSIX_PBAS; i++) {
		/* CCE_MSIX_PBA read-only */
		hfi2_write_csr(dd, dd->params->cce_msix_int_granted_reg, ~0ull);
		hfi2_write_csr(dd, CCE_MSIX_VEC_CLR_WITHOUT_INT, ~0ull);
	}
	for (i = 0; i < dd->params->num_int_map_csrs; i++)
		hfi2_write_csr(
			dd, dd->params->cce_msix_int_map_vec_reg + (8 * i), 0);
	for (i = 0; i < dd->params->num_int_csrs; i++) {
		/* CCE_INT_STATUS read-only */
		hfi2_write_csr(dd, cce_int_mask_reg + (8 * i), 0);
		hfi2_write_csr(dd, cce_int_clear_reg + (8 * i), ~0ull);
		/* CCE_INT_FORCE leave alone */
		/* CCE_INT_BLOCKED read-only */
	}
	for (i = 0; i < CCE_NUM_32_BIT_INT_COUNTERS; i++)
		hfi2_write_csr(dd, CCE_INT_COUNTER_ARRAY32 + (8 * i), 0);
}

/* set MISC CSRs to chip reset defaults */
static void reset_misc_csrs(struct hfi2_devdata *dd)
{
	int i;

	for (i = 0; i < 32; i++) {
		hfi2_write_csr(dd, MISC_CFG_RSA_R2 + (8 * i), 0);
		hfi2_write_csr(dd, MISC_CFG_RSA_SIGNATURE + (8 * i), 0);
		hfi2_write_csr(dd, MISC_CFG_RSA_MODULUS + (8 * i), 0);
	}
	/*
	 * MISC_CFG_SHA_PRELOAD leave alone - always reads 0 and can
	 * only be written 128-byte chunks
	 */
	/* init RSA engine to clear lingering errors */
	hfi2_write_csr(dd, MISC_CFG_RSA_CMD, 1);
	hfi2_write_csr(dd, MISC_CFG_RSA_MU, 0);
	hfi2_write_csr(dd, MISC_CFG_FW_CTRL, 0);
	/* MISC_STS_8051_DIGEST read-only */
	/* MISC_STS_SBM_DIGEST read-only */
	/* MISC_STS_PCIE_DIGEST read-only */
	/* MISC_STS_FAB_DIGEST read-only */
	/* MISC_ERR_STATUS read-only */
	hfi2_write_csr(dd, MISC_ERR_MASK, 0);
	hfi2_write_csr(dd, MISC_ERR_CLEAR, ~0ull);
	/* MISC_ERR_FORCE leave alone */
}

/* set TXE CSRs to chip reset defaults - only called on WFR */
static void reset_txe_csrs(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i, j;

	/*
	 * TXE Kernel CSRs
	 */
	for (i = 0; i < dd->num_pports; i++) {
		write_eport_csr(dd, i, dd->params->send_ctrl_reg, 0);
		__hfi2_cm_reset(&dd->pport[i], 0); /* reset CM internal state */
		/* SEND_CONTEXTS read-only */
		/* SEND_DMA_ENGINES read-only */
		/* SEND_PIO_MEM_SIZE read-only */
		/* SEND_DMA_MEM_SIZE read-only */
		write_eport_csr(dd, i, dd->params->send_high_priority_limit_reg,
				0);
		/* SEND_DMA_ERR_FORCE leave alone */
		/* SEND_EGRESS_ERR_STATUS read-only */
		write_eport_csr(dd, i, dd->params->send_egress_err_mask_reg, 0);
		write_eport_csr(dd, i, dd->params->send_egress_err_clear_reg,
				~0ull);
		/* SEND_EGRESS_ERR_FORCE leave alone */
		write_eport_csr(dd, i, dd->params->send_bth_qp_reg, 0);
		write_eport_csr(dd, i, dd->params->send_static_rate_control_reg,
				0);
		write_eport_csr(dd, i, dd->params->send_sc2vlt0_reg, 0);
		write_eport_csr(dd, i, dd->params->send_sc2vlt1_reg, 0);
		write_eport_csr(dd, i, dd->params->send_sc2vlt2_reg, 0);
		write_eport_csr(dd, i, dd->params->send_sc2vlt3_reg, 0);
		write_eport_csr(dd, i, dd->params->send_len_check0_reg, 0);
		write_eport_csr(dd, i, dd->params->send_len_check1_reg, 0);
		for (j = 0; j < VL_ARB_LOW_PRIO_TABLE_SIZE; j++) {
			write_eport_csr(dd, i,
					dd->params->send_low_priority_list_reg +
						(8 * j),
					0);
		}
		for (j = 0; j < VL_ARB_HIGH_PRIO_TABLE_SIZE; j++) {
			write_eport_csr(
				dd, i,
				dd->params->send_high_priority_list_reg +
					(8 * j),
				0);
		}
		for (j = 0; j < TXE_NUM_32_BIT_COUNTER; j++) {
			write_eport_csr(dd, i,
					dd->params->send_counter_array32_reg +
						(8 * j),
					0);
		}
		for (j = 0; j < TXE_NUM_64_BIT_COUNTER; j++) {
			write_eport_csr(dd, i,
					dd->params->send_counter_array64_reg +
						(8 * j),
					0);
		}
		write_eport_csr(dd, i, dd->params->send_cm_ctrl_reg,
				SEND_CM_CTRL_RESETCSR);
		write_eport_csr(dd, i, dd->params->send_cm_global_credit_reg,
				SEND_CM_GLOBAL_CREDIT_RESETCSR);
		/* SEND_CM_CREDIT_USED_STATUS read-only */
		write_eport_csr(dd, i, dd->params->send_cm_timer_ctrl_reg, 0);
		if (dd->params->chip_type == CHIP_WFR) {
			write_eport_csr(
				dd, i,
				dd->params->send_cm_local_au_table0_to3_reg, 0);
			write_eport_csr(
				dd, i,
				dd->params->send_cm_local_au_table4_to7_reg, 0);
			write_eport_csr(
				dd, i,
				dd->params->send_cm_remote_au_table0_to3_reg,
				0);
			write_eport_csr(
				dd, i,
				dd->params->send_cm_remote_au_table4_to7_reg,
				0);
		}
		for (j = 0; j < TXE_NUM_DATA_VL; j++)
			write_eport_csr(
				dd, i,
				dd->params->send_cm_credit_vl_reg + (8 * j), 0);
		write_eport_csr(dd, i, dd->params->send_cm_credit_vl15_reg, 0);
		/* SEND_CM_CREDIT_USED_VL read-only */
		/* SEND_CM_CREDIT_USED_VL15 read-only */
		/* SEND_EGRESS_CTXT_STATUS read-only */
		/* SEND_EGRESS_SEND_DMA_STATUS read-only */
		write_eport_csr(dd, i, dd->params->send_egress_err_info_reg,
				~0ull);
		/* SEND_EGRESS_ERR_SOURCE read-only */
	}
	hfi2_pio_reset_all(dd); /* SEND_PIO_INIT_CTXT */
	/* SEND_PIO_ERR_STATUS read-only */
	hfi2_write_csr(dd, dd->params->send_pio_err_mask_reg, 0);
	hfi2_write_csr(dd, dd->params->send_pio_err_clear_reg, ~0ull);
	/* SEND_PIO_ERR_FORCE leave alone */
	/* SEND_DMA_ERR_STATUS read-only */
	hfi2_write_csr(dd, dd->params->send_dma_err_mask_reg, 0);
	hfi2_write_csr(dd, dd->params->send_dma_err_clear_reg, ~0ull);
	/* SEND_ERR_STATUS read-only */
	hfi2_write_csr(dd, dd->params->csr_err_mask_reg, 0);
	hfi2_write_csr(dd, dd->params->csr_err_clear_reg, ~0ull);
	/* SEND_ERR_FORCE read-only */
	for (i = 0; i < chip_send_contexts(dd) / NUM_CONTEXTS_PER_SET; i++)
		hfi2_write_csr(dd, SEND_CONTEXT_SET_CTRL + (8 * i), 0);

	/*
	 * TXE Per-Context CSRs
	 */
	for (i = dr->c.first_send_context; i < dr->c.last_send_context; i++) {
		write_tctxt_csr(dd, i, dd->params->send_ctxt_ctrl_reg, 0);
		write_sctxt_csr(dd, i, dd->params->send_ctxt_credit_ctrl_reg,
				0);
		write_sctxt_csr(
			dd, i, dd->params->send_ctxt_credit_return_addr_reg, 0);
		write_sctxt_csr(dd, i, dd->params->send_ctxt_credit_force_reg,
				0);
		write_sctxt_csr(dd, i, dd->params->send_ctxt_err_mask_reg, 0);
		write_sctxt_csr(dd, i, dd->params->send_ctxt_err_clear_reg,
				~0ull);
		for (j = 0; j < dd->num_pports; j++) {
			write_epsc_csr(dd, j, i,
				       dd->params->send_ctxt_check_enable_reg,
				       0);
			write_epsc_csr(dd, j, i,
				       dd->params->send_ctxt_check_vl_reg, 0);
			write_epsc_csr(dd, j, i,
				       dd->params->send_ctxt_check_job_key_reg,
				       0);
			write_epsc_csr(
				dd, j, i,
				dd->params->send_ctxt_check_partition_key_reg,
				0);
			write_epsc_csr(dd, j, i,
				       dd->params->send_ctxt_check_slid_reg, 0);
			write_epsc_csr(dd, j, i,
				       dd->params->send_ctxt_check_opcode_reg,
				       0);
		}
	}

	/*
	 * TXE Per-SDMA CSRs
	 */
	for (i = 0; i < chip_sdma_engines(dd); i++) {
		write_sdma_csr(dd, i, dd->params->send_dma_ctrl_reg, 0);
		/* SEND_DMA_STATUS read-only */
		write_sdma_csr(dd, i, dd->params->send_dma_base_addr_reg, 0);
		write_sdma_csr(dd, i, dd->params->send_dma_len_gen_reg, 0);
		write_sdma_csr(dd, i, dd->params->send_dma_tail_reg, 0);
		/* SEND_DMA_HEAD read-only */
		write_sdma_csr(dd, i, dd->params->send_dma_head_addr_reg, 0);
		write_sdma_csr(dd, i, dd->params->send_dma_priority_thld_reg,
			       0);
		/* SEND_DMA_IDLE_CNT read-only */
		write_sdma_csr(dd, i, dd->params->send_dma_reload_cnt_reg, 0);
		write_sdma_csr(dd, i, dd->params->send_dma_desc_cnt_reg, 0);
		/* SEND_DMA_DESC_FETCHED_CNT read-only */
		/* SEND_DMA_ENG_ERR_STATUS read-only */
		write_sdma_csr(dd, i, dd->params->send_dma_eng_err_mask_reg, 0);
		write_sdma_csr(dd, i, dd->params->send_dma_eng_err_clear_reg,
			       ~0ull);
		/* SEND_DMA_ENG_ERR_FORCE leave alone */
		if (dd->params->chip_type == CHIP_WFR) {
			/* SEND_DMA_CHECK_* are WFR only */
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_ENABLE, 0);
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_VL, 0);
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_JOB_KEY, 0);
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_PARTITION_KEY, 0);
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_SLID, 0);
			write_kctxt_csr(dd, i, SEND_DMA_CHECK_OPCODE, 0);
		}
		write_sdmacfg_csr(dd, i, dd->params->send_dma_cfg_memory_reg,
				  0);
	}
}

/*
 * Expect on entry:
 * o Packet ingress is disabled, i.e. RcvCtrl.RcvPortEnable == 0
 */
static void init_rbufs(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	int count;
	int pidx = ppd->hw_pidx;

	/*
	 * Wait for DMA to stop: RxRbufPktPending and RxPktInProgress are
	 * clear.
	 */
	count = 0;
	while (1) {
		reg = read_iport_csr(dd, pidx,
				     dd->params->rcv_iport_status_reg);
		if ((reg & (RCV_STATUS_RX_RBUF_PKT_PENDING_SMASK |
			    RCV_STATUS_RX_PKT_IN_PROGRESS_SMASK)) == 0)
			break;
		/*
		 * Give up after 1ms - maximum wait time.
		 *
		 * RBuf size is 136KiB.  Slowest possible is PCIe Gen1 x1 at
		 * 250MB/s bandwidth.  Lower rate to 66% for overhead to get:
		 *	136 KB / (66% * 250MB/s) = 844us
		 */
		if (count++ > 500) {
			ppd_dev_err(
				ppd,
				"%s: in-progress DMA not clearing: RcvStatus 0x%llx, continuing\n",
				__func__, reg);
			break;
		}
		udelay(2); /* do not busy-wait the CSR */
	}

	/* start the init - expect RcvCtrl to be 0 */
	write_iport_csr(dd, pidx, dd->params->rcv_iport_ctrl_reg,
			RCV_CTRL_RX_RBUF_INIT_SMASK);

	/*
	 * Read to force the write of RcvCtrl.RxRbufInit.  There is a brief
	 * period after the write before RcvStatus.RxRbufInitDone is valid.
	 * The delay in the first run through the loop below is sufficient and
	 * required before the first read of RcvStatus.RxRbufInitDone.
	 */
	read_iport_csr(dd, pidx, dd->params->rcv_iport_ctrl_reg);

	/* wait for the init to finish */
	count = 0;
	while (1) {
		/* delay is required first time through - see above */
		udelay(2); /* do not busy-wait the CSR */
		reg = read_iport_csr(dd, pidx,
				     dd->params->rcv_iport_status_reg);
		if (reg & (RCV_STATUS_RX_RBUF_INIT_DONE_SMASK))
			break;

		/* give up after 100us - slowest possible at 33MHz is 73us */
		if (count++ > 50) {
			ppd_dev_err(
				ppd,
				"%s: RcvStatus.RxRbufInit not set, continuing\n",
				__func__);
			break;
		}
	}
}

/* set RXE CSRs to chip reset defaults */
static void reset_rxe_csrs(struct hfi2_devdata *dd)
{
	u32 num_rmt_csrs = dd->params->rsm_map_table_entries /
			   dd->params->rsm_map_table_entries_per_csr;
	u32 num_qp_table_regs = dd->params->qp_map_table_entries /
				dd->params->qp_map_table_entries_per_csr;
	int i, j;

	/*
	 * RXE per-port Kernel CSRs
	 */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_pportdata *ppd = dd->pport + i;
		int pidx = ppd->hw_pidx;

		write_iport_csr(dd, pidx, dd->params->rcv_iport_ctrl_reg, 0);
		init_rbufs(ppd);
		/* RCV_STATUS read-only */
		/* RCV_CONTEXTS read-only */
		/* RCV_ARRAY_CNT read-only */
		/* RCV_BUF_SIZE read-only */
		write_iport_csr(dd, pidx, dd->params->rcv_bth_qp_reg, 0);
		write_iport_csr(dd, pidx, dd->params->rcv_multicast_reg, 0);
		write_iport_csr(dd, pidx, dd->params->rcv_bypass_reg, 0);
		write_iport_csr(dd, pidx, dd->params->rcv_vl15_reg, 0);
		/* this is a clear-down */
		write_iport_csr(dd, pidx, dd->params->rcv_err_info_reg,
				RCV_ERR_INFO_RCV_EXCESS_BUFFER_OVERRUN_SMASK);
		/* RCV_ERR_STATUS read-only */
		write_iport_csr(dd, pidx, dd->params->rcv_err_mask_reg, 0);
		write_iport_csr(dd, pidx, dd->params->rcv_err_clear_reg, ~0ull);
		/* RCV_ERR_FORCE leave alone */
		for (j = 0; j < num_qp_table_regs; j++)
			write_iport_csr(
				dd, pidx,
				dd->params->rcv_qp_map_table_reg + (8 * j), 0);
		for (j = 0; j < 4; j++)
			write_iport_csr(
				dd, pidx,
				dd->params->rcv_partition_key_reg + (8 * j), 0);
		for (j = 0; j < RXE_NUM_32_BIT_COUNTERS; j++)
			write_iport_csr(dd, pidx,
					dd->params->rcv_counter_array32_reg +
						(8 * j),
					0);
		for (j = 0; j < RXE_NUM_64_BIT_COUNTERS; j++)
			write_iport_csr(dd, pidx,
					dd->params->rcv_counter_array64_reg +
						(8 * j),
					0);
	}

	/*
	 * Clear all RSM rules from index 0. This function is called during
	 * chip reset where all rules must be cleared regardless of which
	 * rules are currently in use.
	 */
	for (i = 0; i < dd->params->rsm_rule_size; i++)
		clear_rsm_rule(dd, i);
	for (i = 0; i < num_rmt_csrs; i++)
		hfi2_write_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * i),
			       0);

	/*
	 * RXE Kernel and User Per-Context CSRs
	 */
	for (i = 0; i < chip_rcv_contexts(dd); i++) {
		/* kernel */
		write_kctxt_csr(dd, i, dd->params->rcv_kctxt_ctrl_reg, 0);
		write_rctxt_csr(dd, i, dd->params->rcv_rctxt_ctrl_reg, 0);
		/* RCV_CTXT_STATUS read-only */
		write_rctxt_csr(dd, i, dd->params->rcv_egr_ctrl_reg, 0);
		write_rctxt_csr(dd, i, dd->params->rcv_tid_ctrl_reg, 0);
		for (j = 0; j < dd->num_pports; j++)
			write_iprc_csr(dd, j, i, dd->params->rcv_jkey_ctrl_reg,
				       0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_addr_reg, 0);
		if (dd->params->set_rheq_addr)
			dd->params->set_rheq_addr(dd, i, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_cnt_reg, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_ent_size_reg, 0);
		if (dd->params->chip_type == CHIP_WFR)
			write_kctxt_csr(dd, i, RCV_HDR_SIZE, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_tail_addr_reg, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_avail_time_out_reg, 0);
		write_kctxt_csr(dd, i, dd->params->rcv_hdr_ovfl_cnt_reg, 0);

		/* user */
		/* RCV_HDR_TAIL read-only */
		write_uctxt_csr(dd, i, dd->params->rcv_hdr_head_reg, 0);
		/* RCV_EGR_INDEX_TAIL read-only */
		write_uctxt_csr(dd, i, dd->params->rcv_egr_index_head_reg, 0);
		/* RCV_EGR_OFFSET_TAIL read-only */
		for (j = 0; j < RXE_NUM_TID_FLOWS; j++) {
			write_uctxt_csr(dd, i,
					dd->params->rcv_tid_flow_table_reg +
						(8 * j),
					0);
		}
	}
}

/*
 * Set sc2vl tables.
 *
 * They power on to zeros, so to avoid send context errors
 * they need to be set:
 *
 * SC 0-7 -> VL 0-7 (respectively)
 * SC 15  -> VL 15
 * otherwise
 *        -> VL 0
 */
static void init_sc2vl_tables(struct hfi2_devdata *dd)
{
	int i;
	int j;
	/* init per architecture spec, constrained by hardware capability */

	if (dd->params->chip_type != CHIP_WFR) {
		/* TODO: how does a VF get initial sc2vlt? */
		if (dd->is_vf)
			return;
		/* cport is active - read the current sc2vlt */
		for (i = 0; i < dd->num_pports; i++) {
			struct hfi2_pportdata *ppd = &dd->pport[i];

			hfi2_get_sc2vlt_tables(ppd, ppd->sc2vl);
		}

		return;
	}

	/* HFI maps sent packets */
	for (i = 0; i < dd->num_pports; i++) {
		write_eport_csr(dd, i, dd->params->send_sc2vlt0_reg,
				SC2VL_VAL(0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5,
					  6, 6, 7, 7));
		write_eport_csr(dd, i, dd->params->send_sc2vlt1_reg,
				SC2VL_VAL(1, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
					  13, 0, 14, 0, 15, 15));
		write_eport_csr(dd, i, dd->params->send_sc2vlt2_reg,
				SC2VL_VAL(2, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0,
					  21, 0, 22, 0, 23, 0));
		write_eport_csr(dd, i, dd->params->send_sc2vlt3_reg,
				SC2VL_VAL(3, 24, 0, 25, 0, 26, 0, 27, 0, 28, 0,
					  29, 0, 30, 0, 31, 0));
	}

	/* DC maps received packets */
	hfi2_write_csr(dd, DCC_CFG_SC_VL_TABLE_15_0,
		       DC_SC_VL_VAL(15_0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
				    6, 7, 7, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
				    13, 0, 14, 0, 15, 15));
	hfi2_write_csr(dd, DCC_CFG_SC_VL_TABLE_31_16,
		       DC_SC_VL_VAL(31_16, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0,
				    21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0,
				    27, 0, 28, 0, 29, 0, 30, 0, 31, 0));

	/* initialize the cached sc2vl values consistently with h/w */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_pportdata *ppd = &dd->pport[i];

		for (j = 0; j < 32; j++) {
			if (j < 8 || j == 15)
				*((u8 *)(ppd->sc2vl) + j) = (u8)j;
			else
				*((u8 *)(ppd->sc2vl) + j) = 0;
		}
	}
}

/*
 * Read chip sizes and then reset parts to sane, disabled, values.  We cannot
 * depend on the chip going through a power-on reset - a driver may be loaded
 * and unloaded many times.
 *
 * Do not write any CSR values to the chip in this routine - there may be
 * a reset following the (possible) FLR in this routine.
 *
 */
static int init_chip(struct hfi2_devdata *dd)
{
	int i;
	int ret = 0;
	u32 cce_int_mask_reg = dd->params->cce_int_mask_reg;

	/*
	 * Put the HFI CSRs in a known state.
	 * Combine this with a DC reset.
	 *
	 * Stop the device from doing anything while we do a
	 * reset.  We know there are no other active users of
	 * the device since we are now in charge.  Turn
	 * off all outbound and inbound traffic and make sure
	 * the device does not generate any interrupts.
	 */

	/* disable send contexts and SDMA engines */
	for (i = 0; i < dd->num_pports; i++)
		write_eport_csr(dd, i, dd->params->send_ctrl_reg, 0);
	for (i = 0; i < chip_send_contexts(dd); i++)
		write_tctxt_csr(dd, i, dd->params->send_ctxt_ctrl_reg, 0);
	for (i = 0; i < chip_sdma_engines(dd); i++)
		write_sdma_csr(dd, i, dd->params->send_dma_ctrl_reg, 0);
	/* disable port (turn off RXE inbound traffic) and contexts */
	for (i = 0; i < dd->num_pports; i++)
		write_iport_csr(dd, i, dd->params->rcv_iport_ctrl_reg, 0);
	for (i = 0; i < chip_rcv_contexts(dd); i++) {
		write_kctxt_csr(dd, i, dd->params->rcv_kctxt_ctrl_reg, 0);
		write_rctxt_csr(dd, i, dd->params->rcv_rctxt_ctrl_reg, 0);
	}
	/* mask all interrupt sources */
	for (i = 0; i < dd->params->num_int_csrs; i++)
		hfi2_write_csr(dd, cce_int_mask_reg + (8 * i), 0ull);

	/*
	 * DC Reset: do a full DC reset before the register clear.
	 * A recommended length of time to hold is one CSR read,
	 * so reread the CceDcCtrl.  Then, hold the DC in reset
	 * across the clear.
	 */
	hfi2_write_csr(dd, CCE_DC_CTRL, CCE_DC_CTRL_DC_RESET_SMASK);
	(void)hfi2_read_csr(dd, CCE_DC_CTRL);

	if (use_flr) {
		/*
		 * A FLR will reset the SPC core and part of the PCIe.
		 * The parts that need to be restored have already been
		 * saved.
		 */
		dd_dev_info(dd, "Resetting CSRs with FLR\n");

		/* do the FLR, the DC reset will remain */
		pcie_flr(dd->pcidev);

		/* restore command and BARs */
		ret = hfi2_restore_pci_variables(dd);
		if (ret) {
			dd_dev_err(dd, "%s: Could not restore PCI variables\n",
				   __func__);
			return ret;
		}

		if (hfi2_is_ax(dd)) {
			dd_dev_info(dd, "Resetting CSRs with FLR\n");
			pcie_flr(dd->pcidev);
			ret = hfi2_restore_pci_variables(dd);
			if (ret) {
				dd_dev_err(
					dd,
					"%s: Could not restore PCI variables\n",
					__func__);
				return ret;
			}
		}
	} else {
		dd_dev_info(dd, "Resetting CSRs with writes\n");
		reset_cce_csrs(dd);
		reset_txe_csrs(dd);
		reset_rxe_csrs(dd);
		reset_misc_csrs(dd);
	}
	/* clear the DC reset */
	hfi2_write_csr(dd, CCE_DC_CTRL, 0);

	/* Turn off LEDs */
	for (i = 0; i < dd->num_pports; i++)
		dd->params->hfi2_setextled(&dd->pport[i], 0);

	/*
	 * Clear the QSFP reset.
	 * An FLR enforces a 0 on all out pins. The driver does not touch
	 * ASIC_QSFPn_OUT otherwise.  This leaves RESET_N low and
	 * anything plugged constantly in reset, if it pays attention
	 * to RESET_N.
	 * Prime examples of this are optical cables. Set all pins high.
	 * I2CCLK and I2CDAT will change per direction, and INT_N and
	 * MODPRS_N are input only and their value is ignored.
	 */
	hfi2_write_csr(dd, ASIC_QSFP1_OUT, 0x1f);
	hfi2_write_csr(dd, ASIC_QSFP2_OUT, 0x1f);
	hfi2_init_chip_resources(dd);
	return ret;
}

void hfi2_init_early_variables(struct hfi2_devdata *dd)
{
	int i;

	/* assign link credit variables */
	dd->vau = CM_VAU;
	dd->link_credits = CM_GLOBAL_CREDITS;
	if (hfi2_is_ax(dd))
		dd->link_credits--;
	dd->vcu = hfi2_cu_to_vcu(hfi2_cu);
	/* enough room for 8 MAD packets plus header - 17K */
	dd->vl15_init = (8 * (2048 + 128)) / hfi2_vau_to_au(dd->vau);
	if (dd->vl15_init > dd->link_credits)
		dd->vl15_init = dd->link_credits;

	if (HFI2_CAP_IS_KSET(PKEY_CHECK))
		for (i = 0; i < dd->num_pports; i++) {
			struct hfi2_pportdata *ppd = &dd->pport[i];

			hfi2_set_partition_keys(ppd);
		}
	init_sc2vl_tables(dd);
}

void hfi2_init_kdeth_qp(struct hfi2_devdata *dd)
{
	u64 val;
	int i;

	if (dd->is_vf)
		return; /* Only PF0 does this */

	for (i = 0; i < dd->num_pports; i++) {
		val = (RVT_KDETH_QP_PREFIX & SEND_BTH_QP_KDETH_QP_MASK)
		      << SEND_BTH_QP_KDETH_QP_SHIFT;
		write_eport_csr(dd, i, dd->params->send_bth_qp_reg, val);
		if (dd->loopback_enabled)
			write_eport_csr(dd, loopback_pidx_dd(dd, i),
					dd->params->send_bth_qp_reg, val);

		val = (RVT_KDETH_QP_PREFIX & RCV_BTH_QP_KDETH_QP_MASK)
		      << RCV_BTH_QP_KDETH_QP_SHIFT;
		write_iport_csr(dd, i, dd->params->rcv_bth_qp_reg, val);
		if (dd->loopback_enabled)
			write_iport_csr(dd, loopback_pidx_dd(dd, i),
					dd->params->rcv_bth_qp_reg, val);
	}
}

/**
 * hfi2_get_qp_map - look up the receive context for a qp map entry
 * @ppd: per-port data
 * @idx: qp map table index to read (will be masked to table size)
 * @rcd_idx: on success, set to the receive context index for @idx
 *
 * Reads one entry from the qp map table (or forwards the request to the PF
 * when running as a VF) and stores the resulting receive context index in
 * *@rcd_idx.
 * Return: 0 on success with *@rcd_idx set, or a negative errno on failure
 * (VF2PF path only). *@rcd_idx is left unchanged on failure.
 */
int hfi2_get_qp_map(struct hfi2_pportdata *ppd, u16 idx, u16 *rcd_idx)
{
	struct hfi2_devdata *dd = ppd->dd;
	u32 tbl_idx;
	u32 reg_idx;
	u32 entry_idx;
	u32 off;
	u64 reg;

	if (dd->is_vf)
		return vf2pf_get_qp_map(dd, ppd->hw_pidx, idx, rcd_idx);

	tbl_idx = idx & (dd->params->qp_map_table_entries - 1);
	reg_idx = tbl_idx / dd->params->qp_map_table_entries_per_csr;
	entry_idx = tbl_idx % dd->params->qp_map_table_entries_per_csr;

	off = dd->params->rcv_qp_map_table_reg + (reg_idx * 8);
	reg = read_iport_csr(dd, ppd->hw_pidx, off);

	*rcd_idx = (reg >> (entry_idx * dd->params->qp_map_table_entry_shift)) &
		   dd->params->qp_map_table_entry_mask;
	return 0;
}

/**
 * init_qpmap_table - init qp map
 * @ppd: port data
 * @first_ctxt: first context
 * @last_ctxt: last context
 *
 * This return sets the qpn mapping table that
 * is indexed by qpn[8:1].
 *
 * The routine will round robin the 256 settings
 * from first_ctxt to last_ctxt.
 *
 * The first/last looks ahead to having specialized
 * receive contexts for mgmt and bypass.  Normal
 * verbs traffic will assumed to be on a range
 * of receive contexts.
 *
 * Assumes hfi2_loopback QP map is identical to fabric port QP map.
 */
static void init_qpmap_table(struct hfi2_pportdata *ppd, u32 first_ctxt,
			     u32 last_ctxt)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = 0;
	u64 ctxt = first_ctxt;
	u32 regno = dd->params->rcv_qp_map_table_reg;
	u32 entry_shift = dd->params->qp_map_table_entry_shift;
	u32 entry_top = dd->params->qp_map_table_entries_per_csr - 1;
	int count = dd->params->qp_map_table_entries;
	int i;

	for (i = 0; i < count; i++) {
		u32 entry_idx = i % dd->params->qp_map_table_entries_per_csr;

		reg |= ctxt << (entry_shift * entry_idx);
		ctxt++;
		if (ctxt > last_ctxt)
			ctxt = first_ctxt;
		if (entry_idx == entry_top) {
			write_iport_csr(dd, ppd->hw_pidx, regno, reg);
			if (dd->loopback_enabled)
				write_iport_csr(dd, loopback_pidx(ppd), regno,
						reg);
			reg = 0;
			regno += 8;
		}
	}

	hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_QP_MAP_ENABLE_SMASK |
				 RCV_CTRL_RCV_BYPASS_ENABLE_SMASK);
}

void set_rmt_entry(struct hfi2_devdata *dd, struct rsm_map_table *rmt,
		   u16 idx, u16 value);

void set_rmt_entry(struct hfi2_devdata *dd, struct rsm_map_table *rmt,
		   u16 idx, u16 value)
{
	u64 reg;
	int regoff, regidx;
	u32 entries_per_csr = dd->params->rsm_map_table_entries_per_csr;
	u32 entry_mask = dd->params->rsm_map_table_entry_mask;
	u32 entry_shift = dd->params->rsm_map_table_entry_shift;

	regoff = ((unsigned int)idx % entries_per_csr) * entry_shift;
	regidx = (unsigned int)idx / entries_per_csr;
	reg = rmt->map[regidx];
	reg &= ~((u64)entry_mask << regoff);
	reg |= ((u64)(value & entry_mask) << regoff);
	rmt->map[regidx] = reg;
}

/*
 * Assumes hfi2_loopback QP map is identical to fabric port QP map.
 */
static void init_qpmap_table_range(struct hfi2_pportdata *ppd, u32 start_idx,
				   u32 end_idx, u32 first_ctxt, u32 last_ctxt)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = 0;
	u32 regno;
	int i;
	u32 ixshf = dd->params->qp_map_table_entry_shift;
	u32 ixmsk = dd->params->qp_map_table_entries_per_csr - 1;
	u64 mtmsk = dd->params->qp_map_table_entry_mask;
	u64 ctxt = first_ctxt;
	bool valid = false;

	regno = dd->params->rcv_qp_map_table_reg +
		(start_idx / dd->params->qp_map_table_entries_per_csr) * 8;
	for (i = start_idx; i < end_idx; i++) {
		if (!valid) {
			reg = read_iport_csr(dd, ppd->hw_pidx, regno);
			valid = true;
		}
		reg &= ~(mtmsk << (ixshf * (i & ixmsk)));
		reg |= ctxt << (ixshf * (i & ixmsk));
		ctxt++;
		if (ctxt > last_ctxt)
			ctxt = first_ctxt;
		if ((i & ixmsk) == ixmsk) {
			write_iport_csr(dd, ppd->hw_pidx, regno, reg);
			if (dd->loopback_enabled)
				write_iport_csr(dd, loopback_pidx(ppd), regno,
						reg);
			reg = 0;
			regno += 8;
			valid = false;
		}
	}
	if (valid) {
		write_iport_csr(dd, ppd->hw_pidx, regno, reg);
		if (dd->loopback_enabled)
			write_iport_csr(dd, loopback_pidx(ppd), regno, reg);
	}
}

/*
 * Return an initialized RMT map table for users to fill in.  OK if it
 * returns NULL, indicating no table.
 */
static struct rsm_map_table *alloc_rsm_map_table(struct hfi2_devdata *dd)
{
	struct rsm_map_table *rmt;
	u32 num_rmt_csrs = dd->params->rsm_map_table_entries /
			   dd->params->rsm_map_table_entries_per_csr;
	/* 0 is default if a0 version */
	u16 rxcontext = hfi2_is_ax(dd) ? 0 :
					 dd->params->rsm_map_table_entry_mask;
	u32 i;

	rmt = kmalloc(sizeof(*rmt) + (sizeof(rmt->map[0]) * num_rmt_csrs),
		      GFP_KERNEL);
	if (rmt) {
		for (i = 0; i < dd->params->rsm_map_table_entries; ++i)
			set_rmt_entry(dd, rmt, i, rxcontext);
		rmt->used = 0;
		// FIXME: This should be from a "resource start" point.
	}

	return rmt;
}

/*
 * Write the final RSM map table to the chip and enable RSM on each port.
 */
static void complete_rsm_map_table(struct hfi2_devdata *dd,
				   struct rsm_map_table *rmt)
{
	u32 num_rmt_csrs = dd->params->rsm_map_table_entries /
			   dd->params->rsm_map_table_entries_per_csr;
	int i;

	/* write table to chip */
	for (i = 0; i < num_rmt_csrs; i++)
		hfi2_write_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * i),
			       rmt->map[i]);
	/* enable RSM on each port */
	for (i = 0; i < dd->num_pports; i++)
		hfi2_add_rcvctrl(dd->pport + i, RCV_CTRL_RCV_RSM_ENABLE_SMASK);
}

static bool rr_type_is_chain(enum rr_type type)
{
	if (type == RR_CHAIN_EXPECTED_9B  ||
	    type == RR_CHAIN_EXPECTED_16B ||
	    type == RR_CHAIN_EAGER_9B     ||
	    type == RR_CHAIN_EAGER_16B    ||
	    type == RR_CHAIN_VERBS_9B     ||
	    type == RR_CHAIN_VERBS_16B    ||
	    type == RR_CHAIN_BYPASS)
		return true;
	return false;
}

/*
 * Return true if the RR type is 9B.  Only explicit 9B qualify.  All others
 * default to 16B.
 */
static bool rr_type_is_9b(enum rr_type type)
{
	if (type == RR_TYPE_EXPECTED_9B  ||
	    type == RR_TYPE_EAGER_9B     ||
	    type == RR_TYPE_VERBS_9B     ||
	    type == RR_CHAIN_EXPECTED_9B ||
	    type == RR_CHAIN_EAGER_9B    ||
	    type == RR_CHAIN_VERBS_9B)
		return true;
	return false;
}



/*
 * Return the hardware packet classification from given the RR abstraction.
 */
static u32 rr_type_to_pkt_type(struct hfi2_devdata *dd, enum rr_type type)
{
	if (dd->params->chip_type == CHIP_WFR) {
		/* WFR: only 9B can be expected, eager, or verbs */
		switch (type) {
		case RR_TYPE_EXPECTED_9B:
			return RHF_RCV_TYPE_EXPECTED;
		case RR_TYPE_EAGER_9B:
			return RHF_RCV_TYPE_EAGER;
		case RR_TYPE_VERBS_9B:
			return RHF_RCV_TYPE_IB;
		default:
			break;
		}
		/* all others are bypass */
		return RHF_RCV_TYPE_BYPASS;
	}

	/* non-WFR: both 9B and 16B can be expected, eager, or verbs */
	switch (type) {
	case RR_TYPE_EXPECTED_9B:
	case RR_TYPE_EXPECTED_16B:
	case RR_CHAIN_EXPECTED_9B:
	case RR_CHAIN_EXPECTED_16B:
		return RHF_RCV_TYPE_EXPECTED;
	case RR_TYPE_EAGER_9B:
	case RR_TYPE_EAGER_16B:
	case RR_CHAIN_EAGER_9B:
	case RR_CHAIN_EAGER_16B:
		return RHF_RCV_TYPE_EAGER;
	case RR_TYPE_VERBS_9B:
	case RR_TYPE_VERBS_16B:
	case RR_CHAIN_VERBS_9B:
	case RR_CHAIN_VERBS_16B:
		return RHF_RCV_TYPE_IB;
	default:
		break;
	}
	/* all others are bypass */
	return RHF_RCV_TYPE_BYPASS;
}



/*
 * Release all allocated rules.
 * Expect to be called at driver unload time.
 */
void hfi2_release_rsm_rules(struct hfi2_devdata *dd)
{
	int i;

	if (!dd->rsm_rule_init)
		return;

	for (i = dd->first_rsm_rule; i < dd->params->rsm_rule_size; i++) {
		if (dd->rr_info[i] != RR_EMPTY)
			clear_rsm_rule(dd, i);
	}
	dd->rsm_rule_init = false;
}

/*
 * Allocate a RSM rule index.
 * Returns >=0 rule index, or -ENOSPC if no room
 */


/*
 * Return true if this RR abstraction needs an associated chain to
 * differentiate 9B from 16B.
 */
static bool rr_type_needs_chain(struct hfi2_devdata *dd, enum rr_type type)
{
	/* no chains needed on WFR */
	if (dd->params->chip_type == CHIP_WFR)
		return false;

	switch (type) {
	case RR_TYPE_EXPECTED_9B:
	case RR_TYPE_EXPECTED_16B:
	case RR_TYPE_EAGER_9B:
	case RR_TYPE_EAGER_16B:
	case RR_TYPE_VERBS_9B:
	case RR_TYPE_VERBS_16B:
		return true;
	default:
		break;
	}

	/* all others: no chain */
	return false;
}

/* convert the type to its corresponding chain */
static enum rr_type rr_type_to_chain(enum rr_type type)
{
	switch (type) {
	case RR_TYPE_EXPECTED_9B:
		return RR_CHAIN_EXPECTED_9B;
	case RR_TYPE_EXPECTED_16B:
		return RR_CHAIN_EXPECTED_16B;
	case RR_TYPE_EAGER_9B:
		return RR_CHAIN_EAGER_9B;
	case RR_TYPE_EAGER_16B:
		return RR_CHAIN_EAGER_16B;
	case RR_TYPE_VERBS_9B:
		return RR_CHAIN_VERBS_9B;
	case RR_TYPE_VERBS_16B:
		return RR_CHAIN_VERBS_16B;
	default:
		break;
	}
	/* no conversion, return given type */
	return type;
}

/*
 * Return the chain mask for the given rule type.
 *
 * The chain mask is the bottom 4 bits for group indices 0-3.
 * Parameter rule_index is the index of the parent rule.
 */
static u32 rr_type_to_chain_mask(struct hfi2_devdata *dd, enum rr_type type,
				 int rule_index)
{
	u32 block_index;

	if (!rr_type_needs_chain(dd, type))
		return 0;

	/*
	 * Expect the chain will always be the rule immediately following
	 * the parent in a block.
	 */
	block_index = rule_index % 4;
	if (block_index == 3) {
		dd_dev_err(dd, "cannot add a chained rule at block index 3\n");
		return 0;
	}

	return 1 << (block_index + 1);
}

/*
 * Add a typed 9B or 16B match chain rule at the given index.
 *
 * The rule not intended to be used stand-alone.  Rather it is intended
 * to be chained to a parent rule.
 *
 * Only the type, port index mask, and match fields are used.
 */
static void add_chain_rule(struct hfi2_devdata *dd, int index,
			   enum rr_type type, u32 pidx_mask)
{
	struct rsm_rule_data rrd = {};

	/* offset not used */
	rrd.rr_type = rr_type_to_chain(type); /* from parent */
	rrd.pidx_mask = pidx_mask;            /* from parent */
	/*
	 * Match details:  At bits 63:61, 9B and 16B packets have:
	 *
	 *  bits      9B          16B
	 * [63:61]  SC[3:1]    LT=1 L2=2
	 *
	 * The value of 6 will always match 16B.
	 *
	 * This requires that no 9B hfi2_packet have SC 0bx110x => 12, 13, 28, or 29.
	 */
	rrd.field1_off = 61;
	rrd.mask1 = 0x7;
	rrd.value1 = 0x6; /* match this value */
	/* field == 0x6 => 16B, field != 0x6 => 9B */
	rrd.invert1 = rr_type_is_9b(type) ? 1 : 0; /* invert match if 9B */
	/* no field2, mask2, value2, invert2 */
	/* no extraction 1 or 2 off, width */

	add_rsm_rule(dd, index, &rrd);
}

static bool rsm_bypass_chain_ok(struct hfi2_devdata *dd, int rule_index,
				const struct rsm_rule_data *rrd)
{
	int j;

	if (rrd->rr_type != RR_TYPE_BYPASS ||
	    rule_index % 4 + rrd->nchain > 3 ||
	    dd->rr_info[rule_index] != RR_TYPE_BYPASS)
		return false;
	for (j = 1; j <= rrd->nchain; j++)
		if (dd->rr_info[rule_index + j] != RR_CHAIN_BYPASS)
			return false;
	return true;
}


/*
 * Add a receive side mapping rule.
 */
static void __add_rsm_rule(struct hfi2_devdata *dd, u8 rule_index,
			   struct rsm_rule_data *rrd, u8 nchain)
{
	u64 pkt_type = rr_type_to_pkt_type(dd, rrd->rr_type);
	u64 chain_mask = rr_type_to_chain_mask(dd, rrd->rr_type, rule_index);
	u64 self_enable;
	u64 invert;
	u64 bypass_hdr_size;

	if (nchain)
		chain_mask |= GENMASK_ULL(rule_index % 4 + nchain, rule_index % 4 + 1);

	/*
	 * Recursively add a chain to the next slot, if needed.  The rule
	 * index allocator has already arranged for any type that needs a chain
	 * to not be last in a block and has left the next slot marked full
	 * with a chain type.
	 */
	if (rr_type_needs_chain(dd, rrd->rr_type))
		add_chain_rule(dd, rule_index + 1, rrd->rr_type, rrd->pidx_mask);

	/* chains are not directly enabled */
	if (rr_type_is_chain(rrd->rr_type))
		self_enable = 0;
	else
		self_enable = 1ull << (rule_index % 4);

	/*
	 * The bypass-hdr-size field exists only on CYR.  add_rsm_rule() is
	 * generation-shared, so a non-zero bypass_hdr_size on WFR/JKR would
	 * set reserved bits; reject it here rather than corrupting the CSR.
	 */
	if (WARN_ON_ONCE(rrd->bypass_hdr_size && dd->params->chip_type != CHIP_CYR))
		bypass_hdr_size = 0;
	else
		bypass_hdr_size = (rrd->bypass_hdr_size & CYR_RCV_RSM_CFG_BYPASS_HDR_SIZE_MASK) <<
			CYR_RCV_RSM_CFG_BYPASS_HDR_SIZE_SHIFT;

	hfi2_write_csr(dd, dd->params->rcv_rsm_cfg_reg + (8 * rule_index),
		  (u64)rrd->offset << dd->params->rsm_rule_offset_shift |
		  (u64)rrd->pidx_mask << 40 | /* port enable mask (non WFR) */
		  self_enable |
		  chain_mask |
		  pkt_type << RCV_RSM_CFG_PACKET_TYPE_SHIFT | bypass_hdr_size);
	hfi2_write_csr(dd, dd->params->rcv_rsm_select_reg + (8 * rule_index),
		  (u64)rrd->field1_off << RCV_RSM_SELECT_FIELD1_OFFSET_SHIFT |
			  (u64)rrd->field2_off
				  << RCV_RSM_SELECT_FIELD2_OFFSET_SHIFT |
			  (u64)rrd->index1_off
				  << RCV_RSM_SELECT_INDEX1_OFFSET_SHIFT |
			  (u64)rrd->index1_width
				  << RCV_RSM_SELECT_INDEX1_WIDTH_SHIFT |
			  (u64)rrd->index2_off
				  << RCV_RSM_SELECT_INDEX2_OFFSET_SHIFT |
			  (u64)rrd->index2_width
				  << RCV_RSM_SELECT_INDEX2_WIDTH_SHIFT);

	/* MatchInvertField{1,2} do not exist for WFR */
	if (dd->params->chip_type == CHIP_WFR) {
		if (rrd->invert1 || rrd->invert2)
			dd_dev_err(dd, "Adding a rule with an invert is not supported\n");
		invert = 0;
	} else {
		invert = (u64)rrd->invert1 << JKR_RCV_RSM_MATCH_MATCH_INVERT_FIELD1_SHIFT |
			 (u64)rrd->invert2 << JKR_RCV_RSM_MATCH_MATCH_INVERT_FIELD2_SHIFT;
	}
	hfi2_write_csr(dd, dd->params->rcv_rsm_match_reg + (8 * rule_index),
		  invert |
			  (u64)rrd->mask1 << RCV_RSM_MATCH_MASK1_SHIFT |
			  (u64)rrd->value1 << RCV_RSM_MATCH_VALUE1_SHIFT |
			  (u64)rrd->mask2 << RCV_RSM_MATCH_MASK2_SHIFT |
			  (u64)rrd->value2 << RCV_RSM_MATCH_VALUE2_SHIFT);
}

void add_rsm_rule(struct hfi2_devdata *dd, u8 rule_index,
		  struct rsm_rule_data *rrd)
{
	__add_rsm_rule(dd, rule_index, rrd, 0);
}

/*
 * Clear a receive side mapping rule.
 */
void clear_rsm_rule(struct hfi2_devdata *dd, int rule_index)
{
	bool bypass_chain;

	if (rule_index < 0 || rule_index >= dd->params->rsm_rule_size)
		return;
	/*
	 * Recursively remove a chain from next slot, if needed.  When
	 * allocated, any type that needs a chain will not be last in
	 * a block.
	 */
	if (rr_type_needs_chain(dd, dd->rr_info[rule_index]))
		clear_rsm_rule(dd, rule_index + 1);
	bypass_chain = (dd->rr_info[rule_index] == RR_TYPE_BYPASS ||
			dd->rr_info[rule_index] == RR_CHAIN_BYPASS) &&
		       rule_index % 4 != 3 &&
		       dd->rr_info[rule_index + 1] == RR_CHAIN_BYPASS;

	hfi2_write_csr(dd, dd->params->rcv_rsm_cfg_reg + (8 * rule_index), 0);
	hfi2_write_csr(dd, dd->params->rcv_rsm_select_reg + (8 * rule_index), 0);
	hfi2_write_csr(dd, dd->params->rcv_rsm_match_reg + (8 * rule_index), 0);
	dd->rr_info[rule_index] = RR_EMPTY;
	if (bypass_chain)
		clear_rsm_rule(dd, rule_index + 1);
}

/*
 * Release all allocated rules.
 * Expect to be called at driver unload time.
 */


/*
 * Allocate an RSM rule.  This will work for all chip types.
 * If any locking is needed, the caller will do it.
 *
 * Look for an empty slot or, if a chain is needed (never on WFR), an empty
 * pair of slots.
 */
static int gen_alloc_rsm_rule(struct hfi2_devdata *dd, enum rr_type type,
			      int first)
{
	bool needs_chain = rr_type_needs_chain(dd, type);
	int i;

	for (i = first; i < dd->params->rsm_rule_size; i++) {
		if (dd->rr_info[i] != RR_EMPTY)
			continue;

		/* no chain needed, use the first open spot */
		if (!needs_chain) {
			dd->rr_info[i] = type; /* claim slot */
			return i;
		}

		/*
		 * This slot is empty + a chain is needed.
		 *
		 * Can't chain across a block boundary.  Look for current plus
		 * next as the pair.
		 */

		/* reject if this is the last block slot */
		if ((i % 4) == 3)
			continue;

		/* accept if next is empty */
		if (dd->rr_info[i + 1] == RR_EMPTY) {
			/* claim slots */
			dd->rr_info[i] = type;
			dd->rr_info[i + 1] = rr_type_to_chain(type);
			return i;
		}
	}

	return -ENOSPC;
}

/**
 * gen_alloc_rsm_bypass_chain() - claim a bypass rule and its chain slots
 * @dd: device data
 * @nchain: number of RR_CHAIN_BYPASS rules to follow the bypass rule
 * @first: lowest RSM slot to consider
 *
 * Claim a bypass rule followed by @nchain RR_CHAIN_BYPASS rules in the same
 * block, at or above @first.  The caller does any locking.
 *
 * Return: the RSM slot of the bypass rule, or -ENOSPC if no room.
 */
static int gen_alloc_rsm_bypass_chain(struct hfi2_devdata *dd, int nchain,
				      int first)
{
	int i, j;

	for (i = first; i + nchain < dd->params->rsm_rule_size; i++) {
		if (i % 4 + nchain > 3)
			continue;
		for (j = i; j <= i + nchain; j++)
			if (dd->rr_info[j] != RR_EMPTY)
				break;
		if (j <= i + nchain)
			continue;

		dd->rr_info[i] = RR_TYPE_BYPASS;
		for (j = i + 1; j <= i + nchain; j++)
			dd->rr_info[j] = RR_CHAIN_BYPASS;
		return i;
	}

	return -ENOSPC;
}

/**
 * alloc_rsm_bypass_chain_from() - allocate a bypass rule and its chain
 * @dd: device data
 * @nchain: number of RR_CHAIN_BYPASS rules to follow the bypass rule
 * @reason: RSM_TYPE_* user, for the error message
 * @first: lowest RSM slot to consider
 *
 * Return: the RSM slot of the bypass rule, or -ENOSPC if no room.
 */
static int alloc_rsm_bypass_chain_from(struct hfi2_devdata *dd, int nchain,
				       int reason, int first)
{
	unsigned long flags;
	int index;

	spin_lock_irqsave(&dd->dc8051_memlock, flags); /* repurposed lock */
	index = gen_alloc_rsm_bypass_chain(dd, nchain, first);
	spin_unlock_irqrestore(&dd->dc8051_memlock, flags); /* repurposed lock */

	if (index < 0)
		dd_dev_err(dd, "Unable to allocate rule + %d chained for %d at or above %d, err %d\n",
			   nchain, reason, first, index);

	return index;
}

/**
 * add_rsm_bypass_chain() - write a bypass rule and the rules it chains
 * @dd: device data
 * @rule_index: RSM slot of the bypass rule
 * @rrd: the bypass rule
 * @chain: the @rrd->nchain RR_CHAIN_BYPASS rules that @rrd ANDs in
 *
 * Write the chain before the rule that enables it.
 *
 * Return: 0, or -EINVAL with nothing written if the slots did not come from
 * alloc_rsm_bypass_chain_from().
 */
static int add_rsm_bypass_chain(struct hfi2_devdata *dd, int rule_index,
				struct rsm_rule_data *rrd,
				struct rsm_rule_data *chain)
{
	int j;

	if (WARN_ON_ONCE(!rsm_bypass_chain_ok(dd, rule_index, rrd)))
		return -EINVAL;
	for (j = 0; j < rrd->nchain; j++)
		if (WARN_ON_ONCE(chain[j].rr_type != RR_CHAIN_BYPASS ||
				 chain[j].nchain))
			return -EINVAL;

	for (j = 0; j < rrd->nchain; j++)
		add_rsm_rule(dd, rule_index + 1 + j, &chain[j]);
	__add_rsm_rule(dd, rule_index, rrd, rrd->nchain);
	return 0;
}

/*
 * Allocate a RSM rule index at or above @first.
 * Returns >=0 rule index, or -ENOSPC if no room
 */
static int alloc_rsm_rule_from(struct hfi2_devdata *dd, enum rr_type type,
			       int reason, int first)
{
	unsigned long flags;
	int index;

	spin_lock_irqsave(&dd->dc8051_memlock, flags); /* repurposed lock */
	index = gen_alloc_rsm_rule(dd, type, first);
	spin_unlock_irqrestore(&dd->dc8051_memlock, flags); /* repurposed lock */

	if (index < 0) {
		dd_dev_err(dd, "Unable to allocate rule for %d, type %d, err %d\n",
			   reason, type, index);
	}

	return index;
}

/*
 * Allocate a RSM rule index.
 * Returns >=0 rule index, or -ENOSPC if no room
 */
int alloc_rsm_rule(struct hfi2_devdata *dd, enum rr_type type, int reason)
{
	return alloc_rsm_rule_from(dd, type, reason, 0);
}

/* return the number of RSM map table entries that will be used for QOS */
static int qos_rmt_entries(unsigned int n_krcv_queues, unsigned int *mp,
			   unsigned int *np)
{
	int i;
	unsigned int m, n;
	uint max_by_vl = 0;

	/* is QOS active at all? */
	if (n_krcv_queues < MIN_KERNEL_KCTXTS || hfi2_num_vls == 1 || hfi2_krcvqsset <= 1)
		goto no_qos;

	/* determine bits for qpn */
	for (i = 0; i < min_t(unsigned int, hfi2_num_vls, hfi2_krcvqsset); i++)
		if (hfi2_krcvqs[i] > max_by_vl)
			max_by_vl = hfi2_krcvqs[i];
	if (max_by_vl > 32)
		goto no_qos;
	m = ilog2(__roundup_pow_of_two(max_by_vl));

	/* determine bits for vl */
	n = ilog2(__roundup_pow_of_two(hfi2_num_vls));

	/* reject if too much is used */
	if ((m + n) > 7)
		goto no_qos;

	if (mp)
		*mp = m;
	if (np)
		*np = n;

	return 1 << (m + n);

no_qos:
	if (mp)
		*mp = 0;
	if (np)
		*np = 0;
	return 0;
}

/**
 * init_qos_port - initialize RX QOS for a single port
 * @ppd: port data
 * @rmt: RSM map table
 *
 * This routine initializes a rule and the RSM map table to implement
 * quality of service (qos) for this port.
 *
 * If all of the limit tests succeed, qos is applied based on the array
 * interpretation of hfi2_krcvqs where entry 0 is VL0.
 *
 * The number of vl bits (n) and the number of qpn bits (m) are computed to
 * feed both the RSM map table and the single rule.
 */
static void init_qos_port(struct hfi2_pportdata *ppd, struct rsm_map_table *rmt)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_portrsrcs *pr = &dr->ppr[ppd->hw_pidx];
	unsigned int rcb = pr->rcv_context_base;
	struct rsm_rule_data rrd = {};
	unsigned int qpns_per_vl, extended_vl, ctxt, i, qpn, n, m;
	unsigned int rmt_entries;
	int rule_index;

	if (!rmt)
		goto bail;
	if (!pr->n_krcv_queues)
		goto bail;
	rmt_entries = qos_rmt_entries(pr->n_krcv_queues - 1, &m, &n);
	if (rmt_entries == 0)
		goto bail;
	qpns_per_vl = 1 << m;
	extended_vl = 1 << n;

	/* enough room in the map table? */
	if (rmt->used + rmt_entries > dd->params->rsm_map_table_entries)
		goto bail;

	/* allocate a rule */
	rule_index = alloc_rsm_rule(dd, RR_TYPE_VERBS_9B, RSM_TYPE_VERBS);
	if (rule_index < 0)
		goto bail;

	/* fill block in RMT with this port's control context */
	ctxt = rcb + HFI2_CTRL_CTXT;
	for (i = 0; i < rmt_entries; i++)
		set_rmt_entry(dd, rmt, rmt->used + i, ctxt);

	/* overwrite applicable qos entries */
	ctxt = rcb + FIRST_KERNEL_KCTXT;
	for (i = 0; i < hfi2_num_vls; i++) {
		unsigned int tctxt;
		unsigned int idx;

		for (qpn = 0, tctxt = ctxt; hfi2_krcvqs[i] && qpn < qpns_per_vl;
		     qpn++) {
			/* generate the index the hardware will produce */
			idx = rmt->used + ((qpn << n) ^ i);
			set_rmt_entry(dd, rmt, idx, tctxt);
			tctxt++;
			if (tctxt == ctxt + hfi2_krcvqs[i])
				tctxt = ctxt;
		}
		ctxt += hfi2_krcvqs[i];
	}

	/*
	 * Create a rule to extract an index using the formula:
	 *	idx = qpn[m+n+1:1] ^ VL[n-1:0]
	 *
	 * The "qos_shift" setting will ensure the bottom n+1 bits of the QPN
	 * will always be zero (except for GSI QPN=1).
	 */
	rrd.rr_type = RR_TYPE_VERBS_9B;
	rrd.offset = rmt->used;
	rrd.pidx_mask = 1 << ppd->hw_pidx;
	rrd.field1_off = LRH_BTH_MATCH_OFFSET;
	rrd.field2_off = LRH_SC_MATCH_OFFSET;
	rrd.index1_off = LRH_SC_SELECT_OFFSET;
	rrd.index1_width = n;
	rrd.index2_off = QPN_SELECT_OFFSET;
	rrd.index2_width = m + n;
	rrd.mask1 = LRH_BTH_MASK;
	rrd.value1 = LRH_BTH_VALUE;
	rrd.mask2 = LRH_SC_MASK;
	rrd.value2 = LRH_SC_VALUE;

	/* add rule */
	add_rsm_rule(dd, rule_index, &rrd);

	/* mark RSM map entries as used */
	rmt->used += rmt_entries;

	ppd->qos_shift = n + 1;

	/* map everything else to this port's mcast/err/vl15 context */
	init_qpmap_table(ppd, rcb + HFI2_CTRL_CTXT, rcb + HFI2_CTRL_CTXT);
	return;
bail:
	ppd->qos_shift = 1;

	if (pr->n_krcv_queues) {
		/* map everything to this port's kernel contexts (excl. HFI2_CTRL_CTXT) */
		ctxt = rcb + FIRST_KERNEL_KCTXT;
		init_qpmap_table(ppd, ctxt,
				 ctxt + pr->n_krcv_queues - FIRST_KERNEL_KCTXT -
					 1);
	}
}

static void init_qos(struct hfi2_devdata *dd, struct rsm_map_table *rmt)
{
	int i;

	for (i = 0; i < dd->num_pports; i++)
		init_qos_port(&dd->pport[i], rmt);
}

/* set a single RSM Map Table (RMT) entry in the given map */


static void init_fecn_handling(struct hfi2_pportdata *ppd,
			       struct rsm_map_table *rmt)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_portrsrcs *pr = &dr->ppr[ppd->hw_pidx];
	struct rsm_rule_data rrd = {};
	int i, idx, start, end;
	u16 offset;
	u32 total_cnt;
	int rule_index;

	/* do nothing if port is not availble */
	if (!port_available_ppd(ppd))
		return;

	/*
	 * This rule is WFR only.  All chips beyond WFR respond to FECN without
	 * software intervention.
	 *
	 * The FECN+SH rule added here can safely be 9B only.  It is only for
	 * expected packets and expected packets can only be 9B on WFR.
	 */
	if (dd->params->chip_type != CHIP_WFR)
		return;

	if (hfi2_dev_tid_rdma(dd))
		/* Exclude control context */
		start = pr->rcv_context_base + 1;
	else
		start = pr->first_bulksvc_alloc_ctxt;
	end = pr->rcv_context_base + pr->num_rcv_contexts;

	total_cnt = end - start;

	/* there needs to be enough room in the map table */
	if (rmt->used + total_cnt > dd->params->rsm_map_table_entries) {
		ppd_dev_err(
			ppd,
			"FECN handling disabled - too many contexts allocated\n");
		return;
	}

	rule_index = alloc_rsm_rule(dd, RR_TYPE_EXPECTED_9B, RSM_TYPE_FECN);
	if (rule_index < 0)
		return;

	/*
	 * RSM will extract the destination context as an index into the
	 * map table.  The destination contexts are a sequential block
	 * in the range start..end-1 (inclusive).
	 * Map entries are accessed as offset + extracted value.  Adjust
	 * the added offset so this sequence can be placed anywhere in
	 * the table - as long as the entries themselves do not wrap.
	 * There are only enough bits in offset for the table size, so
	 * start with that to allow for a "negative" offset.
	 */
	offset = (dd->params->rsm_map_table_entries + rmt->used - start) &
		 dd->params->rsm_map_table_entry_mask;

	for (i = start, idx = rmt->used; i < end; i++, idx++) {
		/* replace with identity mapping */
		set_rmt_entry(dd, rmt, idx, i);
	}

	/*
	 * For RSM intercept of Expected FECN packets:
	 * o packet type 0 - expected
	 * o match on F (bit 95), using select/match 1, and
	 * o match on SH (bit 133), using select/match 2.
	 *
	 * Use index 1 to extract the 8-bit receive context from DestQP
	 * (start at bit 64).  Use that as the RSM map table index.
	 */
	rrd.rr_type = RR_TYPE_EXPECTED_9B;
	rrd.offset = offset;
	rrd.pidx_mask = 1 << ppd->hw_pidx;
	rrd.field1_off = 95;
	rrd.field2_off = 133;
	rrd.index1_off = 64;
	rrd.index1_width = 8;
	rrd.index2_off = 0;
	rrd.index2_width = 0;
	rrd.mask1 = 1;
	rrd.value1 = 1;
	rrd.mask2 = 1;
	rrd.value2 = 1;

	add_rsm_rule(dd, rule_index, &rrd);

	rmt->used += total_cnt;
}

/* set a single RSM Map Table (RMT) entry in the given map */

/* update a single RSM Map Table (RMT) entry in the CSRs */
static void update_rmt_entry(struct hfi2_devdata *dd, u16 idx, u16 value)
{
	int regoff, regidx;
	u32 entries_per_csr = dd->params->rsm_map_table_entries_per_csr;
	u32 entry_mask = dd->params->rsm_map_table_entry_mask;
	u32 entry_shift = dd->params->rsm_map_table_entry_shift;
	u64 reg;

	regoff = ((unsigned int)idx % entries_per_csr) * entry_shift;
	regidx = (unsigned int)idx / entries_per_csr;
	reg = hfi2_read_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx));
	reg &= ~((u64)entry_mask << regoff);
	reg |= ((u64)(value & entry_mask) << regoff);
	hfi2_write_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx), reg);
}


static inline int hfi2_netdev_set_free_rmt_idx(struct hfi2_pportdata *ppd,
					       struct rsm_map_table *rmt)
{
	if (rmt->used + hfi2_map_entries(ppd->dd) >
	    ppd->dd->params->rsm_map_table_entries) {
		ppd_dev_err(ppd, "Not enough RMT entries, used = %d\n",
			    rmt->used);
		return -ENOSPC;
	}
	ppd->netdev_rx->rmt_start = rmt->used;
	ppd->netdev_rx->rmt_entries = hfi2_map_entries(ppd->dd);
	rmt->used += ppd->netdev_rx->rmt_entries;
	return 0;
}

/*
 * hfi2_netdev_update_rmt - populate the netdev RSM map table (RMT) block
 * @ppd: port data
 * @active_ctxts: number of netdev receive contexts to spread the ingress hash
 *		  across, starting at netdev context index 0.  Callers pass the
 *		  count of contexts actually bound to their receive queues so
 *		  frames only hash to contexts that have a consumer.  The value
 *		  is clamped to [1, hfi2_netdev_ctxt_count(ppd)] since the
 *		  reserved netdev pool may be larger than the set in use.
 *
 * The RMT block is always NUM_NETDEV_MAP_ENTRIES wide.  When @active_ctxts is
 * smaller than that width the first @active_ctxts netdev contexts repeat to
 * fill the block, so no context outside the active set ever receives traffic.
 */
static void hfi2_netdev_update_rmt(struct hfi2_pportdata *ppd, int active_ctxts)
{
	struct hfi2_devdata *dd = ppd->dd;
	int i, j;
	int ctx_id = 0;
	u8 left_shift;
	u64 reg;
	u32 regoff;
	int rmt_start = hfi2_netdev_get_free_rmt_idx(ppd);
	int ctxt_count = hfi2_netdev_ctxt_count(ppd);
	u32 entries_per_csr = ppd->dd->params->rsm_map_table_entries_per_csr;
	u32 entry_mask = ppd->dd->params->rsm_map_table_entry_mask;
	u32 entry_shift = ppd->dd->params->rsm_map_table_entry_shift;
	u32 ctxt;
	int pool_count = hfi2_netdev_ctxt_count(ppd);

	/* Wrap the hash over the active subset, bounded by the netdev pool. */
	ctxt_count = clamp(active_ctxts, 1, pool_count);

	dev_dbg(&dd->pcidev->dev, "RMT start = %d, ctxts %d\n", rmt_start,
		ctxt_count);
	/*
	 * Without netdev contexts there is nothing to map; bail before the
	 * modulo below would divide by zero.
	 */
	if (pool_count <= 0)
		return;

	dev_dbg(&dd->pcidev->dev, "RMT entries %d..%d\n", rmt_start,
		rmt_start + NUM_NETDEV_MAP_ENTRIES);

	/* Update RSM mapping table */
	regoff = dd->params->rcv_rsm_map_table_reg +
		 ((rmt_start / entries_per_csr) * 8);
	reg = hfi2_read_csr(dd, regoff);
	for (i = 0; i < NUM_NETDEV_MAP_ENTRIES; i++) {
		/* Update map register with netdev context */
		j = (rmt_start + i) % entries_per_csr;
		left_shift = j * entry_shift;
		ctxt = hfi2_netdev_get_ctxt(ppd, ctx_id++)->ctxt;
		reg &= ~((u64)entry_mask << left_shift);
		reg |= ((u64)(ctxt & entry_mask) << left_shift);
		/* Wrap up netdev ctx index */
		ctx_id %= ctxt_count;

		/* Write back map register */
		if ((j == entries_per_csr - 1) ||
		    ((i + 1) == NUM_NETDEV_MAP_ENTRIES)) {
			dev_dbg(&(dd)->pcidev->dev, "RMT[%d] = 0x%llx\n",
				(regoff - dd->params->rcv_rsm_map_table_reg) /
					entries_per_csr,
				reg);

			hfi2_write_csr(dd, regoff, reg);
			if (i < (NUM_NETDEV_MAP_ENTRIES - 1)) {
				regoff += 8;
				reg = hfi2_read_csr(dd, regoff);
			}
		}
	}
}

static void hfi2_enable_rsm_rule(struct hfi2_pportdata *ppd, int type,
				 struct rsm_rule_data *rrd)
{
	struct hfi2_devdata *dd = ppd->dd;
	int rule_index;

	if (dd->is_vf) {
		/* TODO: how does a VF get an RSM rule... can't access CSRs */
		ppd_dev_err(ppd, "VFs can't yet setup RSM rules\n");
		return;
	}
	if (hfi2_netdev_get_rmt_entries(ppd) < NUM_NETDEV_MAP_ENTRIES) {
		ppd_dev_err(ppd, "No RMT block for netdev RSM rule\n");
		return;
	}

	/* lock is for setting netdev_rsm_rule */
	mutex_lock(&hfi2_mutex);
	if (ppd->netdev_rsm_rule >= 0) {
		ppd_dev_info(ppd,
			     "Netdev contexts are already mapped in RMT\n");
		goto done;
	}

	rule_index = alloc_rsm_rule(dd, rrd->rr_type, type);
	if (rule_index < 0)
		goto done;

	hfi2_netdev_update_rmt(ppd, hfi2_netdev_ctxt_count(ppd));

	ppd->netdev_rsm_rule = rule_index;
	add_rsm_rule(dd, rule_index, rrd);
	hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_RSM_ENABLE_SMASK);

done:
	mutex_unlock(&hfi2_mutex);
}

/**
 * hfi2_netdev_set_active_ctxts - hash netdev receive traffic over @n contexts
 * @ppd: port data
 * @n: number of netdev contexts, from index 0, that receive traffic
 *
 * Return: 0, -EBUSY while more than one netdev shares the contexts, or
 * -EOPNOTSUPP if the port has no netdev RSM rule.
 */
int hfi2_netdev_set_active_ctxts(struct hfi2_pportdata *ppd, int n)
{
	int ret = 0;

	mutex_lock(&hfi2_mutex);
	if (ppd->netdev_rx->netdevs != 1)
		ret = -EBUSY;
	else if (ppd->netdev_rsm_rule < 0)
		ret = -EOPNOTSUPP;
	else
		hfi2_netdev_update_rmt(ppd, n);
	mutex_unlock(&hfi2_mutex);

	return ret;
}

void hfi2_init_aip_rsm(struct hfi2_pportdata *ppd)
{
	/*
	 * go through with the initialisation only if this rule actually doesn't
	 * exist yet
	 */
	if (atomic_fetch_inc(&ppd->ipoib_rsm_usr_num) == 0) {
		int rmt_start = hfi2_netdev_get_free_rmt_idx(ppd);
		struct rsm_rule_data rrd = {
			.rr_type = RR_TYPE_VERBS_9B,
			.offset = rmt_start,
			.pidx_mask = 1 << ppd->hw_pidx,
			.field1_off = LRH_BTH_MATCH_OFFSET,
			.mask1 = LRH_BTH_MASK,
			.value1 = LRH_BTH_VALUE,
			.field2_off = BTH_DESTQP_MATCH_OFFSET,
			.mask2 = BTH_DESTQP_MASK,
			.value2 = BTH_DESTQP_VALUE,
			.index1_off = DETH_AIP_SQPN_SELECT_OFFSET +
				      ilog2(NUM_NETDEV_MAP_ENTRIES),
			.index1_width = ilog2(NUM_NETDEV_MAP_ENTRIES),
			.index2_off = DETH_AIP_SQPN_SELECT_OFFSET,
			.index2_width = ilog2(NUM_NETDEV_MAP_ENTRIES),
			.bypass_hdr_size = 0,
		};

		hfi2_enable_rsm_rule(ppd, RSM_TYPE_AIP, &rrd);
	}
}

void hfi2_deinit_aip_rsm(struct hfi2_pportdata *ppd)
{
	/* only actually clear the rule if it's the last user asking to do so */
	if (atomic_fetch_add_unless(&ppd->ipoib_rsm_usr_num, -1, 0) == 1) {
		mutex_lock(&hfi2_mutex);
		clear_rsm_rule(ppd->dd, ppd->netdev_rsm_rule);
		ppd->netdev_rsm_rule = -1;
		mutex_unlock(&hfi2_mutex);
	}
}

#define ETH_TYPE_HI_MATCH_OFFSET ((3ull << QW_SHIFT) | 32ull)
#define ETH_TYPE_LO_MATCH_OFFSET ((3ull << QW_SHIFT) | 40ull)
#define ETH_TYPE_MASK 0xFFull
#define ETH_TYPE_HI_VLAN_VALUE 0x81ull		/* ETH_P_8021Q >> 8 */
#define ETH_TYPE_LO_VLAN_VALUE 0x00ull		/* ETH_P_8021Q & 0xff */
#define ETH_TYPE_HI_IPV6_VALUE 0x86ull		/* ETH_P_IPV6 >> 8 */
#define ETH_TYPE_LO_IPV6_VALUE 0xDDull		/* ETH_P_IPV6 & 0xff */
/* Ethernet bytes 16 and 17, the EtherType inside an 802.1Q tag - for match */
#define ETH_VLAN_TYPE_HI_MATCH_OFFSET ((4ull << QW_SHIFT) | 0ull)
#define ETH_VLAN_TYPE_LO_MATCH_OFFSET ((4ull << QW_SHIFT) | 8ull)
/* sport[5:1] and dport[5:1] - for select */
#define ETH_SPORT_SELECT_OFFSET ((6ull << QW_SHIFT) | 25ull)
#define ETH_DPORT_SELECT_OFFSET ((6ull << QW_SHIFT) | 41ull)
#define ETH_VLAN_SPORT_SELECT_OFFSET ((6ull << QW_SHIFT) | 57ull)
#define ETH_VLAN_DPORT_SELECT_OFFSET ((7ull << QW_SHIFT) | 9ull)
#define ETH_IPV6_SPORT_SELECT_OFFSET ((8ull << QW_SHIFT) | 57ull)
#define ETH_IPV6_DPORT_SELECT_OFFSET ((9ull << QW_SHIFT) | 9ull)
#define ETH_VLAN_IPV6_SPORT_SELECT_OFFSET ((9ull << QW_SHIFT) | 25ull)
#define ETH_VLAN_IPV6_DPORT_SELECT_OFFSET ((9ull << QW_SHIFT) | 41ull)


/* RSM L2_TYPE: QW 0, OFFSET 61 - for match */
#define L2_TYPE_QW 0ull
#define L2_TYPE_BIT_OFFSET 61ull
#define L2_TYPE_OFFSET(off) ((L2_TYPE_QW << QW_SHIFT) | (off))
#define L2_TYPE_MATCH_OFFSET L2_TYPE_OFFSET(L2_TYPE_BIT_OFFSET)
#define L2_TYPE_MASK 3ull
#define L2_16B_VALUE 2ull

static void hfi2_eth_update_rmt(struct hfi2_pportdata *ppd,
				int rmt_start,
				const u16 *ctxts,
				int num_ctxts)
{
	struct hfi2_devdata *dd = ppd->dd;
	int i;
	int ctx_id = 0;
	u8 left_shift;
	u64 reg;
	u32 regoff;
	u32 entries_per_csr = dd->params->rsm_map_table_entries_per_csr;
	u32 entry_mask = dd->params->rsm_map_table_entry_mask;
	u32 entry_shift = dd->params->rsm_map_table_entry_shift;

	regoff = dd->params->rcv_rsm_map_table_reg +
		((rmt_start / entries_per_csr) * 8);
	reg = hfi2_read_csr(dd, regoff);

	/* Fill the whole reserved block: the rule indexes HFI2_ETH_MAP_ENTRIES */
	for (i = 0; i < HFI2_ETH_MAP_ENTRIES; i++) {
		int j = (rmt_start + i) % entries_per_csr;
		u32 ctxt = ctxts[ctx_id++];

		left_shift = j * entry_shift;
		reg &= ~((u64)entry_mask << left_shift);
		reg |= ((u64)(ctxt & entry_mask) << left_shift);
		ctx_id %= num_ctxts; /* Repeat a short @ctxts across the block. */

		if ((j == entries_per_csr - 1) || ((i + 1) == HFI2_ETH_MAP_ENTRIES)) {
			hfi2_write_csr(dd, regoff, reg);
			if (i < (HFI2_ETH_MAP_ENTRIES - 1)) {
				regoff += 8;
				reg = hfi2_read_csr(dd, regoff);
			}
		}
	}
}

/*
 * hfi2_init_eth_rsm - install the CN Ethernet ingress RSM rules
 * @ppd: port data
 * @ctxts: hardware context number for each RMT entry; every entry must name
 *	   a context bound to a Linux RX queue
 * @num_ctxts: number of entries in @ctxts, 1..HFI2_ETH_MAP_ENTRIES
 *
 * If the rules are already installed, only the RMT block is rewritten.
 */
int hfi2_init_eth_rsm(struct hfi2_pportdata *ppd,
		      const u16 *ctxts,
		      int num_ctxts)
{
	int idx[5];
	int i, first, ret = 0;
	struct hfi2_devdata *dd = ppd->dd;
	int rmt_start = hfi2_netdev_get_free_rmt_idx(ppd);
	/*
	 * Five rules share one RMT block, listed in RSM priority order (the
	 * lowest-numbered matching rule wins).  All match the 16B L4 ETH type:
	 *  [0] EtherType 0x86DD: untagged IPv6 port offsets
	 *  [1] EtherType 0x8100 holding 0x86DD: 802.1Q IPv6 port offsets
	 *  [2] EtherType high byte != 0x81: untagged port offsets
	 *  [3] EtherType low byte == 0x00, i.e. exactly 0x8100: 802.1Q offsets
	 *  [4] any other 16B ETH frame (0x81xx but not 0x8100): untagged
	 * The IPv6 rules AND in the chained rules chain[i][] for the EtherType
	 * bytes their own two match fields have no room for.
	 */
	struct rsm_rule_data rrd[ARRAY_SIZE(idx)];
	struct rsm_rule_data chain[ARRAY_SIZE(idx)][2] = {
		[0] = {
			{	/* EtherType low byte 0xDD */
				.rr_type = RR_CHAIN_BYPASS,
				.pidx_mask = 1 << ppd->hw_pidx,
				.field1_off = ETH_TYPE_LO_MATCH_OFFSET,
				.mask1 = ETH_TYPE_MASK,
				.value1 = ETH_TYPE_LO_IPV6_VALUE,
			},
		},
		[1] = {
			{	/* low byte 0x00, inner high byte 0x86 */
				.rr_type = RR_CHAIN_BYPASS,
				.pidx_mask = 1 << ppd->hw_pidx,
				.field1_off = ETH_TYPE_LO_MATCH_OFFSET,
				.mask1 = ETH_TYPE_MASK,
				.value1 = ETH_TYPE_LO_VLAN_VALUE,
				.field2_off = ETH_VLAN_TYPE_HI_MATCH_OFFSET,
				.mask2 = ETH_TYPE_MASK,
				.value2 = ETH_TYPE_HI_IPV6_VALUE,
			},
			{	/* inner low byte 0xDD */
				.rr_type = RR_CHAIN_BYPASS,
				.pidx_mask = 1 << ppd->hw_pidx,
				.field1_off = ETH_VLAN_TYPE_LO_MATCH_OFFSET,
				.mask1 = ETH_TYPE_MASK,
				.value1 = ETH_TYPE_LO_IPV6_VALUE,
			},
		},
	};
	struct rsm_rule_data untagged = {
		.rr_type = RR_TYPE_BYPASS,
		.offset = rmt_start,
		.pidx_mask = 1 << ppd->hw_pidx,
		.field1_off = L2_TYPE_MATCH_OFFSET,
		.mask1 = L2_TYPE_MASK,
		.value1 = L2_16B_VALUE,
		.field2_off = L4_TYPE_MATCH_OFFSET,
		.mask2 = L4_16B_TYPE_MASK,
		.value2 = L4_16B_ETH_VALUE,
		.index1_off = ETH_SPORT_SELECT_OFFSET,
		.index1_width = ilog2(HFI2_ETH_MAP_ENTRIES),
		.index2_off = ETH_DPORT_SELECT_OFFSET,
		.index2_width = ilog2(HFI2_ETH_MAP_ENTRIES),
		.bypass_hdr_size = 4,
	};

	BUILD_BUG_ON(ARRAY_SIZE(idx) != ARRAY_SIZE(ppd->eth_rsm_pre_rules) + 1);
	/* RSM matches and indexes only the first 1024 bits of a packet */
	BUILD_BUG_ON(ETH_VLAN_IPV6_DPORT_SELECT_OFFSET +
		     ilog2(HFI2_ETH_MAP_ENTRIES) > 1024);

	rrd[4] = untagged;
	rrd[2] = untagged;
	rrd[2].field1_off = L4_TYPE_MATCH_OFFSET;
	rrd[2].mask1 = L4_16B_TYPE_MASK;
	rrd[2].value1 = L4_16B_ETH_VALUE;
	rrd[2].field2_off = ETH_TYPE_HI_MATCH_OFFSET;
	rrd[2].mask2 = ETH_TYPE_MASK;
	rrd[2].value2 = ETH_TYPE_HI_VLAN_VALUE;
	rrd[2].invert2 = 1;
	rrd[0] = rrd[2];
	rrd[0].value2 = ETH_TYPE_HI_IPV6_VALUE;
	rrd[0].invert2 = 0;
	rrd[0].index1_off = ETH_IPV6_SPORT_SELECT_OFFSET;
	rrd[0].index2_off = ETH_IPV6_DPORT_SELECT_OFFSET;
	rrd[0].nchain = 1;
	rrd[1] = rrd[2];
	rrd[1].invert2 = 0;
	rrd[1].index1_off = ETH_VLAN_IPV6_SPORT_SELECT_OFFSET;
	rrd[1].index2_off = ETH_VLAN_IPV6_DPORT_SELECT_OFFSET;
	rrd[1].nchain = 2;
	rrd[3] = rrd[2];
	rrd[3].field2_off = ETH_TYPE_LO_MATCH_OFFSET;
	rrd[3].value2 = ETH_TYPE_LO_VLAN_VALUE;
	rrd[3].invert2 = 0;
	rrd[3].index1_off = ETH_VLAN_SPORT_SELECT_OFFSET;
	rrd[3].index2_off = ETH_VLAN_DPORT_SELECT_OFFSET;

	if (dd->is_vf) {
		ppd_dev_err(ppd, "VFs can't yet setup RSM rules\n");
		return -EOPNOTSUPP;
	}

	/* The block reserved at init must hold all the entries written below. */
	if (rmt_start < 0 ||
	    hfi2_netdev_get_rmt_entries(ppd) < HFI2_ETH_MAP_ENTRIES ||
	    rmt_start + HFI2_ETH_MAP_ENTRIES > dd->params->rsm_map_table_entries) {
		ppd_dev_err(ppd, "No RMT block for CN Ethernet RSM rule\n");
		return -ENODEV;
	}

	if (num_ctxts <= 0 || num_ctxts > HFI2_ETH_MAP_ENTRIES) {
		ppd_dev_err(ppd, "Invalid CN Ethernet RSM context count %d\n",
			    num_ctxts);
		return -EINVAL;
	}

	/*
	 * Serialize install/teardown under hfi2_mutex.  The per-port
	 * eth_rsm_rule sentinel is the authoritative state: >= 0 means the
	 * rules are live (eth_rsm_pre_rules[] are set with it), -1 means not.
	 * There is exactly one CN Ethernet netdev per port and its
	 * enable/disable path (netdev open/stop, serialized by the netdev
	 * core) drives this once, so gating on the sentinel makes install
	 * idempotent without a separate user count.
	 */
	mutex_lock(&hfi2_mutex);

	/*
	 * Rules already installed by an earlier caller; still apply the
	 * caller's map so a new RSS table is never silently dropped.
	 */
	if (ppd->eth_rsm_rule >= 0) {
		hfi2_eth_update_rmt(ppd, rmt_start, ctxts, num_ctxts);
		goto done;
	}

	/*
	 * The bulksvc rule also matches the 16B L4 ETH type and must see
	 * RoCEv2 frames first, so take only slots after it.  Each rule is
	 * placed after the previous one and its chain, keeping the priority
	 * above.  The chained IPv6 rules are optional: without one, its
	 * frames go to the IPv4 rules as they did before, so a
	 * missing slot costs only IPv6 spreading.
	 */
	first = dd->bulksvc_rsm_rule + 1;
	for (i = 0; i < ARRAY_SIZE(idx); i++) {
		if (!rrd[i].nchain) {
			idx[i] = alloc_rsm_rule_from(dd, RR_TYPE_BYPASS,
						     RSM_TYPE_ETHERNET, first);
		} else if (rrd[i].nchain <= ARRAY_SIZE(chain[i])) {
			idx[i] = alloc_rsm_bypass_chain_from(dd, rrd[i].nchain,
							     RSM_TYPE_ETHERNET,
							     first);
		} else {
			WARN_ON_ONCE(1);
			idx[i] = -EINVAL;
		}
		if (idx[i] < 0 && rrd[i].nchain) {
			ppd_dev_warn(ppd, "No room for %d-slot IPv6 RSM rule %d, its flows will not be spread\n",
				     rrd[i].nchain + 1, i);
			idx[i] = -1;
			continue;
		}
		if (idx[i] < 0) {
			while (i--)
				clear_rsm_rule(dd, idx[i]);
			ppd_dev_warn(ppd, "No RSM rule available\n");
			ret = -ENOSPC;
			goto done;
		}
		first = idx[i] + rrd[i].nchain + 1;
	}

	hfi2_eth_update_rmt(ppd, rmt_start, ctxts, num_ctxts);
	for (i = 0; i < ARRAY_SIZE(idx); i++) {
		if (idx[i] < 0)
			continue;
		if (!rrd[i].nchain) {
			add_rsm_rule(dd, idx[i], &rrd[i]);
		} else if (add_rsm_bypass_chain(dd, idx[i], &rrd[i], chain[i])) {
			clear_rsm_rule(dd, idx[i]);
			idx[i] = -1;
		}
	}
	for (i = 0; i < ARRAY_SIZE(ppd->eth_rsm_pre_rules); i++)
		ppd->eth_rsm_pre_rules[i] = idx[i];
	ppd->eth_rsm_rule = idx[i];
	hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_RSM_ENABLE_SMASK);

done:
	mutex_unlock(&hfi2_mutex);
	return ret;
}

void hfi2_deinit_eth_rsm(struct hfi2_pportdata *ppd)
{
	int i;

	mutex_lock(&hfi2_mutex);
	/* Clear the rule only when one is installed; -1 means already gone. */
	if (ppd->eth_rsm_rule >= 0) {
		clear_rsm_rule(ppd->dd, ppd->eth_rsm_rule);
		ppd->eth_rsm_rule = -1;
	}
	for (i = 0; i < ARRAY_SIZE(ppd->eth_rsm_pre_rules); i++) {
		if (ppd->eth_rsm_pre_rules[i] >= 0) {
			clear_rsm_rule(ppd->dd, ppd->eth_rsm_pre_rules[i]);
			ppd->eth_rsm_pre_rules[i] = -1;
		}
	}
	mutex_unlock(&hfi2_mutex);
}

/**
 * hfi2_eth_set_rmt_map - reprogram the CN Ethernet RMT block in place
 * @ppd: port data
 * @ctxts: hardware context numbers, one per RMT entry
 * @num_ctxts: number of entries in @ctxts, 1..HFI2_ETH_MAP_ENTRIES
 *
 * Rewrite the RMT block owned by the installed Ethernet RSM rules.  Nothing
 * is written when the rules are not installed; the next hfi2_init_eth_rsm()
 * programs the block instead.
 */
void hfi2_eth_set_rmt_map(struct hfi2_pportdata *ppd, const u16 *ctxts,
			  int num_ctxts)
{
	if (WARN_ON(num_ctxts <= 0 || num_ctxts > HFI2_ETH_MAP_ENTRIES))
		return;

	mutex_lock(&hfi2_mutex);
	if (ppd->eth_rsm_rule >= 0)
		hfi2_eth_update_rmt(ppd, hfi2_netdev_get_free_rmt_idx(ppd),
				    ctxts, num_ctxts);
	mutex_unlock(&hfi2_mutex);
}

/*
 * RSM match rules for ports.
 *
 * RSM match bits are numbered little-endian by QWORD.  Take this into account
 * when deciding bit offsets.
 */
static const struct rsm_rule_data mad_response_rules[] = {
	/* 9B Response MAD packets */
	{
		.rr_type = RR_TYPE_VERBS_9B,
		.offset = 0, /* filled in */
		.pidx_mask = 0, /* filled in */
		.field1_off = 60, /* LRH.VL offset */
		.mask1 = 0x0f, /*   4 bits */
		.value1 = 0x0f, /*  match LRH.VL=15 */
		.field2_off = 199, /* MAD.R offset */
		.mask2 = 0x01, /*   1 bit */
		.value2 = 0x01, /*   match MAD.R=1 */
		/* these are for SRIOV but should be no-op for non-SRIOV */
		.index1_off = 32, /* LRH.DLID[2:0] */
		.index1_width = 3,
		.index2_off = 212, /* MAD.MGMT_CLASS[7:4] - DR/LR */
		.index2_width = 4,
		.bypass_hdr_size = 0,
	},
	/* 9B TRAP MAD packets */
	{
		.rr_type = RR_TYPE_VERBS_9B,
		.offset = 0, /* filled in */
		.pidx_mask = 0, /* filled in */
		.field1_off = 60, /* LRH.VL offset */
		.mask1 = 0x0f, /*   4 bits */
		.value1 = 0x0f, /*   match LRH.VL=15 */
		.field2_off = 192, /* MAD.Method offset */
		.mask2 = 0x7f, /*   7 bits */
		.value2 = 0x05, /*   match MAD.Method=TRAP */
		.index1_off = 0, /* do not index off of offset */
		.index1_width = 0,
		.index2_off = 0,
		.index2_width = 0,
		.bypass_hdr_size = 0,
	},
};

static const struct rsm_rule_data mad_action_rules[] = {
	{
		.rr_type = RR_TYPE_BYPASS,
		.offset = 0, /* filled in */
		.pidx_mask = 0, /* filled in */
		.field1_off = 52, /* 16B.SC offset */
		.mask1 = 0x1f, /*   5 bits */
		.value1 = 0x0f, /*   match 16B.SC=15 */
		.field2_off = 223, /* MAD.R offset */
		.mask2 = 0x01, /*   1 bit */
		.value2 = 0x00, /*   match MAD.R=0 */
		.index1_off = 0, /* do not index off of offset */
		.index1_width = 0,
		.index2_off = 0,
		.index2_width = 0,
		.bypass_hdr_size = 0,
	},
};

/*
 * 16B (bypass) Packets (STL Mgmt L4 Header version, aka L4_FM)
 * --------------------
 * A 16B L4_FM type MAD packet starts with headers
 *     16B LRH (16 bytes)
 *     Mgmt L4 (8 bytes)
 *     MAD
 *
 * Match vl15 in 16B.SC (5 bits)
 * 16B.SC is bits 56:52 in the first QWORD.
 *     offset = 52		bit offset
 *     mask   = 0x1f		bits to check
 *     value  = 0x0f		value to compare
 *
 * Match MAD.R (1 bit)
 * MAD.R is the 4th byte on the wire of the MAD header, bit 7.
 *     Preceding headers:      24 bytes  = 192 bits
 *     Preceding bytes of MAD:  3 bytes  =  24 bits
 *     Bit 7:                            =   7 bits
 *     Total: 192 + 24 + 7 = 223
 *
 *     offset = 223		bit offset
 *     mask   = 0x01		bits to check
 *     value  = 0x00		value to compare
 */


/*
 * Set up a rule for all entries in mmr_tbl to go to the target context.
 */
static int do_port_mapping(struct hfi2_pportdata *ppd,
			   struct rsm_map_table *rmt, int num_rmt,
			   const struct rsm_rule_data *rrd_tbl, int rrd_len,
			   int target_ctxt, int rule_type)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct rsm_rule_data rrd;
	int rmt_index;
	int rule_index;
	int row;

	if (!port_available_ppd(ppd))
		return 0;

	/* check for room in RMT */
	if (rmt->used + num_rmt > dd->params->rsm_map_table_entries) {
		ppd_dev_err(ppd, "%s: out of RMT entries\n", __func__);
		return -ENOSPC;
	}
	/* allocate the RMT index */
	rmt_index = rmt->used;
	rmt->used += num_rmt;

	/* update the RSM Map Table entries with the target context */
	for (row = 0; row < num_rmt; ++row)
		set_rmt_entry(dd, rmt, rmt_index + row, target_ctxt);

	/* assign the rules */
	for (row = 0; row < rrd_len; row++) {
		/* copy to a writable structure */
		rrd = rrd_tbl[row];

		/* fill in variable fields */
		rrd.offset = rmt_index; /* lookup dest here... */
		rrd.pidx_mask = 1 << ppd->hw_pidx; /* ...on this port */

		/* allocate a rule index */
		rule_index = alloc_rsm_rule(dd, rrd.rr_type, rule_type);
		if (rule_index < 0)
			return rule_index; /* this is a -ERRNO */

		/* set the rule registers */
		add_rsm_rule(dd, rule_index, &rrd);
	}

	return rmt_index;
}

/*
 * Adjust RcvIportCtrl.RcvWcb, the write coalescing boundary for RX_DMA.
 *
 * Use the module parameter as a starting point.  Tune this setting to the
 * largest size <= PCIe Max Payload Size (MPS).  It is invalid to have
 * RcvWcb > MPS.
 *
 * It is expected that PCIe MPS is not adjusted after this function is called,
 * both internally and externally.
 */
void hfi2_adjust_wcb(struct hfi2_devdata *dd)
{
	int mps = pcie_get_mps(dd->pcidev);
	int local_wcb = rcvwcb;
	int top;
	int def;
	int pidx;

	/* WFR has a different default and range */
	if (dd->params->chip_type == CHIP_WFR) {
		def = 0;
		top = 2;
	} else {
		def = 3;
		top = 3;
	}

	/* force this instance of rcvwcb in the range 0..top, inclusive */
	if (local_wcb < 0 || local_wcb > top)
		local_wcb = def;
	/* reduce local_wcb until it is <= MPS */
	while (local_wcb != 0) {
		int sz = 64 << local_wcb; /* convert to a size */

		if (sz <= mps)
			break;
		local_wcb--;
	}

	/* wcb is required to be the same on all ports */
	for (pidx = 0; pidx < dd->num_pports; pidx++)
		hfi2_set_wcb(&dd->pport[pidx], local_wcb);
}

/*
 * Add port-specific mappings to the RSM Map Table.
 */
static int init_port_mapping(struct hfi2_pportdata *ppd,
			     struct rsm_map_table *rmt)
{
	struct hfi2_portrsrcs *pr = &ppd->dd->rsrcs.ppr[ppd->hw_pidx];
	int ret;

	/* no port mapping for WFR */
	if (ppd->dd->params->chip_type == CHIP_WFR)
		return 0;

	ret = do_port_mapping(ppd, rmt, 16, mad_response_rules,
			      ARRAY_SIZE(mad_response_rules),
			      pr->rcv_context_base + HFI2_CTRL_CTXT,
			      RSM_TYPE_MAD_RSP);
	if (ret < 0)
		return ret;
	ppd->rmt_index = ret;

	/*
	 * Redirect MAD actions to the cport.  Cport owns the same receive
	 * context as the port index.
	 */
	ret = do_port_mapping(ppd, rmt, 1, mad_action_rules,
			      ARRAY_SIZE(mad_action_rules), ppd->hw_pidx,
			      RSM_TYPE_MAD_ACTION);
	if (ret < 0)
		return ret;
	return 0;
}

/*
 * This might be called on behalf of a VF to setup RSM rules and any
 * associated RMT entries. This means it is no longer called only once
 * at driver load.
 *
 * 'dr' is NULL when called for PF0 init.
 */
int hfi2_init_rxe_rsm(struct hfi2_devdata *dd, struct hfi2_devrsrcs *dr)
{
	struct hfi2_pportdata *ppd;
	struct rsm_map_table *rmt;
	int i;
	int ret;

	if (dr) {
		/* working on behalf of VF */
		struct hfi2_portrsrcs *pr;
		u16 rc0, rcn;

		for (i = 0; i < dd->num_pports; ++i) {
			pr = &dr->ppr[i];
			ppd = &dd->pport[i];
			if (!port_available_ppd(ppd))
				continue;
			if (ppd->qos_shift != 1) {
				ppd_dev_err(ppd,
					    "QOS not supported for SRIOV\n");
				return -EINVAL;
			}
			/* map our QPNs to port's kernel contexts (excl. HFI2_CTRL_CTXT) */
			rc0 = dr->ppr[i].rcv_context_base + FIRST_KERNEL_KCTXT;
			rcn = rc0 + dr->ppr[i].n_krcv_queues -
			      FIRST_KERNEL_KCTXT - 1;
			init_qpmap_table_range(ppd,
				dr->c.first_rcv_context, /* our QPN range */
				dr->c.last_rcv_context, rc0, rcn);

			/* map VF control context in RMT */
			update_rmt_entry(dd, ppd->rmt_index + dr->si_idx,
					 pr->rcv_context_base + HFI2_CTRL_CTXT);
		}
		/* Additional RSM/RMT may be needed */
		return 0;
	}
	rmt = alloc_rsm_map_table(dd);
	if (!rmt)
		return -ENOMEM;

	/* set up QOS, including the QPN map table */
	init_qos(dd, rmt);
	for (i = 0; i < dd->num_pports; i++) {
		ppd = &dd->pport[i];
		if (!port_available_ppd(ppd))
			continue;
		ret = init_port_mapping(ppd, rmt);
		if (ret)
			goto done;
		init_fecn_handling(ppd, rmt);
	}
	bulksvc_rsm_reserve(dd, rmt);
	complete_rsm_map_table(dd, rmt);
	/* reserve RMT entries for netdev */
	for (i = 0; i < dd->num_pports; i++) {
		ppd = &dd->pport[i];
		if (!port_available_ppd(ppd))
			continue;
		ret = hfi2_netdev_set_free_rmt_idx(ppd, rmt);
		if (ret < 0)
			goto done;
	}
	ret = 0;
done:
	kfree(rmt);
	return ret;
}

/*
 * Adjust RcvIportCtrl.RcvWcb, the write coalescing boundary for RX_DMA.
 *
 * Use the module parameter as a starting point.  Tune this setting to the
 * largest size <= PCIe Max Payload Size (MPS).  It is invalid to have
 * RcvWcb > MPS.
 *
 * It is expected that PCIe MPS is not adjusted after this function is called,
 * both internally and externally.
 */



void hfi2_init_other(struct hfi2_devdata *dd)
{
	/* enable all CCE errors */
	hfi2_write_csr(dd, CCE_ERR_MASK, ~0ull);
	/* enable *some* Misc errors */
	hfi2_write_csr(dd, MISC_ERR_MASK, DRIVER_MISC_MASK);
	/* enable all DC errors, except LCB */
	hfi2_write_csr(dd, DCC_ERR_FLG_EN, ~0ull);
	hfi2_write_csr(dd, DC_DC8051_ERR_EN, ~0ull);
}

/*
 * Fill out the given AU table using the given CU.  A CU is defined in terms
 * AUs.  The table is a an encoding: given the index, how many AUs does that
 * represent?
 *
 * NOTE: Assumes that the register layout is the same for the
 * local and remote tables.
 */

#define HFI_BASE_GUID(dev) ((dev)->base_guid & ~(1ULL << GUID_HFI_INDEX_SHIFT))

/*
 * Information can be shared between the two HFIs on the same ASIC
 * in the same OS.  This function finds the peer device and sets
 * up a shared structure.
 */
static int init_asic_data(struct hfi2_devdata *dd)
{
	unsigned long index;
	struct hfi2_devdata *peer;
	struct hfi2_asic_data *asic_data;
	int ret = 0;

	/* pre-allocate the asic structure in case we are the first device */
	asic_data = kzalloc_obj(*dd->asic_data, GFP_KERNEL);
	if (!asic_data)
		return -ENOMEM;

	xa_lock_irq(&hfi2_dev_table);
	/* Find our peer device */
	xa_for_each(&hfi2_dev_table, index, peer) {
		if ((HFI_BASE_GUID(dd) == HFI_BASE_GUID(peer)) &&
		    dd->unit != peer->unit)
			break;
	}

	if (peer) {
		/* use already allocated structure */
		dd->asic_data = peer->asic_data;
		kfree(asic_data);
	} else {
		dd->asic_data = asic_data;
		mutex_init(&dd->asic_data->asic_resource_mutex);
	}
	dd->asic_data->dds[dd->hfi2_id] = dd; /* self back-pointer */
	xa_unlock_irq(&hfi2_dev_table);

	/* first one through - set up i2c devices */
	if (!peer)
		ret = hfi2_set_up_i2c(dd, dd->asic_data);

	return ret;
}

/*
 * Set dd->boardname.  Use a generic name if a name is not returned from
 * EFI variable space.
 *
 * Return 0 on success, -ENOMEM if space could not be allocated.
 */
static int obtain_boardname(struct hfi2_devdata *dd)
{
	unsigned long size;
	int ret;

	ret = hfi2_read_hfi2_efi_var(dd, "description", &size,
				     (void **)&dd->boardname);
	if (ret) {
		dd_dev_info(dd, "Board description not found\n");
		/* use generic description */
		dd->boardname =
			kstrdup(dd->params->generic_boardname, GFP_KERNEL);
		if (!dd->boardname)
			return -ENOMEM;
	}
	return 0;
}

/*
 * Check the interrupt registers to make sure that they are mapped correctly.
 * It is intended to help user identify any mismapping by VMM when the driver
 * is running in a VM. This function should only be called before interrupt
 * is set up properly.
 *
 * Return 0 on success, -EINVAL on failure.
 */
static int check_int_registers(struct hfi2_devdata *dd)
{
	u64 reg;
	u64 all_bits = ~(u64)0;
	u64 mask;
	u32 cce_int_mask_reg = dd->params->cce_int_mask_reg;
	u32 cce_int_clear_reg = dd->params->cce_int_clear_reg;
	u32 cce_int_status_reg = dd->params->cce_int_status_reg;

	/* Clear CceIntMask[0] to avoid raising any interrupts */
	mask = hfi2_read_csr(dd, cce_int_mask_reg);
	hfi2_write_csr(dd, cce_int_mask_reg, 0ull);
	reg = hfi2_read_csr(dd, cce_int_mask_reg);
	if (reg)
		goto err_exit;

	/* Clear all interrupt status bits */
	hfi2_write_csr(dd, cce_int_clear_reg, all_bits);
	reg = hfi2_read_csr(dd, cce_int_status_reg);
	if (reg)
		goto err_exit;

	/* Set all interrupt status bits */
	hfi2_write_csr(dd, dd->params->cce_int_force_reg, all_bits);
	reg = hfi2_read_csr(dd, cce_int_status_reg);
	if (reg != all_bits)
		goto err_exit;

	/* Restore the interrupt mask */
	hfi2_write_csr(dd, cce_int_clear_reg, all_bits);
	hfi2_write_csr(dd, cce_int_mask_reg, mask);

	return 0;
err_exit:
	hfi2_write_csr(dd, cce_int_mask_reg, mask);
	dd_dev_err(dd, "Interrupt registers not properly mapped by VMM\n");
	return -EINVAL;
}

int hfi2_wfr_find_used_resources(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i;

	dr->pfunit = dd->unit;
	dd->first_rsm_rule = 0;
	for (i = 0; i < dd->params->rsm_rule_size; i++)
		dd->rr_info[i] = RR_EMPTY;

	/* set resource allocation start values */
	dr->c.first_rcvarray_entry = 0;
	dr->c.last_rcvarray_entry = chip_rcv_array_count(dd);
	dr->c.first_pio_block = 1; /* do not use block 0, HAS entry 291585 */
	dr->c.last_pio_block = chip_pio_mem_size(dd) / PIO_BLOCK_SIZE;
	dr->c.first_rcv_context = 0;
	dr->c.last_rcv_context = chip_rcv_contexts(dd);
	dr->c.first_send_context = 0;
	dr->c.last_send_context = chip_send_contexts(dd);
	dd->rsm_rule_init = true;

	return 0;
}

/* early WFR specific chip init */
int hfi2_wfr_early_per_chip_init(struct hfi2_devdata *dd)
{
	int ret;

	/* set up shared ASIC data with peer device */
	ret = init_asic_data(dd);
	if (ret)
		return ret;

	/* obtain chip sizes, reset chip CSRs */
	ret = init_chip(dd);
	if (ret)
		return ret;

	/* read in the PCIe link speed information */
	ret = hfi2_pcie_speeds(dd);
	if (ret)
		return ret;

	/* call before hfi2_get_platform_config(), after hfi2_init_chip_resources() */
	ret = hfi2_eprom_init(dd);
	if (ret)
		return ret;

	/* Needs to be called before hfi2_firmware_init */
	hfi2_get_platform_config(&dd->pport[HFI2_PORT_IDX]);

	/* read in firmware */
	ret = hfi2_firmware_init(dd);
	if (ret)
		return ret;

	/*
	 * In general, the PCIe Gen3 transition must occur after the
	 * chip has been idled (so it won't initiate any PCIe transactions
	 * e.g. an interrupt) and before the driver changes any registers
	 * (the transition will reset the registers).
	 *
	 * In particular, place this call after:
	 * - init_chip()     - the chip will not initiate any PCIe transactions
	 * - hfi2_pcie_speeds()   - reads the current link speed
	 * - hfi2_firmware_init() - the needed firmware is ready to be
	 *			    downloaded
	 */
	ret = hfi2_do_pcie_gen3_transition(dd);
	if (ret)
		return ret;

	/*
	 * This should probably occur in hfi2_pcie_init(), but historically
	 * occurs after the hfi2_do_pcie_gen3_transition() code.
	 */
	hfi2_tune_pcie_caps(dd);

	/* start setting dd values and adjusting CSRs */
	hfi2_init_early_variables(dd);

	write_uninitialized_csrs_and_memories(dd);

	hfi2_parse_platform_config(&dd->pport[HFI2_PORT_IDX]);

	return 0;
}

int hfi2_wfr_mid_per_chip_init(struct hfi2_devdata *dd)
{
	return 0;
}

int hfi2_wfr_late_per_chip_init(struct hfi2_devdata *dd)
{
	/* set up LCB access - must be after set_up_interrupts() */
	hfi2_init_lcb_access(dd);

	return hfi2_load_firmware(
		dd); /* asymmetric with hfi2_dispose_firmware() */
}
/**
 * hfi2_init_dd() - Initialize most of the dd structure.
 * @dd: the dd device
 *
 * This is global, and is called directly at init to set up the
 * chip-specific function pointers for later use.
 */
int hfi2_init_dd(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct pci_dev *pdev = dd->pcidev;
	struct hfi2_pportdata *ppd;
	u64 reg;
	int i, ret;
	static const char *const inames[] = {
		/* implementation names */
		"RTL silicon", "RTL VCS simulation", "RTL FPGA emulation",
		"Functional simulator"
	};
	struct pci_dev *parent = pdev->bus->self;

	/*
	 * Do remaining PCIe setup.  Error messaging is done by the callee.
	 * On return, the BAR is mapped and register access is enabled.
	 */
	ret = hfi2_pcie_ddinit(dd, pdev);
	if (ret < 0)
		goto bail;

	ret = vf2pf_early_init(dd);
	if (ret)
		goto bail_cleanup;

	/* do this at earliest opportunity - CSRs accessible */
	dd->rctxt_mask = (1 << fls(chip_rcv_contexts(dd))) - 1;
	dd->sctxt_mask = (1 << fls(chip_send_contexts(dd))) - 1;

	if (dd->is_vf) {
		ret = vf2pf_init(dd);
		if (ret)
			goto bail_cleanup;
	}
	ret = hfi2_sriov_set_cfg(dd);
	if (ret)
		goto bail_cleanup;

	if (hfi2_num_vls < HFI2_MIN_VLS_SUPPORTED ||
	    hfi2_num_vls > HFI2_MAX_VLS_SUPPORTED) {
		dd_dev_err(dd, "Invalid hfi2_num_vls %u, using %u VLs\n",
			   hfi2_num_vls, HFI2_MAX_VLS_SUPPORTED);
		hfi2_num_vls = HFI2_MAX_VLS_SUPPORTED;
	}

	/*
	 * Decide on number of SDMA engines to use based on hardware
	 * availability, number of VLs, and module parameter.
	 */
	if (HFI2_CAP_IS_KSET(SDMA)) {
		u32 sdma_engines = chip_sdma_engines(dd);

		dd->num_sdma = sdma_engines;
		if (hfi2_num_vls > sdma_engines) {
			dd_dev_err(dd, "hfi2_num_vls %u too large, using %u VLs\n",
				   hfi2_num_vls, sdma_engines);
			hfi2_num_vls = sdma_engines;
		}
		if (dr->num_vfs) {
			int num_sde = dr->last_sdma_engine - dr->first_sdma_engine;

			if (hfi2_num_vls > num_sde) {
				dd_dev_err(dd,
					   "SI%d: hfi2_num_vls %u too large, using %u VLs\n",
					   dr->si_idx, hfi2_num_vls, num_sde);
				hfi2_num_vls = num_sde;
			}
		} else {
			dr->first_sdma_engine = 0;
			dr->last_sdma_engine = dd->num_sdma;
		}
	} else {
		HFI2_CAP_CLEAR(SDMA_AHG);
		dd->num_sdma = 0;
	}

	ppd = dd->pport;
	for (i = 0; i < dd->num_pports; i++, ppd++) {
		int vl;
		/* init common fields */
		hfi2_init_pportdata(pdev, ppd, dd, i, i + 1);
		/* DC supports 4 link widths */
		ppd->link_width_supported =
			OPA_LINK_WIDTH_1X | OPA_LINK_WIDTH_2X |
			OPA_LINK_WIDTH_3X | OPA_LINK_WIDTH_4X;
		ppd->link_width_downgrade_supported = ppd->link_width_supported;
		/* start out enabling only 4X */
		ppd->link_width_enabled = OPA_LINK_WIDTH_4X;
		ppd->link_width_downgrade_enabled =
			ppd->link_width_downgrade_supported;
		/* link width active is 0 when link is down */
		/* link width downgrade active is 0 when link is down */

		ppd->vls_supported = hfi2_num_vls;
		ppd->vls_operational = ppd->vls_supported;
		/* Set the default MTU. */
		for (vl = 0; vl < hfi2_num_vls; vl++)
			ppd->vld[vl].mtu = hfi2_max_mtu;
		ppd->vld[15].mtu = MAX_MAD_PACKET;

		/*
		 * Set the initial values to reasonable default, will be set
		 * for real when link is up.
		 */
		ppd->overrun_threshold = 0x4;
		ppd->phy_error_threshold = 0xf;
		ppd->port_crc_mode_enabled = hfi2_link_crc_mask;
		/* initialize supported LTP CRC mode */
		ppd->port_ltp_crc_mode = hfi2_cap_to_port_ltp(hfi2_link_crc_mask)
					 << 8;
		/* initialize enabled LTP CRC mode */
		ppd->port_ltp_crc_mode |= hfi2_cap_to_port_ltp(hfi2_link_crc_mask)
					  << 4;
		/* start in offline */
		ppd->host_link_state = HLS_DN_OFFLINE;
		hfi2_init_vl_arb_caches(ppd);

		/* speeds the hardware can support */
		ppd->link_speed_supported = dd->params->link_speed_supported;
		/* speeds allowed to run at */
		ppd->link_speed_enabled = ppd->link_speed_supported;
		/* give a reasonable active value, will be set on link up */
		ppd->link_speed_active = dd->params->link_speed_active;
	}

	/* Save PCI space registers to rewrite after device reset */
	ret = hfi2_save_pci_variables(dd);
	if (ret < 0)
		goto bail_cleanup;

	dd->majrev = (dd->revision >> CCE_REVISION_CHIP_REV_MAJOR_SHIFT) &
		     CCE_REVISION_CHIP_REV_MAJOR_MASK;
	dd->minrev = (dd->revision >> CCE_REVISION_CHIP_REV_MINOR_SHIFT) &
		     CCE_REVISION_CHIP_REV_MINOR_MASK;

	/*
	 * Check interrupt registers mapping if the driver has no access to
	 * the upstream component. In this case, it is likely that the driver
	 * is running in a VM.
	 */
	if (!parent) {
		ret = check_int_registers(dd);
		if (ret)
			goto bail_cleanup;
	}

	if (!dd->is_vf) {
		reg = hfi2_read_csr(dd, CCE_REVISION2);
		dd->hfi2_id = (reg >> CCE_REVISION2_HFI_ID_SHIFT) &
			      CCE_REVISION2_HFI_ID_MASK;
		/* the variable size will remove unwanted bits */
		dd->icode = reg >> CCE_REVISION2_IMPL_CODE_SHIFT;
		dd->irev = reg >> CCE_REVISION2_IMPL_REVISION_SHIFT;
	}
	dd_dev_info(dd, "Implementation: %s, revision 0x%x\n",
		    dd->icode < ARRAY_SIZE(inames) ? inames[dd->icode] :
						     "unknown",
		    (int)dd->irev);

	/*
	 * Convert the ns parameter to the 64 * cclocks used in the CSR.
	 * Limit the max if larger than the field holds.  If timeout is
	 * non-zero, then the calculated field will be at least 1.
	 *
	 * Must be after icode is set up - the cclock rate depends
	 * on knowing the hardware being used.
	 */
	dd->rcv_intr_timeout_csr =
		hfi2_ns_to_cclock(dd, hfi2_rcv_intr_timeout) / 64;
	if (dd->rcv_intr_timeout_csr > RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK)
		dd->rcv_intr_timeout_csr =
			RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK;
	else if (dd->rcv_intr_timeout_csr == 0 && hfi2_rcv_intr_timeout)
		dd->rcv_intr_timeout_csr = 1;
	dd->rcv_intr_count = hfi2_rcv_intr_count;
	dd->rcv_intr_dynamic = hfi2_rcv_intr_dynamic;

	/* find resources already consumed */
	ret = dd->params->find_used_resources(dd);
	if (ret)
		goto bail_cleanup;

	ret = set_up_context_variables(dd);
	if (ret)
		goto bail_cleanup;

	dd->params->hfi2_read_guid(dd);
	dd_dev_info(dd, "GUID %llx", (unsigned long long)dd->base_guid);

	ret = dd->params->early_per_chip_init(dd);
	if (ret)
		goto bail_cleanup;

	ret = set_up_interrupts(dd);
	if (ret)
		goto bail_cleanup;

	/*
	 * This does a STOP which will reset many things,
	 * particularly the PF contexts needed for VF2PF.
	 * The PF must not initialize VF2PF until after this.
	 */
	ret = hfi2_start_cport(dd);
	if (ret)
		goto bail_clean_early_intr;
	init_cport_eal_reset(dd);
	if (!dd->is_vf) {
		/* The PF can safely init resources now */
		ret = vf2pf_init(dd);
		if (ret)
			goto bail_clean_cport;
		ret = vf2pf_init_irq(dd);
		if (ret)
			goto bail_clean_cport;
	}

	ret = dd->params->mid_per_chip_init(dd);
	if (ret)
		goto bail_clean_cport;

	ret = obtain_boardname(dd);
	if (ret)
		goto bail_free_boardname;

	snprintf(dd->boardversion, BOARD_VERS_MAX,
		 "ChipABI %u.%u, ChipRev %u.%u, SW Compat %llu\n",
		 HFI2_CHIP_VERS_MAJ, HFI2_CHIP_VERS_MIN, (u32)dd->majrev,
		 (u32)dd->minrev,
		 (dd->revision >> CCE_REVISION_SW_SHIFT) &
			 CCE_REVISION_SW_MASK);

	/* alloc AIP rx data */
	ret = hfi2_alloc_rx(dd);
	if (ret)
		goto bail_free_boardname;

	/* set initial RXE CSRs */
	ret = hfi2_init_rxe(dd);
	if (ret)
		goto bail_free_rx;

	/* set initial TXE CSRs */
	hfi2_init_txe(dd);
	/* set initial non-RXE, non-TXE CSRs */
	dd->params->hfi2_init_other(dd);
	/* set up KDETH QP prefix in both RX and TX CSRs */
	hfi2_init_kdeth_qp(dd);

	/* send contexts must be set up before receive contexts */
	ret = hfi2_init_send_contexts(dd);
	if (ret)
		goto bail_free_rx;

	ret = hfi2_create_kctxts(dd);
	if (ret)
		goto bail_free_rx;

	/* per-vl send context and sdma init */
	for (i = 0; i < dd->num_pports; ++i) {
		ret = hfi2_init_pervl_scs(dd->pport + i);
		if (ret)
			goto bail_free_rx;
	}
	ret = hfi2_sdma_init(dd);
	if (ret)
		goto bail_free_rx;

	/* use contexts created by hfi2_create_kctxts */
	ret = late_set_up_interrupts(dd);
	if (ret)
		goto bail_free_rx;

	ret = hfi2_comp_vectors_set_up(dd);
	if (ret)
		goto bail_clear_comp_vectors;

	ret = dd->params->late_per_chip_init(dd);
	if (ret)
		goto bail_clear_comp_vectors;

	/*
	 * Serial number is created from the base guid:
	 * [27:24] = base guid [38:35]
	 * [23: 0] = base guid [23: 0]
	 */
	snprintf(dd->serial, SERIAL_MAX, "0x%08llx",
		 (dd->base_guid & 0xFFFFFF) |
			 ((dd->base_guid >> 11) & 0xF000000));

	dd->oui1 = dd->base_guid >> 56 & 0xFF;
	dd->oui2 = dd->base_guid >> 48 & 0xFF;
	dd->oui3 = dd->base_guid >> 40 & 0xFF;

	thermal_init(dd);

	ret = init_cntrs(dd);
	if (ret)
		goto bail_clear_comp_vectors;

	init_completion(&dd->user_comp);

	/* The user refcount starts with one to inidicate an active device */
	refcount_set(&dd->user_refcount, 1);

	goto bail;

bail_clear_comp_vectors:
	hfi2_comp_vectors_clean_up(dd);
bail_free_rx:
	hfi2_free_rx(dd);
bail_free_boardname:
	kfree(dd->boardname);
	dd->boardname = NULL;
bail_clean_cport:
	deinit_cport_eal_reset(dd);
	hfi2_cport_exit(dd);
	hfi2_sriov_free_rsrcs(dd, &dd->rsrcs);
bail_clean_early_intr:
	hfi2_msix_clean_up_interrupts(dd);
bail_cleanup:
	vf2pf_deinit(dd);	/* prevent future attempts to use vf2pf */
	hfi2_pcie_ddcleanup(dd); /* unmaps BARs - CSRs no longer accessible */
bail:
	return ret;
}

static u16 delay_cycles(struct hfi2_pportdata *ppd, u32 desired_egress_rate,
			u32 dw_len)
{
	u32 delta_cycles;
	u32 current_egress_rate = ppd->current_egress_rate;
	/* rates here are in units of 10^6 bits/sec */

	if (desired_egress_rate == -1)
		return 0; /* shouldn't happen */

	if (desired_egress_rate >= current_egress_rate)
		return 0; /* we can't help go faster, only slower */

	delta_cycles = egress_cycles(dw_len * 4, desired_egress_rate) -
		       egress_cycles(dw_len * 4, current_egress_rate);

	return (u16)delta_cycles;
}

/**
 * wfr_create_pbc - build a pbc for transmission
 * hfi2_wfr_create_pbc - build a pbc for transmission
 * @ppd: info of physical Hfi port
 * @hfi2_loopback: ignored for WFR
 * @flags: special case flags or-ed in built pbc
 * @srate_mbs: static rate
 * @vl: vl
 * @dw_len: dword length (header words + data words + pbc words)
 * @l2: L2 header field - determines type
 * @dlid: destination LID - unused
 * @sctxt: send context number - unused
 *
 * Create a PBC with the given flags, rate, VL, and length.
 *
 * NOTE: The PBC created will not insert any HCRC - all callers but one are
 * for verbs, which does not use this PSM feature.  The lone other caller
 * is for the diagnostic interface which calls this if the user does not
 * supply their own PBC.
 */
u64 hfi2_wfr_create_pbc(struct hfi2_pportdata *ppd, bool hfi2_loopback,
			u64 flags, int srate_mbs, u32 vl, u32 dw_len, u32 l2,
			u32 dlid, u32 sctxt)
{
	u64 pbc, delay = 0;

	if (unlikely(srate_mbs))
		delay = delay_cycles(ppd, srate_mbs, dw_len);

	/* on WFR, non-9B are always bypass */
	if (l2 != PBC_L2_9B)
		flags |= PBC_PACKET_BYPASS | PBC_INSERT_BYPASS_ICRC;

	pbc = flags | (delay << PBC_STATIC_RATE_CONTROL_COUNT_SHIFT) |
	      ((u64)PBC_IHCRC_NONE << PBC_INSERT_HCRC_SHIFT) |
	      (vl & PBC_VL_MASK) << PBC_VL_SHIFT |
	      (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT;

	return pbc_test(ppd->dd, pbc);
}

#define SBUS_THERMAL 0x4f
#define SBUS_THERM_MONITOR_MODE 0x1

#define THERM_FAILURE(dev, ret, reason)                                      \
	dd_dev_err((dev), "Thermal sensor initialization failed: %s (%d)\n", \
		   (reason), (ret))

/*
 * Initialize the thermal sensor.
 *
 * After initialization, enable polling of thermal sensor through
 * SBus interface. In order for this to work, the SBus Master
 * firmware has to be loaded due to the fact that the HW polling
 * logic uses SBus interrupts, which are not supported with
 * default firmware. Otherwise, no data will be returned through
 * the ASIC_STS_THERM CSR.
 */
static int thermal_init(struct hfi2_devdata *dd)
{
	int ret = 0;

	if (dd->params->chip_type != CHIP_WFR)
		return ret;
	if (dd->icode != ICODE_RTL_SILICON ||
	    dd->params->chip_type != CHIP_WFR ||
	    hfi2_check_chip_resource(dd, CR_THERM_INIT, NULL))
		return ret;

	ret = hfi2_acquire_chip_resource(dd, CR_SBUS, SBUS_TIMEOUT);
	if (ret) {
		THERM_FAILURE(dd, ret, "Acquire SBus");
		return ret;
	}

	dd_dev_info(dd, "Initializing thermal sensor\n");
	/* Disable polling of thermal readings */
	hfi2_write_csr(dd, ASIC_CFG_THERM_POLL_EN, 0x0);
	msleep(100);
	/* Thermal Sensor Initialization */
	/*    Step 1: Reset the Thermal SBus Receiver */
	ret = hfi2_sbus_request_slow(dd, SBUS_THERMAL, 0x0, RESET_SBUS_RECEIVER,
				     0);
	if (ret) {
		THERM_FAILURE(dd, ret, "Bus Reset");
		goto done;
	}
	/*    Step 2: Set Reset bit in Thermal block */
	ret = hfi2_sbus_request_slow(dd, SBUS_THERMAL, 0x0, WRITE_SBUS_RECEIVER,
				     0x1);
	if (ret) {
		THERM_FAILURE(dd, ret, "Therm Block Reset");
		goto done;
	}
	/*    Step 3: Write clock divider value (100MHz -> 2MHz) */
	ret = hfi2_sbus_request_slow(dd, SBUS_THERMAL, 0x1, WRITE_SBUS_RECEIVER,
				     0x32);
	if (ret) {
		THERM_FAILURE(dd, ret, "Write Clock Div");
		goto done;
	}
	/*    Step 4: Select temperature mode */
	ret = hfi2_sbus_request_slow(dd, SBUS_THERMAL, 0x3, WRITE_SBUS_RECEIVER,
				     SBUS_THERM_MONITOR_MODE);
	if (ret) {
		THERM_FAILURE(dd, ret, "Write Mode Sel");
		goto done;
	}
	/*    Step 5: De-assert block reset and start conversion */
	ret = hfi2_sbus_request_slow(dd, SBUS_THERMAL, 0x0, WRITE_SBUS_RECEIVER,
				     0x2);
	if (ret) {
		THERM_FAILURE(dd, ret, "Write Reset Deassert");
		goto done;
	}
	/*    Step 5.1: Wait for first conversion (21.5ms per spec) */
	msleep(22);

	/* Enable polling of thermal readings */
	hfi2_write_csr(dd, ASIC_CFG_THERM_POLL_EN, 0x1);

	/* Set initialized flag */
	ret = hfi2_acquire_chip_resource(dd, CR_THERM_INIT, 0);
	if (ret)
		THERM_FAILURE(dd, ret, "Unable to set thermal init flag");

done:
	hfi2_release_chip_resource(dd, CR_SBUS);
	return ret;
}

void hfi2_handle_temp_err(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	int pidx;
	/*
	 * Thermal Critical Interrupt
	 * Put the device into forced freeze mode, take link down to
	 * offline, and put DC into reset.
	 */
	dd_dev_emerg(
		dd,
		"Critical temperature reached! Forcing device into freeze mode!\n");
	dd->flags |= HFI2_FORCED_FREEZE;

	hfi2_start_freeze_handling(dd, FREEZE_SELF | FREEZE_ABORT);
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		/*
		 * Shut DC down as much and as quickly as possible.
		 *
		 * Step 1: Iterate over the ports and take the links down to OFFLINE.
		 *	   This will cause the 8051 to put the Serdes in reset. However,
		 *	   we don't want to go through the entire link state machine since
		 *	   we want to shutdown ASAP. Furthermore, this is not a graceful
		 *	   shutdown but rather an attempt to save the chip.
		 *         Code below is almost the same as quiet_serdes() but avoids
		 *         all the extra work and the sleeps.
		 */
		ppd->driver_link_ready = 0;
		ppd->link_enabled = 0;
	}

	hfi2_set_physical_link_state(dd, (OPA_LINKDOWN_REASON_SMA_DISABLED << 8) |
					    PLS_OFFLINE);
	/*
	 * Step 2: Shutdown LCB and 8051
	 *         After shutdown, do not restore DC_CFG_RESET value.
	 */
	hfi2_dc_shutdown(dd);
}

static irqreturn_t _sdma_interrupt(int irq, struct sdma_engine *sde, u64 status)
{
	struct hfi2_devdata *dd = sde->dd;
	u32 off;

#ifdef CONFIG_HFI2_SDMA_VERBOSITY
	dd_dev_err(dd, "CONFIG SDMA(%u) %s:%d %s()\n", sde->this_idx,
		   slashstrip(__FILE__), __LINE__, __func__);
	hfi2_sdma_dumpstate(sde);
#endif

	this_cpu_inc(*dd->int_counter);

	/* hand over to bulksvc irq handler
	 * TODO this is temporary, eventually a fn pointer or handler
	 * specific function at irq registration would be better
	 */
	if (sde->this_idx >= dd->rsrcs.last_sdma_engine && dd->bulksvc) {
		sdma_set_desc_cnt_all(sde);
		/* bulksvc will handle clearing these interrupts */
		bulksvc_sdma_irq(dd, sde);
		return IRQ_HANDLED;
	}

	off = 8 * (dd->params->is_sdma_start / 64);
	/* handle the interrupt(s) */
	hfi2_sdma_engine_interrupt(sde, status);
	if (hfi2_sdma_work_pending(sde))
		return IRQ_WAKE_THREAD;
	__hfi2_sde_eoi_intr(sde, off, status);
	return IRQ_HANDLED;
}

irqreturn_t hfi2_sdma_interrupt(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt(irq, sde, sde->int_mask);
}

irqreturn_t sdma_progress_interrupt(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt(irq, sde, sde->progress_mask);
}

irqreturn_t sdma_idle_interrupt(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt(irq, sde, sde->idle_mask);
}

static irqreturn_t _sdma_interrupt_thr(int irq, struct sdma_engine *sde,
				       u64 status)
{
	struct hfi2_devdata *dd = sde->dd;
	u32 off;
	unsigned long ty;
	unsigned long flags;

	off = 8 * (dd->params->is_sdma_start / 64);
	ty = jiffies + msecs_to_jiffies(sdma_yield);
again:
	/* handle the interrupt(s) */
	hfi2_sdma_engine_interrupt(sde, status);

	if (hfi2_sdma_work_pending(sde)) {
		if (time_after(jiffies, ty)) {
			cond_resched();
			ty = jiffies + msecs_to_jiffies(sdma_yield);
		}
		goto again;
	}
	local_irq_save(flags);
	__hfi2_sde_eoi_intr(sde, off, status);
	local_irq_restore(flags);
	return IRQ_HANDLED;
}

irqreturn_t hfi2_sdma_interrupt_thr(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt_thr(irq, sde, sde->int_mask);
}

irqreturn_t sdma_progress_interrupt_thr(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt_thr(irq, sde, sde->progress_mask);
}

irqreturn_t sdma_idle_interrupt_thr(int irq, void *data)
{
	struct sdma_engine *sde = data;

	return _sdma_interrupt_thr(irq, sde, sde->idle_mask);
}














/* TODO: also call this (common code) at end of init_qos_port()? */
void hfi2_restore_qpmap_table(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	struct hfi2_portrsrcs *pr;
	int i;
	unsigned int rcb, ctxt;

	for (i = 0; i < dd->num_pports; i++) {
		pr = &dd->rsrcs.ppr[i];
		if (!pr->n_krcv_queues)
			continue;
		ppd = &dd->pport[i];
		rcb = pr->rcv_context_base;
		if (ppd->qos_shift == 1) {
			ctxt = rcb + FIRST_KERNEL_KCTXT;
			init_qpmap_table(ppd, ctxt,
					 ctxt + pr->n_krcv_queues -
						 FIRST_KERNEL_KCTXT - 1);
		} else {
			init_qpmap_table(ppd, rcb + HFI2_CTRL_CTXT,
					 rcb + HFI2_CTRL_CTXT);
		}
	}
}


