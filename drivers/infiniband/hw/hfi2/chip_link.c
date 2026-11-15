// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright(c) 2021 - 2026 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 *
 * Link state machine, LNI, 8051/SerDes/LCB management, link quality
 * and QSFP handling.  Split out of the former monolithic chip.c;
 * CSR/interrupt/init code lives in chip.c and send/receive context
 * setup in chip_ctxt.c.
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

#define DCCE(name) DCC_ERR_FLG_##name##_SMASK
static const struct flag_table dcc_err_flags[] = {
	FLAG_ENTRY0("bad_l2_err", DCCE(BAD_L2_ERR)),
	FLAG_ENTRY0("bad_sc_err", DCCE(BAD_SC_ERR)),
	FLAG_ENTRY0("bad_mid_tail_err", DCCE(BAD_MID_TAIL_ERR)),
	FLAG_ENTRY0("bad_preemption_err", DCCE(BAD_PREEMPTION_ERR)),
	FLAG_ENTRY0("preemption_err", DCCE(PREEMPTION_ERR)),
	FLAG_ENTRY0("preemptionvl15_err", DCCE(PREEMPTIONVL15_ERR)),
	FLAG_ENTRY0("bad_vl_marker_err", DCCE(BAD_VL_MARKER_ERR)),
	FLAG_ENTRY0("bad_dlid_target_err", DCCE(BAD_DLID_TARGET_ERR)),
	FLAG_ENTRY0("bad_lver_err", DCCE(BAD_LVER_ERR)),
	FLAG_ENTRY0("uncorrectable_err", DCCE(UNCORRECTABLE_ERR)),
	FLAG_ENTRY0("bad_crdt_ack_err", DCCE(BAD_CRDT_ACK_ERR)),
	FLAG_ENTRY0("unsup_pkt_type", DCCE(UNSUP_PKT_TYPE)),
	FLAG_ENTRY0("bad_ctrl_flit_err", DCCE(BAD_CTRL_FLIT_ERR)),
	FLAG_ENTRY0("event_cntr_parity_err", DCCE(EVENT_CNTR_PARITY_ERR)),
	FLAG_ENTRY0("event_cntr_rollover_err", DCCE(EVENT_CNTR_ROLLOVER_ERR)),
	FLAG_ENTRY0("link_err", DCCE(LINK_ERR)),
	FLAG_ENTRY0("misc_cntr_rollover_err", DCCE(MISC_CNTR_ROLLOVER_ERR)),
	FLAG_ENTRY0("bad_ctrl_dist_err", DCCE(BAD_CTRL_DIST_ERR)),
	FLAG_ENTRY0("bad_tail_dist_err", DCCE(BAD_TAIL_DIST_ERR)),
	FLAG_ENTRY0("bad_head_dist_err", DCCE(BAD_HEAD_DIST_ERR)),
	FLAG_ENTRY0("nonvl15_state_err", DCCE(NONVL15_STATE_ERR)),
	FLAG_ENTRY0("vl15_multi_err", DCCE(VL15_MULTI_ERR)),
	FLAG_ENTRY0("bad_pkt_length_err", DCCE(BAD_PKT_LENGTH_ERR)),
	FLAG_ENTRY0("unsup_vl_err", DCCE(UNSUP_VL_ERR)),
	FLAG_ENTRY0("perm_nvl15_err", DCCE(PERM_NVL15_ERR)),
	FLAG_ENTRY0("slid_zero_err", DCCE(SLID_ZERO_ERR)),
	FLAG_ENTRY0("dlid_zero_err", DCCE(DLID_ZERO_ERR)),
	FLAG_ENTRY0("length_mtu_err", DCCE(LENGTH_MTU_ERR)),
	FLAG_ENTRY0("rx_early_drop_err", DCCE(RX_EARLY_DROP_ERR)),
	FLAG_ENTRY0("late_short_err", DCCE(LATE_SHORT_ERR)),
	FLAG_ENTRY0("late_long_err", DCCE(LATE_LONG_ERR)),
	FLAG_ENTRY0("late_ebp_err", DCCE(LATE_EBP_ERR)),
	FLAG_ENTRY0("fpe_tx_fifo_ovflw_err", DCCE(FPE_TX_FIFO_OVFLW_ERR)),
	FLAG_ENTRY0("fpe_tx_fifo_unflw_err", DCCE(FPE_TX_FIFO_UNFLW_ERR)),
	FLAG_ENTRY0("csr_access_blocked_host", DCCE(CSR_ACCESS_BLOCKED_HOST)),
	FLAG_ENTRY0("csr_access_blocked_uc", DCCE(CSR_ACCESS_BLOCKED_UC)),
	FLAG_ENTRY0("tx_ctrl_parity_err", DCCE(TX_CTRL_PARITY_ERR)),
	FLAG_ENTRY0("tx_ctrl_parity_mbe_err", DCCE(TX_CTRL_PARITY_MBE_ERR)),
	FLAG_ENTRY0("tx_sc_parity_err", DCCE(TX_SC_PARITY_ERR)),
	FLAG_ENTRY0("rx_ctrl_parity_mbe_err", DCCE(RX_CTRL_PARITY_MBE_ERR)),
	FLAG_ENTRY0("csr_parity_err", DCCE(CSR_PARITY_ERR)),
	FLAG_ENTRY0("csr_inval_addr", DCCE(CSR_INVAL_ADDR)),
	FLAG_ENTRY0("tx_byte_shft_parity_err", DCCE(TX_BYTE_SHFT_PARITY_ERR)),
	FLAG_ENTRY0("rx_byte_shft_parity_err", DCCE(RX_BYTE_SHFT_PARITY_ERR)),
	FLAG_ENTRY0("fmconfig_err", DCCE(FMCONFIG_ERR)),
	FLAG_ENTRY0("rcvport_err", DCCE(RCVPORT_ERR)),
};
#define LCBE(name) DC_LCB_ERR_FLG_##name##_SMASK
static const struct flag_table lcb_err_flags[] = {
	/* 0*/ FLAG_ENTRY0("CSR_PARITY_ERR", LCBE(CSR_PARITY_ERR)),
	/* 1*/ FLAG_ENTRY0("INVALID_CSR_ADDR", LCBE(INVALID_CSR_ADDR)),
	/* 2*/ FLAG_ENTRY0("RST_FOR_FAILED_DESKEW", LCBE(RST_FOR_FAILED_DESKEW)),
	/* 3*/
	FLAG_ENTRY0("ALL_LNS_FAILED_REINIT_TEST",
		    LCBE(ALL_LNS_FAILED_REINIT_TEST)),
	/* 4*/
	FLAG_ENTRY0("LOST_REINIT_STALL_OR_TOS", LCBE(LOST_REINIT_STALL_OR_TOS)),
	/* 5*/ FLAG_ENTRY0("TX_LESS_THAN_FOUR_LNS", LCBE(TX_LESS_THAN_FOUR_LNS)),
	/* 6*/ FLAG_ENTRY0("RX_LESS_THAN_FOUR_LNS", LCBE(RX_LESS_THAN_FOUR_LNS)),
	/* 7*/ FLAG_ENTRY0("SEQ_CRC_ERR", LCBE(SEQ_CRC_ERR)),
	/* 8*/ FLAG_ENTRY0("REINIT_FROM_PEER", LCBE(REINIT_FROM_PEER)),
	/* 9*/ FLAG_ENTRY0("REINIT_FOR_LN_DEGRADE", LCBE(REINIT_FOR_LN_DEGRADE)),
	/*10*/ FLAG_ENTRY0("CRC_ERR_CNT_HIT_LIMIT", LCBE(CRC_ERR_CNT_HIT_LIMIT)),
	/*11*/ FLAG_ENTRY0("RCLK_STOPPED", LCBE(RCLK_STOPPED)),
	/*12*/
	FLAG_ENTRY0("UNEXPECTED_REPLAY_MARKER", LCBE(UNEXPECTED_REPLAY_MARKER)),
	/*13*/
	FLAG_ENTRY0("UNEXPECTED_ROUND_TRIP_MARKER",
		    LCBE(UNEXPECTED_ROUND_TRIP_MARKER)),
	/*14*/ FLAG_ENTRY0("ILLEGAL_NULL_LTP", LCBE(ILLEGAL_NULL_LTP)),
	/*15*/ FLAG_ENTRY0("ILLEGAL_FLIT_ENCODING", LCBE(ILLEGAL_FLIT_ENCODING)),
	/*16*/ FLAG_ENTRY0("FLIT_INPUT_BUF_OFLW", LCBE(FLIT_INPUT_BUF_OFLW)),
	/*17*/ FLAG_ENTRY0("VL_ACK_INPUT_BUF_OFLW", LCBE(VL_ACK_INPUT_BUF_OFLW)),
	/*18*/
	FLAG_ENTRY0("VL_ACK_INPUT_PARITY_ERR", LCBE(VL_ACK_INPUT_PARITY_ERR)),
	/*19*/
	FLAG_ENTRY0("VL_ACK_INPUT_WRONG_CRC_MODE",
		    LCBE(VL_ACK_INPUT_WRONG_CRC_MODE)),
	/*20*/ FLAG_ENTRY0("FLIT_INPUT_BUF_MBE", LCBE(FLIT_INPUT_BUF_MBE)),
	/*21*/ FLAG_ENTRY0("FLIT_INPUT_BUF_SBE", LCBE(FLIT_INPUT_BUF_SBE)),
	/*22*/ FLAG_ENTRY0("REPLAY_BUF_MBE", LCBE(REPLAY_BUF_MBE)),
	/*23*/ FLAG_ENTRY0("REPLAY_BUF_SBE", LCBE(REPLAY_BUF_SBE)),
	/*24*/ FLAG_ENTRY0("CREDIT_RETURN_FLIT_MBE", LCBE(CREDIT_RETURN_FLIT_MBE)),
	/*25*/ FLAG_ENTRY0("RST_FOR_LINK_TIMEOUT", LCBE(RST_FOR_LINK_TIMEOUT)),
	/*26*/
	FLAG_ENTRY0("RST_FOR_INCOMPLT_RND_TRIP",
		    LCBE(RST_FOR_INCOMPLT_RND_TRIP)),
	/*27*/ FLAG_ENTRY0("HOLD_REINIT", LCBE(HOLD_REINIT)),
	/*28*/
	FLAG_ENTRY0("NEG_EDGE_LINK_TRANSFER_ACTIVE",
		    LCBE(NEG_EDGE_LINK_TRANSFER_ACTIVE)),
	/*29*/
	FLAG_ENTRY0("REDUNDANT_FLIT_PARITY_ERR",
		    LCBE(REDUNDANT_FLIT_PARITY_ERR))
};
#define D8E(name) DC_DC8051_ERR_FLG_##name##_SMASK
static const struct flag_table dc8051_err_flags[] = {
	FLAG_ENTRY0("SET_BY_8051", D8E(SET_BY_8051)),
	FLAG_ENTRY0("LOST_8051_HEART_BEAT", D8E(LOST_8051_HEART_BEAT)),
	FLAG_ENTRY0("CRAM_MBE", D8E(CRAM_MBE)),
	FLAG_ENTRY0("CRAM_SBE", D8E(CRAM_SBE)),
	FLAG_ENTRY0("DRAM_MBE", D8E(DRAM_MBE)),
	FLAG_ENTRY0("DRAM_SBE", D8E(DRAM_SBE)),
	FLAG_ENTRY0("IRAM_MBE", D8E(IRAM_MBE)),
	FLAG_ENTRY0("IRAM_SBE", D8E(IRAM_SBE)),
	FLAG_ENTRY0("UNMATCHED_SECURE_MSG_ACROSS_BCC_LANES",
		    D8E(UNMATCHED_SECURE_MSG_ACROSS_BCC_LANES)),
	FLAG_ENTRY0("INVALID_CSR_ADDR", D8E(INVALID_CSR_ADDR)),
};
static const struct flag_table dc8051_info_err_flags[] = {
	FLAG_ENTRY0("Spico ROM check failed", SPICO_ROM_FAILED),
	FLAG_ENTRY0("Unknown frame received", UNKNOWN_FRAME),
	FLAG_ENTRY0("Target BER not met", TARGET_BER_NOT_MET),
	FLAG_ENTRY0("Serdes internal hfi2_loopback failure",
		    FAILED_SERDES_INTERNAL_LOOPBACK),
	FLAG_ENTRY0("Failed SerDes init", FAILED_SERDES_INIT),
	FLAG_ENTRY0("Failed LNI(Polling)", FAILED_LNI_POLLING),
	FLAG_ENTRY0("Failed LNI(Debounce)", FAILED_LNI_DEBOUNCE),
	FLAG_ENTRY0("Failed LNI(EstbComm)", FAILED_LNI_ESTBCOMM),
	FLAG_ENTRY0("Failed LNI(OptEq)", FAILED_LNI_OPTEQ),
	FLAG_ENTRY0("Failed LNI(VerifyCap_1)", FAILED_LNI_VERIFY_CAP1),
	FLAG_ENTRY0("Failed LNI(VerifyCap_2)", FAILED_LNI_VERIFY_CAP2),
	FLAG_ENTRY0("Failed LNI(ConfigLT)", FAILED_LNI_CONFIGLT),
	FLAG_ENTRY0("Host Handshake Timeout", HOST_HANDSHAKE_TIMEOUT),
	FLAG_ENTRY0("External Device Request Timeout",
		    EXTERNAL_DEVICE_REQ_TIMEOUT),
};
static const struct flag_table dc8051_info_host_msg_flags[] = {
	FLAG_ENTRY0("Host request done", 0x0001),
	FLAG_ENTRY0("BC PWR_MGM message", 0x0002),
	FLAG_ENTRY0("BC SMA message", 0x0004),
	FLAG_ENTRY0("BC Unknown message (BCC)", 0x0008),
	FLAG_ENTRY0("BC Unknown message (LCB)", 0x0010),
	FLAG_ENTRY0("External device config request", 0x0020),
	FLAG_ENTRY0("VerifyCap all frames received", 0x0040),
	FLAG_ENTRY0("LinkUp achieved", 0x0080),
	FLAG_ENTRY0("Link going down", 0x0100),
	FLAG_ENTRY0("Link width downgraded", 0x0200),
};
/*
 * Table of the DC grouping of error interrupts.  Each entry refers to
 * another register containing more information.
 */
static const struct err_reg_info dc_errs[NUM_DC_ERRS] = {
	DC_EE1(DCC_ERR, hfi2_handle_dcc_err, "DCC Err"),
	DC_EE2(DC_LCB_ERR, hfi2_handle_lcb_err, "LCB Err"),
	DC_EE2(DC_DC8051_ERR, hfi2_handle_8051_interrupt, "DC8051 Interrupt"),
	/* dc_lbm_int - special, see is_dc_int() */
	/* the rest are reserved */
};
static int request_host_lcb_access(struct hfi2_devdata *dd)
{
	int ret;

	ret = hfi2_do_8051_command(dd, HCMD_MISC,
			      (u64)HCMD_MISC_REQUEST_LCB_ACCESS
				      << LOAD_DATA_FIELD_ID_SHIFT,
			      NULL);
	if (ret != HCMD_SUCCESS && !(dd->flags & HFI2_SHUTDOWN)) {
		dd_dev_err(dd, "%s: command failed with error %d\n", __func__,
			   ret);
	}
	return ret == HCMD_SUCCESS ? 0 : -EBUSY;
}

static int request_8051_lcb_access(struct hfi2_devdata *dd)
{
	int ret;

	ret = hfi2_do_8051_command(dd, HCMD_MISC,
			      (u64)HCMD_MISC_GRANT_LCB_ACCESS
				      << LOAD_DATA_FIELD_ID_SHIFT,
			      NULL);
	if (ret != HCMD_SUCCESS) {
		dd_dev_err(dd, "%s: command failed with error %d\n", __func__,
			   ret);
	}
	return ret == HCMD_SUCCESS ? 0 : -EBUSY;
}

/*
 * Set the LCB selector - allow host access.  The DCC selector always
 * points to the host.
 */
static inline void set_host_lcb_access(struct hfi2_devdata *dd)
{
	hfi2_write_csr(dd, DC_DC8051_CFG_CSR_ACCESS_SEL,
		       DC_DC8051_CFG_CSR_ACCESS_SEL_DCC_SMASK |
			       DC_DC8051_CFG_CSR_ACCESS_SEL_LCB_SMASK);
}

/*
 * Clear the LCB selector - allow 8051 access.  The DCC selector always
 * points to the host.
 */
static inline void set_8051_lcb_access(struct hfi2_devdata *dd)
{
	hfi2_write_csr(dd, DC_DC8051_CFG_CSR_ACCESS_SEL,
		       DC_DC8051_CFG_CSR_ACCESS_SEL_DCC_SMASK);
}

/*
 * Acquire LCB access from the 8051.  If the host already has access,
 * just increment a counter.  Otherwise, inform the 8051 that the
 * host is taking access.
 *
 * Returns:
 *	0 on success
 *	-EBUSY if the 8051 has control and cannot be disturbed
 *	-errno if unable to acquire access from the 8051
 */
int hfi2_acquire_lcb_access(struct hfi2_devdata *dd, int sleep_ok)
{
	struct hfi2_pportdata *ppd = dd->pport;
	int ret = 0;

	/*
	 * Use the host link state lock so the operation of this routine
	 * { link state check, selector change, count increment } can occur
	 * as a unit against a link state change.  Otherwise there is a
	 * race between the state change and the count increment.
	 */
	if (sleep_ok) {
		mutex_lock(&ppd->hls_lock);
	} else {
		while (!mutex_trylock(&ppd->hls_lock))
			udelay(1);
	}

	/* this access is valid only when the link is up */
	if (ppd->host_link_state & HLS_DOWN) {
		ppd_dev_info(ppd, "%s: link state %s not up\n", __func__,
			     hfi2_link_state_name(ppd->host_link_state));
		ret = -EBUSY;
		goto done;
	}

	if (dd->lcb_access_count == 0) {
		ret = request_host_lcb_access(dd);
		if (ret) {
			if (!(dd->flags & HFI2_SHUTDOWN))
				ppd_dev_err(
					ppd,
					"%s: unable to acquire LCB access, err %d\n",
					__func__, ret);
			goto done;
		}
		set_host_lcb_access(dd);
	}
	dd->lcb_access_count++;
done:
	mutex_unlock(&ppd->hls_lock);
	return ret;
}

/*
 * Release LCB access by decrementing the use count.  If the count is moving
 * from 1 to 0, inform 8051 that it has control back.
 *
 * Returns:
 *	0 on success
 *	-errno if unable to release access to the 8051
 */
int hfi2_release_lcb_access(struct hfi2_devdata *dd, int sleep_ok)
{
	int ret = 0;

	/*
	 * Use the host link state lock because the acquire needed it.
	 * Here, we only need to keep { selector change, count decrement }
	 * as a unit.
	 */
	if (sleep_ok) {
		mutex_lock(&dd->pport->hls_lock);
	} else {
		while (!mutex_trylock(&dd->pport->hls_lock))
			udelay(1);
	}

	if (dd->lcb_access_count == 0) {
		dd_dev_err(dd, "%s: LCB access count is zero.  Skipping.\n",
			   __func__);
		goto done;
	}

	if (dd->lcb_access_count == 1) {
		set_8051_lcb_access(dd);
		ret = request_8051_lcb_access(dd);
		if (ret) {
			dd_dev_err(dd,
				   "%s: unable to release LCB access, err %d\n",
				   __func__, ret);
			/* restore host access if the grant didn't work */
			set_host_lcb_access(dd);
			goto done;
		}
	}
	dd->lcb_access_count--;
done:
	mutex_unlock(&dd->pport->hls_lock);
	return ret;
}

/*
 * Initialize LCB access variables and state.  Called during driver load,
 * after most of the initialization is finished.
 *
 * The DC default is LCB access on for the host.  The driver defaults to
 * leaving access to the 8051.  Assign access now - this constrains the call
 * to this routine to be after all LCB set-up is done.  In particular, after
 * hf1_init_dd() -> set_up_interrupts() -> hfi2_clear_all_interrupts()
 */
void hfi2_init_lcb_access(struct hfi2_devdata *dd)
{
	dd->lcb_access_count = 0;
}

/*
 * Write a response back to a 8051 request.
 */
static void hreq_response(struct hfi2_devdata *dd, u8 return_code, u16 rsp_data)
{
	hfi2_write_csr(
		dd, DC_DC8051_CFG_EXT_DEV_0,
		DC_DC8051_CFG_EXT_DEV_0_COMPLETED_SMASK |
			(u64)return_code
				<< DC_DC8051_CFG_EXT_DEV_0_RETURN_CODE_SHIFT |
			(u64)rsp_data
				<< DC_DC8051_CFG_EXT_DEV_0_RSP_DATA_SHIFT);
}

/*
 * Handle host requests from the 8051.
 */
static void handle_8051_request(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	u16 data = 0;
	u8 type;

	reg = hfi2_read_csr(dd, DC_DC8051_CFG_EXT_DEV_1);
	if ((reg & DC_DC8051_CFG_EXT_DEV_1_REQ_NEW_SMASK) == 0)
		return; /* no request */

	/* zero out COMPLETED so the response is seen */
	hfi2_write_csr(dd, DC_DC8051_CFG_EXT_DEV_0, 0);

	/* extract request details */
	type = (reg >> DC_DC8051_CFG_EXT_DEV_1_REQ_TYPE_SHIFT) &
	       DC_DC8051_CFG_EXT_DEV_1_REQ_TYPE_MASK;
	data = (reg >> DC_DC8051_CFG_EXT_DEV_1_REQ_DATA_SHIFT) &
	       DC_DC8051_CFG_EXT_DEV_1_REQ_DATA_MASK;

	switch (type) {
	case HREQ_LOAD_CONFIG:
	case HREQ_SAVE_CONFIG:
	case HREQ_READ_CONFIG:
	case HREQ_SET_TX_EQ_ABS:
	case HREQ_SET_TX_EQ_REL:
	case HREQ_ENABLE:
		ppd_dev_info(ppd, "8051 request: request 0x%x not supported\n",
			     type);
		hreq_response(dd, HREQ_NOT_SUPPORTED, 0);
		break;
	case HREQ_LCB_RESET:
		/* Put the LCB, RX FPE and TX FPE into reset */
		hfi2_write_csr(dd, DCC_CFG_RESET, LCB_RX_FPE_TX_FPE_INTO_RESET);
		/* Make sure the write completed */
		(void)hfi2_read_csr(dd, DCC_CFG_RESET);
		/* Hold the reset long enough to take effect */
		udelay(1);
		/* Take the LCB, RX FPE and TX FPE out of reset */
		hfi2_write_csr(dd, DCC_CFG_RESET,
			       LCB_RX_FPE_TX_FPE_OUT_OF_RESET);
		hreq_response(dd, HREQ_SUCCESS, 0);

		break;
	case HREQ_CONFIG_DONE:
		hreq_response(dd, HREQ_SUCCESS, 0);
		break;

	case HREQ_INTERFACE_TEST:
		hreq_response(dd, HREQ_SUCCESS, data);
		break;
	default:
		ppd_dev_err(ppd, "8051 request: unknown request 0x%x\n", type);
		hreq_response(dd, HREQ_NOT_SUPPORTED, 0);
		break;
	}
}

/*
 * Set up allocation unit vaulue.
 */
void hfi2_set_up_vau(struct hfi2_pportdata *ppd, u8 vau)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = read_eport_csr(dd, ppd->hw_pidx,
				 dd->params->send_cm_global_credit_reg);

	/* do not modify other values in the register */
	reg &= ~SEND_CM_GLOBAL_CREDIT_AU_SMASK;
	reg |= (u64)vau << SEND_CM_GLOBAL_CREDIT_AU_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_global_credit_reg,
			reg);
}

/*
 * Set up initial VL15 credits of the remote.  Assumes the rest of
 * the CM credit registers are zero from a previous global or credit reset.
 * Shared limit for VL15 will always be 0.
 */
void hfi2_set_up_vl15(struct hfi2_pportdata *ppd, u16 vl15buf)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = read_eport_csr(dd, ppd->hw_pidx,
				 dd->params->send_cm_global_credit_reg);

	/* set initial values for total and shared credit limit */
	reg &= ~(SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_SMASK |
		 SEND_CM_GLOBAL_CREDIT_SHARED_LIMIT_SMASK);

	/*
	 * Set total limit to be equal to VL15 credits.
	 * Leave shared limit at 0.
	 */
	reg |= (u64)vl15buf << SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_global_credit_reg,
			reg);

	write_eport_csr(
		dd, ppd->hw_pidx, dd->params->send_cm_credit_vl15_reg,
		(u64)vl15buf << SEND_CM_CREDIT_VL15_DEDICATED_LIMIT_VL_SHIFT);
}

/*
 * Zero all credit details from the previous connection and
 * reset the CM manager's internal counters.
 */
void hfi2_reset_link_credits(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	int i;

	/* remove all previous VL credit limits */
	for (i = 0; i < TXE_NUM_DATA_VL; i++)
		write_eport_csr(dd, ppd->hw_pidx,
				dd->params->send_cm_credit_vl_reg + (8 * i), 0);
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_credit_vl15_reg,
			0);
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_global_credit_reg,
			0);
	/* reset the CM block */
	hfi2_pio_send_control(ppd, PSC_CM_RESET);
	/* reset cached value */
	dd->vl15buf_cached = 0;
}

/* convert a vCU to a CU */
u32 hfi2_vcu_to_cu(u8 vcu)
{
	return 1 << vcu;
}

/* convert a CU to a vCU */
u8 hfi2_cu_to_vcu(u32 cu)
{
	return ilog2(cu);
}

/* convert a vAU to an AU */
u32 hfi2_vau_to_au(u8 vau)
{
	return 8 * (1 << vau);
}

static void set_linkup_defaults(struct hfi2_pportdata *ppd)
{
	ppd->sm_trap_qp = 0x0;
	ppd->sa_qp = 0x1;
}

/*
 * Graceful LCB shutdown.  This leaves the LCB FIFOs in reset.
 */
static void lcb_shutdown(struct hfi2_devdata *dd, int abort)
{
	u64 reg;

	/* clear lcb run: LCB_CFG_RUN.EN = 0 */
	hfi2_write_csr(dd, DC_LCB_CFG_RUN, 0);
	/* set tx fifo reset: LCB_CFG_TX_FIFOS_RESET.VAL = 1 */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET,
		       1ull << DC_LCB_CFG_TX_FIFOS_RESET_VAL_SHIFT);
	/* set dcc reset csr: DCC_CFG_RESET.{reset_lcb,reset_rx_fpe} = 1 */
	dd->lcb_err_en = hfi2_read_csr(dd, DC_LCB_ERR_EN);
	reg = hfi2_read_csr(dd, DCC_CFG_RESET);
	hfi2_write_csr(dd, DCC_CFG_RESET,
		       reg | DCC_CFG_RESET_RESET_LCB |
			       DCC_CFG_RESET_RESET_RX_FPE);
	(void)hfi2_read_csr(dd,
			    DCC_CFG_RESET); /* make sure the write completed */
	if (!abort) {
		udelay(1); /* must hold for the longer of 16cclks or 20ns */
		hfi2_write_csr(dd, DCC_CFG_RESET, reg);
		hfi2_write_csr(dd, DC_LCB_ERR_EN, dd->lcb_err_en);
	}
}

/*
 * This routine should be called after the link has been transitioned to
 * OFFLINE (OFFLINE state has the side effect of putting the SerDes into
 * reset).
 *
 * The expectation is that the caller of this routine would have taken
 * care of properly transitioning the link into the correct state.
 * NOTE: the caller needs to acquire the dd->dc8051_lock lock
 *       before calling this function.
 */
static void _dc_shutdown(struct hfi2_devdata *dd)
{
	lockdep_assert_held(&dd->dc8051_lock);

	if (dd->dc_shutdown)
		return;

	dd->dc_shutdown = 1;
	/* Shutdown the LCB */
	lcb_shutdown(dd, 1);
	/*
	 * Going to OFFLINE would have causes the 8051 to put the
	 * SerDes into reset already. Just need to shut down the 8051,
	 * itself.
	 */
	hfi2_write_csr(dd, DC_DC8051_CFG_RST, 0x1);
}

void hfi2_dc_shutdown(struct hfi2_devdata *dd)
{
	mutex_lock(&dd->dc8051_lock);
	_dc_shutdown(dd);
	mutex_unlock(&dd->dc8051_lock);
}

/*
 * Calling this after the DC has been brought out of reset should not
 * do any damage.
 * NOTE: the caller needs to acquire the dd->dc8051_lock lock
 *       before calling this function.
 */
static void _dc_start(struct hfi2_devdata *dd)
{
	lockdep_assert_held(&dd->dc8051_lock);

	if (!dd->dc_shutdown)
		return;

	/* Take the 8051 out of reset */
	hfi2_write_csr(dd, DC_DC8051_CFG_RST, 0ull);
	/* Wait until 8051 is ready */
	if (hfi2_wait_fm_ready(dd, TIMEOUT_8051_START))
		dd_dev_err(dd, "%s: timeout starting 8051 firmware\n",
			   __func__);

	/* Take away reset for LCB and RX FPE (set in lcb_shutdown). */
	hfi2_write_csr(dd, DCC_CFG_RESET, LCB_RX_FPE_TX_FPE_OUT_OF_RESET);
	/* lcb_shutdown() with abort=1 does not restore these */
	hfi2_write_csr(dd, DC_LCB_ERR_EN, dd->lcb_err_en);
	dd->dc_shutdown = 0;
}

void hfi2_dc_start(struct hfi2_devdata *dd)
{
	mutex_lock(&dd->dc8051_lock);
	_dc_start(dd);
	mutex_unlock(&dd->dc8051_lock);
}

/*
 * Handle a SMA idle message
 *
 * This is a work-queue function outside of the interrupt.
 */
void hfi2_handle_sma_message(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, sma_message_work);
	struct hfi2_devdata *dd = ppd->dd;
	u64 msg;
	int ret;

	/*
	 * msg is bytes 1-4 of the 40-bit idle message - the command code
	 * is stripped off
	 */
	ret = hfi2_read_idle_sma(dd, &msg);
	if (ret)
		return;
	ppd_dev_info(ppd, "%s: SMA message 0x%llx\n", __func__, msg);
	/*
	 * React to the SMA message.  Byte[1] (0 for us) is the command.
	 */
	switch (msg & 0xff) {
	case SMA_IDLE_ARM:
		/*
		 * See OPAv1 table 9-14 - HFI and External Switch Ports Key
		 * State Transitions
		 *
		 * Only expected in INIT or ARMED, discard otherwise.
		 */
		if (ppd->host_link_state & (HLS_UP_INIT | HLS_UP_ARMED))
			ppd->neighbor_normal = 1;
		break;
	case SMA_IDLE_ACTIVE:
		/*
		 * See OPAv1 table 9-14 - HFI and External Switch Ports Key
		 * State Transitions
		 *
		 * Can activate the node.  Discard otherwise.
		 */
		if (ppd->host_link_state == HLS_UP_ARMED &&
		    ppd->is_active_optimize_enabled) {
			ppd->neighbor_normal = 1;
			ret = hfi2_set_link_state(ppd, HLS_UP_ACTIVE);
			if (ret)
				ppd_dev_err(
					ppd,
					"%s: received Active SMA idle message, couldn't set link to Active\n",
					__func__);
		}
		break;
	default:
		ppd_dev_err(ppd,
			    "%s: received unexpected SMA idle message 0x%llx\n",
			    __func__, msg);
		break;
	}
}
static void read_ltp_rtt(struct hfi2_pportdata *ppd)
{
	u64 reg;

	if (hfi2_read_lcb_csr(ppd, DC_LCB_STS_ROUND_TRIP_LTP_CNT, &reg)) {
		ppd_dev_err(ppd, "%s: unable to read LTP RTT\n", __func__);
		ppd->link_ltp_rtt = 0;
	} else {
		ppd->link_ltp_rtt = reg;
	}
}

/*
 * Handle a link up interrupt from the 8051.
 *
 * This is a work-queue function outside of the interrupt.
 */
void hfi2_handle_link_up(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, link_up_work);
	struct hfi2_devdata *dd = ppd->dd;

	hfi2_set_link_state(ppd, HLS_UP_INIT);

	/* cache the read of DC_LCB_STS_ROUND_TRIP_LTP_CNT */
	read_ltp_rtt(ppd);
	/*
	 * OPA specifies that certain counters are cleared on a transition
	 * to link up, so do that.
	 */
	hfi2_clear_linkup_counters(ppd);
	/*
	 * And (re)set link up default values.
	 */
	set_linkup_defaults(ppd);

	/*
	 * Set VL15 credits. Use cached value from verify cap interrupt.
	 * In case of quick linkup, vl15 value will be set by
	 * hfi2_handle_linkup_change. VerifyCap interrupt handler will not be
	 * called in those scenarios.
	 */
	if (!hfi2_quick_linkup)
		hfi2_set_up_vl15(ppd, dd->vl15buf_cached);

	/* enforce link speed enabled */
	if ((ppd->link_speed_active & ppd->link_speed_enabled) == 0) {
		/* oops - current speed is not enabled, bounce */
		ppd_dev_err(
			ppd,
			"Link speed active 0x%x is outside enabled 0x%x, downing link\n",
			ppd->link_speed_active, ppd->link_speed_enabled);
		hfi2_set_link_down_reason(ppd, OPA_LINKDOWN_REASON_SPEED_POLICY,
					  0, OPA_LINKDOWN_REASON_SPEED_POLICY);
		hfi2_set_link_state(ppd, HLS_DN_OFFLINE);
		hfi2_start_link(ppd);
	}
}

/*
 * Several pieces of LNI information were cached for SMA in ppd.
 * Reset these on link down
 */
static void reset_neighbor_info(struct hfi2_pportdata *ppd)
{
	ppd->neighbor_guid = 0;
	ppd->neighbor_port_number = 0;
	ppd->neighbor_type = 0;
	ppd->neighbor_fm_security = 0;
}

static const char *const link_down_reason_strs[] = {
	[OPA_LINKDOWN_REASON_NONE] = "None",
	[OPA_LINKDOWN_REASON_RCV_ERROR_0] = "Receive error 0",
	[OPA_LINKDOWN_REASON_BAD_PKT_LEN] = "Bad packet length",
	[OPA_LINKDOWN_REASON_PKT_TOO_LONG] = "Packet too long",
	[OPA_LINKDOWN_REASON_PKT_TOO_SHORT] = "Packet too short",
	[OPA_LINKDOWN_REASON_BAD_SLID] = "Bad SLID",
	[OPA_LINKDOWN_REASON_BAD_DLID] = "Bad DLID",
	[OPA_LINKDOWN_REASON_BAD_L2] = "Bad L2",
	[OPA_LINKDOWN_REASON_BAD_SC] = "Bad SC",
	[OPA_LINKDOWN_REASON_RCV_ERROR_8] = "Receive error 8",
	[OPA_LINKDOWN_REASON_BAD_MID_TAIL] = "Bad mid tail",
	[OPA_LINKDOWN_REASON_RCV_ERROR_10] = "Receive error 10",
	[OPA_LINKDOWN_REASON_PREEMPT_ERROR] = "Preempt error",
	[OPA_LINKDOWN_REASON_PREEMPT_VL15] = "Preempt vl15",
	[OPA_LINKDOWN_REASON_BAD_VL_MARKER] = "Bad VL marker",
	[OPA_LINKDOWN_REASON_RCV_ERROR_14] = "Receive error 14",
	[OPA_LINKDOWN_REASON_RCV_ERROR_15] = "Receive error 15",
	[OPA_LINKDOWN_REASON_BAD_HEAD_DIST] = "Bad head distance",
	[OPA_LINKDOWN_REASON_BAD_TAIL_DIST] = "Bad tail distance",
	[OPA_LINKDOWN_REASON_BAD_CTRL_DIST] = "Bad control distance",
	[OPA_LINKDOWN_REASON_BAD_CREDIT_ACK] = "Bad credit ack",
	[OPA_LINKDOWN_REASON_UNSUPPORTED_VL_MARKER] = "Unsupported VL marker",
	[OPA_LINKDOWN_REASON_BAD_PREEMPT] = "Bad preempt",
	[OPA_LINKDOWN_REASON_BAD_CONTROL_FLIT] = "Bad control flit",
	[OPA_LINKDOWN_REASON_EXCEED_MULTICAST_LIMIT] = "Exceed multicast limit",
	[OPA_LINKDOWN_REASON_RCV_ERROR_24] = "Receive error 24",
	[OPA_LINKDOWN_REASON_RCV_ERROR_25] = "Receive error 25",
	[OPA_LINKDOWN_REASON_RCV_ERROR_26] = "Receive error 26",
	[OPA_LINKDOWN_REASON_RCV_ERROR_27] = "Receive error 27",
	[OPA_LINKDOWN_REASON_RCV_ERROR_28] = "Receive error 28",
	[OPA_LINKDOWN_REASON_RCV_ERROR_29] = "Receive error 29",
	[OPA_LINKDOWN_REASON_RCV_ERROR_30] = "Receive error 30",
	[OPA_LINKDOWN_REASON_EXCESSIVE_BUFFER_OVERRUN] =
		"Excessive buffer overrun",
	[OPA_LINKDOWN_REASON_UNKNOWN] = "Unknown",
	[OPA_LINKDOWN_REASON_REBOOT] = "Reboot",
	[OPA_LINKDOWN_REASON_NEIGHBOR_UNKNOWN] = "Neighbor unknown",
	[OPA_LINKDOWN_REASON_FM_BOUNCE] = "FM bounce",
	[OPA_LINKDOWN_REASON_SPEED_POLICY] = "Speed policy",
	[OPA_LINKDOWN_REASON_WIDTH_POLICY] = "Width policy",
	[OPA_LINKDOWN_REASON_DISCONNECTED] = "Disconnected",
	[OPA_LINKDOWN_REASON_LOCAL_MEDIA_NOT_INSTALLED] =
		"Local media not installed",
	[OPA_LINKDOWN_REASON_NOT_INSTALLED] = "Not installed",
	[OPA_LINKDOWN_REASON_CHASSIS_CONFIG] = "Chassis config",
	[OPA_LINKDOWN_REASON_END_TO_END_NOT_INSTALLED] =
		"End to end not installed",
	[OPA_LINKDOWN_REASON_POWER_POLICY] = "Power policy",
	[OPA_LINKDOWN_REASON_LINKSPEED_POLICY] = "Link speed policy",
	[OPA_LINKDOWN_REASON_LINKWIDTH_POLICY] = "Link width policy",
	[OPA_LINKDOWN_REASON_SWITCH_MGMT] = "Switch management",
	[OPA_LINKDOWN_REASON_SMA_DISABLED] = "SMA disabled",
	[OPA_LINKDOWN_REASON_TRANSIENT] = "Transient"
};

static const char *link_down_reason_str(u8 reason)
{
	const char *str = NULL;

	if (reason < ARRAY_SIZE(link_down_reason_strs))
		str = link_down_reason_strs[reason];
	if (!str)
		str = "(invalid)";

	return str;
}

/*
 * Handle a link down interrupt from the 8051.
 *
 * This is a work-queue function outside of the interrupt.
 */
void hfi2_handle_link_down(struct work_struct *work)
{
	u8 lcl_reason, neigh_reason = 0;
	u8 link_down_reason;
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, link_down_work);
	int was_up;
	static const char ldr_str[] = "Link down reason: ";

	if ((ppd->host_link_state &
	     (HLS_DN_POLL | HLS_VERIFY_CAP | HLS_GOING_UP)) &&
	    ppd->port_type == PORT_TYPE_FIXED)
		ppd->offline_disabled_reason =
			HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NOT_INSTALLED);

	/* Go offline first, then deal with reading/writing through 8051 */
	was_up = !!(ppd->host_link_state & HLS_UP);
	hfi2_set_link_state(ppd, HLS_DN_OFFLINE);
	xchg(&ppd->is_link_down_queued, 0);

	if (was_up) {
		lcl_reason = 0;
		/* link down reason is only valid if the link was up */
		hfi2_read_link_down_reason(ppd->dd, &link_down_reason);
		switch (link_down_reason) {
		case LDR_LINK_TRANSFER_ACTIVE_LOW:
			/* the link went down, no idle message reason */
			ppd_dev_info(ppd, "%sUnexpected link down\n", ldr_str);
			break;
		case LDR_RECEIVED_LINKDOWN_IDLE_MSG:
			/*
			 * The neighbor reason is only valid if an idle message
			 * was received for it.
			 */
			hfi2_read_planned_down_reason_code(ppd->dd, &neigh_reason);
			ppd_dev_info(ppd,
				     "%sNeighbor link down message %d, %s\n",
				     ldr_str, neigh_reason,
				     link_down_reason_str(neigh_reason));
			break;
		case LDR_RECEIVED_HOST_OFFLINE_REQ:
			ppd_dev_info(ppd,
				     "%sHost requested link to go offline\n",
				     ldr_str);
			break;
		default:
			ppd_dev_info(ppd, "%sUnknown reason 0x%x\n", ldr_str,
				     link_down_reason);
			break;
		}

		/*
		 * If no reason, assume peer-initiated but missed
		 * LinkGoingDown idle flits.
		 */
		if (neigh_reason == 0)
			lcl_reason = OPA_LINKDOWN_REASON_NEIGHBOR_UNKNOWN;
	} else {
		/* went down while polling or going up */
		lcl_reason = OPA_LINKDOWN_REASON_TRANSIENT;
	}

	hfi2_set_link_down_reason(ppd, lcl_reason, neigh_reason, 0);

	/* inform the SMA when the link transitions from up to down */
	if (was_up && ppd->local_link_down_reason.sma == 0 &&
	    ppd->neigh_link_down_reason.sma == 0) {
		ppd->local_link_down_reason.sma =
			ppd->local_link_down_reason.latest;
		ppd->neigh_link_down_reason.sma =
			ppd->neigh_link_down_reason.latest;
	}

	reset_neighbor_info(ppd);

	/* disable the port */
	hfi2_clear_rcvctrl(ppd, RCV_CTRL_RCV_PORT_ENABLE_SMASK);

	/*
	 * If there is no cable attached, turn the DC off. Otherwise,
	 * start the link bring up.
	 */
	if (ppd->port_type == PORT_TYPE_QSFP && !hfi2_qsfp_mod_present(ppd))
		hfi2_dc_shutdown(ppd->dd);
	else
		hfi2_start_link(ppd);
}

void hfi2_wfr_handle_link_bounce(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, link_bounce_work);

	/*
	 * Only do something if the link is currently up.
	 */
	if (ppd->host_link_state & HLS_UP) {
		hfi2_set_link_state(ppd, HLS_DN_OFFLINE);
		hfi2_start_link(ppd);
	} else {
		ppd_dev_info(ppd, "%s: link not up (%s), nothing to do\n",
			     __func__,
			     hfi2_link_state_name(ppd->host_link_state));
	}
}

/*
 * Mask conversion: Capability exchange to Port LTP.  The capability
 * exchange has an implicit 16b CRC that is mandatory.
 */
int hfi2_cap_to_port_ltp(int cap)
{
	int port_ltp = PORT_LTP_CRC_MODE_16; /* this mode is mandatory */

	if (cap & CAP_CRC_14B)
		port_ltp |= PORT_LTP_CRC_MODE_14;
	if (cap & CAP_CRC_48B)
		port_ltp |= PORT_LTP_CRC_MODE_48;
	if (cap & CAP_CRC_12B_16B_PER_LANE)
		port_ltp |= PORT_LTP_CRC_MODE_PER_LANE;

	return port_ltp;
}

/*
 * Convert an OPA Port LTP mask to capability mask
 */
int hfi2_port_ltp_to_cap(int port_ltp)
{
	int cap_mask = 0;

	if (port_ltp & PORT_LTP_CRC_MODE_14)
		cap_mask |= CAP_CRC_14B;
	if (port_ltp & PORT_LTP_CRC_MODE_48)
		cap_mask |= CAP_CRC_48B;
	if (port_ltp & PORT_LTP_CRC_MODE_PER_LANE)
		cap_mask |= CAP_CRC_12B_16B_PER_LANE;

	return cap_mask;
}

/*
 * Convert a single DC LCB CRC mode to an OPA Port LTP mask.
 */
static int lcb_to_port_ltp(int lcb_crc)
{
	int port_ltp = 0;

	if (lcb_crc == LCB_CRC_12B_16B_PER_LANE)
		port_ltp = PORT_LTP_CRC_MODE_PER_LANE;
	else if (lcb_crc == LCB_CRC_48B)
		port_ltp = PORT_LTP_CRC_MODE_48;
	else if (lcb_crc == LCB_CRC_14B)
		port_ltp = PORT_LTP_CRC_MODE_14;
	else
		port_ltp = PORT_LTP_CRC_MODE_16;

	return port_ltp;
}



/*
 * Convert the given link width to the OPA link width bitmask.
 */
static u16 link_width_to_bits(struct hfi2_devdata *dd, u16 width)
{
	switch (width) {
	case 0:
		/*
		 * Quick linkup does not set the width.
		 * Just set it to 4x without complaint.
		 */
		if (hfi2_quick_linkup)
			return OPA_LINK_WIDTH_4X;
		return 0; /* no lanes up */
	case 1:
		return OPA_LINK_WIDTH_1X;
	case 2:
		return OPA_LINK_WIDTH_2X;
	case 3:
		return OPA_LINK_WIDTH_3X;
	case 4:
		return OPA_LINK_WIDTH_4X;
	default:
		dd_dev_info(dd, "%s: invalid width %d, using 4\n", __func__,
			    width);
		return OPA_LINK_WIDTH_4X;
	}
}

/*
 * Do a population count on the bottom nibble.
 */
static const u8 bit_counts[16] = { 0, 1, 1, 2, 1, 2, 2, 3,
				   1, 2, 2, 3, 2, 3, 3, 4 };

static inline u8 nibble_to_count(u8 nibble)
{
	return bit_counts[nibble & 0xf];
}

/*
 * Read the active lane information from the 8051 registers and return
 * their widths.
 *
 * Active lane information is found in these 8051 registers:
 *	enable_lane_tx
 *	enable_lane_rx
 */
static void get_link_widths(struct hfi2_pportdata *ppd, u16 *tx_width,
			    u16 *rx_width)
{
	struct hfi2_devdata *dd = ppd->dd;
	u16 tx, rx;
	u8 enable_lane_rx;
	u8 enable_lane_tx;
	u8 tx_polarity_inversion;
	u8 rx_polarity_inversion;
	u8 max_rate;

	/* read the active lanes */
	hfi2_read_tx_settings(dd, &enable_lane_tx, &tx_polarity_inversion,
			 &rx_polarity_inversion, &max_rate);
	hfi2_read_local_lni(dd, &enable_lane_rx);

	/* convert to counts */
	tx = nibble_to_count(enable_lane_tx);
	rx = nibble_to_count(enable_lane_rx);

	/*
	 * Set link_speed_active here, overriding what was set in
	 * hfi2_handle_verify_cap().  The ASIC 8051 firmware does not correctly
	 * set the max_rate field in hfi2_handle_verify_cap until v0.19.
	 */
	if ((dd->icode == ICODE_RTL_SILICON) &&
	    (dd->dc8051_ver < dc8051_ver(0, 19, 0))) {
		/* max_rate: 0 = 12.5G, 1 = 25G */
		switch (max_rate) {
		case 0:
			ppd->link_speed_active = OPA_LINK_SPEED_12_5G;
			break;
		case 1:
			ppd->link_speed_active = OPA_LINK_SPEED_25G;
			break;
		default:
			ppd_dev_err(ppd,
				    "%s: unexpected max rate %d, using 25Gb\n",
				    __func__, (int)max_rate);
			ppd->link_speed_active = OPA_LINK_SPEED_25G;
			break;
		}
	}

	ppd_dev_info(
		ppd,
		"Fabric active lanes (width): tx 0x%x (%d), rx 0x%x (%d)\n",
		enable_lane_tx, tx, enable_lane_rx, rx);
	*tx_width = link_width_to_bits(dd, tx);
	*rx_width = link_width_to_bits(dd, rx);
}

/*
 * Read verify_cap_local_fm_link_width[1] to obtain the link widths.
 * Valid after the end of VerifyCap and during LinkUp.  Does not change
 * after link up.  I.e. look elsewhere for downgrade information.
 *
 * Bits are:
 *	+ bits [7:4] contain the number of active transmitters
 *	+ bits [3:0] contain the number of active receivers
 * These are numbers 1 through 4 and can be different values if the
 * link is asymmetric.
 *
 * verify_cap_local_fm_link_width[0] retains its original value.
 */
static void get_linkup_widths(struct hfi2_pportdata *ppd, u16 *tx_width,
			      u16 *rx_width)
{
	struct hfi2_devdata *dd = ppd->dd;
	u16 widths, tx, rx;
	u8 misc_bits, local_flags;
	u16 active_tx, active_rx;

	hfi2_read_vc_local_link_mode(dd, &misc_bits, &local_flags, &widths);
	tx = widths >> 12;
	rx = (widths >> 8) & 0xf;

	*tx_width = link_width_to_bits(dd, tx);
	*rx_width = link_width_to_bits(dd, rx);

	/* print the active widths */
	get_link_widths(ppd, &active_tx, &active_rx);
}

/*
 * Set ppd->link_width_active and ppd->link_width_downgrade_active using
 * hardware information when the link first comes up.
 *
 * The link width is not available until after VerifyCap.AllFramesReceived
 * (the trigger for hfi2_handle_verify_cap), so this is outside that routine
 * and should be called when the 8051 signals linkup.
 */
void hfi2_get_linkup_link_widths(struct hfi2_pportdata *ppd)
{
	/*
	 * WFR queries the DC for link widths after LNI. JKR does not use
	 * the DC for this; hardcode the known link parameters instead.
	 */
	if (ppd->dd->params->chip_type == CHIP_WFR) {
		u16 tx_width, rx_width;

		/* get end-of-LNI link widths */
		get_linkup_widths(ppd, &tx_width, &rx_width);

		/* use tx_width as the link is supposed to be symmetric on link up */
		ppd->link_width_active = tx_width;
	} else {
		/*
		 * JKR operates at 25G/4X. Set speed and width explicitly
		 * since JKR does not negotiate these via the DC.
		 */
		ppd->link_speed_active = OPA_LINK_SPEED_25G;
		ppd->link_speed_enabled = OPA_LINK_SPEED_25G;
		ppd->link_width_active = OPA_LINK_WIDTH_4X;
	}
		// FIXME: overwrite the "real" default active of 100G so the
		// in case the opa tools fail because of an unknown speed.
	/* link width downgrade active (LWD.A) starts out matching LW.A */
	ppd->link_width_downgrade_tx_active = ppd->link_width_active;
	ppd->link_width_downgrade_rx_active = ppd->link_width_active;
	/* per OPA spec, on link up LWD.E resets to LWD.S */
	ppd->link_width_downgrade_enabled = ppd->link_width_downgrade_supported;
	/* cache the active egress rate (units {10^6 bits/sec]) */
	ppd->current_egress_rate = active_egress_rate(ppd);
}

/*
 * Handle a verify capabilities interrupt from the 8051.
 *
 * This is a work-queue function outside of the interrupt.
 */
void hfi2_handle_verify_cap(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, link_vc_work);
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	u8 power_management;
	u8 continuous;
	u8 vcu;
	u8 vau;
	u8 z;
	u16 vl15buf;
	u16 link_widths;
	u16 crc_mask;
	u16 crc_val;
	u16 device_id;
	u16 active_tx, active_rx;
	u8 partner_supported_crc;
	u8 remote_tx_rate;
	u8 device_rev;

	hfi2_set_link_state(ppd, HLS_VERIFY_CAP);

	lcb_shutdown(dd, 0);

	hfi2_read_vc_remote_phy(dd, &power_management, &continuous);
	hfi2_read_vc_remote_fabric(dd, &vau, &z, &vcu, &vl15buf,
			      &partner_supported_crc);
	hfi2_read_vc_remote_link_width(dd, &remote_tx_rate, &link_widths);
	hfi2_read_remote_device_id(dd, &device_id, &device_rev);

	/* print the active widths */
	get_link_widths(ppd, &active_tx, &active_rx);
	ppd_dev_info(
		ppd,
		"Peer PHY: power management 0x%x, continuous updates 0x%x\n",
		(int)power_management, (int)continuous);
	ppd_dev_info(
		ppd,
		"Peer Fabric: vAU %d, Z %d, vCU %d, vl15 credits 0x%x, CRC sizes 0x%x\n",
		(int)vau, (int)z, (int)vcu, (int)vl15buf,
		(int)partner_supported_crc);
	ppd_dev_info(ppd, "Peer Link Width: tx rate 0x%x, widths 0x%x\n",
		     (u32)remote_tx_rate, (u32)link_widths);
	ppd_dev_info(ppd, "Peer Device ID: 0x%04x, Revision 0x%02x\n",
		     (u32)device_id, (u32)device_rev);
	/*
	 * The peer vAU value just read is the peer receiver value.  HFI does
	 * not support a transmit vAU of 0 (AU == 8).  We advertised that
	 * with Z=1 in the fabric capabilities sent to the peer.  The peer
	 * will see our Z=1, and, if it advertised a vAU of 0, will move its
	 * receive to vAU of 1 (AU == 16).  Do the same here.  We do not care
	 * about the peer Z value - our sent vAU is 3 (hardwired) and is not
	 * subject to the Z value exception.
	 */
	if (vau == 0)
		vau = 1;
	hfi2_set_up_vau(ppd, vau);

	/*
	 * Set VL15 credits to 0 in global credit register. Cache remote VL15
	 * credits value and wait for link-up interrupt ot set it.
	 */
	hfi2_set_up_vl15(ppd, 0);
	dd->vl15buf_cached = vl15buf;

	/* set up the LCB CRC mode */
	crc_mask = ppd->port_crc_mode_enabled & partner_supported_crc;

	/* order is important: use the lowest bit in common */
	if (crc_mask & CAP_CRC_14B)
		crc_val = LCB_CRC_14B;
	else if (crc_mask & CAP_CRC_48B)
		crc_val = LCB_CRC_48B;
	else if (crc_mask & CAP_CRC_12B_16B_PER_LANE)
		crc_val = LCB_CRC_12B_16B_PER_LANE;
	else
		crc_val = LCB_CRC_16B;

	ppd_dev_info(ppd, "Final LCB CRC mode: %d\n", (int)crc_val);
	hfi2_write_csr(dd, DC_LCB_CFG_CRC_MODE,
		       (u64)crc_val << DC_LCB_CFG_CRC_MODE_TX_VAL_SHIFT);

	/* set (14b only) or clear sideband credit */
	reg = read_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_ctrl_reg);
	if (crc_val == LCB_CRC_14B && hfi2_crc_14b_sideband) {
		write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_ctrl_reg,
				reg | SEND_CM_CTRL_FORCE_CREDIT_MODE_SMASK);
	} else {
		write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_ctrl_reg,
				reg & ~SEND_CM_CTRL_FORCE_CREDIT_MODE_SMASK);
	}

	ppd->link_speed_active = 0; /* invalid value */
	if (dd->dc8051_ver < dc8051_ver(0, 20, 0)) {
		/* remote_tx_rate: 0 = 12.5G, 1 = 25G */
		switch (remote_tx_rate) {
		case 0:
			ppd->link_speed_active = OPA_LINK_SPEED_12_5G;
			break;
		case 1:
			ppd->link_speed_active = OPA_LINK_SPEED_25G;
			break;
		}
	} else {
		/* actual rate is highest bit of the ANDed rates */
		u8 rate = remote_tx_rate & ppd->local_tx_rate;

		if (rate & 2)
			ppd->link_speed_active = OPA_LINK_SPEED_25G;
		else if (rate & 1)
			ppd->link_speed_active = OPA_LINK_SPEED_12_5G;
	}
	if (ppd->link_speed_active == 0) {
		ppd_dev_err(ppd,
			    "%s: unexpected remote tx rate %d, using 25Gb\n",
			    __func__, (int)remote_tx_rate);
		ppd->link_speed_active = OPA_LINK_SPEED_25G;
	}

	/*
	 * Cache the values of the supported, enabled, and active
	 * LTP CRC modes to return in 'portinfo' queries. But the bit
	 * flags that are returned in the portinfo query differ from
	 * what's in the hfi2_link_crc_mask, crc_sizes, and crc_val
	 * variables. Convert these here.
	 */
	ppd->port_ltp_crc_mode = hfi2_cap_to_port_ltp(hfi2_link_crc_mask) << 8;
	/* supported crc modes */
	ppd->port_ltp_crc_mode |= hfi2_cap_to_port_ltp(ppd->port_crc_mode_enabled)
				  << 4;
	/* enabled crc modes */
	ppd->port_ltp_crc_mode |= lcb_to_port_ltp(crc_val);
	/* active crc mode */

	/* set up the remote credit return table */
	hfi2_assign_remote_cm_au_table(ppd, vcu);

	/*
	 * The LCB is reset on entry to hfi2_handle_verify_cap(), so this must
	 * be applied on every link up.
	 *
	 * Adjust LCB error kill enable to kill the link if
	 * these RBUF errors are seen:
	 *	REPLAY_BUF_MBE_SMASK
	 *	FLIT_INPUT_BUF_MBE_SMASK
	 */
	if (hfi2_is_ax(dd)) { /* fixed in B0 */
		reg = hfi2_read_csr(dd, DC_LCB_CFG_LINK_KILL_EN);
		reg |= DC_LCB_CFG_LINK_KILL_EN_REPLAY_BUF_MBE_SMASK |
		       DC_LCB_CFG_LINK_KILL_EN_FLIT_INPUT_BUF_MBE_SMASK;
		hfi2_write_csr(dd, DC_LCB_CFG_LINK_KILL_EN, reg);
	}

	/* pull LCB fifos out of reset - all fifo clocks must be stable */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 0);

	/* give 8051 access to the LCB CSRs */
	hfi2_write_csr(dd, DC_LCB_ERR_EN, 0); /* mask LCB errors */
	set_8051_lcb_access(dd);

	/* tell the 8051 to go to LinkUp */
	hfi2_set_link_state(ppd, HLS_GOING_UP);
}

/**
 * hfi2_apply_link_downgrade_policy - Apply the link width downgrade enabled
 * policy against the current active link widths.
 * @ppd: info of physical Hfi port
 * @refresh_widths: True indicates link downgrade event
 * @return: True indicates a successful link downgrade. False indicates
 *	    link downgrade event failed and the link will bounce back to
 *	    default link width.
 *
 * Called when the enabled policy changes or the active link widths
 * change.
 * Refresh_widths indicates that a link downgrade occurred. The
 * link_downgraded variable is set by refresh_widths and
 * determines the success/failure of the policy application.
 */
bool hfi2_apply_link_downgrade_policy(struct hfi2_pportdata *ppd,
				      bool refresh_widths)
{
	int do_bounce = 0;
	int tries;
	u16 lwde;
	u16 tx, rx;
	bool link_downgraded = refresh_widths;

	/* use the hls lock to avoid a race with actual link up */
	tries = 0;
retry:
	mutex_lock(&ppd->hls_lock);
	/* only apply if the link is up */
	if (ppd->host_link_state & HLS_DOWN) {
		/* still going up..wait and retry */
		if (ppd->host_link_state & HLS_GOING_UP) {
			if (++tries < 1000) {
				mutex_unlock(&ppd->hls_lock);
				usleep_range(100, 120); /* arbitrary */
				goto retry;
			}
			ppd_dev_err(
				ppd,
				"%s: giving up waiting for link state change\n",
				__func__);
		}
		goto done;
	}

	lwde = ppd->link_width_downgrade_enabled;

	if (refresh_widths) {
		get_link_widths(ppd, &tx, &rx);
		ppd->link_width_downgrade_tx_active = tx;
		ppd->link_width_downgrade_rx_active = rx;
	}

	if (ppd->link_width_downgrade_tx_active == 0 ||
	    ppd->link_width_downgrade_rx_active == 0) {
		/* the 8051 reported a dead link as a downgrade */
		ppd_dev_err(ppd,
			    "Link downgrade is really a link down, ignoring\n");
		link_downgraded = false;
	} else if (lwde == 0) {
		/* downgrade is disabled */

		/* bounce if not at starting active width */
		if ((ppd->link_width_active !=
		     ppd->link_width_downgrade_tx_active) ||
		    (ppd->link_width_active !=
		     ppd->link_width_downgrade_rx_active)) {
			ppd_dev_err(
				ppd,
				"Link downgrade is disabled and link has downgraded, downing link\n");
			ppd_dev_err(
				ppd,
				"  original 0x%x, tx active 0x%x, rx active 0x%x\n",
				ppd->link_width_active,
				ppd->link_width_downgrade_tx_active,
				ppd->link_width_downgrade_rx_active);
			do_bounce = 1;
			link_downgraded = false;
		}
	} else if ((lwde & ppd->link_width_downgrade_tx_active) == 0 ||
		   (lwde & ppd->link_width_downgrade_rx_active) == 0) {
		/* Tx or Rx is outside the enabled policy */
		ppd_dev_err(
			ppd,
			"Link is outside of downgrade allowed, downing link\n");
		ppd_dev_err(ppd,
			    "  enabled 0x%x, tx active 0x%x, rx active 0x%x\n",
			    lwde, ppd->link_width_downgrade_tx_active,
			    ppd->link_width_downgrade_rx_active);
		do_bounce = 1;
		link_downgraded = false;
	}

done:
	mutex_unlock(&ppd->hls_lock);

	if (do_bounce) {
		hfi2_set_link_down_reason(ppd, OPA_LINKDOWN_REASON_WIDTH_POLICY,
					  0, OPA_LINKDOWN_REASON_WIDTH_POLICY);
		hfi2_set_link_state(ppd, HLS_DN_OFFLINE);
		hfi2_start_link(ppd);
	}

	return link_downgraded;
}

/*
 * Handle a link downgrade interrupt from the 8051.
 *
 * This is a work-queue function outside of the interrupt.
 */
void hfi2_handle_link_downgrade(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, link_downgrade_work);

	ppd_dev_info(ppd, "8051: Link width downgrade\n");
	if (hfi2_apply_link_downgrade_policy(ppd, true))
		hfi2_update_xmit_counters(ppd,
					  ppd->link_width_downgrade_tx_active);
}

static char *dcc_err_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, dcc_err_flags,
			   ARRAY_SIZE(dcc_err_flags));
}

static char *lcb_err_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, lcb_err_flags,
			   ARRAY_SIZE(lcb_err_flags));
}

static char *dc8051_err_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, dc8051_err_flags,
			   ARRAY_SIZE(dc8051_err_flags));
}

static char *dc8051_info_err_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, dc8051_info_err_flags,
			   ARRAY_SIZE(dc8051_info_err_flags));
}

static char *dc8051_info_host_msg_string(char *buf, int buf_len, u64 flags)
{
	return hfi2_flag_string(buf, buf_len, flags, dc8051_info_host_msg_flags,
			   ARRAY_SIZE(dc8051_info_host_msg_flags));
}

void hfi2_handle_8051_interrupt(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	struct hfi2_pportdata *ppd = dd->pport;
	u64 info, err, host_msg;
	int queue_link_down = 0;
	char buf[96];

	/* look at the flags */
	if (reg & DC_DC8051_ERR_FLG_SET_BY_8051_SMASK) {
		/* 8051 information set by firmware */
		/* read DC8051_DBG_ERR_INFO_SET_BY_8051 for details */
		info = hfi2_read_csr(dd, DC_DC8051_DBG_ERR_INFO_SET_BY_8051);
		err = (info >> DC_DC8051_DBG_ERR_INFO_SET_BY_8051_ERROR_SHIFT) &
		      DC_DC8051_DBG_ERR_INFO_SET_BY_8051_ERROR_MASK;
		host_msg = (info >>
			    DC_DC8051_DBG_ERR_INFO_SET_BY_8051_HOST_MSG_SHIFT) &
			   DC_DC8051_DBG_ERR_INFO_SET_BY_8051_HOST_MSG_MASK;

		/*
		 * Handle error flags.
		 */
		if (err & FAILED_LNI) {
			/*
			 * LNI error indications are cleared by the 8051
			 * only when starting polling.  Only pay attention
			 * to them when in the states that occur during
			 * LNI.
			 */
			if (ppd->host_link_state &
			    (HLS_DN_POLL | HLS_VERIFY_CAP | HLS_GOING_UP)) {
				queue_link_down = 1;
				ppd_dev_info(ppd, "Link error: %s\n",
					     dc8051_info_err_string(
						     buf, sizeof(buf),
						     err & FAILED_LNI));
			}
			err &= ~(u64)FAILED_LNI;
		}
		/* unknown frames can happen durning LNI, just count */
		if (err & UNKNOWN_FRAME) {
			ppd->unknown_frame_count++;
			err &= ~(u64)UNKNOWN_FRAME;
		}
		if (err) {
			/* report remaining errors, but do not do anything */
			ppd_dev_err(ppd, "8051 info error: %s\n",
				    dc8051_info_err_string(buf, sizeof(buf),
							   err));
		}

		/*
		 * Handle host message flags.
		 */
		if (host_msg & HOST_REQ_DONE) {
			/*
			 * Presently, the driver does a busy wait for
			 * host requests to complete.  This is only an
			 * informational message.
			 * NOTE: The 8051 clears the host message
			 * information *on the next 8051 command*.
			 * Therefore, when linkup is achieved,
			 * this flag will still be set.
			 */
			host_msg &= ~(u64)HOST_REQ_DONE;
		}
		if (host_msg & BC_SMA_MSG) {
			queue_work(ppd->link_wq, &ppd->sma_message_work);
			host_msg &= ~(u64)BC_SMA_MSG;
		}
		if (host_msg & LINKUP_ACHIEVED) {
			ppd_dev_info(ppd, "8051: Link up\n");
			queue_work(ppd->link_wq, &ppd->link_up_work);
			host_msg &= ~(u64)LINKUP_ACHIEVED;
		}
		if (host_msg & EXT_DEVICE_CFG_REQ) {
			handle_8051_request(ppd);
			host_msg &= ~(u64)EXT_DEVICE_CFG_REQ;
		}
		if (host_msg & VERIFY_CAP_FRAME) {
			queue_work(ppd->link_wq, &ppd->link_vc_work);
			host_msg &= ~(u64)VERIFY_CAP_FRAME;
		}
		if (host_msg & LINK_GOING_DOWN) {
			const char *extra = "";
			/* no downgrade action needed if going down */
			if (host_msg & LINK_WIDTH_DOWNGRADED) {
				host_msg &= ~(u64)LINK_WIDTH_DOWNGRADED;
				extra = " (ignoring downgrade)";
			}
			dd_dev_info(dd, "8051: Link down%s\n", extra);
			queue_link_down = 1;
			host_msg &= ~(u64)LINK_GOING_DOWN;
		}
		if (host_msg & LINK_WIDTH_DOWNGRADED) {
			queue_work(ppd->link_wq, &ppd->link_downgrade_work);
			host_msg &= ~(u64)LINK_WIDTH_DOWNGRADED;
		}
		if (host_msg) {
			/* report remaining messages, but do not do anything */
			ppd_dev_info(ppd, "8051 info host message: %s\n",
				     dc8051_info_host_msg_string(
					     buf, sizeof(buf), host_msg));
		}

		reg &= ~DC_DC8051_ERR_FLG_SET_BY_8051_SMASK;
	}
	if (reg & DC_DC8051_ERR_FLG_LOST_8051_HEART_BEAT_SMASK) {
		/*
		 * Lost the 8051 heartbeat.  If this happens, we
		 * receive constant interrupts about it.  Disable
		 * the interrupt after the first.
		 */
		ppd_dev_err(ppd, "Lost 8051 heartbeat\n");
		hfi2_write_csr(
			dd, DC_DC8051_ERR_EN,
			hfi2_read_csr(dd, DC_DC8051_ERR_EN) &
				~DC_DC8051_ERR_EN_LOST_8051_HEART_BEAT_SMASK);

		reg &= ~DC_DC8051_ERR_FLG_LOST_8051_HEART_BEAT_SMASK;
	}
	if (reg) {
		/* report the error, but do not do anything */
		ppd_dev_err(ppd, "8051 error: %s\n",
			    dc8051_err_string(buf, sizeof(buf), reg));
	}

	if (queue_link_down) {
		/*
		 * if the link is already going down or disabled, do not
		 * queue another. If there's a link down entry already
		 * queued, don't queue another one.
		 */
		if ((ppd->host_link_state &
		     (HLS_GOING_OFFLINE | HLS_LINK_COOLDOWN)) ||
		    ppd->link_enabled == 0) {
			ppd_dev_info(
				ppd,
				"%s: not queuing link down. host_link_state %x, link_enabled %x\n",
				__func__, ppd->host_link_state,
				ppd->link_enabled);
		} else {
			if (xchg(&ppd->is_link_down_queued, 1) == 1)
				ppd_dev_info(
					ppd,
					"%s: link down request already queued\n",
					__func__);
			else
				queue_work(ppd->link_wq, &ppd->link_down_work);
		}
	}
}

static const char *const fm_config_txt[] = {
	[0] = "BadHeadDist: Distance violation between two head flits",
	[1] = "BadTailDist: Distance violation between two tail flits",
	[2] = "BadCtrlDist: Distance violation between two credit control flits",
	[3] = "BadCrdAck: Credits return for unsupported VL",
	[4] = "UnsupportedVLMarker: Received VL Marker",
	[5] = "BadPreempt: Exceeded the preemption nesting level",
	[6] = "BadControlFlit: Received unsupported control flit",
	/* no 7 */
	[8] = "UnsupportedVLMarker: Received VL Marker for unconfigured or disabled VL",
};

static const char *const port_rcv_txt[] = {
	[1] = "BadPktLen: Illegal PktLen",
	[2] = "PktLenTooLong: Packet longer than PktLen",
	[3] = "PktLenTooShort: Packet shorter than PktLen",
	[4] = "BadSLID: Illegal SLID (0, using multicast as SLID, does not include security validation of SLID)",
	[5] = "BadDLID: Illegal DLID (0, doesn't match HFI)",
	[6] = "BadL2: Illegal L2 opcode",
	[7] = "BadSC: Unsupported SC",
	[9] = "BadRC: Illegal RC",
	[11] = "PreemptError: Preempting with same VL",
	[12] = "PreemptVL15: Preempting a VL15 packet",
};

#define OPA_LDR_FMCONFIG_OFFSET 16
#define OPA_LDR_PORTRCV_OFFSET 0
void hfi2_handle_dcc_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	u64 info, hdr0, hdr1;
	const char *extra;
	char buf[96];
	struct hfi2_pportdata *ppd = dd->pport;
	u8 lcl_reason = 0;
	int do_bounce = 0;

	if (reg & DCC_ERR_FLG_UNCORRECTABLE_ERR_SMASK) {
		if (!(dd->err_info_uncorrectable & OPA_EI_STATUS_SMASK)) {
			info = hfi2_read_csr(dd, DCC_ERR_INFO_UNCORRECTABLE);
			dd->err_info_uncorrectable = info & OPA_EI_CODE_SMASK;
			/* set status bit */
			dd->err_info_uncorrectable |= OPA_EI_STATUS_SMASK;
		}
		reg &= ~DCC_ERR_FLG_UNCORRECTABLE_ERR_SMASK;
	}

	if (reg & DCC_ERR_FLG_LINK_ERR_SMASK) {
		/* this counter saturates at (2^32) - 1 */
		if (ppd->link_downed < (u32)UINT_MAX)
			ppd->link_downed++;
		reg &= ~DCC_ERR_FLG_LINK_ERR_SMASK;
	}

	if (reg & DCC_ERR_FLG_FMCONFIG_ERR_SMASK) {
		u8 reason_valid = 1;

		info = hfi2_read_csr(dd, DCC_ERR_INFO_FMCONFIG);
		if (!(dd->err_info_fmconfig & OPA_EI_STATUS_SMASK)) {
			dd->err_info_fmconfig = info & OPA_EI_CODE_SMASK;
			/* set status bit */
			dd->err_info_fmconfig |= OPA_EI_STATUS_SMASK;
		}
		switch (info) {
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
			extra = fm_config_txt[info];
			break;
		case 8:
			extra = fm_config_txt[info];
			if (ppd->port_error_action &
			    OPA_PI_MASK_FM_CFG_UNSUPPORTED_VL_MARKER) {
				do_bounce = 1;
				/*
				 * lcl_reason cannot be derived from info
				 * for this error
				 */
				lcl_reason =
					OPA_LINKDOWN_REASON_UNSUPPORTED_VL_MARKER;
			}
			break;
		default:
			reason_valid = 0;
			snprintf(buf, sizeof(buf), "reserved%lld", info);
			extra = buf;
			break;
		}

		if (reason_valid && !do_bounce) {
			do_bounce = ppd->port_error_action &
				    (1 << (OPA_LDR_FMCONFIG_OFFSET + info));
			lcl_reason = info + OPA_LINKDOWN_REASON_BAD_HEAD_DIST;
		}

		/* just report this */
		dd_dev_info_ratelimited(dd, "DCC Error: fmconfig error: %s\n",
					extra);
		reg &= ~DCC_ERR_FLG_FMCONFIG_ERR_SMASK;
	}

	if (reg & DCC_ERR_FLG_RCVPORT_ERR_SMASK) {
		u8 reason_valid = 1;

		info = hfi2_read_csr(dd, DCC_ERR_INFO_PORTRCV);
		hdr0 = hfi2_read_csr(dd, DCC_ERR_INFO_PORTRCV_HDR0);
		hdr1 = hfi2_read_csr(dd, DCC_ERR_INFO_PORTRCV_HDR1);
		if (!(dd->err_info_rcvport.status_and_code &
		      OPA_EI_STATUS_SMASK)) {
			dd->err_info_rcvport.status_and_code =
				info & OPA_EI_CODE_SMASK;
			/* set status bit */
			dd->err_info_rcvport.status_and_code |=
				OPA_EI_STATUS_SMASK;
			/*
			 * save first 2 flits in the packet that caused
			 * the error
			 */
			dd->err_info_rcvport.packet_flit1 = hdr0;
			dd->err_info_rcvport.packet_flit2 = hdr1;
		}
		switch (info) {
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 9:
		case 11:
		case 12:
			extra = port_rcv_txt[info];
			break;
		default:
			reason_valid = 0;
			snprintf(buf, sizeof(buf), "reserved%lld", info);
			extra = buf;
			break;
		}

		if (reason_valid && !do_bounce) {
			do_bounce = ppd->port_error_action &
				    (1 << (OPA_LDR_PORTRCV_OFFSET + info));
			lcl_reason = info + OPA_LINKDOWN_REASON_RCV_ERROR_0;
		}

		/* just report this */
		dd_dev_info_ratelimited(
			dd,
			"DCC Error: PortRcv error: %s\n"
			"               hdr0 0x%llx, hdr1 0x%llx\n",
			extra, hdr0, hdr1);

		reg &= ~DCC_ERR_FLG_RCVPORT_ERR_SMASK;
	}

	if (reg & DCC_ERR_FLG_EN_CSR_ACCESS_BLOCKED_UC_SMASK) {
		/* informative only */
		dd_dev_info_ratelimited(dd, "8051 access to LCB blocked\n");
		reg &= ~DCC_ERR_FLG_EN_CSR_ACCESS_BLOCKED_UC_SMASK;
	}
	if (reg & DCC_ERR_FLG_EN_CSR_ACCESS_BLOCKED_HOST_SMASK) {
		/* informative only */
		dd_dev_info_ratelimited(dd, "host access to LCB blocked\n");
		reg &= ~DCC_ERR_FLG_EN_CSR_ACCESS_BLOCKED_HOST_SMASK;
	}

	if (unlikely(hfi2_dbg_fault_suppress_err(&dd->verbs_dev)))
		reg &= ~DCC_ERR_FLG_LATE_EBP_ERR_SMASK;

	/* report any remaining errors */
	if (reg)
		dd_dev_info_ratelimited(dd, "DCC Error: %s\n",
					dcc_err_string(buf, sizeof(buf), reg));

	if (lcl_reason == 0)
		lcl_reason = OPA_LINKDOWN_REASON_UNKNOWN;

	if (do_bounce) {
		dd_dev_info_ratelimited(dd, "%s: PortErrorAction bounce\n",
					__func__);
		hfi2_set_link_down_reason(ppd, lcl_reason, 0, lcl_reason);
		queue_work(ppd->link_wq, &ppd->link_bounce_work);
	}
}

void hfi2_handle_lcb_err(struct hfi2_devdata *dd, u32 unused, u64 reg)
{
	char buf[96];

	dd_dev_info(dd, "LCB Error: %s\n",
		    lcb_err_string(buf, sizeof(buf), reg));
}

/*
 * CCE block DC interrupt.  Source is < 8.
 */
void hfi2_is_dc_int(struct hfi2_devdata *dd, unsigned int source)
{
	const struct err_reg_info *eri = &dc_errs[source];

	if (eri->handler) {
		hfi2_interrupt_clear_down(dd, 0, eri);
	} else if (source == 3 /* dc_lbm_int */) {
		/*
		 * This indicates that a parity error has occurred on the
		 * address/control lines presented to the LBM.  The error
		 * is a single pulse, there is no associated error flag,
		 * and it is non-maskable.  This is because if a parity
		 * error occurs on the request the request is dropped.
		 * This should never occur, but it is nice to know if it
		 * ever does.
		 */
		dd_dev_err(dd, "Parity error in DC LBM block\n");
	} else {
		dd_dev_err(dd, "Invalid DC interrupt %u\n", source);
	}
}
u32 hfi2_read_physical_state(struct hfi2_devdata *dd)
{
	u64 reg;

	reg = hfi2_read_csr(dd, DC_DC8051_STS_CUR_STATE);
	return (reg >> DC_DC8051_STS_CUR_STATE_PORT_SHIFT) &
	       DC_DC8051_STS_CUR_STATE_PORT_MASK;
}

u32 hfi2_read_logical_state(struct hfi2_devdata *dd)
{
	u64 reg;

	reg = hfi2_read_csr(dd, DCC_CFG_PORT_CONFIG);
	return (reg >> DCC_CFG_PORT_CONFIG_LINK_STATE_SHIFT) &
	       DCC_CFG_PORT_CONFIG_LINK_STATE_MASK;
}

static void set_logical_state(struct hfi2_devdata *dd, u32 chip_lstate)
{
	u64 reg;

	reg = hfi2_read_csr(dd, DCC_CFG_PORT_CONFIG);
	/* clear current state, set new state */
	reg &= ~DCC_CFG_PORT_CONFIG_LINK_STATE_SMASK;
	reg |= (u64)chip_lstate << DCC_CFG_PORT_CONFIG_LINK_STATE_SHIFT;
	hfi2_write_csr(dd, DCC_CFG_PORT_CONFIG, reg);
}

/*
 * Use the 8051 to read a LCB CSR.
 */
static int read_lcb_via_8051(struct hfi2_devdata *dd, u32 addr, u64 *data)
{
	u32 regno;
	int ret;

	/* register is an index of LCB registers: (offset - base) / 8 */
	regno = (addr - DC_LCB_CFG_RUN) >> 3;
	ret = hfi2_do_8051_command(dd, HCMD_READ_LCB_CSR, regno, data);
	if (ret != HCMD_SUCCESS)
		return -EBUSY;
	return 0;
}

/*
 * Provide a cache for some of the LCB registers in case the LCB is
 * unavailable.
 * (The LCB is unavailable in certain link states, for example.)
 */
struct lcb_datum {
	u32 off;
	u64 val;
};

static struct lcb_datum lcb_cache[] = {
	{ DC_LCB_ERR_INFO_RX_REPLAY_CNT, 0 },
	{ DC_LCB_ERR_INFO_SEQ_CRC_CNT, 0 },
	{ DC_LCB_ERR_INFO_REINIT_FROM_PEER_CNT, 0 },
};

static int __hfi2_read_lcb_csr(struct hfi2_pportdata *ppd, u32 addr, u64 *data);

static void update_lcb_cache(struct hfi2_pportdata *ppd)
{
	int i;
	int ret;
	u64 val;

	/* called from goto_offline() with ppd->hls_lock already held */
	for (i = 0; i < ARRAY_SIZE(lcb_cache); i++) {
		ret = __hfi2_read_lcb_csr(ppd, lcb_cache[i].off, &val);

		/* Update if we get good data */
		if (likely(ret != -EBUSY))
			lcb_cache[i].val = val;
	}
}

static int read_lcb_cache(u32 off, u64 *val)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lcb_cache); i++) {
		if (lcb_cache[i].off == off) {
			*val = lcb_cache[i].val;
			return 0;
		}
	}

	pr_warn("%s bad offset 0x%x\n", __func__, off);
	return -1;
}

/*
 * Read an LCB CSR.  Access may not be in host control, so check.
 * Caller must hold ppd->hls_lock so host_link_state cannot change
 * between the checks below and the selected access path.
 * Return 0 on success, -EBUSY on failure.
 */
static int __hfi2_read_lcb_csr(struct hfi2_pportdata *ppd, u32 addr, u64 *data)
{
	struct hfi2_devdata *dd = ppd->dd;

	/* if up, go through the 8051 for the value */
	if (ppd->host_link_state & HLS_UP)
		return read_lcb_via_8051(dd, addr, data);
	/* if going up or down, check the cache, otherwise, no access */
	if (ppd->host_link_state & (HLS_GOING_UP | HLS_GOING_OFFLINE)) {
		if (read_lcb_cache(addr, data))
			return -EBUSY;
		return 0;
	}

	/* otherwise, host has access */
	*data = hfi2_read_csr(dd, addr);
	return 0;
}

int hfi2_read_lcb_csr(struct hfi2_pportdata *ppd, u32 addr, u64 *data)
{
	int ret;

	mutex_lock(&ppd->hls_lock);
	ret = __hfi2_read_lcb_csr(ppd, addr, data);
	mutex_unlock(&ppd->hls_lock);
	return ret;
}

/*
 * Use the 8051 to write a LCB CSR.
 */
static int write_lcb_via_8051(struct hfi2_devdata *dd, u32 addr, u64 data)
{
	u32 regno;
	int ret;

	/* register is an index of LCB registers: (offset - base) / 8 */
	regno = (addr - DC_LCB_CFG_RUN) >> 3;
	ret = hfi2_do_8051_command(dd, HCMD_WRITE_LCB_CSR, regno, &data);
	if (ret != HCMD_SUCCESS)
		return -EBUSY;
	return 0;
}

/*
 * Write an LCB CSR.  Access may not be in host control, so check.
 * Caller must hold ppd->hls_lock so host_link_state cannot change
 * between the checks below and the selected access path.
 * Return 0 on success, -EBUSY on failure.
 */
static int __hfi2_write_lcb_csr(struct hfi2_pportdata *ppd, u32 addr, u64 data)
{
	struct hfi2_devdata *dd = ppd->dd;

	/* if up, go through the 8051 for the value */
	if (ppd->host_link_state & HLS_UP)
		return write_lcb_via_8051(dd, addr, data);
	/* if going up or down, no access */
	if (ppd->host_link_state & (HLS_GOING_UP | HLS_GOING_OFFLINE))
		return -EBUSY;
	/* otherwise, host has access */
	hfi2_write_csr(dd, addr, data);
	return 0;
}

int hfi2_write_lcb_csr(struct hfi2_pportdata *ppd, u32 addr, u64 data)
{
	int ret;

	mutex_lock(&ppd->hls_lock);
	ret = __hfi2_write_lcb_csr(ppd, addr, data);
	mutex_unlock(&ppd->hls_lock);
	return ret;
}

/*
 * Returns:
 *	< 0 = Linux error, not able to get access
 *	> 0 = 8051 command RETURN_CODE
 */
int hfi2_do_8051_command(struct hfi2_devdata *dd, u32 type, u64 in_data,
			   u64 *out_data)
{
	u64 reg, completed;
	int return_code;
	unsigned long timeout;

	hfi2_cdbg(DC8051, "type %d, data 0x%012llx", type, in_data);

	mutex_lock(&dd->dc8051_lock);

	/* We can't send any commands to the 8051 if it's in reset */
	if (dd->dc_shutdown) {
		return_code = -ENODEV;
		goto fail;
	}

	/*
	 * If an 8051 host command timed out previously, then the 8051 is
	 * stuck.
	 *
	 * On first timeout, attempt to reset and restart the entire DC
	 * block (including 8051). (Is this too big of a hammer?)
	 *
	 * If the 8051 times out a second time, the reset did not bring it
	 * back to healthy life. In that case, fail any subsequent commands.
	 */
	if (dd->dc8051_timed_out) {
		if (dd->dc8051_timed_out > 1) {
			dd_dev_err(
				dd,
				"Previous 8051 host command timed out, skipping command %u\n",
				type);
			return_code = -ENXIO;
			goto fail;
		}
		_dc_shutdown(dd);
		_dc_start(dd);
	}

	/*
	 * If there is no timeout, then the 8051 command interface is
	 * waiting for a command.
	 */

	/*
	 * When writing a LCB CSR, out_data contains the full value to
	 * be written, while in_data contains the relative LCB
	 * address in 7:0.  Do the work here, rather than the caller,
	 * of distrubting the write data to where it needs to go:
	 *
	 * Write data
	 *   39:00 -> in_data[47:8]
	 *   47:40 -> DC8051_CFG_EXT_DEV_0.RETURN_CODE
	 *   63:48 -> DC8051_CFG_EXT_DEV_0.RSP_DATA
	 */
	if (type == HCMD_WRITE_LCB_CSR) {
		in_data |= ((*out_data) & 0xffffffffffull) << 8;
		/* must preserve COMPLETED - it is tied to hardware */
		reg = hfi2_read_csr(dd, DC_DC8051_CFG_EXT_DEV_0);
		reg &= DC_DC8051_CFG_EXT_DEV_0_COMPLETED_SMASK;
		reg |= ((((*out_data) >> 40) & 0xff)
			<< DC_DC8051_CFG_EXT_DEV_0_RETURN_CODE_SHIFT) |
		       ((((*out_data) >> 48) & 0xffff)
			<< DC_DC8051_CFG_EXT_DEV_0_RSP_DATA_SHIFT);
		hfi2_write_csr(dd, DC_DC8051_CFG_EXT_DEV_0, reg);
	}

	/*
	 * Do two writes: the first to stabilize the type and req_data, the
	 * second to activate.
	 */
	reg = ((u64)type & DC_DC8051_CFG_HOST_CMD_0_REQ_TYPE_MASK)
		      << DC_DC8051_CFG_HOST_CMD_0_REQ_TYPE_SHIFT |
	      (in_data & DC_DC8051_CFG_HOST_CMD_0_REQ_DATA_MASK)
		      << DC_DC8051_CFG_HOST_CMD_0_REQ_DATA_SHIFT;
	hfi2_write_csr(dd, DC_DC8051_CFG_HOST_CMD_0, reg);
	reg |= DC_DC8051_CFG_HOST_CMD_0_REQ_NEW_SMASK;
	hfi2_write_csr(dd, DC_DC8051_CFG_HOST_CMD_0, reg);

	/* wait for completion, alternate: interrupt */
	timeout = jiffies + msecs_to_jiffies(DC8051_COMMAND_TIMEOUT);
	while (1) {
		reg = hfi2_read_csr(dd, DC_DC8051_CFG_HOST_CMD_1);
		completed = reg & DC_DC8051_CFG_HOST_CMD_1_COMPLETED_SMASK;
		if (completed)
			break;
		if (time_after(jiffies, timeout)) {
			dd->dc8051_timed_out++;
			dd_dev_err(dd, "8051 host command %u timeout\n", type);
			if (out_data)
				*out_data = 0;
			return_code = -ETIMEDOUT;
			goto fail;
		}
		udelay(2);
	}

	if (out_data) {
		*out_data = (reg >> DC_DC8051_CFG_HOST_CMD_1_RSP_DATA_SHIFT) &
			    DC_DC8051_CFG_HOST_CMD_1_RSP_DATA_MASK;
		if (type == HCMD_READ_LCB_CSR) {
			/* top 16 bits are in a different register */
			*out_data |=
				(hfi2_read_csr(dd, DC_DC8051_CFG_EXT_DEV_1) &
				 DC_DC8051_CFG_EXT_DEV_1_REQ_DATA_SMASK)
				<< (48 -
				    DC_DC8051_CFG_EXT_DEV_1_REQ_DATA_SHIFT);
		}
	}
	return_code = (reg >> DC_DC8051_CFG_HOST_CMD_1_RETURN_CODE_SHIFT) &
		      DC_DC8051_CFG_HOST_CMD_1_RETURN_CODE_MASK;
	dd->dc8051_timed_out = 0;
	/*
	 * Clear command for next user.
	 */
	hfi2_write_csr(dd, DC_DC8051_CFG_HOST_CMD_0, 0);

fail:
	mutex_unlock(&dd->dc8051_lock);
	return return_code;
}

int hfi2_set_physical_link_state(struct hfi2_devdata *dd, u64 state)
{
	return hfi2_do_8051_command(dd, HCMD_CHANGE_PHY_STATE, state, NULL);
}

int hfi2_load_8051_config(struct hfi2_devdata *dd, u8 field_id, u8 lane_id,
			  u32 config_data)
{
	u64 data;
	int ret;

	data = (u64)field_id << LOAD_DATA_FIELD_ID_SHIFT |
	       (u64)lane_id << LOAD_DATA_LANE_ID_SHIFT |
	       (u64)config_data << LOAD_DATA_DATA_SHIFT;
	ret = hfi2_do_8051_command(dd, HCMD_LOAD_CONFIG_DATA, data, NULL);
	if (ret != HCMD_SUCCESS) {
		dd_dev_err(dd,
			   "load 8051 config: field id %d, lane %d, err %d\n",
			   (int)field_id, (int)lane_id, ret);
	}
	return ret;
}

/*
 * Read the 8051 firmware "registers".  Use the RAM directly.  Always
 * set the result, even on error.
 * Return 0 on success, -errno on failure
 */
int hfi2_read_8051_config(struct hfi2_devdata *dd, u8 field_id, u8 lane_id,
			  u32 *result)
{
	u64 big_data;
	u32 addr;
	int ret;

	/* address start depends on the lane_id */
	if (lane_id < 4)
		addr = (4 * NUM_GENERAL_FIELDS) +
		       (lane_id * 4 * NUM_LANE_FIELDS);
	else
		addr = 0;
	addr += field_id * 4;

	/* read is in 8-byte chunks, hardware will truncate the address down */
	ret = hfi2_read_8051_data(dd, addr, 8, &big_data);

	if (ret == 0) {
		/* extract the 4 bytes we want */
		if (addr & 0x4)
			*result = (u32)(big_data >> 32);
		else
			*result = (u32)big_data;
	} else {
		*result = 0;
		dd_dev_err(dd, "%s: direct read failed, lane %d, field %d!\n",
			   __func__, lane_id, field_id);
	}

	return ret;
}

static int write_vc_local_phy(struct hfi2_devdata *dd, u8 power_management,
			      u8 continuous)
{
	u32 frame;

	frame = continuous << CONTINIOUS_REMOTE_UPDATE_SUPPORT_SHIFT |
		power_management << POWER_MANAGEMENT_SHIFT;
	return hfi2_load_8051_config(dd, VERIFY_CAP_LOCAL_PHY, GENERAL_CONFIG,
				     frame);
}

static int write_vc_local_fabric(struct hfi2_devdata *dd, u8 vau, u8 z, u8 vcu,
				 u16 vl15buf, u8 crc_sizes)
{
	u32 frame;

	frame = (u32)vau << VAU_SHIFT | (u32)z << Z_SHIFT |
		(u32)vcu << VCU_SHIFT | (u32)vl15buf << VL15BUF_SHIFT |
		(u32)crc_sizes << CRC_SIZES_SHIFT;
	return hfi2_load_8051_config(dd, VERIFY_CAP_LOCAL_FABRIC,
				     GENERAL_CONFIG, frame);
}

void hfi2_read_vc_local_link_mode(struct hfi2_devdata *dd, u8 *misc_bits,
				    u8 *flag_bits, u16 *link_widths)
{
	u32 frame;

	hfi2_read_8051_config(dd, VERIFY_CAP_LOCAL_LINK_MODE, GENERAL_CONFIG,
			      &frame);
	*misc_bits = (frame >> MISC_CONFIG_BITS_SHIFT) & MISC_CONFIG_BITS_MASK;
	*flag_bits = (frame >> LOCAL_FLAG_BITS_SHIFT) & LOCAL_FLAG_BITS_MASK;
	*link_widths = (frame >> LINK_WIDTH_SHIFT) & LINK_WIDTH_MASK;
}

static int write_vc_local_link_mode(struct hfi2_devdata *dd, u8 misc_bits,
				    u8 flag_bits, u16 link_widths)
{
	u32 frame;

	frame = (u32)misc_bits << MISC_CONFIG_BITS_SHIFT |
		(u32)flag_bits << LOCAL_FLAG_BITS_SHIFT |
		(u32)link_widths << LINK_WIDTH_SHIFT;
	return hfi2_load_8051_config(dd, VERIFY_CAP_LOCAL_LINK_MODE,
				     GENERAL_CONFIG, frame);
}

static int write_local_device_id(struct hfi2_devdata *dd, u16 device_id,
				 u8 device_rev)
{
	u32 frame;

	frame = ((u32)device_id << LOCAL_DEVICE_ID_SHIFT) |
		((u32)device_rev << LOCAL_DEVICE_REV_SHIFT);
	return hfi2_load_8051_config(dd, LOCAL_DEVICE_ID, GENERAL_CONFIG,
				     frame);
}

void hfi2_read_remote_device_id(struct hfi2_devdata *dd, u16 *device_id,
				  u8 *device_rev)
{
	u32 frame;

	hfi2_read_8051_config(dd, REMOTE_DEVICE_ID, GENERAL_CONFIG, &frame);
	*device_id = (frame >> REMOTE_DEVICE_ID_SHIFT) & REMOTE_DEVICE_ID_MASK;
	*device_rev = (frame >> REMOTE_DEVICE_REV_SHIFT) &
		      REMOTE_DEVICE_REV_MASK;
}

int hfi2_write_host_interface_version(struct hfi2_devdata *dd, u8 version)
{
	u32 frame;
	u32 mask;

	mask = (HOST_INTERFACE_VERSION_MASK << HOST_INTERFACE_VERSION_SHIFT);
	hfi2_read_8051_config(dd, RESERVED_REGISTERS, GENERAL_CONFIG, &frame);
	/* Clear, then set field */
	frame &= ~mask;
	frame |= ((u32)version << HOST_INTERFACE_VERSION_SHIFT);
	return hfi2_load_8051_config(dd, RESERVED_REGISTERS, GENERAL_CONFIG,
				     frame);
}

void hfi2_read_misc_status(struct hfi2_devdata *dd, u8 *ver_major,
			   u8 *ver_minor, u8 *ver_patch)
{
	u32 frame;

	hfi2_read_8051_config(dd, MISC_STATUS, GENERAL_CONFIG, &frame);
	*ver_major = (frame >> STS_FM_VERSION_MAJOR_SHIFT) &
		     STS_FM_VERSION_MAJOR_MASK;
	*ver_minor = (frame >> STS_FM_VERSION_MINOR_SHIFT) &
		     STS_FM_VERSION_MINOR_MASK;

	hfi2_read_8051_config(dd, VERSION_PATCH, GENERAL_CONFIG, &frame);
	*ver_patch = (frame >> STS_FM_VERSION_PATCH_SHIFT) &
		     STS_FM_VERSION_PATCH_MASK;
}

void hfi2_read_vc_remote_phy(struct hfi2_devdata *dd, u8 *power_management,
			       u8 *continuous)
{
	u32 frame;

	hfi2_read_8051_config(dd, VERIFY_CAP_REMOTE_PHY, GENERAL_CONFIG,
			      &frame);
	*power_management = (frame >> POWER_MANAGEMENT_SHIFT) &
			    POWER_MANAGEMENT_MASK;
	*continuous = (frame >> CONTINIOUS_REMOTE_UPDATE_SUPPORT_SHIFT) &
		      CONTINIOUS_REMOTE_UPDATE_SUPPORT_MASK;
}

void hfi2_read_vc_remote_fabric(struct hfi2_devdata *dd, u8 *vau, u8 *z,
				  u8 *vcu, u16 *vl15buf, u8 *crc_sizes)
{
	u32 frame;

	hfi2_read_8051_config(dd, VERIFY_CAP_REMOTE_FABRIC, GENERAL_CONFIG,
			      &frame);
	*vau = (frame >> VAU_SHIFT) & VAU_MASK;
	*z = (frame >> Z_SHIFT) & Z_MASK;
	*vcu = (frame >> VCU_SHIFT) & VCU_MASK;
	*vl15buf = (frame >> VL15BUF_SHIFT) & VL15BUF_MASK;
	*crc_sizes = (frame >> CRC_SIZES_SHIFT) & CRC_SIZES_MASK;
}

void hfi2_read_vc_remote_link_width(struct hfi2_devdata *dd,
				      u8 *remote_tx_rate, u16 *link_widths)
{
	u32 frame;

	hfi2_read_8051_config(dd, VERIFY_CAP_REMOTE_LINK_WIDTH, GENERAL_CONFIG,
			      &frame);
	*remote_tx_rate = (frame >> REMOTE_TX_RATE_SHIFT) & REMOTE_TX_RATE_MASK;
	*link_widths = (frame >> LINK_WIDTH_SHIFT) & LINK_WIDTH_MASK;
}

void hfi2_read_local_lni(struct hfi2_devdata *dd, u8 *enable_lane_rx)
{
	u32 frame;

	hfi2_read_8051_config(dd, LOCAL_LNI_INFO, GENERAL_CONFIG, &frame);
	*enable_lane_rx = (frame >> ENABLE_LANE_RX_SHIFT) & ENABLE_LANE_RX_MASK;
}

static void read_last_local_state(struct hfi2_devdata *dd, u32 *lls)
{
	hfi2_read_8051_config(dd, LAST_LOCAL_STATE_COMPLETE, GENERAL_CONFIG,
			      lls);
}

static void read_last_remote_state(struct hfi2_devdata *dd, u32 *lrs)
{
	hfi2_read_8051_config(dd, LAST_REMOTE_STATE_COMPLETE, GENERAL_CONFIG,
			      lrs);
}

void hfi2_wfr_read_link_quality(struct hfi2_pportdata *ppd, u8 *link_quality)
{
	struct hfi2_devdata *dd = ppd->dd;
	u32 frame;
	int ret;

	*link_quality = 0;
	if (ppd->host_link_state & HLS_UP) {
		ret = hfi2_read_8051_config(dd, LINK_QUALITY_INFO,
					    GENERAL_CONFIG, &frame);
		if (ret == 0)
			*link_quality = (frame >> LINK_QUALITY_SHIFT) &
					LINK_QUALITY_MASK;
	}
}

void hfi2_read_planned_down_reason_code(struct hfi2_devdata *dd, u8 *pdrrc)
{
	u32 frame;

	hfi2_read_8051_config(dd, LINK_QUALITY_INFO, GENERAL_CONFIG, &frame);
	*pdrrc = (frame >> DOWN_REMOTE_REASON_SHIFT) & DOWN_REMOTE_REASON_MASK;
}

void hfi2_read_link_down_reason(struct hfi2_devdata *dd, u8 *ldr)
{
	u32 frame;

	hfi2_read_8051_config(dd, LINK_DOWN_REASON, GENERAL_CONFIG, &frame);
	*ldr = (frame & 0xff);
}

int hfi2_read_tx_settings(struct hfi2_devdata *dd, u8 *enable_lane_tx,
			    u8 *tx_polarity_inversion,
			    u8 *rx_polarity_inversion, u8 *max_rate)
{
	u32 frame;
	int ret;

	ret = hfi2_read_8051_config(dd, TX_SETTINGS, GENERAL_CONFIG, &frame);
	*enable_lane_tx = (frame >> ENABLE_LANE_TX_SHIFT) & ENABLE_LANE_TX_MASK;
	*tx_polarity_inversion = (frame >> TX_POLARITY_INVERSION_SHIFT) &
				 TX_POLARITY_INVERSION_MASK;
	*rx_polarity_inversion = (frame >> RX_POLARITY_INVERSION_SHIFT) &
				 RX_POLARITY_INVERSION_MASK;
	*max_rate = (frame >> MAX_RATE_SHIFT) & MAX_RATE_MASK;
	return ret;
}

static int write_tx_settings(struct hfi2_devdata *dd, u8 enable_lane_tx,
			     u8 tx_polarity_inversion, u8 rx_polarity_inversion,
			     u8 max_rate)
{
	u32 frame;

	/* no need to mask, all variable sizes match field widths */
	frame = enable_lane_tx << ENABLE_LANE_TX_SHIFT |
		tx_polarity_inversion << TX_POLARITY_INVERSION_SHIFT |
		rx_polarity_inversion << RX_POLARITY_INVERSION_SHIFT |
		max_rate << MAX_RATE_SHIFT;
	return hfi2_load_8051_config(dd, TX_SETTINGS, GENERAL_CONFIG, frame);
}

/*
 * Read an idle LCB message.
 *
 * Returns 0 on success, -EINVAL on error
 */
static int read_idle_message(struct hfi2_devdata *dd, u64 type, u64 *data_out)
{
	int ret;

	ret = hfi2_do_8051_command(dd, HCMD_READ_LCB_IDLE_MSG, type, data_out);
	if (ret != HCMD_SUCCESS) {
		dd_dev_err(dd, "read idle message: type %d, err %d\n",
			   (u32)type, ret);
		return -EINVAL;
	}
	dd_dev_info(dd, "%s: read idle message 0x%llx\n", __func__, *data_out);
	/* return only the payload as we already know the type */
	*data_out >>= IDLE_PAYLOAD_SHIFT;
	return 0;
}

/*
 * Read an idle SMA message.  To be done in response to a notification from
 * the 8051.
 *
 * Returns 0 on success, -EINVAL on error
 */
int hfi2_read_idle_sma(struct hfi2_devdata *dd, u64 *data)
{
	return read_idle_message(dd, (u64)IDLE_SMA << IDLE_MSG_TYPE_SHIFT,
				 data);
}

/*
 * Send an idle LCB message.
 *
 * Returns 0 on success, -EINVAL on error
 */
static int send_idle_message(struct hfi2_devdata *dd, u64 data)
{
	int ret;

	dd_dev_info(dd, "%s: sending idle message 0x%llx\n", __func__, data);
	ret = hfi2_do_8051_command(dd, HCMD_SEND_LCB_IDLE_MSG, data, NULL);
	if (ret != HCMD_SUCCESS) {
		dd_dev_err(dd, "send idle message: data 0x%llx, err %d\n", data,
			   ret);
		return -EINVAL;
	}
	return 0;
}

/*
 * Send an idle SMA message.
 *
 * Returns 0 on success, -EINVAL on error
 */
int hfi2_send_idle_sma(struct hfi2_devdata *dd, u64 message)
{
	u64 data;

	data = ((message & IDLE_PAYLOAD_MASK) << IDLE_PAYLOAD_SHIFT) |
	       ((u64)IDLE_SMA << IDLE_MSG_TYPE_SHIFT);
	return send_idle_message(dd, data);
}

/*
 * Initialize the LCB then do a quick link up.  This may or may not be
 * in hfi2_loopback.
 *
 * return 0 on success, -errno on error
 */
static int do_quick_linkup(struct hfi2_devdata *dd)
{
	int ret;

	lcb_shutdown(dd, 0);

	if (hfi2_loopback) {
		/* LCB_CFG_LOOPBACK.VAL = 2 */
		/* LCB_CFG_LANE_WIDTH.VAL = 0 */
		hfi2_write_csr(dd, DC_LCB_CFG_LOOPBACK,
			       2ull << DC_LCB_CFG_LOOPBACK_VAL_SHIFT);
		hfi2_write_csr(dd, DC_LCB_CFG_LANE_WIDTH, 0);
	}

	/* start the LCBs */
	/* LCB_CFG_TX_FIFOS_RESET.VAL = 0 */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 0);

	if (!hfi2_loopback) {
		/*
		 * When doing quick linkup and not in hfi2_loopback, both
		 * sides must be done with LCB set-up before either
		 * starts the quick linkup.  Put a delay here so that
		 * both sides can be started and have a chance to be
		 * done with LCB set up before resuming.
		 */
		dd_dev_err(dd,
			   "Pausing for peer to be finished with LCB set up\n");
		msleep(5000);
		dd_dev_err(dd, "Continuing with quick linkup\n");
	}

	hfi2_write_csr(dd, DC_LCB_ERR_EN, 0); /* mask LCB errors */
	set_8051_lcb_access(dd);

	/*
	 * State "quick" LinkUp request sets the physical link state to
	 * LinkUp without a verify capability sequence.
	 * This state is in simulator v37 and later.
	 */
	ret = hfi2_set_physical_link_state(dd, PLS_QUICK_LINKUP);
	if (ret != HCMD_SUCCESS) {
		dd_dev_err(
			dd,
			"%s: set physical link state to quick LinkUp failed with return %d\n",
			__func__, ret);

		set_host_lcb_access(dd);
		hfi2_write_csr(dd, DC_LCB_ERR_EN, ~0ull); /* watch LCB errors */

		if (ret >= 0)
			ret = -EINVAL;
		return ret;
	}

	return 0; /* success */
}

/*
 * Do all special steps to set up hfi2_loopback.
 */
static int init_loopback(struct hfi2_devdata *dd)
{
	dd_dev_info(dd, "Entering hfi2_loopback mode\n");

	/* all loopbacks should disable self GUID check */
	hfi2_write_csr(dd, DC_DC8051_CFG_MODE,
		       (hfi2_read_csr(dd, DC_DC8051_CFG_MODE) |
			DISABLE_SELF_GUID_CHECK));

	/*
	 * The simulator has only one hfi2_loopback option - LCB.  Switch
	 * to that option, which includes quick link up.
	 *
	 * Accept all valid hfi2_loopback values.
	 */
	if ((dd->icode == ICODE_FUNCTIONAL_SIMULATOR) &&
	    (hfi2_loopback == LOOPBACK_SERDES ||
	     hfi2_loopback == LOOPBACK_LCB ||
	     hfi2_loopback == LOOPBACK_CABLE)) {
		hfi2_loopback = LOOPBACK_LCB;
		hfi2_quick_linkup = 1;
		return 0;
	}

	/*
	 * SerDes hfi2_loopback init sequence is handled in set_local_link_attributes
	 */
	if (hfi2_loopback == LOOPBACK_SERDES)
		return 0;

	/* LCB hfi2_loopback - handled at poll time */
	if (hfi2_loopback == LOOPBACK_LCB) {
		hfi2_quick_linkup = 1; /* LCB is always quick linkup */
		return 0;
	}

	/* external cable hfi2_loopback requires no extra steps */
	if (hfi2_loopback == LOOPBACK_CABLE)
		return 0;

	dd_dev_err(dd, "Invalid hfi2_loopback mode %d\n", hfi2_loopback);
	return -EINVAL;
}

/*
 * Translate from the OPA_LINK_WIDTH handed to us by the FM to bits
 * used in the Verify Capability link width attribute.
 */
static u16 opa_to_vc_link_widths(u16 opa_widths)
{
	int i;
	u16 result = 0;

	static const struct link_bits {
		u16 from;
		u16 to;
	} opa_link_xlate[] = {
		{ OPA_LINK_WIDTH_1X, 1 << (1 - 1) },
		{ OPA_LINK_WIDTH_2X, 1 << (2 - 1) },
		{ OPA_LINK_WIDTH_3X, 1 << (3 - 1) },
		{ OPA_LINK_WIDTH_4X, 1 << (4 - 1) },
	};

	for (i = 0; i < ARRAY_SIZE(opa_link_xlate); i++) {
		if (opa_widths & opa_link_xlate[i].from)
			result |= opa_link_xlate[i].to;
	}
	return result;
}

/*
 * Set link attributes before moving to polling.
 */
static int set_local_link_attributes(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u8 enable_lane_tx;
	u8 tx_polarity_inversion;
	u8 rx_polarity_inversion;
	int ret;
	u32 misc_bits = 0;
	/* reset our fabric serdes to clear any lingering problems */
	hfi2_fabric_serdes_reset(dd);

	/* set the local tx rate - need to read-modify-write */
	ret = hfi2_read_tx_settings(dd, &enable_lane_tx, &tx_polarity_inversion,
			       &rx_polarity_inversion, &ppd->local_tx_rate);
	if (ret)
		goto set_local_link_attributes_fail;

	if (dd->dc8051_ver < dc8051_ver(0, 20, 0)) {
		/* set the tx rate to the fastest enabled */
		if (ppd->link_speed_enabled & OPA_LINK_SPEED_25G)
			ppd->local_tx_rate = 1;
		else
			ppd->local_tx_rate = 0;
	} else {
		/* set the tx rate to all enabled */
		ppd->local_tx_rate = 0;
		if (ppd->link_speed_enabled & OPA_LINK_SPEED_25G)
			ppd->local_tx_rate |= 2;
		if (ppd->link_speed_enabled & OPA_LINK_SPEED_12_5G)
			ppd->local_tx_rate |= 1;
	}

	enable_lane_tx = 0xF; /* enable all four lanes */
	ret = write_tx_settings(dd, enable_lane_tx, tx_polarity_inversion,
				rx_polarity_inversion, ppd->local_tx_rate);
	if (ret != HCMD_SUCCESS)
		goto set_local_link_attributes_fail;

	ret = hfi2_write_host_interface_version(dd, HOST_INTERFACE_VERSION);
	if (ret != HCMD_SUCCESS) {
		ppd_dev_err(
			ppd,
			"Failed to set host interface version, return 0x%x\n",
			ret);
		goto set_local_link_attributes_fail;
	}

	/*
	 * DC supports continuous updates.
	 */
	ret = write_vc_local_phy(dd, 0 /* no power management */,
				 1 /* continuous updates */);
	if (ret != HCMD_SUCCESS)
		goto set_local_link_attributes_fail;

	/* z=1 in the next call: AU of 0 is not supported by the hardware */
	ret = write_vc_local_fabric(dd, dd->vau, 1, dd->vcu, dd->vl15_init,
				    ppd->port_crc_mode_enabled);
	if (ret != HCMD_SUCCESS)
		goto set_local_link_attributes_fail;

	/*
	 * SerDes hfi2_loopback init sequence requires
	 * setting bit 0 of MISC_CONFIG_BITS
	 */
	if (hfi2_loopback == LOOPBACK_SERDES)
		misc_bits |= 1 << LOOPBACK_SERDES_CONFIG_BIT_MASK_SHIFT;

	/*
	 * An external device configuration request is used to reset the LCB
	 * to retry to obtain operational lanes when the first attempt is
	 * unsuccesful.
	 */
	if (dd->dc8051_ver >= dc8051_ver(1, 25, 0))
		misc_bits |= 1 << EXT_CFG_LCB_RESET_SUPPORTED_SHIFT;

	ret = write_vc_local_link_mode(
		dd, misc_bits, 0,
		opa_to_vc_link_widths(ppd->link_width_enabled));
	if (ret != HCMD_SUCCESS)
		goto set_local_link_attributes_fail;

	/* let peer know who we are */
	ret = write_local_device_id(dd, dd->pcidev->device, dd->minrev);
	if (ret == HCMD_SUCCESS)
		return 0;

set_local_link_attributes_fail:
	ppd_dev_err(ppd, "Failed to set local link attributes, return 0x%x\n",
		    ret);
	return ret;
}

/*
 * Call this to start the link.
 * Do not do anything if the link is disabled.
 * Returns 0 if link is disabled, moved to polling, or the driver is not ready.
 */
int hfi2_start_link(struct hfi2_pportdata *ppd)
{
	/*
	 * Tune the SerDes to a ballpark setting for optimal signal and bit
	 * error rate.  Needs to be done before starting the link.
	 */
	hfi2_tune_serdes(ppd);

	if (!ppd->driver_link_ready) {
		ppd_dev_info(
			ppd,
			"%s: stopping link start because driver is not ready\n",
			__func__);
		return 0;
	}

	/*
	 * FULL_MGMT_P_KEY is cleared from the pkey table, so that the
	 * pkey table can be configured properly if the HFI unit is connected
	 * to switch port with MgmtAllowed=NO
	 */
	hfi2_clear_full_mgmt_pkey(ppd);

	return hfi2_set_link_state(ppd, HLS_DN_POLL);
}

static void wait_for_qsfp_init(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 mask;
	unsigned long timeout;

	/*
	 * Some QSFP cables have a quirk that asserts the IntN line as a side
	 * effect of power up on plug-in. We ignore this false positive
	 * interrupt until the module has finished powering up by waiting for
	 * a minimum timeout of the module inrush initialization time of
	 * 500 ms (SFF 8679 Table 5-6) to ensure the voltage rails in the
	 * module have stabilized.
	 */
	msleep(500);

	/*
	 * Check for QSFP interrupt for t_init (SFF 8679 Table 8-1)
	 */
	timeout = jiffies + msecs_to_jiffies(2000);
	while (1) {
		mask = hfi2_read_csr(dd, dd->hfi2_id ? ASIC_QSFP2_IN :
						       ASIC_QSFP1_IN);
		if (!(mask & QSFP_HFI0_INT_N))
			break;
		if (time_after(jiffies, timeout)) {
			ppd_dev_info(ppd,
				     "%s: No IntN detected, reset complete\n",
				     __func__);
			break;
		}
		udelay(2);
	}
}

static void set_qsfp_int_n(struct hfi2_pportdata *ppd, u8 enable)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 mask;

	mask = hfi2_read_csr(dd,
			     dd->hfi2_id ? ASIC_QSFP2_MASK : ASIC_QSFP1_MASK);
	if (enable) {
		/*
		 * Clear the status register to avoid an immediate interrupt
		 * when we re-enable the IntN pin
		 */
		hfi2_write_csr(
			dd, dd->hfi2_id ? ASIC_QSFP2_CLEAR : ASIC_QSFP1_CLEAR,
			QSFP_HFI0_INT_N);
		mask |= (u64)QSFP_HFI0_INT_N;
	} else {
		mask &= ~(u64)QSFP_HFI0_INT_N;
	}
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_MASK : ASIC_QSFP1_MASK,
		       mask);
}

int hfi2_reset_qsfp(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 mask, qsfp_mask;

	/* Disable INT_N from triggering QSFP interrupts */
	set_qsfp_int_n(ppd, 0);

	/* Reset the QSFP */
	mask = (u64)QSFP_HFI0_RESET_N;

	qsfp_mask = hfi2_read_csr(dd, dd->hfi2_id ? ASIC_QSFP2_OUT :
						    ASIC_QSFP1_OUT);
	qsfp_mask &= ~mask;
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_OUT : ASIC_QSFP1_OUT,
		       qsfp_mask);

	udelay(10);

	qsfp_mask |= mask;
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_OUT : ASIC_QSFP1_OUT,
		       qsfp_mask);

	wait_for_qsfp_init(ppd);

	/*
	 * Allow INT_N to trigger the QSFP interrupt to watch
	 * for alarms and warnings
	 */
	set_qsfp_int_n(ppd, 1);

	/*
	 * After the reset, AOC transmitters are enabled by default. They need
	 * to be turned off to complete the QSFP setup before they can be
	 * enabled again.
	 */
	return hfi2_set_qsfp_tx(ppd, 0);
}

static int handle_qsfp_error_conditions(struct hfi2_pportdata *ppd,
					u8 *qsfp_interrupt_status)
{
	if ((qsfp_interrupt_status[0] & QSFP_HIGH_TEMP_ALARM) ||
	    (qsfp_interrupt_status[0] & QSFP_HIGH_TEMP_WARNING))
		ppd_dev_err(ppd, "%s: QSFP cable temperature too high\n",
			    __func__);

	if ((qsfp_interrupt_status[0] & QSFP_LOW_TEMP_ALARM) ||
	    (qsfp_interrupt_status[0] & QSFP_LOW_TEMP_WARNING))
		ppd_dev_err(ppd, "%s: QSFP cable temperature too low\n",
			    __func__);

	/*
	 * The remaining alarms/warnings don't matter if the link is down.
	 */
	if (ppd->host_link_state & HLS_DOWN)
		return 0;

	if ((qsfp_interrupt_status[1] & QSFP_HIGH_VCC_ALARM) ||
	    (qsfp_interrupt_status[1] & QSFP_HIGH_VCC_WARNING))
		ppd_dev_err(ppd, "%s: QSFP supply voltage too high\n",
			    __func__);

	if ((qsfp_interrupt_status[1] & QSFP_LOW_VCC_ALARM) ||
	    (qsfp_interrupt_status[1] & QSFP_LOW_VCC_WARNING))
		ppd_dev_err(ppd, "%s: QSFP supply voltage too low\n", __func__);

	/* Byte 2 is vendor specific */

	if ((qsfp_interrupt_status[3] & QSFP_HIGH_POWER_ALARM) ||
	    (qsfp_interrupt_status[3] & QSFP_HIGH_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable RX channel 1/2 power too high\n",
			    __func__);

	if ((qsfp_interrupt_status[3] & QSFP_LOW_POWER_ALARM) ||
	    (qsfp_interrupt_status[3] & QSFP_LOW_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable RX channel 1/2 power too low\n",
			    __func__);

	if ((qsfp_interrupt_status[4] & QSFP_HIGH_POWER_ALARM) ||
	    (qsfp_interrupt_status[4] & QSFP_HIGH_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable RX channel 3/4 power too high\n",
			    __func__);

	if ((qsfp_interrupt_status[4] & QSFP_LOW_POWER_ALARM) ||
	    (qsfp_interrupt_status[4] & QSFP_LOW_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable RX channel 3/4 power too low\n",
			    __func__);

	if ((qsfp_interrupt_status[5] & QSFP_HIGH_BIAS_ALARM) ||
	    (qsfp_interrupt_status[5] & QSFP_HIGH_BIAS_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 1/2 bias too high\n",
			    __func__);

	if ((qsfp_interrupt_status[5] & QSFP_LOW_BIAS_ALARM) ||
	    (qsfp_interrupt_status[5] & QSFP_LOW_BIAS_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 1/2 bias too low\n",
			    __func__);

	if ((qsfp_interrupt_status[6] & QSFP_HIGH_BIAS_ALARM) ||
	    (qsfp_interrupt_status[6] & QSFP_HIGH_BIAS_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 3/4 bias too high\n",
			    __func__);

	if ((qsfp_interrupt_status[6] & QSFP_LOW_BIAS_ALARM) ||
	    (qsfp_interrupt_status[6] & QSFP_LOW_BIAS_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 3/4 bias too low\n",
			    __func__);

	if ((qsfp_interrupt_status[7] & QSFP_HIGH_POWER_ALARM) ||
	    (qsfp_interrupt_status[7] & QSFP_HIGH_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 1/2 power too high\n",
			    __func__);

	if ((qsfp_interrupt_status[7] & QSFP_LOW_POWER_ALARM) ||
	    (qsfp_interrupt_status[7] & QSFP_LOW_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 1/2 power too low\n",
			    __func__);

	if ((qsfp_interrupt_status[8] & QSFP_HIGH_POWER_ALARM) ||
	    (qsfp_interrupt_status[8] & QSFP_HIGH_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 3/4 power too high\n",
			    __func__);

	if ((qsfp_interrupt_status[8] & QSFP_LOW_POWER_ALARM) ||
	    (qsfp_interrupt_status[8] & QSFP_LOW_POWER_WARNING))
		ppd_dev_err(ppd, "%s: Cable TX channel 3/4 power too low\n",
			    __func__);

	/* Bytes 9-10 and 11-12 are reserved */
	/* Bytes 13-15 are vendor specific */

	return 0;
}

/* This routine will only be scheduled if the QSFP module present is asserted */
void hfi2_qsfp_event(struct work_struct *work)
{
	struct qsfp_data *qd;
	struct hfi2_pportdata *ppd;
	struct hfi2_devdata *dd;

	qd = container_of(work, struct qsfp_data, qsfp_work);
	ppd = qd->ppd;
	dd = ppd->dd;

	/* Sanity check */
	if (!hfi2_qsfp_mod_present(ppd))
		return;

	if (ppd->host_link_state == HLS_DN_DISABLE) {
		ppd_dev_info(
			ppd,
			"%s: stopping link start because link is disabled\n",
			__func__);
		return;
	}

	/*
	 * Turn DC back on after cable has been re-inserted. Up until
	 * now, the DC has been in reset to save power.
	 */
	hfi2_dc_start(dd);

	if (qd->cache_refresh_required) {
		set_qsfp_int_n(ppd, 0);

		wait_for_qsfp_init(ppd);

		/*
		 * Allow INT_N to trigger the QSFP interrupt to watch
		 * for alarms and warnings
		 */
		set_qsfp_int_n(ppd, 1);

		hfi2_start_link(ppd);
	}

	if (qd->check_interrupt_flags) {
		u8 qsfp_interrupt_status[16] = {
			0,
		};

		if (hfi2_one_qsfp_read(ppd, dd->hfi2_id, 6,
				       &qsfp_interrupt_status[0], 16) != 16) {
			ppd_dev_info(
				ppd,
				"%s: Failed to read status of QSFP module\n",
				__func__);
		} else {
			unsigned long flags;

			handle_qsfp_error_conditions(ppd,
						     qsfp_interrupt_status);
			spin_lock_irqsave(&ppd->qsfp_info.qsfp_lock, flags);
			ppd->qsfp_info.check_interrupt_flags = 0;
			spin_unlock_irqrestore(&ppd->qsfp_info.qsfp_lock,
					       flags);
		}
	}
}

void hfi2_init_qsfp_int(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 qsfp_mask;

	qsfp_mask = (u64)(QSFP_HFI0_INT_N | QSFP_HFI0_MODPRST_N);
	/* Clear current status to avoid spurious interrupts */
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_CLEAR : ASIC_QSFP1_CLEAR,
		       qsfp_mask);
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_MASK : ASIC_QSFP1_MASK,
		       qsfp_mask);

	set_qsfp_int_n(ppd, 0);

	/* Handle active low nature of INT_N and MODPRST_N pins */
	if (hfi2_qsfp_mod_present(ppd))
		qsfp_mask &= ~(u64)QSFP_HFI0_MODPRST_N;
	hfi2_write_csr(dd, dd->hfi2_id ? ASIC_QSFP2_INVERT : ASIC_QSFP1_INVERT,
		       qsfp_mask);

	/* Enable the appropriate QSFP IRQ source */
	if (!dd->hfi2_id)
		hfi2_set_intr_bits(dd, QSFP1_INT, QSFP1_INT, true);
	else
		hfi2_set_intr_bits(dd, QSFP2_INT, QSFP2_INT, true);
}

/*
 * Do a one-time initialize of the LCB block.
 */
static void init_lcb(struct hfi2_devdata *dd)
{
	/* the DC has been reset earlier in the driver load */

	/* set LCB for cclk hfi2_loopback on the port */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 0x01);
	hfi2_write_csr(dd, DC_LCB_CFG_LANE_WIDTH, 0x00);
	hfi2_write_csr(dd, DC_LCB_CFG_REINIT_AS_SLAVE, 0x00);
	hfi2_write_csr(dd, DC_LCB_CFG_CNT_FOR_SKIP_STALL, 0x110);
	hfi2_write_csr(dd, DC_LCB_CFG_CLK_CNTR, 0x08);
	hfi2_write_csr(dd, DC_LCB_CFG_LOOPBACK, 0x02);
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 0x00);
}

/*
 * Perform a test read on the QSFP.  Return 0 on success, -ERRNO
 * on error.
 */
static int test_qsfp_read(struct hfi2_pportdata *ppd)
{
	int ret;
	u8 status;

	/*
	 * Report success if not a QSFP or, if it is a QSFP, but the cable is
	 * not present
	 */
	if (ppd->port_type != PORT_TYPE_QSFP || !hfi2_qsfp_mod_present(ppd))
		return 0;

	/* read byte 2, the status byte */
	ret = hfi2_one_qsfp_read(ppd, ppd->dd->hfi2_id, 2, &status, 1);
	if (ret < 0)
		return ret;
	if (ret != 1)
		return -EIO;

	return 0; /* success */
}

/*
 * Values for QSFP retry.
 *
 * Give up after 10s (20 x 500ms).  The overall timeout was empirically
 * arrived at from experience on a large cluster.
 */
#define MAX_QSFP_RETRIES 20
#define QSFP_RETRY_WAIT 500 /* msec */

/*
 * Try a QSFP read.  If it fails, schedule a retry for later.
 * Called on first link activation after driver load.
 */
static void try_start_link(struct hfi2_pportdata *ppd)
{
	if (test_qsfp_read(ppd)) {
		/* read failed */
		if (ppd->qsfp_retry_count >= MAX_QSFP_RETRIES) {
			ppd_dev_err(ppd, "QSFP not responding, giving up\n");
			return;
		}
		ppd_dev_info(ppd,
			     "QSFP not responding, waiting and retrying %d\n",
			     (int)ppd->qsfp_retry_count);
		ppd->qsfp_retry_count++;
		queue_delayed_work(ppd->link_wq, &ppd->start_link_work,
				   msecs_to_jiffies(QSFP_RETRY_WAIT));
		return;
	}
	ppd->qsfp_retry_count = 0;

	hfi2_start_link(ppd);
}

/*
 * Workqueue function to start the link after a delay.
 */
void hfi2_handle_start_link(struct work_struct *work)
{
	struct hfi2_pportdata *ppd =
		container_of(work, struct hfi2_pportdata, start_link_work.work);
	try_start_link(ppd);
}

int hfi2_bringup_serdes(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 guid;
	int ret;

	if (HFI2_CAP_IS_KSET(EXTENDED_PSN))
		hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_EXTENDED_PSN_ENABLE_SMASK);

	guid = ppd->guids[HFI2_PORT_GUID_INDEX];
	if (!guid) {
		/* OPA spec says bits 34:32 are port number, 1-7 */
		if (dd->base_guid)
			guid = (dd->base_guid & ~(7ULL << 32)) |
			       ((u64)ppd->port << 32);
		ppd->guids[HFI2_PORT_GUID_INDEX] = guid;
	}

	/* Set linkinit_reason on power up per OPA spec */
	ppd->linkinit_reason = OPA_LINKINIT_REASON_LINKUP;

	/* one-time init of the LCB */
	init_lcb(dd);

	if (hfi2_loopback) {
		ret = init_loopback(dd);
		if (ret < 0)
			return ret;
	}

	hfi2_get_port_type(ppd);
	if (ppd->port_type == PORT_TYPE_QSFP) {
		set_qsfp_int_n(ppd, 0);
		wait_for_qsfp_init(ppd);
		set_qsfp_int_n(ppd, 1);
	}

	try_start_link(ppd);
	return 0;
}

void hfi2_quiet_serdes(struct hfi2_pportdata *ppd)
{
	/*
	 * Shut down the link and keep it down.   First turn off that the
	 * driver wants to allow the link to be up (driver_link_ready).
	 * Then make sure the link is not automatically restarted
	 * (link_enabled).  Cancel any pending restart.  And finally
	 * go offline.
	 */
	ppd->driver_link_ready = 0;
	ppd->link_enabled = 0;

	ppd->qsfp_retry_count = MAX_QSFP_RETRIES; /* prevent more retries */
	flush_delayed_work(&ppd->start_link_work);
	cancel_delayed_work_sync(&ppd->start_link_work);

	ppd->offline_disabled_reason =
		HFI2_ODR_MASK(OPA_LINKDOWN_REASON_REBOOT);
	hfi2_set_link_down_reason(ppd, OPA_LINKDOWN_REASON_REBOOT, 0,
				  OPA_LINKDOWN_REASON_REBOOT);
	hfi2_set_link_state(ppd, HLS_DN_OFFLINE);

	/* disable the port */
	hfi2_clear_rcvctrl(ppd, RCV_CTRL_RCV_PORT_ENABLE_SMASK);
	flush_work(&ppd->dd->freeze_work);
}
static const char *state_completed_string(u32 completed)
{
	static const char *const state_completed[] = { "EstablishComm",
						       "OptimizeEQ",
						       "VerifyCap" };

	if (completed < ARRAY_SIZE(state_completed))
		return state_completed[completed];

	return "unknown";
}

static const char all_lanes_dead_timeout_expired[] =
	"All lanes were inactive – was the interconnect media removed?";
static const char tx_out_of_policy[] =
	"Passing lanes on local port do not meet the local link width policy";
static const char no_state_complete[] =
	"State timeout occurred before link partner completed the state";
static const char *const state_complete_reasons[] = {
	[0x00] = "Reason unknown",
	[0x01] = "Link was halted by driver, refer to LinkDownReason",
	[0x02] = "Link partner reported failure",
	[0x10] = "Unable to achieve frame sync on any lane",
	[0x11] = "Unable to find a common bit rate with the link partner",
	[0x12] =
		"Unable to achieve frame sync on sufficient lanes to meet the local link width policy",
	[0x13] =
		"Unable to identify preset equalization on sufficient lanes to meet the local link width policy",
	[0x14] = no_state_complete,
	[0x15] =
		"State timeout occurred before link partner identified equalization presets",
	[0x16] =
		"Link partner completed the EstablishComm state, but the passing lanes do not meet the local link width policy",
	[0x17] = tx_out_of_policy,
	[0x20] = all_lanes_dead_timeout_expired,
	[0x21] =
		"Unable to achieve acceptable BER on sufficient lanes to meet the local link width policy",
	[0x22] = no_state_complete,
	[0x23] =
		"Link partner completed the OptimizeEq state, but the passing lanes do not meet the local link width policy",
	[0x24] = tx_out_of_policy,
	[0x30] = all_lanes_dead_timeout_expired,
	[0x31] =
		"State timeout occurred waiting for host to process received frames",
	[0x32] = no_state_complete,
	[0x33] =
		"Link partner completed the VerifyCap state, but the passing lanes do not meet the local link width policy",
	[0x34] = tx_out_of_policy,
	[0x35] = "Negotiated link width is mutually exclusive",
	[0x36] =
		"Timed out before receiving verifycap frames in VerifyCap.Exchange",
	[0x37] = "Unable to resolve secure data exchange",
};

static const char *state_complete_reason_code_string(struct hfi2_pportdata *ppd,
						     u32 code)
{
	const char *str = NULL;

	if (code < ARRAY_SIZE(state_complete_reasons))
		str = state_complete_reasons[code];

	if (str)
		return str;
	return "Reserved";
}

/* describe the given last state complete frame */
static void decode_state_complete(struct hfi2_pportdata *ppd, u32 frame,
				  const char *prefix)
{
	u32 success;
	u32 state;
	u32 reason;
	u32 lanes;

	/*
	 * Decode frame:
	 *  [ 0: 0] - success
	 *  [ 3: 1] - state
	 *  [ 7: 4] - next state timeout
	 *  [15: 8] - reason code
	 *  [31:16] - lanes
	 */
	success = frame & 0x1;
	state = (frame >> 1) & 0x7;
	reason = (frame >> 8) & 0xff;
	lanes = (frame >> 16) & 0xffff;

	ppd_dev_err(ppd, "Last %s LNI state complete frame 0x%08x:\n", prefix,
		    frame);
	ppd_dev_err(ppd, "    last reported state state: %s (0x%x)\n",
		    state_completed_string(state), state);
	ppd_dev_err(ppd, "    state successfully completed: %s\n",
		    success ? "yes" : "no");
	ppd_dev_err(ppd, "    fail reason 0x%x: %s\n", reason,
		    state_complete_reason_code_string(ppd, reason));
	ppd_dev_err(ppd, "    passing lane mask: 0x%x", lanes);
}

/*
 * Read the last state complete frames and explain them.  This routine
 * expects to be called if the link went down during link negotiation
 * and initialization (LNI).  That is, anywhere between polling and link up.
 */
static void check_lni_states(struct hfi2_pportdata *ppd)
{
	u32 last_local_state;
	u32 last_remote_state;

	read_last_local_state(ppd->dd, &last_local_state);
	read_last_remote_state(ppd->dd, &last_remote_state);

	/*
	 * Don't report anything if there is nothing to report.  A value of
	 * 0 means the link was taken down while polling and there was no
	 * training in-process.
	 */
	if (last_local_state == 0 && last_remote_state == 0)
		return;

	decode_state_complete(ppd, last_local_state, "transmitted");
	decode_state_complete(ppd, last_remote_state, "received");
}

/* wait for wait_ms for LINK_TRANSFER_ACTIVE to go to 1 */
int hfi2_wait_link_transfer_active(struct hfi2_devdata *dd, int wait_ms)
{
	u64 reg;
	unsigned long timeout;

	/* watch LCB_STS_LINK_TRANSFER_ACTIVE */
	timeout = jiffies + msecs_to_jiffies(wait_ms);
	while (1) {
		reg = hfi2_read_csr(dd, DC_LCB_STS_LINK_TRANSFER_ACTIVE);
		if (reg)
			break;
		if (time_after(jiffies, timeout)) {
			dd_dev_err(
				dd,
				"timeout waiting for LINK_TRANSFER_ACTIVE\n");
			return -ETIMEDOUT;
		}
		udelay(2);
	}
	return 0;
}

/* called when the logical link state is not down as it should be */
static void force_logical_link_state_down(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;

	/*
	 * Bring link up in LCB hfi2_loopback
	 */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 1);
	hfi2_write_csr(dd, DC_LCB_CFG_IGNORE_LOST_RCLK,
		       DC_LCB_CFG_IGNORE_LOST_RCLK_EN_SMASK);

	hfi2_write_csr(dd, DC_LCB_CFG_LANE_WIDTH, 0);
	hfi2_write_csr(dd, DC_LCB_CFG_REINIT_AS_SLAVE, 0);
	hfi2_write_csr(dd, DC_LCB_CFG_CNT_FOR_SKIP_STALL, 0x110);
	hfi2_write_csr(dd, DC_LCB_CFG_LOOPBACK, 0x2);

	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 0);
	(void)hfi2_read_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET);
	udelay(3);
	hfi2_write_csr(dd, DC_LCB_CFG_ALLOW_LINK_UP, 1);
	hfi2_write_csr(dd, DC_LCB_CFG_RUN, 1ull << DC_LCB_CFG_RUN_EN_SHIFT);

	hfi2_wait_link_transfer_active(dd, 100);

	/*
	 * Bring the link down again.
	 */
	hfi2_write_csr(dd, DC_LCB_CFG_TX_FIFOS_RESET, 1);
	hfi2_write_csr(dd, DC_LCB_CFG_ALLOW_LINK_UP, 0);
	hfi2_write_csr(dd, DC_LCB_CFG_IGNORE_LOST_RCLK, 0);

	ppd_dev_info(ppd, "logical state forced to LINK_DOWN\n");
}

/*
 * Helper for hfi2_set_link_state().  Do not call except from that routine.
 * Expects ppd->hls_mutex to be held.
 *
 * @rem_reason value to be sent to the neighbor
 *
 * LinkDownReasons only set if transition succeeds.
 */
static int goto_offline(struct hfi2_pportdata *ppd, u8 rem_reason)
{
	struct hfi2_devdata *dd = ppd->dd;
	u32 previous_state;
	int offline_state_ret;
	int ret;

	update_lcb_cache(ppd);

	previous_state = ppd->host_link_state;
	ppd->host_link_state = HLS_GOING_OFFLINE;

	/* start offline transition */
	ret = hfi2_set_physical_link_state(dd, (rem_reason << 8) | PLS_OFFLINE);

	if (ret != HCMD_SUCCESS) {
		ppd_dev_err(
			ppd,
			"Failed to transition to Offline link state, return %d\n",
			ret);
		return -EINVAL;
	}
	if (ppd->offline_disabled_reason ==
	    HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NONE))
		ppd->offline_disabled_reason =
			HFI2_ODR_MASK(OPA_LINKDOWN_REASON_TRANSIENT);

	offline_state_ret = hfi2_wait_phys_link_offline_substates(ppd, 10000);
	if (offline_state_ret < 0)
		return offline_state_ret;

	/* Disabling AOC transmitters */
	if (ppd->port_type == PORT_TYPE_QSFP &&
	    ppd->qsfp_info.limiting_active && hfi2_qsfp_mod_present(ppd)) {
		int ret;

		ret = hfi2_acquire_chip_resource(dd, qsfp_resource(dd),
						 QSFP_WAIT);
		if (ret == 0) {
			hfi2_set_qsfp_tx(ppd, 0);
			hfi2_release_chip_resource(dd, qsfp_resource(dd));
		} else {
			/* not fatal, but should warn */
			ppd_dev_err(
				ppd,
				"Unable to acquire lock to turn off QSFP TX\n");
		}
	}

	/*
	 * Wait for the offline.Quiet transition if it hasn't happened yet. It
	 * can take a while for the link to go down.
	 */
	if (offline_state_ret != PLS_OFFLINE_QUIET) {
		ret = hfi2_wait_physical_linkstate(ppd, PLS_OFFLINE, 30000);
		if (ret < 0)
			return ret;
	}

	/*
	 * Now in charge of LCB - must be after the physical state is
	 * offline.quiet and before host_link_state is changed.
	 */
	set_host_lcb_access(dd);
	hfi2_write_csr(dd, DC_LCB_ERR_EN, ~0ull); /* watch LCB errors */

	/* make sure the logical state is also down */
	ret = hfi2_wait_logical_linkstate(ppd, IB_PORT_DOWN, 1000);
	if (ret)
		force_logical_link_state_down(ppd);

	ppd->host_link_state = HLS_LINK_COOLDOWN; /* LCB access allowed */
	hfi2_update_statusp(ppd, IB_PORT_DOWN);

	/*
	 * The LNI has a mandatory wait time after the physical state
	 * moves to Offline.Quiet.  The wait time may be different
	 * depending on how the link went down.  The 8051 firmware
	 * will observe the needed wait time and only move to ready
	 * when that is completed.  The largest of the quiet timeouts
	 * is 6s, so wait that long and then at least 0.5s more for
	 * other transitions, and another 0.5s for a buffer.
	 */
	ret = hfi2_wait_fm_ready(dd, 7000);
	if (ret) {
		ppd_dev_err(
			ppd,
			"After going offline, timed out waiting for the 8051 to become ready to accept host requests\n");
		/* state is really offline, so make it so */
		ppd->host_link_state = HLS_DN_OFFLINE;
		return ret;
	}

	/*
	 * The state is now offline and the 8051 is ready to accept host
	 * requests.
	 *	- change our state
	 *	- notify others if we were previously in a linkup state
	 */
	ppd->host_link_state = HLS_DN_OFFLINE;
	if (previous_state & HLS_UP) {
		/* went down while link was up */
		hfi2_handle_linkup_change(ppd, 0);
	} else if (previous_state &
		   (HLS_DN_POLL | HLS_VERIFY_CAP | HLS_GOING_UP)) {
		/* went down while attempting link up */
		check_lni_states(ppd);

		/* The QSFP doesn't need to be reset on LNI failure */
		ppd->qsfp_info.reset_needed = 0;
	}

	/* the active link width (downgrade) is 0 on link down */
	ppd->link_width_active = 0;
	ppd->link_width_downgrade_tx_active = 0;
	ppd->link_width_downgrade_rx_active = 0;
	ppd->current_egress_rate = 0;
	return 0;
}

/* return the link state name */
const char *hfi2_link_state_name(u32 state)
{
	const char *name;
	int n = ilog2(state);
	static const char *const names[] = {
		[__HLS_UP_INIT_BP] = "INIT",
		[__HLS_UP_ARMED_BP] = "ARMED",
		[__HLS_UP_ACTIVE_BP] = "ACTIVE",
		[__HLS_DN_DOWNDEF_BP] = "DOWNDEF",
		[__HLS_DN_POLL_BP] = "POLL",
		[__HLS_DN_DISABLE_BP] = "DISABLE",
		[__HLS_DN_OFFLINE_BP] = "OFFLINE",
		[__HLS_VERIFY_CAP_BP] = "VERIFY_CAP",
		[__HLS_GOING_UP_BP] = "GOING_UP",
		[__HLS_GOING_OFFLINE_BP] = "GOING_OFFLINE",
		[__HLS_LINK_COOLDOWN_BP] = "LINK_COOLDOWN"
	};

	name = n < ARRAY_SIZE(names) ? names[n] : NULL;
	return name ? name : "unknown";
}

/* return the link state reason name */
const char *hfi2_link_state_reason_name(struct hfi2_pportdata *ppd, u32 state)
{
	if (state == HLS_UP_INIT) {
		switch (ppd->linkinit_reason) {
		case OPA_LINKINIT_REASON_LINKUP:
			return "(LINKUP)";
		case OPA_LINKINIT_REASON_FLAPPING:
			return "(FLAPPING)";
		case OPA_LINKINIT_OUTSIDE_POLICY:
			return "(OUTSIDE_POLICY)";
		case OPA_LINKINIT_QUARANTINED:
			return "(QUARANTINED)";
		case OPA_LINKINIT_INSUFIC_CAPABILITY:
			return "(INSUFIC_CAPABILITY)";
		default:
			break;
		}
	}
	return "";
}

/*
 * hfi2_driver_pstate - convert the driver's notion of a port's
 * state (an HLS_*) into a physical state (a {IB,OPA}_PORTPHYSSTATE_*).
 * Return -1 (converted to a u32) to indicate error.
 */
u32 hfi2_driver_pstate(struct hfi2_pportdata *ppd)
{
	switch (ppd->host_link_state) {
	case HLS_UP_INIT:
	case HLS_UP_ARMED:
	case HLS_UP_ACTIVE:
		return IB_PORTPHYSSTATE_LINKUP;
	case HLS_DN_POLL:
		return IB_PORTPHYSSTATE_POLLING;
	case HLS_DN_DISABLE:
		return IB_PORTPHYSSTATE_DISABLED;
	case HLS_DN_OFFLINE:
		return OPA_PORTPHYSSTATE_OFFLINE;
	case HLS_VERIFY_CAP:
		return IB_PORTPHYSSTATE_TRAINING;
	case HLS_GOING_UP:
		return IB_PORTPHYSSTATE_TRAINING;
	case HLS_GOING_OFFLINE:
		return OPA_PORTPHYSSTATE_OFFLINE;
	case HLS_LINK_COOLDOWN:
		return OPA_PORTPHYSSTATE_OFFLINE;
	case HLS_DN_DOWNDEF:
	default:
		ppd_dev_err(ppd, "invalid host_link_state 0x%x\n",
			    ppd->host_link_state);
		return -1;
	}
}

/*
 * hfi2_driver_lstate - convert the driver's notion of a port's
 * state (an HLS_*) into a logical state (a IB_PORT_*). Return -1
 * (converted to a u32) to indicate error.
 */
u32 hfi2_driver_lstate(struct hfi2_pportdata *ppd)
{
	if (ppd->host_link_state && (ppd->host_link_state & HLS_DOWN))
		return IB_PORT_DOWN;

	switch (ppd->host_link_state & HLS_UP) {
	case HLS_UP_INIT:
		return IB_PORT_INIT;
	case HLS_UP_ARMED:
		return IB_PORT_ARMED;
	case HLS_UP_ACTIVE:
		return IB_PORT_ACTIVE;
	default:
		ppd_dev_err(ppd, "invalid host_link_state 0x%x\n",
			    ppd->host_link_state);
		return -1;
	}
}

void hfi2_set_link_down_reason(struct hfi2_pportdata *ppd, u8 lcl_reason,
			       u8 neigh_reason, u8 rem_reason)
{
	if (ppd->local_link_down_reason.latest == 0 &&
	    ppd->neigh_link_down_reason.latest == 0) {
		ppd->local_link_down_reason.latest = lcl_reason;
		ppd->neigh_link_down_reason.latest = neigh_reason;
		ppd->remote_link_down_reason = rem_reason;
	}
}

/**
 * data_vls_operational() - Verify if data VL BCT credits and MTU
 *			    are both set.
 * @ppd: pointer to hfi2_pportdata structure
 *
 * Return: true - Ok, false -otherwise.
 */
static inline bool data_vls_operational(struct hfi2_pportdata *ppd)
{
	int i;
	u64 reg;

	if (!ppd->actual_vls_operational)
		return false;

	for (i = 0; i < ppd->vls_supported; i++) {
		u32 off = ppd->dd->params->send_cm_credit_vl_reg + (8 * i);

		reg = read_eport_csr(ppd->dd, ppd->hw_pidx, off);
		if ((reg && !ppd->vld[i].mtu) || (!reg && ppd->vld[i].mtu))
			return false;
	}

	return true;
}

/*
 * Change the physical and/or logical link state.
 *
 * Do not call this routine while inside an interrupt.  It contains
 * calls to routines that can take multiple seconds to finish.
 *
 * Returns 0 on success, -errno on failure.
 */
int hfi2_set_link_state(struct hfi2_pportdata *ppd, u32 state)
{
	struct hfi2_devdata *dd = ppd->dd;
	int ret1, ret = 0;
	int orig_new_state, poll_bounce;

	mutex_lock(&ppd->hls_lock);

	orig_new_state = state;
	if (state == HLS_DN_DOWNDEF)
		state = HLS_DEFAULT;

	/* interpret poll -> poll as a link bounce */
	poll_bounce = ppd->host_link_state == HLS_DN_POLL &&
		      state == HLS_DN_POLL;

	ppd_dev_info(ppd, "%s: current %s, new %s %s%s\n", __func__,
		     hfi2_link_state_name(ppd->host_link_state),
		     hfi2_link_state_name(orig_new_state),
		     poll_bounce ? "(bounce) " : "",
		     hfi2_link_state_reason_name(ppd, state));

	/*
	 * If we're going to a (HLS_*) link state that implies the logical
	 * link state is neither of (IB_PORT_ARMED, IB_PORT_ACTIVE), then
	 * reset is_sm_config_started to 0.
	 */
	if (!(state & (HLS_UP_ARMED | HLS_UP_ACTIVE)))
		ppd->is_sm_config_started = 0;

	/*
	 * Do nothing if the states match.  Let a poll to poll link bounce
	 * go through.
	 */
	if (ppd->host_link_state == state && !poll_bounce)
		goto done;

	switch (state) {
	case HLS_UP_INIT:
		if (ppd->host_link_state == HLS_DN_POLL && hfi2_quick_linkup) {
			/*
			 * Quick link up jumps from polling to here.
			 * Accept that here.
			 */
			/* OK */
		} else if (ppd->host_link_state != HLS_GOING_UP) {
			goto unexpected;
		}

		/*
		 * Wait for Link_Up physical state.
		 * Physical and Logical states should already
		 * be transitioned to LinkUp and LinkInit respectively.
		 */
		ret = hfi2_wait_physical_linkstate(ppd, PLS_LINKUP, 1000);
		if (ret) {
			dd_dev_err(
				dd,
				"%s: physical state did not change to LINK-UP\n",
				__func__);
			break;
		}

		ret = hfi2_wait_logical_linkstate(ppd, IB_PORT_INIT, 1000);
		if (ret) {
			ppd_dev_err(
				ppd,
				"%s: logical state did not change to INIT\n",
				__func__);
			break;
		}

		/* clear old transient LINKINIT_REASON code */
		if (ppd->linkinit_reason >= OPA_LINKINIT_REASON_CLEAR)
			ppd->linkinit_reason = OPA_LINKINIT_REASON_LINKUP;

		/* enable the port */
		hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_PORT_ENABLE_SMASK);

		hfi2_handle_linkup_change(ppd, 1);
		hfi2_pio_kernel_linkup(ppd);
		/* tell engines to go running after a link bounce */
		hfi2_sdma_all_running(dd);

		/*
		 * After link up, a new link width will have been set.
		 * Update the xmit counters with regards to the new
		 * link width.
		 */
		hfi2_update_xmit_counters(ppd, ppd->link_width_active);

		ppd->host_link_state = HLS_UP_INIT;
		hfi2_update_statusp(ppd, IB_PORT_INIT);
		break;
	case HLS_UP_ARMED:
		if (ppd->host_link_state != HLS_UP_INIT)
			goto unexpected;

		if (!data_vls_operational(ppd)) {
			ppd_dev_err(ppd, "%s: Invalid data VL credits or mtu\n",
				    __func__);
			ret = -EINVAL;
			break;
		}

		set_logical_state(dd, LSTATE_ARMED);
		ret = hfi2_wait_logical_linkstate(ppd, IB_PORT_ARMED, 1000);
		if (ret) {
			ppd_dev_err(
				ppd,
				"%s: logical state did not change to ARMED\n",
				__func__);
			break;
		}
		ppd->host_link_state = HLS_UP_ARMED;
		hfi2_update_statusp(ppd, IB_PORT_ARMED);
		break;
	case HLS_UP_ACTIVE:
		if (ppd->host_link_state != HLS_UP_ARMED)
			goto unexpected;

		set_logical_state(dd, LSTATE_ACTIVE);
		ret = hfi2_wait_logical_linkstate(ppd, IB_PORT_ACTIVE, 1000);
		if (ret) {
			ppd_dev_err(
				ppd,
				"%s: logical state did not change to ACTIVE\n",
				__func__);
		} else {
			ppd->host_link_state = HLS_UP_ACTIVE;
			hfi2_update_statusp(ppd, IB_PORT_ACTIVE);
			hfi2_go_port_active(ppd);
		}
		break;
	case HLS_DN_POLL:
		if ((ppd->host_link_state == HLS_DN_DISABLE ||
		     ppd->host_link_state == HLS_DN_OFFLINE) &&
		    dd->dc_shutdown)
			hfi2_dc_start(dd);
		/* Hand LED control to the DC */
		hfi2_write_csr(dd, DCC_CFG_LED_CNTRL, 0);

		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			u8 tmp = ppd->link_enabled;

			ret = goto_offline(ppd, ppd->remote_link_down_reason);
			if (ret) {
				ppd->link_enabled = tmp;
				break;
			}
			ppd->remote_link_down_reason = 0;

			if (ppd->driver_link_ready)
				ppd->link_enabled = 1;
		}

		hfi2_set_all_slowpath(ppd);
		ret = set_local_link_attributes(ppd);
		if (ret)
			break;

		ppd->port_error_action = 0;

		if (hfi2_quick_linkup) {
			/* quick linkup does not go into polling */
			ret = do_quick_linkup(dd);
		} else {
			ret1 = hfi2_set_physical_link_state(dd, PLS_POLLING);
			if (!ret1)
				ret1 = hfi2_wait_phys_link_out_of_offline(ppd, 3000);
			if (ret1 != HCMD_SUCCESS) {
				ppd_dev_err(
					ppd,
					"Failed to transition to Polling link state, return 0x%x\n",
					ret1);
				ret = -EINVAL;
			}
		}

		/*
		 * Change the host link state after requesting DC8051 to
		 * change its physical state so that we can ignore any
		 * interrupt with stale LNI(XX) error, which will not be
		 * cleared until DC8051 transitions to Polling state.
		 */
		ppd->host_link_state = HLS_DN_POLL;
		ppd->offline_disabled_reason =
			HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NONE);
		/*
		 * If an error occurred above, go back to offline.  The
		 * caller may reschedule another attempt.
		 */
		if (ret)
			goto_offline(ppd, 0);
		else
			hfi2_log_physical_state(ppd, PLS_POLLING);
		break;
	case HLS_DN_DISABLE:
		/* link is disabled */
		ppd->link_enabled = 0;

		/* allow any state to transition to disabled */

		/* must transition to offline first */
		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			ret = goto_offline(ppd, ppd->remote_link_down_reason);
			if (ret)
				break;
			ppd->remote_link_down_reason = 0;
		}

		if (!dd->dc_shutdown) {
			ret1 = hfi2_set_physical_link_state(dd, PLS_DISABLED);
			if (ret1 != HCMD_SUCCESS) {
				ppd_dev_err(
					ppd,
					"Failed to transition to Disabled link state, return 0x%x\n",
					ret1);
				ret = -EINVAL;
				break;
			}
			ret = hfi2_wait_physical_linkstate(ppd, PLS_DISABLED, 10000);
			if (ret) {
				ppd_dev_err(
					ppd,
					"%s: physical state did not change to DISABLED\n",
					__func__);
				break;
			}
			hfi2_dc_shutdown(dd);
		}
		ppd->host_link_state = HLS_DN_DISABLE;
		break;
	case HLS_DN_OFFLINE:
		if (ppd->host_link_state == HLS_DN_DISABLE)
			hfi2_dc_start(dd);

		/* allow any state to transition to offline */
		ret = goto_offline(ppd, ppd->remote_link_down_reason);
		if (!ret)
			ppd->remote_link_down_reason = 0;
		break;
	case HLS_VERIFY_CAP:
		if (ppd->host_link_state != HLS_DN_POLL)
			goto unexpected;
		ppd->host_link_state = HLS_VERIFY_CAP;
		hfi2_log_physical_state(ppd, PLS_CONFIGPHY_VERIFYCAP);
		break;
	case HLS_GOING_UP:
		if (ppd->host_link_state != HLS_VERIFY_CAP)
			goto unexpected;

		ret1 = hfi2_set_physical_link_state(dd, PLS_LINKUP);
		if (ret1 != HCMD_SUCCESS) {
			ppd_dev_err(
				ppd,
				"Failed to transition to link up state, return 0x%x\n",
				ret1);
			ret = -EINVAL;
			break;
		}
		ppd->host_link_state = HLS_GOING_UP;
		break;

	case HLS_GOING_OFFLINE: /* transient within goto_offline() */
	case HLS_LINK_COOLDOWN: /* transient within goto_offline() */
	default:
		ppd_dev_info(ppd, "%s: state 0x%x: not supported\n", __func__,
			     state);
		ret = -EINVAL;
		break;
	}

	goto done;

unexpected:
	ppd_dev_err(ppd, "%s: unexpected state transition from %s to %s\n",
		    __func__, hfi2_link_state_name(ppd->host_link_state),
		    hfi2_link_state_name(state));
	ret = -EINVAL;

done:
	mutex_unlock(&ppd->hls_lock);

	return ret;
}
int hfi2_set_ib_cfg(struct hfi2_pportdata *ppd, int which, u32 val)
{
	u64 reg;
	int ret = 0;

	switch (which) {
	case HFI2_IB_CFG_LIDLMC:
		hfi2_set_lidlmc(ppd);
		break;
	case HFI2_IB_CFG_VL_HIGH_LIMIT:
		/*
		 * The VL Arbitrator high limit is sent in units of 4k
		 * bytes, while HFI stores it in units of 64 bytes.
		 */
		val *= 4096 / 64;
		reg = ((u64)val & SEND_HIGH_PRIORITY_LIMIT_LIMIT_MASK)
		      << SEND_HIGH_PRIORITY_LIMIT_LIMIT_SHIFT;
		write_eport_csr(ppd->dd, ppd->hw_pidx,
				ppd->dd->params->send_high_priority_limit_reg,
				reg);
		break;
	case HFI2_IB_CFG_LINKDEFAULT: /* IB link default (sleep/poll) */
		/* HFI only supports POLL as the default link down state */
		if (val != HLS_DN_POLL)
			ret = -EINVAL;
		break;
	case HFI2_IB_CFG_OP_VLS:
		if (ppd->vls_operational != val) {
			ppd->vls_operational = val;
			if (!ppd->port)
				ret = -EINVAL;
		}
		break;
	/*
	 * For link width, link width downgrade, and speed enable, always AND
	 * the setting with what is actually supported.  This has two benefits.
	 * First, enabled can't have unsupported values, no matter what the
	 * SM or FM might want.  Second, the ALL_SUPPORTED wildcards that mean
	 * "fill in with your supported value" have all the bits in the
	 * field set, so simply ANDing with supported has the desired result.
	 */
	case HFI2_IB_CFG_LWID_ENB: /* set allowed Link-width */
		ppd->link_width_enabled = val & ppd->link_width_supported;
		break;
	case HFI2_IB_CFG_LWID_DG_ENB: /* set allowed link width downgrade */
		ppd->link_width_downgrade_enabled =
			val & ppd->link_width_downgrade_supported;
		break;
	case HFI2_IB_CFG_SPD_ENB: /* allowed Link speeds */
		ppd->link_speed_enabled = val & ppd->link_speed_supported;
		break;
	case HFI2_IB_CFG_OVERRUN_THRESH: /* IB overrun threshold */
		/*
		 * HFI does not follow IB specs, save this value
		 * so we can report it, if asked.
		 */
		ppd->overrun_threshold = val;
		break;
	case HFI2_IB_CFG_PHYERR_THRESH: /* IB PHY error threshold */
		/*
		 * HFI does not follow IB specs, save this value
		 * so we can report it, if asked.
		 */
		ppd->phy_error_threshold = val;
		break;

	case HFI2_IB_CFG_MTU:
		hfi2_set_send_length(ppd);
		break;

	case HFI2_IB_CFG_PKEYS:
		if (HFI2_CAP_IS_KSET(PKEY_CHECK))
			hfi2_set_partition_keys(ppd);
		break;

	default:
		if (HFI2_CAP_IS_KSET(PRINT_UNIMPL))
			ppd_dev_info(
				ppd,
				"%s: which %s, val 0x%x: not implemented\n",
				__func__, hfi2_ib_cfg_name(which), val);
		break;
	}
	return ret;
}
/* begin functions related to vl arbitration table caching */
void hfi2_init_vl_arb_caches(struct hfi2_pportdata *ppd)
{
	int i;

	BUILD_BUG_ON(VL_ARB_TABLE_SIZE != VL_ARB_LOW_PRIO_TABLE_SIZE);
	BUILD_BUG_ON(VL_ARB_TABLE_SIZE != VL_ARB_HIGH_PRIO_TABLE_SIZE);

	/*
	 * Note that we always return values directly from the
	 * 'vl_arb_cache' (and do no CSR reads) in response to a
	 * 'Get(VLArbTable)'. This is obviously correct after a
	 * 'Set(VLArbTable)', since the cache will then be up to
	 * date. But it's also correct prior to any 'Set(VLArbTable)'
	 * since then both the cache, and the relevant h/w registers
	 * will be zeroed.
	 */

	for (i = 0; i < MAX_PRIO_TABLE; i++)
		spin_lock_init(&ppd->vl_arb_cache[i].lock);
}

/*
 * vl_arb_lock_cache
 *
 * All other vl_arb_* functions should be called only after locking
 * the cache.
 */
inline struct vl_arb_cache *hfi2_vl_arb_lock_cache(struct hfi2_pportdata *ppd,
						     int idx)
{
	if (idx != LO_PRIO_TABLE && idx != HI_PRIO_TABLE)
		return NULL;
	spin_lock(&ppd->vl_arb_cache[idx].lock);
	return &ppd->vl_arb_cache[idx];
}

inline void hfi2_vl_arb_unlock_cache(struct hfi2_pportdata *ppd, int idx)
{
	spin_unlock(&ppd->vl_arb_cache[idx].lock);
}

static void vl_arb_get_cache(struct vl_arb_cache *cache,
			     struct ib_vl_weight_elem *vl)
{
	memcpy(vl, cache->table, VL_ARB_TABLE_SIZE * sizeof(*vl));
}

void hfi2_vl_arb_set_cache(struct vl_arb_cache *cache,
			     struct ib_vl_weight_elem *vl)
{
	memcpy(cache->table, vl, VL_ARB_TABLE_SIZE * sizeof(*vl));
}

int hfi2_vl_arb_match_cache(struct vl_arb_cache *cache,
			      struct ib_vl_weight_elem *vl)
{
	return !memcmp(cache->table, vl, VL_ARB_TABLE_SIZE * sizeof(*vl));
}

/* end functions related to vl arbitration table caching */

int hfi2_set_vl_weights(struct hfi2_pportdata *ppd, u32 target, u32 size,
			  struct ib_vl_weight_elem *vl)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	unsigned int i, is_up = 0;
	int drain, ret = 0;

	/* only set the registers on WFR */
	if (dd->params->chip_type != CHIP_WFR)
		return 0;

	mutex_lock(&ppd->hls_lock);

	if (ppd->host_link_state & HLS_UP)
		is_up = 1;

	drain = !hfi2_is_ax(dd) && is_up;

	if (drain)
		/*
		 * Before adjusting VL arbitration weights, empty per-VL
		 * FIFOs, otherwise a packet whose VL weight is being
		 * set to 0 could get stuck in a FIFO with no chance to
		 * egress.
		 */
		ret = hfi2_stop_drain_data_vls(ppd);

	if (ret) {
		ppd_dev_err(
			ppd,
			"%s: cannot stop/drain VLs - refusing to change VL arbitration weights\n",
			__func__);
		goto err;
	}

	for (i = 0; i < size; i++, vl++) {
		/*
		 * NOTE: The low priority shift and mask are used here, but
		 * they are the same for both the low and high registers.
		 */
		reg = (((u64)vl->vl & SEND_LOW_PRIORITY_LIST_VL_MASK)
		       << SEND_LOW_PRIORITY_LIST_VL_SHIFT) |
		      (((u64)vl->weight & SEND_LOW_PRIORITY_LIST_WEIGHT_MASK)
		       << SEND_LOW_PRIORITY_LIST_WEIGHT_SHIFT);
		write_eport_csr(dd, ppd->hw_pidx, target + (i * 8), reg);
	}
	hfi2_pio_send_control(ppd, PSC_GLOBAL_VLARB_ENABLE);

	if (drain)
		hfi2_open_fill_data_vls(ppd); /* reopen all VLs */

err:
	mutex_unlock(&ppd->hls_lock);

	return ret;
}

/*
 * Read one credit merge VL register.
 */
static void read_one_cm_vl(struct hfi2_pportdata *ppd, u32 csr,
			   struct vl_limit *vll)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg = read_eport_csr(dd, ppd->hw_pidx, csr);

	vll->dedicated = cpu_to_be16(
		(reg >> SEND_CM_CREDIT_VL_DEDICATED_LIMIT_VL_SHIFT) &
		SEND_CM_CREDIT_VL_DEDICATED_LIMIT_VL_MASK);
	vll->shared =
		cpu_to_be16((reg >> SEND_CM_CREDIT_VL_SHARED_LIMIT_VL_SHIFT) &
			    SEND_CM_CREDIT_VL_SHARED_LIMIT_VL_MASK);
}

/*
 * Read the current credit merge limits.
 */
static int get_buffer_control(struct hfi2_pportdata *ppd,
			      struct buffer_control *bc, u16 *overall_limit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	int i;

	/* not all entries are filled in */
	memset(bc, 0, sizeof(*bc));

	/* OPA and HFI have a 1-1 mapping */
	for (i = 0; i < TXE_NUM_DATA_VL; i++)
		read_one_cm_vl(ppd, dd->params->send_cm_credit_vl_reg + (8 * i),
			       &bc->vl[i]);

	/* NOTE: assumes that VL* and VL15 CSRs are bit-wise identical */
	read_one_cm_vl(ppd, dd->params->send_cm_credit_vl15_reg, &bc->vl[15]);

	reg = read_eport_csr(dd, ppd->hw_pidx,
			     dd->params->send_cm_global_credit_reg);
	bc->overall_shared_limit =
		cpu_to_be16((reg >> SEND_CM_GLOBAL_CREDIT_SHARED_LIMIT_SHIFT) &
			    SEND_CM_GLOBAL_CREDIT_SHARED_LIMIT_MASK);
	if (overall_limit)
		*overall_limit =
			(reg >>
			 SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_SHIFT) &
			SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_MASK;
	return sizeof(struct buffer_control);
}

static int get_sc2vlnt(struct hfi2_devdata *dd, struct sc2vlnt *dp)
{
	u64 reg;
	int i;

	/* each register contains 16 SC->VLnt mappings, 4 bits each */
	reg = hfi2_read_csr(dd, DCC_CFG_SC_VL_TABLE_15_0);
	for (i = 0; i < sizeof(u64); i++) {
		u8 byte = *(((u8 *)&reg) + i);

		dp->vlnt[2 * i] = byte & 0xf;
		dp->vlnt[(2 * i) + 1] = (byte & 0xf0) >> 4;
	}

	reg = hfi2_read_csr(dd, DCC_CFG_SC_VL_TABLE_31_16);
	for (i = 0; i < sizeof(u64); i++) {
		u8 byte = *(((u8 *)&reg) + i);

		dp->vlnt[16 + (2 * i)] = byte & 0xf;
		dp->vlnt[16 + (2 * i) + 1] = (byte & 0xf0) >> 4;
	}
	return sizeof(struct sc2vlnt);
}

static void get_vlarb_preempt(struct hfi2_devdata *dd, u32 nelems,
			      struct ib_vl_weight_elem *vl)
{
	unsigned int i;

	for (i = 0; i < nelems; i++, vl++) {
		vl->vl = 0xf;
		vl->weight = 0;
	}
}

void hfi2_set_sc2vlnt(struct hfi2_devdata *dd, struct sc2vlnt *dp)
{
	hfi2_write_csr(
		dd, DCC_CFG_SC_VL_TABLE_15_0,
		DC_SC_VL_VAL(15_0, 0, dp->vlnt[0] & 0xf, 1, dp->vlnt[1] & 0xf,
			     2, dp->vlnt[2] & 0xf, 3, dp->vlnt[3] & 0xf, 4,
			     dp->vlnt[4] & 0xf, 5, dp->vlnt[5] & 0xf, 6,
			     dp->vlnt[6] & 0xf, 7, dp->vlnt[7] & 0xf, 8,
			     dp->vlnt[8] & 0xf, 9, dp->vlnt[9] & 0xf, 10,
			     dp->vlnt[10] & 0xf, 11, dp->vlnt[11] & 0xf, 12,
			     dp->vlnt[12] & 0xf, 13, dp->vlnt[13] & 0xf, 14,
			     dp->vlnt[14] & 0xf, 15, dp->vlnt[15] & 0xf));
	hfi2_write_csr(
		dd, DCC_CFG_SC_VL_TABLE_31_16,
		DC_SC_VL_VAL(31_16, 16, dp->vlnt[16] & 0xf, 17,
			     dp->vlnt[17] & 0xf, 18, dp->vlnt[18] & 0xf, 19,
			     dp->vlnt[19] & 0xf, 20, dp->vlnt[20] & 0xf, 21,
			     dp->vlnt[21] & 0xf, 22, dp->vlnt[22] & 0xf, 23,
			     dp->vlnt[23] & 0xf, 24, dp->vlnt[24] & 0xf, 25,
			     dp->vlnt[25] & 0xf, 26, dp->vlnt[26] & 0xf, 27,
			     dp->vlnt[27] & 0xf, 28, dp->vlnt[28] & 0xf, 29,
			     dp->vlnt[29] & 0xf, 30, dp->vlnt[30] & 0xf, 31,
			     dp->vlnt[31] & 0xf));
}

static void nonzero_msg(struct hfi2_devdata *dd, int idx, const char *what,
			u16 limit)
{
	if (limit != 0)
		dd_dev_info(dd, "Invalid %s limit %d on VL %d, ignoring\n",
			    what, (int)limit, idx);
}

/* change only the shared limit portion of SendCmGLobalCredit */
static void set_global_shared(struct hfi2_pportdata *ppd, u16 limit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;

	reg = read_eport_csr(dd, ppd->hw_pidx,
			     dd->params->send_cm_global_credit_reg);
	reg &= ~SEND_CM_GLOBAL_CREDIT_SHARED_LIMIT_SMASK;
	reg |= (u64)limit << SEND_CM_GLOBAL_CREDIT_SHARED_LIMIT_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_global_credit_reg,
			reg);
}

/* change only the total credit limit portion of SendCmGLobalCredit */
static void set_global_limit(struct hfi2_pportdata *ppd, u16 limit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;

	reg = read_eport_csr(dd, ppd->hw_pidx,
			     dd->params->send_cm_global_credit_reg);
	reg &= ~SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_SMASK;
	reg |= (u64)limit << SEND_CM_GLOBAL_CREDIT_TOTAL_CREDIT_LIMIT_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_cm_global_credit_reg,
			reg);
}

/* set the given per-VL shared limit */
static void set_vl_shared(struct hfi2_pportdata *ppd, int vl, u16 limit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	u32 addr;

	if (vl < TXE_NUM_DATA_VL)
		addr = dd->params->send_cm_credit_vl_reg + (8 * vl);
	else
		addr = dd->params->send_cm_credit_vl15_reg;

	reg = read_eport_csr(dd, ppd->hw_pidx, addr);
	reg &= ~SEND_CM_CREDIT_VL_SHARED_LIMIT_VL_SMASK;
	reg |= (u64)limit << SEND_CM_CREDIT_VL_SHARED_LIMIT_VL_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, addr, reg);
}

/* set the given per-VL dedicated limit */
static void set_vl_dedicated(struct hfi2_pportdata *ppd, int vl, u16 limit)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;
	u32 addr;

	if (vl < TXE_NUM_DATA_VL)
		addr = dd->params->send_cm_credit_vl_reg + (8 * vl);
	else
		addr = dd->params->send_cm_credit_vl15_reg;

	reg = read_eport_csr(dd, ppd->hw_pidx, addr);
	reg &= ~SEND_CM_CREDIT_VL_DEDICATED_LIMIT_VL_SMASK;
	reg |= (u64)limit << SEND_CM_CREDIT_VL_DEDICATED_LIMIT_VL_SHIFT;
	write_eport_csr(dd, ppd->hw_pidx, addr, reg);
}

/* spin until the given per-VL status mask bits clear */
static void wait_for_vl_status_clear(struct hfi2_pportdata *ppd, u64 mask,
				     const char *which)
{
	struct hfi2_devdata *dd = ppd->dd;
	unsigned long timeout;
	u64 reg;

	timeout = jiffies + msecs_to_jiffies(VL_STATUS_CLEAR_TIMEOUT);
	while (1) {
		reg = read_eport_csr(
			      dd, ppd->hw_pidx,
			      dd->params->send_cm_credit_used_status_reg) &
		      mask;

		if (reg == 0)
			return; /* success */
		if (time_after(jiffies, timeout))
			break; /* timed out */
		udelay(1);
	}

	ppd_dev_err(
		ppd,
		"%s credit change status not clearing after %dms, mask 0x%llx, not clear 0x%llx\n",
		which, VL_STATUS_CLEAR_TIMEOUT, mask, reg);
	/*
	 * If this occurs, it is likely there was a credit loss on the link.
	 * The only recovery from that is a link bounce.
	 */
	ppd_dev_err(
		ppd,
		"Continuing anyway.  A credit loss may occur.  Suggest a link bounce\n");
}

/*
 * The number of credits on the VLs may be changed while everything
 * is "live", but the following algorithm must be followed due to
 * how the hardware is actually implemented.  In particular,
 * Return_Credit_Status[] is the only correct status check.
 *
 * if (reducing Global_Shared_Credit_Limit or any shared limit changing)
 *     set Global_Shared_Credit_Limit = 0
 *     use_all_vl = 1
 * mask0 = all VLs that are changing either dedicated or shared limits
 * set Shared_Limit[mask0] = 0
 * spin until Return_Credit_Status[use_all_vl ? all VL : mask0] == 0
 * if (changing any dedicated limit)
 *     mask1 = all VLs that are lowering dedicated limits
 *     lower Dedicated_Limit[mask1]
 *     spin until Return_Credit_Status[mask1] == 0
 *     raise Dedicated_Limits
 * raise Shared_Limits
 * raise Global_Shared_Credit_Limit
 *
 * lower = if the new limit is lower, set the limit to the new value
 * raise = if the new limit is higher than the current value (may be changed
 *	earlier in the algorithm), set the new limit to the new value
 */
int hfi2_set_buffer_control(struct hfi2_pportdata *ppd,
			    struct buffer_control *new_bc)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 changing_mask, ld_mask, stat_mask;
	int change_count;
	int i, use_all_mask;
	int this_shared_changing;
	int vl_count = 0, ret;
	/*
	 * A0: add the variable any_shared_limit_changing below and in the
	 * algorithm above.  If removing A0 support, it can be removed.
	 */
	int any_shared_limit_changing;
	struct buffer_control cur_bc;
	u8 changing[OPA_MAX_VLS];
	u8 lowering_dedicated[OPA_MAX_VLS];
	u16 cur_total;
	u32 new_total = 0;
	u8 map_vls;
	struct hfi2_sdma_map_state sdma_map;
	struct pio_vl_map *pio_map;
	const u64 all_mask =
		SEND_CM_CREDIT_USED_STATUS_VL0_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL1_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL2_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL3_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL4_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL5_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL6_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL7_RETURN_CREDIT_STATUS_SMASK |
		SEND_CM_CREDIT_USED_STATUS_VL15_RETURN_CREDIT_STATUS_SMASK;

#define valid_vl(idx) ((idx) < TXE_NUM_DATA_VL || (idx) == 15)
#define NUM_USABLE_VLS 16 /* look at VL15 and less */

	mutex_lock(&ppd->hls_lock);

	/* find the new total credits, do sanity check on unused VLs */
	for (i = 0; i < OPA_MAX_VLS; i++) {
		if (valid_vl(i)) {
			new_total += be16_to_cpu(new_bc->vl[i].dedicated);
			continue;
		}
		nonzero_msg(dd, i, "dedicated",
			    be16_to_cpu(new_bc->vl[i].dedicated));
		nonzero_msg(dd, i, "shared", be16_to_cpu(new_bc->vl[i].shared));
		new_bc->vl[i].dedicated = 0;
		new_bc->vl[i].shared = 0;
	}
	new_total += be16_to_cpu(new_bc->overall_shared_limit);

	/* fetch the current values */
	get_buffer_control(ppd, &cur_bc, &cur_total);

	/*
	 * Create the masks we will use.
	 */
	memset(changing, 0, sizeof(changing));
	memset(lowering_dedicated, 0, sizeof(lowering_dedicated));
	/*
	 * NOTE: Assumes that the individual VL bits are adjacent and in
	 * increasing order
	 */
	stat_mask = SEND_CM_CREDIT_USED_STATUS_VL0_RETURN_CREDIT_STATUS_SMASK;
	changing_mask = 0;
	ld_mask = 0;
	change_count = 0;
	any_shared_limit_changing = 0;
	for (i = 0; i < NUM_USABLE_VLS; i++, stat_mask <<= 1) {
		if (!valid_vl(i))
			continue;
		this_shared_changing = new_bc->vl[i].shared !=
				       cur_bc.vl[i].shared;
		if (this_shared_changing)
			any_shared_limit_changing = 1;
		if (new_bc->vl[i].dedicated != cur_bc.vl[i].dedicated ||
		    this_shared_changing) {
			changing[i] = 1;
			changing_mask |= stat_mask;
			change_count++;
		}
		if (be16_to_cpu(new_bc->vl[i].dedicated) <
		    be16_to_cpu(cur_bc.vl[i].dedicated)) {
			lowering_dedicated[i] = 1;
			ld_mask |= stat_mask;
		}
	}

	if (change_count > 0) {
		for (i = 0; i < TXE_NUM_DATA_VL; i++)
			if (be16_to_cpu(new_bc->vl[i].dedicated) > 0 ||
			    be16_to_cpu(new_bc->vl[i].shared) > 0)
				vl_count++;
		map_vls = vl_count ? vl_count : ppd->vls_operational;
		ret = hfi2_sdma_map_prepare(ppd, map_vls, NULL, &sdma_map);
		if (ret)
			goto unlock;
		pio_map = hfi2_pio_map_prepare(ppd, map_vls);
		if (IS_ERR(pio_map)) {
			ret = PTR_ERR(pio_map);
			hfi2_sdma_map_abort(&sdma_map);
			goto unlock;
		}
	} else {
		memset(&sdma_map, 0, sizeof(sdma_map));
		pio_map = NULL;
	}

	/* bracket the credit change with a total adjustment */
	if (new_total > cur_total)
		set_global_limit(ppd, new_total);

	/*
	 * Start the credit change algorithm.
	 */
	use_all_mask = 0;
	if ((be16_to_cpu(new_bc->overall_shared_limit) <
	     be16_to_cpu(cur_bc.overall_shared_limit)) ||
	    (hfi2_is_ax(dd) && any_shared_limit_changing)) {
		set_global_shared(ppd, 0);
		cur_bc.overall_shared_limit = 0;
		use_all_mask = 1;
	}

	for (i = 0; i < NUM_USABLE_VLS; i++) {
		if (!valid_vl(i))
			continue;

		if (changing[i]) {
			set_vl_shared(ppd, i, 0);
			cur_bc.vl[i].shared = 0;
		}
	}

	wait_for_vl_status_clear(ppd, use_all_mask ? all_mask : changing_mask,
				 "shared");

	if (change_count > 0) {
		for (i = 0; i < NUM_USABLE_VLS; i++) {
			if (!valid_vl(i))
				continue;

			if (lowering_dedicated[i]) {
				set_vl_dedicated(
					ppd, i,
					be16_to_cpu(new_bc->vl[i].dedicated));
				cur_bc.vl[i].dedicated =
					new_bc->vl[i].dedicated;
			}
		}

		wait_for_vl_status_clear(ppd, ld_mask, "dedicated");

		/* now raise all dedicated that are going up */
		for (i = 0; i < NUM_USABLE_VLS; i++) {
			if (!valid_vl(i))
				continue;

			if (be16_to_cpu(new_bc->vl[i].dedicated) >
			    be16_to_cpu(cur_bc.vl[i].dedicated))
				set_vl_dedicated(
					ppd, i,
					be16_to_cpu(new_bc->vl[i].dedicated));
		}
	}

	/* next raise all shared that are going up */
	for (i = 0; i < NUM_USABLE_VLS; i++) {
		if (!valid_vl(i))
			continue;

		if (be16_to_cpu(new_bc->vl[i].shared) >
		    be16_to_cpu(cur_bc.vl[i].shared))
			set_vl_shared(ppd, i,
				      be16_to_cpu(new_bc->vl[i].shared));
	}

	/* finally raise the global shared */
	if (be16_to_cpu(new_bc->overall_shared_limit) >
	    be16_to_cpu(cur_bc.overall_shared_limit))
		set_global_shared(ppd,
				  be16_to_cpu(new_bc->overall_shared_limit));

	/* bracket the credit change with a total adjustment */
	if (new_total < cur_total)
		set_global_limit(ppd, new_total);

	if (change_count > 0) {
		ppd->actual_vls_operational = vl_count;
		hfi2_sdma_map_commit(ppd, &sdma_map);
		hfi2_pio_map_set_thresholds(ppd, pio_map);
		hfi2_pio_map_commit(ppd, pio_map);
	}
	ret = 0;
unlock:
	mutex_unlock(&ppd->hls_lock);
	return ret;
}

/*
 * Read the given fabric manager table. Return the size of the
 * table (in bytes) on success, and a negative error code on
 * failure.
 */
int hfi2_fm_get_table(struct hfi2_pportdata *ppd, int which, void *t)

{
	int size;
	struct vl_arb_cache *vlc;

	switch (which) {
	case FM_TBL_VL_HIGH_ARB:
		size = 256;
		/*
		 * OPA specifies 128 elements (of 2 bytes each), though
		 * HFI supports only 16 elements in h/w.
		 */
		vlc = hfi2_vl_arb_lock_cache(ppd, HI_PRIO_TABLE);
		vl_arb_get_cache(vlc, t);
		hfi2_vl_arb_unlock_cache(ppd, HI_PRIO_TABLE);
		break;
	case FM_TBL_VL_LOW_ARB:
		size = 256;
		/*
		 * OPA specifies 128 elements (of 2 bytes each), though
		 * HFI supports only 16 elements in h/w.
		 */
		vlc = hfi2_vl_arb_lock_cache(ppd, LO_PRIO_TABLE);
		vl_arb_get_cache(vlc, t);
		hfi2_vl_arb_unlock_cache(ppd, LO_PRIO_TABLE);
		break;
	case FM_TBL_BUFFER_CONTROL:
		size = get_buffer_control(ppd, t, NULL);
		break;
	case FM_TBL_SC2VLNT:
		size = get_sc2vlnt(ppd->dd, t);
		break;
	case FM_TBL_VL_PREEMPT_ELEMS:
		size = 256;
		/* OPA specifies 128 elements, of 2 bytes each */
		get_vlarb_preempt(ppd->dd, OPA_MAX_VLS, t);
		break;
	case FM_TBL_VL_PREEMPT_MATRIX:
		size = 256;
		/*
		 * OPA specifies that this is the same size as the VL
		 * arbitration tables (i.e., 256 bytes).
		 */
		break;
	default:
		return -EINVAL;
	}
	return size;
}
