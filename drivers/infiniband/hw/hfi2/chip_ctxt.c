// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright(c) 2021 - 2026 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 *
 * Send/receive context hardware setup, receive-control programming,
 * freeze/unfreeze recovery and context resource init.  Split out of
 * the former monolithic chip.c; link management lives in chip_link.c
 * and CSR/interrupt/init code in chip.c.
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

static void adjust_rcvctrl(struct hfi2_pportdata *ppd, u64 add, u64 clear)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 rcvctrl;
	unsigned long flags;

	spin_lock_irqsave(&dd->rcvctrl_lock, flags);
	rcvctrl = read_iport_csr(dd, ppd->hw_pidx,
				 dd->params->rcv_iport_ctrl_reg);
	rcvctrl &= ~clear;
	rcvctrl |= add;
	write_iport_csr(dd, ppd->hw_pidx, dd->params->rcv_iport_ctrl_reg,
			rcvctrl);
	if (dd->loopback_enabled) {
		rcvctrl = read_iport_csr(dd, loopback_pidx(ppd),
					 dd->params->rcv_iport_ctrl_reg);
		rcvctrl &= ~clear;
		rcvctrl |= add;
		write_iport_csr(dd, loopback_pidx(ppd),
				dd->params->rcv_iport_ctrl_reg, rcvctrl);
	}
	spin_unlock_irqrestore(&dd->rcvctrl_lock, flags);
}

inline void hfi2_add_rcvctrl(struct hfi2_pportdata *ppd, u64 add)
{
	adjust_rcvctrl(ppd, add, 0);
}

inline void hfi2_clear_rcvctrl(struct hfi2_pportdata *ppd, u64 clear)
{
	adjust_rcvctrl(ppd, 0, clear);
}

void hfi2_set_wcb(struct hfi2_pportdata *ppd, int wcb)
{
	u64 set;

	/* reject anything out of range, fields are the same for all chips */
	if ((wcb & JKR_RCV_IPORT_CTRL_RCV_WCB_MASK) != wcb)
		return;
	set = (u64)wcb << JKR_RCV_IPORT_CTRL_RCV_WCB_SHIFT;
	adjust_rcvctrl(ppd, set, JKR_RCV_IPORT_CTRL_RCV_WCB_SMASK);
}
void hfi2_start_linkdown_handling(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct send_context *sc;
	int sc_flags;
	int i;

	/*
	 * Stop step
	 *
	 * SDMA: Keep the engines running - other ports may be using them.
	 * Expect all descriptors bound for the down port to be processed,
	 * but the contents dropped.  This ability is only available on
	 * hardware after WFR.  Pre-WFR, the descriptor would stall.
	 *
	 * PIO: Halt, with linkdown flag, all of the enabled send contexts for
	 * this port.
	 */
	sc_flags = SCF_LINK_DOWN;
	for (i = 0; i < dd->num_send_contexts; i++) {
		sc = dd->send_contexts[i].sc;
		if (!sc || sc->ppd != ppd || !(sc->flags & SCF_ENABLED))
			continue;

		hfi2_sc_stop(sc, sc_flags);
	}

	/*
	 * Disable step
	 *
	 * SDMA: The engines are left running.  Nothing to do.
	 *
	 * PIO: Disable all contexts for this port.  Non-user contexts will be
	 * re-enabled at linkup time.  User contexts will be re-enabled when
	 * the user requests a context reset.
	 */
	for (i = 0; i < dd->num_send_contexts; i++) {
		sc = dd->send_contexts[i].sc;
		if (!sc || sc->ppd != ppd)
			continue;

		hfi2_sc_disable(sc);
	}
}



/*
 * Called from all interrupt handlers to start handling an SPC freeze.
 */
void hfi2_handle_freeze(struct work_struct *work)
{
	struct hfi2_devdata *dd =
		container_of(work, struct hfi2_devdata, freeze_work);

	/* wait for freeze indicators on all affected blocks */
	hfi2_wait_for_freeze_status(dd, 1);

	/* SPC is now frozen */

	/* do send PIO freeze steps */
	hfi2_pio_freeze(dd);

	/* do send DMA freeze steps */
	hfi2_sdma_freeze(dd);

	/* do send egress freeze steps - nothing to do */

	/* do receive freeze steps */
	hfi2_rxe_freeze(dd);

	/*
	 * Unfreeze the hardware - clear the freeze, wait for each
	 * block's frozen bit to clear, then clear the frozen flag.
	 */
	hfi2_write_csr(dd, CCE_CTRL, CCE_CTRL_SPC_UNFREEZE_SMASK);
	hfi2_wait_for_freeze_status(dd, 0);

	if (hfi2_is_ax(dd)) {
		hfi2_write_csr(dd, CCE_CTRL, CCE_CTRL_SPC_FREEZE_SMASK);
		hfi2_wait_for_freeze_status(dd, 1);
		hfi2_write_csr(dd, CCE_CTRL, CCE_CTRL_SPC_UNFREEZE_SMASK);
		hfi2_wait_for_freeze_status(dd, 0);
	}

	/* do send PIO unfreeze steps for kernel contexts */
	hfi2_pio_kernel_unfreeze(dd);

	/* do send DMA unfreeze steps */
	hfi2_sdma_unfreeze(dd);

	/* do send egress unfreeze steps - nothing to do */

	/* do receive unfreeze steps for kernel contexts */
	hfi2_rxe_kernel_unfreeze(dd);

	/*
	 * The unfreeze procedure touches global device registers when
	 * it disables and re-enables RXE. Mark the device unfrozen
	 * after all that is done so other parts of the driver waiting
	 * for the device to unfreeze don't do things out of order.
	 *
	 * The above implies that the meaning of HFI2_FROZEN flag is
	 * "Device has gone into freeze mode and freeze mode handling
	 * is still in progress."
	 *
	 * The flag will be removed when freeze mode processing has
	 * completed.
	 */
	dd->flags &= ~HFI2_FROZEN;
	wake_up(&dd->event_queue);

	/* no longer frozen */
}

void hfi2_start_freeze_handling(struct hfi2_devdata *dd, int flags)
{
	struct send_context *sc;
	int i;
	int sc_flags;

	if (flags & FREEZE_SELF)
		hfi2_write_csr(dd, CCE_CTRL, CCE_CTRL_SPC_FREEZE_SMASK);

	/* enter frozen mode */
	dd->flags |= HFI2_FROZEN;

	/* notify all SDMA engines that they are going into a freeze */
	hfi2_sdma_freeze_notify(dd, !!(flags & FREEZE_LINK_DOWN));

	sc_flags = SCF_FROZEN | SCF_HALTED |
		   (flags & FREEZE_LINK_DOWN ? SCF_LINK_DOWN : 0);
	/* do halt pre-handling on all enabled send contexts */
	for (i = 0; i < dd->num_send_contexts; i++) {
		sc = dd->send_contexts[i].sc;
		if (sc && (sc->flags & SCF_ENABLED))
			hfi2_sc_stop(sc, sc_flags);
	}

	/* Send context are frozen. Notify user space */
	for (i = 0; i < dd->num_pports; i++)
		hfi2_set_uevent_bits(&dd->pport[i], _HFI2_EVENT_FROZEN_BIT);
	for (i = 0; i < dd->num_pports; i++) {
		hfi2_set_sc_uevent_bits(&dd->pport[i], _HFI2_EVENT_FROZEN_BIT);
	}

	if (flags & FREEZE_ABORT) {
		dd_dev_err(dd,
			   "Aborted freeze recovery. Please REBOOT system\n");
		return;
	}
	/* queue non-interrupt handler */
	queue_work(dd->hfi2_wq, &dd->freeze_work);
}

/*
 * Wait until all 4 sub-blocks indicate that they have frozen or unfrozen,
 * depending on the "freeze" parameter.
 *
 * No need to return an error if it times out, our only option
 * is to proceed anyway.
 */
void hfi2_rxe_freeze(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i, j;
	struct hfi2_ctxtdata *rcd;

	/* disable all receive contexts */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		/* disable port */
		hfi2_clear_rcvctrl(&dd->pport[i], RCV_CTRL_RCV_PORT_ENABLE_SMASK);

		for (j = 0; j < pr->num_rcv_contexts; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			hfi2_rcvctrl(dd, HFI2_RCVCTRL_CTXT_DIS, rcd);
			hfi2_rcd_put(rcd);
		}
	}
}

void hfi2_rxe_kernel_unfreeze(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_ctxtdata *rcd;
	u32 rcvmask;
	u16 i;
	u16 j;

	/* enable all kernel contexts */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_pportdata *ppd = dd->pport + i;
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->num_rcv_contexts; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			/*
			 * Ensure all non-user contexts (kernel and vnic) are
			 * enabled.
			 */
			if (!rcd || hfi2_is_user_context(rcd)) {
				hfi2_rcd_put(rcd);
				continue;
			}
			rcvmask = HFI2_RCVCTRL_CTXT_ENB;
			/* HFI2_RCVCTRL_TAILUPD_* needs to be set explicitly */
			rcvmask |= hfi2_rcvhdrtail_kvaddr(rcd) ?
					   HFI2_RCVCTRL_TAILUPD_ENB :
					   HFI2_RCVCTRL_TAILUPD_DIS;
			hfi2_rcvctrl(dd, rcvmask, rcd);
			hfi2_rcd_put(rcd);
		}

		/* enable port */
		hfi2_add_rcvctrl(ppd, RCV_CTRL_RCV_PORT_ENABLE_SMASK);
	}
}
void hfi2_update_xmit_counters(struct hfi2_pportdata *ppd, u16 link_width)
{
	int i;
	u16 tx_width;
	u16 link_speed;

	tx_width = hfi2_tx_link_width(link_width);
	link_speed = get_link_speed(ppd->link_speed_active);

	/*
	 * There are C_VL_COUNT number of PortVLXmitWait counters.
	 * Adding 1 to C_VL_COUNT to include the PortXmitWait counter.
	 */
	for (i = 0; i < C_VL_COUNT + 1; i++)
		hfi2_get_xmit_wait_counters(ppd, tx_width, link_speed, i);
}
inline int hfi2_init_cpu_counters(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	int i;

	ppd = (struct hfi2_pportdata *)(dd + 1);
	for (i = 0; i < dd->num_pports; i++, ppd++) {
		ppd->ibport_data.rvp.rc_acks = NULL;
		ppd->ibport_data.rvp.rc_qacks = NULL;
		ppd->ibport_data.rvp.rc_acks = alloc_percpu(u64);
		ppd->ibport_data.rvp.rc_qacks = alloc_percpu(u64);
		ppd->ibport_data.rvp.rc_delayed_comp = alloc_percpu(u64);
		if (!ppd->ibport_data.rvp.rc_acks ||
		    !ppd->ibport_data.rvp.rc_delayed_comp ||
		    !ppd->ibport_data.rvp.rc_qacks)
			return -ENOMEM;
	}

	return 0;
}
static void adjust_rcv_timeout(struct hfi2_ctxtdata *rcd, u32 npkts)
{
	struct hfi2_devdata *dd = rcd->dd;
	u32 timeout = rcd->rcvavail_timeout;

	/*
	 * This algorithm doubles or halves the timeout depending on whether
	 * the number of packets received in this interrupt were less than or
	 * greater equal the interrupt count.
	 *
	 * The calculations below do not allow a steady state to be achieved.
	 * Only at the endpoints it is possible to have an unchanging
	 * timeout.
	 */
	if (npkts < dd->rcv_intr_count) {
		/*
		 * Not enough packets arrived before the timeout, adjust
		 * timeout downward.
		 */
		if (timeout < 2) /* already at minimum? */
			return;
		timeout >>= 1;
	} else {
		/*
		 * More than enough packets arrived before the timeout, adjust
		 * timeout upward.
		 */
		if (timeout >= dd->rcv_intr_timeout_csr) /* already at max? */
			return;
		timeout = min(timeout << 1, dd->rcv_intr_timeout_csr);
	}

	rcd->rcvavail_timeout = timeout;
	/*
	 * timeout cannot be larger than rcv_intr_timeout_csr which has already
	 * been verified to be in range
	 */
	write_kctxt_csr(dd, rcd->ctxt, dd->params->rcv_avail_time_out_reg,
			(u64)timeout
				<< RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_SHIFT);
}

void hfi2_update_usrhead(struct hfi2_ctxtdata *rcd, u32 hd, u32 updegr,
			 u32 egrhd, u32 intr_adjust, u32 npkts)
{
	struct hfi2_devdata *dd = rcd->dd;
	u32 ctxt = rcd->ctxt;

	/*
	 * Need to write timeout register before updating RcvHdrHead to ensure
	 * that a new value is used when the HW decides to restart counting.
	 */
	if (intr_adjust)
		adjust_rcv_timeout(rcd, npkts);
	hfi2_update_usrhead_ctxt(dd, ctxt, hd, dd->rcv_intr_count, updegr,
				 egrhd);
}

void hfi2_update_usrhead_ctxt(struct hfi2_devdata *dd, u16 ctxt, u32 hd,
			      u32 intr_cnt, u32 updegr, u32 egrhd)
{
	u64 reg;

	if (updegr) {
		reg = (egrhd & RCV_EGR_INDEX_HEAD_HEAD_MASK)
		      << RCV_EGR_INDEX_HEAD_HEAD_SHIFT;
		write_uctxt_csr(dd, ctxt, dd->params->rcv_egr_index_head_reg,
				reg);
	}
	reg = ((u64)intr_cnt << RCV_HDR_HEAD_COUNTER_SHIFT) |
	      (((u64)hd & RCV_HDR_HEAD_HEAD_MASK) << RCV_HDR_HEAD_HEAD_SHIFT);
	write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg, reg);
}

u32 hfi2_hdrqempty(struct hfi2_ctxtdata *rcd)
{
	u32 head, tail;

	head = (read_uctxt_csr(rcd->dd, rcd->ctxt,
			       rcd->dd->params->rcv_hdr_head_reg) &
		RCV_HDR_HEAD_HEAD_SMASK) >>
	       RCV_HDR_HEAD_HEAD_SHIFT;

	if (hfi2_rcvhdrtail_kvaddr(rcd))
		tail = get_rcvhdrtail(rcd);
	else
		tail = read_uctxt_csr(rcd->dd, rcd->ctxt,
				      rcd->dd->params->rcv_hdr_tail_reg);

	return head == tail;
}

/*
 * Context Control and Receive Array encoding for buffer size:
 *	0x0 invalid
 *	0x1   4 KB
 *	0x2   8 KB
 *	0x3  16 KB
 *	0x4  32 KB
 *	0x5  64 KB
 *	0x6 128 KB
 *	0x7 256 KB
 *	0x8 512 KB (Receive Array only)
 *	0x9   1 MB (Receive Array only)
 *	0xa   2 MB (Receive Array only)
 *
 *	0xB-0xF - reserved (Receive Array only)
 *
 *
 * This routine assumes that the value has already been sanity checked.
 */
u32 hfi2_encoded_size(u32 size)
{
	/*
	 * Valid sizes are powers of two from 4 KiB through 2 MiB.
	 * For valid values, ilog2(size >> 11) returns the hardware
	 * encoding. Invalid values fall back to the minimum encoding.
	 */
	return (unlikely(size < SZ_4K ||
			 size > SZ_2M ||
			(size & (size - 1)))) ?	0x1 : ilog2(size >> 11);
}

/**
 * hfi2_encode_rcv_header_entry_size - return chip specific encoding for size
 * @size: size in dwords
 *
 * Convert a receive header entry size that to the encoding used in the CSR.
 *
 * Return a zero if the given size is invalid, otherwise the encoding.
 */
u8 hfi2_encode_rcv_header_entry_size(u8 size)
{
	/* There are 3 valid receive header entry sizes on all devices, 4 on CN6000. */
	if (size == 2)
		return 1;
	if (size == 16)
		return 2;
	if (size == 32)
		return 4;
	if (size == 64)
		return 5;
	return 0; /* invalid */
}

/**
 * hfi2_validate_rcvhdrcnt - validate hdrcnt
 * @pdev: the pci device
 * @thecnt: the header count
 */
int hfi2_validate_rcvhdrcnt(struct pci_dev *pdev, uint thecnt)
{
	if (thecnt <= HFI2_MIN_HDRQ_EGRBUF_CNT) {
		dev_err(&pdev->dev, "Receive header queue count too small\n");
		return -EINVAL;
	}

	if (thecnt > HFI2_MAX_HDRQ_EGRBUF_CNT) {
		dev_err(&pdev->dev,
			"Receive header queue count cannot be greater than %u\n",
			HFI2_MAX_HDRQ_EGRBUF_CNT);
		return -EINVAL;
	}

	if (thecnt % HDRQ_INCREMENT) {
		dev_err(&pdev->dev,
			"Receive header queue count %u must be divisible by %lu\n",
			thecnt, HDRQ_INCREMENT);
		return -EINVAL;
	}

	return 0;
}

void hfi2_wfr_update_rcv_hdr_size(struct hfi2_devdata *dd, u8 pidx, u16 ctxt,
				  u32 size)
{
	u64 reg;

	reg = ((u64)size & RCV_HDR_SIZE_HDR_SIZE_MASK)
	      << RCV_HDR_SIZE_HDR_SIZE_SHIFT;
	write_kctxt_csr(dd, ctxt, RCV_HDR_SIZE, reg);
}

/**
 * hfi2_set_hdrq_regs - set header queue registers for context
 * @ppd: the port data
 * @ctxt: the context
 * @entsize: the dword entry size
 * @hdrcnt: the number of header entries
 * @kdeth_rcv_hdr: KDETH receive header size
 */
void hfi2_set_hdrq_regs(struct hfi2_pportdata *ppd, u16 ctxt, u8 entsize,
			u16 hdrcnt, u8 kdeth_rcv_hdr)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 reg;

	reg = (((u64)hdrcnt >> HDRQ_SIZE_SHIFT) & RCV_HDR_CNT_CNT_MASK)
	      << RCV_HDR_CNT_CNT_SHIFT;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_cnt_reg, reg);
	reg = ((u64)hfi2_encode_rcv_header_entry_size(entsize) &
	       RCV_HDR_ENT_SIZE_ENT_SIZE_MASK)
	      << RCV_HDR_ENT_SIZE_ENT_SIZE_SHIFT;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_ent_size_reg, reg);
	gen_update_rcv_hdr_size(ppd, ctxt, kdeth_rcv_hdr);

	/*
	 * Program dummy tail address for every receive context
	 * before enabling any receive context
	 */
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_tail_addr_reg,
			dd->rcvhdrtail_dummy_dma);
}

/* this is a type of kernel context */
bool hfi2_is_control_context(struct hfi2_ctxtdata *rcd)
{
	return rcd->ctxt ==
	       rcd->ppd->dd->rsrcs.ppr[rcd->ppd->hw_pidx].rcv_context_base +
		       HFI2_CTRL_CTXT;
}

/* includes control context */
bool hfi2_is_kernel_context(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_portrsrcs *pr = &rcd->ppd->dd->rsrcs.ppr[rcd->ppd->hw_pidx];

	/* kernel contexts are between ctrl and bulksvc/user (excl.) */
	return rcd->ctxt >= pr->rcv_context_base &&
	       rcd->ctxt < pr->first_bulksvc_alloc_ctxt;
}

/* includes user and vnic contexts */
bool hfi2_is_dynamic_context(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_portrsrcs *pr = &rcd->ppd->dd->rsrcs.ppr[rcd->ppd->hw_pidx];

	return rcd->ctxt >= pr->first_dyn_alloc_ctxt &&
	       rcd->ctxt < (pr->rcv_context_base + pr->num_rcv_contexts);
}

/* does not include vnic or Ethernet contexts */
bool hfi2_is_user_context(struct hfi2_ctxtdata *rcd)
{
	return hfi2_is_dynamic_context(rcd) && !rcd->is_vnic && !rcd->is_eth;
}

/* WFR specific rcv context enable, disable */
void hfi2_wfr_enable_rcv_context(struct hfi2_devdata *dd, u8 pidx, u16 ctxt,
				 bool enable)
{
	/* nothing special needs to be done */
}

u64 hfi2_rctxt_ctrl_op(struct hfi2_devdata *dd, u16 ctxt, unsigned int op)
{
	u64 rctxt_ctrl;

	if (dd->is_vf)
		return pf0_rctxt_ctrl_op(dd, ctxt, op);
	rctxt_ctrl = read_rctxt_csr(dd, ctxt, dd->params->rcv_rctxt_ctrl_reg);
	if (op & HFI2_RCVCTRL_INTRAVAIL_ENB)
		rctxt_ctrl |= RCV_CTXT_CTRL_INTR_AVAIL_SMASK;
	if (op & HFI2_RCVCTRL_INTRAVAIL_DIS)
		rctxt_ctrl &= ~RCV_CTXT_CTRL_INTR_AVAIL_SMASK;
	if (op & HFI2_RCVCTRL_TIDFLOW_ENB)
		rctxt_ctrl |= RCV_CTXT_CTRL_TID_FLOW_ENABLE_SMASK;
	if (op & HFI2_RCVCTRL_TIDFLOW_DIS)
		rctxt_ctrl &= ~RCV_CTXT_CTRL_TID_FLOW_ENABLE_SMASK;
	if (op & HFI2_RCVCTRL_NO_RHQ_DROP_ENB)
		rctxt_ctrl |= RCV_CTXT_CTRL_DONT_DROP_RHQ_FULL_SMASK;
	if (op & HFI2_RCVCTRL_NO_RHQ_DROP_DIS)
		rctxt_ctrl &= ~RCV_CTXT_CTRL_DONT_DROP_RHQ_FULL_SMASK;
	if (op & HFI2_RCVCTRL_NO_EGR_DROP_ENB)
		rctxt_ctrl |= RCV_CTXT_CTRL_DONT_DROP_EGR_FULL_SMASK;
	if (op & HFI2_RCVCTRL_NO_EGR_DROP_DIS)
		rctxt_ctrl &= ~RCV_CTXT_CTRL_DONT_DROP_EGR_FULL_SMASK;
	write_rctxt_csr(dd, ctxt, dd->params->rcv_rctxt_ctrl_reg, rctxt_ctrl);
	return rctxt_ctrl;
}
static void rcvctxt_clear_bounds_errs(struct hfi2_devdata *dd,
				      u16 ctxt)
{
	const u64 bounds = RCV_CTXT_STATUS_EGR_ARRAY_BOUNDS_ERR_SMASK |
			   RCV_CTXT_STATUS_TID_ARRAY_BOUNDS_ERR_SMASK;
	u64 status;
	u64 egr_ctrl = 0;
	u64 tid_ctrl = 0;

	if (dd->params->chip_type == CHIP_WFR)
		return;

	status = read_ku_csr(dd, ctxt, dd->params->rcv_ctxt_status_reg) & bounds;
	if (!status)
		return;

	if (!dd->is_vf) {
		egr_ctrl = read_rctxt_csr(dd, ctxt, dd->params->rcv_egr_ctrl_reg);
		tid_ctrl = read_rctxt_csr(dd, ctxt, dd->params->rcv_tid_ctrl_reg);
	}
	dd_dev_warn(dd, "ctxt %u RcvArray write out of bounds:%s%s (RcvEgrCtrl 0x%llx RcvTidCtrl 0x%llx), clearing\n",
		    ctxt,
		    status & RCV_CTXT_STATUS_EGR_ARRAY_BOUNDS_ERR_SMASK ?
			" EgrArrayBoundsErr" : "",
		    status & RCV_CTXT_STATUS_TID_ARRAY_BOUNDS_ERR_SMASK ?
			" TidArrayBoundsErr" : "",
		    egr_ctrl, tid_ctrl);
	write_ku_csr(dd, ctxt, dd->params->rcv_ctxt_status_reg, status);
}

void hfi2_rcvctrl(struct hfi2_devdata *dd, unsigned int op,
		  struct hfi2_ctxtdata *rcd)
{
	u64 rcvctrl, reg;
	u64 rctxt_ctrl;
	int did_enable = 0;
	u16 ctxt;

	if (!rcd)
		return;

	ctxt = rcd->ctxt;

	hfi2_cdbg(RCVCTRL, "ctxt %d op 0x%x", ctxt, op);

	rcvctrl = read_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg);
	/* if the context already enabled, don't do the extra steps */
	if ((op & HFI2_RCVCTRL_CTXT_ENB) &&
	    !(rcvctrl & RCV_CTXT_CTRL_ENABLE_SMASK)) {
		/* reset the tail and hdr addresses, and sequence count */
		write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_addr_reg,
				rcd->rcvhdrq_dma);
		if (hfi2_rcvhdrtail_kvaddr(rcd))
			write_kctxt_csr(dd, ctxt,
					dd->params->rcv_hdr_tail_addr_reg,
					rcd->rcvhdrqtailaddr_dma);
		if (dd->params->set_rheq_addr)
			dd->params->set_rheq_addr(dd, ctxt, rcd->rheq_dma);
		hfi2_set_seq_cnt(rcd, 1);

		/* reset the cached receive header queue head value */
		hfi2_set_rcd_head(rcd, 0);

		/*
		 * Zero the receive header queue so we don't get false
		 * positives when checking the sequence number.  The
		 * sequence numbers could land exactly on the same spot.
		 * E.g. a rcd restart before the receive header wrapped.
		 */
		memset(rcd->rcvhdrq, 0, rcvhdrq_size(rcd));

		/* starting timeout */
		rcd->rcvavail_timeout = dd->rcv_intr_timeout_csr;

		/* enable the context */
		rcvctrl |= RCV_CTXT_CTRL_ENABLE_SMASK;

		/* clean the egr buffer size first */
		rcvctrl &= ~RCV_CTXT_CTRL_EGR_BUF_SIZE_SMASK;
		rcvctrl |= ((u64)hfi2_encoded_size(rcd->egrbufs.rcvtid_size) &
			    RCV_CTXT_CTRL_EGR_BUF_SIZE_MASK)
			   << RCV_CTXT_CTRL_EGR_BUF_SIZE_SHIFT;

		/* zero RcvHdrHead - set RcvHdrHead.Counter after enable */
		write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg, 0);
		did_enable = 1;

		/* zero RcvEgrIndexHead */
		write_uctxt_csr(dd, ctxt, dd->params->rcv_egr_index_head_reg,
				0);

		/* WFR only: direct VL15 packets to the control context */
		if (hfi2_is_control_context(rcd) &&
		    dd->params->chip_type == CHIP_WFR) {
			write_iport_csr(dd, rcd->ppd->hw_pidx,
					dd->params->rcv_vl15_reg, ctxt);
		}

		/* per-chip enable */
		gen_enable_rcv_context(rcd->ppd, ctxt, &rcvctrl, true);
	}
	if (op & HFI2_RCVCTRL_CTXT_DIS) {
		/*
		 * When receive context is being disabled turn on tail
		 * update with a dummy tail address and then disable
		 * receive context.
		 */
		if (dd->rcvhdrtail_dummy_dma) {
			write_kctxt_csr(dd, ctxt,
					dd->params->rcv_hdr_tail_addr_reg,
					dd->rcvhdrtail_dummy_dma);
			/* Enabling RcvCtxtCtrl.TailUpd is intentional. */
			rcvctrl |= RCV_CTXT_CTRL_TAIL_UPD_SMASK;
		}

		rcvctrl &= ~RCV_CTXT_CTRL_ENABLE_SMASK;

		/* per-chip disable */
		gen_enable_rcv_context(rcd->ppd, ctxt, &rcvctrl, false);
	}
	if ((op & HFI2_RCVCTRL_TAILUPD_ENB) && hfi2_rcvhdrtail_kvaddr(rcd))
		rcvctrl |= RCV_CTXT_CTRL_TAIL_UPD_SMASK;
	if (op & HFI2_RCVCTRL_TAILUPD_DIS) {
		/* See comment on RcvCtxtCtrl.TailUpd above */
		if (!(op & HFI2_RCVCTRL_CTXT_DIS))
			rcvctrl &= ~RCV_CTXT_CTRL_TAIL_UPD_SMASK;
	}
	if (op & HFI2_RCVCTRL_ONE_PKT_EGR_ENB) {
		/*
		 * In one-packet-per-eager mode, the size comes from
		 * the RcvArray entry.
		 */
		rcvctrl &= ~RCV_CTXT_CTRL_EGR_BUF_SIZE_SMASK;
		rcvctrl |= RCV_CTXT_CTRL_ONE_PACKET_PER_EGR_BUFFER_SMASK;
	}
	if (op & HFI2_RCVCTRL_ONE_PKT_EGR_DIS)
		rcvctrl &= ~RCV_CTXT_CTRL_ONE_PACKET_PER_EGR_BUFFER_SMASK;
	if (op & HFI2_RCVCTRL_URGENT_ENB)
		hfi2_set_intr_bits(dd, dd->params->is_rcvurgent_start + ctxt,
				   dd->params->is_rcvurgent_start + ctxt, true);
	if (op & HFI2_RCVCTRL_URGENT_DIS)
		hfi2_set_intr_bits(dd, dd->params->is_rcvurgent_start + ctxt,
				   dd->params->is_rcvurgent_start + ctxt,
				   false);

	write_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg, rcvctrl);

	if (op & HFI2_RCVCTRL_INTRAVAIL_ENB)
		hfi2_set_intr_bits(dd, dd->params->is_rcvavail_start + ctxt,
				   dd->params->is_rcvavail_start + ctxt, true);
	if (op & HFI2_RCVCTRL_INTRAVAIL_DIS)
		hfi2_set_intr_bits(dd, dd->params->is_rcvavail_start + ctxt,
				   dd->params->is_rcvavail_start + ctxt, false);
	rctxt_ctrl = hfi2_rctxt_ctrl_op(dd, ctxt, op);
	hfi2_cdbg(RCVCTRL, "ctxt %d kctrl 0x%llx rctrl 0x%llx", ctxt, rcvctrl,
		  rctxt_ctrl);

	if (did_enable)
		rcvctxt_clear_bounds_errs(dd, ctxt);

	/* work around sticky RcvCtxtStatus.BlockedRHQFull */
	if (did_enable &&
	    (rctxt_ctrl & RCV_CTXT_CTRL_DONT_DROP_RHQ_FULL_SMASK)) {
		const u64 blocked = RCV_CTXT_STATUS_BLOCKED_RHQ_FULL_SMASK |
				    RCV_CTXT_STATUS_BLOCKED_EGR_FULL_SMASK;

		reg = read_ku_csr(dd, ctxt, dd->params->rcv_ctxt_status_reg) &
		      blocked;
		if (reg != 0) {
			dd_dev_info(dd, "ctxt %d status %lld (blocked)\n", ctxt,
				    reg);
			read_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg);
			write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg,
					0x10);
			write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg,
					0x00);
			read_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg);
			reg = read_ku_csr(dd, ctxt,
					  dd->params->rcv_ctxt_status_reg) &
			      blocked;
			dd_dev_info(dd, "ctxt %d status %lld (%s blocked)\n",
				    ctxt, reg, reg == 0 ? "not" : "still");
		}
	}

	if (did_enable) {
		/*
		 * The interrupt timeout and count must be set after
		 * the context is enabled to take effect.
		 */
		/* set interrupt timeout */
		write_kctxt_csr(
			dd, ctxt, dd->params->rcv_avail_time_out_reg,
			(u64)rcd->rcvavail_timeout
				<< RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_SHIFT);

		/* set RcvHdrHead.Counter, zero RcvHdrHead.Head (again) */
		reg = (u64)dd->rcv_intr_count << RCV_HDR_HEAD_COUNTER_SHIFT;
		write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg, reg);
	}

	if (op & (HFI2_RCVCTRL_TAILUPD_DIS | HFI2_RCVCTRL_CTXT_DIS))
		/*
		 * If the context has been disabled and the Tail Update has
		 * been cleared, set the RCV_HDR_TAIL_ADDR CSR to dummy address
		 * so it doesn't contain an address that is invalid.
		 */
		write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_tail_addr_reg,
				dd->rcvhdrtail_dummy_dma);
}
int hfi2_init_rxe(struct hfi2_devdata *dd)
{
	u64 val;
	int i;
	int ret;

	if (dd->is_vf) {
		for (i = 0; i < dd->num_pports; i++)
			dd->pport[i].qos_shift = 1; /* otherwise won't happen */
		return vf2pf_init_rxe_rsm(dd);
	}

	/* enable all receive errors */
	for (i = 0; i < dd->num_pports; i++) {
		write_iport_csr(dd, i, dd->params->rcv_err_mask_reg, ~0ull);
		if (dd->loopback_enabled)
			write_iport_csr(dd, loopback_pidx_dd(dd, i),
					dd->params->rcv_err_mask_reg, ~0ull);
	}

	ret = hfi2_init_rxe_rsm(dd, NULL);
	if (ret)
		goto done;

	/* set the DMA receive coalesce size */
	hfi2_adjust_wcb(dd);

	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dd->rsrcs.ppr[i];

		u64 control = pr->rcv_context_base + HFI2_CTRL_CTXT;

		/* set 16 bytes (4 DW) header available in header queue */
		/* set bypass context to the port control context */
		val = (4ull << RCV_BYPASS_HDR_SIZE_SHIFT) | control;
		write_iport_csr(dd, i, dd->params->rcv_bypass_reg, val);

		write_iport_csr(dd, i, dd->params->rcv_multicast_reg, control);
		if (dd->loopback_enabled) {
			write_iport_csr(dd, loopback_pidx_dd(dd, i),
					dd->params->rcv_bypass_reg, val);
			write_iport_csr(dd, loopback_pidx_dd(dd, i),
					dd->params->rcv_multicast_reg, control);
		}
	}
	ret = 0;

done:
	return ret;
}
static void assign_cm_au_table(struct hfi2_pportdata *ppd, u32 cu, u32 csr0to3,
			       u32 csr4to7)
{
	struct hfi2_devdata *dd = ppd->dd;
	int pidx = ppd->hw_pidx;

	if (dd->params->chip_type != CHIP_WFR)
		return;

	write_eport_csr(
		dd, pidx, csr0to3,
		0ull << SEND_CM_LOCAL_AU_TABLE0_TO3_LOCAL_AU_TABLE0_SHIFT |
			1ull << SEND_CM_LOCAL_AU_TABLE0_TO3_LOCAL_AU_TABLE1_SHIFT |
			2ull * cu
				<< SEND_CM_LOCAL_AU_TABLE0_TO3_LOCAL_AU_TABLE2_SHIFT |
			4ull * cu
				<< SEND_CM_LOCAL_AU_TABLE0_TO3_LOCAL_AU_TABLE3_SHIFT);
	write_eport_csr(
		dd, pidx, csr4to7,
		8ull * cu << SEND_CM_LOCAL_AU_TABLE4_TO7_LOCAL_AU_TABLE4_SHIFT |
			16ull * cu
				<< SEND_CM_LOCAL_AU_TABLE4_TO7_LOCAL_AU_TABLE5_SHIFT |
			32ull * cu
				<< SEND_CM_LOCAL_AU_TABLE4_TO7_LOCAL_AU_TABLE6_SHIFT |
			64ull * cu
				<< SEND_CM_LOCAL_AU_TABLE4_TO7_LOCAL_AU_TABLE7_SHIFT);
}

static void assign_local_cm_au_table(struct hfi2_pportdata *ppd, u8 vcu)
{
	assign_cm_au_table(ppd, hfi2_vcu_to_cu(vcu),
			   ppd->dd->params->send_cm_local_au_table0_to3_reg,
			   ppd->dd->params->send_cm_local_au_table4_to7_reg);
}

void hfi2_assign_remote_cm_au_table(struct hfi2_pportdata *ppd, u8 vcu)
{
	assign_cm_au_table(ppd, hfi2_vcu_to_cu(vcu),
			   ppd->dd->params->send_cm_remote_au_table0_to3_reg,
			   ppd->dd->params->send_cm_remote_au_table4_to7_reg);
}

void hfi2_init_txe(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i;

	/* enable all PIO, SDMA, general, and Egress errors */
	hfi2_write_csr(dd, dd->params->send_pio_err_mask_reg, ~0ull);
	hfi2_write_csr(dd, dd->params->send_dma_err_mask_reg, ~0ull);
	hfi2_write_csr(dd, dd->params->csr_err_mask_reg, ~0ull);
	if (!dd->is_vf) {
		for (i = 0; i < dd->num_pports; i++) {
			write_eport_csr(dd, i,
					dd->params->send_egress_err_mask_reg,
					~0ull);
			if (dd->loopback_enabled)
				write_eport_csr(dd, loopback_pidx_dd(dd, i),
						dd->params->send_egress_err_mask_reg,
						~0ull);
		}
	}

	/* enable all per-context and per-SDMA engine errors */
	for (i = dr->c.first_send_context; i < dr->c.last_send_context; i++)
		write_sctxt_csr(dd, i, dd->params->send_ctxt_err_mask_reg,
				~0ull);
	for (i = dr->first_sdma_engine; i < dr->last_sdma_engine; i++)
		write_sdma_csr(dd, i, dd->params->send_dma_eng_err_mask_reg,
			       ~0ull);

	if (dd->params->chip_type == CHIP_WFR) {
		/* set the local CU to AU mapping */
		for (i = 0; i < dd->num_pports; i++)
			assign_local_cm_au_table(dd->pport + i, dd->vcu);

		/*
		 * Set reasonable default for Credit Return Timer
		 */
		for (i = 0; i < dd->num_pports; i++) {
			write_eport_csr(dd, i,
					dd->params->send_cm_timer_ctrl_reg,
					HFI2_CREDIT_RETURN_RATE);
		}
	}
}

/*
 * Set the J_KEY for a context. The send-side register is always
 * programmed via the supplied send_context. The receive-side
 * RCV_KEY_CTRL register is programmed using rcv_ctxt; pass
 * HFI2_NO_RCV_CTXT for send-only contexts that have no receive
 * context to update.
 */
int hfi2_set_ctxt_jkey(struct hfi2_devdata *dd, struct send_context *sc,
		       u16 rcv_ctxt, unsigned long flags, u16 jkey)
{
	int pidx;
	u16 hw_ctxt;
	u64 reg;

	if (!sc)
		return -EINVAL;

	pidx = sc->ppd->hw_pidx;
	hw_ctxt = sc->hw_context;
	reg = SEND_CTXT_CHECK_JOB_KEY_MASK_SMASK | /* mask is always 1's */
	      ((jkey & SEND_CTXT_CHECK_JOB_KEY_VALUE_MASK)
	       << SEND_CTXT_CHECK_JOB_KEY_VALUE_SHIFT);
	/* JOB_KEY_ALLOW_PERMISSIVE is not allowed by default */
	if (HFI2_CAP_KGET_MASK(flags, ALLOW_PERM_JKEY))
		reg |= SEND_CTXT_CHECK_JOB_KEY_ALLOW_PERMISSIVE_SMASK;
	hfi2_priv_reg_op(dd, pidx, hw_ctxt | (rcv_ctxt << 16), sc->type,
		    SC_CHK_JKEY_OP, reg);

	return 0;
}

int hfi2_clear_ctxt_jkey(struct hfi2_devdata *dd, struct send_context *sc,
			 u16 rcv_ctxt)
{
	int pidx;
	u16 hw_ctxt;

	if (!sc)
		return -EINVAL;

	pidx = sc->ppd->hw_pidx;
	hw_ctxt = sc->hw_context;
	hfi2_priv_reg_op(dd, pidx, hw_ctxt | (rcv_ctxt << 16), sc->type,
		    SC_CHK_JKEY_OP, 0);

	return 0;
}

int hfi2_set_ctxt_pkey(struct hfi2_devdata *dd, struct send_context *sc,
		       u16 pkey)
{
	int pidx;
	u16 hw_ctxt;
	u64 reg;

	if (!sc)
		return -EINVAL;

	pidx = sc->ppd->hw_pidx;
	hw_ctxt = sc->hw_context;
	reg = ((u64)pkey & SEND_CTXT_CHECK_PARTITION_KEY_VALUE_MASK)
	      << SEND_CTXT_CHECK_PARTITION_KEY_VALUE_SHIFT;
	hfi2_priv_reg_op(dd, pidx, hw_ctxt, sc->type, SC_CHK_PKEY_OP, reg);

	return 0;
}

int hfi2_clear_ctxt_pkey(struct hfi2_devdata *dd, struct send_context *sc)
{
	int pidx;
	u16 hw_ctxt;

	if (!sc)
		return -EINVAL;

	pidx = sc->ppd->hw_pidx;
	hw_ctxt = sc->hw_context;
	hfi2_priv_reg_op(dd, pidx, hw_ctxt, sc->type, SC_CHK_PKEY_OP, 0);

	return 0;
}

/*
 * Start doing the clean up the chip. Our clean up happens in multiple
 * stages and this is just the first.
 */
void hfi2_start_cleanup(struct hfi2_devdata *dd)
{
	hfi2_free_cntrs(dd);
	hfi2_finish_chip_resources(dd);
}
void hfi2_wait_for_freeze_status(struct hfi2_devdata *dd, int freeze)
{
	unsigned long timeout;
	u64 reg;

	timeout = jiffies + msecs_to_jiffies(FREEZE_STATUS_TIMEOUT);
	while (1) {
		reg = hfi2_read_csr(dd, CCE_STATUS);
		if (freeze) {
			/* waiting until all indicators are set */
			if ((reg & ALL_FROZE) == ALL_FROZE)
				return; /* all done */
		} else {
			/* waiting until all indicators are clear */
			if ((reg & ALL_FROZE) == 0)
				return; /* all done */
		}

		if (time_after(jiffies, timeout)) {
			dd_dev_err(
				dd,
				"Time out waiting for SPC %sfreeze, bits 0x%llx, expecting 0x%llx, continuing",
				freeze ? "" : "un", reg & ALL_FROZE,
				freeze ? ALL_FROZE : 0ull);
			return;
		}
		usleep_range(80, 120);
	}
}
