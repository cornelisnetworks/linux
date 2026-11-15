// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2023 - Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific functions and variables.
 */

#include <linux/bitfield.h>

#include "hfi2.h"
#include "chip_gen.h"
#include "chip_jkr.h"
#include "chip_cyr.h"
#include "cport_traps.h"
#include "vf2pf.h"
#include "sriov.h"
#include "eth_main.h"

#undef DEBUG_CPORT_TRAP

/* TODO: this should not be defined in C files - needs common header */
#define SC(name) SEND_CTXT_##name

static int cport_initial_queries(struct hfi2_pportdata *ppd);

/*
 * CPORT LED Control virtual CSR (CPORT_LED_CONTROL_ADDR) value layout, per
 * the CPORT firmware CSR_RDWR mailbox definition (see hfi2_cport.h):
 *   bits[31:0]  PeriodMs    - blink period in ms, range [100, 10000].
 *                             0 disables the override (returns LED to
 *                             normal hardware control).
 *   bits[39:32] DutyPercent - blink duty cycle %, range [0, 100].
 *                             0 forces the LED off, 100 forces it on,
 *                             1-99 blinks it.
 *   bits[61:40] Reserved (a.k.a. "options" on the firmware side; unused
 *                             here - not to be confused with
 *                             cport_csr.options, the mailbox Rd/Wr bit).
 */
#define CPORT_LED_PERIOD_MASK		GENMASK_ULL(31, 0)
#define CPORT_LED_DUTY_MASK		GENMASK_ULL(39, 32)

/*
 * Write the CPORT LED Control virtual CSR to configure (or disable) a
 * firmware-driven LED blink override. CPORT firmware owns the actual
 * blink timing; the driver only supplies period + duty cycle. Passing
 * period_ms == 0 disables the override and hands the LED back to normal
 * hardware (CRK) control - see CYR HAS 0.35 section 6.2.4 and Table 6-6
 * "Fabric Port LED Behavior".
 */
static int cport_write_led(struct hfi2_pportdata *ppd, u32 period_ms, u32 duty_percent)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct cport_csr csr = {
		.options = CPORT_CSR_OP_WRITE,
		.addr = CPORT_LED_CONTROL_ADDR,
		.value = FIELD_PREP(CPORT_LED_PERIOD_MASK, period_ms) |
			 FIELD_PREP(CPORT_LED_DUTY_MASK, duty_percent),
	};
	struct cport_csr *rsp = NULL;
	int rsp_len = 0;
	int ret;

	if (!dd->cport)
		return -EOPNOTSUPP;

	ret = hfi2_cport_send_req(dd, CH_OP_CSR, 0, &csr, sizeof(csr), (void **)&rsp, &rsp_len, HZ);
	kfree(rsp);
	if (ret) {
		dd_dev_warn(dd, "CPORT failed to write LED CSR (%d)\n", ret);
		ret = -EIO;
	}
	return ret;
}

/*
 * Control the port LED state.  Cancel with hfi2_gen_shutdown_led_override().
 */
void hfi2_gen_setextled(struct hfi2_pportdata *ppd, u32 on)
{
	int rc;

	if (ppd->dd->params->chip_type != CHIP_CYR) {
		ppd_dev_warn(ppd, "%s: not implemented on this chip type\n", __func__);
		return;
	}

	/* Use the minimum valid period; DutyPercent 0/100 forces off/on */
	rc = cport_write_led(ppd, 100, on ? 100 : 0);

	if (rc)
		ppd_dev_warn(ppd, "%s: failed to set LED %s (%d)\n", __func__,
			     on ? "on" : "off", rc);
}

/*
 * Make the port LED blink in pattern.  Parameters timeon and timeoff are
 * in milliseconds.  Cancel with hfi2_gen_shutdown_led_override().
 *
 * The CPORT LED Control virtual CSR only accepts a single period plus a
 * duty cycle (not independent on/off durations), so timeon/timeoff are
 * combined into an equivalent period and duty percentage.
 */
void hfi2_gen_start_led_override(struct hfi2_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff)
{
	unsigned int period, duty;
	int rc;

	if (ppd->dd->params->chip_type != CHIP_CYR) {
		ppd_dev_warn(ppd, "%s: not implemented on this chip type\n", __func__);
		return;
	}

	period = clamp_val(timeon + timeoff, 100, 10000);
	duty = clamp_val(DIV_ROUND_CLOSEST(timeon * 100, period), 0, 100);
	rc = cport_write_led(ppd, period, duty);

	if (rc) {
		ppd_dev_warn(ppd, "%s: failed to start LED override (%d)\n", __func__, rc);
		return;
	}

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 1);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}

/*
 * Return to normal LED operation.  This cancels overrides started with
 * hfi2_gen_setextled() or hfi2_gen_start_led_override().
 */
void hfi2_gen_shutdown_led_override(struct hfi2_pportdata *ppd)
{
	int rc;

	if (ppd->dd->params->chip_type != CHIP_CYR) {
		ppd_dev_warn(ppd, "%s: not implemented on this chip type\n", __func__);
		return;
	}

	/* PeriodMs == 0 disables the override, returning the LED to hw control */
	rc = cport_write_led(ppd, 0, 0);

	if (rc)
		ppd_dev_warn(ppd, "%s: failed to shutdown LED override (%d)\n", __func__, rc);

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 0);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}

void hfi2_gen_read_guid(struct hfi2_devdata *dd)
{
	/* XXX Replace with a CPORT message for NodeGUID */
	dd_dev_warn(dd, "%s: JKR TODO\n", __func__);

	/* XXX set dd->base_guid with real value */
	dd->base_guid = 0xabcd;
}

int hfi2_gen_late_per_chip_init(struct hfi2_devdata *dd)
{
	/* XXX Fill in anything needed post interrupt and context init */
	return 0;
}

void hfi2_gen_start_port(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	u64 guid;

	/*
	 * Derive the port GUID from the device base GUID if not already set.
	 * Per OPA spec, bits 34:32 encode the port number (1-7).
	 */
	guid = ppd->guids[HFI2_PORT_GUID_INDEX];
	if (!guid) {
		/* OPA spec says bits 34:32 are port number, 1-7 */
		if (dd->base_guid)
			guid = (dd->base_guid & ~(7ULL << 32)) |
			       ((u64)ppd->port << 32);
		if (guid)
			guid += dd->rsrcs.si_idx;
		ppd->guids[HFI2_PORT_GUID_INDEX] = guid;
		pr_warn("%s: ppd->guids[HFI2_PORT_GUID_INDEX] = 0x%llx",
			__func__, guid);
	}
}

void hfi2_gen_stop_port(struct hfi2_pportdata *ppd)
{
	/* XXX steps to start port serdes */
	ppd_dev_warn(ppd, "%s: pidx %d, JKR TODO\n", __func__, ppd->hw_pidx);
}

void hfi2_gen_set_port_max_mtu(struct hfi2_pportdata *ppd, u32 maxvlmtu)
{
	/* XXX steps to set the port maximum MTU */
	ppd_dev_warn(ppd, "%s: pidx %d, JKR TODO\n", __func__, ppd->hw_pidx);
}

u64 hfi2_gen_create_pbc_pidx(u8 pidx, u64 flags, int srate_mbs, u32 vl, u32 dw_len,
			u32 l2, u32 dlid, u32 sctxt)
{
	/* always add ICRC for non 9B packets */
	if (l2 != PBC_L2_9B)
		flags |= PBC_INSERT_BYPASS_ICRC; /* AKA PbcInsertNon9bIcrc */

	return (u64)sctxt << PBC_SEND_CTXT_SHIFT |
	       (u64)(dlid & PBC_DLID_MASK) << PBC_DLID_SHIFT |
	       /* lower 32 bits */
	       flags | PBC_IHCRC_NONE << PBC_INSERT_HCRC_SHIFT |
	       l2 << PBC_L2_TYPE_SHIFT | pidx << PBC_PORT_IDX_SHIFT |
	       (vl & PBC_VL_MASK) << PBC_VL_SHIFT |
	       (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT;
}

/**
 * hfi2_gen_create_pbc - build a pbc for transmission
 * @ppd: info of physical Hfi port
 * @hfi2_loopback: whether to use hfi2_loopback port
 * @flags: special case flags or-ed in built pbc
 * @srate_mbs: static rate - unused
 * @vl: vl
 * @dw_len: dword length (header words + data words + pbc words)
 * @l2: L2 header field - determines type
 * @dlid: destination LID
 * @sctxt: send context number
 *
 * Create a PBC with the given flags, rate, VL, and length.
 *
 * NOTE: The PBC created will not insert any HCRC.
 */
u64 hfi2_gen_create_pbc(struct hfi2_pportdata *ppd, bool hfi2_loopback, u64 flags,
		   int srate_mbs, u32 vl, u32 dw_len, u32 l2, u32 dlid,
		   u32 sctxt)
{
	u8 pidx = hfi2_loopback ? loopback_pidx(ppd) : ppd->hw_pidx;

	return pbc_test(ppd->dd, hfi2_gen_create_pbc_pidx(pidx, flags, srate_mbs,
							vl, dw_len, l2, dlid, sctxt));
}

/*
 * Send a GET OPA MAD to CPORT and return response.
 * Caller must kfree() the buffer returned (if not IS_ERR()).
 */
static struct opa_smp *build_cport_mad(int meth, int attr)
{
	struct opa_smp *mad;

	mad = kzalloc(sizeof(*mad), GFP_KERNEL);
	if (!mad)
		return mad;
	mad->base_version = OPA_MGMT_BASE_VERSION;
	mad->mgmt_class = IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE;
	mad->class_version = OPA_SM_CLASS_VERSION;
	mad->method = meth;
	mad->attr_id = attr;
	/* XXX - what else */
	return mad;
}

static struct opa_smp *cport_get_opa_mad(struct hfi2_devdata *dd, int port, __be16 attr)
{
	u8 sb = port; /* 1.. */
	struct opa_smp *mad;
	struct opa_smp *rsp;
	size_t rsp_len;
	int ret;

	mad = build_cport_mad(IB_MGMT_METHOD_GET, attr);
	if (!mad)
		return ERR_PTR(-ENOMEM);
	/*
	 * Set port in attribute modifier field, for PORT_INFO.
	 */
	if (attr == IB_SMP_ATTR_PORT_INFO)
		mad->attr_mod = cpu_to_be32(0x1000000 | port);
	/* XXX - need to specify 9B vs 16B? */
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi2_%d: %s: send: %02x %02x %02x %02x - %04x %04x %08x\n",
		dd->unit, __func__,
		mad->base_version, mad->mgmt_class, mad->class_version, mad->method,
		be16_to_cpu(mad->status), be16_to_cpu(mad->attr_id),
		be32_to_cpu(mad->attr_mod));
#endif
	rsp_len = sizeof(*rsp);
	rsp = kzalloc(rsp_len, GFP_KERNEL);
	if (!rsp) {
		kfree(mad);
		return ERR_PTR(-ENOMEM);
	}
	ret = hfi2_cport_send_recv_mad(dd, sb, mad, sizeof(*mad) - OPA_SMP_DR_DATA_SIZE,
				  rsp, &rsp_len);
	kfree(mad);
	if (ret) {
		kfree(rsp);
		if (ret > 0)
			ret = -EINVAL;
		return ERR_PTR(ret);
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi2_%d: %s: resp: %02x %02x %02x %02x - %04x %04x %08x\n",
		dd->unit, __func__,
		rsp->base_version, rsp->mgmt_class, rsp->class_version, rsp->method,
		be16_to_cpu(rsp->status), be16_to_cpu(rsp->attr_id), be32_to_cpu(rsp->attr_mod));
#endif
	return rsp;
}

#ifdef DEBUG_CPORT_TRAP
static const char *ps_state_name(struct opa_port_states *ps)
{
	static const char *const state_name[] = {
		[IB_PORT_NOP] = "NOP",
		[IB_PORT_DOWN] = "DOWN",
		[IB_PORT_INIT] = "INIT",
		[IB_PORT_ARMED] = "ARMED",
		[IB_PORT_ACTIVE] = "ACTIVE",
		[IB_PORT_ACTIVE_DEFER] = "ACTIVE_DEFER"
	};
	u8 ls = port_states_to_logical_state(ps);

	if (ls > IB_PORT_ACTIVE_DEFER)
		return "???";
	return state_name[ls];
}
#endif

static void check_cport_state(struct work_struct *work)
{
	struct hfi2_cport *cport =
		container_of(work, struct hfi2_cport, psc.work);
	struct hfi2_devdata *dd = cport->dd;
	struct opa_smp *mad;
	struct opa_port_info *pi;
	int ret;
	int pidx;

	/*
	 * There should be only one running. Others could abort except for
	 * the race between checking states and releasing semaphore.
	 */
	ret = down_killable(&dd->cport->psc.wait);
	if (ret) {
		atomic_dec(&dd->cport->psc.nq);
		return;
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi2_%d: %s: starting port_info loop\n", dd->unit, __func__);
#endif

	for (pidx = 0; pidx < dd->params->num_ports; ++pidx) {
		if (hfi2_is_eth_mode(dd)) {
			if (port_available_pidx(dd, pidx))
				cne_update_link_state(&dd->pport[pidx]);
			continue;
		}
		if (!port_available_pidx(dd, pidx)) {
			ppd_dev_info(
				&dd->pport[pidx],
				"Skipping port state check - port not available\n");
			continue;
		}
		mad = cport_get_opa_mad(dd, pidx + 1, IB_SMP_ATTR_PORT_INFO);
		if (IS_ERR(mad)) {
			ret = PTR_ERR(mad);
			dd_dev_warn(dd, "Failed to obtain PORT_INFO on port %d (%d)\n",
				    pidx + 1, ret);
			continue;
		}
		pi = (struct opa_port_info *)opa_get_smp_data(mad);
#ifdef DEBUG_CPORT_TRAP
			pr_warn("hfi2_%d: %s: PORTINFO %d: %s %08x (%x)\n",
				dd->unit, __func__, pidx + 1,
				ps_state_name(&pi->port_states),
				be32_to_cpu(mad->attr_mod),
				be16_to_cpu(mad->status));
#endif

		/*
		 * Update initial tables after obtaining the port info, but
		 * before notifiying the ULPs of a possible state change.
		 * If the logical state is >= ARMED the tables have been
		 * set by the FM.  Only need to do this once on startup to
		 * ensure the driver has not missed any FM updates that
		 * occurred before the driver started.
		 */
		if (dd->cport->psc.initial_queries[pidx] &&
		    port_states_to_logical_state(&pi->port_states) >= IB_PORT_ARMED) {
			ret = dd->cport->psc.initial_queries[pidx](&dd->pport[pidx]);
			if (ret)
				dd_dev_warn(dd, "Failed to update initial port info on port %d (%d)\n",
					    pidx + 1, ret);

			dd->cport->psc.initial_queries[pidx] = NULL;
		}

		ret = hfi2_update_from_opa_portinfo(&dd->pport[pidx], mad, pi);
		kfree(mad);
		/* XXX - queue up a retry on error? */
		if (ret)
			dd_dev_warn(
				dd,
				"Failed to update PORT_INFO on port %d (%d)\n",
				pidx + 1, ret);
	}
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi2_%d: %s: finished port_info loop\n", dd->unit, __func__);
#endif
	atomic_dec(&dd->cport->psc.nq);
	up(&dd->cport->psc.wait);
}

static void handle_cport_trap128(struct hfi2_devdata *dd,
				 struct cport_trap_status traps)
{
	/* note: traps are already repressed */
#ifdef DEBUG_CPORT_TRAP
	pr_warn("hfi2_%d: %s: TRAP128 psc=%d\n", dd->unit, __func__,
		!!(traps.flags & CPORT_TRAP_PSC));
#endif

	if (atomic_read(&dd->cport->psc.nq) > 1) {
#ifdef DEBUG_CPORT_TRAP
		pr_warn("hfi2_%d: %s: TRAP128(s) pending: %d\n", dd->unit,
			__func__, atomic_read(&dd->cport->psc.nq));
#endif
		return;
	}
	atomic_inc(&dd->cport->psc.nq);
	queue_work(dd->hfi2_wq, &dd->cport->psc.work);
}

/*
 * This initializes everything necessary to receive and process Port
 * State Change TRAPs from CPORT. It also kicks off the initial gathering
 * of port states from CPORT.
 */
int hfi2_init_cport_trap128(struct hfi2_devdata *dd)
{
	struct cport_trap_status traps = { 0 };
	int ret = 0;
	int pidx;

	if (!dd->cport)
		return 0;

	atomic_set(&dd->cport->psc.nq, 0);
	sema_init(&dd->cport->psc.wait, 1);
	INIT_WORK(&dd->cport->psc.work, check_cport_state);
	dd->cport->trap128_initialized = true;
	traps.flags = CPORT_TRAP_PSC; /* Trap 128 Port State Change */
	for (pidx = 0; pidx < dd->num_pports; pidx++)
		dd->cport->psc.initial_queries[pidx] = cport_initial_queries;
	ret = hfi2_register_cport_trap(dd, traps, handle_cport_trap128);
	if (ret)
		dd_dev_warn(dd, "Failed to register for CPORT TRAP 128: %d\n",
			    ret);
	else if (!(dd->cport->traps_act.flags & CPORT_TRAP_PSC))
		dd_dev_warn(dd, "CPORT TRAP128 not supported\n");
	/* Fake a TRAP-128 to gather initial port states even if register fails */
	handle_cport_trap128(dd, traps);
	return ret;
}

void lock_cport_trap128(struct hfi2_devdata *dd)
{
	if (dd->cport && dd->cport->psc.work.func)
		down(&dd->cport->psc.wait);
}

void unlock_cport_trap128(struct hfi2_devdata *dd)
{
	if (dd->cport && dd->cport->psc.work.func)
		up(&dd->cport->psc.wait);
}

int hfi2_deinit_cport_trap128(struct hfi2_devdata *dd)
{
	int ret = 0;

	if (!dd->cport || !dd->cport->trap128_initialized)
		return 0;
	ret = hfi2_deregister_cport_trap(dd, handle_cport_trap128);
	cancel_work_sync(&dd->cport->psc.work);
	dd->cport->trap128_initialized = false;
	return ret;
}

static void handle_cport_overtemp(struct hfi2_devdata *dd,
				  struct cport_trap_status traps)
{
	/* note: traps are already repressed */
	hfi2_overtemp(dd);
}

/* no deinit_ - clearall_cport_trap() unregisters this */
int hfi2_init_cport_overtemp(struct hfi2_devdata *dd)
{
	struct cport_trap_status traps = { 0 };
	int ret = 0;

	if (!dd->cport)
		return 0;

	traps.flags = CPORT_TRAP_OVTM; /* Over Temp emergency */
	ret = hfi2_register_cport_trap(dd, traps, handle_cport_overtemp);
	if (ret)
		dd_dev_warn(dd, "Failed to register for CPORT Over Temp: %d\n",
			    ret);
	else if (!(dd->cport->traps_act.flags & CPORT_TRAP_OVTM))
		dd_dev_warn(dd, "CPORT Over-Temp notification not supported\n");
	return ret;
}

static int cport_goto_offline(struct hfi2_pportdata *ppd,
			      struct opa_port_info *pi, u8 rem_reason)
{
	u32 previous_state;

	previous_state = ppd->host_link_state;
	ppd->host_link_state = HLS_GOING_OFFLINE;

	/* start offline transition */
	if (ppd->offline_disabled_reason ==
	    HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NONE))
		ppd->offline_disabled_reason =
			HFI2_ODR_MASK(OPA_LINKDOWN_REASON_TRANSIENT);

	hfi2_update_statusp(ppd, IB_PORT_DOWN);

	/*
	 * The state in CPORT is now offline.
	 *	- change our state
	 *	- notify others if we were previously in a linkup state
	 */
	ppd->host_link_state = HLS_DN_OFFLINE;
	if (previous_state & HLS_UP) {
		/* went down while link was up */
		hfi2_cport_handle_linkup_change(ppd, pi, 0);
	}

	/* the active link width (downgrade) is 0 on link down */
	ppd->link_width_active = 0;
	ppd->link_width_downgrade_tx_active = 0;
	ppd->link_width_downgrade_rx_active = 0;
	ppd->current_egress_rate = 0;
	/* XXX - also clear speeds? */
	return 0;
}

/* hfi2_set_link_state() for CPORT-based systems. Only update local data. */
int hfi2_cport_set_link_state(struct hfi2_pportdata *ppd, struct opa_port_info *pi,
			 u32 state)
{
	struct hfi2_devdata *dd = ppd->dd;
	int ret = 0;
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
		hfi2_log_state_transition(ppd, PLS_LINKUP);

		/* clear old transient LINKINIT_REASON code */
		if (ppd->linkinit_reason >= OPA_LINKINIT_REASON_CLEAR)
			ppd->linkinit_reason = OPA_LINKINIT_REASON_LINKUP;

		hfi2_cport_handle_linkup_change(ppd, pi, 1);
		hfi2_pio_kernel_linkup(ppd);

		/*
		 * After link up, a new link width will have been set.
		 * Update the xmit counters with regards to the new
		 * link width.
		 */
		/* XXX - still do this? */
		hfi2_update_xmit_counters(ppd, ppd->link_width_active);

		ppd->host_link_state = HLS_UP_INIT;
		hfi2_update_statusp(ppd, IB_PORT_INIT);
		break;
	case HLS_UP_ARMED:
		/* XXX - is this error check needed? */
		if (ppd->host_link_state != HLS_UP_INIT)
			dd_dev_err(
				dd,
				"%s %d: allowing unexpected state transition from %s to %s\n",
				__func__, ppd->port,
				hfi2_link_state_name(ppd->host_link_state),
				hfi2_link_state_name(state));

		ppd->host_link_state = HLS_UP_ARMED;
		hfi2_update_statusp(ppd, IB_PORT_ARMED);
		break;
	case HLS_UP_ACTIVE:
		/* XXX - is this error check needed? */
		if (ppd->host_link_state != HLS_UP_ARMED)
			dd_dev_err(
				dd,
				"%s %d: allowing unexpected state transition from %s to %s\n",
				__func__, ppd->port,
				hfi2_link_state_name(ppd->host_link_state),
				hfi2_link_state_name(state));

		ppd->host_link_state = HLS_UP_ACTIVE;
		hfi2_update_statusp(ppd, IB_PORT_ACTIVE);
		hfi2_go_port_active(ppd);
		break;
	case HLS_DN_POLL:
		/* XXX - will we see this? do we need to synthesize it? */

		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			u8 tmp = ppd->link_enabled;

			ret = cport_goto_offline(ppd, pi,
						 ppd->remote_link_down_reason);
			if (ret) {
				ppd->link_enabled = tmp;
				break;
			}
			ppd->remote_link_down_reason = 0;

			if (ppd->driver_link_ready)
				ppd->link_enabled = 1;
		}

		/* XXX - alters *ALL* contexts... should not do this?
		 * At least only alter contexts for this port.
		 */
		hfi2_set_all_slowpath(ppd);

		ppd->port_error_action = 0;

		ppd->host_link_state = HLS_DN_POLL;
		ppd->offline_disabled_reason =
			HFI2_ODR_MASK(OPA_LINKDOWN_REASON_NONE);
		hfi2_log_state_transition(ppd, PLS_POLLING);
		break;
	case HLS_DN_DISABLE:
		/* link is disabled */
		ppd->link_enabled = 0;

		/* allow any state to transition to disabled */

		/* must transition to offline first */
		if (ppd->host_link_state != HLS_DN_OFFLINE) {
			ret = cport_goto_offline(ppd, pi,
						 ppd->remote_link_down_reason);
			if (ret)
				break;
			ppd->remote_link_down_reason = 0;
		}

		ppd->host_link_state = HLS_DN_DISABLE;
		break;
	case HLS_DN_OFFLINE:
		/* allow any state to transition to offline */
		ret = cport_goto_offline(ppd, pi, ppd->remote_link_down_reason);
		if (!ret)
			ppd->remote_link_down_reason = 0;
		break;
	case HLS_GOING_UP: /* never seen by driver */
	case HLS_VERIFY_CAP: /* never seen by driver */
	case HLS_GOING_OFFLINE: /* transient within goto_offline() */
	case HLS_LINK_COOLDOWN: /* transient within goto_offline() */
	default:
		dd_dev_info(dd, "%s %d: state 0x%x: not supported\n", __func__,
			    ppd->port, state);
		ret = -EINVAL;
		break;
	}

done:
	mutex_unlock(&ppd->hls_lock);

	return ret;
}

int hfi2_cport_start_link(struct hfi2_pportdata *ppd, struct opa_port_info *pi)
{
	/*
	 * FULL_MGMT_P_KEY is cleared from the pkey table, so that the
	 * pkey table can be configured properly if the HFI unit is connected
	 * to switch port with MgmtAllowed=NO
	 */
	/* this writes CSRs... clear_full_mgmt_pkey(ppd); so do: */
	if (ppd->pkeys[2] != 0) {
		ppd->pkeys[2] = 0;
		/* avoid hfi2_set_ib_cfg(HFI2_IB_CFG_PKEYS) */
		hfi2_event_pkey_change(ppd->dd, ppd->port);
	}

	return hfi2_cport_set_link_state(ppd, pi, HLS_DN_POLL);
}

/**
 * Ask hfi2_cport firmware for the temperature.
 *
 * @gen_temp: temperature output.
 *
 * Return: 0 on success, -EINVAL on invalid reply from CPORT,
 * -EOPNOTSUPP on reply from CPORT but ASIC temperature not
 * valid/supported.
 */
int hfi2_cport_read_temp(struct hfi2_devdata *dd, struct cport_temp *gen_temp)
{
	struct cport_how_payload *how = NULL;
	int resp_len = 0;
	int ret;

	/* Don't trust the caller; assume invalid */
	gen_temp->asic_valid = 0;
	gen_temp->qsfp1_valid = 0;
	gen_temp->qsfp2_valid = 0;

	ret = hfi2_cport_send_req(dd, CH_OP_HOW, 0, NULL, 0, (void **)&how,
			     &resp_len, hfi2_cport_adm_to * HZ);
	if (ret) {
		dd_dev_err(dd, "CPORT how failed %d\n", ret);
		goto done;
	}
	if (resp_len != sizeof(*how)) {
		dd_dev_err(
			dd,
			"CPORT how invalid response length %d (expected %ld)\n",
			resp_len, sizeof(*how));
		ret = -EINVAL;
		goto done;
	}
	if (!CPORT_HOW_TEMP_VALID(how->temps)) {
		ret = -EOPNOTSUPP;
		goto done;
	}
	gen_temp->asic_valid = 1;
	gen_temp->asic = (s16)CPORT_HOW_TEMP(how->temps);

	gen_temp->qsfp1_valid = CPORT_HOW_QSFP1_TEMP_VALID(how->temps);
	if (gen_temp->qsfp1_valid)
		gen_temp->qsfp1 = (s16)CPORT_HOW_QSFP1_TEMP(how->temps);

	gen_temp->qsfp2_valid = CPORT_HOW_QSFP2_TEMP_VALID(how->temps);
	if (gen_temp->qsfp2_valid)
		gen_temp->qsfp2 = (s16)CPORT_HOW_QSFP2_TEMP(how->temps);
done:
	kfree(how);
	return ret;
}


static void gen_reset_rcvarray(struct hfi2_devdata *dd, u16 ctxt, u32 ra_cnt)
{
	u8 __iomem *ra, *raend;

	ra = dd->bar_maps[ctxt_bar_idx(ctxt)].rcvarray_wc +
		((size_t)ctxt_bar_ctxt(ctxt) << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT);
	for (raend = ra + ((size_t)ra_cnt << JKR_RCV_ARRAY_CSR_INDEX_SHIFT);
			ra < raend;
			ra += 1 << JKR_RCV_ARRAY_CSR_INDEX_SHIFT)
		writeq(RCV_ARRAY_RT_WRITE_ENABLE_SMASK, ra);
	flush_wc();
}

/*
 * Called on PF0 before VFs are created.
 * Context will be used for Eager only (no TID).
 * Initialize all CSRs that can only be accessed by PF0.
 * May be called to reset context for re-use.
 */
int gen_init_rctxt_egr(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt,
		       u32 ra_base, u32 ra_cnt, u32 hdr_size)
{
	u64 reg, kreg;

	/* might need to reclaim context in PF0 */
	if (si)
		write_rctxt_csr(dd, ctxt, JKR_RCV_SI_IDX, 0);

	/* reset eager head/tail by enabling ctxt after write of 0 to heads */
	kreg = read_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg);

	/* disable context, in case it was previously used */
	dd->params->enable_rcv_context(dd, pidx, ctxt, false);
	/* remove RCV_CTXT_CTRL_ENABLE_SMASK (disable) */
	kreg &= ~RCV_CTXT_CTRL_ENABLE_SMASK;
	/* force these bits */
	kreg |= RCV_CTXT_CTRL_ONE_PACKET_PER_EGR_BUFFER_SMASK;
	if (dd->params->chip_type == CHIP_JKR)
		kreg |= JKR_RCV_KCTXT_CTRL_RECEIVE_CUT_THROUGH_DISABLE_SMASK;
	else if (dd->params->chip_type == CHIP_CYR)
		kreg |= CYR_RCV_KCTXT_CTRL_RECEIVE_CUT_THROUGH_DISABLE_SMASK;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg, kreg);

	dd->params->set_port_tid_config(dd, pidx, ctxt, ra_base, ra_cnt, 0, 0);
	dd->params->update_rcv_hdr_size(dd, pidx, ctxt, hdr_size);

	reg = RCV_CTXT_CTRL_INTR_AVAIL_SMASK;
	write_rctxt_csr(dd, ctxt, dd->params->rcv_rctxt_ctrl_reg, reg);
	write_uctxt_csr(dd, ctxt, dd->params->rcv_hdr_head_reg, 0);
	write_uctxt_csr(dd, ctxt, dd->params->rcv_egr_index_head_reg, 0);

	gen_reset_rcvarray(dd, ctxt, ra_cnt);

	/* (re-)enable context */
	dd->params->enable_rcv_context(dd, pidx, ctxt, true);
	kreg |= RCV_CTXT_CTRL_ENABLE_SMASK;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg, kreg);

	/*
	 * Read back RcvKctxtCtrl register to force the write
	 * out and ensure that setting RcvHdrHead.Counter = 1
	 * occurs after receive context enable.
	 */
	kreg = read_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg);

	/*
	 * Must be done after enable. The current value
	 * of RcvHdrHead.Counter is ignored when moving receive
	 * context from disabled to enabled. If set to 1 before, interrupts
	 * will never fire.
	 */
	write_kctxt_csr(dd, ctxt, dd->params->rcv_avail_time_out_reg,
			RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK <<
			RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_SHIFT);
	hfi2_update_usrhead_ctxt(dd, ctxt, 0, 1, 0, 0);

	/*
	 * Leave something for the VF to probe on.
	 * Set any non-zero value, will be changed by VF later.
	 */
	reg = ((u64)hfi2_encode_rcv_header_entry_size(32) & RCV_HDR_ENT_SIZE_ENT_SIZE_MASK) <<
	      RCV_HDR_ENT_SIZE_ENT_SIZE_SHIFT;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_ent_size_reg, reg);

	/* finally, assign context to VF */
	if (si)
		write_rctxt_csr(dd, ctxt, JKR_RCV_SI_IDX, si);
	return 0;
}

void gen_deinit_rctxt(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt)
{
	u32 ra_cnt;

	/* first, assign context back to PF0 */
	if (si)
		write_rctxt_csr(dd, ctxt, JKR_RCV_SI_IDX, 0);

	ra_cnt = ((read_rctxt_csr(dd, ctxt, dd->params->rcv_egr_ctrl_reg) >>
		   RCV_EGR_CTRL_EGR_CNT_SHIFT) &
		  RCV_EGR_CTRL_EGR_CNT_MASK) << RCV_SHIFT;
	dd->params->enable_rcv_context(dd, pidx, ctxt, false);

	gen_reset_rcvarray(dd, ctxt, ra_cnt);

	write_kctxt_csr(dd, ctxt, dd->params->rcv_kctxt_ctrl_reg, 0);
	write_rctxt_csr(dd, ctxt, dd->params->rcv_rctxt_ctrl_reg, 0);
	write_rctxt_csr(dd, ctxt, dd->params->rcv_egr_ctrl_reg, 0);

	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_cnt_reg, 0);
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_ent_size_reg, 0);
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_addr_reg, 0);
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_tail_addr_reg, 0);
}

int gen_start_sctxt(struct hfi2_devdata *dd, u8 pidx, u16 ctxt, struct hfi2_ctxtbufs *bufs)
{
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_err_mask_reg, (u64)-1);
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_credit_return_addr_reg, bufs->cr.dma);
	return 0;
}

/*
 * Called by VFs before first VF-PF message.
 */
int gen_start_rctxt_egr(struct hfi2_devdata *dd, u8 pidx, u16 ctxt,
			struct hfi2_ctxtbufs *bufs)
{
	u8 __iomem *ra;
	u16 order;
	u64 reg;
	u32 r_each, r_size, etail;
	dma_addr_t r_dma;

	/* cleanup from anything sent while no driver */
	etail = read_uctxt_csr(dd, ctxt, JKR_RCV_EGR_INDEX_TAIL) & 0xffff;
	if (etail)
		hfi2_update_usrhead_ctxt(dd, ctxt, 0, 1, 1, etail);
	/* just clear overflow coount - can't do anything else */
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_ovfl_cnt_reg, 0);

	/* assumes RCV_CTXT_CTRL_ONE_PACKET_PER_EGR_BUFFER_SMASK is set */
	r_each = bufs->egr_buf_size;
	r_dma = bufs->egr.dma;
	r_size = bufs->egr.size;
	order = hfi2_encoded_size(r_each);

	if (r_size < r_each)	/* none allocated */
		return -ENOSPC;
	ra = dd->bar_maps[ctxt_bar_idx(ctxt)].rcvarray_wc +
		((size_t)ctxt_bar_ctxt(ctxt) << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT);
	reg = RCV_ARRAY_RT_WRITE_ENABLE_SMASK |
		((u64)order << JKR_RCV_ARRAY_EGR_RT_BUF_SIZE_SHIFT) |
		      (r_dma >> RT_ADDR_SHIFT);

	do {
		writeq(reg, ra);
		ra += 1 << JKR_RCV_ARRAY_CSR_INDEX_SHIFT;
		r_size -= r_each;
		reg += r_each >> RT_ADDR_SHIFT;
	} while (r_size >= r_each);

	flush_wc();

	reg = (((u64)bufs->rhq_cnt >> HDRQ_SIZE_SHIFT) & RCV_HDR_CNT_CNT_MASK) <<
	      RCV_HDR_CNT_CNT_SHIFT;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_cnt_reg, reg);
	reg = ((u64)hfi2_encode_rcv_header_entry_size(bufs->rhq_ent_size) &
	       RCV_HDR_ENT_SIZE_ENT_SIZE_MASK) << RCV_HDR_ENT_SIZE_ENT_SIZE_SHIFT;
	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_ent_size_reg, reg);

	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_addr_reg, bufs->rhq.dma);
	if (dd->params->set_rheq_addr)
		dd->params->set_rheq_addr(dd, ctxt, bufs->rheq.dma);

	write_kctxt_csr(dd, ctxt, dd->params->rcv_hdr_tail_addr_reg,
			dd->rcvhdrtail_dummy_dma);

	return 0;
}

/*
 * Called on PF0 before VFs are created.
 * Context is used for PIO only (no SDMA).
 * Initialize all CSRs that can only be accessed by PF0.
 */
int gen_init_sctxt_pio(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt,
		       u32 cr_base, u32 cr_cnt)
{
	u64 reg;
	int ret;

	/* might need to reclaim context in PF0 */
	if (si)
		write_tctxt_csr(dd, ctxt, JKR_SEND_CTXT_SI_IDX, 0);

	/* first, ensure context is disabled - to ensure reset */
	ret = hfi2_priv_reg_op(dd, pidx, ctxt, SC_KERNEL, SC_DISABLE_OP, 0);
	if (ret)
		return ret;

	reg = ((u64)cr_cnt << SEND_CTXT_CTRL_CTXT_DEPTH_SHIFT) |
	      ((u64)cr_base << dd->params->pio_base_shift);
	write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, reg);
	/* or: dd->params->set_pio_integrity(dd, pidx, ctxt, SC_KERNEL, SPI_INIT) */
	write_epsc_csr(dd, pidx, ctxt,
		       dd->params->send_ctxt_check_enable_reg,
		       JKR_SEND_CTXT_CHECK_ENABLE_L2_TYPE9BALLOWED_SMASK);
	write_epsc_csr(dd, pidx, ctxt,
		       dd->params->send_ctxt_check_partition_key_reg,
		       (SEND_CTXT_CHECK_PARTITION_KEY_VALUE_MASK & DEFAULT_PKEY) <<
		       SEND_CTXT_CHECK_PARTITION_KEY_VALUE_SHIFT);
	write_epsc_csr(dd, pidx, ctxt,
		       dd->params->send_ctxt_check_opcode_reg,
		       ((u64)OPCODE_CHECK_MASK_DISABLED <<
			SEND_CTXT_CHECK_OPCODE_MASK_SHIFT) |
		       ((u64)OPCODE_CHECK_VAL_DISABLED <<
			SEND_CTXT_CHECK_OPCODE_VALUE_SHIFT));

	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_err_mask_reg, 0);
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_credit_return_addr_reg, 0);

	/* TODO: what is the correct CR threshold? */
	reg = 1 << SEND_CTXT_CREDIT_CTRL_THRESHOLD_SHIFT;
	/* TODO: need to save? sc->credit_ctrl = reg; */
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_credit_ctrl_reg, reg);
	/* send_ctxt_check_vl_reg stays 0? */

	reg = read_sctxt_csr(dd, ctxt, dd->params->send_ctxt_err_status_reg);
	if (reg)
		write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_err_clear_reg, reg);

	/* this does a PIO init on the context */
	ret = hfi2_priv_reg_op(dd, pidx, ctxt, SC_KERNEL, SC_ENABLE_OP, 0);
	if (ret)
		return ret;

	/* finally, assign context to VF */
	if (si)
		write_tctxt_csr(dd, ctxt, JKR_SEND_CTXT_SI_IDX, si);

	return 0;
}

static void set_sc_check(struct hfi2_devdata *dd, u8 pidx, u32 ctxt, int type)
{
	u8 opval, opmask;

	/* set the default partition key */
	write_epsc_csr(dd, pidx, ctxt,
		       dd->params->send_ctxt_check_partition_key_reg,
		       (SC(CHECK_PARTITION_KEY_VALUE_MASK) & DEFAULT_PKEY)
			       << SC(CHECK_PARTITION_KEY_VALUE_SHIFT));
	/* per context type checks */
	if (type == SC_USER || type == SC_BULKSVC) {
		opval = USER_OPCODE_CHECK_VAL;
		opmask = USER_OPCODE_CHECK_MASK;
	} else {
		opval = OPCODE_CHECK_VAL_DISABLED;
		opmask = OPCODE_CHECK_MASK_DISABLED;
	}
	/* set the send context check opcode mask and value */
	write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_opcode_reg,
		       ((u64)opmask << SC(CHECK_OPCODE_MASK_SHIFT)) |
			       ((u64)opval << SC(CHECK_OPCODE_VALUE_SHIFT)));
	/* User send contexts should not allow sending on VL15 */
	if (type == SC_USER) {
		write_epsc_csr(dd, pidx, ctxt,
			       dd->params->send_ctxt_check_vl_reg, 1ULL << 15);
	}
}

int hfi2_priv_reg_op(struct hfi2_devdata *dd, int pidx, u32 ctxt, int type,
		enum preg_op op, u64 arg)
{
	u16 rctxt;
	int ret = 0;

	rctxt = ctxt >> 16;
	ctxt &= 0xffff;

	if (dd->is_vf) {
		ret = vf2pf_priv_reg_op(dd, pidx, ctxt, type, op, arg);
		if (ret)
			dd_dev_err(dd, "vf2pf_priv_reg_op(%d) failed %d\n", op, ret);
		return ret;
	}

	/* Only PF0 has access to these CSRs */
	switch (op) {
	case SC_CHK_ALLOC_OP: /* 'arg' is send_ctxt_ctrl_reg value */
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_DEFAULT);
		set_sc_check(dd, pidx, ctxt, type);
		if (dd->is_sriov)
			set_sc_check(dd, loopback_pidx_dd(dd, pidx), ctxt, type);
		break;
	case SC_CHK_FREE_OP: /* 'arg' not used */
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, 0);
		write_epsc_csr(dd, pidx, ctxt,
			       dd->params->send_ctxt_check_enable_reg, 0);
		write_epsc_csr(dd, pidx, ctxt,
			       dd->params->send_ctxt_check_partition_key_reg, 0);
		write_epsc_csr(dd, pidx, ctxt,
			       dd->params->send_ctxt_check_opcode_reg, 0);
		if (dd->is_sriov) {
			pidx = loopback_pidx_dd(dd, pidx);
			write_epsc_csr(dd, pidx, ctxt,
				       dd->params->send_ctxt_check_enable_reg, 0);
			write_epsc_csr(dd, pidx, ctxt,
				       dd->params->send_ctxt_check_partition_key_reg, 0);
			write_epsc_csr(dd, pidx, ctxt,
				       dd->params->send_ctxt_check_opcode_reg, 0);
		}
		break;
	case SC_CHK_VL_MASK_OP: /* 'arg' is send_ctxt_check_vl_reg value */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_vl_reg, arg);
		if (dd->is_sriov)
			write_epsc_csr(dd, loopback_pidx_dd(dd, pidx), ctxt,
				       dd->params->send_ctxt_check_vl_reg, arg);
		break;
	case SC_CHK_SLID_OP: /* 'arg' is send_ctxt_check_slid_reg value */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_slid_reg, arg);
		if (dd->is_sriov)
			write_epsc_csr(dd, loopback_pidx_dd(dd, pidx), ctxt,
				       dd->params->send_ctxt_check_slid_reg, arg);
		break;
	case SC_CHK_JKEY_OP: /* 'arg' is send_ctxt_check_job_key_reg val, 'ctxt' incl rcv */
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_job_key_reg, arg);
		if (dd->is_sriov)
			write_epsc_csr(dd, loopback_pidx_dd(dd, pidx), ctxt,
				       dd->params->send_ctxt_check_job_key_reg, arg);
		if (!hfi2_is_ax(dd)) {
			dd->params->set_pio_integrity(dd, pidx, ctxt, type,
				arg ? SPI_SET_JKEY : SPI_CLEAR_JKEY);
		}
		/* Enable/clear J_KEY check on receive context. */
		if (arg) {
			/* convert sctxt jkey to rctxt */
			arg = (arg >> SEND_CTXT_CHECK_JOB_KEY_VALUE_SHIFT) &
				SEND_CTXT_CHECK_JOB_KEY_VALUE_MASK;
			arg = RCV_KEY_CTRL_JOB_KEY_ENABLE_SMASK |
				((arg & RCV_KEY_CTRL_JOB_KEY_VALUE_MASK) <<
				 RCV_KEY_CTRL_JOB_KEY_VALUE_SHIFT);
		}
		/*
		 * Skip rcv-side J_KEY register writes for send-only contexts,
		 * which have no receive context.
		 */
		if (rctxt != HFI2_NO_RCV_CTXT) {
			write_iprc_csr(dd, pidx, rctxt,
				       dd->params->rcv_jkey_ctrl_reg, arg);
			if (dd->is_sriov)
				write_iprc_csr(dd, loopback_pidx_dd(dd, pidx),
					       rctxt,
					       dd->params->rcv_jkey_ctrl_reg, arg);
		}
		break;
	case SC_CHK_PKEY_OP: /* 'arg' is send_ctxt_check_partition_key_reg value */
		if (!arg)
			dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_CLEAR_PKEY);
		write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_partition_key_reg, arg);
		if (dd->is_sriov)
			write_epsc_csr(dd, loopback_pidx_dd(dd, pidx), ctxt,
				       dd->params->send_ctxt_check_partition_key_reg, arg);
		if (arg)
			dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_SET_PKEY);
		break;
	case SC_CHK_ADJ_OP: /* 'arg' is enable flag (do SC_CHK_INIT_OP also) */
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_DEFAULT);
		if (!arg)
			break;
		fallthrough;
	case SC_CHK_INIT_OP: /* 'arg' not used */
		dd->params->set_pio_integrity(dd, pidx, ctxt, type, SPI_INIT);
		break;
	case SC_ENABLE_OP: /* 'arg' not used as input, 'pidx' not used */
		ret = hfi2_pio_reset_one(dd, ctxt);
		if (ret)
			break;

		/*
		 * All is well. Enable the context.
		 */
		arg = read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		arg |= SC(CTRL_CTXT_ENABLE_SMASK);
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		/*
		 * Read SendCtxtCtrl to force the write out and prevent a timing
		 * hazard where a PIO write may reach the context before the enable.
		 */
		read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		break;
	case SC_DISABLE_OP: /* 'arg' not used as input, 'pidx' not used */
		arg = read_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg);
		arg &= ~SC(CTRL_CTXT_ENABLE_SMASK);
		write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, arg);
		break;
	case RC_ENABLE_OP: /* 'arg' is enable flag */
		dd->params->enable_rcv_context(dd, pidx, ctxt, arg);
		if (dd->is_sriov)
			dd->params->enable_rcv_context(dd, loopback_pidx_dd(dd, pidx),
						       ctxt, arg);
		break;
	case RC_HEADER_OP: /* 'arg' is size */
		dd->params->update_rcv_hdr_size(dd, pidx, ctxt, arg);
		if (dd->is_sriov)
			dd->params->update_rcv_hdr_size(dd, loopback_pidx_dd(dd, pidx),
							ctxt, arg);
		break;
	case LINK_BOUNCE_OP: /* 'arg' is not used */
		queue_work(dd->pport[pidx].link_wq, &dd->pport[pidx].link_bounce_work);
		break;
	}
	return ret;
}

static int cport_do_scsl(struct hfi2_pportdata *ppd)
{
	struct opa_smp *mad;
	int ret;

	mad = cport_get_opa_mad(ppd->dd, ppd->hw_pidx + 1, OPA_ATTRIB_ID_SC_TO_SL_MAP);
	if (IS_ERR(mad))
		return PTR_ERR(mad);

	ret = cport_set_opa_scsl_table(ppd, mad, opa_get_smp_data(mad));
	kfree(mad);
	return ret;
}

static int cport_do_slsc(struct hfi2_pportdata *ppd)
{
	struct opa_smp *mad;
	int ret;

	mad = cport_get_opa_mad(ppd->dd, ppd->hw_pidx + 1, OPA_ATTRIB_ID_SL_TO_SC_MAP);
	if (IS_ERR(mad))
		return PTR_ERR(mad);

	ret = cport_set_opa_slsc_table(ppd, mad, opa_get_smp_data(mad));
	kfree(mad);
	return ret;
}

static int cport_initial_queries(struct hfi2_pportdata *ppd)
{
	int ret;
	int rc = 0;

	/* Additional information to get from CPORT since MADs may never be seen */
	ret = cport_do_scsl(ppd);
	if (ret) {
		ppd_dev_err(ppd, "Failed to update SC_TO_SL_MAP from CPORT (%d)\n",
			    ret);
		rc = ret;
	}
	ret = cport_do_slsc(ppd);
	if (ret) {
		ppd_dev_err(ppd, "Failed to update SL_TO_SC_MAP from CPORT (%d)\n",
			    ret);
		rc = ret;
	}
	hfi2_get_sc2vlt_tables(ppd, ppd->sc2vl);

	return rc;
}

void gen_enable_rcv_context(struct hfi2_pportdata *ppd, u16 ctxt,
			    u64 *kctxt_ctrl, bool enable)
{
	struct hfi2_devdata *dd = ppd->dd;

	hfi2_priv_reg_op(dd, ppd->hw_pidx, ctxt, 0, RC_ENABLE_OP, enable);

	if (enable && dd->params->chip_type == CHIP_JKR) /* adjustments to KctxtCtrl */
		*kctxt_ctrl |= JKR_RCV_KCTXT_CTRL_RECEIVE_CUT_THROUGH_DISABLE_SMASK;
	else if (enable && dd->params->chip_type == CHIP_CYR) /* adjustments to KctxtCtrl */
		*kctxt_ctrl |= CYR_RCV_KCTXT_CTRL_RECEIVE_CUT_THROUGH_DISABLE_SMASK;
}

void gen_update_rcv_hdr_size(struct hfi2_pportdata *ppd, u16 ctxt, u32 size)
{
	struct hfi2_devdata *dd = ppd->dd;

	hfi2_priv_reg_op(dd, ppd->hw_pidx, ctxt, 0, RC_HEADER_OP, size);
}

void set_si_int_enable_range(struct hfi2_devdata *dd, u64 *csrs, u32 start, u32 end)
{
	unsigned int i;
	u32 idx;
	u32 bit;

	for (i = start; i < end; ++i) {
		idx = i / 64;
		bit = i % 64;
		csrs[idx] |= (1ull << bit);
	}
}

void write_si_int_enable(struct hfi2_devdata *dd, int si, u64 *csrs)
{
	int i;
	u32 base;

	base = CHIP_SW(dd, CCE_SI_INT_ENABLES) + CHIP_SW(dd, C_CCE_SI_INT_ENABLES_STRIDE) * si;
	for (i = 0; i < dd->params->num_int_csrs; ++i) {
		hfi2_write_csr(dd, base + (i * 8), csrs[i]);
	}
}

/* non-RXE, non-TXE, csr init */
void gen_init_si_ints(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs dr;
	int si, nsi;
	u64 csrs[LARGEST_NUM_INT_CSRS];
	u32 is_base, is_end;

	if (dd->is_vf)
		return; /* VFs can't access these CSRs */

	nsi = dd->rsrcs.num_vfs + 1; /* #VFs + PF0 */

	/* Enable interrupts for each SI according to allocated resources */
	for (si = 0; si < nsi; ++si) {
		if (si)
			hfi2_sriov_get_config(dd, &dr, si);
		else
			dr = dd->rsrcs; /* TODO: avoid this copy? */
		memset(csrs, 0, sizeof(csrs));
		if (!si) {
			is_base = CHIP_SW(dd, IS_GENERAL_ERR_START);
			is_end = CHIP_SW(dd, ASIC_ERR_INT);
			set_si_int_enable_range(dd, csrs, is_base, is_end + 1);
			is_base = CHIP_SW(dd, MCTXT_CPORT_TO_PCIE_INT);
			set_si_int_enable_range(dd, csrs, is_base, is_base + 1);

			/*
			 * Route FlrInt0..7 to PF0's SI=0 so PF0
			 * takes the per-VF FLR interrupt.
			 */
			is_base = CHIP_SW(dd, IS_FLR_START);
			is_end = CHIP_SW(dd, IS_FLR_END);
			set_si_int_enable_range(dd, csrs, is_base, is_end + 1);
		}
		is_base = dd->params->is_sdmaeng_err_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.first_sdma_engine,
					is_base + dr.last_sdma_engine);
		is_base = CHIP_SW(dd, IS_SENDCTXT_ERR_START);
		set_si_int_enable_range(dd, csrs,
					is_base + dr.c.first_send_context,
					is_base + dr.c.last_send_context);
		is_base = dd->params->is_sdma_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.first_sdma_engine,
					is_base + dr.last_sdma_engine);
		is_base = dd->params->is_sdma_progress_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.first_sdma_engine,
					is_base + dr.last_sdma_engine);
		is_base = dd->params->is_sdma_idle_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.first_sdma_engine,
					is_base + dr.last_sdma_engine);
		is_base = dd->params->is_rcvavail_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.c.first_rcv_context,
					is_base + dr.c.last_rcv_context);
		is_base = dd->params->is_rcvurgent_start;
		set_si_int_enable_range(dd, csrs,
					is_base + dr.c.first_rcv_context,
					is_base + dr.c.last_rcv_context);
		is_base = CHIP_SW(dd, IS_SENDCREDIT_START);
		set_si_int_enable_range(dd, csrs,
					is_base + dr.c.first_send_context,
					is_base + dr.c.last_send_context);
		is_base = CHIP_SW(dd, IS_PBC_START);
		set_si_int_enable_range(dd, csrs,
					is_base + dr.c.first_send_context,
					is_base + dr.c.last_send_context);
		is_base = CHIP_SW(dd, IS_PIO_ERR_START);
		set_si_int_enable_range(dd, csrs,
					is_base + si,
					is_base + si + 1);
		is_base = CHIP_SW(dd, IS_SDMA_ERR_SI_START);
		set_si_int_enable_range(dd, csrs,
					is_base + si,
					is_base + si + 1);
		is_base = CHIP_SW(dd, IS_CSR_ERR_START);
		set_si_int_enable_range(dd, csrs,
					is_base + si,
					is_base + si + 1);
		vf2pf_set_si_enables(dd, si, csrs, set_si_int_enable_range);
		write_si_int_enable(dd, si, csrs);
	}
}

/*
 * Obtain data available in CPORT WHO command.
 */
int gen_cport_who_init(struct hfi2_devdata *dd)
{
	struct cport_who_payload *who = NULL;
	int resp_len = 0;
	int ret = 0;

	dd->base_guid = 0xabcd;	/* on success, a valid value is set */
	ret = hfi2_cport_send_req(dd, CH_OP_WHO, 0, NULL, 0, (void **)&who, &resp_len, HZ);
	if (ret) {
		dd_dev_err(dd, "CPORT who failed %d\n", ret);
	} else if (resp_len == sizeof(*who)) {
		struct ib_device *ibdev = &dd->verbs_dev.rdi.ibdev;
		char v_str[IB_FW_VERSION_NAME_MAX] = {};

		dd->base_guid = who->node_guid;
		/* XXX this should be replaced by a TRAP to set guid */
		if (!hfi2_ib_hfi2_sys_image_guid)
			hfi2_ib_hfi2_sys_image_guid = cpu_to_be64(dd->base_guid);
		/* XXX need guids for all ports */
		dd->cport_ver = who->vers;
		dd->cport->suppt = who->suppt;
		hfi2_cport_ib_get_dev_fw_str(ibdev, v_str);
		dd_dev_info(dd, "CPORT firmware version %s\n",
			    v_str);
	} else
		dd_dev_err(dd, "CPORT who invalid resp %d\n", resp_len);

	kfree(who);
	return ret;
}

void gen_deinit_sctxt(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt)
{
	/* first, assign context back to PF0 */
	if (si)
		write_tctxt_csr(dd, ctxt, JKR_SEND_CTXT_SI_IDX, 0);

	write_tctxt_csr(dd, ctxt, dd->params->send_ctxt_ctrl_reg, 0);
	write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_enable_reg, 0);
	write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_partition_key_reg, 0);
	write_epsc_csr(dd, pidx, ctxt, dd->params->send_ctxt_check_opcode_reg, 0);
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_err_mask_reg, 0);
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_credit_return_addr_reg, 0);
	write_sctxt_csr(dd, ctxt, dd->params->send_ctxt_credit_ctrl_reg, 0);
}

static int pf2vf_push_vport_info(struct hfi2_pportdata *ppd,
				 unsigned long si_mask)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct opa_smp *smp;
	unsigned long id;
	int ret = 0;

	si_mask &= atomic_read(&dd->rsrcs.sync_done);
	if (!si_mask)
		return 0;

	smp = kzalloc(sizeof(*smp), GFP_KERNEL);
	if (!smp)
		return -ENOMEM;
	for_each_set_bit(id, &si_mask,
			 min_t(int, dd->rsrcs.num_vfs, HFI2_MAX_VPORT_VFS) + 1) {
		struct hfi2_vport_info *vpi;
		u32 lid;
		u8 state;

		if (!id)
			continue;
		lid = READ_ONCE(ppd->vf_lid[id - 1]);
		state = READ_ONCE(ppd->vf_state[id - 1]);
		if (!lid && !state)
			continue;
		memset(smp, 0, sizeof(*smp));
		smp->method = IB_MGMT_METHOD_SET;
		smp->attr_id = HFI2_ATTR_VPORT_INFO;
		smp->attr_mod = cpu_to_be32(id << 16);
		vpi = (struct hfi2_vport_info *)opa_get_smp_data(smp);
		vpi->lid = cpu_to_be32(lid);
		vpi->state_flags = state;
		ret = pf2vf_vport_mad(ppd, id, smp);
		if (ret) {
			ppd_dev_warn(ppd, "Failed to replay VPortInfo to %lu (%d)\n",
				     id, ret);
			break;
		}
	}
	kfree(smp);
	return ret;
}

int hfi2_sriov_sync_ports(struct hfi2_devdata *dd, int si_mask)
{
	int pidx;
	int ret = 0;

	if (dd->is_vf)
		return -EINVAL;
	for (pidx = 0; pidx < dd->params->num_ports && !ret; ++pidx) {
		ret = pf2vf_push_vport_pkeys(&dd->pport[pidx], si_mask);
		if (!ret)
			ret = pf2vf_push_vport_guid(&dd->pport[pidx], si_mask);
		if (!ret)
			ret = pf2vf_push_vport_info(&dd->pport[pidx], si_mask);
	}
	return ret;
}

#ifdef DEBUG_CPORT_TRAP
static const char *ps_state_name(struct opa_port_states *ps)
{
	static const char * const state_name[] = {
		[IB_PORT_NOP]		= "NOP",
		[IB_PORT_DOWN]		= "DOWN",
		[IB_PORT_INIT]		= "INIT",
		[IB_PORT_ARMED]		= "ARMED",
		[IB_PORT_ACTIVE]	= "ACTIVE",
		[IB_PORT_ACTIVE_DEFER]	= "ACTIVE_DEFER"
	};
	u8 ls = port_states_to_logical_state(ps);

	if (ls > IB_PORT_ACTIVE_DEFER)
		return "???";
	return state_name[ls];
}
#endif


u64 read_csr_type(struct hfi2_devdata *dd, enum csr_type type, u32 off,
		  u16 ctxt, u8 pidx_eng)
{
	u64 reg = ~0ull;

	switch (type) {
	case CSR_TYPE_IPORT:
		reg = read_iport_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_IPRC:
		reg = read_iprc_csr(dd, pidx_eng, ctxt, off);
		break;
	case CSR_TYPE_RCTXT:
		reg = read_rctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_KCTXT:
		reg = read_kctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_KU:
		reg = read_ku_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_UCTXT:
		reg = read_uctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_SCTXT:
		reg = read_sctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_TCTXT:
		reg = read_tctxt_csr(dd, ctxt, off);
		break;
	case CSR_TYPE_SDMA:
		reg = read_sdma_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_SDMACFG:
		reg = read_sdmacfg_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_EPORT:
		reg = read_eport_csr(dd, pidx_eng, off);
		break;
	case CSR_TYPE_EPSC:
		reg = read_epsc_csr(dd, pidx_eng, ctxt, off);
		break;
	case CSR_TYPE_EPSCARR:
		reg = read_epscarr_csr(dd, pidx_eng, ctxt, off);
		break;
	}
	return reg;
}
