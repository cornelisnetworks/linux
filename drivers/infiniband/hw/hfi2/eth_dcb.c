// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 *  Copyright (c) 2026, Cornelis Networks
 *
 *  Data Center Bridging (DCB) support
 */

#include <linux/dcbnl.h>
#include "eth_main.h"

#define CYR_RBUF_CREDS 0x2000 /* TODO: use RcvBufSize */

/* HAS 0.6.1 reset thresholds of EAL_RX_PAUSE_CONFIG_VL0 and _SHR */
#define CYR_RBUF_RESET_LOW_WATER	0x800
#define CYR_RBUF_RESET_RESTART		0x1000

/**
 * cne_set_pause_enabled - allow VLs to generate pause/PFC frames
 * @ndev: network device
 * @enable_bitmask: VLs allowed to pause (bit n = VL/priority n)
 */
void cne_set_pause_enabled(struct net_device *ndev, u8 enable_bitmask)
{
	u64 pause_disable;
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 reg = CYR_EAL_PF_FORCE_PAUSE_DISABLE;

	edev->pause_enable_mask = enable_bitmask;
	pause_disable = hfi2_read_csr(dd, reg);
	EAL_PF_FORCE_PAUSE_DISABLE_SET_MASK(pause_disable, (u8)~enable_bitmask);
	hfi2_write_csr(dd, reg, pause_disable);
}

/**
 * cne_eal_pfc_pause_is_enabled - Determine if CRK EAL has PFC enabled
 * @edev: ether_device to query
 *
 * Return: True if CSR's for PFC are configured and enabled.
 */
static bool cne_eal_pfc_pause_is_enabled(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;

	u64 tx_pause_reg;
	u64 rx_pause_reg;
	u8 pause_enabled, pfc_configured;

	/* during an EAL reset report, and keep, the last state read */
	if (!cne_eal_read(dd, CYR_EAL_PF_FORCE_PAUSE_DISABLE, &tx_pause_reg) ||
	    !cne_eal_read(dd, CYR_EAL_RX_PAUSE_CONFIG, &rx_pause_reg))
		return READ_ONCE(edev->pfc_enabled) && edev->pause_enable_mask;

	pause_enabled = ~EAL_PF_FORCE_PAUSE_DISABLE_GET_MASK(tx_pause_reg);
	pfc_configured = EAL_RX_PAUSE_CFG_GET_PFC_ENABLED(rx_pause_reg);

	WRITE_ONCE(edev->pfc_enabled, (u8)pfc_configured);

	return pause_enabled && pfc_configured;
}

/**
 * get_pfc_en - Get enabled PFC priorities
 * @ndev: network device
 *
 * Return: bitmask of enabled PFC priorities
 */
static u8 get_pfc_en(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u8 pfc_en = 0;
	u64 pause_reg;
	u32 pause_cfg_vl_csr, i;

	pause_cfg_vl_csr = CYR_EAL_RX_PAUSE_CONFIG_VL0;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++, pause_cfg_vl_csr += 8) {
		pause_reg = hfi2_read_csr(dd, pause_cfg_vl_csr);
		pdbg(edev, drv, "VL %d pause config:\n", i);
		pdbg(edev, drv, "\tcreds %llu\n",
		     EAL_RX_PAUSE_CFG_VL0_GET_CREDITS(pause_reg));
		pdbg(edev, drv, "\tlow_water_thresh%llu\n",
		     EAL_RX_PAUSE_CFG_VL0_GET_LOW_WATER(pause_reg));
		pdbg(edev, drv, "\trestart_thresh %llu\n",
		     EAL_RX_PAUSE_CFG_VL0_GET_RESTART(pause_reg));
		pfc_en |= ((!!EAL_RX_PAUSE_CFG_VL0_GET_LOW_WATER(pause_reg)) << i);
	}

	return pfc_en;
}

/**
 * cne_dcb_ieee_getpfc - Get PFC configuration
 * @ndev: network device
 * @pfc: storage for PFC configuration
 *
 * This is the .ieee_getpfc dcbnl_rtnl_ops implementation.
 *
 * Return: 0 on success.
 */
static int cne_dcb_ieee_getpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	u8 pcp_supported = ppd->vls_operational;
	u8 i;

	/* TC's map to VL's 1:1 */
	pfc->pfc_cap = min_t(u8, pcp_supported, IEEE_8021QAZ_MAX_TCS);

	if (cne_eal_pfc_pause_is_enabled(edev))
		pfc->pfc_en = get_pfc_en(ndev);
	else
		pfc->pfc_en = 0;

	/* not reporting:
	 *	- pfc->mb - not supported
	 *	- pfc->delay - unknown
	 *	- pfc->indications - CRK does not track
	 */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		pfc->requests[i] = cne_eal_rbuf_pause_cntr_vl(ndev, i);

	return 0;
}

/**
 * set_vl_percent_rbuf_space - Set rbuf space for a VL
 * @ndev: network device
 * @vl_idx: VL index
 * @percent: percentage of rbuf space to allocate
 * @enable_pfc: if PFC is enabled for this VL
 */
static void set_vl_percent_rbuf_space(struct net_device *ndev, u8 vl_idx,
				      u8 percent, bool enable_pfc)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	u32 restart_percent = 50; /* between low_water and rbuf_cred */
	u32 new_rbuf_creds, new_low_water, new_restart, pause_cfg_vl_csr;
	u64 pause_reg;
	u32 low_to_full_delta, low_to_restart_delta;

	low_to_full_delta = (percent * CYR_RBUF_CREDS) / 100;
	low_to_restart_delta = (restart_percent * low_to_full_delta) / 100;

	if (enable_pfc) {
		new_rbuf_creds = CYR_RBUF_CREDS;
		new_low_water = new_rbuf_creds - low_to_full_delta;
		new_restart = new_low_water + low_to_restart_delta;
	} else {
		new_rbuf_creds = low_to_full_delta;
		new_low_water = 0;
		new_restart = 0;
	}

	pause_cfg_vl_csr = CYR_EAL_RX_PAUSE_CONFIG_VL0 + (vl_idx * 8);
	pause_reg = hfi2_read_csr(ppd->dd, pause_cfg_vl_csr);
	pdbg(edev, drv, "Setting VL %d to %u%% bw:\n", vl_idx, percent);
	pdbg(edev, drv, "\tcreds %llu -> %u\n",
	     EAL_RX_PAUSE_CFG_VL0_GET_CREDITS(pause_reg), new_rbuf_creds);
	pdbg(edev, drv, "\tlow_water_thresh %llu -> %u\n",
	     EAL_RX_PAUSE_CFG_VL0_GET_LOW_WATER(pause_reg), new_low_water);
	pdbg(edev, drv, "\trestart_thresh %llu -> %u\n",
	     EAL_RX_PAUSE_CFG_VL0_GET_RESTART(pause_reg), new_restart);

	EAL_RX_PAUSE_CFG_VL0_SET_CREDITS(pause_reg, new_rbuf_creds);
	EAL_RX_PAUSE_CFG_VL0_SET_LOW_WATER(pause_reg, new_low_water);
	EAL_RX_PAUSE_CFG_VL0_SET_RESTART(pause_reg, new_restart);
	hfi2_write_csr(ppd->dd, pause_cfg_vl_csr, pause_reg);
}

/**
 * assign_pfc_pause_config - Assign PFC pause configuration
 * @ndev: network device
 * @pfc_en: bitmask of enabled PFC priorities
 *
 * Current algorithm is to perform the following:
 *	- Shared rbuf:
 *		- allocate 100% rbuf
 *		- low_water at 20%
 *	- PFC enabled VLs:
 *		- allocate 100% rbuf
 *		- low water at 90% rbuf
 *	- PFC disabled VLs:
 *		- allocate 10% rbuf
 *		- low water at 0% rbuf
 *	- Set restart to halfway between low water and rbuf credits
 *
 * This design allows 20% of the rbuf for emergency low water. The other
 * 80% is divided equally amongst the 8 VLs (10% each). This is an
 * unfortunate workaround for the EAL design which only allows threshold
 * values to be independent per VL. They have no knowledge what the usage
 * of other VLs are or what the remaining rbuf credits for the full rbuf
 * are. We are therefore forced to divide the rbuf among VLs.
 */
static void assign_pfc_pause_config(struct net_device *ndev, u8 pfc_en)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	u32 per_vl_low_to_full_percent = 10;
	u32 shr_lw_percent = 20;
	u32 shr_lw_thresh = (shr_lw_percent * CYR_RBUF_CREDS) / 100;
	u64 reg, old;
	u8 enabled, i;

	/* set shared memory */
	reg = hfi2_read_csr(ppd->dd, CYR_EAL_RX_PAUSE_CFG_SHR);
	old = reg;
	EAL_RX_PAUSE_CFG_SHR_SET_RBUF_CREDITS(reg, CYR_RBUF_CREDS);
	EAL_RX_PAUSE_CFG_SHR_SET_LOW_WATER_THRESHOLD(reg, shr_lw_thresh);
	EAL_RX_PAUSE_CFG_SHR_SET_RESTART_THRESHOLD(reg, shr_lw_thresh +
						   (CYR_RBUF_CREDS - shr_lw_thresh) / 2);
	pdbg(edev, drv,
	     "Shared rbuf: creds %llu -> %llu low_water %llu -> %llu restart %llu -> %llu\n",
	     EAL_RX_PAUSE_CFG_SHR_GET_RBUF_CREDITS(old),
	     EAL_RX_PAUSE_CFG_SHR_GET_RBUF_CREDITS(reg),
	     EAL_RX_PAUSE_CFG_SHR_GET_LOW_WATER_THRESHOLD(old),
	     EAL_RX_PAUSE_CFG_SHR_GET_LOW_WATER_THRESHOLD(reg),
	     EAL_RX_PAUSE_CFG_SHR_GET_RESTART_THRESHOLD(old),
	     EAL_RX_PAUSE_CFG_SHR_GET_RESTART_THRESHOLD(reg));
	hfi2_write_csr(ppd->dd, CYR_EAL_RX_PAUSE_CFG_SHR, reg);

	/* TC's map to VL's 1:1 */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		enabled = (1 << i) & pfc_en;
		set_vl_percent_rbuf_space(ndev, i, per_vl_low_to_full_percent,
					  enabled);
	}
}

/**
 * cne_dcb_set_classic_rbuf - Restore the classic (reset) rbuf layout
 * @ndev: network device
 *
 * Classic mode receives everything into VL0, so VL0 and the shared pool get
 * the whole rbuf with their reset thresholds and VL1..VL7 get nothing.
 */
static void cne_dcb_set_classic_rbuf(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u32 csr = CYR_EAL_RX_PAUSE_CONFIG_VL0;
	u32 creds, low_water, restart;
	u64 reg;
	u8 vl;

	for (vl = 0; vl < IEEE_8021QAZ_MAX_TCS; vl++, csr += 8) {
		if (vl == 0) {
			creds = CYR_RBUF_CREDS;
			low_water = CYR_RBUF_RESET_LOW_WATER;
			restart = CYR_RBUF_RESET_RESTART;
		} else {
			creds = 0;
			low_water = 0;
			restart = 0;
		}

		reg = hfi2_read_csr(dd, csr);
		EAL_RX_PAUSE_CFG_VL0_SET_CREDITS(reg, creds);
		EAL_RX_PAUSE_CFG_VL0_SET_LOW_WATER(reg, low_water);
		EAL_RX_PAUSE_CFG_VL0_SET_RESTART(reg, restart);
		hfi2_write_csr(dd, csr, reg);
	}

	reg = hfi2_read_csr(dd, CYR_EAL_RX_PAUSE_CFG_SHR);
	EAL_RX_PAUSE_CFG_SHR_SET_RBUF_CREDITS(reg, CYR_RBUF_CREDS);
	EAL_RX_PAUSE_CFG_SHR_SET_LOW_WATER_THRESHOLD(reg, CYR_RBUF_RESET_LOW_WATER);
	EAL_RX_PAUSE_CFG_SHR_SET_RESTART_THRESHOLD(reg, CYR_RBUF_RESET_RESTART);
	hfi2_write_csr(dd, CYR_EAL_RX_PAUSE_CFG_SHR, reg);
}

/**
 * cne_dcb_update_roce_prio - Publish the RoCEv2 priority for the RoCE TX path
 * @edev: ether_device to query
 *
 * The priority is the APP table entry for UDP port 4791 while PFC is enabled
 * on the PF, otherwise 0. Callers hold RTNL or own the unregistered netdev.
 */
static void cne_dcb_update_roce_prio(struct ether_device *edev)
{
	struct dcb_app app = {
		.selector = IEEE_8021QAZ_APP_SEL_DGRAM,
		.protocol = ROCE_V2_UDP_DPORT,
	};
	u8 prio = 0;
	u8 mask;

	if (!edev->ppd->dd->is_vf && READ_ONCE(edev->pfc_enabled)) {
		mask = dcb_ieee_getapp_mask(edev->ndev, &app);
		if (mask)
			prio = fls(mask) - 1;
	}
	WRITE_ONCE(edev->ppd->roce_pfc_prio, prio);
	WRITE_ONCE(edev->ppd->roce_pfc_on, READ_ONCE(edev->pfc_enabled));
}

/**
 * cne_dcb_set_classic - Switch the port to classic 802.3x flow control
 * @edev: ether_device to configure
 * @tx_pause: allow VL0 to generate PAUSE frames
 *
 * Leaves PFC mode before VL1..VL7 lose their rbuf credits.
 */
void cne_dcb_set_classic(struct ether_device *edev, bool tx_pause)
{
	edev->pfc_en = 0;
	cne_eal_set_pause_config(edev, false);
	cne_dcb_update_roce_prio(edev);
	cne_dcb_set_classic_rbuf(edev->ndev);
	cne_set_pause_enabled(edev->ndev, tx_pause ? BIT(0) : 0);
}

/**
 * cne_dcb_ieee_setpfc - Set PFC configuration
 * @ndev: network device
 * @pfc: PFC configuration to set
 *
 * This is the .ieee_setpfc dcbnl_rtnl_ops implementation. A non-zero
 * pfc->pfc_en switches the port to PFC mode with per-VL thresholds for the
 * given priorities. A zero pfc->pfc_en switches the port back to classic
 * 802.3x flow control and restores the classic rbuf layout.
 *
 * The EAL pause registers and SEND_CTRL are shared by every function on the
 * port, so only the PF may change them.
 *
 * Return: 0 on success, -EOPNOTSUPP on a VF, other negative errno on failure.
 */
static int cne_dcb_ieee_setpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;

	if (ppd->dd->is_vf)
		return -EOPNOTSUPP;

	/*
	 * PCP maps 1:1 onto a VL, so all eight VLs must be clear in the
	 * SEND_CTRL UnsupportedVL mask or their packets are dropped.
	 */
	if (pfc->pfc_en) {
		u64 need_sup = GENMASK_ULL(IEEE_8021QAZ_MAX_TCS - 1, 0);
		u64 reg, cur_unsup, new_unsup;
		u8 supported = IEEE_8021QAZ_MAX_TCS;
		unsigned long flags;

		/* hfi2_pio_send_control() also read-modify-writes SEND_CTRL. */
		spin_lock_irqsave(&ppd->dd->sendctrl_lock, flags);
		reg = read_eport_csr(ppd->dd, ppd->hw_pidx,
				     ppd->dd->params->send_ctrl_reg);
		cur_unsup = (reg & SEND_CTRL_UNSUPPORTED_VL_SMASK) >>
			    SEND_CTRL_UNSUPPORTED_VL_SHIFT;

		if (cur_unsup & need_sup) {
			new_unsup = cur_unsup & ~need_sup;
			netdev_dbg(ndev,
				   "Enabling VLs for PFC: UnsupportedVL 0x%02llx -> 0x%02llx\n",
				   cur_unsup, new_unsup);

			reg &= ~SEND_CTRL_UNSUPPORTED_VL_SMASK;
			reg |= (new_unsup & SEND_CTRL_UNSUPPORTED_VL_MASK) <<
			       SEND_CTRL_UNSUPPORTED_VL_SHIFT;
			write_eport_csr(ppd->dd, ppd->hw_pidx,
					ppd->dd->params->send_ctrl_reg, reg);

			reg = read_eport_csr(ppd->dd, ppd->hw_pidx,
					     ppd->dd->params->send_ctrl_reg);
			new_unsup = (reg & SEND_CTRL_UNSUPPORTED_VL_SMASK) >>
				    SEND_CTRL_UNSUPPORTED_VL_SHIFT;
			supported = hweight_long(SEND_CTRL_UNSUPPORTED_VL_MASK) -
				    hweight_long(new_unsup);
			/* Port-wide count: only update it once every VL is up. */
			if (supported == IEEE_8021QAZ_MAX_TCS)
				ppd->vls_operational = supported;
		}
		spin_unlock_irqrestore(&ppd->dd->sendctrl_lock, flags);

		if (supported < IEEE_8021QAZ_MAX_TCS) {
			netdev_err(ndev,
				   "%s: Can't enable PFC, limited to %u VLs\n",
				   __func__, supported);
			return -EINVAL;
		}
	}

	if (pfc->pfc_en) {
		edev->pfc_en = pfc->pfc_en;

		/* set per VL PAUSE thresholds before entering PFC mode */
		assign_pfc_pause_config(ndev, pfc->pfc_en);

		/* Only the PFC-enabled priorities may send PFC frames. */
		cne_set_pause_enabled(ndev, pfc->pfc_en);

		/* Be mutually exclusive with LFC, set edev->pfc_enabled */
		cne_eal_set_pause_config(edev, true);
	} else {
		/* Reset default: classic pause from VL0. */
		cne_dcb_set_classic(edev, true);
	}
	cne_dcb_update_roce_prio(edev);

	return 0;
}

/**
 * cne_dcb_ieee_setapp - Add an APP table entry
 * @ndev: network device
 * @app: entry to add
 *
 * This is the .ieee_setapp dcbnl_rtnl_ops implementation.  The APP
 * priority is published to RoCE by the PF only, so a VF may not set one.
 *
 * Return: 0 on success, -EOPNOTSUPP on a VF, other negative errno on failure.
 */
static int cne_dcb_ieee_setapp(struct net_device *ndev, struct dcb_app *app)
{
	struct ether_device *edev = netdev_priv(ndev);
	int rc;

	if (edev->ppd->dd->is_vf)
		return -EOPNOTSUPP;
	if (app->priority >= IEEE_8021QAZ_MAX_TCS)
		return -EINVAL;

	rc = dcb_ieee_setapp(ndev, app);
	if (!rc)
		cne_dcb_update_roce_prio(netdev_priv(ndev));

	return rc;
}

/**
 * cne_dcb_ieee_delapp - Delete an APP table entry
 * @ndev: network device
 * @app: entry to delete
 *
 * This is the .ieee_delapp dcbnl_rtnl_ops implementation.
 *
 * Return: 0 on success, -EOPNOTSUPP on a VF, other negative errno on failure.
 */
static int cne_dcb_ieee_delapp(struct net_device *ndev, struct dcb_app *app)
{
	struct ether_device *edev = netdev_priv(ndev);
	int rc;

	if (edev->ppd->dd->is_vf)
		return -EOPNOTSUPP;
	rc = dcb_ieee_delapp(ndev, app);
	if (!rc)
		cne_dcb_update_roce_prio(netdev_priv(ndev));

	return rc;
}

#define CYR_DCBX_CAP (DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_IEEE)
/**
 * cne_dcb_getdcbx - Get DCBX configuration
 * @ndev: network device
 *
 * This is the .getdcbx dcbnl_rtnl_ops implementation.
 *
 * Return: DCBX capabilities.
 */
static u8 cne_dcb_getdcbx(struct net_device __always_unused *ndev)
{
	return CYR_DCBX_CAP;
}

/**
 * cne_dcb_setdcbx - Set DCBX configuration
 * @ndev: network device
 * @mode: DCBX mode to set
 *
 * This is the .setdcbx dcbnl_rtnl_ops implementation.
 *
 * Return: 0 on success, 1 on failure.
 */
static u8 cne_dcb_setdcbx(struct net_device *ndev, u8 mode)
{
	struct ether_device *edev = netdev_priv(ndev);

	if (edev->ppd->dd->is_vf)
		return 1;

	return mode != CYR_DCBX_CAP;
}

static const struct dcbnl_rtnl_ops cn_dcbnl_ops = {
	/* IEEE 802.1Qaz std */
	.ieee_getpfc = cne_dcb_ieee_getpfc,
	.ieee_setpfc = cne_dcb_ieee_setpfc,
	.ieee_setapp = cne_dcb_ieee_setapp,
	.ieee_delapp = cne_dcb_ieee_delapp,

	/* CEE std not implemented */
	/* DCBX config */
	.getdcbx	= cne_dcb_getdcbx,
	.setdcbx	= cne_dcb_setdcbx,
};

/**
 * cne_dcb_init - Initialize DCB
 * @ndev: network device
 */
void cne_dcb_init(struct net_device *ndev)
{
	ndev->dcbnl_ops = &cn_dcbnl_ops;
	/* init pfc_enabled */
	cne_eal_get_rx_pause_config(ndev);
	cne_dcb_update_roce_prio(netdev_priv(ndev));
}

/**
 * cne_dcb_set_defaults - Restore reset PFC/pause state on probe
 * @ndev: network device
 *
 * The EAL pause CSRs survive a module reload and a warm reboot.
 */
void cne_dcb_set_defaults(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	edev->rx_pause = true;
	hfi2_write_csr(edev->ppd->dd, CYR_EAL_RX_PAUSE_CONFIG, 0);
	cne_dcb_set_classic(edev, true);
	cne_eal_get_rx_pause_config(ndev);
}

/**
 * cne_dcb_restore - restore the PFC/pause state after a port reset
 * @edev: ether_device to configure
 *
 * A link bounce resets the EAL pause mode, the per-VL and shared rbuf
 * thresholds and the pause enables.  Write them back in the order that
 * cne_dcb_ieee_setpfc() and cne_dcb_set_classic() use.  A query made
 * while the port was reset may have read pfc_enabled as off, so publish
 * the RoCE priority again.
 *
 * Context: Caller holds RTNL.  Sleeps: takes edev->rmon_accum.lock.
 */
void cne_dcb_restore(struct ether_device *edev)
{
	struct net_device *ndev = edev->ndev;

	if (edev->pfc_en) {
		assign_pfc_pause_config(ndev, edev->pfc_en);
		cne_set_pause_enabled(ndev, edev->pause_enable_mask);
		cne_eal_set_pause_config(edev, true);
	} else {
		cne_eal_set_pause_config(edev, false);
		cne_dcb_set_classic_rbuf(ndev);
		cne_set_pause_enabled(ndev, edev->pause_enable_mask);
	}
	cne_dcb_update_roce_prio(edev);
}
