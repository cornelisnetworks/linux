// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * ethtool implementation
 */


#include "eth_main.h"
#include "cport.h"

struct cne_stat {
	char name[ETH_GSTRING_LEN];
	u64 (*get)(struct net_device *ndev);
};

struct cne_stat_vl {
	char name[ETH_GSTRING_LEN];
	u64 (*get)(struct net_device *ndev, u8 vl_idx);
};

static u64 eal_get_rx_pfc_frames(struct net_device *ndev);
static u64 eal_get_tx_pfc_frames(struct net_device *ndev);
static u64 eal_get_rx_mac_pause_frames(struct net_device *ndev);
static u64 eal_get_tx_mac_pause_frames(struct net_device *ndev);
static u64 eal_get_rx_mac_pause_xon(struct net_device *ndev);
static u64 eal_get_rx_mac_pause_xoff(struct net_device *ndev);
static u64 eal_get_tx_mac_pause_xon(struct net_device *ndev);
static u64 eal_get_tx_mac_pause_xoff(struct net_device *ndev);
static u64 eal_get_mac_pfc_paused(struct net_device *ndev);
static u64 eal_get_rbuf_pause_cntr_shr(struct net_device *ndev);

static u64 eal_get_rbuf_pause_time_shr(struct net_device *ndev);
static u64 eal_get_rbuf_pause_resend_shr(struct net_device *ndev);
static u64 eal_get_rx_minipause_cntr(struct net_device *ndev);

static u64 eal_rbuf_cred_avail_vl(struct net_device *ndev, u8 vl_idx);
static u64 eal_rbuf_pause_time_vl(struct net_device *ndev, u8 vl_idx);
static u64 eal_rbuf_pause_resend_vl(struct net_device *ndev, u8 vl_idx);
static u64 cne_get_tx_vl_packets(struct net_device *ndev, u8 vl_idx);
static u64 cne_get_tx_vl_flits(struct net_device *ndev, u8 vl_idx);
static u64 cne_get_rx_prio_packets(struct net_device *ndev, u8 prio);
static u64 cne_get_rx_prio_bytes(struct net_device *ndev, u8 prio);

static u64 eal_get_pause_pkt_rx_count(struct net_device *ndev);
static u64 eal_get_pause_pkt_tx_count(struct net_device *ndev);
static u64 eal_get_rx_pkt_count(struct net_device *ndev);
static u64 eal_get_rx_pkt_byte_count(struct net_device *ndev);
static u64 eal_get_tx_pkt_count(struct net_device *ndev);
static u64 eal_get_tx_pkt_byte_count(struct net_device *ndev);
static u64 eal_get_rx_pkt_drop_count(struct net_device *ndev);
static u64 eal_get_tx_pkt_drop_count(struct net_device *ndev);
static u64 eal_get_port_rx_missed_errors(struct net_device *ndev);

static u64 eal_get_rx_crc_errors(struct net_device *ndev);

static u64 eal_get_rocev2_pkts_rcvd(struct net_device *ndev);
static u64 eal_get_rocev2_ooo_pkts_rcvd(struct net_device *ndev);
static u64 eal_get_rocev2_rift_entry_mismatch(struct net_device *ndev);
static void eal_rmon_fold_locked(struct hfi2_devdata *dd, struct cn_rmon_accum *acc);
static void eal_rmon_discard_locked(struct hfi2_devdata *dd, struct cn_rmon_accum *acc);
static bool eal_mac_rx_ctl1_read_locked(struct ether_device *edev);

static u64 cne_get_rxq_packets(struct net_device *ndev, u8 q_idx);
static u64 cne_get_rxq_bytes(struct net_device *ndev, u8 q_idx);
static u64 cne_get_rxq_errors(struct net_device *ndev, u8 q_idx);
static u64 cne_get_rxq_drops(struct net_device *ndev, u8 q_idx);
static u64 cne_get_txq_packets(struct net_device *ndev, u8 q_idx);
static u64 cne_get_txq_bytes(struct net_device *ndev, u8 q_idx);
static u64 cne_get_txq_errors(struct net_device *ndev, u8 q_idx);
static u64 cne_get_txq_drops(struct net_device *ndev, u8 q_idx);

static struct cne_stat cne_stats[] = {
	{"eal_rx_pause_config_is_pfc", cne_eal_get_rx_pause_config},
	{"eal_mac_pfc_paused_bitmap", eal_get_mac_pfc_paused},
	{"eal_vf_prf_rbuf_pause_cntr_shr", eal_get_rbuf_pause_cntr_shr},
	{"eal_vf_prf_rbuf_pause_time_shr", eal_get_rbuf_pause_time_shr},
	{"eal_vf_prf_rbuf_pause_resend_shr", eal_get_rbuf_pause_resend_shr},
	{"eal_vf_prf_rx_minipause_cntr", eal_get_rx_minipause_cntr},
	{"eal_pause_pkt_rx_count", eal_get_pause_pkt_rx_count},
	{"eal_pause_pkt_tx_count", eal_get_pause_pkt_tx_count},
	{"rx_pfc_frames", eal_get_rx_pfc_frames},
	{"tx_pfc_frames", eal_get_tx_pfc_frames},
	{"rx_mac_pause_frames", eal_get_rx_mac_pause_frames},
	{"tx_mac_pause_frames", eal_get_tx_mac_pause_frames},
	{"rx_mac_pause_xon", eal_get_rx_mac_pause_xon},
	{"rx_mac_pause_xoff", eal_get_rx_mac_pause_xoff},
	{"tx_mac_pause_xon", eal_get_tx_mac_pause_xon},
	{"tx_mac_pause_xoff", eal_get_tx_mac_pause_xoff},
	{"rx_packets", eal_get_rx_pkt_count},
	{"rx_bytes", eal_get_rx_pkt_byte_count},
	{"tx_packets", eal_get_tx_pkt_count},
	{"tx_bytes", eal_get_tx_pkt_byte_count},
	{"rx_dropped", eal_get_rx_pkt_drop_count},
	{"tx_dropped", eal_get_tx_pkt_drop_count},
	{"port_rx_missed_errors", eal_get_port_rx_missed_errors},
	{"rx_crc_errors", eal_get_rx_crc_errors},
	{"port_rocev2_pkts_rcvd", eal_get_rocev2_pkts_rcvd},
	{"port_rocev2_ooo_pkts_rcvd", eal_get_rocev2_ooo_pkts_rcvd},
	{"port_rocev2_rift_entry_mismatch", eal_get_rocev2_rift_entry_mismatch},
};

static struct cne_stat_vl cne_stats_per_vl[] = {
	{"eal_rbuf_cred_avail_vl%u", eal_rbuf_cred_avail_vl},
	{"eal_rbuf_pause_cntr_vl%u", cne_eal_rbuf_pause_cntr_vl},
	{"eal_rbuf_pause_time_vl%u", eal_rbuf_pause_time_vl},
	{"eal_rbuf_pause_resend_vl%u", eal_rbuf_pause_resend_vl},
	{"tx_vl%u_packets", cne_get_tx_vl_packets},
	{"tx_vl%u_flits", cne_get_tx_vl_flits},
	{"rx_prio%u_packets", cne_get_rx_prio_packets},
	{"rx_prio%u_bytes", cne_get_rx_prio_bytes},
};

static struct cne_stat_vl cne_stats_per_rxq[] = {
	{"rx_queue_%u_packets", cne_get_rxq_packets},
	{"rx_queue_%u_bytes", cne_get_rxq_bytes},
	{"rx_queue_%u_errors", cne_get_rxq_errors},
	{"rx_queue_%u_drops", cne_get_rxq_drops},
};

static struct cne_stat_vl cne_stats_per_txq[] = {
	{"tx_queue_%u_packets", cne_get_txq_packets},
	{"tx_queue_%u_bytes", cne_get_txq_bytes},
	{"tx_queue_%u_errors", cne_get_txq_errors},
	{"tx_queue_%u_drops", cne_get_txq_drops},
};


/**
 * cne_get_drvinfo - get basic driver information
 * @ndev: network device
 * @info: driver information
 */
static void cne_get_drvinfo(struct net_device *ndev,
			struct ethtool_drvinfo *info)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;

	strscpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strscpy(info->bus_info, pci_name(edev->pdev), sizeof(info->bus_info));
	if (dd->cport_ver)
		hfi2_cport_get_dev_fw_str(dd, info->fw_version,
				     sizeof(info->fw_version));
}

/**
 * cne_dev_unreachable - check whether the device can still be accessed
 * @dd: device data
 *
 * A CYR that has dropped off the bus (e.g. after freezing on an Ethernet
 * link down event) returns all-ones for every MMIO read and never answers
 * CPORT requests.  Detect that so callers fail fast instead of waiting out
 * a CPORT timeout on every query.
 *
 * Returns true if the device cannot be accessed.
 */
static bool cne_dev_unreachable(struct hfi2_devdata *dd)
{
	if (!(dd->flags & HFI2_PRESENT) || (dd->flags & HFI2_FROZEN))
		return true;
	if (pci_channel_offline(dd->pcidev))
		return true;
	return hfi2_read_csr(dd, CCE_REVISION) == ~0ULL;
}

/**
 * cne_query_link_status - read the Ethernet link status CSR from CPORT
 * @ndev: network device
 * @status: returned raw link status value (decode with LINK_* macros)
 *
 * Must only be called on a PF (dd->cport != NULL) and from a context that may
 * sleep.
 *
 * Returns zero on success, -ENODEV if the device is unreachable, -ERRNO
 * otherwise.
 */
int cne_query_link_status(struct net_device *ndev, u64 *status)
{
	int rc;
	int len;
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cport_csr csr = { .addr = CPORT_LINK_STATUS_ADDR };
	struct cport_csr *link = NULL;

	if (!dd->cport)
		return -ENODEV;

	if (cne_dev_unreachable(dd)) {
		netdev_err_once(ndev, "Device unreachable, cannot get link info\n");
		return -ENODEV;
	}

	rc = hfi2_cport_send_req(dd, CH_OP_CSR, 0, &csr, sizeof(csr), (void **)&link, &len, HZ);
	if (rc) {
		if (net_ratelimit())
			netdev_err(ndev, "Failure getting link info (%d)\n", rc);
		if (rc > 0)
			rc = -EIO;
		if (cne_dev_unreachable(dd))
			rc = -ENODEV;
	} else if (len != (int)sizeof(*link)) {
		if (net_ratelimit())
			netdev_err(ndev, "Failure getting link info (%d!=%zu)\n", len,
				   sizeof(*link));
		rc = -EIO;
	} else {
		*status = link->value;
	}

	kfree(link);

	return rc;
}

/**
 * cne_get_link_ksettings - get link configuration
 * @ndev: network device
 * @ksettings: link configuration settings
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_get_link_ksettings(struct net_device *ndev,
				struct ethtool_link_ksettings *ksettings)
{
	int rc;
	u64 link_status = 0;
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;

	/* Initialize supported, advertising, and lp_advertising link modes */
	ethtool_link_ksettings_zero_link_mode(ksettings, supported);
	ethtool_link_ksettings_zero_link_mode(ksettings, advertising);
	ethtool_link_ksettings_zero_link_mode(ksettings, lp_advertising);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, Autoneg);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, FIBRE);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, Pause);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, FEC_RS);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, 200000baseCR4_Full);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, 200000baseSR4_Full);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, 400000baseCR4_Full);
	ethtool_link_ksettings_add_link_mode(ksettings, supported, 400000baseSR4_Full);
	linkmode_copy(ksettings->link_modes.advertising, ksettings->link_modes.supported);

	/* Default base settings */
	ksettings->base.mdio_support = 0;
	ksettings->base.phy_address = 0;

	/* CPORT unavailable for VFs.  Initialize settings to unknown. */
	if (!dd->cport) {
		ksettings->base.speed = SPEED_UNKNOWN;
		ksettings->base.duplex = DUPLEX_UNKNOWN;
		ksettings->base.port = PORT_OTHER;
		ksettings->base.autoneg = AUTONEG_DISABLE;
		ksettings->lanes = 0;
		return 0;
	}

	rc = cne_query_link_status(ndev, &link_status);
	if (!rc) {
		/* Set all base link modes with consideration for link state */
		ksettings->base.autoneg = AUTONEG_ENABLE;

		if (LINK_UP(link_status)) {
			ksettings->base.duplex = DUPLEX_FULL;

			switch (LINK_SPEED(link_status)) {
			case LINK_SPEED_10:
				ksettings->base.speed = SPEED_10000;
				break;
			case LINK_SPEED_25:
				ksettings->base.speed = SPEED_25000;
				break;
			case LINK_SPEED_40:
				ksettings->base.speed = SPEED_40000;
				break;
			case LINK_SPEED_50:
				ksettings->base.speed = SPEED_50000;
				break;
			case LINK_SPEED_100:
				ksettings->base.speed = SPEED_100000;
				break;
			case LINK_SPEED_200:
				ksettings->base.speed = SPEED_200000;
				break;
			case LINK_SPEED_400:
				ksettings->base.speed = SPEED_400000;
				break;
			case LINK_SPEED_800:
				ksettings->base.speed = SPEED_800000;
				break;
			default:
				ksettings->base.speed = SPEED_UNKNOWN;
			}

			ksettings->lanes = LINK_LANE_WIDTH(link_status);

			switch (LINK_CABLE_TYPE(link_status)) {
			case LINK_CABLE_TYPE_CR:
				ksettings->base.port = PORT_DA;
				break;
			case LINK_CABLE_TYPE_SR:
				ksettings->base.port = PORT_FIBRE;
				break;
			default:
				ksettings->base.port = PORT_OTHER;
			}
		} else {
			ksettings->base.speed = SPEED_UNKNOWN;
			ksettings->lanes = 0;
			ksettings->base.port = PORT_NONE;
			ksettings->base.duplex = DUPLEX_UNKNOWN;
		}
	}

	return rc;
}

/**
 * cne_set_phys_id - control the port LED for physical identification
 * @ndev: network device
 * @state: requested LED identification state
 *
 * This is the .set_phys_id ethtool_ops implementation, invoked by
 * `ethtool -p`/`--identify`. CPORT firmware owns LED blink timing (see
 * cport_write_led() / gen_start_led_override() in chip_gen.c), so only
 * ACTIVE and INACTIVE are meaningful here; ON/OFF are handled entirely
 * by the ACTIVE case's chip callback and are not separately driven.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_set_phys_id(struct net_device *ndev,
			   enum ethtool_phys_id_state state)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	struct hfi2_devdata *dd = ppd->dd;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		dd->params->start_led_override(ppd, 2000, 1500);
		return 0;
	case ETHTOOL_ID_INACTIVE:
		dd->params->shutdown_led_override(ppd);
		return 0;
	case ETHTOOL_ID_ON:
	case ETHTOOL_ID_OFF:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * cne_nway_reset - restart auto-negotiation
 * @ndev: network device
 *
 * This is the .nway_reset ethtool_ops implementation, invoked by
 * `ethtool -r`. CPORT firmware owns the auto-negotiation restart
 * sequence; ask it to restart via the link-control CSR.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_nway_reset(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cport_csr csr = {
		.options = CPORT_CSR_OP_WRITE,
		.addr = CPORT_LINK_CONTROL_ADDR,
		.value = CPORT_LINK_CTRL_RESTART_AN,
	};
	struct cport_csr *rsp = NULL;
	int len;
	int rc;

	/* No CPORT on VFs; older firmware does not advertise AN restart */
	if (!dd->cport || !(dd->cport->suppt.flags & CPORT_OPT_AN_RESTART))
		return -EOPNOTSUPP;

	rc = hfi2_cport_send_req(dd, CH_OP_CSR, 0, &csr, sizeof(csr), (void **)&rsp, &len, HZ);
	kfree(rsp);

	switch (rc) {
	case MSG_RSP_STATUS_OK:
		return 0;
	case MSG_RSP_STATUS_RETRY:
		rc = -EAGAIN;
		break;
	case MSG_RSP_STATUS_INVALID_STATE:
		rc = -ENETDOWN;
		break;
	case MSG_RSP_STATUS_DENIED:
	case MSG_RSP_STATUS_OPCODE_UNSUPPORTED:
		rc = -EOPNOTSUPP;
		break;
	default:
		rc = -EIO;
		break;
	}

	if (net_ratelimit())
		netdev_warn(ndev, "Failure restarting autoneg (%d)\n", rc);
	return rc;
}

/**
 * cne_get_pauseparam - Get pause parameters
 * @ndev: network device
 * @parms: storage for pause parameters
 *
 * This is the .get_pauseparam ethtool_ops implementation.
 * Note: Upper levels call get before set and will only call set
 * if get != set request.
 */
static void cne_get_pauseparam(struct net_device *ndev,
				struct ethtool_pauseparam *parms)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 pause_reg;
	struct hfi2_devdata *dd = edev->ppd->dd;

	parms->autoneg = false;

	/* if using PFC then consider all these disabled */
	if (cne_eal_get_rx_pause_config(ndev)) {
		parms->rx_pause = false;
		parms->tx_pause = false;

		return;
	}

	/* the last RX_MAIN_CTL1 read, or the setting if it was never read */
	mutex_lock(&acc->lock);
	if (cne_mac_readable(edev))
		eal_mac_rx_ctl1_read_locked(edev);
	parms->rx_pause = edev->mac_rx_ctl1_valid ?
			  !!OCORE_RX_MAIN_CTL1_GET_PAUSE_EN(edev->mac_rx_ctl1) :
			  edev->mac_pause_en;
	mutex_unlock(&acc->lock);

	if (cne_eal_read(dd, CYR_EAL_PF_FORCE_PAUSE_DISABLE, &pause_reg))
		parms->tx_pause = !(EAL_PF_FORCE_PAUSE_DISABLE_GET_MASK(pause_reg) &
				    BIT(0));
	else
		parms->tx_pause = edev->pause_enable_mask & BIT(0);
}

/**
 * cne_get_pause_stats - IEEE 802.3x PAUSE frame statistics
 * @ndev: network device
 * @pause_stats: pause statistics
 *
 * Report the OmegaCORE MAC PAUSE counters, which only count classic pause frames.
 * Only exposed on the PF, which owns the MAC MIB accumulator.
 */
static void cne_get_pause_stats(struct net_device *ndev,
				struct ethtool_pause_stats *pause_stats)
{
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	if (dd->is_vf) {
		netdev_info(ndev, "%s: VF-level pause stats not exposed by hardware\n", __func__);
		return;
	}

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	pause_stats->tx_pause_frames = acc->pause_frames_tx;
	pause_stats->rx_pause_frames = acc->pause_frames_rx;
	mutex_unlock(&acc->lock);
}

/*
 * Native OmegaCORE MAC MIB byte-size histogram uses 13 HW bins; ethtool's
 * struct ethtool_rmon_stats caps hist[]/hist_tx[] at ETHTOOL_RMON_HIST_MAX
 * (11). The 3 adjacent 1519-1522/1523-1548/1549-2047 HW bins are summed into
 * a single 1519-2047 ethtool bucket (index 6) to fit within 11 entries,
 * matching the traditional RFC-2819 style bucket boundary.
 */
static const struct ethtool_rmon_hist_range cn_rmon_ranges[] = {
	{    0,    64 },
	{   65,   127 },
	{  128,   255 },
	{  256,   511 },
	{  512,  1023 },
	{ 1024,  1518 },
	{ 1519,  2047 },
	{ 2048,  4095 },
	{ 4096,  8191 },
	{ 8192,  9600 },
	{ 9601, 65535 },
};

static const u32 oc_mac_hist_msb_off[OCORE_MAC_HIST_NUM_BINS] = {
	OCORE_MAC_HIST_64B_MSB_OFF,
	OCORE_MAC_HIST_65_127B_MSB_OFF,
	OCORE_MAC_HIST_128_255B_MSB_OFF,
	OCORE_MAC_HIST_256_511B_MSB_OFF,
	OCORE_MAC_HIST_512_1023B_MSB_OFF,
	OCORE_MAC_HIST_1024_1518B_MSB_OFF,
	OCORE_MAC_HIST_1519_1522B_MSB_OFF,
	OCORE_MAC_HIST_1523_1548B_MSB_OFF,
	OCORE_MAC_HIST_1549_2047B_MSB_OFF,
	OCORE_MAC_HIST_2048_4095B_MSB_OFF,
	OCORE_MAC_HIST_4096_8191B_MSB_OFF,
	OCORE_MAC_HIST_8192_9600B_MSB_OFF,
	OCORE_MAC_HIST_9601B_UP_MSB_OFF,
};

static const u8 oc_mac_hist_bucket[OCORE_MAC_HIST_NUM_BINS] = {
	0, 1, 2, 3, 4, 5, 6, 6, 6, 7, 8, 9, 10
};

/**
 * eal_mac_read48 - read a 48-bit OmegaCORE MAC MIB counter
 * @dd: device data
 * @base: CYR_OCORE_RX_MAIN_CTL1 or CYR_OCORE_TX_MAIN_CTL1
 * @msb_off: vendor offset of the MSB half (bits [15:0] valid)
 * @lsb_off: vendor offset of the LSB half (bits [31:0] valid)
 *
 * Returns: (MSB[15:0] << 32) | LSB[31:0].
 */
static u64 eal_mac_read48(struct hfi2_devdata *dd, u32 base, u32 msb_off, u32 lsb_off)
{
	u64 msb = hfi2_read_csr(dd, base + OCORE_MAC_OFF(msb_off));
	u64 lsb = hfi2_read_csr(dd, base + OCORE_MAC_OFF(lsb_off));

	return ((msb & 0xFFFF) << 32) | (lsb & 0xFFFFFFFF);
}

/*
 * eal_fec_read40 - read a 40-bit RS-FEC counter (MSB[7:0]<<32 | LSB[31:0]).
 * LSB is read before MSB: under FEC_PM_TICK_EN the pair is a frozen
 * snapshot for the whole window. This order also matches the ROCP
 * read-to-clear semantics used when PM latching is disabled.
 */
static u64 eal_fec_read40(struct hfi2_devdata *dd, u32 base, u32 msb_off, u32 lsb_off)
{
	u64 lsb = hfi2_read_csr(dd, base + OCORE_MAC_OFF(lsb_off));
	u64 msb = hfi2_read_csr(dd, base + OCORE_MAC_OFF(msb_off));

	return ((msb & 0xFF) << 32) | (lsb & 0xFFFFFFFF);
}

/*
 * Read RX_MAIN_CTL1 into edev->mac_rx_ctl1.  Called with
 * edev->rmon_accum.lock held and only while cne_mac_readable().  A read
 * that EAL reset gated is not cached.
 */
static bool eal_mac_rx_ctl1_read_locked(struct ether_device *edev)
{
	u64 ctl1;

	lockdep_assert_held(&edev->rmon_accum.lock);

	if (!cne_eal_read(edev->ppd->dd, CYR_OCORE_RX_MAIN_CTL1, &ctl1))
		return false;
	edev->mac_rx_ctl1 = ctl1;
	edev->mac_rx_ctl1_valid = true;
	return true;
}

/*
 * Make RX_MAIN_CTL1.PAUSE_EN edev->mac_pause_en without touching the other
 * fields (STATS_EN, PM_TICK_EN, ...).  While the MAC is readable this is a
 * read-modify-write that writes only on a change.  Otherwise the bit is
 * written into the last value read; the write is posted, so it cannot time
 * out.  If RX_MAIN_CTL1 has never been read nothing is written: the first
 * fold with the MAC readable, which cne_mac_link_set() schedules, writes
 * the bit then.  Called with edev->rmon_accum.lock held.
 */
static void eal_mac_pause_sync_locked(struct ether_device *edev)
{
	bool fresh;
	u64 ctl1;

	lockdep_assert_held(&edev->rmon_accum.lock);

	fresh = cne_mac_readable(edev) && eal_mac_rx_ctl1_read_locked(edev);
	if (!edev->mac_rx_ctl1_valid)
		return;
	ctl1 = edev->mac_rx_ctl1;
	OCORE_RX_MAIN_CTL1_SET_PAUSE_EN(ctl1, edev->mac_pause_en ? 1 : 0);
	if (fresh && ctl1 == edev->mac_rx_ctl1)
		return;
	hfi2_write_csr(edev->ppd->dd, CYR_OCORE_RX_MAIN_CTL1, ctl1);
	edev->mac_rx_ctl1 = ctl1;
}

/**
 * eal_mac_stats_enable - run the OmegaCORE MAC/RS-FEC statistics in
 * software-latch mode
 * @edev: Ethernet device
 *
 * MAIN_CTL1.STATS_EN resets to 0; if left unset "All Statistic Registers
 * will return 0" per the vendor regmap. TX_MAC.STATS_EN is at a different
 * bit position (16) than RX_MAC.STATS_EN (17).
 *
 * PM_TICK_EN is cleared to enable software control of the MAC ROP and RS-FEC
 * ROCP registers. The MAC ROP registers then only update when software
 * latches them, and the RS-FEC ROCP counters become read-to-clear.
 *
 * Return: false if the EAL reset gate skipped a read; call it again later.
 */
static bool eal_mac_stats_enable(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	bool ok, all = true;
	u64 ctl1;

	/* never write back a value that EAL reset gated */
	ok = cne_eal_read(dd, CYR_OCORE_RX_MAIN_CTL1, &ctl1);
	all &= ok;
	if (ok &&
	    (!OCORE_RX_MAIN_CTL1_GET_STATS_EN(ctl1) ||
	     OCORE_RX_MAIN_CTL1_GET_PM_TICK_EN(ctl1))) {
		OCORE_RX_MAIN_CTL1_SET_STATS_EN(ctl1, 1);
		OCORE_RX_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_RX_MAIN_CTL1, ctl1);
		edev->mac_rx_ctl1 = ctl1;
		edev->mac_rx_ctl1_valid = true;
		ctl1 = hfi2_read_csr(dd, CYR_OCORE_RX_MAIN_CTL1);
		pr_info("%s: RX_MAIN_CTL1=0x%llx stats_en=%d pm_tick_en=%d\n",
			__func__, ctl1,
			(int)OCORE_RX_MAIN_CTL1_GET_STATS_EN(ctl1),
			(int)OCORE_RX_MAIN_CTL1_GET_PM_TICK_EN(ctl1));
	}

	ok = cne_eal_read(dd, CYR_OCORE_TX_MAIN_CTL1, &ctl1);
	all &= ok;
	if (ok &&
	    (!OCORE_TX_MAIN_CTL1_GET_STATS_EN(ctl1) ||
	     OCORE_TX_MAIN_CTL1_GET_PM_TICK_EN(ctl1))) {
		ctl1 = OCORE_TX_MAIN_CTL1_SET_STATS_EN(ctl1, 1);
		ctl1 = OCORE_TX_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_TX_MAIN_CTL1, ctl1);
		ctl1 = hfi2_read_csr(dd, CYR_OCORE_TX_MAIN_CTL1);
		pr_info("%s: TX_MAIN_CTL1=0x%llx stats_en=%d pm_tick_en=%d\n",
			__func__, ctl1,
			(int)OCORE_TX_MAIN_CTL1_GET_STATS_EN(ctl1),
			(int)OCORE_TX_MAIN_CTL1_GET_PM_TICK_EN(ctl1));
	}

	ok = cne_eal_read(dd, CYR_OCORE_RX_FEC, &ctl1);
	all &= ok;
	if (ok &&
	    (!OCORE_FEC_MAIN_CTL1_GET_STATS_EN(ctl1) ||
	     OCORE_FEC_MAIN_CTL1_GET_PM_TICK_EN(ctl1))) {
		ctl1 = OCORE_FEC_MAIN_CTL1_SET_STATS_EN(ctl1, 1);
		ctl1 = OCORE_FEC_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_RX_FEC, ctl1);
		ctl1 = hfi2_read_csr(dd, CYR_OCORE_RX_FEC);
		pr_info("%s: FEC_MAIN_CTL1=0x%llx stats_en=%d pm_tick_en=%d\n",
			__func__, ctl1,
			(int)OCORE_FEC_MAIN_CTL1_GET_STATS_EN(ctl1),
			(int)OCORE_FEC_MAIN_CTL1_GET_PM_TICK_EN(ctl1));
	}
	return all;
}

/**
 * eal_mac_stats_disable - return the statistics controls to their reset state
 * @edev: Ethernet device
 *
 * Restore the reset values of STATS_EN and PM_TICK_EN on the MAC RX/TX and
 * RS_FEC blocks.  Called with edev->rmon_accum.lock held and only while
 * cne_mac_readable().
 */
static void eal_mac_stats_disable(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 ctl1;

	/* never write back a value that EAL reset gated */
	if (cne_eal_read(dd, CYR_OCORE_RX_MAIN_CTL1, &ctl1)) {
		OCORE_RX_MAIN_CTL1_SET_STATS_EN(ctl1, 0);
		OCORE_RX_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_RX_MAIN_CTL1, ctl1);
		edev->mac_rx_ctl1 = ctl1;
		edev->mac_rx_ctl1_valid = true;
	}

	if (cne_eal_read(dd, CYR_OCORE_TX_MAIN_CTL1, &ctl1)) {
		ctl1 = OCORE_TX_MAIN_CTL1_SET_STATS_EN(ctl1, 0);
		ctl1 = OCORE_TX_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_TX_MAIN_CTL1, ctl1);
	}

	if (cne_eal_read(dd, CYR_OCORE_RX_FEC, &ctl1)) {
		ctl1 = OCORE_FEC_MAIN_CTL1_SET_STATS_EN(ctl1, 0);
		ctl1 = OCORE_FEC_MAIN_CTL1_SET_PM_TICK_EN(ctl1, 0);
		hfi2_write_csr(dd, CYR_OCORE_RX_FEC, ctl1);
	}
}

/* A polling interval of 3600 s prevents the fastest growing counter (48-bit
 * GOOD_BYTE_CNT) from saturating at a 400 Gbps line rate (in ~5600 s) with
 * ~1.5x margin.
 */
#define CNE_RMON_POLL_DELAY	msecs_to_jiffies(3600000)

/**
 * eal_mac_hist_add - add a full 13-bin histogram snapshot into the
 * 11-bucket ethtool histogram total, called with edev->rmon_accum.lock held
 * @dd: device data
 * @base: CYR_OCORE_RX_MAIN_CTL1 or CYR_OCORE_TX_MAIN_CTL1
 * @total: running cumulative per-ethtool-bucket total, size ETHTOOL_RMON_HIST_MAX
 */
static void eal_mac_hist_add(struct hfi2_devdata *dd, u32 base, u64 *total)
{
	int i;

	for (i = 0; i < OCORE_MAC_HIST_NUM_BINS; i++) {
		u32 msb_off = oc_mac_hist_msb_off[i];

		total[oc_mac_hist_bucket[i]] += eal_mac_read48(dd, base, msb_off, msb_off + 4);
	}
}

/*
 * eal_mac_cnt_latch - latch and clear the MAC block counters at @base
 * (CYR_OCORE_RX_MAIN_CTL1 or CYR_OCORE_TX_MAIN_CTL1). A 0->1 write to
 * LOCAL_INT_CNT_CTL.CNT_CLEAR copies the internal counts into the ROP
 * registers and zeroes the internal counts, so the registers then hold
 * exactly the counts since the previous latch. Bit 0 is returned to 0 so
 * the next call produces another rising edge.
 */
static void eal_mac_cnt_latch(struct hfi2_devdata *dd, u32 base)
{
	u32 reg = base + OCORE_MAC_OFF(OCORE_MAC_LOCAL_INT_CNT_CTL_OFF);

	hfi2_write_csr(dd, reg, 0);
	hfi2_write_csr(dd, reg, OCORE_MAC_LOCAL_INT_CNT_CTL_CNT_CLEAR_MASK);
	hfi2_write_csr(dd, reg, 0);
}

/*
 * eal_rmon_fold_locked - latch the MAC counters, drain the read-to-clear
 * RS-FEC counters, and add everything to the running totals. Called with
 * edev->rmon_accum.lock held, so concurrent folds cannot double count.
 */
static void eal_rmon_fold_locked(struct hfi2_devdata *dd, struct cn_rmon_accum *acc)
{
	struct ether_device *edev = container_of(acc, struct ether_device, rmon_accum);
	u64 pause_rx, pause_tx, pfc_rx, pfc_tx;

	lockdep_assert_held(&acc->lock);

	/*
	 * Leave the MAC alone until it is readable.  The hardware keeps
	 * counting, and the next fold adds what accumulated meanwhile.
	 */
	if (!cne_mac_readable(edev))
		return;
	if (acc->start_pending) {
		/* the poll retries soon while start_pending stays set */
		if (!eal_mac_stats_enable(edev))
			return;
		eal_rmon_discard_locked(dd, acc);
		WRITE_ONCE(acc->start_pending, false);
	}
	/* PAUSE_EN may have been set while RX_MAIN_CTL1 was not readable */
	eal_mac_pause_sync_locked(edev);

	eal_mac_cnt_latch(dd, CYR_OCORE_RX_MAIN_CTL1);
	eal_mac_cnt_latch(dd, CYR_OCORE_TX_MAIN_CTL1);

	acc->undersize_pkts += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_UNDERSIZE_FRM_CNT_MSB_OFF,
			OCORE_MAC_UNDERSIZE_FRM_CNT_LSB_OFF);
	acc->oversize_pkts += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_OVERSIZE_FRM_CNT_MSB_OFF,
			OCORE_MAC_OVERSIZE_FRM_CNT_LSB_OFF);
	acc->fragments += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_RUNT_FRM_CNT_MSB_OFF,
			OCORE_MAC_RUNT_FRM_CNT_LSB_OFF);
	acc->jabbers += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_JABBER_FRM_CNT_MSB_OFF,
			OCORE_MAC_JABBER_FRM_CNT_LSB_OFF);
	eal_mac_hist_add(dd, CYR_OCORE_RX_MAIN_CTL1, acc->hist);

	acc->frames_rx_ok += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_GOOD_FRM_CNT_MSB_OFF,
			OCORE_MAC_GOOD_FRM_CNT_LSB_OFF);
	acc->octets_rx_ok += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_GOOD_BYTE_CNT_MSB_OFF,
			OCORE_MAC_GOOD_BYTE_CNT_LSB_OFF);
	acc->fcs_errors += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_CRC_ERR_FRM_CNT_MSB_OFF,
			OCORE_MAC_CRC_ERR_FRM_CNT_LSB_OFF);
	acc->alignment_errors += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_MISALIGNMENT_FRM_CNT_MSB_OFF,
			OCORE_MAC_MISALIGNMENT_FRM_CNT_LSB_OFF);
	acc->mcast_rx_ok += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_RX_MAC_MULTICAST_FRM_CNT_MSB_OFF,
			OCORE_RX_MAC_MULTICAST_FRM_CNT_LSB_OFF);
	acc->bcast_rx_ok += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_RX_MAC_BROADCAST_FRM_CNT_MSB_OFF,
			OCORE_RX_MAC_BROADCAST_FRM_CNT_LSB_OFF);

	acc->fec_corrected_blocks += eal_fec_read40(dd, CYR_OCORE_RX_FEC,
			OCORE_FEC_COR_CW_CNT_MSB_OFF, OCORE_FEC_COR_CW_CNT_LSB_OFF);
	acc->fec_uncorrectable_blocks += eal_fec_read40(dd, CYR_OCORE_RX_FEC,
			OCORE_FEC_UNCOR_CW_CNT_MSB_OFF, OCORE_FEC_UNCOR_CW_CNT_LSB_OFF);
	acc->fec_corrected_bits += eal_fec_read40(dd, CYR_OCORE_RX_FEC,
			OCORE_FEC_CORRECTED_ZEROS_MSB_OFF,
			OCORE_FEC_CORRECTED_ZEROS_LSB_OFF);
	acc->fec_corrected_bits += eal_fec_read40(dd, CYR_OCORE_RX_FEC,
			OCORE_FEC_CORRECTED_ONES_MSB_OFF,
			OCORE_FEC_CORRECTED_ONES_LSB_OFF);

	pause_rx = eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
				  OCORE_MAC_PAUSE_FRM_CNT_MSB_OFF,
				  OCORE_MAC_PAUSE_FRM_CNT_LSB_OFF);
	pfc_rx = eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
				OCORE_RX_MAC_PFC_FRM_CNT_MSB_OFF,
				OCORE_RX_MAC_PFC_FRM_CNT_LSB_OFF);
	acc->mac_ctrl_frames_rx += pause_rx + pfc_rx;
	acc->pause_frames_rx += pause_rx;
	acc->pfc_frames_rx += pfc_rx;
	/* The XON and XOFF counters are swapped */
	acc->pause_xon_rx += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_PAUSE_XOFF_FRM_CNT_MSB_OFF,
			OCORE_MAC_PAUSE_XOFF_FRM_CNT_LSB_OFF);
	acc->pause_xoff_rx += eal_mac_read48(dd, CYR_OCORE_RX_MAIN_CTL1,
			OCORE_MAC_PAUSE_XON_FRM_CNT_MSB_OFF,
			OCORE_MAC_PAUSE_XON_FRM_CNT_LSB_OFF);

	eal_mac_hist_add(dd, CYR_OCORE_TX_MAIN_CTL1, acc->hist_tx);

	acc->frames_tx_ok += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_MAC_GOOD_FRM_CNT_MSB_OFF,
			OCORE_MAC_GOOD_FRM_CNT_LSB_OFF);
	acc->octets_tx_ok += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_MAC_GOOD_BYTE_CNT_MSB_OFF,
			OCORE_MAC_GOOD_BYTE_CNT_LSB_OFF);
	acc->mcast_tx_ok += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_TX_MAC_MULTICAST_FRM_CNT_MSB_OFF,
			OCORE_TX_MAC_MULTICAST_FRM_CNT_LSB_OFF);
	acc->bcast_tx_ok += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_TX_MAC_BROADCAST_FRM_CNT_MSB_OFF,
			OCORE_TX_MAC_BROADCAST_FRM_CNT_LSB_OFF);

	pause_tx = eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
				  OCORE_MAC_PAUSE_FRM_CNT_MSB_OFF,
				  OCORE_MAC_PAUSE_FRM_CNT_LSB_OFF);
	pfc_tx = eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
				OCORE_TX_MAC_PFC_FRM_CNT_MSB_OFF,
				OCORE_TX_MAC_PFC_FRM_CNT_LSB_OFF);
	acc->mac_ctrl_frames_tx += pause_tx + pfc_tx;
	acc->pause_frames_tx += pause_tx;
	acc->pfc_frames_tx += pfc_tx;
	/* The XON and XOFF counters are swapped */
	acc->pause_xon_tx += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_MAC_PAUSE_XOFF_FRM_CNT_MSB_OFF,
			OCORE_MAC_PAUSE_XOFF_FRM_CNT_LSB_OFF);
	acc->pause_xoff_tx += eal_mac_read48(dd, CYR_OCORE_TX_MAIN_CTL1,
			OCORE_MAC_PAUSE_XON_FRM_CNT_MSB_OFF,
			OCORE_MAC_PAUSE_XON_FRM_CNT_LSB_OFF);
}

/*
 * eal_rmon_discard_locked - throw away the counts accumulated so far
 * without adding them to the totals. Called with edev->rmon_accum.lock held.
 */
static void eal_rmon_discard_locked(struct hfi2_devdata *dd, struct cn_rmon_accum *acc)
{
	lockdep_assert_held(&acc->lock);

	eal_mac_cnt_latch(dd, CYR_OCORE_RX_MAIN_CTL1);
	eal_mac_cnt_latch(dd, CYR_OCORE_TX_MAIN_CTL1);
	eal_fec_read40(dd, CYR_OCORE_RX_FEC, OCORE_FEC_COR_CW_CNT_MSB_OFF,
		       OCORE_FEC_COR_CW_CNT_LSB_OFF);
	eal_fec_read40(dd, CYR_OCORE_RX_FEC, OCORE_FEC_UNCOR_CW_CNT_MSB_OFF,
		       OCORE_FEC_UNCOR_CW_CNT_LSB_OFF);
	eal_fec_read40(dd, CYR_OCORE_RX_FEC, OCORE_FEC_CORRECTED_ZEROS_MSB_OFF,
		       OCORE_FEC_CORRECTED_ZEROS_LSB_OFF);
	eal_fec_read40(dd, CYR_OCORE_RX_FEC, OCORE_FEC_CORRECTED_ONES_MSB_OFF,
		       OCORE_FEC_CORRECTED_ONES_LSB_OFF);
}

/**
 * cne_rmon_refresh - fold the current hardware counts into the RMON totals
 * @edev: Ethernet device
 *
 * PF-only. Used by the ethtool getters so they report counts up to the
 * moment of the call rather than up to the last background poll.
 */
static void cne_rmon_refresh(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	if (dd->is_vf)
		return;

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	mutex_unlock(&acc->lock);
}

/**
 * cne_rmon_poll_task - periodically fold the hardware counters into the
 * running RMON totals so they cannot saturate between ethtool reads
 * @work: embedded delayed_work (edev->rmon_accum.work)
 */
static void cne_rmon_poll_task(struct work_struct *work)
{
	struct ether_device *edev = container_of(to_delayed_work(work),
						 struct ether_device, rmon_accum.work);

	cne_rmon_refresh(edev);
	/* retry soon while the counters wait for the MAC to become readable */
	schedule_delayed_work(&edev->rmon_accum.work,
			      READ_ONCE(edev->rmon_accum.start_pending) ?
			      msecs_to_jiffies(CNE_MAC_SETTLE_MS) :
			      CNE_RMON_POLL_DELAY);
}

/**
 * cne_rmon_init - initialize the RMON accumulator
 * @edev: Ethernet device
 *
 * Must run before register_netdev(), since ethtool callbacks take
 * rmon_accum.lock as soon as the netdev is visible.
 */
void cne_rmon_init(struct ether_device *edev)
{
	mutex_init(&edev->rmon_accum.lock);
	INIT_DELAYED_WORK(&edev->rmon_accum.work, cne_rmon_poll_task);
}

/**
 * cne_rmon_start - start the background RMON accumulation poll
 * @edev: Ethernet device
 *
 * PF-only: OmegaCORE MAC MIB registers are not accessible from VFs
 * (EAL MAS S2.11.2). Caller is expected to check dd->is_vf first.
 */
void cne_rmon_start(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	unsigned long delay = CNE_RMON_POLL_DELAY;

	mutex_lock(&acc->lock);
	acc->running = true;
	if (cne_mac_readable(edev) && eal_mac_stats_enable(edev)) {
		eal_rmon_discard_locked(dd, acc);
		eal_mac_pause_sync_locked(edev);
	} else {
		/* the first fold with the MAC readable enables the counters */
		WRITE_ONCE(acc->start_pending, true);
		delay = msecs_to_jiffies(CNE_MAC_SETTLE_MS) + 1;
	}
	mutex_unlock(&acc->lock);

	schedule_delayed_work(&acc->work, delay);
}

/**
 * cne_rmon_stop - stop the background RMON accumulation poll
 * @edev: Ethernet device
 */
void cne_rmon_stop(struct ether_device *edev)
{
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	/* keep cne_mac_link_set() from queueing the poll again */
	mutex_lock(&acc->lock);
	acc->running = false;
	mutex_unlock(&acc->lock);
	cancel_delayed_work_sync(&acc->work);

	/* a read-modify-write of MAC CSRs: skip it while not readable */
	mutex_lock(&acc->lock);
	if (cne_mac_readable(edev))
		eal_mac_stats_disable(edev);
	mutex_unlock(&acc->lock);
}

/**
 * cne_get_rmon_stats - RMON (RFC 2819) statistics
 * @ndev: network device
 * @rmon_stats: RMON statistics
 * @ranges: histogram bucket ranges, set to cn_rmon_ranges
 *
 * OmegaCORE MAC MIB registers are PF-only (EAL MAS S2.11.2: VF accesses
 * are ACK'd but no-op'd by hardware). PFs return the software-accumulated
 * running totals.
 */
static void cne_get_rmon_stats(struct net_device *ndev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	*ranges = cn_rmon_ranges;

	if (dd->is_vf) {
		netdev_info(ndev, "%s: VF-level RMON stats not exposed by hardware\n", __func__);
		return;
	}

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	rmon_stats->undersize_pkts = acc->undersize_pkts;
	rmon_stats->oversize_pkts = acc->oversize_pkts;
	rmon_stats->fragments = acc->fragments;
	rmon_stats->jabbers = acc->jabbers;
	memcpy(rmon_stats->hist, acc->hist, sizeof(acc->hist));
	memcpy(rmon_stats->hist_tx, acc->hist_tx, sizeof(acc->hist_tx));
	mutex_unlock(&acc->lock);
}

/**
 * cne_get_eth_mac_stats - RFC 3635 dot3StatsTable statistics
 * @ndev: network device
 * @mac_stats: IEEE 802.3 MAC statistics
 *
 * OmegaCORE MAC MIB registers are PF-only (EAL MAS S2.11.2: VF accesses
 * are ACK'd but no-op'd by hardware). PFs return the software-accumulated
 * running totals. Only the dot3StatsTable fields with a real backing counter
 * are populated.
 */
static void cne_get_eth_mac_stats(struct net_device *ndev,
				  struct ethtool_eth_mac_stats *mac_stats)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	if (dd->is_vf) {
		netdev_info(ndev, "%s: VF-level MAC stats not exposed by hardware\n", __func__);
		return;
	}

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	mac_stats->FramesTransmittedOK = acc->frames_tx_ok;
	mac_stats->FramesReceivedOK = acc->frames_rx_ok;
	mac_stats->FrameCheckSequenceErrors = acc->fcs_errors;
	mac_stats->AlignmentErrors = acc->alignment_errors;
	mac_stats->OctetsTransmittedOK = acc->octets_tx_ok;
	mac_stats->OctetsReceivedOK = acc->octets_rx_ok;
	mac_stats->MulticastFramesXmittedOK = acc->mcast_tx_ok;
	mac_stats->BroadcastFramesXmittedOK = acc->bcast_tx_ok;
	mac_stats->MulticastFramesReceivedOK = acc->mcast_rx_ok;
	mac_stats->BroadcastFramesReceivedOK = acc->bcast_rx_ok;
	mac_stats->FrameTooLongErrors = acc->oversize_pkts;
	mutex_unlock(&acc->lock);
}

/**
 * cne_get_eth_ctrl_stats - IEEE 802.3 clause 30.3.3 MAC control statistics
 * @ndev: network device
 * @ctrl_stats: MAC control statistics
 *
 * OmegaCORE has no generic MAC-control-frame counter, only PAUSE and PFC
 * specific counters, so MACControlFramesTransmitted/Received are approximated
 * as the sum of those two.
 */
static void cne_get_eth_ctrl_stats(struct net_device *ndev,
				   struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	if (dd->is_vf) {
		netdev_info(ndev, "%s: VF-level MAC control stats not exposed by hardware\n",
			    __func__);
		return;
	}

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	ctrl_stats->MACControlFramesTransmitted = acc->mac_ctrl_frames_tx;
	ctrl_stats->MACControlFramesReceived = acc->mac_ctrl_frames_rx;
	mutex_unlock(&acc->lock);
}

/**
 * cne_get_fec_stats - IEEE 802.3 RS-FEC statistics
 * @ndev: network device
 * @fec_stats: FEC statistics
 * @hist: FEC bit-error histogram (unused; hardware has no per-bin counter)
 *
 * The RS-FEC counters live in the PF-only OmegaCORE APB aperture (EAL MAS
 * S2.11.2) and are folded into software running totals by the RMON poll.
 */

static void cne_get_fec_stats(struct net_device *ndev,
			      struct ethtool_fec_stats *fec_stats,
			      struct ethtool_fec_hist *hist)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rmon_accum *acc = &edev->rmon_accum;

	if (dd->is_vf) {
		netdev_info(ndev, "%s: VF-level FEC stats not exposed by hardware\n", __func__);
		return;
	}

	mutex_lock(&acc->lock);
	eal_rmon_fold_locked(dd, acc);
	fec_stats->corrected_blocks.total = acc->fec_corrected_blocks;
	fec_stats->uncorrectable_blocks.total = acc->fec_uncorrectable_blocks;
	fec_stats->corrected_bits.total = acc->fec_corrected_bits;
	mutex_unlock(&acc->lock);
}

/**
 * cne_get_fecparam - report the active FEC mode
 * @ndev: network device
 * @fp: FEC parameters
 *
 * At 200G/400G the OmegaCORE FEC is always RS; the MAIN_CTL1 decoder-bypass bit
 * (PF-only OmegaCORE APB aperture) tells us whether it is active.
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_get_fecparam(struct net_device *ndev,
			    struct ethtool_fecparam *fp)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 main_ctl1;

	if (dd->is_vf) {
		fp->fec = ETHTOOL_FEC_NONE;
		fp->active_fec = ETHTOOL_FEC_NONE;
		return 0;
	}

	/* report the last mode read while the MAC is not readable */
	if (cne_mac_readable(edev) &&
	    cne_eal_read(dd, CYR_OCORE_RX_FEC, &main_ctl1))
		WRITE_ONCE(edev->mac_fec_off,
			   OCORE_FEC_MAIN_CTL1_GET_DEC_BYPASS_EN(main_ctl1));

	fp->fec = ETHTOOL_FEC_RS;
	fp->active_fec = READ_ONCE(edev->mac_fec_off) ?
			 ETHTOOL_FEC_OFF : ETHTOOL_FEC_RS;

	return 0;
}

/**
 * cne_get_ts_info -
 * @ndev: network device
 * @info: timestamp information
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_get_ts_info(struct net_device *ndev,
			   struct kernel_ethtool_ts_info *info)
{
#ifdef CONFIG_PTP_1588_CLOCK
	struct ether_device *edev = netdev_priv(ndev);

	if (edev->ptp_clock) {
		info->phc_index = ptp_clock_index(edev->ptp_clock);
		info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
			SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE |
			SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
			SOF_TIMESTAMPING_RAW_HARDWARE;

		info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
		info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			BIT(HWTSTAMP_FILTER_SOME) | BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
			BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
			BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ);
	} else {
		return ethtool_op_get_ts_info(ndev, info);
	}
#else
	return ethtool_op_get_ts_info(ndev, info);
#endif

	return 0;
}

/**
 * cne_eal_set_pause_config - Set EAL flow control mode
 * @edev: ether_device to configure
 * @use_pfc: if true, use priority flow control (802.1Qbb) otherwise
 * use IEEE802.3x flow control
 *
 * The RX MAC must classify ingress by PCP in PFC mode and into TC0 in
 * classic mode, so rx_mac_pfc_enable follows pfc_pause_enabled.
 * Classic 802.3x RX pause handling in CYR_OCORE_RX_MAIN_CTL1 is mutually
 * exclusive with PFC and is disabled while PFC mode is active.
 */
void cne_eal_set_pause_config(struct ether_device *edev, bool use_pfc)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 pause_reg = hfi2_read_csr(dd, CYR_EAL_RX_PAUSE_CONFIG);

	EAL_RX_PAUSE_CFG_SET_PFC_ENABLED(pause_reg, use_pfc ? 1 : 0);
	EAL_RX_PAUSE_CFG_SET_RX_MAC_PFC_EN(pause_reg, use_pfc ? 1 : 0);
	hfi2_write_csr(dd, CYR_EAL_RX_PAUSE_CONFIG, pause_reg);

	/* RX_MAIN_CTL1 is a MAC CSR; see eal_mac_pause_sync_locked() */
	mutex_lock(&edev->rmon_accum.lock);
	edev->mac_pause_en = !use_pfc && edev->rx_pause;
	eal_mac_pause_sync_locked(edev);
	mutex_unlock(&edev->rmon_accum.lock);

	WRITE_ONCE(edev->pfc_enabled, (u8)use_pfc);
}

/**
 * cne_set_pauseparam - Set pause parameters
 * @ndev: network device
 * @parms: pause parameters to set
 *
 * This is the .set_pauseparam ethtool_ops implementation. The pause
 * configuration is port-wide, so only the PF may change it.
 *
 * Return: 0 on success, -EOPNOTSUPP on a VF, -EINVAL for autoneg.
 */
static int cne_set_pauseparam(struct net_device *ndev,
			struct ethtool_pauseparam *parms)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;

	pdbg(edev, drv, "set pause: autoneg %u rx_pause %u tx_pause %u\n", parms->autoneg,
		parms->rx_pause, parms->tx_pause);

	if (dd->is_vf)
		return -EOPNOTSUPP;

	/* We don't allow auto negotiation. */
	if (parms->autoneg)
		return -EINVAL;

	edev->rx_pause = parms->rx_pause;

	/* Be mutually exclusive with PFC; sets classic RX and TX pause */
	cne_dcb_set_classic(edev, parms->tx_pause);

	return 0;
}

/**
 * cne_get_channels - get current/max RX and TX channel (queue) counts
 * @ndev: network device
 * @ch: channel info to fill in
 *
 * This is the .get_channels ethtool_ops implementation.
 */
static void cne_get_channels(struct net_device *ndev,
			     struct ethtool_channels *ch)
{
	struct ether_device *edev = netdev_priv(ndev);

	ch->max_rx = cne_max_rxqs(edev->ppd);
	ch->max_tx = cne_max_txqs(edev->ppd, ndev);
	ch->rx_count = edev->num_rxqs;
	ch->tx_count = edev->num_txqs;
}

/**
 * cne_resize_queues - change the number of allocated RX/TX queues
 * @edev: Ethernet device, stopped
 * @num_rx: number of RX queues
 * @num_tx: number of TX queues
 *
 * Helper for cne_set_channels().  Queues below the new counts are kept,
 * with their RX rings resized for the new RX count, and new queues are
 * allocated before any are freed, so on failure the device still has its
 * previous queues and ring size.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_resize_queues(struct ether_device *edev, u32 num_rx,
			     u32 num_tx)
{
	u32 old_rx = edev->num_rxqs;
	int rc;

	rc = cne_alloc_rxqs(edev, num_rx);
	if (rc)
		return rc;
	rc = cne_alloc_txqs(edev, num_tx);
	if (rc) {
		cne_trim_rxqs(edev, old_rx);
		cne_alloc_rxqs(edev, old_rx);
		return rc;
	}

	cne_trim_rxqs(edev, num_rx);
	cne_trim_txqs(edev, num_tx);

	if (!netif_is_rxfh_configured(edev->ndev))
		edev->rss_indir_valid = false;
	return 0;
}

/**
 * cne_set_channels - set RX and TX channel (queue) counts
 * @ndev: network device
 * @ch: requested channel counts
 *
 * This is the .set_channels ethtool_ops implementation.  Called with RTNL
 * held, which also serializes against the SR-IOV reinit stop/open path.
 *
 * Queues are added or removed in place.  If the new counts cannot be
 * allocated or opened, the previous counts are restored and reopened.
 * If that also fails, the interface is closed rather than left
 * administratively UP but unable to pass traffic; it keeps its queues, so
 * bringing it up again retries.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_set_channels(struct net_device *ndev,
			    struct ethtool_channels *ch)
{
	struct ether_device *edev = netdev_priv(ndev);
	bool running = netif_running(ndev);
	u32 old_rx = edev->num_rxqs;
	u32 old_tx = edev->num_txqs;
	int rc, rc2;

	/*
	 * The ethtool core has already rejected unchanged, zero, and
	 * over-max counts, and nonzero other/combined counts.
	 */
	pinfo(edev, drv, "set channels: RXQs %u->%u TXQs %u->%u\n",
	      old_rx, ch->rx_count, old_tx, ch->tx_count);

	if (running)
		cne_stop(ndev);

	rc = cne_resize_queues(edev, ch->rx_count, ch->tx_count);
	if (rc) {
		netdev_err(ndev, "Failed allocating %u RX / %u TX queues (rc %d)\n",
			   ch->rx_count, ch->tx_count, rc);
		goto reopen;
	}
	if (!running)
		return 0;

	rc = cne_open(ndev);
	if (!rc)
		return 0;
	netdev_err(ndev, "Failed opening with %u RX / %u TX queues (rc %d)\n",
		   ch->rx_count, ch->tx_count, rc);

	/*
	 * A failed cne_open() leaves every queue disabled.  Restoring can fail
	 * if user contexts claimed the SC_USER send contexts freed by a TX
	 * shrink, or memory is short; the new counts are kept then.
	 */
	rc2 = cne_resize_queues(edev, old_rx, old_tx);
	if (rc2)
		netdev_err(ndev, "Failed restoring %u RX / %u TX queues (rc %d)\n",
			   old_rx, old_tx, rc2);

reopen:
	if (running && cne_open(ndev)) {
		netdev_err(ndev, "Reopen failed, closing device\n");
		/* Don't leave it IFF_UP with TX and carrier stopped */
		dev_close(ndev);
	}

	return rc;
}

/**
 * cne_get_strings - Return strings that describe the requested objects
 * @ndev: network device
 * @stringset: requested objects
 * @data: strings
 */
static void cne_get_strings(struct net_device *ndev,
			u32 stringset,
			u8 *data)
{
	struct ether_device *edev = netdev_priv(ndev);
	int i, vl, q;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(cne_stats); i++) {
			memcpy(data, cne_stats[i].name, ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		for (i = 0; i < ARRAY_SIZE(cne_stats_per_vl); i++) {
			for (vl = 0; vl < RXE_NUM_DATA_VL; vl++) {
				snprintf(data, ETH_GSTRING_LEN, cne_stats_per_vl[i].name, vl);
				data += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < ARRAY_SIZE(cne_stats_per_rxq); i++) {
			for (q = 0; q < edev->num_rxqs; q++) {
				snprintf(data, ETH_GSTRING_LEN, cne_stats_per_rxq[i].name, q);
				data += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < ARRAY_SIZE(cne_stats_per_txq); i++) {
			for (q = 0; q < edev->num_txqs; q++) {
				snprintf(data, ETH_GSTRING_LEN, cne_stats_per_txq[i].name, q);
				data += ETH_GSTRING_LEN;
			}
		}
		break;

	default:
		return;
	}
}

/**
 * cne_get_sset_count - get number of strings
 * @ndev: network device
 * @stringset: which string set is requested
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_get_sset_count(struct net_device *ndev,
				int stringset)
{
	struct ether_device *edev = netdev_priv(ndev);

	switch (stringset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(cne_stats) +
		       (ARRAY_SIZE(cne_stats_per_vl) * RXE_NUM_DATA_VL) +
		       (ARRAY_SIZE(cne_stats_per_rxq) * edev->num_rxqs) +
		       (ARRAY_SIZE(cne_stats_per_txq) * edev->num_txqs);

	default:
		return -EOPNOTSUPP;
	}
}

/* Minimum time between batches of CPORT mailbox reads of RoCEv2 counters. Rate
 * limits the amount of CPORT traffic that unprivileged `ethtool -S` calls can
 * generate.
 */
#define CNE_ROCEV2_SNAPSHOT_TTL	msecs_to_jiffies(1000)

/* Time to wait for each RoCEv2 counter read. These reads happen under rtnl,
 * so the wait is kept short: an unresponsive mailbox stalls every netdev
 * operation on the system until it returns. Three reads at this timeout hold
 * rtnl for less time than a single read at the mailbox default.
 */
#define CNE_ROCEV2_READ_TIMEOUT	msecs_to_jiffies(250)

/**
 * cne_rocev2_refresh - re-read the RoCEv2 telemetry counters from firmware
 * @edev: Ethernet device
 *
 * Collect all of the counters in one pass, so they are either all updated or
 * none of them are. On failure, keep the previous values to preserve
 * monotonicity.
 */
static void cne_rocev2_refresh(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct cn_rocev2_snapshot *snap = &edev->rocev2;
	u64 pkts = 0, ooo = 0, mismatch = 0;
	int rc;

	if (dd->is_vf || !dd->cport)
		return;

	mutex_lock(&snap->lock);

	if (time_before(jiffies, snap->expires))
		goto unlock;

	rc = cport_read_csr(dd, CPORT_CRK_EAL_PRF_ROCEV2_PKT_RCVD_ADDR, &pkts,
			    CNE_ROCEV2_READ_TIMEOUT);
	if (!rc)
		rc = cport_read_csr(dd, CPORT_CRK_EAL_PRF_ROCEV2_OOO_PKT_RCVD_ADDR, &ooo,
				    CNE_ROCEV2_READ_TIMEOUT);
	if (!rc)
		rc = cport_read_csr(dd, CPORT_CRK_EAL_PRF_RIFT_ENTRY_MISMATCH_ADDR, &mismatch,
				    CNE_ROCEV2_READ_TIMEOUT);
	if (rc) {
		if (net_ratelimit())
			netdev_warn(edev->ndev, "Failure reading RoCEv2 counters (%d)\n", rc);
	} else {
		snap->pkts_rcvd = pkts;
		snap->ooo_pkts_rcvd = ooo;
		snap->rift_entry_mismatch = mismatch;
	}

	snap->expires = jiffies + CNE_ROCEV2_SNAPSHOT_TTL;

unlock:
	mutex_unlock(&snap->lock);
}

/**
 * cne_get_ethtool_stats - Return extended statistics about the device.
 * @ndev: network device
 * @stats:
 * @data: statistics data
 */
static void cne_get_ethtool_stats(struct net_device *ndev,
				struct ethtool_stats *stats,
				u64 *data)
{
	struct ether_device *edev = netdev_priv(ndev);
	int i, j, vl, q;

	cne_rocev2_refresh(netdev_priv(ndev));
	cne_rmon_refresh(edev);
	for (i = 0; i < ARRAY_SIZE(cne_stats); i++)
		data[i] = cne_stats[i].get(ndev);
	for (j = 0; j < ARRAY_SIZE(cne_stats_per_vl); j++) {
		for (vl = 0; vl < RXE_NUM_DATA_VL; vl++, i++)
			data[i] = cne_stats_per_vl[j].get(ndev, vl);
	}
	for (j = 0; j < ARRAY_SIZE(cne_stats_per_rxq); j++) {
		for (q = 0; q < edev->num_rxqs; q++, i++)
			data[i] = cne_stats_per_rxq[j].get(ndev, q);
	}
	for (j = 0; j < ARRAY_SIZE(cne_stats_per_txq); j++) {
		for (q = 0; q < edev->num_txqs; q++, i++)
			data[i] = cne_stats_per_txq[j].get(ndev, q);
	}
}

/**
 * cne_get_msglevel - get current message level (see netif_* functions)
 * @ndev: network device
 *
 * Returns current message level.
 */
static u32 cne_get_msglevel(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return edev->msg_enable;
}

/**
 * cne_set_msglevel - set current message level (see netif_* functions)
 * @ndev: network device
 * @level: desired message level
 */
static void cne_set_msglevel(struct net_device *ndev,
				u32 level)
{
	struct ether_device *edev = netdev_priv(ndev);

	edev->msg_enable = level;
}

/**
 * cne_get_ringparam - Get RX/TX ring (queue depth) parameters
 * @ndev: network device
 * @param: storage for classic ring parameters (rx/tx pending & max pending)
 * @kparam: storage for extended ring parameters (unused)
 * @extack: netlink extended ack (unused)
 *
 * Get RX/TX ring depth for pending and max pending. Back RX pending by the
 * number of eager buffers actually posted (the RcvHdr queue is sized to the
 * requested ring and can be deeper than the eager ring), and back TX
 * pending by SDMA descriptor ring depth.
 */
static void cne_get_ringparam(struct net_device *ndev,
			      struct ethtool_ringparam *param,
			      struct kernel_ethtool_ringparam *kparam,
			      struct netlink_ext_ack *extack)
{
	struct ether_device *edev = netdev_priv(ndev);

	param->rx_max_pending = HFI2_MAX_HDRQ_EGRBUF_CNT;
	param->tx_max_pending = SDMA_DESCQ_CNT_MAX;

	/* queue 0 is representative of every queue */
	if (edev->rxq[0] && edev->rxq[0]->rcd)
		param->rx_pending = edev->rxq[0]->rcd->egrbufs.alloced;
	if (edev->txq[0] && edev->txq[0]->sde)
		param->tx_pending = edev->txq[0]->sde->descq_cnt;
}

/**
 * cne_get_coalesce - Get RX interrupt coalescing parameters
 * @ndev: network device
 * @coal: storage for classic coalescing parameters
 * @kernel_coal: extended coalescing parameters (unused)
 * @extack: netlink extended ack (unused)
 *
 * Backed by the per-context RcvAvail timeout and RcvHdrHead.Counter
 * CSRs, cached per-device in struct hfi2_devdata.
 */
static int cne_get_coalesce(struct net_device *ndev,
			    struct ethtool_coalesce *coal,
			    struct kernel_ethtool_coalesce *kernel_coal,
			    struct netlink_ext_ack *extack)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u32 timeout_csr = dd->rcv_intr_timeout_csr;

	coal->rx_coalesce_usecs =
		DIV_ROUND_CLOSEST(hfi2_cclock_to_ns(dd, timeout_csr * 64), 1000);
	coal->rx_max_coalesced_frames = dd->rcv_intr_count;
	coal->use_adaptive_rx_coalesce = dd->rcv_intr_dynamic;

	return 0;
}

/**
 * cne_set_coalesce - Set RX interrupt coalescing parameters
 * @ndev: network device
 * @coal: requested classic coalescing parameters
 * @kernel_coal: extended coalescing parameters (unused)
 * @extack: netlink extended ack for error reporting
 *
 * Configure RX coalescing of this netdev's receive contexts.  The count,
 * adaptive flag and maximum timeout are device-wide, so other kernel receive
 * contexts pick up the new count on their next head update.
 */
static int cne_set_coalesce(struct net_device *ndev,
			    struct ethtool_coalesce *coal,
			    struct kernel_ethtool_coalesce *kernel_coal,
			    struct netlink_ext_ack *extack)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u32 count = coal->rx_max_coalesced_frames;
	u32 dynamic = coal->use_adaptive_rx_coalesce;
	u32 usecs = coal->rx_coalesce_usecs;
	u32 max_ns = hfi2_cclock_to_ns(dd, RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK * 64);
	u32 max_usecs = DIV_ROUND_CLOSEST(max_ns, 1000);
	u32 timeout_csr;
	int i;

	if (count > RCV_HDR_HEAD_COUNTER_MASK) {
		netdev_warn(ndev, "rx-frames %u exceeds max %u, clamping\n",
			    count, (u32)RCV_HDR_HEAD_COUNTER_MASK);
		count = RCV_HDR_HEAD_COUNTER_MASK;
	}

	/* clamp in the microsecond domain first: rx_coalesce_usecs is user-
	 * controlled and hfi2_ns_to_cclock() scales it by 1000 internally, so an
	 * unclamped value would overflow the u32 ns intermediate before the
	 * CSR-field clamp below could run
	 */
	if (usecs > max_usecs) {
		netdev_warn(ndev,
			    "rx-usecs %u exceeds hardware maximum (~%u us), clamping\n",
			    usecs, max_usecs);
		usecs = max_usecs;
	}

	timeout_csr = hfi2_ns_to_cclock(dd, usecs * 1000) / 64;
	if (timeout_csr > RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK)
		timeout_csr = RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_MASK;

	/* Enforce the same invariants as hfi2_mod_init() */
	if (count == 0 && timeout_csr == 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "rx-frames and rx-usecs cannot both be zero");
		return -EINVAL;
	}
	if (count > 1 && timeout_csr == 0) {
		NL_SET_ERR_MSG_MOD(extack,
				   "rx-usecs cannot be zero when rx-frames is greater than 1");
		return -EINVAL;
	}
	if (dynamic && !(count > 1 && timeout_csr > 0)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "adaptive-rx requires rx-frames > 1 and a nonzero rx-usecs");
		return -EINVAL;
	}

	dd->rcv_intr_count = count;
	dd->rcv_intr_dynamic = dynamic;
	dd->rcv_intr_timeout_csr = timeout_csr;

	for (i = 0; i < edev->num_rxqs; i++) {
		struct hfi2_ctxtdata *rcd;

		if (!edev->rxq[i] || !edev->rxq[i]->rcd)
			continue;
		rcd = edev->rxq[i]->rcd;

		spin_lock_bh(&edev->rxq[i]->poll_lock);
		rcd->rcvavail_timeout = timeout_csr;
		write_kctxt_csr(dd, rcd->ctxt, dd->params->rcv_avail_time_out_reg,
				(u64)rcd->rcvavail_timeout
					<< RCV_AVAIL_TIME_OUT_TIME_OUT_RELOAD_SHIFT);
		hfi2_update_usrhead_ctxt(dd, rcd->ctxt, hfi2_rcd_head(rcd),
				    dd->rcv_intr_count, 0, 0);
		spin_unlock_bh(&edev->rxq[i]->poll_lock);
	}

	return 0;
}

/**
 * cne_get_rxnfc - Get RX network flow classification parameters
 * @ndev: network device
 * @info: RX network flow classification request/response
 * @rule_locs: classification rule locations (unused)
 *
 * Report the number of active RX queues and an empty classification rule
 * table.  RSM RSS steering rules are not ntuple filters.
 *
 * Return: 0 on success, -EOPNOTSUPP for unsupported commands.
 */
static int cne_get_rxnfc(struct net_device *ndev,
			 struct ethtool_rxnfc *info, u32 *rule_locs)
{
	struct ether_device *edev = netdev_priv(ndev);

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = edev->num_rxqs;
		return 0;
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRLALL:
		info->data = 0;
		info->rule_cnt = 0;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * cne_get_rxfh_fields - Get header fields used for RSS flow hashing
 * @ndev: network device
 * @fields: flow type to query; hashed fields are returned in @fields->data
 *
 * The RSM hashes L4 port bits after a fixed-length IPv4 or IPv6 header.
 * Only TCP, UDP and SCTP carry their ports at that location.
 *
 * Return: 0 on success, -EOPNOTSUPP for unsupported flow types or on a VF.
 */
static int cne_get_rxfh_fields(struct net_device *ndev,
			       struct ethtool_rxfh_fields *fields)
{
	struct ether_device *edev = netdev_priv(ndev);

	if (edev->ppd->dd->is_vf)
		return -EOPNOTSUPP;

	switch (fields->flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
	case SCTP_V4_FLOW:
	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
	case SCTP_V6_FLOW:
		fields->data = RXH_L4_B_0_1 | RXH_L4_B_2_3;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * cne_get_rxfh_indir_size - Get RX flow-hash indirection table size
 * @ndev: network device
 *
 * The cne netdev's receive steering is backed by the CYR Receive Side Mapping
 * (RSM) engine. Each cne netdev owns a fixed HFI2_ETH_MAP_ENTRIES window of
 * the globally shared RSM Map Table (RMT); this window is the indirection
 * (RETA) table that ethtool -x reports.
 *
 * Return: the number of entries in the indirection table.
 */
static u32 cne_get_rxfh_indir_size(struct net_device *ndev)
{
	return HFI2_ETH_MAP_ENTRIES;
}

/**
 * cne_get_rxfh_key_size - Get RSS hash key size
 * @ndev: network device
 *
 * There is no Toeplitz/CRC hash and no key register in silicon, so no hash key
 * can be reported.
 *
 * Return: 0 (no configurable hash key).
 */
static u32 cne_get_rxfh_key_size(struct net_device *ndev)
{
	return 0;
}

/**
 * cne_get_rxfh - Get RX flow-hash indirection table contents
 * @ndev: network device
 * @rxfh: RXFH parameters; @rxfh->indir and @rxfh->key may be NULL when the
 *	caller only wants sizes/hfunc.
 *
 * Report the indirection table currently in effect for this netdev's RMT
 * window. The hash XORs L4 source and destination port bits; no key is used.
 *
 * Return: 0 on success.
 */
static int cne_get_rxfh(struct net_device *ndev,
			struct ethtool_rxfh_param *rxfh)
{
	struct ether_device *edev = netdev_priv(ndev);
	u32 n = max_t(u32, edev->num_rxqs, 1);
	u32 i;

	/* The PF owns the RSM rules; a VF has no table to report. */
	if (edev->ppd->dd->is_vf)
		return -EOPNOTSUPP;

	rxfh->hfunc = ETH_RSS_HASH_XOR;

	if (rxfh->indir) {
		for (i = 0; i < HFI2_ETH_MAP_ENTRIES; i++)
			rxfh->indir[i] = edev->rss_indir_valid ?
					 edev->rss_indir[i] :
					 ethtool_rxfh_indir_default(i, n);
	}

	return 0;
}

/**
 * cne_set_rxfh - Set RX flow-hash indirection table contents
 * @ndev: network device
 * @rxfh: RXFH parameters supplied by userspace
 * @extack: netlink extended ack for error reporting
 *
 * Only the indirection table is settable on CYR. On success the table is
 * kept in @edev, pushed to hardware if RX is up, and replayed by
 * cne_enable_rxqs() on every open.
 *
 * Return: 0 on success, negative errno on rejection.
 */
static int cne_set_rxfh(struct net_device *ndev,
			struct ethtool_rxfh_param *rxfh,
			struct netlink_ext_ack *extack)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u16 map[HFI2_ETH_MAP_ENTRIES];
	u32 n = edev->num_rxqs;
	u32 i;

	if (dd->is_vf) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RSS configuration is not supported on VFs");
		return -EOPNOTSUPP;
	}

	if (rxfh->rss_context) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Additional RSS contexts are not supported");
		return -EOPNOTSUPP;
	}

	if (rxfh->key || rxfh->key_size) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Setting the RSS hash key is not supported");
		return -EOPNOTSUPP;
	}

	if (rxfh->hfunc != ETH_RSS_HASH_NO_CHANGE &&
	    rxfh->hfunc != ETH_RSS_HASH_XOR) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Changing the RSS hash function is not supported");
		return -EOPNOTSUPP;
	}

	if (!n) {
		NL_SET_ERR_MSG_MOD(extack, "No RX queues are available");
		return -EOPNOTSUPP;
	}

	if (rxfh->indir) {
		for (i = 0; i < HFI2_ETH_MAP_ENTRIES; i++) {
			if (rxfh->indir[i] >= n) {
				NL_SET_ERR_MSG_MOD(extack,
						   "Indirection table entry exceeds RX queue count");
				return -EINVAL;
			}
		}

		for (i = 0; i < HFI2_ETH_MAP_ENTRIES; i++)
			edev->rss_indir[i] = rxfh->indir[i];
		edev->rss_indir_valid = true;

		if (edev->rx_enabled) {
			cne_rss_build_map(edev, map);
			hfi2_eth_set_rmt_map(edev->ppd, map,
					     HFI2_ETH_MAP_ENTRIES);
		}
	}

	return 0;
}

/*
 * ethtool -d register dump.
 *
 * The dump is a flat array of u64 words with a fixed layout (identified by
 * regs->version) so it can be decoded by index on both PF and VF:
 *
 *   word 0: CNE_REGDUMP_F_* flags describing which sections are valid
 *   word 1: total number of words in the dump, header included
 *   word 2+: one word per register (or assembled counter) in the order of
 *            cne_regdump_tbl[]; arrays expand to consecutive words.
 *
 * Only registers audited as safe to read are included:
 *  - EAL counters are free-running RO/V (TC HAS App. D).
 *  - The RX/TX drop-reason fields are RW/V; they are only read here.
 *  - OmegaCORE MAC MIB counters are ROP; reads are non-destructive.
 *  - OCORE_MAC_LATCHED_INT is RW1C; reading is harmless.
 *  - OmegaCORE control/status registers are limited to RO, RW and RW1C
 *    registers.
 *  - EAL_PF_1588_PTP_EVENTS and EAL_RBUF_CREDIT_RET_ERR are RW/1C/V.
 *
 *  Note: RS-FEC counters are not dumped: with FEC PM_TICK_EN clear they are
 *  ROCP (read-to-clear) and owned by the RMON fold. The ROC counters and
 *  LOCAL_INT_CNT_CTL in the same block are never touched.
 *
 * VF access: a VF only reads its own per-function EAL block (TC HAS D.4).
 */
#define CNE_REGDUMP_VERSION		2
#define CNE_REGDUMP_HDR_WORDS		2

#define CNE_REGDUMP_F_VF		BIT_ULL(0) /* dumped from a VF */
#define CNE_REGDUMP_F_PF_REGS		BIT_ULL(1) /* PF-only words valid */
#define CNE_REGDUMP_F_NO_MAC		BIT_ULL(2) /* MAC words skipped, read 0 */

enum cne_regdump_kind {
	CNE_RD_KIND_CSR,	/* count consecutive 64-bit CSRs, stride 8 */
	CNE_RD_KIND_MAC48,	/* 48-bit OmegaCORE MAC MIB counter */
	CNE_RD_KIND_MAC_HIST,	/* OCORE_MAC_HIST_NUM_BINS 48-bit counters */
};

enum cne_regdump_scope {
	CNE_RD_ANY,		/* readable from PF and VF */
	CNE_RD_PF,		/* PF only */
};

struct cne_regdump_ent {
	u32 addr;		/* CSR address, or block base for MAC */
	u16 msb_off;		/* MAC counter MSB offset */
	u16 lsb_off;		/* MAC counter LSB offset */
	u8 count;		/* number of words this entry produces */
	u8 kind;		/* enum cne_regdump_kind */
	u8 scope;		/* enum cne_regdump_scope */
};

#define CNE_RD_ARR(_scope, _addr, _n) \
	{ .addr = (_addr), .count = (_n), \
	  .kind = CNE_RD_KIND_CSR, .scope = (_scope) }
#define CNE_RD_REG(_scope, _addr)	CNE_RD_ARR(_scope, _addr, 1)
#define CNE_RD_MAC(_base, _cnt) \
	{ .addr = (_base), .msb_off = _cnt##_MSB_OFF, \
	  .lsb_off = _cnt##_LSB_OFF, .count = 1, \
	  .kind = CNE_RD_KIND_MAC48, .scope = CNE_RD_PF }
#define CNE_RD_HIST(_base) \
	{ .addr = (_base), .count = OCORE_MAC_HIST_NUM_BINS, \
	  .kind = CNE_RD_KIND_MAC_HIST, .scope = CNE_RD_PF }
#define CNE_RD_OC1(_base, _off) \
	CNE_RD_REG(CNE_RD_PF, (_base) + OCORE_MAC_OFF(_off))
#define CNE_RD_OC(_base, _run) \
	CNE_RD_ARR(CNE_RD_PF, (_base) + OCORE_MAC_OFF(_run##_OFF), _run##_NUM)

/* Append only: reordering changes the layout and needs a version bump. */
static const struct cne_regdump_ent cne_regdump_tbl[] = {
	/* EAL per-function block (TC HAS D.4), read on VF paths today */
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_LEN_LIMIT0),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_LEN_LIMIT1),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VLAN_CFG),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_PAUSE_PKT_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_RX_PKT_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_RX_PKT_BYTE_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_TX_PKT_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_TX_PKT_BYTE_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_RX_PKT_DROP_COUNT),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_TX_PKT_DROP_COUNT),
	CNE_RD_ARR(CNE_RD_ANY, CYR_EAL_RBUF_CREDITS_AVAIL0, 2),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_MAC_PFC_PAUSED),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_PRF_CREDIT_DROP_CNTR),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR),
	CNE_RD_ARR(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0,
		   RXE_NUM_DATA_VL),

	/* EAL per-function block, only ever accessed from PF paths */
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_ROCEV2_CFG),
	CNE_RD_REG(CNE_RD_PF, CYR_TX_CAPTURE_TOD),

	/* EAL PF/port block (TC HAS D.5); SMAC/DMAC: PF, then VF0..VFn */
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_PF_SMAC_FILTER, CN_MAX_VFS + 1),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_PF_DMAC_ADDRESS, CN_MAX_VFS + 1),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_FILTER_CFG),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_DESTINATION_PORT_TABLE,
		   CYR_EAL_DESTINATION_PORT_TABLE_ENTRIES),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_FORCE_PAUSE_DISABLE),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_RX_PAUSE_CONFIG_VL0, RXE_NUM_DATA_VL),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_RX_PAUSE_CONFIG),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_RX_PAUSE_CFG_SHR),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_1588_PTP_PF_CFG0),
	/*
	 * Not consumed anywhere else in the driver, so even if these turn
	 * out to be clear-on-read no other statistic is affected.
	 */
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_RX_PKT_COUNT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_RX_PKT_BYTE_COUNT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_RX_PKT_DROP_COUNT),

	/* OmegaCORE RX MAC */
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_RX_MAIN_CTL1),
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_RX_MAIN_CTL1 +
			      OCORE_MAC_OFF(OCORE_MAC_LATCHED_INT_OFF)),
	CNE_RD_REG(CNE_RD_PF, CYR_RX_MAC_MAX_PKT_THRES),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_TOTAL_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_GOOD_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_GOOD_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_MULTICAST_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_BROADCAST_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_CRC_ERR_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_MISALIGNMENT_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_UNDERSIZE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_OVERSIZE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_RUNT_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_JABBER_FRM_CNT),
	CNE_RD_HIST(CYR_OCORE_RX_MAIN_CTL1),

	/* OmegaCORE TX MAC */
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_TX_MAIN_CTL1),
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_TX_MAIN_CTL1 +
			      OCORE_MAC_OFF(OCORE_MAC_LATCHED_INT_OFF)),
	CNE_RD_REG(CNE_RD_PF, CYR_TX_MAC_MAX_PKT_THRES),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_TOTAL_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_GOOD_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_GOOD_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_MULTICAST_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_BROADCAST_FRM_CNT),
	CNE_RD_HIST(CYR_OCORE_TX_MAIN_CTL1),

	/* OmegaCORE RS-FEC */
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_RX_FEC),

	/* SOC_CMN latch period shared by the MAC and FEC counter windows */
	CNE_RD_REG(CNE_RD_PF, CYR_OCORE_PM_TICK_PERIOD),

	/* RS-FEC control/status */
	CNE_RD_OC(CYR_OCORE_RX_FEC, OCORE_FEC_CTL_STAT),
	CNE_RD_OC(CYR_OCORE_RX_FEC, OCORE_FEC_LANE_STAT),
	CNE_RD_OC(CYR_OCORE_RX_FEC, OCORE_FEC_DATAPATH),
	CNE_RD_OC(CYR_OCORE_RX_FEC, OCORE_FEC_THRES),
	CNE_RD_OC1(CYR_OCORE_RX_FEC, OCORE_FEC_HI_SER_PERIOD_OFF),
	CNE_RD_OC(CYR_OCORE_RX_FEC, OCORE_FEC_AM_PERIOD),

	/* RX MAC: remaining control, counters and configuration */
	CNE_RD_OC1(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_MAIN_CTL2_OFF),
	CNE_RD_OC1(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_INT_MASK_OFF),
	CNE_RD_OC1(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_MIN_PKT_THRES_OFF),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_PAUSE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_UNICAST_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_ERROR_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_ERROR_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_BAD_PREAMBLE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_PFC_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_PAUSE_XON_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_PAUSE_XOFF_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_RX_MAIN_CTL1, OCORE_MAC_CRC_ALIGN_FRM_CNT),
	CNE_RD_OC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_FRM_CTL),
	CNE_RD_OC(CYR_OCORE_RX_MAIN_CTL1, OCORE_RX_MAC_PTP_VLAN),

	/* TX MAC: remaining control, counters and configuration */
	CNE_RD_OC1(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_MAIN_CTL2_OFF),
	CNE_RD_OC1(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_INT_MASK_OFF),
	CNE_RD_OC1(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_MIN_PKT_THRES_OFF),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_PAUSE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_UNICAST_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_ERROR_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_CRC_ERR_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_ERROR_BYTE_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_UNDERSIZE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_OVERSIZE_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_RUNT_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_JABBER_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_PFC_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_PAUSE_XON_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_PAUSE_XOFF_FRM_CNT),
	CNE_RD_MAC(CYR_OCORE_TX_MAIN_CTL1, OCORE_MAC_CRC_ALIGN_FRM_CNT),
	CNE_RD_OC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_FIFO),
	CNE_RD_OC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_FLOW),
	CNE_RD_OC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_PAUSE),
	CNE_RD_OC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_PTP_VLAN),
	CNE_RD_OC(CYR_OCORE_TX_MAIN_CTL1, OCORE_TX_MAC_PPM),

	/* SOC_CMN control/status */
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_CTL),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_CFG),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_LINK_INT),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_PCS_CFG),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_CLK_RST),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_66B_ERR_INT),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_ECC_INT),
	CNE_RD_OC1(CYR_OCORE_SOC_CONTROL, OCORE_SOC_FLEXO_OTU_AM_CNTRL_OFF),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_CLIENT),
	CNE_RD_OC(CYR_OCORE_SOC_CONTROL, OCORE_SOC_AM_LANE),
	CNE_RD_OC1(CYR_OCORE_SOC_CONTROL, OCORE_SOC_RX_ALIGN_CONFIG_OFF),
	CNE_RD_OC1(CYR_OCORE_SOC_CONTROL, OCORE_SOC_SW_TOD_ADJUST_OFF),
	CNE_RD_OC1(CYR_OCORE_SOC_CONTROL, OCORE_SOC_ECC_INT_MASK2_OFF),

	/* TX RS-FEC control/status */
	CNE_RD_OC(CYR_OCORE_TX_FEC, OCORE_TX_FEC_CTL),
	CNE_RD_OC1(CYR_OCORE_TX_FEC, OCORE_TX_FEC_AM_SF_CTL_OFF),
	CNE_RD_OC(CYR_OCORE_TX_FEC, OCORE_TX_FEC_DATAPATH),
	CNE_RD_OC(CYR_OCORE_TX_FEC, OCORE_TX_FEC_AM_PERIOD),

	/* SERDES handler: lane crossbars, gearbox, loopback, CDC FIFOs */
	CNE_RD_OC(CYR_OCORE_SERDES, OCORE_SERDES_XBAR),
	CNE_RD_OC(CYR_OCORE_SERDES, OCORE_SERDES_CDC),

	/* EAL per-function block, remaining readable registers */
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_RKEY_ALLOCATION),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_BCAST_CFG),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_DMAC_ADDRESS),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_SMAC_FILTER),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_RIFT_ALLOCATION),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_1588_PTP_CFG),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_1588_PTP_TX_CFG),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_DROP_ALL),
	CNE_RD_ARR(CNE_RD_ANY, CYR_EAL_TBUF_CREDITS_AVAIL0, 2),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_SHR),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_SHR),
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_PRF_RX_MINIPAUSE_CNTR),
	CNE_RD_ARR(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_VL0,
		   RXE_NUM_DATA_VL),
	CNE_RD_ARR(CNE_RD_ANY, CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_VL0,
		   RXE_NUM_DATA_VL),

	/* EAL per-function interrupt state, only meaningful for the PF */
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_FIRST_INT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_INT_STATUS),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_INT_MASK),

	/* EAL PF/port block, remaining readable registers */
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_DROP_ALL),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_16B_HEADER_DEFAULTS),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_RKEY_VF_MAPPING_CFG0, 2),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_RIFT_VF_MAPPING_CFG0, 2),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_DMAC_SMAC_CFG),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_VLAN_CFG),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_VL_PFC_MAPPING_TABLE),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_TX_PKT_COUNT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_TX_PKT_BYTE_COUNT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PORT_TX_PKT_DROP_COUNT),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_BCAST_CFG),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_TX_AU_TABLE_0TO3, 2),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_RX_AU_TABLE_0TO3, 2),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_1588_PTP_TX_CFG),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_PF_1588_PTP_EVENTS),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_TBUF_AVAIL_THRESHOLD),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_TBUF_AVAIL_SPACE),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_RBUF_CREDIT_RET_ERR),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_TODGEN_CORE_CLK_PERIOD),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_MINI_PAUSE_CFG),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_TAG_TIME_WINDOW_THRESHOLD),
	CNE_RD_REG(CNE_RD_PF, CYR_EAL_TID_RDMA_CFG),

	/* EAL PF/port filter tables */
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_L2_PROTOCOL_TABLE,
		   CYR_EAL_L2_PROTOCOL_TABLE_ENTRIES),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_MCAST_ADDRESS,
		   CYR_EAL_MCAST_ADDRESS_ENTRIES),
	CNE_RD_ARR(CNE_RD_PF, CYR_EAL_IP_PROTOCOL_TABLE,
		   CYR_EAL_IP_PROTOCOL_TABLE_ENTRIES),

	/* TOD engine configuration; the current time of day is not read */
	CNE_RD_REG(CNE_RD_PF, TOD_CONTROL_OFFSET),
	CNE_RD_REG(CNE_RD_PF, TOD_CLK_PERIOD_OFFSET),
	CNE_RD_REG(CNE_RD_PF, TOD_ACC_PERIOD_ADJ),

	/* EAL per-function RoCE IPv4 destination address */
	CNE_RD_REG(CNE_RD_ANY, CYR_EAL_VF_IP_DA_TABLE),
};

static unsigned int cne_regdump_nwords(void)
{
	unsigned int i, n = CNE_REGDUMP_HDR_WORDS;

	for (i = 0; i < ARRAY_SIZE(cne_regdump_tbl); i++)
		n += cne_regdump_tbl[i].count;

	return n;
}

static bool cne_regdump_ent_readable(const struct cne_regdump_ent *e,
				     bool pf)
{
	switch (e->scope) {
	case CNE_RD_ANY:
		return true;
	case CNE_RD_PF:
		return pf;
	}

	return false;
}

/* EAL MAC and RS-FEC CSRs, see cne_mac_readable() */
#define CNE_EAL_MAC_FIRST	(CYR_EAL_CFG + 0xe0000)
#define CNE_EAL_MAC_LAST	(CYR_EAL_CFG + 0xf1fff)

static bool cne_regdump_ent_mac(const struct cne_regdump_ent *e)
{
	return e->addr >= CNE_EAL_MAC_FIRST && e->addr <= CNE_EAL_MAC_LAST;
}

static u64 cne_regdump_read(struct hfi2_devdata *dd,
			    const struct cne_regdump_ent *e, unsigned int i)
{
	switch (e->kind) {
	case CNE_RD_KIND_CSR:
		return hfi2_read_csr(dd, e->addr + i * 8);
	case CNE_RD_KIND_MAC48:
		return eal_mac_read48(dd, e->addr, e->msb_off, e->lsb_off);
	case CNE_RD_KIND_MAC_HIST:
		return eal_mac_read48(dd, e->addr, oc_mac_hist_msb_off[i],
				      oc_mac_hist_msb_off[i] + 4);
	}

	return 0;
}

static int cne_get_regs_len(struct net_device *ndev)
{
	return cne_regdump_nwords() * sizeof(u64);
}

/**
 * cne_get_regs - ethtool -d handler
 * @ndev: network device
 * @regs: ethtool register dump header; version is set here
 * @p: zeroed output buffer of cne_get_regs_len() bytes
 *
 * See the layout description above cne_regdump_tbl[].
 */
static void cne_get_regs(struct net_device *ndev, struct ethtool_regs *regs,
			 void *p)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	bool pf = !dd->is_vf;
	bool mac_ok = cne_mac_readable(edev);
	unsigned int t, i, w = CNE_REGDUMP_HDR_WORDS;
	u64 *buf = p;

	regs->version = CNE_REGDUMP_VERSION;

	buf[0] = pf ? CNE_REGDUMP_F_PF_REGS : CNE_REGDUMP_F_VF;
	if (pf && !mac_ok)
		buf[0] |= CNE_REGDUMP_F_NO_MAC;
	buf[1] = cne_regdump_nwords();

	for (t = 0; t < ARRAY_SIZE(cne_regdump_tbl); t++) {
		const struct cne_regdump_ent *e = &cne_regdump_tbl[t];

		/* words skipped here stay 0: the buffer comes zeroed */
		if (!cne_regdump_ent_readable(e, pf) ||
		    (!mac_ok && cne_regdump_ent_mac(e))) {
			w += e->count;
			continue;
		}

		for (i = 0; i < e->count; i++)
			buf[w++] = cne_regdump_read(dd, e, i);
	}
}

static const struct ethtool_ops cne_ethtool_ops = {
	.get_channels =		cne_get_channels,
	.get_drvinfo =		cne_get_drvinfo,
	.get_regs_len =		cne_get_regs_len,
	.get_regs =		cne_get_regs,
	.get_link =		ethtool_op_get_link,
	.get_link_ksettings =	cne_get_link_ksettings,
	.get_ringparam =	cne_get_ringparam,
	.get_coalesce =		cne_get_coalesce,
	.set_coalesce =		cne_set_coalesce,
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS |
				      ETHTOOL_COALESCE_RX_MAX_FRAMES |
				      ETHTOOL_COALESCE_USE_ADAPTIVE_RX,
	.get_pauseparam =	cne_get_pauseparam,
	.get_pause_stats =	cne_get_pause_stats,
	.get_rmon_stats =	cne_get_rmon_stats,
	.get_eth_mac_stats =	cne_get_eth_mac_stats,
	.get_eth_ctrl_stats =	cne_get_eth_ctrl_stats,
	.get_fec_stats =	cne_get_fec_stats,
	.get_fecparam =		cne_get_fecparam,
	.get_rxnfc =		cne_get_rxnfc,
	.get_rxfh_indir_size =	cne_get_rxfh_indir_size,
	.get_rxfh_key_size =	cne_get_rxfh_key_size,
	.get_rxfh =		cne_get_rxfh,
	.set_rxfh =		cne_set_rxfh,
	.get_rxfh_fields =	cne_get_rxfh_fields,
	.get_ts_info =		cne_get_ts_info,
	.set_channels =		cne_set_channels,
	.set_pauseparam =	cne_set_pauseparam,
	.get_strings =		cne_get_strings,
	.get_sset_count =	cne_get_sset_count,
	.get_ethtool_stats =	cne_get_ethtool_stats,
	.get_msglevel =		cne_get_msglevel,
	.set_msglevel =		cne_set_msglevel,
	.set_phys_id =		cne_set_phys_id,
	.nway_reset =		cne_nway_reset,
};


/**
 * cne_init_ethtool - Initialize ethtool support
 * @ndev: network device
 *
 * Return: 0 on success.
 */
int cne_init_ethtool(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	mutex_init(&edev->rocev2.lock);
	edev->rocev2.expires = jiffies - 1;

	ndev->ethtool_ops = &cne_ethtool_ops;

	return 0;
}

/**
 * cne_destroy_ethtool - Tear down ethtool support
 * @ndev: network device
 */
void cne_destroy_ethtool(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	if (!edev->ppd->dd->is_vf)
		cne_rmon_stop(edev);
	mutex_destroy(&edev->rmon_accum.lock);
	mutex_destroy(&edev->rocev2.lock);
}

/* ethtool get stats functions */
/**
 * cne_eal_get_rx_pause_config - Get RX pause configuration
 * @ndev: network device
 *
 * Return: 1 if PFC is enabled, 0 otherwise.  While CPORT holds EAL in
 * reset, the last value read.
 */
u64 cne_eal_get_rx_pause_config(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 pause_reg;
	u8 pfc_enabled;

	if (!cne_eal_read(dd, CYR_EAL_RX_PAUSE_CONFIG, &pause_reg))
		return READ_ONCE(edev->pfc_enabled) ? 1 : 0;
	pfc_enabled = EAL_RX_PAUSE_CFG_GET_PFC_ENABLED(pause_reg);

	WRITE_ONCE(edev->pfc_enabled, pfc_enabled);

	return pfc_enabled ? 1 : 0;
}

/**
 * eal_get_mac_pfc_paused -
 * @ndev: network device
 *
 * Returns:
 */
static u64 eal_get_mac_pfc_paused(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_pportdata *ppd = edev->ppd;
	u64 pfc_paused;

	pfc_paused = hfi2_read_csr(ppd->dd, CYR_EAL_MAC_PFC_PAUSED);

	return EAL_MAC_PFC_PAUSED_GET_MAC_PFC_PAUSED(pfc_paused);
}

/**
 * eal_get_rbuf_pause_cntr_shr -
 * @ndev: network device
 *
 * Returns:
 */
static u64 eal_get_rbuf_pause_cntr_shr(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 pause_reg = hfi2_read_csr(dd, CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR);

	return EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR_GET_PAUSE_EVENT_COUNT(pause_reg);
}

/**
 * eal_rbuf_cred_avail_vl -
 * @ndev: network device
 * @vl_idx: Virtual Lane index
 *
 * Returns:
 */
static u64 eal_rbuf_cred_avail_vl(struct net_device *ndev, u8 vl_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 rbuf_reg;
	u32 creds_avail_csr;
	u64 ret;

	creds_avail_csr = CYR_EAL_RBUF_CREDITS_AVAIL0;
	if (vl_idx > 3)
		creds_avail_csr += 8;

	rbuf_reg = hfi2_read_csr(dd, creds_avail_csr);
	switch (vl_idx % 4) {
	case 0:
		ret = EAL_RBUF_CREDITS_AVAIL0_GET_VL0_RBUF_CREDITS_AVAIL(rbuf_reg);
		break;
	case 1:
		ret = EAL_RBUF_CREDITS_AVAIL0_GET_VL1_RBUF_CREDITS_AVAIL(rbuf_reg);
		break;
	case 2:
		ret = EAL_RBUF_CREDITS_AVAIL0_GET_VL2_RBUF_CREDITS_AVAIL(rbuf_reg);
		break;
	case 3:
		ret = EAL_RBUF_CREDITS_AVAIL0_GET_VL3_RBUF_CREDITS_AVAIL(rbuf_reg);
		break;
	default:
		netdev_err(ndev, "Invalid VL %u\n", vl_idx);
		ret = 0;
	}

	return ret;
}

/**
 * cne_eal_rbuf_pause_cntr_vl - Get rbuf pause counter for a VL
 * @ndev: network device
 * @vl_idx: VL index
 *
 * Return: pause event count for the specified VL.
 */
u64 cne_eal_rbuf_pause_cntr_vl(struct net_device *ndev, u8 vl_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	u32 pause_cntr_vl_csr = CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0 + (vl_idx * 8);
	u64 rbuf_reg = hfi2_read_csr(dd, pause_cntr_vl_csr);

	return  EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_GET_PAUSE_EVENT_COUNT(rbuf_reg);
}

static u64 cne_get_rxq_packets(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rxq_stats *rxq = &edev->rxq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&rxq->syncp);
		val = rxq->packets;
	} while (u64_stats_fetch_retry(&rxq->syncp, start));

	return val;
}

static u64 cne_get_rxq_bytes(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rxq_stats *rxq = &edev->rxq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&rxq->syncp);
		val = rxq->bytes;
	} while (u64_stats_fetch_retry(&rxq->syncp, start));

	return val;
}

static u64 cne_get_rxq_errors(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rxq_stats *rxq = &edev->rxq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&rxq->syncp);
		val = rxq->errors;
	} while (u64_stats_fetch_retry(&rxq->syncp, start));

	return val;
}

static u64 cne_get_rxq_drops(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rxq_stats *rxq = &edev->rxq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&rxq->syncp);
		val = rxq->drops;
	} while (u64_stats_fetch_retry(&rxq->syncp, start));

	return val;
}

static u64 cne_get_txq_packets(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_txq_stats *txq = &edev->txq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&txq->syncp);
		val = txq->sdma_packets;
	} while (u64_stats_fetch_retry(&txq->syncp, start));

	return val;
}

static u64 cne_get_txq_bytes(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_txq_stats *txq = &edev->txq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&txq->syncp);
		val = txq->sdma_bytes;
	} while (u64_stats_fetch_retry(&txq->syncp, start));

	return val;
}

static u64 cne_get_txq_errors(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_txq_stats *txq = &edev->txq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&txq->syncp);
		val = txq->errors + txq->sdma_errors;
	} while (u64_stats_fetch_retry(&txq->syncp, start));

	return val;
}

static u64 cne_get_txq_drops(struct net_device *ndev, u8 q_idx)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_txq_stats *txq = &edev->txq_stats[q_idx];
	unsigned int start;
	u64 val;

	do {
		start = u64_stats_fetch_begin(&txq->syncp);
		val = txq->drops;
	} while (u64_stats_fetch_retry(&txq->syncp, start));

	return val;
}

/* Per-priority traffic, summed over every queue slot so that it is monotonic */
static u64 cne_get_rx_prio_stat(struct net_device *ndev, const u64 *field)
{
	struct ether_device *edev = netdev_priv(ndev);
	size_t off = (const u8 *)field - (const u8 *)&edev->rxq_stats[0];
	unsigned int start;
	u64 total = 0, val;
	int i;

	for (i = 0; i < CN_MAX_QUEUES; i++) {
		struct cn_rxq_stats *rxq = &edev->rxq_stats[i];

		do {
			start = u64_stats_fetch_begin(&rxq->syncp);
			val = *(u64 *)((u8 *)rxq + off);
		} while (u64_stats_fetch_retry(&rxq->syncp, start));
		total += val;
	}

	return total;
}

static u64 cne_get_rx_prio_packets(struct net_device *ndev, u8 prio)
{
	struct ether_device *edev = netdev_priv(ndev);

	return cne_get_rx_prio_stat(ndev, &edev->rxq_stats[0].prio_packets[prio]);
}

static u64 cne_get_rx_prio_bytes(struct net_device *ndev, u8 prio)
{
	struct ether_device *edev = netdev_priv(ndev);

	return cne_get_rx_prio_stat(ndev, &edev->rxq_stats[0].prio_bytes[prio]);
}

static u64 eal_read_prf_cntr(struct net_device *ndev, u32 csr)
{
	struct ether_device *edev = netdev_priv(ndev);

	return EAL_VF_PRF_CNTR_GET_COUNT(hfi2_read_csr(edev->ppd->dd, csr));
}

static u64 eal_get_rbuf_pause_time_shr(struct net_device *ndev)
{
	return eal_read_prf_cntr(ndev, CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_SHR);
}

static u64 eal_get_rbuf_pause_resend_shr(struct net_device *ndev)
{
	return eal_read_prf_cntr(ndev, CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_SHR);
}

static u64 eal_get_rx_minipause_cntr(struct net_device *ndev)
{
	return eal_read_prf_cntr(ndev, CYR_EAL_VF_PRF_RX_MINIPAUSE_CNTR);
}

static u64 eal_rbuf_pause_time_vl(struct net_device *ndev, u8 vl_idx)
{
	return eal_read_prf_cntr(ndev, CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_VL0 +
				 vl_idx * 8);
}

static u64 eal_rbuf_pause_resend_vl(struct net_device *ndev, u8 vl_idx)
{
	return eal_read_prf_cntr(ndev, CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_VL0 +
				 vl_idx * 8);
}

/* TXE SendCounterArray64 per-VL counters, zero on a VF */
static u64 cne_get_tx_vl_packets(struct net_device *ndev, u8 vl_idx)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_port_cntr(edev->ppd, C_TX_PKT_VL, vl_idx);
}

static u64 cne_get_tx_vl_flits(struct net_device *ndev, u8 vl_idx)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_port_cntr(edev->ppd, C_TX_FLIT_VL, vl_idx);
}

static u64 eal_get_pause_pkt_tx_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	u64 reg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_PAUSE_PKT_COUNT);

	return EAL_PAUSE_PKT_COUNT_GET_TX(reg);
}

static u64 eal_get_pause_pkt_rx_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	u64 reg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_PAUSE_PKT_COUNT);

	return EAL_PAUSE_PKT_COUNT_GET_RX(reg);
}

static u64 eal_get_rx_pkt_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_csr(edev->ppd->dd, CYR_EAL_RX_PKT_COUNT);
}

static u64 eal_get_rx_pkt_byte_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_csr(edev->ppd->dd, CYR_EAL_RX_PKT_BYTE_COUNT);
}

static u64 eal_get_tx_pkt_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_csr(edev->ppd->dd, CYR_EAL_TX_PKT_COUNT);
}

static u64 eal_get_tx_pkt_byte_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return hfi2_read_csr(edev->ppd->dd, CYR_EAL_TX_PKT_BYTE_COUNT);
}

static u64 eal_get_rx_pkt_drop_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	u64 reg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_RX_PKT_DROP_COUNT);

	return EAL_RX_PKT_DROP_COUNT_GET_RX_DROP_COUNT(reg);
}

static u64 eal_get_tx_pkt_drop_count(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	u64 reg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_TX_PKT_DROP_COUNT);

	return EAL_TX_PKT_DROP_COUNT_GET_TX_DROP_COUNT(reg);
}

/*
 * RBUF-credit exhaustion (receive-buffer-full) drops. This is the
 * rx_missed_errors class per the rtnl stats definitions but per-port.
 */
static u64 eal_get_port_rx_missed_errors(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	u64 reg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_VF_PRF_CREDIT_DROP_CNTR);

	return EAL_VF_PRF_CREDIT_DROP_CNTR_GET_COUNT(reg);
}

/*
 * FCS/CRC receive errors. This aliases the eth-mac FrameCheckSequenceErrors
 * value: both read the OmegaCORE MAC MIB RX_MAC_CRC_ERR_FRM_CNT counter, which
 * is accumulated once per PM_TICK window into rmon_accum.fcs_errors by the RMON
 * poll task. It is a physical-port aggregate (OmegaCORE MAC MIB is PF-only per
 * the EAL MAS), so the accumulator stays zero on VF netdevs.
 */
static u64 eal_get_rx_crc_errors(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* The accumulator is only fed on the PF by cne_rmon_start(), so a VF
	 * always reports zero.
	 */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = acc->fcs_errors;
	mutex_unlock(&acc->lock);

	return val;
}

/* 802.1Qbb PFC frames received from the link partner */
static u64 eal_get_rx_pfc_frames(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* Accumulator is only fed on the PF. */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = acc->pfc_frames_rx;
	mutex_unlock(&acc->lock);

	return val;
}

/* 802.1Qbb PFC frames sent to the link partner */
static u64 eal_get_tx_pfc_frames(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* Accumulator is only fed on the PF. */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = acc->pfc_frames_tx;
	mutex_unlock(&acc->lock);

	return val;
}

/* OmegaCORE RX_MAC_PAUSE_FRM_CNT: PAUSE frames received from the link partner */
static u64 eal_get_rx_mac_pause_frames(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* Accumulator is only fed on the PF. */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = acc->pause_frames_rx;
	mutex_unlock(&acc->lock);

	return val;
}

/* OmegaCORE TX_MAC_PAUSE_FRM_CNT: PAUSE frames sent to the link partner */
static u64 eal_get_tx_mac_pause_frames(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* Accumulator is only fed on the PF. */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = acc->pause_frames_tx;
	mutex_unlock(&acc->lock);

	return val;
}

/* Classic PAUSE frames split by quanta. */
static u64 eal_get_pause_accum(struct net_device *ndev, const u64 *field)
{
	struct ether_device *edev = netdev_priv(ndev);
	struct cn_rmon_accum *acc = &edev->rmon_accum;
	u64 val;

	/* Accumulator is only fed on the PF. */
	if (edev->ppd->dd->is_vf)
		return 0;

	mutex_lock(&acc->lock);
	val = *field;
	mutex_unlock(&acc->lock);

	return val;
}

static u64 eal_get_rx_mac_pause_xon(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return eal_get_pause_accum(ndev, &edev->rmon_accum.pause_xon_rx);
}

static u64 eal_get_rx_mac_pause_xoff(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return eal_get_pause_accum(ndev, &edev->rmon_accum.pause_xoff_rx);
}

static u64 eal_get_tx_mac_pause_xon(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return eal_get_pause_accum(ndev, &edev->rmon_accum.pause_xon_tx);
}

static u64 eal_get_tx_mac_pause_xoff(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	return eal_get_pause_accum(ndev, &edev->rmon_accum.pause_xoff_tx);
}

static u64 eal_get_rocev2_pkts_rcvd(struct net_device *ndev)
{
	struct cn_rocev2_snapshot *snap = &((struct ether_device *)netdev_priv(ndev))->rocev2;
	u64 val;

	mutex_lock(&snap->lock);
	val = snap->pkts_rcvd;
	mutex_unlock(&snap->lock);

	return val;
}

static u64 eal_get_rocev2_ooo_pkts_rcvd(struct net_device *ndev)
{
	struct cn_rocev2_snapshot *snap = &((struct ether_device *)netdev_priv(ndev))->rocev2;
	u64 val;

	mutex_lock(&snap->lock);
	val = snap->ooo_pkts_rcvd;
	mutex_unlock(&snap->lock);

	return val;
}

static u64 eal_get_rocev2_rift_entry_mismatch(struct net_device *ndev)
{
	struct cn_rocev2_snapshot *snap = &((struct ether_device *)netdev_priv(ndev))->rocev2;
	u64 val;

	mutex_lock(&snap->lock);
	val = snap->rift_entry_mismatch;
	mutex_unlock(&snap->lock);

	return val;
}
