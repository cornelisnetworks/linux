// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Ethernet driver main components.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mii.h>
#include <linux/crash_dump.h>
#include <linux/pm_runtime.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/utsname.h>
#include <linux/jhash.h>

#include "eth_main.h"
#include "bulksvc.h"
#include "vf2pf.h"

int debug = -1;

uint num_rxqs = 8;

uint num_txqs = 8;

uint num_sdes;

int max_vlans = VLAN_N_VID - 1;

/*
 * hfi2_num_eth_send_contexts - number of dedicated SC_USER send contexts the CYR Ethernet
 * TX path needs.  Each of up to CN_MAX_QUEUES TX queues claims one SC_USER context via
 * hfi2_sc_alloc() in cne_alloc_txq(), on top of the receive-context-derived SC_USER pool.
 * @dd - HFI device data
 * @pidx - port index
 *
 *  Returns 0 for every non-CYR-Ethernet configuration
 */
int hfi2_num_eth_send_contexts(struct hfi2_devdata *dd,
			       int pidx)
{
	if (!hfi2_is_eth_mode(dd) || dd->params->chip_type != CHIP_CYR)
		return 0;
	return min_t(uint, num_txqs, CN_MAX_QUEUES);
}

/**
 * hfi2_num_eth_tx_engines - SDMA engines cne_probe() gives the TX queues
 * @sde_available: kernel SDMA engines left to Ethernet
 *
 * TX queue i uses engine first_sdma_engine + i % this count, so the engines
 * used are counted from first_sdma_engine.  Affinity setup runs before
 * cne_probe() and sizes the SDMA IRQ slice from it.
 *
 * Return: num_txqs, limited by num_sdes or else by @sde_available.
 */
u32 hfi2_num_eth_tx_engines(u32 sde_available)
{
	return min_t(u32, num_txqs, num_sdes ? num_sdes : sde_available);
}

/**
 * cne_program_mtu - program the hardware frame length limits for an MTU
 * @edev: Ethernet device
 * @_mtu: Ethernet MTU
 *
 * Sets the per-VL MTU and send length checks and the CYR EAL and MAC
 * maximum frame lengths.  cne_probe() calls this for the initial MTU so
 * the receive limit is in place before the first frame arrives, and
 * cne_change_mtu() calls it on every change.
 *
 * Return: 0 on success, -ERRNO otherwise.
 */
static int cne_program_mtu(struct ether_device *edev, int _mtu)
{
	int i;
	int rc;
	int mtu = _mtu;
	u16 mtuDWs;
	u64 send_len_check0;
	u64 send_len_check1;
	u64 len_limit0;
	u64 len_limit1;
	struct hfi2_pportdata *ppd = edev->ppd;
	struct hfi2_devdata *dd = ppd->dd;

	/* Pad and align the MTU to accommodate headers and other considerations. */
	mtu += 64;
	mtu = ALIGN_UP(mtu, 64);
	mtuDWs = mtu / 4;

	for (i = 0; i < ppd->vls_supported; i++)
		ppd->vld[i].mtu = mtu;
	rc = hfi2_set_mtu(ppd);
	if (rc) {
		netdev_err(edev->ndev, "Failure setting MTU (%d) to %d\n", rc, mtu);
		return rc;
	}

	send_len_check0 = read_eport_csr(dd, ppd->hw_pidx, dd->params->send_len_check0_reg);
	send_len_check1 = read_eport_csr(dd, ppd->hw_pidx, dd->params->send_len_check1_reg);
	len_limit0 = hfi2_read_csr(dd, CYR_EAL_LEN_LIMIT0);
	len_limit1 = hfi2_read_csr(dd, CYR_EAL_LEN_LIMIT1);

	if (ppd->vls_supported > 0) {
		SEND_LEN_CHECK0_SET_LEN_VL0(send_len_check0, mtuDWs);
		EAL_LEN_LIMIT0_SET_MAX_LEN_VL0(len_limit0, mtu);
	}
	if (ppd->vls_supported > 1) {
		SEND_LEN_CHECK0_SET_LEN_VL1(send_len_check0, mtuDWs);
		EAL_LEN_LIMIT0_SET_MAX_LEN_VL1(len_limit0, mtu);
	}
	if (ppd->vls_supported > 2) {
		SEND_LEN_CHECK0_SET_LEN_VL2(send_len_check0, mtuDWs);
		EAL_LEN_LIMIT0_SET_MAX_LEN_VL2(len_limit0, mtu);
	}
	if (ppd->vls_supported > 3) {
		SEND_LEN_CHECK0_SET_LEN_VL3(send_len_check0, mtuDWs);
		EAL_LEN_LIMIT0_SET_MAX_LEN_VL3(len_limit0, mtu);
	}
	if (ppd->vls_supported > 4) {
		SEND_LEN_CHECK1_SET_LEN_VL4(send_len_check1, mtuDWs);
		EAL_LEN_LIMIT1_SET_MAX_LEN_VL4(len_limit1, mtu);
	}
	if (ppd->vls_supported > 5) {
		SEND_LEN_CHECK1_SET_LEN_VL5(send_len_check1, mtuDWs);
		EAL_LEN_LIMIT1_SET_MAX_LEN_VL5(len_limit1, mtu);
	}
	if (ppd->vls_supported > 6) {
		SEND_LEN_CHECK1_SET_LEN_VL6(send_len_check1, mtuDWs);
		EAL_LEN_LIMIT1_SET_MAX_LEN_VL6(len_limit1, mtu);
	}
	if (ppd->vls_supported > 7) {
		SEND_LEN_CHECK1_SET_LEN_VL7(send_len_check1, mtuDWs);
		EAL_LEN_LIMIT1_SET_MAX_LEN_VL7(len_limit1, mtu);
	}

	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_len_check0_reg, send_len_check0);
	write_eport_csr(dd, ppd->hw_pidx, dd->params->send_len_check1_reg, send_len_check1);

	hfi2_write_csr(dd, CYR_EAL_LEN_LIMIT0, len_limit0);
	hfi2_write_csr(dd, CYR_EAL_LEN_LIMIT1, len_limit1);

	hfi2_write_csr(dd, CYR_RX_MAC_MAX_PKT_THRES, mtu);
	hfi2_write_csr(dd, CYR_TX_MAC_MAX_PKT_THRES, mtu);

	return 0;
}

/**
 *  cne_change_mtu - update MTU
 *  @ndev: network device
 *  @_mtu: new Maximum Transmission Unit
 *
 *  Returns zero on success, -ERRNO otherwise.
 */
static int cne_change_mtu(struct net_device *ndev,
			  int _mtu)
{
	struct ether_device *edev = netdev_priv(ndev);
	int rc;

	if (_mtu > cne_rx_buf_max_mtu()) {
		netdev_err(ndev, "MTU %d exceeds max %u supported by RX buffers\n",
			   _mtu, cne_rx_buf_max_mtu());
		return -EINVAL;
	}

	rc = cne_program_mtu(edev, _mtu);
	if (rc)
		return rc;

	pinfo(edev, link, "MTU changed from %u to %u\n", ndev->mtu, _mtu);
	ndev->mtu = _mtu;

	return 0;
}

/**
 * cne_eth_ioctl - handle IOCTLs
 * @ndev: network device
 * @req: request
 * @cmd: IOCTL command
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_eth_ioctl(struct net_device *ndev,
			 struct ifreq *req,
			int cmd)
{
	int rc = 0;
	struct mii_ioctl_data *mdio = if_mii(req);

	if (!netif_running(ndev)) {
		netdev_warn(ndev, "Interface not ready.\n");
		return -EAGAIN;
	}

	switch (cmd) {
	case SIOCGMIIPHY:
		mdio->phy_id = 0; /* TODO: this isn't done */
		fallthrough;
	case SIOCGMIIREG:
		mdio->val_out = 7; /* TODO */
		break;
	case SIOCGHWTSTAMP:
		return cne_ptp_get_ts_config(ndev, req);
	case SIOCSHWTSTAMP:
		return cne_ptp_set_ts_config(ndev, req);
	default:
		rc = -EOPNOTSUPP;
		break;
	}

	return rc;
}

/**
 * cne_fix_features - adjust features according to device-specific constraints
 * @ndev: network device
 * @features: specified features to fix
 *
 * Returns the resulting features
 */
static netdev_features_t cne_fix_features(struct net_device *ndev,
					  netdev_features_t features)
{
	if (max_vlans <= 2)
		features |= NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER;
	else
		features &= ~(NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER);

	return features;
}

/**
 * cne_get_stats64 - get network device usage statistics
 * @ndev: network device
 * @stats: statistics storage
 */
static void cne_get_stats64(struct net_device *ndev,
			    struct rtnl_link_stats64 *stats)
{
	struct ether_device *edev = netdev_priv(ndev);
	unsigned int start;
	int i;

	/*
	 * Sum every slot, not just the active queues, so counts from queues
	 * removed by .set_channels are kept.
	 */
	for (i = 0; i < CN_MAX_QUEUES; i++) {
		const struct cn_rxq_stats *rs = &edev->rxq_stats[i];
		const struct cn_txq_stats *ts = &edev->txq_stats[i];
		u64 packets, bytes, errors, drops;

		do {
			start = u64_stats_fetch_begin(&rs->syncp);
			packets = rs->packets;
			bytes = rs->bytes;
			errors = rs->errors;
			drops = rs->drops;
		} while (u64_stats_fetch_retry(&rs->syncp, start));

		stats->rx_packets += packets;
		stats->rx_bytes += bytes;
		stats->rx_errors += errors;
		stats->rx_dropped += drops;

		do {
			start = u64_stats_fetch_begin(&ts->syncp);
			packets = ts->sdma_packets;
			bytes = ts->sdma_bytes;
			errors = ts->errors + ts->sdma_errors;
			drops = ts->drops;
		} while (u64_stats_fetch_retry(&ts->syncp, start));

		stats->tx_packets += packets;
		stats->tx_bytes += bytes;
		stats->tx_errors += errors;
		stats->tx_dropped += drops;
	}

	{
		u64 packets, bytes, drops;

		/* The bulksvc worker owns this slot, independently of NAPI. */
		do {
			start = u64_stats_fetch_begin(&edev->ulp_rx_stats.syncp);
			packets = edev->ulp_rx_stats.packets;
			bytes = edev->ulp_rx_stats.bytes;
			drops = edev->ulp_rx_stats.drops;
		} while (u64_stats_fetch_retry(&edev->ulp_rx_stats.syncp, start));
		stats->rx_packets += packets;
		stats->rx_bytes += bytes;
		stats->rx_dropped += drops;
	}
}

/**
 * cne_open - called when network interface activated
 * @ndev: network device
 *
 * Returns 0 on success, -ERRNO otherwise.
 */
int cne_open(struct net_device *ndev)
{
	int rc;
	struct ether_device *edev = netdev_priv(ndev);
	bool up = true;	/* VF, or link state unknown */
	u64 status;
	int err;

	pinfo(edev, ifup, "open:  RXQs %u TXQs %u max_vlans %u\n", edev->num_rxqs,
	      edev->num_txqs, max_vlans);

	rc = netif_set_real_num_tx_queues(ndev, edev->num_txqs);
	if (rc) {
		netdev_err(ndev, "Failure setting num tx queues (%d)\n", rc);
		return rc;
	}
	rc = netif_set_real_num_rx_queues(ndev, edev->num_rxqs);
	if (rc) {
		netdev_err(ndev, "Failure setting num rx queues (%d)\n", rc);
		return rc;
	}

	rc = cne_enable_txqs(edev);
	if (rc) {
		netdev_err(ndev, "Failure enabling tx queues (%d)\n", rc);
		return rc;
	}
	rc = cne_enable_rxqs(edev);
	if (rc) {
		netdev_err(ndev, "Failure enabling rx queues (%d)\n", rc);
		cne_disable_txqs(edev);
		return rc;
	}

	synchronize_net();
	/* VFs cannot read the link state; keep reporting carrier. */
	if (edev->ppd->dd->cport) {
		err = cne_query_link_status(ndev, &status);
		if (!err)
			up = LINK_UP(status);
		else if (err == -ENODEV)
			up = false;
	}
	if (up)
		netif_carrier_on(ndev);
	else
		netif_carrier_off(ndev);
	WRITE_ONCE(edev->tx_enabled, true);
	netif_tx_wake_all_queues(ndev);

	return rc;
}

/**
 * cne_update_link_state - sync netdev carrier with physical link state
 * @ppd: port data
 *
 * Called from the CPORT port state change (TRAP128) work item when the
 * device is in Ethernet mode.  CPORT firmware raises the same trap for
 * Ethernet link up/down as it does for OPA port state changes.  May sleep.
 */
void cne_update_link_state(struct hfi2_pportdata *ppd)
{
	struct net_device *ndev = READ_ONCE(ppd->ndev);
	u64 status;
	bool up;
	int err;

	if (!ndev || !netif_running(ndev))
		return;

	err = cne_query_link_status(ndev, &status);
	if (!err)
		up = LINK_UP(status);
	else if (err == -ENODEV)
		up = false;
	else
		return;		/* unknown; leave carrier as is */

	if (up == netif_carrier_ok(ndev))
		return;

	if (up) {
		netif_carrier_on(ndev);
		netdev_info(ndev, "Link up\n");
	} else {
		netif_carrier_off(ndev);
		netdev_info(ndev, "Link down\n");
	}
}

/**
 * cne_set_rx_mode - change address filtering
 * @ndev: network device
 */
static void cne_set_rx_mode(struct net_device *ndev)
{
	u64 eal_cfg;
	struct ether_device *edev = netdev_priv(ndev);

	pdbg(edev, drv, "RX mode: %s%s%s%s%s%s%s%s%s\n",
	     ndev->flags & IFF_UP ? "UP " : "",
	     ndev->flags & IFF_BROADCAST ? "BROADCAST " : "",
	     ndev->flags & IFF_DEBUG ? "DEBUG " : "",
	     ndev->flags & IFF_RUNNING ? "RUNNING " : "",
	     ndev->flags & IFF_NOARP ? "NOARP " : "",
	     ndev->flags & IFF_PROMISC ? "PROMISC " : "",
	     ndev->flags & IFF_ALLMULTI ? "ALLMULTI " : "",
	     ndev->flags & IFF_MULTICAST ? "MULTICAST " : "",
	     ndev->flags & IFF_DYNAMIC ? "DYNAMIC " : "");

	/* Disable/enable DMAC filter based on IFF_PROMISC bit. */
	eal_cfg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_FILTER_CFG);
	EAL_CFG_SET_FILTER_UNKNOWN_DMAC(eal_cfg, ndev->flags & IFF_PROMISC ? 0 : 1);
	hfi2_write_csr(edev->ppd->dd, CYR_EAL_FILTER_CFG, eal_cfg);
}

/**
 * cne_set_mac_address - update the MAC address
 * @ndev: network device
 * @p: sockaddr structure holding the desired MAC address
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_set_mac_address(struct net_device *ndev,
			       void *p)
{
	int vf = 0;
	u64 dmac_reg;
	u8 *mac = ((struct sockaddr *)p)->sa_data;
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;

	pinfo(edev, drv, "MAC addr %pM\n", mac);

	if (!is_valid_ether_addr(mac))
		return -EADDRNOTAVAIL;

	/* If VF attempting to change MAC check with PF first. */
	if (dd->is_vf) {
		int rc;
		u8 pf_set_mac;
		u64 smac_reg;
		struct ifla_vf_info ivf;
		struct hfi2_devrsrcs *pdr = &dd->rsrcs;

		vf = pdr->si_idx;

		rc = vf2pf_get_eth_config(dd, vf - 1, &ivf, &pf_set_mac);
		if (rc)
			return rc;

		if (pf_set_mac && !ivf.trusted && !ether_addr_equal(mac, ivf.mac)) {
			netdev_warn(ndev, "Untrusted VF attempted to change PF-assigned MAC!\n");
			return -EPERM;
		}

		if (pf_set_mac && ivf.trusted)
			netdev_warn(ndev, "Trusted VF overriding PF-assigned MAC.\n");

		/* Write MAC into the EAL_PF_SMAC_FILTER CSR */
		smac_reg = hfi2_read_csr(dd, CYR_EAL_PF_SMAC_FILTER + (8 * vf));
		EAL_PF_SMAC_SET_ADDR(smac_reg, ether_addr_to_u64(mac));
		EAL_PF_SMAC_SET_VALID(smac_reg, !!ivf.spoofchk);
		hfi2_write_csr(dd, CYR_EAL_PF_SMAC_FILTER + (8 * vf), smac_reg);
	}

	/* Write the MAC into the EAL_PF_DMAC_ADDRESS CSR. */
	dmac_reg = hfi2_read_csr(dd, CYR_EAL_PF_DMAC_ADDRESS + (8 * vf));
	EAL_PF_DMAC_SET_ADDR(dmac_reg, ether_addr_to_u64(mac));
	EAL_PF_DMAC_SET_FILTER(dmac_reg, 0);
	EAL_PF_DMAC_SET_VALID(dmac_reg, 1);
	EAL_PF_DMAC_SET_MASK(dmac_reg, 0);
	hfi2_write_csr(dd, CYR_EAL_PF_DMAC_ADDRESS + (8 * vf), dmac_reg);

	eth_hw_addr_set(ndev, mac);

	return 0;
}

/**
 * cne_stop - called when network interface going down
 * @ndev: network interface device
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_stop(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	pinfo(edev, ifdown, "Stopping ...\n");

	WRITE_ONCE(edev->tx_enabled, false);
	synchronize_net();

	if (!netif_device_present(ndev) && !ndev->dismantle)
		goto out;

	/*
	 * Stop the stack first, then let in-flight SDMA requests complete
	 * before the send contexts go away; cne_open() resets BQL and must
	 * not see completions from before the stop.
	 */
	netif_tx_disable(ndev);
	netif_carrier_off(ndev);
	cne_disable_rxqs(edev);
	cne_drain_txqs(edev);
	cne_disable_txqs(edev);
	synchronize_net();

out:
	return 0;
}

/**
 * cne_tx_timeout - handle transmit hang
 * @ndev: network device
 * @queue: hung Tx queue
 */
static void cne_tx_timeout(struct net_device *ndev,
			   unsigned int queue)
{
	struct ether_device *edev = netdev_priv(ndev);

	pinfo(edev, timer, "timeout queue (%u)\n", queue);
	cne_tx_timeout_recover(ndev, queue);
}

/**
 * cne_vlan_rx_add_vid - add VLAN ID
 * @ndev: network device
 * @proto: protocol
 * @vid: VLAN ID
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_vlan_rx_add_vid(struct net_device *ndev,
			       __be16 proto,
				u16 vid)
{
	struct ether_device *edev = netdev_priv(ndev);
	u16 proto_host = be16_to_cpu(proto);

	pinfo(edev, drv, "adding vid %u proto 0x%x\n", vid, proto_host);

	/* EAL treats a VID 0 priority tag as untagged; keep both filter slots. */
	if (!vid)
		return 0;

	if (proto_host == ETH_P_8021Q || proto_host == ETH_P_8021AD) {
		u64 cfg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_VLAN_CFG);

		if (!EAL_VLAN_CFG_GET_VID_VALID(cfg)) {
			/* use first VID entry */
			EAL_VLAN_CFG_SET_VID(cfg, vid);
			EAL_VLAN_CFG_SET_VID_VALID(cfg, 1);
		} else if (!EAL_VLAN_CFG_GET_VID2_VALID(cfg)) {
			/* use second VID entry */
			EAL_VLAN_CFG_SET_VID2(cfg, vid);
			EAL_VLAN_CFG_SET_VID2_VALID(cfg, 1);
		} else {
			/* too many VLANs */
			pwarn(edev, drv, "Too many VLANs\n");
			return -ENOSPC;
		}
		hfi2_write_csr(edev->ppd->dd, CYR_EAL_VLAN_CFG, cfg);
	} else {
		netdev_err(ndev, "Unsupported protocol 0x%x\n", proto_host);
		return -EOPNOTSUPP;
	}

	return 0;
}

/**
 * cne_vlan_rx_kill_vid - remove VLAN ID
 * @ndev: network device
 * @proto: protocol
 * @vid: VLAN ID
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_vlan_rx_kill_vid(struct net_device *ndev,
				__be16 proto,
				u16 vid)
{
	struct ether_device *edev = netdev_priv(ndev);
	u16 proto_host = be16_to_cpu(proto);

	pinfo(edev, drv, "removing vid %u proto 0x%x\n", vid, proto_host);

	if (!vid)
		return 0;

	if (proto_host == ETH_P_8021Q || proto_host == ETH_P_8021AD) {
		u64 cfg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_VLAN_CFG);

		if (EAL_VLAN_CFG_GET_VID_VALID(cfg) &&
		    EAL_VLAN_CFG_GET_VID(cfg) == vid) {
			EAL_VLAN_CFG_SET_VID_VALID(cfg, 0);
			EAL_VLAN_CFG_SET_VID(cfg, 0);
		} else if (EAL_VLAN_CFG_GET_VID2_VALID(cfg) &&
			EAL_VLAN_CFG_GET_VID2(cfg) == vid) {
			EAL_VLAN_CFG_SET_VID2_VALID(cfg, 0);
			EAL_VLAN_CFG_SET_VID2(cfg, 0);
		} else {
			 /* unknown VLAN */
			netdev_err(ndev, "Unknown VLAN %u\n", vid);
			return -EINVAL;
		}
		hfi2_write_csr(edev->ppd->dd, CYR_EAL_VLAN_CFG, cfg);
	} else if (proto_host != ETH_P_8021AD) {
		netdev_err(ndev, "Unsupported protocol 0x%x\n", proto_host);
		return -EOPNOTSUPP;
	}

	return 0;
}

/*
 * TX queue i uses SDMA engine i % num_sdes (see cne_alloc_txq), so queues share
 * an engine when num_txqs > num_sdes, and each engine's completion IRQ is pinned
 * to a specific CPU. netdev_pick_tx consults the XPS maps published in
 * cne_enable_txq: first the RX-queue map, which keeps a connected flow on one
 * of the TX queues assigned to the RX queue its ACKs arrive on regardless of
 * the sending CPU, then the CPU map, then the flow hash. The CPU map alone
 * does not preserve per-flow ordering; see cne_set_xps_rxqs().
 */
static u16 cne_select_queue(struct net_device *ndev, struct sk_buff *skb,
			    struct net_device *sb_dev)
{
	return netdev_pick_tx(ndev, skb, sb_dev);
}

static struct net_device_ops cn_ndev_ops = {
	.ndo_change_mtu = cne_change_mtu,
	.ndo_eth_ioctl = cne_eth_ioctl,
	.ndo_fix_features = cne_fix_features,
	.ndo_get_stats64 = cne_get_stats64,
	.ndo_open = cne_open,
	.ndo_select_queue = cne_select_queue,
	.ndo_set_mac_address = cne_set_mac_address,
	.ndo_set_rx_mode = cne_set_rx_mode,
	.ndo_get_vf_config = cne_get_vf_config,
	.ndo_set_vf_mac = cne_set_vf_mac,
	.ndo_set_vf_spoofchk = cne_set_vf_spoofchk,
	.ndo_set_vf_trust = cne_set_vf_trust,
	.ndo_set_vf_vlan = cne_set_vf_vlan,
	.ndo_start_xmit = cne_start_xmit,
	.ndo_stop = cne_stop,
	.ndo_tx_timeout = cne_tx_timeout,
	.ndo_validate_addr = eth_validate_addr,
};

/**
 * cne_max_txqs - max TX queues (channels) the port can support
 * @ppd: HFI port data
 * @ndev: the port's netdev, or NULL when sizing a new one at probe
 *
 * Each TX queue owns one SC_USER send context, so the ceiling is the
 * contexts the Ethernet device already holds plus those still free in the
 * pool.
 *
 * Used both to size the netdev at probe and to bound .set_channels;
 * caller must hold RTNL or be in probe.
 */
u32 cne_max_txqs(struct hfi2_pportdata *ppd, struct net_device *ndev)
{
	u32 n = sc_num_free(ppd->dd, SC_USER);

	if (ndev) {
		struct ether_device *edev = netdev_priv(ndev);

		n = min_t(u32, n + edev->num_txqs, ndev->num_tx_queues);
	}

	return min_t(u32, n, CN_MAX_QUEUES);
}

/**
 * cne_max_rxqs - max RX queues (channels) the port can support
 * @ppd: HFI port data
 *
 * RX queues map 1:1 onto the netdev receive contexts reserved at load time.
 * Used both to size the netdev at probe and to bound .set_channels.
 */
u32 cne_max_rxqs(struct hfi2_pportdata *ppd)
{
	return min_t(u32, CN_MAX_QUEUES, ppd->ppr->num_netdev_contexts);
}

/**
 * cne_probe - Initialize Ethernet device
 * @ppd: HFI port data
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_probe(struct hfi2_pportdata *ppd)
{
	int rc, i;
	u16 num_sde;
	u32 sc_free_cnt;
	struct net_device *ndev = NULL;
	struct ether_device *edev = NULL;
	u32 max_txqs = cne_max_txqs(ppd, NULL);
	u32 max_rxqs = cne_max_rxqs(ppd);
	struct hfi2_devrsrcs *pdr = &ppd->dd->rsrcs;
	int pf = pdr->pfunit;
	u16 sde_available = pdr->last_sdma_engine - pdr->first_sdma_engine;

	/*
	 * The probe runs before hfi2_bulksvc_loan_resources(), so
	 * last_sdma_engine still covers the engines bulksvc will take.
	 * Exclude them as hfi2_sdma_map_init() does.
	 */
	if (ppd->dd->bulksvc && !ppd->dd->bulksvc->rsrc.sde_arr)
		sde_available -= min_t(u16, sde_available,
				       ppd->dd->bulksvc->prereqs.num_sdma);

	/* Valid requested number of queues and SDMA engines */
	if (!num_txqs || num_txqs > ARRAY_SIZE(edev->txq)) {
		dd_dev_err(ppd->dd, "Invalid num_txqs (%u)\n", num_txqs);
		return -EINVAL;
	}
	/*
	 * Each TX queue takes an SC_USER send context.  The pool is shared
	 * with user contexts and may have been trimmed at init, so check
	 * what hfi2_sc_alloc() can actually hand out rather than the pool size.
	 */
	sc_free_cnt = sc_num_free(ppd->dd, SC_USER);
	if (num_txqs > sc_free_cnt) {
		dd_dev_err(ppd->dd,
			   "num_txqs (%u) exceeds %u free send contexts\n",
			   num_txqs, sc_free_cnt);
		return -ENOSPC;
	}
	if (num_sdes > sde_available) {
		dd_dev_err(ppd->dd,
			   "num_sdes (%u) exceeds %u available SDMA engines\n",
			   num_sdes, sde_available);
		return -EINVAL;
	}
	num_sde = hfi2_num_eth_tx_engines(sde_available);
	if (!num_sde) {
		dd_dev_err(ppd->dd, "No SDMA engines available for %u TX queues\n",
			   num_txqs);
		return -ENODEV;
	}
	if (!num_rxqs || num_rxqs > max_rxqs) {
		dd_dev_err(ppd->dd, "Invalid num_rxqs (%u).  Max possible is %u\n",
			   num_rxqs, max_rxqs);
		return -EINVAL;
	}

	/* Allocate network device. */
	ndev = alloc_etherdev_mqs(sizeof(*edev), max_txqs, max_rxqs);
	if (!ndev) {
		pr_err("Failure allocating net_device\n");
		return -ENOMEM;
	}
	edev = (struct ether_device *)netdev_priv(ndev);
	memset(edev, 0, sizeof(*edev));
	edev->ndev = ndev;
	edev->ppd = ppd;
	for (i = 0; i < CN_MAX_QUEUES; i++) {
		u64_stats_init(&edev->txq_stats[i].syncp);
		u64_stats_init(&edev->rxq_stats[i].syncp);
	}
	u64_stats_init(&edev->ulp_rx_stats.syncp);
	edev->pdev = edev->ppd->dd->pcidev;
	SET_NETDEV_DEV(ndev, &edev->pdev->dev);
	edev->msg_enable = netif_msg_init(debug, NETIF_MSG_DRV | NETIF_MSG_PROBE |
					 NETIF_MSG_LINK);
	edev->num_sdes = num_sde;
	edev->first_sde = pdr->first_sdma_engine;

	/* Initialize the network device. */
	if (ppd->dd->is_vf)
		snprintf(ndev->name, sizeof(ndev->name), "%s%uv%u", CNE_IFNAME, pf,
			 pdr->si_idx - 1);
	else
		snprintf(ndev->name, sizeof(ndev->name), "%s%u", CNE_IFNAME, pf);
	ndev->netdev_ops = &cn_ndev_ops;
	ndev->watchdog_timeo = 8 * HZ;
	ndev->hw_features = NETIF_F_SG | NETIF_F_GRO | NETIF_F_RXCSUM;
	ndev->features |= ndev->hw_features | NETIF_F_HIGHDMA;
	ndev->vlan_features |= ndev->features;
	ndev->priv_flags &= ~IFF_TX_SKB_SHARING;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = cne_rx_buf_max_mtu();
	/* Room for the 16B header and a PFC priority tag (cne_start_xmit()). */
	ndev->needed_headroom = LRH_16B_BYTES + VLAN_HLEN;
	cne_init_ethtool(ndev);

	/* The EAL pause CSRs are port-wide and owned by the PF. */
	if (!ppd->dd->is_vf)
		cne_dcb_set_defaults(ndev);

	if (max_vlans <= 2) {
		/* The HW can only manage 2 VLANs.  If 2 are all that
		 * is needed then the HW can filter incoming frames.
		 */
		cn_ndev_ops.ndo_vlan_rx_add_vid = cne_vlan_rx_add_vid;
		cn_ndev_ops.ndo_vlan_rx_kill_vid = cne_vlan_rx_kill_vid;
		ndev->features |= NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER;
	}

	cne_dcb_init(ndev);

	/* Allocate Rx and Tx queues. */
	rc = cne_alloc_rxqs(edev, num_rxqs);
	if (rc < 0) {
		netdev_err(ndev, "Failure allocating RX queues. rc %d\n", rc);
		goto free_netdev;
	}
	cne_rmon_init(edev);
	rc = cne_alloc_txqs(edev, num_txqs);
	if (rc < 0) {
		netdev_err(ndev, "Failure allocating TX queues. rc %d\n", rc);
		goto free_rxqs;
	}

	if (!ppd->dd->is_vf) {
		u64 mac_addr = 0;
		struct sockaddr saddr = {0};

		rc = cport_get_mac(ppd->dd, &mac_addr);
		u64_to_ether_addr(mac_addr, saddr.sa_data);
		if (rc || !is_valid_ether_addr(saddr.sa_data)) {
			/* generate a MAC from the hostname */
			char *nodename = utsname()->nodename;
			u32 hash = jhash(nodename, strlen(nodename), 0);
			u8 *p = (u8 *)&hash;

			if (!rc)
				dd_dev_info(ppd->dd, "Generating a valid MAC address.");

			saddr.sa_data[0] = 0xd0;
			saddr.sa_data[1] = 0x06;
			saddr.sa_data[2] = 0x6a;
			saddr.sa_data[3] = p[2];
			saddr.sa_data[4] = p[1];
			saddr.sa_data[5] = (p[0] & 0xfe) + pf;
		}
		rc = cne_set_mac_address(ndev, &saddr);
		if (rc) {
			netdev_err(ndev, "Failed to set MAC address (%d)\n", rc);
			goto free_txqs;
		}
	}

	/* Initialize the MAC filter.*/
	cne_set_rx_mode(ndev);

	rc = cne_program_mtu(edev, ndev->mtu);
	if (rc)
		goto free_txqs;

	/* Register network device. */
	rc = register_netdev(ndev);
	if (rc) {
		netdev_err(ndev, "Failure registering net_device, rc=%d\n", rc);
		goto free_txqs;
	}

	netif_carrier_off(ndev);

	if (!ppd->dd->is_vf) {
		rc = cne_enable_sriov(edev, pci_num_vf(edev->pdev), false);
		if (rc)
			goto unregister_ndev;
#ifdef CONFIG_PTP_1588_CLOCK
		cne_ptp_init(edev);
#endif
		cne_rmon_start(edev);
	}

	/* Save network device pointer */
	ppd->ndev = ndev;
	rcu_assign_pointer(ppd->ulp_ndev, ndev);

	return rc;

unregister_ndev:
	unregister_netdev(ndev);

free_txqs:
	cne_free_txqs(edev);

free_rxqs:
	cne_free_rxqs(edev);

free_netdev:
	free_netdev(ndev);

	return rc;
}

/**
 * cne_remove - Remove network device
 * @ndev: Ethernet net_device to remove
 */
void cne_remove(struct net_device *ndev)
{
	struct ether_device *edev = netdev_priv(ndev);

	/* Drain ULP RX readers before unregistering flushes the backlog. */
	RCU_INIT_POINTER(edev->ppd->ulp_ndev, NULL);
	synchronize_rcu();
	unregister_netdev(ndev);
	WRITE_ONCE(edev->ppd->roce_pfc_prio, 0);
	WRITE_ONCE(edev->ppd->roce_pfc_on, false);
#ifdef CONFIG_PTP_1588_CLOCK
	cne_ptp_stop(edev);
#endif
	cne_destroy_ethtool(ndev);

	cne_disable_rxqs(edev);
	cne_free_rxqs(edev);
	cne_disable_txqs(edev);
	cne_free_txqs(edev);
	free_netdev(ndev);
}
