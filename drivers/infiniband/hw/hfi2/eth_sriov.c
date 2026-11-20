// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * SRIOV functions
 */

#include "eth_main.h"
#include "vf2pf.h"

/**
 * cne_sriov_reinit -
 * @edev: ethernet device
 *
 * Returns 0 on success.
 */
static int cne_sriov_reinit(struct ether_device *edev)
{
	struct net_device *ndev = edev->ndev;
	bool running;
	int rc = 0;

	rtnl_lock();
	running = netif_running(ndev);

	if (running)
		cne_stop(ndev);

	if (running)
		rc = cne_open(ndev);

	rtnl_unlock();

	return rc;
}

/**
 * cne_enable_sriov - configure SR-IOV
 * @edev: ethernet device
 * @num_vfs: number of Virtual Functions
 * @reinit: if true reinitialize the HW/SW
 *
 * Returns 0 on success, -errno otherwise.
 */
int cne_enable_sriov(struct ether_device *edev,
		     int num_vfs,
		     bool reinit)
{
	int rc = 0;

	if (num_vfs > ARRAY_SIZE(edev->vf))
		return -EPERM;
	if (!num_vfs)
		return 0;

	if (reinit) {
		rc = cne_sriov_reinit(edev);
		if (rc)
			goto out;
	}

	edev->num_vfs = num_vfs;
out:
	return rc;
}

/**
 * cne_get_vf_config - get virtual function info
 * @ndev: network device
 * @vf: virtual function index
 *
 * Return: Zero on success, -ERRNO otherwise.
 */
int cne_get_vf_config(struct net_device *ndev,
		      int vf,
		      struct ifla_vf_info *ivf)
{
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;

	if (vf >= pdr->num_vfs) {
		netdev_err(ndev, "Invalid VF %u >= %u\n", vf, pdr->num_vfs);
		return -EINVAL;
	}

	ivf->vf = vf;
	ether_addr_copy(ivf->mac, edev->vf[vf].mac);
	ivf->vlan = edev->vf[vf].vid;
	ivf->qos = edev->vf[vf].qos;
	ivf->spoofchk = edev->vf[vf].spoofchk;
	ivf->trusted = edev->vf[vf].trusted;

	return 0;
}

/**
 * cne_write_vf_filters - set DMAC and SMAC registers
 * @edev: ethernet device
 * @vf: virtual fn index
 */
static void cne_write_vf_filters(struct ether_device *edev,
				 int vf)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	const u8 *mac = edev->vf[vf].mac;
	u64 smac_reg;

	cne_write_dmac(dd, vf + 1, mac);

	smac_reg = hfi2_read_csr(dd, CYR_EAL_PF_SMAC_FILTER + 8 * (vf + 1));
	EAL_PF_SMAC_SET_ADDR(smac_reg, ether_addr_to_u64(mac));
	EAL_PF_SMAC_SET_VALID(smac_reg, edev->vf[vf].spoofchk ? 1 : 0);
	hfi2_write_csr(dd, CYR_EAL_PF_SMAC_FILTER + 8 * (vf + 1), smac_reg);
}

/**
 * cne_write_vf_spoofchk - set the SMAC valid bit from the spoof check state
 * @edev: ethernet device
 * @vf: virtual fn index
 *
 * Keep the address in the entry.  It may be a MAC that the VF set on its
 * own, which the PF does not know.
 */
static void cne_write_vf_spoofchk(struct ether_device *edev,
				  int vf)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	u64 smac_reg;

	smac_reg = hfi2_read_csr(dd, CYR_EAL_PF_SMAC_FILTER + 8 * (vf + 1));
	EAL_PF_SMAC_SET_VALID(smac_reg, edev->vf[vf].spoofchk ? 1 : 0);
	hfi2_write_csr(dd, CYR_EAL_PF_SMAC_FILTER + 8 * (vf + 1), smac_reg);
}

/**
 * cne_set_vf_mac - set virtual function MAC address
 * @ndev: network device
 * @vf: virtual function index
 * @mac: MAC address value
 *
 * Return: Zero on success, -ERRNO otherwise
 */
int cne_set_vf_mac(struct net_device *ndev,
		   int vf,
		   u8 *mac)
{
	int rc;
	struct ifla_vf_info ivf;
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;

	if (vf >= pdr->num_vfs) {
		netdev_err(ndev, "Invalid VF %u >= %u\n", vf, pdr->num_vfs);
		return -EINVAL;
	}

	if (!is_valid_ether_addr(mac) && !is_zero_ether_addr(mac)) {
		netdev_err(ndev, "Invalid MAC %pM\n", mac);
		return -EINVAL;
	}

	if (dd->is_vf) {
		u8 pf_set_mac;

		rc = vf2pf_get_eth_config(dd, vf, &ivf, &pf_set_mac);
		if (rc)
			return rc;

		if (pf_set_mac && !ivf.trusted) {
			netdev_warn(ndev, "Untrusted VF attempted to change PF-assigned MAC!\n");
			return -EPERM;
		}

		if (pf_set_mac && ivf.trusted)
			netdev_warn(ndev, "Trusted VF overriding PF-assigned MAC.\n");
	} else
		edev->vf[vf].pf_set_mac = !is_zero_ether_addr(mac);

	ether_addr_copy(edev->vf[vf].mac, mac);
	cne_write_vf_filters(edev, vf);

	return 0;
}

/**
 * cne_restore_vf_filters - restore the VF MAC filters set through the PF
 * @edev: Ethernet device
 *
 * Only the MACs assigned through the PF are known here.  A MAC that a VF
 * set on its own is not restored.
 *
 * A port reset clears the DMAC valid bit, and this driver writes every
 * DMAC entry with the bit set.  So if an entry is still valid, no reset
 * has happened since the last write, and the entry may hold the MAC that
 * a trusted VF set over the PF-assigned one.  Leave valid entries alone,
 * e.g. when only the PF is reopened, and replay only the cleared ones.
 *
 * Spoof checking can be set on a VF that has no PF-assigned MAC.  There
 * is no DMAC to replay for such a VF, but the SMAC valid bit still has to
 * be, as cne_set_vf_spoofchk() wrote it.
 */
void cne_restore_vf_filters(struct ether_device *edev)
{
	struct hfi2_devdata *dd = edev->ppd->dd;
	unsigned int num_vfs = min_t(unsigned int, dd->rsrcs.num_vfs,
				     ARRAY_SIZE(edev->vf));

	for (unsigned int vf = 0; vf < num_vfs; vf++) {
		u64 dmac_reg;

		dmac_reg = hfi2_read_csr(dd, CYR_EAL_PF_DMAC_ADDRESS + 8 * (vf + 1));
		if (EAL_PF_DMAC_GET_VALID(dmac_reg))
			continue;

		if (is_zero_ether_addr(edev->vf[vf].mac))
			cne_write_vf_spoofchk(edev, vf);
		else
			cne_write_vf_filters(edev, vf);
	}
}

/**
 * cne_set_vf_spoofchk - set VF spoof check state
 * @ndev: network device
 * @vf: virtual function index
 * @setting: true to enable spoof checking
 *
 * Return: Zero on success, -ERRNO otherwise
 */
int cne_set_vf_spoofchk(struct net_device *ndev,
			int vf,
			bool setting)
{
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;

	if (vf >= pdr->num_vfs) {
		netdev_err(ndev, "Invalid VF %u >= %u\n", vf, pdr->num_vfs);
		return -EINVAL;
	}

	edev->vf[vf].spoofchk = setting;
	cne_write_vf_spoofchk(edev, vf);

	return 0;
}

/**
 * cne_set_vf_trust -
 * @ndev: network device
 * @vf: virtual function index
 * @setting:
 *
 * Return: Zero on success, -ERRNO otherwise
 */
int cne_set_vf_trust(struct net_device *ndev,
		     int vf,
		     bool setting)
{
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;

	if (vf >= pdr->num_vfs) {
		netdev_err(ndev, "Invalid VF %u >= %u\n", vf, pdr->num_vfs);
		return -EINVAL;
	}

	edev->vf[vf].trusted = setting;
	pinfo(edev, drv, "VF %u is %s trusted.\n", vf, setting ? "" : "not");

	return 0;
}

/**
 * cne_set_vf_vlan -
 * @ndev: network device
 * @vf: virtual function index
 * @vid: VLAN ID
 * @qos:
 * @proto: Ethernet protocol
 *
 * Return: Zero on success, -ERRNO otherwise.
 */
int cne_set_vf_vlan(struct net_device *ndev,
		    int vf,
		    u16 vid,
		    u8 qos,
		    __be16 proto)
{
	struct ether_device *edev = (struct ether_device *)netdev_priv(ndev);
	struct hfi2_devdata *dd = edev->ppd->dd;
	struct hfi2_devrsrcs *pdr = &dd->rsrcs;
	u16 proto_host = be16_to_cpu(proto);

	if (vf >= pdr->num_vfs) {
		netdev_err(ndev, "Invalid VF %u >= %u\n", vf, pdr->num_vfs);
		return -EINVAL;
	}

	if (vid > VLAN_N_VID - 1) {
		netdev_err(ndev, "Invalid VLAN ID (%u)\n", vid);
		return -EINVAL;
	}

	if (qos > 7) {
		netdev_err(ndev, "Invalid qos (%u)\n", qos);
		return -EINVAL;
	}

	if (proto_host != ETH_P_8021Q) {
		netdev_err(ndev, "Unsupported protocol 0x%x\n", proto_host);
		return -EPROTONOSUPPORT;
	}

	edev->vf[vf].vid = vid;
	edev->vf[vf].qos = qos;

	return 0;
}
