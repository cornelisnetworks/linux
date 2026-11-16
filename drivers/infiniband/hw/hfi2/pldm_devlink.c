// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#include <linux/firmware.h>
#include <linux/netlink.h>
#include <net/devlink.h>

#include "hfi2.h"
#include "cport.h"
#include "devlink.h"
#include "pldm_devlink.h"
#include "pldm_ua.h"

/*
 * PLDM firmware update and version reporting behind the devlink instance.
 *
 * This is what makes "devlink dev flash" and "devlink dev info" work on an
 * HFI.  It matters most in CN6000 Ethernet mode, where there is no QP0 and
 * therefore no OPA MAD transport for the userspace updateAgent to use; there,
 * devlink is the only way to update firmware locally.  In OPA mode both paths
 * work and the userspace agent is unaffected.
 *
 * The instance itself belongs to devlink.c.  Firmware is card-wide, so only
 * the canonical function talks to the firmware device; the other reports
 * which BDF to use.
 */

/* Version names reported by devlink dev info. */
#define HFI2_INFO_VERSION_CPORT		"fw.mgmt"
#define HFI2_INFO_VERSION_UEFI		"fw.undi"
#define HFI2_INFO_VERSION_PCIE_CFG	"fw.pcie_cfg"
#define HFI2_INFO_VERSION_ASIC_CFG	"fw.asic_cfg"
#define HFI2_INFO_VERSION_BUNDLE	"fw.bundle_id"

/*
 * Component identifiers from the package, used to give each component a
 * stable devlink version name rather than a numbered one.
 */
#define HFI2_COMPONENT_UEFI		0x0201
#define HFI2_COMPONENT_CPORT		0x0202
#define HFI2_COMPONENT_PCIE_CFG		0x0203
#define HFI2_COMPONENT_ASIC_CFG		0x0204

/* Map a component identifier to the version name devlink reports. */
static const char *hfi2_devlink_version_name(u16 identifier)
{
	switch (identifier) {
	case HFI2_COMPONENT_UEFI:
		return HFI2_INFO_VERSION_UEFI;
	case HFI2_COMPONENT_CPORT:
		return HFI2_INFO_VERSION_CPORT;
	case HFI2_COMPONENT_PCIE_CFG:
		return HFI2_INFO_VERSION_PCIE_CFG;
	case HFI2_COMPONENT_ASIC_CFG:
		return HFI2_INFO_VERSION_ASIC_CFG;
	default:
		return NULL;
	}
}

/*
 * Report the CPORT firmware version the driver already learned at probe.
 *
 * This is the fallback when the firmware device cannot be queried, and it is
 * always available because the version arrives in the WHO response during
 * init rather than over the PLDM path.
 */
static int hfi2_devlink_info_cached(struct hfi2_devdata *dd,
				    struct devlink_info_req *req)
{
	char buf[32];
	union cport_fw_ver ver;

	ver.vers = dd->cport_ver;
	if (!ver.vers)
		return 0;

	snprintf(buf, sizeof(buf), "%u.%u.%u.%u.%u",
		 ver.maj, ver.min, ver.mnt, ver.pat, ver.bld);

	return devlink_info_version_running_put(req, HFI2_INFO_VERSION_CPORT, buf);
}

/**
 * hfi2_pldm_info_get - report firmware versions
 * @dd: the device
 * @req: the reply being built
 * @extack: netlink error reporting
 *
 * Asks the firmware device what it is running, which gives a per-component
 * answer including anything staged but not yet activated.  If that query
 * cannot be made, for instance because an update is in progress, fall back to
 * the CPORT version the driver learned at probe so the command still returns
 * something truthful.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int hfi2_pldm_info_get(struct hfi2_devdata *dd, struct devlink_info_req *req,
		       struct netlink_ext_ack *extack)
{
	struct pldm_ua_component_param *cp;
	struct pldm_ua_params params = {};
	int ret = 0;

	/*
	 * Only the canonical function talks to the firmware device.  The two
	 * functions have separate update locks, so letting both query would
	 * let this one start a conversation while the other is mid-flash, and
	 * the device answers one conversation at a time.  The cached CPORT
	 * version needs no such conversation.
	 */
	if (!hfi2_devlink_is_canonical(dd))
		return hfi2_devlink_info_cached(dd, req);

	ret = pldm_ua_get_params(dd, &params);
	if (ret) {
		dd_dev_dbg(dd, "PLDM: version query failed (%d), reporting the cached CPORT version\n",
			   ret);
		return hfi2_devlink_info_cached(dd, req);
	}

	/*
	 * The image set version covers the package as a whole, which is what
	 * an operator compares against a release.
	 */
	if (params.active_image_set_ver[0]) {
		ret = devlink_info_version_running_put(req, HFI2_INFO_VERSION_BUNDLE,
						       params.active_image_set_ver);
		if (ret)
			goto out;
	}

	list_for_each_entry(cp, &params.components, list) {
		const char *name = hfi2_devlink_version_name(cp->identifier);

		if (!name)
			continue;

		if (cp->active_ver_string[0]) {
			ret = devlink_info_version_running_put(req, name,
							       cp->active_ver_string);
			if (ret)
				goto out;
		}

		/*
		 * A pending version is an image already written to flash that
		 * needs a reset to take effect.
		 */
		if (cp->pending_ver_string[0]) {
			ret = devlink_info_version_stored_put(req, name,
							      cp->pending_ver_string);
			if (ret)
				goto out;
		}
	}

out:
	pldm_ua_free_params(&params);
	return ret;
}

/**
 * hfi2_pldm_flash_update - write a firmware package to the card
 * @dd: the device
 * @devlink: the devlink instance, for progress reporting
 * @params: the update request, including the package
 * @extack: netlink error reporting
 *
 * Context: holds the devlink instance lock for the whole update, which runs
 * for minutes.  That is the established pattern for this callback; ice waits
 * up to 300 seconds for a single flash erase under the same lock.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int hfi2_pldm_flash_update(struct hfi2_devdata *dd, struct devlink *devlink,
			   struct devlink_flash_update_params *params,
			   struct netlink_ext_ack *extack)
{
	int ret;

	/* No CPORT means no firmware device to talk to. */
	if (!dd->pldm_ua) {
		NL_SET_ERR_MSG_MOD(extack,
				   "firmware update is not supported on this device");
		return -EOPNOTSUPP;
	}

	/*
	 * Both functions on a card share one flash.  Only the canonical one
	 * updates it; tell the user where to go rather than silently doing
	 * nothing or, worse, flashing twice.
	 */
	if (!hfi2_devlink_is_canonical(dd)) {
		char name[32];

		hfi2_devlink_canonical_name(dd, name, sizeof(name));
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "this function shares its flash with %s; update that one instead",
				       name);
		return -EOPNOTSUPP;
	}

	/* Selective component update is not implemented yet. */
	if (params->component) {
		NL_SET_ERR_MSG_MOD(extack,
				   "component selection is not supported; the whole package is written");
		return -EOPNOTSUPP;
	}

	devlink_flash_update_status_notify(devlink, "Preparing to flash", NULL, 0, 0);

	ret = pldm_ua_flash(dd, devlink, params->fw, extack);
	if (ret) {
		devlink_flash_update_status_notify(devlink, "Flash failed", NULL, 0, 0);
		return ret;
	}

	/*
	 * The images are written and marked for the next boot, but the card
	 * boots from the active bank until it is power cycled.  A warm reboot
	 * is not enough.
	 */
	devlink_flash_update_status_notify(devlink,
					   "Flash complete; power cycle the chassis to activate",
					   NULL, 0, 0);
	return 0;
}
