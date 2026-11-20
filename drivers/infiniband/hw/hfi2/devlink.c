// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/netlink.h>
#include <net/devlink.h>

#include "hfi2.h"
#include "bulksvc.h"
#include "devlink.h"
#include "pldm_devlink.h"

/*
 * Per-function devlink instance.
 *
 * Every PCIe function gets one, whatever features it supports, so that
 * any feature needing devlink can hang off the same instance.  Each devlink
 * operation is routed to the feature that implements it; an operation with
 * no backing feature on this device reports that it is unsupported.
 *
 * A card has one CPORT and one SPI flash regardless of how many PCIe
 * functions it exposes, so card-wide state belongs to one nominated function.
 * The helpers below identify it.
 */

/* how often to repeat the message while removal waits on an operation */
#define HFI2_DEVLINK_WAIT_LOG_INTERVAL	(30 * HZ)
#define HFI2_DEVLINK_WAIT_POLL_MS	100

/**
 * struct hfi2_devlink - devlink private data
 * @dd: the device this instance belongs to
 */
struct hfi2_devlink {
	struct hfi2_devdata *dd;
};

/**
 * hfi2_devlink_is_canonical - does this function own card-wide state?
 * @dd: the device
 *
 * A CN6000 presents two PCIe functions of one device that share one CPORT
 * and one flash.  Physical function 0 is nominated so that two functions
 * cannot act on the same hardware at once.  Every other supported card has
 * a single physical function per device and so is always function 0; a VF
 * never owns card-wide state even if it is function 0 on a virtual bus.
 *
 * This goes by the PCI function rather than dd->hfi2_id or dd->asic_data:
 * asic_data is only set up for WFR, and hfi2_id means the ASIC on a
 * two-ASIC WFR board, not the function.
 *
 * Return: true for the nominated function.
 */
bool hfi2_devlink_is_canonical(struct hfi2_devdata *dd)
{
	return !dd->is_vf && PCI_FUNC(dd->pcidev->devfn) == 0;
}

/**
 * hfi2_devlink_canonical_name - name the function that owns card-wide state
 * @dd: the device
 * @buf: filled with the owning function's PCI name
 * @len: size of @buf
 *
 * The owner is function 0 of the same device, so its name follows from our
 * own PCI address.  Nothing is looked up, so there is nothing to race with
 * the owner being removed.
 */
void hfi2_devlink_canonical_name(struct hfi2_devdata *dd, char *buf, size_t len)
{
	struct pci_dev *pdev = dd->pcidev;

	snprintf(buf, len, "%04x:%02x:%02x.0", pci_domain_nr(pdev->bus),
		 pdev->bus->number, PCI_SLOT(pdev->devfn));
}

static int hfi2_devlink_info_get(struct devlink *devlink,
				 struct devlink_info_req *req,
				 struct netlink_ext_ack *extack)
{
	struct hfi2_devlink *priv = devlink_priv(devlink);
	struct hfi2_devdata *dd = priv->dd;
	int ret;

	if (!dd->is_vf) {
		ret = hfi2_pldm_info_get(dd, req, extack);
		if (ret)
			return ret;
	}

	if (dd->bulksvc && hfi2_bulksvc_is_opa(dd->bulksvc)) {
		char buf[32];

		snprintf(buf, sizeof(buf), "%u.%u",
			 HFI2_BULKSVC_VERSION_MAJOR,
			 HFI2_BULKSVC_VERSION_MINOR);
		ret = devlink_info_version_running_put(req, "bulksvc.api", buf);
		if (ret)
			return ret;

		snprintf(buf, sizeof(buf), "0x%llx", hfi2_bulksvc_get_caps());
		ret = devlink_info_version_running_put(req, "bulksvc.caps",
						       buf);
		if (ret)
			return ret;
	}

	return 0;
}

static int hfi2_devlink_flash_update(struct devlink *devlink,
				     struct devlink_flash_update_params *params,
				     struct netlink_ext_ack *extack)
{
	struct hfi2_devlink *priv = devlink_priv(devlink);

	return hfi2_pldm_flash_update(priv->dd, devlink, params, extack);
}

static const struct devlink_ops hfi2_devlink_ops = {
	.info_get = hfi2_devlink_info_get,
	.flash_update = hfi2_devlink_flash_update,
};

static const struct devlink_ops hfi2_devlink_vf_ops = {
	.info_get = hfi2_devlink_info_get,
};

/**
 * hfi2_devlink_register - create this device's devlink instance
 * @dd: the device
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int hfi2_devlink_register(struct hfi2_devdata *dd)
{
	const struct devlink_ops *ops = dd->is_vf ? &hfi2_devlink_vf_ops :
						    &hfi2_devlink_ops;
	struct hfi2_devlink *priv;
	struct devlink *devlink;

	devlink = devlink_alloc(ops, sizeof(*priv), &dd->pcidev->dev);
	if (!devlink)
		return -ENOMEM;

	priv = devlink_priv(devlink);
	priv->dd = dd;
	dd->devlink = devlink;

	devlink_register(devlink);
	return 0;
}

/**
 * hfi2_devlink_unregister - tear down this device's devlink instance
 * @dd: the device
 *
 * Must run before any feature behind the instance goes away, so that no
 * operation can start against a device that is being removed.
 *
 * Unregistering takes the instance lock, which a firmware flash holds for
 * its whole duration.  Rather than block silently, poll for the lock and say
 * what removal is waiting for.  The wait is deliberately not abandoned: the
 * flash must finish before the device it is writing goes away.
 */
void hfi2_devlink_unregister(struct hfi2_devdata *dd)
{
	struct devlink *devlink = dd->devlink;
	unsigned long next_log = jiffies;

	if (!devlink)
		return;

	while (!devl_trylock(devlink)) {
		if (time_after_eq(jiffies, next_log)) {
			dd_dev_info(dd, "devlink: waiting for the running operation, such as a firmware update, to finish\n");
			next_log = jiffies + HFI2_DEVLINK_WAIT_LOG_INTERVAL;
		}
		msleep(HFI2_DEVLINK_WAIT_POLL_MS);
	}
	devl_unregister(devlink);
	devl_unlock(devlink);

	devlink_free(devlink);
	dd->devlink = NULL;
}
