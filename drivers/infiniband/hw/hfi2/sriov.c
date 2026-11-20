// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 - Cornelis Networks, Inc.
 *
 * SR-IOV related functions and variables.
 */

#include <linux/pci.h>
#include <linux/string_choices.h>

#include "hfi2.h"
#include "sriov.h"
#include "chip_jkr.h"
#include "chip_gen.h"
#include "vf2pf.h"

/* PCIe r6.0: Device Control 2 bit 12, SR-IOV Capabilities bit 2, Control bit 5. */
#define HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ	0x1000
#define HFI2_PCI_SRIOV_CAP_VF_10BIT_TAG_REQ	0x00000004
#define HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ	0x0020

#define HFI_SRIOV_DEBUG
#define HFI_SRIOV_BRINGUP
#define HFI_SRIOV_MOD_PARAMS	/* use module params to define SRIOV config */
#undef HFI_SRIOV_AUTO_CONF	/* automatically enable SRIOV if max_num_vfs > 0 */

static bool sriov_auto; /* might default to 'true' in the future */

#ifdef HFI_SRIOV_BRINGUP
static bool vf_test;

static bool vf_claim;
#endif

#ifdef HFI_SRIOV_MOD_PARAMS
static uint si_idx;
static uint max_num_vfs;
static uint ctxt_per_vf; /* send/recv use same number */
static uint sdma_per_vf;
static uint rcv_per_vf;
static uint pio_per_vf;

/* all of these are fixed at driver load */

#endif

#define SI_PROBE_RETRY_INTERVAL_MS	500

static uint si_probe_retry_timeout_ms;

#define HFI_MIN_PF0_CONTEXTS	32	/* includes max used by CPORT */
#define HFI_MIN_PF0_SDE		2

/*
 * Only called on PF0, but possibly on behalf of VF.
 *
 * 'dd' is the PF0, 'out' is the target based on 'si'.
 * 'out' is assumed to be uninitialized.
 */
int hfi2_sriov_get_config(struct hfi2_devdata *dd, struct hfi2_devrsrcs *out, int si)
{
	u32 num_rctxt, num_sctxt, pf0_rctxts, pf0_sctxts;
	u32 rc_per_vf = 0;
	u32 sc_per_vf = 0;
	u32 vf2pf_ctxts;
	u32 num_sdma;
	u32 num_rcvary;
	u32 num_pio;
	int num_vfs = 0;
	int num;

#ifdef HFI_SRIOV_MOD_PARAMS
	num_vfs = max_num_vfs;
#endif
	/* TODO: other methods of SRIOV config... */

	if (!num_vfs)
		return -ENODEV;

	if (si > JKR_C_CCE_NUM_VFS || num_vfs > JKR_C_CCE_NUM_VFS)
		return -EINVAL;

#ifdef HFI_SRIOV_MOD_PARAMS
	/*
	 * Assumes #send contexts == #recv contexts, uses #recv
	 * as the limit since #send might be larger in the future.
	 */
	vf2pf_ctxts = vf2pf_num_ctxts(dd);
	num_rctxt = chip_rcv_contexts(dd) - vf2pf_ctxts;
	num_sctxt = chip_send_contexts(dd) - vf2pf_ctxts;
	num_sdma = chip_sdma_engines(dd);
	num_rcvary = chip_rcv_array_count(dd) - HFI_MIN_PF0_RCVARY(vf2pf_ctxts);
	num_pio = chip_pio_mem_size(dd) / PIO_BLOCK_SIZE - HFI_MIN_PF0_PIO(vf2pf_ctxts);

	/*
	 * Automatically adjust excessive values and set defaults for '0'.
	 * This may not work well if adapters of different architecture are
	 * installed (and having SRIOV capability).
	 */
	if (ctxt_per_vf)
		rc_per_vf = sc_per_vf = ctxt_per_vf;
	if (!rc_per_vf)
		rc_per_vf = (num_rctxt - HFI_MIN_PF0_CONTEXTS) / max_num_vfs;
	if (!sc_per_vf)
		sc_per_vf = (num_sctxt - HFI_MIN_PF0_CONTEXTS) / max_num_vfs;
	if (rc_per_vf * max_num_vfs > num_rctxt - HFI_MIN_PF0_CONTEXTS) {
		rc_per_vf = (num_rctxt - HFI_MIN_PF0_CONTEXTS) / max_num_vfs;
		dd_dev_info(dd, "Reducing rcv ctxt per vf to %d\n", rc_per_vf);
	}
	if (sc_per_vf * max_num_vfs > num_sctxt - HFI_MIN_PF0_CONTEXTS) {
		sc_per_vf = (num_sctxt - HFI_MIN_PF0_CONTEXTS) / max_num_vfs;
		dd_dev_info(dd, "Reducing snd ctxt per vf to %d\n", sc_per_vf);
	}
	pf0_rctxts = num_rctxt - rc_per_vf * max_num_vfs;
	pf0_sctxts = num_sctxt - sc_per_vf * max_num_vfs;

	if (!sdma_per_vf)
		sdma_per_vf = (num_sdma - HFI_MIN_PF0_SDE) / max_num_vfs;
	if (!rcv_per_vf)
		rcv_per_vf = (num_rcvary - HFI_MIN_PF0_RCVARY(pf0_rctxts)) / max_num_vfs;
	if (!pio_per_vf)
		pio_per_vf = (num_pio - HFI_MIN_PF0_PIO(pf0_sctxts)) / max_num_vfs;

	if (sdma_per_vf * max_num_vfs > num_sdma - HFI_MIN_PF0_SDE) {
		sdma_per_vf = (num_sdma - HFI_MIN_PF0_SDE) / max_num_vfs;
		dd_dev_info(dd, "Reducing sdma_per_vf to %d\n", sdma_per_vf);
	}
	if (rcv_per_vf * max_num_vfs > num_rcvary - HFI_MIN_PF0_RCVARY(pf0_rctxts)) {
		rcv_per_vf = (num_rcvary - HFI_MIN_PF0_RCVARY(pf0_rctxts)) / max_num_vfs;
		dd_dev_info(dd, "Reducing rcv_per_vf to %d\n", rcv_per_vf);
	}
	if (pio_per_vf * max_num_vfs > num_pio - HFI_MIN_PF0_PIO(pf0_sctxts)) {
		pio_per_vf = (num_pio - HFI_MIN_PF0_PIO(pf0_sctxts)) / max_num_vfs;
		dd_dev_info(dd, "Reducing pio_per_vf to %d\n", pio_per_vf);
	}

	out->num_vfs = max_num_vfs;
	out->si_idx = si;
	out->pfunit = dd->unit;
	/* si_idx == 0 implies PF0, which decides all VF resources */

	num = si ? si : max_num_vfs + 1; /* never 0 */
	out->c.first_send_context = si ? num_sctxt - num * sc_per_vf : 0;
	out->c.last_send_context = num_sctxt - (num - 1) * sc_per_vf;
	out->c.first_rcv_context = si ? num_rctxt - num * rc_per_vf : 0;
	out->c.last_rcv_context = num_rctxt - (num - 1) * rc_per_vf;
	out->first_sdma_engine = si ? num_sdma - num * sdma_per_vf : 0;
	out->last_sdma_engine = num_sdma - (num - 1) * sdma_per_vf;
	out->c.first_rcvarray_entry = si ? num_rcvary - num * rcv_per_vf : 0;
	out->c.last_rcvarray_entry = num_rcvary - (num - 1) * rcv_per_vf;
	out->c.first_pio_block = si ? num_pio - num * pio_per_vf : 0;
	out->c.last_pio_block = num_pio - (num - 1) * pio_per_vf;
#endif
	return 0;
}

/*
 * If SRIOV is allowed (max_num_vfs > 0) then divide up
 * resources according to heuristics or limits. The rest of the driver
 * init should use these parameters, if available (dd->rsrcs.num_vfs != 0).
 * Note that the driver can no longer assume a resource begins at "0".
 */
int hfi2_sriov_set_cfg(struct hfi2_devdata *dd)
{
	int ret;

	if (dd->params->chip_type == CHIP_WFR)
		return 0;
	/* prior call to hfi2_sriov_set_si() must have succeeded */
	if (dd->is_vf) {
		ret = vf2pf_get_config(dd, &dd->rsrcs, dd->rsrcs.si_idx);
		return ret;
	}
	if (!hfi2_sriov_is_enabled())
		return 0;

	ret = hfi2_sriov_get_config(dd, &dd->rsrcs, 0);
	return ret;
}

int hfi2_sriov_set_si(struct hfi2_devdata *dd)
{
	int si = 0; /* assume PF0 to start */
	unsigned long deadline;
	unsigned long timeout;

	if (!dd->is_vf)
		goto out_set;

	si = si_idx;
	if (!si) {
		if (dd->is_vm) {
			timeout = si_probe_retry_timeout_ms ? si_probe_retry_timeout_ms :
				2 * flr_interrupt_delay;

			/*
			 * It is possible that the PF0 driver is still in the middle of rebuilding
			 * a VF's loopback contexts after an FLR. Retry probing with a timeout in
			 * case a probe fails for this reason.
			 */
			deadline = jiffies + msecs_to_jiffies(timeout);
			do {
				si = vf2pf_probe_si(dd);
				if (si)
					break;
				msleep(SI_PROBE_RETRY_INTERVAL_MS);
			} while (time_before(jiffies, deadline));
		} else {
			/* TODO: need to adjust for CYR? does pci_iov already do that? */
			si = pci_iov_vf_id(dd->pcidev) + 1;
		}
	}
	if (!si) {
		dd_dev_err(dd, "Cannot determine device SI\n");
		return -ENXIO;
	}
out_set:
	dd->rsrcs.si_idx = si;
	return 0;
}

/*
 * Sets the SiIdx CSRs of contrexts and SDMA engines for
 * VF1..VFn based on data passed in 'dr'.
 *
 * Only PF0 can access the SiIdx CSRS, so any other callers
 * just return success.
 *
 * Called on behalf of a VF when it makes first contact with PF0.
 */
int hfi2_sriov_assign_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *dr)
{
	int x;

	if (dd->is_vf)
		return vf2pf_assign_rsrcs(dd, dr);

	/* Only valid on PF0, if SRIOV is allowed */
	if (!dd->rsrcs.num_vfs || dd->rsrcs.si_idx)
		return 0;

	/*
	 * In theory, resources allocated to PF0 never need to have their
	 * SiIdx written.
	 */
	if (!dr->si_idx)
		return 0;

	for (x = dr->c.first_send_context; x < dr->c.last_send_context; ++x)
		write_tctxt_csr(dd, x, JKR_SEND_CTXT_SI_IDX, dr->si_idx);
	for (x = dr->c.first_rcv_context; x < dr->c.last_rcv_context; ++x)
		write_rctxt_csr(dd, x, JKR_RCV_SI_IDX, dr->si_idx);
	for (x = dr->first_sdma_engine; x < dr->last_sdma_engine; ++x)
		write_sdmacfg_csr(dd, x, JKR_SEND_DMA_CFG_SI_IDX, dr->si_idx);
	return 0;
}

/*
 * Resets the SiIdx CSRs of contrexts and SDMA engines for
 * VF1..VFn back to PF0.
 *
 * Only PF0 can access the SiIdx CSRS, so any other callers
 * just return success.
 *
 * Called on behalf of a VF when it disconnects with PF0.
 */
void hfi2_sriov_free_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *dr)
{
	int x;

	if (dd->is_vf) {
		vf2pf_free_rsrcs(dd, dr);
		return;
	}
	/* Only valid on PF0, if SRIOV is allowed */
	if (!dd->rsrcs.num_vfs || dd->rsrcs.si_idx)
		return;

	/*
	 * In theory, resources allocated to PF0 never need to have their
	 * SiIdx written.
	 */
	if (!dr->si_idx)
		return;

	for (x = dr->c.first_send_context; x < dr->c.last_send_context; ++x)
		write_tctxt_csr(dd, x, JKR_SEND_CTXT_SI_IDX, 0);
	for (x = dr->c.first_rcv_context; x < dr->c.last_rcv_context; ++x)
		write_rctxt_csr(dd, x, JKR_RCV_SI_IDX, 0);
	for (x = dr->first_sdma_engine; x < dr->last_sdma_engine; ++x)
		write_sdmacfg_csr(dd, x, JKR_SEND_DMA_CFG_SI_IDX, 0);
}

/*
 * Free all SRIOV configuration resources. Called during
 * driver unload.
 *
 * Resets SiIdx CSRs as well as freeing memory.
 */
void hfi2_sriov_free_cfg(struct hfi2_devdata *dd)
{
	/* On PF0, set all SiIdx back to 0 */
	hfi2_sriov_free_rsrcs(dd, &dd->rsrcs);
}

/* NOTE:
 * There are three types of PCI devices when using SRIOV and VMs:
 *	in host OS, there is the PF0 pci_dev (pdev->is_physfn != 0)
 *	in host OS, there is the VFx pci_dev (pdev->is_virtfn != 0)
 *		(this will never have a 'dd'?)
 *	in guest OS, there is the VFx pci_dev (PCI_FUNC(pdev->devfn) != 0?)
 *		(what do pdev->is_physfn and pdev->is_virtfn mean?
 *		since pdev->physfn cannot be valid - nor pdev->sriov?)
 *		(this needs to have a 'dd' but handled different)
 *
 * TODO: how to determine whether we're host or guest?!
 *	PCI_FUNC(pdev->devfn) != 0 && !pdev->is_virtfn for guest VFs?
 *
 * TODO: does PCI_FUNC() need to be something different if ARI is active?
 */

int hfi2_sriov_is_enabled(void)
{
#ifdef HFI_SRIOV_MOD_PARAMS
	return max_num_vfs > 0;
#else
	/* TODO: how to determine SRIOV is allowed */
	return 0;
#endif
}

static bool tags_apply(struct pci_dev *pf)
{
	struct hfi2_devdata *dd = pci_get_drvdata(pf);

	return pf->is_physfn && dd && dd->params->chip_type == CHIP_CYR;
}

/*
 * Read the PF's Device Control 2 and its SR-IOV Capabilities and Control.
 * Returns -ENODEV without an SR-IOV capability, else a config access errno.
 */
static int read_pf_vf_tag_regs(struct pci_dev *pf, int *pos, u16 *devctl2, u32 *cap, u16 *ctrl)
{
	int ret;

	*pos = pci_find_ext_capability(pf, PCI_EXT_CAP_ID_SRIOV);
	if (!*pos)
		return -ENODEV;

	ret = pcie_capability_read_word(pf, PCI_EXP_DEVCTL2, devctl2);
	if (!ret)
		ret = pci_read_config_dword(pf, *pos + PCI_SRIOV_CAP, cap);
	if (!ret)
		ret = pci_read_config_word(pf, *pos + PCI_SRIOV_CTRL, ctrl);
	return pcibios_err_to_errno(ret);
}

void hfi2_sriov_tune_pf_tags(struct hfi2_devdata *dd)
{
	struct pci_dev *pf = dd->pcidev;
	u16 devctl2, ctrl;
	u32 cap;
	int pos, ret;

	if (dd->is_vf || !tags_apply(pf) || !hfi2_sriov_is_enabled())
		return;

	ret = read_pf_vf_tag_regs(pf, &pos, &devctl2, &cap, &ctrl);
	if (ret || !(devctl2 & HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ) ||
	    (cap & HFI2_PCI_SRIOV_CAP_VF_10BIT_TAG_REQ))
		return;

	ret = pcie_capability_clear_word(pf, PCI_EXP_DEVCTL2,
					 HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ);
	if (ret) {
		dd_dev_err(dd, "Unable to disable PF 10-bit tags: %d\n",
			   pcibios_err_to_errno(ret));
		return;
	}

	dd->pcie_devctl2 &= ~HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ;
	dd_dev_info(dd, "Disabled PF 10-bit tags: VFs do not support them\n");
	ret = pci_save_state(pf);
	if (ret)
		dd_dev_err(dd, "Unable to save PCI state: %d\n", ret);
}

/*
 * CN6000 SDMA can stall when the PF and VF tag widths differ, so keep them
 * equal. The PCI core never sets the VF tag bit, and it clears the bit
 * whenever it enables SR-IOV or restores SR-IOV state.
 */
void hfi2_sriov_align_vf_tags(struct pci_dev *pf)
{
	u16 devctl2, ctrl, actual;
	u32 cap;
	bool want;
	int pos, ret;

	if (!tags_apply(pf))
		return;

	ret = read_pf_vf_tag_regs(pf, &pos, &devctl2, &cap, &ctrl);
	if (ret == -ENODEV)
		return;
	if (ret)
		goto error;
	/* Nothing to align until VFs exist; enabling them rewrites this register. */
	if (!(ctrl & PCI_SRIOV_CTRL_VFE))
		return;

	want = (devctl2 & HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ) &&
		(cap & HFI2_PCI_SRIOV_CAP_VF_10BIT_TAG_REQ);
	if (!!(ctrl & HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ) == want)
		return;

	if (want)
		ctrl |= HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ;
	else
		ctrl &= ~HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ;
	ret = pci_write_config_word(pf, pos + PCI_SRIOV_CTRL, ctrl);
	if (!ret)
		ret = pci_read_config_word(pf, pos + PCI_SRIOV_CTRL, &actual);
	ret = pcibios_err_to_errno(ret);
	if (ret)
		goto error;
	if (!!(actual & HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ) != want) {
		dev_err(&pf->dev, "VF 10-bit tag setting did not take effect\n");
		return;
	}

	dev_info(&pf->dev, "VF 10-bit tags %s\n", str_enabled_disabled(want));
	return;

error:
	dev_err(&pf->dev, "Unable to set VF 10-bit tags: %d\n", ret);
}

bool hfi2_sriov_vf_tags_match(struct pci_dev *pf)
{
	u16 devctl2, ctrl;
	u32 cap;
	int pos;

	if (!tags_apply(pf) || read_pf_vf_tag_regs(pf, &pos, &devctl2, &cap, &ctrl))
		return true;

	return !!(devctl2 & HFI2_PCI_EXP_DEVCTL2_10BIT_TAG_REQ) ==
		!!(ctrl & HFI2_PCI_SRIOV_CTRL_VF_10BIT_TAG_REQ);
}

/*
 * This initializes the host VF PCI device - not SRIOV from PF0.
 *
 * Normally, the VF devices will be pass-through to VMs, in which
 * case the host driver does not want to claim the device.
 * TODO: Does KVM (virtsh) tolerate the driver claiming the VF,
 * by calling the remove_one() function when assigning the device
 * to the guest? If so, we can go ahead and claim the device here,
 * however that will cause a complete setup (and tear-down) of a 'dd' for it.
 *
 * pdev is the VF. Only called from host driver.
 */
int hfi2_sriov_init(struct pci_dev *pdev)
{
	int ret;

#ifdef HFI_SRIOV_BRINGUP
	if (vf_test) {
		ret = pci_enable_device(pdev);
		if (ret) {
			dev_err(&pdev->dev, "SRIOV pci enable failed %d\n", ret);
			return ret;
		}
		pci_set_master(pdev);
	}
	ret = vf_claim ? 0 : -ENODEV;
	if (ret)
		pci_disable_device(pdev);
#else
	ret = -ENODEV;
#endif
	/*
	 * If not claimed then remove_one()/hfi2_sriov_remove() will never be called.
	 */

	/* pci_num_vf(pdev->physfn) is not valid until later, so can't use it */
#ifdef HFI_SRIOV_DEBUG
	dev_info(&pdev->dev, "probing VF%d (%d)\n", pci_iov_vf_id(pdev) + 1, ret);
	dev_warn(&pdev->dev, "is_vm=%d is_vf=%d is_physfn=%d is_virtfn=%d physfn=%p\n",
#if defined(CONFIG_X86)
		 boot_cpu_has(X86_FEATURE_HYPERVISOR),
#else
		 -1,
#endif
		 !pdev->pm_cap, pdev->is_physfn, pdev->is_virtfn, pdev->physfn);
#endif

	return ret;
}

void hfi2_sriov_remove(struct pci_dev *pdev)
{
#ifdef HFI_SRIOV_DEBUG
	dev_info(&pdev->dev, "removing VF%d\n", pci_iov_vf_id(pdev) + 1);
#endif
}

/*
 * This disables SRIOV from PF0, if it was enabled.
 *
 * pdev is PF0. The driver is about to release this PF0.
 */
int hfi2_sriov_disable(struct pci_dev *pdev)
{
	pci_disable_sriov(pdev);
	return 0;
}

/*
 * Deconfigure SRIOV on PF0. The driver may continue to run on PF0.
 */
static int hfi2_sriov_deconfigure(struct hfi2_devdata *dd)
{
	/* TODO: do paranoid cleanup? */
	pci_disable_sriov(dd->pcidev);
	hfi2_pf0_cleanup(dd);
	return 0;
}

/* TODO: any setup required for RPMSG, etc.
 *
 * pdev is PF0.
 */
int hfi2_sriov_configure(struct pci_dev *pdev, int nvf)
{
	struct hfi2_devdata *dd = pci_get_drvdata(pdev);
	int ret;

	if (!nvf)
		return hfi2_sriov_deconfigure(dd);

	if (nvf > max_num_vfs)
		return -EINVAL;

	/* prepare VF resources (contexts) for creation of VFs */
	ret = vf2pf_prep(dd);
	if (ret)
		return ret;

	ret = pci_enable_sriov(pdev, nvf);
	if (ret < 0) {
		hfi2_sriov_deconfigure(dd);
		return ret;
	}
	hfi2_sriov_align_vf_tags(pdev);
	return nvf;
}

/*
 * Enables SRIOV if max_num_vfs > 0.
 *
 * Called at the very end of PF0 initialization (init_one()).
 */
int hfi2_sriov_auto_conf(struct hfi2_devdata *dd)
{
	int ret = 0;

	if (!max_num_vfs)
		return ret;

	if (sriov_auto) {
		ret = hfi2_sriov_configure(dd->pcidev, max_num_vfs);
		if (ret < 0)
			dd_dev_err(dd, "hfi2_sriov_configure(%d) failed (%d).\n",
				   max_num_vfs, ret);
		else
			ret = 0;
	}
	return ret;
}

/*
 * PF driver callback backing the /sys/bus/pci/devices/<pf>/sriov_vf_total_msix
 * sysfs attribute.
 *
 * The per-VF interrupt need is a function of the contexts/SDMA-engines
 * assigned to that VF, which itself is a software partitioning decision (see hfi2_sriov_get_config()).
 * So the total pool is computed dynamically: work out one VF's MSI-X need using the
 * same accounting as hfi2_msix_initialize() and multiply by the number of VFs
 * the driver is configured to support (max_num_vfs).
 *
 * pdev is PF0.
 */
u32 hfi2_sriov_get_vf_total_msix(struct pci_dev *pdev)
{
	struct hfi2_devdata *dd = pci_get_drvdata(pdev);
	struct hfi2_devrsrcs vf_rsrcs = {};
	u32 sdma_count, rcv_count, per_vf_msix, bulksvc_cnt;
	int ret;

	if (!dd || dd->params->chip_type == CHIP_WFR || !hfi2_sriov_is_enabled())
		return 0;

	/*
	 * All VFs receive an equal resource share under the current
	 * module-param-driven partitioning model, so query VF1's slice
	 * (si=1) as representative of any VF.
	 */
	ret = hfi2_sriov_get_config(dd, &vf_rsrcs, 1);
	if (ret)
		return 0;

	sdma_count = vf_rsrcs.last_sdma_engine - vf_rsrcs.first_sdma_engine;
	rcv_count = vf_rsrcs.c.last_rcv_context - vf_rsrcs.c.first_rcv_context;
	bulksvc_cnt = dd->bulksvc ? 1 : 0;

	/*
	 * Mirror the hfi2_msix_initialize() accounting for a single VF instance:
	 *	one general "slow path" interrupt
	 *	one for the VF's vf2pf communication channel
	 *	three per assigned SDMA engine
	 *	one per assigned receive context
	 *	one for the bulksvc doorbell if enabled
	 * cport is PF0-only and is not counted per VF.
	 */
	per_vf_msix = 1 + vf2pf_num_irq(dd) + (3 * sdma_count) + rcv_count + bulksvc_cnt;

	return per_vf_msix * vf_rsrcs.num_vfs;
}
