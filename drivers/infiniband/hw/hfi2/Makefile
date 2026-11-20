# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025-2026 Cornelis Networks, Inc.
#
# HFI 2 driver
#
#
#
# Called from the kernel module build system.
#
obj-$(CONFIG_INFINIBAND_HFI2) += hfi2.o

ccflags-$(CONFIG_HFI2_SDMA_VERBOSITY) += -DCONFIG_HFI2_SDMA_VERBOSITY
ifneq ($(wildcard $(srctree)/drivers/infiniband/core/Module.symvers),)
KBUILD_EXTRA_SYMBOLS += $(srctree)/drivers/infiniband/core/Module.symvers
endif

hfi2-y := \
	bulksvc.o \
	bulksvc_ipoib.o \
	bulksvc_rvt.o \
	bulksvc_user.o \
	bulksvc_verbs.o \
	bulksvc_roce.o \
	bulksvc_uet.o \
	roce_main.o \
	roce_verbs.o \
	roce_wire.o \
	dms_roce.o \
	bulksvc_net.o \
	roce_pasid.o \
	chip.o \
	chip_link.o \
	chip_ctxt.o \
	chip_cyr.o \
	dms_core.o \
	dms_opfn.o \
	dms_sdma.o \
	eth_dcb.o \
	eth_ethtool.o \
	eth_main.o \
	eth_queue.o \
	eth_rx.o \
	eth_sriov.o \
	eth_tx.o \
	dmabuf_core.o \
	pin_dmabuf.o \
	tid_dmabuf.o \
	mem_region.o \
	sriov.o \
	vf2pf.o \
	vf2pf_lb.o \
	rvt_ah.o \
	rvt_cq.o \
	rvt_mad.o \
	rvt_mcast.o \
	rvt_mmap.o \
	rvt_mr.o \
	rvt_pd.o \
	rvt_qp.o \
	rvt_rc.o \
	rvt_srq.o \
	rvt_trace.o \
	rvt_vt.o \
	affinity.o \
	chip_counters.o \
	chip_gen.o \
	chip_jkr.o \
	cport.o \
	driver.o \
	efivar.o \
	eprom.o \
	exp_rcv.o \
	exp_rcv_tab.o \
	file_ops.o \
	firmware.o \
	init.o \
	intr.o \
	iowait.o \
	ipoib_main.o \
	ipoib_rx.o \
	ipoib_tx.o \
	mad_sma.o \
	mad_pma.o \
	mmu_rb.o \
	msix.o \
	netdev_rx.o \
	opfn.o \
	pcie.o \
	pinning.o \
	pin_system.o \
	pio.o \
	pio_copy.o \
	platform.o \
	devlink.o \
	pldm_devlink.o \
	pldm_mctp.o \
	pldm_pkg.o \
	pldm_ua.o \
	qp.o \
	qsfp.o \
	rc.o \
	ruc.o \
	sdma.o \
	sysfs.o \
	tid_rdma.o \
	tid_system.o \
	trace.o \
	uc.o \
	ud.o \
	user_exp_rcv.o \
	user_pages.o \
	user_sdma.o \
	uverbs.o \
	verbs.o \
	verbs_txreq.o

ifdef CONFIG_DEBUG_FS
hfi2-y += debugfs.o
ifdef CONFIG_FAULT_INJECTION
ifdef CONFIG_FAULT_INJECTION_DEBUG_FS
hfi2-y += fault.o
endif
endif
endif

CFLAGS_trace.o = -I$(src)

CFLAGS_rvt_trace.o = -I$(src)
hfi2-$(CONFIG_DYNAMIC_DEBUG) += eth_debug.o
ifeq ($(CONFIG_PTP_1588_CLOCK),y)
hfi2-y += eth_ptp.o
endif

