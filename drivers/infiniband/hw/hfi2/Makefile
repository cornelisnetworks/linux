# SPDX-License-Identifier: GPL-2.0
#
# HFI2 driver
#
#
#
# Called from the kernel module build system.
#
obj-$(CONFIG_INFINIBAND_HFI2) += hfi2.o

ccflags-$(CONFIG_SDMA_VERBOSITY) += -DCONFIG_SDMA_VERBOSITY

hfi2-y := \
	affinity.o \
	aspm.o \
	chip.o \
	chip_gen.o \
	chip_jkr.o \
	cport.o \
	driver.o \
	efivar.o \
	eprom.o \
	exp_rcv.o \
	file_ops.o \
	firmware.o \
	init.o \
	intr.o \
	iowait.o \
	ipoib_main.o \
	ipoib_rx.o \
	ipoib_tx.o \
	mad.o \
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
