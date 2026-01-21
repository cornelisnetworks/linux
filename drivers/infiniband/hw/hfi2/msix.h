/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2018 - 2020 Intel Corporation.
 */

#ifndef _HFI2_MSIX_H
#define _HFI2_MSIX_H

#include "hfi2.h"

/* MSIx interface */
int msix_initialize(struct hfi2_devdata *dd);
int msix_early_request_irqs(struct hfi2_devdata *dd);
int msix_request_irqs(struct hfi2_devdata *dd);
void msix_clean_up_interrupts(struct hfi2_devdata *dd);
void msix_shut_down_interrupts(struct hfi2_devdata *dd, bool keep_general);
int msix_request_general_irq(struct hfi2_devdata *dd);
int msix_request_rcd_irq(struct hfi2_ctxtdata *rcd);
int msix_request_sdma_irq(struct sdma_engine *sde);
void msix_free_irq(struct hfi2_devdata *dd, u8 msix_intr);
int msix_request_irq_remap(struct hfi2_devdata *dd, u16 ctxt,
			   enum irq_type type, int src,
			   irq_handler_t handler, irq_handler_t thread,
			   void *arg, const char *name);

/* Netdev interface */
void msix_netdev_synchronize_irq(struct hfi2_pportdata *ppd);
int msix_netdev_request_rcd_irq(struct hfi2_ctxtdata *rcd);

#endif
