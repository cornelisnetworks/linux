/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#ifndef _HFI1_FILE_OPS_H
#define _HFI1_FILE_OPS_H

#include "hfi.h"

int hfi1_set_uevent_bits(struct hfi1_pportdata *ppd, const int evtbit);
int hfi1_device_create(struct hfi1_devdata *dd);
void hfi1_device_remove(struct hfi1_devdata *dd);
struct hfi1_filedata *hfi1_alloc_filedata(struct hfi1_devdata *dd);
void hfi1_dealloc_filedata(struct hfi1_filedata *fdata);
int hfi1_do_assign_ctxt(struct hfi1_filedata *fd,
			const struct hfi1_assign_ctxt_cmd *uinfo);

#endif /* _HFI1_FILE_OPS_H */
