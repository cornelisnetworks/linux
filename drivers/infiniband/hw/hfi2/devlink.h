/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_DEVLINK_H
#define _HFI2_DEVLINK_H

#include <linux/types.h>

struct hfi2_devdata;

int hfi2_devlink_register(struct hfi2_devdata *dd);
void hfi2_devlink_unregister(struct hfi2_devdata *dd);
bool hfi2_devlink_is_canonical(struct hfi2_devdata *dd);
void hfi2_devlink_canonical_name(struct hfi2_devdata *dd, char *buf, size_t len);

#endif /* _HFI2_DEVLINK_H */
