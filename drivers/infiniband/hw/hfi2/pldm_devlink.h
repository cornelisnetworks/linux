/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_PLDM_DEVLINK_H
#define _HFI2_PLDM_DEVLINK_H

struct hfi2_devdata;
struct devlink;
struct devlink_info_req;
struct devlink_flash_update_params;
struct netlink_ext_ack;

int hfi2_pldm_info_get(struct hfi2_devdata *dd, struct devlink_info_req *req,
		       struct netlink_ext_ack *extack);
int hfi2_pldm_flash_update(struct hfi2_devdata *dd, struct devlink *devlink,
			   struct devlink_flash_update_params *params,
			   struct netlink_ext_ack *extack);

#endif /* _HFI2_PLDM_DEVLINK_H */
