/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 */

#ifndef _HFI2_VPORT_H
#define _HFI2_VPORT_H

#include <linux/bits.h>
#include <linux/types.h>
#include <asm/byteorder.h>

/*
 * IBTA Annex A18 (Virtualization) SMP attributes.
 * VPort 0 is the physical port; VF index N (0-based) is
 * VPort N + 1, which is also its SI index.
 */
#define HFI2_ATTR_VIRTUALIZATION_INFO	cpu_to_be16(0x0040)
#define HFI2_ATTR_VNODE_INFO		cpu_to_be16(0x0041)
#define HFI2_ATTR_VNODE_DESCRIPTION	cpu_to_be16(0x0042)
#define HFI2_ATTR_VPORT_INFO		cpu_to_be16(0x0043)
#define HFI2_ATTR_VPORT_GUID_INFO	cpu_to_be16(0x0044)
#define HFI2_ATTR_VPORT_PARTITION_TABLE	cpu_to_be16(0x0045)
#define HFI2_ATTR_VPORT_STATE		cpu_to_be16(0x0046)

/* Maximum number of VFs (and so of non-physical VPorts) per port */
#define HFI2_MAX_VPORT_VFS		7

/* attribute modifier: VPort index is in bits 31:16 */
#define HFI2_VPORT_AM_INDEX(am)		(((am) >> 16) & 0xffff)
/* VPortGUIDInfo attribute modifier: GUID block number is in bits 4:0 */
#define HFI2_VPORT_AM_GUID_BLK(am)	((am) & 0x1f)
#define HFI2_VPORT_GUIDS_PER_BLK	8

struct hfi2_vnode_info {
	__be16 partition_cap;
	u8 local_port_num;
	u8 num_ports;
	__be64 system_image_guid;
	__be64 node_guid;
	__be64 port_guid;
	u8 reserved[36];
} __packed;

/* hfi2_vport_info.state_flags */
#define HFI2_VPORT_INFO_PORT_STATE		GENMASK(3, 0)
#define HFI2_VPORT_INFO_CLIENT_REREGISTER	BIT(4)
#define HFI2_VPORT_INFO_LID_REQUIRED		BIT(5)

struct hfi2_vport_info {
	u8 state_flags;
	u8 guid_cap;
	__be16 flags;
	u8 local_port_num;
	u8 reserved1[3];
	__be16 pkey_violations;
	__be16 qkey_violations;
	__be32 lid;
	__be16 lid_by_vport_index;
	u8 reserved3[6];
	__be64 profile_id;
	__be16 sl_mask;
	u8 reserved2[30];
} __packed;

struct hfi2_vport_guid_info {
	__be64 gid[HFI2_VPORT_GUIDS_PER_BLK];
} __packed;

#endif /* _HFI2_VPORT_H */
