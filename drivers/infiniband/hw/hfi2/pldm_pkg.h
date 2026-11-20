/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_PLDM_PKG_H
#define _HFI2_PLDM_PKG_H

#include <linux/types.h>
#include <linux/list.h>

struct hfi2_devdata;
struct firmware;
struct netlink_ext_ack;

/*
 * DSP0267 PLDM firmware update package parser.
 *
 * Ported from the userspace updateAgent (pldmUpdateAgent/updateAgent.c).  The
 * userspace parser streams the package with fread()/fseek() and leans on the
 * file layer to catch a short read; here the whole package is already resident
 * as fw->data/fw->size, so every field read is bounds-checked against the
 * buffer instead.
 *
 * lib/pldmfw is deliberately not used: it accepts package header revision 1
 * only and has no downstream device record support, while our packages are
 * moving to revision 2+.  Each revision also carries a different UUID, so a
 * revision 2 package fails two independent hard checks there.
 */

/* Package header revisions understood by this parser. */
#define PLDM_PKG_REV_MIN		1
#define PLDM_PKG_REV_MAX		4

/*
 * Sizing limits.  The wire fields are u8/u16 counts, so a malformed package
 * could otherwise ask us to allocate for 65535 components.  These caps are far
 * above anything we ship (JKR has four components and one record).
 */
#define PLDM_PKG_MAX_RECORDS		32
#define PLDM_PKG_MAX_COMPONENTS		32
#define PLDM_PKG_MAX_DESCRIPTORS	32

/* Version strings carry a u8 length, so 255 bytes plus a NUL terminator. */
#define PLDM_PKG_VER_STRING_MAX		256

/* DSP0267 caps a descriptor value at 40 bytes; round up for alignment. */
#define PLDM_PKG_DESC_VALUE_MAX		64

/* Descriptor types (DSP0267 table 7). */
#define PLDM_DESC_PCI_VENDOR_ID		0x0000
#define PLDM_DESC_PCI_DEVICE_ID		0x0100
#define PLDM_DESC_PCI_SUBSYS_VENDOR_ID	0x0101
#define PLDM_DESC_PCI_SUBSYS_ID		0x0102

/*
 * The applicable-components bitmap is componentBitmapBitLen/8 bytes.  The
 * spec allows up to 8192 bits; matching userspace we cap the bitmap at 512
 * bytes (4096 components), which is far more than any real package.
 */
#define PLDM_PKG_APPLICABLE_MAX		512

/* deviceUpdateOptionFlags bit 0: self-contained activation fields present. */
#define PLDM_PKG_OPT_SELF_CONTAINED	BIT(0)

/**
 * struct pldm_pkg_descriptor - one device descriptor from a device ID record
 * @list: linked into &pldm_pkg_record.descriptors
 * @type: descriptor type (e.g. PCI vendor ID)
 * @len: valid bytes in @value
 * @value: descriptor payload
 */
struct pldm_pkg_descriptor {
	struct list_head list;
	u16 type;
	u16 len;
	u8 value[PLDM_PKG_DESC_VALUE_MAX];
};

/**
 * struct pldm_pkg_record - a firmware device or downstream device ID record
 * @list: linked into &pldm_pkg.records or &pldm_pkg.downstream_records
 * @descriptors: list of &pldm_pkg_descriptor
 * @record_len: declared record length, used to verify what we consumed
 * @descriptor_count: number of entries on @descriptors
 * @update_option_flags: deviceUpdateOptionFlags
 * @set_ver_string_type: componentImageSetVersionStringType, or for a
 *			 downstream record selfContainedActivationMinVersionStringType
 * @set_ver_string_len: valid bytes in @set_ver_string
 * @set_ver_string: componentImageSetVersionString, or for a downstream record
 *		    selfContainedActivationMinVersionString; NUL terminated
 * @min_ver_comparison_stamp: selfContainedActivationMinVersionComparisonStamp,
 *			      downstream records only
 * @pkg_data_len: firmwareDevicePackageDataLength
 * @pkg_data_offset: absolute offset of the firmware device package data
 * @manifest_len: referenceManifestLength (revision 4+, else zero)
 * @manifest_offset: absolute offset of the reference manifest (revision 4+)
 * @applicable: applicable-components bitmap
 * @applicable_len: valid bytes in @applicable
 * @downstream: true if this came from the downstream record area
 *
 * DSP0267 table 4 (firmware device) and table 5 (downstream device) differ in
 * field order and in which fields are conditional, but the parsed result is
 * shaped the same, so both share this struct.  Downstream-only fields are left
 * zero for firmware device records.
 */
struct pldm_pkg_record {
	struct list_head list;
	struct list_head descriptors;
	u16 record_len;
	u8 descriptor_count;
	u32 update_option_flags;
	u8 set_ver_string_type;
	u8 set_ver_string_len;
	u8 set_ver_string[PLDM_PKG_VER_STRING_MAX];
	u32 min_ver_comparison_stamp;
	u16 pkg_data_len;
	size_t pkg_data_offset;
	u32 manifest_len;
	size_t manifest_offset;
	u8 applicable[PLDM_PKG_APPLICABLE_MAX];
	u16 applicable_len;
	bool downstream;
};

/**
 * struct pldm_pkg_component - one component image entry
 * @list: linked into &pldm_pkg.components
 * @classification: componentClassification
 * @identifier: componentIdentifier
 * @comparison_stamp: componentComparisonStamp
 * @options: componentOptions
 * @activation_method: requestedComponentActivationMethod
 * @location_offset: absolute offset of the image inside the package
 * @size: image length in bytes
 * @ver_string_type: componentVersionStringType
 * @ver_string_len: valid bytes in @ver_string
 * @ver_string: componentVersionString, NUL terminated
 * @opaque_len: componentOpaqueDataLength (revision 3+, else zero)
 * @opaque_offset: absolute offset of the opaque data (revision 3+)
 * @index: position in the package component list, which is also the bit
 *	   position to test in &pldm_pkg_record.applicable
 */
struct pldm_pkg_component {
	struct list_head list;
	u16 classification;
	u16 identifier;
	u32 comparison_stamp;
	u16 options;
	u16 activation_method;
	u32 location_offset;
	u32 size;
	u8 ver_string_type;
	u8 ver_string_len;
	u8 ver_string[PLDM_PKG_VER_STRING_MAX];
	u32 opaque_len;
	size_t opaque_offset;
	u16 index;
};

/**
 * struct pldm_pkg - a fully parsed PLDM firmware update package
 * @data: the package bytes, borrowed from the caller's &struct firmware
 * @size: length of @data
 * @uuid: package header identifier
 * @rev: package header format revision, 1-4
 * @header_size: declared package header size
 * @release_date: packageReleaseDateTime, 13 raw bytes
 * @bitmap_bit_len: componentBitmapBitLength
 * @ver_string_type: packageVersionStringType
 * @ver_string_len: valid bytes in @ver_string
 * @ver_string: packageVersionString, NUL terminated
 * @record_count: number of entries on @records
 * @downstream_record_count: number of entries on @downstream_records
 * @component_count: number of entries on @components
 * @records: list of &pldm_pkg_record for firmware devices
 * @downstream_records: list of &pldm_pkg_record for downstream devices
 * @components: list of &pldm_pkg_component, in package order
 *
 * @data stays owned by the caller.  It must remain valid for the lifetime of
 * this structure, because component images are read straight out of it rather
 * than being copied.
 */
struct pldm_pkg {
	const u8 *data;
	size_t size;

	u8 uuid[16];
	u8 rev;
	u16 header_size;
	u8 release_date[13];
	u16 bitmap_bit_len;
	u8 ver_string_type;
	u8 ver_string_len;
	u8 ver_string[PLDM_PKG_VER_STRING_MAX];

	u8 record_count;
	u8 downstream_record_count;
	u16 component_count;

	struct list_head records;
	struct list_head downstream_records;
	struct list_head components;
};

struct pldm_pkg *pldm_pkg_parse(struct hfi2_devdata *dd, const struct firmware *fw,
				struct netlink_ext_ack *extack);
void pldm_pkg_free(struct pldm_pkg *pkg);

bool pldm_pkg_record_applies(const struct pldm_pkg_record *record,
			     const struct pldm_pkg_component *comp);
int pldm_pkg_component_data(const struct pldm_pkg *pkg,
			    const struct pldm_pkg_component *comp,
			    u32 offset, u32 len, const u8 **data);

#endif /* _HFI2_PLDM_PKG_H */
