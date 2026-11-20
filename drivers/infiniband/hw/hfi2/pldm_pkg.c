// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#include <linux/crc32.h>
#include <linux/firmware.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "hfi2.h"
#include "pldm_pkg.h"

/*
 * DSP0267 PLDM firmware update package parser.
 *
 * This is a port of the userspace updateAgent parser (parsePkgHeader(),
 * parseRecords(), parseDownstreamRecords(), parseDescriptors() and
 * parseComponentInfo() in pldmUpdateAgent/updateAgent.c).
 *
 * Two things change in the kernel:
 *
 *  - The userspace parser streams the file with fread()/fseek() and relies on
 *    a short read to catch a truncated package.  Here the package is already
 *    resident, so a cursor walks the buffer and every read is bounds-checked
 *    first.  That closes the unchecked reads in the userspace version, where
 *    a declared length could run past the end of the file and only get caught
 *    later (or not at all, since fseek() past EOF succeeds).
 *
 *  - A UUID mismatch is fatal.  The userspace agent warns and continues on any
 *    UUID at all; here we follow the packaging tooling instead, which accepts
 *    the spec UUID for the declared revision or the legacy revision 1 UUID and
 *    rejects everything else (pldm-package/firmwaretools/parse_pldm.py).
 */

/* The package header ends with a header CRC, plus a payload CRC at revision 4. */
#define PLDM_PKG_HEADER_CRC_LEN		sizeof(u32)
#define PLDM_PKG_PAYLOAD_CRC_LEN	sizeof(u32)

/**
 * struct pldm_cursor - bounds-checked read cursor over the package buffer
 * @data: package bytes
 * @size: length of @data
 * @pos: current read offset
 * @dd: device, for error logging
 * @extack: netlink error reporting, may be NULL
 */
struct pldm_cursor {
	const u8 *data;
	size_t size;
	size_t pos;
	struct hfi2_devdata *dd;
	struct netlink_ext_ack *extack;
};

/*
 * Report a parse failure both to the kernel log and, when the caller came in
 * through devlink, to the user's terminal.
 */
__printf(2, 3)
static void pldm_pkg_err(struct pldm_cursor *cur, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	dd_dev_err(cur->dd, "PLDM package: %pV\n", &vaf);
	va_end(args);

	if (cur->extack) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		NL_SET_ERR_MSG_FMT_MOD(cur->extack, "PLDM package: %pV", &vaf);
		va_end(args);
	}
}

/* True when @len more bytes can be read at the current position. */
static bool pldm_avail(const struct pldm_cursor *cur, size_t len)
{
	return len <= cur->size - cur->pos;
}

static int pldm_read(struct pldm_cursor *cur, void *dst, size_t len, const char *what)
{
	if (!pldm_avail(cur, len)) {
		pldm_pkg_err(cur, "truncated reading %s at offset %zu (need %zu, have %zu)",
			     what, cur->pos, len, cur->size - cur->pos);
		return -EINVAL;
	}
	memcpy(dst, cur->data + cur->pos, len);
	cur->pos += len;
	return 0;
}

static int pldm_read_u8(struct pldm_cursor *cur, u8 *val, const char *what)
{
	return pldm_read(cur, val, sizeof(*val), what);
}

/* Package fields are little endian on the wire and need not be aligned. */
static int pldm_read_u16(struct pldm_cursor *cur, u16 *val, const char *what)
{
	if (!pldm_avail(cur, sizeof(*val))) {
		pldm_pkg_err(cur, "truncated reading %s at offset %zu", what, cur->pos);
		return -EINVAL;
	}
	*val = get_unaligned_le16(cur->data + cur->pos);
	cur->pos += sizeof(*val);
	return 0;
}

static int pldm_read_u32(struct pldm_cursor *cur, u32 *val, const char *what)
{
	if (!pldm_avail(cur, sizeof(*val))) {
		pldm_pkg_err(cur, "truncated reading %s at offset %zu", what, cur->pos);
		return -EINVAL;
	}
	*val = get_unaligned_le32(cur->data + cur->pos);
	cur->pos += sizeof(*val);
	return 0;
}

/*
 * Read a counted string into a fixed buffer and NUL terminate it.  @dst_size
 * includes room for the terminator, so a full 255-byte string fits in 256.
 */
static int pldm_read_string(struct pldm_cursor *cur, u8 *dst, size_t dst_size,
			    u8 len, const char *what)
{
	if (len >= dst_size) {
		pldm_pkg_err(cur, "%s length %u exceeds the %zu byte buffer",
			     what, len, dst_size);
		return -EINVAL;
	}
	if (pldm_read(cur, dst, len, what))
		return -EINVAL;
	dst[len] = '\0';
	return 0;
}

/* Advance past a payload we do not need to interpret, still bounds-checked. */
static int pldm_skip(struct pldm_cursor *cur, size_t len, const char *what)
{
	if (!pldm_avail(cur, len)) {
		pldm_pkg_err(cur, "%s length %zu at offset %zu runs past the end of the package",
			     what, len, cur->pos);
		return -EINVAL;
	}
	cur->pos += len;
	return 0;
}

/*
 * Verify the package header CRC, and at revision 4 the payload CRC too.
 *
 * pkgHeaderSize covers the whole header including the trailing CRC fields, so
 * the CRC is computed over pkgHeaderSize minus those fields.  The kernel's
 * crc32_le() with the ~0 pre/post inversion matches zlib crc32(), which is
 * what the package build tooling uses.
 */
static int pldm_pkg_verify_crc(struct pldm_cursor *cur, const struct pldm_pkg *pkg)
{
	size_t crc_len = PLDM_PKG_HEADER_CRC_LEN;
	u32 expected, actual;
	size_t covered;

	if (pkg->rev >= 4)
		crc_len += PLDM_PKG_PAYLOAD_CRC_LEN;

	if (pkg->header_size < crc_len || pkg->header_size > pkg->size) {
		pldm_pkg_err(cur, "header size %u is not valid for a %zu byte package",
			     pkg->header_size, pkg->size);
		return -EINVAL;
	}

	covered = pkg->header_size - crc_len;
	expected = get_unaligned_le32(pkg->data + covered);
	actual = crc32_le(~0, pkg->data, covered) ^ ~0;
	if (actual != expected) {
		pldm_pkg_err(cur, "header CRC mismatch (computed 0x%08x, expected 0x%08x)",
			     actual, expected);
		return -EINVAL;
	}

	if (pkg->rev < 4)
		return 0;

	expected = get_unaligned_le32(pkg->data + covered + PLDM_PKG_HEADER_CRC_LEN);
	actual = crc32_le(~0, pkg->data + pkg->header_size,
			  pkg->size - pkg->header_size) ^ ~0;
	if (actual != expected) {
		pldm_pkg_err(cur, "payload CRC mismatch (computed 0x%08x, expected 0x%08x)",
			     actual, expected);
		return -EINVAL;
	}

	return 0;
}

/*
 * Package header, DSP0267 table 3.  Stops after recordCount; the record area
 * itself is parsed by pldm_pkg_parse_records().
 */
static int pldm_pkg_parse_header(struct pldm_cursor *cur, struct pldm_pkg *pkg)
{
	/*
	 * DSP0267 table 3 assigns one UUID per header revision.  Index 0 is
	 * also the legacy identifier, which the packaging tooling still emits
	 * at higher revisions and every parser accepts.
	 */
	static const u8 spec_uuids[PLDM_PKG_REV_MAX][16] = {
		{ 0xf0, 0x18, 0x87, 0x8c, 0xcb, 0x7d, 0x49, 0x43,
		  0x98, 0x00, 0xa0, 0x2f, 0x05, 0x9a, 0xca, 0x02 },
		{ 0x12, 0x44, 0xd2, 0x64, 0x8d, 0x7d, 0x47, 0x18,
		  0xa0, 0x30, 0xfc, 0x8a, 0x56, 0x58, 0x7d, 0x5a },
		{ 0x31, 0x19, 0xce, 0x2f, 0xe8, 0x0a, 0x4a, 0x99,
		  0xaf, 0x6d, 0x46, 0xf8, 0xb1, 0x21, 0xf6, 0xbf },
		{ 0x7b, 0x29, 0x1c, 0x99, 0x6d, 0xb6, 0x42, 0x08,
		  0x80, 0x1b, 0x02, 0x02, 0x6e, 0x46, 0x3c, 0x78 },
	};

	if (pldm_read(cur, pkg->uuid, sizeof(pkg->uuid), "package UUID"))
		return -EINVAL;
	if (pldm_read_u8(cur, &pkg->rev, "package header revision"))
		return -EINVAL;
	if (pldm_read_u16(cur, &pkg->header_size, "package header size"))
		return -EINVAL;

	if (pkg->rev < PLDM_PKG_REV_MIN || pkg->rev > PLDM_PKG_REV_MAX) {
		pldm_pkg_err(cur, "unsupported header revision %u, expected %u-%u",
			     pkg->rev, PLDM_PKG_REV_MIN, PLDM_PKG_REV_MAX);
		return -EOPNOTSUPP;
	}

	/*
	 * Accept the spec UUID for the declared revision, or the legacy
	 * revision 1 UUID at any revision.  Our own tooling still stamps the
	 * legacy identifier on some revision 2 packages, and both the Python
	 * parser and libpldm accept it, so rejecting it here would refuse
	 * packages that every other consumer takes.
	 */
	if (memcmp(pkg->uuid, spec_uuids[pkg->rev - 1], sizeof(pkg->uuid)) &&
	    memcmp(pkg->uuid, spec_uuids[0], sizeof(pkg->uuid))) {
		pldm_pkg_err(cur, "UUID %16phN matches neither revision %u nor the legacy revision 1 identifier",
			     pkg->uuid, pkg->rev);
		return -EINVAL;
	}

	if (pldm_read(cur, pkg->release_date, sizeof(pkg->release_date),
		      "package release date"))
		return -EINVAL;
	if (pldm_read_u16(cur, &pkg->bitmap_bit_len, "component bitmap length"))
		return -EINVAL;

	/*
	 * The bitmap is stored whole bytes at a time and indexes into a fixed
	 * per-record array, so both constraints have to hold before any record
	 * is read.
	 */
	if (pkg->bitmap_bit_len % 8 ||
	    pkg->bitmap_bit_len / 8 > PLDM_PKG_APPLICABLE_MAX) {
		pldm_pkg_err(cur, "component bitmap length %u must be a multiple of 8 and at most %u bits",
			     pkg->bitmap_bit_len, PLDM_PKG_APPLICABLE_MAX * 8);
		return -EINVAL;
	}

	if (pldm_read_u8(cur, &pkg->ver_string_type, "package version string type"))
		return -EINVAL;
	if (pldm_read_u8(cur, &pkg->ver_string_len, "package version string length"))
		return -EINVAL;
	if (pldm_read_string(cur, pkg->ver_string, sizeof(pkg->ver_string),
			     pkg->ver_string_len, "package version string"))
		return -EINVAL;
	if (pldm_read_u8(cur, &pkg->record_count, "device record count"))
		return -EINVAL;

	return 0;
}

/* Device descriptors, DSP0267 table 7.  Shared by both record flavours. */
static int pldm_pkg_parse_descriptors(struct pldm_cursor *cur,
				      struct pldm_pkg_record *record)
{
	unsigned int i;

	if (record->descriptor_count > PLDM_PKG_MAX_DESCRIPTORS) {
		pldm_pkg_err(cur, "descriptor count %u exceeds the %u supported",
			     record->descriptor_count, PLDM_PKG_MAX_DESCRIPTORS);
		return -EINVAL;
	}

	for (i = 0; i < record->descriptor_count; i++) {
		struct pldm_pkg_descriptor *desc;

		desc = kzalloc(sizeof(*desc), GFP_KERNEL);
		if (!desc)
			return -ENOMEM;
		list_add_tail(&desc->list, &record->descriptors);

		if (pldm_read_u16(cur, &desc->type, "descriptor type"))
			return -EINVAL;
		if (pldm_read_u16(cur, &desc->len, "descriptor length"))
			return -EINVAL;
		if (desc->len > sizeof(desc->value)) {
			pldm_pkg_err(cur, "descriptor length %u exceeds the %zu byte maximum",
				     desc->len, sizeof(desc->value));
			return -EINVAL;
		}
		if (pldm_read(cur, desc->value, desc->len, "descriptor value"))
			return -EINVAL;
	}

	return 0;
}

/*
 * One device ID record.  Firmware device records (DSP0267 table 4) and
 * downstream device records (table 5) share most fields but differ in the
 * middle, so @downstream selects between them.
 */
static int pldm_pkg_parse_record(struct pldm_cursor *cur, struct pldm_pkg *pkg,
				 struct pldm_pkg_record *record, bool downstream)
{
	size_t start = cur->pos;
	size_t consumed;

	record->downstream = downstream;

	if (pldm_read_u16(cur, &record->record_len, "record length"))
		return -EINVAL;
	if (pldm_read_u8(cur, &record->descriptor_count, "descriptor count"))
		return -EINVAL;
	if (pldm_read_u32(cur, &record->update_option_flags, "device update option flags"))
		return -EINVAL;
	if (pldm_read_u8(cur, &record->set_ver_string_type, "version string type"))
		return -EINVAL;
	if (pldm_read_u8(cur, &record->set_ver_string_len, "version string length"))
		return -EINVAL;
	if (pldm_read_u16(cur, &record->pkg_data_len, "device package data length"))
		return -EINVAL;

	/* Revision 4 added a reference manifest alongside the package data. */
	if (pkg->rev >= 4 &&
	    pldm_read_u32(cur, &record->manifest_len, "reference manifest length"))
		return -EINVAL;

	record->applicable_len = pkg->bitmap_bit_len / 8;
	if (pldm_read(cur, record->applicable, record->applicable_len,
		      "applicable components bitmap"))
		return -EINVAL;

	if (downstream) {
		/*
		 * A downstream record only carries the self-contained
		 * activation minimum version when the option flag says so.
		 */
		if (record->update_option_flags & PLDM_PKG_OPT_SELF_CONTAINED) {
			if (pldm_read_string(cur, record->set_ver_string,
					     sizeof(record->set_ver_string),
					     record->set_ver_string_len,
					     "self-contained activation min version string"))
				return -EINVAL;
			if (pldm_read_u32(cur, &record->min_ver_comparison_stamp,
					  "self-contained activation min version comparison stamp"))
				return -EINVAL;
		}
	} else {
		if (pldm_read_string(cur, record->set_ver_string,
				     sizeof(record->set_ver_string),
				     record->set_ver_string_len,
				     "component image set version string"))
			return -EINVAL;
	}

	if (pldm_pkg_parse_descriptors(cur, record))
		return -EINVAL;

	/*
	 * Remember where the opaque payloads live and step over them; nothing
	 * in the driver interprets either one today.
	 */
	record->pkg_data_offset = cur->pos;
	if (pldm_skip(cur, record->pkg_data_len, "device package data"))
		return -EINVAL;

	if (pkg->rev >= 4) {
		record->manifest_offset = cur->pos;
		if (pldm_skip(cur, record->manifest_len, "reference manifest"))
			return -EINVAL;
	}

	/*
	 * recordLen is a self-check on the layout: if our field-by-field walk
	 * disagrees with the declared size then the package is not the shape
	 * this revision requires.
	 */
	consumed = cur->pos - start;
	if (consumed != record->record_len) {
		pldm_pkg_err(cur, "record consumed %zu bytes but declares %u",
			     consumed, record->record_len);
		return -EINVAL;
	}

	return 0;
}

static int pldm_pkg_parse_records(struct pldm_cursor *cur, struct pldm_pkg *pkg,
				  struct list_head *head, u8 count, bool downstream)
{
	unsigned int i;

	if (count > PLDM_PKG_MAX_RECORDS) {
		pldm_pkg_err(cur, "%srecord count %u exceeds the %u supported",
			     downstream ? "downstream " : "", count,
			     PLDM_PKG_MAX_RECORDS);
		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		struct pldm_pkg_record *record;
		int ret;

		record = kzalloc(sizeof(*record), GFP_KERNEL);
		if (!record)
			return -ENOMEM;
		INIT_LIST_HEAD(&record->descriptors);
		list_add_tail(&record->list, head);

		ret = pldm_pkg_parse_record(cur, pkg, record, downstream);
		if (ret) {
			pldm_pkg_err(cur, "failed parsing %srecord %u",
				     downstream ? "downstream " : "", i);
			return ret;
		}
	}

	return 0;
}

/*
 * Component image information area, DSP0267 table 6.  This area ends where the
 * header CRC begins, which gives a second independent check on the walk.
 */
static int pldm_pkg_parse_components(struct pldm_cursor *cur, struct pldm_pkg *pkg)
{
	size_t crc_len = PLDM_PKG_HEADER_CRC_LEN;
	size_t area_end;
	unsigned int i;

	if (pkg->rev >= 4)
		crc_len += PLDM_PKG_PAYLOAD_CRC_LEN;
	area_end = pkg->header_size - crc_len;

	if (pldm_read_u16(cur, &pkg->component_count, "component image count"))
		return -EINVAL;

	if (pkg->component_count > PLDM_PKG_MAX_COMPONENTS) {
		pldm_pkg_err(cur, "component count %u exceeds the %u supported",
			     pkg->component_count, PLDM_PKG_MAX_COMPONENTS);
		return -EINVAL;
	}

	for (i = 0; i < pkg->component_count; i++) {
		struct pldm_pkg_component *comp;

		comp = kzalloc(sizeof(*comp), GFP_KERNEL);
		if (!comp)
			return -ENOMEM;
		comp->index = i;
		list_add_tail(&comp->list, &pkg->components);

		if (pldm_read_u16(cur, &comp->classification, "component classification"))
			return -EINVAL;
		if (pldm_read_u16(cur, &comp->identifier, "component identifier"))
			return -EINVAL;
		if (pldm_read_u32(cur, &comp->comparison_stamp, "component comparison stamp"))
			return -EINVAL;
		if (pldm_read_u16(cur, &comp->options, "component options"))
			return -EINVAL;
		if (pldm_read_u16(cur, &comp->activation_method,
				  "component activation method"))
			return -EINVAL;
		if (pldm_read_u32(cur, &comp->location_offset, "component location offset"))
			return -EINVAL;
		if (pldm_read_u32(cur, &comp->size, "component size"))
			return -EINVAL;
		if (pldm_read_u8(cur, &comp->ver_string_type, "component version string type"))
			return -EINVAL;
		if (pldm_read_u8(cur, &comp->ver_string_len, "component version string length"))
			return -EINVAL;
		if (pldm_read_string(cur, comp->ver_string, sizeof(comp->ver_string),
				     comp->ver_string_len, "component version string"))
			return -EINVAL;

		/* Revision 3 added per-component opaque data. */
		if (pkg->rev >= 3) {
			if (pldm_read_u32(cur, &comp->opaque_len,
					  "component opaque data length"))
				return -EINVAL;
			comp->opaque_offset = cur->pos;
			if (pldm_skip(cur, comp->opaque_len, "component opaque data"))
				return -EINVAL;
		}

		/*
		 * The image itself lives past the header.  Validate it now so a
		 * bad offset is rejected at parse time rather than mid-flash.
		 */
		if (comp->location_offset < pkg->header_size ||
		    comp->location_offset > pkg->size ||
		    comp->size > pkg->size - comp->location_offset) {
			pldm_pkg_err(cur, "component %u image at offset %u length %u lies outside the %zu byte package",
				     i, comp->location_offset, comp->size, pkg->size);
			return -EINVAL;
		}
	}

	if (cur->pos != area_end) {
		pldm_pkg_err(cur, "component area ended at offset %zu but the header places it at %zu",
			     cur->pos, area_end);
		return -EINVAL;
	}

	return 0;
}

/**
 * pldm_pkg_record_applies - does @comp apply to @record
 * @record: a device ID record
 * @comp: a component image entry
 *
 * Each record carries a bitmap with one bit per component image, in package
 * order.  Return true when this record's bitmap selects @comp.
 */
bool pldm_pkg_record_applies(const struct pldm_pkg_record *record,
			     const struct pldm_pkg_component *comp)
{
	u16 byte = comp->index / 8;

	if (byte >= record->applicable_len)
		return false;

	return record->applicable[byte] & BIT(comp->index % 8);
}

/**
 * pldm_pkg_component_data - locate a slice of a component image
 * @pkg: the parsed package
 * @comp: the component to read from
 * @offset: byte offset within the component image
 * @len: number of bytes wanted
 * @data: set to the start of the slice on success
 *
 * The firmware device asks for image bytes by offset and length, and rounds
 * its final request up to a 32 byte multiple, so the last request can run past
 * the end of the image.  Reject anything that is not simply the tail of the
 * image; the caller zero pads the shortfall.
 *
 * Return: 0 with @data set, or -EINVAL if the request is not satisfiable.
 */
int pldm_pkg_component_data(const struct pldm_pkg *pkg,
			    const struct pldm_pkg_component *comp,
			    u32 offset, u32 len, const u8 **data)
{
	if (offset > comp->size || len > comp->size - offset)
		return -EINVAL;

	*data = pkg->data + comp->location_offset + offset;
	return 0;
}

static void pldm_pkg_free_records(struct list_head *head)
{
	struct pldm_pkg_record *record, *rtmp;

	list_for_each_entry_safe(record, rtmp, head, list) {
		struct pldm_pkg_descriptor *desc, *dtmp;

		list_for_each_entry_safe(desc, dtmp, &record->descriptors, list) {
			list_del(&desc->list);
			kfree(desc);
		}
		list_del(&record->list);
		kfree(record);
	}
}

/**
 * pldm_pkg_free - release a parsed package
 * @pkg: result of pldm_pkg_parse(), may be NULL
 *
 * The package bytes themselves are borrowed and are not freed here.
 */
void pldm_pkg_free(struct pldm_pkg *pkg)
{
	struct pldm_pkg_component *comp, *ctmp;

	if (!pkg)
		return;

	pldm_pkg_free_records(&pkg->records);
	pldm_pkg_free_records(&pkg->downstream_records);

	list_for_each_entry_safe(comp, ctmp, &pkg->components, list) {
		list_del(&comp->list);
		kfree(comp);
	}

	kfree(pkg);
}

/**
 * pldm_pkg_parse - parse a PLDM firmware update package
 * @dd: device, for error logging
 * @fw: the package, as returned by request_firmware()
 * @extack: netlink error reporting, may be NULL
 *
 * @fw must stay valid for as long as the returned package is used, because
 * component images are referenced in place rather than copied.
 *
 * Return: the parsed package, or an ERR_PTR on failure.
 */
struct pldm_pkg *pldm_pkg_parse(struct hfi2_devdata *dd, const struct firmware *fw,
				struct netlink_ext_ack *extack)
{
	struct pldm_cursor cur;
	struct pldm_pkg *pkg;
	int ret;

	if (!fw || !fw->data || !fw->size)
		return ERR_PTR(-EINVAL);

	pkg = kzalloc(sizeof(*pkg), GFP_KERNEL);
	if (!pkg)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&pkg->records);
	INIT_LIST_HEAD(&pkg->downstream_records);
	INIT_LIST_HEAD(&pkg->components);
	pkg->data = fw->data;
	pkg->size = fw->size;

	cur.data = fw->data;
	cur.size = fw->size;
	cur.pos = 0;
	cur.dd = dd;
	cur.extack = extack;

	ret = pldm_pkg_parse_header(&cur, pkg);
	if (ret)
		goto err;

	/* Check integrity before trusting any of the lengths that follow. */
	ret = pldm_pkg_verify_crc(&cur, pkg);
	if (ret)
		goto err;

	ret = pldm_pkg_parse_records(&cur, pkg, &pkg->records,
				     pkg->record_count, false);
	if (ret)
		goto err;

	/* Downstream device records arrived in revision 2. */
	if (pkg->rev >= 2) {
		ret = pldm_read_u8(&cur, &pkg->downstream_record_count,
				   "downstream record count");
		if (ret)
			goto err;

		ret = pldm_pkg_parse_records(&cur, pkg, &pkg->downstream_records,
					     pkg->downstream_record_count, true);
		if (ret)
			goto err;
	}

	ret = pldm_pkg_parse_components(&cur, pkg);
	if (ret)
		goto err;

	dd_dev_info(dd, "PLDM package: revision %u, version '%s', %u record(s), %u component(s)\n",
		    pkg->rev, pkg->ver_string, pkg->record_count, pkg->component_count);

	return pkg;

err:
	pldm_pkg_free(pkg);
	return ERR_PTR(ret);
}
