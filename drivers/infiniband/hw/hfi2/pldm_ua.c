// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#include <linux/firmware.h>
#include <linux/netlink.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <net/devlink.h>

#include "hfi2.h"
#include "pldm_mctp.h"
#include "pldm_pkg.h"
#include "pldm_ua.h"

/*
 * In-kernel PLDM update agent (DSP0267), ported from the userspace
 * updateAgent (pldmUpdateAgent/updateAgent.c).
 *
 * The update is a conversation, and both sides get to ask questions:
 *
 *	we ask     GetFirmwareParameters, RequestUpdate
 *	we ask     PassComponentTable, once per component
 *	we ask     UpdateComponent
 *	  FD asks    RequestFirmwareData, repeatedly, until it has the image
 *	  FD asks    TransferComplete
 *	  FD asks    VerifyComplete
 *	  FD asks    ApplyComplete
 *	...next component
 *	we ask     ActivateFirmware
 *
 * Threading is the part that differs from userspace.  There, one thread does
 * a blocking recv in a loop.  Here the firmware device's requests arrive on
 * the CPORT workqueue, while the flash thread drives the sequence.  The
 * receive path therefore must never wait for the flash thread: it serves
 * RequestFirmwareData itself, straight out of the package, and only hands the
 * state transitions over by completing &pldm_ua.done.
 *
 * That split matters for more than tidiness.  hfi2_cport_send_req() and the CPORT
 * receive dispatch share dd->hfi2_wq, so a receive handler that blocked
 * waiting for the flash thread could occupy the worker the flash thread's own
 * send needs.
 */

/* How long to wait for the firmware device to answer one of our commands. */
#define PLDM_REQ_TIMEOUT		(2 * HZ)

/*
 * How long the firmware device may go quiet during a transfer.  The userspace
 * agent uses the device's own estimate plus ten seconds for the first
 * request, then a fixed window afterwards.  Each request served re-arms it,
 * so this bounds silence, not the transfer.
 */
#define PLDM_FIRST_DATA_TIMEOUT_S	10
#define PLDM_DATA_TIMEOUT		(12 * HZ)

/*
 * Backstop for a device that keeps asking for data but never finishes.  The
 * largest component is a few megabytes at just under a kilobyte per request,
 * so half an hour is far beyond any healthy transfer.
 */
#define PLDM_TRANSFER_LIMIT		(30 * 60 * HZ)

/* How long to wait for VerifyComplete and ApplyComplete. */
#define PLDM_VERIFY_TIMEOUT		(60 * HZ)
#define PLDM_APPLY_TIMEOUT		(60 * HZ)

/*
 * How long to wait for the device to finish activating, and how often to ask.
 * ActivateFirmware is answered when the device enters the activate state, not
 * when it leaves it, so the answer alone does not mean the update took.
 */
#define PLDM_ACTIVATE_TIMEOUT		(60 * HZ)
#define PLDM_ACTIVATE_POLL		(HZ / 2)

/* How often to repeat the "still waiting" message during teardown. */
#define PLDM_EXIT_LOG_INTERVAL		(30 * HZ)

/**
 * struct pldm_ua_ctx - per-device update agent context
 * @lock: guards @session and @busy
 * @quiet: woken when @busy reaches zero
 * @session: the running update, or NULL when idle
 * @busy: receive handlers currently holding @session
 * @update_lock: serialises update sessions against each other
 *
 * @session is published by the flash thread and consumed by the receive path.
 * A receive handler takes a reference under @lock and drops it when done, so
 * teardown can wait for in-flight handlers without either side blocking on
 * the other.
 */
struct pldm_ua_ctx {
	/* guards @session and @busy */
	spinlock_t lock;
	wait_queue_head_t quiet;
	struct pldm_ua *session;
	unsigned int busy;
	/* serialises update sessions against each other */
	struct mutex update_lock;
};

/* ---- message cursor ---------------------------------------------------- */

/**
 * struct pldm_put - append cursor for building a PLDM message
 * @buf: destination
 * @size: capacity of @buf
 * @pos: bytes written so far
 *
 * Callers size their buffer for the largest message they build, so an
 * overflow is a driver bug; it is caught here rather than corrupting memory.
 */
struct pldm_put {
	u8 *buf;
	size_t size;
	size_t pos;
};

static void pldm_put_init(struct pldm_put *p, void *buf, size_t size)
{
	p->buf = buf;
	p->size = size;
	p->pos = 0;
}

static void pldm_put8(struct pldm_put *p, u8 val)
{
	if (WARN_ON_ONCE(p->pos + sizeof(val) > p->size))
		return;
	p->buf[p->pos++] = val;
}

static void pldm_put16(struct pldm_put *p, u16 val)
{
	if (WARN_ON_ONCE(p->pos + sizeof(val) > p->size))
		return;
	put_unaligned_le16(val, p->buf + p->pos);
	p->pos += sizeof(val);
}

static void pldm_put32(struct pldm_put *p, u32 val)
{
	if (WARN_ON_ONCE(p->pos + sizeof(val) > p->size))
		return;
	put_unaligned_le32(val, p->buf + p->pos);
	p->pos += sizeof(val);
}

static void pldm_putbuf(struct pldm_put *p, const void *src, size_t len)
{
	if (WARN_ON_ONCE(p->pos + len > p->size))
		return;
	memcpy(p->buf + p->pos, src, len);
	p->pos += len;
}

static void pldm_putzero(struct pldm_put *p, size_t len)
{
	if (WARN_ON_ONCE(p->pos + len > p->size))
		return;
	memset(p->buf + p->pos, 0, len);
	p->pos += len;
}

/**
 * struct pldm_get - bounds-checked read cursor over a PLDM message
 * @buf: message bytes
 * @size: length of @buf
 * @pos: bytes consumed so far
 * @err: set once a read has run off the end
 *
 * Reads are chained without checking each one; @err is tested at the end.
 * Once set, every later read is a no-op, so a short message cannot produce
 * garbage values that look plausible.
 */
struct pldm_get {
	const u8 *buf;
	size_t size;
	size_t pos;
	bool err;
};

static void pldm_get_init(struct pldm_get *g, const void *buf, size_t size)
{
	g->buf = buf;
	g->size = size;
	g->pos = 0;
	g->err = false;
}

static bool pldm_get_avail(struct pldm_get *g, size_t len)
{
	if (g->err)
		return false;
	if (len > g->size - g->pos) {
		g->err = true;
		return false;
	}
	return true;
}

static u8 pldm_get8(struct pldm_get *g)
{
	if (!pldm_get_avail(g, sizeof(u8)))
		return 0;
	return g->buf[g->pos++];
}

static u16 pldm_get16(struct pldm_get *g)
{
	u16 val;

	if (!pldm_get_avail(g, sizeof(val)))
		return 0;
	val = get_unaligned_le16(g->buf + g->pos);
	g->pos += sizeof(val);
	return val;
}

static u32 pldm_get32(struct pldm_get *g)
{
	u32 val;

	if (!pldm_get_avail(g, sizeof(val)))
		return 0;
	val = get_unaligned_le32(g->buf + g->pos);
	g->pos += sizeof(val);
	return val;
}

static void pldm_getbuf(struct pldm_get *g, void *dst, size_t len)
{
	if (!pldm_get_avail(g, len))
		return;
	memcpy(dst, g->buf + g->pos, len);
	g->pos += len;
}

/*
 * Read a counted string and NUL terminate it.  Version strings come straight
 * off the wire and are handed to devlink, which puts them in a netlink
 * attribute that userspace decodes as UTF-8, so restrict them to printable
 * ASCII.  isprint() is not enough on its own: the kernel's ctype table marks
 * the Latin-1 range printable, so bytes like 0xff would survive and produce
 * an undecodable attribute.
 *
 * An unprogrammed component reads back as all 0xff, which sanitises to all
 * blanks.  Report that as absent rather than as a string of spaces.
 */
static void pldm_get_string(struct pldm_get *g, u8 *dst, size_t dst_size, u8 len)
{
	bool blank = true;
	size_t i;

	if (len >= dst_size) {
		g->err = true;
		return;
	}
	if (!pldm_get_avail(g, len))
		return;

	memcpy(dst, g->buf + g->pos, len);
	g->pos += len;
	dst[len] = '\0';

	for (i = 0; i < len; i++) {
		if (dst[i] < 0x20 || dst[i] > 0x7e)
			dst[i] = ' ';
		else if (dst[i] != ' ')
			blank = false;
	}

	if (blank)
		dst[0] = '\0';
}

/* ---- request and response headers -------------------------------------- */

/*
 * Build a request header.  The instance ID rolls within its five bits; the
 * firmware device matches its reply against the one we sent.
 */
static void pldm_put_req_hdr(struct pldm_ua *ua, struct pldm_put *p, u8 cmd)
{
	ua->instance_id = (ua->instance_id + 1) & PLDM_HDR_INSTANCE_MASK;
	pldm_put8(p, PLDM_HDR_REQUEST | ua->instance_id);
	pldm_put8(p, PLDM_TYPE_FIRMWARE_UPDATE);
	pldm_put8(p, cmd);
}

/*
 * Check a reply header against the request it is supposed to answer.
 *
 * The CPORT transaction ID already paired the two messages, but that says
 * only which mailbox request woke us, not that the payload is a well-formed
 * answer to the command we sent.  The firmware device holds us to the same
 * standard in the other direction (jkrPldm.c matches on the instance ID).
 */
static int pldm_check_rsp_hdr(struct pldm_ua *ua, const u8 *rsp, u8 cmd)
{
	if (rsp[0] & PLDM_HDR_REQUEST) {
		dd_dev_err(ua->dd, "PLDM: reply to command 0x%02x has the request bit set\n",
			   cmd);
		return -EPROTO;
	}

	if ((rsp[0] & PLDM_HDR_INSTANCE_MASK) != ua->instance_id) {
		dd_dev_err(ua->dd, "PLDM: reply to command 0x%02x carries instance %u, expected %u\n",
			   cmd, (unsigned int)(rsp[0] & PLDM_HDR_INSTANCE_MASK),
			   ua->instance_id);
		return -EPROTO;
	}

	if (rsp[1] != PLDM_TYPE_FIRMWARE_UPDATE) {
		dd_dev_err(ua->dd, "PLDM: reply to command 0x%02x has type 0x%02x\n",
			   cmd, rsp[1]);
		return -EPROTO;
	}

	if (rsp[2] != cmd) {
		dd_dev_err(ua->dd, "PLDM: asked for command 0x%02x but got 0x%02x\n",
			   cmd, rsp[2]);
		return -EPROTO;
	}

	return 0;
}

/*
 * Build a response header from the request being answered.  The instance ID
 * and command are echoed, with the request bit cleared.
 */
static void pldm_put_rsp_hdr(struct pldm_put *p, const u8 *req, u8 cc)
{
	pldm_put8(p, req[0] & PLDM_HDR_INSTANCE_MASK);
	pldm_put8(p, req[1]);
	pldm_put8(p, req[2]);
	pldm_put8(p, cc);
}

/**
 * pldm_ua_command - send a command and check the completion code
 * @ua: the session
 * @cmd: the command being sent, for error messages
 * @req: the request message including its header
 * @req_len: length of @req
 * @rsp: buffer for the response payload, past the four byte header
 * @rsp_len: in, size of @rsp; out, payload bytes written
 *
 * Return: 0 if the firmware device answered with success, otherwise a
 * negative errno.
 */
static noinline_for_stack int pldm_ua_command(struct pldm_ua *ua, u8 cmd,
					      const void *req, u32 req_len,
					      void *rsp, u32 *rsp_len)
{
	u8 *buf = ua->cmd_buf;
	u32 len = sizeof(ua->cmd_buf);
	int ret;

	ret = pldm_mad_send_req(ua->dd, ua->port, req, req_len, buf, &len);
	if (ret)
		return ret;

	if (len < PLDM_RSP_HDR_LEN) {
		dd_dev_err(ua->dd, "PLDM: command 0x%02x reply is only %u bytes\n",
			   cmd, len);
		return -EPROTO;
	}

	ret = pldm_check_rsp_hdr(ua, buf, cmd);
	if (ret)
		return ret;

	if (buf[3] != PLDM_CC_SUCCESS) {
		dd_dev_err(ua->dd, "PLDM: command 0x%02x failed, completion code 0x%02x\n",
			   cmd, buf[3]);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device rejected command 0x%02x with completion code 0x%02x",
				       cmd, buf[3]);
		return -EREMOTEIO;
	}

	len -= PLDM_RSP_HDR_LEN;
	if (rsp) {
		if (len > *rsp_len) {
			dd_dev_err(ua->dd, "PLDM: command 0x%02x reply of %u bytes exceeds the %u byte buffer\n",
				   cmd, len, *rsp_len);
			return -EMSGSIZE;
		}
		memcpy(rsp, buf + PLDM_RSP_HDR_LEN, len);
		*rsp_len = len;
	}

	return 0;
}

/* ---- GetFirmwareParameters --------------------------------------------- */

/**
 * pldm_ua_free_params - release a decoded GetFirmwareParameters response
 * @params: result of pldm_ua_query_params(), may hold an empty list
 */
void pldm_ua_free_params(struct pldm_ua_params *params)
{
	struct pldm_ua_component_param *cp, *tmp;

	list_for_each_entry_safe(cp, tmp, &params->components, list) {
		list_del(&cp->list);
		kfree(cp);
	}
}

/*
 * Ask the firmware device what it is running and what it will accept.
 * DSP0267 table 9.
 */
static int pldm_ua_query_params(struct pldm_ua *ua, struct pldm_ua_params *params)
{
	u32 rsp_len = sizeof(ua->rsp_buf);
	u8 *rsp = ua->rsp_buf;
	u8 req[PLDM_HDR_LEN];
	struct pldm_put p;
	struct pldm_get g;
	u8 active_len, pending_len;
	unsigned int i;
	int ret;

	INIT_LIST_HEAD(&params->components);

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_GET_FIRMWARE_PARAMETERS);

	ret = pldm_ua_command(ua, PLDM_CMD_GET_FIRMWARE_PARAMETERS,
			      req, p.pos, rsp, &rsp_len);
	if (ret)
		return ret;

	pldm_get_init(&g, rsp, rsp_len);
	params->capabilities = pldm_get32(&g);
	params->component_count = pldm_get16(&g);
	pldm_get8(&g);				/* active image set string type */
	active_len = pldm_get8(&g);
	pldm_get8(&g);				/* pending image set string type */
	pending_len = pldm_get8(&g);
	pldm_get_string(&g, params->active_image_set_ver,
			sizeof(params->active_image_set_ver), active_len);
	pldm_get_string(&g, params->pending_image_set_ver,
			sizeof(params->pending_image_set_ver), pending_len);

	if (g.err) {
		dd_dev_err(ua->dd, "PLDM: truncated GetFirmwareParameters reply\n");
		return -EPROTO;
	}

	if (params->component_count > PLDM_PKG_MAX_COMPONENTS) {
		dd_dev_err(ua->dd, "PLDM: firmware device reports %u components, more than the %u supported\n",
			   params->component_count, PLDM_PKG_MAX_COMPONENTS);
		return -EPROTO;
	}

	for (i = 0; i < params->component_count; i++) {
		struct pldm_ua_component_param *cp;
		u8 alen, plen;

		cp = kzalloc(sizeof(*cp), GFP_KERNEL);
		if (!cp) {
			ret = -ENOMEM;
			goto err;
		}
		list_add_tail(&cp->list, &params->components);

		cp->classification = pldm_get16(&g);
		cp->identifier = pldm_get16(&g);
		cp->classification_index = pldm_get8(&g);
		cp->active_comparison_stamp = pldm_get32(&g);
		pldm_get8(&g);			/* active version string type */
		alen = pldm_get8(&g);
		g.pos = min(g.pos + 8, g.size);	/* active release date */
		pldm_get32(&g);			/* pending comparison stamp */
		pldm_get8(&g);			/* pending version string type */
		plen = pldm_get8(&g);
		g.pos = min(g.pos + 8, g.size);	/* pending release date */
		cp->activation_methods = pldm_get16(&g);
		cp->capabilities = pldm_get32(&g);
		pldm_get_string(&g, cp->active_ver_string,
				sizeof(cp->active_ver_string), alen);
		pldm_get_string(&g, cp->pending_ver_string,
				sizeof(cp->pending_ver_string), plen);

		if (g.err) {
			dd_dev_err(ua->dd, "PLDM: truncated component parameter table at entry %u\n",
				   i);
			ret = -EPROTO;
			goto err;
		}
	}

	return 0;

err:
	pldm_ua_free_params(params);
	return ret;
}

/* ---- component selection ----------------------------------------------- */

/**
 * struct pldm_ua_work - one component to update
 * @list: linked into the update order
 * @comp: the package component supplying the image
 * @param: the firmware device's entry for it
 */
struct pldm_ua_work {
	struct list_head list;
	const struct pldm_pkg_component *comp;
	const struct pldm_ua_component_param *param;
};

static void pldm_ua_free_work(struct list_head *head)
{
	struct pldm_ua_work *w, *tmp;

	list_for_each_entry_safe(w, tmp, head, list) {
		list_del(&w->list);
		kfree(w);
	}
}

/*
 * Pair each component the firmware device reports with the matching image in
 * the package, keeping the device's order.  That order is the order the
 * update must follow.
 *
 * A component the device has but the package lacks is only acceptable when
 * the device supports partial updates.
 */
static int pldm_ua_build_work(struct pldm_ua *ua,
			      const struct pldm_ua_params *params,
			      const struct pldm_pkg_record *record,
			      struct list_head *head, unsigned int *count)
{
	const struct pldm_ua_component_param *cp;

	*count = 0;

	list_for_each_entry(cp, &params->components, list) {
		const struct pldm_pkg_component *comp;
		struct pldm_ua_work *w;
		bool found = false;

		list_for_each_entry(comp, &ua->pkg->components, list) {
			if (comp->classification != cp->classification ||
			    comp->identifier != cp->identifier)
				continue;
			if (!pldm_pkg_record_applies(record, comp))
				continue;

			w = kzalloc(sizeof(*w), GFP_KERNEL);
			if (!w)
				return -ENOMEM;
			w->comp = comp;
			w->param = cp;
			list_add_tail(&w->list, head);
			found = true;
			(*count)++;
			break;
		}

		if (!found && !(params->capabilities & PLDM_CAP_PARTIAL_UPDATE)) {
			dd_dev_err(ua->dd, "PLDM: package has no image for component 0x%04x/0x%04x and the device cannot do a partial update\n",
				   cp->classification, cp->identifier);
			NL_SET_ERR_MSG_FMT_MOD(ua->extack,
					       "package lacks component 0x%04x; this device needs every component",
					       cp->identifier);
			return -EINVAL;
		}
	}

	if (!*count) {
		dd_dev_err(ua->dd, "PLDM: package contains nothing this device can use\n");
		NL_SET_ERR_MSG_MOD(ua->extack,
				   "package contains no components for this device");
		return -EINVAL;
	}

	return 0;
}

/*
 * Pick the package record whose descriptors describe this device.
 *
 * QueryDeviceIdentifiers returns the device's descriptors; a record matches
 * when every descriptor in the shorter of the two lists is present in the
 * other.  Matching on the shorter list is deliberate: packages and firmware
 * have gained descriptors at different times, so requiring an exact set would
 * reject combinations that are actually compatible.
 *
 * It does mean the shorter list decides, so a record carrying only a widely
 * shared descriptor, or none at all, would match anything.  That is fine for
 * a reader and not fine for something that writes flash, so a record must
 * also name the PCI device this package is for.
 */
static int pldm_ua_match_record(struct pldm_ua *ua,
				const struct pldm_pkg_record **out)
{
	struct pldm_pkg_descriptor *dev_desc = NULL;
	const struct pldm_pkg_record *record;
	u32 rsp_len = sizeof(ua->rsp_buf);
	u8 *rsp = ua->rsp_buf;
	u8 req[PLDM_HDR_LEN];
	struct pldm_put p;
	struct pldm_get g;
	unsigned int count;
	unsigned int i;
	int ret;

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_QUERY_DEVICE_IDENTIFIERS);

	ret = pldm_ua_command(ua, PLDM_CMD_QUERY_DEVICE_IDENTIFIERS,
			      req, p.pos, rsp, &rsp_len);
	if (ret)
		return ret;

	pldm_get_init(&g, rsp, rsp_len);
	pldm_get32(&g);				/* device identifiers length */
	count = pldm_get8(&g);

	if (g.err || !count || count > PLDM_PKG_MAX_DESCRIPTORS) {
		dd_dev_err(ua->dd, "PLDM: device reports %u descriptors\n", count);
		return -EPROTO;
	}

	dev_desc = kcalloc(count, sizeof(*dev_desc), GFP_KERNEL);
	if (!dev_desc)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		dev_desc[i].type = pldm_get16(&g);
		dev_desc[i].len = pldm_get16(&g);
		if (dev_desc[i].len > sizeof(dev_desc[i].value)) {
			dd_dev_err(ua->dd, "PLDM: device descriptor %u is %u bytes\n",
				   i, dev_desc[i].len);
			ret = -EPROTO;
			goto out;
		}
		pldm_getbuf(&g, dev_desc[i].value, dev_desc[i].len);
	}

	if (g.err) {
		dd_dev_err(ua->dd, "PLDM: truncated QueryDeviceIdentifiers reply\n");
		ret = -EPROTO;
		goto out;
	}

	list_for_each_entry(record, &ua->pkg->records, list) {
		struct pldm_pkg_descriptor *rd;
		unsigned int rec_count = 0;
		bool has_vendor = false;
		bool has_device = false;
		bool matched = true;

		list_for_each_entry(rd, &record->descriptors, list) {
			rec_count++;
			if (rd->type == PLDM_DESC_PCI_VENDOR_ID)
				has_vendor = true;
			else if (rd->type == PLDM_DESC_PCI_DEVICE_ID)
				has_device = true;
		}

		/*
		 * A record has to name the hardware it is for.  Without at
		 * least the PCI vendor and device IDs the match below accepts
		 * it for anything that answered, and a device ID alone is only
		 * unique within a vendor.  Every package we ship carries all
		 * four PCI descriptors.
		 */
		if (!has_vendor || !has_device)
			continue;

		if (count <= rec_count) {
			/* Every device descriptor must appear in the record. */
			for (i = 0; i < count && matched; i++) {
				matched = false;
				list_for_each_entry(rd, &record->descriptors, list) {
					if (rd->type == dev_desc[i].type &&
					    rd->len == dev_desc[i].len &&
					    !memcmp(rd->value, dev_desc[i].value,
						    rd->len)) {
						matched = true;
						break;
					}
				}
			}
		} else {
			/* Every record descriptor must appear on the device. */
			list_for_each_entry(rd, &record->descriptors, list) {
				bool found = false;

				for (i = 0; i < count; i++) {
					if (rd->type == dev_desc[i].type &&
					    rd->len == dev_desc[i].len &&
					    !memcmp(rd->value, dev_desc[i].value,
						    rd->len)) {
						found = true;
						break;
					}
				}
				if (!found) {
					matched = false;
					break;
				}
			}
		}

		if (matched) {
			*out = record;
			ret = 0;
			goto out;
		}
	}

	dd_dev_err(ua->dd, "PLDM: no record in this package describes this device\n");
	NL_SET_ERR_MSG_MOD(ua->extack,
			   "package does not contain firmware for this device");
	ret = -ENOENT;

out:
	kfree(dev_desc);
	return ret;
}

/* ---- the update sequence ------------------------------------------------ */

/* DSP0267 table 12.  Puts the device into update mode. */
static noinline_for_stack int pldm_ua_get_status(struct pldm_ua *ua, u8 *state, u8 *prev, u8 *aux);

static int pldm_ua_request_update(struct pldm_ua *ua,
				  const struct pldm_pkg_record *record,
				  unsigned int count)
{
	u8 req[PLDM_HDR_LEN + 11 + PLDM_VER_STRING_MAX];
	u32 rsp_len = sizeof(ua->rsp_buf);
	u8 *rsp = ua->rsp_buf;
	struct pldm_put p;
	struct pldm_get g;
	u16 meta_len;
	u8 will_get_pkg_data;
	int ret;

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_REQUEST_UPDATE);
	pldm_put32(&p, PLDM_MAX_TRANSFER_SIZE);
	pldm_put16(&p, count);
	pldm_put8(&p, PLDM_MAX_OUTSTANDING_REQS);
	pldm_put16(&p, record->pkg_data_len);
	pldm_put8(&p, record->set_ver_string_type);
	pldm_put8(&p, record->set_ver_string_len);
	pldm_putbuf(&p, record->set_ver_string, record->set_ver_string_len);

	ret = pldm_ua_command(ua, PLDM_CMD_REQUEST_UPDATE, req, p.pos,
			      rsp, &rsp_len);
	if (ret) {
		u8 state, prev, aux;

		/*
		 * A lost reply is ambiguous: the device may have entered
		 * update mode and only the answer went missing.  Ask, so the
		 * caller knows whether there is anything to cancel.  If we
		 * cannot tell, assume there is; a cancel against a device
		 * that is already idle is harmless, leaving one stuck in
		 * update mode is not.
		 */
		if (ret != -ETIME && ret != -ETIMEDOUT)
			return ret;

		dd_dev_warn(ua->dd, "PLDM: no reply to RequestUpdate; checking whether the device entered update mode\n");

		if (pldm_ua_get_status(ua, &state, &prev, &aux) ||
		    state != PLDM_FD_IDLE)
			ua->update_started = true;

		return ret;
	}

	ua->update_started = true;

	pldm_get_init(&g, rsp, rsp_len);
	meta_len = pldm_get16(&g);
	will_get_pkg_data = pldm_get8(&g);

	if (g.err) {
		dd_dev_err(ua->dd, "PLDM: truncated RequestUpdate reply\n");
		return -EPROTO;
	}

	/*
	 * Neither of these is implemented, here or in the userspace agent, and
	 * our firmware asks for neither.  Refuse rather than proceed into a
	 * sequence we cannot complete.
	 */
	if (meta_len) {
		dd_dev_err(ua->dd, "PLDM: device wants %u bytes of metadata storage, which is not supported\n",
			   meta_len);
		return -EOPNOTSUPP;
	}
	if (will_get_pkg_data) {
		dd_dev_err(ua->dd, "PLDM: device wants to request package data, which is not supported\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

/* DSP0267 table 14.  Offers the whole component set before any transfer. */
static int pldm_ua_pass_component_tables(struct pldm_ua *ua,
					 struct list_head *work,
					 unsigned int count)
{
	struct pldm_ua_work *w;
	unsigned int index = 0;

	list_for_each_entry(w, work, list) {
		u8 req[PLDM_HDR_LEN + 11 + PLDM_VER_STRING_MAX];
		u32 rsp_len = sizeof(ua->rsp_buf);
		u8 *rsp = ua->rsp_buf;
		struct pldm_put p;
		struct pldm_get g;
		u8 response, code;
		u8 flag;
		int ret;

		if (count == 1)
			flag = PLDM_XFER_FLAG_START_END;
		else if (index == 0)
			flag = PLDM_XFER_FLAG_START;
		else if (index == count - 1)
			flag = PLDM_XFER_FLAG_END;
		else
			flag = PLDM_XFER_FLAG_MIDDLE;

		pldm_put_init(&p, req, sizeof(req));
		pldm_put_req_hdr(ua, &p, PLDM_CMD_PASS_COMPONENT_TABLE);
		pldm_put8(&p, flag);
		pldm_put16(&p, w->comp->classification);
		pldm_put16(&p, w->comp->identifier);
		pldm_put8(&p, w->param->classification_index);
		pldm_put32(&p, w->comp->comparison_stamp);
		pldm_put8(&p, w->comp->ver_string_type);
		pldm_put8(&p, w->comp->ver_string_len);
		pldm_putbuf(&p, w->comp->ver_string, w->comp->ver_string_len);

		ret = pldm_ua_command(ua, PLDM_CMD_PASS_COMPONENT_TABLE,
				      req, p.pos, rsp, &rsp_len);
		if (ret)
			return ret;

		pldm_get_init(&g, rsp, rsp_len);
		response = pldm_get8(&g);
		code = pldm_get8(&g);

		if (g.err) {
			dd_dev_err(ua->dd, "PLDM: truncated PassComponentTable reply\n");
			return -EPROTO;
		}

		/*
		 * A nonzero response means the device will not take this
		 * component.  The userspace agent can override some of these
		 * with --force; there is no equivalent here, so any refusal
		 * ends the update.
		 */
		if (response) {
			dd_dev_err(ua->dd, "PLDM: device refused component 0x%04x, response %u code 0x%02x\n",
				   w->comp->identifier, response, code);
			NL_SET_ERR_MSG_FMT_MOD(ua->extack,
					       "firmware device refused component 0x%04x (code 0x%02x)",
					       w->comp->identifier, code);
			return -EREMOTEIO;
		}

		index++;
	}

	return 0;
}

/*
 * Tell the devlink client where the update has got to.
 *
 * An update runs for minutes and prints its progress to the kernel log, but
 * "devlink dev flash" shows only what it is told.  Without this it sits
 * silent for the whole run and an operator cannot tell a slow flash from a
 * hung one.  @done is in bytes and @total is the size of the component being
 * written, so the client can draw a bar per component.
 *
 * Context: flash thread only.  The notification requires the devlink
 * instance lock, which the flash thread holds and the receive path does not,
 * so the receive path records progress and the flash thread reports it.
 */
static void pldm_ua_progress(struct pldm_ua *ua, const char *msg,
			     u16 identifier, u32 done, u32 total)
{
	char component[16];

	if (!ua->devlink)
		return;

	snprintf(component, sizeof(component), "0x%04x", identifier);
	devlink_flash_update_status_notify(ua->devlink, msg, component,
					   done, total);
}

/*
 * Wait for one of the firmware device's transition messages.
 *
 * The receive path latches each transition as it arrives, so waiting here
 * after the message has already been handled still finds it.  That matters:
 * the device can send TransferComplete and VerifyComplete back to back, and
 * with a single completion the second would be lost.
 *
 * @idle bounds how long the device may go silent.  The transfer of a large
 * component takes far longer than any single step of it, so the download
 * phase is bounded by silence rather than by total elapsed time; a healthy
 * but slow transfer would otherwise be cancelled part-written.  @limit is the
 * backstop for a device that keeps asking for data but never finishes.
 */
static int pldm_ua_wait(struct pldm_ua *ua, enum pldm_ua_xfer xfer,
			long idle, long limit, const char *what,
			u8 *result)
{
	unsigned long deadline = jiffies + limit;
	unsigned long flags;
	u32 reported = 0;
	u32 generation;
	int ret;

	for (;;) {
		const struct pldm_pkg_component *comp;
		unsigned long quiet_since;
		u32 sent;
		long left;

		spin_lock_irqsave(&ua->lock, flags);
		if (ua->got_gen[xfer] == ua->generation &&
		    ua->ack_gen[xfer] == ua->generation) {
			*result = ua->result[xfer];
			ret = ua->rx_err;
			spin_unlock_irqrestore(&ua->lock, flags);
			if (ret)
				dd_dev_err(ua->dd, "PLDM: receive path failed while waiting for %s (%d)\n",
					   what, ret);
			return ret;
		}
		generation = ua->generation;
		quiet_since = ua->data_seen;
		comp = ua->comp;
		sent = ua->bytes_sent;
		spin_unlock_irqrestore(&ua->lock, flags);

		/*
		 * @comp is only retired by this thread, so it stays valid here
		 * once read.
		 */
		if (comp && sent != reported) {
			pldm_ua_progress(ua, "Writing", comp->identifier, sent,
					 comp->size);
			reported = sent;
		}

		if (time_after(jiffies, deadline)) {
			dd_dev_err(ua->dd, "PLDM: %s did not finish within the allowed time\n",
				   what);
			NL_SET_ERR_MSG_FMT_MOD(ua->extack,
					       "firmware device did not finish %s in time",
					       what);
			return -ETIMEDOUT;
		}

		/*
		 * Sleep until the idle window expires, measured from the last
		 * sign of life rather than from when this wait started.  Any
		 * sign of life ends the sleep, so a transfer that is moving
		 * never trips the idle deadline; only silence does.
		 *
		 * Bound it by the overall deadline as well.  The device tells
		 * us how long its first request will take, and that estimate
		 * comes off the wire, so an absurd one must not let us sleep
		 * past the backstop.
		 */
		left = quiet_since + idle - jiffies;
		if (left > (long)(deadline - jiffies))
			left = deadline - jiffies;
		if (left < 1)
			left = 1;

		left = wait_event_killable_timeout(ua->wait,
						   READ_ONCE(ua->ack_gen[xfer]) == generation ||
						   READ_ONCE(ua->data_seen) != quiet_since,
						   left);
		if (left < 0) {
			dd_dev_err(ua->dd, "PLDM: interrupted waiting for %s\n", what);
			return -EINTR;
		}
		if (left > 0)
			continue;	/* something moved; re-read under the lock */

		/*
		 * Nothing arrived.  That may only mean the sleep was cut
		 * short by the overall deadline, which the top of the loop
		 * reports; go back and let it decide.
		 */
		spin_lock_irqsave(&ua->lock, flags);
		ret = ua->ack_gen[xfer] == generation ||
		      ua->data_seen != quiet_since;
		spin_unlock_irqrestore(&ua->lock, flags);
		if (ret || time_before(jiffies, quiet_since + idle))
			continue;

		dd_dev_err(ua->dd, "PLDM: timed out waiting for %s\n", what);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device stopped responding while waiting for %s",
				       what);
		return -ETIMEDOUT;
	}
}

/* DSP0267 table 17, then the transfer, verify and apply phases. */
static int pldm_ua_update_component(struct pldm_ua *ua, struct pldm_ua_work *w,
				    unsigned int index, unsigned int total)
{
	u8 req[PLDM_HDR_LEN + 19 + PLDM_VER_STRING_MAX];
	u32 rsp_len = sizeof(ua->rsp_buf);
	u8 *rsp = ua->rsp_buf;
	unsigned long irqflags;
	struct pldm_put p;
	struct pldm_get g;
	u8 compat, code;
	u32 flags = 0;
	u16 estimate;
	u8 result;
	long idle;
	int ret;

	if (w->comp->opaque_len)
		flags |= PLDM_UPDATE_OPT_OPAQUE_DATA;

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_UPDATE_COMPONENT);
	pldm_put16(&p, w->comp->classification);
	pldm_put16(&p, w->comp->identifier);
	pldm_put8(&p, w->param->classification_index);
	pldm_put32(&p, w->comp->comparison_stamp);
	pldm_put32(&p, w->comp->size);
	pldm_put32(&p, flags);
	pldm_put8(&p, w->comp->ver_string_type);
	pldm_put8(&p, w->comp->ver_string_len);
	pldm_putbuf(&p, w->comp->ver_string, w->comp->ver_string_len);

	/*
	 * Arm the component and the download phase before sending the command.
	 * The firmware device can ask for data, or even finish a small
	 * component, as soon as it has replied; anything armed afterwards
	 * could miss that.
	 */
	spin_lock_irqsave(&ua->lock, irqflags);
	ua->comp = w->comp;
	ua->comp_index = index;
	ua->comp_total = total;
	ua->bytes_sent = 0;
	ua->rx_err = 0;
	ua->state = PLDM_UA_DOWNLOAD;
	/*
	 * Date this component rather than clearing the previous one's
	 * entries.  Our responses go out fire-and-forget, so a duplicate can
	 * still arrive after the next component is armed, and it has to stay
	 * recognisable as the straggler it is.  The first generation is 1, so
	 * a zero entry means "never seen" and cannot be mistaken for one.
	 */
	ua->generation++;
	memset(ua->result, 0, sizeof(ua->result));
	ua->data_seen = jiffies;
	spin_unlock_irqrestore(&ua->lock, irqflags);

	ret = pldm_ua_command(ua, PLDM_CMD_UPDATE_COMPONENT, req, p.pos,
			      rsp, &rsp_len);
	if (ret)
		goto out;

	pldm_get_init(&g, rsp, rsp_len);
	compat = pldm_get8(&g);
	code = pldm_get8(&g);
	pldm_get32(&g);				/* update option flags enabled */
	estimate = pldm_get16(&g);

	if (g.err) {
		dd_dev_err(ua->dd, "PLDM: truncated UpdateComponent reply\n");
		ret = -EPROTO;
		goto out;
	}

	if (compat) {
		dd_dev_err(ua->dd, "PLDM: device will not update component 0x%04x, code 0x%02x\n",
			   w->comp->identifier, code);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device rejected component 0x%04x as incompatible (code 0x%02x)",
				       w->comp->identifier, code);
		ret = -EREMOTEIO;
		goto out;
	}

	/*
	 * The device tells us how long it expects to take before asking for
	 * data, for instance while it erases flash.  Honour it, with the same
	 * ten second margin the userspace agent uses.  It bounds only the
	 * first request; once data is flowing each one re-arms the window.
	 */
	idle = ((long)estimate + PLDM_FIRST_DATA_TIMEOUT_S) * HZ;
	if (idle < PLDM_DATA_TIMEOUT)
		idle = PLDM_DATA_TIMEOUT;

	dd_dev_info(ua->dd, "PLDM: writing component 0x%04x (%u of %u), %u bytes\n",
		    w->comp->identifier, index + 1, total, w->comp->size);
	pldm_ua_progress(ua, "Writing", w->comp->identifier, 0, w->comp->size);

	/*
	 * From here the receive path drives: it answers every
	 * RequestFirmwareData out of the package and records
	 * TransferComplete when the device is done.
	 */
	ret = pldm_ua_wait(ua, PLDM_UA_XFER_TRANSFER, idle,
			   PLDM_TRANSFER_LIMIT, "the image transfer", &result);
	if (ret)
		goto out;

	if (result) {
		dd_dev_err(ua->dd, "PLDM: transfer of component 0x%04x failed, result 0x%02x\n",
			   w->comp->identifier, result);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device reported transfer failure 0x%02x for component 0x%04x",
				       result, w->comp->identifier);
		ret = -EREMOTEIO;
		goto out;
	}

	ret = pldm_ua_wait(ua, PLDM_UA_XFER_VERIFY, PLDM_VERIFY_TIMEOUT,
			   PLDM_VERIFY_TIMEOUT, "image verification", &result);
	if (ret)
		goto out;

	if (result) {
		dd_dev_err(ua->dd, "PLDM: verification of component 0x%04x failed, result 0x%02x\n",
			   w->comp->identifier, result);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device failed to verify component 0x%04x (result 0x%02x)",
				       w->comp->identifier, result);
		ret = -EREMOTEIO;
		goto out;
	}

	ret = pldm_ua_wait(ua, PLDM_UA_XFER_APPLY, PLDM_APPLY_TIMEOUT,
			   PLDM_APPLY_TIMEOUT, "the image to be applied",
			   &result);
	if (ret)
		goto out;

	/*
	 * Result 1 means applied, but the device changed the activation
	 * method it will use.  That is still a success.
	 */
	if (result > 1) {
		dd_dev_err(ua->dd, "PLDM: apply of component 0x%04x failed, result 0x%02x\n",
			   w->comp->identifier, result);
		NL_SET_ERR_MSG_FMT_MOD(ua->extack,
				       "firmware device failed to apply component 0x%04x (result 0x%02x)",
				       w->comp->identifier, result);
		ret = -EREMOTEIO;
		goto out;
	}

	dd_dev_info(ua->dd, "PLDM: component 0x%04x written\n",
		    w->comp->identifier);

out:
	/*
	 * Retire the component and the phase together, under the lock the
	 * receive path uses to read them.
	 */
	spin_lock_irqsave(&ua->lock, irqflags);
	ua->comp = NULL;
	ua->state = PLDM_UA_IDLE;
	spin_unlock_irqrestore(&ua->lock, irqflags);

	return ret;
}

/* DSP0267 table 24.  Makes the newly written images live. */
/*
 * Read the firmware device's current update state.  DSP0267 table 26.
 *
 * @aux distinguishes in-progress from finished, and for a finished operation
 * whether it succeeded.
 */
static noinline_for_stack int pldm_ua_get_status(struct pldm_ua *ua, u8 *state, u8 *prev, u8 *aux)
{
	u32 rsp_len = sizeof(ua->rsp_buf);
	u8 *rsp = ua->rsp_buf;
	u8 req[PLDM_HDR_LEN];
	struct pldm_put p;
	struct pldm_get g;
	int ret;

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_GET_STATUS);

	ret = pldm_ua_command(ua, PLDM_CMD_GET_STATUS, req, p.pos,
			      rsp, &rsp_len);
	if (ret)
		return ret;

	pldm_get_init(&g, rsp, rsp_len);
	*state = pldm_get8(&g);
	*prev = pldm_get8(&g);
	*aux = pldm_get8(&g);

	if (g.err) {
		dd_dev_err(ua->dd, "PLDM: truncated GetStatus reply\n");
		return -EPROTO;
	}

	return 0;
}

/*
 * DSP0267 table 24.  Makes the newly written images live.
 *
 * The device answers ActivateFirmware when it *enters* the activate state,
 * not when it leaves it, and it can still fail afterwards while it writes
 * the image summary.  So the reply is only the start; poll GetStatus until
 * the device is back at idle and says whether it worked.
 */
static int pldm_ua_activate(struct pldm_ua *ua)
{
	unsigned long deadline;
	u8 req[PLDM_HDR_LEN + 1];
	struct pldm_put p;
	u8 state, prev, aux;
	int ret;

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_ACTIVATE_FIRMWARE);
	/* We never ask for self-contained activation. */
	pldm_put8(&p, 0);

	/*
	 * From here the device may act on the command whatever happens to us,
	 * so no failure below may cancel; see pldm_ua_cancel().
	 */
	ua->activating = true;

	ret = pldm_ua_command(ua, PLDM_CMD_ACTIVATE_FIRMWARE, req, p.pos,
			      NULL, NULL);
	if (ret) {
		/*
		 * The device may have started activating and only the reply
		 * was lost, so the outcome is unknown.  Ask, rather than
		 * cancel an activation that may have succeeded.
		 *
		 * hfi2_cport_send_req() waits with down_timeout(), which reports
		 * -ETIME rather than -ETIMEDOUT.
		 */
		if (ret != -ETIME && ret != -ETIMEDOUT)
			return ret;
		dd_dev_warn(ua->dd, "PLDM: no reply to ActivateFirmware; checking what the device did\n");
	}

	deadline = jiffies + PLDM_ACTIVATE_TIMEOUT;

	for (;;) {
		ret = pldm_ua_get_status(ua, &state, &prev, &aux);
		if (ret) {
			dd_dev_err(ua->dd, "PLDM: cannot read the device state during activation (%d)\n",
				   ret);
			return ret;
		}

		if (state == PLDM_FD_IDLE) {
			/*
			 * Idle alone is not success.  The device is also idle
			 * after a failure, and it was idle before any of this
			 * started, so require that it came here from the
			 * activate state having succeeded.
			 */
			if (prev == PLDM_FD_ACTIVATE && aux == PLDM_AUX_SUCCESSFUL)
				return 0;

			dd_dev_err(ua->dd, "PLDM: activation failed, device is idle with previous state %u and aux state %u\n",
				   prev, aux);
			NL_SET_ERR_MSG_MOD(ua->extack,
					   "firmware device failed to activate the new image");
			/* The device already left update mode on its own. */
			ua->update_started = false;
			return -EREMOTEIO;
		}

		if (state != PLDM_FD_ACTIVATE) {
			dd_dev_err(ua->dd, "PLDM: device is in state %u during activation\n",
				   state);
			return -EPROTO;
		}

		if (time_after(jiffies, deadline)) {
			dd_dev_err(ua->dd, "PLDM: device is still activating after %u seconds\n",
				   jiffies_to_msecs(PLDM_ACTIVATE_TIMEOUT) / 1000);
			NL_SET_ERR_MSG_MOD(ua->extack,
					   "firmware device did not finish activating");
			return -ETIMEDOUT;
		}

		if (schedule_timeout_killable(PLDM_ACTIVATE_POLL))
			return -EINTR;
	}
}

/*
 * Take the firmware device back out of update mode after a failure.
 *
 * This is best effort and deliberately not on the success path: the device
 * unconditionally records a cancelled update as failed (pldmCancelUpdate() in
 * jkrPldm.c), so cancelling after a successful activation would mislabel it.
 */
static void pldm_ua_cancel(struct pldm_ua *ua)
{
	u8 req[PLDM_HDR_LEN];
	struct pldm_put p;
	int ret;

	if (!ua->update_started)
		return;

	/*
	 * Once ActivateFirmware has been sent we can no longer prove the
	 * device did not act on it, and a cancel would mark a successful
	 * activation as a failed update.  Leave it alone and tell the
	 * operator to look.
	 */
	if (ua->activating) {
		dd_dev_warn(ua->dd, "PLDM: not cancelling after ActivateFirmware; check the device state with devlink dev info\n");
		NL_SET_ERR_MSG_MOD(ua->extack,
				   "the outcome of the activation is unknown; check the reported versions before retrying");
		ua->update_started = false;
		return;
	}

	pldm_put_init(&p, req, sizeof(req));
	pldm_put_req_hdr(ua, &p, PLDM_CMD_CANCEL_UPDATE);

	ret = pldm_ua_command(ua, PLDM_CMD_CANCEL_UPDATE, req, p.pos, NULL, NULL);
	if (ret)
		dd_dev_warn(ua->dd, "PLDM: failed to cancel the update (%d); the device may still be in update mode\n",
			    ret);
	else
		dd_dev_info(ua->dd, "PLDM: update cancelled, device returned to idle\n");

	ua->update_started = false;
}

/* ---- receive path ------------------------------------------------------- */

/*
 * Answer RequestFirmwareData out of the package.
 *
 * The firmware device rounds its final request up to a multiple of 32 bytes,
 * so the last one can ask for more than the image holds; the shortfall is
 * zero padded.  Everything else is rejected with the completion code the
 * specification assigns, which lets the device abort cleanly rather than
 * wait for a reply that is never coming.
 */
static int pldm_ua_serve_data(struct pldm_ua *ua, const struct pldm_mad_req *req)
{
	size_t rsp_size = PLDM_RSP_HDR_LEN + PLDM_MAX_TRANSFER_SIZE;
	const struct pldm_pkg_component *comp;
	const u8 *image = NULL;
	u8 cc = PLDM_CC_SUCCESS;
	unsigned long flags;
	struct pldm_put p;
	struct pldm_get g;
	u32 offset, size;
	u32 remaining;
	u32 avail = 0;
	u8 *rsp;
	int ret;

	rsp = kmalloc(rsp_size, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	pldm_get_init(&g, req->msg.payload + PLDM_HDR_LEN,
		      req->msg.payload_len - PLDM_HDR_LEN);
	offset = pldm_get32(&g);
	size = pldm_get32(&g);

	/*
	 * The component may only be read while the download phase is armed.
	 * Outside it the pointer can be going away, and a device that asks
	 * for data after saying the transfer finished is confused about where
	 * the update is.
	 */
	spin_lock_irqsave(&ua->lock, flags);
	comp = ua->state == PLDM_UA_DOWNLOAD ? ua->comp : NULL;
	spin_unlock_irqrestore(&ua->lock, flags);

	if (g.err) {
		cc = PLDM_CC_INVALID_LENGTH;
	} else if (!comp) {
		cc = PLDM_CC_COMMAND_NOT_EXPECTED;
	} else if (size < PLDM_MIN_TRANSFER_SIZE || size > PLDM_MAX_TRANSFER_SIZE) {
		cc = PLDM_CC_INVALID_TRANSFER_LENGTH;
	} else if (offset >= comp->size) {
		/*
		 * A request starting at or past the end would otherwise be
		 * answered entirely with zero padding.  The device has no
		 * reason to ask for it.
		 */
		cc = PLDM_CC_DATA_OUT_OF_RANGE;
	} else {
		/*
		 * The device rounds its last request up to a multiple of 32,
		 * so it may overshoot the image, but by less than 32 bytes.
		 * Subtract rather than add so nothing can wrap.
		 */
		remaining = comp->size - offset;
		if (size > remaining &&
		    size - remaining >= PLDM_MIN_TRANSFER_SIZE) {
			cc = PLDM_CC_DATA_OUT_OF_RANGE;
		} else {
			avail = min(size, remaining);
			if (pldm_pkg_component_data(ua->pkg, comp, offset,
						    avail, &image))
				cc = PLDM_CC_DATA_OUT_OF_RANGE;
		}
	}

	pldm_put_init(&p, rsp, rsp_size);
	pldm_put_rsp_hdr(&p, req->msg.payload, cc);

	if (cc == PLDM_CC_SUCCESS) {
		pldm_putbuf(&p, image, avail);
		/* Pad the request out past the end of the image with zeroes. */
		if (size > avail)
			pldm_putzero(&p, size - avail);
	} else {
		dd_dev_err(ua->dd, "PLDM: rejecting RequestFirmwareData offset %u size %u with 0x%02x\n",
			   offset, size, cc);
	}

	ret = pldm_mad_send_rsp(ua->dd, ua->port, req, rsp, p.pos);
	kfree(rsp);

	/*
	 * Record progress even on a rejection.  The flash thread's idle
	 * deadline is about the device still talking to us, and a device
	 * working through a rejection is still alive.
	 */
	spin_lock_irqsave(&ua->lock, flags);
	if (cc == PLDM_CC_SUCCESS)
		ua->bytes_sent = offset + avail;
	ua->data_seen = jiffies;
	spin_unlock_irqrestore(&ua->lock, flags);
	wake_up(&ua->wait);

	return ret;
}

/*
 * Acknowledge a state transition and latch it for the flash thread.
 *
 * The device is told success regardless of the result it reported, because
 * the completion code answers "did you understand me", not "was the news
 * good".  The result itself is what the flash thread acts on.
 *
 * The phase is advanced here rather than by the flash thread.  The device
 * can send the next transition before the flash thread has looked at this
 * one, so the two cannot take turns.
 *
 * The transition is latched before the response is sent, not after.  Sending
 * first would leave a window in which a second handler saw the same phase and
 * both advanced it, and the later one could then push the phase backwards.
 * The flash thread only proceeds once the answer has actually gone out, so
 * latching early cannot let it run ahead of the device.
 *
 * A retransmission is answered again and moves nothing.  Our responses go out
 * fire-and-forget, so a lost one leaves the device retransmitting; answering
 * that with "not expected" would abort an update that is going fine.
 *
 * Retransmissions are told apart from new messages by the generation the
 * entry was latched in together with the PLDM instance ID.  The instance ID
 * alone is five bits and the device reuses it, so a straggler from the
 * previous component could otherwise be read as this component's transition.
 */
static int pldm_ua_serve_transition(struct pldm_ua *ua,
				    const struct pldm_mad_req *req,
				    enum pldm_ua_state expect,
				    enum pldm_ua_state next,
				    enum pldm_ua_xfer xfer, u8 cmd)
{
	u8 rsp[PLDM_RSP_HDR_LEN];
	unsigned long flags;
	struct pldm_put p;
	struct pldm_get g;
	u32 generation;
	bool repeat;
	bool stale;
	u8 instance;
	u8 result;
	u8 cc;
	int ret;

	pldm_get_init(&g, req->msg.payload + PLDM_HDR_LEN,
		      req->msg.payload_len - PLDM_HDR_LEN);
	result = pldm_get8(&g);
	cc = g.err ? PLDM_CC_INVALID_LENGTH : PLDM_CC_SUCCESS;

	instance = req->msg.payload[0] & PLDM_HDR_INSTANCE_MASK;

	spin_lock_irqsave(&ua->lock, flags);

	generation = ua->generation;

	/*
	 * A duplicate can only ever be a copy of the most recently latched
	 * transition, because the device sends one at a time and will not
	 * move on until it has been answered.  That is what makes this
	 * identification safe where the instance ID alone is not: the ID is
	 * five bits and wraps within a single component's transfer, so an
	 * older entry sharing an ID proves nothing.
	 *
	 * The latched result is deliberately not re-read, so a differing
	 * payload cannot inherit the acknowledgment of the message we
	 * actually latched.
	 */
	repeat = ua->last_valid && ua->last_xfer == xfer &&
		 ua->last_instance == instance;

	if (!repeat && ua->state != expect) {
		enum pldm_ua_state was = ua->state;

		spin_unlock_irqrestore(&ua->lock, flags);
		dd_dev_err(ua->dd, "PLDM: unexpected command 0x%02x while in state %d\n",
			   cmd, was);
		pldm_put_init(&p, rsp, sizeof(rsp));
		pldm_put_rsp_hdr(&p, req->msg.payload, PLDM_CC_COMMAND_NOT_EXPECTED);
		return pldm_mad_send_rsp(ua->dd, ua->port, req, rsp, p.pos);
	}

	if (repeat) {
		/*
		 * A duplicate of a transition belonging to a component we
		 * have already finished with.  Answer it so the device stops
		 * asking, but leave everything alone.
		 */
		stale = ua->last_gen != generation;
	} else {
		stale = false;
		if (g.err)
			ua->rx_err = -EPROTO;
		else
			ua->result[xfer] = result;
		ua->got_gen[xfer] = generation;
		ua->last_xfer = xfer;
		ua->last_instance = instance;
		ua->last_gen = generation;
		ua->last_valid = true;
	}
	if (!stale)
		ua->state = next;
	ua->data_seen = jiffies;
	spin_unlock_irqrestore(&ua->lock, flags);

	pldm_put_init(&p, rsp, sizeof(rsp));
	pldm_put_rsp_hdr(&p, req->msg.payload, cc);
	ret = pldm_mad_send_rsp(ua->dd, ua->port, req, rsp, p.pos);

	/*
	 * Record the acknowledgment only if this is still the transition the
	 * flash thread is waiting for.  An older handler can reach here after
	 * the next component was armed, and must not overwrite the newer
	 * generation's answer with its own.
	 *
	 * A failed send means the device never heard us and will retransmit;
	 * that retransmission gets another chance to record it.
	 */
	if (!ret && !stale) {
		spin_lock_irqsave(&ua->lock, flags);
		if (ua->generation == generation)
			ua->ack_gen[xfer] = generation;
		spin_unlock_irqrestore(&ua->lock, flags);
	} else if (ret) {
		dd_dev_warn(ua->dd, "PLDM: failed to answer command 0x%02x (%d); awaiting a retransmission\n",
			    cmd, ret);
	}

	wake_up(&ua->wait);
	return ret;
}

/**
 * pldm_ua_recv - handle an inbound MCTP-over-MAD request
 * @dd: device
 * @port: 1-based port the request arrived on
 * @mad: the OPA SMP
 * @len: length of @mad
 *
 * Called from the CPORT receive path for every UMAD, before the packet is
 * delivered to userspace.
 *
 * Context: process context on the CPORT workqueue.  Must not wait for the
 * flash thread, since both share dd->hfi2_wq.
 *
 * There are only two answers.  A MAD this agent could not make sense of is
 * one it does not own, and a response it failed to send is still a MAD it
 * consumed; neither is worth a third return value the caller would have to
 * interpret.
 *
 * Return: 0 if this request was consumed, -ENOMSG if it is not ours and
 * should continue to userspace.
 */
int pldm_ua_recv(struct hfi2_devdata *dd, u8 port, const void *mad, int len)
{
	struct pldm_ua_ctx *ctx = READ_ONCE(dd->pldm_ua);
	struct pldm_mad_req req;
	struct pldm_ua *ua;
	unsigned long flags;
	int ret;
	u8 cmd;

	if (!ctx)
		return -ENOMSG;

	/*
	 * @ctx stays valid for the duration of this call: pldm_ua_exit()
	 * clears dd->pldm_ua and then flushes the workqueue this runs on
	 * before freeing, so it cannot go away underneath us.
	 *
	 * Only claim traffic while an update is running.  With no session the
	 * packet belongs to userspace, which is what keeps the existing
	 * updateAgent working on an OPA-mode device.
	 */
	spin_lock_irqsave(&ctx->lock, flags);
	ua = ctx->session;
	if (ua)
		ctx->busy++;
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (!ua)
		return -ENOMSG;

	/*
	 * The session talks to one port.  A request arriving on another is
	 * not part of this conversation.
	 */
	if (port != ua->port) {
		ret = -ENOMSG;
		goto out;
	}

	/*
	 * A decode failure is "not ours", not "ours and broken".  The MAD got
	 * as far as looking like MCTP over MAD, but nothing has established
	 * that this agent owns it, so claiming it would drop a MAD that the
	 * normal path might still make sense of.  pldm_mad_decode() has
	 * already logged what was wrong with it.
	 */
	if (pldm_mad_decode(dd, mad, len, &req)) {
		ret = -ENOMSG;
		goto out;
	}

	if (req.msg.payload_len < PLDM_HDR_LEN) {
		ret = -ENOMSG;
		goto out;
	}

	if (req.msg.payload[1] != PLDM_TYPE_FIRMWARE_UPDATE) {
		ret = -ENOMSG;
		goto out;
	}

	cmd = req.msg.payload[2];

	switch (cmd) {
	case PLDM_CMD_REQUEST_FIRMWARE_DATA:
		ret = pldm_ua_serve_data(ua, &req);
		break;
	case PLDM_CMD_TRANSFER_COMPLETE:
		ret = pldm_ua_serve_transition(ua, &req, PLDM_UA_DOWNLOAD,
					       PLDM_UA_VERIFY,
					       PLDM_UA_XFER_TRANSFER, cmd);
		break;
	case PLDM_CMD_VERIFY_COMPLETE:
		ret = pldm_ua_serve_transition(ua, &req, PLDM_UA_VERIFY,
					       PLDM_UA_APPLY,
					       PLDM_UA_XFER_VERIFY, cmd);
		break;
	case PLDM_CMD_APPLY_COMPLETE:
		ret = pldm_ua_serve_transition(ua, &req, PLDM_UA_APPLY,
					       PLDM_UA_DONE,
					       PLDM_UA_XFER_APPLY, cmd);
		break;
	default: {
		u8 rsp[PLDM_RSP_HDR_LEN];
		struct pldm_put p;

		dd_dev_err(dd, "PLDM: unsupported command 0x%02x from the firmware device\n",
			   cmd);
		pldm_put_init(&p, rsp, sizeof(rsp));
		pldm_put_rsp_hdr(&p, req.msg.payload, PLDM_CC_COMMAND_NOT_EXPECTED);
		ret = pldm_mad_send_rsp(dd, port, &req, rsp, p.pos);
		break;
	}
	}

	/*
	 * Every arm above claimed the request, so it is ours no matter what
	 * the handler returned.  The caller reads a nonzero return as
	 * "recognised but not handled" and logs it, which would be a second
	 * complaint about a MAD that was in fact claimed.  A failed send or
	 * allocation leaves the device to retransmit until it is answered.
	 */
	ret = 0;

out:
	spin_lock_irqsave(&ctx->lock, flags);
	if (!--ctx->busy)
		wake_up(&ctx->quiet);
	spin_unlock_irqrestore(&ctx->lock, flags);

	return ret;
}

/* ---- entry points ------------------------------------------------------- */

/*
 * Publish the session so the receive path starts claiming firmware device
 * traffic.
 */
static void pldm_ua_open(struct pldm_ua_ctx *ctx, struct pldm_ua *ua)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->session = ua;
	spin_unlock_irqrestore(&ctx->lock, flags);
}

/*
 * Retire the session and wait for any receive handler still inside it.  After
 * this returns, nothing else refers to @ua.
 */
static void pldm_ua_close(struct pldm_ua_ctx *ctx)
{
	unsigned long flags;

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->session = NULL;
	spin_unlock_irqrestore(&ctx->lock, flags);

	wait_event(ctx->quiet, !READ_ONCE(ctx->busy));
}

/**
 * pldm_ua_flash - write a firmware package to the device
 * @dd: the device to update
 * @devlink: instance to report progress on, may be NULL
 * @fw: the package
 * @extack: netlink error reporting, may be NULL
 *
 * Runs the whole DSP0267 sequence: match the package to this device, put it
 * into update mode, write every applicable component, then activate.
 *
 * Context: may sleep for the duration of the update, which is minutes.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int pldm_ua_flash(struct hfi2_devdata *dd, struct devlink *devlink,
		  const struct firmware *fw, struct netlink_ext_ack *extack)
{
	struct pldm_ua_ctx *ctx = dd->pldm_ua;
	const struct pldm_pkg_record *record;
	struct pldm_ua_params params = {};
	struct list_head work;
	struct pldm_ua_work *w;
	unsigned int count = 0;
	unsigned int index = 0;
	struct pldm_ua *ua;
	int ret;

	if (!ctx)
		return -EOPNOTSUPP;

	ua = kzalloc(sizeof(*ua), GFP_KERNEL);
	if (!ua)
		return -ENOMEM;

	/*
	 * Both lists have to be valid before anything can jump to the cleanup
	 * below, which runs even when the very first command fails.
	 */
	INIT_LIST_HEAD(&work);
	INIT_LIST_HEAD(&params.components);
	spin_lock_init(&ua->lock);
	init_waitqueue_head(&ua->wait);
	ua->dd = dd;
	ua->port = 1;
	ua->extack = extack;
	ua->devlink = devlink;

	ua->pkg = pldm_pkg_parse(dd, fw, extack);
	if (IS_ERR(ua->pkg)) {
		ret = PTR_ERR(ua->pkg);
		ua->pkg = NULL;
		goto free;
	}

	/* One update at a time, and not while devlink info is querying. */
	mutex_lock(&ctx->update_lock);
	pldm_ua_open(ctx, ua);

	/*
	 * The device has no endpoint ID out of reset and drops anything
	 * addressed to one, so this has to come before any PLDM command.
	 */
	ret = pldm_mctp_set_eid(dd, ua->port);
	if (ret)
		goto close;

	ret = pldm_ua_match_record(ua, &record);
	if (ret)
		goto close;

	ret = pldm_ua_query_params(ua, &params);
	if (ret)
		goto close;

	ret = pldm_ua_build_work(ua, &params, record, &work, &count);
	if (ret)
		goto close;

	/*
	 * Everything from here can leave the device in update mode, including
	 * the rest of pldm_ua_request_update() after the device has accepted.
	 */
	ret = pldm_ua_request_update(ua, record, count);
	if (ret)
		goto cancel;

	ret = pldm_ua_pass_component_tables(ua, &work, count);
	if (ret)
		goto cancel;

	list_for_each_entry(w, &work, list) {
		ret = pldm_ua_update_component(ua, w, index++, count);
		if (ret)
			goto cancel;
	}

	ret = pldm_ua_activate(ua);
	if (ret)
		goto cancel;

	ua->update_started = false;
	dd_dev_info(dd, "PLDM: firmware update complete, %u component(s) written\n",
		    count);
	goto close;

cancel:
	pldm_ua_cancel(ua);

close:
	pldm_ua_close(ctx);
	mutex_unlock(&ctx->update_lock);
	pldm_ua_free_work(&work);
	pldm_ua_free_params(&params);

free:
	pldm_pkg_free(ua->pkg);
	kfree(ua);
	return ret;
}

/**
 * pldm_ua_get_params - read the firmware device's current versions
 * @dd: the device to query
 * @params: filled in on success; release with pldm_ua_free_params()
 *
 * Context: may sleep.  Refuses while an update is running, because the
 * firmware device answers only one conversation at a time.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int pldm_ua_get_params(struct hfi2_devdata *dd, struct pldm_ua_params *params)
{
	struct pldm_ua_ctx *ctx = dd->pldm_ua;
	struct pldm_ua *ua;
	int ret;

	if (!ctx)
		return -EOPNOTSUPP;

	ua = kzalloc(sizeof(*ua), GFP_KERNEL);
	if (!ua)
		return -ENOMEM;

	if (!mutex_trylock(&ctx->update_lock)) {
		kfree(ua);
		return -EBUSY;
	}

	ua->dd = dd;
	ua->port = 1;
	spin_lock_init(&ua->lock);
	init_waitqueue_head(&ua->wait);

	/*
	 * Same as the flash path: on a freshly booted device nothing has an
	 * endpoint ID yet and every PLDM command would be dropped.
	 */
	ret = pldm_mctp_set_eid(dd, ua->port);
	if (!ret)
		ret = pldm_ua_query_params(ua, params);

	mutex_unlock(&ctx->update_lock);
	kfree(ua);
	return ret;
}

/**
 * pldm_ua_init - set up the update agent
 * @dd: the device
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int pldm_ua_init(struct hfi2_devdata *dd)
{
	struct pldm_ua_ctx *ctx;

	/* CPORT is how we reach the firmware device; without it there is no agent. */
	if (!dd->cport)
		return 0;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	spin_lock_init(&ctx->lock);
	init_waitqueue_head(&ctx->quiet);
	mutex_init(&ctx->update_lock);

	WRITE_ONCE(dd->pldm_ua, ctx);
	return 0;
}

/**
 * pldm_ua_exit - tear down the update agent
 * @dd: the device
 *
 * Waits for any running update to finish.  An update in progress cannot be
 * abandoned safely, since the firmware device would be left mid-write.
 */
void pldm_ua_exit(struct hfi2_devdata *dd)
{
	struct pldm_ua_ctx *ctx = dd->pldm_ua;

	if (!ctx)
		return;

	/*
	 * A flash holds this lock for as long as the update runs, which can
	 * be minutes, and abandoning it would leave the firmware device
	 * mid-write.  So this waits.  It cannot be killable: a remove that
	 * gave up here would free the context out from under the flash.
	 *
	 * It does say so while it waits, and keeps saying so.  A silent
	 * remove parked in D state is indistinguishable from a deadlock, and
	 * one line that has since scrolled away explains nothing.
	 */
	while (!mutex_trylock(&ctx->update_lock)) {
		dd_dev_info(dd, "PLDM: waiting for the running firmware update to finish\n");
		schedule_timeout_uninterruptible(PLDM_EXIT_LOG_INTERVAL);
	}
	WRITE_ONCE(dd->pldm_ua, NULL);
	mutex_unlock(&ctx->update_lock);

	/*
	 * Clearing the pointer stops new receive handlers, but one that
	 * already read it is mid-flight.  Those handlers run as CPORT work
	 * items, and hfi2_mad_deinit() only unhooks the callback; it does not
	 * wait for work already dispatched.  Flush before freeing, or that
	 * handler is holding a pointer to freed memory.
	 */
	if (dd->hfi2_wq)
		flush_workqueue(dd->hfi2_wq);

	mutex_destroy(&ctx->update_lock);
	kfree(ctx);
}
