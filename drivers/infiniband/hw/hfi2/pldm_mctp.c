// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#include <linux/bitfield.h>
#include <linux/slab.h>
#include <rdma/ib_mad.h>
#include <rdma/opa_smi.h>

#include "hfi2.h"
#include "cport.h"
#include "pldm_mctp.h"

/*
 * MCTP over OPA MAD framing for in-kernel PLDM firmware update.
 *
 * This is the transport half of the kernel update agent, ported from the
 * userspace agent's mctp.c (parseMctp(), updateMctpRspHeader()) and
 * updateAgentMad.c (buildLocalMadPacket(), buildAndSendResponse()).
 *
 * Only the local, directed-route case is implemented.  The userspace agent
 * also builds LID-routed MADs to reach a remote HFI across the fabric; that
 * stays in userspace, since the problem being solved here is specifically
 * that CN6000 Ethernet mode has no QP0 for local updates.
 *
 * There are two independent request/response pairings here, and they use
 * different driver interfaces:
 *
 *  - We ask, the firmware device answers (GetFirmwareParameters and the rest
 *    of the update sequence).  These pair at the CPORT level: hfi2_cport_send_req()
 *    allocates a CPORT transaction ID, and the firmware device's reply comes
 *    back with is_req clear and that ID echoed, which wakes the sender.
 *    pldm_mad_send_req() wraps this.
 *
 *  - The firmware device asks, we answer (RequestFirmwareData and friends).
 *    These pair at the MAD level on the MAD transaction ID.  The request
 *    arrives as a posted CPORT request and the reply goes back fire-and-forget
 *    through cport_send_only_mad().  pldm_mad_decode() and
 *    pldm_mad_send_rsp() cover this.
 *
 * Using the wrong one is silent: cport_send_only_mad() never registers a
 * transaction ID, so a reply to it would find no waiter and be dropped.
 */

/* MCTP transport header, byte 3 (DSP0236 figure 4). */
#define MCTP_HDR_SOM			BIT(7)
#define MCTP_HDR_EOM			BIT(6)
#define MCTP_HDR_SEQ_MASK		GENMASK(5, 4)
#define MCTP_HDR_TAG_OWNER		BIT(3)
#define MCTP_HDR_TAG_MASK		GENMASK(2, 0)

#define MCTP_HDR_VERSION		0x01
#define MCTP_HDR_VERSION_MASK		GENMASK(3, 0)

/* Attribute ID and modifier that mark an SMP as carrying MCTP. */
#define OPA_ATTRIB_ID_MCTP_OVER_MAD	cpu_to_be16(0xff30)

/*
 * The MCTP over MAD binding header, four bytes ahead of the MCTP packet:
 *
 *	byte 0-1  reserved
 *	byte 2    pad count in the high nibble, payload length bits 11:8 low
 *	byte 3    payload length bits 7:0
 */
#define MCTP_BINDING_PAD_SHIFT		4
#define MCTP_BINDING_PAD_MASK		GENMASK(7, 4)
#define MCTP_BINDING_LEN_HI_MASK	GENMASK(3, 0)

/* The pad only rounds up to a 4 byte boundary, so it is never larger. */
#define MCTP_BINDING_PAD_MAX		3

/* MCTP control header, byte 0, same request bit position as PLDM. */
#define MCTP_CTRL_HDR_REQUEST		BIT(7)

static int pldm_mctp_exchange(struct hfi2_devdata *dd, u8 port, u8 type,
			      u8 dst_eid, const void *msg, u32 msg_len,
			      void *rsp, u32 *rsp_len);

/**
 * pldm_mctp_check_binding - sanity check an MCTP over MAD binding header
 * @dd: device, for logging
 * @declared: payload length the binding header states
 * @pad: pad count the binding header states
 * @avail: bytes actually present after the binding header
 * @what: "request" or "reply", for the error message
 *
 * The declared length and the pad both have to fit in what arrived, and they
 * sit one after the other, so neither can be checked alone.  A sender that
 * declares a length just inside the buffer can still push its pad past the
 * end.
 *
 * Return: 0 if the header is consistent, otherwise -EINVAL.
 */
static int pldm_mctp_check_binding(struct hfi2_devdata *dd, u32 declared,
				   u32 pad, u32 avail, const char *what)
{
	if (declared < PLDM_MCTP_HDR_BYTES + PLDM_MCTP_TYPE_BYTES) {
		dd_dev_err(dd, "PLDM: MCTP %s declares only %u bytes\n",
			   what, declared);
		return -EINVAL;
	}
	if (pad > MCTP_BINDING_PAD_MAX) {
		dd_dev_err(dd, "PLDM: MCTP %s pad of %u is not an alignment pad\n",
			   what, pad);
		return -EINVAL;
	}
	if (declared > avail || pad > avail - declared) {
		dd_dev_err(dd, "PLDM: MCTP %s declares %u bytes plus %u pad, %u available\n",
			   what, declared, pad, avail);
		return -EINVAL;
	}

	return 0;
}

/**
 * pldm_mad_decode - decode an inbound MCTP-over-MAD request
 * @dd: device, for logging
 * @mad: the OPA SMP, i.e. the CPORT payload past the 9B header
 * @len: length of @mad
 * @req: filled in on success
 *
 * The caller has already stepped over the 28 byte 9B header that CPORT
 * prepends.  @req->msg.payload points into @mad and is only valid while the
 * caller owns that buffer.
 *
 * @len is only as long as the message actually occupies, not the full 2048
 * byte SMP, so bounds are taken from @len rather than from the struct size.
 *
 * Return: 0 if this is a well-formed MCTP request for us, otherwise a negative
 * errno.  -ENOMSG means the packet is simply not ours and the caller should
 * pass it along unchanged.
 */
int pldm_mad_decode(struct hfi2_devdata *dd, const void *mad, int len,
		    struct pldm_mad_req *req)
{
	const size_t data_off = offsetof(struct opa_smp, route.dr.data);
	const struct opa_smp *smp;
	const u8 *smp_data;
	const u8 *mctp;
	u32 declared;
	u32 avail;
	int ret;
	u8 pad;

	/*
	 * Everything up to the directed-route data area has to be present
	 * before any of it can be examined.
	 */
	if (len < 0 || (size_t)len < data_off)
		return -ENOMSG;
	smp = mad;

	if (smp->base_version != OPA_MGMT_BASE_VERSION ||
	    smp->mgmt_class != IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE ||
	    smp->attr_id != OPA_ATTRIB_ID_MCTP_OVER_MAD)
		return -ENOMSG;

	/* Only a request; a GET_RESP is somebody else's reply. */
	if (smp->method != IB_MGMT_METHOD_GET)
		return -ENOMSG;

	/*
	 * The firmware device addresses its local requests with permissive
	 * directed-route source and destination LIDs (jkrMCTP.c and cyrMCTP.c
	 * mctpGenerateHeader(), which also set hop pointer and count to 1).
	 * This alone does not prove local origin, since a fabric peer can send
	 * the same LIDs.  What keeps fabric traffic out is the firmware: it
	 * relays only LID-routed MCTP MADs to the host, and those fail the
	 * directed-route class check above.  Requiring permissive LIDs rejects
	 * anything else that does arrive.
	 */
	if (smp->route.dr.dr_slid != OPA_LID_PERMISSIVE ||
	    smp->route.dr.dr_dlid != OPA_LID_PERMISSIVE)
		return -ENOMSG;

	smp_data = smp->route.dr.data;
	avail = len - offsetof(struct opa_smp, route.dr.data);

	if (avail < PLDM_MCTP_PAYLOAD_OFFSET) {
		dd_dev_err(dd, "PLDM: MAD carries %u bytes, too short for an MCTP message\n",
			   avail);
		return -EINVAL;
	}

	/*
	 * The binding header states the payload length and how many pad bytes
	 * were added to round the MAD to a 4 byte boundary.  Trust it only as
	 * far as the bytes we actually received, and remember that the pad sits
	 * past the payload, so both together have to fit.
	 */
	pad = FIELD_GET(MCTP_BINDING_PAD_MASK, smp_data[2]);
	declared = (FIELD_GET(MCTP_BINDING_LEN_HI_MASK, smp_data[2]) << 8) |
		   smp_data[3];

	ret = pldm_mctp_check_binding(dd, declared, pad,
				      avail - PLDM_MCTP_BINDING_BYTES, "request");
	if (ret)
		return ret;

	mctp = smp_data + PLDM_MCTP_BINDING_BYTES;

	if ((mctp[0] & MCTP_HDR_VERSION_MASK) != MCTP_HDR_VERSION) {
		dd_dev_err(dd, "PLDM: unsupported MCTP header version 0x%02x\n", mctp[0]);
		return -EINVAL;
	}

	req->msg.dst_eid = mctp[1];
	req->msg.src_eid = mctp[2];
	req->msg.tag_owner = !!(mctp[3] & MCTP_HDR_TAG_OWNER);
	req->msg.msg_tag = mctp[3] & MCTP_HDR_TAG_MASK;

	/*
	 * Neither side fragments: the firmware device sizes its requests to
	 * fit one MAD, and our responses are capped the same way.  Anything
	 * that is not a complete single-packet message is malformed.
	 */
	if ((mctp[3] & (MCTP_HDR_SOM | MCTP_HDR_EOM)) != (MCTP_HDR_SOM | MCTP_HDR_EOM)) {
		dd_dev_err(dd, "PLDM: MCTP fragment received, only whole messages are supported\n");
		return -EINVAL;
	}

	/*
	 * Be exact about both endpoints.  A general MCTP stack would also
	 * accept the null and broadcast EIDs, but we do no discovery, and
	 * accepting broadcast would let a stray packet drive a flash.
	 */
	if (req->msg.dst_eid != PLDM_MCTP_UA_EID)
		return -ENOMSG;

	if (req->msg.src_eid != PLDM_MCTP_DEVICE_EID)
		return -ENOMSG;

	/* Only the tag owner is asking a question. */
	if (!req->msg.tag_owner)
		return -ENOMSG;

	req->msg.type = mctp[PLDM_MCTP_HDR_BYTES] & 0x7f;
	if (req->msg.type != PLDM_MCTP_TYPE_PLDM)
		return -ENOMSG;

	req->msg.payload = smp_data + PLDM_MCTP_PAYLOAD_OFFSET;
	req->msg.payload_len = declared - PLDM_MCTP_HDR_BYTES - PLDM_MCTP_TYPE_BYTES;
	req->tid = smp->tid;

	/*
	 * This only ever decodes requests, so the PLDM header must say so too.
	 * Without this a reply that somehow reached the request path could be
	 * acted on as though the firmware device had asked for something.
	 */
	if (req->msg.payload_len < PLDM_HDR_LEN ||
	    !(req->msg.payload[0] & PLDM_HDR_REQUEST))
		return -ENOMSG;

	return 0;
}

/**
 * pldm_mad_send_rsp - send a PLDM response back to the firmware device
 * @dd: device
 * @port: 1-based port number, used as the CPORT sideband
 * @req: the request being answered
 * @pldm: the PLDM response message
 * @pldm_len: length of @pldm
 *
 * Builds a directed-route GET_RESP carrying @pldm and hands it to CPORT.  The
 * field set matches what the userspace agent produces in buildLocalMadPacket()
 * so the firmware device accepts it identically: permissive directed-route
 * LIDs, attribute 0xff30, attribute modifier zero, and the request's
 * transaction ID echoed back.
 *
 * Attribute modifier zero matters.  cport_process_mad() treats modifier bit 0
 * as "inbound" and swallows the MAD; with it clear, a GET_RESP takes the
 * pass-through path out to CPORT.
 *
 * The send is asynchronous.  hfi2_cport_send_notif() returns once the message is
 * queued and a later failure cannot be reported back here, so a successful
 * return only means the response was handed off.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int pldm_mad_send_rsp(struct hfi2_devdata *dd, u8 port,
		      const struct pldm_mad_req *req,
		      const void *pldm, u32 pldm_len)
{
	u32 payload_len = PLDM_MCTP_HDR_BYTES + PLDM_MCTP_TYPE_BYTES + pldm_len;
	struct opa_smp *smp;
	u8 *smp_data;
	u8 *mctp;
	u32 pad;
	int ret;

	if (pldm_len > PLDM_MCTP_MAX_PAYLOAD) {
		dd_dev_err(dd, "PLDM: response of %u bytes exceeds the %u byte MAD budget\n",
			   pldm_len, PLDM_MCTP_MAX_PAYLOAD);
		return -EMSGSIZE;
	}

	/* The MAD payload is padded out to a 4 byte boundary. */
	pad = (4 - (payload_len % 4)) % 4;

	smp = kzalloc(sizeof(*smp), GFP_KERNEL);
	if (!smp)
		return -ENOMEM;

	smp->base_version = OPA_MGMT_BASE_VERSION;
	smp->mgmt_class = IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE;
	smp->class_version = OPA_SM_CLASS_VERSION;
	smp->method = IB_MGMT_METHOD_GET_RESP;
	smp->hop_ptr = 0;
	smp->hop_cnt = 0;
	/* The firmware device matches its outstanding request on this. */
	smp->tid = req->tid;
	smp->attr_id = OPA_ATTRIB_ID_MCTP_OVER_MAD;
	smp->attr_mod = 0;
	smp->route.dr.dr_slid = OPA_LID_PERMISSIVE;
	smp->route.dr.dr_dlid = OPA_LID_PERMISSIVE;

	smp_data = smp->route.dr.data;

	/* MCTP over MAD binding header. */
	smp_data[0] = 0;
	smp_data[1] = 0;
	smp_data[2] = FIELD_PREP(MCTP_BINDING_PAD_MASK, pad) |
		      FIELD_PREP(MCTP_BINDING_LEN_HI_MASK, payload_len >> 8);
	smp_data[3] = payload_len & 0xff;

	/*
	 * MCTP transport header.  Swap the endpoints, clear the tag owner bit
	 * because this is a response, and keep the request's message tag.
	 */
	mctp = smp_data + PLDM_MCTP_BINDING_BYTES;
	mctp[0] = MCTP_HDR_VERSION;
	mctp[1] = req->msg.src_eid;
	mctp[2] = PLDM_MCTP_UA_EID;
	mctp[3] = MCTP_HDR_SOM | MCTP_HDR_EOM | req->msg.msg_tag;
	mctp[PLDM_MCTP_HDR_BYTES] = PLDM_MCTP_TYPE_PLDM;

	memcpy(smp_data + PLDM_MCTP_PAYLOAD_OFFSET, pldm, pldm_len);

	/*
	 * Send only as much as the response occupies.  cport_send_only_mad()
	 * prepends the 9B header, which firmware ignores for a local MAD.
	 */
	ret = cport_send_only_mad(dd, port, smp,
				  offsetof(struct opa_smp, route.dr.data) +
				  PLDM_MCTP_BINDING_BYTES + payload_len + pad,
				  NULL);
	if (ret)
		dd_dev_err(dd, "PLDM: failed to send the response MAD (%d)\n", ret);

	kfree(smp);
	return ret;
}

/*
 * Check that a reply really came from the firmware device in answer to what
 * we sent, before any of its payload is believed.  The CPORT transaction ID
 * already matched or we would not be here, but that only says the mailbox
 * paired them, not that the contents are the conversation we are having.
 */
static int pldm_mctp_check_reply(struct hfi2_devdata *dd,
				 const struct opa_smp *smp, const u8 *mctp,
				 u8 type)
{
	if (smp->base_version != OPA_MGMT_BASE_VERSION ||
	    smp->mgmt_class != IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE ||
	    smp->attr_id != OPA_ATTRIB_ID_MCTP_OVER_MAD) {
		dd_dev_err(dd, "PLDM: reply is not an MCTP over MAD packet\n");
		return -EPROTO;
	}

	if (smp->method != IB_MGMT_METHOD_GET_RESP) {
		dd_dev_err(dd, "PLDM: reply has method 0x%02x, expected a GET_RESP\n",
			   smp->method);
		return -EPROTO;
	}

	if ((mctp[0] & MCTP_HDR_VERSION_MASK) != MCTP_HDR_VERSION) {
		dd_dev_err(dd, "PLDM: reply has MCTP header version 0x%02x\n",
			   mctp[0]);
		return -EPROTO;
	}

	if (mctp[1] != PLDM_MCTP_UA_EID || mctp[2] != PLDM_MCTP_DEVICE_EID) {
		dd_dev_err(dd, "PLDM: reply runs from endpoint 0x%02x to 0x%02x, expected 0x%02x to 0x%02x\n",
			   mctp[2], mctp[1], PLDM_MCTP_DEVICE_EID,
			   PLDM_MCTP_UA_EID);
		return -EPROTO;
	}

	/* We own the tag on a request, so the answer must not claim it. */
	if (mctp[3] & MCTP_HDR_TAG_OWNER) {
		dd_dev_err(dd, "PLDM: reply claims to own the message tag\n");
		return -EPROTO;
	}

	if ((mctp[3] & (MCTP_HDR_SOM | MCTP_HDR_EOM)) !=
	    (MCTP_HDR_SOM | MCTP_HDR_EOM)) {
		dd_dev_err(dd, "PLDM: reply is a fragment, only whole messages are supported\n");
		return -EPROTO;
	}

	if ((mctp[PLDM_MCTP_HDR_BYTES] & 0x7f) != type) {
		dd_dev_err(dd, "PLDM: reply carries MCTP type 0x%02x, expected 0x%02x\n",
			   mctp[PLDM_MCTP_HDR_BYTES] & 0x7f, type);
		return -EPROTO;
	}

	return 0;
}

/**
 * pldm_mctp_exchange - send an MCTP message and wait for the reply
 * @dd: device
 * @port: 1-based port number, used as the CPORT sideband
 * @type: MCTP message type, control or PLDM
 * @dst_eid: destination endpoint
 * @msg: the message to send, past the MCTP type byte
 * @msg_len: length of @msg
 * @rsp: buffer for the reply, past the MCTP type byte
 * @rsp_len: in, size of @rsp; out, bytes written
 *
 * Builds a directed-route GET carrying @msg, sends it to CPORT and blocks
 * until the firmware device answers.  This is the mirror of the userspace
 * agent's sendPldmReq() and sendMctpCtrl(), which share the same framing and
 * differ only in the MCTP type and destination.  The wait is bounded by the
 * cport_mad_to module parameter, the same one every other CPORT MAD uses.
 *
 * Unlike the response path, this pairs at the CPORT level rather than on the
 * MAD transaction ID: cport_send_recv_mad() allocates a CPORT transaction ID
 * and the firmware device's reply carries it back, waking the sender.  The MAD
 * transaction ID is therefore ours to choose, and the firmware device echoes
 * whatever we put there.
 *
 * Context: may sleep.
 *
 * Return: 0 on success with @rsp_len updated, otherwise a negative errno.
 */
static int pldm_mctp_exchange(struct hfi2_devdata *dd, u8 port, u8 type,
			      u8 dst_eid, const void *msg, u32 msg_len,
			      void *rsp, u32 *rsp_len)
{
	u32 payload_len = PLDM_MCTP_HDR_BYTES + PLDM_MCTP_TYPE_BYTES + msg_len;
	size_t out_len = sizeof(struct opa_smp);
	struct opa_smp *out = NULL;
	struct opa_smp *smp;
	u32 declared;
	u8 *smp_data;
	u8 *mctp;
	u32 avail;
	u32 pad;
	int ret;

	if (msg_len > PLDM_MCTP_MAX_PAYLOAD) {
		dd_dev_err(dd, "PLDM: request of %u bytes exceeds the %u byte MAD budget\n",
			   msg_len, PLDM_MCTP_MAX_PAYLOAD);
		return -EMSGSIZE;
	}

	pad = (4 - (payload_len % 4)) % 4;

	smp = kzalloc(sizeof(*smp), GFP_KERNEL);
	if (!smp)
		return -ENOMEM;
	out = kzalloc(out_len, GFP_KERNEL);
	if (!out) {
		ret = -ENOMEM;
		goto out;
	}

	smp->base_version = OPA_MGMT_BASE_VERSION;
	smp->mgmt_class = IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE;
	smp->class_version = OPA_SM_CLASS_VERSION;
	smp->method = IB_MGMT_METHOD_GET;
	smp->attr_id = OPA_ATTRIB_ID_MCTP_OVER_MAD;
	smp->attr_mod = 0;
	smp->route.dr.dr_slid = OPA_LID_PERMISSIVE;
	smp->route.dr.dr_dlid = OPA_LID_PERMISSIVE;

	smp_data = smp->route.dr.data;

	smp_data[0] = 0;
	smp_data[1] = 0;
	smp_data[2] = FIELD_PREP(MCTP_BINDING_PAD_MASK, pad) |
		      FIELD_PREP(MCTP_BINDING_LEN_HI_MASK, payload_len >> 8);
	smp_data[3] = payload_len & 0xff;

	/* We are the tag owner on a request. */
	mctp = smp_data + PLDM_MCTP_BINDING_BYTES;
	mctp[0] = MCTP_HDR_VERSION;
	mctp[1] = dst_eid;
	mctp[2] = PLDM_MCTP_UA_EID;
	mctp[3] = MCTP_HDR_SOM | MCTP_HDR_EOM | MCTP_HDR_TAG_OWNER;
	mctp[PLDM_MCTP_HDR_BYTES] = type;

	memcpy(smp_data + PLDM_MCTP_PAYLOAD_OFFSET, msg, msg_len);

	ret = cport_send_recv_mad(dd, port, smp,
				  offsetof(struct opa_smp, route.dr.data) +
				  PLDM_MCTP_BINDING_BYTES + payload_len + pad,
				  out, &out_len);
	if (ret) {
		dd_dev_err(dd, "PLDM: request MAD failed (%d)\n", ret);
		goto out;
	}

	if (out_len < offsetof(struct opa_smp, route.dr.data) +
		      PLDM_MCTP_PAYLOAD_OFFSET) {
		dd_dev_err(dd, "PLDM: reply is only %zu bytes\n", out_len);
		ret = -EPROTO;
		goto out;
	}

	smp_data = out->route.dr.data;
	avail = out_len - offsetof(struct opa_smp, route.dr.data);
	pad = FIELD_GET(MCTP_BINDING_PAD_MASK, smp_data[2]);
	declared = (FIELD_GET(MCTP_BINDING_LEN_HI_MASK, smp_data[2]) << 8) |
		   smp_data[3];

	ret = pldm_mctp_check_binding(dd, declared, pad,
				      avail - PLDM_MCTP_BINDING_BYTES, "reply");
	if (ret) {
		ret = -EPROTO;
		goto out;
	}

	ret = pldm_mctp_check_reply(dd, out, smp_data + PLDM_MCTP_BINDING_BYTES,
				    type);
	if (ret)
		goto out;

	declared -= PLDM_MCTP_HDR_BYTES + PLDM_MCTP_TYPE_BYTES;
	if (declared > *rsp_len) {
		dd_dev_err(dd, "PLDM: reply of %u bytes exceeds the %u byte buffer\n",
			   declared, *rsp_len);
		ret = -EMSGSIZE;
		goto out;
	}

	memcpy(rsp, smp_data + PLDM_MCTP_PAYLOAD_OFFSET, declared);
	*rsp_len = declared;

out:
	kfree(out);
	kfree(smp);
	return ret;
}

/**
 * pldm_mad_send_req - send a PLDM request and wait for the reply
 * @dd: device
 * @port: 1-based port number, used as the CPORT sideband
 * @pldm: the PLDM request message
 * @pldm_len: length of @pldm
 * @rsp: buffer for the PLDM response message
 * @rsp_len: in, size of @rsp; out, bytes written
 *
 * Context: may sleep.
 *
 * Return: 0 on success with @rsp_len updated, otherwise a negative errno.
 */
int pldm_mad_send_req(struct hfi2_devdata *dd, u8 port,
		      const void *pldm, u32 pldm_len,
		      void *rsp, u32 *rsp_len)
{
	return pldm_mctp_exchange(dd, port, PLDM_MCTP_TYPE_PLDM,
				  PLDM_MCTP_DEVICE_EID, pldm, pldm_len,
				  rsp, rsp_len);
}

/**
 * pldm_mctp_set_eid - assign the firmware device its MCTP endpoint ID
 * @dd: device
 * @port: 1-based port number, used as the CPORT sideband
 *
 * Out of reset the firmware device has no endpoint ID, and it drops any
 * message addressed to one.  Every PLDM command we send is addressed to
 * PLDM_MCTP_DEVICE_EID, so this has to happen first or the conversation never
 * starts.  The userspace agent does the same thing before its first command.
 *
 * The request goes to the broadcast endpoint, since the device has no address
 * yet, and forces the ID rather than requesting one.  The reply reports which
 * ID the device actually took, which must be the one we asked for.
 *
 * Context: may sleep.
 *
 * Return: 0 on success, otherwise a negative errno.
 */
int pldm_mctp_set_eid(struct hfi2_devdata *dd, u8 port)
{
	u8 req[PLDM_MCTP_CTRL_HDR_BYTES + 2];
	u32 rsp_len = PLDM_MCTP_MAX_PAYLOAD;
	u8 *rsp;
	int ret;

	rsp = kmalloc(rsp_len, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	req[0] = MCTP_CTRL_HDR_REQUEST;		/* instance ID 0 */
	req[1] = PLDM_MCTP_CTRL_SET_EID;
	req[2] = PLDM_MCTP_CTRL_OP_FORCE_EID;
	req[3] = PLDM_MCTP_DEVICE_EID;

	ret = pldm_mctp_exchange(dd, port, PLDM_MCTP_TYPE_CONTROL,
				 PLDM_MCTP_BROADCAST_EID, req, sizeof(req),
				 rsp, &rsp_len);
	if (ret)
		goto out;

	/*
	 * Past the control header the reply is a completion code, the
	 * assignment status, then the endpoint ID in effect.
	 */
	if (rsp_len < PLDM_MCTP_CTRL_HDR_BYTES + 3) {
		dd_dev_err(dd, "PLDM: SetEndpointID reply is only %u bytes\n",
			   rsp_len);
		ret = -EPROTO;
		goto out;
	}

	/* The device echoes our instance ID and command with the request bit clear. */
	if (rsp[0] != 0 || rsp[1] != PLDM_MCTP_CTRL_SET_EID) {
		dd_dev_err(dd, "PLDM: SetEndpointID reply carries header 0x%02x 0x%02x\n",
			   rsp[0], rsp[1]);
		ret = -EPROTO;
		goto out;
	}

	if (rsp[PLDM_MCTP_CTRL_HDR_BYTES] != PLDM_MCTP_CTRL_SUCCESS) {
		dd_dev_err(dd, "PLDM: SetEndpointID failed, completion code 0x%02x\n",
			   rsp[PLDM_MCTP_CTRL_HDR_BYTES]);
		ret = -EREMOTEIO;
		goto out;
	}

	if (rsp[PLDM_MCTP_CTRL_HDR_BYTES + 2] != PLDM_MCTP_DEVICE_EID) {
		dd_dev_err(dd, "PLDM: device reports endpoint ID 0x%02x after being assigned 0x%02x\n",
			   rsp[PLDM_MCTP_CTRL_HDR_BYTES + 2], PLDM_MCTP_DEVICE_EID);
		ret = -EPROTO;
		goto out;
	}

out:
	kfree(rsp);
	return ret;
}
