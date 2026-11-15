/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_PLDM_MCTP_H
#define _HFI2_PLDM_MCTP_H

#include <linux/bits.h>
#include <linux/types.h>

struct hfi2_devdata;

/*
 * MCTP over OPA MAD framing for in-kernel PLDM firmware update.
 *
 * The firmware device and the update agent exchange PLDM messages carried in
 * MCTP packets, which in turn ride inside directed-route OPA SMPs with
 * attribute ID 0xff30.  This mirrors the framing the userspace updateAgent
 * builds in pldmUpdateAgent/mctp.c and updateAgentMad.c, so that the firmware
 * device cannot tell a kernel responder from the userspace one.
 *
 * Layout inside the SMP data area:
 *
 *	+0  MCTP over MAD binding	4 bytes
 *	+4  MCTP transport header	4 bytes
 *	+8  MCTP message type		1 byte
 *	+9  PLDM message		variable
 */

/* Endpoint IDs, fixed to match the userspace agent and the firmware device. */
#define PLDM_MCTP_UA_EID		0x0a
#define PLDM_MCTP_DEVICE_EID		0x09
#define PLDM_MCTP_NULL_EID		0x00
#define PLDM_MCTP_BROADCAST_EID		0xff

/* MCTP message types (DSP0236 table 1). */
#define PLDM_MCTP_TYPE_CONTROL		0x00
#define PLDM_MCTP_TYPE_PLDM		0x01

/* MCTP control commands and completion code (DSP0236 table 12). */
#define PLDM_MCTP_CTRL_SET_EID		0x01
#define PLDM_MCTP_CTRL_GET_EID		0x02
#define PLDM_MCTP_CTRL_OP_FORCE_EID	0x01
#define PLDM_MCTP_CTRL_SUCCESS		0x00

/* Header sizes. */
#define PLDM_MCTP_BINDING_BYTES		4
#define PLDM_MCTP_HDR_BYTES		4
#define PLDM_MCTP_TYPE_BYTES		1

/*
 * An MCTP control message carries its own two byte header ahead of the
 * command payload: the instance ID with the request bit, then the command.
 */
#define PLDM_MCTP_CTRL_HDR_BYTES	2

#define PLDM_MCTP_PAYLOAD_OFFSET	(PLDM_MCTP_BINDING_BYTES + \
					 PLDM_MCTP_HDR_BYTES + \
					 PLDM_MCTP_TYPE_BYTES)

/*
 * The PLDM message header is three bytes: instance ID with the request and
 * datagram bits, then the type, then the command.  A response adds a
 * completion code byte.  These live here rather than in pldm_ua.h because
 * the transport has to size and classify a message before the state machine
 * ever sees it, and two copies of the same number is how they drift.
 */
#define PLDM_HDR_LEN			3
#define PLDM_RSP_HDR_LEN		4

#define PLDM_HDR_REQUEST		BIT(7)
#define PLDM_HDR_DATAGRAM		BIT(6)
#define PLDM_HDR_INSTANCE_MASK		GENMASK(4, 0)

/*
 * Largest PLDM message that fits one MAD.  A MAD is capped at 1024 bytes and
 * the four MCTP-over-MAD binding bytes plus the MCTP header and message type
 * come out of that budget.  The firmware device uses the same figure
 * (MCTP_MAD_DATA_BYTES_PER_MSG in jkrMCTP.c), and neither side fragments, so
 * every message must fit here.
 */
#define PLDM_MCTP_MAX_PAYLOAD		(1024 - PLDM_MCTP_PAYLOAD_OFFSET)

/**
 * struct pldm_mctp_msg - one decoded MCTP message
 * @payload: start of the MCTP message payload, past the type byte
 * @payload_len: length of @payload
 * @src_eid: source endpoint ID
 * @dst_eid: destination endpoint ID
 * @msg_tag: MCTP message tag, echoed back on the response
 * @tag_owner: set when this is a request
 * @type: MCTP message type
 */
struct pldm_mctp_msg {
	const u8 *payload;
	u32 payload_len;
	u8 src_eid;
	u8 dst_eid;
	u8 msg_tag;
	bool tag_owner;
	u8 type;
};

/**
 * struct pldm_mad_req - a decoded inbound MCTP-over-MAD request
 * @msg: the MCTP message it carried
 * @tid: MAD transaction ID, which must be echoed on the response
 *
 * The firmware device tracks its outstanding request by MAD transaction ID
 * and drops any response that does not carry it back (madUtilPktTidClear in
 * jkrMadUtil.c), so @tid has to survive into the reply.
 */
struct pldm_mad_req {
	struct pldm_mctp_msg msg;
	__be64 tid;
};

int pldm_mad_decode(struct hfi2_devdata *dd, const void *mad, int len,
		    struct pldm_mad_req *req);
int pldm_mad_send_rsp(struct hfi2_devdata *dd, u8 port,
		      const struct pldm_mad_req *req,
		      const void *pldm, u32 pldm_len);
int pldm_mad_send_req(struct hfi2_devdata *dd, u8 port,
		      const void *pldm, u32 pldm_len,
		      void *rsp, u32 *rsp_len);
int pldm_mctp_set_eid(struct hfi2_devdata *dd, u8 port);

#endif /* _HFI2_PLDM_MCTP_H */
