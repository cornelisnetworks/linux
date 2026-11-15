/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_PLDM_UA_H
#define _HFI2_PLDM_UA_H

#include <linux/bits.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "pldm_mctp.h"
#include "pldm_pkg.h"

struct devlink;
struct hfi2_devdata;
struct netlink_ext_ack;

/*
 * In-kernel PLDM update agent (DSP0267), ported from the userspace
 * updateAgent.  This is the state machine half; pldm_mctp.c carries the
 * messages and pldm_pkg.c parses the package.
 */

/* PLDM message types (DSP0245 table 1). */
#define PLDM_TYPE_FIRMWARE_UPDATE	0x05

/* Firmware update command codes (DSP0267 table 6). */
#define PLDM_CMD_QUERY_DEVICE_IDENTIFIERS	0x01
#define PLDM_CMD_GET_FIRMWARE_PARAMETERS	0x02
#define PLDM_CMD_REQUEST_UPDATE			0x10
#define PLDM_CMD_PASS_COMPONENT_TABLE		0x13
#define PLDM_CMD_UPDATE_COMPONENT		0x14
#define PLDM_CMD_REQUEST_FIRMWARE_DATA		0x15
#define PLDM_CMD_TRANSFER_COMPLETE		0x16
#define PLDM_CMD_VERIFY_COMPLETE		0x17
#define PLDM_CMD_APPLY_COMPLETE			0x18
#define PLDM_CMD_ACTIVATE_FIRMWARE		0x1a
#define PLDM_CMD_GET_STATUS			0x1b
#define PLDM_CMD_CANCEL_UPDATE			0x1d

/* Base completion codes (DSP0240 table 7). */
#define PLDM_CC_SUCCESS				0x00
#define PLDM_CC_ERROR				0x01
#define PLDM_CC_INVALID_DATA			0x02
#define PLDM_CC_INVALID_LENGTH			0x03

/* Firmware update completion codes (DSP0267 table 7). */
#define PLDM_CC_DATA_OUT_OF_RANGE		0x82
#define PLDM_CC_INVALID_TRANSFER_LENGTH		0x83
#define PLDM_CC_COMMAND_NOT_EXPECTED		0x88

/* PassComponentTable transfer flags (DSP0267 table 14). */
#define PLDM_XFER_FLAG_START			0x01
#define PLDM_XFER_FLAG_MIDDLE			0x02
#define PLDM_XFER_FLAG_END			0x04
#define PLDM_XFER_FLAG_START_END		0x05

/* UpdateComponent updateOptionFlags (DSP0267 table 17). */
#define PLDM_UPDATE_OPT_FORCE			BIT(0)
#define PLDM_UPDATE_OPT_OPAQUE_DATA		BIT(1)

/* GetFirmwareParameters capabilitiesDuringUpdate (DSP0267 table 9). */
#define PLDM_CAP_PARTIAL_UPDATE			BIT(3)

/* GetStatus currentState (DSP0267 table 26). */
#define PLDM_FD_IDLE				0
#define PLDM_FD_LEARN_COMPONENTS		1
#define PLDM_FD_READY_XFER			2
#define PLDM_FD_DOWNLOAD			3
#define PLDM_FD_VERIFY				4
#define PLDM_FD_APPLY				5
#define PLDM_FD_ACTIVATE			6

/* GetStatus auxState (DSP0267 table 26). */
#define PLDM_AUX_IN_PROGRESS			0
#define PLDM_AUX_SUCCESSFUL			1
#define PLDM_AUX_FAILED				2
#define PLDM_AUX_IDLE				3

/*
 * The firmware device rounds its final RequestFirmwareData up to a multiple
 * of this, so the last request can ask for bytes past the end of the image
 * (jkrPldm.c sendRequestFirmwareData()).  We zero pad the difference.
 */
#define PLDM_MIN_TRANSFER_SIZE			32

/*
 * Largest image chunk we advertise in RequestUpdate.  Anything larger would
 * need MCTP fragmentation, which neither side implements.  This matches the
 * userspace agent's PLDM_BASE_TRANSFER_SIZE and stays under the firmware
 * device's own PLDM_MAX_TRANSFER_SIZE of 992.
 */
#define PLDM_MAX_TRANSFER_SIZE			992

/* We keep one request outstanding, as the userspace agent does. */
#define PLDM_MAX_OUTSTANDING_REQS		1

/* Version strings are at most 255 bytes plus a terminator. */
#define PLDM_VER_STRING_MAX			256

/* Largest response the firmware device sends us for a command. */
#define PLDM_RSP_MAX				1024

/**
 * enum pldm_ua_state - where the update agent is in the sequence
 * @PLDM_UA_IDLE: no component in progress
 * @PLDM_UA_DOWNLOAD: serving RequestFirmwareData for a component
 * @PLDM_UA_VERIFY: transfer done, waiting for VerifyComplete
 * @PLDM_UA_APPLY: verify done, waiting for ApplyComplete
 * @PLDM_UA_DONE: the current component finished
 *
 * The receive path advances this as each transition message arrives, so an
 * unexpected firmware device request can be rejected with
 * PLDM_CC_COMMAND_NOT_EXPECTED rather than acted on.  The flash thread only
 * reads it; it never drives it, because the firmware device can send the next
 * transition before the flash thread has noticed the previous one.
 */
enum pldm_ua_state {
	PLDM_UA_IDLE,
	PLDM_UA_DOWNLOAD,
	PLDM_UA_VERIFY,
	PLDM_UA_APPLY,
	PLDM_UA_DONE,
};

/**
 * enum pldm_ua_xfer - the three transition messages a component produces
 * @PLDM_UA_XFER_TRANSFER: TransferComplete
 * @PLDM_UA_XFER_VERIFY: VerifyComplete
 * @PLDM_UA_XFER_APPLY: ApplyComplete
 * @PLDM_UA_XFER_COUNT: array size
 */
enum pldm_ua_xfer {
	PLDM_UA_XFER_TRANSFER,
	PLDM_UA_XFER_VERIFY,
	PLDM_UA_XFER_APPLY,
	PLDM_UA_XFER_COUNT,
};

/**
 * struct pldm_ua_component_param - one entry of the component parameter table
 * @list: linked into &pldm_ua_params.components
 * @classification: componentClassification
 * @identifier: componentIdentifier
 * @classification_index: componentClassificationIndex
 * @active_comparison_stamp: activeComponentComparisonStamp
 * @active_ver_string: activeComponentVersionString, NUL terminated
 * @pending_ver_string: pendingComponentVersionString, NUL terminated
 * @activation_methods: componentActivationMethods
 * @capabilities: capabilitiesDuringUpdate for this component
 */
struct pldm_ua_component_param {
	struct list_head list;
	u16 classification;
	u16 identifier;
	u8 classification_index;
	u32 active_comparison_stamp;
	u8 active_ver_string[PLDM_VER_STRING_MAX];
	u8 pending_ver_string[PLDM_VER_STRING_MAX];
	u16 activation_methods;
	u32 capabilities;
};

/**
 * struct pldm_ua_params - decoded GetFirmwareParameters response
 * @capabilities: capabilitiesDuringUpdate for the device
 * @component_count: number of entries on @components
 * @active_image_set_ver: activeComponentImageSetVersionString
 * @pending_image_set_ver: pendingComponentImageSetVersionString
 * @components: list of &pldm_ua_component_param, in device-reported order
 *
 * The device-reported order matters: components must be offered back in the
 * same order during the update.
 */
struct pldm_ua_params {
	u32 capabilities;
	u16 component_count;
	u8 active_image_set_ver[PLDM_VER_STRING_MAX];
	u8 pending_image_set_ver[PLDM_VER_STRING_MAX];
	struct list_head components;
};

/**
 * struct pldm_ua - one firmware update session
 * @dd: the device being updated
 * @port: 1-based port number used as the CPORT sideband
 * @pkg: the parsed package
 * @extack: netlink error reporting, may be NULL
 * @instance_id: rolling PLDM instance ID for our requests
 * @lock: guards everything the receive path writes
 * @wait: woken when a transition arrives or a data request is served
 * @state: how far through the current component the firmware device is
 * @generation: bumped for each component, to date the entries below
 * @got_gen: generation in which each transition was latched, 0 for never
 * @ack_gen: generation for which each transition was successfully answered
 * @result: the result byte each one carried
 * @last_xfer: the most recently latched transition
 * @last_instance: its PLDM instance ID
 * @last_gen: the generation it was latched in
 * @last_valid: false until the first transition of the session
 * @rx_err: set when the receive path fails outside the protocol
 * @comp: the component currently being written
 * @comp_index: its position in the update order, for progress reporting
 * @comp_total: how many components this update covers
 * @bytes_sent: image bytes served for @comp so far
 * @data_seen: jiffies of the last data request served, for the idle deadline
 * @update_started: true once RequestUpdate succeeded, so cleanup must cancel
 * @activating: true once ActivateFirmware has gone out, so cleanup must not
 * @devlink: the instance to report progress on, may be NULL
 * @cmd_buf: flash-thread scratch buffer for raw PLDM command replies
 * @rsp_buf: flash-thread scratch buffer for decoded PLDM command payloads
 *
 * The flash thread owns the session; the receive path runs on the CPORT
 * workqueue and must never wait for it, so it serves RequestFirmwareData
 * itself and records the transitions for the flash thread to collect.
 *
 * @state is advanced by the receive path alone.  The firmware device can send
 * the next transition before the flash thread has noticed the previous one,
 * so the flash thread must not be the one moving the phase along, and the
 * results are latched per phase rather than overwriting a single slot.
 *
 * The firmware device sends one transition at a time and will not move on
 * until it has been answered, retransmitting the same message until then
 * (stateTransitionResponsePending in jkrPldm.c).  So the only duplicate that
 * can ever be in flight is a copy of the most recently latched transition,
 * which is what @last_xfer and friends record.  A five-bit instance ID
 * cannot do that job on its own: the device reuses it, and it wraps within
 * a single component's transfer.
 *
 * The flash thread waits for both @got_gen and @ack_gen to reach the current
 * generation: the transition has to have arrived and our answer to it has to
 * have been sent, or the device is still waiting on us.
 */
struct pldm_ua {
	struct hfi2_devdata *dd;
	u8 port;
	struct pldm_pkg *pkg;
	struct netlink_ext_ack *extack;

	u8 instance_id;

	/* guards everything the receive path writes */
	spinlock_t lock;
	wait_queue_head_t wait;
	enum pldm_ua_state state;
	u32 generation;
	u32 got_gen[PLDM_UA_XFER_COUNT];
	u32 ack_gen[PLDM_UA_XFER_COUNT];
	u8 result[PLDM_UA_XFER_COUNT];

	enum pldm_ua_xfer last_xfer;
	u8 last_instance;
	u32 last_gen;
	bool last_valid;

	int rx_err;

	const struct pldm_pkg_component *comp;
	unsigned int comp_index;
	unsigned int comp_total;
	u32 bytes_sent;
	unsigned long data_seen;

	bool update_started;
	bool activating;

	struct devlink *devlink;

	u8 cmd_buf[PLDM_RSP_MAX];
	u8 rsp_buf[PLDM_RSP_MAX];
};

int pldm_ua_init(struct hfi2_devdata *dd);
void pldm_ua_exit(struct hfi2_devdata *dd);

int pldm_ua_flash(struct hfi2_devdata *dd, struct devlink *devlink,
		  const struct firmware *fw, struct netlink_ext_ack *extack);
int pldm_ua_get_params(struct hfi2_devdata *dd, struct pldm_ua_params *params);
void pldm_ua_free_params(struct pldm_ua_params *params);

int pldm_ua_recv(struct hfi2_devdata *dd, u8 port, const void *mad, int len);

#endif /* _HFI2_PLDM_UA_H */
