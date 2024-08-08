// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#include "hfi.h"
#include "uverbs.h"
#include "file_ops.h"

#define UVERBS_MODULE_NAME hfi1_uv
#include <rdma/uverbs_named_ioctl.h>

int hfi1_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata)
{
	struct hfi1_devdata *dd = dd_from_ibdev(ucontext->device);
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = hfi1_alloc_filedata(dd);
	if (!fd)
		return -ENOMEM;

	rcontext->priv = fd;

	return 0;
}

void hfi1_dealloc_ucontext(struct ib_ucontext *ucontext)
{
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = rcontext->priv;
	if (fd) {
		hfi1_dealloc_filedata(fd);
		rcontext->priv = NULL;
	}
}

static inline struct hfi1_filedata *fd_from_attrs(struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = ib_uverbs_get_ucontext(attrs);
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);

	return rcontext->priv;
}

static int UVERBS_HANDLER(HFI1_METHOD_ASSIGN_CTXT)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_CTXT_INFO)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_USER_INFO)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_UPDATE)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_FREE)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_CREDIT_UPD)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_RECV_CTRL)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_POLL_TYPE)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_ACK_EVENT)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_SET_PKEY)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_CTXT_RESET)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_TID_INVAL_READ)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

static int UVERBS_HANDLER(HFI1_METHOD_GET_VERS)(
	struct uverbs_attr_bundle *attrs)
{
	return -EOPNOTSUPP;
};

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_ASSIGN_CTXT,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_ASSIGN_CTXT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_assign_ctxt_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CTXT_INFO,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_CTXT_INFO_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_ctxt_info_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_USER_INFO,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_USER_INFO_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_user_info_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_UPDATE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_UPDATE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_update_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_UPDATE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_update_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_FREE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_FREE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_free_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_FREE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_free_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CREDIT_UPD,
	/* no arguments */
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_RECV_CTRL,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_RECV_CTRL_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_recv_ctrl_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_POLL_TYPE,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_POLL_TYPE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_poll_type_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_ACK_EVENT,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_ACK_EVENT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_ack_event_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_SET_PKEY,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_SET_PKEY_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_set_pkey_cmd),
			   UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_CTXT_RESET,
	/* no arguments */
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_TID_INVAL_READ,
	UVERBS_ATTR_PTR_IN(HFI1_ATTR_TID_INVAL_READ_CMD,
			   UVERBS_ATTR_TYPE(struct hfi1_tid_inval_read_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_TID_INVAL_READ_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_tid_inval_read_rsp),
			    UA_MANDATORY),
	);

DECLARE_UVERBS_NAMED_METHOD(HFI1_METHOD_GET_VERS,
	UVERBS_ATTR_PTR_OUT(HFI1_ATTR_GET_VERS_RSP,
			    UVERBS_ATTR_TYPE(struct hfi1_get_vers_rsp),
			    UA_MANDATORY),
	);


DECLARE_UVERBS_GLOBAL_METHODS(HFI1_OBJECT_DV0,
	&UVERBS_METHOD(HFI1_METHOD_ASSIGN_CTXT),
	&UVERBS_METHOD(HFI1_METHOD_CTXT_INFO),
	&UVERBS_METHOD(HFI1_METHOD_USER_INFO),
	&UVERBS_METHOD(HFI1_METHOD_TID_UPDATE),
	&UVERBS_METHOD(HFI1_METHOD_TID_FREE),
	&UVERBS_METHOD(HFI1_METHOD_CREDIT_UPD),
	&UVERBS_METHOD(HFI1_METHOD_RECV_CTRL),
	&UVERBS_METHOD(HFI1_METHOD_POLL_TYPE));

DECLARE_UVERBS_GLOBAL_METHODS(HFI1_OBJECT_DV1,
	&UVERBS_METHOD(HFI1_METHOD_ACK_EVENT),
	&UVERBS_METHOD(HFI1_METHOD_SET_PKEY),
	&UVERBS_METHOD(HFI1_METHOD_CTXT_RESET),
	&UVERBS_METHOD(HFI1_METHOD_TID_INVAL_READ),
	&UVERBS_METHOD(HFI1_METHOD_GET_VERS));

const struct uapi_definition hfi1_ib_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI1_OBJECT_DV0),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI1_OBJECT_DV1),
	{}
};
