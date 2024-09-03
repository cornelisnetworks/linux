// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#include "hfi.h"
#include "user_sdma.h"
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
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_assign_ctxt_cmd cmd;
	unsigned int swmajor;
	int ret;

	ret = uverbs_copy_from(&cmd, attrs, HFI1_ATTR_ASSIGN_CTXT_CMD);
	if (ret)
		return ret;

	swmajor = cmd.userversion >> HFI1_SWMAJOR_SHIFT;
	if (swmajor != HFI1_RDMA_USER_SWMAJOR)
		return -ENODEV;

	if (cmd.reserved1 != 0 || cmd.reserved2 != 0)
		return -EINVAL;

	return hfi1_do_assign_ctxt(fd, &cmd);
};

static int UVERBS_HANDLER(HFI1_METHOD_CTXT_INFO)(
	struct uverbs_attr_bundle *attrs)
{
	struct hfi1_filedata *fd = fd_from_attrs(attrs);
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_ctxt_info_rsp rsp = {};

	if (!uctxt)
		return -EINVAL;

	rsp.runtime_flags = (((uctxt->flags >> HFI1_CAP_MISC_SHIFT) &
				HFI1_CAP_MISC_MASK) << HFI1_CAP_USER_SHIFT) |
			    HFI1_CAP_UGET_MASK(uctxt->flags, MASK) |
			    HFI1_CAP_KGET_MASK(uctxt->flags, K2U);
	/* adjust flag if this fd is not able to cache */
	if (!fd->use_mn)
		rsp.runtime_flags |= HFI1_CAP_TID_UNMAP; /* no caching */

	rsp.num_active = hfi1_count_active_units();
	rsp.unit = uctxt->dd->unit;
	rsp.ctxt = uctxt->ctxt;
	rsp.subctxt = fd->subctxt;
	rsp.rcvtids = roundup(uctxt->egrbufs.alloced,
			      uctxt->dd->rcv_entries.group_size) +
		      uctxt->expected_count;
	rsp.credits = uctxt->sc->credits;
	rsp.numa_node = uctxt->numa_id;
	rsp.rec_cpu = fd->rec_cpu_num;
	rsp.send_ctxt = uctxt->sc->hw_context;

	rsp.egrtids = uctxt->egrbufs.alloced;
	rsp.rcvhdrq_cnt = get_hdrq_cnt(uctxt);
	rsp.rcvhdrq_entsize = get_hdrqentsize(uctxt) << 2;
	rsp.sdma_ring_size = fd->cq->nentries;
	rsp.rcvegr_size = uctxt->egrbufs.rcvtid_size;

	return uverbs_copy_to(attrs, HFI1_ATTR_CTXT_INFO_RSP, &rsp,
			      sizeof(rsp));
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
	struct hfi1_get_vers_rsp rsp = {};

	rsp.version = HFI1_RDMA_USER_SWVERSION;
	return uverbs_copy_to(attrs, HFI1_ATTR_GET_VERS_RSP, &rsp, sizeof(rsp));
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
