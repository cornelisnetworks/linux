/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_FILE_OPS_H
#define _HFI2_FILE_OPS_H

#include <rdma/uverbs_ioctl.h>
#include "hfi2.h"
#include "bulksvc_user.h"
#include "uverbs.h"

int hfi2_set_uevent_bits(struct hfi2_pportdata *ppd, const int evtbit);
struct hfi2_filedata *hfi2_alloc_filedata(struct hfi2_devdata *dd);
void hfi2_dealloc_filedata(struct hfi2_filedata *fdata);
void hfi2_filedata_release(struct kref *kref);
int hfi2_do_assign_ctxt(struct hfi2_filedata *fd,
			const struct hfi2_assign_ctxt_cmd *uinfo);
int hfi2_manage_rcvq(struct hfi2_ctxtdata *uctxt, u16 subctxt, int start_stop);
int hfi2_user_event_ack(struct hfi2_ctxtdata *uctxt, u16 subctxt,
		   unsigned long events);
int hfi2_user_set_ctxt_pkey(struct hfi2_ctxtdata *uctxt, u16 pkey);
int hfi2_ctxt_reset(struct hfi2_filedata *fd);
int hfi2_get_pinning_stats(struct hfi2_filedata *fd,
			   struct hfi2_pin_stats *stats);
int hfi2_do_mmap(struct hfi2_filedata *fd, u8 type, struct vm_area_struct *vma,
		 struct rdma_user_mmap_entry *rdma_entry,
		 struct ib_ucontext *ucontext);
ssize_t hfi2_do_write_iter(struct hfi2_filedata *fd, struct iov_iter *from);
void hfi2_set_sc_uevent_bits(struct hfi2_pportdata *ppd, int bit);
unsigned long hfi2_build_runtime_flags(unsigned long flags, bool use_mn);
int user_sc_event_ack(struct hfi2_filedata *fd, unsigned long events);
int user_sc_set_ctxt_pkey(struct send_context *sc, u16 pkey);

/*
 * Types of memories mapped into user processes' space
 */
enum mmap_types {
	PIO_BUFS = 1,
	PIO_BUFS_SOP,
	PIO_CRED,
	RCV_HDRQ,
	RCV_EGRBUF,
	UREGS,
	EVENTS,
	STATUS,
	RTAIL,
	SUBCTXT_UREGS,
	SUBCTXT_RCV_HDRQ,
	SUBCTXT_EGRBUF,
	SDMA_COMP,
	RCV_RHEQ,
	BULKSVC_FAST_DOORBELL,
	/* Range of values reserved for each bulksvc queue-related mmap type */
	BULKSVC_QUEUE_TYPES_FIRST,
	BULKSVC_CMPLQ_CTRL0 = BULKSVC_QUEUE_TYPES_FIRST,
	BULKSVC_CMPLQ_BUF0 = BULKSVC_CMPLQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMPLQS,
	BULKSVC_CMDQ_CTRL0 = BULKSVC_CMPLQ_BUF0 + BULKSVC_USER_MAX_NUM_CMPLQS,
	BULKSVC_CMDQ_BUF0 = BULKSVC_CMDQ_CTRL0 + BULKSVC_USER_MAX_NUM_CMDQS,
	BULKSVC_QUEUE_TYPES_LAST = BULKSVC_CMDQ_BUF0 + BULKSVC_USER_MAX_NUM_CMDQS - 1,
	BULKSVC_DIRTY_BITMAP,
	/* Range of values reserved for each bulksvc cntr mmap type */
	BULKSVC_CNTR_PAGE_FIRST,
	BULKSVC_CNTR_PAGE0 = BULKSVC_CNTR_PAGE_FIRST,
	BULKSVC_CNTR_PAGE_LAST = BULKSVC_CNTR_PAGE0 + BULKSVC_USER_MAX_NUM_CNTR_PAGES - 1,
	MMAP_TYPE_MAX,
};

/* hfi2.h sizes fd->mmap_entries[] from this constant; catch drift. */
static_assert(MMAP_TYPE_MAX == HFI2_MMAP_TYPE_MAX);

int create_bulksvc_queue(struct ib_ucontext *ucontext,
			 struct hfi2_filedata *fd,
			 struct hfi2_devdata *dd,
			 struct hfi2_bulksvc_user_info *const bulksvc_user_info,
			 bool is_cmplq,
			 struct hfi2_bulksvc_queue_info **output_info);
int create_bulksvc_cntr(struct ib_ucontext *ucontext,
			struct hfi2_filedata *fd,
			struct hfi2_devdata *dd,
			struct hfi2_bulksvc_user_info *const bulksvc_user_info,
			struct hfi2_bulksvc_cntr_info **output_info);
int init_bulksvc_client(struct ib_ucontext *ucontext,
			struct hfi2_filedata *fd,
			struct hfi2_bulksvc_client_init *out,
			struct hfi2_bulksvc_user_info **info_out);
int do_bulksvc_synccmd(struct hfi2_filedata *fd, struct hfi2_bulksvc_cmd *cmd);
int release_bulksvc_queue_slot(struct hfi2_filedata *fd,
			       struct hfi2_bulksvc_user_info *bulksvc_user_info,
			       bool is_cmplq, u32 queue_id);

#endif /* _HFI2_FILE_OPS_H */
