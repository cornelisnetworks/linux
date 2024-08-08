/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2015 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2015 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _LINUX__HFI1_IOCTL_H
#define _LINUX__HFI1_IOCTL_H
#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>

/*
 * This structure is passed to the driver to tell it where
 * user code buffers are, sizes, etc.   The offsets and sizes of the
 * fields must remain unchanged, for binary compatibility.  It can
 * be extended, if userversion is changed so user code can tell, if needed
 */
struct hfi1_user_info {
	/*
	 * version of user software, to detect compatibility issues.
	 * Should be set to HFI1_USER_SWVERSION.
	 */
	__u32 userversion;
	__u32 pad;
	/*
	 * If two or more processes wish to share a context, each process
	 * must set the subcontext_cnt and subcontext_id to the same
	 * values.  The only restriction on the subcontext_id is that
	 * it be unique for a given node.
	 */
	__u16 subctxt_cnt;
	__u16 subctxt_id;
	/* 128bit UUID passed in by PSM. */
	__u8 uuid[16];
};

struct hfi1_ctxt_info {
	__aligned_u64 runtime_flags;    /* chip/drv runtime flags (HFI1_CAP_*) */
	__u32 rcvegr_size;      /* size of each eager buffer */
	__u16 num_active;       /* number of active units */
	__u16 unit;             /* unit (chip) assigned to caller */
	__u16 ctxt;             /* ctxt on unit assigned to caller */
	__u16 subctxt;          /* subctxt on unit assigned to caller */
	__u16 rcvtids;          /* number of Rcv TIDs for this context */
	__u16 credits;          /* number of PIO credits for this context */
	__u16 numa_node;        /* NUMA node of the assigned device */
	__u16 rec_cpu;          /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt;        /* send context in use by this user context */
	__u16 egrtids;          /* number of RcvArray entries for Eager Rcvs */
	__u16 rcvhdrq_cnt;      /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize;  /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size;   /* number of entries in SDMA request ring */
};

struct hfi1_tid_info {
	/* virtual address of first page in transfer */
	__aligned_u64 vaddr;
	/* pointer to tid array. this array is big enough */
	__aligned_u64 tidlist;
	/* number of tids programmed by this request */
	__u32 tidcnt;
	/* length of transfer buffer programmed by this request */
	__u32 length;
};

/*
 * This structure is returned by the driver immediately after
 * open to get implementation-specific info, and info specific to this
 * instance.
 *
 * This struct must have explicit pad fields where type sizes
 * may result in different alignments between 32 and 64 bit
 * programs, since the 64 bit * bit kernel requires the user code
 * to have matching offsets
 */
struct hfi1_base_info {
	/* version of hardware, for feature checking. */
	__u32 hw_version;
	/* version of software, for feature checking. */
	__u32 sw_version;
	/* Job key */
	__u16 jkey;
	__u16 padding1;
	/*
	 * The special QP (queue pair) value that identifies PSM
	 * protocol packet from standard IB packets.
	 */
	__u32 bthqp;
	/* PIO credit return address, */
	__aligned_u64 sc_credits_addr;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase_sop;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase;
	/* address where receive buffer queue is mapped into */
	__aligned_u64 rcvhdr_bufbase;
	/* base address of Eager receive buffers. */
	__aligned_u64 rcvegr_bufbase;
	/* base address of SDMA completion ring */
	__aligned_u64 sdma_comp_bufbase;
	/*
	 * User register base for init code, not to be used directly by
	 * protocol or applications.  Always maps real chip register space.
	 * the register addresses are:
	 * ur_rcvhdrhead, ur_rcvhdrtail, ur_rcvegrhead, ur_rcvegrtail,
	 * ur_rcvtidflow
	 */
	__aligned_u64 user_regbase;
	/* notification events */
	__aligned_u64 events_bufbase;
	/* status page */
	__aligned_u64 status_bufbase;
	/* rcvhdrtail update */
	__aligned_u64 rcvhdrtail_base;
	/*
	 * shared memory pages for subctxts if ctxt is shared; these cover
	 * all the processes in the group sharing a single context.
	 * all have enough space for the num_subcontexts value on this job.
	 */
	__aligned_u64 subctxt_uregbase;
	__aligned_u64 subctxt_rcvegrbuf;
	__aligned_u64 subctxt_rcvhdrbuf;
};

/*
 * RDMA character device ioctls
 */

/* verbs objects */
enum hfi1_objects {
	HFI1_OBJECT_DV0 = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_OBJECT_DV1,
};

/* methods for custom objects dv0 and dv1 - max of 8 per object */
enum hfi1_methods_dv0 {
	HFI1_METHOD_ASSIGN_CTXT = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_METHOD_CTXT_INFO,
	HFI1_METHOD_USER_INFO,
	HFI1_METHOD_TID_UPDATE,
	HFI1_METHOD_TID_FREE,
	HFI1_METHOD_CREDIT_UPD,
	HFI1_METHOD_RECV_CTRL,
	HFI1_METHOD_POLL_TYPE,
};

enum hfi1_methods_dv1 {
	HFI1_METHOD_ACK_EVENT = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_METHOD_SET_PKEY,
	HFI1_METHOD_CTXT_RESET,
	HFI1_METHOD_TID_INVAL_READ,
	HFI1_METHOD_GET_VERS,
};

/*
 * assign_ctxt
 */
enum hfi1_attrs_assign_ctxt {
	HFI1_ATTR_ASSIGN_CTXT_CMD = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi1_assign_ctxt_cmd {
	__u32 userversion;	/* user library version */
	__u8 port;		/* target port number */
	__u8 kdeth_rcvhdrsz;	/* 0 means default */
	__u16 reserved1;
	__u16 subctxt_cnt;
	__u16 subctxt_id;
	__u8 uuid[16];		/* 128bit UUID */
	__u32 reserved2;
};

/*
 * ctxt_info
 */
enum hfi1_attrs_ctxt_info {
	HFI1_ATTR_CTXT_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi1_ctxt_info_rsp {
	__aligned_u64 runtime_flags; /* chip/drv runtime flags (HFI1_CAP_*) */

	__u32 rcvegr_size;      /* size of each eager buffer */
	__u16 num_active;       /* number of active units */
	__u16 unit;             /* unit (chip) assigned to caller */

	__u16 ctxt;             /* ctxt on unit assigned to caller */
	__u16 subctxt;          /* subctxt on unit assigned to caller */
	__u16 rcvtids;          /* number of Rcv TIDs for this context */
	__u16 credits;          /* number of PIO credits for this context */

	__u16 numa_node;        /* NUMA node of the assigned device */
	__u16 rec_cpu;          /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt;        /* send context in use by this user context */
	__u16 egrtids;          /* number of RcvArray entries for Eager Rcvs */

	__u16 rcvhdrq_cnt;      /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize;  /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size;   /* number of entries in SDMA request ring */
	__u16 reserved;
};

/*
 * user_info
 */
enum hfi1_attrs_user_info {
	HFI1_ATTR_USER_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

/*
 * Returns both general and specific information to this device open.
 */
struct hfi1_user_info_rsp {
	/* version of hardware, for feature checking. */
	__u32 hw_version;
	/* version of software, for feature checking. */
	__u32 sw_version;
	/* Job key */
	__u16 jkey;
	__u16 reserved;
	/*
	 * The special QP (queue pair) value that identifies PSM/OPX
	 * protocol packet from standard IB packets.
	 */
	__u32 bthqp;
	/* PIO credit return address */
	__aligned_u64 sc_credits_addr;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase_sop;
	/*
	 * Base address of write-only pio buffers for this process.
	 * Each buffer has sendpio_credits*64 bytes.
	 */
	__aligned_u64 pio_bufbase;
	/* address where receive buffer queue is mapped into */
	__aligned_u64 rcvhdr_bufbase;
	/* base address of Eager receive buffers. */
	__aligned_u64 rcvegr_bufbase;
	/* base address of SDMA completion ring */
	__aligned_u64 sdma_comp_bufbase;
	/*
	 * User register base for init code, not to be used directly by
	 * protocol or applications.  Always maps real chip register space.
	 * the register addresses are:
	 * ur_rcvhdrhead, ur_rcvhdrtail, ur_rcvegrhead, ur_rcvegrtail,
	 * ur_rcvtidflow
	 */
	__aligned_u64 user_regbase;
	/* notification events */
	__aligned_u64 events_bufbase;
	/* status page */
	__aligned_u64 status_bufbase;
	/* rcvhdrtail update */
	__aligned_u64 rcvhdrtail_base;
	/*
	 * Shared memory pages for subctxts if ctxt is shared.  These cover
	 * all the processes in the group sharing a single context.
	 * All have enough space for the num_subcontexts value on this job.
	 */
	__aligned_u64 subctxt_uregbase;
	__aligned_u64 subctxt_rcvegrbuf;
	__aligned_u64 subctxt_rcvhdrbuf;
	/* receive header error queue */
	__aligned_u64 rheq_bufbase;
};

/*
 * tid_update
 */
enum hfi1_attrs_tid_update {
	HFI1_ATTR_TID_UPDATE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_ATTR_TID_UPDATE_RSP,
};

struct hfi1_tid_update_cmd {
	__aligned_u64 vaddr;	/* virtual address of buffer */
	__aligned_u64 tidlist;	/* address of output tid array */
	__u32 length;		/* buffer length, in bytes */
	__u32 tidcnt;		/* tidlist size, in TIDs */
	__aligned_u64 flags;	/* flags: [3:0] mem type, [63:4] reserved */
	__aligned_u64 context;	/* reserved */
};

struct hfi1_tid_update_rsp {
	__u32 length;		/* mapped buffer length */
	__u32 tidcnt;		/* number of assigned TIDs */
};

/*
 * tid_free
 */
enum hfi1_attrs_tid_free {
	HFI1_ATTR_TID_FREE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_ATTR_TID_FREE_RSP,
};

struct hfi1_tid_free_cmd {
	__aligned_u64 tidlist;  /* user buffer pointer */
	__u32 tidcnt;           /* number of TID entries in buffer */
	__u32 reserved;
};

struct hfi1_tid_free_rsp {
	__u32 tidcnt;		/* number actually freed */
	__u32 reserved;
};

/*
 * credit_upd
 * (no arguments)
 */

/*
 * recv_ctrl
 */
enum hfi1_attrs_recv_ctrl {
	HFI1_ATTR_RECV_CTRL_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi1_recv_ctrl_cmd {
	__u8 start_stop;
	__u8 reserved[7];
};

/*
 * poll_type
 */
enum hfi1_attrs_poll_type {
	HFI1_ATTR_POLL_TYPE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi1_poll_type_cmd {
	__u32 poll_type;
	__u32 reserved;
};

/*
 * ack_event
 */
enum hfi1_attrs_ack_event {
	HFI1_ATTR_ACK_EVENT_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi1_ack_event_cmd {
	__u64 event;
};

/*
 * set_pkey
 */
enum hfi1_attrs_set_pkey {
	HFI1_ATTR_SET_PKEY_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi1_set_pkey_cmd {
	__u16 pkey;
	__u8 reserved[6];
};

/*
 * ctxt_reset
 * (no arguments)
 */

/*
 * tid_inval_read
 */
enum hfi1_attrs_tid_inval_read {
	HFI1_ATTR_TID_INVAL_READ_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI1_ATTR_TID_INVAL_READ_RSP,
};

struct hfi1_tid_inval_read_cmd {
	__aligned_u64 tidlist;  /* user buffer pointer */
	__u32 tidcnt;		/* space for this many TIDs */
	__u32 reserved;
};

struct hfi1_tid_inval_read_rsp {
	__u32 tidcnt;           /* numnber of returned tids */
	__u32 reserved;
};

/*
 * get_vers
 */
enum hfi1_attrs_get_vers {
	/* no cmd */
	HFI1_ATTR_GET_VERS_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi1_get_vers_rsp {
	__u32 version;
	__u32 reserved;
};

#endif /* _LINIUX__HFI1_IOCTL_H */
