/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/*
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#ifndef _LINUX_HFI2_USER_H
#define _LINUX_HFI2_USER_H

#include <linux/types.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/rdma_user_ioctl.h>

/* Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */
#define HFI2_UVERBS_ABI_VERSION 3

/* hfi2_user_info reserved1 flag bits */
#define HFI2_FLAG_SEND_ONLY 0x1

/*
 * Set of HW and driver capability/feature bits.
 * These bit values are used to configure enabled/disabled HW and
 * driver features. The same set of bits are communicated to user
 * space.
 */
#define HFI2_CAP_DMA_RTAIL (1UL << 0) /* Use DMA'ed RTail value */
#define HFI2_CAP_SDMA (1UL << 1) /* Enable SDMA support */
#define HFI2_CAP_SDMA_AHG (1UL << 2) /* Enable SDMA AHG support */
#define HFI2_CAP_EXTENDED_PSN (1UL << 3) /* Enable Extended PSN support */
#define HFI2_CAP_HDRSUPP (1UL << 4) /* Enable Header Suppression */
#define HFI2_CAP_TID_RDMA (1UL << 5) /* Enable TID RDMA operations */
#define HFI2_CAP_USE_SDMA_HEAD (1UL << 6) /* DMA Hdr Q tail vs. use CSR */
#define HFI2_CAP_MULTI_PKT_EGR (1UL << 7) /* Enable multi-packet Egr buffs*/
#define HFI2_CAP_NODROP_RHQ_FULL (1UL << 8) /* Don't drop on Hdr Q full */
#define HFI2_CAP_NODROP_EGR_FULL (1UL << 9) /* Don't drop on EGR buffs full */
#define HFI2_CAP_TID_UNMAP (1UL << 10) /* Disable Expected TID caching */
#define HFI2_CAP_PRINT_UNIMPL (1UL << 11) /* Show for unimplemented feats */
#define HFI2_CAP_ALLOW_PERM_JKEY (1UL << 12) /* Allow use of permissive JKEY */
#define HFI2_CAP_NO_INTEGRITY (1UL << 13) /* Enable ctxt integrity checks */
#define HFI2_CAP_PKEY_CHECK (1UL << 14) /* Enable ctxt PKey checking */
#define HFI2_CAP_STATIC_RATE_CTRL (1UL << 15) /* Allow PBC.StaticRateControl */
#define HFI2_CAP_OPFN (1UL << 16) /* Enable the OPFN protocol */
#define HFI2_CAP_SDMA_HEAD_CHECK (1UL << 17) /* SDMA head checking */
#define HFI2_CAP_EARLY_CREDIT_RETURN (1UL << 18) /* early credit return */
#define HFI2_CAP_AIP (1UL << 19) /* Enable accelerated IP */
#define HFI2_CAP_DMABUF (1UL << 20)


#define _HFI2_EVENT_FROZEN_BIT 0
#define _HFI2_EVENT_LINKDOWN_BIT 1
#define _HFI2_EVENT_LID_CHANGE_BIT 2
#define _HFI2_EVENT_LMC_CHANGE_BIT 3
#define HFI2_EVENT_SL2VL_CHANGE_BIT 4
#define HFI2_EVENT_SL2VL_CHANGE (1UL << HFI2_EVENT_SL2VL_CHANGE_BIT)
#define _HFI2_EVENT_TID_MMU_NOTIFY_BIT 5
#define _HFI2_MAX_EVENT_BIT _HFI2_EVENT_TID_MMU_NOTIFY_BIT

/*
 * These are the status bits readable (in ASCII form, 64bit value)
 * from the "status" sysfs file.  For binary compatibility, values
 * must remain as is; removed states can be reused for different
 * purposes.
 */
#define HFI2_STATUS_INITTED 0x1 /* basic initialization done */
/* Chip has been found and initialized */
#define HFI2_STATUS_CHIP_PRESENT 0x20
/* IB link is at ACTIVE, usable for data traffic */
#define HFI2_STATUS_IB_READY 0x40
/* link is configured, LID, MTU, etc. have been set */
#define HFI2_STATUS_IB_CONF 0x80
/* A Fatal hardware error has occurred. */
#define HFI2_STATUS_HWERROR 0x200

/*
 * Number of supported shared contexts.
 * This is the maximum number of software contexts that can share
 * a hardware send/receive context.
 */
#define HFI2_MAX_SHARED_CTXTS 8

/*
 * Poll types
 */
#define HFI2_POLL_TYPE_ANYRCV 0x0
#define HFI2_POLL_TYPE_URGENT 0x1

enum hfi2_sdma_comp_state { FREE = 0, QUEUED, COMPLETE, ERROR };

/*
 * SDMA completion ring entry
 */
struct hfi2_sdma_comp_entry {
	__u32 status;
	__u32 errcode;
};

/*
 * Device status and notifications from driver to user-space.
 */
/* c-stream v2 status: same layout, reserved for future extensions */
struct hfi2_status_v2 {
	__aligned_u64 dev;      /* device/hw status bits */
	__aligned_u64 ports[];  /* port state and status bits */
};

struct hfi2_status {
	__aligned_u64 dev; /* device/hw status bits */
	__aligned_u64 ports[]; /* port state and status bits */
};

enum sdma_req_opcode { EXPECTED = 0, EAGER };

#define HFI2_SDMA_REQ_VERSION_MASK 0xF
#define HFI2_SDMA_REQ_VERSION_SHIFT 0x0
#define HFI2_SDMA_REQ_OPCODE_MASK 0xF
#define HFI2_SDMA_REQ_OPCODE_SHIFT 0x4
#define HFI2_SDMA_REQ_IOVCNT_MASK 0x7F
#define HFI2_SDMA_REQ_IOVCNT_SHIFT 0x8
#define HFI2_SDMA_REQ_MEMINFO_MASK 0x1
#define HFI2_SDMA_REQ_MEMINFO_SHIFT 0xF

struct sdma_req_info {
	/*
	 * bits 0-3 - version (currently unused)
	 * bits 4-7 - opcode (enum sdma_req_opcode)
	 * bits 8-14 - io vector count
	 * bit  15 - meminfo present
	 */
	__u16 ctrl;
	/*
	 * Number of fragments contained in this request.
	 * User-space has already computed how many
	 * fragment-sized packet the user buffer will be
	 * split into.
	 */
	__u16 npkts;
	/*
	 * Size of each fragment the user buffer will be
	 * split into.
	 */
	__u16 fragsize;
	/*
	 * Index of the slot in the SDMA completion ring
	 * this request should be using. User-space is
	 * in charge of managing its own ring.
	 */
	__u16 comp_idx;
} __attribute__((__packed__));

#define HFI2_MEMINFO_TYPE_ENTRY_BITS 4
#define HFI2_MEMINFO_TYPE_ENTRY_MASK ((1 << HFI2_MEMINFO_TYPE_ENTRY_BITS) - 1)
#define HFI2_MEMINFO_TYPE_ENTRY_GET(m, n)                \
	(((m) >> ((n) * HFI2_MEMINFO_TYPE_ENTRY_BITS)) & \
	 HFI2_MEMINFO_TYPE_ENTRY_MASK)
#define HFI2_MEMINFO_TYPE_ENTRY_SET(m, n, e) \
	((m) |= ((e) & HFI2_MEMINFO_TYPE_ENTRY_MASK) \
	     << ((n) * HFI2_MEMINFO_TYPE_ENTRY_BITS))
#define HFI2_MAX_MEMINFO_ENTRIES \
	(sizeof(__u64) * 8 / HFI2_MEMINFO_TYPE_ENTRY_BITS)

#define HFI2_MEMINFO_TYPE_SYSTEM 0
/* HFI2_MEMINFO_TYPE_AMD (2) and HFI2_MEMINFO_TYPE_NVIDIA (3) are GPU-vendor
 * memory types added by the out-of-tree GPU patch; values 2 and 3 stay reserved.
 */
/* context[] carries a dma-buf fd. Must not reuse a type existing userspace sends. */
#define HFI2_MEMINFO_TYPE_DMABUF 4

#define HFI2_MEMINFO_CONTEXT_DMABUF_FD_MASK ((__u64)0xffffffff)
#define HFI2_MEMINFO_CONTEXT_DMABUF_RESERVED_MASK \
	(~HFI2_MEMINFO_CONTEXT_DMABUF_FD_MASK)

struct sdma_req_meminfo {
	/*
	 * Packed memory type indicators for each data iovec entry.
	 */
	__u64 types;
	/*
	 * Type-specific context for each data iovec entry.
	 */
	__u64 context[HFI2_MAX_MEMINFO_ENTRIES];
};

/*
 * SW KDETH header.
 * swdata is SW defined portion.
 */
struct hfi2_kdeth_header {
	__le32 ver_tid_offset;
	__le16 jkey;
	__le16 hcrc;
	__le32 swdata[7];
} __attribute__((__packed__));

/*
 * Structure describing the headers that User space uses. The
 * structure above is a subset of this one.
 */
struct hfi2_pkt_header {
	__le16 pbc[4];
	__be16 lrh[4];
	__be32 bth[3];
	struct hfi2_kdeth_header kdeth;
} __attribute__((__packed__));

/*
 * The list of usermode accessible registers.
 */
enum hfi2_ureg {
	/* (RO)  DMA RcvHdr to be used next. */
	ur_rcvhdrtail = 0,
	/* (RW)  RcvHdr entry to be processed next by host. */
	ur_rcvhdrhead = 1,
	/* (RO)  Index of next Eager index to use. */
	ur_rcvegrindextail = 2,
	/* (RW)  Eager TID to be processed next */
	ur_rcvegrindexhead = 3,
	/* (RO)  Receive Eager Offset Tail */
	ur_rcvegroffsettail = 4,
	/* For internal use only; max register number. */
	ur_maxreg,
	/* (RW)  Receive TID flow table */
	ur_rcvtidflowtable = 256
};

/*
 * This structure is passed to the driver to tell it where
 * user code buffers are, sizes, etc.   The offsets and sizes of the
 * fields must remain unchanged, for binary compatibility.  It can
 * be extended, if userversion is changed so user code can tell, if needed
 */
struct hfi2_user_info {
	/*
	 * version of user software, to detect compatibility issues.
	 * Should be set to HFI2_USER_SWVERSION.
	 */
	__u32 userversion;
	__u32 pad; /* Port Address */
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

struct hfi2_ctxt_info {
	__aligned_u64 runtime_flags; /* chip/drv runtime flags (HFI2_CAP_*) */
	__u32 rcvegr_size; /* size of each eager buffer */
	__u16 num_active; /* number of active units */
	__u16 unit; /* unit (chip) assigned to caller */
	__u16 ctxt; /* ctxt on unit assigned to caller */
	__u16 subctxt; /* subctxt on unit assigned to caller */
	__u16 rcvtids; /* number of Rcv TIDs for this context */
	__u16 credits; /* number of PIO credits for this context */
	__u16 numa_node; /* NUMA node of the assigned device */
	__u16 rec_cpu; /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt; /* send context in use by this user context */
	__u16 egrtids; /* number of RcvArray entries for Eager Rcvs */
	__u16 rcvhdrq_cnt; /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize; /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size; /* number of entries in SDMA request ring */
};

#define HFI2_TID_UPDATE_FLAGS_MEMINFO_MASK 0xfUL
#define HFI2_TID_UPDATE_FLAGS_RESERVED_MASK \
	(~(__u64)(HFI2_TID_UPDATE_FLAGS_MEMINFO_MASK))

/*
 * HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_BITS should match
 * HFI2_MEMINFO_TYPE_ENTRY_BITS.
 */
#define HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_BITS 4
#define HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_MASK \
	((1UL << HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_BITS) - 1)
#define HFI2_TID_UPDATE_V3_FLAGS_RESERVED_MASK \
	(~(__u64)(HFI2_TID_UPDATE_V3_FLAGS_MEMINFO_MASK))

/*
 * For memory_type HFI2_MEMINFO_TYPE_DMABUF, hfi2_tid_info_v3.context bits
 * 0-31 carry the dma-buf fd. fd 0 is a valid descriptor: the memory type,
 * not the context value, selects dma-buf pinning. For every other memory
 * type, context is reserved and must be 0.
 */
#define HFI2_TID_UPDATE_V3_CONTEXT_DMABUF_FD_MASK ((__u64)0xffffffff)
#define HFI2_TID_UPDATE_V3_CONTEXT_DMABUF_RESERVED_MASK \
	(~HFI2_TID_UPDATE_V3_CONTEXT_DMABUF_FD_MASK)

struct hfi2_tid_info_v3 {
	/* virtual address of first page in transfer */
	__aligned_u64 vaddr;
	/* pointer to tid array. this array is big enough */
	__aligned_u64 tidlist;
	/* number of tids programmed by this request */
	__u32 tidcnt;
	/* length of transfer buffer programmed by this request */
	__u32 length;

	/*
	 * bits 0-3 memory_type
	 *   memory_type=0 will always mean system memory
	 *   See HFI2_MEMINFO_TYPE* defines
	 * bits 4-63 reserved; must be 0
	 */
	__aligned_u64 flags;
	/*
	 * memory_type HFI2_MEMINFO_TYPE_DMABUF: dma-buf fd in bits 0-31,
	 * bits 32-63 reserved and must be 0.
	 * All other memory types: reserved; must be 0.
	 */
	__aligned_u64 context;
};

struct hfi2_tid_info {
	/* virtual address of first page in transfer */
	__aligned_u64 vaddr;
	/* pointer to tid array. this array is big enough */
	__aligned_u64 tidlist;
	/* number of tids programmed by this request */
	__u32 tidcnt;
	/* length of transfer buffer programmed by this request */
	__u32 length;

	/*
	 * bits 0-3 memory_type
	 *   memory_type=0 will always mean system memory
	 *   See HFI2_MEMINFO_TYPE* defines
	 * bits 4-63 reserved; must be 0
	 */
	__aligned_u64 flags;
	/* dma-buf fd in bits 0-31; otherwise reserved */
	__aligned_u64 context;
};

/*
 * This structure is returned by the driver immediately after
 * open to get implementation-specific info, and info specific to this
 * instance.
 *
 * This struct must have explicit padding fields where type sizes
 * may result in different alignments between 32 and 64 bit
 * programs, since the 64 bit * bit kernel requires the user code
 * to have matching offsets
 */
struct hfi2_base_info {
	/* version of hardware, for feature checking. */
	__u32 hw_version;
	/* HFI2_UVERBS_ABI_VERSION */
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

struct hfi2_pin_stats {
	int memtype;
	/*
	 * If -1, driver returns total number of stats entries for the given
	 * memtype, otherwise returns stats for the given { memtype, index }.
	 */
	int index;
	__u64 id;
	__u64 cache_entries;
	__u64 total_refcounts;
	__u64 total_bytes;
	__u64 hits;
	__u64 misses;
	__u64 hint_hits;
	__u64 hint_misses;
	__u64 internal_evictions; /* due to self-imposed size limit */
	__u64 external_evictions; /* system-driven evictions */
};

/*
 * RDMA character device ioctls
 */

/* verbs objects */
enum hfi2_objects {
	HFI2_OBJECT_DV0 = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_OBJECT_DV1,
	HFI2_OBJECT_DV2,
};

/* methods for custom objects dv0-dv2 - max of 8 per object */
enum hfi2_methods_dv0 {
	HFI2_METHOD_ASSIGN_CTXT = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_METHOD_CTXT_INFO,
	HFI2_METHOD_USER_INFO,
	HFI2_METHOD_TID_UPDATE,
	HFI2_METHOD_TID_FREE,
	HFI2_METHOD_CREDIT_UPD,
	HFI2_METHOD_RECV_CTRL,
	HFI2_METHOD_POLL_TYPE,
};

enum hfi2_methods_dv1 {
	HFI2_METHOD_ACK_EVENT = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_METHOD_SET_PKEY,
	HFI2_METHOD_CTXT_RESET,
	HFI2_METHOD_TID_INVAL_READ,
	HFI2_METHOD_GET_VERS,
	HFI2_METHOD_PIN_STATS,
	HFI2_METHOD_CREATE_SDMA_FD,
	HFI2_METHOD_QUERY_EGR_MMAP,
};

enum hfi2_methods_dv2 {
	HFI2_METHOD_BULKSVC_GET_CMPLQ = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_METHOD_BULKSVC_GET_CMDQ,
	HFI2_METHOD_BULKSVC_CLIENT_INIT,
	HFI2_METHOD_BULKSVC_DOORBELL,
	HFI2_METHOD_BULKSVC_SYNCCMD,
	HFI2_METHOD_BULKSVC_RELEASE_QUEUE,
	HFI2_METHOD_BULKSVC_GET_CNTR,
};

/*
 * assign_ctxt
 */
enum hfi2_attrs_assign_ctxt {
	HFI2_ATTR_ASSIGN_CTXT_CMD = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_assign_ctxt_cmd {
	__u32 userversion; /* user library version */
	__u8 port; /* target port number */
	__u8 kdeth_rcvhdrsz; /* 0 means default */
	__u16 reserved1;
	__u16 subctxt_cnt;
	__u16 subctxt_id;
	__u8 uuid[16]; /* 128bit UUID */
	__u32 reserved2;
};

/*
 * ctxt_info
 */
enum hfi2_attrs_ctxt_info {
	HFI2_ATTR_CTXT_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_ctxt_info_rsp {
	__aligned_u64 runtime_flags; /* chip/drv runtime flags (HFI2_CAP_*) */

	__u32 rcvegr_size; /* size of each eager buffer */
	__u16 num_active; /* number of active units */
	__u16 unit; /* unit (chip) assigned to caller */

	__u16 ctxt; /* ctxt on unit assigned to caller */
	__u16 subctxt; /* subctxt on unit assigned to caller */
	__u16 rcvtids; /* number of Rcv TIDs for this context */
	__u16 credits; /* number of PIO credits for this context */

	__u16 numa_node; /* NUMA node of the assigned device */
	__u16 rec_cpu; /* cpu # for affinity (0xffff if none) */
	__u16 send_ctxt; /* send context in use by this user context */
	__u16 egrtids; /* number of RcvArray entries for Eager Rcvs */

	__u16 rcvhdrq_cnt; /* number of RcvHdrQ entries */
	__u16 rcvhdrq_entsize; /* size (in bytes) for each RcvHdrQ entry */
	__u16 sdma_ring_size; /* number of entries in SDMA request ring */
	__u16 reserved;
};

/*
 * user_info
 */
enum hfi2_attrs_user_info {
	HFI2_ATTR_USER_INFO_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

/*
 * Returns both general and specific information to this device open.
 */
struct hfi2_user_info_rsp {
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
	/* PIO credit return mmap offset */
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
	__u32 sc_credits_offset;
	__u32 events_offset;
};

/*
 * tid_update
 */
enum hfi2_attrs_tid_update {
	HFI2_ATTR_TID_UPDATE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_UPDATE_RSP,
};

struct hfi2_tid_update_cmd {
	__aligned_u64 vaddr; /* virtual address of buffer */
	__aligned_u64 tidlist; /* address of output tid array */
	__u32 length; /* buffer length, in bytes */
	__u32 tidcnt; /* tidlist size, in TIDs */
	__aligned_u64 flags; /* flags: [3:0] mem type, [63:4] reserved */
	__aligned_u64 context; /* dma-buf fd in bits 0-31; otherwise reserved */
};

struct hfi2_tid_update_rsp {
	__u32 length; /* mapped buffer length */
	__u32 tidcnt; /* number of assigned TIDs */
};

/*
 * tid_free
 */
enum hfi2_attrs_tid_free {
	HFI2_ATTR_TID_FREE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_FREE_RSP,
};

struct hfi2_tid_free_cmd {
	__aligned_u64 tidlist; /* user buffer pointer */
	__u32 tidcnt; /* number of TID entries in buffer */
	__u32 reserved;
};

struct hfi2_tid_free_rsp {
	__u32 tidcnt; /* number actually freed */
	__u32 reserved;
};

/*
 * credit_upd
 * (no arguments)
 */

/*
 * recv_ctrl
 */
enum hfi2_attrs_recv_ctrl {
	HFI2_ATTR_RECV_CTRL_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_recv_ctrl_cmd {
	__u8 start_stop;
	__u8 reserved[7];
};

/*
 * poll_type
 */
enum hfi2_attrs_poll_type {
	HFI2_ATTR_POLL_TYPE_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_poll_type_cmd {
	__u32 poll_type;
	__u32 reserved;
};

/*
 * ack_event
 */
enum hfi2_attrs_ack_event {
	HFI2_ATTR_ACK_EVENT_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_ack_event_cmd {
	__u64 event;
};

/*
 * set_pkey
 */
enum hfi2_attrs_set_pkey {
	HFI2_ATTR_SET_PKEY_CMD = (1U << UVERBS_ID_NS_SHIFT),
	/* no response */
};

struct hfi2_set_pkey_cmd {
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
enum hfi2_attrs_tid_inval_read {
	HFI2_ATTR_TID_INVAL_READ_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_TID_INVAL_READ_RSP,
};

struct hfi2_tid_inval_read_cmd {
	__aligned_u64 tidlist; /* user buffer pointer */
	__u32 tidcnt; /* space for this many TIDs */
	__u32 reserved;
};

struct hfi2_tid_inval_read_rsp {
	__u32 tidcnt; /* numnber of returned tids */
	__u32 reserved;
};

/*
 * get_vers
 */
enum hfi2_attrs_get_vers {
	/* no cmd */
	HFI2_ATTR_GET_VERS_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_get_vers_rsp {
	__u32 version;
	__u32 reserved;
};

/*
 * pin_stats
 */
enum hfi2_attrs_pin_stats {
	HFI2_ATTR_PIN_STATS_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_PIN_STATS_RSP,
};

struct hfi2_pin_stats_cmd {
	__u32 memtype;
	/*
	 * If -1, driver returns total number of stats entries for the given
	 * memtype, otherwise returns stats for the given { memtype, index }.
	 */
	__s32 index;
};

struct hfi2_pin_stats_rsp {
	__u64 id;
	__u64 cache_entries;
	__u64 total_refcounts;
	__u64 total_bytes;
	__u64 hits;
	__u64 misses;
	__u64 hint_hits;
	__u64 hint_misses;
	__u64 internal_evictions; /* due to self-imposed size limit */
	__u64 external_evictions; /* system-driven evictions */
};

/*
 * create_sdma_fd
 */
enum hfi2_attrs_create_sdma_fd {
	HFI2_ATTR_SDMA_FD_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

enum hfi2_attrs_query_egr_mmap {
	HFI2_ATTR_QUERY_EGR_MMAP_CMD = (1U << UVERBS_ID_NS_SHIFT),
	HFI2_ATTR_QUERY_EGR_MMAP_RSP,
	HFI2_ATTR_QUERY_EGR_MMAP_SEGMENTS,
};

struct hfi2_query_egr_mmap_cmd {
	__u32 first_segment;
	__u32 reserved;
};

struct hfi2_query_egr_mmap_rsp {
	__u32 total_segments;
	__u32 returned_segments;
	__aligned_u64 total_size;
};

struct hfi2_egr_mmap_segment {
	__aligned_u64 offset;
	__aligned_u64 length;
	__aligned_u64 mmap_offset;
};

#define HFI2_BULKSVC_CACHELINE_SIZE 64

struct hfi2_bulksvc_queue_ctrl {
	union {
		__u64 head;
		__u8 padding1[HFI2_BULKSVC_CACHELINE_SIZE];
	};
	union {
		__u64 tail;
		__u8 padding2[HFI2_BULKSVC_CACHELINE_SIZE];
	};
};

struct hfi2_bulksvc_cmd_reg_dma_buffer {
	__u64 vaddr;
	__u64 app_context;
	__u64 flags;
	__u32 cmpl_id;
	__u32 size_bytes;
	__u32 access_key;
};

struct hfi2_bulksvc_cmd_rdma_read_va {
	__u64 app_context;
	__u64 vaddr;
	__u64 imm_data;
	__u64 flags;
	__u64 remote_offset;
	__u32 len_bytes;
	__u32 access_key;
	__u32 client_key;
	__u32 lid;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_rdma_read_va_triggered {
	struct hfi2_bulksvc_cmd_rdma_read_va rdma_read_va;
	__u32 trigger_cntr_id;
	__u64 target_value;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_rdma_read {
	__u64 app_context;
	__u64 imm_data;
	__u64 flags;
	__u64 mr_offset;
	__u32 mr_key;
	__u32 len_bytes;
	__u64 remote_offset;
	__u32 access_key;
	__u32 client_key;
	__u32 lid;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_rdma_read_triggered {
	struct hfi2_bulksvc_cmd_rdma_read rdma_read;
	__u32 trigger_cntr_id;
	__u64 target_value;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_rdma_write {
	__u64 app_context;
	__u64 imm_data;
	__u64 flags;
	__u64 mr_offset;
	__u32 mr_key;
	__u32 len_bytes;
	__u64 remote_offset;
	__u32 access_key;
	__u32 client_key;
	__u32 lid;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_rdma_write_triggered {
	struct hfi2_bulksvc_cmd_rdma_write rdma_write;
	__u32 trigger_cntr_id;
	__u64 target_value;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_dma_access_once {
	__u64 app_context;
	__u64 flags;
	__u32 mr_key;
	__u32 len;
	__u64 offset;
	__u32 access_key;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_dma_access_enable {
	__u64 app_context;
	__u64 flags;
	__u64 notification_app_context;
	__u64 len;
	__u64 offset;
	__u64 notification_flags;
	__u32 mr_key;
	__u32 access_key;
	__u32 cmpl_id;
	__u32 notification_cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_dma_access_disable {
	__u64 app_context;
	__u64 flags;
	__u32 access_key;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));


/*
 * HFISVC RDMA Command Flags
 * -----------------------------
 * Many hfisvc API functions accept a 64-bit 'flags' parameter. Flags are bitmasks and
 * may be OR'ed together to form a single command.
 *
 * There are several classes of flags:
 *  - Completion selection flags (HFI2_BULKSVC_CMPL_*), which tell
 *    the library/driver how to signal completion for the command.
 *  - Command-specific option flags (e.g., HFI2_BULKSVC_MR_FLAG_MODE_*,
 *    HFI2_BULKSVC_CNTR_*), which modify the behavior of that command.
 *  - Port section flags which steer which hfi port the command should use.
 */

enum hfi2_bulksvc_flags {
	HFI2_BULKSVC_FLAG_PORT_DEFAULT = 0,
	HFI2_BULKSVC_FLAG_PORT_1 = (1ull << 1),
	HFI2_BULKSVC_FLAG_PORT_2 = (1ull << 2),
	HFI2_BULKSVC_FLAG_PORT_DEFAULT2 = (1ull << 3),
	HFI2_BULKSVC_MR_FLAG_MODE_VADDR = (1ull << 4),
	HFI2_BULKSVC_CNTR_VALUE = (1ull << 16),
	HFI2_BULKSVC_CNTR_ERROR = (1ull << 17),
	HFI2_BULKSVC_CMPL_CQ = (1ull << 24),
	HFI2_BULKSVC_CMPL_CNTR = (1ull << 25),

};

/*
 * Port selection bits in flags field for RDMA commands.
 * Port value: 0 = default port, 1-2 = specific port (1-indexed), 3 = default port
 */
#define HFI2_BULKSVC_CMD_FLAG_PORT_SHIFT (1)
#define HFI2_BULKSVC_CMD_FLAG_PORT_BITS (2)
#define HFI2_BULKSVC_CMD_FLAG_PORT_MASK (0x3u)
#define HFI2_BULKSVC_CMD_FLAG_PORT_SMASK  (HFI2_BULKSVC_CMD_FLAG_PORT_MASK << HFI2_BULKSVC_CMD_FLAG_PORT_SHIFT)

enum hfi2_hfisvc_client_hmem_iface {
	HFI2_HFISVC_HMEM_IFACE_SYSTEM	= 0,
	/* HFI2_HFISVC_HMEM_IFACE_CUDA..SYNAPSEAI are GPU-vendor interfaces
	 * added by the out-of-tree GPU patch; their values are reserved here.
	 */
	HFI2_HFISVC_HMEM_IFACE_DMABUF	= 6,
};

struct hfi2_bulksvc_cmd_mr_open {
	__u64 app_context;
	__u64 vaddr;
	__u64 flags;
	__u64 len;
	__u32 cmpl_id;
	__u32 hmem_iface;
	__u32 hmem_device;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_mr_close {
	__u64 app_context;
	__u64 flags;
	__u32 mr_key;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_cntr_add {
	__u64 app_context;
	__u64 flags;
	__u32 cntr_id;
	__u32 amount;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_cntr_set {
	__u64 app_context;
	__u64 flags;
	__u32 cntr_id;
	__u32 value;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_uverbs_post_send {
	__u64 app_context;
	__u16 num_wrs;
	__u32 cmpl_id;
	struct ib_uverbs_send_wr wrs[0];
} __attribute__((packed, aligned(4)));

#define HFI2_BULKSVC_VERSION_MAJOR 1
#define HFI2_BULKSVC_VERSION_MINOR 1

enum hfi2_bulksvc_cap_flags {
	HFI2_BULKSVC_CAP_CNTRS             = (1ULL << 0),
	HFI2_BULKSVC_CAP_TRIGGERED_OPS     = (1ULL << 1),
	HFI2_BULKSVC_CAP_DMA_BUF           = (1ULL << 2),
	HFI2_BULKSVC_CAP_UVERBS_POST_SEND  = (1ULL << 3),
};

#define HFI2_BULKSVC_CAPS_ALL (HFI2_BULKSVC_CAP_CNTRS | \
			       HFI2_BULKSVC_CAP_TRIGGERED_OPS | \
			       HFI2_BULKSVC_CAP_DMA_BUF | \
			       HFI2_BULKSVC_CAP_UVERBS_POST_SEND)

/* Future opcodes use this prefix to report unsupported commands. */
struct hfi2_bulksvc_cmd_common {
	__u64 app_context;
	__u64 flags;
	__u32 cmpl_id;
} __attribute__((packed, aligned(4)));

struct hfi2_bulksvc_cmd_version {
	__u64 app_context;
	__u64 flags;
	__u32 cmpl_id;
	__u32 reserved;
} __attribute__((packed, aligned(4)));

enum hfi2_bulksvc_cmd_op {
	HFI2_BULKSVC_CMD_REG_DMA_BUFFER,
	HFI2_BULKSVC_CMD_RDMA_READ_VA,
	HFI2_BULKSVC_CMD_RDMA_READ_VA_TRIGGERED,
	HFI2_BULKSVC_CMD_RDMA_READ,
	HFI2_BULKSVC_CMD_RDMA_READ_TRIGGERED,
	HFI2_BULKSVC_CMD_RDMA_WRITE,
	HFI2_BULKSVC_CMD_RDMA_WRITE_TRIGGERED,
	HFI2_BULKSVC_CMD_DMA_ACCESS_ONCE,
	HFI2_BULKSVC_CMD_DMA_ACCESS_ENABLE,
	HFI2_BULKSVC_CMD_DMA_ACCESS_DISABLE,
	HFI2_BULKSVC_CMD_MR_OPEN,
	HFI2_BULKSVC_CMD_MR_CLOSE,
	HFI2_BULKSVC_CMD_CNTR_ADD,
	HFI2_BULKSVC_CMD_CNTR_SET,
	HFI2_BULKSVC_CMD_UVERBS_POST_SEND,
	HFI2_BULKSVC_CMD_VERSION,
};

struct hfi2_bulksvc_cmd_hdr {
	enum hfi2_bulksvc_cmd_op op;
	__u16 num_blocks;
	__u16 reserved;
};

struct hfi2_bulksvc_cmd {
	struct hfi2_bulksvc_cmd_hdr hdr;
	union {
		struct hfi2_bulksvc_cmd_common common;
		struct hfi2_bulksvc_cmd_reg_dma_buffer register_dma_buffer;
		struct hfi2_bulksvc_cmd_rdma_read_va rdma_read_va;
		struct hfi2_bulksvc_cmd_rdma_read_va_triggered rdma_read_va_triggered;
		struct hfi2_bulksvc_cmd_rdma_read rdma_read;
		struct hfi2_bulksvc_cmd_rdma_read_triggered rdma_read_triggered;
		struct hfi2_bulksvc_cmd_rdma_write rdma_write;
		struct hfi2_bulksvc_cmd_rdma_write_triggered rdma_write_triggered;
		struct hfi2_bulksvc_cmd_dma_access_once dma_access_once;
		struct hfi2_bulksvc_cmd_dma_access_enable dma_access_enable;
		struct hfi2_bulksvc_cmd_dma_access_disable dma_access_disable;
		struct hfi2_bulksvc_cmd_mr_open mr_open;
		struct hfi2_bulksvc_cmd_mr_close mr_close;
		struct hfi2_bulksvc_cmd_cntr_add cntr_add;
		struct hfi2_bulksvc_cmd_cntr_set cntr_set;
		struct hfi2_bulksvc_cmd_uverbs_post_send uverbs_post_send;
		struct hfi2_bulksvc_cmd_version version;
	} payld[];
} __attribute__((packed, aligned(HFI2_BULKSVC_CACHELINE_SIZE)));

enum hfi2_bulksvc_cq_entry_type {
	HFI2_HFISVC_CQ_ENTRY_TYPE_DEFAULT,
	HFI2_HFISVC_CQ_ENTRY_TYPE_MR,
	HFI2_HFISVC_CQ_ENTRY_TYPE_NOTIFY,
	HFI2_HFISVC_CQ_ENTRY_TYPE_VERSION,
};

union hfi2_bulksvc_cmplq_entry_type_data {
	/* default completion (timestamp populated on -EOPNOTSUPP) */
	struct {
		__u32 access_key;
		__u32 reserved;
		__u64 timestamp;
	} type_default;

	/* memory region completion */
	struct {
		__u32 mr_key;
	} type_mr;

	/* notify completion */
	struct {
		__u32 access_key;
		__u32 flags;
		__u64 imm_data;
	} type_notify;

	struct {
		__u16 major;
		__u16 minor;
		__u32 reserved;
		__u64 caps;
		__u64 reserved_ext[4];
	} type_version;
};

/* CQ rings stride by union hfi2_bulksvc_upd (64 bytes). */
struct hfi2_bulksvc_cmplq_entry {
	__u64 app_context;
	__u32 type;
	__u32 status;
	union hfi2_bulksvc_cmplq_entry_type_data type_data;
};

union hfi2_bulksvc_upd {
	__u8 bytes[64];
	struct {
		union {
			struct hfi2_bulksvc_cmplq_entry cmplq_entry;
		};
	};
};

/*
 * get_cmplq
 */
enum hfi2_attrs_bulksvc_get_cmplq {
	/* no cmd */
	HFI2_ATTR_BULKSVC_GET_CMPLQ_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_bulksvc_queue_info {
	__u32 queue_id;
	__u64 queue_ctrl_mmap_token;
	__u32 queue_ctrl_mmap_size;
	__u64 queue_buffer_mmap_token;
	__u32 queue_buffer_mmap_size;
};

/*
 * get_cntr
 */
enum hfi2_attrs_bulksvc_get_cntr {
	/* no cmd */
	HFI2_ATTR_BULKSVC_GET_CNTR_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_bulksvc_cntr_info {
	__u32 cntr_id;
	__u64 cntr_value_mmap_token;
	__u32 cntr_value_offset;
	__u64 cntr_error_mmap_token;
	__u32 cntr_error_offset;
	__u32 cntr_slot_size;
};

/*
 * get_cmdq
 */
enum hfi2_attrs_bulksvc_get_cmdq {
	/* no cmd */
	HFI2_ATTR_BULKSVC_GET_CMDQ_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

enum hfi2_attrs_bulksvc_release_queue {
	/* no cmd */
	HFI2_ATTR_BULKSVC_RELEASE_QUEUE_CMD = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_bulksvc_queue_release {
	__u32 queue_id;
	__u32 is_cmplq;
};

/*
 * client_init
 */
enum hfi2_bulksvc_get_client_init {
	/* no cmd */
	HFI2_ATTR_BULKSVC_CLIENT_INIT_RSP = (1U << UVERBS_ID_NS_SHIFT),
};

struct hfi2_bulksvc_client_init {
	__u32 client_key;
	__u32 flags;
	__aligned_u64 fast_doorbell;
	__u32 fast_doorbell_mmap_size;
	__aligned_u64 dirty_bitmap_mmap_token;
	__u32 dirty_bitmap_mmap_size;
	__s32 dirty_bitmap_bit;
};
#define HFI2_HFISVC_CLIENT_FLAG_DOORBELL (1u << 0)

enum hfi2_bulksvc_synccmd {
	/* no cmd */
	HFI2_ATTR_BULKSVC_SYNCCMD = (1U << UVERBS_ID_NS_SHIFT),
};

#endif /* _LINUX_HFI2_USER_H */
