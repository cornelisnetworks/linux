/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2025 Cornelis Networks.
 *
 */
#ifndef _HFI2_DMS_H
#define _HFI2_DMS_H

#include "mem_region.h"
#include "dms_sdma.h"
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/bitfield.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/string.h>
#include <linux/xarray.h>

#define HFI2_DMS_COUNTERS_ENABLE 0

#ifndef HFI2_DMS_RHF_TEST_ENABLE
#define HFI2_DMS_RHF_TEST_ENABLE 0
#endif

#define HFI2_DMS_CTRL_JKEY (0xACDC)
#define HFI2_DMS_DATA_JKEY (0xACDD)
/*
 * DMS lane selector, BTH byte 4 of a DMS control packet (header byte 20,
 * RSM bit offset 160; bth[1] bits 7:0 here):
 *   [2:0] DST: receiver lane.  The DMS RSM rule uses it as map table
 *         index; entry i points at lane (i % num_lanes)'s ctrl context.
 *   [5:3] SRC: sender lane.
 *   [7:6] F, B (FECN, BECN), untouched (0); 16B carries them in the LRH.
 * In a 16B packet the selector overlaps the BTH CSPEC[2:0] and RC2
 * positions defined for OPA400.  JKR ignores the BTH CSPEC and RC2 fields on
 * receive for all packet types (16B carries them in the LRH), and the
 * egress SendCtxtCheckCspecAge force/check (JKR HAS 14.13.4.17) acts on the
 * 16B LRH cspec/age field, not the BTH.  Data packets steer by DestQP as
 * before.
 *
 * An initiator on lane I sends DST = T, SRC = I, where T is the lane its
 * hfisvc target client key names, or for verbs the lane the peer QP
 * advertised in DMS OPFN (I with OPFN opted out).  A receiver replies with
 * DST = received SRC and SRC = received DST, so every control packet of a
 * transfer lands on one lane at each end, whatever lane counts the two
 * hosts use.
 *
 * Inside DMS a peer is lid | DST << 24 | SRC << 27, the selector of the
 * packets sent to it (16B LIDs are 24 bits; every LID writer masks to 24
 * bits).  It is the peer identity for tracker lookup and needs no extra
 * state.
 */
#define HFI2_DMS_LANE_SEL_BITS 3
#define HFI2_DMS_LANE_SEL_MASK ((1u << HFI2_DMS_LANE_SEL_BITS) - 1)
#define HFI2_DMS_LANE_SEL_SRC_SHIFT HFI2_DMS_LANE_SEL_BITS
#define HFI2_DMS_LANE_SEL_BTH_MASK \
	((HFI2_DMS_LANE_SEL_MASK << HFI2_DMS_LANE_SEL_SRC_SHIFT) | \
	 HFI2_DMS_LANE_SEL_MASK)
#define HFI2_DMS_LANE_SEL_PEER_SHIFT 24
#define HFI2_DMS_LANE_SEL_PEER_SRC_SHIFT \
	(HFI2_DMS_LANE_SEL_PEER_SHIFT + HFI2_DMS_LANE_SEL_BITS)
/* RSM bit offset of DST: byte 20 (LRH16B 16 + BTH byte 4), bit 0 */
#define HFI2_DMS_LANE_SEL_RSM_OFFSET (20 * 8)
#define HFI2_DMS_PKEY (0x8001)
// Inclusive of loopback ports
#define HFI2_DMS_MAX_PORTS (4)
#define HFI2_DMS_MAX_FABRIC_PORTS (2)
#define HFI2_DMS_MAX_TID_VALUE (1024)
#define HFI2_DMS_TID_SET_SIZE (16)
#define HFI2_DMS_TID_SET_IDX_COUNT (HFI2_DMS_MAX_TID_VALUE / HFI2_DMS_TID_SET_SIZE)

/* Max outstanding tidsets a single rx tracker may hold at once. Header-visible
 * so struct hfi2_dms_rx_tracker can size its outstanding-tidset list.
 */
#define HFI2_DMS_TRACKER_TIDSET_MAX (HFI2_DMS_TID_SET_IDX_COUNT / 8)

/*
 * An op covers at most HFI2_DMS_TID_SET_SIZE TID regions, but a single
 * region whose source gather is heavily fragmented can be split into
 * several same-TID DATA sub-packets to keep each packet within MAX_DESC.
 * Provision twice the TID-region count of AHG headers per set. A request
 * that still needs more headers, or more descriptors than one submission
 * holds, is sent chunk by chunk instead.
 */
#define HFI2_DMS_AHG_HEADERS_PER_SET (HFI2_DMS_TID_SET_SIZE * 2)

/* Each TID entry covers 2 hardware pages, so a tidset window covers
 * TID_SET_SIZE * 2 pages.  This is the natural pin-progress quantum.
 */
#define HFI2_DMS_TID_SET_PAGES_MAX (HFI2_DMS_TID_SET_SIZE * 2)

/* Max payload one tidset can request in a single DATA_REQUEST. */
#define HFI2_DMS_TID_SET_BYTES_MAX (HFI2_DMS_TID_SET_PAGES_MAX * PAGE_SIZE)

/*
 * Pages backing one tidset's bounce region: one, mapped at the lower entry of
 * the tidset's last RcvArray pair (the upper entry maps the zero page).
 */
#define HFI2_DMS_TIDSET_BOUNCE_PAGE_COUNT 1

/* DATA_REQUEST bit flags */
/* The request has bounce edges (rc->scatter_count != 0), for any op. */
#define HFI2_DMS_DR_FLAG_UNALIGNED	BIT(0)
/* BIT(1) is unused (formerly MULTI_PROVIDER). */

/*
 * A recv_chunk starts on a TID (even RcvArray slot) boundary, so a tidset
 * holds at most one chunk per TID.
 */
#define HFI2_DMS_DR_MAX_CHUNKS	HFI2_DMS_TID_SET_SIZE

/*
 * Gather elements one recv_chunk may name. Bounded by the room a parked SDMA
 * inject has to hold the list (struct hfi2_dms_sdma_info shares that space
 * with the 128-byte proto command).
 */
#define HFI2_DMS_DR_CHUNK_MAX_GATHER	14

/*
 * Gather elements one DATA_REQUEST may carry: one per direct chunk plus one
 * fully gathered chunk.
 */
#define HFI2_DMS_DR_MAX_GATHER	32

/*
 * PIO waitlist snapshot capacity in quadwords. Sized to hold the largest
 * control frame: a READ_START_SPECULATIVE carrying two full tidset requests --
 * PBC + the 88-byte fixed prefix + the zeroed 32-byte inline area + twice
 * (HFI2_DMS_DR_MAX_CHUNKS recv_chunks + HFI2_DMS_DR_MAX_GATHER gather
 * elements) + tail flit. A DATA_REQUEST carries at most one request.
 */
#define HFI2_DMS_PIO_WAITER_QWS		113

/*
 * One recv target in a DATA_REQUEST: the TID range it lands in, and the next
 * gather_count source elements of the gather array, which the responder sends
 * into it in order. Chunks consume the gather array in order, so a chunk's
 * elements start where the previous chunk's ended. length_count packs the
 * chunk's summed source bytes (low 24 bits, HFI2_DMS_RECV_CHUNK_LENGTH) and
 * gather_count (high 8 bits), so the responder neither walks the elements to
 * size the chunk nor tracks where its run begins.
 */
struct hfi2_dms_recv_chunk {
	u32 tid_info;
	u32 length_count;
} __packed __aligned(4);

#define HFI2_DMS_RECV_CHUNK_LENGTH	GENMASK(23, 0)
#define HFI2_DMS_RECV_CHUNK_COUNT	GENMASK(31, 24)

static inline u32 hfi2_dms_recv_chunk_length(struct hfi2_dms_recv_chunk const *c)
{
	return FIELD_GET(HFI2_DMS_RECV_CHUNK_LENGTH, c->length_count);
}

static inline u8 hfi2_dms_recv_chunk_count(struct hfi2_dms_recv_chunk const *c)
{
	return FIELD_GET(HFI2_DMS_RECV_CHUNK_COUNT, c->length_count);
}

/*
 * One source range of a recv_chunk, relative to the transfer's source start.
 * Elements land in the chunk in order, each occupying round_up(length, 8)
 * bytes: the responder follows an element whose length is not a quadword
 * multiple with zero bytes up to the next quadword boundary. The final element
 * is padded too, so a chunk always lands a whole number of quadwords.
 */
struct hfi2_dms_gather {
	u32 sbuf_offset;
	u32 length;
} __packed __aligned(4);

/*
 * Default byte ceiling below which an ordered WRITE is treated as
 * single-SDMA-engine for WAW early release. Runtime-tunable via the
 * bulksvc_write_single_engine_max_bytes module parameter; this is only the
 * initial value.
 */
#define HFI2_DMS_WRITE_SINGLE_ENGINE_MAX_BYTES_DEFAULT (HFI2_DMS_TID_SET_BYTES_MAX * 2)

/* process_proactive_pins() pins one tidset window per iteration, plus
 * one possible alignment-spill page (see comment at use site).
 */
#define HFI2_DMS_PROACTIVE_PIN_CHUNK_PAGES HFI2_DMS_TID_SET_PAGES_MAX
// (32 ahg indices per engine * 16 engines * 2)
#define HFI2_DMS_AHG_HEADER_BLOCK_SIZE (1024)

/* Trackers allocated per hfi2_dms_impl_tracker_block_alloc() call. */
#define HFI2_DMS_TRACKER_BLOCK_SIZE (1024)

#define HFI2_DMS_MAX_ACCESS_FAST (1024)

#define HFI2_DMS_RIFT_ALL_BITS (sizeof(u16)*8)

#define HFI2_DMS_RIFT_IDX_BITS (8)
#define HFI2_DMS_RIFT_IDX_SIZE (1ull << HFI2_DMS_RIFT_IDX_BITS)
#define HFI2_DMS_RIFT_IDX_MASK (HFI2_DMS_RIFT_IDX_SIZE - 1)

#define HFI2_DMS_RIFT_ERR_BITS (1)
#define HFI2_DMS_RIFT_ERR_MASK (1ull << (HFI2_DMS_RIFT_ALL_BITS - HFI2_DMS_RIFT_ERR_BITS))

#define HFI2_DMS_RIFT_GEN_BITS (HFI2_DMS_RIFT_ALL_BITS - HFI2_DMS_RIFT_ERR_BITS - HFI2_DMS_RIFT_IDX_BITS)
#define HFI2_DMS_RIFT_GEN_SIZE (1ull << HFI2_DMS_RIFT_GEN_BITS)
#define HFI2_DMS_RIFT_GEN_MASK ((HFI2_DMS_RIFT_GEN_SIZE - 1) << HFI2_DMS_RIFT_IDX_BITS)

#define HFI2_DMS_RIFT_KEY_TYPE_MASK (0x01)

#define HFI2_DMS_RIFT_KEY_SIDE_RX_COUNT (HFI2_DMS_TID_SET_IDX_COUNT)
#define HFI2_DMS_RIFT_KEY_SIDE_TX_COUNT (HFI2_DMS_RIFT_IDX_SIZE - HFI2_DMS_RIFT_KEY_SIDE_RX_COUNT)

#define HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED (~(0ull))

#define HFI2_DMS_FLAG_COMPLETION_VIA_STATUS  (1u << 15)

/* READ flag: the responder must answer with a non-eager DATA_START. Set for a
 * chained child gated at DATA_START, which an eager response would bypass.
 */
#define HFI2_DMS_READ_FLAG_NO_EAGER  BIT(1)

/* WRITE_START flag: the landing buffer is resolved by a registered upper
 * layer (via dms->ext_dest) instead of by an access/dms_key lookup.  DMS
 * stays destination-agnostic.  Same wire bit as the upper layer's own
 * externally-resolved-destination flag.
 */
#define HFI2_DMS_WRITE_START_FLAG_EXT_DEST  (1 << 2)

/* order_key[31:24]: per-submission generation for stale-orphan rejection. */
#define HFI2_DMS_ORDER_KEY_GEN_SHIFT		24
#define HFI2_DMS_ORDER_KEY_GEN_MASK		0xffu

/*
 * Reliability policy carried in the START wire flags word (READ_START
 * info.flags, WRITE_START metadata.flags).  FAST_FAIL selects fast-fail
 * (cancel-on-stale) over in-place health recovery; STALE_SHIFT is the caller's
 * per-submission left-shift for the initial stale backoff.  Both sit in unused
 * bits, so no wire resize.
 */
#define HFI2_DMS_START_FLAG_FAST_FAIL		BIT(4)
#define HFI2_DMS_START_STALE_SHIFT_SHIFT	5
#define HFI2_DMS_START_STALE_SHIFT_BITS		8
#define HFI2_DMS_START_STALE_SHIFT_MASK \
	(((1u << HFI2_DMS_START_STALE_SHIFT_BITS) - 1) << HFI2_DMS_START_STALE_SHIFT_SHIFT)

static inline u16 hfi2_dms_start_flags_set_policy(u16 flags, bool fast_fail, u8 stale_shift)
{
	flags &= ~(HFI2_DMS_START_FLAG_FAST_FAIL | HFI2_DMS_START_STALE_SHIFT_MASK);
	if (fast_fail)
		flags |= HFI2_DMS_START_FLAG_FAST_FAIL;
	flags |= ((u16)stale_shift << HFI2_DMS_START_STALE_SHIFT_SHIFT) &
		 HFI2_DMS_START_STALE_SHIFT_MASK;
	return flags;
}

static inline bool hfi2_dms_start_flags_fast_fail(u16 flags)
{
	return !!(flags & HFI2_DMS_START_FLAG_FAST_FAIL);
}

static inline u8 hfi2_dms_start_flags_stale_shift(u16 flags)
{
	return (u8)((flags & HFI2_DMS_START_STALE_SHIFT_MASK) >>
		    HFI2_DMS_START_STALE_SHIFT_SHIFT);
}

enum hfi2_dms_msg_type {
	HFI2_DMS_MSG_TYPE_READ_START = 0,
	HFI2_DMS_MSG_TYPE_WRITE_START,
	HFI2_DMS_MSG_TYPE_WRITE_START_EAGER,
	HFI2_DMS_MSG_TYPE_DATA_START,
	HFI2_DMS_MSG_TYPE_DATA_START_EAGER,
	HFI2_DMS_MSG_TYPE_DATA_REQUEST,
	HFI2_DMS_MSG_TYPE_DATA,
	HFI2_DMS_MSG_TYPE_ACK,
	HFI2_DMS_MSG_TYPE_NACK,
	HFI2_DMS_MSG_TYPE_STATUS_RESPONSE,
	HFI2_DMS_MSG_TYPE_STATUS_REQUEST,
	HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE,
	HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE,
	HFI2_DMS_MSG_TYPE_READ_START_REPLAY,
	HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY,
	HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY,
	HFI2_DMS_MSG_TYPE_DATA_REPLAY,
	HFI2_DMS_MSG_TYPE_WRITE_START_TINY,

	HFI2_DMS_MSG_TYPE_COUNT,
};

static_assert(HFI2_DMS_MSG_TYPE_WRITE_START_EAGER ==
	      HFI2_DMS_MSG_TYPE_WRITE_START + 1,
	      "WRITE_START_EAGER must follow WRITE_START");
static_assert(HFI2_DMS_MSG_TYPE_DATA_START_EAGER ==
	      HFI2_DMS_MSG_TYPE_DATA_START + 1,
	      "DATA_START_EAGER must follow DATA_START");

/*
 * debugfs.c's positional _pkt_drop_type_names[] and dms.c's
 * _dms_msg_type_names[] both index by this ordinal, so pin every value here:
 * a reorder must break the build rather than silently mislabel a drop type
 * or NACK/name lookup.
 */
static_assert(HFI2_DMS_MSG_TYPE_READ_START == 0, "READ_START ordinal");
static_assert(HFI2_DMS_MSG_TYPE_WRITE_START == 1, "WRITE_START ordinal");
static_assert(HFI2_DMS_MSG_TYPE_WRITE_START_EAGER == 2, "WRITE_START_EAGER ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_START == 3, "DATA_START ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_START_EAGER == 4, "DATA_START_EAGER ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_REQUEST == 5, "DATA_REQUEST ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA == 6, "DATA ordinal");
static_assert(HFI2_DMS_MSG_TYPE_ACK == 7, "ACK ordinal");
static_assert(HFI2_DMS_MSG_TYPE_NACK == 8, "NACK ordinal");
static_assert(HFI2_DMS_MSG_TYPE_STATUS_RESPONSE == 9, "STATUS_RESPONSE ordinal");
static_assert(HFI2_DMS_MSG_TYPE_STATUS_REQUEST == 10, "STATUS_REQUEST ordinal");
static_assert(HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE == 11, "READ_START_SPECULATIVE ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE == 12, "DATA_SPECULATIVE ordinal");
static_assert(HFI2_DMS_MSG_TYPE_READ_START_REPLAY == 13, "READ_START_REPLAY ordinal");
static_assert(HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY == 14, "WRITE_START_REPLAY ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY == 15, "DATA_REQUEST_REPLAY ordinal");
static_assert(HFI2_DMS_MSG_TYPE_DATA_REPLAY == 16, "DATA_REPLAY ordinal");
static_assert(HFI2_DMS_MSG_TYPE_WRITE_START_TINY == 17, "WRITE_START_TINY ordinal");

#define HFI2_DMS_PACKET_DROP_TYPE_COUNT HFI2_DMS_MSG_TYPE_COUNT

/*
 * ULP-id namespacing of the 8-bit BTH message byte (BTH[0] bits [23:16]).
 *
 *   [7:5] ulp_id   0 = native OPA / BTS DMS; 1..HFI2_DMS_ULP_MAX-1 = a ULP
 *   [4:0] subtype  per-ULP message subtype; native OPA uses
 *                  0..HFI2_DMS_MSG_TYPE_COUNT - 1, a pure subset since that
 *                  stays below 32, so the existing decode is unchanged.
 *
 * Native OPA only ever emits message-byte values below
 * HFI2_DMS_MSG_TYPE_COUNT, so the existing cast
 * (enum hfi2_dms_msg_type)msg_byte stays exactly correct for ulp_id == 0.  This
 * convention deliberately does NOT grow enum hfi2_dms_msg_type: doing so would
 * trip its static_asserts and silently resize protocol_cmd_templates[] /
 * packet_drop[] and the positional name tables.
 */
#define HFI2_DMS_MSGBYTE_ULP_SHIFT 5
#define HFI2_DMS_MSGBYTE_SUB_MASK  0x1f
#define HFI2_DMS_ULP_MAX           8

static_assert((HFI2_DMS_MSG_TYPE_COUNT - 1) <= HFI2_DMS_MSGBYTE_SUB_MASK,
	      "native msg types must fit the ulp_id 0 subtype field");

typedef struct {u16 value;} hfi2_dms_rift_key_t;

#define HFI2_DMS_RIFT_KEY_BITS (sizeof(hfi2_dms_rift_key_t) * 8)

#define HFI2_DMS_HANDLE_GEN_BITS  8
#define HFI2_DMS_HANDLE_GEN_MASK  ((1ULL << HFI2_DMS_HANDLE_GEN_BITS) - 1)
#define HFI2_DMS_HANDLE_PTR_MASK  (~HFI2_DMS_HANDLE_GEN_MASK)
#define HFI2_DMS_TRACKER_ALIGN    (1ULL << HFI2_DMS_HANDLE_GEN_BITS)

enum hfi2_dms_rift_err {
	HFI2_DMS_RIFT_ERR_NONE = 0,
	HFI2_DMS_RIFT_ERR_KEY_NOT_SET,
	HFI2_DMS_RIFT_ERR_KEY_DISABLED,
	/*
	 * Eager-only WRITE target: the whole payload arrived in its
	 * WRITE_START_EAGER and it completes inside that admit, so it is never
	 * given a rift key. Local only; never placed on the wire.
	 */
	HFI2_DMS_RIFT_ERR_KEYLESS,
};

struct sdma_engine;

struct hfi2_dms_dlist_element {
	struct hfi2_dms_dlist_element * prev;
	struct hfi2_dms_dlist_element * next;
};

struct hfi2_dms_dlist {
	struct hfi2_dms_dlist_element * head;
	struct hfi2_dms_dlist_element * tail;
};

union hfi2_dms_proto_cmd {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		u32 user_kdeth[5];
		u64 tail_flit; // this is the tail flit if message is only 1 SCB in size
		u64 additional_data[8]; // else the last u64 of this array is the tail flit
	};
} __attribute__((packed, aligned(4)));

union hfi2_dms_completion_cookie {
	u8 byte[64];
	u32 dw[16];
	u64 qw[8];
};

typedef void (*hfi2_dms_completion_fn)(union hfi2_dms_completion_cookie *, int);

struct hfi2_dms_completion {
	hfi2_dms_completion_fn fn;
	union hfi2_dms_completion_cookie cookie;
};

enum hfi2_dms_mr_mode {
	HFI2_DMS_MR_MODE_OFFSET = 0,
	HFI2_DMS_MR_MODE_VADDR = 1,
};

struct hfi2_dms_mr {
	struct {
		unsigned long addr;
		unsigned long len;
	} extended_vaddr;

	dma_addr_t *dma_list;
	unsigned int npages_total;

	struct {
		unsigned long addr;	// user unaligned vaddr of start of buffer
		unsigned long len;  // number of bytes in the user buffer
	} user;
	u64 region_offset; // offset into the mr (from the first page address) where the user buffer starts
	enum hfi2_dms_mr_mode mode;
	u32 active_count;

	/*
	 * Cancel-by-owner key for hfi2_dms_cancel_trackers_for_owner().
	 * Type: struct hfi2_bulksvc_user_info * (only).  NULL = not
	 * cancellable via this walk.  Reached through the page provider's
	 * @owner callback.  Adding a new owner kind requires
	 * extending _tracker_references_owner() to discriminate; raw
	 * pointer equality across different owner types is unsafe.
	 */
	void *owner;
};

enum hfi2_dms_access_type {
	HFI2_DMS_ACCESS_TYPE_PERSISTENT = 0,
	HFI2_DMS_ACCESS_TYPE_EPHEMERAL = 1,
};

enum hfi2_dms_access_state {
	HFI2_DMS_ACCESS_STATE_FREE = 0,
	HFI2_DMS_ACCESS_STATE_ACTIVE,
	HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN,
};



typedef void (*hfi2_dms_access_completion_fn)(union hfi2_dms_completion_cookie *, u16, u64, u64, int);

struct hfi2_dms_access_completion {
	hfi2_dms_access_completion_fn fn;
	union hfi2_dms_completion_cookie cookie;
};

struct hfi2_dms;
struct hfi2_dms_page_provider;
union hfi2_dms_key;

enum hfi2_dms_ext_dest_status {
	HFI2_DMS_EXT_DEST_OK = 0,
	HFI2_DMS_EXT_DEST_RNR,		/* no destination available */
	HFI2_DMS_EXT_DEST_DROP,		/* unroutable destination */
	HFI2_DMS_EXT_DEST_NOMEM,	/* pre-allocation failed */
	/* destination consumed + completion already posted */
	HFI2_DMS_EXT_DEST_CONSUMED,
	HFI2_DMS_EXT_DEST_ALREADY_DELIVERED, /* destination already acquired */
};

typedef enum hfi2_dms_ext_dest_status (*hfi2_dms_ext_dest_resolve_fn)(
	struct hfi2_dms *dms, union hfi2_dms_key dms_key, u64 imm_data,
	u64 order_key, u16 flags, u32 xfer_size,
	struct hfi2_dms_page_provider *provider_out,
	u64 *rbuf_start_offset_out, void **cmpl_ctx_out);

typedef void (*hfi2_dms_ext_dest_complete_fn)(struct hfi2_dms *dms,
					      void *cmpl_ctx, int status);

typedef bool (*hfi2_dms_client_diag_access_fn)(void *ctx, u32 access_key);

union hfi2_dms_key {
	u64 value;
	struct {
		u32 access;
		u32 client;
	};
};

/**
 * struct hfi2_dms_page_provider - Abstraction for DMA page access.
 *
 * Decouples the DMS protocol layer from memory region management and
 * page pinning.  The provider owns one mechanism for source gather
 * (next_src_run, returning DMA runs directly from its own page array)
 * and a separate residency callback (pin_range) for buffers that must be
 * demand-pinned before a DMA run or TID program reads them.  The DMA
 * arrays the iterators return stay valid for the duration of the issuing
 * tracker (until its completion callback fires), guaranteed by
 * @provider_ctx lifetime.
 *
 * @pin_range: Ensure pages [from_page, from_page+npages) are resident and
 *             DMA-mapped, without returning a DMA array.  @writable selects
 *             DMA direction: pass true for buffers the device will write
 *             (RDMA-READ destinations, TID receive targets); pass false for
 *             read-only buffers (RDMA-WRITE sources, RDMA-READ-response
 *             sources).  Pre-pinned providers return 0 immediately.  Returns
 *             0 on success or -errno on fatal error / transient pressure.
 *             The bulksvc kworker may sleep here.
 * @next_src_run (early summary; see the full entry below): TX source-gather
 *             iterator.  Given a logical byte offset into the transfer source
 *             and a byte cap, fill @run with the contiguous DMA run starting
 *             at that offset.  The range must already be resident (pinned via
 *             pin_range for demand-pin providers).  Returns 0 / -errno.
 * @resolve_start: Translate a protocol @mr_offset (+ @size) into the
 *             0-based logical byte offset into the transfer buffer, applying
 *             the provider's addressing mode and bounds check.  Returns 0 /
 *             -EINVAL on a range violation.
 * @promote:   Optional non-blocking hint that this provider is now hot
 *             (DMS is committing to a transfer that will use it within
 *             one RTT). Fired bilaterally:
 *               - Responder side: handle_read_start / handle_write_start,
 *                 after access lookup succeeds.
 *               - Initiator side: _dms_rx_rift_continue_read_data /
 *                 _dms_tx_rift_continue_write_data, before START injection.
 *             MUST be idempotent and non-blocking. MUST NOT sleep, take
 *             locks, or call pin_range. Set NULL if not needed (e.g.,
 *             verbs MRs fully pinned at registration).
 *             @provider_ctx MUST remain valid until the tracker's
 *             completion callback returns.
 * @memcpy: Copy @size bytes between @data and logical byte offset
 *             @byte_offset of the transfer buffer; @is_read picks the
 *             direction (true: copy FROM the buffer into @data; false: copy
 *             @data INTO the buffer).  Walks across segments for a
 *             multi-segment provider so head/tail edge bytes land in the
 *             correct MR when they straddle a segment boundary.  Used for the
 *             eager and head/tail straggler host copies.  Returns 0 / -errno.
 * @pio_write: Write [@byte_offset, @byte_offset + @len) to PIO at @dest
 *             (mirror window) as DIV_ROUND_UP(@len, 8) qwords, zero-padding
 *             the last one.  May sleep.  All or nothing: return 0, or -errno
 *             with nothing written (a partly written PIO block cannot be
 *             reused).  A bounce copy that fails partway zero fills the rest
 *             and returns HFI2_DMS_PIO_WRITE_FILLED.
 * @next_src_run: Page-run iterator.  Given a logical byte offset and
 *             a byte cap, fill @run with the
 *             contiguous DMA run starting at that offset.  Returns 0 /
 *             -errno.
 * @get_runs:  Tidset (RX destination) loader.  Fill @runs with up to
 *             @max_runs consecutive DMA runs covering at most @max_bytes
 *             from logical byte offset @byte_offset, in order; every run has
 *             run_bytes > 0.  On return, every page of those runs a tidset
 *             can map -- at most HFI2_DMS_TID_SET_PAGES_MAX pages, counted
 *             from the first run's first page -- is resident and DMA-mapped,
 *             writable when @writable.  One call per tidset load, so the
 *             provider pins and walks its segments once.  Returns the run
 *             count (> 0) or -errno.  The bulksvc kworker may sleep here.
 * @resolve_start: Translate a protocol @mr_offset (+ @size) into the
 *             0-based logical byte offset into the transfer buffer.
 *             Multi-segment providers always resolve to 0.  Returns 0 /
 *             -EINVAL on a range violation.
 * @provider_ctx: Opaque context, interpreted only by the provider's own
 *             callbacks.  For the single-MR providers this is a struct
 *             hfi2_dms_mr * embedded in the concrete provider's container (the
 *             hfi2_dms_single_mr_* helpers read it directly; pin_range/promote
 *             recover the container via container_of); for the verbs
 *             multi-segment provider it is the verbs multiseg ctx.
 * @owner:     Return the cancel-by-owner key of the buffer behind this
 *             provider (see struct hfi2_dms_mr.owner), or NULL when it has
 *             none. NULL @owner means no owner.
 * @length: Total buffer length in bytes.
 */
struct hfi2_dms_run {
	dma_addr_t const *dma_pages;
	u64 page_offset;
	u64 run_bytes;
};

/*
 * Runs one tidset load asks @get_runs for. Every run the load consumes takes
 * at least one of the request's HFI2_DMS_DR_MAX_GATHER gather slots (a direct
 * recv_chunk element or a bounce edge), so a load can never use more.
 */
#define HFI2_DMS_TIDSET_RUNS_MAX	HFI2_DMS_DR_MAX_GATHER

struct hfi2_dms_page_provider {
	int (*pin_range)(void *provider_ctx, unsigned int from_page,
			 unsigned int npages, bool writable);
	int (*next_src_run)(struct hfi2_dms_page_provider const *pp,
			    u64 byte_offset, u64 max_bytes,
			    struct hfi2_dms_run *run);
	int (*memcpy)(struct hfi2_dms_page_provider const *pp,
		      u64 byte_offset, u64 size, void *data, bool is_read);
	int (*pio_write)(struct hfi2_dms_page_provider const *pp,
			 u64 byte_offset, u64 len, void __iomem *dest);
	int (*get_runs)(struct hfi2_dms_page_provider const *pp,
			u64 byte_offset, u64 max_bytes, bool writable,
			struct hfi2_dms_run *runs, u32 max_runs);
	int (*resolve_start)(struct hfi2_dms_page_provider const *pp,
			     u64 mr_offset, u32 size, u64 *byte_offset_out);
	void (*promote)(void *provider_ctx);
	void *(*owner)(struct hfi2_dms_page_provider const *pp);
	void *provider_ctx;
	u64 length;
	bool p2p_flush;
};

/*
 * Qword writer for @pio_write implementations.  Bytes appended with
 * hfi2_dms_pio_wr_bytes() are packed into qwords with no gaps -- a chunk that
 * ends partway through a qword is completed by the next chunk -- and each
 * whole qword is written to @dest with writeq(), advancing @dest.
 * hfi2_dms_pio_wr_finish() zero-pads and writes a final partial qword, if
 * any.  Source bytes past the last whole qword of a chunk are read one at a
 * time, so nothing past @src + @len is ever read.  Initialize with
 * { .dest = dest }.
 */
struct hfi2_dms_pio_wr {
	void __iomem *dest;
	u64 carry;		/* partial qword, little-endian */
	u32 carry_bytes;	/* valid bytes in @carry, 0..7 */
};

void hfi2_dms_pio_wr_bytes(struct hfi2_dms_pio_wr *w, const void *src,
			   u32 len);
void hfi2_dms_pio_wr_finish(struct hfi2_dms_pio_wr *w);

/* Write DIV_ROUND_UP(@len, 8) zero qwords at @dest. */
void hfi2_dms_pio_zero(void __iomem *dest, u64 len);

/*
 * @pio_write return: the range was written, but part of it as zeros, after a
 * source copy failed once some of it had been stored.
 */
#define HFI2_DMS_PIO_WRITE_FILLED	1

/*
 * End a @pio_write of @len bytes at @dest that failed with @err after @w
 * packed some of it.  With nothing stored, return @err (the packet is not
 * sent); otherwise finish @w, zero fill the rest of the range and return
 * HFI2_DMS_PIO_WRITE_FILLED.
 */
int hfi2_dms_pio_wr_fail(struct hfi2_dms_pio_wr *w, void __iomem *dest,
			 u64 len, int err);

/*
 * @pio_write body for memory reached only through @memcpy (dma-buf, GPU):
 * copy the range in HFI2_DMS_PIO_BOUNCE_BYTES chunks into a stack buffer
 * with @pp->memcpy() and pack each chunk to PIO.  A failed copy ends it as
 * hfi2_dms_pio_wr_fail() does.
 */
#define HFI2_DMS_PIO_BOUNCE_BYTES	512
int hfi2_dms_pio_write_bounce(struct hfi2_dms_page_provider const *pp,
			      u64 byte_offset, u64 len, void __iomem *dest);

/* @next_src_run for single-contiguous-MR sources: the whole remaining
 * transfer is one run read straight from the MR's dma_list.
 */
int hfi2_dms_single_mr_next_src_run(struct hfi2_dms_page_provider const *pp,
				    u64 byte_offset, u64 max_bytes,
				    struct hfi2_dms_run *run);

/* @resolve_start for single-contiguous-MR buffers: translate the protocol
 * offset to a logical byte offset against rbuf, bounds-checked.
 */
int hfi2_dms_single_mr_resolve_start(struct hfi2_dms_page_provider const *pp,
				     u64 mr_offset, u32 size,
				     u64 *byte_offset_out);

/* @owner for single-contiguous-MR buffers: the dms_mr's owner. */
void *hfi2_dms_single_mr_owner(struct hfi2_dms_page_provider const *pp);

/*
 * @get_runs body for single-contiguous-MR buffers: the whole remaining
 * buffer is one run, and the pages a tidset can map from it -- at most
 * HFI2_DMS_TID_SET_PAGES_MAX from the page holding @byte_offset -- are made
 * resident with the provider's own @pin before the run is read (a demand-pin
 * may publish the MR's dma_list). Each provider wraps this with its pin
 * function, a compile-time constant, so the call is direct once inlined.
 */
static __always_inline int
hfi2_dms_single_mr_get_runs(struct hfi2_dms_page_provider const *pp,
			    u64 byte_offset, u64 max_bytes, bool writable,
			    struct hfi2_dms_run *runs, u32 max_runs,
			    int (*pin)(void *provider_ctx, unsigned int from_page,
				       unsigned int npages, bool writable))
{
	struct hfi2_dms_mr const *mr;
	u64 len;
	unsigned int from_page, npages;
	int ret;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx || !runs || !max_runs ||
			 !max_bytes))
		return -EINVAL;

	/* Nothing before the buffer's end is pinned or read for a bad offset. */
	mr = pp->provider_ctx;
	if (byte_offset >= mr->extended_vaddr.len)
		return -EINVAL;

	len = min_t(u64, max_bytes, HFI2_DMS_TID_SET_PAGES_MAX * PAGE_SIZE -
				    (byte_offset & (PAGE_SIZE - 1)));
	len = min_t(u64, len, mr->extended_vaddr.len - byte_offset);
	from_page = byte_offset / PAGE_SIZE;
	npages = DIV_ROUND_UP(byte_offset + len, PAGE_SIZE) - from_page;

	ret = pin(pp->provider_ctx, from_page, npages, writable);
	if (ret < 0)
		return ret;

	ret = hfi2_dms_single_mr_next_src_run(pp, byte_offset, max_bytes,
					      &runs[0]);
	return ret < 0 ? ret : 1;
}

struct hfi2_dms_access {
	struct rb_node node;
	struct hfi2_dms_dlist_element element;
	union hfi2_dms_key dms_key;
	enum hfi2_dms_access_type type;
	struct hfi2_dms_access_completion completion;
	struct hfi2_dms_page_provider page_provider;
	u64 offset;
	u64 size;
	u32 active_count; // number of transfers currently using this access

	/*
	 * In-flight transfers admitted on this access (target trackers,
	 * linked via tracker->hdr.access_inflight). access_xfer_begin() walks
	 * this list to recognize a duplicate START for an already-admitted
	 * transfer -- matched by (remote_lid, remote_rift_key) -- so a
	 * re-injected or wire-duplicated START re-drives the existing transfer
	 * instead of colliding with the single-use credential (ACCESS_BUSY).
	 * Ephemeral accesses cap this at one in-flight transfer; persistent
	 * (verbs) accesses allow many.
	 */
	struct hfi2_dms_dlist inflight;

	enum hfi2_dms_access_state state;
	bool unregister_started;
	struct hfi2_dms_completion unregister;
};

/*
 * A speculative READ_START carries at most this many tidset requests
 * (spec[] is valid for [0, tid_count)).
 */
#define HFI2_DMS_READ_START_SPECULATIVE_TID_MAX 2

/*
 * Header-derived fields for READ_START, extracted from the LRH/BTH by the
 * packet handler. rx_id is the return-QP id recovered from bth[0] so the
 * target's responses egress to the initiator's correct receive context.
 * speculative is set from the received message type: the READ_START also
 * carried tid_count of the initiator's tidset requests.
 */
struct hfi2_dms_read_start_metadata {
	u32 slid;
	hfi2_dms_rift_key_t rx_rift_key;
	u16 size_qw;
	u8 rx_id;
	u8 port_idx;
	bool speculative;
	u16 entropy;
};

/*
 * One tidset request a READ_START_SPECULATIVE carries: its generation and the
 * sizes of its recv_chunk and gather arrays, which follow the READ_START body
 * in request order.
 */
struct hfi2_dms_spec_request {
	u16 generation;
	u8 recv_chunk_count;
	u8 gather_count;
} __packed;

/*
 * Wire-layout body for READ_START, READ_START_REPLAY and READ_START_SPECULATIVE
 * -- follows the OPA headers in the receive HDRQ entry and PIO command union
 * (header-embedded fields live in hfi2_dms_read_start_metadata).
 *
 * READ_START_SPECULATIVE is a READ_START sent with up to
 * HFI2_DMS_READ_START_SPECULATIVE_TID_MAX tidsets already enabled. It carries
 * each tidset's request -- the recv_chunks and gather elements a DATA_REQUEST
 * would -- so the responder serves them before the initiator knows it. The
 * arrays of all tid_count requests follow this body, inline when they fit the
 * control HDRQ header and otherwise whole at the start of the eager portion.
 * The other READ_STARTs set tid_count to 0.
 */
struct hfi2_dms_read_start_parameters {
	u32 tbytes;
	union hfi2_dms_key dms_key;
	u64 offset; // offset into access buffer; interpreted on the target as either a byte offset or a virtual address
	u16 flags;
	u8 tid_count;
	u8 reserved0;
	u64 imm_data;
	u64 order_key;
	struct hfi2_dms_spec_request spec[HFI2_DMS_READ_START_SPECULATIVE_TID_MAX];
	u32 reserved1;
} __packed __aligned(4);

struct hfi2_dms_write_start_metadata {
	u32 slid;
	hfi2_dms_rift_key_t tx_rift_key;
	u16 flags;
	u8 port_idx;
};

struct hfi2_dms_write_start_parameters {
	u32 xfer_size;
	union hfi2_dms_key dms_key;
	u64 offset; // offset into access buffer; interpreted on the target as either a byte offset or a virtual address
	u64 imm_data;
	u64 order_key;
	u16 eager_nbytes;
	u8 reserved[6];
	u64 reserved_qw;	/* sent as zero */
	u64 eager_payload;	/* an eager payload starts here */
} __packed __aligned(4);

enum hfi2_dms_xfer_type {
	HFI2_DMS_XFER_TYPE_TARGET = 0,
	HFI2_DMS_XFER_TYPE_INITIATOR,
	HFI2_DMS_XFER_TYPE_COUNT,
	HFI2_DMS_XFER_TYPE_NONE,
};

enum hfi2_dms_xfer_side {
	HFI2_DMS_XFER_SIDE_RX = 0,
	HFI2_DMS_XFER_SIDE_TX,
	HFI2_DMS_XFER_SIDE_COUNT,
	HFI2_DMS_XFER_SIDE_NONE,
};

enum hfi2_dms_xfer_op {
	HFI2_DMS_XFER_OP_WRITE = 0,
	HFI2_DMS_XFER_OP_READ,
	HFI2_DMS_XFER_OP_COUNT,
	HFI2_DMS_XFER_OP_NONE,
};

struct hfi2_dms_ring {
	u64 head;
	u64 tail;
	u64 mask;
	u32 size;
	u32 max_size;
};

struct hfi2_dms_tracker_perf {
	ktime_t lifetime[2];
	ktime_t rift_wait[2];
};

enum hfi2_dms_tracker_health_state {
	HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT = 0,
	HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION,

	HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START,
	HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST,
	HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA,
	/* Speculative READ: its tidsets are enabled and requested in the
	 * READ_START, and no DATA_SPECULATIVE has latched the responder's rift
	 * key yet. The first one moves to WAITING_FOR_REMOTE_DATA.
	 */
	HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_SPECULATIVE,
	HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK,

	/* Gated health states. */
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START,
	/* WAW child: released at parent data egress */
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY,
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START,
	/* mid RAR child: released at parent narrow-to-one */
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START,
	/* large RAR child: released at full parent completion */
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE,
	/* eager WAW child: released at pio injection. */
	HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO,

	HFI2_DMS_HEALTH_WAITING_COUNT,
};

/* bit packed pointer to a hfi2_dms_tracker */
struct hfi2_dms_transfer_handle {
	u64 value;
};
_Static_assert(sizeof(struct hfi2_dms_transfer_handle) == 8,
	       "transfer handle must be exactly one QW");

#define HFI2_DMS_TRANSFER_HANDLE_NONE \
	((struct hfi2_dms_transfer_handle){ .value = 0 })

/*
 * Per-submission policy bits a caller passes in the u64 submit_flags argument.
 * Never on the wire. DMS interprets them once at submit time and then operates
 * on its own derived state, keeping the interior free of caller policy.
 */
enum hfi2_dms_submit_flags {
	HFI2_DMS_SUBMIT_PARK_ON_PARENT_ERROR = (1ull << 0),
	HFI2_DMS_SUBMIT_FAST_FAIL            = (1ull << 1),
	/* initiator: target lane T in the TARGET_LANE field, else T = own lane */
	HFI2_DMS_SUBMIT_TARGET_LANE          = (1ull << 2),
};

#define HFI2_DMS_SUBMIT_TARGET_LANE_SHIFT	16

static inline u64 hfi2_dms_submit_flags_set_target_lane(u64 flags, u32 lane)
{
	return flags | HFI2_DMS_SUBMIT_TARGET_LANE |
	       ((u64)(lane & HFI2_DMS_LANE_SEL_MASK) <<
		HFI2_DMS_SUBMIT_TARGET_LANE_SHIFT);
}

#define HFI2_DMS_SUBMIT_STALE_SHIFT_SHIFT	8
#define HFI2_DMS_SUBMIT_STALE_SHIFT_BITS	8
#define HFI2_DMS_SUBMIT_STALE_SHIFT_MASK \
	(((1ull << HFI2_DMS_SUBMIT_STALE_SHIFT_BITS) - 1) << HFI2_DMS_SUBMIT_STALE_SHIFT_SHIFT)

static inline u64 hfi2_dms_submit_flags_set_stale_shift(u64 flags, u8 shift)
{
	return (flags & ~HFI2_DMS_SUBMIT_STALE_SHIFT_MASK) |
	       ((u64)shift << HFI2_DMS_SUBMIT_STALE_SHIFT_SHIFT);
}

static inline u8 hfi2_dms_submit_flags_get_stale_shift(u64 flags)
{
	return (u8)((flags & HFI2_DMS_SUBMIT_STALE_SHIFT_MASK) >>
		    HFI2_DMS_SUBMIT_STALE_SHIFT_SHIFT);
}

/* Fast-fail reliability mode (dms_fast_fail module param); latched per WR. */
bool hfi2_dms_fast_fail_enabled(void);

/* FGAR master enable (dms_fgar_enable module param); read live per packet. */
bool hfi2_dms_fgar_enabled(void);

/*
 * The per-DATA-packet hot set (stale_time through entropy) shares the
 * first cacheline with @dlist; diagnostics/chaining state follows.
 * @dlist must stay at offset 0: SDMA waitlist code casts list nodes back
 * to trackers.
 */
struct hfi2_dms_tracker_hdr {
	struct hfi2_dms_dlist_element dlist;

	/* Next staleness deadline (per-tracker exponential backoff) */
	ktime_t stale_time;
	/*
	 * Monotonic lifetime byte-progress token (TX: bytes accepted for
	 * egress; RX: bytes from generation-valid DATA). Never reset across
	 * retries; bytes merely queued under backpressure are not counted.
	 * Sampled into status responses and compared only for inequality --
	 * a pure liveness signal.
	 */
	u64 byte_odometer;
	u32 status_req_count;
	enum hfi2_dms_tracker_health_state health_state;
	hfi2_dms_rift_key_t local_rift_key;
	hfi2_dms_rift_key_t remote_rift_key;
	u32 remote_lid;
	enum hfi2_dms_xfer_type type;
	enum hfi2_dms_xfer_side side;
	enum hfi2_dms_xfer_op op;
	u8 port_idx;
	u8 generation;

	/*
	 * Per-request entropy owned by the initiator. It is the single source of
	 * truth that feeds BOTH halves of the 2-part ordering contract: it is
	 * hashed to a deterministic SDMA engine (_dms_sdma_engine_idx_from_entropy)
	 * AND stamped into the 16B LRH Entropy field so the fabric keeps the
	 * request on one route. Stored on the tracker (not read_request_state) so a
	 * chained child can inherit its parent's entropy -- a future change will set
	 * child->hdr.entropy = parent->hdr.entropy to co-order parent and child.
	 */
	u16 entropy;

	/*
	 * Membership in the owning access's in-flight list while this target
	 * tracker holds an access credential (between access_xfer_begin and
	 * access_xfer_end). This is a SEPARATE node from @dlist on purpose: the
	 * two memberships CAN be held at the same time -- e.g. after
	 * access_xfer_begin() links access_inflight, _rift_allocate() may park
	 * the same tracker on the rift waitlist via @dlist, and the cancel paths
	 * thread it onto a pending-cancel list via @dlist while it is still on
	 * access_inflight. Do not union or merge the two nodes.
	 */
	struct hfi2_dms_dlist_element access_inflight;

	/*
	 * Absolute-max lifetime ceiling, sampled at allocation and restarted once
	 * when the tracker gets its rift key. birth_time bounds a tracker's total
	 * lifetime as a last-resort backstop.
	 */
	ktime_t birth_time;
	/*
	 * Forward-progress clock. last_progress_time is advanced ONLY when
	 * byte_odometer moves (real egress/ingress), tracked against
	 * last_progress_odometer. _tracker_is_dead reclaims a slot whose odometer
	 * has been frozen for HFI2_DMS_TRACKER_PROGRESS_MAX_NS -- a genuinely
	 * wedged transfer -- while a transfer moving even one byte per window
	 * survives. This is the liveness signal (odometer advance), distinct
	 * from mere peer-request arrival (status_req_count), so a status-polled
	 * but zero-progress chain-head cannot survive forever and freeze the
	 * transfers chained behind it (whose wedged head would otherwise never
	 * deliver the error completion BTS relies on to flush parked children).
	 * Also restarted when the tracker leaves a rift key or tidset wait.
	 */
	ktime_t last_progress_time;
	u64 last_progress_odometer;

	u64 order_key;

	u32 status_rsp_count;
	u32 rnr_retry_count;
	bool rnr_pending;

	s64 local_rift_number;
	struct {
		u64 last_known_packet_progress;
		s64 last_known_rift_tracker_ticket;
		s64 last_known_rift_global_assigned;
		u64 last_known_tidset_progress;
	} remote_status;

	struct hfi2_dms_transfer_handle parent_handle;
	struct hfi2_dms_transfer_handle child_handle;
	bool chain_child_released;
	bool chain_signalled;
	/* Eager WRITE's payload was accepted by the in-order PIO send context. */
	bool chain_pio_released;
	/* Park gate chosen at bind: READ_START, DATA_START, DATA_START_LARGE, or WRITE_START. */
	enum hfi2_dms_tracker_health_state chain_park_at;

	bool park_on_parent_error;
	bool fast_fail;
	/* Per-submission left-shift on the initial stale backoff. */
	u8 stale_backoff_shift;

#if HFI2_DMS_COUNTERS_ENABLE
	struct hfi2_dms_tracker_perf perf;
#endif
};

static_assert(offsetof(struct hfi2_dms_tracker_hdr, dlist) == 0,
	      "SDMA waitlist casts list nodes back to trackers");
static_assert(offsetof(struct hfi2_dms_tracker_hdr, entropy) + sizeof(u16) <=
	      SMP_CACHE_BYTES,
	      "tracker packet-path fields must fit in the first cache line");

struct hfi2_dms_sdma_waiters {
	struct hfi2_dms_dlist waitlist;
};

enum hfi2_dms_tx_tracker_op {
	HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE = 0,
	HFI2_DMS_TX_TRACKER_OP_RDMA_READ,

	HFI2_DMS_TX_TRACKER_OP_COUNT,
};

/*
 * DATA_REQUEST fields recovered from the LRH/BTH (not the wire body), passed by
 * value -- mirrors hfi2_dms_read_start_metadata. rx_id is the requester's
 * return-QP id from bth[0].
 */
struct hfi2_dms_data_request_metadata {
	u32 slid;
	u32 size_qw;
	u8 rx_id;
	/* Set from the wire msg_type (DATA_REQUEST vs DATA_REQUEST_REPLAY);
	 * consumed by the DATA-emission path so responses to a replayed
	 * request are themselves stamped DATA_REPLAY.
	 */
	bool is_replay;
};

struct hfi2_dms_tx_tracker {
	struct hfi2_dms_tracker_hdr hdr;

	u32 total_payload;
	u32 payload_remaining;

	u64 xfer_start_byte_offset;

	enum hfi2_dms_tx_tracker_op op;
	union {
		struct {
			struct hfi2_dms_page_provider page_provider;
			struct hfi2_dms_completion completion;
			union hfi2_dms_key dms_key;
			u64 rx_offset;
			u64 imm_data;
			u16 flags;
			u16 chain_inherit_entropy;
			bool chain_inherit_valid;
			bool unaligned;
			/*
			 * Served a DATA_REQUEST_REPLAY: a replay re-credits bytes
			 * already credited, so payload_remaining reaching 0 no
			 * longer proves every range was submitted. The chained
			 * child is then released only at completion.
			 */
			bool replayed;
			/*
			 * Cached once at construction from total_payload: true iff
			 * this transfer's entire DATA_REQUEST burst fits within a
			 * single SDMA engine's worth of data. Gates whether the
			 * DATA_REQUEST handler may self-pin a fresh engine
			 * (head-of-chain bootstrap) versus always rotating
			 * (multi-engine transfers must spread load, not pin to
			 * one engine for their whole burst).
			 */
			bool is_single_engine;
		} write;
		struct {
			struct hfi2_dms_access * access;
			struct hfi2_dms_read_start_metadata metadata;
			struct hfi2_dms_read_start_parameters parameters;
			u64 imm_data;
			u16 flags;
		} read;
	};

};

enum hfi2_dms_sdma_engine_idx {
	HFI2_DMS_SDMA_ENGINE_IDX_0 = 0,
	HFI2_DMS_SDMA_ENGINE_IDX_1,
	HFI2_DMS_SDMA_ENGINE_IDX_2,
	HFI2_DMS_SDMA_ENGINE_IDX_3,
	HFI2_DMS_SDMA_ENGINE_IDX_4,
	HFI2_DMS_SDMA_ENGINE_IDX_5,
	HFI2_DMS_SDMA_ENGINE_IDX_6,
	HFI2_DMS_SDMA_ENGINE_IDX_7,
	HFI2_DMS_SDMA_ENGINE_IDX_8,
	HFI2_DMS_SDMA_ENGINE_IDX_9,
	HFI2_DMS_SDMA_ENGINE_IDX_10,
	HFI2_DMS_SDMA_ENGINE_IDX_11,
	HFI2_DMS_SDMA_ENGINE_IDX_12,
	HFI2_DMS_SDMA_ENGINE_IDX_13,
	HFI2_DMS_SDMA_ENGINE_IDX_14,
	HFI2_DMS_SDMA_ENGINE_IDX_15,
	HFI2_DMS_SDMA_ENGINE_IDX_ANY,

	HFI2_DMS_SDMA_ENGINE_IDX_COUNT,
};

enum hfi2_dms_fabric_port_idx {
	HFI2_DMS_FABRIC_PORT_IDX_0 = 0,
	HFI2_DMS_FABRIC_PORT_IDX_1,

	HFI2_DMS_FABRIC_PORT_IDX_COUNT,
};

struct hfi2_dms_sdma_parameters {
	u32 tid_info;
	u8 rx_id;
	u8 gather_count;	/* elements in hfi2_dms_sdma_info.gather[] */
	u16 generation;
	u16 entropy;   /* selects SDMA engine + stamps DATA packet LRH */
	/*
	 * DATA, DATA_REPLAY or DATA_SPECULATIVE selector for the shared SDMA
	 * inject path.
	 * The inject path indexes protocol_cmd_templates[] and
	 * counters.tx_sent[] with it; only ever assigned from a literal
	 * enum hfi2_dms_msg_type constant (never from the wire), so the
	 * enum type here lets the compiler/sparse catch a mismatched
	 * assignment instead of silently truncating an out-of-range value
	 * into a bare u8.
	 */
	enum hfi2_dms_msg_type msg_type;
};

/*
 * One SDMA inject. A DATA inject sends the source elements gather[], each
 * relative to page_offset, into one recv_chunk; nbytes is their summed length
 * (source bytes, excluding quadword pad). The list is held here, not by
 * reference, so a parked inject outlives the DATA_REQUEST it came from.
 */
struct hfi2_dms_sdma_info {
	hfi2_dms_rift_key_t local_rift_key;
	struct hfi2_dms_page_provider page_provider;
	u64 page_offset;
	u32 nbytes;
	union {
		struct {
			struct hfi2_dms_sdma_parameters parameters;
			struct hfi2_dms_gather gather[HFI2_DMS_DR_CHUNK_MAX_GATHER];
		};
		union hfi2_dms_proto_cmd cmd;
	};
};

static_assert(sizeof(struct hfi2_dms_sdma_parameters) +
	      HFI2_DMS_DR_CHUNK_MAX_GATHER * sizeof(struct hfi2_dms_gather) <=
	      sizeof(union hfi2_dms_proto_cmd),
	      "DATA inject gather list must fit the proto command space");

/*
 * A whole DATA_REQUEST sent as one SDMA submission: every recv_chunk of the
 * request, each consuming its gather elements in order from gather[]. Held
 * by value so a parked request outlives the DATA_REQUEST packet it came from.
 * nbytes is the summed source length of all chunks (excluding quadword pad);
 * the request is credited once, by nbytes, when the submission is accepted.
 */
struct hfi2_dms_sdma_req {
	hfi2_dms_rift_key_t local_rift_key;
	u8 rx_id;
	u8 nchunks;
	u8 ngather;
	u16 generation;
	u16 entropy;
	enum hfi2_dms_msg_type msg_type;
	u32 nbytes;
	u64 page_offset;
	struct hfi2_dms_recv_chunk chunk[HFI2_DMS_DR_MAX_CHUNKS];
	struct hfi2_dms_gather gather[HFI2_DMS_DR_MAX_GATHER];
};

struct hfi2_dms;
typedef int (*hfi2_dms_sdma_inject_fn)(struct hfi2_dms *, enum hfi2_dms_sdma_engine_idx const, struct hfi2_dms_sdma_info const *, struct hfi2_dms_tx_tracker *);

/*
 * A parked SDMA inject. @req is NULL for a single-chunk inject described by
 * @info (sent by @inject); otherwise it is a whole parked DATA_REQUEST
 * (struct hfi2_dms_sdma_req, allocated with the waiter and freed with it).
 */
struct hfi2_dms_sdma_tracker {
	struct hfi2_dms_tracker_hdr hdr;
	struct hfi2_dms_sdma_info info;
	hfi2_dms_sdma_inject_fn inject;
	u64 xfer_bytes;
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_sdma_req *req;
};

static_assert(sizeof(struct hfi2_dms_sdma_req) <= 512,
	      "a parked request is one small allocation");

enum hfi2_dms_rx_tracker_op {
	HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE = 0,
	HFI2_DMS_RX_TRACKER_OP_RDMA_READ,
	HFI2_DMS_RX_TRACKER_OP_EXT_DEST,

	HFI2_DMS_RX_TRACKER_OP_COUNT,
 };

struct hfi2_dms_rx_tracker {
	struct hfi2_dms_tracker_hdr hdr;
	struct hfi2_dms *dms;

	u32 payload_remaining;
	u32 total_payload;
	u32 tidsets_in_use;
	u64 tidsets_inflight_bitmap;
	/* READ-chain narrow-to-one inheritance only (see _chain_signal_final_data_request). */
	u16  chain_inherit_entropy;
	bool chain_inherit_valid;

	/*
	 * Bytes of the transfer requested so far: the source offset of the next
	 * request, relative to sbuf_start_offset, and, past rbuf_start_offset,
	 * where its destination begins (the two move together since every
	 * destination edge lands through the tidset). A cursor, not an offset:
	 * it advances as each tidset request is made.
	 */
	u32 sbuf_cursor;
	u64 rbuf_start_offset; // Offset into the rbuf where the data starts
	u64 sbuf_start_offset; // Offset into the sbuf where the data starts; interpreted on the remote as either a byte offset or a virtual address

	// receiving buffer
	struct hfi2_dms_page_provider page_provider;

	enum hfi2_dms_rx_tracker_op op;
	union {
		struct {
			struct hfi2_dms_access * access;
			struct hfi2_dms_write_start_metadata metadata;
			struct hfi2_dms_write_start_parameters parameters;
			/* externally-resolved write destination
			 * (op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST): opaque
			 * upper-layer context handed back at completion.
			 * NULL for an access-keyed RDMA-WRITE target.
			 */
			void *ext_cmpl_ctx;
		} write;

		struct {
			union hfi2_dms_key dms_key;
			struct hfi2_dms_completion completion;
			u16 flags;
			u16 unused[3];
			u64 imm_data;
			struct {
				u32 id;
				u32 tid_info;
				u64 read_size_qw;
			} tidset;
		} read;
	};
};

enum hfi2_dms_tidset_state {
	HFI2_DMS_TIDSET_STATE_FREE = 0,
	HFI2_DMS_TIDSET_STATE_ENABLED,
	HFI2_DMS_TIDSET_STATE_DRAINING,
	HFI2_DMS_TIDSET_STATE_DISABLED
};

struct hfi2_dms_read_request_state {
	/* --- cache line 0: hot fields accessed on every DATA packet --- */
	u64 remaining_qws;
	u64 total_requested_qws;
	struct hfi2_dms_rx_tracker *rx_tracker;
	u32 tid_set;
	enum hfi2_dms_tidset_state state;
	u16 generation;
	u8 drain_count;
	u8 saved_port_idx;
	/*
	 * The request has bounce edges (read_request_chunks[].scatter_count
	 * != 0). Kept here so completion and reset of an aligned request never
	 * touch the per-tidset chunk storage.
	 */
	bool has_bounce;
	ktime_t stale_time;
	/* --- cache line 1: less frequently accessed --- */
	ktime_t disable_ts;
	ktime_t drain_time;
	u32 saved_size_qw;
	u32 saved_remote_lid;
	hfi2_dms_rift_key_t saved_remote_rift_key;
	/* per-request entropy, stable across re-inject */
	u16 saved_entropy;
	/*
	 * True while this tidset's unit is charged against
	 * dms->spec_tidsets_available. The charge is returned exactly once, at
	 * the tidset's FREE transition, and survives an in-place re-arm by
	 * _tidset_enable(). Returning it while the tidset is still
	 * ENABLED/DRAINING/DISABLED would over-subscribe the pool.
	 */
	bool spec_charged;
	struct {
		ktime_t begin;
		ktime_t tidset_enabled;
		ktime_t first_data;
		ktime_t end;
	} perf;
	u8 flags; /* DATA_REQUEST bit flags (HFI2_DMS_DR_FLAG_*) */
	/* Pad to 128 bytes for power-of-2 tid_set indexing. */
	u8 reserved[15];
};

#define HFI2_DMS_READ_REQUEST_STATE_SIZE_CHECK() \
	BUILD_BUG_ON(sizeof(struct hfi2_dms_read_request_state) != 128)

/*
 * One sub-quadword destination edge landed in a tidset's bounce page: the
 * responder sends @length source bytes from @sbuf_offset into @bounce_offset
 * of bounce page 0, and completion copies them to @dest_offset, a coordinate
 * of the rx_tracker's page_provider memcpy.
 */
struct hfi2_dms_bounce_scatter {
	u64 dest_offset;
	u32 sbuf_offset;
	u16 bounce_offset;
	u8 length;
};

/*
 * recv_chunks and gather elements of a tidset's DATA_REQUEST, built by one
 * _tidset_enable pass and kept for the DRAINING re-inject of the same request.
 *
 * A request whose last recv_chunk lands in the bounce page also records where
 * each of that chunk's edges goes (scatter[], scatter_count edges; nonzero
 * means the request uses the bounce TID pair). scatter_valid arms the copy-out
 * at tidset completion for request generation scatter_generation only;
 * cycle_real_bytes is then the request's destination byte count (the chunk
 * lengths without quadword pad), debited from payload_remaining after the
 * copy-out succeeds.
 */
struct hfi2_dms_read_request_chunks {
	/* The counts and scatter state, then the request arrays. */
	u32 load_npages;	/* dma slots filled */
	u32 cycle_real_bytes;
	u16 scatter_generation;
	u8 load_nchunks;	/* recv_chunks filled */
	u8 load_ngather;	/* gather elements filled */
	u8 scatter_count;
	bool scatter_valid;
	struct hfi2_dms_recv_chunk chunk[HFI2_DMS_DR_MAX_CHUNKS];
	struct hfi2_dms_gather gather[HFI2_DMS_DR_MAX_GATHER];
	dma_addr_t load_dma[HFI2_DMS_TID_SET_PAGES_MAX];
	struct hfi2_dms_bounce_scatter scatter[HFI2_DMS_DR_CHUNK_MAX_GATHER];
} ____cacheline_aligned;

/*
 * Per-tidset bounce backing for sub-quadword destination edges:
 * the landing pages of the recv_chunk whose gather elements are a tidset's
 * misaligned head/tail bytes. One cached kernel page, DMA-mapped
 * DMA_FROM_DEVICE (streaming, not coherent, so the scatter-out memcpy reads
 * cached memory), mapped at the tidset's last RcvArray pair only while a
 * request that uses it is ENABLED.
 */
struct hfi2_dms_tidset_bounce_backing {
	struct page *bounce_page[HFI2_DMS_TIDSET_BOUNCE_PAGE_COUNT];
	dma_addr_t bounce_dma[HFI2_DMS_TIDSET_BOUNCE_PAGE_COUNT];
};

struct hfi2_dms_tracker_mgr {
	struct hfi2_dms_dlist free;
	struct hfi2_dms_dlist blocklist;
};

struct hfi2_dms;
struct hfi2_dms_work_item;
typedef int (*hfi2_dms_work_fn)(struct hfi2_dms *dms, struct hfi2_dms_work_item *item);

struct hfi2_dms_work_item {
	struct hfi2_dms_dlist_element dlist;
	hfi2_dms_work_fn work_fn;
	ktime_t enqueue_time;
	u8 data[96];
};

struct hfi2_dms_work_item_block {
	struct hfi2_dms_dlist_element dlist;
	struct hfi2_dms_work_item items[100];
};

struct hfi2_dms_work_item_mgr {
	struct hfi2_dms_dlist active;
	struct hfi2_dms_dlist free;
	struct hfi2_dms_dlist blocklist;
};

struct hfi2_dms_mem_coh {
	void *kvaddr; // kernel virtual address
	dma_addr_t phys_addr; // physical address
	u64 len; // length of the memory region in bytes
	struct page *pg;
};

struct hfi2_dms_ahg_header_set {
	struct hfi2_dms_dlist_element dlist;
	u32 desc_idx; // descriptor index for these headers
	u64 seq_end; /* shared engines: hfi2_dms_sde_share.seq after them */
	u8 port_idx;
	struct hfi2_dms_mem_coh headers[HFI2_DMS_AHG_HEADERS_PER_SET];
};

struct hfi2_dms_ahg_header_block {
	struct hfi2_dms_dlist_element dlist;

	struct hfi2_dms_mem_coh backing_mem;
	struct hfi2_dms_ahg_header_set header_sets[HFI2_DMS_AHG_HEADER_BLOCK_SIZE];
};

// no active list, active headers managed elsewhere
struct hfi2_dms_ahg_header_mgr {
	struct hfi2_dms_dlist free;
	struct hfi2_dms_dlist blocklist;
};

/*
 * DMA page pool: 4 KiB DMA-coherent pages handed out from a free list.
 * Grows on demand by allocating another block (HFI2_DMS_PAGE_POOL_BLOCK_PAGES
 * pages) when the free list empties, up to HFI2_DMS_PAGE_POOL_MAX_PAGES.
 * Only touched from the single-threaded bulksvc event worker, so no locks.
 */
/* Initial free-list size and on-demand grow granule. */
#define HFI2_DMS_PAGE_POOL_BLOCK_PAGES (256)
/* Hard ceiling on total pooled pages across all blocks. */
#define HFI2_DMS_PAGE_POOL_MAX_PAGES   (16384)

struct hfi2_dms_page {
	struct list_head link;       /* on dms_pages.free */
	struct hfi2_dms_mem_coh mem; /* 4 KiB coherent slice: kvaddr + phys */
	struct hfi2_dms *owner;      /* set at block alloc; used by page_put */
};

struct hfi2_dms_page_block {
	struct list_head link;       /* on dms_pages.blocklist */
	struct hfi2_dms_mem_coh backing_mem; /* one big coherent allocation */
	struct hfi2_dms_page pages[HFI2_DMS_PAGE_POOL_BLOCK_PAGES];
};

struct hfi2_dms_page_mgr {
	struct list_head free;
	struct list_head blocklist;
	u32 total_pages; /* pages across all allocated blocks; vs MAX ceiling */
};

struct hfi2_dms_allocation_stats {
	u64 sdma_batch_setup_allocs;
	u64 sdma_batch_setup_failures;
	u64 sdma_batch_growth_allocs;
	u64 sdma_batch_growth_failures;
	u64 sdma_completion_fifo_setup_allocs;
	u64 sdma_completion_fifo_setup_failures;
	u64 sdma_completion_fifo_engine_allocs[TXE_NUM_SDMA_ENGINES];
	u64 sdma_completion_fifo_engine_failures[TXE_NUM_SDMA_ENGINES];
	u64 page_block_setup_allocs;
	u64 page_block_setup_failures;
	u64 page_block_growth_allocs;
	u64 page_block_growth_failures;
};

struct hfi2_dms_sdma_completion_fifo;

/*
 * With more than one DMS lane every lane places descriptors on every bulksvc
 * SDMA engine.  One of these per engine, owned by bulksvc and shared by all
 * lanes: @lock serializes everything that touches the engine's ring (tail,
 * cached head, tail CSR and @seq); @seq counts the descriptors placed on the
 * engine so far, so a lane can tell whether its own descriptors have
 * egressed without reading ring indices that other lanes keep advancing;
 * @run_descs is the engine's open desc_place() run (placed, not yet padded),
 * which whichever lane next appends to the ring or writes its tail CSR pads
 * first, so a run of packets is padded once rather than per packet.
 */
struct hfi2_dms_sde_share {
	spinlock_t lock;	/* ring, cached head, tail CSR, fields below */
	u64 seq;
	u32 run_descs;
} ____cacheline_aligned_in_smp;

struct hfi2_dms_sde_rsrc {
	struct hfi2_dms_dlist active_ahg_headers;

	/*
	 * SDMA ring-layer per-engine state.  sdma_pending is the FIFO of
	 * committed-but-not-yet-fully-drained batch node rings the poll step
	 * places into the HW ring; sdma_completion_fifo holds the
	 * placed-but-not-yet-egressed commits' completion identities;
	 * sdma_teardown_active gates new placement to -ESHUTDOWN.
	 * Single-threaded poll model, so no locks/atomics: this is per-DMS
	 * state even when lanes share the engine (only the ring is shared).
	 */
	struct list_head sdma_pending;
	struct hfi2_dms_sdma_completion_fifo *sdma_completion_fifo;
	bool sdma_teardown_active;

	/*
	 * Hardware-visible descriptor occupancy and its lifetime high-water mark.
	 * The DMS worker is their sole writer; debug readers use READ_ONCE().
	 */
	u32 ring_resident_current;
	u32 ring_resident_high_water;

	/* desc_place() advanced descq_tail; doorbell_all() publishes it. */
	bool sdma_doorbell_pending;

	/*
	 * Descriptors desc_place() has placed but not yet padded, when the
	 * engine is not shared (else hfi2_dms_sde_share.run_descs).
	 */
	u32 sdma_run_descs;
};

struct dms_perf_counters {
	u64 transfers;
	u64 bytes;
	ktime_t total_time;
	ktime_t rift_wait_time;
};

struct dms_perf_tidset {
	ktime_t enable;
	ktime_t rtt;
	ktime_t total;
	ktime_t data;
	u32 bytes;
	hfi2_dms_rift_key_t local;
	hfi2_dms_rift_key_t remote;
	u64 order_key;
	u32 tbytes;
};

struct dms_counters
{
	u64 send_total;
	u64 rget;
	u64 make_data_request;
	u64 map_tids;
	u64 handle_data_request;
	u64 tid_send;
	u64 first_packet_send;
	u64 next_packet_send;
	u64 hdrq_drain;
	u64 hdrq_drain_packet;
	u64 handle_data;
	u64 read_request_done;

	ktime_t sending_first_rr;
	ktime_t rcv_first_data;
	ktime_t rcv_first_rr;
	ktime_t last_sdma_sent;

	struct dms_perf_counters perf[HFI2_DMS_XFER_TYPE_COUNT][HFI2_DMS_XFER_OP_COUNT];

	u64 staleness_exponential_triggers;
	u64 staleness_exempt_skipped;

	/*
	 * Always-on per-msg-type wire-packet counters, indexed by
	 * enum hfi2_dms_msg_type. Unlike packet_drop.entries[].user_dropped/
	 * user_delivered (test-only, gated by HFI2_DMS_TESTING_ENABLE), these
	 * exist on every production build so a stress run can reconcile this
	 * node's tx_sent[type] against the peer's rx_received[type] without
	 * requiring a testing-enabled rebuild. A mismatch after a run with
	 * zero in-flight trackers (access_xfer_begin == access_xfer_end) is
	 * direct evidence of a fabric/HW packet drop, as distinct from the
	 * health protocol's own stale-timer counters below, which only prove
	 * that *no progress was observed* -- not that a packet was actually
	 * lost. See health-protocol.md "Observability: TX/RX Packet
	 * Reconciliation".
	 */
	u64 tx_sent[HFI2_DMS_MSG_TYPE_COUNT];
	u64 rx_received[HFI2_DMS_MSG_TYPE_COUNT];

#if HFI2_DMS_RHF_TEST_ENABLE
	/*
	 * Valid native-16B packets host-delivered through DMS private RCD
	 * pollers, by wire length quadword class. Debug only.
	 */
	u64 rhf_test[HFI2_PBC_TEST_NCNTR];
#endif

	/* health protocol counters */
	u64 health_tidset_draining;
	u64 health_tidset_drain_reinject;
	u64 health_tidset_drain_reinject_fail;
	u64 health_tidset_drain_failed;
	u64 health_tidset_disabled_removed;
	u64 health_status_req_injected;
	u64 health_status_req_packets;
	u64 health_status_rsp_waiting_rift;
	u64 health_status_rsp_waiting_tidset;
	u64 health_status_rsp_in_progress;
	u64 health_status_rsp_complete;
	u64 health_status_rsp_complete_transient; /* COMPLETE with payload outstanding: re-armed, not completed */
	u64 health_status_rsp_not_started;
	u64 health_status_rsp_not_found;
	u64 health_status_rsp_cancelled;
	u64 health_tracker_dead;
	u64 health_fast_fail_cancel; /* fast-fail tracker cancelled instead of replayed */
	/* fast-fail READ target: status request sent instead of cancel */
	u64 health_status_req_fast_fail_read_target;
	u64 health_status_rsp_parked;	/* PARKED answer received */
	/* go-back-N replay counters */
	u64 gbn_windows_armed;		/* replay windows opened */
	u64 gbn_provider_claimed;	/* providers claimed from cancelled cookies */
	u64 gbn_wrs_replayed;		/* WRs re-submitted */
	u64 gbn_wrs_dropped;		/* WRs surfaced terminally (budget/no-path) */
	u64 gbn_intercept_declined;	/* intercept asked but declined */
	u64 gbn_teardown_freed;		/* pending records freed at QP teardown */
	u64 gbn_teardown_active_cancelled;    /* live inflight op cancelled at QP teardown */
	u64 gbn_teardown_active_already_gone; /* inflight op already retired (-ENOENT) */
	u64 gbn_teardown_active_cancel_failed; /* inflight cancel returned unexpected error */
	u64 gbn_drop_qp_errored;	/* terminal drops that moved the QP to ERR (live-prefix RC ordering) */
	u64 gbn_drop_mr_gone;		/* terminal drops: MR gone under parked window */
	u64 gbn_suffix_prefix_spared;	/* prefix WRs left in flight by suffix narrowing */
	u64 gbn_rx_stale_dropped;	/* receiver: stale-generation imm completions dropped (GBN replay) */
	u64 gbn_rx_dup_suppressed;	/* receiver: duplicate imm delivery suppressed on ack-loss replay (GBN) */
	u64 cqe_rx_out_of_order;	/* receiver: slots readied ahead of the delivery watermark */
	u64 cqe_tx_out_of_order;	/* initiator: local completions retired out of issue order */
	u64 held_for_ordering_armed;	/* held records parked */
	/* fatal: predecessor retired SUCCESS in order while successors held
	 * (QP errored)
	 */
	u64 held_for_ordering_faulted;
	u64 held_for_ordering_replayed;	/* absorbed into a predecessor replay window */
	u64 health_nack_sent;
	u64 health_invalid_client;
	u64 health_invalid_rift_key;
	u64 health_remaining_qws_underflow;
	u64 health_invalid_data_request;
	u64 health_bounce_scatter_fail;
	u64 health_tidset_run_fail;
	u64 health_tx_payload_underflow;
	u64 health_duplicate_data_start;
	u64 spec_tid_latch;
	u64 spec_tid_fallback_to_legacy;
	u64 health_zero_size_drop;
	u64 health_short_packet_drop;
	u64 ctrl_rcd_unexpected_data;	/* DATA/DATA_SPECULATIVE misrouted to the ctrl RCD */
	u64 eal_bypass_header_short_drop;
	u64 eal_bypass_egr_bounds_drop;
	u64 eal_bypass_header_mismatch_drop;
	u64 eal_bypass_ulp_build_drop;
	u64 eal_bypass_rhe_error_drop;
	u64 eal_native16b_in_eth_mode_drop;
	u64 eal_fallthrough_bad_rx_drop;
	u64 eal_fallthrough_no_netdev_drop;

	u64 access_deferred_count;
	u64 access_deferred_retry_ok;
	u64 access_deferred_nack;
	u64 access_deferred_nack_fatal;
	u64 access_deferred_full;
	u64 access_deferred_pending_cmd_found; /* diag_access_fn hit */
	u64 access_deferred_pending_cmd_not_found; /* diag_access_fn miss */
	u64 rnr_duplicate_start;

	/* RNR NACK counters */
	u64 rnr_nack_sent;
	u64 rnr_nack_retries;
	u64 rnr_nack_deferred;

	u64 eager_tx;
	u64 eager_sdma_tx;
	u64 eager_rx;
	/* eager-only WRITE targets completed without a target rift key */
	u64 eager_rx_keyless;
	/* PIO waitlist entries dropped because their tracker had gone */
	u64 pio_waiter_stale;
	/* eager STARTs queued on the PIO waitlist instead of sent at once */
	u64 eager_pio_queued;
	/* DMS SDMA engine acquisition stalls (always-on) */
	u64 sdma_no_engine_fallback;

	/*
	 * DATA op deterministically needed more descriptors or AHG headers
	 * than the per-submission capacity; the tx tracker was cancelled
	 * with -EMSGSIZE rather than retried forever (always-on).
	 */
	u64 sdma_desc_overflow;
	/* multi-chunk DATA_REQUESTs sent as one SDMA submission */
	u64 sdma_req_batched;
	/* ... parked whole on the SDMA waitlist (no room, or queued behind one) */
	u64 sdma_req_parked;
	/* ... too large for one submission, sent chunk by chunk instead */
	u64 sdma_req_fallback_per_chunk;

	/* replayed SEND (lost ACK) re-ACKed without re-consuming the destination. */
	u64 health_send_replay_reack;

	/* access xfer lifecycle counters (always-on, not gated by COUNTERS_ENABLE) */
	u64 access_xfer_begin;
	u64 access_xfer_end;
	u64 access_xfer_end_teardown;  /* xfer_end that triggered access removal */
	u64 access_busy_live_dup;      /* duplicate START matched a live in-flight transfer */
	u64 reinject_data_start;       /* duplicate READ_START re-drove DATA_START on the live tracker */
	u64 write_start_dup_mismatch;  /* dup WRITE_START (slid,tx_rift_key) matched but identity mismatch: dropped */
	u64 health_status_rsp_not_found_tidset_wait; /* NOT_FOUND skipped: RX in tidset-wait, DRAINING owns recovery */

	/* tracker cancel counters */
	u64 trackers_cancelled_tx;
	u64 trackers_cancelled_rx;
	u64 cancel_by_handle_success;
	u64 cancel_by_handle_notfound;
	u64 cancel_by_handle_chain_signalled; /* re-entrant cancel of mid-completion parent: skipped */

	/* chain serialization (parent/child strict ordering) counters */
	u64 chain_successfully_attached;            /* child successfully bound to a parent */
	u64 chain_parent_done_before_bind; /* bind found parent retired/drained: child not parked */
	u64 chain_parked_write_start;        /* child parked at WRITE_START gate */
	u64 chain_parked_read;         /* child parked at READ_START gate */
	u64 chain_released_write;      /* parent signal direct-injected a parked write child */
	/* WRITE_START fence child released via ACK backstop */
	u64 chain_released_write_ack;
	u64 chain_released_write_start_early;
	/* WRITE_START_PIO child released at bind: parent already PIO-injected */
	u64 chain_released_write_pio_bind;
	/* WRITE_START_PIO child self-started at its gate (bind- or signal-released) */
	u64 chain_released_write_pio_self_start;
	/* WRITE_START_PIO child already parked at the gate: released at parent ACK */
	u64 chain_released_write_pio_ack;
	/* WRITE_START_PIO child already parked: released after the parent's PIO START */
	u64 chain_released_write_pio_parked;
	u64 chain_released_read;       /* parent signal direct-injected a parked read child */
	u64 chain_parked_read_at_data_start;   /* chained read parked at DATA_START */
	u64 chain_released_read_at_data_start; /* parent signal resumed a DATA_START-parked read child */
	/* completion resumed a DATA_START_LARGE child */
	u64 chain_released_read_at_data_start_large;
	/* write-parent completion resumed a DATA_START read child (RAW) */
	u64 chain_released_read_at_data_start_raw;
	u64 chain_resume_deferred_waiter; /* resume burst could not run inline: rx child enqueued for a TID set */
	u64 chain_child_self_start;          /* gate observed release flag and self-started */
	u64 chain_release_inject_fail; /* direct inject of released child failed: child cancelled */
	u64 chain_null_handle;        /* handle deref returned NULL (retired) during chain op */
	u64 chain_parked_on_parent_error; /* parent errored: child kept parked per caller policy */
	u64 chain_attach_after_signal;   /* attach to a parent that already completed+signalled */
	u64 chain_attach_child_conflict; /* attach refused: parent already bound to a child */

	/* BTS-driven sibling flush (cancel-by-handle) counters */
	u64 bts_inflight_cancel_events;       /* fatal-error sibling flush invoked */
	u64 bts_inflight_cancel_siblings;     /* sibling tracker cancelled by handle */
	u64 bts_inflight_cancel_already_gone; /* sibling already retired (-ENOENT) */
	u64 bts_inflight_cancel_failed;       /* cancel returned an unexpected error */
	/* bulksvc kworker accounting (gated by bulksvc_worker_stats) */
	u64 kworker_cpu_ns;
	u64 last_nloops;
	u64 kworker_resched_saturated;
	u64 kworker_resched_final_check;
	/* Adaptive halt-poll (event-driven mode): a spin window that catches
	 * the next op before the worker sleeps, trading a little CPU for the
	 * per-op wake latency that separates event-driven from polling mode.
	 */
	u64 kworker_halt_poll_success;	/* spin caught work before sleeping */
	u64 kworker_halt_poll_wait_ns;	/* ns spent spinning in halt-poll windows */

	u64 data_generation_mismatch_clobber;

	/* stale-key DATA_REQUEST recovery: fast-path miss, then identity search */
	u64 diag_target_data_req_rift_miss;
	u64 diag_target_data_req_identity_recover;
	/*
	 * Subset of diag_target_data_req_identity_recover where the recovered
	 * tracker was already in WAITING_FOR_REMOTE_ACK (2nd+ tidset of a
	 * segmented READ), not WAITING_FOR_REMOTE_DATA_REQUEST (1st tidset).
	 */
	u64 diag_target_data_req_identity_recover_waiting_ack;
	/* forward-progress liveness gate: stale cadence reset on peer activity */
	u64 diag_tracker_activity_reset;

	/* Indexed by SDMA engine; num_engines is asserted <= TXE_NUM_SDMA_ENGINES at init. */
	u64 sdma_engine_select[TXE_NUM_SDMA_ENGINES];

	struct {
		struct hfi2_dms_ring ring;
		struct dms_perf_tidset arr[1024];
	} tidset;
};

struct hfi2_dms_client_state {
	struct rb_node node;
	u32 key;
	struct {
 		struct hfi2_dms_access * arr[HFI2_DMS_MAX_ACCESS_FAST];
		struct rb_root rbt;
	} access;

	hfi2_dms_client_diag_access_fn diag_access_fn;
	void *diag_access_ctx;
};

union hfi2_dms_tracker {
	struct hfi2_dms_tracker_hdr hdr;
	struct hfi2_dms_rx_tracker rx;
	struct hfi2_dms_tx_tracker tx;
	struct hfi2_dms_sdma_tracker sdma;
} __aligned(HFI2_DMS_TRACKER_ALIGN);

/* The low HFI2_DMS_HANDLE_GEN_BITS of a tracker pointer must be free for the
 * generation counter, i.e. trackers must be at least HFI2_DMS_TRACKER_ALIGN
 * aligned.
 */
static_assert(__alignof__(union hfi2_dms_tracker) >= HFI2_DMS_TRACKER_ALIGN);

struct hfi2_dms_rift {
	struct {
		s64 ticker_total;
		s64 ticker_waiters;
		s64 ticker_assigned;
		s64 ticker_completed;
		struct {
			struct hfi2_dms_ring ring;
			hfi2_dms_rift_key_t keys[(1 << HFI2_DMS_RIFT_IDX_BITS)];
			struct hfi2_dms_dlist waitlist;
			s64 ticker_waiters;
		} side[HFI2_DMS_XFER_SIDE_COUNT];
	} type[HFI2_DMS_XFER_TYPE_COUNT];

	union hfi2_dms_tracker *arr[HFI2_DMS_RIFT_IDX_SIZE];
	DECLARE_BITMAP(occupied, HFI2_DMS_RIFT_IDX_SIZE);

	/*
	 * A completion or cancel body that runs from inside a rift-poll drive
	 * stack requests the next _dms_rift_poll() here instead of calling it
	 * inline, so the freed rift key is handed on from the top of
	 * hfi2_dms_poll() rather than nested inside the drive that freed it.
	 * Written only from the bulksvc event thread that owns this hfi2_dms,
	 * hence unlocked.
	 */
	bool poll_deferred;
};

struct hfi2_dms_rift_keyring {
	struct hfi2_dms_ring ring;
	hfi2_dms_rift_key_t arr[HFI2_DMS_RIFT_IDX_SIZE*2];
};

#define HFI2_DMS_CANCEL_CACHE_ENTRIES_PER_LID 64
#define HFI2_DMS_CANCEL_CACHE_LID_NODE_POOL_SIZE 256
#define HFI2_DMS_CANCEL_CACHE_TTL_MS 60000

struct hfi2_dms_cancel_cache_entry {
	hfi2_dms_rift_key_t tx_rift_key;
	ktime_t cancel_time;
	s32 cancel_err;
};

struct hfi2_dms_cancel_cache_lid_node {
	struct rb_node rb_node;
	struct hfi2_dms_dlist_element dlist;
	u32 remote_lid;
	u8 count;
	struct hfi2_dms_cancel_cache_entry entries[HFI2_DMS_CANCEL_CACHE_ENTRIES_PER_LID];
};

enum hfi2_dms_op {
	HFI2_DMS_OP_NONE = 0,
	HFI2_DMS_OP_RDMA_WRITE,
	HFI2_DMS_OP_RDMA_READ,
};

struct hfi2_dms_deferred_start {
	struct list_head node;
	int retries;
	enum hfi2_dms_op op;
	union {
		struct {
			struct hfi2_dms_read_start_metadata metadata;
			struct hfi2_dms_read_start_parameters parameters;
		} read;
		struct {
			struct hfi2_dms_write_start_metadata metadata;
			struct hfi2_dms_write_start_parameters parameters;
		} write;
	};
};

/*
 * ULP extension data model (scaffolding).
 *
 * These types let an upper-layer protocol (RoCE, UET, net) attach to the DMS
 * data mover via the per-DMS ulp[] table without modifying the native OPA/BTS
 * paths.  All callbacks run on the single-threaded bulksvc event thread; the
 * tracker / rift / tid / completion-cookie machinery used by BTS is NOT part of
 * this API -- a ULP supplies its own transfer tracking.
 */

/*
 * A {base,len} span.  Used both for a received ULP payload fragment and for a
 * PIO egress gather element (a virtual address + length; no bounce buffer).
 */
struct hfi2_dms_ulp_iov {
	const void *base;
	u32 len;
};

/* Most spans hfi2_dms_ulp_egress_pio() accepts in one PIO packet. */
#define HFI2_DMS_ULP_PIO_MAX_IOV 8

/*
 * A received ULP packet, split as the hardware delivered it:
 *   - pkt_hdr  : the format-specific packet header at the start of the HDRQ
 *                entry (native LRH16B/BTH/KDETH or EAL ingress header).
 *   - payload  : a 2-element iovec for bytes following pkt_hdr.  payload[0] is
 *                the portion that landed inline in the HDRQ entry; payload[1]
 *                is the portion the hardware DMA'd into the eager buffer.
 *                Either element is {NULL, 0} when absent.  Ethernet ingress
 *                additionally records its optional timestamp and marks
 *                is_ethernet.
 * A ULP must navigate the JKR (128 B) / CYR (256 B) HDRQ entry-size difference
 * itself; payload[0].len is the inline content, not a fixed offset.
 */
struct hfi2_dms_ulp_rx {
	const void *pkt_hdr;
	struct hfi2_dms_ulp_iov payload[2];
	const void *ingress_timestamp;
	u8 rcv_port;
	bool is_ethernet;
};

/*
 * Copy up to @len leading payload bytes from the ordered HDRQ-inline and eager
 * segments into @buf.  It provides a contiguous prefix for consumers that
 * parse protocol headers, while the descriptor continues to describe the
 * hardware-owned, split packet without a packet-sized bounce buffer.
 */
static inline u32 hfi2_dms_ulp_rx_copy_prefix(const struct hfi2_dms_ulp_rx *rx,
					      void *buf, u32 len)
{
	u8 *dst = buf;
	u32 copied = 0;
	u32 i;

	if (!rx || !buf)
		return 0;

	for (i = 0; i < 2 && copied < len; i++) {
		const struct hfi2_dms_ulp_iov *src = &rx->payload[i];
		u32 bytes = src->len < len - copied ? src->len : len - copied;

		if (!bytes)
			continue;
		if (!src->base)
			break;
		memcpy(dst + copied, src->base, bytes);
		copied += bytes;
	}

	return copied;
}

struct hfi2_devdata;

u8 hfi2_dms_eth_bypass_hdr_dws(struct hfi2_devdata *dd);

/* Hands an unclaimed Ethernet frame to the netdev RX path (eth_rx.c). */
void cne_ulp_fallthrough(struct hfi2_dms *dms,
			 const struct hfi2_dms_ulp_rx *rx);

/*
 * Per-ULP operations registered with DMS.  SINGLE-THREADED CONTRACT: every
 * callback runs ONLY on the bulksvc event thread.  Do NOT take
 * locks/atomics/barriers for ULP-internal or dms->ulp[] state.  @cookie is
 * opaque to DMS, stored by value in the registration table, and passed back to
 * every callback; DMS never dereferences it.
 */
struct hfi2_dms_ulp_ops {
	const char *name;
	u8 ulp_id; /* 1..HFI2_DMS_ULP_MAX-1; 0 is reserved for native OPA/BTS */
	void *cookie;

	/*
	 * Handle one classified ULP packet.  @subtype is ULP-defined (low 5
	 * bits of the BTH message byte on OPA).  @rx carries the header +
	 * payload split.  Return 0 if consumed; <0 to drop+count like an
	 * unknown type.
	 */
	int (*handle_rx)(struct hfi2_dms *dms, u8 subtype,
			 const struct hfi2_dms_ulp_rx *rx, void *cookie);
};

/*
 * A ULP's Ethernet classification criteria, evaluated in software.  The field
 * set is intentionally RSM-rule-shaped so the same descriptor can drive a future
 * hardware-steering tier (multi-hfisvc) with no API change; today it is parsed in
 * software only and programs no hardware.  ethertype/udp_dport are big-endian
 * (as on the wire); 0 = "don't care".
 *
 * On an OPA fabric the ulp_id is carried in-band in the BTH message byte and the
 * classifier is a trivial decode; on an Ethernet fabric the remote peer is a
 * stock NIC carrying no Cornelis ulp_id, so it must be derived from these header
 * fields.  The ulp_id is a host-local routing value -- it is NEVER a value
 * carried on the Ethernet wire.
 */
struct hfi2_dms_ulp_match {
	u8 ulp_id;
	__be16 ethertype;
	u8 ip_proto;
	__be16 udp_dport;
	u8 prio;
};

struct hfi2_dms {
	struct hfi2_devdata *dd; /* provided by bulksvc */
	int numa_node; /* NUMA node local to the HFI PCI device */
	int chip_type;
	/*
	 * The protocol-neutral substrate owns the DMS identity, loaned engines,
	 * dms_sdma state, zero page, and page pool.  This explicit lifecycle flag
	 * prevents ETH teardown from using dms->dd as a proxy for native DMS state.
	 */
	bool common_initialized;
	/*
	 * Set when teardown resumes after the PCI device was disabled.  The
	 * loaned sdma_engine structures are already freed by then, so shutdown
	 * must not touch them; with bus mastering off nothing is in flight.
	 */
	bool hw_released;

	struct sdma_engine **sdma_engines; /* Array of SDMA engines */
	u32 num_engines;                  /* Number of SDMA engines */
	u32 cur_sdma_engine;
	struct sdma_desc p2p_flush_sop_desc[HFI2_DMS_MAX_PORTS];
	u32 p2p_flush_inflight;
	u16 entropy_next;                 /* monotonic per-request entropy seed */

	/*
	 * Ring-layer batches created by batch_new() but not yet
	 * committed/aborted, held so ring_destroy() can discard any the
	 * caller abandoned.  Per-DMS: a held batch has no target engine yet.
	 */
	struct list_head sdma_held;

	/*
	 * Ring-layer batch free-list: pre-allocated batch objects recycled
	 * across injects so the data path never allocates.  Populated at
	 * ring_setup(), drained at ring_destroy().
	 */
	struct list_head sdma_batch_free;
	struct hfi2_dms_allocation_stats allocation_stats;

	struct hfi2_ctxtdata *rcd_ctrl; // used for protocol and small PIO messages
	struct hfi2_ctxtdata *rcd_data; // used for expected receive data (TODO: eager data?)

	u32 lane;

	struct send_context *port_sctxts[HFI2_DMS_MAX_PORTS];
	bool port_available[HFI2_DMS_MAX_PORTS];

	struct {
		struct hfi2_dms_ring ring;
		u8 arr[2 * HFI2_DMS_TID_SET_IDX_COUNT];
	} free_tidsets;

	// these are implicitly indexed by the associated TID set index
	struct hfi2_dms_read_request_state read_requests[HFI2_DMS_TID_SET_IDX_COUNT];
	struct hfi2_dms_read_request_chunks *read_request_chunks;
	struct hfi2_dms_tidset_bounce_backing *read_request_bounce;

	/*
	 * Remaining speculative-TID budget: tidsets that may still be enabled
	 * before their peer has joined, up to the half-of-usable cap. Initialized
	 * to max_tid_set_idx / 2, decremented by a speculative READ_START and
	 * restored at that tidset's FREE transition.
	 */
	u32 spec_tidsets_available;

	struct hfi2_dms_rift_keyring tidset_waiters;  /* Global tracker waiter ring */
	struct hfi2_dms_sdma_waiters sdma_waiters[HFI2_DMS_SDMA_ENGINE_IDX_COUNT];
	s32 sdma_waiter_count;

	/* Internal pointers for protocol/registered buffers */
	union hfi2_dms_proto_cmd *protocol_cmd_templates[HFI2_DMS_MAX_PORTS]; /* Array of protocol command templates */
	struct sdma_desc header_desc_template;
	struct sdma_desc tail_desc_template;

	struct hfi2_dms_tracker_mgr trackers;

	struct hfi2_dms_sde_rsrc *sde_rsrcs; /* per SDMA engine resources */
	/* lanes > 1: indexed like sdma_engines; NULL: engines are ours alone */
	struct hfi2_dms_sde_share *sde_share;

	struct hfi2_dms_ahg_header_mgr ahg_headers[HFI2_DMS_MAX_PORTS];
	struct hfi2_dms_page_mgr dms_pages; /* 4 KiB DMA page pool */
	struct hfi2_dms_mem_coh zero_page; // for tail flit and scratch space
	/*
	 * Source of quadword pad bytes: an all-zero page written only at init,
	 * never mapped into the RcvArray. pad_desc_template[n - 1] sends n of
	 * its bytes, n = 1..7 (a quadword pad is never 0 or 8 bytes).
	 */
	struct hfi2_dms_mem_coh tx_zero_page;
	/*
	 * Read-only SDMA source page for per-port P2P flush SOP headers.
	 * Written only at init and never mapped into RcvArray.
	 */
	struct hfi2_dms_mem_coh p2p_flush_page;
	struct sdma_desc pad_desc_template[sizeof(u64) - 1];

	u8 *pio_scratch;

	struct sdma_desc *desc_stack;
	s32 num_descs;

	struct rb_root client_rbtree;
	struct {
		struct hfi2_dms_dlist freelist;
	} access;

	struct {
		hfi2_dms_ext_dest_resolve_fn resolve;
		hfi2_dms_ext_dest_complete_fn complete;
	} ext_dest;

	struct hfi2_dms_rift rift;

	struct hfi2_dms_work_item_mgr work_items;

	struct hfi2_dms_rx_tracker disabled_rx_tracker;

	ktime_t now;
	ktime_t last_stale_check;

	struct {
		struct list_head active;
		struct list_head free;
		int count;
	} access_deferred;
	struct hfi2_dms_deferred_start *access_deferred_pool;
	u32 access_deferred_pool_size;

	struct {
		struct hfi2_dms_dlist waitlist;
		struct hfi2_dms_dlist freelist;
	} pio;

	struct {
		struct rb_root active;
		struct hfi2_dms_dlist freelist;
		u32 total_count;
		ktime_t last_aging_time;
	} cancel_cache;

	struct dms_counters counters;

	struct {
		u64 suppressed_count;
		ktime_t last_log_time;
		int last_reason;
		u64 last_dms_key;
	} nack_log;

	struct {
		struct {
			atomic_t count;
			u32 frequency_bp;
			atomic64_t user_dropped;
			atomic64_t user_delivered;
		} entries[HFI2_DMS_PACKET_DROP_TYPE_COUNT];
	} packet_drop;

	/*
	 * ULP registration table, indexed by ulp_id (1..HFI2_DMS_ULP_MAX-1;
	 * slot 0 is reserved for native OPA/BTS and is never populated).  The
	 * ops vtable is stored by value (copied at register time, including the
	 * ULP cookie); a slot with a NULL handle_rx is unregistered, which is
	 * what keeps the dispatch hook inert.  Single-threaded: mutated only at
	 * register/unregister on the bulksvc event thread and read only on that
	 * same thread; never locked.
	 */
	struct hfi2_dms_ulp_ops ulp[HFI2_DMS_ULP_MAX];

	/*
	 * Software Ethernet classification table, indexed by ulp_id.  Populated
	 * by hfi2_dms_ulp_add_eth_match(); programs no hardware.  Same
	 * single-threaded discipline as ulp[] above.
	 */
	struct hfi2_dms_ulp_match eth_match[HFI2_DMS_ULP_MAX];
};

static inline u32 dms_num_data_engines(const struct hfi2_dms *dms)
{
	return (dms->num_engines > 1) ? (dms->num_engines - 1) :
		dms->num_engines;
}

static inline u8 dms_reserved_engine_idx(const struct hfi2_dms *dms)
{
	return (dms->num_engines > 1) ? (u8)(dms->num_engines - 1) : 0;
}

/*
 * Serialize ring access to SDMA engine @idx when the engines are shared by
 * several lanes.  A DMS that owns its engines is single threaded and takes
 * no lock.  Plain spin_lock() is enough: every taker runs in process context
 * (the lane kworkers and the JKR rev work), and the SDMA, doorbell, receive
 * and progress timer handlers only schedule work.  Without sharing,
 * __acquire() and __release() keep sparse's lock count the same on both paths.
 */
static inline void hfi2_dms_sde_lock(struct hfi2_dms *dms, u32 idx)
{
	if (dms->sde_share)
		spin_lock(&dms->sde_share[idx].lock);
	else
		__acquire(dms);
}

static inline void hfi2_dms_sde_unlock(struct hfi2_dms *dms, u32 idx)
{
	if (dms->sde_share)
		spin_unlock(&dms->sde_share[idx].lock);
	else
		__release(dms);
}

/*
 * Shared engines, under hfi2_dms_sde_lock(): count the descriptors placed by
 * moving engine @idx's ring tail from @old_tail to @new_tail.  Every update
 * places fewer than @descq_cnt descriptors (placement is bounded by the free
 * count), so the masked distance is exact.
 */
static inline void hfi2_dms_sde_seq_advance(struct hfi2_dms *dms, u32 idx,
					    u32 old_tail, u32 new_tail,
					    u32 descq_cnt)
{
	dms->sde_share[idx].seq += (new_tail - old_tail) & (descq_cnt - 1);
}

/*
 * Shared engines, under hfi2_dms_sde_lock(): engine @idx's head on the
 * placed-descriptor scale.  The in-flight span (head, tail] is shorter than
 * the ring, so it is the masked tail-to-head distance.
 */
static inline u64 hfi2_dms_sde_head_seq(struct hfi2_dms *dms, u32 idx,
					u32 tail, u32 head, u32 descq_cnt)
{
	return dms->sde_share[idx].seq - ((tail - head) & (descq_cnt - 1));
}

struct hfi2_bulksvc_pp_rsrc;

int hfi2_dms_init(struct hfi2_dms *dms, struct hfi2_devdata *dd,
		  struct hfi2_bulksvc_pp_rsrc *pp_rsrc, int num_ports,
		  struct sdma_engine **sdma_engines, int num_engines, u32 lane);
int hfi2_dms_common_init(struct hfi2_dms *dms, struct hfi2_devdata *dd,
			 struct sdma_engine **sdma_engines, int num_engines,
			 int port_idx, struct send_context *port_sctxt);
void hfi2_dms_common_uninit(struct hfi2_dms *dms);
void hfi2_dms_uninit(struct hfi2_dms *dms);
void hfi2_dms_eal_init_rcd(struct hfi2_dms *dms, struct hfi2_ctxtdata *rcd,
			   u8 pidx);
int hfi2_dms_eal_poll(struct hfi2_dms *dms);

// struct hfi2_dms_mr * hfi2_dms_mr_new(struct mmu_rb_handler *handler, uintptr_t vaddr, u64 len);
// int hfi2_dms_mr_free(struct hfi2_dms_mr *mr);

int hfi2_dms_register_access(struct hfi2_dms *dms,
			     struct hfi2_dms_page_provider page_provider,
			     u64 offset, u64 size,
			     union hfi2_dms_key dms_key,
			     struct hfi2_dms_access_completion const completion,
			     enum hfi2_dms_access_type access_type,
			     struct hfi2_dms_access **out);

/**
 * hfi2_dms_unregister_access - Remove a DMS access registration.
 *
 * In-flight trackers drain passively; the unreg_cmpl callback fires
 * exactly once when the last tracker completes (or inline if none
 * are active).
 *
 * @retval: 0 (accepted):
 *   First unregister for this access.  Transitions to ACTIVE_TEARDOWN.
 *   Caller MUST NOT dereference the access after return.
 *
 * @retval: -EALREADY (duplicate):
 *   An unregister was already accepted for this access.  The second
 *   caller's unreg_cmpl is ignored -- the first callback remains the
 *   sole terminal callback.  Caller should treat -EALREADY as
 *   "unregister already in progress, no action needed."
 *
 * @retval: -EINVAL (hard error):
 *   Access not found.  No state change; no callback.
 */
int hfi2_dms_unregister_access(struct hfi2_dms *dms, union hfi2_dms_key dms_key,
			       struct hfi2_dms_completion unreg_cmpl);

/* Initiate an RDMA read from a remote buffer into a local memory region.
 * port_idx is the fabric port index to egress the transfer while
 * src_lid is the LID of the remote HFI2 to read from
 *
 * NOTE: unordered transfers must use order_key HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED
 */
int hfi2_dms_read_data(struct hfi2_dms *dms, enum hfi2_dms_fabric_port_idx port_idx, u32 src_lid,
			union hfi2_dms_key dms_key, u64 key_offset_or_vaddr, u32 size,
			struct hfi2_dms_page_provider page_provider, u64 mr_offset,
			u16 flags, u64 submit_flags, u64 imm_data,
			struct hfi2_dms_completion const completion, u64 order_key,
			struct hfi2_dms_transfer_handle parent_handle,
			struct hfi2_dms_transfer_handle *out_handle);

/* Initiate an RDMA write from a local memory region to a remote buffer.
 * port_idx is the fabric port index to egress the transfer while
 * dest_lid is the LID of the remote HFI2 to write to
 *
 * NOTE: unordered transfers must use order_key HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED
 */
int hfi2_dms_write_data(struct hfi2_dms *dms, enum hfi2_dms_fabric_port_idx port_idx, u32 dest_lid,
			union hfi2_dms_key dms_key, u64 remote_offset, u32 size,
			struct hfi2_dms_page_provider page_provider, u64 mr_offset,
			u16 flags, u64 submit_flags, u64 imm_data,
			struct hfi2_dms_completion const completion, u64 order_key,
			struct hfi2_dms_transfer_handle parent_handle,
			struct hfi2_dms_transfer_handle *out_handle);

// This is only here for now to debug, this will be removed
/* in the future when we have interrupts linked up */
int hfi2_dms_poll(struct hfi2_dms *dms, ktime_t const now);

void hfi2_dms_access_completion_fn_noop(union hfi2_dms_completion_cookie *cookie, u16 flags, u64 imm_data, u64 order_key, int status);
void hfi2_dms_completion_fn_noop(union hfi2_dms_completion_cookie *cookie, int status);

/*
 * Release @client_key and cancel the transfers it serves as a target.
 * Initiator transfers carry the remote peer's key; they are cancelled by
 * owner or at QP teardown instead.
 */
void hfi2_dms_release_client_key(struct hfi2_dms *dms, u32 client_key);

/* Cancel initiator-side trackers (RX destination or TX RDMA_WRITE source)
 * whose local buffer's page provider reports owner == @owner.  Target-side RDMA_READ is
 * excluded; cancel those via hfi2_dms_release_client_key.  No-op if NULL.
 * bulksvc thread only.
 */
void hfi2_dms_cancel_trackers_for_owner(struct hfi2_dms *dms, void *owner);

/**
 * Cancel a tracker by its handle, returning the error code that will be reported to the completion callback.
 * Only valid for initiator-side trackers
 *  * -EFAULT - dms is NULL
 *  * -ENOENT - tracker not present (already completed, recycled, never existed
 *              for this generation, or the handle is zero/malformed)
 */
int hfi2_dms_cancel_tracker_by_handle(struct hfi2_dms *dms,
				      struct hfi2_dms_transfer_handle handle,
				      int err);

/*
 * Allocate and register a new client keyed by @client_key; optionally
 * install the deferred-access diagnostic hook (NULL/NULL to disable).
 */
int hfi2_dms_create_client_key(struct hfi2_dms *dms, u32 client_key,
			       hfi2_dms_client_diag_access_fn diag_access_fn,
			       void *diag_access_ctx);

/*
 * Register/unregister a ULP.  @ops is taken by value and stored in the
 * dms->ulp[] table.  The struct itself is copied, but its POINTER members --
 * @cookie and @name -- are stored as-is and dereferenced (cookie by the ULP's
 * handle_rx, name by debugfs/log code) until unregister; the caller MUST keep
 * those pointed-to objects valid for the whole registered lifetime.  There is
 * no refcount.  BOUNDARY OP: call from module init/teardown while the path is
 * quiescent, not concurrently with packet processing.  Returns 0, -EINVAL
 * (missing handle_rx or bad ulp_id), or -EBUSY (slot already registered).
 */
int hfi2_dms_ulp_register(struct hfi2_dms *dms,
			  struct hfi2_dms_ulp_ops ops);
void hfi2_dms_ulp_unregister(struct hfi2_dms *dms, u8 ulp_id);

/*
 * Transmit a ULP packet.  SINGLE-THREADED: call ONLY from a ULP callback on the
 * bulksvc event thread.  Returns 0, -EAGAIN (engine momentarily out of credits;
 * retry on a later poll), or another negative errno.
 *
 * PIO: a packet that cannot go out at once, behind other waiting DMS PIO
 * packets or for want of credits, is copied and queued in order behind them
 * (0) if it fits a PIO waiter (HFI2_DMS_PIO_WAITER_QWS qwords with PBC and
 * tail flit), else -EAGAIN.  The iov spans, in
 * order, are the packet -- iov[0] starts with the 40-byte header from
 * hfi2_dms_ulp_build_pio_header(), PBC first -- and are packed byte for byte
 * with no padding between them; only the end of the last span is zero-padded
 * to a qword, and the 16B tail flit is appended here.  At most
 * HFI2_DMS_ULP_PIO_MAX_IOV spans (-EINVAL otherwise).  The gathered total MUST
 * fit the send context (-EMSGSIZE otherwise) and MUST agree with the length
 * the header was built for.
 *
 * SDMA: @engine_idx names the SDMA engine to launch on.  This is part of the
 * API (not chosen internally) because the engine choice IS the ordering
 * control point: the DMS data mover bypasses the RC wire protocol's
 * PSN-ordered admission, so packets issued on different engines can interleave
 * on the wire with no ordering guarantee.  A ULP that needs two transmits
 * ordered relative to each other (e.g. a RoCE WAW/RAW hazard pair) MUST pin
 * them to the same engine; one that wants spreading for throughput may select
 * HFI2_DMS_SDMA_ENGINE_IDX_ANY for round-robin placement.  Must be 0..
 * num_engines-1 or HFI2_DMS_SDMA_ENGINE_IDX_ANY; otherwise -EINVAL.
 */
int hfi2_dms_ulp_egress_pio(struct hfi2_dms *dms,
			    enum hfi2_dms_fabric_port_idx port_idx,
			    const struct hfi2_dms_ulp_iov *iov, u32 niov);

/*
 * Build the PIO command-buffer header (PBC + compressed 16B LRH + BTH + KDETH)
 * for a ULP PIO packet into @hdr_buf for transmit to @dlid with the given
 * @ulp_id/@subtype and @payload_bytes (must be an 8-byte multiple).  @hdr_buf
 * MUST be 8-byte aligned (the batch writes u64 PBC/LRH/BTH/KDETH fields);
 * a misaligned buffer is rejected with -EINVAL.  Returns the command-header
 * length in bytes, which is 40 (PBC 8 + lrh16bc 8 + BTH 12 + KDETH 8, zero
 * padded to a qword), to use as iov[0].len, or a negative errno.  The
 * companion to hfi2_dms_ulp_egress_pio(): a ULP fills iov[0] from this and
 * iov[1] with its payload.  SLID is stamped by hardware at injection.
 */
int hfi2_dms_ulp_build_pio_header(struct hfi2_dms *dms,
				  enum hfi2_dms_fabric_port_idx port_idx,
				  u32 dlid, u8 ulp_id, u8 subtype,
				  u32 payload_bytes, void *hdr_buf,
				  u32 hdr_buf_len);

/*
 * DMA page pool.  hfi2_dms_page_get() hands out one PAGE_SIZE (4 KiB)
 * DMA-coherent page (normally an O(1) free-list pop); hfi2_dms_page_put()
 * returns it.  Single-threaded, so no locks.  On an empty free list get()
 * grows the pool by one block (a blocking dma_alloc_coherent, safe in this
 * sleepable context) and returns NULL only on grow failure or at
 * HFI2_DMS_PAGE_POOL_MAX_PAGES.  The handle exposes kvaddr (to fill) and
 * phys_addr (to hand to the SDMA layer as an SGE).
 */
struct hfi2_dms_page *hfi2_dms_page_get(struct hfi2_dms *dms);
int hfi2_dms_page_pool_warm(struct hfi2_dms *dms, u32 pages);
/*
 * O(1) free-list acquisition for atomic producers.  Unlike page_get(), this
 * never grows the pool, so it is safe while a producer holds qp->s_lock.
 */
struct hfi2_dms_page *hfi2_dms_page_try_get(struct hfi2_dms *dms);
void hfi2_dms_page_put(struct hfi2_dms *dms,
		       struct hfi2_dms_page *page);

/*
 * Publish @bytes at @offset into @page's kvaddr to the device.  @page's
 * backing block is mapped DMA_TO_DEVICE once at block-allocation time (see
 * _page_block_alloc()), not per page-get, so every CPU write into the page
 * needs an explicit sync before the SDMA engine reads it, or the engine can
 * fetch stale/partial bytes.  Call this after composing a page's contents
 * and before handing its physical address to the SDMA batch layer.
 */
void hfi2_dms_page_sync_for_device(struct hfi2_dms *dms,
				   struct hfi2_dms_page *page,
				   u32 offset, size_t bytes);

/*
 * Register/unregister a software Ethernet classification rule for a ULP, and
 * classify an inbound frame.  These program NO hardware: hardware RSM steering
 * and per-ULP dedicated receive contexts are deferred pending a multi-hfisvc
 * capability.  add_eth_match() only populates the per-DMS software match table.
 *
 * add_eth_match() keys the table by match->ulp_id and OVERWRITES any existing
 * rule for that same ulp_id (last writer wins) -- there is one match slot per
 * ULP, not a list.  ulp_id is centrally owned, so a ULP only ever replaces its
 * own rule; it can never clobber another ULP's.
 *
 * hfi2_dms_ulp_classify() parses an inbound Ethernet frame header against the
 * registered matches (highest prio first) and returns the ulp_id, or 0 if no
 * ULP claims it (the frame belongs to the host network stack -- it must fall
 * through to the cn6k Ethernet netdev path, never be dropped).  It is a pure
 * function of the header bytes + match table and runs on the bulksvc thread; no
 * locks.
 *
 * Soft-RoCE caveat: claiming RoCEv2 (UDP 4791) frames diverts them from the
 * soft-RoCE provider (rxe) on the same host; running both is unsupported.
 */
int hfi2_dms_ulp_add_eth_match(struct hfi2_dms *dms,
			       const struct hfi2_dms_ulp_match *match);
void hfi2_dms_ulp_del_eth_match(struct hfi2_dms *dms, u8 ulp_id);
u8 hfi2_dms_ulp_classify(struct hfi2_dms *dms, const void *eth_hdr, u32 hdr_len);

hfi2_dms_rift_key_t _rift_key_create(u16 const generation, u16 const index);
bool _rift_key_side_rx(hfi2_dms_rift_key_t const key);
bool _rift_key_side_tx(hfi2_dms_rift_key_t const key);

u32 _ring_size(struct hfi2_dms_ring *ring);
u32 _ring_consume(struct hfi2_dms_ring *ring);

#endif /* _HFI2_DMS_H */
