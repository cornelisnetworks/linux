// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025,2026 Cornelis Networks.
 */

#include "dms.h"
#include <linux/bug.h>
#include <asm/page.h>
#include "chip.h"
#include "common.h"
#include "hfi2.h"
#include "linux/dma-mapping.h"
#include "linux/gfp_types.h"
#include "pio.h"
#include "sdma.h"
#include "bulksvc.h"
#include "sdma_defs.h"
#include "sdma_txreq.h"
#include "dms_sdma.h"
#include "chip_registers_jkr.h"
#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "bulksvc_ulp.h"
#include "eth_hwi.h"

#include "trace_dms.h"

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define HFI2_DMS_TRACE_ENABLE 0
#define HFI2_DMS_BUG_ENABLE 1
#define HFI2_DMS_WORK_ITEM_MAX_RETRY_TIME_NS  (10000000000) //   10 s
#define HFI2_DMS_RNR_IMMEDIATE_RETRY_MAX	3
#define HFI2_DMS_ACCESS_DEFERRED_MAX_RETRIES	32

/* HFI2_DMS_TRACKER_TIDSET_MAX now lives in dms.h (needed to size the rx
 * tracker's outstanding-tidset list).
 */

/* RAR child > this size releases at full parent completion (DATA_START_LARGE);
 * at or below, early at narrow-to-one (DATA_START). See _tracker_bind.
 */
#define HFI2_DMS_CHAIN_DATA_REQUEST_MAX_BYTES (HFI2_DMS_TID_SET_BYTES_MAX)

#define HFI2_DMS_PER_POLL_MAX_PACKETS		16
#define HFI2_DMS_POLL_TOTAL_PACKET_BUDGET	2048
#define DMS_P2P_FLUSH_HDR_BYTES		40

#define USEC_IN_NS (1000l)
#define MS_IN_NS   (1000l * USEC_IN_NS)
#define SEC_IN_NS  (1000l * MS_IN_NS)
#define MIN_IN_NS  (  60l * SEC_IN_NS)

#define HFI2_DMS_STALE_POLL_TIME_MS          (dms_health_cfg.poll_ms)

/**
 * struct dms_health_cfg - DMS health monitoring configuration
 * @poll_ms: Interval between health checks in milliseconds.
 *           Range: 1-10000. Default: 50.
 * @base_ms: Initial timeout for exponential backoff in milliseconds.
 *           Range: 1-100000. Default: 200.
 * @max_retries: Maximum number of retries before declaring a peer dead.
 *               Range: 0-20. Default: 4.
 * @actual_ms: Calculated total cumulative timeout until -ETIMEDOUT.
 *             Formula: base_ms * (2^(max_retries + 1) - 1).
 */
static struct {
	unsigned int poll_ms;
	unsigned int base_ms;
	unsigned int max_retries;
	unsigned int actual_ms;
} dms_health_cfg = {
	.poll_ms = 50,
	.base_ms = 200,
	.max_retries = 4,
	/* 200 * (2^5 - 1) = 200 * 31 = 6200 */
	.actual_ms = 6200,
};

/*
 * Largest eager PIO payload.  Matches DMS_EAGER_SDMA_MAX_LIMIT, giving
 * eager PIO and eager SDMA the same maximum size, with comfortable
 * headroom under both the guaranteed per-context PIO buffer
 * (SCS_BULKSVC_CREDITS credits, pio.h) minus the largest eager header,
 * and the 12-bit PBC DWORD length field (chip.h PBC_LENGTH_DWS_MASK).
 * See the static_assert below the header size definition: do not
 * change this value without also checking that assertion still holds.
 */
#define DMS_EAGER_PIO_MAX_LIMIT		8192
#define DMS_EAGER_SDMA_MAX_LIMIT	8192

static u32 dms_eager_pio_max = 8192;
static u32 dms_eager_sdma_max;

#define HFI2_DMS_PIO_SCRATCH_SIZE 10240

/* Largest PBC + header prefix of any eager PIO packet (WRITE_START_EAGER,
 * per _msgtype_pio_payload_offset[]: PBC + 15 header qwords = 128);
 * HFI2_DMS_AHG_SLOT_SIZE already documents this as its lower bound.
 */
#define DMS_EAGER_PIO_HDR_MAX 128

static_assert(DMS_EAGER_PIO_MAX_LIMIT + DMS_EAGER_PIO_HDR_MAX <=
	      SCS_BULKSVC_CREDITS * PIO_BLOCK_SIZE,
	      "DMS_EAGER_PIO_MAX_LIMIT exceeds the guaranteed bulksvc PIO credit floor");
static_assert(DMS_EAGER_PIO_MAX_LIMIT + DMS_EAGER_PIO_HDR_MAX <=
	      (PBC_LENGTH_DWS_MASK + 1) * 4,
	      "DMS_EAGER_PIO_MAX_LIMIT exceeds the 12-bit PBC DWORD length field");
static_assert(!((DMS_EAGER_PIO_MAX_LIMIT | DMS_EAGER_SDMA_MAX_LIMIT) >> 16),
	      "eager payload size does not fit the 16-bit eager_nbytes field");

/**
 * _dms_health_init() - Initialize and log DMS health parameters
 * @dms: The DMS structure
 *
 * This helper prints the current DMS health configuration to the kernel log.
 */
static void _dms_health_init(struct hfi2_dms *dms)
{
	dd_dev_info(dms->dd, "dms health: poll=%ums base=%ums retries=%u (-ETIMEDOUT at %u ms, %u requests before cancellation)\n",
		    dms_health_cfg.poll_ms, dms_health_cfg.base_ms,
		    dms_health_cfg.max_retries, dms_health_cfg.actual_ms,
		    dms_health_cfg.max_retries + 1);
	dd_dev_info(dms->dd, "dms eager: pio_max=%u sdma_max=%u\n",
		    dms_eager_pio_max, dms_eager_sdma_max);
}

/*
 * Calculate total cumulative timeout for exponential backoff with base-2 growth.
 *
 * The health protocol uses exponential backoff: base_ms * 2^retry_count.
 * This function computes the total time across all retries:
 *   Sum from i=0 to max_retries of (base_ms * 2^i)
 *       = base_ms * (2^(max_retries+1) - 1)
 *
 * Example: base_ms=200, max_retries=4
 *   Retry 0: 200ms, Retry 1: 400ms, Retry 2: 800ms,
 *   Retry 3: 1600ms, Retry 4: 3200ms
 *   Total: 200 * (2^5 - 1) = 200 * 31 = 6200ms
 *
 * The expression can also be evaluated as:
 *   base_ms * (2^(max_retries+1) - 1)
 *       = (base_ms * 2^(max_retries+1)) - base_ms
 *
 * Therefore, the calculation below uses a 64-bit shift followed by a
 * subtraction. The cast must be performed before the shift so that the
 * intermediate value is calculated in uint64_t. This avoids explicitly
 * calculating the multiplier, as well as the multiplication-overflow
 * division check used by the equivalent formulation.
 *
 * This implementation assumes that unsigned int is 32 bits. For this type
 * width, max_retries=31 requires a shift by 32 and produces:
 *   base_ms * (2^32 - 1)
 *
 * For base_ms=0, the result is zero. For base_ms=1, the result is exactly
 * UINT_MAX; for larger base_ms values, it exceeds UINT_MAX. Consequently,
 * retry counts above 31 cannot produce any return value other than the
 * UINT_MAX saturation/error value, so they are clamped to 31. This also
 * keeps the maximum shift count within the 64-bit intermediate type.
 *
 * UINT_MAX is used as the saturation/error result. An exact mathematical
 * result of UINT_MAX therefore has the same representation as overflow.
 */
static unsigned int dms_health_timeout_from_retries(unsigned int base_ms, unsigned int max_retries)
{
	if (max_retries > 31)
		max_retries = 31;
	u64 raw_timeout = ((u64)base_ms << (max_retries + 1)) - base_ms;

	return raw_timeout < UINT_MAX ? (unsigned int)raw_timeout : UINT_MAX;
}

/* Forward declarations for DMS health module parameter callbacks */
static __maybe_unused int dms_health_poll_set(const char *val, const struct kernel_param *kp);
static __maybe_unused int dms_health_poll_get(char *buffer, const struct kernel_param *kp);
static __maybe_unused int dms_health_base_set(const char *val, const struct kernel_param *kp);
static __maybe_unused int dms_health_base_get(char *buffer, const struct kernel_param *kp);
static __maybe_unused int dms_health_retries_set(const char *val, const struct kernel_param *kp);
static __maybe_unused int dms_health_retries_get(char *buffer, const struct kernel_param *kp);
static __maybe_unused int dms_eager_max_set(const char *val, const struct kernel_param *kp);
static __maybe_unused int dms_eager_max_get(char *buffer, const struct kernel_param *kp);

static __maybe_unused const struct kernel_param_ops dms_health_poll_ops = {
	.set = dms_health_poll_set,
	.get = dms_health_poll_get,
};

static __maybe_unused const struct kernel_param_ops dms_health_base_ops = {
	.set = dms_health_base_set,
	.get = dms_health_base_get,
};

static __maybe_unused const struct kernel_param_ops dms_health_retries_ops = {
	.set = dms_health_retries_set,
	.get = dms_health_retries_get,
};

static __maybe_unused const struct kernel_param_ops dms_eager_max_ops = {
	.set = dms_eager_max_set,
	.get = dms_eager_max_get,
};




static uint dms_access_deferred_max;


/*
 * Fast-fail reliability mode.  1: cancel a stale transfer to -ETIMEDOUT so the
 * upper layer owns retransmission.  0: recover in place via the health protocol
 * (STATUS_REQUEST + backoff).  Runtime-writable; latched per submission.
 */
static bool dms_fast_fail = true;

bool hfi2_dms_fast_fail_enabled(void)
{
	return READ_ONCE(dms_fast_fail);
}

static bool bulksvc_spec_tid_enabled = true;

/*
 * FGAR (Fine Grained Adaptive Routing) master enable: 1=FGAR (adaptive
 * out-of-order routing, RC=b'100 min-hop), 0=SDR (in-order, RC=0).
 * Runtime-writable; read live per packet build. Defaults on so CI
 * exercises the FGAR-tagged code path without an explicit opt-in.
 */
static bool dms_fgar_enable = true;

bool hfi2_dms_fgar_enabled(void)
{
	return READ_ONCE(dms_fgar_enable);
}

static uint dms_write_single_engine_max_bytes =
	HFI2_DMS_WRITE_SINGLE_ENGINE_MAX_BYTES_DEFAULT;

static __maybe_unused noinline int dms_health_generic_set(const char *val, unsigned int lo,
					   unsigned int hi, unsigned int *vout)
{
	unsigned int val_int;
	int ret;

	ret = kstrtouint(val, 0, &val_int);
	if (ret)
		return ret;
	if (val_int < lo || val_int > hi)
		return -EINVAL;
	*vout = val_int;
	dms_health_cfg.actual_ms = dms_health_timeout_from_retries(
		dms_health_cfg.base_ms, dms_health_cfg.max_retries);
	return 0;
}

static __maybe_unused int dms_health_poll_set(const char *val, const struct kernel_param *kp)
{
	return dms_health_generic_set(val, 1, 10000, &dms_health_cfg.poll_ms);
}

static __maybe_unused int dms_health_poll_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", dms_health_cfg.poll_ms);
}

static __maybe_unused int dms_health_base_set(const char *val, const struct kernel_param *kp)
{
	return dms_health_generic_set(val, 1, 100000, &dms_health_cfg.base_ms);
}

static __maybe_unused int dms_health_base_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", dms_health_cfg.base_ms);
}

static __maybe_unused int dms_health_retries_set(const char *val, const struct kernel_param *kp)
{
	return dms_health_generic_set(val, 0, 20, &dms_health_cfg.max_retries);
}

static __maybe_unused int dms_health_retries_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u\n", dms_health_cfg.max_retries);
}

/**
 * dms_eager_max_set() - Parse "P[,S]" format for eager thresholds
 *
 * Accepts "P" (PIO max only, SDMA disabled) or "P,S" (PIO max, SDMA max).
 * Validation: P <= DMS_EAGER_PIO_MAX_LIMIT, S <= DMS_EAGER_SDMA_MAX_LIMIT,
 * if S > 0 then P < S.
 */
static __maybe_unused int dms_eager_max_set(const char *val, const struct kernel_param *kp)
{
	u32 pio_max, sdma_max;
	const char *comma;
	char buf[32];
	int ret;

	if (!val)
		return -EINVAL;

	comma = strchr(val, ',');
	if (!comma) {
		/* Single value "P" — SDMA disabled */
		ret = kstrtou32(val, 0, &pio_max);
		if (ret) {
			pr_err("bulksvc_eager_max: invalid PIO value '%s'\n", val);
			return ret;
		}
		sdma_max = 0;
	} else {
		/* Dual value "P,S" — copy P portion into temp buffer */
		size_t p_len = comma - val;

		if (p_len == 0 || p_len >= sizeof(buf)) {
			pr_err("bulksvc_eager_max: empty or oversized PIO value in '%s'\n", val);
			return -EINVAL;
		}
		memcpy(buf, val, p_len);
		buf[p_len] = '\0';

		ret = kstrtou32(buf, 0, &pio_max);
		if (ret) {
			pr_err("bulksvc_eager_max: invalid PIO value '%s'\n", buf);
			return ret;
		}

		ret = kstrtou32(comma + 1, 0, &sdma_max);
		if (ret) {
			pr_err("bulksvc_eager_max: invalid SDMA value '%s'\n", comma + 1);
			return ret;
		}
	}

	if (pio_max > DMS_EAGER_PIO_MAX_LIMIT) {
		pr_err("bulksvc_eager_max: PIO value %u exceeds limit %u\n",
		       pio_max, DMS_EAGER_PIO_MAX_LIMIT);
		return -EINVAL;
	}
	if (sdma_max > DMS_EAGER_SDMA_MAX_LIMIT) {
		pr_err("bulksvc_eager_max: SDMA value %u exceeds limit %u\n",
		       sdma_max, DMS_EAGER_SDMA_MAX_LIMIT);
		return -EINVAL;
	}
	if (sdma_max > 0 && pio_max >= sdma_max) {
		pr_err("bulksvc_eager_max: PIO (%u) must be less than SDMA (%u)\n",
		       pio_max, sdma_max);
		return -EINVAL;
	}

	dms_eager_pio_max = pio_max;
	dms_eager_sdma_max = sdma_max;
	return 0;
}

static __maybe_unused int dms_eager_max_get(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%u,%u\n",
			 dms_eager_pio_max, dms_eager_sdma_max);
}

#define HFI2_DMS_FABRIC_PACKET_MAX_LIFETIME_NS  (10l * SEC_IN_NS)

#define HFI2_DMS_STALE_BACKOFF_BASE_MS          (dms_health_cfg.base_ms)
#define HFI2_DMS_STALE_BACKOFF_MAX_COUNT        (dms_health_cfg.max_retries)
#define HFI2_DMS_STALE_EXEMPT_COUNT             (HFI2_DMS_STALE_BACKOFF_MAX_COUNT+1)
#define HFI2_DMS_STALE_EXEMPT_CANCEL_NS         (10l * MIN_IN_NS)
#define HFI2_DMS_TRACKER_ABSOLUTE_MAX_NS        (30l * SEC_IN_NS)
/*
 * Forward-progress window: a tracker whose byte_odometer has not advanced for
 * this long is genuinely wedged and is reclaimed (delivering the error
 * completion BTS uses to flush any parked chain children). Shorter than the
 * absolute-max lifetime backstop; a transfer moving even one byte per window
 * refreshes it and is never reclaimed.
 */
#define HFI2_DMS_TRACKER_PROGRESS_MAX_NS        (5l * SEC_IN_NS)
#define HFI2_DMS_TIDSET_STALE_TIMEOUT_NS        ((HFI2_DMS_STALE_BACKOFF_BASE_MS / 2) * MS_IN_NS)

#if HFI2_DMS_COUNTERS_ENABLE
#if defined(CONFIG_X86_64)
#define dms_rdtsc() rdtsc()
#elif defined(CONFIG_ARM64)
#include <asm/arch_timer.h>
#define dms_rdtsc() arch_timer_read_counter()
#else
#define dms_rdtsc() (0ull)
#endif
#else
#define dms_rdtsc() (0ull)
#endif

#if HFI2_DMS_COUNTERS_ENABLE
static void _dms_aggregate_perf_counters(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	enum hfi2_dms_xfer_type const type = tracker->hdr.type;
	enum hfi2_dms_xfer_op const op = tracker->hdr.op;

	struct dms_perf_counters *perf = &dms->counters.perf[type][op];
	struct hfi2_dms_tracker_perf *tperf = &tracker->hdr.perf;
	u32 size = 0;

	if (tracker->hdr.side == HFI2_DMS_XFER_SIDE_RX)
		size = tracker->rx.total_payload;
	else
		size = tracker->tx.total_payload;

	perf->transfers++;
	perf->bytes += size;

	perf->total_time = ktime_add(perf->total_time, ktime_sub(tperf->lifetime[1], tperf->lifetime[0]));
	if (ktime_to_ns(tperf->rift_wait[0]) > 0)
		perf->rift_wait_time = ktime_add(perf->rift_wait_time, ktime_sub(tperf->rift_wait[1], tperf->rift_wait[0]));
}
#endif

#if HFI2_DMS_TRACE_ENABLE
#define dms_trace(trace_name, ...) \
	trace_##trace_name( __VA_ARGS__)
#else
#define dms_trace(trace_name, ...) \
	do { } while (0)
#endif

#if HFI2_DMS_BUG_ENABLE
#define DMS_BUG_ON(...) WARN_ON_ONCE(__VA_ARGS__)
#define DMS_WARN_ON(...) WARN_ON(__VA_ARGS__)
#else
#define DMS_BUG_ON(...)
#define DMS_WARN_ON(...) (false)
#endif

#define HFI2_DMS_CSPECAGE (0) // unsure if this should be specifiable
#define HFI2_DMS_BTH_OPCODE (192) // USER_0
#define HFI2_DMS_MAX_PAYLOAD_SIZE (8192)
#define HFI2_DMS_CTRL_HDR_SIZE (23ull)
#define HFI2_DMS_MAX_TX_TRACKERS_FAST ((u64) U16_MAX)

static_assert(HFI2_DMS_CTRL_HDR_SIZE * sizeof(u32) >=
	      sizeof(struct eal_ingress_header) + CNE_RX_TS_SIZE + ETH_HLEN +
	      sizeof(struct iphdr) + sizeof(struct udphdr),
	      "DMS control HDRQ split must retain EAL plus Ethernet/IPv4/UDP headers");

/*
 * The ETH EAL RCD split and RcvRsmCfg.BypassHdrSize derive from this helper
 * and cannot diverge.  The unrelated OPA ctrl RCD uses HFI2_DMS_CTRL_HDR_SIZE.
 */
u8 hfi2_dms_eth_bypass_hdr_dws(struct hfi2_devdata *dd)
{
	u32 const max_hdr_dws = dd->rcv_hdr_ent_size > 2 ?
		dd->rcv_hdr_ent_size - 2 : 0;

	if (max_hdr_dws < 4)
		return 4;

	return min_t(u32, HFI2_DMS_CTRL_HDR_SIZE, max_hdr_dws);
}

/* In DMS regardless of the actual host page size we use 4k as
 * our "page" / chunk size as the hfi hardware expects it and
 * it keeps the core DMS protocol logic the same.
 */
#define HFI2_DMS_TID_PAGE_SIZE (4096)
#define HFI2_DMS_TID_PAGE_SHIFT (12)

/* For a TID entry this smask value implies a 4k buffer size */
#define HFI2_DMS_TID_BUF_SIZE_SMASK (0x1ull << 46)
/*
 * SDMA inject can span at most one tidset window plus a single spill
 * page caused by head misalignment of the issuing rx_tracker (the
 * inject begins on the misaligned page, so the tail can extend one
 * page past the tidset boundary).
 */
#define HFI2_DMS_SDMA_DATA_PAGES_MAX (HFI2_DMS_TID_SET_PAGES_MAX + 1)
#define HFI2_DMS_DESC_CHUNK_SIZE (32)
#define HFI2_DMS_PAYLOAD_CHUNK_SIZE (256)
static_assert (MAX_DESC % HFI2_DMS_DESC_CHUNK_SIZE == 0,
	"Descriptor submission alignment must be a factor of max descriptors per packet" );

/*
 * A DATA packet spans 1 header descriptor + payload descriptors + 1 tail
 * descriptor, all counted FIRST..LAST inclusive against the hardware
 * MAX_DESC=64 limit.  The per-packet payload budget therefore reserves
 * only the header and the tail; the packetizer then pads each packet up to
 * a multiple of HFI2_DMS_DESC_CHUNK_SIZE (32), so the whole submission
 * stays 32-aligned without the packetizer having to insert
 * padding inside the last packet (the source of the MAX_DESC overflow).
 */
#define HFI2_DMS_PKT_PAYLOAD_DESC_BUDGET (MAX_DESC - 2)

/* SDMA descriptors address payload in quad-word granular byte counts. */
#define HFI2_DMS_DESCS_PER_QWORD (8)

/*
 * Scratch descriptor stack: one inject spans at most
 * HFI2_DMS_AHG_HEADERS_PER_SET DATA sub-packets, each padded to at most
 * MAX_DESC descriptors.  The extra HFI2_DMS_DESCS_PER_QWORD slots absorb
 * the transient overshoot the budget search may write past a packet's
 * payload budget before retreating to the largest legal qword-aligned cut.
 */
#define HFI2_DMS_DESC_STACK_DESCS \
	(HFI2_DMS_AHG_HEADERS_PER_SET * MAX_DESC + HFI2_DMS_DESCS_PER_QWORD)


/*
 * CYR and JKR SDMA descriptors share identical byte_count, phy_addr,
 * first_desc, last_desc, head_to_host, and header_mode field layouts
 * (per the CYR HAS: "The CYR SDMA Descriptor is identical to the JKR
 * SDMA Descriptor format except that bits [63:62] of the SDmaLastDesc
 * now indicate bits [9:8] of the send context idx").
 *
 * These wrappers call the jkr_ accessors directly and exist so that
 * DMS code does not appear to use the wrong chip's helpers on CYR.
 */
static inline void _sdma_qw_set_byte_count(u64 *qw, u32 bytes)
{
	jkr_sdma_qw_set_byte_count(qw, bytes);
}

static inline void _sdma_qw_set_phy_addr(u64 *qw, u64 phy_addr)
{
	jkr_sdma_qw_set_phy_addr(qw, phy_addr);
}

static inline void _sdma_qw_set_first_desc(u64 *qw)
{
	jkr_sdma_qw_set_first_desc(qw);
}

static inline void _sdma_qw_set_last_desc(u64 *qw)
{
	jkr_sdma_qw_set_last_desc(qw);
}

static inline void _sdma_qw_set_header_mode(u64 *qw, u8 mode)
{
	jkr_sdma_qw_set_header_mode(qw, mode);
}

/*
 * CYR and JKR share identical RHF bit layouts for RHE_VALID (bit 63),
 * L2_TYPE (shift 54, mask 0x3), RCV_SEQ (shift 56, mask 0xf), and
 * RCV_PORT (shift 60, mask 0x3).
 */
static inline u32 _rhf_l2_type(u64 rhf)
{
	return jkr_rhf_l2_type(rhf);
}

static inline bool _rhf_rhe_valid(u64 rhf)
{
	return jkr_rhf_rhe_valid(rhf);
}

static inline u32 _rhf_rcv_seq(u64 rhf)
{
	return jkr_rhf_rcv_seq(rhf);
}

static inline u8 _rhf_rcv_port(u64 rhf)
{
	return jkr_rhf_rcv_port(rhf);
}

#define HFI2_DMS_LRH16BC_LEN_QW_MASK (0x7ffull)
#define HFI2_DMS_LRH16BC_LEN_QW_SHIFT (48)

#define HFI2_DMS_LRH16BC_ENTROPY_MASK (0xFFFFull)
#define HFI2_DMS_LRH16BC_ENTROPY_SHIFT (32)

/* Route Control (RC) field in the compressed 16B LRH, bits [30:28]. */
#define HFI2_DMS_LRH16BC_RC_MASK (0x7ull)
#define HFI2_DMS_LRH16BC_RC_SHIFT (28)

/*
 * RC[2] selects SDR (0, in-order) vs FGAR (1, adaptive out-of-order);
 * RC[1:0] selects a routing variant within that class. b'100 is FGAR
 * min-hop, the only variant used on tree topologies.
 */
#define HFI2_DMS_ROUTE_CONTROL_SDR (0x0)
#define HFI2_DMS_ROUTE_CONTROL_FGAR_MIN_HOP (0x4)

static u8 _dms_route_control_unconditional(void)
{
	return hfi2_dms_fgar_enabled() ? HFI2_DMS_ROUTE_CONTROL_FGAR_MIN_HOP :
					  HFI2_DMS_ROUTE_CONTROL_SDR;
}

/*
 * Ordered (verbs-chained) transfers must stay SDR: same-engine,
 * same-route delivery is required for per-engine SDMA FIFO ordering.
 * order_key is UNORDERED only for transfers submitted outside the verbs
 * chaining path, and is fixed for a tracker's lifetime.
 */
static u8 _dms_route_control_for_order_key(u64 order_key)
{
	if (order_key == HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED)
		return _dms_route_control_unconditional();
	return HFI2_DMS_ROUTE_CONTROL_SDR;
}

/*
 * Ordered transfers carry a real order_key; UNORDERED is the sentinel
 * for transfers submitted outside the verbs chaining path.
 */
static bool _dms_transfer_is_ordered(u64 order_key)
{
	return order_key != HFI2_DMS_ORDER_DOMAIN_KEY_UNORDERED;
}

#define HFI2_DMS_ARRAY_SIZE(arr) ((sizeof(arr) / sizeof(arr[0])))

/* enum hfi2_dms_msg_type and its ordinal-pinning static_asserts live in
 * dms.h so HFI2_DMS_PACKET_DROP_TYPE_COUNT can be defined directly in terms
 * of HFI2_DMS_MSG_TYPE_COUNT there.
 */

#ifndef HFI2_DMS_TESTING_ENABLE
#define HFI2_DMS_TESTING_ENABLE (0)
#endif

/*
 * Count a valid native-16B packet by its wire length quadword class. This is
 * a debug view of what the hardware delivered, independent of what the
 * transmit side counted
 */
static void _dms_rhf_test(struct hfi2_dms *dms, u64 rhf)
{
#if HFI2_DMS_RHF_TEST_ENABLE
	++dms->counters.rhf_test[HFI2_TEST_LEN_QW_CLASS(rhf_pkt_len(rhf))];
#else
	(void)dms;
	(void)rhf;
#endif
}

#if HFI2_DMS_TESTING_ENABLE
/*
 * DMS Packet Drop Testing via debugfs: /sys/kernel/debug/hfi2/hfi2_<unit>/packet_drop
 *
 * Write: "[<type>] <freq> [<count>]"
 *   type  - Message type (read_start, data, ack, nack, etc.) or "all" (default: all)
 *   freq  - Drop frequency as percentage (0-100, supports decimals, -1 = always = 100%)
 *   count - Number of packets to drop (inf/all/-1 = unlimited, default: inf)
 *
 * Read: Shows per-type drop/delivered counts and frequency as percentage.
 *
 * A rule applies to every DMS lane, and a finite count is per lane.
 * Read sums the counts over the lanes.
 *
 * Examples:
 *   echo "0.0001" > packet_drop              # Drop 0.0001% of all packet types indefinitely
 *   echo "data 50" > packet_drop             # Drop 50% of data packets indefinitely
 *   echo "data 0.01 10" > packet_drop        # Drop 0.01% of next 10 data packets
 *   echo "data 0" > packet_drop              # Clear data packet drop rule
 *   echo "clear" > packet_drop               # Clear all drop rules and counters
 */
#include <linux/random.h>

static const char * const _dms_msg_type_names[] = {
	[HFI2_DMS_MSG_TYPE_READ_START] = "read_start",
	[HFI2_DMS_MSG_TYPE_WRITE_START] = "write_start",
	[HFI2_DMS_MSG_TYPE_WRITE_START_EAGER] = "write_start_eager",
	[HFI2_DMS_MSG_TYPE_DATA_START] = "data_start",
	[HFI2_DMS_MSG_TYPE_DATA_START_EAGER] = "data_start_eager",
	[HFI2_DMS_MSG_TYPE_DATA_REQUEST] = "data_request",
	[HFI2_DMS_MSG_TYPE_DATA] = "data",
	[HFI2_DMS_MSG_TYPE_ACK] = "ack",
	[HFI2_DMS_MSG_TYPE_NACK] = "nack",
	[HFI2_DMS_MSG_TYPE_STATUS_RESPONSE] = "status_response",
	[HFI2_DMS_MSG_TYPE_STATUS_REQUEST] = "status_request",
	[HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE] = "read_start_speculative",
	[HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE] = "data_speculative",
	[HFI2_DMS_MSG_TYPE_READ_START_REPLAY] = "read_start_replay",
	[HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY] = "write_start_replay",
	[HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY] = "data_request_replay",
	[HFI2_DMS_MSG_TYPE_DATA_REPLAY] = "data_replay",
	[HFI2_DMS_MSG_TYPE_WRITE_START_TINY] = "write_start_tiny",
};

#define HFI2_DMS_DROP_FREQ_ALWAYS 1000000000u

static bool _test_should_drop_for_type(struct hfi2_dms *dms, int type_idx)
{
	int count = atomic_read(&dms->packet_drop.entries[type_idx].count);
	u32 freq;

	if (count == 0)
		return false;

	freq = READ_ONCE(dms->packet_drop.entries[type_idx].frequency_bp);

	if (freq >= HFI2_DMS_DROP_FREQ_ALWAYS) {
		if (count > 0) {
			if (atomic_dec_if_positive(&dms->packet_drop.entries[type_idx].count) >= 0) {
				atomic64_inc(&dms->packet_drop.entries[type_idx].user_dropped);
				return true;
			}
		} else {
			atomic64_inc(&dms->packet_drop.entries[type_idx].user_dropped);
			return true;
		}
	} else if (freq > 0) {
		if (get_random_u32_below(HFI2_DMS_DROP_FREQ_ALWAYS) < freq) {
			if (count > 0) {
				if (atomic_dec_if_positive(&dms->packet_drop.entries[type_idx].count) >= 0) {
					atomic64_inc(&dms->packet_drop.entries[type_idx].user_dropped);
					return true;
				}
			} else {
				atomic64_inc(&dms->packet_drop.entries[type_idx].user_dropped);
				return true;
			}
		}
	}
	return false;
}
#endif /* HFI2_DMS_TESTING_ENABLE */

static inline bool _test_drop_packet(struct hfi2_dms *dms, int msg_type)
{
#if HFI2_DMS_TESTING_ENABLE
	if (_test_should_drop_for_type(dms, msg_type))
		return true;

	atomic64_inc(&dms->packet_drop.entries[msg_type].user_delivered);
#endif /* HFI2_DMS_TESTING_ENABLE */
	return false;
}

enum hfi2_dms_err_type {
	HFI2_DMS_ERR_TYPE_NONE = 0,
	HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND,
	HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
	HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION,
	HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION,
	HFI2_DMS_ERR_TYPE_NO_MEMORY,
	HFI2_DMS_ERR_TYPE_ACCESS_BUSY,
	HFI2_DMS_ERR_TYPE_RNR,

	HFI2_DMS_ERR_TYPE_COUNT,
};

struct hfi2_dms_proto_info_nack {
	enum hfi2_dms_msg_type msg_type;
	enum hfi2_dms_err_type err_type;
	hfi2_dms_rift_key_t rift_key;
	u16 unused;
} __attribute__((packed, aligned(4)));

enum hfi2_dms_status_type {
	HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS = 0,
	HFI2_DMS_STATUS_TYPE_RESPONSE_TIMEDOUT,
	HFI2_DMS_STATUS_TYPE_RESPONSE_TRANSFER_COMPLETE,
	HFI2_DMS_STATUS_TYPE_RESPONSE_NOT_STARTED,
	HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED,
	HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT,
	/* Alias for deferred access pool entries: same wire value as WAITING_RIFT,
	 * but distinguishes sender-side semantics (waiting for access registration
	 * vs. waiting for a RIFT key). The initiator handles both identically. */
	HFI2_DMS_STATUS_TYPE_RESPONSE_ACCESS_PENDING =
		HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT,
	HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET,
	/*
	 * Wire value appended after WAITING_TIDSET to keep existing values
	 * stable (append-only). The responder emits this when it has neither
	 * a local tracker nor a cancel-cache record, instead of guessing
	 * TRANSFER_COMPLETE/NOT_STARTED; the requester reconciles it against
	 * its own health_state. An older peer treats this as an unknown type
	 * (logged + ignored).
	 */
	HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND,
	/* Responder emits this for a tracker that is intentionally parked. */
	HFI2_DMS_STATUS_TYPE_RESPONSE_PARKED,

	HFI2_DMS_STATUS_TYPE_COUNT,
};

struct hfi2_dms_proto_info_status {
	hfi2_dms_rift_key_t requester_rift_key;
	hfi2_dms_rift_key_t responder_rift_key;
	enum hfi2_dms_status_type type;
	union {
		u64 packet_progress;
		struct {
			u64 rift_tracker_ticket;
			u64 rift_global_assigned;
		};
		u64 tidset_progress;
	};
} __attribute__((packed, aligned(4)));

struct hfi2_dms_proto_info_data_request_small {
	u32 bth[3];
	u32 kdeth[2];
	u16 size;
	hfi2_dms_rift_key_t rx_rift_key;
	u32 offset;
	hfi2_dms_rift_key_t tx_rift_key;
} __packed __aligned(8);

struct hfi2_dms_proto_info_ack {
	u32 bth[3];
	u32 kdeth[2];
	hfi2_dms_rift_key_t tx_rift_key;
	u16 flags;
	u64 imm_data;
	u8 unused[8];
} __packed __aligned(8);

struct hfi2_dms_proto_info_data_small {
	u32 bth[3];
	u32 kdeth[2];
	hfi2_dms_rift_key_t tx_rift_key;
	hfi2_dms_rift_key_t rx_rift_key;
	u64 data[2];
} __packed __aligned(8);

struct hfi2_dms_proto_info_data {
	u32 bth[3];
	u32 kdeth[2];
	hfi2_dms_rift_key_t tx_rift_key;
	u16 generation;
	u64 reserved[2];
} __packed __aligned(8);

/*
 * Bytes of recv_chunk + gather array carried inline in the control HDRQ header.
 * The DATA_REQUEST arm sits at wire offset 36 (after the shared lrh/bth/kdeth);
 * its 20-byte fixed body puts the arrays at wire offset 56, leaving the
 * 120-byte control inline budget for 64 bytes: four direct chunks with their
 * single gather element each.
 */
#define HFI2_DMS_DR_INLINE_BYTES (120 - 56)

/*
 * DATA_REQUEST wire body -- the arm of union _pkt_cmd / struct _hdrq_entry that
 * follows the shared lrh/bth/kdeth header, mirroring hfi2_dms_read_start_parameters.
 * Header-derived fields (slid, size_qw, rx_id) are recovered from that shared
 * header, not this body.
 *
 * The body is followed by recv_chunks[recv_chunk_count] and then
 * gather[gather_count]. The fixed part is exactly 20 bytes so the arrays start
 * at wire offset 56, an 8-byte record boundary: arrays up to
 * HFI2_DMS_DR_INLINE_BYTES end within the 120-byte control boundary, and a
 * larger pair goes whole into the eager portion that begins right there.
 *
 * A request that is one recv_chunk with one gather element covering the whole
 * chunk (the common case: a quadword-aligned destination in one run) is sent
 * in compact form instead: recv_chunk_count is 0, no arrays follow, and the
 * range is carried in the fixed body (sbuf_offset, tid_info) with its length
 * taken from the BTH size_qw. The frame then stays at 64 bytes; carrying the
 * same range as arrays would add a 16-byte record pair, which costs about 4%
 * of small-message RDMA WRITE bandwidth on the responder's control path.
 */
struct hfi2_dms_data_request_parameters {
	union {
		struct {	/* recv_chunk_count != 0 */
			u8 gather_count;
			u8 reserved0[3];
		};
		u32 sbuf_offset;	/* compact: the range's source offset */
	};
	u32 tid_info;	/* compact: the range's tid_info; otherwise 0 */
	hfi2_dms_rift_key_t tx_rift_key;
	u8 reserved2[2];
	u16 generation;
	hfi2_dms_rift_key_t rx_rift_key;
	u16 entropy;
	u8 flags;
	u8 recv_chunk_count;
	u8 arrays[HFI2_DMS_DR_INLINE_BYTES];
} __packed __aligned(4);

_Static_assert(sizeof(struct hfi2_dms_proto_info_data) == 40,
	       "data payload must be exactly 40 bytes (5 QWs)");
static_assert(offsetof(struct hfi2_dms_data_request_parameters, arrays) == 20,
	      "DATA_REQUEST fixed body must be 20 bytes so the arrays land at wire offset 56 (arm@36)");
static_assert(sizeof(struct hfi2_dms_recv_chunk) == 8 &&
	      sizeof(struct hfi2_dms_gather) == 8,
	      "recv_chunk and gather records must be 8 bytes so the 120-byte boundary falls on a record edge");
static_assert(HFI2_DMS_DR_INLINE_BYTES % 8 == 0,
	      "120-byte control boundary must fall on a record edge (no gap into eager)");
static_assert(HFI2_DMS_DR_MAX_GATHER >= HFI2_DMS_DR_CHUNK_MAX_GATHER,
	      "one fully gathered chunk must fit the DATA_REQUEST gather array");
static_assert(HFI2_DMS_DR_MAX_GATHER <= U8_MAX && HFI2_DMS_DR_MAX_CHUNKS <= U8_MAX,
	      "recv_chunk_count/gather_count are u8");
static_assert(HFI2_DMS_TID_SET_BYTES_MAX <= HFI2_DMS_RECV_CHUNK_LENGTH,
	      "a chunk's source length must fit the recv_chunk length field");

/* Wire bytes of a DATA_REQUEST's recv_chunk + gather arrays. */
static u32 _data_request_arrays_bytes(u32 recv_chunk_count, u32 gather_count)
{
	return recv_chunk_count * sizeof(struct hfi2_dms_recv_chunk) +
	       gather_count * sizeof(struct hfi2_dms_gather);
}

/*
 * True if a received control packet of @pktlen_qws (its LRH length: header
 * from the LRH, through the tail flit) holds @arrays_bytes of request arrays
 * starting at wire offset @arrays_wire, placed as the sender places them:
 * inline when they fit the @inline_bytes left in the control HDRQ header,
 * otherwise whole after that inline area (the start of the eager buffer).
 * The arrays are peer-supplied counts; a frame shorter than they claim must
 * not be walked, or the walk reads past the packet into stale HDRQ / eager
 * buffer contents.
 */
static bool _request_arrays_fit(u32 pktlen_qws, u32 arrays_wire,
				u32 inline_bytes, u32 arrays_bytes)
{
	u32 const used = arrays_wire +
		(arrays_bytes > inline_bytes ? inline_bytes : 0) + arrays_bytes;

	/* The tail flit follows the payload, padded to a quadword. */
	return (u64)pktlen_qws * sizeof(u64) >=
	       round_up(used, sizeof(u64)) + sizeof(u64);
}

/*
 * Bytes of a READ_START_SPECULATIVE's request arrays carried inline in the
 * control HDRQ header, after the 52-byte READ_START body at wire offset 36:
 * one direct chunk with its gather element, or two arrays' worth spilled to
 * the eager portion.
 */
#define HFI2_DMS_RS_INLINE_BYTES (120 - (36 + 52))


/**
 * specifically this is the header we expect to land
 * in the HDRQ
 * NOTE: the `user_kdeth` might not fully land (read: won't)
 * and in reality there will only be 5 DWs there.
 * The RHF will be in those last 2 DWs though
 */
union hfi2_dms_16b_header {
	u64 qws[8];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		u32 user_kdeth[7];
	};
};

/*
 * Decode the 16B header's 8-bit BTH message byte into its ULP-id and per-ULP
 * subtype, per the namespacing convention documented with
 * HFI2_DMS_MSGBYTE_ULP_SHIFT in dms.h.  ulp_id 0 is native OPA/BTS, in which
 * case @subtype is the enum hfi2_dms_msg_type ordinal.  Returns -EINVAL if any
 * argument is NULL; the caller decides how to treat that.
 */
static inline int hfi2_dms_16b_ulp_decode(union hfi2_dms_16b_header *hdr,
					  u8 *ulp_id, u8 *subtype)
{
	if (!hdr || !ulp_id || !subtype)
		return -EINVAL;

	u8 msgbyte = hdr->bth[0] >> 16;

	*ulp_id = msgbyte >> HFI2_DMS_MSGBYTE_ULP_SHIFT;
	*subtype = msgbyte & HFI2_DMS_MSGBYTE_SUB_MASK;
	return 0;
}

//
// HFI2_DMS_MSG_TYPE_READ_START
//

union hfi2_dms_proto_cmd_data_small {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi2_dms_proto_info_data_small info;	// 5 qws
		u64 tail_flit;
	};
};

union hfi2_dms_proto_pkt_data_small {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi2_dms_proto_info_data_small info; // 5 qws
		u64 tail_flit; // <-- dropped on receive
	};
};

union hfi2_dms_proto_cmd_data {
	u64 qws[12];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi2_dms_proto_info_data info;	// 5 qws
		u64 reserved[5];
	};
};

union hfi2_dms_proto_pkt_data {
	u64 qws[12];
	struct {
		u64 lrh[2];
		struct hfi2_dms_proto_info_data info; // 5 qws
		u64 reserved[5];
	};
};

/*
 * RcvPktCtrl HdrSize for the data receive context: the KDETH size in DWs, from
 * the start of the KDETH header to the end of the DATA header. Everything
 * after it is payload and is placed by TID, so it applies to every packet
 * received on the context and the DATA header cannot vary in size.
 */
#define HFI2_DMS_DATA_HDR_SIZE \
	((sizeof(union hfi2_dms_proto_pkt_data) - \
	  offsetof(union hfi2_dms_proto_pkt_data, info.kdeth)) / sizeof(u32))

/* Wire length of a DATA packet with @payload bytes: header, payload, tail flit. */
#define HFI2_DMS_DATA_WIRE_BYTES(payload) \
	(sizeof(union hfi2_dms_proto_pkt_data) + (payload) + sizeof(u64))

static_assert(sizeof(union hfi2_dms_proto_pkt_data) ==
	      sizeof(union hfi2_dms_proto_cmd_data),
	      "DATA command and packet headers must have the same wire size");
/*
 * A DATA packet that needs the PBC test bit is split into two that do not,
 * which needs the smallest packets not to need it: no payload (the edge
 * carrier), the smallest payload, and the full payload.
 */
static_assert(!HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(0)),
	      "an empty DATA packet must not need the PBC test bit");
static_assert(!HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(sizeof(u64))),
	      "an 8 byte DATA packet must not need the PBC test bit");
static_assert(!HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(HFI2_DMS_MAX_PAYLOAD_SIZE)),
	      "a full DATA packet must not need the PBC test bit");

/*
 * True if a DATA packet with @payload bytes must be split in two: its wire
 * length needs the PBC test bit, which is when the payload, rounded up to a
 * quadword, is one of HFI2_TEST_LEN_*_QW_CLASS quadwords past a multiple of
 * 128 bytes less the 104 bytes of header and tail flit.
 */
static inline bool _dms_split_data_packet(u64 payload)
{
	return HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(ALIGN(payload, sizeof(u64))));
}

/*
 * Bytes to move from a DATA packet that needs the PBC test bit into the packet
 * that follows it. The packet that is left ends one quadword below the first
 * length that needs the bit, and the one that follows carries 8 to 32 bytes,
 * which never needs it.
 */
static inline u64 _dms_data_split_trim(u64 payload)
{
	u64 const wire = HFI2_DMS_DATA_WIRE_BYTES(ALIGN(payload, sizeof(u64)));
	u64 const span_mask = ((HFI2_TEST_LEN_QW_CLASS_MASK + 1) <<
			       HFI2_TEST_LEN_QW_BYTE_SHIFT) - 1;

	return (wire & span_mask) -
	       ((HFI2_TEST_LEN_QW_CLASS_FIRST - 1) << HFI2_TEST_LEN_QW_BYTE_SHIFT);
}

static_assert(!HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(1 * sizeof(u64))) &&
	      !HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(2 * sizeof(u64))) &&
	      !HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(3 * sizeof(u64))) &&
	      !HFI2_TEST_LEN(HFI2_DMS_DATA_WIRE_BYTES(4 * sizeof(u64))),
	      "the packet after a split (1 to 4 quadwords) must not need the PBC test bit");
static_assert(HFI2_TEST_LEN_QW_CLASS_LAST - HFI2_TEST_LEN_QW_CLASS_FIRST + 1 == 4,
	      "the split packet size checks above cover every length that needs the PBC test bit");

union hfi2_dms_proto_cmd_ack {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		struct hfi2_dms_proto_info_ack info; // 5 qws
		u64 tail_flit;
	};
};

union hfi2_dms_proto_pkt_ack {
	u64 qws[8];
	struct {
		u64 lrh[2];
		struct hfi2_dms_proto_info_ack info; // 5 qws
		u64 tail_flit; // <-- dropped on receive
	};
};

/*
 * Eager DATA_START parameters — rift keys for small READ responses.
 * Inline payload follows immediately after this struct in the packet.
 */
struct hfi2_dms_data_start_parameters {
	hfi2_dms_rift_key_t tx_rift_key;
	hfi2_dms_rift_key_t rx_rift_key;
	u64 reserved_qw;	/* sent as zero */
	u64 eager_payload;	/* an eager payload starts here */
} __packed __aligned(4);

/*
 * PIO command buffer layout for eager packets.  The union overlays the
 * generic proto_cmd with typed field access for DATA_START eager.
 */
union _pkt_cmd {
	union hfi2_dms_proto_cmd pio;
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		union {
			u32 sw[128/4-9];
			struct hfi2_dms_data_start_parameters data_start;
			struct hfi2_dms_write_start_parameters write_start;
			struct hfi2_dms_read_start_parameters read_start;
			struct hfi2_dms_data_request_parameters data_request;
		};
		//u64 tail_flit;
	};
};

static void _pkt_cmd_layout_check(void)
{
	BUILD_BUG_ON(offsetof(union _pkt_cmd, bth) != 16);
}

/*
 * WRITE_START_EAGER layout.  The header is padded so the PIO command is the
 * PBC plus exactly 15 header qwords (two whole PIO blocks) and the eager
 * payload starts at qword 0 of the third block.  On the wire the 8-byte
 * lrh16bc expands to the 16-byte 16B LRH, so the payload is at wire byte 128.
 * The receive header-queue entry holds 120 bytes of header, so all the
 * write_start parameters arrive in the header queue, wire bytes 120..127
 * (padding) land at the start of the eager buffer, and the payload lands at
 * eager-buffer offset WSE_EBUF_PAYLOAD_OFFSET.
 */
#define WSE_PIO_PAYLOAD_OFFSET		(2 * PIO_BLOCK_SIZE)	/* from the PBC */
#define WSE_WIRE_PAYLOAD_OFFSET		WSE_PIO_PAYLOAD_OFFSET	/* from the LRH */
#define WSE_HDR_QWS			((WSE_PIO_PAYLOAD_OFFSET - 8) / 8)
#define WSE_HDRQ_HDR_BYTES		120
#define WSE_EBUF_PAYLOAD_OFFSET		(WSE_WIRE_PAYLOAD_OFFSET - WSE_HDRQ_HDR_BYTES)

/*
 * WRITE_START_TINY layout.  The packet is a WRITE_START whose payload, at
 * most WST_PAYLOAD_MAX bytes, takes the place of the reserved_qw and
 * eager_payload slots, so the whole packet, tail flit included, lands in the
 * receive header-queue entry.  The 8-byte PBC plus 8-byte lrh16bc occupy the
 * same bytes as the 16-byte wire LRH, so the payload offset is the same in
 * the PIO command and in the header-queue entry.
 */
#define WST_PAYLOAD_OFFSET	(offsetof(struct _hdrq_entry, write_start) + \
				 offsetof(struct hfi2_dms_write_start_parameters, reserved_qw))
#define WST_PAYLOAD_MAX		32
/*
 * Shortest payload actually sent.  Fewer qwords would put the wire length
 * (payload offset + payload + tail flit) on a PBC test length, so a 0 to 16
 * byte write sends both of those qwords, zero padded.  eager_nbytes carries
 * the real byte count.
 */
#define WST_PAYLOAD_MIN_SENT	16

/*
 * Header queue entry layout for received eager packets.
 * Maps the 16B header to typed field access.
 */
struct _hdrq_entry {
	u64 lrh[2];
	u32 bth[3];
	u32 kdeth[2];
	union {
		struct hfi2_dms_data_start_parameters data_start;
		struct hfi2_dms_write_start_parameters write_start;
		struct hfi2_dms_read_start_parameters read_start;
		struct hfi2_dms_data_request_parameters data_request;
	};
};

/*
 * A DATA_REQUEST's request arrays follow its fixed body; the largest frame
 * (arrays carried in the eager portion) must fit the PIO paths that build it.
 */
static void _data_request_layout_check(void)
{
	u32 const arrays_wire =
		offsetof(struct _hdrq_entry, data_request) +
		offsetof(struct hfi2_dms_data_request_parameters, arrays);
	u32 const max_frame = sizeof(u64) + arrays_wire +
		HFI2_DMS_DR_INLINE_BYTES +
		_data_request_arrays_bytes(HFI2_DMS_DR_MAX_CHUNKS,
					   HFI2_DMS_DR_MAX_GATHER) +
		sizeof(u64);

	/* Worst case: PBC + header + zeroed inline area + the largest arrays in
	 * the eager portion + tail flit fits scratch, the credit floor, and the
	 * PIO waiter snapshot.
	 */
	BUILD_BUG_ON(max_frame > HFI2_DMS_PIO_SCRATCH_SIZE);
	BUILD_BUG_ON(max_frame > SCS_BULKSVC_CREDITS * PIO_BLOCK_SIZE);
	BUILD_BUG_ON(DIV_ROUND_UP(max_frame, sizeof(u64)) >
		     HFI2_DMS_PIO_WAITER_QWS);
	/*
	 * Padding off a PBC test-bit length never grows a frame past a longer
	 * one that needs no padding, so the worst case above bounds every
	 * padded frame as long as the worst case itself needs none.
	 */
	BUILD_BUG_ON(HFI2_TEST_LEN(max_frame - sizeof(u64)));
}

/*
 * The read_start arm must land at the same byte offset in both the
 * PIO command union and the receive HDRQ entry, and must fit inside
 * the shared hfi2_dms_proto_cmd overlay. This is what lets
 * hfi2_dms_impl_handle_read_start_packet() take &entry->read_start
 * and hfi2_dms_impl_inject_read_start() write cmd.read_start without
 * either side silently drifting if a field is ever added/removed.
 */
static void _read_start_layout_check(void)
{
	BUILD_BUG_ON(offsetof(union _pkt_cmd, read_start) !=
		     offsetof(struct _hdrq_entry, read_start));
	BUILD_BUG_ON(offsetof(union _pkt_cmd, read_start) +
		     sizeof_field(union _pkt_cmd, read_start) >
		     sizeof(union hfi2_dms_proto_cmd));
	/* Received frame + tail flit must fit the control HDRQ inline budget. */
	BUILD_BUG_ON(offsetof(struct _hdrq_entry, read_start) +
		     sizeof_field(struct _hdrq_entry, read_start) +
		     sizeof(u64) > 120);
	/* Pin the packed wire-body size so any ABI change is deliberate. */
	BUILD_BUG_ON(sizeof(struct hfi2_dms_read_start_parameters) != 52);
	/*
	 * A READ_START_SPECULATIVE's request arrays start right after the body,
	 * on a record edge, so the 120-byte control boundary falls on one too.
	 */
	BUILD_BUG_ON((offsetof(struct _hdrq_entry, read_start) +
		      sizeof_field(struct _hdrq_entry, read_start)) % 8 != 0);
	BUILD_BUG_ON(offsetof(struct _hdrq_entry, read_start) +
		     sizeof_field(struct _hdrq_entry, read_start) +
		     HFI2_DMS_RS_INLINE_BYTES != 120);
	/*
	 * PBC + header + zeroed inline area + TID_MAX of the largest requests +
	 * tail flit fits scratch, the credit floor, and the PIO waiter snapshot.
	 */
	BUILD_BUG_ON(sizeof(u64) + 120 + HFI2_DMS_READ_START_SPECULATIVE_TID_MAX *
		     _data_request_arrays_bytes(HFI2_DMS_DR_MAX_CHUNKS,
						HFI2_DMS_DR_MAX_GATHER) +
		     sizeof(u64) > HFI2_DMS_PIO_WAITER_QWS * sizeof(u64));
	BUILD_BUG_ON(sizeof(u64) + 120 + HFI2_DMS_READ_START_SPECULATIVE_TID_MAX *
		     _data_request_arrays_bytes(HFI2_DMS_DR_MAX_CHUNKS,
						HFI2_DMS_DR_MAX_GATHER) +
		     sizeof(u64) > HFI2_DMS_PIO_SCRATCH_SIZE);
	BUILD_BUG_ON(sizeof(u64) + 120 + HFI2_DMS_READ_START_SPECULATIVE_TID_MAX *
		     _data_request_arrays_bytes(HFI2_DMS_DR_MAX_CHUNKS,
						HFI2_DMS_DR_MAX_GATHER) +
		     sizeof(u64) > SCS_BULKSVC_CREDITS * PIO_BLOCK_SIZE);
	/* The worst case needs no PBC test-bit padding, so it bounds padded frames. */
	BUILD_BUG_ON(HFI2_TEST_LEN(120 + HFI2_DMS_READ_START_SPECULATIVE_TID_MAX *
				   _data_request_arrays_bytes(HFI2_DMS_DR_MAX_CHUNKS,
							      HFI2_DMS_DR_MAX_GATHER) +
				   sizeof(u64)));

	/* data_request is a header-less arm like read_start: same offset in the
	 * PIO command and HDRQ entry so the send builder and receive handler
	 * address it identically.
	 */
	BUILD_BUG_ON(offsetof(union _pkt_cmd, data_request) !=
		     offsetof(struct _hdrq_entry, data_request));
	BUILD_BUG_ON(offsetof(struct _hdrq_entry, data_request) +
		     offsetof(struct hfi2_dms_data_request_parameters, arrays) != 56);
	/* The arm with its full inline area must fit the shared command overlay
	 * and, with the tail flit, the 128-byte frame.
	 */
	BUILD_BUG_ON(offsetof(union _pkt_cmd, data_request) +
		     sizeof_field(union _pkt_cmd, data_request) >
		     sizeof(union hfi2_dms_proto_cmd));
	BUILD_BUG_ON(offsetof(struct _hdrq_entry, data_request) +
		     sizeof_field(struct _hdrq_entry, data_request) +
		     sizeof(u64) > sizeof(union hfi2_dms_proto_cmd));
	/*
	 * WRITE_START_EAGER: the parameters, eager_payload included, must sit in
	 * the 120-byte header-queue part, and the header must fill exactly
	 * the PIO command buffer's two leading blocks.
	 */
	BUILD_BUG_ON(offsetof(struct _hdrq_entry, write_start) +
		     sizeof_field(struct _hdrq_entry, write_start) >
		     WSE_HDRQ_HDR_BYTES);
	BUILD_BUG_ON(WSE_HDR_QWS != 2 * PIO_BLOCK_QWS - 1);
	BUILD_BUG_ON(sizeof(union hfi2_dms_proto_cmd) < WSE_PIO_PAYLOAD_OFFSET);
	BUILD_BUG_ON(WSE_EBUF_PAYLOAD_OFFSET != 8);
	/* _inject_write_start_pio() zeroes command qwords 12..15 as padding. */
	BUILD_BUG_ON(offsetof(union _pkt_cmd, write_start) +
		     sizeof_field(union _pkt_cmd, write_start) != 12 * sizeof(u64));
	/*
	 * WRITE_START_TINY: the payload starts at the same offset in the PIO
	 * command and the header-queue entry, qword aligned, and a full-size
	 * payload plus the tail flit fits both the 120-byte header-queue part
	 * and the 15-qword PIO command (_pio_cmd_send()).
	 */
	BUILD_BUG_ON(offsetof(union _pkt_cmd, write_start) +
		     offsetof(struct hfi2_dms_write_start_parameters, reserved_qw) !=
		     WST_PAYLOAD_OFFSET);
	BUILD_BUG_ON(WST_PAYLOAD_OFFSET % sizeof(u64));
	BUILD_BUG_ON(WST_PAYLOAD_MAX % sizeof(u64));
	BUILD_BUG_ON(WST_PAYLOAD_OFFSET + WST_PAYLOAD_MAX + sizeof(u64) >
		     WSE_HDRQ_HDR_BYTES);
	BUILD_BUG_ON(WST_PAYLOAD_OFFSET + WST_PAYLOAD_MAX + sizeof(u64) >
		     2 * PIO_BLOCK_SIZE);
	/* _inject_write_start_tiny() zeroes command qwords 12..14. */
	BUILD_BUG_ON(WST_PAYLOAD_OFFSET + WST_PAYLOAD_MIN_SENT !=
		     12 * sizeof(u64));
	BUILD_BUG_ON(WST_PAYLOAD_OFFSET + WST_PAYLOAD_MAX + sizeof(u64) !=
		     15 * sizeof(u64));
	/* No WRITE_START_TINY length needs the PBC test bit. */
	BUILD_BUG_ON(HFI2_TEST_LEN(WST_PAYLOAD_OFFSET + 16 + sizeof(u64)));
	BUILD_BUG_ON(HFI2_TEST_LEN(WST_PAYLOAD_OFFSET + 24 + sizeof(u64)));
	BUILD_BUG_ON(HFI2_TEST_LEN(WST_PAYLOAD_OFFSET + 32 + sizeof(u64)));
}

/*
 * Wire-format byte offset from the start of the frame (LRH) to the
 * inline payload field, indexed by message type.  Used by _pkt_len_qws()
 * to compute the on-the-wire packet length in quadwords.
 *
 * These are _hdrq_entry offsets (16-byte LRH, no PBC).
 */
static u64 const _msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_COUNT] = {
	(offsetof(struct _hdrq_entry, read_start) + sizeof_field(struct _hdrq_entry, read_start)),
	(offsetof(struct _hdrq_entry, write_start) + sizeof_field(struct _hdrq_entry, write_start)),
	WSE_WIRE_PAYLOAD_OFFSET,	/* HFI2_DMS_MSG_TYPE_WRITE_START_EAGER */
	(offsetof(struct _hdrq_entry, data_start) + sizeof_field(struct _hdrq_entry, data_start)),
	(offsetof(struct _hdrq_entry, data_start) + sizeof_field(struct _hdrq_entry, data_start)),
	/*
	 * DATA_REQUEST carries variable-length recv_chunk + gather arrays; its
	 * payload base is the array start (wire 56), and _pkt_len_qws() adds
	 * their size.
	 */
	(offsetof(struct _hdrq_entry, data_request) +
	 offsetof(struct hfi2_dms_data_request_parameters, arrays)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA */
	0,	/* HFI2_DMS_MSG_TYPE_ACK */
	0,	/* HFI2_DMS_MSG_TYPE_NACK */
	0,	/* HFI2_DMS_MSG_TYPE_STATUS_RESPONSE */
	0,	/* HFI2_DMS_MSG_TYPE_STATUS_REQUEST */
	/*
	 * READ_START_SPECULATIVE appends its requests' recv_chunk + gather
	 * arrays; _pkt_len_qws() adds their size.
	 */
	(offsetof(struct _hdrq_entry, read_start) + sizeof_field(struct _hdrq_entry, read_start)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE */
	(offsetof(struct _hdrq_entry, read_start) + sizeof_field(struct _hdrq_entry, read_start)),
	(offsetof(struct _hdrq_entry, write_start) + sizeof_field(struct _hdrq_entry, write_start)),
	/* DATA_REQUEST_REPLAY shares the DATA_REQUEST wire layout. */
	(offsetof(struct _hdrq_entry, data_request) +
	 offsetof(struct hfi2_dms_data_request_parameters, arrays)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA_REPLAY */
	WST_PAYLOAD_OFFSET,	/* HFI2_DMS_MSG_TYPE_WRITE_START_TINY */
};

/*
 * PIO-command byte offset from lrh16bc to the inline payload field,
 * indexed by message type.
 */
static u64 const _msgtype_pio_payload_offset[HFI2_DMS_MSG_TYPE_COUNT] = {
	(offsetof(union _pkt_cmd, read_start) + sizeof_field(union _pkt_cmd, read_start)),
	(offsetof(union _pkt_cmd, write_start) + sizeof_field(union _pkt_cmd, write_start)),
	WSE_PIO_PAYLOAD_OFFSET,		/* HFI2_DMS_MSG_TYPE_WRITE_START_EAGER */
	(offsetof(union _pkt_cmd, data_start) + sizeof_field(union _pkt_cmd, data_start)),
	(offsetof(union _pkt_cmd, data_start) + sizeof_field(union _pkt_cmd, data_start)),
	(offsetof(union _pkt_cmd, data_request) +
	 offsetof(struct hfi2_dms_data_request_parameters, arrays)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA */
	0,	/* HFI2_DMS_MSG_TYPE_ACK */
	0,	/* HFI2_DMS_MSG_TYPE_NACK */
	0,	/* HFI2_DMS_MSG_TYPE_STATUS_RESPONSE */
	0,	/* HFI2_DMS_MSG_TYPE_STATUS_REQUEST */
	(offsetof(union _pkt_cmd, read_start) + sizeof_field(union _pkt_cmd, read_start)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE */
	(offsetof(union _pkt_cmd, read_start) + sizeof_field(union _pkt_cmd, read_start)),
	(offsetof(union _pkt_cmd, write_start) + sizeof_field(union _pkt_cmd, write_start)),
	(offsetof(union _pkt_cmd, data_request) +
	 offsetof(struct hfi2_dms_data_request_parameters, arrays)),
	0,	/* HFI2_DMS_MSG_TYPE_DATA_REPLAY */
	WST_PAYLOAD_OFFSET,	/* HFI2_DMS_MSG_TYPE_WRITE_START_TINY */
};

static u64 _pkt_len_qws(enum hfi2_dms_msg_type const type, u64 const payload_bytes)
{
	DMS_BUG_ON(_msgtype_wire_payload_offset[type] == 0);
	static u32 const TAIL_FLIT_QWS = 1;
	static u32 const QW_BYTES = sizeof(u64);
	static u32 const QW_MASK = QW_BYTES - 1;
	static u32 const BYTES_TO_QWS_SHIFT = 3;

	u32 const used = _msgtype_wire_payload_offset[type] + payload_bytes;
	u32 const pad = (QW_BYTES - (used & QW_MASK)) & QW_MASK;
	u32 const pkt_bytes = used + pad;

	return (pkt_bytes >> BYTES_TO_QWS_SHIFT) + TAIL_FLIT_QWS;
}

/*
 * Quadwords of zero padding that move a packet of @len_qws (LRH through tail
 * flit) to the next length that does not need the PBC test bit.
 */
static u32 _test_len_pad_qws(u32 len_qws)
{
	u32 const class_qws = len_qws & HFI2_TEST_LEN_QW_CLASS_MASK;

	if (class_qws < HFI2_TEST_LEN_QW_CLASS_FIRST ||
	    class_qws > HFI2_TEST_LEN_QW_CLASS_LAST)
		return 0;

	return HFI2_TEST_LEN_QW_CLASS_LAST + 1 - class_qws;
}

/*
 * Quadwords of zero padding to place after an eager payload, ahead of the
 * tail flit, so the packet length does not need the PBC test bit.
 */
static u32 _eager_pad_qws(enum hfi2_dms_msg_type const type,
			  u64 const payload_bytes)
{
	/*
	 * DATA_START_EAGER starts its payload at the eager_payload slot, one
	 * qword shorter than _pkt_len_qws() reports; WRITE_START_EAGER has a
	 * whole header and no overlay.
	 */
	u32 const overlay_qws = type != HFI2_DMS_MSG_TYPE_WRITE_START_EAGER;

	return _test_len_pad_qws(_pkt_len_qws(type, payload_bytes) -
				 overlay_qws);
}

/*
 * Pad a control frame of @len_qws (LRH through tail flit) built in @cmd off a
 * length that needs the PBC test bit, zeroing the pad and the tail flit, and
 * return the padded length. The pad sits between the payload and the tail
 * flit; a receiver that checks the length only requires room for what the
 * header says the frame carries.
 */
static u32 _pkt_cmd_test_len_pad(union _pkt_cmd *cmd, u32 len_qws)
{
	u32 const pad_qws = _test_len_pad_qws(len_qws);

	memset(&((u64 *)cmd)[len_qws - 1], 0, (pad_qws + 2) * sizeof(u64));
	return len_qws + pad_qws;
}

static void hfi2_dms_impl_pbc_length_dws_set(u64 *pbc, u32 length_dws);
void hfi2_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws);

static void _pkt_cmd_set_lengths(union _pkt_cmd *cmd, u32 pkt_len_qws)
{
	hfi2_dms_impl_pbc_length_dws_set(&cmd->pbc, pkt_len_qws << 1);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
}


struct dms_proto_read_sdma_parameters {
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_mr *mr;
	u64 page_offset;
	u32 nbytes;
	u32 tid_info;
	u8 rx_id;
	u64 head;
	u64 tail;
	enum hfi2_dms_msg_type msg_type;
};

union hfi2_dms_cmd_nack {
	u64 qws[8];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_nack info; // 3 dws
		u64 tail_flit;
		u64 padding[1];
	};
};
union hfi2_dms_pkt_nack {
	u64 qws[7];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_nack info; // 3 dws
		u64 tail_flit; // <-- dropped on receive
	};
};

union hfi2_dms_cmd_status {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_status info;
		u64 tail_flit;
		u64 padding[6];
	};
};

union hfi2_dms_pkt_status {
	u64 qws[10];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_status info;
		u64 reserved[4];
		u64 tail_flit; // <-- dropped on receive
	};
};

static_assert(!HFI2_TEST_LEN(sizeof(union hfi2_dms_pkt_status)),
	      "status response packet length must not need the PBC test bit");
static_assert(sizeof(union hfi2_dms_pkt_status) <=
	      sizeof(union hfi2_dms_cmd_status),
	      "status response packet must fit the PIO command buffer");

/*
 * Batched status request packet — carries up to 41 requester_rift_key
 * entries in a single PIO packet. Each entry is the sender's local RIFT
 * key; the receiver uses it as a remote key for _locate_tracker() lookup.
 */
#define HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES 41

struct hfi2_dms_proto_info_status_request {
	u8 count;
	hfi2_dms_rift_key_t entries[HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES];
	u8 _padding;
} __attribute__((packed, aligned(4)));

union hfi2_dms_cmd_status_request {
	u64 qws[16];
	struct {
		u64 pbc;
		u64 lrh16bc;
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_status_request info;
		u64 tail_flit;
	};
};

union hfi2_dms_pkt_status_request {
	u64 qws[16];
	struct {
		u64 lrh[2];
		u32 bth[3];
		u32 kdeth[2];
		struct hfi2_dms_proto_info_status_request info;
		u64 tail_flit;
	};
};

_Static_assert(sizeof(struct hfi2_dms_proto_info_status_request) == 84,
	       "status request payload must be exactly 84 bytes");
_Static_assert(sizeof(union hfi2_dms_pkt_status_request) == 128,
	       "status request packet must be exactly 16 QWs");

/*
 * A PIO packet waiting for send credits, described so it can be built into
 * the PIO buffer when its turn comes: @buf holds the PBC and @hdr_qws header
 * qwords after it, then @nbytes of @pp's buffer from @byte_offset follow,
 * then @trail_qws zero qwords (pad and tail flit).  A self-contained packet
 * (control command, copied ULP packet) has @nbytes 0 and its tail flit in
 * @buf.  A packet sent for a tracker carries the tracker's @handle; once the
 * tracker is cancelled, completed or recycled the handle no longer resolves
 * and the waiter is dropped without touching @pp.
 */
struct pio_waiter {
	struct hfi2_dms_dlist_element element;
	struct hfi2_dms_transfer_handle handle;	/* NONE: no tracker */
	struct hfi2_dms_page_provider pp;	/* used only when nbytes != 0 */
	u64 byte_offset;
	u32 nbytes;
	u16 hdr_qws;
	u8 trail_qws;
	u64 buf[HFI2_DMS_PIO_WAITER_QWS];
};

// redundant now but keeping it here just in case
static void hfi2_sdma_disable_gen_check(struct hfi2_dms *dms, struct sdma_engine *sde)
{
	u64 reg;

	sde->check_generation = SDMA_CHECK_GEN_DISABLE; // disabled
	reg = read_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg);
	reg &= ~(((u64) (BIT(3) - 1)) << SEND_DMA_LEN_GEN_GENERATION_SHIFT);
	write_sdma_csr(dms->dd, sde->this_idx, sde->dd->params->send_dma_len_gen_reg, reg);
}

static inline u32 hfi2_dms_lrh16B_slid_get(u32 *lrh)
{
	u32 ret;

	ret = (u32)((lrh[0] & OPA_16B_LID_MASK) |
			 (((lrh[2] & OPA_16B_SLID_MASK) >>
			 OPA_16B_SLID_HIGH_SHIFT) << OPA_16B_SLID_SHIFT));
	return ret;
}

/*
 * Wire-format entropy getter: LRH3 (lrh[3]) carries the 16B entropy field on
 * the raw wire, distinct from the compressed PIO command's lrh16bc bit[47:32]
 * (see hfi2_dms_impl_lrh16bc_entropy_set) -- the two formats are expected to
 * differ, this is not a bug to unify.
 */
static inline u16 hfi2_dms_lrh16B_entropy_get(u32 *lrh)
{
	return (u16)(lrh[3] & OPA_16B_ENTROPY_MASK);
}

static inline u32 hfi2_dms_lrh16B_pkt_len_get(u64 *lrh)
{
	u32 ret;

	ret = (u32)((lrh[0] & OPA_16B_LEN_MASK) >> OPA_16B_LEN_SHIFT);
	return ret;
}

static inline u32 hfi2_dms_16b_data_payload_qws_get(union hfi2_dms_16b_header *hdr)
{
	u32 pktlen_qws;
	u32 ret;

	/*
	 * For DMS data messages the amount of payload is
	 * pktlen_qws - header QWs - 1 (tail flit)
	 */
	pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	ret = pktlen_qws - 1 - sizeof(union hfi2_dms_proto_pkt_data) / sizeof(u64);
	return ret;
}

static inline u32 hfi2_dms_tid_info_make(u16 tid, u16 offset_dw)
{
	u32 const kver = 0x1u << 30; // Kernel version bit
	u32 const tid_ctrl = 0x3u << 26; // Upper and Lower
	u32 const TID_MASK = 0x3ffu;
	u32 const TID_SHIFT = 16;
	u32 const OFFSET_DW_MASK = 0xffffu;
	u32 ret;

	ret = kver | tid_ctrl | (((u32) tid & TID_MASK) << TID_SHIFT) | (offset_dw & OFFSET_DW_MASK);
	return ret;
}

static inline u32 hfi2_dms_tid_info_update_tid(u32 tid_info, u16 tid)
{
	u32 const TID_MASK = 0x3ffu;
	u32 const TID_SHIFT = 16;

	// Clear the old TID
	tid_info &= ~(TID_MASK << TID_SHIFT);
	// Set the new TID
	tid_info |= ((u32) tid & TID_MASK) << TID_SHIFT;

	return tid_info;
}

/**
 * Sets the RX-ID in the DestQP field of the BTH for a KDETH packet
 * bth should be the start of the bth header field. Packets are routed
 * to this receive context when there are no RSM rule matches.
 */
static inline void _dms_destqp_rx_set(u32 *bth, u16 rx_id)
{
	bth[1] = (bth[1] & ~(0xffu << 24)) | (u32) (rx_id << 24); // Set RX QP prefix
}

/**
 * Sets the RX ID of the context data should be returned to.
 * This is used in the protocol messages e.g. READ_START
 * bth should be the start of the bth header field
 */
static inline void _dms_return_rx_set(u32 *bth, u16 rx_id)
{
	bth[0] = (bth[0] & ~(0xffu << 24)) | (u32) (rx_id << 24);
}

static inline u16 _dms_return_rx_get(u32 *bth)
{
	return bth[0] >> 24;
}

/*
 * DATA_START_EAGER carries its inline payload byte count in BTH[2] bits 15:0.
 * The field is unused by every other DATA_START.
 */
static inline void _dms_data_start_eager_nbytes_set(u32 *bth, u16 nbytes)
{
	bth[2] = nbytes;
}

static inline u16 _dms_data_start_eager_nbytes_get(u32 *bth)
{
	return bth[2] & 0xffff;
}

/* A peer's lane selector (DST: bits 26:24, SRC: bits 29:27) into a packet. */
static inline void _dms_lane_sel_set(u32 *bth, u32 peer)
{
	u32 const dst = (peer >> HFI2_DMS_LANE_SEL_PEER_SHIFT) &
			HFI2_DMS_LANE_SEL_MASK;
	u32 const src = (peer >> HFI2_DMS_LANE_SEL_PEER_SRC_SHIFT) &
			HFI2_DMS_LANE_SEL_MASK;

	bth[1] = (bth[1] & ~HFI2_DMS_LANE_SEL_BTH_MASK) |
		 (src << HFI2_DMS_LANE_SEL_SRC_SHIFT) | dst;
}

/*
 * Peer of a received control packet: SLID plus the lane selector of the
 * replies.  The replies go to the sender's lane (reply DST = received SRC)
 * and name the received DST as their SRC.  The received DST is echoed, not
 * this lane's index: a verbs DST may exceed this host's lane count, as the
 * RSM rule maps DST to lane DST % num_lanes.
 */
static inline u32 _dms_peer_get(union hfi2_dms_16b_header *hdr)
{
	u32 const dst = hdr->bth[1] & HFI2_DMS_LANE_SEL_MASK;
	u32 const src = (hdr->bth[1] >> HFI2_DMS_LANE_SEL_SRC_SHIFT) &
			HFI2_DMS_LANE_SEL_MASK;

	return hfi2_dms_lrh16B_slid_get((u32 *)&hdr->lrh[0]) |
	       (src << HFI2_DMS_LANE_SEL_PEER_SHIFT) |
	       (dst << HFI2_DMS_LANE_SEL_PEER_SRC_SHIFT);
}

/*
 * Peer of an initiator tracker: DST = target lane T (from @submit_flags,
 * else this lane), SRC = this lane.  The target's replies decode (see
 * _dms_peer_get()) to the same value, the tracker's peer identity.
 */
static inline u32 _dms_initiator_peer(struct hfi2_dms *dms, u32 lid,
				      u64 submit_flags)
{
	u32 const lane = dms->lane & HFI2_DMS_LANE_SEL_MASK;
	u32 dst = lane;

	if (submit_flags & HFI2_DMS_SUBMIT_TARGET_LANE)
		dst = (submit_flags >> HFI2_DMS_SUBMIT_TARGET_LANE_SHIFT) &
		      HFI2_DMS_LANE_SEL_MASK;
	return (lid & PBC_DLID_MASK) |
	       (dst << HFI2_DMS_LANE_SEL_PEER_SHIFT) |
	       (lane << HFI2_DMS_LANE_SEL_PEER_SRC_SHIFT);
}

/**
 * _sctxt_is_active - Check if a port's send context is active and usable
 *
 * Returns true if the send context is enabled.
 */
static inline bool _sctxt_is_active(struct send_context *sc)
{
	return sc && (sc->flags & SCF_ENABLED);
}

static u8 _pbc_port_idx_get(u64 pbc);

void hfi2_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid);
void hfi2_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid);
void hfi2_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws);
static u64 hfi2_dms_impl_pbc_template_create_16Bc(u8 port_idx, u32 dw_len, u16 sctxt);
void hfi2_dms_impl_lrh16bc_entropy_set(u64 *lrh16bc, u16 entropy);
static void hfi2_dms_impl_lrh16bc_rc_set(u64 *lrh16bc, u8 rc);


// Context and CSR utility functions
static void _configure_send_ctxt(struct hfi2_dms *dms, u8 pidx, struct send_context *sc);
static void _clone_send_ctxt_to_loopback(struct hfi2_dms *dms, u8 fabric_pidx,
					 struct send_context *sc);
/* Clones the relevant per-port per-context configuration from the source iprc csr
 * to all other available ports' corresponding iprc csrs.
 */
static void _clone_rcd_config(struct hfi2_dms *dms, u8 src_pidx, struct hfi2_ctxtdata *rcd);
static void _configure_ctrl_rcd(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd);
static void _configure_data_rcd(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd);

static void _dms_rcv_context_disable9B(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd);
/* Sets the header/payload split point (KDETH size in DWs) for a particular RCD */
static void _set_split_point(struct hfi2_dms *dms, u8 pidx,
			     struct hfi2_ctxtdata *rcd, u64 hdr_size);

// Data structure functions
int hfi2_dms_impl_work_item_block_alloc(struct hfi2_dms *dms);
void hfi2_dms_impl_work_item_block_free(struct hfi2_dms *dms);
struct hfi2_dms_work_item *hfi2_dms_impl_work_item_new(struct hfi2_dms *dms);
void hfi2_dms_impl_work_item_free(struct hfi2_dms *dms, struct hfi2_dms_work_item *item);
int hfi2_dms_impl_tracker_block_alloc(struct hfi2_dms *dms);
void hfi2_dms_impl_tracker_block_free(struct hfi2_dms *dms);
static int hfi2_dms_impl_ahg_header_block_alloc(struct hfi2_dms *dms, u8 port_idx);
void hfi2_dms_impl_ahg_header_block_free(struct hfi2_dms *dms);

static int hfi2_dms_access_block_new(struct hfi2_dms *dms);
static struct hfi2_dms_access *hfi2_dms_access_freelist_pop(struct hfi2_dms *dms);

static struct hfi2_dms_sdma_tracker *_sdma_tracker_new(struct hfi2_dms *dms, u8 port_idx, hfi2_dms_sdma_inject_fn inject,
		struct hfi2_dms_sdma_info const *info, u64 xfer_bytes);

union hfi2_dms_tracker *hfi2_dms_impl_tracker_new(struct hfi2_dms *dms, u8 port_idx,
		hfi2_dms_rift_key_t remote_rift_key, u32 remote_lid, u64 order_key,
		enum hfi2_dms_xfer_type type, enum hfi2_dms_xfer_op op);
struct hfi2_dms_rx_tracker *hfi2_dms_impl_rx_tracker_read_new(struct hfi2_dms *dms,
							   u8 port_idx, u32 size,
							   u64 starting_sbuf_offset, union hfi2_dms_key dms_key,
							   u32 src_lid,
							   struct hfi2_dms_page_provider page_provider,
							   u64 rbuf_offset, u16 flags, u64 submit_flags, u64 imm_data,
							   struct hfi2_dms_completion const *completion,
							   u64 order_key);
void hfi2_dms_impl_tracker_recycle(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker);

struct hfi2_dms_tx_tracker *hfi2_dms_impl_tx_tracker_write_new(struct hfi2_dms *dms, u8 port_idx, u32 size,
		u64 byte_offset_from_first_page, u32 remote_lid,
		struct hfi2_dms_page_provider page_provider, u64 mr_offset,
		u16 flags, u64 submit_flags, u64 imm_data,
		struct hfi2_dms_completion const *completion,
		union hfi2_dms_key rx_dms_key, u64 rx_offset, u64 order_key);

static struct hfi2_dms_ahg_header_set *
hfi2_dms_impl_ahg_header_set_get(struct hfi2_dms *dms, u8 port_idx);
static int _page_pool_init(struct hfi2_dms *dms);
static int _page_block_alloc(struct hfi2_dms *dms, bool setup);
static void _page_block_free(struct hfi2_dms *dms);
static int _tidset_bounce_backing_init(struct hfi2_dms *dms);
static void _tidset_bounce_backing_uninit(struct hfi2_dms *dms);
static int _tidset_bounce_scatter(struct hfi2_dms *dms, u32 tid_set,
				  struct hfi2_dms_rx_tracker *rx_tracker);
static void _tidset_bounce_attach(struct hfi2_dms *dms, u32 tid_set);
static void _tidset_bounce_detach(struct hfi2_dms *dms, u32 tid_set);
static int hfi2_dms_impl_sdma_send(struct hfi2_dms *dms,
			    enum hfi2_dms_sdma_engine_idx const engine_idx,
			    u64 page_offset,
			    struct hfi2_dms_recv_chunk const *chunks, u8 nchunks,
			    struct hfi2_dms_gather const *gather,
			    u8 port_idx, u32 dlid, u8 rx_id,
			    hfi2_dms_rift_key_t tx_rift_key,
			    u16 generation,
			    struct hfi2_dms_page_provider const *src_provider,
			    u16 entropy, enum hfi2_dms_msg_type msg_type,
			    u64 order_key);

void hfi2_dms_impl_dlist_init(struct hfi2_dms_dlist *dlist);
bool hfi2_dms_impl_dlist_empty(struct hfi2_dms_dlist *dlist);
struct hfi2_dms_dlist_element *hfi2_dms_impl_dlist_pop(struct hfi2_dms_dlist *dlist);
void hfi2_dms_impl_dlist_push(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element);
void hfi2_dms_impl_dlist_append(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element);
void hfi2_dms_impl_dlist_remove(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element);

int _tidset_idx_peek(struct hfi2_dms *dms, u32 *tid_set);
void _tidset_idx_reserve(struct hfi2_dms *dms, u32 tid_set);
void _tidset_idx_release(struct hfi2_dms *dms, u32 tid_set);

static void _tidset_reset(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_tidset_state new_state);
int _tidset_enable(struct hfi2_dms *dms, u32 tid_set, struct hfi2_dms_rx_tracker *rx_tracker, u32 *tid_info, u64 *tidset_nbytes);
u32 _tidset_free_count(struct hfi2_dms *dms);

// protocol message creation functions
void hfi2_dms_impl_fill_proto_templates(struct hfi2_dms *dms);
int hfi2_dms_impl_16bc_state_set(struct hfi2_dms *dms);

u32 hfi2_dms_impl_data_request_size_qw_get(union hfi2_dms_16b_header *hdr);

// protocol functions
int hfi2_dms_impl_make_data_request(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *tracker, u32 tid_set);
void hfi2_dms_rx_tracker_handle_completion(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int status, u32 do_ack);
static void hfi2_dms_impl_handle_read_start_packet(struct hfi2_dms *dms, u8 rcv_port,
						   union hfi2_dms_16b_header *hdr,
						   void *ebuf, bool speculative);
int hfi2_dms_impl_handle_read_start(struct hfi2_dms *dms,
		struct hfi2_dms_read_start_metadata const *metadata,
		struct hfi2_dms_read_start_parameters const *parameters,
		void const *arrays);

// protocol packet handling functions
static int _poll_ctrl_rcd(struct hfi2_dms *dms, u32 budget);
static int _poll_data_rcd(struct hfi2_dms *dms, u32 budget);
static void _noop_handle_packet(struct hfi2_packet *packet);

static int hfi2_dms_impl_handle_data_request_packet(struct hfi2_dms *dms,
						    union hfi2_dms_16b_header *hdr, void *ebuf);
void hfi2_dms_impl_handle_ack(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr, enum hfi2_dms_msg_type const type);

static void hfi2_dms_handle_data_start_packet(struct hfi2_dms *dms, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf);
static void hfi2_dms_handle_data_start(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr,
				       bool eager, void *ebuf, u32 const eager_nbytes);
static void _hfi2_dms_handle_data_common(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr,
					 bool speculative);
static void hfi2_dms_handle_data(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr);
static void hfi2_dms_handle_data_speculative(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr);

static void hfi2_dms_impl_handle_write_start_packet(struct hfi2_dms *dms, u8 rcv_port, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf);
static void hfi2_dms_impl_handle_write_start_tiny_packet(struct hfi2_dms *dms, u8 rcv_port,
							 union hfi2_dms_16b_header *hdr);
int hfi2_dms_impl_handle_write_start(struct hfi2_dms *dms,
		struct hfi2_dms_write_start_metadata const *metadata,
		struct hfi2_dms_write_start_parameters const *parameters,
		void *hbuf, void *ebuf, u32 const eager_nbytes);
void hfi2_dms_impl_handle_nack_packet(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr);
void hfi2_dms_impl_handle_status_response_packet(struct hfi2_dms *dms, u8 rcv_port, union hfi2_dms_16b_header *hdr);
void hfi2_dms_impl_handle_status_request_packet(struct hfi2_dms *dms, u8 rcv_port, union hfi2_dms_16b_header *hdr);

// PIO functions - note: these should only be used in bulksvc/dms or similar.
// the assumption here is only one thread is controlling the PIO buffers at any given time

u64 hfi2_dms_impl_pbc_length_dws_get(u64 pbc);

int calculate_access_mr_page_offset(struct hfi2_dms *dms, struct hfi2_dms_access *access, u64 offset, u32 size, u64 *page_offset);
int calculate_mr_page_offset(struct hfi2_dms *dms, struct hfi2_dms_mr * mr, u64 offset, u32 size, u64 *page_offset);

static void hfi2_dms_rx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int err);
void hfi2_dms_tx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_tx_tracker *tx_tracker, int err);
static void _tracker_cancel(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, int err);

static hfi2_dms_rift_key_t _rift_key_create_err(enum hfi2_dms_rift_err const err);
static u16 _rift_key_index(hfi2_dms_rift_key_t const key);
static u16 _rift_key_generation(hfi2_dms_rift_key_t const key);
static enum hfi2_dms_xfer_type _rift_key_type(hfi2_dms_rift_key_t const key);
static enum hfi2_dms_rift_err _rift_key_error(hfi2_dms_rift_key_t const key);
static enum hfi2_dms_xfer_type _rift_key_type_opposite(hfi2_dms_rift_key_t const key);

static void access_xfer_end(struct hfi2_dms *dms, struct hfi2_dms_access *access,
			    union hfi2_dms_tracker *tracker,
			    u16 flags, u64 imm_data, u64 order_key, int status);

void _rift_init(struct hfi2_dms_rift * rift);
static union hfi2_dms_tracker *_rift_search(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const remote_rift_key, u32 const remote_lid);
bool _rift_available(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type const t, enum hfi2_dms_xfer_side const s);
static int _rift_reserve(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type const t, enum hfi2_dms_xfer_side const s, hfi2_dms_rift_key_t *key);
static void _rift_assign(struct hfi2_dms_rift *rift, union hfi2_dms_tracker *tracker, hfi2_dms_rift_key_t const key);
static union hfi2_dms_tracker *_rift_lookup(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key);
static void _rift_release(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key);
static void _rift_cancel(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key);
static void _rift_waitlist_add(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type t, enum hfi2_dms_xfer_side s, struct hfi2_dms_dlist_element *waiter);
static struct hfi2_dms_dlist_element *_rift_waitlist_peek(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type t, enum hfi2_dms_xfer_side s);
static int _rift_allocate(struct hfi2_dms_rift *rift, union hfi2_dms_tracker *tracker);
static void _dms_rift_poll(struct hfi2_dms *dms);
static void _dms_rift_poll_request(struct hfi2_dms *dms);

static void _tidset_waiter_enqueue(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker);
static void _tidset_waiter_remove(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker);
static void _service_global_tidset_waiters(struct hfi2_dms *dms);

void _ring_init(struct hfi2_dms_ring *ring, u32 arr_size_lg2, u32 max_size);
u32 _ring_size(struct hfi2_dms_ring *ring);
static u32 _ring_free(struct hfi2_dms_ring *ring);
static u32 _ring_produce(struct hfi2_dms_ring *ring);
u32 _ring_consume(struct hfi2_dms_ring *ring);

void _rift_keyring_init(struct hfi2_dms_rift_keyring *keyring);
void _rift_keyring_add(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key);
void _rift_keyring_add_front(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key);
u64 _rift_keyring_size(struct hfi2_dms_rift_keyring *keyring);
bool _rift_keyring_empty(struct hfi2_dms_rift_keyring *keyring);
hfi2_dms_rift_key_t _rift_keyring_tail(struct hfi2_dms_rift_keyring *keyring);
hfi2_dms_rift_key_t _rift_keyring_head(struct hfi2_dms_rift_keyring *keyring);
hfi2_dms_rift_key_t _rift_keyring_peek(struct hfi2_dms_rift_keyring *keyring);
hfi2_dms_rift_key_t _rift_keyring_at(struct hfi2_dms_rift_keyring *keyring, u32 pos);
void _rift_keyring_set(struct hfi2_dms_rift_keyring *keyring, u64 pos, hfi2_dms_rift_key_t const key);
void _rift_keyring_advance(struct hfi2_dms_rift_keyring *keyring);
bool _rift_keyring_remove(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key);


static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_pop(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx);
static void _sdma_engine_waitlist_discard(struct hfi2_dms *dms,
					  enum hfi2_dms_sdma_engine_idx const engine_idx);
static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_peek(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx);
static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_next(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx);
static void _sdma_engine_waitlist_append(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx, struct hfi2_dms_sdma_tracker *waiter);
static int _sdma_engine_waitlist_add(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx, hfi2_dms_sdma_inject_fn inject, struct hfi2_dms_sdma_info const *info, u64 xfer_bytes, struct hfi2_dms_tx_tracker *tx_tracker);
static void _sdma_engine_waitlist_poll(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx);
static int _sdma_inject_req_fn(struct hfi2_dms *dms,
			       enum hfi2_dms_sdma_engine_idx const engine_idx,
			       struct hfi2_dms_sdma_req const *req,
			       struct hfi2_dms_tx_tracker *tx_tracker);
static void _sdma_req_chunk_info(struct hfi2_dms_sdma_req const *req, u8 i,
				 u8 first_gather,
				 struct hfi2_dms_tx_tracker const *tx_tracker,
				 struct hfi2_dms_sdma_info *info);
static int _sdma_tracker_new_per_chunk(struct hfi2_dms *dms,
				       enum hfi2_dms_sdma_engine_idx const engine_idx,
				       struct hfi2_dms_sdma_tracker *waiter);
static void _sdma_engine_waitlist_poll_all(struct hfi2_dms *dms);

static int _pio_waitlist_initialize(struct hfi2_dms *dms);
static void _pio_waitlist_finalize(struct hfi2_dms *dms);
static int _pio_waitlist_poll(struct hfi2_dms *dms);
static bool _pio_waitlist_empty(struct hfi2_dms *dms);
static int _pio_waitlist_append_pkt(struct hfi2_dms *dms, const u64 *hdr,
				    u32 hdr_qws, u32 copy_qws,
				    struct hfi2_dms_page_provider const *pp,
				    u64 byte_offset, u32 nbytes, u32 trail_qws,
				    struct hfi2_dms_transfer_handle handle);
static int _pio_waitlist_append_ulp(struct hfi2_dms *dms, u64 pbc,
				    const struct hfi2_dms_ulp_iov *iov,
				    u32 niov);

static int _inject_cmd_pio(struct hfi2_dms *dms, union hfi2_dms_proto_cmd *cmd,
			   struct hfi2_dms_transfer_handle handle, bool via_waitlist);
static int hfi2_dms_impl_pio_sendv(struct hfi2_dms *dms, u64 pbc,
				   const struct hfi2_dms_ulp_iov *iov,
				   u32 niov, bool tail_flit);
static __always_inline int
_pio_pkt_send(struct hfi2_dms *dms, const u64 *hdr, u32 hdr_qws,
	      struct hfi2_dms_page_provider const *pp, u64 byte_offset,
	      u32 nbytes, u32 trail_qws);
int _inject_cmd_sdma(struct hfi2_dms *dms, union hfi2_dms_proto_cmd * cmd, enum hfi2_dms_sdma_engine_idx const engine_idx);

static u32
hfi2_dms_cmd_data_request_stage(struct hfi2_dms *dms, union _pkt_cmd *cmd,
				u8 port_idx,
				struct hfi2_dms_read_request_chunks const *rc,
				hfi2_dms_rift_key_t tx_rift_key, hfi2_dms_rift_key_t rx_rift_key,
				u32 src_lid, u32 read_size_qw,
				u16 generation, u16 entropy, u64 order_key, u8 flags,
				enum hfi2_dms_msg_type msg_type);
static u16 _dms_entropy_next(struct hfi2_dms *dms);
static enum hfi2_dms_sdma_engine_idx _dms_sdma_engine_idx_from_entropy(struct hfi2_dms *dms,
								       u16 entropy);
static void _chain_signal_last_engine(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker);
static void _dms_write_signal_pio_release(struct hfi2_dms *dms,
					  struct hfi2_dms_tx_tracker *tx_tracker);
static void _chain_signal_final_data_request(struct hfi2_dms *dms,
					     struct hfi2_dms_rx_tracker *rx_tracker);
static void _dms_rx_tracker_tidset_inflight_set(struct hfi2_dms_rx_tracker *rx_tracker,
						u32 const tidset_idx);
static void _dms_rx_tracker_tidset_inflight_clear(struct hfi2_dms_rx_tracker *rx_tracker,
						  u32 const tidset_idx);
static int
hfi2_dms_impl_handle_data_request(struct hfi2_dms *dms,
				  struct hfi2_dms_data_request_metadata const *metadata,
				  struct hfi2_dms_data_request_parameters const *parameters,
				  struct hfi2_dms_recv_chunk const *chunks,
				  u8 nchunks,
				  struct hfi2_dms_gather const *gather,
				  u8 ngather);
static void _tx_serve_tidset_request(struct hfi2_dms *dms,
				     struct hfi2_dms_tx_tracker *tx_tracker,
				     u8 rx_id, u16 generation, u16 entropy,
				     u8 flags, enum hfi2_dms_msg_type data_msg_type,
				     struct hfi2_dms_recv_chunk const *chunks,
				     u8 nchunks,
				     struct hfi2_dms_gather const *gather,
				     u8 ngather);

static int _inject_data_request(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_msg_type msg_type);
static int _inject_data_request_replay(struct hfi2_dms *dms, u32 tid_set);

static int _dms_rx_rift_continue_write_start(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, void *hbuf, void *ebuf, u32 const eager_nbytes);
static int _dms_tx_rift_continue_read_start(struct hfi2_dms *dms,
					    struct hfi2_dms_tx_tracker *tx_tracker,
					    void const *arrays);
static int _dms_tx_rift_continue_write_data(struct hfi2_dms *dms, struct hfi2_dms_tx_tracker *tx_tracker);
static int _dms_rx_rift_continue_read_data(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker);
static int _chain_resume_read_at_data_start(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker);
static void _dms_rx_issue_data_request_burst(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, bool deferred);

static void _tracker_health_state_set(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, enum hfi2_dms_tracker_health_state state);


static struct hfi2_dms_cancel_cache_lid_node *_cancel_cache_rb_search(struct rb_root *root, u32 remote_lid);
static int _cancel_cache_rb_insert(struct rb_root *root, struct hfi2_dms_cancel_cache_lid_node *lid_node);
static struct hfi2_dms_cancel_cache_lid_node *_cancel_cache_lid_node_alloc(struct hfi2_dms *dms, u32 remote_lid);
static void _cancel_cache_lid_node_free(struct hfi2_dms *dms, struct hfi2_dms_cancel_cache_lid_node *lid_node);
static void _cancel_cache_add(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key, int err);
static struct hfi2_dms_cancel_cache_entry *_cancel_cache_find(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key);
static void _cancel_cache_remove(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key);
static void _cancel_cache_age(struct hfi2_dms *dms, ktime_t now);

/* We no longer use the RCD vtable for handling
 * DMS packets as they arrive. So set this all to _noop_handle_packet
 * just in case
 */
static const rhf_rcv_function_ptr _dms_rhf_rcv_functions_data[] = {
	[RHF_RCV_TYPE_EAGER] = _noop_handle_packet,
	[RHF_RCV_TYPE_EXPECTED] = _noop_handle_packet,
	[RHF_RCV_TYPE_ERROR] = _noop_handle_packet,
	[RHF_RCV_TYPE_BYPASS] = _noop_handle_packet,

	[RHF_RCV_TYPE_IB] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID5] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID6] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID7] = _noop_handle_packet,
};

static const rhf_rcv_function_ptr _dms_rhf_rcv_functions_ctrl[] = {
	[RHF_RCV_TYPE_EAGER] = _noop_handle_packet,
	[RHF_RCV_TYPE_EXPECTED] = _noop_handle_packet,
	[RHF_RCV_TYPE_ERROR] = _noop_handle_packet,
	[RHF_RCV_TYPE_BYPASS] = _noop_handle_packet,

	[RHF_RCV_TYPE_IB] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID5] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID6] = _noop_handle_packet,
	[RHF_RCV_TYPE_INVALID7] = _noop_handle_packet,
};

int hfi2_dms_common_init(struct hfi2_dms *dms, struct hfi2_devdata *dd,
			 struct sdma_engine **sdma_engines, int num_engines,
			 int port_idx, struct send_context *port_sctxt)
{
	int ret;

	if (!dms || !dd || !sdma_engines || num_engines <= 0 ||
	    num_engines > TXE_NUM_SDMA_ENGINES || port_idx < -1 ||
	    port_idx >= HFI2_DMS_MAX_PORTS ||
	    (port_idx >= 0 &&
	     (port_idx >= dd->num_pports || !port_sctxt ||
	      port_sctxt->ppd != &dd->pport[port_idx])))
		return -EINVAL;
	if (dms->common_initialized)
		return -EALREADY;

	*dms = (struct hfi2_dms){0};
	dms->dd = dd;
	dms->numa_node = dev_to_node(&dd->pcidev->dev);
	dms->chip_type = dd->params->chip_type;
	dms->sdma_engines = sdma_engines;
	dms->num_engines = num_engines;
	dms->common_initialized = true;

	if (port_idx >= 0) {
		dms->port_available[port_idx] = true;
		dms->port_sctxts[port_idx] = port_sctxt;
	}

	dms->sde_rsrcs = kcalloc_node(num_engines,
				      sizeof(*dms->sde_rsrcs), GFP_KERNEL,
				      dms->numa_node);
	if (!dms->sde_rsrcs) {
		ret = -ENOMEM;
		goto bail;
	}

	ret = hfi2_dms_sdma_setup(dms);
	if (ret)
		goto bail;

	ret = _page_pool_init(dms);
	if (ret)
		goto bail;

	dms->zero_page.kvaddr = dma_alloc_coherent(&dd->pcidev->dev, PAGE_SIZE,
					       &dms->zero_page.phys_addr,
					       GFP_KERNEL);
	if (!dms->zero_page.kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}
	memset(dms->zero_page.kvaddr, 0, PAGE_SIZE);
	dms->zero_page.len = PAGE_SIZE;

	for (int i = 0; i < num_engines; ++i)
		hfi2_sdma_disable_gen_check(dms, dms->sdma_engines[i]);

	return 0;

bail:
	hfi2_dms_common_uninit(dms);
	return ret;
}

void hfi2_dms_common_uninit(struct hfi2_dms *dms)
{
	struct hfi2_devdata *dd;

	if (!dms || !dms->common_initialized)
		return;

	dd = dms->dd;
	hfi2_dms_sdma_destroy(dms);
	_page_block_free(dms);

	if (dms->zero_page.kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
				  dms->zero_page.kvaddr,
				  dms->zero_page.phys_addr);
		dms->zero_page.kvaddr = NULL;
		dms->zero_page.phys_addr = 0;
		dms->zero_page.len = 0;
	}

	kfree(dms->sde_rsrcs);
	dms->sde_rsrcs = NULL;
	dms->sdma_engines = NULL;
	dms->num_engines = 0;
	memset(dms->port_sctxts, 0, sizeof(dms->port_sctxts));
	memset(dms->port_available, 0, sizeof(dms->port_available));
	dms->common_initialized = false;
}

/*
 * @lane selects this DMS's receive contexts: bulksvc rcd[2 * lane] (ctrl)
 * and rcd[2 * lane + 1] (data) of each port.
 */
int hfi2_dms_init(struct hfi2_dms *dms, struct hfi2_devdata *dd,
		  struct hfi2_bulksvc_pp_rsrc *pp_rsrc, int num_ports,
		  struct sdma_engine **sdma_engines, int num_engines, u32 lane)
{
	u32 const rcd_ctrl_idx = 2 * lane;
	u32 const rcd_data_idx = rcd_ctrl_idx + 1;
	struct hfi2_dms_access *access = NULL;
	struct hfi2_ctxtdata *rcds[2];
	struct hfi2_pportdata *ppd;
	int rcd_pidxs[2];
	int num_rcds = 0;
	int ports_initialized = 0;
	int ret = 0;
	s32 max_tid_set_idx;
	int i;

	HFI2_DMS_READ_REQUEST_STATE_SIZE_CHECK();
	_pkt_cmd_layout_check();
	_read_start_layout_check();
	_data_request_layout_check();

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(dd == NULL);
	DMS_BUG_ON(!pp_rsrc);
	DMS_BUG_ON(num_ports <= 0);
	DMS_BUG_ON(sdma_engines == NULL);
	DMS_BUG_ON(num_engines <= 0);
	DMS_BUG_ON(num_engines > TXE_NUM_SDMA_ENGINES);

	ret = hfi2_dms_common_init(dms, dd, sdma_engines, num_engines,
				   -1, NULL);
	if (ret)
		return ret;
	dms->lane = lane;
	_dms_health_init(dms);

	/* Receive contexts can receive from any port
	 * if configured properly so we only need
	 * 2 max. Send contexts we need 1 per port
	 * because we use compressed 16B headers
	 * which uses SendCtxtCheckSlid to determine
	 * the slid to use in the 16B header and
	 * each port has a different lid
	 */
	for (i = 0; i < num_ports; ++i) {
		struct send_context *sc;

		ppd = &dd->pport[i];

		if (!port_available_ppd(ppd))
			continue;

		if (WARN_ON(ppd->hw_pidx != i))
			continue;

		if (pp_rsrc[i].rcd_len <= rcd_ctrl_idx)
			continue;

		sc = pp_rsrc[i].rcd[rcd_ctrl_idx]->sc;

		if (num_rcds < 2) {
			rcds[num_rcds] = pp_rsrc[i].rcd[rcd_ctrl_idx];
			rcd_pidxs[num_rcds] = i;
			num_rcds++;

			if (num_rcds < 2 && pp_rsrc[i].rcd_len > rcd_data_idx) {
				rcds[num_rcds] = pp_rsrc[i].rcd[rcd_data_idx];
				rcd_pidxs[num_rcds] = i;
				num_rcds++;
			}
		}

		dms->port_available[i] = true;
		dms->port_sctxts[i] = sc;
		ports_initialized++;
	}

	/* Enable loopback ports — reuse fabric port's send context */
	for (i = 0; i < dd->num_pports; ++i) {
		u8 lb_pidx = loopback_pidx_dd(dd, i);

		if (!dms->port_available[i])
			continue;
		dms->port_available[lb_pidx] = true;
		dms->port_sctxts[lb_pidx] = dms->port_sctxts[i];
	}

	if (ports_initialized == 0) {
		dd_dev_warn(dd, "dms: No ports with RCD contexts provided\n");
		ret = -ENODEV;
		goto bail;
	}

	if (num_rcds < 2) {
		dd_dev_warn(dd, "dms: Not enough RCD contexts provided: found %d, need 2\n", num_rcds);
		ret = -EINVAL;
		goto bail;
	}

	for (i = 0; i < dd->num_pports; ++i) {
		if (!dms->port_available[i])
			continue;
		_configure_send_ctxt(dms, i, dms->port_sctxts[i]);
	}
	_configure_ctrl_rcd(dms, rcd_pidxs[0], rcds[0]);
	_configure_data_rcd(dms, rcd_pidxs[1], rcds[1]);

	for (i = 0; i < dd->num_pports; ++i) {
		if (!dms->port_available[i])
			continue;
		_clone_send_ctxt_to_loopback(dms, i, dms->port_sctxts[i]);
	}

	dms->rcd_ctrl = rcds[0];
	dms->rcd_data = rcds[1];

	max_tid_set_idx = (dms->rcd_data->expected_count / 2) / HFI2_DMS_TID_SET_SIZE;
	max_tid_set_idx = min(max_tid_set_idx, (s32)HFI2_DMS_TID_SET_IDX_COUNT);
	max_tid_set_idx = min(max_tid_set_idx, (s32)HFI2_DMS_ARRAY_SIZE(dms->read_requests));

	_ring_init(&dms->free_tidsets.ring,
		   const_ilog2(HFI2_DMS_TID_SET_IDX_COUNT) + 1, max_tid_set_idx);

	for (i = 0; i < max_tid_set_idx; ++i) {
		dms->free_tidsets.arr[_ring_produce(&dms->free_tidsets.ring)] = (u8)i;
		dms->read_requests[i].tid_set = i;
	}

	dms->spec_tidsets_available = max_tid_set_idx / 2;

	_rift_keyring_init(&dms->tidset_waiters);

	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		dms->protocol_cmd_templates[i] =
			kcalloc_node(HFI2_DMS_MSG_TYPE_COUNT,
				     sizeof(union hfi2_dms_proto_cmd),
				     GFP_KERNEL, dms->numa_node);
		if (!dms->protocol_cmd_templates[i]) {
			ret = -ENOMEM;
			goto bail;
		}
	}
	hfi2_dms_impl_fill_proto_templates(dms);

	// initialize a set of trackers
	if (hfi2_dms_impl_tracker_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	if (hfi2_dms_impl_work_item_block_alloc(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	dms->tx_zero_page.kvaddr = dma_alloc_coherent(&dd->pcidev->dev, PAGE_SIZE,
						      &dms->tx_zero_page.phys_addr,
						      GFP_KERNEL);
	if (!dms->tx_zero_page.kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}
	memset(dms->tx_zero_page.kvaddr, 0, PAGE_SIZE);
	dms->tx_zero_page.len = PAGE_SIZE;
	for (u32 i = 0; i < ARRAY_SIZE(dms->pad_desc_template); i++) {
		_sdma_qw_set_byte_count(&dms->pad_desc_template[i].qw[0], i + 1);
		_sdma_qw_set_phy_addr(&dms->pad_desc_template[i].qw[0],
				      dms->tx_zero_page.phys_addr);
	}

	dms->p2p_flush_page.kvaddr =
		dma_alloc_coherent(&dd->pcidev->dev, PAGE_SIZE,
				   &dms->p2p_flush_page.phys_addr, GFP_KERNEL);
	if (!dms->p2p_flush_page.kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}
	memset(dms->p2p_flush_page.kvaddr, 0, PAGE_SIZE);
	dms->p2p_flush_page.len = PAGE_SIZE;

	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		void *hdr = dms->p2p_flush_page.kvaddr +
			i * DMS_P2P_FLUSH_HDR_BYTES;
		dma_addr_t phys = dms->p2p_flush_page.phys_addr +
			i * DMS_P2P_FLUSH_HDR_BYTES;
		int len;

		if (hfi2_dms_impl_ahg_header_block_alloc(dms, i)) {
			ret = -ENOMEM;
			goto bail;
		}
		if (!dms->port_available[i] || !dd->pbc_test_bit)
			continue;
		len = hfi2_dms_ulp_build_pio_header(dms, i, 0xFFFFFF, 1, 0, 0,
						    hdr,
						    DMS_P2P_FLUSH_HDR_BYTES);
		if (WARN_ON_ONCE(len < 0))
			continue;
		*(u64 *)hdr |= dd->pbc_test_bit;
		_sdma_qw_set_byte_count(&dms->p2p_flush_sop_desc[i].qw[0],
					DMS_P2P_FLUSH_HDR_BYTES);
		_sdma_qw_set_phy_addr(&dms->p2p_flush_sop_desc[i].qw[0], phys);
		dms->p2p_flush_sop_desc[i].qw[1] |=
			HFI2_DMS_SDMA_DESC_TYPE_SOP;
	}

	/* pre-fill header and tail sdma descriptor templates */
	_sdma_qw_set_byte_count(&dms->header_desc_template.qw[0],
				sizeof(union hfi2_dms_proto_cmd_data));
	_sdma_qw_set_first_desc(&dms->header_desc_template.qw[0]);
	_sdma_qw_set_header_mode(&dms->header_desc_template.qw[0],
				 SDMA_AHG_NO_AHG);

	// tail flit
	_sdma_qw_set_byte_count(&dms->tail_desc_template.qw[0], sizeof(u64));
	_sdma_qw_set_phy_addr(&dms->tail_desc_template.qw[0],
			      dms->zero_page.phys_addr);
	_sdma_qw_set_last_desc(&dms->tail_desc_template.qw[0]);

	dms->desc_stack = kcalloc_node(HFI2_DMS_DESC_STACK_DESCS,
				       sizeof(struct sdma_desc),
				       GFP_KERNEL, dms->numa_node);
	if (!dms->desc_stack) {
		ret = -ENOMEM;
		goto bail;
	}
	dms->num_descs = HFI2_DMS_DESC_STACK_DESCS;

	dms->client_rbtree = RB_ROOT;

	if (hfi2_dms_access_block_new(dms)) {
		ret = -ENOMEM;
		goto bail;
	}

	_rift_init(&dms->rift);

	INIT_LIST_HEAD(&dms->access_deferred.active);
	INIT_LIST_HEAD(&dms->access_deferred.free);
	dms->access_deferred.count = 0;
	/*
	 * Hold every initiator key of a peer running HFI2_BULKSVC_MAX_LANES
	 * lanes; overflow is RNR NACKed and stalls that peer until its stale
	 * check.
	 */
	dms->access_deferred_pool_size = dms_access_deferred_max ?:
		max_t(uint, num_online_cpus(), HFI2_BULKSVC_MAX_LANES *
		      HFI2_DMS_RIFT_IDX_SIZE / HFI2_DMS_XFER_TYPE_COUNT);
	dms->access_deferred_pool = kvcalloc_node(dms->access_deferred_pool_size,
						  sizeof(*dms->access_deferred_pool),
						  GFP_KERNEL, dd->node);
	if (!dms->access_deferred_pool) {
		ret = -ENOMEM;
		goto bail;
	}
	for (i = 0; i < dms->access_deferred_pool_size; i++) {
		INIT_LIST_HEAD(&dms->access_deferred_pool[i].node);
		list_add_tail(&dms->access_deferred_pool[i].node,
			      &dms->access_deferred.free);
	}

	dms->disabled_rx_tracker.hdr.local_rift_key = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_DISABLED);
	dms->disabled_rx_tracker.hdr.remote_rift_key = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_DISABLED);
	dms->last_stale_check = ktime_get();

	dd_dev_warn(dms->dd, "DMS initialized with %d SDMA engines, %u deferred pool entries.\n",
		    num_engines, dms->access_deferred_pool_size);

	ret = _pio_waitlist_initialize(dms);
	if (ret)
		goto bail;

	dms->pio_scratch = kzalloc_node(HFI2_DMS_PIO_SCRATCH_SIZE, GFP_KERNEL, dms->numa_node);
	if (!dms->pio_scratch) {
		ret = -ENOMEM;
		goto bail;
	}

	dms->read_request_chunks = kcalloc_node(HFI2_DMS_TID_SET_IDX_COUNT,
						sizeof(*dms->read_request_chunks),
						GFP_KERNEL, dms->numa_node);
	if (!dms->read_request_chunks) {
		ret = -ENOMEM;
		goto bail;
	}

	ret = _tidset_bounce_backing_init(dms);
	if (ret)
		goto bail;

	dms->sdma_waiter_count = 0;

	dms->cancel_cache.active = RB_ROOT;
	hfi2_dms_impl_dlist_init(&dms->cancel_cache.freelist);
	dms->cancel_cache.total_count = 0;
	dms->cancel_cache.last_aging_time = ktime_get();

	_ring_init(&dms->counters.tidset.ring, 10, HFI2_DMS_ARRAY_SIZE(dms->counters.tidset.arr) - 2);

	return 0;

bail:
	INIT_LIST_HEAD(&dms->access_deferred.active);
	INIT_LIST_HEAD(&dms->access_deferred.free);
	dms->access_deferred.count = 0;
	dms->access_deferred_pool_size = 0;
	if (dms->access_deferred_pool) {
		kvfree(dms->access_deferred_pool);
		dms->access_deferred_pool = NULL;
	}
	while ((access = hfi2_dms_access_freelist_pop(dms))) {
		kfree(access);
	}

	hfi2_dms_impl_ahg_header_block_free(dms);

	if (dms->desc_stack) {
		kfree(dms->desc_stack);
		dms->desc_stack = NULL;
		dms->num_descs = 0;
	}

	if (dms->tx_zero_page.kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
				  dms->tx_zero_page.kvaddr,
				  dms->tx_zero_page.phys_addr);
		dms->tx_zero_page.kvaddr = NULL;
	}

	hfi2_dms_impl_work_item_block_free(dms);
	hfi2_dms_impl_tracker_block_free(dms);

	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		kfree(dms->protocol_cmd_templates[i]);
		dms->protocol_cmd_templates[i] = NULL;
	}

	kfree(dms->pio_scratch);
	dms->pio_scratch = NULL;
	kfree(dms->read_request_chunks);
	dms->read_request_chunks = NULL;
	_tidset_bounce_backing_uninit(dms);

	_pio_waitlist_finalize(dms);
	hfi2_dms_common_uninit(dms);

	if (dms->p2p_flush_page.kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
				  dms->p2p_flush_page.kvaddr,
				  dms->p2p_flush_page.phys_addr);
		dms->p2p_flush_page.kvaddr = NULL;
	}

	return ret;
}

static void _nack_log_flush(struct hfi2_dms *dms);

void hfi2_dms_uninit(struct hfi2_dms *dms)
{
	int i;

	DMS_BUG_ON(dms == NULL);

	list_splice_init(&dms->access_deferred.active, &dms->access_deferred.free);
	dms->access_deferred.count = 0;
	dms->access_deferred_pool_size = 0;
	kvfree(dms->access_deferred_pool);
	dms->access_deferred_pool = NULL;

	for (i = 0; i < dms->num_engines; ++i) {
		struct hfi2_dms_sde_rsrc *rsrc = &dms->sde_rsrcs[i];
		while (rsrc->active_ahg_headers.head != NULL) {
			hfi2_dms_impl_dlist_pop(&rsrc->active_ahg_headers);
			// don't bother pushing on free list we're about to free all the blocks
		}
	}

	for (s32 i = 0; i < dms->num_engines; ++i) {
		enum hfi2_dms_sdma_engine_idx const idx = i;

		_sdma_engine_waitlist_discard(dms, idx);
	}
	_sdma_engine_waitlist_discard(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY);

	hfi2_dms_sdma_destroy(dms);
	hfi2_dms_impl_work_item_block_free(dms);
	hfi2_dms_impl_ahg_header_block_free(dms);

	if (dms->tx_zero_page.kvaddr) {
		dma_free_coherent(&dms->dd->pcidev->dev, PAGE_SIZE,
				  dms->tx_zero_page.kvaddr,
				  dms->tx_zero_page.phys_addr);
		dms->tx_zero_page.kvaddr = NULL;
		dms->tx_zero_page.phys_addr = 0;
		dms->tx_zero_page.len = 0;
	}
	if (dms->p2p_flush_page.kvaddr) {
		dma_free_coherent(&dms->dd->pcidev->dev, PAGE_SIZE,
				  dms->p2p_flush_page.kvaddr,
				  dms->p2p_flush_page.phys_addr);
		dms->p2p_flush_page.kvaddr = NULL;
		dms->p2p_flush_page.phys_addr = 0;
		dms->p2p_flush_page.len = 0;
	}

	kfree(dms->desc_stack);
	dms->desc_stack = NULL;
	kfree(dms->pio_scratch);
	dms->pio_scratch = NULL;
	kfree(dms->read_request_chunks);
	dms->read_request_chunks = NULL;
	_tidset_bounce_backing_uninit(dms);
	hfi2_dms_impl_tracker_block_free(dms);

	struct hfi2_dms_access *access = NULL;
	while ((access = hfi2_dms_access_freelist_pop(dms))) {
		kfree(access);
	}

	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		kfree(dms->protocol_cmd_templates[i]);
		dms->protocol_cmd_templates[i] = NULL;
	}

	/* Free all active cancel cache LID nodes */
	while (!RB_EMPTY_ROOT(&dms->cancel_cache.active)) {
		struct rb_node *rb_node = rb_first(&dms->cancel_cache.active);
		struct hfi2_dms_cancel_cache_lid_node *lid_node =
			rb_entry(rb_node, struct hfi2_dms_cancel_cache_lid_node, rb_node);
		rb_erase(rb_node, &dms->cancel_cache.active);
		kfree(lid_node);
	}

	/* Free all cancel cache LID nodes on freelist */
	while (dms->cancel_cache.freelist.head) {
		struct hfi2_dms_dlist_element *element = hfi2_dms_impl_dlist_pop(&dms->cancel_cache.freelist);
		struct hfi2_dms_cancel_cache_lid_node *lid_node =
			container_of(element, struct hfi2_dms_cancel_cache_lid_node, dlist);
		kfree(lid_node);
	}
	_pio_waitlist_finalize(dms);

	_nack_log_flush(dms);

	if (dms->dd)
		dd_dev_warn(dms->dd, "DMS uninitialized successfully.\n");
	hfi2_dms_common_uninit(dms);
}

static struct hfi2_dms_cancel_cache_lid_node *_cancel_cache_rb_search(struct rb_root *root, u32 remote_lid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct hfi2_dms_cancel_cache_lid_node *lid_node =
			container_of(node, struct hfi2_dms_cancel_cache_lid_node, rb_node);

		if (remote_lid < lid_node->remote_lid)
			node = node->rb_left;
		else if (remote_lid > lid_node->remote_lid)
			node = node->rb_right;
		else
			return lid_node;
	}

	return NULL;
}

static int _cancel_cache_rb_insert(struct rb_root *root, struct hfi2_dms_cancel_cache_lid_node *lid_node)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	while (*new) {
		struct hfi2_dms_cancel_cache_lid_node *this =
			container_of(*new, struct hfi2_dms_cancel_cache_lid_node, rb_node);

		parent = *new;
		if (lid_node->remote_lid < this->remote_lid)
			new = &((*new)->rb_left);
		else if (lid_node->remote_lid > this->remote_lid)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	rb_link_node(&lid_node->rb_node, parent, new);
	rb_insert_color(&lid_node->rb_node, root);

	return 0;
}

static struct hfi2_dms_cancel_cache_lid_node *_cancel_cache_lid_node_alloc(struct hfi2_dms *dms, u32 remote_lid)
{
	struct hfi2_dms_dlist_element *element = hfi2_dms_impl_dlist_pop(&dms->cancel_cache.freelist);
	struct hfi2_dms_cancel_cache_lid_node *lid_node;

	if (element) {
		lid_node = container_of(element, struct hfi2_dms_cancel_cache_lid_node, dlist);
	} else {
		lid_node = kzalloc_node(sizeof(*lid_node), GFP_ATOMIC, dms->numa_node);
		if (!lid_node)
			return NULL;
	}

	lid_node->remote_lid = remote_lid;
	lid_node->count = 0;

	return lid_node;
}

static void _cancel_cache_lid_node_free(struct hfi2_dms *dms, struct hfi2_dms_cancel_cache_lid_node *lid_node)
{
	DMS_BUG_ON(!lid_node);
	DMS_BUG_ON(lid_node->count != 0);

	hfi2_dms_impl_dlist_push(&dms->cancel_cache.freelist, &lid_node->dlist);
}

static void _cancel_cache_add(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key, int err)
{
	struct hfi2_dms_cancel_cache_lid_node *lid_node;

	lid_node = _cancel_cache_rb_search(&dms->cancel_cache.active, remote_lid);
	if (!lid_node) {
		lid_node = _cancel_cache_lid_node_alloc(dms, remote_lid);
		if (!lid_node)
			return;

		if (_cancel_cache_rb_insert(&dms->cancel_cache.active, lid_node) < 0) {
			_cancel_cache_lid_node_free(dms, lid_node);
			return;
		}
	}

	u8 idx;
	if (lid_node->count < HFI2_DMS_CANCEL_CACHE_ENTRIES_PER_LID) {
		idx = lid_node->count;
		lid_node->count++;
	} else {
		idx = HFI2_DMS_CANCEL_CACHE_ENTRIES_PER_LID - 1;
		memmove(&lid_node->entries[0], &lid_node->entries[1],
			idx * sizeof(lid_node->entries[0]));
	}

	lid_node->entries[idx].tx_rift_key = tx_rift_key;
	lid_node->entries[idx].cancel_time = ktime_get();
	lid_node->entries[idx].cancel_err = err;

	dms->cancel_cache.total_count++;
}

static struct hfi2_dms_cancel_cache_entry *_cancel_cache_find(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key)
{
	if (dms->cancel_cache.total_count == 0)
		return NULL;

	struct hfi2_dms_cancel_cache_lid_node *lid_node =
		_cancel_cache_rb_search(&dms->cancel_cache.active, remote_lid);
	if (!lid_node)
		return NULL;

	for (u8 i = 0; i < lid_node->count; i++) {
		if (lid_node->entries[i].tx_rift_key.value == tx_rift_key.value)
			return &lid_node->entries[i];
	}

	return NULL;
}

static void _cancel_cache_remove(struct hfi2_dms *dms, u32 remote_lid, hfi2_dms_rift_key_t tx_rift_key)
{
	struct hfi2_dms_cancel_cache_lid_node *lid_node =
		_cancel_cache_rb_search(&dms->cancel_cache.active, remote_lid);
	if (!lid_node)
		return;

	for (u8 i = 0; i < lid_node->count; i++) {
		if (lid_node->entries[i].tx_rift_key.value == tx_rift_key.value) {
			lid_node->count--;
			dms->cancel_cache.total_count--;

			if (i < lid_node->count) {
				lid_node->entries[i] = lid_node->entries[lid_node->count];
			}

			if (lid_node->count == 0) {
				rb_erase(&lid_node->rb_node, &dms->cancel_cache.active);
				_cancel_cache_lid_node_free(dms, lid_node);
			}
			return;
		}
	}
}

static void _cancel_cache_age(struct hfi2_dms *dms, ktime_t now)
{
	if (dms->cancel_cache.total_count == 0)
		return;

	ktime_t expiry = ktime_sub_ms(now, HFI2_DMS_CANCEL_CACHE_TTL_MS);
	struct rb_node *rb_node, *rb_next_node;

	for (rb_node = rb_first(&dms->cancel_cache.active); rb_node; rb_node = rb_next_node) {
		rb_next_node = rb_next(rb_node);

		struct hfi2_dms_cancel_cache_lid_node *lid_node =
			rb_entry(rb_node, struct hfi2_dms_cancel_cache_lid_node, rb_node);

		for (u8 i = 0; i < lid_node->count; ) {
			if (ktime_before(lid_node->entries[i].cancel_time, expiry)) {
				lid_node->count--;
				dms->cancel_cache.total_count--;

				if (i < lid_node->count) {
					lid_node->entries[i] = lid_node->entries[lid_node->count];
				}
			} else {
				i++;
			}
		}

		if (lid_node->count == 0) {
			rb_erase(&lid_node->rb_node, &dms->cancel_cache.active);
			_cancel_cache_lid_node_free(dms, lid_node);
		}
	}
}

static struct hfi2_dms_client_state *hfi2_dms_client_rbtree_search(struct hfi2_dms *dms, u32 client_key)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node *node = root->rb_node;
	struct hfi2_dms_client_state *client;

	while (node) {
		client = container_of(node, struct hfi2_dms_client_state, node);

		if (client_key < client->key)
			node = node->rb_left;
		else if (client_key > client->key)
			node = node->rb_right;
		else {
			return client;
		}
	}
	return NULL;
}

static int hfi2_dms_client_rbtree_insert(struct hfi2_dms *dms, u32 client_key, struct hfi2_dms_client_state * client)
{
	struct rb_root *root = &dms->client_rbtree;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct hfi2_dms_client_state *this = container_of(*new, struct hfi2_dms_client_state, node);

		parent = *new;
		if (client_key < this->key)
			new = &((*new)->rb_left);
		else if (client_key > this->key)
			new = &((*new)->rb_right);
		else {
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&client->node, parent, new);
	rb_insert_color(&client->node, &dms->client_rbtree);

	return 0;
 }

static void hfi2_dms_client_rbtree_remove(struct hfi2_dms *dms, struct hfi2_dms_client_state *client)
{
	/* this and insert should have locking, or some garauntee on serialization */
	rb_erase(&client->node, &dms->client_rbtree);
}

int hfi2_dms_create_client_key(struct hfi2_dms *dms, u32 client_key,
			       hfi2_dms_client_diag_access_fn diag_access_fn,
			       void *diag_access_ctx)
{
	struct hfi2_dms_client_state *client;
	int rc;

	client = hfi2_dms_client_rbtree_search(dms, client_key);
	if (client) {
		dd_dev_err(dms->dd, "Client key %u already exists.\n", client_key);
		return -EEXIST;
	}

	client = (struct hfi2_dms_client_state *)kzalloc_node(sizeof(*client),
							   GFP_KERNEL, dms->numa_node);
	if (!client) {
		dd_dev_err(dms->dd, "Memory allocation error.\n");
		return -ENOMEM;
	}

	client->key = client_key;
	client->access.rbt = RB_ROOT;
	client->diag_access_fn = diag_access_fn;
	client->diag_access_ctx = diag_access_ctx;
	rc = hfi2_dms_client_rbtree_insert(dms, client_key, client);
	if (rc < 0) {
		dd_dev_err(dms->dd, "Client rbtree insertion error.\n");
		kfree(client);
		return -EINVAL;
	}
	return 0;
}

static struct hfi2_dms_access *hfi2_dms_access_rbtree_search(struct hfi2_dms_client_state *client, u32 access_key)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node *node = root->rb_node;
	struct hfi2_dms_access *access;

	while (node) {
		access = container_of(node, struct hfi2_dms_access, node);

		if (access_key < access->dms_key.access)
			node = node->rb_left;
		else if (access_key > access->dms_key.access)
			node = node->rb_right;
		else {
			return access;
		}
	}
	return NULL;
}

static int hfi2_dms_access_rbtree_insert(struct hfi2_dms_client_state *client, u32 access_key, struct hfi2_dms_access *access)
{
	struct rb_root *root = &client->access.rbt;
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct hfi2_dms_access *this = container_of(*new, struct hfi2_dms_access, node);

		parent = *new;
		if (access_key < this->dms_key.access)
			new = &((*new)->rb_left);
		else if (access_key > this->dms_key.access)
			new = &((*new)->rb_right);
		else {
			return -ENOSPC;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&access->node, parent, new);
	rb_insert_color(&access->node, &client->access.rbt);

	return 0;
}

static void hfi2_dms_access_freelist_push(struct hfi2_dms *dms, struct hfi2_dms_access *access)
{
	access->state = HFI2_DMS_ACCESS_STATE_FREE;
	hfi2_dms_impl_dlist_push(&dms->access.freelist, &access->element);
}

static struct hfi2_dms_access *hfi2_dms_access_freelist_pop(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *element;
	element = hfi2_dms_impl_dlist_pop(&dms->access.freelist);
	if (!element) {
		return NULL;
	}
	return container_of(element, struct hfi2_dms_access, element);
}

static int hfi2_dms_access_block_new(struct hfi2_dms *dms)
{
	int i;
	// allocate a bunch more
	for (i = 0; i < 1024; ++i) {
		struct hfi2_dms_access *access;

		access = (struct hfi2_dms_access *)kzalloc_node(sizeof(*access),
								GFP_KERNEL,
								dms->numa_node);
		if (!access) {
			dd_dev_err(dms->dd, "Memory allocation error.\n");
			return -ENOMEM;
		}
		hfi2_dms_access_freelist_push(dms, access);
	}
	return 0;
}

static struct hfi2_dms_access *hfi2_dms_access_new(struct hfi2_dms *dms)
{
	struct hfi2_dms_access *access;

	access = hfi2_dms_access_freelist_pop(dms);
	if (!access) {
		if (hfi2_dms_access_block_new(dms)) {
			dd_dev_err(dms->dd, "Failed to allocate new access block.\n");
			return NULL;
		}

		access = hfi2_dms_access_freelist_pop(dms);
		if (!access) {
			dd_dev_err(dms->dd, "Free list error.\n");
			return NULL;
		}
	}
	return access;
}

static int hfi2_dms_access_assign(struct hfi2_dms *dms, union hfi2_dms_key dms_key, struct hfi2_dms_access *access)
{
	u64 const client_key = dms_key.client;
	u64 const access_key = dms_key.access;
	struct hfi2_dms_client_state * client;
	int rc;

	client = hfi2_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dd_dev_err(dms->dd, "Client key %llu not found.\n", client_key);
		return -EINVAL;
	}

	access->dms_key = dms_key;

	if (access_key < HFI2_DMS_MAX_ACCESS_FAST) {
		if (client->access.arr[access_key]) {
			dd_dev_err(dms->dd, "Client access already active for id %llu.\n", access_key);
			return -EEXIST;
		}
		client->access.arr[access_key] = access;
	} else {
		rc = hfi2_dms_access_rbtree_insert(client, access_key, access);
		if (rc < 0) {
			dd_dev_err(dms->dd, "Client access rbtree insertion error.\n");
			return -1;
		}
	}

	return 0;
}

/*
 * Cancel the transfers @client serves as a target, matched by the local
 * access's key (access->dms_key.client).
 *
 * Initiator trackers are not matched: their dms_key.client is the remote
 * peer's key, which can equal @client's for an unrelated process.  They are
 * cancelled by owner for bulksvc user clients, and at QP teardown for verbs
 * (each holds a QP reference, so none are left when the verbs client key is
 * released).
 */
static void _cancel_target_trackers_for_client(struct hfi2_dms *dms,
					       struct hfi2_dms_client_state *client)
{
	struct hfi2_dms_dlist pending_cancel;
	union hfi2_dms_tracker *tracker;
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_rx_tracker *rx_tracker;
	struct hfi2_dms_dlist_element *elem, *next;
	u32 client_key = client->key;
	u32 i;

	hfi2_dms_impl_dlist_init(&pending_cancel);

	elem = dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_RX].waitlist.head;
	while (elem) {
		next = elem->next;
		tracker = (union hfi2_dms_tracker *)elem;
		rx_tracker = &tracker->rx;
		if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE &&
				rx_tracker->write.access &&
				rx_tracker->write.access->dms_key.client == client_key) {
			hfi2_dms_impl_dlist_remove(&dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_RX].waitlist, elem);
			hfi2_dms_impl_dlist_append(&pending_cancel, elem);
		}
		elem = next;
	}

	elem = dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_TX].waitlist.head;
	while (elem) {
		next = elem->next;
		tracker = (union hfi2_dms_tracker *)elem;
		tx_tracker = &tracker->tx;
		if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ &&
				tx_tracker->read.access &&
				tx_tracker->read.access->dms_key.client == client_key) {
			hfi2_dms_impl_dlist_remove(&dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_TX].waitlist, elem);
			hfi2_dms_impl_dlist_append(&pending_cancel, elem);
		}
		elem = next;
	}

	u64 tidset_waiter_count = _rift_keyring_size(&dms->tidset_waiters);
	for (u64 pos = 0; pos < tidset_waiter_count; pos++) {
		hfi2_dms_rift_key_t const key = _rift_keyring_at(&dms->tidset_waiters, pos);
		tracker = _rift_lookup(&dms->rift, key);
		if (!tracker)
			continue;

		rx_tracker = &tracker->rx;
		if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE &&
		    rx_tracker->write.access &&
		    rx_tracker->write.access->dms_key.client == client_key) {
			_rift_keyring_remove(&dms->tidset_waiters, key);
			tidset_waiter_count--;
			pos--;
		}
	}

	for (i = 0; i < HFI2_DMS_RIFT_IDX_SIZE; i++) {
		tracker = dms->rift.arr[i];
		if (!tracker)
			continue;

		if (_rift_key_side_tx(tracker->hdr.local_rift_key)) {
			tx_tracker = &tracker->tx;
			if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
				if (tx_tracker->read.access &&
						tx_tracker->read.access->dms_key.client == client_key) {
					hfi2_dms_impl_dlist_append(&pending_cancel, &tracker->hdr.dlist);
				}
			}
		}

		if (_rift_key_side_rx(tracker->hdr.local_rift_key)) {
			rx_tracker = &tracker->rx;
			if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE) {
				if (rx_tracker->write.access &&
						rx_tracker->write.access->dms_key.client == client_key) {
					hfi2_dms_impl_dlist_append(&pending_cancel, &tracker->hdr.dlist);
				}
			}
		}
	}

	while (!hfi2_dms_impl_dlist_empty(&pending_cancel)) {
		elem = hfi2_dms_impl_dlist_pop(&pending_cancel);
		tracker = (union hfi2_dms_tracker *)elem;

		if (tracker->hdr.side == HFI2_DMS_XFER_SIDE_TX) {
			hfi2_dms_tx_tracker_cancel(dms, &tracker->tx, -ECANCELED);
		} else {
			hfi2_dms_rx_tracker_cancel(dms, &tracker->rx, -ECANCELED);
		}
	}
}

/*
 * Drop user_info krefs held by EPHEMERAL accesses whose tracker never
 * fired (e.g. remote never issued READ_START).  PERSISTENT accesses
 * are owned by bulksvc_user_info_destroy's unregister_access path.
 */
static void _drain_idle_client_ephemerals(struct hfi2_dms *dms,
					  struct hfi2_dms_client_state *client)
{
	struct rb_node *rb_node, *rb_next_node;
	u32 i;

	for (i = 0; i < HFI2_DMS_MAX_ACCESS_FAST; i++) {
		struct hfi2_dms_access *access = client->access.arr[i];

		if (!access)
			continue;
		if (access->type != HFI2_DMS_ACCESS_TYPE_EPHEMERAL)
			continue;

		WARN_ONCE(access->active_count != 0,
			  "DMS: client %u access_key %u reached release with active_count=%u\n",
			  client->key, i, access->active_count);

		client->access.arr[i] = NULL;

		access->completion.fn(&access->completion.cookie, 0, 0, 0,
				      -ECANCELED);
		if (access->unregister.fn)
			access->unregister.fn(&access->unregister.cookie,
					      -ECANCELED);
		hfi2_dms_access_freelist_push(dms, access);
	}

	for (rb_node = rb_first(&client->access.rbt); rb_node;
	     rb_node = rb_next_node) {
		struct hfi2_dms_access *access =
			container_of(rb_node, struct hfi2_dms_access, node);

		rb_next_node = rb_next(rb_node);

		if (access->type != HFI2_DMS_ACCESS_TYPE_EPHEMERAL)
			continue;

		WARN_ONCE(access->active_count != 0,
			  "DMS: client %u access_key %u (rbt) reached release with active_count=%u\n",
			  client->key, access->dms_key.access,
			  access->active_count);

		rb_erase(&access->node, &client->access.rbt);
		RB_CLEAR_NODE(&access->node);

		access->completion.fn(&access->completion.cookie, 0, 0, 0,
				      -ECANCELED);
		if (access->unregister.fn)
			access->unregister.fn(&access->unregister.cookie,
					      -ECANCELED);
		hfi2_dms_access_freelist_push(dms, access);
	}
}

void hfi2_dms_release_client_key(struct hfi2_dms *dms, u32 client_key)
{
	struct hfi2_dms_client_state *client;
	client = hfi2_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		/* Expected no-op on second call (MMU .release + destroy). */
		dd_dev_dbg(dms->dd, "release_client_key: client %u already drained.\n",
			   client_key);
		return;
	}

	_cancel_target_trackers_for_client(dms, client);

	/* Drop user_info krefs held by idle ephemerals that never got a
	 * tracker (cancel above only drives completion for trackered ones).
	 */
	_drain_idle_client_ephemerals(dms, client);

	hfi2_dms_client_rbtree_remove(dms, client);

	kfree(client);
}

/* The cancel-by-owner key of a provider's buffer; NULL when it has none. */
static void *_pp_owner(struct hfi2_dms_page_provider const *pp)
{
	return pp->owner ? pp->owner(pp) : NULL;
}

/*
 * True if the tracker's local MR was created with dms_mr.owner == @owner.
 *
 * Cancels the initiator trackers THIS user_info started (RX destination or
 * WRITE source); their dms_key is the remote peer's, so the owner finds them.
 * Target RDMA_READ TX trackers are excluded: release_client_key cancels them.
 * A target RX WRITE tracker can match both walks; release runs first in
 * MMU_SYNC_DRAIN.
 *
 * Only owner-keyed providers (user host/ephemeral MRs) report an owner; any
 * other provider reports NULL and never matches the non-NULL @owner.
 *
 * Caller invariant: every MR for which the caller is the logical owner has
 * dms_mr.owner == @owner; no MR for a different owner shares the @owner
 * pointer numerically.
 */
static bool _tracker_references_owner(union hfi2_dms_tracker *tracker,
				      void *owner)
{
	if (tracker->hdr.side == HFI2_DMS_XFER_SIDE_RX)
		return _pp_owner(&tracker->rx.page_provider) == owner;
	if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE)
		return _pp_owner(&tracker->tx.write.page_provider) == owner;
	return false;
}

void hfi2_dms_cancel_trackers_for_owner(struct hfi2_dms *dms, void *owner)
{
	struct hfi2_dms_dlist pending_cancel;
	struct hfi2_dms_dlist_element *elem, *next;
	union hfi2_dms_tracker *tracker;
	unsigned side;
	unsigned type;
	u32 i;

	DMS_BUG_ON(!dms);

	if (!owner)
		return;

	hfi2_dms_impl_dlist_init(&pending_cancel);

	/* waitlists */
	for (type = 0; type < HFI2_DMS_XFER_TYPE_COUNT; type++) {
		for (side = 0; side < HFI2_DMS_XFER_SIDE_COUNT; side++) {
			struct hfi2_dms_dlist *wl =
				&dms->rift.type[type].side[side].waitlist;

			elem = wl->head;
			while (elem) {
				next = elem->next;
				tracker = (union hfi2_dms_tracker *)elem;
				if (_tracker_references_owner(tracker, owner)) {
					hfi2_dms_impl_dlist_remove(wl, elem);
					hfi2_dms_impl_dlist_append(
						&pending_cancel, elem);
				}
				elem = next;
			}
		}
	}

	/* tidset_waiters keyring */
	u64 waiter_count = _rift_keyring_size(&dms->tidset_waiters);
	for (u64 pos = 0; pos < waiter_count; pos++) {
		hfi2_dms_rift_key_t const key =
			_rift_keyring_at(&dms->tidset_waiters, pos);
		tracker = _rift_lookup(&dms->rift, key);
		if (!tracker)
			continue;
		if (_tracker_references_owner(tracker, owner)) {
			_rift_keyring_remove(&dms->tidset_waiters, key);
			waiter_count--;
			pos--;
		}
	}

	/* active rift slots */
	for (i = 0; i < HFI2_DMS_RIFT_IDX_SIZE; i++) {
		tracker = dms->rift.arr[i];
		if (!tracker)
			continue;
		if (_tracker_references_owner(tracker, owner))
			hfi2_dms_impl_dlist_append(&pending_cancel,
						   &tracker->hdr.dlist);
	}

	while (!hfi2_dms_impl_dlist_empty(&pending_cancel)) {
		elem = hfi2_dms_impl_dlist_pop(&pending_cancel);
		tracker = (union hfi2_dms_tracker *)elem;
		if (tracker->hdr.side == HFI2_DMS_XFER_SIDE_TX)
			hfi2_dms_tx_tracker_cancel(dms, &tracker->tx,
						   -ECANCELED);
		else
			hfi2_dms_rx_tracker_cancel(dms, &tracker->rx,
						   -ECANCELED);
	}
}

static int hfi2_dms_access_remove(struct hfi2_dms *dms, struct hfi2_dms_access *access)
{
	// FIXME - There must be a faster/better way to remove access from the rbtree since we already have pointers to it ....

	u64 client_key = access->dms_key.client;
	u64 access_key = access->dms_key.access;
	struct hfi2_dms_client_state * client;

	client = hfi2_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		dms->counters.health_invalid_client++;
		dd_dev_dbg(dms->dd,
			   "Invalid client in access_remove. key = 0x%016llx (%llu), total = %llu\n",
			   client_key, client_key,
			   dms->counters.health_invalid_client);
		return -ENOENT;
	}

	if (access_key < HFI2_DMS_MAX_ACCESS_FAST) {
		if (!client->access.arr[access_key]) {
			dd_dev_err_ratelimited(dms->dd,
					       "Access not active error. id = %llu\n",
					       access_key);
			return -ENOENT;
		}
		client->access.arr[access_key] = NULL;
	} else {
		if (RB_EMPTY_NODE(&access->node)) {
			dd_dev_err_ratelimited(dms->dd,
				"access_remove on unlinked node, dms_key 0x%016llx\n",
				access->dms_key.value);
			return -ENOENT;
		}
		rb_erase(&access->node, &client->access.rbt);
		RB_CLEAR_NODE(&access->node);
	}
	return 0;
}

static struct hfi2_dms_access *hfi2_dms_access_lookup(struct hfi2_dms *dms, union hfi2_dms_key dms_key, struct hfi2_dms_client_state **client_out)
{
	WARN_ON(client_out == NULL);
	struct hfi2_dms_access *access = NULL;
	u64 client_key = dms_key.client;
	u64 access_key = dms_key.access;
	struct hfi2_dms_client_state * client;

	client = hfi2_dms_client_rbtree_search(dms, client_key);
	if (!client) {
		*client_out = NULL;
		dms->counters.health_invalid_client++;
		dd_dev_dbg(dms->dd,
			   "Invalid client in access_lookup. key = 0x%016llx (%llu), total = %llu\n",
			   client_key, client_key,
			   dms->counters.health_invalid_client);
		return NULL;
	}
	*client_out = client;

	if (access_key < HFI2_DMS_MAX_ACCESS_FAST) {
		access = client->access.arr[access_key];
	} else {
		access = hfi2_dms_access_rbtree_search(client, access_key);
	}

	if (!access) {
		return NULL;
	}
	return access;
}

void hfi2_dms_completion_fn_noop(union hfi2_dms_completion_cookie *cookie, int status)
{
	(void) cookie;
	(void) status;
}

void hfi2_dms_access_completion_fn_noop(union hfi2_dms_completion_cookie *cookie, u16 flags, u64 imm_data, u64 order_key, int status)
{
	(void) cookie;
	(void) imm_data;
	(void) order_key;
	(void) flags;
	(void) status;
}

static void hfi2_dms_impl_access_initialize(struct hfi2_dms_access *access,
					     enum hfi2_dms_access_type access_type,
					     struct hfi2_dms_page_provider page_provider,
					     u64 offset, u64 size,
					     union hfi2_dms_key dms_key,
					     struct hfi2_dms_access_completion const *completion)
{
	RB_CLEAR_NODE(&access->node);
	access->element = (struct hfi2_dms_dlist_element){ 0 };

	access->dms_key = dms_key;
	access->type = access_type;

	if (completion) {
		access->completion = *completion;
	} else {
		access->completion.fn = hfi2_dms_access_completion_fn_noop;
	}

	access->page_provider = page_provider;
	access->offset = offset;
	access->size = size;
	access->active_count = 0;
	hfi2_dms_impl_dlist_init(&access->inflight);
	access->state = HFI2_DMS_ACCESS_STATE_ACTIVE;
	access->unregister_started = false;
	access->unregister.fn = hfi2_dms_completion_fn_noop;
}

int hfi2_dms_register_access(struct hfi2_dms *dms,
			     struct hfi2_dms_page_provider page_provider,
			     u64 offset, u64 size,
			     union hfi2_dms_key dms_key,
			     struct hfi2_dms_access_completion const completion,
			     enum hfi2_dms_access_type access_type,
			     struct hfi2_dms_access **out)
{
	struct hfi2_dms_access *access;
	int ret;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!page_provider.pin_range);

	if ((offset > page_provider.length) ||
	    (size > (page_provider.length - offset))) {
		if (out)
			*out = NULL;
		return -EINVAL;
	}

	access = hfi2_dms_access_new(dms);
	if (!access) {
		if (out)
			*out = NULL;
		return -ENOMEM;
	}

	hfi2_dms_impl_access_initialize(access, access_type, page_provider,
					offset, size, dms_key, &completion);

	ret = hfi2_dms_access_assign(dms, dms_key, access);
	if (ret < 0) {
		if (out)
			*out = NULL;
		dd_dev_err(dms->dd, "Access not assigned.\n");
		hfi2_dms_access_freelist_push(dms, access);
		return ret;
	}

	if (out)
		*out = access;

	return 0;
}

/*
 * _cancel_trackers_for_access - actively cancel the target-side trackers
 * serving a DMS access, matched by the access pointer.  Uses the same
 * collect-then-cancel pattern as _cancel_target_trackers_for_client() to
 * avoid mutating the rift table during iteration.
 *
 * Initiator trackers are not matched: their dms_key names the remote buffer,
 * a (client, access) pair from the remote peer's own per-node key spaces,
 * which can equal @access's key for an unrelated transfer.  Their owners
 * cancel them (by MR owner for bulksvc user clients, at QP teardown for
 * verbs).
 *
 * Target-side trackers that call access_xfer_end() on cancel will
 * decrement active_count.  When active_count reaches 0 the unregister
 * callback fires inline — caller must not touch @access after this
 * returns.
 */
static void _cancel_trackers_for_access(struct hfi2_dms *dms,
					struct hfi2_dms_access *access)
{
	struct hfi2_dms_dlist pending_cancel;
	union hfi2_dms_tracker *tracker;
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_rx_tracker *rx_tracker;
	struct hfi2_dms_dlist_element *elem, *next;
	u32 i;

	hfi2_dms_impl_dlist_init(&pending_cancel);

	/* target RX waitlist: RDMA WRITE targets (match by access ptr) */
	elem = dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_RX].waitlist.head;
	while (elem) {
		next = elem->next;
		tracker = (union hfi2_dms_tracker *)elem;
		rx_tracker = &tracker->rx;
		if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE &&
		    rx_tracker->write.access == access) {
			hfi2_dms_impl_dlist_remove(
				&dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_RX].waitlist,
				elem);
			hfi2_dms_impl_dlist_append(&pending_cancel, elem);
		}
		elem = next;
	}

	/* target TX waitlist: RDMA READ targets (match by access ptr) */
	elem = dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_TX].waitlist.head;
	while (elem) {
		next = elem->next;
		tracker = (union hfi2_dms_tracker *)elem;
		tx_tracker = &tracker->tx;
		if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ &&
		    tx_tracker->read.access == access) {
			hfi2_dms_impl_dlist_remove(
				&dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].side[HFI2_DMS_XFER_SIDE_TX].waitlist,
				elem);
			hfi2_dms_impl_dlist_append(&pending_cancel, elem);
		}
		elem = next;
	}

	/* tidset waiters: target RX WRITE trackers waiting for a tidset */
	u64 tidset_waiter_count = _rift_keyring_size(&dms->tidset_waiters);

	for (u64 pos = 0; pos < tidset_waiter_count; pos++) {
		hfi2_dms_rift_key_t const key =
			_rift_keyring_at(&dms->tidset_waiters, pos);
		tracker = _rift_lookup(&dms->rift, key);
		if (!tracker)
			continue;
		rx_tracker = &tracker->rx;
		if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE &&
		    rx_tracker->write.access == access) {
			_rift_keyring_remove(&dms->tidset_waiters, key);
			tidset_waiter_count--;
			pos--;
		}
	}

	/* rift table: active target trackers for this access */
	for (i = 0; i < HFI2_DMS_RIFT_IDX_SIZE; i++) {
		tracker = dms->rift.arr[i];
		if (!tracker)
			continue;

		if (_rift_key_side_tx(tracker->hdr.local_rift_key)) {
			tx_tracker = &tracker->tx;
			if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ &&
			    tx_tracker->read.access == access)
				hfi2_dms_impl_dlist_append(&pending_cancel,
							   &tracker->hdr.dlist);
		}

		if (_rift_key_side_rx(tracker->hdr.local_rift_key)) {
			rx_tracker = &tracker->rx;
			if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE &&
			    rx_tracker->write.access == access)
				hfi2_dms_impl_dlist_append(&pending_cancel,
							   &tracker->hdr.dlist);
		}
	}

	while (!hfi2_dms_impl_dlist_empty(&pending_cancel)) {
		elem = hfi2_dms_impl_dlist_pop(&pending_cancel);
		tracker = (union hfi2_dms_tracker *)elem;

		if (tracker->hdr.side == HFI2_DMS_XFER_SIDE_TX)
			hfi2_dms_tx_tracker_cancel(dms, &tracker->tx,
						   -ECANCELED);
		else
			hfi2_dms_rx_tracker_cancel(dms, &tracker->rx,
						   -ECANCELED);
	}
}

int hfi2_dms_unregister_access(struct hfi2_dms *dms, union hfi2_dms_key dms_key,
			       struct hfi2_dms_completion unreg_cmpl)
{
	struct hfi2_dms_access *access;
	struct hfi2_dms_client_state *client = NULL;
	struct hfi2_dms_deferred_start *entry, *tmp;
	int ret;

	access = hfi2_dms_access_lookup(dms, dms_key, &client);
	if (!access || !client) {
		dd_dev_warn(dms->dd,
			    "Invalid dms_key %llu for unregistering access.\n",
			    dms_key.value);
		return -EINVAL;
	}

	/*
	 * Duplicate detection: unregister_started is false until the
	 * first explicit unregister.  Ephemeral accesses enter
	 * ACTIVE_TEARDOWN at xfer_begin without setting this flag,
	 * so their first explicit unregister is still accepted.
	 */
	if (access->unregister_started)
		return -EALREADY;

	access->state = HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN;
	access->unregister_started = true;
	access->unregister = unreg_cmpl;

	list_for_each_entry_safe(entry, tmp, &dms->access_deferred.active,
				 node) {
		union hfi2_dms_key entry_key;

		if (entry->op == HFI2_DMS_OP_RDMA_READ)
			entry_key = entry->read.parameters.dms_key;
		else
			entry_key = entry->write.parameters.dms_key;

		if (entry_key.value == dms_key.value) {
			list_del(&entry->node);
			entry->op = HFI2_DMS_OP_NONE;
			list_add_tail(&entry->node,
				      &dms->access_deferred.free);
			dms->access_deferred.count--;
			dms->counters.access_deferred_nack++;
			dd_dev_dbg(dms->dd,
				   "DMS: purged deferred entry for deregistered key 0x%llx\n",
				   dms_key.value);
		}
	}

	if (access->active_count == 0) {
		/*
		 * An unadmitted EPHEMERAL access never reaches
		 * access_xfer_end(), so its original registration completion
		 * (access->completion, owner of the mr_record/user_info refs)
		 * would otherwise never fire. EPHEMERAL only -- PERSISTENT
		 * notification-completion semantics are untouched.
		 */
		if (access->type == HFI2_DMS_ACCESS_TYPE_EPHEMERAL &&
		    access->completion.fn)
			access->completion.fn(&access->completion.cookie, 0, 0, 0, -ECANCELED);

		ret = hfi2_dms_access_remove(dms, access);
		if (ret < 0) {
			dd_dev_err(dms->dd,
				   "access_remove failed (%d) during immediate unregister, dms_key %llu — quarantined\n",
				   ret, dms_key.value);
			return ret;
		}
		if (access->unregister.fn)
			access->unregister.fn(&access->unregister.cookie, 0);
		hfi2_dms_access_freelist_push(dms, access);
		return 0;
	}

	/*
	 * Active trackers present — cancel them immediately rather than
	 * waiting for health timeout.  The cancel path calls
	 * access_xfer_end() for each tracker, which decrements
	 * active_count and fires the unregister callback inline when
	 * it reaches zero.  Do not touch @access after this call.
	 */
	_cancel_trackers_for_access(dms, access);
	return 0;
}

/* access_xfer_begin() return code: a START duplicates an already-admitted,
 * still-live transfer on this access. The caller must NOT create a new tracker
 * or consume the credential; it should re-drive the existing transfer instead.
 */
#define HFI2_DMS_ACCESS_ALREADY_STARTED 1

/* Find the live target tracker admitted on @access for a given requester
 * (slid, remote_rift_key), or NULL. Used to re-drive a duplicate START.
 */
static union hfi2_dms_tracker *
_access_inflight_find(struct hfi2_dms_access *access, u32 slid,
		      hfi2_dms_rift_key_t remote_rift_key)
{
	struct hfi2_dms_dlist_element *e;

	for (e = access->inflight.head; e; e = e->next) {
		union hfi2_dms_tracker *t =
			container_of(e, union hfi2_dms_tracker, hdr.access_inflight);

		if (t->hdr.remote_lid == slid &&
		    t->hdr.remote_rift_key.value == remote_rift_key.value)
			return t;
	}
	return NULL;
}

enum hfi2_dms_start_gen_rel {
	HFI2_DMS_START_GEN_STALE = -1,
	HFI2_DMS_START_GEN_DUP = 0,
	HFI2_DMS_START_GEN_NEWER = 1,
};

static enum hfi2_dms_start_gen_rel
_start_gen_compare(u64 incoming_order_key, u64 live_order_key)
{
	u8 const in_gen =
		(incoming_order_key >> HFI2_DMS_ORDER_KEY_GEN_SHIFT) & HFI2_DMS_ORDER_KEY_GEN_MASK;
	u8 const live_gen =
		(live_order_key >> HFI2_DMS_ORDER_KEY_GEN_SHIFT) & HFI2_DMS_ORDER_KEY_GEN_MASK;
	u8 const delta = (u8)(in_gen - live_gen);

	if (delta == 0)
		return HFI2_DMS_START_GEN_DUP;
	return (delta & 0x80) ? HFI2_DMS_START_GEN_STALE : HFI2_DMS_START_GEN_NEWER;
}

/*
 * Admit a transfer (identified by the requester's (slid, remote_rift_key)) onto
 * an access, recording the owning target tracker in the access's in-flight list.
 *
 * Returns:
 *   0                                - admitted; @tracker linked into access->inflight
 *   HFI2_DMS_ACCESS_ALREADY_STARTED  - a live transfer with the same
 *                                      (slid, remote_rift_key) is already admitted
 *                                      (duplicate START); nothing was changed
 *   -EBUSY                           - access not ACTIVE for a NEW transfer, or an
 *                                      ephemeral access already has a DIFFERENT
 *                                      transfer in flight
 *
 * The duplicate scan runs BEFORE the state gate, so a re-injected START is
 * idempotent even after an ephemeral access flips to ACTIVE_TEARDOWN.
 * First ephemeral admit flips ACTIVE_TEARDOWN so the access auto-frees on
 * drain -- the one-shot (dma_access_once) client sends no unregister, so
 * without this the access leaks and key reuse fails with -EEXIST.
 */
static int access_xfer_begin(struct hfi2_dms *dms, struct hfi2_dms_access *access,
			     u32 slid, hfi2_dms_rift_key_t remote_rift_key,
			     union hfi2_dms_tracker *tracker)
{
	struct hfi2_dms_dlist_element *e;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(!tracker);

	for (e = access->inflight.head; e; e = e->next) {
		union hfi2_dms_tracker *t =
			container_of(e, union hfi2_dms_tracker, hdr.access_inflight);

		if (t->hdr.remote_lid == slid &&
		    t->hdr.remote_rift_key.value == remote_rift_key.value) {
			dms->counters.access_busy_live_dup++;
			return HFI2_DMS_ACCESS_ALREADY_STARTED;
		}
	}

	if (access->state != HFI2_DMS_ACCESS_STATE_ACTIVE) {
		dd_dev_warn_ratelimited(dms->dd,
			    "DMS_DIAG: access_xfer_begin REJECTED dms_key=%llu state=%d active_count=%u\n",
			    access->dms_key.value, access->state,
			    access->active_count);
		return -EBUSY;
	}

	if (access->type == HFI2_DMS_ACCESS_TYPE_EPHEMERAL &&
	    !hfi2_dms_impl_dlist_empty(&access->inflight)) {
		dd_dev_warn_ratelimited(dms->dd,
			    "DMS_DIAG: access_xfer_begin EBUSY (ephemeral in use) dms_key=%llu slid=%u rrk=%u\n",
			    access->dms_key.value, slid, remote_rift_key.value);
		return -EBUSY;
	}

	hfi2_dms_impl_dlist_append(&access->inflight, &tracker->hdr.access_inflight);
	access->active_count += 1;
	dms->counters.access_xfer_begin++;

	if (access->type == HFI2_DMS_ACCESS_TYPE_EPHEMERAL)
		access->state = HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN;

	return 0;
}

/* Unlink a target tracker from its access in-flight list, tolerating a node
 * that is not currently linked (an error-path xfer_end before admission).
 */
static void access_inflight_unlink(struct hfi2_dms_access *access,
				   union hfi2_dms_tracker *tracker)
{
	struct hfi2_dms_dlist_element *n = &tracker->hdr.access_inflight;

	if (n->prev || n->next || access->inflight.head == n)
		hfi2_dms_impl_dlist_remove(&access->inflight, n);
}

static void access_xfer_end(struct hfi2_dms *dms, struct hfi2_dms_access *access,
			    union hfi2_dms_tracker *tracker,
			    u16 flags, u64 imm_data, u64 order_key, int status)
{
	int ret;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(access->active_count == 0);

	/* Unlink from the access in-flight list before any teardown below can
	 * free the access; keeps active_count and the list consistent.
	 */
	if (tracker)
		access_inflight_unlink(access, tracker);

	access->active_count -= 1;
	dms->counters.access_xfer_end++;
	access->completion.fn(&access->completion.cookie, flags, imm_data, order_key, status);

	/* Free the access once ACTIVE_TEARDOWN drains. Ephemeral accesses flip at
	 * admit (no unregister from the one-shot client); persistent accesses reach
	 * ACTIVE_TEARDOWN via hfi2_dms_unregister_access(). The ephemeral default
	 * no-op unregister.fn makes the call below harmless here.
	 */
	if (access->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN &&
	    access->active_count == 0) {
		dms->counters.access_xfer_end_teardown++;
		ret = hfi2_dms_access_remove(dms, access);
		if (ret < 0) {
			dd_dev_err(dms->dd,
				   "access_remove failed (%d) during xfer_end teardown, dms_key %llu\n",
				   ret, access->dms_key.value);
			if (access->unregister.fn)
				access->unregister.fn(&access->unregister.cookie, ret);
			return;
		}
		if (access->unregister.fn)
			access->unregister.fn(&access->unregister.cookie, 0);
		hfi2_dms_access_freelist_push(dms, access);
	}
}

/* A tracker must be exempt from frequent staleness checks when it is waiting
 * on a local resource such as a rift assignment, tidset allocation, or fence
 * condition.
 */
static void _tracker_stale_set_exempt(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	tracker->hdr.stale_time = ktime_add_ns(dms->now, HFI2_DMS_STALE_EXEMPT_CANCEL_NS);
	tracker->hdr.status_req_count = HFI2_DMS_STALE_EXEMPT_COUNT;
}

/* A tracker must be checked for staleness when it is waiting on a remote
 * resource, such as an ACK packet, etc.
 */
static void _tracker_stale_set_remote(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, u64 initial_ms)
{
	tracker->hdr.stale_time = ktime_add_ms(dms->now, initial_ms);
	tracker->hdr.status_req_count = 0;
}

/* Re-arm the staleness timer on a negative/ambiguous status response WITHOUT
 * zeroing status_req_count. Resetting the count (as _tracker_stale_set_remote
 * does) would defeat the retry-limit gate (_tracker_is_dead checks
 * status_req_count > HFI2_DMS_STALE_BACKOFF_MAX_COUNT), so a transfer that
 * never recovers could hang forever. Incrementing here preserves retry
 * accounting so a genuinely stuck tracker still ages out to -ETIMEDOUT, while
 * the exponential backoff schedules the next status request.
 */
static void _tracker_stale_rearm_keep_count(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	u32 const count = tracker->hdr.status_req_count + 1;
	u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS
			       << min(count, HFI2_DMS_STALE_BACKOFF_MAX_COUNT);

	tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
	tracker->hdr.status_req_count = count;
}

/* A peer request that lands on this tracker's rift index re-arms the status
 * backoff cadence so the exchange keeps polling, but it is NOT proof of
 * forward progress: a chain-head deadlocked on tidset allocation is polled
 * indefinitely by its peer yet moves zero bytes. Resetting status_req_count
 * here (and only here) therefore does NOT protect the tracker from the
 * odometer-gated reclaim clock in _tracker_is_dead -- that clock is refreshed
 * exclusively by _tracker_note_progress on real byte movement. Keeping
 * request-arrival and liveness separate prevents a status-polled but
 * zero-progress chain-head from surviving indefinitely and freezing its chain.
 */
static void _tracker_note_peer_activity(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	tracker->hdr.status_req_count = 0;
	tracker->hdr.stale_time = ktime_add_ms(dms->now, HFI2_DMS_STALE_BACKOFF_BASE_MS);
	dms->counters.diag_tracker_activity_reset++;
}

/* A READ child waiting at DATA_START for its chain parent. */
static bool _rx_tracker_is_parked_at_data_start(union hfi2_dms_tracker const *tracker)
{
	enum hfi2_dms_tracker_health_state const state = tracker->hdr.health_state;

	return state == HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START ||
	       state == HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE;
}

/*
 * A fast-fail READ target waiting for its initiator's DATA_REQUEST. The
 * initiator may be parked on a chain parent, which only it knows, so a stale
 * target asks probes initiator for status instead of cancelling.
 */
static bool _tx_tracker_is_read_target_awaiting_data_req(union hfi2_dms_tracker const *tracker)
{
	return tracker->hdr.fast_fail &&
	       tracker->hdr.side == HFI2_DMS_XFER_SIDE_TX &&
	       tracker->hdr.op == HFI2_DMS_XFER_OP_READ &&
	       tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST;
}

/* Refresh the forward-progress clock iff byte_odometer actually advanced
 * since the last sample. Called from the stale-sweep before the liveness test
 * so a transfer moving data is retained and a stalled one ages out.
 */
static void _tracker_note_progress(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	u64 const odometer = tracker->hdr.byte_odometer;

	if (odometer != tracker->hdr.last_progress_odometer) {
		tracker->hdr.last_progress_odometer = odometer;
		tracker->hdr.last_progress_time = dms->now;
	}
}

static void _tracker_health_state_set(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, enum hfi2_dms_tracker_health_state state)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(state >= HFI2_DMS_HEALTH_WAITING_COUNT);

	enum hfi2_dms_tracker_health_state const prev = tracker->hdr.health_state;

	/* Reset the staleness/health clocks only on a real state transition. */
	bool const transition = (prev != state);

	tracker->hdr.health_state = state;

	if (!transition)
		return;

	/*
	 * Both health clocks start at creation. Restart them when the tracker
	 * leaves a rift key or tidset wait so local queueing is not counted as
	 * the peer's silence.
	 */
	if (prev == HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT ||
	    prev == HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION)
		tracker->hdr.last_progress_time = dms->now;
	if (prev == HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT)
		tracker->hdr.birth_time = dms->now;

	switch (state) {
	case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT:
		tracker->hdr.remote_status.last_known_packet_progress = 0;
		tracker->hdr.remote_status.last_known_rift_tracker_ticket = 0;
		tracker->hdr.remote_status.last_known_rift_global_assigned = 0;
		tracker->hdr.remote_status.last_known_tidset_progress = 0;
		_tracker_stale_set_exempt(dms, tracker);
		break;

	case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION:
		_tracker_stale_set_exempt(dms, tracker);
		break;

	/* Chain park states: the child holds a live RIFT slot while waiting*/
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START:
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY:
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO:
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START:
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START:
	case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE:
		_tracker_stale_set_exempt(dms, tracker);
		break;

	case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST:
	case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START:
	case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA:
	case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_SPECULATIVE:
	case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK: {
		/*
		 * Widen the initial remote-wait deadline by the caller's
		 * per-submission shift so a re-submitted transfer tolerates
		 * transient loss.  Tidset DRAINING has its own backoff and passes
		 * a pre-scaled initial_ms, so it is left unshifted here.
		 */
		u8 const shift = min(tracker->hdr.stale_backoff_shift,
				     (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT);
		_tracker_stale_set_remote(dms, tracker,
					  HFI2_DMS_STALE_BACKOFF_BASE_MS << shift);
		break;
	}

	default:
		break;
	}
}



hfi2_dms_rift_key_t _rift_key_create(u16 const generation, u16 const index)
{
	DMS_BUG_ON(index >= HFI2_DMS_RIFT_IDX_SIZE);
	return (hfi2_dms_rift_key_t){.value = (((generation << HFI2_DMS_RIFT_IDX_BITS) & HFI2_DMS_RIFT_GEN_MASK) | index)};
}

/*
 * Convert a tracker pointer to a transfer handle. Trackers are 256-aligned,
 * so the lower 8 bits of the pointer hold the generation counter.
 */
static struct hfi2_dms_transfer_handle
_tracker_to_handle(union hfi2_dms_tracker const *tracker)
{
	u64 ptr;

	if (unlikely(!tracker))
		return HFI2_DMS_TRANSFER_HANDLE_NONE;

	ptr = (u64)(uintptr_t)tracker;

	if (WARN_ON_ONCE(ptr & HFI2_DMS_HANDLE_GEN_MASK))
		return HFI2_DMS_TRANSFER_HANDLE_NONE;

	return (struct hfi2_dms_transfer_handle){
		.value = (ptr & HFI2_DMS_HANDLE_PTR_MASK)
		       | ((u64)tracker->hdr.generation & HFI2_DMS_HANDLE_GEN_MASK)
	};
}


static union hfi2_dms_tracker *
_handle_to_tracker(struct hfi2_dms_transfer_handle const handle)
{
	union hfi2_dms_tracker *tracker;
	u8 gen;

	if (unlikely(handle.value == 0))
		return NULL;

	tracker = (union hfi2_dms_tracker *)(uintptr_t)
		  (handle.value & HFI2_DMS_HANDLE_PTR_MASK);
	gen = (u8)(handle.value & HFI2_DMS_HANDLE_GEN_MASK);

	if (unlikely(tracker->hdr.generation != gen))
		return NULL;

	if (unlikely(tracker->hdr.type != HFI2_DMS_XFER_TYPE_INITIATOR))
		return NULL;
	if (unlikely(tracker->hdr.side != HFI2_DMS_XFER_SIDE_TX &&
		     tracker->hdr.side != HFI2_DMS_XFER_SIDE_RX))
		return NULL;

	return tracker;
}

/*
 * Resolve @handle to its tracker if it is still the same live transfer: any
 * type and side, unlike _handle_to_tracker(), which serves the initiator-only
 * chain links.  NULL once the tracker has been recycled.
 */
static union hfi2_dms_tracker *
_handle_to_live_tracker(struct hfi2_dms_transfer_handle const handle)
{
	union hfi2_dms_tracker *tracker;

	if (handle.value == 0)
		return NULL;

	tracker = (union hfi2_dms_tracker *)(uintptr_t)
		  (handle.value & HFI2_DMS_HANDLE_PTR_MASK);
	if (tracker->hdr.generation != (u8)(handle.value & HFI2_DMS_HANDLE_GEN_MASK))
		return NULL;
	if (tracker->hdr.side != HFI2_DMS_XFER_SIDE_TX &&
	    tracker->hdr.side != HFI2_DMS_XFER_SIDE_RX)
		return NULL;
	return tracker;
}

static void _tracker_detach_from_parent(struct hfi2_dms *dms,
			  union hfi2_dms_tracker *child)
{
	struct hfi2_dms_transfer_handle const self_h = _tracker_to_handle(child);
	union hfi2_dms_tracker *parent;

	if (child->hdr.parent_handle.value == 0)
		return;

	parent = _handle_to_tracker(child->hdr.parent_handle);
	if (parent && parent->hdr.child_handle.value == self_h.value)
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
	child->hdr.parent_handle =
		HFI2_DMS_TRANSFER_HANDLE_NONE;
}

/*
 * Eager threshold is sampled exactly once, at bind time, into the child's
 * chain_park_at. Runtime changes to dms_eager_{sdma,pio}_max therefore do
 * not affect transfers already in flight.
 */
static bool _rx_tracker_is_eager(struct hfi2_dms_rx_tracker const *rx)
{
	return rx->total_payload <=
	       max(dms_eager_sdma_max, dms_eager_pio_max);
}

static bool _tx_tracker_is_eager(struct hfi2_dms_tx_tracker const *tx)
{
	return tx->total_payload <=
	       max(dms_eager_sdma_max, dms_eager_pio_max);
}

/* Size takes the eager SDMA path in hfi2_dms_impl_inject_write_start(). */
static bool _tx_tracker_is_eager_sdma(struct hfi2_dms_tx_tracker const *tx)
{
	return dms_eager_sdma_max &&
	       tx->total_payload > dms_eager_pio_max &&
	       tx->total_payload <= dms_eager_sdma_max;
}

static bool _tx_tracker_is_send(struct hfi2_dms_tx_tracker const *tx)
{
	return tx->write.flags & HFI2_DMS_WRITE_START_FLAG_EXT_DEST;
}

static bool _tracker_is_multi_tidset(u32 total_payload)
{
	return total_payload > HFI2_DMS_CHAIN_DATA_REQUEST_MAX_BYTES;
}

static bool _tracker_is_multi_engine(u32 total_payload)
{
	return total_payload > READ_ONCE(dms_write_single_engine_max_bytes);
}

static bool _tracker_bind(struct hfi2_dms *dms,
			  union hfi2_dms_tracker *child,
			  struct hfi2_dms_transfer_handle parent_handle)
{
	struct hfi2_dms_rx_tracker *rx;
	struct hfi2_dms_tx_tracker *tx;
	union hfi2_dms_tracker *parent;
	bool eager;
	bool parent_eager;
	bool multi_tidset;
	bool child_single_engine;
	bool parent_single_engine;
	bool is_send;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!child);

	if (parent_handle.value == 0)
		return false;

	parent = _handle_to_tracker(parent_handle);
	if (!parent) {
		/* Parent already completed/cancelled and recycled: no wait. */
		dms->counters.chain_parent_done_before_bind++;
		return false;
	}

	/* If parent has already signalled, dont attach child. */
	if (unlikely(parent->hdr.chain_signalled)) {
		dms->counters.chain_attach_after_signal++;
		return false;
	}

	if (WARN_ON_ONCE(parent->hdr.child_handle.value != 0)) {
		dms->counters.chain_attach_child_conflict++;
		return false;
	}

	child->hdr.parent_handle = parent_handle;
	child->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = _tracker_to_handle(child);
	dms->counters.chain_successfully_attached++;

	switch (child->hdr.op) {
	/*
	 * Park at DATA_START/DATA_START_LARGE for reads that are not eager
	 * and have either a read or write parent. Otherwise, park at
	 * READ_START. The destination's layout does not matter: an early
	 * release keeps the child behind every byte its parent lands, the
	 * parent's bounce edges included (_rx_tracker_inflight_has_bounce()).
	 */
	case HFI2_DMS_XFER_OP_READ:
		rx = &child->rx;
		eager = _rx_tracker_is_eager(rx);
		multi_tidset = _tracker_is_multi_tidset(rx->total_payload);

		if (!eager && parent->hdr.op == HFI2_DMS_XFER_OP_READ) {
			child->hdr.chain_park_at =
				multi_tidset
				? HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE
				: HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START;
		} else if (!eager && parent->hdr.op == HFI2_DMS_XFER_OP_WRITE) {
			/* RAW parks at DATA_START, signaled by completion. */
			child->hdr.chain_park_at =
				HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START;
		} else {
			child->hdr.chain_park_at =
				HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START;
		}
		break;
	/* Park at WRITE_START_EARLY for writes that are non-eager, use a
	 * single engine, and have a write parent. Otherwise, park at
	 * WRITE_START. The parent decides at run time whether it may release
	 * early (no bounce edges); otherwise it releases at completion.
	 */
	case HFI2_DMS_XFER_OP_WRITE:
		tx = &child->tx;
		eager = _tx_tracker_is_eager(tx);
		is_send = _tx_tracker_is_send(tx);
		if (parent->hdr.op == HFI2_DMS_XFER_OP_WRITE && !is_send) {
			child_single_engine = tx->write.is_single_engine;
			parent_single_engine = parent->tx.write.is_single_engine;
			parent_eager = _tx_tracker_is_eager(&parent->tx);

			/*
			 * eager WAW: a SEND parent is fully fenced.
			 * Eager SDMA is not ordered against the PIO send context,
			 * so an eager SDMA parent or child stays fully fenced.
			 */
			if (eager && parent_eager &&
			    !_tx_tracker_is_eager_sdma(tx) &&
			    !_tx_tracker_is_eager_sdma(&parent->tx) &&
			    !_tx_tracker_is_send(&parent->tx)) {
				child->hdr.chain_park_at =
					HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO;
				/* Parent already PIO-released: bind released. */
				if (parent->hdr.chain_pio_released) {
					child->hdr.chain_child_released = true;
					dms->counters.chain_released_write_pio_bind++;
				}
				break;
			}

			child->hdr.chain_park_at =
				(!child_single_engine || !parent_single_engine || eager)
				? HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START
				: HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY;
		} else {
			child->hdr.chain_park_at =
				HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START;
		}
		break;
	default:
		break;
	}

	return true;
}

static bool _tracker_gate(struct hfi2_dms *dms,
				   union hfi2_dms_tracker *tracker,
				   enum hfi2_dms_tracker_health_state park_health)
{
	union hfi2_dms_tracker *parent;
	struct hfi2_dms_transfer_handle child_h;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);

	if (tracker->hdr.parent_handle.value == 0)
		return false;

	child_h = _tracker_to_handle(tracker);

	/* If the parent signal already ran , tracker self-starts. */
	if (tracker->hdr.chain_child_released) {
		parent = _handle_to_tracker(tracker->hdr.parent_handle);
		tracker->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		if (parent && parent->hdr.child_handle.value == child_h.value)
			parent->hdr.child_handle =
				HFI2_DMS_TRANSFER_HANDLE_NONE;
		dms->counters.chain_child_self_start++;
		if (tracker->hdr.chain_park_at ==
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
			dms->counters.chain_released_write_pio_self_start++;
		return false;
	}

	parent = _handle_to_tracker(tracker->hdr.parent_handle);

	if (!parent) {
		/* Parent retired between bind and gate: start now. */
		dms->counters.chain_null_handle++;
		tracker->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		return false;
	}

	if (unlikely(parent->hdr.child_handle.value != child_h.value)) {
		/* Broken/mismatched link: do not park. */
		tracker->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		return false;
	}

	if (tracker->hdr.chain_park_at != park_health)
		return false;

	_tracker_health_state_set(dms, tracker, park_health);
	return true; /* park tracker here */
}

static hfi2_dms_rift_key_t _rift_key_create_err(enum hfi2_dms_rift_err const err)
{
	return (hfi2_dms_rift_key_t){.value = (HFI2_DMS_RIFT_ERR_MASK | (u16)err)};
}

static u16 _rift_key_index(hfi2_dms_rift_key_t const key)
{
	return key.value & HFI2_DMS_RIFT_IDX_MASK;
}

static u16 _rift_key_generation(hfi2_dms_rift_key_t const key)
{
	return (key.value & HFI2_DMS_RIFT_GEN_MASK) >> HFI2_DMS_RIFT_IDX_BITS;
}

static bool _rift_key_type_initiator(hfi2_dms_rift_key_t const key)
{
	return (key.value & HFI2_DMS_RIFT_KEY_TYPE_MASK);
}

static bool _rift_key_type_target(hfi2_dms_rift_key_t const key)
{
	return !_rift_key_type_initiator(key);
}

static enum hfi2_dms_xfer_type _rift_key_type(hfi2_dms_rift_key_t const key)
{
	return _rift_key_type_initiator(key) ? HFI2_DMS_XFER_TYPE_INITIATOR : HFI2_DMS_XFER_TYPE_TARGET;
}

bool _rift_key_side_rx(hfi2_dms_rift_key_t const key)
{
	return (_rift_key_index(key) < HFI2_DMS_RIFT_KEY_SIDE_RX_COUNT);
}

bool _rift_key_side_tx(hfi2_dms_rift_key_t const key)
{
	return !_rift_key_side_rx(key);
}

static enum hfi2_dms_xfer_side _rift_key_side(hfi2_dms_rift_key_t const key)
{
	return _rift_key_side_rx(key) ? HFI2_DMS_XFER_SIDE_RX : HFI2_DMS_XFER_SIDE_TX;
}
static bool _rift_key_op_read(hfi2_dms_rift_key_t const key)
{
	return (_rift_key_type_initiator(key) && _rift_key_side_rx(key)) || (_rift_key_type_target(key) && _rift_key_side_tx(key));
}

static bool _rift_key_op_write(hfi2_dms_rift_key_t const key)
{
	return !_rift_key_op_read(key);
}

static enum hfi2_dms_rift_err _rift_key_error(hfi2_dms_rift_key_t const key)
{
	return (enum hfi2_dms_rift_err)
		(((key.value & HFI2_DMS_RIFT_ERR_MASK) != 0) *
		 (key.value & ~HFI2_DMS_RIFT_ERR_MASK));
}

static enum hfi2_dms_xfer_type _rift_key_type_opposite(hfi2_dms_rift_key_t const key)
{
	enum hfi2_dms_xfer_type const type = _rift_key_type(key);

	return (enum hfi2_dms_xfer_type)(type ^ 1);
}

void _rift_init(struct hfi2_dms_rift * rift)
{
	for (u32 t = 0; t < HFI2_DMS_XFER_TYPE_COUNT; ++t) {
		rift->type[t].ticker_total = 0;
		rift->type[t].ticker_waiters = 0;
		rift->type[t].ticker_assigned = 0;
		rift->type[t].ticker_completed = 0;
		for (u32 s = 0; s < HFI2_DMS_XFER_SIDE_COUNT; ++s) {
			_ring_init(&rift->type[t].side[s].ring, HFI2_DMS_RIFT_IDX_BITS, HFI2_DMS_RIFT_IDX_SIZE / HFI2_DMS_XFER_TYPE_COUNT);
			rift->type[t].side[s].waitlist.head = NULL;
			rift->type[t].side[s].waitlist.tail = NULL;
			rift->type[t].side[s].ticker_waiters = 0;
		}
	}

	for (u16 idx = 0; idx < HFI2_DMS_ARRAY_SIZE(rift->arr); ++idx) {
		hfi2_dms_rift_key_t const key = _rift_key_create(0, idx);
		enum hfi2_dms_xfer_type const t = _rift_key_type(key);
		enum hfi2_dms_xfer_side const s = _rift_key_side(key);

		u32 const pos = _ring_produce(&rift->type[t].side[s].ring);
		rift->type[t].side[s].keys[pos] = key;

		rift->arr[idx] = NULL;
	}
}

static union hfi2_dms_tracker *_rift_search(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const remote_rift_key, u32 const remote_lid)
{
	u16 const local_is_initiator = _rift_key_type_target(remote_rift_key);
	u16 const local_is_tx = _rift_key_side_rx(remote_rift_key);

	u16 const start = local_is_initiator + local_is_tx * HFI2_DMS_RIFT_KEY_SIDE_RX_COUNT;
	u16 const stop = local_is_tx ? HFI2_DMS_ARRAY_SIZE(rift->arr) : HFI2_DMS_RIFT_KEY_SIDE_RX_COUNT;

	for (u16 idx = start; idx < stop; idx += 2) {

		if (!rift->arr[idx]) continue;

		union hfi2_dms_tracker *tracker = rift->arr[idx];
		if (tracker->hdr.remote_rift_key.value == remote_rift_key.value &&
		    tracker->hdr.remote_lid == remote_lid) {
			return tracker;
		}
	}

	return NULL;
}

bool _rift_available(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type const t, enum hfi2_dms_xfer_side const s)
{
	return (_ring_size(&rift->type[t].side[s].ring) > 0);
}

static int _rift_reserve(struct hfi2_dms_rift *rift, enum hfi2_dms_xfer_type const t, enum hfi2_dms_xfer_side const s, hfi2_dms_rift_key_t *key)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!key);

	if (!_rift_available(rift, t, s))
		return -ENOSPC;
	*key = rift->type[t].side[s].keys[_ring_consume(&rift->type[t].side[s].ring)];
	return 0;
}

static void _rift_assign(struct hfi2_dms_rift *rift, union hfi2_dms_tracker *tracker, hfi2_dms_rift_key_t const key)
{
	static u16 const sz = HFI2_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);
	enum hfi2_dms_xfer_type const t = _rift_key_type(key);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(sz <= idx);

	rift->arr[idx] = tracker;
	set_bit(idx, rift->occupied);
	rift->type[t].ticker_assigned++;
}

static union hfi2_dms_tracker *_rift_lookup(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key)
{
	static u16 const sz = HFI2_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(sz <= idx);

	union hfi2_dms_tracker *tracker = rift->arr[idx];

	if ((tracker == NULL) || (tracker->hdr.local_rift_key.value != key.value))
		return NULL;

	return tracker;
}

static void _rift_release(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(_rift_key_error(key));
	enum hfi2_dms_xfer_type const t = _rift_key_type(key);
	enum hfi2_dms_xfer_side const s = _rift_key_side(key);

	static u16 const sz = HFI2_DMS_ARRAY_SIZE(rift->arr);
	u16 const idx = _rift_key_index(key);
	DMS_BUG_ON(sz <= idx);
	DMS_BUG_ON(_ring_free(&rift->type[t].side[s].ring) == 0);

	/*
	 * Bump generation on every release. This invalidates any stale
	 * references to this key (e.g., in sdma.wait keyrings) without
	 * requiring explicit removal. _rift_lookup() will return NULL
	 * for keys with mismatched generations.
	 */
	u16 const gen = _rift_key_generation(key);
	hfi2_dms_rift_key_t const new_key = _rift_key_create(gen + 1, idx);

	rift->arr[idx] = NULL;
	clear_bit(idx, rift->occupied);
	rift->type[t].side[s].keys[_ring_produce(&rift->type[t].side[s].ring)] = new_key;
	rift->type[t].ticker_completed++;
}

static void _rift_cancel(struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const key)
{
	_rift_release(rift, key);
}

static void _rift_waitlist_add(struct hfi2_dms_rift *rift,
				   enum hfi2_dms_xfer_type const t,
				   enum hfi2_dms_xfer_side const s,
				   struct hfi2_dms_dlist_element *waiter)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!waiter);
	DMS_BUG_ON(t >= HFI2_DMS_XFER_TYPE_COUNT);
	DMS_BUG_ON(s >= HFI2_DMS_XFER_SIDE_COUNT);

	rift->type[t].side[s].ticker_waiters++;
	hfi2_dms_impl_dlist_append(&rift->type[t].side[s].waitlist, waiter);
}

static struct hfi2_dms_dlist_element *_rift_waitlist_peek(struct hfi2_dms_rift *rift,
							   enum hfi2_dms_xfer_type const t,
							   enum hfi2_dms_xfer_side const s)
{
	DMS_BUG_ON(!rift);
	DMS_BUG_ON(t >= HFI2_DMS_XFER_TYPE_COUNT);
	DMS_BUG_ON(s >= HFI2_DMS_XFER_SIDE_COUNT);

	return rift->type[t].side[s].waitlist.head;
}

/*
 * A tracker may use a rift waitlist only if its type and side name one and its
 * op matches what that waitlist's continue function dereferences: the tracker
 * union overlays the rx and tx layouts, so a mismatch would be driven through
 * the wrong one.
 */
static bool _rift_tracker_valid(union hfi2_dms_tracker const *tracker)
{
	enum hfi2_dms_xfer_type const t = tracker->hdr.type;
	enum hfi2_dms_xfer_side const s = tracker->hdr.side;

	if (t >= HFI2_DMS_XFER_TYPE_COUNT || s >= HFI2_DMS_XFER_SIDE_COUNT)
		return false;

	if (t == HFI2_DMS_XFER_TYPE_TARGET && s == HFI2_DMS_XFER_SIDE_RX)
		return tracker->rx.op == HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE ||
		       tracker->rx.op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST;
	if (t == HFI2_DMS_XFER_TYPE_TARGET && s == HFI2_DMS_XFER_SIDE_TX)
		return tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ;
	if (t == HFI2_DMS_XFER_TYPE_INITIATOR && s == HFI2_DMS_XFER_SIDE_TX)
		return tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE;
	return tracker->rx.op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ;
}

/*
 * Allocate a rift key for tracker on the waitlist named by its own
 * hdr.type/hdr.side. Returns 1 if a key was assigned (the caller drives now),
 * 0 if the tracker was parked on that waitlist, or -EINVAL if it is not valid
 * for any waitlist. A rejected tracker is neither parked nor keyed, so nothing
 * that does not belong ever reaches a waitlist.
 */
static int _rift_allocate(struct hfi2_dms_rift *rift, union hfi2_dms_tracker *tracker)
{
	int ret;
	hfi2_dms_rift_key_t key;

	DMS_BUG_ON(!rift);
	DMS_BUG_ON(!tracker);

	if (WARN_ON_ONCE(!_rift_tracker_valid(tracker)))
		return -EINVAL;

	enum hfi2_dms_xfer_type const t = tracker->hdr.type;
	enum hfi2_dms_xfer_side const s = tracker->hdr.side;

	rift->type[t].ticker_total++;

	if (_rift_waitlist_peek(rift, t, s)) {
#if HFI2_DMS_COUNTERS_ENABLE
		if (ktime_to_ns(tracker->hdr.perf.rift_wait[0]) == 0)
			tracker->hdr.perf.rift_wait[0] = ktime_get();
#endif
		_rift_waitlist_add(rift, t, s, &tracker->hdr.dlist);
		return 0;
	}

	ret = _rift_reserve(rift, t, s, &key);
	if (ret < 0) {
#if HFI2_DMS_COUNTERS_ENABLE
		if (ktime_to_ns(tracker->hdr.perf.rift_wait[0]) == 0)
			tracker->hdr.perf.rift_wait[0] = ktime_get();
#endif
		_rift_waitlist_add(rift, t, s, &tracker->hdr.dlist);
		return 0;
	}
	_rift_assign(rift, tracker, key);

	tracker->hdr.local_rift_key = key;
	return 1;
}

static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_pop(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	DMS_BUG_ON(!dms);
	struct hfi2_dms_sdma_tracker *waiter = (struct hfi2_dms_sdma_tracker *) hfi2_dms_impl_dlist_pop(&dms->sdma_waiters[engine_idx].waitlist);
	dms->sdma_waiter_count -= (s32)(waiter != NULL);

	return waiter;
}

/*
 * Drop every waiter parked on @engine_idx. The tracker blocks are freed
 * wholesale by the caller; a parked whole request's copy is not.
 */
static void _sdma_engine_waitlist_discard(struct hfi2_dms *dms,
					  enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	struct hfi2_dms_sdma_tracker *w;

	while ((w = _sdma_engine_waitlist_pop(dms, engine_idx))) {
		kfree(w->req);
		w->req = NULL;
	}
}

static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_peek(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	DMS_BUG_ON(!dms);
	return (struct hfi2_dms_sdma_tracker *) dms->sdma_waiters[engine_idx].waitlist.head;
}

static void _sdma_tracker_free(struct hfi2_dms *dms, struct hfi2_dms_sdma_tracker *sdma_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!sdma_tracker);

	kfree(sdma_tracker->req);
	sdma_tracker->req = NULL;
	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)sdma_tracker);
}

static struct hfi2_dms_sdma_tracker *_sdma_engine_waitlist_next(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	DMS_BUG_ON(!dms);

	struct hfi2_dms_sdma_tracker *waiter = _sdma_engine_waitlist_pop(dms, engine_idx);
	if (waiter) {
		_sdma_tracker_free(dms, waiter);
		return _sdma_engine_waitlist_peek(dms, engine_idx);
	}
	return NULL;
}

static void _sdma_engine_waitlist_append(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx, struct hfi2_dms_sdma_tracker *waiter)
{
	hfi2_dms_impl_dlist_append(&dms->sdma_waiters[engine_idx].waitlist, &waiter->hdr.dlist);
	dms->sdma_waiter_count += 1;
}

static void _sdma_engine_waitlist_remove(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx, struct hfi2_dms_sdma_tracker *waiter)
{
	hfi2_dms_impl_dlist_remove(&dms->sdma_waiters[engine_idx].waitlist, &waiter->hdr.dlist);
	dms->sdma_waiter_count -= 1;
}

static int _sdma_engine_waitlist_add(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx,
		hfi2_dms_sdma_inject_fn inject, struct hfi2_dms_sdma_info const *info, u64 xfer_bytes, struct hfi2_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!info);

	struct hfi2_dms_sdma_tracker *waiter = _sdma_tracker_new(dms, tx_tracker->hdr.port_idx, inject, info, xfer_bytes);
	if (!waiter) {
		return -ENOMEM;
	}
	waiter->tx_tracker = tx_tracker;

	_sdma_engine_waitlist_append(dms, engine_idx, waiter);
	return 0;
}

/*
 * Credit @credit bytes accepted for egress against @tx_tracker. A DRAINING
 * re-request re-services an already-credited region (each redrain bumps
 * generation, so it is not a wire duplicate). Without a clamp the repeated
 * debit wraps payload_remaining once the transfer is fully credited; the
 * lost-ACK STATUS fallback would then read the wrapped value, see it != 0,
 * and age the tracker out to -ETIMEDOUT. Saturate at 0 and count the event,
 * mirroring the RX-side health_remaining_qws_underflow guard.
 */
static void _sdma_tx_credit(struct hfi2_dms *dms,
			    struct hfi2_dms_tx_tracker *tx_tracker, u64 credit)
{
	tx_tracker->hdr.byte_odometer += credit;

	if (unlikely(credit > tx_tracker->payload_remaining)) {
		dms->counters.health_tx_payload_underflow++;
		tx_tracker->payload_remaining = 0;
	} else {
		tx_tracker->payload_remaining -= credit;
	}
}

/*
 * True if an SDMA inject failure can succeed on a later attempt: no room on
 * the engine (-EAGAIN), no free AHG header set or a transient pin allocation
 * failure (-ENOMEM), or the port's send context not active yet (-ECOMM).
 * Anything else -- a pin, provider or validation failure, or a submission
 * that can never fit -- fails the same way every time, so the transfer is
 * cancelled rather than left at the head of an engine's waitlist, where it
 * would block every ordered transfer behind it until the stale timeout.
 */
static bool _sdma_inject_retryable(int ret)
{
	return ret == -EAGAIN || ret == -ENOMEM || ret == -ECOMM;
}

static void _sdma_engine_waitlist_poll(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	struct hfi2_dms_sdma_tracker *waiter = _sdma_engine_waitlist_peek(dms, engine_idx);
	while (waiter) {
		struct hfi2_dms_tx_tracker *const tx_tracker = waiter->tx_tracker;
		u32 const nbytes = waiter->info.nbytes;
		int ret;

		/* Staleness check: see if the tracker has been recycled while waiting */
		if (unlikely(_rift_lookup(&dms->rift, waiter->info.local_rift_key) !=
			     (union hfi2_dms_tracker *)tx_tracker)) {
			_sdma_engine_waitlist_remove(dms, engine_idx, waiter);
			_sdma_tracker_free(dms, waiter);
			waiter = _sdma_engine_waitlist_peek(dms, engine_idx);
			continue;
		}

		if (waiter->req) {
			ret = _sdma_inject_req_fn(dms, engine_idx, waiter->req,
						  tx_tracker);
			/*
			 * An ordered request parks behind others before its size
			 * is known; one too large for a submission is replaced,
			 * where it stands, by one waiter per chunk.
			 */
			if (ret == -E2BIG) {
				dms->counters.sdma_req_fallback_per_chunk++;
				if (_sdma_tracker_new_per_chunk(dms, engine_idx,
								waiter)) {
					_sdma_engine_waitlist_remove(dms, engine_idx,
								     waiter);
					_sdma_tracker_free(dms, waiter);
					hfi2_dms_tx_tracker_cancel(dms, tx_tracker,
								   -ENOMEM);
				}
				waiter = _sdma_engine_waitlist_peek(dms, engine_idx);
				continue;
			}
			if (ret == 0)
				dms->counters.sdma_req_batched +=
					waiter->req->nchunks > 1;
		} else {
			ret = waiter->inject(dms, engine_idx, &waiter->info,
					     tx_tracker);
		}
		if (ret == 0) {
			/* Account bytes only on successful waitlist egress (matches
			 * _sdma_inject); payload_remaining hits 0 only once egressed.
			 */
			_sdma_tx_credit(dms, tx_tracker, nbytes);
			waiter = _sdma_engine_waitlist_next(dms, engine_idx);
		} else if (!_sdma_inject_retryable(ret)) {
			/*
			 * Fails the same way every time: fail the transfer, as
			 * the immediate path does, rather than block the
			 * waitlist. The cancel removes the transfer's other
			 * waiters.
			 */
			_sdma_engine_waitlist_remove(dms, engine_idx, waiter);
			_sdma_tracker_free(dms, waiter);
			hfi2_dms_tx_tracker_cancel(dms, tx_tracker, ret);
			waiter = _sdma_engine_waitlist_peek(dms, engine_idx);
		} else {
			waiter = NULL;
		}
	}
}

static void _sdma_engine_waitlist_poll_all(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);
	if (dms->sdma_waiter_count == 0) {
		return;
	}

	for (s32 i = 0; i < dms->num_engines; ++i) {
		enum hfi2_dms_sdma_engine_idx const engine_idx = (enum hfi2_dms_sdma_engine_idx) i;
		_sdma_engine_waitlist_poll(dms, engine_idx);
	}
	_sdma_engine_waitlist_poll(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY);
}

static void _sdma_inject(struct hfi2_dms *dms, hfi2_dms_sdma_inject_fn inject_fn, struct hfi2_dms_sdma_info const *info, u64 xfer_bytes)
{
	DMS_BUG_ON(!_rift_key_side_tx(info->local_rift_key));

	union hfi2_dms_tracker *tracker = _rift_lookup(&dms->rift, info->local_rift_key);
	if (!tracker) return;

	struct hfi2_dms_tx_tracker *tx_tracker = &tracker->tx;

	_tracker_health_state_set(dms, tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	enum hfi2_dms_sdma_engine_idx const engine_idx =
		_dms_sdma_engine_idx_from_entropy(dms, info->parameters.entropy);

	dms->counters.sdma_engine_select[engine_idx]++;

	/* Ordered transfer: if this engine has a parked request, append behind it
	 * to preserve per-engine FIFO under descriptor backpressure.
	 */
	if (_dms_transfer_is_ordered(tx_tracker->hdr.order_key) &&
	    !hfi2_dms_impl_dlist_empty(&dms->sdma_waiters[engine_idx].waitlist)) {
		if (_sdma_engine_waitlist_add(dms, engine_idx, inject_fn, info,
					      xfer_bytes, tx_tracker))
			hfi2_dms_tx_tracker_cancel(dms, tx_tracker, -ENOMEM);
		return;
	}

	int const ret = inject_fn(dms, engine_idx, info, tx_tracker);

	if (ret < 0 && !_sdma_inject_retryable(ret)) {
		/*
		 * Retrying the identical info cannot help (e.g. the op
		 * exceeds the per-submission capacity, or its source cannot
		 * be pinned), so fail the transfer instead of parking it on
		 * the SDMA waitlist where it would retry forever.
		 */
		hfi2_dms_tx_tracker_cancel(dms, tx_tracker, ret);
	} else if (ret < 0) {
		/* Neither sent nor queued: fail it rather than strand it. */
		if (_sdma_engine_waitlist_add(dms, engine_idx, inject_fn, info,
					      xfer_bytes, tx_tracker))
			hfi2_dms_tx_tracker_cancel(dms, tx_tracker, -ENOMEM);
	} else {
		/*
		 * Mirror the receiver's per-tidset debit (hfi2_dms_handle_data)
		 * so payload_remaining can reach 0. Only at 0 may the lost-ACK
		 * completion gates optimistically finish the transfer.
		 */
		_sdma_tx_credit(dms, tx_tracker, info->nbytes);
	}

	return;
}
/*
 * Demand-pin the pages spanning [byte_offset, byte_offset + byte_len) of the
 * provider's buffer so subsequent ->memcpy / ->next_src_run accesses are
 * safe; @writable when hardware will write the range (a tidset destination).
 * The provider decides what pinning means: a multi-segment provider is
 * pinned at registration and treats this as a no-op. The bulksvc kworker
 * may sleep here; pin_range returns no array because callers only need the
 * pin side-effect.
 */
static int _pp_pin_byte_range(struct hfi2_dms_page_provider const *pp,
			      u64 byte_offset, u64 byte_len, bool writable)
{
	unsigned int from_page;
	unsigned int npages;

	if (byte_len == 0)
		return 0;
	if (WARN_ON_ONCE(!pp || !pp->pin_range))
		return -EFAULT;

	from_page = byte_offset / PAGE_SIZE;
	npages = DIV_ROUND_UP(byte_offset + byte_len, PAGE_SIZE) - from_page;

	return pp->pin_range(pp->provider_ctx, from_page, npages, writable);
}

int hfi2_dms_single_mr_next_src_run(struct hfi2_dms_page_provider const *pp,
				    u64 byte_offset, u64 max_bytes,
				    struct hfi2_dms_run *run)
{
	struct hfi2_dms_mr *mr;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx || !run))
		return -EFAULT;
	mr = pp->provider_ctx;
	if (WARN_ON_ONCE(!mr->dma_list))
		return -EFAULT;
	/*
	 * @byte_offset is an extended-buffer coordinate (resolve_start folds
	 * in region_offset), and dma_list[0] maps extended_vaddr.addr, so the
	 * source run must be bounded by extended_vaddr.len rather than the
	 * registered user length.  pp->length (== user.len) is short by
	 * region_offset and would wrongly reject the final bytes of a buffer
	 * whose user.addr is not page-aligned.
	 */
	if (byte_offset >= mr->extended_vaddr.len || max_bytes == 0)
		return -EINVAL;

	*run = (struct hfi2_dms_run){
		.dma_pages = &mr->dma_list[byte_offset / HFI2_DMS_TID_PAGE_SIZE],
		.page_offset = byte_offset & (HFI2_DMS_TID_PAGE_SIZE - 1),
		.run_bytes = min_t(u64, mr->extended_vaddr.len - byte_offset,
				   max_bytes),
	};
	return 0;
}

void *hfi2_dms_single_mr_owner(struct hfi2_dms_page_provider const *pp)
{
	struct hfi2_dms_mr const *mr = pp->provider_ctx;

	return mr ? mr->owner : NULL;
}

int hfi2_dms_single_mr_resolve_start(struct hfi2_dms_page_provider const *pp,
				     u64 mr_offset, u32 size,
				     u64 *byte_offset_out)
{
	struct hfi2_dms_mr *mr;
	u64 byte_offset, end;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx || !byte_offset_out))
		return -EFAULT;

	mr = pp->provider_ctx;
	if (mr->mode == HFI2_DMS_MR_MODE_VADDR) {
		if (mr_offset < mr->user.addr)
			return -EINVAL;
		mr_offset -= mr->user.addr;
	}
	if (check_add_overflow(mr->region_offset, mr_offset, &byte_offset) ||
	    check_add_overflow(byte_offset, (u64)size, &end) ||
	    end > mr->extended_vaddr.len)
		return -EINVAL;

	*byte_offset_out = byte_offset;
	return 0;
}

/*
 * Pin the eager-payload range that _inject_*_start_{pio,sdma} will read
 * via provider ->memcpy (PIO) or via mr->dma_list (SDMA).  eager_bytes
 * is min(total_payload, dms_eager_*_max) for the chosen eager type; pin
 * exactly what the eager path will copy.
 */
static int _tx_tracker_pin_eager_pages(
		struct hfi2_dms_tx_tracker *tx_tracker,
		struct hfi2_dms_page_provider const *pp,
		u32 eager_bytes)
{
	if (eager_bytes == 0)
		return 0;
	return _pp_pin_byte_range(pp, tx_tracker->xfer_start_byte_offset,
				  eager_bytes, false);
}

static int _sdma_inject_data_fn(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx const engine_idx, struct hfi2_dms_sdma_info const *info, struct hfi2_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!_rift_key_side_tx(info->local_rift_key));
	DMS_BUG_ON(!tx_tracker);

	struct hfi2_dms_sdma_parameters const * parameters = &info->parameters;
	struct hfi2_dms_page_provider const *src_provider = &info->page_provider;
	/*
	 * TX side reads from local memory; receive-side write is
	 * fronted by the responder, not this inject.  See
	 * page_provider.pin_range doc for the writable contract.
	 */
	bool const writable = false;
	struct hfi2_dms_recv_chunk chunk;
	int ret;

	if (WARN_ON_ONCE(parameters->gather_count == 0 ||
			 parameters->gather_count > HFI2_DMS_DR_CHUNK_MAX_GATHER))
		return -EINVAL;

	/*
	 * One gather mechanism for every provider: ensure each element's range
	 * is resident, then hand the logical byte offsets to next_src_run via
	 * src_provider.  Pre-pinned providers no-op in pin_range.
	 */
	if (WARN_ON_ONCE(!info->page_provider.pin_range))
		return -EFAULT;

	for (u8 i = 0; i < parameters->gather_count; i++) {
		struct hfi2_dms_gather const *g = &info->gather[i];
		u64 const elem_offset = info->page_offset + g->sbuf_offset;
		u64 const start_page = elem_offset / HFI2_DMS_TID_PAGE_SIZE;
		u64 const npages = DIV_ROUND_UP(elem_offset + g->length,
						HFI2_DMS_TID_PAGE_SIZE) - start_page;

		if (npages > HFI2_DMS_SDMA_DATA_PAGES_MAX) {
			dd_dev_warn_ratelimited(dms->dd, "DMS_DIAG: sdma_inject_data npages overflow npages=%llu max=%d page_offset=%llu nbytes=%u\n",
						npages, HFI2_DMS_SDMA_DATA_PAGES_MAX,
						elem_offset, g->length);
			return -EINVAL;
		}

		ret = info->page_provider.pin_range(info->page_provider.provider_ctx,
						    start_page, npages, writable);
		if (ret < 0)
			return ret;
	}

	/*
	 * If hfi2_dms_impl_sdma_send below fails (-EAGAIN engine
	 * waitlist, -ECOMM port inactive, -ENOMEM AHG pool), the
	 * pin established by pin_range stays held intentionally:
	 * it is reused on retry via the pin_bitmap fast path, and
	 * any range not later reused is released at MR teardown
	 * by bulksvc_rb_remove walking the bitmap.  No unpin
	 * is needed.
	 */
	chunk = (struct hfi2_dms_recv_chunk){
		.tid_info = parameters->tid_info,
		.length_count =
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, info->nbytes) |
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT,
				   parameters->gather_count),
	};
	return hfi2_dms_impl_sdma_send(
		dms, engine_idx, info->page_offset,
		&chunk, 1, info->gather,
		tx_tracker->hdr.port_idx,
		tx_tracker->hdr.remote_lid, parameters->rx_id,
		tx_tracker->hdr.local_rift_key,
		parameters->generation, src_provider, parameters->entropy,
		parameters->msg_type, tx_tracker->hdr.order_key);
}

/* The source page provider a TX tracker's DATA is gathered from. */
static const struct hfi2_dms_page_provider *
_tx_tracker_src_provider(struct hfi2_dms_tx_tracker const *tx_tracker)
{
	return tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ ?
		&tx_tracker->read.access->page_provider :
		&tx_tracker->write.page_provider;
}

/*
 * Send a whole DATA_REQUEST (@req, all its recv_chunks) as one SDMA
 * submission. Pins every gather element first, like _sdma_inject_data_fn()
 * does for one chunk. Returns 0 when the engine accepted the submission and
 * -errno otherwise; see hfi2_dms_impl_sdma_send() for -EAGAIN / -E2BIG.
 */
static int _sdma_inject_req_fn(struct hfi2_dms *dms,
			       enum hfi2_dms_sdma_engine_idx const engine_idx,
			       struct hfi2_dms_sdma_req const *req,
			       struct hfi2_dms_tx_tracker *tx_tracker)
{
	struct hfi2_dms_page_provider const *pp =
		_tx_tracker_src_provider(tx_tracker);
	int ret;

	if (WARN_ON_ONCE(!pp->pin_range))
		return -EFAULT;

	/* TX reads local memory: not writable (see pin_range's contract). */
	for (u8 i = 0; i < req->ngather; i++) {
		struct hfi2_dms_gather const *g = &req->gather[i];
		u64 const elem_offset = req->page_offset + g->sbuf_offset;
		u64 const start_page = elem_offset / HFI2_DMS_TID_PAGE_SIZE;
		u64 const npages = DIV_ROUND_UP(elem_offset + g->length,
						HFI2_DMS_TID_PAGE_SIZE) - start_page;

		if (npages > HFI2_DMS_SDMA_DATA_PAGES_MAX)
			return -EINVAL;
		ret = pp->pin_range(pp->provider_ctx, start_page, npages, false);
		if (ret < 0)
			return ret;
	}

	return hfi2_dms_impl_sdma_send(dms, engine_idx, req->page_offset,
				       req->chunk, req->nchunks, req->gather,
				       tx_tracker->hdr.port_idx,
				       tx_tracker->hdr.remote_lid, req->rx_id,
				       tx_tracker->hdr.local_rift_key,
				       req->generation, pp, req->entropy,
				       req->msg_type, tx_tracker->hdr.order_key);
}

/*
 * Describe chunk @i of @req, whose gather elements start at @first_gather,
 * as a single-chunk inject.
 */
static void _sdma_req_chunk_info(struct hfi2_dms_sdma_req const *req, u8 i,
				 u8 first_gather,
				 struct hfi2_dms_tx_tracker const *tx_tracker,
				 struct hfi2_dms_sdma_info *info)
{
	struct hfi2_dms_recv_chunk const *chunk = &req->chunk[i];
	u8 const count = hfi2_dms_recv_chunk_count(chunk);

	*info = (struct hfi2_dms_sdma_info){
		.local_rift_key = req->local_rift_key,
		.page_provider = *_tx_tracker_src_provider(tx_tracker),
		.page_offset = req->page_offset,
		.nbytes = hfi2_dms_recv_chunk_length(chunk),
		.parameters = {
			.tid_info = chunk->tid_info,
			.rx_id = req->rx_id,
			.gather_count = count,
			.generation = req->generation,
			.entropy = req->entropy,
			.msg_type = req->msg_type,
		},
	};
	memcpy(info->gather, &req->gather[first_gather],
	       count * sizeof(*info->gather));
}

/*
 * Replace the parked whole request @waiter, at the head of @engine_idx's
 * waitlist, by one single-chunk waiter per chunk, in chunk order, at the
 * head: the same place in the FIFO. Returns 0 (and frees @waiter), or
 * -errno with the waitlist unchanged.
 */
static int _sdma_tracker_new_per_chunk(struct hfi2_dms *dms,
				       enum hfi2_dms_sdma_engine_idx const engine_idx,
				       struct hfi2_dms_sdma_tracker *waiter)
{
	struct hfi2_dms_sdma_req const *req = waiter->req;
	struct hfi2_dms_tx_tracker *tx_tracker = waiter->tx_tracker;
	struct hfi2_dms_sdma_tracker *chunk_waiter[HFI2_DMS_DR_MAX_CHUNKS];
	u8 next_gather = 0;
	u8 i;

	if (WARN_ON_ONCE(_sdma_engine_waitlist_peek(dms, engine_idx) != waiter))
		return -EINVAL;

	for (i = 0; i < req->nchunks; i++) {
		struct hfi2_dms_sdma_info info;

		_sdma_req_chunk_info(req, i, next_gather, tx_tracker, &info);
		next_gather += info.parameters.gather_count;
		chunk_waiter[i] = _sdma_tracker_new(dms, tx_tracker->hdr.port_idx,
						    _sdma_inject_data_fn, &info,
						    info.nbytes);
		if (!chunk_waiter[i])
			goto fail;
		chunk_waiter[i]->tx_tracker = tx_tracker;
	}

	_sdma_engine_waitlist_remove(dms, engine_idx, waiter);
	_sdma_tracker_free(dms, waiter);
	while (i--) {
		hfi2_dms_impl_dlist_push(&dms->sdma_waiters[engine_idx].waitlist,
					 &chunk_waiter[i]->hdr.dlist);
		dms->sdma_waiter_count += 1;
	}
	return 0;

fail:
	while (i--)
		_sdma_tracker_free(dms, chunk_waiter[i]);
	return -ENOMEM;
}

/*
 * Inject @req's chunks one SDMA submission each, as before requests were
 * batched: each chunk is sent, parked or credited on its own.
 */
static void _sdma_inject_req_per_chunk(struct hfi2_dms *dms,
				       struct hfi2_dms_sdma_req const *req,
				       struct hfi2_dms_tx_tracker *tx_tracker)
{
	union hfi2_dms_tracker const *const tracker =
		(union hfi2_dms_tracker *)tx_tracker;
	u8 next_gather = 0;

	for (u8 i = 0; i < req->nchunks; i++) {
		struct hfi2_dms_sdma_info info;

		_sdma_req_chunk_info(req, i, next_gather, tx_tracker, &info);
		next_gather += info.parameters.gather_count;

		_sdma_inject(dms, _sdma_inject_data_fn, &info, info.nbytes);
		/*
		 * A chunk that fails for good cancels the transfer, which
		 * releases its rift key and recycles the tracker: stop.
		 */
		if (_rift_lookup(&dms->rift, req->local_rift_key) != tracker)
			return;
	}
}

/* Park a whole request on @engine_idx's waitlist. */
static int _sdma_engine_waitlist_add_req(struct hfi2_dms *dms,
					 enum hfi2_dms_sdma_engine_idx const engine_idx,
					 struct hfi2_dms_sdma_req const *req,
					 struct hfi2_dms_tx_tracker *tx_tracker)
{
	hfi2_dms_rift_key_t const no_rift =
		_rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET);
	union hfi2_dms_tracker *tracker;
	struct hfi2_dms_sdma_tracker *waiter;
	struct hfi2_dms_sdma_req *copy;

	copy = kmemdup(req, sizeof(*req), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	tracker = hfi2_dms_impl_tracker_new(dms, tx_tracker->hdr.port_idx,
					    no_rift, 0, 0,
					    HFI2_DMS_XFER_TYPE_NONE,
					    HFI2_DMS_XFER_OP_NONE);
	if (!tracker) {
		kfree(copy);
		return -ENOMEM;
	}
	waiter = &tracker->sdma;
	waiter->inject = NULL;
	waiter->info.local_rift_key = req->local_rift_key;
	waiter->info.nbytes = req->nbytes;
	waiter->xfer_bytes = req->nbytes;
	waiter->tx_tracker = tx_tracker;
	waiter->req = copy;
	dms->counters.sdma_req_parked++;
	_sdma_engine_waitlist_append(dms, engine_idx, waiter);
	return 0;
}

/*
 * Inject a whole DATA_REQUEST as one SDMA submission: accepted whole and
 * credited once, or parked whole on the engine's waitlist. A request too
 * large for one submission is sent chunk by chunk instead. Same engine (the
 * request's entropy) and chunk order as sending the chunks one by one.
 */
static void _sdma_inject_req(struct hfi2_dms *dms,
			     struct hfi2_dms_sdma_req const *req)
{
	union hfi2_dms_tracker *tracker =
		_rift_lookup(&dms->rift, req->local_rift_key);
	struct hfi2_dms_tx_tracker *tx_tracker;
	enum hfi2_dms_sdma_engine_idx engine_idx;
	int ret;

	if (!tracker)
		return;
	tx_tracker = &tracker->tx;

	_tracker_health_state_set(dms, tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	engine_idx = _dms_sdma_engine_idx_from_entropy(dms, req->entropy);
	dms->counters.sdma_engine_select[engine_idx]++;

	/*
	 * Ordered transfer: stay behind anything already parked here. This
	 * parks before the submission is sized; the waitlist poll splits a
	 * request too large for one submission.
	 */
	if (_dms_transfer_is_ordered(tx_tracker->hdr.order_key) &&
	    !hfi2_dms_impl_dlist_empty(&dms->sdma_waiters[engine_idx].waitlist)) {
		if (_sdma_engine_waitlist_add_req(dms, engine_idx, req,
						  tx_tracker))
			hfi2_dms_tx_tracker_cancel(dms, tx_tracker, -ENOMEM);
		return;
	}

	ret = _sdma_inject_req_fn(dms, engine_idx, req, tx_tracker);
	if (ret == 0) {
		dms->counters.sdma_req_batched += req->nchunks > 1;
		_sdma_tx_credit(dms, tx_tracker, req->nbytes);
	} else if (ret == -E2BIG) {
		dms->counters.sdma_req_fallback_per_chunk++;
		_sdma_inject_req_per_chunk(dms, req, tx_tracker);
	} else if (!_sdma_inject_retryable(ret)) {
		/* Fails the same way every time: retrying cannot help. */
		hfi2_dms_tx_tracker_cancel(dms, tx_tracker, ret);
	} else if (_sdma_engine_waitlist_add_req(dms, engine_idx, req,
						 tx_tracker)) {
		hfi2_dms_tx_tracker_cancel(dms, tx_tracker, -ENOMEM);
	}
}

static void _pkt_cmd_set_dlid(union _pkt_cmd *cmd, u32 const dlid)
{
	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);
	_dms_lane_sel_set(cmd->bth, dlid);
}

struct hfi2_dms_impl_fill_state {
	struct sdma_desc *cur_desc;
	u64 page_offset;
	struct hfi2_dms_page_provider const *src_provider;
	u64 src_byte_offset;
	u64 run_bytes_remaining;
	int err;
};

static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_run_descriptors(struct sdma_desc *start_desc, u64 nbytes,
				   u64 sbuf_page_offset,
				   dma_addr_t const *run_dma, bool is_jkr);
static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_payload(struct hfi2_dms_impl_fill_state fill_state,
			   u64 nbytes, bool is_jkr);
static struct sdma_engine *
_sdma_engine_acquire(struct hfi2_dms *dms,
		     enum hfi2_dms_sdma_engine_idx engine_idx,
		     u64 ndesc_needed);
static u64 _sdma_desc_stack_finalize(struct hfi2_dms *dms,
				     struct hfi2_dms_impl_fill_state current_fill_state,
				     u64 *pad_out);
/*
 * The PBC of an SDMA packet is the first quadword of its header memory. Count
 * it, and set the test bit if requested, before the descriptors are queued,
 * because the engine reads the header once they are.
 */
static void _sdma_header_pbc_test(struct hfi2_dms *dms, void *hdr)
{
	u64 *pbc = hdr;

	*pbc = pbc_test(dms->dd, *pbc);
}

static void _sdma_engine_write_desc_stack(struct hfi2_dms *dms,
					  enum hfi2_dms_sdma_engine_idx engine_idx,
					  struct sdma_engine *sdma,
					  u64 ndesc_total,
					  u64 npadding,
					  struct hfi2_dms_ahg_header_set *ahg_set);

enum eager_type {
	EAGER_TYPE_NONE = 0,
	EAGER_TYPE_PIO,
	EAGER_TYPE_SDMA
};

/* A WRITE START has been written to PIO: release the child parked behind it. */
static void _pio_start_sent(struct hfi2_dms *dms,
			    struct hfi2_dms_transfer_handle handle)
{
	union hfi2_dms_tracker *tracker = _handle_to_live_tracker(handle);

	if (tracker && tracker->hdr.side == HFI2_DMS_XFER_SIDE_TX &&
	    tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE)
		_dms_write_signal_pio_release(dms, &tracker->tx);
}

/*
 * Send the eager START in @cmd (template, keys, lengths already set; the
 * payload starts at eager_payload, at @payload) with the first @eager_bytes
 * of the transfer.  The source provider's pio_write writes the payload
 * straight into the reserved PIO blocks, from host pages directly or, for
 * memory with no direct CPU path (dma-buf, GPU), through a small bounce
 * chunk.  The payload is zero-padded to a qword and followed by the pad and
 * the tail flit.
 *
 * The START keeps its place among the other PIO packets: behind a non-empty
 * waitlist, or when the send context has no credits, it is queued -- the
 * header copied into the waiter, the payload described by @pp and its byte
 * offset -- and built into the PIO buffer when its turn comes, if the
 * tracker is still live then.  Returns 0 (sent or queued) or -errno, after
 * which the caller fails the transfer: the START was not sent, or (-EIO
 * after a partial source copy, see @pio_write) was sent without its payload.
 */
static int _eager_start_pio_send(struct hfi2_dms *dms,
				 struct hfi2_dms_tx_tracker *tx_tracker,
				 union _pkt_cmd *cmd, u32 pkt_len_qws,
				 void *payload, u32 eager_bytes,
				 struct hfi2_dms_page_provider const *pp,
				 bool via_waitlist)
{
	u64 const hdr_qws = ((u8 *)payload - (u8 *)&cmd->lrh16bc) / sizeof(u64);
	/*
	 * The PBC declares @pkt_len_qws qwords including itself: the PBC, the
	 * header, the qword-rounded payload, the zero pad that keeps the length
	 * off the PBC test lengths, and the tail flit.
	 */
	u32 const pad_qws = pkt_len_qws - 2 - hdr_qws -
			    DIV_ROUND_UP(eager_bytes, sizeof(u64));
	int ret;

	if (!via_waitlist && _pio_waitlist_empty(dms)) {
		ret = _pio_pkt_send(dms, cmd->pio.qws, hdr_qws, pp,
				    tx_tracker->xfer_start_byte_offset,
				    eager_bytes, pad_qws + 1);
		if (ret != -EAGAIN) {
			if (!ret) {
				dms->counters.eager_tx++;
				_pio_start_sent(dms,
						_tracker_to_handle((union hfi2_dms_tracker *)
								   tx_tracker));
			}
			return ret;
		}
	}

	ret = _pio_waitlist_append_pkt(dms, cmd->pio.qws, hdr_qws, 1 + hdr_qws,
				       pp, tx_tracker->xfer_start_byte_offset,
				       eager_bytes, pad_qws + 1,
				       _tracker_to_handle((union hfi2_dms_tracker *)
							  tx_tracker));
	if (ret)
		return ret;
	dms->counters.eager_pio_queued++;
	return 0;
}

static int _inject_data_start_pio(struct hfi2_dms *dms,
				  struct hfi2_dms_tx_tracker *tx_tracker, enum eager_type const eager)
{
	u8 *pkt_buf = dms->pio_scratch;
	union _pkt_cmd *cmd = (union _pkt_cmd *)pkt_buf;
	u64 *pkt_qws = (u64 *)pkt_buf;
	u64 *tmpl;
	u8 const route_control =
		_dms_route_control_for_order_key(tx_tracker->hdr.order_key);

	if (eager != EAGER_TYPE_NONE) {
		enum hfi2_dms_msg_type const tmpl_type = HFI2_DMS_MSG_TYPE_DATA_START_EAGER;
		tmpl = (u64 *)&dms->protocol_cmd_templates
			[tx_tracker->hdr.port_idx][tmpl_type];

		cmd->pio.qws[0] = tmpl[0];
		cmd->pio.qws[1] = tmpl[1];
		cmd->pio.qws[2] = tmpl[2];
		cmd->pio.qws[3] = tmpl[3];
		cmd->pio.qws[4] = tmpl[4];

		cmd->data_start.tx_rift_key = tx_tracker->hdr.local_rift_key;
		cmd->data_start.rx_rift_key = tx_tracker->hdr.remote_rift_key;
		cmd->data_start.reserved_qw = 0;	/* the payload starts at eager_payload */

		_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);
		hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, route_control);
		_dms_destqp_rx_set(&cmd->bth[0], tx_tracker->read.metadata.rx_id);

		int ret;
		u32 const total_bytes = tx_tracker->total_payload;
		u32 const eager_bytes = min_t(u32, total_bytes, dms_eager_pio_max);
		u32 const pad_qws = _eager_pad_qws(tmpl_type, eager_bytes);
		/* The payload starts at eager_payload, hence the - 1. */
		u32 const pkt_len_qws = _pkt_len_qws(tmpl_type, eager_bytes) - 1 +
					pad_qws;

		_dms_data_start_eager_nbytes_set(cmd->bth, eager_bytes);
		_pkt_cmd_set_lengths(cmd, pkt_len_qws);

		void *payload = (void *)(pkt_buf + _msgtype_pio_payload_offset[tmpl_type] - 8);

		ret = _eager_start_pio_send(dms, tx_tracker, cmd, pkt_len_qws,
					    payload, eager_bytes,
					    &tx_tracker->read.access->page_provider,
					    false);

		if (ret)
			return ret;

		/* Sent or queued: in either case the START is on its way. */
		dms->counters.tx_sent[tmpl_type]++;
		tx_tracker->hdr.byte_odometer += eager_bytes;
		_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);
		return 0;
	}

	tmpl = (u64 *)&dms->protocol_cmd_templates
		[tx_tracker->hdr.port_idx][HFI2_DMS_MSG_TYPE_DATA_START];

	cmd->pio.qws[0] = tmpl[0];
	cmd->pio.qws[1] = tmpl[1];
	cmd->pio.qws[2] = tmpl[2];
	cmd->pio.qws[3] = tmpl[3];
	cmd->pio.qws[4] = tmpl[4];

	cmd->data_start.tx_rift_key = tx_tracker->hdr.local_rift_key;
	cmd->data_start.rx_rift_key = tx_tracker->hdr.remote_rift_key;
	cmd->data_start.reserved_qw = 0;
	cmd->data_start.eager_payload = 0;	/* no eager payload */

	_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, route_control);
	_dms_destqp_rx_set(&cmd->bth[0], tx_tracker->read.metadata.rx_id);
	{
		u32 const data_start_pkt_len_qws =
			_pkt_len_qws(HFI2_DMS_MSG_TYPE_DATA_START, 0);
		pkt_qws[data_start_pkt_len_qws]     = 0;
		pkt_qws[data_start_pkt_len_qws - 1] = 0;
	}

	/* The payload follows in DATA packets the initiator requests. */
	_tracker_health_state_set(dms,
		(union hfi2_dms_tracker *)tx_tracker,
		HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	return _inject_cmd_pio(dms, &cmd->pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

/**
 * _inject_data_start_sdma - inject eager data start via SDMA
 * @dms: dms engine
 * @tx_tracker: tx tracker
 *
 * Return:
 * 0         - success
 * -EAGAIN   - resource exhaustion (SDMA engine/credits); caller should fall back to non-eager
 * -ECOMM    - communication error (send context inactive)
 * -ENOMEM   - memory allocation failure (AHG headers)
 * -EINVAL   - invalid parameters or internal state inconsistency
 */
static int _inject_data_start_sdma(struct hfi2_dms *dms,
				   struct hfi2_dms_tx_tracker *tx_tracker)
{
	enum hfi2_dms_msg_type const tmpl_type = HFI2_DMS_MSG_TYPE_DATA_START_EAGER;
	u8 const port_idx = tx_tracker->hdr.port_idx;
	struct send_context *sc = dms->port_sctxts[port_idx];
	struct hfi2_dms_ahg_header_set *ahg_set;
	struct hfi2_dms_mem_coh *ahg_header;
	u64 *hdr;
	u64 *tmpl;
	struct hfi2_dms_impl_fill_state fill_state;
	struct sdma_desc *desc;
	struct sdma_engine *sdma;
	u64 ndesc_total, padding_needed;
	struct hfi2_dms_page_provider const *pp =
		&tx_tracker->read.access->page_provider;
	u32 const total_bytes = tx_tracker->total_payload;
	u32 const eager_bytes = min_t(u32, total_bytes, dms_eager_sdma_max);
	u32 const pad_qws = _eager_pad_qws(tmpl_type, eager_bytes);
	u32 const pkt_len_qws = _pkt_len_qws(tmpl_type, eager_bytes) - 1 +
				pad_qws;
	u8 const route_control =
		_dms_route_control_for_order_key(tx_tracker->hdr.order_key);
	int err = -EINVAL;

	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL))
		return -ENOMEM;

	if (unlikely(!dms->desc_stack || dms->num_descs == 0)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	err = _tx_tracker_pin_eager_pages(tx_tracker, pp, eager_bytes);
	if (err < 0) {
		dd_dev_warn_ratelimited(dms->dd,
			"DMS_DIAG: data_start_sdma eager pin failed ret=%d offset=%llu eager=%u\n",
			err,
			(unsigned long long)tx_tracker->xfer_start_byte_offset,
			eager_bytes);
		goto err_put_ahg;
	}

	ahg_header = &ahg_set->headers[0];
	hdr = (u64 *)ahg_header->kvaddr;

	/*
	 * protocol_cmd_templates[] is sized HFI2_DMS_MSG_TYPE_COUNT and indexed
	 * by the native msg_type ordinal.  tmpl_type is a compile-time constant
	 * here, so bound it at build time -- this both documents the invariant
	 * and actually prevents the OOB (a runtime WARN would not).
	 */
	BUILD_BUG_ON(tmpl_type >= HFI2_DMS_MSG_TYPE_COUNT);
	tmpl = (u64 *)&dms->protocol_cmd_templates[port_idx][tmpl_type];
	{
		u32 tmpl_qws = (_msgtype_pio_payload_offset[tmpl_type] +
				sizeof(u64) - 1) / sizeof(u64);
		u32 i;

		for (i = 0; i < tmpl_qws; i++)
			hdr[i] = tmpl[i];
	}

	{
		union _pkt_cmd *cmd = (union _pkt_cmd *)hdr;

		cmd->data_start.tx_rift_key = tx_tracker->hdr.local_rift_key;
		cmd->data_start.rx_rift_key = tx_tracker->hdr.remote_rift_key;
		cmd->data_start.reserved_qw = 0;	/* the payload starts at eager_payload */

		_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);
		hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, route_control);
		_dms_destqp_rx_set(&cmd->bth[0], tx_tracker->read.metadata.rx_id);
		_dms_data_start_eager_nbytes_set(cmd->bth, eager_bytes);
		_pkt_cmd_set_lengths(cmd, pkt_len_qws);
	}

	{
		u32 hdr_bytes = _msgtype_pio_payload_offset[tmpl_type] - 8;

		desc = &dms->desc_stack[0];
		*desc = (struct sdma_desc){0};
		_sdma_qw_set_byte_count(&desc->qw[0], hdr_bytes);
		_sdma_qw_set_first_desc(&desc->qw[0]);
		_sdma_qw_set_header_mode(&desc->qw[0], SDMA_AHG_NO_AHG);
		_sdma_qw_set_phy_addr(&desc->qw[0], ahg_header->phys_addr);
		desc += 1;
	}

	fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = desc,
		.src_provider = pp,
		.src_byte_offset = tx_tracker->xfer_start_byte_offset,
		.run_bytes_remaining = 0,
	};
	fill_state = hfi2_dms_impl_fill_payload(fill_state, eager_bytes,
						dms->chip_type == CHIP_JKR);
	if (fill_state.err) {
		err = fill_state.err;
		goto err_put_ahg;
	}

	{
		u32 wire_hdr = _msgtype_wire_payload_offset[tmpl_type] - 8;
		u32 pad = (sizeof(u64) - ((wire_hdr + eager_bytes) & (sizeof(u64) - 1))) & (sizeof(u64) - 1);

		pad += pad_qws * sizeof(u64);

		if (pad > 0) {
			struct sdma_desc *pad_desc = fill_state.cur_desc;

			*pad_desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&pad_desc->qw[0], pad);
			_sdma_qw_set_phy_addr(&pad_desc->qw[0], dms->zero_page.phys_addr);
			fill_state.cur_desc += 1;
		}
	}

	*fill_state.cur_desc = dms->tail_desc_template;
	if (dms->chip_type == CHIP_CYR)
		cyr_sdma_qw_set_send_ctxt_extension(&fill_state.cur_desc->qw[0], sc->hw_context);
	fill_state.cur_desc += 1;

	ndesc_total = _sdma_desc_stack_finalize(dms, fill_state, &padding_needed);
	if (unlikely(ndesc_total + padding_needed > dms->num_descs)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	sdma = _sdma_engine_acquire(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd,
			   "dms: eager sdma: no engine available, falling back\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	_sdma_header_pbc_test(dms, hdr);
	_sdma_engine_write_desc_stack(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY,
				      sdma, ndesc_total, padding_needed, ahg_set);

	dms->counters.eager_sdma_tx++;
	dms->counters.tx_sent[tmpl_type]++;
	tx_tracker->hdr.byte_odometer += eager_bytes;
	_tracker_health_state_set(dms,
		(union hfi2_dms_tracker *)tx_tracker,
		HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	return 0;

err_put_ahg:
	hfi2_dms_impl_dlist_append(
		&dms->ahg_headers[ahg_set->port_idx].free,
		&ahg_set->dlist);
	return err;
}

static int hfi2_dms_impl_inject_data_start(struct hfi2_dms *dms,
					    struct hfi2_dms_tx_tracker *tx_tracker)
{
	u32 const tbytes = tx_tracker->total_payload;

	/*
	 * The source provider's pio_write writes the eager payload; the
	 * initiator lands it through its destination's page provider
	 * (->memcpy).  Both serve any buffer, one segment or many.  A chained
	 * child gated at DATA_START asks for a non-eager DATA_START, since an
	 * eager one would bypass its gate.
	 */
	if (tx_tracker->read.parameters.flags & HFI2_DMS_READ_FLAG_NO_EAGER)
		return _inject_data_start_pio(dms, tx_tracker, EAGER_TYPE_NONE);

	if (dms_eager_pio_max && tbytes <= dms_eager_pio_max &&
	    tx_tracker->read.access->page_provider.pio_write)
		return _inject_data_start_pio(dms, tx_tracker, EAGER_TYPE_PIO);

	if (dms_eager_sdma_max && tbytes <= dms_eager_sdma_max) {
		int ret = _inject_data_start_sdma(dms, tx_tracker);

		if (ret != -EAGAIN)
			return ret;
	}

	return _inject_data_start_pio(dms, tx_tracker, EAGER_TYPE_NONE);
}

/*
 * Serve the tidset requests a READ_START_SPECULATIVE carried, as DATA_SPECULATIVE
 * so the initiator's first one promotes its speculative tidsets. @arrays holds
 * the requests' recv_chunk and gather arrays, in request order; they are gone
 * when the READ_START was deferred, and then false is returned so the caller
 * answers DATA_START instead.
 */
static bool _tx_serve_read_start_request(struct hfi2_dms *dms,
					 struct hfi2_dms_tx_tracker *tx_tracker,
					 void const *arrays)
{
	struct hfi2_dms_read_start_parameters const *p =
		&tx_tracker->read.parameters;
	struct hfi2_dms_read_start_metadata const *m = &tx_tracker->read.metadata;
	hfi2_dms_rift_key_t const key = tx_tracker->hdr.local_rift_key;
	u8 const *next = arrays;

	if (!p->tid_count || !arrays)
		return false;

	for (u8 i = 0; i < p->tid_count; i++) {
		struct hfi2_dms_spec_request const *r = &p->spec[i];
		struct hfi2_dms_recv_chunk const *chunks = (void const *)next;

		/*
		 * Serving a request can cancel the transfer (a fatal inject),
		 * releasing its key and recycling the tracker -- and @p, @m
		 * with it: serve no further request through it.
		 */
		if (_rift_lookup(&dms->rift, key) !=
		    (union hfi2_dms_tracker *)tx_tracker)
			break;
		_tx_serve_tidset_request(dms, tx_tracker, m->rx_id,
					 r->generation, m->entropy, 0,
					 HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE,
					 chunks, r->recv_chunk_count,
					 (struct hfi2_dms_gather const *)
					 &chunks[r->recv_chunk_count],
					 r->gather_count);
		next += _data_request_arrays_bytes(r->recv_chunk_count,
						   r->gather_count);
	}
	return true;
}

static int _dms_tx_rift_continue_read_start(struct hfi2_dms *dms,
					    struct hfi2_dms_tx_tracker *tx_tracker,
					    void const *arrays)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	hfi2_dms_rift_key_t const local_rift_key = tx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	bool const is_tx_key = _rift_key_side_tx(local_rift_key);
	bool const is_target_key = _rift_key_type_target(local_rift_key);
	DMS_BUG_ON(!is_tx_key);
	DMS_BUG_ON(!is_target_key);

	if (_rift_lookup(&dms->rift, local_rift_key) == NULL) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "Ignore invalid rift key 0x%04hx (%hu %hu)\n", local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	/*
	 * A speculative READ_START carries the initiator's tidset requests:
	 * serve them with DATA_SPECULATIVE, which also names this tracker to the
	 * initiator. Dispatch on the wire message alone, not
	 * bulksvc_spec_tid_enabled, which only gates whether this side starts
	 * speculative READs.
	 */
	if (tx_tracker->read.metadata.speculative &&
	    _tx_serve_read_start_request(dms, tx_tracker, arrays))
		return 0;

	/* RIFT entry is assigned; inject DATA_START (health state set inside). */
	return hfi2_dms_impl_inject_data_start(dms, tx_tracker);
}

/**
 * _inject_write_start_sdma - inject eager write start via SDMA
 * @dms: dms engine
 * @tx_tracker: tx tracker
 *
 * Return:
 * 0         - success
 * -EAGAIN   - resource exhaustion (SDMA engine/credits); caller should fall back to non-eager
 * -ECOMM    - communication error (send context inactive)
 * -ENOMEM   - memory allocation failure (AHG headers)
 * -EINVAL   - invalid parameters or internal state inconsistency
 */
static int _inject_write_start_sdma(struct hfi2_dms *dms,
				    struct hfi2_dms_tx_tracker *tx_tracker)
{
	enum hfi2_dms_msg_type const tmpl_type = HFI2_DMS_MSG_TYPE_WRITE_START_EAGER;
	u8 const port_idx = tx_tracker->hdr.port_idx;
	struct send_context *sc = dms->port_sctxts[port_idx];
	struct hfi2_dms_ahg_header_set *ahg_set;
	struct hfi2_dms_mem_coh *ahg_header;
	u64 *hdr;
	u64 *tmpl;
	struct sdma_desc *desc;
	struct hfi2_dms_impl_fill_state fill_state;
	u64 ndesc_total, padding_needed;
	struct sdma_engine *sdma;
	struct hfi2_dms_page_provider const *pp =
		&tx_tracker->write.page_provider;
	u32 const total_bytes = tx_tracker->total_payload;
	u32 const eager_bytes = min_t(u32, total_bytes, dms_eager_sdma_max);
	u32 const pad_qws = _eager_pad_qws(tmpl_type, eager_bytes);
	u32 const pkt_len_qws = _pkt_len_qws(tmpl_type, eager_bytes) + pad_qws;
	int err = -EINVAL;

	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL))
		return -ENOMEM;

	if (unlikely(!dms->desc_stack || dms->num_descs == 0)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	err = _tx_tracker_pin_eager_pages(tx_tracker, pp, eager_bytes);
	if (err < 0) {
		dd_dev_warn_ratelimited(dms->dd,
			"DMS_DIAG: write_start_sdma eager pin failed ret=%d offset=%llu eager=%u\n",
			err,
			(unsigned long long)tx_tracker->xfer_start_byte_offset,
			eager_bytes);
		goto err_put_ahg;
	}

	ahg_header = &ahg_set->headers[0];
	hdr = (u64 *)ahg_header->kvaddr;

	/*
	 * protocol_cmd_templates[] is sized HFI2_DMS_MSG_TYPE_COUNT and indexed
	 * by the native msg_type ordinal.  tmpl_type is a compile-time constant
	 * here, so bound it at build time -- this both documents the invariant
	 * and actually prevents the OOB (a runtime WARN would not).
	 */
	BUILD_BUG_ON(tmpl_type >= HFI2_DMS_MSG_TYPE_COUNT);
	tmpl = (u64 *)&dms->protocol_cmd_templates[port_idx][tmpl_type];
	{
		u32 tmpl_qws = (_msgtype_pio_payload_offset[tmpl_type] +
				sizeof(u64) - 1) / sizeof(u64);
		u32 i;

		for (i = 0; i < tmpl_qws; i++)
			hdr[i] = tmpl[i];
	}

	{
		union _pkt_cmd *cmd = (union _pkt_cmd *)hdr;

		cmd->bth[2] = (tx_tracker->hdr.local_rift_key.value << 16) |
			      (u32)tx_tracker->write.flags;

		cmd->write_start.xfer_size = tx_tracker->total_payload;
		cmd->write_start.dms_key = tx_tracker->write.dms_key;
		cmd->write_start.offset = tx_tracker->write.rx_offset;
		cmd->write_start.imm_data = tx_tracker->write.imm_data;
		cmd->write_start.order_key = tx_tracker->hdr.order_key;
		cmd->write_start.eager_nbytes = eager_bytes;
		memset(cmd->write_start.reserved, 0, sizeof(cmd->write_start.reserved));
		cmd->write_start.reserved_qw = 0;
		cmd->write_start.eager_payload = 0;
		/* Zero the padding to the end of the 15-qword header. */
		cmd->pio.qws[12] = 0;
		cmd->pio.qws[13] = 0;
		cmd->pio.qws[14] = 0;
		cmd->pio.qws[15] = 0;

		_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);
		_pkt_cmd_set_lengths(cmd, pkt_len_qws);
	}

	{
		u32 hdr_bytes = _msgtype_pio_payload_offset[tmpl_type];

		desc = &dms->desc_stack[0];
		*desc = (struct sdma_desc){0};
		_sdma_qw_set_byte_count(&desc->qw[0], hdr_bytes);
		_sdma_qw_set_first_desc(&desc->qw[0]);
		_sdma_qw_set_header_mode(&desc->qw[0], SDMA_AHG_NO_AHG);
		_sdma_qw_set_phy_addr(&desc->qw[0], ahg_header->phys_addr);
		desc += 1;
	}

	fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = desc,
		.src_provider = pp,
		.src_byte_offset = tx_tracker->xfer_start_byte_offset,
		.run_bytes_remaining = 0,
	};
	fill_state = hfi2_dms_impl_fill_payload(fill_state, eager_bytes,
						dms->chip_type == CHIP_JKR);
	if (fill_state.err) {
		err = fill_state.err;
		goto err_put_ahg;
	}

	{
		u32 wire_hdr = _msgtype_wire_payload_offset[tmpl_type];
		u32 pad = (sizeof(u64) - ((wire_hdr + eager_bytes) & (sizeof(u64) - 1))) & (sizeof(u64) - 1);

		pad += pad_qws * sizeof(u64);

		if (pad > 0) {
			struct sdma_desc *pad_desc = fill_state.cur_desc;

			*pad_desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&pad_desc->qw[0], pad);
			_sdma_qw_set_phy_addr(&pad_desc->qw[0], dms->zero_page.phys_addr);
			fill_state.cur_desc += 1;
		}
	}

	*fill_state.cur_desc = dms->tail_desc_template;
	if (dms->chip_type == CHIP_CYR)
		cyr_sdma_qw_set_send_ctxt_extension(&fill_state.cur_desc->qw[0], sc->hw_context);
	fill_state.cur_desc += 1;

	ndesc_total = _sdma_desc_stack_finalize(dms, fill_state, &padding_needed);
	if (unlikely(ndesc_total + padding_needed > dms->num_descs)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	sdma = _sdma_engine_acquire(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd, "dms: SDMA eager write_start: no engine available, falling back\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	_sdma_header_pbc_test(dms, hdr);
	_sdma_engine_write_desc_stack(dms, HFI2_DMS_SDMA_ENGINE_IDX_ANY,
				      sdma, ndesc_total, padding_needed, ahg_set);

	dms->counters.eager_sdma_tx++;
	dms->counters.tx_sent[tmpl_type]++;
	/*
	 * Eager WRITE_START payload accepted for egress: advance the liveness
	 * odometer, mirroring the eager DATA_START SDMA path. Without this the
	 * tracker sits in WAITING_FOR_REMOTE_ACK reporting a constant progress
	 * token, so a peer's status request can falsely age it out.
	 */
	tx_tracker->hdr.byte_odometer += eager_bytes;
	_tracker_health_state_set(dms,
		(union hfi2_dms_tracker *)tx_tracker,
		HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	return 0;

err_put_ahg:
	hfi2_dms_impl_dlist_append(
		&dms->ahg_headers[ahg_set->port_idx].free,
		&ahg_set->dlist);
	return err;
}

static int _inject_write_start_pio(struct hfi2_dms *dms,
				  struct hfi2_dms_tx_tracker *tx_tracker,
				  enum eager_type const eager,
				  enum hfi2_dms_msg_type msg_type,
				  bool via_waitlist)
{
	u8 *pkt_buf = dms->pio_scratch;
	union _pkt_cmd *cmd = (union _pkt_cmd *)pkt_buf;
	u64 *pkt_qws = (u64 *)pkt_buf;
	u64 *tmpl;

	if (eager != EAGER_TYPE_NONE) {

		enum hfi2_dms_msg_type const tmpl_type = HFI2_DMS_MSG_TYPE_WRITE_START_EAGER;
		tmpl = (u64 *)&dms->protocol_cmd_templates
			[tx_tracker->hdr.port_idx][tmpl_type];

		cmd->pio.qws[0] = tmpl[0];
		cmd->pio.qws[1] = tmpl[1];
		cmd->pio.qws[2] = tmpl[2];
		cmd->pio.qws[3] = tmpl[3];
		cmd->pio.qws[4] = tmpl[4];

		cmd->bth[2] = (tx_tracker->hdr.local_rift_key.value << 16) | (u32)tx_tracker->write.flags;

		cmd->write_start.xfer_size = tx_tracker->total_payload;
		cmd->write_start.dms_key = tx_tracker->write.dms_key;
		cmd->write_start.offset = tx_tracker->write.rx_offset;
		cmd->write_start.imm_data = tx_tracker->write.imm_data;
		cmd->write_start.order_key = tx_tracker->hdr.order_key;
		memset(cmd->write_start.reserved, 0, sizeof(cmd->write_start.reserved));
		cmd->write_start.reserved_qw = 0;
		cmd->write_start.eager_payload = 0;
		/* Zero the padding to the end of the 15-qword header. */
		cmd->pio.qws[12] = 0;
		cmd->pio.qws[13] = 0;
		cmd->pio.qws[14] = 0;
		cmd->pio.qws[15] = 0;

		_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);

		int ret;
		u32 const total_bytes = tx_tracker->total_payload;
		u32 const eager_bytes = min_t(u32, total_bytes, dms_eager_pio_max);
		u32 const pad_qws = _eager_pad_qws(tmpl_type, eager_bytes);
		u32 const pkt_len_qws = _pkt_len_qws(tmpl_type, eager_bytes) +
					pad_qws;

		cmd->write_start.eager_nbytes = eager_bytes;
		_pkt_cmd_set_lengths(cmd, pkt_len_qws);

		void *payload = (void *)(pkt_buf + _msgtype_pio_payload_offset[tmpl_type]);

		/*
		 * Once this START is written to PIO, now or when its waiter is
		 * sent, _pio_start_sent() releases the WRITE child parked
		 * behind it.  A START that is never sent never releases it.
		 */
		ret = _eager_start_pio_send(dms, tx_tracker, cmd, pkt_len_qws,
					    payload, eager_bytes,
					    &tx_tracker->write.page_provider,
					    via_waitlist);

		if (ret)
			return ret;

		/* Sent or queued: in either case the START is on its way. */
		dms->counters.tx_sent[tmpl_type]++;
		tx_tracker->hdr.byte_odometer += eager_bytes;
		_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);
		return 0;
	}

	tmpl = (u64 *)&dms->protocol_cmd_templates
		[tx_tracker->hdr.port_idx][msg_type];

	cmd->pio.qws[0] = tmpl[0];
	cmd->pio.qws[1] = tmpl[1];
	cmd->pio.qws[2] = tmpl[2];
	cmd->pio.qws[3] = tmpl[3];
	cmd->pio.qws[4] = tmpl[4];

	cmd->bth[2] = (tx_tracker->hdr.local_rift_key.value << 16) | (u32)tx_tracker->write.flags;

	cmd->write_start.xfer_size = tx_tracker->total_payload;
	cmd->write_start.dms_key = tx_tracker->write.dms_key;
	cmd->write_start.offset = tx_tracker->write.rx_offset;
	cmd->write_start.imm_data = tx_tracker->write.imm_data;
	cmd->write_start.order_key = tx_tracker->hdr.order_key;
	cmd->write_start.eager_nbytes = 0;
	memset(cmd->write_start.reserved, 0, sizeof(cmd->write_start.reserved));
	cmd->write_start.reserved_qw = 0;
	cmd->write_start.eager_payload = 0;	/* no eager payload */

	_pkt_cmd_set_dlid(cmd, tx_tracker->hdr.remote_lid);
	{
		u32 const write_start_pkt_len_qws =
			_pkt_len_qws(msg_type, 0);
		pkt_qws[write_start_pkt_len_qws]     = 0;
		pkt_qws[write_start_pkt_len_qws - 1] = 0;
	}

	/*
	 * The payload follows in DATA packets the target requests. A non-eager
	 * SEND can be re-injected (lost ACK) and arrive here already in
	 * WAITING_FOR_REMOTE_ACK to be checked for completion; it must stay
	 * there.
	 */
	_tracker_health_state_set(dms,
		(union hfi2_dms_tracker *)tx_tracker,
		tx_tracker->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK
			? HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK
			: HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	return _inject_cmd_pio(dms, &cmd->pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}


/*
 * True if @nbytes of the source from @byte_offset are one contiguous run.
 * An SDMA eager packet takes its payload descriptors from the source's runs
 * and must stay within one packet's descriptor limit, which a source split
 * into many segments can exceed.
 */
static bool _tx_source_is_one_run(struct hfi2_dms_page_provider const *pp,
				  u64 byte_offset, u64 nbytes)
{
	struct hfi2_dms_run run;

	return pp->next_src_run(pp, byte_offset, nbytes, &run) == 0 &&
	       run.run_bytes >= nbytes;
}

/*
 * Send a write of at most WST_PAYLOAD_MAX bytes as one WRITE_START_TINY
 * packet: the payload is copied from the source into the packet, composed on
 * the stack.  The packet is self-contained, so it takes the PIO command path
 * with the tracker's handle; it is queued on the PIO waitlist when there is no
 * send space or when @via_waitlist is set.
 */
static int _inject_write_start_tiny(struct hfi2_dms *dms,
				    struct hfi2_dms_tx_tracker *tx_tracker,
				    bool via_waitlist)
{
	enum hfi2_dms_msg_type const type = HFI2_DMS_MSG_TYPE_WRITE_START_TINY;
	struct hfi2_dms_page_provider const *pp =
		&tx_tracker->write.page_provider;
	u32 const tbytes = tx_tracker->total_payload;
	union _pkt_cmd cmd;
	u64 const *tmpl;
	int ret;

	tmpl = (u64 *)&dms->protocol_cmd_templates
		[tx_tracker->hdr.port_idx][type];

	cmd.pio.qws[0] = tmpl[0];
	cmd.pio.qws[1] = tmpl[1];
	cmd.pio.qws[2] = tmpl[2];
	cmd.pio.qws[3] = tmpl[3];
	cmd.pio.qws[4] = tmpl[4];

	cmd.bth[2] = (tx_tracker->hdr.local_rift_key.value << 16) |
		     (u32)tx_tracker->write.flags;

	cmd.write_start.xfer_size = tbytes;
	cmd.write_start.dms_key = tx_tracker->write.dms_key;
	cmd.write_start.offset = tx_tracker->write.rx_offset;
	cmd.write_start.imm_data = tx_tracker->write.imm_data;
	cmd.write_start.order_key = tx_tracker->hdr.order_key;
	cmd.write_start.eager_nbytes = tbytes;
	memset(cmd.write_start.reserved, 0, sizeof(cmd.write_start.reserved));

	/*
	 * Zero the payload qwords (reserved_qw and eager_payload at the payload offset,
	 * then qwords 12..14) and the tail flit, so the pad is zero, then copy
	 * the payload over them.  Qword 15 completes the second PIO block the
	 * header is written as; it lies past the packet length.
	 */
	cmd.write_start.reserved_qw = 0;
	cmd.write_start.eager_payload = 0;
	cmd.pio.qws[12] = 0;
	cmd.pio.qws[13] = 0;
	cmd.pio.qws[14] = 0;
	cmd.pio.qws[15] = 0;	/* sent with the header blocks, past the length */

	if (tbytes) {
		u64 const start = tx_tracker->xfer_start_byte_offset;

		ret = _tx_tracker_pin_eager_pages(tx_tracker, pp, tbytes);
		if (ret == 0)
			ret = (*pp->memcpy)(pp, start, tbytes,
					    (u8 *)&cmd + WST_PAYLOAD_OFFSET,
					    true);
		if (ret != 0) {
			dd_dev_warn_ratelimited(dms->dd,
						"DMS_DIAG: write_start_tiny source read failed ret=%d offset=%llu tbytes=%u\n",
						ret, (unsigned long long)start,
						tbytes);
			return ret < 0 ? ret : -EIO;
		}
	}

	_pkt_cmd_set_dlid(&cmd, tx_tracker->hdr.remote_lid);
	_pkt_cmd_set_lengths(&cmd,
			     _pkt_len_qws(type, max_t(u32, tbytes,
						      WST_PAYLOAD_MIN_SENT)));

	tx_tracker->hdr.byte_odometer += tbytes;
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	/*
	 * The handle lets _pio_start_sent() find this tracker and release its
	 * child once the START is written, now or from the waitlist drain.
	 */
	ret = _inject_cmd_pio(dms, &cmd.pio,
			      _tracker_to_handle((union hfi2_dms_tracker *)tx_tracker),
			      via_waitlist);
	return ret;
}

static int hfi2_dms_impl_inject_write_start(struct hfi2_dms *dms,
					    struct hfi2_dms_tx_tracker *tx_tracker,
					    enum hfi2_dms_msg_type msg_type,
					    bool via_waitlist)
{
	u32 const tbytes = tx_tracker->total_payload;

	/*
	 * WRITE_START_TINY copies the source through the page provider's
	 * ->memcpy and eager PIO writes it with ->pio_write; both serve any
	 * source, one segment or many.  TINY has no replay form, so a replay
	 * of a tiny write goes out as the non-eager WRITE_START_REPLAY.
	 */
	if (tbytes <= WST_PAYLOAD_MAX) {
		if (msg_type == HFI2_DMS_MSG_TYPE_WRITE_START)
			return _inject_write_start_tiny(dms, tx_tracker,
							via_waitlist);
		return _inject_write_start_pio(dms, tx_tracker, EAGER_TYPE_NONE,
					       msg_type, via_waitlist);
	}

	if (dms_eager_pio_max && tbytes <= dms_eager_pio_max &&
	    tx_tracker->write.page_provider.pio_write)
		return _inject_write_start_pio(dms, tx_tracker, EAGER_TYPE_PIO,
					       msg_type, via_waitlist);

	if (dms_eager_sdma_max && tbytes <= dms_eager_sdma_max &&
	    _tx_source_is_one_run(&tx_tracker->write.page_provider,
				  tx_tracker->xfer_start_byte_offset, tbytes)) {
		int ret = _inject_write_start_sdma(dms, tx_tracker);

		if (ret != -EAGAIN)
			return ret;
	}

	return _inject_write_start_pio(dms, tx_tracker, EAGER_TYPE_NONE,
				       msg_type, via_waitlist);
}

static int _dms_tx_rift_continue_write_data(struct hfi2_dms *dms, struct hfi2_dms_tx_tracker *tx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);

	hfi2_dms_rift_key_t const local_rift_key = tx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));
	DMS_BUG_ON(!_rift_key_op_write(local_rift_key));
	DMS_BUG_ON(!_rift_key_type_initiator(local_rift_key));

	if (_rift_lookup(&dms->rift, local_rift_key) == NULL) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "Ignore invalid rift key 0x%04hx (%hu %hu)\n", local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	/* Bilateral promote: see comment in _dms_rx_rift_continue_read_data. */
	if (tx_tracker->write.page_provider.promote)
		tx_tracker->write.page_provider.promote(
			tx_tracker->write.page_provider.provider_ctx);

	if (_tracker_gate(dms, (union hfi2_dms_tracker *)tx_tracker,
			  HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START) ||
	    _tracker_gate(dms, (union hfi2_dms_tracker *)tx_tracker,
			  HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY) ||
	    _tracker_gate(dms, (union hfi2_dms_tracker *)tx_tracker,
			  HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)) {
		dms->counters.chain_parked_write_start++;
		return 0; /* parked: RIFT slot retained, no inject */
	}

	/* RIFT entry is assigned; inject WRITE_START and wait for the DATA_REQUEST response. */
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	return hfi2_dms_impl_inject_write_start(dms, tx_tracker,
						HFI2_DMS_MSG_TYPE_WRITE_START,
						false);
}

/*
 * Place at most one waiter from the (t, s) waitlist. Returns true if a tracker
 * was placed on a rift key (drive succeeded) and the waitlist may hold more
 * work; false if it could not place its head this round -- because the waitlist
 * is empty, its key ring is exhausted, or its head stalled on a downstream
 * resource (e.g. a tidset) and was re-queued for a later retry.
 *
 * A "true" return is the signal the sweep in _dms_rift_poll() uses to
 * decide the sweep made progress and should run again.
 */
static bool _dms_rift_poll_waitlist_step(struct hfi2_dms *dms,
					 enum hfi2_dms_xfer_type const t,
					 enum hfi2_dms_xfer_side const s)
{
	int ret;
	struct hfi2_dms_dlist_element *waiter;
	union hfi2_dms_tracker *tracker;

	waiter = _rift_waitlist_peek(&dms->rift, t, s);
	if (!waiter)
		return false;

	tracker = container_of(waiter, union hfi2_dms_tracker, hdr.dlist);

	ret = _rift_reserve(&dms->rift, t, s, &tracker->hdr.local_rift_key);
	if (ret != 0)
		return false;

	_rift_assign(&dms->rift, tracker, tracker->hdr.local_rift_key);

	/*
	 * Latched before driving: the continue functions below can
	 * complete inline, which can cancel and recycle this tracker
	 * onto the free list, from where it may be handed out again.
	 */
	u8 const generation = tracker->hdr.generation;

	/*
	 * Dequeue before driving. A continue function can complete the
	 * transfer inline (fence-only / eager, payload_remaining == 0),
	 * whose completion handler recycles the tracker;
	 * hfi2_dms_impl_tracker_recycle() requires it be off every list.
	 * Removing it here keeps that invariant without the completion
	 * handler having to reach back into this waitlist.
	 *
	 * FIFO across a mid-drive admit is preserved: _rift_allocate() parks a
	 * newcomer behind a non-empty waitlist rather than reserving a key, so
	 * a tracker admitted while this drive runs queues after the current
	 * head, never ahead of it. The only failure paths that re-queue below
	 * fire no inline completion (they return before the completed_* gotos),
	 * so no admit runs before the re-queue. The re-poll that used to hand
	 * the freed key on inline is deferred out of this drive stack
	 * (poll_deferred).
	 */
	hfi2_dms_impl_dlist_remove(&dms->rift.type[t].side[s].waitlist,
				   &tracker->hdr.dlist);

	/*
	 * _rift_allocate() parks a tracker only on the waitlist named by its
	 * own type and side, and only when its op matches
	 * (_rift_tracker_valid()), so the union member each continue function
	 * dereferences is the right one.
	 */
	if (t == HFI2_DMS_XFER_TYPE_TARGET && s == HFI2_DMS_XFER_SIDE_RX)
		ret = _dms_rx_rift_continue_write_start(dms, &tracker->rx, NULL, NULL, 0);
	else if (t == HFI2_DMS_XFER_TYPE_TARGET && s == HFI2_DMS_XFER_SIDE_TX)
		ret = _dms_tx_rift_continue_read_start(dms, &tracker->tx, NULL);
	else if (t == HFI2_DMS_XFER_TYPE_INITIATOR && s == HFI2_DMS_XFER_SIDE_TX)
		ret = _dms_tx_rift_continue_write_data(dms, &tracker->tx);
	else
		ret = _dms_rx_rift_continue_read_data(dms, &tracker->rx);

	if (ret != 0) {
		/*
		 * A failing drive may already have cancelled and recycled the
		 * tracker (_sdma_inject -EMSGSIZE). Cancel has then released the
		 * key, so a bumped generation leaves nothing to undo; releasing
		 * again would double-free the key.
		 */
		if (tracker->hdr.generation != generation)
			return false;

		/*
		 * Otherwise the drive stalled on a downstream resource (e.g. no
		 * tidset) without completing: release the key, mark it
		 * KEY_NOT_SET, and re-queue at the TAIL so the next sweep drives
		 * the next distinct waiter and the freed key goes to whoever is
		 * now at the front -- a head blocked on a resource cannot hold
		 * the whole waitlist hostage.
		 */
		hfi2_dms_rift_key_t const local_rift_key = tracker->hdr.local_rift_key;

		tracker->hdr.local_rift_key = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET);
		_rift_release(&dms->rift, local_rift_key);
		hfi2_dms_impl_dlist_append(&dms->rift.type[t].side[s].waitlist,
					   &tracker->hdr.dlist);
		/*
		 * No key was consumed on net (reserved then released), and the
		 * head made no progress: report "no placement" so the sweep
		 * does not treat a pure stall as progress and spin.
		 */
		return false;
	}

	return true;
}

static void _dms_rift_poll(struct hfi2_dms *dms)
{
	/*
	 * Place at most one waiter from each of the four (type, side) waitlists,
	 * then sweep again, until a full sweep places nothing. Servicing a
	 * waitlist to exhaustion before moving on would let it claim every free
	 * unit of a shared downstream resource -- the tidset pool consumed
	 * inside the continue functions is global across the waitlists --
	 * starving the others. One placement per waitlist per sweep gives every
	 * waitlist an equal shot at each freed tidset while still draining all
	 * the free rift keys within a single poll. The fixed visitation order is
	 * fair because no waitlist is serviced twice before the others are
	 * serviced once.
	 *
	 * A waiter driven here can complete inline, but the completion handlers
	 * only record a re-poll request in poll_deferred (see
	 * _dms_rift_poll_request()); they never re-enter this function, so it
	 * needs no re-entrancy guard.
	 *
	 * Termination: each sweep that returns progress placed at least one
	 * waiter, which consumed one rift key; keys are bounded (128 per
	 * waitlist ring), and a stalled head is tail-re-queued (returns
	 * no-progress) so it is not re-driven within the same sweep. When no
	 * waitlist can place its head -- all empty, key-exhausted, or stalled --
	 * the sweep makes no progress and the loop exits. An inline completion
	 * that appends a fresh waiter cannot cause non-termination: placing it
	 * still requires a free key, and the key supply is finite.
	 */
	bool progress;

	do {
		progress = false;
		progress |= _dms_rift_poll_waitlist_step(dms, HFI2_DMS_XFER_TYPE_TARGET,
							 HFI2_DMS_XFER_SIDE_RX);
		progress |= _dms_rift_poll_waitlist_step(dms, HFI2_DMS_XFER_TYPE_TARGET,
							 HFI2_DMS_XFER_SIDE_TX);
		progress |= _dms_rift_poll_waitlist_step(dms, HFI2_DMS_XFER_TYPE_INITIATOR,
							 HFI2_DMS_XFER_SIDE_RX);
		progress |= _dms_rift_poll_waitlist_step(dms, HFI2_DMS_XFER_TYPE_INITIATOR,
							 HFI2_DMS_XFER_SIDE_TX);
	} while (progress);
}

/*
 * Request a rift poll from outside a drive stack. Completion and cancel bodies
 * run nested inside _dms_rift_poll()'s drive; calling _dms_rift_poll()
 * directly from there re-enters the waitlist scanner from within the frame
 * that is still iterating it. Recording the request here instead lets
 * hfi2_dms_poll() run the poll once from the top level after the drive stack
 * unwinds. Single-threaded, so no locking.
 */
static void _dms_rift_poll_request(struct hfi2_dms *dms)
{
	dms->rift.poll_deferred = true;
}

int hfi2_dms_write_data(struct hfi2_dms *dms,
		enum hfi2_dms_fabric_port_idx port_idx, u32 dest_lid,
		union hfi2_dms_key dms_key, u64 rx_offset, u32 size,
		struct hfi2_dms_page_provider page_provider, u64 mr_offset,
		u16 flags, u64 submit_flags, u64 imm_data,
		struct hfi2_dms_completion const completion, u64 const order_key,
		struct hfi2_dms_transfer_handle parent_handle,
		struct hfi2_dms_transfer_handle *out_handle)
{
	int ret;
	u64 byte_offset_from_first_page;
	struct hfi2_dms_tx_tracker * tx_tracker;

	if (WARN_ON_ONCE(dms == NULL))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.resolve_start))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.provider_ctx))
		return -EFAULT;
	if (WARN_ON(dest_lid == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(size == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(port_idx >= dms->dd->num_pports))
		return -EINVAL;

	if (ppd_same_hfi(&dms->dd->pport[port_idx], dest_lid)) {
		if (!dms->dd->loopback_enabled)
			return -EOPNOTSUPP;
		port_idx = loopback_pidx_dd(dms->dd, port_idx);
		if (!dms->port_available[port_idx])
			return -EOPNOTSUPP;
	}

	ret = page_provider.resolve_start(&page_provider, mr_offset, size,
					  &byte_offset_from_first_page);
	if (ret < 0)
		return ret;

	tx_tracker = hfi2_dms_impl_tx_tracker_write_new(dms, port_idx, size,
			byte_offset_from_first_page,
			_dms_initiator_peer(dms, dest_lid, submit_flags),
			page_provider, mr_offset, flags, submit_flags, imm_data, &completion,
			dms_key, rx_offset, order_key);
	if (!tx_tracker) {
		return -ENOMEM;
	}

	/* Bind: link child to parent and choose where it will park. */
	_tracker_bind(dms, (union hfi2_dms_tracker *)tx_tracker, parent_handle);

	dms_trace(dms_write_data, dms,
		  _tracker_to_handle((union hfi2_dms_tracker *)tx_tracker).value,
		  port_idx, dest_lid, dms_key, rx_offset, size, mr_offset,
		  flags, submit_flags, imm_data, order_key);

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)tx_tracker);
	if (ret < 0) {
		_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)tx_tracker);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
		return ret;
	}
	if (ret > 0) {
		tx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_INITIATOR].ticker_total;
		ret = _dms_tx_rift_continue_write_data(dms, tx_tracker);
		if (ret < 0) {
			/* Sever parent link before recycle. */
			_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)tx_tracker);
			_rift_release(&dms->rift, tx_tracker->hdr.local_rift_key);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
			return ret;
		}
	}

	if (out_handle)
		*out_handle = _tracker_to_handle((union hfi2_dms_tracker *)tx_tracker);

	return 0;
}

static union hfi2_dms_cmd_nack hfi2_dms_cmd_nack_make(struct hfi2_dms *dms, enum hfi2_dms_msg_type msg_type, enum hfi2_dms_err_type err_type, u8 port_idx, u32 dlid, hfi2_dms_rift_key_t rift_key)
{
	DMS_BUG_ON(!dms);

	union hfi2_dms_cmd_nack * tmpl;
	union hfi2_dms_cmd_nack cmd;
	int i;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	tmpl = (union hfi2_dms_cmd_nack *) &dms->protocol_cmd_templates[port_idx][HFI2_DMS_MSG_TYPE_NACK];
	for (i = 0; i < cmd_len_qws; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}
	cmd.info.err_type = err_type;
	cmd.info.msg_type = msg_type;
	cmd.info.rift_key = rift_key;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	_dms_lane_sel_set(cmd.bth, dlid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd.lrh16bc, _dms_route_control_unconditional());
	return cmd;
}

#define NACK_LOG_INTERVAL_MS 5000

static const char *_nack_reason_str(enum hfi2_dms_err_type reason)
{
	switch (reason) {
	case HFI2_DMS_ERR_TYPE_NONE:
		return "none";
	case HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND:
		return "client_not_found";
	case HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND:
		return "access_not_found";
	case HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION:
		return "access_range_violation";
	case HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION:
		return "transfer_size_violation";
	case HFI2_DMS_ERR_TYPE_NO_MEMORY:
		return "no_memory";
	case HFI2_DMS_ERR_TYPE_ACCESS_BUSY:
		return "access_busy";
	case HFI2_DMS_ERR_TYPE_RNR:
		return "rnr";
	default:
		return "unknown";
	}
}

static void _nack_log_flush(struct hfi2_dms *dms)
{
	if (dms->nack_log.suppressed_count > 0) {
		dms->counters.health_nack_sent++;
		dd_dev_dbg(dms->dd,
			"dms: NACK sent for dms_key %llu (%s): %llu additional identical log messages suppressed\n",
			dms->nack_log.last_dms_key,
			_nack_reason_str(dms->nack_log.last_reason),
			dms->nack_log.suppressed_count);
		dms->nack_log.suppressed_count = 0;
	}
}

static void _nack_log(struct hfi2_dms *dms, enum hfi2_dms_err_type reason,
		      union hfi2_dms_key dms_key)
{
	ktime_t now = ktime_get();
	s64 elapsed_ms = ktime_ms_delta(now, dms->nack_log.last_log_time);
	bool params_changed = (reason != dms->nack_log.last_reason ||
			       dms_key.value != dms->nack_log.last_dms_key);

	if (params_changed || elapsed_ms >= NACK_LOG_INTERVAL_MS) {
		_nack_log_flush(dms);
		dms->counters.health_nack_sent++;
		dd_dev_dbg(dms->dd,
			"dms: NACK sent for dms_key %llu (%s)\n",
			dms_key.value, _nack_reason_str(reason));
		dms->nack_log.last_log_time = now;
		dms->nack_log.last_reason = reason;
		dms->nack_log.last_dms_key = dms_key.value;
	} else {
		dms->nack_log.suppressed_count++;
	}
}

static void _inject_nack(struct hfi2_dms *dms, enum hfi2_dms_msg_type msg_type, enum hfi2_dms_err_type reason, u8 port_idx, u32 dlid, hfi2_dms_rift_key_t rift_key)
{
	union hfi2_dms_cmd_nack nack_cmd = hfi2_dms_cmd_nack_make(dms, msg_type, reason, port_idx, dlid, rift_key);
	int ret = _inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&nack_cmd,
				  HFI2_DMS_TRANSFER_HANDLE_NONE, false);
	if (ret < 0) {
		dd_dev_err(dms->dd, "Failed to send or enqueue nack packet! ret = %d\n", ret);
	}
}

static int hfi2_dms_impl_inject_read_start(struct hfi2_dms *dms,
					   struct hfi2_dms_rx_tracker *rx_tracker,
					   u32 const *spec_tidsets, u8 tid_count,
					   enum hfi2_dms_msg_type msg_type);
static void _spec_read_join(struct hfi2_dms *dms,
			    struct hfi2_dms_rx_tracker *rx_tracker,
			    hfi2_dms_rift_key_t tx_rift_key, bool resend);
static void _dms_rx_speculative_topup_burst(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker);
static bool _request_is_compact(struct hfi2_dms_read_request_chunks const *rc,
				u32 read_size_qw);
static bool _rx_tracker_spec_unlatched(struct hfi2_dms_rx_tracker const *rx_tracker);
static void _dms_rx_spec_fallback_to_legacy(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker);

static void _tracker_reinject_start(struct hfi2_dms *dms,
				    union hfi2_dms_tracker *tracker)
{
	int ret;

	/*
	 * Health-protocol re-inject: a fast_fail tracker must have been
	 * cancelled by _tracker_cancel_if_fast_fail before reaching here (every
	 * caller pre-checks it), so seeing one is a logic error -- fail loud.
	 */
	WARN_ON_ONCE(tracker->hdr.fast_fail);

	if (_rift_key_side_tx(tracker->hdr.local_rift_key)) {
		if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
			enum hfi2_dms_msg_type const t =
				HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY;

			ret = hfi2_dms_impl_inject_write_start(dms, &tracker->tx, t,
							       false);
		} else {
			ret = hfi2_dms_impl_inject_data_start(dms, &tracker->tx);
		}
	} else {
		/*
		 * An RNR NACKed READ_START_SPECULATIVE leaves the tracker
		 * holding its speculative tidsets. A legacy replay would draw
		 * a DATA_START that finds them still in use, so give them up
		 * first; the fallback sends the legacy READ_START itself.
		 */
		if (_rx_tracker_spec_unlatched(&tracker->rx)) {
			_dms_rx_spec_fallback_to_legacy(dms, &tracker->rx);
			return;
		}
		tracker->rx.hdr.entropy = 0;
		ret = hfi2_dms_impl_inject_read_start(dms, &tracker->rx, NULL, 0,
						      HFI2_DMS_MSG_TYPE_READ_START_REPLAY);
	}

	if (ret < 0) {
		_tracker_cancel(dms, tracker, ret);
		return;
	}
}

static bool _tracker_cancel_if_fast_fail(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	if (!tracker->hdr.fast_fail)
		return false;
	dms->counters.health_fast_fail_cancel++;
	_tracker_cancel(dms, tracker, -ETIMEDOUT);
	return true;
}

static void _update_tracker_backoff(struct hfi2_dms *dms,
				    union hfi2_dms_tracker *tracker)
{
	u32 const count = tracker->hdr.status_req_count + 1;
	u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS
			       << min(count, HFI2_DMS_STALE_BACKOFF_MAX_COUNT);

	tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
	tracker->hdr.status_req_count += 1;
	dms->counters.health_status_req_injected++;
}

static int _inject_status_request_many(struct hfi2_dms *dms, u8 port_idx,
				       u32 dlid,
				       hfi2_dms_rift_key_t *entries,
				       u8 count)
{
	union hfi2_dms_cmd_status_request cmd;
	union hfi2_dms_cmd_status_request *tmpl;
	int i;
	static int const cmd_len_qws = sizeof(cmd) / sizeof(u64);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(count == 0);
	DMS_BUG_ON(count > HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES);

	tmpl = (union hfi2_dms_cmd_status_request *)
		&dms->protocol_cmd_templates[port_idx][HFI2_DMS_MSG_TYPE_STATUS_REQUEST];
	for (i = 0; i < cmd_len_qws; ++i)
		cmd.qws[i] = tmpl->qws[i];

	cmd.info.count = count;
	memcpy(cmd.info.entries, entries, count * sizeof(hfi2_dms_rift_key_t));
	cmd.tail_flit = 0;

	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	_dms_lane_sel_set(cmd.bth, dlid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd.lrh16bc, _dms_route_control_unconditional());

	dms->counters.health_status_req_packets++;
	return _inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
			       HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

/*
 * Compute the IN_PROGRESS liveness token for a tracker on demand, when a status
 * request arrives -- nothing is maintained on the data critical path beyond the
 * byte_odometer that each DATA inject/land already touches. The token is
 * opaque: the requester only tests it for inequality against the previous value,
 * so it must differ iff this tracker's blocking resource did real work since the
 * last report, and stay identical for idempotent re-injects (the livelock case).
 *
 * It is state-relative: a tracker monitors only the resource its current
 * health_state depends on. For the data phase that is the byte_odometer.
 * For the global tidset wait it is a hash of this tracker's position behind the
 * waitlist head (advances as waiters ahead drain) mixed with its own rift key;
 * no kernel pointer is ever folded into a value that leaves the node.
 */
static u64 _tracker_progress_hash(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	if (tracker->hdr.health_state ==
	    HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION) {
		u64 const size = _rift_keyring_size(&dms->tidset_waiters);
		u64 pos = size;

		for (u64 i = 0; i < size; i++) {
			hfi2_dms_rift_key_t const k =
				_rift_keyring_at(&dms->tidset_waiters, (u32)i);
			if (k.value == tracker->hdr.local_rift_key.value) {
				pos = i;
				break;
			}
		}
		return (pos << 16) ^ tracker->hdr.local_rift_key.value;
	}

	return tracker->hdr.byte_odometer;
}

static void _inject_status_response(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, enum hfi2_dms_status_type type)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);

	union hfi2_dms_cmd_status cmd = *((union hfi2_dms_cmd_status *) &dms->protocol_cmd_templates[tracker->hdr.port_idx][HFI2_DMS_MSG_TYPE_STATUS_RESPONSE]);

	cmd.info.requester_rift_key = tracker->hdr.remote_rift_key;
	cmd.info.responder_rift_key = tracker->hdr.local_rift_key;
	cmd.info.type = type;
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, tracker->hdr.remote_lid);
	_dms_lane_sel_set(cmd.bth, tracker->hdr.remote_lid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd.lrh16bc, _dms_route_control_unconditional());

	if (type == HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT) {
		cmd.info.rift_tracker_ticket = tracker->hdr.local_rift_number;
		cmd.info.rift_global_assigned = dms->rift.type[tracker->hdr.type].ticker_assigned;

	} else if (type == HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS) {
		cmd.info.packet_progress = _tracker_progress_hash(dms, tracker);

	} else if (type == HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET) {
		/*
		 * Report this tracker's position behind the tidset-waitlist
		 * head, not the global free count: a tracker only makes tidset
		 * progress when waiters ahead of it drain, so the global free
		 * count would falsely signal progress from unrelated activity.
		 */
		cmd.info.tidset_progress = _tracker_progress_hash(dms, tracker);

	} else {
		return;
	}

	_inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
			HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

static void _inject_status_response_no_tracker(struct hfi2_dms *dms, u8 port_idx, u32 remote_lid, hfi2_dms_rift_key_t requester_rift_key, enum hfi2_dms_status_type type)
{
	DMS_BUG_ON(!dms);

	union hfi2_dms_cmd_status cmd = *((union hfi2_dms_cmd_status *) &dms->protocol_cmd_templates[port_idx][HFI2_DMS_MSG_TYPE_STATUS_RESPONSE]);
	cmd.info.requester_rift_key = requester_rift_key;
	cmd.info.responder_rift_key = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET);
	cmd.info.type = type;
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, remote_lid);
	_dms_lane_sel_set(cmd.bth, remote_lid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd.lrh16bc, _dms_route_control_unconditional());

	_inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
			HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

static union hfi2_dms_proto_cmd_ack hfi2_dms_proto_cmd_ack_make(struct hfi2_dms *dms, enum hfi2_dms_fabric_port_idx port_idx, u32 dlid, hfi2_dms_rift_key_t tx_rift_key, u16 flags, u64 imm_data)
{
	union hfi2_dms_proto_cmd_ack * tmpl;
	union hfi2_dms_proto_cmd_ack cmd;
	int i;

	DMS_BUG_ON(dms == NULL);

	tmpl = (union hfi2_dms_proto_cmd_ack *)
		&dms->protocol_cmd_templates[port_idx][HFI2_DMS_MSG_TYPE_ACK];

	for (i = 0; i < 5; ++i) {
		cmd.qws[i] = tmpl->qws[i];
	}

	cmd.info.tx_rift_key = tx_rift_key;
	cmd.info.flags = flags;
	cmd.info.imm_data = imm_data;
	cmd.tail_flit = 0;
	// remaining 'scb padding' qws can remain uninitialized because they do not go over the wire

	hfi2_dms_impl_pbc_dlid_set(&cmd.pbc, dlid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, dlid);
	_dms_lane_sel_set(cmd.info.bth, dlid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd.lrh16bc, _dms_route_control_unconditional());

	return cmd;
}

/*
 * A READ child gated at DATA_START waits there for its parent; an eager
 * DATA_START would land its data by CPU before that gate is consulted, and
 * the responder may already have read the source before the parent's data
 * reached it. Such a child asks for a non-eager DATA_START.
 */
static u16 _read_start_no_eager(struct hfi2_dms_rx_tracker const *rx_tracker)
{
	enum hfi2_dms_tracker_health_state const park = rx_tracker->hdr.chain_park_at;

	return park == HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START ||
	       park == HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE
		? HFI2_DMS_READ_FLAG_NO_EAGER : 0;
}

/* The READ_START body fields common to every READ_START variant. */
static void _read_start_body_set(struct hfi2_dms_read_start_parameters *body,
				 struct hfi2_dms_rx_tracker const *rx_tracker)
{
	*body = (struct hfi2_dms_read_start_parameters){
		.tbytes = rx_tracker->total_payload,
		.dms_key = rx_tracker->read.dms_key,
		.offset = rx_tracker->sbuf_start_offset,
		.flags = hfi2_dms_start_flags_set_policy(rx_tracker->read.flags |
						_read_start_no_eager(rx_tracker),
						rx_tracker->hdr.fast_fail,
						rx_tracker->hdr.stale_backoff_shift),
		.imm_data = rx_tracker->read.imm_data,
		.order_key = rx_tracker->hdr.order_key,
	};
}

/*
 * READ_START_SPECULATIVE: a READ_START that also carries the requests of the
 * already-enabled tidsets @tidsets[0, @tid_count) -- their recv_chunk and
 * gather arrays, as their DATA_REQUESTs would carry them, one request after
 * the other. Arrays that fit the HFI2_DMS_RS_INLINE_BYTES left in the control
 * HDRQ header go inline; larger ones go whole into the eager portion right
 * after that zeroed inline area.
 */
static int _inject_read_start_speculative(struct hfi2_dms *dms,
					  struct hfi2_dms_rx_tracker *rx_tracker,
					  u32 const *tidsets, u8 tid_count)
{
	enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE;
	union _pkt_cmd *cmd = (union _pkt_cmd *)dms->pio_scratch;
	u8 *dst = (u8 *)cmd + _msgtype_pio_payload_offset[t];
	u32 wire_bytes = 0;
	u32 pkt_len_qws;

	cmd->pio = dms->protocol_cmd_templates[rx_tracker->hdr.port_idx][t];
	_read_start_body_set(&cmd->read_start, rx_tracker);
	cmd->read_start.tid_count = tid_count;

	for (u8 i = 0; i < tid_count; i++) {
		struct hfi2_dms_read_request_chunks const *rc =
			&dms->read_request_chunks[tidsets[i]];

		cmd->read_start.spec[i] = (struct hfi2_dms_spec_request){
			.generation = dms->read_requests[tidsets[i]].generation,
			.recv_chunk_count = rc->load_nchunks,
			.gather_count = rc->load_ngather,
		};
		wire_bytes += _data_request_arrays_bytes(rc->load_nchunks,
							 rc->load_ngather);
	}
	if (wire_bytes > HFI2_DMS_RS_INLINE_BYTES) {
		memset(dst, 0, HFI2_DMS_RS_INLINE_BYTES);
		dst += HFI2_DMS_RS_INLINE_BYTES;
		wire_bytes += HFI2_DMS_RS_INLINE_BYTES;
	}
	for (u8 i = 0; i < tid_count; i++) {
		struct hfi2_dms_read_request_chunks const *rc =
			&dms->read_request_chunks[tidsets[i]];
		u32 const chunks_bytes =
			rc->load_nchunks * sizeof(struct hfi2_dms_recv_chunk);
		u32 const gather_bytes =
			rc->load_ngather * sizeof(struct hfi2_dms_gather);

		memcpy(dst, rc->chunk, chunks_bytes);
		memcpy(dst + chunks_bytes, rc->gather, gather_bytes);
		dst += chunks_bytes + gather_bytes;
	}

	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, rx_tracker->hdr.remote_lid);
	_dms_lane_sel_set(cmd->bth, rx_tracker->hdr.remote_lid);
	hfi2_dms_impl_lrh16bc_entropy_set(&cmd->lrh16bc, rx_tracker->hdr.entropy);
	cmd->bth[2] = (rx_tracker->hdr.local_rift_key.value << 16);

	pkt_len_qws = _pkt_cmd_test_len_pad(cmd, _pkt_len_qws(t, wire_bytes));
	_pkt_cmd_set_lengths(cmd, pkt_len_qws);

	return _inject_cmd_pio(dms, &cmd->pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

/*
 * Inject a READ_START of @msg_type, or, when @tid_count is nonzero, a
 * READ_START_SPECULATIVE carrying the requests of @spec_tidsets.
 */
static int hfi2_dms_impl_inject_read_start(struct hfi2_dms *dms,
					   struct hfi2_dms_rx_tracker *rx_tracker,
					   u32 const *spec_tidsets, u8 tid_count,
					   enum hfi2_dms_msg_type msg_type)
{
	union _pkt_cmd cmd;
	u64 *tmpl = (u64 *)&dms->protocol_cmd_templates
		[rx_tracker->hdr.port_idx][msg_type];

	if (tid_count)
		return _inject_read_start_speculative(dms, rx_tracker,
						      spec_tidsets, tid_count);

	cmd.pio.qws[0] = tmpl[0];
	cmd.pio.qws[1] = tmpl[1];
	cmd.pio.qws[2] = tmpl[2];
	cmd.pio.qws[3] = tmpl[3];
	cmd.pio.qws[4] = tmpl[4];

	_read_start_body_set(&cmd.read_start, rx_tracker);

	hfi2_dms_impl_lrh16bc_dlid_set(&cmd.lrh16bc, rx_tracker->hdr.remote_lid);
	_dms_lane_sel_set(cmd.bth, rx_tracker->hdr.remote_lid);
	cmd.bth[2] = (rx_tracker->hdr.local_rift_key.value << 16);
	hfi2_dms_impl_lrh16bc_entropy_set(&cmd.lrh16bc, rx_tracker->hdr.entropy);

	/* The 52-byte body makes a 96-byte frame, which needs the PBC test bit. */
	_pkt_cmd_set_lengths(&cmd,
			     _pkt_cmd_test_len_pad(&cmd, _pkt_len_qws(msg_type, 0)));

	return _inject_cmd_pio(dms, &cmd.pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

static bool _spec_tid_read_eligible(struct hfi2_dms_rx_tracker const *rx_tracker)
{
	return rx_tracker->hdr.op == HFI2_DMS_XFER_OP_READ &&
	       !_rx_tracker_is_eager(rx_tracker);
}

/*
 * Speculative READ: enable up to HFI2_DMS_READ_START_SPECULATIVE_TID_MAX of the
 * transfer's tidsets before the responder has joined, and send their requests
 * in the READ_START itself (READ_START_SPECULATIVE), saving the
 * DATA_START/DATA_REQUEST round trip. Each tidset is an ordinary one, enabled
 * by _tidset_enable() for any destination; it differs only in not yet knowing
 * the responder's rift key. The responder answers with DATA_SPECULATIVE, and
 * the first one promotes the tidsets to ordinary ones (_spec_read_join()).
 *
 * At most half the tidset pool may be enabled this way (spec_tidsets_available),
 * so peers that all start speculative READs at once cannot exhaust each
 * other's pools. Returns false, with nothing changed, when no tidset can be
 * enabled or the READ_START cannot be sent; the caller then issues an ordinary
 * READ_START.
 */
static bool _spec_tid_read_start(struct hfi2_dms *dms,
				 struct hfi2_dms_rx_tracker *rx_tracker)
{
	u32 tidsets[HFI2_DMS_READ_START_SPECULATIVE_TID_MAX];
	u32 const saved_sbuf_cursor = rx_tracker->sbuf_cursor;
	u32 const grant_limit =
		min_t(u32, min_t(u32, HFI2_DMS_READ_START_SPECULATIVE_TID_MAX,
				 _tidset_free_count(dms)),
		      dms->spec_tidsets_available);
	u8 granted = 0;
	int ret;

	if (DMS_WARN_ON(!_spec_tid_read_eligible(rx_tracker)))
		return false;

	if (!grant_limit || !_rift_keyring_empty(&dms->tidset_waiters))
		return false;

	while (granted < grant_limit &&
	       rx_tracker->sbuf_cursor < rx_tracker->total_payload) {
		u32 tidset;
		u32 tid_info;
		u64 nbytes;

		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);

		ret = _tidset_enable(dms, tidset, rx_tracker, &tid_info, &nbytes);
		if (ret < 0) {
			_tidset_reset(dms, tidset, HFI2_DMS_TIDSET_STATE_FREE);
			_tidset_idx_release(dms, tidset);
			break;
		}

		tidsets[granted++] = tidset;
		rx_tracker->sbuf_cursor += nbytes;
	}

	if (!granted)
		return false;

	for (u8 i = 0; i < granted; i++)
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidsets[i]);

	ret = hfi2_dms_impl_inject_read_start(dms, rx_tracker, tidsets, granted,
					      HFI2_DMS_MSG_TYPE_READ_START);
	if (ret < 0) {
		for (u8 i = 0; i < granted; i++) {
			_dms_rx_tracker_tidset_inflight_clear(rx_tracker, tidsets[i]);
			_tidset_reset(dms, tidsets[i], HFI2_DMS_TIDSET_STATE_FREE);
			_tidset_idx_release(dms, tidsets[i]);
		}
		rx_tracker->sbuf_cursor = saved_sbuf_cursor;
		return false;
	}

	dms->spec_tidsets_available -= granted;
	for (u8 i = 0; i < granted; i++)
		dms->read_requests[tidsets[i]].spec_charged = true;
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_SPECULATIVE);
	return true;
}

/*
 * Promote a speculative READ's tidsets to ordinary ones: its responder has
 * joined -- the first DATA_SPECULATIVE, or a DATA_START (it could not serve the
 * requests carried in the READ_START) named its rift key. Record it, also in
 * the in-flight tidsets enabled before it was known so their re-requests reach
 * the responder directly, and request the rest of the transfer. @resend
 * re-sends those tidsets' requests, which a DATA_START means the responder did
 * not serve.
 */
static void _spec_read_join(struct hfi2_dms *dms,
			    struct hfi2_dms_rx_tracker *rx_tracker,
			    hfi2_dms_rift_key_t tx_rift_key, bool resend)
{
	u64 bitmap = rx_tracker->tidsets_inflight_bitmap;

	if (unlikely(_rift_key_error(tx_rift_key) ||
		     !_rift_key_side_tx(tx_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		return;
	}

	rx_tracker->hdr.remote_rift_key = tx_rift_key;
	dms->counters.spec_tid_latch++;
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA);

	while (bitmap) {
		u32 const ts = __ffs64(bitmap);
		struct hfi2_dms_read_request_state *rr = &dms->read_requests[ts];

		bitmap &= bitmap - 1;
		if (rr->rx_tracker != rx_tracker)
			continue;
		if (_rift_key_error(rr->saved_remote_rift_key) ==
		    HFI2_DMS_RIFT_ERR_KEY_NOT_SET)
			rr->saved_remote_rift_key = tx_rift_key;
		if (resend && rr->state == HFI2_DMS_TIDSET_STATE_ENABLED &&
		    _inject_data_request(dms, ts, HFI2_DMS_MSG_TYPE_DATA_REQUEST) < 0)
			dms->counters.health_tidset_drain_reinject_fail++;
	}

	if (rx_tracker->sbuf_cursor < rx_tracker->total_payload)
		_dms_rx_speculative_topup_burst(dms, rx_tracker);
}

/*
 * A speculative READ whose tidset has drained without a single DATA arriving,
 * its re-requests included, cannot tell a dropped READ_START_SPECULATIVE from
 * lost DATA; both leave this state. Recover by relinquishing the tidset and
 * falling back to an ordinary READ_START.
 *
 * Not gated on bulksvc_spec_tid_enabled: the state on its own means this
 * tracker holds a speculative tidset that must be recovered regardless of the
 * module param's current value (it is runtime-switchable and must not change
 * how an already-committed transfer is handled).
 */
static bool _rx_tracker_spec_unlatched(struct hfi2_dms_rx_tracker const *rx_tracker)
{
	return rx_tracker->hdr.health_state ==
	       HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_SPECULATIVE;
}

/*
 * Drop every speculative tidset this tracker still owns and re-inject an
 * ordinary READ_START. The relinquished tidsets are DISABLED here; _tidset_reset
 * repoints their rx_tracker to disabled_rx_tracker so the DRAINING sweep cannot
 * touch this now-legacy tracker again, and each returns its budget unit at its
 * own FREE transition. The tracker acquires fresh tidsets via the ordinary
 * DATA_START path once the legacy read starts.
 */
static void _dms_rx_spec_fallback_to_legacy(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker)
{
	bool disabled_any = false;
	int ret;

	u64 bitmap = rx_tracker->tidsets_inflight_bitmap;

	/*
	 * Callers gate on _rx_tracker_spec_unlatched, so no DATA landed and no
	 * tidset was recycled: the tracker's in-flight tidsets are exactly the
	 * ones it enabled speculatively.
	 */
	while (bitmap) {
		u32 const ts = __ffs64(bitmap);

		bitmap &= bitmap - 1;
		if (dms->read_requests[ts].rx_tracker == rx_tracker &&
		    (dms->read_requests[ts].state == HFI2_DMS_TIDSET_STATE_ENABLED ||
		     dms->read_requests[ts].state == HFI2_DMS_TIDSET_STATE_DRAINING)) {
			_tidset_reset(dms, ts, HFI2_DMS_TIDSET_STATE_DISABLED);
			disabled_any = true;
		}
	}
	if (disabled_any)
		flush_wc();

	rx_tracker->tidsets_in_use = 0;
	rx_tracker->tidsets_inflight_bitmap = 0;
	rx_tracker->sbuf_cursor = 0;

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START);

	dms->counters.spec_tid_fallback_to_legacy++;

	rx_tracker->hdr.entropy = 0;
	ret = hfi2_dms_impl_inject_read_start(dms, rx_tracker, NULL, 0,
					      HFI2_DMS_MSG_TYPE_READ_START);
	if (ret < 0)
		hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -ETIMEDOUT);
}


void _ring_init(struct hfi2_dms_ring *ring, u32 arr_size_lg2, u32 max_size)
{
	DMS_BUG_ON(!ring);

	/*
	 * The ring masks backing-array indices with (1 << arr_size_lg2) - 1, so
	 * the caller's backing array MUST hold 1 << arr_size_lg2 entries, not
	 * merely max_size. Callers size the order as const_ilog2(max_size) + 1;
	 * the +1 both provides the sentinel slot that distinguishes empty from
	 * full (max_size < mask, asserted below) and guarantees the backing
	 * array is large enough that a masked index can never run off the end
	 * once head/tail advance past max_size.
	 */
	u64 const mask = (1ull << arr_size_lg2) - 1ull;

	/* max_size < mask reserves the sentinel slot (empty vs full). */
	DMS_BUG_ON(max_size >= mask);

	ring->head = 0;
	ring->tail = 0;
	ring->mask = mask;
	ring->max_size = max_size;
}

static u32 _ring_max_size(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->max_size;
}

u32 _ring_size(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->tail - ring->head;
}

static u32 _ring_free(struct hfi2_dms_ring *ring)
{
	return _ring_max_size(ring) - _ring_size(ring);
}

static bool _ring_empty(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	return ring->head == ring->tail;
}

static u32 _ring_tail(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	DMS_BUG_ON(_ring_empty(ring));
	return (ring->tail - 1) & ring->mask;
}

static u32 _ring_head(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(!ring);
	DMS_BUG_ON(_ring_empty(ring));
	return ring->head & ring->mask;
}

static u32 _ring_index(struct hfi2_dms_ring *ring, u32 pos)
{
	DMS_BUG_ON(pos > _ring_size(ring));
	return (ring->head + pos) & ring->mask;
}

// adds the element to the ring, then returns the _index_ of that element
static u32 _ring_produce(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_free(ring) == 0);
	return (ring->tail++) & ring->mask;
}

static u32 _ring_produce_front(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_free(ring) == 0);
	ring->head -= 1;
	return ring->head & ring->mask;
}

// returns the _index_ of the first element in the ring, then removes that element
u32 _ring_consume(struct hfi2_dms_ring *ring)
{
	DMS_BUG_ON(_ring_empty(ring));
	return (ring->head++) & ring->mask;
}


void _rift_keyring_init(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	_ring_init(&keyring->ring, HFI2_DMS_RIFT_IDX_BITS+1, HFI2_DMS_RIFT_IDX_SIZE);
}

void _rift_keyring_add(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_free(&keyring->ring) == 0);
	u32 const idx = _ring_produce(&keyring->ring);
	keyring->arr[idx] = key;
}

void _rift_keyring_add_front(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_free(&keyring->ring) == 0);
	u32 const idx = _ring_produce_front(&keyring->ring);
	keyring->arr[idx] = key;
}

u64 _rift_keyring_size(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	return _ring_size(&keyring->ring);
}

bool _rift_keyring_empty(struct hfi2_dms_rift_keyring *keyring)
{
	return _ring_empty(&keyring->ring);
}

hfi2_dms_rift_key_t _rift_keyring_tail(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_empty(&keyring->ring));
	u32 const idx = _ring_tail(&keyring->ring);
	return keyring->arr[idx];
}

hfi2_dms_rift_key_t _rift_keyring_head(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	DMS_BUG_ON(_ring_empty(&keyring->ring));
	u32 const idx = _ring_head(&keyring->ring);
	return keyring->arr[idx];
}

hfi2_dms_rift_key_t _rift_keyring_peek(struct hfi2_dms_rift_keyring *keyring)
{
	return _rift_keyring_head(keyring);
}

hfi2_dms_rift_key_t _rift_keyring_at(struct hfi2_dms_rift_keyring *keyring, u32 pos)
{
	DMS_BUG_ON(!keyring);
	u32 const idx = _ring_index(&keyring->ring, pos);
	return keyring->arr[idx];
}

void _rift_keyring_set(struct hfi2_dms_rift_keyring *keyring, u64 pos, hfi2_dms_rift_key_t const key)
{
	DMS_BUG_ON(!keyring);
	u32 const idx = _ring_index(&keyring->ring, pos);
	keyring->arr[idx] = key;
}

void _rift_keyring_advance(struct hfi2_dms_rift_keyring *keyring)
{
	DMS_BUG_ON(!keyring);
	_ring_consume(&keyring->ring);
}

bool _rift_keyring_remove(struct hfi2_dms_rift_keyring *keyring, hfi2_dms_rift_key_t const key)
{
	// PRE - no duplicate ring entries
	DMS_BUG_ON(!keyring);
	u64 const count = _rift_keyring_size(keyring);

	if (count == 0)
		return false;

	if (_rift_keyring_head(keyring).value == key.value) {
		// special case: remove from head
		keyring->ring.head += 1;
		return true;
	}

	if (_rift_keyring_tail(keyring).value == key.value) {
		// special case: remove from tail
		keyring->ring.tail -= 1;
		return true;
	}

	// general case: remove from middle; must iterate entire ring in order to "compact" the ring after
	// potentially removing a middle entry.

	u64 cancel = 0;
	for (u64 i = 0; i < count; ++i) {
		hfi2_dms_rift_key_t const cur = _rift_keyring_at(keyring, i);
		if (cur.value == key.value) {
			cancel += 1;
		} else {
			_rift_keyring_set(keyring, i - cancel, cur);
		}
	}
	keyring->ring.tail -= cancel;

	return cancel > 0;
}

static void _tidset_free_then_poll_waiters(struct hfi2_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);

	/*
	 * Return the speculative-budget unit at the tidset's true FREE
	 * transition -- the only point the pool can actually re-hand this
	 * tidset out. Doing it here (not at cancel or fallback) keeps
	 * spec_tidsets_available from ever exceeding the real free count.
	 */
	if (dms->read_requests[tid_set].spec_charged) {
		dms->spec_tidsets_available += 1;
		dms->read_requests[tid_set].spec_charged = false;
	}

	/* Always release to global free stack (caller may have already set state FREE) */
	_tidset_idx_release(dms, tid_set);

	dms->read_requests[tid_set].state = HFI2_DMS_TIDSET_STATE_FREE;

	_service_global_tidset_waiters(dms);

	if (dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_FREE) {
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
	}
}

static int _eager_rx_copy_prefix(struct hfi2_dms_rx_tracker *rx_tracker,
				 enum hfi2_dms_msg_type msg_type,
				 void *hbuf, void *ebuf, u32 prefix_bytes)
{
	u32 const inline_max = 120 - (_msgtype_wire_payload_offset[msg_type] - 8);
	u32 const hdrq_copy = min(prefix_bytes, inline_max);
	u32 const ebuf_copy = prefix_bytes - hdrq_copy;
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	int ret;

	ret = (pp->memcpy)(pp, rx_tracker->rbuf_start_offset, hdrq_copy, hbuf,
			 false);
	if (ret != 0)
		return -EIO;

	if (ebuf_copy > 0) {
		if (DMS_WARN_ON(!ebuf))
			return -EINVAL;
		ret = (pp->memcpy)(pp, rx_tracker->rbuf_start_offset + hdrq_copy,
				 ebuf_copy, ebuf, false);
		if (ret != 0)
			return -EIO;
	}
	return 0;
}

/*
 * Eager-only WRITE_START: copy @nbytes of the payload at @payload to the start
 * of the destination with a single copy.  @payload is in the eager buffer
 * (WRITE_START_EAGER, ebuf + WSE_EBUF_PAYLOAD_OFFSET) or in the header queue
 * (WRITE_START_TINY).
 */
static int _wse_rx_copy(struct hfi2_dms_rx_tracker *rx_tracker,
			void *payload, u32 nbytes)
{
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	int ret;

	/* Explicit dereference: memcpy may be a function-like macro. */
	ret = (*pp->memcpy)(pp, rx_tracker->rbuf_start_offset, nbytes, payload,
			    false);
	return ret ? -EIO : 0;
}

/*
 * Returns true in two distinct senses: an empty inflight_bitmap means the
 * caller has no in-flight peer tidset to align with, so *entropy is a fresh
 * round-robin pick (not an inherited value); a non-empty bitmap returns true
 * only when every in-flight tidset shares one saved_entropy, in which case
 * *entropy is that shared value. false means in-flight tidsets disagree.
 * Callers that gate on tidsets_in_use > 0 before invoking this (guaranteeing
 * inflight_bitmap != 0, since the two are always kept in lockstep by
 * _dms_rx_tracker_tidset_inflight_set/_clear) only ever observe the
 * shared-or-disagree outcome, never the fresh-pick branch.
 */
static bool _dms_read_requests_inflight_entropy_narrowed(struct hfi2_dms *dms,
							 u64 inflight_bitmap, u16 *entropy)
{
	unsigned int pos;
	u16 prev_entropy;

	if (inflight_bitmap == 0) {
		*entropy = _dms_entropy_next(dms);
		return true;
	}

	pos = __ffs64(inflight_bitmap);
	prev_entropy = dms->read_requests[pos].saved_entropy;
	inflight_bitmap ^= (1ULL << pos);

	while (inflight_bitmap) {
		pos = __ffs64(inflight_bitmap);
		if (prev_entropy != dms->read_requests[pos].saved_entropy)
			return false;
		inflight_bitmap ^= (1ULL << pos);
	}

	*entropy = prev_entropy;
	return true;
}

/*
 * True if any of @rx_tracker's in-flight tidsets has bounce edges. Those
 * edges reach the destination only when software copies them out at the
 * tidset's completion, after every byte hardware placed for it -- so a
 * chained child riding the same SDMA engine behind this tidset could land
 * its own bytes first and then be overwritten by the copy-out. Early READ
 * release must wait until no such tidset is in flight.
 */
static bool _rx_tracker_inflight_has_bounce(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker const *rx_tracker)
{
	u64 bitmap = rx_tracker->tidsets_inflight_bitmap;

	while (bitmap) {
		unsigned int const pos = __ffs64(bitmap);

		if (dms->read_requests[pos].has_bounce)
			return true;
		bitmap &= bitmap - 1;
	}
	return false;
}

static int _dms_rx_rift_continue_read_data(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	hfi2_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(local_rift_key));

	if (_rift_lookup(&dms->rift, local_rift_key) == NULL) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, local_rift_key.value, _rift_key_generation(local_rift_key), _rift_key_index(local_rift_key));
		return 0;
	}

	/*
	 * Bilateral promote: fire on the initiator side just before
	 * READ_START goes on the wire, mirroring the responder-side
	 * fire in hfi2_dms_impl_handle_read_start. The callback is a
	 * non-blocking hint that this MR is now hot; NULL-safe for
	 * providers without proactive pinning (verbs, etc.).
	 */
	if (rx_tracker->page_provider.promote)
		rx_tracker->page_provider.promote(rx_tracker->page_provider.provider_ctx);

	/*
	 * Speculative TID is the preferred protocol if all conditions are satisfied.
	 */
	if (bulksvc_spec_tid_enabled && _spec_tid_read_eligible(rx_tracker)) {
		if (rx_tracker->hdr.parent_handle.value == 0) {
			rx_tracker->hdr.entropy = _dms_entropy_next(dms);
			if (_spec_tid_read_start(dms, rx_tracker))
				return 0;
		} else { /* chaining */
			union hfi2_dms_tracker *parent =
				_handle_to_tracker(rx_tracker->hdr.parent_handle);
			struct hfi2_dms_transfer_handle child_h =
				_tracker_to_handle((union hfi2_dms_tracker *)rx_tracker);

			if (!parent || parent->hdr.child_handle.value != child_h.value) {
				/* Parent retired between bind and gate, or link broken */
				dms->counters.chain_null_handle += (!parent);
				rx_tracker->hdr.parent_handle =
					HFI2_DMS_TRANSFER_HANDLE_NONE;
				rx_tracker->hdr.entropy = _dms_entropy_next(dms);
				if (_spec_tid_read_start(dms, rx_tracker))
					return 0;

			/* The parent has requested all of its payload. */
			} else if (parent->hdr.op == HFI2_DMS_XFER_OP_READ &&
					!_rx_tracker_is_eager(&parent->rx) &&
					parent->rx.sbuf_cursor >= parent->rx.total_payload &&
					!_rx_tracker_inflight_has_bounce(dms, &parent->rx)) {
				union hfi2_dms_tracker *child =
					(union hfi2_dms_tracker *)rx_tracker;
				u64 bitmap = parent->rx.tidsets_inflight_bitmap;
				u16 *entropy = &rx_tracker->hdr.entropy;
				bool narrowed;

				narrowed = _dms_read_requests_inflight_entropy_narrowed(dms, bitmap,
											entropy);
				if (narrowed && _spec_tid_read_start(dms, rx_tracker)) {
					_tracker_detach_from_parent(dms, child);
					/*
					 * Inherited entropy only needs to order
					 * this burst behind the parent's
					 * remaining requests, not any later
					 * request this child makes on its own.
					 * Same-engine FIFO + GBN guarantee the
					 * parent's remaining data is delivered
					 * before this child's own residual
					 * DATA_REQUESTs can fire, so clear the
					 * inherited-entropy flag now: any
					 * residual request is free to rotate to
					 * a fresh engine instead of pinning to
					 * the parent's.
					 */
					child->rx.chain_inherit_valid = false;
					return 0;
				}
			}
		}
	}
	rx_tracker->hdr.entropy = 0;

	/* Park only if READ_START is this child's gate; the gate also self-starts
	 * (and severs links) for an already-released child bound elsewhere. */
	if (_tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
			  HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START)) {
		dms->counters.chain_parked_read++;
		return 0; /* parked: RIFT slot retained, no inject */
	}

	/* RIFT entry is assigned; inject READ_START and wait for the DATA_START response. */
	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START);

	return hfi2_dms_impl_inject_read_start(dms, rx_tracker, NULL, 0,
					       HFI2_DMS_MSG_TYPE_READ_START);
}

static void _dms_rx_tracker_tidset_inflight_set(struct hfi2_dms_rx_tracker *rx_tracker,
						u32 const tidset_idx)
{
	if (WARN_ON_ONCE(!rx_tracker))
		return;
	if (WARN_ON_ONCE(tidset_idx >= HFI2_DMS_TID_SET_IDX_COUNT))
		return;
	if (WARN_ON_ONCE(rx_tracker->tidsets_in_use > HFI2_DMS_TRACKER_TIDSET_MAX))
		return;
	if (WARN_ON_ONCE(!!(rx_tracker->tidsets_inflight_bitmap & (1ULL << tidset_idx))))
		return;

	rx_tracker->tidsets_inflight_bitmap ^= (1ULL << tidset_idx);
	rx_tracker->tidsets_in_use += 1;
}

static void _dms_rx_tracker_tidset_inflight_clear(struct hfi2_dms_rx_tracker *rx_tracker,
						  u32 const tidset_idx)
{
	if (WARN_ON_ONCE(!rx_tracker))
		return;
	if (WARN_ON_ONCE(tidset_idx >= HFI2_DMS_TID_SET_IDX_COUNT))
		return;
	if (WARN_ON_ONCE(!rx_tracker->tidsets_in_use))
		return;
	if (WARN_ON_ONCE(!(rx_tracker->tidsets_inflight_bitmap & (1ULL << tidset_idx))))
		return;

	rx_tracker->tidsets_inflight_bitmap ^= (1ULL << tidset_idx);
	rx_tracker->tidsets_in_use -= 1;
}

static int _dms_rx_rift_continue_write_start(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, void *hbuf, void *ebuf, u32 const eager_nbytes)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	int err = 0;
	hfi2_dms_rift_key_t const local_rift_key = rx_tracker->hdr.local_rift_key;

	if (_rift_key_error(local_rift_key) != HFI2_DMS_RIFT_ERR_KEYLESS) {
		DMS_BUG_ON(_rift_key_error(local_rift_key));

		if (!_rift_lookup(&dms->rift, local_rift_key)) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "(%d) Ignore invalid rx rift key 0x%04x (%u %u)\n",
				   __LINE__, local_rift_key.value,
				   _rift_key_generation(local_rift_key),
				   _rift_key_index(local_rift_key));
			return 0;
		}
	}

	DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

	if (rx_tracker->payload_remaining == 0) {
		/* Complete using fence only. */

		dms->counters.eager_rx++;
		goto completed_success;
	}

	if (hbuf) {
		/*
		 * Eager: the packet carries the first eager_nbytes of the
		 * payload, or all of it. Land that prefix by CPU and request
		 * the rest.
		 */
		u32 const prefix = min_t(u32, rx_tracker->total_payload,
					 eager_nbytes);

		err = _wse_rx_copy(rx_tracker, hbuf, prefix);
		if (err != 0)
			goto completed_error;

		dms->counters.eager_rx++;
		rx_tracker->hdr.byte_odometer += prefix;
		rx_tracker->payload_remaining -= prefix;
		if (rx_tracker->payload_remaining == 0)
			goto completed_success;

		rx_tracker->sbuf_cursor = prefix;
	}

	/*
	 * The tidsets request the payload not yet delivered; any sub-quadword
	 * edges, the start or end of the buffer included, land through the
	 * tidset bounce page.
	 */
	_dms_rx_issue_data_request_burst(dms, rx_tracker, false);
	return 0;

completed_success:
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, true);
	return 0;

completed_error:
	rx_tracker->payload_remaining = 0;
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, err, true);
	return 0;
}

int hfi2_dms_read_data(struct hfi2_dms *dms,
		enum hfi2_dms_fabric_port_idx port_idx, u32 src_lid,
		union hfi2_dms_key dms_key, u64 key_offset_or_vaddr, u32 size,
		struct hfi2_dms_page_provider page_provider, u64 mr_offset,
		u16 flags, u64 submit_flags, u64 imm_data,
		struct hfi2_dms_completion const completion,
		u64 const order_key,
		struct hfi2_dms_transfer_handle parent_handle,
		struct hfi2_dms_transfer_handle *out_handle)
{
	int ret;
	u64 start, end;
	u64 starting_rbuf_offset;
	struct hfi2_dms_rx_tracker *rx_tracker;

	if (WARN_ON_ONCE(!dms))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.resolve_start))
		return -EFAULT;
	if (WARN_ON_ONCE(!page_provider.provider_ctx))
		return -EFAULT;
	if (WARN_ON(src_lid == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(size == 0)) {
		return -EINVAL;
	}
	if (WARN_ON(port_idx >= dms->dd->num_pports))
		return -EINVAL;

	start = dms_rdtsc();
	dms->counters.sending_first_rr = ktime_get();

	if (ppd_same_hfi(&dms->dd->pport[port_idx], src_lid)) {
		if (!dms->dd->loopback_enabled)
			return -EOPNOTSUPP;
		port_idx = loopback_pidx_dd(dms->dd, port_idx);
		if (!dms->port_available[port_idx])
			return -EOPNOTSUPP;
	}

	if (!dms->port_available[port_idx])
		return -ENOLINK;

	ret = page_provider.resolve_start(&page_provider, mr_offset, size,
					  &starting_rbuf_offset);
	if (ret < 0)
		return ret; // Unable to start rdma read bulk transfer operation

	rx_tracker = hfi2_dms_impl_rx_tracker_read_new(dms, port_idx, size,
			key_offset_or_vaddr, dms_key,
			_dms_initiator_peer(dms, src_lid, submit_flags),
			page_provider, starting_rbuf_offset, flags,
			submit_flags, imm_data, &completion, order_key);
	if (rx_tracker == NULL)
		return -ENOMEM;
	
	/* Bind: link child to parent and choose where it will park. */
	_tracker_bind(dms, (union hfi2_dms_tracker *)rx_tracker, parent_handle);

	dms_trace(dms_read_data, dms,
		  _tracker_to_handle((union hfi2_dms_tracker *)rx_tracker).value,
		  port_idx, src_lid, dms_key, key_offset_or_vaddr, size,
		  mr_offset, flags, submit_flags, imm_data, order_key);

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)rx_tracker);
	if (ret < 0) {
		_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		return ret;
	}
	if (ret > 0) {
		rx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_INITIATOR].ticker_total;
		ret = _dms_rx_rift_continue_read_data(dms, rx_tracker);
		if (ret < 0) {
			/* Sever parent link before recycle. */
			_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
			_rift_release(&dms->rift, rx_tracker->hdr.local_rift_key);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			return ret;
		}
	}

	if (out_handle)
		*out_handle = _tracker_to_handle((union hfi2_dms_tracker *)rx_tracker);

	end = dms_rdtsc();
	dms->counters.rget += end - start;

	return 0;
}

static void _tracker_rift_release(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, struct hfi2_dms_rift *rift)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(!rift);

	/* A KEYLESS tracker was never given a rift key. */
	if (_rift_key_error(tracker->hdr.local_rift_key) == HFI2_DMS_RIFT_ERR_KEYLESS)
		return;

	_rift_release(rift, tracker->hdr.local_rift_key);
}

/* Eager WAW release. Called after the parent's START has left via PIO. */
static void _dms_write_signal_pio_release(struct hfi2_dms *dms,
					  struct hfi2_dms_tx_tracker *tx_tracker)
{
	union hfi2_dms_tracker *const parent = (union hfi2_dms_tracker *)tx_tracker;
	union hfi2_dms_tracker *child;
	int ret;

	/* A SEND is fully fenced: it releases its child only at completion. */
	if (_tx_tracker_is_send(tx_tracker))
		return;

	/* An eager WAW child that binds after this is released at bind. */
	parent->hdr.chain_pio_released = true;

	if (parent->hdr.chain_signalled || parent->hdr.child_handle.value == 0)
		return;

	child = _handle_to_tracker(parent->hdr.child_handle);
	if (!child ||
	    child->hdr.op != HFI2_DMS_XFER_OP_WRITE ||
	    child->hdr.parent_handle.value != _tracker_to_handle(parent).value ||
	    child->hdr.chain_park_at !=
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
		return;

	/* Claim the release exactly once. */
	parent->hdr.chain_signalled = true;
	child->hdr.chain_child_released = true;

	/* Not parked yet: the child self-starts at its gate. */
	if (child->hdr.health_state !=
	    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
		return;

	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	_tracker_health_state_set(dms, child,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	/* Queued, not sent: the child signals its own child when it leaves. */
	ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
					       HFI2_DMS_MSG_TYPE_WRITE_START,
					       true);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
		return;
	}
	dms->counters.chain_released_write++;
	dms->counters.chain_released_write_pio_parked++;
}

static void _tracker_signal(struct hfi2_dms *dms, union hfi2_dms_tracker *parent, int status)
{
	struct hfi2_dms_transfer_handle const parent_h = _tracker_to_handle(parent);
	struct hfi2_dms_transfer_handle const child_h = parent->hdr.child_handle;
	union hfi2_dms_tracker *child;

	/* Latch: refuse late binds; we will not signal again. */
	parent->hdr.chain_signalled = true;
	if (child_h.value == 0)
		return;

	child = _handle_to_tracker(child_h);
	if (!child) {
		/* Child retired (cancelled/recycled) before parent completed. */
		dms->counters.chain_null_handle++;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (child->hdr.parent_handle.value != parent_h.value) {
		/* Link no longer reciprocal: drop it. */
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (status && child->hdr.park_on_parent_error) {
		child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		dms->counters.chain_parked_on_parent_error++;
		return;
	}

	child->hdr.chain_child_released = true;

	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START ||
	    child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY ||
	    child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		_tracker_health_state_set(dms, child,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);
		ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
						       HFI2_DMS_MSG_TYPE_WRITE_START,
						       false);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_write++;
		dms->counters.chain_released_write_ack++;
		if (child->hdr.chain_park_at ==
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO)
			dms->counters.chain_released_write_pio_ack++;
		return;
	}

	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		_tracker_health_state_set(dms, child,
					  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START);
		ret = hfi2_dms_impl_inject_read_start(dms, &child->rx, NULL, 0,
						      HFI2_DMS_MSG_TYPE_READ_START);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_read++;
		return;
	}

	/* Completion-time release: sole path for DATA_START_LARGE, fallback for a
	 * DATA_START child not already released by the narrow-to-one fast path.
	 */
	if (child->hdr.health_state ==
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE) {
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		ret = _chain_resume_read_at_data_start(dms, &child->rx);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		dms->counters.chain_released_read_at_data_start_large++;
		return;
	}

	if (child->hdr.health_state ==
		HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) {
		bool const raw = parent->hdr.op == HFI2_DMS_XFER_OP_WRITE;
		int ret;

		child->hdr.parent_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		parent->hdr.child_handle =
			HFI2_DMS_TRANSFER_HANDLE_NONE;
		ret = _chain_resume_read_at_data_start(dms, &child->rx);
		if (ret < 0) {
			dms->counters.chain_release_inject_fail++;
			_tracker_cancel(dms, child, ret);
			return;
		}
		if (raw)
			dms->counters.chain_released_read_at_data_start_raw++;
		else
			dms->counters.chain_released_read_at_data_start++;
		return;
	}
}

static void _dms_rx_tracker_complete_finish(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker,
					    int status);

static void _dms_rx_p2p_flush_done(void *cookie, int status)
{
	struct hfi2_dms_rx_tracker *rx_tracker = cookie;
	struct hfi2_dms *dms = rx_tracker->dms;

	dms->p2p_flush_inflight--;
	WARN_ON_ONCE(status && status != -ESHUTDOWN);
	_dms_rx_tracker_complete_finish(dms, rx_tracker,
					status == -ESHUTDOWN ?
					-ECANCELED : status);
}

static bool _dms_rx_p2p_flush_start(struct hfi2_dms *dms,
				    struct hfi2_dms_rx_tracker *rx_tracker)
{
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	struct hfi2_dms_run run;
	struct sdma_desc descs[2];
	u64 last_byte;
	u8 engine = dms_reserved_engine_idx(dms);
	u8 port_idx = rx_tracker->hdr.port_idx;
	int ret;

	if (!pp->p2p_flush || !rx_tracker->sbuf_cursor)
		return false;
	if (WARN_ON_ONCE(!dms->num_engines ||
			 !dms->p2p_flush_sop_desc[port_idx].qw[0]))
		return false;

	last_byte = rx_tracker->rbuf_start_offset + rx_tracker->total_payload - 1;
	if (WARN_ON_ONCE(pp->next_src_run(pp, last_byte, 1, &run) ||
			 !run.run_bytes))
		return false;

	descs[0] = dms->p2p_flush_sop_desc[port_idx];
	descs[1] = (struct sdma_desc){0};
	_sdma_qw_set_byte_count(&descs[1].qw[0], sizeof(u64));
	_sdma_qw_set_phy_addr(&descs[1].qw[0],
			      run.dma_pages[0] + (run.page_offset & ~0x7ull));
	descs[1].qw[1] |= HFI2_DMS_SDMA_DESC_TYPE_EOP |
		SDMA_DESC1_HEAD_TO_HOST_FLAG;
	if (dms->chip_type != CHIP_JKR)
		cyr_sdma_qw_set_send_ctxt_extension(&descs[1].qw[0],
						    dms->port_sctxts[port_idx]->hw_context);

	rx_tracker->dms = dms;
	ret = hfi2_dms_sdma_desc_place(dms, engine, descs, ARRAY_SIZE(descs),
				       _dms_rx_p2p_flush_done, rx_tracker);
	if (!ret) {
		hfi2_dms_sdma_doorbell_all(dms);
	} else {
		ret = hfi2_dms_sdma_desc_submit(dms, engine, port_idx, descs,
						ARRAY_SIZE(descs),
						_dms_rx_p2p_flush_done,
						rx_tracker);
		if (WARN_ON_ONCE(ret))
			return false;
	}

	dms->p2p_flush_inflight++;
	return true;
}

void hfi2_dms_rx_tracker_handle_completion(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int status, u32 do_ack)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->payload_remaining != 0);

	enum hfi2_dms_rx_tracker_op const op = rx_tracker->op;

	if (do_ack) {
		union hfi2_dms_proto_cmd_ack cmd;
		int ret;

		DMS_BUG_ON(_rift_key_error(rx_tracker->hdr.remote_rift_key));

		if (op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
			cmd = hfi2_dms_proto_cmd_ack_make(dms, rx_tracker->hdr.port_idx, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, rx_tracker->read.flags, rx_tracker->read.imm_data);
		} else { /* externally-resolved or RDMA-WRITE target: ACK carries no imm */
			cmd = hfi2_dms_proto_cmd_ack_make(dms, rx_tracker->hdr.port_idx, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, 0, 0);
		}

		ret = _inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
				      HFI2_DMS_TRANSFER_HANDLE_NONE, false);
		if (ret < 0)
			dd_dev_err(dms->dd, "Failed to send or enqueue ACK packet\n");
	}

#if HFI2_DMS_COUNTERS_ENABLE
	rx_tracker->hdr.perf.lifetime[1] = ktime_get();
	_dms_aggregate_perf_counters(dms, (union hfi2_dms_tracker *)rx_tracker);
#endif
	_tracker_rift_release(dms, (union hfi2_dms_tracker *)rx_tracker, &dms->rift);

	if (!status && _dms_rx_p2p_flush_start(dms, rx_tracker))
		return;
	_dms_rx_tracker_complete_finish(dms, rx_tracker, status);
}

static void _dms_rx_tracker_complete_finish(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker,
					    int status)
{
	enum hfi2_dms_rx_tracker_op const op = rx_tracker->op;

	/* Parent signals to child upon rx completion. */
	_tracker_signal(dms, (union hfi2_dms_tracker *)rx_tracker, status);

	if (op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, status);
	} else if (op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST) {
		dms->ext_dest.complete(dms,
			rx_tracker->write.ext_cmpl_ctx, status);
	} else { // HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access,
			(union hfi2_dms_tracker *)rx_tracker,
			rx_tracker->write.metadata.flags,
			rx_tracker->write.parameters.imm_data,
			rx_tracker->write.parameters.order_key,
			status);
		rx_tracker->write.access = NULL;
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);

	/*
	 * Hand the freed rift key on once this tracker is retired, but defer
	 * the poll: this completion can run nested inside a rift-poll drive.
	 */
	_dms_rift_poll_request(dms);
}

static void _dms_rx_issue_data_request_burst(struct hfi2_dms *dms,
					     struct hfi2_dms_rx_tracker *rx_tracker,
					     bool deferred)
{
	u32 const free_count = _tidset_free_count(dms);
	u32 tidset;
	int ret;

	DMS_BUG_ON(rx_tracker->tidsets_in_use != 0);

	if ((!_rift_keyring_empty(&dms->tidset_waiters)) || (free_count == 0)) {
		if (deferred)
			dms->counters.chain_resume_deferred_waiter++;
		_tidset_waiter_enqueue(dms, rx_tracker);
		return;
	}

	_tidset_idx_peek(dms, &tidset);
	_tidset_idx_reserve(dms, tidset);
	ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
	if (unlikely(ret != 0)) {
		_tidset_idx_release(dms, tidset);
		_tidset_waiter_enqueue(dms, rx_tracker);
		return;
	}
	DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
	_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);

	for (u32 i = 1; i < HFI2_DMS_TRACKER_TIDSET_MAX &&
	     rx_tracker->sbuf_cursor < rx_tracker->total_payload &&
	     free_count > i; i++) {
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
	}

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA);

	_chain_signal_last_engine(dms, rx_tracker);
}

/*
 * Allocate additional tidsets for the unrequested remainder of a transfer whose
 * tracker already holds in-use tidsets, issuing one DATA_REQUEST per newly
 * reserved tidset. The loop seeds from the current in-use count so the
 * per-tracker maximum caps total (not additional) tidsets, and bounds
 * reservations to the free pool. On pool exhaustion the tracker is left for the
 * per-tidset re-request path rather than enqueued as a waiter, since it still
 * has live tidsets in flight.
 */
static void _dms_rx_speculative_topup_burst(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker)
{
	u32 const start = rx_tracker->tidsets_in_use;
	u32 const free_count = _tidset_free_count(dms);
	u32 tidset;
	int ret;

	if (!_rift_keyring_empty(&dms->tidset_waiters) || free_count == 0)
		return;

	for (u32 i = start;
	     i < HFI2_DMS_TRACKER_TIDSET_MAX &&
	     (rx_tracker->sbuf_cursor < rx_tracker->total_payload) &&
	     ((i - start) < free_count);
	     i++) {
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
	}
}

static int _chain_resume_read_at_data_start(struct hfi2_dms *dms,
					    struct hfi2_dms_rx_tracker *rx_tracker)
{
	u32 const tid_nbytes = rx_tracker->total_payload -
			       rx_tracker->sbuf_cursor;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	if (unlikely(tid_nbytes == 0))
		return 0;

	_dms_rx_issue_data_request_burst(dms, rx_tracker, true);
	return 0;
}

static void hfi2_dms_handle_data_start(struct hfi2_dms *dms,
				       union hfi2_dms_16b_header *hdr,
				       bool eager, void *ebuf, u32 const eager_nbytes)
{
	struct _hdrq_entry *e = (struct _hdrq_entry *)hdr;
	struct hfi2_dms_data_start_parameters const * const parameters = &e->data_start;
	hfi2_dms_rift_key_t const rx_rift_key = parameters->rx_rift_key;
	hfi2_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;
	void *hbuf = eager ? (void *)&parameters->eager_payload : NULL;

	struct hfi2_dms_rx_tracker *rx_tracker;
	int err = 0;

	if (unlikely(_rift_key_error(rx_rift_key) || !_rift_key_side_rx(rx_rift_key) ||
		     _rift_key_error(tx_rift_key) || !_rift_key_side_tx(tx_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop DATA_START with malformed rift keys rx=0x%04hx tx=0x%04hx\n",
			   rx_rift_key.value, tx_rift_key.value);
		return;
	}

	rx_tracker = (struct hfi2_dms_rx_tracker *) _rift_lookup(&dms->rift, rx_rift_key);
	if (!rx_tracker) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "(%d) Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", __LINE__, rx_rift_key.value, _rift_key_generation(rx_rift_key), _rift_key_index(rx_rift_key));
		return;
	}
	/*
	 * A speculative READ's responder answers DATA_START when it could not
	 * serve the requests the READ_START carried: promote and re-request.
	 */
	if (unlikely(_rx_tracker_spec_unlatched(rx_tracker))) {
		_spec_read_join(dms, rx_tracker, tx_rift_key, true);
		return;
	}
	/*
	 * Duplicate DATA_START guard: the remote side may re-send DATA_START
	 * via the health protocol if it didn't receive a timely DATA_REQUEST.
	 * If remote_rift_key is already set, this rx_tracker has already
	 * processed a DATA_START - ignore the duplicate.
	 */
	if (_rift_key_error(rx_tracker->hdr.remote_rift_key) != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {
		dms->counters.health_duplicate_data_start++;
		dd_dev_dbg(dms->dd,
			"(%d) Ignoring duplicate DATA_START for rx_tracker (l:%05u r:%05u)\n",
			__LINE__,
			rx_tracker->hdr.local_rift_key.value,
			rx_tracker->hdr.remote_rift_key.value);
		return;
	}

	rx_tracker->hdr.remote_rift_key = tx_rift_key;

	if (rx_tracker->payload_remaining == 0) {
		/* Complete using fence only. */

		dms->counters.eager_rx++;
		goto completed_success;
	}

	if (hbuf) {
		/*
		 * Eager: the packet carries the first eager_nbytes of the
		 * payload, or all of it. Land that prefix by CPU and request
		 * the rest.
		 */
		u32 const prefix = min_t(u32, rx_tracker->total_payload,
					 eager_nbytes);

		err = _eager_rx_copy_prefix(rx_tracker,
			HFI2_DMS_MSG_TYPE_DATA_START_EAGER,
			hbuf, ebuf, prefix);
		if (unlikely(err != 0))
			goto completed_error;

		dms->counters.eager_rx++;
		rx_tracker->hdr.byte_odometer += prefix;
		rx_tracker->payload_remaining -= prefix;
		if (rx_tracker->payload_remaining == 0)
			goto completed_success;

		rx_tracker->sbuf_cursor = prefix;
	} else if (_tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
				 HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) ||
		   _tracker_gate(dms, (union hfi2_dms_tracker *)rx_tracker,
				 HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE)) {
		/* Parked at whichever DATA_START variant _tracker_bind chose. */
		dms->counters.chain_parked_read_at_data_start++;
		return; /* DATA_REQUEST burst deferred to resume */
	}

	/*
	 * The tidsets request the payload not yet delivered; any sub-quadword
	 * edges, the start or end of the buffer included, land through the
	 * tidset bounce page.
	 */
	_dms_rx_issue_data_request_burst(dms, rx_tracker, false);
	return;

completed_success:
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, true);
	return;

completed_error:
	rx_tracker->payload_remaining = 0;
	hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, err, true);
	return;
}

static void _hfi2_dms_handle_data_common(struct hfi2_dms *dms,
					 union hfi2_dms_16b_header *hdr,
					 bool speculative)
{
	u64 start, end;
	struct hfi2_dms_read_request_state *read_request;
	struct hfi2_dms_rx_tracker *rx_tracker;
	u16 tid;
	u16 tid_set;
	u32 payload_qws;

	dms_trace(dms_handle_data, dms, hdr);

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	start = dms_rdtsc();

	tid = (hdr->kdeth[0] >> 16) & (BIT(10) - 1);
	tid_set = (tid / HFI2_DMS_TID_SET_SIZE);
	payload_qws = hfi2_dms_16b_data_payload_qws_get(hdr);

	read_request = &dms->read_requests[tid_set];
	union hfi2_dms_proto_pkt_data *data_pkt = (union hfi2_dms_proto_pkt_data *)hdr;
	u16 const pkt_generation = data_pkt->info.generation;

	if (unlikely((read_request->state != HFI2_DMS_TIDSET_STATE_ENABLED) ||
		     (pkt_generation != read_request->generation)))  {
		/*
		 * A generation mismatch on a tidset that is still ENABLED and has
		 * already accepted legit data (remaining_qws != total_requested_qws)
		 * means a hardware DMA placed a foreign payload into a live receive
		 * buffer before we dropped the header here. The u16 epoch and FIFO
		 * recycling make this unreachable within the fabric packet lifetime;
		 * if it fires it is silent data corruption and the signal to widen
		 * the epoch or add a stronger transfer-identity token.
		 */
		if (read_request->state == HFI2_DMS_TIDSET_STATE_ENABLED &&
		    read_request->remaining_qws != read_request->total_requested_qws) {
			dms->counters.data_generation_mismatch_clobber++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS: stale DATA clobber tid_set=%u pkt_gen=%u cur_gen=%u\n",
				tid_set, pkt_generation, read_request->generation);
		}
		/* Ignore this invalid DATA packet */
		if (read_request->state == HFI2_DMS_TIDSET_STATE_DRAINING) {
			read_request->stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);
		} else {
			read_request->disable_ts = dms->now;
		}
		return;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	if (read_request->remaining_qws == read_request->total_requested_qws) {
		dms->read_requests[tid_set].perf.first_data = ktime_get();
	}
#endif

	rx_tracker = read_request->rx_tracker;
	DMS_BUG_ON(!rx_tracker);

	/*
	 * Promotion: the first DATA_SPECULATIVE names the responder of a
	 * speculative READ, turning its speculative tidsets into ordinary ones.
	 * The packet then lands as ordinary DATA below. DATA never takes this
	 * branch.
	 */
	if (speculative && _rx_tracker_spec_unlatched(rx_tracker))
		_spec_read_join(dms, rx_tracker, data_pkt->info.tx_rift_key, false);
	if (unlikely(_rx_tracker_spec_unlatched(rx_tracker))) {
		dms->counters.health_invalid_rift_key++;
		return;
	}

	/*
	 * New generation-valid DATA landed (the invalid/duplicate/old-gen path
	 * returned above). Advance the lifetime work odometer so this tracker's
	 * progress hash differs on genuine forward progress only.
	 */
	rx_tracker->hdr.byte_odometer += (u64)payload_qws << 3;
	rx_tracker->hdr.status_req_count = 0;
	rx_tracker->hdr.stale_time = ktime_add_ms(dms->now, HFI2_DMS_STALE_BACKOFF_BASE_MS);
	read_request->stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);

	/* Avoid unsigned underflow that can stall tidset completion. */
	if (unlikely(read_request->remaining_qws < payload_qws)) {
		dms->counters.health_remaining_qws_underflow++;
		dd_dev_dbg_ratelimited(dms->dd,
				       "dms: remaining_qws (%llu) < payload_qws (%u) on tid_set %u gen %u, cancelling rx_tracker\n",
				       read_request->remaining_qws, payload_qws,
				       tid_set, pkt_generation);
		hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -EIO);
		return;
	}
	read_request->remaining_qws -= payload_qws;

	if (read_request->remaining_qws > 0) {
		// more data is expected for this tidset
		return;
	}

	// all data for this tidset has been received
	if (unlikely(read_request->has_bounce)) {
		/*
		 * The request's sub-quadword edges landed in the bounce page;
		 * they reach the destination only once copied out, so debit the
		 * request's destination bytes after that succeeds. A failed
		 * copy-out leaves edge bytes missing: cancel rather than report
		 * success.
		 */
		if (unlikely(_tidset_bounce_scatter(dms, tid_set, rx_tracker))) {
			dms->counters.health_bounce_scatter_fail++;
			hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -EIO);
			return;
		}
		rx_tracker->payload_remaining -=
			dms->read_request_chunks[tid_set].cycle_real_bytes;
	} else {
		/* No edges: every destination byte was placed by TID. */
		rx_tracker->payload_remaining -=
			read_request->total_requested_qws << 3;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	read_request->perf.end = ktime_get();
	if (_ring_free(&dms->counters.tidset.ring) > 0) {
		u32 const idx = _ring_produce(&dms->counters.tidset.ring);

		dms->counters.tidset.arr[idx].enable = ktime_sub(read_request->perf.tidset_enabled, read_request->perf.begin);
		dms->counters.tidset.arr[idx].rtt = ktime_sub(read_request->perf.first_data, read_request->perf.tidset_enabled);
		dms->counters.tidset.arr[idx].total = ktime_sub(read_request->perf.end, read_request->perf.begin);
		dms->counters.tidset.arr[idx].data = ktime_sub(read_request->perf.end, read_request->perf.first_data);
		dms->counters.tidset.arr[idx].bytes = read_request->total_requested_qws << 3;
		dms->counters.tidset.arr[idx].local = rx_tracker->hdr.local_rift_key;
		dms->counters.tidset.arr[idx].remote = rx_tracker->hdr.remote_rift_key;
		dms->counters.tidset.arr[idx].order_key = rx_tracker->hdr.order_key;
		dms->counters.tidset.arr[idx].tbytes = rx_tracker->total_payload;
	}
#endif

	if (rx_tracker->sbuf_cursor < rx_tracker->total_payload) {
		int ret;

		/* Re-arm for the next chunk (may land on a new engine). Stays in the
		 * list on success; removed on failure.
		 */
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tid_set);
		if (ret == 0) {
			_chain_signal_last_engine(dms, rx_tracker);
		} else {
			_dms_rx_tracker_tidset_inflight_clear(rx_tracker, tid_set);

			if (rx_tracker->tidsets_in_use == 0) {
				/* No other tidset will complete the transfer; Add to front of
				 * tidset waiter ring (priority over new waiters)
				 */
				hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
				_rift_keyring_add_front(&dms->tidset_waiters, key);

				_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
								HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION);
			}

			_tidset_free_then_poll_waiters(dms, tid_set);
		}
		return;
	}

	_dms_rx_tracker_tidset_inflight_clear(rx_tracker, read_request->tid_set);
	_tidset_free_then_poll_waiters(dms, read_request->tid_set);

	_chain_signal_last_engine(dms, rx_tracker);

	if (rx_tracker->payload_remaining == 0)
		hfi2_dms_rx_tracker_handle_completion(dms, rx_tracker, 0, 1);

	end = dms_rdtsc();
	dms->counters.handle_data += end - start;
}

static void hfi2_dms_handle_data(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	_hfi2_dms_handle_data_common(dms, hdr, false);
}

static void hfi2_dms_handle_data_speculative(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	_hfi2_dms_handle_data_common(dms, hdr, true);
}

static inline enum hfi2_dms_msg_type
hfi2_dms_impl_message_type_get(union hfi2_dms_16b_header *hdr)
{
	enum hfi2_dms_msg_type ret;

	ret = (enum hfi2_dms_msg_type)((hdr->bth[0] & 0x00FF0000) >>
				       16); // Extract the message type from BTH
	return ret;
}

/* CYR and JKR RHF bit layouts are identical — keep raw constants for hot path */
static bool _rhf_is_valid_16b(u64 rhf)
{
	u64 const mask = ((u64)RHF_JKR_RHE_VALID) |
			 ((u64)RHF_JKR_L2_TYPE_MASK << RHF_JKR_L2_TYPE_SHIFT);
	u64 const check = (u64)HFI2_L2_TYPE_16B << RHF_JKR_L2_TYPE_SHIFT;

	return (rhf & mask) == check;
}

static void _log_rhe_reason(struct hfi2_dms *dms, struct hfi2_ctxtdata *rcd,
			    u64 rhf, u32 rhqoff, u32 rsize)
{
	// We set hardware to drop 9B packets to our rcd
	DMS_WARN_ON(_rhf_l2_type(rhf) != HFI2_L2_TYPE_16B);

	if (_rhf_rhe_valid(rhf)) {
		u64 err_flags = ((u64 *)(rcd->rheq))[rhqoff / rsize];

		if (err_flags & RHF_ICRC_ERR)
			dd_dev_dbg(
				dms->dd,
				"DMS data packet dropped due to ICRC error\n");
		else
			dd_dev_dbg(
				dms->dd,
				"DMS data packet dropped due to unhandled error (0x%016llx)\n",
				err_flags);
	}
}

/**
 * _get_rhf_addr - Get the RHF address for a given queue offset
 * @rcd: receive context
 * @rhqoff: queue offset in words
 */
static inline __le32 *_get_rhf_addr(struct hfi2_ctxtdata *rcd, u32 rhqoff)
{
	return (__le32 *)rcd->rcvhdrq + rhqoff + rcd->rhf_offset;
}

/**
 * _get_16b_hdr - Get the 16B header pointer from the RHF address
 * @rcd: receive context
 * @rhf_addr: pointer to the RHF in the header queue
 * @rhf: the RHF value (already read)
 */
static inline union hfi2_dms_16b_header *_get_16b_hdr(struct hfi2_ctxtdata *rcd,
						      __le32 *rhf_addr, u64 rhf)
{
	return (union hfi2_dms_16b_header *)(rhf_addr - rcd->rhf_offset +
					     rhf_hdrq_offset(rhf));
}

/* LRH16(16) + BTH(12) + KDETH(8); hbuf (inline payload) starts here. */
#define HFI2_DMS_ULP_HDR_BYTES 36u

/*
 * On the wire the 36-byte header is qword-rounded: hfi2_dms_ulp_build_pio_header()
 * counts DIV_ROUND_UP(36, 8) = 5 qwords = 40 bytes for the header region in
 * pkt_len_qws, leaving a 4-byte qword-rounding pad between the header and the
 * payload.  rhf_pkt_len() reflects that rounded length, so the receive-side
 * payload split MUST strip the rounded header (40), not the raw 36, or the pad
 * bytes leak into the payload handed to the ULP.
 */
#define HFI2_DMS_ULP_HDR_WIRE_BYTES round_up(HFI2_DMS_ULP_HDR_BYTES, sizeof(u64))

/* Mandatory 16B tail flit (1 qword) every DMS 16B packet carries after payload. */
#define HFI2_DMS_ULP_TAIL_BYTES 8u

/*
 * Split a received ULP packet into the {hbuf, ebuf} iovec the handler sees.
 * The inline prefix (hbuf) is the portion that fit in the HDRQ entry after the
 * 36-byte header, capped by the entry size (JKR 128 / CYR 256, minus the 2-DW
 * RHF); the remainder spilled into the eager buffer (ebuf).
 *
 * rhf_pkt_len() counts the whole on-wire packet after the header: the ULP
 * payload PLUS the mandatory 8-byte 16B tail flit that the egress path always
 * appends (and any qword-rounding pad).  Strip that trailer here so the payload
 * lengths the handler sees match what the sender passed as @payload_bytes and
 * no trailer bytes are exposed as payload.
 */
static struct hfi2_dms_ulp_rx _dms_build_ulp_rx(struct hfi2_ctxtdata *rcd,
						u64 rhf,
						union hfi2_dms_16b_header *hdr,
						void *ebuf)
{
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const rhf_off = rhf_hdrq_offset(rhf);
	/*
	 * prefix_cap is the byte span of the HDRQ entry after the RHF (2 DWs).
	 * Guard the subtraction: a malformed rhf_hdrq_offset (>= rsize - 2) would
	 * underflow u32 to a huge value and push payload[0] past the entry.  The
	 * poll loop already validated the RHF, so this is defence-in-depth.
	 */
	u32 const prefix_cap = (rsize > rhf_off + 2) ?
			       (rsize - rhf_off - 2) << 2 : 0;
	u32 const inline_cap = prefix_cap > HFI2_DMS_ULP_HDR_WIRE_BYTES ?
			       prefix_cap - HFI2_DMS_ULP_HDR_WIRE_BYTES : 0;
	u32 const pkt_len = rhf_pkt_len(rhf);
	/*
	 * Strip the WIRE (qword-rounded, 40-byte) header + the 8-byte tail flit.
	 * The header lands at command-buffer offset HFI2_DMS_ULP_HDR_BYTES(36) but
	 * pkt_len counts the rounded HFI2_DMS_ULP_HDR_WIRE_BYTES(40); stripping 36
	 * here would expose the 4-byte qword pad as payload.
	 */
	u32 const hdr_plus_tail = HFI2_DMS_ULP_HDR_WIRE_BYTES +
				  HFI2_DMS_ULP_TAIL_BYTES;
	u32 const total_pay = pkt_len > hdr_plus_tail ?
			      pkt_len - hdr_plus_tail : 0;
	u32 const hbuf_len = min(total_pay, inline_cap);
	u32 const ebuf_len = total_pay - hbuf_len;

	return (struct hfi2_dms_ulp_rx){
		.pkt_hdr = hdr,
		.payload[0] = {
			.base = hbuf_len ?
				(const u8 *)hdr + HFI2_DMS_ULP_HDR_WIRE_BYTES :
				NULL,
			.len = hbuf_len,
		},
		.payload[1] = {
			.base = ebuf_len ? ebuf : NULL,
			.len = ebuf_len,
		},
		.rcv_port = _rhf_rcv_port(rhf),
	};
}

/*
 * The native builder's HFI2_DMS_ULP_HDR_WIRE_BYTES/HFI2_DMS_ULP_TAIL_BYTES
 * offsets cannot parse EAL ingress + Ethernet/IP/UDP.  The RSM bypass split
 * determines the HDRQ-inline prefix, with the remainder in the eager buffer.
 * The header starts at the RHF-provided offset within the HDRQ entry.
 */
static inline u32 _eth_bypass_header_budget(struct hfi2_ctxtdata *rcd, u64 rhf)
{
	u32 const hdrq_cap = (get_hdrqentsize(rcd) > rhf_hdrq_offset(rhf) + 2) ?
		(get_hdrqentsize(rcd) - rhf_hdrq_offset(rhf) - 2) << 2 : 0;

	return min_t(u32, hdrq_cap,
		hfi2_dms_eth_bypass_hdr_dws(rcd->dd) * sizeof(u32));
}

static bool _dms_build_eth_ulp_rx(struct hfi2_ctxtdata *rcd, u64 rhf,
				  const struct eal_ingress_header *eal_hdr,
				  void *ebuf, struct hfi2_dms_ulp_rx *rx)
{
	u32 const pkt_len = rhf_pkt_len(rhf);
	u32 const hdr_bytes = sizeof(*eal_hdr);
	u32 const header_budget = _eth_bypass_header_budget(rcd, rhf);
	u32 const pad = EAL_INGRESS_GET_E(eal_hdr);
	u32 inline_bytes;
	u32 eth_bytes;
	u32 ebuf_len;
	const u8 *inline_base;
	const void *timestamp = NULL;

	if (pkt_len < hdr_bytes || header_budget < hdr_bytes)
		return false;

	inline_bytes = min(pkt_len - hdr_bytes, header_budget - hdr_bytes);
	eth_bytes = pkt_len - hdr_bytes;
	inline_base = (const u8 *)eal_hdr + hdr_bytes;
	if (EAL_INGRESS_GET_TS_PRESENT(eal_hdr)) {
		if (eth_bytes < CNE_RX_TS_SIZE || inline_bytes < CNE_RX_TS_SIZE)
			return false;
		timestamp = inline_base;
		inline_base += CNE_RX_TS_SIZE;
		inline_bytes -= CNE_RX_TS_SIZE;
		eth_bytes -= CNE_RX_TS_SIZE;
	}
	/* RHF length includes EAL header, optional timestamp and qword pad. */
	if (eth_bytes < pad)
		return false;
	eth_bytes -= pad;
	inline_bytes = min(inline_bytes, eth_bytes);
	ebuf_len = eth_bytes - inline_bytes;
	/* The eager offset is relative to the start of this RcvArray slot. */
	if (ebuf_len && (!ebuf ||
			 (u64)rhf_egr_buf_offset(rhf) * RCV_BUF_BLOCK_SIZE + ebuf_len >
			 rcd->egrbufs.rcvtid_size))
		return false;

	*rx = (struct hfi2_dms_ulp_rx){
		.pkt_hdr = eal_hdr,
		.payload[0] = {
			.base = inline_bytes ? inline_base : NULL,
			.len = inline_bytes,
		},
		.payload[1] = {
			.base = ebuf_len ? ebuf : NULL,
			.len = ebuf_len,
		},
		.ingress_timestamp = timestamp,
		.rcv_port = _rhf_rcv_port(rhf),
		.is_ethernet = true,
	};
	return true;
}

/*
 * Route a classified ULP packet (ulp_id != 0) toward its registered handler.
 * A slot whose handle_rx is NULL (no ULP registered for that ulp_id, or a ULP
 * that has unregistered) accounts the packet exactly like the poll loops'
 * existing "unknown message type" default arm and returns.  ULPs populate
 * dms->ulp[] via hfi2_dms_ulp_register()/unregister() (below).
 *
 * Single-threaded: runs on the bulksvc event thread; reads dms->ulp[] without
 * locking by design (see struct hfi2_dms).
 */
static void hfi2_dms_ulp_dispatch_rx(struct hfi2_dms *dms, u8 ulp_id,
				     u8 subtype,
				     const struct hfi2_dms_ulp_rx *rx)
{
	const struct hfi2_dms_ulp_ops *ops;

	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		goto drop;

	ops = &dms->ulp[ulp_id];
	if (ops->handle_rx &&
	    ops->handle_rx(dms, subtype, rx, ops->cookie) == 0)
		return;

drop:
	dd_dev_dbg_ratelimited(dms->dd,
			       "Dropping ULP packet (no handler): ulp_id=%u subtype=%u\n",
			       ulp_id, subtype);
}

int hfi2_dms_ulp_register(struct hfi2_dms *dms, struct hfi2_dms_ulp_ops ops)
{
	u8 ulp_id;

	/*
	 * Validate the full ops vtable here so the hot dispatch path never has
	 * to: a registered slot is guaranteed to have a non-NULL handle_rx.
	 */
	if (!dms || !ops.handle_rx)
		return -EINVAL;

	ulp_id = ops.ulp_id;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;

	if (dms->ulp[ulp_id].handle_rx)
		return -EBUSY;

	dms->ulp[ulp_id] = ops;
	return 0;
}

void hfi2_dms_ulp_unregister(struct hfi2_dms *dms, u8 ulp_id)
{
	if (!dms || ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return;

	dms->ulp[ulp_id] = (struct hfi2_dms_ulp_ops){0};
}

/*
 * Build the PIO-command header (PBC + 16B-compressed LRH + BTH + KDETH) for a
 * ULP PIO packet into @hdr_buf, so a ULP peer can hand iov[0]=hdr_buf,
 * iov[1]=payload to hfi2_dms_ulp_egress_pio() without reaching into DMS
 * internals.  The command frame uses the 8-byte compressed lrh16bc, so the
 * header after the PBC is lrh16bc(8) + bth(12) + kdeth(8) = 28 bytes, zero
 * padded by 4 so the payload follows at command-buffer offset 40.  That same
 * payload lands at WIRE offset 40 once the 16B LRH expands, matching the
 * receive-side HFI2_DMS_ULP_HDR_WIRE_BYTES.  The 8-bit BTH message byte is
 * encoded as
 * (ulp_id << HFI2_DMS_MSGBYTE_ULP_SHIFT) | (subtype & HFI2_DMS_MSGBYTE_SUB_MASK),
 * matching hfi2_dms_16b_ulp_decode().  SLID is stamped by the send context's
 * SendCtxtCheckSlid at injection time, so it is not set here.  Returns the
 * command-header length in bytes (40), or a negative errno.
 */
int hfi2_dms_ulp_build_pio_header(struct hfi2_dms *dms,
				  enum hfi2_dms_fabric_port_idx port_idx,
				  u32 dlid, u8 ulp_id, u8 subtype,
				  u32 payload_bytes, void *hdr_buf,
				  u32 hdr_buf_len)
{
	/*
	 * Command-buffer header: PBC(8) + lrh16bc(8) + bth(12) + kdeth(8) = 36,
	 * zero-padded to 40 so the payload starts on a qword.  The compressed
	 * lrh16bc is 8 bytes here; the WIRE header it expands to is
	 * 16 + bth(12) + kdeth(8) = 36, padded the same way, so the payload
	 * lands at wire offset 40 -- HFI2_DMS_ULP_HDR_WIRE_BYTES, where the
	 * receive split expects it.
	 */
	u32 const hdr_bytes = round_up(sizeof(u64) /* PBC */ + 8 /* lrh16bc */ +
				       12 /* bth */ + 8 /* kdeth */,
				       sizeof(u64));
	struct send_context *sc;
	union _pkt_cmd *cmd;
	u32 pkt_len_qws;
	u8 msgbyte;

	if (!dms || !hdr_buf)
		return -EINVAL;
	/* The batch stores u64 PBC/LRH/BTH/KDETH fields; require alignment. */
	if (!IS_ALIGNED((uintptr_t)hdr_buf, sizeof(u64)))
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS || !dms->port_available[port_idx])
		return -EINVAL;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;
	if (subtype > HFI2_DMS_MSGBYTE_SUB_MASK)
		return -EINVAL;
	if (dlid == 0)
		return -EINVAL;
	if (payload_bytes & (sizeof(u64) - 1))
		return -EINVAL;
	if (hdr_buf_len < hdr_bytes)
		return -EMSGSIZE;

	sc = dms->port_sctxts[port_idx];
	if (!sc)
		return -ENXIO;

	/*
	 * On-wire qword length carried in the LRH/PBC excludes the PBC itself
	 * but includes the 36-byte header and a 1-qword tail flit.  The 36-byte
	 * header rounds up to 5 qwords on the wire.
	 */
	pkt_len_qws = DIV_ROUND_UP(36, sizeof(u64)) +
		      (payload_bytes / sizeof(u64)) + 1;

	cmd = hdr_buf;
	memset(cmd, 0, hdr_bytes);

	cmd->pbc = hfi2_dms_impl_pbc_template_create_16Bc(port_idx,
							  pkt_len_qws << 1,
							  sc->hw_context);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);

	msgbyte = (ulp_id << HFI2_DMS_MSGBYTE_ULP_SHIFT) |
		  (subtype & HFI2_DMS_MSGBYTE_SUB_MASK);
	cmd->bth[0] = HFI2_DMS_BTH_OPCODE | ((u32)msgbyte << 16);
	cmd->bth[1] = (u32)RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; /* KVER */
	cmd->kdeth[1] = HFI2_DMS_CTRL_JKEY;

	return hdr_bytes;
}

int hfi2_dms_ulp_egress_pio(struct hfi2_dms *dms,
			    enum hfi2_dms_fabric_port_idx port_idx,
			    const struct hfi2_dms_ulp_iov *iov, u32 niov)
{
	struct hfi2_dms_ulp_iov spans[HFI2_DMS_ULP_PIO_MAX_IOV];
	const u8 *hdr;
	u32 i;
	int ret;

	if (!dms || !iov || niov == 0 || niov > HFI2_DMS_ULP_PIO_MAX_IOV)
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS)
		return -EINVAL;

	/*
	 * iov[0] MUST start with the PBC qword from
	 * hfi2_dms_ulp_build_pio_header(): enforce it up front so a {NULL,0}
	 * or short first element can never let payload bytes be misread as
	 * the PBC and emit a corrupted packet.
	 */
	if (!iov[0].base || iov[0].len < sizeof(u64))
		return -EINVAL;

	/*
	 * Hand the PBC to the gather sender separately and the rest of the
	 * packet as packed spans; the sender appends the 16B tail flit.
	 */
	hdr = iov[0].base;
	spans[0] = (struct hfi2_dms_ulp_iov){ .base = hdr + sizeof(u64),
					      .len = iov[0].len - sizeof(u64) };
	for (i = 1; i < niov; i++)
		spans[i] = iov[i];

	if (_pio_waitlist_empty(dms)) {
		ret = hfi2_dms_impl_pio_sendv(dms, get_unaligned_le64(hdr),
					      spans, niov, true);
		if (ret != -EAGAIN)
			return ret;
	}

	/*
	 * Keep the packet's place among the other PIO packets: copy it into a
	 * waiter if it fits one, else leave the retry to the ULP.
	 */
	return _pio_waitlist_append_ulp(dms, get_unaligned_le64(hdr), spans,
					niov);
}


int hfi2_dms_ulp_add_eth_match(struct hfi2_dms *dms,
			       const struct hfi2_dms_ulp_match *match)
{
	u8 ulp_id;

	if (!dms || !match)
		return -EINVAL;

	ulp_id = match->ulp_id;
	if (ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return -EINVAL;

	/*
	 * Software-only: this records the match for hfi2_dms_ulp_classify() and
	 * programs NO hardware.  Hardware RSM steering to a dedicated per-ULP
	 * receive context (see bulksvc_rsm_reserve()/bulksvc_rsm_init()) is
	 * deferred pending a multi-hfisvc capability.
	 *
	 * One match slot per ulp_id: this OVERWRITES any existing rule for the
	 * same ulp_id (last writer wins).  ulp_id is centrally owned, so a ULP
	 * only ever replaces its own rule and cannot clobber another ULP's.
	 *
	 * Soft-RoCE caveat: a RoCEv2 match (udp_dport == htons(4791)) will
	 * divert those frames from the soft-RoCE provider (rxe) on this host;
	 * running both accelerated and soft RoCE simultaneously is unsupported.
	 */
	dms->eth_match[ulp_id] = *match;
	return 0;
}

void hfi2_dms_ulp_del_eth_match(struct hfi2_dms *dms, u8 ulp_id)
{
	if (!dms || ulp_id == 0 || ulp_id >= HFI2_DMS_ULP_MAX)
		return;

	dms->eth_match[ulp_id] = (struct hfi2_dms_ulp_match){0};
}

u8 hfi2_dms_ulp_classify(struct hfi2_dms *dms, const void *eth_hdr, u32 hdr_len)
{
	const struct ethhdr *eth = eth_hdr;
	__be16 ethertype;
	u8 ip_proto = 0;
	__be16 udp_dport = 0;
	u32 l3_off;
	u8 prio_best = 0;
	u8 ulp_best = 0;
	u8 i;

	if (!dms || !eth_hdr || hdr_len < sizeof(*eth))
		return 0;

	ethertype = eth->h_proto;
	l3_off = sizeof(*eth);

	/*
	 * Parse just enough of the L3/L4 header to evaluate the registered match
	 * rules.  Every read is bounds-checked against hdr_len; a truncated
	 * header leaves ip_proto/udp_dport at 0, which does not match a non-zero
	 * rule field, so such a frame is unclaimed (the function returns 0).
	 */
	if (ethertype == htons(ETH_P_IP) &&
	    hdr_len >= l3_off + sizeof(struct iphdr)) {
		const struct iphdr *ip4 =
			(const void *)((const u8 *)eth_hdr + l3_off);
		u32 ihl = ip4->ihl * 4u;

		/*
		 * Only trust the IPv4 fields once the captured header covers the
		 * full IHL (base header + any options).  A frame whose IHL
		 * advertises options beyond hdr_len is truncated; leaving
		 * ip_proto at 0 keeps it from matching an ip_proto rule, so such
		 * a frame stays unclaimed and is handed to the host network
		 * stack.
		 */
		if (ihl >= sizeof(struct iphdr) && hdr_len >= l3_off + ihl) {
			ip_proto = ip4->protocol;
			if (ip_proto == IPPROTO_UDP &&
			    hdr_len >= l3_off + ihl + sizeof(struct udphdr)) {
				const struct udphdr *udp = (const void *)
					((const u8 *)eth_hdr + l3_off + ihl);

				udp_dport = udp->dest;
			}
		}
	} else if (ethertype == htons(ETH_P_IPV6) &&
		   hdr_len >= l3_off + sizeof(struct ipv6hdr)) {
		const struct ipv6hdr *ip6 =
			(const void *)((const u8 *)eth_hdr + l3_off);

		ip_proto = ip6->nexthdr;
		if (ip_proto == IPPROTO_UDP &&
		    hdr_len >= l3_off + sizeof(*ip6) + sizeof(struct udphdr)) {
			const struct udphdr *udp = (const void *)
				((const u8 *)eth_hdr + l3_off + sizeof(*ip6));

			udp_dport = udp->dest;
		}
	}

	for (i = 1; i < HFI2_DMS_ULP_MAX; i++) {
		const struct hfi2_dms_ulp_match *m = &dms->eth_match[i];

		if (m->ulp_id == 0)
			continue;
		if (m->ethertype && m->ethertype != ethertype)
			continue;
		if (m->ip_proto && m->ip_proto != ip_proto)
			continue;
		if (m->udp_dport && m->udp_dport != udp_dport)
			continue;
		if (ulp_best == 0 || m->prio > prio_best) {
			prio_best = m->prio;
			ulp_best = m->ulp_id;
		}
	}

	/*
	 * 0 means "no ULP claims this frame": it belongs to the host network
	 * stack and the caller must hand it to the cn6k Ethernet netdev path
	 * (copy-into-skb), never drop it.  Eager forwarding is NOT required for
	 * that delivery.
	 */
	return ulp_best;
}

static int _poll_data_rcd(struct hfi2_dms *dms, u32 budget)
{
	DMS_BUG_ON(!dms);

	struct hfi2_ctxtdata *rcd = dms->rcd_data;
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const maxcnt = get_hdrq_cnt(rcd) * rsize;
	u32 const max_packets = min_t(u32, budget, rcd->rcvhdrq_cnt);
	u32 rhqoff = hfi2_rcd_head(rcd);
	__le32 *rhf_addr = _get_rhf_addr(rcd, rhqoff);
	u64 rhf = rhf_to_cpu(rhf_addr);
	u32 numpkt = 0;
	u64 start = dms_rdtsc();
	/*
	 * RoCE bypass frames land in eager buffers (DMS data packets use the
	 * expected/TID path and never do).  Track eager returns only for the
	 * bypass path so the eager ring does not stall RoCE RX.
	 */
	u8 updegr = 0;
	u32 etail = (u32)-1;

	/* Order RHF sequence read before header/payload reads */
	smp_rmb();
	while (_rhf_rcv_seq(rhf) == rcd->seq_cnt) {
		union hfi2_dms_16b_header *hdr;
		enum hfi2_dms_msg_type msg_type;
		u8 ulp_id, subtype;

		if (numpkt >= max_packets)
			break;

		if (!_rhf_is_valid_16b(rhf)) {
			_log_rhe_reason(dms, rcd, rhf, rhqoff, rsize);
			goto next_packet;
		}

		_dms_rhf_test(dms, rhf);
		hdr = _get_16b_hdr(rcd, rhf_addr, rhf);

		msg_type = hfi2_dms_impl_message_type_get(hdr);
		if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
			dms->counters.rx_received[msg_type]++;

		switch (msg_type) {
		case HFI2_DMS_MSG_TYPE_DATA:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA))
				hfi2_dms_handle_data(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REPLAY))
				hfi2_dms_handle_data(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE))
				hfi2_dms_handle_data_speculative(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START:
		case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
		case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
		case HFI2_DMS_MSG_TYPE_DATA_REQUEST:
		case HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY:
		case HFI2_DMS_MSG_TYPE_WRITE_START:
		case HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY:
		case HFI2_DMS_MSG_TYPE_WRITE_START_EAGER:
		case HFI2_DMS_MSG_TYPE_WRITE_START_TINY:
		case HFI2_DMS_MSG_TYPE_DATA_START:
		case HFI2_DMS_MSG_TYPE_DATA_START_EAGER:
		case HFI2_DMS_MSG_TYPE_ACK:
		case HFI2_DMS_MSG_TYPE_NACK:
		case HFI2_DMS_MSG_TYPE_STATUS_RESPONSE:
		case HFI2_DMS_MSG_TYPE_STATUS_REQUEST:
			dd_dev_warn(dms->dd,
				    "Received unexpected message type: %d\n",
				    msg_type);
			WARN_ON_ONCE(true);
			break;

		default:
			/*
			 * A non-native msg_type ordinal lands here.  Decode the
			 * ULP namespace: for a ULP packet (ulp_id != 0) the raw
			 * message byte carries the ulp_id in its high bits, so
			 * it is not a valid enum hfi2_dms_msg_type ordinal and
			 * must never index the msg_type-sized packet_drop table.
			 * Dispatch such packets to their ULP handler; a genuine
			 * unknown native ordinal is logged as an error below.
			 */
			if (WARN_ON_ONCE(hfi2_dms_16b_ulp_decode(hdr, &ulp_id,
								 &subtype)))
				break;
			if (ulp_id != 0) {
				u32 egr_idx = wfr_rhf_egr_index(rhf);
				u32 egr_offset = rhf_egr_buf_offset(rhf);
				void *ebuf = rhf_use_egr_bfr(rhf) && rcd->egrbufs.rcvtids &&
					egr_idx < rcd->egrbufs.alloced &&
					rcd->egrbufs.rcvtids[egr_idx].addr ?
					(void *)((u64)rcd->egrbufs.rcvtids[egr_idx].addr +
						 egr_offset * RCV_BUF_BLOCK_SIZE) :
					NULL;
				struct hfi2_dms_ulp_rx const rx =
					_dms_build_ulp_rx(rcd, rhf, hdr, ebuf);

				hfi2_dms_ulp_dispatch_rx(dms, ulp_id, subtype,
							 &rx);
				break;
			}
			dd_dev_err(dms->dd,
				   "Received unknown message type: %d\n",
				   msg_type);
			break;
		}
next_packet:
		if (rhf_use_egr_bfr(rhf)) {
			u32 egr_idx = wfr_rhf_egr_index(rhf);
			u32 egr_offset = rhf_egr_buf_offset(rhf);

			etail = egr_idx;
			updegr |= !(egr_idx & (rcd->egrbufs.threshold - 1)) && !egr_offset;
		}
		numpkt++;
		if (!(rhqoff & 0xff)) {
			hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, 0);
			updegr = 0;
		}

		if (++rcd->seq_cnt > RHF_MAX_SEQ)
			rcd->seq_cnt = 1;
		rhqoff += rsize;
		if (rhqoff >= maxcnt)
			rhqoff = 0;
		rhf_addr = _get_rhf_addr(rcd, rhqoff);
		rhf = rhf_to_cpu(rhf_addr);
		/* Order RHF sequence read before header/payload reads */
		smp_rmb();
	}

	hfi2_set_rcd_head(rcd, rhqoff);
	dms->counters.hdrq_drain_packet += dms_rdtsc() - start;

	if (numpkt > 0)
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, numpkt);

	return numpkt;
}

static bool _access_deferred_find(struct hfi2_dms *dms,
				  hfi2_dms_rift_key_t remote_rift_key,
				  u32 remote_lid)
{
	struct hfi2_dms_deferred_start *entry;

	list_for_each_entry(entry, &dms->access_deferred.active, node) {
		if (entry->op == HFI2_DMS_OP_RDMA_READ) {
			if (entry->read.metadata.rx_rift_key.value == remote_rift_key.value &&
			    entry->read.metadata.slid == remote_lid)
				return true;
		} else {
			if (entry->write.metadata.tx_rift_key.value == remote_rift_key.value &&
			    entry->write.metadata.slid == remote_lid)
				return true;
		}
	}
	return false;
}

static void _access_deferred_add(struct hfi2_dms *dms,
				 enum hfi2_dms_op op,
				 const void *metadata,
				 const void *params)
{
	struct hfi2_dms_deferred_start *entry;

	DMS_BUG_ON(!dms);

	if (list_empty(&dms->access_deferred.free)) {
		dms->counters.access_deferred_full++;
		if (op == HFI2_DMS_OP_RDMA_READ) {
			const struct hfi2_dms_read_start_metadata *m = metadata;
			const struct hfi2_dms_read_start_parameters *p = params;

			_nack_log(dms, HFI2_DMS_ERR_TYPE_RNR, p->dms_key);
			_inject_nack(dms, HFI2_DMS_MSG_TYPE_READ_START,
				     HFI2_DMS_ERR_TYPE_RNR,
				     m->port_idx, m->slid, m->rx_rift_key);
			dms->counters.rnr_nack_sent++;
		} else {
			const struct hfi2_dms_write_start_metadata *m = metadata;
			const struct hfi2_dms_write_start_parameters *p = params;

			_nack_log(dms, HFI2_DMS_ERR_TYPE_RNR, p->dms_key);
			_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START,
				     HFI2_DMS_ERR_TYPE_RNR,
				     m->port_idx, m->slid, m->tx_rift_key);
			dms->counters.rnr_nack_sent++;
		}
		return;
	}

	entry = list_first_entry(&dms->access_deferred.free,
				 struct hfi2_dms_deferred_start, node);
	list_del(&entry->node);

	entry->retries = 0;
	entry->op = op;
	if (op == HFI2_DMS_OP_RDMA_READ) {
		entry->read.metadata = *(const struct hfi2_dms_read_start_metadata *)metadata;
		entry->read.parameters = *(const struct hfi2_dms_read_start_parameters *)params;
	} else {
		entry->write.metadata = *(const struct hfi2_dms_write_start_metadata *)metadata;
		entry->write.parameters = *(const struct hfi2_dms_write_start_parameters *)params;
	}

	list_add_tail(&entry->node, &dms->access_deferred.active);
	dms->access_deferred.count++;
	dms->counters.access_deferred_count++;
}

static void _access_deferred_retry_all(struct hfi2_dms *dms)
{
	struct hfi2_dms_deferred_start *entry, *tmp;

	DMS_BUG_ON(!dms);

	if (list_empty(&dms->access_deferred.active))
		return;

	list_for_each_entry_safe(entry, tmp, &dms->access_deferred.active, node) {
		enum hfi2_dms_op saved_op = entry->op;
		int ret;

		if (entry->retries > HFI2_DMS_ACCESS_DEFERRED_MAX_RETRIES) {
			/* Deferred pool already covered the MR-reg race
			 * window; promote to fatal ACCESS_NOT_FOUND.
			 */
			if (entry->op == HFI2_DMS_OP_RDMA_READ) {
				_nack_log(dms, HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					  entry->read.parameters.dms_key);
				_inject_nack(dms, HFI2_DMS_MSG_TYPE_READ_START,
					     HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					     entry->read.metadata.port_idx, entry->read.metadata.slid,
					     entry->read.metadata.rx_rift_key);
			} else {
				_nack_log(dms, HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					  entry->write.parameters.dms_key);
				_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START,
					     HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND,
					     entry->write.metadata.port_idx,
					     entry->write.metadata.slid,
					     entry->write.metadata.tx_rift_key);
			}
			list_del(&entry->node);
			entry->op = HFI2_DMS_OP_NONE;
			list_add_tail(&entry->node, &dms->access_deferred.free);
			dms->access_deferred.count--;
			dms->counters.access_deferred_nack++;
			dms->counters.access_deferred_nack_fatal++;
			continue;
		}

		if (entry->op == HFI2_DMS_OP_RDMA_READ)
			ret = hfi2_dms_impl_handle_read_start(dms,
				&entry->read.metadata,
				&entry->read.parameters, NULL);
		else
			ret = hfi2_dms_impl_handle_write_start(dms,
				&entry->write.metadata,
				&entry->write.parameters, NULL, NULL, 0);

		if (ret == 0) {
			list_del(&entry->node);
			entry->op = HFI2_DMS_OP_NONE;
			list_add_tail(&entry->node, &dms->access_deferred.free);
			dms->access_deferred.count--;
			dms->counters.access_deferred_retry_ok++;
		} else {
			entry->retries++;
		}
		(void)saved_op;
	}
}

#if HFI2_BULKSVC_ULP_STUBS
void hfi2_dms_eal_init_rcd(struct hfi2_dms *dms, struct hfi2_ctxtdata *rcd,
			   u8 pidx)
{
	u8 lb_pidx = loopback_pidx_dd(dms->dd, pidx);

	if (dms->dd->rcv_hdr_ent_size <= 2 ||
	    dms->dd->rcv_hdr_ent_size - 2 < HFI2_DMS_CTRL_HDR_SIZE)
		dd_dev_warn_ratelimited(dms->dd,
					"EAL HDRQ-inline prefix is shorter than the assumed EAL+TS+Eth/IPv4/UDP budget; frames may be dropped by header-budget checks\n");

	dms->rcd_ctrl = rcd;
	/* Program the same split on loopback without changing RoCE port state. */
	_dms_rcv_context_disable9B(dms, pidx, rcd);
	_set_split_point(dms, pidx, rcd, hfi2_dms_eth_bypass_hdr_dws(dms->dd));
	_dms_rcv_context_disable9B(dms, lb_pidx, rcd);
	_set_split_point(dms, lb_pidx, rcd, hfi2_dms_eth_bypass_hdr_dws(dms->dd));
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_ctrl;
}

int hfi2_dms_eal_poll(struct hfi2_dms *dms)
{
	return _poll_ctrl_rcd(dms, HFI2_DMS_PER_POLL_MAX_PACKETS);
}
#endif

static int _poll_ctrl_rcd(struct hfi2_dms *dms, u32 budget)
{
	DMS_BUG_ON(!dms);

	struct hfi2_ctxtdata *rcd = dms->rcd_ctrl;
	u32 const rsize = get_hdrqentsize(rcd);
	u32 const maxcnt = get_hdrq_cnt(rcd) * rsize;
	u32 const max_packets = min_t(u32, budget, rcd->rcvhdrq_cnt);
	u32 rhqoff = hfi2_rcd_head(rcd);
	__le32 *rhf_addr = _get_rhf_addr(rcd, rhqoff);
	u64 rhf = rhf_to_cpu(rhf_addr);
	u64 start = dms_rdtsc();
	u32 numpkt = 0;
	u8 rcv_port;
	u8 updegr = 0;
	u32 etail = (u32)-1;

	/* Order RHF sequence read before header/payload reads */
	smp_rmb();
	while (_rhf_rcv_seq(rhf) == rcd->seq_cnt) {
		union hfi2_dms_16b_header *hdr;
		enum hfi2_dms_msg_type msg_type;
		void *ebuf = NULL;
		u32 egr_idx = wfr_rhf_egr_index(rhf);
		u32 egr_offset = rhf_egr_buf_offset(rhf);
		u32 prev_etail = etail;
		u8 prev_updegr = updegr;
		u8 ulp_id, subtype;

		if (numpkt >= max_packets)
			break;

		if (rhf_use_egr_bfr(rhf)) {
			etail = egr_idx;
			updegr |= !(egr_idx & (rcd->egrbufs.threshold - 1)) && !egr_offset;
		}

		/*
		 * Bypass frames do not carry native 16B framing, so intercept EAL
		 * Ethernet before the native-16B validity gate below.
		 */
		if (unlikely(rhf_rcv_type(rhf) == RHF_RCV_TYPE_BYPASS &&
			     hfi2_is_eth_mode(dms->dd))) {
			const struct eal_ingress_header *eal_hdr;
			struct hfi2_dms_ulp_rx rx;
			u8 eth_hdr[ETH_HLEN + sizeof(struct iphdr) +
				   MAX_IPOPTLEN + sizeof(struct udphdr)];
			u8 eth_ulp_id;
			u32 eth_hdr_len;
			u32 const header_budget = _eth_bypass_header_budget(rcd, rhf);
			u32 const hw_split = hfi2_dms_eth_bypass_hdr_dws(dms->dd) * sizeof(u32);
			bool const rhe_valid = _rhf_rhe_valid(rhf);
			u64 const err_flags = rhe_valid ? ((u64 *)rcd->rheq)[rhqoff / rsize] : 0;
			bool const tid_overrun = rhe_valid &&
				(err_flags & RHF_ERROR_SMASK) == RHF_TID_ERR;
			bool const valid_egr = rhf_use_egr_bfr(rhf) && rcd->egrbufs.rcvtids &&
				egr_idx < rcd->egrbufs.alloced &&
				rcd->egrbufs.rcvtids[egr_idx].addr;

			/* An overrun names the last filled slot; other frames must use one. */
			if (tid_overrun ? egr_idx >= rcd->egrbufs.alloced : !valid_egr) {
				etail = prev_etail;
				updegr = prev_updegr;
			}

			/* Drop errored bypass frames before parsing attacker-controlled bytes. */
			if (rhe_valid) {
				if (tid_overrun && egr_idx < rcd->egrbufs.alloced)
					updegr = 1;
				dms->counters.eal_bypass_rhe_error_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: RHF error bit set (rhf=0x%016llx)\n",
					 (unsigned long long)rhf);
				goto next_packet;
			}
			if (rhf_use_egr_bfr(rhf)) {
				if (unlikely(!valid_egr)) {
					dms->counters.eal_bypass_egr_bounds_drop++;
					dd_dev_warn_ratelimited
						(dms->dd,
						 "EAL bypass frame dropped: eager index %u invalid (alloced %u)\n",
						 egr_idx, rcd->egrbufs.alloced);
					goto next_packet;
				}
				ebuf = (void *)(((u64)(rcd->egrbufs.rcvtids[egr_idx].addr)) +
						(egr_offset * RCV_BUF_BLOCK_SIZE));
			}
			hdr = _get_16b_hdr(rcd, rhf_addr, rhf);
			eal_hdr = (const void *)hdr;
			if (header_budget < sizeof(*eal_hdr)) {
				dms->counters.eal_bypass_header_short_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: header_budget %u too small for EAL header (%zu)\n",
					 header_budget, sizeof(*eal_hdr));
				goto next_packet;
			}
			/* Eager data starts at the hardware split, not at header_budget. */
			if (header_budget < hw_split && rhf_pkt_len(rhf) > header_budget) {
				dms->counters.eal_bypass_header_short_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: header_budget %u smaller than the hardware split %u\n",
					 header_budget, hw_split);
				goto next_packet;
			}
			if (EAL_INGRESS_GET_L4(eal_hdr) != EAL_INGRESS_L4_ETHERNET ||
			    EAL_INGRESS_GET_TYPE(eal_hdr) != EAL_INGRESS_TYPE_ETHERNET) {
				dms->counters.eal_bypass_header_mismatch_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: unexpected L4/Type in EAL ingress header (L4=%llu Type=%llu)\n",
					 (unsigned long long)EAL_INGRESS_GET_L4(eal_hdr),
					 (unsigned long long)EAL_INGRESS_GET_TYPE(eal_hdr));
				goto next_packet;
			}
			if (!_dms_build_eth_ulp_rx(rcd, rhf, eal_hdr, ebuf, &rx)) {
				dms->counters.eal_bypass_ulp_build_drop++;
				dd_dev_warn_ratelimited
					(dms->dd,
					 "EAL bypass frame dropped: failed to build ULP rx descriptor\n");
				goto next_packet;
			}

			eth_hdr_len = hfi2_dms_ulp_rx_copy_prefix(&rx, eth_hdr,
								  sizeof(eth_hdr));
			eth_ulp_id = hfi2_dms_ulp_classify(dms, eth_hdr, eth_hdr_len);
			if (eth_ulp_id)
				hfi2_dms_ulp_dispatch_rx(dms, eth_ulp_id, 0, &rx);
			else
				cne_ulp_fallthrough(dms, &rx);
			goto next_packet;
		}

		if (!_rhf_is_valid_16b(rhf)) {
			_log_rhe_reason(dms, rcd, rhf, rhqoff, rsize);
			goto next_packet;
		}

		if (rhf_use_egr_bfr(rhf) && rcd->egrbufs.rcvtids &&
		    egr_idx < rcd->egrbufs.alloced && rcd->egrbufs.rcvtids[egr_idx].addr) {
			ebuf = (void *)(((u64)(rcd->egrbufs.rcvtids[egr_idx].addr)) +
					(egr_offset * RCV_BUF_BLOCK_SIZE));
		}

		_dms_rhf_test(dms, rhf);
		hdr = _get_16b_hdr(rcd, rhf_addr, rhf);
		rcv_port = _rhf_rcv_port(rhf);
		/* Native 16B framing cannot occur in eth mode; drop any hardware anomaly. */
		if (hfi2_is_eth_mode(dms->dd)) {
			dms->counters.eal_native16b_in_eth_mode_drop++;
			dd_dev_warn_ratelimited
				(dms->dd,
				 "Native 16B frame dropped in eth mode (rhf=0x%016llx)\n",
				 (unsigned long long)rhf);
			goto next_packet;
		}

		msg_type = hfi2_dms_impl_message_type_get(hdr);
		if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
			dms->counters.rx_received[msg_type]++;

		switch (msg_type) {
		case HFI2_DMS_MSG_TYPE_READ_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, false);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, true);
			break;

		case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_READ_START_REPLAY))
				hfi2_dms_impl_handle_read_start_packet(dms, rcv_port, hdr,
								       ebuf, false);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REQUEST:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REQUEST))
				hfi2_dms_impl_handle_data_request_packet(dms, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY))
				hfi2_dms_impl_handle_data_request_packet(dms, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
								       false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
									false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_EAGER:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_EAGER))
				hfi2_dms_impl_handle_write_start_packet(dms, rcv_port,
								       true, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_WRITE_START_TINY:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_WRITE_START_TINY))
				hfi2_dms_impl_handle_write_start_tiny_packet(dms, rcv_port,
									     hdr);
			break;

		case HFI2_DMS_MSG_TYPE_ACK:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_ACK))
				hfi2_dms_impl_handle_ack(dms, hdr, HFI2_DMS_MSG_TYPE_ACK);
			break;

		case HFI2_DMS_MSG_TYPE_NACK:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_NACK))
				hfi2_dms_impl_handle_nack_packet(dms, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_STATUS_RESPONSE:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_STATUS_RESPONSE))
				hfi2_dms_impl_handle_status_response_packet(dms, rcv_port, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_STATUS_REQUEST:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_STATUS_REQUEST))
				hfi2_dms_impl_handle_status_request_packet(dms, rcv_port, hdr);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_START:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_START))
				hfi2_dms_handle_data_start_packet(dms, false, hdr, NULL);
			break;

		case HFI2_DMS_MSG_TYPE_DATA_START_EAGER:
			if (!_test_drop_packet(dms, HFI2_DMS_MSG_TYPE_DATA_START_EAGER))
				hfi2_dms_handle_data_start_packet(dms, true, hdr, ebuf);
			break;

		case HFI2_DMS_MSG_TYPE_DATA:
		case HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE:
			dms->counters.ctrl_rcd_unexpected_data++;
			dd_dev_warn(dms->dd,
				    "Received unexpected message type: %d\n",
				    msg_type);
			WARN_ON_ONCE(true);
			break;

		default:
			/*
			 * A non-native msg_type ordinal lands here.  Decode the
			 * ULP namespace: for a ULP packet (ulp_id != 0) the raw
			 * message byte carries the ulp_id in its high bits, so
			 * it is not a valid enum hfi2_dms_msg_type ordinal and
			 * must never index the msg_type-sized packet_drop table.
			 * Dispatch such packets to their ULP handler; a genuine
			 * unknown native ordinal is logged as an error below.
			 */
			if (WARN_ON_ONCE(hfi2_dms_16b_ulp_decode(hdr, &ulp_id,
								 &subtype)))
				break;
			if (ulp_id != 0) {
				struct hfi2_dms_ulp_rx const rx =
					_dms_build_ulp_rx(rcd, rhf, hdr, ebuf);

				hfi2_dms_ulp_dispatch_rx(dms, ulp_id, subtype,
							 &rx);
				break;
			}
			dd_dev_err(dms->dd,
				   "Received unknown message type: %d\n",
				   msg_type);
			break;
		}
next_packet:
		numpkt++;
		if (!(rhqoff & 0xff)) {
			hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, 0);
			updegr = 0;
		}

		if (++rcd->seq_cnt > RHF_MAX_SEQ)
			rcd->seq_cnt = 1;
		rhqoff += rsize;
		if (rhqoff >= maxcnt)
			rhqoff = 0;
		rhf_addr = _get_rhf_addr(rcd, rhqoff);
		rhf = rhf_to_cpu(rhf_addr);
		/* Order RHF sequence read before header/payload reads */
		smp_rmb();
	}

	hfi2_set_rcd_head(rcd, rhqoff);
	dms->counters.hdrq_drain_packet += dms_rdtsc() - start;

	if (numpkt > 0)
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, numpkt);

	return numpkt;
}

static void _noop_handle_packet(struct hfi2_packet *packet)
{
	(void) packet;
}


static void hfi2_dms_impl_reclaim_ahg(struct hfi2_dms *dms, struct sdma_engine *sde, struct hfi2_dms_sde_rsrc *sde_rsrc)
{
	u32 descq_head;
	u32 descq_tail;
	struct hfi2_dms_ahg_header_set *ahg_header_set;
	u32 ahg_desc;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(sde == NULL);
	DMS_WARN_ON(sde_rsrc == NULL);

	descq_head = sde->descq_head;
	descq_tail = sde->descq_tail;
	if (descq_head == descq_tail) {
		// reclaim all
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	} else if (descq_head < descq_tail) {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc > descq_head && ahg_desc <= descq_tail) {
				// this is within our list and our headers
				// are in-order here so we can just stop
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	} else {
		while (sde_rsrc->active_ahg_headers.head != NULL) {
			ahg_header_set = (struct hfi2_dms_ahg_header_set *) sde_rsrc->active_ahg_headers.head;
			ahg_desc = ahg_header_set->desc_idx;
			if (ahg_desc <= descq_tail || ahg_desc > descq_head) {
				// tail has wrapped, so this is within our list
				// and we can stop searching
				break;
			}
			//pr_debug("Reclaiming AHG header used in engine %d at idx %u [head, tail): [%u, %u)\n", sde->this_idx, ahg_desc, descq_head, descq_tail);
			hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
			hfi2_dms_impl_dlist_append(
				&dms->ahg_headers[ahg_header_set->port_idx].free,
				&ahg_header_set->dlist);
		}
	}
}

/*
 * Shared engines: other lanes advance the ring too, so a ring index cannot
 * tell this lane's in-flight header sets from ones that egressed a lap ago.
 * Compare the placed-descriptor count recorded with each set against the
 * engine's head on the same scale instead.  This lane's sets are queued in
 * placement order, so stop at the first one still in flight.
 */
static void hfi2_dms_impl_reclaim_ahg_shared(struct hfi2_dms *dms, u32 idx)
{
	struct hfi2_dms_sde_rsrc *sde_rsrc = &dms->sde_rsrcs[idx];
	struct sdma_engine *sde = dms->sdma_engines[idx];
	struct hfi2_dms_ahg_header_set *ahg_header_set;
	u64 head_seq;

	if (!sde_rsrc->active_ahg_headers.head)
		return;

	hfi2_dms_sde_lock(dms, idx);
	sdma_gethead_dma(sde);
	head_seq = hfi2_dms_sde_head_seq(dms, idx, sde->descq_tail,
					 READ_ONCE(sde->descq_head),
					 sde->descq_cnt);
	hfi2_dms_sde_unlock(dms, idx);

	while (sde_rsrc->active_ahg_headers.head) {
		ahg_header_set = (struct hfi2_dms_ahg_header_set *)
				 sde_rsrc->active_ahg_headers.head;
		if (ahg_header_set->seq_end > head_seq)
			break;
		hfi2_dms_impl_dlist_pop(&sde_rsrc->active_ahg_headers);
		hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_header_set->port_idx].free,
					   &ahg_header_set->dlist);
	}
}

static bool _tracker_is_stale(union hfi2_dms_tracker const * const tracker, ktime_t const now)
{
	return ktime_after(now, tracker->hdr.stale_time);
}

static bool _tracker_is_dead(union hfi2_dms_tracker const * const tracker, ktime_t const now)
{
	/*
	 * Dead if EITHER clock trips: progress stalled (odometer idle for
	 * PROGRESS_MAX_NS) or absolute lifetime exceeded. last_progress_time is
	 * refreshed on real byte progress, not peer-request arrival, so a
	 * status-polled but zero-progress chain-head is still reclaimed.
	 */
	bool const progress_stalled = ktime_after(now,
		ktime_add_ns(tracker->hdr.last_progress_time,
			     HFI2_DMS_TRACKER_PROGRESS_MAX_NS));
	bool const lifetime_exceeded = ktime_after(now,
		ktime_add_ns(tracker->hdr.birth_time,
			     HFI2_DMS_TRACKER_ABSOLUTE_MAX_NS));
	bool const res = progress_stalled || lifetime_exceeded;

	if (res) {
		pr_debug("(%d) Tracker is dead (l:%05u r:%05u); sr=%u odo=%llu\n",
			 __LINE__, tracker->hdr.local_rift_key.value,
			 tracker->hdr.remote_rift_key.value,
			 tracker->hdr.status_req_count,
			 tracker->hdr.byte_odometer);
	}
	return res;
}

static void hfi2_dms_poll_stale(struct hfi2_dms *dms)
{
	static int const err = -ETIMEDOUT;

	DMS_BUG_ON(!dms);

	ktime_t const now = dms->now;

	// remove any disabled tidsets
	u32 const sz = HFI2_DMS_ARRAY_SIZE(dms->read_requests);
	for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
		struct hfi2_dms_read_request_state *read_request = &dms->read_requests[tid_set];
		enum hfi2_dms_tidset_state const state = read_request->state;

		if (state == HFI2_DMS_TIDSET_STATE_DISABLED) {
			if (ktime_to_ns(ktime_sub(now, read_request->disable_ts)) > HFI2_DMS_FABRIC_PACKET_MAX_LIFETIME_NS) {
				dms->counters.health_tidset_disabled_removed++;
				dd_dev_dbg(dms->dd, "Removed disabled tidset read request\n");
				_tidset_free_then_poll_waiters(dms, tid_set);
			}
		} else if (state == HFI2_DMS_TIDSET_STATE_ENABLED) {
			if (ktime_after(now, read_request->stale_time)) {
				struct hfi2_dms_rx_tracker *rx_tracker = read_request->rx_tracker;
				DMS_BUG_ON(rx_tracker == &dms->disabled_rx_tracker);

				/* fast_fail cancels here, before the DRAINING
				 * re-arm would starve the tracker-level cancel.
				 */
				if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)
								  rx_tracker))
					continue;

				read_request->drain_count += 1;

				read_request->state = HFI2_DMS_TIDSET_STATE_DRAINING;
				/*
				 * The request is abandoned until re-injected:
				 * disarm its edge copy-out and stop DATA from
				 * landing in the bounce page meanwhile.
				 */
				if (dms->read_request_chunks[tid_set].scatter_count) {
					dms->read_request_chunks[tid_set].scatter_valid = false;
					_tidset_bounce_detach(dms, tid_set);
				}
				read_request->drain_time = ktime_add_ns(now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);

				_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * (HFI2_DMS_STALE_BACKOFF_BASE_MS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT)));

				dms->counters.health_tidset_draining++;
				dd_dev_dbg(dms->dd,
					"tidset DRAINING: tid_set %u (l:%05u r:%05u) drain_count=%u remaining_qws=%llu\n",
					tid_set, rx_tracker->hdr.local_rift_key.value,
					rx_tracker->hdr.remote_rift_key.value,
					read_request->drain_count, read_request->remaining_qws);
			}
		} else if (state == HFI2_DMS_TIDSET_STATE_DRAINING) {
			/*
			 * DRAINING tidset: drain timer has been set. When it
			 * expires, re-inject the DATA_REQUEST using saved
			 * parameters. The same tidset is reused (no disable,
			 * no fresh allocation). If drain_count exceeds max
			 * retries, disable the tidset and cancel the tracker.
			 */
			if (ktime_after(now, read_request->drain_time)) {
				struct hfi2_dms_rx_tracker *rx_tracker = read_request->rx_tracker;

				/* Backstop cancel for a DRAINING tidset that
				 * bypassed the ENABLED-arm cancel above.
				 */
				if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)
								  rx_tracker))
					continue;

				if (read_request->drain_count > HFI2_DMS_STALE_BACKOFF_MAX_COUNT) {
					/* Drained-out unlatched speculative read
					 * falls back to legacy READ_START.
					 */
					if (_rx_tracker_spec_unlatched(rx_tracker)) {
						_dms_rx_spec_fallback_to_legacy(dms, rx_tracker);
						continue;
					}
					/* Exceeded max retries - give up on this tidset and cancel the tracker */
					dms->counters.health_tidset_drain_failed++;
					dd_dev_dbg(dms->dd,
						"tidset DRAIN FAILED: tid_set %u (l:%05u r:%05u) drain_count=%u > max=%u - canceling tracker\n",
						tid_set, rx_tracker->hdr.local_rift_key.value,
						rx_tracker->hdr.remote_rift_key.value,
						read_request->drain_count,
						(u32)HFI2_DMS_STALE_BACKOFF_MAX_COUNT);
					hfi2_dms_rx_tracker_cancel(dms, rx_tracker, -ETIMEDOUT);
					continue;
				}

				struct hfi2_dms_read_request_chunks *rc =
					&dms->read_request_chunks[tid_set];
				int ret;
				read_request->generation += 1;

				/*
				 * The re-request re-sends the whole saved request, so
				 * re-arm its edge copy-out for the new generation and
				 * remap the bounce pair before the responder can send.
				 */
				if (rc->scatter_count) {
					rc->scatter_generation = read_request->generation;
					rc->scatter_valid = true;
					_tidset_bounce_attach(dms, tid_set);
				}

				ret = _inject_data_request_replay(dms, tid_set);
				if (ret < 0) {
					if (rc->scatter_count) {
						rc->scatter_valid = false;
						_tidset_bounce_detach(dms, tid_set);
					}
					read_request->generation -= 1;
					dms->counters.health_tidset_drain_reinject_fail++;
					dd_dev_dbg(dms->dd,
						"tidset DRAIN re-inject failed: tid_set %u ret=%d\n",
						tid_set, ret);
					/* Retry on next poll cycle */
					read_request->drain_time = ktime_add_ns(now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS);
					continue;
				}

				dms->counters.health_tidset_drain_reinject++;
				dd_dev_dbg(dms->dd,
					"tidset DRAIN re-inject: tid_set %u (l:%05u r:%05u) drain_count=%u\n",
					tid_set, rx_tracker->hdr.local_rift_key.value,
					rx_tracker->hdr.remote_rift_key.value,
					read_request->drain_count);

				read_request->remaining_qws = read_request->total_requested_qws;
				read_request->state = HFI2_DMS_TIDSET_STATE_ENABLED;

				u64 stale_backoff_ns = HFI2_DMS_TIDSET_STALE_TIMEOUT_NS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT);
				read_request->stale_time = ktime_add_ns(now, stale_backoff_ns);

				_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * (HFI2_DMS_STALE_BACKOFF_BASE_MS << min(read_request->drain_count, (u8)HFI2_DMS_STALE_BACKOFF_MAX_COUNT)));
			}
		}
	}

	/* check stale/dead active trackers — batch by remote LID */
	DECLARE_BITMAP(visited, HFI2_DMS_RIFT_IDX_SIZE);
	bitmap_zero(visited, HFI2_DMS_RIFT_IDX_SIZE);
	hfi2_dms_rift_key_t entries[HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES];

	unsigned long idx;
	for_each_set_bit(idx, dms->rift.occupied, HFI2_DMS_RIFT_IDX_SIZE) {
		union hfi2_dms_tracker *tracker;

		if (test_bit(idx, visited))
			continue;

		tracker = dms->rift.arr[idx];

		if (!_tracker_is_stale(tracker, now))
			continue;

		_tracker_note_progress(dms, tracker);
		if (_tracker_is_dead(tracker, now)) {
			/*
			 * The tracker-dead clock is a fixed deadline independent
			 * of the drain-retry cadence, so under a raised
			 * bulksvc_dms_health_base it can fire before the tidset
			 * drain arm runs its legacy fallback. Recover an unlatched
			 * speculative read here too (unless fast_fail) rather than
			 * forfeit recovery to -ETIMEDOUT.
			 */
			if (_rx_tracker_spec_unlatched(&tracker->rx) &&
			    !tracker->hdr.fast_fail) {
				_dms_rx_spec_fallback_to_legacy(dms, &tracker->rx);
				continue;
			}
			dms->counters.health_tracker_dead++;
			_tracker_cancel(dms, tracker, err);
			continue;
		}

		/*
		 * A fast_fail tracker defers retransmission to its caller: once
		 * stale, cancel to -ETIMEDOUT instead of emitting a STATUS_REQUEST.
		 * A READ target awaiting its DATA_REQUEST probes initiator instead.
		 */
		if (_tx_tracker_is_read_target_awaiting_data_req(tracker))
			dms->counters.health_status_req_fast_fail_read_target++;
		else if (_tracker_cancel_if_fast_fail(dms, tracker))
			continue;

		u32 const lid = tracker->hdr.remote_lid;
		u8 const port_idx = tracker->hdr.port_idx;

		set_bit(idx, visited);
		u8 n_entries = 0;

		if (tracker->hdr.rnr_pending) {
			tracker->hdr.rnr_pending = false;
			if (_tracker_cancel_if_fast_fail(dms, tracker))
				continue;
			u8 generation = tracker->hdr.generation;

			_tracker_reinject_start(dms, tracker);
			if (tracker->hdr.generation != generation)
				continue;
		} else {
			entries[n_entries++] = tracker->hdr.local_rift_key;
		}
		_update_tracker_backoff(dms, tracker);

		unsigned long next = idx + 1;
		for_each_set_bit_from(next, dms->rift.occupied, HFI2_DMS_RIFT_IDX_SIZE) {
			union hfi2_dms_tracker *next_tracker;

			if (test_bit(next, visited))
				continue;

			next_tracker = dms->rift.arr[next];
			if (next_tracker->hdr.remote_lid != lid ||
			    next_tracker->hdr.port_idx != port_idx)
				continue;

			set_bit(next, visited);

			if (!_tracker_is_stale(next_tracker, now))
				continue;

			_tracker_note_progress(dms, next_tracker);
			if (_tracker_is_dead(next_tracker, now)) {
				/* Same unlatched-speculative recovery as the head
				 * tracker above: prefer legacy fallback over an
				 * -ETIMEDOUT cancel when the dead clock beats the
				 * drain arm (unless fast_fail).
				 */
				if (_rx_tracker_spec_unlatched(&next_tracker->rx) &&
				    !next_tracker->hdr.fast_fail) {
					_dms_rx_spec_fallback_to_legacy(dms, &next_tracker->rx);
					continue;
				}
				dms->counters.health_tracker_dead++;
				_tracker_cancel(dms, next_tracker, err);
				continue;
			}

			if (_tx_tracker_is_read_target_awaiting_data_req(next_tracker))
				dms->counters.health_status_req_fast_fail_read_target++;
			else if (_tracker_cancel_if_fast_fail(dms, next_tracker))
				continue;

			if (next_tracker->hdr.rnr_pending) {
				next_tracker->hdr.rnr_pending = false;
				if (_tracker_cancel_if_fast_fail(dms, next_tracker))
					continue;
				u8 generation = next_tracker->hdr.generation;

				_tracker_reinject_start(dms, next_tracker);
				if (next_tracker->hdr.generation != generation)
					continue;
			} else {
				entries[n_entries++] = next_tracker->hdr.local_rift_key;
			}
			_update_tracker_backoff(dms, next_tracker);

			if (n_entries == HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES) {
				_inject_status_request_many(dms, port_idx, lid,
							    entries, n_entries);
				n_entries = 0;
			}
		}

		if (n_entries > 0)
			_inject_status_request_many(dms, port_idx, lid,
						    entries, n_entries);
	}

	ktime_t aging_deadline = ktime_add_ms(dms->cancel_cache.last_aging_time, 5000);
	if (ktime_after(now, aging_deadline)) {
		_cancel_cache_age(dms, now);
		dms->cancel_cache.last_aging_time = now;
	}
}

static void _dms_drain_workqueue(struct hfi2_dms *dms)
{
	ktime_t now = dms->now;

	if (dms->work_items.active.head) {
		struct hfi2_dms_work_item *item, *next_item;

		item = (struct hfi2_dms_work_item *)dms->work_items.active.head;
		while (item) {
			next_item = (struct hfi2_dms_work_item *)item->dlist.next;
			if (item->work_fn(dms, item) != -EAGAIN) {
				hfi2_dms_impl_work_item_free(dms, item);
			} else {
				/*
				 * Signed: now is sampled when the poll starts, so an
				 * item queued later in the same pass has a negative
				 * age. Unsigned, that wrapped past the limit and the
				 * item was dropped on its first -EAGAIN.
				 */
				s64 elapsed_ns = ktime_to_ns(ktime_sub(now, item->enqueue_time));

				if (elapsed_ns > HFI2_DMS_WORK_ITEM_MAX_RETRY_TIME_NS) {
					dd_dev_err(dms->dd,
						   "DMS work item failed after max retry time, discarding.\n");
					hfi2_dms_impl_work_item_free(dms, item);
				}
			}
			item = next_item;
		}
	}
}

int hfi2_dms_poll(struct hfi2_dms *dms, ktime_t const now)
{
	int numpkt = 0;
	u64 start;
	u64 end;
	int i;

	dms->now = now;
	start = dms_rdtsc();
	dms_trace(dms_poll, dms);

	for (i = 0; i < dms->num_engines; ++i) {
		if (dms->sde_share) {
			hfi2_dms_impl_reclaim_ahg_shared(dms, i);
			continue;
		}
		sdma_gethead_dma(dms->sdma_engines[i]);
		hfi2_dms_impl_reclaim_ahg(dms, dms->sdma_engines[i], &dms->sde_rsrcs[i]);
	}
	_sdma_engine_waitlist_poll_all(dms);
	_dms_drain_workqueue(dms);
	numpkt += _pio_waitlist_poll(dms);

	ktime_t next_stale_check = ktime_add_ms(dms->last_stale_check, HFI2_DMS_STALE_POLL_TIME_MS);
	if (ktime_after(now, next_stale_check)) {
		dms->last_stale_check = now;
		hfi2_dms_poll_stale(dms);
	}

	/*
	 * Retry any rx_trackers waiting for tidsets after demand pinning.
	 * The pin queue (serviced by bulksvc just before dms_poll) may
	 * have pinned pages that allow previously-deferred tidset
	 * allocations to succeed now.
	 */
	_service_global_tidset_waiters(dms);

	_access_deferred_retry_all(dms);

	{
		int ctrl_n, data_n;
		int remaining = HFI2_DMS_POLL_TOTAL_PACKET_BUDGET;

		_access_deferred_retry_all(dms);

		do {
			int budget;

			ctrl_n = 0;
			data_n = 0;
			budget = min_t(int, HFI2_DMS_PER_POLL_MAX_PACKETS, remaining);
			if (budget <= 0)
				break;

			ctrl_n = _poll_ctrl_rcd(dms, budget);
			remaining -= ctrl_n;

			data_n = _poll_data_rcd(dms, min_t(int, HFI2_DMS_PER_POLL_MAX_PACKETS, remaining));
			remaining -= data_n;
			numpkt += ctrl_n + data_n;
		} while (ctrl_n + data_n > 0);
	}

	/*
	 * Service rift-poll requests deferred by completion/cancel bodies that
	 * ran nested inside a drive stack. Run before the SDMA drain below so a
	 * tracker driven here egresses its SDMA this same pass. A poll can
	 * itself defer another via an inline completion, so loop until quiet.
	 */
	while (dms->rift.poll_deferred) {
		dms->rift.poll_deferred = false;
		_dms_rift_poll(dms);
	}

	/*
	 * Drain each engine once per poll pass, decoupled from the RX loop
	 * above: batch_commit() only queues onto sde_rsrcs.sdma_pending, and
	 * ring placement + completion firing happen here, so a batch a ULP
	 * committed with no inbound RX still egresses and returns its cookie
	 * this pass.
	 */
	for (i = 0; i < dms->num_engines; ++i)
		numpkt += hfi2_dms_sdma_drain_and_complete(dms, (u8)i);

	while (dms->rift.poll_deferred) {
		dms->rift.poll_deferred = false;
		_dms_rift_poll(dms);
	}

	/*
	 * Packets still waiting for PIO credits or an in-flight P2P flush read
	 * keep the poll busy: nothing else wakes the event loop when the send
	 * context returns credits or the SDMA flush descriptor retires.
	 */
	numpkt += _pio_waitlist_poll(dms);
	if (!_pio_waitlist_empty(dms) || dms->p2p_flush_inflight)
		numpkt++;

	end = dms_rdtsc();
	dms->counters.hdrq_drain += end - start;

	return numpkt;
}

static void hfi2_dms_handle_tx_tracker_completion(struct hfi2_dms *dms, hfi2_dms_rift_key_t tx_rift_key, u16 flags)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(_rift_key_error(tx_rift_key));
	DMS_BUG_ON(!_rift_key_side_tx(tx_rift_key));

	struct hfi2_dms_tx_tracker *tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, tx_rift_key);
	if (!tx_tracker) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
		return;
	}

#if HFI2_DMS_COUNTERS_ENABLE
	tx_tracker->hdr.perf.lifetime[1] = ktime_get();
	_dms_aggregate_perf_counters(dms, (union hfi2_dms_tracker *)tx_tracker);
#endif

	_tracker_rift_release(dms, (union hfi2_dms_tracker *)tx_tracker, &dms->rift);

	/* Parent signals to child upon tx completion. */
	_tracker_signal(dms, (union hfi2_dms_tracker *)tx_tracker, 0);

	// invoke callback for the completed tx tracker
	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, (union hfi2_dms_tracker *)tx_tracker, flags, tx_tracker->read.parameters.imm_data, tx_tracker->hdr.order_key, 0);
		tx_tracker->read.access = NULL;

	} else if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, 0);
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);

	/*
	 * Hand the freed rift key on once this tracker is retired, but defer
	 * the poll: this completion can run nested inside a rift-poll drive.
	 */
	_dms_rift_poll_request(dms);
}

/**
 * These functions exist in some form in hfi2.h but they don't exist in the way
 * we really want them here. Convenience functions for our pre-defined
 * templates
 */
static u64 hfi2_dms_impl_pbc_template_create_16Bc(u8 port_idx, u32 dw_len, u16 sctxt)
{
	u64 ret;

	ret = (u64) sctxt << PBC_SEND_CTXT_SHIFT |
		(u64) PBC_L2_16B << PBC_L2_TYPE_SHIFT |
		(u64) port_idx << PBC_PORT_IDX_SHIFT |
		(u64) (dw_len & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT |
		(u64) PBC_IHCRC_LKDETH << PBC_INSERT_HCRC_SHIFT |
		(u64) 1 << 19 | // 16B Compressed
		(u64) PBC_INSERT_BYPASS_ICRC; // InsertNon9BIcrc
	return ret;
}

static int hfi2_dms_impl_proto_command_template_make(struct hfi2_dms *dms, union hfi2_dms_proto_cmd *cmd, u8 port_idx, enum hfi2_dms_msg_type msg_type, u32 pkt_len_qws, u16 jkey)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(cmd == NULL);
	// Even though the PBC gets stripped, a 16b compressed header will expand by 1 QW as it goes
	// out on the wire, so actually the pktlen_dw in the pbc should be the same as pktlen_qw in the lrh
	cmd->pbc = hfi2_dms_impl_pbc_template_create_16Bc(port_idx, pkt_len_qws << 1, dms->port_sctxts[port_idx]->hw_context);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pkt_len_qws);
	cmd->bth[0] = HFI2_DMS_BTH_OPCODE | ((u32) msg_type << 16);
	cmd->bth[1] = (u32) RVT_KDETH_QP_PREFIX << 8;
	cmd->kdeth[0] = 1 << 30; // set KVER
	cmd->kdeth[1] = jkey;

	return 0;
}

void hfi2_dms_impl_fill_proto_templates(struct hfi2_dms *dms)
{
	union hfi2_dms_proto_cmd *cmd;

	DMS_BUG_ON(dms == NULL);

	for (int i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		if (!dms->port_available[i])
			continue;

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_READ_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_READ_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_READ_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);
		_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
			_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
		}

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_READ_START_REPLAY;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
			_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
		}

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_DATA_REQUEST;
			u64 const size_qws = _pkt_len_qws(t, 0);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_CTRL_JKEY);
		}

		{
			enum hfi2_dms_msg_type const t =
				HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY;
			u64 const size_qws =
				_pkt_len_qws(t, 0);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA_START_EAGER];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA_START_EAGER,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START_EAGER] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_DATA];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_DATA, sizeof(union hfi2_dms_proto_pkt_data)/sizeof(u64), HFI2_DMS_DATA_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_DATA_REPLAY;
			u64 const size_qws =
				sizeof(union hfi2_dms_proto_pkt_data) / sizeof(u64);

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, size_qws,
								  HFI2_DMS_DATA_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates
			[i][HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i,
							  HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE,
			sizeof(union hfi2_dms_proto_pkt_data) / sizeof(u64), HFI2_DMS_DATA_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_WRITE_START];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_WRITE_START,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_WRITE_START] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY;
			u64 const offset_qws = _msgtype_wire_payload_offset[t] / 8;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t, offset_qws + 1,
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_WRITE_START_EAGER];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_WRITE_START_EAGER,
			(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_WRITE_START_EAGER] / 8) + 1,	/* "+1 is for the tail flit "*/
			HFI2_DMS_CTRL_JKEY);

		{
			enum hfi2_dms_msg_type const t = HFI2_DMS_MSG_TYPE_WRITE_START_TINY;

			cmd = (union hfi2_dms_proto_cmd *)&dms->protocol_cmd_templates[i][t];
			hfi2_dms_impl_proto_command_template_make(dms, cmd, i, t,
								  _pkt_len_qws(t, 0),
								  HFI2_DMS_CTRL_JKEY);
		}

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_ACK];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_ACK, sizeof(union hfi2_dms_proto_pkt_ack)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_NACK];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_NACK, sizeof(union hfi2_dms_pkt_nack)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_STATUS_RESPONSE];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_STATUS_RESPONSE, sizeof(union hfi2_dms_pkt_status)/sizeof(u64), HFI2_DMS_CTRL_JKEY);

		cmd = (union hfi2_dms_proto_cmd *) &dms->protocol_cmd_templates[i][HFI2_DMS_MSG_TYPE_STATUS_REQUEST];
		hfi2_dms_impl_proto_command_template_make(dms, cmd, i, HFI2_DMS_MSG_TYPE_STATUS_REQUEST, sizeof(union hfi2_dms_pkt_status_request)/sizeof(u64), HFI2_DMS_CTRL_JKEY);
	}

}

/* This is effectively `hfi2_set_ctxt_pkey` but allowing us to set these values on the loopback
 * ports even when not in SRIOV mode
 */
static int _dms_set_ctxt_pkey(struct hfi2_devdata *dd, struct send_context *sc, u8 pidx, u16 pkey)
{
	u64 reg;

	if (!sc)
		return -EINVAL;

	reg = ((u64) pkey & SEND_CTXT_CHECK_PARTITION_KEY_VALUE_MASK)
		<< SEND_CTXT_CHECK_PARTITION_KEY_VALUE_SHIFT;
	write_epsc_csr(dd, pidx, sc->hw_context, dd->params->send_ctxt_check_partition_key_reg, reg);
	dd->params->set_pio_integrity(dd, pidx, sc->hw_context, sc->type, SPI_SET_PKEY);
	return 0;
}

// put somewhere common later
static inline u32 rcvarray_offset(u32 ctxt, u32 index, u32 type)
{
	u32 ret;
/* RcvArray access shifts. These are the same between JKR and CYR */
#define JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT 25
#define JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT 17
#define JKR_RCV_ARRAY_CSR_INDEX_SHIFT 3
	ret = (type == PT_EAGER ? 0 : BIT(JKR_RCV_ARRAY_EGR_TID_SELECT_SHIFT))
	       | (ctxt_bar_ctxt(ctxt) << JKR_RCV_ARRAY_RCV_CTXT_IDX_SHIFT)
	       | (index << JKR_RCV_ARRAY_CSR_INDEX_SHIFT);
	return ret;
}

/*
 * Caller invariant: dma_addrs[0..npages-1] are all non-zero.  The only
 * reachable runtime failure mode is dma_addrs[i] == 0, which is a page-
 * provider consistency violation and is now caught by the caller before
 * any tracker side effect is committed.  Programming-error checks remain
 * as DMS_BUG_ONs.  See _tidset_enable() for the validation contract.
 */
static void hfi2_dms_impl_map_tid_entries(struct hfi2_dms *dms,
					  dma_addr_t const *dma_addrs,
					  u64 npages,
					  u32 tid_set)
{
	u64 start;
	u64 tid_entries[HFI2_DMS_TID_SET_SIZE * 2] = {0};
	u64 tid_start;
	u64 tid_entry_start;
	u64 npages_twos;
	size_t i;
	dma_addr_t next_phys_addr;
	u64 csr_offset;
	u64 end;

	dms_trace(dms_map_tid_entries, dms, dma_addrs, npages, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(dma_addrs == NULL);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(npages == 0);
	DMS_BUG_ON(npages > (HFI2_DMS_TID_SET_SIZE*2));
	start = dms_rdtsc();

	tid_start = tid_set * HFI2_DMS_TID_SET_SIZE;
	tid_entry_start = tid_start * 2;

	npages_twos = (npages + 1) & ~1ull;

	for (i = 0; i < npages; ++i) {
		next_phys_addr = dma_addrs[i];
		DMS_BUG_ON(next_phys_addr == 0);
		tid_entries[i] = (u64) (next_phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}
	if (npages & 1) {
		tid_entries[npages] = (u64) (dms->zero_page.phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}
	flush_wc();
	end = dms_rdtsc();
	dms->counters.map_tids += end - start;
}

static void tidset_load_clear(struct hfi2_dms *dms, u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	rc->load_npages = 0;
	rc->load_nchunks = 0;
	rc->load_ngather = 0;
	rc->scatter_count = 0;
	rc->scatter_valid = false;
	rc->cycle_real_bytes = 0;
}

/*
 * Load one page-provider run into the tidset as a new recv_chunk: @len bytes
 * starting @page_offset bytes into @dma_pages[0], requested from source offset
 * @sbuf_offset as the chunk's single gather element. Each page maps to one
 * RcvArray entry; the chunk's tid_info names the chunk's first TID and carries
 * @page_offset (as dwords) so the responder's DATA lands at that offset within
 * it. Returns the bytes loaded, which is short of @len when the tidset has no
 * RcvArray entries (or recv_chunks / gather elements) left. Once a bounce edge
 * is loaded, the last TID pair and one recv_chunk stay reserved for it.
 */
static u64 tidset_load(struct hfi2_dms *dms, u32 tid_set, u32 sbuf_offset,
		       dma_addr_t const *dma_pages, u64 page_offset, u64 len)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];
	struct hfi2_dms_recv_chunk *chunk;
	struct hfi2_dms_gather *gather;
	u16 base_tid;
	u64 pages;
	u64 loaded;
	u64 i;

	u32 const bounce = rc->scatter_count ? 1 : 0;
	u32 const entries = HFI2_DMS_TID_SET_PAGES_MAX - 2 * bounce;

	if (rc->load_nchunks + bounce >= HFI2_DMS_DR_MAX_CHUNKS ||
	    rc->load_ngather + rc->scatter_count >= HFI2_DMS_DR_MAX_GATHER ||
	    rc->load_npages >= entries)
		return 0;
	pages = min(DIV_ROUND_UP(page_offset + len, (u64)PAGE_SIZE),
		    (u64)(entries - rc->load_npages));
	if (!pages)
		return 0;
	loaded = min(len, pages * PAGE_SIZE - page_offset);

	base_tid = tid_set * HFI2_DMS_TID_SET_SIZE + (rc->load_npages / 2);
	chunk = &rc->chunk[rc->load_nchunks++];
	chunk->tid_info = hfi2_dms_tid_info_make(base_tid, page_offset >> 2);
	chunk->length_count = FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, loaded) |
			      FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, 1);
	gather = &rc->gather[rc->load_ngather++];
	gather->sbuf_offset = sbuf_offset;
	gather->length = loaded;

	for (i = 0; i < pages; ++i)
		rc->load_dma[rc->load_npages + i] = dma_pages[i];
	rc->load_npages += pages;

	return loaded;
}

/*
 * Pad a dangling upper slot to the inert zero page so the next recv_chunk
 * starts on a TID (even-slot) boundary. The responder never sends into it
 * (bounded by the chunk length) and expected-receive never matches it.
 */
static void tidset_load_pad(struct hfi2_dms *dms, u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	if ((rc->load_npages & 1) &&
	    rc->load_npages < HFI2_DMS_TID_SET_PAGES_MAX) {
		rc->load_dma[rc->load_npages] = dms->zero_page.phys_addr;
		rc->load_npages += 1;
	}
}

/*
 * Record a sub-quadword destination edge of @len bytes, requested from
 * @sbuf_offset, for the tidset's bounce recv_chunk; completion copies it to
 * @dest_offset. The first edge reserves the tidset's last TID pair and one
 * recv_chunk. Returns false, loading nothing, when the tidset has no room.
 */
static bool tidset_load_edge(struct hfi2_dms *dms, u32 tid_set, u32 sbuf_offset,
			     u64 dest_offset, u8 len)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];
	struct hfi2_dms_bounce_scatter *s;

	if (rc->scatter_count >= HFI2_DMS_DR_CHUNK_MAX_GATHER ||
	    rc->load_ngather + rc->scatter_count >= HFI2_DMS_DR_MAX_GATHER)
		return false;
	if (!rc->scatter_count &&
	    (rc->load_nchunks >= HFI2_DMS_DR_MAX_CHUNKS ||
	     ALIGN(rc->load_npages, 2) > HFI2_DMS_TID_SET_PAGES_MAX - 2))
		return false;

	s = &rc->scatter[rc->scatter_count];
	s->dest_offset = dest_offset;
	s->sbuf_offset = sbuf_offset;
	s->bounce_offset = rc->scatter_count * sizeof(u64);
	s->length = len;
	rc->scatter_count++;
	return true;
}

/*
 * Program the tidset's RcvArray with the loaded TID pairs and, when the request
 * has edges, map the bounce page at the last TID pair. Also appends the bounce
 * recv_chunk and its gather elements after the direct ones.
 *
 * As before the tidset load API, only the entries this request uses are
 * written; the responder never sends past a chunk's length, so the rest are
 * never targeted. Writing all 32 on every enable costs up to 30 extra
 * uncached RcvArray writes per DATA_REQUEST.
 */
static noinline_for_stack void tidset_load_complete(struct hfi2_dms *dms,
						    u32 tid_set)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];

	if (rc->load_npages)
		hfi2_dms_impl_map_tid_entries(dms, rc->load_dma,
					      rc->load_npages, tid_set);

	if (rc->scatter_count) {
		struct hfi2_dms_recv_chunk *chunk = &rc->chunk[rc->load_nchunks++];
		u32 real = 0;

		for (u8 i = 0; i < rc->scatter_count; i++) {
			rc->gather[rc->load_ngather++] = (struct hfi2_dms_gather){
				.sbuf_offset = rc->scatter[i].sbuf_offset,
				.length = rc->scatter[i].length,
			};
			real += rc->scatter[i].length;
		}
		chunk->tid_info = hfi2_dms_tid_info_make(tid_set * HFI2_DMS_TID_SET_SIZE +
							 HFI2_DMS_TID_SET_SIZE - 1, 0);
		chunk->length_count =
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, real) |
			FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, rc->scatter_count);
		_tidset_bounce_attach(dms, tid_set);
	}
}

static void _tidset_reset(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_tidset_state new_state)
{
	u64 const npages = HFI2_DMS_TID_SET_SIZE*2;
	u64 const npages_twos = (npages + 1) & ~1ull;
	u64 const tid_start = tid_set * HFI2_DMS_TID_SET_SIZE;
	u64 const tid_entry_start = tid_start * 2;

	u64 csr_offset;
	u64 tid_entries[HFI2_DMS_TID_SET_SIZE * 2] = {0};

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);

	dms->read_requests[tid_set].disable_ts = dms->now;
	dms->read_requests[tid_set].state = new_state;
	/* A reset request never completes, so its edges are never copied out. */
	if (dms->read_requests[tid_set].has_bounce) {
		dms->read_request_chunks[tid_set].scatter_valid = false;
		dms->read_request_chunks[tid_set].scatter_count = 0;
		dms->read_requests[tid_set].has_bounce = false;
	}
	dms->read_requests[tid_set].total_requested_qws = (u64)(-1);
	dms->read_requests[tid_set].remaining_qws = (u64)(-1);
	dms->read_requests[tid_set].rx_tracker = &dms->disabled_rx_tracker;

	for (u64 i = 0; i < npages; ++i) {
		tid_entries[i] = (u64) (dms->zero_page.phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	}

	csr_offset = rcvarray_offset(dms->rcd_data->ctxt, tid_entry_start, PT_EXPECTED);
	for (u64 i = 0; i < npages_twos; ++i) {
		writeq(tid_entries[i], dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc + csr_offset + (i * sizeof(u64)));
	}

	/*
	 * No flush_wc() here: _tidset_reset only programs the RcvArray entries.
	 * On the FREE path the next _tidset_enable() reprograms these same
	 * entries and flushes in hfi2_dms_impl_map_tid_entries(). On the DISABLED
	 * (quarantine) path the caller flushes once after resetting all of the
	 * tracker's tidsets, so the zero-page redirect is made visible without a
	 * redundant per-tidset sfence on the completion hot path.
	 */
}

int _tidset_enable(struct hfi2_dms *dms, u32 tid_set, struct hfi2_dms_rx_tracker *rx_tracker, u32 *tid_info, u64 *tidset_nbytes)
{
	struct hfi2_dms_read_request_chunks *rc;
	struct hfi2_dms_read_request_state *read_req_state;
	struct hfi2_dms_run runs[HFI2_DMS_TIDSET_RUNS_MAX];
	u64 payload_start;
	u64 cursor;
	u64 remaining;
	u64 packed_bytes = 0;
	u64 placed_bytes = 0;
	bool spec_charged;
	u32 read_size_qw;
	int nruns;
	u16 gen;
	int i;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(tid_set >= HFI2_DMS_TID_SET_IDX_COUNT);
	DMS_BUG_ON(dms->read_requests[tid_set].tid_set != tid_set);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(!tid_info);
	DMS_BUG_ON(!tidset_nbytes);

	DMS_WARN_ON(rx_tracker->total_payload == rx_tracker->sbuf_cursor);

	/* Any alignment: the run split below lands sub-quadword edges. */
	payload_start = rx_tracker->rbuf_start_offset + rx_tracker->sbuf_cursor;

	/*
	 * Load the tidset from the destination's page-provider runs: fetch them
	 * with one get_runs() call, which also makes the pages resident, and
	 * load each run as its own recv_chunk until the tidset is full. This is
	 * the same for READ and WRITE and for one or many providers; a single
	 * MR is simply one run. The source is read linearly, so each chunk's
	 * sbuf_offset advances by the bytes already loaded.
	 *
	 * TID expected-receive lands only whole, quadword-aligned quadwords, so
	 * a run splits into a sub-quadword head up to its first quadword
	 * boundary, a quadword-aligned middle loaded directly, and a
	 * sub-quadword tail. The head and tail edges go to the bounce recv_chunk
	 * and are copied to the destination at completion. Fragments are taken
	 * strictly in order; the first one that does not fit ends the request,
	 * and the next request starts there.
	 */
	cursor = payload_start;
	remaining = rx_tracker->total_payload - rx_tracker->sbuf_cursor;

	if (WARN_ON(!rx_tracker->page_provider.get_runs))
		return -EFAULT;

	tidset_load_clear(dms, tid_set);

	/*
	 * Writable: hardware writes inbound data here. All failures are
	 * normalized to -EAGAIN so the tidset waiter loop in
	 * hfi2_dms_impl_make_data_request treats them as transient; any other
	 * than memory pressure is counted and logged, since it will not clear
	 * on its own.
	 */
	nruns = rx_tracker->page_provider.get_runs(&rx_tracker->page_provider,
						   payload_start, remaining,
						   true, runs,
						   HFI2_DMS_TIDSET_RUNS_MAX);
	if (nruns <= 0 || WARN_ON_ONCE(nruns > HFI2_DMS_TIDSET_RUNS_MAX)) {
		if (nruns != -EAGAIN && nruns != -ENOMEM) {
			dms->counters.health_tidset_run_fail++;
			dd_dev_warn_ratelimited(dms->dd,
						"DMS_DIAG: tidset get_runs failed ret=%d key=%05u off=%llu rem=%llu\n",
						nruns,
						rx_tracker->hdr.local_rift_key.value,
						payload_start, remaining);
		}
		return -EAGAIN;
	}

	for (i = 0; i < nruns && remaining; i++) {
		struct hfi2_dms_run const src = runs[i];
		u64 head, mid, tail, loaded;

		if (WARN_ON_ONCE(!src.run_bytes))
			return -EINVAL;

		head = min_t(u64, src.run_bytes, -src.page_offset & 7);
		mid = round_down(src.run_bytes - head, 8);
		tail = src.run_bytes - head - mid;

		if (head) {
			if (!tidset_load_edge(dms, tid_set,
					      rx_tracker->sbuf_cursor + packed_bytes,
					      cursor, head))
				break;
			packed_bytes += head;
			placed_bytes += sizeof(u64);
			cursor += head;
			remaining -= head;
		}

		if (mid) {
			u64 const off = src.page_offset + head;

			loaded = tidset_load(dms, tid_set,
					     rx_tracker->sbuf_cursor + packed_bytes,
					     src.dma_pages + off / PAGE_SIZE,
					     off & (PAGE_SIZE - 1), mid);
			packed_bytes += loaded;
			placed_bytes += loaded;
			cursor += loaded;
			remaining -= loaded;
			if (loaded < mid)
				break;
			tidset_load_pad(dms, tid_set);
		}

		if (tail) {
			if (!tidset_load_edge(dms, tid_set,
					      rx_tracker->sbuf_cursor + packed_bytes,
					      cursor, tail))
				break;
			packed_bytes += tail;
			placed_bytes += sizeof(u64);
			cursor += tail;
			remaining -= tail;
		}
	}

	/* An empty tidset always takes the first fragment. */
	if (WARN_ON_ONCE(!packed_bytes))
		return -EINVAL;

	tidset_load_complete(dms, tid_set);
	rc = &dms->read_request_chunks[tid_set];
	rc->cycle_real_bytes = packed_bytes;

	*tid_info = rc->chunk[0].tid_info;
	/* Quadwords placed, bounce edges' pad included. */
	read_size_qw = placed_bytes >> 3;

	read_req_state = &dms->read_requests[tid_set];
	gen = read_req_state->generation + 1;
	spec_charged = read_req_state->spec_charged;
	/*
	 * Every field not named here (drain state, perf) starts at 0.
	 * spec_charged carries over: a speculative tidset re-armed for the
	 * transfer's next request still owes its budget unit, returned at FREE.
	 */
	*read_req_state = (struct hfi2_dms_read_request_state){
		.total_requested_qws = read_size_qw,
		.remaining_qws = read_size_qw,
		.rx_tracker = rx_tracker,
		.tid_set = tid_set,
		.state = HFI2_DMS_TIDSET_STATE_ENABLED,
		.stale_time = ktime_add_ns(dms->now, HFI2_DMS_TIDSET_STALE_TIMEOUT_NS),
		.generation = gen,
		.has_bounce = rc->scatter_count != 0,
		.saved_size_qw = read_size_qw,
		.saved_port_idx = rx_tracker->hdr.port_idx,
		.saved_remote_lid = rx_tracker->hdr.remote_lid,
		.saved_remote_rift_key = rx_tracker->hdr.remote_rift_key,
		.saved_entropy = rx_tracker->hdr.entropy,
		/*
		 * Bounce edges complete only once this side copies them out, so
		 * the source must not release a chained child on egress.
		 */
		.flags = rc->scatter_count ? HFI2_DMS_DR_FLAG_UNALIGNED : 0,
		.spec_charged = spec_charged,
	};

	if (rc->scatter_count) {
		rc->scatter_generation = gen;
		rc->scatter_valid = true;
	}

	*tidset_nbytes = packed_bytes;
	return 0;
}

/*
 * One chunk with one gather element covering it, whose length is the
 * request's placed bytes, is fully described by the BTH size_qw plus the
 * range's sbuf_offset/tid_info: such a request is sent in compact form.
 */
static bool _request_is_compact(struct hfi2_dms_read_request_chunks const *rc,
				u32 read_size_qw)
{
	return rc->load_nchunks == 1 && rc->load_ngather == 1 &&
	       hfi2_dms_recv_chunk_count(&rc->chunk[0]) == 1 &&
	       hfi2_dms_recv_chunk_length(&rc->chunk[0]) == rc->gather[0].length &&
	       rc->gather[0].length == (read_size_qw << 3);
}

/*
 * Build a ready-to-send DATA_REQUEST frame carrying @rc's recv_chunks and
 * gather elements into @cmd and return its length in quadwords (including the
 * PBC). @cmd must be large enough for the frame (dms->pio_scratch).
 */
static u32 hfi2_dms_cmd_data_request_stage(struct hfi2_dms *dms,
					   union _pkt_cmd *cmd, u8 port_idx,
					   struct hfi2_dms_read_request_chunks const *rc,
					   hfi2_dms_rift_key_t tx_rift_key,
					   hfi2_dms_rift_key_t rx_rift_key,
					   u32 src_lid, u32 read_size_qw,
					   u16 generation, u16 entropy,
					   u64 order_key, u8 flags,
					   enum hfi2_dms_msg_type msg_type)
{
	u8 *dst = (u8 *)cmd +
		_msgtype_pio_payload_offset[HFI2_DMS_MSG_TYPE_DATA_REQUEST];
	u32 const chunks_bytes =
		rc->load_nchunks * sizeof(struct hfi2_dms_recv_chunk);
	u32 const arrays_bytes =
		_data_request_arrays_bytes(rc->load_nchunks, rc->load_ngather);
	bool const compact = _request_is_compact(rc, read_size_qw);
	u32 wire_bytes;
	u32 pkt_len_qws;

	cmd->pio = dms->protocol_cmd_templates[port_idx][msg_type];

	cmd->data_request.tx_rift_key = tx_rift_key;
	cmd->data_request.rx_rift_key = rx_rift_key;
	memset(cmd->data_request.reserved2, 0,
	       sizeof(cmd->data_request.reserved2));
	cmd->data_request.flags = flags;
	cmd->data_request.generation = generation;

	if (compact) {
		cmd->data_request.sbuf_offset = rc->gather[0].sbuf_offset;
		cmd->data_request.tid_info = rc->chunk[0].tid_info;
		cmd->data_request.recv_chunk_count = 0;
		wire_bytes = 0;
		goto staged;
	}

	cmd->data_request.gather_count = rc->load_ngather;
	memset(cmd->data_request.reserved0, 0,
	       sizeof(cmd->data_request.reserved0));
	cmd->data_request.tid_info = 0;
	cmd->data_request.recv_chunk_count = rc->load_nchunks;
	/*
	 * recv_chunks followed by gather elements. Arrays that fit the 120-byte
	 * control HDRQ inline budget go in the inline area. Larger ones go
	 * whole into the eager portion of the packet, which starts right after
	 * the inline area: zero the inline area and place both arrays after it,
	 * so the receiver finds them at the start of its eager buffer.
	 */
	if (arrays_bytes > HFI2_DMS_DR_INLINE_BYTES) {
		memset(dst, 0, HFI2_DMS_DR_INLINE_BYTES);
		dst += HFI2_DMS_DR_INLINE_BYTES;
		wire_bytes = HFI2_DMS_DR_INLINE_BYTES + arrays_bytes;
	} else {
		wire_bytes = arrays_bytes;
	}
	memcpy(dst, rc->chunk, chunks_bytes);
	memcpy(dst + chunks_bytes, rc->gather,
	       rc->load_ngather * sizeof(struct hfi2_dms_gather));

staged:
	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, src_lid);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, src_lid);
	_dms_lane_sel_set(cmd->bth, src_lid);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, _dms_route_control_for_order_key(order_key));
	_dms_return_rx_set(&cmd->bth[0], dms->rcd_data->ctxt);
	cmd->bth[2] = (read_size_qw << 16) | (cmd->bth[2] & 0xffff);

	cmd->data_request.entropy = entropy;

	pkt_len_qws = _pkt_len_qws(HFI2_DMS_MSG_TYPE_DATA_REQUEST, wire_bytes);
	pkt_len_qws = _pkt_cmd_test_len_pad(cmd, pkt_len_qws);
	_pkt_cmd_set_lengths(cmd, pkt_len_qws);

	return pkt_len_qws;
}

/*
 *_inject_data_request - Inject a DATA_REQUEST (or DATA_REQUEST_REPLAY, via
 * msg_type) packet from a fully-initialized read_request_state. All
 * parameters needed to build the packet are read from
 * dms->read_requests[tid_set].saved_* fields. This is the single injection
 * point used by both the normal path and the DRAINING re-inject path.
 */
static int _inject_data_request(struct hfi2_dms *dms, u32 tid_set, enum hfi2_dms_msg_type msg_type)
{
	struct hfi2_dms_read_request_state *read_req_state = &dms->read_requests[tid_set];
	struct hfi2_dms_read_request_chunks const *rc = &dms->read_request_chunks[tid_set];
	union _pkt_cmd *cmd = (union _pkt_cmd *)dms->pio_scratch;

	/* The request's counts size the frame staged in pio_scratch. */
	if (WARN_ON_ONCE(rc->load_nchunks == 0 ||
			 rc->load_nchunks > HFI2_DMS_DR_MAX_CHUNKS ||
			 rc->load_ngather < rc->load_nchunks ||
			 rc->load_ngather > HFI2_DMS_DR_MAX_GATHER))
		return -EINVAL;

	hfi2_dms_cmd_data_request_stage(dms, cmd,
					read_req_state->saved_port_idx,
					rc,
					read_req_state->saved_remote_rift_key,
					read_req_state->rx_tracker->hdr.local_rift_key,
					read_req_state->saved_remote_lid,
					read_req_state->saved_size_qw,
					read_req_state->generation,
					read_req_state->saved_entropy,
					read_req_state->rx_tracker->hdr.order_key,
					read_req_state->flags, msg_type);

	return _inject_cmd_pio(dms, &cmd->pio, HFI2_DMS_TRANSFER_HANDLE_NONE, false);
}

static int _inject_data_request_replay(struct hfi2_dms *dms, u32 tid_set)
{
	return _inject_data_request(dms, tid_set, HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY);
}

int hfi2_dms_impl_make_data_request(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, u32 tid_set)
{
	u64 start;
	u64 nbytes_to_request;
	u32 tid_info;
	int ret;
	u64 end;

	dms_trace(dms_make_data_request, dms, rx_tracker, tid_set);

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(rx_tracker == NULL);

	start = dms_rdtsc();

#if HFI2_DMS_COUNTERS_ENABLE
	ktime_t begin = ktime_get();
#endif
	/* Entropy drives the SDMA-engine hash + LRH. A chained child pins to its
	 * inherited engine (rides behind parent via FIFO); everything else rotates.
	 */
	if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		if (rx_tracker->chain_inherit_valid)
			rx_tracker->hdr.entropy = rx_tracker->chain_inherit_entropy;
		else
			rx_tracker->hdr.entropy = _dms_entropy_next(dms);
	}

	ret = _tidset_enable(dms, tid_set, rx_tracker, &tid_info, &nbytes_to_request);
	if (ret < 0) {
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
		return ret;
	}
#if HFI2_DMS_COUNTERS_ENABLE
	dms->read_requests[tid_set].perf.begin = begin;
	dms->read_requests[tid_set].perf.tidset_enabled = ktime_get();
#endif

	ret = _inject_data_request(dms, tid_set, HFI2_DMS_MSG_TYPE_DATA_REQUEST);
	if (ret < 0) {
		dd_dev_dbg(dms->dd, "Unable to send data request.\n");
		_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_FREE);
		return ret;
	}

	rx_tracker->sbuf_cursor += nbytes_to_request;

	_tracker_stale_set_remote(dms, (union hfi2_dms_tracker *)rx_tracker, 2 * HFI2_DMS_STALE_BACKOFF_BASE_MS);

	end = dms_rdtsc();
	dms->counters.make_data_request += end - start;

	return 0;
}

/* Issue-path narrow-to-one arm. Call AFTER tidsets_in_use is updated so the
 * count is current. Signals a parked child only.
 */
static void _chain_signal_final_data_request(struct hfi2_dms *dms,
					     struct hfi2_dms_rx_tracker *parent_rx)
{
	union hfi2_dms_tracker *parent = (union hfi2_dms_tracker *)parent_rx;
	struct hfi2_dms_transfer_handle const parent_h = _tracker_to_handle(parent);
	struct hfi2_dms_transfer_handle const child_h = parent->hdr.child_handle;
	union hfi2_dms_tracker *child;
	int ret;

	if (child_h.value == 0)
		return;

	child = _handle_to_tracker(child_h);
	if (!child) {
		dms->counters.chain_null_handle++;
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	if (child->hdr.parent_handle.value != parent_h.value) {
		parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
		return;
	}

	/* Narrow-to-one fast path is DATA_START-only. */
	if (child->hdr.chain_park_at !=
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START)
		return;

	/*
	 * Not while a bounce-edge tidset is in flight: its edges are copied
	 * out after the child's same-engine data could land. A later tidset
	 * completion retries; parent completion releases the child otherwise.
	 */
	if (_rx_tracker_inflight_has_bounce(dms, parent_rx))
		return;

	/* Claim the release exactly once. */
	parent->hdr.chain_signalled = true;

	/* Inherit the parent's narrowed entropy. */
	if (parent_rx->tidsets_in_use > 0) {
		u64 const bitmap = parent_rx->tidsets_inflight_bitmap;
		u16 *const entropy = &child->rx.chain_inherit_entropy;

		child->rx.chain_inherit_valid =
			_dms_read_requests_inflight_entropy_narrowed(dms, bitmap, entropy);
	}

	if (child->hdr.health_state !=
			HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START) {
		child->hdr.chain_child_released = true;
		return;
	}

	child->hdr.chain_child_released = true;

	/* Sever the link; the child copies out its own bounce edges at tidset completion. */
	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;

	/* Burst only: child inherits this engine, rides behind the parent via FIFO. */
	ret = _chain_resume_read_at_data_start(dms, &child->rx);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
		return;
	}
	dms->counters.chain_released_read_at_data_start++;
}

static void _chain_signal_last_engine(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker)
{
	if (!(rx_tracker->sbuf_cursor >= rx_tracker->total_payload &&
	      rx_tracker->tidsets_in_use <= 1))
		return;

	if (!rx_tracker->hdr.chain_signalled &&
	    rx_tracker->hdr.child_handle.value != 0)
		_chain_signal_final_data_request(dms, rx_tracker);
}

int calculate_access_mr_page_offset(struct hfi2_dms *dms,
					 struct hfi2_dms_access *access,
					 u64 offset, u32 size, u64 *page_offset)
{
	struct hfi2_dms_mr *rbuf;
	u64 relative_offset;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!access);
	DMS_BUG_ON(!page_offset);

	rbuf = access->page_provider.provider_ctx;
	DMS_BUG_ON(!rbuf);

	/*
	 * The protocol-supplied `offset` is interpreted by MR mode: in
	 * VADDR mode it is an absolute user virtual address; in OFFSET
	 * mode it is a byte offset relative to the start of the access
	 * subrange. Normalize to `relative_offset` (bytes into the access)
	 * so the subrange bounds check is expressed in a single coordinate
	 * system regardless of mode.
	 */
	if (rbuf->mode == HFI2_DMS_MR_MODE_VADDR) {
		u64 const access_vaddr_start = rbuf->user.addr + access->offset;

		if (offset < access_vaddr_start) {
			dd_dev_info(dms->dd,
				    "%s: VADDR offset %llx below access start %llx\n",
				    __func__, offset, access_vaddr_start);
			return -EINVAL;
		}
		relative_offset = offset - access_vaddr_start;
	} else {
		relative_offset = offset;
	}

	if (relative_offset > access->size ||
	    size > (access->size - relative_offset)) {
		dd_dev_info(dms->dd,
			    "%s: Invalid access range offset %llx rel %llx size %x (access size %llx mode %d)\n",
			    __func__, offset, relative_offset, size,
			    access->size, rbuf->mode);
		return -EINVAL;
	}

	/*
	 * Delegate the MR-local page-offset translation and final
	 * bounds-check against the extended (page-aligned) MR length to
	 * calculate_mr_page_offset(). It interprets its `offset`
	 * argument per mr->mode, so pass the input offset unchanged in
	 * VADDR mode and (access->offset + relative_offset) in OFFSET
	 * mode.
	 */
	if (rbuf->mode == HFI2_DMS_MR_MODE_VADDR)
		return calculate_mr_page_offset(dms, rbuf, offset, size,
						page_offset);

	return calculate_mr_page_offset(dms, rbuf,
					access->offset + relative_offset,
					size, page_offset);
}

int calculate_mr_page_offset(struct hfi2_dms *dms, struct hfi2_dms_mr * mr, u64 offset, u32 size, u64 *page_offset)
{
	u64 end;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!mr);
	DMS_BUG_ON(!page_offset);

	if (mr->mode == HFI2_DMS_MR_MODE_VADDR) {
		// offset is interpreted as a user virtual address
		if (offset < mr->user.addr) {
			dd_dev_info(dms->dd, "Invalid virtual address offset.\n");
			return -EINVAL;
		}
		offset -= mr->user.addr;
	}
	if (check_add_overflow(mr->region_offset, offset, page_offset) ||
	    check_add_overflow(*page_offset, (u64)size, &end) ||
	    end > mr->extended_vaddr.len) {
		dd_dev_info(dms->dd,
			    "%s: Invalid length from offset %llx + %x > %lx\n",
			    __func__, *page_offset, size,
			    mr->extended_vaddr.len);
		return -EINVAL;
	}

	return 0;
}

static bool
_read_start_spec_requests_valid(struct hfi2_dms_read_start_parameters const *p)
{
	if (p->tid_count > HFI2_DMS_READ_START_SPECULATIVE_TID_MAX)
		return false;
	for (u8 i = 0; i < p->tid_count; i++) {
		struct hfi2_dms_spec_request const *r = &p->spec[i];

		if (!r->recv_chunk_count ||
		    r->recv_chunk_count > HFI2_DMS_DR_MAX_CHUNKS ||
		    r->gather_count < r->recv_chunk_count ||
		    r->gather_count > HFI2_DMS_DR_MAX_GATHER)
			return false;
	}
	return true;
}

int hfi2_dms_impl_handle_read_start(struct hfi2_dms *dms,
		struct hfi2_dms_read_start_metadata const *metadata,
		struct hfi2_dms_read_start_parameters const *parameters,
		void const *arrays)
{
	u64 start;
	struct hfi2_dms_client_state * client = NULL;
	struct hfi2_dms_access *access;
	struct hfi2_dms_page_provider *page_provider;
	struct hfi2_dms_tx_tracker *tx_tracker;
	int ret = 0;
	u64 end;
	u64 page_offset = 0;
	enum hfi2_dms_err_type reason = HFI2_DMS_ERR_TYPE_NONE;

	DMS_BUG_ON(dms == NULL);

	if (parameters->tbytes == 0) {
		reason = HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION;
		goto nack;
	}

	/*
	 * A speculative READ_START's request counts are peer-supplied and size
	 * the arrays walked when serving it; bound them as a DATA_REQUEST's are.
	 */
	if (metadata->speculative &&
	    !_read_start_spec_requests_valid(parameters)) {
		reason = HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION;
		goto nack;
	}

	start = dms_rdtsc();

	access = hfi2_dms_access_lookup(dms, parameters->dms_key, &client);
	if (!client) {
		reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		/*
		 * Diagnostic-only: report whether a matching registration
		 * command is still pending in the client's cmdq. Does not
		 * change dispatch below.
		 */
		if (client->diag_access_fn) {
			if (client->diag_access_fn(client->diag_access_ctx,
						   parameters->dms_key.access))
				dms->counters.access_deferred_pending_cmd_found++;
			else
				dms->counters.access_deferred_pending_cmd_not_found++;
		}
		return -EAGAIN;
	}

	page_provider = &access->page_provider;
	/* Bilateral promote: a remote rank is initiating an RDMA-READ
	 * whose source is one of THIS rank's MRs (identified by the
	 * access lookup above).  Complementary to the explicit
	 * user_mr_promote() at the initiator-side cmd-handler in
	 * bulksvc_user.c.  Idempotent.
	 */
	if (access->page_provider.promote)
		page_provider->promote(page_provider->provider_ctx);

	ret = calculate_access_mr_page_offset(dms, access, parameters->offset, parameters->tbytes, &page_offset);
	if (ret < 0) {
		reason = HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	union hfi2_dms_tracker *tracker = hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
			metadata->rx_rift_key, metadata->slid, parameters->order_key, HFI2_DMS_XFER_TYPE_TARGET, HFI2_DMS_XFER_OP_READ);
	if (!tracker) {
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}

	ret = access_xfer_begin(dms, access, metadata->slid, metadata->rx_rift_key, tracker);
	if (ret == HFI2_DMS_ACCESS_ALREADY_STARTED) {
		union hfi2_dms_tracker *live =
			_access_inflight_find(access, metadata->slid,
					      metadata->rx_rift_key);
		enum hfi2_dms_start_gen_rel rel =
			live ? _start_gen_compare(parameters->order_key,
						  live->hdr.order_key)
			     : HFI2_DMS_START_GEN_DUP;

		if (rel == HFI2_DMS_START_GEN_NEWER) {
			/*
			 * Newer generation: tear down the stale tracker and
			 * re-admit fresh.  In-line cancel is safe only for a
			 * PERSISTENT access -- the nested _dms_rift_poll drain
			 * cannot free it (never ACTIVE_TEARDOWN) and touches only
			 * waitlist-parked trackers, not our fresh one; access is
			 * re-looked-up by key below.  An ephemeral access would
			 * free on drain and need deferral.
			 */
			WARN_ON_ONCE(access->type != HFI2_DMS_ACCESS_TYPE_PERSISTENT);
			hfi2_dms_tx_tracker_cancel(dms, &live->tx, -ECANCELED);
			live = NULL; /* freed+recycled by cancel; guard future deref */
			access = hfi2_dms_access_lookup(dms, parameters->dms_key,
							&client);
			if (!client || !access) {
				hfi2_dms_impl_tracker_recycle(dms, tracker);
				reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
				goto nack;
			}
			ret = access_xfer_begin(dms, access, metadata->slid,
						metadata->rx_rift_key, tracker);
			if (ret < 0) {
				hfi2_dms_impl_tracker_recycle(dms, tracker);
				reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
				goto nack;
			}
		} else {
			/*
			 * Exact-generation duplicate (re-injected/wire dup) or a
			 * stale orphan of a prior generation. Discard the new
			 * tracker. A duplicate is the initiator re-driving; answer
			 * with DATA_START once the live tracker holds a real rift
			 * key. A KEY_NOT_SET tracker recovers via _dms_rift_poll();
			 * a stale orphan is dropped.
			 *
			 * A speculative initiator that falls back re-sends an
			 * ordinary READ_START; the DATA_START answers it too.
			 */
			hfi2_dms_impl_tracker_recycle(dms, tracker);
			/*
			 * A responder whose payload has all gone out waits in
			 * WAITING_FOR_REMOTE_ACK: re-sending DATA_START would
			 * move it back and refuse the ACK if it is only late,
			 * as on a NOT_FOUND STATUS response.
			 */
			if (rel == HFI2_DMS_START_GEN_DUP && live &&
			    !_rift_key_error(live->tx.hdr.local_rift_key) &&
			    live->tx.payload_remaining) {
				dms->counters.reinject_data_start++;
				ret = hfi2_dms_impl_inject_data_start(dms, &live->tx);
				if (ret < 0)
					hfi2_dms_tx_tracker_cancel(dms, &live->tx, ret);
			}
			return 0;
		}
	} else if (ret < 0) {
		hfi2_dms_impl_tracker_recycle(dms, tracker);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
	}

	tx_tracker = &tracker->tx;

	tx_tracker->op = HFI2_DMS_TX_TRACKER_OP_RDMA_READ;
	tx_tracker->read.access = access;
	tx_tracker->read.metadata = *metadata;
	tx_tracker->read.parameters = *parameters;

	/* Adopt the caller's policy (fast_fail + stale shift) from the START flags. */
	tx_tracker->hdr.fast_fail = hfi2_dms_start_flags_fast_fail(parameters->flags);
	tx_tracker->hdr.stale_backoff_shift =
		hfi2_dms_start_flags_stale_shift(parameters->flags);

	tx_tracker->total_payload = parameters->tbytes;
	tx_tracker->payload_remaining = parameters->tbytes;
	tx_tracker->xfer_start_byte_offset = page_offset;

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)tx_tracker);
	if (ret < 0) {
		access_xfer_end(dms, access, (union hfi2_dms_tracker *)tx_tracker,
				parameters->flags, parameters->imm_data,
				parameters->order_key, ret);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	if (ret > 0) {
		u8 const generation = tx_tracker->hdr.generation;

		tx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
		ret = _dms_tx_rift_continue_read_start(dms, tx_tracker, arrays);
		if (ret < 0) {
			/*
			 * A failing drive may already have cancelled the
			 * tracker (_sdma_inject -EMSGSIZE); cancel released the
			 * key, ended the access and recycled the tracker, so
			 * only the NACK remains to be sent.
			 */
			if (tx_tracker->hdr.generation == generation) {
				union hfi2_dms_tracker *t = (union hfi2_dms_tracker *)tx_tracker;

				_rift_release(&dms->rift, tx_tracker->hdr.local_rift_key);
				access_xfer_end(dms, access, t, parameters->flags,
						parameters->imm_data, parameters->order_key,
						-ENOMEM);
				hfi2_dms_impl_tracker_recycle(dms, t);
			}
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
	}

	end = dms_rdtsc();
	dms->counters.handle_data_request += end - start;

	return 0;

nack:
	dd_dev_warn_ratelimited(dms->dd, "DMS_DIAG: READ_START NACK reason=%s dms_key=%llu slid=%u tbytes=%u offset=%llu\n",
		    _nack_reason_str(reason), parameters->dms_key.value,
		    metadata->slid, parameters->tbytes, parameters->offset);
	_nack_log(dms, reason, parameters->dms_key);
	/*
	 * Echo the message type the initiator sent so its NACK handler, which
	 * matches on the NACK's message-type field, locates the pending tracker
	 * regardless of which READ variant it issued.
	 */
	_inject_nack(dms,
		     metadata->speculative ? HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE
					   : HFI2_DMS_MSG_TYPE_READ_START,
		     reason, metadata->port_idx, metadata->slid, metadata->rx_rift_key);
	return 0;
}

static void hfi2_dms_impl_handle_read_start_packet(struct hfi2_dms *dms, u8 rcv_port,
						   union hfi2_dms_16b_header *hdr,
						   void *ebuf, bool speculative)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;

	struct hfi2_dms_read_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.rx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.size_qw = (u16) ((hdr->bth[2]) & 0xFFFF),
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.port_idx = rcv_port,
		.speculative = speculative,
		.entropy = hfi2_dms_lrh16B_entropy_get((u32 *)&hdr->lrh[0]),
	};

	/*
	 * A speculative READ_START's requests' arrays follow its body: inline when
	 * they fit the control HDRQ header, otherwise whole at the start of the
	 * eager buffer, exactly as a DATA_REQUEST's.
	 */
	void const *arrays = !speculative || !entry->read_start.tid_count ?
		NULL : ebuf ? ebuf : (void const *)(&entry->read_start + 1);

	/*
	 * The request counts are the peer's: the frame must carry the arrays
	 * they describe, where they describe them (counts themselves are
	 * bounded in hfi2_dms_impl_handle_read_start()).
	 */
	if (arrays) {
		struct hfi2_dms_spec_request const *r = entry->read_start.spec;
		u32 arrays_bytes = 0;
		bool in_eager;

		for (u8 i = 0; i < entry->read_start.tid_count &&
		     i < HFI2_DMS_READ_START_SPECULATIVE_TID_MAX; i++)
			arrays_bytes += _data_request_arrays_bytes(r[i].recv_chunk_count,
								   r[i].gather_count);
		in_eager = arrays_bytes > HFI2_DMS_RS_INLINE_BYTES;
		if (unlikely(in_eager != !!ebuf ||
			     !_request_arrays_fit(hfi2_dms_lrh16B_pkt_len_get(hdr->lrh),
						  offsetof(struct _hdrq_entry, read_start) +
						  sizeof_field(struct _hdrq_entry, read_start),
						  HFI2_DMS_RS_INLINE_BYTES,
						  arrays_bytes))) {
			dms->counters.health_invalid_data_request++;
			return;
		}
	}

	/*
	 * A deferred READ_START keeps only its body: a speculative one whose
	 * request needed arrays is then answered with DATA_START.
	 */
	int ret = hfi2_dms_impl_handle_read_start(dms, &metadata, &entry->read_start,
						  arrays);
	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_READ, &metadata, &entry->read_start);
}

static void _dms_write_signal_early_release(struct hfi2_dms *dms,
						struct hfi2_dms_tx_tracker *tx_tracker,
						u16 early_release_entropy)
{
	/* parent is this tx_tracker, re-fetched as a union tracker for the
	 * handle/health-state operations below.
	 */
	union hfi2_dms_tracker *const parent =
		_rift_lookup(&dms->rift, tx_tracker->hdr.local_rift_key);
	union hfi2_dms_tracker *child;
	int ret;

	/* A SEND is fully fenced: it releases its child only at completion. */
	if (_tx_tracker_is_send(tx_tracker))
		return;

	if (!parent || parent->hdr.chain_signalled ||
	    parent->hdr.child_handle.value == 0)
		return;

	child = _handle_to_tracker(parent->hdr.child_handle);
	if (!child ||
	    child->hdr.op != HFI2_DMS_XFER_OP_WRITE ||
	    child->hdr.parent_handle.value != _tracker_to_handle(parent).value ||
	    child->hdr.health_state !=
		    HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_EARLY)
		return;

	/* A SEND child is fully fenced: it resumes only at parent completion. */
	if (_tx_tracker_is_send(&child->tx))
		return;

	parent->hdr.chain_signalled = true;
	child->hdr.chain_child_released = true;
	child->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	parent->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	child->tx.write.chain_inherit_entropy = early_release_entropy;
	child->tx.write.chain_inherit_valid = true;
	_tracker_health_state_set(dms, child,
				  HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST);

	ret = hfi2_dms_impl_inject_write_start(dms, &child->tx,
					       HFI2_DMS_MSG_TYPE_WRITE_START,
					       false);
	if (ret < 0) {
		dms->counters.chain_release_inject_fail++;
		_tracker_cancel(dms, child, ret);
	} else {
		dms->counters.chain_released_write_start_early++;
	}
}

static int
hfi2_dms_impl_handle_data_request(struct hfi2_dms *dms,
				  struct hfi2_dms_data_request_metadata const *metadata,
				  struct hfi2_dms_data_request_parameters const *parameters,
				  struct hfi2_dms_recv_chunk const *chunks,
				  u8 nchunks,
				  struct hfi2_dms_gather const *gather,
				  u8 ngather)
{
	struct hfi2_dms_tx_tracker *tx_tracker;

	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON(parameters == NULL);

	hfi2_dms_rift_key_t const tx_rift_key = parameters->tx_rift_key;

	/*
	 * KEY_NOT_SET: a re-request of a speculative READ's tidset enabled
	 * before this responder was known; found by identity below.
	 */
	if (unlikely(_rift_key_error(tx_rift_key) &&
		     _rift_key_error(tx_rift_key) != HFI2_DMS_RIFT_ERR_KEY_NOT_SET)) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop DATA_REQUEST with error rift key 0x%04hx\n",
			   tx_rift_key.value);
		return 0;
	}

	tx_tracker = _rift_key_error(tx_rift_key) ? NULL :
		(struct hfi2_dms_tx_tracker *)_rift_lookup(&dms->rift, tx_rift_key);
	if (unlikely(!tx_tracker)) {
		/*
		 * Fast-path miss: the learned tx_rift_key generation has gone
		 * stale (the shared rift pool recycled the slot under QP churn,
		 * or a retried/duplicate DATA_REQUEST raced tracker progress).
		 * Recover by the stable transfer identity the initiator stamped
		 * in rx_rift_key -- the same (remote_rift_key, slid) identity the
		 * STATUS_REQUEST handler keys on, which is generation-independent.
		 *
		 * Accept a live READ tracker in either WAITING_FOR_REMOTE_DATA_REQUEST
		 * (1st tidset) or WAITING_FOR_REMOTE_ACK (2nd+ tidset of a segmented
		 * READ -- _sdma_inject() advances health to WAITING_FOR_REMOTE_ACK
		 * after the first tidset is injected, so every later DATA_REQUEST in
		 * a multi-tidset transfer legitimately arrives against a tracker
		 * already in that state). Terminal states (complete/cancel) release
		 * the rift key and NULL the slot in _rift_release(), so _rift_search
		 * can never return a completing/cancelling tracker here -- no state
		 * check for that case is needed.
		 *
		 * WRITE is intentionally excluded: the lazy-pull source read and
		 * early-release/chain-signal on payload_remaining==0 make a WRITE
		 * recovery unsafe without its own drained-buffer guard. WRITE
		 * stale-key DATA_REQUESTs continue to hard drop below.
		 */
		union hfi2_dms_tracker *recovered = NULL;

		if (parameters->rx_rift_key.value &&
		    !_rift_key_error(parameters->rx_rift_key))
			recovered = _rift_search(&dms->rift,
						 parameters->rx_rift_key,
						 metadata->slid);

		if (recovered &&
		    (recovered->hdr.health_state ==
			     HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST ||
		     recovered->hdr.health_state ==
			     HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) &&
		    recovered->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
			tx_tracker = &recovered->tx;
			dms->counters.diag_target_data_req_identity_recover++;
			if (recovered->hdr.health_state ==
			    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK)
				dms->counters.diag_target_data_req_identity_recover_waiting_ack++;
		} else {
			dms->counters.health_invalid_rift_key++;
			dms->counters.diag_target_data_req_rift_miss++;
			dd_dev_dbg_ratelimited(dms->dd,
					       "DMS_DIAG: target_req drop=rift_miss key=%05u rxk=%05u size_qw=%u\n",
					       tx_rift_key.value,
					       parameters->rx_rift_key.value,
					       metadata->size_qw);
			return 0;
		}
	}

	/*
	 * A request without a responder key is a re-request of a speculative
	 * tidset whose DATA_SPECULATIVE never reached the initiator: answer with
	 * DATA_SPECULATIVE so its DATA still promotes the tidset.
	 */
	_tx_serve_tidset_request(dms, tx_tracker, metadata->rx_id,
				 parameters->generation, parameters->entropy,
				 parameters->flags,
				 _rift_key_error(tx_rift_key) ?
					HFI2_DMS_MSG_TYPE_DATA_SPECULATIVE :
				 metadata->is_replay ? HFI2_DMS_MSG_TYPE_DATA_REPLAY :
					HFI2_DMS_MSG_TYPE_DATA,
				 chunks, nchunks, gather, ngather);
	return 0;
}

/*
 * True if a peer-supplied recv_chunk and its @count gather elements describe
 * source bytes this transfer may send, and a landing area that stays inside
 * one tidset: every element non-empty and within [0, @total_payload), the
 * chunk's length their sum, its start offset inside one TID page, and its
 * quadword-padded bytes ending within the tidset that holds its first TID.
 */
static bool _tx_request_chunk_valid(struct hfi2_dms_recv_chunk const *chunk,
				    struct hfi2_dms_gather const *g, u8 count,
				    u32 total_payload)
{
	u32 const tid_info = chunk->tid_info;
	u64 const tid_offset = (tid_info & 0x7fff) << 2;
	u64 const tid_in_set = ((tid_info >> 16) & 0x3ff) &
			       (HFI2_DMS_TID_SET_SIZE - 1);
	u64 sum = 0;
	u64 padded = 0;

	for (u8 i = 0; i < count; i++) {
		if (!g[i].length || g[i].sbuf_offset >= total_payload ||
		    g[i].length > total_payload - g[i].sbuf_offset)
			return false;
		sum += g[i].length;
		padded += round_up(g[i].length, 8);
	}
	if (sum != hfi2_dms_recv_chunk_length(chunk))
		return false;

	return tid_offset < PAGE_SIZE &&
	       tid_in_set * HFI2_DMS_MAX_PAYLOAD_SIZE + tid_offset + padded <=
			HFI2_DMS_TID_SET_BYTES_MAX;
}

/*
 * Send the DATA one tidset request asks for: each recv_chunk's gather elements,
 * in order, into that chunk's TID range, as @data_msg_type. Shared by
 * DATA_REQUEST and by the requests a READ_START_SPECULATIVE carries.
 */
static void _tx_serve_tidset_request(struct hfi2_dms *dms,
				     struct hfi2_dms_tx_tracker *tx_tracker,
				     u8 rx_id, u16 generation, u16 entropy,
				     u8 flags, enum hfi2_dms_msg_type data_msg_type,
				     struct hfi2_dms_recv_chunk const *chunks,
				     u8 nchunks,
				     struct hfi2_dms_gather const *gather,
				     u8 ngather)
{
	struct hfi2_dms_sdma_req req;
	u8 next_gather = 0;

	DMS_BUG_ON((tx_tracker->op != HFI2_DMS_TX_TRACKER_OP_RDMA_READ) && (tx_tracker->op != HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE));

	/* DATA_REQUEST arrival is liveness: reset the stale cadence so the
	 * stale-sweep never cancels a transfer the peer is actively requesting.
	 */
	_tracker_note_peer_activity(dms, (union hfi2_dms_tracker *)tx_tracker);

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)tx_tracker, HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK);

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    (flags & HFI2_DMS_DR_FLAG_UNALIGNED))
		tx_tracker->write.unaligned = true;
	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    data_msg_type == HFI2_DMS_MSG_TYPE_DATA_REPLAY)
		tx_tracker->write.replayed = true;

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    tx_tracker->write.is_single_engine &&
	    !tx_tracker->write.chain_inherit_valid) {
		tx_tracker->write.chain_inherit_entropy = 0;
		tx_tracker->write.chain_inherit_valid = true;
	}

	u16 inject_entropy;

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ)
		inject_entropy = entropy;
	else if (tx_tracker->write.chain_inherit_valid)
		inject_entropy = tx_tracker->write.chain_inherit_entropy;
	else
		inject_entropy = _dms_entropy_next(dms);
	/*
	 * The byte odometer is advanced where the engine actually accepts the
	 * payload for egress (in _sdma_inject_req / the waitlist poll), not here:
	 * a DATA_REQUEST whose payload fails injection is parked on the SDMA
	 * waitlist under egress backpressure and must not count as progress.
	 *
	 * Use the tracker's live key, not the wire tx_rift_key: on the
	 * identity-recovery path the wire key is generation-stale and would
	 * mis-address SDMA completion.
	 */
	/*
	 * Copy the request's chunks and the gather elements they consume; the
	 * copy into req.gather[] is the one place a peer-supplied count indexes
	 * local memory, so bound each chunk's count to both a chunk's list and
	 * what remains of the received array. A malformed chunk ends the
	 * request there, sending the chunks before it.
	 *
	 * The elements themselves are the peer's too. Each must be non-empty
	 * (an empty one sends nothing, and a request of only empty ones would
	 * build an empty SDMA submission) and lie within this transfer's
	 * source -- pinning and the provider's runs are bounded by the whole
	 * buffer, not by the transfer the peer was granted. A chunk's length
	 * must be its elements' sum, as the initiator builds it.
	 */
	req = (struct hfi2_dms_sdma_req){
		.local_rift_key = tx_tracker->hdr.local_rift_key,
		.rx_id = rx_id,
		.generation = generation,
		.entropy = inject_entropy,
		.msg_type = data_msg_type,
		.page_offset = tx_tracker->xfer_start_byte_offset,
	};
	for (u8 i = 0; i < nchunks && i < HFI2_DMS_DR_MAX_CHUNKS; i++) {
		struct hfi2_dms_recv_chunk const *chunk = &chunks[i];
		u8 const count = hfi2_dms_recv_chunk_count(chunk);

		if (unlikely(!count || count > HFI2_DMS_DR_CHUNK_MAX_GATHER ||
			     count > ngather - next_gather ||
			     !_tx_request_chunk_valid(chunk, &gather[next_gather],
						      count, tx_tracker->total_payload))) {
			dms->counters.health_invalid_data_request++;
			break;
		}
		req.chunk[req.nchunks++] = *chunk;
		memcpy(&req.gather[next_gather], &gather[next_gather],
		       count * sizeof(*gather));
		next_gather += count;
		req.nbytes += hfi2_dms_recv_chunk_length(chunk);
	}
	req.ngather = next_gather;

	if (req.nchunks) {
		_sdma_inject_req(dms, &req);
		/* The inject may have cancelled the transfer (and freed it). */
		if (_rift_lookup(&dms->rift, req.local_rift_key) !=
		    (union hfi2_dms_tracker *)tx_tracker)
			return;
	}

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE &&
	    !tx_tracker->write.unaligned &&
	    !tx_tracker->write.replayed &&
	    tx_tracker->payload_remaining == 0)
		_dms_write_signal_early_release(dms, tx_tracker, inject_entropy);
}

static int hfi2_dms_impl_handle_data_request_packet(struct hfi2_dms *dms,
						    union hfi2_dms_16b_header *hdr, void *ebuf)
{
	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;
	struct hfi2_dms_data_request_parameters const *parameters =
		&entry->data_request;
	u8 const nchunks = parameters->recv_chunk_count;
	struct hfi2_dms_recv_chunk const *recv_chunks;
	struct hfi2_dms_recv_chunk compact_chunk;
	struct hfi2_dms_gather compact_gather;

	struct hfi2_dms_data_request_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.size_qw = hfi2_dms_impl_data_request_size_qw_get(hdr),
		.rx_id = _dms_return_rx_get(&hdr->bth[0]),
		.is_replay = hfi2_dms_impl_message_type_get(hdr) ==
			HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY,
	};

	/* Compact form: one range, its length from the BTH size_qw. */
	if (!nchunks) {
		u32 const length = metadata.size_qw << 3;

		compact_chunk = (struct hfi2_dms_recv_chunk){
			.tid_info = parameters->tid_info,
			.length_count =
				FIELD_PREP(HFI2_DMS_RECV_CHUNK_LENGTH, length) |
				FIELD_PREP(HFI2_DMS_RECV_CHUNK_COUNT, 1),
		};
		compact_gather = (struct hfi2_dms_gather){
			.sbuf_offset = parameters->sbuf_offset,
			.length = length,
		};
		return hfi2_dms_impl_handle_data_request(dms, &metadata,
							 parameters,
							 &compact_chunk, 1,
							 &compact_gather, 1);
	}

	/* Bounds the gather array walked below and the arrays' extent. */
	if (unlikely(nchunks > HFI2_DMS_DR_MAX_CHUNKS ||
		     parameters->gather_count > HFI2_DMS_DR_MAX_GATHER)) {
		dms->counters.health_invalid_data_request++;
		return 0;
	}

	/*
	 * The sender places both arrays inline when they fit the 120-byte HDRQ
	 * inline budget and otherwise whole at the start of the eager portion,
	 * which is exactly when the hardware hands over an eager buffer. The
	 * counts are the peer's: the frame must actually carry what they claim,
	 * where they claim it.
	 */
	{
		u32 const arrays_bytes =
			_data_request_arrays_bytes(nchunks, parameters->gather_count);
		bool const in_eager = arrays_bytes > HFI2_DMS_DR_INLINE_BYTES;

		if (unlikely(parameters->gather_count < nchunks ||
			     in_eager != !!ebuf ||
			     !_request_arrays_fit(hfi2_dms_lrh16B_pkt_len_get(hdr->lrh),
						  offsetof(struct _hdrq_entry, data_request) +
						  offsetof(struct hfi2_dms_data_request_parameters,
							   arrays),
						  HFI2_DMS_DR_INLINE_BYTES,
						  arrays_bytes))) {
			dms->counters.health_invalid_data_request++;
			return 0;
		}
	}
	recv_chunks = ebuf ? ebuf :
		(struct hfi2_dms_recv_chunk const *)parameters->arrays;

	return hfi2_dms_impl_handle_data_request(dms, &metadata, parameters,
						 recv_chunks, nchunks,
						 (struct hfi2_dms_gather const *)
						 &recv_chunks[nchunks],
						 parameters->gather_count);
}

void hfi2_dms_impl_handle_ack(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr, enum hfi2_dms_msg_type const type)
{
	union hfi2_dms_proto_pkt_ack * ack;
	struct hfi2_dms_tx_tracker *tx_tracker;

	DMS_WARN_ON(dms == NULL);
	DMS_WARN_ON(hdr == NULL);
	DMS_WARN_ON(hfi2_dms_impl_message_type_get(hdr) != type);

	ack = (union hfi2_dms_proto_pkt_ack *)hdr;

	if (type == HFI2_DMS_MSG_TYPE_ACK) {
		hfi2_dms_rift_key_t const tx_rift_key = ack->info.tx_rift_key;

		if (unlikely(_rift_key_error(tx_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop ACK with error rift key 0x%04hx\n",
				   tx_rift_key.value);
			return;
		}

		tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, tx_rift_key);
		if (!tx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", tx_rift_key.value, _rift_key_generation(tx_rift_key), _rift_key_index(tx_rift_key));
			return;
		}

		/*
		 * Guard against stale ACK completing the wrong tracker.
		 */
		if (tx_tracker->hdr.health_state != HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) {
			dd_dev_dbg(dms->dd,
				"ACK rejected: tx rift key 0x%04hx (%hu %hu) tracker in state %d, expected WAITING_FOR_REMOTE_ACK\n",
				tx_rift_key.value,
				_rift_key_generation(tx_rift_key),
				_rift_key_index(tx_rift_key),
				tx_tracker->hdr.health_state);
			return;
		}
		hfi2_dms_handle_tx_tracker_completion(dms, tx_rift_key, ack->info.flags);
	}
}

int hfi2_dms_impl_handle_write_start(struct hfi2_dms *dms, struct hfi2_dms_write_start_metadata const *metadata,
		struct hfi2_dms_write_start_parameters const *parameters, void *hbuf, void *ebuf, u32 const eager_nbytes)
{
	int ret;
	struct hfi2_dms_access *access;
	struct hfi2_dms_page_provider *page_provider;
	struct hfi2_dms_client_state *client;
	u64 byte_offset_from_first_mr_page;
	struct hfi2_dms_rx_tracker *rx_tracker;

	DMS_BUG_ON(dms == NULL);
	enum hfi2_dms_err_type reason = HFI2_DMS_ERR_TYPE_NONE;

	/* An externally-resolved-destination WRITE_START carries no access
	 * key; the registered upper layer resolves the landing buffer (DMS
	 * stays destination-agnostic), then the payload lands via the WRITE
	 * landing plane.
	 */
	if (metadata->flags & HFI2_DMS_WRITE_START_FLAG_EXT_DEST) {
		struct hfi2_dms_page_provider ext_provider;
		u64 ext_rbuf_start_offset = 0;
		void *ext_cmpl_ctx = NULL;
		enum hfi2_dms_ext_dest_status dst;

		if (!dms->ext_dest.resolve) {
			reason = HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}

		dst = dms->ext_dest.resolve(dms,
				parameters->dms_key, parameters->imm_data,
				parameters->order_key,
				metadata->flags, parameters->xfer_size,
				&ext_provider, &ext_rbuf_start_offset,
				&ext_cmpl_ctx);
		switch (dst) {
		case HFI2_DMS_EXT_DEST_OK:
			break;
		case HFI2_DMS_EXT_DEST_ALREADY_DELIVERED: {
			union hfi2_dms_proto_cmd_ack cmd =
				hfi2_dms_proto_cmd_ack_make(dms,
					metadata->port_idx, metadata->slid,
					metadata->tx_rift_key, 0, 0);
			dms->counters.health_send_replay_reack++;
			_inject_cmd_pio(dms, (union hfi2_dms_proto_cmd *)&cmd,
					HFI2_DMS_TRANSFER_HANDLE_NONE, false);
			return 0;
		}
		case HFI2_DMS_EXT_DEST_RNR:
			reason = HFI2_DMS_ERR_TYPE_RNR;
			goto nack;
		case HFI2_DMS_EXT_DEST_NOMEM:
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		case HFI2_DMS_EXT_DEST_CONSUMED:
		case HFI2_DMS_EXT_DEST_DROP:
		default:
			reason = HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND;
			goto nack;
		}

		union hfi2_dms_tracker *ext_tracker =
			hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
				metadata->tx_rift_key, metadata->slid,
				parameters->order_key,
				HFI2_DMS_XFER_TYPE_TARGET,
				HFI2_DMS_XFER_OP_WRITE);
		if (!ext_tracker) {
			dms->ext_dest.complete(dms, ext_cmpl_ctx, -ENOMEM);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		rx_tracker = &ext_tracker->rx;
		rx_tracker->op = HFI2_DMS_RX_TRACKER_OP_EXT_DEST;
		rx_tracker->tidsets_in_use = 0;
		rx_tracker->tidsets_inflight_bitmap = 0;
		rx_tracker->chain_inherit_entropy = 0;
		rx_tracker->chain_inherit_valid = false;
		rx_tracker->write.metadata = *metadata;
		rx_tracker->write.parameters = *parameters;
		rx_tracker->write.access = NULL;
		rx_tracker->write.ext_cmpl_ctx = ext_cmpl_ctx;

		rx_tracker->total_payload = parameters->xfer_size;
		rx_tracker->payload_remaining = parameters->xfer_size;
		rx_tracker->sbuf_cursor = 0;
		rx_tracker->sbuf_start_offset = 0;
		rx_tracker->rbuf_start_offset = ext_rbuf_start_offset;
		rx_tracker->page_provider = ext_provider;

		ret = _rift_allocate(&dms->rift, ext_tracker);
		if (ret < 0) {
			dms->ext_dest.complete(dms, ext_cmpl_ctx, ret);
			rx_tracker->write.ext_cmpl_ctx = NULL;
			hfi2_dms_impl_tracker_recycle(dms, ext_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		if (ret > 0) {
			rx_tracker->hdr.local_rift_number =
				dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
			ret = _dms_rx_rift_continue_write_start(dms, rx_tracker,
					hbuf, ebuf, eager_nbytes);
			if (ret < 0) {
				_rift_release(&dms->rift,
					      rx_tracker->hdr.local_rift_key);
				dms->ext_dest.complete(dms, ext_cmpl_ctx,
						       -ENOMEM);
				rx_tracker->write.ext_cmpl_ctx = NULL;
				hfi2_dms_impl_tracker_recycle(dms,
					(union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
				goto nack;
			}
		}
		return 0;
	}

	access = hfi2_dms_access_lookup(dms, parameters->dms_key, &client);
	if (!client) {
		dd_dev_info(dms->dd, "WRITE_START: client not found key=%llx\n",
			    parameters->dms_key.value);
		reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
		goto nack;
	}

	if (!access) {
		/*
		 * Diagnostic-only: report whether a matching registration
		 * command is still pending in the client's cmdq. Does not
		 * change dispatch below.
		 */
		if (client->diag_access_fn) {
			if (client->diag_access_fn(client->diag_access_ctx,
						   parameters->dms_key.access))
				dms->counters.access_deferred_pending_cmd_found++;
			else
				dms->counters.access_deferred_pending_cmd_not_found++;
		}
		return -EAGAIN;
	}

	page_provider = &access->page_provider;
	/* Bilateral promote: a remote rank is initiating an RDMA-WRITE
	 * whose destination is one of THIS rank's MRs (identified by
	 * the access lookup above).  Complementary to the explicit
	 * user_mr_promote() at the initiator-side cmd-handler in
	 * bulksvc_user.c.  Idempotent.
	 */
	if (access->page_provider.promote)
		page_provider->promote(page_provider->provider_ctx);

	ret = calculate_access_mr_page_offset(dms, access, parameters->offset, parameters->xfer_size, &byte_offset_from_first_mr_page);
	if (ret < 0) {
		struct hfi2_dms_mr const *acc_mr =
			access->page_provider.provider_ctx;

		dd_dev_info(dms->dd, "WRITE_START: range violation offset=%llx size=%u pp.len=%llu pp.region_offset=%llu acc.off=%llu acc.sz=%llu\n",
			    parameters->offset, parameters->xfer_size,
			    access->page_provider.length,
			    acc_mr ? acc_mr->region_offset : 0,
			    access->offset, access->size);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION;
		goto nack;
	}

	union hfi2_dms_tracker *tracker = hfi2_dms_impl_tracker_new(dms, metadata->port_idx,
			metadata->tx_rift_key, metadata->slid, parameters->order_key, HFI2_DMS_XFER_TYPE_TARGET, HFI2_DMS_XFER_OP_WRITE);
	if (!tracker) {
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	rx_tracker = &tracker->rx;
	rx_tracker->op = HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE;
	rx_tracker->tidsets_in_use = 0;
	rx_tracker->tidsets_inflight_bitmap = 0;
	rx_tracker->chain_inherit_entropy = 0;
	rx_tracker->chain_inherit_valid = false;
	rx_tracker->write.metadata = *metadata;
	rx_tracker->write.parameters = *parameters;
	rx_tracker->write.ext_cmpl_ctx = NULL;

	/* Adopt the caller's policy (fast_fail + stale shift) from the START flags. */
	rx_tracker->hdr.fast_fail = hfi2_dms_start_flags_fast_fail(metadata->flags);
	rx_tracker->hdr.stale_backoff_shift =
		hfi2_dms_start_flags_stale_shift(metadata->flags);

	rx_tracker->total_payload = parameters->xfer_size;
	rx_tracker->payload_remaining = parameters->xfer_size;
	rx_tracker->sbuf_cursor = 0;
	rx_tracker->sbuf_start_offset = 0;

	rx_tracker->rbuf_start_offset = byte_offset_from_first_mr_page;
	rx_tracker->page_provider = access->page_provider;

	rx_tracker->write.access = access;

	ret = access_xfer_begin(dms, access, metadata->slid, metadata->tx_rift_key,
				tracker);
	if (ret == HFI2_DMS_ACCESS_ALREADY_STARTED) {
		/*
		 * A live transfer shares this (slid, tx_rift_key).  Classify by
		 * generation (order_key[31:24]):
		 *
		 *  - NEWER: the initiator fast-failed the prior attempt and
		 *    re-issued this WRITE_START.  Tear down the stale target
		 *    tracker (frees its rift key / tidsets, may free an
		 *    ephemeral access), re-look up the access, and re-admit this
		 *    fresh generation.
		 *  - DUP/STALE: a true duplicate or a stale orphan.  Drop it --
		 *    re-issuing WRITE_START here would bypass the tidset DRAINING
		 *    fence that owns lost-DATA_REQUEST recovery and risk
		 *    mis-delivery.  A same-generation body mismatch can only be a
		 *    corrupted/spoofed packet; drop (do not NACK, which would map
		 *    to -EBUSY and cancel the healthy live transfer) and log.
		 */
		union hfi2_dms_tracker *live =
			_access_inflight_find(access, metadata->slid,
					      metadata->tx_rift_key);
		enum hfi2_dms_start_gen_rel rel =
			live ? _start_gen_compare(parameters->order_key,
						  live->hdr.order_key)
			     : HFI2_DMS_START_GEN_DUP;

		if (rel == HFI2_DMS_START_GEN_NEWER) {
			/*
			 * Newer generation: tear down + re-admit fresh.  In-line
			 * cancel safe only for a PERSISTENT access (see the READ
			 * path); access is re-looked-up by key below.
			 */
			WARN_ON_ONCE(access->type != HFI2_DMS_ACCESS_TYPE_PERSISTENT);
			hfi2_dms_rx_tracker_cancel(dms, &live->rx, -ECANCELED);
			live = NULL; /* freed+recycled by cancel; guard future deref */
			access = hfi2_dms_access_lookup(dms, parameters->dms_key,
							&client);
			if (!client || !access) {
				rx_tracker->write.access = NULL;
				hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND;
				goto nack;
			}
			rx_tracker->write.access = access;
			rx_tracker->page_provider = access->page_provider;
			ret = access_xfer_begin(dms, access, metadata->slid,
						metadata->tx_rift_key, tracker);
			if (ret < 0) {
				rx_tracker->write.access = NULL;
				hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
				reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
				goto nack;
			}
		} else {
			/*
			 * DUP (same generation) or STALE (older generation).  Only
			 * a same-generation DUP can be a genuine body mismatch; a
			 * STALE replay legitimately differs in order_key and is
			 * simply dropped, so it must NOT be flagged as a mismatch.
			 */
			struct hfi2_dms_write_start_parameters const *lp =
				(rel == HFI2_DMS_START_GEN_DUP && live)
					? &live->rx.write.parameters : NULL;

			rx_tracker->write.access = NULL;
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);

			if (rel == HFI2_DMS_START_GEN_DUP &&
			    !(lp &&
			      lp->dms_key.value == parameters->dms_key.value &&
			      lp->offset == parameters->offset &&
			      lp->xfer_size == parameters->xfer_size &&
			      lp->order_key == parameters->order_key)) {
				dms->counters.write_start_dup_mismatch++;
				dd_dev_warn_ratelimited(dms->dd,
							"DMS_DIAG: WRITE_START dup mismatch slid=%u tx_rift_key=%u; dropping (not cancelling live transfer)\n",
					metadata->slid, metadata->tx_rift_key.value);
			}
			return 0;
		}
	} else if (ret < 0) {
		rx_tracker->write.access = NULL;
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		reason = HFI2_DMS_ERR_TYPE_ACCESS_BUSY;
		goto nack;
	}

	/*
	 * eager-only WRITE: the whole payload is in this packet, so the
	 * target copies it, ACKs, releases the access and recycles the tracker
	 * without a target rift key.
	 */
	if (hbuf && parameters->xfer_size <= eager_nbytes) {
		rx_tracker->hdr.local_rift_key =
			_rift_key_create_err(HFI2_DMS_RIFT_ERR_KEYLESS);
		dms->counters.eager_rx_keyless++;
		ret = _dms_rx_rift_continue_write_start(dms, rx_tracker, hbuf, ebuf, eager_nbytes);
		if (ret < 0) {
			access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker,
					metadata->flags, parameters->imm_data,
					parameters->order_key, -ENOMEM);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
		return 0;
	}

	ret = _rift_allocate(&dms->rift, (union hfi2_dms_tracker *)rx_tracker);
	if (ret < 0) {
		access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker,
				metadata->flags, parameters->imm_data,
				parameters->order_key, ret);
		hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
		reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
		goto nack;
	}
	if (ret > 0) {
		rx_tracker->hdr.local_rift_number =
			dms->rift.type[HFI2_DMS_XFER_TYPE_TARGET].ticker_total;
		ret = _dms_rx_rift_continue_write_start(dms, rx_tracker, hbuf, ebuf, eager_nbytes);
		if (ret < 0) {
			_rift_release(&dms->rift, rx_tracker->hdr.local_rift_key);
			access_xfer_end(dms, access, (union hfi2_dms_tracker *)rx_tracker, metadata->flags, parameters->imm_data, parameters->order_key, -ENOMEM);
			hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
			reason = HFI2_DMS_ERR_TYPE_NO_MEMORY;
			goto nack;
		}
	}

	return 0;

nack:
	dd_dev_warn_ratelimited(dms->dd, "DMS_DIAG: WRITE_START NACK reason=%s dms_key=%llu slid=%u size=%u offset=%llu\n",
		    _nack_reason_str(reason), parameters->dms_key.value,
		    metadata->slid, parameters->xfer_size, parameters->offset);
	_nack_log(dms, reason, parameters->dms_key);
	_inject_nack(dms, HFI2_DMS_MSG_TYPE_WRITE_START, reason, metadata->port_idx, metadata->slid, metadata->tx_rift_key);
	return 0;
}

static void hfi2_dms_handle_data_start_packet(struct hfi2_dms *dms, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	u32 const hdr_qws =
		(_msgtype_wire_payload_offset[HFI2_DMS_MSG_TYPE_DATA_START_EAGER] - 8) >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	u32 eager_nbytes = 0;

	if (eager) {
		eager_nbytes = _dms_data_start_eager_nbytes_get(hdr->bth);
		if (unlikely(pktlen_qws < hdr_qws + 1 ||
			     eager_nbytes > ((pktlen_qws - hdr_qws - 1) << 3))) {
			dms->counters.health_short_packet_drop++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: short DATA_START_EAGER pktlen_qws=%u hdr_qws=%u eager_nbytes=%u dropped\n",
				pktlen_qws, hdr_qws, eager_nbytes);
			return;
		}
	}

	hfi2_dms_handle_data_start(dms, hdr, eager, ebuf, eager_nbytes);
}

static void hfi2_dms_impl_handle_write_start_packet(struct hfi2_dms *dms, u8 rcv_port, bool eager, union hfi2_dms_16b_header *hdr, void *ebuf)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!hdr);

	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;

	/*
	 * WRITE_START_EAGER carries no payload in the header queue: the whole
	 * payload is in the eager buffer at WSE_EBUF_PAYLOAD_OFFSET.  @hbuf is
	 * the eager payload pointer for eager packets and NULL otherwise, so
	 * the receive path takes the normal TID/SDMA flow for non-eager.
	 */
	void *hbuf = (eager && ebuf) ? (u8 *)ebuf + WSE_EBUF_PAYLOAD_OFFSET : NULL;

	u32 const hdr_qws = WSE_WIRE_PAYLOAD_OFFSET >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	u32 eager_nbytes = 0;

	if (eager) {
		eager_nbytes = entry->write_start.eager_nbytes;
		if (unlikely(pktlen_qws < hdr_qws + 1 || !ebuf ||
			     eager_nbytes > ((pktlen_qws - hdr_qws - 1) << 3))) {
			dms->counters.health_short_packet_drop++;
			dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: short WRITE_START_EAGER pktlen_qws=%u hdr_qws=%u eager_nbytes=%u dropped\n",
				pktlen_qws, hdr_qws, eager_nbytes);
			return;
		}
	}

	struct hfi2_dms_write_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.tx_rift_key = {.value = (u16) ((hdr->bth[2] >> 16) & 0xFFFF)},
		.flags = (u16) ((hdr->bth[2]) & 0xFFFF),
		.port_idx = rcv_port
	};

	int ret = hfi2_dms_impl_handle_write_start(dms, &metadata, &entry->write_start, hbuf, ebuf, eager_nbytes);

	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_WRITE, &metadata, &entry->write_start);
}

/*
 * WRITE_START_TINY: the payload follows the write_start parameters in the
 * header queue, in place of the reserved_qw and eager_payload slots, and is
 * landed from there like a WRITE_START_EAGER payload.  A path that cannot use
 * the in-packet payload (a deferred retry) requests it with DATA_REQUESTs,
 * as for any WRITE_START.
 */
static void hfi2_dms_impl_handle_write_start_tiny_packet(struct hfi2_dms *dms,
							 u8 rcv_port,
							 union hfi2_dms_16b_header *hdr)
{
	struct _hdrq_entry const *entry = (struct _hdrq_entry *)hdr;
	u8 *payload = (u8 *)entry + WST_PAYLOAD_OFFSET;
	u32 const hdr_qws = WST_PAYLOAD_OFFSET >> 3;
	u32 const pktlen_qws = hfi2_dms_lrh16B_pkt_len_get(hdr->lrh);
	struct hfi2_dms_write_start_parameters const *parameters =
		&entry->write_start;
	u32 nbytes;
	int ret;

	if (unlikely(pktlen_qws < hdr_qws + 1 ||
		     pktlen_qws > hdr_qws + 1 + WST_PAYLOAD_MAX / 8))
		goto bad_len;

	nbytes = parameters->eager_nbytes;
	if (unlikely(nbytes > ((pktlen_qws - hdr_qws - 1) << 3) ||
		     parameters->xfer_size > nbytes))
		goto bad_len;

	struct hfi2_dms_write_start_metadata const metadata = {
		.slid = _dms_peer_get(hdr),
		.tx_rift_key = {.value = (u16)((hdr->bth[2] >> 16) & 0xFFFF)},
		.flags = (u16)((hdr->bth[2]) & 0xFFFF),
		.port_idx = rcv_port
	};

	ret = hfi2_dms_impl_handle_write_start(dms, &metadata, parameters,
					       payload, NULL, nbytes);
	if (ret < 0)
		_access_deferred_add(dms, HFI2_DMS_OP_RDMA_WRITE, &metadata,
				     parameters);
	return;

bad_len:
	dms->counters.health_short_packet_drop++;
	dd_dev_warn_ratelimited(dms->dd,
				"DMS_DIAG: bad WRITE_START_TINY pktlen_qws=%u xfer_size=%u dropped\n",
				pktlen_qws, entry->write_start.xfer_size);
}

void hfi2_dms_tx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_tx_tracker *tx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tx_tracker);
	DMS_BUG_ON(tx_tracker->hdr.side != HFI2_DMS_XFER_SIDE_TX);

	dms->counters.trackers_cancelled_tx++;

	/*
	 * BTS owns sibling/child cancellation (it flushes in-flight
	 * trackers by handle on the verbs path).  Here we only sever our own
	 * chain links so a parent's later signal cannot touch this recycled
	 * tracker; we do NOT cascade into parked children.
	 */
	_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)tx_tracker);
	tx_tracker->hdr.child_handle =
		HFI2_DMS_TRANSFER_HANDLE_NONE;

	hfi2_dms_rift_key_t const key = tx_tracker->hdr.local_rift_key;
	enum hfi2_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_KEY_DISABLED);

	if (status != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {

		/* Scan every waitlist bucket: entropy-hashed injects park on real
		 * engines 0..num_engines-1, not just IDX_ANY.
		 */
		for (s32 i = 0; i < HFI2_DMS_SDMA_ENGINE_IDX_COUNT; ++i) {
			enum hfi2_dms_sdma_engine_idx const idx = (enum hfi2_dms_sdma_engine_idx) i;
			struct hfi2_dms_sdma_tracker *waiter = _sdma_engine_waitlist_peek(dms, idx);
			while (waiter) {
				struct hfi2_dms_sdma_tracker *next = (struct hfi2_dms_sdma_tracker *) waiter->hdr.dlist.next;
				if ((struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, waiter->info.local_rift_key) == tx_tracker) {
					_sdma_engine_waitlist_remove(dms, idx, waiter);
					_sdma_tracker_free(dms, waiter);
				}
				waiter = next;
			}
		}

		_rift_release(&dms->rift, key);

	} else {
		enum hfi2_dms_xfer_type t = tx_tracker->hdr.type;
		enum hfi2_dms_xfer_side s = tx_tracker->hdr.side;
		hfi2_dms_impl_dlist_remove(&dms->rift.type[t].side[s].waitlist,
					   (struct hfi2_dms_dlist_element *)tx_tracker);
	}

	if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
		access_xfer_end(dms, tx_tracker->read.access, (union hfi2_dms_tracker *)tx_tracker, tx_tracker->read.parameters.flags, tx_tracker->read.parameters.imm_data, tx_tracker->hdr.order_key, err);
		tx_tracker->read.access = NULL;

	} else if (tx_tracker->op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
		tx_tracker->write.completion.fn(&tx_tracker->write.completion.cookie, err);
	}

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)tx_tracker);
	_dms_rift_poll_request(dms);
}

static void hfi2_dms_rx_tracker_cancel(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *rx_tracker, int err)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	DMS_BUG_ON(rx_tracker->hdr.side != HFI2_DMS_XFER_SIDE_RX);

	dms->counters.trackers_cancelled_rx++;

	/*
	 * Do not return speculative budget here: the tidsets are DISABLED below
	 * and each returns its unit at its own FREE transition. Returning it now,
	 * while they are still DISABLED and not reprogrammable, would over-
	 * subscribe the pool.
	 */

	/*
	 * BTS owns sibling/child cancellation (it flushes in-flight
	 * trackers by handle on the verbs path).  Here we only sever our own
	 * chain links so a parent's later signal cannot touch this recycled
	 * tracker; we do NOT cascade into parked children.
	 */
	_tracker_detach_from_parent(dms, (union hfi2_dms_tracker *)rx_tracker);
	rx_tracker->hdr.child_handle =
		HFI2_DMS_TRANSFER_HANDLE_NONE;

	hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
	enum hfi2_dms_rift_err const status = _rift_key_error(key);

	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_KEY_DISABLED);
	DMS_BUG_ON(status == HFI2_DMS_RIFT_ERR_NONE && !_rift_key_side_rx(key));

	if (status != HFI2_DMS_RIFT_ERR_KEY_NOT_SET) {

		_tidset_waiter_remove(dms, rx_tracker);

		u32 const sz = HFI2_DMS_ARRAY_SIZE(dms->read_requests);
		bool disabled_any = false;
		for (u32 tid_set = 0; tid_set < sz; ++tid_set) {
			union hfi2_dms_tracker *tracker = (union hfi2_dms_tracker *) dms->read_requests[tid_set].rx_tracker;
			if (((struct hfi2_dms_rx_tracker *)tracker == rx_tracker) &&
					    (dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_ENABLED ||
					     dms->read_requests[tid_set].state == HFI2_DMS_TIDSET_STATE_DRAINING)) {
				DMS_BUG_ON(rx_tracker->tidsets_in_use == 0);
				_dms_rx_tracker_tidset_inflight_clear(rx_tracker, tid_set);
				_tidset_reset(dms, tid_set, HFI2_DMS_TIDSET_STATE_DISABLED);
				disabled_any = true;
			}
		}
		if (disabled_any)
			flush_wc();

		_cancel_cache_add(dms, rx_tracker->hdr.remote_lid, rx_tracker->hdr.remote_rift_key, err);

		_rift_cancel(&dms->rift, key);

	} else {
		enum hfi2_dms_xfer_type t = rx_tracker->hdr.type;
		enum hfi2_dms_xfer_side s = rx_tracker->hdr.side;
		hfi2_dms_impl_dlist_remove(&dms->rift.type[t].side[s].waitlist,
					   (struct hfi2_dms_dlist_element *)rx_tracker);
	}

	if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_RDMA_READ) {
		rx_tracker->read.completion.fn(&rx_tracker->read.completion.cookie, err);
	} else if (rx_tracker->op == HFI2_DMS_RX_TRACKER_OP_EXT_DEST) {
		dms->ext_dest.complete(dms,
			rx_tracker->write.ext_cmpl_ctx, err);
	} else { // HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE
		access_xfer_end(dms, rx_tracker->write.access,
			(union hfi2_dms_tracker *)rx_tracker,
			rx_tracker->write.metadata.flags,
			rx_tracker->write.parameters.imm_data,
			rx_tracker->write.parameters.order_key,
			err);
		rx_tracker->write.access = NULL;
	}

	_dms_rift_poll_request(dms);
	_service_global_tidset_waiters(dms);

	hfi2_dms_impl_tracker_recycle(dms, (union hfi2_dms_tracker *)rx_tracker);
}

int hfi2_dms_cancel_tracker_by_handle(struct hfi2_dms *dms,
				      struct hfi2_dms_transfer_handle handle,
				      int err)
{
	union hfi2_dms_tracker *tracker;

	if (WARN_ON_ONCE(!dms))
		return -EFAULT;

	tracker = _handle_to_tracker(handle);
	if (unlikely(!tracker)) {
		dms->counters.cancel_by_handle_notfound++;
		return -ENOENT;
	}

	if (unlikely(tracker->hdr.chain_signalled)) {
		dms->counters.cancel_by_handle_chain_signalled++;
		return -ENOENT;
	}

	if (_rift_key_error(tracker->hdr.local_rift_key) == HFI2_DMS_RIFT_ERR_NONE &&
	    _rift_lookup(&dms->rift, tracker->hdr.local_rift_key) != tracker) {
		dms->counters.cancel_by_handle_notfound++;
		return -ENOENT;
	}

	_tracker_cancel(dms, tracker, err);
	dms->counters.cancel_by_handle_success++;

	return 0;
}


static void _tidset_waiter_enqueue(struct hfi2_dms *dms,
				      struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);
	WARN_ON_ONCE(rx_tracker->sbuf_cursor >= rx_tracker->total_payload);

	hfi2_dms_rift_key_t const key = rx_tracker->hdr.local_rift_key;
	DMS_BUG_ON(_rift_key_error(key));
	DMS_BUG_ON(!_rift_key_side_rx(key));

	_rift_keyring_add(&dms->tidset_waiters, key);

	_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
				  HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION);
}

static void _tidset_waiter_remove(struct hfi2_dms *dms,
				     struct hfi2_dms_rx_tracker *rx_tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!rx_tracker);

	_rift_keyring_remove(&dms->tidset_waiters, rx_tracker->hdr.local_rift_key);
}

static void _service_global_tidset_waiters(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);

	while (!_rift_keyring_empty(&dms->tidset_waiters)) {
		hfi2_dms_rift_key_t const key = _rift_keyring_peek(&dms->tidset_waiters);
		union hfi2_dms_tracker *tracker = _rift_lookup(&dms->rift, key);

		if (!tracker) {
			_rift_keyring_advance(&dms->tidset_waiters);
			continue;
		}

		struct hfi2_dms_rx_tracker *rx_tracker = &tracker->rx;

		if (rx_tracker->sbuf_cursor >= rx_tracker->total_payload) {
			_rift_keyring_advance(&dms->tidset_waiters);
			continue;
		}

		u32 const free_count = _tidset_free_count(dms);
		if (free_count == 0)
			break;

		u32 tidset;
		int ret;
		_tidset_idx_peek(dms, &tidset);
		_tidset_idx_reserve(dms, tidset);
		ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
		if (ret != 0) {
			_tidset_idx_release(dms, tidset);
			break;
		}
		DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
		_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);

		for (u32 i = 1; i < HFI2_DMS_TRACKER_TIDSET_MAX &&
		     rx_tracker->sbuf_cursor < rx_tracker->total_payload &&
		     free_count > i; i++) {
			_tidset_idx_peek(dms, &tidset);
			_tidset_idx_reserve(dms, tidset);
			ret = hfi2_dms_impl_make_data_request(dms, rx_tracker, tidset);
			if (ret != 0) {
				_tidset_idx_release(dms, tidset);
				break;
			}
			DMS_BUG_ON(tidset >= HFI2_DMS_TID_SET_IDX_COUNT);
			_dms_rx_tracker_tidset_inflight_set(rx_tracker, tidset);
		}

		_tracker_health_state_set(dms, (union hfi2_dms_tracker *)rx_tracker,
						HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA);

		_chain_signal_last_engine(dms, rx_tracker);

		_rift_keyring_advance(&dms->tidset_waiters);
	}
}

static void _tracker_cancel(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker, int err)
{
	DMS_BUG_ON(!tracker);

	switch (tracker->hdr.side) {
	case HFI2_DMS_XFER_SIDE_TX:
		hfi2_dms_tx_tracker_cancel(dms, &tracker->tx, err);
		break;
	case HFI2_DMS_XFER_SIDE_RX:
		hfi2_dms_rx_tracker_cancel(dms, &tracker->rx, err);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

void hfi2_dms_impl_handle_nack_packet(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_nack *nack;
	struct hfi2_dms_tx_tracker *tx_tracker;
	struct hfi2_dms_rx_tracker *rx_tracker;

	DMS_WARN_ON(!dms);
	DMS_WARN_ON(!hdr);
	DMS_WARN_ON(hfi2_dms_impl_message_type_get(hdr) != HFI2_DMS_MSG_TYPE_NACK);

	nack = (union hfi2_dms_pkt_nack *)hdr;

	DMS_WARN_ON(nack->info.err_type == HFI2_DMS_ERR_TYPE_NONE);

	hfi2_dms_rift_key_t const nack_rift_key = nack->info.rift_key;

	if (unlikely(_rift_key_error(nack_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop NACK with error rift key 0x%04hx\n",
			   nack_rift_key.value);
		return;
	}

	int err = 0;
	switch (nack->info.err_type) {
	case HFI2_DMS_ERR_TYPE_CLIENT_NOT_FOUND:
		err = -EINVAL;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_NOT_FOUND:
		err = -EINVAL;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_RANGE_VIOLATION:
		err = -EACCES;
		break;
	case HFI2_DMS_ERR_TYPE_TRANSFER_SIZE_VIOLATION:
		err = -EMSGSIZE;
		break;
	case HFI2_DMS_ERR_TYPE_NO_MEMORY:
		err = -ENOMEM;
		break;
	case HFI2_DMS_ERR_TYPE_ACCESS_BUSY:
		err = -EBUSY;
		break;
	case HFI2_DMS_ERR_TYPE_RNR:
		err = -EINVAL;
		break;
	default:
		err = -EPROTO;
		break;
	}

	switch (nack->info.msg_type) {
	case HFI2_DMS_MSG_TYPE_WRITE_START:
		if (unlikely(!_rift_key_side_tx(nack_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop WRITE_START NACK with non-tx rift key 0x%04hx\n",
				   nack_rift_key.value);
			return;
		}
		tx_tracker = (struct hfi2_dms_tx_tracker *) _rift_lookup(&dms->rift, nack_rift_key);
		if (!tx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid tx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
			return;
		}
		if (nack->info.err_type == HFI2_DMS_ERR_TYPE_RNR) {
			/* FAST_FAIL is strict: an RNR NACK is a replay decision, so cancel instead of retrying, even the immediate local retry. */
			if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)tx_tracker))
				return;
			tx_tracker->hdr.rnr_retry_count++;
			dms->counters.rnr_nack_retries++;
			if (tx_tracker->hdr.rnr_retry_count <= HFI2_DMS_RNR_IMMEDIATE_RETRY_MAX) {
				_tracker_reinject_start(dms, (union hfi2_dms_tracker *)tx_tracker);
				return;
			}
			if (!tx_tracker->hdr.rnr_pending) {
				dms->counters.rnr_nack_deferred++;
				tx_tracker->hdr.rnr_pending = true;
			}
			return;
		}
		dd_dev_dbg(dms->dd, "DMS: WRITE_START fatal NACK err_type=%u err=%d rift=0x%04hx\n",
			    nack->info.err_type, err, nack_rift_key.value);
		hfi2_dms_tx_tracker_cancel(dms, tx_tracker, err);
		break;

	case HFI2_DMS_MSG_TYPE_READ_START:
	case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
	case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
		if (unlikely(!_rift_key_side_rx(nack_rift_key))) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd,
				   "Drop READ_START NACK with non-rx rift key 0x%04hx\n",
				   nack_rift_key.value);
			return;
		}
		rx_tracker = (struct hfi2_dms_rx_tracker *) _rift_lookup(&dms->rift, nack_rift_key);
		if (!rx_tracker) {
			dms->counters.health_invalid_rift_key++;
			dd_dev_dbg(dms->dd, "Ignore invalid rx rift key 0x%04hx (%hu %hu)\n", nack_rift_key.value, _rift_key_generation(nack_rift_key), _rift_key_index(nack_rift_key));
			return;
		}
		if (nack->info.err_type == HFI2_DMS_ERR_TYPE_RNR) {
			/* FAST_FAIL is strict: an RNR NACK is a replay decision, so cancel instead of retrying, even the immediate local retry. */
			if (_tracker_cancel_if_fast_fail(dms, (union hfi2_dms_tracker *)rx_tracker))
				return;
			rx_tracker->hdr.rnr_retry_count++;
			dms->counters.rnr_nack_retries++;
			if (rx_tracker->hdr.rnr_retry_count <= HFI2_DMS_RNR_IMMEDIATE_RETRY_MAX) {
				_tracker_reinject_start(dms, (union hfi2_dms_tracker *)rx_tracker);
				return;
			}
			if (!rx_tracker->hdr.rnr_pending) {
				dms->counters.rnr_nack_deferred++;
				rx_tracker->hdr.rnr_pending = true;
			}
			return;
		}
		dd_dev_dbg(dms->dd, "DMS: READ_START fatal NACK err_type=%u err=%d rift=0x%04hx\n",
			    nack->info.err_type, err, nack_rift_key.value);
		hfi2_dms_rx_tracker_cancel(dms, rx_tracker, err);
		break;

	default:
		dd_dev_dbg(dms->dd, "Received NACK for unknown message type %u with rift index: %hu, error type: %u\n", nack->info.msg_type, nack->info.rift_key.value, nack->info.err_type);
		break;
	}
}

static union hfi2_dms_tracker *_locate_tracker(struct hfi2_dms *dms, struct hfi2_dms_rift *rift, hfi2_dms_rift_key_t const remote_rift_key, u32 const remote_lid, u8 const port_idx)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(_rift_key_error(remote_rift_key) != HFI2_DMS_RIFT_ERR_NONE);

	union hfi2_dms_tracker *tracker;

	tracker = _rift_search(rift, remote_rift_key, remote_lid);
	if (tracker) {
		return tracker;
	}

	struct hfi2_dms_dlist_element *waiter;
	enum hfi2_dms_xfer_type const t = _rift_key_type_opposite(remote_rift_key);

	for (enum hfi2_dms_xfer_side s = 0; s < HFI2_DMS_XFER_SIDE_COUNT; ++s) {
		waiter = rift->type[t].side[s].waitlist.head;
		while (waiter) {
			tracker = container_of(waiter, union hfi2_dms_tracker, hdr.dlist);
			if (tracker->hdr.remote_rift_key.value == remote_rift_key.value &&
			    tracker->hdr.remote_lid == remote_lid &&
			    tracker->hdr.port_idx == port_idx)
				return tracker;
			waiter = waiter->next;
		}
	}

	return NULL;
}

static void _handle_single_status_request(struct hfi2_dms *dms,
					  u8 rcv_port, u32 remote_lid,
					  hfi2_dms_rift_key_t requester_rift_key)
{
	union hfi2_dms_tracker *tracker;

	if (unlikely(_rift_key_error(requester_rift_key))) {
		dms->counters.health_invalid_rift_key++;
		dd_dev_dbg(dms->dd,
			   "Drop STATUS_REQUEST entry with error rift key 0x%04hx\n",
			   requester_rift_key.value);
		return;
	}

	tracker = _locate_tracker(dms, &dms->rift, requester_rift_key,
				  remote_lid, rcv_port);

	/* An incoming STATUS_REQUEST is the peer polling this transfer: proof it
	 * is still live. Reset the stale cadence so a transfer under active
	 * status polling is never cancelled by the stale-sweep.
	 *
	 * Not for a parked child: that would end its park exemption and let its
	 * own sweep cancel it.
	 */
	if (tracker && !_rx_tracker_is_parked_at_data_start(tracker))
		_tracker_note_peer_activity(dms, tracker);

	if (_rift_key_side_tx(requester_rift_key)) {
		/*
		 * Requester has a TX tracker asking about our local RX
		 * (target) side.
		 */
		if (tracker) {
			enum hfi2_dms_tracker_health_state const state =
				tracker->hdr.health_state;

			switch (state) {
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START:
			case HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE: {
				enum hfi2_dms_status_type const parked =
					HFI2_DMS_STATUS_TYPE_RESPONSE_PARKED;

				_inject_status_response_no_tracker(dms, rcv_port,
								   remote_lid,
								   requester_rift_key,
								   parked);
				break;
			}
			default:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			}
		} else {
			struct hfi2_dms_cancel_cache_entry *cancel_entry =
				_cancel_cache_find(dms, remote_lid,
						   requester_rift_key);

			if (cancel_entry) {
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED);
				_cancel_cache_remove(dms, remote_lid,
						     requester_rift_key);
			} else if (_access_deferred_find(dms, requester_rift_key, remote_lid)) {
				/* START is deferred awaiting access registration — suppress retransmit */
				dms->counters.rnr_duplicate_start++;
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_ACCESS_PENDING);
			} else {
				/*
				 * No local RX tracker, no cancel-cache record,
				 * not access-deferred. tracker == NULL is
				 * ambiguous (never-started vs completed-and-
				 * freed); report only what we know and let the
				 * requester reconcile against its health_state.
				 */
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND);
			}
		}
	} else {
		/*
		 * Requester has an RX tracker asking about our local TX
		 * (initiator) side.
		 */
		if (tracker) {
			enum hfi2_dms_tracker_health_state const state =
				tracker->hdr.health_state;

			switch (state) {
			case HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT);
				break;
			case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST:
				if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE) {
					enum hfi2_dms_msg_type const t =
						HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY;

					if (_tracker_cancel_if_fast_fail(dms, tracker))
						break;
					hfi2_dms_impl_inject_write_start(dms, &tracker->tx, t,
									 false);
				} else if (tracker->tx.op == HFI2_DMS_TX_TRACKER_OP_RDMA_READ) {
					hfi2_dms_impl_inject_data_start(dms,
									&tracker->tx);
				}
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			default:
				_inject_status_response(dms, tracker,
					HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS);
				break;
			}
		} else {
			struct hfi2_dms_cancel_cache_entry *cancel_entry =
				_cancel_cache_find(dms, remote_lid,
						   requester_rift_key);

			if (cancel_entry) {
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED);
				_cancel_cache_remove(dms, remote_lid,
						     requester_rift_key);
			} else {
				/*
				 * No local TX tracker, no cancel-cache record.
				 * tracker == NULL is ambiguous (completed-and-
				 * freed vs a READ_START that never created a TX
				 * tracker); report only what we know and let the
				 * requester reconcile against its health_state.
				 */
				_inject_status_response_no_tracker(dms, rcv_port,
					remote_lid, requester_rift_key,
					HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND);
			}
		}
	}
}

void hfi2_dms_impl_handle_status_request_packet(struct hfi2_dms *dms,
						 u8 rcv_port,
						 union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_status_request *pkt =
		(union hfi2_dms_pkt_status_request *)hdr;
	u32 const remote_lid = _dms_peer_get(hdr);
	u8 count = pkt->info.count;
	u8 i;

	DMS_BUG_ON(!dms);

	if (count > HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES)
		count = HFI2_DMS_STATUS_REQUEST_MAX_ENTRIES;

	for (i = 0; i < count; i++)
		_handle_single_status_request(dms, rcv_port, remote_lid,
					      pkt->info.entries[i]);
}

/*
 * True if a STATUS response may complete this TX tracker in place of the
 * ACK it is waiting for: all its payload went out as DATA in answer to the
 * initiator's own DATA_REQUESTs, which proves the initiator held the RX side.
 * A speculative READ's responder sends DATA from the requests in the
 * READ_START, so having sent everything proves nothing about the initiator:
 * a lost ACK and a cancelled initiator look the same from here, and only a
 * real ACK completes it -- whether or not DATA_REQUESTs followed.
 */
static bool _tx_tracker_status_completable(struct hfi2_dms_tx_tracker const *tx)
{
	if (tx->payload_remaining)
		return false;
	return tx->op != HFI2_DMS_TX_TRACKER_OP_RDMA_READ ||
	       !tx->read.metadata.speculative;
}

/*
 * NOT_FOUND recovery for a tx tracker parked in WAITING_FOR_REMOTE_ACK.
 *
 * Optimistic completion is sound ONLY when all the payload left as separate
 * DATA packets, i.e. payload_remaining == 0. The tracker enters
 * WAITING_FOR_REMOTE_ACK when it hands a request to SDMA; payload_remaining
 * is debited as the engine accepts each request's DATA. Outside a speculative READ the TX
 * side only sources that DATA in response to a DATA_REQUEST -- so the peer
 * provably created an RX tracker (see _tx_tracker_status_completable()).
 * A NOT_FOUND then means the peer completed and freed it (its ACK was
 * lost), and completing is correct. This mirrors the existing
 * TRANSFER_COMPLETE + WAITING_FOR_REMOTE_ACK path and the stale-ACK guard
 * in the ACK handler.
 *
 * A transfer whose payload rides INLINE in the START packet (eager)
 * instead jumps straight to WAITING_FOR_REMOTE_ACK with
 * payload_remaining still == total_payload. There a NOT_FOUND means the
 * START -- and therefore the only copy of the data -- was lost; the peer
 * never received anything. Completing would silently report success for
 * data that never landed. Treat it like a lost START: re-inject with retry
 * accounting and age out to -ETIMEDOUT, never complete.
 */
static void _tx_tracker_not_found_waiting_ack(struct hfi2_dms *dms,
					      union hfi2_dms_tracker *tracker,
					      hfi2_dms_rift_key_t requester_rift_key)
{
	if (_tx_tracker_status_completable(&tracker->tx)) {
		hfi2_dms_handle_tx_tracker_completion(dms, requester_rift_key,
						      HFI2_DMS_FLAG_COMPLETION_VIA_STATUS);
		return;
	}

	_tracker_stale_rearm_keep_count(dms, tracker);
	if (_tracker_is_dead(tracker, dms->now))
		_tracker_cancel(dms, tracker, -ETIMEDOUT);
	/*
	 * A speculative READ that sent everything from its READ_START has
	 * nothing to re-drive, and re-sending DATA_START would leave
	 * WAITING_FOR_REMOTE_ACK and refuse the ACK if it is only late: keep
	 * waiting for the ACK, or age out.
	 */
	else if (tracker->tx.payload_remaining &&
		 !_tracker_cancel_if_fast_fail(dms, tracker))
		_tracker_reinject_start(dms, tracker);
}

void hfi2_dms_impl_handle_status_response_packet(struct hfi2_dms *dms, u8 rcv_port, union hfi2_dms_16b_header *hdr)
{
	union hfi2_dms_pkt_status *pkt = (union hfi2_dms_pkt_status *)hdr;
	hfi2_dms_rift_key_t const requester_rift_key = pkt->info.requester_rift_key;
	union hfi2_dms_tracker *tracker;

	DMS_BUG_ON(!dms);

	tracker = _rift_lookup(&dms->rift, requester_rift_key);

	switch (pkt->info.type) {
	case HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_RIFT:
	/* Note: ACCESS_PENDING aliases WAITING_RIFT (same wire value 5) */
		{
			dms->counters.health_status_rsp_waiting_rift++;
			if (tracker) {
				bool const made_progress =
					pkt->info.rift_global_assigned !=
					tracker->hdr.remote_status.last_known_rift_global_assigned;

				tracker->hdr.remote_status.last_known_rift_tracker_ticket =
					pkt->info.rift_tracker_ticket;
				tracker->hdr.remote_status.last_known_rift_global_assigned =
					pkt->info.rift_global_assigned;
				if (made_progress) {
					u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS * 10;
					tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
					tracker->hdr.status_req_count = 0;
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_WAITING_TIDSET:
		{
			dms->counters.health_status_rsp_waiting_tidset++;
			if (tracker) {
				bool const made_progress =
					pkt->info.tidset_progress !=
					tracker->hdr.remote_status.last_known_tidset_progress;

				tracker->hdr.remote_status.last_known_tidset_progress =
					pkt->info.tidset_progress;
				if (made_progress) {
					u64 const backoff_ms = HFI2_DMS_STALE_BACKOFF_BASE_MS * 10;
					tracker->hdr.stale_time = ktime_add_ms(dms->now, backoff_ms);
					tracker->hdr.status_req_count = 0;
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_IN_PROGRESS:
		{
			dms->counters.health_status_rsp_in_progress++;
			if (tracker) {
				bool const made_progress =
					pkt->info.packet_progress !=
					tracker->hdr.remote_status.last_known_packet_progress;

				tracker->hdr.remote_status.last_known_packet_progress =
					pkt->info.packet_progress;
				if (made_progress) {
					_tracker_stale_set_remote(dms, tracker, HFI2_DMS_STALE_BACKOFF_BASE_MS);
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_TRANSFER_COMPLETE:
		{
			dms->counters.health_status_rsp_complete++;
			if (tracker) {
				if (_rift_key_side_tx(requester_rift_key)) {
					/*
					 * Requester is TX — remote RX reports complete.
					 * Complete only if all payload left as separate
					 * DATA packets (payload_remaining == 0). A TX whose
					 * payload rode inline in the (possibly lost) START
					 * still has payload_remaining == total; a
					 * legacy TRANSFER_COMPLETE from an old peer must not
					 * silently complete it. Mismatch is treated as
					 * transient and aged out, never falsely completed.
					 */
					if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK &&
					    _tx_tracker_status_completable(&tracker->tx))
						hfi2_dms_handle_tx_tracker_completion(dms, requester_rift_key, HFI2_DMS_FLAG_COMPLETION_VIA_STATUS);
					else if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK) {
						dms->counters.health_status_rsp_complete_transient++;
						_tracker_stale_rearm_keep_count(dms, tracker);
					}
				} else {
					/* Requester is RX tracker — remote TX completed, complete local RX */
					if (tracker->rx.payload_remaining == 0) {
						hfi2_dms_rx_tracker_handle_completion(dms, &tracker->rx, 0, 0);
					} else {
					/*
					 * COMPLETE with RX payload outstanding shouldn't occur (responder no
					 * longer fabricates it); treat as transient and rearm WITHOUT resetting
					 * status_req_count, so a stuck tracker still ages out to -ETIMEDOUT.
					 */
					dms->counters.health_status_rsp_complete_transient++;
					_tracker_stale_rearm_keep_count(dms, tracker);
					}
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_NOT_STARTED:
		{
			if (tracker) {
				dms->counters.health_status_rsp_not_started++;
				if (_rift_key_side_tx(requester_rift_key)) {
					/*
					 * TX-side requester can be an RDMA_WRITE
					 * initiator (resend WRITE_START) or an
					 * RDMA_READ target (resend DATA_START).
					 * Dispatch by op; otherwise the wrong
					 * union arm is serialized onto the wire
					 * (e.g. a zero dms_key WRITE_START from
					 * a READ TX tracker).
					 */
					if (tracker->hdr.health_state !=
					    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST &&
					    tracker->hdr.health_state !=
					    HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK)
						break;

					if (!_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
				} else {
					/* Requester is RX tracker — remote didn't get READ_START, re-inject */
					if (tracker->hdr.health_state == HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START &&
					    !_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
				}
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_TRACKER_NOT_FOUND:
		{
			/*
			 * The responder knows nothing about this rift key (no
			 * tracker, no cancel record). Reconcile against our own
			 * health_state — the only place that disambiguates
			 * "peer finished and freed" from "START never landed".
			 * Never fatally cancel here.
			 */
			dms->counters.health_status_rsp_not_found++;
			if (!tracker)
				break; /* ACK race: both sides already done */

			/*
			 * A START that never lands (e.g. permanent packet loss)
			 * must not loop forever. Advance the retry-limit accounting
			 * on every NOT_FOUND that drives a re-injection and bail to
			 * a terminal -ETIMEDOUT once the retry budget is exhausted.
			 * _tracker_stale_rearm_keep_count() increments
			 * status_req_count and re-arms the backoff timer; if the
			 * tracker has exhausted its retries, cancel terminally
			 * instead of re-injecting. This preserves recovery for the
			 * common case (a re-injected START gets through within the
			 * budget) while guaranteeing termination when it never can.
			 */
			if (_rift_key_side_tx(requester_rift_key)) {
				switch (tracker->hdr.health_state) {
				case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST:
					_tracker_stale_rearm_keep_count(dms, tracker);
					if (_tracker_is_dead(tracker, dms->now))
						_tracker_cancel(dms, tracker, -ETIMEDOUT);
					else if (!_tracker_cancel_if_fast_fail(dms, tracker))
						_tracker_reinject_start(dms, tracker);
					break;
				case HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK:
					_tx_tracker_not_found_waiting_ack(dms, tracker,
									  requester_rift_key);
					break;
				default:
					break;
				}
			} else if (tracker->hdr.health_state ==
				   HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION) {
				/*
				 * RX requester blocked on local tidsets. The local
				 * tidset path owns recovery and sets status_req_count to
				 * the stale-exempt value, so this transfer must not be
				 * subject to the retry-limit cancel check: a single late
				 * NOT_FOUND from its prior WAITING_FOR_REMOTE_DATA phase
				 * would otherwise push the count past the budget and
				 * cancel a recoverable transfer. Leave it for the tidset
				 * path to drive. Termination is bounded: the DRAINING
				 * path cancels the tracker after HFI2_DMS_STALE_BACKOFF_MAX_COUNT
				 * retries (see _hfi2_dms_poll_read_requests, DRAINING arm).
				 */
				dms->counters.health_status_rsp_not_found_tidset_wait++;
			} else {
				/*
				 * On NOT_FOUND, bump retry accounting and reinject; once the budget is
				 * spent, terminate with -ETIMEDOUT so a START that never lands cannot
				 * loop forever.
				 */
				_tracker_stale_rearm_keep_count(dms, tracker);
				if (_tracker_is_dead(tracker, dms->now))
					_tracker_cancel(dms, tracker, -ETIMEDOUT);
				else if (tracker->hdr.health_state ==
					 HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START &&
					 !_tracker_cancel_if_fast_fail(dms, tracker))
					_tracker_reinject_start(dms, tracker);
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_CANCELLED:
		{
			if (tracker) {
				dms->counters.health_status_rsp_cancelled++;
				if (_rift_key_side_tx(requester_rift_key))
					hfi2_dms_tx_tracker_cancel(dms, &tracker->tx, -ECANCELED);
				else
					hfi2_dms_rx_tracker_cancel(dms, &tracker->rx, -ECANCELED);
			}
			break;
		}

	case HFI2_DMS_STATUS_TYPE_RESPONSE_PARKED:
		{
			dms->counters.health_status_rsp_parked++;
			if (tracker && _rift_key_side_tx(requester_rift_key)) {
				_tracker_stale_set_remote(dms, tracker,
							  HFI2_DMS_STALE_BACKOFF_BASE_MS);
				tracker->hdr.last_progress_time = dms->now;
			}
			break;
		}

	default:
		dd_dev_warn(dms->dd, "Received status response with unknown type: %u\n", pkt->info.type);
		break;
	}
}

u32 hfi2_dms_impl_data_request_size_qw_get(union hfi2_dms_16b_header *hdr)
{
	u32 ret;

	DMS_BUG_ON(hdr == NULL);
	ret = (u32) ((hdr->bth[2] >> 16) & 0xFFFF);
	return ret;
}

void hfi2_dms_impl_lrh16bc_dlid_set(u64 *lrh16bc, u32 dlid)
{
	u64 newlrh;

	DMS_BUG_ON(lrh16bc == NULL);
	newlrh = (*lrh16bc & ~0xFFFFFFull) | (dlid & 0xFFFFFF);

	*lrh16bc = newlrh;
}

void hfi2_dms_impl_lrh16bc_len_qws_set(u64 *lrh16bc, u32 len_qws)
{
	DMS_BUG_ON(lrh16bc == NULL);

	/* Set the length in QWs in the LRH16BC */
	*lrh16bc = (*lrh16bc & ~(HFI2_DMS_LRH16BC_LEN_QW_MASK << HFI2_DMS_LRH16BC_LEN_QW_SHIFT)) | (
		((u64) (len_qws & HFI2_DMS_LRH16BC_LEN_QW_MASK) << HFI2_DMS_LRH16BC_LEN_QW_SHIFT));
}

void hfi2_dms_impl_lrh16bc_entropy_set(u64 *lrh16bc, u16 entropy)
{
	DMS_BUG_ON(!lrh16bc);

	/* Set the 16-bit entropy field in the LRH16BC (bits [47:32]) */
	*lrh16bc &= ~(HFI2_DMS_LRH16BC_ENTROPY_MASK << HFI2_DMS_LRH16BC_ENTROPY_SHIFT);
	*lrh16bc |= ((u64)entropy << HFI2_DMS_LRH16BC_ENTROPY_SHIFT);
}

static void hfi2_dms_impl_lrh16bc_rc_set(u64 *lrh16bc, u8 rc)
{
	if (WARN_ON_ONCE(!lrh16bc))
		return;

	/* Set the 3-bit Route Control field in the LRH16BC (bits [30:28]) */
	*lrh16bc &= ~(HFI2_DMS_LRH16BC_RC_MASK << HFI2_DMS_LRH16BC_RC_SHIFT);
	*lrh16bc |= ((u64)(rc & HFI2_DMS_LRH16BC_RC_MASK) << HFI2_DMS_LRH16BC_RC_SHIFT);
}

void hfi2_dms_impl_pbc_dlid_set(u64 *pbc, u32 dlid)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the DLID in the PBC
	*pbc = (*pbc & ~(((u64) PBC_DLID_MASK << PBC_DLID_SHIFT))) |
	       ((u64) (dlid & PBC_DLID_MASK) << PBC_DLID_SHIFT);
}

static u8 _pbc_port_idx_get(u64 pbc)
{
	return (pbc >> PBC_PORT_IDX_SHIFT) & PBC_PORT_IDX_MASK;
}

static void hfi2_dms_impl_pbc_length_dws_set(u64 *pbc, u32 length_dws)
{
	DMS_BUG_ON(pbc == NULL);

	// Set the length in DWords in the PBC
	*pbc = (*pbc & ~(((u64) PBC_LENGTH_DWS_MASK << PBC_LENGTH_DWS_SHIFT))) |
	       ((u64) (length_dws & PBC_LENGTH_DWS_MASK) << PBC_LENGTH_DWS_SHIFT);
}

u64 hfi2_dms_impl_pbc_length_dws_get(u64 pbc)
{
	return (pbc >> PBC_LENGTH_DWS_SHIFT) & PBC_LENGTH_DWS_MASK;
}

/*
	return the 16bc size including PBC in DWs of the data
	packet type we send given the current payload size
*/
static u32 hfi2_dms_impl_data_pktlen_dws_from_payload_dws(u32 payload_dws)
{
	u32 ret;

	/* 16B compressed header (with PBC) + payload + 2 dws for 16B tail flit */
	ret = sizeof(union hfi2_dms_proto_cmd_data) / sizeof(u32) + payload_dws + 2;
	return ret;
}

/*
 * Build the SDMA descriptors for ONE contiguous DMA run.  This is the pure
 * JKR/CYR descriptor logic; the run-iterating wrapper lives in
 * hfi2_dms_impl_fill_payload().
 */
static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_run_descriptors(struct sdma_desc *start_desc, u64 nbytes,
				   u64 sbuf_page_offset,
				   dma_addr_t const *run_dma, bool is_jkr)
{
	u64 PHYS_PAGE_SIZE = PAGE_SIZE;
	u64 offset;
	struct sdma_desc *desc;
	u64 chunk_align_bytes;
	u64 page_idx;
	dma_addr_t phys_addr;
	u64 bytes_until_page_end;
	u64 nbytes_256_chunks;
	u64 page_align_bytes;
	u64 page_count;
	u64 i;
	u64 phy_addr;
	u64 chunk_tail_bytes;
	u64 tail_bytes;

	DMS_BUG_ON(start_desc == NULL);
	DMS_BUG_ON(run_dma == NULL);
	DMS_BUG_ON((PHYS_PAGE_SIZE & (PHYS_PAGE_SIZE - 1)) != 0);
	DMS_BUG_ON(nbytes > HFI2_DMS_MAX_PAYLOAD_SIZE);

	offset = sbuf_page_offset;
	desc = start_desc;

	if (is_jkr) {
		/*
		 * JKR errata requires a single descriptor must not cross
		 * a 256 byte boundary unless it is a multiple of 256 bytes in size.
		 */
		chunk_align_bytes = min((HFI2_DMS_PAYLOAD_CHUNK_SIZE - (offset & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1))) & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1), nbytes);
		if (chunk_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], chunk_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += chunk_align_bytes;
			nbytes -= chunk_align_bytes;
		}

		// fill 256 chunks until end of current page (if 4096 page) or end of 256 chunks in this page
		bytes_until_page_end = (PHYS_PAGE_SIZE - (offset & (PHYS_PAGE_SIZE - 1))) & (PHYS_PAGE_SIZE - 1);
		nbytes_256_chunks = nbytes & ~(HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		page_align_bytes = min(bytes_until_page_end, nbytes_256_chunks);
		DMS_BUG_ON((page_align_bytes & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
		if (page_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], page_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += page_align_bytes;
			nbytes -= page_align_bytes;
		}

		// in reality this should be MAX 1, but it could be 0 if we are
		// given a huge page
		page_count = nbytes / PHYS_PAGE_SIZE;
		for (i = 0; i < page_count; ++i) {
			DMS_BUG_ON((offset & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1)) != 0);
			page_idx = offset / PHYS_PAGE_SIZE;
			phy_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], PHYS_PAGE_SIZE);
			_sdma_qw_set_phy_addr(&desc->qw[0], phy_addr);
			desc += 1;

			offset += PHYS_PAGE_SIZE;
			nbytes -= PHYS_PAGE_SIZE;
		}

		// tail chunks
		chunk_tail_bytes = nbytes & ~(HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		if (chunk_tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], chunk_tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += chunk_tail_bytes;
			nbytes -= chunk_tail_bytes;
		}

		// finally, tail bytes
		tail_bytes = nbytes & (HFI2_DMS_PAYLOAD_CHUNK_SIZE - 1);
		if (tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += tail_bytes;
			nbytes -= tail_bytes;
		}
	} else {
		/* For CYR there is no need to follow the JKR errata for payload alignment */
		bytes_until_page_end = (PHYS_PAGE_SIZE - (offset & (PHYS_PAGE_SIZE - 1))) & (PHYS_PAGE_SIZE - 1);
		page_align_bytes = min(bytes_until_page_end, nbytes);
		if (page_align_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], page_align_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += page_align_bytes;
			nbytes -= page_align_bytes;
		}

		page_count = nbytes / PHYS_PAGE_SIZE;
		for (i = 0; i < page_count; ++i) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phy_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], PHYS_PAGE_SIZE);
			_sdma_qw_set_phy_addr(&desc->qw[0], phy_addr);
			desc += 1;

			offset += PHYS_PAGE_SIZE;
			nbytes -= PHYS_PAGE_SIZE;
		}

		tail_bytes = nbytes;
		if (tail_bytes > 0) {
			page_idx = offset / PHYS_PAGE_SIZE;
			phys_addr = run_dma[page_idx] + (offset & (PHYS_PAGE_SIZE - 1));
			*desc = (struct sdma_desc){0};
			_sdma_qw_set_byte_count(&desc->qw[0], tail_bytes);
			_sdma_qw_set_phy_addr(&desc->qw[0], phys_addr);
			desc += 1;

			offset += tail_bytes;
			nbytes -= tail_bytes;
		}
	}

	DMS_BUG_ON(nbytes != 0); // We should have consumed all bytes

	return (struct hfi2_dms_impl_fill_state){
		.cur_desc = desc,
		.page_offset = offset, // This is the total offset we filled
	};
}

/*
 * Fill @nbytes of one packet's payload, iterating contiguous DMA runs from
 * the source provider (next_src_run) and emitting descriptors per run via
 * hfi2_dms_impl_fill_run_descriptors().  src_provider is always present.
 */
static struct hfi2_dms_impl_fill_state
hfi2_dms_impl_fill_payload(struct hfi2_dms_impl_fill_state fill_state,
			   u64 nbytes, bool is_jkr)
{
	u64 packet_remaining = nbytes;
	dma_addr_t const *run_dma = NULL;
	u64 run_page_offset = 0;

	while (packet_remaining) {
		struct hfi2_dms_impl_fill_state run_state;
		u64 run_chunk;

		if (fill_state.run_bytes_remaining == 0) {
			struct hfi2_dms_run run;
			int ret = fill_state.src_provider->next_src_run(
				fill_state.src_provider,
				fill_state.src_byte_offset,
				packet_remaining, &run);
			if (ret < 0) {
				fill_state.err = ret;
				return fill_state;
			}
			run_dma = run.dma_pages;
			run_page_offset = run.page_offset;
			fill_state.run_bytes_remaining = run.run_bytes;
			fill_state.page_offset = run_page_offset;
		}

		run_chunk = min_t(u64, packet_remaining,
				  fill_state.run_bytes_remaining);

		run_state = hfi2_dms_impl_fill_run_descriptors(
			fill_state.cur_desc, run_chunk, fill_state.page_offset,
			run_dma, is_jkr);
		fill_state.cur_desc = run_state.cur_desc;
		fill_state.page_offset = run_state.page_offset;

		packet_remaining -= run_chunk;
		fill_state.src_byte_offset += run_chunk;
		fill_state.run_bytes_remaining -= run_chunk;
	}

	return fill_state;
}

/*
 * Cursor state for budgeted DATA-payload descriptor emission.  run_dma is
 * the page-array base for the current source run; it is not part of struct
 * hfi2_dms_impl_fill_state and is re-derived only when run_bytes_remaining
 * drains to 0, so any mid-run checkpoint must snapshot it explicitly.
 */
struct hfi2_dms_fill_cursor {
	struct sdma_desc tail_desc;
	struct sdma_desc *cur_desc;
	struct hfi2_dms_page_provider const *src_provider;
	u64 src_byte_offset;
	u64 run_bytes_remaining;
	u64 page_offset;
	dma_addr_t const *run_dma;
	/*
	 * Gather list being sent: element gather_idx has elem_remaining source
	 * bytes left, at src_byte_offset; src_base is what each element's
	 * sbuf_offset is relative to. pad_owed is the zero bytes still owed
	 * after the finished element, so every element ends on a quadword
	 * boundary. The list is exhausted when gather_idx == gather_count.
	 */
	struct hfi2_dms_gather const *gather;
	struct sdma_desc const *pad_desc;
	u64 src_base;
	/*
	 * Also the reach handed to next_src_run when (re)fetching a run: the
	 * rest of the element, so a single contiguous source MR is returned as
	 * ONE run that spans every DATA packet of the element. run_dma then
	 * stays the same dma_list base while page_offset accumulates, keeping
	 * the head of the DMA-address array L1-resident and collapsing the
	 * per-packet provider callback into one call per contiguous region.
	 * The emitted run-chunk is still budget-bounded below.
	 */
	u64 elem_remaining;
	u8 gather_count;
	u8 gather_idx;
	u8 pad_owed;
	int err;
};

/* Start the cursor on gather element @idx (< gather_count). */
static void hfi2_dms_fill_elem_start(struct hfi2_dms_fill_cursor *cur, u8 idx)
{
	cur->gather_idx = idx;
	cur->src_byte_offset = cur->src_base + cur->gather[idx].sbuf_offset;
	cur->elem_remaining = cur->gather[idx].length;
	cur->run_bytes_remaining = 0;
}

/* Move past the finished element; after the last one the list is exhausted. */
static void hfi2_dms_fill_elem_next(struct hfi2_dms_fill_cursor *cur)
{
	if (cur->gather_idx + 1 < cur->gather_count) {
		hfi2_dms_fill_elem_start(cur, cur->gather_idx + 1);
		return;
	}
	cur->gather_idx = cur->gather_count;
	cur->run_bytes_remaining = 0;
}

/*
 * Emit descriptors for at most @max_bytes of one contiguous source run,
 * fetching the next run when the current one drains.  Returns the byte
 * count actually emitted (one run-chunk); sets cur->err and returns 0 on a
 * source provider failure.
 */
static u64 hfi2_dms_fill_bounded_step(struct hfi2_dms_fill_cursor *cur,
				      u64 max_bytes, bool is_jkr)
{
	struct hfi2_dms_impl_fill_state run_state;
	u64 run_chunk;

	/* Callers bound their requests by the wire bytes of the list. */
	if (WARN_ON_ONCE(cur->gather_idx >= cur->gather_count)) {
		cur->err = -EINVAL;
		return 0;
	}

	/*
	 * The pad ends on the quadword boundary the element started from, and
	 * every caller's bound is a quadword boundary at or past it, so it is
	 * always emitted whole.
	 */
	if (cur->pad_owed) {
		u8 const pad = cur->pad_owed;

		if (WARN_ON_ONCE(pad >= sizeof(u64) || max_bytes < pad)) {
			cur->err = -EINVAL;
			return 0;
		}
		*cur->cur_desc = cur->pad_desc[pad - 1];
		cur->cur_desc += 1;
		cur->pad_owed = 0;
		hfi2_dms_fill_elem_next(cur);
		return pad;
	}

	if (cur->run_bytes_remaining == 0) {
		struct hfi2_dms_run run;
		int ret = cur->src_provider->next_src_run(cur->src_provider,
							  cur->src_byte_offset,
							  cur->elem_remaining,
							  &run);
		if (ret < 0) {
			cur->err = ret;
			return 0;
		}
		/*
		 * A provider that returns success with a zero-length run makes
		 * no forward progress; the callers' "while (filled < cap)" loops
		 * would spin forever on the single-threaded BTS event thread,
		 * wedging all DMS on the device. Reject it as a provider
		 * contract violation.
		 */
		if (WARN_ON_ONCE(run.run_bytes == 0)) {
			cur->err = -EINVAL;
			return 0;
		}
		cur->run_dma = run.dma_pages;
		cur->page_offset = run.page_offset;
		cur->run_bytes_remaining = run.run_bytes;
	}

	run_chunk = min3(max_bytes, cur->run_bytes_remaining,
			 cur->elem_remaining);

	run_state = hfi2_dms_impl_fill_run_descriptors(cur->cur_desc, run_chunk,
						       cur->page_offset,
						       cur->run_dma, is_jkr);
	cur->cur_desc = run_state.cur_desc;
	cur->page_offset = run_state.page_offset;
	cur->src_byte_offset += run_chunk;
	cur->run_bytes_remaining -= run_chunk;
	cur->elem_remaining -= run_chunk;

	/* Element done: owe its quadword pad, or move straight on. */
	if (cur->elem_remaining == 0) {
		cur->pad_owed = -cur->gather[cur->gather_idx].length & 7;
		if (!cur->pad_owed)
			hfi2_dms_fill_elem_next(cur);
	}

	return run_chunk;
}

/*
 * Step the current run forward in qword-sized increments, recording the
 * last qword-aligned cut that still fits within @budget payload
 * descriptors.  A qword spans at most HFI2_DMS_DESCS_PER_QWORD
 * descriptors, so a legal cut always exists within
 * [budget - HFI2_DMS_DESCS_PER_QWORD, budget].
 */
static void hfi2_dms_fill_qword_search(struct hfi2_dms_fill_cursor *cur,
				       struct sdma_desc const *base, u64 cap,
				       u64 *filled, u32 budget,
				       struct hfi2_dms_fill_cursor *best,
				       u64 *best_filled, bool is_jkr)
{
	while (*filled < cap) {
		u64 to_qword = HFI2_DMS_DESCS_PER_QWORD - (*filled & 7);
		u64 max_bytes = min(to_qword, cap - *filled);
		u64 step = hfi2_dms_fill_bounded_step(cur, max_bytes, is_jkr);

		if (cur->err)
			return;

		*filled += step;

		if ((*filled & 7) == 0) {
			if ((u64)(cur->cur_desc - base) <= budget) {
				*best = *cur;
				*best_filled = *filled;
			} else {
				break;
			}
		}
	}
}

/*
 * Fill up to @cap bytes of one DATA sub-packet payload, ending on a qword
 * boundary with no more than @budget payload descriptors.  Source runs are
 * emitted wholesale; only the single run that would exceed @budget is undone
 * and re-emitted qword-by-qword to find the largest legal cut.  Returns the
 * payload byte count committed (always a qword multiple, since @cap is).
 */
static u64 hfi2_dms_fill_one_subpacket(struct hfi2_dms_fill_cursor *cur,
				       u64 cap, u32 budget, bool is_jkr)
{
	struct sdma_desc const *base = cur->cur_desc;
	struct hfi2_dms_fill_cursor best = *cur;
	u64 best_filled = 0;
	u64 filled = 0;

	while (filled < cap) {
		struct hfi2_dms_fill_cursor save = *cur;
		u64 save_filled = filled;
		u64 step = hfi2_dms_fill_bounded_step(cur, cap - filled, is_jkr);

		if (cur->err)
			return 0;

		filled += step;

		if ((u64)(cur->cur_desc - base) <= budget) {
			if ((filled & 7) == 0 || filled == cap) {
				best = *cur;
				best_filled = filled;
			}
			continue;
		}

		*cur = save;
		filled = save_filled;
		hfi2_dms_fill_qword_search(cur, base, cap, &filled, budget,
					   &best, &best_filled, is_jkr);
		if (cur->err)
			return 0;
		break;
	}

	if (filled == cap && (u64)(cur->cur_desc - base) <= budget)
		return cap;

	*cur = best;
	return best_filled;
}

/*
 * Initialise one DATA-packet AHG header in place from the per-port
 * template.  The full template copy is mandatory: AHG slots are recycled
 * across message types, so stale WRITE_START/DATA_START fields must be
 * cleared every time.
 */
static void hfi2_dms_impl_emit_data_header(struct hfi2_dms *dms,
					   struct hfi2_dms_mem_coh *hdr,
					   u8 port_idx, u32 dlid,
					   hfi2_dms_rift_key_t tx_rift_key,
					   u8 rx_id, u16 generation, u16 entropy,
					   enum hfi2_dms_msg_type msg_type,
					   u64 order_key)
{
	union hfi2_dms_proto_cmd_data const *data_template =
		(union hfi2_dms_proto_cmd_data *)
		&dms->protocol_cmd_templates[port_idx][msg_type];
	u32 payload_dws = HFI2_DMS_MAX_PAYLOAD_SIZE >> 2;
	u32 pbc_pktlen_dws =
		hfi2_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
	u32 pktlen_qws = pbc_pktlen_dws >> 1;
	union hfi2_dms_proto_cmd_data *cmd =
		(union hfi2_dms_proto_cmd_data *)hdr->kvaddr;
	u64 j;

	for (j = 0; j < ARRAY_SIZE(cmd->qws); j++)
		cmd->qws[j] = data_template->qws[j];

	hfi2_dms_impl_pbc_dlid_set(&cmd->pbc, dlid);
	hfi2_dms_impl_pbc_length_dws_set(&cmd->pbc, pbc_pktlen_dws);
	hfi2_dms_impl_lrh16bc_dlid_set(&cmd->lrh16bc, dlid);
	hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc, pktlen_qws);
	hfi2_dms_impl_lrh16bc_rc_set(&cmd->lrh16bc, _dms_route_control_for_order_key(order_key));
	/*
	 * Every DATA packet of this request carries the same entropy so the
	 * fabric keeps them on one in-order (SLID,DLID,entropy) path matching
	 * the SDMA engine chosen by _dms_sdma_engine_idx_from_entropy().
	 */
	hfi2_dms_impl_lrh16bc_entropy_set(&cmd->lrh16bc, entropy);
	_dms_destqp_rx_set(&cmd->info.bth[0], rx_id);
	cmd->info.tx_rift_key = tx_rift_key;
	cmd->info.generation = generation;
}

static u16 _dms_entropy_next(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);
	/* u16 wrap is intentional: entropy is a spread seed, not an identity. */
	return dms->entropy_next++;
}

/*
 * Pick an SDMA engine from a per-request entropy value, division-free:
 *   1. entropy * 0x9E37  -- Fibonacci (golden-ratio) hash; scatters the
 *      sequential entropy counter so adjacent requests hit different engines.
 *   2. (hashed * num_engines) >> 16  -- folds the 16-bit hash into
 *      [0, num_engines) with no modulo. Uniform for any engine count.
 */
static enum hfi2_dms_sdma_engine_idx
_dms_sdma_engine_idx_from_entropy(struct hfi2_dms *dms, u16 entropy)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(dms->num_engines <= 0);

	u16 const hashed = (u16)((u32)entropy * 0x9E37u);

	return (enum hfi2_dms_sdma_engine_idx)(((u32)hashed *
						   dms_num_data_engines(dms)) >> 16);
}

/*
 * Find an engine with room for @ndesc_needed descriptors.  With shared
 * engines (lanes > 1) the engine is returned with its hfi2_dms_sde_lock()
 * held so that no other lane can claim the room before
 * _sdma_engine_write_desc_stack() fills it and drops the lock.  Callers
 * must go straight from a successful acquire to that write: no exit path
 * and nothing that sleeps in between.  The engine's open desc_place() run
 * (another lane's IPoIB packets) is padded first, so the stack starts on a
 * granule boundary.  For sparse, the held lock is handed over with a
 * __release() here and an __acquire() there.
 */
static struct sdma_engine *
_sdma_engine_acquire(struct hfi2_dms *dms,
		     enum hfi2_dms_sdma_engine_idx const engine_idx,
		     u64 ndesc_needed)
{
	u32 cur_sdma_engine;
	u32 sdma_engine_count;
	u32 num_sdma_engines;
	int gethead;
	struct sdma_engine *sdma;

	DMS_BUG_ON(!dms);

	if (engine_idx != HFI2_DMS_SDMA_ENGINE_IDX_ANY) {

		if (WARN_ON_ONCE(engine_idx >= dms_num_data_engines(dms)))
			return NULL;
		sdma = dms->sdma_engines[engine_idx];
		DMS_BUG_ON(!sdma);

		hfi2_dms_sde_lock(dms, engine_idx);
		hfi2_dms_sdma_close_run(dms, engine_idx);
		if (!__sdma_running(sdma))
			goto busy;

		if (sdma_descq_freecnt(sdma) < ndesc_needed) {
			sdma_gethead_dma(sdma);
			if (sdma_descq_freecnt(sdma) < ndesc_needed)
				goto busy;
		}

		__release(&dms->sde_share[engine_idx].lock);
		return sdma;
busy:
		hfi2_dms_sde_unlock(dms, engine_idx);
		return NULL;
	}

	num_sdma_engines = dms_num_data_engines(dms);
	for (gethead = 0; gethead < 2; gethead++) {
		cur_sdma_engine = dms->cur_sdma_engine;
		for (sdma_engine_count = 0; sdma_engine_count < num_sdma_engines; sdma_engine_count++) {
			if (unlikely(cur_sdma_engine >= num_sdma_engines))
				cur_sdma_engine = 0; // keep range [0..num_sdma_engines)
			sdma = dms->sdma_engines[cur_sdma_engine];
			DMS_BUG_ON(!sdma);
			hfi2_dms_sde_lock(dms, cur_sdma_engine);
			hfi2_dms_sdma_close_run(dms, cur_sdma_engine);
			if (gethead != 0)
				sdma_gethead_dma(sdma);
			if (__sdma_running(sdma) && sdma_descq_freecnt(sdma) >= ndesc_needed) {
				dms->cur_sdma_engine = cur_sdma_engine;
				__release(&dms->sde_share[cur_sdma_engine].lock);
				return sdma;
			}
			hfi2_dms_sde_unlock(dms, cur_sdma_engine);
			++cur_sdma_engine;
		} // for sdma_engine_count
	} // for gethead

	return NULL;
}

static u64 _sdma_desc_stack_finalize(struct hfi2_dms *dms, struct hfi2_dms_impl_fill_state current_fill_state, u64 *pad_out)
{
	struct sdma_desc *last_desc;
	u64 ndesc_filled;
	struct sdma_desc *tail;
	u64 pad_needed;

	last_desc = current_fill_state.cur_desc - 1;
	ndesc_filled = (u64) (current_fill_state.cur_desc - dms->desc_stack);
	if (dms->chip_type == CHIP_JKR) {
		u64 pad_total = (HFI2_DMS_DESC_CHUNK_SIZE -
				 (ndesc_filled & (HFI2_DMS_DESC_CHUNK_SIZE - 1))) &
				(HFI2_DMS_DESC_CHUNK_SIZE - 1);
		struct sdma_desc *p;
		u64 last_pkt = 1;
		u64 room, pad_in_last;

		/*
		 * Absorb as much CHUNK-rounding padding as fits into the final
		 * packet, ahead of its head-to-host tail, so the dead
		 * descriptors ride at the very end of the submission rather than
		 * delaying an earlier packet's egress and throttling the
		 * single-threaded op->ACK pipeline. Only the overflow (last
		 * packet already at MAX_DESC) is returned for the caller to
		 * front-distribute across earlier packets.
		 */
		for (p = last_desc - 1;
		     p >= dms->desc_stack && !jkr_sdma_qw_get_last_desc(&p->qw[0]);
		     --p)
			last_pkt++;
		room = MAX_DESC - last_pkt;
		pad_in_last = min(pad_total, room);

		tail = last_desc + pad_in_last;
		*tail = *last_desc;
		jkr_sdma_qw_set_head_to_host(&tail->qw[0]);
		for (u64 i = 0; i < pad_in_last; ++i)
			last_desc[i] = (struct sdma_desc){0};

		ndesc_filled += pad_in_last;
		pad_needed = pad_total - pad_in_last;
	} else if (dms->chip_type == CHIP_CYR) {
		tail = last_desc;
		cyr_sdma_qw_set_head_to_host(&tail->qw[0]);
		pad_needed = 0;

	} else {
		WARN_ON_ONCE(1); // Unknown chip type
		pad_needed = 0;
	}

	*pad_out = pad_needed;
	return ndesc_filled;
}

static void _sdma_engine_write_desc_stack(struct hfi2_dms *dms, enum hfi2_dms_sdma_engine_idx engine_idx, struct sdma_engine *sdma, u64 ndesc_total, u64 npadding, struct hfi2_dms_ahg_header_set *ahg_set)
{
	u32 desc_tail;
	u32 descq_cnt;
	struct sdma_desc *desc;
	struct hfi2_dms_sde_rsrc *sdma_rsrc;

	// write all descriptors into the descriptor queue
	desc_tail = sdma->descq_tail;
	descq_cnt = sdma->descq_cnt;
	u64 i_f = 0;

	for (u64 i = 0; i < ndesc_total; ++i) {
		desc = &dms->desc_stack[i];
		/*
		 * _sdma_desc_stack_finalize already placed as much padding as
		 * fit trailing in the last packet; only its overflow reaches
		 * here (last packet was at MAX_DESC).  Spread that remainder
		 * into the earliest packets that have room.
		 */
		if (npadding && jkr_sdma_qw_get_last_desc(&desc->qw[0])) {
			u32 ndesc_this_packet = (i - i_f) + 1;
			while (ndesc_this_packet < MAX_DESC && npadding) {
				sdma->descq[desc_tail].qw[0] = 0;
				sdma->descq[desc_tail].qw[1] = 0;
				desc_tail += 1;
				if (desc_tail == descq_cnt) {
					desc_tail = 0;
				}
				ndesc_this_packet++;
				npadding--;
			}
			i_f = i + 1;
		}
		sdma->descq[desc_tail].qw[0] = cpu_to_le64(desc->qw[0]);
		sdma->descq[desc_tail].qw[1] = cpu_to_le64(desc->qw[1]);
		desc_tail += 1;
		if (desc_tail == descq_cnt) {
			desc_tail = 0;
		}
	}

	WARN_ON_ONCE(npadding);

	if (engine_idx == HFI2_DMS_SDMA_ENGINE_IDX_ANY) {
		engine_idx = dms->cur_sdma_engine;
		dms->cur_sdma_engine = (dms->cur_sdma_engine + 1) %
			dms_num_data_engines(dms);
	}

	if (dms->sde_share) {
		/* taken by _sdma_engine_acquire() */
		lockdep_assert_held(&dms->sde_share[engine_idx].lock);
		hfi2_dms_sde_seq_advance(dms, engine_idx, sdma->descq_tail,
					 desc_tail, descq_cnt);
		ahg_set->seq_end = dms->sde_share[engine_idx].seq;
	}
	sdma->descq_tail = desc_tail;
	smp_wmb();
	writeq(sdma->descq_tail, sdma->tail_csr);
	__acquire(&dms->sde_share[engine_idx].lock);
	hfi2_dms_sde_unlock(dms, engine_idx);
	sdma_rsrc = &dms->sde_rsrcs[engine_idx];
	ahg_set->desc_idx = desc_tail;
	hfi2_dms_impl_dlist_append(&sdma_rsrc->active_ahg_headers, &ahg_set->dlist);
}

/*
 * Send @nchunks recv_chunks as one SDMA submission. Chunk i lands in the TID
 * range its tid_info names and takes the next hfi2_dms_recv_chunk_count()
 * elements of @gather, each relative to @page_offset; its wire bytes are its
 * element lengths each rounded up to a quadword.
 *
 * All the chunks' DATA packets share one AHG header set and one descriptor
 * stack, so the submission is accepted or refused whole: -EAGAIN when the
 * engine has no room (park the whole request), -E2BIG when a multi-chunk
 * request needs more headers or descriptors than one submission holds (send
 * it chunk by chunk instead), -EMSGSIZE when a single chunk does (fatal).
 */
static int hfi2_dms_impl_sdma_send(struct hfi2_dms *dms,
			    enum hfi2_dms_sdma_engine_idx engine_idx,
			    u64 page_offset,
			    struct hfi2_dms_recv_chunk const *chunks, u8 nchunks,
			    struct hfi2_dms_gather const *gather,
			    u8 port_idx, u32 dlid, u8 rx_id,
			    hfi2_dms_rift_key_t tx_rift_key, u16 generation,
			    struct hfi2_dms_page_provider const *src_provider,
			    u16 entropy, enum hfi2_dms_msg_type msg_type,
			    u64 order_key)
{
	struct send_context *sc;
	u64 start;
	u32 tid_offset;
	u32 tid;
	struct hfi2_dms_fill_cursor cursor;
	struct hfi2_dms_impl_fill_state current_fill_state;
	struct hfi2_dms_ahg_header_set *ahg_set;
	u64 in_tid_bytes;
	u64 region_rem;
	u64 op_rem;
	u32 k = 0;
	bool is_jkr;
	u64 ndesc_total, padding_needed;
	struct sdma_engine *sdma;
	u64 end;
	u8 next_gather = 0;

	if (WARN_ON_ONCE(dms == NULL))
		return -EFAULT;
	if (WARN_ON_ONCE(!src_provider))
		return -EFAULT;

	dms_trace(dms_sdma_send, dms, src_provider);

	sc = dms->port_sctxts[port_idx];

	start = dms_rdtsc();
	// sdma still performs send context checks on egress
	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL)) {
		return -ENOMEM;
	}

	if (unlikely(!dms->desc_stack || dms->num_descs == 0 || !nchunks)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg;
	}

	is_jkr = dms->chip_type == CHIP_JKR;
	cursor = (struct hfi2_dms_fill_cursor){
		.cur_desc = &dms->desc_stack[0],
		.src_provider = src_provider,
		.page_offset = 0,
		.run_dma = NULL,
		.pad_desc = dms->pad_desc_template,
		.src_base = page_offset,
		.err = 0,
		.tail_desc = dms->tail_desc_template
	};
	if (dms->chip_type == CHIP_CYR)
		cyr_sdma_qw_set_send_ctxt_extension(&cursor.tail_desc.qw[0], sc->hw_context);

	for (u8 c = 0; c < nchunks; c++) {
		u32 const tid_info = chunks[c].tid_info;
		u8 const gather_count = hfi2_dms_recv_chunk_count(&chunks[c]);

		tid_offset = (tid_info & 0x7fff) << 2;
		tid = (tid_info >> 16) & 0x3ff;

		if (unlikely(tid_offset >= PAGE_SIZE || !gather_count)) {
			dms->counters.health_invalid_data_request++;
			goto err_put_ahg;
		}

		/* This chunk's elements; the cursor walks them like a one-chunk list. */
		cursor.gather = &gather[next_gather];
		cursor.gather_count = gather_count;
		cursor.pad_owed = 0;
		hfi2_dms_fill_elem_start(&cursor, 0);

		in_tid_bytes = tid_offset;
		region_rem = HFI2_DMS_MAX_PAYLOAD_SIZE - tid_offset;
		op_rem = 0;
		for (u8 i = 0; i < gather_count; i++)
			op_rem += round_up(cursor.gather[i].length, 8);
		next_gather += gather_count;

		/*
		 * Walk the chunk one TID region (HFI2_DMS_MAX_PAYLOAD_SIZE window) at a
		 * time, splitting each region into one or more same-TID DATA
		 * sub-packets so no single packet exceeds the descriptor budget.
		 */
		while (op_rem > 0) {
			struct hfi2_dms_mem_coh *hdr;
			union hfi2_dms_proto_cmd_data *cmd;
			struct hfi2_dms_fill_cursor fill_start;
			struct sdma_desc *hdr_desc;
			u64 descs_used = (u64)(cursor.cur_desc - dms->desc_stack);
			u64 cap;
			u64 bytes;

			if (unlikely(k >= HFI2_DMS_AHG_HEADERS_PER_SET))
				goto err_put_ahg_fatal;
			/*
			 * Reserve a full padded packet (MAX_DESC) plus the
			 * HFI2_DMS_DESCS_PER_QWORD transient slots the budget search
			 * may momentarily emit past the payload budget before
			 * retreating, so the fill never writes past desc_stack.
			 */
			if (unlikely(dms->num_descs - descs_used <
				     MAX_DESC + HFI2_DMS_DESCS_PER_QWORD))
				goto err_put_ahg_fatal;

			hdr = &ahg_set->headers[k];
			hfi2_dms_impl_emit_data_header(dms, hdr, port_idx, dlid,
						       tx_rift_key, rx_id, generation,
						       entropy, msg_type, order_key);
			cmd = (union hfi2_dms_proto_cmd_data *)hdr->kvaddr;
			cmd->info.kdeth[0] =
				hfi2_dms_tid_info_make(tid, in_tid_bytes >> 2);

			hdr_desc = cursor.cur_desc;
			*hdr_desc = dms->header_desc_template;
			_sdma_qw_set_phy_addr(&hdr_desc->qw[0], hdr->phys_addr);
			cursor.cur_desc += 1;

			cap = min(region_rem, op_rem);
			fill_start = cursor;
			bytes = hfi2_dms_fill_one_subpacket(&cursor, cap,
							    HFI2_DMS_PKT_PAYLOAD_DESC_BUDGET,
							    is_jkr);
			if (cursor.err)
				goto err_put_ahg;

			/*
			 * The op_rem/region_rem decrements below drive the loop toward
			 * termination and rely on the provider densely tiling the
			 * requested span. A zero fill is a non-tiling provider that
			 * would spin this loop forever on the single BTS thread, so
			 * treat it as a fatal contract violation rather than hanging
			 * the device.
			 */
			if (unlikely(bytes == 0))
				goto err_put_ahg_fatal;

			/*
			 * A packet of this length needs the PBC test bit.
			 * The DATA header size is fixed for the receive context,
			 * so it cannot be padded. Send fewer bytes in this packet
			 * and the rest in the next one: fill again from the start
			 * of this packet, stopping short by the trim. The shorter
			 * fill needs no more descriptors than the one it replaces,
			 * so it always returns everything asked of it. The next
			 * packet takes one more AHG header from the set; a
			 * request that runs out of them falls back chunk by chunk.
			 */
			if (unlikely(_dms_split_data_packet(bytes))) {
				u32 const budget = HFI2_DMS_PKT_PAYLOAD_DESC_BUDGET;
				u64 keep = ALIGN(bytes, sizeof(u64)) -
					   _dms_data_split_trim(bytes);

				cursor = fill_start;
				bytes = hfi2_dms_fill_one_subpacket(&cursor, keep, budget,
								    is_jkr);
				if (cursor.err)
					goto err_put_ahg;
				if (unlikely(bytes != keep))
					goto err_put_ahg_fatal;
			}

			if (bytes != HFI2_DMS_MAX_PAYLOAD_SIZE) {
				u32 payload_dws = (bytes + 3) >> 2;
				u32 pbc_pktlen_dws;
				u32 pktlen_qws;

				pbc_pktlen_dws =
					hfi2_dms_impl_data_pktlen_dws_from_payload_dws(payload_dws);
				pktlen_qws = pbc_pktlen_dws >> 1;

				hfi2_dms_impl_lrh16bc_len_qws_set(&cmd->lrh16bc,
								  pktlen_qws);
				hfi2_dms_impl_pbc_length_dws_set(&cmd->pbc,
								 pbc_pktlen_dws);
			}

			*cursor.cur_desc = cursor.tail_desc;
			cursor.cur_desc += 1;

			in_tid_bytes += bytes;
			region_rem -= bytes;
			op_rem -= bytes;
			k += 1;

			if (region_rem == 0) {
				tid += 1;
				in_tid_bytes = 0;
				region_rem = HFI2_DMS_MAX_PAYLOAD_SIZE;
			}
		}
	}

	/* Finalizing rewrites the last descriptor: there must be one. */
	if (WARN_ON_ONCE(!k))
		goto err_put_ahg;

	current_fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = cursor.cur_desc,
	};
	ndesc_total = _sdma_desc_stack_finalize(dms, current_fill_state, &padding_needed);
	if (unlikely(ndesc_total + padding_needed > dms->num_descs)) {
		WARN_ON_ONCE(1);
		goto err_put_ahg_fatal;
	}
	/*
	 * A ring holds at most descq_cnt - 1 descriptors in flight (every
	 * engine shares the sdma_descq_cnt setting), so a submission larger
	 * than that is never accepted and would stay parked, blocking the
	 * engine's waitlist, until the stale timeout cancels the transfer.
	 * Send such a multi-chunk request chunk by chunk instead; a single
	 * chunk that large (only with a very small sdma_descq_cnt) fails.
	 */
	if (unlikely(ndesc_total + padding_needed >
		     dms->sdma_engines[0]->descq_cnt - 1u)) {
		if (nchunks > 1)
			goto err_put_ahg_fatal;
		hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free,
					   &ahg_set->dlist);
		dms->counters.sdma_desc_overflow++;
		return -EMSGSIZE;
	}

	sdma = _sdma_engine_acquire(dms, engine_idx, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	for (u32 i = 0; i < k; ++i)
		_sdma_header_pbc_test(dms, ahg_set->headers[i].kvaddr);

	_sdma_engine_write_desc_stack(dms, engine_idx, sdma, ndesc_total, padding_needed, ahg_set);

	/*
	 * Count the k DATA packets once the engine has them: a build refused
	 * for room is retried or rebuilt per chunk and counted then.
	 */
	if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
		dms->counters.tx_sent[msg_type] += k;

	end = dms_rdtsc();
	dms->counters.tid_send += end - start;

	return 0;

err_put_ahg:
	hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free, &ahg_set->dlist);
	return -EINVAL;

err_put_ahg_fatal:
	hfi2_dms_impl_dlist_append(&dms->ahg_headers[ahg_set->port_idx].free, &ahg_set->dlist);
	/*
	 * A multi-chunk request too large for one submission is not an error:
	 * the caller sends it chunk by chunk instead, as before batching.
	 */
	if (nchunks > 1)
		return -E2BIG;
	/*
	 * A single chunk deterministically needs more descriptors or AHG
	 * headers than one submission provides; retrying the identical op
	 * cannot help, so signal a permanent failure (-EMSGSIZE) that
	 * _sdma_inject escalates to a tracker cancel rather than parking on
	 * the SDMA waitlist.
	 */
	WARN_ON_ONCE(1);
	dms->counters.sdma_desc_overflow++;
	return -EMSGSIZE;
}

int _inject_cmd_sdma(struct hfi2_dms *dms, union hfi2_dms_proto_cmd * cmd, enum hfi2_dms_sdma_engine_idx const engine_idx)
{
	u32 const count = 1;
	struct hfi2_dms_ahg_header_set *ahg_set;
	struct hfi2_dms_impl_fill_state current_fill_state;
	u64 ndesc_total, padding_needed;
	struct sdma_engine *sdma;
	struct sdma_desc *desc;
	struct hfi2_dms_mem_coh *ahg_header;
	u8 port_idx = _pbc_port_idx_get(cmd->pbc);
	struct send_context *sc = dms->port_sctxts[port_idx];

	// sdma still performs send context checks on egress
	if (!_sctxt_is_active(sc))
		return -ECOMM;

	ahg_set = hfi2_dms_impl_ahg_header_set_get(dms, port_idx);
	if (DMS_WARN_ON(ahg_set == NULL)) {
		return -ENOMEM;
	}

	current_fill_state = (struct hfi2_dms_impl_fill_state){
		.cur_desc = &dms->desc_stack[0],
	};

	for (u32 i = 0; i < count; ++i) {
		ahg_header = &ahg_set->headers[i];
		memcpy(ahg_header->kvaddr, &cmd[i], sizeof(union hfi2_dms_proto_cmd));

		desc = current_fill_state.cur_desc;
		*desc = (struct sdma_desc){0};
		u32 const nbytes = (hfi2_dms_impl_pbc_length_dws_get(cmd[i].pbc) << 2) - sizeof(u64);
		_sdma_qw_set_byte_count(&desc->qw[0], nbytes);
		_sdma_qw_set_first_desc(&desc->qw[0]);
		_sdma_qw_set_header_mode(&desc->qw[0], SDMA_AHG_NO_AHG);
		_sdma_qw_set_phy_addr(&desc->qw[0], ahg_header->phys_addr);
		current_fill_state.cur_desc += 1;

		desc = current_fill_state.cur_desc;
		*desc = dms->tail_desc_template;
		if (dms->chip_type == CHIP_CYR)
			cyr_sdma_qw_set_send_ctxt_extension(&desc->qw[0], sc->hw_context);
		current_fill_state.cur_desc += 1;
	}

	ndesc_total = _sdma_desc_stack_finalize(dms, current_fill_state, &padding_needed);

	sdma = _sdma_engine_acquire(dms, engine_idx, ndesc_total + padding_needed);
	if (!sdma) {
		dms->counters.sdma_no_engine_fallback++;
		dd_dev_dbg(dms->dd, "dms: No sdma engine available. Tracker will be put back on the todo list\n");
		hfi2_dms_impl_dlist_append(
			&dms->ahg_headers[ahg_set->port_idx].free,
			&ahg_set->dlist);
		return -EAGAIN;
	}

	_sdma_header_pbc_test(dms, ahg_set->headers[0].kvaddr);
	_sdma_engine_write_desc_stack(dms, engine_idx, sdma, ndesc_total, padding_needed, ahg_set);

	return 0;
}

int hfi2_dms_impl_work_item_block_alloc(struct hfi2_dms *dms)
{
	size_t sz = sizeof(struct hfi2_dms_dlist_element) + 100 * sizeof(struct hfi2_dms_work_item);
	struct hfi2_dms_dlist_element *block;
	struct hfi2_dms_dlist_element *item;
	size_t i;

	block = (struct hfi2_dms_dlist_element *)kzalloc_node(sz, GFP_KERNEL, dms->numa_node);
	if (block == NULL) {
		return -ENOMEM;
	}

	hfi2_dms_impl_dlist_push(&dms->work_items.blocklist, block);

	item = block + 1;
	for (i = 0; i < 100; ++i) {
		hfi2_dms_impl_dlist_push(&dms->work_items.free, item);
		item = (struct hfi2_dms_dlist_element *)((u64)item + sizeof(struct hfi2_dms_work_item));
	}

	return 0;
}

int hfi2_dms_impl_tracker_block_alloc(struct hfi2_dms *dms)
{
	static size_t const stride = ALIGN(sizeof(union hfi2_dms_tracker), HFI2_DMS_TRACKER_ALIGN);
	static size_t const sz = sizeof(struct hfi2_dms_dlist_element)
				 + (HFI2_DMS_TRACKER_ALIGN - 1)
				 + HFI2_DMS_TRACKER_BLOCK_SIZE * stride;
	struct hfi2_dms_dlist_element *block;
	union hfi2_dms_tracker *tracker;
	size_t i;

	block = (struct hfi2_dms_dlist_element *) kzalloc_node(sz, GFP_KERNEL, dms->numa_node);
	if (block == NULL) {
		return -ENOMEM;
	}

	hfi2_dms_impl_dlist_push(&dms->trackers.blocklist, block);

	tracker = (union hfi2_dms_tracker *)
		  ALIGN((uintptr_t)(block + 1), HFI2_DMS_TRACKER_ALIGN);
	for (i = 0; i < HFI2_DMS_TRACKER_BLOCK_SIZE; ++i) {
		hfi2_dms_impl_dlist_push(&dms->trackers.free, &tracker->hdr.dlist);
		tracker = (union hfi2_dms_tracker *)((u64)tracker + stride);
	}

	return 0;
}

/*
 * AHG slot size in bytes.  Each AHG backing slot must be large enough to
 * hold the largest eager header (WRITE_START_EAGER: PBC + 120-byte header =
 * 128 bytes, exactly one slot).
 * This constant must be >= max(_msgtype_pio_payload_offset[]), where each
 * offset is measured from the start of the packet buffer and therefore
 * already accounts for the leading PBC.
 */
#define HFI2_DMS_AHG_SLOT_SIZE 128

static_assert(sizeof(union hfi2_dms_proto_cmd_data) <= HFI2_DMS_AHG_SLOT_SIZE,
	      "the DATA command header must fit an AHG header slot");

static int hfi2_dms_impl_ahg_header_block_alloc(struct hfi2_dms *dms, u8 port_idx)
{
	u64 const SLOTS_PER_BLOCK =
		HFI2_DMS_AHG_HEADER_BLOCK_SIZE * HFI2_DMS_AHG_HEADERS_PER_SET;
	u64 const AHG_BACKING_ALLOC_SIZE =
		SLOTS_PER_BLOCK * HFI2_DMS_AHG_SLOT_SIZE;
	u64 const SDMA_HEADER_SIZE = HFI2_DMS_AHG_SLOT_SIZE;
	struct hfi2_dms_dlist_element *block;
	struct hfi2_dms_ahg_header_block *ahg_block;
	u64 i, j, k;
	struct hfi2_dms_mem_coh ahg_memory;
	struct hfi2_dms_ahg_header_set *header_set;
	union hfi2_dms_proto_cmd_data *data_template;
	union hfi2_dms_proto_cmd_data *cmd;
	u64 cmd_data_qw_size;

	block = kzalloc_node(sizeof(struct hfi2_dms_ahg_header_block),
			     GFP_KERNEL, dms->numa_node);
	if (block == NULL) {
		return -ENOMEM;
	}
	ahg_block = (struct hfi2_dms_ahg_header_block *) block;
	ahg_block->backing_mem.kvaddr = dma_alloc_coherent(&dms->dd->pcidev->dev,
						    AHG_BACKING_ALLOC_SIZE,
						    &ahg_block->backing_mem.phys_addr,
						    GFP_KERNEL);
	ahg_block->backing_mem.len = AHG_BACKING_ALLOC_SIZE;
	if (!ahg_block->backing_mem.kvaddr) {
		kfree(block);
		return -ENOMEM;
	}
	hfi2_dms_impl_dlist_push(&dms->ahg_headers[port_idx].blocklist, block);

	/* Uses per port allocation pool*/
	data_template =
		(union hfi2_dms_proto_cmd_data *)&dms
			->protocol_cmd_templates[port_idx]
						[HFI2_DMS_MSG_TYPE_DATA];
	cmd_data_qw_size = sizeof(union hfi2_dms_proto_cmd_data) >> 3;

	for (i = 0; i < HFI2_DMS_AHG_HEADER_BLOCK_SIZE; ++i) {
		header_set = &ahg_block->header_sets[i];
		for (j = 0; j < HFI2_DMS_AHG_HEADERS_PER_SET; ++j) {
			u64 slot = (i * HFI2_DMS_AHG_HEADERS_PER_SET + j) *
				   SDMA_HEADER_SIZE;

			ahg_memory = (struct hfi2_dms_mem_coh){
				.kvaddr = ahg_block->backing_mem.kvaddr + slot,
				.phys_addr = ahg_block->backing_mem.phys_addr + slot,
				.len = SDMA_HEADER_SIZE,
			};
			header_set->headers[j] = ahg_memory;
			header_set->port_idx = port_idx;
			cmd = (union hfi2_dms_proto_cmd_data *)header_set
				      ->headers[j]
				      .kvaddr;
			for (k = 0; k < cmd_data_qw_size; ++k)
				cmd->qws[k] = data_template->qws[k];
		}
		hfi2_dms_impl_dlist_push(&dms->ahg_headers[port_idx].free,
					 &header_set->dlist);
	}

	return 0;
}

/* Set up the (empty) page pool and seed it with one block. */
static int _page_pool_init(struct hfi2_dms *dms)
{
	INIT_LIST_HEAD(&dms->dms_pages.free);
	INIT_LIST_HEAD(&dms->dms_pages.blocklist);
	dms->dms_pages.total_pages = 0;

	return _page_block_alloc(dms, true);
}

/*
 * Allocate one block, carve it into 4 KiB pages, splice them onto the free
 * list.  Called at init and again from hfi2_dms_page_get() to grow.
 */
static int _page_block_alloc(struct hfi2_dms *dms, bool setup)
{
	u64 const BACKING_ALLOC_SIZE =
		(u64)HFI2_DMS_PAGE_POOL_BLOCK_PAGES * PAGE_SIZE;
	struct hfi2_dms_page_block *block;
	u64 i;

	if (dms->dms_pages.total_pages + HFI2_DMS_PAGE_POOL_BLOCK_PAGES >
	    HFI2_DMS_PAGE_POOL_MAX_PAGES) {
		if (setup)
			dms->allocation_stats.page_block_setup_failures++;
		else
			dms->allocation_stats.page_block_growth_failures++;
		return -ENOSPC;
	}

	block = kzalloc_node(sizeof(*block), GFP_KERNEL, dms->numa_node);
	if (!block) {
		if (setup)
			dms->allocation_stats.page_block_setup_failures++;
		else
			dms->allocation_stats.page_block_growth_failures++;
		return -ENOMEM;
	}

	block->backing_mem.pg = alloc_pages_node(dms->numa_node,
						 GFP_KERNEL | __GFP_ZERO,
						 get_order(BACKING_ALLOC_SIZE));
	if (!block->backing_mem.pg) {
		kfree(block);
		if (setup)
			dms->allocation_stats.page_block_setup_failures++;
		else
			dms->allocation_stats.page_block_growth_failures++;
		return -ENOMEM;
	}
	block->backing_mem.kvaddr = page_address(block->backing_mem.pg);
	block->backing_mem.phys_addr =
		dma_map_single(&dms->dd->pcidev->dev, block->backing_mem.kvaddr,
			       BACKING_ALLOC_SIZE, DMA_TO_DEVICE);
	if (dma_mapping_error(&dms->dd->pcidev->dev, block->backing_mem.phys_addr)) {
		__free_pages(block->backing_mem.pg, get_order(BACKING_ALLOC_SIZE));
		kfree(block);
		if (setup)
			dms->allocation_stats.page_block_setup_failures++;
		else
			dms->allocation_stats.page_block_growth_failures++;
		return -ENOMEM;
	}
	block->backing_mem.len = BACKING_ALLOC_SIZE;
	list_add(&block->link, &dms->dms_pages.blocklist);

	for (i = 0; i < HFI2_DMS_PAGE_POOL_BLOCK_PAGES; ++i) {
		u64 slot = i * PAGE_SIZE;
		struct hfi2_dms_page *page = &block->pages[i];

		page->mem = (struct hfi2_dms_mem_coh){
			.kvaddr = block->backing_mem.kvaddr + slot,
			.phys_addr = block->backing_mem.phys_addr + slot,
			.len = PAGE_SIZE,
			.pg = NULL,
		};
		page->owner = dms;
		list_add(&page->link, &dms->dms_pages.free);
	}

	dms->dms_pages.total_pages += HFI2_DMS_PAGE_POOL_BLOCK_PAGES;
	if (setup)
		dms->allocation_stats.page_block_setup_allocs++;
	else
		dms->allocation_stats.page_block_growth_allocs++;

	return 0;
}

static void _page_block_free(struct hfi2_dms *dms)
{
	struct hfi2_dms_page_block *block, *tmp;

	/*
	 * Guard against a not-yet-initialized blocklist.  On the hfi2_dms_init()
	 * bail path this can be reached before _page_pool_init() has
	 * INIT_LIST_HEAD'd dms_pages, and a zeroed struct list_head (NULL
	 * next/prev) is _not_ an empty list.  Re-init both heads here so every
	 * caller -- init bail and uninit alike -- sees a valid empty list, and
	 * the invariant lives in one place rather than open-coded at the call site.
	 * This is single-threaded teardown, so a plain pointer check suffices;
	 * an uninitialized head has next == NULL, an initialized one never does.
	 */
	if (!dms->dms_pages.blocklist.next) {
		INIT_LIST_HEAD(&dms->dms_pages.free);
		INIT_LIST_HEAD(&dms->dms_pages.blocklist);
	}

	list_for_each_entry_safe(block, tmp, &dms->dms_pages.blocklist, link) {
		list_del(&block->link);
		if (!DMS_WARN_ON(block->backing_mem.kvaddr == NULL)) {
			dma_unmap_single(&dms->dd->pcidev->dev,
					 block->backing_mem.phys_addr,
					 block->backing_mem.len, DMA_TO_DEVICE);
			__free_pages(block->backing_mem.pg,
				     get_order(block->backing_mem.len));
			block->backing_mem.kvaddr = NULL;
			block->backing_mem.phys_addr = 0;
			block->backing_mem.len = 0;
			block->backing_mem.pg = NULL;
		}
		kfree(block);
	}

	INIT_LIST_HEAD(&dms->dms_pages.free);
	dms->dms_pages.total_pages = 0;
}

static void _tidset_bounce_backing_uninit(struct hfi2_dms *dms)
{
	u32 tid_set;
	int i;

	if (!dms->read_request_bounce)
		return;

	for (tid_set = 0; tid_set < HFI2_DMS_TID_SET_IDX_COUNT; ++tid_set) {
		struct hfi2_dms_tidset_bounce_backing *b =
			&dms->read_request_bounce[tid_set];

		for (i = HFI2_DMS_TIDSET_BOUNCE_PAGE_COUNT - 1; i >= 0; --i) {
			if (b->bounce_dma[i]) {
				dma_unmap_page(&dms->dd->pcidev->dev,
					       b->bounce_dma[i], PAGE_SIZE,
					       DMA_FROM_DEVICE);
				b->bounce_dma[i] = 0;
			}
			if (b->bounce_page[i]) {
				__free_page(b->bounce_page[i]);
				b->bounce_page[i] = NULL;
			}
		}
	}

	kfree(dms->read_request_bounce);
	dms->read_request_bounce = NULL;
}

static int _tidset_bounce_backing_init(struct hfi2_dms *dms)
{
	u32 tid_set;
	int i;

	dms->read_request_bounce =
		kcalloc_node(HFI2_DMS_TID_SET_IDX_COUNT,
			     sizeof(*dms->read_request_bounce),
			     GFP_KERNEL, dms->numa_node);
	if (!dms->read_request_bounce)
		return -ENOMEM;

	for (tid_set = 0; tid_set < HFI2_DMS_TID_SET_IDX_COUNT; ++tid_set) {
		struct hfi2_dms_tidset_bounce_backing *b =
			&dms->read_request_bounce[tid_set];

		for (i = 0; i < HFI2_DMS_TIDSET_BOUNCE_PAGE_COUNT; ++i) {
			b->bounce_page[i] = alloc_pages_node(dms->numa_node,
							     GFP_KERNEL | __GFP_ZERO,
							     0);
			if (!b->bounce_page[i])
				goto fail;

			b->bounce_dma[i] =
				dma_map_page(&dms->dd->pcidev->dev,
					     b->bounce_page[i], 0, PAGE_SIZE,
					     DMA_FROM_DEVICE);
			if (dma_mapping_error(&dms->dd->pcidev->dev,
					      b->bounce_dma[i])) {
				b->bounce_dma[i] = 0;
				goto fail;
			}
		}
	}

	return 0;

fail:
	_tidset_bounce_backing_uninit(dms);
	return -ENOMEM;
}

/* Program the tidset's bounce TID pair (its last two RcvArray entries). */
static void _tidset_bounce_pair_set(struct hfi2_dms *dms, u32 tid_set,
				    dma_addr_t lower)
{
	u64 const flags = HFI2_DMS_TID_BUF_SIZE_SMASK | BIT(63);
	u32 const first = (tid_set * HFI2_DMS_TID_SET_SIZE +
			   HFI2_DMS_TID_SET_SIZE - 1) * 2;
	u8 __iomem *base = dms->dd->bar_maps[ctxt_bar_idx(dms->rcd_data->ctxt)].rcvarray_wc +
			   rcvarray_offset(dms->rcd_data->ctxt, first, PT_EXPECTED);

	writeq((u64)(lower >> HFI2_DMS_TID_PAGE_SHIFT) | flags, base);
	writeq((u64)(dms->zero_page.phys_addr >> HFI2_DMS_TID_PAGE_SHIFT) | flags,
	       base + sizeof(u64));
	flush_wc();
}

/* Map bounce page 0 at the tidset's bounce TID pair so its edges can land. */
static void _tidset_bounce_attach(struct hfi2_dms *dms, u32 tid_set)
{
	_tidset_bounce_pair_set(dms, tid_set,
				dms->read_request_bounce[tid_set].bounce_dma[0]);
}

/*
 * Point the tidset's bounce TID pair back at the inert zero page, so no
 * further DATA can land in the bounce page.
 */
static void _tidset_bounce_detach(struct hfi2_dms *dms, u32 tid_set)
{
	_tidset_bounce_pair_set(dms, tid_set, dms->zero_page.phys_addr);
}

/*
 * Copy a completed request's sub-quadword edges from the tidset's bounce page
 * to the destination. Called once every quadword of the request has landed;
 * detaches the bounce TID pair first so the bytes being copied cannot change
 * underneath, and disarms the scatter. Returns 0, or a negative errno if the
 * scatter is not armed for the current request generation or a destination
 * copy fails.
 */
static int _tidset_bounce_scatter(struct hfi2_dms *dms, u32 tid_set,
				  struct hfi2_dms_rx_tracker *rx_tracker)
{
	struct hfi2_dms_read_request_chunks *rc =
		&dms->read_request_chunks[tid_set];
	struct hfi2_dms_tidset_bounce_backing *b =
		&dms->read_request_bounce[tid_set];
	struct hfi2_dms_page_provider const *pp = &rx_tracker->page_provider;
	struct device *dev = &dms->dd->pcidev->dev;
	u8 const *bounce = page_address(b->bounce_page[0]);
	int ret = 0;

	bool const armed = rc->scatter_valid;

	rc->scatter_valid = false;
	_tidset_bounce_detach(dms, tid_set);

	if (unlikely(!armed ||
		     rc->scatter_generation != dms->read_requests[tid_set].generation ||
		     rc->scatter_count > ARRAY_SIZE(rc->scatter)))
		return -EIO;

	dma_sync_single_for_cpu(dev, b->bounce_dma[0], PAGE_SIZE, DMA_FROM_DEVICE);
	for (u8 i = 0; i < rc->scatter_count; i++) {
		struct hfi2_dms_bounce_scatter const *s = &rc->scatter[i];

		ret = (*pp->memcpy)(pp, s->dest_offset, s->length,
				    (void *)(bounce + s->bounce_offset), false);
		if (ret)
			break;
	}
	dma_sync_single_for_device(dev, b->bounce_dma[0], PAGE_SIZE,
				   DMA_FROM_DEVICE);
	return ret;
}

struct hfi2_dms_page *hfi2_dms_page_get(struct hfi2_dms *dms)
{
	struct hfi2_dms_page *page;

	if (WARN_ON_ONCE(!dms))
		return NULL;

	if (list_empty(&dms->dms_pages.free)) {
		int ret = _page_block_alloc(dms, false);

		if (ret) {
			dd_dev_dbg_ratelimited(dms->dd,
					       "dms: page pool exhausted, grow failed (%d, total_pages=%u)\n",
					       ret, dms->dms_pages.total_pages);
			return NULL;
		}
	}

	page = list_first_entry(&dms->dms_pages.free, struct hfi2_dms_page, link);
	list_del(&page->link);
	return page;
}

int hfi2_dms_page_pool_warm(struct hfi2_dms *dms, u32 pages)
{
	int ret;

	if (!dms || !dms->dms_pages.free.next)
		return -EINVAL;

	while (dms->dms_pages.total_pages < pages) {
		ret = _page_block_alloc(dms, true);
		if (ret)
			return ret;
	}

	return 0;
}

struct hfi2_dms_page *hfi2_dms_page_try_get(struct hfi2_dms *dms)
{
	struct hfi2_dms_page *page;

	if (WARN_ON_ONCE(!dms) || list_empty(&dms->dms_pages.free))
		return NULL;

	page = list_first_entry(&dms->dms_pages.free, struct hfi2_dms_page, link);
	list_del(&page->link);
	return page;
}

void hfi2_dms_page_put(struct hfi2_dms *dms, struct hfi2_dms_page *page)
{
	if (WARN_ON_ONCE(!dms || !page))
		return;

	list_add(&page->link, &dms->dms_pages.free);
}

void hfi2_dms_page_sync_for_device(struct hfi2_dms *dms,
				   struct hfi2_dms_page *page,
				   u32 offset, size_t bytes)
{
	dma_sync_single_for_device(&dms->dd->pcidev->dev,
				   page->mem.phys_addr + offset,
				   bytes, DMA_TO_DEVICE);
}

void hfi2_dms_impl_work_item_block_free(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *block;

	DMS_BUG_ON(dms == NULL);
	DMS_WARN_ON(dms->work_items.active.head != NULL || dms->work_items.active.tail != NULL);

	block = hfi2_dms_impl_dlist_pop(&dms->work_items.blocklist);
	while (block) {
		kfree(block);
		block = hfi2_dms_impl_dlist_pop(&dms->work_items.blocklist);
	}

	DMS_BUG_ON(dms->work_items.blocklist.head != NULL);
	DMS_BUG_ON(dms->work_items.blocklist.tail != NULL);

	dms->work_items.free.head = NULL;
	dms->work_items.free.tail = NULL;
}

void hfi2_dms_impl_tracker_block_free(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *block;

	DMS_BUG_ON(dms == NULL);

	block = hfi2_dms_impl_dlist_pop(&dms->trackers.blocklist);
	while (block) {
		kfree(block);
		block = hfi2_dms_impl_dlist_pop(&dms->trackers.blocklist);
	}

	DMS_BUG_ON(dms->trackers.blocklist.head != NULL);
	DMS_BUG_ON(dms->trackers.blocklist.tail != NULL);

	dms->trackers.free.head = NULL;
	dms->trackers.free.tail = NULL;
}

void hfi2_dms_impl_ahg_header_block_free(struct hfi2_dms *dms)
{
	struct hfi2_dms_ahg_header_block *block;
	u64 i;

	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		while (dms->ahg_headers[i].blocklist.head != NULL) {
			block = (struct hfi2_dms_ahg_header_block *)
				hfi2_dms_impl_dlist_pop(
					&dms->ahg_headers[i].blocklist);
			if (!DMS_WARN_ON(block->backing_mem.kvaddr == NULL)) {
				dma_free_coherent(&dms->dd->pcidev->dev,
						  block->backing_mem.len,
						  block->backing_mem.kvaddr,
						  block->backing_mem.phys_addr);
				block->backing_mem.kvaddr = NULL;
				block->backing_mem.phys_addr = 0;
				block->backing_mem.len = 0;
			}
			kfree(block);
		}
	}
}

struct hfi2_dms_work_item *hfi2_dms_impl_work_item_new(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *item;

	item = hfi2_dms_impl_dlist_pop(&dms->work_items.free);
	if (item == NULL) {
		hfi2_dms_impl_work_item_block_alloc(dms);
		item = hfi2_dms_impl_dlist_pop(&dms->work_items.free);
	}
	if (!item) {
		return NULL;
	}

	/* add this item to the 'active' list */
	hfi2_dms_impl_dlist_append(&dms->work_items.active, item);

	return (struct hfi2_dms_work_item *)item;
}

void hfi2_dms_impl_work_item_free(struct hfi2_dms *dms, struct hfi2_dms_work_item *item)
{
	hfi2_dms_impl_dlist_remove(&dms->work_items.active, &item->dlist);
	hfi2_dms_impl_dlist_push(&dms->work_items.free, &item->dlist);
}

union hfi2_dms_tracker *hfi2_dms_impl_tracker_new(struct hfi2_dms *dms, u8 port_idx,
		hfi2_dms_rift_key_t remote_rift_key, u32 remote_lid, u64 order_key, enum hfi2_dms_xfer_type type,
		enum hfi2_dms_xfer_op op)
{
	int ret;
	struct hfi2_dms_dlist_element *dlist_element;
	union hfi2_dms_tracker *tracker;

	DMS_BUG_ON(!dms);

	dlist_element = hfi2_dms_impl_dlist_pop(&dms->trackers.free);
	if (dlist_element == NULL) {
		ret = hfi2_dms_impl_tracker_block_alloc(dms);
		if (ret < 0) {
			return NULL;
		}
		dlist_element = hfi2_dms_impl_dlist_pop(&dms->trackers.free);
		DMS_BUG_ON(!dlist_element);
	}
	tracker = container_of(dlist_element, union hfi2_dms_tracker, hdr.dlist);

#if HFI2_DMS_COUNTERS_ENABLE
	memset(&tracker->hdr.perf, 0, sizeof(tracker->hdr.perf));
	tracker->hdr.perf.lifetime[0] = ktime_get();
#endif
	/* deliberately do not clear the generation counter */
	tracker->hdr.local_rift_key = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET);
	tracker->hdr.remote_rift_key = remote_rift_key;
	tracker->hdr.remote_lid = remote_lid;
	tracker->hdr.order_key = order_key;
	tracker->hdr.type = type;
	tracker->hdr.op = op;
	tracker->hdr.port_idx = port_idx;

	if (type == HFI2_DMS_XFER_TYPE_TARGET) {
		tracker->hdr.side = (op == HFI2_DMS_XFER_OP_WRITE) ? HFI2_DMS_XFER_SIDE_RX : HFI2_DMS_XFER_SIDE_TX;
	} else if (type == HFI2_DMS_XFER_TYPE_INITIATOR) {
		tracker->hdr.side = (op == HFI2_DMS_XFER_OP_WRITE) ? HFI2_DMS_XFER_SIDE_TX : HFI2_DMS_XFER_SIDE_RX;
	} else { // HFI2_DMS_XFER_TYPE_NONE
		tracker->hdr.side = HFI2_DMS_XFER_SIDE_NONE;
	}

	_tracker_health_state_set(dms, tracker, HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT);
	tracker->hdr.local_rift_number = 0;
	tracker->hdr.byte_odometer = 0;
	tracker->hdr.remote_status.last_known_packet_progress = 0;
	tracker->hdr.remote_status.last_known_rift_tracker_ticket = 0;
	tracker->hdr.remote_status.last_known_rift_global_assigned = 0;
	tracker->hdr.remote_status.last_known_tidset_progress = 0;

	tracker->hdr.status_req_count = 0;
	tracker->hdr.status_rsp_count = 0;
	tracker->hdr.rnr_retry_count = 0;
	tracker->hdr.rnr_pending = false;
	tracker->hdr.birth_time = dms->now;
	tracker->hdr.last_progress_time = dms->now;
	tracker->hdr.last_progress_odometer = 0;

	tracker->hdr.access_inflight.prev = NULL;
	tracker->hdr.access_inflight.next = NULL;

	tracker->hdr.parent_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	tracker->hdr.child_handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	tracker->hdr.entropy = 0;
	tracker->hdr.park_on_parent_error = false;
	tracker->hdr.fast_fail = false;
	tracker->hdr.stale_backoff_shift = 0;
	tracker->hdr.chain_child_released = false;
	tracker->hdr.chain_signalled = false;
	tracker->hdr.chain_pio_released = false;
	/* Default park gate per op; _tracker_bind may upgrade reads. */
	tracker->hdr.chain_park_at = (op == HFI2_DMS_XFER_OP_WRITE)
		? HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START
		: HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START;

	return tracker;
}

static struct hfi2_dms_sdma_tracker *_sdma_tracker_new(struct hfi2_dms *dms, u8 port_idx, hfi2_dms_sdma_inject_fn inject,
		struct hfi2_dms_sdma_info const *info, u64 xfer_bytes)
{
	hfi2_dms_rift_key_t const no_rift = _rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET);
	union hfi2_dms_tracker *tracker =
		hfi2_dms_impl_tracker_new(dms, port_idx, no_rift, 0, 0, HFI2_DMS_XFER_TYPE_NONE, HFI2_DMS_XFER_OP_NONE);
	if (!tracker) return NULL;

	struct hfi2_dms_sdma_tracker *waiter = &tracker->sdma;
	waiter->inject = inject;
	waiter->info = *info;
	waiter->xfer_bytes = xfer_bytes;
	waiter->req = NULL;

	return waiter;
}

static struct hfi2_dms_tx_tracker *hfi2_dms_impl_tx_tracker_new(struct hfi2_dms *dms, u8 port_idx, u32 size,
		u64 byte_offset_from_first_page, u32 remote_lid, hfi2_dms_rift_key_t remote_rift_key, u64 order_key,
		enum hfi2_dms_xfer_type type, enum hfi2_dms_xfer_op op)
{
	struct hfi2_dms_tx_tracker * tx_tracker;

	DMS_BUG_ON(!dms);

	tx_tracker = (struct hfi2_dms_tx_tracker *) hfi2_dms_impl_tracker_new(dms, port_idx,
			remote_rift_key, remote_lid, order_key, type, op);
	if (!tx_tracker) {
		return NULL;
	}

	tx_tracker->total_payload = size;
	tx_tracker->payload_remaining = size;
	tx_tracker->xfer_start_byte_offset = byte_offset_from_first_page;

	return tx_tracker;
}

struct hfi2_dms_tx_tracker *hfi2_dms_impl_tx_tracker_write_new(struct hfi2_dms *dms,
		u8 port_idx, u32 size, u64 byte_offset_from_first_page,
		u32 remote_lid,
		struct hfi2_dms_page_provider page_provider, u64 mr_offset,
		u16 flags, u64 submit_flags, u64 imm_data,
		struct hfi2_dms_completion const *completion,
		union hfi2_dms_key rx_dms_key, u64 rx_offset, u64 order_key)
{
	struct hfi2_dms_tx_tracker * tx_tracker;

	if (WARN_ON_ONCE(!dms))
		return NULL;
	if (WARN_ON_ONCE(!completion))
		return NULL;
	if (WARN_ON_ONCE(!completion->fn))
		return NULL;
	if (WARN_ON_ONCE(!page_provider.pin_range))
		return NULL;
	if (WARN_ON_ONCE(!page_provider.provider_ctx))
		return NULL;

	tx_tracker = hfi2_dms_impl_tx_tracker_new(dms, port_idx, size, byte_offset_from_first_page, remote_lid,
			_rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET), order_key, HFI2_DMS_XFER_TYPE_INITIATOR, HFI2_DMS_XFER_OP_WRITE);
	if (tx_tracker) {
		tx_tracker->op = HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE;
		tx_tracker->write.page_provider = page_provider;
		tx_tracker->write.completion = *completion;
		tx_tracker->write.dms_key = rx_dms_key;
		tx_tracker->write.rx_offset = rx_offset;
		tx_tracker->hdr.park_on_parent_error =
			!!(submit_flags & HFI2_DMS_SUBMIT_PARK_ON_PARENT_ERROR);
		tx_tracker->hdr.fast_fail =
			!!(submit_flags & HFI2_DMS_SUBMIT_FAST_FAIL);
		tx_tracker->hdr.stale_backoff_shift =
			hfi2_dms_submit_flags_get_stale_shift(submit_flags);
		/* Carry the policy on the wire so every WRITE_START inject site emits it. */
		tx_tracker->write.flags =
			hfi2_dms_start_flags_set_policy(flags,
							tx_tracker->hdr.fast_fail,
						     tx_tracker->hdr.stale_backoff_shift);
		tx_tracker->write.imm_data = imm_data;
		tx_tracker->write.chain_inherit_entropy = 0;
		tx_tracker->write.chain_inherit_valid = false;
		tx_tracker->write.unaligned = false;
		tx_tracker->write.replayed = false;
		tx_tracker->write.is_single_engine =
			!_tracker_is_multi_engine(tx_tracker->total_payload);
	}

	return tx_tracker;
}

static struct hfi2_dms_rx_tracker *hfi2_dms_impl_rx_tracker_new(struct hfi2_dms *dms, u8 port_idx, u32 size, u32 remote_lid,
		u64 rbuf_offset, u64 const order_key,
		enum hfi2_dms_xfer_type type, enum hfi2_dms_xfer_op op)
{
	struct hfi2_dms_rx_tracker * rx_tracker;

	/* Tidset indices must fit in the u64 XOR accumulator's value range; <64
	 * guarantees a valid read_requests[] index.
	 */
	BUILD_BUG_ON(HFI2_DMS_TID_SET_IDX_COUNT > 64);

	DMS_BUG_ON(!dms);

	rx_tracker = (struct hfi2_dms_rx_tracker *) hfi2_dms_impl_tracker_new(dms, port_idx,
			_rift_key_create_err(HFI2_DMS_RIFT_ERR_KEY_NOT_SET), remote_lid, order_key, type, op);
	if (!rx_tracker) {
		return NULL;
	}

	// initialize tracker state
	rx_tracker->total_payload = size;
	rx_tracker->payload_remaining = size;
	rx_tracker->tidsets_in_use = 0;
	rx_tracker->tidsets_inflight_bitmap = 0;
	rx_tracker->chain_inherit_entropy = 0;
	rx_tracker->chain_inherit_valid = false;
	rx_tracker->sbuf_cursor = 0;
	rx_tracker->rbuf_start_offset = rbuf_offset;
	rx_tracker->sbuf_start_offset = 0;

	return rx_tracker;
}

struct hfi2_dms_rx_tracker *hfi2_dms_impl_rx_tracker_read_new(struct hfi2_dms *dms,
							   u8 port_idx, u32 size,
							   u64 starting_sbuf_offset,
							   union hfi2_dms_key dms_key,
							   u32 remote_lid,
							   struct hfi2_dms_page_provider page_provider,
							   u64 rbuf_offset, u16 flags,
							   u64 submit_flags,
							   u64 imm_data,
							   struct hfi2_dms_completion const *completion,
							   u64 const order_key)
{
	struct hfi2_dms_rx_tracker * rx_tracker;

	if (WARN_ON_ONCE(dms == NULL))
		return NULL;
	if (WARN_ON_ONCE(!page_provider.pin_range))
		return NULL;
	if (WARN_ON_ONCE(!page_provider.provider_ctx))
		return NULL;

	rx_tracker = hfi2_dms_impl_rx_tracker_new(dms, port_idx, size,
			remote_lid, rbuf_offset, order_key,
			HFI2_DMS_XFER_TYPE_INITIATOR,
			HFI2_DMS_XFER_OP_READ);
	if (!rx_tracker)
		return NULL;
	rx_tracker->page_provider = page_provider;
	rx_tracker->sbuf_start_offset = starting_sbuf_offset;

	rx_tracker->op = HFI2_DMS_RX_TRACKER_OP_RDMA_READ;
	rx_tracker->read.dms_key = dms_key;
	rx_tracker->read.flags = flags;
	rx_tracker->read.imm_data = imm_data;
	rx_tracker->hdr.park_on_parent_error =
		!!(submit_flags & HFI2_DMS_SUBMIT_PARK_ON_PARENT_ERROR);
	rx_tracker->hdr.fast_fail =
		!!(submit_flags & HFI2_DMS_SUBMIT_FAST_FAIL);
	rx_tracker->hdr.stale_backoff_shift =
		hfi2_dms_submit_flags_get_stale_shift(submit_flags);

	rx_tracker->read.tidset.id = 0;
	rx_tracker->read.tidset.tid_info = 0;
	rx_tracker->read.tidset.read_size_qw = 0;
	if (!completion || !completion->fn) {
		rx_tracker->read.completion.fn = hfi2_dms_completion_fn_noop;
	} else {
		rx_tracker->read.completion = *completion;
	}

	return rx_tracker;
}

static struct hfi2_dms_ahg_header_set *
hfi2_dms_impl_ahg_header_set_get(struct hfi2_dms *dms, u8 port_idx)
{
	struct hfi2_dms_dlist_element *header;
	struct hfi2_dms_ahg_header_set *ret;

	DMS_BUG_ON(dms == NULL);

	header = hfi2_dms_impl_dlist_pop(&dms->ahg_headers[port_idx].free);
	if (header == NULL) {
		dd_dev_dbg(dms->dd, "dms: No free AHG header available, allocating a new block.\n");
		hfi2_dms_impl_ahg_header_block_alloc(dms, port_idx);
		header = hfi2_dms_impl_dlist_pop(
			&dms->ahg_headers[port_idx].free);
		DMS_WARN_ON(header == NULL);
	}

	ret = (struct hfi2_dms_ahg_header_set *) header;
	return ret;
}

/*
 * Frees tracker and increments its generation to invalidate any existing
 * handles referencing this tracker. Recycled trackers are appended to the
 * tail of the free list (consumed head-first by hfi2_dms_impl_tracker_new)
 * so the pool cycles FIFO, spreading allocations round-robin across the
 * block rather than repeatedly reusing the most-recently-freed tracker.
 */
void hfi2_dms_impl_tracker_recycle(struct hfi2_dms *dms, union hfi2_dms_tracker *tracker)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tracker);
	DMS_BUG_ON(tracker->hdr.dlist.prev != NULL);
	DMS_BUG_ON(tracker->hdr.dlist.next != NULL);

	tracker->hdr.generation++;
	hfi2_dms_impl_dlist_append(&dms->trackers.free, &tracker->hdr.dlist);
}

void hfi2_dms_impl_dlist_init(struct hfi2_dms_dlist *dlist)
{
	DMS_BUG_ON(!dlist);
	dlist->head = NULL;
	dlist->tail = NULL;
}

bool hfi2_dms_impl_dlist_empty(struct hfi2_dms_dlist *dlist)
{
	return (dlist->head == NULL);
}

struct hfi2_dms_dlist_element *hfi2_dms_impl_dlist_pop(struct hfi2_dms_dlist *dlist)
{
	if (hfi2_dms_impl_dlist_empty(dlist)) {
		return NULL;
	}

	struct hfi2_dms_dlist_element *element = dlist->head;

	dlist->head = element->next;
	if (dlist->head) {
		dlist->head->prev = NULL;
	} else {
		dlist->tail = NULL;
	}

	element->prev = NULL;
	element->next = NULL;

	return element;
}

void hfi2_dms_impl_dlist_push(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element)
{
	element->prev = NULL;
	element->next = NULL;

	if (dlist->head == NULL) {
		DMS_BUG_ON(dlist->tail != NULL);
		dlist->head = element;
		dlist->tail = element;
		element->prev = NULL;
		element->next = NULL;
	} else {
		element->next = dlist->head;
		element->next->prev = element; //?
		dlist->head = element;
		element->prev = NULL;
	}

	DMS_BUG_ON(dlist->head->prev != NULL);
	DMS_BUG_ON(dlist->tail->next != NULL);
}

void hfi2_dms_impl_dlist_append(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element)
{
	element->prev = NULL;
	element->next = NULL;

	if (dlist->tail == NULL) {
		DMS_BUG_ON(dlist->head != NULL);
		dlist->head = element;
		dlist->tail = element;
		element->prev = NULL;
		element->next = NULL;
	} else {
		element->prev = dlist->tail;
		element->prev->next = element;
		dlist->tail = element;
		element->next = NULL;
	}

	DMS_BUG_ON(dlist->head->prev != NULL);
	DMS_BUG_ON(dlist->tail->next != NULL);
}

void hfi2_dms_impl_dlist_remove(struct hfi2_dms_dlist *dlist, struct hfi2_dms_dlist_element *element)
{
	DMS_BUG_ON(!element);

	/*
	 * Determine if only element vs not in list.
	 * Using list_head instead would avoid this issue.
	 */
	if (!element->prev && element != dlist->head)
		goto done;
	if (!element->next && element != dlist->tail)
		goto done;

	DMS_BUG_ON(dlist->head == NULL);
	DMS_BUG_ON(dlist->tail == NULL);

	if (element->prev != NULL) {
		element->prev->next = element->next;
	} else {
		dlist->head = element->next;
	}

	if (element->next != NULL) {
		element->next->prev = element->prev;
	} else {
		dlist->tail = element->prev;
	}

done:
	element->prev = NULL;
	element->next = NULL;

}

u32 _tidset_free_count(struct hfi2_dms *dms)
{
	DMS_BUG_ON(!dms);
	return _ring_size(&dms->free_tidsets.ring);
}

int _tidset_idx_peek(struct hfi2_dms *dms, u32 *tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!tid_set);
	if (_ring_empty(&dms->free_tidsets.ring))
		return -1;

	*tid_set = dms->free_tidsets.arr[_ring_head(&dms->free_tidsets.ring)];
	return 0;
}

void _tidset_idx_reserve(struct hfi2_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(!dms);
	DMS_BUG_ON(_ring_empty(&dms->free_tidsets.ring));

	u32 const value = dms->free_tidsets.arr[_ring_consume(&dms->free_tidsets.ring)];
	DMS_BUG_ON(value != tid_set);
}

void _tidset_idx_release(struct hfi2_dms *dms, u32 tid_set)
{
	DMS_BUG_ON(dms == NULL);
	DMS_BUG_ON((tid_set & 0xffffff00u) != 0);
	dms->free_tidsets.arr[_ring_produce(&dms->free_tidsets.ring)] = (u8)tid_set;
}

void _configure_send_ctxt(struct hfi2_dms *dms, u8 pidx, struct send_context *sc)
{
	struct hfi2_devdata *dd = dms->dd;
	u64 reg = 0;
	u64 mask;
	u64 lid;

	_dms_set_ctxt_pkey(dd, sc, pidx, HFI2_DMS_PKEY);

	mask = ~((1U << dd->pport[pidx].lmc) - 1);
	lid = dd->pport[pidx].lid;

	if (dms->chip_type == CHIP_JKR)
		reg = BIT_ULL(63)
				| (mask & JKR_SEND_CTXT_CHECK_SLID_MASK_MASK) << JKR_SEND_CTXT_CHECK_SLID_MASK_SHIFT
				| (lid & JKR_SEND_CTXT_CHECK_SLID_VALUE_MASK) << JKR_SEND_CTXT_CHECK_SLID_VALUE_SHIFT;
	else if (dms->chip_type == CHIP_CYR)
		reg = BIT_ULL(63)
				| (mask & CYR_SEND_CTXT_CHECK_SLID_MASK_MASK) << CYR_SEND_CTXT_CHECK_SLID_MASK_SHIFT
				| (lid & CYR_SEND_CTXT_CHECK_SLID_VALUE_MASK) << CYR_SEND_CTXT_CHECK_SLID_VALUE_SHIFT;
	else {
		WARN_ON_ONCE(true);
		return;
	}

	write_epsc_csr(dd, pidx, sc->hw_context,
				dd->params->send_ctxt_check_slid_reg, reg);
}

static void _clone_send_ctxt_to_loopback(struct hfi2_dms *dms, u8 fabric_pidx,
					 struct send_context *sc)
{
	struct hfi2_devdata *dd = dms->dd;
	u8 lb_pidx = loopback_pidx_dd(dd, fabric_pidx);
	u32 hw = sc->hw_context;
	u64 val;

	if (!dms->port_available[lb_pidx])
		return;

	/* per-context send checks */
	val = read_epsc_csr(dd, fabric_pidx, hw,
			    dd->params->send_ctxt_check_partition_key_reg);
	write_epsc_csr(dd, lb_pidx, hw,
		       dd->params->send_ctxt_check_partition_key_reg, val);

	val = read_epsc_csr(dd, fabric_pidx, hw,
			    dd->params->send_ctxt_check_enable_reg);
	write_epsc_csr(dd, lb_pidx, hw,
		       dd->params->send_ctxt_check_enable_reg, val);

	val = read_epsc_csr(dd, fabric_pidx, hw,
			    dd->params->send_ctxt_check_slid_reg);
	write_epsc_csr(dd, lb_pidx, hw,
		       dd->params->send_ctxt_check_slid_reg, val);

	val = read_epsc_csr(dd, fabric_pidx, hw,
			    dd->params->send_ctxt_check_job_key_reg);
	write_epsc_csr(dd, lb_pidx, hw,
		       dd->params->send_ctxt_check_job_key_reg, val);

	/* per-port egress: SendBthQP */
	val = read_eport_csr(dd, fabric_pidx, dd->params->send_bth_qp_reg);
	write_eport_csr(dd, lb_pidx, dd->params->send_bth_qp_reg, val);
}

void _clone_rcd_config(struct hfi2_dms *dms, u8 src_pidx, struct hfi2_ctxtdata *rcd)
{
	u64 rcv_pkt_ctrl;
	u64 rcv_jkey_ctrl;
	u64 rcv_tid_pair_count;
	u32 rcv_pkt_ctrl_offset;
	u32 rcv_tid_pair_count_offset;
	int i;

	if (dms->chip_type == CHIP_JKR) {
		rcv_pkt_ctrl_offset = JKR_RCV_PKT_CTRL;
		rcv_tid_pair_count_offset = JKR_RCV_TID_PAIR_COUNT;
	} else if (dms->chip_type == CHIP_CYR) {
		rcv_pkt_ctrl_offset = CYR_RCV_PKT_CTRL;
		rcv_tid_pair_count_offset = CYR_RCV_TID_PAIR_COUNT;
	} else {
		WARN_ON_ONCE(true);
		return;
	}

	rcv_pkt_ctrl = read_iprc_csr(dms->dd, src_pidx, rcd->ctxt, rcv_pkt_ctrl_offset);
	rcv_jkey_ctrl = read_iprc_csr(dms->dd, src_pidx, rcd->ctxt,
					dms->dd->params->rcv_jkey_ctrl_reg);
	rcv_tid_pair_count = read_iprc_csr(dms->dd, src_pidx, rcd->ctxt, rcv_tid_pair_count_offset);
	for (i = 0; i < HFI2_DMS_MAX_PORTS; ++i) {
		if (!dms->port_available[i] || i == src_pidx)
			continue;

		write_iprc_csr(dms->dd, i, rcd->ctxt,
				rcv_pkt_ctrl_offset, rcv_pkt_ctrl);
		write_iprc_csr(dms->dd, i, rcd->ctxt,
				dms->dd->params->rcv_jkey_ctrl_reg, rcv_jkey_ctrl);
		write_iprc_csr(dms->dd, i, rcd->ctxt,
				rcv_tid_pair_count_offset, rcv_tid_pair_count);
	}
}

void _configure_ctrl_rcd(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd)
{
	_dms_rcv_context_disable9B(dms, pidx, rcd);
	_set_split_point(dms, pidx, rcd, HFI2_DMS_CTRL_HDR_SIZE);
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_ctrl;
	_clone_rcd_config(dms, pidx, rcd);
}

void _configure_data_rcd(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd)
{
	_dms_rcv_context_disable9B(dms, pidx, rcd);
	_set_split_point(dms, pidx, rcd, HFI2_DMS_DATA_HDR_SIZE);
	rcd->rhf_rcv_function_map = _dms_rhf_rcv_functions_data;
	_clone_rcd_config(dms, pidx, rcd);
}

void _dms_rcv_context_disable9B(struct hfi2_dms *dms, u8 pidx, struct hfi2_ctxtdata *rcd)
{
	u32 offset;
	u64 reg;

	dd_dev_dbg(dms->dd, "Disabling 9B context for pidx %u, ctxt %u\n", pidx, rcd->ctxt);

	if (dms->chip_type == CHIP_JKR) {
		offset = JKR_RCV_PKT_CTRL;
		reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, offset);
		dd_dev_dbg(dms->dd, "Current JKR_RCV_PKT_CTRL: 0x%016llx\n", reg);
		reg &= ~JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SMASK;
		reg |= 0x4ull << JKR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SHIFT;
		dd_dev_dbg(dms->dd, "Setting JKR_RCV_PKT_CTRL to 0x%016llx\n", reg);
	} else if (dms->chip_type == CHIP_CYR) {
		offset = CYR_RCV_PKT_CTRL;
		reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, offset);
		dd_dev_dbg(dms->dd, "Current CYR_RCV_PKT_CTRL: 0x%016llx\n", reg);
		reg &= ~CYR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SMASK;
		reg |= 0x4ull << CYR_RCV_PKT_CTRL_L2_TYPE_ENABLE_MASK_SHIFT;
		dd_dev_dbg(dms->dd, "Setting CYR_RCV_PKT_CTRL to 0x%016llx\n", reg);
	} else {
		WARN_ON_ONCE(true);
		return;
	}

	write_iprc_csr(dms->dd, pidx, rcd->ctxt, offset, reg);
}

static void _set_split_point(struct hfi2_dms *dms, u8 pidx,
			     struct hfi2_ctxtdata *rcd, u64 hdr_size)
{
	u32 offset;
	u64 reg;

	dd_dev_dbg(dms->dd, "Setting split point for rctxt %u to %llu DWs\n", rcd->ctxt, hdr_size);

	if (dms->chip_type == CHIP_JKR) {
		offset = JKR_RCV_PKT_CTRL;
		reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, offset);
		reg &= ~JKR_RCV_PKT_CTRL_HDR_SIZE_SMASK;
		reg |= hdr_size << JKR_RCV_PKT_CTRL_HDR_SIZE_SHIFT;
	} else if (dms->chip_type == CHIP_CYR) {
		offset = CYR_RCV_PKT_CTRL;
		reg = read_iprc_csr(dms->dd, pidx, rcd->ctxt, offset);
		reg &= ~CYR_RCV_PKT_CTRL_HDR_SIZE_SMASK;
		reg |= hdr_size << CYR_RCV_PKT_CTRL_HDR_SIZE_SHIFT;
	} else {
		WARN_ON_ONCE(true);
		return;
	}

	write_iprc_csr(dms->dd, pidx, rcd->ctxt, offset, reg);
}

#define SOP_DISTANCE (TXE_PIO_SIZE / 2)

#if HFI2_DMS_TESTING_ENABLE
/*
 * Testing builds only: make this share of PIO reservations, in basis points
 * (0..10000), fail with -EAGAIN as if the send context had no credits, to
 * drive the PIO waitlist.
 */
static uint dms_test_pio_eagain_bp;

static bool _test_pio_eagain(void)
{
	u32 const bp = READ_ONCE(dms_test_pio_eagain_bp);

	return bp && get_random_u32_below(10000) < bp;
}
#else
static inline bool _test_pio_eagain(void)
{
	return false;
}
#endif /* HFI2_DMS_TESTING_ENABLE */

/*
 * Find @blocks free PIO blocks at the ring fill position, without taking
 * them: *@fill_wrap is their first block.  _pio_blocks_take() takes them.
 */
static inline int _pio_blocks_find(struct send_context *sc, u32 blocks,
				   u32 *fill_wrap)
{
	u64 hw_free;
	unsigned long old_free;
	unsigned long extra;
	u32 avail;

	if (!_sctxt_is_active(sc))
		return -ECOMM;
	if (_test_pio_eagain())
		return -EAGAIN;

	sc->alloc_free = READ_ONCE(sc->free);
	avail = (u32)sc->credits - (sc->fill - sc->alloc_free);
	if (blocks > avail) {
		/*
		 * Inline the credit delta calculation from sc_release_update()
		 * without the release_lock, PIO callbacks, or sc_piobufavail().
		 * DMS is single-threaded and does not use the send ring.
		 */
		hw_free = le64_to_cpu(*sc->hw_free);
		old_free = sc->free;
		extra = (((hw_free & CR_COUNTER_SMASK) >> CR_COUNTER_SHIFT) -
			 (old_free & CR_COUNTER_MASK)) & CR_COUNTER_MASK;

		sc->free = old_free + extra;
		sc->alloc_free = sc->free;
		avail = (u32)sc->credits - (sc->fill - sc->alloc_free);
		if (blocks > avail)
			return -EAGAIN;
	}

	*fill_wrap = sc->fill & (SCS_BULKSVC_CREDITS - 1);
	return 0;
}

/* Take the @blocks found by _pio_blocks_find(); returns the next ring head. */
static inline u32 _pio_blocks_take(struct send_context *sc, u32 blocks)
{
	u32 next = sc->sr_head + 1;

	sc->fill += blocks;
	return next >= sc->sr_size ? 0 : next;
}

/*
 * Find and take @blocks PIO blocks on @sc.  On success returns 0 with the
 * block index of the first one in *@fill_wrap and the ring head to publish
 * after the writes in *@next; the caller must write every block (SOP block
 * first-addressed via SOP_DISTANCE), then wmb() and store *@next into
 * sc->sr_head.
 */
static inline int _pio_blocks_reserve(struct send_context *sc, u32 blocks,
				      u32 *fill_wrap, u32 *next)
{
	int ret = _pio_blocks_find(sc, blocks, fill_wrap);

	if (!ret)
		*next = _pio_blocks_take(sc, blocks);
	return ret;
}

/*
 * Write a staged SOP block: qwords 7..1 first, the PBC (qword 0) last.  The
 * hardware only requires the SOP-addressed write to land at block offset 0,
 * not to come first (JKR/CYR HAS 7.2.7).
 */
static __always_inline void _pio_sop_write(void __iomem *sop, const u64 *q)
{
	writeq(q[7], sop + 7 * sizeof(u64));
	writeq(q[6], sop + 6 * sizeof(u64));
	writeq(q[5], sop + 5 * sizeof(u64));
	writeq(q[4], sop + 4 * sizeof(u64));
	writeq(q[3], sop + 3 * sizeof(u64));
	writeq(q[2], sop + 2 * sizeof(u64));
	writeq(q[1], sop + 1 * sizeof(u64));
	writeq(q[0], sop + 0 * sizeof(u64));
}

/*
 * As _pio_sop_write(), but write @pbc in place of @q[0], so a caller-composed
 * block that must stay const can send an adjusted PBC.
 */
static __always_inline void _pio_sop_write_pbc(void __iomem *sop,
					       const u64 *q, u64 pbc)
{
	writeq(q[7], sop + 7 * sizeof(u64));
	writeq(q[6], sop + 6 * sizeof(u64));
	writeq(q[5], sop + 5 * sizeof(u64));
	writeq(q[4], sop + 4 * sizeof(u64));
	writeq(q[3], sop + 3 * sizeof(u64));
	writeq(q[2], sop + 2 * sizeof(u64));
	writeq(q[1], sop + 1 * sizeof(u64));
	writeq(pbc, sop + 0 * sizeof(u64));
}

/*
 * Stage up to 7 header qwords into SOP block slots 1..7 with a fixed unrolled
 * copy, no loop.  Returns the number staged.
 */
static __always_inline u64 _pio_sop_stage_hdr(u64 *q, const u64 *hdr,
					      u64 hdr_qws)
{
	u64 const n = min_t(u64, hdr_qws, PIO_BLOCK_QWS - 1);

	switch (n) {
	case 7:
		q[7] = hdr[6];
		fallthrough;
	case 6:
		q[6] = hdr[5];
		fallthrough;
	case 5:
		q[5] = hdr[4];
		fallthrough;
	case 4:
		q[4] = hdr[3];
		fallthrough;
	case 3:
		q[3] = hdr[2];
		fallthrough;
	case 2:
		q[2] = hdr[1];
		fallthrough;
	case 1:
		q[1] = hdr[0];
		fallthrough;
	case 0:
		break;
	}
	return n;
}

/*
 * Emit qword @q at packet qword position @pos: positions 1..7 are staged in
 * @sop_qws (the SOP block, written last), everything after streams to the
 * mirror window at @mirror + (pos - PIO_BLOCK_QWS) qwords.  Position 0 is
 * the PBC, which never goes through here.
 */
static __always_inline void _pio_sendv_put(u64 *sop_qws,
					   void __iomem *mirror,
					   u64 pos, u64 q)
{
	if (pos < PIO_BLOCK_QWS)
		sop_qws[pos] = q;
	else
		writeq(q, mirror + (pos - PIO_BLOCK_QWS) * sizeof(u64));
}

/*
 * Gather @niov spans into one PIO packet after @pbc and send it.  @pbc is the
 * packet's PBC, passed separately, so the spans hold only what follows it
 * (header and payload).
 *
 * The spans are PACKED: they are concatenated byte for byte into a single
 * stream, and a span that ends partway through a qword is completed with the
 * leading bytes of the next non-empty span -- never with zeros.  Only the
 * very end of the stream is zero-padded to a qword, after which @tail_flit
 * appends one zero qword, and the final PIO block is zero-filled.  Spans may
 * have any length (including zero) and any byte alignment; no load ever
 * reads past the end of a span.
 *
 * The PBC's declared length is not checked against the gathered length:
 * DIV_ROUND_UP(sum of span lengths, 8) + tail_flit qwords after the PBC.
 * They must agree or the send context halts on a packet-length mismatch.
 *
 * Not yet optimized: every qword is placed with a per-qword SOP-vs-mirror
 * test.  The SOP block is staged in a stack buffer and written with the PBC
 * last (JKR/CYR HAS 7.2.7).
 */
static int
hfi2_dms_impl_pio_sendv(struct hfi2_dms *dms, u64 pbc,
			const struct hfi2_dms_ulp_iov *iov,
			u32 niov, bool tail_flit)
{
	u64 sop_qws[PIO_BLOCK_QWS] = {};
	struct send_context *sc;
	void __iomem *sop;
	void __iomem *mirror;
	u64 total_bytes = 0;
	u64 total_qws;
	u64 pos;
	u64 carry = 0;		/* partially filled qword, little-endian */
	u32 carry_bytes = 0;	/* valid bytes in carry, 0..7 */
	u32 blocks;
	u32 fill_wrap;
	u32 next;
	u32 i;
	int ret;

	BUILD_BUG_ON(PIO_BLOCK_QWS != 8);

	if (niov && !iov)
		return -EINVAL;
	for (i = 0; i < niov; i++) {
		if (iov[i].len && !iov[i].base)
			return -EINVAL;
		total_bytes += iov[i].len;
	}

	/* pbc + packed spans (last qword zero-padded) + optional tail flit */
	total_qws = 1 + DIV_ROUND_UP(total_bytes, sizeof(u64)) +
		    (tail_flit ? 1 : 0);
	if (total_qws > (u64)SCS_BULKSVC_CREDITS * PIO_BLOCK_QWS)
		return -EMSGSIZE;
	blocks = DIV_ROUND_UP(total_qws, PIO_BLOCK_QWS);

	sc = dms->port_sctxts[_pbc_port_idx_get(pbc)];
	ret = _pio_blocks_reserve(sc, blocks, &fill_wrap, &next);
	if (ret)
		return ret;

	sop = sc->base_addr + fill_wrap * PIO_BLOCK_SIZE + SOP_DISTANCE;
	mirror = sc->mirror_addr + fill_wrap * PIO_BLOCK_SIZE + PIO_BLOCK_SIZE;

	sop_qws[0] = pbc;
	pos = 1;
	for (i = 0; i < niov; i++) {
		const u8 *src = iov[i].base;
		u32 len = iov[i].len;

		/*
		 * Complete a qword left open by an earlier span with this
		 * span's leading bytes.  A span too short to complete it just
		 * adds its bytes and the carry stays open.
		 */
		if (carry_bytes) {
			u32 take = min_t(u32, sizeof(u64) - carry_bytes, len);
			u32 b;

			for (b = 0; b < take; b++)
				carry |= (u64)src[b] << ((carry_bytes + b) * 8);
			carry_bytes += take;
			src += take;
			len -= take;
			if (carry_bytes < sizeof(u64))
				continue;
			_pio_sendv_put(sop_qws, mirror, pos++, carry);
			carry = 0;
			carry_bytes = 0;
		}

		/* Whole qwords of this span (unaligned loads are fine). */
		for (; len >= sizeof(u64); len -= sizeof(u64)) {
			_pio_sendv_put(sop_qws, mirror, pos++,
				       get_unaligned_le64(src));
			src += sizeof(u64);
		}

		/*
		 * Trailing sub-qword bytes open a new carry; they are loaded
		 * bytewise so nothing past the span is ever read.
		 */
		for (; len; len--, carry_bytes++)
			carry |= (u64)*src++ << (carry_bytes * 8);
	}

	/* End of the stream: the only zero padding inside the packet. */
	if (carry_bytes)
		_pio_sendv_put(sop_qws, mirror, pos++, carry);

	/* Count, and mark if enabled, a PBC length that needs the test bit. */
	sop_qws[0] = pbc_test(dms->dd, sop_qws[0]);

	/*
	 * The tail flit and the final-block pad are both zero, and @blocks
	 * already counts the tail flit, so one zero fill writes both.
	 * sop_qws[] is already zero past the packet; past the SOP block, zero
	 * the mirror up to the end of the last reserved block.
	 */
	if (pos < PIO_BLOCK_QWS)
		pos = PIO_BLOCK_QWS;
	for (; pos < (u64)blocks * PIO_BLOCK_QWS; pos++)
		writeq(0, mirror + (pos - PIO_BLOCK_QWS) * sizeof(u64));

	/* SOP block last, PBC write last of all (JKR/CYR HAS 7.2.7). */
	writeq(sop_qws[7], sop + 7 * sizeof(u64));
	writeq(sop_qws[6], sop + 6 * sizeof(u64));
	writeq(sop_qws[5], sop + 5 * sizeof(u64));
	writeq(sop_qws[4], sop + 4 * sizeof(u64));
	writeq(sop_qws[3], sop + 3 * sizeof(u64));
	writeq(sop_qws[2], sop + 2 * sizeof(u64));
	writeq(sop_qws[1], sop + 1 * sizeof(u64));
	writeq(sop_qws[0], sop + 0 * sizeof(u64));

	/* Commit the completed PIO writes before publishing the new ring head. */
	wmb();
	sc->sr_head = next;

	return 0;
}

void hfi2_dms_pio_wr_bytes(struct hfi2_dms_pio_wr *w, const void *src,
			   u32 len)
{
	const u8 *s = src;
	/*
	 * Work on local copies: with @dest and @carry in registers the copy
	 * loop does no loads or stores to @w between the PIO stores.
	 */
	void __iomem *dest = w->dest;
	u64 carry = w->carry;
	u32 carry_bytes = w->carry_bytes;

	/*
	 * Complete a qword left open by an earlier chunk.  A chunk too short
	 * to complete it just adds its bytes.
	 */
	if (carry_bytes) {
		while (len && carry_bytes < sizeof(u64)) {
			carry |= (u64)*s++ << (carry_bytes * 8);
			carry_bytes++;
			len--;
		}
		if (carry_bytes < sizeof(u64))
			goto out;
		writeq(carry, dest);
		dest += sizeof(u64);
		carry = 0;
		carry_bytes = 0;
	}

	/* Whole qwords, 8 at a time; the source may be at any alignment. */
	for (; len >= PIO_BLOCK_SIZE; len -= PIO_BLOCK_SIZE) {
		writeq(get_unaligned_le64(s + 0 * sizeof(u64)), dest + 0 * sizeof(u64));
		writeq(get_unaligned_le64(s + 1 * sizeof(u64)), dest + 1 * sizeof(u64));
		writeq(get_unaligned_le64(s + 2 * sizeof(u64)), dest + 2 * sizeof(u64));
		writeq(get_unaligned_le64(s + 3 * sizeof(u64)), dest + 3 * sizeof(u64));
		writeq(get_unaligned_le64(s + 4 * sizeof(u64)), dest + 4 * sizeof(u64));
		writeq(get_unaligned_le64(s + 5 * sizeof(u64)), dest + 5 * sizeof(u64));
		writeq(get_unaligned_le64(s + 6 * sizeof(u64)), dest + 6 * sizeof(u64));
		writeq(get_unaligned_le64(s + 7 * sizeof(u64)), dest + 7 * sizeof(u64));
		s += PIO_BLOCK_SIZE;
		dest += PIO_BLOCK_SIZE;
	}
	for (; len >= sizeof(u64); len -= sizeof(u64)) {
		writeq(get_unaligned_le64(s), dest);
		s += sizeof(u64);
		dest += sizeof(u64);
	}

	/* Leftover bytes open a carry; read bytewise, never past the chunk. */
	for (; len; len--) {
		carry |= (u64)*s++ << (carry_bytes * 8);
		carry_bytes++;
	}
out:
	w->dest = dest;
	w->carry = carry;
	w->carry_bytes = carry_bytes;
}

void hfi2_dms_pio_wr_finish(struct hfi2_dms_pio_wr *w)
{
	if (!w->carry_bytes)
		return;
	writeq(w->carry, w->dest);	/* bytes past carry_bytes are zero */
	w->dest += sizeof(u64);
	w->carry = 0;
	w->carry_bytes = 0;
}

void hfi2_dms_pio_zero(void __iomem *dest, u64 len)
{
	void __iomem *const end = dest + round_up(len, sizeof(u64));

	for (; dest < end; dest += sizeof(u64))
		writeq(0, dest);
}

int hfi2_dms_pio_wr_fail(struct hfi2_dms_pio_wr *w, void __iomem *dest,
			 u64 len, int err)
{
	if (w->dest == dest)
		return err;	/* nothing stored: the packet is not sent */
	hfi2_dms_pio_wr_finish(w);
	hfi2_dms_pio_zero(w->dest, dest + round_up(len, sizeof(u64)) - w->dest);
	return HFI2_DMS_PIO_WRITE_FILLED;
}

int hfi2_dms_pio_write_bounce(struct hfi2_dms_page_provider const *pp,
			      u64 byte_offset, u64 len, void __iomem *dest)
{
	u8 bounce[HFI2_DMS_PIO_BOUNCE_BYTES] __aligned(sizeof(u64));
	struct hfi2_dms_pio_wr w = { .dest = dest };
	u64 const total = len;
	int ret;

	BUILD_BUG_ON(HFI2_DMS_PIO_BOUNCE_BYTES % sizeof(u64));

	if (WARN_ON_ONCE(!pp || !pp->memcpy))
		return -EFAULT;

	while (len) {
		u32 const n = min_t(u64, len, sizeof(bounce));

		/* Explicit dereference: memcpy may be a function-like macro. */
		ret = (*pp->memcpy)(pp, byte_offset, n, bounce, true);
		if (ret)
			return hfi2_dms_pio_wr_fail(&w, dest, total, ret);
		hfi2_dms_pio_wr_bytes(&w, bounce, n);
		byte_offset += n;
		len -= n;
	}
	hfi2_dms_pio_wr_finish(&w);
	return 0;
}

/*
 * Write one header block (8 qwords) at @dst.  Used for the blocks after the
 * SOP block, in the mirror window.
 */
static __always_inline void _pio_block_write(void __iomem *dst, const u64 *q)
{
	writeq(q[0], dst + 0 * sizeof(u64));
	writeq(q[1], dst + 1 * sizeof(u64));
	writeq(q[2], dst + 2 * sizeof(u64));
	writeq(q[3], dst + 3 * sizeof(u64));
	writeq(q[4], dst + 4 * sizeof(u64));
	writeq(q[5], dst + 5 * sizeof(u64));
	writeq(q[6], dst + 6 * sizeof(u64));
	writeq(q[7], dst + 7 * sizeof(u64));
}

/*
 * Write the header blocks of @scb after the SOP block, blocks 1..@hdr_scbs-1,
 * to the mirror window: unrolled for a two-block header, a loop otherwise.
 */
static __always_inline void _pio_scb_hdr_tail_write(void __iomem *mirror,
						    const u64 *scb,
						    u32 hdr_scbs)
{
	u32 i;

	switch (hdr_scbs) {
	case 1:
		break;
	case 2:
		_pio_block_write(mirror, scb + PIO_BLOCK_QWS);
		break;
	default:
		for (i = 1; i < hdr_scbs; i++)
			_pio_block_write(mirror + (i - 1) * PIO_BLOCK_SIZE,
					 scb + i * PIO_BLOCK_QWS);
		break;
	}
}

/*
 * Turn the staged SOP block of a WRITE_START_EAGER or DATA_START_EAGER into
 * the same START without an eager payload: each eager type is its plain
 * type + 1 (dms.h), the message type is BTH[0] bits 23:16, and BTH[0] is the
 * low half of qword 2.  The receiver then requests the whole payload and
 * ignores the packet's extra length.
 */
static void _pio_start_drop_eager(u64 *sop_qws)
{
	u32 const msg_type = (sop_qws[2] >> 16) & 0xff;

	if (DMS_WARN_ON(msg_type != HFI2_DMS_MSG_TYPE_WRITE_START_EAGER &&
			msg_type != HFI2_DMS_MSG_TYPE_DATA_START_EAGER))
		return;
	sop_qws[2] -= 1ull << 16;
}

/*
 * Send one PIO packet: PBC and @hdr_qws header qwords from @hdr, @nbytes of
 * @pp from @byte_offset, then @trail_qws zero qwords.  The payload is written
 * first and the credits taken only after it succeeds, so a failure sends
 * nothing.  The SOP block goes last, PBC last of all.
 */
static __always_inline int
_pio_pkt_send(struct hfi2_dms *dms, const u64 *hdr, u32 hdr_qws,
	      struct hfi2_dms_page_provider const *pp, u64 byte_offset,
	      u32 nbytes, u32 trail_qws)
{
	u64 const pkt_qws = 1 + (u64)hdr_qws + DIV_ROUND_UP(nbytes, sizeof(u64)) +
			    trail_qws;
	u32 const blocks = DIV_ROUND_UP(pkt_qws, PIO_BLOCK_QWS);
	bool const whole = (1 + hdr_qws) % PIO_BLOCK_QWS == 0;
	u64 sop_qws[PIO_BLOCK_QWS] = {};
	struct send_context *sc;
	void __iomem *sop;
	void __iomem *mirror;
	void __iomem *dest;
	void __iomem *end;
	u64 pre = 0;		/* payload bytes staged in the SOP block */
	u64 pbc = hdr[0];
	u32 hdr_blocks = 0;
	u32 fill_wrap;
	u32 next;
	u32 gen;
	u32 i;
	int ret;
	bool filled = false;

	BUILD_BUG_ON(PIO_BLOCK_QWS != 8);

	if (unlikely(pkt_qws > (u64)SCS_BULKSVC_CREDITS * PIO_BLOCK_QWS))
		return -EMSGSIZE;
	if (unlikely(nbytes && (!pp || !pp->pio_write || !pp->memcpy)))
		return -EINVAL;

	if (!whole) {
		_pio_sop_stage_hdr(sop_qws, hdr + 1, hdr_qws);
		if (1 + hdr_qws < PIO_BLOCK_QWS && nbytes) {
			pre = min_t(u64, nbytes,
				    (PIO_BLOCK_QWS - 1 - hdr_qws) * sizeof(u64));
			/* Explicit dereference: memcpy may be a function-like macro. */
			ret = (*pp->memcpy)(pp, byte_offset, pre,
					    &sop_qws[1 + hdr_qws], true);
			if (ret)
				return ret < 0 ? ret : -EIO;
		}
	}

	sc = dms->port_sctxts[_pbc_port_idx_get(pbc)];
	gen = READ_ONCE(sc->enable_gen);
	ret = _pio_blocks_find(sc, blocks, &fill_wrap);
	if (ret)
		return ret;

	sop = sc->base_addr + fill_wrap * PIO_BLOCK_SIZE + SOP_DISTANCE;
	mirror = sc->mirror_addr + fill_wrap * PIO_BLOCK_SIZE + PIO_BLOCK_SIZE;
	end = mirror + (blocks - 1) * PIO_BLOCK_SIZE;

	if (whole) {
		hdr_blocks = (1 + hdr_qws) / PIO_BLOCK_QWS;
		dest = mirror + (hdr_blocks - 1) * PIO_BLOCK_SIZE;
	} else {
		/*
		 * If payload remains past the SOP block, pre filled it, so
		 * this is a qword-aligned address in the mirror window.
		 */
		i = 1 + hdr_qws + DIV_ROUND_UP(pre, sizeof(u64));
		dest = mirror + (max_t(u32, i, PIO_BLOCK_QWS) - PIO_BLOCK_QWS) *
				sizeof(u64);
	}

	/* Payload first: a failed pio_write() has written nothing. */
	if (nbytes > pre) {
		ret = pp->pio_write(pp, byte_offset + pre, nbytes - pre, dest);
		if (unlikely(ret < 0)) {
			dd_dev_warn_ratelimited(dms->dd,
						"DMS_DIAG: pio_write failed (%d); packet not sent\n",
						ret);
			/* -EAGAIN from here means no PIO credits; this is not that. */
			return ret == -EAGAIN ? -EIO : ret;
		}
		if (unlikely(ret == HFI2_DMS_PIO_WRITE_FILLED)) {
			dd_dev_warn_ratelimited(dms->dd,
						"DMS_DIAG: pio_write source copy failed partway; START sent without its payload\n");
			filled = true;
		}
		dest += round_up(nbytes - pre, sizeof(u64));

		/* pio_write() may sleep: drop the packet if the context restarted. */
		if (unlikely(!_sctxt_is_active(sc) ||
			     READ_ONCE(sc->enable_gen) != gen))
			return -ECOMM;
	}

	if (whole) {
		_pio_scb_hdr_tail_write(mirror, hdr, hdr_blocks);
	} else {
		/* Header qwords past the SOP block. */
		for (i = PIO_BLOCK_QWS - 1; i < hdr_qws; i++)
			writeq(hdr[1 + i],
			       mirror + (1 + i - PIO_BLOCK_QWS) * sizeof(u64));
	}

	/*
	 * Pad, tail flit and final-block zero fill: @blocks counts the pad and
	 * the tail flit, both zero.  sop_qws[] is already zero past the packet.
	 */
	for (; dest < end; dest += sizeof(u64))
		writeq(0, dest);

	next = _pio_blocks_take(sc, blocks);

	/* Count, and mark if enabled, a PBC length that needs the test bit. */
	pbc = pbc_test(dms->dd, pbc);

	/*
	 * A START whose blocks hold zeros in place of part of its payload
	 * must still be sent, as a PIO block cannot be left partly written.
	 * Send it as the START without an eager payload, so the receiver
	 * lands nothing from it, and fail the transfer.
	 */
	if (unlikely(filled)) {
		if (whole)
			memcpy(sop_qws, hdr, sizeof(sop_qws));
		_pio_start_drop_eager(sop_qws);
	}

	/* SOP block last, PBC write last of all. */
	if (whole && !filled) {
		_pio_sop_write_pbc(sop, hdr, pbc);
	} else {
		sop_qws[0] = pbc;
		_pio_sop_write(sop, sop_qws);
	}

	/* Commit the completed PIO writes before publishing the new ring head. */
	wmb();
	sc->sr_head = next;

	return filled ? -EIO : 0;
}

static struct pio_waiter *_pio_waitlist_new(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *element;

	element = hfi2_dms_impl_dlist_pop(&dms->pio.freelist);
	if (!element) {
		// allocate a bunch more
		for (int i = 0; i < 256; ++i) {
			struct pio_waiter *waiter;

			waiter = kzalloc_node(sizeof(*waiter),
					      GFP_KERNEL, dms->numa_node);
			if (!waiter) {
				dd_dev_err(dms->dd, "Memory allocation error.\n");
				return NULL;
			}
			hfi2_dms_impl_dlist_push(&dms->pio.freelist, &waiter->element);
		}
		element = hfi2_dms_impl_dlist_pop(&dms->pio.freelist);
		if (!element) {
			return NULL;
		}
	}

	return container_of(element, struct pio_waiter, element);
}

static int _pio_waitlist_initialize(struct hfi2_dms *dms)
{
	struct pio_waiter *waiter = _pio_waitlist_new(dms);
	if (!waiter)
		return -ENOMEM;
	hfi2_dms_impl_dlist_push(&dms->pio.freelist, &waiter->element);
	return 0;
}

static void _pio_waitlist_finalize(struct hfi2_dms *dms)
{
	while (dms->pio.waitlist.head) {
		kfree(hfi2_dms_impl_dlist_pop(&dms->pio.waitlist));
	}
	while (dms->pio.freelist.head) {
		kfree(hfi2_dms_impl_dlist_pop(&dms->pio.freelist));
	}
}

static bool _pio_waitlist_empty(struct hfi2_dms *dms)
{
	return (dms->pio.waitlist.head == NULL) ? true : false;
}

/*
 * Queue a PIO packet behind the waitlist: the PBC and @hdr_qws header qwords
 * from @hdr (@copy_qws of them copied, the rest past the PBC's declared
 * length need not be), then @nbytes of @pp from @byte_offset, then
 * @trail_qws zero qwords.  @handle names the tracker the packet is for, or
 * HFI2_DMS_TRANSFER_HANDLE_NONE.
 */
static int _pio_waitlist_append_pkt(struct hfi2_dms *dms, const u64 *hdr,
				    u32 hdr_qws, u32 copy_qws,
				    struct hfi2_dms_page_provider const *pp,
				    u64 byte_offset, u32 nbytes, u32 trail_qws,
				    struct hfi2_dms_transfer_handle handle)
{
	struct pio_waiter *waiter;

	if (DMS_WARN_ON(copy_qws > 1 + hdr_qws ||
			1 + hdr_qws > HFI2_DMS_PIO_WAITER_QWS ||
			trail_qws > U8_MAX || (nbytes && !pp)))
		return -EMSGSIZE;

	waiter = _pio_waitlist_new(dms);
	if (!waiter)
		return -ENOMEM;

	waiter->handle = handle;
	if (nbytes)
		waiter->pp = *pp;
	waiter->byte_offset = byte_offset;
	waiter->nbytes = nbytes;
	waiter->hdr_qws = hdr_qws;
	waiter->trail_qws = trail_qws;
	memcpy(waiter->buf, hdr, copy_qws * sizeof(u64));
	memset(waiter->buf + copy_qws, 0,
	       (1 + hdr_qws - copy_qws) * sizeof(u64));

	hfi2_dms_impl_dlist_append(&dms->pio.waitlist, &waiter->element);
	return 0;
}

static u32 _pio_cmd_hdr_qws(union hfi2_dms_proto_cmd const *cmd);

/*
 * Queue a ULP packet: @pbc, then the @niov packed spans, zero-padded to a
 * qword, then the tail flit, all copied into the waiter.  -EAGAIN when the
 * packet does not fit a waiter; the ULP retries it on a later poll.
 */
static int _pio_waitlist_append_ulp(struct hfi2_dms *dms, u64 pbc,
				    const struct hfi2_dms_ulp_iov *iov,
				    u32 niov)
{
	struct pio_waiter *waiter;
	u64 total_bytes = 0;
	u64 total_qws;
	u8 *dst;
	u32 i;

	for (i = 0; i < niov; i++) {
		if (iov[i].len && !iov[i].base)
			return -EINVAL;
		total_bytes += iov[i].len;
	}
	/* PBC + packed spans (last qword zero-padded) + tail flit */
	total_qws = 1 + DIV_ROUND_UP(total_bytes, sizeof(u64)) + 1;
	if (total_qws > (u64)SCS_BULKSVC_CREDITS * PIO_BLOCK_QWS)
		return -EMSGSIZE;	/* could never be sent */
	if (total_qws > HFI2_DMS_PIO_WAITER_QWS)
		return -EAGAIN;

	waiter = _pio_waitlist_new(dms);
	if (!waiter)
		return -ENOMEM;

	/* Built in place: a whole-packet copy is too big for the stack. */
	waiter->handle = HFI2_DMS_TRANSFER_HANDLE_NONE;
	waiter->byte_offset = 0;
	waiter->nbytes = 0;
	waiter->hdr_qws = total_qws - 1;
	waiter->trail_qws = 0;
	waiter->buf[0] = pbc;
	dst = (u8 *)&waiter->buf[1];
	for (i = 0; i < niov; i++) {
		memcpy(dst, iov[i].base, iov[i].len);
		dst += iov[i].len;
	}
	memset(dst, 0, (u8 *)&waiter->buf[total_qws] - dst);

	hfi2_dms_impl_dlist_append(&dms->pio.waitlist, &waiter->element);
	return 0;
}

/* Queue a self-contained control command; only its declared length is kept. */
static int _pio_waitlist_append(struct hfi2_dms *dms, union hfi2_dms_proto_cmd *cmd,
				struct hfi2_dms_transfer_handle handle)
{
	/* PBC dw length counts the PBC dword; +1 qw covers the PBC itself. */
	u32 const total_qws =
		((hfi2_dms_impl_pbc_length_dws_get(cmd->pbc) >> 1) - 1) + 1;
	u32 const hdr_qws = _pio_cmd_hdr_qws(cmd);

	if (unlikely(!hdr_qws)) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	return _pio_waitlist_append_pkt(dms, cmd->qws, hdr_qws,
					min_t(u32, total_qws, 1 + hdr_qws),
					NULL, 0, 0, 0, handle);
}

/*
 * Header qwords after the PBC to send a self-contained command with: one or
 * two whole PIO blocks, reading straight through its own tail flit and any
 * command-buffer bytes after it (only the PBC's declared length reaches the
 * wire).  A DATA_REQUEST (or its replay) or READ_START_SPECULATIVE whose
 * recv_chunk and gather arrays do not fit the control inline area carries
 * them past its usual blocks and is sent at its declared length.  Returns 0,
 * a bug, for a command type that never reaches the PIO command path or one
 * whose PBC length needs a different number of PIO blocks than its header.
 */
static u32 _pio_cmd_hdr_qws(union hfi2_dms_proto_cmd const *cmd)
{
	u32 const msg_type = (cmd->bth[0] & 0x00FF0000) >> 16;
	/* Qwords after the PBC the PBC declares, tail flit included. */
	u32 const size_qw = (hfi2_dms_impl_pbc_length_dws_get(cmd->pbc) >> 1) - 1;
	u32 hdr_qws;

	switch (msg_type) {
	case HFI2_DMS_MSG_TYPE_DATA_REQUEST:
	case HFI2_DMS_MSG_TYPE_DATA_REQUEST_REPLAY:
		hdr_qws = max_t(u32, size_qw, PIO_BLOCK_QWS - 1);
		break;
	case HFI2_DMS_MSG_TYPE_ACK:
	case HFI2_DMS_MSG_TYPE_DATA_START:
	case HFI2_DMS_MSG_TYPE_NACK:
		hdr_qws = PIO_BLOCK_QWS - 1;
		break;
	case HFI2_DMS_MSG_TYPE_READ_START_SPECULATIVE:
		hdr_qws = max_t(u32, size_qw, 2 * PIO_BLOCK_QWS - 1);
		break;
	case HFI2_DMS_MSG_TYPE_WRITE_START:
	case HFI2_DMS_MSG_TYPE_WRITE_START_REPLAY:
	case HFI2_DMS_MSG_TYPE_WRITE_START_TINY:
	case HFI2_DMS_MSG_TYPE_READ_START:
	case HFI2_DMS_MSG_TYPE_READ_START_REPLAY:
	case HFI2_DMS_MSG_TYPE_STATUS_REQUEST:
	case HFI2_DMS_MSG_TYPE_STATUS_RESPONSE:
		hdr_qws = 2 * PIO_BLOCK_QWS - 1;
		break;
	default:
		return 0;
	}

	/*
	 * The hardware takes as many PIO blocks as the PBC length needs; the
	 * sender writes as many as the header needs.  They must agree, or
	 * sc->fill and the hardware fall out of step.
	 */
	if (DIV_ROUND_UP(size_qw + 1, PIO_BLOCK_QWS) !=
	    DIV_ROUND_UP(1 + hdr_qws, PIO_BLOCK_QWS))
		return 0;
	return hdr_qws;
}

/* Send one self-contained command; see _pio_cmd_hdr_qws(). */
static __always_inline int _pio_cmd_send(struct hfi2_dms *dms,
					 union hfi2_dms_proto_cmd *cmd)
{
	u32 const hdr_qws = _pio_cmd_hdr_qws(cmd);

	if (unlikely(!hdr_qws)) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
	return _pio_pkt_send(dms, cmd->qws, hdr_qws, NULL, 0, 0, 0);
}

/*
 * Send @waiter's packet.  A packet for a tracker that has since been
 * cancelled, completed or recycled is dropped: its handle no longer resolves
 * and its page provider may be gone.  Returns 0 (sent or dropped), -EAGAIN
 * (no PIO credits; nothing sent) or another -errno, after which the packet
 * has not been sent or, for -EIO, was sent without its eager payload; the
 * caller cancels the tracker either way.
 */
static int _pio_waiter_send(struct hfi2_dms *dms, struct pio_waiter *waiter)
{
	if (waiter->handle.value && !_handle_to_live_tracker(waiter->handle)) {
		dms->counters.pio_waiter_stale++;
		return 0;
	}
	return _pio_pkt_send(dms, waiter->buf, waiter->hdr_qws,
			     waiter->nbytes ? &waiter->pp : NULL,
			     waiter->byte_offset, waiter->nbytes,
			     waiter->trail_qws);
}

/*
 * Send waiting PIO packets in order until the send context runs out of
 * credits.  Returns the number of packets taken off the waitlist.
 */
static int _pio_waitlist_poll(struct hfi2_dms *dms)
{
	struct hfi2_dms_dlist_element *element;
	struct pio_waiter *waiter;
	int n = 0;

	while (!_pio_waitlist_empty(dms)) {
		struct hfi2_dms_transfer_handle handle;
		int rc;

		element = dms->pio.waitlist.head;
		waiter = container_of(element, struct pio_waiter, element);
		handle = waiter->handle;

		rc = _pio_waiter_send(dms, waiter);
		if (rc == -EAGAIN)
			break;

		/*
		 * Sent, dropped as stale, or failed for good: a failed packet
		 * would fail again and hold back every packet behind it.
		 */
		element = hfi2_dms_impl_dlist_pop(&dms->pio.waitlist);
		hfi2_dms_impl_dlist_push(&dms->pio.freelist, element);
		n++;
		if (!rc) {
			if (waiter->nbytes)
				dms->counters.eager_tx++;
			_pio_start_sent(dms, handle);
			continue;
		}

		dd_dev_err_ratelimited(dms->dd, "Error in pio inject; rc = %d\n", rc);
		/* The packet's transfer cannot complete without it. */
		if (waiter->handle.value) {
			union hfi2_dms_tracker *tracker =
				_handle_to_live_tracker(waiter->handle);

			if (tracker)
				_tracker_cancel(dms, tracker, rc);
		}
	}
	return n;
}

static int _inject_cmd_pio(struct hfi2_dms *dms, union hfi2_dms_proto_cmd *cmd,
			   struct hfi2_dms_transfer_handle handle, bool via_waitlist)
{
	int rc;
	u32 const msg_type = (cmd->bth[0] & 0x00FF0000) >> 16;

	DMS_BUG_ON(!dms);
	DMS_BUG_ON(!cmd);

	if (msg_type < HFI2_DMS_MSG_TYPE_COUNT)
		dms->counters.tx_sent[msg_type]++;

	if (via_waitlist || !_pio_waitlist_empty(dms))
		return _pio_waitlist_append(dms, cmd, handle);

	rc = _pio_cmd_send(dms, cmd);
	if (rc == -EAGAIN)
		return _pio_waitlist_append(dms, cmd, handle);

	if (rc != 0)
		dd_dev_err_ratelimited(dms->dd, "Error in pio inject; rc = %d\n", rc);
	else
		_pio_start_sent(dms, handle);

	return rc;
}
