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
#define DMS_BUG_ON(...) BUG_ON(__VA_ARGS__)
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
					       GFP_DMA);
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
	u64 byte_offset;

	if (WARN_ON_ONCE(!pp || !pp->provider_ctx || !byte_offset_out))
		return -EFAULT;

	mr = pp->provider_ctx;
	if (mr->mode == HFI2_DMS_MR_MODE_VADDR) {
		if (mr_offset < mr->user.addr)
			return -EINVAL;
		byte_offset = mr->region_offset + mr_offset - mr->user.addr;
	} else {
		byte_offset = mr->region_offset + mr_offset;
	}

	if ((byte_offset + size) > mr->extended_vaddr.len)
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
	/* TX side reads from local memory; receive-side write is
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


#include "dms_xfer.c"

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
	ahg_block->backing_mem.kvaddr = dma_alloc_coherent(&dms->dd->pcidev->dev, AHG_BACKING_ALLOC_SIZE, &ahg_block->backing_mem.phys_addr, GFP_DMA);
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
