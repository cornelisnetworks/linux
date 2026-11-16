// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * DMS_RoCE software backend.  See dms_roce.h.  It binds RoCE QPs to the
 * bulksvc-loaned PIO/RX contexts and implements the Stage 1.5 SEND, plain
 * RDMA WRITE/READ, ACK/NAK, replay, and ingress-validation paths.
 */

#include <linux/bitmap.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/dma-buf.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/hash.h>
#include <linux/if_vlan.h>
#include <linux/iommu.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/udp.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/vmalloc.h>
#include <linux/unaligned.h>
#ifdef CONFIG_X86_64
#include <asm/cpufeature.h>
#include <asm/special_insns.h>
#endif
#include <rdma/ib_mad.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_verbs.h>
#include "rvt.h"
#include "rvt_mr.h"
#include "rvt_qp.h"

#include "bulksvc.h"
#include "bulksvc_verbs.h"
#include "chip.h"
#include "dms_roce.h"
#include "eth_hwi.h"
#include "hfi2.h"
#include "pio.h"
#include "qp.h"
#include "rc.h"
#include "roce.h"
#include "roce_pasid.h"
#include "roce_wire.h"
#include "verbs.h"

/*
 * Bring-up trace switch.  0 = counters only (default).  1 = one dd_dev_info
 * per TX/RX/ACK frame with opcode/PSN/QPN/len.  Very chatty on the slow
 * emulator; leave off unless a run stalls and the counters are ambiguous.
 */
static bool roce_hwp_pool = true;

#define HFI2_ROCE_HWP_WIN_BYTES SZ_1M
#define HFI2_ROCE_HWP_WIN_COUNT 256
#define HFI2_ROCE_HWP_WIN_QUARANTINE_MS 1

/*
 * H15: oversized (>= 16 MiB) or row-full MRs have no R_Key entry.  Arm the
 * RIF after validating FIRST's RETH so MIDDLE/LAST can be placed; an unmatched
 * LAST loses its payload.  Software-only mode has no PASID and cannot arm.
 * RUNNING entries, whether software- or hardware-created, ignore end_psn:
 * DMA is confined to the PASID, not the MR or RETH length.  Post-DMA overrun
 * detection cannot undo writes, so hardware placement requires trusted peers.
 */

/*
 * RX copy helpers are load-time only.  Zero leaves the existing synchronous
 * rvt_copy_sge() path untouched; nonzero selects up to HFI2_DMS_ROCE_RX_HELPER_MAX bound kthreads.
 */
static uint roce_rx_helpers;

static __maybe_unused int roce_rx_helpers_set(const char *val, const struct kernel_param *kp)
{
	uint helpers;
	int ret;

	ret = kstrtouint(val, 0, &helpers);
	if (ret)
		return ret;
	if (helpers > HFI2_DMS_ROCE_RX_HELPER_MAX)
		return -EINVAL;
	*(uint *)kp->arg = helpers;
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_rx_helpers_ops = {
	.set = roce_rx_helpers_set,
	.get = param_get_uint,
};
static char *roce_rx_helper_cpus;

/*
 * Helper CPUs already taken by a port.  Every port starts its own helpers,
 * and two busy-polling helpers on one CPU halve each other.
 */
static DEFINE_MUTEX(roce_rx_helper_cpus_lock);
static struct cpumask roce_rx_helper_cpus_used;
/* Worker CPUs of ports seen so far, never picked automatically. */
static struct cpumask roce_rx_worker_cpus;
/*
 * Idle spin before a helper sleeps. Waking a helper out of a deep C-state
 * takes hundreds of microseconds, long enough to overflow the receive
 * buffer at line rate, so the default keeps helpers polling through the
 * short gaps of a busy stream.
 */
static uint roce_rx_helper_spin_us = 10000;

static uint roce_rx_helper_claim_max = 64;

/*
 * While the worker is still adding copies in a receive pass, a helper waits
 * for this many queued entries before claiming, up to
 * roce_rx_helper_claim_wait_ns.  Small claims on a fast stream turn the shared
 * claim cursor into the bottleneck.  Once the worker leaves the pass or starts
 * waiting on the helpers, whatever is queued is claimed at once.
 */
static uint roce_rx_helper_claim_min = 32;

static uint roce_rx_helper_claim_wait_ns = 5000;

static uint roce_rx_helper_min = 1024;
static bool roce_rx_helper_last_hold;
static bool roce_rx_helper_verify;

/*
 * Without DDIO (AMD) the NIC writes eager buffers to DRAM, and a cached copy
 * reads every destination line before overwriting it, so each copied byte
 * crosses the CCD link twice.  Non-temporal stores skip that read.  On Intel
 * the eager data is already in the LLC and the destination is better left
 * cached for the consumer.
 */
static int roce_rx_helper_nt = -1;

static bool roce_rx_helper_use_nt(void)
{
	int nt = READ_ONCE(roce_rx_helper_nt);

	if (nt >= 0)
		return nt;
#ifdef CONFIG_X86
	return boot_cpu_data.x86_vendor == X86_VENDOR_AMD ||
	       boot_cpu_data.x86_vendor == X86_VENDOR_HYGON;
#else
	return false;
#endif
}

/*
 * EAL_ROCEV2_CFG.roce_last_by_software (App D.4.8).  Every WRITE LAST is
 * delivered to software with its payload, whether or not a RIF entry
 * matches.  Without it a LAST that finds no entry - its FIRST went to
 * software for an MR over 16 MiB, or the row was full - arrives header-only
 * and its payload is lost on every retry (ASIC-13002).
 *
 * The cost is that hardware never retires the entry it created at FIRST:
 * the diverted LAST leaves it valid and RUNNING, where it blocks this QP's
 * next hardware FIRST and holds one of the row's buckets.  Software takes
 * over each hardware-started burst from its FIRST report, finishes it at
 * the LAST, and invalidates the entry itself.
 */
static bool roce_last_by_software;

static bool roce_rif_pasid_full_sweep;

bool hfi2_dms_roce_last_by_software(void)
{
	return roce_last_by_software;
}

/* Diagnostic: EAL MIDDLE header suppression; 0 reports every header. */
static uint roce_hdr_suppress;

u32 hfi2_dms_roce_hdr_suppress(void)
{
	return min_t(u32, roce_hdr_suppress, 0xff);
}

/*
 * Recover a WRITE FIRST hardware diverted with end_state 0x01 although its MR
 * has an R_Key entry: the RIF row had no bucket for it, or this QP's own
 * entry was left valid and blocks it.  With roce_last_by_software off such a
 * burst cannot finish in software - its LAST arrives header-only
 * (ASIC-13002) - so free what the row holds without doing useful work and
 * NAK the FIRST at its own PSN.  The resent FIRST then takes the hardware
 * path, LAST included.
 */
static bool roce_rif_reclaim = true;

/* NAKs per FIRST PSN before the FIRST is consumed in software instead. */
#define HFI2_ROCE_RIF_RECLAIM_TRIES 8

static void roce_lbs_invalidate(struct hfi2_dms_roce_qp *rqp, bool early);
static void roce_vrma_reset(struct hfi2_dms_roce_qp *rqp);
static void roce_rif_release(struct hfi2_dms_roce_qp *rqp);
static int roce_rif_invalidate_qp(struct hfi2_dms_roce_qp *rqp);
static int roce_rif_invalidate_qpn(struct hfi2_dms_roce_qp *rqp, u8 cleanup);

static bool roce_debug_trace;
static uint roce_drop_rx_skip;
static bool roce_drop_rx_once;
static bool roce_fail_tx_pio_once;

#if HFI2_DMS_ROCE_INJECT
static bool roce_inject_hwp_cleanup_drain;
static uint roce_inject_hwp_donor;
static bool roce_inject_sdma_preaccept_shutdown_once;
static bool roce_inject_sdma_callback_error_once;
static bool roce_inject_sdma_hold_for_ack_once;
static uint roce_inject_request_emitter;
#endif

static uint roce_fail_tx_pio_period;

/*
 * Performance controls default to the established wire behavior.  The
 * alternative modes exist only for bounded same-kernel A/B runs.
 */
static bool roce_perf_stats;
/*
 * The s_lock hold telemetry (s_lock_hold_max_ns, s_lock_hold_over_100us)
 * reads the clock twice per worker turn.  At small message rates that is a
 * few percent of the worker, so only one turn in this many is timed;
 * s_lock_hold_samples counts the turns that were.  roce_perf_stats times
 * every turn.  0 disables the sampling.
 */
static uint roce_lock_hold_sample = 64;
static uint roce_tx_packet_quantum = 4;
/*
 * 4 packets per bundle caps every RoCE operation near 70 Gb/s at PMTU 4096,
 * with or without hardware placement.  128 is the smallest size at which
 * hardware-placed WRITE reaches its peak; software receive is flat from 64
 * up.  256 gained nothing and one single-QP READ run was slower.
 */
static uint roce_sdma_bundle_packets = 128;

/*
 * Path MTU of every hardware-placed (VRMA) RoCE QP.  EAL places a MIDDLE at
 * start_vaddr + stride * (PSN - start_psn), with the stride taken from the
 * one per-function field EAL_ROCEV2_CFG.rocev2_mtu, so all hardware-placed
 * QPs share one path MTU.  Programmed once at backend init; a QP asking for
 * a different path MTU is refused at modify-QP.  Unused with roce_by_software,
 * where nothing is hardware-placed and any path MTU is accepted.
 */
static uint roce_vrma_mtu = 4096;

static __maybe_unused int roce_vrma_mtu_set(const char *val, const struct kernel_param *kp)
{
	uint mtu;
	int ret;

	ret = kstrtouint(val, 0, &mtu);
	if (ret)
		return ret;
	if (mtu != 1024 && mtu != 2048 && mtu != 4096 && mtu != 8192)
		return -EINVAL;
	*(uint *)kp->arg = mtu;
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_vrma_mtu_ops = {
	.set = roce_vrma_mtu_set,
	.get = param_get_uint,
};


/*
 * Device-wide RoCE transmit path, fixed at load: "sdma" (default) sends
 * every request and response of every QP through the QP's SDMA engine,
 * "pio" sends all of them through the RoCE PIO send context.  Read only
 * at backend init, so a device never mixes the two after it is up.  Any
 * other value fails the module load rather than picking a mode.
 */
static bool roce_tx_pio_only;

static __maybe_unused int roce_tx_emitter_set(const char *val, const struct kernel_param *kp)
{
	if (sysfs_streq(val, "sdma"))
		*(bool *)kp->arg = false;
	else if (sysfs_streq(val, "pio"))
		*(bool *)kp->arg = true;
	else
		return -EINVAL;
	return 0;
}

static __maybe_unused int roce_tx_emitter_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%s\n", *(bool *)kp->arg ? "pio" : "sdma");
}

static __maybe_unused const struct kernel_param_ops roce_tx_emitter_ops = {
	.set = roce_tx_emitter_set,
	.get = roce_tx_emitter_get,
};

static uint roce_pio_max_bytes = 512;

static __maybe_unused int roce_sdma_bundle_packets_set(const char *val,
					const struct kernel_param *kp)
{
	uint packets;
	int ret;

	ret = kstrtouint(val, 0, &packets);
	if (ret)
		return ret;
	if (packets != 4 && packets != 16 && packets != 32 && packets != 64 &&
	    packets != 128 && packets != 256 && packets != 512)
		return -EINVAL;
	if (packets > HFI2_DMS_ROCE_SDMA_BUNDLE_PACKET_MAX)
		return -EINVAL;
	WRITE_ONCE(*(uint *)kp->arg, packets);
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_sdma_bundle_packets_ops = {
	.set = roce_sdma_bundle_packets_set,
	.get = param_get_uint,
};

/*
 * SDMA bundles in flight.  Each QP lane may hold roce_sdma_qp_bundles and
 * each loaned engine roce_sdma_engine_bundles, across all its QPs.  With
 * many QPs per engine the engine cap is what the sender parks on, so it
 * must cover several QPs' windows; with few QPs the per-QP cap bounds how
 * far one QP runs ahead of its ACKs.  Read once at backend init.
 */
static uint roce_sdma_qp_bundles = 4;

static uint roce_sdma_engine_bundles = 16;

static u16 roce_sdma_engine_bundle_cap(void)
{
	return clamp_t(uint, roce_sdma_engine_bundles, 1,
		       HFI2_DMS_ROCE_SDMA_ENGINE_BUNDLE_LIMIT);
}

/*
 * One command page per packet: the engine page budget must cover every
 * bundle the engine admits at the default 128-packet size, or the page
 * check, not the bundle cap, is what the sender parks on.
 */
static u16 roce_sdma_engine_page_cap(void)
{
	return max_t(u32, HFI2_DMS_ROCE_SDMA_ENGINE_PAGE_CAP,
		     roce_sdma_engine_bundle_cap() * 128);
}

/*
 * A request no longer than this is copied into its SDMA command page and
 * sent as one descriptor, as PIO would copy it.  The copy ends the source's
 * part in the transfer, so no source provider is built, walked, or released,
 * and the descriptor accounting is a constant.  The wire image is identical.
 * 0 sends every request by gather.
 */
#define HFI2_DMS_ROCE_SDMA_INLINE_MAX 2048
static uint roce_sdma_inline_bytes = 512;

static __maybe_unused int roce_sdma_inline_bytes_set(const char *val,
				      const struct kernel_param *kp)
{
	uint bytes;
	int ret;

	ret = kstrtouint(val, 0, &bytes);
	if (ret)
		return ret;
	if (bytes > HFI2_DMS_ROCE_SDMA_INLINE_MAX)
		return -EINVAL;
	WRITE_ONCE(*(uint *)kp->arg, bytes);
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_sdma_inline_bytes_ops = {
	.set = roce_sdma_inline_bytes_set,
	.get = param_get_uint,
};

static bool roce_sdma_one_pass = true;

static __maybe_unused int roce_tx_packet_quantum_set(const char *val,
				      const struct kernel_param *kp)
{
	uint quantum;
	int ret;

	ret = kstrtouint(val, 0, &quantum);
	if (ret)
		return ret;
	if (quantum < 1 || quantum > 512)
		return -EINVAL;
	WRITE_ONCE(*(uint *)kp->arg, quantum);
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_tx_packet_quantum_ops = {
	.set = roce_tx_packet_quantum_set,
	.get = param_get_uint,
};
static uint roce_pio_fence_interval;
/*
 * Each forced credit return costs one status write to host memory, and the
 * context threshold still returns credits without it.  Measured on CN6000
 * PIO (4 QPs, 1 MiB WRITE/SEND): every 16 packets beats every packet by
 * 1-3 Gb/s; threshold alone (0) re-reads the returned count twice as
 * often and loses 1-3 Gb/s, with or without early return.
 */
static uint roce_pio_credit_return_interval = 16;
/*
 * CN6000 receive placement ignores BTH PadCnt: a hardware-placed WRITE LAST
 * or ONLY is placed to the Ethernet byte count, so the pad bytes an IBTA
 * sender appends to an unaligned payload land in host memory past the end of
 * the WRITE (measured: a 1-byte WRITE ONLY places 4 bytes).  Omitting them -
 * PadCnt 0 and an Ethernet length that is not a dword multiple - places
 * byte-exact, and EAL computes the ICRC over what is sent.  The result is
 * not an IBTA frame and is for CN6000 peers only.  Load-time, because a
 * bundle's descriptor count and its frames must agree on the pad.
 *
 * A short frame is the exception.  EAL neither pads a frame to the
 * Ethernet minimum on transmit nor accepts a shorter one on receive (a
 * runt, HAS 4.5.2.5.12): the 54 header bytes, the extension header, the
 * payload, the pad and the ICRC must reach 60.  A BTH-only packet with one
 * payload byte - a SEND or WRITE LAST, a SEND ONLY - is 59 without pad, and
 * a zero-length SEND ONLY is 58 with or without it.  Pad would make the
 * one-byte case legal but a hardware-placed WRITE LAST still writes it, so
 * such a frame carries an 802.1Q priority tag (VID 0) instead: four bytes
 * no receiver places, and which needs no VLAN configured at either end.
 * With PFC on every frame is tagged anyway (roce_tx_vlan_id()).
 */
static bool roce_unpadded = true;

static inline u8 roce_bth_pad(u32 len)
{
	return roce_unpadded ? 0 : (-len) & 3;
}

/*
 * Advance a non-releasing SGE cursor by @len bytes; same result as
 * rvt_update_sge(ss, len, false).
 *
 * rvt_update_sge() is out of line so its full body is not copied into every
 * caller, but the RoCE per-packet loops call it once per frame.  Handle the
 * per-frame case here: kernel memory, still inside the current SGE, possibly
 * stepping to the next MR segment (a 4 KiB MTU frame on 4 KiB pages ends a
 * segment every time).  Ending an SGE and dmabuf memory go to rvt_update_sge().
 */
static inline void roce_advance_sge(struct rvt_sge_state *ss, u32 len)
{
	struct rvt_sge *sge = &ss->sge;

	if (unlikely(sge->mem.type != RVT_MEM_KERNEL ||
		     len >= sge->sge_length)) {
		rvt_update_sge(ss, len, false);
		return;
	}
	sge->mem.vaddr += len;
	sge->mem.length -= len;
	sge->sge_length -= len;
	if (sge->mem.length || !sge->mr->lkey)
		return;
	if (unlikely(++sge->n >= RVT_SEGSZ)) {
		if (++sge->m >= sge->mr->mapsz)
			return;
		sge->n = 0;
	}
	sge->mem = sge->mr->map[sge->m]->segs[sge->n];
}

/*
 * rvt_skip_sge(ss, length, false) built on roce_advance_sge().  Placement
 * reports skip whole hardware-placed bursts, one MR segment per step, so
 * this runs once per placed page and must not call out per step either.
 */
static inline void roce_skip_sge(struct rvt_sge_state *ss, u32 length)
{
	while (length) {
		u32 len = rvt_get_sge_length(&ss->sge, length);

		if (WARN_ON_ONCE(!len))
			return;
		roce_advance_sge(ss, len);
		length -= len;
	}
}

/* Gather uses tx_off directly; catch up the CPU cursor only before use. */
static void roce_tx_sge_sync(struct hfi2_dms_roce_qp *rqp)
{
	roce_skip_sge(&rqp->tx_ss, rqp->tx_off - rqp->tx_ss_off);
	rqp->tx_ss_off = rqp->tx_off;
}

/* Whether a frame with this extension header, payload and pad is a runt. */
static inline bool roce_is_runt(u32 ext_len, u32 len, u8 pad)
{
	return ext_len + len + pad < 2;
}

/*
 * VLAN ID of the 802.1Q header a frame carries: the GID's VLAN, else VID 0
 * (a priority tag) for every frame of a PFC QP and for a runt, else
 * HFI2_ROCE_NO_VLAN for none.  See hfi2_qp_priv_roce.pfc_tag.
 */
static inline u16 roce_tx_vlan_id(const struct hfi2_qp_priv_roce *priv,
				  u32 ext_len, u32 len, u8 pad)
{
	if (priv->vlan_id != HFI2_ROCE_NO_VLAN)
		return priv->vlan_id;
	return priv->pfc_tag || roce_is_runt(ext_len, len, pad) ?
		0 : HFI2_ROCE_NO_VLAN;
}

/*
 * PCP of that header: a PFC QP's priority, which also picks the PBC VL
 * (roce_build_egress_geometry()), else 0.
 */
static inline u8 roce_tx_pcp(const struct hfi2_qp_priv_roce *priv)
{
	return priv->pfc_tag ? priv->pcp : 0;
}

static inline void roce_tx_addr_vlan(struct hfi2_roce_wire_addr *addr,
				     const struct hfi2_qp_priv_roce *priv,
				     u32 ext_len, u32 len, u8 pad)
{
	addr->vlan_id = roce_tx_vlan_id(priv, ext_len, len, pad);
	addr->vlan_prio = roce_tx_pcp(priv);
}

static bool roce_direct_gather = true;
/* Requests and responses default to SDMA when engines are loaned. */
static bool roce_read_resp_sdma = true;
/*
 * CYR HAS A00418 §7.2.7: an interrupt inside a sequence of 8-byte WC stores
 * flushes a partially occupied WC buffer early, and the remaining stores are
 * "then delayed until some arbitrarily later point".  A 64-byte store is the
 * HAS's only complete mitigation, and MOVDIR64B is the cheapest form of it --
 * no kernel FPU state handling, and it cannot cross the 64-byte send-block
 * boundary.
 *
 * Off by default because it measured neutral once roce_pio_span() removed the
 * per-qword branch and memcpy overhead: across 1 QP ib_write_bw from 64 KB to
 * 4 MB, in both ingress modes, store time converged to ~330 ns/packet whether
 * the block went out as one 64-byte store or eight 8-byte stores, with the
 * sign of the difference flipping by size.  The store is no longer the
 * bottleneck, so the path cannot pay for the per-packet wmb() it forces (see
 * roce_pio_copy_end()).  Kept as a lever for a future workload or a wider link
 * where the store becomes the limit again.
 */
static bool roce_pio_movdir64b;

static __maybe_unused int roce_fail_tx_pio_period_set(const char *val,
				       const struct kernel_param *kp)
{
	struct hfi2_devdata *dd;
	unsigned long index;
	int ret;

	ret = param_set_uint(val, kp);
	if (ret)
		return ret;

	xa_for_each(&hfi2_dev_table, index, dd) {
		if (dd->bulksvc && dd->bulksvc->dms_roce &&
		    dd->bulksvc->dms_roce->initialized)
			atomic_set(&dd->bulksvc->dms_roce->pio_fail_attempts, 0);
	}
	return 0;
}

static __maybe_unused const struct kernel_param_ops roce_fail_tx_pio_period_ops = {
	.set = roce_fail_tx_pio_period_set,
	.get = param_get_uint,
};

#define roce_trace(dd, fmt, ...) \
	do { \
		if (unlikely(roce_debug_trace)) \
			dd_dev_info((dd), "roce: " fmt, ##__VA_ARGS__); \
	} while (0)

/* PBC L2 field for EAL bypass frames; matches the netdev TX path. */
#define ROCE_PBC_L2 2
/* DLID nibble EAL requires to be non-zero (multicast range), like eth_tx. */
#define ROCE_PBC_DLID_23_20 0xf
/* Fixed 16-byte EAL egress encapsulation header. */
#define EAL_EGRESS_HDR_BYTES sizeof(struct eal_egress_header)

static bool roce_frame_vlan_tagged(const u8 *buf)
{
	return get_unaligned_be16(buf + EAL_EGRESS_HDR_BYTES + 2 * ETH_ALEN) ==
		ETH_P_8021Q;
}
/* Round a byte count up to whole 8-byte quantities. */
#define ROCE_QWORD_ROUND_UP(n) (((n) + 7) >> 3)
/* Low @b bits of @v. */
#define ROCE_LSBITS(v, b) ((u64)(v) & ((1ULL << (b)) - 1))
#define ROCE_PIO_QWS_PER_BLOCK (PIO_BLOCK_SIZE / sizeof(u64))
#define ROCE_PIO_TX_QP_BUDGET 64
#define ROCE_PIO_RX_BUDGET 2048
/*
 * WQEs retired per QP-ERROR flush pass.  The send queue can be
 * hfi2_max_qp_wrs (0x3FFF) deep and the flush runs under s_lock with
 * interrupts disabled, so draining it whole in one pass is not an option.
 */
#define ROCE_PIO_TX_FLUSH_BUDGET 64
#if HFI2_DMS_ROCE_INJECT
#define HFI2_DMS_ROCE_INJECT_FILL 0xa5
#endif

/*
 * Derive the per-engine descriptor budget from the SDMA ring rather than a
 * constant.  A constant silently disagrees with an sdma_descq_cnt= override:
 * larger than the ring fails engine setup with -ENOSPC at dms_roce.c's
 * descq_cnt guard, smaller starves a bundle of budget the ring could serve.
 * The ring reserves two entries, hence the -2.
 */
static u32 roce_sdma_engine_descriptor_cap(void)
{
	return (u32)hfi2_sdma_get_descq_cnt() - 2;
}

static u32 roce_sdma_engine_batch_nodes(void)
{
	return DIV_ROUND_UP(roce_sdma_engine_descriptor_cap(),
			    HFI2_DMS_ROCE_SDMA_BATCH_NODE_DESCRIPTOR_CAP) +
	       (roce_sdma_engine_bundle_cap() - 1);
}

/*
 * rdmavt keeps wqe->psn, wqe->lpsn, and qp->s_next_psn as unmasked u32
 * values. RoCE BTH and the RIF use 24 bits, so every rdmavt-to-RoCE PSN
 * crossing uses roce_psn() and every comparison uses roce_cmp_psn().
 */
static u32 roce_psn(u32 psn)
{
	return psn & HFI2_ROCE_PSN_MASK;
}

static s32 roce_cmp_psn(u32 a, u32 b)
{
	/* Sign-extend the low 24-bit modular difference. */
	return (s32)((roce_psn(a) - roce_psn(b)) << 8) >> 8;
}

static bool roce_read_response_opcode(u8 opcode)
{
	return opcode >= IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST &&
	       opcode <= IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
}

static bool roce_read_write_opcode(u8 opcode)
{
	return opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_LAST ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY;
}

static bool roce_write_answer_data_opcode(u8 opcode)
{
	return roce_read_write_opcode(opcode);
}

static bool roce_request_opcode(u8 opcode)
{
	switch (opcode) {
	case IB_OPCODE_RC_SEND_FIRST:
	case IB_OPCODE_RC_SEND_MIDDLE:
	case IB_OPCODE_RC_SEND_LAST:
	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE:
	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
	case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
	case IB_OPCODE_RC_RDMA_WRITE_LAST:
	case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_READ_REQUEST:
	case IB_OPCODE_RC_COMPARE_SWAP:
	case IB_OPCODE_RC_FETCH_ADD:
		return true;
	default:
		return false;
	}
}

static bool roce_answer_opcode(u8 opcode)
{
	return roce_read_write_opcode(opcode) || roce_read_response_opcode(opcode) ||
	       opcode == IB_OPCODE_RC_ACKNOWLEDGE ||
	       opcode == IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE;
}

static bool roce_hwp_write_mode(const struct hfi2_dms_roce *roce)
{
	return READ_ONCE(roce->hwp_mode);
}

/*
 * PSN-space split: private-write responder answers target the requester's
 * alias QPN, while requester traffic retains the base QPN.
 */
static u32 roce_answer_dest_qpn(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv)
{
	u32 qpn = priv->dest_qpn;

	if (qpn == IB_MULTICAST_QPN)
		return qpn;
	if (roce_hwp_write_mode(rqp->roce))
		qpn |= HFI2_ROCE_QPN_ALIAS_BIT;
	return qpn;
}

static bool roce_write_first_opcode(u8 opcode)
{
	return opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
}

static bool roce_write_last_opcode(u8 opcode)
{
	return opcode == IB_OPCODE_RC_RDMA_WRITE_LAST ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
}

static inline bool _sctxt_active(struct send_context *sc)
{
	return sc && (sc->flags & SCF_ENABLED);
}

/*
 * Why the RoCE send context is not taking frames.  A halt, freeze or link
 * bounce stops it only until hfi2_sc_restart(), hfi2_pio_kernel_unfreeze() or
 * hfi2_pio_kernel_linkup() enables it again, so park the QP like a credit stall
 * (-ENOSPC) and let roce_pio_restart_kick() requeue it, instead of flushing
 * it.  Anything else means the context is gone.
 */
static int roce_pio_stopped_rc(struct send_context *sc)
{
	u16 flags = READ_ONCE(sc->flags);

	if (!(flags & SCF_IN_FREE) &&
	    (flags & (SCF_HALTED | SCF_FROZEN | SCF_LINK_DOWN)))
		return -ENOSPC;
	return -ECOMM;
}

static void roce_stride_reset_csr(struct hfi2_dms_roce *roce);
static void roce_stride_program(struct hfi2_dms_roce *roce);
static void hfi2_dms_roce_sdma_drain_callbacks(struct hfi2_dms_roce *roce);
static void roce_sdma_cancel_requested(struct hfi2_dms_roce *roce);
static int roce_ack_retry_pending(struct hfi2_dms_roce_qp *rqp,
				  struct hfi2_qp_priv_roce *priv);
static void roce_rx_helpers_drain(struct hfi2_dms_roce *roce);
static bool roce_ack_behind_resp(struct rvt_qp *qp);
static int roce_build_ack_frame(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv, u32 psn, u8 syndrome,
				u8 *frame, size_t frame_sz, size_t *frame_len);
static int roce_sdma_send_ack(struct hfi2_dms_roce_qp *rqp,
			      struct hfi2_qp_priv_roce *priv, u32 psn, u8 syndrome);
static void roce_resp_xfer_abandon(struct hfi2_dms_roce_qp *rqp);
static struct ib_other_headers *
roce_vrma_report_bth(const struct eal_ingress_vrma_header *ih, u32 ext_len);
static bool roce_vrma_report_psn(const struct eal_ingress_vrma_header *ih,
				 u32 *psn);
static void roce_requester_read_write_resp(struct hfi2_dms_roce_qp *rqp,
					   const struct hfi2_roce_wire_rx *rx);

static bool roce_read_write_eligible(struct hfi2_dms_roce_qp *rqp,
				     struct hfi2_qp_priv_roce *priv,
				     struct rvt_swqe *wqe, u64 *dest_va,
				     u32 *dest_rkey, bool count_ineligible);
static void roce_hwp_window_release_wqe(struct hfi2_dms_roce_qp *rqp,
					const struct rvt_swqe *wqe);
static void roce_hwp_window_release_all(struct hfi2_dms_roce_qp *rqp);
static bool roce_hwp_cleanup_start(struct hfi2_dms_roce_qp *rqp);
static bool roce_hwp_defer_error(struct hfi2_dms_roce_qp *rqp,
				 struct rvt_swqe *wqe, enum ib_wc_status status,
				 enum rvt_qp_lock_state lock_state);
static int roce_hwp_pool_init(struct hfi2_dms_roce *roce);
static void roce_hwp_pool_quiesce(struct hfi2_dms_roce *roce);
static void roce_hwp_wait_donor_holds(struct hfi2_dms_roce_qp *rqp);
static void roce_hwp_pool_exit(struct hfi2_dms_roce *roce);
static int roce_inject_poll(struct hfi2_dms_roce *roce);
static void roce_inject_init(struct hfi2_dms_roce *roce);
static void roce_inject_teardown(struct hfi2_dms_roce *roce);
static bool roce_wqe_is_rd_atomic(enum ib_wr_opcode op);
static void roce_wqe_clear_read_write_reply(struct hfi2_dms_roce_qp *rqp,
					    const struct rvt_swqe *wqe);

/*
 * The default egress checks are OPA-shaped: CheckSLID constrains LRH.SLID to
 * the port's LID and Check16BVLMapping requires SC2VL_t[SC] == PBC.PbcVL.  A
 * 16B RoCEv2 frame carries L4=ETH(0x78), VL 0 and SLID nibble 0xf, so both
 * fail by construction (SendCtxtCheck -> DisallowedPacket, VLMappingErr16B /
 * SLIDErr16B).  cne_enable_txq() relaxes the same set per netdev TX queue.
 *
 * A helper rather than open-coded because this state is per (egress port,
 * send context) on CYR: every context the RoCE path adopts needs its own
 * relaxation, and a missed one does not drop frames - a PIO integrity
 * failure is an early error that HALTS the context, surfacing far from its
 * cause.
 */
static void roce_adopt_send_ctxt(struct hfi2_devdata *dd,
				 struct hfi2_pportdata *ppd,
				 struct send_context *sc,
				 struct hfi2_dms_roce *roce)
{
	u64 val;

	if (!sc)
		return;

	WRITE_ONCE(sc->roce_owner, roce);
	val = read_epsc_csr(dd, ppd->hw_pidx, sc->hw_context,
			    dd->params->send_ctxt_check_enable_reg);
	val |= CYR_SEND_CTXT_CHECK_ENABLE_L2_TYPE16BALLOWED_SMASK;
	val &= ~CYR_SEND_CTXT_CHECK_ENABLE_CHECK16BVL_MAPPING_SMASK;
	val &= ~CYR_SEND_CTXT_CHECK_ENABLE_CHECK16BSLID_SMASK;
	write_epsc_csr(dd, ppd->hw_pidx, sc->hw_context,
		       dd->params->send_ctxt_check_enable_reg, val);

	val = read_epsc_csr(dd, ppd->hw_pidx, sc->hw_context,
			    CYR_SEND_CTXT_CHECK_L4_0X40_0X7F);
	val |= 1ULL << (0x78 - 0x40);
	write_epsc_csr(dd, ppd->hw_pidx, sc->hw_context,
		       CYR_SEND_CTXT_CHECK_L4_0X40_0X7F, val);

	/* Read back: a relaxation that failed to take halts the context. */
	val = read_epsc_csr(dd, ppd->hw_pidx, sc->hw_context,
			    dd->params->send_ctxt_check_enable_reg);
	if (!(val & CYR_SEND_CTXT_CHECK_ENABLE_L2_TYPE16BALLOWED_SMASK) ||
	    (val & CYR_SEND_CTXT_CHECK_ENABLE_CHECK16BVL_MAPPING_SMASK) ||
	    (val & CYR_SEND_CTXT_CHECK_ENABLE_CHECK16BSLID_SMASK))
		dd_dev_err(dd,
			   "roce: sc %u SendCtxtCheckEnable read back 0x%016llx on port %u - a RoCEv2 frame on this context will be rejected as DisallowedPacket and halt it\n",
			   sc->hw_context, val, ppd->hw_pidx);
}

enum roce_rif_cleanup {
	ROCE_RIF_RELEASE = BIT(0),
	ROCE_RIF_CLEAN_QP = BIT(1),
	ROCE_RIF_CLEAN_LBS = BIT(2),
	ROCE_RIF_CLEAN_BASE = BIT(3),
	ROCE_RIF_CLEAN_ALIAS = BIT(4),
};

enum roce_rif_arm_kind {
	ROCE_RIF_ARM_NONE,
	ROCE_RIF_ARM_H15,
};

struct roce_rif_cleanup_state {
	u32 epoch;
	u32 qpn;
	s16 h15_bucket;
	s16 lbs_bucket;
	bool lbs_entry;
	bool lbs_cleaned;
	bool release;
	bool superseded;
	unsigned long cleared;
	u32 alias_invalidated;
	u32 invalidate_read_err;
};

static void roce_rif_cleanup_snapshot(struct hfi2_dms_roce_qp *rqp,
				      struct roce_rif_cleanup_state *state);
static void roce_rif_cleanup_apply(struct hfi2_dms_roce_qp *rqp,
				   const struct roce_rif_cleanup_state *state);
static void roce_lbs_invalidate_csr(struct hfi2_dms_roce *roce,
				    struct roce_rif_cleanup_state *state, bool early);
static bool roce_rif_enter(struct hfi2_dms_roce *roce);
static void roce_rif_leave(struct hfi2_dms_roce *roce, bool entered);
static void roce_rif_progress(struct hfi2_dms_roce *roce);
static void roce_rif_flush_invalidations(struct hfi2_dms_roce *roce);
static void roce_rif_cancel(struct hfi2_dms_roce_qp *rqp);
static void roce_rif_wait(struct hfi2_dms_roce_qp *rqp);
static void roce_rif_queue(struct hfi2_dms_roce_qp *rqp);
static void roce_rif_defer_arm(struct hfi2_dms_roce_qp *rqp,
			       const struct hfi2_dms_roce_rif_entry *entry,
			       struct rvt_mregion *mr,
			       enum roce_rif_arm_kind kind);
static void roce_rif_write(struct hfi2_dms_roce *roce, const u64 wdata[3]);
static int roce_tomb_evict(struct hfi2_dms_roce *roce, int row);
static int roce_tomb_reuse(struct hfi2_dms_roce_qp *rqp);
static void roce_tomb_destroy(struct hfi2_dms_roce_qp *rqp);
static void roce_rkey_write(struct hfi2_dms_roce *roce, const u64 wdata[3]);
static void roce_rif_pasid_rows_destroy(struct hfi2_dms_roce *roce);
static struct roce_rif_rows *
roce_rif_pasid_take(struct hfi2_dms_roce *roce, u32 pasid);

/*
 * RX copy helpers share one single-producer, multi-consumer queue.  The RX
 * worker appends copies in packet order; any idle helper claims the next
 * few entries with one cmpxchg, so no helper is picked per copy and an idle
 * helper takes over whatever is queued.  Completion is a per-entry stamp,
 * and the worker retires the completed prefix in order, so a fence (a head
 * update, a drain) is one compare against @retired.
 *
 * Copies to the same destination page must land in packet order (a later
 * WRITE to the same bytes wins).  Two such copies can be claimed by
 * different helpers, so the worker records the previous in-flight entry for
 * the page's hash slot in @dep and the helper waits for it before copying.
 * Each entry waits for its predecessor in the slot, so the chain covers
 * every older entry of the slot; a collision only adds a needless wait.
 */
/*
 * Copy one claimed entry.  The caller publishes done_seq.  Returns true when
 * it had to wait for an earlier overlapping entry.
 */
static bool roce_rx_copy_desc(struct hfi2_dms_roce_rx_queue *q,
			      struct hfi2_dms_roce_rx_copy_desc *desc, bool nt)
{
	struct hfi2_dms_roce_rx_copy_desc *dep;
	bool waited = false;

	if (desc->dep) {
		/*
		 * The earlier entry was claimed before this one, so it is being
		 * copied now.  Its slot cannot be reused until it retires, and
		 * reuse only raises @done_seq, so ">=" is safe.
		 */
		dep = &q->ring[desc->dep & HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
		/* Pairs with the dep copier's done_seq release. */
		while (smp_load_acquire(&dep->done_seq) < desc->dep) {
			waited = true;
			cpu_relax();
		}
	}
	desc->err = 0;
	if (desc->dmabuf_do) {
		desc->err = hfi2_dmabuf_memcpy(desc->dst.dmabuf_do,
					       rvt_to_kseg((void *)desc->src,
							   desc->len));
	} else if (nt) {
		memcpy_flushcache(desc->dst.kaddr, desc->src, desc->len);
		/* Order the NT stores before the done_seq release. */
		wmb();
	} else {
		memcpy(desc->dst.kaddr, desc->src, desc->len);
	}
	return waited;
}

static int roce_rx_helper_thread(void *data)
{
	struct hfi2_dms_roce_rx_helper *helper = data;
	struct hfi2_dms_roce_rx_queue *q = helper->q;
	struct hfi2_dms_roce_rx_copy_desc *desc;
	u64 idle_start = 0, batch_start = 0;
	u64 head, seq, end;
	s64 claim;
	bool nt;

	for (;;) {
		/* Pairs with the worker's head release: descriptors are filled. */
		head = smp_load_acquire(&q->head);
		claim = atomic64_read(&q->claim);
		if ((u64)claim >= head) {
			if (kthread_should_stop())
				break;
			if (!idle_start)
				idle_start = ktime_get_ns();
			if (ktime_get_ns() - idle_start <
			    (u64)READ_ONCE(roce_rx_helper_spin_us) * NSEC_PER_USEC) {
				cpu_relax();
				continue;
			}
			set_current_state(TASK_INTERRUPTIBLE);
			atomic_inc(&q->sleepers);
			/*
			 * Order the sleepers count before the head recheck, so
			 * either this sees the new head or the worker's next
			 * kick sees a sleeper.
			 */
			smp_mb__after_atomic();
			head = smp_load_acquire(&q->head); /* see loop top */
			if ((u64)atomic64_read(&q->claim) >= head &&
			    !kthread_should_stop())
				schedule();
			atomic_dec(&q->sleepers);
			__set_current_state(TASK_RUNNING);
			idle_start = 0;
			continue;
		}
		/*
		 * Let the backlog build while the worker is still filling, so
		 * each claim covers a useful batch.  The wait is bounded and
		 * ends as soon as the worker stops publishing.
		 */
		if (head - (u64)claim < READ_ONCE(roce_rx_helper_claim_min) &&
		    READ_ONCE(q->filling)) {
			if (!batch_start)
				batch_start = ktime_get_ns();
			if (ktime_get_ns() - batch_start <
			    READ_ONCE(roce_rx_helper_claim_wait_ns)) {
				cpu_relax();
				continue;
			}
		}
		batch_start = 0;
		/*
		 * Claim an even share of the backlog, so a deep queue costs one
		 * contended cmpxchg per several copies instead of one per four.
		 */
		end = min_t(u64, (head - (u64)claim) / helper->count,
			    READ_ONCE(roce_rx_helper_claim_max));
		end = max_t(u64, end, HFI2_DMS_ROCE_RX_CLAIM_BATCH);
		end = min_t(u64, head, (u64)claim + end);
		/*
		 * A claimed entry must reach done_seq without yielding: the
		 * worker and roce_rx_helpers_wait_qp() spin on it with IRQs
		 * off, possibly on this CPU, so a preempted claim would never
		 * finish.  Unclaimed entries they copy themselves.
		 */
		preempt_disable();
		if (!atomic64_try_cmpxchg(&q->claim, &claim, end)) {
			preempt_enable();
			continue;
		}
		idle_start = 0;
		helper->wakeups++;
		nt = roce_rx_helper_use_nt();

		for (seq = (u64)claim + 1; seq <= end; seq++) {
			desc = &q->ring[seq & HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
			if (roce_rx_copy_desc(q, desc, nt))
				helper->dep_waits++;
			if (!desc->dmabuf_do && READ_ONCE(roce_rx_helper_verify) &&
			    memcmp(desc->dst.kaddr, desc->src, desc->len))
				helper->verify_bad++;
			helper->copies++;
			helper->bytes += desc->len;
			/* Publish the copied bytes before the worker retires the entry. */
			smp_store_release(&desc->done_seq, seq);
		}
		preempt_enable();
		cond_resched();
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static bool roce_rx_helpers_enabled(const struct hfi2_dms_roce *roce)
{
	return READ_ONCE(roce->rx_helper_count);
}

static void roce_rx_helpers_kick(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_rx_queue *q = &roce->rx_q;
	u8 i;

	/* With no helper threads nothing is published and nobody sleeps. */
	if (!roce_rx_helpers_enabled(roce))
		return;
	if (q->head != q->submitted)
		/* Publish filled descriptors; pairs with the helper's acquire. */
		smp_store_release(&q->head, q->submitted);
	/*
	 * Pairs with smp_mb__after_atomic() in roce_rx_helper_thread(): order
	 * the head store before the sleepers load, so either the helper sees
	 * the new head or this sees the sleeper.  Without it a helper could
	 * sleep on work published just before an idle gap with no later kick.
	 */
	smp_mb();
	if (unlikely(atomic_read(&q->sleepers)) && q->retired != q->submitted)
		for (i = 0; i < roce->rx_helper_count; i++)
			wake_up_process(roce->rx_helpers[i].task);
}

static void roce_rx_helpers_retire(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_rx_queue *q = &roce->rx_q;
	struct hfi2_dms_roce_rx_copy_desc *desc;

	while (q->retired != q->submitted) {
		desc = &q->ring[(q->retired + 1) &
				HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
		/* The acquire observes the completed memcpy before rvt_put_mr(). */
		if (smp_load_acquire(&desc->done_seq) != q->retired + 1)
			break;
		if (desc->dmabuf_do) {
			if (unlikely(desc->err)) {
				roce->stats.rx_helper_dmabuf_err++;
				dd_dev_err_ratelimited(roce->dd,
						       "roce: RX helper dma-buf copy failed: %d\n",
						       desc->err);
			} else {
				roce->stats.rx_helper_dmabuf += desc->len;
				roce->stats.rx_dmabuf_copy += desc->len;
			}
		}
		rvt_put_mr(desc->mr);
		q->retired++;
	}
}

/*
 * True when a helper is bound to the CPU running this caller.  The worker
 * is an unbound work item, so it can land on a helper's CPU; that helper
 * cannot run while the worker spins with interrupts off.
 */
static bool roce_rx_helper_shares_cpu(const struct hfi2_dms_roce *roce)
{
	return cpumask_test_cpu(raw_smp_processor_id(), &roce->rx_helper_mask);
}

/*
 * Copy the still-unclaimed entries up to @fence on this CPU, for a waiter
 * that spins with interrupts off on a CPU a helper may be bound to.
 * Entries already claimed finish without yielding.
 */
static void roce_rx_helpers_copy_unclaimed(struct hfi2_dms_roce_rx_queue *q,
					   u64 fence)
{
	struct hfi2_dms_roce_rx_copy_desc *desc;
	bool nt = roce_rx_helper_use_nt();
	s64 claim = atomic64_read(&q->claim);
	u64 seq;

	while ((u64)claim < fence) {
		preempt_disable();
		if (!atomic64_try_cmpxchg(&q->claim, &claim, claim + 1)) {
			preempt_enable();
			continue;
		}
		seq = (u64)claim + 1;
		desc = &q->ring[seq & HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
		roce_rx_copy_desc(q, desc, nt);
		/* Pairs with the worker's retire acquire. */
		smp_store_release(&desc->done_seq, seq);
		preempt_enable();
		claim = atomic64_read(&q->claim);
	}
}

/*
 * True once a wait that started at @start has outlasted any batch a running
 * helper could copy: the helpers are not getting CPU time (preempted, or
 * their CPU is busy), so the waiter copies the unclaimed entries itself.
 */
static bool roce_rx_helpers_stalled(struct hfi2_dms_roce *roce, u64 start)
{
	if (local_clock() - start < HFI2_DMS_ROCE_RX_HELPER_STALL_NS)
		return false;
	roce->stats.rx_helper_stalls++;
	dd_dev_warn_ratelimited(roce->dd,
				"roce: RX helpers stalled, copying on the worker\n");
	return true;
}

/*
 * Spin until every entry up to @fence (<= submitted) has retired.  Worker
 * only.  Bounded: unclaimed entries are taken over when a helper shares
 * this CPU or the helpers stall, and a claimed entry is copied with
 * preemption disabled, so it always finishes.
 */
static void roce_rx_helpers_drain_to(struct hfi2_dms_roce *roce, u64 fence)
{
	struct hfi2_dms_roce_rx_queue *q = &roce->rx_q;
	bool steal = roce_rx_helper_shares_cpu(roce);
	u64 start = local_clock();

	/* Helpers must not hold back for a batch the worker will not add. */
	WRITE_ONCE(q->filling, 0);
	for (;;) {
		roce_rx_helpers_kick(roce);
		roce_rx_helpers_retire(roce);
		if (q->retired >= fence)
			break;
		if (!steal)
			steal = roce_rx_helpers_stalled(roce, start);
		if (steal)
			roce_rx_helpers_copy_unclaimed(q, fence);
		cpu_relax();
	}
}

static void roce_rx_helpers_drain(struct hfi2_dms_roce *roce)
{
	if (!roce_rx_helpers_enabled(roce))
		return;
	roce->stats.rx_helper_drains++;
	roce_rx_helpers_drain_to(roce, roce->rx_q.submitted);
}

/*
 * Hold an ACK or NAK until this QP's helper copies have landed.  Off by
 * default: no observer can tell the difference.  Anything that reaches the
 * responder after the ACK - a SEND or WRITE with immediate completion, a
 * READ, an atomic, a flush or destroy - already waits for these copies
 * through the in-order retirement.  A signal that bypasses this port races
 * the payload's visibility to the target CPU whether or not the ACK waited,
 * as it does behind any NIC's posted writes.
 */
#ifdef HFI2_ROCE_RX_HELPER_ACK_WAIT
static void roce_rx_helpers_drain_qp(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;

	if (!roce_rx_helpers_enabled(roce) ||
	    rqp->rx_helper_fence <= roce->rx_q.retired)
		return;
	roce->stats.rx_helper_ack_drains++;
	/* Entries queued for other QPs after this one's need not land first. */
	roce_rx_helpers_drain_to(roce, rqp->rx_helper_fence);
}
#else
static void roce_rx_helpers_drain_qp(struct hfi2_dms_roce_qp *rqp)
{
}
#endif

/*
 * A receive or READ completion, or an error flush, hands the buffer to the
 * consumer, so this QP's helper copies into it must land first.  Worker only.
 */
static void roce_rx_helpers_land_qp(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;

	if (!roce_rx_helpers_enabled(roce) ||
	    rqp->rx_helper_fence <= roce->rx_q.retired)
		return;
	roce->stats.rx_helper_drains++;
	roce_rx_helpers_drain_to(roce, rqp->rx_helper_fence);
}

/*
 * Wait for this QP's helper copies from outside the worker, before rdmavt
 * completes its receive WQEs in error and hands the buffers back.  Caller
 * holds qp->r_lock, so the worker cannot queue more for this QP.
 *
 * Only the worker retires entries, so this never touches @retired; it copies
 * still-unclaimed entries itself (see roce_rx_helpers_copy_unclaimed()).
 */
static void roce_rx_helpers_wait_qp(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_roce_rx_queue *q;
	struct hfi2_dms_roce_rx_copy_desc *desc;
	u64 fence, seq;

	if (!roce || !roce_rx_helpers_enabled(roce))
		return;
	q = &roce->rx_q;
	fence = READ_ONCE(rqp->rx_helper_fence);
	if (fence <= READ_ONCE(q->retired))
		return;
	roce_rx_helpers_copy_unclaimed(q, fence);
	for (seq = READ_ONCE(q->retired) + 1; seq <= fence; seq++) {
		desc = &q->ring[seq & HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
		/* Pairs with the copier's done_seq release. */
		while (smp_load_acquire(&desc->done_seq) < seq)
			cpu_relax();
	}
}

void hfi2_dms_roce_rx_helpers_wait_qp(struct hfi2_dms_roce_qp *rqp)
{
	if (rqp)
		roce_rx_helpers_wait_qp(rqp);
}

static int roce_rx_helpers_copy(struct hfi2_dms_roce *roce,
				struct rvt_qp *qp,
				struct rvt_sge_state *ss,
				void *src, u32 length, bool release)
{
	struct hfi2_dms_roce_rx_queue *q = &roce->rx_q;
	u8 *data = src;

	if (!roce_rx_helpers_enabled(roce)) {
		bool dmabuf_do = ss->sge.mem.type == RVT_MEM_DMABUF_DO;
		int ret = rvt_copy_sge(qp, ss, rvt_to_kseg(src, length), release,
				       false);

		if (!ret && dmabuf_do)
			roce->stats.rx_dmabuf_copy += length;
		return ret;
	}
	if (length < READ_ONCE(roce_rx_helper_min) || roce->rx_copy_sync) {
		bool dmabuf_do = ss->sge.mem.type == RVT_MEM_DMABUF_DO;
		int ret;

		if (roce->rx_copy_sync)
			roce->stats.rx_helper_cpu_skb++;
		else
			roce->stats.rx_helper_cpu_small++;
		roce_rx_helpers_drain(roce);
		ret = rvt_copy_sge(qp, ss, rvt_to_kseg(src, length), release, false);
		if (!ret && dmabuf_do)
			roce->stats.rx_dmabuf_copy += length;
		return ret;
	}

	while (length) {
		struct hfi2_dms_roce_rx_copy_desc *desc;
		struct rvt_sge *sge = &ss->sge;
		bool dmabuf_do = sge->mem.type == RVT_MEM_DMABUF_DO;
		u32 len = rvt_get_sge_length(sge, length);
		u32 slot;
		u64 seq, dep;
		unsigned long dep_key;

		WARN_ON_ONCE(!len);
		if (sge->mem.type != RVT_MEM_KERNEL && !dmabuf_do) {
			roce->stats.rx_helper_cpu_nonkernel++;
			roce_rx_helpers_drain(roce);
			return rvt_copy_sge(qp, ss, rvt_to_kseg(data, length), release,
					    false);
		}
		/*
		 * One page per entry, so one dependency covers the overlap.  A
		 * coarser granule would chain neighbouring copies of the same
		 * message behind each other.
		 */
		len = min_t(u32, len, PAGE_SIZE - offset_in_page(sge->mem.vaddr));
		if (unlikely(q->submitted - q->retired >=
			     HFI2_DMS_ROCE_RX_HELPER_RING_SIZE)) {
			roce->stats.rx_helper_full_waits++;
			/* The ring is full, so retired + 1 <= submitted. */
			roce_rx_helpers_drain_to(roce, q->retired + 1);
		}
		seq = q->submitted + 1;
		dep_key = (unsigned long)sge->mem.vaddr >> PAGE_SHIFT;
		if (dmabuf_do)
			dep_key ^= (unsigned long)sge->mr;
		slot = hash_long(dep_key, HFI2_DMS_ROCE_RX_DEP_BITS);
		dep = q->dep_tbl[slot];
		if (dep <= q->retired)
			dep = 0;
		else
			roce->stats.rx_helper_deps++;
		q->dep_tbl[slot] = seq;

		desc = &q->ring[seq & HFI2_DMS_ROCE_RX_HELPER_RING_MASK];
		desc->src = data;
		desc->mr = sge->mr;
		desc->dep = dep;
		desc->len = len;
		desc->dmabuf_do = dmabuf_do;
		if (dmabuf_do)
			desc->dst.dmabuf_do = rvt_seg_new_len(sge->mem, len);
		else
			desc->dst.kaddr = sge->mem.vaddr;
		/* The MR hold prevents DMA-BUF unpin until retirement. */
		rvt_get_mr(sge->mr);
		rvt_update_sge(ss, len, release);
		q->submitted = seq;
		/*
		 * Publish (after the MR hold) every 16 entries here and at the
		 * kick points, so the line helpers poll moves once per batch.
		 */
		if (seq - q->head >= 16)
			/* Pairs with the helper's head acquire. */
			smp_store_release(&q->head, seq);
		data += len;
		length -= len;
	}
	to_roce_priv(qp)->roce_qp->rx_helper_fence = q->submitted;
	return 0;
}

static void
roce_rx_usrhead_retire(struct hfi2_dms_roce *roce,
		       u8 rcd_idx, struct hfi2_ctxtdata *rcd)
{
	struct hfi2_dms_roce_rx_usrhead *entry;
	u8 head = roce->rx_usrhead_head[rcd_idx];
	u8 tail = roce->rx_usrhead_tail[rcd_idx];
	u32 rhqoff = 0, etail = 0, npkts = 0;
	u8 updegr = 0;
	bool update = false;

	while (head != tail) {
		entry = &roce->rx_usrhead[rcd_idx][head];
		if (entry->fence > roce->rx_q.retired)
			break;
		rhqoff = entry->rhqoff;
		/*
		 * A batch with no eager packet carries etail == -1; keep the
		 * last real tail so a merged updegr never writes -1.
		 */
		if (entry->etail != (u32)-1)
			etail = entry->etail;
		npkts = entry->npkts;
		updegr |= entry->updegr;
		update = true;
		head = (head + 1) & (HFI2_DMS_ROCE_RX_USRHEAD_FIFO_SIZE - 1);
	}
	roce->rx_usrhead_head[rcd_idx] = head;
	if (update)
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, npkts);
}

static void
roce_rx_usrhead_update(struct hfi2_dms_roce *roce,
		       u8 rcd_idx, struct hfi2_ctxtdata *rcd, u32 rhqoff,
		       u8 updegr, u32 etail, u32 npkts)
{
	struct hfi2_dms_roce_rx_usrhead *entry;
	u8 tail, next;

	if (!roce_rx_helpers_enabled(roce)) {
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, npkts);
		return;
	}
	roce_rx_helpers_kick(roce);
	roce_rx_helpers_retire(roce);
	roce_rx_usrhead_retire(roce, rcd_idx, rcd);
	/* Nothing in flight: release the head now. */
	if (roce->rx_usrhead_head[rcd_idx] == roce->rx_usrhead_tail[rcd_idx] &&
	    roce->rx_q.retired == roce->rx_q.submitted) {
		hfi2_update_usrhead(rcd, rhqoff, updegr, etail, 0, npkts);
		return;
	}
	tail = roce->rx_usrhead_tail[rcd_idx];
	next = (tail + 1) & (HFI2_DMS_ROCE_RX_USRHEAD_FIFO_SIZE - 1);
	if (next == roce->rx_usrhead_head[rcd_idx]) {
		/*
		 * FIFO full: fold this update into the newest pending entry
		 * instead of spinning. The merged entry releases the later
		 * head under the later fence, which only delays the earlier
		 * release; the hardware never sees a head past an uncopied
		 * eager slot.
		 */
		entry = &roce->rx_usrhead[rcd_idx]
			[(tail - 1) & (HFI2_DMS_ROCE_RX_USRHEAD_FIFO_SIZE - 1)];
		entry->rhqoff = rhqoff;
		if (etail != (u32)-1)
			entry->etail = etail;
		entry->updegr |= updegr;
		entry->npkts += npkts;
		entry->fence = roce->rx_q.submitted;
		roce->stats.rx_helper_usrhead_spin++;
		return;
	}
	entry = &roce->rx_usrhead[rcd_idx][tail];
	entry->rhqoff = rhqoff;
	entry->etail = etail;
	entry->updegr = updegr;
	entry->npkts = npkts;
	entry->fence = roce->rx_q.submitted;
	roce->rx_usrhead_tail[rcd_idx] = next;
	roce->stats.rx_helper_usrhead_deferred++;
}

static void roce_rx_queue_free(struct hfi2_dms_roce_rx_queue *q)
{
	kfree(q->ring);
	kfree(q->dep_tbl);
	q->ring = NULL;
	q->dep_tbl = NULL;
	q->submitted = 0;
	q->retired = 0;
	q->head = 0;
	atomic64_set(&q->claim, 0);
	atomic_set(&q->sleepers, 0);
}

static void roce_rx_helper_cpus_release(const struct cpumask *cpus)
{
	mutex_lock(&roce_rx_helper_cpus_lock);
	cpumask_andnot(&roce_rx_helper_cpus_used, &roce_rx_helper_cpus_used,
		       cpus);
	mutex_unlock(&roce_rx_helper_cpus_lock);
}

/*
 * Default helper CPUs: the worker's die, which on current x86 parts is the
 * worker's L3.  Helpers read the eager-buffer lines the worker has just
 * parsed; on AMD a helper in another CCD pulls each one across the fabric
 * and copies at well under half the rate (gen7/8: 175 vs 280 Gb/s).
 * Whole cores first, skipping the worker's own core, then their SMT
 * siblings; fall back to the rest of the NUMA node if the die is short.
 */
static void roce_rx_helper_auto_cpus(struct hfi2_dms_roce *roce, int node,
				     u8 count, struct cpumask *out)
{
	const struct cpumask *node_cpus = cpumask_of_node(node);
	int wcpu = roce->svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].cpu;
	int cpu, pass;

	/*
	 * Ascending order: bulksvc puts workers on the last CPUs of the node,
	 * so a port that starts first rarely lands on a later port's worker.
	 */
	mutex_lock(&roce_rx_helper_cpus_lock);
	cpumask_set_cpu(wcpu, &roce_rx_worker_cpus);
	mutex_unlock(&roce_rx_helper_cpus_lock);
	for (pass = 0; pass < 3; pass++) {
		for_each_cpu(cpu, node_cpus) {
			bool primary = cpumask_first(topology_sibling_cpumask(cpu)) == cpu;

			if (!cpu_online(cpu) || cpu == 0 ||
			    cpumask_test_cpu(cpu, topology_sibling_cpumask(wcpu)) ||
			    cpumask_test_cpu(cpu, &roce_rx_worker_cpus))
				continue;
			if (pass < 2 &&
			    !cpumask_test_cpu(cpu, topology_die_cpumask(wcpu)))
				continue;
			if (pass == 0 && !primary)
				continue;
			cpumask_set_cpu(cpu, out);
		}
		mutex_lock(&roce_rx_helper_cpus_lock);
		cpu = cpumask_weight(out) -
			cpumask_weight_and(out, &roce_rx_helper_cpus_used);
		mutex_unlock(&roce_rx_helper_cpus_lock);
		if (cpu >= count)
			return;
	}
}

static int roce_rx_helpers_init(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_rx_queue *q = &roce->rx_q;
	cpumask_var_t helper_cpus;
	cpumask_var_t selected_cpus;
	int cpus[HFI2_DMS_ROCE_RX_HELPER_MAX];
	u8 count = min_t(uint, READ_ONCE(roce_rx_helpers),
			 HFI2_DMS_ROCE_RX_HELPER_MAX);
	u8 i = 0;
	int cpu;
	int node = dev_to_node(&roce->dd->pcidev->dev);
	int ret;

	if (!count)
		return 0;
	/* cpumask_of_node() indexes its map with the node unchecked */
	if (node == NUMA_NO_NODE)
		node = cpu_to_node(roce->svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].cpu);
	if (!zalloc_cpumask_var(&helper_cpus, GFP_KERNEL))
		return -ENOMEM;
	if (!zalloc_cpumask_var(&selected_cpus, GFP_KERNEL)) {
		free_cpumask_var(helper_cpus);
		return -ENOMEM;
	}

	cpumask_clear(helper_cpus);
	if (roce_rx_helper_cpus && *roce_rx_helper_cpus) {
		int wcpu = roce->svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].cpu;

		ret = cpulist_parse(roce_rx_helper_cpus, helper_cpus);
		if (ret)
			goto out_masks;
		cpumask_and(helper_cpus, helper_cpus, cpu_online_mask);
		/*
		 * roce_rx_helpers_drain() spins on the worker CPU with the QP
		 * lock held and interrupts off until the helpers finish, so a
		 * helper bound to a worker CPU, this port's or another's, can
		 * never run and the drain never ends.
		 */
		mutex_lock(&roce_rx_helper_cpus_lock);
		cpumask_set_cpu(wcpu, &roce_rx_worker_cpus);
		if (cpumask_intersects(helper_cpus, &roce_rx_worker_cpus))
			dd_dev_warn(roce->dd,
				    "roce: RX helper CPUs %*pbl include RoCE worker CPUs %*pbl, skipping them\n",
				    cpumask_pr_args(helper_cpus),
				    cpumask_pr_args(&roce_rx_worker_cpus));
		cpumask_andnot(helper_cpus, helper_cpus, &roce_rx_worker_cpus);
		mutex_unlock(&roce_rx_helper_cpus_lock);
	} else {
		roce_rx_helper_auto_cpus(roce, node, count, helper_cpus);
	}
	if (cpumask_weight(helper_cpus) < count) {
		ret = -EINVAL;
		goto out_masks;
	}
	mutex_lock(&roce_rx_helper_cpus_lock);
	cpumask_andnot(selected_cpus, helper_cpus, &roce_rx_helper_cpus_used);
	if (cpumask_weight(selected_cpus) < count) {
		dd_dev_warn(roce->dd,
			    "roce: RX helper CPUs %*pbl already used by another port, sharing\n",
			    cpumask_pr_args(&roce_rx_helper_cpus_used));
		cpumask_copy(selected_cpus, helper_cpus);
	}
	cpumask_copy(helper_cpus, selected_cpus);
	cpumask_clear(selected_cpus);
	for_each_cpu(cpu, helper_cpus) {
		cpus[i] = cpu;
		cpumask_set_cpu(cpu, selected_cpus);
		if (++i == count)
			break;
	}
	cpumask_or(&roce_rx_helper_cpus_used, &roce_rx_helper_cpus_used,
		   selected_cpus);
	mutex_unlock(&roce_rx_helper_cpus_lock);
	i = 0;

	q->ring = kcalloc_node(HFI2_DMS_ROCE_RX_HELPER_RING_SIZE,
			       sizeof(*q->ring), GFP_KERNEL, node);
	q->dep_tbl = kcalloc_node(1U << HFI2_DMS_ROCE_RX_DEP_BITS,
				  sizeof(*q->dep_tbl), GFP_KERNEL, node);
	if (!q->ring || !q->dep_tbl) {
		roce_rx_queue_free(q);
		ret = -ENOMEM;
		goto out_release;
	}

	i = 0;
	while (i < count) {
		struct hfi2_dms_roce_rx_helper *helper = &roce->rx_helpers[i];

		cpu = cpus[i];
		helper->q = q;
		helper->cpu = cpu;
		helper->count = count;
		helper->task = kthread_create_on_node(roce_rx_helper_thread, helper,
						      node, "hfi2_roce_rx/%u", i);
		if (IS_ERR(helper->task)) {
			ret = PTR_ERR(helper->task);
			helper->task = NULL;
			goto err_stop;
		}
		kthread_bind(helper->task, cpu);
		wake_up_process(helper->task);
		i++;
	}
	cpumask_copy(&roce->rx_helper_mask, selected_cpus);
	roce->rx_helper_count = count;
	dd_dev_info(roce->dd, "roce: RX helpers %u on CPUs %*pbl\n", count,
		    cpumask_pr_args(selected_cpus));
	free_cpumask_var(helper_cpus);
	free_cpumask_var(selected_cpus);
	return 0;

err_stop:
	while (i--) {
		kthread_stop(roce->rx_helpers[i].task);
		roce->rx_helpers[i].task = NULL;
	}
	roce_rx_queue_free(q);
out_release:
	roce_rx_helper_cpus_release(selected_cpus);
out_masks:
	free_cpumask_var(helper_cpus);
	free_cpumask_var(selected_cpus);
	return ret;
}

static void roce_rx_helpers_finish(struct hfi2_dms_roce *roce)
{
	u8 i;

	if (!roce_rx_helpers_enabled(roce))
		return;
	roce_rx_helpers_drain(roce);
	mutex_lock(&roce_rx_helper_cpus_lock);
	for (i = 0; i < roce->rx_helper_count; i++) {
		kthread_stop(roce->rx_helpers[i].task);
		roce->rx_helpers[i].task = NULL;
		cpumask_clear_cpu(roce->rx_helpers[i].cpu,
				  &roce_rx_helper_cpus_used);
	}
	mutex_unlock(&roce_rx_helper_cpus_lock);
	roce->rx_helper_count = 0;
	cpumask_clear(&roce->rx_helper_mask);
	roce_rx_queue_free(&roce->rx_q);
}

/*
 * Clear both placement tables before publishing or removing the backend.
 *
 * These CSR-backed tables survive rmmod, while the software residency maps
 * are freshly zeroed.  An interrupted run can leave a valid RIF entry whose
 * stale PASID and virtual address match a new QP after reload.  Clearing at
 * teardown also revokes the internal READ-as-WRITE R_Keys before their
 * software ownership records disappear.
 */
static void roce_table_reset(struct hfi2_dms_roce *roce)
{
	unsigned long flags;
	u64 wdata[3] = { 0 };
	u32 row, bucket;
	bool entered = roce_rif_enter(roce);

	for (row = 0; row < EAL_RIF_TABLE_ROWS; row++) {
		for (bucket = 0; bucket < EAL_TABLE_ENTRIES_PER_ROW; bucket++) {
			wdata[2] = FIELD_PREP(EAL_RIF_WDATA2_BUCKET_NUMB_MASK,
					      bucket) |
				   FIELD_PREP(EAL_RIF_WDATA2_QP_MASK, row);
			roce_rif_write(roce, wdata);
		}
		cond_resched();
	}
	if (roce->tombs) {
		memset(roce->tombs->tombstones, 0, sizeof(roce->tombs->tombstones));
		bitmap_zero(roce->tombs->rows, EAL_RIF_TABLE_ROWS);
		roce->tombs->sequence = 0;
	}
	roce_rif_leave(roce, entered);

	spin_lock_irqsave(&roce->rkey_lock, flags);
	for (row = 0; row < EAL_RKEY_TABLE_ROWS; row++) {
		for (bucket = 0; bucket < EAL_TABLE_ENTRIES_PER_ROW; bucket++) {
			wdata[2] = FIELD_PREP(EAL_RKEY_WDATA2_BUCKET_NUMB_MASK,
					      bucket) |
				   FIELD_PREP(EAL_RKEY_WDATA2_RKEY_MASK, row);
			roce_rkey_write(roce, wdata);
		}
	}
	spin_unlock_irqrestore(&roce->rkey_lock, flags);

	dd_dev_info(roce->dd,
		    "roce: cleared %u RIF and %u R_Key entries inherited from a previous load\n",
		    EAL_RIF_TABLE_ROWS * EAL_TABLE_ENTRIES_PER_ROW,
		    EAL_RKEY_TABLE_ROWS * EAL_TABLE_ENTRIES_PER_ROW);
}

static int roce_backend_init(struct hfi2_bulksvc *svc,
			     struct hfi2_dms_roce *roce,
		       struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT],
		       struct send_context *sc)
{
	struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(svc);
	u8 i;
	int ret;

	BUILD_BUG_ON(HFI2_DMS_ROCE_RCD_COUNT != 2);
	BUILD_BUG_ON(HFI2_ROCE_QPN_ALIAS_BIT & (EAL_RIF_TABLE_ROWS - 1));

	if (!hfi2_is_eth_mode(svc->dd) || roce->initialized ||
	    svc->backend != HFI2_BULKSVC_BACKEND_ETH_ROCE)
		return -EINVAL;
	if (!sc || !rcd[0] || !rcd[1]) {
		dd_dev_err(svc->dd,
			   "roce: ETH loan missing send ctx (%p) or receive ctxs (%p, %p)\n",
			   sc, rcd[0], rcd[1]);
		return -ENODEV;
	}

	if (!dms->common_initialized ||
	    dms->port_sctxts[HFI2_PORT_IDX] != sc ||
	    sc->ppd != &svc->dd->pport[HFI2_PORT_IDX]) {
		dd_dev_err(svc->dd,
			   "roce: common DMS substrate is missing the selected port/send context\n");
		return -EINVAL;
	}
	/*
	 * RoCE admission accounts roce_sdma_engine_bundle_cap()
	 * worst-case bundles per loaned engine.  Keep that policy here: the
	 * common layer's initial eight nodes are a warm start, not a transport
	 * admission limit.
	 */
	ret = hfi2_dms_sdma_warm_reserve(dms, dms->num_engines *
				 roce_sdma_engine_batch_nodes());
	if (ret)
		return ret;
	ret = hfi2_dms_page_pool_warm(dms, dms->num_engines *
				roce_sdma_engine_page_cap());
	if (ret)
		return ret;
	if (!hfi2_dms_sdma_capacity_ready(dms, dms->num_engines *
			roce_sdma_engine_batch_nodes(),
			dms->num_engines * roce_sdma_engine_page_cap(),
			roce_sdma_engine_bundle_cap(),
			roce_sdma_engine_descriptor_cap())) {
		dd_dev_err(svc->dd,
			   "roce: common SDMA warm inventory cannot satisfy bounded engine caps\n");
		return -ENOSPC;
	}
	roce->dd = svc->dd;
	roce->svc = svc;
	roce->sc = sc;
	roce->hwp_mode = !hfi2_bulksvc_roce_by_software(svc->dd);
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++)
		roce->rcd[i] = rcd[i];
	/* Cache backend-invariant PBC fields; length and credit return are dynamic. */
	roce->pbc_template =
		roce->dd->params->create_pbc(roce->sc->ppd, false, 0, 0, 0, 0,
					     ROCE_PBC_L2,
					     ROCE_PBC_DLID_23_20 << 20,
					     roce->sc->hw_context);
	roce->pbc_template &= ~PBC_INSERT_BYPASS_ICRC;
	WRITE_ONCE(roce->mtu_8192_capable,
		   (sc->type == SC_USER || sc->type == SC_BULKSVC) &&
		   sc->credits >= 130 &&
		   rcd[0]->egrbufs.rcvtid_size >= HFI2_ROCE_TXBUF_8192_SZ &&
		   rcd[1]->egrbufs.rcvtid_size >= HFI2_ROCE_TXBUF_8192_SZ);
	/*
	 * 2048 rows x 16 buckets x 4 bytes = 128 KiB.  Allocated once at init
	 * rather than grown on demand: the arm path runs under rif_lock and
	 * cannot sleep, and a failed allocation there would have to be
	 * reported as a placement failure rather than an out-of-memory.
	 */
	roce->rif_owner = kvcalloc_node(EAL_RIF_TABLE_ROWS *
					EAL_TABLE_ENTRIES_PER_ROW,
					sizeof(*roce->rif_owner),
					GFP_KERNEL, svc->dd->node);
	if (!roce->rif_owner)
		return -ENOMEM;

	/* Same geometry, same lock, same reason it cannot be grown on demand. */
	roce->rif_pasid = kvcalloc_node(EAL_RIF_TABLE_ROWS *
					EAL_TABLE_ENTRIES_PER_ROW,
					sizeof(*roce->rif_pasid),
					GFP_KERNEL, svc->dd->node);
	if (!roce->rif_pasid) {
		kvfree(roce->rif_owner);
		roce->rif_owner = NULL;
		return -ENOMEM;
	}

	roce->rif_invalidations = kvcalloc_node(EAL_RIF_TABLE_ROWS *
						EAL_TABLE_ENTRIES_PER_ROW,
						sizeof(*roce->rif_invalidations),
						GFP_KERNEL, svc->dd->node);
	roce->rif_dirty = bitmap_zalloc(EAL_RIF_TABLE_ROWS *
				       EAL_TABLE_ENTRIES_PER_ROW, GFP_KERNEL);
	if (!roce->rif_invalidations || !roce->rif_dirty) {
		bitmap_free(roce->rif_dirty);
		kvfree(roce->rif_invalidations);
		kvfree(roce->rif_pasid);
		kvfree(roce->rif_owner);
		roce->rif_pasid = NULL;
		roce->rif_owner = NULL;
		return -ENOMEM;
	}

	/* 512 x 16 x 4 B = 32 KiB each. */
	roce->rkey_owner = kvcalloc_node(EAL_RKEY_TABLE_ROWS *
					 EAL_TABLE_ENTRIES_PER_ROW,
					 sizeof(*roce->rkey_owner),
					 GFP_KERNEL, svc->dd->node);
	roce->rkey_pasid = kvcalloc_node(EAL_RKEY_TABLE_ROWS *
					 EAL_TABLE_ENTRIES_PER_ROW,
					 sizeof(*roce->rkey_pasid),
					 GFP_KERNEL, svc->dd->node);
	roce->rkey_internal = kvcalloc_node(EAL_RKEY_TABLE_ROWS *
					    EAL_TABLE_ENTRIES_PER_ROW,
					    sizeof(*roce->rkey_internal),
					    GFP_KERNEL, svc->dd->node);
	if (!roce->rkey_owner || !roce->rkey_pasid || !roce->rkey_internal) {
		bitmap_free(roce->rif_dirty);
		kvfree(roce->rif_invalidations);
		kvfree(roce->rkey_internal);
		kvfree(roce->rkey_pasid);
		kvfree(roce->rkey_owner);
		kvfree(roce->rif_pasid);
		kvfree(roce->rif_owner);
		roce->rkey_internal = NULL;
		roce->rkey_pasid = NULL;
		roce->rkey_owner = NULL;
		roce->rif_pasid = NULL;
		roce->rif_owner = NULL;
		return -ENOMEM;
	}

	atomic_set(&roce->pio_fail_attempts, 0);
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
		if (!rcd[i]) {
			roce->rx_rcd_state[i] = 0;
			continue;
		}
		roce->rx_rcd_state[i] =
			roce_rx_state_pack(0, hfi2_rcd_head(rcd[i]));
		roce->rif_pasid_hdr_overflow[i] =
			read_kctxt_csr(svc->dd, rcd[i]->ctxt,
				       svc->dd->params->rcv_hdr_ovfl_cnt_reg);
	}
	spin_lock_init(&roce->stride_lock);
	/*
	 * Reconcile software state with the register rather than assuming a
	 * reset value.  rocev2_mtu is a CSR and survives rmmod: after any
	 * reload it still holds the previous run's encoding, measured as 7 on
	 * both lab hosts with stride_bytes reading 0.
	 *
	 * The driver cannot simply PROGRAM the field here - no QP exists yet,
	 * so there is no path MTU to write - and it must not silently inherit
	 * it either, because the R_Key installer is not gated on the stride:
	 * an MR registered before any QP reaches RTR installs an entry that
	 * hardware can hit, and the resulting placement would use whatever
	 * encoding the previous module left.  That writes correct bytes to the
	 * wrong address at line rate.
	 *
	 * So: clear the field, and clear it loudly if it was carrying
	 * something, then program roce_vrma_mtu before any MR or QP exists.
	 * With software placement the field stays zero: nothing is placed.
	 */
	roce->stride_bytes = 0;
	roce_stride_reset_csr(roce);
	if (!hfi2_bulksvc_roce_by_software(svc->dd))
		roce_stride_program(roce);
	mutex_init(&roce->rif_mutex);
	roce->tombs = kzalloc(sizeof(*roce->tombs), GFP_KERNEL);
	if (roce->tombs) {
		xa_init(&roce->tombs->qps);
		roce->tombs->pasid.pasid = IOMMU_PASID_INVALID;
	}
	spin_lock_init(&roce->rif_lock);
	INIT_LIST_HEAD(&roce->rif_pending);
	roce->rif_dirty_count = 0;
	spin_lock_init(&roce->rows_lock);
	xa_init(&roce->rif_pasid_rows);
	roce->rif_pasid_loss_gen = 0;
	atomic64_set(&roce->stats.rif_pasid_rows_scanned, 0);
	atomic64_set(&roce->stats.rif_pasid_late_rows, 0);
	atomic64_set(&roce->stats.rif_pasid_full_sweep, 0);
	atomic64_set(&roce->stats.rif_pasid_track_enomem, 0);
	spin_lock_init(&roce->rkey_lock);
	roce_table_reset(roce);
	if (roce->tombs && !hfi2_bulksvc_roce_by_software(svc->dd) &&
	    svc->dd->pcidev->dev.iommu) {
		roce->tombs->pasid.pasid = iommu_alloc_global_pasid(&svc->dd->pcidev->dev);
		if (roce->tombs->pasid.pasid != IOMMU_PASID_INVALID &&
		    roce->tombs->pasid.pasid > FIELD_MAX(EAL_RIF_WDATA2_PASID_MASK)) {
			iommu_free_global_pasid(roce->tombs->pasid.pasid);
			roce->tombs->pasid.pasid = IOMMU_PASID_INVALID;
		}
		/* Reserved in the global allocator, never attached to a domain. */
		roce->tombs->pasid.live = roce->tombs->pasid.pasid != IOMMU_PASID_INVALID;
	}
	spin_lock_init(&roce->runq_lock);
	skb_queue_head_init(&roce->netdev_rxq);
	INIT_LIST_HEAD(&roce->runq);
	INIT_LIST_HEAD(&roce->pio_waitq);
	INIT_LIST_HEAD(&roce->sdma_waitq);
	INIT_LIST_HEAD(&roce->read_restart);
	roce->pio_intr_armed = false;
	roce->pio_last_fill = READ_ONCE(sc->fill);
	roce->pio_ctx_stopped = false;
	roce->pio_restarted = false;
	INIT_LIST_HEAD(&roce->sdma_done);
	spin_lock_init(&roce->sdma_cancel_lock);
	INIT_LIST_HEAD(&roce->sdma_cancel);
	memset(roce->sdma_engines, 0, sizeof(roce->sdma_engines));
	atomic_set(&roce->sdma_local_holds, 0);
	roce->pio_attempts = 0;
	/*
	 * PIO-only leaves the loaned engines unused: with no RoCE engine a
	 * QP's request_engine_idx is ENGINE_NONE, so requests and responses
	 * alike take PIO.
	 */
	roce->sdma_engine_count =
		roce_tx_pio_only ? 0 : dms_num_data_engines(dms);
	roce->sdma_qp_bundles = clamp_t(uint, roce_sdma_qp_bundles, 1,
					HFI2_DMS_ROCE_SDMA_QP_BUNDLE_LIMIT);
	if (roce->sdma_engine_count) {
		u8 i;

		for (i = 0; i < roce->sdma_engine_count; i++) {
			struct hfi2_dms_roce_sdma_engine *engine =
				&roce->sdma_engines[i];
			u32 ring_usable = roce_sdma_engine_descriptor_cap();

			if (dms->sdma_engines[i]->descq_cnt - 1 <= ring_usable) {
				ret = -ENOSPC;
				goto err_placement;
			}
			engine->bundle_cap = roce_sdma_engine_bundle_cap();
			engine->descriptor_cap = roce_sdma_engine_descriptor_cap();
			engine->page_cap = roce_sdma_engine_page_cap();
		}
		roce->sdma_admission_closed = false;
	} else {
		roce->sdma_admission_closed = true;
	}

	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
		u64 kctrl;

		kctrl = read_kctxt_csr(svc->dd, rcd[i]->ctxt,
				       svc->dd->params->rcv_kctxt_ctrl_reg);
		kctrl |= CYR_RCV_KCTXT_CTRL_RCV_DIRECT_PLACEMENT_ENABLE_SMASK;
		write_kctxt_csr(svc->dd, rcd[i]->ctxt,
				svc->dd->params->rcv_kctxt_ctrl_reg, kctrl);
		kctrl = read_kctxt_csr(svc->dd, rcd[i]->ctxt,
				       svc->dd->params->rcv_kctxt_ctrl_reg);
		if (!(kctrl & CYR_RCV_KCTXT_CTRL_RCV_DIRECT_PLACEMENT_ENABLE_SMASK)) {
			dd_dev_err(svc->dd, "roce: ctxt %u RcvDirectPlacementEnable did not set (RcvKctxtCtrl=0x%016llx)\n",
				   rcd[i]->ctxt, kctrl);
			goto err_placement;
		}
	}

	roce_adopt_send_ctxt(svc->dd, roce->sc->ppd, roce->sc, roce);
	ret = roce_rx_helpers_init(roce);
	if (ret)
		goto err_placement;

	roce_inject_init(roce);
	roce->initialized = true;
	roce->active = true;
	dd_dev_info(svc->dd,
		    "roce: DMS_RoCE backend active (sc %u, rcds %u/%u, tx %s, %u SDMA engines)\n",
		    roce->sc->hw_context, roce->rcd[0]->ctxt, roce->rcd[1]->ctxt,
		    roce->sdma_engine_count ? "sdma" : "pio",
		    roce->sdma_engine_count);
	return 0;

err_placement:
	if (roce->sc) {
		unsigned long flags;

		spin_lock_irqsave(&roce->dd->sc_lock, flags);
		WRITE_ONCE(roce->sc->roce_owner, NULL);
		spin_unlock_irqrestore(&roce->dd->sc_lock, flags);
	}
	roce_rx_helpers_finish(roce);
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
		u64 kctrl;

		kctrl = read_kctxt_csr(svc->dd, rcd[i]->ctxt,
				       svc->dd->params->rcv_kctxt_ctrl_reg);
		kctrl &= ~CYR_RCV_KCTXT_CTRL_RCV_DIRECT_PLACEMENT_ENABLE_SMASK;
		write_kctxt_csr(svc->dd, rcd[i]->ctxt,
				svc->dd->params->rcv_kctxt_ctrl_reg, kctrl);
	}
	roce_hwp_pool_exit(roce);
	roce_rif_pasid_rows_destroy(roce);
	bitmap_free(roce->rif_dirty);
	kvfree(roce->rif_invalidations);
	kvfree(roce->rkey_internal);
	roce->rkey_internal = NULL;
	kvfree(roce->rkey_pasid);
	roce->rkey_pasid = NULL;
	kvfree(roce->rkey_owner);
	roce->rkey_owner = NULL;
	kvfree(roce->rif_pasid);
	roce->rif_pasid = NULL;
	kvfree(roce->rif_owner);
	roce->rif_owner = NULL;
	roce->sdma_engine_count = 0;
	roce->rcd[0] = NULL;
	roce->rcd[1] = NULL;
	roce->sc = NULL;
	roce->svc = NULL;
	roce->dd = NULL;
	return ret ? ret : -ENODEV;
}

int hfi2_dms_roce_init(struct hfi2_bulksvc *svc,
		       struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT],
		       struct send_context *sc)
{
	struct hfi2_dms_roce *roce;
	int ret;

	/*
	 * Heap-allocated so OPA-mode devices carry only the pointer in
	 * struct hfi2_bulksvc; published only once fully initialized.
	 */
	if (svc->dms_roce)
		return -EINVAL;
	roce = kzalloc_node(sizeof(*roce), GFP_KERNEL, svc->dd->node);
	if (!roce)
		return -ENOMEM;
	ret = roce_backend_init(svc, roce, rcd, sc);
	if (ret) {
		kfree(roce);
		return ret;
	}
	svc->dms_roce = roce;
	return 0;
}

void hfi2_dms_roce_teardown_begin(struct hfi2_bulksvc *svc)
{
	struct hfi2_dms_roce *roce = svc->dms_roce;

	if (!roce || !roce->initialized)
		return;

	/*
	 * Preserve callback-facing state across hfi2_dms_common_uninit(): SDMA
	 * destroy can synchronously publish its final failures after this point.
	 */
	WRITE_ONCE(roce->sdma_admission_closed, true);
	WRITE_ONCE(roce->active, false);
	roce_inject_teardown(roce);
	hfi2_dms_roce_sdma_drain_callbacks(roce);
}

/*
 * Forget the hardware objects RoCE borrowed once the device is gone.
 * cleanup_device_data() has freed the send context and the receive
 * contexts, so the remaining teardown must not dereference them.
 */
void hfi2_dms_roce_detach_hw(struct hfi2_bulksvc *svc)
{
	struct hfi2_dms_roce *roce = svc->dms_roce;
	unsigned int i;

	if (!roce)
		return;
	roce->pio_intr_armed = false;
	roce->sc = NULL;
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++)
		roce->rcd[i] = NULL;
}

void hfi2_dms_roce_teardown_drain(struct hfi2_bulksvc *svc)
{
	struct hfi2_dms_roce *roce = svc->dms_roce;
	unsigned int i;

	if (!roce || !roce->initialized)
		return;

	/*
	 * Common shutdown publishes final failures but deliberately retains every
	 * pool.  Consume those records now because releasing a cookie returns its
	 * command pages and provider holds to common storage.
	 */
	svc->sdma_quiesce_failed = !hfi2_dms_sdma_shutdown(hfi2_bulksvc_primary_dms(svc));
	if (svc->sdma_quiesce_failed)
		return;
	hfi2_dms_roce_sdma_drain_callbacks(roce);
	roce_rx_helpers_drain(roce);
	WARN_ON_ONCE(atomic_read(&roce->sdma_local_holds));
	for (i = 0; i < roce->sdma_engine_count; i++)
		WARN_ON_ONCE(roce->sdma_engines[i].bundle_used ||
			     roce->sdma_engines[i].descriptor_used ||
			     roce->sdma_engines[i].page_used);
}

static void roce_backend_teardown_finish(struct hfi2_bulksvc *svc,
			struct hfi2_dms_roce *roce)
{
	u8 i;

	if (!roce->initialized)
		return;

	if (roce->sc) {
		unsigned long flags;

		spin_lock_irqsave(&roce->dd->sc_lock, flags);
		WRITE_ONCE(roce->sc->roce_owner, NULL);
		spin_unlock_irqrestore(&roce->dd->sc_lock, flags);
	}
	WRITE_ONCE(roce->mtu_8192_capable, false);
	/*
	 * Drop the latched stride so the next init re-programs rocev2_mtu from
	 * roce_vrma_mtu, rather than trusting a value whose register may not
	 * have survived teardown.
	 */
	roce->stride_bytes = 0;
	roce_stride_reset_csr(roce);
	hfi2_dms_roce_drain(roce);
	roce_rif_progress(roce);
	roce_rx_helpers_finish(roce);
	roce_hwp_pool_exit(roce);

	if (roce->dd) {
		struct hfi2_devdata *dd = roce->dd;
		u8 i;

		roce_table_reset(roce);

		for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
			struct hfi2_ctxtdata *rcd = roce->rcd[i];
			u64 kctrl;

			if (!rcd)
				continue;
			kctrl = read_kctxt_csr(dd, rcd->ctxt,
					       dd->params->rcv_kctxt_ctrl_reg);
			kctrl &= ~CYR_RCV_KCTXT_CTRL_RCV_DIRECT_PLACEMENT_ENABLE_SMASK;
			write_kctxt_csr(dd, rcd->ctxt,
					dd->params->rcv_kctxt_ctrl_reg, kctrl);

			kctrl = read_kctxt_csr(dd, rcd->ctxt,
					       dd->params->rcv_kctxt_ctrl_reg);
			if ((dd->flags & HFI2_PRESENT) &&
			    (kctrl & CYR_RCV_KCTXT_CTRL_RCV_DIRECT_PLACEMENT_ENABLE_SMASK))
				dd_dev_err(dd, "roce: ctxt %u RcvDirectPlacementEnable did not clear (RcvKctxtCtrl=0x%016llx) - the context is handed back with placement still armed\n",
					   rcd->ctxt, kctrl);
		}
	}

	/* Freed after the drain: quiesce first, then release. */
	roce_rif_pasid_rows_destroy(roce);
	bitmap_free(roce->rif_dirty);
	kvfree(roce->rif_invalidations);
	kvfree(roce->rif_owner);
	roce->rif_owner = NULL;
	kvfree(roce->rif_pasid);
	roce->rif_pasid = NULL;
	kvfree(roce->rkey_owner);
	roce->rkey_owner = NULL;
	kvfree(roce->rkey_pasid);
	roce->rkey_pasid = NULL;
	kvfree(roce->rkey_internal);
	roce->rkey_internal = NULL;
	roce->sdma_engine_count = 0;
	roce->initialized = false;
	roce->sc = NULL;
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++)
		roce->rcd[i] = NULL;
	roce->svc = NULL;
	roce->dd = NULL;
}

void hfi2_dms_roce_quiesce_internal_mrs(struct rvt_dev_info *rdi)
{
	struct hfi2_devdata *dd = dd_from_dev(dev_from_rdi(rdi));

	if (dd->bulksvc && dd->bulksvc->dms_roce)
		roce_hwp_pool_quiesce(dd->bulksvc->dms_roce);
}

void hfi2_dms_roce_release_internal_mrs(struct rvt_dev_info *rdi)
{
	struct hfi2_devdata *dd = dd_from_dev(dev_from_rdi(rdi));
	struct hfi2_dms_roce *roce;

	if (!dd->bulksvc)
		return;
	roce = dd->bulksvc->dms_roce;
	if (roce)
		roce_hwp_pool_exit(roce);
}

void hfi2_dms_roce_teardown_finish(struct hfi2_bulksvc *svc)
{
	struct hfi2_dms_roce *roce = svc->dms_roce;

	if (!roce)
		return;
	WRITE_ONCE(roce->active, false);
	roce_backend_teardown_finish(svc, roce);
	WRITE_ONCE(svc->dms_roce, NULL);
	/* Wait out hfi2_dms_roce_netdev_enqueue() callers that loaded @roce. */
	synchronize_net();
	skb_queue_purge(&roce->netdev_rxq);
	kfree(roce);
}

static void roce_tx_snapshot_release(struct hfi2_dms_roce_qp *rqp);
static bool roce_qp_is_ud(const struct rvt_qp *qp);
static void roce_rewind_to_acked(struct rvt_qp *qp);
static void roce_replay_resume_set(struct hfi2_dms_roce_qp *rqp, u32 psn);
static void roce_tx_snapshot_init(struct hfi2_dms_roce_qp *rqp,
				  struct rvt_swqe *wqe, u32 wqe_idx, u32 pmtu);
static void roce_priority_refresh(struct hfi2_dms_roce_qp *rqp);
static void roce_priority_refresh_rx(struct hfi2_dms_roce_qp *rqp, u8 opcode);
static void roce_sdma_terminalize_qp(struct hfi2_dms_roce_qp *rqp);
static void roce_retry_exhausted_complete(struct hfi2_dms_roce_qp *rqp);
static struct hfi2_dms_roce_sdma_xfer *
roce_sdma_xfer_lookup(struct hfi2_dms_roce_qp *rqp, u8 lane,
		      u32 wqe_index, u32 wqe_generation,
		      enum ib_wr_opcode opcode, u32 first_psn, u32 last_psn);
static struct hfi2_dms_roce_sdma_xfer *
roce_sdma_xfer_lookup_any_epoch(struct hfi2_dms_roce_qp *rqp, u32 wqe_index,
				const struct rvt_swqe *wqe);

/*
 * Assign the QP's request lane to the engine carrying the fewest QPs.  The
 * choice is made once per QP lifetime and kept across resets, so every bundle
 * and replay stays on one engine, including an engine's terminal-halt path.
 *
 * A QPN hash alone was used before; with 4 engines and 8 QPs it often placed
 * 3 QPs on one engine and 1 on another, and the loaded engine's bundle budget
 * capped the whole port (362 vs 396 Gb/s, run to run, depending on QPNs).
 * The hash still picks the starting point so ties spread across engines.
 * Concurrent creates may read the same counts; the result is only a balance
 * hint and any engine index is valid.
 */
static u8 roce_sdma_engine_pick(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce;
	u8 num_engines, start, best, i;
	int best_qps = INT_MAX;
	u16 hashed;

	if (!rqp || !rqp->roce || !rqp->qp)
		return HFI2_DMS_ROCE_SDMA_ENGINE_NONE;
	if (rqp->request_engine_counted)
		return rqp->request_engine_idx;
	roce = rqp->roce;
	num_engines = READ_ONCE(roce->sdma_engine_count);
	if (!num_engines)
		return HFI2_DMS_ROCE_SDMA_ENGINE_NONE;

	hashed = (u16)(rqp->qp->ibqp.qp_num * 0x9E37u);
	start = ((u32)hashed * num_engines) >> 16;
	best = start;
	for (i = 0; i < num_engines; i++) {
		u8 idx = (start + i) % num_engines;
		int qps = atomic_read(&roce->sdma_engine_qps[idx]);

		if (qps < best_qps) {
			best_qps = qps;
			best = idx;
		}
	}
	atomic_inc(&roce->sdma_engine_qps[best]);
	rqp->request_engine_counted = true;
	return best;
}

static void roce_sdma_engine_unpick(struct hfi2_dms_roce_qp *rqp)
{
	if (!rqp->request_engine_counted)
		return;
	atomic_dec(&rqp->roce->sdma_engine_qps[rqp->request_engine_idx]);
	rqp->request_engine_counted = false;
}

#if HFI2_DMS_ROCE_INJECT
static bool roce_inject_request_emitter_get(enum hfi2_dms_roce_emitter *emitter)
{
	switch (READ_ONCE(roce_inject_request_emitter)) {
	case HFI2_DMS_ROCE_INJECT_EMITTER_AUTO:
		return false;
	case HFI2_DMS_ROCE_INJECT_EMITTER_PIO:
		*emitter = HFI2_DMS_ROCE_EMITTER_PIO;
		return true;
	case HFI2_DMS_ROCE_INJECT_EMITTER_SDMA:
		*emitter = HFI2_DMS_ROCE_EMITTER_SDMA;
		return true;
	default:
		return false;
	}
}
#endif

/*
 * A request SDMA declined used to fall back to PIO once the request lane
 * was idle.  That mixes emitters on a QP whose responses use SDMA, so the
 * request now waits for SDMA.  Define HFI2_DMS_ROCE_REQ_PIO_FALLBACK to
 * restore the fallback.  A QP with no SDMA engine always uses PIO.
 */
static bool roce_request_pio_fallback_ok(const struct hfi2_dms_roce_qp *rqp,
					 int rc)
{
#ifdef HFI2_DMS_ROCE_REQ_PIO_FALLBACK
	return true;
#else
	/* Unsupported requests use PIO; only temporary resource pressure waits. */
	return rqp->request_engine_idx == HFI2_DMS_ROCE_SDMA_ENGINE_NONE ||
	       (rc != -EAGAIN && rc != -E2BIG && rc != -ENOSPC);
#endif
}

static bool roce_request_emitter_select(struct hfi2_dms_roce_qp *rqp,
					enum hfi2_dms_roce_emitter emitter,
					u8 engine_idx)
{
#if HFI2_DMS_ROCE_INJECT
	enum hfi2_dms_roce_emitter forced;

	if (roce_inject_request_emitter_get(&forced) &&
	    (forced != emitter ||
	     (rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_UNSET &&
	      rqp->request_emitter != forced))) {
		if (rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_UNSET &&
		    rqp->request_emitter != forced)
			rqp->roce->stats.emitter_live_switch_reject++;
		return false;
	}
#endif

	if (emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
	    engine_idx == HFI2_DMS_ROCE_SDMA_ENGINE_NONE)
		return false;
	if (rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_UNSET) {
		if (rqp->sdma_req_holds ||
		    (emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
		     rqp->request_engine_idx != engine_idx))
			return false;
		rqp->request_emitter = emitter;
		rqp->request_epoch++;
#if HFI2_DMS_ROCE_INJECT
		rqp->roce->stats.emitter_epoch_open++;
		if (rqp->request_epoch > 1)
			rqp->roce->stats.emitter_idle_switch_accept++;
#endif
		return true;
	}
	if (rqp->request_emitter != emitter)
		return false;
	if (emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
	    rqp->request_engine_idx != engine_idx)
		return false;

	return true;
}

static void roce_request_emitter_close(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	lockdep_assert_held(&qp->s_lock);
	/*
	 * Callbacks can momentarily drain holds while a partial WQE still
	 * needs its epoch-keyed xfer.
	 */
	if (rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_UNSET &&
	    !rqp->sdma_req_holds && !rqp->replay_pending &&
	    !rqp->tx_in_progress && qp->s_acked == qp->s_tail &&
	    qp->s_last == qp->s_tail) {
		rqp->request_emitter = HFI2_DMS_ROCE_EMITTER_UNSET;
		rqp->request_sdma_accepted = false;
#if HFI2_DMS_ROCE_INJECT
		rqp->roce->stats.emitter_epoch_close++;
#endif
	}
}

static void roce_request_emitter_unselect_sdma(struct hfi2_dms_roce_qp *rqp)
{
	if (!rqp->request_sdma_accepted && !rqp->sdma_req_holds &&
	    rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_SDMA)
		rqp->request_emitter = HFI2_DMS_ROCE_EMITTER_UNSET;
}

/*
 * s_tail only steps past a new WQE once its last packet is built, so while
 * the first transmission of a multi-packet WQE is still going out
 * s_acked == s_tail although its leading packets are on the wire.  A
 * responder may NAK one of those - a sequence error on an early MIDDLE,
 * or a FIRST it had to divert - and that NAK must rewind the WQE, not be
 * dropped as having nothing outstanding.
 */
static bool roce_request_outstanding(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	return qp->s_acked != qp->s_tail ||
	       (rqp->tx_in_progress && qp->s_cur == qp->s_tail);
}

static bool roce_request_replay_defer(struct hfi2_dms_roce_qp *rqp,
				      u32 psn,
				      enum hfi2_dms_roce_replay_action action,
				      u32 rnr_aeth)
{
	if (action != HFI2_DMS_ROCE_REPLAY_NONE) {
		if (!rqp->replay_pending)
			rqp->replay_rewound = false;
		rqp->replay_pending = true;
		rqp->replay_psn = psn;
		rqp->replay_action = action;
		rqp->replay_rnr_aeth = rnr_aeth;
	}
	if (!rqp->replay_pending || rqp->sdma_req_holds)
		return rqp->replay_pending;
	lockdep_assert_held(&rqp->qp->s_lock);
	if (!roce_request_outstanding(rqp)) {
		rqp->replay_pending = false;
		rqp->replay_action = HFI2_DMS_ROCE_REPLAY_NONE;
		return false;
	}
	if (rqp->replay_action == HFI2_DMS_ROCE_REPLAY_EXHAUSTED) {
		roce_retry_exhausted_complete(rqp);
		rqp->replay_pending = false;
		rqp->replay_action = HFI2_DMS_ROCE_REPLAY_NONE;
		return false;
	}

	rqp->qp->s_flags &= ~(RVT_S_WAIT_SSN_CREDIT | RVT_S_WAIT_ACK |
				 RVT_S_WAIT_PSN | RVT_S_WAIT_PIO |
				 RVT_S_WAIT_FENCE);
	/* Cleanup resumes this same replay; do not requeue its alias invalidation. */
	if (!rqp->replay_rewound) {
		roce_rewind_to_acked(rqp->qp);
		rqp->replay_rewound = true;
	}
	if (rqp->rif_read_cleanup)
		return true;
	if (rqp->replay_action == HFI2_DMS_ROCE_REPLAY_SEND)
		roce_replay_resume_set(rqp, rqp->replay_psn);
	if (rqp->replay_action == HFI2_DMS_ROCE_REPLAY_RNR)
		rvt_add_rnr_timer(rqp->qp, rqp->replay_rnr_aeth);
	rqp->replay_pending = false;
	rqp->replay_action = HFI2_DMS_ROCE_REPLAY_NONE;
	return false;
}

static void roce_retry_exhausted_complete(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;

	lockdep_assert_held(&qp->r_lock);
	lockdep_assert_held(&qp->s_lock);
	if (qp->s_acked == qp->s_tail || qp->s_last != qp->s_acked)
		return;

	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (WARN_ON_ONCE(rqp->sdma_req_holds))
		return;
	if (WARN_ON_ONCE(rqp->sdma_local_holds))
		return;
	roce_sdma_terminalize_qp(rqp);
	if (rqp->tx_in_progress)
		roce_tx_snapshot_release(rqp);
	rqp->roce->stats.retry_exhausted++;
	if (roce_hwp_defer_error(rqp, wqe, IB_WC_RETRY_EXC_ERR,
				 RVT_QP_LOCK_STATE_RS))
		return;
	hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
	rvt_send_complete(qp, wqe, IB_WC_RETRY_EXC_ERR,
			      RVT_QP_LOCK_STATE_RS);
	rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
}

static bool roce_sdma_xfer_valid(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_dms_roce_sdma_xfer *xfer)
{
	unsigned long first;
	unsigned long end;
	unsigned long addr = (unsigned long)xfer;

	if (!rqp || !rqp->sdma_xfers || !rqp->sdma_xfer_count)
		return false;
	first = (unsigned long)rqp->sdma_xfers;
	end = first + rqp->sdma_xfer_count * sizeof(*rqp->sdma_xfers);

	return addr >= first && addr < end &&
	       !((addr - first) % sizeof(*rqp->sdma_xfers));
}

static void roce_sdma_xfer_source_destroy(struct hfi2_dms_roce_sdma_xfer *xfer)
{
	if (xfer->source) {
		hfi2_bulksvc_verbs_source_provider_release(xfer->source);
		xfer->source = NULL;
	}
	if (xfer->mr) {
		rvt_put_mr(xfer->mr);
		xfer->mr = NULL;
	}
}

static inline void
roce_sdma_xfer_hold_mr(struct hfi2_dms_roce_sdma_xfer *xfer,
			       struct rvt_mregion *mr)
{
	if (WARN_ON_ONCE(xfer->mr || !mr))
		return;
	rvt_get_mr(mr);
	xfer->mr = mr;
}

static bool hfi2_dms_roce_sdma_try_retire(struct hfi2_dms_roce_sdma_xfer *xfer)
{
	return xfer && (xfer->wire_acked || xfer->terminal) &&
		!xfer->local_holds && !xfer->retired;
}

static void roce_sdma_xfer_recycle(struct hfi2_dms_roce_sdma_xfer *xfer)
{
	if (!hfi2_dms_roce_sdma_try_retire(xfer))
		return;

	xfer->retired = true;
	xfer->active = false;
	if (xfer->displaced) {
		xfer->displaced = false;
		xfer->rqp->sdma_xfer_displaced--;
	}
	roce_sdma_xfer_source_destroy(xfer);
}

static void roce_sdma_note_bundle_commit(struct hfi2_dms_roce *roce,
					u32 packets, u32 descriptors)
{
	if (packets <= 4)
		roce->stats.bundle_packets_1_4++;
	else if (packets <= 16)
		roce->stats.bundle_packets_5_16++;
	else if (packets <= 32)
		roce->stats.bundle_packets_17_32++;
	else if (packets <= 64)
		roce->stats.bundle_packets_33_64++;
	else if (packets <= 128)
		roce->stats.bundle_packets_65_128++;
	else if (packets <= 256)
		roce->stats.bundle_packets_129_256++;
	else
		roce->stats.bundle_packets_257_512++;
	roce->stats.bundle_packets_total += packets;
	roce->stats.bundle_descriptors_total += descriptors;
	roce->stats.bundle_packets_max =
		max(roce->stats.bundle_packets_max, packets);
	roce->stats.bundle_descriptors_max =
		max(roce->stats.bundle_descriptors_max, descriptors);
}

static void roce_sdma_cookie_release(struct hfi2_dms_roce *roce,
				     struct hfi2_dms_roce_sdma_cookie *cookie,
				     bool poison)
{
	struct hfi2_dms_roce_qp *rqp = cookie->rqp;
	struct hfi2_dms_roce_sdma_xfer *xfer = cookie->xfer;
	struct hfi2_dms_roce_sdma_engine *engine = NULL;
	u16 page_count = cookie->page_count;
	u16 i;
	bool xfer_valid = rqp && roce_sdma_xfer_valid(rqp, xfer);
	bool engine_valid = cookie->engine_idx < roce->sdma_engine_count;

	if (WARN_ON_ONCE(!cookie->local_hold || !rqp ||
			 cookie->state == HFI2_DMS_ROCE_SDMA_COOKIE_CONSUMED ||
			 !rqp->sdma_local_holds))
		return;

	for (i = 0; i < cookie->page_count; i++) {
		if (cookie->pages[i]) {
			hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), cookie->pages[i]);
			cookie->pages[i] = NULL;
		}
	}
	cookie->page_count = 0;
	cookie->local_hold = false;
	rqp->sdma_local_holds--;
	if (cookie->lane == HFI2_DMS_ROCE_LANE_REQUEST) {
		if (!WARN_ON_ONCE(!rqp->sdma_req_holds))
			rqp->sdma_req_holds--;
	} else if (cookie->lane == HFI2_DMS_ROCE_LANE_RESPONDER) {
		if (!WARN_ON_ONCE(!rqp->sdma_resp_holds))
			rqp->sdma_resp_holds--;
	} else {
		WARN_ON_ONCE(1);
	}
	if (cookie->ack_hold && !WARN_ON_ONCE(!rqp->sdma_ack_holds))
		rqp->sdma_ack_holds--;
	cookie->ack_hold = false;

	if (xfer_valid) {
		if (WARN_ON_ONCE(!xfer->local_holds))
			xfer_valid = false;
		else
			xfer->local_holds--;
#if HFI2_DMS_ROCE_INJECT
		if (!xfer->local_holds) {
			xfer->local_done = true;
			if (xfer->retire_order == HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_NONE)
				xfer->retire_order = xfer->wire_acked ?
					HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_ACK_FIRST :
					HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_CALLBACK_FIRST;
		}
#endif
		if (poison || cookie->terminal)
			xfer->terminal = true;
	}

	if (engine_valid)
		engine = &roce->sdma_engines[cookie->engine_idx];
	if (!engine ||
	    WARN_ON_ONCE(engine->bundle_used < cookie->bundle_count ||
			 engine->descriptor_used < cookie->descriptor_count ||
			 engine->page_used < page_count)) {
	} else {
		engine->bundle_used -= cookie->bundle_count;
		engine->descriptor_used -= cookie->descriptor_count;
		engine->page_used -= page_count;
	}
	if (WARN_ON_ONCE(roce->stats.admitted_descriptors_current <
			 cookie->descriptor_count))
		roce->stats.admitted_descriptors_current = 0;
	else
		roce->stats.admitted_descriptors_current -= cookie->descriptor_count;

	if ((cookie->state == HFI2_DMS_ROCE_SDMA_COOKIE_PUBLISHED &&
	     cookie->done_status < 0) || cookie->terminal) {
		if (xfer_valid)
			xfer->terminal = true;
	}
	cookie->state = HFI2_DMS_ROCE_SDMA_COOKIE_CONSUMED;
	cookie->terminal = poison || cookie->done_status < 0;
	cookie->active = false;
	if (rqp && !rqp->sdma_local_holds)
		complete_all(&rqp->sdma_local_zero);
	if (atomic_read(&roce->sdma_local_holds))
		atomic_dec(&roce->sdma_local_holds);
	else
		WARN_ON_ONCE(1);
	if (!cookie->qp)
		WARN_ON_ONCE(1);
}

/*
 * SDMA callbacks and done-list consumption run on the same bulksvc worker,
 * or synchronously during teardown after that worker has been quiesced.
 * Callbacks only publish status; consumption releases local QP ownership.
 */
static void hfi2_dms_roce_sdma_callback(struct hfi2_dms_roce_sdma_cookie *done,
					 int status, bool terminal)
{
	struct hfi2_dms_roce_qp *rqp;
	struct hfi2_dms_roce *roce;

	if (!done)
		return;

	rqp = done->rqp;
	if (WARN_ON_ONCE(!rqp || !rqp->roce))
		return;
	roce = rqp->roce;

	if (WARN_ON_ONCE(!done->active || !done->local_hold ||
			 (done->state != HFI2_DMS_ROCE_SDMA_COOKIE_HELD &&
			  done->state != HFI2_DMS_ROCE_SDMA_COOKIE_COMMITTED)))
		return;
	done->done_status = status;
	done->terminal = terminal;
	/* Pair with the worker acquire before it validates completion fields. */
	smp_store_release(&done->state, HFI2_DMS_ROCE_SDMA_COOKIE_PUBLISHED);
	list_add_tail(&done->done_node, &roce->sdma_done);
}

/* Completion callbacks only publish; worker/teardown consumes ownership. */
void hfi2_dms_roce_sdma_publish_done(void *cookie, int status)
{
#if HFI2_DMS_ROCE_INJECT
	struct hfi2_dms_roce_sdma_cookie *done = cookie;

	if (!status && done && done->rqp &&
	    done->state == HFI2_DMS_ROCE_SDMA_COOKIE_COMMITTED &&
	    READ_ONCE(roce_inject_sdma_callback_error_once)) {
		WRITE_ONCE(roce_inject_sdma_callback_error_once, false);
		done->rqp->roce->stats.sdma_inject_callback_error++;
		status = -EIO;
	}
#endif
	hfi2_dms_roce_sdma_callback(cookie, status, status < 0);
}

static void
hfi2_dms_roce_sdma_abort_uncommitted(struct hfi2_dms_roce_sdma_cookie *cookie,
				      int status);

static int hfi2_dms_roce_sdma_commit(struct hfi2_dms_roce_sdma_cookie *cookie,
				     struct hfi2_dms_sdma_batch *batch, u8 engine_idx)
{
	struct hfi2_dms_roce_qp *rqp;
	struct hfi2_dms_roce *roce;
	u32 packets;
	u32 descriptors;
	int ret;

	/* Invalid arguments leave both caller-owned inputs untouched. */
	if (!cookie || !batch ||
	    WARN_ON_ONCE(!cookie->active || !cookie->local_hold ||
			 !cookie->rqp ||
			 cookie->state != HFI2_DMS_ROCE_SDMA_COOKIE_LOCAL) ||
	    !hfi2_dms_sdma_batch_is_held(batch))
		return -EINVAL;
	rqp = cookie->rqp;
	roce = rqp->roce;
	if (!roce || !roce->svc ||
	    READ_ONCE(rqp->sdma_admission_stopped) ||
	    READ_ONCE(roce->sdma_admission_closed)) {
		hfi2_dms_sdma_batch_abort(batch);
		hfi2_dms_roce_sdma_abort_uncommitted(cookie, -ESHUTDOWN);
		return -ESHUTDOWN;
	}
#if HFI2_DMS_ROCE_INJECT
	if (READ_ONCE(roce_inject_sdma_preaccept_shutdown_once)) {
		WRITE_ONCE(roce_inject_sdma_preaccept_shutdown_once, false);
		roce->stats.sdma_inject_preaccept_shutdown++;
		hfi2_dms_sdma_batch_abort(batch);
		hfi2_dms_roce_sdma_abort_uncommitted(cookie, -ESHUTDOWN);
		return -ESHUTDOWN;
	}
#endif

	ret = hfi2_dms_sdma_batch_tag(batch, hfi2_dms_roce_sdma_publish_done,
				      cookie);
	if (ret) {
		hfi2_dms_sdma_batch_abort(batch);
		hfi2_dms_roce_sdma_abort_uncommitted(cookie, ret);
		return ret;
	}
	cookie->state = HFI2_DMS_ROCE_SDMA_COOKIE_HELD;
	ret = hfi2_dms_sdma_batch_commit(batch, engine_idx,
					 hfi2_dms_roce_sdma_publish_done,
					 cookie);
	if (ret) {
		cookie->state = HFI2_DMS_ROCE_SDMA_COOKIE_LOCAL;
		hfi2_dms_roce_sdma_abort_uncommitted(cookie, ret);
		return ret;
	}
	cookie->state = HFI2_DMS_ROCE_SDMA_COOKIE_COMMITTED;
	packets = cookie->page_count;
	descriptors = cookie->descriptor_count;
	roce_sdma_note_bundle_commit(roce, packets, descriptors);
	if (cookie->lane == HFI2_DMS_ROCE_LANE_REQUEST)
		rqp->request_sdma_accepted = true;
	roce->stats.sdma_commit_accepted++;
	return 0;
}

static void
hfi2_dms_roce_sdma_abort_uncommitted(struct hfi2_dms_roce_sdma_cookie *cookie,
					  int status)
{
	struct hfi2_dms_roce_qp *rqp;
	struct hfi2_dms_roce *roce;

	if (!cookie || WARN_ON_ONCE(!cookie->active || !cookie->local_hold ||
				    cookie->state != HFI2_DMS_ROCE_SDMA_COOKIE_LOCAL))
		return;
	rqp = cookie->rqp;
	if (WARN_ON_ONCE(!rqp || !rqp->roce))
		return;
	roce = rqp->roce;
	cookie->done_status = status;
	cookie->terminal = cookie->xfer_new;
	roce_sdma_cookie_release(roce, cookie, false);
	if (cookie->xfer_new)
		roce_sdma_xfer_recycle(cookie->xfer);
	if (cookie->lane == HFI2_DMS_ROCE_LANE_REQUEST)
		roce_request_emitter_unselect_sdma(rqp);
	if (cookie->qp)
		rvt_put_qp(cookie->qp);
}

/*
 * Retire the wire-done WQE at s_last, if its transfer records allow it.
 * Every slot in [s_last, s_acked) is done on the wire: ACKed, or answered by
 * its READ RESPONSE or ATOMIC ACKNOWLEDGE.  It still cannot complete while
 * SDMA owns its source pages.  The records are matched on any epoch, because
 * the emitter can reopen while older bundles are outstanding, and an old-epoch
 * record that nothing names would hold its slot for the life of the QP.
 */
static bool roce_sdma_retire_wire_done(struct hfi2_dms_roce_qp *rqp,
				       struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_sdma_xfer *xfer;

	while ((xfer = roce_sdma_xfer_lookup_any_epoch(rqp, qp->s_last, wqe))) {
		if (xfer->local_holds)
			return false;
		if (xfer->terminal) {
			if (!rqp->sdma_req_holds && !rqp->sdma_local_holds) {
				roce_sdma_xfer_recycle(xfer);
				roce_sdma_terminalize_qp(rqp);
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR,
					     RVT_QP_LOCK_STATE_RS);
			}
			return false;
		}
		hfi2_dms_roce_sdma_note_ack(xfer);
		roce_sdma_xfer_recycle(xfer);
		if (WARN_ON_ONCE(xfer->active))
			return false;
		if (likely(!rqp->sdma_xfer_displaced))
			break;
	}
	if (unlikely(wqe->wr.opcode == IB_WR_RDMA_READ))
		roce_wqe_clear_read_write_reply(rqp, wqe);
	rvt_qp_complete_swqe(qp, wqe,
			     ib_to_rvt(qp->ibqp.device)->wc_opcode[wqe->wr.opcode],
			     IB_WC_SUCCESS, RVT_QP_LOCK_STATE_RS);
	rqp->roce->stats.rx_ack_completed++;
	return true;
}

/* Preserve the ACKed prefix before ERR discards its local transfer evidence. */
static u32 roce_sdma_retire_error_prefix(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	u32 retired = 0;

	lockdep_assert_held(&qp->s_lock);
	while (rqp->hwp_error_pending && !roce_qp_is_ud(qp) &&
	       !rqp->hwp_cleanup_pending && !rqp->hwp_fencing &&
	       !rqp->rif_read_cleanup && !READ_ONCE(rqp->tx_cancelled) &&
	       qp->s_last != qp->s_acked && qp->s_last != rqp->hwp_error_index &&
	       qp->s_last != READ_ONCE(qp->s_head) &&
	       retired < ROCE_PIO_TX_FLUSH_BUDGET) {
		struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, qp->s_last);
		struct hfi2_dms_roce_sdma_xfer *xfer;

		while ((xfer = roce_sdma_xfer_lookup_any_epoch(rqp, qp->s_last, wqe))) {
			if (xfer->local_holds || xfer->terminal)
				return retired;
			hfi2_dms_roce_sdma_note_ack(xfer);
			roce_sdma_xfer_recycle(xfer);
			if (WARN_ON_ONCE(xfer->active))
				return retired;
		}
		if (wqe->wr.opcode == IB_WR_RDMA_READ)
			roce_wqe_clear_read_write_reply(rqp, wqe);
		rvt_qp_complete_swqe(qp, wqe,
				     ib_to_rvt(qp->ibqp.device)->wc_opcode[wqe->wr.opcode],
				     IB_WC_SUCCESS, RVT_QP_LOCK_STATE_S);
		rqp->roce->stats.rx_ack_completed++;
		retired++;
	}
	return retired;
}

static void roce_sdma_retire_request_ready(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	lockdep_assert_held(&qp->r_lock);
	lockdep_assert_held(&qp->s_lock);
	if (rqp->hwp_cleanup_pending || rqp->hwp_fencing || rqp->rif_read_cleanup)
		return;
	while (qp->s_last != qp->s_tail) {
		struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, qp->s_last);
		struct hfi2_dms_roce_sdma_xfer *xfer;

		if (qp->s_last != qp->s_acked && !roce_qp_is_ud(qp)) {
			if (!roce_sdma_retire_wire_done(rqp, wqe))
				break;
			continue;
		}
		xfer = roce_sdma_xfer_lookup(rqp,
					     HFI2_DMS_ROCE_LANE_REQUEST,
					     qp->s_last, rqp->request_epoch,
					     wqe->wr.opcode, wqe->psn, wqe->lpsn);
		if (!xfer)
			break;
		if (xfer->terminal) {
			if (!rqp->sdma_req_holds && !rqp->sdma_local_holds) {
				roce_sdma_xfer_recycle(xfer);
				roce_sdma_terminalize_qp(rqp);
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR,
					     RVT_QP_LOCK_STATE_RS);
			}
			break;
		}
		if (roce_qp_is_ud(qp))
			break;
		if (roce_wqe_is_rd_atomic(wqe->wr.opcode)) {
			if (!xfer->local_holds)
				roce_sdma_xfer_recycle(xfer);
			break;
		}
		if (!xfer->wire_acked || xfer->local_holds)
			break;

		qp->s_last_psn = roce_psn(wqe->lpsn);
		if (unlikely(wqe->wr.opcode == IB_WR_RDMA_READ))
			roce_wqe_clear_read_write_reply(rqp, wqe);
		rvt_qp_complete_swqe(qp, wqe,
				     ib_to_rvt(qp->ibqp.device)->
					     wc_opcode[wqe->wr.opcode],
				     IB_WC_SUCCESS, RVT_QP_LOCK_STATE_RS);
		rqp->roce->stats.rx_ack_completed++;
		roce_sdma_xfer_recycle(xfer);
	}
	roce_request_emitter_close(rqp);
}

static void hfi2_dms_roce_sdma_consume_done(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_sdma_cookie *done;
	bool poison;
	LIST_HEAD(batch);

	if (list_empty(&roce->sdma_done))
		return;
	list_splice_init(&roce->sdma_done, &batch);

	while (!list_empty(&batch)) {
		done = list_first_entry(&batch,
					struct hfi2_dms_roce_sdma_cookie, done_node);
#if HFI2_DMS_ROCE_INJECT
		if (READ_ONCE(roce_inject_sdma_hold_for_ack_once) && done->xfer &&
		    done->xfer->local_holds == 1) {
			WRITE_ONCE(roce_inject_sdma_hold_for_ack_once, false);
			done->hold_for_ack = true;
			roce->stats.sdma_inject_hold_for_ack++;
		}
		if (done->hold_for_ack && done->xfer && !done->xfer->wire_acked) {
			/* The worker also owns this held-tail requeue. */
			list_splice(&batch, &roce->sdma_done);
			break;
		}
#endif
		list_del_init(&done->done_node);

		/* Pairs with callback publication after the producer has filled fields. */
		poison = smp_load_acquire(&done->state) !=
			 HFI2_DMS_ROCE_SDMA_COOKIE_PUBLISHED ||
			 !done->active || !done->local_hold ||
			 done->engine_idx >= TXE_NUM_SDMA_ENGINES ||
			 done->engine_idx >= roce->sdma_engine_count || !done->rqp ||
			 !roce_sdma_xfer_valid(done->rqp, done->xfer) ||
			 (done->xfer->needs_source && !done->xfer->source);
		WARN_ON_ONCE(poison);
		if (!done->done_status)
			roce->stats.sdma_callback_ok++;
		else if (done->done_status == -ESHUTDOWN)
			roce->stats.sdma_callback_shutdown++;
		else
			roce->stats.sdma_callback_error++;
		roce_sdma_cookie_release(roce, done, poison);
		if (done->qp) {
			unsigned long r_flags, s_flags;

			spin_lock_irqsave(&done->qp->r_lock, r_flags);
			spin_lock_irqsave(&done->qp->s_lock, s_flags);
			/*
			 * READ completion can advance s_last before this
			 * callback drains. Recycle through the cookie while it
			 * still identifies the transfer.
			 */
			if (roce_sdma_xfer_valid(done->rqp, done->xfer) &&
			    done->xfer->active && !done->xfer->local_holds &&
			    done->xfer->lane == HFI2_DMS_ROCE_LANE_REQUEST &&
			    (done->xfer->opcode == IB_WR_RDMA_READ ||
			     roce_qp_is_ud(done->qp))) {
				bool failed = done->xfer->terminal;

				if (roce_qp_is_ud(done->qp)) {
					struct rvt_swqe *wqe;

					wqe = rvt_get_swqe_ptr(done->qp,
							       done->xfer->wqe_index);

					done->xfer->wire_acked = true;
					roce_sdma_xfer_recycle(done->xfer);
					hfi2_dms_roce_clear_wqe_read_write_reply(done->qp, wqe);
					rvt_send_complete(done->qp, wqe,
						  failed ? IB_WC_GENERAL_ERR :
						  IB_WC_SUCCESS, RVT_QP_LOCK_STATE_RS);
				} else if (failed) {
					/*
					 * A failed READ bundle errors the queue pair,
					 * as a failed WRITE does in the retirement
					 * walk; recycling it here would otherwise leave
					 * only the retry timer to notice.  With other
					 * bundles still held, the ERROR flush defers
					 * its terminalize until they drain.
					 */
					roce_sdma_xfer_recycle(done->xfer);
					done->rqp->roce->stats.tx_sdma_read_req_error++;
					if (!done->rqp->sdma_req_holds &&
					    !done->rqp->sdma_local_holds)
						roce_sdma_terminalize_qp(done->rqp);
					rvt_error_qp(done->qp, IB_WC_WR_FLUSH_ERR,
						     RVT_QP_LOCK_STATE_RS);
				} else {
					roce_sdma_xfer_recycle(done->xfer);
				}
			} else if (roce_sdma_xfer_valid(done->rqp, done->xfer) &&
				   done->xfer->active && !done->xfer->local_holds &&
				   done->xfer->lane == HFI2_DMS_ROCE_LANE_RESPONDER) {
				bool failed = done->xfer->terminal;

				roce_sdma_xfer_recycle(done->xfer);
				if (failed) {
					done->rqp->roce->stats.tx_sdma_resp_error++;
					if (!done->rqp->sdma_local_holds)
						roce_sdma_terminalize_qp(done->rqp);
					rvt_error_qp(done->qp, IB_WC_WR_FLUSH_ERR,
						     RVT_QP_LOCK_STATE_RS);
				} else if (!done->xfer->abandoned &&
					   !done->rqp->sdma_resp_holds &&
					   (done->rqp->ack_pending ||
					    (done->qp->s_flags & RVT_S_RESP_PENDING))) {
					hfi2_roce_schedule_send(done->qp);
				}
			}
			roce_sdma_retire_request_ready(done->rqp);
			spin_unlock_irqrestore(&done->qp->s_lock, s_flags);
			spin_unlock_irqrestore(&done->qp->r_lock, r_flags);
		}
		if (done->rqp &&
		    ((done->rqp->replay_pending && !done->rqp->sdma_req_holds) ||
		     !done->rqp->sdma_local_holds)) {
			struct rvt_qp *qp = done->rqp->qp;
			unsigned long r_flags, s_flags;

			spin_lock_irqsave(&qp->r_lock, r_flags);
			spin_lock_irqsave(&qp->s_lock, s_flags);
			if (done->rqp->replay_pending && !done->rqp->sdma_req_holds) {
				enum hfi2_dms_roce_replay_action action =
					done->rqp->replay_action;

				if (!roce_request_replay_defer(done->rqp,
							       done->rqp->replay_psn,
							       HFI2_DMS_ROCE_REPLAY_NONE,
							       0) &&
				    action != HFI2_DMS_ROCE_REPLAY_RNR)
					hfi2_roce_schedule_send(qp);
			} else if (!done->rqp->sdma_local_holds &&
				   !(ib_rvt_state_ops[qp->state] &
				     RVT_PROCESS_SEND_OK) &&
				   (ib_rvt_state_ops[qp->state] & RVT_FLUSH_SEND)) {
				/* Resume a QP ERROR flush deferred for local SDMA. */
				hfi2_roce_schedule_send(qp);
			}
			spin_unlock_irqrestore(&qp->s_lock, s_flags);
			spin_unlock_irqrestore(&qp->r_lock, r_flags);
		}
		if (done->qp)
			rvt_put_qp(done->qp);
	}
}

void hfi2_dms_roce_sdma_note_ack(struct hfi2_dms_roce_sdma_xfer *xfer)
{
	if (!xfer || !xfer->active || xfer->retired)
		return;

	if (!xfer->wire_acked) {
#if HFI2_DMS_ROCE_INJECT
		if (xfer->retire_order == HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_NONE)
			xfer->retire_order = xfer->local_done ?
				HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_CALLBACK_FIRST :
				HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_ACK_FIRST;
		if (xfer->rqp && xfer->rqp->roce) {
			if (xfer->retire_order == HFI2_DMS_ROCE_SDMA_RETIRE_ORDER_ACK_FIRST)
				xfer->rqp->roce->stats.sdma_retire_ack_first++;
			else
				xfer->rqp->roce->stats.sdma_retire_callback_first++;
		}
#endif
	}
	xfer->wire_acked = true;
#if HFI2_DMS_ROCE_INJECT
	if (xfer->rqp && xfer->rqp->roce)
		hfi2_bulksvc_schedule(xfer->rqp->roce->svc);
#endif
}

/*
 * A requester transfer belongs to one send-ring slot and a responder READ
 * transfer to one ack-queue slot, and the array is sized s_size plus the ack
 * slots, so each normally has a home index.  Try it first; the scan stays as
 * the fallback for a home slot still held by an older transfer (an ACK
 * record, which has no ring slot, or one still awaiting its callback).
 */
static unsigned int roce_sdma_xfer_home(const struct hfi2_dms_roce_qp *rqp,
					u8 lane, u32 index)
{
	u32 s_size = rqp->qp->s_size;

	if (lane == HFI2_DMS_ROCE_LANE_REQUEST && index < s_size)
		return index;
	if (lane == HFI2_DMS_ROCE_LANE_RESPONDER &&
	    index != HFI2_DMS_ROCE_RESP_ACK_INDEX &&
	    rqp->sdma_xfer_count > s_size &&
	    index < rqp->sdma_xfer_count - s_size)
		return s_size + index;
	return rqp->sdma_xfer_count;
}

static bool roce_sdma_xfer_match(const struct hfi2_dms_roce_sdma_xfer *xfer,
				 u8 lane, u32 wqe_index, u32 wqe_generation,
				 enum ib_wr_opcode opcode, u32 first_psn,
				 u32 last_psn)
{
	return xfer->active && xfer->lane == lane &&
	       xfer->wqe_index == wqe_index &&
	       xfer->wqe_generation == wqe_generation &&
	       xfer->opcode == opcode && xfer->first_psn == first_psn &&
	       xfer->last_psn == last_psn;
}

static struct hfi2_dms_roce_sdma_xfer *
roce_sdma_xfer_lookup(struct hfi2_dms_roce_qp *rqp, u8 lane,
		      u32 wqe_index, u32 wqe_generation,
		      enum ib_wr_opcode opcode, u32 first_psn, u32 last_psn)
{
	unsigned int home = roce_sdma_xfer_home(rqp, lane, wqe_index);
	unsigned int i;

	if (home < rqp->sdma_xfer_count &&
	    roce_sdma_xfer_match(&rqp->sdma_xfers[home], lane, wqe_index,
				 wqe_generation, opcode, first_psn, last_psn))
		return &rqp->sdma_xfers[home];
	if (!rqp->sdma_xfer_displaced)
		return NULL;
	for (i = 0; i < rqp->sdma_xfer_count; i++) {
		if (i != home &&
		    roce_sdma_xfer_match(&rqp->sdma_xfers[i], lane, wqe_index,
					 wqe_generation, opcode, first_psn,
					 last_psn))
			return &rqp->sdma_xfers[i];
	}

	return NULL;
}

static struct hfi2_dms_roce_sdma_xfer *
roce_sdma_xfer_lookup_any_epoch(struct hfi2_dms_roce_qp *rqp, u32 wqe_index,
				const struct rvt_swqe *wqe)
{
	unsigned int home = roce_sdma_xfer_home(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
						wqe_index);
	unsigned int i;

	if (home < rqp->sdma_xfer_count &&
	    roce_sdma_xfer_match(&rqp->sdma_xfers[home],
				 HFI2_DMS_ROCE_LANE_REQUEST, wqe_index,
				 rqp->sdma_xfers[home].wqe_generation,
				 wqe->wr.opcode, wqe->psn, wqe->lpsn))
		return &rqp->sdma_xfers[home];
	if (!rqp->sdma_xfer_displaced)
		return NULL;
	for (i = 0; i < rqp->sdma_xfer_count; i++) {
		struct hfi2_dms_roce_sdma_xfer *xfer = &rqp->sdma_xfers[i];

		if (i != home &&
		    roce_sdma_xfer_match(xfer, HFI2_DMS_ROCE_LANE_REQUEST,
					 wqe_index, xfer->wqe_generation,
					 wqe->wr.opcode, wqe->psn, wqe->lpsn))
			return xfer;
	}
	return NULL;
}

/* Index of a free transfer record, preferring the home slot. */
static unsigned int roce_sdma_xfer_free(const struct hfi2_dms_roce_qp *rqp,
					u8 lane, u32 index)
{
	unsigned int home = roce_sdma_xfer_home(rqp, lane, index);
	unsigned int i;

	if (home < rqp->sdma_xfer_count && !rqp->sdma_xfers[home].active)
		return home;
	for (i = 0; i < rqp->sdma_xfer_count; i++) {
		if (!rqp->sdma_xfers[i].active)
			return i;
	}
	return rqp->sdma_xfer_count;
}

static struct hfi2_dms_roce_sdma_xfer *
roce_sdma_xfer_get(struct hfi2_dms_roce_qp *rqp, u8 lane,
		   u32 wqe_index, u32 wqe_generation,
		   enum ib_wr_opcode opcode, u32 first_psn, u32 last_psn,
		   bool needs_source, bool copy_fallback,
		   struct hfi2_bulksvc_verbs_source *new_source,
		   struct hfi2_dms_roce_sdma_xfer *new_xfer)
{
	struct hfi2_dms_roce_sdma_xfer *xfer;
	unsigned int source_idx;

	xfer = roce_sdma_xfer_lookup(rqp, lane, wqe_index, wqe_generation,
				     opcode, first_psn, last_psn);
	if (xfer)
		return new_source || new_xfer ||
			(xfer->needs_source && !xfer->source) ? NULL : xfer;

	if (!roce_sdma_xfer_valid(rqp, new_xfer) || new_xfer->active ||
	    (needs_source && !new_source))
		return NULL;
	source_idx = new_xfer - rqp->sdma_xfers;
	if (new_source &&
	    (!rqp->sdma_sources || new_source != &rqp->sdma_sources[source_idx]))
		return NULL;

	*new_xfer = (struct hfi2_dms_roce_sdma_xfer) {
		.rqp = rqp,
		.wqe_index = wqe_index,
		.wqe_generation = wqe_generation,
		.first_psn = first_psn,
		.last_psn = last_psn,
		.epoch = wqe_generation,
		.lane = lane,
		.port_idx = rqp->port_idx,
		.opcode = opcode,
		.source = new_source,
		.needs_source = needs_source,
		.copy_fallback = copy_fallback,
		.active = true,
		.displaced = source_idx !=
			roce_sdma_xfer_home(rqp, lane, wqe_index),
	};
	if (new_xfer->displaced)
		rqp->sdma_xfer_displaced++;
	return new_xfer;
}

/*
 * Engine and per-QP budget check for one bundle.  On failure it marks the
 * QP stalled and attributes the stall to the first budget that ran out.
 * With one-pass emit the descriptor count is a worst-case bound; the unused
 * part is returned by roce_sdma_cookie_trim() before commit.
 *
 * A responder ACK/NAK is exempt from the engine bundle cap.  The engine is
 * shared by every QP loaned to it, and its bundle slots go to whichever
 * data bundle asks first; an ACK parked behind them can wait past the
 * peer's retry timeout while the peer, waiting for that ACK, sends nothing
 * that would free a slot it needs.  An ACK is one descriptor and one page,
 * still counted against those budgets and in bundle_used, so a data bundle
 * is refused while ACKs hold the engine above its cap.
 */
static bool roce_sdma_admit_room(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_dms_roce_sdma_engine *engine,
				 u16 lane_holds, u16 bundle_count,
				 u16 descriptor_count, u16 page_count, bool ack)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	bool bundle_room = ack ||
		(engine->bundle_used <= engine->bundle_cap &&
		 bundle_count <= engine->bundle_cap - engine->bundle_used);

	if (lane_holds < roce->sdma_qp_bundles && bundle_room &&
	    engine->descriptor_used <= engine->descriptor_cap &&
	    engine->page_used <= engine->page_cap &&
	    descriptor_count <= engine->descriptor_cap - engine->descriptor_used &&
	    page_count <= engine->page_cap - engine->page_used)
		return true;

	roce->stats.sdma_admission_stall++;
	/* Attribute the refusal to the first budget that failed. */
	if (lane_holds >= roce->sdma_qp_bundles)
		roce->stats.sdma_stall_qp_holds++;
	else if (!bundle_room)
		roce->stats.sdma_stall_eng_bundle++;
	else if (engine->descriptor_used + descriptor_count >
		 engine->descriptor_cap)
		roce->stats.sdma_stall_eng_desc++;
	else if (engine->page_used + page_count > engine->page_cap)
		roce->stats.sdma_stall_eng_page++;
	rqp->sdma_stalled = true;
	return false;
}

/*
 * Admission is a dormant producer seam: no live caller opens it and zero caps
 * refuse every request before any QP reference is acquired.
 */
static struct hfi2_dms_roce_sdma_cookie *
hfi2_dms_roce_sdma_admit(struct hfi2_dms_roce_qp *rqp, u8 lane,
			 u32 wqe_index, u32 wqe_generation,
			 enum ib_wr_opcode opcode, u32 first_psn, u32 last_psn,
			 u8 engine_idx, u16 bundle_count,
			 u16 descriptor_count, u16 page_count, bool needs_source,
			 bool copy_fallback,
			 struct hfi2_bulksvc_verbs_source *new_source,
			 struct hfi2_dms_roce_sdma_xfer *new_xfer)
{
	struct hfi2_dms_roce *roce;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_dms_roce_sdma_cookie *done = NULL;
	u16 lane_holds;
	bool xfer_new;
	unsigned int i;

	if (!rqp || engine_idx >= TXE_NUM_SDMA_ENGINES ||
	    (lane != HFI2_DMS_ROCE_LANE_REQUEST &&
	     lane != HFI2_DMS_ROCE_LANE_RESPONDER) ||
	    page_count > HFI2_DMS_ROCE_SDMA_BUNDLE_PACKET_MAX)
		return NULL;
	if (lane == HFI2_DMS_ROCE_LANE_RESPONDER &&
	    (rqp->resp_emitter != HFI2_DMS_ROCE_EMITTER_SDMA ||
	     engine_idx != rqp->request_engine_idx))
		return NULL;
	lane_holds = lane == HFI2_DMS_ROCE_LANE_REQUEST ?
		rqp->sdma_req_holds : rqp->sdma_resp_holds;
	roce = rqp->roce;
	if (!roce || !roce->svc || READ_ONCE(roce->sdma_admission_closed) ||
	    READ_ONCE(rqp->sdma_admission_stopped) ||
	    engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines)
		return NULL;
	engine = &roce->sdma_engines[engine_idx];
	if (bundle_count != 1 || !descriptor_count || !page_count) {
		roce->stats.sdma_admission_stall++;
		rqp->sdma_stalled = true;
		return NULL;
	}
	if (!roce_sdma_admit_room(rqp, engine, lane_holds, bundle_count,
				  descriptor_count, page_count,
				  lane == HFI2_DMS_ROCE_LANE_RESPONDER &&
				  wqe_index == HFI2_DMS_ROCE_RESP_ACK_INDEX))
		return NULL;

	if (WARN_ON_ONCE(!rqp->sdma_cookies || !rqp->sdma_xfers))
		return NULL;
	for (i = 0; i < HFI2_DMS_ROCE_SDMA_COOKIE_COUNT; i++) {
		if (!rqp->sdma_cookies[i].active) {
			done = &rqp->sdma_cookies[i];
			break;
		}
	}
	if (WARN_ON_ONCE(!done))
		return NULL;
	if (lane == HFI2_DMS_ROCE_LANE_REQUEST &&
	    !roce_request_emitter_select(rqp, HFI2_DMS_ROCE_EMITTER_SDMA,
					 engine_idx))
		return NULL;
	xfer_new = !roce_sdma_xfer_lookup(rqp, lane, wqe_index, wqe_generation,
				  opcode, first_psn, last_psn);
	if (xfer_new && needs_source && !new_source) {
		if (lane == HFI2_DMS_ROCE_LANE_REQUEST)
			roce_request_emitter_unselect_sdma(rqp);
		return NULL;
	}
	xfer = roce_sdma_xfer_get(rqp, lane, wqe_index, wqe_generation, opcode,
			  first_psn, last_psn, needs_source, copy_fallback,
			  new_source, new_xfer);

	if (!xfer) {
		if (lane == HFI2_DMS_ROCE_LANE_REQUEST)
			roce_request_emitter_unselect_sdma(rqp);
		return NULL;
	}

	/* Reset the pooled cookie in place, without a large stack temporary. */
	memset(done, 0, sizeof(*done));
	done->rqp = rqp;
	done->xfer = xfer;
	done->qp = rqp->qp;
	done->bundle_count = bundle_count;
	done->descriptor_count = descriptor_count;
	done->page_count = page_count;
	done->lane = lane;
	done->engine_idx = engine_idx;
	done->state = HFI2_DMS_ROCE_SDMA_COOKIE_LOCAL;
	done->active = true;
	done->local_hold = true;
	done->xfer_new = xfer_new;
	done->ack_hold = lane == HFI2_DMS_ROCE_LANE_REQUEST &&
		opcode != IB_WR_RDMA_READ;
	INIT_LIST_HEAD(&done->done_node);
	if (!rqp->sdma_local_holds)
		reinit_completion(&rqp->sdma_local_zero);
	rvt_get_qp(done->qp);
	rqp->sdma_local_holds++;
	if (lane == HFI2_DMS_ROCE_LANE_REQUEST)
		rqp->sdma_req_holds++;
	else
		rqp->sdma_resp_holds++;
	if (done->ack_hold)
		rqp->sdma_ack_holds++;
	atomic_inc(&roce->sdma_local_holds);

	xfer->local_holds++;
	engine->bundle_used += bundle_count;
	engine->descriptor_used += descriptor_count;
	engine->page_used += page_count;
	engine->bundle_high_water = max(engine->bundle_high_water,
					engine->bundle_used);
	engine->descriptor_high_water =
		max(engine->descriptor_high_water, engine->descriptor_used);
	engine->page_high_water = max(engine->page_high_water, engine->page_used);
	engine->bundle_admit_count += bundle_count;
	engine->descriptor_admit_count += descriptor_count;
	engine->page_admit_count += page_count;
	roce->stats.admitted_descriptors_current += descriptor_count;
	roce->stats.admitted_descriptors_high_water = max(
		roce->stats.admitted_descriptors_high_water,
		roce->stats.admitted_descriptors_current);
	return done;
}

static void hfi2_dms_roce_sdma_drain_callbacks(struct hfi2_dms_roce *roce)
{
	hfi2_dms_roce_sdma_consume_done(roce);
}

static void roce_sdma_cancel_requested(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_qp *rqp;
	unsigned long flags;

	while (!list_empty_careful(&roce->sdma_cancel)) {
		/*
		 * Lockless peek above: the producer, hfi2_dms_roce_quiesce_qp(),
		 * adds under sdma_cancel_lock and only then queues the worker,
		 * so a missed add is followed by a fresh run of this function.
		 * Once the service is stopping the producer does not queue the
		 * worker; see hfi2_dms_roce_quiesce_qp() for that case.
		 */
		spin_lock_irqsave(&roce->sdma_cancel_lock, flags);
		if (list_empty(&roce->sdma_cancel)) {
			spin_unlock_irqrestore(&roce->sdma_cancel_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->sdma_cancel,
				       struct hfi2_dms_roce_qp, sdma_cancel_node);
		list_del_init(&rqp->sdma_cancel_node);
		rqp->sdma_cancel_requested = false;
		spin_unlock_irqrestore(&roce->sdma_cancel_lock, flags);

		if (READ_ONCE(roce->svc->worker_exited))
			WARN_ON_ONCE(!READ_ONCE(roce->svc->stop_scheduling));
		complete_all(&rqp->sdma_cancel_done);
	}
}

static unsigned int roce_read_meta_count(struct rvt_qp *qp)
{
	return rvt_max_atomic(ib_to_rvt(qp->ibqp.device));
}

static struct hfi2_dms_roce_read_meta *
roce_alloc_read_meta(struct rvt_qp *qp, struct hfi2_devdata *dd)
{
	struct hfi2_dms_roce_read_meta *meta;

	meta = kcalloc_node(roce_read_meta_count(qp), sizeof(*meta),
			    GFP_KERNEL, dd->node);
	return meta;
}

static unsigned long *
roce_alloc_read_write_wqes(struct rvt_qp *qp, struct hfi2_devdata *dd)
{
	return bitmap_zalloc_node(qp->s_size, GFP_KERNEL, dd->node);
}

static unsigned long *
roce_alloc_read_software_wqes(struct rvt_qp *qp, struct hfi2_devdata *dd)
{
	return bitmap_zalloc_node(qp->s_size, GFP_KERNEL, dd->node);
}

static struct hfi2_dms_roce_hwp_window **
roce_alloc_read_hwp_windows(struct rvt_qp *qp, struct hfi2_devdata *dd)
{
	return kcalloc_node(qp->s_size, sizeof(struct hfi2_dms_roce_hwp_window *),
			     GFP_KERNEL, dd->node);
}

static unsigned int roce_wqe_index(const struct rvt_qp *qp,
				   const struct rvt_swqe *wqe)
{
	return ((const char *)wqe - (const char *)qp->s_wq) /
		(struct_size(wqe, sg_list, qp->s_max_sge));
}

static bool roce_hwp_pool_supported(void)
{
#ifdef CONFIG_X86
	return boot_cpu_data.x86_vendor == X86_VENDOR_INTEL;
#else
	return false;
#endif
}

static void roce_hwp_window_uninstall(struct hfi2_dms_roce *roce,
				      struct hfi2_dms_roce_hwp_window *window)
{
	if (window->rkey_bucket != HFI2_ROCE_MR_NO_BUCKET) {
		hfi2_dms_roce_rkey_invalidate(roce, window->rkey,
					      window->rkey_bucket);
		window->rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
	}
}

static void roce_hwp_window_unmap(struct hfi2_dms_roce_hwp_pool *pool,
				  struct hfi2_dms_roce_hwp_window *window)
{
	struct iommu_iotlb_gather gather;
	unsigned long flags;
	size_t unmapped;

	mutex_lock(&pool->roce->hwp_unmap_mutex);
	if (!window->mapped)
		goto unlock;
	iommu_iotlb_gather_init(&gather);
	unmapped = iommu_unmap_fast(pool->domain, window->map_iova,
				    window->mapped_len, &gather);
	if (unmapped != window->mapped_len)
		pr_warn_ratelimited("hfi2 RoCE: unmapped %zu of %u window bytes\n",
				    unmapped, window->mapped_len);
	iommu_iotlb_sync(pool->domain, &gather);
	window->map_iova = 0;
	window->mapped_len = 0;
	spin_lock_irqsave(&pool->lock, flags);
	if (window->released_ns) {
		u64 elapsed = ktime_get_ns() - window->released_ns;

		pool->pending--;
		pool->reaped++;
		pool->quarantine_ns += elapsed;
		pool->quarantine_max_ns = max(pool->quarantine_max_ns, elapsed);
		window->released_ns = 0;
	}
	window->mapped = false;
	window->state = HFI2_ROCE_HWP_FREE;
	spin_unlock_irqrestore(&pool->lock, flags);
unlock:
	mutex_unlock(&pool->roce->hwp_unmap_mutex);
}

static void roce_hwp_donor_run(struct hfi2_roce_kmr_async *request);

static int roce_hwp_donor_queue(struct hfi2_dms_roce_hwp_window *window)
{
	int ret;

	window->busy = true;
	reinit_completion(&window->idle);
	ret = hfi2_roce_kmr_queue(&window->pool->reservation, &window->request);
	if (ret) {
		window->busy = false;
		complete_all(&window->idle);
	}
	return ret;
}

/* A refused retirement job leaves the QP hold outstanding. */
static void roce_hwp_donor_retire_queue(struct hfi2_dms_roce_qp *rqp,
					struct hfi2_dms_roce_hwp_window *window)
{
	int ret = roce_hwp_donor_queue(window);

	if (ret)
		dd_dev_warn(rqp->dd,
			    "roce: QP %u could not queue donor window retirement (%d); its hold stays\n",
			    rqp->qp->ibqp.qp_num, ret);
}

static void roce_hwp_donor_put_pages(struct hfi2_dms_roce_hwp_window *window)
{
	u32 i;

	for (i = 0; i < window->nr_pages; i++)
		put_page(window->pages[i]);
	window->nr_pages = 0;
}

static int roce_hwp_donor_snapshot(struct hfi2_dms_roce_qp *rqp,
				   struct rvt_swqe *wqe,
				   struct hfi2_dms_roce_hwp_window *window);

static void roce_hwp_pool_quarantine_work(struct work_struct *work)
{
	struct hfi2_dms_roce_hwp_pool *pool =
		container_of(to_delayed_work(work), struct hfi2_dms_roce_hwp_pool,
			     quarantine_work);
	struct hfi2_dms_roce_hwp_window *window;
	struct hfi2_dms_roce_hwp_window *tmp;
	LIST_HEAD(release);
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	if (pool->stopping) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return;
	}
	list_for_each_entry_safe(window, tmp, &pool->quarantine, quarantine) {
		u64 delay_ns = (u64)HFI2_ROCE_HWP_WIN_QUARANTINE_MS * NSEC_PER_MSEC;
		u64 elapsed = ktime_get_ns() - window->released_ns;

		if (elapsed < delay_ns) {
			queue_delayed_work(system_wq, &pool->quarantine_work,
					   nsecs_to_jiffies(delay_ns - elapsed) + 1);
			break;
		}
		list_move_tail(&window->quarantine, &release);
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	list_for_each_entry_safe(window, tmp, &release, quarantine) {
		list_del_init(&window->quarantine);
		roce_hwp_window_unmap(pool, window);
	}
}

static void roce_hwp_window_queue(struct hfi2_dms_roce_hwp_pool *pool,
				  struct hfi2_dms_roce_hwp_window *window)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	pool->active--;
	pool->released++;
	pool->hold_ns += ktime_get_ns() - window->acquired_ns;
	pool->hold_max_ns = max(pool->hold_max_ns,
				ktime_get_ns() - window->acquired_ns);
	window->in_use = false;
	window->state = window->mapped ? HFI2_ROCE_HWP_RETIRING :
		HFI2_ROCE_HWP_FREE;
	if (window->mapped && list_empty(&window->quarantine)) {
		window->released_ns = ktime_get_ns();
		pool->pending++;
		pool->pending_high = max(pool->pending_high, pool->pending);
		list_add_tail(&window->quarantine, &pool->quarantine);
		/* Later releases must not postpone an older window's deadline. */
		if (!pool->stopping)
			queue_delayed_work(system_wq, &pool->quarantine_work,
					   msecs_to_jiffies(HFI2_ROCE_HWP_WIN_QUARANTINE_MS));
	}
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void roce_hwp_window_release_wqe(struct hfi2_dms_roce_qp *rqp,
					const struct rvt_swqe *wqe)
{
	struct hfi2_dms_roce_hwp_pool *pool;
	struct hfi2_dms_roce_hwp_window *window;
	unsigned int index;

	if (!rqp || !rqp->read_hwp_windows || !rqp->roce)
		return;
	index = roce_wqe_index(rqp->qp, wqe);
	if (index >= rqp->qp->s_size)
		return;
	window = rqp->read_hwp_windows[index];
	if (!window)
		return;
	if (rqp->hwp_cleanup_pending)
		return;
	rqp->read_hwp_windows[index] = NULL;
	pool = &rqp->roce->hwp_pool;
	if (pool->backend == HFI2_ROCE_HWP_DONOR) {
		unsigned long flags;

		roce_hwp_window_uninstall(rqp->roce, window);
		hfi2_read_csr(rqp->dd, CYR_EAL_ROCEV2_CFG);
		spin_lock_irqsave(&pool->lock, flags);
		window->cancelled = true;
		window->state = HFI2_ROCE_HWP_RETIRING;
		window->released_ns = ktime_get_ns();
		if (!window->busy)
			roce_hwp_donor_retire_queue(rqp, window);
		spin_unlock_irqrestore(&pool->lock, flags);
		return;
	}

	/* Errors retain the window until cleanup; successful LAST retired its RIF. */
	roce_hwp_window_uninstall(rqp->roce, window);
	roce_hwp_window_queue(pool, window);
}

static void roce_hwp_window_release_all(struct hfi2_dms_roce_qp *rqp)
{
	unsigned int i;

	if (!rqp || !rqp->read_hwp_windows)
		return;
	for (i = 0; i < rqp->qp->s_size; i++) {
		struct rvt_swqe *wqe;

		if (!rqp->read_hwp_windows[i])
			continue;
		wqe = rvt_get_swqe_ptr(rqp->qp, i);
		roce_hwp_window_release_wqe(rqp, wqe);
	}
}

#define HFI2_ROCE_HWP_CLEANUP_WARN_MS 10000
#define HFI2_ROCE_HWP_CLEANUP_MS 1000

static void roce_h15_clear_owner_locked(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_mregion *mr = rqp->h15_mr;

	rqp->h15_mr = NULL;
	rqp->h15_token = NULL;
	if (mr)
		rvt_put_mr(mr);
}

static void roce_hwp_hold_rx(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	lockdep_assert_held(&qp->r_lock);
	lockdep_assert_held(&qp->s_lock);
	if (rqp->hwp_rx_mr)
		return;
	spin_lock(&rqp->roce->rif_lock);
	if (rqp->h15_mr) {
		rqp->hwp_rx_mr = rqp->h15_mr;
		rqp->hwp_rx_pasid = rqp->h15_token;
		rqp->h15_mr = NULL;
		rqp->h15_token = NULL;
	} else if (rqp->rif_arm_kind == ROCE_RIF_ARM_H15 && rqp->rif_mr) {
		rqp->hwp_rx_mr = rqp->rif_mr;
		rvt_get_mr(rqp->hwp_rx_mr);
		rqp->hwp_rx_pasid = rqp->rif_token;
	}
	spin_unlock(&rqp->roce->rif_lock);
}

static bool roce_hwp_cleanup_start(struct hfi2_dms_roce_qp *rqp)
{
	unsigned int i;
	bool found = rqp->hwp_donor_holds != 0;

	lockdep_assert_held(&rqp->qp->s_lock);
	found |= !!rqp->hwp_rx_mr;
	if (rqp->hwp_cleanup_pending)
		return true;
	if (!rqp->roce || !rqp->read_hwp_windows || !rqp->read_internal_keys ||
	    !rqp->read_targets)
		return false;
	for (i = 0; i < rqp->qp->s_size; i++) {
		struct hfi2_dms_roce_hwp_window *window = rqp->read_hwp_windows[i];

		if (rqp->read_internal_keys[i])
			found = true;
		if (window) {
			roce_hwp_window_uninstall(rqp->roce, window);
			found = true;
		}
	}
	if (!found)
		return false;
	rqp->hwp_cleanup_pending = true;
	rqp->hwp_cleanup_start_j = jiffies;
	rqp->hwp_cleanup_warn_j = jiffies;
	reinit_completion(&rqp->hwp_cleanup_idle);
	rvt_get_qp(rqp->qp);
	queue_delayed_work(system_unbound_wq, &rqp->hwp_cleanup_work, 0);
	return true;
}

static bool roce_hwp_defer_error(struct hfi2_dms_roce_qp *rqp,
				 struct rvt_swqe *wqe, enum ib_wc_status status,
				 enum rvt_qp_lock_state lock_state)
{
	if (!roce_hwp_cleanup_start(rqp))
		return false;
	if (!rqp->hwp_error_pending) {
		rqp->hwp_error_pending = true;
		rqp->hwp_error_index = roce_wqe_index(rqp->qp, wqe);
		rqp->hwp_error_status = status;
	}
	rvt_error_qp(rqp->qp, IB_WC_WR_FLUSH_ERR, lock_state);
	return true;
}

static int roce_hwp_cleanup_drain(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_roce_rx_mark mark;
	int ret;

#if HFI2_DMS_ROCE_INJECT
	if (READ_ONCE(roce_inject_hwp_cleanup_drain))
		return -ETIMEDOUT;
#endif
	if (READ_ONCE(rqp->hwp_fencing))
		return -EAGAIN;
	if (READ_ONCE(roce->hwp_pool.quiesced) && !rqp->hwp_rx_mr) {
		unsigned int i;

		for (i = 0; i < rqp->qp->s_size; i++)
			if (rqp->read_internal_keys[i])
				break;
		if (i == rqp->qp->s_size)
			return 0;
	}
	if (!READ_ONCE(roce->active) || READ_ONCE(roce->svc->stop_scheduling) ||
	    READ_ONCE(roce->svc->worker_exited))
		return -ENODEV;
	if (hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		return -ENXIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	ret = hfi2_dms_roce_wait_rx(roce, &mark);
	if (ret)
		return ret;
	ret = roce_rif_invalidate_qp(rqp);
	if (ret < 0)
		return ret;
	if (hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		return -ENXIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	return hfi2_dms_roce_wait_rx(roce, &mark);
}

static bool roce_hwp_cleanup_expired(struct hfi2_dms_roce *roce,
				     unsigned long start, int ret)
{
	return ret == -ENXIO || !READ_ONCE(roce->active) ||
		READ_ONCE(roce->svc->stop_scheduling) ||
		READ_ONCE(roce->svc->worker_exited) ||
		time_after_eq(jiffies, start + msecs_to_jiffies(HFI2_ROCE_HWP_CLEANUP_MS));
}

static void roce_hwp_cleanup_count_fence(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;

	spin_lock_irqsave(&rqp->qp->s_lock, flags);
	if (!rqp->hwp_cleanup_counted) {
		rqp->hwp_cleanup_counted = true;
		atomic64_inc(&rqp->roce->fence_stats.hwp_cleanup_fenced);
	}
	spin_unlock_irqrestore(&rqp->qp->s_lock, flags);
}

static int roce_hwp_pool_fence(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;

	if (!pool->token)
		return -ENOENT;
	if (pool->backend == HFI2_ROCE_HWP_PAGING)
		return hfi2_roce_pasid_fence(roce->dd, pool->token,
					   pool->domain, &pool->attached);
	return hfi2_roce_pasid_fence(roce->dd, pool->token, NULL, NULL);
}

static int roce_hwp_cleanup_fence(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_hwp_pool *pool = &rqp->roce->hwp_pool;
	unsigned long flags;
	unsigned int i;
	bool pool_used;
	int ret;

	spin_lock_irqsave(&qp->s_lock, flags);
	rqp->hwp_rx_blocked = true;
	roce_rif_cancel(rqp);
	pool_used = rqp->hwp_donor_holds != 0;
	for (i = 0; i < qp->s_size; i++)
		pool_used |= !!rqp->read_hwp_windows[i];
	spin_unlock_irqrestore(&qp->s_lock, flags);
	if (pool_used) {
		ret = roce_hwp_pool_fence(rqp->roce);
		if (ret)
			return ret;
		if (pool->backend == HFI2_ROCE_HWP_DONOR)
			WRITE_ONCE(pool->reservation.poisoned, true);
	}
	if (rqp->hwp_rx_mr) {
		if (!rqp->hwp_rx_pasid)
			return -ENOENT;
		ret = hfi2_roce_pasid_fence(rqp->dd, rqp->hwp_rx_pasid, NULL, NULL);
		if (ret)
			return ret;
	}
	for (i = 0; i < qp->s_size; i++) {
		if (!rqp->read_internal_keys[i])
			continue;
		if (!rqp->read_targets[i].pasid)
			return -ENOENT;
		ret = hfi2_roce_pasid_fence(rqp->dd, rqp->read_targets[i].pasid,
					    NULL, NULL);
		if (ret)
			return ret;
	}
	return 0;
}

static void roce_hwp_donor_recover(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce_hwp_pool *pool = &rqp->roce->hwp_pool;
	unsigned long flags, sflags;
	u32 i;

	if (pool->backend != HFI2_ROCE_HWP_DONOR || !hfi2_roce_pasid_fenced(pool->token))
		return;
	for (i = 0; i < pool->win_count; i++) {
		struct hfi2_dms_roce_hwp_window *window = &pool->windows[i];
		bool drop = false;

		spin_lock_irqsave(&rqp->qp->s_lock, sflags);
		spin_lock_irqsave(&pool->lock, flags);
		if (window->owner == rqp && !window->busy) {
			if (rqp->read_hwp_windows[window->wqe_index] == window)
				rqp->read_hwp_windows[window->wqe_index] = NULL;
			window->owner = NULL;
			window->cancelled = true;
			window->exhausted = true;
			window->in_use = false;
			roce_hwp_donor_put_pages(window);
			rqp->hwp_donor_holds--;
			rqp->donor_waiting = false;
			if (!READ_ONCE(rqp->tx_cancelled))
				hfi2_dms_roce_enqueue(rqp->qp);
			complete_all(&window->idle);
			drop = true;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
		spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
		if (drop)
			rvt_put_qp(rqp->qp);
	}
}

static void roce_hwp_cleanup_work(struct work_struct *work)
{
	struct hfi2_dms_roce_qp *rqp =
		container_of(to_delayed_work(work), struct hfi2_dms_roce_qp,
			     hwp_cleanup_work);
	struct rvt_qp *qp = rqp->qp;
	struct rvt_mregion *rx_mr;
	unsigned long flags, rflags;
	unsigned int i;
	int ret;

	spin_lock_irqsave(&qp->s_lock, flags);
	rx_mr = rqp->hwp_rx_mr;
	spin_unlock_irqrestore(&qp->s_lock, flags);
	for (i = 0; i < qp->s_size; i++) {
		struct rvt_swqe *wqe;
		u32 key = rqp->read_internal_keys[i];

		if (!key)
			continue;
		wqe = rvt_get_swqe_ptr(qp, i);
		hfi2_roce_revoke_read_key(rqp->dd, wqe->sg_list[0].mr, key);
	}
	ret = rqp->hwp_fence_required ? -ETIMEDOUT : roce_hwp_cleanup_drain(rqp);
	if (ret) {
		atomic64_inc(&rqp->roce->stats.hwp_cleanup_drain_err);
		if (rqp->hwp_fence_required ||
		    roce_hwp_cleanup_expired(rqp->roce, rqp->hwp_cleanup_start_j, ret)) {
			rqp->hwp_fence_required = true;
			ret = roce_hwp_cleanup_fence(rqp);
			if (!ret)
				roce_hwp_donor_recover(rqp);
			if (!ret)
				roce_hwp_cleanup_count_fence(rqp);
			if (ret)
				atomic64_inc(&rqp->roce->fence_stats.hwp_cleanup_fence_fail);
		}
		if (ret) {
			if (time_after_eq(jiffies, rqp->hwp_cleanup_warn_j)) {
				dd_dev_warn_ratelimited(rqp->dd,
							"roce: QP %u cleanup failed (%d); holding buffers\n",
							qp->ibqp.qp_num, ret);
				rqp->hwp_cleanup_warn_j = jiffies +
					msecs_to_jiffies(HFI2_ROCE_HWP_CLEANUP_WARN_MS);
			}
			queue_delayed_work(system_unbound_wq, &rqp->hwp_cleanup_work,
					   msecs_to_jiffies(20));
			return;
		}
	}
	spin_lock_irqsave(&qp->r_lock, rflags);
	spin_lock_irqsave(&qp->s_lock, flags);
	if (rqp->hwp_rx_mr != rx_mr || (rx_mr && rqp->hwp_fencing)) {
		spin_unlock_irqrestore(&qp->s_lock, flags);
		spin_unlock_irqrestore(&qp->r_lock, rflags);
		queue_delayed_work(system_unbound_wq, &rqp->hwp_cleanup_work,
				   msecs_to_jiffies(20));
		return;
	}
	if (rqp->hwp_rx_mr && (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK))
		rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
	rqp->hwp_cleanup_pending = false;
	roce_hwp_window_release_all(rqp);
	if (rqp->hwp_donor_holds) {
		rqp->hwp_cleanup_pending = true;
		spin_unlock_irqrestore(&qp->s_lock, flags);
		spin_unlock_irqrestore(&qp->r_lock, rflags);
		if (roce_hwp_cleanup_expired(rqp->roce, rqp->hwp_cleanup_start_j,
					     -ETIMEDOUT))
			rqp->hwp_fence_required = true;
		queue_delayed_work(system_unbound_wq, &rqp->hwp_cleanup_work,
				   msecs_to_jiffies(20));
		return;
	}
	if (rqp->hwp_rx_mr) {
		rvt_put_mr(rqp->hwp_rx_mr);
		rqp->hwp_rx_mr = NULL;
		rqp->hwp_rx_pasid = NULL;
	}
	memset(rqp->read_internal_keys, 0,
	       qp->s_size * sizeof(*rqp->read_internal_keys));
	memset(rqp->read_targets, 0, qp->s_size * sizeof(*rqp->read_targets));
	if (!READ_ONCE(rqp->tx_cancelled))
		hfi2_dms_roce_enqueue(qp);
	complete_all(&rqp->hwp_cleanup_idle);
	spin_unlock_irqrestore(&qp->s_lock, flags);
	spin_unlock_irqrestore(&qp->r_lock, rflags);
	rvt_put_qp(qp);
}

static bool roce_hwp_mr_uses_pasid(struct rvt_mregion *mr, u32 pasid)
{
	struct hfi2_roce_mr_priv *priv = mr ? mr->driver_priv : NULL;

	return priv && priv->pasid && priv->pasid->pasid == pasid;
}

static void roce_hwp_fence_qp(struct rvt_qp *qp, u64 value)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	u32 pasid = value;
	enum hfi2_roce_fence_outcome outcome = value >> 32;
	unsigned long flags, sflags;
	u32 i, j;
	bool match;

	if (!rqp || roce_qp_is_ud(qp))
		return;
	spin_lock_irqsave(&qp->r_lock, flags);
	spin_lock_irqsave(&qp->s_lock, sflags);
	if (outcome == HFI2_ROCE_FENCE_DONE) {
		if (rqp->hwp_fence_pasid == pasid) {
			if (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
			roce_rif_invalidate_qp(rqp);
			rqp->hwp_fencing = false;
			rqp->hwp_fence_pasid = 0;
			if (!READ_ONCE(rqp->tx_cancelled))
				hfi2_dms_roce_enqueue(qp);
		}
		goto unlock;
	}
	match = (rqp->hwp_donor_holds && rqp->roce->hwp_pool.token->pasid == pasid) ||
		(qp->r_sge.num_sge && roce_hwp_mr_uses_pasid(qp->r_sge.sge.mr, pasid)) ||
		rqp->vrma_pasid == pasid ||
		(rqp->hwp_rx_pasid && rqp->hwp_rx_pasid->pasid == pasid) ||
		(rqp->h15_token && rqp->h15_token->pasid == pasid) ||
		(rqp->rif_arm_kind == ROCE_RIF_ARM_H15 && rqp->rif_token &&
		 rqp->rif_token->pasid == pasid) ||
		(rqp->h15_bucket >= 0 && rqp->h15_pasid == pasid);
	for (i = qp->s_last; !match && i != READ_ONCE(qp->s_head);) {
		struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, i);

		if (wqe->wr.opcode == IB_WR_RDMA_READ) {
			if (rqp->read_targets && rqp->read_targets[i].pasid &&
			    rqp->read_targets[i].pasid->pasid == pasid)
				match = true;
			if (rqp->read_hwp_windows && rqp->read_hwp_windows[i] &&
			    rqp->roce->hwp_pool.token->pasid == pasid)
				match = true;
			for (j = 0; !match && j < wqe->wr.num_sge; j++)
				match = roce_hwp_mr_uses_pasid(wqe->sg_list[j].mr, pasid);
		}
		if (++i == qp->s_size)
			i = 0;
	}
	if (!match && rqp->hwp_fence_pasid != pasid)
		goto unlock;
	rqp->hwp_rx_blocked = true;
	roce_rif_cancel(rqp);
	if (outcome == HFI2_ROCE_FENCE_ABORT) {
		roce_hwp_cleanup_start(rqp);
		/* A failed attempt ends the join, not DMA ownership or RX blocking. */
		if (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)
			rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
		if (rqp->hwp_fence_pasid == pasid) {
			rqp->hwp_fencing = false;
			rqp->hwp_fence_pasid = 0;
		}
		if (!READ_ONCE(rqp->tx_cancelled))
			hfi2_dms_roce_enqueue(qp);
	} else {
		rqp->hwp_fence_pasid = pasid;
		rqp->hwp_fencing = true;
		roce_hwp_hold_rx(rqp);
		roce_hwp_cleanup_start(rqp);
	}
unlock:
	spin_unlock_irqrestore(&qp->s_lock, sflags);
	spin_unlock_irqrestore(&qp->r_lock, flags);
}

void hfi2_dms_roce_fence_qps(struct hfi2_dms_roce *roce, u32 pasid,
			     enum hfi2_roce_fence_outcome outcome)
{
	if (roce && roce->initialized)
		rvt_qp_iter(&roce->dd->verbs_dev.rdi,
			    pasid | ((u64)outcome << 32), roce_hwp_fence_qp);
}

static void roce_hwp_pool_sync_qp(struct rvt_qp *qp, u64 unused)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	unsigned long flags;

	if (!rqp)
		return;
	/* Wait out the synchronous paging mapper without releasing its WQE. */
	spin_lock_irqsave(&qp->s_lock, flags);
	spin_unlock_irqrestore(&qp->s_lock, flags);
}

static void roce_hwp_pool_quiesce(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
	unsigned long flags;
	bool enabled;
	u32 i;

	if (!pool->domain && !pool->pd && !pool->windows &&
	    !pool->reservation.donor)
		return;
	if (pool->quiesced)
		return;
	spin_lock_irqsave(&pool->lock, flags);
	enabled = pool->enabled;
	pool->stopping = true;
	if (pool->backend == HFI2_ROCE_HWP_DONOR)
		pool->enabled = false;
	spin_unlock_irqrestore(&pool->lock, flags);
	if (WARN_ON_ONCE(!roce->dd || !roce->dd->pcidev))
		return;
	if (pool->backend == HFI2_ROCE_HWP_DONOR) {
		unsigned long sflags;

		roce->stats.hwp_pool_enabled = 0;

		for (i = 0; pool->windows && i < pool->win_count; i++) {
			struct hfi2_dms_roce_hwp_window *window = &pool->windows[i];
			struct hfi2_dms_roce_qp *owner;

			spin_lock_irqsave(&pool->lock, flags);
			owner = window->owner;
			if (owner)
				rvt_get_qp(owner->qp);
			spin_unlock_irqrestore(&pool->lock, flags);
			if (owner) {
				spin_lock_irqsave(&owner->qp->s_lock, sflags);
				if (ib_rvt_state_ops[owner->qp->state] & RVT_PROCESS_SEND_OK)
					rvt_error_qp(owner->qp, IB_WC_LOC_PROT_ERR,
						     RVT_QP_LOCK_STATE_S);
				spin_lock_irqsave(&pool->lock, flags);
				/* The error callback can retire it while s_lock is dropped. */
				if (window->owner == owner) {
					if (!window->cancelled) {
						window->state = HFI2_ROCE_HWP_RETIRING;
						window->released_ns = ktime_get_ns();
					}
					window->cancelled = true;
					owner->read_hwp_windows[window->wqe_index] = NULL;
					if (!window->busy)
						roce_hwp_donor_retire_queue(owner, window);
				}
				spin_unlock_irqrestore(&pool->lock, flags);
				spin_unlock_irqrestore(&owner->qp->s_lock, sflags);
			}
			if (owner)
				roce_hwp_wait_donor_holds(owner);
			if (window->pool)
				while (!wait_for_completion_timeout(&window->idle, HZ))
					dd_dev_warn_ratelimited(roce->dd,
								"roce: donor retirement still owns a window\n");
			/* Wait for the donor worker to leave its final pool-lock section. */
			spin_lock_irqsave(&pool->lock, flags);
			spin_unlock_irqrestore(&pool->lock, flags);
			if (owner)
				rvt_put_qp(owner->qp);
		}
		hfi2_roce_kmr_unreserve(&pool->reservation);
		pool->quiesced = true;
		return;
	}
	WRITE_ONCE(pool->pasid.live, false);
	/* Serialize with a paging map/install already running under s_lock. */
	if (enabled)
		rvt_qp_iter(&roce->dd->verbs_dev.rdi, 0, roce_hwp_pool_sync_qp);
	if (enabled && READ_ONCE(roce->active)) {
		DECLARE_BITMAP(scanned, EAL_RIF_TABLE_ROWS);
		struct hfi2_dms_roce_rx_mark mark;
		int ret, failed = 0;

		hfi2_dms_roce_rif_pasid_deactivate(roce, pool->pasid.pasid);
		hfi2_dms_roce_rkey_invalidate_pasid(roce, pool->pasid.pasid);
		hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
		hfi2_dms_roce_rx_mark(roce, &mark);
		ret = hfi2_dms_roce_wait_rx(roce, &mark);
		failed |= ret;
		ret = hfi2_dms_roce_rif_invalidate_pasid(roce, pool->pasid.pasid,
							 failed != 0, scanned);
		if (ret < 0)
			failed = ret;
		hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
		hfi2_dms_roce_rx_mark(roce, &mark);
		ret = hfi2_dms_roce_wait_rx(roce, &mark);
		failed |= ret;
		ret = hfi2_dms_roce_rif_pasid_finish(roce, pool->pasid.pasid, scanned, ret);
		if (ret < 0)
			failed = ret;
		if (failed)
			while ((ret = roce_hwp_pool_fence(roce))) {
				atomic64_inc(&roce->fence_stats.hwp_cleanup_fence_fail);
				dd_dev_warn_ratelimited(roce->dd,
							"roce: pool fence failed (%d); holding mappings\n",
							ret);
				msleep(20);
			}
	} else if (enabled) {
		int ret;

		while ((ret = roce_hwp_pool_fence(roce))) {
			atomic64_inc(&roce->fence_stats.hwp_cleanup_fence_fail);
			dd_dev_warn_ratelimited(roce->dd,
						"roce: stopped pool fence failed (%d); holding mappings\n",
						ret);
			msleep(20);
		}
	}
	if (roce->initialized)
		kfree(roce_rif_pasid_take(roce, pool->pasid.pasid));
	if (pool->windows)
		cancel_delayed_work_sync(&pool->quarantine_work);
	/* Unmap before client pages are freed; retain descriptors for saved pointers. */
	for (i = 0; pool->windows && i < pool->win_count; i++) {
		roce_hwp_window_uninstall(roce, &pool->windows[i]);
		roce_hwp_window_unmap(pool, &pool->windows[i]);
	}
	/* Keep window lookup enabled until in-flight placement reports drain. */
	spin_lock_irqsave(&pool->lock, flags);
	pool->enabled = false;
	spin_unlock_irqrestore(&pool->lock, flags);
	roce->stats.hwp_pool_enabled = 0;
	pool->quiesced = true;
}

static void roce_hwp_pool_exit(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
	struct device *dev;
	u32 i;

	if (!pool->domain && !pool->pd && !pool->windows &&
	    !pool->reservation.donor)
		return;
	roce_hwp_pool_quiesce(roce);
	if (WARN_ON_ONCE(!roce->dd || !roce->dd->pcidev))
		return;
	dev = &roce->dd->pcidev->dev;
	if (pool->windows) {
		for (i = 0; i < pool->win_count; i++)
			if (pool->windows[i].slot)
				rvt_unpublish_internal_mr(pool->windows[i].slot);
		synchronize_rcu();
		for (i = 0; i < pool->win_count; i++)
			if (pool->windows[i].slot)
				rvt_free_internal_mr(pool->windows[i].slot);
	}
	if (pool->pd)
		ib_dealloc_pd(pool->pd);
	mutex_lock(&roce->dd->roce_pasid_mutex);
	if (pool->attached) {
		iommu_detach_device_pasid(pool->domain, dev, pool->pasid.pasid);
		pool->attached = false;
	}
	if (pool->backend == HFI2_ROCE_HWP_PAGING &&
	    !READ_ONCE(pool->pasid.quiesce_failed) &&
	    pool->pasid.pasid != IOMMU_PASID_INVALID)
		iommu_free_global_pasid(pool->pasid.pasid);
	if (pool->domain)
		iommu_domain_free(pool->domain);
	mutex_unlock(&roce->dd->roce_pasid_mutex);
	if (pool->windows)
		for (i = 0; i < pool->win_count; i++) {
			if (WARN_ON_ONCE(pool->windows[i].nr_pages))
				continue;
			kfree(pool->windows[i].pages);
		}
	roce->stats.hwp_pool_enabled = 0;
	kfree(pool->windows);
	memset(pool, 0, sizeof(*pool));
}

void hfi2_dms_roce_hwp_pool_start(struct hfi2_dms_roce *roce)
{
	if (!roce_hwp_pool || !roce->hwp_mode)
		return;
	if (roce_hwp_pool_init(roce))
		pr_info("hfi2 RoCE: private READ IOVA window pool unavailable\n");
}

static int roce_hwp_pool_init(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
	struct device *dev = &roce->dd->pcidev->dev;
	u64 span;
	u32 i;
	int ret;

	if (!roce_hwp_pool || !roce->hwp_mode)
		return 0;
	if (hfi2_roce_kmr_pasid_enabled && !roce_hwp_pool_supported())
		return -EOPNOTSUPP;
	pool->pasid.pasid = IOMMU_PASID_INVALID;
	pool->roce = roce;
	spin_lock_init(&pool->lock);
	mutex_init(&roce->hwp_unmap_mutex);
	INIT_LIST_HEAD(&pool->quarantine);
	INIT_DELAYED_WORK(&pool->quarantine_work, roce_hwp_pool_quarantine_work);
	pool->token = &pool->pasid;
	if (!hfi2_roce_kmr_pasid_enabled) {
		if (check_mul_overflow((u64)HFI2_ROCE_HWP_WIN_BYTES,
				       (u64)HFI2_ROCE_HWP_WIN_COUNT, &span)) {
			ret = -ERANGE;
			goto out;
		}
		ret = hfi2_roce_kmr_reserve(roce->dd, span, &pool->reservation);
		if (ret)
			goto out;
		pool->backend = HFI2_ROCE_HWP_DONOR;
		pool->token = pool->reservation.token;
		pool->donor = pool->reservation.donor;
		pool->pasid.pasid = pool->token->pasid;
		pool->iova_base = pool->reservation.va;
		pool->win_bytes = HFI2_ROCE_HWP_WIN_BYTES;
		pool->win_count = HFI2_ROCE_HWP_WIN_COUNT;
		goto alloc_slots;
	}
	pool->domain =
		iommu_paging_domain_alloc_flags(dev, IOMMU_HWPT_ALLOC_PASID);
	if (IS_ERR(pool->domain)) {
		ret = PTR_ERR(pool->domain);
		pool->domain = NULL;
		goto out;
	}
	pool->pasid.pasid = iommu_alloc_global_pasid(dev);
	if (pool->pasid.pasid == IOMMU_PASID_INVALID) {
		ret = -ENOSPC;
		goto out;
	}
	ret = iommu_attach_device_pasid(pool->domain, dev, pool->pasid.pasid,
					NULL);
	if (ret)
		goto out;
	pool->attached = true;
	pool->win_bytes = HFI2_ROCE_HWP_WIN_BYTES;
	pool->win_count = HFI2_ROCE_HWP_WIN_COUNT;
	pool->iova_base = SZ_4G + SZ_1T;
	if (check_mul_overflow((u64)pool->win_bytes, (u64)pool->win_count,
			       &span) ||
	    pool->iova_base < pool->domain->geometry.aperture_start ||
	    span - 1 > pool->domain->geometry.aperture_end - pool->iova_base) {
		ret = -ERANGE;
		goto out;
	}
alloc_slots:
	pool->pd = ib_alloc_pd(&roce->dd->verbs_dev.rdi.ibdev, 0);
	if (IS_ERR(pool->pd)) {
		ret = PTR_ERR(pool->pd);
		pool->pd = NULL;
		goto out;
	}
	pool->windows = kcalloc_node(pool->win_count, sizeof(*pool->windows),
				     GFP_KERNEL, roce->dd->node);
	if (!pool->windows) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < pool->win_count; i++) {
		struct hfi2_dms_roce_hwp_window *window = &pool->windows[i];

		window->rkey_bucket = HFI2_ROCE_MR_NO_BUCKET;
		window->pool = pool;
		init_completion(&window->idle);
		complete_all(&window->idle);
		INIT_LIST_HEAD(&window->request.list);
		window->request.run = roce_hwp_donor_run;
		if (pool->backend == HFI2_ROCE_HWP_DONOR) {
			window->pages = kcalloc(pool->win_bytes >> PAGE_SHIFT,
						sizeof(*window->pages), GFP_KERNEL);
			if (!window->pages) {
				ret = -ENOMEM;
				goto out;
			}
		}
		INIT_LIST_HEAD(&window->quarantine);
		window->slot = rvt_alloc_internal_mr(pool->pd);
		if (IS_ERR(window->slot)) {
			ret = PTR_ERR(window->slot);
			window->slot = NULL;
			goto out;
		}
		window->iova = pool->iova_base + (u64)i * pool->win_bytes;
	}
	pool->pasid.live = true;
	pool->enabled = true;
	roce->stats.hwp_pool_enabled = 1;
	dd_dev_info(roce->dd,
		    "roce: private READ IOVA window pool PASID %u, %u x %u KiB at 0x%llx\n",
		    pool->pasid.pasid, pool->win_count, pool->win_bytes >> 10,
		    (unsigned long long)pool->iova_base);
	return 0;
out:
	roce_hwp_pool_exit(roce);
	return ret;
}

static int roce_hwp_window_install(struct hfi2_dms_roce *roce,
				   struct hfi2_dms_roce_hwp_window *window,
				   const struct rvt_swqe *wqe)
{
	struct hfi2_dms_roce_rkey_entry entry = {
		.start_vaddr = window->iova +
			offset_in_page(wqe->sg_list[0].mem.vaddr),
		.length = wqe->length,
		.rkey = window->rkey,
		.pasid = roce->hwp_pool.pasid.pasid,
		.permissions = EAL_RKEY_PERMISSION_WRITE,
		.internal = true,
	};
	int bucket;

	bucket = hfi2_dms_roce_rkey_install(roce, &entry, roce->hwp_pool.token);
	if (bucket >= 0)
		window->rkey_bucket = bucket;
	return bucket;
}

static int roce_hwp_window_phys(const struct rvt_sge *sge, u32 offset,
				u32 *bytes, phys_addr_t *phys)
{
	struct rvt_mregion *mr = sge->mr;
	unsigned long addr;
	struct page *page;

	if (offset >= sge->sge_length || sge->mem.type != RVT_MEM_KERNEL)
		return -EINVAL;
	if (mr && mr->lkey) {
		struct rvt_seg *first;
		u64 mapped_len;
		u64 page_index;
		u64 nr_pages;
		u64 in_region;
		u32 page_map;
		u32 page_seg;
		struct rvt_seg *seg;

		if (mr->page_shift != PAGE_SHIFT ||
		    sge->m >= mr->mapsz || sge->n >= RVT_SEGSZ ||
		    !mr->map[sge->m])
			return -EINVAL;
		first = &mr->map[sge->m]->segs[sge->n];
		if (first->type != RVT_MEM_KERNEL || first->length != PAGE_SIZE ||
		    sge->mem.vaddr < first->vaddr)
			return -EINVAL;
		/* offset is SGE-relative; the page-map cursor includes its start. */
		mapped_len = (u8 *)sge->mem.vaddr - (u8 *)first->vaddr;
		if (mapped_len >= PAGE_SIZE ||
		    check_add_overflow(mapped_len, (u64)offset, &in_region))
			return -EINVAL;
		page_index = (u64)sge->m * RVT_SEGSZ + sge->n +
			(in_region >> PAGE_SHIFT);
		nr_pages = DIV_ROUND_UP(mr->offset + mr->length, PAGE_SIZE);
		if (page_index >= mr->max_segs || page_index >= nr_pages)
			return -EINVAL;
		page_map = page_index / RVT_SEGSZ;
		page_seg = page_index % RVT_SEGSZ;
		if (page_map >= mr->mapsz || !mr->map[page_map])
			return -EINVAL;
		seg = &mr->map[page_map]->segs[page_seg];
		if (seg->type != RVT_MEM_KERNEL)
			return -EINVAL;
		addr = (unsigned long)seg->vaddr +
			(in_region & ~PAGE_MASK);
	} else {
		addr = (unsigned long)sge->mem.vaddr + offset;
	}
	if (virt_addr_valid((void *)addr)) {
		*phys = virt_to_phys((void *)addr);
	} else if (is_vmalloc_addr((void *)addr)) {
		page = vmalloc_to_page((void *)addr);
		if (!page)
			return -EINVAL;
		*phys = page_to_phys(page) + offset_in_page(addr);
	} else {
		return -EINVAL;
	}
	*bytes = min_t(u32, PAGE_SIZE - offset_in_page(addr),
		       sge->sge_length - offset);
	return 0;
}

static bool roce_hwp_window_layout_valid(const struct rvt_swqe *wqe)
{
	u32 i;

	for (i = 0; i < wqe->wr.num_sge; i++) {
		const struct rvt_sge *sge = &wqe->sg_list[i];

		if (sge->mem.type != RVT_MEM_KERNEL || !sge->sge_length)
			return false;
		if (i + 1 < wqe->wr.num_sge &&
		    (!IS_ALIGNED((unsigned long)sge->mem.vaddr +
					sge->sge_length, PAGE_SIZE) ||
		     !IS_ALIGNED((unsigned long)wqe->sg_list[i + 1].mem.vaddr,
				 PAGE_SIZE)))
			return false;
	}
	return true;
}

static int roce_hwp_window_map_sges(struct hfi2_dms_roce_qp *rqp,
				    struct rvt_swqe *wqe,
				    struct hfi2_dms_roce_hwp_window *window)
{
	struct hfi2_dms_roce_hwp_pool *pool = &rqp->roce->hwp_pool;
	u32 sge_index = 0;
	u32 sge_offset = 0;
	u32 mapped = 0;
	u32 pages = 0;
	int ret = 0;

	window->map_iova = window->iova & PAGE_MASK;
	if (wqe->length > pool->win_bytes -
	    (window->iova - window->map_iova))
		return -E2BIG;
	while (mapped < wqe->length) {
		struct rvt_sge *sge;
		phys_addr_t phys;
		u32 bytes;

		if (sge_index >= wqe->wr.num_sge) {
			ret = -EINVAL;
			break;
		}
		sge = &wqe->sg_list[sge_index];
		if (sge_offset == sge->sge_length) {
			sge_index++;
			sge_offset = 0;
			continue;
		}
		ret = roce_hwp_window_phys(sge, sge_offset, &bytes, &phys);
		if (ret) {
			rqp->roce->stats.hwp_rd_win_phys_err++;
			break;
		}
		ret = iommu_map(pool->domain, window->map_iova + pages * PAGE_SIZE,
				phys & PAGE_MASK, PAGE_SIZE, IOMMU_READ | IOMMU_WRITE,
				GFP_ATOMIC);
		if (ret) {
			rqp->roce->stats.hwp_rd_win_iommu_err++;
			if (ret == -ENOMEM)
				rqp->roce->stats.hwp_rd_win_iommu_nomem++;
			if (ret == -EEXIST)
				rqp->roce->stats.hwp_rd_win_iommu_exists++;
			break;
		}
		pages++;
		mapped += bytes;
		sge_offset += bytes;
	}
	if (ret || mapped != wqe->length) {
		window->mapped_len = pages * PAGE_SIZE;
		window->mapped = !!pages;
		return ret ?: -EINVAL;
	}
	window->mapped_len = pages * PAGE_SIZE;
	window->mapped = true;
	return 0;
}

static int roce_hwp_donor_snapshot(struct hfi2_dms_roce_qp *rqp,
				   struct rvt_swqe *wqe,
				   struct hfi2_dms_roce_hwp_window *window)
{
	u32 index = 0, offset = 0, mapped = 0;
	int ret = -EINVAL;

	lockdep_assert_held(&rqp->qp->s_lock);
	while (mapped < wqe->length) {
		phys_addr_t phys;
		struct page *page;
		u32 bytes;

		if (index >= wqe->wr.num_sge)
			goto fail;
		if (offset == wqe->sg_list[index].sge_length) {
			index++;
			offset = 0;
			continue;
		}
		/*
		 * LOCAL_INV/FastReg can replace registered page lists outside
		 * s_lock. DMA MRs have no registration cycle to race or revoke.
		 */
		if (wqe->sg_list[index].mr && wqe->sg_list[index].mr->lkey) {
			ret = -EOPNOTSUPP;
			goto fail;
		}
		ret = roce_hwp_window_phys(&wqe->sg_list[index], offset, &bytes, &phys);
		if (ret)
			goto fail;
		if (!pfn_valid(PHYS_PFN(phys))) {
			ret = -EOPNOTSUPP;
			goto fail;
		}
		page = pfn_to_page(PHYS_PFN(phys));
		if (is_zone_device_page(page) || PageReserved(page) || PageSlab(page) ||
		    PageCompound(page) || !get_page_unless_zero(page)) {
			ret = -EOPNOTSUPP;
			goto fail;
		}
		window->pages[window->nr_pages++] = page;
		bytes = min(bytes, wqe->length - mapped);
		mapped += bytes;
		offset += bytes;
	}
	window->mapped_len = window->nr_pages << PAGE_SHIFT;
	window->map_iova = window->iova;
	return 0;
fail:
	roce_hwp_donor_put_pages(window);
	return ret;
}

static int
roce_rif_reclaim_entry_current_mutex_held(struct hfi2_dms_roce *roce,
					  const struct hfi2_dms_roce_rif_entry *candidate,
					  int bucket);
static void roce_rif_invalidate_mutex_held(struct hfi2_dms_roce *roce, u32 qpn,
					   u8 bucket);

static int roce_hwp_donor_revoke(struct hfi2_dms_roce_hwp_window *window)
{
	struct hfi2_dms_roce *roce = window->pool->roce;
	struct hfi2_dms_roce_rif_entry entry;
	u32 qpn = window->owner->qp->ibqp.qp_num;
	bool entered = roce_rif_enter(roce);
	int bucket, ret, error = 0;

	for (bucket = 0; bucket < EAL_TABLE_ENTRIES_PER_ROW; bucket++) {
		ret = hfi2_dms_roce_rif_readback(roce, qpn, bucket, &entry);
		if (ret == -ENOENT)
			continue;
		if (ret) {
			error = ret;
			continue;
		}
		/* A shared QP/PASID may also own an unrelated inbound WRITE. */
		if ((entry.qpn != qpn && entry.qpn != (qpn | HFI2_ROCE_QPN_ALIAS_BIT)) ||
		    entry.pasid != window->pool->token->pasid ||
		    entry.start_vaddr < window->iova ||
		    entry.start_vaddr - window->iova >= window->pool->win_bytes)
			continue;
		ret = roce_rif_reclaim_entry_current_mutex_held(roce, &entry, bucket);
		if (ret < 0)
			error = ret;
		else if (ret)
			roce_rif_invalidate_mutex_held(roce, entry.qpn, bucket);
	}
	roce_rif_leave(roce, entered);
	return error;
}

static int roce_hwp_donor_drain(struct hfi2_dms_roce_hwp_window *window)
{
	struct hfi2_dms_roce *roce = window->pool->roce;
	struct hfi2_dms_roce_rx_mark mark;
	int ret;

#if HFI2_DMS_ROCE_INJECT
	if (READ_ONCE(roce_inject_hwp_cleanup_drain))
		return -ETIMEDOUT;
#endif
	if (!READ_ONCE(roce->active) || READ_ONCE(roce->svc->stop_scheduling))
		return -ENODEV;
	if (hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		return -ENXIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	ret = hfi2_dms_roce_wait_rx(roce, &mark);
	if (ret)
		return ret;
	ret = roce_hwp_donor_revoke(window);
	if (ret)
		return ret;
	if (hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
		return -ENXIO;
	hfi2_dms_roce_rx_mark(roce, &mark);
	return hfi2_dms_roce_wait_rx(roce, &mark);
}

static void roce_hwp_donor_run(struct hfi2_roce_kmr_async *request)
{
	struct hfi2_dms_roce_hwp_window *window =
		container_of(request, struct hfi2_dms_roce_hwp_window, request);
	struct hfi2_dms_roce_hwp_pool *pool = window->pool;
	struct hfi2_dms_roce_qp *rqp = window->owner;
	struct hfi2_dms_roce *roce = pool->roce;
	struct rvt_qp *qp = rqp->qp;
	unsigned long flags, sflags;
	bool cancelled, map;
	int ret = 0;

	spin_lock_irqsave(&pool->lock, flags);
	cancelled = window->cancelled || pool->stopping;
	map = window->state == HFI2_ROCE_HWP_MAP_PENDING;
	spin_unlock_irqrestore(&pool->lock, flags);
	if (!cancelled && map) {
#if HFI2_DMS_ROCE_INJECT
		if (READ_ONCE(roce_inject_hwp_donor) == 4)
			msleep(100);
		if (READ_ONCE(roce_inject_hwp_donor) == 1)
			ret = -EIO;
		else
#endif
			ret = hfi2_roce_kmr_map_pages(&pool->reservation, window->iova,
						      window->pages, window->nr_pages);
		window->mapped = !ret;
#if HFI2_DMS_ROCE_INJECT
		if (READ_ONCE(roce_inject_hwp_donor) == 3)
			cancelled = true;
#endif
		spin_lock_irqsave(&qp->s_lock, sflags);
		spin_lock_irqsave(&pool->lock, flags);
		cancelled |= window->cancelled || pool->stopping ||
			window->epoch != rqp->hwp_epoch ||
			rqp->read_hwp_windows[window->wqe_index] != window ||
			!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
			READ_ONCE(rqp->tx_cancelled) ||
			rvt_get_swqe_ptr(qp, window->wqe_index)->psn != window->wqe_psn ||
			!READ_ONCE(pool->token->live);
		if (!cancelled) {
			window->status = ret;
			window->state = HFI2_ROCE_HWP_READY;
			window->busy = false;
			rqp->donor_waiting = false;
			if (ret)
				atomic64_inc(&roce->stats.hwp_rd_win_donor_map_err);
			else
				atomic64_inc(&roce->stats.hwp_rd_win_donor_ready);
			complete_all(&window->idle);
			spin_unlock_irqrestore(&pool->lock, flags);
			hfi2_dms_roce_enqueue(qp);
			spin_unlock_irqrestore(&qp->s_lock, sflags);
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
		spin_unlock_irqrestore(&qp->s_lock, sflags);
		atomic64_inc(&roce->stats.hwp_rd_win_donor_cancelled);
		spin_lock_irqsave(&qp->s_lock, sflags);
		if (!pool->stopping &&
		    (ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK))
			rvt_error_qp(qp, IB_WC_LOC_PROT_ERR, RVT_QP_LOCK_STATE_S);
		spin_unlock_irqrestore(&qp->s_lock, sflags);
	}

	/* No later donor READ can arm this QP until its old alias is revoked. */
	roce_hwp_window_uninstall(roce, window);
	if (window->mapped && !hfi2_roce_pasid_fenced(pool->token)) {
		unsigned long start = jiffies;
		u64 delay_ns = (u64)HFI2_ROCE_HWP_WIN_QUARANTINE_MS * NSEC_PER_MSEC;

		/* Cancellation during mapping may precede the WQE release callback. */
		spin_lock_irqsave(&pool->lock, flags);
		if (!window->released_ns)
			window->released_ns = ktime_get_ns();
		spin_unlock_irqrestore(&pool->lock, flags);

		while (!hfi2_roce_pasid_fenced(pool->token)) {
			ret = roce_hwp_donor_drain(window);
			if (!ret)
				break;
			atomic64_inc(&roce->stats.hwp_cleanup_drain_err);
			if (roce_hwp_cleanup_expired(roce, start, ret)) {
				window->exhausted = true;
				break;
			}
			msleep(20);
		}
		if (window->exhausted)
			goto fence;
		/* Tick rounding cannot prove the minimum age of this mapping. */
		for (;;) {
			u64 elapsed;
			unsigned long remaining_us;

			spin_lock_irqsave(&pool->lock, flags);
			elapsed = ktime_get_ns() - window->released_ns;
			if (elapsed >= delay_ns) {
				window->state = HFI2_ROCE_HWP_ZAP_PENDING;
				spin_unlock_irqrestore(&pool->lock, flags);
				break;
			}
			spin_unlock_irqrestore(&pool->lock, flags);
			remaining_us = DIV_ROUND_UP_ULL(delay_ns - elapsed, NSEC_PER_USEC);
			usleep_range(remaining_us, remaining_us + 50);
		}
		ret = hfi2_roce_kmr_zap_pages(&pool->reservation, window->iova,
					      window->mapped_len);
		if (ret) {
			atomic64_inc(&roce->stats.hwp_rd_win_donor_zap_err);
			/* Retain the pages/extent rather than reuse an unrevoked alias. */
			window->exhausted = true;
		} else {
			window->mapped = false;
			atomic64_inc(&roce->stats.hwp_rd_win_donor_zapped);
		}
	}
fence:
	if (window->exhausted && !hfi2_roce_pasid_fenced(pool->token)) {
		while ((ret = roce_hwp_pool_fence(roce))) {
			atomic64_inc(&roce->fence_stats.hwp_cleanup_fence_fail);
			dd_dev_warn_ratelimited(roce->dd,
						"roce: donor fence failed (%d); holding pages\n",
						ret);
			msleep(20);
		}
		WRITE_ONCE(pool->reservation.poisoned, true);
	}
	if (hfi2_roce_pasid_fenced(pool->token)) {
		window->exhausted = true;
		roce_hwp_donor_put_pages(window);
	} else if (!window->mapped && !window->exhausted) {
		roce_hwp_donor_put_pages(window);
	} else if (window->nr_pages) {
		/* Failed revocation must not expose this VA to another allocation. */
		ret = hfi2_roce_kmr_retain_pages(&pool->reservation, window->pages,
						 window->nr_pages);
		if (!ret) {
			window->pages = NULL;
			window->nr_pages = 0;
		}
	}
	spin_lock_irqsave(&qp->s_lock, sflags);
	spin_lock_irqsave(&pool->lock, flags);
	if (rqp->read_hwp_windows[window->wqe_index] == window)
		rqp->read_hwp_windows[window->wqe_index] = NULL;
	window->owner = NULL;
	rqp->hwp_donor_holds--;
	rqp->donor_waiting = false;
	spin_unlock_irqrestore(&pool->lock, flags);
	if (!READ_ONCE(rqp->tx_cancelled))
		hfi2_dms_roce_enqueue(qp);
	spin_unlock_irqrestore(&qp->s_lock, sflags);
	rvt_put_qp(qp);
	spin_lock_irqsave(&pool->lock, flags);
	window->in_use = false;
	window->busy = false;
	window->state = window->mapped || window->exhausted ?
		HFI2_ROCE_HWP_ZAP_PENDING : HFI2_ROCE_HWP_FREE;
	complete_all(&window->idle);
	spin_unlock_irqrestore(&pool->lock, flags);
}

static bool roce_hwp_window_key_stale(struct hfi2_dms_roce *roce,
				      u32 rkey)
{
	struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
	unsigned long flags;
	u32 i;
	bool stale = false;

	spin_lock_irqsave(&pool->lock, flags);
	for (i = 0; pool->windows && i < pool->win_count; i++) {
		struct hfi2_dms_roce_hwp_window *window = &pool->windows[i];

		if (!window->in_use &&
		    window->rkey_bucket == HFI2_ROCE_MR_NO_BUCKET &&
		    window->rkey == rkey) {
			stale = true;
			break;
		}
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	return stale;
}

static void roce_hwp_window_dest(const struct hfi2_dms_roce_hwp_window *window,
				 const struct rvt_swqe *wqe, u64 *dest_va,
				 u32 *dest_rkey)
{
	if (dest_va)
		*dest_va = window->iova +
			((unsigned long)wqe->sg_list[0].mem.vaddr & ~PAGE_MASK);
	if (dest_rkey)
		*dest_rkey = window->rkey;
}

static int roce_hwp_window_rotate(struct hfi2_dms_roce_qp *rqp,
				  struct hfi2_dms_roce_hwp_window *window)
{
	struct hfi2_dms_roce_hwp_pool *pool = &rqp->roce->hwp_pool;
	int ret;

	do {
		ret = rvt_rotate_internal_mr_key(window->slot, &window->rkey,
						 RVT_INTERNAL_MR_KEY_WRAP_AFTER_DRAIN);
		if (ret) {
			rqp->roce->stats.hwp_rd_win_key_err++;
			return ret;
		}
		window->generation++;
		/* Reserved slots differ above the row bits; spread equal generations. */
		window->rkey ^= HFI2_ROCE_RKEY_INTERNAL_MARK ^
			((window - pool->windows) & (EAL_RKEY_TABLE_ROWS - 1));
		rqp->roce->stats.hwp_rd_win_rotations++;
	} while (window->rkey == HFI2_ROCE_RKEY_NO_OWNER);
	return 0;
}

static int roce_hwp_donor_reserve(struct hfi2_dms_roce_qp *rqp,
				  struct rvt_swqe *wqe,
				  struct hfi2_dms_roce_hwp_window *window,
				  unsigned int index)
	__must_hold(&rqp->roce->hwp_pool.lock)
{
	int ret;

	/* Reject unsupported pages before consuming a key generation. */
	ret = roce_hwp_donor_snapshot(rqp, wqe, window);
	if (ret)
		goto err_free;
	ret = roce_hwp_window_rotate(rqp, window);
	if (ret)
		goto err_put;
	window->owner = rqp;
	window->epoch = rqp->hwp_epoch;
	window->wqe_index = index;
	window->wqe_psn = wqe->psn;
	window->cancelled = false;
	window->released_ns = 0;
	window->status = 0;
	rqp->read_hwp_windows[index] = window;
	rvt_get_qp(rqp->qp);
	rqp->hwp_donor_holds++;
	ret = roce_hwp_donor_queue(window);
	if (ret) {
		rqp->read_hwp_windows[index] = NULL;
		rqp->hwp_donor_holds--;
		rvt_put_qp(rqp->qp);
		window->owner = NULL;
		goto err_put;
	}
	atomic64_inc(&rqp->roce->stats.hwp_rd_win_donor_queued);
	return 0;

err_put:
	roce_hwp_donor_put_pages(window);
err_free:
	window->state = HFI2_ROCE_HWP_FREE;
	window->in_use = false;
	return ret;
}

static int roce_hwp_window_get(struct hfi2_dms_roce_qp *rqp,
			       struct rvt_swqe *wqe, u64 *dest_va, u32 *dest_rkey,
			       bool count_ineligible)
{
	struct hfi2_dms_roce_hwp_pool *pool = &rqp->roce->hwp_pool;
	struct hfi2_dms_roce_hwp_window *window = NULL;
	unsigned long flags;
	unsigned int index;
	u32 i, n;
	u32 active = 0, pending = 0, exhausted = 0;
	int ret;

	if (!pool->enabled || !rqp->read_hwp_windows ||
	    !READ_ONCE(pool->token->live) || READ_ONCE(pool->token->quiesce_failed))
		return -EOPNOTSUPP;
	if (!roce_hwp_window_layout_valid(wqe)) {
		if (count_ineligible)
			rqp->roce->stats.hwp_rd_win_misaligned++;
		return -EINVAL;
	}
	if (wqe->length > pool->win_bytes ||
	    wqe->length > pool->win_bytes -
	    offset_in_page(wqe->sg_list[0].mem.vaddr)) {
		if (count_ineligible)
			rqp->roce->stats.hwp_rd_win_too_big++;
		return -E2BIG;
	}
	index = roce_wqe_index(rqp->qp, wqe);
	if (index >= rqp->qp->s_size)
		return -EINVAL;
	window = rqp->read_hwp_windows[index];
	if (window) {
		if (pool->backend == HFI2_ROCE_HWP_DONOR) {
			if (window->state == HFI2_ROCE_HWP_MAP_PENDING ||
			    window->state == HFI2_ROCE_HWP_RETIRING ||
			    window->state == HFI2_ROCE_HWP_ZAP_PENDING)
				return -EINPROGRESS;
			if (window->wqe_psn != wqe->psn ||
			    window->epoch != rqp->hwp_epoch)
				return -ESTALE;
			if (window->state == HFI2_ROCE_HWP_READY) {
				ret = window->status;
				if (!ret) {
#if HFI2_DMS_ROCE_INJECT
					if (READ_ONCE(roce_inject_hwp_donor) == 2)
						ret = -ENOSPC;
					else
#endif
						ret = roce_hwp_window_install(rqp->roce,
									      window, wqe);
					if (ret == -ENOSPC)
						rqp->roce->stats.hwp_rd_win_install_full++;
					else if (ret < 0)
						rqp->roce->stats.hwp_rd_win_install_err++;
				}
				if (ret < 0) {
					if (count_ineligible)
						rqp->roce->stats.hwp_rd_win_map_err++;
					set_bit(index, rqp->read_software_wqes);
					roce_hwp_window_release_wqe(rqp, wqe);
					return -EINPROGRESS;
				}
				window->state = HFI2_ROCE_HWP_ACTIVE;
				rqp->roce->stats.hwp_rd_win_reads++;
				rqp->roce->stats.hwp_rd_win_bytes += wqe->length;
			}
		}
		roce_hwp_window_dest(window, wqe, dest_va, dest_rkey);
		return 0;
	}

	if (pool->backend == HFI2_ROCE_HWP_DONOR) {
		/* Reject mutable registered page lists before consuming a slot generation. */
		for (i = 0; i < wqe->wr.num_sge; i++) {
			if (wqe->sg_list[i].mr && wqe->sg_list[i].mr->lkey) {
				if (count_ineligible)
					rqp->roce->stats.hwp_rd_win_donor_reg_mr++;
				return -EOPNOTSUPP;
			}
		}
		if (rqp->hwp_donor_holds || rqp->qp->s_num_rd_atomic) {
			rqp->roce->stats.hwp_rd_win_donor_serialize++;
			return -EBUSY;
		}
	}
	spin_lock_irqsave(&pool->lock, flags);
	if (pool->stopping || !pool->enabled) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return -ESHUTDOWN;
	}
	for (n = 0; n < pool->win_count; n++) {
		i = (pool->next + n) % pool->win_count;
		if (!pool->windows[i].in_use && !pool->windows[i].exhausted &&
		    !pool->windows[i].mapped &&
		    list_empty(&pool->windows[i].quarantine)) {
			window = &pool->windows[i];
			pool->next = i + 1;
			window->in_use = true;
			if (pool->backend == HFI2_ROCE_HWP_PAGING) {
				window->acquired_ns = ktime_get_ns();
				pool->acquired++;
				pool->active++;
				pool->active_high = max(pool->active_high, pool->active);
			}
			window->state = HFI2_ROCE_HWP_MAP_PENDING;
			break;
		}
		active += pool->windows[i].in_use;
		pending += !pool->windows[i].in_use && pool->windows[i].mapped;
		exhausted += pool->windows[i].exhausted;
	}
	if (window && pool->backend == HFI2_ROCE_HWP_DONOR) {
		ret = roce_hwp_donor_reserve(rqp, wqe, window, index);
		spin_unlock_irqrestore(&pool->lock, flags);
		if (!ret)
			return -EINPROGRESS;
		goto err_count;
	}
	spin_unlock_irqrestore(&pool->lock, flags);
	if (!window) {
		if (count_ineligible) {
			rqp->roce->stats.hwp_rd_win_busy++;
			if (active)
				rqp->roce->stats.hwp_rd_win_busy_active++;
			if (pending)
				rqp->roce->stats.hwp_rd_win_busy_quarantine++;
			if (exhausted)
				rqp->roce->stats.hwp_rd_win_busy_exhausted++;
		}
		ret = -EBUSY;
		goto out;
	}

	/* Map before rotating: a failed map then leaves the generation intact. */
	ret = roce_hwp_window_map_sges(rqp, wqe, window);
	if (ret)
		goto err_release;
	ret = roce_hwp_window_rotate(rqp, window);
	if (ret)
		goto err_release;
	window->state = HFI2_ROCE_HWP_READY;
	ret = roce_hwp_window_install(rqp->roce, window, wqe);
	if (ret < 0) {
		if (ret == -ENOSPC)
			rqp->roce->stats.hwp_rd_win_install_full++;
		else
			rqp->roce->stats.hwp_rd_win_install_err++;
		goto err_release;
	}
	window->state = HFI2_ROCE_HWP_ACTIVE;
	rqp->read_hwp_windows[index] = window;
	roce_hwp_window_dest(window, wqe, dest_va, dest_rkey);
	rqp->roce->stats.hwp_rd_win_reads++;
	rqp->roce->stats.hwp_rd_win_bytes += wqe->length;
	return 0;

err_release:
	roce_hwp_window_queue(pool, window);
err_count:
	if (count_ineligible)
		rqp->roce->stats.hwp_rd_win_map_err++;
out:
	return ret;
}

static bool roce_wqe_read_write_reply(const struct hfi2_dms_roce_qp *rqp,
				      const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	return rqp->read_write_wqes && index < rqp->qp->s_size &&
		test_bit(index, rqp->read_write_wqes);
}

static void roce_wqe_set_read_write_reply(struct hfi2_dms_roce_qp *rqp,
					  const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	if (index < rqp->qp->s_size)
		set_bit(index, rqp->read_write_wqes);
}

static void roce_wqe_clear_read_write_reply(struct hfi2_dms_roce_qp *rqp,
					    const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	if (index < rqp->qp->s_size) {
		roce_hwp_window_release_wqe(rqp, wqe);
		clear_bit(index, rqp->read_write_wqes);
		clear_bit(index, rqp->read_software_wqes);
		if (rqp->read_internal_keys && !rqp->hwp_cleanup_pending) {
			rqp->read_internal_keys[index] = 0;
			memset(&rqp->read_targets[index], 0,
			       sizeof(rqp->read_targets[index]));
		}
	}
}

static bool roce_wqe_read_software_reply(const struct hfi2_dms_roce_qp *rqp,
					 const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	return rqp->read_software_wqes && index < rqp->qp->s_size &&
		test_bit(index, rqp->read_software_wqes);
}

static void roce_wqe_set_read_software_reply(struct hfi2_dms_roce_qp *rqp,
					     const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	if (index < rqp->qp->s_size)
		set_bit(index, rqp->read_software_wqes);
}

static void roce_wqe_clear_read_software_reply(struct hfi2_dms_roce_qp *rqp,
					       const struct rvt_swqe *wqe)
{
	unsigned int index = roce_wqe_index(rqp->qp, wqe);

	if (index < rqp->qp->s_size)
		clear_bit(index, rqp->read_software_wqes);
}

void
hfi2_dms_roce_clear_wqe_read_write_reply(struct rvt_qp *qp,
					 const struct rvt_swqe *wqe)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;

	if (rqp && rqp->read_write_wqes &&
	    roce_wqe_index(qp, wqe) < qp->s_size) {
		roce_wqe_clear_read_write_reply(rqp, wqe);
		roce_wqe_clear_read_software_reply(rqp, wqe);
	}
}

static bool roce_qp_is_ud(const struct rvt_qp *qp)
{
	return qp->ibqp.qp_type == IB_QPT_GSI ||
	       qp->ibqp.qp_type == IB_QPT_UD;
}

/*
 * QP1 is created by ib_mad during ib_register_device(), before bulksvc loans
 * the RoCE backend.  Device teardown reverses that order: rvt_unregister_device()
 * destroys every QP before bulksvc frees the backend, so caching the published
 * backend here cannot outlive it.
 */
static struct hfi2_dms_roce *
roce_qp_backend(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_bulksvc *svc;
	struct hfi2_dms_roce *roce;

	if (!rqp)
		return NULL;
	roce = READ_ONCE(rqp->roce);
	if (roce)
		return READ_ONCE(roce->initialized) ? roce : NULL;

	svc = READ_ONCE(rqp->dd->bulksvc);
	if (!svc || READ_ONCE(svc->backend) != HFI2_BULKSVC_BACKEND_ETH_ROCE)
		return NULL;
	roce = READ_ONCE(svc->dms_roce);
	if (!roce || !READ_ONCE(roce->initialized))
		return NULL;

	WRITE_ONCE(rqp->roce, roce);
	return roce;
}

struct hfi2_dms_roce_qp *hfi2_dms_roce_qp_bind(struct rvt_qp *qp)
{
	struct hfi2_devdata *dd = dd_from_ibdev(qp->ibqp.device);
	struct hfi2_dms_roce_qp *rqp;
	struct net_device *ndev;
	u32 port = HFI2_PORT_IDX + 1;
	size_t txbuf_sz;

	ndev = ib_device_get_netdev(qp->ibqp.device, port);
	txbuf_sz = roce_qp_is_ud(qp) || hfi2_roce_mtu_8192_available(dd, ndev) ?
		HFI2_ROCE_TXBUF_8192_SZ : HFI2_ROCE_TXBUF_DEFAULT_SZ;
	if (ndev)
		dev_put(ndev);
	rqp = kzalloc_node(sizeof(*rqp), GFP_KERNEL, dd->node);
	if (!rqp)
		return NULL;

	rqp->txbuf = kzalloc_node(txbuf_sz, GFP_KERNEL, dd->node);
	if (!rqp->txbuf) {
		kfree(rqp);
		return NULL;
	}
	rqp->ackbuf = kzalloc_node(HFI2_ROCE_ACKBUF_SZ, GFP_KERNEL, dd->node);
	if (!rqp->ackbuf) {
		kfree(rqp->txbuf);
		kfree(rqp);
		return NULL;
	}
	if (!roce_qp_is_ud(qp))
		rqp->read_meta = roce_alloc_read_meta(qp, dd);
	if (!roce_qp_is_ud(qp) && !rqp->read_meta) {
		kfree(rqp->ackbuf);
		kfree(rqp->txbuf);
		kfree(rqp);
		return NULL;
	}

	/*
	 * Store the resolved device/port handles directly.  Unlike the OPA
	 * bulksvc qp_info, we do not stash qp->priv for a later downcast --
	 * a RoCE priv only aliases OPA on its @common prefix (see roce.h), so
	 * any consumer that needs ppd/rcd reads them from here.
	 */
	rqp->qp = qp;
	rqp->dd = dd;
	rqp->port_idx = HFI2_PORT_IDX;
	rqp->txbuf_sz = txbuf_sz;
	rqp->ackbuf_sz = HFI2_ROCE_ACKBUF_SZ;
	INIT_DELAYED_WORK(&rqp->hwp_cleanup_work, roce_hwp_cleanup_work);
	init_completion(&rqp->hwp_cleanup_idle);
	complete_all(&rqp->hwp_cleanup_idle);
	INIT_LIST_HEAD(&rqp->rif_node);
	init_completion(&rqp->rif_idle);
	complete_all(&rqp->rif_idle);
	init_completion(&rqp->tx_idle);
	complete_all(&rqp->tx_idle);
	init_completion(&rqp->sdma_local_zero);
	complete_all(&rqp->sdma_local_zero);
	init_completion(&rqp->sdma_cancel_done);
	complete_all(&rqp->sdma_cancel_done);
	spin_lock_init(&rqp->tx_state_lock);
	INIT_LIST_HEAD(&rqp->runq_node);
	INIT_LIST_HEAD(&rqp->read_restart_node);
	INIT_LIST_HEAD(&rqp->pio_wait_node);
	INIT_LIST_HEAD(&rqp->sdma_wait_node);
	INIT_LIST_HEAD(&rqp->sdma_cancel_node);
	rqp->h15_bucket = -1;
	rqp->lbs_bucket = -1;
	if (dd->bulksvc &&
	    dd->bulksvc->backend == HFI2_BULKSVC_BACKEND_ETH_ROCE)
		rqp->roce = dd->bulksvc->dms_roce;
	return rqp;
}

int hfi2_dms_roce_qp_init(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_devdata *dd;
	size_t source_segment_count;
	u32 n_sge;
	u32 xfer_count;
	int ret = -ENOMEM;

	if (!rqp)
		return 0;
	if (rqp->qp->ibqp.qp_type == IB_QPT_GSI)
		return 0;
	if (!roce_qp_backend(rqp))
		return -ENODEV;

	dd = rqp->dd;
	if (!roce_qp_is_ud(rqp->qp) && !rqp->read_write_wqes) {
		rqp->read_write_wqes = roce_alloc_read_write_wqes(rqp->qp, dd);
		if (!rqp->read_write_wqes)
			return -ENOMEM;
		rqp->read_software_wqes =
			roce_alloc_read_software_wqes(rqp->qp, dd);
		if (!rqp->read_software_wqes) {
			bitmap_free(rqp->read_write_wqes);
			rqp->read_write_wqes = NULL;
			return -ENOMEM;
		}
		/* qp_bind() runs before rdmavt sets s_size. */
		rqp->read_hwp_windows =
			roce_alloc_read_hwp_windows(rqp->qp, dd);
		if (!rqp->read_hwp_windows) {
			bitmap_free(rqp->read_software_wqes);
			rqp->read_software_wqes = NULL;
			bitmap_free(rqp->read_write_wqes);
			rqp->read_write_wqes = NULL;
			return -ENOMEM;
		}
	}
	if (!roce_qp_is_ud(rqp->qp) && !rqp->read_internal_keys) {
		rqp->read_internal_keys =
			kcalloc_node(rqp->qp->s_size, sizeof(*rqp->read_internal_keys),
				     GFP_KERNEL, dd->node);
		if (!rqp->read_internal_keys)
			return -ENOMEM;
	}
	if (!roce_qp_is_ud(rqp->qp) && !rqp->read_targets) {
		rqp->read_targets = kcalloc_node(rqp->qp->s_size, sizeof(*rqp->read_targets),
						 GFP_KERNEL, dd->node);
		if (!rqp->read_targets)
			return -ENOMEM;
	}
	n_sge = rqp->qp->s_max_sge;
	if (!n_sge)
		n_sge = 1;

	rqp->tx_sges = kcalloc_node(n_sge, sizeof(*rqp->tx_sges),
				    GFP_KERNEL, dd->node);
	if (!rqp->tx_sges)
		return -ENOMEM;

	rqp->tx_mrs = kcalloc_node(n_sge, sizeof(*rqp->tx_mrs),
				   GFP_KERNEL, dd->node);
	if (!rqp->tx_mrs) {
		kfree(rqp->tx_sges);
		rqp->tx_sges = NULL;
		return -ENOMEM;
	}

	/* One record per SQ WQE plus responder READ slots, never provider memory. */
	if (check_add_overflow(rqp->qp->s_size,
			       roce_read_meta_count(rqp->qp), &xfer_count) ||
	    !xfer_count) {
		kfree(rqp->tx_mrs);
		kfree(rqp->tx_sges);
		rqp->tx_mrs = NULL;
		rqp->tx_sges = NULL;
		return -EOVERFLOW;
	}
	rqp->sdma_xfers =
		kcalloc_node(xfer_count, sizeof(*rqp->sdma_xfers), GFP_KERNEL,
			     dd->node);
	if (!rqp->sdma_xfers) {
		kfree(rqp->tx_mrs);
		kfree(rqp->tx_sges);
		rqp->tx_mrs = NULL;
		rqp->tx_sges = NULL;
		return -ENOMEM;
	}
	rqp->sdma_cookies =
		kcalloc_node(HFI2_DMS_ROCE_SDMA_COOKIE_COUNT,
			     sizeof(*rqp->sdma_cookies), GFP_KERNEL, dd->node);
	if (!rqp->sdma_cookies)
		goto err_xfers;
	rqp->sdma_command_pages =
		kcalloc_node(HFI2_DMS_ROCE_SDMA_BUNDLE_PACKET_MAX,
			     sizeof(*rqp->sdma_command_pages), GFP_KERNEL,
			     dd->node);
	if (!rqp->sdma_command_pages)
		goto err_cookies;

	/*
	 * Each active transfer owns one immutable source snapshot until wire ACK
	 * and its last local callback.  Allocate both the provider objects and all
	 * segment storage while QP creation is sleepable; the send path later only
	 * acquires page-set references while holding qp->s_lock.
	 */
	rqp->sdma_sources = kcalloc_node(xfer_count,
					 sizeof(*rqp->sdma_sources),
					 GFP_KERNEL, dd->node);
	if (!rqp->sdma_sources)
		goto err_command_pages;
	if (check_mul_overflow((size_t)xfer_count, (size_t)n_sge,
			       &source_segment_count)) {
		ret = -EOVERFLOW;
		goto err_sources;
	}
	rqp->sdma_source_segments =
		kcalloc_node(source_segment_count,
			     sizeof(*rqp->sdma_source_segments), GFP_KERNEL, dd->node);
	if (!rqp->sdma_source_segments)
		goto err_sources;
	rqp->sdma_xfer_count = xfer_count;
	rqp->sdma_xfer_displaced = 0;
	rqp->tx_max_sge = n_sge;
	if (WARN_ON_ONCE(!roce_qp_backend(rqp))) {
		ret = -ENODEV;
		goto err_sources;
	}
	rqp->rcd_idx = rqp->qp->ibqp.qp_num & 1;
	rqp->rcd = rqp->roce->rcd[rqp->rcd_idx];
	if (WARN_ON_ONCE(!rqp->rcd)) {
		ret = -ENODEV;
		goto err_sources;
	}
	rqp->roce->stats.qp_rcd_bindings[rqp->rcd_idx]++;
	dd_dev_dbg(dd, "roce: QP %u bound to RCD %u (ctxt %u)\n",
		   rqp->qp->ibqp.qp_num, rqp->rcd_idx, rqp->rcd->ctxt);
	rqp->request_emitter = HFI2_DMS_ROCE_EMITTER_UNSET;
	rqp->request_engine_idx = roce_sdma_engine_pick(rqp);
	/*
	 * rdmavt only calls notify_qp_reset() on a transition INTO RESET, and
	 * a new QP is born there, so the first RESET->INIT->RTR never reaches
	 * hfi2_dms_roce_reset_qp().  Latch here too.
	 */
	rqp->resp_emitter = roce_read_resp_sdma &&
		rqp->request_engine_idx != HFI2_DMS_ROCE_SDMA_ENGINE_NONE ?
		HFI2_DMS_ROCE_EMITTER_SDMA : HFI2_DMS_ROCE_EMITTER_PIO;
	ret = roce_tomb_reuse(rqp);
	if (ret)
		goto err_sources;
	return 0;

err_sources:
	kfree(rqp->sdma_sources);
	rqp->sdma_sources = NULL;
err_command_pages:
	kfree(rqp->sdma_command_pages);
	rqp->sdma_command_pages = NULL;
err_cookies:
	kfree(rqp->sdma_cookies);
	rqp->sdma_cookies = NULL;
err_xfers:
	kfree(rqp->sdma_xfers);
	kfree(rqp->tx_mrs);
	kfree(rqp->tx_sges);
	rqp->sdma_xfers = NULL;
	rqp->tx_mrs = NULL;
	rqp->tx_sges = NULL;
	return ret;
}

void hfi2_dms_roce_qp_unbind(struct hfi2_dms_roce_qp *rqp)
{
	unsigned int i;

	if (!rqp)
		return;

	hfi2_dms_roce_cancel_qp(rqp);
	hfi2_dms_roce_quiesce_qp(rqp);
	/* Normally already done by the reset destroy goes through. */
	if (!roce_qp_is_ud(rqp->qp)) {
		roce_hwp_window_release_all(rqp);
		roce_rif_release(rqp);
	}
	roce_tomb_destroy(rqp);
	roce_sdma_engine_unpick(rqp);
	WARN_ON_ONCE(rqp->sdma_local_holds);
	if (rqp->sdma_cookies) {
		for (i = 0; i < HFI2_DMS_ROCE_SDMA_COOKIE_COUNT; i++)
			WARN_ON_ONCE(rqp->sdma_cookies[i].active ||
				     rqp->sdma_cookies[i].state ==
				     HFI2_DMS_ROCE_SDMA_COOKIE_PUBLISHED);
	}
	if (rqp->sdma_xfers) {
		for (i = 0; i < rqp->sdma_xfer_count; i++) {
			WARN_ON_ONCE(rqp->sdma_xfers[i].active);
			roce_sdma_xfer_source_destroy(&rqp->sdma_xfers[i]);
		}
	}
	if (rqp->tx_in_progress) {
		unsigned long flags;

		spin_lock_irqsave(&rqp->qp->s_lock, flags);
		if (rqp->tx_in_progress)
			roce_tx_snapshot_release(rqp);
		spin_unlock_irqrestore(&rqp->qp->s_lock, flags);
	}
	WARN_ON_ONCE(rqp->replay_pending);
	if (rqp->h15_mr) {
		rvt_put_mr(rqp->h15_mr);
		rqp->h15_mr = NULL;
		rqp->h15_token = NULL;
	}
	kfree(rqp->sdma_source_segments);
	rqp->sdma_source_segments = NULL;
	kfree(rqp->sdma_sources);
	rqp->sdma_sources = NULL;
	kfree(rqp->sdma_command_pages);
	rqp->sdma_command_pages = NULL;
	kfree(rqp->sdma_cookies);
	rqp->sdma_cookies = NULL;
	kfree(rqp->sdma_xfers);
	rqp->sdma_xfers = NULL;
	rqp->sdma_xfer_count = 0;
	kfree(rqp->tx_mrs);
	kfree(rqp->tx_sges);
	bitmap_free(rqp->read_write_wqes);
	bitmap_free(rqp->read_software_wqes);
	kfree(rqp->read_hwp_windows);
	kfree(rqp->read_internal_keys);
	kfree(rqp->read_targets);
	kfree(rqp->read_meta);
	kfree(rqp->ackbuf);
	kfree(rqp->txbuf);
	kfree(rqp);
}

void hfi2_dms_roce_reset_read_state(struct rvt_qp *qp)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;

	lockdep_assert_held(&qp->s_lock);
	if (rqp && !roce_qp_is_ud(qp)) {
		rqp->write_gap.active = false;
		roce_rif_cancel(rqp);
		if (rqp->rif_read_cleanup) {
			rqp->rif_read_cleanup = false;
			rqp->replay_pending = false;
			rqp->replay_action = HFI2_DMS_ROCE_REPLAY_NONE;
		}
		memset(&rqp->read_response, 0, sizeof(rqp->read_response));
		rqp->restart_rx_deferred = false;
		rqp->hwp_epoch++;
		rqp->donor_waiting = false;
		roce_hwp_hold_rx(rqp);
		roce_hwp_cleanup_start(rqp);
		if (rqp->h15_bucket >= 0 || rqp->rif_arm_kind)
			roce_rif_release(rqp);
		roce_hwp_window_release_all(rqp);
		roce_resp_xfer_abandon(rqp);
		rqp->read_cursor.valid = false;
		rqp->read_response.active = false;
		rqp->read_response.restart_latched = false;
		if (rqp->read_write_wqes)
			bitmap_zero(rqp->read_write_wqes, qp->s_size);
		if (rqp->read_software_wqes)
			bitmap_zero(rqp->read_software_wqes, qp->s_size);
		memset(rqp->read_meta, 0,
		       roce_read_meta_count(qp) * sizeof(*rqp->read_meta));
	}
	qp->s_flags &= ~RVT_S_RESP_PENDING;
}

/*
 * Map a path MTU in bytes to its EAL_ROCEV2_CFG.rocev2_mtu encoding.
 *
 * This is deliberately a switch and not arithmetic on the IB/OPA path-MTU
 * enum.  The two ladders look interchangeable and are not: the verbs ladder
 * starts at 256 (IB_MTU_256 = 1) and this one starts at 128, so they run one
 * apart across the whole overlapping range and both have a "6" - the verbs 6
 * means 8192 while this 6 means 4096.  A +1 conversion also silently truncates
 * OPA_MTU_10240 + 1 = 8 to 0 in a three-bit field, which reads back as 4096.
 *
 * 4096 maps to encoding 6 and never to encoding 0, even though the HAS lists
 * both as 4096: encoding 0 is documented as "target defaults to zeros" and is
 * the reset value, so programming it would be indistinguishable from never
 * having programmed the register at all.
 *
 * Returns a negative value for a path MTU hardware cannot express as a stride.
 */
static int roce_rocev2_mtu_encoding(u32 pmtu)
{
	switch (pmtu) {
	case 128:
		return EAL_ROCEV2_MTU_128;
	case 256:
		return EAL_ROCEV2_MTU_256;
	case 512:
		return EAL_ROCEV2_MTU_512;
	case 1024:
		return EAL_ROCEV2_MTU_1024;
	case 2048:
		return EAL_ROCEV2_MTU_2048;
	case 4096:
		return EAL_ROCEV2_MTU_4096;
	case 8192:
		return EAL_ROCEV2_MTU_8192;
	default:
		return -EINVAL;
	}
}

/*
 * Drive rocev2_mtu to zero and say so if it was not already.
 *
 * Called at init and at teardown.  At init it stops the driver inheriting the
 * previous module's stride; at teardown it stops the next module inheriting
 * this one's.  Either alone would leave one direction open, and CSR state
 * outliving rmmod is the defect class this project has now hit four times.
 *
 * Zero is not a valid encoding, and that is deliberate: it makes the
 * unclaimed state distinguishable from a claimed 4096 or 8192 rather than
 * indistinguishable from a stale one.
 */
static void roce_stride_reset_csr(struct hfi2_dms_roce *roce)
{
	unsigned long flags;
	u64 reg;
	u8 was;

	if (!roce || !roce->dd || !(roce->dd->flags & HFI2_PRESENT))
		return;

	spin_lock_irqsave(&roce->stride_lock, flags);
	reg = hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
	was = EAL_ROCEV2_CFG_GET_ROCEV2_MTU(reg);
	if (was) {
		EAL_ROCEV2_CFG_SET_ROCEV2_MTU(reg, 0);
		hfi2_write_csr(roce->dd, CYR_EAL_ROCEV2_CFG, reg);
		reg = hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
	}
	spin_unlock_irqrestore(&roce->stride_lock, flags);

	if (was)
		dd_dev_info(roce->dd,
			    "roce: rocev2_mtu carried encoding %u across a module boundary; cleared to %llu\n",
			    was, EAL_ROCEV2_CFG_GET_ROCEV2_MTU(reg));
}

/*
 * Latch the device placement stride from roce_vrma_mtu.  8 KiB needs the
 * send context and receive buffers sized for it; without them fall back to
 * 4 KiB rather than fail the backend.
 */
static void roce_stride_program(struct hfi2_dms_roce *roce)
{
	unsigned long flags;
	u32 mtu = roce_vrma_mtu;
	int encoding;
	u64 reg;

	if (mtu == 8192 && !READ_ONCE(roce->mtu_8192_capable)) {
		dd_dev_warn(roce->dd,
			    "roce: roce_vrma_mtu=8192 needs 8 KiB send and receive buffers; using 4096\n");
		mtu = 4096;
	}
	encoding = roce_rocev2_mtu_encoding(mtu);
	if (encoding < 0)
		return;

	spin_lock_irqsave(&roce->stride_lock, flags);
	reg = hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
	EAL_ROCEV2_CFG_SET_ROCEV2_MTU(reg, encoding);
	hfi2_write_csr(roce->dd, CYR_EAL_ROCEV2_CFG, reg);
	reg = hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG);
	if (EAL_ROCEV2_CFG_GET_ROCEV2_MTU(reg) == encoding)
		roce->stride_bytes = mtu;
	spin_unlock_irqrestore(&roce->stride_lock, flags);

	if (roce->stride_bytes)
		dd_dev_info(roce->dd, "roce: hardware placement path MTU %u\n",
			    mtu);
	else
		dd_dev_err(roce->dd,
			   "roce: rocev2_mtu read back %llu, expected %d; no RoCE QP will be hardware-placed\n",
			   EAL_ROCEV2_CFG_GET_ROCEV2_MTU(reg), encoding);
}

/**
 * hfi2_dms_roce_stride_conflict - would @pmtu disagree with the latched stride?
 * @qp: QP whose path MTU is being validated
 * @pmtu: the QP's requested path MTU in bytes
 *
 * Read-only companion to hfi2_dms_roce_claim_stride(), for callers that must
 * decide before the transition commits.  Reports only the disagreement case:
 * an unprogrammed stride, an absent or uninitialised backend, and an MTU with
 * no rocev2_mtu encoding are all "no conflict" here, because each is either
 * claimable or already declined by claim_stride() on its own terms.
 *
 * @pmtu is signed because its callers decode an enum that has no byte value
 * for every input: a negative result means "not a size this driver can name",
 * which is claim_stride()'s decision to make, not a conflict.
 *
 * Returns true only when a stride is latched and @pmtu differs from it.
 */
bool hfi2_dms_roce_stride_conflict(struct rvt_qp *qp, int pmtu)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	struct hfi2_dms_roce *roce;
	unsigned long flags;
	u32 stride;

	if (!rqp || !rqp->roce)
		return false;
	if (pmtu <= 0)
		return false;
	/* With software placement no stride is latched, so any MTU is fine. */
	if (hfi2_bulksvc_roce_by_software(rqp->dd))
		return false;
	roce = rqp->roce;
	if (!roce->initialized)
		return false;

	spin_lock_irqsave(&roce->stride_lock, flags);
	stride = roce->stride_bytes;
	spin_unlock_irqrestore(&roce->stride_lock, flags);

	return stride && stride != (u32)pmtu;
}

/**
 * hfi2_dms_roce_claim_stride - check a QP against the device placement stride
 * @qp: QP whose path MTU is now final
 * @pmtu: the QP's path MTU in bytes
 *
 * EAL_ROCEV2_CFG.rocev2_mtu is the stride hardware uses to place a MIDDLE at
 * start_vaddr + stride * (BTH.PSN - start_psn).  The RIF entry carries no MTU
 * field, so this register is hardware's only source for it, and it is per-VF
 * while path_mtu is per-QP.
 *
 * Backend init programs it from roce_vrma_mtu, so it no longer depends on
 * which QP reaches RTR first.  A QP that disagrees is declined for
 * acceleration and counted rather than accommodated: a wrong stride does not
 * fail, it places correct bytes at an incorrect address at line rate.
 *
 * Returns true if @qp may be hardware-accelerated at this MTU.
 */
bool hfi2_dms_roce_claim_stride(struct rvt_qp *qp, u32 pmtu)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	struct hfi2_dms_roce *roce;
	unsigned long flags;
	u32 stride;

	if (!rqp || !rqp->roce)
		return false;
	roce = rqp->roce;
	if (!roce->initialized)
		return false;
	/* Nothing is hardware-placed: no stride to program, no QP to decline. */
	if (hfi2_bulksvc_roce_by_software(rqp->dd))
		return false;

	spin_lock_irqsave(&roce->stride_lock, flags);
	stride = roce->stride_bytes;
	spin_unlock_irqrestore(&roce->stride_lock, flags);

	if (stride && stride == pmtu)
		return true;

	if (!stride) {
		roce->stats.stride_unsupported++;
		return false;
	}
	roce->stats.stride_mismatch++;
	dd_dev_warn_ratelimited(roce->dd,
				"roce: QP %u path MTU %u differs from roce_vrma_mtu %u; QP runs in software\n",
				qp->ibqp.qp_num, pmtu, stride);
	return false;
}

/*
 * Encode a RIF entry into the three WDATA registers.
 *
 * Split out from the write so the field placement can be exercised without a
 * device.  Everything here is transcription from A00502-0.6.1 D.2.3-D.2.5;
 * the arithmetic that produces @entry is the caller's and is the part that
 * can be silently wrong.
 *
 * rif_next_psn is the only split field in either table - bits [23:8] in
 * WDATA1 and [7:0] in WDATA2, both halves carrying the same name - so it is
 * built through the EAL_RIF_NEXT_PSN_{HI,LO} helpers rather than by hand.
 */
static void roce_rif_encode(const struct hfi2_dms_roce_rif_entry *entry,
			    u64 wdata[3])
{
	wdata[0] = FIELD_PREP(EAL_RIF_WDATA0_START_VIRTUAL_ADDRESS_MASK,
			      entry->start_vaddr);

	wdata[1] = FIELD_PREP(EAL_RIF_WDATA1_END_PSN_MASK, entry->end_psn) |
		   FIELD_PREP(EAL_RIF_WDATA1_START_PSN_MASK, entry->start_psn) |
		   FIELD_PREP(EAL_RIF_WDATA1_NEXT_PSN_HI_MASK,
			      EAL_RIF_NEXT_PSN_HI(entry->next_psn));

	wdata[2] = FIELD_PREP(EAL_RIF_WDATA2_NEXT_PSN_LO_MASK,
			      EAL_RIF_NEXT_PSN_LO(entry->next_psn)) |
		   FIELD_PREP(EAL_RIF_WDATA2_NEXT_PSN_STATE_MASK,
			      entry->next_psn_state) |
		   FIELD_PREP(EAL_RIF_WDATA2_PASID_MASK, entry->pasid) |
		   FIELD_PREP(EAL_RIF_WDATA2_BUCKET_NUMB_MASK, entry->bucket) |
		   FIELD_PREP(EAL_RIF_WDATA2_QP_MASK, entry->qpn) |
		   FIELD_PREP(EAL_RIF_WDATA2_ENTRY_VALID_MASK, 1);
}

/*
 * Nested helpers share the current task's transaction; only its outermost
 * enter/leave pair acquires and releases the sleepable CSR mutex.
 */
static bool roce_rif_enter(struct hfi2_dms_roce *roce)
{
	might_sleep();
	if (READ_ONCE(roce->rif_task) == current)
		return false;
	mutex_lock(&roce->rif_mutex);
	WRITE_ONCE(roce->rif_task, current);
	return true;
}

static void roce_rif_leave(struct hfi2_dms_roce *roce, bool entered)
{
	if (!entered)
		return;
	WRITE_ONCE(roce->rif_task, NULL);
	mutex_unlock(&roce->rif_mutex);
}

/*
 * Write every staging register, WDATA2 last to commit.  Registers retain old
 * values, so partial writes can reuse stale fields.  The uncached kregbase1
 * mapping preserves store order without a barrier, unlike WC PIO egress.
 */
static void roce_rif_write(struct hfi2_dms_roce *roce, const u64 wdata[3])
{
	lockdep_assert_held(&roce->rif_mutex);
	WARN_ON_ONCE(irqs_disabled());

	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RIF_TABLE + EAL_TABLE_WDATA0, wdata[0]);
	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RIF_TABLE + EAL_TABLE_WDATA1, wdata[1]);
	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RIF_TABLE + EAL_TABLE_WDATA2, wdata[2]);
}

/*
 * Fetch one RIF entry through the config-bus staging latch.
 *
 * Reading q0 fetches the selected entry into the staging latch; q1/q2 read
 * that latch.  rif_mutex serializes complete q0/q1/q2 and WDATA sequences.
 * No spinlock or RCU read-side section may span these config-bus reads.
 */
static void roce_rif_read_entry(struct hfi2_dms_roce *roce, u32 row, u8 bucket,
				u64 q[3])
{
	lockdep_assert_held(&roce->rif_mutex);
	WARN_ON_ONCE(irqs_disabled());

	q[0] = hfi2_read_csr(roce->dd, EAL_RIF_READ_ADDR(row, bucket, 0));
	q[1] = hfi2_read_csr(roce->dd, EAL_RIF_READ_ADDR(row, bucket, 1));
	q[2] = hfi2_read_csr(roce->dd, EAL_RIF_READ_ADDR(row, bucket, 2));
}

static bool roce_rif_arm_scan_end(struct hfi2_dms_roce *roce,
				  u64 scan_start_ns)
{
	if (ktime_get_ns() - scan_start_ns <= HFI2_DMS_ROCE_RIF_ARM_SCAN_SLOW_NS)
		return false;
	roce->stats.rif_arm_scan_wall_slow++;
	if (!irqs_disabled())
		return false;
	roce->stats.rif_arm_scan_slow++;
	return true;
}

static void roce_rif_arm_scan_warn(struct hfi2_dms_roce *roce)
{
	dd_dev_warn_ratelimited(roce->dd,
				"roce: RIF arm scan held IRQs off for too long\n");
}

/*
 * Allocate before either table writer publishes an entry, not on the first
 * report: a report can already have been lost by then.  Both tables have
 * atomic callers, so allocation uses GFP_ATOMIC.  RX only updates existing
 * records; late reports cannot allocate after teardown erased one.
 * rows_lock protects record lifetime and bitmap updates against MR teardown.
 */
struct roce_rif_rows {
	DECLARE_BITMAP(rows, EAL_RIF_TABLE_ROWS);
	u64 loss_gen;
	bool retiring;
};

enum roce_rif_pasid_loss_reason {
	ROCE_RIF_LOSS_RHE,
	ROCE_RIF_LOSS_OVFL,
	ROCE_RIF_LOSS_BYPASS,
	ROCE_RIF_LOSS_NETDEV,
	ROCE_RIF_LOSS_REPORT,
};

static void roce_rif_pasid_note_loss(struct hfi2_dms_roce *roce,
				     enum roce_rif_pasid_loss_reason reason)
{
	unsigned long flags;

	spin_lock_irqsave(&roce->rows_lock, flags);
	roce->rif_pasid_loss_gen++;
	switch (reason) {
	case ROCE_RIF_LOSS_RHE:
		roce->stats.rif_pasid_loss_rhe++;
		break;
	case ROCE_RIF_LOSS_OVFL:
		roce->stats.rif_pasid_loss_ovfl++;
		break;
	case ROCE_RIF_LOSS_BYPASS:
		roce->stats.rif_pasid_loss_bypass++;
		break;
	case ROCE_RIF_LOSS_NETDEV:
		roce->stats.rif_pasid_loss_netdev++;
		break;
	case ROCE_RIF_LOSS_REPORT:
		roce->stats.rif_pasid_loss_report++;
		break;
	}
	spin_unlock_irqrestore(&roce->rows_lock, flags);
}

static void roce_rif_pasid_check_overflow(struct hfi2_dms_roce *roce)
{
	u8 i;
	bool entered = roce_rif_enter(roce);

	/* Serialize samples without making RX wait behind config-bus reads. */
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
		struct hfi2_ctxtdata *rcd = roce->rcd[i];
		u64 overflow = ~0ULL;

		/* Missing contexts/all-ones reads cannot prove reports were kept. */
		if (rcd)
			overflow = read_kctxt_csr(roce->dd, rcd->ctxt,
						  roce->dd->params->rcv_hdr_ovfl_cnt_reg);
		if (overflow == ~0ULL ||
		    overflow != roce->rif_pasid_hdr_overflow[i]) {
			roce->rif_pasid_hdr_overflow[i] = overflow;
			roce_rif_pasid_note_loss(roce, ROCE_RIF_LOSS_OVFL);
		}
	}
	roce_rif_leave(roce, entered);
}

static void roce_rif_pasid_track_report(struct hfi2_dms_roce *roce, u32 pasid,
					u32 row)
{
	struct roce_rif_rows *tracked;
	unsigned long flags;

	if (!pasid)
		return;
	if (likely(roce->rx_row_pasid == pasid && roce->rx_row == row &&
		   roce->rx_row_gen == READ_ONCE(roce->rif_pasid_rows_gen)))
		return;
	spin_lock_irqsave(&roce->rows_lock, flags);
	tracked = xa_load(&roce->rif_pasid_rows, pasid);
	if (tracked) {
		__set_bit(row, tracked->rows);
		roce->rx_row_pasid = pasid;
		roce->rx_row = row;
		roce->rx_row_gen = roce->rif_pasid_rows_gen;
	}
	spin_unlock_irqrestore(&roce->rows_lock, flags);
}

static struct roce_rif_rows *
roce_rif_pasid_take(struct hfi2_dms_roce *roce, u32 pasid)
{
	struct roce_rif_rows *tracked;
	unsigned long flags;

	spin_lock_irqsave(&roce->rows_lock, flags);
	tracked = xa_erase(&roce->rif_pasid_rows, pasid);
	WRITE_ONCE(roce->rif_pasid_rows_gen, roce->rif_pasid_rows_gen + 1);
	spin_unlock_irqrestore(&roce->rows_lock, flags);
	return tracked;
}

static struct roce_rif_rows *
roce_rif_pasid_get_locked(struct hfi2_dms_roce *roce, u32 pasid)
{
	struct roce_rif_rows *tracked;
	int ret;

	lockdep_assert_held(&roce->rows_lock);
	tracked = xa_load(&roce->rif_pasid_rows, pasid);
	if (tracked)
		return tracked;
	tracked = kzalloc(sizeof(*tracked), GFP_ATOMIC);
	if (!tracked)
		goto enomem;
	tracked->loss_gen = roce->rif_pasid_loss_gen;
	ret = xa_err(xa_store(&roce->rif_pasid_rows, pasid, tracked, GFP_ATOMIC));
	if (!ret)
		return tracked;
	kfree(tracked);
enomem:
	/* Installers refuse publication, so no record means no lost evidence. */
	atomic64_inc(&roce->stats.rif_pasid_track_enomem);
	return NULL;
}

void hfi2_dms_roce_rif_pasid_activate(struct hfi2_dms_roce *roce, u32 pasid)
{
	unsigned long flags;

	if (!roce || !roce->initialized || !pasid ||
	    pasid > FIELD_MAX(EAL_RIF_WDATA2_PASID_MASK))
		return;
	/* Private maps reserve even empty records before their first REG_MR. */
	spin_lock_irqsave(&roce->rows_lock, flags);
	roce_rif_pasid_get_locked(roce, pasid);
	spin_unlock_irqrestore(&roce->rows_lock, flags);
}

/**
 * hfi2_dms_roce_rif_pasid_deactivate - close and drain software arm admission
 * @roce: per-device RoCE backend
 * @pasid: address space being retired
 *
 * Context: sleepable, with no QP or table spinlock held. Waits for copied
 * arms and the CSR transaction owner before the caller sweeps RIF rows.
 */
void hfi2_dms_roce_rif_pasid_deactivate(struct hfi2_dms_roce *roce, u32 pasid)
{
	struct roce_rif_rows *tracked;
	unsigned long flags;

	if (!roce || !roce->initialized)
		return;
	might_sleep();
	/* Close admission before waiting; never wait under the table locks. */
	spin_lock_irqsave(&roce->rkey_lock, flags);
	spin_lock(&roce->rif_lock);
	spin_lock(&roce->rows_lock);
	tracked = xa_load(&roce->rif_pasid_rows, pasid);
	if (tracked)
		tracked->retiring = true;
	spin_unlock(&roce->rows_lock);
	spin_unlock(&roce->rif_lock);
	spin_unlock_irqrestore(&roce->rkey_lock, flags);
	for (;;) {
		struct hfi2_dms_roce_qp *rqp, *pending = NULL;

		spin_lock_irqsave(&roce->rif_lock, flags);
		list_for_each_entry(rqp, &roce->rif_pending, rif_node) {
			if (rqp->rif_arm_kind && rqp->rif_entry.pasid == pasid) {
				WRITE_ONCE(rqp->rif_stage_error, -ESTALE);
				pending = rqp;
				rvt_get_qp(rqp->qp);
				break;
			}
		}
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		if (!pending)
			break;
		roce_rif_wait(pending);
		rvt_put_qp(pending->qp);
	}
	{
		bool entered = roce_rif_enter(roce);

		roce_rif_flush_invalidations(roce);
		roce_rif_leave(roce, entered);
	}
}

static void roce_rif_pasid_rows_destroy(struct hfi2_dms_roce *roce)
{
	struct roce_rif_rows *tracked;
	unsigned long index;

	/* Backend shutdown has stopped RX and all MR/table writers. */
	if (roce->tombs) {
		xa_destroy(&roce->tombs->qps);
		if (roce->tombs->pasid.live)
			iommu_free_global_pasid(roce->tombs->pasid.pasid);
		kfree(roce->tombs);
		roce->tombs = NULL;
	}
	xa_for_each(&roce->rif_pasid_rows, index, tracked)
		kfree(tracked);
	xa_destroy(&roce->rif_pasid_rows);
}

/*
 * Hold rif_mutex with IRQs enabled, not a spinlock. The live token
 * must match entry->pasid; return a bucket or a negative error.
 */
static int roce_rif_arm(struct hfi2_dms_roce *roce,
			const struct hfi2_dms_roce_rif_entry *entry,
			const struct hfi2_roce_pasid *pasid)
{
	struct hfi2_dms_roce_rif_entry armed;
	struct roce_rif_rows *tracked;
	int free_bucket = -1;
	unsigned long flags;
	u64 wdata[3];
	u32 *pasid_row;
	u32 *owner;
	u32 row;
	u32 owners[EAL_TABLE_ENTRIES_PER_ROW];
	u64 scan_start_ns = 0;
	bool scan_slow = false;
	int i;

	if (!roce || !roce->initialized || !roce->rif_owner || !roce->rif_pasid)
		return -ENODEV;

	/*
	 * A NULL binding is a caller defect, not an ineligible MR: the
	 * eligibility test belongs upstream, and reaching here without one
	 * means something decided to arm an entry it could not vouch for.
	 */
	if (!pasid) {
		roce->stats.rif_arm_reject++;
		return -EINVAL;
	}

	/*
	 * Validate before touching hardware.  Every field below is masked into
	 * its register by FIELD_PREP, which truncates silently, so an
	 * out-of-range value would install a valid entry describing the wrong
	 * memory rather than failing.
	 *
	 * RUNNING is accepted alongside IDLE and INITIALIZING because it is
	 * what the hardware FIRST path itself writes (4.5.2.5.13.2), and it is
	 * the safer of the two armed states: RUNNING admits only a packet whose
	 * PSN equals next_psn, where INITIALIZING latches unconditionally on
	 * whatever arrives first and lets a stray packet adopt the burst.
	 * RECOVERING stays rejected - software has no reason to create an entry
	 * already in its error state.
	 */
	if ((entry->next_psn_state != EAL_RIF_NEXT_PSN_STATE_INITIALIZING &&
	     entry->next_psn_state != EAL_RIF_NEXT_PSN_STATE_IDLE &&
	     entry->next_psn_state != EAL_RIF_NEXT_PSN_STATE_RUNNING) ||
	    entry->qpn > FIELD_MAX(EAL_RIF_WDATA2_QP_MASK) ||
	    entry->qpn == HFI2_ROCE_RIF_NO_OWNER ||
	    !entry->pasid || entry->pasid > FIELD_MAX(EAL_RIF_WDATA2_PASID_MASK) ||
	    entry->start_psn > HFI2_ROCE_PSN_MASK ||
	    entry->end_psn > HFI2_ROCE_PSN_MASK ||
	    entry->next_psn > HFI2_ROCE_PSN_MASK) {
		roce->stats.rif_arm_reject++;
		return -EINVAL;
	}

	row = EAL_RIF_ROW_FROM_QP(entry->qpn);
	owner = &roce->rif_owner[row * EAL_TABLE_ENTRIES_PER_ROW];
	pasid_row = &roce->rif_pasid[row * EAL_TABLE_ENTRIES_PER_ROW];

retry:
	free_bucket = -1;
	spin_lock_irqsave(&roce->rif_lock, flags);
	/*
	 * Reserve the tracked row before CSR traffic.  Retirement closes admission
	 * under these metadata locks, then waits for rif_mutex without spinlocks.
	 * A transaction already admitted must finish (or compensate its commit)
	 * before that wait ends, so the subsequent sweep cannot miss its entry.
	 */
	spin_lock(&roce->rows_lock);
	tracked = xa_load(&roce->rif_pasid_rows, entry->pasid);
	if (!READ_ONCE(pasid->live) || READ_ONCE(pasid->quiesce_failed) ||
	    xa_load(&roce->dd->roce_pasid_blocked, entry->pasid) ||
	    (tracked && tracked->retiring) ||
	    (!tracked && entry->next_psn_state == EAL_RIF_NEXT_PSN_STATE_IDLE)) {
		roce->stats.rif_arm_dead_mm++;
		spin_unlock(&roce->rows_lock);
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		return -ESTALE;
	}

	if (entry->pasid != pasid->pasid) {
		roce->stats.rif_arm_pasid_mismatch++;
		spin_unlock(&roce->rows_lock);
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		return -EINVAL;
	}
	if (!tracked)
		tracked = roce_rif_pasid_get_locked(roce, entry->pasid);
	if (!tracked) {
		spin_unlock(&roce->rows_lock);
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		return -ENOMEM;
	}
	__set_bit(row, tracked->rows);
	spin_unlock(&roce->rows_lock);

	/*
	 * The match key is {VF, QP}, not bucket. A second entry is ambiguous
	 * and could place a burst into another transfer's destination.
	 */
	for (i = 0; i < EAL_TABLE_ENTRIES_PER_ROW; i++) {
		if (owner[i] == entry->qpn) {
			roce->stats.rif_arm_exclusive++;
			spin_unlock_irqrestore(&roce->rif_lock, flags);
			return -EBUSY;
		}
		if (free_bucket < 0 && owner[i] == HFI2_ROCE_RIF_NO_OWNER)
			free_bucket = i;
	}
	memcpy(owners, owner, sizeof(owners));
	spin_unlock_irqrestore(&roce->rif_lock, flags);

	/*
	 * rif_owner tracks only software arms.  Fetch every map-free bucket to
	 * reject an existing hardware entry for this QPN.  Choose the highest
	 * free bucket because hardware allocates upward.  rif_mutex excludes
	 * software writers, not hardware allocation between scan and commit;
	 * no CSR closes that race.  Keep IRQs enabled across config reads.
	 */
	free_bucket = -1;
	WARN_ON_ONCE(irqs_disabled());
	scan_start_ns = ktime_get_ns();
	for (i = EAL_TABLE_ENTRIES_PER_ROW - 1; i >= 0; i--) {
		u64 q[3];
		u64 q2;

		if (owners[i] != HFI2_ROCE_RIF_NO_OWNER)
			continue;
		roce_rif_read_entry(roce, row, i, q);
		roce->stats.rif_arm_hw_scan_reads += ARRAY_SIZE(q);
		q2 = q[2];
		if (q[0] == ~0ULL || q[1] == ~0ULL || q2 == ~0ULL) {
			scan_slow = roce_rif_arm_scan_end(roce, scan_start_ns);
			roce->stats.rif_arm_read_err++;
			if (scan_slow)
				roce_rif_arm_scan_warn(roce);
			return -EIO;
		}
		if (FIELD_GET(EAL_RIF_WDATA2_ENTRY_VALID_MASK, q2)) {
			if (FIELD_GET(EAL_RIF_WDATA2_QP_MASK, q2) ==
			    entry->qpn) {
				scan_slow = roce_rif_arm_scan_end(roce, scan_start_ns);
				roce->stats.rif_arm_exclusive++;
				if (scan_slow)
					roce_rif_arm_scan_warn(roce);
				return -EBUSY;
			}
			roce->stats.rif_arm_hw_busy++;
			continue;
		}
		if (free_bucket < 0)
			free_bucket = i;
	}
	scan_slow = roce_rif_arm_scan_end(roce, scan_start_ns);

	/* Hardware performs no free-bucket search for a software arm. */
	if (free_bucket < 0) {
		i = roce_tomb_evict(roce, row);
		if (!i)
			goto retry;
		if (i != -ENOSPC)
			return i;
		roce->stats.rif_row_full++;
		if (scan_slow)
			roce_rif_arm_scan_warn(roce);
		return -ENOSPC;
	}

	armed = *entry;
	armed.bucket = (u8)free_bucket;
	roce_rif_encode(&armed, wdata);
	roce_rif_write(roce, wdata);
	/* Track the committed arm until WRITE cleanup can retire it. */
	spin_lock_irqsave(&roce->rif_lock, flags);
	owner[free_bucket] = entry->qpn;
	pasid_row[free_bucket] = entry->pasid;
	roce->stats.rif_arm++;
	spin_unlock_irqrestore(&roce->rif_lock, flags);
	if (scan_slow)
		roce_rif_arm_scan_warn(roce);

	return free_bucket;
}

/*
 * Sleepable; hold no QP/table spinlock or RCU read lock. Atomic callers
 * defer to the worker and retain the PASID token. Returns bucket or errno.
 */
int hfi2_dms_roce_rif_arm(struct hfi2_dms_roce *roce,
			  const struct hfi2_dms_roce_rif_entry *entry,
			  const struct hfi2_roce_pasid *pasid)
{
	bool entered;
	int ret;

	if (!roce)
		return -ENODEV;
	if (WARN_ON_ONCE(irqs_disabled()))
		return -EWOULDBLOCK;
	entered = roce_rif_enter(roce);
	roce_rif_flush_invalidations(roce);
	ret = roce_rif_arm(roce, entry, pasid);
	roce_rif_leave(roce, entered);
	return ret;
}

bool hfi2_dms_roce_hwp_mode(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc = dd ? dd->bulksvc : NULL;
	struct hfi2_dms_roce *roce = svc ? READ_ONCE(svc->dms_roce) : NULL;

	return roce && READ_ONCE(roce->initialized) &&
		READ_ONCE(roce->hwp_mode);
}

static void roce_rif_invalidate_mutex_held(struct hfi2_dms_roce *roce, u32 qpn,
					   u8 bucket)
{
	u64 wdata[3];
	u32 *pasid_row;
	u32 *owner;
	unsigned long flags;

	lockdep_assert_held(&roce->rif_mutex);
	lockdep_assert_not_held(&roce->rif_lock);
	wdata[0] = 0;
	wdata[1] = 0;
	wdata[2] = FIELD_PREP(EAL_RIF_WDATA2_BUCKET_NUMB_MASK, bucket) |
		   FIELD_PREP(EAL_RIF_WDATA2_QP_MASK, qpn);
	owner = &roce->rif_owner[EAL_RIF_ROW_FROM_QP(qpn) *
				 EAL_TABLE_ENTRIES_PER_ROW];
	pasid_row = &roce->rif_pasid[EAL_RIF_ROW_FROM_QP(qpn) *
				     EAL_TABLE_ENTRIES_PER_ROW];
	roce_rif_write(roce, wdata);
	/*
	 * Release the slot only when this QP is the recorded owner.  A direct
	 * invalidation, reclaim, or teardown racing another QP's arm would
	 * otherwise hand away that QP's live bucket.
	 */
	spin_lock_irqsave(&roce->rif_lock, flags);
	if (owner[bucket] == qpn) {
		owner[bucket] = HFI2_ROCE_RIF_NO_OWNER;
		pasid_row[bucket] = 0;
	}
	spin_unlock_irqrestore(&roce->rif_lock, flags);
	roce->stats.rif_invalidate++;
}

/*
 * Clear all entry fields to prevent stale staging data from being reused.
 * Sleepable callers hold no QP/table locks.  IRQ-disabled callers defer a
 * software-owned slot; recheck ownership before executing the invalidation.
 * Return 0 when invalidated or deferred, or a negative error.
 */
int hfi2_dms_roce_rif_invalidate(struct hfi2_dms_roce *roce, u32 qpn, u8 bucket)
{
	unsigned long flags;
	bool entered;
	u32 slot;

	if (!roce || !roce->initialized || !roce->rif_owner || !roce->rif_pasid)
		return -ENODEV;
	if (qpn > FIELD_MAX(EAL_RIF_WDATA2_QP_MASK) ||
	    bucket >= EAL_TABLE_ENTRIES_PER_ROW) {
		roce->stats.rif_invalidate_reject++;
		return -EINVAL;
	}

	if (irqs_disabled()) {
		slot = EAL_RIF_ROW_FROM_QP(qpn) * EAL_TABLE_ENTRIES_PER_ROW + bucket;
		spin_lock_irqsave(&roce->rif_lock, flags);
		if (roce->rif_owner[slot] == qpn) {
			roce->rif_invalidations[slot] = qpn;
			if (!__test_and_set_bit(slot, roce->rif_dirty))
				WRITE_ONCE(roce->rif_dirty_count, roce->rif_dirty_count + 1);
		}
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		hfi2_bulksvc_schedule(roce->svc);
		return 0;
	}
	entered = roce_rif_enter(roce);
	roce_rif_invalidate_mutex_held(roce, qpn, bucket);
	roce_rif_leave(roce, entered);
	return 0;
}

/*
 * Drop @qpn's claim on @bucket in the residency map without touching the
 * table: hardware has already reused the bucket for another QP, whose entry
 * an invalidate would remove.
 */
static void roce_rif_forget(struct hfi2_dms_roce *roce, u32 qpn, u8 bucket)
{
	unsigned long flags;
	u32 row = EAL_RIF_ROW_FROM_QP(qpn) * EAL_TABLE_ENTRIES_PER_ROW;

	spin_lock_irqsave(&roce->rif_lock, flags);
	if (roce->rif_owner[row + bucket] == qpn) {
		roce->rif_owner[row + bucket] = HFI2_ROCE_RIF_NO_OWNER;
		roce->rif_pasid[row + bucket] = 0;
	}
	spin_unlock_irqrestore(&roce->rif_lock, flags);
}

static bool roce_tomb_matches(struct hfi2_dms_roce *roce, int slot,
			      const struct hfi2_dms_roce_rif_entry *entry)
{
	return entry->qpn == roce->tombs->tombstones[slot].qpn &&
		entry->pasid == roce->tombs->pasid.pasid && !entry->start_vaddr &&
		entry->start_psn == roce->tombs->tombstones[slot].psn &&
		entry->end_psn == roce->tombs->tombstones[slot].psn;
}

static int roce_tomb_remove(struct hfi2_dms_roce *roce, int slot)
{
	struct hfi2_dms_roce_rif_entry entry;
	u32 qpn = roce->tombs->tombstones[slot].qpn;
	u32 row = EAL_RIF_ROW_FROM_QP(qpn);
	u8 bucket = roce->tombs->tombstones[slot].bucket;
	unsigned long flags;
	int i, ret;

	lockdep_assert_held(&roce->rif_mutex);
	ret = hfi2_dms_roce_rif_readback(roce, qpn, bucket, &entry);
	if (ret && ret != -ENOENT)
		return ret;
	if (!ret && roce_tomb_matches(roce, slot, &entry)) {
		roce_rif_invalidate_mutex_held(roce, qpn, bucket);
		ret = hfi2_dms_roce_rif_readback(roce, qpn, bucket, &entry);
		if (ret != -ENOENT && (ret || roce_tomb_matches(roce, slot, &entry)))
			return ret ? ret : -EIO;
	}
	spin_lock_irqsave(&roce->rif_lock, flags);
	i = row * EAL_TABLE_ENTRIES_PER_ROW + bucket;
	if (roce->rif_owner[i] == qpn &&
	    roce->rif_pasid[i] == roce->tombs->pasid.pasid) {
		roce->rif_owner[i] = HFI2_ROCE_RIF_NO_OWNER;
		roce->rif_pasid[i] = 0;
	}
	spin_unlock_irqrestore(&roce->rif_lock, flags);
	roce->tombs->tombstones[slot].sequence = 0;
	for (i = 0; i < ARRAY_SIZE(roce->tombs->tombstones); i++)
		if (roce->tombs->tombstones[i].sequence &&
		    EAL_RIF_ROW_FROM_QP(roce->tombs->tombstones[i].qpn) == row)
			return 0;
	clear_bit(row, roce->tombs->rows);
	return 0;
}

static int roce_tomb_evict(struct hfi2_dms_roce *roce, int row)
{
	int i, oldest = -1, ret;

	lockdep_assert_held(&roce->rif_mutex);
	if (!roce->tombs)
		return -ENOSPC;
	for (i = 0; i < ARRAY_SIZE(roce->tombs->tombstones); i++) {
		if (!roce->tombs->tombstones[i].sequence ||
		    (row >= 0 && EAL_RIF_ROW_FROM_QP(roce->tombs->tombstones[i].qpn) != row))
			continue;
		if (oldest < 0 || roce->tombs->tombstones[i].sequence <
		    roce->tombs->tombstones[oldest].sequence)
			oldest = i;
	}
	if (oldest < 0)
		return -ENOSPC;
	ret = roce_tomb_remove(roce, oldest);
	if (!ret)
		roce->tombs->evicted++;
	return ret;
}

static int roce_tomb_row_full(struct hfi2_dms_roce *roce, u32 qpn)
{
	struct hfi2_dms_roce_rif_entry entry;
	int b, ret;

	lockdep_assert_held(&roce->rif_mutex);
	if (!roce->tombs ||
	    !test_bit(EAL_RIF_ROW_FROM_QP(qpn), roce->tombs->rows))
		return 0;
	for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
		ret = hfi2_dms_roce_rif_readback(roce, qpn, b, &entry);
		if (ret == -ENOENT)
			return 0;
		if (ret)
			return ret;
	}
	ret = roce_tomb_evict(roce, EAL_RIF_ROW_FROM_QP(qpn));
	return ret ? ret : 1;
}

static int roce_tomb_reuse(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	int i, ret = 0;
	bool entered;

	if (rqp->qp->ibqp.qp_type != IB_QPT_RC || !roce->tombs ||
	    hfi2_bulksvc_roce_by_software(rqp->dd))
		return 0;
	entered = roce_rif_enter(roce);
	ret = xa_err(xa_store(&roce->tombs->qps, rqp->qp->ibqp.qp_num,
			      rqp, GFP_KERNEL));
	if (ret)
		goto out;
	rqp->tomb_bound = true;
	for (i = 0; i < ARRAY_SIZE(roce->tombs->tombstones); i++) {
		if (!roce->tombs->tombstones[i].sequence ||
		    roce->tombs->tombstones[i].qpn != rqp->qp->ibqp.qp_num)
			continue;
		ret = roce_tomb_remove(roce, i);
		if (ret)
			break;
		roce->tombs->cleared_reuse++;
	}
out:
	roce_rif_leave(roce, entered);
	return ret;
}

static void roce_tomb_destroy(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_roce_rif_entry entry = {
		.next_psn_state = EAL_RIF_NEXT_PSN_STATE_RUNNING,
	};
	struct hfi2_dms_roce_rif_entry check;
	struct hfi2_dms_roce_rx_mark mark;
	u32 qpn = rqp->qp->ibqp.qp_num;
	int slot, b, attempt, bucket = -1, ret = -ENODEV;
	bool entered;

	if (!roce || !roce->tombs || !rqp->tomb_bound)
		return;
	entered = roce_rif_enter(roce);
	/* A reused QPN belongs to the new binding, even before it reaches RTR. */
	if (xa_load(&roce->tombs->qps, qpn) != rqp)
		goto unlock;
	xa_erase(&roce->tombs->qps, qpn);
	if (!rqp->tomb_recv_seen)
		goto unlock;
	if (!READ_ONCE(roce->active) || !roce->svc ||
	    READ_ONCE(roce->svc->stop_scheduling) ||
	    READ_ONCE(roce->svc->worker_exited) || !roce->tombs->pasid.live)
		goto failed;
	roce_rif_flush_invalidations(roce);
	for (slot = 0; slot < ARRAY_SIZE(roce->tombs->tombstones); slot++)
		if (!roce->tombs->tombstones[slot].sequence)
			break;
	if (slot == ARRAY_SIZE(roce->tombs->tombstones)) {
		ret = roce_tomb_evict(roce, -1);
		if (ret)
			goto failed;
		for (slot = 0; slot < ARRAY_SIZE(roce->tombs->tombstones); slot++)
			if (!roce->tombs->tombstones[slot].sequence)
				break;
	}
	entry.qpn = qpn;
	entry.pasid = roce->tombs->pasid.pasid;
	entry.start_psn = (rqp->tomb_r_psn + 0x400000) & HFI2_ROCE_PSN_MASK;
	entry.end_psn = entry.start_psn;
	entry.next_psn = entry.start_psn;
	for (attempt = 0; attempt < HFI2_ROCE_RIF_RECLAIM_TRIES; attempt++) {
		for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
			ret = hfi2_dms_roce_rif_readback(roce, qpn, b, &check);
			if (ret == -ENOENT || (!ret && check.qpn != qpn)) {
				roce_rif_forget(roce, qpn, b);
				continue;
			}
			if (ret)
				goto failed;
			roce_rif_invalidate_mutex_held(roce, qpn, b);
		}
		bucket = hfi2_dms_roce_rif_arm(roce, &entry, &roce->tombs->pasid);
		if (bucket >= 0)
			break;
		ret = bucket;
		if (ret != -EBUSY && ret != -ENOSPC)
			goto failed;
	}
	if (bucket < 0)
		goto failed;
	roce->tombs->tombstones[slot].qpn = qpn;
	roce->tombs->tombstones[slot].psn = entry.start_psn;
	roce->tombs->tombstones[slot].bucket = bucket;
	roce->tombs->tombstones[slot].sequence = ++roce->tombs->sequence;
	set_bit(EAL_RIF_ROW_FROM_QP(qpn), roce->tombs->rows);
	ret = hfi2_dms_roce_rif_readback(roce, qpn, bucket, &check);
	if (ret || !roce_tomb_matches(roce, slot, &check) ||
	    (check.next_psn_state != EAL_RIF_NEXT_PSN_STATE_RUNNING &&
	     check.next_psn_state != EAL_RIF_NEXT_PSN_STATE_RECOVERING)) {
		ret = ret ? ret : -EIO;
	} else {
		ret = 0;
		roce->tombs->armed++;
	}
	roce_rif_leave(roce, entered);
	/* RX progress needs rif_mutex; never wait for reports while holding it. */
	hfi2_dms_roce_rx_mark(roce, &mark);
	b = hfi2_dms_roce_wait_rx(roce, &mark);
	if (!ret)
		ret = b;
	if (!ret)
		return;
	entered = roce_rif_enter(roce);
failed:
	/* Public WRITE MRs have no retained per-QP PASID tokens for fencing here. */
	roce->tombs->arm_fail++;
	dd_dev_warn_ratelimited(rqp->dd,
				"roce: QP %u WRITE tombstone failed (%d); no retained MR token\n",
				qpn, ret);
unlock:
	roce_rif_leave(roce, entered);
}

static void roce_rif_unreadable_row_error(struct rvt_qp *qp, u64 row)
{
	unsigned long flags;

	if (qp->ibqp.qp_type != IB_QPT_RC || !to_roce_priv(qp)->roce_qp ||
	    EAL_RIF_ROW_FROM_QP(qp->ibqp.qp_num) != row)
		return;
	spin_lock_irqsave(&qp->r_lock, flags);
	rvt_rc_error(qp, IB_WC_LOC_PROT_ERR);
	spin_unlock_irqrestore(&qp->r_lock, flags);
}

/* Keep the software clear bounded to 16 slots and each HW fetch to one bucket. */
static unsigned int
roce_rif_invalidate_pasid_row(struct hfi2_dms_roce *roce, u32 pasid, u32 row,
			      unsigned int *unreadable)
{
	unsigned int b, cleared = 0, read_errs = 0;
	unsigned long flags;
	u64 q[3];
	bool entered = roce_rif_enter(roce);

	for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
		u32 i = row * EAL_TABLE_ENTRIES_PER_ROW + b;
		u32 qpn;

		spin_lock_irqsave(&roce->rif_lock, flags);
		qpn = roce->rif_owner[i];
		if (roce->rif_pasid[i] != pasid)
			qpn = HFI2_ROCE_RIF_NO_OWNER;
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		if (qpn == HFI2_ROCE_RIF_NO_OWNER)
			continue;
		roce_rif_invalidate_mutex_held(roce, qpn, b);
		cleared++;
	}

	for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
		u32 qpn;

		roce_rif_read_entry(roce, row, b, q);
		if (q[0] == ~0ULL || q[1] == ~0ULL || q[2] == ~0ULL) {
			u32 i = row * EAL_TABLE_ENTRIES_PER_ROW + b;

			roce->stats.rif_invalidate_read_err++;
			(*unreadable)++;
			read_errs++;
			spin_lock_irqsave(&roce->rif_lock, flags);
			qpn = roce->rif_owner[i];
			spin_unlock_irqrestore(&roce->rif_lock, flags);
			if (qpn == HFI2_ROCE_RIF_NO_OWNER)
				qpn = row;
			roce_rif_invalidate_mutex_held(roce, qpn, b);
			continue;
		}
		if (!FIELD_GET(EAL_RIF_WDATA2_ENTRY_VALID_MASK, q[2]) ||
		    FIELD_GET(EAL_RIF_WDATA2_PASID_MASK, q[2]) != pasid)
			continue;
		qpn = FIELD_GET(EAL_RIF_WDATA2_QP_MASK, q[2]);
		/* HW bucket reuse here can evict another PASID's acceleration. */
		roce_rif_invalidate_mutex_held(roce, qpn, b);
		roce->stats.rif_invalidate_hw++;
		cleared++;
	}
	roce_rif_leave(roce, entered);
	if (read_errs)
		rvt_qp_iter(&roce->dd->verbs_dev.rdi, row,
			    roce_rif_unreadable_row_error);
	return cleared;
}

static int roce_rif_pasid_scan_rows(struct hfi2_dms_roce *roce, u32 pasid,
				    const unsigned long *rows, bool full_sweep)
{
	unsigned int cleared = 0, unreadable = 0;
	unsigned long row;

	if (full_sweep)
		atomic64_inc(&roce->stats.rif_pasid_full_sweep);
	for_each_set_bit(row, rows, EAL_RIF_TABLE_ROWS) {
		if (!full_sweep)
			atomic64_inc(&roce->stats.rif_pasid_rows_scanned);
		cleared += roce_rif_invalidate_pasid_row(roce, pasid, row,
						       &unreadable);
		cond_resched();
	}
	if (unreadable)
		dd_dev_warn_ratelimited(roce->dd,
					"roce: PASID RIF teardown blindly invalidated %u unreadable buckets; revocation unproven\n",
					unreadable);
	return unreadable ? -EIO : (int)cleared;
}

static bool roce_rif_pasid_needs_full(struct hfi2_dms_roce *roce,
				      const struct roce_rif_rows *tracked)
{
	lockdep_assert_held(&roce->rows_lock);

	return READ_ONCE(roce_rif_pasid_full_sweep) || !roce->svc ||
		READ_ONCE(roce->svc->vrma_rsm_rule) < 0 ||
		(tracked && tracked->loss_gen != roce->rif_pasid_loss_gen);
}

/*
 * Record rows before arm MMIO or RX-progress publication; records precede
 * all keys/arms.  rows_lock nests inside table locks and never spans MMIO.
 * Callers close arms, revoke/flush keys and drain RX before scanning.
 * Rescan late rows; lost evidence or failed drains force a full sweep.
 * Drains are not an ingress fence: late FIRSTs can escape or recreate rows.
 * Unreadable buckets leave revocation unproven; return an error to retain PASID.
 */
int hfi2_dms_roce_rif_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid,
				       bool full_sweep, unsigned long *scanned)
{
	struct roce_rif_rows *tracked;
	unsigned long flags;
	int ret;

	bitmap_zero(scanned, EAL_RIF_TABLE_ROWS);
	if (!roce || !roce->initialized)
		return -ENODEV;
	if (!roce->rif_owner || !roce->rif_pasid) {
		ret = -ENODEV;
		goto forget;
	}
	if (!pasid || pasid > FIELD_MAX(EAL_RIF_WDATA2_PASID_MASK)) {
		ret = -EINVAL;
		goto forget;
	}

	roce_rif_pasid_check_overflow(roce);
	spin_lock_irqsave(&roce->rows_lock, flags);
	tracked = xa_load(&roce->rif_pasid_rows, pasid);
	if (!tracked && !roce_rif_pasid_needs_full(roce, NULL)) {
		spin_unlock_irqrestore(&roce->rows_lock, flags);
		return 0;
	}
	if (tracked) {
		tracked->retiring = true;
		bitmap_copy(scanned, tracked->rows, EAL_RIF_TABLE_ROWS);
	}
	full_sweep |= roce_rif_pasid_needs_full(roce, tracked);
	spin_unlock_irqrestore(&roce->rows_lock, flags);
	if (full_sweep)
		bitmap_fill(scanned, EAL_RIF_TABLE_ROWS);
	return roce_rif_pasid_scan_rows(roce, pasid, scanned, full_sweep);

forget:
	kfree(roce_rif_pasid_take(roce, pasid));
	return ret;
}

int hfi2_dms_roce_rif_pasid_finish(struct hfi2_dms_roce *roce, u32 pasid,
				   unsigned long *scanned, int drain_ret)
{
	DECLARE_BITMAP(delta, EAL_RIF_TABLE_ROWS);
	struct hfi2_dms_roce_rx_mark mark;
	struct roce_rif_rows *tracked;
	unsigned long flags;
	unsigned int pass, late;
	int cleared = 0, err = drain_ret, ret;
	bool full_sweep;

	if (!roce || !roce->initialized)
		return -ENODEV;
	if (!roce->rif_owner || !roce->rif_pasid || !pasid ||
	    pasid > FIELD_MAX(EAL_RIF_WDATA2_PASID_MASK)) {
		err = -EINVAL;
		goto forget;
	}

	for (pass = 0; ; pass++) {
		roce_rif_pasid_check_overflow(roce);
		spin_lock_irqsave(&roce->rows_lock, flags);
		tracked = xa_load(&roce->rif_pasid_rows, pasid);
		if (!tracked && !roce_rif_pasid_needs_full(roce, NULL)) {
			spin_unlock_irqrestore(&roce->rows_lock, flags);
			return err ?: cleared;
		}
		bitmap_zero(delta, EAL_RIF_TABLE_ROWS);
		if (tracked)
			bitmap_andnot(delta, tracked->rows, scanned, EAL_RIF_TABLE_ROWS);
		late = bitmap_weight(delta, EAL_RIF_TABLE_ROWS);
		atomic64_add(late, &roce->stats.rif_pasid_late_rows);
		full_sweep = !bitmap_full(scanned, EAL_RIF_TABLE_ROWS) &&
			(drain_ret || roce_rif_pasid_needs_full(roce, tracked) ||
			 (late && pass == 4));
		if (!full_sweep && !late) {
			tracked = xa_erase(&roce->rif_pasid_rows, pasid);
			WRITE_ONCE(roce->rif_pasid_rows_gen, roce->rif_pasid_rows_gen + 1);
			spin_unlock_irqrestore(&roce->rows_lock, flags);
			kfree(tracked);
			return err ?: cleared;
		}
		spin_unlock_irqrestore(&roce->rows_lock, flags);
		if (full_sweep)
			bitmap_fill(delta, EAL_RIF_TABLE_ROWS);
		ret = roce_rif_pasid_scan_rows(roce, pasid, delta, full_sweep);
		if (ret < 0)
			err = ret;
		else
			cleared += ret;
		bitmap_or(scanned, scanned, delta, EAL_RIF_TABLE_ROWS);
		if (hfi2_read_csr(roce->dd, CYR_EAL_ROCEV2_CFG) == ~0ULL)
			err = -EIO;
		hfi2_dms_roce_rx_mark(roce, &mark);
		drain_ret = hfi2_dms_roce_wait_rx(roce, &mark);
		if (drain_ret) {
			err = drain_ret;
			dd_dev_warn_ratelimited(roce->dd,
						"roce: PASID %u delta drain failed: %d\n",
						pasid, drain_ret);
		}
		if (full_sweep)
			break;
	}
forget:
	kfree(roce_rif_pasid_take(roce, pasid));
	return err ?: cleared;
}

/**
 * hfi2_dms_roce_mr_eligible - can this MR ever be hardware-placed?
 * @dd: device
 * @has_mm: the MR has a umem with an owning address space
 * @has_pinned_dmabuf: the MR is backed by a pinned dma-buf
 * @has_donor: the MR is backed by the donor SVA address space
 * @length: the region size in bytes
 *
 * The MR-lifetime half of the eligibility ladder (design S5.3.3).  Two of the
 * four checks that section lists are properties of the MR and are answered
 * here, once, at registration.  The other two are not: the placement stride is
 * a QP property already settled by hfi2_dms_roce_claim_stride() at RTR, and
 * SGE linearity is a per-WQE question with no meaning until a work request
 * exists.
 *
 * Order is load-bearing and design states it: the address space FIRST, ahead
 * of size.  A kernel region has no placement mechanism AT ALL - rif_pasid is
 * the only translation control in either EAL table, so every placement write
 * is a PASID-tagged TLP and a region with no address space can never be a
 * target (S5.3.4, withdrawn on measurement).  Asking about its length first
 * would imply a mechanism exists that merely cannot describe it, and would
 * attribute a kernel MR's decline to its size.
 *
 * The verdict does not depend on the backend, because eligibility is a
 * property of the region rather than of the device's state.  Counting does:
 * bulksvc is absent on WFR and after an init failure, and nothing can be
 * accelerated there at all, so an uncounted decline is not a lost signal.
 *
 * Return: true if the MR may be hardware-placed.
 */
bool hfi2_dms_roce_mr_eligible(struct hfi2_devdata *dd, bool has_mm,
			       bool has_pinned_dmabuf, bool has_donor, size_t length)
{
	struct hfi2_dms_roce *roce = NULL;

	if (dd && dd->bulksvc && dd->bulksvc->dms_roce &&
	    dd->bulksvc->dms_roce->initialized)
		roce = dd->bulksvc->dms_roce;

	/* Nothing is hardware-placed; see hfi2_bulksvc_roce_by_software(). */
	if (hfi2_bulksvc_roce_by_software(dd)) {
		if (roce)
			roce->stats.mr_ineligible_sw_rx++;
		return false;
	}

	if (!has_mm && !has_pinned_dmabuf && !has_donor) {
		if (roce)
			roce->stats.mr_ineligible_kernel++;
		return false;
	}

	/*
	 * The R_Key entry's length field is a 24-bit BYTE count (gate H15), so
	 * a region of 16 MiB or more cannot be described.  Deciding it here
	 * rather than at install time keeps the decline attributable to the MR
	 * that caused it; by install time the only thing left to say is that
	 * some entry did not fit.
	 */
	if (length > EAL_RKEY_LENGTH_MAX) {
		if (roce)
			roce->stats.mr_ineligible_length++;
		/*
		 * H15 keeps the MR eligible past this point so it still binds
		 * a PASID, which the software-armed RIF entry needs.  The
		 * decline itself is unchanged - mr_rkey_install() refuses the
		 * same length, so no R_Key entry is ever created and the count
		 * above still attributes the decline to this MR.  Binding the
		 * PASID is what exposes the MR to placement past the WRITE's
		 * length; see roce_h15_arm_burst().
		 */
		return true;
	}

	if (roce)
		roce->stats.mr_eligible++;

	return true;
}

/*
 * Encode an R_Key entry into the three staging registers.
 *
 * WDATA2 carries the FULL 32-bit key, not the 23-bit comparand.  4.5.2.5.13.9
 * describes an entry as holding the "upper 23 bits of the R_Key", which is what
 * hardware STORES after deriving the row from R_Key[8:0] - it is not what
 * software supplies.  The register field is [32:1], and masking to 23 bits
 * before the write corrupts row selection: the entry lands in a row chosen from
 * the wrong bits and is never found again.
 */
static void roce_rkey_encode(const struct hfi2_dms_roce_rkey_entry *entry,
			     u64 wdata[3])
{
	wdata[0] = FIELD_PREP(EAL_RKEY_WDATA0_VIRTUAL_ADDRESS_MASK,
			      entry->start_vaddr);
	wdata[1] = FIELD_PREP(EAL_RKEY_WDATA1_PASID_MASK, entry->pasid) |
		   FIELD_PREP(EAL_RKEY_WDATA1_PERMISSIONS_MASK,
			      entry->permissions) |
		   FIELD_PREP(EAL_RKEY_WDATA1_LENGTH_MASK, entry->length);
	wdata[2] = FIELD_PREP(EAL_RKEY_WDATA2_BUCKET_NUMB_MASK, entry->bucket) |
		   FIELD_PREP(EAL_RKEY_WDATA2_RKEY_MASK, entry->rkey) |
		   FIELD_PREP(EAL_RKEY_WDATA2_ENTRY_VALID_MASK, 1);
}

/*
 * Identical discipline to roce_rif_write(): three stores, WDATA2 last, no
 * barrier needed because the aperture resolves into kregbase1, and all three
 * written every time because the staging registers retain their last value
 * indefinitely.
 */
static void roce_rkey_write(struct hfi2_dms_roce *roce, const u64 wdata[3])
{
	lockdep_assert_held(&roce->rkey_lock);

	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RKEY_TABLE + EAL_TABLE_WDATA0, wdata[0]);
	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RKEY_TABLE + EAL_TABLE_WDATA1, wdata[1]);
	hfi2_write_csr(roce->dd, CYR_EAL_PIO_RKEY_TABLE + EAL_TABLE_WDATA2, wdata[2]);
}

/**
 * hfi2_dms_roce_rkey_permissions - translate IB access flags for the R_Key entry
 * @access_flags: the MR's access flags
 *
 * Only the two REMOTE permissions are meaningful here.  Hardware consults this
 * entry to validate a request that arrived from the wire; the local access
 * flags govern what this host may do with the region and have no bearing on
 * what a peer may ask for.
 *
 * Return: the EAL permission bits, or 0 if no peer may touch the region.
 */
u8 hfi2_dms_roce_rkey_permissions(int access_flags)
{
	u8 perms = 0;

	if (access_flags & IB_ACCESS_REMOTE_WRITE)
		perms |= EAL_RKEY_PERMISSION_WRITE;
	if (access_flags & IB_ACCESS_REMOTE_READ)
		perms |= EAL_RKEY_PERMISSION_READ;

	return perms;
}

/*
 * FIRST validates its RETH here and copies this PASID into the RIF entry.
 * Require a matching live token: placement reports carry no R_Key to diagnose
 * a wrong address space later.  A miss sends FIRST to software for arming.
 * Return the selected bucket or a negative error; reject before MMIO so a
 * refused install cannot leave a partial entry.
 */
int hfi2_dms_roce_rkey_install(struct hfi2_dms_roce *roce,
			       const struct hfi2_dms_roce_rkey_entry *entry,
			       const struct hfi2_roce_pasid *pasid)
{
	struct hfi2_dms_roce_rkey_entry installed;
	struct roce_rif_rows *tracked;
	int free_bucket = -1;
	unsigned long flags;
	u32 *pasid_row;
	u8 *internal_row;
	u64 wdata[3];
	u32 *owner;
	u32 row;
	int i;

	if (!roce || !roce->initialized || !roce->rkey_owner ||
	    !roce->rkey_pasid || !roce->rkey_internal)
		return -ENODEV;

	if (!pasid) {
		roce->stats.rkey_install_reject++;
		return -EINVAL;
	}

	/*
	 * Length is a BYTE count in a 24-bit field (gate H15), so a region of
	 * 16 MiB or more cannot be described.  Refuse it rather than clamp:
	 * a truncated length would install a valid entry describing a SHORTER
	 * region than the one registered, and hardware would then bounds-check
	 * an inbound RETH against the wrong end address and decline placements
	 * that are legitimately in range - or, on the RIF side, place a burst
	 * whose tail runs past what this entry claims.  Losing acceleration is
	 * recoverable; describing the wrong region is not.
	 */
	if (entry->length > EAL_RKEY_LENGTH_MAX || entry->length == 0) {
		roce->stats.rkey_too_long++;
		return -EFBIG;
	}

	/*
	 * Every remaining field is masked into its register by FIELD_PREP,
	 * which truncates silently.
	 */
	if (entry->rkey == HFI2_ROCE_RKEY_NO_OWNER || !entry->pasid ||
	    entry->pasid > FIELD_MAX(EAL_RKEY_WDATA1_PASID_MASK) ||
	    entry->permissions > FIELD_MAX(EAL_RKEY_WDATA1_PERMISSIONS_MASK)) {
		roce->stats.rkey_install_reject++;
		return -EINVAL;
	}

	row = EAL_RKEY_ROW_FROM_KEY(entry->rkey);
	owner = &roce->rkey_owner[row * EAL_TABLE_ENTRIES_PER_ROW];
	pasid_row = &roce->rkey_pasid[row * EAL_TABLE_ENTRIES_PER_ROW];
	internal_row = &roce->rkey_internal[row * EAL_TABLE_ENTRIES_PER_ROW];

	spin_lock_irqsave(&roce->rkey_lock, flags);

	if (!READ_ONCE(pasid->live) || READ_ONCE(pasid->quiesce_failed) ||
	    xa_load(&roce->dd->roce_pasid_blocked, entry->pasid)) {
		roce->stats.rkey_dead_mm++;
		spin_unlock_irqrestore(&roce->rkey_lock, flags);
		return -ESTALE;
	}

	if (entry->pasid != pasid->pasid) {
		roce->stats.rkey_pasid_mismatch++;
		spin_unlock_irqrestore(&roce->rkey_lock, flags);
		return -EINVAL;
	}
	/* No FIRST can hit this key until its tracking record exists. */
	spin_lock(&roce->rows_lock);
	tracked = roce_rif_pasid_get_locked(roce, entry->pasid);
	if (!tracked || tracked->retiring) {
		int ret = tracked ? -ESTALE : -ENOMEM;

		spin_unlock(&roce->rows_lock);
		spin_unlock_irqrestore(&roce->rkey_lock, flags);
		return ret;
	}
	spin_unlock(&roce->rows_lock);

	/*
	 * A key already present is REPLACED in its own bucket rather than
	 * added to a second one.  Successive generations of one region share
	 * the comparand and differ only in the row, so they cannot collide
	 * with each other here; what this catches is a re-install of the same
	 * key, where a second bucket would leave two entries hardware could
	 * match ambiguously - the R_Key analogue of the RIF exclusivity rule.
	 */
	for (i = 0; i < EAL_TABLE_ENTRIES_PER_ROW; i++) {
		if (owner[i] == entry->rkey) {
			if (internal_row[i] != entry->internal) {
				roce->stats.rkey_install_reject++;
				spin_unlock_irqrestore(&roce->rkey_lock, flags);
				return -EEXIST;
			}
			free_bucket = i;
			break;
		}
		if (free_bucket < 0 && owner[i] == HFI2_ROCE_RKEY_NO_OWNER)
			free_bucket = i;
	}

	/*
	 * Row full.  Pressure is per row and never global: a row holds 16
	 * entries and can fill while the table is 99.8% empty, so this is not
	 * a signal to shed load device-wide.  Declining costs hardware-FIRST
	 * for this region only - software-FIRST still arms the RIF entry and
	 * MIDDLEs are still hardware-placed (4.5.2.5.13.3 never consults this
	 * table).
	 */
	if (free_bucket < 0) {
		roce->stats.rkey_row_full++;
		spin_unlock_irqrestore(&roce->rkey_lock, flags);
		return -ENOSPC;
	}

	installed = *entry;
	installed.bucket = (u8)free_bucket;
	roce_rkey_encode(&installed, wdata);
	roce_rkey_write(roce, wdata);
	owner[free_bucket] = entry->rkey;
	pasid_row[free_bucket] = entry->pasid;
	internal_row[free_bucket] = entry->internal;
	roce->stats.rkey_install++;
	spin_unlock_irqrestore(&roce->rkey_lock, flags);

	return free_bucket;
}

/**
 * hfi2_dms_roce_rkey_invalidate - clear one R_Key entry
 * @roce: per-device RoCE backend
 * @rkey: the key whose low bits select the row
 * @bucket: bucket within that row
 *
 * Revocation is mandatory rather than an optimization: a stale entry keeps a
 * region hardware-validatable after the MR it describes is gone, and the
 * PASID it carries may by then belong to a different address space.
 */
int hfi2_dms_roce_rkey_invalidate(struct hfi2_dms_roce *roce, u32 rkey,
				  u8 bucket)
{
	unsigned long flags;
	u32 *pasid_row;
	u8 *internal_row;
	u64 wdata[3];
	u32 *owner;

	if (!roce || !roce->initialized || !roce->rkey_owner ||
	    !roce->rkey_pasid || !roce->rkey_internal)
		return -ENODEV;
	if (rkey == HFI2_ROCE_RKEY_NO_OWNER ||
	    bucket >= EAL_TABLE_ENTRIES_PER_ROW) {
		roce->stats.rkey_invalidate_reject++;
		return -EINVAL;
	}

	wdata[0] = 0;
	wdata[1] = 0;
	wdata[2] = FIELD_PREP(EAL_RKEY_WDATA2_BUCKET_NUMB_MASK, bucket) |
		   FIELD_PREP(EAL_RKEY_WDATA2_RKEY_MASK, rkey);

	owner = &roce->rkey_owner[EAL_RKEY_ROW_FROM_KEY(rkey) *
				  EAL_TABLE_ENTRIES_PER_ROW];
	pasid_row = &roce->rkey_pasid[EAL_RKEY_ROW_FROM_KEY(rkey) *
					  EAL_TABLE_ENTRIES_PER_ROW];
	internal_row = &roce->rkey_internal[EAL_RKEY_ROW_FROM_KEY(rkey) *
					       EAL_TABLE_ENTRIES_PER_ROW];

	spin_lock_irqsave(&roce->rkey_lock, flags);
	/*
	 * A LOCAL_INV may have already revoked this slot.  Do not write the
	 * table until ownership proves this call still names the installed
	 * entry: the bucket might now belong to a different MR in the same row.
	 */
	if (owner[bucket] != rkey) {
		spin_unlock_irqrestore(&roce->rkey_lock, flags);
		return 0;
	}
	roce_rkey_write(roce, wdata);
	owner[bucket] = HFI2_ROCE_RKEY_NO_OWNER;
	pasid_row[bucket] = 0;
	internal_row[bucket] = false;
	roce->stats.rkey_invalidate++;
	spin_unlock_irqrestore(&roce->rkey_lock, flags);

	return 0;
}

bool hfi2_dms_roce_rkey_is_internal(struct hfi2_dms_roce *roce, u32 rkey)
{
	unsigned long flags;
	bool internal = false;
	u32 *owner;
	u8 *internal_row;
	int i;

	if (!roce || !roce->initialized || !roce->rkey_owner ||
	    !roce->rkey_internal || rkey == HFI2_ROCE_RKEY_NO_OWNER)
		return false;

	owner = &roce->rkey_owner[EAL_RKEY_ROW_FROM_KEY(rkey) *
				  EAL_TABLE_ENTRIES_PER_ROW];
	internal_row = &roce->rkey_internal[EAL_RKEY_ROW_FROM_KEY(rkey) *
					       EAL_TABLE_ENTRIES_PER_ROW];
	spin_lock_irqsave(&roce->rkey_lock, flags);
	for (i = 0; i < EAL_TABLE_ENTRIES_PER_ROW; i++) {
		if (owner[i] == rkey) {
			internal = internal_row[i];
			break;
		}
	}
	spin_unlock_irqrestore(&roce->rkey_lock, flags);
	return internal;
}

/**
 * hfi2_dms_roce_rkey_invalidate_pasid - clear every entry carrying a PASID
 * @roce: per-device RoCE backend
 * @pasid: the PASID whose entries must stop being able to validate
 *
 * The R_Key half of the address-space teardown sweep.  It must run BEFORE the
 * RIF sweep, not after: an R_Key entry left valid lets hardware create a fresh
 * RIF entry on the next FIRST, which would repopulate rows the RIF sweep has
 * already cleared.
 *
 * Return: the number of entries invalidated, or -ENODEV if the backend is down.
 */
int hfi2_dms_roce_rkey_invalidate_pasid(struct hfi2_dms_roce *roce, u32 pasid)
{
	unsigned int cleared = 0;
	unsigned long flags;
	unsigned int i;
	u64 wdata[3];

	if (!roce || !roce->initialized || !roce->rkey_owner ||
	    !roce->rkey_pasid || !roce->rkey_internal)
		return -ENODEV;

	/* PASID 0 is never installed; treating it as a wildcard would clear
	 * every unused slot and hide a caller that lost its binding.
	 */
	if (!pasid || pasid > FIELD_MAX(EAL_RKEY_WDATA1_PASID_MASK))
		return -EINVAL;

	spin_lock_irqsave(&roce->rkey_lock, flags);

	for (i = 0; i < EAL_RKEY_TABLE_ROWS * EAL_TABLE_ENTRIES_PER_ROW; i++) {
		u32 rkey = roce->rkey_owner[i];

		if (rkey == HFI2_ROCE_RKEY_NO_OWNER ||
		    roce->rkey_pasid[i] != pasid)
			continue;

		wdata[0] = 0;
		wdata[1] = 0;
		wdata[2] = FIELD_PREP(EAL_RKEY_WDATA2_BUCKET_NUMB_MASK,
				      i % EAL_TABLE_ENTRIES_PER_ROW) |
			   FIELD_PREP(EAL_RKEY_WDATA2_RKEY_MASK, rkey);
		roce_rkey_write(roce, wdata);

		roce->rkey_owner[i] = HFI2_ROCE_RKEY_NO_OWNER;
		roce->rkey_pasid[i] = 0;
		roce->rkey_internal[i] = false;
		roce->stats.rkey_invalidate++;
		cleared++;
	}

	spin_unlock_irqrestore(&roce->rkey_lock, flags);

	return (int)cleared;
}

/**
 * hfi2_dms_roce_rkey_readback - read an installed entry over the config bus
 * @roce: per-device RoCE backend
 * @rkey: the key whose low bits select the row
 * @bucket: bucket within that row
 * @out: decoded entry
 *
 * PIO is write-only, so verification goes through the Configuration bus.
 *
 * What this CAN observe, unlike its RIF counterpart: the R_Key table is written
 * only by software and hardware never advances an entry in place, so a
 * read-back here reflects committed state rather than a pipeline's view of it.
 * That makes it a genuine check on the fields software computes - the full
 * 32-bit key, the byte length, and the PASID.
 *
 * Return: 0 if the entry is valid, -ENOENT if it is not.
 */
int hfi2_dms_roce_rkey_readback(struct hfi2_dms_roce *roce, u32 rkey, u8 bucket,
				struct hfi2_dms_roce_rkey_entry *out)
{
	u64 q0, q1, q2;
	u32 row;

	if (!roce || !roce->initialized)
		return -ENODEV;
	if (rkey == HFI2_ROCE_RKEY_NO_OWNER ||
	    bucket >= EAL_TABLE_ENTRIES_PER_ROW)
		return -EINVAL;

	row = EAL_RKEY_ROW_FROM_KEY(rkey);
	q0 = hfi2_read_csr(roce->dd, EAL_RKEY_READ_ADDR(row, bucket, 0));
	q1 = hfi2_read_csr(roce->dd, EAL_RKEY_READ_ADDR(row, bucket, 1));
	q2 = hfi2_read_csr(roce->dd, EAL_RKEY_READ_ADDR(row, bucket, 2));

	out->start_vaddr = FIELD_GET(EAL_RKEY_WDATA0_VIRTUAL_ADDRESS_MASK, q0);
	out->pasid = FIELD_GET(EAL_RKEY_WDATA1_PASID_MASK, q1);
	out->permissions = FIELD_GET(EAL_RKEY_WDATA1_PERMISSIONS_MASK, q1);
	out->length = FIELD_GET(EAL_RKEY_WDATA1_LENGTH_MASK, q1);
	out->bucket = FIELD_GET(EAL_RKEY_WDATA2_BUCKET_NUMB_MASK, q2);
	out->rkey = FIELD_GET(EAL_RKEY_WDATA2_RKEY_MASK, q2);

	return FIELD_GET(EAL_RKEY_WDATA2_ENTRY_VALID_MASK, q2) ? 0 : -ENOENT;
}

/*
 * PIO is write-only: fetch q0 through the config bus before reading q1/q2
 * from its staging latch.  q3 is a packet counter, not entry data.
 * Readback is not a fence for live placement.  Sleepable callers must hold
 * no QP/table spinlock or RCU read-side section.
 * Return 0 for a valid entry, -ENOENT for an empty slot, or a negative error.
 */
int hfi2_dms_roce_rif_readback(struct hfi2_dms_roce *roce, u32 qpn, u8 bucket,
			       struct hfi2_dms_roce_rif_entry *out)
{
	u32 row;
	u64 q[3];
	bool entered;

	if (!roce || !roce->initialized)
		return -ENODEV;
	if (qpn > FIELD_MAX(EAL_RIF_WDATA2_QP_MASK) ||
	    bucket >= EAL_TABLE_ENTRIES_PER_ROW)
		return -EINVAL;

	if (irqs_disabled())
		return -EWOULDBLOCK;
	row = EAL_RIF_ROW_FROM_QP(qpn);
	entered = roce_rif_enter(roce);
	roce_rif_read_entry(roce, row, bucket, q);
	roce_rif_leave(roce, entered);
	if (q[0] == ~0ULL || q[1] == ~0ULL || q[2] == ~0ULL)
		return -EIO;

	out->start_vaddr = FIELD_GET(EAL_RIF_WDATA0_START_VIRTUAL_ADDRESS_MASK,
				     q[0]);
	out->end_psn = FIELD_GET(EAL_RIF_WDATA1_END_PSN_MASK, q[1]);
	out->start_psn = FIELD_GET(EAL_RIF_WDATA1_START_PSN_MASK, q[1]);
	out->next_psn =
		EAL_RIF_NEXT_PSN_FROM_HALVES(FIELD_GET(EAL_RIF_WDATA1_NEXT_PSN_HI_MASK,
						       q[1]),
					     FIELD_GET(EAL_RIF_WDATA2_NEXT_PSN_LO_MASK,
						       q[2]));
	out->next_psn_state = FIELD_GET(EAL_RIF_WDATA2_NEXT_PSN_STATE_MASK, q[2]);
	out->pasid = FIELD_GET(EAL_RIF_WDATA2_PASID_MASK, q[2]);
	out->bucket = FIELD_GET(EAL_RIF_WDATA2_BUCKET_NUMB_MASK, q[2]);
	out->qpn = FIELD_GET(EAL_RIF_WDATA2_QP_MASK, q[2]);

	return FIELD_GET(EAL_RIF_WDATA2_ENTRY_VALID_MASK, q[2]) ? 0 : -ENOENT;
}

/*
 * IB opcode for one packet of a multi-packet SEND message.  @first is the
 * first packet of the message, @last the last; SEND_ONLY when both.
 */
static u8 roce_send_opcode(bool first, bool last, bool with_imm, bool with_inv)
{
	u8 opcode;

	if (first && last)
		opcode = IB_OPCODE_RC_SEND_ONLY;
	else if (first)
		opcode = IB_OPCODE_RC_SEND_FIRST;
	else if (last)
		opcode = IB_OPCODE_RC_SEND_LAST;
	else
		return IB_OPCODE_RC_SEND_MIDDLE;

	if (!last)
		return opcode;
	if (with_imm)
		return opcode == IB_OPCODE_RC_SEND_ONLY ?
			IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
			IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE;
	if (with_inv)
		return opcode == IB_OPCODE_RC_SEND_ONLY ?
			IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE :
			IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE;
	return opcode;
}

static u8 roce_write_opcode(bool first, bool last, bool with_imm)
{
	if (first && last)
		return with_imm ? IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				  IB_OPCODE_RC_RDMA_WRITE_ONLY;
	if (first)
		return IB_OPCODE_RC_RDMA_WRITE_FIRST;
	if (last)
		return with_imm ? IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				  IB_OPCODE_RC_RDMA_WRITE_LAST;
	return IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
}

/*
 * The request lengths a WRITE, WRITE_WITH_IMM, SEND, SEND_WITH_IMM, or
 * SEND_WITH_INV packet carries after its BTH: a RETH on the first packet of
 * either WRITE, and immediate data or an invalidate key on the last packet.
 * A WRITE ONLY with immediate carries both, RETH first.
 */
static bool roce_req_is_write(enum ib_wr_opcode op)
{
	return op == IB_WR_RDMA_WRITE || op == IB_WR_RDMA_WRITE_WITH_IMM;
}

static bool roce_wqe_is_rd_atomic(enum ib_wr_opcode op)
{
	return op == IB_WR_RDMA_READ || op == IB_WR_ATOMIC_CMP_AND_SWP ||
	       op == IB_WR_ATOMIC_FETCH_AND_ADD;
}

static bool roce_order_request(enum ib_wr_opcode op)
{
	return op == IB_WR_ATOMIC_CMP_AND_SWP ||
	       op == IB_WR_ATOMIC_FETCH_AND_ADD || op == IB_WR_SEND_WITH_INV;
}

static bool roce_order_write_blocked(struct hfi2_dms_roce_qp *rqp,
				     struct rvt_swqe *write)
{
	struct rvt_qp *qp = rqp->qp;
	u32 i;

	lockdep_assert_held(&qp->s_lock);
	if (!roce_req_is_write(write->wr.opcode))
		return false;

	/*
	 * Keep debt until wire ACKs; scan the live SQ so no invalidate is lost
	 * and a later request cannot block an earlier replay.
	 */
	for (i = qp->s_acked; i != qp->s_tail;
	     i = i + 1 < qp->s_size ? i + 1 : 0) {
		struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, i);

		if (roce_cmp_psn(wqe->psn, write->psn) >= 0)
			break;
		switch (wqe->wr.opcode) {
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			rqp->roce->stats.tx_order_gate_atomic++;
			return true;
		case IB_WR_SEND_WITH_INV:
			if (wqe->wr.ex.invalidate_rkey == write->rdma_wr.rkey) {
				rqp->roce->stats.tx_order_gate_inv++;
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

static void roce_order_request_acked(struct hfi2_dms_roce_qp *rqp)
{
	lockdep_assert_held(&rqp->qp->s_lock);
	rqp->order_pending--;
	if ((rqp->qp->s_flags & RVT_S_WAIT_FENCE) &&
	    !rqp->order_pending && !rqp->qp->s_num_rd_atomic)
		rqp->qp->s_flags &= ~(RVT_S_WAIT_FENCE | RVT_S_WAIT_ACK);
	hfi2_roce_schedule_send(rqp->qp);
}

static bool roce_req_has_imm(enum ib_wr_opcode op)
{
	return op == IB_WR_SEND_WITH_IMM || op == IB_WR_RDMA_WRITE_WITH_IMM;
}

static bool roce_req_has_inv(enum ib_wr_opcode op)
{
	return op == IB_WR_SEND_WITH_INV;
}

static u32 roce_req_ext_len(enum ib_wr_opcode op, bool first, bool last)
{
	return (roce_req_is_write(op) && first ? HFI2_ROCE_RETH_BYTES : 0) +
	       (roce_req_has_imm(op) && last ? HFI2_ROCE_IMMDT_BYTES : 0) +
	       (roce_req_has_inv(op) && last ? HFI2_ROCE_IETH_BYTES : 0);
}

/*
 * PIO one fully built RoCEv2 frame.  @roce_len is the full frame length from
 * the Ethernet header through the pad, NOT including the 4 ICRC bytes EAL
 * appends.  The buffer at rqp->txbuf is
 * [EAL egress hdr(16)][Eth][IPv4][UDP][BTH][payload][pad]; EAL hardware
 * computes and appends the ICRC (add_icrc=1) after decapsulation, so the EAL
 * LENGTH/E fields and the PIO length describe the pre-ICRC bytes only.  (The
 * IP/UDP length fields still count the ICRC per the RoCE wire spec -- that is
 * built into the Eth/IP/UDP header and is independent of the EAL sizing.)
 * Returns 0 on success, -EAGAIN if no PIO credits are available.
 */
struct roce_pio_span {
	void __iomem *limit;
	void __iomem *next;
};

struct roce_pio_copy {
	struct hfi2_dms_roce *roce;
	void __iomem *base;
	void __iomem *end;
	void __iomem *dest;
	struct roce_pio_span spans[3];
	union mix carry;
	u8 carry_bytes;
	u8 span;
	bool fence;		/* flush this packet's stores at copy end */
	bool credit_return;
};

static __always_inline void roce_pio_next_span(struct roce_pio_copy *copy)
{
	copy->dest = copy->spans[copy->span++].next;
}

static __always_inline void roce_pio_normalize_span(struct roce_pio_copy *copy)
{
	while (copy->dest == copy->spans[copy->span].limit)
		roce_pio_next_span(copy);
}

static void roce_pio_init_spans(struct roce_pio_copy *copy, u32 data_qws)
{
	void __iomem *send = copy->dest + 7 * sizeof(u64);
	void __iomem *dend = copy->dest + data_qws * sizeof(u64);

	copy->span = 0;
	if (dend <= send) {
		copy->spans[0].limit = dend;
		return;
	}

	copy->spans[0].limit = send;
	copy->spans[0].next = send - SOP_DISTANCE;
	dend -= SOP_DISTANCE;
	if (dend <= copy->end) {
		copy->spans[1].limit = dend;
		return;
	}

	copy->spans[1].limit = copy->end;
	copy->spans[1].next = copy->base;
	copy->spans[2].limit = copy->base + (dend - copy->end);
}

#ifdef CONFIG_X86_64
static bool roce_pio_blk64_ready(void)
{
	return READ_ONCE(roce_pio_movdir64b) &&
	       cpu_feature_enabled(X86_FEATURE_MOVDIR64B);
}

static void roce_pio_blk64(void __iomem *dest, const u64 *src)
{
	movdir64b_io(dest, src);
}
#else
static bool roce_pio_blk64_ready(void)
{
	return false;
}

/*
 * Unreachable while roce_pio_blk64_ready() is false, but kept semantically
 * identical to the 64-byte store rather than empty so enabling it on another
 * architecture cannot silently drop a send block.
 */
static void roce_pio_blk64(void __iomem *dest, const u64 *src)
{
	unsigned int i;

	for (i = 0; i < ROCE_PIO_QWS_PER_BLOCK; i++)
		writeq(src[i], dest + i * sizeof(u64));
}
#endif

/*
 * Write the contiguous run [@dest, @limit) from *@srcp and return the new
 * @dest.  Both loops are branch-free: the caller has already split the
 * transfer at the SOP and ring-wrap boundaries, so nothing here has to test
 * for them.  This is what makes the copy cheap -- the previous per-qword
 * implementation evaluated a block-boundary mask on every qword plus an SOP
 * and a wrap compare on every eighth, which for an 8 KB frame is ~1024 mask
 * tests and 256 extra compares that the span split hoists away entirely.
 */
static void __iomem *roce_pio_span(void __iomem *dest, void __iomem *limit,
				   const u64 **srcp, bool blk64)
{
	const u64 *src = *srcp;

	/*
	 * MOVDIR64B needs a 64-byte-aligned destination and writes exactly one
	 * send block, so it is used only for whole blocks starting on a block
	 * boundary.  The source is deliberately not aligned: with the PBC in
	 * qword 0 every later block starts 56 bytes into the frame buffer, and
	 * a split load off a hot L1 line is far cheaper than restructuring the
	 * frame layout across every header-build site.
	 */
	if (blk64 && !((unsigned long)dest & PIO_BLOCK_MASK)) {
		void __iomem *blkend =
			dest + ((limit - dest) & ~(long)PIO_BLOCK_MASK);

		while (dest < blkend) {
			roce_pio_blk64(dest, src);
			src += ROCE_PIO_QWS_PER_BLOCK;
			dest += PIO_BLOCK_SIZE;
		}
	}

	while (dest < limit) {
		writeq(*src++, dest);
		dest += sizeof(u64);
	}

	*srcp = src;
	return dest;
}

/*
 * Frames are counted in the send context's own allocator state - fill,
 * fill_wrap and alloc_free under alloc_lock, as hfi2_sc_buffer_alloc() does - so
 * the reset sc_enable() applies when this SC_BULKSVC context is re-enabled
 * after a halt (sc_halted()), a freeze or a link bounce restarts these counts
 * too.  Whatever was outstanding when the context stopped was dropped or has
 * already egressed; RC retransmission covers the frames.
 *
 * A restart is seen either as the context found stopped by this worker and
 * then enabled again, or - when it completed between two looks - as fill
 * moving backwards; this backend is the only allocator on the context.  The
 * worker checks on every poll as well as before each frame, so a restart is
 * counted even while every request goes out over SDMA.  Caller holds
 * sc->alloc_lock.
 */
static void roce_pio_note_restart(struct hfi2_dms_roce *roce)
{
	struct send_context *sc = roce->sc;

	if (!(sc->flags & SCF_ENABLED)) {
		WRITE_ONCE(roce->pio_ctx_stopped, true);
		return;
	}
	if (unlikely(roce->pio_ctx_stopped || sc->fill < roce->pio_last_fill)) {
		WRITE_ONCE(roce->pio_ctx_stopped, false);
		WRITE_ONCE(roce->pio_restarted, true);
		roce->stats.tx_pio_resync++;
	}
	WRITE_ONCE(roce->pio_last_fill, sc->fill);
}

/*
 * Pull returned credits into sc->free, as hfi2_sc_release_update() does, without
 * its sc_piobufavail() call: that would wake every QP parked for credits each
 * time the worker finds the ring still full.  The shadow ring is untouched;
 * this backend never queues to it.  Caller holds sc->alloc_lock.
 */
static void roce_pio_refresh_free(struct send_context *sc)
{
	unsigned long flags;
	u64 hw_free;

	spin_lock_irqsave(&sc->release_lock, flags);
	hw_free = le64_to_cpu(READ_ONCE(*sc->hw_free));
	sc->free += (((hw_free & CR_COUNTER_SMASK) >> CR_COUNTER_SHIFT) -
		     (sc->free & CR_COUNTER_MASK)) & CR_COUNTER_MASK;
	spin_unlock_irqrestore(&sc->release_lock, flags);
}

static void roce_pio_ungate(struct hfi2_dms_roce *roce)
{
	this_cpu_dec(*roce->sc->buffers_allocated);
	preempt_enable();
}

/*
 * Admit one frame into the send context the way hfi2_sc_buffer_alloc() does:
 * check SCF_ENABLED, take the credits and count the writer in
 * buffers_allocated, all under alloc_lock.  hfi2_sc_stop() clears SCF_ENABLED
 * under the same lock, and hfi2_sc_restart() then waits for buffers_allocated to
 * drain before disabling and re-enabling the context, so a frame is never
 * stored into a context that is being reinitialized.  roce_pio_copy_end()
 * drops the count.
 */
static int roce_pio_reserve(struct hfi2_dms_roce *roce, u32 data_qws,
			    struct roce_pio_copy *copy)
{
	struct hfi2_dms_roce_stats *st = &roce->stats;
	struct send_context *sc = roce->sc;
	u32 interval = READ_ONCE(roce_pio_credit_return_interval);
	u32 total_qws = data_qws + 1;
	u32 blocks = DIV_ROUND_UP(total_qws, ROCE_PIO_QWS_PER_BLOCK);
	unsigned long flags;
	bool credit_return;
	u64 outstanding;
	u32 fill_wrap;

	spin_lock_irqsave(&sc->alloc_lock, flags);
	roce_pio_note_restart(roce);
	if (!(sc->flags & SCF_ENABLED)) {
		int rc = roce_pio_stopped_rc(sc);

		spin_unlock_irqrestore(&sc->alloc_lock, flags);
		return rc;
	}
	if (blocks > sc->credits - (sc->fill - sc->alloc_free)) {
		roce_pio_refresh_free(sc);
		sc->alloc_free = READ_ONCE(sc->free);
		st->tx_pio_refresh++;
		if (blocks > sc->credits - (sc->fill - sc->alloc_free)) {
			st->tx_pio_eagain++;
			spin_unlock_irqrestore(&sc->alloc_lock, flags);
			return -EAGAIN;
		}
	}

	/*
	 * CYR HAS A00418 §7.2.7: a preemption inside the store sequence can
	 * flush a partially filled write-combining buffer, stalling the block
	 * until some arbitrary later flush.  Hold preemption off for the whole
	 * sequence as pio.c:1581 does for the OPA verbs copy.  Every caller
	 * that sees success here reaches roce_pio_copy_end(), which releases
	 * it together with the buffers_allocated count.
	 */
	preempt_disable();
	this_cpu_inc(*sc->buffers_allocated);
	fill_wrap = sc->fill_wrap;
	sc->fill += blocks;
	sc->fill_wrap += blocks;
	if (sc->fill_wrap >= sc->credits)
		sc->fill_wrap -= sc->credits;
	WRITE_ONCE(roce->pio_last_fill, sc->fill);
	outstanding = sc->fill - sc->alloc_free;
	if (outstanding > st->tx_pio_outstanding_high)
		st->tx_pio_outstanding_high = outstanding;
	credit_return = interval && ++roce->pio_attempts % interval == 0;
	spin_unlock_irqrestore(&sc->alloc_lock, flags);
	copy->roce = roce;
	copy->base = sc->base_addr;
	copy->end = copy->base + sc->size;
	copy->dest = copy->base + fill_wrap * PIO_BLOCK_SIZE + SOP_DISTANCE;
	copy->carry.val64 = 0;
	copy->carry_bytes = 0;
	copy->fence = false;
	copy->credit_return = credit_return;
	return 0;
}

static __always_inline void roce_pio_copy_tail(u8 *dest, const u8 *src,
					       unsigned int nbytes)
{
	switch (nbytes) {
	case 7:
		dest[6] = src[6];
		fallthrough;
	case 6:
		dest[5] = src[5];
		fallthrough;
	case 5:
		dest[4] = src[4];
		fallthrough;
	case 4:
		dest[3] = src[3];
		fallthrough;
	case 3:
		dest[2] = src[2];
		fallthrough;
	case 2:
		dest[1] = src[1];
		fallthrough;
	case 1:
		dest[0] = src[0];
	}
}

static __always_inline void roce_pio_write_qwords(struct roce_pio_copy *copy,
						  const u64 **srcp,
						  unsigned int qwords)
{
	void __iomem *dest = copy->dest;
	const u64 *src = *srcp;

	while (qwords--) {
		writeq(get_unaligned(src), dest);
		src++;
		dest += sizeof(*src);
	}
	copy->dest = dest;
	*srcp = src;
}

static __always_inline void roce_pio_copy_sge(struct roce_pio_copy *copy,
					      const void *from, size_t nbytes)
{
	const u8 *src = from;
	const u64 *qsrc;
	void __iomem *limit;
	unsigned int qwords;
	size_t bytes;

	/*
	 * Complete a partial qword before copying this SGE directly.  Once the
	 * carry is flushed, src is advanced by precisely the appended bytes, so
	 * every remaining qword belongs wholly to this SGE and get_unaligned()
	 * cannot read past its end.
	 */
	if (copy->carry_bytes) {
		bytes = min_t(size_t, nbytes,
			      sizeof(copy->carry.val8) - copy->carry_bytes);
		roce_pio_copy_tail(&copy->carry.val8[copy->carry_bytes], src, bytes);
		copy->carry_bytes += bytes;
		src += bytes;
		nbytes -= bytes;
		if (copy->carry_bytes != sizeof(copy->carry.val8))
			return;

		roce_pio_normalize_span(copy);
		writeq(copy->carry.val64, copy->dest);
		copy->dest += sizeof(u64);
		copy->carry.val64 = 0;
		copy->carry_bytes = 0;
	}

	while (nbytes >= sizeof(u64)) {
		roce_pio_normalize_span(copy);
		limit = copy->spans[copy->span].limit;

		qwords = min_t(size_t, nbytes / sizeof(u64),
			       (limit - copy->dest) / sizeof(u64));
		qsrc = (const u64 *)src;
		roce_pio_write_qwords(copy, &qsrc, qwords);
		src = (const u8 *)qsrc;
		nbytes -= qwords * sizeof(u64);
	}

	if (nbytes) {
		copy->carry.val64 = 0;
		roce_pio_copy_tail(copy->carry.val8, src, nbytes);
		copy->carry_bytes = nbytes;
	}
}

/*
 * Zero-fill @nbytes.  Callers pass a sub-qword tail (BTH pad, 0-3 bytes, and
 * the frame's odd-byte remainder, 0-7), so this is at most one qword per
 * packet.  The unused bytes of @carry are zero by construction, which lets
 * carry extension be a bare advance of carry_bytes rather than copying zero
 * bytes through roce_pio_copy_sge().
 */
static __always_inline void roce_pio_copy_zeroes(struct roce_pio_copy *copy,
					 size_t nbytes)
{
	size_t bytes;

	if (copy->carry_bytes) {
		bytes = min_t(size_t, nbytes,
			      sizeof(copy->carry.val8) - copy->carry_bytes);
		copy->carry_bytes += bytes;
		nbytes -= bytes;
		if (copy->carry_bytes == sizeof(copy->carry.val8)) {
			roce_pio_normalize_span(copy);
			writeq(copy->carry.val64, copy->dest);
			copy->dest += sizeof(u64);
			copy->carry.val64 = 0;
			copy->carry_bytes = 0;
		}
	}

	while (nbytes >= sizeof(u64)) {
		roce_pio_normalize_span(copy);
		writeq(0, copy->dest);
		copy->dest += sizeof(u64);
		nbytes -= sizeof(u64);
	}

	if (nbytes) {
		roce_pio_normalize_span(copy);
		copy->carry.val64 = 0;
		copy->carry_bytes = nbytes;
	}
}

/*
 * Pad out to a whole send block and release the reservation.  The fill loop
 * keys off @dest rather than @written because the one-shot path advances
 * @dest in spans and never touches @written; @dest is ground truth for both
 * paths.  No wrap test is needed -- the ring only wraps on a block boundary,
 * so a partially filled block is always wholly inside the reservation.
 */
static void roce_pio_copy_end(struct roce_pio_copy *copy, bool from_worker)
{
	if (copy->carry_bytes) {
		roce_pio_normalize_span(copy);
		writeq(copy->carry.val64, copy->dest);
		copy->dest += sizeof(u64);
	}
	while ((unsigned long)copy->dest & PIO_BLOCK_MASK) {
		writeq(0, copy->dest);
		copy->dest += sizeof(u64);
	}

	/*
	 * CYR HAS A00418 §7.2.7 does not need an sfence for correctness: the
	 * HFI reassembles arbitrarily reordered qword writes and gates launch
	 * on the PBC plus every block reaching full.  But the HAS's reason a
	 * fence is avoidable is that a *following* packet's write-combining
	 * traffic evicts an earlier packet's prematurely flushed, partially
	 * occupied WC buffer.  MOVDIR64B is a direct store that allocates no WC
	 * buffer, so it stops performing that eviction, while the SOP block is
	 * still filled with 8-byte WC stores (its qword 0 is the PBC, which is
	 * not contiguous with the frame buffer).  A stranded SOP buffer would
	 * then hold the packet back with nothing left to flush it.  So fence
	 * per packet when 64-byte stores are in play; the pure writeq() path
	 * keeps its existing fence-free behavior under
	 * roce_pio_fence_interval.
	 */
	/* An inline producer must flush WC before it can migrate or go idle. */
	if (copy->fence || !from_worker)
		/* Flush the SOP block's WC stores; see above. */
		wmb();
	roce_pio_ungate(copy->roce);
}

/* Only the worker writes plain TX counters; posting CPUs share atomics. */
static inline void roce_tx_stat_add(u64 *worker, atomic64_t *shared, u64 value,
				    bool from_worker)
{
	if (from_worker)
		*worker += value;
	else
		atomic64_add(value, shared);
}

static inline u64 roce_tx_stat_read(const u64 *worker, const atomic64_t *shared)
{
	return READ_ONCE(*worker) + atomic64_read(shared);
}

static int roce_pio_emit(struct hfi2_dms_roce *roce, u64 pbc,
			 const void *data, u32 data_qws, bool *credit_return_out,
			 bool from_worker)
{
	const u64 *src = data;
	struct roce_pio_copy copy;
	u32 total_qws = data_qws + 1;
	bool perf_stats = READ_ONCE(roce_perf_stats);
	void __iomem *dest;
	void __iomem *send;	/* first qword past the SOP block */
	void __iomem *dend;	/* first qword past the packet data */
	size_t sc_size;
	bool blk64;
	u64 start_ns;
	int rc;

	rc = roce_pio_reserve(roce, data_qws, &copy);
	if (rc)
		return rc;
	*credit_return_out = copy.credit_return;
	if (*credit_return_out)
		pbc |= PBC_CREDIT_RETURN;

	if (perf_stats)
		start_ns = ktime_get_ns();

	/*
	 * Split the transfer at the two discontinuities -- the end of the SOP
	 * block and the ring wrap -- so each run in between is contiguous and
	 * can be stored without any per-qword bookkeeping.  Structure follows
	 * pio_copy() in pio_copy.c, which has carried the OPA verbs send path
	 * since 2015; the difference here is qword rather than dword counts
	 * (no dangling u32 case) and the optional 64-byte block store.
	 */
	dest = copy.dest;
	send = dest + PIO_BLOCK_SIZE;
	dend = dest + total_qws * sizeof(u64);
	sc_size = roce->sc->size;
	blk64 = roce_pio_blk64_ready();
	/*
	 * base_addr is at least 64 KB aligned (pio.c: piobase from ioremap_wc()
	 * plus a PIO_ADDR_CONTEXT_SHIFT=16 offset) and every later adjustment
	 * -- pio_fill_wrap * 64, SOP_DISTANCE (16 MB), sc->size (credits * 64)
	 * -- is a multiple of 64, so block starts are 64-byte aligned as
	 * MOVDIR64B requires.  Trip once if that ever stops holding.
	 */
	WARN_ON_ONCE(blk64 && ((unsigned long)dest & PIO_BLOCK_MASK));

	writeq(pbc, dest);
	dest += sizeof(u64);

	if (dend < send) {
		/*
		 * Packet ends strictly inside the SOP block, so SOP space is
		 * never left and the block tail is padded through the SOP
		 * alias too.  A 64-byte store cannot apply: the PBC already
		 * occupies qword 0, so this block's start is behind us.
		 */
		dest = roce_pio_span(dest, dend, &src, false);
	} else {
		dest = roce_pio_span(dest, send, &src, false);
		/* Leave the SOP alias; the remaining blocks are non-SOP. */
		dest -= SOP_DISTANCE;
		dend -= SOP_DISTANCE;

		if (copy.end <= dend) {
			dest = roce_pio_span(dest, copy.end, &src, blk64);
			dest -= sc_size;
			dend -= sc_size;
		}

		dest = roce_pio_span(dest, dend, &src, blk64);
	}

	copy.dest = dest;
	copy.fence = blk64;
	roce_pio_copy_end(&copy, from_worker);
	if (perf_stats)
		roce_tx_stat_add(&roce->stats.tx_pio_write_ns,
				 &roce->inline_stats.tx_pio_write_ns,
				 ktime_get_ns() - start_ns, from_worker);
	return 0;
}

static void roce_pio_publish(struct hfi2_dms_roce *roce, bool from_worker)
{
	u32 fence_interval = READ_ONCE(roce_pio_fence_interval);
	bool perf_stats = READ_ONCE(roce_perf_stats);
	u64 packet;
	u64 fence_ns;

	if (from_worker)
		packet = ++roce->stats.tx_pkts;
	else
		packet = atomic64_inc_return(&roce->inline_stats.tx_pkts);
	if (!fence_interval || packet % fence_interval)
		return;

	/* Flush this packet's WC stores before a configured batching boundary. */
	if (perf_stats)
		fence_ns = ktime_get_ns();
	/* Pair WC packet stores before crossing the configured batch boundary. */
	wmb();
	if (perf_stats)
		roce_tx_stat_add(&roce->stats.tx_pio_fence_ns,
				 &roce->inline_stats.tx_pio_fence_ns,
				 ktime_get_ns() - fence_ns, from_worker);
	roce_tx_stat_add(&roce->stats.tx_pio_fences,
			 &roce->inline_stats.tx_pio_fences, 1, from_worker);
}

static void roce_tag_count(struct hfi2_dms_roce_qp *rqp,
			   const struct hfi2_qp_priv_roce *priv, bool runt,
			   bool from_worker)
{
	if (runt)
		roce_tx_stat_add(&rqp->roce->stats.tx_runt_tagged,
				 &rqp->roce->inline_stats.tx_runt_tagged, 1, from_worker);
	if (priv->pfc_tag)
		roce_tx_stat_add(&rqp->roce->stats.tx_pfc_tagged,
				 &rqp->roce->inline_stats.tx_pfc_tagged, 1, from_worker);
}

static void roce_build_egress_geometry(struct hfi2_dms_roce_qp *rqp, u8 *buf,
				       size_t roce_len, u64 pbc_flags,
				       u64 *pbc_out, u32 *pio_qws_out)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct eal_egress_header *eh = (struct eal_egress_header *)buf;
	u8 *mac_end = buf + EAL_EGRESS_HDR_BYTES + 2 * ETH_ALEN;
	bool tagged = get_unaligned_be16(mac_end) == ETH_P_8021Q;
	/* PCP maps 1:1 onto a VL (eth_dcb.c); an untagged frame uses VL0. */
	u8 vl = tagged ? get_unaligned_be16(mac_end + 2) >> VLAN_PRIO_SHIFT : 0;
	size_t pio_bytes = EAL_EGRESS_HDR_BYTES + roce_len;
	u32 pio_qws = ROCE_QWORD_ROUND_UP(pio_bytes);
	u32 len_dws = pio_qws * 2;
	u64 pbc;

	eh->q0 = 0;
	eh->q1 = 0;
	EAL_EGRESS_SET_LT(eh, 1);
	EAL_EGRESS_SET_L2(eh, ROCE_PBC_L2);
	EAL_EGRESS_SET_TYPE(eh, EAL_EGRESS_TYPE_ROCEV2);
	EAL_EGRESS_SET_LENGTH(eh, pio_qws);
	EAL_EGRESS_SET_E(eh, ROCE_LSBITS((8 - (pio_bytes & 0x7)) & 0x7, 3));
	EAL_EGRESS_SET_IP_VER(eh, EAL_EGRESS_IP_VER_4);
	EAL_EGRESS_SET_VLAN_TAGS(eh, tagged ? EAL_EGRESS_VLAN_TAGS_1 :
				 EAL_EGRESS_VLAN_TAGS_0);
	EAL_EGRESS_SET_ADD_ICRC(eh, 1);
	EAL_EGRESS_SET_BTH_OFFSET(eh, HFI2_ROCE_IPV4_BTH_OFFSET +
				  (tagged ? VLAN_HLEN : 0));
	EAL_EGRESS_SET_L4(eh, EAL_EGRESS_L4_ETH);
	EAL_EGRESS_SET_PKEY(eh, HFI2_DMS_PKEY);
	EAL_EGRESS_SET_DLID_23_20(eh, ROCE_PBC_DLID_23_20);
	EAL_EGRESS_SET_SLID_23_20(eh, 0xf);
	pbc = roce->pbc_template;
	pbc &= ~(PBC_LENGTH_DWS_SMASK | PBC_VL_SMASK);
	pbc |= (u64)((len_dws + 2) & PBC_LENGTH_DWS_MASK) <<
	       PBC_LENGTH_DWS_SHIFT;
	pbc |= (u64)vl << PBC_VL_SHIFT;
	pbc |= pbc_flags;
	*pbc_out = pbc;
	if (pio_qws_out)
		*pio_qws_out = pio_qws;
}

static int roce_pio_prepare_frame(struct hfi2_dms_roce_qp *rqp, u8 *buf,
				  size_t roce_len, u64 *pbc_out,
				  u32 *pio_qws_out, bool from_worker)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	size_t pio_bytes = EAL_EGRESS_HDR_BYTES + roce_len;
	u32 fail_period;

	if (!_sctxt_active(roce->sc)) {
		roce_tx_stat_add(&roce->stats.tx_pio_fail,
				 &roce->inline_stats.tx_pio_fail, 1, from_worker);
		return roce_pio_stopped_rc(roce->sc);
	}

	roce_build_egress_geometry(rqp, buf, roce_len, 0, pbc_out, pio_qws_out);
	if (*pio_qws_out * 8 > pio_bytes)
		memset(buf + pio_bytes, 0, *pio_qws_out * 8 - pio_bytes);

	if (unlikely(READ_ONCE(roce_fail_tx_pio_once)) &&
	    xchg(&roce_fail_tx_pio_once, false)) {
		roce_tx_stat_add(&roce->stats.tx_pio_fail,
				 &roce->inline_stats.tx_pio_fail, 1, from_worker);
		return -EAGAIN;
	}
	fail_period = READ_ONCE(roce_fail_tx_pio_period);
	if (unlikely(fail_period) &&
	    (u32)atomic_inc_return(&roce->pio_fail_attempts) % fail_period == 0) {
		roce_tx_stat_add(&roce->stats.tx_pio_fail,
				 &roce->inline_stats.tx_pio_fail, 1, from_worker);
		return -EAGAIN;
	}

	return 0;
}

static bool roce_pio_credit_blocked(struct hfi2_dms_roce_qp *rqp,
				    u32 data_qws)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct send_context *sc = roce->sc;
	u32 blocks = DIV_ROUND_UP(data_qws + 1, ROCE_PIO_QWS_PER_BLOCK);
	u64 outstanding = READ_ONCE(sc->fill) - READ_ONCE(sc->alloc_free);

	return blocks > sc->credits - outstanding;
}

static int roce_pio_frame_buf(struct hfi2_dms_roce_qp *rqp, u8 *buf,
			      size_t roce_len, bool from_worker)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	bool credit_return;
	u32 pio_qws;
	u64 pbc;
	int rc;

	rc = roce_pio_prepare_frame(rqp, buf, roce_len, &pbc, &pio_qws,
				    from_worker);
	if (rc)
		return rc;
	rc = roce_pio_emit(roce, pbc, buf, pio_qws, &credit_return, from_worker);
	if (rc) {
		roce_tx_stat_add(&roce->stats.tx_pio_fail,
				 &roce->inline_stats.tx_pio_fail, 1, from_worker);
		if (rc == -ECOMM || rc == -ENOSPC)
			return rc;
		return roce_pio_credit_blocked(rqp, pio_qws) ? -ENOSPC : -EAGAIN;
	}

	roce_pio_publish(roce, from_worker);
	if (roce_frame_vlan_tagged(buf))
		roce_tx_stat_add(&roce->stats.tx_vlan_tagged,
				 &roce->inline_stats.tx_vlan_tagged, 1, from_worker);
	if (credit_return)
		roce_tx_stat_add(&roce->stats.tx_pio_credit_returns,
				 &roce->inline_stats.tx_pio_credit_returns, 1, from_worker);
	return 0;
}

static int roce_pio_frame(struct hfi2_dms_roce_qp *rqp, size_t roce_len,
			  bool from_worker)
{
	return roce_pio_frame_buf(rqp, rqp->txbuf, roce_len, from_worker);
}

static __always_inline int
roce_sge_copy_to_kernel(struct hfi2_dms_roce *roce, void *dest,
			struct rvt_seg src, u32 len)
{
	struct rvt_dev_info *rdi = &roce->dd->verbs_dev.rdi;
	struct rvt_seg dst = rvt_to_kseg(dest, len);
	int ret;

	if (src.type == RVT_MEM_DMABUF_DO) {
		ret = rdi->driver_f.dmabuf_memcpy(dst, rvt_seg_new_len(src, len));
		if (!ret)
			roce->stats.tx_dmabuf_copy += len;
		return ret;
	}
	if (src.type == RVT_MEM_DMABUF)
		dma_buf_begin_cpu_access(src.seg_dmabuf.dmabuf, DMA_FROM_DEVICE);
	memcpy(dest, src.vaddr, len);
	if (src.type == RVT_MEM_DMABUF)
		dma_buf_end_cpu_access(src.seg_dmabuf.dmabuf, DMA_FROM_DEVICE);
	return 0;
}

static int roce_pio_send_frame(struct hfi2_dms_roce_qp *rqp,
			       struct rvt_sge_state *ss, u32 len, u8 pad,
			       size_t frame_len, size_t header_bytes,
			       bool from_worker)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct rvt_sge_state next_ss = *ss;
	struct roce_pio_copy copy;
	size_t pio_bytes = EAL_EGRESS_HDR_BYTES + frame_len;
	u32 pio_qws;
	u32 remaining = len;
	u64 pbc;
	bool credit_return;
	bool perf_stats;
	u64 start_ns;
	u64 payload_ns;
	int rc;

	rc = roce_pio_prepare_frame(rqp, rqp->txbuf, frame_len, &pbc, &pio_qws,
				    from_worker);
	if (rc)
		return rc;
	rc = roce_pio_reserve(roce, pio_qws, &copy);
	if (rc) {
		roce_tx_stat_add(&roce->stats.tx_pio_fail,
				 &roce->inline_stats.tx_pio_fail, 1, from_worker);
		if (rc == -ECOMM || rc == -ENOSPC)
			return rc;
		return roce_pio_credit_blocked(rqp, pio_qws) ? -ENOSPC : -EAGAIN;
	}
	credit_return = copy.credit_return;
	if (credit_return)
		pbc |= PBC_CREDIT_RETURN;

	perf_stats = READ_ONCE(roce_perf_stats);
	if (perf_stats)
		start_ns = ktime_get_ns();
	writeq(pbc, copy.dest);
	copy.dest += sizeof(pbc);
	roce_pio_init_spans(&copy, pio_qws);
	roce_pio_copy_sge(&copy, rqp->txbuf, header_bytes);
	if (perf_stats) {
		payload_ns = ktime_get_ns();
		roce_tx_stat_add(&roce->stats.tx_pio_write_ns,
				 &roce->inline_stats.tx_pio_write_ns, payload_ns - start_ns,
				 from_worker);
	}
	while (remaining) {
		u32 slen = rvt_get_sge_length(&next_ss.sge, remaining);

		roce_pio_copy_sge(&copy, next_ss.sge.mem.vaddr, slen);
		roce_advance_sge(&next_ss, slen);
		remaining -= slen;
	}
	roce_pio_copy_zeroes(&copy, pad);
	if (perf_stats) {
		start_ns = ktime_get_ns();
		roce_tx_stat_add(&roce->stats.tx_payload_copy_ns,
				 &roce->inline_stats.tx_payload_copy_ns,
				 start_ns - payload_ns,
				 from_worker);
	}
	roce_pio_copy_zeroes(&copy, pio_qws * sizeof(u64) - pio_bytes);
	roce_pio_copy_end(&copy, from_worker);
	if (perf_stats)
		roce_tx_stat_add(&roce->stats.tx_pio_write_ns,
				 &roce->inline_stats.tx_pio_write_ns,
				 ktime_get_ns() - start_ns, from_worker);

	*ss = next_ss;
	roce_pio_publish(roce, from_worker);
	if (roce_frame_vlan_tagged(rqp->txbuf))
		roce_tx_stat_add(&roce->stats.tx_vlan_tagged,
				 &roce->inline_stats.tx_vlan_tagged, 1, from_worker);
	if (credit_return)
		roce_tx_stat_add(&roce->stats.tx_pio_credit_returns,
				 &roce->inline_stats.tx_pio_credit_returns, 1, from_worker);
	return 0;
}

/* Constant-size copies so the common untagged prefix stays inline. */
static __always_inline void roce_copy_prefix(u8 *dst, const u8 *src,
					     size_t bth_offset)
{
	dst += EAL_EGRESS_HDR_BYTES;
	src += EAL_EGRESS_HDR_BYTES;
	if (likely(bth_offset == HFI2_ROCE_IPV4_BTH_OFFSET))
		memcpy(dst, src, HFI2_ROCE_IPV4_BTH_OFFSET + HFI2_ROCE_BTH_BYTES);
	else
		memcpy(dst, src, HFI2_ROCE_IPV4_BTH_OFFSET + VLAN_HLEN +
		       HFI2_ROCE_BTH_BYTES);
}

static int roce_build_send_frame(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_qp_priv_roce *priv,
				 struct rvt_sge_state *ss, u32 len,
				 bool first, bool last, bool direct_gather,
				 u32 psn, u8 *frame_buf, size_t frame_buf_sz,
				 size_t *frame_len_out, size_t *header_bytes_out,
				 u8 *opcode_out, u8 *pad_out, bool from_worker)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	bool write = roce_req_is_write(rqp->tx_opcode);
	bool with_imm = last && roce_req_has_imm(rqp->tx_opcode);
	bool with_inv = last && roce_req_has_inv(rqp->tx_opcode);
	bool middle = !first && !last;
	bool perf_stats = READ_ONCE(roce_perf_stats);
	u8 opcode = write ? roce_write_opcode(first, last, with_imm) :
			    roce_send_opcode(first, last, with_imm, with_inv);
	u8 *bth, *imm_or_payload;
	size_t ext_len = roce_req_ext_len(rqp->tx_opcode, first, last);
	size_t bth_offset, ib_len, frame_len;
	u64 start_ns;
	u8 pad;

	/* BTH PadCount: see roce_unpadded. */
	pad = roce_bth_pad(len);
	roce_tx_addr_vlan(&addr, priv, ext_len, len, pad);
	bth_offset = hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	/* ib_len: BTH..pad (no ICRC).  frame_len: full frame Eth..pad (no ICRC). */
	ib_len = HFI2_ROCE_BTH_BYTES + ext_len + len + pad;
	frame_len = bth_offset + ib_len;

	if ((frame_buf == rqp->txbuf || !direct_gather) &&
	    EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES > frame_buf_sz)
		return -EMSGSIZE;
	if (direct_gather && frame_buf != rqp->txbuf &&
	    EAL_EGRESS_HDR_BYTES + bth_offset + HFI2_ROCE_BTH_BYTES +
	    ext_len + pad > frame_buf_sz)
		return -EMSGSIZE;

	bth = frame_buf + EAL_EGRESS_HDR_BYTES + bth_offset;
	if (middle && rqp->tx_middle_prefix_valid) {
		/*
		 * Across a burst's MIDDLE packets only BTH word 2 changes.  Keep
		 * the invariant Ethernet-through-BTH prefix (tag included) in
		 * txbuf so both PIO and separately mapped SDMA command pages
		 * consume one template.
		 */
		if (frame_buf != rqp->txbuf)
			roce_copy_prefix(frame_buf, rqp->txbuf, bth_offset);
		((__be32 *)bth)[2] = cpu_to_be32(roce_psn(psn));
		imm_or_payload = bth + HFI2_ROCE_BTH_BYTES;
	} else {
		u8 *prefix_buf = middle ? rqp->txbuf : frame_buf;
		u8 *prefix_bth = prefix_buf + EAL_EGRESS_HDR_BYTES + bth_offset;
		u8 *prefix_ext;

		if (perf_stats)
			start_ns = ktime_get_ns();

		ether_addr_copy(addr.smac, priv->smac);
		ether_addr_copy(addr.dmac, priv->dmac);

		/* Headers: EAL(16) + Eth/IP/UDP.  IP/UDP lengths include the ICRC. */
		hfi2_roce_build_eth_ipv4_udp(prefix_buf + EAL_EGRESS_HDR_BYTES,
					     &addr,
					     ib_len + HFI2_ROCE_ICRC_BYTES);

		/*
		 * Stage 1 uses the default partition.  AckReq goes on the last
		 * packet, and so does SE for a SEND or WRITE with immediate
		 * (IBA 9.2.3): the only messages that complete a receive WQE.
		 */
		hfi2_roce_build_bth(prefix_bth, opcode, IB_DEFAULT_PKEY_FULL,
				    priv->dest_qpn, last,
				    last && rqp->tx_solicited && (!write || with_imm),
				    pad, roce_psn(psn));

		prefix_ext = prefix_bth + HFI2_ROCE_BTH_BYTES;
		if (write && first) {
			hfi2_roce_build_reth(prefix_ext, rqp->tx_remote_addr,
					     rqp->tx_rkey, rqp->tx_length);
			prefix_ext += HFI2_ROCE_RETH_BYTES;
		}
		if (with_imm)
			*(__be32 *)prefix_ext = rqp->tx_imm_data;
		else if (with_inv)
			((struct ib_other_headers *)prefix_bth)->u.ieth =
				cpu_to_be32(rqp->tx_invalidate_rkey);
		/*
		 * A MIDDLE segment is always a full path MTU and therefore pad
		 * 0.  Build its burst template in txbuf even when the consumer is
		 * an SDMA command page, then copy the prefix to that page.
		 */
		if (middle) {
			rqp->tx_middle_prefix_valid = true;
			if (frame_buf != rqp->txbuf)
				roce_copy_prefix(frame_buf, rqp->txbuf, bth_offset);
			bth = frame_buf + EAL_EGRESS_HDR_BYTES + bth_offset;
		}
		imm_or_payload = bth + HFI2_ROCE_BTH_BYTES;
		if (perf_stats)
			roce_tx_stat_add(&rqp->roce->stats.tx_header_ns,
					 &rqp->roce->inline_stats.tx_header_ns,
					 ktime_get_ns() - start_ns, from_worker);
	}

	if (!direct_gather) {
		u8 *payload = imm_or_payload + ext_len;
		u32 remaining = len;

		if (perf_stats)
			start_ns = ktime_get_ns();
		while (remaining) {
			u32 slen = rvt_get_sge_length(&ss->sge, remaining);
			int rc;

			rc = roce_sge_copy_to_kernel(rqp->roce, payload, ss->sge.mem,
						     slen);
			if (rc)
				return rc;
			payload += slen;
			roce_advance_sge(ss, slen);
			remaining -= slen;
		}
		if (pad)
			memset(payload, 0, pad);
		if (perf_stats)
			roce_tx_stat_add(&rqp->roce->stats.tx_payload_copy_ns,
					 &rqp->roce->inline_stats.tx_payload_copy_ns,
					 ktime_get_ns() - start_ns, from_worker);
	}

	*header_bytes_out = (u8 *)imm_or_payload - frame_buf + ext_len;
	if (addr.vlan_id != HFI2_ROCE_NO_VLAN)
		roce_tag_count(rqp, priv, roce_is_runt(ext_len, len, pad),
			       from_worker);
	*frame_len_out = frame_len;
	*opcode_out = opcode;
	*pad_out = pad;
	return 0;
}

static u32 roce_sdma_command_pad(u32 header_bytes, u32 payload_bytes,
				  u8 bth_pad)
{
	u32 pio_bytes = header_bytes + payload_bytes + bth_pad;

	/*
	 * The command page owns both the logical BTH pad and the physical zero
	 * tail implied by EAL's qword-rounded LENGTH.  Payload bytes come from
	 * the provider, so exclude them and the header from the returned suffix.
	 */
	return ROCE_QWORD_ROUND_UP(pio_bytes) * sizeof(u64) -
		header_bytes - payload_bytes;
}

static int
roce_sdma_bundle_account(struct hfi2_dms_roce_qp *rqp,
			 u16 descriptor_budget,
			 struct hfi2_bulksvc_verbs_source *source,
			 struct hfi2_dms_page *const *command_pages,
			 u64 offset, u32 length, u32 pmtu, bool read_response,
			 bool read_response_write, bool read_response_reth_every,
			 u16 *packets_out, u16 *descs_out)
{
	struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(rqp->roce->svc);
	const struct hfi2_qp_priv_roce *priv = to_roce_priv(rqp->qp);
	u32 actual_descriptors;
	u32 descs = 0;
	u16 packet;

	if (!pmtu && length)
		return -EINVAL;
	for (packet = 0; packet < *packets_out &&
	     (offset < length || (!length && !packet)); packet++) {
		u32 seg = length ? min_t(u64, length - offset, pmtu) : 0;
		u32 remaining = seg;
		u64 run_offset = offset;
		bool first = !offset;
		bool last = offset + seg >= length;
		u8 ext_len = read_response ?
			(read_response_write ?
			 ((read_response_reth_every || first) ?
			  HFI2_ROCE_RETH_BYTES : 0) :
			 (first || last ? HFI2_ROCE_AETH_BYTES : 0)) :
			roce_req_ext_len(rqp->tx_opcode, first, last);
		u8 bth_pad = roce_bth_pad(seg);
		u16 vlan_id = roce_tx_vlan_id(priv, ext_len, seg, bth_pad);
		u32 header_bytes = EAL_EGRESS_HDR_BYTES +
			hfi2_roce_ipv4_bth_offset(vlan_id) +
			HFI2_ROCE_BTH_BYTES + ext_len;
		u32 command_pad = roce_sdma_command_pad(header_bytes, seg,
							bth_pad);
		u32 packet_descs = hfi2_dms_sdma_fragment_desc_count(dms,
				command_pages[packet]->mem.phys_addr,
				sizeof(u64) + header_bytes + (!seg ? command_pad : 0));

		while (remaining) {
			struct hfi2_dms_run run;
			u64 run_bytes;
			u64 consumed;
			int rc;

			rc = source->provider.next_src_run(&source->provider, run_offset,
						  remaining, &run);
			if (rc || !run.run_bytes || !run.dma_pages)
				return rc ? rc : -EINVAL;
			run_bytes = min_t(u64, remaining, run.run_bytes);
			consumed = run_bytes;
			while (run_bytes) {
				u32 page_bytes = min_t(u64, run_bytes,
							PAGE_SIZE - run.page_offset);

				packet_descs += hfi2_dms_sdma_fragment_desc_count(dms,
						run.dma_pages[0] + run.page_offset,
						page_bytes);
				run_bytes -= page_bytes;
				run.page_offset = 0;
				run.dma_pages++;
			}
			run_offset += consumed;
			remaining -= consumed;
		}
		if (seg && command_pad)
			packet_descs += hfi2_dms_sdma_fragment_desc_count(dms,
				command_pages[packet]->mem.phys_addr + sizeof(u64) +
				header_bytes, command_pad);
		actual_descriptors = hfi2_dms_sdma_run_desc_count(dms,
							 descs + packet_descs);
		if (actual_descriptors <= descriptor_budget) {
			descs += packet_descs;
			offset = run_offset;
			continue;
		}
		if (!packet)
			return -E2BIG;
		break;
	}

	*packets_out = packet;
	*descs_out = hfi2_dms_sdma_run_desc_count(dms, descs);
	return packet ? 0 : -E2BIG;
}

static bool roce_sdma_one_pass_ok(struct hfi2_dms_roce *roce,
				  const struct rvt_swqe *wqe)
{
	return READ_ONCE(roce_sdma_one_pass) && wqe->wr.num_sge <= 1 &&
		hfi2_bulksvc_primary_dms(roce->svc)->chip_type != CHIP_JKR;
}

/*
 * One-pass sizing: reserve a worst-case descriptor count instead of walking
 * the source twice, then trim the reservation to what the emit loop actually
 * produced, before commit.  The bound holds only where every fragment is
 * one descriptor, which roce_sdma_one_pass_ok() guarantees: CYR has no
 * 256-byte split, a page piece is below the descriptor byte limit, and a
 * single SGE adds no fragment boundaries beyond the pages it spans.  Per
 * packet that is the header, at most DIV_ROUND_UP(pmtu, PAGE_SIZE) + 1 page
 * pieces, and the pad.
 */
static int roce_sdma_bundle_bound(struct hfi2_dms_roce *roce,
				  u16 descriptor_budget, u32 pmtu,
				  u16 *packets_out, u16 *descs_out)
{
	struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(roce->svc);
	u32 per_packet = DIV_ROUND_UP(pmtu, PAGE_SIZE) + 3;
	u16 packets = *packets_out;

	while (packets &&
	       hfi2_dms_sdma_run_desc_count(dms, packets * per_packet) >
	       descriptor_budget)
		packets--;
	if (!packets)
		return -E2BIG;
	*packets_out = packets;
	*descs_out = hfi2_dms_sdma_run_desc_count(dms, packets * per_packet);
	return 0;
}

/* Return the unused part of a one-pass reservation to the engine. */
static int roce_sdma_cookie_trim(struct hfi2_dms_roce_sdma_cookie *cookie,
				 struct hfi2_dms_sdma_batch *batch)
{
	struct hfi2_dms_roce *roce = cookie->rqp->roce;
	struct hfi2_dms_roce_sdma_engine *engine =
		&roce->sdma_engines[cookie->engine_idx];
	u32 actual = hfi2_dms_sdma_run_desc_count(hfi2_bulksvc_primary_dms(roce->svc),
						  hfi2_dms_sdma_batch_ndesc(batch));
	u16 unused;

	if (WARN_ON_ONCE(!actual || actual > cookie->descriptor_count))
		return -EOVERFLOW;
	unused = cookie->descriptor_count - actual;
	cookie->descriptor_count = actual;
	engine->descriptor_used -= unused;
	roce->stats.admitted_descriptors_current -= unused;
	return 0;
}


/*
 * A source provider can only describe a pageset-backed user MR.  Kernel MRs
 * are CPU-addressable but have no pageset, so copy their payload into the
 * coherent command pages and emit it as ordinary SDMA fragments.
 */
static bool roce_sdma_kernel_sges(const struct rvt_sge *sges, u32 num_sge)
{
	u32 i;

	for (i = 0; i < num_sge; i++) {
		if (sges[i].sge_length && sges[i].mem.type != RVT_MEM_KERNEL)
			return false;
	}
	return true;
}

static __always_inline bool
roce_ss_kernel_sges(const struct rvt_sge_state *ss)
{
	struct rvt_sge sge = ss->sge;
	struct rvt_sge *sg_list = ss->sg_list;
	u8 num_sge = ss->num_sge;

	while (num_sge--) {
		if (sge.mem.type != RVT_MEM_KERNEL)
			return false;
		if (num_sge)
			sge = *sg_list++;
	}
	return true;
}

static int roce_sdma_copy_payload(struct hfi2_dms_roce *roce,
				  struct hfi2_dms_sdma_batch *batch,
				  struct hfi2_dms_roce_sdma_cookie *cookie,
				  struct rvt_sge_state *ss, u32 length,
				  enum hfi2_dms_sdma_desc_type final_type)
{
	u16 page_idx = 1;

	while (length) {
		struct hfi2_dms_page *page;
		u32 page_bytes = min_t(u32, length, PAGE_SIZE);
		u32 remaining = page_bytes;
		u8 *payload;
		int rc;

		if (WARN_ON_ONCE(page_idx >= cookie->page_count))
			return -EINVAL;
		page = cookie->pages[page_idx];
		if (WARN_ON_ONCE(!page))
			return -EINVAL;
		payload = page->mem.kvaddr;

		while (remaining) {
			u32 bytes = rvt_get_sge_length(&ss->sge, remaining);

			if (WARN_ON_ONCE(!bytes))
				return -EINVAL;
			rc = roce_sge_copy_to_kernel(roce, payload, ss->sge.mem,
						     bytes);
			if (rc)
				return rc;
			payload += bytes;
			roce_advance_sge(ss, bytes);
			remaining -= bytes;
		}
		hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
					     page_bytes);
		rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
					      page_bytes,
					      page_bytes == length ? final_type :
					      HFI2_DMS_SDMA_DESC_TYPE_MID);
		if (rc)
			return rc;
		length -= page_bytes;
		page_idx++;
	}
	return 0;
}

static int roce_sdma_copy_account(struct hfi2_dms *dms,
				  struct hfi2_dms_page *const *pages,
				  u16 page_count, u32 header_bytes,
				  u32 payload_bytes, u32 command_pad,
				  u16 descriptor_budget, u16 *descs_out)
{
	u32 descriptors;
	u32 remaining = payload_bytes;
	u16 page = 1;

	descriptors = hfi2_dms_sdma_fragment_desc_count(dms,
			pages[0]->mem.phys_addr, sizeof(u64) + header_bytes);
	while (remaining) {
		u32 bytes = min_t(u32, remaining, PAGE_SIZE);

		if (WARN_ON_ONCE(page >= page_count))
			return -EINVAL;
		descriptors += hfi2_dms_sdma_fragment_desc_count(dms,
			pages[page]->mem.phys_addr, bytes);
		remaining -= bytes;
		page++;
	}
	if (command_pad)
		descriptors += hfi2_dms_sdma_fragment_desc_count(dms,
			pages[0]->mem.phys_addr + sizeof(u64) + header_bytes,
			command_pad);
	descriptors = hfi2_dms_sdma_run_desc_count(dms, descriptors);
	if (descriptors > descriptor_budget)
		return -E2BIG;
	*descs_out = descriptors;
	return 0;
}

#define ROCE_SDMA_REQUEST_DESC_RESERVE 8

static int roce_sdma_send_bundle(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_qp_priv_roce *priv,
				 struct rvt_swqe *wqe)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_sdma_batch *batch = NULL;
	struct hfi2_dms_roce_sdma_cookie *cookie;
	struct hfi2_dms_roce_sdma_xfer *new_xfer = NULL;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_bulksvc_verbs_source *source = NULL;
	struct hfi2_bulksvc_verbs_source_segment *segments;
	struct hfi2_dms_page **command_pages = rqp->sdma_command_pages;
	u32 off = rqp->tx_off;
	u32 start_off = off;
	u32 psn = rqp->tx_psn;
	u32 packet_target;
	u32 remaining_packets;
	u16 packet_count;
	u16 candidate_packets;
	u16 descriptor_count;
	u16 descriptor_budget;
	u16 packet;
	u8 engine_idx = rqp->request_engine_idx;
	u32 source_idx;
	u32 copy_pages = 0;
	u16 vlan_packets = 0;
	bool inline_copy;
	bool copy_fallback;
	bool one_pass = false;
	int rc = -EAGAIN;

	/*
	 * WRITE and SEND differ only in the opcode, RETH and immediate data,
	 * which roce_build_send_frame() and roce_sdma_bundle_account() already
	 * derive from tx_opcode.  A zero-length WRITE or SEND is one
	 * header-only packet.  Refusing it here would strand it: once an
	 * earlier WQE has opened an SDMA epoch, the request may not fall back
	 * to PIO until that epoch closes.
	 */
	if ((!roce_req_is_write(rqp->tx_opcode) &&
	     rqp->tx_opcode != IB_WR_SEND &&
	     rqp->tx_opcode != IB_WR_SEND_WITH_IMM &&
	     rqp->tx_opcode != IB_WR_SEND_WITH_INV) ||
	    !rqp->tx_pmtu || (rqp->tx_length && off >= rqp->tx_length))
		return -EOPNOTSUPP;
	if (!roce_request_emitter_select(rqp, HFI2_DMS_ROCE_EMITTER_SDMA,
					 engine_idx))
		return -EAGAIN;
	if (engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines)
		goto abort_unselected;
	engine = &roce->sdma_engines[engine_idx];
	if (!roce_sdma_admit_room(rqp, engine, rqp->sdma_req_holds, 1,
				  ROCE_SDMA_REQUEST_DESC_RESERVE, 1, false)) {
		rc = -EAGAIN;
		goto abort_unselected;
	}
	descriptor_budget = engine->descriptor_cap - engine->descriptor_used;

	xfer = roce_sdma_xfer_lookup(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
				     rqp->tx_wqe_idx, rqp->request_epoch,
				     wqe->wr.opcode, wqe->psn, wqe->lpsn);
	/*
	 * A replay keeps the form of the original: an inline transfer has no
	 * source to gather from.
	 */
	copy_fallback = xfer && xfer->copy_fallback;
	if (xfer)
		inline_copy = rqp->tx_length && !xfer->needs_source &&
			!copy_fallback;
	else
		inline_copy = rqp->tx_length && !off &&
			roce_sdma_kernel_sges(rqp->tx_sges, rqp->tx_num_mrs) &&
			rqp->tx_length <= rqp->tx_pmtu &&
			rqp->tx_length <= READ_ONCE(roce_sdma_inline_bytes);
	if (!xfer) {
		source_idx = roce_sdma_xfer_free(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
						 rqp->tx_wqe_idx);
		if (WARN_ON_ONCE(source_idx == rqp->sdma_xfer_count)) {
			rc = -EINVAL;
			goto abort_unselected;
		}
		new_xfer = &rqp->sdma_xfers[source_idx];
		if (rqp->tx_length && !inline_copy) {
			if (WARN_ON_ONCE(!rqp->sdma_sources ||
					 !rqp->sdma_source_segments)) {
				rc = -EINVAL;
				goto abort_unselected;
			}
			source = &rqp->sdma_sources[source_idx];
			segments = &rqp->sdma_source_segments[source_idx * rqp->tx_max_sge];
			rc = hfi2_bulksvc_verbs_source_provider_init(source, segments,
							     rqp->tx_max_sge,
							     rqp->tx_sges,
							     rqp->tx_num_mrs);
			if (rc == -ENOENT &&
			    roce_sdma_kernel_sges(rqp->tx_sges, rqp->tx_num_mrs)) {
				copy_fallback = true;
				source = NULL;
			} else if (rc) {
				goto abort_source;
			}
		}
	}
	if (copy_fallback || inline_copy)
		roce_tx_sge_sync(rqp);
	packet_target = READ_ONCE(roce_sdma_bundle_packets);
	remaining_packets = max_t(u32, 1, DIV_ROUND_UP(rqp->tx_length - off,
						       rqp->tx_pmtu));
	candidate_packets = min_t(u32, packet_target, remaining_packets);
	candidate_packets = min_t(u16, candidate_packets,
				  engine->page_cap - engine->page_used);
	if (inline_copy || copy_fallback)
		candidate_packets = 1;
	if (copy_fallback) {
		u32 seg = min(rqp->tx_length - off, rqp->tx_pmtu);

		copy_pages = 1 + DIV_ROUND_UP(seg, PAGE_SIZE);
		if (copy_pages > engine->page_cap - engine->page_used) {
			rqp->sdma_stalled = true;
			rc = -EAGAIN;
			goto abort_source;
		}
	}
	/*
	 * The scratch is per-QP and reused across calls, so clear the window
	 * this call may touch.  Without it a short acquire leaves pointers
	 * from an earlier, longer bundle above the break point, and a later
	 * abort would free them a second time.
	 */
	memset(command_pages, 0,
	       (copy_fallback ? copy_pages : candidate_packets) *
	       sizeof(*command_pages));
	for (packet = 0; packet < (copy_fallback ? copy_pages : candidate_packets);
	     packet++) {
		command_pages[packet] = hfi2_dms_page_try_get(hfi2_bulksvc_primary_dms(roce->svc));
		if (!command_pages[packet])
			break;
	}
	if (!packet) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		rc = -EAGAIN;
		goto abort_source;
	}
	candidate_packets = packet;
	if (copy_fallback && candidate_packets != copy_pages) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		rc = -EAGAIN;
		goto abort_pages;
	}
	packet_count = candidate_packets;
	if (copy_fallback) {
		struct rvt_sge_state copy_ss = rqp->tx_ss;
		u32 seg = min(rqp->tx_length - off, rqp->tx_pmtu);
		size_t frame_len;
		size_t header_bytes;
		u8 opcode;
		u8 bth_pad;
		u32 command_pad;

		rc = roce_build_send_frame(rqp, priv, &copy_ss, seg,
					   !off, off + seg >= rqp->tx_length,
					   true, psn,
					   command_pages[0]->mem.kvaddr + sizeof(u64),
					   command_pages[0]->mem.len - sizeof(u64),
					   &frame_len, &header_bytes, &opcode,
					   &bth_pad, true);
		if (rc)
			goto abort_pages;
		command_pad = roce_sdma_command_pad(header_bytes, seg, bth_pad);
		packet_count = 1;
		rc = roce_sdma_copy_account(hfi2_bulksvc_primary_dms(roce->svc), command_pages,
					   copy_pages, header_bytes, seg, command_pad,
					   descriptor_budget, &descriptor_count);
	} else if (!rqp->tx_length || inline_copy) {
		descriptor_count = 1;
		rc = 0;
	} else {
		if (xfer && WARN_ON_ONCE(!xfer->source)) {
			rc = -EINVAL;
			goto abort_pages;
		}
		if (roce_sdma_one_pass_ok(roce, wqe)) {
			rc = roce_sdma_bundle_bound(roce, descriptor_budget,
						    rqp->tx_pmtu, &packet_count,
						    &descriptor_count);
			one_pass = !rc;
		}
		if (!one_pass)
			rc = roce_sdma_bundle_account(rqp, descriptor_budget,
						      xfer ? xfer->source : source,
						      command_pages, off,
						      rqp->tx_length, rqp->tx_pmtu,
						      false, false, false, &packet_count,
						      &descriptor_count);
	}
	if (rc)
		goto abort_pages;
	if (descriptor_count > descriptor_budget) {
		rc = -E2BIG;
		rqp->sdma_stalled = true;
		goto abort_pages;
	}
	for (packet = (copy_fallback ? copy_pages : packet_count);
	     packet < candidate_packets; packet++) {
		hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), command_pages[packet]);
		command_pages[packet] = NULL;
	}
	candidate_packets = copy_fallback ? copy_pages : packet_count;

	cookie = hfi2_dms_roce_sdma_admit(rqp,
					  HFI2_DMS_ROCE_LANE_REQUEST,
					  rqp->tx_wqe_idx, rqp->request_epoch,
					  wqe->wr.opcode, wqe->psn, wqe->lpsn,
				  engine_idx, 1, descriptor_count,
				  copy_fallback ? copy_pages : packet_count,
				  rqp->tx_length && !inline_copy && !copy_fallback,
				  copy_fallback, source, new_xfer);

	if (!cookie) {
		rc = -EAGAIN;
		goto abort_pages;
	}
	xfer = cookie->xfer;
	source = NULL;
	for (packet = 0; packet < (copy_fallback ? copy_pages : packet_count);
	     packet++) {
		cookie->pages[packet] = command_pages[packet];
		command_pages[packet] = NULL;
	}

	if (WARN_ON_ONCE(hfi2_bulksvc_primary_dms(roce->svc)->port_sctxts[rqp->port_idx] !=
			 roce->sc)) {
		roce->stats.sdma_context_mismatch++;
		rc = -EINVAL;
		goto abort_cookie;
	}
	batch = hfi2_dms_sdma_batch_new_nowait(hfi2_bulksvc_primary_dms(roce->svc), rqp->port_idx);
	if (!batch) {
		roce->stats.sdma_batch_stall++;
		rqp->sdma_stalled = true;
		goto abort_cookie;
	}

	for (packet = 0; packet < packet_count; packet++) {
		struct hfi2_dms_page *page = cookie->pages[packet];
		u8 *frame;
		u32 seg = rqp->tx_length ?
			min(rqp->tx_length - off, rqp->tx_pmtu) : 0;
		u32 packet_bytes = seg;
		bool first = off == 0;
		bool last = !rqp->tx_length || off + seg >= rqp->tx_length;
		size_t frame_len;
		size_t header_bytes;
		u8 opcode;
		u8 bth_pad;
		u32 command_pad;
		u64 pbc;

		frame = page->mem.kvaddr + sizeof(pbc);
		if (copy_fallback) {
			struct rvt_sge_state copy_ss = rqp->tx_ss;

			rc = roce_build_send_frame(rqp, priv, &copy_ss, seg, first, last,
					   true, psn, frame,
					   page->mem.len - sizeof(pbc), &frame_len,
					   &header_bytes, &opcode, &bth_pad, true);
			if (rc)
				goto abort_cookie;
			roce_build_egress_geometry(rqp, frame, frame_len, 0, &pbc, NULL);
			if (roce_frame_vlan_tagged(frame))
				vlan_packets++;
			command_pad = roce_sdma_command_pad(header_bytes, seg, bth_pad);
			if (command_pad)
				memset(frame + header_bytes, 0, command_pad);
			*(u64 *)page->mem.kvaddr = pbc;
			rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
					      sizeof(pbc) + header_bytes,
					      HFI2_DMS_SDMA_DESC_TYPE_SOP);
			if (rc)
				goto abort_cookie;
			rc = roce_sdma_copy_payload(roce, batch, cookie, &copy_ss, seg,
					    command_pad ? HFI2_DMS_SDMA_DESC_TYPE_MID :
					    HFI2_DMS_SDMA_DESC_TYPE_EOP);
			if (rc)
				goto abort_cookie;
			if (command_pad) {
				rc = hfi2_dms_sdma_batch_emit(batch,
						      page->mem.phys_addr + sizeof(pbc) +
						      header_bytes, command_pad,
						      HFI2_DMS_SDMA_DESC_TYPE_EOP);
				if (rc)
					goto abort_cookie;
			}
			hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
						     sizeof(pbc) + header_bytes +
						     command_pad);
			off += seg;
			psn = roce_psn(psn + 1);
			roce->stats.tx_sdma_copy_fallback++;
			continue;
		}
		if (inline_copy) {
			struct rvt_sge_state copy_ss = rqp->tx_ss;

			rc = roce_build_send_frame(rqp, priv, &copy_ss, seg,
						   first, last, false, psn,
						   frame,
						   page->mem.len - sizeof(pbc),
						   &frame_len, &header_bytes,
						   &opcode, &bth_pad, true);
			if (rc)
				goto abort_cookie;
			roce_build_egress_geometry(rqp, frame, frame_len, 0,
						   &pbc, NULL);
			if (roce_frame_vlan_tagged(frame))
				vlan_packets++;
			command_pad = roce_sdma_command_pad(header_bytes, seg,
							    bth_pad);
			if (command_pad)
				memset(frame + header_bytes + seg, 0,
				       command_pad);
			*(u64 *)page->mem.kvaddr = pbc;
			rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
						      sizeof(pbc) + header_bytes +
						      seg + command_pad,
						      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
			if (rc)
				goto abort_cookie;
			hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
						      sizeof(pbc) +
						      header_bytes + seg +
						      command_pad);
			off += seg;
			psn = roce_psn(psn + 1);
			roce->stats.tx_sdma_inline++;
			continue;
		}
		if (!first && !last && rqp->tx_middle_cmd_valid) {
			/*
			 * A MIDDLE is a full path MTU with pad 0, AckReq 0 and SE 0,
			 * so PBC length, EAL LENGTH/E, IP total length and checksum,
			 * UDP length and every BTH field but the PSN repeat for the
			 * whole request.  The image carries the zero tail as well.
			 */
			header_bytes = rqp->tx_middle_cmd_hdr;
			command_pad = rqp->tx_middle_cmd_pad;
			memcpy(page->mem.kvaddr, rqp->tx_middle_cmd,
			       sizeof(pbc) + header_bytes + command_pad);
			((__be32 *)(frame + header_bytes))[-1] =
				cpu_to_be32(roce_psn(psn));
			if (rqp->tx_middle_cmd_vlan)
				vlan_packets++;
			pbc = *(u64 *)page->mem.kvaddr;
			roce->stats.tx_sdma_middle_cached++;
			goto emit_header;
		}
		rc = roce_build_send_frame(rqp, priv, NULL, seg, first,
					   last, true, psn, frame,
					   page->mem.len - sizeof(pbc),
					   &frame_len, &header_bytes, &opcode,
					   &bth_pad, true);
		if (rc)
			goto abort_cookie;
		roce_build_egress_geometry(rqp, frame, frame_len, 0, &pbc, NULL);
		if (roce_frame_vlan_tagged(frame))
			vlan_packets++;
		command_pad = roce_sdma_command_pad(header_bytes, packet_bytes,
						    bth_pad);
		if (!packet_bytes && command_pad)
			memset(frame + header_bytes, 0, command_pad);
		*(u64 *)page->mem.kvaddr = pbc;
		if (!first && !last &&
		    sizeof(pbc) + header_bytes + command_pad <=
		    sizeof(rqp->tx_middle_cmd)) {
			memcpy(rqp->tx_middle_cmd, page->mem.kvaddr,
			       sizeof(pbc) + header_bytes);
			memset(rqp->tx_middle_cmd + sizeof(pbc) + header_bytes, 0,
			       command_pad);
			rqp->tx_middle_cmd_hdr = header_bytes;
			rqp->tx_middle_cmd_pad = command_pad;
			rqp->tx_middle_cmd_vlan = roce_frame_vlan_tagged(frame);
			rqp->tx_middle_cmd_valid = true;
		}
emit_header:
		rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
					      sizeof(pbc) + header_bytes +
					      (!packet_bytes ? command_pad : 0),
					      seg ? HFI2_DMS_SDMA_DESC_TYPE_SOP :
					      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
		if (rc)
			goto abort_cookie;
		while (seg) {
			struct hfi2_dms_run run;
			u32 run_bytes;

			rc = xfer->source->provider.next_src_run(&xfer->source->provider,
							    off, seg, &run);
			if (rc || !run.run_bytes || !run.dma_pages) {
				rc = rc ? rc : -EINVAL;
				goto abort_cookie;
			}
			run_bytes = min_t(u64, seg, run.run_bytes);
			while (run_bytes) {
				u32 page_bytes = min_t(u64, run_bytes,
						      PAGE_SIZE - run.page_offset);
				enum hfi2_dms_sdma_desc_type type =
					(!command_pad && page_bytes == seg) ?
					HFI2_DMS_SDMA_DESC_TYPE_EOP :
					HFI2_DMS_SDMA_DESC_TYPE_MID;

				rc = hfi2_dms_sdma_batch_emit(batch,
							      run.dma_pages[0] + run.page_offset,
							      page_bytes, type);
				if (rc)
					goto abort_cookie;
				off += page_bytes;
				seg -= page_bytes;
				run_bytes -= page_bytes;
				run.page_offset = 0;
				run.dma_pages++;
			}
		}
		if (packet_bytes && command_pad) {
			memset(frame + header_bytes, 0, command_pad);
			rc = hfi2_dms_sdma_batch_emit(batch,
						      page->mem.phys_addr +
						      sizeof(pbc) + header_bytes,
						      command_pad,
						      HFI2_DMS_SDMA_DESC_TYPE_EOP);
			if (rc)
				goto abort_cookie;
		}
		hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
					      sizeof(pbc) + header_bytes + command_pad);

		psn = roce_psn(psn + 1);
	}
	if (one_pass) {
		rc = roce_sdma_cookie_trim(cookie, batch);
		if (rc)
			goto abort_cookie;
	}
	rc = hfi2_dms_roce_sdma_commit(cookie, batch, engine_idx);
	if (rc)
		return rc;
	roce->stats.tx_vlan_tagged += vlan_packets;

	rqp->tx_off = off;
	rqp->tx_psn = psn;
	rqp->roce->stats.tx_worker_packets += packet_count;
	rqp->roce->stats.tx_bytes += off - start_off;
	return packet_count;

abort_cookie:
	if (batch)
		hfi2_dms_sdma_batch_abort(batch);
	hfi2_dms_roce_sdma_abort_uncommitted(cookie, rc);
	return rc;
abort_pages:
	for (packet = 0; packet < candidate_packets; packet++) {
		if (command_pages[packet]) {
			hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc),
					  command_pages[packet]);
			command_pages[packet] = NULL;
		}
	}
abort_source:
	if (source)
		hfi2_bulksvc_verbs_source_provider_release(source);
abort_unselected:
	roce_request_emitter_unselect_sdma(rqp);
	return rc;
}

static int roce_send_one_packet(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv,
				struct rvt_sge_state *ss, u32 len,
				bool first, bool last, u32 psn, bool from_worker)
{
	size_t frame_len;
	size_t header_bytes;
	bool direct_gather = READ_ONCE(roce_direct_gather) &&
		roce_ss_kernel_sges(ss);
	u8 opcode, pad;
	int rc;

	rc = roce_build_send_frame(rqp, priv, ss, len, first, last, direct_gather,
			   psn, rqp->txbuf, rqp->txbuf_sz, &frame_len, &header_bytes,
			   &opcode, &pad, from_worker);
	if (rc)
		return rc;


	if (direct_gather)
		rc = roce_pio_send_frame(rqp, ss, len, pad, frame_len,
				 header_bytes, from_worker);
	else
		rc = roce_pio_frame(rqp, frame_len, from_worker);
	if (!rc) {
		roce_tx_stat_add(&rqp->roce->stats.tx_bytes,
				 &rqp->roce->inline_stats.tx_bytes, len, from_worker);
		roce_trace(rqp->dd,
			   "tx SEND op=0x%02x psn=%u qpn=%u len=%u pad=%u\n",
			   opcode, psn, priv->dest_qpn, len, pad);
	}
	return rc;
}

static void roce_advance_read_ack(struct rvt_qp *qp, u8 index)
{
	u8 next = index + 1;

	if (next > rvt_size_atomic(ib_to_rvt(qp->ibqp.device)))
		next = 0;
	if (qp->s_acked_ack_queue == index)
		qp->s_acked_ack_queue = next;
	qp->s_tail_ack_queue = next;
	qp->s_ack_state = OP(ACKNOWLEDGE);
}

static int roce_build_read_response_frame(
		struct hfi2_dms_roce_qp *rqp,
		struct hfi2_qp_priv_roce *priv,
		struct rvt_ack_entry *entry,
		struct hfi2_dms_roce_read_cursor *cursor,
		bool direct_gather,
		u8 *frame_buf, size_t frame_buf_sz,
		struct rvt_sge_state *packet_ss_out,
		u32 *packet_len_out, bool *last_out, size_t *frame_len_out,
		size_t *header_bytes_out, u8 *pad_out, bool *use_alias_out)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	struct hfi2_dms_roce_read_meta *meta;
	struct rvt_sge_state packet_ss;
	u32 remaining, packet_len, bytes_left;
	bool only, first, last, use_alias, reply_write, software_place;
	u8 opcode, *bth, *payload, *payload_start;
	u8 pad;
	size_t ext_len, ib_len, frame_len;

	if (unlikely(cursor->off > entry->rdma_sge.sge_length))
		return -EINVAL;
	meta = &rqp->read_meta[cursor->ack_index];
	reply_write = meta->reply_write;
	software_place = meta->software_place;

	remaining = entry->rdma_sge.sge_length - cursor->off;
	packet_len = min_t(u32, remaining, qp->pmtu);
	only = cursor->off == 0 && packet_len == remaining;
	first = cursor->off == 0;
	last = packet_len == remaining;
	if (reply_write) {
		/*
		 * An unmatched WRITE LAST is delivered header-only as LAST_ERR.
		 * Software replies use WRITE_ONLY with a RETH on every packet,
		 * preserving payload and avoiding MIDDLE_OO trimming.
		 */
		if (software_place)
			opcode = IB_OPCODE_RC_RDMA_WRITE_ONLY;
		else if (only)
			opcode = IB_OPCODE_RC_RDMA_WRITE_ONLY;
		else if (first)
			opcode = IB_OPCODE_RC_RDMA_WRITE_FIRST;
		else if (last)
			opcode = IB_OPCODE_RC_RDMA_WRITE_LAST;
		else
			opcode = IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
	} else if (roce_hwp_write_mode(rqp->roce)) {
		WARN_ON_ONCE(1);
		rqp->roce->stats.tx_hwp_read_resp_bug++;
		return -EINVAL;
	} else if (only) {
		opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
	} else if (first) {
		opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	} else if (last) {
		opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	} else {
		opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
	}

	ext_len = reply_write ?
		  ((software_place || first) ? HFI2_ROCE_RETH_BYTES : 0) :
		  (opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE ? 0 :
		   HFI2_ROCE_AETH_BYTES);

	pad = roce_bth_pad(packet_len);
	if (reply_write)
		addr.vlan_id = roce_tx_vlan_id(priv, ext_len, packet_len, pad);
	ib_len = HFI2_ROCE_BTH_BYTES + ext_len + packet_len + pad;
	frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if ((frame_buf == rqp->txbuf || !direct_gather) &&
	    EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES > frame_buf_sz)
		return -EMSGSIZE;
	if (direct_gather && frame_buf != rqp->txbuf &&
	    EAL_EGRESS_HDR_BYTES + hfi2_roce_ipv4_bth_offset(addr.vlan_id) +
	    HFI2_ROCE_BTH_BYTES + ext_len + pad > frame_buf_sz)
		return -EMSGSIZE;

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(frame_buf + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame_buf + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	use_alias = roce_answer_dest_qpn(rqp, priv) != priv->dest_qpn;
	hfi2_roce_build_bth(bth, opcode, IB_DEFAULT_PKEY_FULL,
			    roce_answer_dest_qpn(rqp, priv), false, false, pad,
			    roce_psn(cursor->psn));
	payload = bth + HFI2_ROCE_BTH_BYTES;
	if (reply_write && (software_place || first)) {
		hfi2_roce_build_reth(payload, meta->dest_va, meta->dest_rkey,
				     entry->rdma_sge.sge_length);
		payload += HFI2_ROCE_RETH_BYTES;
	} else if (ext_len) {
		*(__be32 *)payload = rvt_compute_aeth(qp);
		payload += HFI2_ROCE_AETH_BYTES;
	}
	payload_start = payload;

	/*
	 * The walk runs either way: @packet_ss_out advances the caller's cursor
	 * to the next packet, and a direct-gather build still owes that even
	 * though the payload itself reaches the wire by descriptor rather than
	 * through this copy.
	 */
	packet_ss = cursor->ss;
	for (bytes_left = packet_len; bytes_left; ) {
		u32 slen = rvt_get_sge_length(&packet_ss.sge, bytes_left);
		int rc;

		if (!direct_gather) {
			rc = roce_sge_copy_to_kernel(rqp->roce, payload,
						     packet_ss.sge.mem, slen);
			if (rc)
				return rc;
			payload += slen;
		}
		roce_advance_sge(&packet_ss, slen);
		bytes_left -= slen;
	}
	if (!direct_gather && pad)
		memset(payload, 0, pad);

	*header_bytes_out = payload_start - frame_buf;
	if (addr.vlan_id != HFI2_ROCE_NO_VLAN)
		roce_tag_count(rqp, priv, false, true);
	*packet_ss_out = packet_ss;
	*packet_len_out = packet_len;
	*last_out = last;
	*frame_len_out = frame_len;
	*pad_out = pad;
	if (use_alias_out)
		*use_alias_out = use_alias;
	return 0;
}

static void roce_resp_xfer_abandon(struct hfi2_dms_roce_qp *rqp)
{
	bool abandoned = false;
	unsigned int i;

	for (i = 0; i < rqp->sdma_xfer_count; i++) {
		struct hfi2_dms_roce_sdma_xfer *xfer = &rqp->sdma_xfers[i];

		if (xfer->active && xfer->lane == HFI2_DMS_ROCE_LANE_RESPONDER) {
			xfer->abandoned = true;
			xfer->wire_acked = true;
			roce_sdma_xfer_recycle(xfer);
			abandoned = true;
		}
	}
	if (abandoned) {
		rqp->resp_generation++;
		rqp->roce->stats.tx_sdma_resp_abandon++;
	}
}

static int roce_sdma_send_read_response(struct hfi2_dms_roce_qp *rqp,
					struct hfi2_qp_priv_roce *priv,
					struct rvt_ack_entry *entry,
					struct hfi2_dms_roce_read_cursor *cursor)
{
	struct hfi2_dms_roce_read_meta *meta =
		&rqp->read_meta[cursor->ack_index];
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_sdma_batch *batch = NULL;
	struct hfi2_dms_roce_sdma_cookie *cookie;
	struct hfi2_dms_roce_sdma_xfer *new_xfer = NULL;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_bulksvc_verbs_source *source = NULL;
	struct hfi2_bulksvc_verbs_source *bundle_source;
	struct hfi2_bulksvc_verbs_source_segment *segments;
	struct hfi2_dms_page **command_pages = rqp->sdma_command_pages;
	struct rvt_sge_state next_ss = cursor->ss;
	u32 off = cursor->off;
	u32 psn = cursor->psn;
	u32 start_off = off;
	u32 packet_target;
	u32 remaining_packets;
	u16 candidate_packets;
	u16 packet_count;
	u16 descriptor_count;
	u16 descriptor_budget;
	u16 alias_packets = 0;
	u16 alias_skip_packets = 0;
	u16 packet;
	u8 engine_idx = rqp->request_engine_idx;
	u32 source_idx;
	u32 copy_pages = 0;
	u16 vlan_packets = 0;
	bool copy_fallback;
	int rc = -EAGAIN;

	if (engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines) {
		roce->stats.tx_sdma_read_resp_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	engine = &roce->sdma_engines[engine_idx];
	if (!roce_sdma_admit_room(rqp, engine, rqp->sdma_resp_holds,
				  1, 1, 1, false)) {
		roce->stats.tx_sdma_read_resp_stall++;
		return -EAGAIN;
	}
	descriptor_budget = engine->descriptor_cap - engine->descriptor_used;

	xfer = roce_sdma_xfer_lookup(rqp, HFI2_DMS_ROCE_LANE_RESPONDER,
				     cursor->ack_index, rqp->resp_generation,
				     IB_WR_RDMA_READ, entry->psn, entry->lpsn);
	copy_fallback = xfer && xfer->copy_fallback;
	if (!xfer) {
		source_idx = roce_sdma_xfer_free(rqp, HFI2_DMS_ROCE_LANE_RESPONDER,
						 cursor->ack_index);
		if (WARN_ON_ONCE(source_idx == rqp->sdma_xfer_count)) {
			roce->stats.tx_sdma_read_resp_stall++;
			rqp->sdma_stalled = true;
			return -EAGAIN;
		}
		new_xfer = &rqp->sdma_xfers[source_idx];
		if (entry->rdma_sge.sge_length) {
			if (WARN_ON_ONCE(!rqp->sdma_sources ||
					 !rqp->sdma_source_segments)) {
				rc = -EINVAL;
				goto abort_unselected;
			}
			source = &rqp->sdma_sources[source_idx];
			segments = &rqp->sdma_source_segments[
				source_idx * rqp->tx_max_sge];
			rc = hfi2_bulksvc_verbs_source_provider_init(source, segments, 1,
							     &cursor->ss.sge, 1);
			if (rc == -ENOENT &&
			    cursor->ss.sge.mem.type == RVT_MEM_KERNEL) {
				copy_fallback = true;
				source = NULL;
			} else if (rc) {
				goto abort_source;
			}
		}
	}

	packet_target = READ_ONCE(roce_sdma_bundle_packets);
	remaining_packets = entry->rdma_sge.sge_length ?
		DIV_ROUND_UP(entry->rdma_sge.sge_length - off, rqp->qp->pmtu) : 1;
	candidate_packets = min_t(u32, packet_target, remaining_packets);
	candidate_packets = min_t(u16, candidate_packets,
				  engine->page_cap - engine->page_used);
	if (copy_fallback) {
		u32 packet_len = min_t(u64, entry->rdma_sge.sge_length - off,
				       rqp->qp->pmtu);

		copy_pages = 1 + DIV_ROUND_UP(packet_len, PAGE_SIZE);
		if (copy_pages > engine->page_cap - engine->page_used) {
			rqp->sdma_stalled = true;
			rc = -EAGAIN;
			goto abort_source;
		}
		candidate_packets = 1;
	}
	memset(command_pages, 0,
	       (copy_fallback ? copy_pages : candidate_packets) *
	       sizeof(*command_pages));
	for (packet = 0; packet < (copy_fallback ? copy_pages : candidate_packets);
	     packet++) {
		command_pages[packet] = hfi2_dms_page_try_get(hfi2_bulksvc_primary_dms(roce->svc));
		if (!command_pages[packet])
			break;
	}
	if (!packet) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		goto abort_source;
	}
	candidate_packets = packet;
	if (copy_fallback && candidate_packets != copy_pages) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		rc = -EAGAIN;
		goto abort_pages;
	}
	packet_count = candidate_packets;
	if (copy_fallback) {
		struct hfi2_dms_roce_read_cursor packet_cursor = {
			.ss = next_ss,
			.psn = psn,
			.off = off,
			.ack_index = cursor->ack_index,
			.valid = true,
		};
		struct rvt_sge_state packet_ss;
		u32 packet_len;
		bool last;
		bool use_alias;
		size_t frame_len;
		size_t header_bytes;
		u8 pad;
		u32 command_pad;

		rc = roce_build_read_response_frame(rqp, priv, entry, &packet_cursor,
						    true,
						    command_pages[0]->mem.kvaddr +
						    sizeof(u64),
					    command_pages[0]->mem.len - sizeof(u64),
					    &packet_ss, &packet_len, &last,
					    &frame_len, &header_bytes, &pad, &use_alias);

		if (rc)
			goto abort_pages;
		if (use_alias)
			alias_packets++;
		else if (roce_hwp_write_mode(roce))
			alias_skip_packets++;
		command_pad = roce_sdma_command_pad(header_bytes, packet_len, pad);
		packet_count = 1;
		rc = roce_sdma_copy_account(hfi2_bulksvc_primary_dms(roce->svc), command_pages,
					   copy_pages, header_bytes, packet_len,
					   command_pad, descriptor_budget,
					   &descriptor_count);
	} else if (entry->rdma_sge.sge_length) {
		if (xfer && WARN_ON_ONCE(!xfer->source)) {
			rc = -EINVAL;
			goto abort_pages;
		}
		bundle_source = xfer ? xfer->source : source;
		rc = roce_sdma_bundle_account(rqp, descriptor_budget,
					      bundle_source, command_pages, off,
					      entry->rdma_sge.sge_length, rqp->qp->pmtu,
					      true, meta->reply_write, meta->software_place,
					      &packet_count, &descriptor_count);
	} else {
		descriptor_count = 1;
	}
	if (rc)
		goto abort_pages;
	if (descriptor_count > descriptor_budget) {
		rc = -E2BIG;
		rqp->sdma_stalled = true;
		goto abort_pages;
	}
	for (packet = (copy_fallback ? copy_pages : packet_count);
	     packet < candidate_packets; packet++) {
		hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), command_pages[packet]);
		command_pages[packet] = NULL;
	}
	candidate_packets = copy_fallback ? copy_pages : packet_count;

	cookie = hfi2_dms_roce_sdma_admit(rqp, HFI2_DMS_ROCE_LANE_RESPONDER,
					  cursor->ack_index, rqp->resp_generation,
					  IB_WR_RDMA_READ, entry->psn, entry->lpsn,
			  engine_idx, 1, descriptor_count,
			  copy_fallback ? copy_pages : packet_count,
			  entry->rdma_sge.sge_length != 0 && !copy_fallback,
			  copy_fallback, source, new_xfer);
	if (!cookie)
		goto abort_pages;
	xfer = cookie->xfer;
	if (cookie->xfer_new && entry->rdma_sge.sge_length)
		roce_sdma_xfer_hold_mr(xfer, entry->rdma_sge.mr);
	source = NULL;
	for (packet = 0; packet < (copy_fallback ? copy_pages : packet_count);
	     packet++) {
		cookie->pages[packet] = command_pages[packet];
		command_pages[packet] = NULL;
	}

	if (WARN_ON_ONCE(hfi2_bulksvc_primary_dms(roce->svc)->port_sctxts[rqp->port_idx] !=
			 roce->sc)) {
		roce->stats.sdma_context_mismatch++;
		rc = -EINVAL;
		goto abort_cookie;
	}
	batch = hfi2_dms_sdma_batch_new_nowait(hfi2_bulksvc_primary_dms(roce->svc), rqp->port_idx);
	if (!batch) {
		roce->stats.sdma_batch_stall++;
		rqp->sdma_stalled = true;
		goto abort_cookie;
	}

	for (packet = 0; packet < packet_count; packet++) {
		struct hfi2_dms_page *page = cookie->pages[packet];
		struct hfi2_dms_roce_read_cursor packet_cursor;
		struct rvt_sge_state copy_ss;
		struct rvt_sge_state packet_ss;
		u8 *frame = page->mem.kvaddr + sizeof(u64);
		u32 packet_len;
		u32 remaining;
		bool last;
		size_t frame_len;
		size_t header_bytes;
		u8 pad;
		u32 command_pad;
		u64 pbc;
		bool use_alias;
		bool middle;
		bool cached;

		/*
		 * A WRITE MIDDLE of a response is a full path MTU with no RETH
		 * and pad 0, so everything but the BTH PSN repeats for the
		 * response; only the payload walk is still owed.
		 */
		middle = meta->reply_write && !meta->software_place &&
			 !copy_fallback && off &&
			 entry->rdma_sge.sge_length - off > rqp->qp->pmtu;
		cached = middle && rqp->resp_middle_valid &&
			 rqp->resp_middle_ack_index == cursor->ack_index &&
			 rqp->resp_middle_generation == rqp->resp_generation &&
			 rqp->resp_middle_psn == entry->psn;
		if (cached) {
			u32 bytes_left;

			header_bytes = rqp->resp_middle_hdr;
			command_pad = rqp->resp_middle_pad;
			memcpy(page->mem.kvaddr, rqp->resp_middle_cmd,
			       sizeof(pbc) + header_bytes + command_pad);
			((__be32 *)(frame + header_bytes))[-1] =
				cpu_to_be32(roce_psn(psn));
			packet_len = rqp->qp->pmtu;
			for (bytes_left = packet_len; bytes_left; ) {
				u32 slen = rvt_get_sge_length(&next_ss.sge,
							      bytes_left);

				roce_advance_sge(&next_ss, slen);
				bytes_left -= slen;
			}
			use_alias = rqp->resp_middle_alias;
			pbc = *(u64 *)page->mem.kvaddr;
			if (roce_frame_vlan_tagged(frame)) {
				vlan_packets++;
				roce_tag_count(rqp, priv, false, true);
			}
			roce->stats.tx_read_resp_middle_cached++;
		} else {
			packet_cursor = (struct hfi2_dms_roce_read_cursor) {
				.ss = next_ss,
				.psn = psn,
				.off = off,
				.ack_index = cursor->ack_index,
				.valid = true,
			};
			if (copy_fallback)
				copy_ss = next_ss;
			rc = roce_build_read_response_frame(rqp, priv, entry,
							    &packet_cursor, true, frame,
							    page->mem.len - sizeof(pbc),
							    &packet_ss, &packet_len,
							    &last, &frame_len,
							    &header_bytes, &pad,
							    &use_alias);
			if (rc)
				goto abort_cookie;
			roce_build_egress_geometry(rqp, frame, frame_len, 0,
						   &pbc, NULL);
			if (roce_frame_vlan_tagged(frame))
				vlan_packets++;
			command_pad = roce_sdma_command_pad(header_bytes,
							    packet_len, pad);
			if (!packet_len && command_pad)
				memset(frame + header_bytes, 0, command_pad);
			*(u64 *)page->mem.kvaddr = pbc;
			rqp->resp_middle_valid = false;
			if (middle && !pad && packet_len == rqp->qp->pmtu &&
			    sizeof(pbc) + header_bytes + command_pad <=
			    sizeof(rqp->resp_middle_cmd)) {
				memcpy(rqp->resp_middle_cmd, page->mem.kvaddr,
				       sizeof(pbc) + header_bytes);
				memset(rqp->resp_middle_cmd + sizeof(pbc) +
				       header_bytes, 0, command_pad);
				rqp->resp_middle_hdr = header_bytes;
				rqp->resp_middle_pad = command_pad;
				rqp->resp_middle_alias = use_alias;
				rqp->resp_middle_ack_index = cursor->ack_index;
				rqp->resp_middle_generation = rqp->resp_generation;
				rqp->resp_middle_psn = entry->psn;
				rqp->resp_middle_valid = true;
			}
		}
		if (use_alias)
			alias_packets++;
		else if (roce_hwp_write_mode(roce))
			alias_skip_packets++;
		rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
					      sizeof(pbc) + header_bytes +
					      (!packet_len ? command_pad : 0),
					      packet_len ? HFI2_DMS_SDMA_DESC_TYPE_SOP :
					      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
		if (rc)
			goto abort_cookie;
		if (copy_fallback) {
			rc = roce_sdma_copy_payload(roce, batch, cookie, &copy_ss,
					    packet_len,
					    command_pad ? HFI2_DMS_SDMA_DESC_TYPE_MID :
					    HFI2_DMS_SDMA_DESC_TYPE_EOP);
			if (rc)
				goto abort_cookie;
			next_ss = copy_ss;
			off += packet_len;
			if (command_pad) {
				memset(frame + header_bytes, 0, command_pad);
				rc = hfi2_dms_sdma_batch_emit(batch,
							      page->mem.phys_addr + sizeof(pbc) +
							      header_bytes, command_pad,
							      HFI2_DMS_SDMA_DESC_TYPE_EOP);
				if (rc)
					goto abort_cookie;
			}
			roce->stats.tx_sdma_copy_fallback++;
			remaining = 0;
		} else {
			remaining = packet_len;
		}
		while (remaining) {
			struct hfi2_dms_run run;
			u32 run_bytes;

			rc = xfer->source->provider.next_src_run(&xfer->source->provider,
								 off, remaining, &run);
			if (rc || !run.run_bytes || !run.dma_pages) {
				rc = rc ? rc : -EINVAL;
				goto abort_cookie;
			}
			run_bytes = min_t(u64, remaining, run.run_bytes);
			while (run_bytes) {
				u32 page_bytes = min_t(u64, run_bytes,
						      PAGE_SIZE - run.page_offset);
				enum hfi2_dms_sdma_desc_type type =
					(!command_pad && page_bytes == remaining) ?
					HFI2_DMS_SDMA_DESC_TYPE_EOP :
					HFI2_DMS_SDMA_DESC_TYPE_MID;

				rc = hfi2_dms_sdma_batch_emit(batch,
							      run.dma_pages[0] + run.page_offset,
							      page_bytes, type);
				if (rc)
					goto abort_cookie;
				off += page_bytes;
				remaining -= page_bytes;
				run_bytes -= page_bytes;
				run.page_offset = 0;
				run.dma_pages++;
			}
		}
		if (packet_len && command_pad && !copy_fallback) {
			memset(frame + header_bytes, 0, command_pad);
			rc = hfi2_dms_sdma_batch_emit(batch,
						      page->mem.phys_addr + sizeof(pbc) +
						      header_bytes, command_pad,
						      HFI2_DMS_SDMA_DESC_TYPE_EOP);
			if (rc)
				goto abort_cookie;
		}
		hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
					      sizeof(pbc) + header_bytes + command_pad);
		if (!copy_fallback && !cached)
			next_ss = packet_ss;
		psn = roce_psn(psn + 1);
	}
	rc = hfi2_dms_roce_sdma_commit(cookie, batch, engine_idx);
	if (rc)
		return rc;
	roce->stats.tx_vlan_tagged += vlan_packets;
	roce->stats.tx_read_resp_alias += alias_packets;
	roce->stats.tx_read_resp_alias_skip += alias_skip_packets;

	cursor->ss = next_ss;
	cursor->off = off;
	cursor->psn = psn;
	roce->stats.tx_worker_packets += packet_count;
	roce->stats.tx_sdma_read_resp += packet_count;
	if (meta->reply_write)
		roce->stats.tx_read_as_write_pkts += packet_count;
	roce->stats.tx_bytes += off - start_off;
	if (off == entry->rdma_sge.sge_length) {
		xfer->wire_acked = true;
		release_rdma_sge_mr(entry);
		entry->sent = 1;
		roce_advance_read_ack(rqp->qp, cursor->ack_index);
		cursor->valid = false;
		if (rqp->qp->r_head_ack_queue == rqp->qp->s_tail_ack_queue)
			rqp->qp->s_flags &= ~RVT_S_RESP_PENDING;
	}
	return packet_count;

abort_cookie:
	if (batch)
		hfi2_dms_sdma_batch_abort(batch);
	hfi2_dms_roce_sdma_abort_uncommitted(cookie, rc);
	return rc;
abort_pages:
	for (packet = 0; packet < candidate_packets; packet++) {
		if (command_pages[packet]) {
			hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc),
					  command_pages[packet]);
			command_pages[packet] = NULL;
		}
	}
abort_source:
	if (source)
		hfi2_bulksvc_verbs_source_provider_release(source);
abort_unselected:
	if (rc == -EAGAIN || rc == -ENOSPC || rc == -E2BIG) {
		roce->stats.tx_sdma_read_resp_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	return rc;
}

static int roce_build_atomic_ack_frame(struct hfi2_dms_roce_qp *rqp,
				       struct hfi2_qp_priv_roce *priv,
				       const struct rvt_ack_entry *entry,
				       u8 *frame, size_t frame_sz, size_t *frame_len)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	size_t ib_len = HFI2_ROCE_BTH_BYTES + HFI2_ROCE_AETH_BYTES +
		HFI2_ROCE_ATOMIC_ACK_ETH_BYTES;
	u8 *bth;

	*frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES + *frame_len + HFI2_ROCE_ICRC_BYTES > frame_sz)
		return -EMSGSIZE;

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(frame + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
			    IB_DEFAULT_PKEY_FULL, roce_answer_dest_qpn(rqp, priv),
			    false, false, 0, entry->psn);
	*(__be32 *)(bth + HFI2_ROCE_BTH_BYTES) = rvt_compute_aeth(rqp->qp);
	ib_u64_put(entry->atomic_data,
		   (__be64 *)(bth + HFI2_ROCE_BTH_BYTES + HFI2_ROCE_AETH_BYTES));
	return 0;
}

static int roce_send_atomic_ack(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv,
				struct rvt_ack_entry *entry, u8 index)
{
	struct rvt_qp *qp = rqp->qp;
	size_t frame_len;
	int rc;

	if (rqp->resp_emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
	    rqp->sdma_resp_holds) {
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	rc = roce_build_atomic_ack_frame(rqp, priv, entry, rqp->txbuf,
					 rqp->txbuf_sz, &frame_len);
	if (rc)
		return rc;
	rc = roce_pio_frame(rqp, frame_len, true);
	if (rc)
		return rc;

	entry->sent = 1;
	rqp->roce->stats.tx_atomic_ack++;
	roce_advance_read_ack(qp, index);
	if (qp->r_head_ack_queue == qp->s_tail_ack_queue)
		qp->s_flags &= ~RVT_S_RESP_PENDING;
	return 1;
}

static int roce_send_read_response(struct hfi2_dms_roce_qp *rqp,
				   struct hfi2_qp_priv_roce *priv)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_read_cursor *cursor = &rqp->read_cursor;
	struct rvt_ack_entry *entry;
	struct rvt_sge_state packet_ss, gather_ss;
	bool direct_gather = READ_ONCE(roce_direct_gather);
	u32 packet_len;
	bool last;
	size_t frame_len, header_bytes;
	u8 pad;
	bool use_alias;
	int rc;

	if (qp->r_head_ack_queue == qp->s_tail_ack_queue) {
		qp->s_flags &= ~RVT_S_RESP_PENDING;
		return 0;
	}

	entry = &qp->s_ack_queue[qp->s_tail_ack_queue];
	if (entry->opcode == IB_OPCODE_RC_COMPARE_SWAP ||
	    entry->opcode == IB_OPCODE_RC_FETCH_ADD)
		return roce_send_atomic_ack(rqp, priv, entry, qp->s_tail_ack_queue);
	if (entry->opcode != IB_OPCODE_RC_RDMA_READ_REQUEST) {
		qp->s_flags &= ~RVT_S_RESP_PENDING;
		return 0;
	}
	if (entry->rdma_sge.sge_length && !entry->rdma_sge.mr) {
		if (qp->s_acked_ack_queue == qp->s_tail_ack_queue)
			qp->s_acked_ack_queue = qp->r_head_ack_queue;
		qp->s_tail_ack_queue = qp->r_head_ack_queue;
		if (qp->r_head_ack_queue == qp->s_tail_ack_queue)
			qp->s_flags &= ~RVT_S_RESP_PENDING;
		return 0;
	}

	if (!cursor->valid || cursor->ack_index != qp->s_tail_ack_queue) {
		cursor->valid = false;
		roce_priority_refresh(rqp);
		memset(cursor, 0, sizeof(*cursor));
		cursor->ack_index = qp->s_tail_ack_queue;
		cursor->psn = roce_psn(entry->psn);
		cursor->ss.sge = entry->rdma_sge;
		cursor->ss.num_sge = entry->rdma_sge.mr ? 1 : 0;
		cursor->ss.total_len = entry->rdma_sge.sge_length;
		cursor->valid = true;
	}
	/* Only a complete single-packet reply may bypass the SDMA policy. */
	if (rqp->resp_emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
	    (rqp->sdma_resp_holds || cursor->off || !qp->pmtu ||
	     entry->rdma_sge.sge_length > qp->pmtu ||
	     !READ_ONCE(roce_pio_max_bytes) ||
	     entry->rdma_sge.sge_length > READ_ONCE(roce_pio_max_bytes) ||
	     !roce_ss_kernel_sges(&cursor->ss)))
		return roce_sdma_send_read_response(rqp, priv, entry, cursor);

	direct_gather = direct_gather && roce_ss_kernel_sges(&cursor->ss);
	rc = roce_build_read_response_frame(rqp, priv, entry, cursor,
					    direct_gather, rqp->txbuf,
					    rqp->txbuf_sz, &packet_ss,
					    &packet_len, &last, &frame_len,
					    &header_bytes, &pad, &use_alias);
	if (rc)
		return rc;

	/*
	 * Gather the payload straight from the MR into the PIO buffer, as
	 * roce_send_one_packet() does for WRITE and SEND, rather than staging
	 * it in txbuf first.  The cursor only advances once the packet is
	 * sent, so gather from a copy of it.
	 */
	if (direct_gather) {
		gather_ss = cursor->ss;
		rc = roce_pio_send_frame(rqp, &gather_ss, packet_len, pad,
					 frame_len, header_bytes, true);
	} else {
		rc = roce_pio_frame(rqp, frame_len, true);
	}
	if (rc)
		return rc;

	cursor->ss = packet_ss;
	cursor->off += packet_len;
	cursor->psn = roce_psn(cursor->psn + 1);
	rqp->roce->stats.tx_bytes += packet_len;
	if (use_alias)
		rqp->roce->stats.tx_read_resp_alias++;
	else if (roce_hwp_write_mode(rqp->roce))
		rqp->roce->stats.tx_read_resp_alias_skip++;
	if (!last)
		return 1;

	release_rdma_sge_mr(entry);
	entry->sent = 1;
	roce_advance_read_ack(qp, cursor->ack_index);
	cursor->valid = false;

	if (qp->r_head_ack_queue == qp->s_tail_ack_queue)
		qp->s_flags &= ~RVT_S_RESP_PENDING;
	return 1;
}

static int roce_build_atomic_request_frame(struct hfi2_dms_roce_qp *rqp,
					   struct hfi2_qp_priv_roce *priv,
					   struct rvt_swqe *wqe,
					   u8 *frame_buf, size_t frame_buf_sz,
					   size_t *frame_len_out,
					   size_t *header_bytes_out)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	struct ib_atomic_eth *ateth;
	size_t ib_len = HFI2_ROCE_BTH_BYTES + HFI2_ROCE_ATOMIC_ETH_BYTES;
	size_t frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	u8 *bth;
	u8 opcode;

	if (EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES >
	    frame_buf_sz)
		return -EMSGSIZE;

	switch (wqe->wr.opcode) {
	case IB_WR_ATOMIC_CMP_AND_SWP:
		opcode = IB_OPCODE_RC_COMPARE_SWAP;
		break;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		opcode = IB_OPCODE_RC_FETCH_ADD;
		break;
	default:
		return -EINVAL;
	}

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(frame_buf + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame_buf + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, opcode, IB_DEFAULT_PKEY_FULL, priv->dest_qpn,
			    true, false, 0, roce_psn(wqe->psn));
	ateth = (struct ib_atomic_eth *)(bth + HFI2_ROCE_BTH_BYTES);
	put_ib_ateth_vaddr(wqe->atomic_wr.remote_addr, ateth);
	ateth->rkey = cpu_to_be32(wqe->atomic_wr.rkey);
	put_ib_ateth_swap(wqe->wr.opcode == IB_WR_ATOMIC_CMP_AND_SWP ?
			     wqe->atomic_wr.swap : wqe->atomic_wr.compare_add, ateth);
	put_ib_ateth_compare(wqe->wr.opcode == IB_WR_ATOMIC_CMP_AND_SWP ?
			     wqe->atomic_wr.compare_add : 0, ateth);
	*frame_len_out = frame_len;
	*header_bytes_out = (u8 *)ateth - frame_buf + HFI2_ROCE_ATOMIC_ETH_BYTES;
	return 0;
}

static int roce_build_read_request_frame(struct hfi2_dms_roce_qp *rqp,
					 struct hfi2_qp_priv_roce *priv,
					 struct rvt_swqe *wqe,
					 u8 *frame_buf, size_t frame_buf_sz,
					 size_t *frame_len_out,
					 size_t *header_bytes_out,
					 bool from_worker)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	struct hfi2_roce_read_ext *ext;
	u64 dest_va = 0;
	u32 dest_rkey = HFI2_ROCE_RKEY_NO_OWNER;
	unsigned int index = roce_wqe_index(rqp->qp, wqe);
	bool reply_write;
	bool software_place;
	size_t ext_len;
	size_t ib_len;
	size_t frame_len;
	u8 *bth, *reth;

	reply_write = roce_read_write_eligible(rqp, priv, wqe, &dest_va,
					       &dest_rkey, true);
	software_place = roce_hwp_write_mode(rqp->roce) && !reply_write;
	if (reply_write) {
		roce_wqe_set_read_write_reply(rqp, wqe);
	} else {
		roce_hwp_window_release_wqe(rqp, wqe);
		clear_bit(index, rqp->read_write_wqes);
	}
	if (software_place)
		roce_wqe_set_read_software_reply(rqp, wqe);
	else
		roce_wqe_clear_read_software_reply(rqp, wqe);
	ext_len = (reply_write || software_place) ? HFI2_ROCE_READ_EXT_BYTES : 0;
	ib_len = HFI2_ROCE_BTH_BYTES + HFI2_ROCE_RETH_BYTES + ext_len;
	addr.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_RETH_BYTES + ext_len, 0, 0);
	frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES >
	    frame_buf_sz)
		return -EMSGSIZE;

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(frame_buf + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame_buf + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, IB_OPCODE_RC_RDMA_READ_REQUEST,
			    IB_DEFAULT_PKEY_FULL, priv->dest_qpn, true, false, 0,
			    roce_psn(wqe->psn));
	reth = bth + HFI2_ROCE_BTH_BYTES;
	hfi2_roce_build_reth(reth, wqe->rdma_wr.remote_addr,
			     wqe->rdma_wr.rkey, wqe->length);
	if (reply_write || software_place) {
		ext = (struct hfi2_roce_read_ext *)(reth + HFI2_ROCE_RETH_BYTES);
		ext->version = HFI2_ROCE_READ_EXT_VERSION;
		ext->flags = software_place ? HFI2_ROCE_READ_EXT_SOFTWARE_FLAGS :
			HFI2_ROCE_READ_EXT_DIRECT_FLAGS;
		ext->reserved0 = 0;
		ext->dest_va = cpu_to_be64(dest_va);
		ext->dest_rkey = cpu_to_be32(dest_rkey);
		ext->request_id = cpu_to_be32(roce_psn(wqe->psn));
		ext->reserved1 = 0;
		rqp->roce->stats.tx_read_as_write++;
	}
	*header_bytes_out = reth - frame_buf + HFI2_ROCE_RETH_BYTES + ext_len;
	if (addr.vlan_id != HFI2_ROCE_NO_VLAN)
		roce_tag_count(rqp, priv, false, from_worker);
	*frame_len_out = frame_len;
	return 0;
}

static int roce_send_atomic_request(struct hfi2_dms_roce_qp *rqp,
				    struct hfi2_qp_priv_roce *priv,
				    struct rvt_swqe *wqe, bool from_worker)
{
	size_t frame_len, header_bytes;
	int rc;

	rc = roce_build_atomic_request_frame(rqp, priv, wqe, rqp->txbuf,
					     rqp->txbuf_sz, &frame_len,
					     &header_bytes);
	if (rc)
		return rc;

	rc = roce_pio_frame(rqp, frame_len, from_worker);
	if (!rc) {
		roce_tx_stat_add(&rqp->roce->stats.tx_atomic_req,
				 &rqp->roce->inline_stats.tx_atomic_req, 1, from_worker);
		roce_trace(rqp->dd, "tx ATOMIC_REQUEST psn=%u qpn=%u op=0x%02x\n",
			   wqe->psn, priv->dest_qpn,
			   wqe->wr.opcode == IB_WR_ATOMIC_CMP_AND_SWP ?
			   IB_OPCODE_RC_COMPARE_SWAP : IB_OPCODE_RC_FETCH_ADD);
	}
	return rc;
}

static int roce_send_read_request(struct hfi2_dms_roce_qp *rqp,
				  struct hfi2_qp_priv_roce *priv,
				  struct rvt_swqe *wqe, bool from_worker)
{
	size_t frame_len, header_bytes;
	int rc;

	rc = roce_build_read_request_frame(rqp, priv, wqe, rqp->txbuf,
					   rqp->txbuf_sz, &frame_len, &header_bytes,
					   from_worker);
	if (rc)
		return rc;

	rc = roce_pio_frame(rqp, frame_len, from_worker);
	if (!rc) {
		roce_trace(rqp->dd, "tx READ_REQUEST psn=%u qpn=%u len=%u\n",
			   wqe->psn, priv->dest_qpn, wqe->length);
	}
	return rc;
}

/* Caller holds qp->s_lock.  A fence wait cannot make forward progress. */
static bool roce_donor_wait_pending(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce_hwp_window *window;

	lockdep_assert_held(&rqp->qp->s_lock);
	if (rqp->roce->hwp_pool.backend != HFI2_ROCE_HWP_DONOR ||
	    !rqp->hwp_donor_holds ||
	    rqp->qp->s_cur == READ_ONCE(rqp->qp->s_head) ||
	    rvt_get_swqe_ptr(rqp->qp, rqp->qp->s_cur)->wr.opcode != IB_WR_RDMA_READ)
		return false;
	window = rqp->read_hwp_windows[rqp->qp->s_cur];
	return !window || (window->state != HFI2_ROCE_HWP_ACTIVE &&
			   window->state != HFI2_ROCE_HWP_READY);
}

static bool roce_send_turn_ready(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	lockdep_assert_held(&qp->s_lock);
	return !rqp->replay_pending && qp->s_cur != READ_ONCE(qp->s_head) &&
		!(qp->s_flags & (RVT_S_WAIT_RNR | RVT_S_WAIT_FENCE |
				 RVT_S_WAIT_RDMAR)) &&
		!roce_donor_wait_pending(rqp);
}

static int roce_turn_claim_progress(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	lockdep_assert_held(&qp->s_lock);
	if ((qp->s_flags & RVT_S_RESP_PENDING) || rqp->ack_pending)
		return -EINPROGRESS;
	if (!rqp->replay_pending && qp->s_cur != READ_ONCE(qp->s_head) &&
	    !(qp->s_flags & RVT_S_WAIT_RNR))
		return -EINPROGRESS;
	return 0;
}

static bool roce_serve_resp(struct hfi2_dms_roce_qp *rqp,
			    struct hfi2_qp_priv_roce *priv, int *ret)
{
	struct rvt_qp *qp = rqp->qp;
	int rc;

	lockdep_assert_held(&qp->s_lock);
	if (!(qp->s_flags & RVT_S_RESP_PENDING))
		return false;

	rc = roce_send_read_response(rqp, priv);
	if (rc == -EAGAIN || rc == -ENOSPC) {
		*ret = rc;
		return true;
	}
	if (rc == -EBUSY) {
		/* Both arms are blocked; an ACK or retry will wake the QP. */
		if (*ret != -ENOSPC &&
		    !(*ret == -EAGAIN && rqp->sdma_stalled))
			*ret = 0;
		return true;
	}
	if (rc < 0)
		rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_S);
	rqp->resp_yield_send = false;
	*ret = roce_turn_claim_progress(rqp);
	return true;
}

static int roce_requester_rd_atomic_sent(struct hfi2_dms_roce_qp *rqp,
					    struct rvt_swqe *wqe,
					    bool new_request, bool from_worker)
{
	struct rvt_qp *qp = rqp->qp;

	if (new_request) {
		if (roce_order_request(wqe->wr.opcode))
			rqp->order_pending++;
		qp->s_num_rd_atomic++;
		if (!(qp->s_flags & RVT_S_UNLIMITED_CREDIT))
			qp->s_lsn++;
		/* Later READs must not acknowledge an outstanding response. */
		if (qp->s_acked == qp->s_tail)
			qp->s_last_psn = roce_psn(wqe->psn - 1);
		if (++qp->s_tail >= qp->s_size)
			qp->s_tail = 0;
	}
	if (++qp->s_cur >= qp->s_size)
		qp->s_cur = 0;
	qp->s_psn = roce_psn(wqe->lpsn + 1);
	qp->s_flags |= RVT_S_WAIT_ACK;
	if (!(qp->s_flags & RVT_S_TIMER))
		rvt_add_retry_timer(qp);
	roce_tx_stat_add(&rqp->roce->stats.tx_send_wqe,
			 &rqp->roce->inline_stats.tx_send_wqe, 1, from_worker);
	roce_request_emitter_close(rqp);
	return roce_turn_claim_progress(rqp);
}

static int roce_sdma_send_read_request(struct hfi2_dms_roce_qp *rqp,
				       struct hfi2_qp_priv_roce *priv,
				       struct rvt_swqe *wqe, u32 wqe_idx)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_sdma_batch *batch = NULL;
	struct hfi2_dms_roce_sdma_cookie *cookie;
	struct hfi2_dms_roce_sdma_xfer *new_xfer;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_dms_page *page;
	u8 engine_idx = rqp->request_engine_idx;
	u8 *frame;
	u32 command_pad;
	u64 pbc;
	size_t frame_len;
	size_t header_bytes;
	unsigned int source_idx;
	bool vlan_tagged;
	int rc = -EAGAIN;

	if (!roce_request_emitter_select(rqp, HFI2_DMS_ROCE_EMITTER_SDMA,
					 engine_idx))
		return -EAGAIN;
	if (engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines)
		goto abort_unselected;
	engine = &roce->sdma_engines[engine_idx];
	if (engine->descriptor_used > engine->descriptor_cap ||
	    engine->page_used >= engine->page_cap) {
		rqp->sdma_stalled = true;
		goto abort_unselected;
	}

	xfer = roce_sdma_xfer_lookup(rqp, HFI2_DMS_ROCE_LANE_REQUEST, wqe_idx,
				     rqp->request_epoch, IB_WR_RDMA_READ, wqe->psn,
				     wqe->lpsn);
	if (xfer)
		goto abort_unselected;
	source_idx = roce_sdma_xfer_free(rqp, HFI2_DMS_ROCE_LANE_REQUEST, wqe_idx);
	if (WARN_ON_ONCE(source_idx == rqp->sdma_xfer_count)) {
		rc = -EINVAL;
		goto abort_unselected;
	}
	new_xfer = &rqp->sdma_xfers[source_idx];
	page = hfi2_dms_page_try_get(hfi2_bulksvc_primary_dms(roce->svc));
	if (!page) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		goto abort_unselected;
	}
	cookie = hfi2_dms_roce_sdma_admit(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
					  wqe_idx, rqp->request_epoch,
					  IB_WR_RDMA_READ, wqe->psn, wqe->lpsn,
				  engine_idx, 1, 1, 1, false, false, NULL,
				  new_xfer);

	if (!cookie)
		goto abort_page;
	cookie->pages[0] = page;
	xfer = cookie->xfer;
	/* Requester response handling acknowledges the payload-free READ request. */
	xfer->wire_acked = true;

	if (WARN_ON_ONCE(hfi2_bulksvc_primary_dms(roce->svc)->port_sctxts[rqp->port_idx] !=
			 roce->sc)) {
		roce->stats.sdma_context_mismatch++;
		rc = -EINVAL;
		goto abort_cookie;
	}
	batch = hfi2_dms_sdma_batch_new_nowait(hfi2_bulksvc_primary_dms(roce->svc), rqp->port_idx);
	if (!batch) {
		roce->stats.sdma_batch_stall++;
		rqp->sdma_stalled = true;
		goto abort_cookie;
	}

	frame = page->mem.kvaddr + sizeof(pbc);
	rc = roce_build_read_request_frame(rqp, priv, wqe, frame,
					   page->mem.len - sizeof(pbc), &frame_len,
					   &header_bytes, true);
	if (rc)
		goto abort_cookie;
	roce_build_egress_geometry(rqp, frame, frame_len, 0, &pbc, NULL);
	vlan_tagged = roce_frame_vlan_tagged(frame);
	command_pad = roce_sdma_command_pad(header_bytes, 0, 0);
	if (command_pad)
		memset(frame + header_bytes, 0, command_pad);
	*(u64 *)page->mem.kvaddr = pbc;
	rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
				      sizeof(pbc) + header_bytes + command_pad,
				      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
	if (rc)
		goto abort_cookie;
	hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page,
				      0, sizeof(pbc) + header_bytes + command_pad);
	rc = hfi2_dms_roce_sdma_commit(cookie, batch, engine_idx);
	if (rc)
		return rc;
	if (vlan_tagged)
		roce->stats.tx_vlan_tagged++;

	roce->stats.tx_worker_packets++;
	roce->stats.tx_sdma_read_req++;
	roce_trace(rqp->dd, "tx READ_REQUEST psn=%u qpn=%u len=%u\n",
		   wqe->psn, priv->dest_qpn, wqe->length);
	return 0;

abort_cookie:
	if (batch)
		hfi2_dms_sdma_batch_abort(batch);
	hfi2_dms_roce_sdma_abort_uncommitted(cookie, rc);
	return rc;
abort_page:
	hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), page);
abort_unselected:
	roce_request_emitter_unselect_sdma(rqp);
	return rc;
}

static void roce_requester_ack(struct hfi2_dms_roce_qp *rqp, const struct hfi2_roce_wire_rx *rx);

static void roce_tx_snapshot_release_at_emit(struct hfi2_dms_roce_qp *rqp)
{
	u8 i;

	for (i = 0; i < rqp->tx_num_mrs; i++)
		rvt_put_mr(rqp->tx_mrs[i]);
	rqp->tx_num_mrs = 0;
	memset(&rqp->tx_ss, 0, sizeof(rqp->tx_ss));
	rqp->tx_ss_off = 0;
	rqp->tx_in_progress = false;
}

static void roce_tx_snapshot_release(struct hfi2_dms_roce_qp *rqp)
{
	roce_tx_snapshot_release_at_emit(rqp);
}

/*
 * Follow a PFC or APP priority change at a message boundary: only while
 * this QP is not part-way through sending a message (a SEND/WRITE snapshot
 * or a READ response), so no message straddles two VLs.  Bundles already
 * handed to SDMA carry their own built headers and are unaffected.  The
 * requester and responder sides share the state, so either may refresh it
 * here.  Caller holds s_lock.
 */
static void roce_priority_refresh(struct hfi2_dms_roce_qp *rqp)
{
	if (rqp->tx_in_progress || rqp->read_cursor.valid)
		return;
	hfi2_roce_refresh_priority(rqp->qp);
}

/*
 * A responder-only QP has no send-side boundary, so refresh too when a new
 * request message arrives; its ACK/NAKs then follow.  Caller holds s_lock.
 */
static void roce_priority_refresh_rx(struct hfi2_dms_roce_qp *rqp, u8 opcode)
{
	switch (opcode) {
	case IB_OPCODE_RC_SEND_FIRST:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
		roce_priority_refresh(rqp);
		break;
	}
}

static void roce_tx_snapshot_init(struct hfi2_dms_roce_qp *rqp,
				  struct rvt_swqe *wqe, u32 wqe_idx, u32 pmtu)
{
	u32 num_sge = min_t(u32, wqe->wr.num_sge, rqp->tx_max_sge);
	u8 i;
	u8 retained = 0;

	memset(&rqp->tx_ss, 0, sizeof(rqp->tx_ss));
	for (i = 0; i < num_sge; i++) {
		const struct rvt_sge *sge = &wqe->sg_list[i];

		if (!sge->sge_length)
			continue;
		rqp->tx_sges[retained] = *sge;
		rqp->tx_mrs[retained] = sge->mr;
		rvt_get_mr(rqp->tx_mrs[retained]);
		retained++;
	}
	rqp->tx_num_mrs = retained;
	if (retained) {
		rqp->tx_ss.sge = rqp->tx_sges[0];
		rqp->tx_ss.sg_list = rqp->tx_sges + 1;
		rqp->tx_ss.num_sge = retained;
	}
	rqp->tx_opcode = wqe->wr.opcode;
	rqp->tx_length = wqe->length;
	rqp->tx_remote_addr = wqe->rdma_wr.remote_addr;
	rqp->tx_rkey = wqe->rdma_wr.rkey;
	rqp->tx_imm_data = wqe->wr.ex.imm_data;
	rqp->tx_invalidate_rkey = wqe->wr.ex.invalidate_rkey;
	rqp->tx_solicited = wqe->wr.send_flags & IB_SEND_SOLICITED;
	rqp->tx_pmtu = pmtu;
	rqp->tx_wqe_idx = wqe_idx;
	rqp->tx_off = 0;
	rqp->tx_ss_off = 0;
	rqp->tx_psn = roce_psn(wqe->psn);
	rqp->tx_middle_prefix_valid = false;
	rqp->tx_middle_cmd_valid = false;
	rqp->tx_in_progress = true;
}

static bool roce_tx_worker_begin(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;
	bool begin = false;

	spin_lock_irqsave(&rqp->tx_state_lock, flags);
	if (!rqp->tx_cancelled) {
		if (!rqp->tx_worker_active) {
			reinit_completion(&rqp->tx_idle);
			rqp->tx_worker_active = true;
			rqp->tx_resched = false;
			begin = true;
		} else {
			rqp->tx_resched = true;
		}
	}
	spin_unlock_irqrestore(&rqp->tx_state_lock, flags);
	return begin;
}

static bool roce_tx_worker_end(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;
	bool resched;

	spin_lock_irqsave(&rqp->tx_state_lock, flags);
	rqp->tx_worker_active = false;
	resched = rqp->tx_resched;
	rqp->tx_resched = false;
	complete_all(&rqp->tx_idle);
	spin_unlock_irqrestore(&rqp->tx_state_lock, flags);
	return resched;
}

static bool roce_tx_worker_requeue(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	unsigned long runq_flags, state_flags;
	bool queued = false;

	spin_lock_irqsave(&roce->runq_lock, runq_flags);
	spin_lock_irqsave(&rqp->tx_state_lock, state_flags);
	if (!rqp->tx_cancelled && !rqp->runq_queued) {
		rqp->runq_queued = true;
		/* Peeked locklessly by hfi2_dms_roce_poll(), the worker itself. */
		list_add_tail(&rqp->runq_node, &roce->runq);
		queued = true;
	}
	rqp->tx_worker_active = false;
	complete_all(&rqp->tx_idle);
	spin_unlock_irqrestore(&rqp->tx_state_lock, state_flags);
	spin_unlock_irqrestore(&roce->runq_lock, runq_flags);
	return queued;
}

static void roce_tx_worker_park_donor(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	unsigned long flags, runq_flags, state_flags;

	/*
	 * The callback takes s_lock too: its enqueue cannot be lost to parking.
	 * No parked reference is needed; donor ownership already holds the QP.
	 */
	spin_lock_irqsave(&rqp->qp->s_lock, flags);
	spin_lock_irqsave(&roce->runq_lock, runq_flags);
	spin_lock_irqsave(&rqp->tx_state_lock, state_flags);
	if (!rqp->tx_cancelled && !roce->svc->stop_scheduling &&
	    !rqp->donor_waiting && !rqp->runq_queued) {
		rqp->runq_queued = true;
		rvt_get_qp(rqp->qp);
		list_add_tail(&rqp->runq_node, &roce->runq);
	}
	rqp->tx_worker_active = false;
	complete_all(&rqp->tx_idle);
	spin_unlock_irqrestore(&rqp->tx_state_lock, state_flags);
	spin_unlock_irqrestore(&roce->runq_lock, runq_flags);
	spin_unlock_irqrestore(&rqp->qp->s_lock, flags);
}

static bool roce_tx_worker_park_pio(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	unsigned long runq_flags, state_flags;
	bool parked = false;

	spin_lock_irqsave(&roce->runq_lock, runq_flags);
	spin_lock_irqsave(&rqp->tx_state_lock, state_flags);
	/*
	 * rvt_post_send() runs in the poster's context, not on this worker,
	 * and can queue the QP again through hfi2_dms_roce_enqueue() while
	 * the worker is sending it.  That entry already runs it, so do not
	 * park it as well: a QP on both lists is re-added to the run queue
	 * when credits return, corrupting it, and until then the parked
	 * reference keeps the QP from being destroyed.
	 */
	if (!rqp->tx_cancelled && !rqp->pio_wait_queued &&
	    !rqp->runq_queued) {
		rqp->pio_wait_queued = true;
		list_add_tail(&rqp->pio_wait_node, &roce->pio_waitq);
		parked = true;
		if (!roce->pio_intr_armed) {
			roce->pio_intr_armed = true;
			hfi2_sc_wantpiobuf_intr(roce->sc, 1);
		}
	}
	rqp->tx_worker_active = false;
	complete_all(&rqp->tx_idle);
	spin_unlock_irqrestore(&rqp->tx_state_lock, state_flags);
	spin_unlock_irqrestore(&roce->runq_lock, runq_flags);
	return parked;
}

/*
 * Park a QP whose send turn stopped on SDMA capacity: its lane or engine
 * bundle cap, the descriptor budget, or the command-page or batch-node pool.
 * Every one of those is returned only by roce_sdma_cookie_release(), which
 * runs from hfi2_dms_roce_sdma_consume_done() on this worker, so retrying
 * the QP before a cookie drains cannot succeed.  Requeueing it at once
 * spends the turn rebuilding the same refusal under s_lock and ends the
 * worker's TX pass, starving every QP behind it.
 *
 * Only park while some bundle is in flight: that is what guarantees a
 * later release, and so a wakeup.  With nothing in flight, fall back to the
 * run queue.  The same membership rules as the PIO park apply.
 */
static bool roce_tx_worker_park_sdma(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	unsigned long runq_flags, state_flags;
	bool parked = false;

	if (!atomic_read(&roce->sdma_local_holds))
		return roce_tx_worker_requeue(rqp);

	spin_lock_irqsave(&roce->runq_lock, runq_flags);
	spin_lock_irqsave(&rqp->tx_state_lock, state_flags);
	if (!rqp->tx_cancelled && !rqp->sdma_wait_queued &&
	    !rqp->pio_wait_queued && !rqp->runq_queued) {
		rqp->sdma_wait_queued = true;
		list_add_tail(&rqp->sdma_wait_node, &roce->sdma_waitq);
		roce->stats.sdma_park++;
		parked = true;
	}
	rqp->tx_worker_active = false;
	complete_all(&rqp->tx_idle);
	spin_unlock_irqrestore(&rqp->tx_state_lock, state_flags);
	spin_unlock_irqrestore(&roce->runq_lock, runq_flags);
	return parked;
}

/*
 * Move SDMA-parked QPs that can now be admitted back to the run queue.
 *
 * Waking every parked QP on every release made each one retry, fail
 * admission and park again: with 8+ QPs per engine the sender spent its
 * time cycling QPs through the wait queue.  A QP is woken only when its
 * own lane and its engine have room, and an engine wakes no more QPs than
 * it has free bundle slots.  The page and batch pools are not checked; a
 * QP stalled on them is woken by the engine test and parks again, as
 * before.  Nothing parks forever: every release runs this again, and
 * @all (no bundle in flight anywhere) wakes everyone.
 */
static void roce_sdma_waitq_wake(struct hfi2_dms_roce *roce, bool all)
{
	struct hfi2_dms_roce_qp *rqp, *tmp;
	u16 room[TXE_NUM_SDMA_ENGINES];
	unsigned long flags;
	u8 i;

	for (i = 0; i < roce->sdma_engine_count; i++) {
		struct hfi2_dms_roce_sdma_engine *engine =
			&roce->sdma_engines[i];

		room[i] = engine->bundle_used < engine->bundle_cap &&
			  engine->descriptor_used < engine->descriptor_cap &&
			  engine->page_used < engine->page_cap ?
			  engine->bundle_cap - engine->bundle_used : 0;
	}
	spin_lock_irqsave(&roce->runq_lock, flags);
	list_for_each_entry_safe(rqp, tmp, &roce->sdma_waitq, sdma_wait_node) {
		u8 e = rqp->request_engine_idx;

		if (!all && !rqp->tx_cancelled &&
		    e < roce->sdma_engine_count) {
			bool resp_pending = READ_ONCE(rqp->qp->s_flags) & RVT_S_RESP_PENDING;
			bool req_pending = rqp->qp->s_cur != READ_ONCE(rqp->qp->s_head);
			bool resp_ok = resp_pending &&
				rqp->sdma_resp_holds < roce->sdma_qp_bundles;
			bool req_ok = (!resp_pending || req_pending) &&
				rqp->sdma_req_holds < roce->sdma_qp_bundles;
			u16 holds = resp_ok ? rqp->sdma_resp_holds : rqp->sdma_req_holds;
			u16 want = min_t(u16, room[e], roce->sdma_qp_bundles - holds);
			u16 reserve = resp_ok ? 1 : ROCE_SDMA_REQUEST_DESC_RESERVE;
			struct hfi2_dms_roce_sdma_engine *engine = &roce->sdma_engines[e];

			if (!want || (!resp_ok && !req_ok) ||
			    reserve > engine->descriptor_cap - engine->descriptor_used) {
				roce->stats.sdma_wake_skipped++;
				continue;
			}
			room[e] -= want;
		}
		list_del_init(&rqp->sdma_wait_node);
		rqp->sdma_wait_queued = false;
		if (rqp->tx_cancelled) {
			rvt_put_qp(rqp->qp);
			continue;
		}
		rqp->runq_queued = true;
		/* Peeked locklessly by hfi2_dms_roce_poll(), which calls this. */
		list_add_tail(&rqp->runq_node, &roce->runq);
		roce->stats.sdma_wake++;
	}
	spin_unlock_irqrestore(&roce->runq_lock, flags);
}

/*
 * Keyed on tx_worker_iters, which the turn already increments: a separate
 * tick in struct hfi2_dms_roce shared a cache line with runq_lock, and
 * writing it on every turn cost more than the clock reads it saved.
 */
static bool roce_lock_hold_timed(struct hfi2_dms_roce *roce, bool perf_stats)
{
	u32 n = READ_ONCE(roce_lock_hold_sample);

	return perf_stats || (n && !(roce->stats.tx_worker_iters % n));
}

static int roce_ud_resolve_av(struct hfi2_dms_roce_qp *rqp,
			      struct rvt_swqe *wqe,
			      struct hfi2_roce_wire_addr *addr)
{
	struct rdma_ah_attr *attr = rvt_get_swqe_ah_attr(wqe);
	const struct ib_global_route *grh = rdma_ah_read_grh(attr);
	u32 flow_label = grh->flow_label;

	if (!flow_label)
		flow_label = rdma_calc_flow_label(rqp->qp->ibqp.qp_num,
						  rvt_get_swqe_remote_qpn(wqe));
	return hfi2_roce_resolve_ah(rqp->dd, attr,
				    rdma_flow_label_to_udp_sport(flow_label), addr);
}

static int roce_ud_send_one(struct hfi2_dms_roce_qp *rqp,
			    struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_roce_wire_addr addr = {};
	struct rvt_sge_state ss = {};
	u32 remaining = wqe->length;
	u32 qkey;
	u8 *bth, *deth, *payload;
	u8 pad = roce_bth_pad(wqe->length);
	u8 opcode = wqe->wr.opcode == IB_WR_SEND_WITH_IMM ?
		IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE : IB_OPCODE_UD_SEND_ONLY;
	size_t ext_len = HFI2_ROCE_DETH_BYTES +
		(wqe->wr.opcode == IB_WR_SEND_WITH_IMM ? HFI2_ROCE_IMMDT_BYTES : 0);
	size_t ib_len = HFI2_ROCE_BTH_BYTES + ext_len + wqe->length + pad;
	size_t frame_len;
	int rc;

	rc = roce_ud_resolve_av(rqp, wqe, &addr);
	if (rc)
		return rc;
	frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES >
	    rqp->txbuf_sz)
		return -EMSGSIZE;

	hfi2_roce_build_eth_ipv4_udp(rqp->txbuf + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = rqp->txbuf + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, opcode, IB_DEFAULT_PKEY_FULL,
			    rvt_get_swqe_remote_qpn(wqe), false,
			    wqe->wr.send_flags & IB_SEND_SOLICITED, pad,
			    roce_psn(wqe->psn));
	deth = bth + HFI2_ROCE_BTH_BYTES;
	qkey = (int)rvt_get_swqe_remote_qkey(wqe) < 0 ? qp->qkey :
		rvt_get_swqe_remote_qkey(wqe);
	if (qp->ibqp.qp_type == IB_QPT_GSI && !qkey)
		qkey = IB_QP1_QKEY;
	put_unaligned_be32(qkey, deth);
	put_unaligned_be32(qp->ibqp.qp_num & IB_QPN_MASK, deth + sizeof(__be32));
	payload = deth + HFI2_ROCE_DETH_BYTES;
	if (wqe->wr.opcode == IB_WR_SEND_WITH_IMM) {
		*(__be32 *)payload = wqe->wr.ex.imm_data;
		payload += HFI2_ROCE_IMMDT_BYTES;
	}

	if (remaining) {
		ss.sge = wqe->sg_list[0];
		ss.sg_list = wqe->sg_list + 1;
		ss.num_sge = wqe->wr.num_sge;
		ss.total_len = remaining;
	}
	while (remaining) {
		u32 len = rvt_get_sge_length(&ss.sge, remaining);

		if (unlikely(!len))
			return -EINVAL;
		rc = roce_sge_copy_to_kernel(rqp->roce, payload, ss.sge.mem, len);
		if (rc)
			return rc;
		payload += len;
		roce_advance_sge(&ss, len);
		remaining -= len;
	}
	if (pad)
		memset(payload, 0, pad);

	return roce_pio_frame(rqp, frame_len, true);
}

static bool roce_ud_has_dmabuf_do(const struct rvt_swqe *wqe)
{
	u8 i;

	for (i = 0; i < wqe->wr.num_sge; i++) {
		if (wqe->sg_list[i].sge_length &&
		    wqe->sg_list[i].mem.type == RVT_MEM_DMABUF_DO)
			return true;
	}
	return false;
}

static int roce_ud_sdma_account(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_bulksvc_verbs_source *source,
				 struct hfi2_dms_page *page, u32 length,
				 size_t header_bytes, u32 command_pad,
				 u16 descriptor_budget, u16 *descs_out)
{
	struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(rqp->roce->svc);
	u32 remaining = length;
	u64 offset = 0;
	u32 descs;

	descs = hfi2_dms_sdma_fragment_desc_count(dms, page->mem.phys_addr,
						   sizeof(u64) + header_bytes);
	while (remaining) {
		struct hfi2_dms_run run;
		u32 run_bytes;
		int rc;

		rc = source->provider.next_src_run(&source->provider, offset,
						  remaining, &run);
		if (rc || !run.run_bytes || !run.dma_pages)
			return rc ? rc : -EINVAL;
		run_bytes = min_t(u64, remaining, run.run_bytes);
		while (run_bytes) {
			u32 page_bytes = min_t(u64, run_bytes,
						       PAGE_SIZE - run.page_offset);

			descs += hfi2_dms_sdma_fragment_desc_count(dms,
					run.dma_pages[0] + run.page_offset, page_bytes);
			run_bytes -= page_bytes;
			run.page_offset = 0;
			run.dma_pages++;
		}
		offset += min_t(u64, remaining, run.run_bytes);
		remaining -= min_t(u64, remaining, run.run_bytes);
	}
	if (command_pad)
		descs += hfi2_dms_sdma_fragment_desc_count(dms,
			page->mem.phys_addr + sizeof(u64) + header_bytes,
			command_pad);
	descs = hfi2_dms_sdma_run_desc_count(dms, descs);
	if (descs > descriptor_budget)
		return -E2BIG;
	*descs_out = descs;
	return 0;
}

static int roce_ud_send_one_sdma(struct hfi2_dms_roce_qp *rqp,
				 struct rvt_swqe *wqe, u32 wqe_idx)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_dms_roce_sdma_cookie *cookie;
	struct hfi2_dms_roce_sdma_xfer *new_xfer;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_bulksvc_verbs_source *source;
	struct hfi2_bulksvc_verbs_source_segment *segments;
	struct hfi2_dms_sdma_batch *batch = NULL;
	struct hfi2_dms_page *page;
	struct hfi2_roce_wire_addr addr = {};
	u8 engine_idx = rqp->request_engine_idx;
	u8 *bth, *deth, *payload, *frame;
	u8 opcode = wqe->wr.opcode == IB_WR_SEND_WITH_IMM ?
		IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE : IB_OPCODE_UD_SEND_ONLY;
	u8 pad = roce_bth_pad(wqe->length);
	u16 descriptor_count;
	u32 qkey;
	u32 command_pad;
	u32 remaining = wqe->length;
	u32 source_idx;
	size_t ext_len = HFI2_ROCE_DETH_BYTES +
		(wqe->wr.opcode == IB_WR_SEND_WITH_IMM ? HFI2_ROCE_IMMDT_BYTES : 0);
	size_t ib_len = HFI2_ROCE_BTH_BYTES + ext_len + wqe->length + pad;
	size_t frame_len;
	size_t header_bytes;
	u64 pbc;
	bool vlan_tagged;
	int rc = -EAGAIN;

	if (engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines)
		return -EOPNOTSUPP;
	if (WARN_ON_ONCE(hfi2_bulksvc_primary_dms(roce->svc)->port_sctxts[rqp->port_idx] !=
			 roce->sc))
		return -EINVAL;
	engine = &roce->sdma_engines[engine_idx];
	if (engine->descriptor_used >= engine->descriptor_cap ||
	    engine->page_used >= engine->page_cap) {
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	if (!roce_request_emitter_select(rqp, HFI2_DMS_ROCE_EMITTER_SDMA,
					 engine_idx))
		return -EAGAIN;
	xfer = roce_sdma_xfer_lookup(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
				     wqe_idx, rqp->request_epoch, wqe->wr.opcode,
				     wqe->psn, wqe->lpsn);
	if (xfer) {
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	source_idx = roce_sdma_xfer_free(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
					 wqe_idx);
	if (WARN_ON_ONCE(source_idx == rqp->sdma_xfer_count)) {
		rc = -EAGAIN;
		goto abort_unselected;
	}
	new_xfer = &rqp->sdma_xfers[source_idx];
	if (WARN_ON_ONCE(!rqp->sdma_sources || !rqp->sdma_source_segments)) {
		rc = -EINVAL;
		goto abort_unselected;
	}
	source = &rqp->sdma_sources[source_idx];
	segments = &rqp->sdma_source_segments[source_idx * rqp->tx_max_sge];
	rc = hfi2_bulksvc_verbs_source_provider_init(source, segments,
					     rqp->tx_max_sge, wqe->sg_list,
					     wqe->wr.num_sge);
	if (rc) {
		if (rc == -ENOENT)
			rc = -EOPNOTSUPP;
		goto abort_unselected;
	}
	page = hfi2_dms_page_try_get(hfi2_bulksvc_primary_dms(roce->svc));
	if (!page) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		goto abort_source;
	}

	rc = roce_ud_resolve_av(rqp, wqe, &addr);
	if (rc)
		goto abort_page;
	frame = page->mem.kvaddr + sizeof(pbc);
	frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES +
	    hfi2_roce_ipv4_bth_offset(addr.vlan_id) +
	    HFI2_ROCE_BTH_BYTES + ext_len + pad >
	    page->mem.len - sizeof(pbc)) {
		rc = -EMSGSIZE;
		goto abort_page;
	}
	hfi2_roce_build_eth_ipv4_udp(frame + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, opcode, IB_DEFAULT_PKEY_FULL,
			    rvt_get_swqe_remote_qpn(wqe), false,
			    wqe->wr.send_flags & IB_SEND_SOLICITED, pad,
			    roce_psn(wqe->psn));
	deth = bth + HFI2_ROCE_BTH_BYTES;
	qkey = (int)rvt_get_swqe_remote_qkey(wqe) < 0 ? qp->qkey :
		rvt_get_swqe_remote_qkey(wqe);
	if (qp->ibqp.qp_type == IB_QPT_GSI && !qkey)
		qkey = IB_QP1_QKEY;
	put_unaligned_be32(qkey, deth);
	put_unaligned_be32(qp->ibqp.qp_num & IB_QPN_MASK, deth + sizeof(__be32));
	payload = deth + HFI2_ROCE_DETH_BYTES;
	if (wqe->wr.opcode == IB_WR_SEND_WITH_IMM) {
		*(__be32 *)payload = wqe->wr.ex.imm_data;
		payload += HFI2_ROCE_IMMDT_BYTES;
	}
	header_bytes = payload - frame;
	command_pad = roce_sdma_command_pad(header_bytes, wqe->length, pad);
	if (command_pad)
		memset(payload, 0, command_pad);
	roce_build_egress_geometry(rqp, frame, frame_len, 0, &pbc, NULL);
	*(u64 *)page->mem.kvaddr = pbc;
	vlan_tagged = roce_frame_vlan_tagged(frame);
	rc = roce_ud_sdma_account(rqp, source, page, wqe->length,
				   header_bytes, command_pad,
				   engine->descriptor_cap - engine->descriptor_used,
				   &descriptor_count);
	if (rc) {
		if (rc == -E2BIG)
			rqp->sdma_stalled = true;
		goto abort_page;
	}
	cookie = hfi2_dms_roce_sdma_admit(rqp, HFI2_DMS_ROCE_LANE_REQUEST,
					  wqe_idx, rqp->request_epoch,
					  wqe->wr.opcode, wqe->psn, wqe->lpsn,
					  engine_idx, 1, descriptor_count, 1, true,
					  false, source, new_xfer);
	if (!cookie) {
		rc = -EAGAIN;
		goto abort_page;
	}
	cookie->pages[0] = page;
	if (cookie->xfer_new)
		roce_sdma_xfer_hold_mr(cookie->xfer, wqe->sg_list[0].mr);
	source = NULL;
	batch = hfi2_dms_sdma_batch_new_nowait(hfi2_bulksvc_primary_dms(roce->svc), rqp->port_idx);
	if (!batch) {
		roce->stats.sdma_batch_stall++;
		rqp->sdma_stalled = true;
		goto abort_cookie;
	}
	rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
				      sizeof(pbc) + header_bytes,
				      wqe->length ? HFI2_DMS_SDMA_DESC_TYPE_SOP :
				      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
	if (rc)
		goto abort_cookie;
	while (remaining) {
		struct hfi2_dms_page_provider *prov =
			&cookie->xfer->source->provider;
		struct hfi2_dms_run run;
		u32 run_bytes;
		int next_rc;

		next_rc = prov->next_src_run(prov, wqe->length - remaining,
					     remaining, &run);
		if (next_rc || !run.run_bytes || !run.dma_pages) {
			rc = next_rc ? next_rc : -EINVAL;
			goto abort_cookie;
		}
		run_bytes = min_t(u64, remaining, run.run_bytes);
		while (run_bytes) {
			u32 page_bytes = min_t(u64, run_bytes,
						       PAGE_SIZE - run.page_offset);
			enum hfi2_dms_sdma_desc_type type =
				!command_pad && page_bytes == remaining ?
				HFI2_DMS_SDMA_DESC_TYPE_EOP :
				HFI2_DMS_SDMA_DESC_TYPE_MID;

			rc = hfi2_dms_sdma_batch_emit(batch,
				run.dma_pages[0] + run.page_offset, page_bytes, type);
			if (rc)
				goto abort_cookie;
			remaining -= page_bytes;
			run_bytes -= page_bytes;
			run.page_offset = 0;
			run.dma_pages++;
		}
	}
	if (command_pad) {
		rc = hfi2_dms_sdma_batch_emit(batch,
			page->mem.phys_addr + sizeof(pbc) + header_bytes,
			command_pad, HFI2_DMS_SDMA_DESC_TYPE_EOP);
		if (rc)
			goto abort_cookie;
	}
	hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page, 0,
				     sizeof(pbc) + header_bytes + command_pad);
	rc = hfi2_dms_roce_sdma_commit(cookie, batch, engine_idx);
	if (rc)
		return rc;
	qp->s_cur = rvt_qp_swqe_incr(qp, qp->s_cur);
	if (vlan_tagged)
		roce->stats.tx_vlan_tagged++;
	roce->stats.tx_ud_sdma++;
	roce->stats.tx_worker_packets++;
	roce->stats.tx_bytes += wqe->length;
	return 0;

abort_cookie:
	if (batch)
		hfi2_dms_sdma_batch_abort(batch);
	hfi2_dms_roce_sdma_abort_uncommitted(cookie, rc);
	return rc;
abort_page:
	hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), page);
abort_source:
	if (source)
		hfi2_bulksvc_verbs_source_provider_release(source);
abort_unselected:
	roce_request_emitter_unselect_sdma(rqp);
	return rc;
}

static int roce_ud_do_send(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce *roce = rqp->roce;
	u32 quantum = READ_ONCE(roce_tx_packet_quantum);
	u32 packets = 0;
	unsigned long flags;
	int ret = 0;

	while (packets < quantum) {
		struct rvt_swqe *wqe;
		int rc;

		ret = 0;
		spin_lock_irqsave(&qp->s_lock, flags);
		roce->stats.tx_worker_iters++;
		if (READ_ONCE(rqp->tx_cancelled))
			goto unlock;
		if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_NEXT_SEND_OK)) {
			if (!(ib_rvt_state_ops[qp->state] & RVT_FLUSH_SEND) ||
			    qp->s_last == READ_ONCE(qp->s_head) ||
			    rqp->sdma_local_holds)
				goto unlock;
			wqe = rvt_get_swqe_ptr(qp, qp->s_last);
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe, IB_WC_WR_FLUSH_ERR,
				      RVT_QP_LOCK_STATE_S);
			roce->stats.tx_flush_wqe++;
			ret = -EINPROGRESS;
			goto unlock;
		}
		if (qp->s_cur == READ_ONCE(qp->s_head))
			goto unlock;
		if (rqp->sdma_req_holds) {
			rqp->sdma_stalled = true;
			ret = -EAGAIN;
			goto unlock;
		}

		wqe = rvt_get_swqe_ptr(qp, qp->s_cur);
		if (qp->ibqp.qp_type == IB_QPT_UD && roce_ud_has_dmabuf_do(wqe)) {
			rc = roce_ud_send_one_sdma(rqp, wqe, qp->s_cur);
			if (!rc) {
				qp->s_psn = roce_psn(wqe->lpsn + 1);
				qp->s_last_psn = roce_psn(wqe->lpsn);
				roce->stats.tx_ud_pkts++;
				roce->stats.tx_send_wqe++;
				packets++;
				ret = -EINPROGRESS;
				goto unlock;
			}
			if (rc == -EAGAIN || rc == -ENOSPC || rc == -E2BIG) {
				rqp->sdma_stalled = true;
				ret = -EAGAIN;
				goto unlock;
			}
		}
		rc = roce_ud_send_one(rqp, wqe);
		if (rc == -EAGAIN || rc == -ENOSPC) {
			ret = rc;
			goto unlock;
		}
		if (rc) {
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe,
					  rc == -EMSGSIZE ? IB_WC_LOC_LEN_ERR :
				      IB_WC_GENERAL_ERR,
				      RVT_QP_LOCK_STATE_S);
			ret = -EINPROGRESS;
			goto unlock;
		}

		qp->s_psn = roce_psn(wqe->lpsn + 1);
		qp->s_last_psn = roce_psn(wqe->lpsn);
		hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
		rvt_send_complete(qp, wqe, IB_WC_SUCCESS, RVT_QP_LOCK_STATE_S);
		roce->stats.tx_ud_pkts++;
		roce->stats.tx_send_wqe++;
		roce->stats.tx_worker_packets++;
		roce->stats.tx_bytes += wqe->length;
		packets++;
		ret = qp->s_cur != READ_ONCE(qp->s_head) ? -EINPROGRESS : 0;
unlock:
		spin_unlock_irqrestore(&qp->s_lock, flags);
		if (ret != -EINPROGRESS)
			return ret;
	}

	return -EINPROGRESS;
}

static bool roce_prefer_pio_request(struct hfi2_dms_roce_qp *rqp,
				    const struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = rqp->qp;
	u32 thresh = READ_ONCE(roce_pio_max_bytes);
#if HFI2_DMS_ROCE_INJECT
	enum hfi2_dms_roce_emitter forced;

	if (roce_inject_request_emitter_get(&forced) &&
	    forced == HFI2_DMS_ROCE_EMITTER_SDMA)
		return false;
#endif

	if (!thresh ||
	    (rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_UNSET &&
	     rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_PIO) ||
	    rqp->sdma_req_holds || rqp->replay_pending)
		return false;
	if (wqe->length > thresh || (qp->pmtu && wqe->length > qp->pmtu))
		return false;
	if (rqp->tx_in_progress && rqp->tx_off)
		return false;
	if (wqe->wr.opcode != IB_WR_RDMA_READ) {
		roce_tx_sge_sync(rqp);
		if (!roce_ss_kernel_sges(&rqp->tx_ss))
			return false;
	}
	return true;
}

static int roce_do_send(struct rvt_qp *qp, bool from_worker);

static void roce_request_error(struct hfi2_dms_roce_qp *rqp,
			       struct rvt_swqe *wqe)
{
	/* Retain SQ ownership until local DMA drains, then flush in ring order. */
	if (!rqp->hwp_error_pending) {
		rqp->hwp_error_pending = true;
		rqp->hwp_error_index = roce_wqe_index(rqp->qp, wqe);
		rqp->hwp_error_status = IB_WC_GENERAL_ERR;
	}
	roce_hwp_cleanup_start(rqp);
	rvt_error_qp(rqp->qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_S);
}

int hfi2_dms_roce_do_send(struct rvt_qp *qp)
{
	return roce_do_send(qp, true);
}

/* Only the worker may service responses, flushes, SDMA or deferred local work. */
static int roce_do_send(struct rvt_qp *qp, bool from_worker)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(qp);
	struct hfi2_dms_roce_qp *rqp = priv->roce_qp;
	u32 quantum = READ_ONCE(roce_tx_packet_quantum);
	bool perf_stats = READ_ONCE(roce_perf_stats);
	u32 packets = 0;
	unsigned long flags;
	bool timed;
	bool retry;
	bool served_resp;
	int ret = 0;
	u64 lock_start_ns;
	u64 lock_end_ns;
	u64 hold_ns;
	bool send_turn;

	if (!rqp || !roce_qp_backend(rqp) || !rqp->roce->active)
		return 0;
	if (roce_qp_is_ud(qp))
		return from_worker ? roce_ud_do_send(rqp) : -EINPROGRESS;

	if (from_worker)
		rqp->roce->stats.tx_worker_turns++;
	while (packets < quantum) {
		struct rvt_sge_state next_ss;
		struct rvt_swqe *wqe;
		u32 seg;
		bool first, last, send_flush;
		u32 flushed;
		int rc;

		spin_lock_irqsave(&qp->s_lock, flags);
		timed = false;
		retry = false;
		if (!from_worker) {
			u32 thresh = READ_ONCE(roce_pio_max_bytes);

			ret = -EINPROGRESS;
			if (READ_ONCE(rqp->tx_cancelled) || !priv->av_valid ||
			    !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
			    rqp->ack_pending || (qp->s_flags & RVT_S_RESP_PENDING) ||
			    rqp->hwp_cleanup_pending || rqp->hwp_fencing ||
			    rqp->rif_queued || rqp->rif_arm_kind ||
			    rqp->replay_pending || rqp->tx_in_progress ||
			    rqp->order_pending || rqp->sdma_req_holds ||
			    rqp->sdma_local_holds || rqp->hwp_donor_holds ||
			    qp->s_tail != qp->s_cur)
				goto unlock;
			if (qp->s_cur == READ_ONCE(qp->s_head)) {
				ret = 0;
				goto unlock;
			}
			wqe = rvt_get_swqe_ptr(qp, qp->s_cur);
			if (!thresh || wqe->length > thresh)
				goto unlock;
			/* Placement and non-kernel memory stay on the worker. */
			if ((wqe->wr.opcode != IB_WR_RDMA_READ &&
			     wqe->wr.opcode != IB_WR_ATOMIC_CMP_AND_SWP &&
			     wqe->wr.opcode != IB_WR_ATOMIC_FETCH_AND_ADD &&
			     wqe->wr.opcode != IB_WR_SEND &&
			     wqe->wr.opcode != IB_WR_SEND_WITH_IMM &&
			     wqe->wr.opcode != IB_WR_SEND_WITH_INV &&
			     !roce_req_is_write(wqe->wr.opcode)) ||
			    (wqe->wr.opcode == IB_WR_RDMA_READ &&
			     roce_hwp_write_mode(rqp->roce)) ||
			    !roce_sdma_kernel_sges(wqe->sg_list, wqe->wr.num_sge) ||
			    !qp->pmtu || wqe->length > qp->pmtu ||
			    (rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_UNSET &&
			     rqp->request_emitter != HFI2_DMS_ROCE_EMITTER_PIO) ||
			    (wqe->wr.opcode != IB_WR_RDMA_WRITE &&
			     !(qp->s_flags & RVT_S_UNLIMITED_CREDIT) &&
			     rvt_cmp_msn(wqe->ssn, qp->s_lsn + 1) > 0))
				goto unlock;
		} else {
			rqp->roce->stats.tx_worker_iters++;
			timed = roce_lock_hold_timed(rqp->roce, perf_stats);
		}
		lock_start_ns = timed ? local_clock() : 0;
		/*
		 * Retry a held responder ACK/NAK before any send work: it is
		 * the signal the peer is blocked on, and it needs one PIO
		 * credit that a data frame would otherwise consume.
		 */
		rc = from_worker ? roce_ack_retry_pending(rqp, priv) : 0;
		if (rc) {
			ret = rc;
			goto unlock;
		}
		send_flush = !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) &&
			(!(qp->s_flags & RVT_S_RESP_PENDING) ||
			 !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK));
		/*
		 * A QP that cannot transmit can still owe flush completions,
		 * so the RVT_FLUSH_SEND arm below is reached before the
		 * transmit-readiness gates -- mirroring hfi2_make_rc_req(),
		 * where the flush check precedes every send-path gate.  Only
		 * an explicit cancel (RESET teardown) suppresses it: there
		 * quiesce_qp() waits on tx_idle and rdmavt discards the SQ.
		 */
		if (READ_ONCE(rqp->tx_cancelled) ||
		    (!priv->av_valid && !send_flush)) {
			if (from_worker &&
			    ((qp->s_flags & RVT_S_RESP_PENDING) ||
			     qp->s_cur != READ_ONCE(qp->s_head)))
				rqp->roce->stats.tx_send_state_drop++;
			if (rqp->tx_in_progress)
				roce_tx_snapshot_release(rqp);
			goto unlock;
		}
		if (rqp->hwp_cleanup_pending || rqp->hwp_fencing)
			goto unlock;
		if (send_flush) {
			rqp->order_pending = 0;
			qp->s_num_rd_atomic = 0;
			qp->s_flags &= ~RVT_S_WAIT_FENCE;
			if (!(ib_rvt_state_ops[qp->state] & RVT_FLUSH_SEND)) {
				/*
				 * Refused, not flushed.  tx_send_state_drop
				 * counts only this arm: 13.1 requires a
				 * counter used to discriminate an error class
				 * to be distinct from one sharing its code
				 * path, and the flush arm below has its own.
				 */
				if ((qp->s_flags & RVT_S_RESP_PENDING) ||
				    qp->s_cur != READ_ONCE(qp->s_head))
					rqp->roce->stats.tx_send_state_drop++;
				if (rqp->tx_in_progress)
					roce_tx_snapshot_release(rqp);
				goto unlock;
			}
			if (qp->s_last == READ_ONCE(qp->s_head))
				goto unlock;
			/*
			 * Accepted SDMA reads source memory asynchronously.  A
			 * flush CQE therefore cannot release the WQE's ownership
			 * until every local completion callback has been consumed.
			 * The last callback reschedules this QP to finish the flush.
			 */
			/* Donor aliases target the caller's pages until retirement. */
			if (rqp->sdma_local_holds || rqp->hwp_donor_holds)
				goto unlock;
			rc = roce_sdma_retire_error_prefix(rqp);
			if (READ_ONCE(rqp->tx_cancelled) || rqp->hwp_cleanup_pending ||
			    rqp->hwp_fencing || rqp->rif_read_cleanup)
				goto unlock;
			if (rc == ROCE_PIO_TX_FLUSH_BUDGET) {
				ret = -EINPROGRESS;
				goto unlock;
			}
			/*
			 * ERROR no longer waits for a wire ACK.  Once local SDMA
			 * ownership is gone, recycle its retained providers before
			 * advancing s_last through the flush loop.
			 */
			roce_resp_xfer_abandon(rqp);
			roce_sdma_terminalize_qp(rqp);
			if (rqp->tx_in_progress)
				roce_tx_snapshot_release(rqp);
			/*
			 * Retire in bulk, as BTS's verbs_deferred_retry() does,
			 * rather than one WQE per worker invocation: this engine
			 * is worker-driven off a private run list, so one WQE
			 * per pass costs a run-list trip each, on a QP already
			 * in error.  Design 3.5 makes BTS the comparand for
			 * send-engine questions.  BTS's backlog is a deferred
			 * list; ours is the send queue, up to hfi2_max_qp_wrs
			 * deep, so bound the pass and requeue rather than
			 * holding s_lock across all of it.
			 *
			 * s_lock is NOT held continuously across this loop: on
			 * a full send CQ, rvt_send_cq() -> rvt_error_qp() with
			 * RVT_QP_LOCK_STATE_S drops and retakes s_lock to
			 * honour r_lock -> s_lock ordering (rdmavt qp.c).
			 * Re-test the condition and re-derive wqe from s_last
			 * every iteration -- do not hoist either -- so a cursor
			 * moved in that window is observed, not walked past.
			 */
			flushed = 0;
			while (qp->s_last != READ_ONCE(qp->s_head) &&
			       flushed + rc < ROCE_PIO_TX_FLUSH_BUDGET) {
				enum ib_wc_status status = IB_WC_WR_FLUSH_ERR;

				wqe = rvt_get_swqe_ptr(qp, qp->s_last);
				if (rqp->hwp_error_pending &&
				    rqp->hwp_error_index == qp->s_last) {
					status = rqp->hwp_error_status;
					rqp->hwp_error_pending = false;
				}
				rvt_send_complete(qp, wqe, status,
						  RVT_QP_LOCK_STATE_S);
				flushed++;
			}
			rqp->roce->stats.tx_flush_wqe += flushed;
			ret = qp->s_last != READ_ONCE(qp->s_head) ?
				-EINPROGRESS : 0;
			goto unlock;
		}

		served_resp = false;
		rc = 0;
		/*
		 * IBTA gives READ responses no priority over sends: serve one
		 * response bundle, then give an eligible send one turn.
		 */
		if ((qp->s_flags & RVT_S_RESP_PENDING) &&
		    (!rqp->resp_yield_send || !roce_send_turn_ready(rqp))) {
			served_resp = true;
			rc = roce_send_read_response(rqp, priv);
			if (rc > 0)
				rqp->resp_yield_send =
					(qp->s_flags & RVT_S_RESP_PENDING) &&
					roce_send_turn_ready(rqp);
		}
		if (served_resp) {
			if (rc == -EAGAIN || rc == -ENOSPC) {
				ret = rc;
				goto unlock;
			}
			if (rc < 0)
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_S);
			if (!rc)
				rqp->resp_yield_send = false;
			ret = roce_turn_claim_progress(rqp);
			if (rc > 0) {
				packets += rc;
				if (packets < quantum &&
				    (rqp->resp_yield_send ||
				     ((qp->s_flags & RVT_S_RESP_PENDING) &&
				      rqp->sdma_resp_holds < rqp->roce->sdma_qp_bundles)))
					retry = true;
			}
			goto unlock;
		}

		if (rqp->replay_pending || qp->s_cur == READ_ONCE(qp->s_head) ||
		    (qp->s_flags & RVT_S_WAIT_RNR)) {
			if (roce_serve_resp(rqp, priv, &ret))
				goto unlock;
			goto unlock;
		}

		wqe = rvt_get_swqe_ptr(qp, qp->s_cur);
		if (qp->s_cur == qp->s_tail &&
		    (wqe->wr.send_flags & IB_SEND_FENCE) &&
		    qp->s_num_rd_atomic) {
			qp->s_flags |= RVT_S_WAIT_FENCE;
			if (roce_serve_resp(rqp, priv, &ret))
				goto unlock;
			goto unlock;
		}
		if (unlikely(rqp->order_pending) && !rqp->tx_in_progress &&
		    roce_order_write_blocked(rqp, wqe)) {
			qp->s_flags |= RVT_S_WAIT_FENCE;
			roce_serve_resp(rqp, priv, &ret);
			goto unlock;
		}
		send_turn = (qp->s_flags & RVT_S_RESP_PENDING) &&
			rqp->resp_yield_send;
		if (send_turn) {
			rqp->resp_yield_send = false;
			rqp->roce->stats.tx_resp_yield++;
		}
		if (wqe->wr.opcode == IB_WR_REG_MR ||
		    wqe->wr.opcode == IB_WR_LOCAL_INV) {
			int err = 0;

			if (WARN_ON_ONCE(!from_worker)) {
				ret = -EINPROGRESS;
				goto unlock;
			}

			/* Ordered LOCAL_INV and REG_MR effects must precede the next SWQE. */
			if (qp->s_cur != qp->s_tail ||
			    qp->s_last != qp->s_cur) {
				roce_serve_resp(rqp, priv, &ret);
				goto unlock;
			}
			if (wqe->wr.send_flags & RVT_SEND_REG_MR_DEFERRED) {
				/*
				 * RESET waits for tx_idle; the unchanged s_tail
				 * blocks ACK retirement while the worker drops
				 * s_lock to install the mapping.
				 */
				timed = false;
				spin_unlock_irqrestore(&qp->s_lock, flags);
				err = hfi2_roce_kmr_map_reg(wqe);
				spin_lock_irqsave(&qp->s_lock, flags);
				if (READ_ONCE(rqp->tx_cancelled) ||
				    !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK)) {
					ret = -EINPROGRESS;
					goto unlock;
				}
				err = hfi2_roce_kmr_publish_reg(qp, wqe, err);
			} else if (!(wqe->wr.send_flags & RVT_SEND_COMPLETION_ONLY)) {
				timed = false;
				spin_unlock_irqrestore(&qp->s_lock, flags);
				err = hfi2_roce_local_inv(qp, wqe);
				spin_lock_irqsave(&qp->s_lock, flags);
				if (READ_ONCE(rqp->tx_cancelled) ||
				    !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK)) {
					ret = -EINPROGRESS;
					goto unlock;
				}
			}
			if (++qp->s_cur >= qp->s_size)
				qp->s_cur = 0;
			if (++qp->s_tail >= qp->s_size)
				qp->s_tail = 0;
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe,
					  err ? IB_WC_LOC_PROT_ERR : IB_WC_SUCCESS,
					  RVT_QP_LOCK_STATE_S);
			if (err)
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_S);
			roce_request_emitter_close(rqp);
			ret = roce_turn_claim_progress(rqp);
			goto unlock;
		}
		if (roce_wqe_is_rd_atomic(wqe->wr.opcode)) {
			bool read = wqe->wr.opcode == IB_WR_RDMA_READ;
			bool new_request = qp->s_cur == qp->s_tail;
			bool read_write;
#if HFI2_DMS_ROCE_INJECT
			enum hfi2_dms_roce_emitter forced;
			bool forced_valid = roce_inject_request_emitter_get(&forced);
#endif

			if (new_request && qp->s_num_rd_atomic >= qp->s_max_rd_atomic) {
				qp->s_flags |= RVT_S_WAIT_RDMAR;
				roce_serve_resp(rqp, priv, &ret);
				goto unlock;
			}
			if (new_request)
				roce_priority_refresh(rqp);
			/*
			 * roce_requester_read_response() completes the READ
			 * with rvt_qp_complete_swqe(), which advances s_last by
			 * one from wherever it is.  An earlier SDMA WRITE that
			 * is wire-ACKed but still holds its bundle keeps s_last
			 * behind s_acked, so the READ's response would retire
			 * the WRITE's slot under the READ's wr_id.  Emit the
			 * READ only once every such bundle has drained.  An
			 * earlier READ's bundle cannot cause this: nothing
			 * advances s_acked past a READ but its own response,
			 * which completes it at s_last.
			 */
			if (rqp->sdma_ack_holds) {
				rqp->roce->stats.tx_sdma_read_req_hold_wait++;
				ret = -EAGAIN;
				roce_serve_resp(rqp, priv, &ret);
				goto unlock;
			}
			if (read && READ_ONCE(rqp->roce->hwp_pool.stopping) &&
			    rqp->read_hwp_windows[qp->s_cur]) {
				roce_serve_resp(rqp, priv, &ret);
				goto unlock;
			}
			read_write = read && new_request &&
				roce_read_write_eligible(rqp, priv, wqe, NULL, NULL, false);
			if (read && rqp->roce->hwp_pool.backend == HFI2_ROCE_HWP_DONOR &&
			    rqp->hwp_donor_holds) {
				struct hfi2_dms_roce_hwp_window *window =
					rqp->read_hwp_windows[qp->s_cur];

				if (window && window->state == HFI2_ROCE_HWP_ACTIVE &&
				    (!READ_ONCE(rqp->roce->hwp_pool.token->live) ||
				     READ_ONCE(rqp->roce->hwp_pool.stopping) ||
				     window->epoch != rqp->hwp_epoch ||
				     window->wqe_psn != wqe->psn)) {
					rvt_error_qp(qp, IB_WC_LOC_PROT_ERR, RVT_QP_LOCK_STATE_S);
					goto unlock;
				}
				if (!window || window->state != HFI2_ROCE_HWP_ACTIVE) {
					rqp->donor_waiting = true;
					ret = -EINPROGRESS;
					roce_serve_resp(rqp, priv, &ret);
					goto unlock;
				}
			}
			if (read && new_request && !read_write &&
			    rqp->roce->hwp_pool.backend == HFI2_ROCE_HWP_DONOR)
				roce_wqe_set_read_software_reply(rqp, wqe);
			if (read && !roce_prefer_pio_request(rqp, wqe) &&
			    (rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_UNSET ||
			     rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_SDMA)
#if HFI2_DMS_ROCE_INJECT
			    && !(forced_valid &&
				 forced == HFI2_DMS_ROCE_EMITTER_PIO)
#endif
			    ) {
				if (unlikely(!from_worker)) {
					ret = -EINPROGRESS;
					goto unlock;
				}
				rc = roce_sdma_send_read_request(rqp, priv, wqe,
							 qp->s_cur);
				if (!rc) {
					packets++;
					ret = roce_requester_rd_atomic_sent(rqp, wqe,
									      new_request, true);
					if (ret == -EINPROGRESS && packets < quantum)
						retry = true;
					goto unlock;
				}
				if (rqp->request_sdma_accepted ||
				    rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_SDMA ||
				    !roce_request_pio_fallback_ok(rqp, rc)) {
					rqp->roce->stats.tx_sdma_read_req_decline++;
					ret = -EAGAIN;
					if (roce_serve_resp(rqp, priv, &ret))
						goto unlock;
					goto unlock;
				}
				rqp->roce->stats.tx_sdma_read_req_decline++;

#if HFI2_DMS_ROCE_INJECT
				if (forced_valid &&
				    forced == HFI2_DMS_ROCE_EMITTER_SDMA) {
					ret = -EAGAIN;
					if (roce_serve_resp(rqp, priv, &ret))
						goto unlock;
					goto unlock;
				}
#endif
			}
			if (!roce_request_emitter_select(rqp,
						 HFI2_DMS_ROCE_EMITTER_PIO,
						 HFI2_DMS_ROCE_SDMA_ENGINE_NONE)) {
				ret = -EAGAIN;
				if (roce_serve_resp(rqp, priv, &ret))
					goto unlock;
				goto unlock;
			}
			rc = read ? roce_send_read_request(rqp, priv, wqe, from_worker) :
				    roce_send_atomic_request(rqp, priv, wqe, from_worker);
			if (rc == -EAGAIN || rc == -ENOSPC) {
				ret = rc;
				if (roce_serve_resp(rqp, priv, &ret))
					goto unlock;
				goto unlock;
			}
			if (rc) {
				if (!from_worker) {
					ret = -EINPROGRESS;
					goto unlock;
				}
				roce_request_error(rqp, wqe);
				ret = -EINPROGRESS;
				goto unlock;
			}
			packets++;
			ret = roce_requester_rd_atomic_sent(rqp, wqe, new_request,
							    from_worker);
			if (from_worker && ret == -EINPROGRESS && packets < quantum)
				retry = true;
			goto unlock;

		}

		if (wqe->wr.opcode != IB_WR_SEND &&
		    wqe->wr.opcode != IB_WR_SEND_WITH_IMM &&
		    wqe->wr.opcode != IB_WR_SEND_WITH_INV &&
		    !roce_req_is_write(wqe->wr.opcode)) {
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe, IB_WC_LOC_QP_OP_ERR,
				      RVT_QP_LOCK_STATE_S);
			ret = -EINPROGRESS;
			goto unlock;
		}
		/*
		 * Plain RDMA WRITE consumes no responder receive WQE, so it is
		 * outside the SEND/WRITE_WITH_IMM SSN credit window.  Keep s_lsn
		 * aligned below when the new WRITE reaches the wire, matching
		 * hfi2_make_rc_req().
		 */
		if (wqe->wr.opcode != IB_WR_RDMA_WRITE &&
		    !rvt_rc_credit_avail(qp, wqe)) {
			if (roce_serve_resp(rqp, priv, &ret))
				goto unlock;
			goto unlock;
		}
		if (!rqp->tx_in_progress) {
			roce_priority_refresh(rqp);
			roce_tx_snapshot_init(rqp, wqe, qp->s_cur, qp->pmtu);
			if (rqp->resume_pending &&
			    rqp->resume_wqe_idx == qp->s_cur) {
				u32 skip = ((rqp->resume_psn - wqe->psn) &
					    HFI2_ROCE_PSN_MASK) * qp->pmtu;

				rqp->resume_pending = false;
				if (skip < rqp->tx_length) {
					rqp->tx_off = skip;
					rqp->tx_psn = rqp->resume_psn;
					rqp->roce->stats.tx_replay_resume++;
				}
			}
		}
		if (qp->s_cur != rqp->tx_wqe_idx) {
			roce_tx_snapshot_release(rqp);
			ret = roce_turn_claim_progress(rqp);
			goto unlock;
		}

		if (!roce_prefer_pio_request(rqp, wqe) &&
		    (rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_UNSET ||
		     rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_SDMA)) {
#if HFI2_DMS_ROCE_INJECT
			enum hfi2_dms_roce_emitter forced;

			if (roce_inject_request_emitter_get(&forced) &&
			    forced == HFI2_DMS_ROCE_EMITTER_PIO)
				goto request_pio;
#endif
			if (unlikely(!from_worker)) {
				ret = -EINPROGRESS;
				goto unlock;
			}
			rqp->roce->stats.tx_sdma_arm_try++;
			rc = roce_sdma_send_bundle(rqp, priv, wqe);
			if (rc > 0) {
				packets += rc;
				if (rqp->tx_off < rqp->tx_length) {
					ret = -EINPROGRESS;
					retry = true;
					goto unlock;
				}

				goto request_complete;
			}
			if (rc != -EAGAIN && rc != -E2BIG && rc != -ENOSPC &&
			    rc != -EOPNOTSUPP) {
				roce_request_error(rqp, wqe);
				ret = -EINPROGRESS;
				goto unlock;
			}
			if (rqp->request_sdma_accepted ||
			    rqp->request_emitter == HFI2_DMS_ROCE_EMITTER_SDMA ||
			    !roce_request_pio_fallback_ok(rqp, rc)) {
				ret = -EAGAIN;
				if (roce_serve_resp(rqp, priv, &ret))
					goto unlock;
				goto unlock;
			}
#if HFI2_DMS_ROCE_INJECT
			if (roce_inject_request_emitter_get(&forced) &&
			    forced == HFI2_DMS_ROCE_EMITTER_SDMA) {
				ret = -EAGAIN;
				if (roce_serve_resp(rqp, priv, &ret))
					goto unlock;
				goto unlock;
			}
#endif
		}
#if HFI2_DMS_ROCE_INJECT
request_pio:
#endif
		if (!roce_request_emitter_select(rqp,
					 HFI2_DMS_ROCE_EMITTER_PIO,
					 HFI2_DMS_ROCE_SDMA_ENGINE_NONE)) {
			ret = -EAGAIN;
			if (roce_serve_resp(rqp, priv, &ret))
				goto unlock;
			goto unlock;
		}

		roce_tx_sge_sync(rqp);
		next_ss = rqp->tx_ss;
		seg = min(rqp->tx_length - rqp->tx_off, rqp->tx_pmtu);
		first = rqp->tx_off == 0;
		last = rqp->tx_off + seg >= rqp->tx_length;
		rc = roce_send_one_packet(rqp, priv, &next_ss, seg, first, last,
			  rqp->tx_psn, from_worker);

		if (rc == -EAGAIN || rc == -ENOSPC) {
			ret = rc;
			if (roce_serve_resp(rqp, priv, &ret))
				goto unlock;
			goto unlock;
		}
		if (rc && !from_worker) {
			ret = -EINPROGRESS;
			goto unlock;
		}
		if (rc == -ECOMM) {
			rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_S);
			ret = -ECOMM;
			goto unlock;
		}
		if (rc) {
			roce_request_error(rqp, wqe);
			ret = -EINPROGRESS;
			goto unlock;
		}

		rqp->tx_ss = next_ss;
		rqp->tx_off += seg;
		rqp->tx_ss_off = rqp->tx_off;
		rqp->tx_psn = roce_psn(rqp->tx_psn + 1);
		packets++;
		if (from_worker)
			rqp->roce->stats.tx_worker_packets++;
		if (rqp->tx_off < rqp->tx_length) {
			retry = true;
			ret = roce_turn_claim_progress(rqp);
			goto unlock;
		}

request_complete:
		qp->s_psn = rqp->tx_psn;
		/*
		 * s_tail marks the newest WQE ever handed to the wire; s_cur
		 * marks the one being sent now.  A retransmit rewinds only
		 * s_cur (roce_rewind_to_acked(), hfi2_dms_roce_restart()), so
		 * advancing s_tail on every last packet would step it again
		 * for work it already covered and carry it past s_head.  The
		 * retire loops are bounded by s_tail (s_acked != s_tail), so
		 * an overshot s_tail makes them walk never-posted ring slots
		 * and drop an MR reference per stale SGE.  Gate it on the WQE
		 * being new, as the READ arm above and OPA's hfi2_make_rc_req()
		 * newreq do.  Read s_cur before it advances, under s_lock:
		 * nothing else moves s_tail while this WQE is in flight --
		 * rvt_post_send() moves s_head, and rvt_send_complete() only
		 * pulls s_tail forward when it equals the retiring s_last.
		 */
		if (qp->s_cur == qp->s_tail) {
			if (wqe->wr.opcode == IB_WR_SEND_WITH_INV)
				rqp->order_pending++;
			if (wqe->wr.opcode == IB_WR_RDMA_WRITE &&
			    !(qp->s_flags & RVT_S_UNLIMITED_CREDIT))
				qp->s_lsn++;
			if (++qp->s_tail >= qp->s_size)
				qp->s_tail = 0;
		}
		if (++qp->s_cur >= qp->s_size)
			qp->s_cur = 0;
		if (!(qp->s_flags & RVT_S_TIMER))
			rvt_add_retry_timer(qp);
		roce_tx_stat_add(&rqp->roce->stats.tx_send_wqe,
				 &rqp->roce->inline_stats.tx_send_wqe, 1, from_worker);
		roce_tx_snapshot_release(rqp);
		roce_request_emitter_close(rqp);
		ret = roce_turn_claim_progress(rqp);
		/*
		 * Go on to the QP's next WQE while the turn has quantum left,
		 * rather than requeueing it behind every other ready QP and
		 * paying a dequeue, a requeue and a lock round trip per WQE.
		 * The quantum still bounds the turn, so a QP posting a long
		 * chain of small WQEs cannot starve the others.
		 */
		if (from_worker && ret == -EINPROGRESS && packets < quantum) {
			rqp->roce->stats.tx_turn_next_wqe++;
			retry = true;
		}
		goto unlock;

unlock:
		if (from_worker && (ret == -EINPROGRESS || !ret) && !rqp->ack_pending &&
		    !(qp->s_flags & RVT_S_RESP_PENDING) &&
		    !READ_ONCE(rqp->tx_cancelled) &&
		    (ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) &&
		    roce_donor_wait_pending(rqp)) {
			rqp->donor_waiting = true;
			rqp->donor_stalled = true;
			retry = false;
			ret = 0;
		}
		if (timed) {
			lock_end_ns = local_clock();
			hold_ns = lock_end_ns - lock_start_ns;
			rqp->roce->stats.s_lock_hold_samples++;
			if (hold_ns > rqp->roce->stats.s_lock_hold_max_ns)
				rqp->roce->stats.s_lock_hold_max_ns = hold_ns;
			if (hold_ns > 100000)
				rqp->roce->stats.s_lock_hold_over_100us++;
		}
		spin_unlock_irqrestore(&qp->s_lock, flags);
		if (from_worker && READ_ONCE(rqp->rif_queued))
			roce_rif_progress(rqp->roce);
		if (retry)
			continue;
		return ret;
	}

	return -EINPROGRESS;
}

bool hfi2_dms_roce_enqueue(struct rvt_qp *qp)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	struct hfi2_dms_roce *roce;
	unsigned long flags;
	bool queued = false;

	if (!rqp || !roce_qp_backend(rqp) || !rqp->roce->active)
		return false;
	roce = rqp->roce;

	/*
	 * Order send publication before membership loads; the worker's barrier
	 * after clearing runq_queued prevents a store-buffer lost wakeup.
	 */
	smp_mb();
	if (READ_ONCE(rqp->runq_queued) || READ_ONCE(rqp->pio_wait_queued) ||
	    READ_ONCE(rqp->sdma_wait_queued) ||
	    READ_ONCE(roce->svc->stop_scheduling))
		return false;
	spin_lock_irqsave(&roce->runq_lock, flags);
	if (!roce->svc->stop_scheduling && !rqp->runq_queued &&
	    !rqp->pio_wait_queued && !rqp->sdma_wait_queued) {
		rqp->runq_queued = true;
		rvt_get_qp(qp);
		/* Peeked locklessly: hfi2_bulksvc_schedule() must follow. */
		list_add_tail(&rqp->runq_node, &roce->runq);
		queued = true;
	}
	spin_unlock_irqrestore(&roce->runq_lock, flags);

	if (queued)
		hfi2_bulksvc_schedule(roce->svc);
	return queued;
}

bool hfi2_dms_roce_sdma_busy(struct hfi2_dms_roce *roce)
{
	if (!roce || !roce->active)
		return false;
	return atomic_read(&roce->sdma_local_holds) > 0;
}

void hfi2_dms_roce_kick_send(struct rvt_qp *qp)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	bool resched;
	int rc;

	if (!rqp || !roce_qp_backend(rqp) || !rqp->roce->active)
		return;
	/* Injection borrows txbuf outside the per-QP send-turn guard. */
	if (HFI2_DMS_ROCE_INJECT) {
		hfi2_dms_roce_enqueue(qp);
		return;
	}
	if (roce_qp_is_ud(qp) ||
	    READ_ONCE(rqp->pio_wait_queued) || READ_ONCE(rqp->sdma_wait_queued) ||
	    unlikely(READ_ONCE(roce_fail_tx_pio_once) ||
		     READ_ONCE(roce_fail_tx_pio_period)) ||
	    READ_ONCE(rqp->runq_queued) || READ_ONCE(rqp->sdma_req_holds) ||
	    READ_ONCE(rqp->ack_pending) ||
	    (READ_ONCE(qp->s_flags) & RVT_S_RESP_PENDING) ||
	    !roce_tx_worker_begin(rqp)) {
		hfi2_dms_roce_enqueue(qp);
		return;
	}

	rc = roce_do_send(qp, false);
	resched = roce_tx_worker_end(rqp);
	if (resched || rc == -ENOSPC ||
	    rc == -EAGAIN || rc == -EINPROGRESS)
		hfi2_dms_roce_enqueue(qp);
}

void hfi2_dms_roce_dequeue_qp(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce;
	unsigned long runq_flags, state_flags;
	bool drop = false;

	if (!rqp || !rqp->roce || !rqp->roce->initialized)
		return;
	roce = rqp->roce;
	spin_lock_irqsave(&roce->runq_lock, runq_flags);
	spin_lock_irqsave(&rqp->tx_state_lock, state_flags);
	if (rqp->runq_queued) {
		list_del_init(&rqp->runq_node);
		rqp->runq_queued = false;
		drop = true;
	}
	if (rqp->sdma_wait_queued) {
		list_del_init(&rqp->sdma_wait_node);
		rqp->sdma_wait_queued = false;
		drop = true;
	}
	if (rqp->pio_wait_queued) {
		list_del_init(&rqp->pio_wait_node);
		rqp->pio_wait_queued = false;
		drop = true;
		if (list_empty(&roce->pio_waitq) && roce->pio_intr_armed) {
			roce->pio_intr_armed = false;
			hfi2_sc_wantpiobuf_intr(roce->sc, 0);
		}
	}
	spin_unlock_irqrestore(&rqp->tx_state_lock, state_flags);
	spin_unlock_irqrestore(&roce->runq_lock, runq_flags);
	if (drop)
		rvt_put_qp(rqp->qp);
}

void hfi2_dms_roce_cancel_qp(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;

	if (!rqp)
		return;
	roce_rif_cancel(rqp);
	spin_lock_irqsave(&rqp->tx_state_lock, flags);
	WRITE_ONCE(rqp->sdma_admission_stopped, true);
	rqp->tx_cancelled = true;
	spin_unlock_irqrestore(&rqp->tx_state_lock, flags);
	hfi2_dms_roce_dequeue_qp(rqp);
}

static void roce_sdma_terminalize_qp(struct hfi2_dms_roce_qp *rqp)
{
	unsigned int i;

	if (!rqp->sdma_xfers)
		return;

	for (i = 0; i < rqp->sdma_xfer_count; i++) {
		if (!rqp->sdma_xfers[i].active)
			continue;
		WARN_ON_ONCE(rqp->sdma_xfers[i].local_holds);
		rqp->sdma_xfers[i].terminal = true;
		roce_sdma_xfer_recycle(&rqp->sdma_xfers[i]);
	}
}

static void roce_hwp_wait_donor_holds(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long start = jiffies;
	unsigned long warn = start +
		HFI2_ROCE_HWP_CLEANUP_WARN_MS * HZ / MSEC_PER_SEC;
	unsigned long next_fence = start + msecs_to_jiffies(HFI2_ROCE_HWP_CLEANUP_MS);
	u32 holds;

	while ((holds = READ_ONCE(rqp->hwp_donor_holds))) {
		if (time_after_eq(jiffies, next_fence) ||
		    !READ_ONCE(rqp->roce->active) ||
		    READ_ONCE(rqp->roce->svc->stop_scheduling)) {
			int ret = roce_hwp_pool_fence(rqp->roce);

			next_fence = jiffies + msecs_to_jiffies(20);
			if (!ret) {
				WRITE_ONCE(rqp->roce->hwp_pool.reservation.poisoned, true);
				roce_hwp_donor_recover(rqp);
				roce_hwp_cleanup_count_fence(rqp);
			} else {
				atomic64_inc(&rqp->roce->fence_stats.hwp_cleanup_fence_fail);
			}
		}
		if (time_after_eq(jiffies, warn)) {
			dd_dev_warn_ratelimited(rqp->dd,
						"roce: QP %u destroy waiting %u ms for %u donor holds\n",
						rqp->qp->ibqp.qp_num,
						jiffies_to_msecs(jiffies - start), holds);
			warn = jiffies +
				HFI2_ROCE_HWP_CLEANUP_WARN_MS * HZ / MSEC_PER_SEC;
		}
		usleep_range(1000, 2000);
	}
}

static void roce_hwp_wait_cleanup(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long start = jiffies;

	while (!wait_for_completion_timeout(&rqp->hwp_cleanup_idle,
					    msecs_to_jiffies(HFI2_ROCE_HWP_CLEANUP_WARN_MS)))
		dd_dev_warn(rqp->dd,
			    "roce: QP %u destroy waiting %u ms for READ placement drain\n",
			    rqp->qp->ibqp.qp_num,
			    jiffies_to_msecs(jiffies - start));
}

void hfi2_dms_roce_quiesce_qp(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags, sflags;

	if (!rqp)
		return;
	hfi2_dms_roce_cancel_qp(rqp);
	if (rqp->roce) {
		/* Retire hardware before remove_qp() waits for our queued QP refs. */
		spin_lock_irqsave(&rqp->qp->r_lock, flags);
		spin_lock_irqsave(&rqp->qp->s_lock, sflags);
		roce_hwp_hold_rx(rqp);
		roce_hwp_cleanup_start(rqp);
		roce_lbs_invalidate(rqp, false);
		roce_rif_release(rqp);
		spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
		spin_unlock_irqrestore(&rqp->qp->r_lock, flags);
		roce_rif_wait(rqp);
		roce_hwp_wait_cleanup(rqp);
		while (READ_ONCE(rqp->hwp_fencing)) {
			dd_dev_warn_ratelimited(rqp->dd,
						"roce: QP %u waiting for shared PASID fence\n",
						rqp->qp->ibqp.qp_num);
			msleep(20);
		}
		if (rqp->roce->hwp_pool.backend == HFI2_ROCE_HWP_DONOR)
			roce_hwp_wait_donor_holds(rqp);
		/* Terminal fence callbacks can queue cleanup after the first join. */
		roce_rif_wait(rqp);
		{
			bool entered = roce_rif_enter(rqp->roce);

			roce_rif_flush_invalidations(rqp->roce);
			roce_rif_leave(rqp->roce, entered);
		}
	}
	spin_lock_irqsave(&rqp->qp->r_lock, flags);
	roce_rx_helpers_wait_qp(rqp);
	spin_unlock_irqrestore(&rqp->qp->r_lock, flags);
	wait_for_completion(&rqp->tx_idle);
	if (rqp->sdma_local_holds && rqp->roce) {
		struct hfi2_dms_roce *roce = rqp->roce;
		bool worker_gone;

		WRITE_ONCE(rqp->sdma_admission_stopped, true);
		spin_lock_irqsave(&roce->sdma_cancel_lock, flags);
		if (!rqp->sdma_cancel_requested) {
			reinit_completion(&rqp->sdma_cancel_done);
			rqp->sdma_cancel_requested = true;
			/*
			 * Peeked locklessly: the worker is queued below,
			 * except when the service is stopping.
			 */
			list_add_tail(&rqp->sdma_cancel_node, &roce->sdma_cancel);
		}
		spin_unlock_irqrestore(&roce->sdma_cancel_lock, flags);

		worker_gone = READ_ONCE(roce->svc->worker_exited);
		if (!worker_gone) {
			if (!READ_ONCE(roce->svc->stop_scheduling))
				hfi2_bulksvc_schedule(roce->svc);
			if (READ_ONCE(roce->svc->stop_scheduling)) {
				wait_for_completion(&roce->svc->worker_exited_done);
				worker_gone = true;
			}
		}
		/*
		 * A live worker will list-process this QP itself. A worker that
		 * is gone may have made its last pass before this QP was listed,
		 * so finish the list here.
		 */
		if (worker_gone)
			roce_sdma_cancel_requested(roce);
		wait_for_completion(&rqp->sdma_cancel_done);
	}
	if (rqp->roce && !READ_ONCE(rqp->roce->svc->stop_scheduling))
		wait_for_completion(&rqp->sdma_local_zero);
	roce_sdma_terminalize_qp(rqp);
	spin_lock_irqsave(&rqp->qp->s_lock, flags);
	if (rqp->tx_in_progress)
		roce_tx_snapshot_release(rqp);
	spin_unlock_irqrestore(&rqp->qp->s_lock, flags);
}

void hfi2_dms_roce_reset_qp(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;

	if (!rqp)
		return;

	lockdep_assert_held(&rqp->qp->s_lock);
	if (rqp->tomb_recv_active) {
		rqp->tomb_r_psn = rqp->qp->r_psn;
		rqp->tomb_recv_active = false;
	}
	rqp->ack_pending = false;
	rqp->ack_psn = 0;
	rqp->ack_syndrome = 0;
	rqp->rif_nak_pending = false;
	rqp->write_gap.active = false;
	rqp->order_pending = 0;
	rqp->qp->s_flags &= ~RVT_S_WAIT_FENCE;
	rqp->resp_middle_valid = false;

	/* quiesce_qp() completed the sleeping drain before this locked hook. */
	WARN_ON_ONCE(rqp->sdma_local_holds);
	if (!rqp->sdma_local_holds)
		roce_sdma_terminalize_qp(rqp);
	spin_lock_irqsave(&rqp->tx_state_lock, flags);
	rqp->tx_cancelled = false;
	if (rqp->roce) {
		spin_lock(&rqp->roce->rif_lock);
		WARN_ON_ONCE(rqp->rif_queued || rqp->rif_busy || rqp->rif_arm_kind);
		rqp->rif_cancelled = false;
		spin_unlock(&rqp->roce->rif_lock);
	}
	rqp->hwp_error_pending = false;
	rqp->hwp_rx_blocked = false;
	rqp->hwp_fence_required = false;
	rqp->hwp_cleanup_counted = false;
	WRITE_ONCE(rqp->sdma_admission_stopped, false);
	rqp->request_emitter = HFI2_DMS_ROCE_EMITTER_UNSET;
	rqp->request_engine_idx = roce_sdma_engine_pick(rqp);
	rqp->resp_emitter = !roce_qp_is_ud(rqp->qp) && roce_read_resp_sdma &&
		rqp->request_engine_idx != HFI2_DMS_ROCE_SDMA_ENGINE_NONE ?
		HFI2_DMS_ROCE_EMITTER_SDMA : HFI2_DMS_ROCE_EMITTER_PIO;
	rqp->request_epoch = 0;
	rqp->resp_generation++;
	rqp->request_sdma_accepted = false;
	rqp->resp_yield_send = false;
	rqp->replay_pending = false;
	rqp->replay_psn = 0;
	rqp->resume_pending = false;
	rqp->replay_action = HFI2_DMS_ROCE_REPLAY_NONE;
	rqp->replay_rnr_aeth = 0;

	spin_unlock_irqrestore(&rqp->tx_state_lock, flags);

	if (!roce_qp_is_ud(rqp->qp)) {
		rqp->lbs_burst = false;
		rqp->imm_rnr_pending = false;
		roce_lbs_invalidate(rqp, false);
		roce_rif_release(rqp);
	}
}

/*
 * The tail update follows the payload placement into host memory. Capture its
 * packet count after invalidating EAL entries, then wait for the worker to
 * consume through that sequence after the posted writes are flushed.
 */
void hfi2_dms_roce_rx_mark(struct hfi2_dms_roce *roce,
			   struct hfi2_dms_roce_rx_mark *mark)
{
	u8 i;

	memset(mark, 0, sizeof(*mark));
	if (!roce || !READ_ONCE(roce->active))
		return;

	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
		struct hfi2_ctxtdata *rcd = roce->rcd[i];
		u32 head, tail, rsize, rshift;
		s32 pending;
		u64 state;

		if (!rcd)
			continue;
		rsize = get_hdrqentsize(rcd);
		/* rsize is always 2^N, see hfi2_encode_rcv_header_entry_size() */
		rshift = __ffs(rsize);
		/*
		 * One load gives a (consumed, head) pair that the worker
		 * published together, so the pair cannot be torn.  The tail
		 * must be read after it: every header between this head and
		 * the tail is then still unconsumed or counted in consumed.
		 * The hardware only holds the tail within one ring of the head
		 * it was given, so if the worker published a newer head while
		 * the (slow) CSR read was in flight the tail may have wrapped
		 * past the head we loaded.  Reload and retry in that case.
		 * Pairs with the release store in roce_poll_rcd().
		 */
		do {
			/* Acquire: pairs with the release in roce_poll_rcd(). */
			state = smp_load_acquire(&roce->rx_rcd_state[i]);
			head = roce_rx_state_head(state);
			tail = (u32)read_uctxt_csr(roce->dd, rcd->ctxt,
						   roce->dd->params->rcv_hdr_tail_reg);
		} while (READ_ONCE(roce->rx_rcd_state[i]) != state);

		/*
		 * Offsets are below the ring size, so a negative delta is a
		 * wrap: add maxcnt, the ring size in dwords (entries << rshift).
		 */
		pending = tail - head;
		if (unlikely(pending < 0))
			pending += get_hdrq_cnt(rcd) << rshift;
		/*
		 * Entries are rsize apart, so this is a corrupt CSR.  Round up
		 * rather than skip the RCD, so the wait is long, not absent.
		 */
		if (WARN_ON_ONCE(pending & (rsize - 1)))
			pending = ALIGN(pending, rsize);
		mark->target[i] = roce_rx_state_consumed(state) +
				  (pending >> rshift);
		mark->valid[i] = true;
	}
}

int hfi2_dms_roce_wait_rx(struct hfi2_dms_roce *roce,
			 const struct hfi2_dms_roce_rx_mark *mark)
{
	unsigned long deadline;
	u8 i;

	if (!roce || !READ_ONCE(roce->active))
		return -ENODEV;
	for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++)
		if (!mark->valid[i])
			return -EIO;

	deadline = jiffies + msecs_to_jiffies(100);
	for (;;) {
		bool done = true;

		for (i = 0; i < HFI2_DMS_ROCE_RCD_COUNT; i++) {
			u64 state;
			u32 consumed;

			/* Acquire: pairs with the release in roce_poll_rcd(). */
			state = smp_load_acquire(&roce->rx_rcd_state[i]);
			consumed = roce_rx_state_consumed(state);
			/* The counter is free-running: compare modulo 2^32. */
			if (mark->valid[i] &&
			    (s32)(consumed - mark->target[i]) < 0) {
				done = false;
				break;
			}
		}
		if (done)
			return 0;
		if (time_after_eq(jiffies, deadline) ||
		    !READ_ONCE(roce->active) ||
		    READ_ONCE(roce->svc->stop_scheduling))
			break;

		hfi2_bulksvc_schedule(roce->svc);
		usleep_range(50, 100);
	}

	dd_dev_warn_ratelimited(roce->dd,
				"roce: timed out waiting for pre-invalidate receive reports\n");
	return -ETIMEDOUT;
}

void hfi2_dms_roce_drain(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_qp *rqp;
	unsigned long flags;

	if (!roce)
		return;
	if (!roce->initialized)
		return;

	while (!list_empty(&roce->read_restart)) {
		rqp = list_first_entry(&roce->read_restart,
				       struct hfi2_dms_roce_qp, read_restart_node);
		list_del_init(&rqp->read_restart_node);
		rvt_put_qp(rqp->qp);
	}
	for (;;) {
		spin_lock_irqsave(&roce->runq_lock, flags);
		if (list_empty(&roce->runq)) {
			spin_unlock_irqrestore(&roce->runq_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->runq, struct hfi2_dms_roce_qp,
					       runq_node);
		list_del_init(&rqp->runq_node);
		rqp->runq_queued = false;
		spin_unlock_irqrestore(&roce->runq_lock, flags);
		rvt_put_qp(rqp->qp);
	}
	for (;;) {
		spin_lock_irqsave(&roce->runq_lock, flags);
		if (list_empty(&roce->sdma_waitq)) {
			spin_unlock_irqrestore(&roce->runq_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->sdma_waitq,
				       struct hfi2_dms_roce_qp, sdma_wait_node);
		list_del_init(&rqp->sdma_wait_node);
		rqp->sdma_wait_queued = false;
		spin_unlock_irqrestore(&roce->runq_lock, flags);
		rvt_put_qp(rqp->qp);
	}
	for (;;) {
		spin_lock_irqsave(&roce->runq_lock, flags);
		if (list_empty(&roce->pio_waitq)) {
			if (roce->pio_intr_armed) {
				roce->pio_intr_armed = false;
				hfi2_sc_wantpiobuf_intr(roce->sc, 0);
			}
			spin_unlock_irqrestore(&roce->runq_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->pio_waitq,
					       struct hfi2_dms_roce_qp,
					       pio_wait_node);
		list_del_init(&rqp->pio_wait_node);
		rqp->pio_wait_queued = false;
		spin_unlock_irqrestore(&roce->runq_lock, flags);
		rvt_put_qp(rqp->qp);
	}
}

void hfi2_dms_roce_pio_available(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_qp *rqp;
	unsigned long flags;
	bool wake = false;

	if (!roce || !READ_ONCE(roce->active))
		return;

	spin_lock_irqsave(&roce->runq_lock, flags);
	if (roce->pio_intr_armed) {
		roce->pio_intr_armed = false;
		hfi2_sc_wantpiobuf_intr(roce->sc, 0);
	}
	while (!list_empty(&roce->pio_waitq)) {
		rqp = list_first_entry(&roce->pio_waitq,
					       struct hfi2_dms_roce_qp,
					       pio_wait_node);
		list_del_init(&rqp->pio_wait_node);
		rqp->pio_wait_queued = false;
		if (rqp->tx_cancelled) {
			rvt_put_qp(rqp->qp);
			continue;
		}
		rqp->runq_queued = true;
		/* Peeked locklessly: hfi2_bulksvc_schedule() must follow. */
		list_add_tail(&rqp->runq_node, &roce->runq);
		wake = true;
	}
	spin_unlock_irqrestore(&roce->runq_lock, flags);
	if (wake)
		hfi2_bulksvc_schedule(roce->svc);
}


/*
 * Locate the EAL ingress header for a bypass frame.
 *
 * The RSM rule splits bypass_hdr_size dwords into the header queue and leaves
 * the rest in the eager buffer, so the header and the frame are in separate
 * regions: the eager buffer starts at the Ethernet header, and the ingress
 * header is only reachable through the RHF's header-queue offset.  Duplicated
 * from the Ethernet receive path (eth_rx.c), which does the same thing for the
 * Type 0 overlay.
 */
static const struct eal_ingress_header *
roce_ingress_header(struct hfi2_ctxtdata *rcd, __le32 *rhf_addr)
{
	u32 offset = rhf_hdrq_offset(rhf_to_cpu(rhf_addr));

	return (const struct eal_ingress_header *)
		(rhf_addr - rcd->rhf_offset + offset);
}

static void roce_rx_placement_report(
	struct hfi2_dms_roce *roce, u8 rcd_idx,
	const struct eal_ingress_vrma_header *ih);

static void roce_rx_qp_unlock(struct hfi2_dms_roce *roce);
static void roce_restart_read_progress(struct hfi2_dms_roce *roce);

/*
 * Publish (consumed, head) for hfi2_dms_roce_rx_mark().  This must happen
 * BEFORE the matching RcvHdrHead CSR write: the hardware keeps its tail from
 * reaching the head in that CSR, so while the published head is never behind
 * the CSR the tail stays within one ring of it and rx_mark() can tell how many
 * headers are pending.  A published head that is ahead of the CSR is harmless,
 * since the tail is always at or past every header already processed.
 */
static void roce_rx_state_publish(struct hfi2_dms_roce *roce, u8 rcd_idx,
				  u32 consumed, u32 head)
{
	u64 state = roce_rx_state_pack(consumed, head);

	/* Release: pairs with the acquire loads in rx_mark()/wait_rx(). */
	smp_store_release(&roce->rx_rcd_state[rcd_idx], state);
}

static void roce_rx_rif_progress(struct hfi2_dms_roce *roce)
{
	struct rvt_qp *qp = roce->rx_locked_qp;
	struct hfi2_dms_roce_qp *rqp;

	if (!qp)
		return;
	rqp = to_roce_priv(qp)->roce_qp;
	if (likely(!READ_ONCE(rqp->rif_queued)))
		return;
	/* Only this QP's continuation may break its packet/RCU lock batch. */
	roce_rx_qp_unlock(roce);
	roce_rif_progress(roce);
}

static u32 roce_poll_rcd(struct hfi2_dms_roce *roce, u8 rcd_idx, u32 budget)
{
	struct hfi2_ctxtdata *rcd;
	u32 rsize, maxcnt, rhqoff, base;
	__le32 *rhf_addr;
	u64 rhf;
	u32 processed = 0;
	u8 updegr = 0;
	u32 etail = (u32)-1;

	if (WARN_ON_ONCE(rcd_idx >= HFI2_DMS_ROCE_RCD_COUNT) || !budget)
		return 0;
	rcd = roce->rcd[rcd_idx];
	if (WARN_ON_ONCE(!rcd))
		return 0;
	roce_rx_helpers_kick(roce);
	roce_rx_helpers_retire(roce);
	roce_rx_usrhead_retire(roce, rcd_idx, rcd);
	WRITE_ONCE(roce->rx_q.filling, 1);

	rsize = get_hdrqentsize(rcd);
	maxcnt = get_hdrq_cnt(rcd) * rsize;
	rhqoff = hfi2_rcd_head(rcd);
	/* Single writer: this worker is the only one that updates the state. */
	base = roce_rx_state_consumed(roce->rx_rcd_state[rcd_idx]);
	/*
	 * Only this function moves rcd->head and it always publishes the
	 * same head, so a difference means the head was reset behind our
	 * back (SPC freeze recovery restarts the RCD at 0).  Follow it, or
	 * rx_mark() would pair the stale head with the restarted tail.
	 */
	if (rhqoff != roce_rx_state_head(roce->rx_rcd_state[rcd_idx]))
		roce_rx_state_publish(roce, rcd_idx, base, rhqoff);
	rhf_addr = (__le32 *)rcd->rcvhdrq + rhqoff + rcd->rhf_offset;
	rhf = rhf_to_cpu(rhf_addr);

	if (likely(jkr_rhf_rcv_seq(rhf) != rcd->seq_cnt)) {
		WRITE_ONCE(roce->rx_q.filling, 0);
		roce->stats.rx_rcd_empty_polls[rcd_idx]++;
		return 0;
	}

	/* RoCE runs on CN5000/CN6000 only, whose RHF carries the JKR layout. */
	while (jkr_rhf_rcv_seq(rhf) == rcd->seq_cnt && processed < budget) {
		const struct eal_ingress_header *ih =
			roce_ingress_header(rcd, rhf_addr);
		u32 rcv_type = rhf_rcv_type(rhf);
		u32 next = rhqoff + rsize;
		bool l2_type_16b;

		if (next >= maxcnt)
			next = 0;
		prefetch((__le32 *)rcd->rcvhdrq + next + rcd->rhf_offset);
		if (jkr_rhf_rhe_valid(rhf)) {
			if (rcv_type == RHF_RCV_TYPE_ETH_ROCEV2_VRMA)
				roce_rif_pasid_note_loss(roce, ROCE_RIF_LOSS_RHE);
			roce->stats.rx_rhe_drop++;
			roce->stats.rx_rhe_last_reason =
				((u64 *)rcd->rheq)[rhqoff / rsize];
		} else {
			l2_type_16b = jkr_rhf_l2_type(rhf) == HFI2_L2_TYPE_16B;
			if (l2_type_16b &&
			    rcv_type == RHF_RCV_TYPE_ETH_ROCEV2_VRMA) {
				const struct eal_ingress_vrma_header *vh =
					(const void *)ih;

				roce_rx_placement_report(roce, rcd_idx, vh);
			} else if (rhf_use_egr_bfr(rhf)) {
				u32 egr_idx = wfr_rhf_egr_index(rhf);
				u32 egr_offset = rhf_egr_buf_offset(rhf);

				etail = egr_idx;
				updegr |= !(egr_idx & (rcd->egrbufs.threshold - 1)) &&
					  !egr_offset;
				if (l2_type_16b &&
				    rcv_type == RHF_RCV_TYPE_BYPASS) {
					void *frame = (void *)
						((u64)rcd->egrbufs.rcvtids[egr_idx].addr +
						 egr_offset * RCV_BUF_BLOCK_SIZE);

					hfi2_dms_roce_rx_bypass(roce, rcd_idx, ih,
								frame,
								rhf_pkt_len(rhf));
				}
			}
		}

		if (unlikely(!list_empty_careful(&roce->rif_pending) ||
			     READ_ONCE(roce->rif_dirty_count)))
			roce_rx_rif_progress(roce);
		processed++;
		if (!(u8)rhqoff) {
			/*
			 * The CSR gets this entry's offset, so the entry itself
			 * is still pending: count only the ones before it.
			 */
			roce_rx_state_publish(roce, rcd_idx,
					      base + processed - 1, rhqoff);
			roce_rx_usrhead_update(roce, rcd_idx, rcd, rhqoff, updegr,
					       etail, 0);
			updegr = 0;
		}
		rcd->seq_cnt = hfi2_seq_incr_wrap(rcd->seq_cnt);
		rhqoff += rsize;
		if (rhqoff >= maxcnt)
			rhqoff = 0;
		rhf_addr = (__le32 *)rcd->rcvhdrq + rhqoff + rcd->rhf_offset;
		rhf = rhf_to_cpu(rhf_addr);
	}

	roce_rx_qp_unlock(roce);
	roce_rif_progress(roce);
	if (!processed)
		roce->stats.rx_rcd_empty_polls[rcd_idx]++;
	else
		roce->stats.rx_rcd_packets[rcd_idx] += processed;
	if (processed == budget && jkr_rhf_rcv_seq(rhf) == rcd->seq_cnt)
		roce->stats.rx_rcd_budget_limited[rcd_idx]++;

	if (processed) {
		/*
		 * rhqoff only moves with processed.  Inside one call the
		 * published head may lead rcd->head (the ring-wrap publish
		 * above), but every return leaves them equal, which is what
		 * the entry check relies on to spot an external reset.  Do
		 * not add a return between the wrap publish and here.
		 *
		 * Publish before the RcvHdrHead write inside
		 * roce_rx_usrhead_update(); see roce_rx_state_publish().  The
		 * release also publishes the packets above to
		 * hfi2_dms_roce_wait_rx(), which pairs it with an acquire.
		 * The helper/usrhead retire calls below only drop references
		 * to copies that already finished and never wait, so they
		 * add nothing the drain could rely on.
		 */
		hfi2_set_rcd_head(rcd, rhqoff);
		roce_rx_state_publish(roce, rcd_idx, base + processed, rhqoff);
		roce_rx_usrhead_update(roce, rcd_idx, rcd, rhqoff, updegr, etail,
				       processed);
	}
	WRITE_ONCE(roce->rx_q.filling, 0);
	/* After clearing filling, so a helper does not wait on a finished batch. */
	if (processed)
		roce_rx_helpers_kick(roce);
	roce_rx_helpers_retire(roce);
	roce_rx_usrhead_retire(roce, rcd_idx, rcd);
	return processed;
}

void hfi2_dms_roce_netdev_track_loss(struct hfi2_devdata *dd,
				     const struct eal_ingress_header *ih)
{
	struct hfi2_bulksvc *svc;
	struct hfi2_dms_roce *roce;

	if (EAL_INGRESS_GET_TYPE(ih) != EAL_INGRESS_TYPE_ROCEV2 ||
	    EAL_INGRESS_GET_L4(ih) != EAL_EGRESS_L4_VRMA)
		return;
	rcu_read_lock();
	svc = READ_ONCE(dd->bulksvc);
	roce = svc ? READ_ONCE(svc->dms_roce) : NULL;
	if (roce && READ_ONCE(roce->initialized) && READ_ONCE(roce->active))
		roce_rif_pasid_note_loss(roce, ROCE_RIF_LOSS_NETDEV);
	rcu_read_unlock();
}

bool hfi2_dms_roce_netdev_match_ipv4(struct hfi2_devdata *dd,
					 const void *frame, u32 len)
{
	const struct ethhdr *eth = frame;
	const struct iphdr *ip;
	const struct udphdr *udp;
	u16 proto;
	u16 ip_total;
	u16 udp_len;
	u32 l3_off = ETH_HLEN;
	u32 ihl;

	if (!READ_ONCE(dd->verbs_dev.roce_ip_da.sw_rx_count))
		return false;
	if (len < ETH_HLEN)
		return false;
	proto = ntohs(eth->h_proto);
	if (proto == ETH_P_8021Q) {
		if (len < ETH_HLEN + VLAN_HLEN)
			return false;
		proto = get_unaligned_be16((const u8 *)frame + ETH_HLEN + 2);
		l3_off += VLAN_HLEN;
	}
	if (proto != ETH_P_IP || len < l3_off + sizeof(*ip))
		return false;

	ip = (const struct iphdr *)((const u8 *)frame + l3_off);
	ihl = ip->ihl * 4;
	if (ip->version != 4 || ihl < sizeof(*ip) ||
	    len < l3_off + ihl + sizeof(*udp) || ip->protocol != IPPROTO_UDP ||
	    ip_is_fragment(ip))
		return false;
	ip_total = ntohs(ip->tot_len);
	if (ip_total < ihl + sizeof(*udp) || len < l3_off + ip_total)
		return false;
	udp = (const struct udphdr *)((const u8 *)ip + ihl);
	udp_len = ntohs(udp->len);
	return udp->dest == htons(HFI2_ROCE_UDP_DPORT) &&
	       udp_len >= sizeof(*udp) && udp_len <= ip_total - ihl &&
	       hfi2_roce_sw_rx_ipv4_match(dd, ip->daddr);
}

void hfi2_dms_roce_netdev_enqueue(struct hfi2_devdata *dd,
					  struct sk_buff *skb)
{
	struct hfi2_bulksvc *svc;
	struct hfi2_dms_roce *roce = NULL;
	bool queued = false;

	if (!hfi2_bulksvc_roce_by_software(dd)) {
		dev_kfree_skb_any(skb);
		return;
	}
	/* Pairs with synchronize_net() in hfi2_dms_roce_teardown_finish(). */
	rcu_read_lock();
	svc = READ_ONCE(dd->bulksvc);
	if (!svc || READ_ONCE(svc->stop_scheduling) ||
	    READ_ONCE(svc->backend) != HFI2_BULKSVC_BACKEND_ETH_ROCE)
		goto drop;
	roce = READ_ONCE(svc->dms_roce);
	if (!roce)
		goto drop;
	if (!READ_ONCE(roce->initialized) || !READ_ONCE(roce->active))
		goto drop_count;

	spin_lock_bh(&roce->netdev_rxq.lock);
	if (roce->netdev_rxq.qlen < HFI2_DMS_ROCE_NETDEV_RX_QUEUE_LEN) {
		__skb_queue_tail(&roce->netdev_rxq, skb);
		queued = true;
	}
	spin_unlock_bh(&roce->netdev_rxq.lock);
	if (queued) {
		atomic64_inc(&roce->stats.rx_netdev_diverted);
		hfi2_bulksvc_schedule(svc);
		rcu_read_unlock();
		return;
	}
drop_count:
	atomic64_inc(&roce->stats.rx_netdev_dropped);
drop:
	rcu_read_unlock();
	dev_kfree_skb_any(skb);
}

static u32 roce_poll_netdev_rx(struct hfi2_dms_roce *roce, u32 budget)
{
	struct hfi2_roce_wire_rx rx;
	struct sk_buff *skb;
	u32 processed = 0;
	u8 rcd_idx;

	while (processed < budget &&
	       (skb = skb_dequeue(&roce->netdev_rxq))) {
		if (hfi2_roce_parse_ipv4(skb->data, skb->len, &rx)) {
			roce->stats.rx_parse_err++;
		} else {
			rcd_idx = rx.dest_qpn & 1;
			/*
			 * The SKB is freed below, so its payload cannot be
			 * left for a helper to copy after this returns.
			 */
			roce->rx_copy_sync = true;
			hfi2_dms_roce_rx_bypass(roce, rcd_idx, NULL, skb->data,
						 skb->len);
			roce->rx_copy_sync = false;
		}
		roce_rx_rif_progress(roce);
		dev_kfree_skb_any(skb);
		processed++;
	}
	/* Do not carry this queue's QP lock into the ring poll */
	roce_rx_qp_unlock(roce);
	roce_rif_progress(roce);

	return processed;
}

/*
 * A QP parked for PIO credits waits for a credit-return interrupt, and a
 * restarted context has nothing outstanding to return.  Once the context is
 * enabled again after a restart, move the parked QPs back to the run queue.
 * This also covers a QP parked on a context that stopped before this backend
 * ever wrote a frame to it.
 */
static void roce_pio_restart_kick(struct hfi2_dms_roce *roce)
{
	struct send_context *sc = roce->sc;
	unsigned long flags;
	bool kick;

	/* Restart state is updated under alloc_lock by either PIO producer. */
	if (likely((READ_ONCE(sc->flags) & SCF_ENABLED) &&
		   !READ_ONCE(roce->pio_ctx_stopped) &&
		   !READ_ONCE(roce->pio_restarted) &&
		   READ_ONCE(sc->fill) >= READ_ONCE(roce->pio_last_fill)))
		return;

	spin_lock_irqsave(&sc->alloc_lock, flags);
	roce_pio_note_restart(roce);
	kick = roce->pio_restarted;
	WRITE_ONCE(roce->pio_restarted, false);
	spin_unlock_irqrestore(&sc->alloc_lock, flags);
	if (kick && !list_empty_careful(&roce->pio_waitq))
		hfi2_dms_roce_pio_available(roce);
}

int hfi2_dms_roce_poll(struct hfi2_dms_roce *roce, ktime_t now)
{
	struct hfi2_dms_roce_qp *rqp;
	unsigned long flags;
	u32 processed = 0;
	u32 tx_done = 0;
	u32 tx_attempts = 0;
	u32 first_done;
	u32 half_budget = ROCE_PIO_RX_BUDGET / HFI2_DMS_ROCE_RCD_COUNT;
	u8 first, second;
	u64 released;
	int rc;

	(void)now;
	if (!roce || !roce->active)
		return 0;
	roce_rif_progress(roce);
	if (WARN_ON_ONCE(roce->next_rx_rcd >= HFI2_DMS_ROCE_RCD_COUNT))
		roce->next_rx_rcd = 0;

	released = roce->stats.sdma_callback_ok +
		   roce->stats.sdma_callback_error +
		   roce->stats.sdma_callback_shutdown;
	hfi2_dms_roce_sdma_consume_done(roce);
	roce_sdma_cancel_requested(roce);
	hfi2_dms_roce_sdma_consume_done(roce);
	released = roce->stats.sdma_callback_ok +
		   roce->stats.sdma_callback_error +
		   roce->stats.sdma_callback_shutdown - released;
	/*
	 * A parked QP waits for any cookie release; with nothing left in
	 * flight no release is coming, so let it retry and find out why.
	 */
	if (!list_empty_careful(&roce->sdma_waitq)) {
		bool idle = !atomic_read(&roce->sdma_local_holds);

		if (released || idle)
			roce_sdma_waitq_wake(roce, idle);
	}
	roce_pio_restart_kick(roce);
	roce_rx_helpers_kick(roce);
	roce_rx_helpers_retire(roce);
	roce_rx_usrhead_retire(roce, 0, roce->rcd[0]);
	roce_rx_usrhead_retire(roce, 1, roce->rcd[1]);

	processed += roce_poll_netdev_rx(roce, HFI2_DMS_ROCE_NETDEV_RX_BUDGET);

	first = roce->next_rx_rcd;
	second = first ^ 1;
	first_done = roce_poll_rcd(roce, first, half_budget);
	processed += first_done;
	processed += roce_poll_rcd(roce, second,
		ROCE_PIO_RX_BUDGET - first_done);
	roce->next_rx_rcd = second;
	roce_restart_read_progress(roce);
	if (!list_empty(&roce->read_restart))
		processed++;

	processed += roce_inject_poll(roce);

	if (!list_empty_careful(&roce->sdma_done)) {
		u64 mid_rel = roce->stats.sdma_callback_ok +
			      roce->stats.sdma_callback_error +
			      roce->stats.sdma_callback_shutdown;

		hfi2_dms_roce_sdma_consume_done(roce);
		mid_rel = roce->stats.sdma_callback_ok +
			  roce->stats.sdma_callback_error +
			  roce->stats.sdma_callback_shutdown - mid_rel;
		if (!list_empty_careful(&roce->sdma_waitq)) {
			bool idle = !atomic_read(&roce->sdma_local_holds);

			if (mid_rel || idle)
				roce_sdma_waitq_wake(roce, idle);
		}
	}
	for (; tx_attempts < ROCE_PIO_TX_QP_BUDGET; tx_attempts++) {
		/*
		 * Lockless peek: every runq producer adds under runq_lock and
		 * then queues the worker (see roce_tx_worker_requeue(),
		 * hfi2_dms_roce_enqueue(), roce_sdma_waitq_wake(),
		 * hfi2_dms_roce_pio_available()), so a missed add is followed
		 * by a fresh run of this function.
		 */
		if (list_empty_careful(&roce->runq))
			break;
		spin_lock_irqsave(&roce->runq_lock, flags);
		if (list_empty(&roce->runq)) {
			spin_unlock_irqrestore(&roce->runq_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->runq, struct hfi2_dms_roce_qp,
				       runq_node);
		list_del_init(&rqp->runq_node);
		rqp->runq_queued = false;
		/* Pair with enqueue before RC or UD can inspect the send ring. */
		smp_mb();
		spin_unlock_irqrestore(&roce->runq_lock, flags);

		if (!roce_tx_worker_begin(rqp)) {
			rvt_put_qp(rqp->qp);
			tx_done++;
			continue;
		}
		rqp->sdma_stalled = false;
		rqp->donor_stalled = false;
		rc = hfi2_dms_roce_do_send(rqp->qp);

		if (rqp->donor_stalled) {
			roce_tx_worker_park_donor(rqp);
			rvt_put_qp(rqp->qp);
			continue;
		}
		if (rc == -ENOSPC) {
			if (roce_tx_worker_park_pio(rqp)) {
				tx_done++;
				break;
			}
			rvt_put_qp(rqp->qp);
			continue;
		}
		/*
		 * An SDMA-stalled QP waits off the run queue, and the
		 * pass goes on to the QPs behind it.
		 */
		if (rc == -EAGAIN && rqp->sdma_stalled) {
			if (!roce_tx_worker_park_sdma(rqp))
				rvt_put_qp(rqp->qp);
			tx_done++;
			continue;
		}
		if (rc == -EAGAIN || rc == -EINPROGRESS) {
			if (roce_tx_worker_requeue(rqp)) {
				tx_done++;
				if (rc == -EAGAIN || tx_done >= 16)
					break;
				continue;
			}
			rvt_put_qp(rqp->qp);
			continue;
		}
		if (roce_tx_worker_end(rqp))
			hfi2_dms_roce_enqueue(rqp->qp);
		rvt_put_qp(rqp->qp);
		tx_done++;
	}
	/*
	 * Parked QPs are work in progress: report it so the worker keeps
	 * draining completions rather than closing out and waiting for an
	 * SDMA interrupt or the progress timer.
	 */
	if (!list_empty_careful(&roce->sdma_waitq))
		processed++;
	roce_rx_helpers_kick(roce);
	roce_rx_helpers_retire(roce);
	roce_rx_usrhead_retire(roce, 0, roce->rcd[0]);
	roce_rx_usrhead_retire(roce, 1, roce->rcd[1]);
	/*
	 * A deferred head update is work in progress too: until it retires
	 * the hardware sees a full ring and raises no receive interrupt, so
	 * idling here would wait on an event that cannot come.
	 */
	if (roce->rx_usrhead_head[0] != roce->rx_usrhead_tail[0] ||
	    roce->rx_usrhead_head[1] != roce->rx_usrhead_tail[1])
		processed++;
	return processed + tx_done + !list_empty_careful(&roce->runq);
}

static int roce_build_ack_frame(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv, u32 psn, u8 syndrome,
				u8 *frame, size_t frame_sz, size_t *frame_len)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	size_t ib_len = HFI2_ROCE_BTH_BYTES + HFI2_ROCE_AETH_BYTES;
	u8 *bth;

	*frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES + *frame_len + HFI2_ROCE_ICRC_BYTES > frame_sz)
		return -EMSGSIZE;

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(frame + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);
	bth = frame + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	hfi2_roce_build_bth(bth, IB_OPCODE_RC_ACKNOWLEDGE, IB_DEFAULT_PKEY_FULL,
			    roce_answer_dest_qpn(rqp, priv), false, false, 0, psn);
	if (syndrome)
		hfi2_roce_build_aeth(bth + HFI2_ROCE_BTH_BYTES, syndrome,
				     rqp->qp->r_msn);
	else
		*(__be32 *)(bth + HFI2_ROCE_BTH_BYTES) = rvt_compute_aeth(rqp->qp);
	if (addr.vlan_id != HFI2_ROCE_NO_VLAN)
		roce_tag_count(rqp, priv, false, true);
	return 0;
}

/* Emit a bare AETH ACK back to the requester for @psn on @qp (responder). */
static int roce_send_ack(struct hfi2_dms_roce_qp *rqp,
			 struct hfi2_qp_priv_roce *priv, u32 psn, u8 syndrome)
{
	size_t frame_len;
	int rc;

	WARN_ON_ONCE(rqp->resp_emitter == HFI2_DMS_ROCE_EMITTER_SDMA &&
		     (roce_ack_behind_resp(rqp->qp) || rqp->sdma_resp_holds));
	rc = roce_build_ack_frame(rqp, priv, psn, syndrome, rqp->ackbuf,
				  rqp->ackbuf_sz, &frame_len);
	if (rc)
		return rc;
	rc = roce_pio_frame_buf(rqp, rqp->ackbuf, frame_len, true);
	if (rc)
		return rc;

	rqp->roce->stats.tx_acks++;
	roce_trace(rqp->dd, "tx ACK psn=%u qpn=%u syn=0x%02x\n",
		   psn, roce_answer_dest_qpn(rqp, priv), syndrome);
	return 0;
}

static int roce_sdma_send_ack(struct hfi2_dms_roce_qp *rqp,
			      struct hfi2_qp_priv_roce *priv, u32 psn, u8 syndrome)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	struct hfi2_dms_sdma_batch *batch = NULL;
	struct hfi2_dms_roce_sdma_cookie *cookie;
	struct hfi2_dms_roce_sdma_xfer *new_xfer;
	struct hfi2_dms_roce_sdma_xfer *xfer;
	struct hfi2_dms_roce_sdma_engine *engine;
	struct hfi2_dms_page *page;
	u8 engine_idx = rqp->request_engine_idx;
	u8 *frame;
	u32 command_pad;
	u64 pbc;
	size_t frame_len;
	size_t header_bytes;
	unsigned int source_idx;
	bool vlan_tagged;
	int rc = -EAGAIN;

	if (engine_idx >= roce->sdma_engine_count ||
	    engine_idx >= hfi2_bulksvc_primary_dms(roce->svc)->num_engines) {
		roce->stats.tx_sdma_ack_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	engine = &roce->sdma_engines[engine_idx];
	if (engine->descriptor_used > engine->descriptor_cap ||
	    engine->page_used >= engine->page_cap) {
		roce->stats.tx_sdma_ack_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}

	source_idx = roce_sdma_xfer_free(rqp, HFI2_DMS_ROCE_LANE_RESPONDER,
					 HFI2_DMS_ROCE_RESP_ACK_INDEX);
	if (WARN_ON_ONCE(source_idx == rqp->sdma_xfer_count)) {
		roce->stats.tx_sdma_ack_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	new_xfer = &rqp->sdma_xfers[source_idx];
	page = hfi2_dms_page_try_get(hfi2_bulksvc_primary_dms(roce->svc));
	if (!page) {
		roce->stats.sdma_page_stall++;
		rqp->sdma_stalled = true;
		roce->stats.tx_sdma_ack_stall++;
		rqp->sdma_stalled = true;
		return -EAGAIN;
	}
	cookie = hfi2_dms_roce_sdma_admit(rqp, HFI2_DMS_ROCE_LANE_RESPONDER,
					  HFI2_DMS_ROCE_RESP_ACK_INDEX,
					  rqp->resp_generation, IB_WR_SEND, psn, psn,
					  engine_idx, 1, 1, 1, false, false, NULL, new_xfer);
	if (!cookie)
		goto abort_page;
	cookie->pages[0] = page;
	xfer = cookie->xfer;
	xfer->wire_acked = true;

	if (WARN_ON_ONCE(hfi2_bulksvc_primary_dms(roce->svc)->port_sctxts[rqp->port_idx] !=
			 roce->sc)) {
		roce->stats.sdma_context_mismatch++;
		rc = -EINVAL;
		goto abort_cookie;
	}
	batch = hfi2_dms_sdma_batch_new_nowait(hfi2_bulksvc_primary_dms(roce->svc), rqp->port_idx);
	if (!batch) {
		roce->stats.sdma_batch_stall++;
		rqp->sdma_stalled = true;
		goto abort_cookie;
	}
	frame = page->mem.kvaddr + sizeof(pbc);
	rc = roce_build_ack_frame(rqp, priv, psn, syndrome, frame,
				  page->mem.len - sizeof(pbc), &frame_len);
	if (rc)
		goto abort_cookie;
	roce_build_egress_geometry(rqp, frame, frame_len, 0, &pbc, NULL);
	vlan_tagged = roce_frame_vlan_tagged(frame);
	/* frame_len starts at the Ethernet header; the EAL header precedes it. */
	header_bytes = EAL_EGRESS_HDR_BYTES + frame_len;
	command_pad = roce_sdma_command_pad(header_bytes, 0, 0);
	if (command_pad)
		memset(frame + header_bytes, 0, command_pad);
	*(u64 *)page->mem.kvaddr = pbc;
	rc = hfi2_dms_sdma_batch_emit(batch, page->mem.phys_addr,
				      sizeof(pbc) + header_bytes + command_pad,
				      HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
	if (rc)
		goto abort_cookie;
	hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(roce->svc), page,
				      0, sizeof(pbc) + header_bytes + command_pad);
	rc = hfi2_dms_roce_sdma_commit(cookie, batch, engine_idx);
	if (rc)
		return rc;
	if (vlan_tagged)
		roce->stats.tx_vlan_tagged++;

	roce->stats.tx_worker_packets++;
	roce->stats.tx_sdma_ack++;
	roce_trace(rqp->dd, "tx SDMA ACK psn=%u qpn=%u syn=0x%02x\n",
		   psn, roce_answer_dest_qpn(rqp, priv), syndrome);
	return 0;

abort_cookie:
	if (batch)
		hfi2_dms_sdma_batch_abort(batch);
	hfi2_dms_roce_sdma_abort_uncommitted(cookie, rc);
	return rc;
abort_page:
	hfi2_dms_page_put(hfi2_bulksvc_primary_dms(roce->svc), page);
	return rc;
}

/*
 * Emit a responder ACK/NAK, holding it for the worker if PIO had no credit.
 * Dropping it instead costs the requester a full retry timeout.
 *
 * A NAK outranks a plain ACK for the one slot: cumulative ACKs are subsumed
 * by any later ACK, but a NAK syndrome carries recovery semantics (RNR timer,
 * PSN-error class) that a later ACK would silently erase.  Between two NAKs,
 * or two ACKs, the newer PSN wins.
 *
 * Caller must hold qp->s_lock.
 */
/*
 * A READ RESPONSE is built by the worker, but ACKs and NAKs are sent from
 * the receive path, which bulksvc runs first.  An ACK for a request that
 * arrived after a READ would then reach the wire ahead of that READ's
 * response, and a conforming requester reads an ACK beyond an outstanding
 * READ as an implicit NAK and retries it (IBA C9-63).  In ERROR the owed
 * response is flushed rather than sent, so nothing is held behind it.
 */
static bool roce_ack_behind_resp(struct rvt_qp *qp)
{
	return (qp->s_flags & RVT_S_RESP_PENDING) &&
	       (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK);
}

static bool roce_ack_pio_blocked(struct hfi2_dms_roce_qp *rqp)
{
	return roce_ack_behind_resp(rqp->qp) || rqp->sdma_resp_holds;
}

static void roce_ack_or_defer(struct hfi2_dms_roce_qp *rqp,
			      struct hfi2_qp_priv_roce *priv, u32 psn,
			      u8 syndrome)
{
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;

	roce_rx_helpers_drain_qp(rqp);
	if (rqp->rif_arm_kind) {
		st->rif_arm_pending++;
		st->rif_arm_ack_held++;
	} else if (roce_ack_pio_blocked(rqp)) {
		if (roce_ack_behind_resp(rqp->qp))
			st->tx_ack_behind_resp++;
	} else if (!roce_send_ack(rqp, priv, psn, syndrome)) {
		rqp->ack_pending = false;
		return;
	}

	if (rqp->ack_pending) {
		/*
		 * A NAK names the PSN the responder still expects; an ACK at
		 * or past it means that PSN has since arrived, so the NAK is
		 * stale.
		 */
		if (rqp->ack_syndrome && !syndrome &&
		    roce_cmp_psn(psn, rqp->ack_psn) < 0)
			return;
		st->tx_ack_dropped++;
	}

	rqp->ack_psn = psn;
	rqp->ack_syndrome = syndrome;
	rqp->ack_pending = true;
	st->tx_ack_deferred++;
	if (!rqp->rif_arm_kind)
		hfi2_dms_roce_enqueue(rqp->qp);
}

/* Retry a held ACK/NAK from the worker.  Caller must hold qp->s_lock. */
static int roce_ack_retry_pending(struct hfi2_dms_roce_qp *rqp,
				  struct hfi2_qp_priv_roce *priv)
{
	int rc;

	if (!rqp->ack_pending)
		return 0;
	if (rqp->rif_arm_kind) {
		rqp->roce->stats.rif_arm_ack_held++;
		return -EINPROGRESS;
	}

	if (roce_ack_behind_resp(rqp->qp))
		return 0;

	roce_rx_helpers_drain_qp(rqp);
	if (roce_ack_pio_blocked(rqp))
		rc = roce_sdma_send_ack(rqp, priv, rqp->ack_psn,
					rqp->ack_syndrome);
	else
		rc = roce_send_ack(rqp, priv, rqp->ack_psn, rqp->ack_syndrome);
	if (rc) {
		if (rc == -EAGAIN)
			rqp->roce->stats.tx_sdma_ack_stall++;
		return rc;
	}

	rqp->ack_pending = false;
	return 0;
}

/* Complete a fatal responder error under qp->r_lock and qp->s_lock. */
static void roce_responder_error(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_qp_priv_roce *priv,
				 enum ib_wc_status status, u8 syndrome)
{
	struct rvt_qp *qp = rqp->qp;

	rqp->imm_rnr_pending = false;
	roce_rif_release(rqp);
	roce_rx_helpers_land_qp(rqp);
	/* rvt_rc_error() releases an acquired WRITE MR through r_sge. */
	spin_unlock(&qp->s_lock);
	rvt_rc_error(qp, status);
	spin_lock(&qp->s_lock);
	roce_ack_or_defer(rqp, priv, qp->r_psn & HFI2_ROCE_PSN_MASK, syndrome);
}

static void roce_responder_send(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv,
				const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	bool first, last, with_imm, with_inv, inv_success = false;
	u32 invalidate_rkey = 0;
	int ret;

	rqp->roce->stats.rx_send++;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK))
		return;

	if (rx->psn != (qp->r_psn & HFI2_ROCE_PSN_MASK)) {
		u32 expected_psn = qp->r_psn & HFI2_ROCE_PSN_MASK;

		rqp->roce->stats.rx_send_psn_drop++;
		if (roce_cmp_psn(rx->psn, expected_psn) > 0) {
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				rqp->roce->stats.rx_send_nak_seq++;
				roce_ack_or_defer(rqp, priv, expected_psn,
						  IB_NAK_PSN_ERROR);
			}
		} else if (rx->ack_req) {
			roce_ack_or_defer(rqp, priv,
					  (expected_psn - 1) & HFI2_ROCE_PSN_MASK,
					  0);
		}
		return;
	}

	switch (rx->opcode) {
	case IB_OPCODE_RC_SEND_FIRST:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE:
		first = true;
		break;
	default:
		first = false;
		break;
	}
	switch (rx->opcode) {
	case IB_OPCODE_RC_SEND_LAST:
	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE:
		last = true;
		break;
	default:
		last = false;
		break;
	}
	with_imm = rx->opcode == IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE ||
		   rx->opcode == IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE;
	with_inv = rx->opcode == IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE ||
		   rx->opcode == IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE;

	if (first) {
		if (qp->r_state == IB_OPCODE_RC_SEND_FIRST ||
		    qp->r_state == IB_OPCODE_RC_SEND_MIDDLE ||
		    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_INVALID_REQUEST);
			return;
		}
		ret = rvt_get_rwqe(qp, false);
		if (ret < 0) {
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_REMOTE_OPERATIONAL_ERROR);
			return;
		}
		if (!ret) {
			rqp->roce->stats.rx_send_rnr++;
			roce_ack_or_defer(rqp, priv,
					  qp->r_psn & HFI2_ROCE_PSN_MASK,
					  IB_RNR_NAK |
					  (qp->r_min_rnr_timer & IB_AETH_CREDIT_MASK));
			return;
		}
		qp->r_rcv_len = 0;
	} else if (qp->r_state != IB_OPCODE_RC_SEND_FIRST &&
		   qp->r_state != IB_OPCODE_RC_SEND_MIDDLE) {
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return;
	}

	if (qp->r_rcv_len + rx->payload_len > qp->r_len ||
	    (!last && rx->payload_len != qp->pmtu)) {
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return;
	}
	qp->r_rcv_len += rx->payload_len;
	ret = roce_rx_helpers_copy(rqp->roce, qp, &qp->r_sge, rx->payload,
				   rx->payload_len, true);
	if (ret) {
		roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
				     IB_NAK_REMOTE_ACCESS_ERROR);
		return;
	}

	/* Advance the expected PSN and comm-established state. */
	if (qp->state == IB_QPS_RTR && !(qp->r_flags & RVT_R_COMM_EST))
		rvt_comm_est(qp);
	qp->r_psn = (qp->r_psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = rx->opcode;
	qp->r_nak_state = 0;

	if (last) {
		struct ib_wc wc = {};

		/* The receive completion means the payload is in place. */
		roce_rx_helpers_land_qp(rqp);
		if (with_inv) {
			invalidate_rkey = be32_to_cpu(rx->ohdr->u.ieth);
			if (rvt_invalidate_rkey(qp, invalidate_rkey)) {
				rqp->roce->stats.rx_send_inv_fail++;
			} else {
				rqp->roce->stats.rx_send_inv++;
				inv_success = true;
			}
		}
		rvt_put_ss(&qp->r_sge);
		qp->r_msn++;
		if (__test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags)) {
			wc.wr_id = qp->r_wr_id;
			wc.status = IB_WC_SUCCESS;
			wc.opcode = IB_WC_RECV;
			wc.byte_len = qp->r_rcv_len;
			wc.qp = &qp->ibqp;
			wc.src_qp = qp->remote_qpn;
			wc.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX;
			wc.sl = rdma_ah_get_sl(&qp->remote_ah_attr);
			if (with_imm) {
				wc.ex.imm_data =
					*(__be32 *)((u8 *)rx->ohdr +
							    HFI2_ROCE_BTH_BYTES);
				wc.wc_flags = IB_WC_WITH_IMM;
			} else if (inv_success) {
				wc.ex.invalidate_rkey = invalidate_rkey;
				wc.wc_flags = IB_WC_WITH_INVALIDATE;
			}
			rvt_recv_cq(qp, &wc, ib_bth_is_solicited(rx->ohdr),
				    RVT_QP_LOCK_STATE_RS);
			rqp->roce->stats.rx_recv_cqe++;
		}
	}

	/* ACK the highest in-order PSN when the requester asked. */
	if (rx->ack_req)
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
}

static bool roce_write_with_imm(u8 opcode)
{
	return opcode == IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
}

static bool roce_write_first(u8 opcode)
{
	return roce_write_first_opcode(opcode);
}

static bool roce_write_last(u8 opcode)
{
	return roce_write_last_opcode(opcode);
}

/*
 * A WRITE with immediate consumes a receive WQE at its last packet.  Take it
 * there, before the packet changes any state.  With none posted the LAST is
 * refused with an RNR NAK, which tells the requester to resend from the PSN
 * it names.
 *
 * With @keep the RNR names the LAST and the packets already accepted stay
 * accepted: r_psn, r_sge and r_rcv_len are left where the LAST found them,
 * so the resent LAST lands as if it were the first try.  This is required
 * whenever the requester may have seen an ACK for part of the message - RXE
 * asks for one every 64 packets and resumes from its last acknowledged PSN,
 * ignoring an RNR that points further back.
 *
 * Without @keep the RNR names the message's first PSN and the accepted packets
 * are forgotten, so the resend starts from a clean FIRST.  The callers use it
 * when hardware placement holds burst state the LAST has already retired
 * (a RIF entry, an H15 arm, a last-by-software burst), where resuming
 * mid-message has nothing to resume against; those bursts come from a CN6K
 * requester, which asks for an ACK only on the last packet.
 *
 * Returns 1 with the WQE taken, 0 after an RNR NAK, -1 after the QP was
 * moved to error.
 */
static int roce_write_imm_rwqe(struct hfi2_dms_roce_qp *rqp,
			       struct hfi2_qp_priv_roce *priv, u32 first_psn,
			       bool keep)
{
	struct rvt_qp *qp = rqp->qp;
	int ret = rvt_get_rwqe(qp, true);

	if (ret > 0)
		return 1;
	if (ret < 0) {
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_REMOTE_OPERATIONAL_ERROR);
		return -1;
	}
	rqp->roce->stats.rx_write_imm_rnr++;
	if (!keep) {
		rvt_put_ss(&qp->r_sge);
		rqp->lbs_burst = false;
		roce_lbs_invalidate(rqp, false);
		roce_rif_release(rqp);
		qp->r_psn = first_psn & HFI2_ROCE_PSN_MASK;
		qp->r_state = IB_OPCODE_RC_RDMA_WRITE_LAST;
		qp->r_rcv_len = 0;
	}
	roce_ack_or_defer(rqp, priv, qp->r_psn & HFI2_ROCE_PSN_MASK,
			  IB_RNR_NAK |
			  (qp->r_min_rnr_timer & IB_AETH_CREDIT_MASK));
	return 0;
}

/* The receive completion a WRITE with immediate owes once it is placed. */
static void roce_write_imm_complete(struct hfi2_dms_roce_qp *rqp, __be32 imm,
				    u32 byte_len, bool solicited)
{
	struct rvt_qp *qp = rqp->qp;
	struct ib_wc wc = {};

	roce_rx_helpers_land_qp(rqp);

	if (!__test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags))
		return;
	wc.wr_id = qp->r_wr_id;
	wc.status = IB_WC_SUCCESS;
	wc.opcode = IB_WC_RECV_RDMA_WITH_IMM;
	wc.byte_len = byte_len;
	wc.qp = &qp->ibqp;
	wc.src_qp = qp->remote_qpn;
	wc.slid = rdma_ah_get_dlid(&qp->remote_ah_attr) & U16_MAX;
	wc.sl = rdma_ah_get_sl(&qp->remote_ah_attr);
	wc.ex.imm_data = imm;
	wc.wc_flags = IB_WC_WITH_IMM;
	rvt_recv_cq(qp, &wc, solicited, RVT_QP_LOCK_STATE_RS);
	rqp->roce->stats.rx_write_imm_cqe++;
}

/*
 * The resent LAST of a WRITE with immediate refused for want of a receive
 * WQE (imm_rnr_pending).  Its payload already landed; deliver the immediate
 * and finish the message.  Another RNR NAK names the LAST again.
 */
static void roce_imm_rnr_resume(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv, __be32 imm,
				bool solicited)
{
	struct rvt_qp *qp = rqp->qp;

	if (roce_write_imm_rwqe(rqp, priv, qp->r_psn, true) <= 0)
		return;
	rqp->imm_rnr_pending = false;
	rqp->roce->stats.rx_write_imm_resume++;
	roce_write_imm_complete(rqp, imm, rqp->imm_rnr_len, solicited);
	qp->r_psn = (qp->r_psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE;
	qp->r_nak_state = 0;
	qp->r_msn++;
	roce_ack_or_defer(rqp, priv, (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
}

/* The first PSN of the WRITE whose last packet carries @last_psn. */
static u32 roce_write_first_psn(struct rvt_qp *qp, u32 last_psn, u32 len)
{
	u32 packets = len && qp->pmtu ? DIV_ROUND_UP(len, qp->pmtu) : 1;

	return (last_psn - (packets - 1)) & HFI2_ROCE_PSN_MASK;
}

/*
 * Attribute a length-contract violation to the specific invariant it broke,
 * most-specific first: an overrun is reported as an overrun even when the
 * packet is also a short MIDDLE, because the length is what the peer got
 * wrong.  Counted here rather than beside the NAK -- roce_send_ack() only
 * counts tx_acks when the PIO succeeds, so a rejection that could not be
 * transmitted would otherwise leave no trace at all.
 */
static void roce_count_burst_length_violation(struct hfi2_dms_roce_qp *rqp,
					      struct rvt_qp *qp,
					      const struct hfi2_roce_wire_rx *rx,
					      bool last, u32 received_len)
{
	if (received_len > qp->r_len)
		rqp->roce->stats.rx_burst_overlong++;
	else if (last)
		rqp->roce->stats.rx_burst_last_mismatch++;
	else if (rx->payload_len != qp->pmtu)
		rqp->roce->stats.rx_burst_short_middle++;
	else
		rqp->roce->stats.rx_burst_middle_completes++;
}

/*
 * Arm a RIF entry for a burst hardware declined.
 *
 * An MR of 16 MiB or more has no R_Key entry (the field is 24 bits), and
 * neither has one whose R_Key row was full at registration, so 4.5.2.5.13.2
 * cannot validate its WRITE FIRST and diverts the whole burst to software.
 * Software has just consumed the RETH, so it holds everything the entry
 * needs, and hfi2_dms_roce_rif_arm() returns the bucket it chose.
 *
 * Armed RUNNING with next_psn = FIRST.PSN + 1, which is what the hardware FIRST
 * path writes.  INITIALIZING also works but latches on whatever PSN arrives
 * first, so a stray packet can adopt the burst; RUNNING rejects a foreign PSN
 * outright.
 *
 * end_psn is advisory only: silicon measurement showed MIDDLE placement is not
 * bounded by it (NOTE-STL-78285-end-psn-not-enforced-20260902.md), so the real
 * blast radius is the PASID's whole address space; see the H15 note at the
 * top of this file.
 */
static int roce_rif_row_reclaim(struct hfi2_dms_roce_qp *rqp);

/* Return 1 for a pending arm, or 0 for an ineligible software-only burst. */
static int roce_h15_arm_burst(struct hfi2_dms_roce_qp *rqp,
			      const struct hfi2_roce_wire_rx *rx,
			      struct hfi2_roce_mr_priv *mr_priv)
{
	struct hfi2_qp_priv_roce *priv = to_roce_priv(rqp->qp);
	struct hfi2_dms_roce_rif_entry entry = { 0 };
	struct rvt_qp *qp = rqp->qp;
	struct ib_reth *reth;
	u64 reth_vaddr;
	u32 packets;

	/* Check the installed bucket: row-full MRs also need software arming. */
	if (!priv->stride_ok || !mr_priv || !mr_priv->pasid ||
	    !READ_ONCE(mr_priv->pasid->live) ||
	    mr_priv->rkey_bucket != HFI2_ROCE_MR_NO_BUCKET ||
	    !qp->pmtu || qp->r_len <= qp->pmtu) {
		roce_trace(rqp->dd, "h15 skip psn %u stride %d mr %d r_len %u\n",
			   rx->psn, priv->stride_ok, !!mr_priv, qp->r_len);
		return 0;
	}

	/* Retire the previous software arm before replacing this QP's entry. */
	if (rqp->h15_bucket >= 0) {
		rqp->rif_cleanup |= ROCE_RIF_RELEASE;
		rqp->h15_armed = false;
	}

	reth = &rx->ohdr->u.rc.reth;
	reth_vaddr = get_ib_reth_vaddr(reth);
	reth_vaddr = hfi2_roce_kmr_translate_iova(mr_priv, reth_vaddr);
	packets = DIV_ROUND_UP(qp->r_len, qp->pmtu);
	entry.start_vaddr = reth_vaddr;
	entry.start_psn = rx->psn;
	entry.end_psn = (rx->psn + packets - 1) & HFI2_ROCE_PSN_MASK;
	entry.next_psn = (rx->psn + 1) & HFI2_ROCE_PSN_MASK;
	entry.pasid = mr_priv->pasid->pasid;
	entry.qpn = qp->ibqp.qp_num;
	entry.next_psn_state = EAL_RIF_NEXT_PSN_STATE_RUNNING;

	rqp->rif_payload = rx->payload_len;
	rqp->rif_length = qp->r_len;
	roce_rif_defer_arm(rqp, &entry, qp->r_sge.sge.mr, ROCE_RIF_ARM_H15);
	return 1;
}

/*
 * Classify one valid RIF entry for roce_rif_row_reclaim().  Returns the stat
 * to charge when the entry may be freed, or NULL to leave it.
 *
 * Another QP's state is read without its locks: the caller holds only its
 * own.  Every class is chosen so a stale read errs towards leaving the entry
 * alone - a RUNNING entry counts as finished only once its owner's r_psn has
 * moved past end_psn, and the placement reports that move r_psn trail the
 * hardware, never lead it.
 */
static u64 *roce_rif_reclaim_class(struct hfi2_dms_roce_qp *rqp,
				   const struct hfi2_dms_roce_rif_entry *e,
				   int bucket)
{
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	struct hfi2_devdata *dd = rqp->dd;
	struct hfi2_ibport *ibp = &dd->pport[HFI2_PORT_IDX].ibport_data;
	struct hfi2_dms_roce_qp *orqp;
	struct rvt_qp *oqp;
	u32 qpn = e->qpn & ~HFI2_ROCE_QPN_ALIAS_BIT;
	u64 *why = NULL;
	u8 r_state;

	/*
	 * A responder FIRST owns the real QPN; a drained private reply owns
	 * only its alias up to first_psn.  The real QPN can still be placing
	 * an unrelated inbound WRITE during requester recovery.
	 */
	if (e->qpn == rqp->qp->ibqp.qp_num &&
	    !READ_ONCE(rqp->read_response.first_retry_pending))
		return &st->rif_reclaim_own;
	if (e->qpn == (rqp->qp->ibqp.qp_num | HFI2_ROCE_QPN_ALIAS_BIT) &&
	    READ_ONCE(rqp->read_response.first_retry_pending) &&
	    roce_cmp_psn(e->start_psn,
			 READ_ONCE(rqp->read_response.first_psn)) <= 0)
		return &st->rif_reclaim_own;

	/*
	 * The receive path already holds rcu_read_lock(); take it here as
	 * well so the owner cannot be freed under this lookup whoever calls
	 * it.  rvt_remove_qp() waits for a grace period before the QP and its
	 * priv go away.
	 */
	rcu_read_lock();
	oqp = rvt_lookup_qpn(&dd->verbs_dev.rdi, &ibp->rvp, qpn);
	if (!oqp || oqp->ibqp.qp_type != IB_QPT_RC ||
	    !to_roce_priv(oqp)->roce_qp ||
	    !(ib_rvt_state_ops[READ_ONCE(oqp->state)] & RVT_PROCESS_RECV_OK)) {
		why = &st->rif_reclaim_dead;
		goto out;
	}
	orqp = to_roce_priv(oqp)->roce_qp;
	/* Private WRITE replies advance send state, not the responder r_psn. */
	if (e->qpn & HFI2_ROCE_QPN_ALIAS_BIT) {
		if (!READ_ONCE(oqp->s_num_rd_atomic))
			why = &st->rif_reclaim_dead;
		goto out;
	}
	/* Leave another QP's software arm to its owner. */
	if (READ_ONCE(orqp->h15_bucket) == bucket)
		goto out;

	r_state = READ_ONCE(oqp->r_state);
	switch (e->next_psn_state) {
	case EAL_RIF_NEXT_PSN_STATE_RECOVERING:
		why = &st->rif_reclaim_recovering;
		break;
	case EAL_RIF_NEXT_PSN_STATE_IDLE:
		why = &st->rif_reclaim_idle;
		break;
	case EAL_RIF_NEXT_PSN_STATE_INITIALIZING:
		if (r_state != IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		    r_state != IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			why = &st->rif_reclaim_unlatched;
		break;
	default:
		if (roce_cmp_psn(READ_ONCE(oqp->r_psn) & HFI2_ROCE_PSN_MASK,
				 e->end_psn) > 0)
			why = &st->rif_reclaim_finished;
		break;
	}
out:
	rcu_read_unlock();
	return why;
}

static int
roce_rif_reclaim_entry_current_mutex_held(struct hfi2_dms_roce *roce,
					  const struct hfi2_dms_roce_rif_entry *e,
					  int bucket)
{
	u32 row = EAL_RIF_ROW_FROM_QP(e->qpn);
	u32 owner;
	u64 q[3];

	lockdep_assert_held(&roce->rif_mutex);
	lockdep_assert_not_held(&roce->rif_lock);
	owner = READ_ONCE(roce->rif_owner[row * EAL_TABLE_ENTRIES_PER_ROW + bucket]);
	if (owner != HFI2_ROCE_RIF_NO_OWNER && owner != e->qpn)
		return 0;
	roce_rif_read_entry(roce, row, bucket, q);
	if (q[0] == ~0ULL || q[1] == ~0ULL || q[2] == ~0ULL)
		return -EIO;
	return FIELD_GET(EAL_RIF_WDATA2_ENTRY_VALID_MASK, q[2]) &&
		FIELD_GET(EAL_RIF_WDATA2_QP_MASK, q[2]) == e->qpn &&
		FIELD_GET(EAL_RIF_WDATA0_START_VIRTUAL_ADDRESS_MASK, q[0]) ==
		e->start_vaddr &&
		FIELD_GET(EAL_RIF_WDATA1_START_PSN_MASK, q[1]) == e->start_psn;
}

/*
 * Scan the RIF row of @rqp's QP and invalidate every entry that holds a
 * bucket without placing anything.  Hardware allocates buckets on its own,
 * so the software residency map cannot answer this; the readback can.
 * Returns the number of entries freed.
 */
static int roce_rif_row_reclaim_csr(struct hfi2_dms_roce_qp *rqp,
				    struct roce_rif_cleanup_state *state)
{
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	struct hfi2_dms_roce_rif_entry e;
	u32 qpn = rqp->qp->ibqp.qp_num;
	unsigned long flags;
	int b, entry_current, freed = 0;
	u64 *why;
	bool entered;

	if (state->superseded)
		return 0;
	entered = roce_rif_enter(rqp->roce);
	st->rif_reclaim_scan++;
	for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
		if (hfi2_dms_roce_rif_readback(rqp->roce, qpn, (u8)b, &e))
			continue;
		if (rqp->roce->tombs && e.pasid == rqp->roce->tombs->pasid.pasid)
			continue;
		why = roce_rif_reclaim_class(rqp, &e, b);
		if (!why) {
			st->rif_reclaim_live++;
			continue;
		}
		spin_lock_irqsave(&rqp->roce->rif_lock, flags);
		if (!rqp->roce->initialized || !rqp->roce->rif_owner ||
		    !rqp->roce->rif_pasid) {
			spin_unlock_irqrestore(&rqp->roce->rif_lock, flags);
			st->rif_reclaim_live++;
			continue;
		}
		spin_unlock_irqrestore(&rqp->roce->rif_lock, flags);
		entry_current =
			roce_rif_reclaim_entry_current_mutex_held(rqp->roce, &e, b);
		if (entry_current <= 0) {
			if (entry_current < 0)
				st->rif_invalidate_read_err++;
			st->rif_reclaim_live++;
			continue;
		}
		roce_rif_invalidate_mutex_held(rqp->roce, e.qpn, (u8)b);
		(*why)++;
		freed++;
		if (e.qpn == qpn) {
			state->cleared |= BIT(b);
			if (state->h15_bucket == b)
				state->h15_bucket = -1;
			if (state->lbs_bucket == b)
				state->lbs_bucket = -1;
		}
	}
	if (!freed && roce_tomb_row_full(rqp->roce, qpn) > 0)
		freed++;
	if (!freed)
		st->rif_reclaim_none++;
	roce_rif_leave(rqp->roce, entered);
	return freed;
}

static int roce_rif_row_reclaim(struct hfi2_dms_roce_qp *rqp)
{
	struct roce_rif_cleanup_state state = { };
	unsigned long rflags, sflags;
	int freed;
	bool entered;

	if (irqs_disabled()) {
		rqp->rif_reclaim = true;
		roce_rif_queue(rqp);
		return 0;
	}
	entered = roce_rif_enter(rqp->roce);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_snapshot(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	freed = roce_rif_row_reclaim_csr(rqp, &state);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_apply(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_rif_leave(rqp->roce, entered);
	return freed;
}

static void roce_rif_recovery_nak(struct hfi2_dms_roce_qp *rqp, u32 psn)
{
	/* This reply becomes eligible only after its CSR snapshot completes. */
	rqp->rif_nak_pending = true;
	rqp->rif_nak_psn = psn;
	rqp->ack_pending = false;
}

/*
 * Called with r_sge just taken for a WRITE FIRST.  Returns true when the
 * FIRST was NAKed or failed instead of consumed; r_sge is released and the
 * QP's receive position has not moved.
 *
 * A sequence NAK names the next PSN the responder expects, which is this
 * FIRST's own PSN because it was not consumed.  The MIDDLEs and the
 * header-only LAST behind it are above r_psn and are dropped as out of
 * sequence; r_nak_state keeps them from adding NAKs of their own.  Even when
 * the scan frees nothing the NAK still buys the round trip in which a live
 * burst completes and releases its bucket.  Exhaustion must fail the QP:
 * without an arm, hardware cannot deliver the remaining burst payload.
 */
static bool roce_rif_reclaim_first(struct hfi2_dms_roce_qp *rqp,
				   struct hfi2_qp_priv_roce *priv,
				   const struct hfi2_roce_wire_rx *rx)
{
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_roce_mr_priv *mr_priv;
	bool reclaim;

	if (rx->eal_end_state != EAL_INGRESS_ROCE_END_STATE_FIRST_ERR ||
	    rx->opcode != IB_OPCODE_RC_RDMA_WRITE_FIRST)
		return false;
	reclaim = READ_ONCE(roce_rif_reclaim) && !roce_last_by_software;
	if (!reclaim && (!rqp->roce->tombs ||
			 !test_bit(EAL_RIF_ROW_FROM_QP(qp->ibqp.qp_num),
				   rqp->roce->tombs->rows)))
		return false;
	/* Only an MR with an R_Key entry was meant for hardware. */
	mr_priv = qp->r_sge.sge.mr->driver_priv;
	if (!mr_priv || mr_priv->rkey_bucket == HFI2_ROCE_MR_NO_BUCKET)
		return false;

	st->rx_first_diverted++;
	if (rqp->reclaim_psn != rx->psn) {
		rqp->reclaim_psn = rx->psn;
		rqp->reclaim_tries = 0;
	}
	if (rqp->reclaim_tries >= HFI2_ROCE_RIF_RECLAIM_TRIES) {
		st->rif_reclaim_giveup++;
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return true;
	}
	rqp->reclaim_tries++;
	if (reclaim) {
		roce_rif_row_reclaim(rqp);
	} else {
		rqp->rif_tomb_reclaim = true;
		roce_rif_queue(rqp);
	}

	rvt_put_ss(&qp->r_sge);
	/*
	 * NAK every arrival, not just the first.  This FIRST is at r_psn, so
	 * it is the requester's answer to the previous NAK; latching on
	 * r_nak_state would leave the next try to the retry timer.  The
	 * MIDDLEs behind it still see r_nak_state and add no NAKs.
	 */
	qp->r_nak_state = IB_NAK_PSN_ERROR;
	st->rx_first_reclaim_nak++;
	roce_rif_recovery_nak(rqp, rx->psn);
	return true;
}

static bool roce_write_gap_packet(struct hfi2_dms_roce_qp *rqp, u8 opcode,
				  u32 psn, u32 bytes, bool trimmed, bool padded)
{
	struct rvt_qp *qp = rqp->qp;
	u32 first, length, offset, terminal, expected;
	bool last = roce_write_last(opcode);

	if (opcode != IB_OPCODE_RC_RDMA_WRITE_MIDDLE &&
	    opcode != IB_OPCODE_RC_RDMA_WRITE_LAST &&
	    opcode != IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE)
		return false;
	if (rqp->write_gap.active) {
		first = rqp->write_gap.first_psn;
		length = rqp->write_gap.length;
	} else {
		if (!rqp->vrma_write_active || rqp->h15_armed ||
		    rqp->h15_drop_sw || rqp->lbs_burst || rqp->lbs_entry ||
		    rqp->rif_arm_kind || rqp->rif_busy ||
		    (qp->r_state != IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		     qp->r_state != IB_OPCODE_RC_RDMA_WRITE_MIDDLE))
			return false;
		first = rqp->vrma_first_psn;
		length = rqp->vrma_length;
	}
	if (!qp->pmtu || length <= qp->pmtu)
		return false;
	terminal = (length - 1) / qp->pmtu;
	offset = (psn - first) & HFI2_ROCE_PSN_MASK;
	if (!offset || (last ? offset != terminal : offset >= terminal))
		return false;
	expected = last ? (length - 1) % qp->pmtu + 1 : qp->pmtu;
	return trimmed || bytes == expected ||
		(padded && last && bytes == ALIGN(expected, 4));
}

static void roce_write_gap_retry(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	u32 first = rqp->vrma_first_psn;
	u32 length = rqp->vrma_length;
	u32 pasid = rqp->vrma_pasid;
	u64 va = rqp->vrma_next_va - rqp->vrma_placed;

	if (rqp->write_gap.active)
		return;
	/* Preserve a duplex READ's alias; the hardware FIRST has no r_sge. */
	roce_rif_invalidate_qpn(rqp, ROCE_RIF_CLEAN_BASE);
	roce_rx_helpers_land_qp(rqp);
	rvt_put_ss(&qp->r_sge);
	rqp->h15_armed = false;
	rqp->lbs_burst = false;
	rqp->lbs_entry = false;
	roce_vrma_reset(rqp);
	rqp->write_gap.first_va = va;
	rqp->write_gap.first_psn = first;
	rqp->write_gap.length = length;
	rqp->write_gap.pasid = pasid;
	rqp->write_gap.active = true;
	qp->r_psn = first;
	qp->r_nak_state = 0;
	rqp->ack_pending = false;
	qp->r_state = IB_OPCODE_RC_RDMA_WRITE_LAST;
	qp->r_len = 0;
	qp->r_rcv_len = 0;
	rqp->roce->stats.rx_write_gap_retry++;
	/* The CSR continuation sends the NAK only after base-QPN retirement. */
}

static void roce_responder_write(struct hfi2_dms_roce_qp *rqp,
				 struct hfi2_qp_priv_roce *priv,
				 const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	bool first = roce_write_first(rx->opcode);
	bool last = roce_write_last(rx->opcode);
	bool with_imm = roce_write_with_imm(rx->opcode);
	u32 expected_psn = qp->r_psn & HFI2_ROCE_PSN_MASK;
	u32 received_len;
	int armed = 0;
	int ret;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK))
		return;

	/*
	 * After a software arm the burst is replayed from the first MIDDLE.
	 * Any MIDDLE or LAST still arriving on the software path was
	 * classified before the entry existed; copying it would move r_psn
	 * past the entry's next_psn, and the replay would then be placed by
	 * hardware against a sequence software has already consumed.  The
	 * receive ring is FIFO, so every such straggler is seen before the
	 * first placement report of the replay, which clears this.
	 */
	if (rqp->h15_drop_sw && !first) {
		rqp->roce->stats.h15_straggler_drop++;
		return;
	}
	if (!roce_last_by_software && !first &&
	    (rqp->write_gap.active ||
	     (rqp->vrma_write_active && !rqp->lbs_burst &&
	      roce_cmp_psn(rx->psn, expected_psn) >= 0)) &&
	    (rx->eal_end_state == EAL_INGRESS_ROCE_END_STATE_OK ||
	     rx->eal_end_state == EAL_INGRESS_ROCE_END_STATE_MIDDLE_NO_QP ||
	     rx->eal_end_state == EAL_INGRESS_ROCE_END_STATE_LAST_ERR) &&
	    roce_write_gap_packet(rqp, rx->opcode, rx->psn, 0, true, false)) {
		if (roce_write_gap_packet(rqp, rx->opcode, rx->psn,
					  rx->payload_len, false, false)) {
			roce_write_gap_retry(rqp);
			return;
		}
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return;
	}

	if (rx->psn != expected_psn) {
		roce_trace(rqp->dd, "wr psn drop psn %u exp %u nak %u\n",
			   rx->psn, expected_psn, qp->r_nak_state);
		rqp->roce->stats.rx_write_psn_drop++;
		if (roce_cmp_psn(rx->psn, expected_psn) > 0) {
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				rqp->roce->stats.rx_write_nak_seq++;
				roce_ack_or_defer(rqp, priv, expected_psn,
						  IB_NAK_PSN_ERROR);
			}
		} else {
			roce_ack_or_defer(rqp, priv,
					  (expected_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
		}
		return;
	}

	if (!roce_last_by_software && first && rqp->write_gap.active) {
		if (rx->opcode != IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    be32_to_cpu(rx->ohdr->u.rc.reth.length) !=
			rqp->write_gap.length ||
		    get_ib_reth_vaddr(&rx->ohdr->u.rc.reth) !=
			rqp->write_gap.first_va) {
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_INVALID_REQUEST);
			return;
		}
	}
	if (rqp->imm_rnr_pending) {
		roce_trace(rqp->dd,
			   "imm rnr resend qpn %u op 0x%02x psn %u paylen %u end 0x%02x\n",
			   qp->ibqp.qp_num, rx->opcode, rx->psn, rx->payload_len,
			   rx->eal_end_state);
		if (last && with_imm)
			roce_imm_rnr_resume(rqp, priv,
				*(__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES +
					    (first ? HFI2_ROCE_RETH_BYTES : 0)),
				ib_bth_is_solicited(rx->ohdr));
		return;
	}

	if (first) {
		if (qp->r_state == IB_OPCODE_RC_SEND_FIRST ||
		    qp->r_state == IB_OPCODE_RC_SEND_MIDDLE ||
		    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
			rqp->roce->stats.rx_burst_first_live++;
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_INVALID_REQUEST);
			return;
		}
	} else if (qp->r_state != IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		   qp->r_state != IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
		rqp->roce->stats.rx_burst_orphan++;
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return;
	}

	if (first) {
		struct ib_reth *reth = &rx->ohdr->u.rc.reth;

		if (hfi2_dms_roce_rkey_is_internal(rqp->roce,
						   be32_to_cpu(reth->rkey))) {
			rqp->roce->stats.rx_internal_key_on_base++;
			dd_dev_warn_ratelimited(rqp->dd,
						"roce: internal reply R_Key on base QPN %u; erroring QP\n",
				qp->ibqp.qp_num);
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_INVALID_REQUEST);
			return;
		}
		if (unlikely(!(qp->qp_access_flags & IB_ACCESS_REMOTE_WRITE))) {
			roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
					     IB_NAK_INVALID_REQUEST);
			return;
		}
		/*
		 * A fresh FIRST with an armed entry still recorded: the last
		 * burst ended without the hardware LAST that retires it.
		 */
		if (rqp->h15_armed) {
			rqp->roce->stats.h15_stale_first++;
			roce_rif_release(rqp);
		}
		qp->r_len = be32_to_cpu(reth->length);
		qp->r_rcv_len = 0;
		qp->r_sge.sg_list = NULL;
		if (qp->r_len) {
			if (unlikely(!rvt_rkey_ok(qp, &qp->r_sge.sge, qp->r_len,
						  get_ib_reth_vaddr(reth),
						  be32_to_cpu(reth->rkey),
						  IB_ACCESS_REMOTE_WRITE))) {
				roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
						     IB_NAK_REMOTE_ACCESS_ERROR);
				return;
			}
			qp->r_sge.num_sge = 1;
			if (roce_rif_reclaim_first(rqp, priv, rx))
				return;
			rqp->lbs_first_psn = rx->psn;
			rqp->lbs_first_va = get_ib_reth_vaddr(reth);
			/*
			 * Arm here, not at the tail.  The RETH is validated
			 * and r_len/r_sge are set, which is everything the
			 * arm needs, and the peer is already sending MIDDLEs
			 * at line rate - measured, one arrived before a
			 * tail-placed arm completed and was reported
			 * end_state 0x04 (no matching entry).
			 */
			armed = roce_h15_arm_burst(rqp, rx,
						   qp->r_sge.sge.mr->driver_priv);
			if (armed < 0)
				return;
		} else {
			qp->r_sge.num_sge = 0;
		}
	}

	received_len = qp->r_rcv_len + rx->payload_len;
	if (unlikely(received_len > qp->r_len ||
		     (!last && (rx->payload_len != qp->pmtu ||
				received_len == qp->r_len)) ||
		     (last && received_len != qp->r_len))) {
		roce_count_burst_length_violation(rqp, qp, rx, last,
						  received_len);
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return;
	}

	if (with_imm &&
	    roce_write_imm_rwqe(rqp, priv,
				roce_write_first_psn(qp, rx->psn, qp->r_len),
				!first && !rqp->h15_armed &&
				!rqp->lbs_burst) <= 0)
		return;

	if (last && READ_ONCE(roce_rx_helper_last_hold)) {
		bool dmabuf_do = qp->r_sge.sge.mem.type == RVT_MEM_DMABUF_DO;

		roce_rx_helpers_land_qp(rqp);
		ret = rvt_copy_sge(qp, &qp->r_sge,
				   rvt_to_kseg(rx->payload, rx->payload_len), true,
				   false);
		if (!ret && dmabuf_do)
			rqp->roce->stats.rx_dmabuf_copy += rx->payload_len;
	} else {
		ret = roce_rx_helpers_copy(rqp->roce, qp, &qp->r_sge,
					   rx->payload, rx->payload_len, true);
	}
	if (ret) {
		roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
				     IB_NAK_REMOTE_ACCESS_ERROR);
		return;
	}
	qp->r_rcv_len = received_len;
	if (qp->state == IB_QPS_RTR && !(qp->r_flags & RVT_R_COMM_EST))
		rvt_comm_est(qp);
	qp->r_psn = (expected_psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = rx->opcode;
	qp->r_nak_state = 0;
	if (first)
		rqp->write_gap.active = false;

	if (last) {
		rvt_put_ss(&qp->r_sge);
		qp->r_msn++;
		if (with_imm)
			roce_write_imm_complete(rqp,
				*(__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES +
					    (first ? HFI2_ROCE_RETH_BYTES : 0)),
				qp->r_len, ib_bth_is_solicited(rx->ohdr));
		if (rqp->lbs_burst) {
			rqp->lbs_burst = false;
			rqp->roce->stats.rx_lbs_last++;
		}
		roce_lbs_invalidate(rqp, false);
		/*
		 * The placement reports opened burst accounting that only a
		 * hardware LAST would otherwise close; left open, the next
		 * FIRST report is refused as a second burst.  An armed entry
		 * a LAST did not match is still valid and RUNNING.
		 */
		if (roce_last_by_software || rqp->h15_armed)
			roce_rif_release(rqp);
	}
	/*
	 * NAK right after the arm so the peer replays the burst from the first
	 * MIDDLE: MIDDLEs already in flight when the entry was written miss it,
	 * and the first one hardware then sees is out of order and trimmed.
	 * The NAK names the first MIDDLE, which is also the entry's next_psn,
	 * so the replayed burst matches the entry from its first packet.
	 */
	if (armed > 0) {
		rqp->roce->stats.rif_arm_pending++;
		return;
	}
	if (rx->ack_req)
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
}

/*
 * Sole producer of RVT_S_RESP_PENDING on the DMS_RoCE responder path.
 * hfi2_dms_roce_do_send() services that flag from RTR onward, which is legal
 * for READ because the response is built from local memory and consumes no
 * peer receive resources.  A future responder that raises the same flag for an
 * operation with different state requirements must re-verify that gate.
 */
static bool roce_rkey_is_dmabuf_do(struct rvt_qp *qp, u32 rkey)
{
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct rvt_mregion *mr;
	bool ret = false;

	if (!rkey)
		return false;
	rcu_read_lock();
	mr = rcu_dereference(rdi->lkey_table.table[rkey >>
						      rdi->lkey_table.shift]);
	if (mr && READ_ONCE(mr->lkey_published) &&
	    !mr->driver_internal && !atomic_read(&mr->lkey_invalid) &&
	    mr->lkey == rkey)
		ret = mr->map[0]->segs[0].type == RVT_MEM_DMABUF_DO;
	rcu_read_unlock();
	return ret;
}

static void roce_responder_atomic(struct hfi2_dms_roce_qp *rqp,
				  struct hfi2_qp_priv_roce *priv,
				  const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct rvt_ack_entry *entry;
	struct ib_atomic_eth *ateth = &rx->ohdr->u.atomic_eth;
	u32 expected = qp->r_psn & HFI2_ROCE_PSN_MASK;
	struct dma_buf *dmabuf;
	u64 vaddr;
	u64 swap;
	u8 next;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK))
		return;
	rqp->roce->stats.rx_atomic_req++;
	if (rx->payload_len || rx->pad_count ||
	    !(qp->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC))
		goto invalid;

	if (rx->psn != expected) {
		bool older;

		if (roce_cmp_psn(rx->psn, expected) > 0) {
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce_ack_or_defer(rqp, priv, expected,
						  IB_NAK_PSN_ERROR);
			}
			return;
		}

		entry = hfi2_find_prev_entry(qp, rx->psn, NULL, NULL, &older);
		if (!entry || entry->opcode != rx->opcode || older)
			return;
		rqp->roce->stats.rx_atomic_dup++;
		if (qp->s_tail_ack_queue == qp->s_acked_ack_queue)
			qp->s_acked_ack_queue = entry - qp->s_ack_queue;
		qp->s_tail_ack_queue = entry - qp->s_ack_queue;
		qp->s_flags |= RVT_S_RESP_PENDING;
		hfi2_roce_schedule_send(qp);
		return;
	}

	/* A retried atomic may precede a later, still-fragmented receive. */
	if (qp->r_state == IB_OPCODE_RC_SEND_FIRST ||
	    qp->r_state == IB_OPCODE_RC_SEND_MIDDLE ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
		goto invalid;

	next = qp->r_head_ack_queue + 1;
	if (next > rvt_size_atomic(rdi))
		next = 0;
	if (next == qp->s_acked_ack_queue) {
		if (!qp->s_ack_queue[next].sent)
			goto invalid;
		update_ack_queue(qp, next);
	}

	vaddr = get_ib_ateth_vaddr(ateth);
	if (vaddr & (sizeof(u64) - 1))
		goto invalid;

	entry = &qp->s_ack_queue[qp->r_head_ack_queue];
	release_rdma_sge_mr(entry);
	if (!rvt_rkey_ok(qp, &entry->rdma_sge, sizeof(u64), vaddr,
			 be32_to_cpu(ateth->rkey), IB_ACCESS_REMOTE_ATOMIC)) {
		if (roce_rkey_is_dmabuf_do(qp, be32_to_cpu(ateth->rkey)))
			rqp->roce->stats.atomic_dmabuf_nak++;
		goto access_error;
	}

	swap = get_ib_ateth_swap(ateth);
	dmabuf = entry->rdma_sge.mem.type == RVT_MEM_DMABUF ?
		 entry->rdma_sge.mem.seg_dmabuf.dmabuf : NULL;
	if (dmabuf)
		dma_buf_begin_cpu_access(dmabuf, DMA_BIDIRECTIONAL);
	if (rx->opcode == IB_OPCODE_RC_FETCH_ADD)
		entry->atomic_data = (u64)atomic64_add_return(swap,
			(atomic64_t *)entry->rdma_sge.mem.vaddr) - swap;
	else
		entry->atomic_data = (u64)cmpxchg((u64 *)entry->rdma_sge.mem.vaddr,
			get_ib_ateth_compare(ateth), swap);
	if (dmabuf)
		dma_buf_end_cpu_access(dmabuf, DMA_BIDIRECTIONAL);
	rvt_put_mr(entry->rdma_sge.mr);
	entry->rdma_sge.mr = NULL;
	entry->opcode = rx->opcode;
	entry->sent = 0;
	entry->psn = rx->psn;
	entry->lpsn = rx->psn;
	qp->r_msn++;
	qp->r_psn = (rx->psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = rx->opcode;
	qp->r_nak_state = 0;
	qp->r_head_ack_queue = next;
	qp->s_flags |= RVT_S_RESP_PENDING;
	hfi2_roce_schedule_send(qp);
	return;

invalid:
	roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
			     IB_NAK_INVALID_REQUEST);
	return;
access_error:
	roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
			     IB_NAK_REMOTE_ACCESS_ERROR);
}

static void roce_responder_read(struct hfi2_dms_roce_qp *rqp,
				struct hfi2_qp_priv_roce *priv,
				const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
	struct rvt_ack_entry *entry;
	struct hfi2_dms_roce_read_meta *meta;
	struct ib_reth *reth = &rx->ohdr->u.rc.reth;
	u32 expected = qp->r_psn & HFI2_ROCE_PSN_MASK;
	s32 psn_delta;
	u32 len, span, next;
	u64 offset;
	u64 vaddr;
	u64 dest_va = 0;
	u32 dest_rkey = 0;
	bool reply_write = false;
	bool software_place = false;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)) {
		/*
		 * RESET/INIT/ERR have no negotiated PSN or AV, so neither a
		 * response nor a well-formed NAK can be built.  Drop, but
		 * count it so the drop is visible without a wire capture.
		 */
		rqp->roce->stats.rx_read_state_drop++;
		roce_trace(rqp->dd, "rx READ drop state=%d psn=%u\n",
			   qp->state, rx->psn);
		return;
	}
	if (rx->pad_count)
		goto invalid;

	if (rx->payload_len) {
		const struct hfi2_roce_read_ext *ext = rx->payload;

		if (!rqp->roce->hwp_mode ||
		    rx->payload_len != HFI2_ROCE_READ_EXT_BYTES)
			goto invalid;
		if (ext->version != HFI2_ROCE_READ_EXT_VERSION || ext->reserved0 ||
		    ext->reserved1 || be32_to_cpu(ext->request_id) != rx->psn)
			goto invalid;
		dest_va = be64_to_cpu(ext->dest_va);
		dest_rkey = be32_to_cpu(ext->dest_rkey);
		if (ext->flags == HFI2_ROCE_READ_EXT_DIRECT_FLAGS) {
			if (!dest_rkey)
				goto invalid;
			reply_write = true;
		} else if (ext->flags == HFI2_ROCE_READ_EXT_SOFTWARE_FLAGS) {
			if (dest_va || dest_rkey != HFI2_ROCE_RKEY_NO_OWNER)
				goto invalid;
			software_place = true;
			reply_write = true;
		} else {
			goto invalid;
		}
	}
	if (rqp->roce->hwp_mode && !reply_write)
		goto invalid;
	if (!(qp->qp_access_flags & IB_ACCESS_REMOTE_READ))
		goto invalid;

	if (rx->psn != expected) {
		bool older, software_retry;
		u8 index;

		if (roce_cmp_psn(rx->psn, expected) > 0) {
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce_ack_or_defer(rqp, priv, expected,
						  IB_NAK_PSN_ERROR);
			}
			return;
		}

		entry = hfi2_find_prev_entry(qp, rx->psn, NULL, NULL, &older);
		if (!entry || entry->opcode != IB_OPCODE_RC_RDMA_READ_REQUEST) {
			rqp->roce->stats.rx_read_dup_drop++;
			roce_trace(rqp->dd, "rx READ dup psn=%u\n", rx->psn);
			return;
		}
		index = entry - qp->s_ack_queue;
		meta = &rqp->read_meta[index];
		psn_delta = roce_cmp_psn(rx->psn, meta->psn);
		if (psn_delta < 0) {
			rqp->roce->stats.rx_read_dup_drop++;
			roce_trace(rqp->dd, "rx READ dup psn=%u\n", rx->psn);
			return;
		}
		offset = (u64)psn_delta * qp->pmtu;
		len = be32_to_cpu(reth->length);
		vaddr = get_ib_reth_vaddr(reth);
		software_retry = meta->reply_write && !meta->software_place &&
			software_place;
		if (offset > meta->length || len > meta->length - offset ||
		    offset + len != meta->length || vaddr != meta->vaddr + offset ||
		    be32_to_cpu(reth->rkey) != meta->rkey ||
		    reply_write != meta->reply_write ||
		    (!software_retry &&
		     (software_place != meta->software_place ||
		      (reply_write && (dest_va != meta->dest_va ||
				 dest_rkey != meta->dest_rkey)))))
			goto invalid;
		release_rdma_sge_mr(entry);
		if (len && !rvt_rkey_ok(qp, &entry->rdma_sge, len, vaddr,
					be32_to_cpu(reth->rkey),
					IB_ACCESS_REMOTE_READ))
			goto access_error;
		if (!len) {
			memset(&entry->rdma_sge, 0, sizeof(entry->rdma_sge));
			entry->rdma_sge.sge_length = 0;
		}
		if (older) {
			rqp->roce->stats.rx_read_dup_drop++;
			roce_trace(rqp->dd, "rx READ dup psn=%u\n", rx->psn);
			return;
		}
		/* A duplicate READ resends the entire response train from FIRST. */
		entry->psn = rx->psn;
		entry->lpsn =
			(rx->psn + (len ? rvt_div_mtu(qp, len - 1) : 0)) &
			HFI2_ROCE_PSN_MASK;
		meta->reply_write = reply_write;
		meta->software_place = software_place;
		meta->dest_va = dest_va;
		meta->dest_rkey = dest_rkey;
		if (qp->s_acked_ack_queue == qp->s_tail_ack_queue)
			qp->s_acked_ack_queue = index;
		qp->s_tail_ack_queue = index;
		roce_resp_xfer_abandon(rqp);
		memset(&rqp->read_cursor, 0, sizeof(rqp->read_cursor));
		qp->s_flags |= RVT_S_RESP_PENDING;
		hfi2_roce_schedule_send(qp);
		return;
	}

	/* A retried READ may precede a later, still-fragmented receive. */
	if (qp->r_state == IB_OPCODE_RC_SEND_FIRST ||
	    qp->r_state == IB_OPCODE_RC_SEND_MIDDLE ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
		goto invalid;

	next = qp->r_head_ack_queue + 1;
	if (next > rvt_size_atomic(rdi))
		next = 0;
	if (next == qp->s_acked_ack_queue) {
		if (!qp->s_ack_queue[next].sent)
			goto invalid;
		update_ack_queue(qp, next);
	}

	entry = &qp->s_ack_queue[qp->r_head_ack_queue];
	meta = &rqp->read_meta[qp->r_head_ack_queue];
	len = be32_to_cpu(reth->length);
	vaddr = get_ib_reth_vaddr(reth);
	span = len ? rvt_div_mtu(qp, len - 1) + 1 : 1;
	release_rdma_sge_mr(entry);
	if (len && !rvt_rkey_ok(qp, &entry->rdma_sge, len, vaddr,
				be32_to_cpu(reth->rkey), IB_ACCESS_REMOTE_READ))
		goto access_error;
	if (!len) {
		memset(&entry->rdma_sge, 0, sizeof(entry->rdma_sge));
		entry->rdma_sge.sge_length = 0;
	}

	meta->vaddr = vaddr;
	meta->psn = rx->psn;
	meta->rkey = be32_to_cpu(reth->rkey);
	meta->length = len;
	meta->reply_write = reply_write;
	meta->software_place = software_place;
	meta->dest_va = dest_va;
	meta->dest_rkey = dest_rkey;
	entry->opcode = IB_OPCODE_RC_RDMA_READ_REQUEST;
	entry->sent = 0;
	entry->psn = rx->psn;
	entry->lpsn = (rx->psn + span - 1) & HFI2_ROCE_PSN_MASK;
	qp->r_msn++;
	qp->r_psn = (rx->psn + span) & HFI2_ROCE_PSN_MASK;
	qp->r_state = rx->opcode;
	qp->r_nak_state = 0;
	qp->r_head_ack_queue = next;
	qp->s_flags |= RVT_S_RESP_PENDING;
	/* READ response data is its acknowledgment; a plain ACK can trigger retry. */
	if (READ_ONCE(roce_pio_max_bytes) && qp->pmtu && len <= qp->pmtu &&
	    len <= READ_ONCE(roce_pio_max_bytes) && !rqp->sdma_resp_holds &&
	    (!len || entry->rdma_sge.mem.type == RVT_MEM_KERNEL) &&
	    !rqp->rif_arm_kind && !rqp->ack_pending &&
	    qp->s_tail_ack_queue == (entry - qp->s_ack_queue) &&
	    roce_tx_worker_begin(rqp)) {
		int rc = roce_send_read_response(rqp, priv);
		bool resched;

		if (rc < 0 && rc != -EAGAIN && rc != -ENOSPC && rc != -EBUSY)
			rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
		resched = roce_tx_worker_end(rqp);
		if (rc > 0 && !(qp->s_flags & RVT_S_RESP_PENDING) && !resched)
			return;
	}
	hfi2_roce_schedule_send(qp);
	return;

invalid:
	roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
			     IB_NAK_INVALID_REQUEST);
	return;
access_error:
	roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
			     IB_NAK_REMOTE_ACCESS_ERROR);
}

/*
 * One gap in a READ RESPONSE stream is one retry.  Every packet behind the
 * gap is out of sequence too, so without a latch each of them restarted the
 * READ and spent another unit of s_retry: a single lost packet in a 1 MiB
 * response burned the whole budget.  As hfi2's set_restart_qp() does with
 * RVT_R_RDMAR_SEQ, restart once and ignore the rest of the old stream until
 * a response packet is accepted in sequence.  A lost reissue is still
 * recovered by the retry timer, which does not consult the latch.
 */
static void roce_restart_read_response(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;

	rqp->read_response.active = false;
	if (rqp->read_response.restart_latched) {
		rqp->roce->stats.rx_read_resp_seq_drop++;
		return;
	}
	rqp->read_response.restart_latched = true;
	rqp->roce->stats.rx_read_resp_restart++;
	if (current_work() == &rqp->roce->svc->lanes[0].work) {
		rqp->read_response.restart_pending = true;
		rqp->read_response.restart_psn = roce_psn(qp->s_last_psn + 1);
		rqp->read_response.restart_wqe_index = qp->s_acked;
		if (list_empty(&rqp->read_restart_node)) {
			rvt_get_qp(qp);
			list_add_tail(&rqp->read_restart_node,
				      &rqp->roce->read_restart);
		}
		rvt_mod_retry_timer(qp);
	} else {
		hfi2_dms_roce_restart(qp, roce_psn(qp->s_last_psn + 1));
	}
	if (ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK)
		hfi2_roce_schedule_send(qp);
}

/*
 * Retire every non-READ request at s_acked whose last PSN is covered by
 * @ack_psn, and return how many were retired.  A READ ends the walk: it
 * is completed by its response, never by an acknowledgment.
 */
static u32 roce_requester_retire_acked(struct hfi2_dms_roce_qp *rqp,
				       u32 ack_psn)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;
	u32 retired = 0;

	while (qp->s_acked != qp->s_tail) {
		struct hfi2_dms_roce_sdma_xfer *xfer;
		u32 index = qp->s_acked;

		wqe = rvt_get_swqe_ptr(qp, index);
		if (roce_wqe_is_rd_atomic(wqe->wr.opcode) ||
		    roce_cmp_psn(ack_psn, wqe->lpsn) < 0)
			break;
		retired++;
		xfer = roce_sdma_xfer_lookup_any_epoch(rqp, index, wqe);
		hfi2_dms_roce_sdma_note_ack(xfer);
		if (wqe->wr.opcode == IB_WR_SEND_WITH_INV)
			roce_order_request_acked(rqp);
		qp->s_last_psn = roce_psn(wqe->lpsn);
		if (++qp->s_acked >= qp->s_size)
			qp->s_acked = 0;
	}
	roce_sdma_retire_request_ready(rqp);
	return retired;
}

static bool roce_read_write_eligible(struct hfi2_dms_roce_qp *rqp,
				     struct hfi2_qp_priv_roce *priv,
				     struct rvt_swqe *wqe, u64 *dest_va,
				     u32 *dest_rkey, bool count_ineligible)
{
	struct rvt_sge *sge;
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	struct hfi2_roce_mr_priv *mr_priv;
	struct rvt_mregion *mr;
	struct hfi2_dms_roce_read_target *target;
	unsigned int index = roce_wqe_index(rqp->qp, wqe);
	unsigned long flags;
	u64 page_idx, intra, off;
	u32 key;
	bool eligible = false;

	if (!rqp->roce->hwp_mode)
		return false;
	/* A replay must not re-enable hardware placement after software fallback. */
	if (roce_wqe_read_software_reply(rqp, wqe))
		return false;
	target = &rqp->read_targets[index];
	if (rqp->read_internal_keys[index]) {
		if (dest_va)
			*dest_va = target->va;
		if (dest_rkey)
			*dest_rkey = rqp->read_internal_keys[index];
		return true;
	}
	if (!wqe->length || !wqe->wr.num_sge) {
		if (count_ineligible)
			st->hwp_rd_sw_other++;
		return false;
	}
	sge = &wqe->sg_list[0];
	mr = sge->mr;
	if (!mr || mr->driver_internal)
		return false;
	mr_priv = mr->driver_priv;
	if (mr_priv) {
		spin_lock_irqsave(&mr_priv->pageset_lock, flags);
		if (mr_priv->pasid && READ_ONCE(mr_priv->pasid->quiesce_failed)) {
			spin_unlock_irqrestore(&mr_priv->pageset_lock, flags);
			return false;
		}
		eligible = mr_priv->pasid && READ_ONCE(mr_priv->pasid->live);
		spin_unlock_irqrestore(&mr_priv->pageset_lock, flags);
	}
	if (!eligible) {
		if (priv->stride_ok && rqp->qp->pmtu &&
		    !roce_hwp_window_get(rqp, wqe, dest_va, dest_rkey,
					 count_ineligible))
			return true;
		if (count_ineligible)
			st->hwp_rd_sw_no_pasid++;
		return false;
	}
	if (wqe->wr.num_sge != 1) {
		if (priv->stride_ok && rqp->qp->pmtu &&
		    !roce_hwp_window_get(rqp, wqe, dest_va, dest_rkey,
					 count_ineligible))
			return true;
		if (count_ineligible)
			st->hwp_rd_sw_multi_sge++;
		return false;
	}
	if (mr->length > EAL_RKEY_LENGTH_MAX) {
		if (priv->stride_ok && rqp->qp->pmtu &&
		    !roce_hwp_window_get(rqp, wqe, dest_va, dest_rkey,
					 count_ineligible))
			return true;
		if (count_ineligible)
			st->hwp_rd_sw_mr_too_big++;
		return false;
	}
	eligible = false;
	spin_lock_irqsave(&mr_priv->pageset_lock, flags);
	if (!priv->stride_ok || !rqp->qp->pmtu ||
	    sge->sge_length != wqe->length || sge->mem.type != RVT_MEM_KERNEL ||
	    mr->page_shift != PAGE_SHIFT) {
		if (count_ineligible)
			st->hwp_rd_sw_misaligned++;
		goto unlock;
	}

	page_idx = (u64)sge->m * RVT_SEGSZ + sge->n;
	intra = (u8 *)sge->mem.vaddr -
		(u8 *)mr->map[sge->m]->segs[sge->n].vaddr;
	off = (page_idx << PAGE_SHIFT) + intra;
	if (off < mr->offset) {
		if (count_ineligible)
			st->hwp_rd_sw_other++;
		goto unlock;
	}
	off -= mr->offset;
	key = mr_priv->internal_rkey;
	if (!key || !mr_priv->pasid || !READ_ONCE(mr_priv->pasid->live) ||
	    READ_ONCE(mr_priv->pasid->quiesce_failed) ||
	    off > mr_priv->read_key_length ||
	    wqe->length > mr_priv->read_key_length - off) {
		if (count_ineligible)
			st->hwp_rd_sw_no_ikey++;
		goto unlock;
	}
	/* Keep the advertised registration, not a later FastReg incarnation. */
	target->va = mr_priv->read_key_iova + off;
	target->pasid = mr_priv->pasid;
	rqp->read_internal_keys[index] = key;
	if (dest_va)
		*dest_va = target->va;
	if (dest_rkey)
		*dest_rkey = key;
	eligible = true;
unlock:
	spin_unlock_irqrestore(&mr_priv->pageset_lock, flags);
	return eligible;
}

static int roce_requester_read_complete(struct hfi2_dms_roce_qp *rqp,
					struct rvt_swqe *wqe);

/*
 * An unarmed WRITE LAST has no payload.  Drain the failed train through LAST
 * before replay so its tail cannot enter the retry's identical PSN range;
 * reclaim after dropping QP locks.
 */
static bool
roce_read_write_drop_diverted(struct hfi2_dms_roce_qp *rqp, u32 psn, bool last)
{
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;

	if (!response->first_diverted || qp->s_acked == qp->s_tail)
		return false;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (last && psn == roce_psn(wqe->lpsn) &&
	    !response->first_retry_pending) {
		response->first_retry_pending = true;
		roce_rif_row_reclaim(rqp);
	}
	return true;
}

static void roce_requester_read_write_error(struct hfi2_dms_roce_qp *rqp)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	roce_rx_helpers_land_qp(rqp);
	if (roce_hwp_defer_error(rqp, wqe, IB_WC_LOC_QP_OP_ERR,
				 RVT_QP_LOCK_STATE_RS))
		return;
	rqp->read_response.active = false;
	roce_wqe_clear_read_write_reply(rqp, wqe);
	if (qp->s_last == qp->s_acked) {
		hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
		rvt_send_complete(qp, wqe, IB_WC_LOC_QP_OP_ERR,
				  RVT_QP_LOCK_STATE_RS);
		rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
	}
}

/*
 * A final placed-byte count may include BTH dword padding or report the
 * unpadded payload length.  Accept only the remaining length or its
 * dword-aligned length.
 */
static bool roce_read_write_last_placed_ok(u32 placed, u32 left)
{
	return placed == left || placed == ALIGN(left, 4);
}

/* Drain a broken train through LAST, then reclaim its alias before replay. */
static void roce_read_write_retry(struct hfi2_dms_roce_qp *rqp,
				  struct rvt_swqe *wqe, u32 psn, bool last)
{
	rqp->read_response.active = false;
	rqp->read_response.first_psn = roce_psn(wqe->psn);
	rqp->read_response.first_diverted = true;
	roce_read_write_drop_diverted(rqp, psn, last);
}

static bool
roce_read_write_retry_report(struct hfi2_dms_roce_qp *rqp,
			     const struct eal_ingress_vrma_header *ih,
			     u8 opcode, u8 end_state, u32 placed)
{
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;
	u32 psn, expected;
	bool last = opcode == IB_OPCODE_RC_RDMA_WRITE_LAST;

	if ((!last && opcode != IB_OPCODE_RC_RDMA_WRITE_MIDDLE) ||
	    !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return false;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (wqe->wr.opcode != IB_WR_RDMA_READ ||
	    !roce_wqe_read_write_reply(rqp, wqe) ||
	    roce_wqe_read_software_reply(rqp, wqe))
		return false;

	switch (end_state) {
	case EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO:
		/* A trimmed MIDDLE carries both PSNs in q2, not a placement VA. */
		psn = EAL_INGRESS_VRMA_GET_PKT_PSN(ih);
		expected = EAL_INGRESS_VRMA_GET_NEXT_PSN(ih);
		if (last || placed || roce_cmp_psn(expected, wqe->psn) <= 0 ||
		    roce_cmp_psn(expected, wqe->lpsn) > 0 || psn == expected)
			return false;
		break;
	case EAL_INGRESS_ROCE_END_STATE_LAST_ERR:
		if (!last || !roce_vrma_report_psn(ih, &psn))
			return false;
		break;
	case EAL_INGRESS_ROCE_END_STATE_OK:
		if (placed || !roce_vrma_report_psn(ih, &psn) || !response->active ||
		    !response->write_reply || response->wqe_index != qp->s_acked ||
		    roce_cmp_psn(psn, response->next_psn) <= 0)
			return false;
		break;
	default:
		return false;
	}
	if (roce_cmp_psn(psn, wqe->psn) <= 0 ||
	    roce_cmp_psn(psn, qp->s_last_psn) <= 0 ||
	    (last ? roce_cmp_psn(psn, wqe->lpsn) != 0 :
	     roce_cmp_psn(psn, wqe->lpsn) >= 0))
		return false;
	if (placed) {
		if (!qp->pmtu)
			return false;
		expected = wqe->length % qp->pmtu ?: qp->pmtu;
		if (!roce_read_write_last_placed_ok(placed, expected))
			return false;
	}

	roce_read_write_retry(rqp, wqe, psn, last);
	return true;
}

static int roce_read_write_placed(struct hfi2_dms_roce_qp *rqp,
				  const struct eal_ingress_vrma_header *ih,
				  u32 placed, bool last)
{
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;
	u32 psn, expected;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return -EAGAIN;
	if (!roce_vrma_report_psn(ih, &psn))
		return -EINVAL;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	/* Match the READ before interpreting a late report's byte count. */
	if (roce_cmp_psn(psn, wqe->psn) < 0 ||
	    roce_cmp_psn(psn, qp->s_last_psn) <= 0) {
		rqp->roce->stats.rx_read_resp_stale++;
		return -EAGAIN;
	}
	if (wqe->wr.opcode != IB_WR_RDMA_READ)
		return -EINVAL;
	if (roce_wqe_read_software_reply(rqp, wqe)) {
		rqp->roce->stats.rx_read_as_write_fallback_drop++;
		return -EAGAIN;
	}
	if (!roce_wqe_read_write_reply(rqp, wqe))
		return -EAGAIN;
	if (!qp->pmtu)
		return -EINVAL;
	expected = wqe->length % qp->pmtu ?: qp->pmtu;
	if (last ? roce_cmp_psn(psn, wqe->lpsn) != 0 ||
	    !roce_read_write_last_placed_ok(placed, expected) :
	    roce_cmp_psn(psn, wqe->lpsn) >= 0 || placed != qp->pmtu)
		return -EINVAL;
	/* A rewind discards the cursor, not the reply capability or old traffic. */
	if (!response->active || !response->write_reply ||
	    response->wqe_index != qp->s_acked ||
	    roce_cmp_psn(psn, response->next_psn)) {
		roce_read_write_retry(rqp, wqe, psn, last);
		return -EAGAIN;
	}
	if ((last && roce_cmp_psn(psn, wqe->lpsn)) ||
	    (!last && (placed != qp->pmtu ||
		      placed >= qp->s_rdma_read_len)) ||
	    (last && !roce_read_write_last_placed_ok(placed,
						     qp->s_rdma_read_len)))
		return -EINVAL;
	placed = last ? qp->s_rdma_read_len : placed;
	if (unlikely(qp->s_rdma_read_sge.num_sge))
		roce_skip_sge(&qp->s_rdma_read_sge, placed);
	qp->s_rdma_read_len -= placed;
	qp->s_last_psn = psn;
	qp->s_retry = qp->s_retry_cnt;
	response->next_psn = roce_psn(psn + 1);
	response->restart_latched = false;
	response->restart_pending = false;
	rqp->restart_rx_deferred = false;
	if (last)
		return roce_requester_read_complete(rqp, wqe);
	rvt_mod_retry_timer(qp);
	return 0;
}

static int roce_read_write_first_placed(struct hfi2_dms_roce_qp *rqp,
					const struct eal_ingress_vrma_header *ih,
					u8 opcode, u32 placed)
{
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_qp *qp = rqp->qp;
	struct ib_other_headers *ohdr;
	struct ib_reth *reth;
	struct rvt_swqe *wqe;
	u64 dest_va;
	u32 dest_rkey;
	u32 psn;
	bool only = opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return -EAGAIN;
	ohdr = roce_vrma_report_bth(ih, HFI2_ROCE_RETH_BYTES);
	if (!ohdr)
		return -EINVAL;
	psn = ib_bth_get_psn(ohdr) & HFI2_ROCE_PSN_MASK;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (wqe->wr.opcode != IB_WR_RDMA_READ) {
		roce_requester_retire_acked(rqp,
					    (psn - 1) & HFI2_ROCE_PSN_MASK);
		if (qp->s_acked == qp->s_tail)
			return -EAGAIN;
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	}
	if (roce_cmp_psn(psn, wqe->psn) < 0) {
		rqp->roce->stats.rx_read_resp_stale++;
		return -EAGAIN;
	}
	if (wqe->wr.opcode != IB_WR_RDMA_READ)
		return -EINVAL;
	if (!roce_wqe_read_write_reply(rqp, wqe) ||
	    roce_wqe_read_software_reply(rqp, wqe))
		return -EAGAIN;
	if (response->active) {
		if (roce_cmp_psn(psn, wqe->psn) <= 0)
			return -EAGAIN;
		roce_restart_read_response(rqp);
		return -EAGAIN;
	}
	if (roce_cmp_psn(psn, wqe->psn)) {
		if (roce_cmp_psn(psn, wqe->psn) < 0)
			return -EAGAIN;
		roce_restart_read_response(rqp);
		return -EAGAIN;
	}
	reth = &ohdr->u.rc.reth;
	if (!roce_read_write_eligible(rqp, to_roce_priv(qp), wqe, &dest_va,
				      &dest_rkey, false))
		return -EINVAL;
	if (get_ib_reth_vaddr(reth) != dest_va ||
	    be32_to_cpu(reth->rkey) != dest_rkey ||
	    be32_to_cpu(reth->length) != wqe->length)
		return roce_hwp_window_key_stale(rqp->roce,
					 be32_to_cpu(reth->rkey)) ? -ESTALE : -EAGAIN;
	if ((!only && (wqe->length <= qp->pmtu || placed != qp->pmtu)) ||
	    (only && !roce_read_write_last_placed_ok(placed, wqe->length)))
		return -EINVAL;
	/* This cursor borrows the WQE's MR references; placement needs no walk. */
	qp->s_rdma_read_sge.num_sge = 0;
	qp->s_rdma_read_len = wqe->length;
	response->first_replaying = false;
	response->active = true;
	response->write_reply = true;
	response->wqe_index = qp->s_acked;
	response->next_psn = roce_psn(psn);
	return roce_read_write_placed(rqp, ih, placed, only);
}

static int roce_requester_read_complete(struct hfi2_dms_roce_qp *rqp,
					struct rvt_swqe *wqe)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;

	if (rqp->rif_read_cleanup)
		return -EAGAIN;
	if (qp->s_rdma_read_len || qp->s_rdma_read_sge.num_sge ||
	    unlikely(!qp->s_num_rd_atomic))
		return -EINVAL;
	roce_rx_helpers_land_qp(rqp);
	qp->s_num_rd_atomic--;
	response->active = false;
	response->first_tries = 0;
	response->first_replaying = false;
	roce_wqe_clear_read_write_reply(rqp, wqe);
	if (qp->s_last != qp->s_acked)
		rqp->roce->stats.rx_read_resp_slast_lag++;
	if (qp->s_acked == qp->s_cur) {
		if (++qp->s_cur >= qp->s_size)
			qp->s_cur = 0;
		qp->s_acked = qp->s_cur;
		if (qp->s_acked != qp->s_tail) {
			qp->s_state = IB_OPCODE_RC_SEND_LAST;
			qp->s_psn = roce_psn(rvt_get_swqe_ptr(qp, qp->s_cur)->psn);
		}
		rqp->roce->stats.rx_read_resp_skip_resend++;
	} else if (++qp->s_acked >= qp->s_size) {
		qp->s_acked = 0;
	}
	if (qp->s_acked == qp->s_tail) {
		rvt_stop_rc_timers(qp);
		qp->s_flags &= ~RVT_S_TIMER;
	} else if (qp->s_flags & RVT_S_TIMER) {
		rvt_mod_retry_timer(qp);
	} else {
		rvt_add_retry_timer(qp);
	}
	if ((qp->s_flags & RVT_S_WAIT_FENCE) &&
	    !rqp->order_pending && !qp->s_num_rd_atomic)
		qp->s_flags &= ~(RVT_S_WAIT_FENCE | RVT_S_WAIT_ACK);
	if (qp->s_flags & RVT_S_WAIT_RDMAR)
		qp->s_flags &= ~(RVT_S_WAIT_RDMAR | RVT_S_WAIT_ACK);
	roce_sdma_retire_request_ready(rqp);
	hfi2_roce_schedule_send(qp);
	return 0;
}

static void roce_requester_read_response(struct hfi2_dms_roce_qp *rqp,
					 const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_swqe *wqe;
	__be32 *aeth;
	u32 aeth_value;
	bool first, last;

	if (roce_hwp_write_mode(rqp->roce)) {
		rqp->roce->stats.rx_hwp_read_resp_drop++;
		dd_dev_warn_ratelimited(rqp->dd,
					"roce: reject READ RESPONSE on hardware QPN %u\n",
					qp->ibqp.qp_num);
		return;
	}
	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (wqe->wr.opcode != IB_WR_RDMA_READ) {
		/*
		 * A READ RESPONSE implicitly acknowledges every request sent
		 * before the READ (IBA 9.7.5.1.2), so a lost or coalesced ACK
		 * for an earlier WRITE or SEND must not fault the queue pair.
		 */
		rqp->roce->stats.rx_read_resp_implicit_ack +=
			roce_requester_retire_acked(rqp,
						    (rx->psn - 1) & HFI2_ROCE_PSN_MASK);
		if (qp->s_acked == qp->s_tail)
			return;
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
		if (wqe->wr.opcode != IB_WR_RDMA_READ) {
			/* Older than every outstanding request: a duplicate. */
			if (roce_cmp_psn(rx->psn, wqe->psn) < 0) {
				rqp->roce->stats.rx_read_resp_stale++;
				return;
			}
			goto protocol_error;
		}
	}

	first = rx->opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST ||
		rx->opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
	last = rx->opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST ||
	       rx->opcode == IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
	if (first) {
		if (response->active) {
			if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
				return;
			roce_restart_read_response(rqp);
			return;
		}
		if (roce_cmp_psn(rx->psn, wqe->psn) < 0)
			return;
		if (roce_cmp_psn(rx->psn, wqe->psn) > 0) {
			roce_restart_read_response(rqp);
			return;
		}
		aeth = (__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES);
		aeth_value = be32_to_cpu(*aeth);
		if (aeth_value >> IB_AETH_NAK_SHIFT) {
			response->active = false;
			roce_requester_ack(rqp, rx);
			return;
		}
		qp->s_rdma_read_len =
			rvt_restart_sge(&qp->s_rdma_read_sge, wqe, 0);
		response->active = true;
		response->write_reply = false;
		response->wqe_index = qp->s_acked;
		response->next_psn = roce_psn(rx->psn + 1);
		rvt_get_credit(qp, aeth_value);
	} else {
		if (!response->active ||
		    response->write_reply ||
		    response->wqe_index != qp->s_acked) {
			if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
				return;
			roce_restart_read_response(rqp);
			return;
		}
		if (roce_cmp_psn(rx->psn, response->next_psn) < 0)
			return;
		if (roce_cmp_psn(rx->psn, response->next_psn) > 0) {
			roce_restart_read_response(rqp);
			return;
		}
		if (last) {
			aeth = (__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES);
			aeth_value = be32_to_cpu(*aeth);
			if (aeth_value >> IB_AETH_NAK_SHIFT) {
				response->active = false;
				roce_requester_ack(rqp, rx);
				return;
			}
			rvt_get_credit(qp, aeth_value);
		}
	}

	if (last && roce_cmp_psn(rx->psn, wqe->lpsn))
		goto protocol_error;
	if ((!last && rx->payload_len != qp->pmtu) ||
	    (last && rx->payload_len != qp->s_rdma_read_len) ||
	    rx->payload_len > qp->s_rdma_read_len)
		goto protocol_error;

	if (roce_rx_helpers_copy(rqp->roce, qp, &qp->s_rdma_read_sge,
				 rx->payload, rx->payload_len, false))
		goto protocol_error;
	qp->s_rdma_read_len -= rx->payload_len;
	qp->s_last_psn = rx->psn;
	qp->s_retry = qp->s_retry_cnt;
	response->restart_latched = false;
	response->restart_pending = false;
	rqp->restart_rx_deferred = false;
	if (qp->s_flags & RVT_S_WAIT_ACK) {
		qp->s_flags &= ~RVT_S_WAIT_ACK;
		hfi2_roce_schedule_send(qp);
	}

	if (!last) {
		response->next_psn = roce_psn(rx->psn + 1);
		rvt_mod_retry_timer(qp);
		return;
	}
	if (roce_requester_read_complete(rqp, wqe))
		goto protocol_error;

	return;

protocol_error:
	roce_rx_helpers_land_qp(rqp);
	if (roce_hwp_defer_error(rqp, wqe, IB_WC_LOC_QP_OP_ERR,
				 RVT_QP_LOCK_STATE_RS))
		return;
	response->active = false;
	roce_wqe_clear_read_write_reply(rqp, wqe);
	if (qp->s_last == qp->s_acked) {
		hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
		rvt_send_complete(qp, wqe, IB_WC_LOC_QP_OP_ERR,
				  RVT_QP_LOCK_STATE_RS);
		rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR, RVT_QP_LOCK_STATE_RS);
	}
}

/*
 * Complete a software-delivered WRITE_ONLY packet on X* as a READ response.
 * A WRITE LAST with the unmatched sentinel key arrives without payload, so
 * each software reply packet is WRITE_ONLY with its own RETH.  These packets
 * are READ responses, not responder WRITEs; they have no ACK request or AETH.
 */
static void roce_requester_read_write_resp(struct hfi2_dms_roce_qp *rqp,
					   const struct hfi2_roce_wire_rx *rx)
{
	struct hfi2_dms_roce_read_response *response = &rqp->read_response;
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;
	struct ib_reth *reth;
	u64 dest_va;
	u32 dest_rkey;
	bool only = rx->opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY;
	bool first = roce_write_first_opcode(rx->opcode);
	bool last = roce_write_last_opcode(rx->opcode);
	bool software_reply;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail || rqp->rif_read_cleanup)
		return;

	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (wqe->wr.opcode != IB_WR_RDMA_READ) {
		rqp->roce->stats.rx_read_resp_implicit_ack +=
			roce_requester_retire_acked(rqp,
						    (rx->psn - 1) & HFI2_ROCE_PSN_MASK);
		if (qp->s_acked == qp->s_tail)
			return;
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	}
	/* Match before decoding: an old software ONLY may follow a direct READ. */
	if (roce_cmp_psn(rx->psn, wqe->psn) < 0) {
		rqp->roce->stats.rx_read_resp_stale++;
		return;
	}
	if (wqe->wr.opcode != IB_WR_RDMA_READ)
		goto protocol_error;
	/* Ignore replies until a private READ request has selected its mode. */
	if (!roce_wqe_read_write_reply(rqp, wqe) &&
	    !roce_wqe_read_software_reply(rqp, wqe))
		return;
	if (roce_read_write_drop_diverted(rqp, rx->psn, last) ||
	    (response->first_replaying && !first))
		return;
	software_reply = roce_wqe_read_software_reply(rqp, wqe);
	if (software_reply &&
	    (!only || be32_to_cpu(rx->ohdr->u.rc.reth.rkey) !=
		      HFI2_ROCE_RKEY_NO_OWNER))
		return;
	if (!software_reply && only && wqe->length > qp->pmtu)
		goto protocol_error;
	last = software_reply ? !roce_cmp_psn(rx->psn, wqe->lpsn) : last;
	if (software_reply && response->active) {
		if (!response->write_reply || response->wqe_index != qp->s_acked) {
			if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
				return;
			roce_restart_read_response(rqp);
			return;
		}
		if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
			return;
		if (roce_cmp_psn(rx->psn, response->next_psn)) {
			roce_restart_read_response(rqp);
			return;
		}
	}

	if (first && (!software_reply || !response->active)) {
		if (!roce_wqe_read_write_reply(rqp, wqe) &&
		    !roce_wqe_read_software_reply(rqp, wqe))
			return;

		if (response->active) {
			if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
				return;
			roce_restart_read_response(rqp);
			return;
		}
		if (roce_cmp_psn(rx->psn, wqe->psn) < 0)
			return;
		if (roce_cmp_psn(rx->psn, wqe->psn) > 0) {
			roce_restart_read_response(rqp);
			return;
		}
		reth = &rx->ohdr->u.rc.reth;
		if (software_reply) {
			if (get_ib_reth_vaddr(reth) ||
			    be32_to_cpu(reth->rkey) != HFI2_ROCE_RKEY_NO_OWNER ||
			    be32_to_cpu(reth->length) != wqe->length)
				goto protocol_error;
		} else if (!roce_read_write_eligible(rqp, to_roce_priv(qp), wqe,
						     &dest_va, &dest_rkey, false)) {
			goto protocol_error;
		} else if (get_ib_reth_vaddr(reth) != dest_va ||
			   be32_to_cpu(reth->rkey) != dest_rkey ||
			   be32_to_cpu(reth->length) != wqe->length) {
			return;
		}
		if (!software_reply && !roce_last_by_software &&
		    rx->opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		    rx->eal_end_state == EAL_INGRESS_ROCE_END_STATE_FIRST_ERR) {
			struct hfi2_dms_roce_hwp_window *window =
				rqp->read_hwp_windows ?
				rqp->read_hwp_windows[qp->s_acked] : NULL;

			if (window && window->mapped &&
			    window->rkey_bucket != HFI2_ROCE_MR_NO_BUCKET) {
				rqp->roce->stats.rx_rrsp_first_diverted++;
				if (response->first_psn != rx->psn) {
					response->first_psn = rx->psn;
					response->first_tries = 0;
				}
				if (response->first_tries >= HFI2_ROCE_RIF_RECLAIM_TRIES) {
					rqp->roce->stats.rrsp_first_giveup++;
					goto protocol_error;
				}
				response->first_tries++;
				response->first_diverted = true;
				return;
			}
		}
		response->first_replaying = false;
		qp->s_rdma_read_len = rvt_restart_sge(&qp->s_rdma_read_sge, wqe, 0);
		response->active = true;
		response->write_reply = true;
		response->wqe_index = qp->s_acked;
		response->next_psn = roce_psn(rx->psn);
	} else if (!software_reply && (!response->active || !response->write_reply ||
				      response->wqe_index != qp->s_acked)) {
		if (roce_cmp_psn(rx->psn, qp->s_last_psn) <= 0)
			return;
		roce_restart_read_response(rqp);
		return;
	}
	if (software_reply) {
		reth = &rx->ohdr->u.rc.reth;
		if (get_ib_reth_vaddr(reth) ||
		    be32_to_cpu(reth->rkey) != HFI2_ROCE_RKEY_NO_OWNER ||
		    be32_to_cpu(reth->length) != wqe->length)
			goto protocol_error;
	}

	if (roce_cmp_psn(rx->psn, response->next_psn) ||
	    (last && roce_cmp_psn(rx->psn, wqe->lpsn)) ||
	    (!last && rx->payload_len != qp->pmtu) ||
	    (last && rx->payload_len != qp->s_rdma_read_len) ||
	    rx->payload_len > qp->s_rdma_read_len)
		goto protocol_error;
	if (unlikely(!qp->s_rdma_read_sge.num_sge))
		rvt_restart_sge(&qp->s_rdma_read_sge, wqe,
				wqe->length - qp->s_rdma_read_len);
	if (roce_rx_helpers_copy(rqp->roce, qp, &qp->s_rdma_read_sge,
				 rx->payload, rx->payload_len, false))
		goto protocol_error;

	qp->s_rdma_read_len -= rx->payload_len;
	qp->s_last_psn = rx->psn;
	qp->s_retry = qp->s_retry_cnt;
	response->restart_latched = false;
	response->restart_pending = false;
	rqp->restart_rx_deferred = false;
	if (qp->s_flags & RVT_S_WAIT_ACK) {
		qp->s_flags &= ~RVT_S_WAIT_ACK;
		hfi2_roce_schedule_send(qp);
	}
	if (!last) {
		response->next_psn = roce_psn(rx->psn + 1);
		rvt_mod_retry_timer(qp);
		return;
	}
	roce_rx_helpers_land_qp(rqp);
	if (!roce_requester_read_complete(rqp, wqe))
		return;

protocol_error:
	roce_requester_read_write_error(rqp);
}

static void roce_replay_resume_set(struct hfi2_dms_roce_qp *rqp, u32 psn)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, qp->s_acked);

	rqp->resume_pending = false;
	if (!roce_req_is_write(wqe->wr.opcode) || !qp->pmtu ||
	    roce_cmp_psn(psn, wqe->psn) <= 0 ||
	    roce_cmp_psn(psn, wqe->lpsn) > 0)
		return;
	rqp->resume_pending = true;
	rqp->resume_wqe_idx = qp->s_acked;
	rqp->resume_psn = psn & HFI2_ROCE_PSN_MASK;
	qp->s_psn = rqp->resume_psn;
}

static void roce_rewind_to_acked(struct rvt_qp *qp)
{
	struct rvt_swqe *wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;

	lockdep_assert_held(&qp->s_lock);
	if (rqp) {
		u32 i;

		rqp->resume_pending = false;
		for (i = qp->s_acked; i != qp->s_tail;) {
			struct rvt_swqe *retry_wqe = rvt_get_swqe_ptr(qp, i);

			if (retry_wqe->wr.opcode == IB_WR_RDMA_READ &&
			    roce_wqe_read_write_reply(rqp, retry_wqe)) {
				if (!rqp->read_hwp_windows[i]) {
					clear_bit(i, rqp->read_write_wqes);
					roce_wqe_set_read_software_reply(rqp, retry_wqe);
				}
				rqp->rif_read_cleanup = true;
				rqp->rif_cleanup |= ROCE_RIF_CLEAN_ALIAS;
				roce_rif_queue(rqp);
			}
			if (++i >= qp->s_size)
				i = 0;
		}
		WARN_ON_ONCE(rqp->sdma_req_holds);
		if (rqp->tx_in_progress)
			roce_tx_snapshot_release(rqp);
		rqp->read_response.active = false;
	}
	qp->s_cur = qp->s_acked;
	qp->s_state = IB_OPCODE_RC_SEND_LAST;
	qp->s_psn = roce_psn(wqe->psn);
	qp->s_last_psn = roce_psn(wqe->psn - 1);
}

static void roce_requester_atomic_ack(struct hfi2_dms_roce_qp *rqp,
				       const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	struct rvt_swqe *wqe;
	__be32 *aeth;
	u32 aeth_value;
	u8 nak_class;
	u64 value;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) ||
	    qp->s_acked == qp->s_tail)
		return;
	rqp->roce->stats.rx_atomic_ack++;

	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	if (!roce_wqe_is_rd_atomic(wqe->wr.opcode)) {
		rqp->roce->stats.rx_read_resp_implicit_ack +=
			roce_requester_retire_acked(rqp,
						    (rx->psn - 1) & HFI2_ROCE_PSN_MASK);
		if (qp->s_acked == qp->s_tail)
			return;
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
	}
	/* Duplicates and responses for anything but the oldest atomic. */
	if ((wqe->wr.opcode != IB_WR_ATOMIC_CMP_AND_SWP &&
	     wqe->wr.opcode != IB_WR_ATOMIC_FETCH_AND_ADD) ||
	    roce_cmp_psn(rx->psn, wqe->psn))
		return;

	aeth = (__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES);
	aeth_value = be32_to_cpu(*aeth);
	nak_class = aeth_value >> IB_AETH_NAK_SHIFT;
	if (nak_class) {
		roce_requester_ack(rqp, rx);
		return;
	}

	value = ib_u64_get(&rx->ohdr->u.at.atomic_ack_eth);
	if (wqe->sg_list[0].mem.type == RVT_MEM_DMABUF_DO) {
		struct rvt_dev_info *rdi = ib_to_rvt(qp->ibqp.device);
		struct rvt_seg src = rvt_to_kseg(&value, sizeof(value));

		if (rdi->driver_f.dmabuf_memcpy(wqe->sg_list[0].mem, src)) {
			rvt_error_qp(qp, IB_WC_LOC_PROT_ERR, RVT_QP_LOCK_STATE_RS);
			return;
		}
		rqp->roce->stats.rx_dmabuf_copy += sizeof(value);
	} else {
		struct dma_buf *dmabuf =
			wqe->sg_list[0].mem.type == RVT_MEM_DMABUF ?
			wqe->sg_list[0].mem.seg_dmabuf.dmabuf : NULL;

		if (dmabuf)
			dma_buf_begin_cpu_access(dmabuf, DMA_TO_DEVICE);
		*(u64 *)wqe->sg_list[0].mem.vaddr = value;
		if (dmabuf)
			dma_buf_end_cpu_access(dmabuf, DMA_TO_DEVICE);
	}
	rvt_get_credit(qp, aeth_value);
	if (unlikely(!qp->s_num_rd_atomic))
		return;

	qp->s_last_psn = roce_psn(wqe->lpsn);
	qp->s_retry = qp->s_retry_cnt;
	qp->s_num_rd_atomic--;
	roce_order_request_acked(rqp);
	if (qp->s_acked == qp->s_cur) {
		if (++qp->s_cur >= qp->s_size)
			qp->s_cur = 0;
		qp->s_acked = qp->s_cur;
		if (qp->s_acked != qp->s_tail) {
			qp->s_state = IB_OPCODE_RC_SEND_LAST;
			qp->s_psn = roce_psn(rvt_get_swqe_ptr(qp, qp->s_cur)->psn);
		}
	} else if (++qp->s_acked >= qp->s_size) {
		qp->s_acked = 0;
	}
	if (qp->s_acked == qp->s_tail) {
		rvt_stop_rc_timers(qp);
		qp->s_flags &= ~RVT_S_TIMER;
	} else if (qp->s_flags & RVT_S_TIMER) {
		rvt_mod_retry_timer(qp);
	} else {
		rvt_add_retry_timer(qp);
	}
	if (qp->s_flags & RVT_S_WAIT_RDMAR)
		qp->s_flags &= ~(RVT_S_WAIT_RDMAR | RVT_S_WAIT_ACK);
	roce_sdma_retire_request_ready(rqp);
	hfi2_roce_schedule_send(qp);
}

static void roce_requester_ack(struct hfi2_dms_roce_qp *rqp, const struct hfi2_roce_wire_rx *rx)
{
	struct rvt_qp *qp = rqp->qp;
	__be32 *aeth;
	u32 aeth_value;
	u8 syndrome;
	u8 nak_class;
	u32 subcode;
	u32 ack_psn;
	bool credit_wait = false;
	struct rvt_swqe *wqe;
	enum ib_wc_status status;

	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK))
		return;

	aeth = (__be32 *)((u8 *)rx->ohdr + HFI2_ROCE_BTH_BYTES);
	aeth_value = be32_to_cpu(*aeth);
	syndrome = aeth_value >> IB_AETH_CREDIT_SHIFT;
	nak_class = aeth_value >> IB_AETH_NAK_SHIFT;
	subcode = syndrome & IB_AETH_CREDIT_MASK;
	ack_psn = rx->psn;

	roce_trace(rqp->dd,
		   "rx ACK psn=%u qpn=%u aeth=0x%08x syn=0x%02x\n",
		   rx->psn, rx->dest_qpn, aeth_value, syndrome);
	rqp->roce->stats.rx_ack++;
	if (nak_class) {
		ack_psn = (ack_psn - 1) & HFI2_ROCE_PSN_MASK;
	} else {
		credit_wait = qp->s_flags & RVT_S_WAIT_SSN_CREDIT;
		rvt_get_credit(qp, aeth_value);
	}

	roce_requester_retire_acked(rqp, ack_psn);

	switch (nak_class) {
	case 0:
		qp->s_retry = qp->s_retry_cnt;
		qp->s_rnr_retry = qp->s_rnr_retry_cnt;
		if (qp->s_acked == qp->s_tail) {
			rvt_stop_rc_timers(qp);
			qp->s_flags &= ~RVT_S_TIMER;
		} else if (!(qp->s_flags & RVT_S_TIMER)) {
			rvt_add_retry_timer(qp);
		} else {
			rvt_mod_retry_timer(qp);
		}
		if (!credit_wait && qp->s_cur != qp->s_head)
			hfi2_roce_schedule_send(qp);
		return;
	case 1:
		rqp->roce->stats.rx_ack_rnr++;
		if (qp->s_acked == qp->s_tail) {
			rvt_stop_rc_timers(qp);
			return;
		}
		if (qp->s_flags & RVT_S_WAIT_RNR)
			return;
		if (qp->s_rnr_retry == 0) {
			wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
		if (qp->s_last == qp->s_acked) {
			rqp->roce->stats.retry_rnr_exhausted++;
			if (roce_hwp_defer_error(rqp, wqe, IB_WC_RNR_RETRY_EXC_ERR,
						 RVT_QP_LOCK_STATE_RS))
				return;
			if (wqe->wr.opcode == IB_WR_RDMA_READ)
				rqp->read_response.active = false;
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe,
				      IB_WC_RNR_RETRY_EXC_ERR,
				      RVT_QP_LOCK_STATE_RS);
				rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR,
					     RVT_QP_LOCK_STATE_RS);
			}
			rvt_stop_rc_timers(qp);
			return;
		}
		if (qp->s_rnr_retry_cnt > 0 && qp->s_rnr_retry_cnt < 7)
			qp->s_rnr_retry--;
		rvt_stop_rc_timers(qp);
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
		if (roce_request_replay_defer(rqp, wqe->psn,
					      HFI2_DMS_ROCE_REPLAY_RNR,
					      aeth_value))
			return;
		return;
	case 3:
		if (!roce_request_outstanding(rqp)) {
			rvt_stop_rc_timers(qp);
			return;
		}
		if (subcode == 0) {
			rqp->roce->stats.rx_ack_nak_seq++;
			if (roce_request_replay_defer(rqp, rx->psn,
						      HFI2_DMS_ROCE_REPLAY_SEND, 0)) {
				rvt_stop_rc_timers(qp);
				return;
			}
			rvt_stop_rc_timers(qp);
			hfi2_roce_schedule_send(qp);
			return;
		}
		switch (subcode) {
		case 1:
			status = IB_WC_REM_INV_REQ_ERR;
			break;
		case 2:
			status = IB_WC_REM_ACCESS_ERR;
			break;
		case 3:
			status = IB_WC_REM_OP_ERR;
			break;
		case 4:
			status = IB_WC_REM_INV_RD_REQ_ERR;
			break;
		default:
			rvt_stop_rc_timers(qp);
			return;
		}
		rqp->roce->stats.rx_ack_fatal++;
		wqe = rvt_get_swqe_ptr(qp, qp->s_acked);
		if (qp->s_last == qp->s_acked) {
			if (roce_hwp_defer_error(rqp, wqe, status, RVT_QP_LOCK_STATE_RS))
				return;
			if (roce_wqe_is_rd_atomic(wqe->wr.opcode) &&
			    qp->s_num_rd_atomic)
				qp->s_num_rd_atomic--;
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe, status, RVT_QP_LOCK_STATE_RS);
			rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR,
				     RVT_QP_LOCK_STATE_RS);
		}
		qp->s_retry = qp->s_retry_cnt;
		qp->s_rnr_retry = qp->s_rnr_retry_cnt;
		rvt_stop_rc_timers(qp);
		return;
	default:
		rvt_stop_rc_timers(qp);
		return;
	}
}

static bool roce_rx_reports_pending(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	u64 state = READ_ONCE(roce->rx_rcd_state[rqp->rcd_idx]);
	u32 tail = (u32)read_uctxt_csr(roce->dd, rqp->rcd->ctxt,
				       roce->dd->params->rcv_hdr_tail_reg);

	return tail != roce_rx_state_head(state);
}

static void roce_restart_read_progress(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_qp *rqp, *next;

	list_for_each_entry_safe(rqp, next, &roce->read_restart, read_restart_node) {
		struct hfi2_dms_roce_read_response *response = &rqp->read_response;
		struct rvt_qp *qp = rqp->qp;
		unsigned long rflags, sflags;
		bool pending = false;

		spin_lock_irqsave(&qp->r_lock, rflags);
		spin_lock_irqsave(&qp->s_lock, sflags);
		if (response->restart_pending && response->restart_latched &&
		    !READ_ONCE(rqp->tx_cancelled) && READ_ONCE(roce->active) &&
		    (ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK) &&
		    qp->s_acked != qp->s_tail &&
		    qp->s_acked == response->restart_wqe_index &&
		    roce_psn(qp->s_last_psn + 1) == response->restart_psn &&
		    rvt_get_swqe_ptr(qp, qp->s_acked)->wr.opcode == IB_WR_RDMA_READ) {
			if (roce_rx_reports_pending(rqp)) {
				pending = true;
			} else {
				/* A racing tail must not spend the timer's bypass. */
				rqp->restart_rx_deferred = false;
				hfi2_dms_roce_restart(qp, response->restart_psn);
				pending = response->restart_pending &&
					  rqp->restart_rx_deferred;
				if (ib_rvt_state_ops[qp->state] & RVT_PROCESS_SEND_OK)
					hfi2_roce_schedule_send(qp);
			}
		}
		response->restart_pending = pending;
		spin_unlock_irqrestore(&qp->s_lock, sflags);
		spin_unlock_irqrestore(&qp->r_lock, rflags);
		if (!pending) {
			list_del_init(&rqp->read_restart_node);
			rvt_put_qp(qp);
		}
	}
}

void hfi2_dms_roce_restart(struct rvt_qp *qp, u32 psn)
{
	struct hfi2_dms_roce_qp *rqp = to_roce_priv(qp)->roce_qp;
	struct rvt_swqe *wqe;

	lockdep_assert_held(&qp->r_lock);
	lockdep_assert_held(&qp->s_lock);

	if (rqp)
		rqp->roce->stats.retry_restart++;
	if (rqp && rqp->read_response.first_diverted) {
		/* A lost terminal report must still reach reclaim through the timer. */
		if (!rqp->read_response.first_retry_pending) {
			rqp->read_response.first_retry_pending = true;
			roce_rif_row_reclaim(rqp);
		}
		return;
	}

	if (rqp && rqp->replay_pending)
		return;
	if (qp->s_acked == qp->s_tail)
		return;
	/*
	 * The reports that would have reset the timer may still sit unread in
	 * this QP's receive ring.  Give the worker one more period before
	 * resending; every other expiry restarts, so loss still recovers.
	 */
	if (rqp && rqp->rcd) {
		if (!rqp->restart_rx_deferred && roce_rx_reports_pending(rqp)) {
			rqp->restart_rx_deferred = true;
			rqp->roce->stats.retry_rx_defer++;
			rvt_mod_retry_timer(qp);
			hfi2_bulksvc_schedule(rqp->roce->svc);
			return;
		}
		rqp->restart_rx_deferred = false;
	}
	if (rqp)
		rqp->read_response.restart_pending = false;
	wqe = rvt_get_swqe_ptr(qp, qp->s_acked);

	/* Retry budget exhausted with the oldest WQE still unacked: fail. */
	if (qp->s_retry == 0) {
		if (rqp && rqp->sdma_req_holds) {
			roce_request_replay_defer(rqp, psn,
					  HFI2_DMS_ROCE_REPLAY_EXHAUSTED, 0);
			return;
		}
		if (rqp)
			roce_retry_exhausted_complete(rqp);
		else if (qp->s_last == qp->s_acked) {
			hfi2_dms_roce_clear_wqe_read_write_reply(qp, wqe);
			rvt_send_complete(qp, wqe, IB_WC_RETRY_EXC_ERR,
				      RVT_QP_LOCK_STATE_RS);
			rvt_error_qp(qp, IB_WC_WR_FLUSH_ERR,
				     RVT_QP_LOCK_STATE_RS);
		}
		return;
	}
	qp->s_retry--;

	/*
	 * A committed SDMA batch may still read retained request state when a
	 * timeout fires.  Record the replay without sleeping under r_lock/s_lock;
	 * the event owner rewinds only after the final local callback is consumed.
	 * Rebuild the whole oldest unacked WQE on its existing emitter epoch.
	 */
	if (rqp &&
	    roce_request_replay_defer(rqp, psn, HFI2_DMS_ROCE_REPLAY_SEND, 0))
		return;
	if (!rqp)
		roce_rewind_to_acked(qp);
}

/*
 * Classify a bypass frame from its EAL ingress header.
 *
 * Type is read before anything else because the Type 0 and Type 1 overlays
 * share every field position and differ only in meaning - q1 63:59 is a
 * multicast index under Type 0 and End_state under Type 1 - so reading a
 * RoCEv2 field from an Ethernet header yields a plausible wrong value rather
 * than an error.
 *
 * The L4 arm is counted rather than acted on.  The RSM rule matches L4 == 0x78
 * exactly (bulksvc.c, mask 0xFF value 0x78), so 0x79, 0x7A and 0x7C are not
 * steered to this context at all and these counters are expected to stay zero
 * until that rule is widened.  They exist so that a change in steering is
 * visible here immediately instead of presenting as unexplained loss.
 */
static __always_inline void roce_rx_classify(struct hfi2_dms_roce *roce,
					     const struct eal_ingress_header *ih)
{
	struct hfi2_dms_roce_stats *st = &roce->stats;
	u8 end_state;

	if (!ih)
		return;

	if (EAL_INGRESS_GET_TYPE(ih) != EAL_INGRESS_TYPE_ROCEV2) {
		st->rx_type_not_roce++;
		return;
	}

	switch (EAL_INGRESS_GET_L4(ih)) {
	case EAL_EGRESS_L4_ETH:
		st->rx_l4_eth++;
		break;
	case EAL_EGRESS_L4_EXCPTN:
		st->rx_l4_excptn++;
		break;
	case EAL_EGRESS_L4_VRMA:
		st->rx_l4_vrma++;
		break;
	case EAL_EGRESS_L4_TID:
		st->rx_l4_tid++;
		break;
	default:
		st->rx_l4_unknown++;
		break;
	}

	end_state = EAL_INGRESS_ROCE_GET_END_STATE(ih);
	switch (end_state) {
	case EAL_INGRESS_ROCE_END_STATE_OK:
		st->rx_end_state_ok++;
		break;
	case EAL_INGRESS_ROCE_END_STATE_FIRST_ERR:
		st->rx_end_state_first_err++;
		break;
	case EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO:
		st->rx_end_state_middle_oo++;
		break;
	case EAL_INGRESS_ROCE_END_STATE_MIDDLE_NO_QP:
		st->rx_end_state_middle_no_qp++;
		break;
	case EAL_INGRESS_ROCE_END_STATE_LAST_ERR:
		st->rx_end_state_last_err++;
		break;
	default:
		/*
		 * End_state is an enumeration, not a bitmask; every other
		 * value is reserved.  Count it rather than mapping it onto a
		 * neighbour, so a hardware or decode surprise is attributable.
		 */
		st->rx_end_state_reserved++;
		break;
	}
}

static bool roce_vrma_write_opcode(u8 opcode)
{
	return opcode >= IB_OPCODE_RC_RDMA_WRITE_FIRST &&
	       opcode <= IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
}

static bool
roce_vrma_software_read_reply(const struct eal_ingress_vrma_header *ih,
			      u8 opcode, u32 placed)
{
	const struct ib_other_headers *ohdr;

	if (opcode != IB_OPCODE_RC_RDMA_WRITE_ONLY || placed)
		return false;
	ohdr = roce_vrma_report_bth(ih, HFI2_ROCE_RETH_BYTES);
	return ohdr && be32_to_cpu(ohdr->u.rc.reth.rkey) ==
		HFI2_ROCE_RKEY_NO_OWNER;
}

static void roce_vrma_reset(struct hfi2_dms_roce_qp *rqp)
{
	rqp->h15_drop_sw = false;
	rqp->vrma_write_active = false;
	rqp->vrma_next_va = 0;
	rqp->vrma_length = 0;
	rqp->vrma_placed = 0;
	rqp->vrma_pasid = 0;
}

static void roce_rif_cleanup_snapshot(struct hfi2_dms_roce_qp *rqp,
				      struct roce_rif_cleanup_state *state)
{
	lockdep_assert_held(&rqp->qp->r_lock);
	lockdep_assert_held(&rqp->qp->s_lock);
	state->qpn = rqp->qp->ibqp.qp_num;
	state->superseded = rqp->tomb_bound &&
		(!rqp->roce->tombs ||
		 xa_load(&rqp->roce->tombs->qps, state->qpn) != rqp);
	state->h15_bucket = rqp->h15_bucket;
	state->lbs_bucket = rqp->lbs_bucket;
	state->lbs_entry = roce_last_by_software && rqp->lbs_entry;
	spin_lock(&rqp->roce->rif_lock);
	state->epoch = rqp->rif_epoch;
	spin_unlock(&rqp->roce->rif_lock);
}

static void roce_rif_cleanup_apply(struct hfi2_dms_roce_qp *rqp,
				   const struct roce_rif_cleanup_state *state)
{
	lockdep_assert_held(&rqp->qp->r_lock);
	lockdep_assert_held(&rqp->qp->s_lock);
	spin_lock(&rqp->roce->rif_lock);
	if (rqp->h15_bucket >= 0 &&
	    (state->cleared & BIT(rqp->h15_bucket))) {
		rqp->h15_bucket = -1;
		rqp->h15_pasid = 0;
		roce_h15_clear_owner_locked(rqp);
	}
	if (state->release) {
		rqp->h15_bucket = -1;
		rqp->h15_pasid = 0;
		rqp->h15_armed = false;
		roce_h15_clear_owner_locked(rqp);
		roce_vrma_reset(rqp);
	}
	if (rqp->rif_epoch != state->epoch)
		goto unlock;
	rqp->roce->stats.rif_read_alias_invalidate += state->alias_invalidated;
	rqp->roce->stats.rif_invalidate_read_err += state->invalidate_read_err;
	if (rqp->lbs_bucket >= 0 && (state->cleared & BIT(rqp->lbs_bucket)))
		rqp->lbs_bucket = -1;
	if (state->lbs_cleaned) {
		rqp->lbs_entry = false;
		rqp->lbs_bucket = state->lbs_bucket;
	}
unlock:
	spin_unlock(&rqp->roce->rif_lock);
}

/*
 * Retire software arms when no hardware LAST does so. Verify identity:
 * hardware may have freed the bucket and another QP may now own it.
 */
static void roce_rif_release_csr(struct hfi2_dms_roce *roce,
				 struct roce_rif_cleanup_state *state)
{
	struct hfi2_dms_roce_rif_entry e;
	u32 qpn = state->qpn;
	int b = state->h15_bucket;

	lockdep_assert_held(&roce->rif_mutex);
	state->release = true;
	if (state->superseded || b < 0 || !roce->rif_owner)
		return;
	if (!hfi2_dms_roce_rif_readback(roce, qpn, b, &e) && e.qpn != qpn) {
		roce_rif_forget(roce, qpn, b);
		roce->stats.rif_release_foreign++;
	} else {
		hfi2_dms_roce_rif_invalidate(roce, qpn, b);
		roce->stats.rif_release++;
	}
	state->h15_bucket = -1;
}

static void roce_rif_release(struct hfi2_dms_roce_qp *rqp)
{
	struct roce_rif_cleanup_state state = { };
	unsigned long rflags, sflags;
	bool entered;

	if (irqs_disabled()) {
		lockdep_assert_held(&rqp->qp->s_lock);
		if (rqp->h15_bucket >= 0) {
			rqp->rif_cleanup |= ROCE_RIF_RELEASE;
			roce_rif_queue(rqp);
		} else {
			rqp->h15_pasid = 0;
			spin_lock(&rqp->roce->rif_lock);
			roce_h15_clear_owner_locked(rqp);
			spin_unlock(&rqp->roce->rif_lock);
		}
		rqp->h15_armed = false;
		roce_vrma_reset(rqp);
		return;
	}
	entered = roce_rif_enter(rqp->roce);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_snapshot(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_rif_release_csr(rqp->roce, &state);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_apply(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_rif_leave(rqp->roce, entered);
}

/*
 * Invalidate the base QPN, its READ alias, or both, as selected by @cleanup.
 * For an entry hardware created, software never learns the bucket.
 * Returns the number cleared.
 */
static int roce_rif_invalidate_qpn_csr(struct hfi2_dms_roce_qp *rqp, u8 cleanup,
				       struct roce_rif_cleanup_state *state)
{
	struct hfi2_dms_roce_rif_entry e;
	unsigned long flags;
	u32 qpn = state->qpn;
	int b, entry_current, found = 0, ret, retries;
	u32 owner;
	bool incomplete = false;
	bool unreadable = false;
	bool entered;

	if (state->superseded)
		return 0;
	entered = roce_rif_enter(rqp->roce);
	for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
		retries = 0;
recheck:
		ret = hfi2_dms_roce_rif_readback(rqp->roce, qpn, (u8)b, &e);
		if (ret) {
			if (ret != -ENOENT) {
				state->invalidate_read_err++;
				unreadable = true;
			}
			continue;
		}
		if (!((cleanup & (ROCE_RIF_CLEAN_QP | ROCE_RIF_CLEAN_BASE)) &&
		      e.qpn == qpn) &&
		    !((cleanup & (ROCE_RIF_CLEAN_QP | ROCE_RIF_CLEAN_ALIAS)) &&
		      e.qpn == (qpn | HFI2_ROCE_QPN_ALIAS_BIT)))
			continue;
		spin_lock_irqsave(&rqp->roce->rif_lock, flags);
		if (!rqp->roce->initialized || !rqp->roce->rif_owner ||
		    !rqp->roce->rif_pasid) {
			spin_unlock_irqrestore(&rqp->roce->rif_lock, flags);
			incomplete = true;
			continue;
		}
		owner = rqp->roce->rif_owner[EAL_RIF_ROW_FROM_QP(e.qpn) *
					     EAL_TABLE_ENTRIES_PER_ROW + b];
		spin_unlock_irqrestore(&rqp->roce->rif_lock, flags);
		/* A foreign software owner prevents the helper from reading hardware. */
		if (owner != HFI2_ROCE_RIF_NO_OWNER && owner != e.qpn) {
			incomplete = true;
			continue;
		}
		entry_current =
			roce_rif_reclaim_entry_current_mutex_held(rqp->roce, &e, b);
		if (entry_current < 0) {
			unreadable = true;
			state->invalidate_read_err++;
			dd_dev_warn_ratelimited(rqp->dd, "roce: RIF recheck failed\n");
			continue;
		}
		if (!entry_current) {
			/* Reclassify hardware retirement/replacement, including our new burst. */
			if (++retries < HFI2_ROCE_RIF_RECLAIM_TRIES)
				goto recheck;
			incomplete = true;
			continue;
		}
		roce_rif_invalidate_mutex_held(rqp->roce, e.qpn, (u8)b);
		if ((cleanup & ROCE_RIF_CLEAN_ALIAS) &&
		    e.qpn == (qpn | HFI2_ROCE_QPN_ALIAS_BIT)) {
			struct hfi2_dms_roce_rif_entry check;

			ret = hfi2_dms_roce_rif_readback(rqp->roce, qpn, (u8)b, &check);
			if (ret != -ENOENT &&
			    (ret || check.qpn == (qpn | HFI2_ROCE_QPN_ALIAS_BIT))) {
				state->invalidate_read_err++;
				unreadable = true;
			} else {
				state->alias_invalidated++;
			}
		}
		state->cleared |= BIT(b);
		if (state->h15_bucket == b)
			state->h15_bucket = -1;
		if (state->lbs_bucket == b)
			state->lbs_bucket = -1;
		found++;
	}
	if (unreadable)
		dd_dev_warn_ratelimited(rqp->dd,
					"roce: RIF teardown qpn %u skipped unreadable buckets; an entry may remain\n",
					qpn);
	if (incomplete)
		dd_dev_warn_ratelimited(rqp->dd,
					"roce: RIF teardown qpn %u has conflicting ownership or changing entries\n",
					qpn);
	roce_rif_leave(rqp->roce, entered);
	return unreadable ? -EIO : incomplete ? -EAGAIN : found;
}

static int roce_rif_invalidate_qpn(struct hfi2_dms_roce_qp *rqp, u8 cleanup)
{
	struct roce_rif_cleanup_state state = { };
	unsigned long rflags, sflags;
	int ret;
	bool entered;

	if (irqs_disabled()) {
		rqp->rif_cleanup |= cleanup;
		roce_rif_queue(rqp);
		return 0;
	}
	entered = roce_rif_enter(rqp->roce);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_snapshot(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	ret = roce_rif_invalidate_qpn_csr(rqp, cleanup, &state);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_apply(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_rif_leave(rqp->roce, entered);
	return ret;
}

static int roce_rif_invalidate_qp(struct hfi2_dms_roce_qp *rqp)
{
	return roce_rif_invalidate_qpn(rqp, ROCE_RIF_CLEAN_QP);
}

static void roce_rif_queue(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;
	unsigned long flags;

	spin_lock_irqsave(&roce->rif_lock, flags);
	if (!rqp->rif_queued) {
		if (!rqp->rif_arm_kind && !rqp->rif_busy)
			rqp->rif_pending_epoch = rqp->rif_epoch;
		rvt_get_qp(rqp->qp);
		if (!rqp->rif_busy)
			reinit_completion(&rqp->rif_idle);
		list_add_tail(&rqp->rif_node, &roce->rif_pending);
		rqp->rif_queued = true;
	}
	spin_unlock_irqrestore(&roce->rif_lock, flags);
	hfi2_bulksvc_schedule(roce->svc);
}

static void roce_rif_defer_arm(struct hfi2_dms_roce_qp *rqp,
			       const struct hfi2_dms_roce_rif_entry *entry,
			       struct rvt_mregion *mr,
			       enum roce_rif_arm_kind kind)
{
	lockdep_assert_held(&rqp->qp->s_lock);
	if (WARN_ON_ONCE(rqp->rif_arm_kind))
		return;
	/* Only the bulksvc producer stages arms; cleanup may already be queued. */
	if (WARN_ON_ONCE(rqp->rif_busy))
		return;
	spin_lock(&rqp->roce->rif_lock);
	rqp->rif_entry = *entry;
	rqp->rif_arm_start_ns = ktime_get_ns();
	rqp->rif_arm_kind = kind;
	rqp->rif_pending_epoch = rqp->rif_epoch;
	rqp->rif_mr = mr;
	if (mr) {
		struct hfi2_roce_mr_priv *priv = mr->driver_priv;

		rvt_get_mr(mr);
		rqp->rif_token = priv->pasid;
	}
	spin_lock(&rqp->roce->rows_lock);
	{
		struct roce_rif_rows *tracked;

		tracked = xa_load(&rqp->roce->rif_pasid_rows, entry->pasid);
		rqp->rif_stage_error = 0;
		if ((mr && (!READ_ONCE(rqp->rif_token->live) ||
			    READ_ONCE(rqp->rif_token->quiesce_failed))) ||
		    xa_load(&rqp->dd->roce_pasid_blocked, entry->pasid) ||
		    (tracked && tracked->retiring)) {
			rqp->rif_stage_error = -ESTALE;
		} else {
			if (!tracked)
				tracked = roce_rif_pasid_get_locked(rqp->roce, entry->pasid);
			if (tracked)
				__set_bit(EAL_RIF_ROW_FROM_QP(entry->qpn), tracked->rows);
			else
				rqp->rif_stage_error = -ENOMEM;
		}
	}
	spin_unlock(&rqp->roce->rows_lock);
	if (!rqp->rif_queued && !rqp->rif_busy) {
		rvt_get_qp(rqp->qp);
		reinit_completion(&rqp->rif_idle);
		list_add_tail(&rqp->rif_node, &rqp->roce->rif_pending);
		rqp->rif_queued = true;
	}
	spin_unlock(&rqp->roce->rif_lock);
	rqp->roce->stats.rif_arm_deferred++;
	hfi2_bulksvc_schedule(rqp->roce->svc);
}

static void roce_rif_cancel(struct hfi2_dms_roce_qp *rqp)
{
	unsigned long flags;

	if (!rqp || !rqp->roce)
		return;
	spin_lock_irqsave(&rqp->roce->rif_lock, flags);
	rqp->rif_epoch++;
	rqp->rif_cancelled = true;
	spin_unlock_irqrestore(&rqp->roce->rif_lock, flags);
}

static void roce_rif_wait(struct hfi2_dms_roce_qp *rqp)
{
	struct hfi2_dms_roce *roce = rqp->roce;

	/* A PASID release on the worker must consume, not wait on, its own queue. */
	if (current_work() == &roce->svc->lanes[0].work) {
		roce_rif_progress(roce);
		return;
	}
	while (!completion_done(&rqp->rif_idle)) {
		hfi2_bulksvc_schedule(roce->svc);
		if (READ_ONCE(roce->svc->stop_scheduling)) {
			wait_for_completion(&roce->svc->worker_exited_done);
			roce_rif_progress(roce);
		}
		/* Recheck shutdown if scheduling raced the stop flag. */
		wait_for_completion_timeout(&rqp->rif_idle, msecs_to_jiffies(20));
	}
}

static void roce_rif_flush_invalidations(struct hfi2_dms_roce *roce)
{
	unsigned long flags, slot;
	u32 qpn;

	lockdep_assert_held(&roce->rif_mutex);
	for (;;) {
		spin_lock_irqsave(&roce->rif_lock, flags);
		if (!roce->rif_dirty_count) {
			spin_unlock_irqrestore(&roce->rif_lock, flags);
			break;
		}
		slot = find_first_bit(roce->rif_dirty,
				      EAL_RIF_TABLE_ROWS * EAL_TABLE_ENTRIES_PER_ROW);
		if (slot == EAL_RIF_TABLE_ROWS * EAL_TABLE_ENTRIES_PER_ROW) {
			spin_unlock_irqrestore(&roce->rif_lock, flags);
			break;
		}
		qpn = roce->rif_invalidations[slot];
		__clear_bit(slot, roce->rif_dirty);
		WRITE_ONCE(roce->rif_dirty_count, roce->rif_dirty_count - 1);
		if (roce->rif_owner[slot] != qpn)
			qpn = HFI2_ROCE_RIF_NO_OWNER;
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		if (qpn == HFI2_ROCE_RIF_NO_OWNER)
			continue;
		roce_rif_invalidate_mutex_held(roce, qpn,
					       slot % EAL_TABLE_ENTRIES_PER_ROW);
	}
}

static bool roce_aeth_is_fatal_nak(u8 syndrome)
{
	switch (syndrome) {
	case IB_NAK_INVALID_REQUEST:
	case IB_NAK_REMOTE_ACCESS_ERROR:
	case IB_NAK_REMOTE_OPERATIONAL_ERROR:
	case IB_NAK_INVALID_RD_REQUEST:
		return true;
	default:
		return false;
	}
}

/*
 * Take the CSR mutex outside QP locks. FIRST is already copied and
 * awaits a replay NAK.
 */
static void roce_rif_progress(struct hfi2_dms_roce *roce)
{
	struct hfi2_dms_roce_qp *rqp;
	unsigned long flags, rflags, sflags;
	bool entered, worker;

	if (!roce || WARN_ON_ONCE(irqs_disabled()))
		return;
	if (list_empty_careful(&roce->rif_pending) &&
	    !READ_ONCE(roce->rif_dirty_count))
		return;
	worker = current_work() == &roce->svc->lanes[0].work;
	entered = roce_rif_enter(roce);
	roce_rif_flush_invalidations(roce);
	for (;;) {
		struct roce_rif_cleanup_state state = { };
		struct rvt_mregion *mr;
		struct rvt_qp *qp;
		u8 kind;
		bool cancelled, arm_current, token_dead, recover, reclaim, tomb_reclaim;
		bool h15_fatal = false;
		bool write_gap_error = false;
		bool nak_pending;
		u32 nak_psn;
		u8 cleanup;
		int bucket = -ECANCELED;

		spin_lock_irqsave(&roce->rif_lock, flags);
		if (list_empty(&roce->rif_pending)) {
			spin_unlock_irqrestore(&roce->rif_lock, flags);
			break;
		}
		rqp = list_first_entry(&roce->rif_pending,
				       struct hfi2_dms_roce_qp, rif_node);
		list_del_init(&rqp->rif_node);
		rqp->rif_queued = false;
		rqp->rif_busy = true;
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		qp = rqp->qp;
		spin_lock_irqsave(&qp->r_lock, rflags);
		spin_lock_irqsave(&qp->s_lock, sflags);
		roce_rif_cleanup_snapshot(rqp, &state);
		kind = rqp->rif_arm_kind;
		mr = rqp->rif_mr;
		cleanup = rqp->rif_cleanup;
		reclaim = rqp->rif_reclaim;
		tomb_reclaim = rqp->rif_tomb_reclaim;
		nak_pending = rqp->rif_nak_pending;
		nak_psn = rqp->rif_nak_psn;
		rqp->rif_nak_pending = false;
		rqp->rif_cleanup = false;
		rqp->rif_reclaim = false;
		rqp->rif_tomb_reclaim = false;
		spin_lock(&roce->rif_lock);
		cancelled = !READ_ONCE(roce->active) || rqp->rif_cancelled ||
			rqp->rif_pending_epoch != rqp->rif_epoch ||
			!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK);
		spin_unlock(&roce->rif_lock);
		spin_unlock_irqrestore(&qp->s_lock, sflags);
		spin_unlock_irqrestore(&qp->r_lock, rflags);
		if (cleanup & (ROCE_RIF_CLEAN_QP | ROCE_RIF_CLEAN_BASE |
			       ROCE_RIF_CLEAN_ALIAS))
			write_gap_error = roce_rif_invalidate_qpn_csr(rqp, cleanup, &state) < 0;
		if (cleanup & ROCE_RIF_RELEASE)
			roce_rif_release_csr(roce, &state);
		if (cleanup & ROCE_RIF_CLEAN_LBS)
			roce_lbs_invalidate_csr(roce, &state, false);
		if (tomb_reclaim && !cancelled && !state.superseded)
			roce_tomb_row_full(roce, state.qpn);
		if (reclaim)
			roce_rif_row_reclaim_csr(rqp, &state);
		if (kind && !cancelled && !READ_ONCE(rqp->rif_stage_error)) {
			bucket = hfi2_dms_roce_rif_arm(roce, &rqp->rif_entry,
						       rqp->rif_token);
			if (kind == ROCE_RIF_ARM_H15 &&
			    (bucket == -ENOSPC || bucket == -EBUSY) &&
			    READ_ONCE(roce_rif_reclaim) &&
			    roce_rif_row_reclaim_csr(rqp, &state)) {
				bucket = hfi2_dms_roce_rif_arm(roce, &rqp->rif_entry,
							       rqp->rif_token);
				if (bucket >= 0)
					roce->stats.h15_arm_reclaim++;
			}
		}
		spin_lock_irqsave(&qp->r_lock, rflags);
		spin_lock_irqsave(&qp->s_lock, sflags);
		roce_rif_cleanup_apply(rqp, &state);
		spin_lock(&roce->rif_lock);
		arm_current = !cancelled && READ_ONCE(roce->active) &&
			!rqp->rif_cancelled &&
			rqp->rif_pending_epoch == rqp->rif_epoch &&
			(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK);
		token_dead = mr && !READ_ONCE(rqp->rif_token->live);
		cancelled |= !arm_current || rqp->rif_stage_error == -ESTALE ||
			bucket == -ESTALE;
		spin_lock(&roce->rows_lock);
		if (kind) {
			struct roce_rif_rows *tracked;

			tracked = xa_load(&roce->rif_pasid_rows, rqp->rif_entry.pasid);
			cancelled |= (!tracked && rqp->rif_stage_error != -ENOMEM) ||
				(tracked && tracked->retiring) ||
				(mr && !READ_ONCE(rqp->rif_token->live));
		}
		spin_unlock(&roce->rows_lock);
		recover = cancelled && arm_current && mr && !token_dead;
		if (kind && cancelled) {
			roce->stats.rif_arm_cancelled++;
		} else if (kind == ROCE_RIF_ARM_H15) {
			if (bucket >= 0) {
				roce_h15_clear_owner_locked(rqp);
				rqp->h15_mr = mr;
				if (mr)
					rvt_get_mr(mr);
				rqp->h15_token = rqp->rif_token;
				rqp->h15_bucket = bucket;
				rqp->h15_pasid = rqp->rif_entry.pasid;
				rqp->h15_armed = true;
				rqp->vrma_write_active = true;
				rqp->vrma_pasid = rqp->rif_entry.pasid;
				rqp->vrma_next_va = rqp->rif_entry.start_vaddr +
					rqp->rif_payload;
				rqp->vrma_placed = rqp->rif_payload;
				rqp->vrma_length = rqp->rif_length;
				rqp->vrma_first_psn = rqp->rif_entry.start_psn;
				rqp->lbs_burst = roce_last_by_software;
				rqp->lbs_entry = roce_last_by_software;
				roce->stats.h15_arm_ok++;
			} else {
				roce->stats.h15_arm_fail++;
				if (rqp->reclaim_psn != rqp->rif_entry.start_psn) {
					rqp->reclaim_psn = rqp->rif_entry.start_psn;
					rqp->reclaim_tries = 0;
				}
				h15_fatal = rqp->reclaim_tries++ >=
					HFI2_ROCE_RIF_RECLAIM_TRIES;
				qp->r_psn = rqp->rif_entry.start_psn;
				qp->r_state = IB_OPCODE_RC_RDMA_WRITE_LAST;
				rvt_put_ss(&qp->r_sge);
				roce->stats.h15_arm_nak++;
			}
			qp->r_nak_state = IB_NAK_PSN_ERROR;
			rqp->h15_drop_sw = bucket >= 0;
			rqp->ack_pending = true;
			rqp->ack_psn = qp->r_psn & HFI2_ROCE_PSN_MASK;
			rqp->ack_syndrome = IB_NAK_PSN_ERROR;
			roce->stats.h15_nak++;
		}
		/* ERROR cleanup may owe a fatal NAK; RESET must discard all replies. */
		if (cancelled) {
			if (qp->state != IB_QPS_ERR ||
			    !roce_aeth_is_fatal_nak(rqp->ack_syndrome))
				rqp->ack_pending = false;
			if (kind == ROCE_RIF_ARM_H15) {
				rvt_put_ss(&qp->r_sge);
				roce_vrma_reset(rqp);
				if (recover) {
					/* Replay FIRST; an unarmed LAST may have no payload. */
					qp->r_psn = rqp->rif_entry.start_psn;
					qp->r_state = IB_OPCODE_RC_RDMA_WRITE_LAST;
					qp->r_nak_state = IB_NAK_PSN_ERROR;
					rqp->ack_pending = true;
					rqp->ack_psn = qp->r_psn;
					rqp->ack_syndrome = IB_NAK_PSN_ERROR;
					roce->stats.h15_arm_nak++;
					roce->stats.h15_nak++;
				}
			}
		}
		if (kind != ROCE_RIF_ARM_NONE) {
			u64 ns = ktime_get_ns() - rqp->rif_arm_start_ns;

			roce->stats.rif_arm_completed++;
			roce->stats.rif_arm_latency_ns += ns;
			if (ns > roce->stats.rif_arm_latency_max_ns)
				roce->stats.rif_arm_latency_max_ns = ns;
			if (ns > HFI2_DMS_ROCE_RIF_ARM_SCAN_SLOW_NS)
				roce->stats.rif_arm_latency_slow++;
		}
		rqp->rif_arm_kind = ROCE_RIF_ARM_NONE;
		/* The stage result belongs to this arm, not a later cleanup item. */
		rqp->rif_stage_error = 0;
		rqp->rif_mr = NULL;
		spin_unlock(&roce->rif_lock);
		if (reclaim && rqp->read_response.first_retry_pending) {
			rqp->read_response.first_retry_pending = false;
			if (!cancelled) {
				rqp->read_response.first_diverted = false;
				rqp->read_response.first_replaying = true;
				rqp->read_response.restart_latched = false;
				roce->stats.rrsp_first_retry++;
				roce_restart_read_response(rqp);
			}
		}
		if ((cleanup & ROCE_RIF_CLEAN_ALIAS) && rqp->rif_read_cleanup &&
		    READ_ONCE(roce->active) && !rqp->rif_cancelled &&
		    state.epoch == rqp->rif_epoch &&
		    (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)) {
			if (write_gap_error) {
				rvt_error_qp(qp, IB_WC_LOC_QP_OP_ERR, RVT_QP_LOCK_STATE_RS);
			} else {
				rqp->rif_read_cleanup = false;
				if (!roce_request_replay_defer(rqp, rqp->replay_psn,
							       HFI2_DMS_ROCE_REPLAY_NONE, 0) &&
				    !(qp->s_flags & RVT_S_WAIT_RNR))
					hfi2_roce_schedule_send(qp);
			}
		}
		if ((cleanup & ROCE_RIF_CLEAN_BASE) && rqp->write_gap.active &&
		    !cancelled && state.epoch == rqp->rif_epoch) {
			if (write_gap_error)
				roce_responder_error(rqp, to_roce_priv(qp),
						     IB_WC_LOC_QP_OP_ERR,
						     IB_NAK_INVALID_REQUEST);
			else if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce->stats.rx_write_nak_seq++;
				roce_ack_or_defer(rqp, to_roce_priv(qp),
						  qp->r_psn, IB_NAK_PSN_ERROR);
			}
		}
		if (nak_pending && !cancelled && !state.superseded &&
		    state.epoch == rqp->rif_epoch &&
		    nak_psn == (qp->r_psn & HFI2_ROCE_PSN_MASK)) {
			if (write_gap_error) {
				roce_responder_error(rqp, to_roce_priv(qp),
						     IB_WC_LOC_QP_OP_ERR,
						     IB_NAK_INVALID_REQUEST);
			} else if (rqp->rif_cleanup || rqp->rif_reclaim ||
				   rqp->rif_tomb_reclaim || rqp->rif_nak_pending) {
				if (!rqp->rif_nak_pending)
					roce_rif_recovery_nak(rqp, nak_psn);
			} else {
				rqp->ack_pending = true;
				rqp->ack_psn = nak_psn;
				rqp->ack_syndrome = IB_NAK_PSN_ERROR;
			}
		}
		if (cancelled && token_dead &&
		    (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK))
			rvt_error_qp(qp, IB_WC_LOC_PROT_ERR, RVT_QP_LOCK_STATE_RS);
		if (h15_fatal) {
			/* An unarmed WRITE LAST loses its payload; fail rather than fall back. */
			roce->stats.rif_reclaim_giveup++;
			rqp->ack_pending = false;
			roce_responder_error(rqp, to_roce_priv(qp),
					     IB_WC_LOC_QP_OP_ERR, IB_NAK_INVALID_REQUEST);
		}
		/* Only the primary worker may emit the now-unblocked ACK inline. */
		if (worker && kind && !cancelled && rqp->ack_pending &&
		    !roce_ack_retry_pending(rqp, to_roce_priv(qp)) &&
		    !rqp->ack_pending)
			roce->stats.rif_arm_ack_inline++;
		if (rqp->ack_pending && qp->state != IB_QPS_RESET &&
		    !READ_ONCE(rqp->tx_cancelled))
			hfi2_dms_roce_enqueue(qp);
		spin_unlock_irqrestore(&qp->s_lock, sflags);
		spin_unlock_irqrestore(&qp->r_lock, rflags);
		if (cancelled && bucket >= 0)
			roce_rif_invalidate_mutex_held(roce, rqp->rif_entry.qpn, bucket);
		if (mr)
			rvt_put_mr(mr);
		spin_lock_irqsave(&roce->rif_lock, flags);
		rqp->rif_busy = false;
		if (!rqp->rif_queued)
			complete_all(&rqp->rif_idle);
		spin_unlock_irqrestore(&roce->rif_lock, flags);
		rvt_put_qp(qp);
	}
	roce_rif_leave(roce, entered);
}

static bool roce_vrma_begin(struct hfi2_dms_roce_qp *rqp,
			    const struct eal_ingress_vrma_header *ih,
			    u32 placed)
{
	u64 va = EAL_INGRESS_VRMA_GET_VA(ih);

	if (rqp->vrma_write_active || !placed)
		return false;

	rqp->vrma_write_active = true;
	rqp->vrma_next_va = va + placed;
	rqp->vrma_length = 0;
	rqp->vrma_placed = placed;
	rqp->vrma_pasid = EAL_INGRESS_VRMA_GET_PASID(ih);
	return true;
}

static bool roce_vrma_continue(struct hfi2_dms_roce_qp *rqp,
			       const struct eal_ingress_vrma_header *ih,
			       u32 placed, bool last)
{
	u64 va = EAL_INGRESS_VRMA_GET_VA(ih);

	if (!rqp->vrma_write_active || !placed || va != rqp->vrma_next_va ||
	    EAL_INGRESS_VRMA_GET_PASID(ih) != rqp->vrma_pasid)
		return false;
	if ((last && placed > rqp->qp->pmtu) ||
	    (!last && placed != rqp->qp->pmtu) ||
	    rqp->vrma_placed > U32_MAX - placed)
		return false;

	rqp->vrma_next_va += placed;
	rqp->vrma_placed += placed;
	return true;
}

/*
 * Retire the RIF entry a roce_last_by_software burst leaves behind.  Hardware
 * created it (or H15 armed it) and the diverted LAST never touches it, so it
 * stays valid and RUNNING until software clears it.  The bucket is not in any
 * report, so look where it was last found, then scan the row.  Matching on
 * QPN is exact: hfi2_dms_roce_rif_arm() keeps one entry per QP, and hardware
 * reuses the bucket of an entry for the same QP rather than allocating a
 * second.
 *
 * @early: called at the burst's final MIDDLE rather than its LAST, so the
 * next FIRST - which the peer sends right behind the LAST - finds the bucket
 * free instead of meeting this entry still RUNNING.
 */
static void roce_lbs_invalidate_csr(struct hfi2_dms_roce *roce,
				    struct roce_rif_cleanup_state *state, bool early)
{
	struct hfi2_dms_roce_stats *st = &roce->stats;
	struct hfi2_dms_roce_rif_entry e;
	u32 qpn = state->qpn;
	int b, found = 0;

	lockdep_assert_held(&roce->rif_mutex);
	if (state->superseded || !state->lbs_entry)
		return;
	state->lbs_cleaned = true;
	b = state->lbs_bucket >= 0 ? state->lbs_bucket : state->h15_bucket;
	if (b >= 0 && !hfi2_dms_roce_rif_readback(roce, qpn, b, &e) && e.qpn == qpn) {
		hfi2_dms_roce_rif_invalidate(roce, qpn, b);
		state->lbs_bucket = b;
		state->cleared |= BIT(b);
		st->rif_lbs_cache_hit++;
		found = 1;
	} else {
		st->rif_lbs_scan++;
		for (b = 0; b < EAL_TABLE_ENTRIES_PER_ROW; b++) {
			if (hfi2_dms_roce_rif_readback(roce, qpn, b, &e) || e.qpn != qpn)
				continue;
			hfi2_dms_roce_rif_invalidate(roce, qpn, b);
			state->lbs_bucket = b;
			state->cleared |= BIT(b);
			found++;
		}
		if (!found)
			st->rif_lbs_scan_miss++;
		else if (found > 1)
			st->rif_lbs_multi++;
	}
	st->rif_lbs_inval += found;
	if (found && early)
		st->rif_lbs_early++;
}

static void roce_lbs_invalidate(struct hfi2_dms_roce_qp *rqp, bool early)
{
	struct roce_rif_cleanup_state state = { };
	unsigned long rflags, sflags;
	bool entered;

	if (!rqp->roce)
		return;
	if (irqs_disabled()) {
		if (roce_last_by_software && rqp->lbs_entry) {
			rqp->rif_cleanup |= ROCE_RIF_CLEAN_LBS;
			roce_rif_queue(rqp);
		}
		return;
	}
	entered = roce_rif_enter(rqp->roce);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_snapshot(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_lbs_invalidate_csr(rqp->roce, &state, early);
	spin_lock_irqsave(&rqp->qp->r_lock, rflags);
	spin_lock_irqsave(&rqp->qp->s_lock, sflags);
	roce_rif_cleanup_apply(rqp, &state);
	spin_unlock_irqrestore(&rqp->qp->s_lock, sflags);
	spin_unlock_irqrestore(&rqp->qp->r_lock, rflags);
	roce_rif_leave(rqp->roce, entered);
}

/*
 * Take over a burst whose FIRST hardware placed, so software can finish it
 * at the LAST.  The FIRST report carries the whole frame header (26 dwords:
 * the 32-byte VRMA header, then Ethernet, IPv4, UDP, BTH and RETH), which is
 * everything roce_responder_write() derives from a software FIRST.
 *
 * Returns 0 when adopted, 1 when the report is not this QP's next burst
 * (a retransmitted FIRST hardware placed again), or -1 after the QP was
 * moved to error.
 */
/*
 * The BTH of the packet header hardware copied behind the VRMA header, or
 * NULL when the copy is too short to hold the BTH and @ext_len bytes after
 * it.  A short WRITE LAST, or any frame from a PFC peer, carries a priority
 * tag (see roce_unpadded).
 */
static __always_inline struct ib_other_headers *
roce_vrma_report_bth(const struct eal_ingress_vrma_header *ih, u32 ext_len)
{
	u8 *eth = (u8 *)ih + sizeof(*ih);
	u32 have = EAL_INGRESS_VRMA_GET_HDR_DWORDS(ih) * sizeof(u32);
	u32 off = HFI2_ROCE_IPV4_BTH_OFFSET;

	if (have < sizeof(*ih) + 2 * ETH_ALEN + 2)
		return NULL;
	if (get_unaligned_be16(eth + 2 * ETH_ALEN) == ETH_P_8021Q)
		off += VLAN_HLEN;
	if (have < sizeof(*ih) + off + HFI2_ROCE_BTH_BYTES + ext_len)
		return NULL;
	return (struct ib_other_headers *)(eth + off);
}

/*
 * The PSN of a placement report, from the packet header hardware copied
 * behind the VRMA header.  False when the copy is too short to hold a BTH.
 */
static bool roce_vrma_report_psn(const struct eal_ingress_vrma_header *ih,
				 u32 *psn)
{
	const struct ib_other_headers *ohdr = roce_vrma_report_bth(ih, 0);

	if (!ohdr)
		return false;
	*psn = ib_bth_get_psn((struct ib_other_headers *)ohdr) &
	       HFI2_ROCE_PSN_MASK;
	return true;
}

/*
 * Whether the packet behind a placement report asked for an ACK.  Hardware
 * places such a packet like any other and nothing else answers it; an RXE
 * requester asks every 64 packets and stops at 128 unacknowledged.
 */
static bool roce_vrma_report_ackreq(const struct eal_ingress_vrma_header *ih)
{
	struct ib_other_headers *ohdr = roce_vrma_report_bth(ih, 0);

	return ohdr && ib_bth_get_ackreq(ohdr);
}

/*
 * A report for a packet behind r_psn: a resend of data already accepted.
 * Answer it as the software path answers a duplicate, when it asks.
 */
static void roce_vrma_dup(struct hfi2_dms_roce_qp *rqp,
			  struct hfi2_qp_priv_roce *priv,
			  const struct eal_ingress_vrma_header *ih)
{
	rqp->roce->stats.rx_vrma_dup++;
	if (roce_vrma_report_ackreq(ih))
		roce_ack_or_defer(rqp, priv,
				  roce_psn(rqp->qp->r_psn - 1), 0);
}

/*
 * Hardware places a FIRST or ONLY at any PSN its R_Key admits, and the
 * packets that follow it, so a burst ahead of r_psn is already in memory.
 * Accept none of it: no ACK, no immediate, no r_psn move.  Retire the entry
 * it left RUNNING, or the resent FIRST at r_psn would be diverted, and ask
 * again from r_psn once.
 */
static void roce_vrma_ahead(struct hfi2_dms_roce_qp *rqp,
			    struct hfi2_qp_priv_roce *priv)
{
	struct rvt_qp *qp = rqp->qp;

	rqp->roce->stats.rx_vrma_ahead++;
	roce_rif_invalidate_qpn(rqp, ROCE_RIF_CLEAN_BASE);
	if (qp->r_nak_state && qp->r_nak_state != IB_NAK_PSN_ERROR)
		return;
	if (!qp->r_nak_state)
		rqp->roce->stats.rx_vrma_nak_seq++;
	qp->r_nak_state = IB_NAK_PSN_ERROR;
	roce_rif_recovery_nak(rqp, qp->r_psn & HFI2_ROCE_PSN_MASK);
}

/*
 * The RETH length of a FIRST placement report, or 0 when the header copy is
 * too short to hold the RETH.
 */
static u32 roce_vrma_report_length(const struct eal_ingress_vrma_header *ih)
{
	const struct ib_other_headers *ohdr =
		roce_vrma_report_bth(ih, sizeof(struct ib_reth));

	if (!ohdr)
		return 0;
	return be32_to_cpu(ohdr->u.rc.reth.length);
}

static int roce_lbs_adopt(struct hfi2_dms_roce_qp *rqp,
			  struct hfi2_qp_priv_roce *priv,
			  const struct eal_ingress_vrma_header *ih, u32 placed)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	struct ib_other_headers *ohdr;
	struct ib_reth reth;
	u32 psn, len;
	u64 va;

	ohdr = roce_vrma_report_bth(ih, sizeof(reth));
	if (!ohdr) {
		st->rx_lbs_hdr_short++;
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return -1;
	}
	psn = ib_bth_get_psn(ohdr) & HFI2_ROCE_PSN_MASK;
	memcpy(&reth, &ohdr->u.rc.reth, sizeof(reth));
	/*
	 * A NAK names the PSN after a FIRST software already took, but the
	 * requester replays the whole WQE, so the FIRST comes back.  With no
	 * entry left for the QP, hardware accelerates it and builds a new
	 * entry whose next_psn is exactly software's r_psn.  Its payload is
	 * the one software already copied, so carry on with that burst and
	 * let the entry place the MIDDLEs software is waiting for.
	 */
	if (((psn + 1) & HFI2_ROCE_PSN_MASK) ==
	    (qp->r_psn & HFI2_ROCE_PSN_MASK) &&
	    psn == rqp->lbs_first_psn &&
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST &&
	    qp->r_rcv_len == placed && qp->r_len > placed &&
	    get_ib_reth_vaddr(&reth) == rqp->lbs_first_va &&
	    EAL_INGRESS_VRMA_GET_VA(ih) == rqp->lbs_first_va) {
		rqp->lbs_burst = true;
		rqp->vrma_first_psn = psn;
		st->rx_lbs_adopt_dup++;
		return 2;
	}
	if (psn != (qp->r_psn & HFI2_ROCE_PSN_MASK) ||
	    qp->r_state == IB_OPCODE_RC_SEND_FIRST ||
	    qp->r_state == IB_OPCODE_RC_SEND_MIDDLE ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	    qp->r_state == IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
		st->rx_lbs_adopt_skip++;
		return 1;
	}
	len = be32_to_cpu(reth.length);
	va = get_ib_reth_vaddr(&reth);
	if (!(qp->qp_access_flags & IB_ACCESS_REMOTE_WRITE) ||
	    len <= placed || va != EAL_INGRESS_VRMA_GET_VA(ih)) {
		st->rx_lbs_rkey_err++;
		roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
				     IB_NAK_INVALID_REQUEST);
		return -1;
	}
	qp->r_len = len;
	qp->r_rcv_len = 0;
	qp->r_sge.sg_list = NULL;
	if (unlikely(!rvt_rkey_ok(qp, &qp->r_sge.sge, len, va,
				  be32_to_cpu(reth.rkey),
				  IB_ACCESS_REMOTE_WRITE))) {
		st->rx_lbs_rkey_err++;
		roce_responder_error(rqp, priv, IB_WC_LOC_PROT_ERR,
				     IB_NAK_REMOTE_ACCESS_ERROR);
		return -1;
	}
	qp->r_sge.num_sge = 1;
	roce_skip_sge(&qp->r_sge, placed);
	qp->r_rcv_len = placed;
	rqp->lbs_burst = true;
	rqp->lbs_first_psn = psn;
	rqp->lbs_first_va = va;
	st->rx_lbs_adopt++;
	return 0;
}

/*
 * The last packet of a WRITE with immediate, placed by hardware: take the
 * receive WQE it consumes and post the completion carrying the immediate
 * data from the header hardware copied behind the report.  @len is the
 * message length from the RETH.
 *
 * Returns 1 when completed, 0 after an RNR NAK or after the QP was moved to
 * error, or -1
 * when the report is malformed and the caller should take the protocol-error
 * path.
 *
 * The RNR names the LAST and keeps what was placed (imm_rnr_pending).  It
 * cannot name the FIRST: an RXE requester has seen ACKs for the MIDDLEs that
 * asked for one and ignores a NAK behind them, so it would time out and
 * resend from its last ACK for ever.  Hardware has retired the entry at this
 * LAST, so whatever the requester resends behind it is a duplicate, and the
 * resent LAST - placed again or diverted header-only (ASIC-13002) - carries
 * the immediate.
 */
static int roce_vrma_write_imm(struct hfi2_dms_roce_qp *rqp,
			       struct hfi2_qp_priv_roce *priv,
			       const struct eal_ingress_vrma_header *ih,
			       u8 opcode, u32 len)
{
	bool only = opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE;
	u32 reth = only ? sizeof(struct ib_reth) : 0;
	struct ib_other_headers *ohdr =
		roce_vrma_report_bth(ih, reth + HFI2_ROCE_IMMDT_BYTES);
	struct rvt_qp *qp = rqp->qp;
	__be32 imm;
	int rc;

	if (!ohdr)
		return -1;
	imm = *(__be32 *)((u8 *)ohdr + HFI2_ROCE_BTH_BYTES + reth);
	rc = roce_write_imm_rwqe(rqp, priv, qp->r_psn, true);
	if (!rc) {
		rqp->imm_rnr_pending = true;
		rqp->imm_rnr_len = len;
	}
	if (rc <= 0)
		return 0;
	roce_write_imm_complete(rqp, imm, len, ib_bth_is_solicited(ohdr));
	return 1;
}

/*
 * Consecutive packets in the receive ring mostly belong to one QP, and each
 * lock/unlock pair is a full barrier that waits for the worker's queued
 * stores.  Keep the QP's r_lock and s_lock across a run of packets for the
 * same QP, up to HFI2_DMS_ROCE_RX_LOCK_BATCH, and drop them when the QP
 * changes or the ring poll ends.  The RCU read lock taken with them keeps
 * the QP alive while held.
 */
#define HFI2_DMS_ROCE_RX_LOCK_BATCH 64

static void roce_rx_qp_unlock(struct hfi2_dms_roce *roce)
{
	struct rvt_qp *qp = roce->rx_locked_qp;

	if (!qp)
		return;
	roce->rx_locked_qp = NULL;
	spin_unlock_irqrestore(&qp->s_lock, roce->rx_locked_sflags);
	spin_unlock_irqrestore(&qp->r_lock, roce->rx_locked_rflags);
	rcu_read_unlock();
	/* Taken by an earlier roce_rx_qp_relock(); balance sparse here */
	__acquire(RCU);
	__acquire(&qp->r_lock);
	__acquire(&qp->s_lock);
}

static noinline void roce_rx_qp_relock(struct hfi2_dms_roce *roce,
				      struct rvt_qp *qp)
{
	/*
	 * Enter the new read side first: when @qp is the QP being released,
	 * its only pin may be the read side the unlock drops.
	 */
	rcu_read_lock();
	roce_rx_qp_unlock(roce);
	spin_lock_irqsave(&qp->r_lock, roce->rx_locked_rflags);
	spin_lock_irqsave(&qp->s_lock, roce->rx_locked_sflags);
	roce->rx_locked_qp = qp;
	roce->rx_locked_pkts = 0;
	roce->stats.rx_qp_lock_holds++;
	/* Held in roce->rx_locked_qp until roce_rx_qp_unlock() */
	__release(&qp->s_lock);
	__release(&qp->r_lock);
	__release(RCU);
}

static __always_inline void roce_rx_qp_lock(struct hfi2_dms_roce *roce,
					    struct rvt_qp *qp)
{
	if (likely(roce->rx_locked_qp == qp &&
		   ++roce->rx_locked_pkts < HFI2_DMS_ROCE_RX_LOCK_BATCH))
		return;
	roce_rx_qp_relock(roce, qp);
}

/*
 * The common report: an in-order, full-MTU WRITE MIDDLE of a burst already
 * running, which only advances the byte cursor and r_psn.  Take it here with
 * the same checks the general path applies to it - burst, PASID, VA, length,
 * overrun and PSN - and leave every other report, including anything under
 * roce_last_by_software, an RNR'd immediate or a pending NAK, to the general
 * path.  Returns true if the report was consumed.
 */
static __always_inline bool
roce_vrma_middle_fast(struct hfi2_dms_roce_qp *rqp,
		      struct hfi2_qp_priv_roce *priv,
		      const struct eal_ingress_vrma_header *ih,
		      u8 opcode, u8 end_state, u32 placed)
{
	struct rvt_qp *qp = rqp->qp;
	struct hfi2_dms_roce_stats *st = &rqp->roce->stats;
	const struct ib_other_headers *ohdr;

	if (opcode != IB_OPCODE_RC_RDMA_WRITE_MIDDLE ||
	    end_state != EAL_INGRESS_ROCE_END_STATE_OK ||
	    placed != qp->pmtu || roce_last_by_software ||
	    (qp->state == IB_QPS_RTR && !(qp->r_flags & RVT_R_COMM_EST)) ||
	    !rqp->vrma_write_active || rqp->lbs_burst ||
	    rqp->imm_rnr_pending || qp->r_nak_state ||
	    EAL_INGRESS_VRMA_GET_VA(ih) != rqp->vrma_next_va ||
	    EAL_INGRESS_VRMA_GET_PASID(ih) != rqp->vrma_pasid ||
	    rqp->vrma_placed > U32_MAX - placed ||
	    (rqp->vrma_length &&
	     rqp->vrma_placed + placed >= rqp->vrma_length))
		return false;
	ohdr = roce_vrma_report_bth(ih, 0);
	if (!ohdr ||
	    (ib_bth_get_psn((struct ib_other_headers *)ohdr) &
	     HFI2_ROCE_PSN_MASK) != (qp->r_psn & HFI2_ROCE_PSN_MASK))
		return false;

	rqp->vrma_next_va += placed;
	rqp->vrma_placed += placed;
	rqp->h15_drop_sw = false;
	st->rx_vrma_placed_packets++;
	st->rx_vrma_placed_bytes += placed;
	st->rx_vrma_middle_fast++;
	qp->r_psn = (qp->r_psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = opcode;
	if (ib_bth_get_ackreq((struct ib_other_headers *)ohdr)) {
		st->rx_vrma_ack_req++;
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
	}
	return true;
}

static int
roce_write_gap_report(struct hfi2_dms_roce_qp *rqp,
		      const struct eal_ingress_vrma_header *ih,
		      u8 opcode, u8 end_state, u32 placed)
{
	struct rvt_qp *qp = rqp->qp;
	struct ib_other_headers *ohdr;
	const struct udphdr *udp;
	u32 psn, expected, first, length, terminal, pasid, bytes, overhead;
	u64 va;
	bool last = roce_write_last(opcode);

	if (roce_last_by_software ||
	    (!rqp->write_gap.active && !rqp->vrma_write_active) ||
	    (opcode != IB_OPCODE_RC_RDMA_WRITE_MIDDLE &&
	     opcode != IB_OPCODE_RC_RDMA_WRITE_LAST &&
	     opcode != IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE))
		return 0;
	first = rqp->write_gap.active ? rqp->write_gap.first_psn :
		rqp->vrma_first_psn;
	length = rqp->write_gap.active ? rqp->write_gap.length : rqp->vrma_length;
	pasid = rqp->write_gap.active ? rqp->write_gap.pasid : rqp->vrma_pasid;
	va = rqp->write_gap.active ? rqp->write_gap.first_va :
		rqp->vrma_next_va - rqp->vrma_placed;
	if (!qp->pmtu || length <= qp->pmtu)
		return 0;
	terminal = roce_psn(first + (length - 1) / qp->pmtu);
	ohdr = roce_vrma_report_bth(ih, roce_write_with_imm(opcode) ?
				    HFI2_ROCE_IMMDT_BYTES : 0);
	if (!ohdr || ib_bth_get_opcode(ohdr) != opcode)
		return 0;
	psn = ib_bth_get_psn(ohdr) & HFI2_ROCE_PSN_MASK;
	if (!roce_write_gap_packet(rqp, opcode, psn, 0, true, false))
		return 0;
	/* Stale reports do not describe the burst's first missing packet. */
	if (!rqp->write_gap.active &&
	    roce_cmp_psn(psn, qp->r_psn & HFI2_ROCE_PSN_MASK) < 0)
		return 0;
	switch (end_state) {
	case EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO:
		expected = EAL_INGRESS_VRMA_GET_NEXT_PSN(ih);
		if (last || placed || psn != EAL_INGRESS_VRMA_GET_PKT_PSN(ih) ||
		    roce_cmp_psn(psn, expected) <= 0 ||
		    roce_cmp_psn(expected, first) <= 0 ||
		    roce_cmp_psn(expected, terminal) > 0)
			return 0;
		if (!rqp->write_gap.active &&
		    (roce_hdr_suppress ?
		     roce_cmp_psn(expected, qp->r_psn & HFI2_ROCE_PSN_MASK) < 0 :
		     expected != (qp->r_psn & HFI2_ROCE_PSN_MASK)))
			return 0;
		break;
	case EAL_INGRESS_ROCE_END_STATE_LAST_ERR:
		if (!last)
			return 0;
		break;
	case EAL_INGRESS_ROCE_END_STATE_OK:
	case EAL_INGRESS_ROCE_END_STATE_MIDDLE_NO_QP:
		break;
	default:
		return 0;
	}
	udp = (const struct udphdr *)((const u8 *)ohdr - sizeof(*udp));
	overhead = sizeof(*udp) + HFI2_ROCE_BTH_BYTES + HFI2_ROCE_ICRC_BYTES +
		ib_bth_get_pad(ohdr) +
		(roce_write_with_imm(opcode) ? HFI2_ROCE_IMMDT_BYTES : 0);
	if (ntohs(udp->len) < overhead)
		return -EINVAL;
	bytes = ntohs(udp->len) - overhead;
	if (!roce_write_gap_packet(rqp, opcode, psn, bytes, false, false) ||
	    !roce_write_gap_packet(rqp, opcode, psn, placed, !placed, true) ||
	    (placed && (EAL_INGRESS_VRMA_GET_PASID(ih) != pasid ||
			EAL_INGRESS_VRMA_GET_VA(ih) != va +
			(u64)((psn - first) & HFI2_ROCE_PSN_MASK) * qp->pmtu)))
		return -EINVAL;
	roce_write_gap_retry(rqp);
	return 1;
}

/* Drop the read side roce_rx_placement_report() took, if it took one */
static __always_inline void roce_rx_report_rcu_put(bool rcu)
	__releases(RCU)
{
	if (rcu)
		rcu_read_unlock();
	else
		__release(RCU);
}

static void roce_rx_placement_report(
	struct hfi2_dms_roce *roce, u8 rcd_idx,
	const struct eal_ingress_vrma_header *ih)
{
	struct hfi2_devdata *dd = roce->dd;
	struct rvt_dev_info *rdi = &dd->verbs_dev.rdi;
	struct hfi2_ibport *ibp = &dd->pport[HFI2_PORT_IDX].ibport_data;
	struct hfi2_qp_priv_roce *priv;
	struct hfi2_dms_roce_qp *rqp;
	struct rvt_qp *qp;
	u32 qpn, lookup_qpn, placed, rpt_psn;
	u8 end_state, opcode;
	bool alias, last, write_mode, rcu = false;

	roce->stats.rx_vrma_reports++;
	roce_rx_classify(roce, (const struct eal_ingress_header *)ih);
	if (EAL_INGRESS_GET_TYPE(ih) != EAL_INGRESS_TYPE_ROCEV2 ||
	    EAL_INGRESS_GET_L4(ih) != EAL_EGRESS_L4_VRMA) {
		roce_rif_pasid_note_loss(roce, ROCE_RIF_LOSS_REPORT);
		return;
	}

	qpn = EAL_INGRESS_ROCE_GET_QP(ih);
	if (unlikely(!xa_empty(&dd->roce_pasid_blocked)) &&
	    xa_load(&dd->roce_pasid_blocked, EAL_INGRESS_VRMA_GET_PASID(ih)))
		return;
	roce_rif_pasid_track_report(roce, EAL_INGRESS_VRMA_GET_PASID(ih),
				    EAL_RIF_ROW_FROM_QP(qpn));
	lookup_qpn = qpn;
	write_mode = roce_hwp_write_mode(roce);
	/* IB multicast uses all 24 QPN bits, including the alias marker. */
	alias = write_mode && lookup_qpn != IB_MULTICAST_QPN &&
		(lookup_qpn & HFI2_ROCE_QPN_ALIAS_BIT);
	if (alias)
		lookup_qpn &= ~HFI2_ROCE_QPN_ALIAS_BIT;
	opcode = EAL_INGRESS_ROCE_GET_OPCODE(ih);
	end_state = EAL_INGRESS_ROCE_GET_END_STATE(ih);
	placed = EAL_INGRESS_VRMA_GET_WR_PAYLOAD(ih) ?
		EAL_INGRESS_VRMA_PLACED_BYTES(ih) : 0;
	qp = roce->rx_locked_qp;
	if (likely(opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE &&
		   end_state == EAL_INGRESS_ROCE_END_STATE_OK &&
		   qp && qp->ibqp.qp_num == lookup_qpn && !alias &&
		   roce->rx_locked_pkts < HFI2_DMS_ROCE_RX_LOCK_BATCH)) {
		priv = to_roce_priv(qp);
		rqp = priv->roce_qp;
		if (likely(rqp && rqp->rcd_idx == rcd_idx &&
			   !rqp->hwp_rx_blocked && priv->av_valid &&
			   (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK) &&
			   ingress_pkey_matches_entry(EAL_INGRESS_GET_PKEY(ih),
						      IB_DEFAULT_PKEY_FULL) &&
			   roce_vrma_middle_fast(rqp, priv, ih, opcode,
						 end_state, placed))) {
			roce->rx_locked_pkts++;
			if (placed)
				rqp->hw_write_seen = true;
			return;
		}
	}
	/*
	 * q2 changes meaning on an out-of-order report, so log the raw value
	 * beside its discriminator rather than labelling every value as a VA.
	 */
	roce_trace(dd,
		   "VRMA report qpn %u opcode 0x%02x end 0x%02x q2 0x%016llx placed %u pasid 0x%x hdr_dw %u payload %u\n",
		   qpn, opcode, end_state, (unsigned long long)ih->q2, placed,
		   (u32)EAL_INGRESS_VRMA_GET_PASID(ih),
		   (u32)EAL_INGRESS_VRMA_GET_HDR_DWORDS(ih),
		   (u32)EAL_INGRESS_VRMA_GET_WR_PAYLOAD(ih));

	/*
	 * Reports for one burst arrive back to back.  The QP the previous
	 * report left locked is still pinned by that lock's RCU read side, so
	 * reuse it rather than hashing the QPN again; only a fresh lookup
	 * needs a read side of its own, until the QP lock below pins it.
	 */
	qp = roce->rx_locked_qp;
	if (!qp || qp->ibqp.qp_num != lookup_qpn) {
		rcu_read_lock();
		rcu = true;
		qp = rvt_lookup_qpn(rdi, &ibp->rvp, lookup_qpn);
	} else {
		__acquire(RCU);	/* the held QP lock's read side */
	}
	if (!qp || qp->ibqp.qp_type != IB_QPT_RC) {
		roce->stats.rx_no_qp++;
		goto out_rcu;
	}
	priv = to_roce_priv(qp);
	rqp = priv->roce_qp;
	if (!rqp)
		goto out_rcu;
	if (rqp->rcd_idx != rcd_idx) {
		roce->stats.rx_wrong_rcd++;
		goto out_rcu;
	}

	/*
	 * Held across up to HFI2_DMS_ROCE_RX_LOCK_BATCH packets of this QP and
	 * dropped by roce_poll_rcd() at a QP change or the end of the poll,
	 * exactly as the bypass path holds it.  Nothing below drops or retakes
	 * these locks; every callee already ran under both of them.
	 */
	roce_rx_qp_lock(roce, qp);
	roce_rx_report_rcu_put(rcu);
	if (!alias && roce_vrma_write_opcode(opcode) &&
	    EAL_INGRESS_VRMA_GET_WR_PAYLOAD(ih))
		rqp->hw_write_seen = true;
	if (rqp->hwp_rx_blocked)
		goto out_unlock;
	if (write_mode && alias && !roce_write_answer_data_opcode(opcode) &&
	    opcode != IB_OPCODE_RC_ACKNOWLEDGE &&
	    opcode != IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE) {
		if (roce_read_response_opcode(opcode)) {
			roce->stats.rx_hwp_read_resp_drop++;
			dd_dev_warn_ratelimited(dd,
						"roce: reject READ RESPONSE on hardware QPN %u\n",
						qpn);
		} else {
			roce->stats.rx_alias_bad_opcode++;
		}
		goto out_unlock;
	}
	if (write_mode && !alias && !roce_request_opcode(opcode)) {
		if (roce_read_response_opcode(opcode)) {
			roce->stats.rx_hwp_read_resp_drop++;
			dd_dev_warn_ratelimited(dd,
						"roce: reject READ RESPONSE on hardware QPN %u\n",
						qpn);
		} else if (roce_answer_opcode(opcode)) {
			roce->stats.rx_answer_on_base++;
		} else {
			roce->stats.rx_unhandled_opcode++;
		}
		goto out_unlock;
	}
	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)) {
		roce->stats.rx_qp_state_drop++;
		goto out_unlock;
	}
	if (!priv->av_valid) {
		roce->stats.rx_invalid_av++;
		goto out_unlock;
	}
	if (!ingress_pkey_matches_entry(EAL_INGRESS_GET_PKEY(ih),
					IB_DEFAULT_PKEY_FULL)) {
		roce->stats.rx_vrma_bad_pkey++;
		goto out_unlock;
	}
	if (alias && roce_read_write_opcode(opcode)) {
		int ret;

		if (roce_vrma_report_ackreq(ih)) {
			roce->stats.rx_alias_bad_opcode++;
			goto out_unlock;
		}
		if (roce_vrma_software_read_reply(ih, opcode, placed))
			goto out_unlock;
		if (rqp->read_response.first_diverted) {
			bool terminal = roce_write_last_opcode(opcode);

			if (roce_vrma_report_psn(ih, &rpt_psn))
				roce_read_write_drop_diverted(rqp, rpt_psn, terminal);
			goto out_unlock;
		}
		if (rqp->read_response.first_replaying &&
		    opcode != IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		    opcode != IB_OPCODE_RC_RDMA_WRITE_ONLY)
			goto out_unlock;
		if (end_state == EAL_INGRESS_ROCE_END_STATE_MIDDLE_NO_QP)
			goto out_unlock;
		if (end_state != EAL_INGRESS_ROCE_END_STATE_OK || !placed) {
			if (qp->s_acked != qp->s_tail &&
			    roce_wqe_read_software_reply(rqp,
							 rvt_get_swqe_ptr(qp, qp->s_acked)))
				goto out_unlock;
			if (roce_read_write_retry_report(rqp, ih, opcode,
							 end_state, placed))
				goto out_unlock;
			roce_requester_read_write_error(rqp);
			goto out_unlock;
		}
		if (opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
			roce->stats.rx_read_as_write_placed++;
			ret = roce_read_write_placed(rqp, ih, placed, false);
		} else if (opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
			   opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY) {
			ret = roce_read_write_first_placed(rqp, ih, opcode, placed);
		} else {
			ret = roce_read_write_placed(rqp, ih, placed, true);
		}
		if (!ret)
			goto out_unlock;
		if (ret == -EAGAIN)
			goto out_unlock;
		if (ret == -ESTALE)
			goto out_unlock;
		roce->stats.read_write_bad_report++;
		/* Private replies belong to the SQ, never the responder PSN space. */
		roce_requester_read_write_error(rqp);
		goto out_unlock;
	}
	if (roce_vrma_middle_fast(rqp, priv, ih, opcode, end_state, placed))
		goto out_unlock;
	if (!roce_vrma_write_opcode(opcode)) {
		roce->stats.rx_vrma_bad_opcode++;
		goto out_unlock;
	}
	roce_priority_refresh_rx(rqp, opcode);
	if (!roce_last_by_software &&
	    (rqp->write_gap.active ||
	     end_state == EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO ||
	     end_state == EAL_INGRESS_ROCE_END_STATE_LAST_ERR)) {
		int ret = roce_write_gap_report(rqp, ih, opcode, end_state, placed);

		if (ret < 0)
			goto protocol_error;
		if (ret > 0)
			goto out_unlock;
	}
	if (!roce_last_by_software && rqp->write_gap.active &&
	    roce_write_first(opcode) &&
	    end_state == EAL_INGRESS_ROCE_END_STATE_OK &&
	    roce_vrma_report_psn(ih, &rpt_psn) &&
	    rpt_psn == rqp->write_gap.first_psn) {
		if (opcode != IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    roce_vrma_report_length(ih) != rqp->write_gap.length ||
		    EAL_INGRESS_VRMA_GET_PASID(ih) != rqp->write_gap.pasid ||
		    EAL_INGRESS_VRMA_GET_VA(ih) != rqp->write_gap.first_va)
			goto protocol_error;
		rqp->write_gap.active = false;
	}

	/*
	 * A requester that times out resends from its last ACK, behind r_psn.
	 * Hardware places those packets again over identical data, or reports
	 * them out of order behind the entry's next_psn.  Neither says
	 * anything about the burst at r_psn; answer them as duplicates.
	 * roce_last_by_software tracks its own duplicates below.
	 */
	if (!roce_last_by_software && roce_vrma_report_psn(ih, &rpt_psn)) {
		s32 diff = roce_cmp_psn(rpt_psn, qp->r_psn & HFI2_ROCE_PSN_MASK);

		if (diff < 0) {
			roce_vrma_dup(rqp, priv, ih);
			goto out_unlock;
		}
		if (diff > 0 && end_state == EAL_INGRESS_ROCE_END_STATE_OK &&
		    (roce_write_first(opcode) || !roce_hdr_suppress)) {
			if (!roce_write_first(opcode) && rqp->vrma_write_active) {
				int ret = roce_write_gap_report(rqp, ih, opcode,
								end_state, placed);

				if (ret < 0)
					goto protocol_error;
				if (ret > 0)
					goto out_unlock;
			}
			roce_vrma_ahead(rqp, priv);
			goto out_unlock;
		}
		if (rqp->imm_rnr_pending) {
			struct ib_other_headers *ohdr = NULL;

			if (!diff && roce_write_last(opcode) &&
			    roce_write_with_imm(opcode))
				ohdr = roce_vrma_report_bth(ih,
					(roce_write_first(opcode) ?
					 HFI2_ROCE_RETH_BYTES : 0) +
					HFI2_ROCE_IMMDT_BYTES);
			roce_trace(dd,
				   "imm rnr report qpn %u opcode 0x%02x end 0x%02x psn %u hdr_dw %u imm %d\n",
				   qpn, opcode, end_state, rpt_psn,
				   (u32)EAL_INGRESS_VRMA_GET_HDR_DWORDS(ih), !!ohdr);
			if (ohdr) {
				roce_imm_rnr_resume(rqp, priv,
					*(__be32 *)((u8 *)ohdr + HFI2_ROCE_BTH_BYTES +
						    (roce_write_first(opcode) ?
						     HFI2_ROCE_RETH_BYTES : 0)),
					ib_bth_is_solicited(ohdr));
				if (!rqp->imm_rnr_pending) {
					roce_rif_release(rqp);
					roce_vrma_reset(rqp);
				}
			}
			goto out_unlock;
		}
	}

	if (end_state == EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO) {
		u32 expected = EAL_INGRESS_VRMA_GET_NEXT_PSN(ih);

		roce->stats.rx_vrma_trimmed++;
		if (roce_last_by_software) {
			/*
			 * Software, not the entry, owns the burst position
			 * here: an entry a diverted LAST left RUNNING still
			 * matches the next burst's MIDDLEs and reports its own
			 * stale next_psn.  NAK at software's expected PSN, and
			 * clear an entry that is not tracking it.
			 */
			roce->stats.rx_lbs_trim++;
			if (expected != (qp->r_psn & HFI2_ROCE_PSN_MASK)) {
				rqp->lbs_entry = true;
				roce_lbs_invalidate(rqp, false);
			}
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce->stats.rx_vrma_nak_seq++;
				roce_ack_or_defer(rqp, priv,
						  qp->r_psn & HFI2_ROCE_PSN_MASK,
						  IB_NAK_PSN_ERROR);
			}
			goto out_unlock;
		}
		if (!qp->r_nak_state) {
			/*
			 * Every report advances r_psn, so the entry's next_psn
			 * can only be ahead of it when header suppression hides
			 * MIDDLE reports.  Otherwise the entry came from a
			 * FIRST at a foreign PSN and its position is not ours.
			 */
			if (roce_hdr_suppress)
				qp->r_psn = expected;
			qp->r_nak_state = IB_NAK_PSN_ERROR;
			roce->stats.rx_vrma_nak_seq++;
			roce_ack_or_defer(rqp, priv,
					  qp->r_psn & HFI2_ROCE_PSN_MASK,
					  IB_NAK_PSN_ERROR);
		}
		goto out_unlock;
	}
	if (end_state != EAL_INGRESS_ROCE_END_STATE_OK) {
		/*
		 * A non-OK report normally means the burst is over, because on
		 * the hardware-armed path the entry and the burst are created
		 * together.  A software-armed burst (H15) is different: the
		 * peer is already sending MIDDLEs when software arms, so a
		 * packet that lost that race arrives as 0x04 and says nothing
		 * about the burst now running correctly behind it.  Resetting
		 * here discards the accounting the arm just seeded, and the
		 * MIDDLEs hardware then places have no burst to belong to -
		 * measured rx_vrma_no_burst 2 against rx_end_state_ok 2.
		 */
		if (!rqp->h15_armed)
			roce_vrma_reset(rqp);
		goto out_unlock;
	}
	/*
	 * A zero-length WRITE ONLY passes every placement check and reports
	 * OK with nothing to place.  It still owes an ACK, and nothing else
	 * will send one.
	 */
	if (!placed && (opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY ||
			opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE) &&
	    roce_vrma_report_length(ih) == 0) {
		u32 rpt_psn;
		s32 diff;

		if (!roce_vrma_report_psn(ih, &rpt_psn))
			goto protocol_error;
		diff = roce_cmp_psn(rpt_psn, qp->r_psn & HFI2_ROCE_PSN_MASK);
		if (diff > 0) {
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce->stats.rx_vrma_nak_seq++;
				roce_ack_or_defer(rqp, priv,
						  qp->r_psn & HFI2_ROCE_PSN_MASK,
						  IB_NAK_PSN_ERROR);
			}
			goto out_unlock;
		}
		if (!diff) {
			if (roce_write_with_imm(opcode)) {
				int rc = roce_vrma_write_imm(rqp, priv, ih,
							     opcode, 0);

				if (rc < 0)
					goto protocol_error;
				if (!rc)
					goto out_unlock;
			}
			if (qp->state == IB_QPS_RTR &&
			    !(qp->r_flags & RVT_R_COMM_EST))
				rvt_comm_est(qp);
			qp->r_psn = (qp->r_psn + 1) & HFI2_ROCE_PSN_MASK;
			qp->r_state = opcode;
			qp->r_nak_state = 0;
			qp->r_msn++;
		}
		roce->stats.rx_vrma_zero_write++;
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
		goto out_unlock;
	}
	if (!placed) {
		roce->stats.rx_vrma_trimmed++;
		goto out_unlock;
	}

	/*
	 * A timeout replays the whole WQE from its FIRST.  Under
	 * roce_last_by_software the entry was invalidated before the LAST,
	 * so hardware builds a new one from the replayed FIRST and places the
	 * burst again over the data software has already credited.  Those
	 * reports sit behind r_psn: count them and leave the burst alone, so
	 * the LAST software is waiting for still completes it.
	 */
	{
		u32 rpt_psn;

		if (roce_last_by_software && rqp->vrma_write_active &&
		    roce_vrma_report_psn(ih, &rpt_psn) &&
		    roce_cmp_psn(rpt_psn, qp->r_psn & HFI2_ROCE_PSN_MASK) < 0) {
			roce->stats.rx_lbs_dup_report++;
			goto out_unlock;
		}
	}

	last = roce_write_last(opcode);
	if (roce_write_first(opcode)) {
		if (!roce_vrma_begin(rqp, ih, placed) ||
		    (opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		     placed != qp->pmtu) ||
		    (last && placed > qp->pmtu)) {
			roce->stats.rx_vrma_length_error++;
			goto protocol_error;
		}
		if (opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST) {
			rqp->vrma_length = roce_vrma_report_length(ih);
			rqp->vrma_first_psn = qp->r_psn & HFI2_ROCE_PSN_MASK;
		}
		if (opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST &&
		    roce_last_by_software) {
			int rc;

			rqp->lbs_entry = true;
			rc = roce_lbs_adopt(rqp, priv, ih, placed);
			if (rc == 2) {
				/* r_psn already sits past this FIRST. */
				roce->stats.rx_vrma_placed_packets++;
				roce->stats.rx_vrma_placed_bytes += placed;
				goto out_unlock;
			}
			if (rc) {
				roce_vrma_reset(rqp);
				roce_lbs_invalidate(rqp, true);
				goto out_unlock;
			}
		}
	} else if (!roce_vrma_continue(rqp, ih, placed, last)) {
		/*
		 * Under roce_last_by_software a report can belong to an entry
		 * hardware built for a replayed FIRST software declined to
		 * adopt.  Hardware validated that FIRST's R_Key and wrote the
		 * peer's own data at its own VA, so nothing is lost but the
		 * position: drop the entry and ask again from r_psn.
		 */
		if (roce_last_by_software && !rqp->vrma_write_active &&
		    !rqp->lbs_burst) {
			roce->stats.rx_lbs_orphan++;
			rqp->lbs_entry = true;
			roce_lbs_invalidate(rqp, false);
			if (!qp->r_nak_state) {
				qp->r_nak_state = IB_NAK_PSN_ERROR;
				roce->stats.rx_vrma_nak_seq++;
				roce_ack_or_defer(rqp, priv,
						  qp->r_psn & HFI2_ROCE_PSN_MASK,
						  IB_NAK_PSN_ERROR);
			}
			goto out_unlock;
		}
		if (!rqp->vrma_write_active)
			roce->stats.rx_vrma_no_burst++;
		else if (EAL_INGRESS_VRMA_GET_PASID(ih) != rqp->vrma_pasid)
			roce->stats.rx_vrma_bad_pasid++;
		else if (EAL_INGRESS_VRMA_GET_VA(ih) != rqp->vrma_next_va) {
			roce_trace(dd,
				   "VRMA VA mismatch qpn %u opcode 0x%02x got 0x%016llx expected 0x%016llx placed %u total %u\n",
				   qpn, opcode,
				   (unsigned long long)EAL_INGRESS_VRMA_GET_VA(ih),
				   (unsigned long long)rqp->vrma_next_va,
				   placed, rqp->vrma_placed);
			roce->stats.rx_vrma_va_mismatch++;
		} else
			roce->stats.rx_vrma_length_error++;
		goto protocol_error;
	}

	/*
	 * Hardware places a LAST in full without checking it against the
	 * RETH length, and does not bound a MIDDLE by end_psn when next_psn
	 * was ever moved past it.  The reports trail the DMA, so this cannot
	 * stop an overrun, only end it: clear the entry so nothing more is
	 * placed, and error the QP.  A MIDDLE must leave room for the LAST.
	 *
	 * A LAST's placed count includes its BTH pad bytes (LENGTH_ADJ_PAD
	 * reads 0), so a 4914-byte WRITE reports 4916 placed.  Compare it
	 * against the length rounded up to a dword.
	 */
	if (rqp->vrma_length &&
	    (last ? rqp->vrma_placed > ALIGN(rqp->vrma_length, 4) :
	     opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE &&
	     rqp->vrma_placed >= rqp->vrma_length)) {
		roce->stats.rx_vrma_overrun++;
		roce_trace(dd, "VRMA overrun qpn %u placed %u length %u\n",
			   qpn, rqp->vrma_placed, rqp->vrma_length);
		roce_rif_invalidate_qp(rqp);
		goto protocol_error;
	}

	if (rqp->lbs_burst && !last) {
		if (opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE) {
			if (qp->r_rcv_len + placed >= qp->r_len) {
				roce->stats.rx_vrma_length_error++;
				goto protocol_error;
			}
			roce_skip_sge(&qp->r_sge, placed);
			qp->r_rcv_len += placed;
			roce->stats.rx_lbs_middle++;
		}
		/* Only the LAST is left: free the entry for the next FIRST. */
		if (qp->r_len - qp->r_rcv_len <= qp->pmtu)
			roce_lbs_invalidate(rqp, true);
	}
	if (roce_write_with_imm(opcode)) {
		int rc = roce_vrma_write_imm(rqp, priv, ih, opcode,
					     roce_write_first(opcode) ?
					     roce_vrma_report_length(ih) :
					     rqp->vrma_length ?: qp->r_len);

		if (rc < 0)
			goto protocol_error;
		if (!rc) {
			/* The data is placed; only the LAST is owed again. */
			if (ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK) {
				rqp->lbs_burst = false;
				rvt_put_ss(&qp->r_sge);
				roce_rif_release(rqp);
				rqp->h15_armed = false;
				roce_vrma_reset(rqp);
			}
			goto out_unlock;
		}
	}
	rqp->h15_drop_sw = false;
	roce->stats.rx_vrma_placed_packets++;
	roce->stats.rx_vrma_placed_bytes += placed;
	if (qp->state == IB_QPS_RTR && !(qp->r_flags & RVT_R_COMM_EST))
		rvt_comm_est(qp);
	qp->r_psn = (qp->r_psn + 1) & HFI2_ROCE_PSN_MASK;
	qp->r_state = opcode;
	qp->r_nak_state = 0;
	if (!last && roce_vrma_report_ackreq(ih)) {
		roce->stats.rx_vrma_ack_req++;
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
	}
	if (last) {
		qp->r_msn++;
		rqp->lbs_burst = false;
		/*
		 * A software-handled FIRST took an MR reference through
		 * rvt_rkey_ok() into r_sge, and only the software LAST path
		 * releases it.  When hardware places the LAST, drop it here or
		 * every such burst leaks one reference and dereg times out.
		 */
		rvt_put_ss(&qp->r_sge);
		roce_rif_release(rqp);
		rqp->h15_armed = false;
		roce_vrma_reset(rqp);
		roce_ack_or_defer(rqp, priv,
				  (qp->r_psn - 1) & HFI2_ROCE_PSN_MASK, 0);
		roce->stats.rx_vrma_last_ack++;
	}
	goto out_unlock;

protocol_error:
	rqp->h15_armed = false;
	rqp->lbs_burst = false;
	roce_lbs_invalidate(rqp, false);
	roce_vrma_reset(rqp);
	/*
	 * An INVALID REQUEST NAK is fatal, so error the queue pair as the
	 * software path does.  Only NAKing used to leave it receiving with
	 * r_state still mid-WRITE and r_sge released: a LAST already in
	 * flight then passed the burst checks in roce_responder_write() and
	 * was copied through the released r_sge.
	 */
	roce->stats.rx_vrma_protocol_error++;
	roce_responder_error(rqp, priv, IB_WC_LOC_QP_OP_ERR,
			     IB_NAK_INVALID_REQUEST);
out_unlock:
	return;
out_rcu:
	roce_rx_report_rcu_put(rcu);
}

static void roce_ud_rcv(struct hfi2_dms_roce *roce, struct rvt_qp *qp,
			const struct hfi2_roce_wire_rx *rx)
{
	struct ib_wc wc = {};
	struct ib_other_headers *ohdr = rx->ohdr;
	struct iphdr *ip = rx->ip;
	union rdma_network_hdr grh = {};
	unsigned long flags;
	u32 qkey;
	u32 byte_len = rx->payload_len + sizeof(grh);
	int ret;

	if (rx->opcode != IB_OPCODE_UD_SEND_ONLY &&
	    rx->opcode != IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
		roce->stats.rx_ud_drop++;
		return;
	}

	spin_lock_irqsave(&qp->r_lock, flags);
	if (!(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)) {
		roce->stats.rx_qp_state_drop++;
		goto unlock;
	}
	qkey = qp->ibqp.qp_type == IB_QPT_GSI && !qp->qkey ?
		IB_QP1_QKEY : qp->qkey;
	if (ib_get_qkey(ohdr) != qkey) {
		roce->stats.rx_ud_qkey_drop++;
		goto unlock;
	}

	if (qp->r_flags & RVT_R_REUSE_SGE) {
		qp->r_flags &= ~RVT_R_REUSE_SGE;
	} else {
		ret = rvt_get_rwqe(qp, false);
		if (ret < 0) {
			rvt_rc_error(qp, IB_WC_LOC_QP_OP_ERR);
			goto unlock;
		}
		if (!ret) {
			roce->stats.rx_ud_no_rwqe++;
			goto unlock;
		}
	}
	if (byte_len > qp->r_len) {
		qp->r_flags |= RVT_R_REUSE_SGE;
		roce->stats.rx_ud_too_long++;
		goto unlock;
	}

	memcpy(&grh.roce4grh, ip, sizeof(*ip));
	ret = rvt_copy_sge(qp, &qp->r_sge,
			   rvt_to_kseg(&grh, sizeof(grh)), true, false);
	if (!ret)
		ret = rvt_copy_sge(qp, &qp->r_sge,
				   rvt_to_kseg(rx->payload, rx->payload_len),
				   true, false);
	if (ret) {
		rvt_rc_error(qp, IB_WC_LOC_QP_OP_ERR);
		goto unlock;
	}
	rvt_put_ss(&qp->r_sge);
	if (!test_and_clear_bit(RVT_R_WRID_VALID, &qp->r_aflags))
		goto unlock;

	wc.wr_id = qp->r_wr_id;
	wc.status = IB_WC_SUCCESS;
	wc.opcode = IB_WC_RECV;
	wc.byte_len = byte_len;
	wc.qp = &qp->ibqp;
	wc.src_qp = ib_get_sqpn(ohdr);
	wc.pkey_index = 0;
	wc.wc_flags = IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE |
		IB_WC_WITH_SMAC;
	wc.network_hdr_type = RDMA_NETWORK_IPV4;
	ether_addr_copy(wc.smac, rx->eth->h_source);
	/* VID 0 is a priority tag, not VLAN membership */
	if (rx->vlan_tagged && rx->vlan_id) {
		wc.wc_flags |= IB_WC_WITH_VLAN;
		wc.vlan_id = rx->vlan_id;
	}
	wc.port_num = qp->port_num;
	if (rx->opcode == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
		wc.wc_flags |= IB_WC_WITH_IMM;
		wc.ex.imm_data = ohdr->u.ud.imm_data;
	}
	rvt_recv_cq(qp, &wc, ib_bth_is_solicited(ohdr),
		    RVT_QP_LOCK_STATE_R);
	roce->stats.rx_ud_pkts++;
unlock:
	spin_unlock_irqrestore(&qp->r_lock, flags);
}

void hfi2_dms_roce_rx_bypass(struct hfi2_dms_roce *state, u8 rcd_idx,
			     const struct eal_ingress_header *ih,
			     void *frame, u32 len)
{
	struct hfi2_dms_roce *roce = state;
	struct hfi2_bulksvc *svc;
	struct hfi2_devdata *dd;
	struct rvt_dev_info *rdi;
	struct hfi2_ibport *ibp;
	struct hfi2_roce_wire_rx rx;
	struct hfi2_qp_priv_roce *priv;
	struct hfi2_dms_roce_qp *rqp;
	struct rvt_qp *qp;
	u32 lookup_qpn;
	bool alias;
	bool alias_bad_opcode;
	bool base_bad_opcode;
	bool write_mode;

	if (!roce || !roce->active || !frame)
		return;

	svc = roce->svc;
	if (!svc || svc->backend != HFI2_BULKSVC_BACKEND_ETH_ROCE)
		return;
	dd = svc->dd;
	rdi = &dd->verbs_dev.rdi;
	ibp = &dd->pport[HFI2_PORT_IDX].ibport_data;
	roce->stats.rx_bypass++;

	roce_rx_classify(roce, ih);
	if (ih && EAL_INGRESS_GET_TYPE(ih) == EAL_INGRESS_TYPE_ROCEV2 &&
	    EAL_INGRESS_GET_L4(ih) == EAL_EGRESS_L4_VRMA)
		roce_rif_pasid_note_loss(roce, ROCE_RIF_LOSS_BYPASS);

	if (hfi2_roce_parse_ipv4(frame, len, &rx)) {
		roce_trace(dd, "rx parse err len=%u\n", len);
		/* not IPv4 RoCE, or malformed: drop (Stage 1) */
		roce->stats.rx_parse_err++;
		return;
	}
	if (!ingress_pkey_matches_entry(rx.pkey, IB_DEFAULT_PKEY_FULL)) {
		roce->stats.rx_pkey_drop++;
		return;
	}
	if (ih && EAL_INGRESS_GET_TYPE(ih) == EAL_INGRESS_TYPE_ROCEV2)
		rx.eal_end_state = EAL_INGRESS_ROCE_GET_END_STATE(ih);

	roce_trace(dd, "rx frame op=0x%02x psn=%u qpn=%u paylen=%u ack=%d\n",
		   rx.opcode, rx.psn, rx.dest_qpn, rx.payload_len, rx.ack_req);
	lookup_qpn = rx.dest_qpn;
	write_mode = roce_hwp_write_mode(roce);
	/* IB multicast uses all 24 QPN bits, including the alias marker. */
	alias = write_mode && lookup_qpn != IB_MULTICAST_QPN &&
		(lookup_qpn & HFI2_ROCE_QPN_ALIAS_BIT);
	alias_bad_opcode = alias && !roce_write_answer_data_opcode(rx.opcode) &&
		rx.opcode != IB_OPCODE_RC_ACKNOWLEDGE &&
		rx.opcode != IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE;
	/*
	 * Write mode only accepts requests on the base QPN; answers belong on
	 * the alias.  UD SENDs are requests too: rdma_cm reaches QP1 with them,
	 * and roce_ud_rcv() below validates the opcode against the QP type.
	 */
	base_bad_opcode = write_mode && !alias &&
		!roce_request_opcode(rx.opcode) &&
		rx.opcode != IB_OPCODE_UD_SEND_ONLY &&
		rx.opcode != IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
	if (alias)
		lookup_qpn &= ~HFI2_ROCE_QPN_ALIAS_BIT;
	if (alias_bad_opcode) {
		if (roce_read_response_opcode(rx.opcode)) {
			roce->stats.rx_hwp_read_resp_drop++;
			dd_dev_warn_ratelimited(dd,
						"roce: reject READ RESPONSE on hardware QPN %u\n",
						rx.dest_qpn);
		} else {
			roce->stats.rx_alias_bad_opcode++;
		}
		roce_rx_qp_unlock(roce);
		return;
	}
	if (base_bad_opcode) {
		if (roce_read_response_opcode(rx.opcode)) {
			roce->stats.rx_hwp_read_resp_drop++;
			dd_dev_warn_ratelimited(dd,
						"roce: reject READ RESPONSE on hardware QPN %u\n",
						rx.dest_qpn);
		} else if (roce_answer_opcode(rx.opcode)) {
			roce->stats.rx_answer_on_base++;
		} else {
			roce->stats.rx_unhandled_opcode++;
		}
		roce_rx_qp_unlock(roce);
		return;
	}
	if (roce_drop_rx_once) {
		if (roce_drop_rx_skip) {
			roce_drop_rx_skip--;
		} else {
			roce_drop_rx_once = false;
			roce->stats.rx_test_drop++;
			roce_trace(dd,
				   "rx test drop op=0x%02x psn=%u qpn=%u\n",
				   rx.opcode, rx.psn, rx.dest_qpn);
			return;
		}
	}

	rcu_read_lock();
	qp = rvt_lookup_qpn(rdi, &ibp->rvp, lookup_qpn);
	if (qp && roce_qp_is_ud(qp)) {
		roce_rx_qp_unlock(roce);
		roce_ud_rcv(roce, qp, &rx);
		rcu_read_unlock();
		return;
	}
	if (!qp || qp->ibqp.qp_type != IB_QPT_RC) {
		/*
		 * DestQPN not one of our RoCE QPs (e.g. soft-RoCE sharing the
		 * netdev).  Stage 1 drops; a later change forwards to the
		 * netdev stack.
		 */
		roce->stats.rx_no_qp++;
		rcu_read_unlock();
		return;
	}

	priv = to_roce_priv(qp);
	rqp = priv->roce_qp;
	if (!rqp || !rqp->roce) {
		/*
		 * @roce is latched at bind, which becomes reachable once
		 * hfi2_register_ib_device() runs, but the backend is not
		 * allocated until hfi2_bulksvc_loan_resources() later in
		 * hfi2_init_dd().  A queue pair created in that window holds a
		 * NULL backend for its lifetime, so drop here rather than let
		 * the responders fault on it.  The transmit side already
		 * refuses such a queue pair in hfi2_dms_roce_do_send().
		 */
		roce->stats.rx_no_backend++;
		rcu_read_unlock();
		return;
	}
	if (rqp->rcd_idx != rcd_idx) {
		roce->stats.rx_wrong_rcd++;
		rcu_read_unlock();
		return;
	}

	roce_rx_qp_lock(roce, qp);

	if (rqp->hwp_rx_blocked ||
	    !(ib_rvt_state_ops[qp->state] & RVT_PROCESS_RECV_OK)) {
		roce->stats.rx_qp_state_drop++;
		rcu_read_unlock();
		return;
	}
	if (!priv->av_valid) {
		roce->stats.rx_invalid_av++;
		rcu_read_unlock();
		return;
	}
	if (rx.ip->saddr != priv->daddr || rx.ip->daddr != priv->saddr) {
		roce->stats.rx_bad_peer++;
		rcu_read_unlock();
		return;
	}

	roce_priority_refresh_rx(rqp, rx.opcode);

	/*
	 * WRITE, SEND and READ response payloads go through the helper
	 * queue and order themselves per page; their completions drain.  A
	 * READ request must see every earlier WRITE placed, and an ACK may
	 * complete work queued behind those copies, so drain first.
	 */
	if ((alias &&
	     roce_write_first_opcode(rx.opcode)) ||
	    rx.opcode == IB_OPCODE_RC_RDMA_READ_REQUEST ||
	    rx.opcode == IB_OPCODE_RC_COMPARE_SWAP ||
	    rx.opcode == IB_OPCODE_RC_FETCH_ADD ||
	    rx.opcode == IB_OPCODE_RC_ACKNOWLEDGE ||
	    rx.opcode == IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE)
		roce_rx_helpers_drain(roce);

	switch (rx.opcode) {
	case IB_OPCODE_RC_SEND_FIRST:
	case IB_OPCODE_RC_SEND_MIDDLE:
	case IB_OPCODE_RC_SEND_LAST:
	case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
	case IB_OPCODE_RC_SEND_ONLY:
	case IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE:
	case IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE:
		roce_responder_send(rqp, priv, &rx);
		break;
	case IB_OPCODE_RC_RDMA_WRITE_FIRST:
	case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
	case IB_OPCODE_RC_RDMA_WRITE_LAST:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY:
		if (alias) {
			if (rx.ack_req) {
				roce->stats.rx_alias_bad_opcode++;
			} else {
				roce->stats.rx_read_as_write++;
				roce_requester_read_write_resp(rqp, &rx);
			}
		} else {
			roce_responder_write(rqp, priv, &rx);
		}
		break;
	case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
	case IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE:
		roce_responder_write(rqp, priv, &rx);
		break;
	case IB_OPCODE_RC_RDMA_READ_REQUEST:
		roce_responder_read(rqp, priv, &rx);
		break;
	case IB_OPCODE_RC_COMPARE_SWAP:
	case IB_OPCODE_RC_FETCH_ADD:
		roce_responder_atomic(rqp, priv, &rx);
		break;
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		roce_requester_read_response(rqp, &rx);
		break;
	case IB_OPCODE_RC_ACKNOWLEDGE:
		roce_requester_ack(rqp, &rx);
		break;
	case IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE:
		roce_requester_atomic_ack(rqp, &rx);
		break;
	default:
		roce->stats.rx_unhandled_opcode++;
		rcu_read_unlock();
		return;
	}

	rcu_read_unlock();
}

#if HFI2_DMS_ROCE_INJECT

/*
 * Burst-conformance emitter.  Builds one hand-specified RoCEv2 WRITE frame and
 * emits it through the ordinary PIO path, so the malformed-burst cases reach
 * the peer responder the same way a driver-built frame does.  An AF_PACKET
 * frame cannot: it is marked End Bad Packet at the link layer and discarded at
 * the receive-header-error gate before any protocol code runs.
 */

static bool roce_inject_takes_reth(u8 opcode)
{
	return opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
	       opcode == IB_OPCODE_RC_RDMA_WRITE_ONLY;
}

static int roce_inject_emit(struct hfi2_dms_roce_qp *rqp,
			    struct hfi2_qp_priv_roce *priv,
			    const struct hfi2_dms_roce_inject_cmd *cmd)
{
	struct hfi2_roce_wire_addr addr = {
		.saddr = priv->saddr,
		.daddr = priv->daddr,
		.vlan_id = roce_tx_vlan_id(priv, HFI2_ROCE_AETH_BYTES, 0, 0),
		.udp_sport = priv->udp_sport,
		.traffic_class = priv->traffic_class,
		.vlan_prio = roce_tx_pcp(priv),
		.hop_limit = priv->hop_limit ? priv->hop_limit : 64,
	};
	bool aeth = cmd->opcode == IB_OPCODE_RC_ACKNOWLEDGE;
	size_t ext_len = aeth ? HFI2_ROCE_AETH_BYTES :
			 (roce_inject_takes_reth(cmd->opcode) ?
			  HFI2_ROCE_RETH_BYTES : 0);
	u8 pad = aeth ? 0 : roce_bth_pad(cmd->payload_len);
	size_t payload_len = aeth ? 0 : cmd->payload_len;
	size_t ib_len = HFI2_ROCE_BTH_BYTES + ext_len + payload_len + pad;
	size_t frame_len;
	u8 *bth, *payload;

	if (roce_hwp_write_mode(rqp->roce) &&
	    roce_read_response_opcode(cmd->opcode))
		return -EINVAL;
	roce_tx_addr_vlan(&addr, priv, ext_len, payload_len, pad);
	frame_len = hfi2_roce_ipv4_bth_offset(addr.vlan_id) + ib_len;
	if (EAL_EGRESS_HDR_BYTES + frame_len + HFI2_ROCE_ICRC_BYTES >
	    rqp->txbuf_sz)
		return -EMSGSIZE;

	ether_addr_copy(addr.smac, priv->smac);
	ether_addr_copy(addr.dmac, priv->dmac);
	hfi2_roce_build_eth_ipv4_udp(rqp->txbuf + EAL_EGRESS_HDR_BYTES, &addr,
				     ib_len + HFI2_ROCE_ICRC_BYTES);

	bth = rqp->txbuf + EAL_EGRESS_HDR_BYTES +
		hfi2_roce_ipv4_bth_offset(addr.vlan_id);
	/* The ingress gate drops anything but the default partition. */
	hfi2_roce_build_bth(bth, cmd->opcode, IB_DEFAULT_PKEY_FULL,
			    cmd->dest_qpn, cmd->ack_req, false, pad, cmd->psn);

	payload = bth + HFI2_ROCE_BTH_BYTES;
	if (aeth) {
		hfi2_roce_build_aeth(payload, cmd->syndrome, cmd->msn);
	} else {
		if (ext_len) {
			hfi2_roce_build_reth(payload, cmd->vaddr, cmd->rkey,
					     cmd->reth_len);
			payload += HFI2_ROCE_RETH_BYTES;
		}
		memset(payload, HFI2_DMS_ROCE_INJECT_FILL,
		       cmd->payload_len);
		if (pad)
			memset(payload + cmd->payload_len, 0, pad);
	}
	if (addr.vlan_id != HFI2_ROCE_NO_VLAN)
		roce_tag_count(rqp, priv, roce_is_runt(ext_len, payload_len,
							pad), true);

	return roce_pio_frame(rqp, frame_len, true);
}

static bool roce_inject_dequeue(struct hfi2_dms_roce *roce,
				struct hfi2_dms_roce_inject_cmd *out)
{
	unsigned long flags;
	bool got = false;

	spin_lock_irqsave(&roce->inject_lock, flags);
	if (roce->inject_tail != roce->inject_head) {
		*out = roce->inject_ring[roce->inject_tail %
					 HFI2_DMS_ROCE_INJECT_RING];
		roce->inject_tail++;
		got = true;
	}
	spin_unlock_irqrestore(&roce->inject_lock, flags);
	return got;
}

/*
 * Drain staged commands on the bulksvc worker.  Emission must happen here and
 * not in the writing task: the send context and the borrowed QP's txbuf are
 * owned by this single thread, which serializes this against the ordinary send
 * path -- so borrowing the buffer is safe regardless of what the QP is doing.
 * (Keeping the borrowed QP free of posted work is a test-hygiene rule, not a
 * memory-safety one: concurrent traffic would perturb the counter deltas the
 * case assertions read.)  The QP named by the command may have been destroyed
 * since the write, so it is resolved under RCU with a reference held across
 * the emit.
 */
static int roce_inject_poll(struct hfi2_dms_roce *roce)
{
	struct rvt_dev_info *rdi = &roce->dd->verbs_dev.rdi;
	struct hfi2_ibport *ibp = &roce->dd->pport[HFI2_PORT_IDX].ibport_data;
	struct hfi2_dms_roce_inject_cmd cmd;
	int processed = 0;

	while (roce_inject_dequeue(roce, &cmd)) {
		struct hfi2_qp_priv_roce *priv;
		struct hfi2_dms_roce_qp *rqp;
		struct rvt_qp *qp;

		processed++;

		rcu_read_lock();
		qp = rvt_lookup_qpn(rdi, &ibp->rvp, cmd.local_qpn);
		if (qp && qp->ibqp.qp_type == IB_QPT_RC)
			rvt_get_qp(qp);
		else
			qp = NULL;
		rcu_read_unlock();
		if (!qp)
			continue;

		priv = to_roce_priv(qp);
		rqp = priv->roce_qp;
		if (!rqp || !priv->av_valid ||
		    roce_inject_emit(rqp, priv, &cmd))
			roce->stats.inject_fail++;
		rvt_put_qp(qp);
	}
	return processed;
}

static ssize_t roce_inject_write(struct file *file, const char __user *ubuf,
				 size_t len, loff_t *ppos)
{
	struct hfi2_dms_roce *roce = file->private_data;
	struct hfi2_dms_roce_inject_cmd cmd = {};
	char buf[128];
	unsigned long flags;
	unsigned int opcode, ack_req, syndrome = 0;
	int parsed;

	if (len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	parsed = sscanf(buf, "%u %u %u %u %u %llu %u %u %u %u %u",
			&cmd.local_qpn, &cmd.dest_qpn, &opcode, &cmd.psn,
			&ack_req, &cmd.vaddr, &cmd.rkey, &cmd.reth_len,
			&cmd.payload_len, &syndrome, &cmd.msn);
	if (parsed < 9 || opcode > U8_MAX || syndrome > U8_MAX)
		return -EINVAL;
	cmd.opcode = (u8)opcode;
	if (roce_hwp_write_mode(roce) && roce_read_response_opcode(cmd.opcode))
		return -EINVAL;
	cmd.syndrome = (u8)syndrome;
	cmd.ack_req = !!ack_req;

	spin_lock_irqsave(&roce->inject_lock, flags);
	if (roce->inject_head - roce->inject_tail >=
	    HFI2_DMS_ROCE_INJECT_RING) {
		spin_unlock_irqrestore(&roce->inject_lock, flags);
		return -ENOSPC;
	}
	roce->inject_ring[roce->inject_head % HFI2_DMS_ROCE_INJECT_RING] = cmd;
	roce->inject_head++;
	spin_unlock_irqrestore(&roce->inject_lock, flags);

	hfi2_bulksvc_schedule(roce->svc);
	return len;
}

static const struct file_operations roce_inject_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = roce_inject_write,
	.llseek = default_llseek,
};

/*
 * Debugfs table operations use synthetic PASID tokens, not MR bindings.
 * Optional bind_pasid/live fields exercise mismatch and dead-token rejection;
 * defaults permit the supplied PASID.  Arm selects its own bucket, and reads
 * report the last readback.  mreligible uses the registration predicate.
 */
static ssize_t roce_rif_dbg_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	struct hfi2_dms_roce *roce = ((struct seq_file *)file->private_data)->private;
	struct hfi2_dms_roce_rif_entry entry = {};
	struct hfi2_roce_pasid dbg_pasid = {};
	char buf[160], verb[16];
	u32 qpn, bucket;
	int ret, len;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	len = count;

	if (sscanf(buf, "%15s", verb) != 1)
		return -EINVAL;

	if (!strcmp(verb, "tombdump")) {
		struct hfi2_dms_roce_tombs *tombs = roce->tombs;
		bool entered;
		int i;

		if (!tombs)
			return -ENODEV;
		entered = roce_rif_enter(roce);
		for (i = 0; i < ARRAY_SIZE(tombs->tombstones); i++) {
			if (!tombs->tombstones[i].sequence)
				continue;
			qpn = tombs->tombstones[i].qpn;
			bucket = tombs->tombstones[i].bucket;
			memset(&entry, 0, sizeof(entry));
			ret = hfi2_dms_roce_rif_readback(roce, qpn, bucket, &entry);
			dd_dev_info(roce->dd,
				    "roce: tombdump row %u qpn %u bucket %u sequence %llu psn 0x%06x hw_qpn %u valid %u state %u next_psn 0x%06x pasid %u rc %d\n",
				    EAL_RIF_ROW_FROM_QP(qpn), qpn, bucket,
				    tombs->tombstones[i].sequence,
				    tombs->tombstones[i].psn, entry.qpn, !ret,
				    entry.next_psn_state, entry.next_psn, entry.pasid, ret);
		}
		roce_rif_leave(roce, entered);
		return count;
	}

	if (!strcmp(verb, "readback")) {
		if (sscanf(buf, "%15s %u %u", verb, &qpn, &bucket) != 3 ||
		    qpn >= EAL_RIF_TABLE_ROWS ||
		    bucket >= EAL_TABLE_ENTRIES_PER_ROW)
			return -EINVAL;
		/* A row is also a QPN whose low bits select exactly that row. */
	} else if (!strcmp(verb, "invalidate")) {
		if (sscanf(buf, "%15s %u %u", verb, &qpn, &bucket) != 3)
			return -EINVAL;
		ret = hfi2_dms_roce_rif_invalidate(roce, qpn, (u8)bucket);
		if (ret)
			return ret;
	} else if (!strcmp(verb, "arm")) {
		u64 vaddr;

		u32 bind_pasid;
		u32 live = 1;
		int fields;

		fields = sscanf(buf, "%15s %u %llu %u %u %u %u %u %u", verb,
				&qpn, &vaddr, &entry.start_psn, &entry.end_psn,
				&entry.next_psn, &entry.pasid, &bind_pasid,
				&live);
		if (fields < 7)
			return -EINVAL;
		if (fields < 8)
			bind_pasid = entry.pasid;
		entry.qpn = qpn;
		entry.start_vaddr = vaddr;
		entry.next_psn_state = EAL_RIF_NEXT_PSN_STATE_INITIALIZING;

		/*
		 * No MR here: build the binding from the supplied values. The
		 * comparison still runs and defaults to agreeing, so the
		 * diagnostic can arm an arbitrary PASID. bind_pasid and live
		 * make the two refusal branches reachable.
		 */
		dbg_pasid.pasid = bind_pasid;
		dbg_pasid.live = !!live;

		ret = hfi2_dms_roce_rif_arm(roce, &entry, &dbg_pasid);
		if (ret < 0)
			return ret;
		bucket = (u32)ret;
	} else if (!strcmp(verb, "rkey")) {
		struct hfi2_dms_roce_rkey_entry rk = {};
		u32 perm, bind_pasid, live = 1;
		u64 vaddr;
		int fields;

		fields = sscanf(buf, "%15s %u %llu %u %u %u %u %u", verb,
				&rk.rkey, &vaddr, &rk.length, &rk.pasid, &perm,
				&bind_pasid, &live);
		if (fields < 6)
			return -EINVAL;
		if (fields < 7)
			bind_pasid = rk.pasid;
		rk.start_vaddr = vaddr;
		rk.permissions = (u8)perm;

		dbg_pasid.pasid = bind_pasid;
		dbg_pasid.live = !!live;

		ret = hfi2_dms_roce_rkey_install(roce, &rk, &dbg_pasid);
		if (ret < 0)
			return ret;
		bucket = (u32)ret;

		ret = hfi2_dms_roce_rkey_readback(roce, rk.rkey, (u8)bucket,
						  &roce->rkey_last);
		roce->rkey_last_rc = ret;
		if (ret && ret != -ENOENT)
			return ret;
		return len;
	} else if (!strcmp(verb, "mreligible")) {
		u32 has_mm, has_pinned_dmabuf;
		u64 length;

		if (sscanf(buf, "%15s %u %u %llu", verb, &has_mm,
			   &has_pinned_dmabuf, &length) != 4)
			return -EINVAL;

		/*
		 * Calls the same predicate the registration hook calls, with
		 * the same arguments it would pass.  It is not a reimplemen-
		 * tation: a divergent copy here would report on itself rather
		 * than on the code that runs in production.
		 */
		hfi2_dms_roce_mr_eligible(roce->dd, !!has_mm,
					  !!has_pinned_dmabuf, false, (size_t)length);
		return len;
	} else if (!strcmp(verb, "rkeyinv")) {
		if (sscanf(buf, "%15s %u %u", verb, &qpn, &bucket) != 3)
			return -EINVAL;
		ret = hfi2_dms_roce_rkey_invalidate(roce, qpn, (u8)bucket);
		if (ret)
			return ret;
		return len;
	} else {
		return -EINVAL;
	}

	ret = hfi2_dms_roce_rif_readback(roce, qpn, (u8)bucket,
					 &roce->rif_last_readback);
	roce->rif_last_readback_rc = ret;
	if (ret && ret != -ENOENT)
		roce->stats.rif_readback_fail++;

	return len;
}

static int roce_rif_show(struct seq_file *s, void *v)
{
	struct hfi2_dms_roce *roce = s->private;
	const struct hfi2_dms_roce_rif_entry *e = &roce->rif_last_readback;

	seq_printf(s, "readback_rc     %d\n", roce->rif_last_readback_rc);
	seq_printf(s, "rkey_readback_rc %d\n", roce->rkey_last_rc);
	seq_printf(s, "rkey            0x%x\n", roce->rkey_last.rkey);
	seq_printf(s, "rkey_vaddr      0x%llx\n", roce->rkey_last.start_vaddr);
	seq_printf(s, "rkey_length     %u\n", roce->rkey_last.length);
	seq_printf(s, "rkey_pasid      %u\n", roce->rkey_last.pasid);
	seq_printf(s, "rkey_perm       0x%x\n", roce->rkey_last.permissions);
	seq_printf(s, "rkey_bucket     %u\n", roce->rkey_last.bucket);
	seq_printf(s, "qpn             %u\n", e->qpn);
	seq_printf(s, "bucket          %u\n", e->bucket);
	seq_printf(s, "start_vaddr     0x%llx\n", e->start_vaddr);
	seq_printf(s, "start_psn       %u\n", e->start_psn);
	seq_printf(s, "end_psn         %u\n", e->end_psn);
	seq_printf(s, "next_psn        %u\n", e->next_psn);
	seq_printf(s, "next_psn_state  %u\n", e->next_psn_state);
	seq_printf(s, "pasid           %u\n", e->pasid);
	return 0;
}

static int roce_rif_open(struct inode *inode, struct file *file)
{
	int ret = single_open(file, roce_rif_show, inode->i_private);

	if (!ret)
		((struct seq_file *)file->private_data)->private = inode->i_private;
	return ret;
}

static const struct file_operations roce_rif_fops = {
	.owner = THIS_MODULE,
	.open = roce_rif_open,
	.read = seq_read,
	.write = roce_rif_dbg_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int roce_rif_dump_show(struct seq_file *s, void *v)
{
	struct hfi2_dms_roce *roce = s->private;
	struct hfi2_dms_roce_rif_entry rif;
	struct hfi2_dms_roce_rkey_entry rkey;
	unsigned long flags;
	u32 row;
	u8 bucket;
	int ret;

	seq_puts(s, "rif-table\n");
	seq_puts(s, "row bucket qpn pasid next_psn_state start_psn end_psn next_psn start_vaddr\n");
	for (row = 0; row < EAL_RIF_TABLE_ROWS; row++) {
		for (bucket = 0; bucket < EAL_TABLE_ENTRIES_PER_ROW; bucket++) {
			ret = hfi2_dms_roce_rif_readback(roce, row, bucket, &rif);
			if (ret == -ENOENT)
				continue;
			if (ret)
				return ret;
			seq_printf(s, "%u %u %u %u %u %u %u %u 0x%llx\n",
				   row, bucket, rif.qpn, rif.pasid,
				   rif.next_psn_state, rif.start_psn, rif.end_psn,
				   rif.next_psn, rif.start_vaddr);
		}
		cond_resched();
	}

	seq_puts(s, "rkey-table\n");
	seq_puts(s, "rkey pasid bucket length perm\n");
	for (row = 0; row < EAL_RKEY_TABLE_ROWS; row++) {
		for (bucket = 0; bucket < EAL_TABLE_ENTRIES_PER_ROW; bucket++) {
			/* Keep row zero addressable without passing the no-owner key. */
			spin_lock_irqsave(&roce->rkey_lock, flags);
			ret = hfi2_dms_roce_rkey_readback(roce,
							  row | EAL_RKEY_TABLE_ROWS,
							  bucket, &rkey);
			spin_unlock_irqrestore(&roce->rkey_lock, flags);
			if (ret == -ENOENT)
				continue;
			if (ret)
				return ret;
			seq_printf(s, "%u %u %u %u %u\n", rkey.rkey, rkey.pasid,
				   bucket, rkey.length, rkey.permissions);
		}
		cond_resched();
	}
	return 0;
}

static int roce_rif_dump_open(struct inode *inode, struct file *file)
{
	/* Full tables: 73 bytes per RIF, 34 per R_Key, plus headings. */
	size_t size = 128 + EAL_TABLE_ENTRIES_PER_ROW *
		(EAL_RIF_TABLE_ROWS * 73 + EAL_RKEY_TABLE_ROWS * 34);

	return single_open_size(file, roce_rif_dump_show, inode->i_private, size);
}

static const struct file_operations roce_rif_dump_fops = {
	.owner = THIS_MODULE,
	.open = roce_rif_dump_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t roce_rif_loss_inject_write(struct file *file,
					  const char __user *ubuf, size_t count,
					  loff_t *ppos)
{
	struct hfi2_dms_roce *roce = file->private_data;
	enum roce_rif_pasid_loss_reason reason;
	char buf[16];

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!count || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	if (!roce || !roce->initialized)
		return -ENODEV;

	if (sysfs_streq(buf, "rhe"))
		reason = ROCE_RIF_LOSS_RHE;
	else if (sysfs_streq(buf, "ovfl"))
		reason = ROCE_RIF_LOSS_OVFL;
	else if (sysfs_streq(buf, "bypass"))
		reason = ROCE_RIF_LOSS_BYPASS;
	else if (sysfs_streq(buf, "netdev"))
		reason = ROCE_RIF_LOSS_NETDEV;
	else
		return -EINVAL;

	roce_rif_pasid_note_loss(roce, reason);
	return count;
}

static const struct file_operations roce_rif_loss_inject_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = roce_rif_loss_inject_write,
	.llseek = default_llseek,
};

static void roce_inject_init(struct hfi2_dms_roce *roce)
{
	spin_lock_init(&roce->inject_lock);
	roce->inject_head = 0;
	roce->inject_tail = 0;
	if (roce->dd->verbs_dev.hfi2_ibdev_dbg) {
		roce->inject_dentry =
			debugfs_create_file("roce_inject", 0200,
					    roce->dd->verbs_dev.hfi2_ibdev_dbg,
					    roce, &roce_inject_fops);
		roce->rif_dentry =
			debugfs_create_file("roce_rif", 0600,
					    roce->dd->verbs_dev.hfi2_ibdev_dbg,
					    roce, &roce_rif_fops);
		roce->rif_dump_dentry =
			debugfs_create_file("roce_rif_dump", 0400,
					    roce->dd->verbs_dev.hfi2_ibdev_dbg,
					    roce, &roce_rif_dump_fops);
		roce->rif_loss_inject_dentry =
			debugfs_create_file("roce_rif_loss_inject", 0200,
					    roce->dd->verbs_dev.hfi2_ibdev_dbg,
					    roce, &roce_rif_loss_inject_fops);
	}
}

/*
 * debugfs drains in-flight ->write callers before debugfs_remove() returns and
 * fails any later access on a still-open fd, so the backend may be torn down
 * immediately afterwards.
 */
static void roce_inject_teardown(struct hfi2_dms_roce *roce)
{
	/*
	 * If hfi2_dbg_ibdev_exit() already ran, its recursive removal freed
	 * this dentry and NULLed hfi2_ibdev_dbg; removing it again here hangs
	 * the host on rmmod. On error paths the parent is still alive and this
	 * is the sole removal.
	 */
	if (!roce->dd->verbs_dev.hfi2_ibdev_dbg)
		goto clear;

	debugfs_remove(roce->inject_dentry);
	debugfs_remove(roce->rif_dentry);
	debugfs_remove(roce->rif_dump_dentry);
	debugfs_remove(roce->rif_loss_inject_dentry);
clear:
	roce->inject_dentry = NULL;
	roce->rif_dentry = NULL;
	roce->rif_dump_dentry = NULL;
	roce->rif_loss_inject_dentry = NULL;
}

#else

static int roce_inject_poll(struct hfi2_dms_roce *roce)
{
	return 0;
}

static void roce_inject_init(struct hfi2_dms_roce *roce)
{
}

static void roce_inject_teardown(struct hfi2_dms_roce *roce)
{
}

#endif /* HFI2_DMS_ROCE_INJECT */

void hfi2_dms_roce_stats_print(struct hfi2_devdata *dd, struct seq_file *s)
{
	struct rvt_ibport *rvp;
	struct hfi2_dms *dms;
	struct hfi2_dms_roce *roce;
	struct hfi2_dms_roce_stats *st;
	struct hfi2_dms_roce_tombs *tombs;
	u64 helper_verify_bad = 0;
	u64 helper_wakeups = 0;

	if (!dd->bulksvc || !dd->bulksvc->dms_roce ||
	    !dd->bulksvc->dms_roce->active) {
		seq_puts(s, "roce: backend inactive (not in ETH mode?)\n");
		return;
	}
	roce = dd->bulksvc->dms_roce;
	if (!roce->active) {
		seq_puts(s, "roce: backend inactive (not in ETH mode?)\n");
		return;
	}
	st = &roce->stats;
	tombs = roce->tombs;
	dms = hfi2_bulksvc_primary_dms(dd->bulksvc);
	rvp = &dd->pport[HFI2_PORT_IDX].ibport_data.rvp;

	seq_printf(s, "rc_credit_waits   %llu\n",
		   READ_ONCE(rvp->n_rc_crwaits));
	seq_printf(s, "tx_pkts           %llu\n",
		   roce_tx_stat_read(&st->tx_pkts, &roce->inline_stats.tx_pkts));
	seq_printf(s, "tx_bytes          %llu\n",
		   roce_tx_stat_read(&st->tx_bytes, &roce->inline_stats.tx_bytes));
	seq_printf(s, "tx_wqe            %llu\n",
		   roce_tx_stat_read(&st->tx_send_wqe, &roce->inline_stats.tx_send_wqe));
	seq_printf(s, "tx_ud_pkts        %llu\n", st->tx_ud_pkts);
	seq_printf(s, "tx_ud_sdma        %llu\n", st->tx_ud_sdma);
	seq_printf(s, "tx_acks           %llu\n", st->tx_acks);
	seq_printf(s, "tx_ack_deferred   %llu\n", st->tx_ack_deferred);
	seq_printf(s, "tx_ack_dropped    %llu\n", st->tx_ack_dropped);
	seq_printf(s, "tx_pio_fail       %llu\n",
		   roce_tx_stat_read(&st->tx_pio_fail, &roce->inline_stats.tx_pio_fail));
	seq_printf(s, "tx_pio_credits    %u\n", READ_ONCE(roce->sc->credits));
	seq_printf(s, "tx_pio_outstanding %lu\n",
		   READ_ONCE(roce->sc->fill) - READ_ONCE(roce->sc->free));
	seq_printf(s, "tx_pio_outstanding_high %llu\n",
		   st->tx_pio_outstanding_high);
	seq_printf(s, "tx_pio_refresh    %llu\n", st->tx_pio_refresh);
	seq_printf(s, "tx_pio_eagain     %llu\n", st->tx_pio_eagain);
	seq_printf(s, "tx_pio_resync     %llu\n", st->tx_pio_resync);
	seq_printf(s, "tx_header_ns      %llu\n",
		   roce_tx_stat_read(&st->tx_header_ns, &roce->inline_stats.tx_header_ns));
	seq_printf(s, "tx_payload_copy_ns %llu\n",
		   roce_tx_stat_read(&st->tx_payload_copy_ns,
				     &roce->inline_stats.tx_payload_copy_ns));
	seq_printf(s, "tx_pio_write_ns   %llu\n",
		   roce_tx_stat_read(&st->tx_pio_write_ns, &roce->inline_stats.tx_pio_write_ns));
	seq_printf(s, "tx_pio_fence_ns   %llu\n",
		   roce_tx_stat_read(&st->tx_pio_fence_ns, &roce->inline_stats.tx_pio_fence_ns));
	seq_printf(s, "tx_pio_fences     %llu\n",
		   roce_tx_stat_read(&st->tx_pio_fences, &roce->inline_stats.tx_pio_fences));
	seq_printf(s, "tx_pio_credit_returns %llu\n",
		   roce_tx_stat_read(&st->tx_pio_credit_returns,
				     &roce->inline_stats.tx_pio_credit_returns));
	seq_printf(s, "tx_perf_stats     %u\n", READ_ONCE(roce_perf_stats));
	seq_printf(s, "tx_direct_gather  %u\n", READ_ONCE(roce_direct_gather));
	/* Effective state, not just the request: the CPU may lack the insn. */
	seq_printf(s, "tx_pio_movdir64b  %u\n", roce_pio_blk64_ready());
	seq_printf(s, "tx_pio_fence_interval %u\n",
		   READ_ONCE(roce_pio_fence_interval));
	seq_printf(s, "tx_pio_credit_return_interval %u\n",
		   READ_ONCE(roce_pio_credit_return_interval));
	seq_printf(s, "tx_pio_credit_threshold %llu\n",
		   READ_ONCE(roce->sc->credit_ctrl) &
		   SEND_CTXT_CREDIT_CTRL_THRESHOLD_MASK);
	seq_printf(s, "tx_pio_early_return %u\n",
		   !!(READ_ONCE(roce->sc->credit_ctrl) &
		      SEND_CTXT_CREDIT_CTRL_EARLY_RETURN_SMASK));
	seq_printf(s, "tx_worker_turns   %llu\n", st->tx_worker_turns);
	seq_printf(s, "tx_turn_next_wqe  %llu\n", st->tx_turn_next_wqe);
	seq_printf(s, "tx_resp_yield     %llu\n", st->tx_resp_yield);
	seq_printf(s, "tx_worker_iters   %llu\n", st->tx_worker_iters);
	seq_printf(s, "tx_sdma_arm_try   %llu\n", st->tx_sdma_arm_try);
	seq_printf(s, "tx_sdma_inline    %llu\n", st->tx_sdma_inline);
	seq_printf(s, "tx_sdma_middle_cached %llu\n", st->tx_sdma_middle_cached);
	seq_printf(s, "tx_read_resp_middle_cached %llu\n",
		   st->tx_read_resp_middle_cached);
	seq_printf(s, "tx_sdma_copy_fallback %llu\n", st->tx_sdma_copy_fallback);
	seq_printf(s, "tx_dmabuf_copy    %llu\n", st->tx_dmabuf_copy);
	seq_printf(s, "rx_dmabuf_copy    %llu\n", st->rx_dmabuf_copy);
	seq_printf(s, "rx_helper_dmabuf %llu\n", st->rx_helper_dmabuf);
	seq_printf(s, "rx_helper_dmabuf_err %llu\n", st->rx_helper_dmabuf_err);
	seq_printf(s, "atomic_dmabuf_nak %llu\n", st->atomic_dmabuf_nak);
	seq_printf(s, "tx_vlan_tagged    %llu\n",
		   roce_tx_stat_read(&st->tx_vlan_tagged, &roce->inline_stats.tx_vlan_tagged));
	seq_printf(s, "tx_runt_tagged    %llu\n",
		   roce_tx_stat_read(&st->tx_runt_tagged, &roce->inline_stats.tx_runt_tagged));
	seq_printf(s, "tx_pfc_tagged     %llu\n",
		   roce_tx_stat_read(&st->tx_pfc_tagged, &roce->inline_stats.tx_pfc_tagged));
	seq_printf(s, "tx_sdma_read_req  %llu\n", st->tx_sdma_read_req);
	seq_printf(s, "tx_atomic_req     %llu\n",
		   roce_tx_stat_read(&st->tx_atomic_req, &roce->inline_stats.tx_atomic_req));
	seq_printf(s, "tx_atomic_ack     %llu\n", st->tx_atomic_ack);
	seq_printf(s, "tx_order_gate_atomic %llu\n", st->tx_order_gate_atomic);
	seq_printf(s, "tx_order_gate_inv %llu\n", st->tx_order_gate_inv);
	seq_printf(s, "tx_sdma_read_req_decline %llu\n",
		   st->tx_sdma_read_req_decline);
	seq_printf(s, "tx_sdma_read_req_hold_wait %llu\n",
		   st->tx_sdma_read_req_hold_wait);
	seq_printf(s, "tx_sdma_ack       %llu\n", st->tx_sdma_ack);
	seq_printf(s, "tx_sdma_ack_stall %llu\n", st->tx_sdma_ack_stall);
	seq_printf(s, "tx_sdma_resp_error %llu\n", st->tx_sdma_resp_error);
	seq_printf(s, "tx_sdma_read_resp %llu\n", st->tx_sdma_read_resp);
	seq_printf(s, "tx_sdma_read_resp_stall %llu\n",
		   st->tx_sdma_read_resp_stall);
	seq_printf(s, "tx_sdma_resp_abandon %llu\n", st->tx_sdma_resp_abandon);
	seq_printf(s, "rx_read_resp_slast_lag %llu\n",
		   st->rx_read_resp_slast_lag);
	seq_printf(s, "tx_ack_behind_resp %llu\n", st->tx_ack_behind_resp);
	seq_printf(s, "tx_sdma_read_req_error %llu\n",
		   st->tx_sdma_read_req_error);
	seq_printf(s, "rx_read_resp_implicit_ack %llu\n",
		   st->rx_read_resp_implicit_ack);
	seq_printf(s, "rx_read_resp_stale %llu\n", st->rx_read_resp_stale);
	seq_printf(s, "rx_read_resp_restart %llu\n", st->rx_read_resp_restart);
	seq_printf(s, "rx_read_resp_seq_drop %llu\n", st->rx_read_resp_seq_drop);
	seq_printf(s, "rx_read_resp_skip_resend %llu\n",
		   st->rx_read_resp_skip_resend);
	seq_printf(s, "tx_read_resp_alias %llu\n", st->tx_read_resp_alias);
	seq_printf(s, "tx_read_resp_alias_skip %llu\n",
		   st->tx_read_resp_alias_skip);
	seq_printf(s, "tx_hwp_read_resp_bug %llu\n", st->tx_hwp_read_resp_bug);
	seq_printf(s, "rx_hwp_read_resp_drop %llu\n", st->rx_hwp_read_resp_drop);
	seq_printf(s, "tx_read_as_write %llu\n", st->tx_read_as_write);
	seq_printf(s, "hwp_rd_sw_multi_sge %llu\n", st->hwp_rd_sw_multi_sge);
	seq_printf(s, "hwp_rd_sw_no_pasid %llu\n", st->hwp_rd_sw_no_pasid);
	seq_printf(s, "hwp_rd_sw_mr_too_big %llu\n", st->hwp_rd_sw_mr_too_big);
	seq_printf(s, "hwp_rd_sw_no_ikey %llu\n", st->hwp_rd_sw_no_ikey);
	seq_printf(s, "hwp_rd_sw_misaligned %llu\n", st->hwp_rd_sw_misaligned);
	seq_printf(s, "hwp_rd_sw_other %llu\n", st->hwp_rd_sw_other);
	seq_printf(s, "hwp_rd_win_reads %llu\n", st->hwp_rd_win_reads);
	seq_printf(s, "hwp_rd_win_bytes %llu\n", st->hwp_rd_win_bytes);
	seq_printf(s, "hwp_rd_win_busy %llu\n", st->hwp_rd_win_busy);
	seq_printf(s, "hwp_rd_win_map_err %llu\n", st->hwp_rd_win_map_err);
	seq_printf(s, "hwp_rd_win_misaligned %llu\n",
		   st->hwp_rd_win_misaligned);
	seq_printf(s, "hwp_rd_win_too_big %llu\n", st->hwp_rd_win_too_big);
	seq_printf(s, "hwp_rd_win_rotations %llu\n",
		   st->hwp_rd_win_rotations);
	seq_printf(s, "hwp_rd_win_donor_queued %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_queued));
	seq_printf(s, "hwp_rd_win_donor_ready %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_ready));
	seq_printf(s, "hwp_rd_win_donor_cancelled %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_cancelled));
	seq_printf(s, "hwp_rd_win_donor_map_err %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_map_err));
	seq_printf(s, "hwp_rd_win_donor_zapped %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_zapped));
	seq_printf(s, "hwp_rd_win_donor_zap_err %lld\n",
		   (long long)atomic64_read(&st->hwp_rd_win_donor_zap_err));
	seq_printf(s, "hwp_cleanup_drain_err %lld\n",
		   (long long)atomic64_read(&st->hwp_cleanup_drain_err));
	seq_printf(s, "hwp_cleanup_fenced %lld\n",
		   (long long)atomic64_read(&roce->fence_stats.hwp_cleanup_fenced));
	seq_printf(s, "hwp_cleanup_fence_fail %lld\n",
		   (long long)atomic64_read(&roce->fence_stats.hwp_cleanup_fence_fail));
	seq_printf(s, "pasid_quarantined %lld\n",
		   (long long)atomic64_read(&roce->dd->roce_pasid_quarantined));
	seq_printf(s, "hwp_pool_enabled %llu\n", st->hwp_pool_enabled);
	seq_printf(s, "hwp_rd_win_busy_active %llu\n", st->hwp_rd_win_busy_active);
	seq_printf(s, "hwp_rd_win_busy_quarantine %llu\n",
		   st->hwp_rd_win_busy_quarantine);
	seq_printf(s, "hwp_rd_win_busy_exhausted %llu\n",
		   st->hwp_rd_win_busy_exhausted);
	seq_printf(s, "hwp_rd_win_key_err %llu\n", st->hwp_rd_win_key_err);
	seq_printf(s, "hwp_rd_win_phys_err %llu\n", st->hwp_rd_win_phys_err);
	seq_printf(s, "hwp_rd_win_iommu_err %llu\n", st->hwp_rd_win_iommu_err);
	seq_printf(s, "hwp_rd_win_iommu_nomem %llu\n", st->hwp_rd_win_iommu_nomem);
	seq_printf(s, "hwp_rd_win_iommu_exists %llu\n", st->hwp_rd_win_iommu_exists);
	seq_printf(s, "hwp_rd_win_install_full %llu\n", st->hwp_rd_win_install_full);
	seq_printf(s, "hwp_rd_win_install_err %llu\n", st->hwp_rd_win_install_err);
	seq_printf(s, "hwp_rd_win_donor_serialize %llu\n",
		   st->hwp_rd_win_donor_serialize);
	seq_printf(s, "hwp_rd_win_donor_reg_mr %llu\n",
		   st->hwp_rd_win_donor_reg_mr);
	seq_printf(s, "hwp_pool_backend_donor %u\n",
		   roce->hwp_pool.backend == HFI2_ROCE_HWP_DONOR);
	if (roce->hwp_pool.windows &&
	    roce->hwp_pool.backend == HFI2_ROCE_HWP_DONOR) {
		struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
		unsigned long flags;
		u32 active = 0, pending = 0, unavailable = 0, count, i;

		/* Donor lifetimes bypass the paging quarantine counters below. */
		spin_lock_irqsave(&pool->lock, flags);
		count = pool->win_count;
		for (i = 0; i < count; i++) {
			struct hfi2_dms_roce_hwp_window *window = &pool->windows[i];

			if (window->in_use) {
				if (window->state == HFI2_ROCE_HWP_RETIRING ||
				    window->state == HFI2_ROCE_HWP_ZAP_PENDING)
					pending++;
				else
					active++;
			} else if (window->state != HFI2_ROCE_HWP_FREE ||
				   window->exhausted || window->mapped ||
				   window->busy || window->owner) {
				unavailable++;
			}
		}
		spin_unlock_irqrestore(&pool->lock, flags);
		seq_printf(s, "hwp_donor_pool_count %u\n", count);
		seq_printf(s, "hwp_donor_pool_active %u\n", active);
		seq_printf(s, "hwp_donor_pool_pending %u\n", pending);
		seq_printf(s, "hwp_donor_pool_unavailable %u\n", unavailable);
		seq_printf(s, "hwp_donor_pool_free %u\n",
			   count - active - pending - unavailable);
	}
	if (roce->hwp_pool.windows &&
	    roce->hwp_pool.backend == HFI2_ROCE_HWP_PAGING) {
		struct hfi2_dms_roce_hwp_pool *pool = &roce->hwp_pool;
		unsigned long flags;
		u32 active, pending, exhausted = 0, i;

		spin_lock_irqsave(&pool->lock, flags);
		active = pool->active;
		pending = pool->pending;
		for (i = 0; i < pool->win_count; i++)
			exhausted += pool->windows[i].exhausted;
		seq_printf(s, "hwp_pool_count %u\n", pool->win_count);
		seq_printf(s, "hwp_pool_active %u\n", active);
		seq_printf(s, "hwp_pool_pending %u\n", pending);
		seq_printf(s, "hwp_pool_free %u\n",
			   pool->win_count - active - pending - exhausted);
		seq_printf(s, "hwp_pool_exhausted %u\n", exhausted);
		seq_printf(s, "hwp_pool_active_high %u\n", pool->active_high);
		seq_printf(s, "hwp_pool_pending_high %u\n", pool->pending_high);
		seq_printf(s, "hwp_pool_acquired %llu\n", pool->acquired);
		seq_printf(s, "hwp_pool_released %llu\n", pool->released);
		seq_printf(s, "hwp_pool_reaped %llu\n", pool->reaped);
		seq_printf(s, "hwp_pool_hold_ns %llu\n", pool->hold_ns);
		seq_printf(s, "hwp_pool_hold_max_ns %llu\n", pool->hold_max_ns);
		seq_printf(s, "hwp_pool_quarantine_ns %llu\n", pool->quarantine_ns);
		seq_printf(s, "hwp_pool_quarantine_max_ns %llu\n",
			   pool->quarantine_max_ns);
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	seq_printf(s, "tx_read_as_write_pkts %llu\n",
		   st->tx_read_as_write_pkts);
	seq_printf(s, "rx_read_as_write %llu\n", st->rx_read_as_write);
	seq_printf(s, "rx_read_as_write_placed %llu\n",
		   st->rx_read_as_write_placed);
	seq_printf(s, "rx_read_as_write_fallback_drop %llu\n",
		   st->rx_read_as_write_fallback_drop);
	seq_printf(s, "rif_read_alias_invalidate %llu\n",
		   st->rif_read_alias_invalidate);
	seq_printf(s, "rx_internal_key_on_base %llu\n",
		   st->rx_internal_key_on_base);
	seq_printf(s, "internal_rkey_install %llu\n",
		   st->internal_rkey_install);
	seq_printf(s, "internal_rkey_install_fail %llu\n",
		   st->internal_rkey_install_fail);
	seq_printf(s, "internal_rkey_exhausted %lld\n",
		   atomic64_read(&st->internal_rkey_exhausted));
	seq_printf(s, "rx_alias_bad_opcode %llu\n", st->rx_alias_bad_opcode);
	seq_printf(s, "rx_answer_on_base %llu\n", st->rx_answer_on_base);
	seq_printf(s, "tx_worker_packets %llu\n", st->tx_worker_packets);
	seq_printf(s, "tx_send_state_drop %llu\n", st->tx_send_state_drop);
	seq_printf(s, "tx_flush_wqe      %llu\n", st->tx_flush_wqe);
	seq_printf(s, "rx_rcd_0_packets  %llu\n", st->rx_rcd_packets[0]);
	seq_printf(s, "rx_rcd_1_packets  %llu\n", st->rx_rcd_packets[1]);
	seq_printf(s, "rx_rcd_0_empty_polls %llu\n", st->rx_rcd_empty_polls[0]);
	seq_printf(s, "rx_rcd_1_empty_polls %llu\n", st->rx_rcd_empty_polls[1]);
	seq_printf(s, "rx_rcd_0_budget_limited %llu\n",
		   st->rx_rcd_budget_limited[0]);
	seq_printf(s, "rx_rcd_1_budget_limited %llu\n",
		   st->rx_rcd_budget_limited[1]);
	seq_printf(s, "rx_wrong_rcd      %llu\n", st->rx_wrong_rcd);
	seq_printf(s, "qp_rcd_0_bindings %llu\n", st->qp_rcd_bindings[0]);
	seq_printf(s, "qp_rcd_1_bindings %llu\n", st->qp_rcd_bindings[1]);
	seq_printf(s, "rx_rhe_drop       %llu\n", st->rx_rhe_drop);
	seq_printf(s, "rx_rhe_last_reason 0x%016llx\n",
		   st->rx_rhe_last_reason);
	seq_printf(s, "rx_bypass         %llu\n", st->rx_bypass);
	seq_printf(s, "rx_netdev_diverted %llu\n",
		   atomic64_read(&st->rx_netdev_diverted));
	seq_printf(s, "rx_netdev_dropped %llu\n",
		   atomic64_read(&st->rx_netdev_dropped));
	seq_printf(s, "rx_test_drop      %llu\n", st->rx_test_drop);
	seq_printf(s, "rx_vrma_protocol_error %llu\n",
		   st->rx_vrma_protocol_error);
	seq_printf(s, "rx_parse_err      %llu\n", st->rx_parse_err);
	seq_printf(s, "rx_no_qp          %llu\n", st->rx_no_qp);
	seq_printf(s, "rx_ud_pkts        %llu\n", st->rx_ud_pkts);
	seq_printf(s, "rx_ud_drop        %llu\n", st->rx_ud_drop);
	seq_printf(s, "rx_ud_qkey_drop   %llu\n", st->rx_ud_qkey_drop);
	seq_printf(s, "rx_ud_no_rwqe     %llu\n", st->rx_ud_no_rwqe);
	seq_printf(s, "rx_ud_too_long    %llu\n", st->rx_ud_too_long);
	seq_printf(s, "rx_no_backend     %llu\n", st->rx_no_backend);
	seq_printf(s, "rx_bad_pkey       %llu\n", st->rx_bad_pkey);
	seq_printf(s, "rx_pkey_drop      %llu\n", st->rx_pkey_drop);
	seq_printf(s, "rx_qp_state_drop  %llu\n", st->rx_qp_state_drop);
	seq_printf(s, "rx_invalid_av     %llu\n", st->rx_invalid_av);
	seq_printf(s, "rx_bad_peer       %llu\n", st->rx_bad_peer);
	seq_printf(s, "rx_unhandled_opcode %llu\n", st->rx_unhandled_opcode);
	seq_printf(s, "rx_send           %llu\n", st->rx_send);
	seq_printf(s, "rx_send_psn_drop  %llu\n", st->rx_send_psn_drop);
	seq_printf(s, "rx_send_rnr       %llu\n", st->rx_send_rnr);
	seq_printf(s, "rx_send_nak_seq   %llu\n", st->rx_send_nak_seq);
	seq_printf(s, "rx_send_inv       %llu\n", st->rx_send_inv);
	seq_printf(s, "rx_send_inv_fail  %llu\n", st->rx_send_inv_fail);
	seq_printf(s, "rx_write_psn_drop %llu\n", st->rx_write_psn_drop);
	seq_printf(s, "rx_write_nak_seq  %llu\n", st->rx_write_nak_seq);
	seq_printf(s, "rx_write_gap_retry %llu\n", st->rx_write_gap_retry);
	seq_printf(s, "rx_burst_first_live %llu\n", st->rx_burst_first_live);
	seq_printf(s, "rx_burst_orphan   %llu\n", st->rx_burst_orphan);
	seq_printf(s, "rx_burst_short_middle %llu\n",
		   st->rx_burst_short_middle);
	seq_printf(s, "rx_burst_overlong %llu\n", st->rx_burst_overlong);
	seq_printf(s, "rx_burst_middle_completes %llu\n",
		   st->rx_burst_middle_completes);
	seq_printf(s, "rx_burst_last_mismatch %llu\n",
		   st->rx_burst_last_mismatch);
	seq_printf(s, "rx_read_state_drop %llu\n", st->rx_read_state_drop);
	seq_printf(s, "rx_read_dup_drop  %llu\n", st->rx_read_dup_drop);
	seq_printf(s, "rx_atomic_req     %llu\n", st->rx_atomic_req);
	seq_printf(s, "rx_atomic_dup     %llu\n", st->rx_atomic_dup);
	seq_printf(s, "rx_atomic_ack     %llu\n", st->rx_atomic_ack);
	seq_printf(s, "rx_recv_cqe       %llu\n", st->rx_recv_cqe);
	seq_printf(s, "rx_write_imm_cqe  %llu\n", st->rx_write_imm_cqe);
	seq_printf(s, "rx_write_imm_rnr  %llu\n", st->rx_write_imm_rnr);
	{
		u8 i;

		st->rx_helper_dep_waits = 0;
		for (i = 0; i < HFI2_DMS_ROCE_RX_HELPER_MAX; i++) {
			struct hfi2_dms_roce_rx_helper *helper = &roce->rx_helpers[i];

			st->rx_helper_copies[i] = READ_ONCE(helper->copies);
			st->rx_helper_bytes[i] = READ_ONCE(helper->bytes);
			helper_verify_bad += READ_ONCE(helper->verify_bad);
			helper_wakeups += READ_ONCE(helper->wakeups);
			st->rx_helper_dep_waits += READ_ONCE(helper->dep_waits);
			seq_printf(s, "rx_helper_%u_copies %llu\n", i,
				   st->rx_helper_copies[i]);
			seq_printf(s, "rx_helper_%u_bytes %llu\n", i,
				   st->rx_helper_bytes[i]);
		}
		seq_printf(s, "rx_helper_cpu_small %llu\n",
			   st->rx_helper_cpu_small);
		seq_printf(s, "rx_helper_cpu_nonkernel %llu\n",
			   st->rx_helper_cpu_nonkernel);
		seq_printf(s, "rx_helper_cpu_skb %llu\n", st->rx_helper_cpu_skb);
		seq_printf(s, "rx_helper_full_waits %llu\n",
			   st->rx_helper_full_waits);
		seq_printf(s, "rx_helper_drains %llu\n", st->rx_helper_drains);
		seq_printf(s, "rx_helper_stalls %llu\n", st->rx_helper_stalls);
		seq_printf(s, "rx_helper_ack_drains %llu\n",
			   st->rx_helper_ack_drains);
		seq_printf(s, "rx_helper_usrhead_deferred %llu\n",
			   st->rx_helper_usrhead_deferred);
		seq_printf(s, "rx_helper_usrhead_spin %llu\n",
			   st->rx_helper_usrhead_spin);
		st->rx_helper_verify_bad = helper_verify_bad;
		st->rx_helper_wakeups = helper_wakeups;
		seq_printf(s, "rx_helper_verify_bad %llu\n",
			   st->rx_helper_verify_bad);
		seq_printf(s, "rx_helper_wakeups %llu\n",
			   st->rx_helper_wakeups);
	}
	seq_printf(s, "rx_helper_deps %llu\n", st->rx_helper_deps);
	seq_printf(s, "rx_helper_dep_waits %llu\n", st->rx_helper_dep_waits);
	seq_printf(s, "rx_qp_lock_holds %llu\n", st->rx_qp_lock_holds);
	seq_printf(s, "rx_ack            %llu\n", st->rx_ack);
	seq_printf(s, "rx_ack_completed  %llu\n", st->rx_ack_completed);
	seq_printf(s, "rx_ack_nak_seq    %llu\n", st->rx_ack_nak_seq);
	seq_printf(s, "rx_ack_rnr        %llu\n", st->rx_ack_rnr);
	seq_printf(s, "rx_ack_fatal      %llu\n", st->rx_ack_fatal);
	seq_printf(s, "retry_restart     %llu\n", st->retry_restart);
	seq_printf(s, "retry_rx_defer    %llu\n", st->retry_rx_defer);
	seq_printf(s, "retry_exhausted   %llu\n", st->retry_exhausted);
	seq_printf(s, "retry_rnr_exhausted %llu\n",
		   st->retry_rnr_exhausted);
	seq_printf(s, "stride_mismatch   %llu\n", st->stride_mismatch);
	seq_printf(s, "stride_unsupported %llu\n", st->stride_unsupported);
	seq_printf(s, "tomb_armed %llu\n", tombs ? READ_ONCE(tombs->armed) : 0);
	seq_printf(s, "tomb_cleared_reuse %llu\n",
		   tombs ? READ_ONCE(tombs->cleared_reuse) : 0);
	seq_printf(s, "tomb_evicted %llu\n", tombs ? READ_ONCE(tombs->evicted) : 0);
	seq_printf(s, "tomb_arm_fail %llu\n", tombs ? READ_ONCE(tombs->arm_fail) : 0);
	seq_printf(s, "rif_arm           %llu\n", st->rif_arm);
	seq_printf(s, "rif_arm_hw_busy   %llu\n", st->rif_arm_hw_busy);
	seq_printf(s, "rif_arm_read_err  %llu\n", st->rif_arm_read_err);
	seq_printf(s, "rif_arm_hw_scan_reads %llu\n", st->rif_arm_hw_scan_reads);
	seq_printf(s, "rif_arm_scan_slow %llu\n", st->rif_arm_scan_slow);
	seq_printf(s, "rif_arm_scan_wall_slow %llu\n", st->rif_arm_scan_wall_slow);
	seq_printf(s, "rif_arm_deferred %llu\n", st->rif_arm_deferred);
	seq_printf(s, "rif_arm_pending %llu\n", st->rif_arm_pending);
	seq_printf(s, "rif_arm_cancelled %llu\n", st->rif_arm_cancelled);
	seq_printf(s, "rif_arm_ack_held %llu\n", st->rif_arm_ack_held);
	seq_printf(s, "rif_arm_ack_inline %llu\n", st->rif_arm_ack_inline);
	seq_printf(s, "rif_arm_completed %llu\n", st->rif_arm_completed);
	seq_printf(s, "rif_arm_latency_ns %llu\n", st->rif_arm_latency_ns);
	seq_printf(s, "rif_arm_latency_max_ns %llu\n", st->rif_arm_latency_max_ns);
	seq_printf(s, "rif_arm_latency_slow %llu\n", st->rif_arm_latency_slow);
	seq_printf(s, "rif_arm_reject    %llu\n", st->rif_arm_reject);
	seq_printf(s, "rif_invalidate    %llu\n", st->rif_invalidate);
	seq_printf(s, "rif_invalidate_read_err %llu\n",
		   st->rif_invalidate_read_err);
	seq_printf(s, "rif_readback_fail %llu\n", st->rif_readback_fail);
	seq_printf(s, "rif_invalidate_reject %llu\n", st->rif_invalidate_reject);
	seq_printf(s, "rif_arm_exclusive %llu\n", st->rif_arm_exclusive);
	seq_printf(s, "rif_row_full      %llu\n", st->rif_row_full);
	seq_printf(s, "rif_arm_pasid_mismatch %llu\n",
		   st->rif_arm_pasid_mismatch);
	seq_printf(s, "rif_arm_dead_mm   %llu\n", st->rif_arm_dead_mm);
	seq_printf(s, "rkey_install      %llu\n", st->rkey_install);
	seq_printf(s, "rkey_install_reject %llu\n", st->rkey_install_reject);
	seq_printf(s, "rkey_row_full     %llu\n", st->rkey_row_full);
	seq_printf(s, "rkey_too_long     %llu\n", st->rkey_too_long);
	seq_printf(s, "rkey_pasid_mismatch %llu\n", st->rkey_pasid_mismatch);
	seq_printf(s, "rkey_dead_mm      %llu\n", st->rkey_dead_mm);
	seq_printf(s, "rkey_invalidate   %llu\n", st->rkey_invalidate);
	seq_printf(s, "rkey_invalidate_reject %llu\n",
		   st->rkey_invalidate_reject);
	seq_printf(s, "mr_eligible       %llu\n", st->mr_eligible);
	seq_printf(s, "mr_pasid_dmabuf   %lld\n",
		   atomic64_read(&dd->roce_mr_pasid_dmabuf_count));
	seq_printf(s, "mr_pasid_sva      %lld\n",
		   atomic64_read(&dd->roce_mr_pasid_sva_count));
	seq_printf(s, "mr_pasid_map      %lld\n",
		   atomic64_read(&dd->roce_mr_pasid_map_count));
	seq_printf(s, "kmr_pasid_mapped  %llu\n", st->kmr_pasid_mapped);
	seq_printf(s, "kmr_pasid_skip_iova %llu\n", st->kmr_pasid_skip_iova);
	seq_printf(s, "kmr_pasid_err     %llu\n", st->kmr_pasid_err);
	seq_printf(s, "kmr_donor_mapped  %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_mapped));
	seq_printf(s, "kmr_donor_skip_iova %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_skip_iova));
	seq_printf(s, "kmr_donor_skip_pool %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_skip_pool));
	seq_printf(s, "kmr_donor_err     %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_err));
	seq_printf(s, "kmr_donor_dmabuf_mapped %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_dmabuf_mapped));
	seq_printf(s, "kmr_donor_dmabuf_busy %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_dmabuf_busy));
	seq_printf(s, "kmr_donor_dmabuf_err %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_dmabuf_err));
	seq_printf(s, "kmr_donor_flushes %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_flushes));
	seq_printf(s, "kmr_donor_windows_free %lld\n",
		   (long long)atomic64_read(&st->kmr_donor_windows_free));
	seq_printf(s, "mr_ineligible_sw_rx %llu\n", st->mr_ineligible_sw_rx);
	seq_printf(s, "mr_ineligible_kernel %llu\n", st->mr_ineligible_kernel);
	seq_printf(s, "mr_ineligible_length %llu\n", st->mr_ineligible_length);
	seq_printf(s, "rkey_no_remote_access %llu\n",
		   st->rkey_no_remote_access);
	seq_printf(s, "rx_type_not_roce  %llu\n", st->rx_type_not_roce);
	seq_printf(s, "rx_l4_eth         %llu\n", st->rx_l4_eth);
	seq_printf(s, "rx_l4_excptn      %llu\n", st->rx_l4_excptn);
	seq_printf(s, "rx_l4_vrma        %llu\n", st->rx_l4_vrma);
	seq_printf(s, "rx_l4_tid         %llu\n", st->rx_l4_tid);
	seq_printf(s, "rx_l4_unknown     %llu\n", st->rx_l4_unknown);
	seq_printf(s, "rx_end_state_ok   %llu\n", st->rx_end_state_ok);
	seq_printf(s, "rx_end_state_first_err %llu\n",
		   st->rx_end_state_first_err);
	seq_printf(s, "rx_end_state_middle_oo %llu\n",
		   st->rx_end_state_middle_oo);
	seq_printf(s, "rx_end_state_middle_no_qp %llu\n",
		   st->rx_end_state_middle_no_qp);
	seq_printf(s, "rx_end_state_last_err %llu\n",
		   st->rx_end_state_last_err);
	seq_printf(s, "rx_end_state_reserved %llu\n",
		   st->rx_end_state_reserved);
	seq_printf(s, "rx_vrma_reports   %llu\n", st->rx_vrma_reports);
	seq_printf(s, "rx_vrma_placed_packets %llu\n",
		   st->rx_vrma_placed_packets);
	seq_printf(s, "rx_vrma_placed_bytes %llu\n",
		   st->rx_vrma_placed_bytes);
	seq_printf(s, "rx_vrma_trimmed   %llu\n", st->rx_vrma_trimmed);
	seq_printf(s, "rx_vrma_zero_write %llu\n", st->rx_vrma_zero_write);
	seq_printf(s, "rx_vrma_bad_opcode %llu\n", st->rx_vrma_bad_opcode);
	seq_printf(s, "read_write_bad_report %llu\n", st->read_write_bad_report);
	seq_printf(s, "rx_rrsp_first_diverted %llu\n", st->rx_rrsp_first_diverted);
	seq_printf(s, "rrsp_first_retry %llu\n", st->rrsp_first_retry);
	seq_printf(s, "rrsp_first_giveup %llu\n", st->rrsp_first_giveup);
	seq_printf(s, "h15_arm_ok         %llu\n", st->h15_arm_ok);
	seq_printf(s, "h15_arm_fail       %llu\n", st->h15_arm_fail);
	seq_printf(s, "h15_stale_first    %llu\n", st->h15_stale_first);
	seq_printf(s, "rif_release        %llu\n", st->rif_release);
	seq_printf(s, "rif_release_foreign %llu\n", st->rif_release_foreign);
	seq_printf(s, "rx_vrma_overrun    %llu\n", st->rx_vrma_overrun);
	seq_printf(s, "h15_nak            %llu\n", st->h15_nak);
	seq_printf(s, "h15_arm_reclaim    %llu\n", st->h15_arm_reclaim);
	seq_printf(s, "h15_arm_nak        %llu\n", st->h15_arm_nak);
	seq_printf(s, "h15_straggler_drop %llu\n", st->h15_straggler_drop);
	seq_printf(s, "rx_lbs_adopt %llu\n", st->rx_lbs_adopt);
	seq_printf(s, "rx_lbs_adopt_skip %llu\n", st->rx_lbs_adopt_skip);
	seq_printf(s, "rx_lbs_hdr_short %llu\n", st->rx_lbs_hdr_short);
	seq_printf(s, "rx_lbs_rkey_err %llu\n", st->rx_lbs_rkey_err);
	seq_printf(s, "rx_lbs_middle %llu\n", st->rx_lbs_middle);
	seq_printf(s, "rx_lbs_last %llu\n", st->rx_lbs_last);
	seq_printf(s, "rx_lbs_trim %llu\n", st->rx_lbs_trim);
	seq_printf(s, "rx_lbs_adopt_dup %llu\n", st->rx_lbs_adopt_dup);
	seq_printf(s, "rx_lbs_dup_report %llu\n", st->rx_lbs_dup_report);
	seq_printf(s, "tx_replay_resume %llu\n", st->tx_replay_resume);
	seq_printf(s, "rx_lbs_orphan %llu\n", st->rx_lbs_orphan);
	seq_printf(s, "rif_lbs_inval %llu\n", st->rif_lbs_inval);
	seq_printf(s, "rif_lbs_early %llu\n", st->rif_lbs_early);
	seq_printf(s, "rif_lbs_cache_hit %llu\n", st->rif_lbs_cache_hit);
	seq_printf(s, "rif_lbs_scan %llu\n", st->rif_lbs_scan);
	seq_printf(s, "rif_lbs_scan_miss %llu\n", st->rif_lbs_scan_miss);
	seq_printf(s, "rif_lbs_multi %llu\n", st->rif_lbs_multi);
	seq_printf(s, "rx_first_diverted %llu\n", st->rx_first_diverted);
	seq_printf(s, "rx_first_reclaim_nak %llu\n", st->rx_first_reclaim_nak);
	seq_printf(s, "rif_reclaim_scan %llu\n", st->rif_reclaim_scan);
	seq_printf(s, "rif_reclaim_none %llu\n", st->rif_reclaim_none);
	seq_printf(s, "rif_reclaim_giveup %llu\n", st->rif_reclaim_giveup);
	seq_printf(s, "rif_reclaim_live %llu\n", st->rif_reclaim_live);
	seq_printf(s, "rif_reclaim_own %llu\n", st->rif_reclaim_own);
	seq_printf(s, "rif_reclaim_dead %llu\n", st->rif_reclaim_dead);
	seq_printf(s, "rif_reclaim_recovering %llu\n",
		   st->rif_reclaim_recovering);
	seq_printf(s, "rif_reclaim_idle %llu\n", st->rif_reclaim_idle);
	seq_printf(s, "rif_reclaim_unlatched %llu\n",
		   st->rif_reclaim_unlatched);
	seq_printf(s, "rif_reclaim_finished %llu\n", st->rif_reclaim_finished);
	seq_printf(s, "rx_vrma_bad_pkey %llu\n", st->rx_vrma_bad_pkey);
	seq_printf(s, "rx_vrma_bad_pasid %llu\n", st->rx_vrma_bad_pasid);
	seq_printf(s, "rx_vrma_va_mismatch %llu\n", st->rx_vrma_va_mismatch);
	seq_printf(s, "rx_vrma_length_error %llu\n", st->rx_vrma_length_error);
	seq_printf(s, "rx_vrma_no_burst %llu\n", st->rx_vrma_no_burst);
	seq_printf(s, "rx_vrma_nak_seq  %llu\n", st->rx_vrma_nak_seq);
	seq_printf(s, "rx_vrma_last_ack %llu\n", st->rx_vrma_last_ack);
	seq_printf(s, "rx_vrma_ack_req  %llu\n", st->rx_vrma_ack_req);
	seq_printf(s, "rx_vrma_middle_fast %llu\n", st->rx_vrma_middle_fast);
	seq_printf(s, "rx_vrma_dup      %llu\n", st->rx_vrma_dup);
	seq_printf(s, "rx_vrma_ahead    %llu\n", st->rx_vrma_ahead);
	seq_printf(s, "rx_write_imm_resume %llu\n", st->rx_write_imm_resume);
	seq_printf(s, "rif_invalidate_hw %llu\n", st->rif_invalidate_hw);
	seq_printf(s, "rif_pasid_rows_scanned %llu\n",
		   (unsigned long long)atomic64_read(&st->rif_pasid_rows_scanned));
	seq_printf(s, "rif_pasid_late_rows %llu\n",
		   (unsigned long long)atomic64_read(&st->rif_pasid_late_rows));
	seq_printf(s, "rif_pasid_loss_gen %llu\n",
		   READ_ONCE(roce->rif_pasid_loss_gen));
	seq_printf(s, "rif_pasid_loss_rhe %llu\n",
		   READ_ONCE(st->rif_pasid_loss_rhe));
	seq_printf(s, "rif_pasid_loss_ovfl %llu\n",
		   READ_ONCE(st->rif_pasid_loss_ovfl));
	seq_printf(s, "rif_pasid_loss_bypass %llu\n",
		   READ_ONCE(st->rif_pasid_loss_bypass));
	seq_printf(s, "rif_pasid_loss_netdev %llu\n",
		   READ_ONCE(st->rif_pasid_loss_netdev));
	seq_printf(s, "rif_pasid_loss_report %llu\n",
		   READ_ONCE(st->rif_pasid_loss_report));
	seq_printf(s, "rif_pasid_full_sweep %llu\n",
		   (unsigned long long)atomic64_read(&st->rif_pasid_full_sweep));
	seq_printf(s, "rif_pasid_track_enomem %llu\n",
		   (unsigned long long)atomic64_read(&st->rif_pasid_track_enomem));
	seq_printf(s, "sdma_admission_stall %llu\n",
		   READ_ONCE(st->sdma_admission_stall));
	seq_printf(s, "sdma_stall_qp_holds %llu\n",
		   READ_ONCE(st->sdma_stall_qp_holds));
	seq_printf(s, "sdma_stall_eng_bundle %llu\n",
		   READ_ONCE(st->sdma_stall_eng_bundle));
	seq_printf(s, "sdma_stall_eng_desc %llu\n",
		   READ_ONCE(st->sdma_stall_eng_desc));
	seq_printf(s, "sdma_stall_eng_page %llu\n",
		   READ_ONCE(st->sdma_stall_eng_page));
	seq_printf(s, "sdma_page_stall   %llu\n", READ_ONCE(st->sdma_page_stall));
	seq_printf(s, "sdma_batch_stall  %llu\n", READ_ONCE(st->sdma_batch_stall));
	seq_printf(s, "sdma_park         %llu\n", READ_ONCE(st->sdma_park));
	seq_printf(s, "sdma_wake         %llu\n", READ_ONCE(st->sdma_wake));
	seq_printf(s, "sdma_wake_skipped %llu\n",
		   READ_ONCE(st->sdma_wake_skipped));
	seq_printf(s, "sdma_commit_accepted %llu\n",
		   READ_ONCE(st->sdma_commit_accepted));
	seq_printf(s, "sdma_callback_ok  %llu\n", READ_ONCE(st->sdma_callback_ok));
	seq_printf(s, "sdma_callback_error %llu\n",
		   READ_ONCE(st->sdma_callback_error));
	seq_printf(s, "sdma_callback_shutdown %llu\n",
		   READ_ONCE(st->sdma_callback_shutdown));
	seq_printf(s, "sdma_context_mismatch %llu\n",
		   READ_ONCE(st->sdma_context_mismatch));
	seq_printf(s, "roce_sdma_bundle_packets %u\n",
		     READ_ONCE(roce_sdma_bundle_packets));
	seq_printf(s, "bundle_packets_1_4 %llu\n",
		     READ_ONCE(st->bundle_packets_1_4));
	seq_printf(s, "bundle_packets_5_16 %llu\n",
		     READ_ONCE(st->bundle_packets_5_16));
	seq_printf(s, "bundle_packets_17_32 %llu\n",
		     READ_ONCE(st->bundle_packets_17_32));
	seq_printf(s, "bundle_packets_33_64 %llu\n",
		     READ_ONCE(st->bundle_packets_33_64));
	seq_printf(s, "bundle_packets_65_128 %llu\n",
		     READ_ONCE(st->bundle_packets_65_128));
	seq_printf(s, "bundle_packets_129_256 %llu\n",
		     READ_ONCE(st->bundle_packets_129_256));
	seq_printf(s, "bundle_packets_257_512 %llu\n",
		     READ_ONCE(st->bundle_packets_257_512));
	seq_printf(s, "bundle_packets_total %llu\n",
		     READ_ONCE(st->bundle_packets_total));
	seq_printf(s, "bundle_descriptors_total %llu\n",
		     READ_ONCE(st->bundle_descriptors_total));
	seq_printf(s, "bundle_packets_max %u\n",
		     READ_ONCE(st->bundle_packets_max));
	seq_printf(s, "bundle_descriptors_max %u\n",
		     READ_ONCE(st->bundle_descriptors_max));
	seq_printf(s, "admitted_descriptors_current %u\n",
		     READ_ONCE(st->admitted_descriptors_current));
	seq_printf(s, "admitted_descriptors_high_water %u\n",
		     READ_ONCE(st->admitted_descriptors_high_water));
	seq_printf(s, "s_lock_hold_max_ns %llu\n",
		     READ_ONCE(st->s_lock_hold_max_ns));
	seq_printf(s, "s_lock_hold_over_100us %llu\n",
		     READ_ONCE(st->s_lock_hold_over_100us));
	seq_printf(s, "s_lock_hold_samples %llu\n",
		     READ_ONCE(st->s_lock_hold_samples));
	seq_puts(s, "roce_stats_units bundle_packets=count bundle_descriptors=count admitted_descriptors=current/high-water logical-descriptors ring_resident=current/high-water hardware-visible-descriptors s_lock_hold_max_ns=ns s_lock_hold_over_100us=count s_lock_hold_samples=count\n");
	seq_printf(s, "dms_sdma_batch_setup_allocs %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_batch_setup_allocs));
	seq_printf(s, "dms_sdma_batch_setup_failures %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_batch_setup_failures));
	seq_printf(s, "dms_sdma_batch_growth_allocs %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_batch_growth_allocs));
	seq_printf(s, "dms_sdma_batch_growth_failures %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_batch_growth_failures));
	seq_printf(s, "dms_sdma_completion_fifo_setup_allocs %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_completion_fifo_setup_allocs));
	seq_printf(s, "dms_sdma_completion_fifo_setup_failures %llu\n",
		   READ_ONCE(dms->allocation_stats.sdma_completion_fifo_setup_failures));
	seq_printf(s, "dms_page_block_setup_allocs %llu\n",
		   READ_ONCE(dms->allocation_stats.page_block_setup_allocs));
	seq_printf(s, "dms_page_block_setup_failures %llu\n",
		   READ_ONCE(dms->allocation_stats.page_block_setup_failures));
	seq_printf(s, "dms_page_block_growth_allocs %llu\n",
		   READ_ONCE(dms->allocation_stats.page_block_growth_allocs));
	seq_printf(s, "dms_page_block_growth_failures %llu\n",
		   READ_ONCE(dms->allocation_stats.page_block_growth_failures));
	{
		struct hfi2_dms_allocation_stats *stats = &dms->allocation_stats;
		u8 i;

		for (i = 0; i < dms->num_engines; i++) {
			seq_printf(s,
				   "dms_sdma_completion_fifo_engine_%u allocs %llu failures %llu\n",
				   i,
				   READ_ONCE(stats->sdma_completion_fifo_engine_allocs[i]),
				   READ_ONCE(stats->sdma_completion_fifo_engine_failures[i]));
		}
	}
#if HFI2_DMS_ROCE_INJECT
	seq_printf(s, "sdma_retire_ack_first %llu\n",
		   READ_ONCE(st->sdma_retire_ack_first));
	seq_printf(s, "sdma_retire_callback_first %llu\n",
		   READ_ONCE(st->sdma_retire_callback_first));
	seq_printf(s, "sdma_inject_preaccept_shutdown %llu\n",
		   READ_ONCE(st->sdma_inject_preaccept_shutdown));
	seq_printf(s, "sdma_inject_callback_error %llu\n",
		   READ_ONCE(st->sdma_inject_callback_error));
	seq_printf(s, "sdma_inject_hold_for_ack %llu\n",
		   READ_ONCE(st->sdma_inject_hold_for_ack));
	seq_printf(s, "emitter_epoch_open %llu\n",
		   READ_ONCE(st->emitter_epoch_open));
	seq_printf(s, "emitter_epoch_close %llu\n",
		   READ_ONCE(st->emitter_epoch_close));
	seq_printf(s, "emitter_live_switch_reject %llu\n",
		   READ_ONCE(st->emitter_live_switch_reject));
	seq_printf(s, "emitter_idle_switch_accept %llu\n",
		   READ_ONCE(st->emitter_idle_switch_accept));
#endif
	{
		u8 i;

		for (i = 0; i < READ_ONCE(roce->sdma_engine_count); i++) {
			struct hfi2_dms_roce_sdma_engine *engine =
				&roce->sdma_engines[i];

			seq_printf(s,
				     "sdma_engine_%u bundle_current %u bundle_cap %u bundle_high_water %u bundle_admitted %llu descriptor_current %u descriptor_cap %u descriptor_high_water %u descriptor_admitted %llu page_current %u page_cap %u page_high_water %u page_admitted %llu ring_resident_current %u ring_resident_high_water %u\n",
				     i, READ_ONCE(engine->bundle_used),
				     READ_ONCE(engine->bundle_cap),
				     READ_ONCE(engine->bundle_high_water),
				     READ_ONCE(engine->bundle_admit_count),
				     READ_ONCE(engine->descriptor_used),
				     READ_ONCE(engine->descriptor_cap),
				     READ_ONCE(engine->descriptor_high_water),
				     READ_ONCE(engine->descriptor_admit_count),
				     READ_ONCE(engine->page_used),
				     READ_ONCE(engine->page_cap),
				     READ_ONCE(engine->page_high_water),
				     READ_ONCE(engine->page_admit_count),
				     hfi2_dms_sdma_ring_resident_current(dms, i),
				     hfi2_dms_sdma_ring_resident_high_water(dms, i));
		}
	}
	hfi2_bulksvc_closeout_stats_print(roce->svc, s);
	/*
	 * Report the stride from the CSR rather than from stride_bytes, so a
	 * register that did not retain what software wrote is visible here
	 * instead of being masked by the driver's own copy.
	 */
	seq_printf(s, "stride_bytes      %u\n", roce->stride_bytes);
	seq_printf(s, "rocev2_mtu_csr    %llu\n",
		   EAL_ROCEV2_CFG_GET_ROCEV2_MTU(hfi2_read_csr(roce->dd,
							  CYR_EAL_ROCEV2_CFG)));
#if HFI2_DMS_ROCE_INJECT
	seq_printf(s, "inject_fail       %llu\n", st->inject_fail);
#endif
}
