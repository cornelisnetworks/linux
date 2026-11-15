/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks.
 */

#include "bulksvc.h"
#include "chip.h"
#include "chip_registers.h"
#include "common.h"
#include "dms.h"
#include "hfi2.h"
#include "linux/workqueue.h"
#include "msix.h"
#include "sdma.h"
#include "exp_rcv.h"
#include "trace_dbg.h"
#include "mem_region.h"
#include "roce_pasid.h"
#include "verbs_txreq.h"
#include "bulksvc_verbs.h"
#include "bulksvc_rvt.h"
#include "bulksvc_ulp.h"
#include "netdev.h"
#include "eth_hwi.h"
#include "roce_wire.h"

#include <linux/string.h>
#include <linux/bitfield.h>
#include <linux/pci-ats.h>
#include <linux/jump_label.h>
#include <rdma/hfi2-abi.h>

#ifdef CONFIG_SMP
static_assert(offsetof(struct hfi2_bulksvc, dirty_notify) == SMP_CACHE_BYTES,
	      "bulksvc dirty_notify must start the second cache line");
static_assert(offsetof(struct hfi2_bulksvc, prereqs) == 2 * SMP_CACHE_BYTES,
	      "bulksvc cold state must start the third cache line");
#endif

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

static uint bulksvc_num_sdma = 5;

static uint bulksvc_per_sdma_credits = 392;

/* currently unused, rctx comes with a send context */
static uint bulksvc_num_sctx = 2;

uint bulksvc_user_queue_size_pages_log2 = 4;

static bool roce_by_software = true;

static bool bulksvc_polling_array[32];
static int bulksvc_polling_count;

static int bulksvc_cpu_array[32];
static int bulksvc_cpu_count;

static uint bulksvc_num_lanes = 8;

static uint bulksvc_max_iters_per_work = 100;

static long bulksvc_progress_interval = 1000; /* 1ms */

/*
 * Adaptive halt-poll for event-driven mode, modeled on KVM halt-polling
 * (virt/kvm/kvm_main.c).  Before the worker clears interrupts and sleeps, it
 * spins for an adaptive window watching for the next op.
 */
#define BULKSVC_HALT_POLL_NS_MAX 10000000u /* 10ms hard ceiling */
static uint bulksvc_halt_poll_ns = 100000; /* 100us cap */

static uint bulksvc_rev_sdma_engines = 1024000;

static uint bulksvc_rev_sdma_engines_reps = 8;

static bool bulksvc_diag_access;

/*
 * Worker tuning stats (kworker_* CPU time, halt-poll and reschedule counts,
 * last_nloops) are written on every worker pass into the lane's DMS counter
 * block.  They are only useful when tuning the worker, so they sit behind a
 * static key that compiles to a patched-out branch when off.  Protocol and
 * health counters (tx_sent, rx_received, eager_*) are not gated.
 */
static DEFINE_STATIC_KEY_FALSE(bulksvc_worker_stats_key);

static __maybe_unused int bulksvc_worker_stats_set(const char *val,
				    const struct kernel_param *kp)
{
	bool enable;
	int ret;

	ret = kstrtobool(val, &enable);
	if (ret)
		return ret;
	if (enable)
		static_branch_enable(&bulksvc_worker_stats_key);
	else
		static_branch_disable(&bulksvc_worker_stats_key);
	return 0;
}

static __maybe_unused int bulksvc_worker_stats_get(char *buf, const struct kernel_param *kp)
{
	return sysfs_emit(buf, "%c\n",
			  static_key_enabled(&bulksvc_worker_stats_key) ?
			  'Y' : 'N');
}

static __maybe_unused const struct kernel_param_ops bulksvc_worker_stats_ops = {
	.set = bulksvc_worker_stats_set,
	.get = bulksvc_worker_stats_get,
};

static inline bool bulksvc_worker_stats(void)
{
	return static_branch_unlikely(&bulksvc_worker_stats_key);
}

// copy from chip.c
#define RSM_TYPE_BULKSVC          6

// LRH16B (4 DW) + BTH (3 DW) + KDETH_1 (1 DW)
#define HFI2_DMS_JKEY_OFFSET_LOWER (256)
#define HFI2_DMS_JKEY_OFFSET_UPPER (264)

/*
 * RSM match-field offsets are (QW << 6) | bit.  The L4-type byte of a 16B
 * packet lives at QW1 bit 0 (mirrors L4_TYPE_MATCH_OFFSET in chip.c); the 16B
 * L4=ETH marker is 0x78.  These are chip.c-local there, redeclared here for
 * the RoCE rule the same way the DMS JKEY offsets above are.
 */
#define HFI2_ROCE_RSM_QW_SHIFT	6
#define HFI2_ROCE_RSM_L4_TYPE_OFFSET	((1ull << HFI2_ROCE_RSM_QW_SHIFT) | 0)
#define HFI2_ROCE_RSM_L4_TYPE_MASK	0xFFull
#define HFI2_ROCE_RSM_L4_ETH_VALUE	0x78ull
#define HFI2_ROCE_RSM_EAL_TYPE_MASK	FIELD_MAX(EAL_INGRESS_TYPE_MASK)
#define HFI2_ROCE_RSM_BYPASS_HDR_DWS	4ull
#define HFI2_ROCE_RSM_QPN_LSB_OFFSET	__bf_shf(EAL_INGRESS_ROCE_QP_19_0_MASK)

/*
 * A VRMA-encapsulated frame carries four header qwords where an on-load frame
 * carries two, so it needs its own rule with its own bypass_hdr_size: that
 * field is per rule_index, and it is what splits the EAL header from the
 * payload.  Sizing it per L4 keeps the eager buffer starting at the Ethernet
 * header in both cases, so the ingress parser is identical for both and q2/q3
 * are simply present for VRMA.  Widening the on-load rule's match instead
 * would deliver VRMA frames under a 4-DW split and put q2/q3 at the head of
 * the eager buffer, where the parser would read them as an Ethernet header.
 */
#define HFI2_ROCE_RSM_L4_VRMA_VALUE	0x7Aull
#define HFI2_ROCE_RSM_VRMA_BYPASS_HDR_DWS 8ull

/*
 * RXE presents PacketType 5 to the RSM match unit once
 * RcvIportCtrl.RcvEthRoceV2VrmaEnable promotes an L4=0x7A frame:
 *
 *	else if (q5_bypass_trig_1 | q4_bypass_trig_2)
 *		o_rx_pkt_type_rsm <= 3'd4;
 *	else if (q4_roce_vrma_pkt)
 *		o_rx_pkt_type_rsm <= 3'd5;
 *				(cyr wfr_rxe_rcvdp.sv, "Packet Type to RSM")
 *
 * RcvRsmCfg.PacketType documents 0x5-0x7 as reserved.  The register
 * specification is wrong and the RTL is authoritative - this is a deliberate
 * departure from the documented encoding, not an oversight.  enum rr_type has
 * no type-5 member and gaining one would mean adding an RHF receive type the
 * dispatch tables treat as invalid, so the field is patched in place after
 * add_rsm_rule() has programmed everything else.
 */
#define HFI2_ROCE_RSM_VRMA_PACKET_TYPE	5ull
#define HFI2_ROCE_RSM_PACKET_TYPE_MASK	0x7ull

static void bulksvc_lane_clear_interrupts(struct hfi2_bulksvc_lane *l);
static void bulksvc_roce_disable_vrma_iport(struct hfi2_devdata *dd);
static int bulksvc_roce_check_placement(struct hfi2_devdata *dd);
static void bulksvc_lane_work_eventing(struct work_struct *work);
static void bulksvc_lane_work_polling(struct work_struct *work);
static void bulksvc_schedule_all(struct hfi2_bulksvc *svc);
static void bulksvc_doorbell_wake(struct hfi2_bulksvc *svc);
static void bulksvc_wake_dirty_lanes(struct hfi2_bulksvc *svc);

static_assert(HFI2_BULKSVC_ROCE_UDP_DSTPORT_ENTRY <
	      CYR_EAL_DESTINATION_PORT_TABLE_ENTRIES);
#if HFI2_BULKSVC_ULP_STUBS
static_assert(HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY <
	      CYR_EAL_DESTINATION_PORT_TABLE_ENTRIES);
/*
 * Match context_info bits [13:9] as an RSM field that starts at q0 bit 41:
 * bit 4 is the L4 dest-port table match flag and bits [3:0] are the
 * matching entry index.
 */
#define HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_BIT \
	(EAL_INGRESS_CTXT_INFO_L4_DSTPORT_MATCH_BIT - \
	 EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_BIT)
#define HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_MASK \
	GENMASK(HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_BIT, 0)
#define HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_VALUE \
	(BIT(HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_BIT) | \
	 FIELD_PREP(GENMASK(HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_BIT - 1, 0), \
		    HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY))

static_assert(EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_MASK ==
	      GENMASK_ULL(EAL_INGRESS_CTXT_INFO_L4_DSTPORT_MATCH_BIT - 1,
			  EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_BIT));
static_assert(HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY <=
	      (EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_MASK >>
	       EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_BIT));
#endif

static enum hrtimer_restart bulksvc_progress_timer_callback(struct hrtimer *timer);
static int get_bulksvc_cpu(struct hfi2_devdata *dd);
static bool get_bulksvc_polling(struct hfi2_devdata *dd);

static int bulksvc_loan_sdma(struct hfi2_devdata *dd, u32 start, u32 end)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;
	u32 count = end - start; /* should equal prereqs.num_sdma */
	int ret = 0;

	svc->rsrc.sde_arr = kmalloc(sizeof(*svc->rsrc.sde_arr) * count,
				    GFP_KERNEL);
	if (!svc->rsrc.sde_arr) {
		ret = -ENOMEM;
		goto exit;
	}

	/* transfer references from dd to svc */
	for (int i = 0; i < count; i++)
		svc->rsrc.sde_arr[i] = &dd->per_sdma[start + i];

	dd->rsrcs.last_sdma_engine = start;

exit:
	return ret;
}

static bool hfi2_bulksvc_return_sdma(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;
	u32 ret_count;
	u32 i;

	if (!svc || !svc->rsrc.sde_arr)
		return true;
	if (svc->sdma_quiesce_failed) {
		dd_dev_err(dd, "Bulksvc retaining unquiesced SDMA engine loan\n");
		return false;
	}

	ret_count = svc->prereqs.num_sdma;
	if (!hfi2_bulksvc_is_opa(svc) && !hfi2_bulksvc_primary_dms(svc)->hw_released)
		for (i = 0; i < ret_count; i++)
			hfi2_sdma_engine_restart(svc->rsrc.sde_arr[i]);
	dd->rsrcs.last_sdma_engine += ret_count;
	kfree(svc->rsrc.sde_arr);
	svc->rsrc.sde_arr = NULL;
	return true;
}

/* does not clean up after itself, call hfi2_bulksvc_teardown on non-zero rc */
static int bulksvc_loan_rctxts(struct hfi2_devdata *dd,
		       struct hfi2_bulksvc_pp_rsrc *pp_loan)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_pportdata *ppd;
	struct hfi2_portrsrcs *pr;
	struct hfi2_bulksvc_pp_rsrc *pp_rsrc;
	u32 cnt;
	int i, ret = 0;

	/* store ctxdata pointer for dd->rcd[bulkvc_ctxts] */
	for (i = 0; i < dd->num_pports; i++) {
		ppd = dd->pport + i;
		pr = &dr->ppr[i];
		pp_rsrc = &pp_loan[i];
		cnt = 0;

		pp_rsrc->rcd_len = pr->num_bulksvc_contexts;
		pp_rsrc->rcd = kcalloc(pp_rsrc->rcd_len,
				       sizeof(*pp_rsrc->rcd), GFP_KERNEL);
		if (!pp_rsrc->rcd) {
			ret = -ENOMEM;
			goto bail;
		}

		for (u32 ctxt = pr->first_bulksvc_alloc_ctxt;
		     ctxt < pr->first_dyn_alloc_ctxt; ctxt++) {
			struct hfi2_ctxtdata *rcd;

			/* use hfi2_create_kctxt despite not being a kctxt */
			if (hfi2_create_kctxt(ppd, ctxt, true)) {
				ret = -EFAULT;
				goto bail;
			}

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			/* hfi2_sc_alloc(SC_BULKSVC) already gave rcd->sc a shadow ring. */

			if (msix_bulksvc_request_rcd_irq(rcd)) {
				ret = -EFAULT;
				goto bail;
			}

			/* initialize rcd */
			if (hfi2_create_rcvhdrq(dd, rcd) ||
			    hfi2_setup_eagerbufs(rcd) ||
			    hfi2_kern_exp_rcv_init(rcd, false)) {
				hfi2_rcd_put(rcd);
				ret = -EFAULT;
				goto bail;
			}
			/* enable rcd */
			hfi2_enable_kctxt(dd, rcd);
			pp_rsrc->rcd[cnt++] = rcd;
			hfi2_rcd_put(rcd);
		}
	}

	goto exit;
bail:
	dd_dev_err(dd, "%s:%d:%s() bulksvc: Failed to allocate rcv contexts\n",
		   __FILENAME__, __LINE__, __func__);
	if (ret == 0)
		ret = -1;
	for (; i >= 0; i--) {
		ppd = dd->pport + i;
		pr = &dr->ppr[i];
		pp_rsrc = &pp_loan[i];
		if (!pp_rsrc->rcd)
			continue;
		for (u32 ctxt = pr->first_bulksvc_alloc_ctxt; ctxt <
		     pr->first_dyn_alloc_ctxt; ctxt++) {
			if (!dd->rcd[ctxt])
				continue;
			hfi2_free_ctxt_rcv_groups(dd->rcd[ctxt]);
			hfi2_free_ctxt(dd->rcd[ctxt]);
		}
		kfree(pp_rsrc->rcd);
		pp_rsrc->rcd = NULL;
	}

exit:
	return ret;
}

/** Sets the JKEY for both rcd and send_context as normal, but then marks
  * the send_context's jkey mask to allow both dms jkeys.
  */
static int _set_bulksvc_ctxt_jkey(struct hfi2_devdata *dd, struct hfi2_ctxtdata *rcd, u16 jkey)
{
	hfi2_set_ctxt_jkey(dd, rcd->sc, rcd->ctxt, rcd->flags, jkey);
	// mask is 0xFFFE to allow both DATA and PROTO job keys
	u64 const bulksvc_jkey_mask = (SEND_CTXT_CHECK_JOB_KEY_VALUE_MASK - 1) << SEND_CTXT_CHECK_JOB_KEY_MASK_SHIFT;
	int pidx;
	u16 hw_ctxt;
	u64 reg;

	if (!rcd || !rcd->sc)
		return -EINVAL;

	pidx = rcd->ppd->hw_pidx;
	hw_ctxt = rcd->sc->hw_context;
	reg = bulksvc_jkey_mask |
		((jkey & SEND_CTXT_CHECK_JOB_KEY_VALUE_MASK) <<
		 SEND_CTXT_CHECK_JOB_KEY_VALUE_SHIFT);
	/* JOB_KEY_ALLOW_PERMISSIVE is not allowed by default */
	if (HFI2_CAP_KGET_MASK(rcd->flags, ALLOW_PERM_JKEY))
		reg |= SEND_CTXT_CHECK_JOB_KEY_ALLOW_PERMISSIVE_SMASK;
	write_epsc_csr(dd, pidx, hw_ctxt, dd->params->send_ctxt_check_job_key_reg, reg);

	return 0;
}

irqreturn_t hfi2_bulksvc_doorbell_interrupt(int irq, void *data)
{
	struct hfi2_bulksvc *svc = data;
	bulksvc_doorbell_wake(svc);
	return IRQ_HANDLED;
}

irqreturn_t hfi2_bulksvc_doorbell_interrupt_thr(int irq, void *data)
{
	struct hfi2_bulksvc *svc = data;
	dd_dev_dbg(svc->dd, "DOORBELL!\n");
	bulksvc_doorbell_wake(svc);
	return IRQ_HANDLED;
}

/*
 * A rev pass's DMA source page.  Every submitted batch holds a reference,
 * so a timed-out pass can return while batches are still pending: the page
 * goes back to the pool only when the last of them completes.
 */
struct bulksvc_rev_ctx {
	struct kref ref;
	atomic_t outstanding;
	struct hfi2_dms *dms;
	struct hfi2_dms_page *page;
};

static void bulksvc_rev_ctx_release(struct kref *ref)
{
	struct bulksvc_rev_ctx *ctx =
		container_of(ref, struct bulksvc_rev_ctx, ref);

	hfi2_dms_page_put(ctx->dms, ctx->page);
	kfree(ctx);
}

/* Completion callback for a rev batch: drop its reference. */
static void bulksvc_rev_sdma_engines_done(void *cookie, int status)
{
	struct bulksvc_rev_ctx *ctx = cookie;

	atomic_dec(&ctx->outstanding);
	kref_put(&ctx->ref, bulksvc_rev_ctx_release);
}

/*
 * Rev the SDMA engines to warm the PCIe read path (JKR only).
 *
 * On a cold boot the PCIe root-complex/switch read-completion buffer on the
 * HFI bus-master read path is under-provisioned, capping read bandwidth.
 * Driving concurrent large-MRRS read traffic grows its high-water mark, which
 * then persists across driver reload until the next cold-boot PERST#.
 *
 * Compose one throwaway well-formed packet in a DMS page, tag its PBC with
 * the End-Bad-Packet test bit, raise MRRS to 512, and submit it many times
 * as SDMA read batches (spread round-robin over the engines).  The engines
 * DMA-read the payload with large Memory-Read TLPs -- that read is the prime
 * -- and TXE then drops each packet locally at the egress-integrity stage
 * before it reaches the wire, so nothing is ever transmitted on the fabric.
 * bulksvc is the sole DMS drainer, so we submit then kick it -- never
 * draining concurrently.
 *
 * A completer may send completions up to its own MPS, and a receiver treats
 * any payload above its own MPS as malformed.  So if the upstream MPS is
 * above ours (e.g. root port 512, endpoint 256), raise ours to match for the
 * warm-up; otherwise leave it alone.  Skip on a VF, in a VM, or when no
 * upstream port is visible and our MPS is below 512.
 *
 * If MRRS is already 512 there is nothing to do.  Best-effort and non-fatal:
 * restores the entry MRRS and egress-error mask on every path, and MPS unless
 * MRRS fails to restore.  Returns true only if the pass ran to completion and
 * restored MRRS and MPS.
 */
static bool bulksvc_rev_sdma_engines_once(struct hfi2_devdata *dd)
{
	const int mrrs_hi = 512;	/* transient MRRS for large read TLPs */
	const int hdr_bytes = 40;	/* qword-aligned SDMA cmd header */
	const int payload = 4000;	/* 8-aligned, fits one 4K page */
	const u32 iters_max = 1024000;
	const u32 chunks = 64;		/* batches; keeps the frag alloc small */
	const u32 budget_ms = 5000;	/* init must never hang if engines wedge */
	const u8 ulp_id = 1;		/* any valid ULP id; packet is a throwaway */
	const u32 dlid = 0xFFFFFF;	/* permissive LID; packet is EBP-dropped before egress */
	struct hfi2_dms_sdma_frag *frags;
	struct bulksvc_rev_ctx *ctx;
	struct pci_dev *br;
	struct hfi2_dms *dms;
	enum hfi2_dms_fabric_port_idx port_idx;
	unsigned long deadline;
	u64 egr_mask[LARGEST_NUM_PORTS];
	u32 iters_per_chunk, i;
	int ep_saved, mps_saved, up_mps, hdr_len, ret;
	bool mps_raised = false, egr_masked = false, timed_out = false;
	bool restored, ok = false;
	u8 *img;

	/* off unless requested; DMS present, JKR only, PCIe only */
	if (!bulksvc_rev_sdma_engines)
		return false;
	if (!dd->bulksvc)
		return false;
	if (dd->params->chip_type != CHIP_JKR)
		return false;
	if (!pci_is_pcie(dd->pcidev))
		return false;
	/* VF MPS/MRRS are reserved; a guest's MPS writes may be virtualized */
	if (dd->is_vf || dd->is_vm)
		return false;

	/* already at the target read size: nothing to warm up */
	ep_saved = pcie_get_readrq(dd->pcidev);
	mps_saved = pcie_get_mps(dd->pcidev);
	if (ep_saved == mrrs_hi)
		return false;

	dms = hfi2_bulksvc_primary_dms(dd->bulksvc);
	if (dms->num_engines == 0)
		return false;
	port_idx = HFI2_DMS_MAX_PORTS;
	for (i = 0; i < dd->num_pports; i++) {
		if (dd->pport[i].host_link_state == HLS_UP_ACTIVE) {
			port_idx = i;
			break;
		}
	}
	if (port_idx >= HFI2_DMS_MAX_PORTS || !dms->port_available[port_idx])
		return false;

	iters_per_chunk = max_t(u32, 1,
				min_t(u32, bulksvc_rev_sdma_engines,
				      iters_max) / chunks);

	/* one chunk's worth of SOP+EOP frag pairs, resubmitted per batch */
	frags = kcalloc(iters_per_chunk * 2, sizeof(*frags), GFP_KERNEL);
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (frags && ctx)
		ctx->page = hfi2_dms_page_get(dms);
	if (!frags || !ctx || !ctx->page) {
		dd_dev_warn(dd, "rev_sdma_engines: allocation failed, skipping\n");
		kfree(ctx);
		kfree(frags);
		return false;
	}
	kref_init(&ctx->ref);
	ctx->dms = dms;
	img = ctx->page->mem.kvaddr;

	/*
	 * Build a real command header, then zero-pad it to the qword-aligned
	 * SDMA header length so the descriptor byte sum matches the PBC/LRH
	 * qword length (a bare 36-byte header halts JKR with a length
	 * mismatch).  Mirrors bulksvc_net.c net_pp_build_sdma_header().  One
	 * source page is reused by every packet: the content is a throwaway,
	 * only the resulting Memory-Read train matters.
	 */
	hdr_len = hfi2_dms_ulp_build_pio_header(dms, port_idx, dlid,
						ulp_id, 0, payload, img,
						ctx->page->mem.len);
	if (hdr_len < 0 || hdr_len > hdr_bytes) {
		dd_dev_warn(dd, "rev_sdma_engines: header build failed (%d)\n",
			    hdr_len);
		kref_put(&ctx->ref, bulksvc_rev_ctx_release);
		kfree(frags);
		return false;
	}
	memset(img + hdr_len, 0, hdr_bytes - hdr_len);
	memset(img + hdr_bytes, 0, payload);
	/*
	 * Tag the PBC (the first qword of the packet) End-Bad.  The engine
	 * still DMA-reads the payload -- the prime we want -- but TXE drops
	 * the assembled packet at the egress-integrity stage before the wire.
	 */
	*(u64 *)img |= PBC_TEST_EBP;
	/* tail flit carved from the page's last qword, as net_pp does */
	*(u64 *)(img + PAGE_SIZE - sizeof(u64)) = 0;
	hfi2_dms_page_sync_for_device(dms, ctx->page, 0, PAGE_SIZE);

	/* @iters_per_chunk packets, each a SOP+EOP frag pair */
	for (i = 0; i < iters_per_chunk; i++) {
		frags[i * 2].paddr = ctx->page->mem.phys_addr;
		frags[i * 2].len = hdr_bytes + payload;
		frags[i * 2].type = HFI2_DMS_SDMA_DESC_TYPE_SOP;
		frags[i * 2 + 1].paddr =
			ctx->page->mem.phys_addr + (PAGE_SIZE - sizeof(u64));
		frags[i * 2 + 1].len = sizeof(u64);
		frags[i * 2 + 1].type = HFI2_DMS_SDMA_DESC_TYPE_EOP;
	}

	/*
	 * Only ever raise MPS to the upstream value: above it is malformed too,
	 * and pcie_set_mps() checks only our DevCap.  Bridges are only read.
	 */
	br = pci_upstream_bridge(dd->pcidev);
	if (!br && mps_saved < mrrs_hi) {
		dd_dev_dbg(dd,
			   "rev_sdma_engines: no upstream port to check MPS %d against, skipping\n",
			   mps_saved);
		goto restore;
	}
	up_mps = mrrs_hi;
	for (; br; br = pci_upstream_bridge(br))
		up_mps = min(up_mps, pcie_get_mps(br));
	if (up_mps > mps_saved) {
		dd_dev_dbg(dd,
			   "rev_sdma_engines: MPS %d below upstream %d, raising for warm-up\n",
			   mps_saved, up_mps);
		pcie_set_mps(dd->pcidev, up_mps);
		mps_raised = true;
		if (pcie_get_mps(dd->pcidev) != up_mps) {
			dd_dev_warn(dd,
				    "rev_sdma_engines: MPS raise to %d failed, skipping\n",
				    up_mps);
			goto restore;
		}
	}

	/* raise MRRS to 512 for large read TLPs */
	pcie_set_readrq(dd->pcidev, mrrs_hi);
	if (pcie_get_readrq(dd->pcidev) != mrrs_hi) {
		dd_dev_warn(dd,
			    "rev_sdma_engines: MRRS raise blocked (pci=pcie_bus_perf/no_inc_mrrs?), skipping\n");
		goto restore;
	}

	/*
	 * Every dropped packet raises a per-engine DisallowedPacket egress
	 * error; at ~1M packets that is an interrupt/log storm.  Suppress the
	 * egress-error mask for the warm-up window (bulksvc is the sole
	 * consumer here) and restore it below.
	 */
	for (i = 0; i < dd->num_pports; i++)
		egr_mask[i] = read_eport_csr(dd, i,
					     dd->params->send_egress_err_mask_reg);
	for (i = 0; i < dd->num_pports; i++)
		write_eport_csr(dd, i, dd->params->send_egress_err_mask_reg, 0);
	egr_masked = true;

	/* submit the batches, kick bulksvc (the sole drainer), wait */
	deadline = jiffies + msecs_to_jiffies(budget_ms);
	for (i = 0; i < chunks; i++) {
		kref_get(&ctx->ref);
		atomic_inc(&ctx->outstanding);
		ret = hfi2_dms_sdma_frag_submit(dms, i % dms->num_engines,
						(u8)port_idx, frags,
						iters_per_chunk * 2,
						bulksvc_rev_sdma_engines_done,
						ctx);
		if (ret) {
			/* @done is not called on a failed submit */
			atomic_dec(&ctx->outstanding);
			kref_put(&ctx->ref, bulksvc_rev_ctx_release);
			dd_dev_warn(dd,
				    "rev_sdma_engines: submit %u failed (%d)\n",
				    i, ret);
			break;
		}
	}
	while (atomic_read(&ctx->outstanding) != 0) {
		/*
		 * The rev owns DMS while quiesced, so schedule() is a no-op
		 * (stop_scheduling is set): run one full DMS poll pass directly,
		 * exactly as the bulksvc worker would.  A bare drain is not
		 * enough -- the poll also refreshes engine heads, reclaims AHG,
		 * and services the engine waitlists that the batches wait on.
		 * Each completion runs bulksvc_rev_sdma_engines_done() on this
		 * thread, dropping @outstanding.
		 */
		hfi2_dms_poll(dms, ktime_get());
		if (time_after(jiffies, deadline)) {
			timed_out = true;
			dd_dev_warn(dd,
				    "rev_sdma_engines: budget expired (outstanding=%d)\n",
				    atomic_read(&ctx->outstanding));
			break;
		}
		usleep_range(20, 60);
	}
	ok = !timed_out && i == chunks;

restore:
	/*
	 * MRRS first so no new large reads issue.  Lower MPS only once MRRS is
	 * back: MRRS 512 with MPS 256 is the very mismatch we are avoiding.
	 * MPS is restored even on a timeout, with some reads possibly still
	 * pending.
	 */
	pcie_set_readrq(dd->pcidev, ep_saved);
	if (mps_raised && pcie_get_readrq(dd->pcidev) != ep_saved)
		dd_dev_warn(dd,
			    "rev_sdma_engines: MRRS restore failed, leaving MPS at %d\n",
			    pcie_get_mps(dd->pcidev));
	else if (mps_raised)
		pcie_set_mps(dd->pcidev, mps_saved);

	if (egr_masked) {
		for (i = 0; i < dd->num_pports; i++) {
			write_eport_csr(dd, i,
					dd->params->send_egress_err_clear_reg,
					~0ull);
			write_eport_csr(dd, i,
					dd->params->send_egress_err_mask_reg,
					egr_mask[i]);
		}
	}

	kref_put(&ctx->ref, bulksvc_rev_ctx_release);
	kfree(frags);

	restored = pcie_get_readrq(dd->pcidev) == ep_saved &&
		   pcie_get_mps(dd->pcidev) == mps_saved;
	if (!restored)
		dd_dev_warn(dd,
			    "rev_sdma_engines: restore failed (mrrs=%d mps=%d, want %d/%d)\n",
			    pcie_get_readrq(dd->pcidev),
			    pcie_get_mps(dd->pcidev), ep_saved, mps_saved);
	dd_dev_dbg(dd,
		   "rev_sdma_engines: packets=%u chunks=%d bytes~=%u mrrs=%d mps=%d%s restored=%c%s\n",
		   iters_per_chunk * chunks, chunks,
		   iters_per_chunk * chunks * (hdr_bytes + payload),
		   ep_saved, mps_saved, mps_raised ? "(raised)" : "",
		   restored ? 'Y' : 'N', timed_out ? " (timed out)" : "");

	return ok && restored;
}

/*
 * Replay the warm-up; each pass restores MRRS and MPS, and the count is
 * capped.  Stop at the first pass that does not complete or restore.
 */
static void bulksvc_rev_sdma_engines_run(struct hfi2_devdata *dd)
{
	u32 reps = clamp_t(u32, bulksvc_rev_sdma_engines_reps, 1, 16);
	u32 i;

	if (!bulksvc_rev_sdma_engines)
		return;

	for (i = 0; i < reps; i++)
		if (!bulksvc_rev_sdma_engines_once(dd))
			break;
}

/*
 * Quiesce bulksvc so the rev is the sole consumer of the lock-free DMS batch
 * lists (stop_scheduling gates the lane workers; the progress timer and any
 * live lane work are stopped), run the warm-up, then resume.  Deferred to
 * dd->hfi2_wq so cancel_work_sync() cannot self-deadlock.
 */
static void bulksvc_rev_work_fn(struct work_struct *work)
{
	struct hfi2_bulksvc *svc = container_of(work, struct hfi2_bulksvc,
						rev_work);
	struct hfi2_devdata *dd = svc->dd;
	u32 k;

	svc->stop_scheduling = true;
	if (svc->timer_interval > 0)
		hrtimer_cancel(&svc->progress_timer);
	for (k = 0; k < svc->num_lanes; k++)
		cancel_work_sync(&svc->lanes[k].work);

	bulksvc_rev_sdma_engines_run(dd);

	svc->stop_scheduling = false;
	for (k = 0; k < svc->num_lanes; k++)
		bulksvc_lane_clear_interrupts(&svc->lanes[k]);
	if (svc->timer_interval > 0)
		hrtimer_start(&svc->progress_timer, svc->timer_interval,
			      HRTIMER_MODE_REL);
	bulksvc_schedule_all(svc);
}

/*
 * Called both when bulksvc is loaned and when the fabric link goes ACTIVE.
 * When both are true (and JKR + enabled), run the warm-up once via rev_work.
 * event_workq is set only while loaned; host_link_state gives live link state.
 */
void hfi2_bulksvc_rev_maybe_fire(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;
	bool link_active = false;
	int i;

	if (!svc || svc->rev_done)
		return;
	if (!bulksvc_rev_sdma_engines || dd->params->chip_type != CHIP_JKR)
		return;
	if (!svc->event_workq)
		return;
	for (i = 0; i < dd->num_pports; i++) {
		if (dd->pport[i].host_link_state == HLS_UP_ACTIVE) {
			link_active = true;
			if (dd->pport[svc->port_lut[0]].host_link_state != HLS_UP_ACTIVE)
				svc->port_lut[0] = i;
			break;
		}
	}
	if (!link_active)
		return;

	svc->rev_done = true;
	queue_work(dd->hfi2_wq, &svc->rev_work);
}

/*
 * Free every lane's DMS and the SDMA engine share; the lanes must be
 * stopped and uninitialized.
 */
static void bulksvc_lanes_free(struct hfi2_bulksvc *svc)
{
	for (u32 k = 0; k < svc->num_lanes; k++)
		kfree(svc->lanes[k].dms);
	kfree(svc->sde_share);
}

/*
 * Set up the DMS lanes before chip init sizes the receive contexts and
 * reserves the RSM rules.  Lanes > 1 are not supported on a CN6000
 * Ethernet-mode (RoCE) PF: the RoCE bypass rule carries no job key to steer
 * on.  Every lane's DMS is allocated here, so IRQ-path readers
 * (bulksvc_sdma_irq(), the RoCE backend) always see a valid DMS until
 * hfi2_bulksvc_teardown() frees it after every worker and IRQ is stopped.
 */
static int bulksvc_lanes_setup(struct hfi2_bulksvc *svc, bool polling)
{
	struct hfi2_devdata *dd = svc->dd;
	u32 lanes = clamp_t(u32, bulksvc_num_lanes, 1, HFI2_BULKSVC_MAX_LANES);

	if (lanes != bulksvc_num_lanes)
		dd_dev_warn(dd, "bulksvc_num_lanes %u out of range, using %u\n",
			    bulksvc_num_lanes, lanes);
	if (lanes > 1 && hfi2_is_eth_mode(dd)) {
		dd_dev_warn(dd, "bulksvc_num_lanes %u not supported in Ethernet mode, using 1\n",
			    lanes);
		lanes = 1;
	}
	svc->num_lanes = lanes;

	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_bulksvc_lane *l = &svc->lanes[k];

		l->svc = svc;
		l->idx = k;
		INIT_WORK(&l->work, polling ? bulksvc_lane_work_polling :
					      bulksvc_lane_work_eventing);
		mpsc_init(&l->rdma_cmds.mpsc);
		atomic_set(&l->rdma_cmds.depth, 0);
		/*
		 * The primary lane drains the verbs cmd queue: MR reg/dereg
		 * and the rdmavt RDMA cmds of its QPs share one FIFO, so a
		 * post after MR_REG sees the registration.
		 */
		l->cmdq = bulksvc_lane_is_primary(l) ? &svc->verbs_state.cmd_queue :
						    &l->rdma_cmds;
		mpsc_init(&l->mr_ops);
		INIT_LIST_HEAD(&l->mr_replicas);
		spin_lock_init(&l->event_lock);
		INIT_LIST_HEAD(&l->event_queue);
		INIT_LIST_HEAD(&l->pins.pin_speculative);
		INIT_LIST_HEAD(&l->pins.pin_active);
		l->dms = kzalloc_node(sizeof(*l->dms), GFP_KERNEL, dd->node);
		if (!l->dms) {
			bulksvc_lanes_free(svc);
			return -ENOMEM;
		}
		if (WARN_ON(!IS_ALIGNED((uintptr_t)l->dms,
					__alignof__(struct hfi2_dms)))) {
			bulksvc_lanes_free(svc);
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * Pick each lane's CPU, NUMA local and disjoint across HFI units: unit d's
 * lane k takes the (d * num_lanes + k)-th last CPU of the device's node.  With
 * one lane that is the (d)-th last CPU.  A bulksvc_cpu override replaces lane
 * 0's CPU.  The lane's worker and its receive context IRQs run there.
 */
static void bulksvc_pick_lane_cpus(struct hfi2_bulksvc *svc, int override_cpu)
{
	struct hfi2_devdata *dd = svc->dd;
	const struct cpumask *mask = cpumask_of_node(dd->node);
	bool wrapped = false;
	unsigned int n, base;

	if (cpumask_empty(mask))
		mask = cpu_online_mask;
	n = cpumask_weight(mask);
	base = ((unsigned int)dd->unit * svc->num_lanes) % n;

	for (u32 k = 0; k < svc->num_lanes; k++) {
		unsigned int slot = base + k;

		if (slot >= n) {
			wrapped = true;
			slot %= n;
		}
		svc->lanes[k].cpu = cpumask_nth(n - 1 - slot, mask);
	}
	if (wrapped)
		dd_dev_warn(dd, "bulksvc: %u lanes of unit %d exceed the %u CPUs of node %d; lanes share CPUs\n",
			    svc->num_lanes, dd->unit, n, dd->node);

	if (override_cpu != -1) {
		if (!cpumask_test_cpu(override_cpu, cpumask_of_node(dd->node)))
			dd_dev_warn(dd, "module param bulksvc_cpu (%d) is not on the device's numa node (%d). Performance will be affected\n",
				    override_cpu, dd->node);
		svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].cpu = override_cpu;
		for (u32 k = 0; k < svc->num_lanes; k++)
			if (!bulksvc_lane_is_primary(&svc->lanes[k]) &&
			    svc->lanes[k].cpu == override_cpu)
				dd_dev_warn(dd, "module param bulksvc_cpu (%d) is also the CPU of lane %u; the lanes share it\n",
					    override_cpu, k);
	}

	for (u32 k = 0; k < svc->num_lanes; k++)
		dd_dev_info(dd, "Bulksvc configured to run on CPU %d (lane %u)\n",
			    svc->lanes[k].cpu, k);
}

/* Lane k owns bulksvc receive contexts rcd[2k] and rcd[2k + 1] of each port */
static u32 bulksvc_rcd_lane(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_devdata *dd = rcd->dd;
	struct hfi2_portrsrcs *pr = &dd->rsrcs.ppr[rcd->ppd->hw_pidx];
	u32 lane = (rcd->ctxt - pr->first_bulksvc_alloc_ctxt) / 2;

#if HFI2_BULKSVC_ULP_STUBS
	if (!hfi2_bulksvc_is_opa(dd->bulksvc) &&
	    rcd->ctxt - pr->first_bulksvc_alloc_ctxt == HFI2_BULKSVC_EAL_RCD_IDX)
		return HFI2_BULKSVC_PRIMARY_LANE;
#endif
	if (WARN_ON_ONCE(lane >= dd->bulksvc->num_lanes))
		lane = HFI2_BULKSVC_PRIMARY_LANE;
	return lane;
}

/*
 * CPU for the IRQ of bulksvc receive context @rcd: the owning lane's CPU.
 * Otherwise the IRQs would share the kernel receive-context CPUs and, in
 * event mode, delay verbs RC receive into retransmit timeouts.
 */
int hfi2_bulksvc_rcd_irq_cpu(struct hfi2_ctxtdata *rcd)
{
	return rcd->dd->bulksvc->lanes[bulksvc_rcd_lane(rcd)].cpu;
}

/*
 * Receive IRQ of bulksvc receive context @rcd, hard IRQ context.  Only the
 * owning lane's worker drains the context, so wake it and leave the
 * interrupt status set: the chip raises no further IRQ for @rcd until the
 * worker clears it before sleeping, which re-raises it if a packet arrived
 * meanwhile.  OPA: bulksvc_lane_clear_interrupts(); RoCE: the explicit
 * hfi2_rcd_eoi_intr() of rcd[0]/rcd[1] in bulksvc_lane_work_eventing().
 * Clearing or forcing it here would let the IRQ re-fire on its own CPU
 * ahead of the worker forever.
 */
void hfi2_bulksvc_rcd_wake(struct hfi2_ctxtdata *rcd)
{
	hfi2_bulksvc_schedule_lane(rcd->dd->bulksvc, bulksvc_rcd_lane(rcd));
}

/*
 * Every lane places on all loaned SDMA engines.  A lane may serve a single
 * process, so splitting the engines would cap it at num_sdma / lanes
 * engines; with lanes > 1 the ring accesses are serialized per engine
 * instead (svc->sde_share, see struct hfi2_dms_sde_share).  One lane owns
 * its engines and takes no lock.
 */
static int bulksvc_lanes_share_sdma(struct hfi2_bulksvc *svc, u32 num_sdma)
{
	struct sdma_engine **sde = svc->rsrc.sde_arr;

	if (svc->num_lanes == 1)
		return 0;

	svc->sde_share = kcalloc_node(num_sdma, sizeof(*svc->sde_share),
				      GFP_KERNEL, svc->dd->node);
	if (!svc->sde_share)
		return -ENOMEM;
	for (u32 i = 0; i < num_sdma; i++) {
		spin_lock_init(&svc->sde_share[i].lock);
		/* like the completion FIFO seed: seq - inflight >= 0 */
		svc->sde_share[i].seq = sde[i]->descq_cnt;
	}
	return 0;
}

/*
 * num_lanes rows of max_clients bits (one bit per client per lane), indexed
 * like the dirty-notify bitmap; row k is lanes[k].client_bits.  A client's
 * bit is set only in the row of the lane it is bound to, and that lane is
 * the only one polling it.
 */
static int bulksvc_lanes_client_bits_alloc(struct hfi2_bulksvc *svc)
{
	unsigned int const nlongs = BITS_TO_LONGS(svc->dirty_notify.max_clients);

	svc->lane_client_bits =
		bitmap_zalloc_node(nlongs * BITS_PER_LONG * svc->num_lanes,
				   GFP_KERNEL, svc->dd->node);
	if (!svc->lane_client_bits)
		return -ENOMEM;
	for (u32 k = 0; k < svc->num_lanes; k++)
		svc->lanes[k].client_bits = svc->lane_client_bits + k * nlongs;
	return 0;
}

int hfi2_bulksvc_loan_resources(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;
	u32 last = dd->rsrcs.last_sdma_engine;
	u32 sdma_avail = last - dd->rsrcs.first_sdma_engine;
	bool bulksvc_polling = get_bulksvc_polling(dd);
	unsigned int wq_flags;
	u32 sdma_rm;
	int ret = 0;
	int nr;

	/* Clamp to 1 to prevent kworker progress stall at value 0 */
	if (bulksvc_max_iters_per_work == 0) {
		dd_dev_warn(dd,
			    "bulksvc_max_iters_per_work clamped to 1 (was 0)\n");
		bulksvc_max_iters_per_work = 1;
	}

	/*
	 * Clamp the halt-poll spin budget to a sane ceiling.  This is a busy
	 * spin (cpu_relax(), no cond_resched()) on a WQ_CPU_INTENSIVE /
	 * WQ_HIGHPRI kworker, so an unbounded value would burn a full CPU on
	 * every idle wake with the only visible signal being bulksvc_dbg.
	 */
	if (bulksvc_halt_poll_ns > BULKSVC_HALT_POLL_NS_MAX) {
		dd_dev_warn(dd,
			    "bulksvc_halt_poll_ns clamped to %u (was %u)\n",
			    BULKSVC_HALT_POLL_NS_MAX, bulksvc_halt_poll_ns);
		bulksvc_halt_poll_ns = BULKSVC_HALT_POLL_NS_MAX;
	}

	if (!svc) {
		ret = -1;
		goto exit;
	}

	if (!hfi2_bulksvc_is_opa(svc) &&
	    svc->backend != HFI2_BULKSVC_BACKEND_ETH_ROCE) {
		ret = -EINVAL;
		goto fail;
	}

	sdma_rm = svc->prereqs.num_sdma;
	if (!sdma_rm || sdma_rm > sdma_avail ||
	    (hfi2_bulksvc_is_opa(svc) && sdma_avail - sdma_rm < hfi2_num_vls)) {
		dd_dev_err(dd, "%s:%d:%s() Not enough sdma engines(%u) to cover VLs(%u) and enable hfisvc (%u)\n",
			   __FILENAME__, __LINE__, __func__,
			   sdma_avail, hfi2_num_vls, sdma_rm);
		ret = -EINVAL;
		goto fail;
	}
	if (bulksvc_loan_sdma(dd, last - sdma_rm, last)) {
		ret = -EFAULT;
		goto fail;
	}

	/* allocate per port resources structure */
	svc->rsrc.pp = kcalloc(dd->num_pports, sizeof(*svc->rsrc.pp),
			       GFP_KERNEL);
	if (!svc->rsrc.pp) {
		ret = -ENOMEM;
		goto fail;
	}

	if (bulksvc_loan_rctxts(dd, svc->rsrc.pp)) {
		ret = -EFAULT;
		goto fail;
	}

	if (!hfi2_bulksvc_is_opa(svc) &&
	    (dd->num_pports <= HFI2_PORT_IDX ||
	     svc->rsrc.pp[HFI2_PORT_IDX].rcd_len < HFI2_DMS_ROCE_RCD_COUNT ||
	     !svc->rsrc.pp[HFI2_PORT_IDX].rcd[0] ||
	     !svc->rsrc.pp[HFI2_PORT_IDX].rcd[1] ||
	     !svc->rsrc.pp[HFI2_PORT_IDX].rcd[1]->sc)) {
		ret = -ENOSPC;
		goto fail;
	}
#if HFI2_BULKSVC_ULP_STUBS
	if (!hfi2_bulksvc_is_opa(svc) &&
	    (svc->rsrc.pp[HFI2_PORT_IDX].rcd_len <= HFI2_BULKSVC_EAL_RCD_IDX ||
	     !svc->rsrc.pp[HFI2_PORT_IDX].rcd[HFI2_BULKSVC_EAL_RCD_IDX])) {
		dd_dev_err(dd, "Bulksvc: missing EAL receive context (rcd_len %u, EAL rcd index %u: %s)\n",
			   svc->rsrc.pp[HFI2_PORT_IDX].rcd_len,
			   (unsigned int)HFI2_BULKSVC_EAL_RCD_IDX,
			   svc->rsrc.pp[HFI2_PORT_IDX].rcd_len <= HFI2_BULKSVC_EAL_RCD_IDX ?
			   "rcd_len too small" : "rcd pointer NULL");
		ret = -ENOSPC;
		goto fail;
	}
#endif

	if (hfi2_bulksvc_is_opa(svc)) {
		for (s32 i = 0; i < dd->num_pports; i++) {
			if (!port_available_ppd(&dd->pport[i]))
				continue;

			if (unlikely(svc->rsrc.pp[i].rcd_len < 2 * svc->num_lanes)) {
				dd_dev_err(dd,
					   "%s:%d:%s() svc->rsrc.ppi[%d].rcd_len=%u < %u\n",
					   __FILENAME__, __LINE__, __func__, i,
					   svc->rsrc.pp[i].rcd_len, 2 * svc->num_lanes);
				ret = -EINVAL;
				goto fail;
			}

			/* lane k: rcd[2k] ctrl, rcd[2k + 1] data */
			for (u32 j = 0; j < 2 * svc->num_lanes; j++) {
				u16 const jkey = j & 1 ? HFI2_DMS_DATA_JKEY :
							 HFI2_DMS_CTRL_JKEY;

				dd_dev_dbg(dd, "%s:%d:%s() bulksvc: Setting JKEY %u for rctxt %u on port %u\n",
					   __FILENAME__, __LINE__, __func__, jkey,
					   svc->rsrc.pp[i].rcd[j]->ctxt, i);
				_set_bulksvc_ctxt_jkey(dd, svc->rsrc.pp[i].rcd[j],
						       jkey);
			}
		}

		ret = bulksvc_lanes_share_sdma(svc, sdma_rm);
		if (ret)
			goto fail;

		for (u32 k = 0; k < svc->num_lanes; k++) {
			struct hfi2_bulksvc_lane *l = &svc->lanes[k];

			if (hfi2_dms_init(l->dms, dd, svc->rsrc.pp,
					  dd->num_pports, svc->rsrc.sde_arr,
					  sdma_rm, k)) {
				ret = -EFAULT;
				goto fail;
			}
			/* hfi2_dms_init() zeroed the DMS and placed no descriptors */
			l->dms->sde_share = svc->sde_share;
			l->dms_up = true;
		}
	} else {
		struct hfi2_ctxtdata **rcd = svc->rsrc.pp[HFI2_PORT_IDX].rcd;
		struct send_context *sc = rcd[1]->sc;

		ret = hfi2_dms_common_init(hfi2_bulksvc_primary_dms(svc), dd,
					   svc->rsrc.sde_arr, sdma_rm,
					   HFI2_PORT_IDX, sc);
		if (ret)
			goto fail;

		ret = hfi2_dms_roce_init(svc, rcd, sc);
		if (ret)
			goto fail;
#if HFI2_BULKSVC_ULP_STUBS
		/* The RoCE backend owns both of its RCDs; EAL needs a private ring. */
		hfi2_dms_eal_init_rcd(hfi2_bulksvc_primary_dms(svc),
				      rcd[HFI2_BULKSVC_EAL_RCD_IDX], HFI2_PORT_IDX);
#endif
	}

	ret = bulksvc_rsm_init(svc);
	if (ret)
		goto fail;

	if (!hfi2_bulksvc_is_opa(svc) && svc->dms_roce)
		hfi2_dms_roce_hwp_pool_start(svc->dms_roce);

	if (hfi2_bulksvc_is_opa(svc)) {
		for (u32 k = 0; k < svc->num_lanes; k++) {
			ret = hfi2_bulksvc_verbs_dms_reg_client_id(svc->lanes[k].dms);
			if (ret) {
				dd_dev_err(dd, "Bulksvc: lane %u verbs client key failed %d\n",
					   k, ret);
				goto fail;
			}
		}
	}

	hfi2_bulksvc_ipoib_init(svc);

#if HFI2_BULKSVC_ULP_STUBS
	/*
	 * Register the DMS ULP stub peers.  Failures are non-fatal to bulksvc:
	 * the scaffold is optional and must never block bringup.  The RoCE,
	 * UET and net stubs are OPA-only; eal_test is Ethernet-only.
	 */
	if (hfi2_bulksvc_is_opa(svc)) {
		if (hfi2_bulksvc_roce_init(svc))
			dd_dev_warn(dd, "Bulksvc: roce ULP stub init failed\n");
		if (hfi2_bulksvc_uet_init(svc))
			dd_dev_warn(dd, "Bulksvc: uet ULP stub init failed\n");
		if (hfi2_bulksvc_net_init(svc))
			dd_dev_warn(dd, "Bulksvc: net ULP stub init failed\n");
	}
	if (!hfi2_bulksvc_is_opa(svc)) {
		if (hfi2_bulksvc_eal_test_port_valid(svc)) {
			if (hfi2_bulksvc_eal_test_init(svc)) {
				dd_dev_warn(dd, "Bulksvc: eal_test ULP init failed\n");
				hfi2_bulksvc_eal_test_clear_dstport(svc);
			}
		} else {
			dd_dev_info(dd, "Bulksvc: eal_test ULP not registered: invalid port or no eth RSM steering rule available\n");
		}
	}
#endif

	svc->doorbell_msix_intr = CCE_NUM_MSIX_VECTORS;
	if (hfi2_bulksvc_is_opa(svc)) {
		nr = msix_request_doorbell_irq(dd);
		if (nr < 0)
			dd_dev_warn(dd, "Bulksvc: could not allocate msix vector for doorbell, using general handler\n");
		else
			svc->doorbell_irq_allocated = true;
	}

	/*
	 * setup polling event queue.  Event mode with lanes > 1 stays bound,
	 * so each lane's worker runs on its own CPU (an unbound worker
	 * floats within the node and lanes would pile onto each other).
	 */
	wq_flags = WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE;
	if (!bulksvc_polling)
		wq_flags |= WQ_HIGHPRI | WQ_SYSFS |
			    (svc->num_lanes == 1 ? WQ_UNBOUND : HFI_RVT_WQ_PERCPU);

	/* one work item per lane, each one non-reentrant */
	svc->event_workq = alloc_workqueue("hfi%d-bulksvc-event",
					   wq_flags, svc->num_lanes, dd->unit);
	if (!svc->event_workq) {
		ret = -ENOMEM;
		goto fail;
	}

	if (bulksvc_polling) {
		pr_info("Bulksvc configured to poll\n");
	} else {
		for (u32 k = 0; k < svc->num_lanes; k++)
			if (svc->lanes[k].dms->common_initialized)
				bulksvc_lane_clear_interrupts(&svc->lanes[k]);
		pr_info("Bulksvc configured to be event driven\n");
	}

	if (bulksvc_polling) {
		for (u32 k = 0; k < svc->num_lanes; k++)
			queue_work_on(svc->lanes[k].cpu, svc->event_workq,
				      &svc->lanes[k].work);
	} else if (svc->timer_interval > 0) {
		hrtimer_start(&svc->progress_timer, svc->timer_interval, HRTIMER_MODE_REL);
	}
	pr_debug("%s:%d:%s() LOANED RESOURCES\n", __FILENAME__, __LINE__, __func__);

	/* bulksvc is up; rev now if the link is already ACTIVE. */
	hfi2_bulksvc_rev_maybe_fire(dd);

	goto exit;

fail:
	hfi2_bulksvc_teardown(dd);
	if (ret == 0)
		ret = -1;
exit:
	return ret;
}

int hfi2_bulksvc_init(struct hfi2_devdata *dd)
{
	bool bulksvc_polling = get_bulksvc_polling(dd);
	struct hfi2_bulksvc_requirements *reqs;
	int bulksvc_cpu = get_bulksvc_cpu(dd);
	int ret = 0;

	/*
	 * bulksvc runs on loaned SDMA engines; init_one() would only find
	 * that none were requested after the device and its Ethernet netdev
	 * are live.  Refuse here, before anything is registered.
	 */
	if (!bulksvc_num_sdma) {
		dd_dev_err(dd, "bulksvc_num_sdma=0: bulksvc needs at least one SDMA engine\n");
		return -EINVAL;
	}

	/*
	 * The bulksvc PIO ring is written through a mirrored mapping made
	 * with vmap_pfn() over whole pages.  Kconfig selects VMAP_PFN for
	 * in-tree builds; an out-of-tree build against a kernel without it,
	 * or a kernel whose pages are larger than the ring (ARM64 16/64 KiB),
	 * runs without bulksvc.
	 */
	if (!IS_ENABLED(CONFIG_VMAP_PFN)) {
		dd_dev_info(dd, "kernel built without CONFIG_VMAP_PFN; bulksvc disabled\n");
		return 0;
	}
	if ((SCS_BULKSVC_CREDITS * PIO_BLOCK_SIZE) % PAGE_SIZE) {
		dd_dev_info(dd, "bulksvc PIO ring is not a whole number of %lu-byte pages; bulksvc disabled\n",
			    PAGE_SIZE);
		return 0;
	}

	if (hfi2_is_eth_mode(dd) &&
	    !IS_ENABLED(CONFIG_INFINIBAND_HFI2_ROCE)) {
		dd_dev_info(dd, "RoCE support not built (CONFIG_INFINIBAND_HFI2_ROCE=n); Ethernet only\n");
		return 0;
	}

	dd->bulksvc = kcalloc(1, sizeof(*dd->bulksvc), GFP_KERNEL);
	if (!dd->bulksvc) {
		ret = -ENOMEM;
		return ret;
	}

	dd->verbs_dev.rdi.use_bulksvc = false;
	dd->bulksvc->dd = dd;
	dd->bulksvc->backend = hfi2_is_eth_mode(dd) ?
		HFI2_BULKSVC_BACKEND_ETH_ROCE : HFI2_BULKSVC_BACKEND_OPA_DMS;
	dd->bulksvc->roce_by_software = roce_by_software;
	if (hfi2_is_eth_mode(dd)) {
		ret = bulksvc_roce_check_placement(dd);
		if (!ret)
			ret = hfi2_roce_kmr_placement_init(dd);
		if (ret) {
			kfree(dd->bulksvc);
			dd->bulksvc = NULL;
			return ret;
		}
	}
	ret = bulksvc_lanes_setup(dd->bulksvc, bulksvc_polling);
	if (ret) {
		hfi2_roce_kmr_donor_exit(dd);
		kfree(dd->bulksvc);
		dd->bulksvc = NULL;
		return ret;
	}
	init_completion(&dd->bulksvc->worker_exited_done);
	complete_all(&dd->bulksvc->worker_exited_done);
	init_waitqueue_head(&dd->bulksvc->lane_reps_wq);
	dd->bulksvc->first_rsm_rule = -1;
	dd->bulksvc->vrma_rsm_rule = -1;
	dd->bulksvc->first_rsm_index = -1;
#if HFI2_BULKSVC_ULP_STUBS
	dd->bulksvc->eth_rsm_rule = -1;
	dd->bulksvc->eth_rsm_index = -1;
#endif
	INIT_WORK(&dd->bulksvc->rev_work, bulksvc_rev_work_fn);
	reqs = &dd->bulksvc->prereqs;
	reqs->num_sdma = bulksvc_num_sdma;
	reqs->credits_per_sdma = bulksvc_per_sdma_credits & ~1;
	/* OPA: a ctrl and a data receive context per DMS lane */
	reqs->num_rcv_ctxs = hfi2_bulksvc_is_opa(dd->bulksvc) ?
		2 * dd->bulksvc->num_lanes : HFI2_DMS_ROCE_RCD_COUNT;
#if HFI2_BULKSVC_ULP_STUBS
	if (!hfi2_bulksvc_is_opa(dd->bulksvc))
		reqs->num_rcv_ctxs++;
#endif
	reqs->num_send_ctxs = bulksvc_num_sctx;
	if (hfi2_bulksvc_is_opa(dd->bulksvc) &&
	    (bulksvc_per_sdma_credits >= chip_sdma_mem_size(dd) /
					SDMA_BLOCK_SIZE ||
	     reqs->num_rcv_ctxs >= chip_rcv_contexts(dd))) {
		bulksvc_lanes_free(dd->bulksvc);
		kfree(dd->bulksvc);
		dd->bulksvc = NULL;
		return -EINVAL;
	}

	bulksvc_pick_lane_cpus(dd->bulksvc, bulksvc_cpu);

	/* From here on, failures goto err_teardown so partially-set-up
	 * resources are released rather than leaked by a bare kfree(svc).
	 */

	if (bulksvc_progress_interval > 0 && !bulksvc_polling) {
		dd->bulksvc->timer_interval = ns_to_ktime(bulksvc_progress_interval * NSEC_PER_USEC);
		hrtimer_setup(&dd->bulksvc->progress_timer,
				      bulksvc_progress_timer_callback,
				      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	}

	dd->bulksvc->stop_scheduling = false;
	WRITE_ONCE(dd->bulksvc->worker_exited, false);

	dd->bulksvc->mr_unmap_wq =
		alloc_workqueue("hfi%d-bts-mr-unmap",
				WQ_UNBOUND | WQ_MEM_RECLAIM, 0, dd->unit);
	if (!dd->bulksvc->mr_unmap_wq) {
		ret = -ENOMEM;
		goto err_teardown;
	}

	if (!hfi2_bulksvc_is_opa(dd->bulksvc))
		return 0;

	mutex_init(&dd->bulksvc->user_info_lock);
	INIT_LIST_HEAD(&dd->bulksvc->user_infos);
	atomic_set(&dd->bulksvc->pending_user_info_destroys, 0);
	init_waitqueue_head(&dd->bulksvc->pending_user_info_destroys_wq);
	dd->bulksvc->user_state_initialized = true;

	/* Must precede any err_teardown: the drain mpsc_dequeue()s this
	 * queue, which derefs a NULL tail if left uninitialised.
	 */
	hfi2_bulksvc_verbs_state_init(&dd->bulksvc->verbs_state);
	dd->bulksvc->verbs_state_initialized = true;

	/*
	 * Allocate the dirty bitmap page shared with userspace.
	 * Each client gets one bit; a single page supports up to
	 * PAGE_SIZE * 8 clients (32768 on 4K pages).  Client init
	 * fails with -ENOSPC if the bitmap is full.
	 */
	dd->bulksvc->dirty_notify.page = alloc_pages_node(dd->node,
							   GFP_KERNEL | __GFP_ZERO,
							   0);
	if (!dd->bulksvc->dirty_notify.page) {
		ret = -ENOMEM;
		goto err_teardown;
	}
	dd->bulksvc->dirty_notify.bitmap = page_address(dd->bulksvc->dirty_notify.page);
	dd->bulksvc->dirty_notify.max_clients = PAGE_SIZE * BITS_PER_BYTE;
	dd->bulksvc->dirty_notify.allocated = bitmap_zalloc_node(dd->bulksvc->dirty_notify.max_clients,
							      GFP_KERNEL, dd->node);
	if (!dd->bulksvc->dirty_notify.allocated) {
		ret = -ENOMEM;
		goto err_teardown;
	}
	dd->bulksvc->dirty_notify.client_map = kcalloc_node(dd->bulksvc->dirty_notify.max_clients,
							    sizeof(struct hfi2_bulksvc_user_info *),
							    GFP_KERNEL, dd->node);
	if (!dd->bulksvc->dirty_notify.client_map) {
		ret = -ENOMEM;
		goto err_teardown;
	}
	if (bulksvc_lanes_client_bits_alloc(dd->bulksvc)) {
		ret = -ENOMEM;
		goto err_teardown;
	}

	/* Must precede any path that can produce a cmd/cmpl. */
	if (hfi2_bulksvc_verbs_caches_init(dd->bulksvc)) {
		ret = -ENOMEM;
		goto err_teardown;
	}
	dd->bulksvc->verbs_caches_initialized = true;

	dd->verbs_dev.rdi.use_bulksvc = true;

	atomic_set(&dd->bulksvc->last_client_key, 0);

	/*
	 * Initialize port lookup table based on chip type and subsystem_device.
	 * LUT maps user-provided port number (e.g. 0-3) to port index (e.g. 0 or 1).
	 *
	 * For JKR:
	 *   subsystem 1: 1-port, only port 2 valid, default=1 -> LUT = [1,1,1,1]
	 *   subsystem 2: 2-port, default=1                    -> LUT = [1,0,1,1]
	 *   subsystem 3: 1-port, only port 1 valid, default=0 -> LUT = [0,0,0,0]
	 *   subsystem 4: 2-port, default=0                    -> LUT = [0,0,1,0]
	 *
	 * For non-JKR (single port): LUT = [0,0,0,0]
	 */
	if (dd->params->chip_type == CHIP_JKR) {
		u16 subsys = dd->pcidev->subsystem_device;
		enum hfi2_dms_fabric_port_idx default_idx = (subsys == PCI_DEVICE_ID_CORNELIS_CN5000 || subsys == PCI_SUBDEVICE_CN5000_DUAL_PORT) ? HFI2_DMS_FABRIC_PORT_IDX_1 : HFI2_DMS_FABRIC_PORT_IDX_0;
		bool dual_port = (subsys == PCI_SUBDEVICE_CN5000_DUAL_PORT  || subsys == PCI_SUBDEVICE_CN5000_DUAL_PORT_PS);

		dd->bulksvc->port_lut[0] = default_idx;
		dd->bulksvc->port_lut[1] = dual_port ? HFI2_DMS_FABRIC_PORT_IDX_0 : default_idx;
		dd->bulksvc->port_lut[2] = dual_port ? HFI2_DMS_FABRIC_PORT_IDX_1 : default_idx;
		dd->bulksvc->port_lut[3] = default_idx;

		dd_dev_dbg(dd, "Bulksvc port LUT: [%u,%u,%u,%u] (subsystem_device=%u, dual_port=%d)\n",
			   (u32) dd->bulksvc->port_lut[0], (u32) dd->bulksvc->port_lut[1],
			   (u32) dd->bulksvc->port_lut[2], (u32) dd->bulksvc->port_lut[3],
			   subsys, dual_port);
	} else {
		/* Non-JKR: single port, all map to port index 0 */
		dd->bulksvc->port_lut[0] = HFI2_DMS_FABRIC_PORT_IDX_0;
		dd->bulksvc->port_lut[1] = HFI2_DMS_FABRIC_PORT_IDX_0;
		dd->bulksvc->port_lut[2] = HFI2_DMS_FABRIC_PORT_IDX_0;
		dd->bulksvc->port_lut[3] = HFI2_DMS_FABRIC_PORT_IDX_0;
	}

	return ret;

err_teardown:
	hfi2_bulksvc_teardown(dd);
	return ret;
}

int hfi2_bulksvc_dirty_bit_alloc_locked(struct hfi2_bulksvc *svc)
{
	unsigned int const max = svc->dirty_notify.max_clients;
	unsigned int bit, qw;

	lockdep_assert_held(&svc->user_info_lock);
	bit = find_first_zero_bit(svc->dirty_notify.allocated, max);
	if (bit >= max)
		return -ENOSPC;
	set_bit(bit, svc->dirty_notify.allocated);
	/*
	 * Several lane workers may publish clients concurrently, so the
	 * polled bitmap length only grows, here, under the lock.
	 */
	qw = bit / BITS_PER_LONG + 1;
	if (qw > svc->dirty_notify.num_bitmap_qwords)
		WRITE_ONCE(svc->dirty_notify.num_bitmap_qwords, qw);
	return bit;
}

void hfi2_bulksvc_dirty_bit_free_locked(struct hfi2_bulksvc *svc, int bit)
{
	lockdep_assert_held(&svc->user_info_lock);
	if (bit < 0)
		return;
	for (u32 k = 0; k < svc->num_lanes; k++)
		clear_bit(bit, svc->lanes[k].client_bits);
	clear_bit(bit, svc->dirty_notify.allocated);
}

/*
 * Lane with the fewest bound clients.  On a tie a secondary lane wins,
 * since the primary lane also runs the svc-wide work.
 */
static u32 bulksvc_least_loaded_lane(struct hfi2_bulksvc *svc)
{
	u32 lane = 1 % svc->num_lanes;

	lockdep_assert_held(&svc->user_info_lock);
	for (u32 i = 2; i <= svc->num_lanes; i++) {
		u32 const k = i % svc->num_lanes;

		if (svc->lanes[k].nr_clients < svc->lanes[lane].nr_clients)
			lane = k;
	}
	return lane;
}

/*
 * Bind a new user client for life to the least loaded lane, before any
 * lane can see it (its USER_INFO_ADD event is not queued yet).  That lane
 * polls the client and holds its DMS state (client key, hfisvc accesses,
 * initiator trackers), its events, its pin lists and its verbs QPs.  The
 * lane goes into the client key, so a peer's hfisvc RDMA initiator can
 * steer its control packets to it (see hfi2_bulksvc_client_key_lane()).
 * Undone by hfi2_bulksvc_user_info_unbind_locked() if the client is aborted
 * before USER_INFO_ADD, else by the USER_INFO_RELEASE handler.
 */
void hfi2_bulksvc_user_info_bind_locked(struct hfi2_bulksvc_user_info *user_info)
{
	struct hfi2_bulksvc *svc = user_info->svc;
	u32 const lane = bulksvc_least_loaded_lane(svc);

	lockdep_assert_held(&svc->user_info_lock);
	set_bit(user_info->dirty_bit, svc->lanes[lane].client_bits);
	user_info->lane = lane;
	user_info->client_key = hfi2_bulksvc_client_key_make(user_info->client_key,
							     lane);
	svc->lanes[lane].nr_clients++;
}

void hfi2_bulksvc_user_info_unbind_locked(struct hfi2_bulksvc_user_info *user_info)
{
	lockdep_assert_held(&user_info->svc->user_info_lock);
	user_info->svc->lanes[user_info->lane].nr_clients--;
}

/* Add a user_info: create its DMS key, publish it in the dirty-notify map,
 * and link it onto svc->user_infos.
 */
static void bulksvc_process_user_info_add(struct hfi2_bulksvc *svc,
					  struct hfi2_bulksvc_user_info *user_info)
{
	int bit;

	if (WARN_ON(!user_info))
		return;

	if (hfi2_dms_create_client_key(hfi2_bulksvc_user_dms(user_info),
				       user_info->client_key,
				       READ_ONCE(bulksvc_diag_access) ?
					       bulksvc_user_diag_access : NULL,
				       user_info)) {
		dd_dev_err(svc->dd, "Failed to create DMS client key %u\n",
			   user_info->client_key);
		return;
	}

	bit = user_info->dirty_bit;
	WRITE_ONCE(svc->dirty_notify.client_map[bit], user_info);
	/*
	 * This runs on the client's lane, its only poller: replay any
	 * doorbell the lane consumed while the slot was still NULL.
	 */
	set_bit(bit, svc->dirty_notify.bitmap);

	mutex_lock(&svc->user_info_lock);
	list_add_tail(&user_info->list_entry, &svc->user_infos);
	mutex_unlock(&svc->user_info_lock);
}

/* Release a user_info: unlink it and start its destroy.  The counter is
 * bumped before the destroy queues its deferred tail (which decrements it),
 * so a later wait_event() blocks until the destroy completes.  The sleeping
 * destroy runs outside user_info_lock.
 */
static void bulksvc_process_user_info_release(struct hfi2_bulksvc *svc,
					      struct hfi2_bulksvc_user_info *user_info)
{
	int bit;

	if (WARN_ON(!user_info))
		return;

	bit = user_info->dirty_bit;
	WRITE_ONCE(svc->dirty_notify.client_map[bit], NULL);
	clear_bit(bit, svc->dirty_notify.bitmap);

	mutex_lock(&svc->user_info_lock);
	hfi2_bulksvc_user_info_unbind_locked(user_info);
	hfi2_bulksvc_dirty_bit_free_locked(svc, bit);
	list_del(&user_info->list_entry);
	mutex_unlock(&svc->user_info_lock);

	atomic_inc(&svc->pending_user_info_destroys);
	bulksvc_user_info_destroy(user_info);
}

static void bulksvc_flush_lane_event_queue(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc *svc = l->svc;
	struct list_head *entry, *tmp_entry;

	if (list_empty(&l->event_queue))
		return;

	list_for_each_safe(entry, tmp_entry, &l->event_queue) {
		struct hfi2_bulksvc_event_entry *ee =
			list_entry(entry, struct hfi2_bulksvc_event_entry,
				   list);

		list_del(entry);

		switch (ee->event.type) {
		case BULKSVC_EVENT_TYPE_USER_INFO_ADD:
			bulksvc_process_user_info_add(svc, ee->event.user_info);
			break;
		case BULKSVC_EVENT_TYPE_USER_INFO_RELEASE:
			bulksvc_process_user_info_release(svc,
							  ee->event.user_info);
			break;
		case BULKSVC_EVENT_TYPE_MMU_SYNC_DRAIN:
			/* Wake any blocked .release waiter, drop the ref. */
			if (ee->event.sync_drain) {
				struct hfi2_bulksvc_mmu_sync_drain *sd =
					ee->event.sync_drain;

				hfi2_bulksvc_user_info_drop_host_mrs(sd->user_info);
				complete(&sd->done);
				hfi2_bulksvc_mmu_sync_drain_put(sd);
			}
			break;
		default:
			break;
		}
		kfree(ee);
	}
}

/*
 * Drain every lane's event queue, processing queued add/release events
 * instead of dropping them.  A dropped release would never unregister its
 * user_info's mmu_notifier, leaving a stale subscription that faults on the
 * next munmap.
 */
void hfi2_bulksvc_flush_event_queue(struct hfi2_bulksvc *svc)
{
	for (u32 k = 0; k < svc->num_lanes; k++)
		bulksvc_flush_lane_event_queue(&svc->lanes[k]);
}

/*
 * mpsc_dequeue() also returns NULL transiently while a producer is
 * mid-update (head != tail but its link isn't published yet); mpsc_is_empty()
 * distinguishes that from a genuine empty so we don't orphan cmds queued
 * behind a half-linked node.
 */
static void bulksvc_drain_cmdq(struct hfi2_bulksvc_mpsc_verbs_cmd_queue *cmdq)
{
	struct mpsc_node *mn;

	while (true) {
		struct hfi2_bulksvc_verbs_cmd *cmd;

		mn = mpsc_dequeue(&cmdq->mpsc);
		if (!mn) {
			if (mpsc_is_empty(&cmdq->mpsc))
				break;
			cpu_relax();
			continue;
		}
		cmd = container_of(mn, struct hfi2_bulksvc_verbs_cmd,
				   mpsc_node);
		atomic_dec(&cmdq->depth);

		/*
		 * Dropping a dereg cmd without running its BTS handler
		 * would strand an mr_priv_free blocked on the destroy
		 * barrier.  Release it so it can make progress.
		 */
		if (cmd->op == HFI2_BULKSVC_VERBS_CMD_OP_MR_DEREG &&
		    cmd->mr_dereg.mr)
			verbs_bulksvc_mr_dereg_cmd_discarded(cmd->mr_dereg.mr);

		hfi2_bulksvc_verbs_cmd_put(cmd);
	}
}

/*
 * Drain every lane's queued verbs cmds and drop the krefs they pin
 * (verbs_txreq, rvt_mregion, qp_info).  Caller must have stopped the
 * bulksvc thread.
 *
 * No cmpl-side drain: cmpls are delivered synchronously on the BTS
 * thread, so a quiesced thread leaves nothing pending there.
 */
void hfi2_bulksvc_drain_verbs_queues(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc;

	if (!dd || !dd->bulksvc)
		return;
	svc = dd->bulksvc;
	if (!svc->verbs_state_initialized)
		return;

	for (u32 k = 0; k < svc->num_lanes; k++)
		bulksvc_drain_cmdq(svc->lanes[k].cmdq);
}

/*
 * Stop the bulksvc thread and drain anything that could still call into
 * rvt / verbs_txreq_cache.  Must run before verbs_txreq_exit but after
 * all user files have closed.  Idempotent (event_workq NULLed on first
 * call).  Leaves DMS / SDE / rcd alone for hfi2_bulksvc_teardown.
 */
void hfi2_bulksvc_quiesce_thread(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc *svc;

	if (!dd || !dd->bulksvc)
		return;

	svc = dd->bulksvc;

	if (!READ_ONCE(svc->worker_exited))
		reinit_completion(&svc->worker_exited_done);
	WRITE_ONCE(svc->stop_scheduling, true);
	/* rev work must be quiesced before teardown frees svc */
	cancel_work_sync(&svc->rev_work);

	if (svc->timer_interval > 0)
		hrtimer_cancel(&svc->progress_timer);

	if (svc->event_workq) {
		for (u32 k = 0; k < svc->num_lanes; k++)
			flush_work(&svc->lanes[k].work);
		if (svc->dms_roce && svc->dms_roce->initialized)
			hfi2_dms_roce_drain(svc->dms_roce);
		hfi2_bulksvc_flush_event_queue(svc);
		destroy_workqueue(svc->event_workq);
		svc->event_workq = NULL;
	}
	WRITE_ONCE(svc->worker_exited, true);
	complete_all(&svc->worker_exited_done);
	wake_up_all(&svc->lane_reps_wq);

	if (!hfi2_bulksvc_is_opa(svc)) {
		if (svc->dms_roce && svc->dms_roce->initialized)
			hfi2_dms_roce_drain(svc->dms_roce);
		return;
	}
	if (!svc->user_state_initialized)
		return;

	/* Wait for deferred user_info destroys (system_unbound_wq) so no

	 * stale work fires after svc is freed.
	 */
	wait_event(svc->pending_user_info_destroys_wq,
		   atomic_read(&svc->pending_user_info_destroys) == 0);

	/* Flush deferred MR page-set teardown.  The BTS thread (the only
	 * producer) is stopped above, so nothing new can be queued.
	 * destroy_workqueue() runs later in teardown.
	 */
	if (svc->mr_unmap_wq)
		drain_workqueue(svc->mr_unmap_wq);

	hfi2_bulksvc_drain_verbs_queues(dd);
}

#if HFI2_BULKSVC_ULP_STUBS
/*
 * Tear down every registered ULP stub peer.  dms.dd is guaranteed set
 * here: hfi2_bulksvc_loan_resources() (this file) only reaches the ULP
 * stub _init() calls after the primary lane's hfi2_dms_init() has already
 * succeeded -- a failed hfi2_dms_init() takes the earlier "goto fail;"
 * and never reaches the ULP _init() block at all.  dms.dd is also
 * never cleared anywhere in this codebase once hfi2_dms_init() sets it
 * (hfi2_dms_uninit() only reads dms.dd for a log message; grep the
 * tree: "grep -nE 'dms->dd\s*=' *.c" to confirm the single assignment
 * site), so there is no teardown or error path that can clear it out
 * from under already-registered ULP peers.  So a bulksvc with ULP peers
 * registered but dms.dd unset can never exist; the guard below only
 * protects against dms.dd being unset because bulksvc itself was never
 * fully loaned (dms never initialized, so no ULP peers exist to tear down
 * either).
 *
 * Each hfi2_bulksvc_{net,uet,roce}_teardown() is separately self-guarded
 * against a peer that was never registered or already torn down (it
 * checks its own state pointer, e.g. svc->roce_ulp, before doing
 * anything), so calling all three unconditionally here is also safe if
 * one ULP's _init() failed while the others succeeded (loan_resources
 * treats each ULP _init() failure as a non-fatal warning, so partial
 * registration across the three ULPs is reachable).
 */
void hfi2_bulksvc_ulp_teardown_all(struct hfi2_bulksvc *svc)
{
	if (!hfi2_bulksvc_primary_dms(svc) || !hfi2_bulksvc_primary_dms(svc)->dd)
		return;

	hfi2_bulksvc_eal_test_teardown(svc);
	hfi2_bulksvc_net_teardown(svc);
	hfi2_bulksvc_uet_teardown(svc);
	hfi2_bulksvc_roce_teardown(svc);
}
#endif

/* can be called multiple times */
void hfi2_bulksvc_teardown(struct hfi2_devdata *dd)
{
	struct hfi2_bulksvc_user_info *user_info;
	struct hfi2_devrsrcs *dr;
	struct hfi2_bulksvc *svc;

	if (!dd)
		return;

	dr = &dd->rsrcs;
	/* TODO add logic to wait until it safe to free bulksvc */
	dd->verbs_dev.rdi.use_bulksvc = false;

	svc = dd->bulksvc;

	if (!svc)
		return;

	/*
	 * shutdown_device() stops here early when a loaned SDMA engine does
	 * not confirm its halt: the engine may still own its descriptor ring,
	 * so nothing it can reach is released.  hfi2_free_devdata() calls
	 * again after the PCI device was disabled.  Bus mastering is off, so
	 * the engine can no longer reach host memory, but the sdma_engine
	 * array, the send context and the receive contexts are already
	 * freed.  Finish in software only, without touching any of them.
	 */
	if (svc->sdma_quiesce_failed && !pci_is_enabled(dd->pcidev)) {
		dd_dev_info(dd, "bulksvc: finishing teardown after device disable\n");
		hfi2_bulksvc_primary_dms(svc)->hw_released = true;
		svc->sdma_quiesce_failed = false;
		hfi2_dms_roce_detach_hw(svc);
	}

	/* Idempotent: already a no-op if hfi2_unregister_ib_device ran. */
	hfi2_bulksvc_quiesce_thread(dd);

	/* Catch anything rvt_unregister_device's dereg_mr enqueued. */
	hfi2_bulksvc_drain_verbs_queues(dd);

#if HFI2_BULKSVC_ULP_STUBS
	hfi2_bulksvc_ulp_teardown_all(svc);
#endif
	if (hfi2_bulksvc_is_opa(svc)) {
		for (u32 k = 0; k < svc->num_lanes; k++) {
			struct hfi2_bulksvc_lane *l = &svc->lanes[k];

			if (l->dms_up) {
				hfi2_bulksvc_verbs_release_client_id(l->dms);
				hfi2_dms_uninit(l->dms);
				l->dms_up = false;
			}
			hfi2_bulksvc_lane_mr_teardown(l);
		}
	} else {
		struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(svc);

		if (svc->dms_roce && svc->dms_roce->initialized) {
			hfi2_dms_roce_teardown_begin(svc);
			hfi2_dms_roce_teardown_drain(svc);
		} else {
			svc->sdma_quiesce_failed = !hfi2_dms_sdma_shutdown(dms);
		}
		if (!svc->sdma_quiesce_failed)
			hfi2_dms_common_uninit(dms);
	}

	if (svc->roce_rsm_programmed) {
		mutex_lock(&hfi2_mutex);
		if (svc->first_rsm_rule >= 0)
			clear_rsm_rule(dd, svc->first_rsm_rule);
		if (svc->vrma_rsm_rule >= 0) {
			clear_rsm_rule(dd, svc->vrma_rsm_rule);
			svc->vrma_rsm_rule = -1;
		}
#if HFI2_BULKSVC_ULP_STUBS
		if (svc->eth_rsm_rule >= 0) {
			clear_rsm_rule(dd, svc->eth_rsm_rule);
			svc->eth_rsm_rule = -1;
		}
		hfi2_bulksvc_eal_test_clear_dstport(svc);
#endif
		/*
		 * Clear the iport gate with the rule that makes it coherent.
		 * Leaving the gate set without a PacketType-5 rule is worse
		 * than leaving both: a promoted VRMA frame then misses RSM and
		 * is dropped silently instead of falling back to eager
		 * delivery.
		 */
		if (hfi2_is_eth_mode(dd))
			bulksvc_roce_disable_vrma_iport(dd);
		svc->roce_rsm_programmed = false;
		mutex_unlock(&hfi2_mutex);
	}
#if HFI2_BULKSVC_ULP_STUBS
	else if (!hfi2_bulksvc_is_opa(svc) && svc->eth_rsm_rule >= 0) {
		mutex_lock(&hfi2_mutex);
		clear_rsm_rule(dd, svc->eth_rsm_rule);
		svc->eth_rsm_rule = -1;
		mutex_unlock(&hfi2_mutex);
	}
#endif

	/* Common SDMA teardown must finish before RoCE releases its callback state. */
	if (!hfi2_bulksvc_is_opa(svc))
		hfi2_roce_kmr_donor_exit(dd);
	if (!hfi2_bulksvc_is_opa(svc) && svc->dms_roce &&
	    svc->dms_roce->initialized) {
		if (svc->sdma_quiesce_failed)
			return;
		hfi2_dms_roce_teardown_finish(svc);
	}

	if (svc->rsrc.sde_arr && !hfi2_bulksvc_return_sdma(dd))
		return;

	if (svc->user_state_initialized) {
		mutex_lock(&svc->user_info_lock);
		list_for_each_entry(user_info, &svc->user_infos, list_entry) {
			dd_dev_err(dd,
				   "%s:%d:%s() bulksvc: Lingering user_info %u: %u\n",
				   __FILENAME__, __LINE__, __func__,
				   user_info->client_key,
				   kref_read(&user_info->refcount));
		}
		mutex_unlock(&svc->user_info_lock);
	}
#if HFI2_BULKSVC_ULP_STUBS
	if (!hfi2_bulksvc_is_opa(svc))
		hfi2_bulksvc_primary_dms(svc)->rcd_ctrl = NULL;
#endif
	if (svc->rsrc.pp) {
		/* free any bulksvc rctxts */
		for (u32 i = 0; i < dd->num_pports; i++) {
			struct hfi2_portrsrcs *pr = &dr->ppr[i];

			for (u32 ctxt = pr->first_bulksvc_alloc_ctxt;
			     dd->rcd && ctxt < pr->first_dyn_alloc_ctxt; ctxt++) {
				if (!dd->rcd[ctxt])
					continue;
				hfi2_rcvctrl(dd,
					     HFI2_RCVCTRL_CTXT_DIS |
					     HFI2_RCVCTRL_INTRAVAIL_DIS,
					     dd->rcd[ctxt]);
				if (dd->rcd[ctxt]->msix_intr != CCE_NUM_MSIX_VECTORS)
					hfi2_msix_free_irq(dd, dd->rcd[ctxt]->msix_intr);

				dd->rcd[ctxt]->msix_intr = CCE_NUM_MSIX_VECTORS;
				dd->rcd[ctxt]->event_flags = 0;
				hfi2_free_ctxt_rcv_groups(dd->rcd[ctxt]);
				hfi2_free_ctxt(dd->rcd[ctxt]);
			}
			kfree(svc->rsrc.pp[i].rcd);
			svc->rsrc.pp[i].rcd = NULL;
		}
		kfree(svc->rsrc.pp);
		svc->rsrc.pp = NULL;
	}

	if (svc->doorbell_irq_allocated)
		hfi2_msix_free_irq(dd, svc->doorbell_msix_intr);

	u64 debug_info_ptr = atomic64_xchg(&svc->debug_info_buf_ptr, 0);
	if (debug_info_ptr != 0 && debug_info_ptr != 1) {
		kvfree((char*) debug_info_ptr);
	}

	if (svc->user_state_initialized) {
		if (svc->dirty_notify.page)
			__free_page(svc->dirty_notify.page);
		bitmap_free(svc->dirty_notify.allocated);
		kfree(svc->dirty_notify.client_map);
		bitmap_free(svc->lane_client_bits);
	}

	/* Drained in quiesce_thread; destroy here before the slab caches. */
	if (svc->mr_unmap_wq) {
		destroy_workqueue(svc->mr_unmap_wq);
		svc->mr_unmap_wq = NULL;
	}

	/* Caches must outlive the drain above that freed the last cmd/cmpl. */
	if (svc->verbs_caches_initialized)
		hfi2_bulksvc_verbs_caches_destroy(svc);

	bulksvc_lanes_free(svc);
	kfree(svc);
	dd->bulksvc = NULL;
}

/* interrupt handler for bulksvc sdma irqs, bulksvc will clear the IRQs if/when it goes to sleep */
void bulksvc_sdma_irq(struct hfi2_devdata *dd, struct sdma_engine *sde)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;

	if (!svc || !hfi2_bulksvc_primary_dms(svc)->common_initialized)
		return;

	/* every lane places on every loaned engine */
	bulksvc_schedule_all(svc);
}

/* Drain lane @l's event queue on the lane's worker. */
static int bulksvc_poll_event_queue(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc_event_entry *event_entry, *tmp;
	struct hfi2_bulksvc *svc = l->svc;
	struct list_head local_list;
	unsigned long flags;
	int processed = 0;

	/* handle events */
	if (!list_empty(&l->event_queue)) {
		INIT_LIST_HEAD(&local_list);
		spin_lock_irqsave(&l->event_lock, flags);

		/* reduce time holding lock: move list locally and clear list */
		list_cut_position(&local_list, &l->event_queue,
				  l->event_queue.prev);

		spin_unlock_irqrestore(&l->event_lock, flags);

		list_for_each_entry_safe(event_entry, tmp, &local_list, list) {
			list_del(&event_entry->list);
			processed += 1;

			switch (event_entry->event.type) {
			case BULKSVC_EVENT_TYPE_SDMA:
				break;
			case BULKSVC_EVENT_TYPE_USER_INFO_ADD:
				bulksvc_process_user_info_add(svc,
							      event_entry->event.user_info);
				break;
			case BULKSVC_EVENT_TYPE_USER_INFO_RELEASE:
				bulksvc_process_user_info_release(svc,
								  event_entry->event.user_info);
				break;
			case BULKSVC_EVENT_TYPE_MMU_SYNC_DRAIN: {
				struct hfi2_bulksvc_mmu_sync_drain *sd =
					event_entry->event.sync_drain;
				struct hfi2_bulksvc_user_info *user_info;

				if (WARN_ON(!sd || !sd->user_info))
					break;

				user_info = sd->user_info;

				/* Short-circuit cmplq posts and reject further
				 * user cmds while we cancel.
				 */
				user_info->mm_releasing = true;
				user_info->shutting_down = true;

				hfi2_dms_release_client_key(hfi2_bulksvc_user_dms(user_info),
							    user_info->client_key);

				/* Cancel this client's initiator transfers, by buffer owner. */
				hfi2_bulksvc_user_info_cancel_dms_trackers(user_info);

				hfi2_bulksvc_user_info_drain_ephemeral_mrs(user_info);

				/*
				 * Must run here: the cancels above can drop the
				 * last user_info ref and queue USER_INFO_RELEASE,
				 * which frees user_mr_list entries on this lane.
				 */
				hfi2_bulksvc_user_info_drop_host_mrs(user_info);

				complete(&sd->done);

				hfi2_bulksvc_mmu_sync_drain_put(sd);
				break;
			}
			}


			kfree(event_entry);
		}
	}
	return processed;
}



void hfi2_bulksvc_pin_entry_unlink(struct hfi2_bulksvc_pin_lists *pins,
				   struct hfi2_bulksvc_proactive_pin_entry *entry)
{
	WARN_ON_ONCE(entry->on_active_pin_list && entry->on_speculative_pin_list);

	if (entry->on_active_pin_list) {
		list_del_init(&entry->node);
		pins->active_count--;
		entry->on_active_pin_list = false;
	}
	if (entry->on_speculative_pin_list) {
		list_del_init(&entry->node);
		pins->speculative_count--;
		entry->on_speculative_pin_list = false;
	}
}

/* Pin one chunk of the first entry on lane @l's pin lists. */
static int process_proactive_pins(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc_pin_lists *pins = &l->pins;
	struct hfi2_bulksvc *svc = l->svc;
	struct hfi2_bulksvc_proactive_pin_entry *entry;
	struct hfi2_mem_region *hfi2_mr;
	unsigned long start;
	unsigned int chunk;
	int ret;

	if (!list_empty(&pins->pin_active))
		entry = list_first_entry(&pins->pin_active,
					 struct hfi2_bulksvc_proactive_pin_entry,
					 node);
	else if (!list_empty(&pins->pin_speculative))
		entry = list_first_entry(&pins->pin_speculative,
					 struct hfi2_bulksvc_proactive_pin_entry,
					 node);
	else
		return 0;

	hfi2_mr = entry->hfi2_mr;
	if (!hfi2_mr)
		goto remove_from_list;

	start = find_first_zero_bit(hfi2_mr->pin_bitmap, hfi2_mr->npages_total);
	if (start >= hfi2_mr->npages_total)
		goto remove_from_list;

	chunk = HFI2_DMS_PROACTIVE_PIN_CHUNK_PAGES;
	/*
	 * Spill: when starting at page 0 with a head-misaligned MR
	 * (region_offset_bytes != 0), the first inject covers one
	 * extra page (see HFI2_DMS_SDMA_DATA_PAGES_MAX in dms.c).
	 * Pin the spill page now to avoid a follow-up GUP on the
	 * inject path.
	 */
	if (start == 0 && entry->region_offset_bytes)
		chunk++;
	chunk = min_t(unsigned int, chunk, hfi2_mr->npages_total - start);

	/* Conservative writable=true.  On failure the entry is removed
	 * from the proactive pipeline; demand-pin via user_pin_range
	 * may still succeed later for the same MR with the correct
	 * direction.  Failures are counted in proactive_pin_failures.
	 */
	ret = entry->pin_range(svc, entry, start, chunk, true);
	if (ret < 0) {
		pins->proactive_pin_failures++;
		goto remove_from_list;
	}

	pins->pages_pinned_proactive += chunk;
	pins->proactive_pin_ops++;

	if (!bitmap_full(hfi2_mr->pin_bitmap, hfi2_mr->npages_total)) {
		if (entry->on_active_pin_list)
			list_move_tail(&entry->node, &pins->pin_active);
		else
			list_move_tail(&entry->node, &pins->pin_speculative);
		return 1;
	}

remove_from_list:
	hfi2_bulksvc_pin_entry_unlink(pins, entry);
	return 1;
}

static inline void clear_doorbell_is(struct hfi2_devdata *dd, u32 src)
{
	hfi2_write_csr(dd, dd->params->cce_int_clear_reg + (8 * (src / 64)),
		  1ull << (src % 64));
}

/*
 * Re-arm lane @l's receive and SDMA interrupts; the primary lane also
 * re-arms the doorbell, which every lane shares.
 */
static void bulksvc_lane_clear_interrupts(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc *svc = l->svc;
	struct hfi2_devdata *dd = svc->dd;
	u32 off = 8 * (dd->params->is_sdma_start / 64);
	unsigned long flags;

	local_irq_save(flags);
	if (hfi2_bulksvc_is_opa(svc)) {
		hfi2_rcd_eoi_intr(l->dms->rcd_ctrl);
		hfi2_rcd_eoi_intr(l->dms->rcd_data);
	}
	if (l->dms->common_initialized) {
		for (int i = 0; i < l->dms->num_engines; ++i) {
			struct sdma_engine *sde = l->dms->sdma_engines[i];

			hfi2_write_csr(dd, dd->params->cce_int_clear_reg + off, sde->imask);
		}
	}
	if (bulksvc_lane_is_primary(l)) {
		/* clear both doorbell interrupt sources (chip-specific IS numbers) */
		clear_doorbell_is(dd, dd->params->is_doorbell0);
		clear_doorbell_is(dd, dd->params->is_doorbell1);
	}
	local_irq_restore(flags);
}

/*
 * Primary-lane-only work: the pollers of the services bound to the primary
 * lane's DMS (IPoIB, ULP stubs, the Ethernet RoCE backend) and the debug
 * info producer.
 */
static int bulksvc_primary_poll(struct hfi2_bulksvc *svc, ktime_t now)
{
	int processed = 0;

	if (hfi2_bulksvc_is_opa(svc)) {
		processed += hfi2_bulksvc_ipoib_poll(svc);
#if HFI2_BULKSVC_ULP_STUBS
		processed += hfi2_bulksvc_roce_poll(svc);
		processed += hfi2_bulksvc_uet_poll(svc);
		processed += hfi2_bulksvc_net_poll(svc);
#endif
	} else if (svc->backend == HFI2_BULKSVC_BACKEND_ETH_ROCE) {
		struct hfi2_dms *dms = hfi2_bulksvc_primary_dms(svc);
		int i;

		if (dms->common_initialized &&
		    hfi2_dms_roce_sdma_busy(svc->dms_roce)) {
			for (i = 0; i < dms->num_engines; ++i)
				processed += hfi2_dms_sdma_drain_and_complete(dms, i);
		}
		processed += hfi2_dms_roce_poll(svc->dms_roce, now);
#if HFI2_BULKSVC_ULP_STUBS
		if (dms->rcd_ctrl)
			processed += hfi2_dms_eal_poll(dms);
		processed += hfi2_bulksvc_eal_test_poll(svc);
#endif
	}

	/*
	 * bulksvc_dbg_open() publishes the sentinel 1 and waits for this
	 * producer to replace it with a heap pointer, failing -ETIMEDOUT if
	 * none arrives.  An OPA-only producer left that wait unanswerable on
	 * ETH_ROCE, so the file never opened on the backend that needs it.
	 * Answering here is safe because hfi2_bulksvc_prepare_debug_info()
	 * already has a non-OPA path returning a kmalloc'd notice, and both
	 * consumers free with kvfree(), which accepts that kmalloc'd buffer.
	 */
	if (atomic64_read(&svc->debug_info_buf_ptr) == 1) {
		char const * const buf = hfi2_bulksvc_prepare_debug_info(svc);

		atomic64_set(&svc->debug_info_buf_ptr, (u64)buf);
		processed += 1;
	}

	return processed;
}

/* One pass over everything lane @l owns; returns the amount of work done. */
static int bulksvc_lane_once(struct hfi2_bulksvc_lane *l, ktime_t now)
{
	struct hfi2_bulksvc *svc = l->svc;
	int processed = 0;

	processed += bulksvc_poll_event_queue(l);
	if (hfi2_bulksvc_is_opa(svc)) {
		processed += hfi2_bulksvc_lane_poll_mr_ops(l);
		processed += hfi2_bulksvc_poll_user_cmds(l);
		processed += process_proactive_pins(l);
		processed += hfi2_dms_poll(l->dms, now);
		processed += hfi2_bulksvc_poll_verbs_cmds(svc, l->cmdq);
		processed += hfi2_bulksvc_poll_gate_retries(svc, l->idx);
		processed += hfi2_bulksvc_poll_gbn_teardown(svc, l->idx);
	}
	if (bulksvc_lane_is_primary(l))
		processed += bulksvc_primary_poll(svc, now);

	return processed;
}

/*
 * Run bulksvc_lane_once() until idle or bulksvc_max_iters_per_work passes,
 * then flush what the IPoIB pass held back.
 */
static enum hfi2_bulksvc_event_work_outcome
bulksvc_lane_run(struct hfi2_bulksvc_lane *l, unsigned int *iters_done)
{
	struct hfi2_bulksvc *svc = l->svc;
	enum hfi2_bulksvc_event_work_outcome outcome;
	int iters = 0;
	int processed;
	bool is_opa = hfi2_bulksvc_is_opa(svc);

	do {
		processed = bulksvc_lane_once(l, is_opa ? ktime_get() : ktime_get_coarse());
		iters++;
	} while (iters < bulksvc_max_iters_per_work &&
		 (processed || (!is_opa && bulksvc_lane_is_primary(l) &&
				!iters_done && !READ_ONCE(svc->stop_scheduling))));

	if (bulksvc_worker_stats() && iters == bulksvc_max_iters_per_work &&
	    is_opa)
		l->dms->counters.kworker_resched_saturated++;

	if (READ_ONCE(svc->stop_scheduling)) {
		outcome = HFI2_BULKSVC_EVENT_WORK_STOPPED;
	} else if (iters == bulksvc_max_iters_per_work) {
		outcome = HFI2_BULKSVC_EVENT_WORK_SATURATED;
	} else {
		outcome = HFI2_BULKSVC_EVENT_WORK_IDLE;
	}

	if (iters_done)
		*iters_done = iters;

	/* The loop is over; issue anything a per-pass flush held back. */
	if (bulksvc_lane_is_primary(l))
		hfi2_bulksvc_ipoib_drain(svc);
	return outcome;
}

/* Polling mode: lane work function that requeues itself */
static void bulksvc_lane_work_polling(struct work_struct *work)
{
	struct hfi2_bulksvc_lane *l = container_of(work, struct hfi2_bulksvc_lane,
						   work);
	struct hfi2_bulksvc *svc = l->svc;
	u64 const cpu_start = current->se.sum_exec_runtime;

	bulksvc_lane_run(l, NULL);
	cond_resched_tasks_rcu_qs();
	hfi2_bulksvc_schedule_lane(svc, l->idx);

	if (svc->stop_scheduling &&
	    (hfi2_bulksvc_is_opa(svc) || l->dms->common_initialized)) {
		synchronize_rcu();
		bulksvc_lane_clear_interrupts(l);
	}

	if (bulksvc_worker_stats() && hfi2_bulksvc_is_opa(svc))
		l->dms->counters.kworker_cpu_ns +=
			current->se.sum_exec_runtime - cpu_start;
}

/* KVM-style window growth: 0 -> grow_start, then *= grow, capped at the param. */
static void grow_halt_poll_ns(struct hfi2_bulksvc_lane *l)
{
	unsigned int val = l->halt_poll_ns;
	const unsigned int grow_factor = 2;
	const unsigned int grow_min = 1000; /* 1 us*/

	val *= grow_factor;
	/*
	 * Seed a zero/tiny window straight to grow_start rather than creeping
	 * up by doubling from 1ns.  Without this the window takes ~14 grows to
	 * reach a useful spin budget, so the grace never spans the inter-op RTT
	 * and the worker stays wake-latency-bound (measured: server window stuck
	 * near 0, throughput ~half of polling).
	 */
	if (val < grow_min)
		val = grow_min;
	if (val > bulksvc_halt_poll_ns)
		val = bulksvc_halt_poll_ns;

	l->halt_poll_ns = val;
}

/* KVM-style window shrink: /= shrink */
static void shrink_halt_poll_ns(struct hfi2_bulksvc_lane *l)
{
	unsigned int shrink_factor = 2;

	if (l->halt_poll_ns < shrink_factor)
		l->halt_poll_ns = 0;
	else
		l->halt_poll_ns /= 2;
}

/*
 * Event-driven mode, OPA DMS lane.
 *
 * Do at most bulksvc_max_iters_per_work successful iterations of
 * bulksvc_lane_once().  After draining the available work it arms an adaptive
 * soft-poll grace window (KVM halt-polling model, virt/kvm/kvm_main.c) and
 * spins briefly for the next op. The spin window is dynamic so a busy link
 * trends toward spinning and an idle link toward sleeping.
 *
 * The timer also schedules this function, so in this case, when the timer
 * schedules work that results in no work being done, leave the soft poll
 * window alone.
 * In this way the following rules are created:
 *  1. If nothing was found on first iteration, then fast exit, don't
 *     soft poll. This was an unnecessary schedule call, likely the timer
 *  2. If something was found on first iteration, this is expected, go again
 *  3. If something was found after first iteration, grow soft poll window
 *  4. If nothing was found after first iteration, start soft polling
 *  5. If soft polling yields no work, shrink poll window
 *  6. If soft polling yields work, increase poll window
 */
static void bulksvc_opa_lane_work_eventing(struct hfi2_bulksvc_lane *l)
{
	struct hfi2_bulksvc *svc = l->svc;
	struct hfi2_dms *dms = l->dms;
	u64 const cpu_start = current->se.sum_exec_runtime;
	u64 spin_cpu_start = 0;
	bool in_soft_poll = false;
	ktime_t spin_deadline = 0;
	ktime_t now;
	int processed;
	u32 i;

	/* var i should represent n loops which processed SOME work */
	for (i = 0; i < bulksvc_max_iters_per_work; i++) {
soft_poll:
		now = ktime_get();
		processed = bulksvc_lane_once(l, now);

		if (processed != 0) {
			/* normal successful loop, go again */
			if (!bulksvc_halt_poll_ns)
				continue;
			if (in_soft_poll) {
				/* waiting around paid off */
				if (bulksvc_worker_stats()) {
					dms->counters.kworker_halt_poll_success++;
					dms->counters.kworker_halt_poll_wait_ns +=
						current->se.sum_exec_runtime -
						spin_cpu_start;
				}
				in_soft_poll = false;
			}
			/* grow if > 1 loop was successful */
			if (i)
				grow_halt_poll_ns(l);
			continue;
		} else if (i == 0 || !bulksvc_halt_poll_ns) {
			/*
			 * nothing to do on first iteration!
			 * AKA unnecessary schedule, (likely the timer woke us)
			 */
			break;
		} else if (!in_soft_poll) {
			/* hang around to see if anything new shows up */
			spin_cpu_start = current->se.sum_exec_runtime;
			spin_deadline = ktime_add_ns(now, l->halt_poll_ns);
			in_soft_poll = true;
			goto soft_poll;
		} else if (ktime_after(now, spin_deadline)) {
			/* waited long enough, nothing showed */
			if (bulksvc_worker_stats())
				dms->counters.kworker_halt_poll_wait_ns +=
					current->se.sum_exec_runtime -
					spin_cpu_start;
			shrink_halt_poll_ns(l);
			break;
		} else {
			cpu_relax();
			goto soft_poll;
		}
		/* nothing should fall to here */
	}


	/* Before cond_resched(), so held-back work does not wait one out. */
	if (bulksvc_lane_is_primary(l))
		hfi2_bulksvc_ipoib_drain(svc);

	cond_resched_tasks_rcu_qs();
	/* Skip uneventful iterations, since these are likely just timer driven */
	if (bulksvc_worker_stats() && i)
		dms->counters.last_nloops = i;

	/*
	 * Clear interrupts so the hardware can re-assert them, then do one
	 * final pass to catch an op whose interrupt fired between our last
	 * poll and the clear (lost-interrupt defense).  Reschedule if that
	 * pass finds late work, or if we bailed on the iter cap while still
	 * busy, so nothing is stranded.
	 */
	bulksvc_lane_clear_interrupts(l);
	if (svc->stop_scheduling)
		return;

	/*
	 * The doorbell is shared by all lanes and re-armed only here: a
	 * client of another lane that rang it while it was still pending
	 * raised no IRQ, so wake the lanes that have dirty clients (else
	 * they would wait for the progress timer).
	 */
	if (bulksvc_lane_is_primary(l))
		bulksvc_wake_dirty_lanes(svc);

	if (i >= bulksvc_max_iters_per_work) {
		if (bulksvc_worker_stats())
			dms->counters.kworker_resched_saturated++;
		hfi2_bulksvc_schedule_lane(svc, l->idx);
	} else if (bulksvc_lane_once(l, ktime_get()) != 0) {
		if (bulksvc_worker_stats())
			dms->counters.kworker_resched_final_check++;
		if (bulksvc_halt_poll_ns)
			grow_halt_poll_ns(l);
		hfi2_bulksvc_schedule_lane(svc, l->idx);
	}

	/*
	 * The pass above can fire completions while returning zero, because
	 * hfi2_dms_poll() does not count what hfi2_dms_sdma_drain_and_complete()
	 * retires.  Zero means no reschedule, so drain again rather than leave
	 * held-back work for an unrelated wakeup.
	 */
	if (bulksvc_lane_is_primary(l))
		hfi2_bulksvc_ipoib_drain(svc);

	if (bulksvc_worker_stats())
		dms->counters.kworker_cpu_ns +=
			current->se.sum_exec_runtime - cpu_start;
}

void hfi2_bulksvc_closeout_stats_print(struct hfi2_bulksvc *svc,
					    struct seq_file *s)
{
	seq_printf(s, "closeout_idle %llu\n",
		   READ_ONCE(svc->closeout_stats.idle));
	seq_printf(s, "closeout_saturated %llu\n",
		   READ_ONCE(svc->closeout_stats.saturated));
	seq_printf(s, "closeout_stopped %llu\n",
		   READ_ONCE(svc->closeout_stats.stopped));
	seq_printf(s, "closeout_eoi_issued %llu\n",
		   READ_ONCE(svc->closeout_stats.eoi_issued));
	seq_printf(s, "closeout_rx_race_reschedule %llu\n",
		   READ_ONCE(svc->closeout_stats.rx_race_reschedule));
}

/* Event mode: lane work function, woken by the lane's wake sources */
static void bulksvc_lane_work_eventing(struct work_struct *work)
{
	struct hfi2_bulksvc_lane *l = container_of(work, struct hfi2_bulksvc_lane,
						   work);
	struct hfi2_bulksvc *svc = l->svc;
	enum hfi2_bulksvc_event_work_outcome outcome;
	unsigned int iters;

	if (hfi2_bulksvc_is_opa(svc)) {
		bulksvc_opa_lane_work_eventing(l);
		return;
	}

	/* Ethernet mode: the RoCE backend runs on its only lane */
	outcome = bulksvc_lane_run(l, &iters);
	cond_resched_tasks_rcu_qs();
	if (outcome == HFI2_BULKSVC_EVENT_WORK_SATURATED) {
		svc->closeout_stats.saturated++;
		hfi2_bulksvc_schedule_lane(svc, l->idx);
		return;
	}
	if (outcome == HFI2_BULKSVC_EVENT_WORK_STOPPED) {
		svc->closeout_stats.stopped++;
		return;
	}
	if (outcome != HFI2_BULKSVC_EVENT_WORK_IDLE)
		return;
	svc->closeout_stats.idle++;

	if (svc->backend != HFI2_BULKSVC_BACKEND_ETH_ROCE ||
	    !svc->dms_roce || !svc->dms_roce->initialized ||
	    !svc->dms_roce->active ||
	    !svc->dms_roce->rcd[0] || !svc->dms_roce->rcd[1] ||
	    READ_ONCE(svc->stop_scheduling) ||
	    iters > bulksvc_max_iters_per_work)
		return;

	bulksvc_lane_clear_interrupts(l);
	hfi2_rcd_eoi_intr(svc->dms_roce->rcd[0]);
	hfi2_rcd_eoi_intr(svc->dms_roce->rcd[1]);
	svc->closeout_stats.eoi_issued += HFI2_DMS_ROCE_RCD_COUNT;
#if HFI2_BULKSVC_ULP_STUBS
	if (l->dms->rcd_ctrl) {
		hfi2_rcd_eoi_intr(l->dms->rcd_ctrl);
		svc->closeout_stats.eoi_issued++;
	}
#endif
	if (hfi2_rcd_packet_present(svc->dms_roce->rcd[0]) ||
	    hfi2_rcd_packet_present(svc->dms_roce->rcd[1]) ||
	    (l->dms->rcd_ctrl && hfi2_rcd_packet_present(l->dms->rcd_ctrl))) {
		svc->closeout_stats.rx_race_reschedule++;
		hfi2_bulksvc_schedule_lane(svc, l->idx);
	}
}

/* Guaranteed progress callback */
static enum hrtimer_restart bulksvc_progress_timer_callback(struct hrtimer *timer)
{
	struct hfi2_bulksvc *svc = container_of(timer, struct hfi2_bulksvc, progress_timer);

	if (svc->stop_scheduling) {
		return HRTIMER_NORESTART;
	}

	bulksvc_schedule_all(svc);

	hrtimer_forward_now(timer, svc->timer_interval);
	return HRTIMER_RESTART;
}

/*
 * Grant this function every RIF and R_Key table column.
 *
 * Both tables reset to zero columns owned, and a table write to a bucket the
 * function does not own is silently ignored - so without this an armed entry
 * disappears with no error reported anywhere, which is indistinguishable from
 * an arm that was never attempted.  Nothing can be placed by hardware until
 * ownership is programmed, so it is done at init rather than lazily.
 *
 * Single tenant (design 5.1.1, gate H8): all sixteen columns to VF0, which is
 * this PF.  The mapping registers are PF-only and hardware does not reject a
 * wrong configuration, so the write is read back and any disagreement is
 * reported rather than left to surface later as a silently dropped arm.
 */
static void bulksvc_roce_eal_grant_table_columns(struct hfi2_devdata *dd)
{
	static const struct {
		const char *name;
		u32 offset;
	} mapping[] = {
		{ "rift", CYR_EAL_RIFT_VF_MAPPING_CFG0 },
		{ "rkey", CYR_EAL_RKEY_VF_MAPPING_CFG0 },
	};
	u64 reg, columns;

	for (int i = 0; i < ARRAY_SIZE(mapping); ++i) {
		reg = hfi2_read_csr(dd, mapping[i].offset);
		reg &= ~EAL_VF_MAPPING_COLUMNS_MASK(0);
		reg |= FIELD_PREP(EAL_VF_MAPPING_COLUMNS_MASK(0),
				  EAL_VF_MAPPING_ALL_COLUMNS);
		hfi2_write_csr(dd, mapping[i].offset, reg);

		reg = hfi2_read_csr(dd, mapping[i].offset);
		columns = FIELD_GET(EAL_VF_MAPPING_COLUMNS_MASK(0), reg);
		if (columns != EAL_VF_MAPPING_ALL_COLUMNS)
			dd_dev_err(dd,
				   "%s:%d:%s() roce: %s VF0 column ownership read back 0x%04llx, expected 0x%04x - hardware placement will be silently dropped\n",
				   __FILENAME__, __LINE__, __func__,
				   mapping[i].name, columns,
				   EAL_VF_MAPPING_ALL_COLUMNS);
	}
}

/*
 * Set RcvIportCtrl.RcvEthRoceV2VrmaEnable on every port that carries RoCE.
 * The register is per port, so a device with two fabric ports needs both.
 *
 * RcvCtxtDefault is deliberately not touched here.  It is the Type-3/invalid
 * fallback; VRMA context selection falls back to RcvBypass.BypassContext, and
 * pointing RcvCtxtDefault at the RoCE context was measured to change nothing.
 */
static void bulksvc_roce_enable_vrma_iport(struct hfi2_devdata *dd)
{
	u64 iport;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_pportdata *ppd = &dd->pport[pidx];

		iport = read_iport_csr(dd, ppd->hw_pidx,
				       dd->params->rcv_iport_ctrl_reg);
		iport |= CYR_RCV_IPORT_CTRL_RCV_ETH_ROCEV2_VRMA_ENABLE_SMASK;
		write_iport_csr(dd, ppd->hw_pidx,
				dd->params->rcv_iport_ctrl_reg, iport);

		/*
		 * Read back: a bit that failed to set leaves placement inert
		 * with nothing in the log to say so.  The log is not the state.
		 */
		iport = read_iport_csr(dd, ppd->hw_pidx,
				       dd->params->rcv_iport_ctrl_reg);
		if (!(iport & CYR_RCV_IPORT_CTRL_RCV_ETH_ROCEV2_VRMA_ENABLE_SMASK))
			dd_dev_err(dd, "%s:%d:%s() roce: port %d RcvEthRoceV2VrmaEnable did not set (RcvIportCtrl=0x%016llx) - VRMA frames will not be placed\n",
				   __FILENAME__, __LINE__, __func__,
				   pidx, iport);
	}
}

/*
 * Clear RcvIportCtrl.RcvEthRoceV2VrmaEnable on every port.
 *
 * This is not tidiness.  The bit is CSR state and survives rmmod, so a module
 * that sets it and never clears it leaves the host in a configuration the NEXT
 * module neither programs nor logs.  Worse, the leftover state is not merely
 * inert: with the bit set and no PacketType-5 RSM rule present, RXE promotes an
 * L4=0x7A frame to type 5, RSM has no rule that matches it, and the frame is
 * dropped with no counter - where on a clean host it would have reverted to
 * RCV_TYPE_4 and been delivered.  A stale enable turns a delivered packet into
 * a silent drop.
 */
static void bulksvc_roce_disable_vrma_iport(struct hfi2_devdata *dd)
{
	u64 iport;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_pportdata *ppd = &dd->pport[pidx];

		iport = read_iport_csr(dd, ppd->hw_pidx,
				       dd->params->rcv_iport_ctrl_reg);
		iport &= ~CYR_RCV_IPORT_CTRL_RCV_ETH_ROCEV2_VRMA_ENABLE_SMASK;
		write_iport_csr(dd, ppd->hw_pidx,
				dd->params->rcv_iport_ctrl_reg, iport);

		iport = read_iport_csr(dd, ppd->hw_pidx,
				       dd->params->rcv_iport_ctrl_reg);
		if ((dd->flags & HFI2_PRESENT) &&
		    (iport & CYR_RCV_IPORT_CTRL_RCV_ETH_ROCEV2_VRMA_ENABLE_SMASK))
			dd_dev_err(dd, "%s:%d:%s() roce: port %d RcvEthRoceV2VrmaEnable did not clear (RcvIportCtrl=0x%016llx) - the next module inherits a stale placement gate\n",
				   __FILENAME__, __LINE__, __func__,
				   pidx, iport);
	}
}

/*
 * Program the EAL UDP destination-port table so RoCEv2 (port 4791, UDP) frames
 * get the context_info dst-port-match bit set on ingress, then hand RoCEv2
 * ingress to the hardware R_Key/RIF placement path.  ETH mode only.
 */
/*
 * With every RoCEv2 frame delivered to software, nothing is ever placed by
 * hardware, so the per-MR setup for it - PASID bind, R_Key entry, RIF arming -
 * is work with no effect.  It also needs PASID support the platform may not
 * have (the ACS quirk), so skipping it is what lets software RoCE run on a
 * stock kernel.
 */
bool hfi2_bulksvc_roce_by_software(const struct hfi2_devdata *dd)
{
	return !dd || !dd->bulksvc || dd->bulksvc->roce_by_software;
}

/*
 * roce_by_software=0 is an explicit request; quietly placing in software
 * instead hands back numbers that look like hardware placement and are not.
 */
int hfi2_bulksvc_roce_placement_unavailable(struct hfi2_devdata *dd,
					    const char *reason)
{
	dd_dev_err(dd,
		   "RoCE: roce_by_software=0 but hardware placement is unavailable (%s); load with roce_by_software=1 for software placement\n",
		   reason);
	return -EOPNOTSUPP;
}

/*
 * Hardware placement (roce_by_software=0) tags every placed packet with the
 * MR's PASID, so it needs PASID enabled on the device.  The IOMMU driver
 * enables it at probe, and Linux allows that only when the function and every
 * bridge to the root provide ACS isolation; CN6000 has no ACS capability, so a
 * kernel without the CN6000 ACS quirk (pci_quirk_mf_endpoint_acs) leaves
 * PASID disabled, as does a kernel with the IOMMU off.  The device's own DMA
 * domain does not matter: with the RID domain in identity mode a PASID still
 * translates through its own table (measured).  Without it no MR can bind a
 * PASID, nothing gets an R_Key entry or a RIF entry, and every multi-packet
 * WRITE to a hardware-placed MR has its LAST trimmed.  Refuse to load before
 * EAL is programmed.
 */
static int bulksvc_roce_check_placement(struct hfi2_devdata *dd)
{
	int status;

	if (hfi2_bulksvc_roce_by_software(dd))
		return 0;

	status = pci_pasid_status(dd->pcidev);
	if (status < 0)
		return hfi2_bulksvc_roce_placement_unavailable(dd,
							       "PASID unavailable");
	if (!(status & PCI_PASID_CTRL_ENABLE))
		return hfi2_bulksvc_roce_placement_unavailable(dd,
							       "PASID disabled");

	return 0;
}

static void bulksvc_roce_eal_configure(struct hfi2_devdata *dd)
{
	u64 reg = 0;

	EAL_DSTPORT_SET_PORT(reg, HFI2_ROCE_UDP_DPORT);
	EAL_DSTPORT_SET_TCP(reg, 0);
	EAL_DSTPORT_SET_VF_MASK(reg, 0xff);
	EAL_DSTPORT_SET_VALID(reg, 1);
	hfi2_write_csr(dd, CYR_EAL_DESTINATION_PORT_TABLE +
		  HFI2_BULKSVC_ROCE_UDP_DSTPORT_ENTRY * sizeof(u64), reg);

#if HFI2_BULKSVC_ULP_STUBS
	if (hfi2_bulksvc_eal_test_port_valid(dd->bulksvc)) {
		reg = 0;
		EAL_DSTPORT_SET_PORT(reg, hfi2_bulksvc_eal_test_udp_port);
		EAL_DSTPORT_SET_TCP(reg, 0);
		EAL_DSTPORT_SET_VF_MASK(reg, 0xff);
		EAL_DSTPORT_SET_VALID(reg, 1);
		hfi2_write_csr(dd, CYR_EAL_DESTINATION_PORT_TABLE +
			  HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY * sizeof(reg), reg);
		dd->bulksvc->eal_test_dstport_armed = true;
	}
#endif

	/* Clear stale controls across reloads; backend init sets rocev2_mtu. */
	reg = hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG);
	EAL_ROCEV2_CFG_SET_ROCE_BY_SOFTWARE(reg,
				       hfi2_bulksvc_roce_by_software(dd));
	EAL_ROCEV2_CFG_SET_ROCE_FIRST_BY_SOFTWARE(reg, 0);
	EAL_ROCEV2_CFG_SET_ROCE_LAST_BY_SOFTWARE(reg,
		hfi2_dms_roce_last_by_software());
	EAL_ROCEV2_CFG_SET_PSN_HDR_SUPPRESS_ENB(reg,
		!!hfi2_dms_roce_hdr_suppress());
	EAL_ROCEV2_CFG_SET_PSN_WR_HDR_COUNT(reg, hfi2_dms_roce_hdr_suppress());
	hfi2_write_csr(dd, CYR_EAL_ROCEV2_CFG, reg);

	/*
	 * Read back and report.  A field that failed to take leaves the
	 * accelerated path in a configuration nothing in the log describes,
	 * which is how bit 1 stayed hidden for two days.
	 *
	 * Assert all three software-diversion bits, not just bit 0.  A device
	 * that accepted the bit-0 clear but latched FIRST or LAST would place
	 * MIDDLEs and divert the ends, and the resulting half-accelerated
	 * transfer is the hardest failure here to attribute from a bandwidth
	 * number alone.
	 */
	reg = hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG);
	if (EAL_ROCEV2_CFG_GET_ROCE_BY_SOFTWARE(reg) !=
	    hfi2_bulksvc_roce_by_software(dd) ||
	    EAL_ROCEV2_CFG_GET_ROCE_FIRST_BY_SOFTWARE(reg) ||
	    EAL_ROCEV2_CFG_GET_ROCE_LAST_BY_SOFTWARE(reg) !=
		hfi2_dms_roce_last_by_software())
		dd_dev_err(dd,
			   "roce: EAL_ROCEV2_CFG read back 0x%llx; roce_by_software=%llu roce_first_by_software=%llu roce_last_by_software=%llu - the accelerated path is not in the configuration this driver programmed\n",
			   reg, EAL_ROCEV2_CFG_GET_ROCE_BY_SOFTWARE(reg),
			   EAL_ROCEV2_CFG_GET_ROCE_FIRST_BY_SOFTWARE(reg),
			   EAL_ROCEV2_CFG_GET_ROCE_LAST_BY_SOFTWARE(reg));

	bulksvc_roce_eal_grant_table_columns(dd);

	/*
	 * RcvIportCtrl bit 3 decides whether the receive pipeline honours an
	 * L4=0x7A VRMA header at all.  With it clear the frame reverts to
	 * RCV_TYPE_4 semantics and lands in the eager buffer with the address
	 * EAL computed discarded - no error, no counter, and an RHF that looks
	 * like ordinary bypass traffic.  It is programmed unconditionally
	 * rather than behind a parameter: an armed RIF entry with this bit
	 * clear is not a degraded configuration, it is a silently inert one.
	 */
	bulksvc_roce_enable_vrma_iport(dd);

	/*
	 * Report the value read back from the device, not the value this
	 * function meant to write.  The previous form hard-coded "1" into the
	 * text, so it kept claiming a configuration the driver had stopped
	 * programming - a log line that cannot disagree with the code is not
	 * evidence of anything.
	 */
	reg = hfi2_read_csr(dd, CYR_EAL_ROCEV2_CFG);
	dd_dev_dbg(dd,
		   "%s:%d:%s() roce: EAL dst-port CAM=%u, EAL_ROCEV2_CFG=0x%llx roce_by_software=%llu\n",
		   __FILENAME__, __LINE__, __func__, HFI2_ROCE_UDP_DPORT,
		   reg, EAL_ROCEV2_CFG_GET_ROCE_BY_SOFTWARE(reg));
}

/*
 * Compute the port enable mask (fabric + loopback bits) for RSM rules.
 */
static u8 bulksvc_rsm_port_mask(struct hfi2_devdata *dd)
{
	u8 port_mask = 0;

	for (int i = 0; i < dd->num_pports; ++i) {
		struct hfi2_pportdata *ppd = &dd->pport[i];

		BUG_ON(ppd == NULL);
		if (!port_available_ppd(ppd))
			continue;

		port_mask |= 1 << i;
		port_mask |= 1 << (i + dd->num_pports); // loopback port
	}
	return port_mask;
}

/*
 * Match on-load RoCEv2 bypass frames by their L4=ETH marker and EAL Type.
 * Type 1 context_info contains the destination QP, so none of its bits are a
 * stable protocol discriminator.  Keep the complete frame in the eager buffer.
 */
static void bulksvc_roce_fill_rsm_rule(struct rsm_rule_data *rrd, u16 offset,
				       u8 port_mask)
{
	rrd->rr_type = RR_TYPE_BYPASS;
	rrd->offset = offset;
	rrd->pidx_mask = port_mask;
	rrd->bypass_hdr_size = HFI2_ROCE_RSM_BYPASS_HDR_DWS;
	rrd->field1_off = HFI2_ROCE_RSM_L4_TYPE_OFFSET;
	rrd->mask1 = HFI2_ROCE_RSM_L4_TYPE_MASK;
	rrd->value1 = HFI2_ROCE_RSM_L4_ETH_VALUE;
	rrd->field2_off = EAL_INGRESS_TYPE_Q0_BIT;
	rrd->mask2 = HFI2_ROCE_RSM_EAL_TYPE_MASK;
	rrd->value2 = EAL_INGRESS_TYPE_ROCEV2;
	rrd->index1_off = HFI2_ROCE_RSM_QPN_LSB_OFFSET;
	rrd->index1_width = 1;
	rrd->index2_width = 0;
}

/*
 * The VRMA rule differs from the on-load rule in exactly two fields: the L4
 * value it matches, and the header size it splits at.  Deriving it from the
 * on-load filler keeps the EAL Type match, the port mask and the map-table
 * offset identical by construction, so the two rules cannot drift apart.
 */
static void bulksvc_roce_fill_vrma_rsm_rule(struct rsm_rule_data *rrd,
					    u16 offset, u8 port_mask)
{
	bulksvc_roce_fill_rsm_rule(rrd, offset, port_mask);
	rrd->value1 = HFI2_ROCE_RSM_L4_VRMA_VALUE;
	rrd->bypass_hdr_size = HFI2_ROCE_RSM_VRMA_BYPASS_HDR_DWS;
}

/*
 * Patch RcvRsmCfg.PacketType to 5 after add_rsm_rule() has written the rule.
 * add_rsm_rule() derives PacketType from enum rr_type, which has no type-5
 * member; adding one would require an RHF receive type that every dispatch
 * table in the driver treats as invalid.  Patching the field is the smaller
 * change and keeps the departure from the documented encoding in one place
 * with the RTL citation beside it.
 */
static void bulksvc_roce_patch_vrma_packet_type(struct hfi2_devdata *dd,
						int rule_index)
{
	u32 reg = dd->params->rcv_rsm_cfg_reg + (8 * rule_index);
	u64 cfg, readback;

	cfg = hfi2_read_csr(dd, reg);
	cfg &= ~(HFI2_ROCE_RSM_PACKET_TYPE_MASK <<
		 RCV_RSM_CFG_PACKET_TYPE_SHIFT);
	cfg |= HFI2_ROCE_RSM_VRMA_PACKET_TYPE << RCV_RSM_CFG_PACKET_TYPE_SHIFT;
	hfi2_write_csr(dd, reg, cfg);

	/*
	 * Read back rather than trust the write.  PacketType 5 is documented
	 * as reserved, so a device that rejected the value would leave the
	 * rule matching type 4 and every VRMA frame would miss RSM with no
	 * counter anywhere to say so.
	 */
	readback = hfi2_read_csr(dd, reg);
	if (((readback >> RCV_RSM_CFG_PACKET_TYPE_SHIFT) &
	     HFI2_ROCE_RSM_PACKET_TYPE_MASK) != HFI2_ROCE_RSM_VRMA_PACKET_TYPE)
		dd_dev_err(dd, "%s:%d:%s() bulksvc: VRMA RSM rule %d PacketType read back %llu, expected %llu - VRMA frames will not be steered\n",
			   __FILENAME__, __LINE__, __func__, rule_index,
			   (readback >> RCV_RSM_CFG_PACKET_TYPE_SHIFT) &
			   HFI2_ROCE_RSM_PACKET_TYPE_MASK,
			   HFI2_ROCE_RSM_VRMA_PACKET_TYPE);
}

static_assert(HFI2_BULKSVC_MAX_LANES <= (1u << HFI2_DMS_LANE_SEL_BITS),
	      "every lane needs a lane-selector value");

/*
 * Map table entries of the OPA DMS rule.  One lane: one entry and no index
 * extraction, so the rule is the single-DMS rule.  Several lanes: one entry
 * per lane-selector value, indexed by the selector's DST field (see dms.h);
 * entry i points at lane (i % num_lanes)'s ctrl context.
 */
static unsigned int bulksvc_dms_rsm_map_entries(u32 num_lanes)
{
	return num_lanes > 1 ? 1u << HFI2_DMS_LANE_SEL_BITS : 1;
}

static void bulksvc_dms_fill_rsm_rule(struct rsm_rule_data *rrd, u16 offset,
				      u8 port_mask, u32 num_lanes)
{
	rrd->rr_type = RR_TYPE_EAGER_16B;
	rrd->offset = offset;
	rrd->pidx_mask = port_mask;
	rrd->field1_off = HFI2_DMS_JKEY_OFFSET_LOWER;
	rrd->field2_off = HFI2_DMS_JKEY_OFFSET_UPPER;
	rrd->mask1 = 0xFF;
	rrd->value1 = HFI2_DMS_CTRL_JKEY & 0xFF;
	rrd->mask2 = 0xFF;
	rrd->value2 = (HFI2_DMS_CTRL_JKEY >> 8) & 0xFF;
	if (bulksvc_dms_rsm_map_entries(num_lanes) > 1) {
		rrd->index1_off = HFI2_DMS_LANE_SEL_RSM_OFFSET;
		rrd->index1_width = HFI2_DMS_LANE_SEL_BITS;
	}
}

#if HFI2_BULKSVC_ULP_STUBS
static void bulksvc_eth_fill_rsm_rule(struct hfi2_devdata *dd,
				      struct rsm_rule_data *rrd, u16 offset,
				      u8 port_mask)
{
	rrd->rr_type = RR_TYPE_BYPASS;
	rrd->offset = offset;
	rrd->pidx_mask = port_mask;
	/*
	 * BypassHdrSize is the HDRQ/eager split.  Size it to retain the EAL header,
	 * optional 12-byte timestamp, and Ethernet/IPv4/UDP headers for classification.
	 */
	rrd->bypass_hdr_size = hfi2_dms_eth_bypass_hdr_dws(dd);
	/*
	 * EAL Type 1 RoCEv2 frames also carry L4=ETH, and their context_info is
	 * the BTH destination QP rather than dst-port table metadata.  Match Type 0
	 * first so a RoCE QP bit pattern cannot steer an RDMA frame here.
	 *
	 * Matching Type == ETHERNET (0) excludes RoCEv2 (1) and other Type
	 * values before field2 is evaluated.
	 */
	rrd->field1_off = EAL_INGRESS_TYPE_Q0_BIT;
	rrd->mask1 = HFI2_ROCE_RSM_EAL_TYPE_MASK;
	rrd->value1 = EAL_INGRESS_TYPE_ETHERNET;
	/*
	 * Require both the L4 dest-port table match flag and this peer's matching
	 * entry index.  This is defense in depth: nonmatching-frame context_info
	 * contents are not yet hardware-verified, so matching only the shared flag
	 * is insufficient.
	 */
	rrd->field2_off = EAL_INGRESS_L4_DSTPORT_ENTRY_Q0_BIT;
	rrd->mask2 = HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_MASK;
	rrd->value2 = HFI2_BULKSVC_EAL_RSM_DSTPORT_MATCH_VALUE;
}
#endif

/*
 * Runs from hfi2_init_rxe(), after hfi2_bulksvc_init() fixed svc->num_lanes.
 * Every DMS map table entry points at an invalid context until
 * bulksvc_rsm_init() points them at the lanes.  In OPA mode the drop rule is
 * installed even when bulksvc is disabled (use_bulksvc=N) so stray DMS packets
 * from peers with bulksvc enabled are discarded instead of landing in the
 * default receive context.
 */
void bulksvc_rsm_reserve(struct hfi2_devdata *dd, struct rsm_map_table *rmt)
{
	struct hfi2_bulksvc *svc = dd->bulksvc;
	u32 const lanes = svc ? svc->num_lanes : 1;
	u16 invalid_ctxt = (u16)-1;
	struct rsm_rule_data rrd = {};
	u8 port_mask;
	unsigned int map_entries;
	int rule_index;
	u16 offset;

	dd->bulksvc_rsm_rule = -1;

	/*
	 * Without bulksvc an Ethernet PF has no RoCE: RoCEv2 frames are plain
	 * UDP for the network stack, not something to drop.
	 */
	if (!svc && hfi2_is_eth_mode(dd))
		return;

	map_entries = hfi2_is_eth_mode(dd) ? HFI2_DMS_ROCE_RCD_COUNT :
		      bulksvc_dms_rsm_map_entries(lanes);
	if (rmt->used + map_entries > dd->params->rsm_map_table_entries) {
		dd_dev_err(dd, "%s:%d:%s() bulksvc: insufficient RSM map entries for DMS\n",
			   __FILENAME__, __LINE__, __func__);
		return;
	}

	rule_index = alloc_rsm_rule(dd,
				    hfi2_is_eth_mode(dd) ? RR_TYPE_BYPASS :
				    RR_TYPE_EAGER_16B,
				    RSM_TYPE_BULKSVC);
	if (rule_index < 0)
		goto alloc_err;

	port_mask = bulksvc_rsm_port_mask(dd);
	offset = (u16)rmt->used;
	for (u32 i = 0; i < map_entries; i++)
		set_rmt_entry(dd, rmt, offset + i, invalid_ctxt);

	if (hfi2_is_eth_mode(dd))
		bulksvc_roce_fill_rsm_rule(&rrd, offset, port_mask);
	else
		bulksvc_dms_fill_rsm_rule(&rrd, offset, port_mask, lanes);
	add_rsm_rule(dd, rule_index, &rrd);
	dd->bulksvc_rsm_rule = rule_index;

	dd_dev_dbg(dd,
		   "%s:%d:%s() bulksvc: RSM rule %d for port mask 0x%x programmed to drop DMS packets\n",
		   __FILENAME__, __LINE__, __func__, rule_index, port_mask);

	if (svc) {
		dd_dev_dbg(dd,
			   "%s:%d:%s() bulksvc: Setting first RSM rule to %d\n",
			   __FILENAME__, __LINE__, __func__, rule_index);
		svc->first_rsm_rule = rule_index;
		svc->first_rsm_index = offset;
	}

	if (svc && hfi2_is_eth_mode(dd)) {
		int vrma_rule = alloc_rsm_rule(dd, RR_TYPE_BYPASS,
					       RSM_TYPE_BULKSVC);

		if (vrma_rule < 0) {
			dd_dev_err(dd, "%s:%d:%s() bulksvc: no RSM rule available for VRMA; direct placement will not engage\n",
				   __FILENAME__, __LINE__, __func__);
		} else {
			svc->vrma_rsm_rule = vrma_rule;
			dd_dev_dbg(dd,
				   "%s:%d:%s() bulksvc: VRMA RSM rule %d reserved at offset %u\n",
				   __FILENAME__, __LINE__, __func__,
				   vrma_rule, offset);
		}
	}

	rmt->used += map_entries;
#if HFI2_BULKSVC_ULP_STUBS
	/*
	 * RoCE uses HFI2_DMS_ROCE_RCD_COUNT slots; the optional EAL slot
	 * follows at rmt->used.  chip.c counts num_bulksvc_contexts from
	 * prereqs.num_rcv_ctxs, which includes the EAL RCD, in RMT capacity.
	 * The check below still guards the slot.
	 */
	if (svc && hfi2_is_eth_mode(dd) && hfi2_bulksvc_eal_test_udp_port_valid()) {
		u32 netdev_entries = 0;

		/* hfi2_init_rxe() reserves each port's netdev RMT block after bulksvc. */
		for (int i = 0; i < dd->num_pports; i++)
			if (port_available_ppd(&dd->pport[i]))
				netdev_entries += hfi2_map_entries(dd);
		if (rmt->used + 1 > dd->params->rsm_map_table_entries ||
		    rmt->used + 1 + netdev_entries > dd->params->rsm_map_table_entries)
			goto eth_alloc_err;

		rule_index = alloc_rsm_rule(dd, RR_TYPE_BYPASS, RSM_TYPE_BULKSVC);
		if (rule_index < 0)
			goto eth_alloc_err;

		offset = (u16)rmt->used;
		set_rmt_entry(dd, rmt, offset, invalid_ctxt);
		rrd = (struct rsm_rule_data){};
		bulksvc_eth_fill_rsm_rule(dd, &rrd, offset, port_mask);
		add_rsm_rule(dd, rule_index, &rrd);
		svc->eth_rsm_rule = rule_index;
		svc->eth_rsm_index = offset;
		rmt->used++;
	}
#endif
	return;

#if HFI2_BULKSVC_ULP_STUBS
eth_alloc_err:
	dd_dev_warn(dd, "%s:%d:%s() bulksvc: Failed to allocate optional eth/eal_test RSM rule; eal_test peer will not be steered (RoCE unaffected)\n",
		    __FILENAME__, __LINE__, __func__);
	return;
#endif

alloc_err:
	dd_dev_err(dd, "%s:%d:%s() bulksvc: Failed to allocate RSM rule for DMS\n",
		   __FILENAME__, __LINE__, __func__);
}

static void bulksvc_rsm_write_map_table(struct hfi2_devdata *dd, u16 idx, u16 value)
{
	u32 entries_per_csr = dd->params->rsm_map_table_entries_per_csr;
	u32 entry_mask = dd->params->rsm_map_table_entry_mask;
	u32 entry_shift = dd->params->rsm_map_table_entry_shift;
	int regoff = ((unsigned int)idx % entries_per_csr) * entry_shift;
	int regidx = ((unsigned int)idx) / entries_per_csr;
	u64 reg;

	reg = hfi2_read_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx));
	reg &= ~((u64)entry_mask << regoff);
	reg |= ((u64)(value & entry_mask)) << regoff;
	hfi2_write_csr(dd, dd->params->rcv_rsm_map_table_reg + (8 * regidx), reg);
}

int bulksvc_rsm_init(struct hfi2_bulksvc *svc)
{
	struct rsm_rule_data rrd = {};
	struct hfi2_devdata *dd;
	struct hfi2_ctxtdata *rcd[HFI2_DMS_ROCE_RCD_COUNT];
	u8 port_mask = 0;
	int rule_index;
	int ret = 0;
	u16 offset;

	BUG_ON(svc == NULL);
	BUG_ON(svc->dd == NULL);
	dd = svc->dd;

	if (svc->first_rsm_rule < 0 || svc->first_rsm_index < 0) {
		dd_dev_err(svc->dd, "%s:%d:%s() bulksvc: No RSM rules reserved, cannot initialize RSM\n",
			   __FILENAME__, __LINE__, __func__);
		return -ENOSPC;
	}

	mutex_lock(&hfi2_mutex);
	port_mask = bulksvc_rsm_port_mask(dd);

	if (hfi2_bulksvc_is_opa(svc)) {
		rcd[0] = hfi2_bulksvc_primary_dms(svc)->rcd_ctrl;
	} else {
		rcd[0] = svc->dms_roce->rcd[0];
		rcd[1] = svc->dms_roce->rcd[1];
		if (WARN_ON_ONCE(!rcd[0] || !rcd[1])) {
			/* Propagate failure so the caller tears down the backend. */
			ret = -ENODEV;
			goto unlock;
		}
	}

	offset = (u16)svc->first_rsm_index;
	rule_index = svc->first_rsm_rule;
	if (!hfi2_bulksvc_is_opa(svc)) {
		bulksvc_rsm_write_map_table(dd, offset, rcd[0]->ctxt);
		bulksvc_rsm_write_map_table(dd, offset + 1, rcd[1]->ctxt);
		bulksvc_roce_eal_configure(dd);
		bulksvc_roce_fill_rsm_rule(&rrd, offset, port_mask);
#if HFI2_BULKSVC_ULP_STUBS
		if (hfi2_bulksvc_eal_test_port_valid(svc)) {
			struct rsm_rule_data eth_rrd = {};
			u16 eth_offset = (u16)svc->eth_rsm_index;

			bulksvc_rsm_write_map_table(dd, eth_offset,
						    hfi2_bulksvc_primary_dms(svc)->rcd_ctrl->ctxt);
			bulksvc_eth_fill_rsm_rule(dd, &eth_rrd, eth_offset, port_mask);
			add_rsm_rule(dd, svc->eth_rsm_rule, &eth_rrd);
		}
#endif
	} else {
		u32 const entries = bulksvc_dms_rsm_map_entries(svc->num_lanes);

		/* lane selector i lands on lane i % num_lanes's ctrl context */
		for (u32 i = 0; i < entries; i++) {
			struct hfi2_dms *ldms = svc->lanes[i % svc->num_lanes].dms;

			bulksvc_rsm_write_map_table(dd, offset + i,
						    ldms->rcd_ctrl->ctxt);
		}
		bulksvc_dms_fill_rsm_rule(&rrd, offset, port_mask,
					  svc->num_lanes);
	}

	add_rsm_rule(svc->dd, rule_index, &rrd);

	/*
	 * Program the VRMA rule against the same map-table slot and context.
	 * PacketType has to be patched afterwards because add_rsm_rule()
	 * derives it from enum rr_type, which cannot express 5.
	 */
	if (!hfi2_bulksvc_is_opa(svc) && svc->vrma_rsm_rule >= 0) {
		struct rsm_rule_data vrma_rrd = {};

		bulksvc_roce_fill_vrma_rsm_rule(&vrma_rrd, offset, port_mask);
		add_rsm_rule(svc->dd, svc->vrma_rsm_rule, &vrma_rrd);
		bulksvc_roce_patch_vrma_packet_type(dd, svc->vrma_rsm_rule);
		dd_dev_dbg(dd,
			   "%s:%d:%s() bulksvc: VRMA RSM rule %d -> ctxts %u/%u (L4 0x%llx, hdr %llu DW, PacketType %llu)\n",
			   __FILENAME__, __LINE__, __func__,
			   svc->vrma_rsm_rule, rcd[0]->ctxt, rcd[1]->ctxt,
			   HFI2_ROCE_RSM_L4_VRMA_VALUE,
			   HFI2_ROCE_RSM_VRMA_BYPASS_HDR_DWS,
			   HFI2_ROCE_RSM_VRMA_PACKET_TYPE);
	}

	if (svc->backend == HFI2_BULKSVC_BACKEND_ETH_ROCE)
		svc->roce_rsm_programmed = true;

	dd_dev_dbg(dd,
		   "%s:%d:%s() bulksvc: RSM rule %d for port mask 0x%x registered at offset %u to ctxt %u\n",
		   __FILENAME__, __LINE__, __func__,
		   rule_index, port_mask, offset, rcd[0]->ctxt);

unlock:
	mutex_unlock(&hfi2_mutex);
	if (hfi2_bulksvc_is_opa(svc))
		dd_dev_dbg(dd,
			   "%s:%d:%s() bulksvc: Finished registering RSM rules for bulksvc\n",
			   __FILENAME__, __LINE__, __func__);
	return ret;
}

static void bulksvc_mmu_sync_drain_release(struct kref *ref)
{
	struct hfi2_bulksvc_mmu_sync_drain *sd =
		container_of(ref, struct hfi2_bulksvc_mmu_sync_drain, refcount);
	kfree(sd);
}

void hfi2_bulksvc_mmu_sync_drain_put(struct hfi2_bulksvc_mmu_sync_drain *sd)
{
	if (sd)
		kref_put(&sd->refcount, bulksvc_mmu_sync_drain_release);
}

void hfi2_bulksvc_schedule_lane(struct hfi2_bulksvc *svc, u32 lane)
{
	struct hfi2_bulksvc_lane *l = &svc->lanes[lane];

	if (!READ_ONCE(svc->stop_scheduling) && svc->event_workq)
		queue_work_on(l->cpu, svc->event_workq, &l->work);
}

void hfi2_bulksvc_schedule(struct hfi2_bulksvc *svc)
{
	if (WARN_ON(svc == NULL)) {
		return;
	}

	hfi2_bulksvc_schedule_lane(svc, HFI2_BULKSVC_PRIMARY_LANE);
}

/* Wake every lane: shared wake sources (doorbell, SDMA, progress timer) */
static void bulksvc_schedule_all(struct hfi2_bulksvc *svc)
{
	for (u32 k = 0; k < svc->num_lanes; k++)
		hfi2_bulksvc_schedule_lane(svc, k);
}

void hfi2_bulksvc_schedule_user(struct hfi2_bulksvc_user_info *user_info)
{
	hfi2_bulksvc_schedule_lane(user_info->svc, user_info->lane);
}

/*
 * Wake every lane, other than the primary lane, with a dirty client bound
 * to it.  The primary lane is woken by every doorbell (it re-arms it).
 */
static void bulksvc_wake_dirty_lanes(struct hfi2_bulksvc *svc)
{
	unsigned long *bitmap = svc->dirty_notify.bitmap;
	unsigned int const nw = READ_ONCE(svc->dirty_notify.num_bitmap_qwords);

	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_bulksvc_lane *l = &svc->lanes[k];
		bool wake = false;

		if (bulksvc_lane_is_primary(l))
			continue;
		for (unsigned int w = 0; !wake && w < nw; w++)
			wake = READ_ONCE(bitmap[w]) & READ_ONCE(l->client_bits[w]);
		if (wake)
			hfi2_bulksvc_schedule_lane(svc, k);
	}
}

/* Doorbell: the primary lane and every lane with a dirty client. */
static void bulksvc_doorbell_wake(struct hfi2_bulksvc *svc)
{
	hfi2_bulksvc_schedule(svc);
	bulksvc_wake_dirty_lanes(svc);
}

bool hfi2_bulksvc_requires_doorbell(struct hfi2_bulksvc *svc)
{
	bool polling_mode = get_bulksvc_polling(svc->dd);
	return !polling_mode;
}

/*
 * Queue a user-info event (add, release, MMU sync drain) of @user_info for
 * the worker of the client's DMS lane, which owns the client's DMS state,
 * and wake that worker.
 */
int hfi2_bulksvc_enqueue_user_event(struct hfi2_bulksvc_user_info *user_info,
				    struct hfi2_bulksvc_event_entry *entry)
{
	struct hfi2_bulksvc_lane *l;
	unsigned long flags;

	if (WARN_ON(!user_info || !entry))
		return -EINVAL;
	if (!hfi2_bulksvc_is_opa(user_info->svc) &&
	    entry->event.type != BULKSVC_EVENT_TYPE_SDMA)
		return -EOPNOTSUPP;

	l = &user_info->svc->lanes[user_info->lane];
	spin_lock_irqsave(&l->event_lock, flags);
	list_add_tail(&entry->list, &l->event_queue);
	spin_unlock_irqrestore(&l->event_lock, flags);
	/* event mode: a doorbell only wakes the lanes with a dirty client */
	hfi2_bulksvc_schedule_user(user_info);

	return 0;
}

static int get_bulksvc_cpu(struct hfi2_devdata *dd)
{
	int start = dd->unit;
	int cpu;

	/* check if enough elements are set for this unit's port */
	if (start >= bulksvc_cpu_count)
		return -1;

	cpu = bulksvc_cpu_array[start];
	if (cpu >= nr_cpu_ids || cpu < -1) {
		dd_dev_warn(dd, "bulksvc_cpu %d for unit %d invalid, ignoring value", cpu, start);
		cpu = -1;
	}
	return cpu;
}

static bool get_bulksvc_polling(struct hfi2_devdata *dd)
{
	int start = dd->unit;

	if (start >= bulksvc_polling_count)
		return false;

	return bulksvc_polling_array[start];
}

char* hfi2_bulksvc_prepare_debug_info(struct hfi2_bulksvc * const svc)
{
	struct hfi2_dms * const dms = hfi2_bulksvc_primary_dms(svc);

	if (!hfi2_bulksvc_is_opa(svc))
		return kasprintf(GFP_KERNEL,
			"Native DMS debug info unavailable\n"
			"  EAL Bypass Header Short Drop: ... %llu\n"
			"  EAL Bypass Egr Bounds Drop: ..... %llu\n"
			"  EAL Bypass Header Mismatch Drop: %llu\n"
			"  EAL Bypass ULP Build Drop: ...... %llu\n"
			"  EAL Bypass RHE Error Drop: ...... %llu\n"
			"  EAL Native16B In Eth Mode Drop: . %llu\n"
			"  EAL Fallthrough Bad RX Drop: ... %llu\n"
			"  EAL Fallthrough No Netdev Drop:  %llu\n",
			dms->counters.eal_bypass_header_short_drop,
			dms->counters.eal_bypass_egr_bounds_drop,
			dms->counters.eal_bypass_header_mismatch_drop,
			dms->counters.eal_bypass_ulp_build_drop,
			dms->counters.eal_bypass_rhe_error_drop,
			dms->counters.eal_native16b_in_eth_mode_drop,
			dms->counters.eal_fallthrough_bad_rx_drop,
			dms->counters.eal_fallthrough_no_netdev_drop);

	size_t const tot_size = 256 * PAGE_SIZE;
	char* res = kvzalloc(tot_size, GFP_KERNEL);
	if (!res) {
		return NULL;
	}

	char* cursor = res;
	char* end = res + tot_size;

	/*
	 * snprintf returns the length it WOULD have written, so a naive
	 * "cursor += snprintf(cursor, end - cursor, ...)" walks cursor past end
	 * once the dump exceeds tot_size; the next call then passes a negative
	 * (end - cursor) that converts to a huge size_t and trips vsnprintf's
	 * size > INT_MAX WARN. DBG_EMIT clamps every step to the remaining space
	 * and pins cursor at end once full, so the dump is safely truncated.
	 */
#define DBG_EMIT(...) do {						\
		size_t _rem = (size_t)(end - cursor);			\
		if (_rem == 0)						\
			break;						\
		int _n = snprintf(cursor, _rem, __VA_ARGS__);		\
		if (_n < 0)						\
			break;						\
		if ((size_t)_n >= _rem) {				\
			cursor = end;					\
			break;						\
		}							\
		cursor += (size_t)_n;					\
	} while (0)
#define LANE_SUM(field) ({						\
		u64 _sum = 0;						\
		for (u32 _k = 0; _k < svc->num_lanes; _k++)		\
			_sum += svc->lanes[_k].dms->counters.field;	\
		_sum;							\
	})

	DBG_EMIT("DMS Debug Info:\n");
	DBG_EMIT("Number of SDMA Engines: %u\n", dms->num_engines);

	DBG_EMIT("Free TID Sets Count: %u\n", _ring_size(&dms->free_tidsets.ring));

	DBG_EMIT("sdma_waiters: head=%p tail=%p\n", dms->sdma_waiters[HFI2_DMS_SDMA_ENGINE_IDX_ANY].waitlist.head, dms->sdma_waiters[HFI2_DMS_SDMA_ENGINE_IDX_ANY].waitlist.tail);

	DBG_EMIT("num sdma descs %u\n", dms->num_descs);

	static const char * const _health_state_names[] = {
		[HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_RIFT_ASSIGNMENT] = "WAIT_RIFT",
		[HFI2_DMS_HEALTH_WAITING_FOR_LOCAL_TIDSET_ALLOCATION] = "WAIT_TIDSET",
		[HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_START] = "WAIT_DATA_START",
		[HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_REQUEST] = "WAIT_DATA_REQ",
		[HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA] = "WAIT_DATA",
		[HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_DATA_SPECULATIVE] = "WAIT_DATA_SPEC",
		[HFI2_DMS_HEALTH_WAITING_FOR_REMOTE_ACK] = "WAIT_ACK",
		[HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START] = "WAIT_PARENT_WRITE_START",
		[HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_READ_START] = "WAIT_PARENT_READ_START",
		[HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START] = "WAIT_PARENT_DATA_START",
		[HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_DATA_START_LARGE] =
			"WAIT_PARENT_DATA_START_LG",
		[HFI2_DMS_HEALTH_WAITING_FOR_PARENT_AT_WRITE_START_PIO] =
			"WAIT_PARENT_WRITE_START_PIO",
	};

	DBG_EMIT("Rift:\n");
	for (int i = 0; i < HFI2_DMS_RIFT_IDX_SIZE; ++i) {
		union hfi2_dms_tracker* tracker = dms->rift.arr[i];
		if (!tracker) {
			continue;
		}
		hfi2_dms_rift_key_t const key = _rift_key_create(0, i);
		const char *hs = (tracker->hdr.health_state < HFI2_DMS_HEALTH_WAITING_COUNT)
			? _health_state_names[tracker->hdr.health_state]
			: "UNKNOWN";
		if (_rift_key_side_tx(key)) {
			if (tracker->tx.payload_remaining == 0) {
				DBG_EMIT("\tTracker %d: local_rift_key=%u remote_rift_key=%u remote_lid=%u op=%d health=%s - rift entry present but no remaining data\n",
					i, tracker->hdr.local_rift_key.value, tracker->hdr.remote_rift_key.value, tracker->hdr.remote_lid, tracker->tx.op, hs);

				continue;
			}
			DBG_EMIT("\tTracker %d: local_rift_key=%u remote_rift_key=%u remote_lid=%u op=%d health=%s total_payload=%u payload_remaining=%u xfer_start_byte_offset=%llu\n",
				i, tracker->hdr.local_rift_key.value, tracker->hdr.remote_rift_key.value, tracker->hdr.remote_lid, tracker->tx.op, hs, tracker->tx.total_payload, tracker->tx.payload_remaining, (unsigned long long)tracker->tx.xfer_start_byte_offset);

			switch (tracker->tx.op) {
				case HFI2_DMS_TX_TRACKER_OP_RDMA_WRITE:
					DBG_EMIT("\t\tWrite: mr=%p dms_key=%llu rx_offset=%llu flags=%u imm_data=%llu\n",
						 tracker->tx.write.page_provider.provider_ctx,
						 tracker->tx.write.dms_key.value,
						 tracker->tx.write.rx_offset,
						 tracker->tx.write.flags,
						 tracker->tx.write.imm_data);

					break;
				case HFI2_DMS_TX_TRACKER_OP_RDMA_READ:
					DBG_EMIT("\t\tRead: access=%p flags=%u imm_data=%llu",
						 tracker->tx.read.access,
						 tracker->tx.read.parameters.flags,
						 tracker->tx.read.parameters.imm_data);
					DBG_EMIT(" size_qw=%u rx_id=%u\n",
						 tracker->tx.read.metadata.size_qw,
						 tracker->tx.read.metadata.rx_id);

					break;
				default:
					break;
			}
		} else {	// rx
			if (tracker->rx.payload_remaining == 0) {
				DBG_EMIT("\tTracker %d: local_rift_key=%u remote_rift_key=%u remote_lid=%u op=%d health=%s - rift entry present but no remaining data\n",
					i, tracker->hdr.local_rift_key.value, tracker->hdr.remote_rift_key.value, tracker->hdr.remote_lid, tracker->rx.op, hs);

				continue;
			}
			DBG_EMIT("\tTracker %d: local_rift_key=%u remote_rift_key=%u remote_lid=%u",
				 i, tracker->hdr.local_rift_key.value,
				 tracker->hdr.remote_rift_key.value,
				 tracker->hdr.remote_lid);
			DBG_EMIT(" op=%d health=%s total_payload=%u payload_remaining=%u",
				 tracker->rx.op, hs, tracker->rx.total_payload,
				 tracker->rx.payload_remaining);
			DBG_EMIT(" sbuf_cursor=%u rbuf_start_offset=%llu\n",
				 tracker->rx.sbuf_cursor,
				 tracker->rx.rbuf_start_offset);

			switch (tracker->rx.op) {
				case HFI2_DMS_RX_TRACKER_OP_RDMA_READ:
					DBG_EMIT("\t\tRead: dms_key=%llu flags=%u imm_data=%llu\n",
						tracker->rx.read.dms_key.value, tracker->rx.read.flags, tracker->rx.read.imm_data);

					break;
				case HFI2_DMS_RX_TRACKER_OP_RDMA_WRITE:
					DBG_EMIT("\t\tWrite: access=%p flags=%u imm_data=%llu size=%u\n",
						tracker->rx.write.access, tracker->rx.write.metadata.flags, tracker->rx.write.parameters.imm_data, tracker->rx.write.parameters.xfer_size);

					break;
				default:
					break;
			}
		}
	}

	struct rb_node *node;
	struct hfi2_dms_client_state *client;

	for (node = rb_first(&dms->client_rbtree); node; node = rb_next(node)) {
		client = rb_entry(node, struct hfi2_dms_client_state, node);
		DBG_EMIT("Client: key=%u\n", client->key);

		int active_in_fast = 0;
		int tearing_down = 0;
		for (int i = 0; i < HFI2_DMS_MAX_ACCESS_FAST; ++i) {
			struct hfi2_dms_access *acc = client->access.arr[i];
			if (!acc)
				continue;
			active_in_fast++;
			if (acc->active_count > 0 ||
			    acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN) {
				const char *st = acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE
					? "ACTIVE"
					: acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN
						? "TEARDOWN"
						: "FREE";
				DBG_EMIT("\t  access[%d] dms_key=%llu state=%s active_count=%u unreg_started=%d\n",
					i, acc->dms_key.value, st, acc->active_count, acc->unregister_started);
				if (acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN)
					tearing_down++;
			}
		}
		DBG_EMIT("\tAccess Fast: count=%d tearing_down=%d\n",
			active_in_fast, tearing_down);

		int active_in_rbt = 0;
		struct rb_node *access_node;
		for (access_node = rb_first(&client->access.rbt); access_node; access_node = rb_next(access_node)) {
			struct hfi2_dms_access *acc = rb_entry(access_node, struct hfi2_dms_access, node);
			active_in_rbt++;
			if (acc->active_count > 0 ||
			    acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN) {
				const char *st = acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE
					? "ACTIVE"
					: acc->state == HFI2_DMS_ACCESS_STATE_ACTIVE_TEARDOWN
						? "TEARDOWN"
						: "FREE";
				DBG_EMIT("\t  access(rbt) dms_key=%llu state=%s active_count=%u unreg_started=%d\n",
					acc->dms_key.value, st, acc->active_count, acc->unregister_started);
			}
		}
		DBG_EMIT("\tAccess RBT: count=%d\n", active_in_rbt);

	}
	struct hfi2_bulksvc_user_info *user_info = NULL;
	mutex_lock(&svc->user_info_lock);
	list_for_each_entry(user_info, &svc->user_infos, list_entry) {
		int num_mr = 0;
		struct hfi2_bulksvc_user_mr_record *mr_record;
		struct hfi2_bulksvc_user_mr_access_record *mr_access_record;
		int num_mr_access = 0;

		/*
		 * This runs on the primary lane's worker; the MR and access
		 * lists of a client of another lane belong to that lane's
		 * worker, so do not walk them (-1).
		 */
		if (user_info->lane != HFI2_BULKSVC_PRIMARY_LANE) {
			num_mr = -1;
			num_mr_access = -1;
			goto emit;
		}
		list_for_each_entry(mr_record, &user_info->user_mr_list, list_entry) {
			num_mr++;
		}
		list_for_each_entry(mr_access_record, &user_info->active_access_list, list_entry) {
			num_mr_access++;
		}
emit:

		DBG_EMIT("User %u: lane %u\n", user_info->client_key, user_info->lane);
		DBG_EMIT("User %d Info: num_inflight: %d num_completion_overflows: %d num_mr: %d num_mr_access: %d eph_mr_deferred: %u eph_mr_create_fail: %u eph_mr_pin_fail: %u eph_mr_dispatch_fail: %u\n",
			user_info->client_key, user_info->num_inflight,
			user_info->num_completion_overflows, num_mr, num_mr_access,
			user_info->eph_mr_deferred_count,
			user_info->eph_mr_create_fail,
			user_info->eph_mr_pin_fail,
			user_info->eph_mr_dispatch_fail);

		for (int i = 0; i < user_info->num_cmplqs; ++i) {
			struct hfi2_bulksvc_queue_record *rec =
				&user_info->cmplq_records[i];

			DBG_EMIT("\tCMPLQ %d: head=%llu tail=%llu credits=%u/%u\n",
				 i, atomic64_read(rec->head), atomic64_read(rec->tail),
				 rec->max_inflight - min(rec->inflight, rec->max_inflight),
				 rec->max_inflight);
		}
		for (int i = 0; i < user_info->num_cmdqs; ++i) {
			DBG_EMIT("\tCMDQ %d: head=%llu tail=%llu\n", i, atomic64_read(user_info->cmdq_records[i].head), atomic64_read(user_info->cmdq_records[i].tail));
		}
	}
	mutex_unlock(&svc->user_info_lock);

	DBG_EMIT("Verbs ring_full_deferrals: %llu\n",
		atomic64_read(&svc->verbs_state.ring_full_deferrals));

	DBG_EMIT("Verbs cmd_queue: %d pending\n",
		atomic_read(&svc->verbs_state.cmd_queue.depth));

	{
		static const char * const qp_state_names[] = {
			[IB_QPS_RESET] = "RESET",
			[IB_QPS_INIT]  = "INIT",
			[IB_QPS_RTR]   = "RTR",
			[IB_QPS_RTS]   = "RTS",
			[IB_QPS_SQD]   = "SQD",
			[IB_QPS_SQE]   = "SQE",
			[IB_QPS_ERR]   = "ERR",
		};
		struct hfi2_bulksvc_qp_info *qpi;

		mutex_lock(&svc->verbs_state.qp_infos_lock);
		list_for_each_entry(qpi, &svc->verbs_state.qp_infos, node) {
			struct rvt_qp *qp = qpi->owner;

			/*
			 * A qp_info is published with a NULL owner and is
			 * cleared again on teardown, so this diagnostic walk
			 * can observe either edge.  Skip, as the other
			 * qp_infos walkers do.
			 */
			if (!qp)
				continue;

			u32 qpn = qp->ibqp.qp_num;
			enum ib_qp_state st = qp->state;
			const char *st_name = (st <= IB_QPS_ERR)
				? qp_state_names[st] : "???";
			u64 full_def = atomic64_read(&qpi->inflight_full_deferrals);

			/*
			 * This runs on the primary lane's worker.  The ordering
			 * and deferral lists of a QP on another lane belong to
			 * that lane's worker, which frees their entries, so
			 * only count them for primary-lane QPs (else -1).
			 */
			bool own_lane = qpi->lane == HFI2_BULKSVC_PRIMARY_LANE;
			int ord_pending = own_lane ? 0 : -1;
			int deferred = own_lane ? 0 : -1;
			struct verbs_ordered_wr *ow;
			struct verbs_deferred_wr *dw;

			if (own_lane) {
				list_for_each_entry(ow, &qpi->ordering.pending, node)
					ord_pending++;
				list_for_each_entry(dw, &qpi->deferred_wrs, list)
					deferred++;
			}

			/*
			 * bulksvc_gated is normally protected by qp->s_lock; this
			 * is a diagnostic walk under qp_infos_lock only and may
			 * race with set/clear sites.  READ_ONCE keeps KCSAN quiet.
			 */
			bool gated_snap = READ_ONCE(qpi->bulksvc_gated);

			DBG_EMIT("  QP 0x%x: state=%s hotpath_inflight=%u rvt_rdma_ops_sched=%u"
				" ordering(issue=%llu deliver=%llu pending=%d)"
				" deferred=%d inflight_ring(head=%u tail=%u)"
				" ring_full_deferrals=%llu"
				" bulksvc_gated=%d\n",
				qpn, st_name,
				qpi->bts_path_inflight_bts,
				qpi->rvt_rdma_ops_sched,
				qpi->ordering.next_issue_seq,
				qpi->ordering.next_deliver_seq,
				ord_pending,
				deferred,
				qpi->inflight_head, qpi->inflight_tail,
				full_def,
				gated_snap);

			/* dump individual pending entry seq numbers */
			if (ord_pending > 0) {
				DBG_EMIT("    pending seqs:");
				list_for_each_entry(ow, &qpi->ordering.pending, node) {
					DBG_EMIT(" %llu(%s)", ow->seq,
						ow->type == ORDERED_WR_RDMAVT
							? "rvt" : "hp");
				}
				DBG_EMIT("\n");
			}
		}
		mutex_unlock(&svc->verbs_state.qp_infos_lock);
	}

	int rift_counts[HFI2_DMS_XFER_TYPE_COUNT][HFI2_DMS_XFER_SIDE_COUNT] = {{0}};
	for (enum hfi2_dms_xfer_type t = 0; t < HFI2_DMS_XFER_TYPE_COUNT; ++t) {
		for (enum hfi2_dms_xfer_side s = 0; s < HFI2_DMS_XFER_SIDE_COUNT; ++s) {
			struct hfi2_dms_dlist_element *curd = dms->rift.type[t].side[s].waitlist.head;
			while (curd != NULL) {
				rift_counts[t][s]++;
				curd = curd->next;
			}
		}
	}
	DBG_EMIT("Rift Waitlists: Target(RX=%d TX=%d) Initiator(RX=%d TX=%d)\n",
		rift_counts[HFI2_DMS_XFER_TYPE_TARGET][HFI2_DMS_XFER_SIDE_RX],
		rift_counts[HFI2_DMS_XFER_TYPE_TARGET][HFI2_DMS_XFER_SIDE_TX],
		rift_counts[HFI2_DMS_XFER_TYPE_INITIATOR][HFI2_DMS_XFER_SIDE_RX],
		rift_counts[HFI2_DMS_XFER_TYPE_INITIATOR][HFI2_DMS_XFER_SIDE_TX]);

#if HFI2_DMS_COUNTERS_ENABLE
	DBG_EMIT("DMS Counters:\n");
	for (enum hfi2_dms_xfer_type t = 0; t < HFI2_DMS_XFER_TYPE_COUNT; ++t) {
		DBG_EMIT("  %s:\n", t == HFI2_DMS_XFER_TYPE_INITIATOR ? "Initiator" : "Target");

		for (enum hfi2_dms_xfer_op o = 0; o < HFI2_DMS_XFER_OP_COUNT; ++o) {
			u64 ns;
			DBG_EMIT("    %s:\n", o == HFI2_DMS_XFER_OP_READ ? "RDMA Read" : "RDMA Write");
			struct dms_perf_counters * perf = &dms->counters.perf[t][o];

			DBG_EMIT("      Total Transfers: ......... %llu\n", perf->transfers);
			DBG_EMIT("      Total Bytes: ............. %llu\n", perf->bytes);

			u64 const total_ns = ktime_to_ns(perf->total_time);
			ns = perf->transfers == 0 ? 0 : total_ns / perf->transfers;
			DBG_EMIT("      Total Transfer Time (ns):  %llu, %llu\n", total_ns, ns);

			u64 const rift_wait_ns = ktime_to_ns(perf->rift_wait_time);
			ns = perf->transfers == 0 ? 0 : rift_wait_ns / perf->transfers;
			DBG_EMIT("      Total Rift Wait Time (ns): %llu, %llu\n", rift_wait_ns, ns);

			u64 gbps = total_ns == 0 ? 0 : (perf->bytes * 8) / total_ns;
			DBG_EMIT("      Bandwidth (gbps): ........ %llu\n", gbps);
		}
	}
#endif

	{
		static const char * const msg_type_names[HFI2_DMS_MSG_TYPE_COUNT] = {
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
		int i;

		DBG_EMIT("Counters below: sum of %u lane(s); state above: lane 0\n",
			 svc->num_lanes);
		DBG_EMIT("DMS TX/RX Packet Counters (always-on):\n");
		DBG_EMIT("  %-24s %14s %14s %14s\n", "Type", "TX Sent", "RX Recv", "Diff");
		for (i = 0; i < HFI2_DMS_MSG_TYPE_COUNT; i++) {
			u64 const tx = LANE_SUM(tx_sent[i]);
			u64 const rx = LANE_SUM(rx_received[i]);

			DBG_EMIT("  %-24s %14llu %14llu %14lld\n",
				 msg_type_names[i], tx, rx, (s64)(tx - rx));
		}
	}

	DBG_EMIT("DMS Health Counters:\n");
	DBG_EMIT("  Tidset Draining: ................. %llu\n", LANE_SUM(health_tidset_draining));
	DBG_EMIT("  Tidset Drain Reinject: ........... %llu\n",
		 LANE_SUM(health_tidset_drain_reinject));
	DBG_EMIT("  Tidset Drain Reinject Fail: ...... %llu\n",
		 LANE_SUM(health_tidset_drain_reinject_fail));
	DBG_EMIT("  Tidset Drain Failed: ............. %llu\n",
		 LANE_SUM(health_tidset_drain_failed));
	DBG_EMIT("  Tidset Disabled Removed: ......... %llu\n",
		 LANE_SUM(health_tidset_disabled_removed));
	DBG_EMIT("  Status Req Injected: ............. %llu\n",
		 LANE_SUM(health_status_req_injected));
	DBG_EMIT("  Status Req Packets: .............. %llu\n",
		 LANE_SUM(health_status_req_packets));
	DBG_EMIT("  Status Rsp Waiting Rift: ......... %llu\n",
		 LANE_SUM(health_status_rsp_waiting_rift));
	DBG_EMIT("  Status Rsp Waiting Tidset: ....... %llu\n",
		 LANE_SUM(health_status_rsp_waiting_tidset));
	DBG_EMIT("  Status Rsp In Progress: .......... %llu\n",
		 LANE_SUM(health_status_rsp_in_progress));
	DBG_EMIT("  Status Rsp Complete: ............. %llu\n",
		 LANE_SUM(health_status_rsp_complete));
	DBG_EMIT("  Status Rsp Complete (Transient): . %llu\n",
		 LANE_SUM(health_status_rsp_complete_transient));
	DBG_EMIT("  Status Rsp Not Started: .......... %llu\n",
		 LANE_SUM(health_status_rsp_not_started));
	DBG_EMIT("  Status Rsp Not Found: ............ %llu\n",
		 LANE_SUM(health_status_rsp_not_found));
	DBG_EMIT("  Status Rsp Cancelled: ............ %llu\n",
		 LANE_SUM(health_status_rsp_cancelled));
	DBG_EMIT("  Tracker Dead: .................... %llu\n", LANE_SUM(health_tracker_dead));
	DBG_EMIT("  Fast-Fail Cancel: ................ %llu\n", LANE_SUM(health_fast_fail_cancel));
	DBG_EMIT("  NACK Sent: ....................... %llu\n", LANE_SUM(health_nack_sent));
	DBG_EMIT("  SEND Replay Re-ACK: .............. %llu\n", LANE_SUM(health_send_replay_reack));
	DBG_EMIT("  Invalid Client: .................. %llu\n", LANE_SUM(health_invalid_client));
	DBG_EMIT("  Invalid Rift Key: ................ %llu\n", LANE_SUM(health_invalid_rift_key));
	DBG_EMIT("  Remaining QWs Underflow: ......... %llu\n",
		 LANE_SUM(health_remaining_qws_underflow));
	DBG_EMIT("  Invalid DATA_REQUEST: ............ %llu\n",
		 LANE_SUM(health_invalid_data_request));
	DBG_EMIT("  Bounce Scatter Fail: ............. %llu\n",
		 LANE_SUM(health_bounce_scatter_fail));
	DBG_EMIT("  Tidset Run Fetch Fail: ........... %llu\n",
		 LANE_SUM(health_tidset_run_fail));
	DBG_EMIT("  TX Payload Underflow: ............ %llu\n",
		 LANE_SUM(health_tx_payload_underflow));
	DBG_EMIT("  RNR NACK Sent: ................... %llu\n", LANE_SUM(rnr_nack_sent));
	DBG_EMIT("  RNR NACK Retries: ................ %llu\n", LANE_SUM(rnr_nack_retries));
	DBG_EMIT("  RNR NACK Deferred: ............... %llu\n", LANE_SUM(rnr_nack_deferred));
	DBG_EMIT("  Deferred Pool Add: ............... %llu\n", LANE_SUM(access_deferred_count));
	DBG_EMIT("  Deferred Pool Retry OK: .......... %llu\n", LANE_SUM(access_deferred_retry_ok));
	DBG_EMIT("  Deferred Pool NACK: .............. %llu\n", LANE_SUM(access_deferred_nack));
	DBG_EMIT("  Deferred Pool NACK (Fatal): ...... %llu\n",
			  LANE_SUM(access_deferred_nack_fatal));
	DBG_EMIT("  Deferred Pool Full: .............. %llu\n", LANE_SUM(access_deferred_full));
	DBG_EMIT("  Deferred Pool Pending Cmd Found: . %llu\n",
		 LANE_SUM(access_deferred_pending_cmd_found));
	DBG_EMIT("  Deferred Pool Pending Cmd Not Found: %llu\n",
		 LANE_SUM(access_deferred_pending_cmd_not_found));
	DBG_EMIT("  RNR Duplicate Start: ............. %llu\n", LANE_SUM(rnr_duplicate_start));
	DBG_EMIT("  Duplicate DATA_START: ........... %llu\n",
		 LANE_SUM(health_duplicate_data_start));
	DBG_EMIT("  Zero-size Drop: ................. %llu\n",
			  LANE_SUM(health_zero_size_drop));
	DBG_EMIT("  Short-packet Drop: .............. %llu\n",
			  LANE_SUM(health_short_packet_drop));
	DBG_EMIT("  EAL Bypass Header Short Drop: ... %llu\n",
		 LANE_SUM(eal_bypass_header_short_drop));
	DBG_EMIT("  EAL Bypass Egr Bounds Drop: ..... %llu\n",
		 LANE_SUM(eal_bypass_egr_bounds_drop));
	DBG_EMIT("  EAL Bypass Header Mismatch Drop: %llu\n",
		 LANE_SUM(eal_bypass_header_mismatch_drop));
	DBG_EMIT("  EAL Bypass ULP Build Drop: ...... %llu\n",
		 LANE_SUM(eal_bypass_ulp_build_drop));
	DBG_EMIT("  EAL Bypass RHE Error Drop: ...... %llu\n",
		 LANE_SUM(eal_bypass_rhe_error_drop));
	DBG_EMIT("  EAL Native16B In Eth Mode Drop: . %llu\n",
		 LANE_SUM(eal_native16b_in_eth_mode_drop));
	DBG_EMIT("  EAL Fallthrough Bad RX Drop: ... %llu\n",
		 LANE_SUM(eal_fallthrough_bad_rx_drop));
	DBG_EMIT("  EAL Fallthrough No Netdev Drop:  %llu\n",
		 LANE_SUM(eal_fallthrough_no_netdev_drop));
	DBG_EMIT("DMS Eager Counters:\n");
	DBG_EMIT("  DMS Eager PIO TX: ................ %llu\n", LANE_SUM(eager_tx));
	DBG_EMIT("  DMS Eager SDMA TX: ............... %llu\n", LANE_SUM(eager_sdma_tx));
	DBG_EMIT("  DMS Eager RX: .................... %llu\n", LANE_SUM(eager_rx));
	DBG_EMIT("  DMS Eager RX Keyless: ............ %llu\n", LANE_SUM(eager_rx_keyless));
	DBG_EMIT("  PIO Waiter Stale: ................ %llu\n", LANE_SUM(pio_waiter_stale));
	DBG_EMIT("  DMS Eager PIO Queued: ............ %llu\n", LANE_SUM(eager_pio_queued));
	DBG_EMIT("  SDMA No-Engine Fallback: ........ %llu\n", LANE_SUM(sdma_no_engine_fallback));
	DBG_EMIT("  SDMA Req Batched: ............... %llu\n", LANE_SUM(sdma_req_batched));
	DBG_EMIT("  SDMA Req Parked: ................ %llu\n", LANE_SUM(sdma_req_parked));
	DBG_EMIT("  SDMA Req Fallback Per-Chunk: .... %llu\n",
		 LANE_SUM(sdma_req_fallback_per_chunk));
#if HFI2_DMS_RHF_TEST_ENABLE
	DBG_EMIT("DMS RHF Test Counters (host-delivered valid native 16B):\n");
	for (u32 i = 0; i < HFI2_PBC_TEST_NCNTR; ++i)
		DBG_EMIT("  RhfTest%u: ........................ %llu\n",
			 i, LANE_SUM(rhf_test[i]));
#endif
	DBG_EMIT("DMS SDMA Engine Selection (entropy spread):\n");
	for (s32 i = 0; i < dms->num_engines; ++i)
		DBG_EMIT("  engine[%d]: ...................... %llu\n",
			 i, LANE_SUM(sdma_engine_select[i]));

	DBG_EMIT("DMS Access Xfer Counters:\n");
	DBG_EMIT("  access_xfer_begin: ............... %llu\n", LANE_SUM(access_xfer_begin));
	DBG_EMIT("  access_xfer_end: ................. %llu\n", LANE_SUM(access_xfer_end));
	DBG_EMIT("  access_xfer_end_teardown: ........ %llu\n", LANE_SUM(access_xfer_end_teardown));
	DBG_EMIT("  access_busy_live_dup: ............ %llu\n", LANE_SUM(access_busy_live_dup));
	DBG_EMIT("  reinject_data_start: ............. %llu\n", LANE_SUM(reinject_data_start));
	DBG_EMIT("  write_start_dup_mismatch: ........ %llu\n", LANE_SUM(write_start_dup_mismatch));
	DBG_EMIT("  rsp_not_found_tidset_wait: ....... %llu\n",
		 LANE_SUM(health_status_rsp_not_found_tidset_wait));
	{
		/* Other lanes keep counting: read end first, never wrap. */
		u64 xfer_end = LANE_SUM(access_xfer_end);
		u64 xfer_begin = LANE_SUM(access_xfer_begin);

		DBG_EMIT("  in_flight (begin - end): ......... %llu\n",
			 xfer_begin > xfer_end ? xfer_begin - xfer_end : 0);
	}
	DBG_EMIT("  trackers_cancelled_tx: ........... %llu\n", LANE_SUM(trackers_cancelled_tx));
	DBG_EMIT("  trackers_cancelled_rx: ........... %llu\n", LANE_SUM(trackers_cancelled_rx));
	DBG_EMIT("  cancel_by_handle_success: ........ %llu\n", LANE_SUM(cancel_by_handle_success));
	DBG_EMIT("  cancel_by_handle_notfound: ....... %llu\n",
		 LANE_SUM(cancel_by_handle_notfound));
	DBG_EMIT("Bulksvc Chain Ordering Counters:\n");
	DBG_EMIT("  chain_successfully_attached: .................. %llu\n",
		 LANE_SUM(chain_successfully_attached));
	DBG_EMIT("  chain_parent_done_before_bind: ....... %llu\n",
		 LANE_SUM(chain_parent_done_before_bind));
	DBG_EMIT("  chain_parked_write_start: .............. %llu\n",
		 LANE_SUM(chain_parked_write_start));
	DBG_EMIT("  chain_parked_read: ............... %llu\n", LANE_SUM(chain_parked_read));
	DBG_EMIT("  chain_released_write: ............ %llu\n", LANE_SUM(chain_released_write));
	DBG_EMIT("  chain_released_write_ack: ........ %llu\n",
		 LANE_SUM(chain_released_write_ack));
	DBG_EMIT("  chain_released_write_start_early: %llu\n",
		 LANE_SUM(chain_released_write_start_early));
	DBG_EMIT("  chain_released_write_pio_bind: ... %llu\n",
		 LANE_SUM(chain_released_write_pio_bind));
	DBG_EMIT("  chain_released_write_pio_self_start: %llu\n",
		 LANE_SUM(chain_released_write_pio_self_start));
	DBG_EMIT("  chain_released_write_pio_ack: .... %llu\n",
		 LANE_SUM(chain_released_write_pio_ack));
	DBG_EMIT("  chain_released_write_pio_parked: . %llu\n",
		 LANE_SUM(chain_released_write_pio_parked));
	DBG_EMIT("  chain_released_read: ............. %llu\n", LANE_SUM(chain_released_read));
	DBG_EMIT("  chain_parked_read_at_data_start: ... %llu\n",
		 LANE_SUM(chain_parked_read_at_data_start));
	DBG_EMIT("  chain_released_read_at_data_start: %llu\n",
		 LANE_SUM(chain_released_read_at_data_start));
	DBG_EMIT("  chain_released_read_at_data_start_large: %llu\n",
		 LANE_SUM(chain_released_read_at_data_start_large));
	DBG_EMIT("  chain_released_read_at_data_start_raw: %llu\n",
		 LANE_SUM(chain_released_read_at_data_start_raw));
	DBG_EMIT("  chain_resume_deferred_waiter: ..... %llu\n",
		 LANE_SUM(chain_resume_deferred_waiter));
	DBG_EMIT("  chain_child_self_start: ................ %llu\n",
		 LANE_SUM(chain_child_self_start));
	DBG_EMIT("  chain_attach_after_signal: ....... %llu\n",
		 LANE_SUM(chain_attach_after_signal));
	DBG_EMIT("  chain_release_inject_fail: ....... %llu\n",
		 LANE_SUM(chain_release_inject_fail));
	DBG_EMIT("  chain_null_handle: .............. %llu\n", LANE_SUM(chain_null_handle));
	DBG_EMIT("  chain_attach_child_conflict: .. %llu\n", LANE_SUM(chain_attach_child_conflict));
	DBG_EMIT("  chain_parked_on_parent_error: . %llu\n",
		 LANE_SUM(chain_parked_on_parent_error));
	DBG_EMIT("BTS In-flight Cancel Counters:\n");
	DBG_EMIT("  bts_inflight_cancel_events: ........... %llu\n",
		 LANE_SUM(bts_inflight_cancel_events));
	DBG_EMIT("  bts_inflight_cancel_siblings: ......... %llu\n",
		 LANE_SUM(bts_inflight_cancel_siblings));
	DBG_EMIT("  bts_inflight_cancel_already_gone: ..... %llu\n",
		 LANE_SUM(bts_inflight_cancel_already_gone));
	DBG_EMIT("  bts_inflight_cancel_failed: ........... %llu\n",
		 LANE_SUM(bts_inflight_cancel_failed));
	DBG_EMIT("Go-Back-N Counters:\n");
	DBG_EMIT("  health_fast_fail_cancel: ......... %llu\n", LANE_SUM(health_fast_fail_cancel));
	DBG_EMIT("  status_probe_target_read_stale: .. %llu\n",
		 LANE_SUM(health_status_req_fast_fail_read_target));
	DBG_EMIT("  health_status_rsp_parked: ........ %llu\n",
		 LANE_SUM(health_status_rsp_parked));
	DBG_EMIT("  gbn_windows_armed: ............... %llu\n", LANE_SUM(gbn_windows_armed));
	DBG_EMIT("  gbn_provider_claimed: ............. %llu\n", LANE_SUM(gbn_provider_claimed));
	DBG_EMIT("  gbn_wrs_replayed: ................ %llu\n", LANE_SUM(gbn_wrs_replayed));
	DBG_EMIT("  gbn_wrs_dropped: ................. %llu\n", LANE_SUM(gbn_wrs_dropped));
	DBG_EMIT("  gbn_intercept_declined: .......... %llu\n", LANE_SUM(gbn_intercept_declined));
	DBG_EMIT("  gbn_teardown_freed: .............. %llu\n", LANE_SUM(gbn_teardown_freed));
	DBG_EMIT("  gbn_teardown_active_cancelled: ... %llu\n",
		 LANE_SUM(gbn_teardown_active_cancelled));
	DBG_EMIT("  gbn_teardown_active_already_gone:  %llu\n",
		 LANE_SUM(gbn_teardown_active_already_gone));
	DBG_EMIT("  gbn_teardown_active_cancel_failed: %llu\n",
		 LANE_SUM(gbn_teardown_active_cancel_failed));
	DBG_EMIT("  gbn_drop_qp_errored: ............. %llu\n", LANE_SUM(gbn_drop_qp_errored));
	DBG_EMIT("  gbn_drop_mr_gone: ................ %llu\n", LANE_SUM(gbn_drop_mr_gone));
	DBG_EMIT("  gbn_suffix_prefix_spared: ........ %llu\n", LANE_SUM(gbn_suffix_prefix_spared));
	DBG_EMIT("  gbn_rx_stale_dropped: ............ %llu\n", LANE_SUM(gbn_rx_stale_dropped));
	DBG_EMIT("  gbn_rx_dup_suppressed: ........... %llu\n", LANE_SUM(gbn_rx_dup_suppressed));
	DBG_EMIT("  cqe_rx_out_of_order: ............. %llu\n", LANE_SUM(cqe_rx_out_of_order));
	DBG_EMIT("  cqe_tx_out_of_order: ............. %llu\n", LANE_SUM(cqe_tx_out_of_order));
	DBG_EMIT("  held_for_ordering_armed: ......... %llu\n",
		 LANE_SUM(held_for_ordering_armed));
	DBG_EMIT("  held_for_ordering_faulted: ....... %llu\n",
		 LANE_SUM(held_for_ordering_faulted));
	DBG_EMIT("  held_for_ordering_replayed: ...... %llu\n",
		 LANE_SUM(held_for_ordering_replayed));
	DBG_EMIT("Bulksvc Kworker Counters (bulksvc_worker_stats=%c):\n",
		 bulksvc_worker_stats() ? 'Y' : 'N');
	DBG_EMIT("  kworker_cpu_ns: .................. %llu\n", LANE_SUM(kworker_cpu_ns));
	DBG_EMIT("  kworker_resched_saturated: ....... %llu\n",
		 LANE_SUM(kworker_resched_saturated));
	DBG_EMIT("  kworker_resched_final_check: ..... %llu\n",
		 LANE_SUM(kworker_resched_final_check));
	DBG_EMIT("  kworker_halt_poll_success: ....... %llu\n",
		 LANE_SUM(kworker_halt_poll_success));
	DBG_EMIT("  kworker_halt_poll_wait_ns: ....... %llu\n",
		 LANE_SUM(kworker_halt_poll_wait_ns));
	DBG_EMIT("  halt_poll_ns (current window): ... %u\n",
		 svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].halt_poll_ns);
	DBG_EMIT("  kworker_loops_last (lane 0): ..... %llu\n", dms->counters.last_nloops);
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_bulksvc_lane const *l = &svc->lanes[k];
		struct hfi2_dms const *ldms = l->dms;

		if (!l->dms_up)
			continue;
		DBG_EMIT("  lane%u cpu %d worker_cpu_ns: ..... %llu\n", k,
			 l->cpu, ldms->counters.kworker_cpu_ns);
		DBG_EMIT("  lane%u bound user clients: ....... %u\n", k,
			 READ_ONCE(l->nr_clients));
		DBG_EMIT("  lane%u verbs cmds pending: ....... %d\n", k,
			 atomic_read(&l->cmdq->depth));
		DBG_EMIT("  lane%u tx_sent write_start/data_start/ack: %llu/%llu/%llu\n", k,
			 ldms->counters.tx_sent[HFI2_DMS_MSG_TYPE_WRITE_START],
			 ldms->counters.tx_sent[HFI2_DMS_MSG_TYPE_DATA_START],
			 ldms->counters.tx_sent[HFI2_DMS_MSG_TYPE_ACK]);
		DBG_EMIT("  lane%u rx_received write_start/ack: %llu/%llu\n", k,
			 ldms->counters.rx_received[HFI2_DMS_MSG_TYPE_WRITE_START],
			 ldms->counters.rx_received[HFI2_DMS_MSG_TYPE_ACK]);
		DBG_EMIT("  lane%u read_start tx/rx: %llu/%llu\n", k,
			 ldms->counters.tx_sent[HFI2_DMS_MSG_TYPE_READ_START],
			 ldms->counters.rx_received[HFI2_DMS_MSG_TYPE_READ_START]);
	}

	DBG_EMIT("\n--- Pin Lists ---\n");
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_bulksvc_pin_lists const *pins = &svc->lanes[k].pins;

		DBG_EMIT("  Lane %u:\n", k);
		DBG_EMIT("  Speculative Depth: ............... %u\n",
			 pins->speculative_count);
		DBG_EMIT("  Active Depth: .................... %u\n",
			 pins->active_count);
		DBG_EMIT("  Pages Pinned (Inline): ........... %llu\n",
			 pins->pages_pinned_inline);
		DBG_EMIT("  Pages Pinned (Proactive): ............ %llu\n",
			 pins->pages_pinned_proactive);
		DBG_EMIT("  Inline Pin Count: ................ %llu\n",
			 pins->inline_pin_count);
		DBG_EMIT("  Proactive Pin Ops: ................... %llu\n",
			 pins->proactive_pin_ops);
		DBG_EMIT("  Proactive Pin Failures: .......... %llu\n",
			 pins->proactive_pin_failures);
	}

	DBG_EMIT("DMS Stale-Key Recovery Counters:\n");
	DBG_EMIT("  diag_target_data_req_rift_miss: .. %llu\n",
		 LANE_SUM(diag_target_data_req_rift_miss));
	DBG_EMIT("  diag_target_data_req_identity_recover: %llu\n",
		 LANE_SUM(diag_target_data_req_identity_recover));
	DBG_EMIT("  diag_target_data_req_identity_recover_waiting_ack: %llu\n",
		 LANE_SUM(diag_target_data_req_identity_recover_waiting_ack));
	DBG_EMIT("  diag_tracker_activity_reset: .. %llu\n",
		 LANE_SUM(diag_tracker_activity_reset));
	DBG_EMIT("  data_generation_mismatch_clobber: %llu\n",
		 LANE_SUM(data_generation_mismatch_clobber));

	DBG_EMIT("DMS Speculative TID Counters:\n");
	DBG_EMIT("  spec_tid_latch: .................. %llu\n",
		 LANE_SUM(spec_tid_latch));
	DBG_EMIT("  spec_tid_fallback_to_legacy: ..... %llu\n",
		 LANE_SUM(spec_tid_fallback_to_legacy));
	DBG_EMIT("  spec_tidsets_available (lane 0): %u\n",
		 dms->spec_tidsets_available);
	DBG_EMIT("  health_invalid_rift_key: ......... %llu\n",
		 LANE_SUM(health_invalid_rift_key));
	DBG_EMIT("  health_tx_payload_underflow: ..... %llu\n",
		 LANE_SUM(health_tx_payload_underflow));
	DBG_EMIT("  ctrl_rcd_unexpected_data: ........ %llu\n",
		 LANE_SUM(ctrl_rcd_unexpected_data));

	if (_ring_size(&dms->counters.tidset.ring) > 0) {
		DBG_EMIT("Tidset Log (lane 0):\n");
		DBG_EMIT("%12s %12s %12s %12s %12s %12s %12s %12s\n", "idx", "total_ns", "enable_ns", "rtt_ns", "data_ns", "bytes", "order_key", "rift(l:r)");
		u32 i = 0;
		while (_ring_size(&dms->counters.tidset.ring) > 0) {
			u32 const idx = _ring_consume(&dms->counters.tidset.ring);
			u64 const total_ns = ktime_to_ns(dms->counters.tidset.arr[idx].total);
			u64 const enable_ns = ktime_to_ns(dms->counters.tidset.arr[idx].enable);
			u64 const rtt_ns = ktime_to_ns(dms->counters.tidset.arr[idx].rtt);
			u64 const data_ns = ktime_to_ns(dms->counters.tidset.arr[idx].data);
			u32 const bytes = dms->counters.tidset.arr[idx].bytes;
			u64 const order = dms->counters.tidset.arr[idx].order_key;
			hfi2_dms_rift_key_t const local = dms->counters.tidset.arr[idx].local;
			hfi2_dms_rift_key_t const remote = dms->counters.tidset.arr[idx].remote;
			DBG_EMIT("%12u %12llu %12llu %12llu %12llu %12u %12llu %7hu:%-4hu\n", i++, total_ns, enable_ns, rtt_ns, data_ns, bytes, order, local.value, remote.value);
		}
	}

	memset(dms->counters.perf, 0, sizeof(dms->counters.perf));


	return res;
#undef LANE_SUM
#undef DBG_EMIT
}
