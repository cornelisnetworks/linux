/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * RoCE DMS ULP stub peer -- SCAFFOLD / DEVELOPMENT VEHICLE for RoCE on both the
 * OmniPath and Ethernet fabrics.
 *
 * This file demonstrates the DMS ULP consumer contract: how a ULP registers an
 * ops vtable plus a cookie, installs an Ethernet classification match, receives
 * the {hdr,eager} split, and transmits via the egress shims.  It is function
 * stubs plus documentation only.
 *
 * OUT OF SCOPE here (the RoCE team owns these; see cn-forge-sw/cn6k/roce/):
 *   - the RoCEv2 wire protocol (BTH/RETH/AETH, PSN, Go-Back-N, ICRC, 256-byte
 *     Ethernet headers),
 *   - hardware packet steering to a dedicated RoCE receive context (deferred
 *     pending a multi-hfisvc capability),
 *   - EAL RKEY/RIF acceleration.
 *
 * BTS-specific facilities (client key, access registration, trackers, rift
 * keys, tidsets, the 64-byte completion cookie) are NOT used here -- a non-BTS
 * ULP defines its own transfer tracking.  The page-provider abstraction is the
 * one transfer-side facility that is genuinely common, and a real RoCE peer may
 * reuse it for its buffers.
 */
#include "bulksvc.h"
#include "bulksvc_ulp.h"
#include "roce_wire.h"

#if HFI2_BULKSVC_ULP_STUBS

#include <linux/if_ether.h>
#include <linux/in.h>

/*
 * ============================================================================
 * EXAMPLE CODE -- PIO PINGPONG SELF-TEST -- NOT REQUIRED -- SAFE TO DELETE
 * ============================================================================
 * Everything guarded by HFI2_DMS_ULP_PINGPONG_EXAMPLE is a worked example that
 * exercises the ULP egress + ingress paths end to end (build a packet header,
 * PIO-inject it, receive and reflect it, time the round trip).  It is NOT part
 * of the RoCE ULP contract and is NOT needed for the peer to register and run.
 * A ULP team adopting this file may delete every #if HFI2_DMS_ULP_PINGPONG_
 * EXAMPLE ... #endif region (and this banner) with no effect on the rest.
 * Set to 0 to compile it out; delete to remove it entirely.
 * ============================================================================
 */
#define HFI2_DMS_ULP_PINGPONG_EXAMPLE 1

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
#include <linux/debugfs.h>
#include <linux/ktime.h>

/*
 * PIO pingpong self-test subtypes (carried in the 5-bit BTH message-byte
 * subtype field) and payload magic.  The initiator sends PING; the target
 * reflects it as PONG with the payload echoed verbatim.
 */
#define ROCE_PP_SUBTYPE_PING 1
#define ROCE_PP_SUBTYPE_PONG 2
#define ROCE_PP_MAGIC 0x524f4345504e4731ull /* "ROCEPNG1" */

struct roce_pp_payload {
	__le64 magic;
	__le64 t0_ns;
	__le32 seq;
	__le32 reserved;
};
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

/*
 * RoCE private peer state.  Embeds the common hfi2_bulksvc_ulp_state as its
 * first member so a pointer to .common round-trips as the DMS cookie; the
 * fields below are RoCE-specific and illustrate how a ULP extends the shared
 * state.  A real RoCE peer would hang its QP/flow tables and command rings here.
 */
struct hfi2_bulksvc_roce {
	struct hfi2_bulksvc_ulp_state common;
	u16 udp_dport;
	u64 icrc_errors;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	/* EXAMPLE pingpong self-test state (safe to delete). */
	struct hfi2_bulksvc *svc;
	struct dentry *pp_dentry;
	u32 pending_dlid;        /* debugfs producer -> poll consumer */
	bool pending_ping;
	u32 tx_seq;
	u32 last_tx_seq;
	u64 pingpong_tx;
	u64 pingpong_inject_fail;
	u64 pingpong_count;
	u64 pingpong_elapsed_ns;
	u64 pingpong_min_ns;
	u64 pingpong_max_ns;
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */
};

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
/*
 * Inject one pingpong packet (PING or PONG) of @subtype to @dlid.  Builds the
 * wire header via the DMS helper and PIO-injects it with the payload in
 * place.  Runs ONLY on the bulksvc event thread (poll / handle_rx).  Returns
 * 0 or <0.
 */
static int roce_pp_inject(struct hfi2_bulksvc *svc, u32 dlid, u8 subtype,
			  const struct roce_pp_payload *pp)
{
	/* 8-byte aligned: build_pio_header() writes u64 PBC/LRH/BTH/KDETH. */
	u8 hdr[40] __aligned(sizeof(u64));
	enum hfi2_dms_fabric_port_idx port_idx = svc->port_lut[0];
	struct hfi2_dms_ulp_iov iov[2];
	int hdr_len;

	hdr_len = hfi2_dms_ulp_build_pio_header(hfi2_bulksvc_primary_dms(svc), port_idx, dlid,
						HFI2_BULKSVC_ULP_ID_ROCE,
						subtype, sizeof(*pp),
						hdr, sizeof(hdr));
	if (hdr_len < 0)
		return hdr_len;

	iov[0] = (struct hfi2_dms_ulp_iov){ .base = hdr, .len = hdr_len };
	iov[1] = (struct hfi2_dms_ulp_iov){ .base = pp, .len = sizeof(*pp) };

	return hfi2_dms_ulp_egress_pio(hfi2_bulksvc_primary_dms(svc), port_idx, iov, 2);
}

/* Pull the pingpong payload from the rx split (inline prefix, else eager). */
static const struct roce_pp_payload *roce_pp_get(const struct hfi2_dms_ulp_rx *rx)
{
	if (rx->payload[0].base && rx->payload[0].len >= sizeof(struct roce_pp_payload))
		return rx->payload[0].base;
	if (rx->payload[1].base && rx->payload[1].len >= sizeof(struct roce_pp_payload))
		return rx->payload[1].base;
	return NULL;
}

/*
 * EXAMPLE: handle a pingpong PING/PONG.  Returns true if the packet was a
 * pingpong packet this routine consumed.  Called from handle_rx().
 */
static bool roce_pp_handle_rx(struct hfi2_bulksvc_roce *roce, u8 subtype,
			      const struct hfi2_dms_ulp_rx *rx)
{
	const struct roce_pp_payload *pp = roce_pp_get(rx);
	u64 t0, now;

	if (!pp || le64_to_cpu(pp->magic) != ROCE_PP_MAGIC)
		return false;

	switch (subtype) {
	case ROCE_PP_SUBTYPE_PING:
		/* Target: reflect to the ping's source LID, echo payload. */
		roce_pp_inject(roce->svc,
			       hfi2_16B_get_slid((struct hfi2_16b_header *)rx->pkt_hdr),
			       ROCE_PP_SUBTYPE_PONG, pp);
		return true;
	case ROCE_PP_SUBTYPE_PONG:
		/* Initiator: account only the most-recent ping's echo. */
		if (le32_to_cpu(pp->seq) != roce->last_tx_seq)
			return true;
		t0 = le64_to_cpu(pp->t0_ns);
		now = ktime_get_ns();
		if (now > t0) {
			u64 elapsed = now - t0;

			roce->pingpong_count++;
			roce->pingpong_elapsed_ns += elapsed;
			if (elapsed < roce->pingpong_min_ns)
				roce->pingpong_min_ns = elapsed;
			if (elapsed > roce->pingpong_max_ns)
				roce->pingpong_max_ns = elapsed;
		}
		return true;
	default:
		return false;
	}
}

/*
 * debugfs: write "<dlid>" to fire one ping (event thread does the inject);
 * read returns the accumulated pingpong stats.  Counters move only on PONG
 * ingress, so a lost ping/pong simply produces no movement.
 */
static ssize_t roce_pp_write(struct file *file, const char __user *ubuf,
			     size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_roce *roce = file->private_data;
	struct hfi2_pportdata *ppd = &roce->svc->dd->pport[0];
	u32 dlid;
	int ret;

	ret = kstrtou32_from_user(ubuf, len, 0, &dlid);
	if (ret)
		return ret;
	if (dlid == 0 || dlid == ppd->lid)
		return -EINVAL;

	WRITE_ONCE(roce->pending_dlid, dlid);
	WRITE_ONCE(roce->pending_ping, true);
	hfi2_bulksvc_schedule(roce->svc);
	return len;
}

static ssize_t roce_pp_read(struct file *file, char __user *ubuf,
			    size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_roce *roce = file->private_data;
	u64 count = roce->pingpong_count;
	char buf[256];
	int n;

	n = scnprintf(buf, sizeof(buf),
		      "ulp: roce  tx: %llu  count: %llu  inject_fail: %llu\n"
		      "elapsed_ns: %llu  avg_ns: %llu  min_ns: %llu  max_ns: %llu\n",
		      roce->pingpong_tx, count, roce->pingpong_inject_fail,
		      roce->pingpong_elapsed_ns,
		      count ? roce->pingpong_elapsed_ns / count : 0,
		      count ? roce->pingpong_min_ns : 0,
		      roce->pingpong_max_ns);

	return simple_read_from_buffer(ubuf, len, ppos, buf, n);
}

static const struct file_operations roce_pp_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = roce_pp_write,
	.read = roce_pp_read,
	.llseek = default_llseek,
};

/* EXAMPLE: create the per-ULP pingpong debugfs file. */
static void roce_pp_init(struct hfi2_bulksvc_roce *roce, struct hfi2_bulksvc *svc)
{
	roce->svc = svc;
	roce->pingpong_min_ns = U64_MAX;

	if (svc->dd->verbs_dev.hfi2_ibdev_dbg)
		roce->pp_dentry =
			debugfs_create_file("roce_pingpong", 0644,
					    svc->dd->verbs_dev.hfi2_ibdev_dbg,
					    roce, &roce_pp_fops);
}

static void roce_pp_teardown(struct hfi2_bulksvc_roce *roce)
{
	/*
	 * The debugfs file's parent (hfi2_ibdev_dbg) is torn down recursively
	 * by hfi2_dbg_ibdev_exit() before bulksvc teardown runs, so pp_dentry
	 * is already stale here -- drop the reference without a second remove.
	 */
	roce->pp_dentry = NULL;
}

/*
 * EXAMPLE: drain a pending pingpong request on the event thread -- build a PING
 * carrying the initiator timestamp + sequence and PIO-inject it.  Round-trip
 * counters are updated on the PONG ingress path, not here.  Returns 1 if a ping
 * was processed, 0 otherwise.
 */
static int roce_pp_poll(struct hfi2_bulksvc_roce *roce, struct hfi2_bulksvc *svc)
{
	struct roce_pp_payload pp;
	u32 dlid;
	int ret;

	if (!READ_ONCE(roce->pending_ping))
		return 0;
	dlid = READ_ONCE(roce->pending_dlid);
	WRITE_ONCE(roce->pending_ping, false);

	roce->last_tx_seq = ++roce->tx_seq;
	pp = (struct roce_pp_payload){
		.magic = cpu_to_le64(ROCE_PP_MAGIC),
		.t0_ns = cpu_to_le64(ktime_get_ns()),
		.seq = cpu_to_le32(roce->last_tx_seq),
	};

	ret = roce_pp_inject(svc, dlid, ROCE_PP_SUBTYPE_PING, &pp);
	if (ret) {
		roce->pingpong_inject_fail++;
		return 1;
	}
	roce->pingpong_tx++;
	return 1;
}
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

/*
 * Receive one classified RoCE packet.  Runs on the single bulksvc event thread,
 * so ULP-internal state needs no locking.
 *
 * @rx carries the header + payload split the hardware produced: rx->pkt_hdr is
 * the native header or, for Ethernet delivery, the EAL ingress header.  The
 * Ethernet frame bytes are in rx->payload[0] (inline in the HDRQ entry) and
 * rx->payload[1] (DMA'd into the eager buffer).  A real RoCE handler must parse
 * the appropriate header and both payload segments, accounting for the JKR
 * (128 B) / CYR (256 B) HDRQ entry sizes.  Non-BTS ULPs use eager buffers,
 * never expected-TID; a short packet may be entirely inline.
 */
static int hfi2_bulksvc_roce_handle_rx(struct hfi2_dms *dms, u8 subtype,
				       const struct hfi2_dms_ulp_rx *rx,
				       void *cookie)
{
	struct hfi2_bulksvc_roce *roce =
		container_of(cookie, struct hfi2_bulksvc_roce, common);

	roce->common.rx_packets++;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	if (roce_pp_handle_rx(roce, subtype, rx))
		return 0;
#endif

	/*
	 * A real implementation would dispatch on @subtype, parse the RoCE
	 * headers from rx->pkt_hdr, place the payload, and (if a response is
	 * owed) build a packet image and transmit it via the DMS PIO egress
	 * (small/control) or SDMA egress (bulk) path.  The stub consumes the
	 * packet so it is accounted, not dropped.
	 */
	return 0;
}

int hfi2_bulksvc_roce_init(struct hfi2_bulksvc *svc)
{
	struct hfi2_dms_ulp_match match = {
		.ulp_id = HFI2_BULKSVC_ULP_ID_ROCE,
		.ethertype = htons(ETH_P_IP),
		.ip_proto = IPPROTO_UDP,
		.udp_dport = htons(HFI2_ROCE_UDP_DPORT),
		.prio = 10,
	};
	struct hfi2_bulksvc_roce *roce;
	struct hfi2_dms_ulp_ops ops;
	int ret;

	roce = kzalloc(sizeof(*roce), GFP_KERNEL);
	if (!roce)
		return -ENOMEM;
	roce->common.ulp_id = HFI2_BULKSVC_ULP_ID_ROCE;
	roce->udp_dport = HFI2_ROCE_UDP_DPORT;

	ops = (struct hfi2_dms_ulp_ops){
		.name = "roce",
		.ulp_id = HFI2_BULKSVC_ULP_ID_ROCE,
		.cookie = &roce->common,
		.handle_rx = hfi2_bulksvc_roce_handle_rx,
	};

	ret = hfi2_dms_ulp_register(hfi2_bulksvc_primary_dms(svc), ops);
	if (ret) {
		kfree(roce);
		return ret;
	}

	/*
	 * Install the Ethernet-fabric classification match (RoCEv2 UDP 4791).
	 * Software-only today; on the OPA fabric the ulp_id is carried in-band
	 * and no match is needed.  WARNING: this diverts UDP 4791 frames from
	 * the soft-RoCE provider (rxe) on this host; running both accelerated
	 * and soft RoCE simultaneously is unsupported.  A failure here is
	 * non-fatal to the scaffold -- the OPA in-band path still works.
	 */
	ret = hfi2_dms_ulp_add_eth_match(hfi2_bulksvc_primary_dms(svc), &match);
	if (ret)
		dd_dev_warn(svc->dd,
			    "bulksvc_roce: add_eth_match failed (%d); OPA in-band path only\n",
			    ret);

	roce->common.registered = true;
	svc->roce_ulp = &roce->common;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	roce_pp_init(roce, svc);
#endif
	return 0;
}

void hfi2_bulksvc_roce_teardown(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->roce_ulp;
	struct hfi2_bulksvc_roce *roce;

	if (!st)
		return;

	roce = container_of(st, struct hfi2_bulksvc_roce, common);
#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	roce_pp_teardown(roce);
#endif
	hfi2_dms_ulp_del_eth_match(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_ROCE);
	hfi2_dms_ulp_unregister(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_ROCE);
	kfree(roce);
	svc->roce_ulp = NULL;
}

/*
 * Poll hook for ULP-submitted work (e.g. a command ring).  Called from
 * bulksvc_primary_poll() on the primary lane worker.  The scaffold has no work
 * source of its own; the EXAMPLE pingpong below is the only producer.
 */
int hfi2_bulksvc_roce_poll(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->roce_ulp;
	struct hfi2_bulksvc_roce *roce;

	if (!st)
		return 0;
	roce = container_of(st, struct hfi2_bulksvc_roce, common);

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	return roce_pp_poll(roce, svc);
#else
	(void)roce;
	return 0;
#endif
}

#endif /* HFI2_BULKSVC_ULP_STUBS */
