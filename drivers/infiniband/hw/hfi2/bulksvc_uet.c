/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * Ultra Ethernet (UET) DMS ULP stub peer -- SCAFFOLD / DEVELOPMENT VEHICLE for
 * UET on both the OmniPath and Ethernet fabrics.
 *
 * Function stubs plus documentation only.  The UEC wire format and any hardware
 * steering / dedicated receive context are out of scope here.  The UET Ethernet
 * match criteria (EtherType / UDP port / UEC markers) are TBD by the UEC
 * specification, so no classification match is installed yet.
 */
#include "bulksvc.h"
#include "bulksvc_ulp.h"

#if HFI2_BULKSVC_ULP_STUBS

/*
 * ============================================================================
 * EXAMPLE CODE -- PIO PINGPONG SELF-TEST -- NOT REQUIRED -- SAFE TO DELETE
 * ============================================================================
 * Everything guarded by HFI2_DMS_ULP_PINGPONG_EXAMPLE is a worked example that
 * exercises the ULP egress + ingress paths end to end (build a packet header,
 * PIO-inject it, receive and reflect it, time the round trip).  It is NOT part
 * of the UET ULP contract and is NOT needed for the peer to register and run.
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
#define UET_PP_SUBTYPE_PING 1
#define UET_PP_SUBTYPE_PONG 2
#define UET_PP_MAGIC 0x5545545f504e4731ull /* "UET_PNG1" */

struct uet_pp_payload {
	__le64 magic;
	__le64 t0_ns;
	__le32 seq;
	__le32 reserved;
};
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

/*
 * UET private peer state.  Embeds the common hfi2_bulksvc_ulp_state first so a
 * pointer to .common round-trips as the DMS cookie; the fields below are
 * UET-specific and show how a ULP extends the shared state.
 */
struct hfi2_bulksvc_uet {
	struct hfi2_bulksvc_ulp_state common;
	u32 uec_job_id;
	u64 marker_mismatches;

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
static int uet_pp_inject(struct hfi2_bulksvc *svc, u32 dlid, u8 subtype,
			 const struct uet_pp_payload *pp)
{
	/* 8-byte aligned: build_pio_header() writes u64 PBC/LRH/BTH/KDETH. */
	u8 hdr[40] __aligned(sizeof(u64));
	enum hfi2_dms_fabric_port_idx port_idx = svc->port_lut[0];
	struct hfi2_dms_ulp_iov iov[2];
	int hdr_len;

	hdr_len = hfi2_dms_ulp_build_pio_header(hfi2_bulksvc_primary_dms(svc), port_idx, dlid,
						HFI2_BULKSVC_ULP_ID_UET,
						subtype, sizeof(*pp),
						hdr, sizeof(hdr));
	if (hdr_len < 0)
		return hdr_len;

	iov[0] = (struct hfi2_dms_ulp_iov){ .base = hdr, .len = hdr_len };
	iov[1] = (struct hfi2_dms_ulp_iov){ .base = pp, .len = sizeof(*pp) };

	return hfi2_dms_ulp_egress_pio(hfi2_bulksvc_primary_dms(svc), port_idx, iov, 2);
}

/* Pull the pingpong payload from the rx split (inline prefix, else eager). */
static const struct uet_pp_payload *uet_pp_get(const struct hfi2_dms_ulp_rx *rx)
{
	if (rx->payload[0].base && rx->payload[0].len >= sizeof(struct uet_pp_payload))
		return rx->payload[0].base;
	if (rx->payload[1].base && rx->payload[1].len >= sizeof(struct uet_pp_payload))
		return rx->payload[1].base;
	return NULL;
}

/*
 * EXAMPLE: handle a pingpong PING/PONG.  Returns true if the packet was a
 * pingpong packet this routine consumed.  Called from handle_rx().
 */
static bool uet_pp_handle_rx(struct hfi2_bulksvc_uet *uet, u8 subtype,
			     const struct hfi2_dms_ulp_rx *rx)
{
	const struct uet_pp_payload *pp = uet_pp_get(rx);
	u64 t0, now;

	if (!pp || le64_to_cpu(pp->magic) != UET_PP_MAGIC)
		return false;

	switch (subtype) {
	case UET_PP_SUBTYPE_PING:
		/* Target: reflect to the ping's source LID, echo payload. */
		uet_pp_inject(uet->svc,
			      hfi2_16B_get_slid((struct hfi2_16b_header *)rx->pkt_hdr),
			      UET_PP_SUBTYPE_PONG, pp);
		return true;
	case UET_PP_SUBTYPE_PONG:
		/* Initiator: account only the most-recent ping's echo. */
		if (le32_to_cpu(pp->seq) != uet->last_tx_seq)
			return true;
		t0 = le64_to_cpu(pp->t0_ns);
		now = ktime_get_ns();
		if (now > t0) {
			u64 elapsed = now - t0;

			uet->pingpong_count++;
			uet->pingpong_elapsed_ns += elapsed;
			if (elapsed < uet->pingpong_min_ns)
				uet->pingpong_min_ns = elapsed;
			if (elapsed > uet->pingpong_max_ns)
				uet->pingpong_max_ns = elapsed;
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
static ssize_t uet_pp_write(struct file *file, const char __user *ubuf,
			    size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_uet *uet = file->private_data;
	struct hfi2_pportdata *ppd = &uet->svc->dd->pport[0];
	u32 dlid;
	int ret;

	ret = kstrtou32_from_user(ubuf, len, 0, &dlid);
	if (ret)
		return ret;
	if (dlid == 0 || dlid == ppd->lid)
		return -EINVAL;

	WRITE_ONCE(uet->pending_dlid, dlid);
	WRITE_ONCE(uet->pending_ping, true);
	hfi2_bulksvc_schedule(uet->svc);
	return len;
}

static ssize_t uet_pp_read(struct file *file, char __user *ubuf,
			   size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_uet *uet = file->private_data;
	u64 count = uet->pingpong_count;
	char buf[256];
	int n;

	n = scnprintf(buf, sizeof(buf),
		      "ulp: uet  tx: %llu  count: %llu  inject_fail: %llu\n"
		      "elapsed_ns: %llu  avg_ns: %llu  min_ns: %llu  max_ns: %llu\n",
		      uet->pingpong_tx, count, uet->pingpong_inject_fail,
		      uet->pingpong_elapsed_ns,
		      count ? uet->pingpong_elapsed_ns / count : 0,
		      count ? uet->pingpong_min_ns : 0,
		      uet->pingpong_max_ns);

	return simple_read_from_buffer(ubuf, len, ppos, buf, n);
}

static const struct file_operations uet_pp_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = uet_pp_write,
	.read = uet_pp_read,
	.llseek = default_llseek,
};

/* EXAMPLE: create the per-ULP pingpong debugfs file. */
static void uet_pp_init(struct hfi2_bulksvc_uet *uet, struct hfi2_bulksvc *svc)
{
	uet->svc = svc;
	uet->pingpong_min_ns = U64_MAX;

	if (svc->dd->verbs_dev.hfi2_ibdev_dbg)
		uet->pp_dentry =
			debugfs_create_file("uet_pingpong", 0644,
					    svc->dd->verbs_dev.hfi2_ibdev_dbg,
					    uet, &uet_pp_fops);
}

static void uet_pp_teardown(struct hfi2_bulksvc_uet *uet)
{
	/*
	 * The debugfs file's parent (hfi2_ibdev_dbg) is torn down recursively
	 * by hfi2_dbg_ibdev_exit() before bulksvc teardown runs, so pp_dentry
	 * is already stale here -- drop the reference without a second remove.
	 */
	uet->pp_dentry = NULL;
}

/*
 * EXAMPLE: drain a pending pingpong request on the event thread -- build a PING
 * carrying the initiator timestamp + sequence and PIO-inject it.  Round-trip
 * counters are updated on the PONG ingress path, not here.  Returns 1 if a ping
 * was processed, 0 otherwise.
 */
static int uet_pp_poll(struct hfi2_bulksvc_uet *uet, struct hfi2_bulksvc *svc)
{
	struct uet_pp_payload pp;
	u32 dlid;
	int ret;

	if (!READ_ONCE(uet->pending_ping))
		return 0;
	dlid = READ_ONCE(uet->pending_dlid);
	WRITE_ONCE(uet->pending_ping, false);

	uet->last_tx_seq = ++uet->tx_seq;
	pp = (struct uet_pp_payload){
		.magic = cpu_to_le64(UET_PP_MAGIC),
		.t0_ns = cpu_to_le64(ktime_get_ns()),
		.seq = cpu_to_le32(uet->last_tx_seq),
	};

	ret = uet_pp_inject(svc, dlid, UET_PP_SUBTYPE_PING, &pp);
	if (ret) {
		uet->pingpong_inject_fail++;
		return 1;
	}
	uet->pingpong_tx++;
	return 1;
}
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

static int hfi2_bulksvc_uet_handle_rx(struct hfi2_dms *dms, u8 subtype,
				      const struct hfi2_dms_ulp_rx *rx,
				      void *cookie)
{
	struct hfi2_bulksvc_uet *uet =
		container_of(cookie, struct hfi2_bulksvc_uet, common);

	uet->common.rx_packets++;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	if (uet_pp_handle_rx(uet, subtype, rx))
		return 0;
#endif

	/*
	 * A real UET handler would parse the UET headers from rx->pkt_hdr
	 * (navigating JKR-128 / CYR-256), place the payload from
	 * rx->payload[1], and respond via the egress shims.  Non-BTS ULPs
	 * receive EAGER, never expected-TID.
	 */
	return 0;
}

int hfi2_bulksvc_uet_init(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_uet *uet;
	struct hfi2_dms_ulp_ops ops;
	int ret;

	uet = kzalloc(sizeof(*uet), GFP_KERNEL);
	if (!uet)
		return -ENOMEM;
	uet->common.ulp_id = HFI2_BULKSVC_ULP_ID_UET;

	ops = (struct hfi2_dms_ulp_ops){
		.name = "uet",
		.ulp_id = HFI2_BULKSVC_ULP_ID_UET,
		.cookie = &uet->common,
		.handle_rx = hfi2_bulksvc_uet_handle_rx,
	};

	ret = hfi2_dms_ulp_register(hfi2_bulksvc_primary_dms(svc), ops);
	if (ret) {
		kfree(uet);
		return ret;
	}

	/*
	 * No Ethernet match is installed: the UEC EtherType / UDP port / marker
	 * criteria are not yet finalized.  A real UET peer would install
	 * hfi2_dms_ulp_add_eth_match() once they are; the OPA in-band path
	 * (ulp_id stamped in the BTH message byte) works without a match.
	 */

	uet->common.registered = true;
	svc->uet_ulp = &uet->common;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	uet_pp_init(uet, svc);
#endif
	return 0;
}

void hfi2_bulksvc_uet_teardown(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->uet_ulp;
	struct hfi2_bulksvc_uet *uet;

	if (!st)
		return;

	uet = container_of(st, struct hfi2_bulksvc_uet, common);
#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	uet_pp_teardown(uet);
#endif
	hfi2_dms_ulp_del_eth_match(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_UET);
	hfi2_dms_ulp_unregister(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_UET);
	kfree(uet);
	svc->uet_ulp = NULL;
}

/*
 * Poll hook, called on the bulksvc event thread.  The scaffold has no work
 * source of its own; the EXAMPLE pingpong below is the only producer.
 */
int hfi2_bulksvc_uet_poll(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->uet_ulp;
	struct hfi2_bulksvc_uet *uet;

	if (!st)
		return 0;
	uet = container_of(st, struct hfi2_bulksvc_uet, common);

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	return uet_pp_poll(uet, svc);
#else
	(void)uet;
	return 0;
#endif
}

#endif /* HFI2_BULKSVC_ULP_STUBS */
