/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * net (IPoIB-replacement) DMS ULP stub peer -- SCAFFOLD / DEVELOPMENT VEHICLE
 * for net on both the OmniPath and Ethernet fabrics.
 *
 * Function stubs plus documentation only.
 *
 * IMPORTANT -- this is NOT the host networking fast path.  Regular Ethernet
 * traffic (TCP/IP, ARP, ICMP, ...) belongs on the cn6k Ethernet auxiliary
 * driver context, which owns the net_device, its rx queues + NAPI, and skb
 * production.  This ULP peer is only for net frames a ULP explicitly claims.
 *
 * When the software classifier returns 0 (no ULP claims a frame), the frame is
 * delivered to that cn6k Ethernet netdev path via copy-into-skb +
 * netif_receive_skb (ownership-passing); it is never dropped.  Eager forwarding
 * is NOT required for that delivery: copy-into-skb inline (then return the eager
 * buffer immediately) is the correct path and needs no worker-thread pool.
 * Eager forwarding is a deferred throughput optimization that departs the
 * single-threaded DMS model; do not pull it into the DMS loop for basic
 * delivery.
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
 * of the net ULP contract and is NOT needed for the peer to register and run.
 * A ULP team adopting this file may delete every #if HFI2_DMS_ULP_PINGPONG_
 * EXAMPLE ... #endif region (and this banner) with no effect on the rest.
 * Set to 0 to compile it out; delete to remove it entirely.
 * ============================================================================
 */
#define HFI2_DMS_ULP_PINGPONG_EXAMPLE 1

/*
 * Pingpong egress path selector: 1 = SDMA (engine reads the packet from a
 * pooled DMA page), 0 = PIO (gather an on-stack iovec into the send FIFO).
 * The two are functionally equivalent for this self-test; the switch lets a
 * ULP author exercise either DMS egress path with a one-line change.
 */
#define NET_PP_USE_SDMA 1

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
#include <linux/debugfs.h>
#include <linux/ktime.h>

/*
 * Pingpong self-test subtypes (carried in the 5-bit BTH message-byte
 * subtype field) and payload magic.  The initiator sends PING; the target
 * reflects it as PONG with the payload echoed verbatim.
 */
#define NET_PP_SUBTYPE_PING 1
#define NET_PP_SUBTYPE_PONG 2
#define NET_PP_MAGIC 0x4e45545f504e4731ull /* "NET_PNG1" */

struct net_pp_payload {
	__le64 magic;
	__le64 t0_ns;
	__le32 seq;
	__le32 reserved;
};
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

/*
 * net private peer state.  Embeds the common hfi2_bulksvc_ulp_state first so a
 * pointer to .common round-trips as the DMS cookie; the fields below are
 * net-specific and show how a ULP extends the shared state.
 */
struct hfi2_bulksvc_net {
	struct hfi2_bulksvc_ulp_state common;
	u32 net_ifindex;
	u64 frames_to_netdev;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	/* EXAMPLE pingpong self-test state (safe to delete). */
	struct hfi2_bulksvc *svc;
	struct dentry *pp_dentry;
	u32 pending_dlid;        /* debugfs producer -> poll consumer */
	u32 pending_count;       /* debugfs producer -> poll consumer */
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
#if NET_PP_USE_SDMA
/*
 * Absolute SDMA engine this self-test injects on.  The ring layer takes a
 * concrete engine index (engine selection is caller policy); this example
 * has no reason to spread across engines, so it pins engine 0.
 */
#define NET_PP_SDMA_ENGINE 0

/*
 * SDMA gather element: a physical address + length, physically contiguous.
 * Private to this net_pp self-test; not part of the dms_sdma public API.
 */
struct net_pp_sge {
	dma_addr_t paddr;
	u32 len;
};

/*
 * SDMA command-header length: the 36-byte {PBC, lrh16bc, BTH, KDETH} command
 * header padded up to an 8-byte boundary (40), the same length
 * hfi2_dms_ulp_build_pio_header() returns, so the descriptor byte sum the JKR
 * length check sees matches the PBC/LRH qword length.
 */
#define HFI2_BULKSVC_ULP_SDMA_HDR_BYTES 40

/*
 * Build the SDMA command-buffer header into @hdr_buf: format the PIO header
 * and zero-pad it to HFI2_BULKSVC_ULP_SDMA_HDR_BYTES, so the header fragment
 * the descriptors fetch stays qword-aligned even if the PIO header length
 * changes (a bare 36-byte header is 4 bytes short of the PBC/LRH length and
 * halts JKR with SDmaLengthMismatchErr).  @hdr_buf MUST be DMA-addressable.
 * Returns the padded length (40) or a negative errno.
 */
static int net_pp_build_sdma_header(struct hfi2_dms *dms,
				    enum hfi2_dms_fabric_port_idx port_idx,
				    u32 dlid, u8 ulp_id, u8 subtype,
				    u32 payload_bytes, void *hdr_buf,
				    u32 hdr_buf_len)
{
	int hdr_len;

	if (hdr_buf_len < HFI2_BULKSVC_ULP_SDMA_HDR_BYTES)
		return -EMSGSIZE;

	hdr_len = hfi2_dms_ulp_build_pio_header(dms, port_idx, dlid, ulp_id,
					       subtype, payload_bytes, hdr_buf,
					       hdr_buf_len);
	if (hdr_len < 0)
		return hdr_len;

	memset((u8 *)hdr_buf + hdr_len, 0,
	       HFI2_BULKSVC_ULP_SDMA_HDR_BYTES - hdr_len);

	return HFI2_BULKSVC_ULP_SDMA_HDR_BYTES;
}

/*
 * Egress ONE fully-composed SDMA packet: a convenience wrapper over the
 * dms_sdma batch (batch_new/batch_emit/batch_commit).  The caller
 * composes the ENTIRE on-wire packet in @sgl/@nsge (header + payload +
 * mandatory 1-qword tail flit); this adds no header/tail/padding of its
 * own.  @nsge MUST be >= 2 (SOP on the first fragment, EOP on the last).
 * @done fires once after egress on success; on ANY negative return @done
 * is NEVER called and the caller's error path owns cleanup.  -EAGAIN means
 * transient engine backpressure.
 */
static int net_pp_sdma_egress_pkt(struct hfi2_dms *dms,
				  enum hfi2_dms_fabric_port_idx port_idx,
				  u8 engine_idx,
				  const struct net_pp_sge *sgl,
				  u32 nsge,
				  hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sdma_batch *b;
	u32 i;
	int ret;

	if (!dms || !sgl)
		return -EINVAL;
	if (nsge < 2)
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS)
		return -EINVAL;
	if (engine_idx >= dms_num_data_engines(dms))
		return -EINVAL;

	for (i = 0; i < nsge; i++) {
		if (sgl[i].len == 0)
			return -EINVAL;
	}

	b = hfi2_dms_sdma_batch_new(dms, (u8)port_idx);
	if (!b)
		return -EAGAIN;

	ret = hfi2_dms_sdma_batch_emit(b, sgl[0].paddr, sgl[0].len,
				       HFI2_DMS_SDMA_DESC_TYPE_SOP);
	if (ret)
		goto err_abort;

	for (i = 1; i < nsge - 1; i++) {
		ret = hfi2_dms_sdma_batch_emit(b, sgl[i].paddr, sgl[i].len,
					       HFI2_DMS_SDMA_DESC_TYPE_MID);
		if (ret)
			goto err_abort;
	}

	ret = hfi2_dms_sdma_batch_emit(b, sgl[nsge - 1].paddr,
				       sgl[nsge - 1].len,
				       HFI2_DMS_SDMA_DESC_TYPE_EOP);
	if (ret)
		goto err_abort;

	return hfi2_dms_sdma_batch_commit(b, engine_idx, done, cookie);

err_abort:
	hfi2_dms_sdma_batch_abort(b);
	return ret;
}

/*
 * Egress @count COPIES of the SAME fully-composed SDMA packet {paddr,len}
 * in ONE batch, each emitted as its own lone SOP+EOP descriptor (a legal
 * HW encoding: a single descriptor may carry both FirstDesc and LastDesc).
 * This exercises the SOP_EOP emit type and, whenever the batch needs JKR
 * 32-descriptor alignment padding, the ring layer's lone-SOP+EOP pad
 * relocation.  @done fires EXACTLY ONCE for the whole batch (after the
 * LAST copy's descriptor egresses), never once per copy -- @cookie's
 * owner must size any accounting to
 * that.  On any negative return @done is NEVER called and the caller's
 * error path owns @cookie.  -EAGAIN means transient engine backpressure.
 */
static int net_pp_sdma_egress_pkt_n(struct hfi2_dms *dms,
				    enum hfi2_dms_fabric_port_idx port_idx,
				    u8 engine_idx,
				    dma_addr_t paddr, u32 len, u32 count,
				    hfi2_dms_sdma_done_fn done, void *cookie)
{
	struct hfi2_dms_sdma_batch *b;
	u32 i;
	int ret;

	if (!dms || len == 0 || count == 0)
		return -EINVAL;
	if (port_idx >= HFI2_DMS_MAX_PORTS)
		return -EINVAL;
	if (engine_idx >= dms_num_data_engines(dms))
		return -EINVAL;

	b = hfi2_dms_sdma_batch_new(dms, (u8)port_idx);
	if (!b)
		return -EAGAIN;

	for (i = 0; i < count; i++) {
		ret = hfi2_dms_sdma_batch_emit(b, paddr, len,
					       HFI2_DMS_SDMA_DESC_TYPE_SOP_EOP);
		if (ret)
			goto err_abort;
	}

	return hfi2_dms_sdma_batch_commit(b, engine_idx, done, cookie);

err_abort:
	hfi2_dms_sdma_batch_abort(b);
	return ret;
}

/*
 * SDMA egress completion: return the pooled page (whose front held this
 * packet's header+payload+tail-flit image) to the DMS ULP page pool.  Fires
 * once, on the bulksvc event context, after the packet's descriptors egress.
 * @cookie is the page handed to net_pp_sdma_egress_pkt().
 */
static void net_pp_sdma_done(void *cookie, int status)
{
	struct hfi2_dms_page *page = cookie;

	(void)status;

	if (WARN_ON_ONCE(!page || !page->owner))
		return;

	hfi2_dms_page_put(page->owner, page);
}

/*
 * Inject @count COPIES of one pingpong packet of @subtype to @dlid via the
 * SDMA ring layer, as ONE batch.  SDMA reads the packet's bytes out of host
 * memory by DMA, so the whole packet image -- command header, payload, and
 * the trailing 1-qword tail flit -- is composed ONCE into a pooled DMS DMA
 * page (hfi2_dms_page_get() -- an O(1) free-list pop, no allocation on this
 * path).
 *
 * @count == 1 keeps the original two-SGE {header+payload, tail-flit} shape
 * (net_pp_sdma_egress_pkt()), with the tail flit carved from the page's
 * OWN LAST qword -- physically distant from the header+payload, gathered
 * as a second, physically-discontiguous descriptor.
 *
 * @count > 1 instead writes the tail flit immediately AFTER the payload
 * (NOT at the page's last qword), so header+payload+tail-flit form ONE
 * physically-contiguous range -- required because the whole image is fed
 * to the ring layer as a SINGLE fragment, repeated @count times as @count
 * independent lone SOP+EOP packets (net_pp_sdma_egress_pkt_n()).
 * hdr_len+sizeof(*pp)+8 is already a multiple of 8 (hdr_len is the
 * qword-rounded HFI2_BULKSVC_ULP_SDMA_HDR_BYTES(40), sizeof(*pp) is 24),
 * so no further alignment is needed for the JKR length check on this
 * single-descriptor packet.
 *
 * Either way @done fires EXACTLY ONCE per net_pp_inject() call (once per
 * BATCH, not once per copy), and net_pp_sdma_done() returns the ONE page
 * to the pool at that point.  On any synchronous failure the page is
 * still ours and is returned here.  Runs ONLY on the bulksvc event thread
 * (poll / handle_rx).  Returns 0 or <0.
 */
static int net_pp_inject(struct hfi2_bulksvc *svc, u32 dlid, u8 subtype,
			 const struct net_pp_payload *pp, u32 count)
{
	enum hfi2_dms_fabric_port_idx port_idx = svc->port_lut[0];
	struct hfi2_dms_page *page;
	u8 *img;
	int hdr_len;
	int ret;

	page = hfi2_dms_page_get(hfi2_bulksvc_primary_dms(svc));
	if (!page)
		return -EAGAIN;
	img = page->mem.kvaddr;

	hdr_len = net_pp_build_sdma_header(hfi2_bulksvc_primary_dms(svc),
					   port_idx, dlid,
					   HFI2_BULKSVC_ULP_ID_NET,
					   subtype, sizeof(*pp),
					   img, page->mem.len);
	if (hdr_len < 0) {
		ret = hdr_len;
		goto out_put;
	}

	memcpy(img + hdr_len, pp, sizeof(*pp));

	if (count <= 1) {
		u32 const tail_off = PAGE_SIZE - sizeof(u64);
		struct net_pp_sge sge[2] = {
			{ .paddr = page->mem.phys_addr,
			  .len = hdr_len + sizeof(*pp) },
			{ .paddr = page->mem.phys_addr + tail_off,
			  .len = sizeof(u64) },
		};

		*(u64 *)(img + tail_off) = 0;
		hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(svc), page, 0, PAGE_SIZE);
		ret = net_pp_sdma_egress_pkt(hfi2_bulksvc_primary_dms(svc), port_idx,
					     NET_PP_SDMA_ENGINE,
					     sge, 2, net_pp_sdma_done, page);
	} else {
		u32 const pkt_off = hdr_len + sizeof(*pp);
		u32 const pkt_len = pkt_off + sizeof(u64);

		*(u64 *)(img + pkt_off) = 0;
		hfi2_dms_page_sync_for_device(hfi2_bulksvc_primary_dms(svc), page, 0, pkt_len);
		ret = net_pp_sdma_egress_pkt_n(hfi2_bulksvc_primary_dms(svc), port_idx,
					       NET_PP_SDMA_ENGINE,
					       page->mem.phys_addr, pkt_len,
					       count, net_pp_sdma_done, page);
	}
	if (ret)
		goto out_put;

	return 0;

out_put:
	hfi2_dms_page_put(hfi2_bulksvc_primary_dms(svc), page);
	return ret;
}

#else /* !NET_PP_USE_SDMA */

/*
 * Inject one pingpong packet of @subtype to @dlid via PIO.  Builds the wire
 * header with the DMS PIO helper and gathers it, with the payload in place,
 * straight into the MMIO send FIFO (contrast SDMA, which reads the packet
 * from a pooled DMA page).  Runs ONLY on the bulksvc event thread (poll /
 * handle_rx).  @count is accepted for signature parity with the SDMA path's
 * batching but is NOT implemented here -- PIO gathers directly into the MMIO
 * send FIFO with no ring-layer batch primitive to repeat a packet through, so
 * only a single packet is ever sent regardless of @count (see NET_PP_USE_SDMA
 * to select the batching-capable path).
 * Returns 0 or <0.
 */
static int net_pp_inject(struct hfi2_bulksvc *svc, u32 dlid, u8 subtype,
			 const struct net_pp_payload *pp, u32 count)
{
	(void)count;

	/* 8-byte aligned: build_pio_header() writes u64 PBC/LRH/BTH/KDETH. */
	u8 hdr[40] __aligned(sizeof(u64));
	enum hfi2_dms_fabric_port_idx port_idx = svc->port_lut[0];
	struct hfi2_dms_ulp_iov iov[2];
	int hdr_len;

	hdr_len = hfi2_dms_ulp_build_pio_header(hfi2_bulksvc_primary_dms(svc), port_idx, dlid,
						HFI2_BULKSVC_ULP_ID_NET,
						subtype, sizeof(*pp),
						hdr, sizeof(hdr));
	if (hdr_len < 0)
		return hdr_len;

	iov[0] = (struct hfi2_dms_ulp_iov){ .base = hdr, .len = hdr_len };
	iov[1] = (struct hfi2_dms_ulp_iov){ .base = pp, .len = sizeof(*pp) };

	return hfi2_dms_ulp_egress_pio(hfi2_bulksvc_primary_dms(svc), port_idx, iov, 2);
}

#endif /* NET_PP_USE_SDMA */

/* Pull the pingpong payload from the rx split (inline prefix, else eager). */
static const struct net_pp_payload *net_pp_get(const struct hfi2_dms_ulp_rx *rx)
{
	if (rx->payload[0].base && rx->payload[0].len >= sizeof(struct net_pp_payload))
		return rx->payload[0].base;
	if (rx->payload[1].base && rx->payload[1].len >= sizeof(struct net_pp_payload))
		return rx->payload[1].base;
	return NULL;
}

/*
 * EXAMPLE: handle a pingpong PING/PONG.  Returns true if the packet was a
 * pingpong packet this routine consumed.  Called from handle_rx().
 */
static bool net_pp_handle_rx(struct hfi2_bulksvc_net *net, u8 subtype,
			     const struct hfi2_dms_ulp_rx *rx)
{
	const struct net_pp_payload *pp = net_pp_get(rx);
	u64 t0, now;

	if (!pp || le64_to_cpu(pp->magic) != NET_PP_MAGIC)
		return false;

	switch (subtype) {
	case NET_PP_SUBTYPE_PING:
		/* Target: reflect to the ping's source LID, echo payload. */
		net_pp_inject(net->svc,
				   hfi2_16B_get_slid((struct hfi2_16b_header *)rx->pkt_hdr),
				   NET_PP_SUBTYPE_PONG, pp, 1);
		return true;
	case NET_PP_SUBTYPE_PONG: {
		/* A batch's @count copies share one seq; count every match. */
		u32 seq = le32_to_cpu(pp->seq);

		if (seq != net->last_tx_seq)
			return true;
		t0 = le64_to_cpu(pp->t0_ns);
		now = ktime_get_ns();
		if (now > t0) {
			u64 elapsed = now - t0;

			net->pingpong_count++;
			net->pingpong_elapsed_ns += elapsed;
			if (elapsed < net->pingpong_min_ns)
				net->pingpong_min_ns = elapsed;
			if (elapsed > net->pingpong_max_ns)
				net->pingpong_max_ns = elapsed;
		}
		return true;
	}
	default:
		return false;
	}
}

/*
 * debugfs: write "<dlid>" or "<dlid> <count>" (count optional, default 1)
 * to fire a batch of @count identical lone SOP+EOP pings in one SDMA
 * commit (event thread does the inject); read returns the accumulated
 * pingpong stats.  Counters move only on PONG ingress, so a lost
 * ping/pong simply produces no movement.  @count is capped at
 * NET_PP_MAX_COUNT: this is a self-test knob, and an unbounded value
 * would tie up an SDMA engine and grow the batch node ring (a kzalloc
 * per node) on the single event thread.
 */
#define NET_PP_MAX_COUNT 4096
static ssize_t net_pp_write(struct file *file, const char __user *ubuf,
			    size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_net *net = file->private_data;
	struct hfi2_pportdata *ppd = &net->svc->dd->pport[0];
	char kbuf[32];
	char *p = kbuf;
	char *tok;
	u32 dlid;
	u32 count = 1;
	int ret;

	if (len == 0 || len >= sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	p = strstrip(kbuf);
	tok = strsep(&p, " \t");
	if (!tok || !*tok)
		return -EINVAL;
	ret = kstrtou32(tok, 0, &dlid);
	if (ret)
		return ret;
	if (dlid == 0 || dlid == ppd->lid)
		return -EINVAL;

	tok = p ? strsep(&p, " \t") : NULL;
	if (tok && *tok) {
		ret = kstrtou32(tok, 0, &count);
		if (ret)
			return ret;
		if (count == 0 || count > NET_PP_MAX_COUNT)
			return -EINVAL;
	}

	WRITE_ONCE(net->pending_dlid, dlid);
	WRITE_ONCE(net->pending_count, count);
	WRITE_ONCE(net->pending_ping, true);
	hfi2_bulksvc_schedule(net->svc);
	return len;
}

static ssize_t net_pp_read(struct file *file, char __user *ubuf,
			   size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_net *net = file->private_data;
	u64 count = net->pingpong_count;
	char buf[256];
	int n;

	n = scnprintf(buf, sizeof(buf),
		      "ulp: net  tx: %llu  count: %llu  inject_fail: %llu\n"
		      "elapsed_ns: %llu  avg_ns: %llu  min_ns: %llu  max_ns: %llu\n",
		      net->pingpong_tx, count, net->pingpong_inject_fail,
		      net->pingpong_elapsed_ns,
		      count ? net->pingpong_elapsed_ns / count : 0,
		      count ? net->pingpong_min_ns : 0,
		      net->pingpong_max_ns);

	return simple_read_from_buffer(ubuf, len, ppos, buf, n);
}

static const struct file_operations net_pp_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = net_pp_write,
	.read = net_pp_read,
	.llseek = default_llseek,
};

/* EXAMPLE: create the per-ULP pingpong debugfs file. */
static void net_pp_init(struct hfi2_bulksvc_net *net, struct hfi2_bulksvc *svc)
{
	net->svc = svc;
	net->pingpong_min_ns = U64_MAX;

	if (svc->dd->verbs_dev.hfi2_ibdev_dbg)
		net->pp_dentry =
			debugfs_create_file("net_pingpong", 0644,
					    svc->dd->verbs_dev.hfi2_ibdev_dbg,
					    net, &net_pp_fops);
}

static void net_pp_teardown(struct hfi2_bulksvc_net *net)
{
	/*
	 * The debugfs file's parent (hfi2_ibdev_dbg) is torn down recursively
	 * by hfi2_dbg_ibdev_exit() before bulksvc teardown runs, so pp_dentry
	 * is already stale here -- drop the reference without a second remove.
	 */
	net->pp_dentry = NULL;
}

/*
 * EXAMPLE: drain a pending pingpong request on the event thread -- build a PING
 * carrying the initiator timestamp + sequence and SDMA-inject it.  Round-trip
 * counters are updated on the PONG ingress path, not here.  Returns 1 if a ping
 * was processed, 0 otherwise.
 */
static int net_pp_poll(struct hfi2_bulksvc_net *net, struct hfi2_bulksvc *svc)
{
	struct net_pp_payload pp;
	u32 dlid;
	u32 count;
	int ret;

	if (!READ_ONCE(net->pending_ping))
		return 0;
	dlid = READ_ONCE(net->pending_dlid);
	count = READ_ONCE(net->pending_count);
	WRITE_ONCE(net->pending_ping, false);

	net->last_tx_seq = ++net->tx_seq;
	pp = (struct net_pp_payload){
		.magic = cpu_to_le64(NET_PP_MAGIC),
		.t0_ns = cpu_to_le64(ktime_get_ns()),
		.seq = cpu_to_le32(net->last_tx_seq),
	};

	ret = net_pp_inject(svc, dlid, NET_PP_SUBTYPE_PING, &pp, count);
	if (ret) {
		net->pingpong_inject_fail++;
		return 1;
	}
	net->pingpong_tx += count;
	return 1;
}
#endif /* HFI2_DMS_ULP_PINGPONG_EXAMPLE */

static int hfi2_bulksvc_net_handle_rx(struct hfi2_dms *dms, u8 subtype,
				      const struct hfi2_dms_ulp_rx *rx,
				      void *cookie)
{
	struct hfi2_bulksvc_net *net =
		container_of(cookie, struct hfi2_bulksvc_net, common);

	net->common.rx_packets++;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	if (net_pp_handle_rx(net, subtype, rx))
		return 0;
#endif

	/*
	 * A real net handler would consume the frame from the rx->pkt_hdr +
	 * rx->payload split for whatever the net ULP delivers.  Frames NOT
	 * claimed by a ULP never reach here -- they are classified as host
	 * traffic and handed to the cn6k Ethernet netdev (see the file banner).
	 */
	return 0;
}

int hfi2_bulksvc_net_init(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_net *net;
	struct hfi2_dms_ulp_ops ops;
	int ret;

	net = kzalloc(sizeof(*net), GFP_KERNEL);
	if (!net)
		return -ENOMEM;
	net->common.ulp_id = HFI2_BULKSVC_ULP_ID_NET;

	ops = (struct hfi2_dms_ulp_ops){
		.name = "net",
		.ulp_id = HFI2_BULKSVC_ULP_ID_NET,
		.cookie = &net->common,
		.handle_rx = hfi2_bulksvc_net_handle_rx,
	};

	ret = hfi2_dms_ulp_register(hfi2_bulksvc_primary_dms(svc), ops);
	if (ret) {
		kfree(net);
		return ret;
	}

	/*
	 * No Ethernet match is installed: this peer does NOT want to capture
	 * general Ethernet traffic (that belongs to the cn6k netdev).  A real
	 * net ULP that defines a specific claimed-frame criterion would install
	 * a narrow hfi2_dms_ulp_add_eth_match() here.  The OPA in-band path
	 * works without a match.
	 */

	net->common.registered = true;
	svc->net_ulp = &net->common;

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	net_pp_init(net, svc);
#endif
	return 0;
}

void hfi2_bulksvc_net_teardown(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->net_ulp;
	struct hfi2_bulksvc_net *net;

	if (!st)
		return;

	net = container_of(st, struct hfi2_bulksvc_net, common);
#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	net_pp_teardown(net);
#endif
	hfi2_dms_ulp_del_eth_match(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_NET);
	hfi2_dms_ulp_unregister(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_NET);
	kfree(net);
	svc->net_ulp = NULL;
}

/*
 * Poll hook, called on the bulksvc event thread.  The scaffold has no work
 * source of its own; the EXAMPLE pingpong below is the only producer.
 */
int hfi2_bulksvc_net_poll(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->net_ulp;
	struct hfi2_bulksvc_net *net;

	if (!st)
		return 0;
	net = container_of(st, struct hfi2_bulksvc_net, common);

#if HFI2_DMS_ULP_PINGPONG_EXAMPLE
	return net_pp_poll(net, svc);
#else
	(void)net;
	return 0;
#endif
}

#endif /* HFI2_BULKSVC_ULP_STUBS */
