// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * eal_test DMS ULP peer: test-only IPv4/UDP sink for CYR EAL ingress.
 */
#include "bulksvc.h"
#include "bulksvc_ulp.h"
#include "chip.h"
#include "eth_hwi.h"
#include "roce_wire.h"

#if HFI2_BULKSVC_ULP_STUBS

#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/moduleparam.h>
#include <linux/udp.h>

ushort hfi2_bulksvc_eal_test_udp_port = HFI2_BULKSVC_EAL_TEST_UDP_PORT;

struct hfi2_bulksvc_eal_test {
	struct hfi2_bulksvc_ulp_state common;
	struct dentry *stats_dentry;
	u64 rx_bytes;
	u64 unexpected_cam;
	u64 parse_errors;
	u64 last_source_mac;
	__be32 last_source_ip;
	u16 udp_dport;
	u8 last_cam_entry;
	bool cam_available;
	bool source_mac_available;
	bool source_ip_available;
};

static void eal_test_record_parse_error(struct hfi2_bulksvc_eal_test *eal_test)
{
	WRITE_ONCE(eal_test->parse_errors,
		   READ_ONCE(eal_test->parse_errors) + 1);
}

static bool eal_test_parse_eth(struct hfi2_bulksvc_eal_test *eal_test,
			       const struct hfi2_dms_ulp_rx *rx,
			       const struct eal_ingress_header *eal_hdr)
{
	u8 eth_hdr[ETH_HLEN + sizeof(struct iphdr) + MAX_IPOPTLEN +
		   sizeof(struct udphdr)];
	const struct ethhdr *eth = (const void *)eth_hdr;
	const struct iphdr *ip4;
	u32 eth_hdr_len;
	u32 ihl;

	/*
	 * The HDRQ-inline and eager segments are logically contiguous.  Copy only
	 * the bounded Ethernet/IPv4 prefix needed for debugfs accounting so the
	 * parser is independent of the hardware's segment split.
	 */
	eth_hdr_len = hfi2_dms_ulp_rx_copy_prefix(rx, eth_hdr, sizeof(eth_hdr));
	if (eth_hdr_len < sizeof(*eth)) {
		WRITE_ONCE(eal_test->source_mac_available, false);
		WRITE_ONCE(eal_test->source_ip_available, false);
		eal_test_record_parse_error(eal_test);
		return false;
	}

	WRITE_ONCE(eal_test->last_source_mac, ether_addr_to_u64(eth->h_source));
	WRITE_ONCE(eal_test->source_mac_available, true);

	/* VLAN parsing can be added here later if needed. */
	if (eth->h_proto != htons(ETH_P_IP) ||
	    eth_hdr_len < sizeof(*eth) + sizeof(*ip4)) {
		WRITE_ONCE(eal_test->source_ip_available, false);
		eal_test_record_parse_error(eal_test);
		return false;
	}

	ip4 = (const void *)(eth + 1);
	ihl = ip4->ihl * 4;
	if (ip4->version != 4 || ihl < sizeof(*ip4) ||
	    eth_hdr_len < sizeof(*eth) + ihl) {
		WRITE_ONCE(eal_test->source_ip_available, false);
		eal_test_record_parse_error(eal_test);
		return false;
	}
	WRITE_ONCE(eal_test->last_source_ip, ip4->saddr);
	WRITE_ONCE(eal_test->source_ip_available, true);

	if (EAL_INGRESS_GET_TYPE(eal_hdr) != EAL_INGRESS_TYPE_ETHERNET ||
	    !EAL_INGRESS_L4_DSTPORT_MATCH(eal_hdr)) {
		WRITE_ONCE(eal_test->cam_available, false);
		WRITE_ONCE(eal_test->unexpected_cam,
			   READ_ONCE(eal_test->unexpected_cam) + 1);
		return true;
	}

	WRITE_ONCE(eal_test->last_cam_entry,
		   EAL_INGRESS_GET_L4_DSTPORT_ENTRY(eal_hdr));
	WRITE_ONCE(eal_test->cam_available, true);
	if (EAL_INGRESS_GET_L4_DSTPORT_ENTRY(eal_hdr) !=
	    HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY)
		WRITE_ONCE(eal_test->unexpected_cam,
			   READ_ONCE(eal_test->unexpected_cam) + 1);
	return true;
}

static int hfi2_bulksvc_eal_test_handle_rx(struct hfi2_dms *dms, u8 subtype,
					   const struct hfi2_dms_ulp_rx *rx,
					   void *cookie)
{
	struct hfi2_bulksvc_eal_test *eal_test =
		container_of(cookie, struct hfi2_bulksvc_eal_test, common);
	const struct eal_ingress_header *eal_hdr = rx->pkt_hdr;
	u64 bytes = (u64)rx->payload[0].len + rx->payload[1].len;

	(void)dms;
	(void)subtype;
	if (rx->is_ethernet) {
		if (!eal_hdr)
			eal_test_record_parse_error(eal_test);
		else
			eal_test_parse_eth(eal_test, rx, eal_hdr);
	}

	WRITE_ONCE(eal_test->common.rx_packets,
		   READ_ONCE(eal_test->common.rx_packets) + 1);
	WRITE_ONCE(eal_test->rx_bytes, READ_ONCE(eal_test->rx_bytes) + bytes);
	return 0;
}

static ssize_t eal_test_stats_read(struct file *file, char __user *ubuf,
				   size_t len, loff_t *ppos)
{
	struct hfi2_bulksvc_eal_test *eal_test = file->private_data;
	__be32 source_ip = READ_ONCE(eal_test->last_source_ip);
	u64 source_mac = READ_ONCE(eal_test->last_source_mac);
	u8 source_mac_bytes[ETH_ALEN];
	bool cam_available = READ_ONCE(eal_test->cam_available);
	bool source_mac_available = READ_ONCE(eal_test->source_mac_available);
	bool source_ip_available = READ_ONCE(eal_test->source_ip_available);
	char buf[320];
	int n;

	if (source_mac_available)
		u64_to_ether_addr(source_mac, source_mac_bytes);
	n = scnprintf(buf, sizeof(buf), "rx_packets: %llu\nrx_bytes: %llu\n",
		      READ_ONCE(eal_test->common.rx_packets),
		      READ_ONCE(eal_test->rx_bytes));
	if (cam_available)
		n += scnprintf(buf + n, sizeof(buf) - n, "last_cam_entry: %u\n",
			       READ_ONCE(eal_test->last_cam_entry));
	else
		n += scnprintf(buf + n, sizeof(buf) - n,
			       "last_cam_entry: unavailable\n");
	if (source_mac_available)
		n += scnprintf(buf + n, sizeof(buf) - n, "last_source_mac: %pM\n",
			       source_mac_bytes);
	else
		n += scnprintf(buf + n, sizeof(buf) - n,
			       "last_source_mac: unavailable\n");
	if (source_ip_available)
		n += scnprintf(buf + n, sizeof(buf) - n, "last_source_ip: %pI4\n",
			       &source_ip);
	else
		n += scnprintf(buf + n, sizeof(buf) - n,
			       "last_source_ip: unavailable\n");
	n += scnprintf(buf + n, sizeof(buf) - n,
		       "unexpected_cam: %llu\nparse_errors: %llu\nmatch_port: %u\n",
		       READ_ONCE(eal_test->unexpected_cam),
		       READ_ONCE(eal_test->parse_errors),
		       READ_ONCE(eal_test->udp_dport));

	return simple_read_from_buffer(ubuf, len, ppos, buf, n);
}

static const struct file_operations eal_test_stats_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = eal_test_stats_read,
	.llseek = default_llseek,
};

int hfi2_bulksvc_eal_test_init(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_eal_test *eal_test;
	struct hfi2_dms_ulp_match match;
	struct hfi2_dms_ulp_ops ops;
	int ret;

	/*
	 * Unreachable defense-in-depth, not dead code: the sole caller
	 * (hfi2_bulksvc_loan_resources() in bulksvc.c) already gates this
	 * call on hfi2_bulksvc_eal_test_port_valid(), which enforces the
	 * identical port != 0 and port != HFI2_ROCE_UDP_DPORT constraints
	 * before this function is ever entered.  Kept here so this function
	 * remains safe to call directly if that invariant is ever broken.
	 */
	if (!hfi2_bulksvc_eal_test_udp_port) {
		dd_dev_info(svc->dd, "Bulksvc: eal_test ULP disabled (port=0)\n");
		return 0;
	}
	if (hfi2_bulksvc_eal_test_udp_port == HFI2_ROCE_UDP_DPORT) {
		dd_dev_err(svc->dd, "Bulksvc: eal_test UDP port collides with RoCEv2 port %u\n",
			   HFI2_ROCE_UDP_DPORT);
		return -EINVAL;
	}

	eal_test = kzalloc(sizeof(*eal_test), GFP_KERNEL);
	if (!eal_test)
		return -ENOMEM;
	eal_test->common.ulp_id = HFI2_BULKSVC_ULP_ID_EAL_TEST;
	eal_test->udp_dport = hfi2_bulksvc_eal_test_udp_port;

	ops = (struct hfi2_dms_ulp_ops){
		.name = "eal_test",
		.ulp_id = HFI2_BULKSVC_ULP_ID_EAL_TEST,
		.cookie = &eal_test->common,
		.handle_rx = hfi2_bulksvc_eal_test_handle_rx,
	};
	ret = hfi2_dms_ulp_register(hfi2_bulksvc_primary_dms(svc), ops);
	if (ret)
		goto free_peer;

	match = (struct hfi2_dms_ulp_match){
		.ulp_id = HFI2_BULKSVC_ULP_ID_EAL_TEST,
		.ethertype = htons(ETH_P_IP),
		.ip_proto = IPPROTO_UDP,
		.udp_dport = htons(eal_test->udp_dport),
		.prio = 10,
	};
	ret = hfi2_dms_ulp_add_eth_match(hfi2_bulksvc_primary_dms(svc), &match);
	if (ret)
		goto unregister;

	if (svc->dd->verbs_dev.hfi2_ibdev_dbg) {
		eal_test->stats_dentry =
			debugfs_create_file("eal_test_stats", 0400,
					    svc->dd->verbs_dev.hfi2_ibdev_dbg,
					    eal_test, &eal_test_stats_fops);
		if (IS_ERR_OR_NULL(eal_test->stats_dentry))
			eal_test->stats_dentry = NULL;
	}
	eal_test->common.registered = true;
	svc->eal_test_ulp = &eal_test->common;
	return 0;

unregister:
	hfi2_dms_ulp_unregister(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_EAL_TEST);
free_peer:
	kfree(eal_test);
	return ret;
}

void hfi2_bulksvc_eal_test_teardown(struct hfi2_bulksvc *svc)
{
	struct hfi2_bulksvc_ulp_state *st = svc->eal_test_ulp;
	struct hfi2_bulksvc_eal_test *eal_test;

	hfi2_bulksvc_eal_test_clear_dstport(svc);
	if (!st)
		return;

	eal_test = container_of(st, struct hfi2_bulksvc_eal_test, common);
	/*
	 * Unlike the net/uet/roce peers, remove this dentry explicitly:
	 * eal_test is kfree()'d below, before hfi2_dbg_ibdev_exit()'s later
	 * recursive removal runs, so leaving stats_dentry merely NULLed would
	 * open a UAF window for eal_test_stats_read() against freed memory.
	 * debugfs_remove() synchronizes with any in-flight reader before
	 * returning, so it is safe to kfree() eal_test right after.
	 */
	debugfs_remove(eal_test->stats_dentry);
	eal_test->stats_dentry = NULL;
	hfi2_dms_ulp_del_eth_match(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_EAL_TEST);
	hfi2_dms_ulp_unregister(hfi2_bulksvc_primary_dms(svc), HFI2_BULKSVC_ULP_ID_EAL_TEST);
	svc->eal_test_ulp = NULL;
	kfree(eal_test);
}

int hfi2_bulksvc_eal_test_poll(struct hfi2_bulksvc *svc)
{
	(void)svc;
	return 0;
}

#endif /* HFI2_BULKSVC_ULP_STUBS */
