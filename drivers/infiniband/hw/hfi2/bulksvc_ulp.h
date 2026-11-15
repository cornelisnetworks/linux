/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * DMS ULP extension stub peers (RoCE / UET / net).
 *
 * SCAFFOLD / DEVELOPMENT VEHICLE ONLY.  These peers exist so the RoCE, Ultra
 * Ethernet, and net (IPoIB-replacement) ULP teams can start integrating with
 * the DMS data mover on both the OmniPath and Ethernet fabrics without first
 * mastering DMS internals.  They are function stubs plus documentation; they do
 * NOT implement any ULP wire protocol.  See
 * cn-forge-sw/hfisvc/ulp-extension.md for the design.
 *
 * Gated entirely behind HFI2_BULKSVC_ULP_STUBS (default 0 in bulksvc.h), so a
 * production build does not compile or link any of this.
 */
#ifndef DEF_HFI2_BULKSVC_ULP_H
#define DEF_HFI2_BULKSVC_ULP_H

#include <linux/types.h>
#include "bulksvc.h"

struct hfi2_bulksvc;

#define HFI2_BULKSVC_ROCE_UDP_DSTPORT_ENTRY	0

#if HFI2_BULKSVC_ULP_STUBS

#include "chip.h"
#include "eth_hwi.h"
#include "roce_wire.h"

#define HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY	1
#define HFI2_BULKSVC_EAL_TEST_UDP_PORT	59905
extern ushort hfi2_bulksvc_eal_test_udp_port;

static inline bool hfi2_bulksvc_eal_test_udp_port_valid(void)
{
	return hfi2_bulksvc_eal_test_udp_port &&
	       hfi2_bulksvc_eal_test_udp_port != HFI2_ROCE_UDP_DPORT;
}

/* A valid port and reserved steering are both required to register the peer. */
static inline bool hfi2_bulksvc_eal_test_port_valid(struct hfi2_bulksvc *svc)
{
	return svc->eth_rsm_rule >= 0 && svc->eth_rsm_index >= 0 &&
	       hfi2_bulksvc_eal_test_udp_port_valid();
}

static inline void hfi2_bulksvc_eal_test_clear_dstport(struct hfi2_bulksvc *svc)
{
	struct hfi2_devdata *dd = svc->dd;
	u64 reg = 0;

	if (!svc->eal_test_dstport_armed)
		return;

	if (hfi2_is_eth_mode(dd) && !hfi2_bulksvc_primary_dms(svc)->hw_released &&
	    pci_is_enabled(dd->pcidev)) {
		EAL_DSTPORT_SET_VALID(reg, 0);
		hfi2_write_csr(dd, CYR_EAL_DESTINATION_PORT_TABLE +
			  HFI2_BULKSVC_EAL_TEST_UDP_DSTPORT_ENTRY * sizeof(reg), reg);
	}
	svc->eal_test_dstport_armed = false;
}

/*
 * Host-local ULP-id assignments (1..HFI2_DMS_ULP_MAX-1; 0 is reserved for
 * native OPA/BTS).  These are routing values only -- they are never carried on
 * the Ethernet wire.
 */
#define HFI2_BULKSVC_ULP_ID_ROCE	1
#define HFI2_BULKSVC_ULP_ID_UET		2
#define HFI2_BULKSVC_ULP_ID_NET		3
#define HFI2_BULKSVC_ULP_ID_EAL_TEST	4

/*
 * Common per-ULP peer state.  Each peer embeds this as the FIRST member of its
 * own private struct (e.g. struct hfi2_bulksvc_roce in bulksvc_roce.c) and
 * registers a pointer to it as the DMS cookie; the peer recovers its private
 * struct with container_of().  This shows how a ULP extends the shared
 * lifecycle/accounting fields with state unique to that ULP.
 */
struct hfi2_bulksvc_ulp_state {
	bool registered;
	u8 ulp_id;
	u64 rx_packets;
};

int hfi2_bulksvc_roce_init(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_roce_teardown(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_roce_poll(struct hfi2_bulksvc *svc);

int hfi2_bulksvc_uet_init(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_uet_teardown(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_uet_poll(struct hfi2_bulksvc *svc);

int hfi2_bulksvc_net_init(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_net_teardown(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_net_poll(struct hfi2_bulksvc *svc);

int hfi2_bulksvc_eal_test_init(struct hfi2_bulksvc *svc);
void hfi2_bulksvc_eal_test_teardown(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_eal_test_poll(struct hfi2_bulksvc *svc);

/*
 * Tear down every registered ULP stub peer.  Centralizes the per-ULP
 * _teardown() list so a future ULP only needs its _teardown() added
 * here, not duplicated at each call site.  Called from two ordered
 * places: early in remove_one() (while the debugfs parent directory
 * still exists, before hfi2_dbg_ibdev_exit()'s recursive removal) and
 * again, as a safe no-op, from hfi2_bulksvc_teardown() (used on other,
 * non-rmmod cleanup paths where the early call in remove_one() never
 * ran).  dms.dd stays set across both calls (see the comment on this
 * function's definition in bulksvc.c), so its guard does not gate the
 * second call; what makes the second call a no-op instead of a double
 * removal is that each hfi2_bulksvc_{net,uet,roce,eal_test}_teardown()
 * NULLs its own svc->*_ulp state pointer and self-guards on it.  The
 * eal_test teardown also disarms its dst-port entry once using the armed
 * flag, skipping the CSR write after hardware release or PCI disable.
 * A second call therefore neither double-frees nor touches that CSR.
 */
void hfi2_bulksvc_ulp_teardown_all(struct hfi2_bulksvc *svc);

#endif /* HFI2_BULKSVC_ULP_STUBS */

#endif /* DEF_HFI2_BULKSVC_ULP_H */
