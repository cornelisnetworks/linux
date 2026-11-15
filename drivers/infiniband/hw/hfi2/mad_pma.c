// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015-2018 Intel Corporation.
 * Copyright(c) 2023-2026 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 *
 * Performance Management Agent: PortCounters/DataCounters/ErrorInfo,
 * congestion control attributes and the perf-mad dispatch.  Split out
 * of mad.c; the Subnet Management Agent lives in mad_sma.c.
 */

#include <linux/net.h>
#include <rdma/opa_addr.h>

#include "hfi2.h"
#include "file_ops.h"
#include "chip_gen.h"
#include "mad.h"
#include "trace.h"
#include "qp.h"
#include <rdma/ib_sa.h>


struct opa_pma_mad {
	struct ib_mad_hdr mad_hdr;
	u8 data[2024];
} __packed;

struct opa_port_status_req {
	__u8 port_num;
	__u8 reserved[3];
	__be32 vl_select_mask;
};

#define VL_MASK_ALL 0x00000000000080ffUL

struct opa_port_status_rsp {
	__u8 port_num;
	__u8 reserved[3];
	__be32 vl_select_mask;

	/* Data counters */
	__be64 port_xmit_data;
	__be64 port_rcv_data;
	__be64 port_xmit_pkts;
	__be64 port_rcv_pkts;
	__be64 port_multicast_xmit_pkts;
	__be64 port_multicast_rcv_pkts;
	__be64 port_xmit_wait;
	__be64 sw_port_congestion;
	__be64 port_rcv_fecn;
	__be64 port_rcv_becn;
	__be64 port_xmit_time_cong;
	__be64 port_xmit_wasted_bw;
	__be64 port_xmit_wait_data;
	__be64 port_rcv_bubble;
	__be64 port_mark_fecn;
	/* Error counters */
	__be64 port_rcv_constraint_errors;
	__be64 port_rcv_switch_relay_errors;
	__be64 port_xmit_discards;
	__be64 port_xmit_constraint_errors;
	__be64 port_rcv_remote_physical_errors;
	__be64 local_link_integrity_errors;
	__be64 port_rcv_errors;
	__be64 excessive_buffer_overruns;
	__be64 fm_config_errors;
	__be32 link_error_recovery;
	__be32 link_downed;
	u8 uncorrectable_errors;

	u8 link_quality_indicator; /* 5res, 3bit */
	u8 res2[6];
	struct _vls_pctrs {
		/* per-VL Data counters */
		__be64 port_vl_xmit_data;
		__be64 port_vl_rcv_data;
		__be64 port_vl_xmit_pkts;
		__be64 port_vl_rcv_pkts;
		__be64 port_vl_xmit_wait;
		__be64 sw_port_vl_congestion;
		__be64 port_vl_rcv_fecn;
		__be64 port_vl_rcv_becn;
		__be64 port_xmit_time_cong;
		__be64 port_vl_xmit_wasted_bw;
		__be64 port_vl_xmit_wait_data;
		__be64 port_vl_rcv_bubble;
		__be64 port_vl_mark_fecn;
		__be64 port_vl_xmit_discards;
	} vls[]; /* real array size defined by # bits set in vl_select_mask */
};

enum counter_selects {
	CS_PORT_XMIT_DATA = (1 << 31),
	CS_PORT_RCV_DATA = (1 << 30),
	CS_PORT_XMIT_PKTS = (1 << 29),
	CS_PORT_RCV_PKTS = (1 << 28),
	CS_PORT_MCAST_XMIT_PKTS = (1 << 27),
	CS_PORT_MCAST_RCV_PKTS = (1 << 26),
	CS_PORT_XMIT_WAIT = (1 << 25),
	CS_SW_PORT_CONGESTION = (1 << 24),
	CS_PORT_RCV_FECN = (1 << 23),
	CS_PORT_RCV_BECN = (1 << 22),
	CS_PORT_XMIT_TIME_CONG = (1 << 21),
	CS_PORT_XMIT_WASTED_BW = (1 << 20),
	CS_PORT_XMIT_WAIT_DATA = (1 << 19),
	CS_PORT_RCV_BUBBLE = (1 << 18),
	CS_PORT_MARK_FECN = (1 << 17),
	CS_PORT_RCV_CONSTRAINT_ERRORS = (1 << 16),
	CS_PORT_RCV_SWITCH_RELAY_ERRORS = (1 << 15),
	CS_PORT_XMIT_DISCARDS = (1 << 14),
	CS_PORT_XMIT_CONSTRAINT_ERRORS = (1 << 13),
	CS_PORT_RCV_REMOTE_PHYSICAL_ERRORS = (1 << 12),
	CS_LOCAL_LINK_INTEGRITY_ERRORS = (1 << 11),
	CS_PORT_RCV_ERRORS = (1 << 10),
	CS_EXCESSIVE_BUFFER_OVERRUNS = (1 << 9),
	CS_FM_CONFIG_ERRORS = (1 << 8),
	CS_LINK_ERROR_RECOVERY = (1 << 7),
	CS_LINK_DOWNED = (1 << 6),
	CS_UNCORRECTABLE_ERRORS = (1 << 5),
};

struct opa_clear_port_status {
	__be64 port_select_mask[4];
	__be32 counter_select_mask;
};


#define MSK_LLI 0x000000f0
#define MSK_LLI_SFT 4
#define MSK_LER 0x0000000f
#define MSK_LER_SFT 0
#define ADD_LLI 8
#define ADD_LER 2

/* Request contains first three fields, response contains those plus the rest */
struct opa_port_data_counters_msg {
	__be64 port_select_mask[4];
	__be32 vl_select_mask;
	__be32 resolution;

	/* Response fields follow */
	struct _port_dctrs {
		u8 port_number;
		u8 reserved2[3];
		__be32 link_quality_indicator; /* 29res, 3bit */

		/* Data counters */
		__be64 port_xmit_data;
		__be64 port_rcv_data;
		__be64 port_xmit_pkts;
		__be64 port_rcv_pkts;
		__be64 port_multicast_xmit_pkts;
		__be64 port_multicast_rcv_pkts;
		__be64 port_xmit_wait;
		__be64 sw_port_congestion;
		__be64 port_rcv_fecn;
		__be64 port_rcv_becn;
		__be64 port_xmit_time_cong;
		__be64 port_xmit_wasted_bw;
		__be64 port_xmit_wait_data;
		__be64 port_rcv_bubble;
		__be64 port_mark_fecn;

		__be64 port_error_counter_summary;
		/* Sum of error counts/port */

		struct _vls_dctrs {
			/* per-VL Data counters */
			__be64 port_vl_xmit_data;
			__be64 port_vl_rcv_data;
			__be64 port_vl_xmit_pkts;
			__be64 port_vl_rcv_pkts;
			__be64 port_vl_xmit_wait;
			__be64 sw_port_vl_congestion;
			__be64 port_vl_rcv_fecn;
			__be64 port_vl_rcv_becn;
			__be64 port_xmit_time_cong;
			__be64 port_vl_xmit_wasted_bw;
			__be64 port_vl_xmit_wait_data;
			__be64 port_vl_rcv_bubble;
			__be64 port_vl_mark_fecn;
		} vls[];
		/* array size defined by #bits set in vl_select_mask*/
	} port;
};

struct opa_port_error_counters64_msg {
	/*
	 * Request contains first two fields, response contains the
	 * whole magilla
	 */
	__be64 port_select_mask[4];
	__be32 vl_select_mask;

	/* Response-only fields follow */
	__be32 reserved1;
	struct _port_ectrs {
		u8 port_number;
		u8 reserved2[7];
		__be64 port_rcv_constraint_errors;
		__be64 port_rcv_switch_relay_errors;
		__be64 port_xmit_discards;
		__be64 port_xmit_constraint_errors;
		__be64 port_rcv_remote_physical_errors;
		__be64 local_link_integrity_errors;
		__be64 port_rcv_errors;
		__be64 excessive_buffer_overruns;
		__be64 fm_config_errors;
		__be32 link_error_recovery;
		__be32 link_downed;
		u8 uncorrectable_errors;
		u8 reserved3[7];
		struct _vls_ectrs {
			__be64 port_vl_xmit_discards;
		} vls[];
		/* array size defined by #bits set in vl_select_mask */
	} port;
};

struct opa_port_error_info_msg {
	__be64 port_select_mask[4];
	__be32 error_info_select_mask;
	__be32 reserved1;
	struct _port_ei {
		u8 port_number;
		u8 reserved2[7];

		/* PortRcvErrorInfo */
		struct {
			u8 status_and_code;
			union {
				u8 raw[17];
				struct {
					/* EI1to12 format */
					u8 packet_flit1[8];
					u8 packet_flit2[8];
					u8 remaining_flit_bits12;
				} ei1to12;
				struct {
					u8 packet_bytes[8];
					u8 remaining_flit_bits;
				} ei13;
			} ei;
			u8 reserved3[6];
		} __packed port_rcv_ei;

		/* ExcessiveBufferOverrunInfo */
		struct {
			u8 status_and_sc;
			u8 reserved4[7];
		} __packed excessive_buffer_overrun_ei;

		/* PortXmitConstraintErrorInfo */
		struct {
			u8 status;
			u8 reserved5;
			__be16 pkey;
			__be32 slid;
		} __packed port_xmit_constraint_ei;

		/* PortRcvConstraintErrorInfo */
		struct {
			u8 status;
			u8 reserved6;
			__be16 pkey;
			__be32 slid;
		} __packed port_rcv_constraint_ei;

		/* PortRcvSwitchRelayErrorInfo */
		struct {
			u8 status_and_code;
			u8 reserved7[3];
			__u32 error_info;
		} __packed port_rcv_switch_relay_ei;

		/* UncorrectableErrorInfo */
		struct {
			u8 status_and_code;
			u8 reserved8;
		} __packed uncorrectable_ei;

		/* FMConfigErrorInfo */
		struct {
			u8 status_and_code;
			u8 error_info;
		} __packed fm_config_ei;
		__u32 reserved9;
	} port;
};

/* opa_port_error_info_msg error_info_select_mask bit definitions */
enum error_info_selects {
	ES_PORT_RCV_ERROR_INFO = (1 << 31),
	ES_EXCESSIVE_BUFFER_OVERRUN_INFO = (1 << 30),
	ES_PORT_XMIT_CONSTRAINT_ERROR_INFO = (1 << 29),
	ES_PORT_RCV_CONSTRAINT_ERROR_INFO = (1 << 28),
	ES_PORT_RCV_SWITCH_RELAY_ERROR_INFO = (1 << 27),
	ES_UNCORRECTABLE_ERROR_INFO = (1 << 26),
	ES_FM_CONFIG_ERROR_INFO = (1 << 25)
};

static int pma_get_opa_classportinfo(struct opa_pma_mad *pmp,
				     struct ib_device *ibdev, u32 *resp_len)
{
	struct opa_class_port_info *p = (struct opa_class_port_info *)pmp->data;

	memset(pmp->data, 0, sizeof(pmp->data));

	if (pmp->mad_hdr.attr_mod != 0)
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;

	p->base_version = OPA_MGMT_BASE_VERSION;
	p->class_version = OPA_SM_CLASS_VERSION;
	/*
	 * Expected response time is 4.096 usec. * 2^18 == 1.073741824 sec.
	 */
	p->cap_mask2_resp_time = cpu_to_be32(18);

	if (resp_len)
		*resp_len += sizeof(*p);

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static void a0_portstatus(struct hfi2_pportdata *ppd,
			  struct opa_port_status_rsp *rsp)
{
	if (!hfi2_is_bx(ppd->dd)) {
		unsigned long vl;
		u64 sum_vl_xmit_wait = 0;
		unsigned long vl_all_mask = VL_MASK_ALL;

		for_each_set_bit(vl, &vl_all_mask, BITS_PER_LONG) {
			u64 tmp = sum_vl_xmit_wait +
				  hfi2_read_port_cntr(ppd, C_TX_WAIT_VL,
						      idx_from_vl(vl));
			if (tmp < sum_vl_xmit_wait) {
				/* we wrapped */
				sum_vl_xmit_wait = (u64)~0;
				break;
			}
			sum_vl_xmit_wait = tmp;
		}
		if (be64_to_cpu(rsp->port_xmit_wait) > sum_vl_xmit_wait)
			rsp->port_xmit_wait = cpu_to_be64(sum_vl_xmit_wait);
	}
}

/**
 * hfi2_tx_link_width - convert link width bitmask to integer
 * value representing actual link width.
 * @link_width: width of active link
 * @return: return index of the bit set in link_width var
 *
 * The function convert and return the index of bit set
 * that indicate the current link width.
 */
u16 hfi2_tx_link_width(u16 link_width)
{
	u16 masked = link_width & ((1u << LINK_WIDTH_DEFAULT) - 1);

	return masked ? fls(masked) : LINK_WIDTH_DEFAULT;
}

/**
 * hfi2_get_xmit_wait_counters - Convert HFI 's SendWaitCnt/SendWaitVlCnt
 * counter in unit of TXE cycle times to flit times.
 * @ppd: info of physical Hfi port
 * @link_width: width of active link
 * @link_speed: speed of active link
 * @vl: represent VL0-VL7, VL15 for PortVLXmitWait counters request
 * and if vl value is C_VL_COUNT, it represent SendWaitCnt
 * counter request
 * @return: return SendWaitCnt/SendWaitVlCnt counter value per vl.
 *
 * Convert SendWaitCnt/SendWaitVlCnt counter from TXE cycle times to
 * flit times. Call this function to samples these counters. This
 * function will calculate for previous state transition and update
 * current state at end of function using ppd->prev_link_width and
 * ppd->port_vl_xmit_wait_last to port_vl_xmit_wait_curr and link_width.
 */
u64 hfi2_get_xmit_wait_counters(struct hfi2_pportdata *ppd, u16 link_width,
				u16 link_speed, int vl)
{
	u64 port_vl_xmit_wait_curr;
	u64 delta_vl_xmit_wait;
	u64 xmit_wait_val;

	if (vl > C_VL_COUNT)
		return 0;
	if (vl < C_VL_COUNT)
		port_vl_xmit_wait_curr =
			hfi2_read_port_cntr(ppd, C_TX_WAIT_VL, vl);
	else
		port_vl_xmit_wait_curr =
			hfi2_read_port_cntr(ppd, C_TX_WAIT, CNTR_INVALID_VL);

	xmit_wait_val =
		port_vl_xmit_wait_curr - ppd->port_vl_xmit_wait_last[vl];
	delta_vl_xmit_wait = convert_xmit_counter(
		xmit_wait_val, ppd->prev_link_width, link_speed);

	ppd->vl_xmit_flit_cnt[vl] += delta_vl_xmit_wait;
	ppd->port_vl_xmit_wait_last[vl] = port_vl_xmit_wait_curr;
	ppd->prev_link_width = link_width;

	return ppd->vl_xmit_flit_cnt[vl];
}

static int pma_get_opa_portstatus(struct opa_pma_mad *pmp,
				  struct ib_device *ibdev, u32 port,
				  u32 *resp_len)
{
	struct opa_port_status_req *req =
		(struct opa_port_status_req *)pmp->data;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct opa_port_status_rsp *rsp;
	unsigned long vl_select_mask = be32_to_cpu(req->vl_select_mask);
	unsigned long vl;
	size_t response_data_size;
	u32 nports = be32_to_cpu(pmp->mad_hdr.attr_mod) >> 24;
	u32 port_num = req->port_num;
	u8 hfi2_num_vls = hweight64(vl_select_mask);
	struct _vls_pctrs *vlinfo;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	int vfi;
	u64 tmp, tmp2;
	u16 link_width;
	u16 link_speed;

	response_data_size = struct_size(rsp, vls, hfi2_num_vls);
	if (response_data_size > sizeof(pmp->data)) {
		pmp->mad_hdr.status |= OPA_PM_STATUS_REQUEST_TOO_LARGE;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	if (nports != 1 || (port_num && port_num != port) ||
	    hfi2_num_vls > OPA_MAX_VLS || (vl_select_mask & ~VL_MASK_ALL)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	memset(pmp->data, 0, sizeof(pmp->data));

	rsp = (struct opa_port_status_rsp *)pmp->data;
	if (port_num)
		rsp->port_num = port_num;
	else
		rsp->port_num = port;

	rsp->port_rcv_constraint_errors = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_RCV_CSTR_ERR, CNTR_INVALID_VL));

	dd->params->read_link_quality(ppd, &rsp->link_quality_indicator);

	rsp->vl_select_mask = cpu_to_be32((u32)vl_select_mask);
	rsp->port_xmit_data = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_XMIT_FLITS, CNTR_INVALID_VL));
	rsp->port_rcv_data = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_FLITS, CNTR_INVALID_VL));
	rsp->port_xmit_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_XMIT_PKTS, CNTR_INVALID_VL));
	rsp->port_rcv_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_PKTS, CNTR_INVALID_VL));
	rsp->port_multicast_xmit_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_MC_XMIT_PKTS, CNTR_INVALID_VL));
	rsp->port_multicast_rcv_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_MC_RCV_PKTS, CNTR_INVALID_VL));
	/*
	 * Convert PortXmitWait counter from TXE cycle times
	 * to flit times.
	 */
	link_width = hfi2_tx_link_width(ppd->link_width_downgrade_tx_active);
	link_speed = get_link_speed(ppd->link_speed_active);
	rsp->port_xmit_wait = cpu_to_be64(hfi2_get_xmit_wait_counters(
		ppd, link_width, link_speed, C_VL_COUNT));
	rsp->port_rcv_fecn = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_FCN, CNTR_INVALID_VL));
	rsp->port_rcv_becn = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_BCN, CNTR_INVALID_VL));
	rsp->port_xmit_discards = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_XMIT_DSCD, CNTR_INVALID_VL));
	rsp->port_xmit_constraint_errors = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_XMIT_CSTR_ERR, CNTR_INVALID_VL));
	rsp->port_rcv_remote_physical_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RMT_PHY_ERR, CNTR_INVALID_VL));
	rsp->local_link_integrity_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RX_REPLAY, CNTR_INVALID_VL));
	tmp = hfi2_read_dev_cntr(dd, C_DC_SEQ_CRC_CNT, CNTR_INVALID_VL);
	tmp2 = tmp + hfi2_read_dev_cntr(dd, C_DC_REINIT_FROM_PEER_CNT,
					CNTR_INVALID_VL);
	if (tmp2 > (u32)UINT_MAX || tmp2 < tmp) {
		/* overflow/wrapped */
		rsp->link_error_recovery = cpu_to_be32(~0);
	} else {
		rsp->link_error_recovery = cpu_to_be32(tmp2);
	}
	rsp->port_rcv_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_ERR, CNTR_INVALID_VL));
	rsp->excessive_buffer_overruns = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_RCV_OVF, CNTR_INVALID_VL));
	rsp->fm_config_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_FM_CFG_ERR, CNTR_INVALID_VL));
	rsp->link_downed = cpu_to_be32(
		hfi2_read_port_cntr(ppd, C_SW_LINK_DOWN, CNTR_INVALID_VL));

	/* rsp->uncorrectable_errors is 8 bits wide, and it pegs at 0xff */
	tmp = hfi2_read_dev_cntr(dd, C_DC_UNC_ERR, CNTR_INVALID_VL);
	rsp->uncorrectable_errors = tmp < 0x100 ? (tmp & 0xff) : 0xff;

	vlinfo = &rsp->vls[0];
	vfi = 0;
	/* The vl_select_mask has been checked above, and we know
	 * that it contains only entries which represent valid VLs.
	 * So in the for_each_set_bit() loop below, we don't need
	 * any additional checks for vl.
	 */
	for_each_set_bit(vl, &vl_select_mask, BITS_PER_LONG) {
		memset(vlinfo, 0, sizeof(*vlinfo));

		tmp = hfi2_read_dev_cntr(dd, C_DC_RX_FLIT_VL, idx_from_vl(vl));
		rsp->vls[vfi].port_vl_rcv_data = cpu_to_be64(tmp);

		rsp->vls[vfi].port_vl_rcv_pkts = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RX_PKT_VL, idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_xmit_data =
			cpu_to_be64(hfi2_read_port_cntr(ppd, C_TX_FLIT_VL,
							idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_xmit_pkts = cpu_to_be64(
			hfi2_read_port_cntr(ppd, C_TX_PKT_VL, idx_from_vl(vl)));
		/*
		 * Convert PortVlXmitWait counter from TXE cycle
		 * times to flit times.
		 */
		rsp->vls[vfi].port_vl_xmit_wait = cpu_to_be64(
			hfi2_get_xmit_wait_counters(ppd, link_width, link_speed,
						    idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_rcv_fecn = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RCV_FCN_VL, idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_rcv_becn = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RCV_BCN_VL, idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_xmit_discards =
			cpu_to_be64(hfi2_read_port_cntr(ppd, C_SW_XMIT_DSCD_VL,
							idx_from_vl(vl)));
		vlinfo++;
		vfi++;
	}

	a0_portstatus(ppd, rsp);

	if (resp_len)
		*resp_len += response_data_size;

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static u64 get_error_counter_summary(struct ib_device *ibdev, u32 port,
				     u8 res_lli, u8 res_ler)
{
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u64 error_counter_summary = 0, tmp;

	error_counter_summary +=
		hfi2_read_port_cntr(ppd, C_SW_RCV_CSTR_ERR, CNTR_INVALID_VL);
	/* port_rcv_switch_relay_errors is 0 for HFIs */
	error_counter_summary +=
		hfi2_read_port_cntr(ppd, C_SW_XMIT_DSCD, CNTR_INVALID_VL);
	error_counter_summary +=
		hfi2_read_port_cntr(ppd, C_SW_XMIT_CSTR_ERR, CNTR_INVALID_VL);
	error_counter_summary +=
		hfi2_read_dev_cntr(dd, C_DC_RMT_PHY_ERR, CNTR_INVALID_VL);
	/* local link integrity must be right-shifted by the lli resolution */
	error_counter_summary +=
		(hfi2_read_dev_cntr(dd, C_DC_RX_REPLAY, CNTR_INVALID_VL) >>
		 res_lli);
	/* link error recovery must b right-shifted by the ler resolution */
	tmp = hfi2_read_dev_cntr(dd, C_DC_SEQ_CRC_CNT, CNTR_INVALID_VL);
	tmp += hfi2_read_dev_cntr(dd, C_DC_REINIT_FROM_PEER_CNT,
				  CNTR_INVALID_VL);
	error_counter_summary += (tmp >> res_ler);
	error_counter_summary +=
		hfi2_read_dev_cntr(dd, C_DC_RCV_ERR, CNTR_INVALID_VL);
	error_counter_summary +=
		hfi2_read_port_cntr(ppd, C_RCV_OVF, CNTR_INVALID_VL);
	error_counter_summary +=
		hfi2_read_dev_cntr(dd, C_DC_FM_CFG_ERR, CNTR_INVALID_VL);
	/* ppd->link_downed is a 32-bit value */
	error_counter_summary +=
		hfi2_read_port_cntr(ppd, C_SW_LINK_DOWN, CNTR_INVALID_VL);
	tmp = hfi2_read_dev_cntr(dd, C_DC_UNC_ERR, CNTR_INVALID_VL);
	/* this is an 8-bit quantity */
	error_counter_summary += tmp < 0x100 ? (tmp & 0xff) : 0xff;

	return error_counter_summary;
}

static void a0_datacounters(struct hfi2_pportdata *ppd, struct _port_dctrs *rsp)
{
	if (!hfi2_is_bx(ppd->dd)) {
		unsigned long vl;
		u64 sum_vl_xmit_wait = 0;
		unsigned long vl_all_mask = VL_MASK_ALL;

		for_each_set_bit(vl, &vl_all_mask, BITS_PER_LONG) {
			u64 tmp = sum_vl_xmit_wait +
				  hfi2_read_port_cntr(ppd, C_TX_WAIT_VL,
						      idx_from_vl(vl));
			if (tmp < sum_vl_xmit_wait) {
				/* we wrapped */
				sum_vl_xmit_wait = (u64)~0;
				break;
			}
			sum_vl_xmit_wait = tmp;
		}
		if (be64_to_cpu(rsp->port_xmit_wait) > sum_vl_xmit_wait)
			rsp->port_xmit_wait = cpu_to_be64(sum_vl_xmit_wait);
	}
}

static void pma_get_opa_port_dctrs(struct ib_device *ibdev,
				   struct _port_dctrs *rsp)
{
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);

	rsp->port_xmit_data = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_XMIT_FLITS, CNTR_INVALID_VL));
	rsp->port_rcv_data = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_FLITS, CNTR_INVALID_VL));
	rsp->port_xmit_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_XMIT_PKTS, CNTR_INVALID_VL));
	rsp->port_rcv_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_PKTS, CNTR_INVALID_VL));
	rsp->port_multicast_xmit_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_MC_XMIT_PKTS, CNTR_INVALID_VL));
	rsp->port_multicast_rcv_pkts = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_MC_RCV_PKTS, CNTR_INVALID_VL));
}

static int pma_get_opa_datacounters(struct opa_pma_mad *pmp,
				    struct ib_device *ibdev, u32 port,
				    u32 *resp_len)
{
	struct opa_port_data_counters_msg *req =
		(struct opa_port_data_counters_msg *)pmp->data;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct _port_dctrs *rsp;
	struct _vls_dctrs *vlinfo;
	size_t response_data_size;
	u32 num_ports;
	u8 lq, hfi2_num_vls;
	u8 res_lli, res_ler;
	u64 port_mask;
	u32 port_num;
	unsigned long vl;
	unsigned long vl_select_mask;
	int vfi;
	u16 link_width;
	u16 link_speed;

	num_ports = be32_to_cpu(pmp->mad_hdr.attr_mod) >> 24;
	hfi2_num_vls = hweight32(be32_to_cpu(req->vl_select_mask));
	vl_select_mask = be32_to_cpu(req->vl_select_mask);
	res_lli = (u8)(be32_to_cpu(req->resolution) & MSK_LLI) >> MSK_LLI_SFT;
	res_lli = res_lli ? res_lli + ADD_LLI : 0;
	res_ler = (u8)(be32_to_cpu(req->resolution) & MSK_LER) >> MSK_LER_SFT;
	res_ler = res_ler ? res_ler + ADD_LER : 0;

	if (num_ports != 1 || (vl_select_mask & ~VL_MASK_ALL)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	/* Sanity check */
	response_data_size = struct_size(req, port.vls, hfi2_num_vls);

	if (response_data_size > sizeof(pmp->data)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	/*
	 * The bit set in the mask needs to be consistent with the
	 * port the request came in on.
	 */
	port_mask = be64_to_cpu(req->port_select_mask[3]);
	port_num = find_first_bit((unsigned long *)&port_mask,
				  sizeof(port_mask) * 8);

	if (port_num != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	rsp = &req->port;
	memset(rsp, 0, sizeof(*rsp));

	rsp->port_number = port;
	/*
	 * Note that link_quality_indicator is a 32 bit quantity in
	 * 'datacounters' queries (as opposed to 'portinfo' queries,
	 * where it's a byte).
	 */
	dd->params->read_link_quality(ppd, &lq);
	rsp->link_quality_indicator = cpu_to_be32((u32)lq);
	pma_get_opa_port_dctrs(ibdev, rsp);

	/*
	 * Convert PortXmitWait counter from TXE
	 * cycle times to flit times.
	 */
	link_width = hfi2_tx_link_width(ppd->link_width_downgrade_tx_active);
	link_speed = get_link_speed(ppd->link_speed_active);
	rsp->port_xmit_wait = cpu_to_be64(hfi2_get_xmit_wait_counters(
		ppd, link_width, link_speed, C_VL_COUNT));
	rsp->port_rcv_fecn = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_FCN, CNTR_INVALID_VL));
	rsp->port_rcv_becn = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_BCN, CNTR_INVALID_VL));
	rsp->port_error_counter_summary = cpu_to_be64(
		get_error_counter_summary(ibdev, port, res_lli, res_ler));

	vlinfo = &rsp->vls[0];
	vfi = 0;
	/* The vl_select_mask has been checked above, and we know
	 * that it contains only entries which represent valid VLs.
	 * So in the for_each_set_bit() loop below, we don't need
	 * any additional checks for vl.
	 */
	for_each_set_bit(vl, &vl_select_mask, BITS_PER_LONG) {
		memset(vlinfo, 0, sizeof(*vlinfo));

		rsp->vls[vfi].port_vl_xmit_data =
			cpu_to_be64(hfi2_read_port_cntr(ppd, C_TX_FLIT_VL,
							idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_rcv_data = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RX_FLIT_VL, idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_xmit_pkts = cpu_to_be64(
			hfi2_read_port_cntr(ppd, C_TX_PKT_VL, idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_rcv_pkts = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RX_PKT_VL, idx_from_vl(vl)));

		/*
		 * Convert PortVlXmitWait counter from TXE
		 * cycle times to flit times.
		 */
		rsp->vls[vfi].port_vl_xmit_wait = cpu_to_be64(
			hfi2_get_xmit_wait_counters(ppd, link_width, link_speed,
						    idx_from_vl(vl)));

		rsp->vls[vfi].port_vl_rcv_fecn = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RCV_FCN_VL, idx_from_vl(vl)));
		rsp->vls[vfi].port_vl_rcv_becn = cpu_to_be64(hfi2_read_dev_cntr(
			dd, C_DC_RCV_BCN_VL, idx_from_vl(vl)));

		/* rsp->port_vl_xmit_time_cong is 0 for HFIs */
		/* rsp->port_vl_xmit_wasted_bw ??? */
		/* port_vl_xmit_wait_data - TXE (table 13-9 HFI spec) ???
		 * does this differ from rsp->vls[vfi].port_vl_xmit_wait
		 */
		/*rsp->vls[vfi].port_vl_mark_fecn =
		 *	cpu_to_be64(hfi2_read_csr(dd, DCC_PRF_PORT_VL_MARK_FECN_CNT
		 *		+ offset));
		 */
		vlinfo++;
		vfi++;
	}

	a0_datacounters(ppd, rsp);

	if (resp_len)
		*resp_len += response_data_size;

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static int pma_get_ib_portcounters_ext(struct ib_pma_mad *pmp,
				       struct ib_device *ibdev, u32 port)
{
	struct ib_pma_portcounters_ext *p =
		(struct ib_pma_portcounters_ext *)pmp->data;
	struct _port_dctrs rsp;

	if (pmp->mad_hdr.attr_mod != 0 || p->port_select != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	memset(&rsp, 0, sizeof(rsp));
	pma_get_opa_port_dctrs(ibdev, &rsp);

	p->port_xmit_data = rsp.port_xmit_data;
	p->port_rcv_data = rsp.port_rcv_data;
	p->port_xmit_packets = rsp.port_xmit_pkts;
	p->port_rcv_packets = rsp.port_rcv_pkts;
	p->port_unicast_xmit_packets = 0;
	p->port_unicast_rcv_packets = 0;
	p->port_multicast_xmit_packets = rsp.port_multicast_xmit_pkts;
	p->port_multicast_rcv_packets = rsp.port_multicast_rcv_pkts;

bail:
	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static void pma_get_opa_port_ectrs(struct ib_device *ibdev,
				   struct _port_ectrs *rsp, u32 port)
{
	u64 tmp, tmp2;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);

	tmp = hfi2_read_dev_cntr(dd, C_DC_SEQ_CRC_CNT, CNTR_INVALID_VL);
	tmp2 = tmp + hfi2_read_dev_cntr(dd, C_DC_REINIT_FROM_PEER_CNT,
					CNTR_INVALID_VL);
	if (tmp2 > (u32)UINT_MAX || tmp2 < tmp) {
		/* overflow/wrapped */
		rsp->link_error_recovery = cpu_to_be32(~0);
	} else {
		rsp->link_error_recovery = cpu_to_be32(tmp2);
	}

	rsp->link_downed = cpu_to_be32(
		hfi2_read_port_cntr(ppd, C_SW_LINK_DOWN, CNTR_INVALID_VL));
	rsp->port_rcv_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_ERR, CNTR_INVALID_VL));
	rsp->port_rcv_remote_physical_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RMT_PHY_ERR, CNTR_INVALID_VL));
	rsp->port_rcv_switch_relay_errors = 0;
	rsp->port_xmit_discards = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_XMIT_DSCD, CNTR_INVALID_VL));
	rsp->port_xmit_constraint_errors = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_XMIT_CSTR_ERR, CNTR_INVALID_VL));
	rsp->port_rcv_constraint_errors = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_SW_RCV_CSTR_ERR, CNTR_INVALID_VL));
	rsp->local_link_integrity_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RX_REPLAY, CNTR_INVALID_VL));
	rsp->excessive_buffer_overruns = cpu_to_be64(
		hfi2_read_port_cntr(ppd, C_RCV_OVF, CNTR_INVALID_VL));
}

static int pma_get_opa_porterrors(struct opa_pma_mad *pmp,
				  struct ib_device *ibdev, u32 port,
				  u32 *resp_len)
{
	size_t response_data_size;
	struct _port_ectrs *rsp;
	u32 port_num;
	struct opa_port_error_counters64_msg *req;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	u32 num_ports;
	u8 num_pslm;
	u8 hfi2_num_vls;
	struct hfi2_ibport *ibp;
	struct hfi2_pportdata *ppd;
	struct _vls_ectrs *vlinfo;
	unsigned long vl;
	u64 port_mask, tmp;
	unsigned long vl_select_mask;
	int vfi;

	req = (struct opa_port_error_counters64_msg *)pmp->data;

	num_ports = be32_to_cpu(pmp->mad_hdr.attr_mod) >> 24;

	num_pslm = hweight64(be64_to_cpu(req->port_select_mask[3]));
	hfi2_num_vls = hweight32(be32_to_cpu(req->vl_select_mask));

	if (num_ports != 1 || num_ports != num_pslm) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	response_data_size = struct_size(req, port.vls, hfi2_num_vls);

	if (response_data_size > sizeof(pmp->data)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}
	/*
	 * The bit set in the mask needs to be consistent with the
	 * port the request came in on.
	 */
	port_mask = be64_to_cpu(req->port_select_mask[3]);
	port_num = find_first_bit((unsigned long *)&port_mask,
				  sizeof(port_mask) * 8);

	if (port_num != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	rsp = &req->port;

	ibp = to_iport(ibdev, port_num);
	ppd = ppd_from_ibp(ibp);

	memset(rsp, 0, sizeof(*rsp));
	rsp->port_number = port_num;

	pma_get_opa_port_ectrs(ibdev, rsp, port_num);

	rsp->port_rcv_remote_physical_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RMT_PHY_ERR, CNTR_INVALID_VL));
	rsp->fm_config_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_FM_CFG_ERR, CNTR_INVALID_VL));
	tmp = hfi2_read_dev_cntr(dd, C_DC_UNC_ERR, CNTR_INVALID_VL);

	rsp->uncorrectable_errors = tmp < 0x100 ? (tmp & 0xff) : 0xff;
	rsp->port_rcv_errors = cpu_to_be64(
		hfi2_read_dev_cntr(dd, C_DC_RCV_ERR, CNTR_INVALID_VL));
	vlinfo = &rsp->vls[0];
	vfi = 0;
	vl_select_mask = be32_to_cpu(req->vl_select_mask);
	for_each_set_bit(vl, &vl_select_mask, BITS_PER_LONG) {
		memset(vlinfo, 0, sizeof(*vlinfo));
		rsp->vls[vfi].port_vl_xmit_discards =
			cpu_to_be64(hfi2_read_port_cntr(ppd, C_SW_XMIT_DSCD_VL,
							idx_from_vl(vl)));
		vlinfo += 1;
		vfi++;
	}

	if (resp_len)
		*resp_len += response_data_size;

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static int pma_get_ib_portcounters(struct ib_pma_mad *pmp,
				   struct ib_device *ibdev, u32 port)
{
	struct ib_pma_portcounters *p = (struct ib_pma_portcounters *)pmp->data;
	struct _port_ectrs rsp;
	u64 temp_link_overrun_errors;
	u64 temp_64;
	u32 temp_32;

	memset(&rsp, 0, sizeof(rsp));
	pma_get_opa_port_ectrs(ibdev, &rsp, port);

	if (pmp->mad_hdr.attr_mod != 0 || p->port_select != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		goto bail;
	}

	p->symbol_error_counter = 0; /* N/A for OPA */

	temp_32 = be32_to_cpu(rsp.link_error_recovery);
	if (temp_32 > 0xFFUL)
		p->link_error_recovery_counter = 0xFF;
	else
		p->link_error_recovery_counter = (u8)temp_32;

	temp_32 = be32_to_cpu(rsp.link_downed);
	if (temp_32 > 0xFFUL)
		p->link_downed_counter = 0xFF;
	else
		p->link_downed_counter = (u8)temp_32;

	temp_64 = be64_to_cpu(rsp.port_rcv_errors);
	if (temp_64 > 0xFFFFUL)
		p->port_rcv_errors = cpu_to_be16(0xFFFF);
	else
		p->port_rcv_errors = cpu_to_be16((u16)temp_64);

	temp_64 = be64_to_cpu(rsp.port_rcv_remote_physical_errors);
	if (temp_64 > 0xFFFFUL)
		p->port_rcv_remphys_errors = cpu_to_be16(0xFFFF);
	else
		p->port_rcv_remphys_errors = cpu_to_be16((u16)temp_64);

	temp_64 = be64_to_cpu(rsp.port_rcv_switch_relay_errors);
	p->port_rcv_switch_relay_errors = cpu_to_be16((u16)temp_64);

	temp_64 = be64_to_cpu(rsp.port_xmit_discards);
	if (temp_64 > 0xFFFFUL)
		p->port_xmit_discards = cpu_to_be16(0xFFFF);
	else
		p->port_xmit_discards = cpu_to_be16((u16)temp_64);

	temp_64 = be64_to_cpu(rsp.port_xmit_constraint_errors);
	if (temp_64 > 0xFFUL)
		p->port_xmit_constraint_errors = 0xFF;
	else
		p->port_xmit_constraint_errors = (u8)temp_64;

	temp_64 = be64_to_cpu(rsp.port_rcv_constraint_errors);
	if (temp_64 > 0xFFUL)
		p->port_rcv_constraint_errors = 0xFFUL;
	else
		p->port_rcv_constraint_errors = (u8)temp_64;

	/* LocalLink: 7:4, BufferOverrun: 3:0 */
	temp_64 = be64_to_cpu(rsp.local_link_integrity_errors);
	if (temp_64 > 0xFUL)
		temp_64 = 0xFUL;

	temp_link_overrun_errors = temp_64 << 4;

	temp_64 = be64_to_cpu(rsp.excessive_buffer_overruns);
	if (temp_64 > 0xFUL)
		temp_64 = 0xFUL;
	temp_link_overrun_errors |= temp_64;

	p->link_overrun_errors = (u8)temp_link_overrun_errors;

	p->vl15_dropped = 0; /* N/A for OPA */

bail:
	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static int pma_get_opa_errorinfo(struct opa_pma_mad *pmp,
				 struct ib_device *ibdev, u32 port,
				 u32 *resp_len)
{
	size_t response_data_size;
	struct _port_ei *rsp;
	struct opa_port_error_info_msg *req;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u64 port_mask;
	u32 num_ports;
	u32 port_num;
	u8 num_pslm;
	u64 reg;

	req = (struct opa_port_error_info_msg *)pmp->data;
	rsp = &req->port;

	num_ports = OPA_AM_NPORT(be32_to_cpu(pmp->mad_hdr.attr_mod));
	num_pslm = hweight64(be64_to_cpu(req->port_select_mask[3]));

	memset(rsp, 0, sizeof(*rsp));

	if (num_ports != 1 || num_ports != num_pslm) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	/* Sanity check */
	response_data_size = sizeof(struct opa_port_error_info_msg);

	if (response_data_size > sizeof(pmp->data)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	/*
	 * The bit set in the mask needs to be consistent with the port
	 * the request came in on.
	 */
	port_mask = be64_to_cpu(req->port_select_mask[3]);
	port_num = find_first_bit((unsigned long *)&port_mask,
				  sizeof(port_mask) * 8);

	if (port_num != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}
	rsp->port_number = port;

	/* PortRcvErrorInfo */
	rsp->port_rcv_ei.status_and_code = dd->err_info_rcvport.status_and_code;
	memcpy(&rsp->port_rcv_ei.ei.ei1to12.packet_flit1,
	       &dd->err_info_rcvport.packet_flit1, sizeof(u64));
	memcpy(&rsp->port_rcv_ei.ei.ei1to12.packet_flit2,
	       &dd->err_info_rcvport.packet_flit2, sizeof(u64));

	/* ExcessiverBufferOverrunInfo */
	reg = read_iport_csr(dd, ppd->hw_pidx, dd->params->rcv_err_info_reg);
	if (reg & RCV_ERR_INFO_RCV_EXCESS_BUFFER_OVERRUN_SMASK) {
		/*
		 * if the RcvExcessBufferOverrun bit is set, save SC of
		 * first pkt that encountered an excess buffer overrun
		 */
		u8 tmp = (u8)reg;

		tmp &= RCV_ERR_INFO_RCV_EXCESS_BUFFER_OVERRUN_SC_SMASK;
		tmp <<= 2;
		rsp->excessive_buffer_overrun_ei.status_and_sc = tmp;
		/* set the status bit */
		rsp->excessive_buffer_overrun_ei.status_and_sc |= 0x80;
	}

	rsp->port_xmit_constraint_ei.status =
		dd->err_info_xmit_constraint.status;
	rsp->port_xmit_constraint_ei.pkey =
		cpu_to_be16(dd->err_info_xmit_constraint.pkey);
	rsp->port_xmit_constraint_ei.slid =
		cpu_to_be32(dd->err_info_xmit_constraint.slid);

	rsp->port_rcv_constraint_ei.status = dd->err_info_rcv_constraint.status;
	rsp->port_rcv_constraint_ei.pkey =
		cpu_to_be16(dd->err_info_rcv_constraint.pkey);
	rsp->port_rcv_constraint_ei.slid =
		cpu_to_be32(dd->err_info_rcv_constraint.slid);

	/* UncorrectableErrorInfo */
	rsp->uncorrectable_ei.status_and_code = dd->err_info_uncorrectable;

	/* FMConfigErrorInfo */
	rsp->fm_config_ei.status_and_code = dd->err_info_fmconfig;

	if (resp_len)
		*resp_len += response_data_size;

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static int pma_set_opa_portstatus(struct opa_pma_mad *pmp,
				  struct ib_device *ibdev, u32 port,
				  u32 *resp_len)
{
	struct opa_clear_port_status *req =
		(struct opa_clear_port_status *)pmp->data;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u32 nports = be32_to_cpu(pmp->mad_hdr.attr_mod) >> 24;
	u64 portn = be64_to_cpu(req->port_select_mask[3]);
	u32 counter_select = be32_to_cpu(req->counter_select_mask);
	unsigned long vl_select_mask = VL_MASK_ALL; /* clear all per-vl cnts */
	unsigned long vl;

	if ((nports != 1) || (portn != 1 << port)) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}
	/*
	 * only counters returned by pma_get_opa_portstatus() are
	 * handled, so when pma_get_opa_portstatus() gets a fix,
	 * the corresponding change should be made here as well.
	 */

	if (counter_select & CS_PORT_XMIT_DATA)
		hfi2_write_dev_cntr(dd, C_DC_XMIT_FLITS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_RCV_DATA)
		hfi2_write_dev_cntr(dd, C_DC_RCV_FLITS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_XMIT_PKTS)
		hfi2_write_dev_cntr(dd, C_DC_XMIT_PKTS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_RCV_PKTS)
		hfi2_write_dev_cntr(dd, C_DC_RCV_PKTS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_MCAST_XMIT_PKTS)
		hfi2_write_dev_cntr(dd, C_DC_MC_XMIT_PKTS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_MCAST_RCV_PKTS)
		hfi2_write_dev_cntr(dd, C_DC_MC_RCV_PKTS, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_XMIT_WAIT) {
		hfi2_write_port_cntr(ppd, C_TX_WAIT, CNTR_INVALID_VL, 0);
		ppd->port_vl_xmit_wait_last[C_VL_COUNT] = 0;
		ppd->vl_xmit_flit_cnt[C_VL_COUNT] = 0;
	}
	/* ignore cs_sw_portCongestion for HFIs */

	if (counter_select & CS_PORT_RCV_FECN)
		hfi2_write_dev_cntr(dd, C_DC_RCV_FCN, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_RCV_BECN)
		hfi2_write_dev_cntr(dd, C_DC_RCV_BCN, CNTR_INVALID_VL, 0);

	/* ignore cs_port_xmit_time_cong for HFIs */
	/* ignore cs_port_xmit_wasted_bw for now */
	/* ignore cs_port_xmit_wait_data for now */
	if (counter_select & CS_PORT_RCV_BUBBLE)
		hfi2_write_dev_cntr(dd, C_DC_RCV_BBL, CNTR_INVALID_VL, 0);

	/* Only applicable for switch */
	/* if (counter_select & CS_PORT_MARK_FECN)
	 *	hfi2_write_csr(dd, DCC_PRF_PORT_MARK_FECN_CNT, 0);
	 */

	if (counter_select & CS_PORT_RCV_CONSTRAINT_ERRORS)
		hfi2_write_port_cntr(ppd, C_SW_RCV_CSTR_ERR, CNTR_INVALID_VL,
				     0);

	/* ignore cs_port_rcv_switch_relay_errors for HFIs */
	if (counter_select & CS_PORT_XMIT_DISCARDS)
		hfi2_write_port_cntr(ppd, C_SW_XMIT_DSCD, CNTR_INVALID_VL, 0);

	if (counter_select & CS_PORT_XMIT_CONSTRAINT_ERRORS)
		hfi2_write_port_cntr(ppd, C_SW_XMIT_CSTR_ERR, CNTR_INVALID_VL,
				     0);

	if (counter_select & CS_PORT_RCV_REMOTE_PHYSICAL_ERRORS)
		hfi2_write_dev_cntr(dd, C_DC_RMT_PHY_ERR, CNTR_INVALID_VL, 0);

	if (counter_select & CS_LOCAL_LINK_INTEGRITY_ERRORS)
		hfi2_write_dev_cntr(dd, C_DC_RX_REPLAY, CNTR_INVALID_VL, 0);

	if (counter_select & CS_LINK_ERROR_RECOVERY) {
		hfi2_write_dev_cntr(dd, C_DC_SEQ_CRC_CNT, CNTR_INVALID_VL, 0);
		hfi2_write_dev_cntr(dd, C_DC_REINIT_FROM_PEER_CNT,
				    CNTR_INVALID_VL, 0);
	}

	if (counter_select & CS_PORT_RCV_ERRORS)
		hfi2_write_dev_cntr(dd, C_DC_RCV_ERR, CNTR_INVALID_VL, 0);

	if (counter_select & CS_EXCESSIVE_BUFFER_OVERRUNS) {
		hfi2_write_port_cntr(ppd, C_RCV_OVF, CNTR_INVALID_VL, 0);
		ppd->rcv_ovfl_cnt = 0;
	}

	if (counter_select & CS_FM_CONFIG_ERRORS)
		hfi2_write_dev_cntr(dd, C_DC_FM_CFG_ERR, CNTR_INVALID_VL, 0);

	if (counter_select & CS_LINK_DOWNED)
		hfi2_write_port_cntr(ppd, C_SW_LINK_DOWN, CNTR_INVALID_VL, 0);

	if (counter_select & CS_UNCORRECTABLE_ERRORS)
		hfi2_write_dev_cntr(dd, C_DC_UNC_ERR, CNTR_INVALID_VL, 0);

	for_each_set_bit(vl, &vl_select_mask, BITS_PER_LONG) {
		if (counter_select & CS_PORT_XMIT_DATA)
			hfi2_write_port_cntr(ppd, C_TX_FLIT_VL, idx_from_vl(vl),
					     0);

		if (counter_select & CS_PORT_RCV_DATA)
			hfi2_write_dev_cntr(dd, C_DC_RX_FLIT_VL,
					    idx_from_vl(vl), 0);

		if (counter_select & CS_PORT_XMIT_PKTS)
			hfi2_write_port_cntr(ppd, C_TX_PKT_VL, idx_from_vl(vl),
					     0);

		if (counter_select & CS_PORT_RCV_PKTS)
			hfi2_write_dev_cntr(dd, C_DC_RX_PKT_VL, idx_from_vl(vl),
					    0);

		if (counter_select & CS_PORT_XMIT_WAIT) {
			hfi2_write_port_cntr(ppd, C_TX_WAIT_VL, idx_from_vl(vl),
					     0);
			ppd->port_vl_xmit_wait_last[idx_from_vl(vl)] = 0;
			ppd->vl_xmit_flit_cnt[idx_from_vl(vl)] = 0;
		}

		/* sw_port_vl_congestion is 0 for HFIs */
		if (counter_select & CS_PORT_RCV_FECN)
			hfi2_write_dev_cntr(dd, C_DC_RCV_FCN_VL,
					    idx_from_vl(vl), 0);

		if (counter_select & CS_PORT_RCV_BECN)
			hfi2_write_dev_cntr(dd, C_DC_RCV_BCN_VL,
					    idx_from_vl(vl), 0);

		/* port_vl_xmit_time_cong is 0 for HFIs */
		/* port_vl_xmit_wasted_bw ??? */
		/* port_vl_xmit_wait_data - TXE (table 13-9 HFI spec) ??? */
		if (counter_select & CS_PORT_RCV_BUBBLE)
			hfi2_write_dev_cntr(dd, C_DC_RCV_BBL_VL,
					    idx_from_vl(vl), 0);

		/* if (counter_select & CS_PORT_MARK_FECN)
		 *     hfi2_write_csr(dd, DCC_PRF_PORT_VL_MARK_FECN_CNT + offset, 0);
		 */
		if (counter_select & C_SW_XMIT_DSCD_VL)
			hfi2_write_port_cntr(ppd, C_SW_XMIT_DSCD_VL,
					     idx_from_vl(vl), 0);
	}

	if (resp_len)
		*resp_len += sizeof(*req);

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

static int pma_set_opa_errorinfo(struct opa_pma_mad *pmp,
				 struct ib_device *ibdev, u32 port,
				 u32 *resp_len)
{
	struct _port_ei *rsp;
	struct opa_port_error_info_msg *req;
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u64 port_mask;
	u32 num_ports;
	u32 port_num;
	u8 num_pslm;
	u32 error_info_select;

	req = (struct opa_port_error_info_msg *)pmp->data;
	rsp = &req->port;

	num_ports = OPA_AM_NPORT(be32_to_cpu(pmp->mad_hdr.attr_mod));
	num_pslm = hweight64(be64_to_cpu(req->port_select_mask[3]));

	memset(rsp, 0, sizeof(*rsp));

	if (num_ports != 1 || num_ports != num_pslm) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	/*
	 * The bit set in the mask needs to be consistent with the port
	 * the request came in on.
	 */
	port_mask = be64_to_cpu(req->port_select_mask[3]);
	port_num = find_first_bit((unsigned long *)&port_mask,
				  sizeof(port_mask) * 8);

	if (port_num != port) {
		pmp->mad_hdr.status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	error_info_select = be32_to_cpu(req->error_info_select_mask);

	/* PortRcvErrorInfo */
	if (error_info_select & ES_PORT_RCV_ERROR_INFO)
		/* turn off status bit */
		dd->err_info_rcvport.status_and_code &= ~OPA_EI_STATUS_SMASK;

	/* ExcessiveBufferOverrunInfo */
	if (error_info_select & ES_EXCESSIVE_BUFFER_OVERRUN_INFO) {
		/*
		 * status bit is essentially kept in the h/w - bit 5 of
		 * RCV_ERR_INFO
		 */
		write_iport_csr(dd, ppd->hw_pidx, dd->params->rcv_err_info_reg,
				RCV_ERR_INFO_RCV_EXCESS_BUFFER_OVERRUN_SMASK);
		if (dd->loopback_enabled)
			write_iport_csr(dd, loopback_pidx(ppd),
					dd->params->rcv_err_info_reg,
					RCV_ERR_INFO_RCV_EXCESS_BUFFER_OVERRUN_SMASK);
	}

	if (error_info_select & ES_PORT_XMIT_CONSTRAINT_ERROR_INFO)
		dd->err_info_xmit_constraint.status &= ~OPA_EI_STATUS_SMASK;

	if (error_info_select & ES_PORT_RCV_CONSTRAINT_ERROR_INFO)
		dd->err_info_rcv_constraint.status &= ~OPA_EI_STATUS_SMASK;

	/* UncorrectableErrorInfo */
	if (error_info_select & ES_UNCORRECTABLE_ERROR_INFO)
		/* turn off status bit */
		dd->err_info_uncorrectable &= ~OPA_EI_STATUS_SMASK;

	/* FMConfigErrorInfo */
	if (error_info_select & ES_FM_CONFIG_ERROR_INFO)
		/* turn off status bit */
		dd->err_info_fmconfig &= ~OPA_EI_STATUS_SMASK;

	if (resp_len)
		*resp_len += sizeof(*req);

	return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
}

struct opa_congestion_info_attr {
	__be16 congestion_info;
	u8 control_table_cap; /* Multiple of 64 entry unit CCTs */
	u8 congestion_log_length;
} __packed;

int hfi2_subn_get_opa_cong_info(struct opa_smp *smp, u32 am, u8 *data,
				    struct ib_device *ibdev, u32 port,
				    u32 *resp_len, u32 max_len)
{
	struct opa_congestion_info_attr *p =
		(struct opa_congestion_info_attr *)data;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);

	if (hfi2_mad_smp_length_check(sizeof(*p), max_len)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	p->congestion_info = 0;
	p->control_table_cap = ppd->cc_max_table_entries;
	p->congestion_log_length = OPA_CONG_LOG_ELEMS;

	if (resp_len)
		*resp_len += sizeof(*p);

	return hfi2_mad_reply((struct ib_mad_hdr *)smp);
}

int hfi2_subn_get_opa_cong_setting(struct opa_smp *smp, u32 am, u8 *data,
				       struct ib_device *ibdev, u32 port,
				       u32 *resp_len, u32 max_len)
{
	int i;
	struct opa_congestion_setting_attr *p =
		(struct opa_congestion_setting_attr *)data;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct opa_congestion_setting_entry_shadow *entries;
	struct cc_state *cc_state;

	if (hfi2_mad_smp_length_check(sizeof(*p), max_len)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	rcu_read_lock();

	cc_state = get_cc_state(ppd);

	if (!cc_state) {
		rcu_read_unlock();
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	entries = cc_state->cong_setting.entries;
	p->port_control = cpu_to_be16(cc_state->cong_setting.port_control);
	p->control_map = cpu_to_be32(cc_state->cong_setting.control_map);
	for (i = 0; i < OPA_MAX_SLS; i++) {
		p->entries[i].ccti_increase = entries[i].ccti_increase;
		p->entries[i].ccti_timer = cpu_to_be16(entries[i].ccti_timer);
		p->entries[i].trigger_threshold = entries[i].trigger_threshold;
		p->entries[i].ccti_min = entries[i].ccti_min;
	}

	rcu_read_unlock();

	if (resp_len)
		*resp_len += sizeof(*p);

	return hfi2_mad_reply((struct ib_mad_hdr *)smp);
}

/*
 * Apply congestion control information stored in the ppd to the
 * active structure.
 */
static void apply_cc_state(struct hfi2_pportdata *ppd)
{
	struct cc_state *old_cc_state, *new_cc_state;

	new_cc_state = kzalloc_obj(*new_cc_state, GFP_KERNEL);
	if (!new_cc_state)
		return;

	/*
	 * Hold the lock for updating *and* to prevent ppd information
	 * from changing during the update.
	 */
	spin_lock(&ppd->cc_state_lock);

	old_cc_state = get_cc_state_protected(ppd);
	if (!old_cc_state) {
		/* never active, or shutting down */
		spin_unlock(&ppd->cc_state_lock);
		kfree(new_cc_state);
		return;
	}

	*new_cc_state = *old_cc_state;

	if (ppd->total_cct_entry)
		new_cc_state->cct.ccti_limit = ppd->total_cct_entry - 1;
	else
		new_cc_state->cct.ccti_limit = 0;

	memcpy(new_cc_state->cct.entries, ppd->ccti_entries,
	       ppd->total_cct_entry * sizeof(struct ib_cc_table_entry));

	new_cc_state->cong_setting.port_control = IB_CC_CCS_PC_SL_BASED;
	new_cc_state->cong_setting.control_map = ppd->cc_sl_control_map;
	memcpy(new_cc_state->cong_setting.entries, ppd->congestion_entries,
	       OPA_MAX_SLS * sizeof(struct opa_congestion_setting_entry));

	rcu_assign_pointer(ppd->cc_state, new_cc_state);

	spin_unlock(&ppd->cc_state_lock);

	kfree_rcu(old_cc_state, rcu);
}

int hfi2_subn_set_opa_cong_setting(struct opa_smp *smp, u32 am, u8 *data,
				       struct ib_device *ibdev, u32 port,
				       u32 *resp_len, u32 max_len)
{
	struct opa_congestion_setting_attr *p =
		(struct opa_congestion_setting_attr *)data;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct opa_congestion_setting_entry_shadow *entries;
	int i;

	if (hfi2_mad_smp_length_check(sizeof(*p), max_len)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	/*
	 * Save details from packet into the ppd.  Hold the cc_state_lock so
	 * our information is consistent with anyone trying to apply the state.
	 */
	spin_lock(&ppd->cc_state_lock);
	ppd->cc_sl_control_map = be32_to_cpu(p->control_map);

	entries = ppd->congestion_entries;
	for (i = 0; i < OPA_MAX_SLS; i++) {
		entries[i].ccti_increase = p->entries[i].ccti_increase;
		entries[i].ccti_timer = be16_to_cpu(p->entries[i].ccti_timer);
		entries[i].trigger_threshold = p->entries[i].trigger_threshold;
		entries[i].ccti_min = p->entries[i].ccti_min;
	}
	spin_unlock(&ppd->cc_state_lock);

	/* now apply the information */
	apply_cc_state(ppd);

	return hfi2_subn_get_opa_cong_setting(smp, am, data, ibdev, port, resp_len,
					   max_len);
}

int hfi2_subn_get_opa_hfi2_cong_log(struct opa_smp *smp, u32 am, u8 *data,
					struct ib_device *ibdev, u32 port,
					u32 *resp_len, u32 max_len)
{
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	struct opa_hfi2_cong_log *cong_log = (struct opa_hfi2_cong_log *)data;
	u64 ts;
	int i;

	if (am || hfi2_mad_smp_length_check(sizeof(*cong_log), max_len)) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	spin_lock_irq(&ppd->cc_log_lock);

	cong_log->log_type = OPA_CC_LOG_TYPE_HFI;
	cong_log->congestion_flags = 0;
	cong_log->threshold_event_counter =
		cpu_to_be16(ppd->threshold_event_counter);
	memcpy(cong_log->threshold_cong_event_map,
	       ppd->threshold_cong_event_map,
	       sizeof(cong_log->threshold_cong_event_map));
	/* keep timestamp in units of 1.024 usec */
	ts = ktime_get_ns() / 1024;
	cong_log->current_time_stamp = cpu_to_be32(ts);
	for (i = 0; i < OPA_CONG_LOG_ELEMS; i++) {
		struct opa_hfi2_cong_log_event_internal *cce =
			&ppd->cc_events[ppd->cc_mad_idx++];
		if (ppd->cc_mad_idx == OPA_CONG_LOG_ELEMS)
			ppd->cc_mad_idx = 0;
		/*
		 * Entries which are older than twice the time
		 * required to wrap the counter are supposed to
		 * be zeroed (CA10-49 IBTA, release 1.2.1, V1).
		 */
		if ((ts - cce->timestamp) / 2 > U32_MAX)
			continue;
		memcpy(cong_log->events[i].local_qp_cn_entry, &cce->lqpn, 3);
		memcpy(cong_log->events[i].remote_qp_number_cn_entry,
		       &cce->rqpn, 3);
		cong_log->events[i].sl_svc_type_cn_entry =
			((cce->sl & 0x1f) << 3) | (cce->svc_type & 0x7);
		cong_log->events[i].remote_lid_cn_entry =
			cpu_to_be32(cce->rlid);
		cong_log->events[i].timestamp_cn_entry =
			cpu_to_be32(cce->timestamp);
	}

	/*
	 * Reset threshold_cong_event_map, and threshold_event_counter
	 * to 0 when log is read.
	 */
	memset(ppd->threshold_cong_event_map, 0x0,
	       sizeof(ppd->threshold_cong_event_map));
	ppd->threshold_event_counter = 0;

	spin_unlock_irq(&ppd->cc_log_lock);

	if (resp_len)
		*resp_len += sizeof(struct opa_hfi2_cong_log);

	return hfi2_mad_reply((struct ib_mad_hdr *)smp);
}

int hfi2_subn_get_opa_cc_table(struct opa_smp *smp, u32 am, u8 *data,
				   struct ib_device *ibdev, u32 port,
				   u32 *resp_len, u32 max_len)
{
	struct ib_cc_table_attr *cc_table_attr =
		(struct ib_cc_table_attr *)data;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u32 start_block = OPA_AM_START_BLK(am);
	u32 n_blocks = OPA_AM_NBLK(am);
	struct ib_cc_table_entry_shadow *entries;
	int i, j;
	u32 sentry, eentry;
	struct cc_state *cc_state;
	u32 size = sizeof(u16) * (IB_CCT_ENTRIES * n_blocks + 1);

	/* sanity check n_blocks, start_block */
	if (n_blocks == 0 || hfi2_mad_smp_length_check(size, max_len) ||
	    start_block + n_blocks > ppd->cc_max_table_entries) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	rcu_read_lock();

	cc_state = get_cc_state(ppd);

	if (!cc_state) {
		rcu_read_unlock();
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	sentry = start_block * IB_CCT_ENTRIES;
	eentry = sentry + (IB_CCT_ENTRIES * n_blocks);

	cc_table_attr->ccti_limit = cpu_to_be16(cc_state->cct.ccti_limit);

	entries = cc_state->cct.entries;

	/* return n_blocks, though the last block may not be full */
	for (j = 0, i = sentry; i < eentry; j++, i++)
		cc_table_attr->ccti_entries[j].entry =
			cpu_to_be16(entries[i].entry);

	rcu_read_unlock();

	if (resp_len)
		*resp_len += size;

	return hfi2_mad_reply((struct ib_mad_hdr *)smp);
}

int hfi2_subn_set_opa_cc_table(struct opa_smp *smp, u32 am, u8 *data,
				   struct ib_device *ibdev, u32 port,
				   u32 *resp_len, u32 max_len)
{
	struct ib_cc_table_attr *p = (struct ib_cc_table_attr *)data;
	struct hfi2_ibport *ibp = to_iport(ibdev, port);
	struct hfi2_pportdata *ppd = ppd_from_ibp(ibp);
	u32 start_block = OPA_AM_START_BLK(am);
	u32 n_blocks = OPA_AM_NBLK(am);
	struct ib_cc_table_entry_shadow *entries;
	int i, j;
	u32 sentry, eentry;
	u16 ccti_limit;
	u32 size = sizeof(u16) * (IB_CCT_ENTRIES * n_blocks + 1);

	/* sanity check n_blocks, start_block */
	if (n_blocks == 0 || hfi2_mad_smp_length_check(size, max_len) ||
	    start_block + n_blocks > ppd->cc_max_table_entries) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	sentry = start_block * IB_CCT_ENTRIES;
	eentry = sentry + ((n_blocks - 1) * IB_CCT_ENTRIES) +
		 (be16_to_cpu(p->ccti_limit)) % IB_CCT_ENTRIES + 1;

	/* sanity check ccti_limit */
	ccti_limit = be16_to_cpu(p->ccti_limit);
	if (ccti_limit + 1 > eentry) {
		smp->status |= IB_SMP_INVALID_FIELD;
		return hfi2_mad_reply((struct ib_mad_hdr *)smp);
	}

	/*
	 * Save details from packet into the ppd.  Hold the cc_state_lock so
	 * our information is consistent with anyone trying to apply the state.
	 */
	spin_lock(&ppd->cc_state_lock);
	ppd->total_cct_entry = ccti_limit + 1;
	entries = ppd->ccti_entries;
	for (j = 0, i = sentry; i < eentry; j++, i++)
		entries[i].entry = be16_to_cpu(p->ccti_entries[j].entry);
	spin_unlock(&ppd->cc_state_lock);

	/* now apply the information */
	apply_cc_state(ppd);

	return hfi2_subn_get_opa_cc_table(smp, am, data, ibdev, port, resp_len,
				       max_len);
}

int hfi2_mad_process_perf(struct ib_device *ibdev, u32 port,
			const struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	struct ib_pma_mad *pmp = (struct ib_pma_mad *)out_mad;
	struct ib_class_port_info *cpi =
		(struct ib_class_port_info *)&pmp->data;
	int ret = IB_MAD_RESULT_FAILURE;

	*out_mad = *in_mad;
	if (pmp->mad_hdr.class_version != 1) {
		pmp->mad_hdr.status |= IB_SMP_UNSUP_VERSION;
		ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
		return ret;
	}

	switch (pmp->mad_hdr.method) {
	case IB_MGMT_METHOD_GET:
		switch (pmp->mad_hdr.attr_id) {
		case IB_PMA_PORT_COUNTERS:
			ret = pma_get_ib_portcounters(pmp, ibdev, port);
			break;
		case IB_PMA_PORT_COUNTERS_EXT:
			ret = pma_get_ib_portcounters_ext(pmp, ibdev, port);
			break;
		case IB_PMA_CLASS_PORT_INFO:
			cpi->capability_mask = IB_PMA_CLASS_CAP_EXT_WIDTH;
			ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
			break;
		default:
			pmp->mad_hdr.status |= IB_SMP_UNSUP_METH_ATTR;
			ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
			break;
		}
		break;

	case IB_MGMT_METHOD_SET:
		if (pmp->mad_hdr.attr_id) {
			pmp->mad_hdr.status |= IB_SMP_UNSUP_METH_ATTR;
			ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
		}
		break;

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_GET_RESP:
		/*
		 * The ib_mad module will call us to process responses
		 * before checking for other consumers.
		 * Just tell the caller to process it normally.
		 */
		ret = IB_MAD_RESULT_SUCCESS;
		break;

	default:
		pmp->mad_hdr.status |= IB_SMP_UNSUP_METHOD;
		ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
		break;
	}

	return ret;
}

int hfi2_mad_process_perf_opa(struct ib_device *ibdev, u32 port,
			    const struct opa_mad *in_mad,
			    struct opa_mad *out_mad, u32 *resp_len)
{
	struct opa_pma_mad *pmp = (struct opa_pma_mad *)out_mad;
	int ret;

	*out_mad = *in_mad;

	if (pmp->mad_hdr.class_version != OPA_SM_CLASS_VERSION) {
		pmp->mad_hdr.status |= IB_SMP_UNSUP_VERSION;
		return hfi2_mad_reply((struct ib_mad_hdr *)pmp);
	}

	*resp_len = sizeof(pmp->mad_hdr);

	switch (pmp->mad_hdr.method) {
	case IB_MGMT_METHOD_GET:
		switch (pmp->mad_hdr.attr_id) {
		case IB_PMA_CLASS_PORT_INFO:
			ret = pma_get_opa_classportinfo(pmp, ibdev, resp_len);
			break;
		case OPA_PM_ATTRIB_ID_PORT_STATUS:
			ret = pma_get_opa_portstatus(pmp, ibdev, port,
						     resp_len);
			break;
		case OPA_PM_ATTRIB_ID_DATA_PORT_COUNTERS:
			ret = pma_get_opa_datacounters(pmp, ibdev, port,
						       resp_len);
			break;
		case OPA_PM_ATTRIB_ID_ERROR_PORT_COUNTERS:
			ret = pma_get_opa_porterrors(pmp, ibdev, port,
						     resp_len);
			break;
		case OPA_PM_ATTRIB_ID_ERROR_INFO:
			ret = pma_get_opa_errorinfo(pmp, ibdev, port, resp_len);
			break;
		default:
			pmp->mad_hdr.status |= IB_SMP_UNSUP_METH_ATTR;
			ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
			break;
		}
		break;

	case IB_MGMT_METHOD_SET:
		switch (pmp->mad_hdr.attr_id) {
		case OPA_PM_ATTRIB_ID_CLEAR_PORT_STATUS:
			ret = pma_set_opa_portstatus(pmp, ibdev, port,
						     resp_len);
			break;
		case OPA_PM_ATTRIB_ID_ERROR_INFO:
			ret = pma_set_opa_errorinfo(pmp, ibdev, port, resp_len);
			break;
		default:
			pmp->mad_hdr.status |= IB_SMP_UNSUP_METH_ATTR;
			ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
			break;
		}
		break;

	case IB_MGMT_METHOD_TRAP:
	case IB_MGMT_METHOD_GET_RESP:
		/*
		 * The ib_mad module will call us to process responses
		 * before checking for other consumers.
		 * Just tell the caller to process it normally.
		 */
		ret = IB_MAD_RESULT_SUCCESS;
		break;

	default:
		pmp->mad_hdr.status |= IB_SMP_UNSUP_METHOD;
		ret = hfi2_mad_reply((struct ib_mad_hdr *)pmp);
		break;
	}

	return ret;
}

