// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015 - 2020 Intel Corporation.
 * Copyright(c) 2021-2026 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/xarray.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/hrtimer.h>
#include <linux/bitmap.h>
#include <linux/numa.h>
#include "rvt.h"

#include "hfi2.h"
#include "file_ops.h"
#include "hfi2.h"
#include "common.h"
#include "trace.h"
#include "mad.h"
#include "sdma.h"
#include "debugfs.h"
#include "verbs.h"

#include "roce.h"
#include "roce_pasid.h"
#include "affinity.h"
#include "exp_rcv.h"
#include "netdev.h"
#include "chip_jkr.h"
#include "chip_cyr.h"
#include "chip_gen.h"
#include "devlink.h"
#include "pldm_ua.h"
#include "pinning.h"
#include "cport_traps.h"
#include "sriov.h"
#include "vf2pf.h"
#include "bulksvc.h"
#include "bulksvc_ulp.h"
#include "eth_main.h"

#undef pr_fmt
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

#undef CPORT_TRAP_DEBUG	/* all MCTXT TRAP events from CPORT */
#define PDEV_SRIOV_DEBUG
#undef CPORT_TRAP_DEBUG /* all MCTXT TRAP events from CPORT */
/*
 * min buffers we want to have per context, after driver
 */
#define HFI2_MIN_USER_CTXT_BUFCNT 7

#define HFI2_MIN_EAGER_BUFFER_SIZE (4 * 1024) /* 4KB */
#define HFI2_MAX_EAGER_BUFFER_SIZE (256 * 1024) /* 256KB */

static void wfr_start_port(struct hfi2_pportdata *ppd);
static void wfr_stop_port(struct hfi2_pportdata *ppd);
static void destroy_workqueues(struct hfi2_devdata *dd);

/* parameters for the WFR ASIC */
static const struct chip_params wfr_params = {
	.chip_type = CHIP_WFR,
	.num_ports = 1,
	.dma_mask_bits = 48,

	/* BAR0 map: rcv array splits kreg1 and kreg2 */
	.bar0_size = TXE_PIO_SEND + TXE_PIO_SIZE,
	.kreg1_size = RCV_ARRAY,
	.kreg2_offset = RCV_ARRAY + RCV_ARRAY_SIZE,
	.kreg2_size = TXE_PIO_SEND - (RCV_ARRAY + RCV_ARRAY_SIZE),
	.rcv_array_offset = RCV_ARRAY,
	.rcv_array_size = RCV_ARRAY_SIZE,

	.link_speed_supported = OPA_LINK_SPEED_25G,
	.link_speed_active = OPA_LINK_SPEED_25G,
	.asic_cclock_ps = ASIC_CCLOCK_PS,
	.rsm_rule_size = WFR_RXE_NUM_RSM_INSTANCES,
	.rsm_rule_offset_shift = WFR_RCV_RSM_CFG_OFFSET_SHIFT,
	.rsm_map_table_entries = 256,
	.rsm_map_table_entries_per_csr = 8,
	.rsm_map_table_entry_mask = 0xff,
	.rsm_map_table_entry_shift = 8,
	.qp_map_table_entries = 256,
	.qp_map_table_entries_per_csr = 8,
	.qp_map_table_entry_mask = 0xff,
	.qp_map_table_entry_shift = 8,
	.pkey_table_size = WFR_MAX_PKEY_VALUES,
	.generic_boardname =
		"Cornelis Omni-Path Host Fabric Interface Adapter 100 Series",
	.max_eager_entries = WFR_MAX_EAGER_ENTRIES,
	.pio_base_bits = WFR_PIO_BASE_BITS,
	.pio_base_shift = WFR_SEND_CTXT_CTRL_CTXT_BASE_SHIFT,
	.egress_err_info_data = &hfi2_wfr_egress_err_info_data,
	.send_ctrl_flush = 0, /* no flush flag available */
	.port_discard_egress_errs = WFR_PORT_DISCARD_EGRESS_ERRS,
	.rcv_hdr_ent_size_max = 32,

	/* interrupt sources */
	.num_int_csrs = WFR_CCE_NUM_INT_CSRS,
	.num_int_map_csrs = WFR_CCE_NUM_INT_MAP_CSRS,
	.is_rcvavail_start = IS_RCVAVAIL_START,
	.is_rcvurgent_start = IS_RCVURGENT_START,
	.is_sdmaeng_err_start = IS_SDMAENG_ERR_START,
	.is_sdma_idle_start = IS_SDMA_IDLE_START,
	.is_sdma_progress_start = IS_SDMA_PROGRESS_START,
	.is_sdma_start = IS_SDMA_START,
	.is_last_source = IS_LAST_SOURCE,
	.is_table = hfi2_is_table,
	.gi_enable_table = hfi2_wfr_gi_enable_table,

	/* cce_interrupt registers */
	.cce_int_status_reg = WFR_CCE_INT_STATUS,
	.cce_int_mask_reg = WFR_CCE_INT_MASK,
	.cce_int_clear_reg = WFR_CCE_INT_CLEAR,
	.cce_int_force_reg = WFR_CCE_INT_FORCE,
	.cce_int_blocked_reg = WFR_CCE_INT_BLOCKED,

	/* counters */
	.chip_dev_cntrs = hfi2_wfr_dev_cntrs,
	.chip_dev_cntr_first = WFR_DEV_CNTR_FIRST,
	.chip_num_dev_cntrs = WFR_NUM_DEV_CNTRS,
	.chip_port_cntrs = hfi2_wfr_port_cntrs,
	.chip_port_cntr_first = WFR_PORT_CNTR_FIRST,
	.chip_num_port_cntrs = WFR_NUM_PORT_CNTRS,

	/* ingress port registers */
	.rxe_iport_stride = 0,
	.rcv_iport_ctrl_reg = WFR_RCV_CTRL,
	.rcv_iport_status_reg = WFR_RCV_STATUS,
	.rcv_bth_qp_reg = WFR_RCV_BTH_QP,
	.rcv_multicast_reg = WFR_RCV_MULTICAST,
	.rcv_bypass_reg = WFR_RCV_BYPASS,
	.rcv_vl15_reg = WFR_RCV_VL15,
	.rcv_err_info_reg = WFR_RCV_ERR_INFO,
	.rcv_err_status_reg = WFR_RCV_ERR_STATUS,
	.rcv_err_mask_reg = WFR_RCV_ERR_MASK,
	.rcv_err_clear_reg = WFR_RCV_ERR_CLEAR,
	.rcv_qp_map_table_reg = WFR_RCV_QP_MAP_TABLE,
	.rcv_partition_key_reg = WFR_RCV_PARTITION_KEY,
	.rcv_counter_array32_reg = WFR_RCV_COUNTER_ARRAY32,
	.rcv_counter_array64_reg = WFR_RCV_COUNTER_ARRAY64,

	/* ingress port receive context registers */
	.rxe_iprc_stride = WFR_RXE_IPRC_STRIDE,
	.rcv_jkey_ctrl_reg = WFR_RCV_KEY_CTRL,

	/* RXE restricted context registers */
	.rxe_rctxt_stride = WFR_RXE_RCTXT_STRIDE,
	.rcv_rctxt_ctrl_reg = WFR_RCV_CTXT_CTRL,
	.rcv_egr_ctrl_reg = WFR_RCV_EGR_CTRL,
	.rcv_tid_ctrl_reg = WFR_RCV_TID_CTRL,

	/* RXE kernel context registers */
	.rxe_kctxt_stride = WFR_RXE_KCTXT_STRIDE,
	.rcv_kctxt_ctrl_reg = WFR_RCV_CTXT_CTRL,
	.rcv_hdr_addr_reg = WFR_RCV_HDR_ADDR,
	.rcv_hdr_cnt_reg = WFR_RCV_HDR_CNT,
	.rcv_hdr_ent_size_reg = WFR_RCV_HDR_ENT_SIZE,
	.rcv_hdr_tail_addr_reg = WFR_RCV_HDR_TAIL_ADDR,
	.rcv_avail_time_out_reg = WFR_RCV_AVAIL_TIME_OUT,
	.rcv_hdr_ovfl_cnt_reg = WFR_RCV_HDR_OVFL_CNT,

	/* RXE kernel/user registers */
	.rxe_ku_stride = WFR_RXE_KCTXT_STRIDE,
	.rcv_ctxt_status_reg = WFR_RCV_CTXT_STATUS,

	/* RXE user registers */
	.rxe_uctxt_stride = WFR_RXE_UCTXT_STRIDE,
	.rcv_hdr_tail_reg = WFR_RCV_HDR_TAIL,
	.rcv_hdr_head_reg = WFR_RCV_HDR_HEAD,
	.rcv_egr_index_head_reg = WFR_RCV_EGR_INDEX_HEAD,
	.rcv_tid_flow_table_reg = WFR_RCV_TID_FLOW_TABLE,

	/* RXE RSM registers */
	.rcv_rsm_cfg_reg = WFR_RCV_RSM_CFG,
	.rcv_rsm_select_reg = WFR_RCV_RSM_SELECT,
	.rcv_rsm_match_reg = WFR_RCV_RSM_MATCH,
	.rcv_rsm_map_table_reg = WFR_RCV_RSM_MAP_TABLE,

	/* TXE kernel registers */
	.send_contexts_reg = SEND_CONTEXTS,
	.send_dma_engines_reg = WFR_SEND_DMA_ENGINES,
	.send_pio_mem_size_reg = WFR_SEND_PIO_MEM_SIZE,
	.send_dma_mem_size_reg = WFR_SEND_DMA_MEM_SIZE,
	.send_pio_init_ctxt_reg = WFR_SEND_PIO_INIT_CTXT,

	/* send context_registers */
	.txe_sctxt_stride = WFR_TXE_SCTXT_STRIDE,
	.send_ctxt_status_reg = WFR_SEND_CTXT_STATUS,
	.send_ctxt_credit_ctrl_reg = WFR_SEND_CTXT_CREDIT_CTRL,
	.send_ctxt_credit_status_reg = WFR_SEND_CTXT_CREDIT_STATUS,
	.send_ctxt_credit_return_addr_reg = WFR_SEND_CTXT_CREDIT_RETURN_ADDR,
	.send_ctxt_credit_force_reg = WFR_SEND_CTXT_CREDIT_FORCE,
	.send_ctxt_err_status_reg = WFR_SEND_CTXT_ERR_STATUS,
	.send_ctxt_err_mask_reg = WFR_SEND_CTXT_ERR_MASK,
	.send_ctxt_err_clear_reg = WFR_SEND_CTXT_ERR_CLEAR,

	/* TXE send context registers */
	.txe_tctxt_stride = WFR_TXE_TCTXT_STRIDE,
	.send_ctxt_ctrl_reg = WFR_SEND_CTXT_CTRL,

	/* SDMA registers */
	.txe_sdma_stride = WFR_TXE_SDMA_STRIDE,
	.send_dma_ctrl_reg = WFR_SEND_DMA_CTRL,
	.send_dma_status_reg = WFR_SEND_DMA_STATUS,
	.send_dma_base_addr_reg = WFR_SEND_DMA_BASE_ADDR,
	.send_dma_len_gen_reg = WFR_SEND_DMA_LEN_GEN,
	.send_dma_tail_reg = WFR_SEND_DMA_TAIL,
	.send_dma_head_reg = WFR_SEND_DMA_HEAD,
	.send_dma_head_addr_reg = WFR_SEND_DMA_HEAD_ADDR,
	.send_dma_priority_thld_reg = WFR_SEND_DMA_PRIORITY_THLD,
	.send_dma_idle_cnt_reg = WFR_SEND_DMA_IDLE_CNT,
	.send_dma_reload_cnt_reg = WFR_SEND_DMA_RELOAD_CNT,
	.send_dma_desc_cnt_reg = WFR_SEND_DMA_DESC_CNT,
	.send_dma_desc_fetched_cnt_reg = WFR_SEND_DMA_DESC_FETCHED_CNT,
	.send_dma_eng_err_status_reg = WFR_SEND_DMA_ENG_ERR_STATUS,
	.send_dma_eng_err_mask_reg = WFR_SEND_DMA_ENG_ERR_MASK,
	.send_dma_eng_err_clear_reg = WFR_SEND_DMA_ENG_ERR_CLEAR,

	/* SDMA Config registers */
	.txe_sdmacfg_stride = WFR_TXE_SDMACFG_STRIDE,
	.send_dma_cfg_memory_reg = WFR_SEND_DMA_MEMORY,

	/* egress port registers */
	.txe_eport_stride = 0,
	.send_ctrl_reg = SEND_CTRL,
	.send_high_priority_limit_reg = WFR_SEND_HIGH_PRIORITY_LIMIT,
	.send_egress_err_status_reg = WFR_SEND_EGRESS_ERR_STATUS,
	.send_egress_err_mask_reg = WFR_SEND_EGRESS_ERR_MASK,
	.send_egress_err_clear_reg = WFR_SEND_EGRESS_ERR_CLEAR,
	.send_bth_qp_reg = WFR_SEND_BTH_QP,
	.send_static_rate_control_reg = WFR_SEND_STATIC_RATE_CONTROL,
	.send_sc2vlt0_reg = WFR_SEND_SC2VLT0,
	.send_sc2vlt1_reg = WFR_SEND_SC2VLT1,
	.send_sc2vlt2_reg = WFR_SEND_SC2VLT2,
	.send_sc2vlt3_reg = WFR_SEND_SC2VLT3,
	.send_len_check0_reg = WFR_SEND_LEN_CHECK0,
	.send_len_check1_reg = WFR_SEND_LEN_CHECK1,
	.send_low_priority_list_reg = WFR_SEND_LOW_PRIORITY_LIST,
	.send_high_priority_list_reg = WFR_SEND_HIGH_PRIORITY_LIST,
	.send_counter_array32_reg = WFR_SEND_COUNTER_ARRAY32,
	.send_counter_array64_reg = WFR_SEND_COUNTER_ARRAY64,
	.send_cm_ctrl_reg = WFR_SEND_CM_CTRL,
	.send_cm_global_credit_reg = WFR_SEND_CM_GLOBAL_CREDIT,
	.send_cm_credit_used_status_reg = WFR_SEND_CM_CREDIT_USED_STATUS,
	.send_cm_timer_ctrl_reg = WFR_SEND_CM_TIMER_CTRL,
	.send_cm_local_au_table0_to3_reg = WFR_SEND_CM_LOCAL_AU_TABLE0_TO3,
	.send_cm_local_au_table4_to7_reg = WFR_SEND_CM_LOCAL_AU_TABLE4_TO7,
	.send_cm_remote_au_table0_to3_reg = WFR_SEND_CM_REMOTE_AU_TABLE0_TO3,
	.send_cm_remote_au_table4_to7_reg = WFR_SEND_CM_REMOTE_AU_TABLE4_TO7,
	.send_cm_credit_vl_reg = WFR_SEND_CM_CREDIT_VL,
	.send_cm_credit_vl15_reg = WFR_SEND_CM_CREDIT_VL15,
	.send_egress_err_info_reg = WFR_SEND_EGRESS_ERR_INFO,
	.send_egress_err_source_reg = WFR_SEND_EGRESS_ERR_SOURCE,
	.send_egress_ctxt_status_reg = WFR_SEND_EGRESS_CTXT_STATUS,
	.send_egress_send_dma_status_reg = WFR_SEND_EGRESS_SEND_DMA_STATUS,

	/* egress port send context registers */
	.txe_epsc_stride = WFR_TXE_EPSC_STRIDE,
	.send_ctxt_check_enable_reg = WFR_SEND_CTXT_CHECK_ENABLE,
	.send_ctxt_check_vl_reg = WFR_SEND_CTXT_CHECK_VL,
	.send_ctxt_check_job_key_reg = WFR_SEND_CTXT_CHECK_JOB_KEY,
	.send_ctxt_check_partition_key_reg = WFR_SEND_CTXT_CHECK_PARTITION_KEY,
	.send_ctxt_check_slid_reg = WFR_SEND_CTXT_CHECK_SLID,
	.send_ctxt_check_opcode_reg = WFR_SEND_CTXT_CHECK_OPCODE,

	/* SI registers */
	.cce_msix_int_map_vec_reg = WFR_CCE_INT_MAP,
	.cce_msix_int_granted_reg = WFR_CCE_MSIX_INT_GRANTED,
	.send_pio_err_status_reg = WFR_SEND_PIO_ERR_STATUS,
	.send_pio_err_mask_reg = WFR_SEND_PIO_ERR_MASK,
	.send_pio_err_clear_reg = WFR_SEND_PIO_ERR_CLEAR,
	.send_dma_err_status_reg = WFR_SEND_DMA_ERR_STATUS,
	.send_dma_err_mask_reg = WFR_SEND_DMA_ERR_MASK,
	.send_dma_err_clear_reg = WFR_SEND_DMA_ERR_CLEAR,
	.csr_err_status_reg = WFR_SEND_ERR_STATUS,
	.csr_err_mask_reg = WFR_SEND_ERR_MASK,
	.csr_err_clear_reg = WFR_SEND_ERR_CLEAR,

	.hfi2_setextled = hfi2_setextled,
	.start_led_override = hfi2_start_led_override,
	.shutdown_led_override = hfi2_shutdown_led_override,
	.hfi2_read_guid = hfi2_read_guid,
	.early_per_chip_init = hfi2_wfr_early_per_chip_init,
	.mid_per_chip_init = hfi2_wfr_mid_per_chip_init,
	.hfi2_init_other = hfi2_init_other,
	.late_per_chip_init = hfi2_wfr_late_per_chip_init,
	.start_port = wfr_start_port,
	.stop_port = wfr_stop_port,
	.put_tid = hfi2_wfr_put_tid,
	.rcv_array_wc_fill = hfi2_wfr_rcv_array_wc_fill,
	.set_port_tid_config = hfi2_wfr_set_port_tid_config,
	.set_port_max_mtu = hfi2_wfr_set_port_max_mtu,
	.update_rcv_hdr_size = hfi2_wfr_update_rcv_hdr_size,
	.check_synth_status = hfi2_wfr_check_synth_status,
	.update_synth_status = hfi2_wfr_update_synth_status,
	.create_pbc = hfi2_wfr_create_pbc,
	.set_pio_integrity = hfi2_wfr_set_pio_integrity,
	.find_used_resources = hfi2_wfr_find_used_resources,
	.read_link_quality = hfi2_wfr_read_link_quality,
	.set_rheq_addr = NULL,
	.handle_link_bounce = hfi2_wfr_handle_link_bounce,
	.enable_rcv_context = hfi2_wfr_enable_rcv_context,
};

/* parameters for the JKR ASIC */
static const struct chip_params jkr_params = {
	.chip_type = CHIP_JKR,
	.num_ports = 2,
	.dma_mask_bits = 58,

	/* BAR0 map: see comments where KREG values are defined */
	.bar0_size = JKR_BAR0_SIZE,
	.kreg1_size = JKR_KREG1_SIZE,
	.kreg2_offset = JKR_KREG2_OFFSET,
	.kreg2_size = JKR_KREG2_SIZE,
	.rcv_array_offset = JKR_RCV_ARRAY,
	.rcv_array_size = JKR_RCV_ARRAY_SIZE,

	.link_speed_supported = OPA_LINK_SPEED_100G | OPA_LINK_SPEED_25G,
	.link_speed_active = OPA_LINK_SPEED_100G,
	.asic_cclock_ps = JKR_ASIC_CCLOCK_PS,
	.rsm_rule_size = JKR_C_RXE_NUM_RSM_INSTANCES,
	.rsm_rule_offset_shift = JKR_RCV_RSM_CFG_OFFSET_SHIFT,
	.rsm_map_table_entries = 256,
	.rsm_map_table_entries_per_csr = 8,
	.rsm_map_table_entry_mask = 0xff,
	.rsm_map_table_entry_shift = 8,
	.qp_map_table_entries = 256,
	.qp_map_table_entries_per_csr = 8,
	.qp_map_table_entry_mask = 0xff,
	.qp_map_table_entry_shift = 8,
	.pkey_table_size = JKR_MAX_PKEY_VALUES,
	.generic_boardname =
		"Cornelis Networks 5000 Host Fabric Interface Adapter",
	.max_eager_entries = JKR_MAX_EAGER_ENTRIES,
	.pio_base_bits = JKR_PIO_BASE_BITS,
	.pio_base_shift = JKR_SEND_CTXT_CTRL_CTXT_BASE_SHIFT,
	.egress_err_info_data = &hfi2_jkr_egress_err_info_data,
	.send_ctrl_flush = JKR_SEND_CTRL_FLUSH_WRONG_LINK_STATE_SMASK,
	.port_discard_egress_errs = JKR_PORT_DISCARD_EGRESS_ERRS,
	.rcv_hdr_ent_size_max = 32,

	/* interrupt sources */
	.num_int_csrs = JKR_C_CCE_NUM_INT_CSRS,
	.num_int_map_csrs = JKR_C_CCE_NUM_INT_MAP_CSRS,
	.is_cport_int = JKR_MCTXT_CPORT_TO_PCIE_INT,
	.is_rcvavail_start = JKR_IS_RCVAVAIL_START,
	.is_rcvurgent_start = JKR_IS_RCVURGENT_START,
	.is_sdmaeng_err_start = JKR_IS_SDMAENG_ERR_START,
	.is_sdma_idle_start = JKR_IS_SDMA_IDLE_START,
	.is_sdma_progress_start = JKR_IS_SDMA_PROGRESS_START,
	.is_sdma_start = JKR_IS_SDMA_START,
	.is_doorbell0 = JKR_IS_DOORBELL0,
	.is_doorbell1 = JKR_IS_DOORBELL1,
	.is_last_source = JKR_IS_LAST_SOURCE,
	.is_table = hfi2_jkr_is_table,
	.gi_enable_table = hfi2_jkr_gi_enable_table,

	/* cce_interrupt registers */
	.cce_int_status_reg = JKR_CCE_INT_STATUS,
	.cce_int_mask_reg = JKR_CCE_INT_MASK,
	.cce_int_clear_reg = JKR_CCE_INT_CLEAR,
	.cce_int_force_reg = JKR_CCE_INT_FORCE,
	.cce_int_blocked_reg = JKR_CCE_INT_BLOCKED,

	/* counters */
	.chip_dev_cntrs = hfi2_jkr_dev_cntrs,
	.chip_dev_cntr_first = JKR_DEV_CNTR_FIRST,
	.chip_num_dev_cntrs = JKR_NUM_DEV_CNTRS,
	.chip_port_cntrs = hfi2_jkr_port_cntrs,
	.chip_port_cntr_first = JKR_PORT_CNTR_FIRST,
	.chip_num_port_cntrs = JKR_NUM_PORT_CNTRS,

	/* ingress port registers */
	.rxe_iport_stride = JKR_C_RXE_IPORT_STRIDE,
	.rcv_iport_ctrl_reg = JKR_RCV_IPORT_CTRL,
	.rcv_iport_status_reg = JKR_RCV_IPORT_STATUS,
	.rcv_bth_qp_reg = JKR_RCV_BTH_QP,
	.rcv_multicast_reg = JKR_RCV_MULTICAST,
	.rcv_bypass_reg = JKR_RCV_BYPASS,
	.rcv_vl15_reg = JKR_RCV_VL15,
	.rcv_err_info_reg = JKR_RCV_ERR_INFO,
	.rcv_err_status_reg = JKR_RCV_ERR_STATUS,
	.rcv_err_mask_reg = JKR_RCV_ERR_MASK,
	.rcv_err_clear_reg = JKR_RCV_ERR_CLEAR,
	.rcv_qp_map_table_reg = JKR_RCV_QP_MAP_TABLE,
	.rcv_partition_key_reg = JKR_RCV_PARTITION_KEY,
	.rcv_counter_array32_reg = JKR_RCV_COUNTER_ARRAY32,
	.rcv_counter_array64_reg = JKR_RCV_COUNTER_ARRAY64,

	/* ingress port receive context registers */
	.rxe_iprc_stride = JKR_C_RXE_IPRC_STRIDE,
	.rcv_jkey_ctrl_reg = JKR_RCV_JKEY_CTRL,

	/* RXE restricted context registers */
	.rxe_rctxt_stride = JKR_C_RXE_RCTXT_STRIDE,
	.rcv_rctxt_ctrl_reg = JKR_RCV_RCTXT_CTRL,
	.rcv_egr_ctrl_reg = JKR_RCV_EGR_CTRL,
	.rcv_tid_ctrl_reg = JKR_RCV_TID_CTRL,

	/* RXE kernel context registers */
	.rxe_kctxt_stride = JKR_C_RXE_KCTXT_STRIDE,
	.rcv_kctxt_ctrl_reg = JKR_RCV_KCTXT_CTRL,
	.rcv_hdr_addr_reg = JKR_RCV_HDR_ADDR,
	.rcv_hdr_cnt_reg = JKR_RCV_HDR_CNT,
	.rcv_hdr_ent_size_reg = JKR_RCV_HDR_ENT_SIZE,
	.rcv_hdr_tail_addr_reg = JKR_RCV_HDR_TAIL_ADDR,
	.rcv_avail_time_out_reg = JKR_RCV_AVAIL_TIME_OUT,
	.rcv_hdr_ovfl_cnt_reg = JKR_RCV_HDR_OVFL_CNT,

	/* RXE kernel/user registers */
	.rxe_ku_stride = JKR_C_RXE_UCTXT_STRIDE,
	.rcv_ctxt_status_reg = JKR_RCV_CTXT_STATUS,

	/* RXE user registers */
	.rxe_uctxt_stride = JKR_C_RXE_UCTXT_STRIDE,
	.rcv_hdr_tail_reg = JKR_RCV_HDR_TAIL,
	.rcv_hdr_head_reg = JKR_RCV_HDR_HEAD,
	.rcv_egr_index_head_reg = JKR_RCV_EGR_INDEX_HEAD,
	.rcv_tid_flow_table_reg = JKR_RCV_TID_FLOW_TABLE,

	/* RXE RSM registers */
	.rcv_rsm_cfg_reg = JKR_RCV_RSM_CFG,
	.rcv_rsm_select_reg = JKR_RCV_RSM_SELECT,
	.rcv_rsm_match_reg = JKR_RCV_RSM_MATCH,
	.rcv_rsm_map_table_reg = JKR_RCV_RSM_MAP_TABLE,

	/* TXE kernel registers */
	.send_contexts_reg = JKR_SEND_CONTEXTS,
	.send_dma_engines_reg = JKR_SEND_DMA_ENGINES,
	.send_pio_mem_size_reg = JKR_SEND_PIO_MEM_SIZE,
	.send_dma_mem_size_reg = JKR_SEND_DMA_MEM_SIZE,
	.send_pio_init_ctxt_reg = JKR_SEND_PIO_INIT_CTXT,

	/* send context_registers */
	.txe_sctxt_stride = JKR_C_TXE_SCTXT_STRIDE,
	.send_ctxt_status_reg = JKR_SEND_CTXT_STATUS,
	.send_ctxt_credit_ctrl_reg = JKR_SEND_CTXT_CREDIT_CTRL,
	.send_ctxt_credit_status_reg = JKR_SEND_CTXT_CREDIT_STATUS,
	.send_ctxt_credit_return_addr_reg = JKR_SEND_CTXT_CREDIT_RETURN_ADDR,
	.send_ctxt_credit_force_reg = JKR_SEND_CTXT_CREDIT_FORCE,
	.send_ctxt_err_status_reg = JKR_SEND_CTXT_ERR_STATUS,
	.send_ctxt_err_mask_reg = JKR_SEND_CTXT_ERR_MASK,
	.send_ctxt_err_clear_reg = JKR_SEND_CTXT_ERR_CLEAR,

	/* TXE send context registers */
	.txe_tctxt_stride = JKR_C_TXE_TCTXT_STRIDE,
	.send_ctxt_ctrl_reg = JKR_SEND_CTXT_CTRL,

	/* SDMA registers */
	.txe_sdma_stride = JKR_C_TXE_SDMA_STRIDE,
	.send_dma_ctrl_reg = JKR_SEND_DMA_CTRL,
	.send_dma_status_reg = JKR_SEND_DMA_STATUS,
	.send_dma_base_addr_reg = JKR_SEND_DMA_BASE_ADDR,
	.send_dma_len_gen_reg = JKR_SEND_DMA_LEN_GEN,
	.send_dma_tail_reg = JKR_SEND_DMA_TAIL,
	.send_dma_head_reg = JKR_SEND_DMA_HEAD,
	.send_dma_head_addr_reg = JKR_SEND_DMA_HEAD_ADDR,
	.send_dma_priority_thld_reg = JKR_SEND_DMA_PRIORITY_THLD,
	.send_dma_idle_cnt_reg = JKR_SEND_DMA_IDLE_CNT,
	.send_dma_reload_cnt_reg = JKR_SEND_DMA_RELOAD_CNT,
	.send_dma_desc_cnt_reg = JKR_SEND_DMA_DESC_CNT,
	.send_dma_desc_fetched_cnt_reg = JKR_SEND_DMA_DESC_FETCHED_CNT,
	.send_dma_eng_err_status_reg = JKR_SEND_DMA_ENG_ERR_STATUS,
	.send_dma_eng_err_mask_reg = JKR_SEND_DMA_ENG_ERR_MASK,
	.send_dma_eng_err_clear_reg = JKR_SEND_DMA_ENG_ERR_CLEAR,

	/* SDMA Config registers */
	.txe_sdmacfg_stride = JKR_C_TXE_SDMACFG_STRIDE,
	.send_dma_cfg_memory_reg = JKR_SEND_DMA_CFG_MEMORY,

	/* egress port registers */
	.txe_eport_stride = JKR_C_TXE_EPORT_STRIDE,
	.send_ctrl_reg = JKR_SEND_CTRL,
	.send_high_priority_limit_reg = JKR_SEND_HIGH_PRIORITY_LIMIT,
	.send_egress_err_status_reg = JKR_SEND_EGRESS_ERR_STATUS,
	.send_egress_err_mask_reg = JKR_SEND_EGRESS_ERR_MASK,
	.send_egress_err_clear_reg = JKR_SEND_EGRESS_ERR_CLEAR,
	.send_bth_qp_reg = JKR_SEND_BTH_QP,
	.send_static_rate_control_reg = JKR_SEND_STATIC_RATE_CONTROL,
	.send_sc2vlt0_reg = JKR_SEND_SC2VLT0,
	.send_sc2vlt1_reg = JKR_SEND_SC2VLT1,
	.send_sc2vlt2_reg = JKR_SEND_SC2VLT2,
	.send_sc2vlt3_reg = JKR_SEND_SC2VLT3,
	.send_len_check0_reg = JKR_SEND_LEN_CHECK0,
	.send_len_check1_reg = JKR_SEND_LEN_CHECK1,
	.send_low_priority_list_reg = JKR_SEND_LOW_PRIORITY_LIST,
	.send_high_priority_list_reg = JKR_SEND_HIGH_PRIORITY_LIST,
	.send_counter_array32_reg = JKR_SEND_COUNTER_ARRAY32,
	.send_counter_array64_reg = JKR_SEND_COUNTER_ARRAY64,
	.send_cm_ctrl_reg = JKR_SEND_CM_CTRL,
	.send_cm_global_credit_reg = JKR_SEND_CM_GLOBAL_CREDIT,
	.send_cm_credit_used_status_reg = JKR_SEND_CM_CREDIT_USED_STATUS,
	.send_cm_timer_ctrl_reg = JKR_SEND_CM_TIMER_CTRL,
	.send_cm_local_au_table0_to3_reg = JKR_SEND_CM_LOCAL_AU_TABLE0_TO3,
	.send_cm_local_au_table4_to7_reg = JKR_SEND_CM_LOCAL_AU_TABLE4_TO7,
	.send_cm_remote_au_table0_to3_reg = JKR_SEND_CM_REMOTE_AU_TABLE0_TO3,
	.send_cm_remote_au_table4_to7_reg = JKR_SEND_CM_REMOTE_AU_TABLE4_TO7,
	.send_cm_credit_vl_reg = JKR_SEND_CM_CREDIT_VL,
	.send_cm_credit_vl15_reg = JKR_SEND_CM_CREDIT_VL15,
	.send_egress_err_info_reg = JKR_SEND_EGRESS_ERR_INFO,
	.send_egress_err_source_reg = JKR_SEND_EGRESS_ERR_SOURCE,
	.send_egress_ctxt_status_reg = JKR_SEND_EGRESS_CTXT_STATUS,
	.send_egress_send_dma_status_reg = JKR_SEND_EGRESS_SEND_DMA_STATUS,

	/* egress port send context registers */
	.txe_epsc_stride = JKR_C_TXE_EPSC_STRIDE,
	.send_ctxt_check_enable_reg = JKR_SEND_CTXT_CHECK_ENABLE,
	.send_ctxt_check_vl_reg = JKR_SEND_CTXT_CHECK_VL,
	.send_ctxt_check_job_key_reg = JKR_SEND_CTXT_CHECK_JOB_KEY,
	.send_ctxt_check_partition_key_reg = JKR_SEND_CTXT_CHECK_PARTITION_KEY,
	.send_ctxt_check_slid_reg = JKR_SEND_CTXT_CHECK_SLID,
	.send_ctxt_check_opcode_reg = JKR_SEND_CTXT_CHECK_OPCODE,

	/* SI registers */
	.cce_msix_int_map_vec_reg = JKR_CCE_MSIX_INT_MAP_VEC,
	.cce_msix_int_granted_reg = JKR_CCE_MSIX_INT_GRANTED,
	.send_pio_err_status_reg = JKR_SEND_PIO_ERR_STATUS,
	.send_pio_err_mask_reg = JKR_SEND_PIO_ERR_MASK,
	.send_pio_err_clear_reg = JKR_SEND_PIO_ERR_CLEAR,
	.send_dma_err_status_reg = JKR_SEND_DMA_ERR_STATUS,
	.send_dma_err_mask_reg = JKR_SEND_DMA_ERR_MASK,
	.send_dma_err_clear_reg = JKR_SEND_DMA_ERR_CLEAR,
	.csr_err_status_reg = JKR_CSR_ERR_STATUS,
	.csr_err_mask_reg = JKR_CSR_ERR_MASK,
	.csr_err_clear_reg = JKR_CSR_ERR_CLEAR,

	.hfi2_setextled = hfi2_gen_setextled,
	.start_led_override = hfi2_gen_start_led_override,
	.shutdown_led_override = hfi2_gen_shutdown_led_override,
	.hfi2_read_guid = hfi2_jkr_read_guid,
	.early_per_chip_init = hfi2_jkr_early_per_chip_init,
	.mid_per_chip_init = hfi2_jkr_mid_per_chip_init,
	.hfi2_init_other = hfi2_jkr_init_other,
	.late_per_chip_init = hfi2_gen_late_per_chip_init,
	.start_port = hfi2_gen_start_port,
	.stop_port = hfi2_gen_stop_port,
	.put_tid = hfi2_jkr_put_tid,
	.rcv_array_wc_fill = hfi2_jkr_rcv_array_wc_fill,
	.set_port_tid_config = hfi2_jkr_set_port_tid_config,
	.set_port_max_mtu = hfi2_gen_set_port_max_mtu,
	.update_rcv_hdr_size = hfi2_jkr_update_rcv_hdr_size,
	.check_synth_status = hfi2_jkr_check_synth_status,
	.update_synth_status = hfi2_jkr_update_synth_status,
	.create_pbc = hfi2_gen_create_pbc,
	.set_pio_integrity = hfi2_jkr_set_pio_integrity,
	.find_used_resources = hfi2_jkr_find_used_resources,
	.read_link_quality = hfi2_jkr_read_link_quality,
	.set_rheq_addr = hfi2_jkr_set_rheq_addr,
	.handle_link_bounce = hfi2_jkr_handle_link_bounce,
	.enable_rcv_context = hfi2_jkr_enable_rcv_context,
};

static const struct chip_params cyr_params = {
	.chip_type = CHIP_CYR,
	.num_ports = 1,
	.dma_mask_bits = 58,

	/* BAR0 map: see comments where KREG values are defined */
	.bar0_size = CYR_BAR0_SIZE,
	.kreg1_size = CYR_KREG1_SIZE,
	.kreg2_offset = CYR_KREG2_OFFSET,
	.kreg2_size = CYR_KREG2_SIZE,
	.rcv_array_offset = CYR_RCV_ARRAY,
	.rcv_array_size = CYR_RCV_ARRAY_SIZE,

	.link_speed_supported = OPA_LINK_SPEED_100G | OPA_LINK_SPEED_25G,
	.link_speed_active = OPA_LINK_SPEED_100G,
	.asic_cclock_ps = CYR_ASIC_CCLOCK_PS,
	.rsm_rule_size = CYR_C_RXE_NUM_RSM_INSTANCES,
	.rsm_rule_offset_shift = CYR_RCV_RSM_CFG_OFFSET_SHIFT,
	.rsm_map_table_entries = 512,
	.rsm_map_table_entries_per_csr = 4,
	.rsm_map_table_entry_mask = 0x1ff,
	.rsm_map_table_entry_shift = 16,
	.qp_map_table_entries = 512,
	.qp_map_table_entries_per_csr = 4,
	.qp_map_table_entry_mask = 0x1ff,
	.qp_map_table_entry_shift = 16,
	.pkey_table_size = CYR_MAX_PKEY_VALUES,
	.generic_boardname = "Cornelis Networks 6000 Host Fabric Interface Adapter",
	.max_eager_entries = CYR_MAX_EAGER_ENTRIES,
	.pio_base_bits = CYR_PIO_BASE_BITS,
	.pio_base_shift = CYR_SEND_CTXT_CTRL_CTXT_BASE_SHIFT,
	.egress_err_info_data = &cyr_egress_err_info_data,
	.send_ctrl_flush = CYR_SEND_CTRL_FLUSH_WRONG_LINK_STATE_SMASK,
	.port_discard_egress_errs = CYR_PORT_DISCARD_EGRESS_ERRS,
	.rcv_hdr_ent_size_max = 64,


	/* interrupt sources */
	.num_int_csrs = CYR_C_CCE_NUM_INT_CSRS,
	.num_int_map_csrs = CYR_C_CCE_NUM_INT_MAP_CSRS,
	.is_cport_int = CYR_MCTXT_CPORT_TO_PCIE_INT,
	.is_rcvavail_start = CYR_IS_RCVAVAIL_START,
	.is_rcvurgent_start = CYR_IS_RCVURGENT_START,
	.is_sdmaeng_err_start = CYR_IS_SDMAENG_ERR_START,
	.is_sdma_idle_start = CYR_IS_SDMA_IDLE_START,
	.is_sdma_progress_start = CYR_IS_SDMA_PROGRESS_START,
	.is_sdma_start = CYR_IS_SDMA_START,
	.is_doorbell0 = CYR_IS_DOORBELL0,
	.is_doorbell1 = CYR_IS_DOORBELL1,
	.is_last_source = CYR_IS_LAST_SOURCE,
	.is_table = cyr_is_table,
	.gi_enable_table = cyr_gi_enable_table,

	/* cce_interrupt registers */
	.cce_int_status_reg = CYR_CCE_INT_STATUS,
	.cce_int_mask_reg = CYR_CCE_INT_MASK,
	.cce_int_clear_reg = CYR_CCE_INT_CLEAR,
	.cce_int_force_reg = CYR_CCE_INT_FORCE,
	.cce_int_blocked_reg = CYR_CCE_INT_BLOCKED,

	/* counters */
	.chip_dev_cntrs = hfi2_cyr_dev_cntrs,
	.chip_dev_cntr_first = CYR_DEV_CNTR_FIRST,
	.chip_num_dev_cntrs = CYR_NUM_DEV_CNTRS,
	.chip_port_cntrs = hfi2_cyr_port_cntrs,
	.chip_port_cntr_first = CYR_PORT_CNTR_FIRST,
	.chip_num_port_cntrs = CYR_NUM_PORT_CNTRS,

	/* ingress port registers */
	.rxe_iport_stride = CYR_C_RXE_IPORT_STRIDE,
	.rcv_iport_ctrl_reg = CYR_RCV_IPORT_CTRL,
	.rcv_iport_status_reg = CYR_RCV_IPORT_STATUS,
	.rcv_bth_qp_reg = CYR_RCV_BTH_QP,
	.rcv_multicast_reg = CYR_RCV_MULTICAST,
	.rcv_bypass_reg = CYR_RCV_BYPASS,
	.rcv_vl15_reg = CYR_RCV_VL15,
	.rcv_err_info_reg = CYR_RCV_ERR_INFO,
	.rcv_err_status_reg = CYR_RCV_ERR_STATUS,
	.rcv_err_mask_reg = CYR_RCV_ERR_MASK,
	.rcv_err_clear_reg = CYR_RCV_ERR_CLEAR,
	.rcv_qp_map_table_reg = CYR_RCV_QP_MAP_TABLE,
	.rcv_partition_key_reg = CYR_RCV_PARTITION_KEY,
	.rcv_counter_array32_reg = CYR_RCV_COUNTER_ARRAY32,
	.rcv_counter_array64_reg = CYR_RCV_COUNTER_ARRAY64,

	/* ingress port receive context registers */
	.rxe_iprc_stride = CYR_C_RXE_IPRC_STRIDE,
	.rcv_jkey_ctrl_reg = CYR_RCV_JKEY_CTRL,

	/* RXE restricted context registers */
	.rxe_rctxt_stride = CYR_C_RXE_RCTXT_STRIDE,
	.rcv_rctxt_ctrl_reg = CYR_RCV_RCTXT_CTRL,
	.rcv_egr_ctrl_reg = CYR_RCV_EGR_CTRL,
	.rcv_tid_ctrl_reg = CYR_RCV_TID_CTRL,

	/* RXE kernel context registers */
	.rxe_kctxt_stride = CYR_C_RXE_KCTXT_STRIDE,
	.rcv_kctxt_ctrl_reg = CYR_RCV_KCTXT_CTRL,
	.rcv_hdr_addr_reg = CYR_RCV_HDR_ADDR,
	.rcv_hdr_cnt_reg = CYR_RCV_HDR_CNT,
	.rcv_hdr_ent_size_reg = CYR_RCV_HDR_ENT_SIZE,
	.rcv_hdr_tail_addr_reg = CYR_RCV_HDR_TAIL_ADDR,
	.rcv_avail_time_out_reg = CYR_RCV_AVAIL_TIME_OUT,
	.rcv_hdr_ovfl_cnt_reg = CYR_RCV_HDR_OVFL_CNT,

	/* RXE kernel/user registers */
	.rxe_ku_stride = CYR_C_RXE_UCTXT_STRIDE,
	.rcv_ctxt_status_reg = CYR_RCV_CTXT_STATUS,

	/* RXE user registers */
	.rxe_uctxt_stride = CYR_C_RXE_UCTXT_STRIDE,
	.rcv_hdr_tail_reg = CYR_RCV_HDR_TAIL,
	.rcv_hdr_head_reg = CYR_RCV_HDR_HEAD,
	.rcv_egr_index_head_reg = CYR_RCV_EGR_INDEX_HEAD,
	.rcv_tid_flow_table_reg = CYR_RCV_TID_FLOW_TABLE,

	/* RXE RSM registers */
	.rcv_rsm_cfg_reg = CYR_RCV_RSM_CFG,
	.rcv_rsm_select_reg = CYR_RCV_RSM_SELECT,
	.rcv_rsm_match_reg = CYR_RCV_RSM_MATCH,
	.rcv_rsm_map_table_reg = CYR_RCV_RSM_MAP_TABLE,

	/* TXE kernel registers */
	.send_contexts_reg = CYR_SEND_CONTEXTS,
	.send_dma_engines_reg = CYR_SEND_DMA_ENGINES,
	.send_pio_mem_size_reg = CYR_SEND_PIO_MEM_SIZE,
	.send_dma_mem_size_reg = CYR_SEND_DMA_MEM_SIZE,
	.send_pio_init_ctxt_reg = CYR_SEND_PIO_INIT_CTXT,

	/* send context_registers */
	.txe_sctxt_stride = CYR_C_TXE_SCTXT_STRIDE,
	.send_ctxt_status_reg = CYR_SEND_CTXT_STATUS,
	.send_ctxt_credit_ctrl_reg = CYR_SEND_CTXT_CREDIT_CTRL,
	.send_ctxt_credit_status_reg = CYR_SEND_CTXT_CREDIT_STATUS,
	.send_ctxt_credit_return_addr_reg = CYR_SEND_CTXT_CREDIT_RETURN_ADDR,
	.send_ctxt_credit_force_reg = CYR_SEND_CTXT_CREDIT_FORCE,
	.send_ctxt_err_status_reg = CYR_SEND_CTXT_ERR_STATUS,
	.send_ctxt_err_mask_reg = CYR_SEND_CTXT_ERR_MASK,
	.send_ctxt_err_clear_reg = CYR_SEND_CTXT_ERR_CLEAR,

	/* TXE send context registers */
	.txe_tctxt_stride = CYR_C_TXE_TCTXT_STRIDE,
	.send_ctxt_ctrl_reg = CYR_SEND_CTXT_CTRL,

	/* SDMA registers */
	.txe_sdma_stride = CYR_C_TXE_SDMA_STRIDE,
	.send_dma_ctrl_reg = CYR_SEND_DMA_CTRL,
	.send_dma_status_reg = CYR_SEND_DMA_STATUS,
	.send_dma_base_addr_reg = CYR_SEND_DMA_BASE_ADDR,
	.send_dma_len_gen_reg = CYR_SEND_DMA_LEN_GEN,
	.send_dma_tail_reg = CYR_SEND_DMA_TAIL,
	.send_dma_head_reg = CYR_SEND_DMA_HEAD,
	.send_dma_head_addr_reg = CYR_SEND_DMA_HEAD_ADDR,
	.send_dma_priority_thld_reg = CYR_SEND_DMA_PRIORITY_THLD,
	.send_dma_idle_cnt_reg = CYR_SEND_DMA_IDLE_CNT,
	.send_dma_reload_cnt_reg = CYR_SEND_DMA_RELOAD_CNT,
	.send_dma_desc_cnt_reg = CYR_SEND_DMA_DESC_CNT,
	.send_dma_desc_fetched_cnt_reg = CYR_SEND_DMA_DESC_FETCHED_CNT,
	.send_dma_eng_err_status_reg = CYR_SEND_DMA_ENG_ERR_STATUS,
	.send_dma_eng_err_mask_reg = CYR_SEND_DMA_ENG_ERR_MASK,
	.send_dma_eng_err_clear_reg = CYR_SEND_DMA_ENG_ERR_CLEAR,

	/* SDMA Config registers */
	.txe_sdmacfg_stride = CYR_C_TXE_SDMACFG_STRIDE,
	.send_dma_cfg_memory_reg = CYR_SEND_DMA_CFG_MEMORY,

	/* egress port registers */
	.txe_eport_stride = CYR_C_TXE_EPORT_STRIDE,
	.send_ctrl_reg = CYR_SEND_CTRL,
	.send_high_priority_limit_reg = CYR_SEND_HIGH_PRIORITY_LIMIT,
	.send_egress_err_status_reg = CYR_SEND_EGRESS_ERR_STATUS,
	.send_egress_err_mask_reg = CYR_SEND_EGRESS_ERR_MASK,
	.send_egress_err_clear_reg = CYR_SEND_EGRESS_ERR_CLEAR,
	.send_bth_qp_reg = CYR_SEND_BTH_QP,
	.send_static_rate_control_reg = CYR_SEND_STATIC_RATE_CONTROL,
	.send_sc2vlt0_reg = CYR_SEND_SC2VLT0,
	.send_sc2vlt1_reg = CYR_SEND_SC2VLT1,
	.send_sc2vlt2_reg = CYR_SEND_SC2VLT2,
	.send_sc2vlt3_reg = CYR_SEND_SC2VLT3,
	.send_len_check0_reg = CYR_SEND_LEN_CHECK0,
	.send_len_check1_reg = CYR_SEND_LEN_CHECK1,
	.send_low_priority_list_reg = CYR_SEND_LOW_PRIORITY_LIST,
	.send_high_priority_list_reg = CYR_SEND_HIGH_PRIORITY_LIST,
	.send_counter_array32_reg = CYR_SEND_COUNTER_ARRAY32,
	.send_counter_array64_reg = CYR_SEND_COUNTER_ARRAY64,
	.send_cm_ctrl_reg = CYR_SEND_CM_CTRL,
	.send_cm_global_credit_reg = CYR_SEND_CM_GLOBAL_CREDIT,
	.send_cm_credit_used_status_reg = CYR_SEND_CM_CREDIT_USED_STATUS,
	.send_cm_timer_ctrl_reg = CYR_SEND_CM_TIMER_CTRL,
	.send_cm_local_au_table0_to3_reg = CYR_SEND_CM_LOCAL_AU_TABLE0_TO3,
	.send_cm_local_au_table4_to7_reg = CYR_SEND_CM_LOCAL_AU_TABLE4_TO7,
	.send_cm_remote_au_table0_to3_reg = CYR_SEND_CM_REMOTE_AU_TABLE0_TO3,
	.send_cm_remote_au_table4_to7_reg = CYR_SEND_CM_REMOTE_AU_TABLE4_TO7,
	.send_cm_credit_vl_reg = CYR_SEND_CM_CREDIT_VL,
	.send_cm_credit_vl15_reg = CYR_SEND_CM_CREDIT_VL15,
	.send_egress_err_info_reg = CYR_SEND_EGRESS_ERR_INFO,
	.send_egress_err_source_reg = CYR_SEND_EGRESS_ERR_SOURCE,
	.send_egress_ctxt_status_reg = CYR_SEND_EGRESS_CTXT_STATUS,
	.send_egress_send_dma_status_reg = CYR_SEND_EGRESS_SEND_DMA_STATUS,

	/* egress port send context registers */
	.txe_epsc_stride = CYR_C_TXE_EPSC_STRIDE,
	.send_ctxt_check_enable_reg = CYR_SEND_CTXT_CHECK_ENABLE,
	.send_ctxt_check_vl_reg = CYR_SEND_CTXT_CHECK_VL,
	.send_ctxt_check_job_key_reg = CYR_SEND_CTXT_CHECK_JOB_KEY,
	.send_ctxt_check_partition_key_reg = CYR_SEND_CTXT_CHECK_PARTITION_KEY,
	.send_ctxt_check_slid_reg = CYR_SEND_CTXT_CHECK_SLID,
	.send_ctxt_check_opcode_reg = CYR_SEND_CTXT_CHECK_OPCODE,

	/* SI registers */
	.cce_msix_int_map_vec_reg = CYR_CCE_MSIX_INT_MAP_VEC,
	.cce_msix_int_granted_reg = CYR_CCE_MSIX_INT_GRANTED,
	.send_pio_err_status_reg = CYR_SEND_PIO_ERR_STATUS,
	.send_pio_err_mask_reg = CYR_SEND_PIO_ERR_MASK,
	.send_pio_err_clear_reg = CYR_SEND_PIO_ERR_CLEAR,
	.send_dma_err_status_reg = CYR_SEND_DMA_ERR_STATUS,
	.send_dma_err_mask_reg = CYR_SEND_DMA_ERR_MASK,
	.send_dma_err_clear_reg = CYR_SEND_DMA_ERR_CLEAR,
	.csr_err_status_reg = CYR_CSR_ERR_STATUS,
	.csr_err_mask_reg = CYR_CSR_ERR_MASK,
	.csr_err_clear_reg = CYR_CSR_ERR_CLEAR,

	.hfi2_setextled = hfi2_gen_setextled,
	.start_led_override = hfi2_gen_start_led_override,
	.shutdown_led_override = hfi2_gen_shutdown_led_override,
	.hfi2_read_guid = cyr_read_guid,
	.early_per_chip_init = cyr_early_per_chip_init,
	.mid_per_chip_init = cyr_mid_per_chip_init,
	.hfi2_init_other = cyr_init_other,
	.late_per_chip_init = hfi2_gen_late_per_chip_init,
	.start_port = hfi2_gen_start_port,
	.stop_port = hfi2_gen_stop_port,
	.put_tid = cyr_put_tid,
	.rcv_array_wc_fill = cyr_rcv_array_wc_fill,
	.set_port_tid_config = cyr_set_port_tid_config,
	.set_port_max_mtu = hfi2_gen_set_port_max_mtu,
	.update_rcv_hdr_size = cyr_update_rcv_hdr_size,
	.check_synth_status = cyr_check_synth_status,
	.update_synth_status = cyr_update_synth_status,
	.create_pbc = hfi2_gen_create_pbc,
	.set_pio_integrity = cyr_set_pio_integrity,
	.find_used_resources = cyr_find_used_resources,
	.read_link_quality = cyr_read_link_quality,
	.set_rheq_addr = cyr_set_rheq_addr,
	.handle_link_bounce = cyr_handle_link_bounce,
	.enable_rcv_context = cyr_enable_rcv_context,
};

/*
 * Number of user receive contexts each port configured to use (allow for more
 * pio buffers per ctxt, etc).
 */
static char *num_user_contexts_array[32];
unsigned int hfi2_cu = 1;
static int num_user_contexts_count;

uint hfi2_krcvqs[RXE_NUM_DATA_VL];
int hfi2_krcvqsset;

/* computed based on above array */
unsigned long hfi2_n_krcvqs;

static unsigned int hfi2_rcvarr_split = 25;

static uint eager_buffer_size = (8 << 20); /* 8MB */

static uint rcvhdrcnt = 2048; /* 2x the max eager buffer count */

static uint hfi2_hdrq_entsize = DEFAULT_HDRQ_ENTSIZE;

unsigned int hfi2_user_credit_return_threshold = 33; /* default is 33% */

int work_around_ASIC_6032 = 5000;








/* use and give resources to rdmavt bulk service */
bool use_bulksvc = true;

DEFINE_XARRAY_FLAGS(hfi2_dev_table, XA_FLAGS_ALLOC | XA_FLAGS_LOCK_IRQ);

struct cport_trap_reg {
	u32 mask;
	cport_trap_handler func;
};

/* send, or resend, START message */
int cport_start_si(struct hfi2_devdata *dd, u8 si, u8 port, int to_secs)
{
	struct cport_start_payload start = { 0 };
	union {
		struct cport_start_payload pl;
		u64 qw;
	} *resp = NULL;
	int resp_len = 0;
	int ret;

	if (si > 7 || port > 3)
		return -EINVAL;
	if (!dd->cport)
		return 0;
	start.sidx = si | (port << 3);
	start.opts_ena = dd->cport->opts;
	start.trap_ena = dd->cport->traps;

	ret = hfi2_cport_send_req(dd, CH_OP_START, 0, &start, sizeof(start),
				  (void **)&resp, &resp_len, to_secs * HZ);
	if (ret == MSG_RSP_STATUS_SEQ_NO_ERROR) {
		dd_dev_info(dd, "CPORT sequence error, retrying\n");
		kfree(resp);
		resp = NULL;
		ret = hfi2_cport_send_req(dd, CH_OP_START, 0, &start,
					  sizeof(start), (void **)&resp,
					  &resp_len, HZ);
	}
	if (ret) {
		dd_dev_err(dd, "CPORT start failed %d\n", ret);
	} else if (resp_len) {
		dd_dev_info(dd, "CPORT started %016llx\n", resp->qw);
		if (!si)
			dd->cport->traps_act = resp->pl.trap_ena;
	} else {
		dd_dev_info(dd, "CPORT started\n");
	}
	kfree(resp);
	return ret;
}

static int cport_start(struct hfi2_devdata *dd, int to_secs)
{
	return cport_start_si(dd, 0, 0, to_secs);
}

static void cport_trap_mask(struct hfi2_cport *cport,
			    struct cport_trap_status *traps)
{
	struct cport_trap_reg *entry;
	unsigned long index;
	u32 mask = 0;

	xa_for_each(&cport->trap_xa, index, entry)
		mask |= entry->mask;
	traps->flags = mask;
}

int hfi2_register_cport_trap(struct hfi2_devdata *dd,
			     struct cport_trap_status traps,
			     cport_trap_handler func)
{
	struct hfi2_cport *cport = hfi2_cport_get_live(dd);
	struct cport_trap_reg *entry;
	struct cport_trap_status old_traps;
	u32 index;
	int ret;

	if (!cport)
		return 0;
	if (!func) {
		hfi2_cport_put(cport);
		return -EINVAL;
	}

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry) {
		hfi2_cport_put(cport);
		return -ENOMEM;
	}
	entry->mask = traps.flags;
	entry->func = func;

	mutex_lock(&cport->trap_lock);
	old_traps = cport->traps;
	ret = xa_alloc(&cport->trap_xa, &index, entry, xa_limit_32b,
		       GFP_KERNEL);
	if (ret < 0)
		goto unlock_free;
	cport_trap_mask(cport, &cport->traps);
	if (cport->traps.flags != old_traps.flags) {
		ret = cport_start(dd, hfi2_cport_adm_to);
		if (ret) {
			xa_erase(&cport->trap_xa, index);
			cport->traps = old_traps;
			goto unlock_free;
		}
	}
	mutex_unlock(&cport->trap_lock);
	hfi2_cport_put(cport);
	return 0;

unlock_free:
	mutex_unlock(&cport->trap_lock);
	kfree(entry);
	hfi2_cport_put(cport);
	return ret;
}

int hfi2_deregister_cport_trap(struct hfi2_devdata *dd, cport_trap_handler func)
{
	struct hfi2_cport *cport = hfi2_cport_get_live(dd);
	struct cport_trap_reg *entry;
	struct cport_trap_status old_traps;
	struct cport_trap_status new_traps = { };
	unsigned long index;
	int ret = 0;

	if (!cport)
		return 0;

	mutex_lock(&cport->trap_lock);
	old_traps = cport->traps;
	xa_for_each(&cport->trap_xa, index, entry) {
		if (entry->func != func)
			new_traps.flags |= entry->mask;
	}
	cport->traps = new_traps;
	if (new_traps.flags != old_traps.flags) {
		ret = cport_start(dd, hfi2_cport_adm_to);
		if (ret) {
			cport->traps = old_traps;
			goto unlock;
		}
	}
	xa_for_each(&cport->trap_xa, index, entry) {
		if (entry->func == func) {
			xa_erase(&cport->trap_xa, index);
			kfree(entry);
		}
	}

unlock:
	mutex_unlock(&cport->trap_lock);
	hfi2_cport_put(cport);

	return ret;
}

static void clearall_cport_trap(struct hfi2_devdata *dd)
{
	struct hfi2_cport *cport = hfi2_cport_get_live(dd);
	struct cport_trap_reg *entry;
	struct cport_trap_status no_traps = { };
	unsigned long index;

	if (!cport)
		return;

	mutex_lock(&cport->trap_lock);
	cport->traps = no_traps;
	cport_start(dd, hfi2_cport_adm_to);
	WRITE_ONCE(cport->handlers[CH_OP_TRAP], NULL);
	xa_for_each(&cport->trap_xa, index, entry) {
		xa_erase(&cport->trap_xa, index);
		dd_dev_info(dd, "removing latent TRAP handler %ps\n", entry->func);
		kfree(entry);
	}
	mutex_unlock(&cport->trap_lock);
	hfi2_cport_put(cport);
}

static int handle_cport_trap(struct hfi2_devdata *dd, u8 op, u8 sideband,
			     void *payload, int len, void *handle)
{
	struct cport_trap_payload *traps = payload;
	struct cport_trap_payload repress = { 0 };
	union {
		struct cport_trap_status traps;
		u32 dw;
	} trap_val;
	struct cport_trap_reg *entry;
	unsigned long index;
	int ret;

	if (len != sizeof(*traps))
		return MSG_RSP_STATUS_INVALID_STATE;

	trap_val.traps = traps->trap_sts;

	/* clear-down the traps we got */
	repress.trap_sts = traps->trap_sts;
	ret = hfi2_cport_send_notif(dd, CH_OP_TRAP_REPRESS, 0, &repress,
				    sizeof(repress), hfi2_cport_adm_to * HZ);
	if (ret)
		dd_dev_warn(dd, "CPORT TRAP_REPRESS failed: %d\n", ret);
#ifdef CPORT_TRAP_DEBUG
	pr_warn("hfi2_%d: %s: CPORT TRAP %08x\n", dd->unit, __func__,
		trap_val.dw);
#endif

	mutex_lock(&dd->cport->trap_lock);
	xa_for_each(&dd->cport->trap_xa, index, entry) {
		if (entry->mask & trap_val.dw)
			entry->func(dd, trap_val.traps);
	}
	mutex_unlock(&dd->cport->trap_lock);

	return 0;
}

int cport_stop_si(struct hfi2_devdata *dd, u8 si, u8 port)
{
	struct cport_stop_payload stop = { 0 };
	u64 *resp = NULL;
	int resp_len = 0;
	int ret;

	if (si > 7 || port > 3)
		return -EINVAL;
	if (!dd->cport)
		return 0;
	stop.sidx = si | ((u64)port << 3);

	ret = hfi2_cport_send_req(dd, CH_OP_STOP, 0, &stop, sizeof(stop),
				  (void **)&resp, &resp_len,
				  hfi2_cport_adm_to * HZ);
	if (ret)
		dd_dev_err(dd, "CPORT stop failed %d\n", ret);
	else if (resp_len)
		dd_dev_info(dd, "CPORT stopped %016llx\n", *resp);
	else
		dd_dev_info(dd, "CPORT stopped\n");
	kfree(resp);
	return ret;
}

static void cport_stop(struct hfi2_devdata *dd)
{
	cport_stop_si(dd, 0, 0);
}

int hfi2_start_cport(struct hfi2_devdata *dd)
{
	int ret;

	ret = hfi2_cport_init(dd);
	if (ret || !dd->cport)
		return ret;

	/*
	 * Do a STOP to ensure the device is properly cleaned up.
	 * This may cause firmware to be unresponsive for awhile,
	 * so increase the timeout for the subsequent START.
	 */
	cport_stop(dd);

	hfi2_cport_register_cb(dd, CH_OP_TRAP, CH_OP_TRAP, handle_cport_trap);

	dd->cport->opts.flags |= CPORT_OPT_BARE_METAL;

	ret = cport_start(dd, 3 * hfi2_cport_adm_to);
	if (ret) {
		hfi2_cport_register_cb(dd, CH_OP_TRAP, CH_OP_TRAP, NULL);
		hfi2_cport_exit(dd);
	}
	return (ret > 0 ? -EIO : ret);
}

static void stop_cport(struct hfi2_devdata *dd)
{
	if (!dd->cport)
		return;

	cport_stop(dd);

	hfi2_cport_exit(dd);
}

int hfi2_create_kctxt(struct hfi2_pportdata *ppd, u16 ctxt,
			    bool is_bulksvc)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_ctxtdata *rcd;
	int ret;

	/* Control context has to be always 0 */
	BUILD_BUG_ON(HFI2_CTRL_CTXT != 0);

	ret = hfi2_create_ctxtdata(ppd, dd->node, ctxt, &rcd);
	if (ret < 0) {
		dd_dev_err(dd, "Kernel receive context allocation failed\n");
		return ret;
	}

	/*
	 * Set up the kernel context flags here and now because they use
	 * default values for all receive side memories.  User contexts will
	 * be handled as they are created.
	 */
	rcd->flags = HFI2_CAP_KGET(MULTI_PKT_EGR) |
		     HFI2_CAP_KGET(NODROP_RHQ_FULL) |
		     HFI2_CAP_KGET(NODROP_EGR_FULL) | HFI2_CAP_KGET(DMA_RTAIL);

	/* Control context must use DMA_RTAIL */
	if (hfi2_is_control_context(rcd))
		rcd->flags |= HFI2_CAP_DMA_RTAIL;
	rcd->fast_handler = get_dma_rtail_setting(rcd) ?
				    hfi2_handle_receive_interrupt_dma_rtail :
				    hfi2_handle_receive_interrupt_nodma_rtail;

	hfi2_set_seq_cnt(rcd, 1);

	rcd->sc = hfi2_sc_alloc(ppd, is_bulksvc ? SC_BULKSVC : SC_ACK,
			   rcd->rcvhdrqentsize, dd->node);
	if (!rcd->sc) {
		dd_dev_err(dd, "Kernel send context allocation failed\n");
		return -ENOMEM;
	}
	hfi2_init_ctxt(rcd->sc);

	return 0;
}

/*
 * Create the receive context array and one or more kernel contexts
 */
int hfi2_create_kctxts(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	u16 i;
	u16 j;
	int ret;

	/*
	 * so this is making dd->rcd much larger than needed. Unfortunately,
	 * current code requires that dd->rcd[x].ctxt == x (h/w context number
	 * must be the same as dd->rcd index number - s/w context number)
	 * and much code needs to change in order to fix this.
	 */
	dd->num_rcd = chip_rcv_contexts(dd);
	dd->rcd = kcalloc_node(dd->num_rcd, sizeof(*dd->rcd), GFP_KERNEL,
			       dd->node);
	if (!dd->rcd) {
		dd->num_rcd = 0;
		return -ENOMEM;
	}

	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_pportdata *ppd = dd->pport + i;
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			ret = hfi2_create_kctxt(ppd, ctxt, false);
			if (ret)
				goto bail;
		}
	}

	return 0;
bail:
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			hfi2_free_ctxt(dd->rcd[ctxt]);
		}
	}

	/* All the contexts should be freed, free the array */
	kfree(dd->rcd);
	dd->rcd = NULL;
	dd->num_rcd = 0;
	return ret;
}

/*
 * Helper routines for the receive context reference count (rcd and uctxt).
 */
static void hfi2_rcd_init(struct hfi2_ctxtdata *rcd)
{
	kref_init(&rcd->kref);
}

/**
 * hfi2_rcd_free - When reference is zero clean up.
 * @kref: pointer to an initialized rcd data structure
 *
 */
static void hfi2_rcd_free(struct kref *kref)
{
	unsigned long flags;
	struct hfi2_ctxtdata *rcd =
		container_of(kref, struct hfi2_ctxtdata, kref);

	spin_lock_irqsave(&rcd->dd->uctxt_lock, flags);
	rcd->dd->rcd[rcd->ctxt] = NULL;
	spin_unlock_irqrestore(&rcd->dd->uctxt_lock, flags);

	hfi2_free_ctxtdata(rcd->dd, rcd);

	kfree(rcd);
}

/**
 * hfi2_rcd_put - decrement reference for rcd
 * @rcd: pointer to an initialized rcd data structure
 *
 * Use this to put a reference after the init.
 */
int hfi2_rcd_put(struct hfi2_ctxtdata *rcd)
{
	if (rcd)
		return kref_put(&rcd->kref, hfi2_rcd_free);

	return 0;
}

/**
 * hfi2_rcd_get - increment reference for rcd
 * @rcd: pointer to an initialized rcd data structure
 *
 * Use this to get a reference after the init.
 *
 * Return : reflect kref_get_unless_zero(), which returns non-zero on
 * increment, otherwise 0.
 */
int hfi2_rcd_get(struct hfi2_ctxtdata *rcd)
{
	return kref_get_unless_zero(&rcd->kref);
}

/**
 * allocate_rcd_index - allocate an rcd index from the rcd array
 * @ppd: pointer to a valid port data structure
 * @rcd: rcd data structure to assign
 * @index[in,out]: in, suggested context number; out, selected context number
 * @index: suggested context number on input, selected context number on output
 *
 * Allocate an rcd index, either at the given context number or any within
 * a dynamic range.  If the fixed index is used or the dynamic range is full,
 * return -EBUSY.
 */
static int allocate_rcd_index(struct hfi2_pportdata *ppd,
			      struct hfi2_ctxtdata *rcd, u16 *index)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_portrsrcs *pr = &dd->rsrcs.ppr[ppd->hw_pidx];
	unsigned long flags;
	u16 ctxt = *index;
	bool found;

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	found = false;
	if (ctxt == DYNAMIC_CONTEXT) {
		/* look for an unused dynamic context */
		for (ctxt = pr->first_dyn_alloc_ctxt;
		     ctxt < pr->rcv_context_base + pr->num_rcv_contexts;
		     ctxt++) {
			if (!dd->rcd[ctxt]) {
				found = true;
				break;
			}
		}
	} else {
		/* use the context number given */
		if (!dd->rcd[ctxt])
			found = true;
	}

	if (found) {
		rcd->ctxt = ctxt;
		dd->rcd[ctxt] = rcd;
		hfi2_rcd_init(rcd);
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	if (!found)
		return -EBUSY;

	*index = ctxt;

	return 0;
}

/**
 * hfi2_rcd_get_by_index - get rcd by index
 * @dd: pointer to a valid devdata structure
 * @ctxt: the index of a possible rcd
 *
 * Hold the protecting spinlock and increment the reference on the selected
 * rcd element.
 *
 * The caller is responsible for calling hfi2_rcd_put() on the returned
 * pointer.
 */
struct hfi2_ctxtdata *hfi2_rcd_get_by_index(struct hfi2_devdata *dd, u16 ctxt)
{
	unsigned long flags;
	struct hfi2_ctxtdata *rcd = NULL;

	spin_lock_irqsave(&dd->uctxt_lock, flags);
	if (ctxt < dd->num_rcd) {
		rcd = dd->rcd[ctxt];
		if (rcd && !hfi2_rcd_get(rcd))
			rcd = NULL;
	}
	spin_unlock_irqrestore(&dd->uctxt_lock, flags);

	return rcd;
}

/*
 * Common code for user and kernel context create and setup.
 * NOTE: the initial kref is done here (hf1_rcd_init()).
 */
int hfi2_create_ctxtdata(struct hfi2_pportdata *ppd, int numa, u16 ctxt,
			 struct hfi2_ctxtdata **context)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_portrsrcs *pr = &dr->ppr[ppd->hw_pidx];
	struct hfi2_ctxtdata *rcd;

	rcd = kzalloc_node(sizeof(*rcd), GFP_KERNEL, numa);
	if (rcd) {
		u32 rcvtids, max_entries;
		int ret;

		ret = allocate_rcd_index(ppd, rcd, &ctxt);
		if (ret) {
			*context = NULL;
			kfree(rcd);
			return ret;
		}

		INIT_LIST_HEAD(&rcd->qp_wait_list);
		hfi2_exp_tid_group_init(rcd);
		rcd->ppd = ppd;
		rcd->dd = dd;
		rcd->numa_id = numa;
		rcd->rcv_array_groups = dd->rcv_entries.ngroups;
		rcd->rhf_rcv_function_map = hfi2_normal_rhf_rcv_functions;
		rcd->slow_handler = hfi2_handle_receive_interrupt;
		rcd->do_interrupt = rcd->slow_handler;
		rcd->msix_intr = CCE_NUM_MSIX_VECTORS;

		mutex_init(&rcd->exp_mutex);
		spin_lock_init(&rcd->exp_lock);
		INIT_LIST_HEAD(&rcd->flow_queue.queue_head);
		INIT_LIST_HEAD(&rcd->rarr_queue.queue_head);

		hfi2_cdbg(PROC, "setting up context %u", rcd->ctxt);

		/* calculate the context's RcvArray entry starting point */
		rcd->eager_base =
			pr->rcv_array_base +
			((ctxt - pr->rcv_context_base) *
			 dd->rcv_entries.ngroups * dd->rcv_entries.group_size);

		rcd->rcvhdrq_cnt = rcvhdrcnt;
		rcd->rcvhdrqentsize = dd->rcv_hdr_ent_size;
		rcd->rhf_offset =
			rcd->rcvhdrqentsize - sizeof(u64) / sizeof(u32);
		rcd->kdeth_rcv_hdr = DEFAULT_RCVHDRSIZE;
		/*
		 * Simple Eager buffer allocation: we have already pre-allocated
		 * the number of RcvArray entry groups. Each ctxtdata structure
		 * holds the number of groups for that context.
		 *
		 * To follow CSR requirements and maintain cacheline alignment,
		 * make sure all sizes and bases are multiples of group_size.
		 *
		 * The expected entry count is what is left after assigning
		 * eager.
		 */
		max_entries =
			rcd->rcv_array_groups * dd->rcv_entries.group_size;
		rcvtids = ((max_entries * hfi2_rcvarr_split) / 100);
		rcd->egrbufs.count =
			round_down(rcvtids, dd->rcv_entries.group_size);
		if (rcd->egrbufs.count > dd->params->max_eager_entries) {
			dd_dev_err(
				dd,
				"ctxt%u: requested too many RcvArray entries.\n",
				rcd->ctxt);
			rcd->egrbufs.count = dd->params->max_eager_entries;
		}
		hfi2_cdbg(PROC, "ctxt%u: max Eager buffer RcvArray entries: %u",
			  rcd->ctxt, rcd->egrbufs.count);

		/*
		 * Allocate array that will hold the eager buffer accounting
		 * data.
		 * This will allocate the maximum possible buffer count based
		 * on the value of the RcvArray split parameter.
		 * The resulting value will be rounded down to the closest
		 * multiple of dd->rcv_entries.group_size.
		 */
		rcd->egrbufs.buffers = kcalloc_node(
			rcd->egrbufs.count, sizeof(*rcd->egrbufs.buffers),
			GFP_KERNEL, numa);
		if (!rcd->egrbufs.buffers)
			goto bail;
		rcd->egrbufs.rcvtids = kcalloc_node(
			rcd->egrbufs.count, sizeof(*rcd->egrbufs.rcvtids),
			GFP_KERNEL, numa);
		if (!rcd->egrbufs.rcvtids)
			goto bail;
		rcd->egrbufs.size = eager_buffer_size;
		/*
		 * The size of the buffers programmed into the RcvArray
		 * entries needs to be big enough to handle the highest
		 * MTU supported.
		 */
		if (rcd->egrbufs.size < hfi2_max_mtu) {
			rcd->egrbufs.size = __roundup_pow_of_two(hfi2_max_mtu);
			hfi2_cdbg(
				PROC,
				"ctxt%u: eager bufs size too small. Adjusting to %u",
				rcd->ctxt, rcd->egrbufs.size);
		}
		rcd->egrbufs.rcvtid_size = HFI2_MAX_EAGER_BUFFER_SIZE;

		/* Applicable only for statically created kernel contexts */
		if (ctxt < pr->first_dyn_alloc_ctxt) {
			rcd->opstats = kzalloc_node(sizeof(*rcd->opstats),
						    GFP_KERNEL, numa);
			if (!rcd->opstats)
				goto bail;

			/* Initialize TID flow generations for the context */
			hfi2_kern_init_ctxt_generations(rcd);
		}

		*context = rcd;
		return 0;
	}

bail:
	*context = NULL;
	hfi2_free_ctxt(rcd);
	return -ENOMEM;
}

/**
 * hfi2_free_ctxt - free context
 * @rcd: pointer to an initialized rcd data structure
 *
 * This wrapper is the free function that matches hfi2_create_ctxtdata().
 * When a context is done being used (kernel or user), this function is called
 * for the "final" put to match the kref init from hfi2_create_ctxtdata().
 * Other users of the context do a get/put sequence to make sure that the
 * structure isn't removed while in use.
 */
void hfi2_free_ctxt(struct hfi2_ctxtdata *rcd)
{
	hfi2_rcd_put(rcd);
}

/*
 * Select the largest ccti value over all SLs to determine the intra-
 * packet gap for the link.
 *
 * called with cca_timer_lock held (to protect access to cca_timer
 * array), and rcu_read_lock() (to protect access to cc_state).
 */
void hfi2_set_link_ipg(struct hfi2_pportdata *ppd)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct cc_state *cc_state;
	int i;
	u16 cce, ccti_limit, max_ccti = 0;
	u16 shift, mult;
	u64 src;
	u32 current_egress_rate; /* Mbits /sec */
	u64 max_pkt_time;
	/*
	 * max_pkt_time is the maximum packet egress time in units
	 * of the fabric clock period 1/(805 MHz).
	 */

	cc_state = get_cc_state(ppd);

	if (!cc_state)
		/*
		 * This should _never_ happen - rcu_read_lock() is held,
		 * and hfi2_set_link_ipg() should not be called if cc_state
		 * is NULL.
		 */
		return;

	for (i = 0; i < OPA_MAX_SLS; i++) {
		u16 ccti = ppd->cca_timer[i].ccti;

		if (ccti > max_ccti)
			max_ccti = ccti;
	}

	ccti_limit = cc_state->cct.ccti_limit;
	if (max_ccti > ccti_limit)
		max_ccti = ccti_limit;

	cce = cc_state->cct.entries[max_ccti].entry;
	shift = (cce & 0xc000) >> 14;
	mult = (cce & 0x3fff);

	current_egress_rate = active_egress_rate(ppd);

	max_pkt_time = egress_cycles(ppd->ibmaxlen, current_egress_rate);

	src = (max_pkt_time >> shift) * mult;

	src &= SEND_STATIC_RATE_CONTROL_CSR_SRC_RELOAD_SMASK;
	src <<= SEND_STATIC_RATE_CONTROL_CSR_SRC_RELOAD_SHIFT;

	write_eport_csr(dd, ppd->hw_pidx,
			dd->params->send_static_rate_control_reg, src);
}

static enum hrtimer_restart cca_timer_fn(struct hrtimer *t)
{
	struct cca_timer *cca_timer;
	struct hfi2_pportdata *ppd;
	int sl;
	u16 ccti_timer, ccti_min;
	struct cc_state *cc_state;
	unsigned long flags;
	enum hrtimer_restart ret = HRTIMER_NORESTART;

	cca_timer = container_of(t, struct cca_timer, hrtimer);
	ppd = cca_timer->ppd;
	sl = cca_timer->sl;

	rcu_read_lock();

	cc_state = get_cc_state(ppd);

	if (!cc_state) {
		rcu_read_unlock();
		return HRTIMER_NORESTART;
	}

	/*
	 * 1) decrement ccti for SL
	 * 2) calculate IPG for link (hfi2_set_link_ipg())
	 * 3) restart timer, unless ccti is at min value
	 */

	ccti_min = cc_state->cong_setting.entries[sl].ccti_min;
	ccti_timer = cc_state->cong_setting.entries[sl].ccti_timer;

	spin_lock_irqsave(&ppd->cca_timer_lock, flags);

	if (cca_timer->ccti > ccti_min) {
		cca_timer->ccti--;
		hfi2_set_link_ipg(ppd);
	}

	if (cca_timer->ccti > ccti_min) {
		unsigned long nsec = 1024 * ccti_timer;
		/* ccti_timer is in units of 1.024 usec */
		hrtimer_forward_now(t, ns_to_ktime(nsec));
		ret = HRTIMER_RESTART;
	}

	spin_unlock_irqrestore(&ppd->cca_timer_lock, flags);
	rcu_read_unlock();
	return ret;
}

/*
 * Common code for initializing the physical port structure.
 */
void hfi2_init_pportdata(struct pci_dev *pdev, struct hfi2_pportdata *ppd,
			 struct hfi2_devdata *dd, u8 hw_pidx, u32 port)
{
	int i;
	uint default_pkey_idx;
	struct cc_state *cc_state;

	ppd->dd = dd;
	ppd->hw_pidx = hw_pidx;
	ppd->port = port; /* IB port number, not index */
	ppd->lid_block_mask = ~0U;
	ppd->prev_link_width = LINK_WIDTH_DEFAULT;
	/*
	 * There are C_VL_COUNT number of PortVLXmitWait counters.
	 * Adding 1 to C_VL_COUNT to include the PortXmitWait counter.
	 */
	for (i = 0; i < C_VL_COUNT + 1; i++) {
		ppd->port_vl_xmit_wait_last[i] = 0;
		ppd->vl_xmit_flit_cnt[i] = 0;
	}

	default_pkey_idx = 1;

	ppd->pkeys[default_pkey_idx] = DEFAULT_P_KEY;
	ppd->part_enforce |= HFI2_PART_ENFORCE_IN;
	ppd->pkeys[0] = 0x8001;

	INIT_WORK(&ppd->link_vc_work, hfi2_handle_verify_cap);
	INIT_WORK(&ppd->link_up_work, hfi2_handle_link_up);
	INIT_WORK(&ppd->link_down_work, hfi2_handle_link_down);
	INIT_WORK(&ppd->link_downgrade_work, hfi2_handle_link_downgrade);
	INIT_WORK(&ppd->sma_message_work, hfi2_handle_sma_message);
	INIT_WORK(&ppd->link_bounce_work, dd->params->handle_link_bounce);
	INIT_WORK(&ppd->portcfg_work, vf_apply_portcfg_work);
	INIT_DELAYED_WORK(&ppd->start_link_work, hfi2_handle_start_link);
	INIT_WORK(&ppd->linkstate_active_work, hfi2_receive_interrupt_work);
	INIT_WORK(&ppd->qsfp_info.qsfp_work, hfi2_qsfp_event);

	mutex_init(&ppd->hls_lock);
	spin_lock_init(&ppd->qsfp_info.qsfp_lock);
	seqlock_init(&ppd->sc2vl_lock);

	ppd->qsfp_info.ppd = ppd;
	ppd->sm_trap_qp = 0x0;
	ppd->sa_qp = 0x1;

	spin_lock_init(&ppd->cca_timer_lock);
	spin_lock_init(&ppd->vf_pkey_lock);
	spin_lock_init(&ppd->portcfg_lock);

	for (i = 0; i < OPA_MAX_SLS; i++) {
		ppd->cca_timer[i].ppd = ppd;
		ppd->cca_timer[i].sl = i;
		ppd->cca_timer[i].ccti = 0;
		hrtimer_setup(&ppd->cca_timer[i].hrtimer, cca_timer_fn,
			      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	}

	ppd->cc_max_table_entries = IB_CC_TABLE_CAP_DEFAULT;

	spin_lock_init(&ppd->cc_state_lock);
	spin_lock_init(&ppd->cc_log_lock);
	cc_state = kzalloc_obj(*cc_state, GFP_KERNEL);
	RCU_INIT_POINTER(ppd->cc_state, cc_state);
	if (!cc_state)
		goto bail;
	atomic_set(&ppd->ipoib_rsm_usr_num, 0);
	atomic_set(&ppd->vnic_rsm_usr_num, 0);
	ppd->netdev_rsm_rule = -1;
	ppd->eth_rsm_rule = -1;
	for (int i = 0; i < ARRAY_SIZE(ppd->eth_rsm_pre_rules); i++)
		ppd->eth_rsm_pre_rules[i] = -1;
	ppd->ndev = NULL;
	ppd->ppr = &dd->rsrcs.ppr[hw_pidx];

	return;

bail:
	dd_dev_err(dd, "Congestion Control Agent disabled for port %d\n", port);
}

/*
 * Do initialization for device that is only needed on
 * first detect, not on resets.
 */
static int loadtime_init(struct hfi2_devdata *dd)
{
	return 0;
}

/**
 * init_after_reset - re-initialize after a reset
 * @dd: the hfi2_ib device
 *
 * sanity check at least some of the values after reset, and
 * ensure no receive or transmit (explicitly, in case reset
 * failed
 */
static int init_after_reset(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int i;
	int j;
	struct hfi2_ctxtdata *rcd;
	/*
	 * Ensure chip does no sends or receives, tail updates, or
	 * pioavail updates while we re-initialize.  This is mostly
	 * for the driver data structures, not chip registers.
	 */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->num_rcv_contexts; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			hfi2_rcvctrl(dd,
				     HFI2_RCVCTRL_CTXT_DIS |
					     HFI2_RCVCTRL_INTRAVAIL_DIS |
					     HFI2_RCVCTRL_TAILUPD_DIS,
				     rcd);
			hfi2_rcd_put(rcd);
		}
	}
	for (i = 0; i < dd->num_pports; i++)
		hfi2_pio_send_control(&dd->pport[i], PSC_GLOBAL_DISABLE);
	for (i = 0; i < dd->num_send_contexts; i++)
		hfi2_sc_disable(dd->send_contexts[i].sc);

	return 0;
}

void hfi2_enable_kctxt(struct hfi2_devdata *dd, struct hfi2_ctxtdata *rcd)
{
	u32 rcvmask;

	rcvmask = HFI2_RCVCTRL_CTXT_ENB
		  | HFI2_RCVCTRL_INTRAVAIL_ENB;
	if (HFI2_CAP_KGET_MASK(rcd->flags, DMA_RTAIL))
		rcvmask |= HFI2_RCVCTRL_TAILUPD_ENB;
	else
		rcvmask |= HFI2_RCVCTRL_TAILUPD_DIS;
	if (!HFI2_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR))
		rcvmask |= HFI2_RCVCTRL_ONE_PKT_EGR_ENB;
	if (HFI2_CAP_KGET_MASK(rcd->flags, NODROP_RHQ_FULL))
		rcvmask |= HFI2_RCVCTRL_NO_RHQ_DROP_ENB;
	if (HFI2_CAP_KGET_MASK(rcd->flags, NODROP_EGR_FULL))
		rcvmask |= HFI2_RCVCTRL_NO_EGR_DROP_ENB;
	if (HFI2_CAP_IS_KSET(TID_RDMA))
		rcvmask |= HFI2_RCVCTRL_TIDFLOW_ENB;
	hfi2_rcvctrl(dd, rcvmask, rcd);
	hfi2_sc_enable(rcd->sc);
}

static void enable_chip(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_ctxtdata *rcd;
	u16 i;
	u16 j;

	/* enable PIO send */
	for (i = 0; i < dd->num_pports; i++)
		hfi2_pio_send_control(&dd->pport[i], PSC_GLOBAL_ENABLE);

	/*
	 * Enable kernel hfi2_ctxts' receive and receive interrupt.
	 * Other hfi2_ctxts done as user opens and initializes them.
	 */
	for (i = 0; i < dd->num_pports; i++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[i];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			if (!rcd)
				continue;
			hfi2_enable_kctxt(dd, rcd);
			hfi2_rcd_put(rcd);
		}
	}
}



/**
 * create_workqueues - create per port workqueues
 * @dd: the hfi2_ib device
 */
static int create_workqueues(struct hfi2_devdata *dd)
{
	int pidx;
	struct hfi2_pportdata *ppd;

	dd->hfi2_wq = alloc_workqueue("hfi%d",
				      WQ_SYSFS | WQ_HIGHPRI | WQ_CPU_INTENSIVE |
					      WQ_MEM_RECLAIM | WQ_PERCPU,
				      HFI2_MAX_ACTIVE_GEN_WQ_ENTRIES, dd->unit);
	if (!dd->hfi2_wq)
		goto wq_error;

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		/*
		 * Make the link workqueue single-threaded to enforce
		 * serialization.
		 */
		ppd->link_wq =
			alloc_workqueue("hfi_link_%d_%d",
					WQ_SYSFS | WQ_MEM_RECLAIM | WQ_UNBOUND,
					1, /* max_active */
					dd->unit, pidx);
		if (!ppd->link_wq) {
			pr_err("alloc_workqueue failed for port %d\n",
			       pidx + 1);
			goto wq_error;
		}
	}
	return 0;

wq_error:
	destroy_workqueues(dd);
	return -ENOMEM;
}

/**
 * destroy_workqueues - destroy per port workqueues
 * @dd: the hfi2_ib device
 */
static void destroy_workqueues(struct hfi2_devdata *dd)
{
	int pidx;
	struct hfi2_pportdata *ppd;

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		/*
		 * link_wq may not have been allocated for every port if
		 * create_workqueues() failed partway through, and
		 * destroy_workqueue() does not tolerate a NULL argument.
		 */
		if (ppd->link_wq) {
			destroy_workqueue(ppd->link_wq);
			ppd->link_wq = NULL;
		}
	}
	if (dd->hfi2_wq) {
		destroy_workqueue(dd->hfi2_wq);
		dd->hfi2_wq = NULL;
	}
}

/**
 * enable_general_intr() - Enable the IRQs that will be handled by the
 * general interrupt handler.
 * @dd: valid devdata
 *
 */
static void enable_general_intr(struct hfi2_devdata *dd)
{
	const struct gi_enable_entry *entry = dd->params->gi_enable_table;

	for (; entry->start <= entry->end; entry++)
		hfi2_set_intr_bits(dd, entry->start, entry->end, true);
}

static void wfr_start_port(struct hfi2_pportdata *ppd)
{
	int ret;

	hfi2_init_qsfp_int(ppd);

	/*
	 * start the serdes - must be after interrupts are
	 * enabled so we are notified when the link goes up
	 */
	ret = hfi2_bringup_serdes(ppd);
	if (ret)
		ppd_dev_info(ppd, "Failed to bring up port\n");
}

static void wfr_stop_port(struct hfi2_pportdata *ppd)
{
	/*
	 * Clear SerdesEnable.
	 * We can't count on interrupts since we are stopping.
	 */
	hfi2_quiet_serdes(ppd);
	if (ppd->link_wq)
		flush_workqueue(ppd->link_wq);
}

/**
 * hfi2_init - do the actual initialization sequence on the chip
 * @dd: the hfi2_ib device
 * @reinit: re-initializing, so don't allocate new memory
 *
 * Do the actual initialization sequence on the chip.  This is done
 * both from the init routine called from the PCI infrastructure, and
 * when we reset the chip, or detect that it was reset internally,
 * or it's administratively re-enabled.
 *
 * Memory allocation here and in called routines is only done in
 * the first case (reinit == 0).  We have to be careful, because even
 * without memory allocation, we need to re-write all the chip registers
 * TIDs, etc. after the reset or enable has completed.
 */
int hfi2_init(struct hfi2_devdata *dd, int reinit)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	int ret = 0, pidx, lastfail = 0;
	unsigned long len;
	u16 i;
	struct hfi2_ctxtdata *rcd;
	struct hfi2_pportdata *ppd;
	u32 num_sc;

	/* Set up send low level handlers */
	dd->process_pio_send = hfi2_verbs_send_pio;
	dd->process_dma_send = hfi2_verbs_send_dma;
	dd->pio_inline_send = hfi2_pio_copy;

	if (hfi2_is_ax(dd)) {
		atomic_set(&dd->drop_packet, DROP_PACKET_ON);
		dd->do_drop = true;
	} else {
		atomic_set(&dd->drop_packet, DROP_PACKET_OFF);
		dd->do_drop = false;
	}

	/* make sure the link is not "up" */
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		ppd->linkup = 0;
	}

	if (reinit)
		ret = init_after_reset(dd);
	else
		ret = loadtime_init(dd);
	if (ret)
		goto done;

	/* dd->rcd can be NULL if early initialization failed */
	for (pidx = 0; dd->rcd && pidx < dd->num_pports; pidx++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];

		for (i = 0; i < pr->n_krcv_queues; ++i) {
			u16 ctxt = pr->rcv_context_base + i;
			/*
			 * Set up the (kernel) hfi2_rcvhdr queue and egr TIDs.  If
			 * doing re-init, the simplest way to handle this is
			 * to free existing, and re-allocate.
			 * Need to re-create rest of ctxt 0 hfi2_ctxtdata as well.
			 */
			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			if (!rcd)
				continue;

			lastfail = hfi2_create_rcvhdrq(dd, rcd);
			if (!lastfail)
				lastfail = hfi2_setup_eagerbufs(rcd);
			if (!lastfail)
				lastfail = hfi2_kern_exp_rcv_init(rcd, reinit);
			if (lastfail) {
				dd_dev_err(dd,
					   "failed to allocate kernel ctxt's rcvhdrq and/or egr bufs\n");
				ret = lastfail;
			}
			/* enable IRQ */
			hfi2_rcd_put(rcd);
		}
	}

	/*
	 * TODO: This SI might have only a fraction of the total contexts,
	 * so this is making dd->events much larger than needed. Unfortunately,
	 * uctxt_offset() uses the h/w context number and so all that would
	 * need to change in order to fix this.
	 */
	/* Allocate enough memory for user event notification. */
	len = PAGE_ALIGN(chip_rcv_contexts(dd) * HFI2_MAX_SHARED_CTXTS *
			 sizeof(*dd->events));
	dd->events = vmalloc_user(len);
	if (!dd->events)
		dd_dev_err(dd, "Failed to allocate user events page\n");

	/* Allocate send context events for send-only contexts */
	if (!reinit) {
		num_sc = chip_send_contexts(dd);
		dd->sc_events = vmalloc_user(num_sc * sizeof(*dd->sc_events));
		dd->sc_events_bitmap = bitmap_zalloc(num_sc, GFP_KERNEL);
		/* Initialize send-only context counters */
		for (pidx = 0; pidx < dd->num_pports; ++pidx)
			atomic_set(&dd->pport[pidx].num_send_only_ctxts, 0);
	}
	if (!dd->sc_events || !dd->sc_events_bitmap) {
		dd_dev_err(dd, "Failed to allocate send context events or bitmap\n");
		ret = -ENOMEM;
		goto done;
	}

	/*
	 * Allocate a page for device and port status.
	 * Page will be shared amongst all user processes.
	 */
	dd->status = vmalloc_user(PAGE_SIZE);
	if (!dd->status)
		dd_dev_err(dd, "Failed to allocate dev status page\n");
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		if (dd->status)
			ppd->statusp = &dd->status->ports[pidx];

		hfi2_set_mtu(ppd);
	}

	/* enable chip even if we have an error, so we can debug cause */
	enable_chip(dd);

done:
	/*
	 * Set status even if port serdes is not initialized
	 * so that diags will work.
	 */
	if (dd->status)
		dd->status->dev |= HFI2_STATUS_CHIP_PRESENT |
			HFI2_STATUS_INITTED;
	if (!ret) {
		/* enable all interrupts from the chip */
		enable_general_intr(dd);

		/* chip is OK for user apps; mark it as initialized */
		for (pidx = 0; pidx < dd->num_pports; ++pidx) {
			ppd = dd->pport + pidx;

			dd->params->start_port(ppd);

			/*
			 * Set status even if port serdes is not initialized
			 * so that diags will work.
			 */
			if (ppd->statusp)
				*ppd->statusp |= HFI2_STATUS_CHIP_PRESENT |
							HFI2_STATUS_INITTED;

			/* If this is an Ethernet device then add auxiliary device */
			if (hfi2_is_eth_mode(dd)) {
				if (ppd->ndev)
					cne_remove(ppd->ndev);
				ret = cne_probe(ppd);
				if (ret) {
					dd_dev_err(dd, "Failure probing Ethernet device (%d)\n", ret);
					ret = -ENODEV;
				} else if (reinit) {
					/*
					 * cne_probe recreated ppd->ndev; the
					 * RoCE ib_device is still registered from
					 * the initial probe, so re-point it at the
					 * new netdev (drops the stale tracker,
					 * repopulates the GID table).
					 */
					hfi2_roce_refresh_netdev(dd);
				}
			}
		}
	}

	/* if ret is non-zero, we probably should do some cleanup here... */
	return ret;
}

struct hfi2_devdata *hfi2_lookup(int unit)
{
	/*
	 * Dropping rcu_read_lock() before returning the looked up pointer
	 * provides no real protection against a concurrent xa_erase() plus
	 * free of the hfi2_devdata (the caller is not holding a reference).
	 * hfi2_devdata lifetime is instead guaranteed by the caller only
	 * ever looking up units while driver-wide teardown is serialized
	 * against hfi2_mutex, matching the reference hfi1 implementation.
	 */
	return xa_load(&hfi2_dev_table, unit);
}

/*
 * Stop the timers during unit shutdown, or after an error late
 * in initialization.
 */
static void stop_timers(struct hfi2_devdata *dd)
{
	struct hfi2_pportdata *ppd;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;
		if (ppd->led_override_timer.function) {
			timer_delete_sync(&ppd->led_override_timer);
			atomic_set(&ppd->led_override_timer_active, 0);
		}
		if (ppd->ibport_data.rvp.trap_timer.function)
			timer_delete_sync(&ppd->ibport_data.rvp.trap_timer);
	}
}

/**
 * shutdown_device - shut down a device
 * @dd: the hfi2_ib device
 *
 * This is called to make the device quiet when we are about to
 * unload the driver, and also when the device is administratively
 * disabled.   It does not free any data structures.
 * Everything it does has to be setup again by hfi2_init(dd, 1)
 */
static void shutdown_device(struct hfi2_devdata *dd)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_pportdata *ppd;
	struct hfi2_ctxtdata *rcd;
	unsigned int pidx;
	int i;

	if (dd->flags & HFI2_SHUTDOWN)
		return;
	dd->flags |= HFI2_SHUTDOWN;

	if (dd->bulksvc)
		hfi2_bulksvc_teardown(dd);

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		ppd->linkup = 0;
		if (ppd->statusp)
			*ppd->statusp &=
				~(HFI2_STATUS_IB_CONF | HFI2_STATUS_IB_READY);
	}
	dd->flags &= ~HFI2_INITTED;

	/*
	 * Drop all traps.  After this point, there should be no more cport
	 * handlers that depend on driver state.
	 */
	clearall_cport_trap(dd);

	/* disable all interrupts except cport response */
	if (dd->params->chip_type == CHIP_WFR) {
		/* WFR has no cport */
		hfi2_set_intr_bits(dd, 0, dd->params->is_last_source, false);
		hfi2_msix_shut_down_interrupts(dd, false);
	} else {
		/* mask all but the cport interrupt source */
		hfi2_set_intr_bits(dd, 0, dd->params->is_cport_int - 1,
				   false);
		hfi2_set_intr_bits(dd, dd->params->is_cport_int + 1,
				   dd->params->is_last_source, false);
		hfi2_msix_shut_down_interrupts(dd, true);
	}

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];

		ppd = dd->pport + pidx;
		for (i = 0; i < pr->num_rcv_contexts; i++) {
			u16 ctxt = pr->rcv_context_base + i;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			hfi2_rcvctrl(dd,
				     HFI2_RCVCTRL_TAILUPD_DIS |
					     HFI2_RCVCTRL_CTXT_DIS |
					     HFI2_RCVCTRL_INTRAVAIL_DIS |
					     HFI2_RCVCTRL_PKEY_DIS |
					     HFI2_RCVCTRL_ONE_PKT_EGR_DIS,
				     rcd);
			hfi2_rcd_put(rcd);
		}
	}
	/*
	 * Gracefully stop all sends allowing any in progress to
	 * trickle out first.
	 */
	for (i = 0; i < dd->num_send_contexts; i++)
		hfi2_sc_flush(dd->send_contexts[i].sc);

	/*
	 * Enough for anything that's going to trickle out to have actually
	 * done so.
	 */
	udelay(20);

	/* disable all contexts */
	for (i = 0; i < dd->num_send_contexts; i++)
		hfi2_sc_disable(dd->send_contexts[i].sc);

	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		ppd = dd->pport + pidx;

		/* disable the send device */
		hfi2_pio_send_control(ppd, PSC_GLOBAL_DISABLE);

		dd->params->shutdown_led_override(ppd);

		dd->params->stop_port(ppd);

		/* Remove any Ethernet device. */
		if (ppd->ndev) {
			cne_remove(ppd->ndev);
			ppd->ndev = NULL;
		}
	}
	if (dd->hfi2_wq)
		flush_workqueue(dd->hfi2_wq);
	hfi2_sdma_exit(dd);
}

static void hfi2_free_egrbuf(struct hfi2_devdata *dd,
			     struct eager_buffer *buf)
{
	if (!buf->addr)
		return;

	dma_free_coherent(&dd->pcidev->dev, buf->len, buf->addr, buf->dma);
	buf->addr = NULL;
	buf->dma = 0;
	buf->len = 0;
}
/*
 * SRIOV has been disabled. Do any cleanup not handled by
 * VF remove_one() calls.
 */
void hfi2_pf0_cleanup(struct hfi2_devdata *dd)
{
	hfi2_restore_qpmap_table(dd);
	/* TODO: other cleanup */
}

/**
 * hfi2_free_ctxtdata - free a context's allocated data
 * @dd: the hfi2_ib device
 * @rcd: the ctxtdata structure
 *
 * free up any allocated data for a context
 * It should never change any chip state, or global driver state.
 */
void hfi2_free_ctxtdata(struct hfi2_devdata *dd, struct hfi2_ctxtdata *rcd)
{
	u32 e;

	if (!rcd)
		return;

	if (rcd->rcvhdrq) {
		dma_free_coherent(&dd->pcidev->dev, rcvhdrq_size(rcd),
				  rcd->rcvhdrq, rcd->rcvhdrq_dma);
		rcd->rcvhdrq = NULL;
		if (hfi2_rcvhdrtail_kvaddr(rcd)) {
			dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
					  (void *)hfi2_rcvhdrtail_kvaddr(rcd),
					  rcd->rcvhdrqtailaddr_dma);
			rcd->rcvhdrtail_kvaddr = NULL;
		}
	}
	if (rcd->rheq) {
		dma_free_coherent(&dd->pcidev->dev, rheq_size(rcd), rcd->rheq,
				  rcd->rheq_dma);
		rcd->rheq = NULL;
	}

	/* all the RcvArray entries should have been cleared by now */
	kfree(rcd->egrbufs.rcvtids);
	rcd->egrbufs.rcvtids = NULL;

	for (e = 0; e < rcd->egrbufs.numbufs; e++)
		hfi2_free_egrbuf(dd, &rcd->egrbufs.buffers[e]);
	kfree(rcd->egrbufs.buffers);
	rcd->egrbufs.alloced = 0;
	rcd->egrbufs.numbufs = 0;
	rcd->egrbufs.buffers = NULL;

	hfi2_sc_free(rcd->sc);
	rcd->sc = NULL;

	vfree(rcd->subctxt_uregbase);
	vfree(rcd->subctxt_rcvegrbuf);
	vfree(rcd->subctxt_rcvhdr_base);
	kfree(rcd->opstats);

	rcd->subctxt_uregbase = NULL;
	rcd->subctxt_rcvegrbuf = NULL;
	rcd->subctxt_rcvhdr_base = NULL;
	rcd->opstats = NULL;
}

/*
 * Release our hold on the shared asic data.  If we are the last one,
 * return the structure to be finalized outside the lock.  Must be
 * holding hfi2_dev_table lock.
 */
static struct hfi2_asic_data *release_asic_data(struct hfi2_devdata *dd)
{
	struct hfi2_asic_data *ad;
	int other;

	if (!dd->asic_data)
		return NULL;
	dd->asic_data->dds[dd->hfi2_id] = NULL;
	other = dd->hfi2_id ? 0 : 1;
	ad = dd->asic_data;
	dd->asic_data = NULL;
	/* return NULL if the other dd still has a link */
	return ad->dds[other] ? NULL : ad;
}

static void finalize_asic_data(struct hfi2_devdata *dd,
			       struct hfi2_asic_data *ad)
{
	hfi2_clean_up_i2c(dd, ad);
	kfree(ad);
}

/**
 * hfi2_free_devdata - cleans up and frees per-unit data structure
 * @dd: pointer to a valid devdata structure
 *
 * It cleans up and frees all data structures set up by
 * hfi2_alloc_devdata().
 */
static void hfi2_free_devdata(struct hfi2_devdata *dd)
{
	struct hfi2_asic_data *ad;
	unsigned long flags;

	if (!dd)
		return;

	xa_lock_irqsave(&hfi2_dev_table, flags);
	__xa_erase(&hfi2_dev_table, dd->unit);
	ad = release_asic_data(dd);
	xa_unlock_irqrestore(&hfi2_dev_table, flags);

	finalize_asic_data(dd, ad);
	hfi2_free_platform_config(dd);
	rcu_barrier(); /* wait for rcu callbacks to complete */
	free_percpu(dd->int_counter);
	free_percpu(dd->rcv_limit);
	free_percpu(dd->send_schedule);
	free_percpu(dd->pbc_test);
	free_percpu(dd->tx_opstats);
	dd->int_counter = NULL;
	dd->rcv_limit = NULL;
	dd->send_schedule = NULL;
	dd->pbc_test = NULL;
	dd->tx_opstats = NULL;
	if (dd->rcvhdrtail_dummy_kvaddr)
		dma_free_coherent(&dd->pcidev->dev, sizeof(u64),
				  (void *)dd->rcvhdrtail_dummy_kvaddr,
				  dd->rcvhdrtail_dummy_dma);
	dd->rcvhdrtail_dummy_kvaddr = NULL;
	hfi2_sdma_clean(dd);
	hfi2_sriov_free_cfg(dd);	/* needs WQs on VFs */
	hfi2_bulksvc_teardown(dd);
	hfi2_roce_pasid_map_exit(dd);
	destroy_workqueues(dd);
	/* dd is freed by the time this returns: */
	rvt_dealloc_device(&dd->verbs_dev.rdi);
}

static u64 hfi2_pbc_test_bit_get(struct hfi2_devdata *dd,
				 const struct chip_params *params)
{
	if (hfi2_is_eth_mode(dd))
		return 0;

	switch (params->chip_type) {
	case CHIP_JKR:
	case CHIP_CYR:
		return PBC_TEST_EBP;
	case CHIP_WFR:
#ifdef CONFIG_FAULT_INJECTION
		return PBC_TEST_EBP;
#endif
		fallthrough;
	default:
		return HFI2_CAP_IS_KSET(NO_INTEGRITY) ? PBC_TEST_EBP : 0;
	}
}


/**
 * hfi2_alloc_devdata - Allocate our primary per-unit data structure.
 * @pdev: Valid PCI device
 * @params: chip-specific parameters
 *
 * Must be done via verbs allocator, because the verbs cleanup process
 * both does cleanup and free of the data structure.
 */
static struct hfi2_devdata *hfi2_alloc_devdata(struct pci_dev *pdev,
					       const struct chip_params *params)
{
	struct hfi2_devdata *dd;
	size_t extra;
	int ret, nports;

	nports = params->num_ports;
	extra = nports * sizeof(struct hfi2_pportdata);
	dd = (struct hfi2_devdata *)rvt_alloc_device(sizeof(*dd) + extra,
						     nports);
	if (!dd)
		return ERR_PTR(-ENOMEM);
	dd->params = params;
	dd->num_pports = nports;
	dd->pport = (struct hfi2_pportdata *)(dd + 1);
	dd->pcidev = pdev;
	dd->pbc_test_bit = hfi2_pbc_test_bit_get(dd, params);
	hfi2_roce_pasid_map_init(dd);
	dd->bulksvc_rsm_rule = -1;
	/*
	 * Check for PCI device being a VF in SRIOV.
	 * The VFs do not have a Power Management capability block.
	 */
	dd->is_vf = (params->chip_type != CHIP_WFR && !pdev->pm_cap);
	dd->is_sriov = (dd->is_vf || hfi2_sriov_is_enabled());
	dd->loopback_enabled = dd->is_sriov;
#if defined(CONFIG_X86)
	dd->is_vm = boot_cpu_has(X86_FEATURE_HYPERVISOR);
#endif
#ifdef PDEV_SRIOV_DEBUG
	dev_warn(&pdev->dev, "is_vm=%d is_vf=%d is_physfn=%d is_virtfn=%d physfn=%p\n",
		dd->is_vm, dd->is_vf, pdev->is_physfn, pdev->is_virtfn, pdev->physfn);
#endif
	atomic_set(&dd->vf2pf_seq, 0);

	pci_set_drvdata(pdev, dd);

	/*
	 * Must set DMA mask for device before any dma_map*() or
	 * dma_alloc*() calls referring to pdev->dev. Otherwise
	 * those calls may return DMA addresses that are
	 * incompatible with the HFI.
	 */
	ret = dma_set_mask_and_coherent(&pdev->dev,
					DMA_BIT_MASK(params->dma_mask_bits));
	if (ret) {
		dd_dev_warn(
			dd,
			"Failed to set %u-bit DMA mask ret %d; setting 32-bit DMA mask\n",
			params->dma_mask_bits, ret);
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret) {
			dd_dev_err(dd, "Unable to set DMA mask: %d\n", ret);
			goto bail;
		}
	}
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(params->dma_mask_bits));
	if (ret) {
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		if (ret) {
			dd_dev_err(dd, "Unable to set DMA mask: %d\n", ret);
			goto bail;
		}
	}
	dd->cport_vec = -1; /* initial bad value */
	ret = xa_alloc_irq(&hfi2_dev_table, &dd->unit, dd, xa_limit_32b,
			   GFP_KERNEL);
	if (ret < 0) {
		dev_err(&pdev->dev, "Could not allocate unit ID: error %d\n",
			-ret);
		rvt_dealloc_device(&dd->verbs_dev.rdi);
		return ERR_PTR(ret);
	}
	dev_set_name(&dd->verbs_dev.rdi.ibdev.dev, "%s_%d", "hfi2", dd->unit);
	strscpy(dd->verbs_dev.rdi.ibdev.name,
		dev_name(&dd->verbs_dev.rdi.ibdev.dev), IB_DEVICE_NAME_MAX);
	/*
	 * If the BIOS does not have the NUMA node information set, select
	 * NUMA 0 so we get consistent performance.
	 */
	dd->node = pcibus_to_node(pdev->bus);
	if (dd->node == NUMA_NO_NODE) {
		dd_dev_err(
			dd,
			"Invalid PCI NUMA node. Performance may be affected\n");
		dd->node = 0;
	}

	/*
	 * Initialize all locks for the device. This needs to be as early as
	 * possible so locks are usable.
	 */
	spin_lock_init(&dd->sc_lock);
	spin_lock_init(&dd->sendctrl_lock);
	spin_lock_init(&dd->rcvctrl_lock);
	spin_lock_init(&dd->uctxt_lock);
	spin_lock_init(&dd->sc_init_lock);
	spin_lock_init(&dd->dc8051_memlock);
	spin_lock_init(&dd->pio_map_lock);
	mutex_init(&dd->cport_lock);
	mutex_init(&dd->dc8051_lock);
	init_waitqueue_head(&dd->event_queue);
	spin_lock_init(&dd->irq_src_lock);
	INIT_WORK(&dd->freeze_work, hfi2_handle_freeze);

	dd->int_counter = alloc_percpu(u64);
	if (!dd->int_counter) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->rcv_limit = alloc_percpu(u64);
	if (!dd->rcv_limit) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->send_schedule = alloc_percpu(u64);
	if (!dd->send_schedule) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->pbc_test = __alloc_percpu(HFI2_PBC_TEST_NCNTR * sizeof(u64),
				      __alignof__(u64));
	if (!dd->pbc_test) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->tx_opstats = alloc_percpu(struct hfi2_opcode_stats_perctx);
	if (!dd->tx_opstats) {
		ret = -ENOMEM;
		goto bail;
	}

	dd->rcv_hdr_ent_size = hfi2_hdrq_entsize ? hfi2_hdrq_entsize :
			       params->rcv_hdr_ent_size_max;

	/* allocate dummy tail memory for all receive contexts */
	dd->rcvhdrtail_dummy_kvaddr =
		dma_alloc_coherent(&dd->pcidev->dev, sizeof(u64),
				   &dd->rcvhdrtail_dummy_dma, GFP_KERNEL);
	if (!dd->rcvhdrtail_dummy_kvaddr) {
		ret = -ENOMEM;
		goto bail;
	}


	ret = create_workqueues(dd);
	if (ret)
		goto bail;
	/* If we are going to be loaning resources, find out which ones */
	dd->verbs_dev.rdi.use_bulksvc = false;
	if (use_bulksvc) {
		if (hfi2_max_sges > 255) {
			pr_err("When using bulksvc, only 255 sges may be used\n");
			goto bail;
		}
		if (dd->params->chip_type == CHIP_WFR)
			dd_dev_dbg(dd, "bulksvc not supported on WFR\n");
		else {
			ret = hfi2_bulksvc_init(dd);
			if (ret)
				goto bail;
			dd->loopback_enabled = true;
		}
	}
	return dd;

bail:
	hfi2_free_devdata(dd);
	return ERR_PTR(ret);
}

/*
 * Called from freeze mode handlers, and from PCI error
 * reporting code.  Should be paranoid about state of
 * system and data structures.
 */
void hfi2_disable_after_error(struct hfi2_devdata *dd)
{
	if (dd->flags & HFI2_INITTED) {
		u32 pidx;

		dd->flags &= ~HFI2_INITTED;
		if (dd->pport)
			for (pidx = 0; pidx < dd->num_pports; ++pidx) {
				struct hfi2_pportdata *ppd;

				ppd = dd->pport + pidx;
				if (dd->flags & HFI2_PRESENT)
					hfi2_set_link_state(ppd,
							    HLS_DN_DISABLE);

				if (ppd->statusp)
					*ppd->statusp &= ~HFI2_STATUS_IB_READY;
			}
	}

	/*
	 * Mark as having had an error for driver, and also
	 * for /sys and status word mapped to user programs.
	 * This marks unit as not usable, until reset.
	 */
	if (dd->status)
		dd->status->dev |= HFI2_STATUS_HWERROR;
}

static void remove_one(struct pci_dev *);
static int init_one(struct pci_dev *, const struct pci_device_id *);
static void shutdown_one(struct pci_dev *);

#define DRIVER_LOAD_MSG "Cornelis " DRIVER_NAME " loaded: "
#define PFX DRIVER_NAME ": "

const struct pci_device_id hfi2_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CORNELIS, PCI_DEVICE_ID_CORNELIS_CN5000) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CORNELIS, PCI_DEVICE_ID_CORNELIS_CN6000) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, hfi2_pci_tbl);

static struct pci_driver hfi2_pci_driver = {
	.name = DRIVER_NAME,
	.probe = init_one,
	.remove = remove_one,
	.shutdown = shutdown_one,
	.id_table = hfi2_pci_tbl,
	.err_handler = &hfi2_pci_err_handler,
	.sriov_configure = hfi2_sriov_configure,
	.sriov_get_vf_total_msix = hfi2_sriov_get_vf_total_msix,
};

static void __init compute_krcvqs(void)
{
	int i;

	for (i = 0; i < hfi2_krcvqsset; i++)
		hfi2_n_krcvqs += hfi2_krcvqs[i];
}

/*
 * Do all the generic driver unit- and chip-independent memory
 * allocation and initialization.
 */
static int __init hfi2_mod_init(void)
{
	int ret;

	hfi2_register_system_pinning_interface();
	hfi2_register_system_tid_ops();
	hfi2_tid_dmabuf_init();
	hfi2_pin_dmabuf_init();

	/* validate max MTU before any devices start */
	if (!valid_opa_max_mtu(hfi2_max_mtu)) {
		pr_err("Invalid max_mtu 0x%x, using 0x%x instead\n",
		       hfi2_max_mtu, HFI2_DEFAULT_MAX_MTU);
		hfi2_max_mtu = HFI2_DEFAULT_MAX_MTU;
	}
	/* valid CUs run from 1-128 in powers of 2 */
	if (hfi2_cu > 128 || !is_power_of_2(hfi2_cu))
		hfi2_cu = 1;
	/* valid credit return threshold is 0-100, variable is unsigned */
	if (hfi2_user_credit_return_threshold > 100)
		hfi2_user_credit_return_threshold = 100;

	compute_krcvqs();
	/*
	 * sanitize receive interrupt count, time must wait until after
	 * the hardware type is known
	 */
	if (hfi2_rcv_intr_count > RCV_HDR_HEAD_COUNTER_MASK)
		hfi2_rcv_intr_count = RCV_HDR_HEAD_COUNTER_MASK;
	/* reject invalid combinations */
	if (hfi2_rcv_intr_count == 0 && hfi2_rcv_intr_timeout == 0) {
		pr_err("Invalid mode: both receive interrupt count and available timeout are zero - setting interrupt count to 1\n");
		hfi2_rcv_intr_count = 1;
	}
	if (hfi2_rcv_intr_count > 1 && hfi2_rcv_intr_timeout == 0) {
		/*
		 * Avoid indefinite packet delivery by requiring a timeout
		 * if count is > 1.
		 */
		pr_err("Invalid mode: receive interrupt count greater than 1 and available timeout is zero - setting available timeout to 1\n");
		hfi2_rcv_intr_timeout = 1;
	}
	if (hfi2_rcv_intr_dynamic &&
	    !(hfi2_rcv_intr_count > 1 && hfi2_rcv_intr_timeout > 0)) {
		/*
		 * The dynamic algorithm expects a non-zero timeout
		 * and a count > 1.
		 */
		pr_err("Invalid mode: dynamic receive interrupt mitigation with invalid count and timeout - turning dynamic off\n");
		hfi2_rcv_intr_dynamic = 0;
	}

	/* sanitize link CRC options */
	hfi2_link_crc_mask &= SUPPORTED_CRCS;

	/* The PIO send path can wedge a QP, more readily under use_bulksvc; warn unless disabled. */
	if (use_bulksvc && hfi2_piothreshold)
		pr_warn("use_bulksvc with hfi2_piothreshold=%u: PIO send path may wedge a QP; hfi2_piothreshold=0 is recommended\n",
			hfi2_piothreshold);

	ret = hfi2_opfn_init();
	if (ret < 0) {
		pr_err("Failed to allocate opfn_wq");
		goto bail_opfn;
	}

	ret = hfi2_rvt_init();
	if (ret)
		goto bail_rvt;

	/*
	 * These must be called before the driver is registered with
	 * the PCI subsystem.
	 */
	hfi2_dbg_init();
	/*
	 * This causes devices to be probed, so any initialization
	 * that must happen before that must be above this point.
	 */
	ret = pci_register_driver(&hfi2_pci_driver);
	if (ret < 0) {
		pr_err("Unable to register driver: error %d\n", -ret);
		goto bail_dev;
	}

	return 0;
bail_dev:
	hfi2_dbg_exit();
	hfi2_rvt_cleanup();
bail_rvt:
	hfi2_opfn_exit();
bail_opfn:
	hfi2_deregister_system_tid_ops();
	hfi2_deregister_system_pinning_interface();
	hfi2_pin_dmabuf_free();
	hfi2_tid_dmabuf_free();

	return ret;
}

MODULE_DESCRIPTION("Cornelis Networks HFI2 driver");
MODULE_LICENSE("Dual BSD/GPL");

module_init(hfi2_mod_init);

/*
 * Do the non-unit driver cleanup, memory free, etc. at unload.
 */
static void __exit hfi2_mod_cleanup(void)
{
	pci_unregister_driver(&hfi2_pci_driver);
	hfi2_rvt_cleanup();
	hfi2_opfn_exit();
	hfi2_dbg_exit();

	WARN_ON(!xa_empty(&hfi2_dev_table));
	hfi2_dispose_firmware(); /* asymmetric with obtain_firmware() */

	hfi2_deregister_system_tid_ops();
	hfi2_deregister_system_pinning_interface();
	hfi2_pin_dmabuf_free();
	hfi2_tid_dmabuf_free();
}

module_exit(hfi2_mod_cleanup);

/* this can only be called after a successful initialization */
static void cleanup_device_data(struct hfi2_devdata *dd)
{
	int ctxt;
	int pidx;

	/* users can't do anything more with chip */
	for (pidx = 0; pidx < dd->num_pports; ++pidx) {
		struct hfi2_pportdata *ppd = &dd->pport[pidx];
		struct cc_state *cc_state;
		int i;

		if (ppd->statusp)
			*ppd->statusp &= ~HFI2_STATUS_CHIP_PRESENT;

		for (i = 0; i < OPA_MAX_SLS; i++)
			hrtimer_cancel(&ppd->cca_timer[i].hrtimer);

		spin_lock(&ppd->cc_state_lock);
		cc_state = get_cc_state_protected(ppd);
		RCU_INIT_POINTER(ppd->cc_state, NULL);
		spin_unlock(&ppd->cc_state_lock);

		if (cc_state)
			kfree_rcu(cc_state, rcu);
	}

	hfi2_free_credit_return(dd);

	/*
	 * Free any receive resources still in use (usually just kernel
	 * contexts) at unload.
	 */
	for (ctxt = 0; dd->rcd && ctxt < dd->num_rcd; ctxt++) {
		struct hfi2_ctxtdata *rcd = dd->rcd[ctxt];

		if (rcd) {
			hfi2_free_ctxt_rcv_groups(rcd);
			hfi2_free_ctxt(rcd);
		}
	}

	kfree(dd->rcd);
	dd->rcd = NULL;
	dd->num_rcd = 0;

	hfi2_free_pio_map(dd);
	/* must follow rcv context free - need to remove rcv's hooks */
	if (dd->send_contexts) {
		for (ctxt = 0; ctxt < dd->num_send_contexts; ctxt++)
			hfi2_sc_free(dd->send_contexts[ctxt].sc);
	}
	dd->num_send_contexts = 0;
	kfree(dd->send_contexts);
	dd->send_contexts = NULL;
	kfree(dd->hw_to_sw);
	dd->hw_to_sw = NULL;
	/* free netdev data */
	hfi2_free_rx(dd);
	kfree(dd->boardname);
	vfree(dd->events);
	vfree(dd->status);
	vfree(dd->sc_events);
	bitmap_free(dd->sc_events_bitmap);

	vf2pf_deinit(dd); /* still requires CSR access/permissions */

	/* finalize the cport - CSR perms revoked on PF0 */
	stop_cport(dd);
	/* release interrupts */
	hfi2_msix_clean_up_interrupts(dd);

	/* CSR reads and writes are invalid after this call */
	hfi2_pcie_ddcleanup(dd);
}

/*
 * Clean up on unit shutdown, or error during unit load after
 * successful initialization.
 */
static void postinit_cleanup(struct hfi2_devdata *dd)
{
	hfi2_start_cleanup(dd);
	hfi2_comp_vectors_clean_up(dd);
	hfi2_release_rsm_rules(dd);

	cleanup_device_data(dd);

	hfi2_pcie_cleanup(dd->pcidev);
}

static int init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret = 0, pidx;
	struct hfi2_devdata *dd;
	const struct chip_params *params;

#ifdef CONFIG_HFI_L8SIM
	if (!(pdev->bus->bus_flags & PCI_BUS_FLAGS_SIMULATED)) {
		dev_warn(&pdev->dev, "Ignoring real hardware on simulator driver\n");
		return -ENODEV;
	}
#endif
	/* VF in host driver - leave for KVM */
	if (pdev->is_virtfn) {
		/*
		 * It is theoretically possible for the host driver to claim
		 * a VF, so the decision whether to claim or not is made by
		 * hfi2_sriov_init(). Returning ENODEV does not fail SRIOV init.
		 */
		ret = hfi2_sriov_init(pdev); /* may do nothing */
		if (ret)
			return ret; /* do not claim device */
	}

#ifdef CONFIG_HFI_L8SIM
	if (!(pdev->bus->bus_flags & PCI_BUS_FLAGS_SIMULATED)) {
		dev_warn(&pdev->dev,
			 "Ignoring real hardware on simulator driver\n");
		return -ENODEV;
	}
#endif
	/* First, lock the non-writable module parameters */
	HFI2_CAP_LOCK();

	/* Validate dev ids */
	if (ent->vendor == PCI_VENDOR_ID_INTEL &&
	    (ent->device == PCI_DEVICE_ID_INTEL0 ||
	     ent->device == PCI_DEVICE_ID_INTEL1)) {
		params = &wfr_params;
	} else if (ent->vendor == PCI_VENDOR_ID_CORNELIS &&
		   ent->device == PCI_DEVICE_ID_CORNELIS_CN5000) {
		params = &jkr_params;
	} else if (ent->vendor == PCI_VENDOR_ID_CORNELIS &&
		   ent->device == PCI_DEVICE_ID_CORNELIS_CN6000) {
		params = &cyr_params;
	} else {
		dev_err(&pdev->dev, "Failing on unknown device %04x:%04x\n",
			ent->vendor, ent->device);
		return -ENODEV;
	}

	if (pdev->is_virtfn ||
	    (params->chip_type == CHIP_JKR && !pdev->pm_cap))
		return -ENODEV;

	if (pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV) &&
	    pci_num_vf(pdev))
		return -EBUSY;

	/* verify arrays are large enough */
	if (params->num_int_csrs > LARGEST_NUM_INT_CSRS ||
	    params->num_ports > LARGEST_NUM_PORTS ||
	    params->pkey_table_size > MAX_PKEY_VALUES) {
		dev_err(&pdev->dev, "Source arrays are compiled too small\n");
		return -EINVAL;
	}

	/* Validate some global module parameters */
	ret = hfi2_validate_rcvhdrcnt(pdev, rcvhdrcnt);
	if (ret)
		return ret;

	/* use the encoding function as a sanitization check */
	if (!hfi2_encode_rcv_header_entry_size(hfi2_hdrq_entsize)) {
		dev_err(&pdev->dev, "Invalid HdrQ Entry size %u\n",
			hfi2_hdrq_entsize);
		return -EINVAL;
	}

	/* The receive eager buffer size must be set before the receive
	 * contexts are created.
	 *
	 * Set the eager buffer size.  Validate that it falls in a range
	 * allowed by the hardware - all powers of 2 between the min and
	 * max.  The maximum valid MTU is within the eager buffer range
	 * so we do not need to cap the max_mtu by an eager buffer size
	 * setting.
	 */
	if (eager_buffer_size) {
		if (!is_power_of_2(eager_buffer_size))
			eager_buffer_size =
				roundup_pow_of_two(eager_buffer_size);
		eager_buffer_size = clamp_val(eager_buffer_size,
					      MIN_EAGER_BUFFER * 8,
					      MAX_EAGER_BUFFER_TOTAL);
		pci_info(pdev, "Eager buffer size %u\n", eager_buffer_size);
	} else {
		dev_err(&pdev->dev, "Invalid Eager buffer size of 0\n");
		return -EINVAL;
	}

	/* restrict value of hfi2_rcvarr_split */
	hfi2_rcvarr_split = clamp_val(hfi2_rcvarr_split, 0, 100);

	ret = hfi2_pcie_init(pdev);
	if (ret)
		return ret;
	if (params->chip_type == CHIP_JKR)
		mask_aer_unsupported_request(pdev);

	/* Allocate the dd so we can get to work */
	dd = hfi2_alloc_devdata(pdev, params);
	if (IS_ERR(dd)) {
		ret = PTR_ERR(dd);
		goto pcie_cleanup;
	}

	/*
	 * Do device-specific initialization.  If hfi2_init_dd() fails, it
	 * cleans up after itself.
	 */
	ret = hfi2_init_dd(dd);
	if (ret)
		goto destroy_wqs; /* error already printed */

	/* do the generic initialization */
	ret = hfi2_init(dd, 0);
	if (ret)
		goto teardown;

	ret = hfi2_mad_init(dd);
	if (ret)
		goto free_mad;

	ret = pldm_ua_init(dd);
	if (ret)
		goto free_mad;

	/*
	 * The IB device is registered (making it visible to userspace and
	 * other in-kernel ULPs) before HFI2_INITTED is set and before
	 * hfi2_sdma_start() below.  This matches the ordering used by the
	 * hfi1 reference driver; verbs/uverbs call paths are expected to
	 * tolerate encountering the device in this transitional state
	 * (e.g. via internal readiness checks), so registration is not
	 * reordered here to avoid disturbing well-tested error/cleanup
	 * unwind ordering in this function.
	 */
	ret = hfi2_register_ib_device(dd);
	if (ret)
		goto free_mad;

	ret = hfi2_init_cport_trap128(dd); /* after IB device register */
	if (ret)
		goto free_ib_dev;

	ret = hfi2_devlink_register(dd);
	if (ret)
		goto free_ib_dev;

	/*
	 * Now ready for use.  this should be cleared whenever we
	 * detect a reset, or initiate one.
	 */
	dd->flags |= HFI2_INITTED;
	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_pportdata *ppd = dd->pport + pidx;

		if (ppd->host_link_state == HLS_UP_ACTIVE)
			hfi2_go_port_active(ppd);
	}

	/* create debugfs files after init and ib register */
	hfi2_dbg_ibdev_init(&dd->verbs_dev);

	if (dd->bulksvc) {
		u32 last = dd->rsrcs.last_sdma_engine;
		u32 to_borrow = dd->bulksvc->prereqs.num_sdma;

		for (u32 i = last - to_borrow; i < last; i++) {
			struct sdma_engine *sde = &dd->per_sdma[i];

			sde->check_generation = SDMA_CHECK_GEN_DISABLE;
		}
	}

	hfi2_sdma_start(dd);

	if (dd->bulksvc) {
		ret = hfi2_bulksvc_loan_resources(dd);
		if (ret) {
			hfi2_dbg_ibdev_exit(&dd->verbs_dev);
			hfi2_devlink_unregister(dd);
			goto free_ib_dev;
		}
	}

	hfi2_init_cport_overtemp(dd);
	hfi2_sriov_auto_conf(dd);
	vf2pf_ready(dd);

	return 0;

free_ib_dev:
	hfi2_unregister_ib_device(dd);
free_mad:
	pldm_ua_exit(dd);
	hfi2_mad_deinit(dd);
	clearall_cport_trap(dd);
	stop_cport(dd);
	goto cport_stopped;
teardown:
	stop_cport(dd);
cport_stopped:
	hfi2_msix_clean_up_interrupts(dd);
	stop_timers(dd);
	for (pidx = 0; pidx < dd->num_pports; ++pidx)
		dd->params->stop_port(dd->pport + pidx);

	hfi2_sdma_exit(dd);
	postinit_cleanup(dd);

destroy_wqs:
	destroy_workqueues(dd);
free_dd:
	hfi2_free_devdata(dd);
	return ret;

pcie_cleanup:
	hfi2_pcie_cleanup(pdev);
	goto free_dd;
}

static void wait_for_clients(struct hfi2_devdata *dd)
{
	/*
	 * Remove the device init value and complete the device if there is
	 * no clients or wait for active clients to finish.
	 */
	if (refcount_dec_and_test(&dd->user_refcount))
		complete(&dd->user_comp);

	wait_for_completion(&dd->user_comp);
}

/*
 * This is called for rmmod or other driver-device unbinds.
 * (and now by shutdown_one() if not WFR)
 */
static void remove_one(struct pci_dev *pdev)
{
	struct hfi2_devdata *dd = pci_get_drvdata(pdev);

	if (pdev->is_virtfn) {
		/*
		 * Should only reach here if the VF was claimed by the driver,
		 * however, this cannot destroy device functionality.
		 */
		hfi2_sriov_remove(pdev); /* TODO: does this need to be last? */
	}


	/*
	 * If VFs are still active, must shut them down now,
	 * before PF0 becomes unusable.
	 */
	if (pdev->is_physfn)
		hfi2_sriov_disable(dd->pcidev);
	/*
	 * Reorder relative to the pre-fix baseline:  neither touches debugfs.  hfi2_dbg_ibdev_exit()'s
	 * debugfs_remove_recursive() is self-contained and synchronizes
	 * with in-flight readers on its own, regardless of when it runs
	 * relative to cdev cleanup.  So the two subsystems have no
	 * ordering dependency on each other, and it is safe to run this
	 * reorder unconditionally rather than gating it on
	 * HFI2_BULKSVC_ULP_STUBS to match the old order only in the
	 * HFI2_BULKSVC_ULP_STUBS=0 case.  Keeping a single, unconditional
	 * order here is intentional: gating this reorder on the flag too
	 * would give remove_one() two different code shapes depending on
	 * HFI2_BULKSVC_ULP_STUBS, doubling the paths that need testing and
	 * reasoning about.  With this reorder unconditional, the exact
	 * same remove_one() shape runs regardless of the flag; only the
	 * ULP-specific "if (dd->bulksvc) { ... }" block below remains
	 * gated on HFI2_BULKSVC_ULP_STUBS.
	 */
	/* wait for existing user space clients to finish */
	wait_for_clients(dd);

#if HFI2_BULKSVC_ULP_STUBS
	if (dd->bulksvc) {
		/*
		 * Stop the event thread before freeing ULP state.  The ULP pingpong
		 * files must be removed while their debugfs parent still exists:
		 * hfi2_dbg_ibdev_exit() recursively removes that parent, and leaving
		 * the individual removals for hfi2_bulksvc_teardown() would remove
		 * the same dentries a second time and can hang the host during
		 * rmmod hfi2.
		 *
		 * This call is intentionally redundant with the unconditional
		 * hfi2_bulksvc_quiesce_thread(dd) call that already happens later
		 * in this same remove_one() chain, via hfi2_unregister_ib_device()
		 * -> hfi2_unregister_roce_ib_device() in roce_main.c for the
		 * Ethernet/RoCE path this driver uses (or directly inside
		 * hfi2_unregister_ib_device() in verbs.c for the OPA path).  So
		 * when HFI2_BULKSVC_ULP_STUBS=0 and this whole block is compiled out,
		 * the bulksvc thread is still quiesced correctly by that later,
		 * unconditional call -- nothing is skipped.  Only the event_workq
		 * teardown inside the function is self-guarded (it NULLs
		 * svc->event_workq on first call, so that step is skipped on a
		 * later call); the wait_event() on pending_user_info_destroys,
		 * drain_workqueue(mr_unmap_wq), and hfi2_bulksvc_drain_verbs_queues()
		 * steps run unconditionally on every call, but are cheap and
		 * harmless to repeat (they just re-drain queues that are already
		 * empty by the second call).  That combination -- one guarded step
		 * plus several safe-to-repeat steps -- is what makes this early-
		 * and-late double call safe, not a blanket idempotency guarantee.
		 *
		 * Possible future cleanup: collapse to a single unconditional
		 * call by moving this hfi2_bulksvc_quiesce_thread(dd) out of the
		 * HFI2_BULKSVC_ULP_STUBS block above (so it always runs right after
		 * wait_for_clients(dd)) and dropping the now-redundant calls in
		 * hfi2_unregister_roce_ib_device() (roce_main.c) and directly in
		 * hfi2_unregister_ib_device() (verbs.c).  Not done here: those
		 * call sites carry their own comment explaining a real, already
		 * fixed crash (a race with hfi2_verbs_txreq_exit's kmem_cache_destroy)
		 * and belong to code outside this fix's scope, including the
		 * OPA path this fix was never exercised against.
		 */
		hfi2_bulksvc_quiesce_thread(dd);
		hfi2_bulksvc_ulp_teardown_all(dd->bulksvc);
	}
#endif
	hfi2_devlink_unregister(dd);
	pldm_ua_exit(dd);
	/* close debugfs files before hfi2_ib unregister */
	hfi2_dbg_ibdev_exit(&dd->verbs_dev);
	/* unregister from IB core */
	hfi2_unregister_ib_device(dd);


	/* stop handling LOCAL_MAD_ from CPORT */
	hfi2_mad_deinit(dd);
	clearall_cport_trap(dd);
	stop_cport(dd);
	/*
	 * Disable the IB link, disable interrupts on the device,
	 * clear dma engines, etc.
	 */
	shutdown_device(dd);

	stop_timers(dd);

	postinit_cleanup(dd);
	hfi2_free_devdata(dd);
}

/*
 * This is called during system reboot/shutdown/halt.
 */
static void shutdown_one(struct pci_dev *pdev)
{
	struct hfi2_devdata *dd = pci_get_drvdata(pdev);

	if (dd->params->chip_type == CHIP_WFR)
		shutdown_device(dd);
	else
		remove_one(pdev);
}

/* The device has reported over-temp and will shutdown soon (~500mS) */
void hfi2_overtemp(struct hfi2_devdata *dd)
{
	dd_dev_err(dd, "*** OVER TEMP *** device shutdown imminent!\n");
	/* take some action to gracefully shut down/quiesce */
}

/**
 * hfi2_create_rcvhdrq - create a receive header queue
 * @dd: the hfi2_ib device
 * @rcd: the context data
 *
 * This must be contiguous memory (from an i/o perspective), and must be
 * DMA'able (which means for some systems, it will go through an IOMMU,
 * or be forced into a low address range).
 */
int hfi2_create_rcvhdrq(struct hfi2_devdata *dd, struct hfi2_ctxtdata *rcd)
{
	u32 amt = rcvhdrq_size(rcd);

	if (!rcd->rcvhdrq) {
		rcd->rcvhdrq = dma_alloc_coherent(
			&dd->pcidev->dev, amt, &rcd->rcvhdrq_dma, GFP_KERNEL);

		if (!rcd->rcvhdrq) {
			dd_dev_err(
				dd,
				"attempt to allocate %d bytes for ctxt %u rcvhdrq failed\n",
				amt, rcd->ctxt);
			goto bail;
		}

		if (HFI2_CAP_KGET_MASK(rcd->flags, DMA_RTAIL) ||
		    HFI2_CAP_UGET_MASK(rcd->flags, DMA_RTAIL)) {
			rcd->rcvhdrtail_kvaddr = dma_alloc_coherent(
				&dd->pcidev->dev, PAGE_SIZE,
				&rcd->rcvhdrqtailaddr_dma, GFP_KERNEL);
			if (!rcd->rcvhdrtail_kvaddr) {
				dd_dev_err(
					dd,
					"attempt to allocate 1 page for ctxt %u rcvhdrqtailaddr failed\n",
					rcd->ctxt);
				goto rhq_free;
			}
		}

		if (dd->params->chip_type != CHIP_WFR) {
			u32 rheq_amt = rheq_size(rcd);

			rcd->rheq = dma_alloc_coherent(&dd->pcidev->dev,
						       rheq_amt, &rcd->rheq_dma,
						       GFP_KERNEL);
			if (!rcd->rheq) {
				dd_dev_err(
					dd,
					"attempt to allocate %d bytes for ctxt %u rheq failed\n",
					rheq_amt, rcd->ctxt);
				goto tail_free;
			}
		}
	}

	hfi2_set_hdrq_regs(rcd->ppd, rcd->ctxt, rcd->rcvhdrqentsize,
			   rcd->rcvhdrq_cnt, rcd->kdeth_rcv_hdr);

	return 0;

tail_free:
	if (rcd->rcvhdrtail_kvaddr) {
		dma_free_coherent(&dd->pcidev->dev, PAGE_SIZE,
				  (void *)hfi2_rcvhdrtail_kvaddr(rcd),
				  rcd->rcvhdrqtailaddr_dma);
		rcd->rcvhdrtail_kvaddr = NULL;
	}
rhq_free:
	dma_free_coherent(&dd->pcidev->dev, amt, rcd->rcvhdrq,
			  rcd->rcvhdrq_dma);
	rcd->rcvhdrq = NULL;
bail:
	return -ENOMEM;
}

/**
 * hfi2_setup_eagerbufs - allocate eager buffers, both kernel and user
 * contexts.
 * @rcd: the context we are setting up.
 *
 * Allocate the eager TID buffers and program them into the chip.
 * They are no longer completely contiguous, we do multiple allocation
 * calls.  Otherwise we get the OOM code involved, by asking for too
 * much per call, with disastrous results on some kernels.
 */
int hfi2_setup_eagerbufs(struct hfi2_ctxtdata *rcd)
{
	struct hfi2_devdata *dd = rcd->dd;
	u32 max_entries, egrtop, alloced_bytes = 0;
	u16 order, idx = 0;
	int ret = 0;
	u16 round_mtu = roundup_pow_of_two(hfi2_max_mtu);

	/*
	 * The minimum size of the eager buffers is a groups of MTU-sized
	 * buffers.
	 * The global eager_buffer_size parameter is checked against the
	 * theoretical lower limit of the value. Here, we check against the
	 * MTU.
	 */
	if (rcd->egrbufs.size < (round_mtu * dd->rcv_entries.group_size))
		rcd->egrbufs.size = round_mtu * dd->rcv_entries.group_size;
	/*
	 * If using one-pkt-per-egr-buffer, lower the eager buffer
	 * size to the max MTU (page-aligned).
	 */
	if (!HFI2_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR))
		rcd->egrbufs.rcvtid_size = round_mtu;

	/*
	 * Eager buffers sizes of 1MB or less require smaller TID sizes
	 * to satisfy the "multiple of 8 RcvArray entries" requirement.
	 */
	if (rcd->egrbufs.size <= (1 << 20))
		rcd->egrbufs.rcvtid_size =
			max((unsigned long)round_mtu,
			    rounddown_pow_of_two(rcd->egrbufs.size / 8));

	while (alloced_bytes < rcd->egrbufs.size &&
	       rcd->egrbufs.alloced < rcd->egrbufs.count) {
		rcd->egrbufs.buffers[idx].addr = dma_alloc_coherent(
			&dd->pcidev->dev, rcd->egrbufs.rcvtid_size,
			&rcd->egrbufs.buffers[idx].dma, GFP_KERNEL);
		if (rcd->egrbufs.buffers[idx].addr) {
			rcd->egrbufs.buffers[idx].len =
				rcd->egrbufs.rcvtid_size;
			rcd->egrbufs.rcvtids[rcd->egrbufs.alloced].addr =
				rcd->egrbufs.buffers[idx].addr;
			rcd->egrbufs.rcvtids[rcd->egrbufs.alloced].dma =
				rcd->egrbufs.buffers[idx].dma;
			rcd->egrbufs.alloced++;
			alloced_bytes += rcd->egrbufs.rcvtid_size;
			idx++;
		} else {
			u32 new_size, i, j;
			u64 offset = 0;

			/*
			 * Fail the eager buffer allocation if:
			 *   - we are already using the lowest acceptable size
			 *   - we are using one-pkt-per-egr-buffer (this implies
			 *     that we are accepting only one size)
			 */
			if (rcd->egrbufs.rcvtid_size == round_mtu ||
			    !HFI2_CAP_KGET_MASK(rcd->flags, MULTI_PKT_EGR)) {
				dd_dev_err(
					dd,
					"ctxt%u: Failed to allocate eager buffers\n",
					rcd->ctxt);
				ret = -ENOMEM;
				goto bail_rcvegrbuf_phys;
			}

			new_size = rcd->egrbufs.rcvtid_size / 2;

			/*
			 * If the first attempt to allocate memory failed, don't
			 * fail everything but continue with the next lower
			 * size.
			 */
			if (idx == 0) {
				rcd->egrbufs.rcvtid_size = new_size;
				continue;
			}

			/*
			 * Re-partition already allocated buffers to a smaller
			 * size.
			 */
			rcd->egrbufs.alloced = 0;
			for (i = 0, j = 0, offset = 0; j < idx; i++) {
				if (i >= rcd->egrbufs.count)
					break;
				rcd->egrbufs.rcvtids[i].dma =
					rcd->egrbufs.buffers[j].dma + offset;
				rcd->egrbufs.rcvtids[i].addr =
					rcd->egrbufs.buffers[j].addr + offset;
				rcd->egrbufs.alloced++;
				if ((rcd->egrbufs.buffers[j].dma + offset +
				     new_size) ==
				    (rcd->egrbufs.buffers[j].dma +
				     rcd->egrbufs.buffers[j].len)) {
					j++;
					offset = 0;
				} else {
					offset += new_size;
				}
			}
			rcd->egrbufs.rcvtid_size = new_size;
		}
	}
	rcd->egrbufs.numbufs = idx;
	rcd->egrbufs.size = alloced_bytes;

	hfi2_cdbg(PROC, "ctxt%u: Alloced %u rcv tid entries @ %uKB, total %uKB",
		  rcd->ctxt, rcd->egrbufs.alloced,
		  rcd->egrbufs.rcvtid_size / 1024, rcd->egrbufs.size / 1024);

	/*
	 * Set the contexts rcv array head update threshold to the closest
	 * power of 2 (so we can use a mask instead of modulo) below half
	 * the allocated entries.
	 */
	rcd->egrbufs.threshold = rounddown_pow_of_two(rcd->egrbufs.alloced / 2);
	/*
	 * Compute the expected RcvArray entry base. This is done after
	 * allocating the eager buffers in order to maximize the
	 * expected RcvArray entries for the context.
	 */
	max_entries = rcd->rcv_array_groups * dd->rcv_entries.group_size;
	egrtop = roundup(rcd->egrbufs.alloced, dd->rcv_entries.group_size);
	rcd->expected_count = max_entries - egrtop;
	if (rcd->expected_count > MAX_TID_PAIR_ENTRIES * 2)
		rcd->expected_count = MAX_TID_PAIR_ENTRIES * 2;

	rcd->expected_base = rcd->eager_base + egrtop;
	hfi2_cdbg(PROC, "ctxt%u: eager:%u, exp:%u, egrbase:%u, expbase:%u",
		  rcd->ctxt, rcd->egrbufs.alloced, rcd->expected_count,
		  rcd->eager_base, rcd->expected_base);

	if (!hfi2_rcvbuf_validate(rcd->egrbufs.rcvtid_size, PT_EAGER, &order)) {
		hfi2_cdbg(PROC,
			  "ctxt%u: current Eager buffer size is invalid %u",
			  rcd->ctxt, rcd->egrbufs.rcvtid_size);
		ret = -EINVAL;
		goto bail_rcvegrbuf_phys;
	}

	/*
	 * Enable RcvArray access on JKR and later by configuring RcvEgrCtrl and
	 * RcvTidCtrl before writing TIDs to the RcvArray.
	 *
	 * Call set_port_tid_config only after eager_base, egrbufs.alloced,
	 * expected_count, and expected_base are initialized in rcd.  The last
	 * 3 of the 4 are initialized above in this function.
	 */
	dd->params->set_port_tid_config(dd, rcd->ppd->hw_pidx, rcd->ctxt,
					rcd->eager_base, rcd->egrbufs.alloced,
					rcd->expected_base,
					rcd->expected_count);

	/*
	 * There must be sufficient time between writing RcvEgrCtrl in
	 * dd->params->set_port_tid_config() and writing RcvArrayEgr in
	 * dd->params->put_tid(). Insert a CSR read to delay "long enough".
	 */
	if (!dd->is_vf)
		read_uctxt_csr(dd, rcd->ctxt, dd->params->rcv_hdr_head_reg);

	for (idx = 0; idx < rcd->egrbufs.alloced; idx++) {
		dd->params->put_tid(rcd, idx, PT_EAGER,
				    rcd->egrbufs.rcvtids[idx].dma, order,
				    false);
		cond_resched();
	}

	return 0;

bail_rcvegrbuf_phys:
	for (idx = 0; idx < rcd->egrbufs.count; idx++)
		hfi2_free_egrbuf(dd, &rcd->egrbufs.buffers[idx]);

	return ret;
}

/*
 * Return number of requested user contexts for the given unit and port based
 * on information given in the module parameter num_user_contexts.
 * Return -1 (use non-HT cores) if the corresponding entry is not set.
 */
int hfi2_get_num_user_contexts(struct hfi2_devdata *dd, int pidx)
{
	struct hfi2_devdata *xdd;
	int start;
	int i;

	/* find the count of ports from earlier units */
	start = 0;
	for (i = 0; i < dd->unit; i++) {
		xdd = hfi2_lookup(i);
		/* previous units should exist - check anyway */
		if (!xdd) {
			dd_dev_err(dd, "%s: unit %d not found?\n", __func__, i);
			return -1;
		}
		start += xdd->num_pports;
	}

	/* adjust for the port on this unit */
	start += pidx;

	/* check if enough elements are set for this unit's port */
	if (start >= num_user_contexts_count)
		return -1;

	/* array holds "N" or "N:E" strings; N is the user context count */
	{
		char *s = num_user_contexts_array[start];
		char *endp;
		long val;

		val = simple_strtol(s, &endp, 0);
		if (val < 0 || val > INT_MAX)
			return -1;
		return (int)val;
	}
}
