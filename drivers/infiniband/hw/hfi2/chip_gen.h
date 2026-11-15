/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific declaractions.
 */

#ifndef _CHIP_GEN_H
#define _CHIP_GEN_H

void hfi2_gen_setextled(struct hfi2_pportdata *ppd, u32 on);
void hfi2_gen_start_led_override(struct hfi2_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff);
void hfi2_gen_shutdown_led_override(struct hfi2_pportdata *ppd);
void hfi2_gen_read_guid(struct hfi2_devdata *dd);
int hfi2_gen_late_per_chip_init(struct hfi2_devdata *dd);
void hfi2_gen_start_port(struct hfi2_pportdata *ppd);
void hfi2_gen_stop_port(struct hfi2_pportdata *ppd);
void hfi2_gen_set_port_max_mtu(struct hfi2_pportdata *ppd, u32 maxvlmtu);
u64 hfi2_gen_create_pbc(struct hfi2_pportdata *ppd, bool hfi2_loopback, u64 flags, int srate_mbs,
		   u32 vl, u32 dw_len, u32 l2, u32 dlid, u32 sctxt);
u64 hfi2_gen_create_pbc_pidx(u8 pidx, u64 flags, int srate_mbs,
			u32 vl, u32 dw_len, u32 l2, u32 dlid, u32 sctxt);

int hfi2_cport_set_link_state(struct hfi2_pportdata *ppd, struct opa_port_info *pi, u32 state);
int hfi2_cport_start_link(struct hfi2_pportdata *ppd, struct opa_port_info *pi);
int hfi2_cport_read_temp(struct hfi2_devdata *dd, struct cport_temp *gen_temp);

int gen_init_special(struct hfi2_devdata *dd);

int hfi2_init_cport_trap128(struct hfi2_devdata *dd);
int hfi2_deinit_cport_trap128(struct hfi2_devdata *dd);
void lock_cport_trap128(struct hfi2_devdata *dd);
void unlock_cport_trap128(struct hfi2_devdata *dd);
int hfi2_init_cport_overtemp(struct hfi2_devdata *dd);


void gen_enable_rcv_context(struct hfi2_pportdata *ppd, u16 ctxt,
			    u64 *kctxt_ctrl, bool enable);
void gen_update_rcv_hdr_size(struct hfi2_pportdata *ppd, u16 ctxt, u32 size);
void gen_init_si_ints(struct hfi2_devdata *dd);
int gen_cport_who_init(struct hfi2_devdata *dd);

#endif /* _CHIP_GEN_H */
int gen_init_rctxt_egr(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt,
		       u32 ra_base, u32 ra_cnt, u32 hdr_size);
void gen_deinit_rctxt(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt);
int gen_init_sctxt_pio(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt,
		       u32 cr_base, u32 cr_cnt);
int gen_start_sctxt(struct hfi2_devdata *dd, u8 pidx, u16 ctxt, struct hfi2_ctxtbufs *bufs);
int hfi2_sriov_sync_ports(struct hfi2_devdata *dd, int si_mask);
int gen_start_rctxt_egr(struct hfi2_devdata *dd, u8 pidx, u16 ctxt,
			struct hfi2_ctxtbufs *bufs);
void gen_deinit_sctxt(struct hfi2_devdata *dd, u8 pidx, int si, u16 ctxt);
void set_si_int_enable_range(struct hfi2_devdata *dd, u64 *csrs, u32 start, u32 end);
void write_si_int_enable(struct hfi2_devdata *dd, int si, u64 *csrs);
