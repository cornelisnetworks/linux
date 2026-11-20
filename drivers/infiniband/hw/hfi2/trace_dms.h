/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2025 Cornelis Networks, Inc.
 * Copyright(c) 2017 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#if !defined(__HFI2_TRACE_DMS_H) || defined(TRACE_HEADER_MULTI_READ)
#define __HFI2_TRACE_DMS_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#include "dms.h"

const char *hfi2_memtype_str(unsigned int mt);

#undef TRACE_SYSTEM
#define TRACE_SYSTEM hfi2_dms

struct hfi2_dms;
struct hfi2_dms_page_provider;
struct hfi2_dms_rx_tracker;
union hfi2_dms_16b_header;

TRACE_EVENT(dms_read_data,
	    TP_PROTO(struct hfi2_dms *dms, u64 handle,
		     enum hfi2_dms_fabric_port_idx port_idx, u32 src_lid,
		     union hfi2_dms_key dms_key, u64 offset, u32 size,
		     u64 mr_offset, u16 flags, u64 submit_flags,
		     u64 imm_data, u64 order_key),
	    TP_ARGS(dms, handle, port_idx, src_lid, dms_key, offset, size,
		    mr_offset, flags, submit_flags, imm_data, order_key),
	    TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
			     __field(u64, handle)
			     __field(int, port_idx)
			     __field(u32, src_lid)
			     __field(u64, dms_key)
				 __field(u64, offset)
				 __field(u32, size)
				 __field(u64, mr_offset)
				 __field(u16, flags)
				 __field(u64, submit_flags)
				 __field(u64, imm_data)
				 __field(u64, order_key)),
	    TP_fast_assign(__entry->dms = dms;
			   __entry->handle = handle;
			   __entry->port_idx = port_idx;
			   __entry->src_lid = src_lid;
			   __entry->dms_key = dms_key.value;
			   __entry->offset = offset;
			   __entry->size = size;
			   __entry->mr_offset = mr_offset;
			   __entry->flags = flags;
			   __entry->submit_flags = submit_flags;
			   __entry->imm_data = imm_data;
			   __entry->order_key = order_key;
	    ),
	    TP_printk("READ DATA - dms %p handle %llx port_idx %d src_lid %u key %llx offset %llu size %u mr_offset %llu flags %x submit_flags %llx imm_data %llx order_key %llx",
		      __entry->dms, __entry->handle, __entry->port_idx,
		      __entry->src_lid, __entry->dms_key, __entry->offset,
		      __entry->size, __entry->mr_offset, __entry->flags,
		      __entry->submit_flags, __entry->imm_data,
		      __entry->order_key)
);

TRACE_EVENT(dms_write_data,
	    TP_PROTO(struct hfi2_dms *dms, u64 handle,
		     enum hfi2_dms_fabric_port_idx port_idx, u32 dest_lid,
		     union hfi2_dms_key dms_key, u64 offset, u32 size,
		     u64 mr_offset, u16 flags, u64 submit_flags,
		     u64 imm_data, u64 order_key),
	    TP_ARGS(dms, handle, port_idx, dest_lid, dms_key, offset, size,
		    mr_offset, flags, submit_flags, imm_data, order_key),
	    TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
			     __field(u64, handle)
			     __field(int, port_idx)
			     __field(u32, dest_lid)
			     __field(u64, dms_key)
				 __field(u64, offset)
				 __field(u32, size)
				 __field(u64, mr_offset)
				 __field(u16, flags)
				 __field(u64, submit_flags)
				 __field(u64, imm_data)
				 __field(u64, order_key)),
	    TP_fast_assign(__entry->dms = dms;
			   __entry->handle = handle;
			   __entry->port_idx = port_idx;
			   __entry->dest_lid = dest_lid;
			   __entry->dms_key = dms_key.value;
			   __entry->offset = offset;
			   __entry->size = size;
			   __entry->mr_offset = mr_offset;
			   __entry->flags = flags;
			   __entry->submit_flags = submit_flags;
			   __entry->imm_data = imm_data;
			   __entry->order_key = order_key;
	    ),
	    TP_printk("WRITE DATA - dms %p handle %llx port_idx %d dest_lid %u key %llx offset %llu size %u mr_offset %llu flags %x submit_flags %llx imm_data %llx order_key %llx",
		      __entry->dms, __entry->handle, __entry->port_idx,
		      __entry->dest_lid, __entry->dms_key, __entry->offset,
		      __entry->size, __entry->mr_offset, __entry->flags,
		      __entry->submit_flags, __entry->imm_data,
		      __entry->order_key)
);

TRACE_EVENT(dms_make_data_request,
		TP_PROTO(struct hfi2_dms *dms, struct hfi2_dms_rx_tracker *tracker, u32 tid_set),
		TP_ARGS(dms, tracker, tid_set),
		TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
				 __field(struct hfi2_dms_rx_tracker *, tracker)
				 __field(u32, tid_set)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->tracker = tracker;
			       __entry->tid_set = tid_set;),
		TP_printk("MAKE DATA REQUEST - dms %p tracker %p tid_set %u",
			  __entry->dms, __entry->tracker, __entry->tid_set)
);

TRACE_EVENT(dms_map_tid_entries,
		TP_PROTO(struct hfi2_dms *dms, dma_addr_t const *dma_addrs, u64 npages, u32 tid_set),
		TP_ARGS(dms, dma_addrs, npages, tid_set),
		TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
				 __field(dma_addr_t const *, dma_addrs)
				 __field(u64, npages)
				 __field(u32, tid_set)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->dma_addrs = dma_addrs;
			       __entry->npages = npages;
			       __entry->tid_set = tid_set;),
		TP_printk("MAP TID ENTRIES - dms %p dma_addrs %p npages %llu tid_set %u",
			  __entry->dms, __entry->dma_addrs,
			  __entry->npages, __entry->tid_set)
);

TRACE_EVENT(dms_poll,
		TP_PROTO(struct hfi2_dms *dms),
		TP_ARGS(dms),
		TP_STRUCT__entry(__field(struct hfi2_dms *, dms)),
		TP_fast_assign(__entry->dms = dms;),
		TP_printk("POLL - dms %p",
			  __entry->dms)
);

TRACE_EVENT(dms_sdma_send,
		TP_PROTO(struct hfi2_dms *dms,
			 struct hfi2_dms_page_provider const *src_provider),
		TP_ARGS(dms, src_provider),
		TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
				 __field(struct hfi2_dms_page_provider const *,
					 src_provider)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->src_provider = src_provider;),
		TP_printk("SDMA SEND - dms %p src_provider %p",
			  __entry->dms, __entry->src_provider)
);

TRACE_EVENT(dms_handle_data,
		TP_PROTO(struct hfi2_dms *dms, union hfi2_dms_16b_header *hdr),
		TP_ARGS(dms, hdr),
		TP_STRUCT__entry(__field(struct hfi2_dms *, dms)
				 __field(union hfi2_dms_16b_header *, hdr)),
		TP_fast_assign(__entry->dms = dms;
			       __entry->hdr = hdr;),
		TP_printk("HANDLE DATA - dms %p hdr %p",
			  __entry->dms, __entry->hdr)
);

TRACE_EVENT(verbs_dms_submit,
		TP_PROTO(u32 qp_num, bool is_read, bool is_send, bool is_imm,
			 u32 size, u32 num_sge),
		TP_ARGS(qp_num, is_read, is_send, is_imm, size, num_sge),
		TP_STRUCT__entry(__field(u32, qp_num)
				 __field(bool, is_read)
				 __field(bool, is_send)
				 __field(bool, is_imm)
				 __field(u32, size)
				 __field(u32, num_sge)),
		TP_fast_assign(__entry->qp_num = qp_num;
			       __entry->is_read = is_read;
			       __entry->is_send = is_send;
			       __entry->is_imm = is_imm;
			       __entry->size = size;
			       __entry->num_sge = num_sge;),
		TP_printk("VERBS DMS SUBMIT - qp %u is_read %d is_send %d is_imm %d size %u num_sge %u",
			  __entry->qp_num, __entry->is_read, __entry->is_send,
			  __entry->is_imm, __entry->size, __entry->num_sge)
);

#endif /* __HFI2_TRACE_DMS_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace_dms
#include <trace/define_trace.h>
