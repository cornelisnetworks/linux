// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#include <linux/anon_inodes.h>
#include <linux/fdtable.h>
#include "hfi2.h"
#include "user_sdma.h"
#include "uverbs.h"
#include "file_ops.h"

#define UVERBS_MODULE_NAME hfi2_uv
#include <rdma/uverbs_named_ioctl.h>

static const u64 zero8; /* 8 bytes of 0 */

/* rdmavt mmap for CQ/QP/SRQ fallback */
#include "../../sw/rdmavt/mmap.h"

/*
 * Insert a driver mmap entry into the rdma_user_mmap infrastructure.
 * Returns 0 on success and stores the opaque offset in *offset for
 * userspace to pass back to mmap(2).
 */
static int hfi2_mmap_entry_insert(struct ib_ucontext *ucontext,
				  struct hfi2_filedata *fd, u8 type,
				  size_t length, u64 address, void *memvirt,
				  dma_addr_t memdma, u64 *offset)
{
	struct hfi2_user_mmap_entry *entry;
	int ret;

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	INIT_LIST_HEAD(&entry->list);
	entry->address = address;
	entry->memvirt = memvirt;
	entry->memdma = memdma;
	entry->mmap_flag = type;
	entry->dma = memvirt && (type == PIO_CRED || type == RCV_HDRQ ||
				  type == RCV_EGRBUF || type == RTAIL ||
				  type == RCV_RHEQ);

	ret = rdma_user_mmap_entry_insert(ucontext, &entry->rdma_entry, length);
	if (ret) {
		kfree(entry);
		return ret;
	}

	if (offset)
		*offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
	if (type == RCV_EGRBUF) {
		mutex_lock(&fd->eager_mmap_entries_lock);
		list_add_tail(&entry->list, &fd->eager_mmap_entries);
		mutex_unlock(&fd->eager_mmap_entries_lock);
	} else {
		struct rdma_user_mmap_entry *old_entry;

		mutex_lock(&fd->mmap_entries_lock);
		old_entry = fd->mmap_entries[type];
		fd->mmap_entries[type] = &entry->rdma_entry;
		mutex_unlock(&fd->mmap_entries_lock);
		if (old_entry)
			rdma_user_mmap_entry_remove(old_entry);
	}
	return 0;
}

static void hfi2_remove_eager_mmap_entries(struct hfi2_filedata *fd)
{
	struct hfi2_user_mmap_entry *entry, *tmp;
	LIST_HEAD(entries);

	mutex_lock(&fd->eager_mmap_entries_lock);
	list_splice_init(&fd->eager_mmap_entries, &entries);
	mutex_unlock(&fd->eager_mmap_entries_lock);

	list_for_each_entry_safe(entry, tmp, &entries, list) {
		list_del(&entry->list);
		rdma_user_mmap_entry_remove(&entry->rdma_entry);
	}
}

static int hfi2_add_eager_mmap_entries(struct ib_ucontext *ucontext,
				       struct hfi2_filedata *fd)
{
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	int i, ret;

	hfi2_remove_eager_mmap_entries(fd);

	for (i = 0; i < uctxt->egrbufs.numbufs; i++) {
		ret = hfi2_mmap_entry_insert(ucontext, fd, RCV_EGRBUF,
					     uctxt->egrbufs.buffers[i].len, 0,
					     uctxt->egrbufs.buffers[i].addr,
					     uctxt->egrbufs.buffers[i].dma, NULL);
		if (ret) {
			hfi2_remove_eager_mmap_entries(fd);
			return ret;
		}
	}

	return 0;
}

int hfi2_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata)
{
	struct hfi2_devdata *dd = dd_from_ibdev(ucontext->device);
	struct rvt_ucontext *rcontext =
		container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi2_filedata *fd;

	fd = hfi2_alloc_filedata(dd);
	if (!fd)
		return -ENOMEM;

	rcontext->priv = fd;

	return 0;
}

void hfi2_dealloc_ucontext(struct ib_ucontext *ucontext)
{
	struct rvt_ucontext *rcontext =
		container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi2_filedata *fd;
	int i;

	fd = rcontext->priv;
	if (fd) {
		hfi2_remove_eager_mmap_entries(fd);
		for (i = 0; i < ARRAY_SIZE(fd->mmap_entries); i++) {
			struct rdma_user_mmap_entry *entry;

			mutex_lock(&fd->mmap_entries_lock);
			entry = fd->mmap_entries[i];
			fd->mmap_entries[i] = NULL;
			mutex_unlock(&fd->mmap_entries_lock);
			rdma_user_mmap_entry_remove(entry);
		}
		hfi2_dealloc_filedata(fd);
		rcontext->priv = NULL;
	}
}

static inline struct hfi2_filedata *
fd_from_attrs(struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = ib_uverbs_get_ucontext(attrs);
	struct rvt_ucontext *rcontext =
		container_of(ucontext, struct rvt_ucontext, ibucontext);

	return rcontext->priv;
}

static int
UVERBS_HANDLER(HFI2_METHOD_ASSIGN_CTXT)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_assign_ctxt_cmd cmd;
	int ret;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_ASSIGN_CTXT_CMD);
	if (ret)
		return ret;

	if (cmd.reserved1 != 0 || cmd.reserved2 != 0)
		return -EINVAL;

	return hfi2_do_assign_ctxt(fd, &cmd);
};

static int
UVERBS_HANDLER(HFI2_METHOD_CTXT_INFO)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_ctxt_info_rsp rsp = {};

	if (!uctxt)
		return -EINVAL;

	rsp.runtime_flags =
		(((uctxt->flags >> HFI2_CAP_MISC_SHIFT) & HFI2_CAP_MISC_MASK)
		 << HFI2_CAP_USER_SHIFT) |
		HFI2_CAP_UGET_MASK(uctxt->flags, MASK) |
		HFI2_CAP_KGET_MASK(uctxt->flags, K2U);
	/* adjust flag if this fd is not able to cache */
	if (!fd->use_mn)
		rsp.runtime_flags |= HFI2_CAP_TID_UNMAP; /* no caching */

	rsp.num_active = hfi2_count_active_units();
	rsp.unit = uctxt->dd->unit;
	rsp.ctxt = uctxt->ctxt;
	rsp.subctxt = fd->subctxt;
	rsp.rcvtids = roundup(uctxt->egrbufs.alloced,
			      uctxt->dd->rcv_entries.group_size) +
		      uctxt->expected_count;
	rsp.credits = uctxt->sc->credits;
	rsp.numa_node = uctxt->numa_id;
	/*
	 * The driver does not enforce per-process CPU affinity.  User space
	 * sets affinity via sched_setaffinity()/taskset; report 0xffff (no
	 * driver-recommended CPU) to preserve the ABI layout.
	 */
	rsp.rec_cpu = 0xffff;
	rsp.send_ctxt = uctxt->sc->hw_context;

	rsp.egrtids = uctxt->egrbufs.alloced;
	rsp.rcvhdrq_cnt = get_hdrq_cnt(uctxt);
	rsp.rcvhdrq_entsize = get_hdrqentsize(uctxt) << 2;
	rsp.sdma_ring_size = fd->cq->nentries;
	rsp.rcvegr_size = uctxt->egrbufs.rcvtid_size;

	return uverbs_copy_to(attrs, HFI2_ATTR_CTXT_INFO_RSP, &rsp,
			      sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_USER_INFO)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_user_info_rsp rsp = {};
	struct hfi2_devdata *dd;

	if (!uctxt || !fd->cq)
		return -EINVAL;
	dd = uctxt->dd;

	rsp.hw_version = dd->revision;
	rsp.sw_version = HFI2_UVERBS_ABI_VERSION;
	rsp.bthqp = RVT_KDETH_QP_PREFIX;
	rsp.jkey = uctxt->jkey;
	/*
	 * If more than 64 contexts are enabled, the allocated credit return
	 * will span two or three contiguous pages. Only the page containing
	 * the context's credit return address is mapped.  Calculate the offset
	 * in the proper page.
	 */

	/*
	 * Replace the old token scheme with rdma_user_mmap_entry_insert().
	 * Each buffer type gets an entry in the xarray; the opaque offset
	 * returned to userspace is passed back to mmap(2).
	 */
	{
		struct ib_ucontext *ucontext = ib_uverbs_get_ucontext(attrs);
		u64 cr_page_offset;
		unsigned long events;
		u32 cbi, cbc;
		int ret;

		/* PIO send buffers (write-combine MMIO) */
		cbi = ctxt_bar_idx(uctxt->sc->hw_context);
		cbc = ctxt_bar_ctxt(uctxt->sc->hw_context);
		ret = hfi2_mmap_entry_insert(
			ucontext, fd, PIO_BUFS,
			PAGE_ALIGN(uctxt->sc->credits * PIO_BLOCK_SIZE),
			dd->bar_maps[cbi].physaddr + TXE_PIO_SEND +
				(cbc * BIT(16)),
			NULL, 0, &rsp.pio_bufbase);
		if (ret)
			return ret;

		ret = hfi2_mmap_entry_insert(
			ucontext, fd, PIO_BUFS_SOP,
			PAGE_ALIGN(uctxt->sc->credits * PIO_BLOCK_SIZE),
			dd->bar_maps[cbi].physaddr + TXE_PIO_SEND +
				(cbc * BIT(16)) + (TXE_PIO_SIZE / 2),
			NULL, 0, &rsp.pio_bufbase_sop);
		if (ret)
			return ret;

		/*
		 * PIO credit return (DMA-coherent). If more than 64 contexts are
		 * enabled, the credit return spans multiple pages; map only the page
		 * containing this context's credit return address.
		 */
		cr_page_offset = ((u64)uctxt->sc->hw_free -
				  (u64)dd->cr_base[uctxt->numa_id].va) &
				 PAGE_MASK;
		rsp.sc_credits_offset = offset_in_page(uctxt->sc->hw_free);
		ret = hfi2_mmap_entry_insert(
			ucontext, fd, PIO_CRED, PAGE_SIZE, 0,
			(void *)dd->cr_base[uctxt->numa_id].va + cr_page_offset,
			dd->cr_base[uctxt->numa_id].dma + cr_page_offset,
			&rsp.sc_credits_addr);
		if (ret)
			return ret;

		/* Receive header queue (DMA-coherent) */
		ret = hfi2_mmap_entry_insert(ucontext, fd, RCV_HDRQ,
					     rcvhdrq_size(uctxt), 0,
					     uctxt->rcvhdrq, uctxt->rcvhdrq_dma,
					     &rsp.rcvhdr_bufbase);
		if (ret)
			return ret;

		ret = hfi2_add_eager_mmap_entries(ucontext, fd);
		if (ret)
			return ret;

		/* SDMA completion queue (vmalloc'd) */
		ret = hfi2_mmap_entry_insert(
			ucontext, fd, SDMA_COMP,
			PAGE_ALIGN(sizeof(*fd->cq->comps) * fd->cq->nentries),
			(u64)fd->cq->comps, NULL, 0, &rsp.sdma_comp_bufbase);
		if (ret)
			return ret;

		/*
		 * User registers (non-cached MMIO).
		 * RcvHdrTail is the first register in the hardware UCTXT block.
		 */
		cbi = ctxt_bar_idx(uctxt->ctxt);
		cbc = ctxt_bar_ctxt(uctxt->ctxt);
		ret = hfi2_mmap_entry_insert(
			ucontext, fd, UREGS, dd->params->rxe_uctxt_stride,
			(u64)dd->bar_maps[cbi].physaddr +
				dd->params->rcv_hdr_tail_reg +
				(cbc * dd->params->rxe_uctxt_stride),
			NULL, 0, &rsp.user_regbase);
		if (ret)
			return ret;

		/* Events page (vmalloc'd) */
		events = (unsigned long)(dd->events + uctxt_offset(uctxt) +
					 fd->subctxt);
		rsp.events_offset = offset_in_page(events);
		ret = hfi2_mmap_entry_insert(
			ucontext, fd, EVENTS, PAGE_SIZE, events & PAGE_MASK, NULL, 0,
			&rsp.events_bufbase);
		if (ret)
			return ret;

		/* Status page (kernel virtual) */
		ret = hfi2_mmap_entry_insert(ucontext, fd, STATUS, PAGE_SIZE, 0,
					     (void *)dd->status, 0,
					     &rsp.status_bufbase);
		if (ret)
			return ret;

		/* Receive header tail (DMA-coherent) */
		if (HFI2_CAP_IS_USET(DMA_RTAIL)) {
			ret = hfi2_mmap_entry_insert(
				ucontext, fd, RTAIL, PAGE_SIZE, 0,
				(void *)hfi2_rcvhdrtail_kvaddr(uctxt),
				uctxt->rcvhdrqtailaddr_dma,
				&rsp.rcvhdrtail_base);
			if (ret)
				return ret;
		}

		/* Sub-context shared regions (vmalloc'd) */
		if (uctxt->subctxt_cnt) {
			ret = hfi2_mmap_entry_insert(
				ucontext, fd, SUBCTXT_UREGS, PAGE_SIZE,
				(u64)uctxt->subctxt_uregbase, NULL, 0,
				&rsp.subctxt_uregbase);
			if (ret)
				return ret;

			ret = hfi2_mmap_entry_insert(
				ucontext, fd, SUBCTXT_RCV_HDRQ,
				rcvhdrq_size(uctxt) * uctxt->subctxt_cnt,
				(u64)uctxt->subctxt_rcvhdr_base, NULL, 0,
				&rsp.subctxt_rcvhdrbuf);
			if (ret)
				return ret;

			ret = hfi2_mmap_entry_insert(
				ucontext, fd, SUBCTXT_EGRBUF,
				uctxt->egrbufs.size * uctxt->subctxt_cnt,
				(u64)uctxt->subctxt_rcvegrbuf, NULL, 0,
				&rsp.subctxt_rcvegrbuf);
			if (ret)
				return ret;
		}

		/* Receive header error queue (DMA-coherent, JKR only) */
		if (dd->params->chip_type != CHIP_WFR) {
			ret = hfi2_mmap_entry_insert(ucontext, fd, RCV_RHEQ,
						     rheq_size(uctxt), 0,
						     uctxt->rheq,
						     uctxt->rheq_dma,
						     &rsp.rheq_bufbase);
			if (ret)
				return ret;
		}
	}

	return uverbs_copy_to(attrs, HFI2_ATTR_USER_INFO_RSP, &rsp,
			      sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_TID_UPDATE)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_tid_info tinfo = {};
	struct hfi2_tid_update_cmd cmd;
	struct hfi2_tid_update_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_TID_UPDATE_CMD);
	if (ret)
		return ret;

	/* reserved .flags bits must be 0 */
	if (cmd.flags & HFI2_TID_UPDATE_FLAGS_RESERVED_MASK)
		return -EINVAL;
	/* reserved for now */
	if (cmd.context)
		return -EINVAL;

	/* copy to internal structure */
	tinfo.vaddr = cmd.vaddr;
	tinfo.tidlist = cmd.tidlist;
	tinfo.length = cmd.length;
	tinfo.tidcnt = cmd.tidcnt;
	tinfo.flags = cmd.flags;
	tinfo.context = cmd.context;

	ret = hfi2_user_exp_rcv_setup(fd, &tinfo, false, true);
	if (ret)
		return ret;

	rsp.length = tinfo.length;
	rsp.tidcnt = tinfo.tidcnt;

	return uverbs_copy_to(attrs, HFI2_ATTR_TID_UPDATE_RSP, &rsp,
			      sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_TID_FREE)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_tid_info tinfo = {};
	struct hfi2_tid_free_cmd cmd;
	struct hfi2_tid_free_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_TID_FREE_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	tinfo.tidlist = cmd.tidlist;
	tinfo.tidcnt = cmd.tidcnt;

	ret = hfi2_user_exp_rcv_clear(fd, &tinfo);
	if (ret)
		return ret;

	rsp.tidcnt = tinfo.tidcnt;

	return uverbs_copy_to(attrs, HFI2_ATTR_TID_FREE_RSP, &rsp, sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_CREDIT_UPD)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;

	if (!uctxt)
		return -EINVAL;
	hfi2_sc_return_credits(uctxt->sc);

	return 0;
};

static int
UVERBS_HANDLER(HFI2_METHOD_RECV_CTRL)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_recv_ctrl_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_RECV_CTRL_CMD);
	if (ret)
		return ret;

	/* verify small reserved array of u8s is zero */
	if (memcmp(cmd.reserved, &zero8, sizeof(cmd.reserved)) != 0)
		return -EINVAL;

	return hfi2_manage_rcvq(uctxt, fd->subctxt, cmd.start_stop);
};

static int
UVERBS_HANDLER(HFI2_METHOD_POLL_TYPE)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_poll_type_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_POLL_TYPE_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	uctxt->poll_type = (typeof(uctxt->poll_type))cmd.poll_type;

	return 0;
};

static int
UVERBS_HANDLER(HFI2_METHOD_ACK_EVENT)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_ack_event_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_ACK_EVENT_CMD);
	if (ret)
		return ret;

	return hfi2_user_event_ack(uctxt, fd->subctxt, cmd.event);
};

static int
UVERBS_HANDLER(HFI2_METHOD_SET_PKEY)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;
	struct hfi2_set_pkey_cmd cmd;
	int ret;

	if (!uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_SET_PKEY_CMD);
	if (ret)
		return ret;

	/* verify small reserved array of u8s is zero */
	if (memcmp(cmd.reserved, &zero8, sizeof(cmd.reserved)) != 0)
		return -EINVAL;

	return hfi2_user_set_ctxt_pkey(uctxt, cmd.pkey);
};

static int
UVERBS_HANDLER(HFI2_METHOD_CTXT_RESET)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_ctxtdata *uctxt = fd->uctxt;

	if (!uctxt)
		return -EINVAL;

	return hfi2_ctxt_reset(uctxt);
};

static int
UVERBS_HANDLER(HFI2_METHOD_TID_INVAL_READ)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_tid_info tinfo = {};
	struct hfi2_tid_inval_read_cmd cmd;
	struct hfi2_tid_inval_read_rsp rsp = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_TID_INVAL_READ_CMD);
	if (ret)
		return ret;

	if (cmd.reserved != 0)
		return -EINVAL;

	tinfo.tidlist = cmd.tidlist;
	tinfo.tidcnt = cmd.tidcnt;

	ret = hfi2_user_exp_rcv_invalid(fd, &tinfo, true);
	if (ret)
		return ret;

	rsp.tidcnt = tinfo.tidcnt;

	return uverbs_copy_to(attrs, HFI2_ATTR_TID_INVAL_READ_RSP, &rsp,
			      sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_GET_VERS)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_get_vers_rsp rsp = {};

	rsp.version = HFI2_UVERBS_ABI_VERSION;
	return uverbs_copy_to(attrs, HFI2_ATTR_GET_VERS_RSP, &rsp, sizeof(rsp));
};

static int
UVERBS_HANDLER(HFI2_METHOD_PIN_STATS)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_pin_stats_cmd cmd;
	struct hfi2_pin_stats_rsp rsp = {};
	struct hfi2_pin_stats stats = {};
	int ret;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_PIN_STATS_CMD);
	if (ret)
		return ret;

	stats.memtype = cmd.memtype;
	stats.index = cmd.index;
	ret = hfi2_get_pinning_stats(fd, &stats);
	if (ret)
		return ret;

	rsp.id = stats.id;
	rsp.cache_entries = stats.cache_entries;
	rsp.total_refcounts = stats.total_refcounts;
	rsp.total_bytes = stats.total_bytes;
	rsp.hits = stats.hits;
	rsp.misses = stats.misses;
	rsp.internal_evictions = stats.internal_evictions;
	rsp.external_evictions = stats.external_evictions;

	return uverbs_copy_to(attrs, HFI2_ATTR_PIN_STATS_RSP, &rsp,
			      sizeof(rsp));
};

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_ASSIGN_CTXT,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_ASSIGN_CTXT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_assign_ctxt_cmd),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_CTXT_INFO,
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_CTXT_INFO_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_ctxt_info_rsp),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_USER_INFO,
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_USER_INFO_RSP,
			    UVERBS_ATTR_STRUCT(struct hfi2_user_info_rsp,
					       rheq_bufbase),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_TID_UPDATE,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_TID_UPDATE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_tid_update_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_TID_UPDATE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_tid_update_rsp),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_TID_FREE,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_TID_FREE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_tid_free_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_TID_FREE_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_tid_free_rsp),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(HFI2_METHOD_CREDIT_UPD,
			    /* no arguments */
);

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_RECV_CTRL,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_RECV_CTRL_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_recv_ctrl_cmd),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_POLL_TYPE,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_POLL_TYPE_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_poll_type_cmd),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_ACK_EVENT,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_ACK_EVENT_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_ack_event_cmd),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_SET_PKEY,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_SET_PKEY_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_set_pkey_cmd),
			   UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(HFI2_METHOD_CTXT_RESET,
			    /* no arguments */
);

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_TID_INVAL_READ,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_TID_INVAL_READ_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_tid_inval_read_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_TID_INVAL_READ_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_tid_inval_read_rsp),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_GET_VERS,
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_GET_VERS_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_get_vers_rsp),
			    UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_PIN_STATS,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_PIN_STATS_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_pin_stats_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_PIN_STATS_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_pin_stats_rsp),
			    UA_MANDATORY));

static ssize_t hfi2_sdma_fd_write_iter(struct kiocb *kiocb,
				       struct iov_iter *from)
{
	struct hfi2_filedata *fd = kiocb->ki_filp->private_data;

	return hfi2_do_write_iter(fd, from);
}

static int hfi2_sdma_fd_release(struct inode *inode, struct file *filp)
{
	struct hfi2_filedata *fd = filp->private_data;

	kref_put(&fd->kref, hfi2_filedata_release);
	return 0;
}

static const struct file_operations hfi2_sdma_fd_fops = {
	.owner = THIS_MODULE,
	.write_iter = hfi2_sdma_fd_write_iter,
	.release = hfi2_sdma_fd_release,
};

static int
UVERBS_HANDLER(HFI2_METHOD_QUERY_EGR_MMAP)(struct uverbs_attr_bundle *attrs)
{
	struct hfi2_filedata *fd = fd_from_attrs(attrs);
	struct hfi2_query_egr_mmap_cmd cmd;
	struct hfi2_query_egr_mmap_rsp rsp = {};
	struct hfi2_egr_mmap_segment *segments;
	struct hfi2_user_mmap_entry *entry;
	int capacity, ret;
	u32 i = 0, max_segments, returned = 0;
	u64 offset = 0;

	if (!fd->uctxt)
		return -EINVAL;

	ret = uverbs_copy_from(&cmd, attrs, HFI2_ATTR_QUERY_EGR_MMAP_CMD);
	if (ret)
		return ret;
	if (cmd.reserved)
		return -EINVAL;

	capacity = uverbs_attr_ptr_get_array_size(
		attrs, HFI2_ATTR_QUERY_EGR_MMAP_SEGMENTS, sizeof(*segments));
	if (capacity <= 0)
		return capacity ?: -EINVAL;

	if (!fd->uctxt->egrbufs.numbufs ||
	    cmd.first_segment >= fd->uctxt->egrbufs.numbufs)
		return -EINVAL;

	max_segments = min_t(u32, capacity,
			     fd->uctxt->egrbufs.numbufs - cmd.first_segment);
	segments = uverbs_kcalloc(attrs, max_segments, sizeof(*segments));
	if (IS_ERR(segments))
		return PTR_ERR(segments);

	mutex_lock(&fd->eager_mmap_entries_lock);
	list_for_each_entry(entry, &fd->eager_mmap_entries, list) {
		u64 length = entry->rdma_entry.npages * PAGE_SIZE;

		if (i >= cmd.first_segment && returned < max_segments) {
			segments[returned].offset = offset;
			segments[returned].length = length;
			segments[returned].mmap_offset =
				rdma_user_mmap_get_offset(&entry->rdma_entry);
			returned++;
		}
		offset += length;
		i++;
	}
	mutex_unlock(&fd->eager_mmap_entries_lock);

	if (i != fd->uctxt->egrbufs.numbufs ||
	    offset != fd->uctxt->egrbufs.size)
		return -EINVAL;
	if (returned != max_segments)
		return -EINVAL;

	rsp.total_segments = i;
	rsp.returned_segments = returned;
	rsp.total_size = offset;
	ret = uverbs_copy_to(attrs, HFI2_ATTR_QUERY_EGR_MMAP_RSP, &rsp,
			     sizeof(rsp));
	if (ret)
		return ret;

	return uverbs_copy_to(attrs, HFI2_ATTR_QUERY_EGR_MMAP_SEGMENTS,
			      segments, returned * sizeof(*segments));
}

static int
UVERBS_HANDLER(HFI2_METHOD_CREATE_SDMA_FD)(struct uverbs_attr_bundle *attrs)
{
	struct ib_ucontext *ucontext = ib_uverbs_get_ucontext(attrs);
	struct rvt_ucontext *rcontext;
	struct hfi2_filedata *fd;
	int sdma_fd, ret;

	if (IS_ERR(ucontext))
		return PTR_ERR(ucontext);

	rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	fd = rcontext->priv;
	if (!fd)
		return -EINVAL;

	kref_get(&fd->kref);
	sdma_fd = anon_inode_getfd("hfi2-sdma", &hfi2_sdma_fd_fops, fd,
				   O_RDWR | O_CLOEXEC);
	if (sdma_fd < 0) {
		kref_put(&fd->kref, hfi2_filedata_release);
		return sdma_fd;
	}

	ret = uverbs_copy_to(attrs, HFI2_ATTR_SDMA_FD_RSP, &sdma_fd,
			     sizeof(sdma_fd));
	if (ret)
		close_fd(sdma_fd);

	return ret;
}

DECLARE_UVERBS_NAMED_METHOD(HFI2_METHOD_CREATE_SDMA_FD,
			    UVERBS_ATTR_PTR_OUT(HFI2_ATTR_SDMA_FD_RSP,
						UVERBS_ATTR_TYPE(__s32),
						UA_MANDATORY));

DECLARE_UVERBS_NAMED_METHOD(
	HFI2_METHOD_QUERY_EGR_MMAP,
	UVERBS_ATTR_PTR_IN(HFI2_ATTR_QUERY_EGR_MMAP_CMD,
			   UVERBS_ATTR_TYPE(struct hfi2_query_egr_mmap_cmd),
			   UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_QUERY_EGR_MMAP_RSP,
			    UVERBS_ATTR_TYPE(struct hfi2_query_egr_mmap_rsp),
			    UA_MANDATORY),
	UVERBS_ATTR_PTR_OUT(HFI2_ATTR_QUERY_EGR_MMAP_SEGMENTS,
			    UVERBS_ATTR_MIN_SIZE(sizeof(struct hfi2_egr_mmap_segment)),
			    UA_MANDATORY));

DECLARE_UVERBS_GLOBAL_METHODS(HFI2_OBJECT_DV0,
			      &UVERBS_METHOD(HFI2_METHOD_ASSIGN_CTXT),
			      &UVERBS_METHOD(HFI2_METHOD_CTXT_INFO),
			      &UVERBS_METHOD(HFI2_METHOD_USER_INFO),
			      &UVERBS_METHOD(HFI2_METHOD_TID_UPDATE),
			      &UVERBS_METHOD(HFI2_METHOD_TID_FREE),
			      &UVERBS_METHOD(HFI2_METHOD_CREDIT_UPD),
			      &UVERBS_METHOD(HFI2_METHOD_RECV_CTRL),
			      &UVERBS_METHOD(HFI2_METHOD_POLL_TYPE));

DECLARE_UVERBS_GLOBAL_METHODS(HFI2_OBJECT_DV1,
			      &UVERBS_METHOD(HFI2_METHOD_ACK_EVENT),
			      &UVERBS_METHOD(HFI2_METHOD_SET_PKEY),
			      &UVERBS_METHOD(HFI2_METHOD_CTXT_RESET),
			      &UVERBS_METHOD(HFI2_METHOD_TID_INVAL_READ),
			      &UVERBS_METHOD(HFI2_METHOD_GET_VERS),
			      &UVERBS_METHOD(HFI2_METHOD_PIN_STATS),
			      &UVERBS_METHOD(HFI2_METHOD_CREATE_SDMA_FD),
			      &UVERBS_METHOD(HFI2_METHOD_QUERY_EGR_MMAP));

const struct uapi_definition hfi2_ib_defs[] = {
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI2_OBJECT_DV0),
	UAPI_DEF_CHAIN_OBJ_TREE_NAMED(HFI2_OBJECT_DV1),
	{}
};

int hfi2_mmap(struct ib_ucontext *ucontext, struct vm_area_struct *vma)
{
	struct rvt_ucontext *rcontext =
		container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi2_filedata *fd = rcontext->priv;
	struct rdma_user_mmap_entry *rdma_entry;
	struct hfi2_user_mmap_entry *entry;
	int ret;

	/*
	 * Try to look up the offset in the rdma_user_mmap xarray.
	 * If found, this is a driver data-path buffer mmap.
	 */
	rdma_entry = rdma_user_mmap_entry_get(ucontext, vma);
	if (rdma_entry) {
		entry = to_hfi2_mmap(rdma_entry);
		ret = hfi2_do_mmap(fd, entry->mmap_flag, vma, rdma_entry,
				   ucontext);
		rdma_user_mmap_entry_put(rdma_entry);
		return ret;
	}

	return rvt_mmap(ucontext, vma);
}

void hfi2_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	kfree(to_hfi2_mmap(rdma_entry));
}
