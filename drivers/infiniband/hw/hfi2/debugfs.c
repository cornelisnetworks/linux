// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2015-2018 Intel Corporation.
 * Copyright(c) 2024 Cornelis Networks.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#include "linux/ktime.h"
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include <linux/fault-inject.h>
#include <linux/xarray.h>
#include <linux/parser.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/atomic.h>

#include "hfi2.h"
#include "trace.h"
#include "debugfs.h"
#include "qp.h"
#include "sdma.h"
#include "fault.h"
#include "cport.h"
#include <linux/slab.h>
#include <linux/atomic.h>
#include "mem_region.h"
#include "file_ops.h"
#include "bulksvc.h"
#include "dms_roce.h"

#define BULKSVC_DBG_OPEN_TIMEOUT_MS 5000


static struct dentry *hfi2_dbg_root;

#define private2dd(file) (file_inode(file)->i_private)
#define private2ppd(file) (file_inode(file)->i_private)

static void *_opcode_stats_seq_start(struct seq_file *s, loff_t *pos)
{
	struct hfi2_opcode_stats_perctx *opstats;

	if (*pos >= ARRAY_SIZE(opstats->stats))
		return NULL;
	return pos;
}

static void *_opcode_stats_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct hfi2_opcode_stats_perctx *opstats;

	++*pos;
	if (*pos >= ARRAY_SIZE(opstats->stats))
		return NULL;
	return pos;
}

static void _opcode_stats_seq_stop(struct seq_file *s, void *v)
{
}

static int opcode_stats_show(struct seq_file *s, u8 i, u64 packets, u64 bytes)
{
	if (!packets && !bytes)
		return SEQ_SKIP;
	seq_printf(s, "%02x %llu/%llu\n", i, (unsigned long long)packets,
		   (unsigned long long)bytes);

	return 0;
}

static int _opcode_stats_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos = v;
	loff_t i = *spos, j;
	u64 n_packets = 0, n_bytes = 0;
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_ctxtdata *rcd;
	int pidx;

	for (pidx = 0; pidx < dd->num_pports; pidx++) {
		struct hfi2_portrsrcs *pr = &dr->ppr[pidx];

		for (j = 0; j < pr->n_krcv_queues; j++) {
			u16 ctxt = pr->rcv_context_base + j;

			rcd = hfi2_rcd_get_by_index(dd, ctxt);
			if (rcd) {
				n_packets += rcd->opstats->stats[i].n_packets;
				n_bytes += rcd->opstats->stats[i].n_bytes;
			}
			hfi2_rcd_put(rcd);
		}
	}
	return opcode_stats_show(s, i, n_packets, n_bytes);
}

DEBUGFS_SEQ_FILE_OPS(opcode_stats);
DEBUGFS_SEQ_FILE_OPEN(opcode_stats);
DEBUGFS_FILE_OPS(opcode_stats);

static void *_tx_opcode_stats_seq_start(struct seq_file *s, loff_t *pos)
{
	return _opcode_stats_seq_start(s, pos);
}

static void *_tx_opcode_stats_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return _opcode_stats_seq_next(s, v, pos);
}

static void _tx_opcode_stats_seq_stop(struct seq_file *s, void *v)
{
}

static int _tx_opcode_stats_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos = v;
	loff_t i = *spos;
	int j;
	u64 n_packets = 0, n_bytes = 0;
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	for_each_possible_cpu(j) {
		struct hfi2_opcode_stats_perctx *s =
			per_cpu_ptr(dd->tx_opstats, j);
		n_packets += s->stats[i].n_packets;
		n_bytes += s->stats[i].n_bytes;
	}
	return opcode_stats_show(s, i, n_packets, n_bytes);
}

DEBUGFS_SEQ_FILE_OPS(tx_opcode_stats);
DEBUGFS_SEQ_FILE_OPEN(tx_opcode_stats)
DEBUGFS_FILE_OPS(tx_opcode_stats);

static void *_ctx_stats_seq_start(struct seq_file *s, loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	/* plan: iterate through all rcds, looking for kernel contexts */

	/* starting point must be in range */
	if (*pos >= dd->num_rcd)
		return NULL;

	return pos;
}

static void *_ctx_stats_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	++*pos;
	if (*pos >= dd->num_rcd)
		return NULL;

	return pos;
}

static void _ctx_stats_seq_stop(struct seq_file *s, void *v)
{
	/* nothing allocated */
}

static int _ctx_stats_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos;
	loff_t i, j;
	u64 n_packets = 0;
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct hfi2_ctxtdata *rcd;

	spos = v;
	i = *spos;

	if (i == 0)
		seq_puts(s, "Ctx:npkts\n");

	rcd = hfi2_rcd_get_by_index(dd, i);
	if (!rcd)
		return 0;

	/* only kernel contexts have opstats */
	if (rcd->opstats) {
		for (j = 0; j < ARRAY_SIZE(rcd->opstats->stats); j++)
			n_packets += rcd->opstats->stats[j].n_packets;
	}

	hfi2_rcd_put(rcd);

	if (!n_packets)
		return 0;

	seq_printf(s, "  %llu:%llu\n", i, n_packets);
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(ctx_stats);
DEBUGFS_SEQ_FILE_OPEN(ctx_stats)
DEBUGFS_FILE_OPS(ctx_stats);

static void *_qp_stats_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(RCU)
{
	struct rvt_qp_iter *iter;
	loff_t n = *pos;

	iter = rvt_qp_iter_init(s->private, 0, NULL);

	/* stop calls rcu_read_unlock */
	rcu_read_lock();

	if (!iter)
		return NULL;

	do {
		if (rvt_qp_iter_next(iter)) {
			kfree(iter);
			return NULL;
		}
	} while (n--);

	return iter;
}

static void *_qp_stats_seq_next(struct seq_file *s, void *iter_ptr, loff_t *pos)
	__must_hold(RCU)
{
	struct rvt_qp_iter *iter = iter_ptr;

	(*pos)++;

	if (rvt_qp_iter_next(iter)) {
		kfree(iter);
		return NULL;
	}

	return iter;
}

static void _qp_stats_seq_stop(struct seq_file *s, void *iter_ptr)
	__releases(RCU)
{
	kfree(iter_ptr);
	rcu_read_unlock();
}

static int _qp_stats_seq_show(struct seq_file *s, void *iter_ptr)
{
	struct rvt_qp_iter *iter = iter_ptr;

	if (!iter)
		return 0;

	hfi2_qp_iter_print(s, iter);

	return 0;
}

DEBUGFS_SEQ_FILE_OPS(qp_stats);
DEBUGFS_SEQ_FILE_OPEN(qp_stats)
DEBUGFS_FILE_OPS(qp_stats);

static void *_sdes_seq_start(struct seq_file *s, loff_t *pos)
{
	struct hfi2_ibdev *ibd;
	struct hfi2_devdata *dd;

	ibd = (struct hfi2_ibdev *)s->private;
	dd = dd_from_dev(ibd);
	if (!dd->per_sdma || *pos >= dd->num_sdma)
		return NULL;
	return pos;
}

static void *_sdes_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	++*pos;
	if (!dd->per_sdma || *pos >= dd->num_sdma)
		return NULL;
	return pos;
}

static void _sdes_seq_stop(struct seq_file *s, void *v)
{
}

static int _sdes_seq_show(struct seq_file *s, void *v)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	loff_t *spos = v;
	loff_t i = *spos;

	/*
	 * Dump every engine in per_sdma[], including the ones loaned to
	 * bulksvc.  Loaning only narrows [first_sdma_engine, last_sdma_engine)
	 * and moves the engine's references to bulksvc; the sde itself stays
	 * live in per_sdma[], so dumping it here needs no bulksvc bookkeeping.
	 */
	if (dd->per_sdma && i >= 0 && i < dd->num_sdma && dd->per_sdma[i].dd)
		hfi2_sdma_seqfile_dump_sde(s, &dd->per_sdma[i]);

	return 0;
}

DEBUGFS_SEQ_FILE_OPS(sdes);
DEBUGFS_SEQ_FILE_OPEN(sdes)
DEBUGFS_FILE_OPS(sdes);

static void *_sdma_outstanding_limit_cnt_seq_start(struct seq_file *s,
						   loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	if (!dd->per_sdma || *pos >= dd->num_sdma)
		return NULL;
	if (!dd->sdma_limit_outstanding_pkts)
		return NULL;
	return pos;
}

static void *_sdma_outstanding_limit_cnt_seq_next(struct seq_file *s, void *v,
						  loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	++*pos;
	if (!dd->per_sdma || *pos >= dd->num_sdma)
		return NULL;
	return pos;
}

static void _sdma_outstanding_limit_cnt_seq_stop(struct seq_file *s, void *v)
{
}

/* common function for which engines are displayed or cleared */
static bool sdma_limit_cnt_engine_displayed(struct hfi2_devdata *dd, loff_t i)
{
	struct hfi2_devrsrcs *dr = &dd->rsrcs;

	return (i >= dr->first_sdma_engine && i < dr->last_sdma_engine);
}

static int _sdma_outstanding_limit_cnt_seq_show(struct seq_file *s, void *v)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	loff_t *spos = v;
	loff_t i = *spos;
	struct sdma_engine *sde;

	if (!dd->per_sdma || i >= dd->num_sdma)
		return 0;

	sde = &dd->per_sdma[i];

	if (sdma_limit_cnt_engine_displayed(dd, i))
		sdma_seqfile_dump_sde_limit_cnt(s, sde);
	return 0;
}

/*
 * Any write to sdma_outstanding_limit_cnt clears the outstanding-limit counter
 * for every engine displayed by the read path.  The write payload is ignored -
 * the presence of a write is the entire command.  Each counter is zeroed under
 * sde->tail_lock so we synchronize with the increment site in the SDMA
 * submission path (see outstanding_limit_cnt++ in sdma.c).
 */
static ssize_t sdma_outstanding_limit_cnt_write(struct file *file,
						const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct hfi2_ibdev *ibd = seq->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct sdma_engine *sde;
	unsigned long flags;
	loff_t i;

	if (!dd->per_sdma)
		return count;
	if (!dd->sdma_limit_outstanding_pkts)
		return count;

	for (i = 0; i < dd->num_sdma; i++) {
		if (!sdma_limit_cnt_engine_displayed(dd, i))
			continue;

		sde = &dd->per_sdma[i];
		spin_lock_irqsave(&sde->tail_lock, flags);
		sde->outstanding_limit_cnt = 0;
		spin_unlock_irqrestore(&sde->tail_lock, flags);
	}

	return count;
}

DEBUGFS_SEQ_FILE_OPS(sdma_outstanding_limit_cnt);
DEBUGFS_SEQ_FILE_OPEN(sdma_outstanding_limit_cnt)
/*
 * Explicit file_operations (instead of DEBUGFS_FILE_OPS) so we can add a write
 * handler while preserving the standard seq-file open/read/llseek/release.
 */
static const struct file_operations _sdma_outstanding_limit_cnt_file_ops = {
	.owner   = THIS_MODULE,
	.open    = _sdma_outstanding_limit_cnt_open,
	.read    = seq_read,
	.write   = sdma_outstanding_limit_cnt_write,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void *_rcds_seq_start(struct seq_file *s, loff_t *pos)
{
	struct hfi2_ibdev *ibd;
	struct hfi2_devdata *dd;

	ibd = (struct hfi2_ibdev *)s->private;
	dd = dd_from_dev(ibd);
	if (!dd->rcd || *pos >= dd->num_rcd)
		return NULL;
	return pos;
}

static void *_rcds_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	++*pos;
	if (!dd->rcd || *pos >= dd->num_rcd)
		return NULL;
	return pos;
}

static void _rcds_seq_stop(struct seq_file *s, void *v)
{
}

static int _rcds_seq_show(struct seq_file *s, void *v)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct hfi2_ctxtdata *rcd;
	loff_t *spos = v;
	loff_t i = *spos;

	rcd = hfi2_rcd_get_by_index(dd, i);
	if (rcd)
		hfi2_seqfile_dump_rcd(s, rcd);
	hfi2_rcd_put(rcd);
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(rcds);
DEBUGFS_SEQ_FILE_OPEN(rcds)
DEBUGFS_FILE_OPS(rcds);

static void *_pios_seq_start(struct seq_file *s, loff_t *pos)
{
	struct hfi2_ibdev *ibd;
	struct hfi2_devdata *dd;

	ibd = (struct hfi2_ibdev *)s->private;
	dd = dd_from_dev(ibd);
	if (!dd->send_contexts || *pos >= dd->num_send_contexts)
		return NULL;
	return pos;
}

static void *_pios_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);

	++*pos;
	if (!dd->send_contexts || *pos >= dd->num_send_contexts)
		return NULL;
	return pos;
}

static void _pios_seq_stop(struct seq_file *s, void *v)
{
}

static int _pios_seq_show(struct seq_file *s, void *v)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct send_context_info *sci;
	loff_t *spos = v;
	loff_t i = *spos;
	unsigned long flags;

	spin_lock_irqsave(&dd->sc_lock, flags);
	sci = &dd->send_contexts[i];
	hfi2_seqfile_dump_sci(s, i, sci);
	spin_unlock_irqrestore(&dd->sc_lock, flags);
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(pios);
DEBUGFS_SEQ_FILE_OPEN(pios)
DEBUGFS_FILE_OPS(pios);

/* read the per-device counters */
static ssize_t dev_counters_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	u64 *counters;
	size_t avail;
	struct hfi2_devdata *dd;
	ssize_t rval;

	dd = private2dd(file);
	avail = hfi2_read_cntrs(dd, NULL, &counters);
	rval = simple_read_from_buffer(buf, count, ppos, counters, avail);
	return rval;
}

/* read the per-device counters */
static ssize_t dev_names_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	char *names;
	size_t avail;
	struct hfi2_devdata *dd;
	ssize_t rval;

	dd = private2dd(file);
	avail = hfi2_read_cntrs(dd, &names, NULL);
	rval = simple_read_from_buffer(buf, count, ppos, names, avail);
	return rval;
}

struct counter_info {
	char *name;
	const struct file_operations ops;
};

/*
 * Could use file_inode(file)->i_ino to figure out which file,
 * instead of separate routine for each, but for now, this works...
 */

/* read the per-port names (same for each port) */
static ssize_t portnames_read(struct file *file, char __user *buf, size_t count,
			      loff_t *ppos)
{
	char *names;
	size_t avail;
	struct hfi2_devdata *dd;
	ssize_t rval;

	dd = private2dd(file);
	avail = hfi2_read_portcntrs(dd->pport, &names, NULL);
	rval = simple_read_from_buffer(buf, count, ppos, names, avail);
	return rval;
}

/* read the per-port counters */
static ssize_t portcntrs_debugfs_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	u64 *counters;
	size_t avail;
	struct hfi2_pportdata *ppd;
	ssize_t rval;

	ppd = private2ppd(file);
	avail = hfi2_read_portcntrs(ppd, NULL, &counters);
	rval = simple_read_from_buffer(buf, count, ppos, counters, avail);
	return rval;
}

static void check_dyn_flag(u64 scratch0, char *p, int size, int *used,
			   int this_hfi, int hfi, u32 flag, const char *what)
{
	u32 mask;

	mask = flag << (hfi ? CR_DYN_SHIFT : 0);
	if (scratch0 & mask) {
		*used += scnprintf(p + *used, size - *used,
				   "  0x%08x - HFI%d %s in use, %s device\n",
				   mask, hfi, what,
				   this_hfi == hfi ? "this" : "other");
	}
}

static ssize_t asic_flags_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd;
	u64 scratch0;
	char *tmp;
	int ret = 0;
	int size;
	int used;
	int i;

	dd = private2dd(file);
	size = PAGE_SIZE;
	used = 0;
	tmp = kmalloc(size, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	scratch0 = hfi2_read_csr(dd, ASIC_CFG_SCRATCH);
	used += scnprintf(tmp + used, size - used,
			  "Resource flags: 0x%016llx\n", scratch0);

	/* check permanent flag */
	if (scratch0 & CR_THERM_INIT) {
		used += scnprintf(tmp + used, size - used,
				  "  0x%08x - thermal monitoring initialized\n",
				  (u32)CR_THERM_INIT);
	}

	/* check each dynamic flag on each HFI */
	for (i = 0; i < 2; i++) {
		check_dyn_flag(scratch0, tmp, size, &used, dd->hfi2_id, i,
			       CR_SBUS, "SBus");
		check_dyn_flag(scratch0, tmp, size, &used, dd->hfi2_id, i,
			       CR_EPROM, "EPROM");
		check_dyn_flag(scratch0, tmp, size, &used, dd->hfi2_id, i,
			       CR_I2C1, "i2c chain 1");
		check_dyn_flag(scratch0, tmp, size, &used, dd->hfi2_id, i,
			       CR_I2C2, "i2c chain 2");
	}
	used += scnprintf(tmp + used, size - used, "Write bits to clear\n");

	ret = simple_read_from_buffer(buf, count, ppos, tmp, used);
	kfree(tmp);
	return ret;
}

static ssize_t asic_flags_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd;
	char *buff;
	int ret;
	unsigned long long value;
	u64 scratch0;
	u64 clear;

	dd = private2dd(file);

	if (!dd->asic_data)
		return -EINVAL;

	/* zero terminate and read the expected integer */
	buff = memdup_user_nul(buf, count);
	if (IS_ERR(buff))
		return PTR_ERR(buff);

	ret = kstrtoull(buff, 0, &value);
	if (ret)
		goto do_free;
	clear = value;

	/* obtain exclusive access */
	mutex_lock(&dd->asic_data->asic_resource_mutex);
	ret = hfi2_acquire_hw_mutex(dd);
	if (ret) {
		mutex_unlock(&dd->asic_data->asic_resource_mutex);
		goto do_free;
	}

	scratch0 = hfi2_read_csr(dd, ASIC_CFG_SCRATCH);
	scratch0 &= ~clear;
	hfi2_write_csr(dd, ASIC_CFG_SCRATCH, scratch0);
	/* force write to be visible to other HFI on another OS */
	(void)hfi2_read_csr(dd, ASIC_CFG_SCRATCH);

	hfi2_release_hw_mutex(dd);
	mutex_unlock(&dd->asic_data->asic_resource_mutex);

	/* return the number of bytes written */
	ret = count;

do_free:
	kfree(buff);
	return ret;
}

/* read the dc8051 memory */
static ssize_t dc8051_memory_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct hfi2_pportdata *ppd = private2ppd(file);
	ssize_t rval;
	void *tmp;
	loff_t start, end;

	/* the checks below expect the position to be positive */
	if (*ppos < 0)
		return -EINVAL;

	tmp = kzalloc(DC8051_DATA_MEM_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	/*
	 * Fill in the requested portion of the temporary buffer from the
	 * 8051 memory.  The 8051 memory read is done in terms of 8 bytes.
	 * Adjust start and end to fit.  Skip reading anything if out of
	 * range.
	 */
	start = *ppos & ~0x7; /* round down */
	if (start < DC8051_DATA_MEM_SIZE) {
		end = (*ppos + count + 7) & ~0x7; /* round up */
		if (end > DC8051_DATA_MEM_SIZE)
			end = DC8051_DATA_MEM_SIZE;
		rval = hfi2_read_8051_data(ppd->dd, start, end - start,
				      (u64 *)(tmp + start));
		if (rval)
			goto done;
	}

	rval = simple_read_from_buffer(buf, count, ppos, tmp,
				       DC8051_DATA_MEM_SIZE);
done:
	kfree(tmp);
	return rval;
}

static ssize_t debugfs_lcb_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct hfi2_pportdata *ppd = private2ppd(file);
	unsigned long total, csr_off;
	u64 data;

	if (*ppos < 0)
		return -EINVAL;
	/* only read 8 byte quantities */
	if ((count % 8) != 0)
		return -EINVAL;
	/* offset must be 8-byte aligned */
	if ((*ppos % 8) != 0)
		return -EINVAL;
	/* do nothing if out of range or zero count */
	if (*ppos >= (LCB_END - LCB_START) || !count)
		return 0;
	/* reduce count if needed */
	if (*ppos + count > LCB_END - LCB_START)
		count = (LCB_END - LCB_START) - *ppos;

	csr_off = LCB_START + *ppos;
	for (total = 0; total < count; total += 8, csr_off += 8) {
		if (hfi2_read_lcb_csr(ppd, csr_off, (u64 *)&data))
			break; /* failed */
		if (put_user(data, (unsigned long __user *)(buf + total)))
			break;
	}
	*ppos += total;
	return total;
}

static ssize_t debugfs_lcb_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct hfi2_pportdata *ppd = private2ppd(file);
	unsigned long total, csr_off, data;

	if (*ppos < 0)
		return -EINVAL;
	/* only write 8 byte quantities */
	if ((count % 8) != 0)
		return -EINVAL;
	/* offset must be 8-byte aligned */
	if ((*ppos % 8) != 0)
		return -EINVAL;
	/* do nothing if out of range or zero count */
	if (*ppos >= (LCB_END - LCB_START) || !count)
		return 0;
	/* reduce count if needed */
	if (*ppos + count > LCB_END - LCB_START)
		count = (LCB_END - LCB_START) - *ppos;

	csr_off = LCB_START + *ppos;
	for (total = 0; total < count; total += 8, csr_off += 8) {
		if (get_user(data, (unsigned long __user *)(buf + total)))
			break;
		if (hfi2_write_lcb_csr(ppd, csr_off, data))
			break; /* failed */
	}
	*ppos += total;
	return total;
}

/*
 * read the per-port QSFP data for pp
 */
static ssize_t qsfp_debugfs_dump(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct hfi2_pportdata *ppd;
	char *tmp;
	int ret;

	ppd = private2ppd(file);
	tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	ret = hfi2_qsfp_dump(ppd, tmp, PAGE_SIZE);
	if (ret > 0)
		ret = simple_read_from_buffer(buf, count, ppos, tmp, ret);
	kfree(tmp);
	return ret;
}

/* Do an i2c write operation on the chain for the given HFI. */
static ssize_t __i2c_debugfs_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos, u32 target)
{
	struct hfi2_pportdata *ppd;
	char *buff;
	int ret;
	int i2c_addr;
	int offset;
	int total_written;

	ppd = private2ppd(file);

	/* byte offset format: [offsetSize][i2cAddr][offsetHigh][offsetLow] */
	i2c_addr = (*ppos >> 16) & 0xffff;
	offset = *ppos & 0xffff;

	/* explicitly reject invalid address 0 to catch cp and cat */
	if (i2c_addr == 0)
		return -EINVAL;

	/* i2c_bus_read()/i2c_bus_write() take a u16 length */
	if (count > U16_MAX)
		return -EINVAL;

	buff = memdup_user(buf, count);
	if (IS_ERR(buff))
		return PTR_ERR(buff);

	total_written = hfi2_i2c_write(ppd, target, i2c_addr, offset, buff, count);
	if (total_written < 0) {
		ret = total_written;
		goto _free;
	}

	*ppos += total_written;

	ret = total_written;

_free:
	kfree(buff);
	return ret;
}

/* Do an i2c write operation on chain for HFI 0. */
static ssize_t i2c1_debugfs_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	return __i2c_debugfs_write(file, buf, count, ppos, 0);
}

/* Do an i2c write operation on chain for HFI 1. */
static ssize_t i2c2_debugfs_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	return __i2c_debugfs_write(file, buf, count, ppos, 1);
}

/* Do an i2c read operation on the chain for the given HFI. */
static ssize_t __i2c_debugfs_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos, u32 target)
{
	struct hfi2_pportdata *ppd;
	char *buff;
	int ret;
	int i2c_addr;
	int offset;
	int total_read;

	ppd = private2ppd(file);

	/* byte offset format: [offsetSize][i2cAddr][offsetHigh][offsetLow] */
	i2c_addr = (*ppos >> 16) & 0xffff;
	offset = *ppos & 0xffff;

	/* explicitly reject invalid address 0 to catch cp and cat */
	if (i2c_addr == 0)
		return -EINVAL;

	/* i2c_bus_read()/i2c_bus_write() take a u16 length */
	if (count > U16_MAX)
		return -EINVAL;

	buff = kmalloc(count, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	total_read = hfi2_i2c_read(ppd, target, i2c_addr, offset, buff, count);
	if (total_read < 0) {
		ret = total_read;
		goto _free;
	}

	*ppos += total_read;

	ret = copy_to_user(buf, buff, total_read);
	if (ret > 0) {
		ret = -EFAULT;
		goto _free;
	}

	ret = total_read;

_free:
	kfree(buff);
	return ret;
}

/* Do an i2c read operation on chain for HFI 0. */
static ssize_t i2c1_debugfs_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return __i2c_debugfs_read(file, buf, count, ppos, 0);
}

/* Do an i2c read operation on chain for HFI 1. */
static ssize_t i2c2_debugfs_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	return __i2c_debugfs_read(file, buf, count, ppos, 1);
}

/* Do a QSFP write operation on the i2c chain for the given HFI. */
static ssize_t __qsfp_debugfs_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos, u32 target)
{
	struct hfi2_pportdata *ppd;
	char *buff;
	int ret;
	int total_written;

	if (*ppos + count > QSFP_PAGESIZE * 4) /* base page + page00-page03 */
		return -EINVAL;

	ppd = private2ppd(file);

	buff = memdup_user(buf, count);
	if (IS_ERR(buff))
		return PTR_ERR(buff);

	total_written = hfi2_qsfp_write(ppd, target, *ppos, buff, count);
	if (total_written < 0) {
		ret = total_written;
		goto _free;
	}

	*ppos += total_written;

	ret = total_written;

_free:
	kfree(buff);
	return ret;
}

/* Do a QSFP write operation on i2c chain for HFI 0. */
static ssize_t qsfp1_debugfs_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return __qsfp_debugfs_write(file, buf, count, ppos, 0);
}

/* Do a QSFP write operation on i2c chain for HFI 1. */
static ssize_t qsfp2_debugfs_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	return __qsfp_debugfs_write(file, buf, count, ppos, 1);
}

/* Do a QSFP read operation on the i2c chain for the given HFI. */
static ssize_t __qsfp_debugfs_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos, u32 target)
{
	struct hfi2_pportdata *ppd;
	char *buff;
	int ret;
	int total_read;

	if (*ppos + count > QSFP_PAGESIZE * 4) { /* base page + page00-page03 */
		ret = -EINVAL;
		goto _return;
	}

	ppd = private2ppd(file);

	buff = kmalloc(count, GFP_KERNEL);
	if (!buff) {
		ret = -ENOMEM;
		goto _return;
	}

	total_read = hfi2_qsfp_read(ppd, target, *ppos, buff, count);
	if (total_read < 0) {
		ret = total_read;
		goto _free;
	}

	*ppos += total_read;

	ret = copy_to_user(buf, buff, total_read);
	if (ret > 0) {
		ret = -EFAULT;
		goto _free;
	}

	ret = total_read;

_free:
	kfree(buff);
_return:
	return ret;
}

/* Do a QSFP read operation on i2c chain for HFI 0. */
static ssize_t qsfp1_debugfs_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	return __qsfp_debugfs_read(file, buf, count, ppos, 0);
}

/* Do a QSFP read operation on i2c chain for HFI 1. */
static ssize_t qsfp2_debugfs_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	return __qsfp_debugfs_read(file, buf, count, ppos, 1);
}

static int __i2c_debugfs_open(struct inode *in, struct file *fp, u32 target)
{
	struct hfi2_pportdata *ppd;

	ppd = private2ppd(fp);

	return hfi2_acquire_chip_resource(ppd->dd, i2c_target(target), 0);
}

static int i2c1_debugfs_open(struct inode *in, struct file *fp)
{
	return __i2c_debugfs_open(in, fp, 0);
}

static int i2c2_debugfs_open(struct inode *in, struct file *fp)
{
	return __i2c_debugfs_open(in, fp, 1);
}

static int __i2c_debugfs_release(struct inode *in, struct file *fp, u32 target)
{
	struct hfi2_pportdata *ppd;

	ppd = private2ppd(fp);

	hfi2_release_chip_resource(ppd->dd, i2c_target(target));

	return 0;
}

static int i2c1_debugfs_release(struct inode *in, struct file *fp)
{
	return __i2c_debugfs_release(in, fp, 0);
}

static int i2c2_debugfs_release(struct inode *in, struct file *fp)
{
	return __i2c_debugfs_release(in, fp, 1);
}

static int __qsfp_debugfs_open(struct inode *in, struct file *fp, u32 target)
{
	struct hfi2_pportdata *ppd;

	ppd = private2ppd(fp);

	return hfi2_acquire_chip_resource(ppd->dd, i2c_target(target), 0);
}

static int qsfp1_debugfs_open(struct inode *in, struct file *fp)
{
	return __qsfp_debugfs_open(in, fp, 0);
}

static int qsfp2_debugfs_open(struct inode *in, struct file *fp)
{
	return __qsfp_debugfs_open(in, fp, 1);
}

static int __qsfp_debugfs_release(struct inode *in, struct file *fp, u32 target)
{
	struct hfi2_pportdata *ppd;

	ppd = private2ppd(fp);

	hfi2_release_chip_resource(ppd->dd, i2c_target(target));

	return 0;
}

static int qsfp1_debugfs_release(struct inode *in, struct file *fp)
{
	return __qsfp_debugfs_release(in, fp, 0);
}

static int qsfp2_debugfs_release(struct inode *in, struct file *fp)
{
	return __qsfp_debugfs_release(in, fp, 1);
}

#define EXPROM_WRITE_ENABLE BIT_ULL(14)

static bool exprom_wp_disabled;

static int exprom_wp_set(struct hfi2_devdata *dd, bool disable)
{
	u64 gpio_val = 0;

	if (disable) {
		gpio_val = EXPROM_WRITE_ENABLE;
		exprom_wp_disabled = true;
		dd_dev_info(dd, "Disable Expansion ROM Write Protection\n");
	} else {
		exprom_wp_disabled = false;
		dd_dev_info(dd, "Enable Expansion ROM Write Protection\n");
	}

	hfi2_write_csr(dd, ASIC_GPIO_OUT, gpio_val);
	hfi2_write_csr(dd, ASIC_GPIO_OE, gpio_val);

	return 0;
}

static ssize_t exprom_wp_debugfs_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t exprom_wp_debugfs_write(struct file *file,
				       const char __user *buf, size_t count,
				       loff_t *ppos)
{
	struct hfi2_pportdata *ppd = private2ppd(file);
	char cdata;

	if (count != 1)
		return -EINVAL;
	if (get_user(cdata, buf))
		return -EFAULT;
	if (cdata == '0')
		exprom_wp_set(ppd->dd, false);
	else if (cdata == '1')
		exprom_wp_set(ppd->dd, true);
	else
		return -EINVAL;

	return 1;
}

static unsigned long exprom_in_use;

static int exprom_wp_debugfs_open(struct inode *in, struct file *fp)
{
	if (test_and_set_bit(0, &exprom_in_use))
		return -EBUSY;

	return 0;
}

static int exprom_wp_debugfs_release(struct inode *in, struct file *fp)
{
	struct hfi2_pportdata *ppd = private2ppd(fp);

	if (exprom_wp_disabled)
		exprom_wp_set(ppd->dd, false);
	clear_bit(0, &exprom_in_use);

	return 0;
}

#define DEBUGFS_OPS(nm, readroutine, writeroutine)                             \
	{                                                                      \
		.name = nm, .ops = {                                           \
			.owner = THIS_MODULE,                                  \
			.read = readroutine,                                   \
			.write = writeroutine,                                 \
			.llseek = generic_file_llseek,                         \
		},                                                             \
	}

#define DEBUGFS_XOPS(nm, readf, writef, openf, releasef) \
	{                                                \
		.name = nm,                              \
		.ops = { .owner = THIS_MODULE,           \
			 .read = readf,                  \
			 .write = writef,                \
			 .llseek = generic_file_llseek,  \
			 .open = openf,                  \
			 .release = releasef },          \
	}

static const struct counter_info cntr_ops[] = {
	DEBUGFS_OPS("counter_names", dev_names_read, NULL),
	DEBUGFS_OPS("counters", dev_counters_read, NULL),
	DEBUGFS_OPS("portcounter_names", portnames_read, NULL),
};

static const struct counter_info wfr_cntr_ops[] = {
	DEBUGFS_OPS("asic_flags", asic_flags_read, asic_flags_write),
};

static const struct counter_info port_cntr_ops[] = {
	DEBUGFS_OPS("port%dcounters", portcntrs_debugfs_read, NULL),
};

static const struct counter_info wfr_port_cntr_ops[] = {
	DEBUGFS_XOPS("i2c1", i2c1_debugfs_read, i2c1_debugfs_write,
		     i2c1_debugfs_open, i2c1_debugfs_release),
	DEBUGFS_XOPS("i2c2", i2c2_debugfs_read, i2c2_debugfs_write,
		     i2c2_debugfs_open, i2c2_debugfs_release),
	DEBUGFS_OPS("qsfp_dump%d", qsfp_debugfs_dump, NULL),
	DEBUGFS_XOPS("qsfp1", qsfp1_debugfs_read, qsfp1_debugfs_write,
		     qsfp1_debugfs_open, qsfp1_debugfs_release),
	DEBUGFS_XOPS("qsfp2", qsfp2_debugfs_read, qsfp2_debugfs_write,
		     qsfp2_debugfs_open, qsfp2_debugfs_release),
	DEBUGFS_XOPS("exprom_wp", exprom_wp_debugfs_read,
		     exprom_wp_debugfs_write, exprom_wp_debugfs_open,
		     exprom_wp_debugfs_release),
	DEBUGFS_OPS("dc8051_memory", dc8051_memory_read, NULL),
	DEBUGFS_OPS("lcb", debugfs_lcb_read, debugfs_lcb_write),
};

static void *_sdma_cpu_list_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= num_online_cpus())
		return NULL;

	return pos;
}

static void *_sdma_cpu_list_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	++*pos;
	if (*pos >= num_online_cpus())
		return NULL;

	return pos;
}

static void _sdma_cpu_list_seq_stop(struct seq_file *s, void *v)
{
	/* nothing allocated */
}

static int _sdma_cpu_list_seq_show(struct seq_file *s, void *v)
{
	struct hfi2_ibdev *ibd = (struct hfi2_ibdev *)s->private;
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	loff_t *spos = v;
	loff_t i = *spos;

	hfi2_sdma_seqfile_dump_cpu_list(s, dd, (unsigned long)i);
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(sdma_cpu_list);
DEBUGFS_SEQ_FILE_OPEN(sdma_cpu_list)
DEBUGFS_FILE_OPS(sdma_cpu_list);

static ssize_t link_debug_read(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	return 0;
}

static void fake_linkup(struct hfi2_devdata *dd, int pidx)
{
	struct hfi2_pportdata *ppd;

	if (pidx < 0 || pidx >= dd->num_pports) {
		pr_info("%s: invalid port index %d\n", __func__, pidx);
		return;
	}
	ppd = &dd->pport[pidx];

	pr_info("%s: fake linkup port index %d\n", __func__, pidx);
	ppd->host_link_state = HLS_UP_INIT;
	hfi2_handle_linkup_change(ppd, 1);
}

static void fake_linkdown(struct hfi2_devdata *dd, int pidx)
{
	struct hfi2_pportdata *ppd;

	if (pidx < 0 || pidx >= dd->num_pports) {
		pr_info("%s: invalid port index %d\n", __func__, pidx);
		return;
	}
	ppd = &dd->pport[pidx];

	pr_info("%s: fake linkdown port index %d\n", __func__, pidx);
	ppd->host_link_state = HLS_DN_OFFLINE;
	hfi2_handle_linkup_change(ppd, 0);
}

static void fake_active(struct hfi2_devdata *dd, int pidx)
{
	struct hfi2_pportdata *ppd;
	struct ib_event event = { 0 };
	u32 lid;
	u8 lmc;

	if (pidx < 0 || pidx >= dd->num_pports) {
		pr_info("%s: invalid port index %d\n", __func__, pidx);
		return;
	}
	ppd = &dd->pport[pidx];

	/* IB Port 1 = LID 1, IB Port 2 = LID 2 */
	lid = pidx + 1;
	lmc = 0x0; /* only allow 1 */

	pr_info("%s: fake active port index %d, lid %d (with hfi2_set_mtu call)\n",
		__func__, pidx, lid);

	/*
	 * From __subn_set_opa_portinfo().  In there, this comes after
	 * call to hfi2_set_lid().
	 *
	 * Need to set SendCtxtCreditCtrl.  Can be set after setting
	 * host_link_state, but it may be simpler to do it before.
	 */
	hfi2_set_mtu(ppd);

	/* swiped from __subn_set_opa_portinfo() */
	hfi2_set_lid(ppd, lid, lmc);

	ppd->host_link_state = HLS_UP_ACTIVE;

	event.device = &dd->verbs_dev.rdi.ibdev;
	event.element.port_num = pidx + 1;
	event.event = IB_EVENT_LID_CHANGE;
	ib_dispatch_event(&event);
	ppd->guids[HFI2_PORT_GUID_INDEX + 1] = be64_to_cpu(OPA_MAKE_ID(lid));
	event.event = IB_EVENT_GID_CHANGE;
	ib_dispatch_event(&event);

	/* swiped from hfi2_set_link_state - sorta.  hfi2_go_port_active() is new in this
	 * stack of patches
	 */
	hfi2_go_port_active(ppd);
}

static ssize_t link_debug_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd = file->private_data;
	char buf[128];
	size_t buf_size;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = 0;

	if (strcmp(buf, "linkup0\n") == 0)
		fake_linkup(dd, 0);
	else if (strcmp(buf, "linkup1\n") == 0)
		fake_linkup(dd, 1);
	else if (strcmp(buf, "linkdown0\n") == 0)
		fake_linkdown(dd, 0);
	else if (strcmp(buf, "linkdown1\n") == 0)
		fake_linkdown(dd, 1);
	else if (strcmp(buf, "active0\n") == 0)
		fake_active(dd, 0);
	else if (strcmp(buf, "active1\n") == 0)
		fake_active(dd, 1);
	else
		pr_info("%s: unknown command \"%s\"\n", __func__, buf);

	return count;
}

static const struct file_operations _link_debug_ops = {
	.open = simple_open,
	.read = link_debug_read,
	.write = link_debug_write,
	.llseek = default_llseek,
};


static int roce_stats_show(struct seq_file *s, void *v)
{
	hfi2_dms_roce_stats_print((struct hfi2_devdata *)s->private, s);
	return 0;
}

static int roce_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, roce_stats_show, inode->i_private);
}

static const struct file_operations _roce_stats_ops = {
	.open = roce_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
static ssize_t cport_ping_read(struct file *file, char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd = file->private_data;
	char buf[16];
	loff_t pos = *ppos;
	int len;

	if (pos < 0 || !count)
		return -EINVAL;

	len = snprintf(buf, sizeof(buf), "%u", atomic_read(&dd->cport->nping));
	if (pos >= len)
		return 0;
	if (count > len - pos)
		count = len - pos;
	if (copy_to_user(user_buf, buf + *ppos, count))
		return -EFAULT;

	*ppos += count;
	return count;
}

static ssize_t cport_ping_write(struct file *file, const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd = file->private_data;
	char buf[16];
	char *start = buf;
	size_t buf_size;
	unsigned int value;
	int rc;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = 0;
	while (*start == ' ')
		start++;

	rc = kstrtouint(start, 0, &value);
	if (rc)
		return -EINVAL;

	rc = hfi2_cport_ping_start(dd, value);
	if (rc)
		return rc;
	return count;
}

static const struct file_operations _cport_ping_ops = {
	.open = simple_open,
	.read = cport_ping_read,
	.write = cport_ping_write,
	.llseek = default_llseek,
};

static void add_port_files(struct dentry *root, struct hfi2_pportdata *ppd,
			   const struct counter_info *port_ops, int num_ops)
{
	char name[64];
	int i;

	for (i = 0; i < num_ops; i++) {
		snprintf(name, sizeof(name), port_ops[i].name, ppd->port);
		debugfs_create_file(name, !port_ops[i].ops.write ? 0444 : 0644,
				    root, ppd, &port_ops[i].ops);
	}
}



static const char * const _pkt_drop_type_names[] = {
	"read_start",
	"write_start",
	"write_start_eager",
	"data_start",
	"data_start_eager",
	"data_request",
	"data",
	"ack",
	"nack",
	"status_response",
	"status_request",
	"read_start_speculative",
	"data_speculative",
	"read_start_replay",
	"write_start_replay",
	"data_request_replay",
	"data_replay",
	"write_start_tiny",
};


static int _pkt_drop_parse_type(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(_pkt_drop_type_names); i++) {
		if (strcmp(name, _pkt_drop_type_names[i]) == 0)
			return i;
	}
	return -1;
}


static ssize_t packet_drop_read(struct file *file, char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd = file->private_data;
	struct hfi2_bulksvc *svc = dd->bulksvc;
	char *buf;
	int len = 0;
	int i;
	ssize_t ret;
	u64 total_dropped = 0, total_delivered = 0;

	if (!svc)
		return -ENODEV;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len += scnprintf(buf + len, PAGE_SIZE - len,
		"%-14s %10s %14s %14s %14s\n",
		"Type", "Cfg.Count", "Freq%", "Dropped", "Delivered");

	for (i = 0; i < ARRAY_SIZE(_pkt_drop_type_names); i++) {
		struct hfi2_dms *pdms = hfi2_bulksvc_primary_dms(svc);
		u32 freq = READ_ONCE(pdms->packet_drop.entries[i].frequency_bp);
		u32 pct_int = freq / 10000000;
		u32 pct_frac = freq % 10000000;
		u64 dropped = 0, delivered = 0;
		bool inf = false;
		long cnt = 0;

		for (u32 k = 0; k < svc->num_lanes; k++) {
			struct hfi2_dms *dms = svc->lanes[k].dms;
			int left = atomic_read(&dms->packet_drop.entries[i].count);

			if (left == -1)
				inf = true;
			else
				cnt += left;
			dropped += atomic64_read(&dms->packet_drop.entries[i].user_dropped);
			delivered += atomic64_read(&dms->packet_drop.entries[i].user_delivered);
		}

		total_dropped += dropped;
		total_delivered += delivered;

		if (inf) {
			len += scnprintf(buf + len, PAGE_SIZE - len,
				"%-14s %10s %7u.%07u %14llu %14llu\n",
				_pkt_drop_type_names[i], "inf", pct_int, pct_frac, dropped, delivered);
		} else {
			len += scnprintf(buf + len, PAGE_SIZE - len,
				"%-14s %10ld %7u.%07u %14llu %14llu\n",
				_pkt_drop_type_names[i], cnt, pct_int, pct_frac, dropped, delivered);
		}
	}

	len += scnprintf(buf + len, PAGE_SIZE - len,
		"%-14s %10s %15s %14llu %14llu\n",
		"TOTAL", "", "", total_dropped, total_delivered);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"Counts are summed over %u lane(s); a finite Cfg.Count applies per lane.\n",
		svc->num_lanes);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return ret;
}

static void _pkt_drop_set_entry(struct hfi2_bulksvc *svc, int idx, int drop_count, u32 freq_bp)
{
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_dms *dms = svc->lanes[k].dms;

		WRITE_ONCE(dms->packet_drop.entries[idx].frequency_bp, freq_bp);
		atomic_set(&dms->packet_drop.entries[idx].count, drop_count);
	}
}

static void _pkt_drop_clear_entry(struct hfi2_bulksvc *svc, int idx)
{
	for (u32 k = 0; k < svc->num_lanes; k++) {
		struct hfi2_dms *dms = svc->lanes[k].dms;

		atomic_set(&dms->packet_drop.entries[idx].count, 0);
		WRITE_ONCE(dms->packet_drop.entries[idx].frequency_bp, 0);
		atomic64_set(&dms->packet_drop.entries[idx].user_dropped, 0);
		atomic64_set(&dms->packet_drop.entries[idx].user_delivered, 0);
	}
}

static int _pkt_drop_process_line(struct hfi2_devdata *dd, struct hfi2_bulksvc *svc, char *line)
{
	char *p, *token;
	int type_idx = -1;
	bool apply_all = false;
	int drop_count = -1;
	u32 freq_bp = 0;
	int rc;

	p = strstrip(line);

	if (strcmp(p, "clear") == 0) {
		int i;

		for (i = 0; i < ARRAY_SIZE(_pkt_drop_type_names); i++)
			_pkt_drop_clear_entry(svc, i);
		dd_dev_info(dd, "packet_drop: cleared all drop rules and counters\n");
		return 0;
	}

	if (!*p)
		return 0;

	token = strsep(&p, " \t");
	if (!token || !*token)
		return -EINVAL;

	type_idx = _pkt_drop_parse_type(token);
	if (type_idx < 0) {
		if (strcmp(token, "all") == 0) {
			apply_all = true;
			token = strsep(&p, " \t");
		} else {
			apply_all = true;
		}
	} else {
		token = strsep(&p, " \t");
		if (!token || !*token)
			return -EINVAL;
	}

	if (token && *token) {
		char *decimal_point;
		u64 int_part = 0;
		u64 frac_part = 0;
		u32 frac_digits = 0;
		u64 total_bp;

		/* Handle special case: -1 means always drop (100%) */
		if (strcmp(token, "-1") == 0) {
			freq_bp = 1000000000u;
			goto freq_done;
		}

		/* Parse integer part */
		decimal_point = strchr(token, '.');
		if (decimal_point) {
			*decimal_point = '\0';
			decimal_point++;
		}

		if (*token) {
			rc = kstrtou64(token, 10, &int_part);
			if (rc)
				return -EINVAL;
		}

		/* Parse fractional part if present */
		if (decimal_point && *decimal_point) {
			char *frac_start = decimal_point;

			/* Count digits and parse fractional part */
			while (*decimal_point >= '0' && *decimal_point <= '9') {
				frac_digits++;
				decimal_point++;
			}

			/* Limit to 9 decimal places (0.0000001% = 1bp minimum) */
			if (frac_digits > 9)
				frac_digits = 9;

			rc = kstrtou64(frac_start, 10, &frac_part);
			if (rc)
				return -EINVAL;

			/* Truncate frac_part to frac_digits */
			if (frac_digits < strlen(frac_start)) {
				u32 divisor = 1;
				u32 extra = strlen(frac_start) - frac_digits;
				u32 i;

				if (extra > 9) {
					frac_part = 0;
				} else {
					for (i = 0; i < extra; i++)
						divisor *= 10;
					frac_part /= divisor;
				}
			}
		}

		total_bp = min_t(u64, int_part, 100) * 10000000ULL;
		if (frac_digits > 0) {
			u64 divisor = 1;
			u32 i;

			for (i = 0; i < frac_digits; i++)
				divisor *= 10;
			total_bp += (frac_part * 10000000ULL) / divisor;
		}

		/* Cap at 100% (1B basis points) */
		if (total_bp > 1000000000ULL)
			total_bp = 1000000000ULL;

		freq_bp = (u32)total_bp;
	}
freq_done:

	token = strsep(&p, " \t");
	if (token && *token) {
		if (strcmp(token, "all") == 0 || strcmp(token, "inf") == 0) {
			drop_count = -1;
		} else {
			rc = kstrtoint(token, 0, &drop_count);
			if (rc)
				return -EINVAL;
		}
	}

	if (freq_bp == 0) {
		if (apply_all) {
			int i;

			for (i = 0; i < ARRAY_SIZE(_pkt_drop_type_names); i++)
				_pkt_drop_clear_entry(svc, i);
			dd_dev_info(dd, "packet_drop: cleared all drop rules and counters\n");
		} else {
			_pkt_drop_clear_entry(svc, type_idx);
			dd_dev_info(dd, "packet_drop: cleared type=%s\n",
				    _pkt_drop_type_names[type_idx]);
		}
		return 0;
	}

	if (apply_all) {
		int i;

		for (i = 0; i < ARRAY_SIZE(_pkt_drop_type_names); i++)
			_pkt_drop_set_entry(svc, i, drop_count, freq_bp);
		if (drop_count == -1) {
			dd_dev_info(dd, "packet_drop: type=all count=inf freq=%u.%07u%%\n",
				    freq_bp / 10000000, freq_bp % 10000000);
		} else {
			dd_dev_info(dd, "packet_drop: type=all count=%d per lane freq=%u.%07u%%\n",
				    drop_count, freq_bp / 10000000, freq_bp % 10000000);
		}
	} else {
		_pkt_drop_set_entry(svc, type_idx, drop_count, freq_bp);
		if (drop_count == -1) {
			dd_dev_info(dd, "packet_drop: type=%s count=inf freq=%u.%07u%%\n",
				    _pkt_drop_type_names[type_idx],
				    freq_bp / 10000000, freq_bp % 10000000);
		} else {
			dd_dev_info(dd, "packet_drop: type=%s count=%d per lane freq=%u.%07u%%\n",
				    _pkt_drop_type_names[type_idx], drop_count,
				    freq_bp / 10000000, freq_bp % 10000000);
		}
	}

	return 0;
}

static ssize_t packet_drop_write(struct file *file, const char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct hfi2_devdata *dd = file->private_data;
	char *buf, *line, *next_line;
	int rc;

	if (!dd->bulksvc)
		return -ENODEV;

	buf = kmalloc(count + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, user_buf, count)) {
		kfree(buf);
		return -EFAULT;
	}
	buf[count] = '\0';

	line = buf;
	while (line && *line) {
		next_line = strchr(line, '\n');
		if (next_line) {
			*next_line = '\0';
			next_line++;
		}

		rc = _pkt_drop_process_line(dd, dd->bulksvc, line);
		if (rc < 0) {
			dd_dev_warn(dd, "packet_drop: failed to process line: '%s'\n", line);
		}

		line = next_line;
	}

	kfree(buf);
	return count;
}

static const struct file_operations _packet_drop_ops = {
	.open = simple_open,
	.read = packet_drop_read,
	.write = packet_drop_write,
	.llseek = default_llseek,
};

static int bulksvc_dbg_open(struct inode *in, struct file *fp)
{
	simple_open(in, fp);
	struct hfi2_devdata *dd = fp->private_data;

	if (!dd->bulksvc) {
		fp->private_data = NULL;
		return 0;
	}

	atomic64_t *debug_info_ptr = &dd->bulksvc->debug_info_buf_ptr;

	u64 prev = atomic64_xchg(debug_info_ptr, 1);

	if (prev != 0 && prev != 1) {
		/* Stale buffer from a previous request - free it */
		kvfree((void *)prev);
	}

	/*
	 * Wait for the bulksvc worker to produce the debug info buffer.
	 * The worker sets debug_info_buf_ptr to a heap pointer when ready.
	 */
	char *info_buf = NULL;
	unsigned long deadline = jiffies + msecs_to_jiffies(BULKSVC_DBG_OPEN_TIMEOUT_MS);

	while (!info_buf) {
		if (time_after(jiffies, deadline)) {
			/*
			 * Worker did not produce debug info in time.
			 * Clear our request so we don't leave a stale
			 * signal, and return an error to userspace.
			 */
			prev = atomic64_xchg(debug_info_ptr, 0);
			if (prev != 0 && prev != 1)
				kvfree((void *)prev);
			fp->private_data = NULL;
			return -ETIMEDOUT;
		}

		prev = atomic64_read(debug_info_ptr);
		if (prev == 1) {
			/* Worker hasn't produced the buffer yet - sleep and retry */
			usleep_range(1000, 2000);
			continue;
		}
		if (prev == 0) {
			/* Someone else consumed the buffer - re-request */
			atomic64_xchg(debug_info_ptr, 1);
			usleep_range(1000, 2000);
			continue;
		}
		/* prev is a heap pointer - try to claim it */
		prev = atomic64_xchg(debug_info_ptr, 0);
		if (prev != 0 && prev != 1)
			info_buf = (char *)prev;
		/* else: lost race, loop will retry */
	}

	fp->private_data = info_buf;

	return 0;
}

static int bulksvc_dbg_release(struct inode *in, struct file *fp)
{
	char *bulksvc_info = fp->private_data;

	if (bulksvc_info)
		kvfree(bulksvc_info);
	fp->private_data = NULL;
	return 0;
}

static ssize_t bulksvc_dbg_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char *bulksvc_info = file->private_data;

	if (!bulksvc_info)
		return 0;

	size_t info_len = strlen(bulksvc_info);

	loff_t pos = *ppos;

	if (pos == info_len)
		return 0;

	bulksvc_info += pos;

	if (pos < 0 || !count || pos >= info_len)
		return -EINVAL;

	count = count < (info_len - pos) ? count : info_len - pos;

	if (copy_to_user(buf, bulksvc_info, count))
		return -EFAULT;

	*ppos += count;
	return count;
}

static const struct file_operations _bulksvc_dbg_ops = {
	.open = bulksvc_dbg_open,
	.release = bulksvc_dbg_release,
	.read = bulksvc_dbg_read,
	.llseek = default_llseek,
};

void hfi2_dbg_ibdev_init(struct hfi2_ibdev *ibd)
{
	char name[sizeof("port0counters") + 1];
	char link[10];
	struct hfi2_devdata *dd = dd_from_dev(ibd);
	struct hfi2_pportdata *ppd;
	struct dentry *root;
	int unit = dd->unit;
	int i;

	if (!hfi2_dbg_root)
		return;
	snprintf(name, sizeof(name), "%s_%d", "hfi2", unit);
	snprintf(link, sizeof(link), "%d", unit);
	root = debugfs_create_dir(name, hfi2_dbg_root);
	ibd->hfi2_ibdev_dbg = root;

	ibd->hfi2_ibdev_link =
		debugfs_create_symlink(link, hfi2_dbg_root, name);

	debugfs_create_file("opcode_stats", 0444, root, ibd,
			    &_opcode_stats_file_ops);
	debugfs_create_file("tx_opcode_stats", 0444, root, ibd,
			    &_tx_opcode_stats_file_ops);
	debugfs_create_file("ctx_stats", 0444, root, ibd, &_ctx_stats_file_ops);
	if (ibd->rdi.qp_dev)
		debugfs_create_file("qp_stats", 0444, root, ibd,
				    &_qp_stats_file_ops);
	debugfs_create_file("sdes", 0444, root, ibd, &_sdes_file_ops);
	debugfs_create_file("sdma_outstanding_limit_cnt", 0644, root, ibd,
			    &_sdma_outstanding_limit_cnt_file_ops);
	debugfs_create_file("rcds", 0444, root, ibd, &_rcds_file_ops);
	debugfs_create_file("pios", 0444, root, ibd, &_pios_file_ops);
	debugfs_create_file("sdma_cpu_list", 0444, root, ibd,
			    &_sdma_cpu_list_file_ops);
	if (dd->cport)
		debugfs_create_file("cport_ping", 0644, root, dd,
				    &_cport_ping_ops);
	debugfs_create_file("link_debug", 0644, root, dd, &_link_debug_ops);
	if (IS_ENABLED(CONFIG_INFINIBAND_HFI2_ROCE) && hfi2_is_eth_mode(dd))
		debugfs_create_file("roce_stats", 0444, root, dd,
				    &_roce_stats_ops);

	/* dev counter files */
	for (i = 0; i < ARRAY_SIZE(cntr_ops); i++)
		debugfs_create_file(cntr_ops[i].name, 0444, root, dd,
				    &cntr_ops[i].ops);

	if (dd->params->chip_type == CHIP_WFR) {
		for (i = 0; i < ARRAY_SIZE(wfr_cntr_ops); i++) {
			debugfs_create_file(wfr_cntr_ops[i].name,
					    wfr_cntr_ops[i].ops.write ? 0644 : 0444, root,
					    dd, &wfr_cntr_ops[i].ops);
		}
	}

	/* per port files */
	for (ppd = dd->pport, i = 0; i < dd->num_pports; i++, ppd++) {
		add_port_files(root, ppd, port_cntr_ops,
			       ARRAY_SIZE(port_cntr_ops));
		if (dd->params->chip_type == CHIP_WFR) {
			add_port_files(root, ppd, wfr_port_cntr_ops,
				       ARRAY_SIZE(wfr_port_cntr_ops));
		}
	}

	hfi2_fault_init_debugfs(ibd);

	debugfs_create_file("bulksvc_dbg", 0444, root, dd, &_bulksvc_dbg_ops);
	debugfs_create_file("packet_drop", 0644, root, dd, &_packet_drop_ops);
}

void hfi2_dbg_ibdev_exit(struct hfi2_ibdev *ibd)
{
	if (!hfi2_dbg_root)
		goto out;
	hfi2_fault_exit_debugfs(ibd);
	debugfs_remove(ibd->hfi2_ibdev_link);
	debugfs_remove_recursive(ibd->hfi2_ibdev_dbg);
out:
	ibd->hfi2_ibdev_link = NULL;
	ibd->hfi2_ibdev_dbg = NULL;
}

/*
 * driver stats field names, one line per stat, single string.  Used by
 * programs like hfistats to print the stats in a way which works for
 * different versions of drivers, without changing program source.
 * if hfi2_ib_stats changes, this needs to change.  Names need to be
 * 12 chars or less (w/o newline), for proper display by hfistats utility.
 */
static const char *const hfi2_statnames[] = {
	/* must be element 0*/
	"KernIntr",  "ErrorIntr", "Tx_Errs",	 "Rcv_Errs",   "H/W_Errs",
	"NoPIOBufs", "CtxtsOpen", "RcvLen_Errs", "EgrBufFull", "EgrHdrFull"
};

static void *_driver_stats_names_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= ARRAY_SIZE(hfi2_statnames))
		return NULL;
	return pos;
}

static void *_driver_stats_names_seq_next(struct seq_file *s, void *v,
					  loff_t *pos)
{
	++*pos;
	if (*pos >= ARRAY_SIZE(hfi2_statnames))
		return NULL;
	return pos;
}

static void _driver_stats_names_seq_stop(struct seq_file *s, void *v)
{
}

static int _driver_stats_names_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos = v;

	seq_printf(s, "%s\n", hfi2_statnames[*spos]);
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(driver_stats_names);
DEBUGFS_SEQ_FILE_OPEN(driver_stats_names)
DEBUGFS_FILE_OPS(driver_stats_names);

static void *_driver_stats_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= ARRAY_SIZE(hfi2_statnames))
		return NULL;
	return pos;
}

static void *_driver_stats_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	++*pos;
	if (*pos >= ARRAY_SIZE(hfi2_statnames))
		return NULL;
	return pos;
}

static void _driver_stats_seq_stop(struct seq_file *s, void *v)
{
}

static void hfi2_sps_show_ints(struct seq_file *s)
{
	unsigned long index, flags;
	struct hfi2_devdata *dd;
	u64 sps_ints = 0;

	xa_lock_irqsave(&hfi2_dev_table, flags);
	xa_for_each(&hfi2_dev_table, index, dd) {
		sps_ints += hfi2_get_all_cpu_total(dd->int_counter);
	}
	xa_unlock_irqrestore(&hfi2_dev_table, flags);
	seq_write(s, &sps_ints, sizeof(u64));
}

static int _driver_stats_seq_show(struct seq_file *s, void *v)
{
	loff_t *spos = v;
	u64 *stats = (u64 *)&hfi2_stats;

	/* special case for interrupts */
	if (*spos == 0)
		hfi2_sps_show_ints(s);
	else
		seq_write(s, stats + *spos, sizeof(u64));
	return 0;
}

DEBUGFS_SEQ_FILE_OPS(driver_stats);
DEBUGFS_SEQ_FILE_OPEN(driver_stats)
DEBUGFS_FILE_OPS(driver_stats);

void hfi2_dbg_init(void)
{
	hfi2_dbg_root = debugfs_create_dir(DRIVER_NAME, NULL);
	debugfs_create_file("driver_stats_names", 0444, hfi2_dbg_root, NULL,
			    &_driver_stats_names_file_ops);
	debugfs_create_file("driver_stats", 0444, hfi2_dbg_root, NULL,
			    &_driver_stats_file_ops);
}

void hfi2_dbg_exit(void)
{
	debugfs_remove_recursive(hfi2_dbg_root);
	hfi2_dbg_root = NULL;
}
