/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2016 Intel Corporation.
 */

#ifndef DEF_RDMAVT_INCMR_H
#define DEF_RDMAVT_INCMR_H

/*
 * For Memory Regions. This stuff should probably be moved into rdmavt/mr.h once
 * drivers no longer need access to the MR directly.
 */
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/iosys-map.h>

enum rvt_mem_type {
	RVT_MEM_KERNEL,
	RVT_MEM_DMABUF,
	RVT_MEM_DMABUF_DO /* device accessible only */
};

struct rvt_seg_dmabuf {
	struct dma_buf *dmabuf;
	dma_addr_t dma_addr;
};

struct rvt_seg_dmabuf_do {
	struct dma_buf *dmabuf;
	dma_addr_t dma_addr;
	void *priv; /* device driver specific */
};

/*
 * A segment is a linear region of memory.
 * Used by the verbs layer.
 */
struct rvt_seg {
	enum rvt_mem_type type;
	void *vaddr; /* type specific value */
	size_t length;
	union {
		/*
		 * RVT_MEM_DMABUF - vaddr is a vmapped kernel address, access
		 *		     with dma_buf_[begin,end]_cpu_access. Don't
		 *		     try to DMA map this
		 *		  -  dma_addr holds DMA handle
		 */
		struct rvt_seg_dmabuf seg_dmabuf;
		/*
		 * RVT_MEM_DMABUF_DO - vaddr holds offset within dmabuf, access
		 *		       with rvt_driver_provided.dmabuf_memcpy
		 *		     - dma_addr holds DMA handle
		 */
		struct rvt_seg_dmabuf_do seg_dmabuf_do;
		/*
		 * RVT_MEM_KERNEL - No extra data needed, vaddr is cpu accessible
		 *		    and can be DMA mapped
		 */
	};

};

/* The number of rvt_segs that fit in a page. */
#define RVT_SEGSZ     (PAGE_SIZE / sizeof(struct rvt_seg))

struct rvt_segarray {
	struct rvt_seg segs[RVT_SEGSZ];
};

/*
 * Per-CPU monotonic get/put counts.  A reference may be dropped on another
 * CPU than took it, and a holder may take a further reference while it drops
 * its own, so a single summed counter can read zero while held; summing all
 * puts before all gets cannot.  See rvt_mr_refs().
 */
struct rvt_mref {
	u32 gets;
	u32 puts;
};

struct rvt_mregion {
	struct iosys_map vmap;  /* if dmabuf */
	struct ib_pd *pd;       /* shares refcnt of ibmr.pd */
	u64 user_base;          /* User's address for this region */
	u64 iova;               /* IB start address of this region */
	size_t length;
	u32 lkey;
	u32 internal_generation;
	u32 offset;             /* offset (bytes) to start of region */
	int access_flags;
	u32 max_segs;           /* number of rvt_segs in all the arrays */
	u32 mapsz;              /* size of the map array */
	atomic_t lkey_invalid;	/* true if current lkey is invalid */
	u8  page_shift;         /* 0 - non unform/non powerof2 sizes */
	u8  lkey_published;     /* in global table */
	bool driver_internal;
	struct rvt_mref __percpu *refs;
	int dying;		/* set by rvt_mr_kill(); rvt_tryget_mr() fails after */
	atomic_t done;		/* comp is completed exactly once */
	struct completion comp; /* complete when the ref sum reaches zero */
	void *driver_priv;       /* opaque per-MR slot for driver use */
	struct rvt_segarray *map[];    /* the segments */
};

#define RVT_MAX_LKEY_TABLE_BITS 23

struct rvt_lkey_table {
	/* read mostly fields */
	u32 max;                /* size of the table */
	u32 shift;              /* lkey/rkey shift */
	struct rvt_mregion __rcu **table;
	/* writeable fields */
	/* protect changes in this struct */
	spinlock_t lock ____cacheline_aligned_in_smp;
	u32 next;               /* next unused index (speeds search) */
	u32 gen;                /* generation count */
};

/*
 * These keep track of the copy progress within a memory region.
 * Used by the verbs layer.
 */
struct rvt_sge {
	struct rvt_seg mem;	/* remaining len and address of segment */
	struct rvt_mregion *mr;
	u32 sge_length;         /* length of the SGE */
	u16 m;                  /* current index: mr->map[m] */
	u16 n;                  /* current index: mr->map[m]->segs[n] */
};

struct rvt_sge_state {
	struct rvt_sge *sg_list;      /* next SGE to be used if any */
	struct rvt_sge sge;   /* progress state for the current SGE */
	u32 total_len;
	u8 num_sge;
};

/*
 * Once @dying is set (see rvt_mr_kill()) rvt_tryget_mr() fails, while a holder
 * may still take a further reference with rvt_get_mr().  The put that finds
 * no reference outstanding completes @comp.  The full
 * barrier on the get and put side pairs with the one in rvt_mr_kill():
 * either the taker sees @dying or the killer sees its get.
 */
void rvt_mr_put_slow(struct rvt_mregion *mr);

static inline void rvt_put_mr(struct rvt_mregion *mr)
{
	rcu_read_lock();
	this_cpu_inc(mr->refs->puts);
	smp_mb(); /* pairs with the barrier in rvt_mr_kill() */
	if (unlikely(READ_ONCE(mr->dying)))
		rvt_mr_put_slow(mr);
	rcu_read_unlock();
}

/* The caller already holds a reference. */
static inline void rvt_get_mr(struct rvt_mregion *mr)
{
	this_cpu_inc(mr->refs->gets);
	smp_wmb(); /* order gets before a subsequent rvt_put_mr() */
}

/*
 * For lookups under rcu_read_lock() that hold no reference yet.
 * Returns false if @mr is NULL or dying.
 */
static inline bool rvt_tryget_mr(struct rvt_mregion *mr)
{
	if (unlikely(!mr))
		return false;
	this_cpu_inc(mr->refs->gets);
	smp_mb(); /* pairs with the barrier in rvt_mr_kill() */
	if (likely(!READ_ONCE(mr->dying)))
		return true;
	rvt_put_mr(mr);
	return false;
}

static inline void rvt_put_ss(struct rvt_sge_state *ss)
{
	while (ss->num_sge) {
		rvt_put_mr(ss->sge.mr);
		if (--ss->num_sge)
			ss->sge = *ss->sg_list++;
	}
}

static inline u32 rvt_get_sge_length(struct rvt_sge *sge, u32 length)
{
	u32 len = sge->mem.length;

	if (len > length)
		len = length;
	if (len > sge->sge_length)
		len = sge->sge_length;

	return len;
}

/* Keep this out of line to limit data-path code growth. */
void rvt_update_sge(struct rvt_sge_state *ss, u32 length, bool release);

static inline void rvt_skip_sge(struct rvt_sge_state *ss, u32 length,
				bool release)
{
	struct rvt_sge *sge = &ss->sge;

	while (length) {
		u32 len = rvt_get_sge_length(sge, length);

		WARN_ON_ONCE(len == 0);
		rvt_update_sge(ss, len, release);
		length -= len;
	}
}

/*
 * Helper for converting to kernel addressable struct rvt_seg,
 * allocated on stack
 */
static inline struct rvt_seg rvt_to_kseg(void *kaddr, u32 len)
{
	return (struct rvt_seg){
		.type = RVT_MEM_KERNEL,
		.vaddr = kaddr,
		.length = len
	};
}

/*
 * Helper for changing the value of the len of a seg (should be
 * reducing only!). Return a shallow copy with modified len
 */
static inline struct rvt_seg rvt_seg_new_len(struct rvt_seg old,
					     u32 len)
{
	old.length = len;
	return old;
}

bool rvt_ss_has_lkey(struct rvt_sge_state *ss, u32 lkey);
bool rvt_mr_has_lkey(struct rvt_mregion *mr, u32 lkey);

#endif          /* DEF_RDMAVT_INCMRH */
