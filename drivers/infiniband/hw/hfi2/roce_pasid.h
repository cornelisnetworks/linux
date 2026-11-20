/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks, Inc.
 */

#ifndef _HFI2_ROCE_PASID_H
#define _HFI2_ROCE_PASID_H

#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/mmu_notifier.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

struct hfi2_devdata;
struct hfi2_roce_kmr_donor;
struct hfi2_roce_pasid;
struct iova;
struct page;

/* Caller storage remains owned by the queue until run() returns. */
struct hfi2_roce_kmr_async {
	struct list_head list;
	void (*run)(struct hfi2_roce_kmr_async *request);
};

struct hfi2_roce_kmr_reservation {
	struct hfi2_roce_kmr_donor *donor;
	struct hfi2_roce_pasid *token;
	struct iova *extent;
	unsigned long va;
	unsigned long len;
	bool poisoned;
};

struct hfi2_roce_kmr_window;
struct rvt_dev_info;
struct rvt_mregion;
struct rvt_qp;
struct rvt_swqe;

/**
 * struct hfi2_roce_pasid - hardware-table PASID trust token
 * @pasid: PASID programmed into hardware tables
 * @live: permits installation while holding the table lock
 * @quiesce_failed: prevents PASID allocator reuse
 * @fenced: IOMMU fencing completed; protected by the device PASID mutex
 *
 * Teardown clears @live before taking the table lock to revoke entries.
 */
struct hfi2_roce_pasid {
	u32 pasid;
	bool live;
	bool quiesce_failed;
	bool fenced;
};

/**
 * struct hfi2_roce_pasid_bind - one SVA binding, shared by every MR of an mm
 * @common: live PASID token programmed into hardware tables
 * @handle: the SVA handle returned by iommu_sva_bind_device()
 * @notifier: fires once at exit_mmap() to drive hardware state to invalid
 * @dd: owning device, so the notifier can reach the tables
 * @owning_mm: the key this entry is filed under; never dereferenced, only
 *	compared and used to erase the xarray slot
 * @refs: number of MRs holding this binding
 * @rcu: frees the binding after a grace period; hfi2_roce_pasid_get() reads
 *	the map under RCU only
 *
 * Why the PASID is cached rather than fetched on demand: the arm path runs
 * under a spinlock and cannot sleep, and the install-time invariant has to be
 * re-asserted there.  The value is deterministic per mm for the lifetime of
 * the binding, so caching costs nothing in accuracy and turns the assertion
 * into a comparison of two scalars already in hand.
 *
 * Why @common.live exists: mmu_notifier .release may be called from exit_mmap()
 * before the page tables are torn down, and hfi2's own mmu_rb.c documents the
 * same hazard.  After it returns, the address space must be treated as gone -
 * any later arm keyed on this binding has to fail rather than install an entry
 * naming a PASID that is about to be freed and recycled.
 */
struct bts_verbs_pageset;

struct hfi2_roce_pasid_bind {
	struct hfi2_roce_pasid common;
	struct iommu_sva *handle;
	struct mmu_notifier notifier;
	struct hfi2_devdata *dd;
	struct mm_struct *owning_mm;
	refcount_t refs;
	bool fence_pin;
	struct rcu_head rcu;
};

/**
 * struct hfi2_roce_pasid_map - one driver-managed PASID mapping for an MR
 * @common: live PASID token programmed into hardware tables
 * @domain: paging domain attached to @common.pasid
 * @dd: owning device
 * @map_lock: serializes kernel mapping changes, nested inside pageset_lock
 * @iova: page-aligned base mapped into @domain
 * @length: page-aligned mapping length
 * @attached: true after iommu_attach_device_pasid() succeeds
 * @tracked: true while listed in the device's teardown xarray
 * @kernel_mr: this map belongs to a kernel FastReg MR
 * @quarantine: holds this mapping while its PASID awaits timed release
 * @quarantine_release_jiffies: jiffies when the map entered quarantine
 *
 * Unlike an SVA binding, this object is private to one MR and owns no mmu
 * notifier.  The MR's ib_umem already owns the long-term page pins; this object
 * only gives those pages a contiguous device address space for placement.
 */
struct hfi2_roce_pasid_map {
	struct hfi2_roce_pasid common;
	struct iommu_domain *domain;
	struct hfi2_devdata *dd;
	spinlock_t map_lock; /* nested inside pageset_lock */
	u64 iova;
	size_t length;
	bool attached;
	bool tracked;
	bool kernel_mr;
	struct list_head quarantine;
	unsigned long quarantine_release_jiffies;
};

static inline bool hfi2_roce_pasid_fenced(struct hfi2_roce_pasid *pasid)
{
	/* Pairs with fence publication after synchronous IOMMU invalidation. */
	return smp_load_acquire(&pasid->fenced);
}

enum hfi2_roce_pasid_type {
	HFI2_ROCE_PASID_NONE,
	HFI2_ROCE_PASID_SVA,
	HFI2_ROCE_PASID_MAP,
	HFI2_ROCE_PASID_DONOR,
	HFI2_ROCE_PASID_DONOR_DMABUF,
};

/*
 * Retain installed keys and buckets for invalidation after mr->lkey changes;
 * private keys have no rdmavt table entry.  NO_BUCKET marks an absent entry.
 * pageset_lock is an IRQ-safe leaf below QP s_lock, protecting replacement
 * and counted snapshots.  rdmavt serializes sleepable PASID release;
 * pasid_ref_held prevents releasing the binding twice.
 */
struct hfi2_roce_mr_priv {
	struct hfi2_roce_pasid *pasid;
	struct hfi2_roce_pasid_bind *sva;
	struct hfi2_roce_pasid_map *map;
	struct bts_verbs_pageset *pageset;
	spinlock_t pageset_lock; /* protects pageset */
	u32 rkey;
	u32 internal_rkey;
	/* Immutable installed-key bounds, retained through error revocation. */
	u64 read_key_iova;
	u32 read_key_length;
	/* Never wrap peer-held keys; exhaustion disables direct READs. */
	struct ib_mr *read_key_slot;
	bool read_key_disabled;
	s8 rkey_bucket;
	s8 internal_rkey_bucket;
	enum hfi2_roce_pasid_type pasid_type;
	struct hfi2_roce_kmr_window *donor_window;
	u64 donor_iova;
	u64 kmr_iova_delta; /* consumer IOVA to PASID placement address */
	u64 donor_dmabuf_va;
	size_t donor_dmabuf_len;
	bool donor_window_live;
	bool pasid_ref_held;
	u64 donor_generation; /* rejects stale deferred publication */
	u64 local_generation;
	u64 hardware_generation;
	u32 deferred_invalidates;
	u32 deferred_registers;
};

/* No R_Key entry is installed for this MR. */
#define HFI2_ROCE_MR_NO_BUCKET (-1)

#ifdef CONFIG_INFINIBAND_HFI2_ROCE

extern bool hfi2_roce_kmr_pasid_enabled;
extern bool hfi2_roce_kmr_donor_enabled;
/* The window starts at 4 GiB and must stay below the 47-bit IOVA limit. */
#define HFI2_ROCE_KMR_DONOR_GB_MAX 131068
extern unsigned int hfi2_roce_kmr_donor_gb;

int hfi2_roce_kmr_reserve(struct hfi2_devdata *dd, unsigned long len,
			  struct hfi2_roce_kmr_reservation *reservation);
void hfi2_roce_kmr_unreserve(struct hfi2_roce_kmr_reservation *reservation);
int hfi2_roce_kmr_retain_pages(struct hfi2_roce_kmr_reservation *reservation,
			       struct page **pages, u32 count);
int hfi2_roce_kmr_queue(struct hfi2_roce_kmr_reservation *reservation,
			struct hfi2_roce_kmr_async *request);
int hfi2_roce_kmr_map_pages(struct hfi2_roce_kmr_reservation *reservation,
			    unsigned long va, struct page **pages, u32 count);
int hfi2_roce_kmr_zap_pages(struct hfi2_roce_kmr_reservation *reservation,
			    unsigned long va, unsigned long len);
int hfi2_roce_kmr_donor_init(struct hfi2_devdata *dd);
void hfi2_roce_kmr_donor_exit(struct hfi2_devdata *dd);
int hfi2_roce_kmr_placement_init(struct hfi2_devdata *dd);

void hfi2_roce_pasid_map_init(struct hfi2_devdata *dd);
void hfi2_roce_pasid_map_exit(struct hfi2_devdata *dd);

struct hfi2_roce_pasid_bind *hfi2_roce_pasid_get(struct hfi2_devdata *dd,
						 struct mm_struct *mm);
void hfi2_roce_pasid_put(struct hfi2_roce_pasid_bind *bind);
int hfi2_roce_pasid_fence(struct hfi2_devdata *dd,
			  struct hfi2_roce_pasid *pasid,
			  struct iommu_domain *domain, bool *attached);

void *hfi2_roce_mr_priv_alloc(struct rvt_dev_info *rdi, struct rvt_mregion *mr);
void hfi2_roce_mr_priv_free(struct rvt_dev_info *rdi, struct rvt_mregion *mr);
void hfi2_roce_revoke_read_key(struct hfi2_devdata *dd, struct rvt_mregion *mr,
			       u32 key);
int hfi2_roce_notify_mr_pages_set(struct rvt_dev_info *rdi,
				  struct rvt_mregion *mr);
int hfi2_roce_notify_register_mr(struct rvt_dev_info *rdi,
				 struct rvt_mregion *mr);
int hfi2_roce_fast_reg_mr(struct rvt_dev_info *rdi, struct rvt_mregion *mr,
			  unsigned int *reg_flags);
int hfi2_roce_kmr_setup_reg(struct rvt_qp *qp, struct rvt_swqe *wqe);
int hfi2_roce_setup_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe);
int hfi2_roce_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe);
void hfi2_roce_cleanup_local_inv(struct rvt_qp *qp, struct rvt_swqe *wqe);
int hfi2_roce_kmr_map_reg(struct rvt_swqe *wqe);
int hfi2_roce_kmr_publish_reg(struct rvt_qp *qp, struct rvt_swqe *wqe,
			      int status);
void hfi2_roce_kmr_cleanup_reg(struct rvt_qp *qp, struct rvt_swqe *wqe);
u64 hfi2_roce_kmr_translate_iova(const struct hfi2_roce_mr_priv *priv,
				  u64 iova);
void hfi2_roce_notify_unregister_mr(struct rvt_dev_info *rdi,
				    struct rvt_mregion *mr);

#else /* !CONFIG_INFINIBAND_HFI2_ROCE */

static inline void hfi2_roce_kmr_donor_exit(struct hfi2_devdata *dd) { }
static inline int hfi2_roce_kmr_placement_init(struct hfi2_devdata *dd)
{
	return 0;
}
static inline void hfi2_roce_pasid_map_init(struct hfi2_devdata *dd) { }
static inline void hfi2_roce_pasid_map_exit(struct hfi2_devdata *dd) { }

static inline u64
hfi2_roce_kmr_translate_iova(const struct hfi2_roce_mr_priv *priv, u64 iova)
{
	return iova;
}

static inline struct hfi2_roce_pasid_bind *
hfi2_roce_pasid_get(struct hfi2_devdata *dd, struct mm_struct *mm)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void hfi2_roce_pasid_put(struct hfi2_roce_pasid_bind *bind) { }

#endif /* CONFIG_INFINIBAND_HFI2_ROCE */

#endif /* _HFI2_ROCE_PASID_H */
