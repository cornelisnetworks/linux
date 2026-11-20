// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2025 - Cornelis Networks, Inc.
 */

#ifndef _HFI2_MEM_REGION_H
#define _HFI2_MEM_REGION_H

#include "mmu_rb.h"
#include <linux/bitmap.h>
#include <linux/types.h>

struct hfi2_mem_region {
	struct mmu_rb_node rb;
	struct page **pages;
	dma_addr_t *dma_list;
	unsigned int npages_total;
	unsigned int npages_pinned;
	unsigned long *pin_bitmap;
};

int init_bulksvc_mmu(struct hfi2_bulksvc_user_info *uinfo);
int uninit_bulksvc_mmu(struct hfi2_bulksvc_user_info *uinfo);

struct hfi2_mem_region *hfi2_mem_region_create_unpinned(struct mmu_rb_handler *handler,
							uintptr_t vaddr,
							u64 len);
int hfi2_mem_region_pin_range(struct hfi2_devdata *dd,
			      struct hfi2_mem_region *mr,
			      unsigned int from_page,
			      unsigned int npages,
			      bool writable);
bool hfi2_mem_region_range_pinned(struct hfi2_mem_region *mr,
				  unsigned int from_page,
				  unsigned int npages);
struct hfi2_mem_region *hfi2_mem_region_pin(struct mmu_rb_handler *handler,
				    uintptr_t vaddr, u64 len);

static inline void hfi2_mem_region_put(struct hfi2_mem_region *mr)
{
	kref_put(&mr->rb.refcount, hfi2_mmu_rb_release);
}

#endif /* _HFI2_MEM_REGION_H */
