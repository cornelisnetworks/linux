/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#ifndef HFI2_UVERBS_H
#define HFI2_UVERBS_H

#include <rdma/uverbs_ioctl.h>

/*
 * Driver-specific mmap entry, embedding the core rdma_user_mmap_entry.
 * One entry is created per mappable region and tracked for the lifetime
 * of the user context.
 */
struct hfi2_filedata;

struct hfi2_user_mmap_entry {
	struct rdma_user_mmap_entry rdma_entry;
	struct list_head list;
	u64 address;
	void *memvirt;
	dma_addr_t memdma;
	u8 mmap_flag;
	bool dma;
	bool vmalloc;
};

static inline struct hfi2_user_mmap_entry *
to_hfi2_mmap(struct rdma_user_mmap_entry *rdma_entry)
{
	return container_of(rdma_entry, struct hfi2_user_mmap_entry,
			    rdma_entry);
}

int hfi2_mmap(struct ib_ucontext *ucontext, struct vm_area_struct *vma);
int hfi2_mmap_entry_insert(struct ib_ucontext *ucontext,
			   struct hfi2_filedata *fd, u8 type,
			   size_t length, u64 address, void *memvirt,
			   dma_addr_t memdma, u64 *offset);
void hfi2_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
int hfi2_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata);
void hfi2_dealloc_ucontext(struct ib_ucontext *ucontext);
int hfi2_rdma_mmap(struct ib_ucontext *ucontext, struct vm_area_struct *vma);
ssize_t hfi2_uverbs_write_iter(struct ib_ucontext *ucontext,
			       struct iov_iter *from);

extern const struct uapi_definition hfi2_ib_defs[];

#endif /* HFI2_UVERBS_H */
