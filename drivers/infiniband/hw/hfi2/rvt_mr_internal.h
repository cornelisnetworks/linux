/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2016 Intel Corporation.
 */

#ifndef DEF_RVTMR_H
#define DEF_RVTMR_H

#include <linux/workqueue.h>

#include "rvt.h"

struct rvt_mr {
	struct ib_mr ibmr;
	struct ib_umem *umem;
	struct rvt_dev_info *rdi;
	struct rcu_work dereg_work;
	struct rcu_head rcu;
	struct rvt_mregion mr;  /* must be last */
};

static inline struct rvt_mr *to_imr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct rvt_mr, ibmr);
}

int rvt_mr_refs_init(struct rvt_mregion *mr);
void rvt_mr_refs_free(struct rvt_mregion *mr);
void rvt_mr_kill(struct rvt_mregion *mr);
int rvt_driver_mr_init(struct rvt_dev_info *rdi);
void rvt_mr_exit(struct rvt_dev_info *rdi);

/* Mem Regions */
struct ib_mr *rvt_get_dma_mr(struct ib_pd *pd, int acc);
struct ib_mr *rvt_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
			      u64 virt_addr, int mr_access_flags,
			      struct ib_dmah *dmah,
			      struct ib_udata *udata);
struct ib_mr *rvt_reg_user_mr_dmabuf(struct ib_pd *pd, u64 offset,
				     u64 length, u64 virt_addr,
				     int fd, int mr_access_flags,
				     struct ib_dmah *dmah,
				     struct uverbs_attr_bundle *attrs);
int rvt_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata);
struct ib_mr *rvt_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			   u32 max_num_sg);
struct ib_mr *rvt_alloc_internal_mr(struct ib_pd *pd);
void rvt_unpublish_internal_mr(struct ib_mr *ibmr);
void rvt_free_internal_mr(struct ib_mr *ibmr);
int rvt_rotate_internal_mr_key(struct ib_mr *ibmr, u32 *key,
			       enum rvt_internal_mr_key_policy policy);
int rvt_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
		  int sg_nents, unsigned int *sg_offset);

#endif          /* DEF_RVTMR_H */
