// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2016 Intel Corporation.
 */

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <rdma/uverbs_ioctl.h>

#include "srq.h"
#include "vt.h"
#include "qp.h"
/**
 * rvt_driver_srq_init - init srq resources on a per driver basis
 * @rdi: rvt dev structure
 *
 * Do any initialization needed when a driver registers with rdmavt.
 */
void rvt_driver_srq_init(struct rvt_dev_info *rdi)
{
	spin_lock_init(&rdi->n_srqs_lock);
	rdi->n_srqs_allocated = 0;
}

/**
 * rvt_create_srq - create a shared receive queue
 * @ibsrq: the protection domain of the SRQ to create
 * @srq_init_attr: the attributes of the SRQ
 * @udata: data from libibverbs when creating a user SRQ
 *
 * Return: 0 on success
 */
int rvt_create_srq(struct ib_srq *ibsrq, struct ib_srq_init_attr *srq_init_attr,
		   struct ib_udata *udata)
{
	struct rvt_dev_info *dev = ib_to_rvt(ibsrq->device);
	struct rvt_srq *srq = ibsrq_to_rvtsrq(ibsrq);
	u32 sz;
	int ret;

	if (srq_init_attr->srq_type != IB_SRQT_BASIC)
		return -EOPNOTSUPP;

	if (srq_init_attr->attr.max_sge == 0 ||
	    srq_init_attr->attr.max_sge > dev->dparms.props.max_srq_sge ||
	    srq_init_attr->attr.max_wr == 0 ||
	    srq_init_attr->attr.max_wr > dev->dparms.props.max_srq_wr)
		return -EINVAL;

	/*
	 * Need to use vmalloc() if we want to support large #s of entries.
	 */
	srq->rq.size = srq_init_attr->attr.max_wr + 1;
	srq->rq.max_sge = srq_init_attr->attr.max_sge;
	sz = sizeof(struct ib_sge) * srq->rq.max_sge +
		sizeof(struct rvt_rwqe);
	if (rvt_alloc_rq(&srq->rq, srq->rq.size * sz,
			 dev->dparms.node, udata)) {
		ret = -ENOMEM;
		goto bail_srq;
	}

	/*
	 * Return the address of the RWQ as the offset to mmap.
	 * See rvt_mmap() for details.
	 */
	if (udata && udata->outlen >= sizeof(__u64)) {
		u32 s = sizeof(struct rvt_rwq) + srq->rq.size * sz;

		srq->ip = rvt_create_mmap_info(dev, s, udata, srq->rq.wq);
		if (IS_ERR(srq->ip)) {
			ret = PTR_ERR(srq->ip);
			goto bail_wq;
		}

		ret = ib_copy_to_udata(udata, &srq->ip->offset,
				       sizeof(srq->ip->offset));
		if (ret)
			goto bail_ip;
	}

	/*
	 * ib_create_srq() will initialize srq->ibsrq.
	 */
	spin_lock_init(&srq->rq.lock);
	srq->limit = srq_init_attr->attr.srq_limit;

	spin_lock(&dev->n_srqs_lock);
	if (dev->n_srqs_allocated == dev->dparms.props.max_srq) {
		spin_unlock(&dev->n_srqs_lock);
		ret = -ENOMEM;
		goto bail_ip;
	}

	dev->n_srqs_allocated++;
	spin_unlock(&dev->n_srqs_lock);

	if (srq->ip) {
		spin_lock_irq(&dev->pending_lock);
		list_add(&srq->ip->pending_mmaps, &dev->pending_mmaps);
		spin_unlock_irq(&dev->pending_lock);
	}

	return 0;

bail_ip:
	kfree(srq->ip);
bail_wq:
	rvt_free_rq(&srq->rq);
bail_srq:
	return ret;
}

/**
 * rvt_modify_srq - modify a shared receive queue
 * @ibsrq: the SRQ to modify
 * @attr: the new attributes of the SRQ
 * @attr_mask: indicates which attributes to modify
 * @udata: user data for libibverbs.so
 *
 * Return: 0 on success
 */
int rvt_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
		   enum ib_srq_attr_mask attr_mask,
		   struct ib_udata *udata)
{
	struct rvt_srq *srq = ibsrq_to_rvtsrq(ibsrq);
	struct rvt_dev_info *dev = ib_to_rvt(ibsrq->device);
	struct rvt_rq tmp_rq = {};
	__u64 offset_addr;
	int ret = 0;

	if (attr_mask & IB_SRQ_MAX_WR) {
		struct rvt_mmap_info *new_ip = NULL;
		struct rvt_mmap_info *old_ip;
		struct rvt_krwq *okwq;
		struct rvt_rwq *owq = NULL;
		struct rvt_rwqe *p;
		unsigned long flags;
		u32 sz, size, n, head, tail, nsge;
		bool mapped;

		if (attr->max_wr > dev->dparms.props.max_srq_wr)
			return -EINVAL;
		sz = sizeof(struct rvt_rwqe) +
			srq->rq.max_sge * sizeof(struct ib_sge);
		size = attr->max_wr + 1;
		if (rvt_alloc_rq(&tmp_rq, size * sz, dev->dparms.node,
				 udata))
			return -ENOMEM;

		spin_lock_irqsave(&srq->rq.lock, flags);
		mapped = !!srq->ip;
		spin_unlock_irqrestore(&srq->rq.lock, flags);

		if (mapped) {
			if (!udata || udata->inlen < sizeof(offset_addr)) {
				ret = -EINVAL;
				goto bail_free;
			}
			ret = ib_copy_from_udata(&offset_addr, udata,
						 sizeof(offset_addr));
			if (ret)
				goto bail_free;
			new_ip = rvt_create_mmap_info(dev,
						      sizeof(struct rvt_rwq) + size * sz,
						      udata, tmp_rq.wq);
			if (IS_ERR(new_ip)) {
				ret = PTR_ERR(new_ip);
				new_ip = NULL;
				goto bail_free;
			}
			if (copy_to_user(u64_to_user_ptr(offset_addr), &new_ip->offset,
					 sizeof(new_ip->offset))) {
				ret = -EFAULT;
				goto bail_free;
			}
		}

		spin_lock_irqsave(&srq->rq.lock, flags);
		okwq = srq->rq.kwq;
		spin_lock(&okwq->c_lock);
		spin_lock(&okwq->p_lock);
		old_ip = srq->ip;
		if (!!old_ip != mapped || (!!udata != mapped) ||
		    (!!new_ip != mapped)) {
			ret = -EBUSY;
			goto bail_unlock;
		}
		if (attr_mask & IB_SRQ_LIMIT) {
			if (attr->srq_limit > attr->max_wr) {
				ret = -EINVAL;
				goto bail_unlock;
			}
		} else if (srq->limit > attr->max_wr) {
			ret = -EINVAL;
			goto bail_unlock;
		}
		if (udata) {
			owq = srq->rq.wq;
			head = RDMA_READ_UAPI_ATOMIC(owq->head);
			tail = RDMA_READ_UAPI_ATOMIC(owq->tail);
		} else {
			head = okwq->head;
			tail = okwq->tail;
		}
		if (head >= srq->rq.size || tail >= srq->rq.size) {
			ret = -EINVAL;
			goto bail_unlock;
		}
		n = head;
		if (n < tail)
			n += srq->rq.size - tail;
		else
			n -= tail;
		if (size <= n) {
			ret = -EINVAL;
			goto bail_unlock;
		}
		n = 0;
		p = tmp_rq.kwq->curr_wq;
		while (tail != head) {
			struct rvt_rwqe *wqe;
			int i;

			wqe = (struct rvt_rwqe *)((char *)okwq->curr_wq + sz * tail);
			p->wr_id = wqe->wr_id;
			nsge = min_t(u32, wqe->num_sge, srq->rq.max_sge);
			p->num_sge = nsge;
			for (i = 0; i < nsge; i++)
				p->sg_list[i] = wqe->sg_list[i];
			n++;
			p = (struct rvt_rwqe *)((char *)p + sz);
			if (++tail >= srq->rq.size)
				tail = 0;
		}

		srq->rq.kwq = tmp_rq.kwq;
		if (udata) {
			srq->rq.wq = tmp_rq.wq;
			RDMA_WRITE_UAPI_ATOMIC(tmp_rq.wq->head, n);
			RDMA_WRITE_UAPI_ATOMIC(tmp_rq.wq->tail, 0);
			srq->ip = new_ip;
		} else {
			tmp_rq.kwq->head = n;
			tmp_rq.kwq->tail = 0;
		}
		srq->rq.size = size;
		if (attr_mask & IB_SRQ_LIMIT)
			srq->limit = attr->srq_limit;
		if (new_ip) {
			spin_lock(&dev->pending_lock);
			list_add(&new_ip->pending_mmaps, &dev->pending_mmaps);
			spin_unlock(&dev->pending_lock);
		}
		spin_unlock(&okwq->p_lock);
		spin_unlock(&okwq->c_lock);
		spin_unlock_irqrestore(&srq->rq.lock, flags);

		if (old_ip)
			kref_put(&old_ip->ref, rvt_release_mmap_info);
		else
			vfree(owq);
		kvfree(okwq);
		return 0;

bail_unlock:
		spin_unlock(&okwq->p_lock);
		spin_unlock(&okwq->c_lock);
		spin_unlock_irqrestore(&srq->rq.lock, flags);
bail_free:
		if (new_ip) {
			new_ip->obj = NULL;
			kref_put(&new_ip->ref, rvt_release_mmap_info);
		}
		rvt_free_rq(&tmp_rq);
		return ret;
	} else if (attr_mask & IB_SRQ_LIMIT) {
		struct rvt_krwq *kwq;
		unsigned long flags;

		spin_lock_irqsave(&srq->rq.lock, flags);
		kwq = srq->rq.kwq;
		spin_lock(&kwq->c_lock);
		if (attr->srq_limit >= srq->rq.size)
			ret = -EINVAL;
		else
			srq->limit = attr->srq_limit;
		spin_unlock(&kwq->c_lock);
		spin_unlock_irqrestore(&srq->rq.lock, flags);
	}
	return ret;
}

/**
 * rvt_query_srq - query srq data
 * @ibsrq: srq to query
 * @attr: return info in attr
 *
 * Return: always 0
 */
int rvt_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct rvt_srq *srq = ibsrq_to_rvtsrq(ibsrq);
	unsigned long flags;

	spin_lock_irqsave(&srq->rq.lock, flags);
	attr->max_wr = srq->rq.size - 1;
	attr->max_sge = srq->rq.max_sge;
	attr->srq_limit = srq->limit;
	spin_unlock_irqrestore(&srq->rq.lock, flags);
	return 0;
}

/**
 * rvt_destroy_srq - destory an srq
 * @ibsrq: srq object to destroy
 * @udata: user data for libibverbs.so
 */
int rvt_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct rvt_srq *srq = ibsrq_to_rvtsrq(ibsrq);
	struct rvt_dev_info *dev = ib_to_rvt(ibsrq->device);

	spin_lock(&dev->n_srqs_lock);
	dev->n_srqs_allocated--;
	spin_unlock(&dev->n_srqs_lock);
	if (srq->ip)
		kref_put(&srq->ip->ref, rvt_release_mmap_info);
	kvfree(srq->rq.kwq);
	return 0;
}
