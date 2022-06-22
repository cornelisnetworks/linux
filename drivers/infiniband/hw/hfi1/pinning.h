/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2022 Cornelis Networks, Inc.
 */
#ifndef _HFI1_PINNING_H
#define _HFI1_PINNING_H

#include <rdma/hfi/hfi1_user.h>

struct page;
struct sg_table;

struct hfi1_devdata;
struct hfi1_user_sdma_pkt_q;
struct sdma_desc;
struct user_sdma_request;
struct user_sdma_txreq;
struct user_sdma_iovec;

struct pinning_interface {
	int (*init)(struct hfi1_user_sdma_pkt_q *pq);
	void (*free)(struct hfi1_user_sdma_pkt_q *pq);

	/*
	 * Add up to pkt_data_remaining bytes to the txreq, starting at the
	 * current offset in the given iovec entry and continuing until all
	 * data has been added to the iovec or the iovec entry type changes.
	 * On success, prior to returning, the implementation must adjust
	 * pkt_data_remaining, req->iov_idx, and the offset value in
	 * req->iov[req->iov_idx] to reflect the data that has been
	 * consumed.
	 */
	int (*add_to_sdma_packet)(struct user_sdma_request *req,
				  struct user_sdma_txreq *tx,
				  struct user_sdma_iovec *iovec,
				  u32 *pkt_data_remaining);

	/*
	 * At completion of a txreq, this is invoked for each descriptor.
	 */
	void (*descriptor_complete)(struct hfi1_devdata *dd,
				    struct sdma_desc *descp);
	int (*get_stats)(struct hfi1_user_sdma_pkt_q *pq, int index,
			 struct hfi1_pin_stats *stats);
};

#define PINNING_MAX_INTERFACES (1 << HFI1_MEMINFO_TYPE_ENTRY_BITS)

struct pinning_state {
	void *interface[PINNING_MAX_INTERFACES];
};

#define PINNING_STATE(pq, i) ((pq)->pinning_state.interface[(i)])

extern struct pinning_interface pinning_interfaces[PINNING_MAX_INTERFACES];

void register_pinning_interface(unsigned int type,
				struct pinning_interface *interface);
void deregister_pinning_interface(unsigned int type);

void register_system_pinning_interface(void);
void deregister_system_pinning_interface(void);
void register_dmabuf_pinning_interface(void);
void deregister_dmabuf_pinning_interface(void);

int init_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq);
void free_pinning_interfaces(struct hfi1_user_sdma_pkt_q *pq);

static inline bool pinning_type_supported(unsigned int type)
{
	return (type < PINNING_MAX_INTERFACES &&
		pinning_interfaces[type].add_to_sdma_packet);
}

static inline int add_to_sdma_packet(unsigned int type,
				     struct user_sdma_request *req,
				     struct user_sdma_txreq *tx,
				     struct user_sdma_iovec *iovec,
				     u32 *pkt_data_remaining)
{
	return pinning_interfaces[type].add_to_sdma_packet(req, tx, iovec,
							   pkt_data_remaining);
}

static inline void sdma_descriptor_complete(unsigned int type,
					    struct hfi1_devdata *dd,
					    struct sdma_desc *descp)
{
	pinning_interfaces[type].descriptor_complete(dd, descp);
}

void release_sdma_request_pages(struct user_sdma_request *req, bool unpin);

#endif /* _HFI1_PINNING_H */
