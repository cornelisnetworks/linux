/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * IPoIB transmit handoff to the bulksvc event thread.  The DMS egress
 * primitives may only run on that thread, so IPoIB transmit enqueues an
 * already-built packet here and the event thread egresses it.
 */
#ifndef DEF_HFI2_BULKSVC_IPOIB_H
#define DEF_HFI2_BULKSVC_IPOIB_H

#include <linux/types.h>

#include "bulksvc_mpsc.h"

struct hfi2_bulksvc;

/**
 * struct hfi2_bulksvc_ipoib_lane - one independently-drained handoff queue
 * @txq: handoff queue; transmitters enqueue, the event thread dequeues
 * @retry: a node whose egress returned -EAGAIN.  Held rather than put back on
 *	@txq, which is append-only: requeueing would move the packet behind
 *	everything enqueued meanwhile and reorder the flow.
 *
 * A held @retry stops its own lane only, so a backend wants one lane per
 * resource that can independently refuse a packet.
 */
struct hfi2_bulksvc_ipoib_lane {
	struct mpsc_queue txq;
	struct mpsc_node *retry;
};

/**
 * struct hfi2_bulksvc_ipoib_port - per-port transmit handoff state
 * @lanes: @nlanes handoff queues, allocated at register
 * @nlanes: number of lanes
 * @ctx: backend context for @egress
 * @egress: backend transmit callback, and the register/unregister latch
 * @flush: optional end-of-pass hook, see hfi2_bulksvc_ipoib_ops
 */
struct hfi2_bulksvc_ipoib_port {
	struct hfi2_bulksvc_ipoib_lane *lanes;
	u8 nlanes;
	void *ctx;
	int (*egress)(void *ctx, struct mpsc_node *node,
		      struct mpsc_node **retry);
	void (*flush)(void *ctx);
};

/**
 * struct hfi2_bulksvc_ipoib_ops - per-port transmit callbacks
 * @ctx: opaque backend context, passed back unchanged
 * @nlanes: independently-drained queues to create, >= 1
 * @egress: transmit one dequeued node, on the bulksvc event thread.  Return
 *	-EAGAIN to have the node retried on a later pass; any other value means
 *	@egress has completed the node, including freeing the skb.  A node may
 *	cover a run of several packets, so on -EAGAIN the node to resume from is
 *	not necessarily the one passed in -- earlier packets may already be
 *	placed and reclaimable at any moment -- and @egress writes it to @retry.
 * @flush: optional, runs at the end of every pass, after the deferred SDMA
 *	doorbell.  Where a backend publishes what the pass produced, keeping
 *	@egress free of per-packet work.
 */
struct hfi2_bulksvc_ipoib_ops {
	void *ctx;
	u8 nlanes;
	int (*egress)(void *ctx, struct mpsc_node *node,
		      struct mpsc_node **retry);
	void (*flush)(void *ctx);
};

/*
 * Register/unregister a port's transmit handoff, from ndo_open/ndo_stop and
 * never concurrently with transmit.  When unregister returns the event thread
 * no longer uses the port; nodes still queued are dropped without egress and
 * the caller reclaims them.
 */
int hfi2_bulksvc_ipoib_port_register(struct hfi2_bulksvc *svc, u8 port_idx,
				     const struct hfi2_bulksvc_ipoib_ops *ops);
void hfi2_bulksvc_ipoib_port_unregister(struct hfi2_bulksvc *svc, u8 port_idx);

/*
 * Hand one built packet to the event thread and wake it.  Safe from any CPU.
 * @lane selects the handoff queue and must be < the registered @nlanes.
 * @node then belongs to the event thread until its egress completes it.
 */
void hfi2_bulksvc_ipoib_tx_enqueue(struct hfi2_bulksvc *svc, u8 port_idx,
				   u8 lane, struct mpsc_node *node);

/* Called from bulksvc.c. */
void hfi2_bulksvc_ipoib_init(struct hfi2_bulksvc *svc);
int hfi2_bulksvc_ipoib_poll(struct hfi2_bulksvc *svc);

/*
 * Run the end-of-pass publication without accepting new work.  Call from the
 * event thread when it is about to stop polling, so anything a poll placed
 * does not wait for the next unrelated wakeup.
 */
void hfi2_bulksvc_ipoib_drain(struct hfi2_bulksvc *svc);

#endif /* DEF_HFI2_BULKSVC_IPOIB_H */
