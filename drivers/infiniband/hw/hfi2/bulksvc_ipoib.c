// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * IPoIB transmit handoff.  See bulksvc_ipoib.h.
 */
#include <linux/slab.h>

#include "bulksvc.h"
#include "bulksvc_ipoib.h"
#include "dms.h"
#include "dms_sdma.h"

/*
 * Nodes egressed per port per pass, split across its lanes so the bound does
 * not scale with the lane count.  The event thread also drives DMS, verbs
 * completions and the user command queues, so an unbounded drain starves them.
 */
#define HFI2_BULKSVC_IPOIB_POLL_BUDGET 256
#define HFI2_BULKSVC_IPOIB_LANE_BUDGET_MIN 16

void hfi2_bulksvc_ipoib_init(struct hfi2_bulksvc *svc)
{
	u8 i;

	for (i = 0; i < HFI2_DMS_MAX_PORTS; i++) {
		svc->ipoib[i].lanes = NULL;
		svc->ipoib[i].nlanes = 0;
		svc->ipoib[i].egress = NULL;
	}
	svc->ipoib_registered = 0;
}

int hfi2_bulksvc_ipoib_port_register(struct hfi2_bulksvc *svc, u8 port_idx,
				     const struct hfi2_bulksvc_ipoib_ops *ops)
{
	struct hfi2_bulksvc_ipoib_port *port;
	struct hfi2_bulksvc_ipoib_lane *lanes;
	struct hfi2_dms *dms;
	u8 i;

	if (!svc || !ops || !ops->egress || !ops->nlanes ||
	    port_idx >= HFI2_DMS_MAX_PORTS)
		return -EINVAL;
	dms = hfi2_bulksvc_primary_dms(svc);
	if (!dms->dd || !dms->port_available[port_idx])
		return -ENXIO;

	port = &svc->ipoib[port_idx];
	if (port->egress)
		return -EBUSY;

	lanes = kcalloc_node(ops->nlanes, sizeof(*lanes), GFP_KERNEL,
			     dms->numa_node);
	if (!lanes)
		return -ENOMEM;

	for (i = 0; i < ops->nlanes; i++)
		mpsc_init(&lanes[i].txq);

	port->lanes = lanes;
	port->nlanes = ops->nlanes;
	port->ctx = ops->ctx;
	port->flush = ops->flush;
	/* Publish all of the above before @egress; the poll acquires it. */
	smp_store_release(&port->egress, ops->egress);

	/* After @egress, so a non-zero count implies a fully-built port. */
	WRITE_ONCE(svc->ipoib_registered, svc->ipoib_registered + 1);

	return 0;
}

void hfi2_bulksvc_ipoib_port_unregister(struct hfi2_bulksvc *svc, u8 port_idx)
{
	struct hfi2_bulksvc_ipoib_port *port;

	if (!svc || port_idx >= HFI2_DMS_MAX_PORTS)
		return;

	port = &svc->ipoib[port_idx];
	if (!port->egress)
		return;

	/* Stop the event thread from entering the callback again. */
	smp_store_release(&port->egress, NULL);

	/*
	 * Wait out the one pass that could still hold the old pointer.
	 * flush_work() does not wait for a self-requeued instance, and this
	 * work does self-requeue; that is safe only because every later pass
	 * re-reads @egress in hfi2_bulksvc_ipoib_poll() and returns before
	 * touching anything else.  Do not hoist or cache that load.
	 */
	if (svc->event_workq)
		flush_work(&svc->lanes[HFI2_BULKSVC_PRIMARY_LANE].work);

	/*
	 * Queued nodes belong to the caller, which reclaims them from its own
	 * ring, so the lanes are discarded rather than drained.
	 */
	kfree(port->lanes);
	port->lanes = NULL;
	port->nlanes = 0;
	port->flush = NULL;
	port->ctx = NULL;

	/* After the port is torn down, so no pass can find it half-freed. */
	WRITE_ONCE(svc->ipoib_registered, svc->ipoib_registered - 1);
}

void hfi2_bulksvc_ipoib_tx_enqueue(struct hfi2_bulksvc *svc, u8 port_idx,
				   u8 lane, struct mpsc_node *node)
{
	struct hfi2_bulksvc_ipoib_port *port;

	if (WARN_ON_ONCE(!svc || !node || port_idx >= HFI2_DMS_MAX_PORTS))
		return;

	port = &svc->ipoib[port_idx];
	if (WARN_ON_ONCE(!port->lanes || lane >= port->nlanes))
		return;

	mpsc_enqueue(&port->lanes[lane].txq, node);
	hfi2_bulksvc_schedule(svc);
}

/*
 * Drain one lane.  Runs on the bulksvc event thread.  Returns nodes egressed;
 * a held retry is reported through @held, being work owed rather than done.
 */
static int ipoib_lane_poll(struct hfi2_bulksvc_ipoib_port *port,
			   struct hfi2_bulksvc_ipoib_lane *lane,
			   int (*egress)(void *ctx, struct mpsc_node *node,
					 struct mpsc_node **retry),
			   int budget, bool *held)
{
	int done = 0;

	while (budget--) {
		struct mpsc_node *node;
		struct mpsc_node *retry;
		int ret;

		/* A previously deferred node goes first, to keep FIFO order. */
		if (lane->retry) {
			node = lane->retry;
			lane->retry = NULL;
		} else {
			node = mpsc_dequeue(&lane->txq);
			if (!node)
				break;
		}

		retry = node;
		ret = egress(port->ctx, node, &retry);
		if (ret == -EAGAIN) {
			/*
			 * Dequeuing past it would reorder the flow.  Hold the
			 * node @egress asked for, not the one passed in: a
			 * run's earlier packets may already be placed and
			 * reclaimable at any moment.
			 */
			lane->retry = retry;
			*held = true;
			break;
		}

		/* Any other outcome: egress completed the node. */
		done++;
	}

	return done;
}

/*
 * End of pass: ring the deferred tails, then let each port publish.  The
 * doorbell is here rather than in a port's hook because tail CSRs are per
 * engine, so it belongs to the pass and not to any one port.
 */
static void ipoib_publish(struct hfi2_bulksvc *svc)
{
	u8 i;

	hfi2_dms_sdma_doorbell_all(hfi2_bulksvc_primary_dms(svc));

	for (i = 0; i < HFI2_DMS_MAX_PORTS; i++) {
		struct hfi2_bulksvc_ipoib_port *port = &svc->ipoib[i];

		/* Same acquire load as the poll path.  See unregister. */
		if (!smp_load_acquire(&port->egress) || !port->flush)
			continue;

		port->flush(port->ctx);
	}
}

int hfi2_bulksvc_ipoib_poll(struct hfi2_bulksvc *svc)
{
	int done = 0;
	bool held = false;
	u8 i;

	if (!READ_ONCE(svc->ipoib_registered))
		return 0;

	for (i = 0; i < HFI2_DMS_MAX_PORTS; i++) {
		struct hfi2_bulksvc_ipoib_port *port = &svc->ipoib[i];
		int (*egress)(void *ctx, struct mpsc_node *node,
			      struct mpsc_node **retry);
		int lane_budget;
		u8 l;

		/* Pairs with the release stores in register/unregister. */
		egress = smp_load_acquire(&port->egress);
		if (!egress)
			continue;

		lane_budget = max(HFI2_BULKSVC_IPOIB_POLL_BUDGET /
				  port->nlanes,
				  HFI2_BULKSVC_IPOIB_LANE_BUDGET_MIN);

		for (l = 0; l < port->nlanes; l++)
			done += ipoib_lane_poll(port, &port->lanes[l], egress,
						lane_budget, &held);
	}

	ipoib_publish(svc);

	/*
	 * Ask for another pass rather than counting the retry as progress,
	 * which would keep the shared event thread at its iteration cap and
	 * grow its halt-poll window on passes that placed nothing.
	 */
	if (held)
		hfi2_bulksvc_schedule(svc);

	return done;
}

void hfi2_bulksvc_ipoib_drain(struct hfi2_bulksvc *svc)
{
	if (!READ_ONCE(svc->ipoib_registered))
		return;

	ipoib_publish(svc);
}
