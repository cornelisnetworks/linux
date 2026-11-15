/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2026 Cornelis Networks.
 *
 * Intrusive multi-producer / single-consumer FIFO queue.
 *
 * Dmitry Vyukov's intrusive node-based MPSC algorithm:
 *   https://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue
 *
 * Producer is wait-free (one xchg + one store_release, no IRQ disable).
 * The single consumer needs no atomics on the fast path but may return
 * NULL transiently while a producer is between its xchg and its
 * store_release; the caller treats that like a transiently empty queue
 * and retries.  A permanent stub node is recycled as the sentinel and
 * is skipped transparently by mpsc_dequeue().
 */

#ifndef DEF_HFI2_BULKSVC_MPSC_H
#define DEF_HFI2_BULKSVC_MPSC_H

#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/types.h>

struct mpsc_node {
	struct mpsc_node *next;
};

/* head/tail/stub on separate cachelines so producers and the consumer
 * don't bounce each other.
 */
struct mpsc_queue {
	struct mpsc_node *head ____cacheline_aligned;
	struct mpsc_node *tail ____cacheline_aligned;
	struct mpsc_node stub  ____cacheline_aligned;
};

static inline void mpsc_init(struct mpsc_queue *q)
{
	q->stub.next = NULL;
	q->head = &q->stub;
	q->tail = &q->stub;
}

/**
 * mpsc_enqueue - append a node to the queue (multi-producer safe)
 * @q: the queue
 * @n: the node to append
 *
 * The producer hands ownership of @n to the queue.  After this call
 * returns, the producer must not touch @n.  (Other producers and the
 * consumer may both be inspecting @n's `next` pointer.)
 *
 * Returns true if @q was empty (previous head was the stub) as observed
 * by this producer - a hint for eliding a redundant consumer wakeup.
 */
static inline bool mpsc_enqueue(struct mpsc_queue *q, struct mpsc_node *n)
{
	struct mpsc_node *prev;

	WRITE_ONCE(n->next, NULL);
	/* xchg is a full barrier; we own the right to publish prev->next once. */
	prev = xchg(&q->head, n);
	/* Release-publish the link; pairs with the consumer's acquire load
	 * of tail->next.  Until it lands the consumer sees a transient NULL.
	 */
	smp_store_release(&prev->next, n);
	return prev == &q->stub;
}

/**
 * mpsc_dequeue - remove and return one node from the queue (single consumer)
 * @q: the queue
 *
 * Returns the next FIFO-ordered node, or NULL if the queue is empty
 * (or transiently inconsistent because a producer is between its
 * xchg and its store_release).
 *
 * Caller must serialize calls; this is *not* multi-consumer safe.
 */
static inline struct mpsc_node *mpsc_dequeue(struct mpsc_queue *q)
{
	struct mpsc_node *tail = q->tail;
	struct mpsc_node *next = smp_load_acquire(&tail->next);

	/* Skip the stub sentinel; the real first node is stub->next. */
	if (tail == &q->stub) {
		if (!next)
			return NULL;	/* genuinely empty */
		q->tail = next;
		tail = next;
		next = smp_load_acquire(&tail->next);
	}

	if (next) {
		q->tail = next;
		return tail;
	}

	/* tail->next == NULL: queue empty, or a producer is mid-update
	 * (head != tail but its store_release hasn't landed yet).
	 */
	if (tail != READ_ONCE(q->head))
		return NULL;	/* producer mid-update; retry next time */

	/* Genuinely empty and the stub isn't in the queue: re-link it. */
	mpsc_enqueue(q, &q->stub);

	next = smp_load_acquire(&tail->next);
	if (next) {
		q->tail = next;
		return tail;
	}

	return NULL;
}

/**
 * mpsc_is_empty - lock-free emptiness probe
 * @q: the queue
 *
 * Returns true if the queue is empty at this instant.  A producer may
 * enqueue right after we return true; callers must tolerate a stale
 * `true` (they see the new node on the next call).
 */
static inline bool mpsc_is_empty(struct mpsc_queue *q)
{
	struct mpsc_node *tail = READ_ONCE(q->tail);
	struct mpsc_node *head = READ_ONCE(q->head);

	return tail == head && tail == &q->stub;
}

#endif /* DEF_HFI2_BULKSVC_MPSC_H */
