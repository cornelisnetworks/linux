// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright(c) 2020-2024 Cornelis Networks, Inc.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 * Copyright(c) 2016 - 2017 Intel Corporation.
 * Copyright(c) 2025-2026 Cornelis Networks, Inc.
 */

#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/mmu_notifier.h>
#include <linux/interval_tree_generic.h>
#include <linux/sched/mm.h>

#include "mmu_rb.h"
#include "trace.h"

static unsigned long mmu_node_start(struct mmu_rb_node *);
static unsigned long mmu_node_last(struct mmu_rb_node *);
static int mmu_notifier_range_start(struct mmu_notifier *,
		const struct mmu_notifier_range *);
static void mmu_rb_notifier_release(struct mmu_notifier *, struct mm_struct *);
static struct mmu_rb_node *__mmu_rb_search(struct mmu_rb_handler *,
					   unsigned long, unsigned long);
static void release_immediate(struct kref *refcount);
static void handle_remove(struct work_struct *work);

static const struct mmu_notifier_ops mn_opts = {
	.invalidate_range_start = mmu_notifier_range_start,
	.release = mmu_rb_notifier_release,
};

INTERVAL_TREE_DEFINE(struct mmu_rb_node, node, unsigned long, __last,
		     mmu_node_start, mmu_node_last, static, __mmu_int_rb);

static unsigned long mmu_node_start(struct mmu_rb_node *node)
{
	return node->addr & PAGE_MASK;
}

static unsigned long mmu_node_last(struct mmu_rb_node *node)
{
	return PAGE_ALIGN(node->addr + node->len) - 1;
}

static int _hfi2_mmu_rb_register(void *ops_arg, const struct mmu_rb_ops *ops,
				 struct workqueue_struct *wq,
				 struct mmu_rb_handler **handler,
				 const struct mmu_notifier_ops *mnops)
{
	struct mmu_rb_handler *h;
	void *free_ptr;
	int ret;

	free_ptr = kzalloc(sizeof(*h) + cache_line_size() - 1, GFP_KERNEL);
	if (!free_ptr)
		return -ENOMEM;

	h = PTR_ALIGN(free_ptr, cache_line_size());
	h->root = RB_ROOT_CACHED;
	h->ops = ops;
	h->ops_arg = ops_arg;
	INIT_HLIST_NODE(&h->mn.hlist);
	spin_lock_init(&h->lock);
	h->mn.ops = mnops;
	INIT_WORK(&h->del_work, handle_remove);
	INIT_LIST_HEAD(&h->del_list);
	INIT_LIST_HEAD(&h->lru_list);
	h->wq = wq;
	h->free_ptr = free_ptr;

	for (int i = 0; i < 20; i++) { /* arbitrary retry count */
		ret = mmu_notifier_register(&h->mn, current->mm);
		if (ret != -EINTR)
			break;
		/* let the process die if a fatal signal is pending */
		if (fatal_signal_pending(current))
			break;
		/* allow the signal handler to run before retrying */
		cond_resched();
	}

	if (ret) {
		kfree(free_ptr);
		return ret;
	}

	*handler = h;
	return 0;
}

int hfi2_mmu_rb_register(void *ops_arg, const struct mmu_rb_ops *ops,
			 struct workqueue_struct *wq,
			 struct mmu_rb_handler **handler)
{
	return _hfi2_mmu_rb_register(ops_arg, ops, wq, handler, &mn_opts);
}

void hfi2_mmu_rb_unregister(struct mmu_rb_handler *handler)
{
	struct mmu_rb_node *rbnode;
	struct rb_node *node;
	unsigned long flags;
	struct list_head del_list;

	/* Prevent freeing of mm until we are completely finished. */
	mmgrab(handler->mn.mm);

	/* mmu_notifier_unregister invokes .release on this thread; the
	 * flag tells it to skip the drain (we're about to do it ourselves).
	 */
	handler->release_in_unregister = true;

	/* Unregister first so we don't get any more notifications. */
	mmu_notifier_unregister(&handler->mn, handler->mn.mm);

	handler->release_in_unregister = false;

	/*
	 * Make sure the wq delete handler is finished running.  It will not
	 * be triggered once the mmu notifiers are unregistered above.
	 */
	flush_work(&handler->del_work);

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&handler->lock, flags);
	while ((node = rb_first_cached(&handler->root))) {
		rbnode = rb_entry(node, struct mmu_rb_node, node);
		rb_erase_cached(node, &handler->root);
		/* move from LRU list to delete list */
		list_move(&rbnode->list, &del_list);
	}
	spin_unlock_irqrestore(&handler->lock, flags);

	while (!list_empty(&del_list)) {
		rbnode = list_first_entry(&del_list, struct mmu_rb_node, list);
		list_del_init(&rbnode->list);
		kref_put(&rbnode->refcount, release_immediate);
	}

	/* Now the mm may be freed. */
	mmdrop(handler->mn.mm);

	kfree(handler->free_ptr);
}

int hfi2_mmu_rb_insert(struct mmu_rb_handler *handler,
		       struct mmu_rb_node *mnode)
{
	struct mmu_rb_node *node;
	unsigned long flags;
	int ret = 0;

	trace_hfi2_mmu_rb_insert(mnode);

	// Figure this out, need to pin from poll loop.
	// if (current->mm != handler->mn.mm)
	// 	return -EPERM;

	spin_lock_irqsave(&handler->lock, flags);
	node = __mmu_rb_search(handler, mnode->addr, mnode->len);
	if (node) {
		ret = -EEXIST;
		goto unlock;
	}
	__mmu_int_rb_insert(mnode, &handler->root);
	list_add_tail(&mnode->list, &handler->lru_list);
	mnode->handler = handler;
unlock:
	spin_unlock_irqrestore(&handler->lock, flags);
	return ret;
}

/* Caller must hold handler lock */
struct mmu_rb_node *hfi2_mmu_rb_get_first(struct mmu_rb_handler *handler,
					  unsigned long addr, unsigned long len)
{
	struct mmu_rb_node *node;

	trace_hfi2_mmu_rb_search(addr, len);
	node = __mmu_int_rb_iter_first(&handler->root, addr, (addr + len) - 1);
	if (node)
		list_move_tail(&node->list, &handler->lru_list);
	return node;
}

/* Caller must hold handler lock */
static struct mmu_rb_node *__mmu_rb_search(struct mmu_rb_handler *handler,
					   unsigned long addr,
					   unsigned long len)
{
	struct mmu_rb_node *node = NULL;

	trace_hfi2_mmu_rb_search(addr, len);
	if (!handler->ops->filter) {
		node = __mmu_int_rb_iter_first(&handler->root, addr,
					       (addr + len) - 1);
	} else {
		for (node = __mmu_int_rb_iter_first(&handler->root, addr,
						    (addr + len) - 1);
		     node; node = __mmu_int_rb_iter_next(node, addr,
							 (addr + len) - 1)) {
			if (handler->ops->filter(node, addr, len))
				return node;
		}
	}
	return node;
}

/* Caller must hold handler lock */
struct mmu_rb_node *hfi2_mmu_rb_search(struct mmu_rb_handler *handler,
					  unsigned long addr, unsigned long len)
{
	struct mmu_rb_node *node;

	trace_hfi2_mmu_rb_search(addr, len);
	node = __mmu_rb_search(handler, addr, len);
	if (node)
		list_move_tail(&node->list, &handler->lru_list);
	return node;
}



/*
 * Must NOT call while holding mnode->handler->lock.
 * mnode->handler->ops->remove() may sleep and mnode->handler->lock is a
 * spinlock.
 */
static void release_immediate(struct kref *refcount)
{
	struct mmu_rb_node *mnode =
		container_of(refcount, struct mmu_rb_node, refcount);
	trace_hfi2_mmu_release_node(mnode);
	mnode->handler->ops->remove(mnode->handler->ops_arg, mnode);
}

/* Caller must hold mnode->handler->lock */
static void release_nolock(struct kref *refcount)
{
	struct mmu_rb_node *mnode =
		container_of(refcount, struct mmu_rb_node, refcount);
	list_move(&mnode->list, &mnode->handler->del_list);
	queue_work(mnode->handler->wq, &mnode->handler->del_work);
}

/*
 * struct mmu_rb_node->refcount kref_put() callback.
 * Adds mmu_rb_node to mmu_rb_node->handler->del_list and queues
 * handler->del_work on handler->wq.
 * Does not remove mmu_rb_node from handler->lru_list or handler->rb_root.
 * Acquires mmu_rb_node->handler->lock; do not call while already holding
 * handler->lock.
 */
void hfi2_mmu_rb_release(struct kref *refcount)
{
	struct mmu_rb_node *mnode =
		container_of(refcount, struct mmu_rb_node, refcount);
	struct mmu_rb_handler *handler = mnode->handler;
	unsigned long flags;

	spin_lock_irqsave(&handler->lock, flags);
	list_move(&mnode->list, &mnode->handler->del_list);
	spin_unlock_irqrestore(&handler->lock, flags);
	queue_work(handler->wq, &handler->del_work);
}

void hfi2_mmu_rb_evict(struct mmu_rb_handler *handler, void *evict_arg)
{
	struct mmu_rb_node *rbnode, *ptr;
	struct list_head del_list;
	unsigned long flags;
	bool stop = false;

	if (current->mm != handler->mn.mm)
		return;

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&handler->lock, flags);
	list_for_each_entry_safe(rbnode, ptr, &handler->lru_list, list) {
		/* refcount == 1 implies mmu_rb_handler has only rbnode ref */
		if (kref_read(&rbnode->refcount) > 1)
			continue;

		if (handler->ops->evict(handler->ops_arg, rbnode, evict_arg,
					&stop)) {
			__mmu_int_rb_remove(rbnode, &handler->root);
			/* move from LRU list to delete list */
			list_move(&rbnode->list, &del_list);
			++handler->internal_evictions;
		}
		if (stop)
			break;
	}
	spin_unlock_irqrestore(&handler->lock, flags);

	list_for_each_entry_safe(rbnode, ptr, &del_list, list) {
		trace_hfi2_mmu_rb_evict(rbnode);
		list_del_init(&rbnode->list);
		kref_put(&rbnode->refcount, release_immediate);
	}
}

unsigned long hfi2_mmu_rb_for_n(
	struct mmu_rb_handler *handler, unsigned long start, int count,
	void (*fn)(const struct mmu_rb_node *rb_node, void *), void *arg)
{
	struct mmu_rb_node *node = NULL, *next;
	int i;

	/*
	 * The query range (start, ~0ULL) must stay constant across
	 * __mmu_int_rb_iter_first()/__mmu_int_rb_iter_next() calls; the
	 * interval-tree iterator walks the tree using this fixed range and
	 * the current node's position, not by re-deriving a new starting
	 * point from the previous node's length on each call. Previously
	 * "~0ULL - start" (relative) was passed as the upper bound and the
	 * lower bound was advanced by the previous node's length on every
	 * iteration, which does not match this iterator's expected usage
	 * and could skip or double count nodes.
	 */
	next = __mmu_int_rb_iter_first(&handler->root, start, ~0ULL);
	for (i = 0; i < count; i++) {
		node = next;
		if (!node)
			return ~0UL;

		next = __mmu_int_rb_iter_next(node, start, ~0ULL);
		fn(node, arg);
	}
	return node->addr;
}

static int mmu_notifier_range_start(struct mmu_notifier *mn,
				    const struct mmu_notifier_range *range)
{
	struct mmu_rb_handler *handler =
		container_of(mn, struct mmu_rb_handler, mn);
	struct rb_root_cached *root = &handler->root;
	struct mmu_rb_node *node, *ptr = NULL;
	unsigned long flags;

	spin_lock_irqsave(&handler->lock, flags);
	for (node = __mmu_int_rb_iter_first(root, range->start, range->end - 1);
	     node; node = ptr) {
		/* Guard against node removal. */
		ptr = __mmu_int_rb_iter_next(node, range->start,
					     range->end - 1);
		trace_hfi2_mmu_mem_invalidate(node);
		/* Remove from rb tree and lru_list. */
		__mmu_int_rb_remove(node, root);
		list_del_init(&node->list);
		kref_put(&node->refcount, release_nolock);
		handler->external_evictions++;
	}
	spin_unlock_irqrestore(&handler->lock, flags);

	return 0;
}

/*
 * exit_mmap calls us before unmap_vmas / free_pgtables and delists the
 * subscription, so invalidate_range_start won't fire for the subsequent
 * zaps.  This is the last chance to drop FOLL_PIN while anon_vma is
 * still live.  May sleep.
 */
static void mmu_rb_notifier_release(struct mmu_notifier *mn,
				    struct mm_struct *mm)
{
	struct mmu_rb_handler *handler =
		container_of(mn, struct mmu_rb_handler, mn);
	struct mmu_rb_node *rbnode;
	struct rb_node *node;
	struct list_head del_list;
	unsigned long flags;

	/* hfi2_mmu_rb_unregister path has already drained; skip. */
	if (handler->release_in_unregister)
		return;

	if (handler->ops->sync_drain)
		handler->ops->sync_drain(handler->ops_arg);

	INIT_LIST_HEAD(&del_list);

	spin_lock_irqsave(&handler->lock, flags);
	while ((node = rb_first_cached(&handler->root))) {
		rbnode = rb_entry(node, struct mmu_rb_node, node);
		rb_erase_cached(node, &handler->root);
		list_move(&rbnode->list, &del_list);
	}
	spin_unlock_irqrestore(&handler->lock, flags);

	while (!list_empty(&del_list)) {
		rbnode = list_first_entry(&del_list, struct mmu_rb_node, list);
		list_del_init(&rbnode->list);
		kref_put(&rbnode->refcount, release_immediate);
	}

	/* Targeted flush: handler->wq is shared (dd->hfi2_wq); only del_work
	 * matters here.
	 */
	flush_work(&handler->del_work);
}

/*
 * Work queue function to remove all nodes that have been queued up to
 * be removed.  The key feature is that mm->mmap_lock is not being held
 * and the remove callback can sleep while taking it, if needed.
 */
static void handle_remove(struct work_struct *work)
{
	struct mmu_rb_handler *handler =
		container_of(work, struct mmu_rb_handler, del_work);
	struct list_head del_list;
	unsigned long flags;
	struct mmu_rb_node *node;

	/* remove anything that is queued to get removed */
	spin_lock_irqsave(&handler->lock, flags);
	list_replace_init(&handler->del_list, &del_list);
	spin_unlock_irqrestore(&handler->lock, flags);

	while (!list_empty(&del_list)) {
		node = list_first_entry(&del_list, struct mmu_rb_node, list);
		list_del_init(&node->list);
		trace_hfi2_mmu_release_node(node);
		handler->ops->remove(handler->ops_arg, node);
	}
}

