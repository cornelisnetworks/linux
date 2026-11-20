// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2023 Cornelis Networks.
 */

/*
 * Implementation details of CPORT communications.
 */

#include <linux/semaphore.h>
#include <linux/io.h>

#include "hfi2.h"
#include "chip_jkr.h"
#include "chip_cyr.h"
#include "cport.h"
#include "trace.h"

static uint cport_ping_to;

uint hfi2_cport_adm_to = 1;

static bool cport_mctxt_recovery = true;




struct cport_work;
#if (JKR_MCTXT_PF0_INT_STATUS != CYR_MCTXT_PF_INT_STATUS) ||  (JKR_MCTXT_PF0_INT_ENABLE != CYR_MCTXT_PF_INT_ENABLE) ||  (JKR_MCTXT_PF0_INT_STATUS_ENABLED != CYR_MCTXT_PF_INT_STATUS_ENABLED) ||  (JKR_MCTXT_PF0_INT_ACK != CYR_MCTXT_PF_INT_ACK)
#error "MCTXT register offset change"
#endif

static void cport_work_fn(struct work_struct *work);
static void cport_req_fn(struct work_struct *work);
static void cport_rx_timeout(struct work_struct *work);
static int cwcopy(struct cport_work *msg, const void *from, u32 offset,
		  u32 len, bool req);

bool hfi2_cport_get(struct hfi2_cport *cport)
{
	return refcount_inc_not_zero(&cport->refcount);
}

void hfi2_cport_put(struct hfi2_cport *cport)
{
	if (refcount_dec_and_test(&cport->refcount))
		complete(&cport->refcount_zero);
}

struct hfi2_cport *hfi2_cport_get_live(struct hfi2_devdata *dd)
{
	struct hfi2_cport *cport;

	mutex_lock(&dd->cport_lock);
	cport = dd->cport;
	if (cport) {
		mutex_lock(&cport->admission_lock);
		if (READ_ONCE(cport->stopping) || !hfi2_cport_get(cport)) {
			mutex_unlock(&cport->admission_lock);
			cport = NULL;
		} else {
			mutex_unlock(&cport->admission_lock);
		}
	}
	mutex_unlock(&dd->cport_lock);

	return cport;
}

enum cport_work_op {
	CPORT_WORK_SEND_REQ,
	CPORT_WORK_RECV_REQ,
	CPORT_WORK_SEND_RSP,
};

#undef CPORT_XA_DEBUG /* every tid assigned from xarray */
#undef CPORT_RCV_DEBUG /* every message (header) received, and outbox empty */
#undef CPORT_SND_DEBUG /* every message (header) sent */
#undef CPORT_INT_DEBUG /* every interrupt processed, and status in timeouts */
#define LOST_INT_DEBUG /* print if lost intr detected */

static unsigned int cport_lost_int;

/*
 * This limit needs to balance memory consuption against
 * the need to ensure tids don't repeat during periods of
 * CPORT stall and message timeout.
 *
 * Also note that the limit parameter passed to xa_alloc*()
 * gets modified, so we cannot use a static structure here.
 */
#define cport_tid_limit XA_LIMIT(0, 255)

/*
 * The "header" (first qword) of a message to/from CPORT.
 */
union cport_header {
	struct {
		u64 len : 15;
		u64 _resv1 : 1;
		u64 is_req : 1;
		u64 no_rsp : 1;
		u64 seq_no : 6;
		u64 sts : 8;
		u64 tid : 16;
		u64 sideband : 8;
		u64 op_code : 8;
	};
	u64 qw;
};

#define CPORT_SEQNO_MASK 0x3f
#define CPORT_MAX_MSG_LEN ((1U << 15) - 1)

#define CPORT_HDR_DEF 0x0000007ec0000000ul
#define CPORT_HDR_LEN 48 /* bit position of length in CPORT_HDR_DEF */
#define CPORT_HDR_SEQ 28 /* bit position of SEQ_NO */
#define CPORT_HDR_EOM 30 /* bit position of EOM */
#define CPORT_HDR_SOM 31 /* bit position of SOM */

/*
 * Assignment of bits in JKR_MCTXT_CPORT_INT_STATUS and
 * JKR_MCTXT_PF0_INT_STATUS.
 */
#define JKR_MCTXT_INT_OUTBOX_EMPTY	0b00000001
#define JKR_MCTXT_INT_INBOX_FULL	0b00000010
#define JKR_MCTXT_INT_NOTIFY		0b00001000

/*
 * The remainder is private to the host driver.
 * CPORT firmware has no need of this interface.
 */

/*
 * How the MCTXT CSRs are interpreted.
 */
union mctxt_mem {
	union cport_header hdr;
	u64 qw[JKR_C_MCTXT_MEM_SIZE_IN_QWORDS];
};

/*
 * The common structure used to implement CPORT messages in hfi2.
 */
struct cport_work {
	struct work_struct work;
	struct kref kref;
	int flags;
	int error;
	enum cport_work_op op;
	u8 n_mctxts; /* len of mctxt_mem req/rsp arrays */
	bool cancelled;
	u8 tx_mctxts_done; /* number of mctxs sent */
	u8 rx_mctxts_done; /* number of mctxs received */
	u32 bytes_received;
	long timeout;
	struct delayed_work rx_timeout_work;
	spinlock_t completion_lock;
	struct completion done;
	struct semaphore *sem; /* only valid in send, if request w/response */
	struct hfi2_cport *cport;
	struct hfi2_devdata *dd; /* only valid in recv context */
	union mctxt_mem *req;
	union mctxt_mem *rsp; /* only used for request w/response */
};

#define CW_FLAG_SEND 0x01 /* struct originated in send */
#define CW_FLAG_RECV 0x02 /* struct originated in receive */

/*
 * Suspected lost interrupt, try to recover if possible.
 */
static void lost_mctxt_intr(struct hfi2_devdata *dd)
{
	unsigned long flags;
	u64 ints;

	spin_lock_irqsave(&dd->irq_src_lock, flags);
	ints = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_STATUS_ENABLED);
	/* if bits set, assume lost interrupt and attempt recovery. */
	if (ints) {
#ifdef LOST_INT_DEBUG
		dd_dev_info(dd, "%s forcing int for %llx\n", __func__, ints);
#endif
		hfi2_force_intr(dd, JKR_MCTXT_CPORT_TO_PCIE_INT);
	}
	spin_unlock_irqrestore(&dd->irq_src_lock, flags);
}

static void cport_lost_int_chk(struct timer_list *t)
{
	struct hfi2_cport *cport = timer_container_of(cport, t, lost_int_timer);

	if (cport_lost_int) {
		lost_mctxt_intr(cport->dd);
		mod_timer(&cport->lost_int_timer, jiffies + cport_lost_int);
	}
}

/*
 * Acquire a reference to the message structure
 */
static inline void cwget(struct cport_work *cw)
{
	kref_get(&cw->kref);
}

/*
 * Locate and remove the 'id' message in the xarray and atomically
 * acquire a reference to the message structure.
 */
static inline struct cport_work *cwget_xa(struct hfi2_cport *cport, u32 id)
{
	struct cport_work *cw;
	unsigned long flags;

	xa_lock_irqsave(&cport->tid_xa, flags);
	cw = __xa_erase(&cport->tid_xa, id);
	if (cw)
		cwget(cw);
	xa_unlock_irqrestore(&cport->tid_xa, flags);
	return cw;
}

static inline int cport_alloc_tid(struct hfi2_devdata *dd, u32 *idx, struct cport_work *msg)
{
	int ret;
	unsigned long flags;

	xa_lock_irqsave(&dd->cport->tid_xa, flags);
	ret = __xa_alloc_cyclic(&dd->cport->tid_xa, idx, msg, cport_tid_limit,
				&dd->cport->tid_next, GFP_ATOMIC);
	xa_unlock_irqrestore(&dd->cport->tid_xa, flags);
	return ret;
}

static void cwrelease(struct kref *kref)
{
	struct cport_work *cw = container_of(kref, struct cport_work, kref);

	if (cw->cport)
		hfi2_cport_put(cw->cport);
	kfree(cw->req);
	kfree(cw->rsp);

	kfree(cw);
}

static void cwput(struct cport_work *cw)
{
	kref_put(&cw->kref, cwrelease);
}

static void cport_work_signal(struct cport_work *msg, int error)
{
	unsigned long flags;

	if (msg->flags & CW_FLAG_SEND && msg->sem) {
		spin_lock_irqsave(&msg->completion_lock, flags);
		msg->error = error;
		spin_unlock_irqrestore(&msg->completion_lock, flags);
		up(msg->sem);
		complete_all(&msg->done);
	}
}

static void cport_work_complete(struct cport_work *msg, int error)
{
	cport_work_signal(msg, error);
	cwput(msg);
}

static bool cport_tid_erase(struct hfi2_cport *cport,
			    struct cport_work *msg)
{
	return xa_cmpxchg(&cport->tid_xa, msg->req->hdr.tid, msg, NULL,
			  GFP_ATOMIC) == msg;
}

static bool cport_stopping(struct hfi2_cport *cport)
{
	return READ_ONCE(cport->stopping);
}

static void cport_abort_requests(struct hfi2_cport *cport, int error)
{
	struct cport_work *msg;
	unsigned long index;

	for (index = 0; ; index++) {
		xa_lock_irq(&cport->tid_xa);
		msg = xa_find(&cport->tid_xa, &index, U32_MAX, XA_PRESENT);
		if (msg) {
			__xa_erase(&cport->tid_xa, index);
			cwget(msg);
		}
		xa_unlock_irq(&cport->tid_xa);
		if (!msg)
			break;
		cport_work_complete(msg, error);
	}
}

static struct cport_work *cport_detach_incomplete_rx(
	struct hfi2_cport *cport)
{
	struct cport_work *msg;

	mutex_lock(&cport->rx_lock);
	msg = cport->incomplete_mctxt_msg_rx;
	cport->incomplete_mctxt_msg_rx = NULL;
	mutex_unlock(&cport->rx_lock);

	return msg;
}

static void cport_abort_incomplete_rx(struct hfi2_cport *cport, int error)
{
	struct cport_work *msg;

	msg = cport_detach_incomplete_rx(cport);
	if (msg) {
		cancel_delayed_work_sync(&msg->rx_timeout_work);
		cport_work_complete(msg, error);
	}
}

static void cport_rx_timeout(struct work_struct *work)
{
	struct cport_work *msg =
		container_of(work, struct cport_work, rx_timeout_work.work);
	struct hfi2_cport *cport = msg->cport;

	mutex_lock(&cport->rx_lock);
	if (cport->incomplete_mctxt_msg_rx == msg)
		cport->incomplete_mctxt_msg_rx = NULL;
	else
		msg = NULL;
	mutex_unlock(&cport->rx_lock);
	if (msg)
		cport_work_complete(msg, -ETIMEDOUT);
}

static void cport_cancel_owned(struct cport_work *msg)
{
	struct hfi2_cport *cport = msg->cport;
	unsigned long flags;

	spin_lock_irqsave(&cport->tx_lock, flags);
	WRITE_ONCE(msg->cancelled, true);
	if (cport->incomplete_mctxt_msg_tx == msg)
		cport->incomplete_mctxt_msg_tx = NULL;
	spin_unlock_irqrestore(&cport->tx_lock, flags);

	if (cancel_work(&msg->work))
		cwput(msg);
	cwput(msg);
}

static struct cport_work *cwalloc(int flag)
{
	struct cport_work *cw = kzalloc(sizeof(*cw), GFP_ATOMIC);

	if (!cw)
		return NULL;

	cw->flags = flag;
	cw->op = CPORT_WORK_SEND_REQ;
	cw->n_mctxts = 1;
	spin_lock_init(&cw->completion_lock);
	init_completion(&cw->done);
	INIT_DELAYED_WORK(&cw->rx_timeout_work, cport_rx_timeout);
	INIT_WORK(&cw->work, cport_work_fn);
	cw->req = kzalloc(sizeof(*cw->req), GFP_ATOMIC);
	if (!cw->req) {
		kfree(cw);
		return NULL;
	}

	cw->rsp = kzalloc(sizeof(*cw->rsp), GFP_ATOMIC);
	if (!cw->rsp) {
		kfree(cw->req);
		kfree(cw);
		return NULL;
	}

	kref_init(&cw->kref);
	return cw;
}

/* set "external" (non-alloc) response payload */
static int pld_rsp_set(struct cport_work *cw, const void *pld, int len)
{
	int ret;

	if (len < 0 || len > CPORT_MAX_MSG_LEN - sizeof(cw->rsp->hdr))
		return -EMSGSIZE;
	ret = cwcopy(cw, pld, sizeof(cw->rsp->hdr), len, false);
	if (ret)
		return ret;
	cw->rsp->hdr.len = len + sizeof(cw->rsp->hdr);
	return 0;
}

static int cw_pad_size(struct cport_work *msg, u32 size)
{
	union mctxt_mem *new_reqs, *new_rsps;
	u32 new_ctxts;

	/* already large enough */
	if (size <= msg->n_mctxts * (sizeof(*new_reqs)))
		return 0;

	/* round up to next mctxt buffer len */
	new_ctxts = (size + (sizeof(*new_reqs) - 1)) / sizeof(*new_reqs);
	if (new_ctxts > U8_MAX)
		return -EINVAL;
	/*
	 * Zero the newly grown portion: msg->req/msg->rsp are copied to
	 * hardware and to userspace (via response payloads), so any
	 * uninitialized heap bytes in the padding must not be exposed.
	 */
	new_reqs = krealloc(msg->req, new_ctxts * sizeof(*new_reqs),
			    GFP_KERNEL | __GFP_ZERO);
	if (!new_reqs)
		return -ENOMEM;
	msg->req = new_reqs;

	new_rsps = krealloc(msg->rsp, new_ctxts * sizeof(*new_reqs),
			    GFP_KERNEL | __GFP_ZERO);
	if (!new_rsps)
		return -ENOMEM;

	msg->rsp = new_rsps;
	msg->n_mctxts = new_ctxts;

	return 0;
}

static int cwcopy(struct cport_work *msg, const void *from, u32 offset,
		  u32 len, bool req)
{
	union mctxt_mem *mc;
	int ret;

	ret = cw_pad_size(msg, offset + len);
	if (ret)
		return ret;

	mc = req ? msg->req : msg->rsp;
	memcpy(((u8 *)mc) + offset, from, len);

	return 0;
}

/*
 * Send request, non-blocking, with timeout for OUTBOX_EMPTY wait.
 * Caller must watch returned cport_work->sem for completion, and
 * then call hfi2_cport_send_comp() or hfi2_cport_send_cancel() to finalize everything.
 * Returns handle for hfi2_cport_send_comp()/_cancel(), or ERR_PTR().
 *
 * See hfi2_cport_send_req() for example usage.
 */
void *hfi2_cport_send_req_nb(struct hfi2_devdata *dd, u8 op, u8 sideband,
			     void *payload, int len, struct semaphore *wait,
			     long timeout)
{
	struct hfi2_cport *cport;
	int ret;
	struct cport_work *msg;
	u32 idx;

	if (unlikely(!(dd->flags & HFI2_PRESENT)))
		return ERR_PTR(-ENODEV);

	cport = hfi2_cport_get_live(dd);
	if (!cport)
		return ERR_PTR(-ESHUTDOWN);
	mutex_lock(&cport->admission_lock);
	if (cport_stopping(cport)) {
		mutex_unlock(&cport->admission_lock);
		hfi2_cport_put(cport);
		return ERR_PTR(-ESHUTDOWN);
	}

	msg = cwalloc(CW_FLAG_SEND);
	if (!msg) {
		ret = -ENOMEM;
		goto unlock;
	}
	hfi2_cport_get(cport);
	msg->cport = cport;
	msg->dd = dd;
	msg->timeout = timeout;
	if (len < 0 || len > CPORT_MAX_MSG_LEN -
	    sizeof(union cport_header)) {
		ret = -EMSGSIZE;
		goto put;
	}
	ret = cwcopy(msg, payload, sizeof(union cport_header), len, true);
	if (ret)
		goto put;
	ret = xa_alloc_cyclic(&cport->tid_xa, &idx, msg, cport_tid_limit,
			      &cport->tid_next, GFP_KERNEL);
	if (ret < 0)
		goto put;
#ifdef CPORT_XA_DEBUG
	dd_dev_info(dd, "CPORT tid is %04x\n", idx);
#endif
	msg->req->hdr.op_code = op;
	msg->req->hdr.sideband = sideband;
	msg->req->hdr.is_req = 1;
	msg->req->hdr.no_rsp = 0;
	msg->req->hdr.tid = idx;
	msg->req->hdr.len = len + sizeof(msg->req->hdr);
	msg->sem = wait;
	cwget(msg); /* extra ref so not freed after send */
	queue_work(dd->hfi2_wq, &msg->work);
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return msg;

put:
	cwput(msg);
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return ERR_PTR(ret);

unlock:
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return ERR_PTR(ret);
}

/*
 * Extract results from response and drop (last) reference to structure.
 * Returns status from response header.
 * Must never be called twice for the same message (message has been freed).
 * Must never be called on a message that has not received response (up'ed wait).
 */
int hfi2_cport_send_comp(struct hfi2_devdata *dd, void *handle, void **rsp_pld,
			 int *rsp_len)
{
	struct cport_work *msg = handle;
	void *ptr;
	int ret;
	int len;

	if (rsp_pld)
		*rsp_pld = NULL;
	*rsp_len = 0;
	ret = READ_ONCE(msg->error);
	if (ret)
		goto done;
	if (msg->rsp->hdr.len < sizeof(msg->rsp->hdr)) {
		ret = -EPROTO;
		goto done;
	}

	len = msg->rsp->hdr.len - sizeof(msg->rsp->hdr);
	if (rsp_pld) {
		ptr = kzalloc(len, GFP_KERNEL);
		if (!ptr) {
			ret = -ENOMEM;
			goto done;
		}
		memcpy(ptr, &msg->rsp[0].qw[1], len);
		*rsp_pld = ptr;
	}
	*rsp_len = len;
	ret = msg->rsp->hdr.sts;

done:
	cwput(msg);
	return ret;
}

/*
 * Cleanup aborted wait for response.
 * Only called for requests w/responses.
 * Must never be called twice for the same message (message has been freed).
 */
void hfi2_cport_send_cancel(struct hfi2_devdata *dd, void *handle)
{
	struct cport_work *msg = handle;

	if (cport_tid_erase(msg->cport, msg)) {
		cport_cancel_owned(msg);
	} else {
		wait_for_completion(&msg->done);
		cwput(msg);
	}
}

/*
 * Send request and wait for response, with timeout.
 * Caller must be able to sleep.
 * Returns status from response header, and response payload data, on success.
 * Response payload was from k[z]alloc() and caller must kfree().
 * On error, returns -errno (response status is always 0-15).
 */
int hfi2_cport_send_req(struct hfi2_devdata *dd, u8 op, u8 sideband,
			void *payload, int len, void **rsp_pld, int *rsp_len,
			long timeout)
{
	int ret;
	struct cport_work *msg;
	struct semaphore comp;

	sema_init(&comp, 0);

	might_sleep();

	msg = hfi2_cport_send_req_nb(dd, op, sideband, payload, len, &comp,
				     timeout);
	if (IS_ERR(msg))
		return PTR_ERR(msg);
	if (timeout > 0 && timeout != MAX_SCHEDULE_TIMEOUT)
		ret = down_timeout(&comp, timeout);
	else
		ret = down_killable(&comp);
	if (ret) {
		/*
		 * The wait was interrupted or timed out. Try to remove
		 * 'msg' from the tid xarray ourselves. If we succeed, no
		 * other context can be holding (or about to acquire) a
		 * reference to our stack-allocated 'comp' semaphore, so it
		 * is safe to cancel below via hfi2_cport_send_cancel().
		 *
		 * If we fail to remove it, a response is already being
		 * processed concurrently by cport_mctxt_fn(), which will
		 * signal msg->sem after recording either its status or an
		 * error. Consume that signal before returning so the receive
		 * path cannot access the stack semaphore after this function
		 * returns.
		 */
		if (!cport_tid_erase(msg->cport, msg)) {
			wait_for_completion(&msg->done);
			return hfi2_cport_send_comp(dd, msg, rsp_pld, rsp_len);
		}
#ifdef CPORT_INT_DEBUG
		u64 ints;

		ints = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
		dd_dev_err(
			dd,
			"CPORT request wait interrupted %016llx (%d) [%02llx]\n",
			msg->req->hdr.qw, ret, ints);
#else
		dd_dev_err(dd, "CPORT request wait interrupted %016llx (%d)\n",
			   msg->req->hdr.qw, ret);
#endif
		cport_cancel_owned(msg);
		lost_mctxt_intr(dd); /* attempt recovery */
		return ret;
	}
	return hfi2_cport_send_comp(dd, msg, rsp_pld, rsp_len);
}

int hfi2_cport_send_notif(struct hfi2_devdata *dd, u8 op, u8 sideband,
			  void *payload, int len, long timeout)
{
	struct hfi2_cport *cport;
	struct cport_work *msg;
	int ret;

	if (unlikely(!(dd->flags & HFI2_PRESENT)))
		return -ENODEV;

	cport = hfi2_cport_get_live(dd);
	if (!cport)
		return -ESHUTDOWN;
	mutex_lock(&cport->admission_lock);
	if (cport_stopping(cport)) {
		mutex_unlock(&cport->admission_lock);
		hfi2_cport_put(cport);
		return -ESHUTDOWN;
	}

	msg = cwalloc(CW_FLAG_SEND);
	if (!msg) {
		ret = -ENOMEM;
		goto unlock;
	}
	hfi2_cport_get(cport);
	msg->cport = cport;
	msg->dd = dd;
	msg->timeout = timeout;
	if (len < 0 || len > CPORT_MAX_MSG_LEN -
	    sizeof(union cport_header)) {
		ret = -EMSGSIZE;
		goto put;
	}
	ret = cwcopy(msg, payload, sizeof(union cport_header), len, true);
	if (ret)
		goto put;
	msg->req->hdr.len = len + sizeof(msg->req->hdr);
	msg->req->hdr.op_code = op;
	msg->req->hdr.sideband = sideband;
	msg->req->hdr.is_req = 1;
	msg->req->hdr.no_rsp = 1;
	queue_work(dd->hfi2_wq, &msg->work);
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return 0;

put:
	cwput(msg);
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return ret;
unlock:
	mutex_unlock(&cport->admission_lock);
	hfi2_cport_put(cport);
	return ret;
}

/*
 ********************************************************************
 * Internal routines.
 */

/*
 * Send a response to CPORT's request.
 *
 * Re-uses message structure from request. Queues to send workqueue.
 */
static int cport_send_rsp(struct cport_work *msg, int sts)
{
	struct hfi2_devdata *dd = msg->dd;

	/* rsp.hdr.len and rsp.qw[1..] already setup, also rsp.op_code/rsp.tid */
	msg->rsp->hdr.is_req = 0;
	msg->rsp->hdr.sts = sts;
	msg->op = CPORT_WORK_SEND_RSP;
	queue_work(dd->hfi2_wq, &msg->work);
	return 0;
}

static void cport_send(struct cport_work *msg, bool req)
{
	union mctxt_mem *mc = req ? msg->req : msg->rsp;
	struct hfi2_devdata *dd = msg->dd;
	struct hfi2_cport *cport = msg->cport;
	u32 csr_i, tot_len, len_sent;
	u64 cport_hdr;
	u8 seq_no;
	u64 *ptr;
	int ret, mcxt_len;

	/*
	 * Sleep until OutboxEmpty. This runs in a workqueue context, where
	 * (unlike a user process) non-fatal signals are blocked and cannot
	 * wake a killable sleep, so down_killable() here would behave
	 * exactly like down() anyway; use down_timeout() with an
	 * administrative timeout instead of an unbounded down(), since an
	 * unbounded wait here can never be interrupted and would otherwise
	 * hang hfi2_cport_exit()'s flush_workqueue() forever if the outbox
	 * semaphore is never signaled (e.g. CPORT stopped responding).
	 * cport-originated response sends leave msg->timeout at its default
	 * of 0, so fall back to hfi2_cport_adm_to for those.
	 */
	if (cport_stopping(cport)) {
		ret = -ESHUTDOWN;
	} else if (msg->timeout == MAX_SCHEDULE_TIMEOUT) {
		do {
			ret = down_timeout(&cport->outbox, hfi2_cport_adm_to * HZ);
		} while (ret == -ETIME && !cport_stopping(cport));
		if (cport_stopping(cport))
			ret = -ESHUTDOWN;
	} else {
		long timeout = msg->timeout > 0 ?
				       msg->timeout : hfi2_cport_adm_to * HZ;

		ret = down_timeout(&cport->outbox, timeout);
		if (!ret && cport_stopping(cport))
			ret = -ESHUTDOWN;
	}
	if (ret)
		goto send_error;

	/* sequential under lock, check if there are unfinished messages */
	spin_lock_irq(&cport->tx_lock);
	if (cport->incomplete_mctxt_msg_tx &&
	    cport->incomplete_mctxt_msg_tx != msg) {
		spin_unlock_irq(&cport->tx_lock);
		/* give up empty outbox, the incomplete msg must finish next */
		up(&cport->outbox);
		/* reschedule this work until next time */
		queue_work(dd->hfi2_wq, &msg->work);
		return;
	}
	if (msg->cancelled) {
		spin_unlock_irq(&cport->tx_lock);
		up(&cport->outbox);
		ret = -ECANCELED;
		goto send_error;
	}
	tot_len = mc->hdr.len;
	len_sent = msg->tx_mctxts_done * sizeof(union mctxt_mem);
	if (tot_len < sizeof(mc->hdr) ||
	    tot_len > msg->n_mctxts * sizeof(union mctxt_mem) ||
	    msg->tx_mctxts_done >= DIV_ROUND_UP(tot_len, sizeof(union mctxt_mem)) ||
	    len_sent >= tot_len) {
		spin_unlock_irq(&cport->tx_lock);
		up(&cport->outbox);
		ret = -EPROTO;
		goto send_error;
	}
	if (msg->tx_mctxts_done + 1 < DIV_ROUND_UP(tot_len, sizeof(union mctxt_mem)))
		cport->incomplete_mctxt_msg_tx = msg;
	else if (cport->incomplete_mctxt_msg_tx == msg)
		cport->incomplete_mctxt_msg_tx = NULL;
	spin_unlock_irq(&cport->tx_lock);

#ifdef CPORT_SND_DEBUG
	dd_dev_info(dd, "MCTXT sent %016llx\n", mc->hdr.qw);
#endif
	ptr = &mc[msg->tx_mctxts_done].qw[0];
	seq_no = msg->tx_mctxts_done;
	mcxt_len =
		min_t(int, (int)(tot_len - len_sent), sizeof(union mctxt_mem));
	/* NOTE: "CPORT IN" is our output */
	csr_i = JKR_MCTXT_CPORT_IN;
	cport_hdr = CPORT_HDR_DEF;
	cport_hdr |= ((u64)mcxt_len << CPORT_HDR_LEN);

	cport_hdr |= (((u64)seq_no & 0x3) << CPORT_HDR_SEQ);

	/* CPORT_HDR_DEF sets SOM/EOM, clear if not */
	if (msg->tx_mctxts_done)
		cport_hdr &= ~((u64)1 << CPORT_HDR_SOM);
	else
		mc->hdr.seq_no = atomic_fetch_inc(&cport->seqno);

	if (msg->tx_mctxts_done + 1 <
	    DIV_ROUND_UP(tot_len, sizeof(union mctxt_mem)))
		cport_hdr &= ~((u64)1 << CPORT_HDR_EOM);

	hfi2_write_csr(dd, dd->cport->cport_in_scratch, cport_hdr);
	while (mcxt_len > 0) {
		hfi2_write_csr(dd, csr_i, *ptr++);
		csr_i += sizeof(u64);
		mcxt_len -= sizeof(u64);
	}
	hfi2_write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS,
		       JKR_MCTXT_INT_INBOX_FULL);

	if (++msg->tx_mctxts_done < DIV_ROUND_UP(tot_len, sizeof(union mctxt_mem))) {
		queue_work(dd->hfi2_wq, &msg->work);
		return;
	}
	cwput(msg);
	return;

send_error:
	spin_lock_irq(&cport->tx_lock);
	if (cport->incomplete_mctxt_msg_tx == msg)
		cport->incomplete_mctxt_msg_tx = NULL;
	spin_unlock_irq(&cport->tx_lock);
	if (req && !msg->req->hdr.no_rsp && cport_tid_erase(cport, msg))
		cport_work_signal(msg, ret);
	cwput(msg);
}

/*
 * Low-level send to CPORT via MCTXT.
 *
 * Interfaces with MCTXT.
 */
static void cport_work_fn(struct work_struct *work)
{
	struct cport_work *msg = container_of(work, struct cport_work, work);

	switch (msg->op) {
	case CPORT_WORK_SEND_REQ:
		cport_send(msg, true);
		break;
	case CPORT_WORK_RECV_REQ:
		cport_req_fn(work);
		break;
	case CPORT_WORK_SEND_RSP:
		cport_send(msg, false);
		break;
	}
}

static int echo_req(struct hfi2_devdata *dd, u8 op, u8 sideband, void *pld,
		    int pll, void *handle)
{
	struct cport_work *msg = handle;

	dd_dev_info(msg->dd, "cport ping %02x (%d)\n", sideband, pll);
	/* Leave payload in-tact (echo). */
	if (pld_rsp_set(msg, pld, pll))
		return MSG_RSP_STATUS_INVALID_STATE;
	return MSG_RSP_STATUS_OK;
}

static int inval_req(struct hfi2_devdata *dd, u8 op, u8 sideband, void *pld,
		     int pll, void *handle)
{
	return MSG_RSP_STATUS_OPCODE_UNSUPPORTED;
}

/*
 * Process a request from CPORT.
 *
 * May be dispatched to external function from handlers[].
 */
static void cport_req_fn(struct work_struct *work)
{
	struct cport_work *msg = container_of(work, struct cport_work, work);
	cport_handler func;
	int ret = MSG_RSP_STATUS_OK;
	void *pld;
	int pll;

	/*
	 * Guard against the race where hfi2_cport_exit() freed dd->cport and set
	 * it to NULL after cport_mctxt_fn() queued this work item but before
	 * this function had a chance to run.  This can occur when the hardware
	 * is in a wedged state (i.e. PCIe DPC isolation) and the teardown
	 * sequence does not fully quiesce the interrupt handler before the
	 * final flush_workqueue().  In that case, silently discard the work.
	 */
	if (!msg->dd->cport) {
		cwput(msg);
		return;
	}

	pll = msg->req->hdr.len - sizeof(msg->req->hdr);
	pld = &msg->req->qw[1];
	msg->rsp->hdr.qw = msg->req->hdr.qw;
	/* default to no payload in response (if any) */
	msg->rsp->hdr.len = sizeof(msg->req->hdr);
	func = READ_ONCE(msg->cport->handlers[msg->req->hdr.op_code]);
	if (func)
		ret = func(msg->dd, msg->req->hdr.op_code,
			   msg->req->hdr.sideband, pld, pll, msg);
	else
		ret = inval_req(msg->dd, msg->req->hdr.op_code,
				msg->req->hdr.sideband, pld, pll, msg);
	if (msg->req->hdr.no_rsp) {
		if (ret)
			dd_dev_err_ratelimited(msg->dd,
					       "Op %d %02x failed (%d)\n",
					       msg->req->hdr.op_code,
					       msg->req->hdr.sideband, ret);
		cwput(msg);
		return;
	}

	/* msg->rsp->qw[*] and msg->rsp->hdr.len have been updated */
	ret = cport_send_rsp(msg, ret);
	if (ret)
		dd_dev_err(msg->dd, "Response send failed (%d)\n", ret);
}

/*
 * Handler for MCTXT Inbox Full interrupt.
 *
 * Only one can be queued/run until JKR_MCTXT_INT_OUTBOX_EMPTY is cleared.
 * Run in a workqueue (not interrupt context).
 */
static void cport_mctxt_fn(struct work_struct *work)
{
	struct hfi2_cport *cport =
		container_of(work, struct hfi2_cport, mctxt_work);
	struct hfi2_devdata *dd = cport->dd;
	int ret = 0;
	u8 is_start, is_end;
	bool first_fragment = false;
	bool rx_locked = false;
	int len;
	u64 *ptr;
	u64 mhdr;
	u32 expected, fragment_len, i;
	struct cport_work *msg;
	union cport_header hdr = { };

	/*
	 * CPORT output MCTXT is our input.
	 */
	i = JKR_MCTXT_CPORT_OUT;

	mhdr = hfi2_read_csr(dd, cport->cport_out_scratch);
	len = (mhdr >> CPORT_HDR_LEN) & 0xfff;
	is_start = (mhdr >> CPORT_HDR_SOM) & 1;
	is_end = (mhdr >> CPORT_HDR_EOM) & 1;
	if (len > sizeof(union mctxt_mem)) {
		ret = -EMSGSIZE;
		goto fail;
	}
	if (is_start && len < sizeof(hdr)) {
		ret = -EPROTO;
		goto fail;
	}
	if (is_start) {
		msg = cport_detach_incomplete_rx(cport);
		if (msg) {
			dd_dev_warn(dd, "cport dropped incomplete message on new start\n");
			cancel_delayed_work_sync(&msg->rx_timeout_work);
			cport_work_complete(msg, -EPROTO);
		}
		hdr.qw = hfi2_read_csr(dd, i);
	} else {
		mutex_lock(&cport->rx_lock);
		msg = cport->incomplete_mctxt_msg_rx;
		if (!msg) {
			mutex_unlock(&cport->rx_lock);
			goto fail;
		}
		rx_locked = true;
		/*
		 * Bound mctxts_done against the allocated req/rsp array
		 * size before using it as an index below. CPORT is
		 * expected to send exactly msg->n_mctxts continuation
		 * packets, but a misbehaving/faulty peer sending more
		 * would otherwise write past the end of the array.
		 */
		if (msg->rx_mctxts_done >= msg->n_mctxts) {
			dd_dev_warn(
				dd,
				"cport sent too many continuation packets\n");
			cport->incomplete_mctxt_msg_rx = NULL;
			mutex_unlock(&cport->rx_lock);
			rx_locked = false;
			cancel_delayed_work_sync(&msg->rx_timeout_work);
			cport_work_complete(msg, -EPROTO);
			ret = -EDOM;
			goto fail;
		}
		hfi2_cdbg(DC8051, "rx tid 0x%04x, seq_no %d (start)", hdr.tid, hdr.seq_no);
		if (msg->flags & CW_FLAG_RECV) {
			ptr = &msg->req[msg->rx_mctxts_done++].qw[0];
			hdr.qw = msg->req->hdr.qw;
			hfi2_cdbg(DC8051, "rx tid 0x%04x, seq_no %d (RECV)", hdr.tid, hdr.seq_no);
		} else {
			ptr = &msg->rsp[msg->rx_mctxts_done++].qw[0];
			hdr.qw = msg->rsp->hdr.qw;
			hfi2_cdbg(DC8051, "rx tid 0x%04x, seq_no %d (!RECV)", hdr.tid, hdr.seq_no);
		}
		dd_dev_info(dd, "%s: got continuation of %u\n", __func__,
			    hdr.seq_no);
		/* skip all the start-message parsing/allocation */
		goto copy;
	}
#ifdef CPORT_RCV_DEBUG
	dd_dev_info(dd, "cport_mctxt_fn() %016llx\n", hdr.qw);
#endif
	if (hdr.len < sizeof(hdr)) {
		/* assume message is invalid  - cannot be processed */
		ret = -EDOM;
		goto fail;
	}
	if (hdr.len > CPORT_MAX_MSG_LEN) {
		ret = -EMSGSIZE;
		goto fail;
	}
	i += sizeof(u64);
	/* No need for atomics here, we are single threaded */
	if (hdr.seq_no != cport->rseqno) {
		dd_dev_info(dd, "Recv out of sequence: %d -> %d\n",
			    cport->rseqno, hdr.seq_no);
		cport->rseqno = hdr.seq_no;
	}
	cport->rseqno = (cport->rseqno + 1) & CPORT_SEQNO_MASK;
	if (hdr.is_req) {
		/* Request from CPORT, has no existing message context */
		msg = cwalloc(CW_FLAG_RECV);
		if (!msg) {
			ret = -ENOMEM;
			goto fail; /* drop message, with error */
		}
		ret = cw_pad_size(msg, hdr.len);
		if (ret) {
			cwput(msg); /* drop the newly allocated msg */
			goto fail;
		}
		if (!hfi2_cport_get(cport)) {
			cwput(msg);
			ret = -ESHUTDOWN;
			goto fail;
		}
		msg->cport = cport;
		msg->dd = dd;
		msg->bytes_received = 0;
		ptr = &msg->req->qw[msg->rx_mctxts_done++];
		first_fragment = true;
	} else {
		/*
		 * Responses already have a 'msg', extra ref was already taken.
		 * Take an additional ref against possible race with timeout
		 * (hfi2_cport_send_cancel()) between here and the up().
		 */
		msg = cwget_xa(cport, hdr.tid);
		if (!msg) {
			ret = -ESRCH;
			goto fail; /* drop message, with error */
		}
		ret = cw_pad_size(msg, hdr.len);
		if (ret) {
			cport_work_complete(msg, ret);
			goto fail;
		}
		msg->bytes_received = 0;
		ptr = &msg->rsp->qw[msg->rx_mctxts_done++];
		first_fragment = true;
		/* assert msg->req->hdr ~= hdr */
	}
	*ptr++ = hdr.qw;
	if (first_fragment) {
		len -= sizeof(hdr);
		msg->bytes_received = sizeof(hdr);
	}
copy:
	expected = min_t(u32, hdr.len - msg->bytes_received,
			 sizeof(union mctxt_mem) -
			 (first_fragment ? sizeof(hdr) : 0));
	fragment_len = len;
	if (fragment_len != expected) {
		if (!first_fragment && rx_locked) {
			cport->incomplete_mctxt_msg_rx = NULL;
			mutex_unlock(&cport->rx_lock);
			rx_locked = false;
		}
		cancel_delayed_work_sync(&msg->rx_timeout_work);
		cport_work_complete(msg, -EPROTO);
		ret = -EPROTO;
		goto fail;
	}
	/* now copy payload into chosen buffer */
	while (fragment_len > 0) {
		*ptr++ = hfi2_read_csr(dd, i);
		i += sizeof(u64);
		fragment_len = fragment_len > sizeof(u64) ?
			fragment_len - sizeof(u64) : 0;
	}
	msg->bytes_received += len;
	/*
	 * We are finished with the dd->cport->mctxt_work struct,
	 * and the MCTXT, so it can all be re-used now.
	 */
	hfi2_cdbg(DC8051, "set CPORT OUTBOX_EMPTY (normal)");
	hfi2_write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS, JKR_MCTXT_INT_OUTBOX_EMPTY);
#ifdef CPORT_RCV_DEBUG
	dd_dev_info(dd, "cport_mctxt_fn() set CPORT OUTBOX_EMPTY\n");
#endif
	/*
	 * if we do not contain the end of the message then we need to wait
	 * until next mailbox
	 */
	if (!is_end) {
		if (msg->bytes_received >= hdr.len) {
			if (rx_locked) {
				cport->incomplete_mctxt_msg_rx = NULL;
				mutex_unlock(&cport->rx_lock);
				rx_locked = false;
			}
			cancel_delayed_work_sync(&msg->rx_timeout_work);
			cport_work_complete(msg, -EPROTO);
			ret = -EDOM;
			goto fail;
		}
		if (rx_locked) {
			mutex_unlock(&cport->rx_lock);
			rx_locked = false;
		} else {
			mutex_lock(&cport->rx_lock);
			cport->incomplete_mctxt_msg_rx = msg;
			if (!queue_delayed_work(dd->hfi2_wq,
						&msg->rx_timeout_work,
						hfi2_cport_adm_to * HZ)) {
				cport->incomplete_mctxt_msg_rx = NULL;
				mutex_unlock(&cport->rx_lock);
				cport_work_complete(msg, -EIO);
				ret = -EIO;
				goto fail;
			}
			mutex_unlock(&cport->rx_lock);
		}
		dd_dev_info(dd, "%s: expecting continuation of %u\n", __func__,
			    hdr.seq_no);
		return;
	}
	if (rx_locked) {
		cport->incomplete_mctxt_msg_rx = NULL;
		mutex_unlock(&cport->rx_lock);
		rx_locked = false;
	}
	if (msg->bytes_received != hdr.len) {
		cancel_delayed_work_sync(&msg->rx_timeout_work);
		cport_work_complete(msg, -EPROTO);
		ret = -EDOM;
		goto fail;
	}
	cancel_delayed_work_sync(&msg->rx_timeout_work);

	/* responses don't require any more work here - just wakeup requester */
	if (!hdr.is_req) {
		cport_work_complete(msg, 0);
		return;
	}
	/* reset mctxts for response parsing */
	msg->tx_mctxts_done = 0;
	msg->op = CPORT_WORK_RECV_REQ;

	/* don't care about locality */
	queue_work(dd->hfi2_wq, &msg->work);
	return;
fail:
	if (rx_locked)
		mutex_unlock(&cport->rx_lock);
	hfi2_write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS,
		       JKR_MCTXT_INT_OUTBOX_EMPTY);
	dd_dev_err(dd, "Dropping incoming CPORT message %016llx (%d)\n", hdr.qw,
		   ret);
	hfi2_cdbg(DC8051, "set CPORT OUTBOX_EMPTY (error)");
}

/*
 * Handler for PF0 MCTXT interrupts.
 *
 * Called when one of the enabled MCTXT_PF0 conditions occurs.
 * 'source' is always 0. Called in interrupt context.
 *
 * Since this interrupt is exclusive to MCTXT, there is no doubt
 * about which transport to use (always is MCTXT).
 */
void hfi2_is_cport_int(struct hfi2_devdata *dd, unsigned int source)
{
	u64 ints;
	const int limit = 100; /* arbitrary */
	int count;
	u32 idx = dd->params->is_cport_int / 64;
	u32 bit = dd->params->is_cport_int % 64;
	bool cleared;

	if (!dd->cport || !(dd->flags & HFI2_PRESENT))
		return;

	/*
	 * MctxtCportToPcieInt is a "one shot" merged interrupt.  To ensure
	 * nothing is missed, ensure that its source, MctxtPf0IntStatusEnabled,
	 * is cleared and reads as zero.
	 *
	 * The hardware implementation requires no source be set while
	 * CceIntStatus is set.  Enforce this by re-clearing CceIntStatus until
	 * the source reads zero.
	 */
	ints = 0;
	cleared = false;
	for (count = 0; count < limit; count++) {
		u64 temp;

		temp = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_STATUS_ENABLED);
		if (temp == 0) {
			if (cleared)
				break;
		} else {
			ints |= temp;
			hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_ACK, temp);
		}
		cleared = true;
		hfi2_write_csr(dd, dd->params->cce_int_clear_reg + (8 * idx),
			  1ull << bit);
	}
	if (count == limit)
		dd_dev_warn(dd, "MCTXT interrupt too many loops\n");
	if (!ints) {
		atomic_inc(&dd->cport->intr_nops);
		return;
	}

#ifdef CPORT_INT_DEBUG
	dd_dev_info(dd, "hfi2_is_cport_int() %02llx\n", ints);
#endif
	if (ints & JKR_MCTXT_INT_INBOX_FULL) {
		hfi2_cdbg(DC8051, "calling cport_mctxt_fn()");
		queue_work(dd->hfi2_wq, &dd->cport->mctxt_work);
	}
	if (ints & JKR_MCTXT_INT_NOTIFY) {
		int pending = work_pending(&dd->cport->mctxt_work);

		dd_dev_info(dd, "%s OUTBOX_EMPTY wait notification (pending %d)\n",
			    __func__, pending);
		/* only do something if work is not pending */
		if (!pending) {
			/* set hfi2_cport outbox empty again */
			hfi2_write_csr(dd, JKR_MCTXT_CPORT_INT_STATUS, JKR_MCTXT_INT_OUTBOX_EMPTY);
		}
	}
	if (ints & JKR_MCTXT_INT_OUTBOX_EMPTY)
		up(&dd->cport->outbox);
}

/* direct MSI-X interrupt */
irqreturn_t cport_interrupt(int irq, void *data)
{
	struct hfi2_devdata *dd = data;

	/* the called function will clear down the interrupt and source */
	hfi2_is_cport_int(dd, 0);

	return IRQ_HANDLED;
}

/***************************************************
 * API for handling notifications from CPORT
 */

int hfi2_cport_resp_set(void *handle, const void *payload, int len)
{
	struct cport_work *msg = handle;
	int ret;

	if (!msg || !payload || len <= 0)
		return -EINVAL;
	if (len > CPORT_MAX_MSG_LEN - sizeof(msg->rsp->hdr) ||
	    len > msg->n_mctxts * sizeof(*msg->rsp) - sizeof(msg->rsp->hdr))
		return -EINVAL;
	ret = cwcopy(msg, payload, sizeof(msg->rsp->hdr), len, false);
	if (ret)
		return ret;
	msg->rsp->hdr.len = len + sizeof(msg->rsp->hdr);
	return 0;
}

int hfi2_cport_register_cb(struct hfi2_devdata *dd, u8 op_start, u8 op_end,
			   cport_handler func)
{
	struct hfi2_cport *cport;
	int x;

	if (op_start > op_end)
		return -ERANGE;
	cport = hfi2_cport_get_live(dd);
	if (!cport)
		return func ? -EINVAL : 0;

	for (x = op_start; x <= op_end; ++x)
		WRITE_ONCE(cport->handlers[x], func);
	hfi2_cport_put(cport);
	return 0;
}

static void cport_ping_stop(struct hfi2_cport *cport)
{
	struct task_struct *th;
	bool put = false;

	mutex_lock(&cport->ping_lock);
	th = cport->ping_th;
	if (th) {
		get_task_struct(th);
		cport->ping_th = NULL;
		if (cport->ping_ref) {
			cport->ping_ref = false;
			put = true;
		}
	}
	atomic_set(&cport->nping, 0);
	mutex_unlock(&cport->ping_lock);

	if (th) {
		kthread_stop(th);
		put_task_struct(th);
	}
	if (put)
		hfi2_cport_put(cport);
}

static int cport_ping(void *data)
{
	struct hfi2_cport *cport = data;
	struct hfi2_devdata *dd = cport->dd;
	char buf[16];
	int len;
	unsigned int num;
	void *rspbuf;
	int rsplen;
	int rc;
	bool put = false;

	while (!kthread_should_stop() &&
	       (num = atomic_read(&cport->nping)) > 0) {
		len = snprintf(buf, sizeof(buf), "ping %u", num);
		rspbuf = NULL;
		rc = hfi2_cport_send_req(dd, CH_OP_PING, 0, buf, len, &rspbuf,
					 &rsplen,
					 cport_ping_to ? cport_ping_to * HZ :
							 hfi2_cport_adm_to * HZ);
		if (rc < 0) {
			dd_dev_info(dd, "CPORT \"%s\" error %d\n", buf, rc);
			if (!cport_ping_to)
				break;
		} else {
			dd_dev_info(dd, "CPORT \"%s\" -> %d \"%.*s\"\n", buf,
				    rc, rsplen, (char *)rspbuf);
		}
		kfree(rspbuf);
		atomic_dec(&cport->nping);
	}
	mutex_lock(&cport->ping_lock);
	if (cport->ping_th == current) {
		cport->ping_th = NULL;
		if (cport->ping_ref) {
			cport->ping_ref = false;
			put = true;
		}
	}
	if (cport_stopping(cport) || !cport->ping_th)
		atomic_set(&cport->nping, 0);
	mutex_unlock(&cport->ping_lock);
	if (put)
		hfi2_cport_put(cport);
	return 0;
}

int hfi2_cport_ping_start(struct hfi2_devdata *dd, unsigned int count)
{
	struct hfi2_cport *cport;
	struct task_struct *th;
	int rc;

	cport = hfi2_cport_get_live(dd);
	if (!cport)
		return -ESHUTDOWN;
	if (!count) {
		cport_ping_stop(cport);
		hfi2_cport_put(cport);
		return 0;
	}

	mutex_lock(&cport->ping_lock);
	if (cport_stopping(cport)) {
		mutex_unlock(&cport->ping_lock);
		hfi2_cport_put(cport);
		return -ESHUTDOWN;
	}
	atomic_set(&cport->nping, count);
	if (cport->ping_th) {
		mutex_unlock(&cport->ping_lock);
		hfi2_cport_put(cport);
		return 0;
	}

	if (!hfi2_cport_get(cport)) {
		mutex_unlock(&cport->ping_lock);
		hfi2_cport_put(cport);
		return -ESHUTDOWN;
	}
	th = kthread_create_on_node(cport_ping, cport, dd->node, "cport_ping");
	if (IS_ERR(th)) {
		rc = PTR_ERR(th);
		mutex_unlock(&cport->ping_lock);
		hfi2_cport_put(cport);
		hfi2_cport_put(cport);
		dd_dev_err(dd, "Failed to create CPORT ping thread %d\n", rc);
		return rc;
	}
	cport->ping_th = th;
	cport->ping_ref = true;
	get_task_struct(th);
	mutex_unlock(&cport->ping_lock);
	wake_up_process(th);
	put_task_struct(th);
	hfi2_cport_put(cport);
	return 0;
}

/*
 * cport_get_mac - Get burned-in MAC address
 * @dd: hfi device descriptor
 * @addr: storage for MAC address
 *
 * Return zero on success, -ERRNO otherwise.
 */
int cport_get_mac(struct hfi2_devdata *dd,
		  u64 *addr)
{
	int rc;
	int resp_len = 0;
	struct cport_mac_payload *mac = NULL;

	if (!dd->cport)
		return -EOPNOTSUPP;

	rc = hfi2_cport_send_req(dd, CH_OP_MAC_ADDR, 0, NULL, 0, (void **)&mac, &resp_len, HZ);
	if (rc) {
		dd_dev_err(dd, "Failure getting MAC address (%d)\n", rc);
		if (rc > 0)
			rc = -EIO;
	} else if (resp_len != (int)sizeof(*mac)) {
		dd_dev_err(dd, "Invalid MAC response length (%d!=%zu)\n", resp_len, sizeof(*mac));
		rc = -EIO;
	} else if (mac->valid) {
		*addr = mac->address;
	} else {
		dd_dev_warn(dd, "MAC address not available\n");
		rc = -ENXIO;
	}

	kfree(mac);

	return rc;
}

/**
 * cport_read_csr - Read a firmware-mediated Virtual CSR
 * @dd: hfi device descriptor
 * @addr: Virtual CSR address
 * @val: storage for the 64-bit CSR value
 *
 * Return zero on success, -ERRNO otherwise.
 */
int cport_read_csr(struct hfi2_devdata *dd, u32 addr, u64 *val, long timeout)
{
	int rc;
	int resp_len = 0;
	struct cport_csr req = { .addr = addr };
	struct cport_csr *rsp = NULL;

	if (!dd->cport)
		return -EOPNOTSUPP;

	rc = hfi2_cport_send_req(dd, CH_OP_CSR, 0, &req, sizeof(req), (void **)&rsp, &resp_len, timeout);
	if (rc > 0 || (!rc && resp_len != (int)sizeof(*rsp)))
		rc = -EIO;
	else if (!rc)
		*val = rsp->value;

	kfree(rsp);

	return rc;
}

#ifdef CONFIG_HFI_CPORT_POLLING
static int cport_poll(void *data)
{
	struct hfi2_devdata *dd = data;
	u64 v;

	while (!kthread_should_stop()) {
		v = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
		if (v & 0xff)
			hfi2_is_cport_int(dd, 0);
		fsleep(30);
	}
	return 0;
}
#endif

static ssize_t cport_intr_nops_show(struct device *device,
				    struct device_attribute *attr, char *buf)
{
	struct hfi2_ibdev *dev =
		rdma_device_to_drv_device(device, struct hfi2_ibdev, rdi.ibdev);
	struct hfi2_devdata *dd = dd_from_dev(dev);

	return sysfs_emit(buf, "%d\n", atomic_read(&dd->cport->intr_nops));
}

static ssize_t cport_intr_nops_store(struct device *device,
				     struct device_attribute *attr, const char *buf,
				     size_t count)
{
	struct hfi2_ibdev *dev = rdma_device_to_drv_device(device, struct hfi2_ibdev, rdi.ibdev);
	struct hfi2_devdata *dd = dd_from_dev(dev);

	/* don't care what is written, just clear the counter */
	atomic_set(&dd->cport->intr_nops, 0);

	return count;
}

static DEVICE_ATTR_RW(cport_intr_nops);

void cport_init_sysfs(struct hfi2_devdata *dd, struct device *class_dev)
{
	int ret;

	if (!dd->cport)
		return;

	ret = sysfs_create_file(&class_dev->kobj, &dev_attr_cport_intr_nops.attr);
	if (ret)
		dd_dev_warn(dd, "failed to create sysfs attr %s (%d)\n",
			dev_attr_cport_intr_nops.attr.name, ret);
}

/*
 * Initialization/setup of MCTXT CPORT communications channel.
 */
int hfi2_cport_init(struct hfi2_devdata *dd)
{
	struct hfi2_cport *cport;

	if (dd->params->chip_type == CHIP_WFR || dd->is_vf)
		return 0;

	cport = kzalloc(sizeof(*cport), GFP_KERNEL);
	if (!cport)
		goto err1;

	if (dd->params->chip_type == CHIP_CYR && dd->hfi2_id) {
		cport->cport_in_scratch = CYR_CCE_SCRATCH;
		cport->cport_out_scratch = CYR_CCE_SCRATCH + sizeof(u64);
	} else {
		cport->cport_in_scratch = JKR_ASIC_CFG_SCRATCH;
		cport->cport_out_scratch = JKR_ASIC_CFG_SCRATCH + sizeof(u64);
	}

	refcount_set(&cport->refcount, 1);
	init_completion(&cport->refcount_zero);
	INIT_WORK(&cport->mctxt_work, cport_mctxt_fn);
	xa_init_flags(&cport->tid_xa, XA_FLAGS_ALLOC);
	xa_init_flags(&cport->trap_xa, XA_FLAGS_ALLOC);

	/*
	 * Setting initial state can be problematic.
	 * We require that CPORT set JKR_MCTXT_INT_OUTBOX_EMPTY in
	 * JKR_MCTXT_PF0_INT_STATUS or we will never start sending.
	 * We also require that CPORT never set JKR_MCTXT_INT_OUTBOX_EMPTY
	 * gratuitously, or we get a semaphore count > 1 and will
	 * start overrunning MCTXT. Essentially, CPORT must set this
	 * exactly once when entering the "ready to receive" state
	 * (initially and after processing each message).
	 */
	sema_init(&cport->outbox, 0);
	mutex_init(&cport->admission_lock);
	mutex_init(&cport->ping_lock);
	mutex_init(&cport->trap_lock);

	cport->dd = dd;
	spin_lock_init(&cport->tx_lock);
	mutex_init(&cport->rx_lock);
	mutex_lock(&dd->cport_lock);
	dd->cport = cport;
	mutex_unlock(&dd->cport_lock);

	hfi2_cport_register_cb(dd, CH_OP_PING, CH_OP_PING, echo_req);

	if (cport_mctxt_recovery) {
		u64 is, ie;

		is = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_STATUS);
		ie = hfi2_read_csr(dd, JKR_MCTXT_PF0_INT_ENABLE);
		if (!(is & JKR_MCTXT_INT_OUTBOX_EMPTY) && ie) {
			dd_dev_warn(dd, "recovering CPORT MCTXT state\n");
			hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_ENABLE, 0);
			hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_STATUS,
				       JKR_MCTXT_INT_OUTBOX_EMPTY);
		}
	}

#ifdef CONFIG_HFI_CPORT_POLLING
	cport->poll_th =
		kthread_create_on_node(cport_poll, dd, dd->node, "cport_poll");
	if (IS_ERR(cport->poll_th)) {
		dd_dev_err(dd, "Failed to create CPORT polling thread\n");
		cport->poll_th = NULL;
	} else {
		wake_up_process(dd->cport->poll_th);
	}
#else
	/* Enable intr source for MCTXT from CPORT (to PF0) */
	hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_ENABLE,
		  JKR_MCTXT_INT_INBOX_FULL | JKR_MCTXT_INT_OUTBOX_EMPTY | JKR_MCTXT_INT_NOTIFY);
	hfi2_set_intr_bits(dd, JKR_MCTXT_CPORT_TO_PCIE_INT, JKR_MCTXT_CPORT_TO_PCIE_INT, true);
	timer_setup(&cport->lost_int_timer, cport_lost_int_chk, 0);
	if (cport_lost_int)
		mod_timer(&cport->lost_int_timer, jiffies + cport_lost_int);

	/*
	 * Must reset/resync sequence numbers as CPORT is strictly enforcing
	 * sequence number order. Use a timeout to allow easier cleanup should
	 * init fail.
	 */
	hfi2_cport_send_notif(dd, CH_OP_PING, 0, NULL, 0,
			      hfi2_cport_adm_to * HZ);
#endif
	return 0;

err1:
	return -ENOMEM;
}

/*
 * Deinitialization of MCTXT CPORT communications channel.
 */
int hfi2_cport_exit(struct hfi2_devdata *dd)
{
	struct hfi2_cport *cport;

	mutex_lock(&dd->cport_lock);
	cport = dd->cport;
	if (!cport) {
		mutex_unlock(&dd->cport_lock);
		return 0;
	}
	mutex_lock(&cport->admission_lock);
	WRITE_ONCE(cport->stopping, true);
	mutex_unlock(&cport->admission_lock);
	mutex_unlock(&dd->cport_lock);

	cport_ping_stop(cport);
#ifdef CONFIG_HFI_CPORT_POLLING
	if (cport->poll_th)
		kthread_stop(cport->poll_th);
#else
	timer_shutdown_sync(&cport->lost_int_timer);
#endif

	/* Disable intr source for MCTXT from CPORT (to PF0) */
	hfi2_set_intr_bits(dd, JKR_MCTXT_CPORT_TO_PCIE_INT,
			   JKR_MCTXT_CPORT_TO_PCIE_INT, false);
	hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_ENABLE, 0);

	/* remove the hfi2_cport IRQ - this can queue more hfi2_cport work */
	if (dd->cport_vec >= 0) {
		if (dd->msix_info.msix_entries &&
		    dd->cport_vec < dd->msix_info.max_requested)
			synchronize_irq(dd->msix_info.msix_entries[dd->cport_vec].irq);
		hfi2_msix_free_irq(dd, dd->cport_vec);
		dd->cport_vec = -1;
	}
	if (dd->msix_info.msix_entries && dd->msix_info.max_requested > 0 &&
	    dd->msix_info.msix_entries[0].irq)
		synchronize_irq(dd->msix_info.msix_entries[0].irq);

	/* flush again to clear any workers that could have slipped in */
	flush_workqueue(dd->hfi2_wq);

	/* leave JKR_MCTXT_INT_OUTBOX_EMPTY set so that future users are ready-to-go */
	hfi2_write_csr(dd, JKR_MCTXT_PF0_INT_STATUS,
		       JKR_MCTXT_INT_OUTBOX_EMPTY);
	cancel_work_sync(&cport->mctxt_work);
	cport_abort_incomplete_rx(cport, -ESHUTDOWN);
	cport_abort_requests(cport, -ESHUTDOWN);
	flush_workqueue(dd->hfi2_wq);

	hfi2_cport_put(cport);
	wait_for_completion(&cport->refcount_zero);
	mutex_lock(&dd->cport_lock);
	dd->cport = NULL;
	mutex_unlock(&dd->cport_lock);
	mutex_destroy(&cport->trap_lock);
	mutex_destroy(&cport->rx_lock);
	mutex_destroy(&cport->ping_lock);
	mutex_destroy(&cport->admission_lock);
	xa_destroy(&cport->tid_xa);
	xa_destroy(&cport->trap_xa);
	kfree(cport);

	return 0;
}
