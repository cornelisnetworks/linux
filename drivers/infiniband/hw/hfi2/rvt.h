/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2016 - 2019 Intel Corporation.
 */

#ifndef DEF_RDMA_VT_H
#define DEF_RDMA_VT_H

#define ib_rvt_state_ops hfi2_ib_rvt_state_ops
#define rvt_alloc_internal_mr hfi2_rvt_alloc_internal_mr
#define rvt_unpublish_internal_mr hfi2_rvt_unpublish_internal_mr
#define rvt_free_internal_mr hfi2_rvt_free_internal_mr
#define rvt_rotate_internal_mr_key hfi2_rvt_rotate_internal_mr_key
#define rvt_mr_refs_init hfi2_rvt_mr_refs_init
#define rvt_mr_refs_free hfi2_rvt_mr_refs_free
#define rvt_mr_kill hfi2_rvt_mr_kill
#define rvt_mr_put_slow hfi2_rvt_mr_put_slow
#define rvt_update_sge hfi2_rvt_update_sge
#define rvt_qp_reset_all_on_exit hfi2_rvt_qp_reset_all_on_exit
#define rvt_qp_free_storage hfi2_rvt_qp_free_storage
#define rvt_add_retry_timer_ext hfi2_rvt_add_retry_timer_ext
#define rvt_add_rnr_timer hfi2_rvt_add_rnr_timer
#define rvt_alloc_device hfi2_rvt_alloc_device
#define rvt_alloc_mr hfi2_rvt_alloc_mr
#define rvt_alloc_pd hfi2_rvt_alloc_pd
#define rvt_alloc_rq hfi2_rvt_alloc_rq
#define rvt_attach_mcast hfi2_rvt_attach_mcast
#define rvt_check_ah hfi2_rvt_check_ah
#define rvt_cmp_msn hfi2_rvt_cmp_msn
#define rvt_comm_est hfi2_rvt_comm_est
#define rvt_compute_aeth hfi2_rvt_compute_aeth
#define rvt_copy_sge hfi2_rvt_copy_sge
#define rvt_cq_enter hfi2_rvt_cq_enter
#define rvt_cq_exit hfi2_rvt_cq_exit
#define rvt_create_ah hfi2_rvt_create_ah
#define rvt_create_cq hfi2_rvt_create_cq
#define rvt_create_mad_agents hfi2_rvt_create_mad_agents
#define rvt_create_mmap_info hfi2_rvt_create_mmap_info
#define rvt_create_qp hfi2_rvt_create_qp
#define rvt_create_srq hfi2_rvt_create_srq
#define rvt_dealloc_device hfi2_rvt_dealloc_device
#define rvt_dealloc_pd hfi2_rvt_dealloc_pd
#define rvt_del_timers_sync hfi2_rvt_del_timers_sync
#define rvt_dereg_mr hfi2_rvt_dereg_mr
#define rvt_destroy_ah hfi2_rvt_destroy_ah
#define rvt_destroy_cq hfi2_rvt_destroy_cq
#define rvt_destroy_qp hfi2_rvt_destroy_qp
#define rvt_destroy_srq hfi2_rvt_destroy_srq
#define rvt_detach_mcast hfi2_rvt_detach_mcast
#define rvt_driver_cq_init hfi2_rvt_driver_cq_init
#define rvt_driver_mcast_init hfi2_rvt_driver_mcast_init
#define rvt_driver_mr_init hfi2_rvt_driver_mr_init
#define rvt_driver_qp_init hfi2_rvt_driver_qp_init
#define rvt_driver_srq_init hfi2_rvt_driver_srq_init
#define rvt_error_qp hfi2_rvt_error_qp
#define rvt_fast_reg_mr hfi2_rvt_fast_reg_mr
#define rvt_free_mad_agents hfi2_rvt_free_mad_agents
#define rvt_get_credit hfi2_rvt_get_credit
#define rvt_get_dma_mr hfi2_rvt_get_dma_mr
#define rvt_get_rwqe hfi2_rvt_get_rwqe
#define rvt_init_port hfi2_rvt_init_port
#define rvt_invalidate_rkey hfi2_rvt_invalidate_rkey
#define rvt_lkey_ok hfi2_rvt_lkey_ok
#define rvt_map_mr_sg hfi2_rvt_map_mr_sg
#define rvt_mcast_add hfi2_rvt_mcast_add
#define rvt_mcast_find hfi2_rvt_mcast_find
#define rvt_mcast_tree_empty hfi2_rvt_mcast_tree_empty
#define rvt_mmap hfi2_rvt_mmap
#define rvt_mmap_init hfi2_rvt_mmap_init
#define rvt_modify_ah hfi2_rvt_modify_ah
#define rvt_modify_qp hfi2_rvt_modify_qp
#define rvt_modify_srq hfi2_rvt_modify_srq
#define rvt_mr_exit hfi2_rvt_mr_exit
#define rvt_mr_has_lkey hfi2_rvt_mr_has_lkey
#define rvt_poll_cq hfi2_rvt_poll_cq
#define rvt_post_recv hfi2_rvt_post_recv
#define rvt_post_send hfi2_rvt_post_send
#define rvt_post_srq_recv hfi2_rvt_post_srq_recv
#define rvt_process_mad hfi2_rvt_process_mad
#define rvt_qp_exit hfi2_rvt_qp_exit
#define rvt_qp_iter hfi2_rvt_qp_iter
#define rvt_qp_iter_init hfi2_rvt_qp_iter_init
#define rvt_qp_iter_next hfi2_rvt_qp_iter_next
#define rvt_qp_mr_clean hfi2_rvt_qp_mr_clean
#define rvt_query_ah hfi2_rvt_query_ah
#define rvt_query_qp hfi2_rvt_query_qp
#define rvt_query_srq hfi2_rvt_query_srq
#define rvt_rc_error hfi2_rvt_rc_error
#define rvt_rc_rnr_retry hfi2_rvt_rc_rnr_retry
#define rvt_reg_user_mr hfi2_rvt_reg_user_mr
#define rvt_reg_user_mr_dmabuf hfi2_rvt_reg_user_mr_dmabuf
#define rvt_register_device hfi2_rvt_register_device
#define rvt_release_mmap_info hfi2_rvt_release_mmap_info
#define rvt_req_notify_cq hfi2_rvt_req_notify_cq
#define rvt_resize_cq hfi2_rvt_resize_cq
#define rvt_restart_sge hfi2_rvt_restart_sge
#define rvt_rkey_ok hfi2_rvt_rkey_ok
#define rvt_rnr_tbl_to_usec hfi2_rvt_rnr_tbl_to_usec
#define rvt_ruc_loopback hfi2_rvt_ruc_loopback
#define rvt_send_complete hfi2_rvt_send_complete
#define rvt_ss_has_lkey hfi2_rvt_ss_has_lkey
#define rvt_stop_rc_timers hfi2_rvt_stop_rc_timers
#define rvt_unregister_device hfi2_rvt_unregister_device
#define rvt_wss_exit hfi2_rvt_wss_exit
#define rvt_wss_init hfi2_rvt_wss_init

int hfi2_rvt_init(void);
void hfi2_rvt_cleanup(void);

/*
 * Structure that low level drivers will populate in order to register with the
 * rdmavt layer.
 */

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include "rvt_mr.h"

#define RVT_MAX_PKEY_VALUES 16

#define RVT_MAX_TRAP_LEN 100 /* Limit pending trap list */
#define RVT_MAX_TRAP_LISTS 5 /*((IB_NOTICE_TYPE_INFO & 0x0F) + 1)*/
#define RVT_TRAP_TIMEOUT 4096 /* 4.096 usec */

struct trap_list {
	u32 list_len;
	struct list_head list;
};

struct rvt_qp;
struct rvt_qpn_table;
struct workqueue_struct;
struct rvt_ibport {
	struct rvt_qp __rcu *qp[2];
	struct ib_mad_agent *send_agent;	/* agent for SMI (traps) */
	struct rb_root mcast_tree;
	spinlock_t lock;		/* protect changes in this struct */

	/* non-zero when timer is set */
	unsigned long mkey_lease_timeout;
	unsigned long trap_timeout;
	__be64 gid_prefix;      /* in network order */
	__be64 mkey;
	u64 tid;
	u32 port_cap_flags;
	u16 port_cap3_flags;
	u32 port_cap4_flags;
	u32 pma_sample_start;
	u32 pma_sample_interval;
	__be16 pma_counter_select[5];
	u16 pma_tag;
	u16 mkey_lease_period;
	u32 sm_lid;
	u8 sm_sl;
	u8 mkeyprot;
	u8 subnet_timeout;
	u8 vl_high_limit;

	/*
	 * Driver is expected to keep these up to date. These
	 * counters are informational only and not required to be
	 * completely accurate.
	 */
	u64 n_rc_resends;
	u64 n_seq_naks;
	u64 n_rdma_seq;
	u64 n_rnr_naks;
	u64 n_other_naks;
	u64 n_loop_pkts;
	u64 n_pkt_drops;
	u64 n_vl15_dropped;
	u64 n_rc_timeouts;
	u64 n_dmawait;
	u64 n_unaligned;
	u64 n_rc_dupreq;
	u64 n_rc_seqnak;
	u64 n_rc_crwaits;
	u16 pkey_violations;
	u16 qkey_violations;
	u16 mkey_violations;

	/* Hot-path per CPU counters to avoid cacheline trading to update */
	u64 z_rc_acks;
	u64 z_rc_qacks;
	u64 z_rc_delayed_comp;
	u64 __percpu *rc_acks;
	u64 __percpu *rc_qacks;
	u64 __percpu *rc_delayed_comp;

	void *priv; /* driver private data */

	/*
	 * The pkey table is allocated and maintained by the driver. Drivers
	 * need to have access to this before registering with rdmav. However
	 * rdmavt will need access to it so drivers need to provide this during
	 * the attach port API call.
	 */
	u16 *pkey_table;

	struct rvt_ah *sm_ah;

	/*
	 * Keep a list of traps that have not been repressed.  They will be
	 * resent based on trap_timer.
	 */
	struct trap_list trap_lists[RVT_MAX_TRAP_LISTS];
	struct timer_list trap_timer;
};

#define RVT_CQN_MAX 16 /* maximum length of cq name */

#define RVT_SGE_COPY_MEMCPY	0
#define RVT_SGE_COPY_CACHELESS	1
#define RVT_SGE_COPY_ADAPTIVE	2

/*
 * Things that are driver specific, module parameters in hfi1 and qib
 */
struct rvt_driver_params {
	struct ib_device_attr props;

	/*
	 * Anything driver specific that is not covered by props
	 * For instance special module parameters. Goes here.
	 */
	unsigned int lkey_table_size;
	unsigned int qp_table_size;
	unsigned int sge_copy_mode;
	u32 max_inline_data;
	unsigned int wss_threshold;
	unsigned int wss_clean_period;
	int qpn_start;
	int qpn_inc;
	int qpn_res_start;
	int qpn_res_end;
	int nports;
	int npkeys;
	int node;
	int psn_mask;
	int psn_shift;
	int psn_modify_mask;
	u32 core_cap_flags;
	u32 max_mad_size;
	u8 qos_shift;
	u8 max_rdma_atomic;
	u8 extra_rdma_atomic;
	u8 reserved_operations;
	/*
	 * Free kernel (umem-less) MRs from a workqueue after an RCU grace
	 * period instead of waiting in ib_dereg_mr().  Only for drivers whose
	 * kernel ULPs tear down many MRs at once; the ULP must already have
	 * drained every QP using the MR, as the IB spec requires.
	 */
	bool async_kernel_mr_dereg;
};

/* User context */
struct rvt_ucontext {
	struct ib_ucontext ibucontext;
	void *priv;
};

/* Protection domain */
struct rvt_pd {
	struct ib_pd ibpd;
	bool user;
};

/* Address handle */
struct rvt_ah {
	struct ib_ah ibah;
	struct rdma_ah_attr attr;
	u8 vl;
	u8 log_pmtu;
};

/*
 * This structure is used by rvt_mmap() to validate an offset
 * when an mmap() request is made.  The vm_area_struct then uses
 * this as its vm_private_data.
 */
struct rvt_mmap_info {
	struct list_head pending_mmaps;
	struct ib_ucontext *context;
	void *obj;
	__u64 offset;
	struct kref ref;
	u32 size;
};

/* memory working set size */
struct rvt_wss {
	unsigned long *entries;
	atomic_t total_count;
	atomic_t clean_counter;
	atomic_t clean_entry;

	int threshold;
	int num_entries;
	long pages_mask;
	unsigned int clean_period;
};

struct rvt_dev_info;
struct rvt_swqe;
struct rvt_driver_provided {
	/*
	 * Which functions are required depends on which verbs rdmavt is
	 * providing and which verbs the driver is overriding. See
	 * check_support() for details.
	 */

	/* hot path calldowns in a single cacheline */

	/*
	 * Give the driver a notice that there is send work to do. It is up to
	 * the driver to generally push the packets out, this just queues the
	 * work with the driver. There are two variants here. The no_lock
	 * version requires the s_lock not to be held. The other assumes the
	 * s_lock is held.
	 */
	bool (*schedule_send)(struct rvt_qp *qp);
	bool (*schedule_send_no_lock)(struct rvt_qp *qp);

	/*
	 * Driver specific work request setup and checking.
	 * This function is allowed to perform any setup, checks, or
	 * adjustments required to the SWQE in order to be usable by
	 * underlying protocols. This includes private data structure
	 * allocations.
	 */
	int (*setup_wqe)(struct rvt_qp *qp, struct rvt_swqe *wqe,
			 bool *call_send);
	/*
	 * Release a deferred REG_MR snapshot on completion or SQ discard.
	 * Required with setup_wqe when fast_reg_mr requests deferral.
	 * Final-release callback: the deferred bit is already consumed.
	 */
	void (*cleanup_reg_mr)(struct rvt_qp *qp, struct rvt_swqe *wqe);
	/* Opt-in final release of a delayed LOCAL_INV snapshot from setup_wqe. */
	void (*cleanup_local_inv)(struct rvt_qp *qp, struct rvt_swqe *wqe);

	/*
	 * Sometimes rdmavt needs to kick the driver's send progress. That is
	 * done by this call back.
	 */
	void (*do_send)(struct rvt_qp *qp);

	/*
	 * Returns a pointer to the underlying hardware's PCI device. This is
	 * used to display information as to what hardware is being referenced
	 * in an output message
	 */
	struct pci_dev * (*get_pci_dev)(struct rvt_dev_info *rdi);

	/*
	 * Allocate a private queue pair data structure for driver specific
	 * information which is opaque to rdmavt.  Errors are returned via
	 * ERR_PTR(err).  The driver is free to return NULL or a valid
	 * pointer.
	 */
	void * (*qp_priv_alloc)(struct rvt_dev_info *rdi, struct rvt_qp *qp);

	/*
	 * Init a structure allocated with qp_priv_alloc(). This should be
	 * called after all qp fields have been initialized in rdmavt.
	 */
	int (*qp_priv_init)(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			    struct ib_qp_init_attr *init_attr);

	/*
	 * Free the driver's private qp structure.
	 */
	void (*qp_priv_free)(struct rvt_dev_info *rdi, struct rvt_qp *qp);

	/*
	 * Inform the driver the particular qp in question has been reset so
	 * that it can clean up anything it needs to.
	 */
	void (*notify_qp_reset)(struct rvt_qp *qp);

	/*
	 * Get a path mtu from the driver based on qp attributes.
	 */
	int (*get_pmtu_from_attr)(struct rvt_dev_info *rdi, struct rvt_qp *qp,
				  struct ib_qp_attr *attr);

	/*
	 * Notify driver that it needs to flush any outstanding IO requests that
	 * are waiting on a qp.
	 */
	void (*flush_qp_waiters)(struct rvt_qp *qp);

	/*
	 * Notify driver to stop its queue of sending packets. Nothing else
	 * should be posted to the queue pair after this has been called.
	 */
	void (*stop_send_queue)(struct rvt_qp *qp);

	/*
	 * Have the driver drain any in progress operations
	 */
	void (*quiesce_qp)(struct rvt_qp *qp);

	/*
	 * Inform the driver a qp has went to error state.
	 */
	void (*notify_error_qp)(struct rvt_qp *qp);

	/*
	 * Get an MTU for a qp.
	 */
	u32 (*mtu_from_qp)(struct rvt_dev_info *rdi, struct rvt_qp *qp,
			   u32 pmtu);
	/*
	 * Convert an mtu to a path mtu
	 */
	int (*mtu_to_path_mtu)(u32 mtu);

	/*
	 * Get the guid of a port in big endian byte order
	 */
	int (*get_guid_be)(struct rvt_dev_info *rdi, struct rvt_ibport *rvp,
			   int guid_index, __be64 *guid);

	/*
	 * Query driver for the state of the port.
	 */
	int (*query_port_state)(struct rvt_dev_info *rdi, u32 port_num,
				struct ib_port_attr *props);

	/*
	 * Tell driver to shutdown a port
	 */
	int (*shut_down_port)(struct rvt_dev_info *rdi, u32 port_num);

	/* Tell driver to send a trap for changed  port capabilities */
	void (*cap_mask_chg)(struct rvt_dev_info *rdi, u32 port_num);

	/*
	 * The following functions can be safely ignored completely. Any use of
	 * these is checked for NULL before blindly calling. Rdmavt should also
	 * be functional if drivers omit these.
	 */

	/* Called to inform the driver that all qps should now be freed. */
	unsigned int (*free_all_qps)(struct rvt_dev_info *rdi);
	void (*quiesce_internal_mrs)(struct rvt_dev_info *rdi);
	void (*release_internal_mrs)(struct rvt_dev_info *rdi);

	/* Driver specific AH validation */
	int (*check_ah)(struct ib_device *, struct rdma_ah_attr *);

	/* Inform the driver a new AH has been created */
	void (*notify_new_ah)(struct ib_device *, struct rdma_ah_attr *,
			      struct rvt_ah *);

	/* Let the driver pick the next queue pair number*/
	int (*alloc_qpn)(struct rvt_dev_info *rdi, struct rvt_qpn_table *qpt,
			 enum ib_qp_type type, u32 port_num);

	/* Determine if its safe or allowed to modify the qp */
	int (*check_modify_qp)(struct rvt_qp *qp, struct ib_qp_attr *attr,
			       int attr_mask, struct ib_udata *udata);

	/* Driver specific QP modification/notification-of */
	void (*modify_qp)(struct rvt_qp *qp, struct ib_qp_attr *attr,
			  int attr_mask, struct ib_udata *udata);

	/* Notify driver a mad agent has been created */
	void (*notify_create_mad_agent)(struct rvt_dev_info *rdi, int port_idx);

	/* Notify driver a mad agent has been removed */
	void (*notify_free_mad_agent)(struct rvt_dev_info *rdi, int port_idx);

	/* Notify driver to restart rc */
	void (*notify_restart_rc)(struct rvt_qp *qp, u32 psn, int wait);

	/* Get and return CPU to pin CQ processing thread */
	int (*comp_vect_cpu_lookup)(struct rvt_dev_info *rdi, int comp_vect);

	/* allocate a ucontext */
	int (*alloc_ucontext)(struct ib_ucontext *uctx, struct ib_udata *udata);

	/* deallocate a ucontext */
	void (*dealloc_ucontext)(struct ib_ucontext *context);

	/* driver mmap */
	int (*mmap)(struct ib_ucontext *context, struct vm_area_struct *vma);

	/* Ordinary MR notification. Legacy FastReg ignores its return value. */
	int (*notify_register_mr)(struct rvt_dev_info *rdi,
				  struct rvt_mregion *mr);
	/*
	 * Optional FastReg replacement, called atomically under s_hlock after
	 * software-key publication. Return 0/-errno; set only
	 * RVT_SEND_REG_MR_DEFERRED in the zero-initialized output. No sleeping.
	 * On failure leave no new hardware publication; notify_unregister_mr
	 * must support atomic revocation of rejected outcomes. With no hook,
	 * retain legacy notify_register_mr behavior, including ignored returns.
	 */
	int (*fast_reg_mr)(struct rvt_dev_info *rdi, struct rvt_mregion *mr,
			   unsigned int *reg_flags);
	void (*notify_unregister_mr)(struct rvt_dev_info *rdi,
				     struct rvt_mregion *mr);

	/*
	 * Allocate driver-private per-MR state at MR allocation time.
	 * Returns a pointer stashed in mr->driver_priv, NULL if the
	 * driver has nothing to attach, or ERR_PTR(-errno) on failure
	 * (which fails the MR allocation back to the caller).  Mirrors
	 * the qp_priv_alloc/qp_priv_free pattern.
	 */
	void *(*mr_priv_alloc)(struct rvt_dev_info *rdi,
			       struct rvt_mregion *mr);

	/*
	 * Free driver-private per-MR state.  Called once, just before
	 * the rvt_mregion-containing allocation is freed, after the
	 * references on the MR have drained.  Driver must be tolerant of NULL
	 * mr->driver_priv (the mr_priv_alloc may have returned NULL).
	 *
	 * The rvt_mregion itself is freed only after an RCU grace period.  A
	 * driver that reads mr->driver_priv under rcu_read_lock() without
	 * holding a reference on the MR must clear it with WRITE_ONCE() and
	 * free the private state through RCU (kfree_rcu() or equivalent), not
	 * immediately.  A driver whose readers all hold a reference needs
	 * neither.
	 */
	void (*mr_priv_free)(struct rvt_dev_info *rdi,
			     struct rvt_mregion *mr);

	/*
	 * Called after MR pages change; a nonzero return fails the operation.
	 * FastReg may be atomic; only user registration guarantees sleepable
	 * context.
	 */
	int (*notify_mr_pages_set)(struct rvt_dev_info *rdi,
				   struct rvt_mregion *mr);
	/*
	 * Perform a memcpy to/from/between RVT_MEM_DMABUF_DO memory. It is
	 * expected at least one of src or dest is of type RVT_MEM_DMABUF_DO,
	 * otherwise just use normal memcpy facilities.
	 */
	int (*dmabuf_memcpy)(struct rvt_seg dest, struct rvt_seg src);
};

struct rvt_dev_info {
	struct ib_device ibdev; /* Keep this first. Nothing above here */

	/*
	 * Prior to calling for registration the driver will be responsible for
	 * allocating space for this structure.
	 *
	 * The driver will also be responsible for filling in certain members of
	 * dparms.props. The driver needs to fill in dparms exactly as it would
	 * want values reported to a ULP. This will be returned to the caller
	 * in rdmavt's device. The driver should also therefore refrain from
	 * modifying this directly after registration with rdmavt.
	 */

	/* Driver specific properties */
	struct pci_dev *pdev;
	struct rvt_driver_params dparms;

	/* post send table */
	const struct rvt_operation_params *post_parms;

	/* opcode translation table */
	const enum ib_wc_opcode *wc_opcode;

	/* Driver specific helper functions */
	struct rvt_driver_provided driver_f;

	struct rvt_mregion __rcu *dma_mr;
	struct rvt_lkey_table lkey_table;
	struct workqueue_struct *mr_dereg_wq;

	/* Internal use */
	int n_pds_allocated;
	spinlock_t n_pds_lock; /* Protect pd allocated count */

	int n_ahs_allocated;
	spinlock_t n_ahs_lock; /* Protect ah allocated count */

	u32 n_srqs_allocated;
	spinlock_t n_srqs_lock; /* Protect srqs allocated count */

	int flags;
	bool use_bulksvc;
	struct rvt_ibport **ports;

	/* QP */
	struct rvt_qp_ibdev *qp_dev;
	u32 n_qps_allocated;    /* number of QPs allocated for device */
	u32 n_rc_qps;		/* number of RC QPs allocated for device */
	u32 busy_jiffies;	/* timeout scaling based on RC QP count */
	spinlock_t n_qps_lock;	/* protect qps, rc qps and busy jiffy counts */

	/* memory maps */
	struct list_head pending_mmaps;
	spinlock_t mmap_offset_lock; /* protect mmap_pgoff */
	u32 mmap_pgoff;
	spinlock_t pending_lock; /* protect pending mmap list */

	/* CQ */
	u32 n_cqs_allocated;    /* number of CQs allocated for device */
	spinlock_t n_cqs_lock; /* protect count of in use cqs */

	/* Multicast */
	u32 n_mcast_grps_allocated; /* number of mcast groups allocated */
	spinlock_t n_mcast_grps_lock;

	/* Memory Working Set Size */
	struct rvt_wss *wss;
};

/**
 * rvt_get_ibdev_name - return the IB name
 * @rdi: rdmavt device
 *
 * Return the registered name of the device.
 */
static inline const char *rvt_get_ibdev_name(const struct rvt_dev_info *rdi)
{
	return dev_name(&rdi->ibdev.dev);
}

static inline struct rvt_pd *ibpd_to_rvtpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct rvt_pd, ibpd);
}

static inline struct rvt_ah *ibah_to_rvtah(struct ib_ah *ibah)
{
	return container_of(ibah, struct rvt_ah, ibah);
}

static inline struct rvt_dev_info *ib_to_rvt(struct ib_device *ibdev)
{
	return  container_of(ibdev, struct rvt_dev_info, ibdev);
}

static inline unsigned int rvt_get_npkeys(struct rvt_dev_info *rdi)
{
	/*
	 * All ports have same number of pkeys.
	 */
	return rdi->dparms.npkeys;
}

/*
 * Return the max atomic suitable for determining
 * the size of the ack ring buffer in a QP.
 */
static inline unsigned int rvt_max_atomic(struct rvt_dev_info *rdi)
{
	return rdi->dparms.max_rdma_atomic +
		rdi->dparms.extra_rdma_atomic + 1;
}

static inline unsigned int rvt_size_atomic(struct rvt_dev_info *rdi)
{
	return rdi->dparms.max_rdma_atomic +
		rdi->dparms.extra_rdma_atomic;
}

/*
 * Return the indexed PKEY from the port PKEY table.
 */
static inline u16 rvt_get_pkey(struct rvt_dev_info *rdi,
			       int port_index,
			       unsigned int index)
{
	if (index >= rvt_get_npkeys(rdi))
		return 0;
	else
		return rdi->ports[port_index]->pkey_table[index];
}

struct rvt_dev_info *rvt_alloc_device(size_t size, int nports);
void rvt_dealloc_device(struct rvt_dev_info *rdi);
int rvt_register_device(struct rvt_dev_info *rvd, struct pci_dev *pdev);
void rvt_unregister_device(struct rvt_dev_info *rvd);
int rvt_check_ah(struct ib_device *ibdev, struct rdma_ah_attr *ah_attr);
int rvt_init_port(struct rvt_dev_info *rdi, struct rvt_ibport *port,
		  int port_index, u16 *pkey_table);
int rvt_fast_reg_mr(struct rvt_qp *qp, struct ib_mr *ibmr, u32 key,
		    int access, unsigned int *reg_flags);
enum rvt_internal_mr_key_policy {
	RVT_INTERNAL_MR_KEY_NO_WRAP = 0,
	/* Caller has revoked hardware use and drained accesses before reuse. */
	RVT_INTERNAL_MR_KEY_WRAP_AFTER_DRAIN,
};

struct ib_mr *rvt_alloc_internal_mr(struct ib_pd *pd);
void rvt_unpublish_internal_mr(struct ib_mr *ibmr);
void rvt_free_internal_mr(struct ib_mr *ibmr);
int rvt_rotate_internal_mr_key(struct ib_mr *ibmr, u32 *key,
			       enum rvt_internal_mr_key_policy policy);
int rvt_invalidate_rkey(struct rvt_qp *qp, u32 rkey);
int rvt_rkey_ok(struct rvt_qp *qp, struct rvt_sge *sge,
		u32 len, u64 vaddr, u32 rkey, int acc);
int rvt_lkey_ok(struct rvt_lkey_table *rkt, struct rvt_pd *pd,
		struct rvt_sge *isge, struct rvt_sge *last_sge,
		struct ib_sge *sge, int acc);
struct rvt_mcast *rvt_mcast_find(struct rvt_ibport *ibp, union ib_gid *mgid,
				 u16 lid);
#endif          /* DEF_RDMA_VT_H */
