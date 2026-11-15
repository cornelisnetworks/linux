// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (c) 2026 Cornelis Networks, Inc.
 *
 * RoCE IB device registration for hfi2 in CN6000 Ethernet mode.
 *
 * On CN6000, an hfi2 PF can be configured at boot to operate either as
 * an OPA HCA (existing path in verbs.c) or as a network controller
 * with RoCE riding on top.  The RoCE registration path lives in this
 * file and is reached via hfi2_register_roce_ib_device(), which is
 * called from hfi2_register_ib_device() when hfi2_is_eth_mode(dd) is
 * true.  We share the same RDMA_DRIVER_HFI2 driver_id for both modes;
 * userspace distinguishes via a one-time link_layer query.
 *
 * Architecturally we go through the same rvt_register_device() entry
 * point as the OPA path.  rdmavt itself is transport-agnostic; the
 * RoCE flavour comes from supplying RoCE versions of the per-driver
 * driver_f hooks (see roce_verbs.c) and a RoCE-flavoured dparms
 * (core_cap_flags=RoCEv2 UDP encapsulation plus IB CM/MAD support, standard
 * IB MTU enums only).  This lets us reuse rdmavt's QP/CQ/MR/PD/AH state
 * machines unchanged.  The send-engine entry point hands RC and UD WQEs to
 * the DMS_RoCE software wire backend and bulksvc-loaned PIO context.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include "rvt.h"
#include <rdma/uverbs_ioctl.h>

#include "bulksvc.h"
#include "eth_hwi.h"
#include "hfi2.h"
#include "roce_pasid.h"
#include "qp.h"
#include "roce.h"
#include "verbs.h"
#include "verbs_txreq.h"

/* HFI2_ROCE_GID_TBL_LEN lives in roce.h (shared with check_ah bounds). */

/*
 * Forward decls for symbols in verbs.c that we deliberately reuse.
 * They are not in any header today because the OPA path is the only
 * caller; rather than churn the existing exports just for this file
 * we declare them locally.
 */
/*
 * The OPA path keeps these as module parameters in verbs.c; rather
 * than promoting all of them to non-static just to be visible here
 * we hard-code conservative RoCE defaults.  They become module
 * parameters in their own right if/when we need tunability on the
 * RoCE side.
 */
#define HFI2_ROCE_QP_TABLE_SIZE		256
#define HFI2_ROCE_LKEY_TABLE_SIZE	16
#define HFI2_ROCE_MAX_QPS		32768
#define HFI2_ROCE_MAX_QP_WRS		((u32)0x3FFFFF)
#define HFI2_ROCE_MAX_SGES		30
#define HFI2_ROCE_MAX_CQS		0x1FFFF
#define HFI2_ROCE_MAX_CQES		0x2FFFFF
#define HFI2_ROCE_MAX_PDS		0xFFFF
#define HFI2_ROCE_MAX_AHS		0xFFFF
#define HFI2_ROCE_MAX_SRQS		1024
#define HFI2_ROCE_MAX_SRQ_WRS		0x1FFFF
#define HFI2_ROCE_MAX_SRQ_SGES		128
#define HFI2_ROCE_MAX_MCAST_GRPS	16384
#define HFI2_ROCE_MAX_MCAST_QP_ATTACHED	16
#define HFI2_ROCE_SGE_COPY_MODE		0
#define HFI2_ROCE_WSS_THRESHOLD		80
#define HFI2_ROCE_WSS_CLEAN_PERIOD	256

static char *roce_ip_da_netdev;

bool hfi2_roce_kmr_pasid_enabled;

bool hfi2_roce_kmr_donor_enabled;

unsigned int hfi2_roce_kmr_donor_gb = 64;

bool hfi2_roce_mtu_8192_available(const struct hfi2_devdata *dd,
				  const struct net_device *ndev)
{
	const struct hfi2_bulksvc *svc = READ_ONCE(dd->bulksvc);

	return ndev && READ_ONCE(ndev->mtu) >= 8255 && svc &&
		svc->backend == HFI2_BULKSVC_BACKEND_ETH_ROCE &&
		svc->dms_roce && READ_ONCE(svc->dms_roce->initialized) &&
		READ_ONCE(svc->dms_roce->mtu_8192_capable);
}

extern const struct rvt_operation_params hfi2_post_parms[];
extern const enum ib_wc_opcode hfi2_ib_hfi2_wc_opcode[];
extern const struct uapi_definition hfi2_ib_defs[];

extern struct pci_dev *hfi2_get_pci_dev(struct rvt_dev_info *rdi);
extern int hfi2_alloc_ucontext(struct ib_ucontext *uctx,
			       struct ib_udata *udata);
extern void hfi2_dealloc_ucontext(struct ib_ucontext *uctx);
extern int hfi2_mmap(struct ib_ucontext *uctx,
		     struct vm_area_struct *vma);
extern void hfi2_mmap_free(struct rdma_user_mmap_entry *rdma_entry);
extern int hfi2_comp_vect_mappings_lookup(struct rvt_dev_info *rdi,
					  int comp_vector);

/* ------------------------------------------------------------------------- */
/* RoCE-specific ib_device_ops (small overlay; rdmavt provides the bulk).    */
/* ------------------------------------------------------------------------- */

static int hfi2_roce_query_port(struct ib_device *ibdev, u32 port_num,
				struct ib_port_attr *props)
{
	struct hfi2_devdata *dd = dd_from_ibdev(ibdev);
	struct hfi2_pportdata *ppd;
	struct net_device *ndev;

	if (port_num < 1 || port_num > dd->num_pports)
		return -EINVAL;
	ppd = &dd->pport[port_num - 1];
	ndev = ppd->ndev;

	/* props is zeroed by the caller. */
	if (ndev && netif_carrier_ok(ndev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state = IB_PORT_DOWN;
		props->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}

	props->gid_tbl_len = HFI2_ROCE_GID_TBL_LEN;
	props->pkey_tbl_len = 1;
	/*
	 * max_mtu/active_mtu cross the standard verbs ABI as a raw enum
	 * ib_mtu byte (copy_port_attr_to_resp() -> ib_uverbs_query_port_resp,
	 * no per-consumer branching).  enum ib_mtu only has members up to
	 * IB_MTU_4096=5 (include/rdma/ib_verbs.h); the private OPA_MTU_8192=6
	 * value used here is not a legal member of that enum.  A conformant
	 * consumer calling the standard ib_mtu_enum_to_int()/
	 * uct_ib_mtu_value()-style accessor on it hits the "unknown enum"
	 * path (observed as a hard "Fatal: Invalid MTU value (6)" abort in
	 * UCX's uct_ib_mtu_value()).  Report only a value the generic ABI
	 * understands here; the DMS RC path's private 8192 PMTU capability
	 * is unaffected and is negotiated separately per-QP via
	 * hfi2_roce_get_pmtu_from_attr() (roce_verbs.c), which still accepts
	 * an explicit path_mtu=OPA_MTU_8192 modify-QP request.
	 */
	props->max_mtu = IB_MTU_4096;
	props->active_mtu = ndev ? iboe_get_mtu(ndev->mtu) : IB_MTU_1024;
	props->max_msg_sz = 0x80000000;
	props->max_vl_num = 1;

	/*
	 * Report a fixed active_speed/active_width instead of querying the
	 * netdev's ethtool link settings.
	 *
	 * rvt_modify_qp() calls rvt_check_ah() -> ib_query_port() ->
	 * hfi2_roce_query_port() while holding the QP spinlock (qp->s_lock/
	 * r_lock).  ib_get_eth_speed() -> cne_get_link_ksettings() ->
	 * hfi2_cport_send_req() -> down_timeout() sleeps on the cport mailbox
	 * semaphore waiting for the emulator to reply.  Sleeping while
	 * holding a spinlock triggers "scheduling while atomic" and, on the
	 * slow emulator, effectively hangs ibv_modify_qp so the RC handshake
	 * never completes.  Speed accuracy is irrelevant for functional
	 * verbs traffic, so report a fixed 100G-class rate and avoid the
	 * sleeping mailbox round-trip entirely.
	 */
	props->active_speed = IB_SPEED_EDR;
	props->active_width = IB_WIDTH_4X;

	return 0;
}

static enum rdma_link_layer hfi2_roce_get_link_layer(struct ib_device *ibdev,
						     u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static struct net_device *hfi2_roce_provider_get_netdev(struct ib_device *ibdev,
							u32 port_num)
{
	struct hfi2_devdata *dd;
	struct hfi2_pportdata *ppd;
	struct net_device *ndev;

	if (!ibdev)
		return NULL;
	dd = dd_from_ibdev(ibdev);
	if (port_num < 1 || port_num > dd->num_pports)
		return NULL;
	ppd = &dd->pport[port_num - 1];

	ndev = READ_ONCE(ppd->ndev);
	if (ndev)
		dev_hold(ndev);
	return ndev;
}

static struct net_device *hfi2_roce_get_netdev(struct ib_device *ibdev,
					       u32 port_num)
{
	return hfi2_roce_provider_get_netdev(ibdev, port_num);
}

static u64 hfi2_roce_ip_da_value(__be32 ipv4, bool valid)
{
	u64 value = ((u64)ntohl(ipv4) << 32) & EAL_VF_IP_DA_ADDR_MASK;

	if (valid)
		value |= EAL_VF_IP_DA_VALID_MASK;
	return value;
}

static struct hfi2_roce_sw_rx_ipv4 *
hfi2_roce_sw_rx_ipv4_find(struct hfi2_roce_ip_da *ip_da, __be32 ipv4)
{
	u8 i;

	for (i = 0; i < HFI2_ROCE_SW_RX_IPV4_MAX; i++)
		if (refcount_read(&ip_da->sw_rx[i].refs) &&
		    ip_da->sw_rx[i].ipv4 == ipv4)
			return &ip_da->sw_rx[i];
	return NULL;
}

static int hfi2_roce_sw_rx_ipv4_add(struct hfi2_roce_ip_da *ip_da,
					   __be32 ipv4,
					   struct hfi2_roce_sw_rx_ipv4 **entry)
{
	struct hfi2_roce_sw_rx_ipv4 *sw_rx;
	u8 i;

	sw_rx = hfi2_roce_sw_rx_ipv4_find(ip_da, ipv4);
	if (sw_rx) {
		refcount_inc(&sw_rx->refs);
		*entry = sw_rx;
		return 0;
	}
	if (ip_da->sw_rx_count == HFI2_ROCE_SW_RX_IPV4_MAX)
		return -ENOSPC;

	for (i = 0; i < HFI2_ROCE_SW_RX_IPV4_MAX; i++)
		if (!refcount_read(&ip_da->sw_rx[i].refs))
			break;
	if (WARN_ON_ONCE(i == HFI2_ROCE_SW_RX_IPV4_MAX))
		return -ENOSPC;

	sw_rx = &ip_da->sw_rx[i];
	sw_rx->ipv4 = ipv4;
	refcount_set(&sw_rx->refs, 1);
	ip_da->sw_rx_count++;
	*entry = sw_rx;
	return 0;
}

static void hfi2_roce_sw_rx_ipv4_del(struct hfi2_roce_ip_da *ip_da,
					     struct hfi2_roce_sw_rx_ipv4 *entry)
{
	if (!refcount_dec_and_test(&entry->refs))
		return;

	entry->ipv4 = 0;
	ip_da->sw_rx_count--;
}

bool hfi2_roce_sw_rx_ipv4_match(struct hfi2_devdata *dd, __be32 ipv4)
{
	struct hfi2_roce_ip_da *ip_da = &dd->verbs_dev.roce_ip_da;
	unsigned int seq;
	bool match;
	u8 count;
	u8 i;

	/* A free slot holds 0.0.0.0; never let it match */
	if (!ipv4 || !READ_ONCE(ip_da->sw_rx_count))
		return false;

	do {
		seq = read_seqbegin(&ip_da->sw_rx_lock);
		match = false;
		count = READ_ONCE(ip_da->sw_rx_count);
		if (count)
			for (i = 0; i < HFI2_ROCE_SW_RX_IPV4_MAX; i++)
				if (READ_ONCE(ip_da->sw_rx[i].ipv4) == ipv4) {
					match = true;
					break;
				}
	} while (read_seqretry(&ip_da->sw_rx_lock, seq));

	return match;
}

static int hfi2_roce_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hfi2_devdata *dd = dd_from_ibdev(attr->device);
	struct hfi2_roce_ip_da *ip_da = &dd->verbs_dev.roce_ip_da;
	struct hfi2_roce_sw_rx_ipv4 *sw_rx;
	struct net_device *ndev;
	__be32 ipv4;
	bool netdev_owner = true;
	bool sw_placement = hfi2_bulksvc_roce_by_software(dd);
	int ret;

	if (rdma_gid_attr_network_type(attr) != RDMA_NETWORK_IPV4)
		return 0;

	if (roce_ip_da_netdev && *roce_ip_da_netdev) {
		rcu_read_lock();
		ndev = rcu_dereference(attr->ndev);
		netdev_owner = ndev && !strcmp(ndev->name, roce_ip_da_netdev);
		rcu_read_unlock();
	}

	memcpy(&ipv4, &attr->gid.raw[12], sizeof(ipv4));
	mutex_lock(&ip_da->lock);
	if (!refcount_read(&ip_da->refs)) {
		if (netdev_owner) {
			ip_da->ipv4 = ipv4;
			refcount_set(&ip_da->refs, 1);
			hfi2_write_csr(dd, CYR_EAL_VF_IP_DA_TABLE,
				  hfi2_roce_ip_da_value(ipv4, true));
			*context = ip_da;
			ret = 0;
			goto unlock;
		}
		if (!sw_placement) {
			ret = -ENOSPC;
			goto unlock;
		}
		write_seqlock_bh(&ip_da->sw_rx_lock);
		ret = hfi2_roce_sw_rx_ipv4_add(ip_da, ipv4, &sw_rx);
		write_sequnlock_bh(&ip_da->sw_rx_lock);
		if (!ret)
			*context = sw_rx;
		goto unlock;
	}
	if (ip_da->ipv4 == ipv4) {
		refcount_inc(&ip_da->refs);
		*context = ip_da;
		ret = 0;
		goto unlock;
	}
	if (!sw_placement) {
		ret = -ENOSPC;
		goto unlock;
	}

	write_seqlock_bh(&ip_da->sw_rx_lock);
	ret = hfi2_roce_sw_rx_ipv4_add(ip_da, ipv4, &sw_rx);
	write_sequnlock_bh(&ip_da->sw_rx_lock);
	if (!ret)
		*context = sw_rx;
unlock:
	mutex_unlock(&ip_da->lock);
	return ret;
}

static int hfi2_roce_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hfi2_devdata *dd = dd_from_ibdev(attr->device);
	struct hfi2_roce_ip_da *ip_da = &dd->verbs_dev.roce_ip_da;
	void *entry = *context;
	struct hfi2_roce_sw_rx_ipv4 *sw_rx = entry;
	int ret = 0;

	if (!entry)
		return 0;

	mutex_lock(&ip_da->lock);
	if (entry == ip_da) {
		if (!refcount_read(&ip_da->refs)) {
			WARN_ON_ONCE(1);
			ret = -EINVAL;
		} else if (refcount_dec_and_test(&ip_da->refs)) {
			hfi2_write_csr(dd, CYR_EAL_VF_IP_DA_TABLE,
				  hfi2_roce_ip_da_value(ip_da->ipv4, false));
			ip_da->ipv4 = 0;
		}
	} else if (sw_rx < ip_da->sw_rx ||
		   sw_rx >= ip_da->sw_rx + HFI2_ROCE_SW_RX_IPV4_MAX ||
		   !refcount_read(&sw_rx->refs)) {
		WARN_ON_ONCE(1);
		ret = -EINVAL;
	} else {
		write_seqlock_bh(&ip_da->sw_rx_lock);
		hfi2_roce_sw_rx_ipv4_del(ip_da, sw_rx);
		write_sequnlock_bh(&ip_da->sw_rx_lock);
	}
	if (!ret)
		*context = NULL;
	mutex_unlock(&ip_da->lock);

	return ret;
}

/*
 * Overlay over the rvt_dev_ops table installed by rvt_register_device().
 * Anything not listed here comes from rdmavt unchanged.
 */
/*
 * RoCE modify_device.  Only node_desc / sys_image_guid are supported.
 * Unlike the OPA modify_device we do NOT emit SMA traps -- the OPA
 * trap machinery (send_trap/cleanup_traps) is not initialised on an
 * Ethernet-mode device and dereferencing it faults.
 */
static int hfi2_roce_modify_device(struct ib_device *device,
				   int device_modify_mask,
				   struct ib_device_modify *device_modify)
{
	if (device_modify_mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID |
				   IB_DEVICE_MODIFY_NODE_DESC))
		return -EOPNOTSUPP;

	if (device_modify_mask & IB_DEVICE_MODIFY_NODE_DESC)
		memcpy(device->node_desc, device_modify->node_desc,
		       IB_DEVICE_NODE_DESC_MAX);

	if (device_modify_mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		hfi2_ib_hfi2_sys_image_guid =
			cpu_to_be64(device_modify->sys_image_guid);

	return 0;
}

static const struct ib_device_ops hfi2_roce_dev_ops = {
	.driver_id = RDMA_DRIVER_HFI2,

	/*
	 * rvt_register_device's check_support() requires port_groups and
	 * modify_device (the MISC / MODIFY_DEVICE capability groups) before
	 * it will call ib_register_device().  Use the RoCE (trap-free)
	 * modify_device and reuse the OPA path's cport sysfs groups.
	 */
	.modify_device = hfi2_roce_modify_device,
	.port_groups = hfi2_cport_attr_port_groups,

	.add_gid = hfi2_roce_add_gid,
	.del_gid = hfi2_roce_del_gid,
	.get_dev_fw_str = hfi2_cport_ib_get_dev_fw_str,
	.get_link_layer = hfi2_roce_get_link_layer,
	.get_netdev = hfi2_roce_get_netdev,
	.mmap = hfi2_mmap,
	.mmap_free = hfi2_mmap_free,
	.query_port = hfi2_roce_query_port,
};

/* ------------------------------------------------------------------------- */
/* rvt driver_f hooks bridged from the OPA path                              */
/* ------------------------------------------------------------------------- */

/*
 * RoCE flavour of rdmavt's driver_f.query_port_state.  rvt_query_port
 * has already filled in the OPA-irrelevant fields (sm_lid, pkeys,
 * etc.); all we need to do is the state/MTU/width/speed bit, which
 * is exactly what hfi2_roce_query_port does for the IB-core path.
 */
static int hfi2_roce_query_port_state(struct rvt_dev_info *rdi, u32 port_num,
				      struct ib_port_attr *props)
{
	return hfi2_roce_query_port(&rdi->ibdev, port_num, props);
}

static int hfi2_roce_shut_down_port(struct rvt_dev_info *rdi, u32 port_num)
{
	/*
	 * IB_PORT_SHUTDOWN modify_port comes from a privileged caller
	 * asking the port to be administratively brought down.  In
	 * Ethernet mode the netdev controls real link state; we
	 * accept the request and let the netdev path drive the wire.
	 */
	return 0;
}

static void hfi2_roce_cap_mask_chg(struct rvt_dev_info *rdi, u32 port_num)
{
	/* No SMA/PMA cap-mask gossip needed on RoCE. */
}

static int hfi2_roce_get_guid_be(struct rvt_dev_info *rdi,
				 struct rvt_ibport *rvp,
				 int guid_index, __be64 *guid)
{
	struct hfi2_devdata *dd = container_of(rdi, struct hfi2_devdata,
					       verbs_dev.rdi);
	struct hfi2_pportdata *ppd = &dd->pport[HFI2_PORT_IDX];
	__be64 g = 0;

	if (guid_index != 0)
		return -EINVAL;
	if (ppd->ndev)
		addrconf_addr_eui48((u8 *)&g, ppd->ndev->dev_addr);
	*guid = g;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* RoCE flavour of hfi2_fill_device_attr                                     */
/* ------------------------------------------------------------------------- */

static void hfi2_roce_fill_device_attr(struct hfi2_devdata *dd)
{
	struct rvt_dev_info *rdi = &dd->verbs_dev.rdi;

	memset(&rdi->dparms.props, 0, sizeof(rdi->dparms.props));

	rdi->dparms.props.fw_ver = 0;
	rdi->dparms.props.sys_image_guid = hfi2_ib_hfi2_sys_image_guid;
	rdi->dparms.props.device_cap_flags =
		IB_DEVICE_BAD_PKEY_CNTR | IB_DEVICE_BAD_QKEY_CNTR |
		IB_DEVICE_SHUTDOWN_PORT | IB_DEVICE_SYS_IMAGE_GUID |
		IB_DEVICE_RC_RNR_NAK_GEN | IB_DEVICE_PORT_ACTIVE_EVENT |
		IB_DEVICE_SRQ_RESIZE | IB_DEVICE_MEM_MGT_EXTENSIONS;
	rdi->dparms.props.kernel_cap_flags = 0;
	rdi->dparms.props.page_size_cap = PAGE_SIZE;
	rdi->dparms.props.vendor_id =
		dd->oui1 << 16 | dd->oui2 << 8 | dd->oui3;
	rdi->dparms.props.vendor_part_id = dd->pcidev->device;
	rdi->dparms.props.hw_ver = dd->minrev;
	rdi->dparms.props.max_mr_size = U64_MAX;
	rdi->dparms.props.max_fast_reg_page_list_len = UINT_MAX;
	rdi->dparms.props.max_qp = HFI2_ROCE_MAX_QPS;
	rdi->dparms.props.max_qp_wr =
		(HFI2_ROCE_MAX_QP_WRS >= HFI2_QP_WQE_INVALID ?
			HFI2_QP_WQE_INVALID - 1 : HFI2_ROCE_MAX_QP_WRS);
	rdi->dparms.props.max_send_sge = HFI2_ROCE_MAX_SGES;
	rdi->dparms.props.max_recv_sge = HFI2_ROCE_MAX_SGES;
	rdi->dparms.props.max_sge_rd = HFI2_ROCE_MAX_SGES;
	rdi->dparms.props.max_cq = HFI2_ROCE_MAX_CQS;
	rdi->dparms.props.max_ah = HFI2_ROCE_MAX_AHS;
	rdi->dparms.props.max_cqe = HFI2_ROCE_MAX_CQES;
	rdi->dparms.props.max_pd = HFI2_ROCE_MAX_PDS;
	rdi->dparms.props.max_qp_rd_atom = HFI2_MAX_RDMA_ATOMIC;
	rdi->dparms.props.max_qp_init_rd_atom = 255;
	rdi->dparms.props.max_srq = HFI2_ROCE_MAX_SRQS;
	rdi->dparms.props.max_srq_wr = HFI2_ROCE_MAX_SRQ_WRS;
	rdi->dparms.props.max_srq_sge = HFI2_ROCE_MAX_SRQ_SGES;
	rdi->dparms.props.atomic_cap = IB_ATOMIC_GLOB;
	rdi->dparms.props.max_pkeys = 1;
	rdi->dparms.props.max_mcast_grp = HFI2_ROCE_MAX_MCAST_GRPS;
	rdi->dparms.props.max_mcast_qp_attach =
		HFI2_ROCE_MAX_MCAST_QP_ATTACHED;
	rdi->dparms.props.max_total_mcast_qp_attach =
		rdi->dparms.props.max_mcast_qp_attach *
		rdi->dparms.props.max_mcast_grp;
}

/*
 * mem_timer fires from rdmavt's MR-mem-spillover path on the OPA
 * side.  RoCE has no producer for that today, but rdmavt expects a
 * usable timer to be set up before verbs_txreq_init() runs (the OPA
 * path passes mem_timer() from verbs.c, which derefs OPA-only state).
 * Use a no-op with a one-shot warn so an unexpected fire is loud but
 * does not oops the kernel.  When/if the RoCE path actually needs
 * mem-spillover handling this is the seam to extend.
 */
static void hfi2_roce_mem_timer(struct timer_list *t)
{
	WARN_ONCE(1,
		  "hfi2: mem_timer fired in RoCE mode; no producer expected\n");
}

/* ------------------------------------------------------------------------- */
/* Registration entry points                                                 */
/* ------------------------------------------------------------------------- */

int hfi2_register_roce_ib_device(struct hfi2_devdata *dd)
{
	struct hfi2_ibdev *dev = &dd->verbs_dev;
	struct ib_device *ibdev = &dev->rdi.ibdev;
	struct hfi2_pportdata *ppd;
	unsigned int i;
	int ret;

	ppd = &dd->pport[HFI2_PORT_IDX];
	if (!ppd->ndev) {
		dd_dev_err(dd,
			   "RoCE register: no netdev on port %d (cne_probe failed?)\n",
			   HFI2_PORT_IDX);
		return -ENODEV;
	}

	/*
	 * Mirror the OPA path's verbs-side bookkeeping; rvt expects
	 * mem_timer / txwait / memwait to be initialised before
	 * verbs_txreq_init runs.
	 */
	timer_setup(&dev->mem_timer, hfi2_roce_mem_timer, 0);
	mutex_init(&dev->roce_ip_da.lock);
	refcount_set(&dev->roce_ip_da.refs, 0);
	seqlock_init(&dev->roce_ip_da.sw_rx_lock);
	dev->roce_ip_da.ipv4 = 0;
	seqlock_init(&dev->iowait_lock);
	seqlock_init(&dev->txwait_lock);
	INIT_LIST_HEAD(&dev->txwait);
	INIT_LIST_HEAD(&dev->memwait);

	ret = hfi2_verbs_txreq_init(dev);
	if (ret)
		return ret;

	/*
	 * Use the netdev's permanent address as the node GUID.  This
	 * matches what other RoCE drivers do and gives us a stable
	 * GUID without needing the OPA GUID-index machinery.
	 */
	ibdev->phys_port_cnt = dd->num_pports;
	ibdev->dev.parent = &dd->pcidev->dev;
	addrconf_addr_eui48((u8 *)&ibdev->node_guid, ppd->ndev->dev_addr);

	/*
	 * sys_image_guid defaults to the node GUID (same as the OPA path).
	 * Not guaranteed unique across a mixed-device host, but far better
	 * than an all-zero GUID in ibstat / ibv_devinfo.  Must be set before
	 * hfi2_roce_fill_device_attr(), which snapshots it into dparms.props.
	 */
	if (!hfi2_ib_hfi2_sys_image_guid)
		hfi2_ib_hfi2_sys_image_guid = ibdev->node_guid;

	if (IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS))
		ibdev->driver_def = hfi2_ib_defs;

	ib_set_device_ops(ibdev, &hfi2_roce_dev_ops);

	strscpy(ibdev->node_desc, init_utsname()->nodename,
		sizeof(ibdev->node_desc));

	/*
	 * Fill in rvt info object.  Most fields parallel the OPA path
	 * (queue depths, lkey table, comp-vector mapping); RoCE-only
	 * differences are core_cap_flags, max_mad_size, the RoCE-bounded
	 * alloc_qpn callback, and the RoCE-flavoured driver_f hooks.
	 */
	dd->verbs_dev.rdi.driver_f.get_pci_dev = hfi2_get_pci_dev;
	dd->verbs_dev.rdi.driver_f.check_ah = hfi2_roce_check_ah;
	dd->verbs_dev.rdi.driver_f.notify_new_ah = hfi2_roce_notify_new_ah;
	dd->verbs_dev.rdi.driver_f.get_guid_be = hfi2_roce_get_guid_be;
	dd->verbs_dev.rdi.driver_f.query_port_state = hfi2_roce_query_port_state;
	dd->verbs_dev.rdi.driver_f.shut_down_port = hfi2_roce_shut_down_port;
	dd->verbs_dev.rdi.driver_f.cap_mask_chg = hfi2_roce_cap_mask_chg;

	hfi2_roce_fill_device_attr(dd);

	dd->verbs_dev.rdi.dparms.qp_table_size = HFI2_ROCE_QP_TABLE_SIZE;
	dd->verbs_dev.rdi.dparms.qpn_start = 0;
	dd->verbs_dev.rdi.dparms.qpn_inc = 1;
	/*
	 * The RIF table indexes on QP[10:0], so a QPN stride of two would leave
	 * bit 0 constant and half its 2048 rows unreachable.  On this
	 * personality qos_shift feeds nothing but that stride - the send-context
	 * and SDMA selectors read ppd->qos_shift instead - so all it bought was
	 * stepping over the GSI QPN.  Reserve QPN 1 explicitly and let the
	 * allocator step by one.
	 */
	dd->verbs_dev.rdi.dparms.qos_shift = 0;
	dd->verbs_dev.rdi.dparms.qpn_res_start = 0;
	dd->verbs_dev.rdi.dparms.qpn_res_end = 1;
	dd->verbs_dev.rdi.dparms.max_rdma_atomic = HFI2_MAX_RDMA_ATOMIC;
	dd->verbs_dev.rdi.dparms.psn_mask = 0xFFFFFF; /* RoCEv2 24-bit PSN */
	dd->verbs_dev.rdi.dparms.psn_shift = 8;
	dd->verbs_dev.rdi.dparms.psn_modify_mask = 0xFFFFFF;
	/* QP1 MADs are carried by the RoCE UD path in dms_roce.c. */
	dd->verbs_dev.rdi.dparms.core_cap_flags =
		RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	dd->verbs_dev.rdi.dparms.max_mad_size = IB_MGMT_MAD_SIZE;

	dd->verbs_dev.rdi.driver_f.alloc_qpn = hfi2_roce_alloc_qpn;
	dd->verbs_dev.rdi.driver_f.qp_priv_alloc = hfi2_roce_qp_priv_alloc;
	dd->verbs_dev.rdi.driver_f.qp_priv_init = hfi2_roce_qp_priv_init;
	dd->verbs_dev.rdi.driver_f.qp_priv_free = hfi2_roce_qp_priv_free;
	dd->verbs_dev.rdi.driver_f.free_all_qps = hfi2_roce_free_all_qps;
	dd->verbs_dev.rdi.driver_f.quiesce_internal_mrs =
		hfi2_dms_roce_quiesce_internal_mrs;
	dd->verbs_dev.rdi.driver_f.release_internal_mrs =
		hfi2_dms_roce_release_internal_mrs;
	dd->verbs_dev.rdi.driver_f.notify_qp_reset = hfi2_roce_notify_qp_reset;
	dd->verbs_dev.rdi.driver_f.do_send = hfi2_roce_do_send_from_rvt;
	dd->verbs_dev.rdi.driver_f.schedule_send = hfi2_roce_schedule_send;
	dd->verbs_dev.rdi.driver_f.schedule_send_no_lock =
		hfi2_roce_schedule_send_no_lock;
	dd->verbs_dev.rdi.driver_f.get_pmtu_from_attr =
		hfi2_roce_get_pmtu_from_attr;
	dd->verbs_dev.rdi.driver_f.notify_error_qp = hfi2_roce_notify_error_qp;
	dd->verbs_dev.rdi.driver_f.flush_qp_waiters =
		hfi2_roce_flush_qp_waiters;
	dd->verbs_dev.rdi.driver_f.stop_send_queue = hfi2_roce_stop_send_queue;
	dd->verbs_dev.rdi.driver_f.quiesce_qp = hfi2_roce_quiesce_qp;
	dd->verbs_dev.rdi.driver_f.mtu_from_qp = hfi2_roce_mtu_from_qp;
	dd->verbs_dev.rdi.driver_f.mtu_to_path_mtu = hfi2_roce_mtu_to_path_mtu;
	dd->verbs_dev.rdi.driver_f.check_modify_qp = hfi2_roce_check_modify_qp;
	dd->verbs_dev.rdi.driver_f.modify_qp = hfi2_roce_modify_qp;
	dd->verbs_dev.rdi.driver_f.notify_restart_rc =
		hfi2_roce_notify_restart_rc;
	dd->verbs_dev.rdi.driver_f.setup_wqe = hfi2_roce_setup_wqe;
	dd->verbs_dev.rdi.driver_f.cleanup_reg_mr = hfi2_roce_kmr_cleanup_reg;
	dd->verbs_dev.rdi.driver_f.cleanup_local_inv = hfi2_roce_cleanup_local_inv;
	dd->verbs_dev.rdi.driver_f.comp_vect_cpu_lookup =
		hfi2_comp_vect_mappings_lookup;
	dd->verbs_dev.rdi.driver_f.alloc_ucontext = hfi2_alloc_ucontext;
	dd->verbs_dev.rdi.driver_f.dealloc_ucontext = hfi2_dealloc_ucontext;

	/*
	 * FastReg and LOCAL_INV cannot sleep under s_hlock. Defer donor
	 * mapping; user registration binds PASIDs and mr_priv_free releases
	 * them.
	 */
	dd->verbs_dev.rdi.driver_f.mr_priv_alloc = hfi2_roce_mr_priv_alloc;
	dd->verbs_dev.rdi.driver_f.mr_priv_free = hfi2_roce_mr_priv_free;
	dd->verbs_dev.rdi.driver_f.notify_mr_pages_set =
		hfi2_roce_notify_mr_pages_set;
	dd->verbs_dev.rdi.driver_f.notify_register_mr =
		hfi2_roce_notify_register_mr;
	dd->verbs_dev.rdi.driver_f.fast_reg_mr = hfi2_roce_fast_reg_mr;
	dd->verbs_dev.rdi.driver_f.notify_unregister_mr =
		hfi2_roce_notify_unregister_mr;
	dd->verbs_dev.rdi.driver_f.dmabuf_memcpy = hfi2_dmabuf_memcpy;

	/* Completion queue */
	dd->verbs_dev.rdi.ibdev.num_comp_vectors = dd->comp_vect_possible_cpus;
	dd->verbs_dev.rdi.dparms.node = dd->node;

	/* Misc settings */
	dd->verbs_dev.rdi.flags = 0; /* Let rdmavt handle it all */
	dd->verbs_dev.rdi.dparms.lkey_table_size = HFI2_ROCE_LKEY_TABLE_SIZE;
	dd->verbs_dev.rdi.dparms.nports = dd->num_pports;
	dd->verbs_dev.rdi.dparms.npkeys = 1;
	dd->verbs_dev.rdi.dparms.sge_copy_mode = HFI2_ROCE_SGE_COPY_MODE;
	dd->verbs_dev.rdi.dparms.max_inline_data = 256;
	dd->verbs_dev.rdi.dparms.wss_threshold = HFI2_ROCE_WSS_THRESHOLD;
	dd->verbs_dev.rdi.dparms.wss_clean_period = HFI2_ROCE_WSS_CLEAN_PERIOD;
	dd->verbs_dev.rdi.dparms.reserved_operations = 1;
	/* nvme-rdma tears down 128 FastReg MRs per queue */
	dd->verbs_dev.rdi.dparms.async_kernel_mr_dereg = true;
	dd->verbs_dev.rdi.dparms.extra_rdma_atomic = 0;

	/* Post-send / opcode tables (shared with OPA — opcodes are common). */
	dd->verbs_dev.rdi.post_parms = hfi2_post_parms;
	dd->verbs_dev.rdi.wc_opcode = hfi2_ib_hfi2_wc_opcode;

	/*
	 * Initialise per-port rvt state.  rdmavt requires this even
	 * for our minimal setup; without it rvt_query_port would
	 * dereference a NULL rvp.
	 */
	for (i = 0; i < dd->num_pports; i++) {
		dd->pport[i].pkeys[0] = IB_DEFAULT_PKEY_FULL;
		rvt_init_port(&dd->verbs_dev.rdi,
			      &dd->pport[i].ibport_data.rvp,
			      i,
			      dd->pport[i].pkeys);
	}

	ret = ib_device_set_netdev(ibdev, ppd->ndev, 1);
	if (ret) {
		dd_dev_err(dd, "RoCE register: ib_device_set_netdev failed: %d\n",
			   ret);
		goto err_txreq;
	}

	ret = rvt_register_device(&dd->verbs_dev.rdi, dd->pcidev);
	if (ret) {
		dd_dev_err(dd, "RoCE register: rvt_register_device failed: %d\n",
			   ret);
		goto err_txreq;
	}

	dev->roce_registered = true;
	dd_dev_info(dd, "RoCE IB device registered (link_layer=Ethernet)\n");
	return 0;

err_txreq:
	hfi2_verbs_txreq_exit(dev);
	return ret;
}

int hfi2_roce_refresh_netdev(struct hfi2_devdata *dd)
{
	struct ib_device *ibdev = &dd->verbs_dev.rdi.ibdev;
	struct hfi2_pportdata *ppd = &dd->pport[HFI2_PORT_IDX];
	int ret;

	/*
	 * The reset/EEH path (hfi2_init(dd, 1)) frees and recreates
	 * ppd->ndev via cne_remove()+cne_probe() without touching the IB
	 * device.  Re-point the RoCE ib_device at the new netdev so its
	 * netdev_tracker drops the freed ndev and the IB core repopulates
	 * the GID table (ib_device_set_netdev emits ATTACH/DETACH events).
	 */
	if (!dd->verbs_dev.roce_registered)
		return 0;
	if (!ppd->ndev)
		return -ENODEV;

	ret = ib_device_set_netdev(ibdev, ppd->ndev, 1);
	if (ret) {
		dd_dev_err(dd, "RoCE: netdev refresh failed: %d\n", ret);
	} else {
		struct hfi2_roce_ip_da *ip_da = &dd->verbs_dev.roce_ip_da;

		mutex_lock(&ip_da->lock);
		if (refcount_read(&ip_da->refs) && (dd->flags & HFI2_PRESENT)) {
			/*
			 * A reset can clear the CAM while the GID table retains this
			 * reference, so reassert the cached address after refresh.
			 */
			hfi2_write_csr(dd, CYR_EAL_VF_IP_DA_TABLE,
				  hfi2_roce_ip_da_value(ip_da->ipv4, true));
		}
		mutex_unlock(&ip_da->lock);
	}

	return ret;
}

void hfi2_roce_disable(struct hfi2_devdata *dd)
{
	/*
	 * EAL treats a frame as RoCEv2 only when its IP destination matches
	 * the IP DA table, and only GID add programs that table.  With no
	 * RoCE device nothing adds a GID, but CSRs survive rmmod, so clear
	 * what an earlier RoCE load may have left: the IP DA entry, and the
	 * UDP 4791 destination-port entry bulksvc programs.
	 */
	hfi2_write_csr(dd, CYR_EAL_VF_IP_DA_TABLE, 0);
	hfi2_write_csr(dd, CYR_EAL_DESTINATION_PORT_TABLE, 0);
	dd_dev_info(dd, "RoCE disabled: no bulksvc (use_bulksvc=N); Ethernet only\n");
}

void hfi2_unregister_roce_ib_device(struct hfi2_devdata *dd)
{
	struct hfi2_ibdev *dev = &dd->verbs_dev;

	if (!dev->roce_registered) {
		hfi2_roce_kmr_donor_exit(dd);
		return;
	}
	dev->roce_registered = false;

	/*
	 * rvt_unregister_device() resets every QP and waits for its references.
	 * Keep the single bulksvc worker alive through that phase so a QP's
	 * terminal SDMA cookie can egress and be consumed before rvt_destroy_qp()
	 * waits for it.  Stop the worker only after unregister has drained QPs.
	 */
	rvt_unregister_device(&dev->rdi);
	hfi2_roce_kmr_donor_exit(dd);

	if (dd->bulksvc)
		hfi2_bulksvc_quiesce_thread(dd);

	if (WARN_ON(refcount_read(&dev->roce_ip_da.refs))) {
		hfi2_write_csr(dd, CYR_EAL_VF_IP_DA_TABLE,
			  hfi2_roce_ip_da_value(dev->roce_ip_da.ipv4, false));
		refcount_set(&dev->roce_ip_da.refs, 0);
		dev->roce_ip_da.ipv4 = 0;
	}
	if (WARN_ON(dev->roce_ip_da.sw_rx_count)) {
		write_seqlock_bh(&dev->roce_ip_da.sw_rx_lock);
		memset(dev->roce_ip_da.sw_rx, 0, sizeof(dev->roce_ip_da.sw_rx));
		dev->roce_ip_da.sw_rx_count = 0;
		write_sequnlock_bh(&dev->roce_ip_da.sw_rx_lock);
	}

	hfi2_bulksvc_drain_verbs_queues(dd);
	if (dd->bulksvc) {
		hfi2_bulksvc_flush_event_queue(dd->bulksvc);
		wait_event(dd->bulksvc->pending_user_info_destroys_wq,
			   atomic_read(&dd->bulksvc->pending_user_info_destroys) == 0);
	}

	timer_delete_sync(&dev->mem_timer);
	hfi2_verbs_txreq_exit(dev);

	dd_dev_info(dd, "RoCE IB device unregistered\n");
}
