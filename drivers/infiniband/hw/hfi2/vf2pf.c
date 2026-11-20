// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 *
 * SRIOV support for VFs making requests to PF0.
 */

#include "hfi2.h"
#include "chip.h"
#include "chip_gen.h"
#include "mad.h"
#include "sriov.h"
#include "vf2pf_int.h"
#include "eth_main.h"

#ifdef HFI_VF2PF_LOOPBACK
#include "vf2pf_lb.h"
#define HFI_VF2PF_LOOPBACK_CONFIG
#endif

/* TODO: this may not be for production */
static bool vf2pf_lb = true;

static uint vf2pf_to = 1;

#define VF2PF_FORCE_LB	/* set to force use of loopback vf2pf even if VFs are local */

#ifdef VF2PF_FORCE_LB
#define IS_LOCAL_VF(dd)		(!vf2pf_lb && !(dd)->is_vm)
#define IS_LOCAL_VDD(vdd)	(!vf2pf_lb && (vdd))
#else
#define IS_LOCAL_VF(dd)		(!(dd)->is_vm)
#define IS_LOCAL_VDD(vdd)	(vdd)
#endif

static struct vf2pf_devops vf2pf_nodev = { };

static struct vf2pf_devops *vf2pf_dev = &vf2pf_nodev;

/* for additional output to "hw_resources" */
int vf2pf_sysfs_emit_at(struct hfi2_devdata *dd, char *buf, int at)
{
	int off = at;

	/*
	 * Anything for vf2pf core goes here.
	 */

	if (vf2pf_dev->sysfs_emit_at)
		off += vf2pf_dev->sysfs_emit_at(dd, buf, off);

	return off - at;
}

/*
 * Allocate memory for a vf2pf message to transmit.
 * Returns pointer to allocation, to be used in kfree() and
 * passing to vf2pf_devops.send().
 *
 * On success,
 * 'msg' is set to struct vf2pf_hdr (vf2pf payload) part of allocation,
 *
 * buffer contents/structure:
 *
 * ret->	struct vf2pf_prefix
 *		-align u64-
 *		[opt: implimentation headers]
 * msg->	struct vf2pf_hdr
 *		variable payload...
 */
static void *msg_alloc(struct hfi2_devdata *dd, struct vf2pf_hdr **msg)
{
	if (!vf2pf_dev->msg_alloc)
		return NULL;

	return vf2pf_dev->msg_alloc(dd, msg, 0);
}
static void *msg_alloc_len(struct hfi2_devdata *dd, struct vf2pf_hdr **msg, int len)
{
	if (!vf2pf_dev->msg_alloc)
		return NULL;

	return vf2pf_dev->msg_alloc(dd, msg, len);
}

/*
 * Send a message to 'si'.
 *
 * 'buf' is opaque pointer returned by msg_alloc().
 * header part (vf2pf_dev->get_msg(dd, buf)) must have been filled out.
 * caller may kfree on return.
 */
static int vf2pf_send(struct hfi2_devdata *dd, u8 si, void *buf)
{
	struct vf2pf_hdr *hdr;

	if (!vf2pf_dev->send || !vf2pf_dev->get_msg)
		return -ENXIO;
	if (!buf)
		return -EINVAL;

	hdr = vf2pf_dev->get_msg(dd, buf);
	if (!(hdr->op & VF2PF_OP_RESP)) {
		hdr->seq = (u32)atomic_inc_return(&dd->vf2pf_seq);
		dd_dev_dbg(dd,
			"VF2PF SEND VF=%d op=%u si=%u tid=%u seq=%u len=%u\n",
			dd->is_vf ? dd->rsrcs.si_idx : -1, hdr->op, si, hdr->tid, hdr->seq,
			hdr->len);
	}

	return vf2pf_dev->send(dd, si, buf);
}

/*
 * overwrites 'buf' with response.
 * caller acquired 'buf' via msg_alloc().
 * on success, 'buf' contains the response (caller kfrees when done).
 */
static int vf2pf_send_recv(struct hfi2_devdata *dd, u8 si, void *buf, long to)
{
	struct vf2pf_prefix *pfx = buf;
	bool track = !dd->is_vf && si;
	struct vf2pf_hdr *hdr;
	int ret;

	if (!vf2pf_dev->set_tid || !vf2pf_dev->get_msg)
		return -EINVAL;

	if (to > 0) {
		pfx->type = VF2PF_PFX_TYPE_WAIT;
		init_waitqueue_head(&pfx->wait);
	} else {
		to = -to;
		pfx->type = VF2PF_PFX_TYPE_SEMA;
		sema_init(&pfx->sema, 0);
	}
	hdr = vf2pf_dev->get_msg(dd, buf);
	hdr->tid = vf2pf_dev->set_tid(dd, buf);

	if (track) {
		/*
		 * Checked under the lock so that a request is either on the list
		 * when a stop aborts the SI's waiters or sees sync_done cleared.
		 */
		spin_lock(&dd->vf2pf_waiters_lock);
		if (!(atomic_read(&dd->rsrcs.sync_done) & BIT(si))) {
			spin_unlock(&dd->vf2pf_waiters_lock);
			vf2pf_dev->get_tid(dd, hdr->tid); /* discard tid */
			return -ENXIO;
		}
		pfx->wsi = si;
		list_add_tail(&pfx->wnode, &dd->vf2pf_waiters);
		spin_unlock(&dd->vf2pf_waiters_lock);
	}

	ret = vf2pf_send(dd, si, buf);
	if (ret) {
		if (track) {
			spin_lock(&dd->vf2pf_waiters_lock);
			list_del(&pfx->wnode);
			spin_unlock(&dd->vf2pf_waiters_lock);
		}
		vf2pf_dev->get_tid(dd, hdr->tid); /* discard tid */
		return ret;
	}

	if (pfx->type == VF2PF_PFX_TYPE_WAIT) {
		if (vf2pf_dev->rcv_wait) {
			ret = vf2pf_dev->rcv_wait(dd, buf, to);
		} else {
			ret = wait_event_timeout(pfx->wait,
						 (hdr->op & VF2PF_OP_RESP), to);
			ret = ret ? 0 : -ETIME; /* convert residual time  to error */
		}
	} else {
		ret = down_timeout(&pfx->sema, to);
	}
	if (track) {
		/* also keeps a concurrent abort from touching @buf after we return */
		spin_lock(&dd->vf2pf_waiters_lock);
		list_del(&pfx->wnode);
		spin_unlock(&dd->vf2pf_waiters_lock);
	}
	if (ret)	/* timeout or other error */
		vf2pf_dev->get_tid(dd, hdr->tid); /* discard tid */

	return ret;
}

/*
 * Fail the PF0 requests still waiting on @si's VF. get_tid() is destructive,
 * so it arbitrates with vf2pf_rsp_msg(): whoever erases the tid completes
 * the request.
 */
static void vf2pf_abort_waiters(struct hfi2_devdata *dd, u8 si)
{
	struct vf2pf_prefix *pfx;

	spin_lock(&dd->vf2pf_waiters_lock);
	list_for_each_entry(pfx, &dd->vf2pf_waiters, wnode) {
		struct vf2pf_hdr *whdr;

		if (pfx->wsi != si)
			continue;
		whdr = vf2pf_dev->get_msg(dd, pfx);
		if (!vf2pf_dev->get_tid(dd, whdr->tid))
			continue;
		whdr->status = -ENXIO;
		smp_wmb(); /* status before the response flag the waiter tests */
		whdr->op |= VF2PF_OP_RESP;
		if (pfx->type == VF2PF_PFX_TYPE_WAIT)
			wake_up(&pfx->wait);
		else
			up(&pfx->sema);
	}
	spin_unlock(&dd->vf2pf_waiters_lock);
}

/*
 * VF call to PF0 to setup dd->rsrcs.
 */
int vf2pf_get_config(struct hfi2_devdata *dd, struct hfi2_devrsrcs *out, int si)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_getcfg_msg *msg;
	void *mem;
	int ret;

	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		ret = hfi2_sriov_get_config(pdd, out, si);
		if (ret)
			return ret;
		dd->base_guid = pdd->base_guid;
		dd->revision = pdd->revision;
		dd->hfi2_id = pdd->hfi2_id;
		dd->icode = pdd->icode;
		dd->irev = pdd->irev;
		dd->cport_ver = pdd->cport_ver;
		return 0;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_getcfg_msg *)hdr;
	msg->hdr.op = VF2PF_GET_CFG;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->si = si;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	if (ret)
		goto out;
	memcpy(out, &msg->rsrcs, sizeof(*out));
	dd->base_guid = msg->base_guid;
	dd->revision = msg->revision;
	dd->hfi2_id = msg->hfi2_id;
	dd->icode = msg->icode;
	dd->irev = msg->irev;
	dd->cport_ver = msg->cport_ver;
out:
	kfree(mem);
	return ret;
}

int vf2pf_get_eth_config(struct hfi2_devdata *dd,
			 u16 vf,
			 struct ifla_vf_info *ivf,
			 u8 *pf_set_mac)
{
        struct vf2pf_hdr *hdr;
        struct vf2pf_get_ethcfg_msg *msg;
        void *mem;
        int ret;

        if (!dd->is_vf || dd->params->chip_type != CHIP_CYR)
                return -EINVAL;
        if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pfdd = pci_get_drvdata(dd->pcidev->physfn);
		struct hfi2_pportdata *ppd;
		struct ether_device *edev;

		if (!pfdd)
			return -EINVAL;
		ppd = pfdd->pport;
		if (!ppd || !ppd->ndev)
			return -ENODEV;
		if (vf >= CN_MAX_VFS)
			return -EINVAL;
		edev = netdev_priv(ppd->ndev);

		ether_addr_copy(ivf->mac, edev->vf[vf].mac);
		ivf->spoofchk = edev->vf[vf].spoofchk;
		ivf->trusted = edev->vf[vf].trusted;
		ivf->vlan = edev->vf[vf].vid;
		ivf->qos = edev->vf[vf].qos;
		*pf_set_mac = edev->vf[vf].pf_set_mac;

                return 0;
        }
        mem = msg_alloc(dd, &hdr);
        if (!mem)
                return -ENOMEM;
        msg = (struct vf2pf_get_ethcfg_msg *)hdr;
        msg->hdr.op = VF2PF_GET_ETH_CFG;
        msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->vf = vf;
        ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
        if (!ret)
                ret = hdr->status;
        if (ret)
                goto out;
	u64_to_ether_addr(msg->mac, ivf->mac);
	ivf->spoofchk = msg->spoofchk;
	ivf->trusted = msg->trusted;
	ivf->vlan = msg->vlan;
	ivf->qos = msg->qos;
	*pf_set_mac = msg->pf_set_mac;
out:
        kfree(mem);
        return ret;
}

static int do_asgnrs_msg(struct hfi2_devdata *dd, u8 op, struct hfi2_devrsrcs *vfr)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_asgnrs_msg *msg;
	void *mem;
	int ret;

	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_asgnrs_msg *)hdr;
	msg->hdr.op = op;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	memcpy(&msg->rsrcs, vfr, sizeof(msg->rsrcs));
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	kfree(mem);
	return ret;
}

/*
 * VF call to PF0 to assign chip resources to this SI.
 * May include additional early setup.
 */
int vf2pf_assign_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *vfr)
{
	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi2_sriov_assign_rsrcs(pdd, vfr);
	}
	return do_asgnrs_msg(dd, VF2PF_ASGN_RES, vfr);
}

/*
 * VF call to PF0 to release chip resources.
 * May include other late shutdown.
 */
int vf2pf_free_rsrcs(struct hfi2_devdata *dd, struct hfi2_devrsrcs *vfr)
{
	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		hfi2_sriov_free_rsrcs(pdd, vfr);
		return 0;
	}
	return do_asgnrs_msg(dd, VF2PF_FREE_RES, vfr);
}

int vf2pf_priv_reg_op(struct hfi2_devdata *dd, int pidx, u32 ctxt, int type,
		      enum preg_op op, u64 arg)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_pregop_msg *msg;
	void *mem;
	int ret;

	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi2_priv_reg_op(pdd, pidx, ctxt, type, op, arg);
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_pregop_msg *)hdr;
	msg->hdr.op = VF2PF_PREG_OP;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->pidx = pidx;
	msg->ctxt = ctxt;
	msg->type = type;
	msg->op = op;
	msg->arg = arg;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	kfree(mem);
	return ret;
}

/* Called for PF0 and VFs */
u64 pf0_read_csr(struct hfi2_devdata *dd, enum csr_type type, u32 off,
		 u16 ctxt, u8 pidx_eng)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_readcsr_msg *msg;
	void *mem;
	u64 reg = ~(u64)0; /* error */
	int ret;

	if (!dd->is_vf)
		return read_csr_type(dd, type, off, ctxt, pidx_eng);
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return read_csr_type(pdd, type, off, ctxt, pidx_eng);
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return reg;
	msg = (struct vf2pf_readcsr_msg *)hdr;
	msg->hdr.op = VF2PF_RCSR_OP;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->off = off + dd->params->txe_eport_stride * pidx_eng + 8 * ctxt;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret && !hdr->status)
		reg = msg->reg;
	kfree(mem);
	return reg;
}

/* Only called for VFs */
u64 pf0_rctxt_ctrl_op(struct hfi2_devdata *dd, u16 ctxt, unsigned int op)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_rcctrl_msg *msg;
	void *mem;
	u64 reg = ~(u64)0; /* error */
	int ret;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi2_rctxt_ctrl_op(pdd, ctxt, op);
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return reg;
	msg = (struct vf2pf_rcctrl_msg *)hdr;
	msg->hdr.op = VF2PF_RCCTRL_OP;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->ctxt = ctxt;
	msg->op = op;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret && !hdr->status)
		reg = msg->reg;
	kfree(mem);
	return reg;
}

void vf2pf_tid_config(struct hfi2_devdata *dd, int pidx, u16 ctxt,
		      u32 eager_base, u16 alloced,
		      u32 expected_base, u32 expected_count)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_tidcfg_msg *msg;
	void *mem;
	int ret;

	if (!dd->is_vf)
		return; /*should never happen */
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		pdd->params->set_port_tid_config(pdd, pidx, ctxt, eager_base, alloced,
						 expected_base, expected_count);
		return;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem) {
		dd_dev_err(dd, "Failed to allocate vf2pf message buffer for tid_config\n");
		return;
	}
	msg = (struct vf2pf_tidcfg_msg *)hdr;
	msg->hdr.op = VF2PF_TIDCFG_OP;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->pidx = pidx;
	msg->ctxt = ctxt;
	msg->alloced = alloced;
	msg->egr_base = eager_base;
	msg->exp_base = expected_base;
	msg->exp_cnt = expected_count;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	kfree(mem);
}

int vf2pf_init_rxe_rsm(struct hfi2_devdata *dd)
{
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi2_init_rxe_rsm(pdd, &dd->rsrcs);
	}
	return do_asgnrs_msg(dd, VF2PF_RXERSM_OP, &dd->rsrcs);
}

/**
 * vf2pf_get_qp_map - VF-side lookup of the receive context for a qp map entry
 * @dd: device data
 * @pidx: port index
 * @idx: qp map table index to read
 * @rcd_idx: on success, set to the receive context index for @idx
 *
 * Resolves the qp map entry either locally (when the VF and PF share the same
 * driver instance) or by issuing a VF2PF request to the PF, storing the
 * resulting receive context index in *@rcd_idx.
 *
 * Return: 0 on success with *@rcd_idx set, or a negative errno on failure.
 * *@rcd_idx is left unchanged on failure.
 */
int vf2pf_get_qp_map(struct hfi2_devdata *dd, int pidx, u16 idx, u16 *rcd_idx)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_qpmap_msg *msg;
	void *mem;
	int ret;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return hfi2_get_qp_map(pdd->pport + pidx, idx, rcd_idx);
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_qpmap_msg *)hdr;
	msg->hdr.op = VF2PF_QPMAP_OP;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->pidx = pidx;
	msg->idx = idx;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	if (!ret)
		*rcd_idx = msg->res;
	kfree(mem);
	return ret;
}

static void pf2vf_fill_portcfg(struct hfi2_pportdata *ppd,
			       struct vf2pf_portcfg *msg)
{
	struct hfi2_ibport *ibp = &ppd->ibport_data;
	unsigned int seq;
	int i;

	/* read the tag first: the fields below can then only be newer than it */
	msg->generation = portcfg_gen_read(ppd);
	msg->pidx = ppd->hw_pidx;
	do {
		seq = read_seqbegin(&ppd->sc2vl_lock);
		memcpy(msg->sc2vl, ppd->sc2vl, sizeof(msg->sc2vl));
	} while (read_seqretry(&ppd->sc2vl_lock, seq));
	memcpy(msg->sl2sc, ibp->sl_to_sc, sizeof(msg->sl2sc));
	memcpy(msg->sc2sl, ibp->sc_to_sl, sizeof(msg->sc2sl));
	memset(msg->mtu, 0, sizeof(msg->mtu));
	for (i = 0; i < ARRAY_SIZE(ppd->vld); i++)
		msg->mtu[i] = ppd->vld[i].mtu;
	msg->ibmtu = ppd->ibmtu;
	msg->ibmaxlen = ppd->ibmaxlen;
	msg->vls_operational = ppd->vls_operational;
	msg->actual_vls_operational = ppd->actual_vls_operational;
	msg->gid_prefix = ibp->rvp.gid_prefix;
	msg->link_width_active = ppd->link_width_active;
	msg->link_speed_active = ppd->link_speed_active;
	msg->sm_lid = ibp->rvp.sm_lid;
	msg->sm_sl = ibp->rvp.sm_sl;
	msg->lid_block_mask = ppd->lid_block_mask;
	msg->neighbor_type = ppd->neighbor_type;
	msg->sm_trap_qp = ppd->sm_trap_qp;
	msg->subnet_timeout = ibp->rvp.subnet_timeout;
}

static void vf_apply_portcfg_msg(struct hfi2_pportdata *ppd,
				 struct vf2pf_portcfg *msg)
{
	struct hfi2_ibport *ibp = &ppd->ibport_data;
	int i;

	hfi2_update_sc2vlt(ppd, msg->sc2vl, false);
	hfi2_apply_sl_to_sc(ibp, msg->sl2sc);
	memcpy(ibp->sc_to_sl, msg->sc2sl, sizeof(ibp->sc_to_sl));
	for (i = 0; i < ARRAY_SIZE(ppd->vld); i++)
		ppd->vld[i].mtu = msg->mtu[i];
	ppd->ibmtu = msg->ibmtu;
	ppd->ibmaxlen = msg->ibmaxlen;
	ppd->vls_operational = msg->vls_operational;
	ppd->actual_vls_operational = msg->actual_vls_operational;
	if (ibp->rvp.gid_prefix != msg->gid_prefix) {
		ibp->rvp.gid_prefix = msg->gid_prefix;
		hfi2_dispatch_event(ppd, IB_EVENT_GID_CHANGE);
		hfi2_dispatch_event(ppd, IB_EVENT_CLIENT_REREGISTER);
	}
	ppd->link_width_active = msg->link_width_active;
	ppd->link_speed_active = msg->link_speed_active;
	hfi2_vport_set_sm(ppd, msg->sm_lid, msg->sm_sl);
	ppd->lid_block_mask = msg->lid_block_mask;
	ppd->lid_block_programmed = true;
	ppd->neighbor_type = msg->neighbor_type;
	ppd->sm_trap_qp = msg->sm_trap_qp;
	ibp->rvp.subnet_timeout = msg->subnet_timeout;
	portcfg_gen_set(ppd, msg->generation);
}

int vf_apply_portcfg(struct hfi2_devdata *dd, u8 pidx)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_get_portcfg_msg *req;
	struct vf2pf_portcfg local;
	struct hfi2_pportdata *ppd;
	void *mem;
	int ret;

	if (!dd->is_vf || pidx >= dd->num_pports)
		return -EINVAL;
	ppd = &dd->pport[pidx];
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		if (!pdd || pidx >= pdd->num_pports)
			return -ENODEV;
		pf2vf_fill_portcfg(&pdd->pport[pidx], &local);
		vf_apply_portcfg_msg(ppd, &local);
		return 0;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	req = (struct vf2pf_get_portcfg_msg *)hdr;
	req->hdr.op = VF2PF_GET_PORTCFG;
	req->hdr.len = sizeof(*req) - sizeof(*hdr);
	req->pidx = pidx;
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	if (!ret) {
		if (hdr->len != sizeof(struct vf2pf_portcfg) - sizeof(*hdr))
			ret = -EBADMSG;
		else
			vf_apply_portcfg_msg(ppd, (struct vf2pf_portcfg *)hdr);
	}
	kfree(mem);
	return ret;
}

void vf_apply_portcfg_work(struct work_struct *work)
{
	struct hfi2_pportdata *ppd = container_of(work, struct hfi2_pportdata,
						     portcfg_work);
	int ret;

	ret = vf_apply_portcfg(ppd->dd, ppd->hw_pidx);
	if (ret)
		ppd_dev_err(ppd, "Failed to apply PF port configuration (%d)\n", ret);
}

/*
 * The VF is untrusted, so take only the attribute payload and the status from
 * its reply.  The management header and routing fields of @smp stay as CPORT
 * sent them: the class selects where the payload lives, and the direction bit
 * and path fields steer the response.
 */
static void pf2vf_merge_vport_reply(struct opa_smp *smp,
				    const struct opa_smp *reply)
{
	struct opa_smp *rsp = (struct opa_smp *)reply;
	size_t dsz = opa_get_smp_data_size(smp);
	__be16 dir = smp->status & IB_SMP_DIRECTION;

	memcpy(opa_get_smp_data(smp), opa_get_smp_data(rsp), dsz);
	smp->status = (reply->status & ~IB_SMP_DIRECTION) | dir;
}

/*
 * Called on PF0 to have the VF owning @smp's VPort process the MAD. The
 * VF's attribute payload and status are merged back into @smp. Fails if the
 * VF is not up.
 */
int pf2vf_vport_mad(struct hfi2_pportdata *ppd, u8 si, struct opa_smp *smp)
{
	struct hfi2_devdata *dd = ppd->dd, *vdd;
	struct pci_dev *pdev = dd->pcidev, *vpdev;
	struct vf2pf_hdr *hdr;
	struct pf0_vportmad_msg *msg;
	void *mem;
	int ret;

	if (dd->is_vf || !si || si > HFI2_MAX_VPORT_VFS ||
	    si > dd->rsrcs.num_vfs) {
		return -EINVAL;
	}
	if (!(atomic_read(&dd->rsrcs.sync_done) & BIT(si)))
		return -ENXIO;

	vpdev = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
					    pdev->bus->number,
					    pci_iov_virtfn_devfn(pdev, si - 1));
	vdd = vpdev ? pci_get_drvdata(vpdev) : NULL;
	if (IS_LOCAL_VDD(vdd)) { /* must not be in VM... */
		ret = hfi2_vport_mad_vf(&vdd->pport[ppd->hw_pidx], smp);
		pci_dev_put(vpdev);
		return ret;
	}
	if (vpdev)
		pci_dev_put(vpdev);

	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct pf0_vportmad_msg *)hdr;
	msg->hdr.op = PF0_VPORT_MAD;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->pidx = ppd->hw_pidx;
	memcpy(&msg->smp, smp, sizeof(*smp));
	ret = vf2pf_send_recv(dd, si, mem, vf2pf_to * HZ);
	if (!ret)
		ret = hdr->status;
	if (!ret)
		pf2vf_merge_vport_reply(smp, &msg->smp);
	kfree(mem);
	return ret;
}

/*
 * Called on PF0 to give the VFs in @si_mask the node and port GUIDs configured
 * for them through set_vf_guid(). VFs that are down or have no configured
 * GUID are skipped; they pick the GUIDs up when they sync.
 */
int pf2vf_push_vport_guid(struct hfi2_pportdata *ppd, unsigned long si_mask)
{
	struct hfi2_devdata *dd = ppd->dd, *vdd;
	struct pci_dev *pdev = dd->pcidev, *vpdev;
	struct vf2pf_hdr *hdr;
	struct pf0_vportguids_msg *msg;
	unsigned long id;
	void *mem;
	int ret = 0, rc;

	if (dd->is_vf)
		return -EINVAL;

	si_mask &= atomic_read(&dd->rsrcs.sync_done);
	for_each_set_bit(id, &si_mask, min_t(int, dd->rsrcs.num_vfs,
					     HFI2_MAX_VPORT_VFS) + 1) {
		u64 node_guid, port_guid;

		if (!id || !(atomic_read(&dd->rsrcs.sync_done) & BIT(id)))
			continue;
		node_guid = READ_ONCE(ppd->vf_node_guid[id - 1]);
		port_guid = READ_ONCE(ppd->vf_port_guid[id - 1]);
		if (!node_guid && !port_guid)
			continue;

		vpdev = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
						    pdev->bus->number,
						    pci_iov_virtfn_devfn(pdev, id - 1));
		vdd = vpdev ? pci_get_drvdata(vpdev) : NULL;
		if (IS_LOCAL_VDD(vdd)) {
			hfi2_vport_set_guids(&vdd->pport[ppd->hw_pidx],
					     node_guid, port_guid);
			pci_dev_put(vpdev);
			continue;
		}
		if (vpdev)
			pci_dev_put(vpdev);

		mem = msg_alloc(dd, &hdr);
		if (!mem)
			return -ENOMEM;
		msg = (struct pf0_vportguids_msg *)hdr;
		msg->hdr.op = PF0_VPORT_GUIDS;
		msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
		msg->pidx = ppd->hw_pidx;
		msg->node_guid = node_guid;
		msg->port_guid = port_guid;
		rc = vf2pf_send_recv(dd, id, mem, vf2pf_to * HZ);
		if (!rc)
			rc = hdr->status;
		kfree(mem);
		if (rc) {
			dd_dev_warn(dd, "Failed to push GUIDs to %ld (%d)\n",
				    id, rc);
			ret = rc;
		}
	}
	return ret;
}

/* Returns the SI index of the VF that was assigned @lid, or 0 if none. */
int pf2vf_vport_lid_to_si(struct hfi2_pportdata *ppd, u32 lid)
{
	int i;

	if (!lid)
		return 0;
	for (i = 0; i < HFI2_MAX_VPORT_VFS; i++)
		if (READ_ONCE(ppd->vf_lid[i]) == lid)
			return i + 1;
	return 0;
}

/*
 * Forget the FM assigned state of a VF that is going away. The SI also stops
 * counting as synced so the push paths do not send to it and wait out
 * vf2pf_to for an answer that will never come.
 */
void pf2vf_vport_clear(struct hfi2_devdata *dd, u8 si)
{
	unsigned long flags;
	int i;

	if (!si || si > HFI2_MAX_VPORT_VFS)
		return;
	spin_lock_irqsave(&dd->sync_lock, flags);
	atomic_andnot(BIT(si), &dd->rsrcs.sync_pending);
	atomic_inc(&dd->sync_gen[si]);
	atomic_andnot(BIT(si), &dd->rsrcs.sync_done);
	spin_unlock_irqrestore(&dd->sync_lock, flags);
	vf2pf_abort_waiters(dd, si);
	for (i = 0; i < dd->num_pports; i++) {
		/*
		 * LID, state and the P_Key table are FM state; do not hand them
		 * to the next VF.  vf_pkey_lock pairs with the commit in
		 * cport_vport_mad(), which rechecks sync_gen under it.
		 */
		spin_lock(&dd->pport[i].vf_pkey_lock);
		WRITE_ONCE(dd->pport[i].vf_lid[si - 1], 0);
		WRITE_ONCE(dd->pport[i].vf_state[si - 1], 0);
		dd->pport[i].vf_pkey_blk_valid[si - 1] = 0;
		memset(dd->pport[i].vf_pkeys[si - 1], 0,
		       sizeof(dd->pport[i].vf_pkeys[si - 1]));
		spin_unlock(&dd->pport[i].vf_pkey_lock);
	}
}

/*
 * Called on PF0 to replay the P_Key table the FM set on each vPort. The
 * tables are per vPort, so they are delivered as VPortPartitionTable SETs.
 */
int pf2vf_push_vport_pkeys(struct hfi2_pportdata *ppd, unsigned long si_mask)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct opa_smp *smp;
	unsigned long id;
	int ret = 0;

	if (dd->is_vf)
		return -EINVAL;

	si_mask &= atomic_read(&dd->rsrcs.sync_done);
	if (!si_mask)
		return 0;

	smp = kzalloc(sizeof(*smp), GFP_KERNEL);
	if (!smp)
		return -ENOMEM;

	for_each_set_bit(id, &si_mask,
			 min_t(int, dd->rsrcs.num_vfs, HFI2_MAX_VPORT_VFS) + 1) {
		unsigned long valid;
		u32 blk;

		if (!id)
			continue;

		spin_lock(&ppd->vf_pkey_lock);
		valid = ppd->vf_pkey_blk_valid[id - 1];
		spin_unlock(&ppd->vf_pkey_lock);

		for_each_set_bit(blk, &valid,
				 DIV_ROUND_UP(dd->params->pkey_table_size,
					      OPA_PARTITION_TABLE_BLK_SIZE)) {
			__be16 *out = (__be16 *)opa_get_smp_data(smp);
			u32 start = blk * OPA_PARTITION_TABLE_BLK_SIZE;
			u32 n = min_t(u32, OPA_PARTITION_TABLE_BLK_SIZE,
				      dd->params->pkey_table_size - start);
			u32 i;

			memset(smp, 0, sizeof(*smp));
			smp->method = IB_MGMT_METHOD_SET;
			smp->attr_id = HFI2_ATTR_VPORT_PARTITION_TABLE;
			smp->attr_mod = cpu_to_be32((id << 16) | blk);

			spin_lock(&ppd->vf_pkey_lock);
			for (i = 0; i < n; i++)
				out[i] = cpu_to_be16(ppd->vf_pkeys[id - 1][start + i]);
			spin_unlock(&ppd->vf_pkey_lock);

			ret = pf2vf_vport_mad(ppd, id, smp);
			if (ret) {
				dd_dev_warn(dd,
					    "Failed to push vPort %lu pkey blk %u (%d)\n",
					    id, blk, ret);
				break;
			}
		}
		if (ret)
			break;
	}
	kfree(smp);
	return ret;
}

void pf2vf_notify_portcfg(struct hfi2_pportdata *ppd, unsigned long si_mask)
{
	struct hfi2_devdata *dd = ppd->dd, *vdd;
	struct pci_dev *pdev = dd->pcidev, *vpdev;
	struct vf2pf_hdr *hdr;
	struct pf0_portcfg_chg_msg *msg;
	unsigned long id;
	void *mem;
	int ret;

	if (dd->is_vf || !dd->is_sriov || !dd->rsrcs.num_vfs)
		return;
	if (si_mask == VF2PF_SI_ALL)
		si_mask = GENMASK(dd->rsrcs.num_vfs, 1);

	si_mask &= atomic_read(&dd->rsrcs.sync_done);
	if (!si_mask)
		return;

	for_each_set_bit(id, &si_mask,
			 min_t(int, dd->rsrcs.num_vfs, HFI2_MAX_VPORT_VFS) + 1) {
		if (!id)
			continue;
		vpdev = pci_get_domain_bus_and_slot(pci_domain_nr(pdev->bus),
						    pdev->bus->number,
						    pci_iov_virtfn_devfn(pdev, id - 1));
		vdd = vpdev ? pci_get_drvdata(vpdev) : NULL;
		if (IS_LOCAL_VDD(vdd)) {
			queue_work(vdd->hfi2_wq,
				   &vdd->pport[ppd->hw_pidx].portcfg_work);
			pci_dev_put(vpdev);
			continue;
		}
		if (vpdev)
			pci_dev_put(vpdev);
		mem = msg_alloc(dd, &hdr);
		if (!mem) {
			dd_dev_err(dd,
				   "Failed to allocate port configuration notification\n");
			return;
		}
		msg = (struct pf0_portcfg_chg_msg *)hdr;
		msg->hdr.op = PF0_PORTCFG_CHG;
		msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
		msg->pidx = ppd->hw_pidx;
		msg->generation = portcfg_gen_read(ppd);
		ret = vf2pf_send(dd, id, mem);
		kfree(mem);
		if (ret)
			dd_dev_warn(dd, "Failed to notify port configuration to %lu (%d)\n",
				    id, ret);
	}
}

int pf2vf_push_umad(struct hfi2_pportdata *ppd, bool is16B, u8 si,
		    void *payload, int len)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct vf2pf_hdr *hdr;
	struct pf0_pushumad_msg *msg;
	void *mem;
	int ret = 0;

	if (dd->is_vf || len > sizeof(msg->data))
		return -EINVAL;

	/*
	 * SI 0 is PF0 and SIs above num_vfs have no context, so neither can
	 * receive a pushed UMAD.  Reject here: vf2pf_send() does not validate
	 * 'si', and lb_send() derives its target context from it, so an
	 * out-of-range value is delivered nowhere and still returns success.
	 */
	if (!si || si > dd->rsrcs.num_vfs) {
		dd_dev_err_ratelimited(dd, "UMAD push to invalid SI %u (num_vfs %u)\n",
				       si, dd->rsrcs.num_vfs);
		return -EINVAL;
	}

	/*
	 * If this needs to support vf_claim=true then a short cut
	 * will need to be implemented here.
	 */

	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct pf0_pushumad_msg *)hdr;
	msg->hdr.op = PF0_PUSH_UMAD;
	msg->hdr.len = len + VF2PF_MAD_OVERHEAD;
	msg->is16B = is16B;
	msg->pidx = ppd->hw_pidx;
	memcpy(msg->data, payload, len);
	ret = vf2pf_send(dd, si, mem);
	kfree(mem);
	return ret;
}

int pf2vf_push_mcast(struct hfi2_pportdata *ppd, struct hfi2_packet *packet)
{
	struct hfi2_devdata *dd = ppd->dd;
	struct vf2pf_hdr *hdr;
	struct pf0_pushmc_msg *msg;
	void *mem;
	int id, plen, hlen, mlen;
	int ret = 0;

	if (dd->is_vf)
		return -EINVAL;

	/* should never get here if errors, but make certain */
	if (packet->has_errs)
		return -EINVAL;

	/* This may be called from interrupt, so may require spawning to a WQ */

	hlen = packet->hlen; /* header length */
	plen = packet->tlen - hlen; /* payload length */
	mlen = sizeof(*msg) - sizeof(*hdr) + hlen + plen;
	mem = msg_alloc_len(dd, &hdr, mlen);
	if (!mem)
		return -ENOMEM;
	msg = (struct pf0_pushmc_msg *)hdr;
	msg->hdr.op = PF0_PUSH_MCAST;
	msg->hdr.len = mlen;
	msg->pidx = ppd->hw_pidx;
	msg->datoff = hlen;
	msg->rhf = packet->rhf;
	memcpy(msg->pkt, packet->hdr, hlen);
	memcpy(msg->pkt + msg->datoff, packet->payload, plen);

	/*
	 * If this needs to support vf_claim=true, will require a short cut
	 * to be implemented.
	 */
	for (id = 0; id < dd->rsrcs.num_vfs; ++id) {
		if (!(atomic_read(&dd->rsrcs.sync_done) & (1 << (id + 1))))
			continue;
		ret = vf2pf_send(dd, id + 1, mem);
		if (ret) {
			dd_dev_warn(dd, "Failed to push mcast to %d (%d)\n", id + 1, ret);
			break;
		}
	}
	kfree(mem);
	return ret;
}

int vf2pf_send_only_mad(struct hfi2_devdata *dd, u8 sb, const void *mad, int len)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_mad *msg;
	void *mem;
	int ret;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return cport_send_only_mad(pdd, sb, mad, len, NULL);
	}
	if (len > sizeof(msg->mad)) {
		dd_dev_err(dd, "Failing oversized VF2PF MAD response (%d)\n", len);
		return -EINVAL;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_mad *)hdr;
	msg->hdr.op = VF2PF_MAD_SND;
	msg->hdr.len = len + VF2PF_MAD_OVERHEAD;
	msg->sb = sb;
	memcpy(&msg->mad, mad, len);
	ret = vf2pf_send(dd, 0, mem);
	if (!ret)
		ret = hdr->status;
	kfree(mem);
	return ret;
}

int vf2pf_send_recv_mad(struct hfi2_devdata *dd, u8 sb, const void *mad, int len,
			void *omad, size_t *omad_len, long to)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_mad *msg;
	void *mem;
	int ret;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		return cport_send_recv_mad(pdd, sb, mad, len, omad, omad_len);
	}
	if (len > sizeof(msg->mad)) {
		dd_dev_err(dd, "Failing oversized VF2PF MAD request (%d)\n", len);
		return -EINVAL;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_mad *)hdr;
	msg->hdr.op = VF2PF_MAD_SNDRCV;
	msg->hdr.len = len + VF2PF_MAD_OVERHEAD;
	msg->sb = sb;
	memcpy(&msg->mad, mad, len);
	ret = vf2pf_send_recv(dd, 0, mem, -to); /* -to: signal use semaphore */
	if (!ret)
		ret = hdr->status;
	if (!ret) {
		int olen;

		if (msg->hdr.len < VF2PF_MAD_OVERHEAD) {
			kfree(mem);
			return -EPROTO;
		}
		olen = msg->hdr.len - VF2PF_MAD_OVERHEAD;
		if (olen > *omad_len) {
			dd_dev_warn(dd, "VF2PF MAD resp length 0x%x > 0x%lx, truncating\n",
				    olen, *omad_len);
			olen = *omad_len;
		}
		memcpy(omad, &msg->mad, olen);
		*omad_len = olen;
	}
	kfree(mem);
	return ret;
}

static void vf2pf_syncup(struct hfi2_devdata *dd, int si)
{
	unsigned long flags;

	if (si <= 0 || si > dd->rsrcs.num_vfs)
		return;
	spin_lock_irqsave(&dd->sync_lock, flags);
	atomic_or(BIT(si), &dd->rsrcs.sync_pending);
	spin_unlock_irqrestore(&dd->sync_lock, flags);
	queue_delayed_work(dd->hfi2_wq, &dd->sync_vf_work, 0);
}

/* SIs in @mask whose VF stopped since @gen was sampled */
static int vf2pf_sync_stale(struct hfi2_devdata *dd, int mask, const int *gen)
{
	int stale = 0;
	int si;

	for (si = 1; si <= dd->rsrcs.num_vfs; si++)
		if ((mask & BIT(si)) &&
		    atomic_read(&dd->sync_gen[si]) != gen[si])
			stale |= BIT(si);
	return stale;
}

static void vf2pf_sync_fn(struct work_struct *work)
{
	struct hfi2_devdata *dd = container_of(work, struct hfi2_devdata,
					       sync_vf_work.work);
	int gen[HFI2_MAX_VPORT_VFS + 1];
	unsigned long flags;
	int sync_pending;
	int failed = 0;
	int stale = 0;
	int started;
	int ret;
	int pidx;
	int si;

	/*
	 * Sample the generations and take the pending bits together: a READY
	 * that arrives after a STOP must be consumed with the post-STOP
	 * generation, not an older one that would make it look stale.
	 */
	spin_lock_irqsave(&dd->sync_lock, flags);
	for (si = 1; si <= dd->rsrcs.num_vfs; si++)
		gen[si] = atomic_read(&dd->sync_gen[si]);
	sync_pending = atomic_fetch_and(0, &dd->rsrcs.sync_pending);
	spin_unlock_irqrestore(&dd->sync_lock, flags);
	if (!sync_pending)
		return;

	if (!hfi2_sriov_vf_tags_match(dd->pcidev))
		dd_dev_warn_ratelimited(dd,
					"PF and VF 10-bit tag settings differ; SDMA may hang\n");

	dd_dev_info(dd, "syncing VFs %02x\n", sync_pending);

	for (pidx = 0; pidx < dd->num_pports; pidx++)
		portcfg_gen_bump(&dd->pport[pidx]);
	for (si = 1; si <= dd->rsrcs.num_vfs; si++) {
		if (!(sync_pending & BIT(si)))
			continue;
		ret = cport_start_si(dd, si, 0, hfi2_cport_adm_to);
		if (ret) {
			dd_dev_err(dd, "Failed to start CPORT for VF SI %d (%d)\n", si, ret);
			failed |= BIT(si);
		}
	}

	/* A VF whose CPORT START failed is neither notified nor replayed; it retries */
	started = sync_pending & ~failed;
	atomic_or(started, &dd->rsrcs.sync_done);
	/*
	 * A VF that stopped while this ran must not stay synced. The stop bumps
	 * sync_gen before clearing sync_done and before its CPORT STOP, so
	 * either it clears the bit we just set or we see the new generation
	 * here, clear it and undo any START that landed after the STOP.
	 */
	smp_mb__after_atomic();
	stale = vf2pf_sync_stale(dd, sync_pending, gen);
	if (stale) {
		atomic_andnot(stale, &dd->rsrcs.sync_done);
		started &= ~stale;
		failed &= ~stale;
		for (si = 1; si <= dd->rsrcs.num_vfs; si++) {
			if (!(stale & BIT(si)))
				continue;
			vf2pf_abort_waiters(dd, si);
			cport_stop_si(dd, si, 0);
		}
	}
	for (pidx = 0; pidx < dd->num_pports; pidx++)
		pf2vf_notify_portcfg(&dd->pport[pidx], started);

	for (si = 1; si <= dd->rsrcs.num_vfs; si++) {
		if (!(started & BIT(si)))
			continue;
		ret = hfi2_sriov_sync_ports(dd, BIT(si));
		if (!ret) {
			dd->rsrcs.sync_retries[si] = 0;
			continue;
		}
		dd_dev_err(dd, "Failed to sync ports to VF SI %d (%d)\n", si, ret);
		failed |= BIT(si);
	}

	/*
	 * A failed SI must not be treated as synced. Take it out of sync_done
	 * and retry it later, up to a limit so that a VF that never answers does
	 * not retry forever.
	 */
	if (failed) {
		int retry = 0;
		int late;

		atomic_andnot(failed, &dd->rsrcs.sync_done);
		stale |= vf2pf_sync_stale(dd, failed, gen);
		for (si = 1; si <= dd->rsrcs.num_vfs; si++) {
			if (!(failed & BIT(si)))
				continue;
			if (stale & BIT(si)) {
				dd->rsrcs.sync_retries[si] = 0;
				continue;
			}
			if (dd->rsrcs.sync_retries[si]++ >= VF2PF_SYNC_RETRIES) {
				dd_dev_err(dd, "Giving up syncing VF SI %d\n", si);
				dd->rsrcs.sync_retries[si] = 0;
				continue;
			}
			retry |= BIT(si);
		}
		/*
		 * Publish under sync_lock, rechecking the generation: a STOP
		 * since the check above has cleared the bit and must not have
		 * it restored, or the next worker would START a stopped VF.
		 */
		spin_lock_irqsave(&dd->sync_lock, flags);
		late = vf2pf_sync_stale(dd, retry, gen);
		retry &= ~late;
		if (retry)
			atomic_or(retry, &dd->rsrcs.sync_pending);
		spin_unlock_irqrestore(&dd->sync_lock, flags);
		for (si = 1; si <= dd->rsrcs.num_vfs; si++)
			if (late & BIT(si))
				dd->rsrcs.sync_retries[si] = 0;
		if (retry) {
			queue_delayed_work(dd->hfi2_wq, &dd->sync_vf_work,
					   msecs_to_jiffies(VF2PF_SYNC_RETRY_MS));
		}
	}
}

static int vf2pf_mk_packet(struct hfi2_pportdata *ppd,
			    struct hfi2_packet *packet, struct pf0_pushmc_msg *msg)
{
	struct hfi2_portrsrcs *pr = &ppd->dd->rsrcs.ppr[ppd->hw_pidx];
	struct hfi2_ctxtdata *rcd;
	struct ib_header *hdr = (struct ib_header *)msg->pkt;
	u8 lnh;
	extern void cache_rhf_values(struct hfi2_packet *packet);

	rcd = hfi2_rcd_get_by_index(ppd->dd, pr->rcv_context_base + HFI2_CTRL_CTXT);
	if (!rcd)
		return -EINVAL; /* something fundamentally wrong */

	/* like init_packet() */
	packet->rsize = get_hdrqentsize(rcd); /* words */
	packet->maxcnt = get_hdrq_cnt(rcd) * packet->rsize; /* words */
	packet->rcd = rcd;
	packet->updegr = 0;
	packet->etail = -1;
	packet->rhqoff = hfi2_rcd_head(rcd);
	packet->numpkt = 0;
	packet->rhf_addr = NULL; /* NOT VALID! DO NOT USE! */
	packet->rhf = msg->rhf & ~RHF_JKR_RHE_VALID; /* force RHF.RheValid=0 */
	cache_rhf_values(packet); /* rcd-safe since !RHF.RheValid */

	/* from process_rcv_packet() */
	packet->etype = rhf_rcv_type(packet->rhf);
	packet->tlen = rhf_pkt_len(packet->rhf);
	packet->ebuf = msg->pkt + msg->datoff;

	/* like hfi2_setup_9B_packet() */
	packet->hdr = hdr;
	packet->hlen = msg->datoff;
	lnh = ib_get_lnh(hdr);
	if (lnh == HFI2_LRH_BTH) {
		packet->ohdr = &hdr->u.oth;
		packet->grh = NULL;
	} else if (lnh == HFI2_LRH_GRH) {
		u32 vtf;

		packet->ohdr = &hdr->u.l.oth;
		packet->grh = &hdr->u.l.grh;
		if (hfi2_is_pad_grh(packet->grh)) {
			/* dummy pad GRH: skip it, it is not a real GRH */
			packet->grh = NULL;
		} else {
			if (packet->grh->next_hdr != IB_GRH_NEXT_HDR)
				goto drop;
			vtf = be32_to_cpu(packet->grh->version_tclass_flow);
			if ((vtf >> IB_GRH_VERSION_SHIFT) != IB_GRH_VERSION)
				goto drop;
		}
	} else {
		goto drop;
	}
	packet->payload = packet->ebuf;
	packet->mgmt = NULL; /* or packet->ebuf if OPA_16B_L4_FM */
	packet->qp = NULL; /* set later, before calling packet_handler */
	packet->opcode = ib_bth_get_opcode(packet->ohdr);
	packet->slid = ib_get_slid(hdr);
	packet->dlid = ib_get_dlid(hdr);
	if (unlikely((packet->dlid >= be16_to_cpu(IB_MULTICAST_LID_BASE)) &&
		     (packet->dlid != be16_to_cpu(IB_LID_PERMISSIVE))))
		packet->dlid += opa_get_mcast_base(OPA_MCAST_NR) -
				be16_to_cpu(IB_MULTICAST_LID_BASE);
	packet->sl = ib_get_sl(hdr);
	packet->sc = hfi2_9B_get_sc5(hdr, packet->sc4);
	packet->pad = ib_bth_get_pad(packet->ohdr);
	packet->extra_byte = 0;
	packet->pkey = ib_bth_get_pkey(packet->ohdr);
	packet->migrated = ib_bth_is_migration(packet->ohdr);

	return 0;
drop:
	hfi2_rcd_put(rcd);
	return -EIO;
}

static int vf2pf_get_si_rsrcs(struct hfi2_devdata *dd, struct vf2pf_hdr *hdr,
			      struct hfi2_devrsrcs *vfr)
{
	if (hdr->si < 1 || hdr->si > dd->rsrcs.num_vfs)
		return -EINVAL;
	return hfi2_sriov_get_config(dd, vfr, hdr->si);
}

/*
 * received responses handled elsewhere.
 * 'buf' (and 'hdr') are allocated memory.
 * must be safe to destroy 'buf' on return.
 * An invalid message always generates a response.
 */
void vf2pf_rcv_msg(struct hfi2_devdata *dd, struct vf2pf_hdr *hdr, void *buf)
{
	int ret = 0;
	u8 si = hdr->si;
	u32 seq = hdr->seq;
	u16 tid = hdr->tid;

	dd_dev_dbg(dd, "VF2PF RECV op=%u si=%u tid=%u seq=%u ver=%u\n",
		   hdr->op, si, tid, seq, hdr->ver);

	/* Validate message version */
	if (hdr->ver != VF2PF_HDR_VERSION) {
		dd_dev_err_ratelimited(dd, "Invalid VF2PF message version=0x%x, expected 0x%x\n",
				       hdr->ver, VF2PF_HDR_VERSION);
		ret = -EBADMSG;
		hdr->len = 0;
		goto out;
	}
	if ((hdr->len + sizeof(*hdr)) > ((struct vf2pf_prefix *)buf)->len) {
		ret = -EBADMSG;
		hdr->len = 0;
		goto out;
	}

	/* Reject PF0 opcodes not sent by the PF or not being applied to a VF */
	if (hdr->op >= PF0_PUSH_UMAD && (hdr->si != 0 || !dd->is_vf)) {
		ret = -EBADMSG;
		hdr->len = 0;
		goto out;
	}

	/* hdr == vf2pf_dev->get_msg(dd, buf) */
	switch (hdr->op) {
	case VF2PF_OP_PING: {
		struct vf2pf_ping_msg *ping = (struct vf2pf_ping_msg *)hdr;

		dd_dev_info(dd, "vf2pf ping-pong with %u \"%.*s\"\n", hdr->si,
			    hdr->len, ping->data);
		if (hdr->len >= sizeof(ping->data))
			hdr->len = sizeof(ping->data) - 1;
		ping->data[hdr->len++] = '!';
		break;
	}

	/* only received on PF0 */
	case VF2PF_GET_CFG: {
		struct vf2pf_getcfg_msg *msg = (struct vf2pf_getcfg_msg *)hdr;

		ret = hfi2_sriov_get_config(dd, &msg->rsrcs, msg->si);
		/* copy these even if error */
		msg->base_guid = dd->base_guid;
		msg->revision = dd->revision;
		msg->hfi2_id = dd->hfi2_id;
		msg->icode = dd->icode;
		msg->irev = dd->irev;
		msg->cport_ver = dd->cport_ver;
		break;
	}
	case VF2PF_GET_ETH_CFG: {
		struct hfi2_pportdata *ppd = dd->pport;
		struct vf2pf_get_ethcfg_msg *msg = (struct vf2pf_get_ethcfg_msg*) hdr;
		struct ether_device *edev;

		if (!ppd || !ppd->ndev) {
			/* netdev disabled (small configuration) — no eth cfg to report */
			ret = -ENODEV;
			break;
		}
		if (msg->vf >= CN_MAX_VFS) {
			ret = -EINVAL;
			break;
		}
		edev = netdev_priv(ppd->ndev);
		msg->mac = ether_addr_to_u64(edev->vf[msg->vf].mac);
		msg->pf_set_mac = edev->vf[msg->vf].pf_set_mac;
		msg->trusted = edev->vf[msg->vf].trusted ? 1 : 0;
		msg->spoofchk = edev->vf[msg->vf].spoofchk ? 1 : 0;
		msg->vlan = edev->vf[msg->vf].vid;
		msg->qos = edev->vf[msg->vf].qos;
		break;
	}
	case VF2PF_GET_PORTCFG: {
		struct vf2pf_get_portcfg_msg *req =
			(struct vf2pf_get_portcfg_msg *)hdr;
		struct vf2pf_portcfg *msg = (struct vf2pf_portcfg *)hdr;

		if (hdr->len != sizeof(*req) - sizeof(*hdr) ||
		    req->pidx >= dd->num_pports) {
			ret = -EINVAL;
			break;
		}
		pf2vf_fill_portcfg(&dd->pport[req->pidx], msg);
		hdr->len = sizeof(*msg) - sizeof(*hdr);
		break;
	}
	case VF2PF_ASGN_RES: {
		struct vf2pf_asgnrs_msg *msg = (struct vf2pf_asgnrs_msg *)hdr;

		ret = hfi2_sriov_assign_rsrcs(dd, &msg->rsrcs);
		break;
	}
	case VF2PF_FREE_RES: {
		struct vf2pf_asgnrs_msg *msg = (struct vf2pf_asgnrs_msg *)hdr;

		hfi2_sriov_free_rsrcs(dd, &msg->rsrcs);
		break;
	}
	case VF2PF_PREG_OP: {
		struct vf2pf_pregop_msg *msg = (struct vf2pf_pregop_msg *)hdr;
		struct hfi2_devrsrcs vfr;
		u16 sctxt = msg->ctxt & 0xffff;
		u16 rctxt = msg->ctxt >> 16;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EINVAL;
			break;
		}
		ret = vf2pf_get_si_rsrcs(dd, hdr, &vfr);
		if (ret)
			break;
		if (msg->op >= SC_CHK_ALLOC_OP && msg->op <= SC_DISABLE_OP) {
			if (sctxt < vfr.c.first_send_context || sctxt >= vfr.c.last_send_context ||
			    (msg->op == SC_CHK_JKEY_OP && rctxt != HFI2_NO_RCV_CTXT &&
			     (rctxt < vfr.c.first_rcv_context ||
			      rctxt >= vfr.c.last_rcv_context)) ||
			    (msg->op != SC_CHK_JKEY_OP && rctxt)) {
				ret = -EINVAL;
				break;
			}
		} else if (msg->op >= RC_ENABLE_OP && msg->op <= RC_HEADER_OP) {
			if (rctxt || sctxt < vfr.c.first_rcv_context ||
			    sctxt >= vfr.c.last_rcv_context) {
				ret = -EINVAL;
				break;
			}
		} else {
			ret = -EINVAL;
			break;
		}
		ret = hfi2_priv_reg_op(dd, msg->pidx, msg->ctxt, msg->type,
				       msg->op, msg->arg);
		break;
	}
	case VF2PF_RCSR_OP: {
		struct vf2pf_readcsr_msg *msg = (struct vf2pf_readcsr_msg *)hdr;
		struct hfi2_devrsrcs vfr;
		u64 base, end;
		unsigned int pidx;
		bool valid = false;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) || (msg->off & 7)) {
			ret = -EINVAL;
			break;
		}
		ret = vf2pf_get_si_rsrcs(dd, hdr, &vfr);
		if (ret)
			break;
		for (pidx = 0; pidx < dd->num_pports; pidx++) {
			base = (u64)dd->params->send_egress_ctxt_status_reg +
			       (u64)dd->params->txe_eport_stride * pidx;
			end = base + 8ULL * vfr.c.last_send_context;
			base += 8ULL * vfr.c.first_send_context;
			if (msg->off >= base && msg->off < end &&
			    !((msg->off - base) & 7) &&
			    (u64)msg->off + sizeof(u64) <= dd->params->bar0_size) {
				valid = true;
				break;
			}
		}
		if (!valid) {
			ret = -EINVAL;
			break;
		}
		msg->reg = hfi2_read_csr(dd, msg->off);
		break;
	}
	case VF2PF_RCCTRL_OP: {
		struct vf2pf_rcctrl_msg *msg = (struct vf2pf_rcctrl_msg *)hdr;
		struct hfi2_devrsrcs vfr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr)) {
			ret = -EINVAL;
			break;
		}
		ret = vf2pf_get_si_rsrcs(dd, hdr, &vfr);
		if (ret)
			break;
		if (msg->ctxt < vfr.c.first_rcv_context || msg->ctxt >= vfr.c.last_rcv_context) {
			ret = -EINVAL;
			break;
		}
		msg->reg = hfi2_rctxt_ctrl_op(dd, msg->ctxt, msg->op);
		break;
	}
	case VF2PF_TIDCFG_OP: {
		struct vf2pf_tidcfg_msg *msg = (struct vf2pf_tidcfg_msg *)hdr;
		struct hfi2_devrsrcs vfr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EINVAL;
			break;
		}
		ret = vf2pf_get_si_rsrcs(dd, hdr, &vfr);
		if (ret)
			break;
		if (msg->ctxt < vfr.c.first_rcv_context ||
		    msg->ctxt >= vfr.c.last_rcv_context ||
		    (msg->alloced &&
		     (msg->egr_base < vfr.c.first_rcvarray_entry ||
		      msg->egr_base >= vfr.c.last_rcvarray_entry ||
		      msg->alloced > vfr.c.last_rcvarray_entry - msg->egr_base)) ||
		    (msg->exp_cnt &&
		     (msg->exp_base < vfr.c.first_rcvarray_entry ||
		      msg->exp_base >= vfr.c.last_rcvarray_entry ||
		      msg->exp_cnt > vfr.c.last_rcvarray_entry - msg->exp_base))) {
			ret = -EINVAL;
			break;
		}
		dd->params->set_port_tid_config(dd, msg->pidx, msg->ctxt, msg->egr_base,
						msg->alloced, msg->exp_base, msg->exp_cnt);
		break;
	}
	case VF2PF_RXERSM_OP: {
		struct vf2pf_asgnrs_msg *msg = (struct vf2pf_asgnrs_msg *)hdr;

		ret = hfi2_init_rxe_rsm(dd, &msg->rsrcs);
		break;
	}
	case VF2PF_QPMAP_OP: {
		struct vf2pf_qpmap_msg *msg = (struct vf2pf_qpmap_msg *)hdr;

		if (msg->pidx >= dd->num_pports) {
			ret = -EINVAL;
			break;
		}
		ret = hfi2_get_qp_map(dd->pport + msg->pidx, msg->idx, &msg->res);
		break;
	}
	case VF2PF_STOP: {
		if (hdr->si < 1 || hdr->si > dd->rsrcs.num_vfs)
			return;

		pf2vf_vport_clear(dd, hdr->si);
		cport_stop_si(dd, hdr->si, 0);
		if (vf2pf_dev->deinit)
			vf2pf_dev->deinit(dd, hdr->si);
		return;	/* no response */
	}
	case VF2PF_MAD_SND: {
		struct vf2pf_mad *msg = (struct vf2pf_mad *)hdr;

		if (hdr->len < VF2PF_MAD_OVERHEAD ||
		    hdr->len > (sizeof(struct vf2pf_mad) - sizeof(*hdr))) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}

		ret = cport_send_only_mad(dd, msg->sb, &msg->mad,
					  msg->hdr.len - VF2PF_MAD_OVERHEAD, NULL);
		if (ret)
			dd_dev_err(dd, "Failed to send MAD to CPORT (%d)\n", ret);
		return;	/* no response */
	}
	case VF2PF_MAD_SNDRCV: {
		struct vf2pf_mad *msg = (struct vf2pf_mad *)hdr;
		size_t olen = sizeof(msg->mad);

		if (hdr->len < VF2PF_MAD_OVERHEAD ||
		    hdr->len > (sizeof(struct vf2pf_mad) - sizeof(*hdr))) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}

		ret = cport_send_recv_mad(dd, msg->sb,
					  &msg->mad, msg->hdr.len - VF2PF_MAD_OVERHEAD,
					  &msg->mad, &olen);
		if (!ret)
			msg->hdr.len = olen + VF2PF_MAD_OVERHEAD;
		break;
	}
	case VF2PF_READY: {
		vf2pf_syncup(dd, hdr->si);
		return;	/* no response */
	}
	case VF2PF_VPORT_CHG: {
		struct vf2pf_vport_chg_msg *msg = (struct vf2pf_vport_chg_msg *)hdr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports ||
		    (!msg->flags1 && !msg->flags2) ||
		    (msg->flags1 & ~OPA_VPORT_LOCAL_CHG_FLAGS1_VALID) ||
		    (msg->flags2 & ~OPA_VPORT_LOCAL_CHG_FLAGS2_VALID)) {
			dd_dev_err_ratelimited(dd, "Invalid VPort change from %u\n",
					       hdr->si);
			return;	/* no response */
		}
		hfi2_vport_local_chg(&dd->pport[msg->pidx].ibport_data,
				     msg->flags1, msg->flags2);
		return;	/* no response */
	}

	/* only received on VFs */
	case PF0_PUSH_UMAD: {
		struct pf0_pushumad_msg *msg = (struct pf0_pushumad_msg *)hdr;

		if (hdr->len < VF2PF_MAD_OVERHEAD ||
		    hdr->len > (sizeof(struct pf0_pushumad_msg) - sizeof(*hdr)) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}

		vf_umad_handler(dd->pport + msg->pidx, msg->is16B,
				msg->data, msg->hdr.len - VF2PF_MAD_OVERHEAD);
		return;	/* no response */
	}
	case PF0_PUSH_MCAST: {
		struct pf0_pushmc_msg *msg = (struct pf0_pushmc_msg *)hdr;
		struct hfi2_packet packet;

		if (msg->pidx >= dd->num_pports) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}

		/* packet has already been validated, so should be no errors */
		ret = vf2pf_mk_packet(dd->pport + msg->pidx, &packet, msg);
		if (ret) {
			dd_dev_err(dd, "cannot make fake packet (%d)\n", ret);
			return;	/* no response */
		}
		hfi2_ib_rcv(&packet);
		hfi2_rcd_put(packet.rcd);
		return;	/* no response */
	}
	case PF0_PORTCFG_CHG: {
		struct pf0_portcfg_chg_msg *msg = (struct pf0_portcfg_chg_msg *)hdr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}
		if (msg->generation > portcfg_gen_read(&dd->pport[msg->pidx]))
			queue_work(dd->hfi2_wq, &dd->pport[msg->pidx].portcfg_work);
		return;
	}
	case PF0_VPORT_MAD: {
		struct pf0_vportmad_msg *msg = (struct pf0_vportmad_msg *)hdr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}
		ret = hfi2_vport_mad_vf(dd->pport + msg->pidx, &msg->smp);
		break;
	}
	case PF0_VPORT_GUIDS: {
		struct pf0_vportguids_msg *msg = (struct pf0_vportguids_msg *)hdr;

		if (hdr->len != sizeof(*msg) - sizeof(*hdr) ||
		    msg->pidx >= dd->num_pports) {
			ret = -EBADMSG;
			hdr->len = 0;
			goto out;
		}
		hfi2_vport_set_guids(dd->pport + msg->pidx, msg->node_guid,
				     msg->port_guid);
		ret = 0;
		break;
	}
	default:
		dd_dev_err(dd, "Unknown vf2pf msg op %u from %u\n", hdr->op, hdr->si);
		return;
	}

out:
	/* reaching here means response is to be sent */
	hdr->op |= VF2PF_OP_RESP;
	hdr->status = ret;

	vf2pf_send(dd, hdr->si, buf);
}

/*
 * 'buf' may point to h/w recv buffer.
 * called from intr context: must expedite handling.
 * hdr->op has VF2PF_OP_RESP set, in order to reach here.
 */
void vf2pf_rsp_msg(struct hfi2_devdata *dd, void *buf, u32 buf_len)
{
	struct vf2pf_hdr *hdr = buf;
	struct vf2pf_prefix *wpfx;	/* msg object waiting for response */
	struct vf2pf_hdr *whdr;		/* hdr waiting for response */
	void *wbuf;
	u32 msg_len;

	/* Validate message */
	if (buf_len < sizeof(*hdr)) {
		dd_dev_err_ratelimited(dd, "VF2PF runt message (%u bytes)\n", buf_len);
		return;
	}
	if (hdr->ver != VF2PF_HDR_VERSION) {
		dd_dev_err_ratelimited(dd, "Invalid VF2PF message version=0x%x, expected 0x%x\n",
				       hdr->ver, VF2PF_HDR_VERSION);
		return;
	}
	msg_len = hdr->len + sizeof(*hdr);
	if (msg_len > buf_len) {
		dd_dev_err_ratelimited(dd, "VF2PF RSP length (%u) invalid.\n", msg_len);
		return;
	}

	wpfx = vf2pf_dev->get_tid(dd, hdr->tid);
	if (!wpfx) {
		dd_dev_err(dd, "vf2pf response op %x has no waiter\n", hdr->op);
		return;
	}
	whdr = vf2pf_dev->get_msg(dd, wpfx);
	wbuf = whdr;
	if (whdr->sz < msg_len) {
		dd_dev_err(dd, "VF2PF op=%u message length (%u) > waiter size (%u)\n",
			hdr->op & ~VF2PF_OP_RESP, msg_len, whdr->sz);
		whdr->status = -EMSGSIZE;
	} else {
		/*
		 * need to avoid race by setting VF2PF_OP_RESP in whdr->op last (after barrier).
		 * this requires that VF2PF_OP_RESP is cleared in 'op' before the memcpy,
		 * then set after in the destination.
		 */
		hdr->op &= ~VF2PF_OP_RESP;
		dd_dev_dbg(dd, "VF2PF RESP op=%u si=%u seq=%u\n", hdr->op, hdr->si, hdr->seq);
		memcpy(wbuf, buf, msg_len);
	}
	smp_wmb(); /* needed? */
	whdr->op |= VF2PF_OP_RESP; /* to trigger wakeup condition */
	if (wpfx->type == VF2PF_PFX_TYPE_WAIT)
		wake_up(&wpfx->wait);
	else
		up(&wpfx->sema);
}

/*
 * Return number of special contexts needed by implementation.
 * Should be either 0 or JKR_C_CCE_NUM_VFS + 1.
 */
int vf2pf_num_ctxts(struct hfi2_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;
	return vf2pf_dev->num_ctxts;
}

int vf2pf_num_irq(struct hfi2_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;
	return vf2pf_dev->num_irq;
}

/* returns 0 on error (invalid VF SI) */
int vf2pf_probe_si(struct hfi2_devdata *dd)
{
	if (vf2pf_dev->probe_si)
		return vf2pf_dev->probe_si(dd);
	return 0;
}

static ssize_t vf2pf_ping_store(struct device *device,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct hfi2_ibdev *dev = rdma_device_to_drv_device(device, struct hfi2_ibdev, rdi.ibdev);
	struct hfi2_devdata *dd = dd_from_dev(dev);
	void *mem;
	struct vf2pf_hdr *hdr;
	struct vf2pf_ping_msg *ping;
	size_t len = count;
	int ret;

	if (!count)
		return -EINVAL;

	if (count > sizeof(ping->data))
		return -EINVAL;

	/* trim one newline if present */
	if (buf[len - 1] == '\n')
		--len;

	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;

	ping = (struct vf2pf_ping_msg *)hdr;
	ping->hdr.op = VF2PF_OP_PING;
	ping->hdr.len = len;
	memcpy(ping->data, buf, len);

	dd_dev_info(dd, "vf2pf ping 0 \"%.*s\"\n", ping->hdr.len, buf);
	ret = vf2pf_send_recv(dd, 0, mem, vf2pf_to * HZ);
	if (ret)
		dd_dev_warn(dd, "vf2pf ping send failed (%d)\n", ret);
	else
		dd_dev_info(dd, "vf2pf ping resp from %u \"%.*s\"\n",
			    ping->hdr.si, ping->hdr.len, (char *)ping->data);
	kfree(mem);
	return count;
}

static DEVICE_ATTR_WO(vf2pf_ping);

static ssize_t vf2pf_sync_store(struct device *device,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct hfi2_ibdev *dev = rdma_device_to_drv_device(device, struct hfi2_ibdev, rdi.ibdev);
	struct hfi2_devdata *dd = dd_from_dev(dev);
	unsigned long sync_mask;
	unsigned long flags;
	int ret;

	/* allow 0 mask and trigger work func anyway */
	ret = kstrtoul(buf, 0, &sync_mask);
	if (ret || (sync_mask & ~0b011111110))
		return -EINVAL;

	spin_lock_irqsave(&dd->sync_lock, flags);
	atomic_or(sync_mask, &dd->rsrcs.sync_pending);
	spin_unlock_irqrestore(&dd->sync_lock, flags);
	queue_delayed_work(dd->hfi2_wq, &dd->sync_vf_work, 0);

	return count;
}

static DEVICE_ATTR_WO(vf2pf_sync);

void vf2pf_set_si_enables(struct hfi2_devdata *dd, int si, u64 *csrs,
			  void (*si_enables)(struct hfi2_devdata *dd,
					     u64 *csrs, u32 start, u32 end))
{
	if (!vf2pf_dev->set_si_enables)
		return;
	vf2pf_dev->set_si_enables(dd, si, csrs, si_enables);
}

void vf2pf_ready(struct hfi2_devdata *dd)
{
	struct vf2pf_hdr *hdr;
	void *mem;
	int ret;

	if (!dd->is_vf)
		return;

	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		vf2pf_syncup(pdd, dd->rsrcs.si_idx);
		return;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem) {
		dd_dev_err(dd, "Failed to signal ready to PF0 (msg_alloc)\n");
		return;
	}
	hdr->op = VF2PF_READY;
	hdr->len = 0;
	ret = vf2pf_send(dd, 0, mem);
	kfree(mem);
	if (ret)
		dd_dev_err(dd, "Failed to signal ready to PF0 (%d)\n", ret);
}

/*
 * VF call to PF0 to report a change to the VF's VPort that the SM must hear
 * about. PF0 owns VPort0's LID and sends the trap.
 */
int vf2pf_vport_change(struct hfi2_devdata *dd, u8 pidx, u16 flags1,
		       u32 flags2)
{
	struct vf2pf_hdr *hdr;
	struct vf2pf_vport_chg_msg *msg;
	void *mem;
	int ret;

	if (!dd->is_vf)
		return -EINVAL;
	if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
		struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

		if (pidx >= pdd->num_pports)
			return -EINVAL;
		hfi2_vport_local_chg(&pdd->pport[pidx].ibport_data, flags1, flags2);
		return 0;
	}
	mem = msg_alloc(dd, &hdr);
	if (!mem)
		return -ENOMEM;
	msg = (struct vf2pf_vport_chg_msg *)hdr;
	msg->hdr.op = VF2PF_VPORT_CHG;
	msg->hdr.len = sizeof(*msg) - sizeof(*hdr);
	msg->pidx = pidx;
	msg->flags1 = flags1;
	msg->flags2 = flags2;
	ret = vf2pf_send(dd, 0, mem);
	kfree(mem);
	return ret;
}

void vf2pf_init_sysfs(struct hfi2_devdata *dd, struct device *class_dev)
{
	struct vf2pf_lbdata *lbd = dd->vf2pf;
	int ret;

	if (!lbd)
		return;

	if (dd->is_vf) {
		ret = sysfs_create_file(&class_dev->kobj, &dev_attr_vf2pf_ping.attr);
		if (ret)
			dd_dev_warn(dd, "failed to create sysfs attr %s (%d)\n",
				    dev_attr_vf2pf_ping.attr.name, ret);
	} else {
		ret = sysfs_create_file(&class_dev->kobj, &dev_attr_vf2pf_sync.attr);
		if (ret)
			dd_dev_warn(dd, "failed to create sysfs attr %s (%d)\n",
				    dev_attr_vf2pf_sync.attr.name, ret);
	}
	if (vf2pf_dev->init_sysfs)
		vf2pf_dev->init_sysfs(dd, class_dev);
}

int vf2pf_init_irq(struct hfi2_devdata *dd)
{
	if (!vf2pf_dev->init_irq)
		return 0;
	return vf2pf_dev->init_irq(dd);
}

void vf2pf_deinit_irq(struct hfi2_devdata *dd)
{
	if (!vf2pf_dev->deinit_irq)
		return;
	vf2pf_dev->deinit_irq(dd);
}

/*
 * This is called on PF0 only, just before creation of VFs.
 *
 * This may be called multiple times throughout the life of the PF0
 * driver, if VFs are destroyed and recreated.
 */
int vf2pf_prep(struct hfi2_devdata *dd)
{
	if (!vf2pf_dev->init)
		return 0;
	return vf2pf_dev->init(dd, VF2PF_INIT_ALL);
}

/*
 * This is called early in the initialization.
 * It must not depend on any SRIOV configuration being setup,
 * but may call into the sriov module to decide if SRIOV is allowed.
 */
int vf2pf_early_init(struct hfi2_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;

	if (!dd->is_vf) {
		INIT_DELAYED_WORK(&dd->sync_vf_work, vf2pf_sync_fn);
		spin_lock_init(&dd->vf2pf_waiters_lock);
		spin_lock_init(&dd->sync_lock);
		INIT_LIST_HEAD(&dd->vf2pf_waiters);
		atomic_set(&dd->rsrcs.sync_pending, 0);
		atomic_set(&dd->rsrcs.sync_done, 0);
		INIT_DELAYED_WORK(&dd->flr_work, hfi2_flr_rebuild_fn);
		atomic_set(&dd->rsrcs.flr_pending, 0);
	}

#ifdef HFI_VF2PF_LOOPBACK
#ifndef HFI_VF2PF_LOOPBACK_CONFIG
	if (vf2pf_lb)
#endif
		vf2pf_dev = get_lb_devops();
#endif
	/* this may require BARs, must have been mapped by now */
	return hfi2_sriov_set_si(dd);
}

/*
 * This does the actual vf2pf implementation init,
 * which may need to be done later.
 */
int vf2pf_init(struct hfi2_devdata *dd)
{
	if (dd->params->chip_type == CHIP_WFR || !dd->is_sriov)
		return 0;

	if (!vf2pf_dev->init)
		return 0;
	return vf2pf_dev->init(dd, dd->rsrcs.si_idx);
}

/*
 * On VFs, this only sends a notification to PF0.
 * On PF0, this does a full de-initialization.
 */
void vf2pf_deinit(struct hfi2_devdata *dd)
{
	struct vf2pf_hdr *hdr;
	void *mem;
	int ret;

	/* a retry timer outlives flush_workqueue(); only INIT'd by early_init */
	if (!dd->is_vf && dd->params->chip_type != CHIP_WFR && dd->is_sriov)
		cancel_delayed_work_sync(&dd->sync_vf_work);

	if (dd->is_vf) {
		if (IS_LOCAL_VF(dd)) { /* VF and PF0 are using the same driver/OS instance */
			struct hfi2_devdata *pdd = pci_get_drvdata(dd->pcidev->physfn);

			pf2vf_vport_clear(pdd, dd->rsrcs.si_idx);
			cport_stop_si(pdd, dd->rsrcs.si_idx, 0);
			if (vf2pf_dev->deinit)
				vf2pf_dev->deinit(pdd, dd->rsrcs.si_idx);
			goto out;
		}
		mem = msg_alloc(dd, &hdr);
		if (!mem) {
			dd_dev_err(dd, "Failed to notify PF0 (msg_alloc)\n");
			goto out;
		}
		hdr->op = VF2PF_STOP;
		hdr->len = 0;
		ret = vf2pf_send(dd, 0, mem);
		kfree(mem);
		if (ret)
			dd_dev_err(dd, "Failed to notify PF0 (%d)\n", ret);
	}
out:
	if (vf2pf_dev->deinit)
		vf2pf_dev->deinit(dd, dd->rsrcs.si_idx);
}
