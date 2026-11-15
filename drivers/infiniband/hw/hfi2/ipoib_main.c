// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright(c) 2020 Intel Corporation.
 *
 */

/*
 * This file contains HFI2 support for ipoib functionality
 */

#include "ipoib.h"
#include "hfi2.h"

static bool ipoib_napi_threaded = true;

/* Negative is auto: hfisvc where the device runs bulksvc, aip elsewhere. */
static int ipoib_tx_mode = -1;

/* Indexed by enum hfi2_ipoib_tx_mode. */
static const char * const ipoib_tx_mode_names[] = {
	[HFI2_IPOIB_TX_MODE_AIP]    = "aip",
	[HFI2_IPOIB_TX_MODE_HFISVC] = "hfisvc",
};

static __maybe_unused int ipoib_tx_mode_set(const char *val, const struct kernel_param *kp)
{
	int mode;

	if (!val)
		return -EINVAL;

	if (sysfs_streq(val, "auto")) {
		*(int *)kp->arg = -1;
		return 0;
	}

	mode = sysfs_match_string(ipoib_tx_mode_names, val);
	if (mode < 0)
		return mode;

	*(int *)kp->arg = mode;

	return 0;
}

static __maybe_unused int ipoib_tx_mode_get(char *buffer, const struct kernel_param *kp)
{
	int mode = *(int *)kp->arg;

	if (mode < 0)
		return sysfs_emit(buffer, "auto\n");
	if (mode >= ARRAY_SIZE(ipoib_tx_mode_names))
		return sysfs_emit(buffer, "unknown\n");

	return sysfs_emit(buffer, "%s\n", ipoib_tx_mode_names[mode]);
}

static __maybe_unused const struct kernel_param_ops ipoib_tx_mode_ops = {
	.set = ipoib_tx_mode_set,
	.get = ipoib_tx_mode_get,
};

/* Latched into priv->tx_mode at rdma_netdev setup, so read-only after load. */

static u32 qpn_from_mac(const u8 *mac_arr)
{
	return (u32)mac_arr[1] << 16 | mac_arr[2] << 8 | mac_arr[3];
}

/*
 * ib_ipoib keeps our ops only as rn_ops and installs its own const table,
 * which has no .ndo_select_queue, so our hooks go into a copy of that.
 */
static void hfi2_ipoib_install_select_queue(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);

	ASSERT_RTNL();

	priv->live_ops = *dev->netdev_ops;
	priv->live_ops.ndo_select_queue = hfi2_ipoib_select_queue;
	priv->live_ops.ndo_features_check = hfi2_ipoib_features_check;
	dev->netdev_ops = &priv->live_ops;
}


static int hfi2_ipoib_dev_init(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	int ret;


	hfi2_ipoib_install_select_queue(dev);

	ret = priv->netdev_ops->ndo_init(dev);
	if (ret) {
		return ret;
	}

	ret = hfi2_netdev_add_data(priv->ppd,
				   qpn_from_mac(priv->netdev->dev_addr),
				   dev);
	if (ret < 0) {
		priv->netdev_ops->ndo_uninit(dev);
		return ret;
	}

	return 0;
}

static void hfi2_ipoib_dev_uninit(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);


	hfi2_netdev_remove_data(priv->ppd, qpn_from_mac(priv->netdev->dev_addr));

	priv->netdev_ops->ndo_uninit(dev);
}

static int hfi2_ipoib_dev_open(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	int ret;

	hfi2_ipoib_hfisvc_latch(priv);

	ret = priv->netdev_ops->ndo_open(dev);
	if (!ret) {
		struct hfi2_ibport *ibp = to_iport(priv->device,
						   priv->port_num);
		struct rvt_qp *qp;
		u32 qpn = qpn_from_mac(priv->netdev->dev_addr);

		rcu_read_lock();
		qp = rvt_lookup_qpn(ib_to_rvt(priv->device), &ibp->rvp, qpn);
		if (!qp) {
			rcu_read_unlock();
			priv->netdev_ops->ndo_stop(dev);
			return -EINVAL;
		}
		rvt_get_qp(qp);
		priv->qp = qp;
		rcu_read_unlock();

		hfi2_netdev_enable_queues(priv->ppd);
		hfi2_ipoib_napi_tx_enable(dev);
		/* Before the queues wake, so tx_mode is final at first transmit. */
		hfi2_ipoib_hfisvc_attach(priv);
		netif_tx_wake_all_queues(dev);
	}

	return ret;
}

static int hfi2_ipoib_dev_stop(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);

	if (!priv->qp)
		return 0;

	/*
	 * Before the drain below: this stops new egress and waits out packets
	 * already placed, so the drain cannot free an skb or unmap a
	 * descriptor the engine is still reading.
	 */
	hfi2_ipoib_hfisvc_detach(priv);

	hfi2_ipoib_napi_tx_disable(dev);
	hfi2_netdev_disable_queues(priv->ppd);

	rvt_put_qp(priv->qp);
	priv->qp = NULL;

	return priv->netdev_ops->ndo_stop(dev);
}

static const struct net_device_ops hfi2_ipoib_netdev_ops = {
	.ndo_init         = hfi2_ipoib_dev_init,
	.ndo_uninit       = hfi2_ipoib_dev_uninit,
	.ndo_open         = hfi2_ipoib_dev_open,
	.ndo_stop         = hfi2_ipoib_dev_stop,
	/*
	 * ipoib_get_stats() forwards here; dev_get_stats() sees ib_ipoib's
	 * .ndo_get_stats64 and never reaches its tstats fallback.
	 */
	.ndo_get_stats64  = dev_get_tstats64,
};

static int hfi2_ipoib_mcast_attach(struct net_device *dev,
				   struct ib_device *device,
				   union ib_gid *mgid,
				   u16 mlid,
				   int set_qkey,
				   u32 qkey)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	u32 qpn = (u32)qpn_from_mac(priv->netdev->dev_addr);
	struct hfi2_ibport *ibp = to_iport(priv->device, priv->port_num);
	struct rvt_qp *qp;
	int ret = -EINVAL;

	rcu_read_lock();

	qp = rvt_lookup_qpn(ib_to_rvt(priv->device), &ibp->rvp, qpn);
	if (qp) {
		rvt_get_qp(qp);
		rcu_read_unlock();
		if (set_qkey)
			priv->qkey = qkey;

		/* attach QP to multicast group */
		ret = ib_attach_mcast(&qp->ibqp, mgid, mlid);
		rvt_put_qp(qp);
	} else {
		rcu_read_unlock();
	}

	return ret;
}

static int hfi2_ipoib_mcast_detach(struct net_device *dev,
				   struct ib_device *device,
				   union ib_gid *mgid,
				   u16 mlid)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	u32 qpn = (u32)qpn_from_mac(priv->netdev->dev_addr);
	struct hfi2_ibport *ibp = to_iport(priv->device, priv->port_num);
	struct rvt_qp *qp;
	int ret = -EINVAL;

	rcu_read_lock();

	qp = rvt_lookup_qpn(ib_to_rvt(priv->device), &ibp->rvp, qpn);
	if (qp) {
		rvt_get_qp(qp);
		rcu_read_unlock();
		ret = ib_detach_mcast(&qp->ibqp, mgid, mlid);
		rvt_put_qp(qp);
	} else {
		rcu_read_unlock();
	}
	return ret;
}

static void hfi2_ipoib_netdev_dtor(struct net_device *dev)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);

	hfi2_ipoib_txreq_deinit(priv);
	hfi2_ipoib_rxq_deinit(priv->netdev);

}

static void hfi2_ipoib_set_id(struct net_device *dev, int id)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);

	priv->pkey_index = (u16)id;
	ib_query_pkey(priv->device,
		      priv->port_num,
		      priv->pkey_index,
		      &priv->pkey);
}

static void hfi2_ipoib_get_channels(struct net_device *dev,
				    struct ethtool_channels *ch)
{
	ch->max_rx = dev->num_rx_queues;
	ch->max_tx = dev->num_tx_queues;
	ch->rx_count = dev->real_num_rx_queues;
	ch->tx_count = dev->real_num_tx_queues;
}

static int hfi2_ipoib_set_channels(struct net_device *dev,
				   struct ethtool_channels *ch)
{
	struct hfi2_ipoib_dev_priv *priv = hfi2_ipoib_priv(dev);
	unsigned int old_rx = dev->real_num_rx_queues;
	int ret;

	/* One transmit queue is how ib_ipoib holds a connected-mode netdev. */
	if (ch->tx_count != dev->real_num_tx_queues) {
		if (dev->real_num_tx_queues == 1)
			return -EBUSY;
		if (ch->tx_count == 1)
			return -EINVAL;
	}

	if (ch->rx_count != old_rx) {
		ret = hfi2_netdev_set_active_ctxts(priv->ppd, ch->rx_count);
		if (ret)
			return ret;
	}

	ret = netif_set_real_num_queues(dev, ch->tx_count, ch->rx_count);
	if (ret && ch->rx_count != old_rx)
		WARN_ON_ONCE(hfi2_netdev_set_active_ctxts(priv->ppd, old_rx));

	return ret;
}

static int hfi2_ipoib_setup_rn(struct ib_device *device,
			       u32 port_num,
			       struct net_device *netdev,
			       void *param)
{
	struct hfi2_devdata *dd = dd_from_ibdev(device);
	struct rdma_netdev *rn = netdev_priv(netdev);
	struct hfi2_ipoib_dev_priv *priv;
	int rc;

	rn->send = hfi2_ipoib_send;
	rn->tx_timeout = hfi2_ipoib_tx_timeout;
	rn->attach_mcast = hfi2_ipoib_mcast_attach;
	rn->detach_mcast = hfi2_ipoib_mcast_detach;
	rn->set_id = hfi2_ipoib_set_id;
	rn->hca = device;
	rn->port_num = port_num;
	rn->mtu = netdev->mtu;

	priv = hfi2_ipoib_priv(netdev);
	priv->dd = dd;
	priv->ppd = &dd->pport[port_num - 1];
	priv->netdev = netdev;
	priv->device = device;
	priv->port_num = port_num;
	priv->netdev_ops = netdev->netdev_ops;
	if (ipoib_tx_mode < 0)
		priv->tx_mode = dd->bulksvc ? HFI2_IPOIB_TX_MODE_HFISVC :
					      HFI2_IPOIB_TX_MODE_AIP;
	else
		priv->tx_mode = ipoib_tx_mode;

	ib_query_pkey(device, port_num, priv->pkey_index, &priv->pkey);

	hfi2_ipoib_select_tx_mode(priv);

	rc = hfi2_ipoib_txreq_init(priv);
	if (rc) {
		dd_dev_err(dd, "IPoIB netdev TX init - failed(%d)\n", rc);
		return rc;
	}

	rc = hfi2_ipoib_rxq_init(netdev);
	if (rc) {
		dd_dev_err(dd, "IPoIB netdev RX init - failed(%d)\n", rc);
		hfi2_ipoib_txreq_deinit(priv);
		return rc;
	}

	netdev->netdev_ops = &hfi2_ipoib_netdev_ops;

	priv->ethtool_ops = *netdev->ethtool_ops;
	priv->ethtool_ops.get_channels = hfi2_ipoib_get_channels;
	priv->ethtool_ops.set_channels = hfi2_ipoib_set_channels;
	netdev->ethtool_ops = &priv->ethtool_ops;

	/* Transmit checksums and TSO are done in software by the driver. */
	netdev->hw_features |= NETIF_F_IP_CSUM;
	if (priv->tx_mode == HFI2_IPOIB_TX_MODE_HFISVC)
		netdev->hw_features |= NETIF_F_TSO;
	netdev->features |= netdev->hw_features;

	netif_set_tso_max_size(netdev, HFI2_IPOIB_GSO_MAX_SIZE);
	netif_set_tso_max_segs(netdev, HFI2_IPOIB_TSO_MAX_SEGS);


	if (ipoib_napi_threaded) {
		int rc;

		rc = dev_set_threaded(netdev, NETDEV_NAPI_THREADED_ENABLED);

		if (rc)
			dd_dev_warn(priv->dd,
				    "Failed to enable threaded NAPI: %d\n", rc);
	}

	netdev->priv_destructor = hfi2_ipoib_netdev_dtor;
	netdev->needs_free_netdev = true;
	netdev->pcpu_stat_type = NETDEV_PCPU_STAT_TSTATS;

	return 0;
}

int hfi2_ipoib_rn_get_params(struct ib_device *device,
			     u32 port_num,
			     enum rdma_netdev_t type,
			     struct rdma_netdev_alloc_params *params)
{
	struct hfi2_devdata *dd = dd_from_ibdev(device);
	struct hfi2_devrsrcs *dr = &dd->rsrcs;
	struct hfi2_portrsrcs *pr;
	unsigned int txqs;

	if (type != RDMA_NETDEV_IPOIB)
		return -EOPNOTSUPP;

	if (!port_num || port_num > dd->num_pports)
		return -EINVAL;
	pr = &dr->ppr[port_num - 1];

	if (dd->is_sriov || !HFI2_CAP_IS_KSET(AIP) || !pr->num_netdev_contexts)
		return -EOPNOTSUPP;

	txqs = cpumask_weight(cpumask_of_node(dd->node));
	if (!txqs)
		txqs = num_online_cpus();
	txqs = clamp(txqs, 1U, HFI2_IPOIB_MAX_TXQS);

	params->sizeof_priv = sizeof(struct hfi2_ipoib_rdma_netdev);
	params->txqs = txqs;
	params->rxqs = pr->num_netdev_contexts;
	params->param = NULL;
	params->initialize_rdma_netdev = hfi2_ipoib_setup_rn;

	return 0;
}
