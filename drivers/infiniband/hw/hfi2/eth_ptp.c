// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Ethernet Precision Time Protocol implementation.
 */

#include <linux/net_tstamp.h>
#include <linux/timekeeping.h>
#include <linux/ptp_classify.h>
#include <linux/clocksource.h>
#include <linux/ptp_clock_kernel.h>

#include "eth_main.h"

#define CNE_TOD_CLK_PERIOD	0x9A09A1ULL

/* Backoff between egress timestamp capture polls (see cne_ptp_tx_task). */
#define CNE_PTP_TX_POLL_DELAY	msecs_to_jiffies(1)

#define CNE_TOD_PERIOD_ADJ_DEFAULT 1000000

u32 tod_period_adj = CNE_TOD_PERIOD_ADJ_DEFAULT;

static ktime_t init_time;
static struct timespec64 init_ts;

/**
 * cne_get_tod - get current Time Of Day clock value
 * @edev - Ethernet device
 * @ts - timespec in which to store time
 * @sts - optional system-timestamp snapshot to bracket the TOD read (may be NULL)
 *
 * Returns zero (success).
 */
static int cne_get_tod(struct ether_device *edev,
		       struct timespec64 *ts,
		       struct ptp_system_timestamp *sts)
{
	u64 tod0;
	u64 tod1;
	u64 tod2;
	u64 tod1_recheck;
	u64 tod2_recheck;
	u64 sec;
	u64 nsec;
	u64 frac;

	/* The CUR_TOD0/1/2 registers are plain read-only fields with no
	 * snapshot-on-read latch: reading CUR_TOD0 does not freeze CUR_TOD1/2.
	 */
	do {
		ptp_read_system_prets(sts);
		tod2 = hfi2_read_csr(edev->ppd->dd, TOD_CUR_TOD2_OFFSET);
		tod1 = hfi2_read_csr(edev->ppd->dd, TOD_CUR_TOD1_OFFSET);
		tod0 = hfi2_read_csr(edev->ppd->dd, TOD_CUR_TOD0_OFFSET);
		ptp_read_system_postts(sts);
		tod1_recheck = hfi2_read_csr(edev->ppd->dd, TOD_CUR_TOD1_OFFSET);
		tod2_recheck = hfi2_read_csr(edev->ppd->dd, TOD_CUR_TOD2_OFFSET);
	} while (tod1 != tod1_recheck || tod2 != tod2_recheck);

	sec = (tod2 << 16) | TOD1_GET_SEC_LSB(tod1);
	nsec = (TOD1_GET_NS_MSB(tod1) << 16) | TOD0_GET_NS_LSB(tod0);
	frac = TOD0_GET_FRAC_NS(tod0);

	pdbg(edev, timer, "TOD %llu.%llu.%llu\n", sec, nsec, frac);

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;

	/* Round up nsec based on fraction of nsec */
	if (frac >= 0x8000) {
		ts->tv_nsec++;
		if (ts->tv_nsec >= NSEC_PER_SEC) {
			ts->tv_nsec -= NSEC_PER_SEC;
			ts->tv_sec++;
		}
	}

	return 0;
}

/**
 * cne_set_tod - set Time Of Day clock
 * @edev: Etherner device
 * @ts - time
 */
static void cne_set_tod(struct ether_device *edev,
			const struct timespec64 *ts)
{
	u32 ctrl;
	u32 tod0 = 0;
	u32 tod1 = 0;
	u32 tod2;

	pdbg(edev, timer, "tv_sec %lld tv_nsec %ld\n", ts->tv_sec, ts->tv_nsec);

	/* Configure the TOD clock. */
	TOD0_SET_FRAC_NS(tod0, 0);
	TOD0_SET_NS_LSB(tod0, ts->tv_nsec & 0xffff);
	hfi2_write_csr(edev->ppd->dd, TOD_SW_FRC_TOD0_OFFSET, tod0);
	TOD1_SET_NS_MSB(tod1, ts->tv_nsec >> 16);
	TOD1_SET_SEC_LSB(tod1, ts->tv_sec & 0xffff);
	hfi2_write_csr(edev->ppd->dd, TOD_SW_FRC_TOD1_OFFSET, tod1);
	tod2 = ts->tv_sec >> 16;
	hfi2_write_csr(edev->ppd->dd, TOD_SW_FRC_TOD2_OFFSET, tod2);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
	CONTROL_SET_FORCE_SW_TOD_UPDATE(ctrl, 0);
	hfi2_write_csr(edev->ppd->dd, TOD_CONTROL_OFFSET, ctrl);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
	CONTROL_SET_FORCE_SW_TOD_UPDATE(ctrl, 1);
	hfi2_write_csr(edev->ppd->dd, TOD_CONTROL_OFFSET, ctrl);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
}

#define OMEGA_SCALED_PPM_DENOM	(65536ULL * 1000000ULL) /*  2^16 * 1e6 */
#define CNE_ACC_TIME_ADJ_NS_MAX	127ULL

static int cne_ptp_adjfine(struct ptp_clock_info *ptp_info,
			   long _scaled_ppm)
{
	u32 ctrl;
	u32 time_adj = 0;
	u64 neg = _scaled_ppm < 0 ? 1 : 0;
	u64 scaled_ppm = abs(_scaled_ppm);
	struct ether_device *edev = container_of(ptp_info, struct ether_device, ptp_info);
	u64 period_ns24 = (u64)edev->ptp_period_adj * CNE_TOD_CLK_PERIOD;
	u64 delta_ns24 = mul_u64_u64_div_u64(scaled_ppm, period_ns24, OMEGA_SCALED_PPM_DENOM);
	delta_ns24 = min(delta_ns24, CNE_ACC_TIME_ADJ_NS_MAX << 24);
	u32 ns = (u32)(delta_ns24 >> 24);
	u32 ns_fraction = (u32)(delta_ns24 & 0xFFFFFFu);

	pdbg(edev, timer, "%s ptp_adjfine scaled_ppm %ld ns %u\n", ptp_info->name, _scaled_ppm, ns);

	mutex_lock(&edev->ptp_lock);

	ACC_TIME_ADJ_SET_FRAC(time_adj, ns_fraction);
	ACC_TIME_ADJ_SET_NS(time_adj, ns);
	ACC_TIME_ADJ_SET_SIGN(time_adj, neg);
	hfi2_write_csr(edev->ppd->dd, TOD_ACC_TIME_ADJ, time_adj);

	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
	CONTROL_SET_FORCE_SW_TOD_ADJ_PARA_UPDATE(ctrl, 0);
	hfi2_write_csr(edev->ppd->dd, TOD_CONTROL_OFFSET, ctrl);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
	CONTROL_SET_FORCE_SW_TOD_ADJ_PARA_UPDATE(ctrl, 1);
	hfi2_write_csr(edev->ppd->dd, TOD_CONTROL_OFFSET, ctrl);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);

	mutex_unlock(&edev->ptp_lock);

	return 0;
}

/**
 * cne_ptp_adjtime - shift TOD clock
 * @ptp_info: PTP clock
 * @delta: desired shift in nanoseconds
 *
 * Returns zero (success).
 */
static int cne_ptp_adjtime(struct ptp_clock_info *ptp_info,
			   s64 delta)
{
	struct timespec64 cur;
	struct timespec64 target = ns_to_timespec64(delta);
	struct ether_device *edev = container_of(ptp_info, struct ether_device,
						ptp_info);

	if (!delta)
		return 0;

	pdbg(edev, timer, "%s ptp_adjtime delta %lld\n", ptp_info->name, delta);

	mutex_lock(&edev->ptp_lock);
	cne_get_tod(edev, &cur, NULL);
	target = timespec64_add(cur, target);
	cne_set_tod(edev, &target);
	mutex_unlock(&edev->ptp_lock);

	return 0;
}

/**
 * cne_ptp_enable - enable/disable PTP feature
 * @ptp_info: PTP clock
 * @rq: request
 * @on: on or off?
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_ptp_enable(struct ptp_clock_info *ptp_info,
			  struct ptp_clock_request *rq,
			  int on)
{
	struct ether_device *edev = container_of(ptp_info, struct ether_device,
						ptp_info);

	pdbg(edev, hw, "%s %s feature type %u\n", ptp_info->name,
	     on ? "enabling" : "disabling", rq->type);

	return -EOPNOTSUPP;
}

/**
 * cne_ptp_get_ts_config - get PTP configuration
 * @ndev: network device
 * @ifr: IOCTL
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_ptp_get_ts_config(struct net_device *ndev,
			  struct ifreq *ifr)
{
	struct hwtstamp_config config;
	struct ether_device *edev = netdev_priv(ndev);

	if (!edev->ptp_clock)
		return -EOPNOTSUPP;  /* not supported on VFs */

	mutex_lock(&edev->ptp_lock);
	config = edev->ptp_config;
	mutex_unlock(&edev->ptp_lock);

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

/**
 * cne_ptp_gettimex64 - get time
 * @ptp_info: PTP clock
 * @ts: time
 * @sts: system time
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_ptp_gettimex64(struct ptp_clock_info *ptp_info,
			      struct timespec64 *ts,
			      struct ptp_system_timestamp *sts)
{
	struct ether_device *edev = container_of(ptp_info, struct ether_device, ptp_info);

	mutex_lock(&edev->ptp_lock);
	cne_get_tod(edev, ts, sts);
	mutex_unlock(&edev->ptp_lock);

	return 0;
}

/**
 * cne_ptp_config_tod - program the TOD engine for 2-step operation
 * @edev: Ethernet device
 */
static void cne_ptp_config_tod(struct ether_device *edev)
{
	u32 ctrl;

	hfi2_write_csr(edev->ppd->dd, TOD_CLK_PERIOD_OFFSET, CNE_TOD_CLK_PERIOD);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);
	CONTROL_SET_AUTO_TOD_UP_MODE(ctrl, 0);
	CONTROL_SET_AUTO_TOD_UP_ENABLE(ctrl, 0);
	hfi2_write_csr(edev->ppd->dd, TOD_ACC_PERIOD_ADJ, edev->ptp_period_adj);
	hfi2_write_csr(edev->ppd->dd, TOD_CONTROL_OFFSET, ctrl);
}

/**
 * cne_ptp_check_tod - restore the TOD engine if it was reset
 * @edev: Ethernet device
 *
 * The TOD engine registers have been seen at their reset values after
 * cne_ptp_init(), with the clock period at zero and the TOD frozen.
 * Reprogram them when that happens.  Called with ptp_lock held when
 * timestamping is configured or the time is set.
 */
static void cne_ptp_check_tod(struct ether_device *edev)
{
	u64 period;
	u64 period_adj;
	u64 ctrl;

	lockdep_assert_held(&edev->ptp_lock);

	period = hfi2_read_csr(edev->ppd->dd, TOD_CLK_PERIOD_OFFSET);
	period_adj = hfi2_read_csr(edev->ppd->dd, TOD_ACC_PERIOD_ADJ);
	ctrl = hfi2_read_csr(edev->ppd->dd, TOD_CONTROL_OFFSET);

	if (period == CNE_TOD_CLK_PERIOD &&
	    period_adj == edev->ptp_period_adj &&
	    !CONTROL_GET_AUTO_TOD_UP_MODE(ctrl) &&
	    !CONTROL_GET_AUTO_TOD_UP_ENABLE(ctrl))
		return;

	netdev_warn(edev->ndev,
		    "TOD engine reset (period 0x%llx adj %llu control 0x%llx), reprogramming\n",
		    period, period_adj, ctrl);
	cne_ptp_config_tod(edev);
}

/**
 * cne_ptp_set_ts_config - ioctl interface to control timestamps
 * @ndev: network device
 * @ifr: IOCTL request
 *
 * Returns zero on success, -ERRNO otherwise.
 */
int cne_ptp_set_ts_config(struct net_device *ndev,
			  struct ifreq *ifr)
{
	bool enable_ts;
	u64 mask;
	u64 ptp_pf_cfg0;
	u64 ptp_cfg;
	struct hwtstamp_config config;
	struct ether_device *edev = netdev_priv(ndev);

	if (!edev->ptp_clock)
		return -EOPNOTSUPP; /* not supported on VFs */

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config))) {
		netdev_err(ndev, "copy_from_user failed\n");
		return -EFAULT;
	}

	switch (config.tx_type) {
	case HWTSTAMP_TX_OFF:
	case HWTSTAMP_TX_ON:
		break;
	case HWTSTAMP_TX_ONESTEP_SYNC:
		fallthrough;
	default:
		netdev_err(ndev, "tx_type 0x%x not supported\n", config.tx_type);
		return -ERANGE;
	}

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		enable_ts = false;
		break;
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		enable_ts = true;
		break;
	case HWTSTAMP_FILTER_NTP_ALL:
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		fallthrough;
	default:
		netdev_warn(ndev, "rx_type 0x%x not supported\n", config.rx_filter);
		config.rx_filter = HWTSTAMP_FILTER_NONE;
		return -ERANGE;
	}

	mutex_lock(&edev->ptp_lock);

	cne_ptp_check_tod(edev);

	ptp_pf_cfg0 = hfi2_read_csr(edev->ppd->dd, CYR_EAL_1588_PTP_PF_CFG0);
	switch (CNE_RX_TS_SIZE) {
	case 8:
		EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_SIZE(ptp_pf_cfg0,
							EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_8B);
		break;
	case 10:
		EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_SIZE(ptp_pf_cfg0,
							EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_10B);
		break;
	default:
		EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_SIZE(ptp_pf_cfg0,
							EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_12B);
	}
	EAL_1588_PTP_PF_CFG0_SET_PTP_MASTER(ptp_pf_cfg0, 0);

	mask = EAL_1588_PTP_PF_CFG0_GET_PTP_RX_TS_ENB_MASK(ptp_pf_cfg0);
	if (enable_ts)
		mask |= BIT(0);
	else
		mask &= ~BIT(0);
	EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_ENB_MASK(ptp_pf_cfg0, mask);
	hfi2_write_csr(edev->ppd->dd, CYR_EAL_1588_PTP_PF_CFG0, ptp_pf_cfg0);

	ptp_cfg = hfi2_read_csr(edev->ppd->dd, CYR_EAL_1588_PTP_CFG);
	if (enable_ts)
		ptp_cfg |= EAL_1588_PTP_CFG_PTP_RX_TS_ENABLE;
	else
		ptp_cfg &= ~EAL_1588_PTP_CFG_PTP_RX_TS_ENABLE;
	hfi2_write_csr(edev->ppd->dd, CYR_EAL_1588_PTP_CFG, ptp_cfg);

	WRITE_ONCE(edev->ptp_config.flags, config.flags);
	WRITE_ONCE(edev->ptp_config.tx_type, config.tx_type);
	WRITE_ONCE(edev->ptp_config.rx_filter, config.rx_filter);

	mutex_unlock(&edev->ptp_lock);

	return copy_to_user(ifr->ifr_data, &config, sizeof(config)) ? -EFAULT : 0;
}

/**
 * cne_ptp_settime64 - set time
 * @ptp_info: PTP clock
 * @ts: time
 *
 * Returns zero on success, -ERRNO otherwise.
 */
static int cne_ptp_settime64(struct ptp_clock_info *ptp_info,
			     const struct timespec64 *ts)
{
	struct ether_device *edev = container_of(ptp_info, struct ether_device, ptp_info);

	mutex_lock(&edev->ptp_lock);
	cne_ptp_check_tod(edev);
	cne_set_tod(edev, ts);
	mutex_unlock(&edev->ptp_lock);

	return 0;
}

/**
 * cne_ptp_tx_task - check for timestamps in flight
 * @work: work queue
 */
static void cne_ptp_tx_task(struct work_struct *work)
{
	struct skb_shared_hwtstamps shhwtstamps = {};
	struct ether_device *edev = container_of(to_delayed_work(work),
						 struct ether_device, ptp_tx_work);
	struct sk_buff *skb = READ_ONCE(edev->ptp_tx_skb);
	bool deliver = false;
	bool reschedule = false;
	u64 tx_capture_tod;

	if (!skb)
		return;

	mutex_lock(&edev->ptp_lock);

	/* Timestamp timeout? */
	if (time_is_before_jiffies64(READ_ONCE(edev->ptp_tx_start) + HZ * 8)) {
		pdbg(edev, timer, "SKB timestamp timeout\n");
		WRITE_ONCE(edev->ptp_tx_skb, NULL);
		clear_bit_unlock(1, &edev->ptp_in_progress);
		goto out;
	}

	/* Timestamp taken yet? */
	tx_capture_tod = hfi2_read_csr(edev->ppd->dd, CYR_TX_CAPTURE_TOD);
	if (tx_capture_tod != edev->ptp_last_tod) {
		edev->ptp_last_tod = tx_capture_tod;
		shhwtstamps.hwtstamp = ktime_set(edev->ptp_last_tod >> 32,
						 edev->ptp_last_tod & 0xffffffff);
		WRITE_ONCE(edev->ptp_tx_skb, NULL);
		clear_bit_unlock(1, &edev->ptp_in_progress);
		deliver = true;
	} else {
		 /* Timestamp not taken yet.  check again later */
		reschedule = true;
	}

out:
	mutex_unlock(&edev->ptp_lock);

	if (deliver)
		skb_tstamp_tx(skb, &shhwtstamps);

	if (reschedule)
		/* The egress timestamp is not captured yet.  Poll again. */
		schedule_delayed_work(&edev->ptp_tx_work, CNE_PTP_TX_POLL_DELAY);
	else
		dev_kfree_skb_any(skb);
}

/**
 * cne_ptp_init - register PTP clock and initialize PTP HW
 * @edev: Ethernet device
 */
void cne_ptp_init(struct ether_device *edev)
{
	struct ptp_clock *ptp_clock;

	if (tod_period_adj) {
		edev->ptp_period_adj = tod_period_adj;
	} else {
		edev->ptp_period_adj = CNE_TOD_PERIOD_ADJ_DEFAULT;
		netdev_warn(edev->ndev, "Zero tod_period_adj value invalid.  Defaulting to %u\n",
			    edev->ptp_period_adj);
	}

	snprintf(edev->ptp_info.name, sizeof(edev->ptp_info.name), "%s_clock", edev->ndev->name);
	edev->ptp_info.owner = THIS_MODULE;
	edev->ptp_info.max_adj = mul_u64_u64_div_u64(CNE_ACC_TIME_ADJ_NS_MAX << 24, NSEC_PER_SEC,
				    (u64)edev->ptp_period_adj * CNE_TOD_CLK_PERIOD);
	edev->ptp_info.n_ext_ts = 0;
	edev->ptp_info.n_per_out = 0;
	edev->ptp_info.n_pins = 0;
	edev->ptp_info.pps = 0;
	edev->ptp_info.adjfine = cne_ptp_adjfine;
	edev->ptp_info.adjtime = cne_ptp_adjtime;
	edev->ptp_info.gettimex64 = cne_ptp_gettimex64;
	edev->ptp_info.settime64 = cne_ptp_settime64;
	edev->ptp_info.enable = cne_ptp_enable;

	cne_ptp_config_tod(edev);

	/* Set initial TOD using the same time for all PHC clocks */
	if (!init_time) {
		init_time = ktime_get_real();
		init_ts = ktime_to_timespec64(init_time);
	}
	cne_set_tod(edev, &init_ts);

	mutex_init(&edev->ptp_lock);
	INIT_DELAYED_WORK(&edev->ptp_tx_work, cne_ptp_tx_task);
	edev->ptp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	edev->ptp_config.tx_type = HWTSTAMP_TX_OFF;
	edev->ptp_tx_skb = NULL;
	edev->ptp_in_progress = 0;
	edev->ptp_last_tod = 0;

	ptp_clock = ptp_clock_register(&edev->ptp_info, &edev->pdev->dev);
	if (IS_ERR_OR_NULL(ptp_clock)) {
		netdev_err(edev->ndev, "ptp_clock_register failed %ld\n", PTR_ERR(ptp_clock));
		cancel_delayed_work(&edev->ptp_tx_work);
		mutex_destroy(&edev->ptp_lock);
		return;
	}
	edev->ptp_clock = ptp_clock;

	pinfo(edev, drv, "added PHC %s at %llu ns with ACC_PERIOD_ADJ %u\n",
	      edev->ptp_info.name, init_time, edev->ptp_period_adj);
}

/**
 * cne_ptp_stop - unregister PTP clock, cancel related activity
 * @edev: Ethernet device
 */
void cne_ptp_stop(struct ether_device *edev)
{
	pdbg(edev, drv, "stopping %s\n", edev->ptp_info.name);

	if (edev->ptp_clock) {
		cancel_delayed_work_sync(&edev->ptp_tx_work);
		if (edev->ptp_tx_skb) {
			pwarn(edev, drv, "SKB (%p) timestamp in progress\n",
			      edev->ptp_tx_skb);
			dev_kfree_skb_any(edev->ptp_tx_skb);
			edev->ptp_tx_skb = NULL;
		}
		edev->ptp_in_progress = 0;
		ptp_clock_unregister(edev->ptp_clock);
		edev->ptp_clock = NULL;
		mutex_destroy(&edev->ptp_lock);
	}
}
