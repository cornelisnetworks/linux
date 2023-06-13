// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2023 - Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific functions and variables.
 */

#include "hfi.h"

/*
 * Control the port LED state.  Cancel with gen_shutdown_led_override().
 */
void gen_setextled(struct hfi1_pportdata *ppd, u32 on)
{
	/* XXX Replace with a CPORT message */
	dd_dev_warn(ppd->dd, "%s: on %d, JKR TODO\n", __func__, on);
}

/*
 * Make the port LED blink in pattern.  Parameters timeon and timeoff are
 * in milliseconds.  Cancel with gen_shutdown_led_override().
 */
void gen_start_led_override(struct hfi1_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff)
{
	/* XXX Replace with a CPORT message */
	dd_dev_warn(ppd->dd, "%s: JKR TODO\n", __func__);

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 1);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}

/*
 * Return to normal LED operation.  This cancels overrides started with
 * gen_setextled() or gen_start_led_override().
 */
void gen_shutdown_led_override(struct hfi1_pportdata *ppd)
{
	/* XXX Replace with a CPORT message */
	dd_dev_warn(ppd->dd, "%s: JKR TODO\n", __func__);

	/* used by the subnet manager to know if it set beaconing */
	atomic_set(&ppd->led_override_timer_active, 0);
	/* ensure the atomic_set is visible to all CPUs */
	smp_wmb();
}
