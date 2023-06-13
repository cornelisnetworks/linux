/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright(c) 2023 Cornelis Networks, Inc.
 *
 * Generalized (parameterized) chip specific declaractions.
 */

#ifndef _CHIP_GEN_H
#define _CHIP_GEN_H

void gen_setextled(struct hfi1_pportdata *ppd, u32 on);
void gen_start_led_override(struct hfi1_pportdata *ppd, unsigned int timeon,
			    unsigned int timeoff);
void gen_shutdown_led_override(struct hfi1_pportdata *ppd);

#endif /* _CHIP_GEN_H */
