/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2016, 2017 Intel Corporation.
 */


#define RDI_DEV_ENTRY(rdi)   __string(dev, rvt_get_ibdev_name(rdi))
#define RDI_DEV_ASSIGN(rdi)  __assign_str(dev)

#include "trace_rvt_events.h"
#include "trace_rvt_qp.h"
#include "trace_rvt_tx.h"
#include "trace_rvt_mr.h"
#include "trace_rvt_cq.h"
#include "trace_rvt_rc.h"
