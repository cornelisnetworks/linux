// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 * Copyright(c) 2024 Cornelis Networks, Inc.
 */

#include "hfi.h"
#include "uverbs.h"
#include "file_ops.h"

int hfi1_alloc_ucontext(struct ib_ucontext *ucontext, struct ib_udata *udata)
{
	struct hfi1_devdata *dd = dd_from_ibdev(ucontext->device);
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = hfi1_alloc_filedata(dd);
	if (!fd)
		return -ENOMEM;

	rcontext->priv = fd;

	return 0;
}

void hfi1_dealloc_ucontext(struct ib_ucontext *ucontext)
{
	struct rvt_ucontext *rcontext = container_of(ucontext, struct rvt_ucontext, ibucontext);
	struct hfi1_filedata *fd;

	fd = rcontext->priv;
	if (fd) {
		hfi1_dealloc_filedata(fd);
		rcontext->priv = NULL;
	}
}
