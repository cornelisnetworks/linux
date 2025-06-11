/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright(c) 2015, 2016 Intel Corporation.
 */

#ifndef _HFI2_DEVICE_H
#define _HFI2_DEVICE_H

int hfi2_cdev_init(int minor, const char *name,
		   const struct file_operations *fops,
		   struct cdev *cdev, struct device **devp,
		   bool user_accessible,
		   struct kobject *parent);
void hfi2_cdev_cleanup(struct cdev *cdev, struct device **devp);
int __init dev_init(void);
void dev_cleanup(void);

#endif                          /* _HFI2_DEVICE_H */
