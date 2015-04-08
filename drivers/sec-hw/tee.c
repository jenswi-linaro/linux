/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sec-hw/tee_drv.h>
#include "tee_private.h"

static int tee_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct tee_device *teedev;
	struct tee_context *ctx;

	teedev = container_of(filp->private_data, struct tee_device, miscdev);
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->teedev = teedev;
	filp->private_data = ctx;
	ret = teedev->desc->ops->open(ctx);
	if (ret)
		kfree(ctx);
	return ret;
}

static int tee_release(struct inode *inode, struct file *filp)
{
	struct tee_context *ctx = filp->private_data;

	/* Free all shm:s related to this ctx */
	tee_shm_free_by_tee_context(ctx);

	ctx->teedev->desc->ops->release(ctx);
	return 0;
}

static long tee_ioctl_version(struct tee_context *ctx,
		struct tee_ioctl_version __user *uvers)
{
	struct tee_ioctl_version vers;

	memset(&vers, 0, sizeof(vers));
	vers.gen_version = TEE_SUBSYS_VERSION;
	ctx->teedev->desc->ops->get_version(ctx, &vers.spec_version,
					    vers.uuid);

	return copy_to_user(uvers, &vers, sizeof(vers));
}

static long tee_ioctl_cmd(struct tee_context *ctx,
		struct tee_ioctl_cmd_data __user *ucmd)
{
	long ret;
	struct tee_ioctl_cmd_data cmd;
	void __user *buf_ptr;

	ret = copy_from_user(&cmd, ucmd, sizeof(cmd));
	if (ret)
		return ret;

	buf_ptr = (void __user *)(uintptr_t)cmd.buf_ptr;
	return ctx->teedev->desc->ops->cmd(ctx, buf_ptr, cmd.buf_len);
}

static long tee_ioctl_shm_alloc(struct tee_context *ctx,
		struct tee_ioctl_shm_alloc_data __user *udata)
{
	long ret;
	struct tee_ioctl_shm_alloc_data data;
	struct tee_shm *shm;

	if (copy_from_user(&data, udata, sizeof(data)))
		return -EFAULT;

	/* Currently no input flags are supported */
	if (data.flags)
		return -EINVAL;

	data.fd = -1;

	shm = tee_shm_alloc(ctx->teedev, ctx, data.size,
			    TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	ret = ctx->teedev->desc->ops->shm_share(shm);
	if (ret)
		goto err;

	data.flags = shm->flags;
	data.size = shm->size;
	data.fd = tee_shm_fd(shm);
	if (data.fd < 0) {
		ret = data.fd;
		goto err;
	}

	if (copy_to_user(udata, &data, sizeof(data))) {
		ret = -EFAULT;
		goto err;
	}
	/*
	 * When user space closes the file descriptor the shared memory
	 * should be freed
	 */
	tee_shm_put(shm);
	return 0;
err:
	if (data.fd >= 0)
		tee_shm_put_fd(data.fd);
	tee_shm_free(shm);
	return ret;
}

static long tee_ioctl_mem_share(struct tee_context *ctx,
		struct tee_ioctl_mem_share_data __user *udata)
{
	/* Not supported yet */
	return -ENOENT;
}

static long tee_ioctl_mem_unshare(struct tee_context *ctx,
		struct tee_ioctl_mem_share_data __user *udata)
{
	/* Not supported yet */
	return -ENOENT;
}

static long tee_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct tee_context *ctx = filp->private_data;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case TEE_IOC_VERSION:
		return tee_ioctl_version(ctx, uarg);
	case TEE_IOC_CMD:
		return tee_ioctl_cmd(ctx, uarg);
	case TEE_IOC_SHM_ALLOC:
		return tee_ioctl_shm_alloc(ctx, uarg);
	case TEE_IOC_MEM_SHARE:
		return tee_ioctl_mem_share(ctx, uarg);
	case TEE_IOC_MEM_UNSHARE:
		return tee_ioctl_mem_unshare(ctx, uarg);
	default:
		return -EINVAL;
	}
}


static const struct file_operations tee_fops = {
	.owner = THIS_MODULE,
	.open = tee_open,
	.release = tee_release,
	.unlocked_ioctl = tee_ioctl
};

struct tee_device *tee_register(const struct tee_desc *teedesc,
			struct device *dev, struct tee_shm_pool *pool,
			void *driver_data)
{
	static atomic_t device_no = ATOMIC_INIT(-1);
	static atomic_t priv_device_no = ATOMIC_INIT(-1);
	struct tee_device *teedev;
	int ret;

	if (!teedesc || !teedesc->name || !dev || !pool)
		return NULL;

	teedev = kzalloc(sizeof(*teedev), GFP_KERNEL);
	if (!teedev)
		return NULL;

	teedev->dev = dev;
	teedev->desc = teedesc;
	teedev->pool = pool;
	teedev->driver_data = driver_data;

	if (teedesc->flags & TEE_DESC_PRIVILEGED)
		snprintf(teedev->name, sizeof(teedev->name),
			 "teepriv%d", atomic_inc_return(&priv_device_no));
	else
		snprintf(teedev->name, sizeof(teedev->name),
			 "tee%d", atomic_inc_return(&device_no));

	teedev->miscdev.parent = dev;
	teedev->miscdev.minor = MISC_DYNAMIC_MINOR;
	teedev->miscdev.name = teedev->name;
	teedev->miscdev.fops = &tee_fops;

	ret = misc_register(&teedev->miscdev);
	if (ret) {
		dev_err(dev, "misc_register() failed name=\"%s\"\n",
			teedev->name);
		goto err;
	}

	INIT_LIST_HEAD(&teedev->list_shm);
	teedev->teectx_private.teedev = teedev;

	dev_set_drvdata(teedev->miscdev.this_device, teedev);

	dev_info(dev, "register misc device \"%s\" (minor=%d)\n",
		 dev_name(teedev->miscdev.this_device), teedev->miscdev.minor);

	return teedev;
err:
	kfree(teedev);
	return NULL;
}
EXPORT_SYMBOL_GPL(tee_register);

void tee_unregister(struct tee_device *teedev)
{
	if (!teedev)
		return;

	dev_info(teedev->dev, "unregister misc device \"%s\" (minor=%d)\n",
		 dev_name(teedev->miscdev.this_device), teedev->miscdev.minor);
	misc_deregister(&teedev->miscdev);
	/* TODO finish this function */
}
EXPORT_SYMBOL_GPL(tee_unregister);

void *tee_get_drvdata(struct tee_device *teedev)
{
	return teedev->driver_data;
}
EXPORT_SYMBOL_GPL(tee_get_drvdata);

static int __init tee_init(void)
{
	pr_info("initialized tee subsystem\n");
	return 0;
}

core_initcall(tee_init);
