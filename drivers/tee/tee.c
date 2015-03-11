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
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/tee_drv.h>
#include "tee_private.h"

#define TEE_NUM_DEVICES	32

/*
 * Unprivileged devices in the in the lower half range and privileged
 * devices in the upper half range.
 */
static DECLARE_BITMAP(dev_mask, TEE_NUM_DEVICES);
static DEFINE_SPINLOCK(driver_lock);

static struct class *tee_class;
static dev_t tee_devt;

static int tee_open(struct inode *inode, struct file *filp)
{
	int rc;
	struct tee_device *teedev;
	struct tee_context *ctx;

	teedev = container_of(inode->i_cdev, struct tee_device, cdev);
	if (!down_read_trylock(&teedev->rwsem))
		return -EINVAL;
	if (!teedev->desc) {
		/* teedev has been detached from driver */
		up_read(&teedev->rwsem);
		return -EINVAL;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->teedev = teedev;
	filp->private_data = ctx;
	rc = teedev->desc->ops->open(ctx);
	if (rc) {
		kfree(ctx);
		up_read(&teedev->rwsem);
	}
	return rc;
}

static int tee_release(struct inode *inode, struct file *filp)
{
	struct tee_context *ctx = filp->private_data;
	struct tee_device *teedev = ctx->teedev;

	ctx->teedev->desc->ops->release(ctx);
	kfree(ctx);
	up_read(&teedev->rwsem);
	return 0;
}

static long tee_ioctl_version(struct tee_context *ctx,
		struct tee_ioctl_version_data __user *uvers)
{
	return ctx->teedev->desc->ops->get_version(ctx, uvers);
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

	shm = tee_shm_alloc(ctx->teedev, data.size,
			    TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	ret = ctx->teedev->desc->ops->shm_share(shm);
	if (ret)
		goto err;

	data.flags = shm->flags;
	data.size = shm->size;
	data.fd = tee_shm_get_fd(shm);
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
	default:
		return -EINVAL;
	}
}

static const struct file_operations tee_fops = {
	.open = tee_open,
	.release = tee_release,
	.unlocked_ioctl = tee_ioctl,
	.compat_ioctl = tee_ioctl,
};

static void tee_release_device(struct device *dev)
{
	struct tee_device *teedev = container_of(dev, struct tee_device, dev);

	spin_lock(&driver_lock);
	clear_bit(teedev->id, dev_mask);
	spin_unlock(&driver_lock);
	kfree(teedev);
}

struct tee_device *tee_device_alloc(const struct tee_desc *teedesc,
			struct device *dev, struct tee_shm_pool *pool,
			void *driver_data)
{
	struct tee_device *teedev;
	void *ret;
	int rc;
	int offs = 0;

	if (!teedesc || !teedesc->name || !dev || !pool) {
		ret = ERR_PTR(-EINVAL);
		goto err;
	}

	teedev = kzalloc(sizeof(*teedev), GFP_KERNEL);
	if (!teedev) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	if (teedesc->flags & TEE_DESC_PRIVILEGED)
		offs = TEE_NUM_DEVICES / 2;

	spin_lock(&driver_lock);
	teedev->id = find_next_zero_bit(dev_mask, TEE_NUM_DEVICES, offs);
	if (teedev->id < TEE_NUM_DEVICES)
		set_bit(teedev->id, dev_mask);
	spin_unlock(&driver_lock);

	if (teedev->id >= TEE_NUM_DEVICES) {
		ret = ERR_PTR(-ENOMEM);
		goto err;
	}

	snprintf(teedev->name, sizeof(teedev->name), "tee%s%d",
		 teedesc->flags & TEE_DESC_PRIVILEGED ? "priv" : "",
		 teedev->id - offs);

	teedev->dev.class = tee_class;
	teedev->dev.release = tee_release_device;
	teedev->dev.parent = dev;
	teedev->dev.devt = MKDEV(MAJOR(tee_devt), teedev->id);

	rc = dev_set_name(&teedev->dev, "%s", teedev->name);
	if (rc) {
		ret = ERR_PTR(rc);
		goto err;
	}

	cdev_init(&teedev->cdev, &tee_fops);
	teedev->cdev.owner = teedesc->owner;

	dev_set_drvdata(&teedev->dev, driver_data);
	device_initialize(&teedev->dev);

	init_rwsem(&teedev->rwsem);
	teedev->desc = teedesc;
	teedev->pool = pool;
	INIT_LIST_HEAD(&teedev->list_shm);

	return teedev;
err:
	dev_err(dev, "could not register %s driver\n",
		teedesc->flags & TEE_DESC_PRIVILEGED ? "privileged" : "client");
	if (teedev) {
		spin_lock(&driver_lock);
		clear_bit(teedev->id, dev_mask);
		spin_unlock(&driver_lock);
		kfree(teedev);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tee_device_alloc);


int tee_device_register(struct tee_device *teedev)
{
	int rc;

	rc = cdev_add(&teedev->cdev, teedev->dev.devt, 1);
	if (rc) {
		dev_err(&teedev->dev,
			"unable to cdev_add() %s, major %d, minor %d, err=%d\n",
			teedev->name, MAJOR(teedev->dev.devt),
			MINOR(teedev->dev.devt), rc);

		device_unregister(&teedev->dev);
		return rc;
	}

	rc = device_add(&teedev->dev);
	if (rc) {
		dev_err(&teedev->dev,
			"unable to device_add() %s, major %d, minor %d, err=%d\n",
			teedev->name, MAJOR(teedev->dev.devt),
			MINOR(teedev->dev.devt), rc);
		cdev_del(&teedev->cdev);
		device_unregister(&teedev->dev);
		return rc;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(tee_device_register);

void tee_device_unregister(struct tee_device *teedev)
{
	if (!teedev)
		return;

	get_device(&teedev->dev);

	cdev_del(&teedev->cdev);
	device_unregister(&teedev->dev);

	/*
	 * We'll block in down_write() until all file descriptors to the
	 * device and all shared memory used by user space and secure world
	 * is released.
	 */
	down_write(&teedev->rwsem);
	teedev->desc = NULL;
	teedev->pool = NULL;
	up_write(&teedev->rwsem);

	put_device(&teedev->dev);
}
EXPORT_SYMBOL_GPL(tee_device_unregister);

void *tee_get_drvdata(struct tee_device *teedev)
{
	return dev_get_drvdata(&teedev->dev);
}
EXPORT_SYMBOL_GPL(tee_get_drvdata);

static int __init tee_init(void)
{
	int rc;

	tee_class = class_create(THIS_MODULE, "tee");
	if (IS_ERR(tee_class)) {
		pr_err("couldn't create class\n");
		return PTR_ERR(tee_class);
	}

	rc = alloc_chrdev_region(&tee_devt, 0, TEE_NUM_DEVICES, "tee");
	if (rc < 0) {
		pr_err("failed to allocate char dev region\n");
		class_destroy(tee_class);
		tee_class = NULL;
	}

	return rc;
}

subsys_initcall(tee_init);
