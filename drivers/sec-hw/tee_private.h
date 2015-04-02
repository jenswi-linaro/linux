/* * Copyright (c) 2015, Linaro Limited
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
#ifndef TEE_PRIVATE_H
#define TEE_PRIVATE_H

struct tee_device;

struct tee_shm {
	struct list_head list_node;
	struct tee_filp *teefilp;
	phys_addr_t paddr;
	void *kaddr;
	size_t size;
	struct dma_buf *dmabuf;
	struct page *pages;
	u32 flags;
};

struct tee_shm_pool_mgr;
struct tee_shm_pool_mgr_ops {
	int (*alloc)(struct tee_shm_pool_mgr *poolmgr, struct tee_shm *shm,
		     size_t size);
	void (*free)(struct tee_shm_pool_mgr *poolmgr, struct tee_shm *shm);
};

struct tee_shm_pool_mgr {
	const struct tee_shm_pool_mgr_ops *ops;
	void *private_data;
};

struct tee_shm_pool {
	struct tee_shm_pool_mgr private_mgr;
	struct tee_shm_pool_mgr dma_buf_mgr;
	void *private_data;
};

#define TEE_MAX_DEV_NAME_LEN 32
struct tee_device {
	char name[TEE_MAX_DEV_NAME_LEN];
	const struct tee_desc *desc;
	struct device *dev;
	struct miscdevice miscdev;

	void *driver_data;

	struct list_head list_shm;
	struct tee_filp teefilp_private;
	struct tee_shm_pool *pool;
};

void tee_shm_free_by_teefilp(struct tee_filp *teefilp);

int tee_shm_init(void);

#endif /*TEE_PRIVATE_H*/
