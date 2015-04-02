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
#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/genalloc.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#include <linux/dma-contiguous.h>
#endif
#include <linux/sec-hw/tee_drv.h>
#include "tee_private.h"

#define SHM_POOL_NUM_PRIV_PAGES 1

static int pool_op_gen_alloc(struct tee_shm_pool_mgr *poolm,
			struct tee_shm *shm, size_t size)
{
	unsigned long va;
	struct gen_pool *genpool = poolm->private_data;
	size_t s = roundup(size, 1 << genpool->min_alloc_order);

	va = gen_pool_alloc(genpool, s);
	if (!va)
		return -ENOMEM;
	shm->kaddr = (void *)va;
	shm->paddr = gen_pool_virt_to_phys(genpool, va);
	shm->size = s;
	return 0;
}

static void pool_op_gen_free(struct tee_shm_pool_mgr *poolm,
			struct tee_shm *shm)
{
	gen_pool_free(poolm->private_data, (unsigned long)shm->kaddr,
		      shm->size);
	shm->kaddr = NULL;
}

static const struct tee_shm_pool_mgr_ops pool_ops_generic = {
	.alloc = pool_op_gen_alloc,
	.free = pool_op_gen_free,
};

#ifdef CONFIG_CMA
static int pool_op_cma_alloc(struct tee_shm_pool_mgr *poolm,
			struct tee_shm *shm, size_t size)
{
	unsigned long order = get_order(PAGE_SIZE);
	size_t count;
	struct page *pages;

	/*
	 * It's not valid to call this function with size = 0, but if size
	 * is 0 we'll get a very large number and the allocation will fail.
	 */
	count = ((size - 1) >> PAGE_SHIFT) + 1;
	pages = cma_alloc(poolm->private_data, count, order);
	if (!pages)
		return -ENOMEM;
	shm->kaddr = page_address(pages);
	shm->pages = pages;
	shm->paddr = virt_to_phys(shm->kaddr);
	shm->size = count << PAGE_SHIFT;
	return 0;
}

static void pool_op_cma_free(struct tee_shm_pool_mgr *poolm,
			struct tee_shm *shm)
{
	size_t count;

	count = shm->size >> PAGE_SHIFT;
	cma_release(poolm->private_data, shm->pages, count);
	shm->kaddr = NULL;
}

static const struct tee_shm_pool_mgr_ops pool_ops_cma = {
	.alloc = pool_op_cma_alloc,
	.free = pool_op_cma_free,
};

struct tee_shm_pool *tee_shm_pool_alloc_cma(struct device *dev, u_long *vaddr,
			phys_addr_t *paddr, size_t *size)
{
	struct cma *cma = dev_get_cma_area(dev);
	struct tee_shm_pool *pool;
	struct page *page;
	size_t order = get_order(PAGE_SIZE);
	struct gen_pool *genpool = NULL;
	void *va;
	int ret;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);

	page = cma_alloc(cma, SHM_POOL_NUM_PRIV_PAGES, order);
	if (!page) {
		ret = -ENOMEM;
		goto err;
	}
	genpool = gen_pool_create(get_order(8), -1);
	if (!genpool) {
		ret = -ENOMEM;
		goto err;
	}
	gen_pool_set_algo(genpool, gen_pool_best_fit, NULL);

	va = page_address(page);
	ret = gen_pool_add_virt(genpool, (u_long)va, virt_to_phys(va),
				SHM_POOL_NUM_PRIV_PAGES * PAGE_SIZE, -1);
	if (ret)
		goto err;

	pool->private_data = page;
	pool->private_mgr.private_data = genpool;
	pool->private_mgr.ops = &pool_ops_generic;
	pool->dma_buf_mgr.private_data = cma;
	pool->dma_buf_mgr.ops = &pool_ops_cma;

	*paddr = cma_get_base(cma);
	*vaddr = (u_long)phys_to_virt(*paddr);
	*size = cma_get_size(cma);
	return pool;
err:
	if (genpool)
		gen_pool_destroy(genpool);
	if (page)
		cma_release(cma, page, SHM_POOL_NUM_PRIV_PAGES);
	kfree(pool);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tee_shm_pool_alloc_cma);
#endif

struct tee_shm_pool *tee_shm_pool_alloc_res_mem(u_long vaddr,
			phys_addr_t paddr, size_t size)
{
	size_t page_mask = PAGE_SIZE - 1;
	size_t priv_size = PAGE_SIZE * SHM_POOL_NUM_PRIV_PAGES;
	struct tee_shm_pool *pool;
	struct gen_pool *genpool = NULL;
	int ret;

	/*
	 * Start and end must be page aligned
	 */
	if ((vaddr & page_mask) || (paddr & page_mask) || (size & page_mask))
		return ERR_PTR(-EINVAL);

	/*
	 * Wouldn't make sense to have less than twice the number of
	 * private pages, in practice the size has to be much larger, but
	 * this is the absolute minimum.
	 */
	if (size < priv_size * 2)
		return ERR_PTR(-EINVAL);

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);

	/*
	 * Create the pool for driver private shared memory
	 */
	genpool = gen_pool_create(3 /* 8 byte aligned */, -1);
	if (!genpool) {
		ret = -ENOMEM;
		goto err;
	}
	gen_pool_set_algo(genpool, gen_pool_best_fit, NULL);
	ret = gen_pool_add_virt(genpool, vaddr, paddr, priv_size, -1);
	if (ret)
		goto err;
	pool->private_mgr.private_data = genpool;
	pool->private_mgr.ops = &pool_ops_generic;

	/*
	 * Create the pool for dma_buf shared memory
	 */
	genpool = gen_pool_create(PAGE_SHIFT, -1);
	gen_pool_set_algo(genpool, gen_pool_best_fit, NULL);
	if (!genpool) {
		ret = -ENOMEM;
		goto err;
	}
	ret = gen_pool_add_virt(genpool, vaddr + priv_size, paddr + priv_size,
				size - priv_size, -1);
	if (ret)
		goto err;
	pool->dma_buf_mgr.private_data = genpool;
	pool->dma_buf_mgr.ops = &pool_ops_generic;
	return pool;
err:
	if (pool->private_mgr.private_data)
		gen_pool_destroy(pool->private_mgr.private_data);
	if (genpool)
		gen_pool_destroy(genpool);
	kfree(pool);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tee_shm_pool_alloc_res_mem);

void tee_shm_pool_free(struct tee_shm_pool *pool)
{
#ifdef CONFIG_CMA
	if (pool->dma_buf_mgr.ops == &pool_ops_cma) {
		gen_pool_destroy(pool->private_mgr.private_data);
		cma_release(pool->dma_buf_mgr.private_data, pool->private_data,
			    SHM_POOL_NUM_PRIV_PAGES);
	} else
#endif
	if (pool->dma_buf_mgr.ops == &pool_ops_generic) {
		gen_pool_destroy(pool->private_mgr.private_data);
		gen_pool_destroy(pool->dma_buf_mgr.private_data);
	}

	kfree(pool);
}
EXPORT_SYMBOL_GPL(tee_shm_pool_free);
