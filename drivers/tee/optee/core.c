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
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dma-contiguous.h>
#ifdef CONFIG_OPTEE_USE_CMA
#include <linux/cma.h>
#endif
#include <linux/io.h>
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "optee_smc.h"

#define DRIVER_NAME "optee"

bool optee_param_is(struct opteem_param *param, uint32_t flags)
{
	static const u8 attr_flags[] = {
		[OPTEEM_ATTR_TYPE_NONE]		 = 0,
		[OPTEEM_ATTR_TYPE_VALUE_INPUT]	 = PARAM_VALUE | PARAM_IN,
		[OPTEEM_ATTR_TYPE_VALUE_OUTPUT]	 = PARAM_VALUE | PARAM_OUT,
		[OPTEEM_ATTR_TYPE_VALUE_INOUT]	 = PARAM_VALUE | PARAM_IN |
						   PARAM_OUT,
		[OPTEEM_ATTR_TYPE_MEMREF_INPUT]	 = PARAM_MEMREF | PARAM_IN,
		[OPTEEM_ATTR_TYPE_MEMREF_OUTPUT] = PARAM_MEMREF | PARAM_OUT,
		[OPTEEM_ATTR_TYPE_MEMREF_INOUT]	 = PARAM_MEMREF | PARAM_IN |
						   PARAM_OUT,
	};
	int idx = param->attr & OPTEEM_ATTR_TYPE_MASK;
	u32 masked;

	if (idx >= sizeof(attr_flags))
		return false;

	masked = attr_flags[idx] & flags;
	return (masked & PARAM_ANY) && (masked & PARAM_INOUT);
}

static void optee_get_smc_version(struct optee_smc_param *param)
{
	param->a0 = OPTEE_SMC_CALLS_UID;
	optee_smc(param);
}

static int optee_get_version(struct tee_context *ctx,
			struct tee_ioctl_version_data __user *vers)
{
	struct optee_smc_param param;

	optee_get_smc_version(&param);
	/* The first 4 words in param are the UUID of protocol */
	return copy_to_user(vers, &param, sizeof(*vers));
}

static int optee_open(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata;

	ctxdata = kzalloc(sizeof(*ctxdata), GFP_KERNEL);
	if (!ctxdata)
		return -ENOMEM;

	mutex_init(&ctxdata->mutex);
	INIT_LIST_HEAD(&ctxdata->sess_list);

	ctx->data = ctxdata;
	return 0;
}

static void optee_release(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct opteem_arg *arg = NULL;
	phys_addr_t parg;

	if (!ctxdata)
		return;

	shm = tee_shm_alloc(ctx->teedev, sizeof(struct opteem_arg),
			    TEE_SHM_MAPPED);
	if (!IS_ERR(shm)) {
		arg = tee_shm_get_va(shm, 0);
		/*
		 * If va2pa fails for some reason, we can't call
		 * optee_close_session(), only free the memory. Secure OS
		 * will leak sessions and finally refuse more session, but
		 * we will at least let normal world reclaim its memory.
		 */
		if (!IS_ERR(arg))
			tee_shm_va2pa(shm, arg, &parg);
	}

	while (true) {
		struct optee_session *sess;

		sess = list_first_entry_or_null(&ctxdata->sess_list,
						struct optee_session,
						list_node);
		if (!sess)
			break;
		list_del(&sess->list_node);
		if (!IS_ERR_OR_NULL(arg)) {
			memset(arg, 0, sizeof(*arg));
			arg->cmd = OPTEEM_CMD_CLOSE_SESSION;
			arg->session = sess->session_id;
			optee_do_call_with_arg(ctx, parg);
		}
		kfree(sess);
	}
	kfree(ctxdata);

	if (!IS_ERR(shm))
		tee_shm_free(shm);

	ctx->data = NULL;
}

static int optee_cmd_raw_fastcall(u32 smc_id, struct opteem_cmd_prefix *arg,
		size_t len)
{
	struct optee_smc_param param = { .a0 = smc_id };
	u32 *data = (u32 *)(arg + 1);
	size_t data_len = len - sizeof(*arg);

	if (data_len < 4 * sizeof(u32))
		return -EINVAL;

	/* This is a fast-call no need to take a mutex */

	optee_smc(&param);
	data[0] = param.a0;
	data[1] = param.a1;
	data[2] = param.a2;
	data[3] = param.a3;
	return 0;
}

static int optee_cmd(struct tee_context *ctx, void __user *buf, size_t len)
{
	struct opteem_cmd_prefix *arg;
	struct tee_shm *shm;
	int ret;

	if (len > OPTEE_MAX_ARG_SIZE || len < sizeof(*arg))
		return -EINVAL;

	shm = tee_shm_alloc(ctx->teedev, len, TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	arg = tee_shm_get_va(shm, 0);
	if (IS_ERR(arg) || copy_from_user(arg, buf, len)) {
		ret = -EINVAL;
		goto out;
	}

	switch (arg->func_id) {
	case OPTEEM_FUNCID_CALLS_UID:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALLS_UID, arg, len);
		break;
	case OPTEEM_FUNCID_GET_OS_UUID:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALL_GET_OS_UUID,
					     arg, len);
		break;
	case OPTEEM_FUNCID_CALLS_REVISION:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALLS_REVISION,
					     arg, len);
		break;
	case OPTEEM_FUNCID_GET_OS_REVISION:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALL_GET_OS_REVISION,
					     arg, len);
		break;
	case OPTEEM_FUNCID_CALL_WITH_ARG:
		ret = optee_cmd_call_with_arg(ctx, shm, arg, buf, len);
		goto out_from_call;
	default:
		ret = -EINVAL;
		goto out;
	}

out:
	if (!ret) {
		if (copy_to_user(buf, arg, len))
			ret = -EINVAL;
	}
out_from_call:
	tee_shm_free(shm);
	return ret;
}

static struct tee_driver_ops optee_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.cmd = optee_cmd,
};

static struct tee_desc optee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_ops,
	.owner = THIS_MODULE,
};

static int optee_supp_req(struct tee_context *ctx, void __user *buf,
			size_t len)
{
	struct opteem_cmd_prefix *arg;
	struct tee_shm *shm;
	int ret;

	if (len > OPTEE_MAX_ARG_SIZE || len < sizeof(*arg))
		return -EINVAL;

	shm = tee_shm_alloc(ctx->teedev, len, TEE_SHM_MAPPED);
	if (IS_ERR(shm)) {
		ret = PTR_ERR(shm);
		goto out;
	}

	arg = tee_shm_get_va(shm, 0);
	if (IS_ERR(arg) || copy_from_user(arg, buf, len)) {
		ret = -EINVAL;
		goto out;
	}

	switch (arg->func_id) {
	case OPTEEM_FUNCID_CALLS_UID:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALLS_UID, arg, len);
		break;
	case OPTEEM_FUNCID_GET_OS_UUID:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALL_GET_OS_UUID,
					     arg, len);
		break;
	case OPTEEM_FUNCID_CALLS_REVISION:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALLS_REVISION,
					     arg, len);
		break;
	case OPTEEM_FUNCID_GET_OS_REVISION:
		ret = optee_cmd_raw_fastcall(OPTEE_SMC_CALL_GET_OS_REVISION,
					     arg, len);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret)
		goto out;

	if (copy_to_user(buf, arg, len))
		ret = -EINVAL;
out:
	if (!IS_ERR(shm))
		tee_shm_free(shm);
	return ret;
}

static int optee_supp_cmd(struct tee_context *ctx, void __user *buf,
			size_t len)
{
	struct opteem_cmd_prefix arg;

	if (len < sizeof(arg) || copy_from_user(&arg, buf, sizeof(arg)))
		return -EINVAL;

	switch (arg.func_id) {
	case OPTEEM_FUNCID_SUPP_CMD_WRITE:
		return optee_supp_write(ctx, buf + sizeof(arg),
					len - sizeof(arg));
	case OPTEEM_FUNCID_SUPP_CMD_READ:
		return optee_supp_read(ctx, buf + sizeof(arg),
				       len - sizeof(arg));
	default:
		return optee_supp_req(ctx, buf, len);
	}
}

static struct tee_driver_ops optee_supp_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.cmd = optee_supp_cmd,
};

static struct tee_desc optee_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static bool opteem_api_uid_is_optee_api(void)
{
	struct optee_smc_param param;

	optee_get_smc_version(&param);

	if (param.a0 == OPTEEM_UID_0 && param.a1 == OPTEEM_UID_1 &&
	    param.a2 == OPTEEM_UID_2 && param.a3 == OPTEEM_UID_3)
		return true;
	return false;
}

static bool opteem_api_revision_is_compatible(void)
{
	struct optee_smc_param param = { .a0 = OPTEE_SMC_CALLS_REVISION };

	optee_smc(&param);

	if (param.a0 == OPTEEM_REVISION_MAJOR &&
	    (int)param.a1 >= OPTEEM_REVISION_MINOR)
		return true;
	return false;
}

static struct tee_shm_pool *optee_config_shm_ioremap(struct device *dev,
			void **ioremaped_shm)
{
	struct optee_smc_param param = { .a0 = OPTEE_SMC_GET_SHM_CONFIG };
	struct tee_shm_pool *pool;
	u_long vaddr;
	phys_addr_t paddr;
	size_t size;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;

	optee_smc(&param);
	if (param.a0 != OPTEE_SMC_RETURN_OK) {
		dev_info(dev, "shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (param.a3 != OPTEE_SMC_SHM_CACHED) {
		dev_err(dev, "only normal cached shared memory supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(param.a1, PAGE_SIZE);
	end = rounddown(param.a1 + param.a2, PAGE_SIZE);
	paddr = begin;
	size = end - begin;

	va = ioremap_cache(paddr, size);
	if (!va) {
		dev_err(dev, "shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
	vaddr = (u_long)va;

	pool = tee_shm_pool_alloc_res_mem(dev, vaddr, paddr, size);
	if (IS_ERR(pool))
		iounmap(va);
	else
		*ioremaped_shm = va;
	return pool;
}

#ifdef CONFIG_OPTEE_USE_CMA
static struct tee_shm_pool *optee_config_shm_cma(struct device *dev)
{
	struct optee_smc_param param = { .a0 = OPTEE_SMC_REGISTER_SHM };
	u_long vaddr;
	phys_addr_t paddr;
	size_t size;
	struct tee_shm_pool *pool;

	pool = tee_shm_pool_alloc(dev, &vaddr, &paddr, &size);
	if (IS_ERR(pool))
		return pool;

	reg_pair_from_64(&param.a1, &param.a2, paddr);
	param.a3 = size;
	param.a4 = OPTEE_SMC_SHM_CACHED;
	optee_smc(&param);
	if (param.a0 != OPTEE_SMC_RETURN_OK) {
		dev_err(dev, "can't register shared memory\n");
		tee_shm_pool_free(pool);
		return ERR_PTR(-EINVAL);
	}
	return pool;
}
#else
static struct tee_shm_pool *optee_config_shm_cma(struct device *dev)
{
	return ERR_PTR(-ENOENT);
}
#endif

static int optee_probe(struct platform_device *pdev)
{
	struct tee_shm_pool *pool;
	struct optee *optee = NULL;
	void *ioremaped_shm = NULL;
	int rc;

	if (!opteem_api_uid_is_optee_api() ||
	    !opteem_api_revision_is_compatible())
		return -EINVAL;

	pool = optee_config_shm_ioremap(&pdev->dev, &ioremaped_shm);
	if (IS_ERR(pool))
		pool = optee_config_shm_cma(&pdev->dev);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	optee = devm_kzalloc(&pdev->dev, sizeof(*optee), GFP_KERNEL);
	if (!optee) {
		rc = -ENOMEM;
		goto err;
	}

	optee->dev = &pdev->dev;

	optee->teedev = tee_device_alloc(&optee_desc, &pdev->dev, pool, optee);
	if (IS_ERR(optee->teedev)) {
		rc = PTR_ERR(optee->teedev);
		goto err;
	}

	optee->supp_teedev = tee_device_alloc(&optee_supp_desc, &pdev->dev,
					      pool, optee);
	if (IS_ERR(optee->supp_teedev)) {
		rc = PTR_ERR(optee->supp_teedev);
		goto err;
	}

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err;

	mutex_init(&optee->callsync.mutex);
	init_completion(&optee->callsync.c);
	optee->callsync.c_waiters = 0;
	optee_mutex_wait_init(&optee->mutex_wait);
	optee_supp_init(&optee->supp);
	optee->ioremaped_shm = ioremaped_shm;
	optee->pool = pool;

	platform_set_drvdata(pdev, optee);

	dev_info(&pdev->dev, "initialized driver\n");
	return 0;
err:
	tee_device_unregister(optee->teedev);
	tee_device_unregister(optee->supp_teedev);
	if (pool)
		tee_shm_pool_free(pool);
	if (ioremaped_shm)
		iounmap(optee->ioremaped_shm);
	return rc;
}

static int optee_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	tee_device_unregister(optee->teedev);
	tee_device_unregister(optee->supp_teedev);
	tee_shm_pool_free(optee->pool);
	if (optee->ioremaped_shm)
		iounmap(optee->ioremaped_shm);
	optee_mutex_wait_uninit(&optee->mutex_wait);
	optee_supp_uninit(&optee->supp);
	mutex_destroy(&optee->callsync.mutex);
	return 0;
}

static const struct of_device_id optee_match[] = {
	{ .compatible = "optee,optee-tz" },
	{},
};

static struct platform_driver optee_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = optee_match,
	},
	.probe = optee_probe,
	.remove = optee_remove,
};

module_platform_driver(optee_driver);

MODULE_AUTHOR("Linaro");
MODULE_DESCRIPTION("OP-TEE driver");
MODULE_SUPPORTED_DEVICE("");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
