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
#include <linux/tee/tee_drv.h>
#include "optee_private.h"

#define DRIVER_NAME "tee-optee"

struct put_shm {
	struct tee_shm **shm;
	size_t num_shm;
};

static u32 do_call_with_arg(struct tee_context *ctx, u32 funcid,
			phys_addr_t parg);

bool optee_param_is(struct teesmc_param *param, uint32_t flags)
{
	static const u8 attr_flags[] = {
		[TEESMC_ATTR_TYPE_NONE]		 = 0,
		[TEESMC_ATTR_TYPE_VALUE_INPUT]	 = PARAM_VALUE | PARAM_IN,
		[TEESMC_ATTR_TYPE_VALUE_OUTPUT]	 = PARAM_VALUE | PARAM_OUT,
		[TEESMC_ATTR_TYPE_VALUE_INOUT]	 = PARAM_VALUE | PARAM_IN |
						   PARAM_OUT,
		[TEESMC_ATTR_TYPE_MEMREF_INPUT]	 = PARAM_MEMREF | PARAM_IN,
		[TEESMC_ATTR_TYPE_MEMREF_OUTPUT] = PARAM_MEMREF | PARAM_OUT,
		[TEESMC_ATTR_TYPE_MEMREF_INOUT]	 = PARAM_MEMREF | PARAM_IN |
						   PARAM_OUT,
	};
	int idx = param->attr & TEESMC_ATTR_TYPE_MASK;
	u32 masked;

	if (idx >= sizeof(attr_flags))
		return false;

	masked = attr_flags[idx] & flags;
	return (masked & PARAM_ANY) && (masked & PARAM_INOUT);
}

static void optee_call_lock(struct optee_call_sync *callsync)
{
	mutex_lock(&callsync->mutex);
}

static void optee_call_lock_wait_completion(struct optee_call_sync *callsync)
{
	/*
	 * Release the lock until "something happens" and then reacquire it
	 * again.
	 *
	 * This is needed when TEE returns "busy" and we need to try again
	 * later.
	 */
	callsync->c_waiters++;
	mutex_unlock(&callsync->mutex);
	/*
	 * Wait at most one second. Secure world is normally never busy
	 * more than that so we should normally never timeout.
	 */
	wait_for_completion_timeout(&callsync->c, HZ);
	mutex_lock(&callsync->mutex);
	callsync->c_waiters--;
}

static void optee_call_unlock(struct optee_call_sync *callsync)
{
	/*
	 * If at least one thread is waiting for "something to happen" let
	 * one thread know that "something has happened".
	 */
	if (callsync->c_waiters)
		complete(&callsync->c);
	mutex_unlock(&callsync->mutex);
}

static void optee_get_version(struct tee_context *ctx,
		u32 *version, u8 *uuid)
{
	*version = OPTEE_VERSION;
	memset(uuid, 0, TEE_UUID_SIZE);
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
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct teesmc_arg *arg = NULL;
	phys_addr_t parg;

	if (!ctxdata)
		return;

	shm = tee_shm_alloc(ctx->teedev, sizeof(struct teesmc_arg),
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

		/*
		 * TODO: Do we need to lock the context data when it's
		 * about to be released?
		 */
		sess = list_first_entry_or_null(&ctxdata->sess_list,
						struct optee_session,
						list_node);
		if (!sess)
			break;
		list_del(&sess->list_node);
		if (!IS_ERR_OR_NULL(arg)) {
			dev_dbg(optee->dev, "%s: closing session 0x%x\n",
				__func__, sess->session_id);
			memset(arg, 0, sizeof(*arg));
			arg->cmd = TEESMC_CMD_CLOSE_SESSION;
			arg->session = sess->session_id;
			do_call_with_arg(ctx, TEESMC32_CALL_WITH_ARG, parg);
		}
		kfree(sess);
	}
	kfree(ctxdata);

	if (!IS_ERR(shm))
		tee_shm_free(shm);

	ctx->data = NULL;
}

static int optee_cmd_raw_fastcall32(struct optee_cmd_prefix *arg, size_t len)
{
	struct optee_smc_param param = { .a0 = arg->smc_id };
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

static int teesmc_arg_from_user(struct teesmc_arg *arg, size_t size,
			struct put_shm *put_shm)
{
	struct teesmc_param *param;
	size_t n;
	size_t s = TEESMC_GET_ARG_SIZE(arg->num_params);

	if (size < sizeof(struct teesmc_arg))
		return -EINVAL;
	if (size != s)
		return -EINVAL;

	if (!arg->num_params) {
		put_shm->shm = NULL;
		return 0;
	}
	param = TEESMC_GET_PARAMS(arg);

	put_shm->shm = kcalloc(arg->num_params, sizeof(struct tee_shm *),
			       GFP_KERNEL);
	if (!put_shm->shm)
		return -ENOMEM;
	put_shm->num_shm = arg->num_params;

	for (n = 0; n < arg->num_params; n++) {
		struct tee_shm *shm;
		u32 shm_offs;
		phys_addr_t pa;
		int ret;

		if (param[n].attr & ~(TEESMC_ATTR_TYPE_MASK | TEESMC_ATTR_META))
			return -EINVAL;

		if (optee_param_is(param + n, PARAM_MEMREF | PARAM_INOUT)) {
			shm_offs = param[n].u.memref.buf_ptr;
			shm = tee_shm_get_from_fd(
					(int)param[n].u.memref.shm_ref);
			if (IS_ERR(shm))
				return PTR_ERR(shm);
			put_shm->shm[n] = shm;
			ret = tee_shm_get_pa(shm, shm_offs, &pa);
			if (ret)
				return ret;
			param[n].u.memref.buf_ptr = pa;
		}
	}

	return 0;
}

static int teesmc_arg_to_user(struct teesmc_arg *arg,
			struct teesmc_arg __user *uarg)
{
	struct teesmc_param *param = TEESMC_GET_PARAMS(arg);
	struct teesmc_param __user *uparam = (void __user *)(uarg + 1);
	size_t n;

	if (arg->cmd == TEESMC_CMD_OPEN_SESSION &&
	    put_user(arg->session, &uarg->session))
		return -EINVAL;
	if (put_user(arg->ret, &uarg->ret) ||
	    put_user(arg->ret_origin, &uarg->ret_origin))
		return -EINVAL;

	for (n = 0; n < arg->num_params; n++) {
		struct teesmc_param *p = param + n;
		struct teesmc_param __user *up = uparam + n;

		if (optee_param_is(p, PARAM_VALUE | PARAM_OUT)) {
			if (put_user(p->u.value.a, &up->u.value.a) ||
			    put_user(p->u.value.b, &up->u.value.b))
				return -EINVAL;
		} else if (optee_param_is(p, PARAM_MEMREF | PARAM_OUT)) {
			if (put_user(p->u.memref.size, &up->u.memref.size))
				return -EINVAL;
		}
	}
	return 0;
}

static u32 do_call_with_arg(struct tee_context *ctx, u32 funcid,
			phys_addr_t parg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	u32 ret;
	struct optee_smc_param param = { };

	reg_pair_from_64(&param.a1, &param.a2, parg);
	optee_call_lock(&optee->callsync);
	while (true) {
		param.a0 = funcid;

		optee_smc(&param);
		ret = param.a0;

		if (ret == TEESMC_RETURN_EBUSY) {
			/*
			 * Since secure world returned busy, release the
			 * lock we had when entering this function and wait
			 * for "something to happen" (something else to
			 * exit from secure world and needed resources may
			 * have become available).
			 */
			optee_call_lock_wait_completion(&optee->callsync);
		} else if (TEESMC_RETURN_IS_RPC(ret)) {
			/* Process the RPC. */
			optee_call_unlock(&optee->callsync);
			funcid = optee_handle_rpc(ctx, &param);
			optee_call_lock(&optee->callsync);
		} else {
			break;
		}
	}
	optee_call_unlock(&optee->callsync);
	return ret;
}

/* Requires the filpstate mutex to be held */
static struct optee_session *find_session(struct optee_context_data *ctxdata,
			u32 session_id)
{
	struct optee_session *sess;

	list_for_each_entry(sess, &ctxdata->sess_list, list_node)
		if (sess->session_id == session_id)
			return sess;
	return NULL;
}

static int optee_cmd_call_with_arg(struct tee_context *ctx,
			struct tee_shm *shm, struct optee_cmd_prefix *arg,
			struct optee_cmd_prefix __user *uarg, size_t len)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_context_data *ctxdata = ctx->data;
	struct put_shm put_shm = { .shm = NULL };
	struct teesmc_arg *teesmc_arg;
	struct teesmc_arg __user *teesmc_uarg;
	struct optee_session *sess;
	phys_addr_t teesmc_parg;
	int ret;
	size_t n;

	teesmc_arg = (struct teesmc_arg *)(arg + 1);
	teesmc_uarg = (struct teesmc_arg __user *)(uarg + 1);

	ret = teesmc_arg_from_user(teesmc_arg, len - sizeof(*arg),
				   &put_shm);
	if (ret)
		goto out;

	ret = tee_shm_va2pa(shm, teesmc_arg, &teesmc_parg);
	if (ret)
		goto out;

	switch (teesmc_arg->cmd) {
	case TEESMC_CMD_OPEN_SESSION:
		/* Allocate memory to be able to store the new session below. */
		sess = kzalloc(sizeof(struct optee_session), GFP_KERNEL);
		if (!sess) {
			ret = -ENOMEM;
			goto out;
		}
		break;
	case TEESMC_CMD_CLOSE_SESSION:
		/* A session is about to be closed, remove it from the list */
		dev_dbg(optee->dev, "%s: closing session 0x%x\n",
			__func__, teesmc_arg->session);
		mutex_lock(&ctxdata->mutex);
		sess = find_session(ctxdata, teesmc_arg->session);
		if (sess) {
			list_del(&sess->list_node);
			kfree(sess);
		}
		mutex_unlock(&ctxdata->mutex);
		if (!sess) {
			ret = -EINVAL;
			goto out;
		}
		sess = NULL;
		break;

	case TEESMC_CMD_INVOKE_COMMAND:
	case TEESMC_CMD_CANCEL:
		mutex_lock(&ctxdata->mutex);
		sess = find_session(ctxdata, teesmc_arg->session);
		mutex_unlock(&ctxdata->mutex);
		if (!sess) {
			ret = -EINVAL;
			goto out;
		}
		sess = NULL;
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	if (do_call_with_arg(ctx, arg->smc_id, teesmc_parg)) {
		teesmc_arg->ret = TEEC_ERROR_COMMUNICATION;
		teesmc_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	ret = teesmc_arg_to_user(teesmc_arg, teesmc_uarg);

	if (sess) {
		/* A new session has been created, add it to the list. */
		if (teesmc_arg->ret == TEEC_SUCCESS) {
			sess->session_id = teesmc_arg->session;
			mutex_lock(&ctxdata->mutex);
			list_add(&sess->list_node, &ctxdata->sess_list);
			mutex_unlock(&ctxdata->mutex);
		} else
			kfree(sess);
	}
out:
	if (put_shm.shm) {
		for (n = 0; n < put_shm.num_shm; n++)
			if (put_shm.shm[n])
				tee_shm_put(put_shm.shm[n]);
		kfree(put_shm.shm);
	}
	return ret;
}

static int optee_cmd(struct tee_context *ctx, void __user *buf, size_t len)
{
	struct optee_cmd_prefix *arg;
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

	switch (arg->smc_id) {
	case TEESMC32_CALLS_UID:
	case TEESMC32_CALL_GET_OS_UUID:
	case TEESMC32_CALLS_REVISION:
	case TEESMC32_CALL_GET_OS_REVISION:
		ret = optee_cmd_raw_fastcall32(arg, len);
		goto out;
	case TEESMC32_CALL_WITH_ARG:
	case TEESMC32_FASTCALL_WITH_ARG:
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

static int optee_shm_share(struct tee_shm *shm)
{
	/* No special action needed to share memory with OP-TEE */
	return 0;
}

static void optee_shm_unshare(struct tee_shm *shm)
{
}

static struct tee_driver_ops optee_ops = {
	.get_version = optee_get_version,
	.open = optee_open,
	.release = optee_release,
	.cmd = optee_cmd,
	.shm_share = optee_shm_share,
	.shm_unshare = optee_shm_unshare,
};

static struct tee_desc optee_desc = {
	.name = DRIVER_NAME "-clnt",
	.ops = &optee_ops,
	.owner = THIS_MODULE,
};

static int optee_supp_req(struct tee_context *ctx, void __user *buf,
			size_t len)
{
	struct optee_cmd_prefix *arg;
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

	switch (arg->smc_id) {
	case TEESMC32_CALLS_UID:
	case TEESMC32_CALL_GET_OS_UUID:
	case TEESMC32_CALLS_REVISION:
	case TEESMC32_CALL_GET_OS_REVISION:
		ret = optee_cmd_raw_fastcall32(arg, len);
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
	struct optee_cmd_prefix arg;

	if (len < sizeof(arg) || copy_from_user(&arg, buf, sizeof(arg)))
		return -EINVAL;

	switch (arg.smc_id) {
	case OPTEE_SUPP_CMD_WRITE:
		return optee_supp_write(ctx, buf + sizeof(arg),
					len - sizeof(arg));
	case OPTEE_SUPP_CMD_READ:
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
	.shm_share = optee_shm_share,
	.shm_unshare = optee_shm_unshare,
};

static struct tee_desc optee_supp_desc = {
	.name = DRIVER_NAME "-supp",
	.ops = &optee_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static bool teesmc_api_uid_is_optee_api(void)
{
	struct optee_smc_param param = { .a0 = TEESMC32_CALLS_UID };

	optee_smc(&param);

	if (param.a0 == TEESMC_OPTEE_UID_R0 &&
	    param.a1 == TEESMC_OPTEE_UID_R1 &&
	    param.a2 == TEESMC_OPTEE_UID_R2 &&
	    param.a3 == TEESMC_OPTEE_UID_R3)
		return true;
	return false;
}

static bool teesmc_api_revision_is_compatible(void)
{
	struct optee_smc_param param = { .a0 = TEESMC32_CALLS_REVISION };

	optee_smc(&param);

	if (param.a0 == TEESMC_OPTEE_REVISION_MAJOR &&
	    (int)param.a1 >= TEESMC_OPTEE_REVISION_MINOR)
		return true;
	return false;
}

static struct tee_shm_pool *optee_config_shm_ioremap(struct device *dev,
			u_long *vaddr, phys_addr_t *paddr, size_t *size,
			void **ioremaped_shm)
{
	struct optee_smc_param param = {
		.a0 = TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG
	};
	struct tee_shm_pool *pool;
	phys_addr_t begin;
	phys_addr_t end;
	void *va;

	optee_smc(&param);
	if (param.a0 != TEESMC_RETURN_OK) {
		dev_info(dev, "shm service not available\n");
		return ERR_PTR(-ENOENT);
	}

	if (!param.a3) {
		dev_err(dev, "Uncached shared memory not supported\n");
		return ERR_PTR(-EINVAL);
	}

	begin = roundup(param.a1, PAGE_SIZE);
	end = rounddown(param.a1 + param.a2, PAGE_SIZE);
	*paddr = begin;
	*size = end - begin;

	va = ioremap_cache(*paddr, *size);
	if (!va) {
		dev_err(dev, "shared memory ioremap failed\n");
		return ERR_PTR(-EINVAL);
	}
	*vaddr = (u_long)va;

	pool = tee_shm_pool_alloc_res_mem(dev, *vaddr, *paddr, *size);
	if (IS_ERR(pool))
		iounmap(va);
	else
		*ioremaped_shm = va;
	return pool;
}

#ifdef CONFIG_OPTEE_USE_CMA
static struct tee_shm_pool *optee_config_shm_cma(struct device *dev,
			u_long *vaddr, phys_addr_t *paddr, size_t *size)
{
	return tee_shm_pool_alloc_cma(dev, vaddr, paddr, size);
}
#else
static struct tee_shm_pool *optee_config_shm_cma(struct device *dev,
			u_long *vaddr, phys_addr_t *paddr, size_t *size)
{
	return ERR_PTR(-ENOENT);
}
#endif

static int optee_probe(struct platform_device *pdev)
{
	struct tee_shm_pool *pool;
	struct optee *optee = NULL;
	void *ioremaped_shm = NULL;
	u_long vaddr;
	phys_addr_t paddr;
	size_t size;
	int ret;

	if (!teesmc_api_uid_is_optee_api() ||
	    !teesmc_api_revision_is_compatible())
		return -EINVAL;

	pool = optee_config_shm_ioremap(&pdev->dev, &vaddr, &paddr, &size,
					&ioremaped_shm);
	if (IS_ERR(pool))
		pool = optee_config_shm_cma(&pdev->dev, &vaddr, &paddr, &size);
	if (IS_ERR(pool))
		return PTR_ERR(pool);

	optee = devm_kzalloc(&pdev->dev, sizeof(*optee), GFP_KERNEL);
	if (!optee) {
		ret = -ENOMEM;
		goto err;
	}

	optee->dev = &pdev->dev;

	optee->teedev = tee_register(&optee_desc, &pdev->dev, pool, optee);
	if (IS_ERR(optee->teedev)) {
		ret = PTR_ERR(optee->teedev);
		goto err;
	}

	optee->supp_teedev = tee_register(&optee_supp_desc, &pdev->dev, pool,
					  optee);
	if (!optee->teedev) {
		ret = PTR_ERR(optee->teedev);
		goto err;
	}

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
	if (optee && optee->teedev)
		tee_unregister(optee->teedev);
	if (pool)
		tee_shm_pool_free(pool);
	return ret;
}

static int optee_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	tee_unregister(optee->teedev);
	tee_unregister(optee->supp_teedev);
	tee_shm_pool_free(optee->pool);
	if (optee->ioremaped_shm)
		iounmap(optee->ioremaped_shm);
	optee_mutex_wait_exit(&optee->mutex_wait);
	optee_supp_exit(&optee->supp);
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
