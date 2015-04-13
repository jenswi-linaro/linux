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
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/tee/tee_drv.h>
#include "optee_private.h"

/*
 * Handled within the driver only
 * Keep aligned with optee_os (secure space)
 */
#define TEE_RPC_MUTEX_WAIT	0x20000000
#define TEE_RPC_WAIT		0x30000000

/* Parameters for TEE_RPC_WAIT_MUTEX above */
#define TEE_MUTEX_WAIT_SLEEP	0
#define TEE_MUTEX_WAIT_WAKEUP	1
#define TEE_MUTEX_WAIT_DELETE	2

/*
 * Compares two serial numbers using Serial Number Arithmetic
 * (https://www.ietf.org/rfc/rfc1982.txt).
 */
#define TICK_GT(t1, t2) \
	(((t1) < (t2) && (t2) - (t1) > 0xFFFFFFFFu) || \
	((t1) > (t2) && (t1) - (t2) < 0xFFFFFFFFu))

static struct optee_mutex_wait *optee_mutex_wait_get(struct device *dev,
				struct optee_mutex_wait_private *priv, u32 key)
{
	struct optee_mutex_wait *w;

	mutex_lock(&priv->mu);

	list_for_each_entry(w, &priv->db, link)
		if (w->key == key)
			goto out;

	w = kmalloc(sizeof(struct optee_mutex_wait), GFP_KERNEL);
	if (!w)
		goto out;

	init_completion(&w->comp);
	mutex_init(&w->mu);
	w->wait_after = 0;
	w->key = key;
	list_add_tail(&w->link, &priv->db);
out:
	mutex_unlock(&priv->mu);
	return w;
}

static void optee_mutex_wait_delete_entry(struct optee_mutex_wait *w)
{
	list_del(&w->link);
	mutex_destroy(&w->mu);
	kfree(w);
}

static void optee_mutex_wait_delete(struct device *dev,
			struct optee_mutex_wait_private *priv,
			u32 key)
{
	struct optee_mutex_wait *w;

	mutex_lock(&priv->mu);

	list_for_each_entry(w, &priv->db, link) {
		if (w->key == key) {
			optee_mutex_wait_delete_entry(w);
			break;
		}
	}

	mutex_unlock(&priv->mu);
}

static void optee_mutex_wait_wakeup(struct device *dev,
			struct optee_mutex_wait_private *priv,
			u32 key, u32 wait_after)
{
	struct optee_mutex_wait *w = optee_mutex_wait_get(dev, priv, key);

	if (!w)
		return;

	mutex_lock(&w->mu);
	w->wait_after = wait_after;
	mutex_unlock(&w->mu);
	complete(&w->comp);
}

static void optee_mutex_wait_sleep(struct device *dev,
			struct optee_mutex_wait_private *priv,
			u32 key, u32 wait_tick)
{
	struct optee_mutex_wait *w = optee_mutex_wait_get(dev, priv, key);
	u32 wait_after;

	if (!w)
		return;

	mutex_lock(&w->mu);
	wait_after = w->wait_after;
	mutex_unlock(&w->mu);

	if (TICK_GT(wait_tick, wait_after))
		wait_for_completion_timeout(&w->comp, HZ);
}

void optee_mutex_wait_init(struct optee_mutex_wait_private *priv)
{
	mutex_init(&priv->mu);
	INIT_LIST_HEAD(&priv->db);
}

void optee_mutex_wait_exit(struct optee_mutex_wait_private *priv)
{
	/*
	 * It's the callers responibility to ensure that no one is using
	 * anything inside priv.
	 */

	mutex_destroy(&priv->mu);
	while (!list_empty(&priv->db)) {
		struct optee_mutex_wait *w =
				list_first_entry(&priv->db,
						 struct optee_mutex_wait,
						 link);
		optee_mutex_wait_delete_entry(w);
	}
}

static void handle_rpc_func_cmd_mutex_wait(struct tee_context *ctx,
			struct optee *optee, struct teesmc_arg *arg)
{
	struct device *dev = optee->dev;
	struct teesmc_param *params;

	if (arg->num_params != 2)
		goto bad;

	params = TEESMC_GET_PARAMS(arg);

	if ((params[0].attr & TEESMC_ATTR_TYPE_MASK) !=
			TEESMC_ATTR_TYPE_VALUE_INPUT)
		goto bad;
	if (params[1].attr != TEESMC_ATTR_TYPE_NONE)
		goto bad;

	switch (params[0].u.value.a) {
	case TEE_MUTEX_WAIT_SLEEP:
		optee_mutex_wait_sleep(dev, &optee->mutex_wait,
				       params[0].u.value.b,
				       params[0].u.value.c);
		break;
	case TEE_MUTEX_WAIT_WAKEUP:
		optee_mutex_wait_wakeup(dev, &optee->mutex_wait,
					params[0].u.value.b,
					params[0].u.value.c);
		break;
	case TEE_MUTEX_WAIT_DELETE:
		optee_mutex_wait_delete(dev, &optee->mutex_wait,
					params[0].u.value.b);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct teesmc_arg *arg)
{
	struct teesmc_param *params;
	u32 msec_to_wait;

	if (arg->num_params != 2)
		goto bad;

	params = TEESMC_GET_PARAMS(arg);
	if (params[0].attr != TEESMC_ATTR_TYPE_VALUE_INPUT)
		goto bad;

	msec_to_wait = params[0].u.value.a;

	/* set task's state to interruptible sleep */
	set_current_state(TASK_INTERRUPTIBLE);

	/* take a nap */
	schedule_timeout(msecs_to_jiffies(msec_to_wait));

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd(struct tee_context *ctx, struct optee *optee,
			u32 parg)
{
	struct teesmc_arg *arg;
	void *va;
	struct tee_shm *shm;

	shm = tee_shm_find_by_pa(ctx->teedev, 0, parg);
	if (!shm) {
		dev_err(optee->dev, "%s: cannot find shm for parg 0x%x\n",
			__func__, parg);
		return;
	}
	if (tee_shm_pa2va(shm, parg, &va)) {
		dev_err(optee->dev, "%s: pa2va 0x%x failed\n",
			__func__, parg);
		return;
	}
	arg = va;

	switch (arg->cmd) {
	case TEE_RPC_MUTEX_WAIT:
		handle_rpc_func_cmd_mutex_wait(ctx, optee, arg);
		break;
	case TEE_RPC_WAIT:
		handle_rpc_func_cmd_wait(arg);
		break;
	default:
		optee_supp_thrd_req(ctx, arg);
	}
}

u32 optee_handle_rpc(struct tee_context *ctx, struct optee_smc_param *param)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct tee_shm *shm;
	phys_addr_t pa;

	switch (TEESMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case TEESMC_RPC_FUNC_ALLOC_ARG:
		shm = tee_shm_alloc(teedev, param->a1, TEE_SHM_MAPPED);
		if (!IS_ERR(shm) && !tee_shm_get_pa(shm, 0, &pa)) {
			reg_pair_from_64(&param->a1, &param->a2, pa);
			reg_pair_from_64(&param->a4, &param->a5, (u_long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		break;
	case TEESMC_RPC_FUNC_ALLOC_PAYLOAD:
		shm = tee_shm_alloc(teedev, param->a1,
				    TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);
		if (!IS_ERR(shm) && !tee_shm_get_pa(shm, 0, &pa)) {
			reg_pair_from_64(&param->a1, &param->a2, pa);
			reg_pair_from_64(&param->a4, &param->a5, (u_long)shm);
		} else {
			param->a1 = 0;
			param->a2 = 0;
			param->a4 = 0;
			param->a5 = 0;
		}
		break;
	case TEESMC_RPC_FUNC_FREE_ARG:
	case TEESMC_RPC_FUNC_FREE_PAYLOAD:
		shm = (struct tee_shm *)(u_long)reg_pair_to_64(param->a1,
							       param->a2);
		tee_shm_free(shm);
		break;
	case TEESMC_RPC_FUNC_IRQ:
		break;
	case TEESMC_RPC_FUNC_CMD:
		handle_rpc_func_cmd(ctx, optee,
				    reg_pair_to_64(param->a1, param->a2));
		break;
	default:
		dev_warn(optee->dev, "Unknown RPC func 0x%x\n",
			 (u32)TEESMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	return TEESMC32_CALL_RETURN_FROM_RPC;
}
