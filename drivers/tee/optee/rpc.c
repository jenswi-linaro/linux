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
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "optee_smc.h"

struct optee_mutex_wait_entry {
	struct list_head link;
	struct completion comp;
	struct mutex mu;
	u32 wait_after;
	u32 key;
};

/*
 * Compares two serial numbers using Serial Number Arithmetic
 * (https://www.ietf.org/rfc/rfc1982.txt).
 */
#define TICK_GT(t1, t2) \
	(((t1) < (t2) && (t2) - (t1) > 0xFFFFFFFFu) || \
	((t1) > (t2) && (t1) - (t2) < 0xFFFFFFFFu))

static struct optee_mutex_wait_entry *muw_find_entry(
			struct optee_mutex_wait *muw, u32 key)
{
	struct optee_mutex_wait_entry *w;

	mutex_lock(&muw->mu);

	list_for_each_entry(w, &muw->db, link)
		if (w->key == key)
			goto out;

	w = kmalloc(sizeof(struct optee_mutex_wait), GFP_KERNEL);
	if (!w)
		goto out;

	init_completion(&w->comp);
	mutex_init(&w->mu);
	w->wait_after = 0;
	w->key = key;
	list_add_tail(&w->link, &muw->db);
out:
	mutex_unlock(&muw->mu);
	return w;
}

static void muw_delete_entry(struct optee_mutex_wait_entry *w)
{
	list_del(&w->link);
	mutex_destroy(&w->mu);
	kfree(w);
}

static void muw_delete(struct optee_mutex_wait *muw, u32 key)
{
	struct optee_mutex_wait_entry *w;

	mutex_lock(&muw->mu);

	list_for_each_entry(w, &muw->db, link) {
		if (w->key == key) {
			muw_delete_entry(w);
			break;
		}
	}

	mutex_unlock(&muw->mu);
}

static void muw_wakeup(struct optee_mutex_wait *muw, u32 key,
			u32 wait_after)
{
	struct optee_mutex_wait_entry *w = muw_find_entry(muw, key);

	if (!w)
		return;

	mutex_lock(&w->mu);
	w->wait_after = wait_after;
	mutex_unlock(&w->mu);
	complete(&w->comp);
}

static void muw_sleep(struct optee_mutex_wait *muw, u32 key, u32 wait_tick)
{
	struct optee_mutex_wait_entry *w = muw_find_entry(muw, key);
	u32 wait_after;

	if (!w)
		return;

	mutex_lock(&w->mu);
	wait_after = w->wait_after;
	mutex_unlock(&w->mu);

	/*
	 * Only wait if the wait_tick is larger than wait_after, that is
	 * the mutex_wait hasn't been updated while this function was about
	 * to be called.
	 */
	if (TICK_GT(wait_tick, wait_after))
		wait_for_completion_timeout(&w->comp, HZ);
}

void optee_mutex_wait_init(struct optee_mutex_wait *muw)
{
	mutex_init(&muw->mu);
	INIT_LIST_HEAD(&muw->db);
}

void optee_mutex_wait_uninit(struct optee_mutex_wait *muw)
{
	/*
	 * It's the callers responsibility to ensure that no one is using
	 * anything inside muw.
	 */

	mutex_destroy(&muw->mu);
	while (!list_empty(&muw->db)) {
		struct optee_mutex_wait_entry *w;

		w = list_first_entry(&muw->db, struct optee_mutex_wait_entry,
				     link);
		muw_delete_entry(w);
	}
}

static void handle_rpc_func_cmd_mutex_wait(struct optee *optee,
			struct opteem_arg *arg)
{
	struct opteem_param *params;

	if (arg->num_params != OPTEEM_RPC_NUM_PARAMS)
		goto bad;

	params = OPTEEM_GET_PARAMS(arg);

	if ((params[0].attr & OPTEEM_ATTR_TYPE_MASK) !=
			OPTEEM_ATTR_TYPE_VALUE_INPUT)
		goto bad;
	if (params[1].attr != OPTEEM_ATTR_TYPE_NONE)
		goto bad;

	switch (arg->func) {
	case OPTEEM_RPC_SLEEP_MUTEX_WAIT:
		muw_sleep(&optee->mutex_wait, params[0].u.value.a,
			  params[0].u.value.b);
		break;
	case OPTEEM_RPC_SLEEP_MUTEX_WAKEUP:
		muw_wakeup(&optee->mutex_wait, params[0].u.value.a,
			   params[0].u.value.b);
		break;
	case OPTEEM_RPC_SLEEP_MUTEX_DELETE:
		muw_delete(&optee->mutex_wait, params[0].u.value.a);
		break;
	default:
		goto bad;
	}

	arg->ret = TEEC_SUCCESS;
	return;
bad:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_rpc_func_cmd_wait(struct opteem_arg *arg)
{
	struct opteem_param *params;
	u32 msec_to_wait;

	if (arg->num_params != OPTEEM_RPC_NUM_PARAMS)
		goto bad;

	params = OPTEEM_GET_PARAMS(arg);
	if (params[0].attr != OPTEEM_ATTR_TYPE_VALUE_INPUT)
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
			struct tee_shm *shm)
{
	struct opteem_arg *arg;

	arg = tee_shm_get_va(shm, 0);
	if (IS_ERR(arg)) {
		dev_err(optee->dev, "%s: tee_shm_get_va %p failed\n",
			__func__, shm);
		return;
	}

	switch (arg->cmd) {
	case OPTEEM_RPC_CMD_SLEEP_MUTEX:
		handle_rpc_func_cmd_mutex_wait(optee, arg);
		break;
	case OPTEEM_RPC_CMD_SUSPEND:
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

	switch (OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0)) {
	case OPTEE_SMC_RPC_FUNC_ALLOC_ARG:
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
	case OPTEE_SMC_RPC_FUNC_ALLOC_PAYLOAD:
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
	case OPTEE_SMC_RPC_FUNC_FREE_ARG:
	case OPTEE_SMC_RPC_FUNC_FREE_PAYLOAD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		tee_shm_free(shm);
		break;
	case OPTEE_SMC_RPC_FUNC_IRQ:
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		shm = reg_pair_to_ptr(param->a1, param->a2);
		handle_rpc_func_cmd(ctx, optee, shm);
		break;
	default:
		dev_warn(optee->dev, "Unknown RPC func 0x%x\n",
			 (u32)OPTEE_SMC_RETURN_GET_RPC_FUNC(param->a0));
		break;
	}

	return OPTEE_SMC_CALL_RETURN_FROM_RPC;
}
