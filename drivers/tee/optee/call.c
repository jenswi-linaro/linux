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
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/tee_drv.h>
#include "optee_private.h"
#include "optee_smc.h"

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

static int optee_arg_from_user(struct opteem_arg *arg, size_t size,
			struct tee_shm **put_shm)
{
	struct opteem_param *param;
	size_t n;

	if (!arg->num_params || !put_shm)
		return -EINVAL;

	param = OPTEEM_GET_PARAMS(arg);

	for (n = 0; n < arg->num_params; n++) {
		struct tee_shm *shm;
		u32 shm_offs;
		phys_addr_t pa;
		int ret;

		if (param[n].attr & ~(OPTEEM_ATTR_TYPE_MASK | OPTEEM_ATTR_META))
			return -EINVAL;

		if (optee_param_is(param + n, PARAM_MEMREF | PARAM_INOUT)) {
			shm_offs = param[n].u.memref.buf_ptr;
			shm = tee_shm_get_from_fd(
					(int)param[n].u.memref.shm_ref);
			if (IS_ERR(shm))
				return PTR_ERR(shm);
			put_shm[n] = shm;
			ret = tee_shm_get_pa(shm, shm_offs, &pa);
			if (ret)
				return ret;
			param[n].u.memref.buf_ptr = pa;
		}
	}

	return 0;
}

static int optee_arg_to_user(struct opteem_arg *arg,
			struct opteem_arg __user *uarg)
{
	struct opteem_param *param = OPTEEM_GET_PARAMS(arg);
	struct opteem_param __user *uparam = (void __user *)(uarg + 1);
	size_t n;

	if (arg->cmd == OPTEEM_CMD_OPEN_SESSION &&
	    put_user(arg->session, &uarg->session))
		return -EINVAL;
	if (put_user(arg->ret, &uarg->ret) ||
	    put_user(arg->ret_origin, &uarg->ret_origin))
		return -EINVAL;

	for (n = 0; n < arg->num_params; n++) {
		struct opteem_param *p = param + n;
		struct opteem_param __user *up = uparam + n;

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

u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_smc_param param = { };
	u32 ret;
	u32 cmdid = OPTEE_SMC_CALL_WITH_ARG;

	reg_pair_from_64(&param.a1, &param.a2, parg);
	optee_call_lock(&optee->callsync);
	while (true) {
		param.a0 = cmdid;

		optee_smc(&param);
		ret = param.a0;

		if (ret == OPTEE_SMC_RETURN_EBUSY) {
			/*
			 * Since secure world returned busy, release the
			 * lock we had when entering this function and wait
			 * for "something to happen" (something else to
			 * exit from secure world and needed resources may
			 * have become available).
			 */
			optee_call_lock_wait_completion(&optee->callsync);
		} else if (OPTEE_SMC_RETURN_IS_RPC(ret)) {
			/*
			 * Process the RPC. We're unlocking the path to
			 * secure world to allow another request while
			 * processing the RPC.
			 */
			optee_call_unlock(&optee->callsync);
			cmdid = optee_handle_rpc(ctx, &param);
			optee_call_lock(&optee->callsync);
		} else {
			break;
		}
	}
	optee_call_unlock(&optee->callsync);
	return ret;
}

int optee_cmd_call_with_arg(struct tee_context *ctx, struct tee_shm *shm,
			struct opteem_cmd_prefix *arg,
			struct opteem_cmd_prefix __user *uarg, size_t len)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm **put_shm = NULL;
	struct opteem_arg *opteem_arg;
	struct opteem_arg __user *opteem_uarg;
	struct optee_session *sess;
	phys_addr_t opteem_parg;
	size_t opteem_arg_size;
	int rc;
	size_t n;

	opteem_arg = (struct opteem_arg *)(arg + 1);
	opteem_uarg = (struct opteem_arg __user *)(uarg + 1);

	opteem_arg_size = len - sizeof(*arg);

	/* Check that the header is complete */
	if (opteem_arg_size < sizeof(struct opteem_arg))
		return -EINVAL;
	/* Check that there's room for the specified number of params */
	if (opteem_arg_size != OPTEEM_GET_ARG_SIZE(opteem_arg->num_params))
		return -EINVAL;

	if (opteem_arg->num_params) {
		put_shm = kcalloc(opteem_arg->num_params,
				  sizeof(struct tee_shm *), GFP_KERNEL);
		if (!put_shm)
			return -ENOMEM;
		/*
		 * The params are updated with physical addresses and the ref
		 * counters on the shared memory is increased. The shms to
		 * decreased ref counts on when the call is over are stored in
		 * put_shm.
		 */
		rc = optee_arg_from_user(opteem_arg, opteem_arg_size, put_shm);
		if (rc)
			goto out;
	}

	rc = tee_shm_va2pa(shm, opteem_arg, &opteem_parg);
	if (rc)
		goto out;

	switch (opteem_arg->cmd) {
	case OPTEEM_CMD_OPEN_SESSION:
		/*
		 * Allocate memory now to be able to store the new session
		 * below.
		 */
		sess = kzalloc(sizeof(struct optee_session), GFP_KERNEL);
		if (!sess) {
			rc = -ENOMEM;
			goto out;
		}
		break;
	case OPTEEM_CMD_CLOSE_SESSION:
		/* A session is about to be closed, remove it from the list */
		mutex_lock(&ctxdata->mutex);
		sess = find_session(ctxdata, opteem_arg->session);
		if (sess)
			list_del(&sess->list_node);
		mutex_unlock(&ctxdata->mutex);
		if (!sess) {
			rc = -EINVAL;
			goto out;
		}
		kfree(sess);
		sess = NULL;
		break;

	case OPTEEM_CMD_INVOKE_COMMAND:
	case OPTEEM_CMD_CANCEL:
		mutex_lock(&ctxdata->mutex);
		sess = find_session(ctxdata, opteem_arg->session);
		mutex_unlock(&ctxdata->mutex);
		if (!sess) {
			rc = -EINVAL;
			goto out;
		}
		sess = NULL;
		break;

	default:
		rc = -EINVAL;
		goto out;
	}

	if (optee_do_call_with_arg(ctx, opteem_parg)) {
		opteem_arg->ret = TEEC_ERROR_COMMUNICATION;
		opteem_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	rc = optee_arg_to_user(opteem_arg, opteem_uarg);

	if (sess && opteem_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = opteem_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
		sess = NULL;
	}
out:
	kfree(sess);
	if (put_shm) {
		for (n = 0; n < opteem_arg->num_params; n++)
			if (put_shm[n])
				tee_shm_put(put_shm[n]);
		kfree(put_shm);
	}
	return rc;
}
