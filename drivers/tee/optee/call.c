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
#include <linux/arm-smccc.h>
#include "optee_private.h"
#include "optee_smc.h"

static void optee_call_enter_call_queue(struct optee_call_queue *cq)
{
	struct optee_call_waiter w;
	bool must_wait = false;

	mutex_lock(&cq->mutex);
	if (!list_empty(&cq->waiters)) {
		/*
		 * If there's some one in the queue secure world is
		 * obviously busy. If the queue is empty we can skip this
		 * and try to enter secure world immediately.
		 */
		must_wait = true;
		init_completion(&w.c);
		list_add_tail(&w.list_node, &cq->waiters);
	}
	mutex_unlock(&cq->mutex);

	if (must_wait) {
		wait_for_completion(&w.c);

		mutex_lock(&cq->mutex);
		list_del(&w.list_node);
		mutex_unlock(&cq->mutex);
	}
}

static void optee_call_wait_completion(struct optee_call_queue *cq)
{
	struct optee_call_waiter w;

	init_completion(&w.c);

	mutex_lock(&cq->mutex);
	list_add_tail(&w.list_node, &cq->waiters);
	mutex_unlock(&cq->mutex);

	wait_for_completion(&w.c);

	mutex_lock(&cq->mutex);
	list_del(&w.list_node);
	mutex_unlock(&cq->mutex);
}

static void optee_call_complete_one(struct optee_call_queue *cq)
{
	struct optee_call_waiter *w;

	mutex_lock(&cq->mutex);

	w = list_first_entry_or_null(&cq->waiters, struct optee_call_waiter,
				     list_node);
	if (w)
		complete(&w->c);

	mutex_unlock(&cq->mutex);
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
	struct smccc_param32 param = { };
	u32 ret;
	u32 cmdid = OPTEE_SMC_CALL_WITH_ARG;

	reg_pair_from_64(&param.a1, &param.a2, parg);
	/*
	 * Enter the call queue to be fair against other threads that may
	 * be waiting there.
	 */
	optee_call_enter_call_queue(&optee->call_queue);
	while (true) {
		param.a0 = cmdid;

		smccc_call32(&param);
		ret = param.a0;

		if (ret == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
			/*
			 * Out of threads in secure world, wait for a thread
			 * become available.
			 */
			optee_call_wait_completion(&optee->call_queue);
		} else if (OPTEE_SMC_RETURN_IS_RPC(ret))
			cmdid = optee_handle_rpc(ctx, &param);
		else
			break;
	}
	/*
	 * We're done with our thread in secure world, if there's any
	 * thread waiters wake up one.
	 */
	optee_call_complete_one(&optee->call_queue);
	return ret;
}

static struct tee_shm *get_msg_arg(struct tee_context *ctx, size_t num_params,
			struct optee_msg_arg **msg_arg, phys_addr_t *msg_parg)
{
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *ma;

	shm = tee_shm_alloc(ctx->teedev, OPTEE_MSG_GET_ARG_SIZE(num_params),
			    TEE_SHM_MAPPED);
	if (IS_ERR(shm))
		return shm;
	ma = tee_shm_get_va(shm, 0);
	if (IS_ERR(ma)) {
		rc = PTR_ERR(ma);
		goto out;
	}
	rc = tee_shm_get_pa(shm, 0, msg_parg);
	if (rc)
		goto out;

	memset(ma, 0, OPTEE_MSG_GET_ARG_SIZE(num_params));
	ma->num_params = num_params;
	*msg_arg = ma;
out:
	if (rc) {
		tee_shm_free(shm);
		return ERR_PTR(rc);
	}
	return shm;
}

int optee_open_session(struct tee_context *ctx,
			struct tee_ioctl_open_session_arg *arg,
			struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_msg_param *msg_param;
	struct optee_session *sess = NULL;

	/* +2 for the meta parameters added below */
	shm = get_msg_arg(ctx, arg->num_params + 2, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_OPEN_SESSION;
	msg_param = OPTEE_MSG_GET_PARAMS(msg_arg);

	/*
	 * Initialize and add the meta parameters needed when opening a
	 * session.
	 */
	msg_param[0].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	msg_param[1].attr = OPTEE_MSG_ATTR_TYPE_VALUE_INPUT |
			    OPTEE_MSG_ATTR_META;
	memcpy(&msg_param[0].u.value, arg->uuid, sizeof(arg->uuid));
	memcpy(&msg_param[1].u.value, arg->uuid, sizeof(arg->clnt_uuid));
	msg_param[1].u.value.c = arg->clnt_login;

	rc = optee_to_msg_param(msg_param + 2, arg->num_params, param);
	if (rc)
		goto out;

	sess = kzalloc(sizeof(struct optee_session), GFP_KERNEL);
	if (!sess) {
		rc = -ENOMEM;
		goto out;
	}

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (msg_arg->ret == TEEC_SUCCESS) {
		/* A new session has been created, add it to the list. */
		sess->session_id = msg_arg->session;
		mutex_lock(&ctxdata->mutex);
		list_add(&sess->list_node, &ctxdata->sess_list);
		mutex_unlock(&ctxdata->mutex);
		sess = NULL;
	}

	if (optee_from_msg_param(param, arg->num_params, msg_param + 2)) {
		arg->ret = TEEC_ERROR_COMMUNICATION;
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		/* Close session again to avoid leakage */
		optee_close_session(ctx, msg_arg->session);
	} else {
		arg->session = msg_arg->session;
		arg->ret = msg_arg->ret;
		arg->ret_origin = msg_arg->ret_origin;
	}
out:
	kfree(sess);
	tee_shm_free(shm);
	return rc;
}

int optee_close_session(struct tee_context *ctx, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	/* Check that the session is valid and remove it from the list */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	if (sess)
		list_del(&sess->list_node);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	kfree(sess);

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CLOSE_SESSION;
	msg_arg->session = session;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}

int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
			struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	int rc;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_msg_param *msg_param;
	struct optee_session *sess;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, arg->session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, arg->num_params, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);
	msg_arg->cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
	msg_arg->func = arg->func;
	msg_arg->session = arg->session;
	msg_param = OPTEE_MSG_GET_PARAMS(msg_arg);

	rc = optee_to_msg_param(msg_param, arg->num_params, param);
	if (rc)
		goto out;

	if (optee_do_call_with_arg(ctx, msg_parg)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	if (optee_from_msg_param(param, arg->num_params, msg_param)) {
		msg_arg->ret = TEEC_ERROR_COMMUNICATION;
		msg_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	arg->ret = msg_arg->ret;
	arg->ret_origin = msg_arg->ret_origin;
out:
	tee_shm_free(shm);
	return rc;
}

int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct tee_shm *shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;
	struct optee_session *sess;

	/* Check that the session is valid */
	mutex_lock(&ctxdata->mutex);
	sess = find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;

	shm = get_msg_arg(ctx, 0, &msg_arg, &msg_parg);
	if (IS_ERR(shm))
		return PTR_ERR(shm);

	msg_arg->cmd = OPTEE_MSG_CMD_CANCEL;
	msg_arg->session = session;
	optee_do_call_with_arg(ctx, msg_parg);

	tee_shm_free(shm);
	return 0;
}
