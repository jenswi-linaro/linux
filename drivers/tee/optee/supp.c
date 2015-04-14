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
#include <linux/uaccess.h>
#include "optee_private.h"

void optee_supp_init(struct optee_supp *supp)
{
	memset(supp, 0, sizeof(*supp));
	mutex_init(&supp->thrd_mutex);
	mutex_init(&supp->supp_mutex);
	sema_init(&supp->data_to_supp_sem, 0);
	sema_init(&supp->data_from_supp_sem, 0);
}

void optee_supp_uninit(struct optee_supp *supp)
{
	mutex_destroy(&supp->thrd_mutex);
	mutex_destroy(&supp->supp_mutex);
}

static void optee_supp_send(struct optee *optee,
			const struct opteem_arg *arg,
			struct opteem_arg *resp)
{
	struct optee_supp *supp = &optee->supp;

	/*
	 * Other threads blocks here until we've copied our answer from
	 * supplicant.
	 */
	mutex_lock(&supp->thrd_mutex);

	/*
	 * We have exclusive access to data_to_supp and data_from_supp
	 * since the supplicant is at this point either trying to down()
	 * data_to_supp_sem or still in userspace about to do the ioctl()
	 * to enter optee_supp_read() below.
	 */

	supp->data_to_supp = arg;
	supp->data_from_supp = resp;

	/* Let supplicant get the data */
	up(&supp->data_to_supp_sem);

	/*
	 * Wait for supplicant to process and return result, once we've
	 * down()'ed data_from_supp_sem we have exclusive access again.
	 */
	down(&supp->data_from_supp_sem);

	/* We're done, let someone else talk to the supplicant now. */
	mutex_unlock(&supp->thrd_mutex);
}

void copy_back_outdata(struct opteem_arg *arg,
			const struct opteem_arg *resp)
{
	struct opteem_param *arg_params = OPTEEM_GET_PARAMS(arg);
	struct opteem_param *resp_params = OPTEEM_GET_PARAMS(resp);
	size_t n;

	/* Copy back out and inout parameters */
	for (n = 0; n < arg->num_params; n++) {
		struct opteem_param *ap = arg_params + n;

		if (optee_param_is(ap, PARAM_VALUE | PARAM_OUT))
			ap->u.value = resp_params[n].u.value;
		else if (optee_param_is(ap, PARAM_MEMREF | PARAM_OUT))
			ap->u.memref.size = resp_params[n].u.memref.size;
	}
	arg->ret = resp->ret;

}

void optee_supp_thrd_req(struct tee_context *ctx, struct opteem_arg *arg)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	const size_t s = OPTEEM_GET_ARG_SIZE(OPTEEM_RPC_NUM_PARAMS);
	struct opteem_arg *resp;

	if (arg->num_params != OPTEEM_RPC_NUM_PARAMS) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	resp = kzalloc(s, GFP_KERNEL);
	if (!resp) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	optee_supp_send(optee, arg, resp);
	copy_back_outdata(arg, resp);

	kfree(resp);
}

static u32 memref_to_user(struct tee_shm *shm,
			struct opteem_param_memref *ph_mem,
			struct opteem_param_memref *user_mem, int *fd)
{
	int res;
	phys_addr_t pa;

	if (!shm) {
		*fd = -1;
		return TEEC_SUCCESS;
	}

	res = tee_shm_get_pa(shm, 0, &pa);
	if (res)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (pa > ph_mem->buf_ptr)
		return TEEC_ERROR_BAD_PARAMETERS;

	user_mem->buf_ptr = ph_mem->buf_ptr - pa;
	res = tee_shm_get_fd(shm);
	if (res < 0)
		return TEEC_ERROR_OUT_OF_MEMORY;

	*fd = res;
	return TEEC_SUCCESS;
}

static int optee_supp_copy_to_user(void __user *buf,
			const struct opteem_arg *arg, struct opteem_arg *tmp)
{
	size_t s = OPTEEM_GET_ARG_SIZE(OPTEEM_RPC_NUM_PARAMS);
	struct opteem_param *arg_params;
	struct opteem_param *tmp_params;
	size_t n;
	int ret;

	memcpy(tmp, arg, s);
	arg_params = OPTEEM_GET_PARAMS(arg);
	tmp_params = OPTEEM_GET_PARAMS(tmp);

	for (n = 0; n < arg->num_params; n++) {
		if (optee_param_is(arg_params + n, PARAM_MEMREF | PARAM_INOUT))
			tmp_params[n].u.memref.shm_ref = -1;
	}

	for (n = 0; n < arg->num_params; n++) {
		if (optee_param_is(arg_params + n,
				   PARAM_MEMREF | PARAM_INOUT)) {
			int fd = -1;
			struct tee_shm *shm;
			uint32_t res;
			struct opteem_param_memref *memref;

			memref = &arg_params[n].u.memref;
			shm = (struct tee_shm *)(uintptr_t)memref->shm_ref;
			res = memref_to_user(shm, memref,
					     &tmp_params[n].u.memref, &fd);
			/* Propagate kind of error to requesting thread. */
			if (res != TEEC_SUCCESS) {
				tmp->ret = res;
				if (res == TEEC_ERROR_OUT_OF_MEMORY) {
					/*
					 * For out of memory it could help
					 * if tee-supplicant was restarted,
					 * maybe it leaks something.
					 */
					ret = -ENOMEM;
					goto err;
				}
				/* Let supplicant grab next request. */
				ret = -EAGAIN;
			}
			tmp_params[n].u.memref.shm_ref = fd;
		}
	}

	if (copy_to_user(buf, tmp, s)) {
		/* Something is wrong, let supplicant restart and try again */
		ret = -EINVAL;
		goto err;
	}
	return 0;
err:
	for (n = 0; n < arg->num_params; n++) {
		int fd;

		if (!optee_param_is(arg_params + n, PARAM_MEMREF | PARAM_INOUT))
			continue;
		fd = tmp_params[n].u.memref.shm_ref;
		if (fd >= 0)
			tee_shm_put_fd(fd);
	}
	return ret;
}

int optee_supp_read(struct tee_context *ctx, void __user *buf, size_t len)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct optee_supp *supp = &optee->supp;
	const size_t s = OPTEEM_GET_ARG_SIZE(OPTEEM_RPC_NUM_PARAMS);
	int ret;

	if (len != s)
		return -EINVAL;

	/*
	 * In case two supplicants or two threads in one supplicant is
	 * calling this function simultaneously we need to protect the
	 * data with a mutex which we'll release before returning.
	 */
	mutex_lock(&supp->supp_mutex);
	while (true) {
		if (supp->supp_next_write) {
			/*
			 * optee_supp_read() has been called again without
			 * a optee_supp_write() in between. Supplicant has
			 * probably been restarted before it was able to
			 * write back last result. Abort last request and
			 * wait for a new.
			 */
			if (supp->data_to_supp) {
				memcpy(supp->data_from_supp,
				       supp->data_to_supp, s);
				supp->data_from_supp->ret =
					TEEC_ERROR_COMMUNICATION;
				supp->data_to_supp = NULL;
				supp->supp_next_write = false;
				up(&supp->data_from_supp_sem);
			}
		}

		/*
		 * This is where supplicant will be hanging most of the
		 * time, let's make this interruptable so we can easily
		 * restart supplicant if needed.
		 */
		if (down_interruptible(&supp->data_to_supp_sem)) {
			ret = -ERESTARTSYS;
			goto out;
		}

		/* We have exlusive access to the data */
		ret = optee_supp_copy_to_user(buf, supp->data_to_supp,
					      supp->data_from_supp);
		if (!ret)
			break;
		supp->data_to_supp = NULL;
		up(&supp->data_from_supp_sem);
		if (ret != -EAGAIN)
			goto out;
	}

	/* We've consumed the data, set it to NULL */
	supp->data_to_supp = NULL;

	/* Allow optee_supp_write() below to do its work */
	supp->supp_next_write = true;

	ret = 0;
out:
	mutex_unlock(&supp->supp_mutex);
	return ret;
}

int optee_supp_write(struct tee_context *ctx, void __user *buf, size_t len)
{
	struct tee_device *teedev = ctx->teedev;
	struct optee *optee = tee_get_drvdata(teedev);
	struct optee_supp *supp = &optee->supp;
	const size_t s = OPTEEM_GET_ARG_SIZE(OPTEEM_RPC_NUM_PARAMS);
	int ret = 0;

	if (len != s)
		return -EINVAL;

	/*
	 * We still have exclusive access to the data since that's how we
	 * left it when returning from optee_supp_read().
	 */

	/* See comment on mutex in optee_supp_read() above */
	mutex_lock(&supp->supp_mutex);

	if (!supp->supp_next_write) {
		/*
		 * Something strange is going on, supplicant shouldn't
		 * enter optee_supp_write() in this state
		 */
		ret = -ENOENT;
		goto out;
	}

	if (copy_from_user(supp->data_from_supp, buf, s)) {
		/*
		 * Something is wrong, let supplicant restart. Next call to
		 * optee_supp_read() will give an error to the requesting
		 * thread and release it.
		 */
		ret = -EINVAL;
		goto out;
	}

	/* Data has been populated, set the pointer to NULL */
	supp->data_from_supp = NULL;

	/* Allow optee_supp_read() above to do its work */
	supp->supp_next_write = false;

	/* Let the requesting thread continue */
	up(&supp->data_from_supp_sem);
out:
	mutex_unlock(&supp->supp_mutex);
	return ret;
}
