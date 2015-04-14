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

#ifndef OPTEE_PRIVATE_H
#define OPTEE_PRIVATE_H

#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/optee_msg.h>

#define OPTEE_MAX_ARG_SIZE	1024

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C

#define TEEC_ORIGIN_COMMS		0x00000002

struct optee_call_sync {
	struct mutex mutex;
	struct completion c;
	int c_waiters;
};

struct optee_mutex_wait {
	struct mutex mu;
	struct list_head db;
};

struct optee_supp {
	bool supp_next_write;
	size_t data_size;
	const struct opteem_arg *data_to_supp;
	struct opteem_arg *data_from_supp;
	struct mutex thrd_mutex;
	struct mutex supp_mutex;
	struct semaphore data_to_supp_sem;
	struct semaphore data_from_supp_sem;
};

struct optee {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	struct device *dev;
	struct optee_call_sync callsync;
	struct optee_mutex_wait mutex_wait;
	struct optee_supp supp;
	struct tee_shm_pool *pool;
	void *ioremaped_shm;
};

struct optee_session {
	struct list_head list_node;
	u32 session_id;
};

struct optee_context_data {
	struct mutex mutex;
	struct list_head sess_list;
};

/* Note that 32bit arguments are passed also when running in 64bit */
struct optee_smc_param {
	u32 a0;
	u32 a1;
	u32 a2;
	u32 a3;
	u32 a4;
	u32 a5;
	u32 a6;
	u32 a7;
};

void optee_smc(struct optee_smc_param *param);

u32 optee_handle_rpc(struct tee_context *ctx, struct optee_smc_param *param);

void optee_mutex_wait_init(struct optee_mutex_wait *muw);
void optee_mutex_wait_uninit(struct optee_mutex_wait *muw);

void optee_supp_thrd_req(struct tee_context *ctx, struct opteem_arg *arg);
int optee_supp_read(struct tee_context *ctx, void __user *buf, size_t len);
int optee_supp_write(struct tee_context *ctx, void __user *buf, size_t len);
void optee_supp_init(struct optee_supp *supp);
void optee_supp_uninit(struct optee_supp *supp);


u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg);
int optee_cmd_call_with_arg(struct tee_context *ctx, struct tee_shm *shm,
			struct opteem_cmd_prefix *arg,
			struct opteem_cmd_prefix __user *uarg, size_t len);

/*
 * Small helpers
 */
#define PARAM_VALUE	0x1
#define PARAM_MEMREF	0x2
#define PARAM_ANY	(PARAM_VALUE | PARAM_MEMREF)
#define PARAM_IN	0x4
#define PARAM_OUT	0x8
#define PARAM_INOUT	(PARAM_IN | PARAM_OUT)

/**
 * optee_param_is() - report kind of opteem parameter
 * @param:	the opteem parameter
 * @flags:	which properties of the parameter to check
 * @returns true if any of PARAM_VALUE PARAM_MEMREF is satified _and_
 *	any of the PARAM_IN PARAM_OUT is satisfied
 */
bool optee_param_is(struct opteem_param *param, uint32_t flags);

static inline void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(u_long)(((u64)reg0 << 32) | reg1);
}

static inline void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}


#endif /*OPTEE_PRIVATE_H*/
