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

#ifndef OPTEE_OPTEE_H
#define OPTEE_OPTEE_H

#include <linux/types.h>

/* Number of buffers used in RPC communication */
#define OPTEE_RPC_NUM_BUFS 2
/* Version of the driver interface */
#define OPTEE_VERSION	1

/*
 * These must not interfere with SMCs used by OP-TEE OS, range
 * 0x00000000-0x0100FFFF is reserved "for existing APIs" in the "SMC Calling
 * Convention" specification so OP-TEE will never use them for anything.
 */
#define OPTEE_SUPP_CMD_WRITE	0	/* Supplicant write response */
#define OPTEE_SUPP_CMD_READ	1	/* Supplicant read request */

/**
 * struct optee_cmd_prefix - initial header for all user space buffers
 * @smc_id:	SMC Id from teesmc.h, teesmc_optee.h or the OPTEE_SUPP_CMD_*
 *		above
 * @pad		padding to make the struct size a multiple of 16 bytes
 */
struct optee_cmd_prefix {
	__u32 smc_id;
	__u32 pad;
};

#endif /* OPTEE_OPTEE_H */
