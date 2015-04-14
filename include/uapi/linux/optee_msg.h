/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef OPTEE_MSG_H
#define OPTEE_MSG_H

#include <linux/types.h>

/*
 * This file is exported by OP-TEE and is kept in sync between secure
 * world, normal world kernel driver, and user space client lib.
 *
 * This file is divided into three sections.
 * 1. Formatting of messages.
 * 2. Requests from normal world
 * 3. Requests from secure world, Remote Procedure Call (RPC)
 */

/*****************************************************************************
 * Part 1 - formatting of messages
 *****************************************************************************/

/*
 * Same values as TEE_PARAM_* from TEE Internal API
 */
#define OPTEEM_ATTR_TYPE_NONE		0
#define OPTEEM_ATTR_TYPE_VALUE_INPUT	1
#define OPTEEM_ATTR_TYPE_VALUE_OUTPUT	2
#define OPTEEM_ATTR_TYPE_VALUE_INOUT	3
#define OPTEEM_ATTR_TYPE_MEMREF_INPUT	5
#define OPTEEM_ATTR_TYPE_MEMREF_OUTPUT	6
#define OPTEEM_ATTR_TYPE_MEMREF_INOUT	7

#define OPTEEM_ATTR_TYPE_MASK		0x7

/*
 * Meta parameter to be absorbed by the Secure OS and not passed
 * to the Trusted Application.
 *
 * Currently only used for struct opteem_meta_open_session which
 * is added to OPTEEM_CMD_OPEN_SESSION.
 */
#define OPTEEM_ATTR_META		0x8


/**
 * struct opteem_param_memref - memory reference
 * @buf_ptr:	Address of the buffer
 * @size:	Size of the buffer
 * @shm_ref:	Shared memory reference only used by normal world
 *
 * Secure and normal world communicates pointers as physical address
 * instead of the virtual address. This is because secure and normal world
 * have completely independent memory mapping. Normal world can even have a
 * hypervisor which need to translate the guest physical address (AKA IPA
 * in ARM documentation) to a real physical address before passing the
 * structure to secure world.
 */
struct opteem_param_memref {
	__u64 buf_ptr;
	__u64 size;
	__u64 shm_ref;
};

/**
 * struct opteem_param_value - values
 * @a: first value
 * @b: second value
 * @c: third value
 */
struct opteem_param_value {
	__u64 a;
	__u64 b;
	__u64 c;
};

/**
 * struct opteem_param - parameter
 * @attr: attributes
 * @memref: a memory reference
 * @value: a value
 *
 * @attr & OPTEEM_ATTR_TYPE_MASK indicates if memref or value is used in
 * the union. OPTEEM_ATTR_TYPE_VALUE_* indicates value and
 * OPTEEM_ATTR_TYPE_MEMREF_* indicates memref. OPTEEM_ATTR_TYPE_NONE
 * indicates that none of the members are used.
 */
struct opteem_param {
	__u64 attr;
	union {
		struct opteem_param_memref memref;
		struct opteem_param_value value;
	} u;
};

/**
 * struct opteem_arg - call argument
 * @cmd: Command, one of OPTEEM_CMD_* or OPTEEM_RPC_CMD_*
 * @func: Trusted Application function, specific to the Trusted Application,
 *	     used if cmd == OPTEEM_CMD_INVOKE_COMMAND
 * @session: In parameter for all OPTEEM_CMD_* except
 *	     OPTEEM_CMD_OPEN_SESSION where it's an output parameter instead
 * @ret: return value
 * @ret_origin: origin of the return value
 * @num_params: number of parameters supplied to the OS Command
 * @params: the parameters supplied to the OS Command
 *
 * All normal calls to Trusted OS uses this struct. If cmd requires further
 * information than what these field holds it can be passed as a parameter
 * tagged as meta (setting the OPTEEM_ATTR_META bit in corresponding
 * param_attrs). All parameters tagged as meta has to come first.
 */
struct opteem_arg {
	__u32 cmd;
	__u32 func;
	__u32 session;
	__u32 ret;
	__u32 ret_origin;
	__u32 num_params __aligned(8);

	/*
	 * num_params is 8 byte aligned since the 'struct opteem_param'
	 * which follows requires 8 byte alignment.
	 *
	 * Commented out element used to visualize the layout dynamic part
	 * of the struct. This field is not available at all if
	 * num_params == 0.
	 *
	 * params is accessed through the macro OPTEEM_GET_PARAMS
	 *
	 * struct opteem_param params[num_params];
	 */
};

/**
 * OPTEEM_GET_PARAMS - return pointer to struct opteem_param *
 *
 * @x: Pointer to a struct opteem_arg
 *
 * Returns a pointer to the params[] inside a struct opteem_arg.
 */
#define OPTEEM_GET_PARAMS(x) \
	(struct opteem_param *)(((struct opteem_arg *)(x)) + 1)

/**
 * OPTEEM_GET_ARG_SIZE - return size of struct opteem_arg
 *
 * @num_params: Number of parameters embedded in the struct opteem_arg
 *
 * Returns the size of the struct opteem_arg together with the number
 * of embedded parameters.
 */
#define OPTEEM_GET_ARG_SIZE(num_params) \
	(sizeof(struct opteem_arg) + \
	 sizeof(struct opteem_param) * (num_params))

/* Length in bytes of a UUID */
#define OPTEEM_UUID_LEN	16

/**
 * struct opteem_meta_open_session - additional parameters for
 *				     OPTEEM_CMD_OPEN_SESSION
 * @uuid: UUID of the Trusted Application
 * @clnt_uuid: UUID of client
 * @clnt_login: Login class of client, TEE_LOGIN_* if being Global Platform
 *		compliant
 *
 * This struct is passed in the first parameter as an input memref tagged
 * as meta on an OPTEEM_CMD_OPEN_SESSION cmd.
 */
struct opteem_meta_open_session {
	__u8 uuid[OPTEEM_UUID_LEN];
	__u8 clnt_uuid[OPTEEM_UUID_LEN];
	__u32 clnt_login;
};

/**
 * struct optee_cmd_prefix - initial header for all user space buffers
 * @func_id:	Function Id OPTEEM_FUNCID_* below
 * @pad:	padding to make the struct size a multiple of 16 bytes
 */
struct opteem_cmd_prefix {
	__u32 func_id;
	__u32 pad;
};

/*****************************************************************************
 * Part 2 - requests from normal world
 *****************************************************************************/

/*
 * Return the following UID if using API specified in this file without
 * further extentions:
 * 384fb3e0-e7f8-11e3-af63-0002a5d5c51b.
 * Represented in 4 32-bit words in OPTEEM_UID_0, OPTEEM_UID_1,
 * OPTEEM_UID_2, OPTEEM_UID_3.
 */
#define OPTEEM_UID_0		0x384fb3e0
#define OPTEEM_UID_1		0xe7f811e3
#define OPTEEM_UID_2		0xaf630002
#define OPTEEM_UID_3		0xa5d5c51b
#define OPTEEM_FUNCID_CALLS_UID	0xFF01

/*
 * Returns 2.0 if using API specified in this file without further extentions.
 * Represented in 2 32-bit words in OPTEEM_REVISION_MAJOR and
 * OPTEEM_REVISION_MINOR
 */
#define OPTEEM_REVISION_MAJOR	2
#define OPTEEM_REVISION_MINOR	0
#define OPTEEM_FUNCID_CALLS_REVISION	0xFF03

/*
 * Get UUID of Trusted OS.
 *
 * Used by non-secure world to figure out which Trusted OS is installed.
 * Note that returned UUID is the UUID of the Trusted OS, not of the API.
 *
 * Returns UUID in 4 32-bit words in the same way as OPTEEM_FUNCID_CALLS_UID
 * described above.
 */
#define OPTEEM_OS_OPTEE_UUID_0		0x486178e0
#define OPTEEM_OS_OPTEE_UUID_1		0xe7f811e3
#define OPTEEM_OS_OPTEE_UUID_2		0xbc5e0002
#define OPTEEM_OS_OPTEE_UUID_3		0xa5d5c51b
#define OPTEEM_FUNCID_GET_OS_UUID	0x0000

/*
 * Get revision of Trusted OS.
 *
 * Used by non-secure world to figure out which version of the Trusted OS
 * is installed. Note that the returned revision is the revision of the
 * Trusted OS, not of the API.
 *
 * Returns revision in 2 32-bit words in the same way as OPTEEM_CALLS_REVISION
 * described above.
 */
#define OPTEEM_OS_OPTEE_REVISION_MAJOR	1
#define OPTEEM_OS_OPTEE_REVISION_MINOR	0
#define OPTEEM_FUNCID_GET_OS_REVISION	0x0001

/*
 * Do a secure call with struct opteem_arg as argument
 * The OPTEEM_CMD_* below defines what goes in struct opteem_arg::cmd
 *
 * For OPTEEM_CMD_OPEN_SESSION the first parameter is tagged as meta, holding
 * a memref with a struct opteem_meta_open_session which is needed find the
 * Trusted Application and to indicate the credentials of the client.
 *
 * For OPTEEM_CMD_INVOKE_COMMAND struct opteem_arg::func is Trusted
 * Application function, specific to the Trusted Application.
 */
#define OPTEEM_CMD_OPEN_SESSION		0
#define OPTEEM_CMD_INVOKE_COMMAND	1
#define OPTEEM_CMD_CLOSE_SESSION	2
#define OPTEEM_CMD_CANCEL		3
#define OPTEEM_FUNCID_CALL_WITH_ARG	0x0004

/*
 * Do a write response from tee-supplicant with struct opteem_arg as argument
 */
#define OPTEEM_FUNCID_SUPP_CMD_WRITE	0x1000

/*
 * Do a read request from tee-supplicant with struct opteem_arg as argument
 */
#define OPTEEM_FUNCID_SUPP_CMD_READ	0x1001

/*****************************************************************************
 * Part 3 - Requests from secure world, RPC
 *****************************************************************************/

/*
 * All RPC is done with a struct opteem_arg as bearer of information,
 * struct opteem_arg::arg holds values defined by OPTEEM_RPC_CMD_* below
 */

/*
 * Number of parameters used in RPC communication, always this number but
 * for some commands a parameter may be set to unused.
 */
#define OPTEEM_RPC_NUM_PARAMS 2

/*
 * Load a TA into memory
 * [in] param[0]	memref holding a uuid (OPTEEM_UUID_LEN bytes) of the
 *			TA to load
 * [out] param[1]	memref allocated to hold the TA content. memref.buf
 *			may be == NULL to query the size of the TA content.
 *			memref.size is always updated with the actual size
 *			of the TA content. If returned memref.size is larger
 *			than the supplied memref.size, not content is loaded.
 * [out] arg.ret	return value of request, 0 on success.
 */
#define OPTEEM_RPC_CMD_LOAD_TA		0

/*
 * Reserved
 */
#define OPTEEM_RPC_CMD_RPMB		1

/*
 * File system access, defined in tee-supplicant
 */
#define OPTEEM_RPC_CMD_FS		2

/*
 * Get time, defined in tee-supplicant
 */
#define OPTEEM_RPC_CMD_GET_TIME		3

/*
 * Sleep mutex, helper for secure world to implement a sleeping mutex.
 * struct opteem_arg::func	one of OPTEEM_RPC_SLEEP_MUTEX_* below
 *
 * OPTEEM_RPC_SLEEP_MUTEX_WAIT
 * [in] param[0].value	.a sleep mutex key
 *			.b wait tick
 * [not used] param[1]
 *
 * OPTEEM_RPC_SLEEP_MUTEX_WAKEUP
 * [in] param[0].value	.a sleep mutex key
 *			.b wait after
 * [not used] param[1]
 *
 * OPTEEM_RPC_SLEEP_MUTEX_DELETE
 * [in] param[0].value	.a sleep mutex key
 * [not used] param[1]
 */
#define OPTEEM_RPC_SLEEP_MUTEX_WAIT	0
#define OPTEEM_RPC_SLEEP_MUTEX_WAKEUP	1
#define OPTEEM_RPC_SLEEP_MUTEX_DELETE	2
#define OPTEEM_RPC_CMD_SLEEP_MUTEX	4

/*
 * Suspend execution
 *
 * [in] param[0].value	.a number of milliseconds to suspend
 */
#define OPTEEM_RPC_CMD_SUSPEND		5

#endif /* OPTEE_MSG_H */
