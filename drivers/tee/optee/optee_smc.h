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
#ifndef OPTEE_SMC_H
#define OPTEE_SMC_H

/*
 * This file is exported by OP-TEE and is in kept in sync between secure
 * world and normal world kernel driver. We're following ARM SMC Calling
 * Convention as specified in
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 *
 * This file depends on optee_msg.h being included to expand the SMC id
 * macros below.
 */

#define OPTEE_SMC_32			0
#define OPTEE_SMC_64			0x40000000
#define OPTEE_SMC_FAST_CALL		0x80000000
#define OPTEE_SMC_STD_CALL		0

#define OPTEE_SMC_OWNER_MASK		0x3F
#define OPTEE_SMC_OWNER_SHIFT		24

#define OPTEE_SMC_FUNC_MASK		0xFFFF

#define OPTEE_SMC_IS_FAST_CALL(smc_val)	((smc_val) & OPTEE_SMC_FAST_CALL)
#define OPTEE_SMC_IS_64(smc_val)	((smc_val) & OPTEE_SMC_64)
#define OPTEE_SMC_FUNC_NUM(smc_val)	((smc_val) & OPTEE_SMC_FUNC_MASK)
#define OPTEE_SMC_OWNER_NUM(smc_val) \
	(((smc_val) >> OPTEE_SMC_OWNER_SHIFT) & OPTEE_SMC_OWNER_MASK)

#define OPTEE_SMC_CALL_VAL(type, calling_convention, owner, func_num) \
			((type) | (calling_convention) | \
			(((owner) & OPTEE_SMC_OWNER_MASK) << \
				OPTEE_SMC_OWNER_SHIFT) |\
			((func_num) & OPTEE_SMC_FUNC_MASK))

#define OPTEE_SMC_STD_CALL_VAL(func_num) \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_STD_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS, (func_num))
#define OPTEE_SMC_FAST_CALL_VAL(func_num) \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS, (func_num))

#define OPTEE_SMC_OWNER_ARCH		0
#define OPTEE_SMC_OWNER_CPU		1
#define OPTEE_SMC_OWNER_SIP		2
#define OPTEE_SMC_OWNER_OEM		3
#define OPTEE_SMC_OWNER_STANDARD	4
#define OPTEE_SMC_OWNER_TRUSTED_APP	48
#define OPTEE_SMC_OWNER_TRUSTED_OS	50

#define OPTEE_SMC_OWNER_TRUSTED_OS_OPTEED 62
#define OPTEE_SMC_OWNER_TRUSTED_OS_API	63

/*
 * Function specified by SMC Calling convention.
 */
#define OPTEE_SMC_FUNCID_CALLS_COUNT	0xFF00
#define OPTEE_SMC_CALLS_COUNT \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS_API, \
			   OPTEE_SMC_FUNCID_CALLS_COUNT)

/*
 * Function specified by SMC Calling convention
 *
 * Return one of the following UIDs if using API specified in this file
 * without further extentions:
 * 65cb6b93-af0c-4617-8ed6-644a8d1140f8
 * see OPTEE_SMC_UID_* in optee_msg.h
 */
#define OPTEE_SMC_FUNCID_CALLS_UID OPTEEM_FUNCID_CALLS_UID
#define OPTEE_SMC_CALLS_UID \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS_API, \
			   OPTEE_SMC_FUNCID_CALLS_UID)

/*
 * Function specified by SMC Calling convention
 *
 * Returns 2.0 if using API specified in this file without further extentions.
 * see OPTEEM_REVISION_* in optee_msg.h
 */
#define OPTEE_SMC_FUNCID_CALLS_REVISION OPTEEM_FUNCID_CALLS_REVISION
#define OPTEE_SMC_CALLS_REVISION \
	OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
			   OPTEE_SMC_OWNER_TRUSTED_OS_API, \
			   OPTEE_SMC_FUNCID_CALLS_REVISION)

/*
 * Get UUID of Trusted OS.
 *
 * Used by non-secure world to figure out which Trusted OS is installed.
 * Note that returned UUID is the UUID of the Trusted OS, not of the API.
 *
 * Returns UUID in r0-4/w0-4 in the same way as OPTEE_SMC_CALLS_UID
 * described above.
 */
#define OPTEE_SMC_FUNCID_GET_OS_UUID OPTEEM_FUNCID_GET_OS_UUID
#define OPTEE_SMC_CALL_GET_OS_UUID \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_OS_UUID)

/*
 * Get revision of Trusted OS.
 *
 * Used by non-secure world to figure out which version of the Trusted OS
 * is installed. Note that the returned revision is the revision of the
 * Trusted OS, not of the API.
 *
 * Returns revision in r0-1/w0-1 in the same way as OPTEE_SMC_CALLS_REVISION
 * described above.
 */
#define OPTEE_SMC_FUNCID_GET_OS_REVISION OPTEEM_FUNCID_GET_OS_REVISION
#define OPTEE_SMC_CALL_GET_OS_REVISION \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_OS_REVISION)

/*
 * Call with struct opteem_arg as argument
 *
 * Call register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC*CALL_WITH_ARG
 * r1/w1	Upper 32bit of a 64bit physical pointer to a struct opteem_arg
 * r2/w2	Lower 32bit of a 64bit physical pointer to a struct opteem_arg
 * r3-6/w3-6	Not used
 * r7/w7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * r0/w0	Return value, OPTEE_SMC_RETURN_*
 * r1-3/w1-3	Not used
 * r4-7/w4-7	Preserved
 *
 * Ebusy return register usage:
 * r0/w0	Return value, OPTEE_SMC_RETURN_EBUSY
 * r1-3/w1-3	Preserved
 * r4-7/w4-7	Preserved
 *
 * RPC return register usage:
 * r0/w0	Return value, OPTEE_SMC_RETURN_IS_RPC(val)
 * r1-2/w1-2	RPC parameters
 * r3-7/w3-7	Resume information, must be preserved
 *
 * Possible return values:
 * OPTEE_SMC_RETURN_UNKNOWN_FUNCTION	Trusted OS does not recognize this
 *					function.
 * OPTEE_SMC_RETURN_OK			Call completed, result updated in
 *					the previously supplied struct
 *					opteem_arg.
 * OPTEE_SMC_RETURN_EBUSY		Trusted OS busy, try again later.
 * OPTEE_SMC_RETURN_EBADADDR		Bad physcial pointer to struct
 *					opteem_arg.
 * OPTEE_SMC_RETURN_EBADCMD		Bad/unknown cmd in struct opteem_arg
 * OPTEE_SMC_RETURN_IS_RPC()		Call suspended by RPC call to normal
 *					world.
 */
#define OPTEE_SMC_FUNCID_CALL_WITH_ARG OPTEEM_FUNCID_CALL_WITH_ARG
#define OPTEE_SMC_CALL_WITH_ARG \
	OPTEE_SMC_STD_CALL_VAL(OPTEE_SMC_FUNCID_CALL_WITH_ARG)
/* Same as OPTEE_SMC_CALL_WITH_ARG but a "fast call". */
#define OPTEE_SMC_FASTCALL_WITH_ARG \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_CALL_WITH_ARG)

/*
 * Register a secure/non-secure shared memory region
 *
 * Call register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC*_REGISTER_SHM
 * r1/w1	Upper 32bits of 64bit physical address of start of SHM
 * r2/w2	Lower 32bits of 64bit physical address of start of SHM
 * r3/w3	Size of SHM
 * r4/w4	Cache settings of memory, as defined by the
 *		OPTEE_SMC_SHM_* values below
 * r5-6/w5-6	Not used
 * r7/w7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * r0/w0	OPTEE_SMC_RETURN_OK if OK
 *		OPTEE_SMC_RETURN_EBUSY can't obtain access to register SHM
 *		OPTEE_SMC_RETURN_ENOMEM not enough memory to register SHM
 *		OPTEE_SMC_RETURN_EBADADDR bad parameters
 *		OPTEE_SMC_RETURN_EBADCMD call not available
 * r1-2/w1-2	Not used
 * r3-7/w3-7	Preserved
 */
#define OPTEE_SMC_SHM_NONCACHED		0ULL
#define OPTEE_SMC_SHM_CACHED		1ULL
#define OPTEE_SMC_FUNCID_REGISTER_SHM	5
#define OPTEE_SMC_REGISTER_SHM \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_REGISTER_SHM)

/*
 * Unregister a secure/non-secure shared memory region
 *
 * Call register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC*_*UNREGISTER_SHM
 * r1/w1	Upper 32bits of 64bit physical address of start of SHM
 * r2/w2	Lower 32bits of 64bit physical address of start of SHM
 * r3/w3	Size of SHM
 * r3-6/w2-6	Not used
 * r7/w7	Hypervisor Client ID register
 *
 * Normal return register usage:
 * r0/w0	OPTEE_SMC_RETURN_OK if OK
 *		OPTEE_SMC_RETURN_EBUSY can't obtain access to register SHM
 *		OPTEE_SMC_RETURN_ENOMEM not enough memory to register SHM
 *		OPTEE_SMC_RETURN_EBADCMD call not available
 * r1-3/w1-3	Not used
 * r4-7/w4-7	Preserved
 */
#define OPTEE_SMC_FUNCID_UNREGISTER_SHM	6
#define OPTEE_SMC_UNREGISTER_SHM \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_UNREGISTER_SHM)

/*
 * Get Shared Memory Config
 *
 * Returns the Secure/Non-secure shared memory config.
 *
 * Call register usage:
 * r0	SMC Function ID, OPTEE_SMC_GET_SHM_CONFIG
 * r1-6	Not used
 * r7	Hypervisor Client ID register
 *
 * Have config return register usage:
 * r0	OPTEE_SMC_RETURN_OK
 * r1	Physical address of start of SHM
 * r2	Size of of SHM
 * r3	1 if SHM is cached, 0 if uncached.
 * r4-7	Preserved
 *
 * Not available register usage:
 * r0	OPTEE_SMC_RETURN_NOTAVAIL
 * r1-3 Not used
 * r4-7	Preserved
 */
#define OPTEE_SMC_FUNCID_GET_SHM_CONFIG	7
#define OPTEE_SMC_GET_SHM_CONFIG \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_GET_SHM_CONFIG)

/*
 * Configures L2CC mutex
 *
 * Disables, enables usage of L2CC mutex. Returns or sets physical address
 * of L2CC mutex.
 *
 * Call register usage:
 * r0	SMC Function ID, OPTEE_SMC_L2CC_MUTEX
 * r1	OPTEE_SMC_L2CC_MUTEX_GET_ADDR Get physical address of mutex
 *	OPTEE_SMC_L2CC_MUTEX_SET_ADDR Set physical address of mutex
 *	OPTEE_SMC_L2CC_MUTEX_ENABLE	 Enable usage of mutex
 *	OPTEE_SMC_L2CC_MUTEX_DISABLE	 Disable usage of mutex
 * r2	if r1 == OPTEE_SMC_L2CC_MUTEX_SET_ADDR, physical address of mutex
 * r3-6	Not used
 * r7	Hypervisor Client ID register
 *
 * Have config return register usage:
 * r0	OPTEE_SMC_RETURN_OK
 * r1	Preserved
 * r2	if r1 == OPTEE_SMC_L2CC_MUTEX_GET_ADDR, physical address of L2CC mutex
 * r3-7	Preserved
 *
 * Error return register usage:
 * r0	OPTEE_SMC_RETURN_NOTAVAIL	Physical address not available
 *	OPTEE_SMC_RETURN_EBADADDR		Bad supplied physical address
 *	OPTEE_SMC_RETURN_EBADCMD		Unsupported value in r1
 * r1-7	Preserved
 */
#define OPTEE_SMC_L2CC_MUTEX_GET_ADDR	0
#define OPTEE_SMC_L2CC_MUTEX_SET_ADDR	1
#define OPTEE_SMC_L2CC_MUTEX_ENABLE	2
#define OPTEE_SMC_L2CC_MUTEX_DISABLE	3
#define OPTEE_SMC_FUNCID_L2CC_MUTEX	8
#define OPTEE_SMC_L2CC_MUTEX \
	OPTEE_SMC_FAST_CALL_VAL(OPTEE_SMC_FUNCID_L2CC_MUTEX)

/*
 * Resume from RPC (for example after processing an IRQ)
 *
 * Call register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC
 * r1-3/w1-3	Value of r1-3/w1-3 when OPTEE_SMC_CALL_WITH_ARG returned
 *		OPTEE_SMC_RETURN_RPC in r0/w0
 *
 * Return register usage is the same as for OPTEE_SMC_*CALL_WITH_ARG above.
 *
 * Possible return values
 * OPTEE_SMC_RETURN_UNKNOWN_FUNCTION	Trusted OS does not recognize this
 *					function.
 * OPTEE_SMC_RETURN_OK			Original call completed, result
 *					updated in the previously supplied.
 *					struct opteem_arg
 * OPTEE_SMC_RETURN_RPC			Call suspended by RPC call to normal
 *					world.
 * OPTEE_SMC_RETURN_EBUSY		Trusted OS busy, try again later.
 * OPTEE_SMC_RETURN_ERESUME		Resume failed, the opaque resume
 *					information was corrupt.
 */
#define OPTEE_SMC_FUNCID_RETURN_FROM_RPC	3
#define OPTEE_SMC_CALL_RETURN_FROM_RPC \
	OPTEE_SMC_STD_CALL_VAL(OPTEE_SMC_FUNCID_RETURN_FROM_RPC)

#define OPTEE_SMC_RETURN_RPC_PREFIX_MASK	0xFFFF0000
#define OPTEE_SMC_RETURN_RPC_PREFIX		0xFFFF0000
#define OPTEE_SMC_RETURN_RPC_FUNC_MASK		0x0000FFFF

#define OPTEE_SMC_RETURN_GET_RPC_FUNC(ret) \
	((ret) & OPTEE_SMC_RETURN_RPC_FUNC_MASK)

#define OPTEE_SMC_RPC_VAL(func)		((func) | OPTEE_SMC_RETURN_RPC_PREFIX)

/*
 * Allocate argument memory for RPC parameter passing.
 * Argument memory is used to hold a struct opteem_arg.
 *
 * "Call" register usage:
 * r0/w0	This value, OPTEE_SMC_RETURN_RPC_ALLOC_ARG
 * r1/w1	Size in bytes of required argument memory
 * r2/w2	Not used
 * r3/w3	Resume information, must be preserved
 * r4-r5/w4	Not used
 * r6-7/w5-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1/w1	Upper 32bits of 64bit physical pointer to allocated argument
 *		memory, (r1 == 0 && r2 == 0) if size was 0 or if memory can't
 *		be allocated.
 * r2/w2	Lower 32bits of 64bit physical pointer to allocated argument
 *		memory, (r1 == 0 && r2 == 0) if size was 0 or if memory can't
 *		be allocated
 * r3/w3	Preserved
 * r4/w4	Upper 32bits of 64bit Shared memory cookie used when freeing
 *		the memory or doing an RPC
 * r5/w5	Lower 32bits of 64bit Shared memory cookie used when freeing
 *		the memory or doing an RPC
 * r6-7/w5-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_ALLOC_ARG	0
#define OPTEE_SMC_RETURN_RPC_ALLOC_ARG \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_ALLOC_ARG)

/*
 * Allocate payload memory for RPC parameter passing.
 * Payload memory is used to hold the memory referred to by struct
 * opteem_param_memref.
 *
 * "Call" register usage:
 * r0/w0	This value, OPTEE_SMC_RETURN_RPC_ALLOC_PAYLOAD
 * r1/w1	Size in bytes of required argument memory
 * r2/w2	Not used
 * r3/w3	Resume information, must be preserved
 * r4-5/w4-5	Not used
 * r6-7/w5-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1/w1	Upper 32bits of 64bit physical pointer to allocated argument
 *		memory, (r1 == 0 && r2 == 0) if size was 0 or if memory can't
 *		be allocated
 * r2/w2	Lower 32bits of 64bit physical pointer to allocated argument
 *		memory, (r1 == 0 && r2 == 0) if size was 0 or if memory can't
 *		be allocated
 * r3/w3	Preserved
 * r4/w4	Upper 32bits of 64bit Shared memory cookie used when freeing
 *		the memory
 * r5/w5	Lower 32bits of 64bit Shared memory cookie used when freeing
 *		the memory
 * r6-7/w5-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_ALLOC_PAYLOAD	1
#define OPTEE_SMC_RETURN_RPC_ALLOC_PAYLOAD \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_ALLOC_PAYLOAD)

/*
 * Free memory previously allocated by OPTEE_SMC_RETURN_RPC_ALLOC_ARG.
 *
 * "Call" register usage:
 * r0/w0	This value, OPTEE_SMC_RETURN_RPC_FREE_ARG
 * r1/w1	Upper 32bits of 64bit shared memory cookie belonging to this
 *		argument memory
 * r2/w2	Lower 32bits of 64bit shared memory cookie belonging to this
 *		argument memory
 * r3-7/w3-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1-2/w1-2	Not used
 * r3-7/w3-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_FREE_ARG	2
#define OPTEE_SMC_RETURN_RPC_FREE_ARG \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_FREE_ARG)

/*
 * Free memory previously allocated by OPTEE_SMC_RETURN_RPC_ALLOC_PAYLOAD.
 *
 * "Call" register usage:
 * r0/w0	This value, OPTEE_SMC_RETURN_RPC_FREE_PAYLOAD
 * r1/w1	Upper 32bit of 64bit shared memory cookie belonging to this
 *		payload memory
 * r2/w2	Lower 32bit of 64bit shared memory cookie belonging to this
 *		payload memory
 * r3-7/w3-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1-2/w1-2	Not used
 * r3-7/w2-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_FREE_PAYLOAD	3
#define OPTEE_SMC_RETURN_RPC_FREE_PAYLOAD \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_FREE_PAYLOAD)

/*
 * Deliver an IRQ in normal world.
 *
 * "Call" register usage:
 * r0/w0	OPTEE_SMC_RETURN_RPC_IRQ
 * r1-7/w1-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1-7/w1-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_IRQ		4
#define OPTEE_SMC_RETURN_RPC_IRQ \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_IRQ)

/*
 * Do an RPC request. The supplied struct opteem_arg tells which
 * request to do and the parameters for the request. The following fields
 * are used (the rest are unused):
 * - cmd		the Request ID
 * - ret		return value of the request, filled in by normal world
 * - num_params		number of parameters for the request
 * - params		the parameters
 * - param_attrs	attributes of the parameters
 *
 * "Call" register usage:
 * r0/w0	OPTEE_SMC_RETURN_RPC_CMD
 * r1/w1	Upper 32bit of a 64bit Shared memory cookie holding a
 *		struct opteem_arg, must be preserved, only the data should
 *		be updated
 * r2/w2	Lower 32bit of a 64bit Shared memory cookie holding a
 *		struct opteem_arg, must be preserved, only the data should
 *		be updated
 * r3-7/w3-7	Resume information, must be preserved
 *
 * "Return" register usage:
 * r0/w0	SMC Function ID, OPTEE_SMC_CALL_RETURN_FROM_RPC.
 * r1-2/w1-2	Not used
 * r3-7/w3-7	Preserved
 */
#define OPTEE_SMC_RPC_FUNC_CMD		5
#define OPTEE_SMC_RETURN_RPC_CMD \
	OPTEE_SMC_RPC_VAL(OPTEE_SMC_RPC_FUNC_CMD)

/* Returned in r0/w0 */
#define OPTEE_SMC_RETURN_UNKNOWN_FUNCTION 0xFFFFFFFF

/* Returned in r0/w0 only from Trusted OS functions */
#define OPTEE_SMC_RETURN_OK		0x0
#define OPTEE_SMC_RETURN_EBUSY		0x1
#define OPTEE_SMC_RETURN_ERESUME	0x2
#define OPTEE_SMC_RETURN_EBADADDR	0x3
#define OPTEE_SMC_RETURN_EBADCMD	0x4
#define OPTEE_SMC_RETURN_ENOMEM		0x5
#define OPTEE_SMC_RETURN_NOTAVAIL	0x6
#define OPTEE_SMC_RETURN_IS_RPC(ret) \
	(((ret) != OPTEE_SMC_RETURN_UNKNOWN_FUNCTION) && \
	((((ret) & OPTEE_SMC_RETURN_RPC_PREFIX_MASK) == \
		OPTEE_SMC_RETURN_RPC_PREFIX)))

#endif /* OPTEE_SMC_H */
