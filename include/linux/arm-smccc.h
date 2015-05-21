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
#ifndef __LINUX_ARM_SMCCC_H
#define __LINUX_ARM_SMCCC_H

#include <linux/types.h>
#include <linux/linkage.h>

/*
 * This file provides common defines for ARM SMC Calling Convention as
 * specified in
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

#define SMCCC_SMC_32			(0 << 30)
#define SMCCC_SMC_64			(1 << 30)
#define SMCCC_FAST_CALL			(1 << 31)
#define SMCCC_STD_CALL			(0 << 31)

#define SMCCC_OWNER_MASK		0x3F
#define SMCCC_OWNER_SHIFT		24

#define SMCCC_FUNC_MASK			0xFFFF

#define SMCCC_IS_FAST_CALL(smc_val)	((smc_val) & SMCCC_FAST_CALL)
#define SMCCC_IS_64(smc_val)		((smc_val) & SMCCC_SMC_64)
#define SMCCC_FUNC_NUM(smc_val)		((smc_val) & SMCCC_FUNC_MASK)
#define SMCCC_OWNER_NUM(smc_val) \
	(((smc_val) >> SMCCC_OWNER_SHIFT) & SMCCC_OWNER_MASK)

#define SMCCC_CALL_VAL(type, calling_convention, owner, func_num) \
			((type) | (calling_convention) | \
			(((owner) & SMCCC_OWNER_MASK) << SMCCC_OWNER_SHIFT) | \
			((func_num) & SMCCC_FUNC_MASK))

#define SMCCC_OWNER_ARCH		0
#define SMCCC_OWNER_CPU			1
#define SMCCC_OWNER_SIP			2
#define SMCCC_OWNER_OEM			3
#define SMCCC_OWNER_STANDARD		4
#define SMCCC_OWNER_TRUSTED_APP		48
#define SMCCC_OWNER_TRUSTED_APP_END	49
#define SMCCC_OWNER_TRUSTED_OS		50
#define SMCCC_OWNER_TRUSTED_OS_END	63

/**
 * struct smccc_res - Result from SMC/HVC call
 * @a0-a3 result values from registers 0 to 3
 */
struct smccc_res {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
};

/**
 * smccc_smc() - make SMC calls
 * @a0-a7: arguments passed in registers 0 to 7
 * @res: result values from registers 0 to 3
 *
 * This function is used to make SMC calls following SMC Calling Convention.
 * The content of the supplied param are copied to registers 0 to 7 prior
 * to the SMC instruction. The return values are updated with the content
 * from register 0 to 3 on return from the SMC instruction.
 */
asmlinkage void smccc_smc(unsigned long a0, unsigned long a1, unsigned long a2,
			unsigned long a3, unsigned long a4, unsigned long a5,
			unsigned long a6, unsigned long a7,
			struct smccc_res *res);

/**
 * smccc_hvc() - make HVC calls
 * @a0-a7: arguments passed in registers 0 to 7
 * @res: result values from registers 0 to 3
 *
 * This function is used to make HVC calls following SMC Calling
 * Convention.  The content of the supplied param are copied to registers 0
 * to 7 prior to the HVC instruction. The return values are updated with
 * the content from register 0 to 3 on return from the HVC instruction.
 */
asmlinkage void smccc_hvc(unsigned long a0, unsigned long a1, unsigned long a2,
			unsigned long a3, unsigned long a4, unsigned long a5,
			unsigned long a6, unsigned long a7,
			struct smccc_res *res);

#endif /*__LINUX_ARM_SMCCC_H*/
