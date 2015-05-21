/*
 * Copyright (c) 2015, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */
#include <linux/linkage.h>

#define SMC_RES_X0_OFFS	0
#define SMC_RES_X2_OFFS	16

/*
 * void smccc_smc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct smccc_res *res)
 */
ENTRY(smccc_smc)
	smc	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #SMC_RES_X0_OFFS]
	stp	x2, x3, [x4, #SMC_RES_X2_OFFS]
	ret
ENDPROC(smccc_smc)

/*
 * void smccc_hvc(unsigned long a0, unsigned long a1, unsigned long a2,
 *		  unsigned long a3, unsigned long a4, unsigned long a5,
 *		  unsigned long a6, unsigned long a7, struct smccc_res *res)
 */
ENTRY(smccc_hvc)
	hvc	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #SMC_RES_X0_OFFS]
	stp	x2, x3, [x4, #SMC_RES_X2_OFFS]
	ret
ENDPROC(smccc_hvc)
