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
#include <linux/linkage.h>

#include <asm/opcodes-sec.h>

/* void smccc_call32(struct smccc_param32 *param) */
ENTRY(smccc_call32)
	push	{r4-r8, lr}
	mov	r8, r0
	ldm	r8, {r0-r7}
	__SMC(0)
	stm	r8, {r0-r7}
	pop	{r4-r8, pc}
ENDPROC(smccc_call32)
