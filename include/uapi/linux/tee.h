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

#ifndef __TEE_H
#define __TEE_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * This file describes the API provided by the generic TEE driver to user
 * space
 */


/* Helpers to make the ioctl defines */
#define TEE_IOC_MAGIC	0xa4
#define TEE_IOC_BASE	0

/* Flags relating to shared memory */
#define TEE_IOCTL_SHM_MAPPED	0x1	/* memory mapped in normal world */
#define TEE_IOCTL_SHM_DMA_BUF	0x2	/* dma-buf handle on shared memory */

/**
 * struct tee_version - TEE versions
 * @data:		[out] Specific TEE driver protocol identification
 *
 * Identifies the specific TEE driver, @data can be a uuid or something else
 * which the client can identify the protocol to use in TEE_IOC_CMD
 * Used as argument for TEE_IOC_VERSION below.
 */
struct tee_ioctl_version_data {
	__u8 data[16];
};
/**
 * TEE_IOC_VERSION - query version of drivers
 *
 * Takes a tee_version struct and returns with the version numbers filled in.
 */
#define TEE_IOC_VERSION		_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 0, \
				     struct tee_ioctl_version_data)

/**
 * struct tee_cmd_data - Opaque command argument
 * @buf_ptr:	[in] A __user pointer to a command buffer
 * @buf_len:	[in] Length of the buffer above
 *
 * Opaque command data which is passed on to the specific driver. The command
 * buffer doesn't have to reside in shared memory.
 * Used as argument for TEE_IOC_CMD below.
 */
struct tee_ioctl_cmd_data {
	__u64 buf_ptr;
	__u64 buf_len;
};
/**
 * TEE_IOC_CMD - pass a command to the specific TEE driver
 *
 * Takes tee_cmd_data struct which is passed to the specific TEE driver.
 */
#define TEE_IOC_CMD		_IOR(TEE_IOC_MAGIC, TEE_IOC_BASE + 1, \
				     struct tee_ioctl_cmd_data)

/**
 * struct tee_shm_alloc_data - Shared memory allocate argument
 * @size:	[in/out] Size of shared memory to allocate
 * @flags:	[in/out] Flags to/from allocation.
 * @fd:		[out] dma_buf file descriptor of the shared memory
 *
 * The flags field should currently be zero as input. Updated by the call
 * with actual flags as defined by TEE_IOCTL_SHM_* above.
 * This structure is used as argument for TEE_IOC_SHM_ALLOC below.
 */
struct tee_ioctl_shm_alloc_data {
	__u64 size;
	__u32 flags;
	__s32 fd;
};
/**
 * TEE_IOC_SHM_ALLOC - allocate shared memory
 *
 * Allocates shared memory between the user space process and secure OS.
 * The returned file descriptor is used to map the shared memory into user
 * space. The shared memory is freed when the descriptor is closed and the
 * memory is unmapped.
 */
#define TEE_IOC_SHM_ALLOC	_IOWR(TEE_IOC_MAGIC, TEE_IOC_BASE + 2, \
				     struct tee_ioctl_shm_alloc_data)

/*
 * Five syscalls are used when communicating with the generic TEE driver.
 * open(): opens the device associated with the driver
 * ioctl(): as described above operating on the file descriptor from open()
 * close(): two cases
 *   - closes the device file descriptor
 *   - closes a file descriptor connected to allocated shared memory
 * mmap(): maps shared memory into user space
 * munmap(): unmaps previously shared memory
 */

#endif /*__TEE_H*/
