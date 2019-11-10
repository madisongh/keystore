/*
 * Copyright (c) 2017-2019, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __LIB_IOCTL_H
#define __LIB_IOCTL_H

#include <sys/types.h>

/*
 * IOCTL numbers are 32 bits. The 3 MSB-most bits signify whether the
 * ioctl is present in public source releases, partner source
 * releases, and private source releases. If the corresponding bit is
 * set to 1 the the ioctl is present in that release style. The
 * remaining bits hold the ioctl number.
 *
 * ioctl_nr : [ PRIVATE | PARTNER | PUBLIC | IOCTL_NR ]
 * bit      : [ 31      | 30      | 29     | 28:0     ]
 */

#define IOCTL_PUBLIC_MASK	(0x20000000U)
#define IOCTL_PARTNER_MASK	(0x40000000U | IOCTL_PUBLIC_MASK)
#define IOCTL_PRIVATE_MASK	(0x80000000U | IOCTL_PARTNER_MASK)

#define IOCTL_NR(num, mask)	((mask & ~0x1FFFFFFFU) | (num & 0x1FFFFFFFU))

#if defined(WITH_PLATFORM_PARTNER)
#include <partner/lib/trusty/ioctl.h>
#endif

#define IOCTL_MAP_EKS_TO_USER	IOCTL_NR(0x01U, IOCTL_PUBLIC_MASK)

typedef struct {
	uint32_t eks_addr_ptr;
	uint32_t eks_size_ptr;
	uint32_t map_addr_ptr;
	uint32_t map_size_ptr;
} ioctl_map_eks_params;

/* Map EKS from kernel to TA, which can only be called by NVCrypto when booting.
 * Unmapping this memory is the responsibility of the caller TA.
 */
int32_t ioctl_map_eks_to_user(ioctl_map_eks_params p);

#endif /* __LIB_IOCTL_H */
