/*
 * Copyright (c) 2018, NVIDIA CORPORATION. All rights reserved.
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

#ifndef __DENVER_H__
#define __DENVER_H__

#define DENVER_MIDR_PN0		0x4E0F0000U
#define DENVER_MIDR_PN1		0x4E0F0010U
#define DENVER_MIDR_PN2		0x4E0F0020U
#define DENVER_MIDR_PN3		0x4E0F0030U
#define DENVER_MIDR_PN4		0x4E0F0040U

/* Implementer code in the MIDR register */
#define DENVER_IMPL		0x4EU

#define MIDR_IMPL_SHIFT		24
#define MIDR_IMPL_MASK		0xFFU

/* Speculative store buffering */
#define DENVER_CPU_DIS_SSB_EL0		(1U << 12)
#define DENVER_CPU_DIS_SSB_EL1		(1U << 11)
#define DENVER_PN4_CPU_DIS_SSB_EL0	(1U << 9)
#define DENVER_PN4_CPU_DIS_SSB_EL1	(1U << 8)

/* Speculative memory disambiguation */
#define DENVER_CPU_DIS_MD_EL0		(1U << 10)
#define DENVER_CPU_DIS_MD_EL1		(1U << 9)
#define DENVER_PN4_CPU_DIS_MD_EL0	(1U << 7)
#define DENVER_PN4_CPU_DIS_MD_EL1	(1U << 6)

#endif /* __DENVER_H__ */
