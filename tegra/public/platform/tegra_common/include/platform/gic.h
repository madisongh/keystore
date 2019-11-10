/*
 * Copyright (c) 2012 Travis Geiselbrecht
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved
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
#ifndef __PLATFORM_GIC_H
#define __PLATFORM_GIC_H

#include <platform/memmap.h>

#define GICC_OFFSET (0x2000)
#define GICD_OFFSET (0x1000)

#define GICBASE(n)			TEGRA_ARM_PERIF_BASE

#define INT_GIC_BASE			0
#define INT_PRI_BASE			(INT_GIC_BASE + 32)
#define INT_SEC_BASE			(INT_PRI_BASE + 32)
#define INT_TRI_BASE			(INT_SEC_BASE + 32)
#define INT_QUAD_BASE			(INT_TRI_BASE + 32)
#define INT_QUINT_BASE			(INT_QUAD_BASE + 32)
#define INT_SYNCPT_THRESH_BASE		(INT_QUINT_BASE + 32)
#define INT_SYNCPT_THRESH_NR		32
#define INT_GPIO_BASE			(INT_SYNCPT_THRESH_BASE + \
					 INT_SYNCPT_THRESH_NR)
#define INT_GPIO_NR			(32 * 8)
#define INT_PCI_MSI_BASE		(INT_GPIO_BASE + \
					 INT_GPIO_NR)
#define INT_PCI_MSI_NR			(32 * 8)
#define TEGRA_NR_IRQS			(INT_PCI_MSI_BASE + \
							INT_PCI_MSI_NR)
#define INT_BOARD_BASE			TEGRA_NR_IRQS
#define NR_BOARD_IRQS			64

#define MAX_INT				(INT_BOARD_BASE + NR_BOARD_IRQS)

#endif /*__PLATFORM_GIC_H */
