/*
 * Copyright (c) 2008 Travis Geiselbrecht
 * Copyright (c) 2012-2019, NVIDIA CORPORATION. All rights reserved
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
#ifndef __PLATFORM_P_H
#define __PLATFORM_P_H

#include <lib/trusty/uuid.h>
#include <stdbool.h>
#include <lib/sm.h>
#if defined(WITH_PLATFORM_PARTNER)
#include <partner/platform/platform_p.h>
#endif

/* Structure to hold EKS information */
typedef struct {
	paddr_t paddr;
	uint32_t blob_length;
} eks_info_t;

status_t get_and_clear_eks_info(eks_info_t *info);

void platform_init_debug_port(unsigned int dbg_port);
void platform_disable_debug_intf(void);
void platform_enable_debug_intf(void);
bool platform_is_bootstrapping(void);
void tegra_platform_bootstrap_epilog(void);
long platform_register_ns_dram_ranges(paddr_t ns_base, uint64_t ns_size);
status_t platform_validate_ns_phys_range(paddr_t ns_addr, uint64_t ns_size);
bool platform_validate_range(uint64_t bound_base, uint64_t bound_size,
				uint64_t test_base, uint64_t test_size);
bool platform_is_denver_cpu(void);

#endif
