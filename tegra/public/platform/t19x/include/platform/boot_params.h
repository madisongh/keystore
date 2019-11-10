/*
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

#ifndef __BOOT_PARAMS_H
#define __BOOT_PARAMS_H

#include <sys/types.h>
#include <platform/rollback_prevention.h>

#define DEVICE_UID_SIZE_WORDS	4

typedef struct {
	uint32_t	encrypted_key_sz;
	char		encrypted_keys[];		// encrypted keys
} key_params;

typedef struct boot_params {
	uint32_t version;
	uint32_t uart_id;
	uint32_t chip_uid[DEVICE_UID_SIZE_WORDS];
	uint64_t pmem;
	uint64_t pmem_size;
	uint64_t emem;
	uint64_t emem_size;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t dtb_load_addr;
	struct rollback rb_data;
} boot_params_t;

#endif
