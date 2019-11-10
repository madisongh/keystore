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

#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <trace.h>
#include <kernel/vm.h>
#include <lib/sm.h>
#include <platform/rollback_prevention.h>

#include <platform/boot_params.h>
#include <platform/platform_p.h>

#define MAXIMUM_ENCRYPTED_KEYS_SIZE	(32 * PAGE_SIZE)

#define LOCAL_TRACE 0

extern uint32_t debug_uart_id;
uint32_t device_uid[DEVICE_UID_SIZE_WORDS];
struct rollback rb_data;

/* Structure to hold EKS information */
static eks_info_t eks_info;

status_t get_and_clear_eks_info(eks_info_t *info)
{
	if (!platform_is_bootstrapping()) {
		dprintf(CRITICAL, "%s: ERROR: Not allowed after boot\n", __func__);
		return ERR_NOT_ALLOWED;
	}
	if (info == NULL) {
		dprintf(CRITICAL, "%s: ERROR: Attempting to access NULL pointer\n", __func__);
		return ERR_INVALID_ARGS;
	}
	info->paddr = eks_info.paddr;
	info->blob_length = eks_info.blob_length;

	/* clear eks_info, so this method cannot be used again */
	eks_info.paddr = NULL;
	eks_info.blob_length = 0;

	return NO_ERROR;
}

static void parse_bootargs(boot_params_t *boot_params_ptr)
{
	const void *dest = NULL;
	device_uid[0] = boot_params_ptr->chip_uid[0];
	device_uid[1] = boot_params_ptr->chip_uid[1];
	device_uid[2] = boot_params_ptr->chip_uid[2];
	device_uid[3] = boot_params_ptr->chip_uid[3];

	debug_uart_id = boot_params_ptr->uart_id;

	dest = memcpy((void *)&rb_data, (const void *)&(boot_params_ptr->rb_data),
		sizeof(struct rollback));

	if (dest != (void *)&rb_data) {
		TRACEF("error while doing mem copy\n");
	}
}

__WEAK status_t partner_process_boot_params(boot_params_t *boot_params)
{
	return NO_ERROR;
};

status_t process_boot_params(void)
{
	boot_params_t *boot_params;
	key_params *keys_params;
	size_t total_length, keys_length;
	uint32_t offset;
	status_t ret;
	/* get boot args */
	if ((ret = sm_get_boot_args((void **)&boot_params, &total_length))
			!= NO_ERROR) {
		LTRACEF("sm_get_boot_args failed: %d\n", ret);
		return ret;
	}

	if (!boot_params) {
		ret = ERR_NOT_CONFIGURED;
		goto release_bootargs;
	}

	if (total_length < sizeof(boot_params_t)) {
		ret = ERR_BAD_LEN;
		goto release_bootargs;
	}

	/* Find keys_params located at the end of boot_params. */
	offset = sizeof(boot_params_t);
	keys_params = (key_params *)((uintptr_t)boot_params + offset);

	parse_bootargs(boot_params);

	keys_length = keys_params->encrypted_key_sz;
	LTRACEF("bootargs_version = 0x%x\n", boot_params->version);
	LTRACEF("keys_length = 0x%zx, keys_offset 0x%x\n", keys_length, offset);

        if (keys_length > MAXIMUM_ENCRYPTED_KEYS_SIZE) {
		TRACEF("encrypted key length (%zu) exceeds maximum key length (%lu)\n",
			keys_length, MAXIMUM_ENCRYPTED_KEYS_SIZE);
		eks_info.paddr = NULL;
		eks_info.blob_length = 0;
		ret = ERR_BAD_LEN;
		goto release_bootargs;
	}

	/*
	 * Store EKS base physical address and length of EKS blob
	 * in the kernel's context for TA use
	 */
	eks_info.paddr = kvaddr_to_paddr(keys_params);
	eks_info.blob_length = keys_length;

	ret = partner_process_boot_params(boot_params);
 	if (ret != NO_ERROR) {
		LTRACEF("process_boot_params_partner failed: %d\n", ret);
		return ret;
	}

release_bootargs:
	/* release boot args reference */
	sm_put_boot_args();

	return ret;
}
