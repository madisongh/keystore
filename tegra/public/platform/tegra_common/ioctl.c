/*
 * Copyright (c) 2018, NVIDIA CORPORATION. All rights reserved
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

#include <uthread.h>

#include <kernel/thread.h>
#include <lib/trusty/trusty_app.h>
#include <lib/trusty/ioctl.h>
#include <platform/platform_p.h>
#include <platform/boot_params.h>

static bool valid_address(vaddr_t addr, size_t size)
{
	return uthread_is_valid_range(uthread_get_current(), addr, size);
}

int32_t ioctl_map_eks_to_user(ioctl_map_eks_params p)
{
	if (!valid_address((vaddr_t)p.eks_addr_ptr, sizeof(uint32_t)))
		return ERR_INVALID_ARGS;
	if (!valid_address((vaddr_t)p.eks_size_ptr, sizeof(uint32_t)))
		return ERR_INVALID_ARGS;
	if (!valid_address((vaddr_t)p.map_addr_ptr, sizeof(uint32_t)))
		return ERR_INVALID_ARGS;
	if (!valid_address((vaddr_t)p.map_size_ptr, sizeof(uint32_t)))
		return ERR_INVALID_ARGS;

	status_t ret = NO_ERROR;
	eks_info_t info = {0};

	/*
	 * Get eks struct's physical address and length
	 * saved in kernel context
	 */
	ret = get_and_clear_eks_info(&info);
	if (ret != NO_ERROR) {
		dprintf(CRITICAL, "%s: ERROR: failed to retrieve eks info from kernel\n", __func__);
		return ret;
	}
	if (info.paddr == NULL) {
		dprintf(CRITICAL, "%s: ERROR: ioctl called more than once\n", __func__);
		return ERR_NOT_ALLOWED;
	}

	/* map to userspace */
	vaddr_t vaddr = 0U;
	trusty_app_t *trusty_app = uthread_get_current()->private_data;

	paddr_t paddr = ROUNDDOWN((paddr_t)info.paddr, PAGE_SIZE);
	size_t offset = (paddr_t)info.paddr - paddr;
	size_t size = ROUNDUP(info.blob_length + offset, PAGE_SIZE);

	ret = uthread_map_contig(trusty_app->ut, &vaddr,
			paddr, size,
			(uint32_t)UTM_R | (uint32_t)UTM_NS_MEM,
			UT_MAP_ALIGN_4KB);

	if (ret != NO_ERROR) {
		dprintf(CRITICAL, "%s error: failed to map eks physical address: %x, %u\n", __func__,
			(unsigned int)paddr, (unsigned int)size);
		return ret;
	}

	key_params* keys_params = (key_params *)(vaddr + offset);
	vaddr_t key_string_addr = (vaddr_t)keys_params->encrypted_keys;
	vaddr_t key_size = keys_params->encrypted_key_sz;

	copy_to_user((user_addr_t)p.eks_addr_ptr, &key_string_addr, sizeof(uint32_t));
	copy_to_user((user_addr_t)p.eks_size_ptr, &key_size, sizeof(uint32_t));
	copy_to_user((user_addr_t)p.map_addr_ptr, &vaddr, sizeof(uint32_t));
	copy_to_user((user_addr_t)p.map_size_ptr, &size, sizeof(uint32_t));

	return NO_ERROR;
}
