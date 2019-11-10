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

#include <debug.h>
#include <uthread.h>
#include <string.h>
#include <trace.h>
#include <uthread.h>

#include <lib/trusty/ioctl.h>
#include <lib/trusty/trusty_app.h>
#include <platform/platform_p.h>
#include <trusty_std.h>

static bool valid_address(vaddr_t addr, size_t size)
{
	return uthread_is_valid_range(uthread_get_current(), addr, size);
}

int32_t sys_std_platform_ioctl_partner(uint32_t fd, uint32_t cmd, user_addr_t user_ptr);

int32_t __WEAK sys_std_platform_ioctl_partner(uint32_t fd, uint32_t cmd, user_addr_t user_ptr)
{
	dprintf(ALWAYS, "Unsupported IOCTL request: %d\n", cmd);
	return ERR_NOT_SUPPORTED;
}

int32_t sys_std_platform_ioctl(uint32_t fd, uint32_t cmd, user_addr_t user_ptr)
{
	int32_t ret = 0;
	DEBUG_ASSERT( fd == 3 ); // sys_fd of ioctl

	switch ( cmd ) {
		case IOCTL_MAP_EKS_TO_USER:

			if (!valid_address((vaddr_t)user_ptr,
					sizeof(ioctl_map_eks_params))) {
				dprintf(CRITICAL, "%s error: Invalid arguments\n",
						__func__);
				return ERR_INVALID_ARGS;
			}

                        /* This ioctl should only be called during boot */
			if (!platform_is_bootstrapping()) {
				dprintf(CRITICAL, "%s: ERROR: Not allowed after boot\n",
						__func__);
				return ERR_NOT_ALLOWED;
			}

			ioctl_map_eks_params params;
			copy_from_user(&params, user_ptr,
					sizeof(ioctl_map_eks_params));

			return ioctl_map_eks_to_user(params);

		default:
			ret = sys_std_platform_ioctl_partner(fd, cmd, user_ptr);
        }
	return ret;
}
