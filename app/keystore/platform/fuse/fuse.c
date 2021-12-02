/*
 * Copyright (c) 2019, NVIDIA Corporation. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>

#include <common.h>
#include <fuse.h>

#define FUSE_SECURITY_MODE_0_OFFSET		0x1a0
#define FUSE_SECURITY_MODE_0_MASK		(0x1 << 0)

/* True if device is in ODM Production Mode */
bool is_odm_production = true;
bool skip_fuse_read = false;

uint32_t is_device_odm_production_fused(bool *flag)
{
	uint32_t val = 0;
	void *fuse_base = NULL;

	/*
	 * If the security fuse was already read then return the
	 * previously read value
	 */
	if (skip_fuse_read == true) {
		*flag = is_odm_production;
		return NO_ERROR;
	}

	uint32_t *ret = (uint32_t *)mmap(NULL, TEGRA_FUSE_SIZE, MMAP_FLAG_IO_HANDLE, 2);
	if (IS_ERR(ret)) {
		TLOGE("%s: mmap failure: err = %d, size = %x\n",
			__func__, PTR_ERR(ret), TEGRA_FUSE_SIZE);
		return *ret;
	}

	fuse_base = (void *)ret;

	val = *((uint32_t *)(fuse_base + FUSE_SECURITY_MODE_0_OFFSET));
	val &= FUSE_SECURITY_MODE_0_MASK;

	if (munmap(fuse_base, TEGRA_FUSE_SIZE) != 0) {
		TLOGE("%s: failed to unmap fuse region\n", __func__);
	}

	if (!val)
		is_odm_production = false;

	/* Don't read the fuse again */
	skip_fuse_read = true;

	*flag = is_odm_production;
	return NO_ERROR;
}
