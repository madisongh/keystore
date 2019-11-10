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

#include <stdlib.h>
#include <trace.h>
#include <lib/trusty/hyp.h>
#include <err.h>
#include <assert.h>

#define LOCAL_TRACE 0

bool __WEAK trusty_hyp_is_ctx_available(void)
{
	return false;
}

long __WEAK trusty_hyp_check_guest_pa_valid(uint64_t buf_pa_start,
		uint64_t buf_size, uint32_t guest)
{
	(void) buf_pa_start;
	(void) buf_size;
	(void) guest;

	return NO_ERROR;
}

int __WEAK trusty_hyp_check_guest_access(uint32_t guest, const uuid_t *peer)
{
	(void) guest;
	(void) peer;

	return NO_ERROR;
}
