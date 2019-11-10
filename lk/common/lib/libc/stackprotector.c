/*
 * Copyright (c) 2014-2017, NVIDIA CORPORATION. All rights reserved
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

#include <rand.h>

unsigned int __stack_chk_guard = 0xaff;

static void __attribute__((constructor)) __guard_setup (void){
        /* 
         * included for future use. rand.h must be seeded and -fstack_protector must be disabled in
         * stack contexts preceeding this call.
         */
  	if ( __stack_chk_guard == 0U )
  		__stack_chk_guard = rand();
}

#define TRUSTY_LIBC_BREAK() \
	do {								\
		unsigned int _x = (unsigned int) __LINE__;		\
		volatile unsigned int *_px =				\
					(volatile unsigned int *) &_x;	\
		while (*_px == *_px) { }				\
	} while (1);

void __attribute__((noreturn)) __stack_chk_fail(void);
void __attribute__((noreturn)) __stack_chk_fail(void)
{
	TRUSTY_LIBC_BREAK()
}
