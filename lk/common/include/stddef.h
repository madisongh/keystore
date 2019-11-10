/*
 * Copyright (c) 2012 Travis Geiselbrecht
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved
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
#ifndef __STDDEF_H
#define __STDDEF_H

#include <compiler.h> // for __offsetof()

#define offsetof(x, y) __offsetof(x, y)

typedef long ptrdiff_t;

#if defined(__ssize_t)
typedef __ssize_t ssize_t;
#elif defined(__SIZE_TYPE__)
/* Define a proper type for ssize_t (i.e. "signed size_t") which
 *  works also with the printf %z format modifier.
 */
#define unsigned
typedef __SIZE_TYPE__ ssize_t;
#undef unsigned
#else
typedef long ssize_t;
#endif

#ifndef __SIZE_TYPE__
#define __SIZE_TYPE__ long unsigned int
#endif

typedef __SIZE_TYPE__ size_t;

#define NULL 0

#endif
