/*
 * Copyright (c) 2016-2017, NVIDIA CORPORATION. All rights reserved
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
#ifndef __UNISTD_H
#define __UNISTD_H

#include <stddef.h>
#include <sys/types.h>
#include <time.h>

extern ssize_t read (int fd, void *__buf, size_t nbytes);
extern ssize_t write(int fd, const void *buf, size_t nbytes);
extern int brk(void *addr);
extern pid_t gettid(void);
extern void exit(int status) __NO_RETURN;
extern int raise(int sig);
extern void abort(void);
extern int close(int);
extern int nanosleep(struct timespec *req, struct timespec *rem);

static inline int usleep(useconds_t usec)
{
   /* Explicit casts to silence warnings
    * usec is type useconds_t, which is unsigned int
    * tv_sec id type seconds_t, which is time_t, which is long
    * tv_nsec is long
    * it is always safe to cast int to long
    */
    struct timespec tm;
    tm.tv_sec  = (time_t) usec / 1000000;
    tm.tv_nsec = (long int) ((usec % 1000000) * 1000);
    return nanosleep(&tm, NULL);
}
#endif
