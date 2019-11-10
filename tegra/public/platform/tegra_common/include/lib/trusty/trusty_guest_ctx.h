/*
 * Copyright (c) 2017, NVIDIA CORPORATION. All rights reserved.
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

#ifndef __TRUSTY_GUEST_CTX_H
#define __TRUSTY_GUEST_CTX_H
#include <stdint.h>
#include <sys/types.h>

#define MAX_NUM_SUPPORTED_GUESTS	16U
#define HV_GUEST_ID			((int64_t)-1)
#define NULL_PTR			((void *)0)
#define DEFAULT_GUEST_ID		(0xDEADFEED)
/*
 * Called in virtualization config when hyp calls into
 * TOS with the guest configuration.
 */
status_t tipc_hyp_init(uint32_t num_guests);

/*
 * Allocate virtio bus for all guests HV tells TOS
 */
status_t alloc_guest_virtio_bus(uint32_t total_num_guests);

/*
 *  Free the virtio bus
 */
void free_guest_virtio_bus(void);

#endif //__TRUSTY_GUEST_CTX_H
