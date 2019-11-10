/*
 * Copyright (c) 2014-2015, Google, Inc. All rights reserved
 * Copyright (c) 2017, NVIDIA Corporation. All rights reserved
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

#include <err.h>
#include <assert.h>
#include <trace.h>
#include <platform/speculation_barrier.h>

#include <lk/init.h>
#include <lib/trusty/tipc_dev.h>
#include <lib/trusty/trusty_guest_ctx.h>

/* Default TIPC device (/dev/trusty-ipc-dev0) */
DECLARE_TIPC_DEVICE_DESCR(_descr0, 0, 32, 32, "dev0");

status_t tipc_hyp_init(uint32_t num_guests)
{
	status_t ret = NO_ERROR;
	uint32_t num_additional_guests;
	uint32_t guest;

	/* Virtio bus for guest 0 would have already
	 * been created at TOS init. Return here if
	 * num of guests = 0 or 1 */
	if (num_guests <= 1)
		return NO_ERROR;

	if (num_guests > MAX_NUM_SUPPORTED_GUESTS) {
		TRACEF("%s: ERROR: Registering num_guests %u > %u\n",
			__func__, num_guests, MAX_NUM_SUPPORTED_GUESTS);
		return ERR_INVALID_ARGS;
	}

	/* Barrier against speculating num_guests and later guest in the for loop */
	platform_arch_speculation_barrier();

	/* Virtio bus for guest 0 would have already been created at TOS init */
	num_additional_guests = num_guests - 1;

	ret = alloc_guest_virtio_bus(num_additional_guests);
	if (ret != NO_ERROR) {
		TRACEF("ERROR: failed to allocate virtio bus"
			"for %d VMs, err = %d\n", num_additional_guests, ret);
		return ret;
	}
	for (guest = 1; guest <= num_additional_guests; guest++) {
		ret = create_tipc_device(&_descr0, sizeof(struct tipc_vdev_descr),
				&zero_uuid, guest, NULL_PTR);
		if (ret != NO_ERROR) {
			TRACEF("ERROR: failed to create tipc device"
				"for VM = %d, error = %d\n", guest, ret);
			free_guest_virtio_bus();
			return ret;
		}
	}

	return ret;
}

/*
 *  Returns true if uuid is associated with NS client.
 */
bool is_ns_client(const uuid_t *uuid)
{
	if (uuid == &zero_uuid) {
		return true;
	}
	return false;
}

static void tipc_init(uint level)
{
	status_t res;

	res = create_tipc_device(&_descr0, sizeof(_descr0), &zero_uuid, 0, NULL);
	if (res != NO_ERROR) {
		TRACEF("WARNING: failed (%d) to register tipc device\n", res);
	}
}

LK_INIT_HOOK_FLAGS(tipc_init, tipc_init,
                   LK_INIT_LEVEL_APPS-2, LK_INIT_FLAG_PRIMARY_CPU);

