/*
 * Copyright (c) 2013-2016, Google, Inc. All rights reserved
 * Copyright (c) 2017-2019, NVIDIA CORPORATION. All rights reserved
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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <lk/init.h>
#include <arch/mmu.h>
#include <lib/sm.h>
#include <lib/sm/smcall.h>
#include <kernel/vm.h>
#include <lib/trusty/trusty_guest_ctx.h>
#include <lib/sm/sm_err.h>
#include <dev/interrupt/arm_gic.h>

#include "tipc_dev_ql.h"
#include "trusty_virtio.h"

#define LOCAL_TRACE 0

/*
 * NS buffer helper function
 */
static status_t get_ns_mem_buf(struct smc32_args *args,
			       ns_addr_t *ppa, ns_size_t *psz, uint *pflags)
{
	DEBUG_ASSERT(ppa);
	DEBUG_ASSERT(psz);
	DEBUG_ASSERT(pflags);

	status_t rc = smc32_decode_mem_buf_info(args, ppa, psz, pflags);
	if (rc != NO_ERROR) {
		LTRACEF("Failed (%d) to decode mem buf info\n", rc);
		return rc;
	}

	/* We expect NORMAL CACHED or UNCHACHED RW EL1 memory */
	uint mem_type = *pflags & ARCH_MMU_FLAG_CACHE_MASK;

	if (mem_type != ARCH_MMU_FLAG_CACHED &&
	    mem_type != ARCH_MMU_FLAG_UNCACHED) {
		LTRACEF("Unexpected memory type: 0x%x\n", *pflags);
		return ERR_INVALID_ARGS;
	}

	if ((*pflags & ARCH_MMU_FLAG_PERM_RO) ||
	    (*pflags & ARCH_MMU_FLAG_PERM_USER)) {
		LTRACEF("Unexpected access attr: 0x%x\n", *pflags);
		return ERR_INVALID_ARGS;
	}

	return NO_ERROR;
}

__WEAK long lock_bl_data_interface(void)
{
	return NO_ERROR;
}

__WEAK long handle_bl_data_interface(long data_type, paddr_t addr, size_t size)
{
	(void) data_type;
	(void) addr;
	(void) size;

	return NO_ERROR;
}

__WEAK long set_root_of_trust_params(paddr_t addr, size_t size)
{
	(void) addr;
	(void) size;

	return NO_ERROR;
}

/*
 * Translate internal errors to SMC errors
 */
long to_smc_error(long err)
{
	if (err >= 0) {
		return err;
	}
	switch (err) {
	case ERR_INVALID_ARGS:
		return SM_ERR_INVALID_PARAMETERS;

	case ERR_NOT_SUPPORTED:
		return SM_ERR_NOT_SUPPORTED;

	case ERR_NOT_ALLOWED:
		return SM_ERR_NOT_ALLOWED;

	default:
		return SM_ERR_INTERNAL_FAILURE;
	}
}

__WEAK long smc_hv_init(smc32_args_t *args)
{
	(void)args;

	return to_smc_error(NO_ERROR);
}

/*
 *  Handle standard Trusted OS SMC call function
 */
static long trusty_sm_stdcall(smc32_args_t *args)
{
	long res;
	ns_size_t ns_sz;
	ns_paddr_t ns_pa;
	uint ns_mmu_flags;
	uint32_t guest = args->params[SMC_ARGS_GUESTID];

	LTRACEF("Trusty SM service func %u args 0x%x 0x%x 0x%x %x\n",
		SMC_FUNCTION(args->smc_nr),
		args->params[0],
		args->params[1],
		args->params[2],
		guest);

	 if (((int32_t)guest != HV_GUEST_ID) &&
		(guest >= MAX_NUM_SUPPORTED_GUESTS)) {
		TRACEF("%s: Error. Unexpected guestID %u\n",
			__func__, guest);
		return SM_ERR_INVALID_PARAMETERS;
	}

	switch (args->smc_nr) {

	case SMC_SC_VIRTIO_GET_DESCR:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR) {
			res = virtio_get_description(ns_pa, ns_sz,
						     ns_mmu_flags, guest);
		}
		break;

	case SMC_SC_VIRTIO_START:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR) {
			res = virtio_start(ns_pa, ns_sz, ns_mmu_flags, guest);
		}
		break;

	case SMC_SC_VIRTIO_STOP:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR) {
			res = virtio_stop(ns_pa, ns_sz, ns_mmu_flags, guest);
		}
		break;

	case SMC_SC_VDEV_RESET:
		res = virtio_device_reset(args->params[0], guest);
		break;

	case SMC_SC_VDEV_KICK_VQ:
		res = virtio_kick_vq(args->params[0], args->params[1], guest);
		break;

	/**
	 * This SMC ensures that parameters that were not set by the BL stay
	 * inaccessible to the kernel. It is an additional layer of security
	 * for sensitive parameters against BL bugs, version mismatches, or
	 * rollback attacks.
	 */
	case SMC_SC_BL_LOCK_TOS_DATA:
		res = lock_bl_data_interface();
		break;

	case SMC_SC_BL_SEND_TOS_DATA:
		res = handle_bl_data_interface((long)args->params[0],
						(paddr_t)args->params[1],
						(size_t)args->params[2]);
		break;

	case SMC_SC_SET_ROOT_OF_TRUST:
		res = set_root_of_trust_params((paddr_t)args->params[0],
						(uint)args->params[1]);
		break;

	case SMC_SC_CREATE_QL_TIPC_DEV:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR)
			res = ql_tipc_create_device(ns_pa, ns_sz, ns_mmu_flags);
		break;

	case SMC_SC_SHUTDOWN_QL_TIPC_DEV:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR)
			res = ql_tipc_shutdown_device(ns_pa);
		break;

	case SMC_SC_HANDLE_QL_TIPC_DEV_CMD:
		res = get_ns_mem_buf(args, &ns_pa, &ns_sz, &ns_mmu_flags);
		if (res == NO_ERROR)
			res = ql_tipc_handle_cmd(ns_pa, ns_sz);
		break;

	default:
		LTRACEF("unknown func 0x%x\n", SMC_FUNCTION(args->smc_nr));
		res = ERR_NOT_SUPPORTED;
		break;
	}

	return to_smc_error(res);
}

/*
 *  Handle parameterized NOP Trusted OS SMC call function
 */
static long trusty_sm_nopcall(smc32_args_t *args)
{
	long res;
	uint32_t guest = args->params[SMC_ARGS_GUESTID];

	LTRACEF("Trusty SM service func %u args 0x%x 0x%x 0x%x %x\n",
		SMC_FUNCTION(args->smc_nr),
		args->params[0],
		args->params[1],
		args->params[2],
		guest);

	if (((int32_t)guest != HV_GUEST_ID) &&
		(guest >= MAX_NUM_SUPPORTED_GUESTS)) {
		TRACEF("%s: Error. Unexpected guestID %u\n",
			__func__, guest);
		return SM_ERR_INVALID_PARAMETERS;
	}

	switch (args->params[0]) {
	case SMC_NC_VDEV_KICK_VQ:
		res = virtio_kick_vq(args->params[1], args->params[2], guest);
		break;

	case SMC_NC_SIM_HANDLE_IRQ:
		res = arm_gic_sim_irq_handler(args->params[1]);
		break;

	default:
		LTRACEF("unknown func 0x%x\n", SMC_FUNCTION(args->smc_nr));
		res = ERR_NOT_SUPPORTED;
		break;
	}

	return to_smc_error(res);
}

static smc32_entity_t trusty_sm_entity = {
	.stdcall_handler = trusty_sm_stdcall,
	.nopcall_handler = trusty_sm_nopcall
};

static void trusty_sm_init(uint level)
{
	int err;

	dprintf(INFO, "Initializing Trusted OS SMC handler\n");

	err = sm_register_entity(SMC_ENTITY_TRUSTED_OS, &trusty_sm_entity);
	if (err) {
		TRACEF("WARNING: Cannot register SMC entity! (%d)\n", err);
	}
}
LK_INIT_HOOK(trusty_smcall, trusty_sm_init, LK_INIT_LEVEL_APPS);

