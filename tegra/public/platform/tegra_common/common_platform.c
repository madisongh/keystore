/*
 * Copyright (c) 2016-2019, NVIDIA CORPORATION. All rights reserved.
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
#include <platform/platform_p.h>
#include <err.h>
#include <string.h>
#include <arch/arch_ops.h>
#include <list.h>
#include <arch/mmu.h>
#include <stdlib.h>
#include <kernel/vm.h>
#include <lib/cpus/denver.h>
#include <lib/trusty/hyp.h>

static struct {
	bool bootstrap_done;
} platform_state = {
	.bootstrap_done = false,
};

// platform specific hook for epilog
__WEAK void tegra_platform_bootstrap_epilog(void) {}

typedef struct {
	uint64_t base;
	uint64_t size;
} tos_ns_mem_map_entry_t;

typedef struct {
	tos_ns_mem_map_entry_t ns_dram_entry;
	struct list_node node;
} tos_ns_dram_map_node_t;

typedef struct {
	bool ns_dram_range_available;
	struct list_node ns_dram_map_list_head;
} tos_platform_ctx_t;

static tos_platform_ctx_t platform_ctx = {
	.ns_dram_range_available = false,
	.ns_dram_map_list_head = LIST_INITIAL_VALUE(platform_ctx.ns_dram_map_list_head)
};

bool platform_is_bootstrapping(void)
{
	return !platform_state.bootstrap_done;
}

/*
 * Defining a common platform_bootstrap_epilog handler. If platform specific
 * cleanups are required, implement a platform specific epilog handler.
 */
void platform_bootstrap_epilog(void)
{
	platform_state.bootstrap_done = true;
	tegra_platform_bootstrap_epilog();
	/*
	 * Choosing not to print on embedded platforms due to suspicion of
	 * its impact on boot KPI
	 */
#if !defined(TRUSTY_TARGET_PLATFORM_EMBEDDED)
	dprintf(ALWAYS, "%s: trusty bootstrap complete\n", __func__);
#endif
}

void platform_arch_speculation_barrier(void) {

#if defined(INSERT_SPECULATION_BARRIER)
	mb();
	ISB;
#endif

	return;
}

long platform_register_ns_dram_ranges(paddr_t ns_base, uint64_t ns_size)
{
#define TOS_NS_MEM_MAP_MAGIC_VALUE (0xfeedbeef)
#define TOS_NS_MEM_MAP_CUR_VERSION (0x1)
	dprintf(SPEW, "%s: ns_base: %lx, ns_size: %llu\n", __func__, ns_base, ns_size);

	/*Register DRAM ranges only once*/
	if (platform_ctx.ns_dram_range_available)
		return ERR_ALREADY_EXISTS;

	typedef struct __attribute__ ((packed)) {
		uint32_t magic;
		uint32_t ver;
		uint32_t num;
		uint8_t reserved[2];
		tos_ns_mem_map_entry_t mappings[0];
	} tos_ns_mem_map_t;
	uint32_t map_index = 0;
	tos_ns_dram_map_node_t *map_node = NULL, *tmp_map_node = NULL;
	tos_ns_mem_map_t *ns_mem_map = NULL;

	size_t aligned_size;
	paddr_t aligned_addr;
	ulong offset;
	vaddr_t vptr;
	long ret = NO_ERROR;

	offset = ns_base & (PAGE_SIZE - 1);
	aligned_addr = ROUNDDOWN(ns_base, PAGE_SIZE);
	aligned_size = ROUNDUP(ns_size + offset, PAGE_SIZE);

	ret = vmm_alloc_physical(vmm_get_kernel_aspace(), "cboot",
			aligned_size, (void **)&vptr, PAGE_SIZE_SHIFT,
			aligned_addr, 0,
			ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE |
			ARCH_MMU_FLAG_CACHED | ARCH_MMU_FLAG_PERM_RO);

	if (ret != NO_ERROR) {
		dprintf(CRITICAL, "%s: FATAL: unable to map shared memory. "
				"Trusty may fail to validate NS DRAM ranges\n"
				, __func__);
		return ret;
	}

	ns_mem_map = (tos_ns_mem_map_t *) (vptr + offset);

	/* Memory sanitization check */
	if (ns_mem_map->magic != TOS_NS_MEM_MAP_MAGIC_VALUE) {
		dprintf(CRITICAL, "%s: FATAL: unable to locate magic value "
				"(expected: 0x%x, actual: 0x%x). "
				"Trusty may fail to validate NS DRAM ranges\n",
				__func__,
				TOS_NS_MEM_MAP_MAGIC_VALUE,
				ns_mem_map->magic);
		ret = ERR_INVALID_ARGS;
		goto lbl_free_vmm;
	}

	/* Check supported API version */
	if (ns_mem_map->ver != TOS_NS_MEM_MAP_CUR_VERSION) {
		dprintf(CRITICAL, "%s: FATAL: unsupported version "
				"(expected: %u, actual: %u). "
				"Trusty may fail to validate NS DRAM ranges\n",
				__func__,
				TOS_NS_MEM_MAP_CUR_VERSION,
				ns_mem_map->ver);
		ret = ERR_INVALID_ARGS;
		goto lbl_free_vmm;
	}

	for (map_index = 0; map_index < ns_mem_map->num; map_index++) {
		tos_ns_dram_map_node_t *dram_map_node = calloc(1, sizeof(tos_ns_dram_map_node_t));
		if (NULL == dram_map_node) {
			dprintf(CRITICAL, "%s: FATAL: unable to allocate memory. "
					"object(dram_map_node) "
					"Trusty may fail to validate NS DRAM ranges\n",
					__func__);
			ret = ERR_NO_MEMORY;
			goto err_free_dram_map;
		}
		memcpy(&dram_map_node->ns_dram_entry, &ns_mem_map->mappings[map_index],
				sizeof(tos_ns_mem_map_entry_t));

		dprintf(SPEW, "%s: base: %llx size: %llu entry size: %zu\n", __func__,
				dram_map_node->ns_dram_entry.base,
				dram_map_node->ns_dram_entry.size,
				sizeof(tos_ns_mem_map_entry_t));

		list_add_tail(&platform_ctx.ns_dram_map_list_head, &dram_map_node->node);
	}

	platform_ctx.ns_dram_range_available = true;

	if (0) {
err_free_dram_map:
		list_for_every_entry_safe (&platform_ctx.ns_dram_map_list_head, map_node,
				tmp_map_node, tos_ns_dram_map_node_t, node) {
			list_delete(&map_node->node);
			free(map_node);
			map_node = NULL;
		}
	}
lbl_free_vmm:
	vmm_free_region(vmm_get_kernel_aspace(), vptr);
	return ret;
}

status_t platform_validate_ns_phys_range(paddr_t ns_addr, uint64_t ns_size)
{
	/*
	 * Always return NO_ERROR for Trusty running in virtualized environment.
	 * Trusty uses different mechanism to isolate guest physical addresses
	 * for each VM.
	 */
	if (trusty_hyp_is_ctx_available())
		return NO_ERROR;

	if (!platform_ctx.ns_dram_range_available)
		return ERR_NOT_CONFIGURED;

	tos_ns_dram_map_node_t *map_node;
	list_for_every_entry (&platform_ctx.ns_dram_map_list_head, map_node,
			tos_ns_dram_map_node_t, node) {
		dprintf(SPEW, "%s: ns_addr: {.base = %lx, .size: %llu } "
				"map_node: {.base = %llx, .size = %llu}\n",
				__func__,
				ns_addr, ns_size,
				map_node->ns_dram_entry.base, map_node->ns_dram_entry.size);
		if (platform_validate_range(map_node->ns_dram_entry.base,
					map_node->ns_dram_entry.size, ns_addr, ns_size))
			return NO_ERROR;
	}
	return ERR_NOT_VALID;
}

bool platform_validate_range(uint64_t bound_base, uint64_t bound_size,
		uint64_t test_base, uint64_t test_size)
{
	dprintf(SPEW, "%s: checking {.base: 0x%llx, .size: 0x%llx} against "
			"{.base: 0x%llx, .size: 0x%llx}: ", __func__, test_base, test_size,
			bound_base, bound_size);

	if ( (bound_base <= test_base) &&
			(bound_size >= test_size) &&
			( (bound_size - test_size) >= (test_base - bound_base) ) ) {
		dprintf(SPEW, "PASS\n");
		return true;
	}

	dprintf(SPEW, "FAIL\n");
	return false;
}

/*
 * This function checks the cpu MIDR register to determine if the
 * core is a Denver CPU. This function:
 * - Returns true if the cpu is Denver (or Carmel)
 * - Returns false otherwise
 */
bool platform_is_denver_cpu(void)
{
	uint64_t midr = ARM64_READ_SYSREG(midr_el1);
	uint64_t impl = (midr >> MIDR_IMPL_SHIFT) & MIDR_IMPL_MASK;

	if (impl == DENVER_IMPL)
		return true;
	else
		return false;
}
