/*
 * Copyright (c) 2015-2018, NVIDIA CORPORATION. All rights reserved.
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

#include <assert.h>
#include <err.h>
#include <debug.h>
#include <trace.h>
#include <rand.h>
#include <string.h>
#include <lib/heap.h>
#include <arch/ops.h>
#include <platform.h>
#include <platform/memmap.h>
#include <platform/plat_smcall.h>
#include <target/debugconfig.h>
#include <platform/platform_p.h>
#include <dev/interrupt/arm_gic.h>
#include <dev/timer/arm_generic.h>
#include <lk/init.h>
#include <platform/gic.h>
#include <lib/cpus/denver.h>

#if WITH_KERNEL_VM
#include <kernel/vm.h>
#else
#error "KERNEL_VM is required"
#endif

#include <lib/sm.h>

#define LOCAL_TRACE 0

#define ARM_GENERIC_TIMER_INT_CNTV 27
#define ARM_GENERIC_TIMER_INT_CNTPS 29
#define ARM_GENERIC_TIMER_INT_CNTP 30

#define ARM_GENERIC_TIMER_INT_SELECTED(timer) ARM_GENERIC_TIMER_INT_ ## timer
#define XARM_GENERIC_TIMER_INT_SELECTED(timer) ARM_GENERIC_TIMER_INT_SELECTED(timer)
#define ARM_GENERIC_TIMER_INT XARM_GENERIC_TIMER_INT_SELECTED(TIMER_ARM_GENERIC_SELECTED)

#define NR_SMC_REGS 6

/* MCE command enums for SMC calls */
enum {
	MCE_SMC_ENTER_CSTATE,
	MCE_SMC_UPDATE_CSTATE_INFO,
	MCE_SMC_UPDATE_XOVER_TIME,
	MCE_SMC_READ_CSTATE_STATS,
	MCE_SMC_WRITE_CSTATE_STATS,
	MCE_SMC_IS_SC7_ALLOWED,
	MCE_SMC_ONLINE_CORE,
	MCE_SMC_CC3_CTRL,
	MCE_SMC_ECHO_DATA,
	MCE_SMC_READ_VERSIONS,
	MCE_SMC_ENUM_FEATURES,
	MCE_SMC_ROC_FLUSH_CACHE_TRBITS,
	MCE_SMC_ENUM_READ_MCA,
	MCE_SMC_ENUM_WRITE_MCA,
	MCE_SMC_ROC_FLUSH_CACHE_ONLY,
	MCE_SMC_ROC_CLEAN_CACHE_ONLY,
	MCE_SMC_ENABLE_LATIC,
	MCE_SMC_ENUM_MAX = 0xFF,	/* enums cannot exceed this value */
};
struct mce_regs {
	uint64_t args[NR_SMC_REGS];
};

uint32_t debug_uart_id = DEFAULT_DEBUG_PORT;

extern status_t process_boot_params(void);

/* The following variables might be updated by platform_reset code
 * to adjust amount and location of physical RAM we are alloved to use
 */
uint32_t  _mem_size = MEMSIZE;
uintptr_t _mem_phys_base = MEMBASE + KERNEL_LOAD_OFFSET;

extern void _start(void);

#if WITH_SMP

#if SOC_T186
/* Usually A57_0 is the boot CPU for a lot of T186 platforms */
#define A57_0		4

/* Global to store the boot CPU # */
static uint boot_cpu = 0xFF;

/*
 * The boot map, when A57_0 or D_0 is the boot CPU, looks like:
 *
 *   =====================
 *   | 0 | A57_0 | D_0   |
 *   | 1 | D_0   | D_1   |
 *   | 2 | D_1   | A57_0 |
 *   | 3 | A57_1 | A57_1 |
 *   | 4 | A57_2 | A57_2 |
 *   | 5 | A57_3 | A57_3 |
 *   =====================
 */
static uint a57_boot_map[] = {1, 2, 0xff, 0xff, 0, 3, 4, 5};
static uint denver_boot_map[] = {0, 1, 0xff, 0xff, 2, 3, 4, 5};
#endif

uint plat_arch_curr_cpu_num(void)
{
	unsigned int cpu_num =  ARM64_READ_SYSREG(mpidr_el1) & 0xff;
	unsigned int cluster_num = (ARM64_READ_SYSREG(mpidr_el1) >> 8) & 0xff;
#if SOC_T186
	uint curr_cpu_num = (cpu_num + (cluster_num << 2));

	/* store boot CPU # for future reference */
	if (boot_cpu == 0xFF)
		boot_cpu = curr_cpu_num;

	/* return the CPU # from the proper map */
	if (boot_cpu == A57_0)
		return a57_boot_map[curr_cpu_num];
	else
		return denver_boot_map[curr_cpu_num];
#else
	return (cpu_num + (cluster_num << 1));
#endif
}

#if ROC_FLUSH_ENABLE
void arch_sync_cache_range(addr_t start, size_t len)
{
	/*
	 * arch_sync_cache_range spends lots of time in trusty_app.c
	 * weak this function and add a empty function here.
	 * Need to call ROC_FLUSH_TRBITS to clean icache and dcache
	 * after it.
	 */
}
#endif

#endif

#if ROC_FLUSH_ENABLE
static int send_roc_flush_smc(uint8_t func, struct mce_regs *regs)
{
	uint32_t ret = SMC_SIP_INVOKE_MCE | (func & MCE_SMC_ENUM_MAX);
	asm volatile (
	"	mov	x0, %0 \n"
	"	ldp	x1, x2, [%1, #16 * 0] \n"
	"	ldp	x3, x4, [%1, #16 * 1] \n"
	"	ldp	x5, x6, [%1, #16 * 2] \n"
	"	isb \n"
	"	smc	#0 \n"
	"	mov	%0, x0 \n"
	"	stp	x0, x1, [%1, #16 * 0] \n"
	"	stp	x2, x3, [%1, #16 * 1] \n"
	: "+r" (ret)
	: "r" (regs)
	: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
	"x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17");
	return ret;
}
#endif

void platform_app_bootloader_epilog(void)
{
#if ROC_FLUSH_ENABLE
	struct mce_regs regs;
	send_roc_flush_smc(MCE_SMC_ROC_FLUSH_CACHE_TRBITS, &regs);
#endif
}

void platform_early_init(void)
{
	arm_generic_timer_init(ARM_GENERIC_TIMER_INT, 0);
}

void platform_init(void)
{
	status_t err;

	/* process boot args (cmdline and eks data) */

	if ((err = process_boot_params()) != NO_ERROR) {
		panic("Fatal error: Failed to process boot params\n");
	}

	/* setup debug port passed in boot args */
	platform_init_debug_port(debug_uart_id);
}

/* initial memory mappings. parsed by start.S */
struct mmu_initial_mapping mmu_initial_mappings[] = {
	/* Mark next entry as dynamic as it might be updated
	   by platform_reset code to specify actual size and
	   location of RAM to use */
	{ .phys = MEMBASE + KERNEL_LOAD_OFFSET,
	  .virt = KERNEL_BASE + KERNEL_LOAD_OFFSET,
	  .size = MEMSIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DYNAMIC,
	  .name = "ram" },

	{ .phys = REGISTER_BANK_0_PADDR,
	  .virt = REGISTER_BANK_0_VADDR,
	  .size = 2*REGISTER_BANK_SIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
	  .name = "bank-0" },

	{ .phys = REGISTER_BANK_1_PADDR,
	  .virt = REGISTER_BANK_1_VADDR,
	  .size = 4*REGISTER_BANK_SIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
	  .name = "bank-1" },

	{ .phys = REGISTER_BANK_2_PADDR,
	  .virt = REGISTER_BANK_2_VADDR,
	  .size = REGISTER_BANK_SIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
	  .name = "bank-2" },

	{ .phys = REGISTER_BANK_3_PADDR,
	  .virt = REGISTER_BANK_3_VADDR,
	  .size = PAGE_SIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
	  .name = "bank-3" },

	{ .phys = REGISTER_BANK_4_PADDR,
	  .virt = REGISTER_BANK_4_VADDR,
	  .size = PAGE_SIZE,
	  .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
	  .name = "bank-4" },
	/* null entry to terminate the list */
	{ 0 }
};

static pmm_arena_t ram_arena = {
    .name  = "ram",
    .base  =  MEMBASE + KERNEL_LOAD_OFFSET,
    .size  =  MEMSIZE,
    .flags =  PMM_ARENA_FLAG_KMAP
};

void platform_init_mmu_mappings(void)
{
	if (plat_arch_curr_cpu_num() == 0) {
		/* go through mmu_initial_mapping to find dynamic entry
		 * matching ram_arena (by name) and adjust it. Also update
		 * _mem_size and _mem_phys_base variables
		 */
		struct mmu_initial_mapping *m = mmu_initial_mappings;
		for (uint i = 0; i < countof(mmu_initial_mappings); i++, m++) {
			if (!(m->flags & MMU_INITIAL_MAPPING_FLAG_DYNAMIC))
				continue;

			if (strcmp(m->name, ram_arena.name) == 0) {
				/* update ram_arena */
				ram_arena.base = m->phys;
				ram_arena.size = m->size;
				ram_arena.flags = PMM_ARENA_FLAG_KMAP;

				/* update _mem_size and _mem_phys_base */
				_mem_size = m->size;
				_mem_phys_base = m->phys;
				break;
			}
		}
		pmm_add_arena(&ram_arena);
	}
}

#if WITH_SMP

static void platform_secondary_init(uint level)
{
	dprintf(SPEW, "%s: cpu_id 0x%x\n", __func__, plat_arch_curr_cpu_num());
}

LK_INIT_HOOK_FLAGS(tegra_secondary, platform_secondary_init, LK_INIT_LEVEL_PLATFORM, LK_INIT_FLAG_SECONDARY_CPUS);

#endif

#if defined(WORKAROUND_CVE_2018_3639)
/*
 * Prevent Speculative Store Bypass (SSB)-based exploits (CVE-2018-3639)
 * by disabling memory disambiguation and speculative store buffering in
 * S-EL1 and S-EL0.
 *
 * This mitigation is only ran on Denver and Carmel (DENVER_PN4) cpus.
 */
static void platform_prevent_ssb(uint level) {
	uint64_t midr = ARM64_READ_SYSREG(midr_el1);
	uint64_t actlr = 0;
	uint64_t mask = 0;

	/* Only apply workaround on Denver cores */
	if (!platform_is_denver_cpu())
		return;

	/*
	 * Denver CPUs with DENVER_MIDR_PN3 or earlier, use different
	 * bits in the ACTLR_EL1/ACTLR_EL0 registers to disable
	 * speculative store buffer and memory disambiguation.
	 */
	switch(midr) {

	case DENVER_MIDR_PN0:
	case DENVER_MIDR_PN1:
	case DENVER_MIDR_PN2:
	case DENVER_MIDR_PN3:
		mask = DENVER_CPU_DIS_MD_EL0 | DENVER_CPU_DIS_MD_EL1
			| DENVER_CPU_DIS_SSB_EL0 | DENVER_CPU_DIS_SSB_EL1;
		break;

	case DENVER_MIDR_PN4:
		mask = DENVER_PN4_CPU_DIS_MD_EL0 | DENVER_PN4_CPU_DIS_MD_EL1
			| DENVER_PN4_CPU_DIS_SSB_EL0 | DENVER_PN4_CPU_DIS_SSB_EL1;
		break;

	default:
		dprintf(CRITICAL, "%s: unable to apply cve_2018_3639 TZ"
			" workaround on cpu_id %u midr 0x%08llx\n",
			__func__, plat_arch_curr_cpu_num(), midr);
		break;
	}

	/* update actlr_el1 */
	actlr = ARM64_READ_SYSREG(actlr_el1);
	actlr |= mask;
	ARM64_WRITE_SYSREG(actlr_el1, actlr);
}

LK_INIT_HOOK_FLAGS(prevent_ssb, platform_prevent_ssb, LK_INIT_LEVEL_PLATFORM,
	LK_INIT_FLAG_ALL_CPUS | LK_INIT_FLAG_CPU_RESUME);
#endif
