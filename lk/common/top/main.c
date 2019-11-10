/*
 * Copyright (c) 2013-2015 Travis Geiselbrecht
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

/*
 * Main entry point to the OS. Initializes modules in order and creates
 * the default thread.
 */
#include <compiler.h>
#include <debug.h>
#include <string.h>
#include <app.h>
#include <arch.h>
#include <platform.h>
#include <target.h>
#include <boot_profiler.h>
#include <lib/heap.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <lk/init.h>
#include <lk/main.h>

/* saved boot arguments from whoever loaded the system */
ulong lk_boot_args[4];

extern void *__ctor_list;
extern void *__ctor_end;
extern int __bss_start;
extern int _end;

#if WITH_SMP
static thread_t *secondary_bootstrap_threads[SMP_MAX_CPUS - 1];
static uint secondary_bootstrap_thread_count;
#endif

static int bootstrap2(void *arg);

/* Structure to collect profiling timestamps from early boot */
typedef struct {
	uint64_t start;
	uint64_t arch_init;
	uint64_t platform_init;
	uint64_t target_init;
	uint64_t kernel_init;
} early_tstamps_t;

/* Function to copy prerecorded records */
static void add_early_profiler_records(early_tstamps_t tstamps);

extern void kernel_init(void);

static void call_constructors(void)
{
	void **ctor;

	ctor = &__ctor_list;
	while (ctor != &__ctor_end) {
		void (*func)(void);

		func = (void (*)(void))*ctor;

		func();
		ctor++;
	}
}

/* called from arch code */
void lk_main(ulong arg0, ulong arg1, ulong arg2, ulong arg3)
{
	// save the boot args
	lk_boot_args[0] = arg0;
	lk_boot_args[1] = arg1;
	lk_boot_args[2] = arg2;
	lk_boot_args[3] = arg3;

	early_tstamps_t early_tstamps;
	early_tstamps.start = tegra_boot_profiler_get_timestamp();
	// get us into some sort of thread context
	thread_init_early();

	// early arch stuff
	lk_primary_cpu_init_level(LK_INIT_LEVEL_EARLIEST, LK_INIT_LEVEL_ARCH_EARLY - 1);
	arch_early_init();
	early_tstamps.arch_init = tegra_boot_profiler_get_timestamp();

	// do any super early platform initialization
	lk_primary_cpu_init_level(LK_INIT_LEVEL_ARCH_EARLY, LK_INIT_LEVEL_PLATFORM_EARLY - 1);
	platform_early_init();
	early_tstamps.platform_init = tegra_boot_profiler_get_timestamp();

	// do any super early target initialization
	lk_primary_cpu_init_level(LK_INIT_LEVEL_PLATFORM_EARLY, LK_INIT_LEVEL_TARGET_EARLY - 1);
	target_early_init();
	early_tstamps.target_init = tegra_boot_profiler_get_timestamp();

#if WITH_SMP
	dprintf(INFO, "\nwelcome to lk/MP\n\n");
#else
	dprintf(INFO, "\nwelcome to lk\n\n");
#endif
	dprintf(INFO, "boot args 0x%lx 0x%lx 0x%lx 0x%lx\n",
		lk_boot_args[0], lk_boot_args[1], lk_boot_args[2], lk_boot_args[3]);

	// deal with any static constructors
	dprintf(SPEW, "calling constructors\n");
	call_constructors();

	// bring up the kernel heap
	dprintf(SPEW, "initializing heap\n");
	lk_primary_cpu_init_level(LK_INIT_LEVEL_TARGET_EARLY, LK_INIT_LEVEL_HEAP - 1);
	heap_init();

	// initialize the kernel
	lk_primary_cpu_init_level(LK_INIT_LEVEL_HEAP, LK_INIT_LEVEL_KERNEL - 1);
	kernel_init();
	early_tstamps.kernel_init = tegra_boot_profiler_get_timestamp();

	lk_primary_cpu_init_level(LK_INIT_LEVEL_KERNEL, LK_INIT_LEVEL_THREADING - 1);

	/* Initialize boot_profiler and add early boot records */
	tegra_boot_profiler_init(NULL);
	add_early_profiler_records(early_tstamps);

	// create a thread to complete system initialization
	dprintf(SPEW, "creating bootstrap completion thread\n");
	thread_t *t = thread_create("bootstrap2", &bootstrap2, NULL, DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
	t->pinned_cpu = 0;
	thread_detach(t);
	thread_resume(t);

	// become the idle thread and enable interrupts to start the scheduler
	thread_become_idle();
}

static int bootstrap2(void *arg)
{
	dprintf(SPEW, "top of bootstrap2()\n");

	lk_primary_cpu_init_level(LK_INIT_LEVEL_THREADING, LK_INIT_LEVEL_ARCH - 1);
	arch_init();

	// initialize the rest of the platform
	dprintf(SPEW, "initializing platform\n");
	lk_primary_cpu_init_level(LK_INIT_LEVEL_ARCH, LK_INIT_LEVEL_PLATFORM - 1);
	platform_init();
	tegra_boot_profiler_record("bootstrap2: platform_init done");

	// initialize the target
	dprintf(SPEW, "initializing target\n");
	lk_primary_cpu_init_level(LK_INIT_LEVEL_PLATFORM, LK_INIT_LEVEL_TARGET - 1);
	target_init();
	tegra_boot_profiler_record("bootstrap2: target_init done");

	dprintf(SPEW, "calling apps_init()\n");
	lk_primary_cpu_init_level(LK_INIT_LEVEL_TARGET, LK_INIT_LEVEL_APPS - 1);
	apps_init();
	tegra_boot_profiler_record("bootstrap2: apps_init done");

	lk_primary_cpu_init_level(LK_INIT_LEVEL_APPS, LK_INIT_LEVEL_LAST);

	dprintf(SPEW, "calling platform_bootstrap_epilog\n");
	platform_bootstrap_epilog();

	return 0;
}
static void add_early_profiler_records(early_tstamps_t tstamp)
{
	/* Store pre-recorded timestamps to boot_profiler before thread creation */
	tegra_boot_profiler_prerecorded("lk_main: start", tstamp.start);
	tegra_boot_profiler_prerecorded("lk_main: arch_early_init", tstamp.arch_init);
	tegra_boot_profiler_prerecorded("lk_main: platform_early_init", tstamp.platform_init);
	tegra_boot_profiler_prerecorded("lk_main: target_early_init", tstamp.target_init);
	tegra_boot_profiler_prerecorded("lk_main: kernel_init", tstamp.kernel_init);

}
#if WITH_SMP
void lk_secondary_cpu_entry(void)
{
	uint cpu = arch_curr_cpu_num();

	if (cpu > secondary_bootstrap_thread_count) {
		dprintf(CRITICAL, "Invalid secondary cpu num %d, SMP_MAX_CPUS %d, secondary_bootstrap_thread_count %d\n",
			cpu, SMP_MAX_CPUS, secondary_bootstrap_thread_count);
		return;
	}

	thread_secondary_cpu_init_early();
	thread_resume(secondary_bootstrap_threads[cpu - 1]);

	dprintf(SPEW, "entering scheduler on cpu %d\n", cpu);
	thread_secondary_cpu_entry();
}

static int secondary_cpu_bootstrap2(void *arg)
{
	/* secondary cpu initialize from threading level up. 0 to threading was handled in arch */
	lk_init_level(LK_INIT_FLAG_SECONDARY_CPUS, LK_INIT_LEVEL_THREADING, LK_INIT_LEVEL_LAST);

	return 0;
}

void lk_init_secondary_cpus(uint secondary_cpu_count)
{
	if (secondary_cpu_count >= SMP_MAX_CPUS) {
		dprintf(CRITICAL, "Invalid secondary_cpu_count %d, SMP_MAX_CPUS %d\n",
			secondary_cpu_count, SMP_MAX_CPUS);
		secondary_cpu_count = SMP_MAX_CPUS - 1;
	}
	for (uint i = 0; i < secondary_cpu_count; i++) {
		dprintf(SPEW, "creating bootstrap completion thread for cpu %d\n", i + 1);
		thread_t *t = thread_create("secondarybootstrap2",
					    &secondary_cpu_bootstrap2, NULL,
					    DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
		t->pinned_cpu = i + 1;
		thread_detach(t);
		secondary_bootstrap_threads[i] = t;
	}
	secondary_bootstrap_thread_count = secondary_cpu_count;
}
#endif
// vim: noexpandtab:
