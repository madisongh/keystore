/*
 * Copyright (c) 2018, NVIDIA CORPORATION. All rights reserved
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

#include <arch/ops.h>
#include <kernel/vm.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot_profiler.h"

/*
 * MB2 Profiler allocates 4K for ATF+TOS records
 * ATF gets 0x400 bytes (12 records @ 64b/record)
 * TOS gets 0xC00 bytes (48 records @ 64b/record)
 */
#define ATF_PROFILER_CARVEOUT_SIZE	0x400
#define TOS_PROFILER_CARVEOUT_SIZE	0xC00

/*
 * Early records - records collected before shared DRAM addr
 * from mb2_profiler is available
 */
#define MAX_NUM_EARLY_RECORDS 8
#define MAX_NUM_RECORDS	(TOS_PROFILER_CARVEOUT_SIZE/sizeof(record_t))

/*
 * Global switch for the TOS Boot Profiler.
 * This build variable is defined in the device makefile(s)
 * If the profiler is enabled then all of the profiler library functions
 * get executed normally.
 */
#ifdef TOS_BOOT_PROFILER_ENABLE

/*  Fixed profiler record header for all records */
static const char record_header[] = "[TOS] ";

/* Static Variables: */
static struct {
	/* Base address of the section of memory dedicated to the profiler */
	uint8_t *base;
	/*  Current number of profiler records in memory */
	uint32_t count;
	/*  Early: Base address of the early profiling data */
	record_t *early_data;
	/*  Base address of the actual profiling data */
	record_t *data;
}_profiler;

/*
 *  Global flag to determine whether shared DRAM page
 *  from mb2_profiler is available
 */
static bool shared_dram_available = false;
/*
 *  Fixed max count depending on whether logs are being written to
 *  heap or DRAM
 */
static uint32_t _max_record_count = 0U;


/*Internal function for adding a profiler record */
static void tegra_boot_profiler_add_record(const char *str, uint32_t tstamp);

static void tegra_boot_profiler_add_record(const char *str, volatile uint32_t tstamp) {
	/* Flag to ensure that error messages are only printed once */
	static bool once_flag = true;

	if (tstamp == 0 || str == NULL) {
		dprintf(CRITICAL, "TOS Profiler:: timestamp or log invalid;"
			   " tstamp = 0x%x, str @ %p\n", tstamp, str);
		goto exit;
	}
	dprintf(SPEW, "TOS Profiler:: Entered add_record\n");
	size_t header_len = strlen(record_header);

	/* Check that there's room to add a new record */
	if ((_profiler.count) >= _max_record_count) {
		/* Print error message only once */
		if (once_flag) {
			if (!shared_dram_available) {
				/* If allocated heap is full of early records and dram carveout is not
				 * available then respond accordingly */
				dprintf(CRITICAL, "TOS Profiler:: DRAM carveout for profiler is not available\n");
			} else {
				/* If the DRAM carveout is available but full
				 * and cannot take in more records */
				dprintf(CRITICAL, "TOS Profiler:: DRAM carveout full, reached max entries\n");
			}
			once_flag = false;
		}
		/* Whenever count >= _max_record_count just exit
		 * because there is no space to enter records */
		goto exit;
	}
	dprintf(SPEW, "TOS Profiler:: Max entries not reached\n");
	uint32_t record_index = 0U;

	record_index = _profiler.count;
	_profiler.count++;
	_profiler.data[record_index].timestamp = tstamp;

	/* Copy Header */
	strncpy(_profiler.data[record_index].data,
			record_header, header_len);
	/* Copy profiler log */
	strncpy((char *)_profiler.data[record_index].data + header_len,
			str, (MAX_DATA_STRLEN - header_len));
	/* End line */
	_profiler.data[record_index].data[MAX_DATA_STRLEN - 1] = '\0';
	/* Debug Print */
	dprintf(SPEW, "value: %d: %s: %d \n",
			_profiler.count,
			(char *)_profiler.data[record_index].data,
			tstamp);
exit:
	return;
}

long tegra_boot_profiler_init(paddr_t boot_arg){
	dprintf(SPEW, "\nTOS Profiler:: Entered init: %lu \n", boot_arg);
	long ret = 0L;

	if (boot_arg != 0U) {
		/* shared dram page from mb2_profiler is now available */
		shared_dram_available = true;

		/* Map the address recieved as boot argument*/
		paddr_t profiler_paddr;
		size_t profiler_buffer_size;
		void *profiler_base_vaddr;

		profiler_paddr = ROUNDDOWN(boot_arg, PAGE_SIZE);
		profiler_buffer_size = ROUNDUP(TOS_PROFILER_CARVEOUT_SIZE, PAGE_SIZE);
		ret = vmm_alloc_physical(vmm_get_kernel_aspace(),"tos_profiler",
				profiler_buffer_size, &profiler_base_vaddr, PAGE_SIZE_SHIFT,
				profiler_paddr,
				0,
				ARCH_MMU_FLAG_NS | ARCH_MMU_FLAG_PERM_NO_EXECUTE |
				ARCH_MMU_FLAG_CACHED);
		if (ret) {
			dprintf(CRITICAL, "%s: error while mapping profiler base address."
				   " ret %ld\n", __func__, ret);
			return ret;
		}

		/*
		 * The base_adddr recieved from mb2_profiler is common
		 * for ATF and TOS
		 * Set the end of ATF profiler carveout
		 * as the base for TOS profiling
		 */
		_max_record_count = MAX_NUM_RECORDS;
		_profiler.base = (uint8_t *)profiler_base_vaddr +
				ATF_PROFILER_CARVEOUT_SIZE;
		_profiler.data =
			(record_t *)(_profiler.base + _profiler.count * sizeof(record_t));

		dprintf(SPEW, "TOS_PROFILER_COUNT value: %d\n", _profiler.count);

		/* Copy Pre-collected early records to new mapped memory */
		memcpy(_profiler.base,
				(uint8_t *) _profiler.early_data, _profiler.count * sizeof(record_t));

	} else {
		/*
		 * Else boot_arg is NULL
		 *
		 * Call malloc only if _profiler.early_data is NULL
		 * If !NULL heap has already been allocated in a
		 * previous init call
		 */
		if (_profiler.early_data == NULL) {
			/*
			 * Start store early records in tos_profiler heap
			 * Do not add more than max early records
			 */
			_profiler.count = 0U;
			_max_record_count = MAX_NUM_EARLY_RECORDS;
			_profiler.early_data =
				(record_t *) malloc(sizeof(record_t) * MAX_NUM_EARLY_RECORDS);
			if (_profiler.early_data == NULL) {
				dprintf(CRITICAL, "TOS profiler init: Error in allocating heap \n");
				ret = 1;
			}
			_profiler.data = _profiler.early_data;
			dprintf(SPEW, "TOS_PROFILER_COUNT: %d \n", _profiler.count);
			dprintf(SPEW, "TOS_EARLY_RECORDS_BASE: %p \n", (void*)_profiler.early_data);
		} else {
				/* Heap for Early Data has already been allocated */
				dprintf(CRITICAL, "TOS profiler init: Unexpected 2nd init call \n");
				ret = 1;
		}
	}
	return ret;
}
/*
 * Clean up
 * If shared dram available unmap memory else free malloc
 */
void  tegra_boot_profiler_deinit(void){

	if (shared_dram_available) {
		/* Unmap Memory */
		vmm_free_region(vmm_get_kernel_aspace(), (vaddr_t)_profiler.base);
	}
	/* Free Malloc */
	free(_profiler.early_data);
}

/* Returns the current time since boot */
uint32_t tegra_boot_profiler_get_timestamp(void) {
	dprintf(SPEW, "TOS Profiler:: Entered get_timestamp\n");
	return *((const volatile uint32_t *)TEGRA_TSCUS_BASE);
}

/* Add a profiler record using the current time */
void tegra_boot_profiler_record(const char *str) {
	dprintf(SPEW, "TOS Profiler:: Entered profiler_record\n");
	tegra_boot_profiler_add_record(str, tegra_boot_profiler_get_timestamp());
}

/* Add a profiler record using a specified time */
void tegra_boot_profiler_prerecorded(const char *str, uint32_t tstamp) {
	tegra_boot_profiler_add_record(str, tstamp);
}

/* Utility function for printing out the current records */
void tegra_boot_profiler_data_printnow(void) {

	uint32_t i;
	dprintf(ALWAYS, "TOS_PROFILER_BASE_ADDR: %p \n", (void*) _profiler.base);
	dprintf(ALWAYS, "TOS_PROFILER_COUNT: %d \n", _profiler.count);
	dprintf(ALWAYS, "TOS_RECORDS_BASE: %p \n", (void*)_profiler.data);

	dprintf(ALWAYS, "\nTOS Profiler:: profiler count: %d\n", _profiler.count);
	dprintf(ALWAYS, "TOS Profiler:: records at %p:\n", _profiler.data);
	dprintf(ALWAYS, "%3s| %10s | %8s | %s\n", "---", "----------", "--------", "---------------");
	dprintf(ALWAYS, "%3s| %10s | %8s | %s\n", "   ", "tstamp(us)", "    diff", " record data");
	dprintf(ALWAYS, "%3s| %10s | %8s | %s\n", "---", "----------", "--------", "---------------");

	dprintf(ALWAYS, "%3u| %10ld | %8s | %s\n",
			0,
			(long)_profiler.data[0].timestamp,
			"        ",
			_profiler.data[0].data);

	for (i = 1; i < _profiler.count ; i++) {
		dprintf(ALWAYS, "%3u| %10ld | %8ld | %s\n",
				i,
				(long)_profiler.data[i].timestamp,
				(long)(_profiler.data[i].timestamp - _profiler.data[i-1].timestamp),
				_profiler.data[i].data);
	}
	dprintf(ALWAYS, "%3s| %10s | %8s | %s\n", "---", "----------", "--------","---------------");
}

/* TOS_BOOT_PROFILER_ENABLE */
#else
/* TOS Boot Profiler is NOT enabled.
 * If the profiler is not enabled then we just turn all of the profiler
 * functions into no-ops.
 * The '(void)' statements are to silence compiler
 * warnings */

long tegra_boot_profiler_init(paddr_t boot_arg){ return 0L; }

void tegra_boot_profiler_deinit(void){ ; }

uint32_t tegra_boot_profiler_get_timestamp(void) { return 0U; }

/* If TOS boot profiler is NOT enabled no records will be added */
void tegra_boot_profiler_record(const char *str) {
	(void)str;
}

void tegra_boot_profiler_prerecorded(const char *str, uint32_t tstamp) {
	(void)str;
	(void)tstamp;
}

void tegra_boot_profiler_data_printnow(void) { ; }

#endif /* TOS Boot Profiler is NOT enabled */
