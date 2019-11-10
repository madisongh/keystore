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

#ifndef BOOT_PROFILER_HEADER_
#define BOOT_PROFILER_HEADER_

#include <err.h>
#include <platform/memmap.h>

/* Max Length of profiler record */
#define MAX_DATA_STRLEN 55

/*
 * @brief	typedef for storing boot_profiler records
 *
 * @param	char data[]	to store data associated with the timestamp
 * @param	uint64_t timestamp	to store the time since boot
 */
typedef struct {
	char data[MAX_DATA_STRLEN + 1];
	uint64_t timestamp;
}record_t ;

/*
 * @brief recieve BASE phy address from sm_init and map it
 * @retval error code 0 or 1
 */
long tegra_boot_profiler_init(paddr_t boot_arg);

/*
 * @brief free virtual memmap and heap alloc
 * @retval error code 0 or 1
 */
void  tegra_boot_profiler_deinit(void);
/*
 * @brief	Return time since boot in miliseconds
 * @retval	Integer value containing timestamp
 */
uint32_t tegra_boot_profiler_get_timestamp(void);

/*
 * @brief	Add a boot profile record and current timestamp
 * @param	str String associated with the timestamp
 *
 */
void tegra_boot_profiler_record(const char *str);

/*
 * @brief	Add a boot profile record with a specific timestamp
 * @param	str	String data associated with the timestamp
 * @param	tstamp	Specific timestamp
 */
void tegra_boot_profiler_prerecorded(const char *str, uint32_t tstamp);

/*
 * @brief	[Debug]Print all profiler data to UART
 * 			Printing directy to UART adds latency and timestamps
 * 			are not accurate. For debug purposes only
 */
void tegra_boot_profiler_data_printnow(void);

#endif /* BOOT_PROFILER_HEADER_ */

