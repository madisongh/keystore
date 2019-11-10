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

#include <stdbool.h>
#include <platform.h>
#include <platform/combined_uart.h>
#include <platform/memmap.h>
#include <reg.h>
#include <sys/types.h>

/* 500 ms */
#define TX_TIMEOUT_US	(500 * 1000)

/*
 * Triggers an interrupt. Also indicates that the remote processor
 * is busy when set.
 */
#define MBOX_INTR_TRIGGER	(1 << 31)
/*
 * Ensures that prints up to and including this packet are flushed on
 * the physical uart before de-asserting MBOX_INTR_TRIGGER.
 */
#define MBOX_FLUSH		(1 << 26)
/*
 * Indicates that we're only sending one byte at a time.
 */
#define MBOX_BYTE_COUNT	(1 << 24)

static void comb_uart_putc(char c)
{
	static bool timed_out = false;
	lk_bigtime_t start;

	start = current_time_hires();
	uint32_t msg = MBOX_INTR_TRIGGER | MBOX_BYTE_COUNT | (uint8_t)(c & 0xff);
	if (c == '\n')
		msg |= MBOX_FLUSH;
	while (readl(TEGRA_COMBUART_BASE) & (MBOX_INTR_TRIGGER)) {
		if (timed_out)
			return;
		if (current_time_hires() - start >= TX_TIMEOUT_US) {
			timed_out = true;
			return;
		}
	}
	timed_out = false;
	/*
	 * Only EL3 and Trusty has access to this register. Under normal circumstances, EL3 rarely
	 * prints debug messages, so there should be no race conditions here.
	 *
	 * If EL3 does attempt to print debug messages at the same time as Trusty, messages might
	 * be corrupted. This is acceptable, because it should not cause any functional issues
	 * in Trusty or EL3.
	 */
	writel(msg, TEGRA_COMBUART_BASE);
}

void platform_tegra_comb_uart_putc(char c)
{
	if (c == '\0')
		return;
	if (c == '\n')
		comb_uart_putc('\r');
	comb_uart_putc(c);
}

int platform_tegra_comb_uart_getc(bool wait)
{
	(void)wait;
	return -1;
}
