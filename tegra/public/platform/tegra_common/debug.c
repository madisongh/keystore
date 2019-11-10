/*
 * Copyright (c) 2008 Travis Geiselbrecht
 * Copyright (c) 2012-2018, NVIDIA CORPORATION. All rights reserved
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
#include <stdarg.h>
#include <reg.h>
#include <debug.h>
#include <printf.h>
#include <kernel/thread.h>
#include <platform/debug.h>
#include <arch/ops.h>
#include <platform/memmap.h>
#include <platform/platform_p.h>
#include <target/debugconfig.h>
#include <platform/combined_uart.h>

static unsigned int disable_debug = 1; /* initially disabled */

#define TEGRA_UART_NONE	0x0
#define TEGRA_COMBUART_ID 0xfe

static vaddr_t uart_base[] = {
	TEGRA_UART_NONE,
	TEGRA_UARTA_BASE,
	TEGRA_UARTB_BASE,
	TEGRA_UARTC_BASE,
	TEGRA_UARTD_BASE,
	TEGRA_UARTE_BASE
};

static unsigned int debug_port = DEFAULT_DEBUG_PORT;

#define UART_RHR	0
#define UART_THR	0
#define UART_LSR	5

/* 500 ms UART timeout */
#define UART_TIMEOUT_US	(500L * 1000L) /* in microseconds */

static inline void write_uart_reg(int port, uint reg, unsigned char data)
{
	*REG8(uart_base[port] + (reg << 2)) = data;
}

static inline unsigned char read_uart_reg(int port, uint reg)
{
	return *REG8(uart_base[port] + (reg << 2));
}

static int uart_putc(int port, char c )
{
	static bool timed_out = false;
	lk_bigtime_t start = current_time_hires();

	while (!(read_uart_reg(port, UART_LSR) & (1<<5))) {
		if (timed_out)
			return -1;
		if (current_time_hires() - start >= UART_TIMEOUT_US) {
			timed_out = true;
			return -1;
		}
	}

	timed_out = false;

	write_uart_reg(port, UART_THR, c);
	return 0;
}

static int uart_getc(int port, bool wait)
{
	static bool timed_out = false;
	lk_bigtime_t start = current_time_hires();

	if (wait) {
		while (!(read_uart_reg(port, UART_LSR) & (1<<0))) {
			if (timed_out)
				return -1;
			if (current_time_hires() - start >= UART_TIMEOUT_US) {
				timed_out = true;
				return -1;
			}
		}
	} else {
		if (!(read_uart_reg(port, UART_LSR) & (1<<0)))
			return -1;
	}

	timed_out = false;

	return read_uart_reg(port, UART_RHR);
}

void platform_dputc(char c)
{
	if (disable_debug || (debug_port == TEGRA_UART_NONE))
		return;

	if (debug_port == TEGRA_COMBUART_ID) {
		platform_tegra_comb_uart_putc(c);
		return;
	}

	if (c == '\n') {
		uart_putc(debug_port, '\r');
	} else if (c == '\0') {
		return;
	}
	uart_putc(debug_port, c);
}

int platform_dgetc(char *c, bool wait)
{
	int _c;

	if (disable_debug || (debug_port == TEGRA_UART_NONE))
		return -1;

	if (debug_port == TEGRA_COMBUART_ID) {
		_c = platform_tegra_comb_uart_getc(wait);
	} else {
		_c = uart_getc(debug_port, wait);
	}

	if (_c < 0)
		return -1;

	*c = _c;
	return 0;
}

void platform_init_debug_port(unsigned int dbg_port)
{
	debug_port = dbg_port;
	platform_enable_debug_intf();
}

void platform_disable_debug_intf(void)
{
	disable_debug = 1;
}

void platform_enable_debug_intf(void)
{
	disable_debug = 0;
}

