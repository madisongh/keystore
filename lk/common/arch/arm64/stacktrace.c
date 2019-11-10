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

#include <debug.h>
#include <arch/arm64.h>
#include <reg.h>

#ifndef MAX_STACK_TRACE_DEPTH
#define MAX_STACK_TRACE_DEPTH 50U
#endif

/*
 * This is how the stack should look like as per AArch64 PCS:-
 *
 *   stack_top =>  ___________________________
 *                |                           |
 *                |          ......           |
 *                |          ......           |
 *                |          ......           |
 *                |          ......           |
 * previous-SP => |___________________________|
 *                |                           |
 *                |   local variables, etc    |
 *                |___________________________|
 *                |                           |
 *                |   return address (LR)     | <= 8 bytes
 *                |___________________________|
 *                |                           |
 *                |        previous FP        | <= 8 bytes
 *  SP = FP =>    |___________________________|
 *                |                           |
 *                |          ......           |
 *                |          ......           |
 *                |          ......           |
 *                |          ......           |
 * stack_bottom =>|___________________________|
 *
 *
 *  frame-pointer (FP) is stored in x29,
 *  link-register (LR) is stored in x30
 */

/* This function may be called by debug code from multiple locations
 *
 * You can take stacktraces anytime by e.g. using the following macro.
 */
void arch_print_stacktrace(vaddr_t fp, vaddr_t sp, vaddr_t pc);
void arm64_print_stacktrace(const struct arm64_iframe_long *iframe);

#if 0
/* A sample R&D macro to print non-invasive stack traces at runtime
 * by a call to arch_print_stacktrace.
 */
#define DO_STACKTRACE(level, x...)					\
	do { if ((level) <= LK_DEBUGLEVEL) {				\
		vaddr_t _pc;						\
		register vaddr_t _fp  asm("x29");			\
		register vaddr_t _sp  asm("sp");			\
		__asm__ volatile("adr %0,." : "=r" (_pc));		\
		dprintf(level, x);				\
		dprintf(level, "Stacktrace from %s [ %s:%u ]\n", __func__, __FILE__, __LINE__); \
		arch_print_stacktrace(_fp,_sp,_pc);			\
	     }								\
	} while(false)

#endif	/* Sample R&D stacktrace macro */

/* For arm64 this is set in arm64/thread.c to the initial_thread_func function */
vaddr_t arch_stack_trace_epoch;
extern vaddr_t arch_stack_trace_epoch;

void arch_print_stacktrace(vaddr_t p_fp, vaddr_t p_sp, vaddr_t p_pc)
{
	uint64_t stack_size = 0UL;
	uint32_t tcount = 0U;
	vaddr_t fp = p_fp;
	vaddr_t sp = p_sp;
	vaddr_t pc = p_pc;

	if (0UL == pc) {
		dprintf(CRITICAL, "[ PC value zero => potential corruption, tracing anyway ]\n");
	}

	if ((0UL == fp) || (0UL == sp)) {
		dprintf(CRITICAL, "[ No frame/stack register values => no stack traces ]\n");
		dprintf(CRITICAL, "[ => fp=0x%016lX, sp=0x%016lX, pc=0x%016lX ]\n",
			fp, sp, pc);
		goto fail;
	}

	if (0UL == arch_stack_trace_epoch) {
		dprintf(CRITICAL, "[ Stack tracing disabled ]\n");
		goto fail;
	}

	while (tcount < MAX_STACK_TRACE_DEPTH) {
		dprintf(CRITICAL, "[ %02u ] => pc: 0x%016lX  sp: 0x%016lX\n", tcount, pc, sp);

		/* Stack grows down, so if the next stack frame is
		 * below this => FP is invalid.
		 */
		if ((0UL == fp) || (fp < sp)) {
			break;
		}

		/* ARM-64 stack && frame pointers aligned to 64 bit
		 * boundary, detect simple stack corruption
		 */
		if ((fp & 0xfUL) != 0UL) {
			dprintf(CRITICAL,
				      "[ FP (0x%016lX) not aligned to 64 bit boundary; terminating trace ]\n",
				      fp);
			break;
		}

		/* Native Arm-64 instructions are aligned to 32 bit word
		 * boundary, detect simple PC corruption
		 */
		if ((pc & 0x3UL) != 0UL) {
			dprintf(CRITICAL,
				      "[ PC (0x%016lX) not aligned to 32 bit boundary; terminating trace ]\n",
				      pc);
			break;
		}

		sp = fp;
		pc = *REG64(fp+8UL);

		if (pc != arch_stack_trace_epoch) {
			pc = pc - 4UL; /* LR = PC at function-call + 4 */
		}

		fp = *REG64(fp);
		tcount++;
	}

	stack_size = sp - p_sp;
	if (stack_size >= (uint64_t)ARCH_DEFAULT_STACK_SIZE) {
		dprintf(CRITICAL, "\n Using %llu bytes - STACK OVERFLOW !!!\n",
			stack_size);
	}

	if (tcount >= MAX_STACK_TRACE_DEPTH) {
		dprintf(CRITICAL, "\n [ Configured stack trace depth (%u) exeeded -- trace terminated ]\n",
			      MAX_STACK_TRACE_DEPTH);
	}
fail:
	return;
}

/* Stack tracer for the Arm-64 exception handler */
void arm64_print_stacktrace(const struct arm64_iframe_long *iframe)
{
	vaddr_t fp, sp, pc;

	if (NULL == iframe) {
		dprintf(CRITICAL, "[ No iframe, no stack traces ]\n");
		goto fail;
	}

	fp = iframe->r[29];
	sp = iframe->r[31];
	pc = iframe->elr;

	arch_print_stacktrace(fp, sp, pc);
fail:
	return;
}
