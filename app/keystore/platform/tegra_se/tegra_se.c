/*
 * Copyright (c) 2019, NVIDIA Corporation. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>

#include <keystore.h>
#include <tegra_se_internal.h>

#define MAX_POLL_ATTEMPTS 10
#define MAX_POLL_ATTEMPTS_NO_SLEEP 100
#define MUTEX_POLL_INTERVAL_NS 1000
#define MUTEX_POLL_WAIT_INTERVAL_ZERO 0

uint32_t nv_se_base = NULL;

static uint32_t acquire_sap_hw_mutex(uint32_t sleep_time, uint32_t poll_attempts)
{
	uint32_t count = 0;
	uint32_t data = 0;
	uint32_t nv_se_base = get_nv_se_base();

	while (count < poll_attempts) {
		/*
		 * When MUTEX_REQUEST_RELEASE register is 0, read the register will
		 * set the LOCK to be 1 (atomic), then it means the MUTEX had been
		 * gained by the read request.
		 *
		 * If the mutex is already locked, then any read request to this
		 * register will get the return value of 0, even from the MUTEX owner.
		 */
		if ((SE_REGR(nv_se_base, SE0_MUTEX_REQUEST_RELEASE) &
					SE0_MUTEX_REQUEST_RELEASE_0_LOCK_TRUE) == 1) {
			return NO_ERROR;
		}
		if (sleep_time)
			nanosleep(0, 0, sleep_time);
		count++;
	}

	/* unsuccessful */
	data = SE_REGR(nv_se_base, SE0_MUTEX_STATUS);
	TLOGE("%s: error. could not acquire mutex."
		"mutex status: 0x%x\n", __func__, data);
	return ERR_BUSY;
}

static void release_sap_hw_mutex(void)
{
	uint32_t nv_se_base = get_nv_se_base();
	SE_REGW(nv_se_base, SE0_MUTEX_REQUEST_RELEASE, SE0_MUTEX_REQUEST_RELEASE_0_LOCK_TRUE);
}


uint32_t get_nv_se_base(void)
{
	return nv_se_base;
}

uint32_t se_acquire(void)
{
	uint32_t err = NO_ERROR;

	/* Map SE registers */
	uint32_t *ret = (uint32_t *)mmap(NULL, TEGRA_SE_SIZE, MMAP_FLAG_IO_HANDLE, 1);
	if (IS_ERR(ret)) {
		TLOGE("%s: mmap failure: %d  size = %x\n", __func__, PTR_ERR(ret), TEGRA_SE_SIZE);
		return *ret;
	}

	nv_se_base = (uint32_t)ret;

	/* Spin on the mutex to acquire since this is in boot path */
	err = acquire_sap_hw_mutex(MUTEX_POLL_WAIT_INTERVAL_ZERO,
		MAX_POLL_ATTEMPTS_NO_SLEEP);
	if (err != NO_ERROR) {
		TLOGE("%s: acquire_sap_hw_mutex failure: 0x%x\n",
			__func__, err);
	}
	return err;
}

void se_release(void)
{
	uint32_t nv_se_base = get_nv_se_base();
	uint32_t intstat;

	/* Clean SE interrupt state after our usage */
	intstat = SE_REGR(nv_se_base, SE_INT_STATUS_REG_OFFSET);
	SE_REGW(nv_se_base, SE_INT_STATUS_REG_OFFSET, intstat);
	intstat = SE_REGR(nv_se_base, SE_INT_STATUS_REG_OFFSET);	/* readback to flush */

	release_sap_hw_mutex();
}

uint32_t se_derive_ekb_ek(uint8_t *ekb_ek, size_t ekb_ek_len, uint8_t *fv,
	size_t fv_len)
{
	uint32_t err = NO_ERROR;

	if ((ekb_ek == NULL) || (fv_len == NULL)) {
		TLOGE("%s: invalid arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}
	if ((ekb_ek_len != TEGRA_SE_KEY_128_SIZE) || (fv_len != TEGRA_SE_KEY_128_SIZE)) {
		TLOGE("%s: invalid size arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}

	/* Derive EKB_EK from KEK2 keyslot */
	err = se_aes_ecb_operation(fv, fv_len, ekb_ek, ekb_ek_len,
		SE_AES_KEYSLOT_KEK2_128B);
	if (err != NO_ERROR) {
		TLOGE("%s: se_aes_ecb_operation failed: 0x%x\n",
			__func__, err);
	}

	return err;
}
