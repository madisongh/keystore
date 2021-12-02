/*
 * Copyright (c) 2020-2021, NVIDIA Corporation. All Rights Reserved.
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

#include <tegra_se_internal.h>
#include <common.h>

#define MAX_POLL_ATTEMPTS 10
#define MAX_POLL_ATTEMPTS_NO_SLEEP 100
#define MUTEX_POLL_INTERVAL_NS 1000
#define MUTEX_POLL_WAIT_INTERVAL_ZERO 0

static uint32_t nv_se_base = NULL;

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

	/* Unsuccessful */
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
	if (nv_se_base == NULL) {
		uint32_t *ret = (uint32_t *)mmap(NULL, TEGRA_SE_SIZE, MMAP_FLAG_IO_HANDLE, 1);
		if (IS_ERR(ret)) {
			TLOGE("%s: mmap failure: %d  size = %x\n", __func__, PTR_ERR(ret), TEGRA_SE_SIZE);
			return *ret;
		}
		nv_se_base = (uint32_t)ret;
	}

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
	/* Readback to flush */
	intstat = SE_REGR(nv_se_base, SE_INT_STATUS_REG_OFFSET);

	release_sap_hw_mutex();
}

uint32_t se_get_config(se_aes_op_mode mode, uint32_t keylen)
{
	uint32_t val = 0;

	switch (mode) {
	case SE_AES_OP_MODE_CBC:
	case SE_AES_OP_MODE_CMAC:
	case SE_AES_OP_MODE_ECB:
		val = SE_CONFIG_ENC_ALG(ALG_AES_ENC) |
		      SE_CONFIG_DEC_ALG(ALG_NOP);
		break;
	default:
		break;
	};

	if (keylen == TEGRA_SE_KEY_256_SIZE)
		val |= SE_CONFIG_ENC_MODE(AES_MODE_KEY256);
	else
		val |= SE_CONFIG_ENC_MODE(AES_MODE_KEY128);

	val |= SE_CONFIG_DST(DST_MEMORY);

	return val;
}

uint32_t se_get_crypto_config(se_aes_op_mode mode, uint32_t keyslot, bool org_iv)
{
	uint32_t val = 0;

	switch (mode) {
	case SE_AES_OP_MODE_CBC:
	case SE_AES_OP_MODE_CMAC:
		val= SE_CRYPTO_VCTRAM_SEL(VCTRAM_AESOUT) |
		     SE_CRYPTO_XOR_POS(XOR_TOP) |
		     SE_CRYPTO_CORE_SEL(CORE_ENCRYPT);
		break;
	case SE_AES_OP_MODE_ECB:
		val= SE_CRYPTO_VCTRAM_SEL(VCTRAM_AESOUT) |
		     SE_CRYPTO_XOR_POS(XOR_BYPASS) |
		     SE_CRYPTO_CORE_SEL(CORE_ENCRYPT);
		break;
	default:
		break;
	};

	val |= SE_CRYPTO_KEY_INDEX(keyslot) |
	       (org_iv ? SE_CRYPTO_IV_SEL(IV_ORIGINAL) :
		SE_CRYPTO_IV_SEL(IV_UPDATED));

	if (mode == SE_AES_OP_MODE_CMAC)
		val |= SE_CRYPTO_HASH(HASH_ENABLE);
	else
		val |= SE_CRYPTO_HASH(HASH_DISABLE);

	return val;
}

int se_start_operation(uint32_t config, uint32_t crypto_config,
		       uint8_t *src, size_t src_len,
		       uint8_t *dst, size_t dst_len)
{
	uint64_t phy_src, phy_dst;
	int err = NO_ERROR;
	uint32_t nv_se_base = get_nv_se_base();

	err = se_prepare_dma((void *)src, &phy_src, src_len, true);
	if (err != NO_ERROR) {
		TLOGE("%s: DMA failure: 0x%x\n",
		      __func__, err);
		goto err_mem;
	}

	err = se_prepare_dma((void *)dst, &phy_dst, dst_len, false);
	if (err != NO_ERROR) {
		TLOGE("%s: DMA failure: 0x%x\n",
		      __func__, err);
		goto err_mem;
	}

	SE_REGW(nv_se_base, SE_CONFIG_REG_OFFSET, config);
	SE_REGW(nv_se_base, SE_CRYPTO_REG_OFFSET, crypto_config);

	SE_REGW(nv_se_base, SE0_AES0_IN_ADDR_0, (uint32_t)phy_src);
	SE_REGW(nv_se_base, SE0_AES0_IN_ADDR_HI_0,
		((uint32_t)(phy_src >> 32) << MSB_SHIFT) | src_len);
	SE_REGW(nv_se_base, SE0_AES0_OUT_ADDR_0, (uint32_t)phy_dst);
	SE_REGW(nv_se_base, SE0_AES0_OUT_ADDR_HI_0,
		((uint32_t)(phy_dst >> 32) << MSB_SHIFT) | dst_len);

	SE_REGW(nv_se_base, SE_BLOCK_COUNT_REG_OFFSET, src_len/16 - 1);
	SE_REGW(nv_se_base, SE_OPERATION_REG_OFFSET, SE_OPERATION(OP_SRART));

	while (SE_REGR(nv_se_base, SE_STATUS))
		;

	se_finish_dma((void *)src, src_len, false);
	se_finish_dma((void *)dst, dst_len, false);

err_mem:
	return err;
}

uint32_t se_derive_root_key(uint8_t *root_key, size_t root_key_len, uint8_t *fv,
			    size_t fv_len, uint32_t keyslot)
{
	uint32_t err = NO_ERROR;

	if ((root_key == NULL) || (fv == NULL)) {
		TLOGE("%s: invalid arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}
	if ((root_key_len != TEGRA_SE_KEY_128_SIZE) || (fv_len != TEGRA_SE_KEY_128_SIZE)) {
		TLOGE("%s: invalid size arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}

	/*
	 * Initialize Security Engine (SE) and acquire SE mutex.
	 * The mutex MUST be acquired before interacting with SE.
	 */
	err = se_acquire();
	if (err != NO_ERROR) {
		TLOGE("%s: failed to initialize SE (%d). Exiting\n", __func__, err);
		return err;
	}

	/* Derive root key from keyslot */
	err = se_aes_ecb_operation(fv, fv_len, root_key, root_key_len,
				   keyslot);
	if (err != NO_ERROR) {
		TLOGE("%s: se_aes_ecb_operation failed: 0x%x\n",
		      __func__, err);
	}

	/* Release SE mutex */
	se_release();

	return err;
}
