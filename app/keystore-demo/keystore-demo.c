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
#include <err.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>
#include <lib/trusty/ioctl.h>

#include <keystore-demo.h>
#include <keystore-demo_tests.h>
#include <tegra_se.h>

#define  AES_KEY_128_SIZE		16
#define  EKB_SECRET_STRING_LENGTH 	16

/*
 * key derived from HW-backed key which may used to
 * encrypt/decrypt EKB.
 */
uint8_t ekb_ek[AES_KEY_128_SIZE] = {0};

/*
 * Random fixed vector used to derive EKB_EK.
 *
 * Note: This vector MUST match the 'fv' vector used for EKB binary
 * generation process.
 */
uint8_t fv[] = {
	0x86, 0x23, 0xd6, 0x3f, 0xaf, 0xe4, 0x77, 0x5a,
	0xc3, 0x81, 0x02, 0x4b, 0x4f, 0xb3, 0xef, 0xa6
};

/* The 16-byte secret test message inside the default EKB binary */
uint8_t secret_message[EKB_SECRET_STRING_LENGTH] = "secret message!!";

/* Facilitates the IOCTL_MAP_EKS_TO_USER ioctl() */
union ptr_to_int_bridge {
	uint32_t val;
	void *ptr;
};

/*
 * @brief copies EKB contents to TA memory
 *
 * @param ekb_base [out] pointer to base of ekb content buffer
 * @param ekb_size [out] length of ekb content buffer
 *
 * @return NO_ERROR if successful
 */
static uint32_t get_ekb(uint8_t **ekb_base, uint32_t *ekb_size)
{
	uint32_t r = NO_ERROR;

	void *nsdram_ekb_map_base = NULL;
	uint32_t nsdram_ekb_map_size = 0;
	void *nsdram_ekb_base = NULL;
	uint32_t nsdram_ekb_size = 0;

	union ptr_to_int_bridge params[4] = {
		{.ptr = &nsdram_ekb_base},
		{.ptr = &nsdram_ekb_size},
		{.ptr = &nsdram_ekb_map_base},
		{.ptr = &nsdram_ekb_map_size}
	};

	if ((ekb_base == NULL) || (ekb_size == NULL)) {
		TLOGE("%s: Invalid arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}

	/* Map the NSDRAM region containing EKB */
	r = ioctl(3, IOCTL_MAP_EKS_TO_USER, params);
	if (r != NO_ERROR) {
		TLOGE("%s: failed to map EKB memory (%d)\n", __func__, r);
		return ERR_GENERIC;
	}

	/* enforce a reasonable bound on the EKB size */
	if (nsdram_ekb_size > MIN_HEAP_SIZE) {
		r = ERR_TOO_BIG; goto err_size;
	}

	/* copy EKB contents out of NSDRAM */
	*ekb_size = nsdram_ekb_size;

	*ekb_base = malloc(*ekb_size);
	if (*ekb_base == NULL) {
		TLOGE("%s: malloc failed\n", __func__);
		return ERR_NO_MEMORY;
	}
	memcpy(*ekb_base, nsdram_ekb_base, *ekb_size);

err_size:
	/* Unmap the NSDRAM region containing EKB */
	if (munmap(nsdram_ekb_map_base, nsdram_ekb_map_size) != 0) {
		TLOGE("%s: failed to unmap EKB\n", __func__);
		return ERR_GENERIC;
	}

	return r;
}

/*
 * @brief derives ekb_ek, maps EKB to memory, and runs sanity tests
 *
 * @return NO_ERROR if successful
 */
int main(void)
{
	uint32_t r = NO_ERROR;
	uint8_t message_plaintext[EKB_SECRET_STRING_LENGTH];

	/* Holds ekb contents and EKB content size */
	uint8_t *ekb_base = NULL;
	size_t ekb_size = 0;

	TLOGI("Hello world from keystore-demo app\n");

	/*
	 * Initialize Security Engine (SE) and acquire SE mutex.
	 * The mutex MUST be acquired before interacting with SE.
	 */
	r = se_acquire();
	if (r != NO_ERROR) {
		TLOGE("%s: failed to initialize SE (%d). Exiting\n",__func__, r);
		return r;
	}

	/*
	 * Derive EKB_EK by performing AES-ECB encryption on the fixed
	 * vector (fv) with the key in the KEK2 SE keyslot.
	 */
	r = se_derive_ekb_ek(ekb_ek, sizeof(ekb_ek), fv, sizeof(fv));
	if (r != NO_ERROR)
		TLOGE("%s: failed to derive EKB (%d)\n", __func__, r);

	/* Clear keys from SE keyslots */
	r = se_clear_aes_keyslots();
	if (r != NO_ERROR)
		TLOGE("%s: failed to clear SE keyslots (%d)\n", __func__, r);

	/* Release SE mutex */
	se_release();

#if defined(ENABLE_TEST_EKB_DERIVATION)
	r = ekb_ek_derivation_test(ekb_ek);
	if (r != NO_ERROR)
		TLOGE("%s: EKB_EK derivation test failed (%d)\n", __func__, r);
#endif

	/* Get EKB */
	r = get_ekb(&ekb_base, &ekb_size);
	if ((r != NO_ERROR) || (ekb_base == NULL) || (ekb_size == 0)) {
		TLOGE("%s: failed to get EKB (%d). Exiting\n", __func__, r);
		goto fail;
	}

	/*
	 * The EKB contents should be decrypted here with EKB_EK.
	 *
	 * For simplicity, the default 'eks.img' image which
	 * is flashed to the EKS partition contains a 16-byte string
	 * that is XOR'ed with the EKB_EK key.
	 *
	 * obtain secret by XORing first 16 bytes of EKB contents
	 * with EKB_EK.
	 */
	if (ekb_size < EKB_SECRET_STRING_LENGTH) {
		TLOGE("%s: EKB size is too small. Exiting\n",
			__func__);
		r = ERR_GENERIC;
		goto fail;
	}

	for (int i = 0; i < EKB_SECRET_STRING_LENGTH; i++)
		message_plaintext[i] = ekb_ek[i] ^ ekb_base[i];

	/*
	 * The first 16 bytes of the EKB plaintext should match the
	 * secret_message string.
	 */
	if (!memcmp(message_plaintext, secret_message, EKB_SECRET_STRING_LENGTH)) {
		TLOGI("%s: EKB contents match expected value\n", __func__);
	} else {
		TLOGE("%s: EKB contents do not match expected value\n", __func__);
		r = ERR_GENERIC;
	}

fail:
	free(ekb_base);
	return r;
}
