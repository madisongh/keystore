/*
 * Copyright (c) 2019, NVIDIA Corporation. All Rights Reserved.
 * Copyright (c) 2019, Matthew Madison.
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

#include <keystore.h>
#include <keystore_tests.h>
#include <tegra_se.h>

#define  AES_KEY_128_SIZE		16
#define  EKB_SECRET_STRING_LENGTH 	16

/*
 * key derived from HW-backed key which may used to
 * encrypt/decrypt EKB.
 */
uint8_t ekb_ek[AES_KEY_128_SIZE] = {0};

/*
 * Fixed vector used to derive EKB_EK.
 */
union {
	uint32_t fv_words[4];
	uint8_t  fv_bytes[16];
} fv;

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
	uint32_t r;

	/* Holds ekb contents and EKB content size */
	uint8_t *ekb_base = NULL;
	size_t ekb_size = 0;

	TLOGI("Keystore: starting\n");

	r = ioctl(3, IOCTL_GET_DEVICE_UID, &fv);
	if (r != NO_ERROR) {
		TLOGE("%s: failed to get device UID (%d). Exiting\n",
		      __func__, r);
		return r;
	}
	TLOGI("%s: device ID: 0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x0x%02x\n",
	      __func__, fv.fv_bytes[0], fv.fv_bytes[1], fv.fv_bytes[2], fv.fv_bytes[3],
	      fv.fv_bytes[4], fv.fv_bytes[5], fv.fv_bytes[6], fv.fv_bytes[7],
	      fv.fv_bytes[8], fv.fv_bytes[9], fv.fv_bytes[10], fv.fv_bytes[11],
	      fv.fv_bytes[12], fv.fv_bytes[13], fv.fv_bytes[14], fv.fv_bytes[15]);
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
	r = se_derive_ekb_ek(ekb_ek, sizeof(ekb_ek), fv.fv_bytes, sizeof(fv));
	if (r != NO_ERROR)
		TLOGE("%s: failed to derive EKB (%d)\n", __func__, r);

	/* Clear keys from SE keyslots */
	r = se_clear_aes_keyslots();
	if (r != NO_ERROR)
		TLOGE("%s: failed to clear SE keyslots (%d)\n", __func__, r);

	/* Release SE mutex */
	se_release();

#if defined(ENABLE_TEST_EKB_DERIVATION)
	r = ekb_ek_derivation_test(fv.fv_bytes, ekb_ek);
	if (r != NO_ERROR)
		TLOGE("%s: EKB_EK derivation test failed (%d)\n", __func__, r);
#endif

	/* Get EKB */
	r = get_ekb(&ekb_base, &ekb_size);
	if ((r != NO_ERROR) || (ekb_base == NULL) || (ekb_size == 0)) {
		TLOGE("%s: failed to get EKB (%d). Exiting\n", __func__, r);
		goto fail;
	}
	TLOGI("%s: EKB retrieved, size=%u\n", __func__, ekb_size);

fail:
	free(ekb_base);
	return r;
}
