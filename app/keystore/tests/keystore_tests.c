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

#include <openssl/aes.h>

#include <keystore.h>
#include <keystore_tests.h>
#include <fuse.h>

/*
 * @brief This test will pass under two conditions:
 *
 *   1. The device is in an unfused development state:
 *        The KEK2 fuse has NOT been burned (it holds a zero key)
 *        AND the device is NOT ODM production mode fused.
 *
 *   2. The device is in an fused production state:
 *        The KEK2 fuse HAS been burned (it holds a non-zero key)
 *        AND the device IS in ODM production mode fused.
 *
 * @param ekb_ek [in] pointer to base of buffer holding the EKB_EK key
 *
 * @return NO_ERROR if successful
 *
 *         If the test fails then the device is either not fully fused
 *         to utilize the EKB feature. Either the KEK2 or
 *
 * NOTE: Detecting if the KEK2 keyslot contains a zero key relies on
 *       the correct test_ekb_ek key. If the fixed vector is changed
 *       then test_ekb_ek will need to be updated accordingly,
 *       otherwise this test may produce invalid results.
 */
uint32_t ekb_ek_derivation_test(uint8_t *fv, uint8_t *ekb_ek)
{
	uint32_t r = NO_ERROR;
	bool is_odm_production = false;
	bool keys_match = false;

	AES_KEY key;
	uint8_t allzeros[16] = {0};
	uint8_t test_ekb_ek[AES_BLOCK_SIZE];

	if (AES_set_encrypt_key(allzeros, sizeof(allzeros)*8, &key) != 0) {
		TLOGE("%s: error setting encryption key\n", __func__);
		r = ERR_GENERIC;
		goto fail;
	}
	AES_encrypt(fv, test_ekb_ek, &key);

	if (!memcmp(ekb_ek, test_ekb_ek, sizeof(test_ekb_ek))) {
		keys_match = true;
	}

	r = is_device_odm_production_fused(&is_odm_production);
	if (r != NO_ERROR) {
		TLOGE("%s: Failed to read ODM production mode fuse\n",
			__func__);
		r = ERR_GENERIC;
		goto fail;
	}

	if (is_odm_production) {
		/*
		 * If the device is ODM production mode fused and
		 * HW-backed encrypted keyblobs will be used, then
		 * there should be a non-zero key burned in the
		 * KEK2 fuse.
		 */
		if (keys_match) {
			/*
			 * EKB_EK derivation appears to be derived
			 * using a zero key.
			 *
			 * It is NOT secure to encrypt sensitive
			 * contents with EKB_EK.
			 */
			TLOGE("%s: Device is ODM Production fused yet EKB_EK was derived from a zero key\n",
				__func__);
			r = ERR_GENERIC;
		}
	} else {
		/*
		 * If the device is not ODM production mode fused,
		 * assume no key has been burned into KEK2 fuse, so
		 * the KEK2 keyslot contains a zero key.
		 */
		if (!keys_match) {
			/*
			 * Either KEK2 fuse has been burned or the
			 * EKB_EK derivation flow is broken.
			 */
			TLOGE("%s: Device is not ODM Production fused yet EKB_EK was not derived from a zero key\n",
				__func__);
			r = ERR_GENERIC;
		}
	}

fail:
	return r;
}
