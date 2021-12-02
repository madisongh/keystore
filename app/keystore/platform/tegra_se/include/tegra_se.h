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

#ifndef __TEGRA_SE_H__
#define __TEGRA_SE_H__

#include <tegra_se_internal.h>

/*
 * @brief acquires SE hardware mutex and initializes SE driver
 *
 * @return NO_ERROR if successful
 *
 * @note This function should ALWAYS be called BEFORE interacting
 *       with SE
 */
uint32_t se_acquire(void);

/*
 * @brief releases SE hardware
 *
 * @return NO_ERROR if successful
 *
 * @note This function should ALWAYS be called AFTER interacting
 *       with SE
 */
void se_release(void);

/*
 * @brief derives root key from SE keyslot
 *
 * @param *root_key	[out] root key will be written to this buffer
 * @param root_key_len	[in]  length of root_key buffer
 * @param *fv		[in]  base address of fixed vector (fv)
 * @param fv_len	[in]  length of fixed vector
 * @param keyslot	[in]  keyslot index of the root key source
 *
 * @return NO_ERROR if successful
 */
uint32_t se_derive_root_key(uint8_t *root_key, size_t root_key_len, uint8_t *fv,
			    size_t fv_len, uint32_t keyslot);

/*
 * @brief: Write a key into a SE keyslot
 *
 * @param *key_in	[in] base address of the key
 * @param keylen	[in] key length
 * @param key_quad_sel	[in] key QUAD selection
 * @param keyslot	[in] keyslot index
 *
 * @return NO_ERROR if successful
 */
int se_write_keyslot(uint8_t *key_in, uint32_t keylen, uint32_t key_quad_sel, uint32_t keyslot);

/*
 * @brief Clear SE keyslots that hold secret keys
 *
 * @return NO_ERROR if successful
 *
 * @note This function should ALWAYS be called so secret keys do
 *       not persist in SE keyslots.
 */
uint32_t se_clear_aes_keyslots(void);

typedef struct tegra_se_cmac_context se_cmac_ctx;

/*
 * @brief Create a SE CMAC context
 *
 * @return pointer of the SE CMAC context if successful
 */
se_cmac_ctx *tegra_se_cmac_new(void);

/*
 * @brief Free the SE CMAC context
 *
 * @param *se_cmac	[in] the SE CMAC context
 */
void tegra_se_cmac_free(se_cmac_ctx *se_cmac);

/*
 * @brief Initialize the SE CMAC
 *
 * @param *se_cmac	[in] the SE CMAC context
 * @param *keyslot	[in] the SE keyslot
 * @param *keylen	[in] the key length
 *
 * @return NO_ERROR if successful
 */
int tegra_se_cmac_init(se_cmac_ctx *se_cmac, se_aes_keyslot_t keyslot,
		       uint32_t keylen);
/*
 * @brief SE CMAC Update
 *
 * @param *se_cmac	[in] the SE CMAC context
 * @param *data		[in] the pointer of input data
 * @param dlen		[in] the data length
 */
int tegra_se_cmac_update(se_cmac_ctx *se_cmac, void *data, uint32_t dlen);

/*
 * @brief SE CMAC Final
 *
 * @param *se_cmac	[in] the SE CMAC context
 * @param *out		[out] the pointer of the output buffer
 * @param *poutlen	[out] the pointer of the length of the output buffer
 */
int tegra_se_cmac_final(se_cmac_ctx *se_cmac, uint8_t *out, uint32_t *poutlen);

/*
 * @brief Tegra SE HW-based NIST-SP-800-108 KDF
 *        Note. Please use the HW-based KDF during Trusty initializing/boot
 *        time (a.k.a. the device boot stage) only to derive keys from SE
 *        keyslot. At runtime, please use the SW-based KDF instead.
 *
 * @param keyslot	[in]  the SE keyslot
 * @param key_len	[in]  input key length (byte)
 * @param *context	[in]  context string
 * @param *label	[in]  label string
 * @param dk_len	[in]  length of the derived key (byte)
 * @param *out_dk 	[out] output of derived key
 *
 * @return NO_ERROR if successful
 */
int se_nist_sp_800_108_with_cmac(se_aes_keyslot_t keyslot,
				 uint32_t key_len,
				 char const *context,
				 char const *label,
				 uint32_t dk_len,
				 uint8_t *out_dk);

#endif /* __TEGRA_SE_H__ */
