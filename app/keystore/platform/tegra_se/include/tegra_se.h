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

#ifndef __KEYSTORE_DEMO_TEGRA_SE_H__
#define __KEYSTORE_DEMO_TEGRA_SE_H__

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
 * @brief derives EKB_EK key from SE keyslot
 *
 * @param *ekb_ek    [out] EKB_EK will be written to this buffer
 * @param ekb_ek_len [in]  length of ekb_ek buffer
 * @param *fv        [in]  base address of fixed vector (fv)
 * @param fv_len     [in]  length of fixed vector
 *
 * @return NO_ERROR if successful
 */
uint32_t se_derive_ekb_ek(uint8_t *ekb_ek, size_t ekb_ek_len,
	uint8_t *fv, size_t fv_len);

/*
 * @brief Clears SE keyslots that hold secret keys
 *
 * @return NO_ERROR if successful
 *
 * @note This function should ALWAYS be called so secret keys do
 *       not persist in SE keyslots.
 */
uint32_t se_clear_aes_keyslots(void);

#endif /* __KEYSTORE_DEMO_TEGRA_SE_H__ */
