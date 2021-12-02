/*
 * Copyright (c) 2021, NVIDIA Corporation. All Rights Reserved.
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

#ifndef __TEGRA_SE_RNG1_H__
#define __TEGRA_SE_RNG1_H__

/*
 * @brief Initialize the SE RNG1 module
 *
 * @return NO_ERROR if successful
 */
int se_rng1_init(void);

/*
 * @brief Get random bytes from the SE RNG1 module
 *
 * @param *data_buf	[out] the output of the random data buffer
 * @param data_len	[in] the length of the random bytes
 *
 * @return NO_ERROR if successful
 */
int se_rng1_get_random(uint8_t *data_buf, uint32_t data_len);

#endif /* __TEGRA_SE_RNG1_H__ */
