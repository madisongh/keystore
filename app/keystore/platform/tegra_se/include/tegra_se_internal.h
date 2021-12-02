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

#ifndef __TEGRA_SE_INTERNAL_H__
#define __TEGRA_SE_INTERNAL_H__

#include <tegra_se_aes_config.h>

#define SE_REGW(B, A, V) \
	*(uint32_t volatile*)(B + A) = V
#define SE_REGR(B, A) \
	*(uint32_t volatile*)(B + A)

#define SE_KEYTABLE_SLOT_SHIFT	4
#define SE_KEYTABLE_SLOT(x)		(x << SE_KEYTABLE_SLOT_SHIFT)
#define SE_KEYTABLE_QUAD_SHIFT	2
#define SE_KEYTABLE_WORD_SHIFT	0
#define SE_KEYTABLE_QUAD(x)		(x << SE_KEYTABLE_QUAD_SHIFT)
#define SE_KEYTABLE_WORD(x)		((x) << (SE_KEYTABLE_WORD_SHIFT))

#define AES_QUAD_KEYS		0
#define AES_QUAD_KEYS_256	1
#define AES_QUAD_ORG_IV		2
#define AES_QUAD_UPDTD_IV	3
#define AES_QUAD_MAX		AES_QUAD_UPDTD_IV

typedef enum
{
	SE_AES_KEYSLOT_11 = 11,
	SE_AES_KEYSLOT_12 = 12,
	SE_AES_KEYSLOT_13 = 13,
	SE_AES_KEYSLOT_14 = 14,
	SE_AES_KEYSLOT_15 = 15,

	// SSK is loaded in keyslot 15
	SE_AES_KEYSLOT_SSK = SE_AES_KEYSLOT_15,

	// SBK is loaded in keyslot 14
	SE_AES_KEYSLOT_SBK = SE_AES_KEYSLOT_14,

	// KEK fuse values are loaded in keyslots 11 through 13
	SE_AES_KEYSLOT_KEK1E_128B = SE_AES_KEYSLOT_13,
	SE_AES_KEYSLOT_KEK1G_128B = SE_AES_KEYSLOT_12,
	SE_AES_KEYSLOT_KEK2_128B = SE_AES_KEYSLOT_11,

	SE_AES_KEYSLOT_KEK256 = SE_AES_KEYSLOT_13,
} se_aes_keyslot_t;

/* Security Engine Operation Modes */
typedef enum
{
	SE_AES_OP_MODE_CBC,	/* Cipher Block Chaining (CBC) mode */
	SE_AES_OP_MODE_CMAC,	/* Cipher-based MAC (CMAC) mode */
	SE_AES_OP_MODE_ECB,	/* Electronic Codebook (ECB) mode */
} se_aes_op_mode;

uint32_t get_nv_se_base(void);
uint32_t se_get_config(se_aes_op_mode mode, uint32_t keylen);
uint32_t se_get_crypto_config(se_aes_op_mode mode, uint32_t keyslot, bool org_iv);
uint32_t se_prepare_dma(void *addr, uint64_t *paddr, uint32_t size, bool write);
long se_finish_dma(void *regs, uint32_t size, bool write);
int se_start_operation(uint32_t config, uint32_t crypto_config,
		       uint8_t *src, size_t src_len,
		       uint8_t *dst, size_t dst_len);

/*************************
 * AES operations
 *************************/

uint32_t se_aes_ecb_operation(unsigned char* src, size_t src_len,
			      unsigned char*dst, size_t dst_len,
			      unsigned int keyslot);

#endif /* __TEGRA_SE_INTERNAL_H__ */
