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
#include <err.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>

#include <keystore-demo.h>
#include <tegra_se_internal.h>

#define WORD_SIZE	sizeof(uint32_t)
#define WORD_SIZE_MASK	0x3
#define QUAD_NUM_WORDS	4

static inline void write_word(uint32_t nv_se_base, uint32_t addr,
	uint32_t val);
static void write_aes_keyslot(uint32_t *p_data, uint32_t p_data_len_len,
	uint32_t key_quad_sel, uint32_t key_slot_index);
static void write_aes_keyslot_quad(uint32_t *p_data, uint32_t num_words,
	uint32_t key_quad_sel, uint32_t key_slot_index);
static void config_aes_ecb_operation(unsigned int key_index);

static uint32_t se_prepare_dma(void *addr, uint64_t *paddr, uint32_t size, bool write)
{
	struct dma_pmem pmem[2];
	long ret;
	uint32_t flags;

	/* parameter checking */
	if (paddr == NULL) {
		TLOGE("%s: paddr argument is null\n", __func__);
		return ERR_INVALID_ARGS;
	}

	flags = DMA_FLAG_ALLOW_PARTIAL;
	flags |= write ? DMA_FLAG_TO_DEVICE : DMA_FLAG_FROM_DEVICE;

	/* convert virtual address back to physical */
	ret = prepare_dma(addr, size, flags, pmem);
	if (ret < 0) {
		TLOGE("%s: prepare_dma failure:%ld\n",
				__func__, ret);
		return ERR_GENERIC;
	}

	*paddr = pmem[0].paddr;

	return NO_ERROR;
}

static long se_finish_dma(void *regs, uint32_t size, bool write)
{
	return finish_dma(regs, size, write ? DMA_FLAG_TO_DEVICE : DMA_FLAG_FROM_DEVICE);
}

static void clear_se_keyslot(se_aes_keyslot_t se_slot, uint32_t slot_type)
{
	uint8_t zero_key[] = {
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	write_aes_keyslot((uint32_t *)zero_key, sizeof(zero_key), slot_type, se_slot);
}

uint32_t se_clear_aes_keyslots(void)
{
	clear_se_keyslot(SE_AES_KEYSLOT_11, AES_QUAD_KEYS);
	clear_se_keyslot(SE_AES_KEYSLOT_12, AES_QUAD_KEYS);
	clear_se_keyslot(SE_AES_KEYSLOT_13, AES_QUAD_KEYS);
	clear_se_keyslot(SE_AES_KEYSLOT_14, AES_QUAD_KEYS);
	clear_se_keyslot(SE_AES_KEYSLOT_15, AES_QUAD_KEYS);

	return NO_ERROR;
}

static void write_aes_keyslot(uint32_t *p_data, uint32_t p_data_len_len,
	uint32_t key_quad_sel, uint32_t key_slot_index)
{
	if (!p_data || !p_data_len_len) {
		TLOGE("%s: Invalid key data or length\n", __func__);
		return;
	}

	if (key_slot_index >= TEGRA_SE_KEYSLOT_COUNT) {
		TLOGE("%s: Invalid SE keyslot\n", __func__);
		return;
	}

	if ((p_data_len_len & WORD_SIZE_MASK) != 0) {
		TLOGE("%s: Key length %d is not a multiple of word size\n",
			__func__, p_data_len_len);
		return;
	}

	uint32_t num_words = p_data_len_len / WORD_SIZE;

	/* boundary check */
	uint32_t word_end = SE_KEYTABLE_QUAD(key_quad_sel) + SE_KEYTABLE_WORD(num_words);
	if (word_end > SE_KEYTABLE_SLOT(1)) {
		TLOGE("%s: Key range exceeds current key slot by "
			"%u words\n", __func__, word_end - SE_KEYTABLE_SLOT(1));
		return;
	}

	/* write by unit of quadword */
	uint32_t i;
	for (i = 0; i < num_words; i += QUAD_NUM_WORDS) {
		write_aes_keyslot_quad(p_data + i, MIN(4, num_words - i),
			key_quad_sel++, key_slot_index);
	}
}

/* encrypt or decrypt using AES */
uint32_t se_aes_ecb_operation(unsigned char *src, size_t src_len,
		unsigned char *dst, size_t dst_len,
		unsigned int keyslot)
{
	uint64_t p_src, p_dst;
	uint32_t err = NO_ERROR;
	uint32_t nv_se_base = get_nv_se_base();

	config_aes_ecb_operation(keyslot);

	err = se_prepare_dma((void *)src, &p_src, src_len, true);
	if (err != NO_ERROR) {
		TLOGE("%s: DMA failure: 0x%x\n",
			__func__, err);
		goto err_mem;
	}

	err = se_prepare_dma((void *)dst, &p_dst, dst_len, false);
	if (err != NO_ERROR) {
		TLOGE("%s: DMA failure: 0x%x\n",
			__func__, err);
		goto err_mem;
	}

	SE_REGW(nv_se_base, SE0_AES0_IN_ADDR_0, (uint32_t)p_src);
	SE_REGW(nv_se_base, SE0_AES0_IN_ADDR_HI_0,
		((uint32_t)(p_src >> 32) << MSB_SHIFT) | src_len);
	SE_REGW(nv_se_base, SE0_AES0_OUT_ADDR_0, (uint32_t)p_dst);
	SE_REGW(nv_se_base, SE0_AES0_OUT_ADDR_HI_0,
		((uint32_t)(p_dst >> 32) << MSB_SHIFT) | dst_len);

	/* For AES operation, the specified amount of input bytes = 16 bytes *
	 * (1 + SE_CRYPTO_LAST_BLOCK) where SE_CRYPTO_LAST_BLOCK specifies the
	 * last block number (counting from 0) for current AES operation */
	SE_REGW(nv_se_base, SE_BLOCK_COUNT_REG_OFFSET, src_len/16 - 1);
	SE_REGW(nv_se_base, SE_OPERATION_REG_OFFSET, SE_OPERATION(OP_SRART));

	while (SE_REGR(nv_se_base, SE_STATUS))
		;

	se_finish_dma((void *)src, src_len, false);
	se_finish_dma((void *)dst, dst_len, false);

err_mem:
	return err;
}

static inline void write_word(uint32_t nv_se_base, uint32_t offset,
	uint32_t val)
{
	SE_REGW(nv_se_base, SE_KEYTABLE_REG_OFFSET, offset);
	SE_REGW(nv_se_base, SE_KEYTABLE_DATA0_REG_OFFSET, val);
}

static void write_aes_keyslot_quad(uint32_t *p_data, uint32_t num_words,
	uint32_t key_quad_sel, uint32_t key_slot_index)
{
	uint32_t nv_se_base = get_nv_se_base();
	uint32_t i = 0;

	/* choose key slot */
	uint32_t nv_se_offset = SE_KEYTABLE_SLOT(key_slot_index);

	/* choose quadword */
	nv_se_offset |= SE_KEYTABLE_QUAD(key_quad_sel);

	/* write each word */
	for (i = 0; i < num_words; i++) {
		write_word(nv_se_base, nv_se_offset, p_data[i]);
		nv_se_offset += SE_KEYTABLE_WORD(1);
	}
}

static void config_aes_ecb_operation(unsigned int key_index)
{
	unsigned int crypto_cfg_value = 0, se_cfg_value = 0;
	uint32_t nv_se_base = get_nv_se_base();

	crypto_cfg_value |= SE_CRYPTO_VCTRAM_SEL(VCTRAM_AESOUT);
	crypto_cfg_value |= SE_CRYPTO_XOR_POS(XOR_BYPASS);
	crypto_cfg_value |= SE_CRYPTO_CORE_SEL(CORE_ENCRYPT);

	se_cfg_value |= SE_CONFIG_DEC_ALG(ALG_NOP);
	se_cfg_value |= SE_CONFIG_ENC_ALG(ALG_AES_ENC);
	se_cfg_value |= SE_CONFIG_ENC_MODE(AES_MODE_KEY128);

	se_cfg_value |= SE_CONFIG_DST(DST_MEMORY);

	crypto_cfg_value |= SE_CRYPTO_KEY_INDEX(key_index);

	crypto_cfg_value |= SE_CRYPTO_HASH(HASH_DISABLE);

	SE_REGW(nv_se_base, SE_CRYPTO_REG_OFFSET, crypto_cfg_value);
	SE_REGW(nv_se_base, SE_CONFIG_REG_OFFSET, se_cfg_value);
}
