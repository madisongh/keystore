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
#include <err.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>

#include <tegra_se.h>
#include <common.h>

#define WORD_SIZE	sizeof(uint32_t)
#define WORD_SIZE_MASK	0x3
#define QUAD_NUM_BYTES	16
#define QUAD_NUM_WORDS	4

struct tegra_se_cmac_context {
	se_aes_keyslot_t	keyslot;	/* SE key slot */
	uint32_t		keylen;		/* key lenght */
	uint8_t			k1[TEGRA_SE_AES_BLOCK_SIZE];	/* key 1 */
	uint8_t			k2[TEGRA_SE_AES_BLOCK_SIZE];	/* key 2 */
	void			*data;		/* data for CMAC operation */
	uint32_t		dlen;		/* data length */
};

uint32_t se_prepare_dma(void *addr, uint64_t *paddr, uint32_t size, bool write)
{
	struct dma_pmem pmem[2];
	long ret;
	uint32_t flags;

	/* Parameter checking */
	if (paddr == NULL) {
		TLOGE("%s: paddr argument is null\n", __func__);
		return ERR_INVALID_ARGS;
	}

	flags = DMA_FLAG_ALLOW_PARTIAL;
	flags |= write ? DMA_FLAG_TO_DEVICE : DMA_FLAG_FROM_DEVICE;

	/* Convert virtual address back to physical */
	ret = prepare_dma(addr, size, flags, pmem);
	if (ret < 0) {
		TLOGE("%s: prepare_dma failure:%ld\n",
		      __func__, ret);
		return ERR_GENERIC;
	}

	*paddr = pmem[0].paddr;

	return NO_ERROR;
}

long se_finish_dma(void *regs, uint32_t size, bool write)
{
	return finish_dma(regs, size, write ? DMA_FLAG_TO_DEVICE : DMA_FLAG_FROM_DEVICE);
}

static inline void write_word(uint32_t nv_se_base, uint32_t offset,
			      uint32_t val)
{
	SE_REGW(nv_se_base, SE_KEYTABLE_REG_OFFSET, offset);
	SE_REGW(nv_se_base, SE_KEYTABLE_DATA0_REG_OFFSET, val);
}

static void write_aes_keyslot(uint32_t *p_data, uint32_t p_data_len_len,
			      uint32_t key_quad_sel, uint32_t key_slot_index)
{
	uint32_t nv_se_base = get_nv_se_base();
	uint32_t data_size;
	uint8_t pkt = 0, quad = 0;
	uint32_t val = 0, i = 0;

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

	/* Boundary check */
	uint32_t word_end = SE_KEYTABLE_QUAD(key_quad_sel) + SE_KEYTABLE_WORD(num_words);
	if (word_end > SE_KEYTABLE_SLOT(1)) {
		TLOGE("%s: Key range exceeds current key slot by "
		      "%u words\n", __func__, word_end - SE_KEYTABLE_SLOT(1));
		return;
	}

	quad = key_quad_sel;
	if (key_quad_sel == AES_QUAD_KEYS_256)
		quad = AES_QUAD_KEYS;

	/* Write data to the key table */
	data_size = QUAD_NUM_BYTES;

	do {
		pkt = SE_KEYTABLE_SLOT(key_slot_index) |
		      SE_KEYTABLE_QUAD(quad);

		for (i = 0; i < data_size; i += 4, p_data_len_len -= 4) {
			val = pkt | SE_KEYTABLE_WORD(i/4);
			write_word(nv_se_base, val, *p_data++);
		}

		data_size = p_data_len_len;
		quad = AES_QUAD_KEYS_256;
	} while(p_data_len_len);
}

static void clear_se_keyslot(se_aes_keyslot_t se_slot, uint32_t slot_type)
{
	uint8_t zero_key[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	uint32_t keylen;

	switch (slot_type) {
	case AES_QUAD_KEYS_256:
		keylen = AES_KEY_256_SIZE;
		break;
	default:
		keylen = AES_KEY_128_SIZE;
		break;
	};

	write_aes_keyslot((uint32_t *)zero_key, keylen, slot_type, se_slot);
}

int se_write_keyslot(uint8_t *key_in, uint32_t keylen, uint32_t key_quad_sel, uint32_t keyslot)
{
	int rc = NO_ERROR;

	if ((keylen != TEGRA_SE_KEY_128_SIZE) &&
	    (keylen != TEGRA_SE_KEY_256_SIZE)) {
		TLOGE("%s: invalid key size.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	if ((key_quad_sel != AES_QUAD_KEYS) &&
	    (key_quad_sel != AES_QUAD_KEYS_256) &&
	    (key_quad_sel != AES_QUAD_ORG_IV)) {
		TLOGE("%s: invalid key QUAD selection.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	rc = se_acquire();
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to initialize SE (%d). Exiting\n", __func__, rc);
		return rc;
	}

	write_aes_keyslot((uint32_t *)key_in, keylen, key_quad_sel, keyslot);
	se_release();

	return rc;
}

uint32_t se_clear_aes_keyslots(void)
{
	int rc = NO_ERROR;
	int i;

	/* Acquire SE */
	rc = se_acquire();
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to accquire SE.\n", __func__);
		return rc;
	}

	for (i = 0; i <= AES_QUAD_MAX; i++) {
		clear_se_keyslot(SE_AES_KEYSLOT_11, i);
		clear_se_keyslot(SE_AES_KEYSLOT_12, i);
		clear_se_keyslot(SE_AES_KEYSLOT_13, i);
		clear_se_keyslot(SE_AES_KEYSLOT_14, i);

		/* If the SSK is used in Kernel, don't clear it. */
		clear_se_keyslot(SE_AES_KEYSLOT_15, i);
	}

	/* Release SE */
	se_release();

	return rc;
}

/* encryption using AES-ECB */
uint32_t se_aes_ecb_operation(unsigned char *src, size_t src_len,
			      unsigned char *dst, size_t dst_len,
			      unsigned int keyslot)
{
	uint32_t crypto_cfg_value = 0, se_cfg_value = 0;

	se_cfg_value = se_get_config(SE_AES_OP_MODE_ECB, TEGRA_SE_KEY_128_SIZE);
	crypto_cfg_value = se_get_crypto_config(SE_AES_OP_MODE_ECB, keyslot, true);

	return se_start_operation(se_cfg_value, crypto_cfg_value,
				  src, src_len, dst, dst_len);
}

static void make_sub_key(uint8_t *subkey, uint8_t *in, uint32_t size)
{
	uint8_t msb;
	uint32_t i;

	msb = in[0] >> 7;

	/* Left shift one bit */
	subkey[0] = in[0] << 1;
	for (i = 1; i < size; i++) {
		subkey[i - 1] |= in[i] >> 7;
		subkey[i] = in[i] << 1;
	}

	if (msb)
		subkey[size - 1] ^= 0x87;
}

se_cmac_ctx *tegra_se_cmac_new(void)
{
	se_cmac_ctx *se_cmac;

	se_cmac = calloc(1, sizeof(se_cmac_ctx));
	if (se_cmac == NULL)
		TLOGE("%s: malloc failed.\n", __func__);

	return se_cmac;
}

void tegra_se_cmac_free(se_cmac_ctx *se_cmac)
{
	if (!se_cmac)
		return;

	free(se_cmac);
}

int tegra_se_cmac_init(se_cmac_ctx *se_cmac, se_aes_keyslot_t keyslot,
		       uint32_t keylen)
{
	int rc = NO_ERROR;
	uint32_t config, crypto_config;
	uint8_t *pbuf;

	if (se_cmac == NULL) {
		TLOGE("%s: invalid SE CMAC context.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	if ((keylen != TEGRA_SE_KEY_128_SIZE) &&
	    (keylen != TEGRA_SE_KEY_256_SIZE)) {
		TLOGE("%s: invalid key size.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	if ((keylen == TEGRA_SE_KEY_256_SIZE) &&
	    (keyslot != SE_AES_KEYSLOT_KEK256)) {
		TLOGE("%s: invalid keyslot for 256 bit key.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	pbuf = calloc(1, TEGRA_SE_AES_BLOCK_SIZE);
	if (!pbuf) {
		TLOGE("%s: calloc failed.\n", __func__);
		return ERR_NO_MEMORY;
	}

	se_cmac->keyslot = keyslot;
	se_cmac->keylen = keylen;

	/*
	 * Load the key
	 *
	 * 1. In case of using fuse key, the key should be pre-loaded into
	 *    the dedicated keyslot before using Tegra SE AES-CMAC APIs.
	 *
	 * 2. In case of using user-defined key, please pre-load the key
	 *    into the keyslot you want to use before using Tegra SE AES-CMAC
	 *    APIs.
	 */

	/* Acquire SE */
	rc = se_acquire();
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to accquire SE.\n", __func__);
		return rc;
	}

	/* Load zero IV */
	write_aes_keyslot((uint32_t *)pbuf, TEGRA_SE_AES_IV_SIZE, AES_QUAD_ORG_IV, keyslot);

	config = se_get_config(SE_AES_OP_MODE_CBC, keylen);
	crypto_config = se_get_crypto_config(SE_AES_OP_MODE_CBC, keyslot, true);
	rc = se_start_operation(config, crypto_config,
				pbuf, TEGRA_SE_AES_BLOCK_SIZE,
				pbuf, TEGRA_SE_AES_BLOCK_SIZE);
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to start SE operation.\n", __func__);
		return rc;
	}

	make_sub_key(se_cmac->k1, pbuf, TEGRA_SE_AES_BLOCK_SIZE);
	make_sub_key(se_cmac->k2, se_cmac->k1, TEGRA_SE_AES_BLOCK_SIZE);

	/* Release SE */
	se_release();

	free(pbuf);

	return rc;
}

int tegra_se_cmac_update(se_cmac_ctx *se_cmac, void *data, uint32_t dlen)
{
	int rc = NO_ERROR;

	if ((!se_cmac) || (!data) || (!dlen)) {
		TLOGE("%s: invalid argument.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	se_cmac->data = data;
	se_cmac->dlen = dlen;

	return rc;
}

int tegra_se_cmac_final(se_cmac_ctx *se_cmac, uint8_t *out, uint32_t *poutlen)
{
	int rc = NO_ERROR;
	uint32_t config, crypto_config;
	uint32_t blocks_to_process, last_block_bytes = 0, total, i;
	bool padding_needed = false, use_orig_iv = true;
	uint8_t *iv, *buf, *last_block;

	if ((!se_cmac) || (!out)) {
		TLOGE("%s: invalid argument.\n", __func__);
		return ERR_INVALID_ARGS;
	}

	iv = calloc(1, TEGRA_SE_AES_BLOCK_SIZE);
	buf = calloc(1, TEGRA_SE_AES_BLOCK_SIZE);
	last_block = calloc(1, TEGRA_SE_AES_BLOCK_SIZE);
	if (!iv || !buf || !last_block) {
		TLOGE("%s: calloc failed.\n", __func__);
		return ERR_NO_MEMORY;
	}

	*poutlen = TEGRA_SE_AES_BLOCK_SIZE;

	blocks_to_process = se_cmac->dlen / TEGRA_SE_AES_BLOCK_SIZE;

	/* num of bytes less than block size */
	if ((se_cmac->dlen % TEGRA_SE_AES_BLOCK_SIZE) || !blocks_to_process) {
		padding_needed = true;
		last_block_bytes = se_cmac->dlen % TEGRA_SE_AES_BLOCK_SIZE;
	} else {
		blocks_to_process--;
		if (blocks_to_process)
			last_block_bytes = se_cmac->dlen -
				(blocks_to_process * TEGRA_SE_AES_BLOCK_SIZE);
		else
			last_block_bytes = se_cmac->dlen;
	}

	/* Acquire SE */
	rc = se_acquire();
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to accquire SE.\n", __func__);
		goto err_out;
	}

	/* Processing all blocks except last block */
	if (blocks_to_process) {
		total = blocks_to_process * TEGRA_SE_AES_BLOCK_SIZE;

		/* Write zero IV */
		write_aes_keyslot((uint32_t *)iv, TEGRA_SE_AES_IV_SIZE, AES_QUAD_ORG_IV, se_cmac->keyslot);

		config = se_get_config(SE_AES_OP_MODE_CMAC, se_cmac->keylen);
		crypto_config = se_get_crypto_config(SE_AES_OP_MODE_CMAC, se_cmac->keyslot, use_orig_iv);
		rc = se_start_operation(config, crypto_config,
					se_cmac->data, total,
					buf, TEGRA_SE_AES_BLOCK_SIZE);
		if (rc != NO_ERROR) {
			TLOGE("%s: failed to start SE operation.\n", __func__);
			goto err_out;
		}

		use_orig_iv = false;
	}

	memcpy(last_block, (se_cmac->data + se_cmac->dlen - last_block_bytes), last_block_bytes);

	 /* Processing last block */
	if (padding_needed) {
		last_block[last_block_bytes] = 0x80;

		/* XOR with K2 */
		for (i = 0; i < TEGRA_SE_AES_BLOCK_SIZE; i++)
			last_block[i] ^= se_cmac->k2[i];
	} else {
		/* XOR with K1 */
		for (i = 0; i < TEGRA_SE_AES_BLOCK_SIZE; i++)
			last_block[i] ^= se_cmac->k1[i];
	}

	if (use_orig_iv)
		write_aes_keyslot((uint32_t *)iv, TEGRA_SE_AES_IV_SIZE, AES_QUAD_ORG_IV, se_cmac->keyslot);
	else
		write_aes_keyslot((uint32_t *)buf, TEGRA_SE_AES_IV_SIZE, AES_QUAD_UPDTD_IV, se_cmac->keyslot);

	config = se_get_config(SE_AES_OP_MODE_CMAC, se_cmac->keylen);
	crypto_config = se_get_crypto_config(SE_AES_OP_MODE_CMAC, se_cmac->keyslot, use_orig_iv);
	rc = se_start_operation(config, crypto_config,
				last_block, TEGRA_SE_AES_BLOCK_SIZE,
				out, TEGRA_SE_AES_BLOCK_SIZE);
	if (rc != NO_ERROR) {
		TLOGE("%s: failed to start SE operation.\n", __func__);
		goto err_out;
	}

err_out:
	/* Release SE */
	se_release();

	free(iv);
	free(buf);
	free(last_block);

	return rc;
}

int se_nist_sp_800_108_with_cmac(se_aes_keyslot_t keyslot,
				 uint32_t key_len,
				 char const *context,
				 char const *label,
				 uint32_t dk_len,
				 uint8_t *out_dk)
{
	uint8_t *message = NULL, *mptr;
	uint8_t counter[] = { 1 }, zero_byte[] = { 0 };
	uint32_t L[] = { __builtin_bswap32(dk_len * 8) };
	int msg_len;
	int rc = NO_ERROR;
	se_cmac_ctx *se_cmac = NULL;
	size_t cmac_len;
	int i, n;

	if ((key_len != AES_KEY_128_SIZE) && (key_len != AES_KEY_256_SIZE))
		return ERR_INVALID_ARGS;

	if ((dk_len % TEGRA_SE_AES_BLOCK_SIZE) != 0)
		return ERR_INVALID_ARGS;

	if (!context || !label || !out_dk)
		return ERR_INVALID_ARGS;

	/* SE AES-CMAC */
	se_cmac = tegra_se_cmac_new();
	if (se_cmac == NULL) {
		TLOGE("%s: failed to allocate SE CMAC.\n", __func__);
		rc = ERR_NO_MEMORY;
		goto kdf_error;
	}

	/*
	 *  Regarding to NIST-SP-800-108
	 *  message = counter || label || 0 || context || L
	 *
	 *  A || B = The concatenation of binary strings A and B.
	 */
	msg_len = strlen(context) + strlen(label) + 2 + sizeof(L);
	message = malloc(msg_len);
	if (message == NULL) {
		TLOGE("%s: malloc failed.\n", __func__);
		return ERR_NO_MEMORY;
	}

	/* Concatenate the messages */
	mptr = message;
	memcpy(mptr , counter, sizeof(counter));
	mptr++;
	memcpy(mptr, label, strlen(label));
	mptr += strlen(label);
	memcpy(mptr, zero_byte, sizeof(zero_byte));
	mptr++;
	memcpy(mptr, context, strlen(context));
	mptr += strlen(context);
	memcpy(mptr, L, sizeof(L));

	/* n: iterations of the PRF count */
	n = dk_len / TEGRA_SE_AES_BLOCK_SIZE;

	if (key_len == AES_KEY_128_SIZE)
		tegra_se_cmac_init(se_cmac, keyslot, AES_KEY_128_SIZE);
	else
		tegra_se_cmac_init(se_cmac, keyslot, AES_KEY_256_SIZE);

	for (i = 0; i < n; i++) {
		/* Update the counter */
		message[0] = i + 1;

		tegra_se_cmac_update(se_cmac, message, msg_len);
		tegra_se_cmac_final(se_cmac, (out_dk + (i * TEGRA_SE_AES_BLOCK_SIZE)), &cmac_len);
	}

	tegra_se_cmac_free(se_cmac);

kdf_error:
	free(message);
	return rc;
}
