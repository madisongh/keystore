/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <trusty_std.h>
#include <interface/hwkey/hwkey.h>
#include <openssl/cipher.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hkdf.h>

#include "common.h"
#include "uuids.h"
#include "hwkey_srv_priv.h"

#define LOCAL_TRACE  1
#define LOG_TAG      "hwkey_fake_srv"

#warning "Compiling FAKE HWKEY provider"

/*
 *  This module is a sample only. For real device, this code
 *  needs to be rewritten to operate on real per device key that
 *  should come directly or indirectly from hardware.
 */
static uint8_t fake_device_key[32] = "this is a fake unique device key";

/* This input vector is taken from RFC 5869 (Extract-and-Expand HKDF) */
static const uint8_t IKM[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
			       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c };

static const uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

/* Expected pseudorandom key */
static const uint8_t exp_PRK[] = { 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
				   0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
				   0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
				   0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5 };

/* Expected Output Key */
static const uint8_t exp_OKM[42]= { 0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
				    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
				    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
				    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
				    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
				    0x58, 0x65 };

static bool hkdf_self_test(void)
{
	int res;
	uint8_t OKM[sizeof(exp_OKM)];

	TLOGI("hkdf self test\n");

	/* Check if OKM is OK */
	memset(OKM, 0x55, sizeof(OKM));

	res = HKDF(OKM, sizeof(OKM), EVP_sha256(),
		   IKM, sizeof(IKM), salt, sizeof(salt), info, sizeof(info));
	if (!res) {
		TLOGE("hkdf: failed 0x%x\n", ERR_get_error());
		return false;
	}

	res = memcmp(OKM, exp_OKM, sizeof(OKM));
	if (res) {
		TLOGE("hkdf: data mismatch\n");
		return false;
	}

	TLOGI("hkdf self test: PASSED\n");
	return true;
}

/*
 * Derive key V1 - HMAC SHA256 based Key derivation function
 */
uint32_t derive_key_v1(const uuid_t *uuid,
		       const uint8_t *ikm_data, size_t ikm_len,
		       uint8_t *key_buf, size_t *key_len)
{
	if (!ikm_len) {
		*key_len = 0;
		return HWKEY_ERR_BAD_LEN;
	}

	if (!HKDF(key_buf, ikm_len, EVP_sha256(),
		  (const uint8_t *)fake_device_key, sizeof(fake_device_key),
		  (const uint8_t *)uuid, sizeof(uuid_t),
		  ikm_data, ikm_len)) {
		TLOGE("HDKF failed 0x%x\n", ERR_get_error());
		*key_len = 0;
		memset(key_buf, 0, ikm_len);
		return HWKEY_ERR_GENERIC;
	}

	*key_len = ikm_len;

	return HWKEY_NO_ERROR;
}

/*
 *  RPMB Key support
 */
#define RPMB_SS_AUTH_KEY_SIZE    32
#define RPMB_SS_AUTH_KEY_ID      "com.android.trusty.storage_auth.rpmb"

/* Secure storage service app uuid */
static const uuid_t ss_uuid = SECURE_STORAGE_SERVER_APP_UUID;

static uint8_t rpmb_salt[RPMB_SS_AUTH_KEY_SIZE] = {
	0x42, 0x18, 0xa9, 0xf2, 0xf6, 0xb1, 0xf5, 0x35,
	0x06, 0x37, 0x9f, 0xba, 0xcc, 0x1a, 0xc9, 0x36,
	0xf4, 0x83, 0x04, 0xd4, 0xf1, 0x65, 0x91, 0x32,
	0xa6, 0xae, 0xda, 0x27, 0x4d, 0x21, 0xdb, 0x40
};

/*
 * Generate RPMB Secure Storage Authentication key
 */
static uint32_t get_rpmb_ss_auth_key(const struct hwkey_keyslot *slot,
				     uint8_t *kbuf, size_t kbuf_len, size_t *klen)
{
	int rc;
	int out_len;
	EVP_CIPHER_CTX evp;

	assert(kbuf);
	assert(klen);

	EVP_CIPHER_CTX_init(&evp);

	rc = EVP_EncryptInit_ex(&evp, EVP_aes_256_cbc(), NULL, fake_device_key, NULL);
	if (!rc)
		goto evp_err;

	rc = EVP_CIPHER_CTX_set_padding(&evp, 0);
	if (!rc)
		goto evp_err;

	uint min_kbuf_len = RPMB_SS_AUTH_KEY_SIZE + EVP_CIPHER_CTX_key_length(&evp);
	if (kbuf_len < min_kbuf_len) {
		TLOGE("buffer too small: (%zd vs. %zd )\n", kbuf_len,  min_kbuf_len);
		goto other_err;
	}

	rc = EVP_EncryptUpdate(&evp, kbuf, &out_len, rpmb_salt, sizeof(rpmb_salt));
	if (!rc)
		goto evp_err;

	if ((size_t)out_len != RPMB_SS_AUTH_KEY_SIZE) {
		TLOGE("output length mismatch (%zd vs %zd)\n",
			(size_t)out_len, sizeof(rpmb_salt));
		goto other_err;
	}

	rc = EVP_EncryptFinal_ex(&evp, NULL, &out_len);
	if (!rc)
		goto evp_err;

	*klen = RPMB_SS_AUTH_KEY_SIZE;

	EVP_CIPHER_CTX_cleanup(&evp);
	return HWKEY_NO_ERROR;

evp_err:
	TLOGE("EVP err 0x%x\n", ERR_get_error());
other_err:
	EVP_CIPHER_CTX_cleanup(&evp);
	return HWKEY_ERR_GENERIC;
}

/*
 *  List of keys slots that hwkey service supports
 */
static const struct hwkey_keyslot _keys[] = {
	{
		.uuid = &ss_uuid,
		.key_id = RPMB_SS_AUTH_KEY_ID,
		.handler = get_rpmb_ss_auth_key,
	},
};

/*
 *  Run Self test
 */
static bool hwkey_self_test(void)
{
	TLOGI("hwkey self test\n");

	if (!hkdf_self_test())
		return false;

	TLOGI("hwkey self test: PASSED\n");
	return true;
}

/*
 *  Initialize Fake HWKEY service provider
 */
void hwkey_init_srv_provider(void)
{
	int rc;

	TLOGE("Init FAKE!!!! HWKEY service provider\n");
	TLOGE("FAKE HWKEY service provider MUST be replaced with the REAL one\n");

	/* run self test */
	if (!hwkey_self_test()) {
		TLOGE("hwkey_self_test failed\n");
		abort();
	}

	/* install key handlers */
	hwkey_install_keys(_keys, countof(_keys));

	/* start service */
	rc = hwkey_start_service();
	if (rc != NO_ERROR ) {
		TLOGE("failed (%d) to start HWKEY service\n", rc);
	}
}
