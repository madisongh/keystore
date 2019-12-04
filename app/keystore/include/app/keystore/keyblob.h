#ifndef keystore_keyblob_h__
#define keystore_keyblob_h__
/*
 * Copyright (c) 2019, Matthew Madison.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * Decrypted EKB:
 *
 *   keystore magic number (4 bytes)
 *   TLVs:
 *      tag (2 bytes)
 *      len (2 bytes)
 *      value (len bytes)
 *
 *  recognized tags:
 *    0 = end of list
 *    1 = dm-crypt passphrase base
 *    2 = file encryption passphrase base
 *
 * Passphrases are sha256summed with the device UID when
 * returned.
 */
#define KEYSTORE_MAGIC 		0xABECEDEE
#define KEYSTORE_TAG_EOL	0
#define KEYSTORE_TAG_DMCPP	1
#define KEYSTORE_TAG_FILEPP	2

struct ekb_tlv {
	uint16_t tag;
	uint16_t len;
} __attribute__((packed));

#endif /* keystore_keyblob_h__ */
