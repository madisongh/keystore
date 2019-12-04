#ifndef keystore_vectors_h__
#define keystore_vectors_h__
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
 * Fixed vector used as salt added to the KEK for
 * generating the key for decrypting the EKB.
 * Must be 16 bytes.
 */
#ifndef KEYSTORE_FV
#define KEYSTORE_FV 0x6E, 0xB1, 0x1D, 0x57, 0x25, 0x6E, 0xA5, 0x52, 0xC6, 0x22, 0x9F, 0x92, 0x02, 0x68, 0x62, 0xB2
#endif
/*
 * IV for AES-128-CBC decryption of the EKB contents.
 * Must be 16 bytes.
 */
#ifndef KEYSTORE_IV
#define KEYSTORE_IV 0x96, 0x68, 0x52, 0x3C, 0xB4, 0x95, 0x87, 0x9F, 0x96, 0x55, 0xAB, 0x77, 0x66, 0x55, 0x0F, 0x61
#endif

#endif /* keystore_vectors_h__ */
