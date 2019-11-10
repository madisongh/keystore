/*
 * Copyright (c) 2017-2018, NVIDIA CORPORATION. All rights reserved.
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

/**
 * @file rollback_prevention.h
 *
 * Defines the parameters and data structures related to rollback.
 */

#ifndef INCLUDE_ROLLBACK_PREVENTION_H
#define INCLUDE_ROLLBACK_PREVENTION_H

#if defined(WITH_PLATFORM_PARTNER)
#include <partner/platform/rollback_prevention.h>
#endif /* defined(WITH_PLATFORM_PARTNER) */

#if defined(__cplusplus)
extern "C"
{
#endif

struct rollback_limits {
	const uint8_t boot;               /* BL's rollback level except mb1 */
	const uint8_t bpmp_fw;            /* bpmp-fw's rollback level */
	const uint8_t tos;                /* TLK and SM rollback level */
	const uint8_t tsec;               /* TSEC's rollback level */
	const uint8_t nvdec;              /* NVDEC's rollback level */
	const uint8_t srm;                /* srm rollback level */
	const uint8_t tsec_gsc_ucode;     /* gsc ucode rollback level */
};

/* Rollback struct is aligned to 64 bytes */
struct rollback {
	const uint8_t version;            /* Version of the struct definition */
	uint8_t enabled;                  /* 1 -> rollback will be prevented */
	const uint8_t fuse_idx;           /* Idx in odm reserved fuses array */
	const uint8_t level;              /* mb1_bct's rollback level */
	const struct rollback_limits limits;
	uint8_t reserved[53];
};

#if defined(__cplusplus)
}
#endif

#endif /* INCLUDE_ROLLBACK_PREVENTION_H */
