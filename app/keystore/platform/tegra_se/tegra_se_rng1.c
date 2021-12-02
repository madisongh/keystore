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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <err_ptr.h>
#include <mm.h>

#include <trusty_std.h>
#include <common.h>

#define ELP_ENABLE	1
#define ELP_DISABLE	0
#define ELP_FALSE	0
#define ELP_TRUE	1

#define SE_RNG1_CTRL_OFFSET			0xf00

#define SE_RNG1_MODE_OFFSET			0xf04
#define SE_RNG1_MODE_PRED_RESIST_SHIFT		3
#define SE_RNG1_MODE_SEC_ALG			0
#define SE_RNG1_MODE_PRED_RESIST_EN \
	(ELP_ENABLE << SE_RNG1_MODE_PRED_RESIST_SHIFT)
#define SE_RNG1_MODE_SEC_ALG_AES_256 \
	(ELP_TRUE << SE_RNG1_MODE_SEC_ALG)

#define SE_RNG1_SMODE_OFFSET			0xf08
#define SE_RNG1_SMODE_MAX_REJECTS_SHIFT		2
#define SE_RNG1_SMODE_SECURE_SHIFT		1
#define SE_RNG1_SMODE_MAX_REJECTS_DEFAULT \
	(0xa << SE_RNG1_SMODE_MAX_REJECTS_SHIFT)
#define SE_RNG1_SMODE_SECURE_EN \
	(ELP_ENABLE << SE_RNG1_SMODE_SECURE_SHIFT)

#define SE_RNG1_STAT_OFFSET			0xf0c
#define SE_RNG1_STAT_BUSY_SHIFT			31
#define SE_RNG1_STAT_BUSY(x) \
	(x << SE_RNG1_STAT_BUSY_SHIFT)

#define SE_RNG1_IE_OFFSET			0xf10
#define SE_RNG1_INT_ENABLE_OFFSET		0xfc0

#define SE_RNG1_ISTAT_OFFSET			0xf14
#define SE_RNG1_ISTAT_CLEAR			0x1f
#define SE_RNG1_ISTAT_DONE_OFFSET		4
#define SE_RNG1_ISTAT_DONE \
	(ELP_TRUE << SE_RNG1_ISTAT_DONE_OFFSET)

#define SE_RNG1_ALARMS_OFFSET			0xf18
#define SE_RNG1_ALARMS_CLEAR			0x1f

#define SE_RNG1_RAND0_OFFSET			0xf24

#define SE_RNG1_INT_STATUS_OFFSET		0xfc4
#define SE_RNG1_INT_STATUS_CLEAR		0x30000
#define SE_RNG1_INT_STATUS_MUTEX_TIMEOUT	0x20000

#define SE_RNG1_ECTL_OFFSET			0xfc8
#define SE_RNG1_ECTL_RESET_SHIFT		5
#define SE_RNG1_ECTL_RESET(x) \
	(x << SE_RNG1_ECTL_RESET_SHIFT)

#define SE_RNG1_MUTEX_WATCHDOG_COUNTER_OFFSET	0xfd0
#define SE_RNG1_MUTEX_TIMEOUT_ACTION_OFFSET	0xfd4
#define SE_RNG1_MUTEX_TIMEOUT_ACTION		0xb
#define SE_RNG1_MUTEX_REQUEST_RELEASE_OFFSET	0xfd8

/*
 * Number of bytes that are generated each time 'gen_random' is executed.
 * RNG1 generates 128 random bits (16 bytes) at a time.
 */
#define RNG1_NUM_BYTES_PER_GEN	16

/*
 * Maximum number of bytes allowed in one se_rng1_get_random() call.
 */
#define RNG1_MAX_BYTES		(1024 * 32)

#define NUM_CTS_PER_GEN		(0x0150 * 4)
#define NUM_EXTRA_CTS		(0x0ff000 * 4)
#define MUTEX_POLL_INTERVAL_NS	(1000 * 10)
#define MUTEX_POLL_MAX_ATTEMPTS	20

typedef enum {
	RNG1_CMD_NOP = 0,
	RNG1_CMD_GEN_NOISE = 1,
	RNG1_CMD_GEN_NONCE = 2,
	RNG1_CMD_CREATE_STATE = 3,
	RNG1_CMD_RENEW_STATE = 4,
	RNG1_CMD_REFRESH_ADDIN = 5,
	RNG1_CMD_GEN_RANDOM = 6,
	RNG1_CMD_ADVANCE_STATE = 7,
	RNG1_CMD_KAT = 8,
	RNG1_CMD_ZEROIZE = 15
} se_rng1_cmd_t;

/* Internal functions */
static int se_rng1_accquire_mutex(uint32_t mutex_timeout);
static void se_rng1_release_mutex(void);
static int se_rng1_check_alarms(void);
static void se_rng1_clear_alarms(void);
static int se_rng1_wait_for_idle(void);
static int se_rng1_write_settings(void);
static int se_rng1_execute_cmd(se_rng1_cmd_t cmd);

static uint32_t rng1_base_addr = NULL;

#define SE_RNG1_REGW(A, V) \
	*(uint32_t volatile*)(rng1_base_addr + A) = V
#define SE_RNG1_REGR(A) \
	*(uint32_t volatile*)(rng1_base_addr + A)

static int se_rng1_accquire_mutex(uint32_t mutex_timeout)
{
	uint32_t i;

	for (i = 0; i < MUTEX_POLL_MAX_ATTEMPTS; i++) {
		if (SE_RNG1_REGR(SE_RNG1_MUTEX_REQUEST_RELEASE_OFFSET) == 0x01) {
			SE_RNG1_REGW(SE_RNG1_MUTEX_TIMEOUT_ACTION_OFFSET,
				     SE_RNG1_MUTEX_TIMEOUT_ACTION);
			SE_RNG1_REGW(SE_RNG1_INT_STATUS_OFFSET,
				     SE_RNG1_INT_STATUS_CLEAR);
			SE_RNG1_REGW(SE_RNG1_MUTEX_WATCHDOG_COUNTER_OFFSET,
				     mutex_timeout);
			return NO_ERROR;
		}
		nanosleep(0, 0, MUTEX_POLL_INTERVAL_NS);
	}

	TLOGE("%s: ERROR: RNG1 could not acquire mutex.\n", __func__);
	return ERR_BUSY;
}

static void se_rng1_release_mutex(void)
{
	SE_RNG1_REGW(SE_RNG1_MUTEX_REQUEST_RELEASE_OFFSET, 0x01);
}

static int se_rng1_wait_for_idle(void)
{
	while (SE_RNG1_REGR(SE_RNG1_STAT_OFFSET) & SE_RNG1_STAT_BUSY(ELP_TRUE)) {
		if (SE_RNG1_REGR(SE_RNG1_INT_STATUS_OFFSET) &
				SE_RNG1_INT_STATUS_MUTEX_TIMEOUT) {
			TLOGE("%s: ERROR: RNG1 operation time out.\n", __func__);
			/* Reset RNG1 */
			SE_RNG1_REGW(SE_RNG1_ECTL_OFFSET, SE_RNG1_ECTL_RESET(ELP_TRUE));

			return ERR_BUSY;
		}
	}

	return NO_ERROR;
}

static int se_rng1_check_alarms(void)
{
	uint32_t val;

	val = SE_RNG1_REGR(SE_RNG1_ALARMS_OFFSET);
	if (val) {
		TLOGE("%s: ERROR: RNG1 ALARMS error.\n", __func__);
		se_rng1_clear_alarms();
		return ERR_GENERIC;
	}

	return NO_ERROR;
}

static void se_rng1_clear_alarms(void)
{
	SE_RNG1_REGW(SE_RNG1_ALARMS_OFFSET, SE_RNG1_ALARMS_CLEAR);
}

static int se_rng1_write_settings(void)
{
	int rc;

	/* Clear ISTAT and ALARMS */
	se_rng1_clear_alarms();
	SE_RNG1_REGW(SE_RNG1_ISTAT_OFFSET, SE_RNG1_ISTAT_CLEAR);

	/* Disable all interrupts */
	SE_RNG1_REGW(SE_RNG1_IE_OFFSET, 0x0);
	SE_RNG1_REGW(SE_RNG1_INT_ENABLE_OFFSET, 0x0);

	rc = se_rng1_wait_for_idle();
	if (rc != NO_ERROR)
		return rc;

	/* Enable secure mode */
	SE_RNG1_REGW(SE_RNG1_SMODE_OFFSET,
		     SE_RNG1_SMODE_MAX_REJECTS_DEFAULT | SE_RNG1_SMODE_SECURE_EN);

	/* Configure RNG1 mode */
	SE_RNG1_REGW(SE_RNG1_MODE_OFFSET, SE_RNG1_MODE_PRED_RESIST_EN | SE_RNG1_MODE_SEC_ALG_AES_256);

	return NO_ERROR;
}

static int se_rng1_execute_cmd(se_rng1_cmd_t cmd)
{
	int rc;

	/* Write cmd to the CTRL register */
	SE_RNG1_REGW(SE_RNG1_CTRL_OFFSET, cmd);

	rc = se_rng1_wait_for_idle();
	if (rc != NO_ERROR) {
		TLOGE("%s: ERROR: command = %x\n", __func__, cmd);
		return rc;
	}

	SE_RNG1_REGW(SE_RNG1_ISTAT_OFFSET, SE_RNG1_ISTAT_DONE);

	return NO_ERROR;
}

int se_rng1_get_random(uint8_t *data_buf, uint32_t data_len)
{
	int rc = NO_ERROR, err;
	uint32_t num_gens, num_extra_bytes, mutex_timeout, i;

	if ((data_buf == NULL) || (data_len == 0) || (data_len > RNG1_MAX_BYTES))
		return ERR_INVALID_ARGS;

	num_gens = data_len / RNG1_NUM_BYTES_PER_GEN;
	num_extra_bytes = data_len % RNG1_NUM_BYTES_PER_GEN;
	mutex_timeout = (num_gens * NUM_CTS_PER_GEN) + NUM_EXTRA_CTS;

	rc = se_rng1_accquire_mutex(mutex_timeout);
	if (rc != NO_ERROR)
		return rc;

	/* Configure RNG1 */
	rc = se_rng1_write_settings();
	if (rc != NO_ERROR)
		goto exit;

	/* Zeroize to reset the state */
	rc = se_rng1_execute_cmd(RNG1_CMD_ZEROIZE);
	if (rc != NO_ERROR)
		goto exit;

	/* Generate a random seed and instantiate a new state */
	rc = se_rng1_execute_cmd(RNG1_CMD_GEN_NOISE);
	if (rc != NO_ERROR)
		goto exit;
	rc = se_rng1_execute_cmd(RNG1_CMD_CREATE_STATE);
	if (rc != NO_ERROR)
		goto exit_zeroize;

	/* Re-generate the seed then renew the stat */
	rc = se_rng1_execute_cmd(RNG1_CMD_GEN_NOISE);
	if (rc != NO_ERROR)
		goto exit_zeroize;
	rc = se_rng1_execute_cmd(RNG1_CMD_RENEW_STATE);
	if (rc != NO_ERROR)
		goto exit_zeroize;

	/* Loop until we've generated a sufficient number of random bytes */
	for (i = 0; i < num_gens; i++) {
		rc = se_rng1_execute_cmd(RNG1_CMD_GEN_RANDOM);
		if (rc != NO_ERROR)
			goto exit_zeroize;

		memcpy((data_buf + RNG1_NUM_BYTES_PER_GEN * i),
		       (void*)(rng1_base_addr + SE_RNG1_RAND0_OFFSET), RNG1_NUM_BYTES_PER_GEN);

		rc = se_rng1_execute_cmd(RNG1_CMD_ADVANCE_STATE);
		if (rc != NO_ERROR)
			goto exit_zeroize;
		rc = se_rng1_execute_cmd(RNG1_CMD_GEN_NOISE);
		if (rc != NO_ERROR)
			goto exit_zeroize;
		rc = se_rng1_execute_cmd(RNG1_CMD_RENEW_STATE);
		if (rc != NO_ERROR)
			goto exit_zeroize;
	}

	if (num_extra_bytes != 0) {
		rc = se_rng1_execute_cmd(RNG1_CMD_GEN_RANDOM);
		if (rc != NO_ERROR)
			goto exit_zeroize;

		memcpy((data_buf + RNG1_NUM_BYTES_PER_GEN * num_gens),
		       (void*)(rng1_base_addr + SE_RNG1_RAND0_OFFSET), num_extra_bytes);
	}

exit_zeroize:
	/* Zeroize for security purpose */
	err = se_rng1_execute_cmd(RNG1_CMD_ZEROIZE);
	if (rc == NO_ERROR)
		rc = err;

exit:
	err = se_rng1_check_alarms();
	if (rc == NO_ERROR)
		rc = err;

	se_rng1_release_mutex();

	return rc;
}

int se_rng1_init(void)
{
	int rc = NO_ERROR;

	uint32_t *ret = (uint32_t *)mmap(NULL, TEGRA_SE_RNG1_SIZE, MMAP_FLAG_IO_HANDLE, 3);
	if (IS_ERR(ret)) {
		TLOGE("%s: mmap failure: %d  size = %x\n", __func__, PTR_ERR(ret), TEGRA_SE_RNG1_SIZE);
		return ERR_GENERIC;
	}
	rng1_base_addr = (uint32_t)ret;

	rc = se_rng1_accquire_mutex(NUM_EXTRA_CTS);
	if (rc != NO_ERROR)
		return rc;

	rc = se_rng1_wait_for_idle();
	if (rc != NO_ERROR)
		goto exit;

	rc = se_rng1_check_alarms();
	if (rc != NO_ERROR)
		goto exit;

	/* Clear ISTAT register */
	SE_RNG1_REGW(SE_RNG1_ISTAT_OFFSET, SE_RNG1_ISTAT_CLEAR);

exit:
	se_rng1_release_mutex();

	return rc;
}
