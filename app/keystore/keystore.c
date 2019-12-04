/*
 * Copyright (c) 2019, NVIDIA Corporation. All Rights Reserved.
 * Copyright (c) 2019, Matthew Madison.
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
#include <lib/trusty/ioctl.h>
#include <trusty_std.h>

#include <app/keystore/uuids.h>
#include <app/keystore/vectors.h>
#include <app/keystore/keyblob.h>
#include <keystore.h>
#include <keystore_tests.h>
#include <tegra_se.h>
#include <fuse.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#define AES_KEY_128_SIZE	16
#define MAX_MSG_SIZE		2048

/*
 * key derived from HW-backed key which may used to
 * encrypt/decrypt EKB.
 */
static uint8_t ekb_ek[AES_KEY_128_SIZE] = {0};

static uint8_t keystore_fv[16] = { KEYSTORE_FV };
static uint8_t keystore_iv[16] = { KEYSTORE_IV };

/*
 * Device unique ID, used as salt added to
 * the key extracted from the EKB when generating
 * a passphrase sent to the NS client.
 */
static uint8_t uid[16];

static uint8_t *dmcrypt_passphrase = NULL;
static size_t dmcpplen = 0;
static uint8_t *file_passphrase = NULL;
static size_t filepplen = 0;

/* Facilitates the IOCTL_MAP_EKS_TO_USER ioctl() */
union ptr_to_int_bridge {
	uint32_t val;
	void *ptr;
};

typedef void (*event_handler_proc_t) (const uevent_t *ev);

typedef struct tipc_event_handler {
	event_handler_proc_t proc;
	void *priv;
} tipc_event_handler_t;

typedef struct tipc_srv {
	const char *name;
	uint   msg_num;
	size_t msg_size;
	uint   port_flags;
	size_t port_state_size;
	size_t chan_state_size;
	event_handler_proc_t port_handler;
	event_handler_proc_t chan_handler;
} tipc_srv_t;

typedef struct tipc_srv_state {
	const struct tipc_srv *service;
	handle_t port;
	void *priv;
	tipc_event_handler_t handler;
} tipc_srv_state_t;

static void getdmckey_handle_port(const uevent_t *ev);
static void getfilekey_handle_port(const uevent_t *ev);
static void bootdone_handle_port(const uevent_t *ev);

static const struct tipc_srv _services[] = {
	{
		.name = "private.keystore.getdmckey",
		.msg_num = 2,
		.msg_size = MAX_MSG_SIZE,
		.port_flags = IPC_PORT_ALLOW_NS_CONNECT,
		.port_handler = getdmckey_handle_port,
		.chan_handler = NULL,
	},
	{
		.name = "private.keystore.getfilekey",
		.msg_num = 2,
		.msg_size = MAX_MSG_SIZE,
		.port_flags = IPC_PORT_ALLOW_NS_CONNECT,
		.port_handler = getfilekey_handle_port,
		.chan_handler = NULL,
	},
	{
		.name = "private.keystore.bootdone",
		.msg_num = 2,
		.msg_size = MAX_MSG_SIZE,
		.port_flags = IPC_PORT_ALLOW_NS_CONNECT,
		.port_handler = bootdone_handle_port,
		.chan_handler = NULL,
	},
};

static struct tipc_srv_state _srv_states[] = {
	{
		.port = INVALID_IPC_HANDLE,
	},
};

static bool stopped = false;
static bool bootdone = false;
static bool fused;
static int  dmcppsent = false;

/*
 * @brief copies EKB contents to TA memory
 *
 * @param ekb_base [out] pointer to base of ekb content buffer
 * @param ekb_size [out] length of ekb content buffer
 *
 * @return NO_ERROR if successful
 */
static uint32_t get_ekb(uint8_t **ekb_base, uint32_t *ekb_size)
{
	uint32_t r = NO_ERROR;

	void *nsdram_ekb_map_base = NULL;
	uint32_t nsdram_ekb_map_size = 0;
	void *nsdram_ekb_base = NULL;
	uint32_t nsdram_ekb_size = 0;

	union ptr_to_int_bridge params[4] = {
		{.ptr = &nsdram_ekb_base},
		{.ptr = &nsdram_ekb_size},
		{.ptr = &nsdram_ekb_map_base},
		{.ptr = &nsdram_ekb_map_size}
	};

	if ((ekb_base == NULL) || (ekb_size == NULL)) {
		TLOGE("%s: Invalid arguments\n", __func__);
		return ERR_INVALID_ARGS;
	}

	/* Map the NSDRAM region containing EKB */
	r = ioctl(3, IOCTL_MAP_EKS_TO_USER, params);
	if (r != NO_ERROR) {
		TLOGE("%s: failed to map EKB memory (%d)\n", __func__, r);
		return ERR_GENERIC;
	}

	/* enforce a reasonable bound on the EKB size */
	if (nsdram_ekb_size > MIN_HEAP_SIZE) {
		r = ERR_TOO_BIG; goto err_size;
	}

	/* copy EKB contents out of NSDRAM */
	*ekb_size = nsdram_ekb_size;

	*ekb_base = malloc(*ekb_size);
	if (*ekb_base == NULL) {
		TLOGE("%s: malloc failed\n", __func__);
		return ERR_NO_MEMORY;
	}
	memcpy(*ekb_base, nsdram_ekb_base, *ekb_size);

err_size:
	/* Unmap the NSDRAM region containing EKB */
	if (munmap(nsdram_ekb_map_base, nsdram_ekb_map_size) != 0) {
		TLOGE("%s: failed to unmap EKB\n", __func__);
		return ERR_GENERIC;
	}

	return r;
}

static int decrypt_ekb(uint8_t *ekb, size_t ekb_size)
{
	AES_KEY key;
	uint8_t *buf, *bp;
	ssize_t remain;
	struct ekb_tlv *tlv;
	int r = ERR_GENERIC;

	if (ekb_size < sizeof(uint32_t) + sizeof(struct ekb_tlv)) {
		TLOGE("%s: keystore size invalid\n", __func__);
		return r;
	}
	if (AES_set_decrypt_key(ekb_ek, sizeof(ekb_ek)*8, &key) != 0) {
		TLOGE("%s: failed to set decryption key\n", __func__);
		return r;
	}

	buf = calloc(1, ekb_size);
	if (buf == NULL)
		return ERR_NO_MEMORY;
	AES_cbc_encrypt(ekb, buf, ekb_size, &key, keystore_iv, AES_DECRYPT);
	if (*(uint32_t *)buf != KEYSTORE_MAGIC) {
		TLOGE("%s: bad magic\n", __func__);
		goto fail;
	}
	remain = ekb_size - sizeof(uint32_t);
	tlv = (struct ekb_tlv *) (buf + sizeof(uint32_t));
	while (remain >= sizeof(struct ekb_tlv)) {
		remain -= sizeof(struct ekb_tlv);
		bp = (uint8_t *) (tlv + 1);
		if (tlv->tag == KEYSTORE_TAG_EOL) {
			TLOGI("%s: end of keystore\n", __func__);
			break;
		} else if (tlv->tag == KEYSTORE_TAG_DMCPP) {
			if (remain < tlv->len) {
				TLOGE("%s: DMCPP len mismatch\n", __func__);
				goto fail;
			}
			if (dmcrypt_passphrase != NULL) {
				TLOGE("%s: DMCPP repeat\n", __func__);
				goto fail;
			}
			dmcrypt_passphrase = calloc(1, tlv->len);
			if (dmcrypt_passphrase == NULL ) {
				TLOGE("%s: DMCPP alloc error\n", __func__);
				r = ERR_NO_MEMORY;
				goto fail;
			}
			memcpy(dmcrypt_passphrase, bp, tlv->len);
			dmcpplen = tlv->len;
		} else if (tlv->tag == KEYSTORE_TAG_FILEPP) {
			if (remain < tlv->len) {
				TLOGE("%s: FILEPP len mismatch\n", __func__);
				goto fail;
			}
			if (file_passphrase != NULL) {
				TLOGE("%s: FILEPP repeat\n", __func__);
				goto fail;
			}
			file_passphrase = calloc(1, tlv->len);
			if (file_passphrase == NULL ) {
				TLOGE("%s: FILEPP alloc error\n", __func__);
				r = ERR_NO_MEMORY;
				goto fail;
			}
			memcpy(file_passphrase, bp, tlv->len);
			dmcpplen = tlv->len;
		} else {
			TLOGI("Unrecognized keyblob tag %d\n", __func__, tlv_>tag);
			if (remain < tlv->len) {
				TLOGE("%s: TLV len error\n", __func__);
				goto fail;
			}
		}
		bp += tlv->len;
		remain -= tlv->len;
		tlv = (struct ekb_tlv *) bp;
	}
	r = NO_ERROR;
fail:
	memset(buf, 0, ekb_size);
	free(buf);
	return r;
}

/************************************************************************/

static struct tipc_srv_state *get_srv_state(const uevent_t *ev)
{
	return containerof(ev->cookie, struct tipc_srv_state, handler);
}

static void _destroy_service(struct tipc_srv_state *state)
{
	if (!state) {
		TLOGI("non-null state expected\n");
		return;
	}

	/* free state if any */
	if (state->priv) {
		free(state->priv);
		state->priv = NULL;
	}

	/* close port */
	if (state->port != INVALID_IPC_HANDLE) {
		int rc = close(state->port);
		if (rc != NO_ERROR) {
			TLOGI("Failed (%d) to close port %d\n",
			       rc, state->port);
		}
		state->port = INVALID_IPC_HANDLE;
	}

	/* reset handler */
	state->service = NULL;
	state->handler.proc = NULL;
	state->handler.priv = NULL;
}


/*
 *  Create service
 */
static int _create_service(const struct tipc_srv *srv,
                           struct tipc_srv_state *state)
{
	if (!srv || !state) {
		TLOGI("null services specified\n");
		return ERR_INVALID_ARGS;
	}

	/* create port */
	int rc = port_create(srv->name, srv->msg_num, srv->msg_size,
			     srv->port_flags);
	if (rc < 0) {
		TLOGI("Failed (%d) to create port\n", rc);
		return rc;
	}

	/* setup port state  */
	state->port = (handle_t)rc;
	state->handler.proc = srv->port_handler;
	state->handler.priv = state;
	state->service = srv;
	state->priv = NULL;

	if (srv->port_state_size) {
		/* allocate port state */
		state->priv = calloc(1, srv->port_state_size);
		if (!state->priv) {
			rc = ERR_NO_MEMORY;
			goto err_calloc;
		}
	}

	/* attach handler to port handle */
	rc = set_cookie(state->port, &state->handler);
	if (rc < 0) {
		TLOGI("Failed (%d) to set cookie on port %d\n",
		      rc, state->port);
		goto err_set_cookie;
	}

	return NO_ERROR;

err_calloc:
err_set_cookie:
	_destroy_service(state);
	return rc;
}


/*
 *  Restart specified service
 */
static int restart_service(struct tipc_srv_state *state)
{
	if (!state) {
		TLOGI("non-null state expected\n");
		return ERR_INVALID_ARGS;
	}

	const struct tipc_srv *srv = state->service;
	_destroy_service(state);
	return _create_service(srv, state);
}

/*
 *  Kill all servoces
 */
static void kill_services(void)
{
	TLOGI ("Terminating keystore services\n");

	/* close any opened ports */
	for (uint i = 0; i < countof(_services); i++) {
		_destroy_service(&_srv_states[i]);
	}
}

/*
 *  Initialize all services
 */
static int init_services(void)
{
	TLOGI ("Initializing keystore services\n");

	for (uint i = 0; i < countof(_services); i++) {
		int rc = _create_service(&_services[i], &_srv_states[i]);
		if (rc < 0) {
			TLOGI("Failed (%d) to create service %s\n",
			      rc, _services[i].name);
			return rc;
		}
	}

	return 0;
}

/*
 *  Handle common port errors
 */
static bool handle_port_errors(const uevent_t *ev)
{
	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG) ||
	    (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
		/* should never happen with port handles */
		TLOGI("error event (0x%x) for port (%d)\n",
		       ev->event, ev->handle);

		/* recreate service */
		restart_service(get_srv_state(ev));
		return true;
	}

	return false;
}

static void dispatch_event(const uevent_t *ev)
{
	if (ev->event == IPC_HANDLE_POLL_NONE) {
		/* not really an event, do nothing */
		TLOGI("got an empty event\n");
		return;
	}

	if (ev->handle == INVALID_IPC_HANDLE) {
		/* not a valid handle  */
		TLOGI("got an event (0x%x) with invalid handle (%d)",
		      ev->event, ev->handle);
		return;
	}

	/* check if we have handler */
	struct tipc_event_handler *handler = ev->cookie;
	if (handler && handler->proc) {
		/* invoke it */
		handler->proc(ev);
		return;
	}

	/* no handler? close it */
	TLOGI("no handler for event (0x%x) with handle %d\n",
	       ev->event, ev->handle);
	close(ev->handle);

	return;
}

static void getdmckey_handle_port(const uevent_t *ev)
{
	ipc_msg_t msg;
	iovec_t   iov;
	uuid_t peer_uuid;
	unsigned char outkey[SHA256_DIGEST_LENGTH];

	if (handle_port_errors(ev))
		return;

	if (ev->event & IPC_HANDLE_POLL_READY) {
		handle_t chan;

		/* incomming connection: accept it */
		int rc = accept(ev->handle, &peer_uuid);
		if (rc < 0) {
			TLOGI("failed (%d) to accept on port %d\n",
			       rc, ev->handle);
			return;
		}
		chan = (handle_t) rc;
		if (fused && (bootdone || dmcppsent)) {
			TLOGI("%s: detected repeat offender\n", __func__);
			memset(outkey, 0, sizeof(outkey));
		} else if (dmcrypt_passphrase == NULL || dmcpplen == 0) {
			TLOGE("%s: nothing to return\n", __func__);
			memset(outkey, 0, sizeof(outkey));
			SHA256_CTX c;
			if (!(SHA256_Init(&c) == 0 &&
			      SHA256_Update(&c, dmcrypt_passphrase, dmcpplen) == 0 &&
			      SHA256_Update(&c, uid, sizeof(uid)) == 0 &&
			      SHA256_Final(outkey, &c) == 0)) {
				TLOGE("%s: outkey generation failed\n", __func__);
				memset(outkey, 0, sizeof(outkey));
			}
		}

		/* send interface uuid */
		iov.base = outkey;
		iov.len  = sizeof(outkey);
		msg.num_iov = 1;
		msg.iov     = &iov;
		msg.num_handles = 0;
		msg.handles  = NULL;
		rc = send_msg(chan, &msg);
		if (rc < 0) {
			TLOGI("failed (%d) to send_msg for chan (%d)\n",
			      rc, chan);
		}

		/* and close channel */
		close(chan);
		memset(outkey, 0, sizeof(outkey));
		dmcppsent = true;
	}
}

static void getfilekey_handle_port(const uevent_t *ev)
{
	ipc_msg_t msg;
	iovec_t   iov;
	uuid_t peer_uuid;
	unsigned char outkey[SHA256_DIGEST_LENGTH];

	if (handle_port_errors(ev))
		return;

	if (ev->event & IPC_HANDLE_POLL_READY) {
		handle_t chan;

		/* incomming connection: accept it */
		int rc = accept(ev->handle, &peer_uuid);
		if (rc < 0) {
			TLOGI("failed (%d) to accept on port %d\n",
			       rc, ev->handle);
			return;
		}
		chan = (handle_t) rc;
		if (file_passphrase == NULL || filepplen == 0) {
			TLOGE("%s: nothing to return\n", __func__);
			memset(outkey, 0, sizeof(outkey));
			SHA256_CTX c;
			if (!(SHA256_Init(&c) == 0 &&
			      SHA256_Update(&c, file_passphrase, filepplen) == 0 &&
			      SHA256_Update(&c, uid, sizeof(uid)) == 0 &&
			      SHA256_Final(outkey, &c) == 0)) {
				TLOGE("%s: outkey generation failed\n", __func__);
				memset(outkey, 0, sizeof(outkey));
			}
		}

		/* send interface uuid */
		iov.base = outkey;
		iov.len  = sizeof(outkey);
		msg.num_iov = 1;
		msg.iov     = &iov;
		msg.num_handles = 0;
		msg.handles  = NULL;
		rc = send_msg(chan, &msg);
		if (rc < 0) {
			TLOGI("failed (%d) to send_msg for chan (%d)\n",
			      rc, chan);
		}

		/* and close channel */
		close(chan);
		memset(outkey, 0, sizeof(outkey));
	}
}

static void bootdone_handle_port(const uevent_t *ev)
{
	uuid_t peer_uuid;

	if (handle_port_errors(ev))
		return;

	if (ev->event & IPC_HANDLE_POLL_READY) {
		handle_t chan;

		int rc = accept(ev->handle, &peer_uuid);
		if (rc < 0) {
			TLOGI("%s: failed (%d) to accept on port %d\n",
			      __func__, rc, ev->handle);
			return;
		}
		chan = (handle_t) rc;
		TLOGI("Received boot done notification, stopping\n");
		bootdone = true
		rc = close(chan);
		if (rc != NO_ERROR) {
			TLOGI("%s: Failed (%d) to close chan %d\n",
			      __func__, rc, chan);
		}
	}
}
/*
 * @brief Keystore main - initiaizes keystore and starts services
 *
 * @return NO_ERROR if successful
 */
int main(void)
{
	uint32_t r;
	uevent_t event;

	/* Holds ekb contents and EKB content size */
	uint8_t *ekb_base = NULL;
	size_t ekb_size = 0;

	TLOGI("Keystore: starting\n");

	r = is_device_odm_production_fused(&fused);
	if (r != NO_ERROR) {
		TLOGE("%s: failed to get production fuse status (%d). Exiting\n",
		      __func__, r);
		return r;
	}

	r = ioctl(3, IOCTL_GET_DEVICE_UID, uid);
	if (r != NO_ERROR) {
		TLOGE("%s: failed to get device UID (%d). Exiting\n",
		      __func__, r);
		return r;
	}
	TLOGI("%s: device UID: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	      __func__, uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6], uid[7],
	      uid[8], uid[9], uid[10], uid[11], uid[12], uid[13], uid[14], uid[15]);

	/*
	 * Must acquire SE mutex before using it
	 */
	r = se_acquire();
	if (r != NO_ERROR) {
		TLOGE("%s: failed to initialize SE (%d). Exiting\n",__func__, r);
		return r;
	}

	r = se_derive_ekb_ek(ekb_ek, sizeof(ekb_ek), keystore_fv, sizeof(keystore_fv));
	if (r != NO_ERROR)
		TLOGE("%s: failed to derive EKB (%d)\n", __func__, r);


	r = se_clear_aes_keyslots();
	if (r != NO_ERROR)
		TLOGE("%s: failed to clear SE keyslots (%d)\n", __func__, r);

	se_release();

#if defined(ENABLE_TEST_EKB_DERIVATION)
	r = ekb_ek_derivation_test(keystore_fv, ekb_ek);
	if (r != NO_ERROR)
		TLOGE("%s: EKB_EK derivation test failed (%d)\n", __func__, r);
#endif


	r = get_ekb(&ekb_base, &ekb_size);
	if ((r != NO_ERROR) || (ekb_base == NULL) || (ekb_size == 0)) {
		TLOGE("%s: failed to get EKB (%d). Exiting\n", __func__, r);
		free(ekb_base);
		return r;
	}
	TLOGI("%s: EKB retrieved, size=%u\n", __func__, ekb_size);
	r = decrypt_ekb(ekb_base, ekb_size);
	free(ekb_base);
	ekb_base = NULL;
	if (r != NO_ERROR) {
		TLOGE("%s: failed to decrypt EKB (%d). Exiting\n", __func__, r);
		return r;
	}

	r = init_services();
	if (r != NO_ERROR ) {
		TLOGI("Failed (%d) to init service", r);
		kill_services();
		return r;
	}


	while (!stopped) {
		int rc;
		event.handle = INVALID_IPC_HANDLE;
		event.event  = 0;
		event.cookie = NULL;
		rc = wait_any(&event, -1);
		if (rc < 0) {
			TLOGI("wait_any failed (%d)", rc);
			continue;
		}
		if (rc == NO_ERROR) { /* got an event */
			dispatch_event(&event);
		}
	}

	kill_services();
	if (dmcrypt_passphrase != NULL) {
		if (dmcpplen != 0)
			memset(dmcrypt_passphrase, 0, dmcpplen);
		free(dmcrypt_passphrase);
		dmcpplen = 0;
	}
	memset(keystore_iv, 0, sizeof(keystore_iv));
	memset(keystore_fv, 0, sizeof(keystore_fv));
	memset(ekb_ek, 0, sizeof(ekb_ek));
	return NO_ERROR;
}
