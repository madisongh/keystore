/*
 * Copyright (C) 2015 The Android Open Source Project
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

#pragma once

#include <compiler.h>
#include <sys/types.h>
#include <trusty_std.h>

#define TLOGE(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

#if LOCAL_TRACE
#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)
#else
#define TLOGI(fmt, ...)
#endif

typedef void (*event_handler_proc_t) (const uevent_t *ev, void *ctx);

typedef struct tipc_event_handler {
	event_handler_proc_t proc;
	void *priv;
} tipc_event_handler_t;


__BEGIN_CDECLS

/*
 *  tipc helpers
 */
void tipc_handle_port_errors(const uevent_t *ev);
void tipc_handle_chan_errors(const uevent_t *ev);

int tipc_send_single_buf(handle_t chan, const void *buf, size_t len);
int tipc_recv_single_buf(handle_t chan, void *buf, size_t len);

int tipc_send_two_segments(handle_t chan, const void *hdr, size_t hdr_len,
			   const void *payload, size_t payload_len);

int tipc_recv_two_segments(handle_t chan, void *hdr, size_t hdr_len,
			   void *payload, size_t payload_len);

/*
 * tipc services
 */
int hwrng_setup_service(void);
int hwkey_setup_service(void);

__END_CDECLS

