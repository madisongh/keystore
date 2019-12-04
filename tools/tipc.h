/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019, Matthew Madison.
 */
#ifndef tipc_h__
#define tipc_h__

int tipc_connect(const char *devname, const char *servicename);
void tipc_close(int fd);

#endif /* tipc_h__ */
