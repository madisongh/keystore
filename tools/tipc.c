/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019, Matthew Madison.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <sys/types.h>
#include "tipc.h"

#define TIPC_IOC_MAGIC		'r'
#define TIPC_IOC_CONNECT	_IOW(TIPC_IOC_MAGIC, 0x80, char *)

static const char *TIPC_DEFAULT_DEVNAME = "/dev/trusty-ipc-dev0";

int
tipc_connect (const char *devname, const char *servicename)
{
	int fd;

	if (devname == NULL)
		devname = TIPC_DEFAULT_DEVNAME;

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return fd;
	if (ioctl(fd, TIPC_IOC_CONNECT, servicename) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

void
tipc_close (int fd)
{
	close(fd);
}
