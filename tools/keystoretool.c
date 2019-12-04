/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019, Matthew Madison.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include "tipc.h"


typedef void *kstool_ctx_t;

typedef int (*option_routine_t)(kstool_ctx_t ctx, const char *arg);

static struct option options[] = {
	{ "dmc-passphrase",	no_argument,	0, 'p' },
	{ "file-passphrase",	no_argument,	0, 'f' },
	{ "bootdone",		no_argument,	0, 'b' },
	{ "help",		no_argument,	0, 'h' },
	{ 0,			0,		0, 0   }
};
static const char *shortopts = ":pfbh";

static char *optarghelp[] = {
	"--dmc-passphrase     ",
	"--file-passphrase    ",
	"--bootdone           ",
	"--help               ",
};

static char *opthelp[] = {
	"extract the dmcrypt passphrase",
	"extract the file passphrase",
	"set booting complete",
	"display this help text"
};


static void
print_usage (void)
{
	int i;
	printf("\nUsage:\n");
	printf("\tkeystoretool <option>\n\n");
	printf("Options (use only one per invocation):\n");
	for (i = 0; i < sizeof(options)/sizeof(options[0]) && options[i].name != 0; i++) {
		printf(" %s\t%c%c\t%s\n",
		       optarghelp[i],
		       (options[i].val == 0 ? ' ' : '-'),
		       (options[i].val == 0 ? ' ' : options[i].val),
		       opthelp[i]);
	}

} /* print_usage */

/*
 * get_dmc_passphrase
 *
 * Retrieves a passphrase from the keystore.
 *
 */
static int
get_passphrase (kstool_ctx_t ctx, const char *arg)
{
	char buf[256];
	ssize_t n;
	int i;
	int fd;

	fd = tipc_connect(NULL, arg);
	if (fd < 0) {
		fprintf(stderr, "Could not connect to keystore\n");
		return 1;
	}
	n = read(fd, buf, sizeof(buf));
	if (n <= 0) {
		fprintf(stderr, "Error reading passphrase from keystore\n");
		return 1;
	}
	tipc_close(fd);
	for (i = 0; i < n; i++)
		printf("%02x", buf[i]);
	putchar('\n');
	return 0;

} /* get_passphrase */

/*
 * set_bootdone
 *
 * Informs the keystore that we're
 * done booting and it should refuse
 * any more requests for the passphrase.
 *
 */
static int
set_bootdone (kstool_ctx_t ctx, const char *arg __attribute__((unused)))
{
	int fd;

	fd = tipc_connect(NULL, "private.keystore.bootdone");
	if (fd < 0) {
		fprintf(stderr, "Could not connect to keystore\n");
		return 1;
	}
	tipc_close(fd);
	return 0;

} /* set_bootdone */


/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which, ret;
	kstool_ctx_t ctx = NULL;
	option_routine_t dispatch = NULL;
	const char *dispatch_arg = NULL;

	/*
	 * For now, at least, we allow only one option to
	 * be specified, so argc must be exactly 2.
	 */
	if (argc != 2) {
		print_usage();
		return 1;
	}

	c = getopt_long_only(argc, argv, shortopts, options, &which);
	if (c == -1) {
		perror("getopt");
		print_usage();
		return 1;
	}

	switch (c) {

		case 'h':
			print_usage();
			return 0;
		case 'p':
			dispatch = get_passphrase;
			dispatch_arg = "private.keystore.getdmckey";
			break;
		case 'f':
			dispatch = get_passphrase;
			dispatch_arg = "private.keystore.getfilekey";
			break;
		case 'b':
			dispatch = set_bootdone;
			break;
		default:
			fprintf(stderr, "Error: unrecognized option\n");
			print_usage();
			return 1;
	}

	if (dispatch == NULL) {
		fprintf(stderr, "Error in option processing\n");
		return 1;
	}

	ret = dispatch(ctx, dispatch_arg);

	return ret;

} /* main */
