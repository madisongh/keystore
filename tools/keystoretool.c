/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2019-2020, Matthew Madison.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "tipc.h"


typedef int (*option_routine_t)(const char *arg, FILE *outf);

static struct option options[] = {
	{ "dmc-passphrase",	no_argument,		0, 'p' },
	{ "file-passphrase",	no_argument,		0, 'f' },
	{ "bootdone",		no_argument,		0, 'b' },
	{ "output",             required_argument,	0, 'o' },
	{ "help",		no_argument,		0, 'h' },
	{ 0,			0,			0, 0   }
};
static const char *shortopts = ":pfbo:h";

static char *optarghelp[] = {
	"--dmc-passphrase     ",
	"--file-passphrase    ",
	"--bootdone           ",
	"--output             ",
	"--help               ",
};

static char *opthelp[] = {
	"extract the dmcrypt passphrase",
	"extract the file passphrase",
	"set booting complete",
	"file to write the passphrase to instead of stdout",
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
get_passphrase (const char *arg, FILE *outf)
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
		fprintf(outf, "%02x", buf[i]);
	fputc('\n', outf);
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
set_bootdone (const char *arg __attribute__((unused)),
	      FILE *outf __attribute__((unused)))
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
	option_routine_t dispatch = NULL;
	const char *dispatch_arg = NULL;
	char *outfile = NULL;
	FILE *outf = stdout;

	if (argc < 2) {
		print_usage();
		return 1;
	}

	while ((c = getopt_long_only(argc, argv, shortopts, options, &which)) != -1) {

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
			case 'o':
				outfile = strdup(optarg);
				break;
			default:
				fprintf(stderr, "Error: unrecognized option\n");
				print_usage();
				return 1;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Error: unrecognized extra arguments\n");
		print_usage();
		return 1;
	}

	if (dispatch == NULL) {
		fprintf(stderr, "No operation specified\n");
		print_usage();
		return 1;
	}

	if (outfile != NULL && dispatch == get_passphrase) {
		int fd = open(outfile, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			perror(outfile);
			return 1;
		}
		outf = fdopen(fd, "w");
		if (outf == NULL) {
			perror(outfile);
			close(fd);
			unlink(outfile);
			return 1;
		}
	}

	ret = dispatch(dispatch_arg, outf);
	if (outf != stdout) {
		if (fclose(outf) == EOF) {
			perror(outfile);
			ret = 1;
		}
	}

	return ret;

} /* main */
