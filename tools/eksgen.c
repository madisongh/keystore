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
#include <fcntl.h>
#include <ctype.h>
#include <endian.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include "app/keystore/vectors.h"
#include "app/keystore/keyblob.h"

static struct option options[] = {
	{ "keyfile",		required_argument,	0, 'k' },
	{ "output-file",	required_argument,	0, 'o' },
	{ "help",		no_argument,		0, 'h' },
	{ 0,			0,			0, 0   }
};
static const char *shortopts = ":k:o:h";

static char *optarghelp[] = {
	"--keyfile         ",
	"--output-file     ",
	"--help            ",
};

static char *opthelp[] = {
	"file containing the KEK2 key",
	"name of output file (default: eks.img)",
	"display this help text"
};


static void
print_usage (void)
{
	int i;
	printf("\nUsage:\n");
	printf("\teksgen <option> <dm-crypt-passphrase> [<file-passphrase>]\n\n");
	printf("Options:\n");
	for (i = 0; i < sizeof(options)/sizeof(options[0]) && options[i].name != 0; i++) {
		printf(" %s\t%c%c\t%s\n",
		       optarghelp[i],
		       (options[i].val == 0 ? ' ' : '-'),
		       (options[i].val == 0 ? ' ' : options[i].val),
		       opthelp[i]);
	}

} /* print_usage */



static const uint16_t keyblob_tags[] = {
	KEYSTORE_TAG_DMCPP,
	KEYSTORE_TAG_FILEPP,
};

static struct {
	uint32_t ekb_size;
	uint8_t  ekb_magic[8];
	uint32_t ekb_reserved;
} __attribute__((packed)) ekb_header = {
	.ekb_magic = {'N', 'V', 'E', 'K', 'B', 'P', 0, 0 },
};

static int
hexbyte (char *s, uint8_t *v)
{
	static const char hexdigits[] = "0123456789ABCDEF";
	char *d1, *d2;
	d1 = strchr(hexdigits, toupper(*s));
	d2 = strchr(hexdigits, toupper(*(s+1)));
	if (d1 == NULL || d2 == NULL)
		return -1;
	*v = (d1 - hexdigits) << 4 | (d2 - hexdigits);
	return 0;
}

static int
derive_key (uint8_t *kek, uint8_t *ek)
{
	AES_KEY key;
	uint8_t fv[16] = { KEYSTORE_FV };

	if (AES_set_encrypt_key(kek, 128, &key) != 0)
		return -1;
	AES_encrypt(fv, ek, &key);
	return 0;
}

static int
encrypt_keyblob (uint8_t *enckey, uint8_t *indata, size_t insize,
		 uint8_t *outblob, size_t outsize)
{
	AES_KEY key;
	uint8_t iv[16] = { KEYSTORE_IV };

	if (outsize < insize)
		return -1;
	if (AES_set_encrypt_key(enckey, 128, &key) != 0)
		return -1;

	AES_cbc_encrypt(indata, outblob, insize, &key, iv, AES_ENCRYPT);
	if (outsize > insize)
		memset(outblob + insize, 0, outsize-insize);
	return 0;
}

/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which;
	char *keyfile = NULL;
	char *outfile = NULL;
	uint8_t kekbuf[16], enckey[16];

	static uint8_t keydata[2048], keyblob[4096];
	uint8_t *bp;
	size_t len;
	struct ekb_tlv *tlv;
	int outfd = -1;
	int i;

	if (argc < 2) {
		print_usage();
		return 1;
	}

	while ((c = getopt_long_only(argc, argv, shortopts, options, &which)) != -1) {
		switch (c) {
			case 'h':
				print_usage();
				return 0;
			case 'k':
				keyfile = strdup(optarg);
				break;
			case 'o':
				outfile = strdup(optarg);
				break;
			default:
				fprintf(stderr, "Error: unrecognized option\n");
				print_usage();
				goto err_exit;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: expected at least one passphrase\n");
		print_usage();
		goto err_exit;
	}

	if (outfile == NULL)
		outfile = strdup("eks.img");

	if (keyfile == NULL) {
		fprintf(stderr, "NOTE: using all-zero KEK\n");
		memset(kekbuf, 0, sizeof(kekbuf));
	} else {
		int fd, i;
		char buf[256] = {0};
		ssize_t n;
		fd = open(keyfile, O_RDONLY);
		if (fd < 0) {
			perror(keyfile);
			goto err_exit;
		}
		n = read(fd, buf, sizeof(buf));
		close(fd);
		if (n <= 0) {
			fprintf(stderr, "Error reading key file %s\n", keyfile);
			goto err_exit;
		}
		if (n < 34 || !(buf[0] == '0' && buf[1] == 'x'))
			goto key_error;
		for (i = 0; i < sizeof(kekbuf); i++) {
			if (hexbyte(&buf[2 + i*2], &kekbuf[i]) < 0)
				goto key_error;
		}
	}
	if (derive_key(kekbuf, enckey) < 0) {
		fprintf(stderr, "Could not derive encryption key from KEK\n");
		goto err_exit;
	}

	outfd = open(outfile, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP);
	if (outfd < 0) {
		perror(outfile);
		goto err_exit;
	}

	bp = keydata;
	len = 0;

	*(uint32_t *)bp = htole32(KEYSTORE_MAGIC);
	bp += sizeof(uint32_t);
	len += sizeof(uint32_t);

	tlv = (struct ekb_tlv *)bp;
	for (i = 0; i < sizeof(keyblob_tags)/sizeof(keyblob_tags[0]) && optind + i < argc; i++) {
		size_t pplen = strlen(argv[optind + i]);
		if (len + pplen + sizeof(struct ekb_tlv) >= sizeof(keydata)) {
			fprintf(stderr, "Passphrase too long\n");
			goto err_exit;
		}
		tlv->tag = htole16(keyblob_tags[i]);
		tlv->len = htole16(pplen);
		memcpy(tlv + 1, argv[optind + i], pplen);
		bp += pplen + sizeof(struct ekb_tlv);
		tlv = (struct ekb_tlv *)bp;
	}
	if (len + sizeof(struct ekb_tlv) >= sizeof(keydata)) {
		fprintf(stderr, "Insufficient space for passphrase data\n");
		goto err_exit;
	}
	tlv->tag = htole16(KEYSTORE_TAG_EOL);
	tlv->len = 0;
	bp += sizeof(struct ekb_tlv);
	len = bp - keydata;
	/*
	 * eks.img content must be at least 1KiB
	 */
	while (len < 1024)
		keydata[len++] = 0;
	/*
	 * Must also be a multiple of AES_BLOCK_SIZE
	 */
	while (len < sizeof(keydata) && len % AES_BLOCK_SIZE != 0)
		keydata[len++] = 0;

	if (encrypt_keyblob(enckey, keydata, len,
			    keyblob, sizeof(keyblob)) != 0) {
		fprintf(stderr, "Keyblob encryption failed\n");
		goto err_exit;
	}
	ekb_header.ekb_size = htole32(len + sizeof(ekb_header)-sizeof(ekb_header.ekb_size));
	if (write(outfd, &ekb_header, sizeof(ekb_header)) != sizeof(ekb_header)) {
		perror("writing ekb header");
		goto err_exit;
	}
	if (write(outfd, keyblob, len) != len) {
		perror("writing keyblob");
		goto err_exit;
	}
	close(outfd);

	return 0;

key_error:
	fprintf(stderr, "Key file format error - must be '0x' followed by 32 hex digits\n");
err_exit:
	if (outfd >= 0)
		close(outfd);
	if (keyfile != NULL)
		free(keyfile);
	if (outfile != NULL)
		free(outfile);
	return 1;

} /* main */
