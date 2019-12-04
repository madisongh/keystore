# Keystore tools makefile
#
# Copyright (c) 2019 Matthew Madison
#

AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS =
DIST_SUBDIRS =

prefix = /usr
exec_prefix = /usr
bindir = $(exec_prefix)/bin

AM_CPPFLAGS = -I$(srcdir)/../app/keystore/include

bin_PROGRAMS = keystoretool eksgen
keystoretool_SOURCES = keystoretool.c tipc.c

eksgen_SOURCES = eksgen.c
eksgen_CFLAGS = $(SSLCRYPTO_CFLAGS)
eksgen_LDADD = $(SSLCRYPTO_LIBS)
