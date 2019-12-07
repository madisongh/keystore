# Keystore tools

This directory contains sources for two tools
for working with the Keystore TA. See the
[Keystore README](../app/keystore/README.md) for more information.

## Building the tools

The tools are built using GNU Autotools. You will need
`autoconf`, `automake`, and `libtool` for the build,
as well as the `pkg-config` tool. The tools are written
in C, developed using GCC 7.x and later.

The OpenSSL libcrypto library and headers are also
required. They are typically found in the `libssl-dev`
or `libssl-devel` package on most distros.

Once you have cloned the git repository, use
`autoreconf -i` to set up the Autotools configuration,
then follow the typical `configure` / `make` /
`make install` process to build.

