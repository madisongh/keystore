# trusty-l4t with static keystore

Based on the L4T R32.6.1 sources for the Trusty TEE for
the Jetson-TX2 and Jetson AGX Xavier platforms.

The NVIDIA demo and ipc-unittest trusted apps (TAs) are
removed, and a static key storage TA, just called "keystore",
is implemented.  See [the README file](app/keystore/README.md)
for keystore for more information.

Also provided are a client-side tool for obtaining secrets
from the keystore and a build-time tool for initializing
the "encrypted keyblob" (EKB) with the secrets before
flashing.  See [the README file](tools/README.md) for
more information about the tools.

## Licensing

This software incorporates code from a variety of sources,
covered under different licenses. See the following
files for details:

* [Keystore TA license](app/keystore/LICENSE)
* [Keystore tools license](tools/LICENSE)
* [BoringSSL license](external/boringssl/src/LICENSE)
* [Fiat license](external/boringssl/src/third_party/fiat/LICENSE)
* [Wycheproof testvectors license](external/boringssl/src/third_party/wycheproof_testvectors/LICENSE)
* [Remoteproc license](external/headers/include/remoteproc/LICENSE)
* [Virtio license](external/headers/include/virtio/NOTICE)
* [LK Trusty headers license](lib/include/LICENSE)
* [LK Trusty license](lk/trusty/LICENSE)
* [libc-trusty licenses](lib/lib/libc-trusty/NOTICE)
* [libstdc++-trusty licenses](lib/lib/libstdc++-trusty/NOTICE)
* [openssl-stubs license](lib/openssl-stubs/LICENSE)
* [Little Kernel license](lk/common/LICENSE)
* [Tegra platform code license](tegra/public/LICENSE)

Note that the above may not be a complete list.

## NOTICE

This code is provided as an example of how to implement a
trusted application using the vendor-provided features in
the board support package for the Jetson platforms, and
comes with no warranties or assurances as to its security
or suitability for any particular purpose.  **Use at your
own risk.**
