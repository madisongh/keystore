# Static keystore for Jetson platforms

This TA provides access to a static, encrypted
storage container in a format that is compatible
with the vendor-provided "encrypted keyblob" (EKB)
support in the flashing tools and bootloaders
for the Jetson-TX2 and Jetson AGX Xavier platforms,
as of L4T R32.2.3.

## Usage

For background on the vendor-supplied support for
secure boot and the Trusty TEE, see the
[Security](https://docs.nvidia.com/jetson/l4t/Tegra%20Linux%20Driver%20Package%20Development%20Guide/security.html#) chapter in the L4T on-line documentation.
Keystore uses the same EKB format described in the
documentation, for compatibility with the Tegra
MB2 bootloader.

Keystore can be tested on non-secured devices,
to verify basic functionality.

As mentioned in the L4T documentation, you should
program both an RSA signing key and an SBK secure
boot encryption key to encrypt *and* sign the bootloaders
and secure OS image.

### Preparing the EKB

1. Use the `eksgen` tool (see [here](../../tools/README.md) to
create an encrypted keyblob to be used as the
`eks.img` partition contents when flashing the
device. You'll need the KEK2 key used when
fusing the device to encrypt the keyblob. For
testing with a non-secured device, an all-zeros
KEK2 is used.

2. To make use of the `keystoretool` program for
retrieving keys from Keystore, make sure you
build that tool and include it in your regular
Linux OS image.

3. Flash the device. The flashing tools will
sign the EKB prior to flashing.

### Keystore operation

On startup, the digital signature on the EKB
flash partition is verified, and the 16-byte
EKB header is validated by the Tegra bootloaders.
Assuming the signature is good and the correct
header is present, the bootloader passes the
EKB contents to Keystore in memory.

Keystore derives the AES-128 encryption key
(EK) for decrypting the EKB contents from the
KEK2 key. If successful, it then decrypts (using
AES-128-CBC) the EKB contents into a heap-allocated
memory buffer.  It then parses the decrypted blob
contents, which must begin with a 4-byte "magic"
value to identify it as belonging to the Keystore app.

After the "magic" value, Keystore looks for
a sequence of TLV (tag/length/value) tuples.
Tag and length are 16-bits, little-endian.
The following tag values are recognized:

* KEYSTORE_TAG_DMCPP: value is a passphrase
  to be used for dm-crypt partition encryption.
  This passphrase can be retrieved by the
  non-secure OS exactly once when operating
  in secure mode ("ODM production mode" fuse
  set).
  
* KEYSTORE_TAG_FILEPP: value is a passphrase
  that can be used for encrypting individual
  files.  No limit on number of retrievals.

* KEYSTORE_TAG_EOL: marks the end of the
  keystore.  Length must also be zero.

Once the keystore has been parsed, Keystore
starts up three IPC service endpoints:

* `private.keystore.getdmckey`: retrieves
  the dm-crypt passphrase. On secured devices,
  a maximum of one retrieval is permitted.
  
* `private.keystore.getfilekey`: retrieves
  the file passphrase

* `private.keystore.bootdone`: receives
  notification from the non-secure OS
  that booting the OS has proceeded to
  the point that the `getdmckey` service
  should be closed down.
  
The `keystoretool` program in the [tools](../../tools)
directory implements a Linux client for
communicating with these services.

For implementing encrypted filesystems on the
device, include `keystoretool` in the initramfs,
then use it to retrieve the passphrase to be
given to `cryptsetup` for unlocking any dm-crypt
LUKS partitions. 

Note that to simplify bulk flashing of devices,
the passphrases in the keystore are combined
using SHA256 with the Tegra SoC's unique ID
to produce a unique passphrase for each device.
The key retrieval services return the checksum,
which `keystoretool` prints as a string of
hexadecimal digits.
