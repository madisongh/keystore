#
# Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += \
	$(LOCAL_DIR)/include \
	$(LOCAL_DIR)/platform/fuse/include \
	$(LOCAL_DIR)/platform/tegra_se/include \
	$(LOCAL_DIR)/tests/include

MODULE_SRCS += \
	$(LOCAL_DIR)/keystore-demo.c \
	$(LOCAL_DIR)/platform/fuse/fuse.c \
	$(LOCAL_DIR)/platform/tegra_se/tegra_se.c \
	$(LOCAL_DIR)/platform/tegra_se/tegra_se_aes.c \
	$(LOCAL_DIR)/tests/keystore-demo_tests.c \
	$(LOCAL_DIR)/manifest.c

MODULE_DEPS += \
	app/trusty \
	lib/libc-trusty \

# Two pages for stack
MODULE_CFLAGS += -DMIN_STACK_SIZE=8192

# Four pages for heap
MODULE_CFLAGS += -DMIN_HEAP_SIZE=16384

# SE register range
MODULE_CFLAGS += -DTEGRA_SE_BASE=0x03AC0000
MODULE_CFLAGS += -DTEGRA_SE_SIZE=0x2000

# fuse bank range
MODULE_CFLAGS += -DTEGRA_FUSE_BASE=0x3820000
MODULE_CFLAGS += -DTEGRA_FUSE_SIZE=0x10000

# tests
MODULE_CFLAGS += -DENABLE_TEST_EKB_DERIVATION

include make/module.mk
