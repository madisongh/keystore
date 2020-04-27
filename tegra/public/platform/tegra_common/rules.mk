#
# Copyright (c) 2018, NVIDIA CORPORATION. All rights reserved
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

COMMON_DIR := $(GET_LOCAL_DIR)

# Explicity prevent L4T from including partner/private code from all
# L4T trusty builds except t21x variants because these builds are
# intended for public release. L4T does not have customer manifests to
# differentate between dev and customer style builds.
ifeq ($(filter t186-l4t%, $(TARGET)-$(TRUSTY_VARIANT)),)
-include $(subst public,private,$(COMMON_DIR))/rules.mk
endif
ifeq ($(filter t186-l4t t186-l4t-public%, $(TARGET)-$(TRUSTY_VARIANT)),)
-include $(subst public,partner,$(COMMON_DIR))/rules.mk
endif

GLOBAL_INCLUDES += \
	$(COMMON_DIR)/include

MODULE_SRCS += \
	$(COMMON_DIR)/boot.c		\
	$(COMMON_DIR)/combined_uart.c	\
	$(COMMON_DIR)/debug.c		\
	$(COMMON_DIR)/common_platform.c \
	$(COMMON_DIR)/ioctl.c		\
	$(COMMON_DIR)/syscall.c		\
	$(COMMON_DIR)/hyp_stubs.c

ifeq ($(INSERT_SPECULATION_EXEC_BARRIER),1)
	MODULE_CFLAGS += -DINSERT_SPECULATION_BARRIER
endif
