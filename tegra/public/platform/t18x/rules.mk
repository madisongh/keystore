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

ENABLE_THUMB := false

WITH_SMP=1

# Explicity prevent L4T from including partner/private code
# on t186 and later because these builds are intended for public
# release. L4T does not currently have customer manifests to
# differentate between dev and customer style builds,
ifeq ($(filter l4t%, $(TRUSTY_VARIANT)),)
-include $(subst public,private,$(LOCAL_DIR))/rules.mk
endif
ifeq ($(filter l4t l4t-public%, $(TRUSTY_VARIANT)),)
-include $(subst public,partner,$(LOCAL_DIR))/rules.mk
endif

ARCH := arm64
CPU := generic

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

ifneq ($(filter t194 t234, $(TARGET_SOC)),)
GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/../t19x/include

GLOBAL_DEFINES += \
	SOC_T194=1
endif


GLOBAL_DEFINES += \
	ARM_CLUSTER0_INIT_L2=1 \
	MMU_IDENT_SIZE_SHIFT=39

MEMBASE := $(KERNEL_BASE)

GLOBAL_DEFINES += MEMBASE=$(MEMBASE) \
	MEMSIZE=$(MEMSIZE) \
	VMEMSIZE=$(VMEMSIZE) \

ifeq (,$(WITH_KERNEL_VM))
# if compiling with WITH_KERNEL_VM we have to use trampoline
# as our mmu_initial_mapping table do not have identity map
GLOBAL_DEFINES += \
	MMU_WITH_TRAMPOLINE=1
endif

ifeq ($(TARGET_SOC),t186)
GLOBAL_DEFINES += \
	SOC_T186=1 \
	ROC_FLUSH_ENABLE=1
ifneq ($(filter mods%, $(TRUSTY_VARIANT)),)
GLOBAL_DEFINES += \
	DISABLE_NS_DRAM_RANGE_CHECK=1
endif # ifneq ($(filter mods%, $(TRUSTY_VARIANT)),)
endif

MODULE_DEPS += \
	dev/timer/arm_generic \
	dev/interrupt/arm_gic

# use a two segment memory layout, where all of the read-only sections
# of the binary reside in rom, and the read/write are in memory. The
# ROMBASE, VMEMBASE, and VMEMSIZE make variables are required to be set
# for the linker script to be generated properly.
#
LINKER_SCRIPT += \
	$(BUILDDIR)/system-onesegment.ld

MODULE_SRCS += \
	$(LOCAL_DIR)/platform.c		\
	$(LOCAL_DIR)/combined_uart.c	\

include platform/tegra_common/rules.mk
include make/module.mk
