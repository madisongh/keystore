#
# Copyright (c) 2018-2019, NVIDIA CORPORATION. All rights reserved
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

#
#  This would build TOS image consisting of 3 components:
#
#     monitor.bin - is a 64 bit monitor layer
#     lk.bin  - is a trusted OS that hosts a set of trusted applications
#     user_tasks - a set of trusty applications to be run within trusted os
#
#
LOCAL_DIR := $(GET_LOCAL_DIR)

TARGET := t186
TARGET_TEGRA_FAMILY := t18x

# Select 64 bit kernel by default
KERNEL_32BIT ?= false

# Memory configuration
MEMSIZE := 0x8000000	# 128MB
VMEMSIZE := 0x8000000	# 128MB

# Arm64 address space configuration
KERNEL_ASPACE_BASE := 0xffffffffe0000000
KERNEL_ASPACE_SIZE := 0x0000000020000000
KERNEL_BASE        := 0xffffffffea800000

GLOBAL_DEFINES += MMU_USER_SIZE_SHIFT=25 # 32 MB user-space address space

#
# GLOBAL definitions
#

# requires linker GC
WITH_LINKER_GC := 1

# force enums to be 4bytes
ARCH_arm_COMPILEFLAGS := -mabi=aapcs-linux

# Specify CPU architecture
ifeq (t194,$(TARGET_SOC))
# T194 uses armv8.2-a. However, the current toolchain does not support
# armv8.2-a so this flag is set to armv8-a for now
ARCH_arm_COMPILEFLAGS += -march=armv8-a
else
ARCH_arm_COMPILEFLAGS += -march=armv8-a
endif

# Disable VFP and NEON for now
ARM_WITHOUT_VFP_NEON := true

# Need support for Non-secure memory mapping
WITH_NS_MAPPING := true

# do not relocate kernel in physical memory
GLOBAL_DEFINES += WITH_NO_PHYS_RELOCATION=1

# limit heap grows
GLOBAL_DEFINES += HEAP_GROW_SIZE=65536

# select timer
GLOBAL_DEFINES += TIMER_ARM_GENERIC_SELECTED=CNTPS

TRUSTY_USER_ARCH := arm

WITH_TRUSTY_IPC := true

#Master compile switch for TOS_Boot_Profiler
#GLOBAL_DEFINES += TOS_BOOT_PROFILER_ENABLE

# Enable speculative execution barrier
# Mitigation recommendation #1 for GPZ variant 1 a.k.a Spectre
INSERT_SPECULATION_EXEC_BARRIER := 1

# Enable mitigation for GPZ variant 4 (a.k.a Speculative Store Bypass)
GLOBAL_DEFINES += WORKAROUND_CVE_2018_3639=1

TOP := $(TEGRA_TOP)

#
# Modules to be compiled into lk.bin
#

#Common modules across all variants
MODULES += \
	lib/trusty \
	lib/sm \
	lib/memlog

EXTRA_BUILDRULES += app/trusty/user-tasks.mk

#
# Variant specific trusty config.
#
# These makefiles include components, flags, etc. that are NOT common
# across all trusty build variants. This typically includes
# - User tasks
# - Variant specific makefile variables and defines
# - Variant specific module dependencies and builds rules
#
ifneq ($(filter l4t%, $(TRUSTY_VARIANT)),)
include project/t186/t186-l4t.mk
endif #TRUSTY_VARIANT
ifeq ($(filter l4t l4t-public%, $(TRUSTY_VARIANT)),)
include project/t186/t186-partner-inc.mk
endif
