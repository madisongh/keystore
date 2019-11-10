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

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

PLATFORM := t18x
SMP_MAX_CPUS := 8

ifneq ($(filter android% sim% l4t% mods%, $(TRUSTY_VARIANT)),)
GLOBAL_DEFINES += \
	DEBUG_PORT=1
else
GLOBAL_DEFINES += \
	DEBUG_PORT=2
endif

# Most target-specific makefile logic for Trusty should be placed in
# the corresponding platform makefile. There is currently no need to
# distinguish between Tegra target and tegra platform makefiles.
