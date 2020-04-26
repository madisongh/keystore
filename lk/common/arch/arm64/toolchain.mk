ifndef ARCH_arm64_TOOLCHAIN_INCLUDED
ARCH_arm64_TOOLCHAIN_INCLUDED := 1

ifndef ARCH_arm64_TOOLCHAIN_PREFIX
ARCH_arm64_TOOLCHAIN_PREFIX := aarch64-elf-
FOUNDTOOL=$(shell which $(ARCH_arm64_TOOLCHAIN_PREFIX)gcc)
ifeq ($(FOUNDTOOL),)
ARCH_arm64_TOOLCHAIN_PREFIX := aarch64-linux-android-
FOUNDTOOL=$(shell which $(ARCH_arm64_TOOLCHAIN_PREFIX)gcc)
ifeq ($(FOUNDTOOL),)
$(error cannot find toolchain, please set ARCH_arm64_TOOLCHAIN_PREFIX or add it to your path)
endif
endif
endif

drop-option = $(if $(shell $(1) --help -v 2>/dev/null | grep -- $(2)),$(3),$(4))
ARCH_arm64_COMPILEFLAGS := -mgeneral-regs-only -DWITH_NO_FP=1 $(call drop-option,$(ARCH_arm64_TOOLCHAIN_PREFIX)gcc,-Wcast-function-type,-Wno-cast-function-type,)

endif
