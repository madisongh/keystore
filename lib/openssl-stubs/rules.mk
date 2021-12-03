LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)
MODULE_USER := true

MODULE_SRCS := \
	$(LOCAL_DIR)/bio.c \
	$(LOCAL_DIR)/rand.c \
	$(LOCAL_DIR)/sscanf.c \
	$(LOCAL_DIR)/strcasecmp.c

MODULE_DEPS := \
	lib/rng

GLOBAL_INCLUDES += $(LOCAL_DIR)/include

include make/module.mk
