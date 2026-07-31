LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)


LOCAL_MODULE := olm

SRC_ROOT_DIR := ../../../../..

include $(LOCAL_PATH)/$(SRC_ROOT_DIR)/common.mk
CE_VERSION := $(MAJOR).$(MINOR).$(PATCH)

$(info LOCAL_PATH=$(LOCAL_PATH))
$(info SRC_ROOT_DIR=$(SRC_ROOT_DIR))
$(info CE_VERSION=$(CE_VERSION))

LOCAL_CONLYFLAGS+= -std=c99
LOCAL_CFLAGS+= -DLIBCE_VERSION_MAJOR=$(MAJOR) \
-DLIBCE_VERSION_MINOR=$(MINOR) \
-DLIBCE_VERSION_PATCH=$(PATCH)

#LOCAL_CFLAGS+= -DNDK_DEBUG

LOCAL_CFLAGS+=-fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Wall
LOCAL_LDFLAGS=-z relro -z now -Wl,-z,max-page-size=16384,-z,common-page-size=16384

LOCAL_C_INCLUDES+= $(LOCAL_PATH)/$(SRC_ROOT_DIR)/include/ \
$(LOCAL_PATH)/$(SRC_ROOT_DIR)/lib

$(info LOCAL_C_INCLUDES=$(LOCAL_C_INCLUDES))

LOCAL_SRC_FILES := $(SRC_ROOT_DIR)/src/account.c \
$(SRC_ROOT_DIR)/src/base64.c \
$(SRC_ROOT_DIR)/src/cipher.c \
$(SRC_ROOT_DIR)/src/crypto.c \
$(SRC_ROOT_DIR)/src/memory.c \
$(SRC_ROOT_DIR)/src/message.c \
$(SRC_ROOT_DIR)/src/olm.c \
$(SRC_ROOT_DIR)/src/pickle.c \
$(SRC_ROOT_DIR)/src/ratchet.c \
$(SRC_ROOT_DIR)/src/session.c \
$(SRC_ROOT_DIR)/src/utility.c \
$(SRC_ROOT_DIR)/src/pk.c \
$(SRC_ROOT_DIR)/src/sas.c \
$(SRC_ROOT_DIR)/src/ed25519.c \
$(SRC_ROOT_DIR)/src/error.c \
$(SRC_ROOT_DIR)/src/inbound_group_session.c \
$(SRC_ROOT_DIR)/src/megolm.c \
$(SRC_ROOT_DIR)/src/outbound_group_session.c \
$(SRC_ROOT_DIR)/src/pickle_encoding.c \
$(SRC_ROOT_DIR)/lib/crypto-algorithms/sha256.c \
$(SRC_ROOT_DIR)/lib/crypto-algorithms/aes.c \
$(SRC_ROOT_DIR)/lib/curve25519-donna/curve25519-donna.c \
olm_account.c \
olm_session.c \
olm_jni_helper.c \
olm_inbound_group_session.c \
olm_outbound_group_session.c \
olm_utility.c \
olm_manager.c \
olm_pk.c \
olm_sas.c

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)

