LOCAL_PATH := $(call my-dir)

SRC_ROOT_DIR := ../../../../..

include $(CLEAR_VARS)

LOCAL_MODULE := sodium

SODIUM_DIR := $(LOCAL_PATH)/$(SRC_ROOT_DIR)/lib/libsodium/src/libsodium
SODIUM_GENERATED_DIR := $(LOCAL_PATH)/$(SRC_ROOT_DIR)/lib/sodium-generated

# Compiled from the submodule source without autotools; CONFIGURED=1 silences
# the "undocumented method" warning and the code falls back to portable
# implementations for anything a HAVE_ macro would enable. sodium/version.h is
# the one header autotools would have generated, so it is kept alongside.
LOCAL_CFLAGS := -DCONFIGURED=1 -DSODIUM_STATIC=1 -DHAVE_PTHREAD=1 \
    -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security

ifneq (,$(filter arm64-v8a x86_64,$(TARGET_ARCH_ABI)))
LOCAL_CFLAGS += -DHAVE_TI_MODE=1
endif

LOCAL_C_INCLUDES := \
    $(SODIUM_GENERATED_DIR) \
    $(SODIUM_GENERATED_DIR)/sodium \
    $(SODIUM_DIR)/include \
    $(SODIUM_DIR)/include/sodium

# Only what libce and the JNI glue reach. Everything below the ratchet
# primitives is here because sodium_init() unconditionally calls the
# pick-best-implementation hooks for argon2, blake2b, poly1305, chacha20,
# salsa20 and both aegis variants, and randombytes pulls in chacha20/salsa20.
SODIUM_SRC_FILES := \
    sodium/codecs.c \
    sodium/core.c \
    sodium/runtime.c \
    sodium/utils.c \
    sodium/version.c \
    randombytes/randombytes.c \
    randombytes/internal/randombytes_internal_random.c \
    randombytes/sysrandom/randombytes_sysrandom.c \
    crypto_verify/verify.c \
    crypto_hash/sha256/hash_sha256.c \
    crypto_hash/sha256/cp/hash_sha256_cp.c \
    crypto_hash/sha512/hash_sha512.c \
    crypto_hash/sha512/cp/hash_sha512_cp.c \
    crypto_auth/hmacsha256/auth_hmacsha256.c \
    crypto_kdf/hkdf/kdf_hkdf_sha256.c \
    crypto_core/ed25519/core_ed25519.c \
    crypto_core/ed25519/ref10/ed25519_ref10.c \
    crypto_core/hchacha20/core_hchacha20.c \
    crypto_core/hsalsa20/core_hsalsa20.c \
    crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c \
    crypto_core/salsa/ref/core_salsa_ref.c \
    crypto_core/softaes/softaes.c \
    crypto_scalarmult/curve25519/scalarmult_curve25519.c \
    crypto_scalarmult/curve25519/ref10/x25519_ref10.c \
    crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c \
    crypto_sign/ed25519/sign_ed25519.c \
    crypto_sign/ed25519/ref10/keypair.c \
    crypto_sign/ed25519/ref10/open.c \
    crypto_sign/ed25519/ref10/sign.c \
    crypto_generichash/blake2b/ref/blake2b-ref.c \
    crypto_generichash/blake2b/ref/blake2b-compress-ref.c \
    crypto_generichash/blake2b/ref/generichash_blake2b.c \
    crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
    crypto_onetimeauth/poly1305/donna/poly1305_donna.c \
    crypto_stream/chacha20/stream_chacha20.c \
    crypto_stream/chacha20/ref/chacha20_ref.c \
    crypto_stream/salsa20/stream_salsa20.c \
    crypto_stream/salsa20/ref/salsa20_ref.c \
    crypto_pwhash/argon2/argon2-core.c \
    crypto_pwhash/argon2/argon2-fill-block-ref.c \
    crypto_pwhash/argon2/argon2-fill-block-neon.c \
    crypto_pwhash/argon2/blake2b-long.c \
    crypto_aead/aegis128l/aead_aegis128l.c \
    crypto_aead/aegis128l/aegis128l_soft.c \
    crypto_aead/aegis256/aead_aegis256.c \
    crypto_aead/aegis256/aegis256_soft.c \
    crypto_aead/chacha20poly1305/aead_chacha20poly1305.c

LOCAL_SRC_FILES := $(addprefix $(SRC_ROOT_DIR)/lib/libsodium/src/libsodium/,$(SODIUM_SRC_FILES))

LOCAL_EXPORT_C_INCLUDES := $(SODIUM_GENERATED_DIR) $(SODIUM_DIR)/include

include $(BUILD_STATIC_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE := olm

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
$(SRC_ROOT_DIR)/src/dehydrated_device.c \
$(SRC_ROOT_DIR)/src/memory.c \
$(SRC_ROOT_DIR)/src/message.c \
$(SRC_ROOT_DIR)/src/olm.c \
$(SRC_ROOT_DIR)/src/pickle.c \
$(SRC_ROOT_DIR)/src/ratchet.c \
$(SRC_ROOT_DIR)/src/session.c \
$(SRC_ROOT_DIR)/src/utility.c \
$(SRC_ROOT_DIR)/src/pk.c \
$(SRC_ROOT_DIR)/src/sas.c \
$(SRC_ROOT_DIR)/src/error.c \
$(SRC_ROOT_DIR)/src/inbound_group_session.c \
$(SRC_ROOT_DIR)/src/megolm.c \
$(SRC_ROOT_DIR)/src/outbound_group_session.c \
$(SRC_ROOT_DIR)/src/pickle_encoding.c \
$(SRC_ROOT_DIR)/lib/aes-ct64/aes_ct64.c \
$(SRC_ROOT_DIR)/lib/aes-ct64/aes_ct64_enc.c \
$(SRC_ROOT_DIR)/lib/aes-ct64/aes_ct64_dec.c \
$(SRC_ROOT_DIR)/lib/aes-ct64/aes_ct64_cbcenc.c \
$(SRC_ROOT_DIR)/lib/aes-ct64/aes_ct64_cbcdec.c \
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
LOCAL_STATIC_LIBRARIES := sodium

include $(BUILD_SHARED_LIBRARY)

