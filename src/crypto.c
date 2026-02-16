/* See LICENSE file for copyright and license details. */
#include "libce/crypto.h"
#include "libce/memory.h"

#include <string.h>
#include <stdint.h>

#include "crypto-algorithms/aes.h"
#include "crypto-algorithms/sha256.h"

#include "ed25519/src/ed25519.h"
#include "curve25519-donna.h"


static const uint8_t CURVE25519_BASEPOINT[32] = {9};
static const size_t AES_KEY_SCHEDULE_LENGTH = 60;
static const size_t AES_KEY_BITS = 8 * AES256_KEY_LENGTH;
static const size_t AES_BLOCK_LENGTH = 16;
static const size_t SHA256_BLOCK_LENGTH = 64;
static const uint8_t HKDF_DEFAULT_SALT[32] = {};


inline static void xor_block(
    uint8_t * block, size_t block_length,
    uint8_t const * input
) {
    for (size_t i = 0; i < block_length; ++i) {
        block[i] ^= input[i];
    }
}


inline static void hmac_sha256_key(
    uint8_t const * input_key, size_t input_key_length,
    uint8_t * hmac_key
) {
    memset(hmac_key, 0, SHA256_BLOCK_LENGTH);
    if (input_key_length > SHA256_BLOCK_LENGTH) {
        SHA256_CTX context;
        sha256_init(&context);
        sha256_update(&context, input_key, input_key_length);
        sha256_final(&context, hmac_key);
    } else {
        memcpy(hmac_key, input_key, input_key_length);
    }
}


inline static void hmac_sha256_init(
    SHA256_CTX * context,
    uint8_t const * hmac_key
) {
    uint8_t i_pad[SHA256_BLOCK_LENGTH];
    memcpy(i_pad, hmac_key, SHA256_BLOCK_LENGTH);
    for (size_t i = 0; i < SHA256_BLOCK_LENGTH; ++i) {
        i_pad[i] ^= 0x36;
    }
    sha256_init(context);
    sha256_update(context, i_pad, SHA256_BLOCK_LENGTH);
    _OLM_UNSET_VALUE(i_pad);
}


inline static void hmac_sha256_final(
    SHA256_CTX * context,
    uint8_t const * hmac_key,
    uint8_t * output
) {
    uint8_t o_pad[SHA256_BLOCK_LENGTH + SHA256_OUTPUT_LENGTH];
    memcpy(o_pad, hmac_key, SHA256_BLOCK_LENGTH);
    for (size_t i = 0; i < SHA256_BLOCK_LENGTH; ++i) {
        o_pad[i] ^= 0x5C;
    }
    sha256_final(context, o_pad + SHA256_BLOCK_LENGTH);
    SHA256_CTX final_context;
    sha256_init(&final_context);
    sha256_update(&final_context, o_pad, sizeof(o_pad));
    sha256_final(&final_context, output);
    _OLM_UNSET_VALUE(final_context);
    _OLM_UNSET_VALUE(o_pad);
}


void _olm_crypto_curve25519_generate_key(
    uint8_t const * random_32_bytes,
    _olm_curve25519_key_pair *key_pair
) {
    memcpy(
        key_pair->private_key.private_key, random_32_bytes,
        CURVE25519_KEY_LENGTH
    );
    curve25519_donna(
        key_pair->public_key.public_key,
        key_pair->private_key.private_key,
        CURVE25519_BASEPOINT
    );
}


void _olm_crypto_curve25519_shared_secret(
    const _olm_curve25519_key_pair *our_key,
    const _olm_curve25519_public_key * their_key,
    uint8_t * output
) {
    curve25519_donna(output, our_key->private_key.private_key, their_key->public_key);
}


void _olm_crypto_ed25519_generate_key(
    uint8_t const * random_32_bytes,
    _olm_ed25519_key_pair *key_pair
) {
    ed25519_create_keypair(
        key_pair->public_key.public_key, key_pair->private_key.private_key,
        random_32_bytes
    );
}


void _olm_crypto_ed25519_sign(
    const _olm_ed25519_key_pair *our_key,
    uint8_t const * message, size_t message_length,
    uint8_t * output
) {
    ed25519_sign(
        output,
        message, message_length,
        our_key->public_key.public_key,
        our_key->private_key.private_key
    );
}


int _olm_crypto_ed25519_verify(
    const _olm_ed25519_public_key *their_key,
    uint8_t const * message, size_t message_length,
    uint8_t const * signature
) {
    return 0 != ed25519_verify(
        signature,
        message, message_length,
        their_key->public_key
    );
}


size_t _olm_crypto_aes_encrypt_cbc_length(
    size_t input_length
) {
    return input_length + AES_BLOCK_LENGTH - input_length % AES_BLOCK_LENGTH;
}


void _olm_crypto_aes_encrypt_cbc(
    _olm_aes256_key const *key,
    _olm_aes256_iv const *iv,
    uint8_t const * input, size_t input_length,
    uint8_t * output
) {
    uint32_t key_schedule[AES_KEY_SCHEDULE_LENGTH];
    aes_key_setup(key->key, key_schedule, AES_KEY_BITS);
    uint8_t input_block[AES_BLOCK_LENGTH];
    memcpy(input_block, iv->iv, AES_BLOCK_LENGTH);
    while (input_length >= AES_BLOCK_LENGTH) {
        xor_block(input_block, AES_BLOCK_LENGTH, input);
        aes_encrypt(input_block, output, key_schedule, AES_KEY_BITS);
        memcpy(input_block, output, AES_BLOCK_LENGTH);
        input += AES_BLOCK_LENGTH;
        output += AES_BLOCK_LENGTH;
        input_length -= AES_BLOCK_LENGTH;
    }
    size_t i = 0;
    for (; i < input_length; ++i) {
        input_block[i] ^= input[i];
    }
    for (; i < AES_BLOCK_LENGTH; ++i) {
        input_block[i] ^= AES_BLOCK_LENGTH - input_length;
    }
    aes_encrypt(input_block, output, key_schedule, AES_KEY_BITS);
    _OLM_UNSET_VALUE(key_schedule);
    _OLM_UNSET_VALUE(input_block);
}


size_t _olm_crypto_aes_decrypt_cbc(
    _olm_aes256_key const *key,
    _olm_aes256_iv const *iv,
    uint8_t const * input, size_t input_length,
    uint8_t * output
) {
    uint32_t key_schedule[AES_KEY_SCHEDULE_LENGTH];
    aes_key_setup(key->key, key_schedule, AES_KEY_BITS);
    uint8_t block1[AES_BLOCK_LENGTH];
    uint8_t block2[AES_BLOCK_LENGTH];
    memcpy(block1, iv->iv, AES_BLOCK_LENGTH);
    for (size_t i = 0; i < input_length; i += AES_BLOCK_LENGTH) {
        memcpy(block2, &input[i], AES_BLOCK_LENGTH);
        aes_decrypt(&input[i], &output[i], key_schedule, AES_KEY_BITS);
        xor_block(&output[i], AES_BLOCK_LENGTH, block1);
        memcpy(block1, block2, AES_BLOCK_LENGTH);
    }
    _OLM_UNSET_VALUE(key_schedule);
    _OLM_UNSET_VALUE(block1);
    _OLM_UNSET_VALUE(block2);
    size_t padding = output[input_length - 1];
    return (padding > input_length) ? SIZE_MAX : (input_length - padding);
}


void _olm_crypto_sha256(
    uint8_t const * input, size_t input_length,
    uint8_t * output
) {
    SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, input, input_length);
    sha256_final(&context, output);
    _OLM_UNSET_VALUE(context);
}


void _olm_crypto_hmac_sha256(
    uint8_t const * key, size_t key_length,
    uint8_t const * input, size_t input_length,
    uint8_t * output
) {
    uint8_t hmac_key[SHA256_BLOCK_LENGTH];
    SHA256_CTX context;
    hmac_sha256_key(key, key_length, hmac_key);
    hmac_sha256_init(&context, hmac_key);
    sha256_update(&context, input, input_length);
    hmac_sha256_final(&context, hmac_key, output);
    _OLM_UNSET_VALUE(hmac_key);
    _OLM_UNSET_VALUE(context);
}


void _olm_crypto_hkdf_sha256(
    uint8_t const * input, size_t input_length,
    uint8_t const * salt, size_t salt_length,
    uint8_t const * info, size_t info_length,
    uint8_t * output, size_t output_length
) {
    SHA256_CTX context;
    uint8_t hmac_key[SHA256_BLOCK_LENGTH];
    uint8_t step_result[SHA256_OUTPUT_LENGTH];
    size_t bytes_remaining = output_length;
    uint8_t iteration = 1;
    if (!salt) {
        salt = HKDF_DEFAULT_SALT;
        salt_length = sizeof(HKDF_DEFAULT_SALT);
    }
    /* Extract */
    hmac_sha256_key(salt, salt_length, hmac_key);
    hmac_sha256_init(&context, hmac_key);
    sha256_update(&context, input, input_length);
    hmac_sha256_final(&context, hmac_key, step_result);
    hmac_sha256_key(step_result, SHA256_OUTPUT_LENGTH, hmac_key);

    /* Expand */
    hmac_sha256_init(&context, hmac_key);
    sha256_update(&context, info, info_length);
    sha256_update(&context, &iteration, 1);
    hmac_sha256_final(&context, hmac_key, step_result);
    while (bytes_remaining > SHA256_OUTPUT_LENGTH) {
        memcpy(output, step_result, SHA256_OUTPUT_LENGTH);
        output += SHA256_OUTPUT_LENGTH;
        bytes_remaining -= SHA256_OUTPUT_LENGTH;
        iteration ++;
        hmac_sha256_init(&context, hmac_key);
        sha256_update(&context, step_result, SHA256_OUTPUT_LENGTH);
        sha256_update(&context, info, info_length);
        sha256_update(&context, &iteration, 1);
        hmac_sha256_final(&context, hmac_key, step_result);
    }
    memcpy(output, step_result, bytes_remaining);
    _OLM_UNSET_VALUE(context);
    _OLM_UNSET_VALUE(hmac_key);
    _OLM_UNSET_VALUE(step_result);
}
