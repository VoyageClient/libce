/* See LICENSE file for copyright and license details. */
#include "libce/crypto.h"

#include "crypto-algorithms/aes.h"
#include "libce/memory.h"

#include <sodium.h>
#include <stdlib.h>

static const size_t AES_KEY_SCHEDULE_LENGTH = 60;
static const size_t AES_KEY_BITS = 8 * AES256_KEY_LENGTH;
static const size_t AES_BLOCK_LENGTH = 16;


inline static void ensure_sodium(void) {
    if (sodium_init() == -1) {
        abort();
    }
}


/* The stored scalar is clamped (>= 2^254), which exceeds the group order L
 * that sodium's scalar functions require. B has order L, so reducing first
 * yields the same point. */
inline static void reduce_scalar(
    uint8_t reduced[crypto_core_ed25519_SCALARBYTES],
    const uint8_t * scalar
) {
    uint8_t padded[crypto_core_ed25519_NONREDUCEDSCALARBYTES] = {0};
    memcpy(padded, scalar, 32);
    crypto_core_ed25519_scalar_reduce(reduced, padded);
    _OLM_UNSET_VALUE(padded);
}


inline static void xor_block(
    uint8_t * block, size_t block_length,
    const uint8_t * input
) {
    for (size_t i = 0; i < block_length; ++i) {
        block[i] ^= input[i];
    }
}


void _olm_crypto_curve25519_generate_key(
    const uint8_t * random_32_bytes,
    _olm_curve25519_key_pair *key_pair
) {
    ensure_sodium();
    memcpy(
        key_pair->private_key.private_key, random_32_bytes,
        CURVE25519_KEY_LENGTH
    );
    crypto_scalarmult_curve25519_base(
        key_pair->public_key.public_key,
        key_pair->private_key.private_key
    );
}


void _olm_crypto_curve25519_shared_secret(
    const _olm_curve25519_key_pair *our_key,
    const _olm_curve25519_public_key * their_key,
    uint8_t * output
) {
    ensure_sodium();
    /* sodium returns -1 for small-order peer keys but still writes the
     * all-zero secret; the protocol's MACs reject anything derived from
     * it, so contributory behavior is not required here. */
    (void)crypto_scalarmult_curve25519(
        output, our_key->private_key.private_key, their_key->public_key
    );
}


void _olm_crypto_ed25519_generate_key(
    const uint8_t * random_32_bytes,
    _olm_ed25519_key_pair *key_pair
) {
    uint8_t reduced[crypto_core_ed25519_SCALARBYTES];
    ensure_sodium();
    /* Expanded-key format (clamped SHA-512 of the seed) kept for
     * compatibility with existing pickles. */
    crypto_hash_sha512(
        key_pair->private_key.private_key, random_32_bytes,
        ED25519_RANDOM_LENGTH
    );
    key_pair->private_key.private_key[0] &= 248;
    key_pair->private_key.private_key[31] &= 63;
    key_pair->private_key.private_key[31] |= 64;
    reduce_scalar(reduced, key_pair->private_key.private_key);
    crypto_scalarmult_ed25519_base_noclamp(
        key_pair->public_key.public_key, reduced
    );
    _OLM_UNSET_VALUE(reduced);
}


void _olm_crypto_ed25519_sign(
    const _olm_ed25519_key_pair *our_key,
    const uint8_t * message, size_t message_length,
    uint8_t * output
) {
    uint8_t hash[crypto_hash_sha512_BYTES];
    uint8_t r[crypto_core_ed25519_SCALARBYTES];
    uint8_t hram[crypto_core_ed25519_SCALARBYTES];
    uint8_t a[crypto_core_ed25519_SCALARBYTES];
    uint8_t s[crypto_core_ed25519_SCALARBYTES];
    crypto_hash_sha512_state state;

    ensure_sodium();

    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(
        &state, our_key->private_key.private_key + 32, 32
    );
    crypto_hash_sha512_update(&state, message, message_length);
    crypto_hash_sha512_final(&state, hash);
    crypto_core_ed25519_scalar_reduce(r, hash);

    crypto_scalarmult_ed25519_base_noclamp(output, r);

    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, output, 32);
    crypto_hash_sha512_update(
        &state, our_key->public_key.public_key, ED25519_PUBLIC_KEY_LENGTH
    );
    crypto_hash_sha512_update(&state, message, message_length);
    crypto_hash_sha512_final(&state, hash);
    crypto_core_ed25519_scalar_reduce(hram, hash);

    reduce_scalar(a, our_key->private_key.private_key);
    crypto_core_ed25519_scalar_mul(s, hram, a);
    crypto_core_ed25519_scalar_add(output + 32, s, r);

    _OLM_UNSET_VALUE(state);
    _OLM_UNSET_VALUE(hash);
    _OLM_UNSET_VALUE(r);
    _OLM_UNSET_VALUE(hram);
    _OLM_UNSET_VALUE(a);
    _OLM_UNSET_VALUE(s);
}


int _olm_crypto_ed25519_verify(
    const _olm_ed25519_public_key *their_key,
    const uint8_t * message, size_t message_length,
    const uint8_t * signature
) {
    ensure_sodium();
    return 0 == crypto_sign_ed25519_verify_detached(
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
    const _olm_aes256_key *key,
    const _olm_aes256_iv *iv,
    const uint8_t * input, size_t input_length,
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
    const _olm_aes256_key *key,
    const _olm_aes256_iv *iv,
    const uint8_t * input, size_t input_length,
    uint8_t * output
) {
    if (input_length == 0 || input_length % AES_BLOCK_LENGTH != 0) {
        return SIZE_MAX;
    }
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
    const uint8_t * input, size_t input_length,
    uint8_t * output
) {
    ensure_sodium();
    crypto_hash_sha256(output, input, input_length);
}


void _olm_crypto_hmac_sha256(
    const uint8_t * key, size_t key_length,
    const uint8_t * input, size_t input_length,
    uint8_t * output
) {
    crypto_auth_hmacsha256_state state;
    ensure_sodium();
    crypto_auth_hmacsha256_init(&state, key, key_length);
    crypto_auth_hmacsha256_update(&state, input, input_length);
    crypto_auth_hmacsha256_final(&state, output);
    _OLM_UNSET_VALUE(state);
}


void _olm_crypto_hkdf_sha256(
    const uint8_t * input, size_t input_length,
    const uint8_t * salt, size_t salt_length,
    const uint8_t * info, size_t info_length,
    uint8_t * output, size_t output_length
) {
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    ensure_sodium();
    crypto_kdf_hkdf_sha256_extract(
        prk, salt, salt_length, input, input_length
    );
    crypto_kdf_hkdf_sha256_expand(
        output, output_length, (const char *) info, info_length, prk
    );
    _OLM_UNSET_VALUE(prk);
}
