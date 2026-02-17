/* See LICENSE file for copyright and license details. */
#include "libce/cipher.h"
#include "libce/crypto.h"
#include "libce/memory.h"
#include <string.h>
#include <stdint.h>

#define HMAC_KEY_LENGTH 32

typedef struct DerivedKeys {
    _olm_aes256_key aes_key;
    uint8_t mac_key[HMAC_KEY_LENGTH];
    _olm_aes256_iv aes_iv;
} DerivedKeys;


static void derive_keys(
    const uint8_t * kdf_info, size_t kdf_info_length,
    const uint8_t * key, size_t key_length,
    DerivedKeys *keys
) {
    uint8_t derived_secrets[
        AES256_KEY_LENGTH + HMAC_KEY_LENGTH + AES256_IV_LENGTH
    ];
    _olm_crypto_hkdf_sha256(
        key, key_length,
        NULL, 0,
        kdf_info, kdf_info_length,
        derived_secrets, sizeof(derived_secrets)
    );
    const uint8_t * pos = derived_secrets;
    pos = _OLM_LOAD_ARRAY(keys->aes_key.key, pos);
    pos = _OLM_LOAD_ARRAY(keys->mac_key, pos);
    pos = _OLM_LOAD_ARRAY(keys->aes_iv.iv, pos);
    _OLM_UNSET_VALUE(derived_secrets);
}

static const size_t MAC_LENGTH = 8;

size_t aes_sha_256_cipher_mac_length(const _olm_cipher *cipher) {
    return MAC_LENGTH;
}

size_t aes_sha_256_cipher_encrypt_ciphertext_length(
        const _olm_cipher *cipher, size_t plaintext_length
) {
    return _olm_crypto_aes_encrypt_cbc_length(plaintext_length);
}

size_t aes_sha_256_cipher_encrypt(
    const _olm_cipher *cipher,
    const uint8_t * key, size_t key_length,
    const uint8_t * plaintext, size_t plaintext_length,
    uint8_t * ciphertext, size_t ciphertext_length,
    uint8_t * output, size_t output_length
) {
    const _olm_cipher_aes_sha_256 * c = (const _olm_cipher_aes_sha_256 *)cipher;

    if (ciphertext_length
            < aes_sha_256_cipher_encrypt_ciphertext_length(cipher, plaintext_length)
            || output_length < MAC_LENGTH) {
        return SIZE_MAX;
    }

    DerivedKeys keys;
    uint8_t mac[SHA256_OUTPUT_LENGTH];

    derive_keys(c->kdf_info, c->kdf_info_length, key, key_length, &keys);

    _olm_crypto_aes_encrypt_cbc(
        &keys.aes_key, &keys.aes_iv, plaintext, plaintext_length, ciphertext
    );

    _olm_crypto_hmac_sha256(
        keys.mac_key, HMAC_KEY_LENGTH, output, output_length - MAC_LENGTH, mac
    );

    memcpy(output + output_length - MAC_LENGTH, mac, MAC_LENGTH);

    _OLM_UNSET_VALUE(keys);
    return output_length;
}


size_t aes_sha_256_cipher_decrypt_max_plaintext_length(
    const _olm_cipher *cipher,
    size_t ciphertext_length
) {
    return ciphertext_length;
}

size_t aes_sha_256_cipher_decrypt(
    const _olm_cipher *cipher,
    const uint8_t * key, size_t key_length,
    const uint8_t * input, size_t input_length,
    const uint8_t * ciphertext, size_t ciphertext_length,
    uint8_t * plaintext, size_t max_plaintext_length
) {
    if (max_plaintext_length
            < aes_sha_256_cipher_decrypt_max_plaintext_length(cipher, ciphertext_length)
            || input_length < MAC_LENGTH) {
        return SIZE_MAX;
    }

    const _olm_cipher_aes_sha_256 *c = (const _olm_cipher_aes_sha_256 *)cipher;

    DerivedKeys keys;
    uint8_t mac[SHA256_OUTPUT_LENGTH];

    derive_keys(c->kdf_info, c->kdf_info_length, key, key_length, &keys);

    _olm_crypto_hmac_sha256(
        keys.mac_key, HMAC_KEY_LENGTH, input, input_length - MAC_LENGTH, mac
    );

    const uint8_t * input_mac = input + input_length - MAC_LENGTH;
    if (!_olm_is_equal(input_mac, mac, MAC_LENGTH)) {
        _OLM_UNSET_VALUE(keys);
        return SIZE_MAX;
    }

    size_t plaintext_length = _olm_crypto_aes_decrypt_cbc(
        &keys.aes_key, &keys.aes_iv, ciphertext, ciphertext_length, plaintext
    );

    _OLM_UNSET_VALUE(keys);
    return plaintext_length;
}

const _olm_cipher_ops _olm_cipher_aes_sha_256_ops = {
  aes_sha_256_cipher_mac_length,
  aes_sha_256_cipher_encrypt_ciphertext_length,
  aes_sha_256_cipher_encrypt,
  aes_sha_256_cipher_decrypt_max_plaintext_length,
  aes_sha_256_cipher_decrypt,
};
