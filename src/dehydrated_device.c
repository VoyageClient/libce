/* See LICENSE file for copyright and license details. */
#include "libce/dehydrated_device.h"

#include "libce/memory.h"

#include <sodium.h>

/* MSC3814 pickle version; unrelated to the libolm account pickle version. */
enum { DEHYDRATED_DEVICE_PICKLE_VERSION = 1 };

static size_t pickle_length(const OlmAccount * account) {
    size_t length = 4; /* version */
    length += CURVE25519_KEY_LENGTH;
    length += ED25519_RANDOM_LENGTH;
    length += 4; /* one time key count */
    length += _olm_list_size(&account->one_time_keys) * CURVE25519_KEY_LENGTH;
    length += 1; /* fallback key present */
    if (account->num_fallback_keys >= 1) {
        length += CURVE25519_KEY_LENGTH;
    }
    return length;
}

static uint8_t * store_u32(uint8_t * pos, uint32_t value) {
    *(pos++) = (uint8_t)(value >> 24);
    *(pos++) = (uint8_t)(value >> 16);
    *(pos++) = (uint8_t)(value >> 8);
    *(pos++) = (uint8_t)value;
    return pos;
}

static const uint8_t * load_u32(const uint8_t * pos, uint32_t * value) {
    *value = ((uint32_t)pos[0] << 24) | ((uint32_t)pos[1] << 16)
            | ((uint32_t)pos[2] << 8) | (uint32_t)pos[3];
    return pos + 4;
}

static void pickle(const OlmAccount * account, uint8_t * pos) {
    const _OlmOneTimeKey * key;

    pos = store_u32(pos, DEHYDRATED_DEVICE_PICKLE_VERSION);
    pos = _OLM_STORE_ARRAY(pos, account->identity_keys.curve25519_key.private_key.private_key);
    pos = _OLM_STORE_ARRAY(pos, account->ed25519_seed);
    pos = store_u32(pos, (uint32_t)_olm_list_size(&account->one_time_keys));
    /* Our list runs newest first; the pickle stores keys in key id order. */
    for (key = _olm_list_end(&account->one_time_keys);
            key != _olm_list_begin(&account->one_time_keys); ) {
        pos = _OLM_STORE_ARRAY(pos, (--key)->key.private_key.private_key);
    }
    if (account->num_fallback_keys >= 1) {
        *(pos++) = 1;
        _OLM_STORE_ARRAY(pos, account->current_fallback_key.key.private_key.private_key);
    } else {
        *pos = 0;
    }
}

static size_t unpickle(
    OlmAccount * account,
    const uint8_t * pos, size_t length
) {
    const uint8_t * end = pos + length;
    uint32_t version;
    uint32_t count;
    uint32_t i;

    if (length < 4 + CURVE25519_KEY_LENGTH + ED25519_RANDOM_LENGTH + 4 + 1) {
        account->last_error = OLM_CORRUPTED_PICKLE;
        return SIZE_MAX;
    }

    pos = load_u32(pos, &version);
    if (version != DEHYDRATED_DEVICE_PICKLE_VERSION) {
        account->last_error = OLM_UNKNOWN_PICKLE_VERSION;
        return SIZE_MAX;
    }

    _olm_crypto_curve25519_generate_key(pos, &account->identity_keys.curve25519_key);
    pos += CURVE25519_KEY_LENGTH;
    _olm_crypto_ed25519_generate_key(pos, &account->identity_keys.ed25519_key);
    _OLM_LOAD_ARRAY(account->ed25519_seed, pos);
    account->ed25519_seed_known = true;
    pos += ED25519_RANDOM_LENGTH;

    pos = load_u32(pos, &count);
    if (count > MAX_ONE_TIME_KEYS
            || (size_t)(end - pos) < (size_t)count * CURVE25519_KEY_LENGTH + 1) {
        account->last_error = OLM_CORRUPTED_PICKLE;
        return SIZE_MAX;
    }

    for (i = 0; i < count; ++i) {
        _OlmOneTimeKey * key = _olm_list_insert_front(&account->one_time_keys);
        key->id = i + 1;
        key->published = true;
        _olm_crypto_curve25519_generate_key(pos, &key->key);
        pos += CURVE25519_KEY_LENGTH;
    }
    account->next_one_time_key_id = count;

    if (*(pos++)) {
        if ((size_t)(end - pos) < CURVE25519_KEY_LENGTH) {
            account->last_error = OLM_CORRUPTED_PICKLE;
            return SIZE_MAX;
        }
        account->num_fallback_keys = 1;
        account->current_fallback_key.id = ++account->next_one_time_key_id;
        account->current_fallback_key.published = true;
        _olm_crypto_curve25519_generate_key(pos, &account->current_fallback_key.key);
        pos += CURVE25519_KEY_LENGTH;
    }

    if (pos != end) {
        account->last_error = OLM_PICKLE_EXTRA_DATA;
        return SIZE_MAX;
    }

    return 0;
}

size_t _olm_account_dehydrate_length(
    const OlmAccount * account
) {
    return pickle_length(account) + crypto_aead_chacha20poly1305_ietf_ABYTES;
}

size_t _olm_account_dehydrate(
    OlmAccount * account,
    const uint8_t * key, size_t key_length,
    const uint8_t * nonce, size_t nonce_length,
    uint8_t * ciphertext, size_t ciphertext_length
) {
    size_t plaintext_length = pickle_length(account);
    uint8_t plaintext[4 + CURVE25519_KEY_LENGTH + ED25519_RANDOM_LENGTH + 4
            + MAX_ONE_TIME_KEYS * CURVE25519_KEY_LENGTH + 1 + CURVE25519_KEY_LENGTH];
    unsigned long long written;
    int result;

    if (!account->ed25519_seed_known) {
        account->last_error = OLM_UNSEEDED_ACCOUNT;
        return SIZE_MAX;
    }

    if (key_length != DEHYDRATED_DEVICE_KEY_LENGTH || nonce_length != DEHYDRATED_DEVICE_NONCE_LENGTH) {
        account->last_error = OLM_BAD_ACCOUNT_KEY;
        return SIZE_MAX;
    }

    if (ciphertext_length < _olm_account_dehydrate_length(account)) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    if (sodium_init() == -1) {
        account->last_error = OLM_CORRUPTED_PICKLE;
        return SIZE_MAX;
    }

    pickle(account, plaintext);
    result = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &written,
        plaintext, plaintext_length,
        NULL, 0,
        NULL, nonce, key
    );
    _olm_unset(plaintext, sizeof(plaintext));

    if (result != 0) {
        account->last_error = OLM_BAD_ACCOUNT_KEY;
        return SIZE_MAX;
    }

    return (size_t)written;
}

size_t _olm_account_rehydrate(
    OlmAccount * account,
    const uint8_t * key, size_t key_length,
    const uint8_t * nonce, size_t nonce_length,
    const uint8_t * ciphertext, size_t ciphertext_length
) {
    uint8_t plaintext[4 + CURVE25519_KEY_LENGTH + ED25519_RANDOM_LENGTH + 4
            + MAX_ONE_TIME_KEYS * CURVE25519_KEY_LENGTH + 1 + CURVE25519_KEY_LENGTH];
    unsigned long long written;
    size_t result;

    _olm_account_init(account);

    if (key_length != DEHYDRATED_DEVICE_KEY_LENGTH || nonce_length != DEHYDRATED_DEVICE_NONCE_LENGTH) {
        account->last_error = OLM_BAD_ACCOUNT_KEY;
        return SIZE_MAX;
    }

    if (ciphertext_length < crypto_aead_chacha20poly1305_ietf_ABYTES
            || ciphertext_length - crypto_aead_chacha20poly1305_ietf_ABYTES > sizeof(plaintext)) {
        account->last_error = OLM_CORRUPTED_PICKLE;
        return SIZE_MAX;
    }

    if (sodium_init() == -1) {
        account->last_error = OLM_CORRUPTED_PICKLE;
        return SIZE_MAX;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &written,
            NULL,
            ciphertext, ciphertext_length,
            NULL, 0,
            nonce, key
    ) != 0) {
        account->last_error = OLM_BAD_MESSAGE_MAC;
        return SIZE_MAX;
    }

    result = unpickle(account, plaintext, (size_t)written);
    _olm_unset(plaintext, sizeof(plaintext));
    return result;
}
