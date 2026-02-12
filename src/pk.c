/* See LICENSE file for copyright and license details. */
#include "libce/pk.h"

#include <string.h>

#include "libce/base64.h"
#include "libce/cipher.h"
#include "libce/crypto.h"
#include "libce/error.h"
#include "libce/memory.h"
#include "libce/pickle.h"
#include "libce/pickle_encoding.h"
#include "libce/ratchet.h"

#define PK_MAC_LENGTH 8
#define PK_DECRYPTION_PICKLE_VERSION 1

static const _olm_cipher_aes_sha_256 olm_pk_cipher_aes_sha256 =
    OLM_CIPHER_INIT_AES_SHA_256("");
static const _olm_cipher *olm_pk_cipher =
    OLM_CIPHER_BASE(&olm_pk_cipher_aes_sha256);


typedef struct OlmPkEncryption {
    OlmErrorCode last_error;
    _olm_curve25519_public_key recipient_key;
} OlmPkEncryption;


const char * olm_pk_encryption_last_error(
    const OlmPkEncryption *encryption
) {
    return _olm_error_to_string(encryption->last_error);
}


OlmErrorCode olm_pk_encryption_last_error_code(
    const OlmPkEncryption *encryption
) {
    return encryption->last_error;
}


size_t olm_pk_encryption_size(void) {
    return sizeof(OlmPkEncryption);
}


OlmPkEncryption * olm_pk_encryption(
    void *memory
) {
    _olm_unset(memory, sizeof(OlmPkEncryption));
    return (OlmPkEncryption *) memory;
}


size_t olm_clear_pk_encryption(
    OlmPkEncryption *encryption
) {
    _olm_unset(encryption, sizeof(OlmPkEncryption));
    return sizeof(OlmPkEncryption);
}


size_t olm_pk_encryption_set_recipient_key(
    OlmPkEncryption *encryption,
    void const *key,
    size_t key_length
) {
    if (key_length < olm_pk_key_length()) {
        encryption->last_error = OLM_INPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    _olm_decode_base64(
        (const uint8_t *)key,
        olm_pk_key_length(),
        (uint8_t *)encryption->recipient_key.public_key
    );

    return 0;
}


size_t olm_pk_ciphertext_length(
    size_t plaintext_length
) {
    return _olm_encode_base64_length(
        olm_pk_cipher->ops->encrypt_ciphertext_length(olm_pk_cipher, plaintext_length)
    );
}


size_t olm_pk_mac_length(void) {
    return _olm_encode_base64_length(olm_pk_cipher->ops->mac_length(olm_pk_cipher));
}


size_t olm_pk_encrypt_random_length(void) {
    return CURVE25519_KEY_LENGTH;
}


size_t olm_pk_encrypt(
    OlmPkEncryption *encryption,
    void const *plaintext,
    size_t plaintext_length,
    void *ciphertext,
    size_t ciphertext_length,
    void *mac,
    size_t mac_length,
    void *ephemeral_key,
    size_t ephemeral_key_size,
    const void *random,
    size_t random_length
) {
    if (ciphertext_length < olm_pk_ciphertext_length(plaintext_length)
            || mac_length < olm_pk_mac_length()
            || ephemeral_key_size < olm_pk_key_length()) {
        encryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    if (random_length < olm_pk_encrypt_random_length()) {
        encryption->last_error = OLM_NOT_ENOUGH_RANDOM;
        return (size_t)-1;
    }

    _olm_curve25519_key_pair ephemeral_keypair;
    _olm_crypto_curve25519_generate_key((const uint8_t *) random, &ephemeral_keypair);

    _olm_encode_base64(
        (const uint8_t *)ephemeral_keypair.public_key.public_key,
        CURVE25519_KEY_LENGTH,
        (uint8_t *)ephemeral_key
    );

    _OlmSharedKey secret;
    size_t raw_ciphertext_length;
    uint8_t *ciphertext_pos;
    uint8_t raw_mac[PK_MAC_LENGTH];
    size_t result;

    _olm_crypto_curve25519_shared_secret(&ephemeral_keypair, &encryption->recipient_key, secret);

    raw_ciphertext_length = olm_pk_cipher->ops->encrypt_ciphertext_length(
        olm_pk_cipher,
        plaintext_length
    );

    ciphertext_pos =
        (uint8_t *) ciphertext + ciphertext_length - raw_ciphertext_length;

    result = olm_pk_cipher->ops->encrypt(
        olm_pk_cipher,
        secret,
        sizeof(secret),
        (const uint8_t *) plaintext,
        plaintext_length,
        ciphertext_pos,
        raw_ciphertext_length,
        raw_mac,
        PK_MAC_LENGTH
    );

    if (result != (size_t)-1) {
        _olm_encode_base64(raw_mac, PK_MAC_LENGTH, (uint8_t *)mac);
        _olm_encode_base64(ciphertext_pos, raw_ciphertext_length, (uint8_t *)ciphertext);
    }

    return result;
}


typedef struct OlmPkDecryption {
    OlmErrorCode last_error;
    _olm_curve25519_key_pair key_pair;
} OlmPkDecryption;


const char * olm_pk_decryption_last_error(
    const OlmPkDecryption *decryption
) {
    return _olm_error_to_string(decryption->last_error);
}


OlmErrorCode olm_pk_decryption_last_error_code(
    const OlmPkDecryption *decryption
) {
    return decryption->last_error;
}


size_t olm_pk_decryption_size(void) {
    return sizeof(OlmPkDecryption);
}


OlmPkDecryption * olm_pk_decryption(
    void *memory
) {
    _olm_unset(memory, sizeof(OlmPkDecryption));
    return (OlmPkDecryption *) memory;
}


size_t olm_clear_pk_decryption(
    OlmPkDecryption *decryption
) {
    _olm_unset(decryption, sizeof(OlmPkDecryption));
    return sizeof(OlmPkDecryption);
}


size_t olm_pk_private_key_length(void) {
    return CURVE25519_KEY_LENGTH;
}


size_t olm_pk_generate_key_random_length(void) {
    return olm_pk_private_key_length();
}


size_t olm_pk_key_length(void) {
    return _olm_encode_base64_length(CURVE25519_KEY_LENGTH);
}


size_t olm_pk_key_from_private(
    OlmPkDecryption *decryption,
    void *pubkey,
    size_t pubkey_length,
    const void *privkey,
    size_t privkey_length
) {
    if (pubkey_length < olm_pk_key_length()) {
        decryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    if (privkey_length < olm_pk_private_key_length()) {
        decryption->last_error = OLM_INPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    _olm_crypto_curve25519_generate_key(
        (const uint8_t *) privkey,
        &decryption->key_pair
    );

    _olm_encode_base64(
        (const uint8_t *)decryption->key_pair.public_key.public_key,
        CURVE25519_KEY_LENGTH,
        (uint8_t *)pubkey
    );

    return 0;
}


size_t olm_pk_generate_key(
    OlmPkDecryption *decryption,
    void *pubkey,
    size_t pubkey_length,
    const void *privkey,
    size_t privkey_length
) {
    return olm_pk_key_from_private(
        decryption,
        pubkey,
        pubkey_length,
        privkey,
        privkey_length
    );
}


static size_t raw_pickle_length(
    const OlmPkDecryption *decryption
) {
    size_t length = 0;

    length += _OLM_PICKLE_UINT32_LENGTH(PK_DECRYPTION_PICKLE_VERSION);
    length += _olm_pickle_curve25519_key_pair_length(&decryption->key_pair);

    return length;
}


static uint8_t * pickle_pk_decryption(
    uint8_t *pos,
    const OlmPkDecryption *decryption
) {
    pos = _olm_pickle_uint32(pos, PK_DECRYPTION_PICKLE_VERSION);
    pos = _olm_pickle_curve25519_key_pair(pos, &decryption->key_pair);
    return pos;
}


static const uint8_t * unpickle_pk_decryption(
    const uint8_t *pos,
    const uint8_t *end,
    OlmPkDecryption *decryption
) {
    uint32_t pickle_version;

    pos = _olm_unpickle_uint32(pos, end, &pickle_version);
    UNPICKLE_OK(pos);

    if (pickle_version != PK_DECRYPTION_PICKLE_VERSION) {
        decryption->last_error = OLM_UNKNOWN_PICKLE_VERSION;
        return NULL;
    }

    pos = _olm_unpickle_curve25519_key_pair(pos, end, &decryption->key_pair);
    UNPICKLE_OK(pos);

    return pos;
}


size_t olm_pickle_pk_decryption_length(
    const OlmPkDecryption *decryption
) {
    return _olm_enc_output_length(raw_pickle_length(decryption));
}


size_t olm_pickle_pk_decryption(
    OlmPkDecryption *decryption,
    void const *key,
    size_t key_length,
    void *pickled,
    size_t pickled_length
) {
    size_t raw_length;

    raw_length = raw_pickle_length(decryption);

    if (pickled_length < _olm_enc_output_length(raw_length)) {
        decryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    pickle_pk_decryption(
        _olm_enc_output_pos((uint8_t *)pickled, raw_length),
        decryption
    );

    return _olm_enc_output(
        (const uint8_t *)key,
        key_length,
        (uint8_t *)pickled,
        raw_length
    );
}


size_t olm_unpickle_pk_decryption(
    OlmPkDecryption *decryption,
    void const *key,
    size_t key_length,
    void *pickled,
    size_t pickled_length,
    void *pubkey,
    size_t pubkey_length
) {
    uint8_t *input;
    size_t raw_length;
    const uint8_t *pos;
    const uint8_t *end;

    if (pubkey != NULL && pubkey_length < olm_pk_key_length()) {
        decryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    input = (uint8_t *) pickled;

    raw_length = _olm_enc_input(
        (const uint8_t *)key,
        key_length,
        input,
        pickled_length,
        &decryption->last_error
    );

    if (raw_length == (size_t)-1) {
        return (size_t)-1;
    }

    pos = input;
    end = pos + raw_length;

    pos = unpickle_pk_decryption(pos, end, decryption);

    if (!pos) {
        if (decryption->last_error == OLM_SUCCESS) {
            decryption->last_error = OLM_CORRUPTED_PICKLE;
        }
        return (size_t)-1;
    }

    if (pos != end) {
        decryption->last_error = OLM_PICKLE_EXTRA_DATA;
        return (size_t)-1;
    }

    if (pubkey != NULL) {
        _olm_encode_base64(
            (const uint8_t *)decryption->key_pair.public_key.public_key,
            CURVE25519_KEY_LENGTH,
            (uint8_t *)pubkey
        );
    }

    return pickled_length;
}


size_t olm_pk_max_plaintext_length(
    size_t ciphertext_length
) {
    return olm_pk_cipher->ops->decrypt_max_plaintext_length(
        olm_pk_cipher,
        _olm_decode_base64_length(ciphertext_length)
    );
}


size_t olm_pk_decrypt(
    OlmPkDecryption *decryption,
    void const *ephemeral_key,
    size_t ephemeral_key_length,
    void const *mac,
    size_t mac_length,
    void *ciphertext,
    size_t ciphertext_length,
    void *plaintext,
    size_t max_plaintext_length
) {
    size_t raw_ciphertext_length;
    _olm_curve25519_public_key ephemeral;
    _OlmSharedKey secret;
    uint8_t raw_mac[PK_MAC_LENGTH];
    size_t result;

    if (max_plaintext_length < olm_pk_max_plaintext_length(ciphertext_length)) {
        decryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    raw_ciphertext_length = _olm_decode_base64_length(ciphertext_length);

    if (ephemeral_key_length != _olm_encode_base64_length(CURVE25519_KEY_LENGTH)
            || mac_length != _olm_encode_base64_length(PK_MAC_LENGTH)
            || raw_ciphertext_length == (size_t)-1) {
        decryption->last_error = OLM_INVALID_BASE64;
        return (size_t)-1;
    }

    _olm_decode_base64(
        (const uint8_t *)ephemeral_key,
        _olm_encode_base64_length(CURVE25519_KEY_LENGTH),
        (uint8_t *)ephemeral.public_key
    );

    _olm_crypto_curve25519_shared_secret(&decryption->key_pair, &ephemeral, secret);

    _olm_decode_base64(
        (const uint8_t *)mac,
        _olm_encode_base64_length(PK_MAC_LENGTH),
        raw_mac
    );

    _olm_decode_base64(
        (const uint8_t *)ciphertext,
        ciphertext_length,
        (uint8_t *)ciphertext
    );

    result = olm_pk_cipher->ops->decrypt(
        olm_pk_cipher,
        secret,
        sizeof(secret),
        raw_mac,
        PK_MAC_LENGTH,
        (const uint8_t *)ciphertext,
        raw_ciphertext_length,
        (uint8_t *)plaintext,
        max_plaintext_length
    );

    if (result == (size_t)-1) {
        decryption->last_error = OLM_BAD_MESSAGE_MAC;
    }

    return result;
}


size_t olm_pk_get_private_key(
    OlmPkDecryption *decryption,
    void *private_key,
    size_t private_key_length
) {
    if (private_key_length < olm_pk_private_key_length()) {
        decryption->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    memcpy(
        private_key,
        decryption->key_pair.private_key.private_key,
        olm_pk_private_key_length()
    );

    return olm_pk_private_key_length();
}


typedef struct OlmPkSigning {
    OlmErrorCode last_error;
    _olm_ed25519_key_pair key_pair;
} OlmPkSigning;


size_t olm_pk_signing_size(void) {
    return sizeof(OlmPkSigning);
}


OlmPkSigning * olm_pk_signing(
    void *memory
) {
    _olm_unset(memory, sizeof(OlmPkSigning));
    return (OlmPkSigning *) memory;
}


const char * olm_pk_signing_last_error(
    const OlmPkSigning *sign
) {
    return _olm_error_to_string(sign->last_error);
}


OlmErrorCode olm_pk_signing_last_error_code(
    const OlmPkSigning *sign
) {
    return sign->last_error;
}


size_t olm_clear_pk_signing(
    OlmPkSigning *sign
) {
    _olm_unset(sign, sizeof(OlmPkSigning));
    return sizeof(OlmPkSigning);
}


size_t olm_pk_signing_seed_length(void) {
    return ED25519_RANDOM_LENGTH;
}


size_t olm_pk_signing_public_key_length(void) {
    return _olm_encode_base64_length(ED25519_PUBLIC_KEY_LENGTH);
}


size_t olm_pk_signing_key_from_seed(
    OlmPkSigning *signing,
    void *pubkey,
    size_t pubkey_length,
    const void *seed,
    size_t seed_length
) {
    if (pubkey_length < olm_pk_signing_public_key_length()) {
        signing->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    if (seed_length < olm_pk_signing_seed_length()) {
        signing->last_error = OLM_INPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    _olm_crypto_ed25519_generate_key((const uint8_t *) seed, &signing->key_pair);

    _olm_encode_base64(
        (const uint8_t *)signing->key_pair.public_key.public_key,
        ED25519_PUBLIC_KEY_LENGTH,
        (uint8_t *)pubkey
    );

    return 0;
}


size_t olm_pk_signature_length(void) {
    return _olm_encode_base64_length(ED25519_SIGNATURE_LENGTH);
}


size_t olm_pk_sign(
    OlmPkSigning *signing,
    const uint8_t *message,
    size_t message_length,
    uint8_t *signature,
    size_t signature_length
) {
    uint8_t *raw_sig;

    if (signature_length < olm_pk_signature_length()) {
        signing->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return (size_t)-1;
    }

    raw_sig = signature + olm_pk_signature_length() - ED25519_SIGNATURE_LENGTH;

    _olm_crypto_ed25519_sign(
        &signing->key_pair,
        message,
        message_length,
        raw_sig
    );

    _olm_encode_base64(raw_sig, ED25519_SIGNATURE_LENGTH, signature);

    return olm_pk_signature_length();
}
