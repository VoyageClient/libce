/* See LICENSE file for copyright and license details. */
#ifndef OLM_RATCHET_H_
#define OLM_RATCHET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libce/crypto.h"
#include "libce/error.h"
#include "libce/list.h"

// Note: exports in this file are only for unit tests. Nobody else should be
// using this externally.
#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _olm_cipher _olm_cipher;

/** length of a shared key: the root key R(i), chain key C(i,j), and message
 * key M(i,j). */
#define OLM_SHARED_KEY_LENGTH SHA256_OUTPUT_LENGTH

typedef uint8_t _OlmSharedKey[OLM_SHARED_KEY_LENGTH];

typedef struct _OlmChainKey {
    uint32_t index;
    _OlmSharedKey key;
} _OlmChainKey;

typedef struct _OlmMessageKey {
    uint32_t index;
    _OlmSharedKey key;
} _OlmMessageKey;

typedef struct _OlmSenderChain {
    _olm_curve25519_key_pair ratchet_key;
    _OlmChainKey chain_key;
} _OlmSenderChain;

typedef struct _OlmReceiverChain {
    _olm_curve25519_public_key ratchet_key;
    _OlmChainKey chain_key;
} _OlmReceiverChain;

typedef struct _OlmSkippedMessageKey {
    _olm_curve25519_public_key ratchet_key;
    _OlmMessageKey message_key;
} _OlmSkippedMessageKey;

#define OLM_MAX_RECEIVER_CHAINS 5
#define OLM_MAX_SKIPPED_MESSAGE_KEYS 40

typedef OLM_LIST(_OlmSenderChain, 1) _OlmSenderChainList;
typedef OLM_LIST(_OlmReceiverChain, OLM_MAX_RECEIVER_CHAINS) _OlmReceiverChainList;
typedef OLM_LIST(
    _OlmSkippedMessageKey, OLM_MAX_SKIPPED_MESSAGE_KEYS
) _OlmSkippedMessageKeyList;

typedef struct _OlmKdfInfo {
    uint8_t const *root_info;
    size_t root_info_length;
    uint8_t const *ratchet_info;
    size_t ratchet_info_length;
} _OlmKdfInfo;

typedef struct _OlmRatchet {
    /** Strings identifying the application to feed into the KDF. */
    _OlmKdfInfo const *kdf_info;

    /** The AEAD cipher to use for encrypting messages. */
    _olm_cipher const *ratchet_cipher;

    /** The last error that happened encrypting or decrypting a message. */
    OlmErrorCode last_error;

    /** The root key is used to generate chain keys from ephemeral keys. */
    _OlmSharedKey root_key;

    /** Sender chains for outbound messages. */
    _OlmSenderChainList sender_chain;

    /** Receiver chains for inbound messages. */
    _OlmReceiverChainList receiver_chains;

    /** Message keys skipped while advancing receiver chains. */
    _OlmSkippedMessageKeyList skipped_message_keys;
} _OlmRatchet;

CE_EXPORT void _olm_ratchet_init(
    _OlmRatchet *ratchet,
    _OlmKdfInfo const *kdf_info,
    _olm_cipher const *ratchet_cipher
);

CE_EXPORT void _olm_ratchet_initialise_as_bob(
    _OlmRatchet *ratchet,
    uint8_t const *shared_secret, size_t shared_secret_length,
    _olm_curve25519_public_key const *their_ratchet_key
);

CE_EXPORT void _olm_ratchet_initialise_as_alice(
    _OlmRatchet *ratchet,
    uint8_t const *shared_secret, size_t shared_secret_length,
    _olm_curve25519_key_pair const *our_ratchet_key
);

CE_EXPORT size_t _olm_ratchet_encrypt_output_length(
    _OlmRatchet const *ratchet,
    size_t plaintext_length
);

CE_EXPORT size_t _olm_ratchet_encrypt_random_length(
    _OlmRatchet const *ratchet
);

CE_EXPORT size_t _olm_ratchet_encrypt(
    _OlmRatchet *ratchet,
    uint8_t const *plaintext, size_t plaintext_length,
    uint8_t const *random, size_t random_length,
    uint8_t *output, size_t max_output_length
);

CE_EXPORT size_t _olm_ratchet_decrypt_max_plaintext_length(
    _OlmRatchet *ratchet,
    uint8_t const *input, size_t input_length
);

CE_EXPORT size_t _olm_ratchet_decrypt(
    _OlmRatchet *ratchet,
    uint8_t const *input, size_t input_length,
    uint8_t *plaintext, size_t max_plaintext_length
);

CE_EXPORT size_t _olm_ratchet_pickle_length(
    _OlmRatchet const *ratchet
);

CE_EXPORT uint8_t * _olm_ratchet_pickle(
    uint8_t *pos,
    _OlmRatchet const *ratchet
);

CE_EXPORT uint8_t const * _olm_ratchet_unpickle(
    uint8_t const *pos, uint8_t const *end,
    _OlmRatchet *ratchet,
    bool includes_chain_index
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_RATCHET_H_ */
