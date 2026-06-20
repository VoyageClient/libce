/* See LICENSE file for copyright and license details. */
#ifndef OLM_RATCHET_H_
#define OLM_RATCHET_H_

#include "libce/crypto.h"
#include "libce/error.h"
#include "libce/list.h"

#include <stdbool.h>

// Note: exports in this file are only for unit tests. Nobody else should be
// using this externally.
#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OLM_TYPEDEF__olm_cipher
#define OLM_TYPEDEF__olm_cipher
typedef struct _olm_cipher _olm_cipher;
#endif

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
    const uint8_t *root_info;
    size_t root_info_length;
    const uint8_t *ratchet_info;
    size_t ratchet_info_length;
} _OlmKdfInfo;

typedef struct _OlmRatchet {
    /** Strings identifying the application to feed into the KDF. */
    const _OlmKdfInfo *kdf_info;

    /** The AEAD cipher to use for encrypting messages. */
    const _olm_cipher *ratchet_cipher;

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
    const _OlmKdfInfo *kdf_info,
    const _olm_cipher *ratchet_cipher
);

CE_EXPORT void _olm_ratchet_initialise_as_bob(
    _OlmRatchet *ratchet,
    const uint8_t *shared_secret, size_t shared_secret_length,
    const _olm_curve25519_public_key *their_ratchet_key
);

CE_EXPORT void _olm_ratchet_initialise_as_alice(
    _OlmRatchet *ratchet,
    const uint8_t *shared_secret, size_t shared_secret_length,
    const _olm_curve25519_key_pair *our_ratchet_key
);

CE_EXPORT size_t _olm_ratchet_encrypt_output_length(
    const _OlmRatchet *ratchet,
    size_t plaintext_length
);

CE_EXPORT size_t _olm_ratchet_encrypt_random_length(
    const _OlmRatchet *ratchet
);

CE_EXPORT size_t _olm_ratchet_encrypt(
    _OlmRatchet *ratchet,
    const uint8_t *plaintext, size_t plaintext_length,
    const uint8_t *random, size_t random_length,
    uint8_t *output, size_t max_output_length
);

CE_EXPORT size_t _olm_ratchet_decrypt_max_plaintext_length(
    _OlmRatchet *ratchet,
    const uint8_t *input, size_t input_length
);

CE_EXPORT size_t _olm_ratchet_decrypt(
    _OlmRatchet *ratchet,
    const uint8_t *input, size_t input_length,
    uint8_t *plaintext, size_t max_plaintext_length
);

CE_EXPORT size_t _olm_ratchet_pickle_length(
    const _OlmRatchet *ratchet
);

CE_EXPORT uint8_t * _olm_ratchet_pickle(
    uint8_t *pos,
    const _OlmRatchet *ratchet
);

CE_EXPORT const uint8_t * _olm_ratchet_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmRatchet *ratchet,
    bool includes_chain_index
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_RATCHET_H_ */
