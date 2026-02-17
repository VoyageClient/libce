/* See LICENSE file for copyright and license details. */
#include "libce/ratchet.h"

#include "libce/cipher.h"
#include "libce/memory.h"
#include "libce/message.h"
#include "libce/pickle.h"

static const uint8_t PROTOCOL_VERSION = 3;
static const uint8_t MESSAGE_KEY_SEED[1] = {0x01};
static const uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const size_t MAX_MESSAGE_GAP = 2000;

/**
 * Advance the root key, creating a new message chain.
 *
 * @param root_key            previous root key R(n-1)
 * @param our_key             our new ratchet key T(n)
 * @param their_key           their most recent ratchet key T(n-1)
 * @param info                table of constants for the ratchet function
 * @param new_root_key[out]   returns the new root key R(n)
 * @param new_chain_key[out]  returns the first chain key in the new chain
 *                            C(n,0)
 */
static void create_chain_key(
    const _OlmSharedKey root_key,
    const _olm_curve25519_key_pair *our_key,
    const _olm_curve25519_public_key *their_key,
    const _OlmKdfInfo *info,
    _OlmSharedKey *new_root_key,
    _OlmChainKey *new_chain_key
) {
    _OlmSharedKey secret;
    uint8_t derived_secrets[2 * OLM_SHARED_KEY_LENGTH];
    const uint8_t *pos = derived_secrets;

    _olm_crypto_curve25519_shared_secret(our_key, their_key, secret);
    _olm_crypto_hkdf_sha256(
        secret, sizeof(secret),
        root_key, sizeof(_OlmSharedKey),
        info->ratchet_info, info->ratchet_info_length,
        derived_secrets, sizeof(derived_secrets)
    );

    memcpy(*new_root_key, pos, OLM_SHARED_KEY_LENGTH);
    pos += OLM_SHARED_KEY_LENGTH;
    pos = _OLM_LOAD_ARRAY(new_chain_key->key, pos);
    new_chain_key->index = 0;

    _OLM_UNSET_VALUE(derived_secrets);
    _OLM_UNSET_VALUE(secret);
}

static void advance_chain_key(
    const _OlmChainKey *chain_key,
    _OlmChainKey *new_chain_key
) {
    _olm_crypto_hmac_sha256(
        chain_key->key, sizeof(chain_key->key),
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        new_chain_key->key
    );
    new_chain_key->index = chain_key->index + 1;
}

static void create_message_keys(
    const _OlmChainKey *chain_key,
    _OlmMessageKey *message_key
) {
    _olm_crypto_hmac_sha256(
        chain_key->key, sizeof(chain_key->key),
        MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED),
        message_key->key
    );
    message_key->index = chain_key->index;
}

static size_t verify_mac_and_decrypt(
    const _olm_cipher *cipher,
    const _OlmMessageKey *message_key,
    const _OlmMessageReader *reader,
    uint8_t *plaintext, size_t max_plaintext_length
) {
    return cipher->ops->decrypt(
        cipher,
        message_key->key, sizeof(message_key->key),
        reader->input, reader->input_length,
        reader->ciphertext, reader->ciphertext_length,
        plaintext, max_plaintext_length
    );
}

static size_t verify_mac_and_decrypt_for_existing_chain(
    const _OlmRatchet *ratchet,
    const _OlmChainKey *chain,
    const _OlmMessageReader *reader,
    uint8_t *plaintext, size_t max_plaintext_length
) {
    _OlmChainKey new_chain = *chain;
    _OlmMessageKey message_key;

    if (reader->counter < chain->index) {
        return SIZE_MAX;
    }

    /* Limit the number of hashes we're prepared to compute. */
    if (reader->counter - chain->index > MAX_MESSAGE_GAP) {
        return SIZE_MAX;
    }

    while (new_chain.index < reader->counter) {
        advance_chain_key(&new_chain, &new_chain);
    }

    create_message_keys(&new_chain, &message_key);

    _OLM_UNSET_VALUE(new_chain);
    return verify_mac_and_decrypt(
        ratchet->ratchet_cipher, &message_key, reader,
        plaintext, max_plaintext_length
    );
}

static size_t verify_mac_and_decrypt_for_new_chain(
    const _OlmRatchet *ratchet,
    const _OlmMessageReader *reader,
    uint8_t *plaintext, size_t max_plaintext_length
) {
    _OlmSharedKey new_root_key;
    _OlmReceiverChain new_chain;
    size_t result;

    /* They shouldn't move to a new chain until we've sent a message
     * acknowledging their previous one. */
    if (_olm_list_empty(&ratchet->sender_chain)) {
        return SIZE_MAX;
    }

    /* Limit the number of hashes we're prepared to compute. */
    if (reader->counter > MAX_MESSAGE_GAP) {
        return SIZE_MAX;
    }

    _OLM_LOAD_ARRAY(new_chain.ratchet_key.public_key, reader->ratchet_key);
    create_chain_key(
        ratchet->root_key,
        &_olm_list_get(&ratchet->sender_chain, 0).ratchet_key,
        &new_chain.ratchet_key,
        ratchet->kdf_info,
        &new_root_key, &new_chain.chain_key
    );

    result = verify_mac_and_decrypt_for_existing_chain(
        ratchet, &new_chain.chain_key, reader,
        plaintext, max_plaintext_length
    );

    _OLM_UNSET_VALUE(new_root_key);
    _OLM_UNSET_VALUE(new_chain);
    return result;
}

void _olm_ratchet_init(
    _OlmRatchet *ratchet,
    const _OlmKdfInfo *kdf_info,
    const _olm_cipher *ratchet_cipher
) {
    ratchet->kdf_info = kdf_info;
    ratchet->ratchet_cipher = ratchet_cipher;
    ratchet->last_error = OLM_SUCCESS;
    _olm_list_init(&ratchet->sender_chain);
    _olm_list_init(&ratchet->receiver_chains);
    _olm_list_init(&ratchet->skipped_message_keys);
}

void _olm_ratchet_initialise_as_bob(
    _OlmRatchet *ratchet,
    const uint8_t *shared_secret, size_t shared_secret_length,
    const _olm_curve25519_public_key *their_ratchet_key
) {
    uint8_t derived_secrets[2 * OLM_SHARED_KEY_LENGTH];
    const uint8_t *pos = derived_secrets;
    _OlmReceiverChain *receiver_chain;

    _olm_crypto_hkdf_sha256(
        shared_secret, shared_secret_length,
        NULL, 0,
        ratchet->kdf_info->root_info, ratchet->kdf_info->root_info_length,
        derived_secrets, sizeof(derived_secrets)
    );

    receiver_chain = _olm_list_insert_front(&ratchet->receiver_chains);
    receiver_chain->chain_key.index = 0;

    pos = _OLM_LOAD_ARRAY(ratchet->root_key, pos);
    pos = _OLM_LOAD_ARRAY(receiver_chain->chain_key.key, pos);

    receiver_chain->ratchet_key = *their_ratchet_key;
    _OLM_UNSET_VALUE(derived_secrets);
}

void _olm_ratchet_initialise_as_alice(
    _OlmRatchet *ratchet,
    const uint8_t *shared_secret, size_t shared_secret_length,
    const _olm_curve25519_key_pair *our_ratchet_key
) {
    uint8_t derived_secrets[2 * OLM_SHARED_KEY_LENGTH];
    const uint8_t *pos = derived_secrets;
    _OlmSenderChain *sender_chain;

    _olm_crypto_hkdf_sha256(
        shared_secret, shared_secret_length,
        NULL, 0,
        ratchet->kdf_info->root_info, ratchet->kdf_info->root_info_length,
        derived_secrets, sizeof(derived_secrets)
    );

    sender_chain = _olm_list_insert_front(&ratchet->sender_chain);
    sender_chain->chain_key.index = 0;

    pos = _OLM_LOAD_ARRAY(ratchet->root_key, pos);
    pos = _OLM_LOAD_ARRAY(sender_chain->chain_key.key, pos);

    sender_chain->ratchet_key = *our_ratchet_key;
    _OLM_UNSET_VALUE(derived_secrets);
}

static size_t shared_key_pickle_length(void) {
    return OLM_SHARED_KEY_LENGTH;
}

static uint8_t * shared_key_pickle(
    uint8_t *pos,
    const _OlmSharedKey value
) {
    return _olm_pickle_bytes(pos, value, OLM_SHARED_KEY_LENGTH);
}

static const uint8_t * shared_key_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmSharedKey value
) {
    return _olm_unpickle_bytes(pos, end, value, OLM_SHARED_KEY_LENGTH);
}

static size_t sender_chain_pickle_length(
    const _OlmSenderChain *value
) {
    size_t length = 0;
    length += _olm_pickle_curve25519_key_pair_length(&value->ratchet_key);
    length += shared_key_pickle_length();
    length += _OLM_PICKLE_UINT32_LENGTH(value->chain_key.index);
    return length;
}

static uint8_t * sender_chain_pickle(
    uint8_t *pos,
    const _OlmSenderChain *value
) {
    pos = _olm_pickle_curve25519_key_pair(pos, &value->ratchet_key);
    pos = shared_key_pickle(pos, value->chain_key.key);
    pos = _olm_pickle_uint32(pos, value->chain_key.index);
    return pos;
}

static const uint8_t * sender_chain_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmSenderChain *value
) {
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value->ratchet_key);
    UNPICKLE_OK(pos);

    pos = shared_key_unpickle(pos, end, value->chain_key.key);
    UNPICKLE_OK(pos);

    pos = _olm_unpickle_uint32(pos, end, &value->chain_key.index);
    UNPICKLE_OK(pos);

    return pos;
}

static size_t sender_chain_list_pickle_length(
    const _OlmSenderChainList *value
) {
    size_t length = 0;
    const _OlmSenderChain *chain;

    length += _OLM_PICKLE_UINT32_LENGTH((uint32_t)_olm_list_size(value));
    for (chain = _olm_list_begin(value); chain != _olm_list_end(value); ++chain) {
        length += sender_chain_pickle_length(chain);
    }

    return length;
}

static uint8_t * sender_chain_list_pickle(
    uint8_t *pos,
    const _OlmSenderChainList *value
) {
    const _OlmSenderChain *chain;

    pos = _olm_pickle_uint32(pos, (uint32_t)_olm_list_size(value));
    for (chain = _olm_list_begin(value); chain != _olm_list_end(value); ++chain) {
        pos = sender_chain_pickle(pos, chain);
    }

    return pos;
}

static const uint8_t * sender_chain_list_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmSenderChainList *value
) {
    uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return NULL;
    }

    _olm_list_init(value);
    while (size-- && pos != end) {
        _OlmSenderChain *chain = _olm_list_insert(value, _olm_list_end(value));
        pos = sender_chain_unpickle(pos, end, chain);
        UNPICKLE_OK(pos);
    }

    return pos;
}

static size_t receiver_chain_pickle_length(
    const _OlmReceiverChain *value
) {
    size_t length = 0;
    length += _olm_pickle_curve25519_public_key_length(&value->ratchet_key);
    length += shared_key_pickle_length();
    length += _OLM_PICKLE_UINT32_LENGTH(value->chain_key.index);
    return length;
}

static uint8_t * receiver_chain_pickle(
    uint8_t *pos,
    const _OlmReceiverChain *value
) {
    pos = _olm_pickle_curve25519_public_key(pos, &value->ratchet_key);
    pos = shared_key_pickle(pos, value->chain_key.key);
    pos = _olm_pickle_uint32(pos, value->chain_key.index);
    return pos;
}

static const uint8_t * receiver_chain_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmReceiverChain *value
) {
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value->ratchet_key);
    UNPICKLE_OK(pos);

    pos = shared_key_unpickle(pos, end, value->chain_key.key);
    UNPICKLE_OK(pos);

    pos = _olm_unpickle_uint32(pos, end, &value->chain_key.index);
    UNPICKLE_OK(pos);

    return pos;
}

static size_t receiver_chain_list_pickle_length(
    const _OlmReceiverChainList *value
) {
    size_t length = 0;
    const _OlmReceiverChain *chain;

    length += _OLM_PICKLE_UINT32_LENGTH((uint32_t)_olm_list_size(value));
    for (chain = _olm_list_begin(value); chain != _olm_list_end(value); ++chain) {
        length += receiver_chain_pickle_length(chain);
    }

    return length;
}

static uint8_t * receiver_chain_list_pickle(
    uint8_t *pos,
    const _OlmReceiverChainList *value
) {
    const _OlmReceiverChain *chain;

    pos = _olm_pickle_uint32(pos, (uint32_t)_olm_list_size(value));
    for (chain = _olm_list_begin(value); chain != _olm_list_end(value); ++chain) {
        pos = receiver_chain_pickle(pos, chain);
    }

    return pos;
}

static const uint8_t * receiver_chain_list_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmReceiverChainList *value
) {
    uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return NULL;
    }

    _olm_list_init(value);
    while (size-- && pos != end) {
        _OlmReceiverChain *chain = _olm_list_insert(value, _olm_list_end(value));
        pos = receiver_chain_unpickle(pos, end, chain);
        UNPICKLE_OK(pos);
    }

    return pos;
}

static size_t skipped_message_key_pickle_length(
    const _OlmSkippedMessageKey *value
) {
    size_t length = 0;
    length += _olm_pickle_curve25519_public_key_length(&value->ratchet_key);
    length += shared_key_pickle_length();
    length += _OLM_PICKLE_UINT32_LENGTH(value->message_key.index);
    return length;
}

static uint8_t * skipped_message_key_pickle(
    uint8_t *pos,
    const _OlmSkippedMessageKey *value
) {
    pos = _olm_pickle_curve25519_public_key(pos, &value->ratchet_key);
    pos = shared_key_pickle(pos, value->message_key.key);
    pos = _olm_pickle_uint32(pos, value->message_key.index);
    return pos;
}

static const uint8_t * skipped_message_key_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmSkippedMessageKey *value
) {
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value->ratchet_key);
    UNPICKLE_OK(pos);

    pos = shared_key_unpickle(pos, end, value->message_key.key);
    UNPICKLE_OK(pos);

    pos = _olm_unpickle_uint32(pos, end, &value->message_key.index);
    UNPICKLE_OK(pos);

    return pos;
}

static size_t skipped_message_key_list_pickle_length(
    const _OlmSkippedMessageKeyList *value
) {
    size_t length = 0;
    const _OlmSkippedMessageKey *key;

    length += _OLM_PICKLE_UINT32_LENGTH((uint32_t)_olm_list_size(value));
    for (key = _olm_list_begin(value); key != _olm_list_end(value); ++key) {
        length += skipped_message_key_pickle_length(key);
    }

    return length;
}

static uint8_t * skipped_message_key_list_pickle(
    uint8_t *pos,
    const _OlmSkippedMessageKeyList *value
) {
    const _OlmSkippedMessageKey *key;

    pos = _olm_pickle_uint32(pos, (uint32_t)_olm_list_size(value));
    for (key = _olm_list_begin(value); key != _olm_list_end(value); ++key) {
        pos = skipped_message_key_pickle(pos, key);
    }

    return pos;
}

static const uint8_t * skipped_message_key_list_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmSkippedMessageKeyList *value
) {
    uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return NULL;
    }

    _olm_list_init(value);
    while (size-- && pos != end) {
        _OlmSkippedMessageKey *key = _olm_list_insert(value, _olm_list_end(value));
        pos = skipped_message_key_unpickle(pos, end, key);
        UNPICKLE_OK(pos);
    }

    return pos;
}

size_t _olm_ratchet_pickle_length(
    const _OlmRatchet *ratchet
) {
    size_t length = 0;
    length += OLM_SHARED_KEY_LENGTH;
    length += sender_chain_list_pickle_length(&ratchet->sender_chain);
    length += receiver_chain_list_pickle_length(&ratchet->receiver_chains);
    length += skipped_message_key_list_pickle_length(&ratchet->skipped_message_keys);
    return length;
}

uint8_t * _olm_ratchet_pickle(
    uint8_t *pos,
    const _OlmRatchet *ratchet
) {
    pos = shared_key_pickle(pos, ratchet->root_key);
    pos = sender_chain_list_pickle(pos, &ratchet->sender_chain);
    pos = receiver_chain_list_pickle(pos, &ratchet->receiver_chains);
    pos = skipped_message_key_list_pickle(pos, &ratchet->skipped_message_keys);
    return pos;
}

const uint8_t * _olm_ratchet_unpickle(
    const uint8_t *pos, const uint8_t *end,
    _OlmRatchet *ratchet,
    bool includes_chain_index
) {
    pos = shared_key_unpickle(pos, end, ratchet->root_key);
    UNPICKLE_OK(pos);

    pos = sender_chain_list_unpickle(pos, end, &ratchet->sender_chain);
    UNPICKLE_OK(pos);

    pos = receiver_chain_list_unpickle(pos, end, &ratchet->receiver_chains);
    UNPICKLE_OK(pos);

    pos = skipped_message_key_list_unpickle(pos, end, &ratchet->skipped_message_keys);
    UNPICKLE_OK(pos);

    /* Pickle v0x80000001 includes a chain index; pickle v1 does not. */
    if (includes_chain_index) {
        uint32_t dummy;
        pos = _olm_unpickle_uint32(pos, end, &dummy);
        UNPICKLE_OK(pos);
    }

    return pos;
}

size_t _olm_ratchet_encrypt_output_length(
    const _OlmRatchet *ratchet,
    size_t plaintext_length
) {
    size_t counter = 0;
    size_t padded;

    if (!_olm_list_empty(&ratchet->sender_chain)) {
        counter = _olm_list_get(&ratchet->sender_chain, 0).chain_key.index;
    }

    padded = ratchet->ratchet_cipher->ops->encrypt_ciphertext_length(
        ratchet->ratchet_cipher,
        plaintext_length
    );

    return _olm_encode_message_length(
        (uint32_t)counter,
        CURVE25519_KEY_LENGTH,
        padded,
        ratchet->ratchet_cipher->ops->mac_length(ratchet->ratchet_cipher)
    );
}

size_t _olm_ratchet_encrypt_random_length(
    const _OlmRatchet *ratchet
) {
    return _olm_list_empty(&ratchet->sender_chain) ? CURVE25519_RANDOM_LENGTH : 0;
}

size_t _olm_ratchet_encrypt(
    _OlmRatchet *ratchet,
    const uint8_t *plaintext, size_t plaintext_length,
    const uint8_t *random, size_t random_length,
    uint8_t *output, size_t max_output_length
) {
    size_t output_length = _olm_ratchet_encrypt_output_length(
        ratchet, plaintext_length
    );
    _OlmMessageKey keys;
    size_t ciphertext_length;
    uint32_t counter;
    const _olm_curve25519_public_key *ratchet_key;
    _OlmMessageWriter writer;
    _OlmSenderChain *sender_chain;

    if (random_length < _olm_ratchet_encrypt_random_length(ratchet)) {
        ratchet->last_error = OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }

    if (max_output_length < output_length) {
        ratchet->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    if (_olm_list_empty(&ratchet->sender_chain)) {
        sender_chain = _olm_list_insert_front(&ratchet->sender_chain);
        _olm_crypto_curve25519_generate_key(
            random,
            &sender_chain->ratchet_key
        );
        create_chain_key(
            ratchet->root_key,
            &sender_chain->ratchet_key,
            &_olm_list_get(&ratchet->receiver_chains, 0).ratchet_key,
            ratchet->kdf_info,
            &ratchet->root_key,
            &sender_chain->chain_key
        );
    }

    create_message_keys(&_olm_list_get(&ratchet->sender_chain, 0).chain_key, &keys);
    advance_chain_key(
        &_olm_list_get(&ratchet->sender_chain, 0).chain_key,
        &_olm_list_get(&ratchet->sender_chain, 0).chain_key
    );

    ciphertext_length = ratchet->ratchet_cipher->ops->encrypt_ciphertext_length(
        ratchet->ratchet_cipher,
        plaintext_length
    );
    counter = keys.index;
    ratchet_key = &_olm_list_get(&ratchet->sender_chain, 0).ratchet_key.public_key;

    _olm_encode_message(
        &writer,
        PROTOCOL_VERSION,
        counter,
        CURVE25519_KEY_LENGTH,
        ciphertext_length,
        output
    );

    _OLM_STORE_ARRAY(writer.ratchet_key, ratchet_key->public_key);

    ratchet->ratchet_cipher->ops->encrypt(
        ratchet->ratchet_cipher,
        keys.key, sizeof(keys.key),
        plaintext, plaintext_length,
        writer.ciphertext, ciphertext_length,
        output, output_length
    );

    _OLM_UNSET_VALUE(keys);
    return output_length;
}

size_t _olm_ratchet_decrypt_max_plaintext_length(
    _OlmRatchet *ratchet,
    const uint8_t *input, size_t input_length
) {
    _OlmMessageReader reader;

    _olm_decode_message(
        &reader, input, input_length,
        ratchet->ratchet_cipher->ops->mac_length(ratchet->ratchet_cipher)
    );

    if (!reader.ciphertext) {
        ratchet->last_error = OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    return ratchet->ratchet_cipher->ops->decrypt_max_plaintext_length(
        ratchet->ratchet_cipher, reader.ciphertext_length
    );
}

size_t _olm_ratchet_decrypt(
    _OlmRatchet *ratchet,
    const uint8_t *input, size_t input_length,
    uint8_t *plaintext, size_t max_plaintext_length
) {
    _OlmMessageReader reader;
    size_t max_length;
    _OlmReceiverChain *chain = NULL;
    _OlmReceiverChain *receiver_chain;
    size_t result = SIZE_MAX;

    _olm_decode_message(
        &reader, input, input_length,
        ratchet->ratchet_cipher->ops->mac_length(ratchet->ratchet_cipher)
    );

    if (reader.version != PROTOCOL_VERSION) {
        ratchet->last_error = OLM_BAD_MESSAGE_VERSION;
        return SIZE_MAX;
    }

    if (!reader.has_counter || !reader.ratchet_key || !reader.ciphertext) {
        ratchet->last_error = OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    max_length = ratchet->ratchet_cipher->ops->decrypt_max_plaintext_length(
        ratchet->ratchet_cipher,
        reader.ciphertext_length
    );

    if (max_plaintext_length < max_length) {
        ratchet->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    if (reader.ratchet_key_length != CURVE25519_KEY_LENGTH) {
        ratchet->last_error = OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    for (
        receiver_chain = _olm_list_begin(&ratchet->receiver_chains);
        receiver_chain != _olm_list_end(&ratchet->receiver_chains);
        ++receiver_chain
    ) {
        if (0 == memcmp(
                receiver_chain->ratchet_key.public_key,
                reader.ratchet_key,
                CURVE25519_KEY_LENGTH
        )) {
            chain = receiver_chain;
            break;
        }
    }

    if (!chain) {
        result = verify_mac_and_decrypt_for_new_chain(
            ratchet, &reader, plaintext, max_plaintext_length
        );
    } else if (chain->chain_key.index > reader.counter) {
        /* Chain already advanced beyond this message key.
         * Check if the key is in the skipped key list. */
        _OlmSkippedMessageKey *skipped;
        for (
            skipped = _olm_list_begin(&ratchet->skipped_message_keys);
            skipped != _olm_list_end(&ratchet->skipped_message_keys);
            ++skipped
        ) {
            if (reader.counter == skipped->message_key.index
                    && 0 == memcmp(
                        skipped->ratchet_key.public_key,
                        reader.ratchet_key,
                        CURVE25519_KEY_LENGTH
                    )
            ) {
                result = verify_mac_and_decrypt(
                    ratchet->ratchet_cipher,
                    &skipped->message_key,
                    &reader,
                    plaintext,
                    max_plaintext_length
                );

                if (result != SIZE_MAX) {
                    _OLM_UNSET_VALUE(*skipped);
                    _olm_list_erase(&ratchet->skipped_message_keys, skipped);
                    return result;
                }
            }
        }
    } else {
        result = verify_mac_and_decrypt_for_existing_chain(
            ratchet, &chain->chain_key,
            &reader, plaintext, max_plaintext_length
        );
    }

    if (result == SIZE_MAX) {
        ratchet->last_error = OLM_BAD_MESSAGE_MAC;
        return SIZE_MAX;
    }

    if (!chain) {
        /* They started using a new ephemeral ratchet key.
         * Derive new chain keys and drop our previous sender chain so
         * the next outbound message uses a fresh keypair. */
        chain = _olm_list_insert_front(&ratchet->receiver_chains);
        _OLM_LOAD_ARRAY(chain->ratchet_key.public_key, reader.ratchet_key);

        /* TODO: this derivation was already done in
         * verify_mac_and_decrypt_for_new_chain(); we could cache it. */
        create_chain_key(
            ratchet->root_key,
            &_olm_list_get(&ratchet->sender_chain, 0).ratchet_key,
            &chain->ratchet_key,
            ratchet->kdf_info,
            &ratchet->root_key,
            &chain->chain_key
        );

        _OLM_UNSET_VALUE(_olm_list_get(&ratchet->sender_chain, 0));
        _olm_list_erase(&ratchet->sender_chain, _olm_list_begin(&ratchet->sender_chain));
    }

    while (chain->chain_key.index < reader.counter) {
        _OlmSkippedMessageKey *key = _olm_list_insert_front(&ratchet->skipped_message_keys);
        create_message_keys(&chain->chain_key, &key->message_key);
        key->ratchet_key = chain->ratchet_key;
        advance_chain_key(&chain->chain_key, &chain->chain_key);
    }

    advance_chain_key(&chain->chain_key, &chain->chain_key);
    return result;
}
