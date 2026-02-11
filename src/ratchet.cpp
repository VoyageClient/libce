/* See LICENSE file for copyright and license details. */
#include "libce/ratchet.hh"
#include "libce/message.h"
#include "libce/memory.h"
#include "libce/cipher.h"
#include "libce/pickle.h"

#include <cstring>

namespace {

static const std::uint8_t PROTOCOL_VERSION = 3;
static const std::uint8_t MESSAGE_KEY_SEED[1] = {0x01};
static const std::uint8_t CHAIN_KEY_SEED[1] = {0x02};
static const std::size_t MAX_MESSAGE_GAP = 2000;


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
    olm::SharedKey const & root_key,
    _olm_curve25519_key_pair const & our_key,
    _olm_curve25519_public_key const & their_key,
    olm::KdfInfo const & info,
    olm::SharedKey & new_root_key,
    olm::ChainKey & new_chain_key
) {
    olm::SharedKey secret;
    _olm_crypto_curve25519_shared_secret(&our_key, &their_key, secret);
    std::uint8_t derived_secrets[2 * olm::OLM_SHARED_KEY_LENGTH];
    _olm_crypto_hkdf_sha256(
        secret, sizeof(secret),
        root_key, sizeof(root_key),
        info.ratchet_info, info.ratchet_info_length,
        derived_secrets, sizeof(derived_secrets)
    );
    std::uint8_t const * pos = derived_secrets;
    pos = _OLM_LOAD_ARRAY(new_root_key, pos);
    pos = _OLM_LOAD_ARRAY(new_chain_key.key, pos);
    new_chain_key.index = 0;
    _OLM_UNSET_VALUE(derived_secrets);
    _OLM_UNSET_VALUE(secret);
}


static void advance_chain_key(
    olm::ChainKey const & chain_key,
    olm::ChainKey & new_chain_key
) {
    _olm_crypto_hmac_sha256(
        chain_key.key, sizeof(chain_key.key),
        CHAIN_KEY_SEED, sizeof(CHAIN_KEY_SEED),
        new_chain_key.key
    );
    new_chain_key.index = chain_key.index + 1;
}


static void create_message_keys(
    olm::ChainKey const & chain_key,
    olm::MessageKey & message_key) {
    _olm_crypto_hmac_sha256(
        chain_key.key, sizeof(chain_key.key),
        MESSAGE_KEY_SEED, sizeof(MESSAGE_KEY_SEED),
        message_key.key
    );
    message_key.index = chain_key.index;
}


static std::size_t verify_mac_and_decrypt(
    _olm_cipher const *cipher,
    olm::MessageKey const & message_key,
    _OlmMessageReader const & reader,
    std::uint8_t * plaintext, std::size_t max_plaintext_length
) {
    return cipher->ops->decrypt(
        cipher,
        message_key.key, sizeof(message_key.key),
        reader.input, reader.input_length,
        reader.ciphertext, reader.ciphertext_length,
        plaintext, max_plaintext_length
    );
}


static std::size_t verify_mac_and_decrypt_for_existing_chain(
    olm::Ratchet const & session,
    olm::ChainKey const & chain,
    _OlmMessageReader const & reader,
    std::uint8_t * plaintext, std::size_t max_plaintext_length
) {
    if (reader.counter < chain.index) {
        return SIZE_MAX;
    }

    /* Limit the number of hashes we're prepared to compute */
    if (reader.counter - chain.index > MAX_MESSAGE_GAP) {
        return SIZE_MAX;
    }

    olm::ChainKey new_chain = chain;

    while (new_chain.index < reader.counter) {
        advance_chain_key(new_chain, new_chain);
    }

    olm::MessageKey message_key;
    create_message_keys(new_chain, message_key);

    std::size_t result = verify_mac_and_decrypt(
        session.ratchet_cipher, message_key, reader,
        plaintext, max_plaintext_length
    );

    _OLM_UNSET_VALUE(new_chain);
    return result;
}


static std::size_t verify_mac_and_decrypt_for_new_chain(
    olm::Ratchet const & session,
    _OlmMessageReader const & reader,
    std::uint8_t * plaintext, std::size_t max_plaintext_length
) {
    olm::SharedKey new_root_key;
    olm::ReceiverChain new_chain;

    /* They shouldn't move to a new chain until we've sent them a message
     * acknowledging the last one */
    if (_olm_list_empty(&session.sender_chain)) {
        return SIZE_MAX;
    }

    /* Limit the number of hashes we're prepared to compute */
    if (reader.counter > MAX_MESSAGE_GAP) {
        return SIZE_MAX;
    }
    _OLM_LOAD_ARRAY(new_chain.ratchet_key.public_key, reader.ratchet_key);

    create_chain_key(
        session.root_key, _olm_list_get(&session.sender_chain, 0).ratchet_key,
        new_chain.ratchet_key, session.kdf_info,
        new_root_key, new_chain.chain_key
    );
    std::size_t result = verify_mac_and_decrypt_for_existing_chain(
        session, new_chain.chain_key, reader,
        plaintext, max_plaintext_length
    );
    _OLM_UNSET_VALUE(new_root_key);
    _OLM_UNSET_VALUE(new_chain);
    return result;
}

} // namespace


olm::Ratchet::Ratchet(
    olm::KdfInfo const & kdf_info,
    _olm_cipher const * ratchet_cipher
) : kdf_info(kdf_info),
    ratchet_cipher(ratchet_cipher),
    last_error(OlmErrorCode::OLM_SUCCESS) {
    _olm_list_init(&sender_chain);
    _olm_list_init(&receiver_chains);
    _olm_list_init(&skipped_message_keys);
}


void olm::Ratchet::initialise_as_bob(
    std::uint8_t const * shared_secret, std::size_t shared_secret_length,
    _olm_curve25519_public_key const & their_ratchet_key
) {
    std::uint8_t derived_secrets[2 * olm::OLM_SHARED_KEY_LENGTH];
    _olm_crypto_hkdf_sha256(
        shared_secret, shared_secret_length,
        nullptr, 0,
        kdf_info.root_info, kdf_info.root_info_length,
        derived_secrets, sizeof(derived_secrets)
    );
    _olm_list_insert_front(&receiver_chains);
    _olm_list_get(&receiver_chains, 0).chain_key.index = 0;
    std::uint8_t const * pos = derived_secrets;
    pos = _OLM_LOAD_ARRAY(root_key, pos);
    pos = _OLM_LOAD_ARRAY(_olm_list_get(&receiver_chains, 0).chain_key.key, pos);
    _olm_list_get(&receiver_chains, 0).ratchet_key = their_ratchet_key;
    _OLM_UNSET_VALUE(derived_secrets);
}


void olm::Ratchet::initialise_as_alice(
    std::uint8_t const * shared_secret, std::size_t shared_secret_length,
    _olm_curve25519_key_pair const & our_ratchet_key
) {
    std::uint8_t derived_secrets[2 * olm::OLM_SHARED_KEY_LENGTH];
    _olm_crypto_hkdf_sha256(
        shared_secret, shared_secret_length,
        nullptr, 0,
        kdf_info.root_info, kdf_info.root_info_length,
        derived_secrets, sizeof(derived_secrets)
    );
    _olm_list_insert_front(&sender_chain);
    _olm_list_get(&sender_chain, 0).chain_key.index = 0;
    std::uint8_t const * pos = derived_secrets;
    pos = _OLM_LOAD_ARRAY(root_key, pos);
    pos = _OLM_LOAD_ARRAY(_olm_list_get(&sender_chain, 0).chain_key.key, pos);
    _olm_list_get(&sender_chain, 0).ratchet_key = our_ratchet_key;
    _OLM_UNSET_VALUE(derived_secrets);
}

namespace olm {


static std::size_t pickle_length(
    const olm::SharedKey & value
) {
    return olm::OLM_SHARED_KEY_LENGTH;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::SharedKey & value
) {
    return _olm_pickle_bytes(pos, value, olm::OLM_SHARED_KEY_LENGTH);
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::SharedKey & value
) {
    return _olm_unpickle_bytes(pos, end, value, olm::OLM_SHARED_KEY_LENGTH);
}


static std::size_t pickle_length(
    const olm::SenderChain & value
) {
    std::size_t length = 0;
    length += _olm_pickle_curve25519_key_pair_length(&value.ratchet_key);
    length += pickle_length(value.chain_key.key);
    length += _OLM_PICKLE_UINT32_LENGTH(value.chain_key.index);
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::SenderChain & value
) {
    pos = _olm_pickle_curve25519_key_pair(pos, &value.ratchet_key);
    pos = pickle(pos, value.chain_key.key);
    pos = _olm_pickle_uint32(pos, value.chain_key.index);
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::SenderChain & value
) {
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value.ratchet_key); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.chain_key.key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_uint32(pos, end, &value.chain_key.index); UNPICKLE_OK(pos);
    return pos;
}


static std::size_t pickle_length(
    const olm::SenderChainList & value
) {
    std::size_t length = 0;
    SenderChain const * chain;

    length += _OLM_PICKLE_UINT32_LENGTH(std::uint32_t(_olm_list_size(&value)));
    for (chain = _olm_list_begin(&value); chain != _olm_list_end(&value); ++chain) {
        length += olm::pickle_length(*chain);
    }
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::SenderChainList & value
) {
    SenderChain const * chain;

    pos = _olm_pickle_uint32(pos, std::uint32_t(_olm_list_size(&value)));
    for (chain = _olm_list_begin(&value); chain != _olm_list_end(&value); ++chain) {
        pos = olm::pickle(pos, *chain);
    }
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::SenderChainList & value
) {
    std::uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return nullptr;
    }

    _olm_list_init(&value);
    while (size-- && pos != end) {
        SenderChain * chain = _olm_list_insert(&value, _olm_list_end(&value));
        pos = olm::unpickle(pos, end, *chain); UNPICKLE_OK(pos);
    }

    return pos;
}

static std::size_t pickle_length(
    const olm::ReceiverChain & value
) {
    std::size_t length = 0;
    length += _olm_pickle_curve25519_public_key_length(&value.ratchet_key);
    length += pickle_length(value.chain_key.key);
    length += _OLM_PICKLE_UINT32_LENGTH(value.chain_key.index);
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::ReceiverChain & value
) {
    pos = _olm_pickle_curve25519_public_key(pos, &value.ratchet_key);
    pos = pickle(pos, value.chain_key.key);
    pos = _olm_pickle_uint32(pos, value.chain_key.index);
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::ReceiverChain & value
) {
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value.ratchet_key); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.chain_key.key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_uint32(pos, end, &value.chain_key.index); UNPICKLE_OK(pos);
    return pos;
}


static std::size_t pickle_length(
    const olm::ReceiverChainList & value
) {
    std::size_t length = 0;
    ReceiverChain const * chain;

    length += _OLM_PICKLE_UINT32_LENGTH(std::uint32_t(_olm_list_size(&value)));
    for (chain = _olm_list_begin(&value); chain != _olm_list_end(&value); ++chain) {
        length += olm::pickle_length(*chain);
    }
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::ReceiverChainList & value
) {
    ReceiverChain const * chain;

    pos = _olm_pickle_uint32(pos, std::uint32_t(_olm_list_size(&value)));
    for (chain = _olm_list_begin(&value); chain != _olm_list_end(&value); ++chain) {
        pos = olm::pickle(pos, *chain);
    }
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::ReceiverChainList & value
) {
    std::uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return nullptr;
    }

    _olm_list_init(&value);
    while (size-- && pos != end) {
        ReceiverChain * chain = _olm_list_insert(&value, _olm_list_end(&value));
        pos = olm::unpickle(pos, end, *chain); UNPICKLE_OK(pos);
    }

    return pos;
}


static std::size_t pickle_length(
    const olm::SkippedMessageKey & value
) {
    std::size_t length = 0;
    length += _olm_pickle_curve25519_public_key_length(&value.ratchet_key);
    length += pickle_length(value.message_key.key);
    length += _OLM_PICKLE_UINT32_LENGTH(value.message_key.index);
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::SkippedMessageKey & value
) {
    pos = _olm_pickle_curve25519_public_key(pos, &value.ratchet_key);
    pos = pickle(pos, value.message_key.key);
    pos = _olm_pickle_uint32(pos, value.message_key.index);
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::SkippedMessageKey & value
) {
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value.ratchet_key); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.message_key.key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_uint32(pos, end, &value.message_key.index); UNPICKLE_OK(pos);
    return pos;
}


static std::size_t pickle_length(
    const olm::SkippedMessageKeyList & value
) {
    std::size_t length = 0;
    SkippedMessageKey const * key;

    length += _OLM_PICKLE_UINT32_LENGTH(std::uint32_t(_olm_list_size(&value)));
    for (key = _olm_list_begin(&value); key != _olm_list_end(&value); ++key) {
        length += olm::pickle_length(*key);
    }
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    const olm::SkippedMessageKeyList & value
) {
    SkippedMessageKey const * key;

    pos = _olm_pickle_uint32(pos, std::uint32_t(_olm_list_size(&value)));
    for (key = _olm_list_begin(&value); key != _olm_list_end(&value); ++key) {
        pos = olm::pickle(pos, *key);
    }
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::SkippedMessageKeyList & value
) {
    std::uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return nullptr;
    }

    _olm_list_init(&value);
    while (size-- && pos != end) {
        SkippedMessageKey * key = _olm_list_insert(&value, _olm_list_end(&value));
        pos = olm::unpickle(pos, end, *key); UNPICKLE_OK(pos);
    }

    return pos;
}


} // namespace olm


std::size_t olm::pickle_length(
    olm::Ratchet const & value
) {
    std::size_t length = 0;
    length += olm::OLM_SHARED_KEY_LENGTH;
    length += olm::pickle_length(value.sender_chain);
    length += olm::pickle_length(value.receiver_chains);
    length += olm::pickle_length(value.skipped_message_keys);
    return length;
}

std::uint8_t * olm::pickle(
    std::uint8_t * pos,
    olm::Ratchet const & value
) {
    pos = pickle(pos, value.root_key);
    pos = pickle(pos, value.sender_chain);
    pos = pickle(pos, value.receiver_chains);
    pos = pickle(pos, value.skipped_message_keys);
    return pos;
}


std::uint8_t const * olm::unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::Ratchet & value,
    bool includes_chain_index
) {
    pos = unpickle(pos, end, value.root_key); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.sender_chain); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.receiver_chains); UNPICKLE_OK(pos);
    pos = unpickle(pos, end, value.skipped_message_keys); UNPICKLE_OK(pos);

    // pickle v 0x80000001 includes a chain index; pickle v1 does not.
    if (includes_chain_index) {
        std::uint32_t dummy;
        pos = _olm_unpickle_uint32(pos, end, &dummy); UNPICKLE_OK(pos);
    }
    return pos;
}


std::size_t olm::Ratchet::encrypt_output_length(
    std::size_t plaintext_length
) const {
    std::size_t counter = 0;
    if (!_olm_list_empty(&sender_chain)) {
        counter = _olm_list_get(&sender_chain, 0).chain_key.index;
    }
    std::size_t padded = ratchet_cipher->ops->encrypt_ciphertext_length(
        ratchet_cipher,
        plaintext_length
    );
    return _olm_encode_message_length(
        counter, CURVE25519_KEY_LENGTH, padded, ratchet_cipher->ops->mac_length(ratchet_cipher)
    );
}


std::size_t olm::Ratchet::encrypt_random_length() const {
    return _olm_list_empty(&sender_chain) ? CURVE25519_RANDOM_LENGTH : 0;
}


std::size_t olm::Ratchet::encrypt(
    std::uint8_t const * plaintext, std::size_t plaintext_length,
    std::uint8_t const * random, std::size_t random_length,
    std::uint8_t * output, std::size_t max_output_length
) {
    std::size_t output_length = encrypt_output_length(plaintext_length);

    if (random_length < encrypt_random_length()) {
        last_error = OlmErrorCode::OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }
    if (max_output_length < output_length) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    if (_olm_list_empty(&sender_chain)) {
        _olm_list_insert_front(&sender_chain);
        _olm_crypto_curve25519_generate_key(
            random, &_olm_list_get(&sender_chain, 0).ratchet_key
        );
        create_chain_key(
            root_key,
            _olm_list_get(&sender_chain, 0).ratchet_key,
            _olm_list_get(&receiver_chains, 0).ratchet_key,
            kdf_info,
            root_key, _olm_list_get(&sender_chain, 0).chain_key
        );
    }

    MessageKey keys;
    create_message_keys(_olm_list_get(&sender_chain, 0).chain_key, keys);
    advance_chain_key(
        _olm_list_get(&sender_chain, 0).chain_key,
        _olm_list_get(&sender_chain, 0).chain_key
    );

    std::size_t ciphertext_length = ratchet_cipher->ops->encrypt_ciphertext_length(
        ratchet_cipher,
        plaintext_length
    );
    std::uint32_t counter = keys.index;
    _olm_curve25519_public_key const & ratchet_key =
        _olm_list_get(&sender_chain, 0).ratchet_key.public_key;

    _OlmMessageWriter writer;

    _olm_encode_message(
        &writer, PROTOCOL_VERSION, counter, CURVE25519_KEY_LENGTH,
        ciphertext_length,
        output
    );

    _OLM_STORE_ARRAY(writer.ratchet_key, ratchet_key.public_key);

    ratchet_cipher->ops->encrypt(
        ratchet_cipher,
        keys.key, sizeof(keys.key),
        plaintext, plaintext_length,
        writer.ciphertext, ciphertext_length,
        output, output_length
    );

    _OLM_UNSET_VALUE(keys);
    return output_length;
}


std::size_t olm::Ratchet::decrypt_max_plaintext_length(
    std::uint8_t const * input, std::size_t input_length
) {
    _OlmMessageReader reader;
    _olm_decode_message(
        &reader, input, input_length,
        ratchet_cipher->ops->mac_length(ratchet_cipher)
    );

    if (!reader.ciphertext) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    return ratchet_cipher->ops->decrypt_max_plaintext_length(
        ratchet_cipher, reader.ciphertext_length);
}


std::size_t olm::Ratchet::decrypt(
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * plaintext, std::size_t max_plaintext_length
) {
    _OlmMessageReader reader;
    _olm_decode_message(
        &reader, input, input_length,
        ratchet_cipher->ops->mac_length(ratchet_cipher)
    );

    if (reader.version != PROTOCOL_VERSION) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_VERSION;
        return SIZE_MAX;
    }

    if (!reader.has_counter || !reader.ratchet_key || !reader.ciphertext) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    std::size_t max_length = ratchet_cipher->ops->decrypt_max_plaintext_length(
        ratchet_cipher,
        reader.ciphertext_length
    );

    if (max_plaintext_length < max_length) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    if (reader.ratchet_key_length != CURVE25519_KEY_LENGTH) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    ReceiverChain * chain = nullptr;

    ReceiverChain * receiver_chain;
    for (
        receiver_chain = _olm_list_begin(&receiver_chains);
        receiver_chain != _olm_list_end(&receiver_chains);
        ++receiver_chain
    ) {
        if (0 == std::memcmp(
                receiver_chain->ratchet_key.public_key, reader.ratchet_key,
                CURVE25519_KEY_LENGTH
        )) {
            chain = receiver_chain;
            break;
        }
    }

    std::size_t result = SIZE_MAX;

    if (!chain) {
        result = verify_mac_and_decrypt_for_new_chain(
            *this, reader, plaintext, max_plaintext_length
        );
    } else if (chain->chain_key.index > reader.counter) {
        /* Chain already advanced beyond the key for this message
         * Check if the message keys are in the skipped key list. */
        SkippedMessageKey * skipped;
        for (
            skipped = _olm_list_begin(&skipped_message_keys);
            skipped != _olm_list_end(&skipped_message_keys);
            ++skipped
        ) {
            if (reader.counter == skipped->message_key.index
                    && 0 == std::memcmp(
                        skipped->ratchet_key.public_key, reader.ratchet_key,
                        CURVE25519_KEY_LENGTH
                    )
            ) {
                /* Found the key for this message. Check the MAC. */

                result = verify_mac_and_decrypt(
                    ratchet_cipher, skipped->message_key, reader,
                    plaintext, max_plaintext_length
                );

                if (result != SIZE_MAX) {
                    /* Remove the key from the skipped keys now that we've
                     * decoded the message it corresponds to. */
                    _OLM_UNSET_VALUE(*skipped);
                    _olm_list_erase(&skipped_message_keys, skipped);
                    return result;
                }
            }
        }
    } else {
        result = verify_mac_and_decrypt_for_existing_chain(
            *this, chain->chain_key,
            reader, plaintext, max_plaintext_length
        );
    }

    if (result == SIZE_MAX) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_MAC;
        return SIZE_MAX;
    }

    if (!chain) {
        /* They have started using a new ephemeral ratchet key.
         * We need to derive a new set of chain keys.
         * We can discard our previous ephemeral ratchet key.
         * We will generate a new key when we send the next message. */

        chain = _olm_list_insert_front(&receiver_chains);
        _OLM_LOAD_ARRAY(chain->ratchet_key.public_key, reader.ratchet_key);

        // TODO: we've already done this once, in
        // verify_mac_and_decrypt_for_new_chain(). we could reuse the result.
        create_chain_key(
            root_key, _olm_list_get(&sender_chain, 0).ratchet_key, chain->ratchet_key,
            kdf_info, root_key, chain->chain_key
        );

        _OLM_UNSET_VALUE(_olm_list_get(&sender_chain, 0));
        _olm_list_erase(&sender_chain, _olm_list_begin(&sender_chain));
    }

    while (chain->chain_key.index < reader.counter) {
        olm::SkippedMessageKey * key = _olm_list_insert_front(&skipped_message_keys);
        create_message_keys(chain->chain_key, key->message_key);
        key->ratchet_key = chain->ratchet_key;
        advance_chain_key(chain->chain_key, chain->chain_key);
    }

    advance_chain_key(chain->chain_key, chain->chain_key);

    return result;
}
