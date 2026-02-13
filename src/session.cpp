/* See LICENSE file for copyright and license details. */
#include "libce/account.h"
#include "libce/session.hh"
#include "libce/cipher.h"
#include "libce/crypto.h"
#include "libce/memory.h"
#include "libce/message.h"
#include "libce/pickle.h"

#include <cstring>
#include <stdio.h>

namespace {

static const std::uint8_t PROTOCOL_VERSION = 0x3;

static const std::uint8_t ROOT_KDF_INFO[] = "OLM_ROOT";
static const std::uint8_t RATCHET_KDF_INFO[] = "OLM_RATCHET";
static const std::uint8_t CIPHER_KDF_INFO[] = "OLM_KEYS";

static const _OlmKdfInfo OLM_KDF_INFO = {
    ROOT_KDF_INFO, sizeof(ROOT_KDF_INFO) - 1,
    RATCHET_KDF_INFO, sizeof(RATCHET_KDF_INFO) - 1
};

static const struct _olm_cipher_aes_sha_256 OLM_CIPHER =
    OLM_CIPHER_INIT_AES_SHA_256(CIPHER_KDF_INFO);

} // namespace

olm::Session::Session(
) : last_error(OlmErrorCode::OLM_SUCCESS),
    received_message(false) {
    _olm_ratchet_init(&ratchet, &OLM_KDF_INFO, OLM_CIPHER_BASE(&OLM_CIPHER));
}


std::size_t olm::Session::new_outbound_session_random_length() const {
    return CURVE25519_RANDOM_LENGTH * 2;
}


std::size_t olm::Session::new_outbound_session(
    OlmAccount const & local_account,
    _olm_curve25519_public_key const & identity_key,
    _olm_curve25519_public_key const & one_time_key,
    std::uint8_t const * random, std::size_t random_length
) {
    if (random_length < new_outbound_session_random_length()) {
        last_error = OlmErrorCode::OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }

    _olm_curve25519_key_pair base_key;
    _olm_crypto_curve25519_generate_key(random, &base_key);

    _olm_curve25519_key_pair ratchet_key;
    _olm_crypto_curve25519_generate_key(random + CURVE25519_RANDOM_LENGTH, &ratchet_key);

    _olm_curve25519_key_pair const & alice_identity_key_pair = (
        local_account.identity_keys.curve25519_key
    );

    received_message = false;
    alice_identity_key = alice_identity_key_pair.public_key;
    alice_base_key = base_key.public_key;
    bob_one_time_key = one_time_key;

    // Calculate the shared secret S via triple DH
    std::uint8_t secret[3 * CURVE25519_SHARED_SECRET_LENGTH];
    std::uint8_t * pos = secret;

    _olm_crypto_curve25519_shared_secret(&alice_identity_key_pair, &one_time_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&base_key, &identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&base_key, &one_time_key, pos);

    _olm_ratchet_initialise_as_alice(&ratchet, secret, sizeof(secret), &ratchet_key);

    _OLM_UNSET_VALUE(base_key);
    _OLM_UNSET_VALUE(ratchet_key);
    _OLM_UNSET_VALUE(secret);

    return 0;
}

namespace {

static bool check_message_fields(
    _OlmPreKeyMessageReader & reader, bool have_their_identity_key
) {
    bool ok = true;
    ok = ok && (have_their_identity_key || reader.identity_key);
    if (reader.identity_key) {
        ok = ok && reader.identity_key_length == CURVE25519_KEY_LENGTH;
    }
    ok = ok && reader.message;
    ok = ok && reader.base_key;
    ok = ok && reader.base_key_length == CURVE25519_KEY_LENGTH;
    ok = ok && reader.one_time_key;
    ok = ok && reader.one_time_key_length == CURVE25519_KEY_LENGTH;
    return ok;
}

} // namespace


std::size_t olm::Session::new_inbound_session(
    OlmAccount & local_account,
    _olm_curve25519_public_key const * their_identity_key,
    std::uint8_t const * one_time_key_message, std::size_t message_length
) {
    _OlmPreKeyMessageReader reader;
    _olm_decode_one_time_key_message(&reader, one_time_key_message, message_length);

    if (!check_message_fields(reader, their_identity_key)) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    if (reader.identity_key && their_identity_key) {
        bool same = 0 == std::memcmp(
            their_identity_key->public_key, reader.identity_key, CURVE25519_KEY_LENGTH
        );
        if (!same) {
            last_error = OlmErrorCode::OLM_BAD_MESSAGE_KEY_ID;
            return SIZE_MAX;
        }
    }

    _OLM_LOAD_ARRAY(alice_identity_key.public_key, reader.identity_key);
    _OLM_LOAD_ARRAY(alice_base_key.public_key, reader.base_key);
    _OLM_LOAD_ARRAY(bob_one_time_key.public_key, reader.one_time_key);

    _OlmMessageReader message_reader;
    _olm_decode_message(
        &message_reader, reader.message, reader.message_length,
        ratchet.ratchet_cipher->ops->mac_length(ratchet.ratchet_cipher)
    );

    if (!message_reader.ratchet_key
            || message_reader.ratchet_key_length != CURVE25519_KEY_LENGTH) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    _olm_curve25519_public_key ratchet_key;
    _OLM_LOAD_ARRAY(ratchet_key.public_key, message_reader.ratchet_key);

    _OlmOneTimeKey const * our_one_time_key = _olm_account_lookup_key(
        &local_account, &bob_one_time_key
    );

    if (!our_one_time_key) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_KEY_ID;
        return SIZE_MAX;
    }

    _olm_curve25519_key_pair const & bob_identity_key = (
        local_account.identity_keys.curve25519_key
    );
    _olm_curve25519_key_pair const & bob_one_time_key = our_one_time_key->key;

    // Calculate the shared secret S via triple DH
    std::uint8_t secret[CURVE25519_SHARED_SECRET_LENGTH * 3];
    std::uint8_t * pos = secret;
    _olm_crypto_curve25519_shared_secret(&bob_one_time_key, &alice_identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&bob_identity_key, &alice_base_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&bob_one_time_key, &alice_base_key, pos);

    _olm_ratchet_initialise_as_bob(&ratchet, secret, sizeof(secret), &ratchet_key);

    _OLM_UNSET_VALUE(secret);

    return 0;
}


std::size_t olm::Session::session_id_length() const {
    return SHA256_OUTPUT_LENGTH;
}


std::size_t olm::Session::session_id(
    std::uint8_t * id, std::size_t id_length
) {
    if (id_length < session_id_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    std::uint8_t tmp[CURVE25519_KEY_LENGTH * 3];
    std::uint8_t * pos = tmp;
    pos = _OLM_STORE_ARRAY(pos, alice_identity_key.public_key);
    pos = _OLM_STORE_ARRAY(pos, alice_base_key.public_key);
    pos = _OLM_STORE_ARRAY(pos, bob_one_time_key.public_key);
    _olm_crypto_sha256(tmp, sizeof(tmp), id);
    return session_id_length();
}


bool olm::Session::matches_inbound_session(
    _olm_curve25519_public_key const * their_identity_key,
    std::uint8_t const * one_time_key_message, std::size_t message_length
) const {
    _OlmPreKeyMessageReader reader;
    _olm_decode_one_time_key_message(&reader, one_time_key_message, message_length);

    if (!check_message_fields(reader, their_identity_key)) {
        return false;
    }

    bool same = true;
    if (reader.identity_key) {
        same = same && 0 == std::memcmp(
            reader.identity_key, alice_identity_key.public_key, CURVE25519_KEY_LENGTH
        );
    }
    if (their_identity_key) {
        same = same && 0 == std::memcmp(
            their_identity_key->public_key, alice_identity_key.public_key,
            CURVE25519_KEY_LENGTH
        );
    }
    same = same && 0 == std::memcmp(
        reader.base_key, alice_base_key.public_key, CURVE25519_KEY_LENGTH
    );
    same = same && 0 == std::memcmp(
        reader.one_time_key, bob_one_time_key.public_key, CURVE25519_KEY_LENGTH
    );
    return same;
}


olm::MessageType olm::Session::encrypt_message_type() const {
    if (received_message) {
        return olm::MessageType::MESSAGE;
    } else {
        return olm::MessageType::PRE_KEY;
    }
}


std::size_t olm::Session::encrypt_message_length(
    std::size_t plaintext_length
) const {
    std::size_t message_length = _olm_ratchet_encrypt_output_length(
        &ratchet, plaintext_length
    );

    if (received_message) {
        return message_length;
    }

    return _olm_encode_one_time_key_message_length(
        CURVE25519_KEY_LENGTH,
        CURVE25519_KEY_LENGTH,
        CURVE25519_KEY_LENGTH,
        message_length
    );
}


std::size_t olm::Session::encrypt_random_length() const {
    return _olm_ratchet_encrypt_random_length(&ratchet);
}


std::size_t olm::Session::encrypt(
    std::uint8_t const * plaintext, std::size_t plaintext_length,
    std::uint8_t const * random, std::size_t random_length,
    std::uint8_t * message, std::size_t message_length
) {
    if (message_length < encrypt_message_length(plaintext_length)) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    std::uint8_t * message_body;
    std::size_t message_body_length = _olm_ratchet_encrypt_output_length(
        &ratchet, plaintext_length
    );

    if (received_message) {
        message_body = message;
    } else {
        _OlmPreKeyMessageWriter writer;
        _olm_encode_one_time_key_message(
            &writer,
            PROTOCOL_VERSION,
            CURVE25519_KEY_LENGTH,
            CURVE25519_KEY_LENGTH,
            CURVE25519_KEY_LENGTH,
            message_body_length,
            message
        );
        _OLM_STORE_ARRAY(writer.one_time_key, bob_one_time_key.public_key);
        _OLM_STORE_ARRAY(writer.identity_key, alice_identity_key.public_key);
        _OLM_STORE_ARRAY(writer.base_key, alice_base_key.public_key);
        message_body = writer.message;
    }

    std::size_t result = _olm_ratchet_encrypt(
        &ratchet,
        plaintext, plaintext_length,
        random, random_length,
        message_body, message_body_length
    );

    if (result == SIZE_MAX) {
        last_error = ratchet.last_error;
        ratchet.last_error = OlmErrorCode::OLM_SUCCESS;
        return result;
    }

    return result;
}


std::size_t olm::Session::decrypt_max_plaintext_length(
    MessageType message_type,
    std::uint8_t const * message, std::size_t message_length
) {
    std::uint8_t const * message_body;
    std::size_t message_body_length;
    if (message_type == olm::MessageType::MESSAGE) {
        message_body = message;
        message_body_length = message_length;
    } else {
        _OlmPreKeyMessageReader reader;
        _olm_decode_one_time_key_message(&reader, message, message_length);
        if (!reader.message) {
            last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
            return SIZE_MAX;
        }
        message_body = reader.message;
        message_body_length = reader.message_length;
    }

    std::size_t result = _olm_ratchet_decrypt_max_plaintext_length(
        &ratchet, message_body, message_body_length
    );

    if (result == SIZE_MAX) {
        last_error = ratchet.last_error;
        ratchet.last_error = OlmErrorCode::OLM_SUCCESS;
    }
    return result;
}


std::size_t olm::Session::decrypt(
    olm::MessageType message_type,
    std::uint8_t const * message, std::size_t message_length,
    std::uint8_t * plaintext, std::size_t max_plaintext_length
) {
    std::uint8_t const * message_body;
    std::size_t message_body_length;
    if (message_type == olm::MessageType::MESSAGE) {
        message_body = message;
        message_body_length = message_length;
    } else {
        _OlmPreKeyMessageReader reader;
        _olm_decode_one_time_key_message(&reader, message, message_length);
        if (!reader.message) {
            last_error = OlmErrorCode::OLM_BAD_MESSAGE_FORMAT;
            return SIZE_MAX;
        }
        message_body = reader.message;
        message_body_length = reader.message_length;
    }

    std::size_t result = _olm_ratchet_decrypt(
        &ratchet,
        message_body, message_body_length,
        plaintext, max_plaintext_length
    );

    if (result == SIZE_MAX) {
        last_error = ratchet.last_error;
        ratchet.last_error = OlmErrorCode::OLM_SUCCESS;
        return result;
    }

    received_message = true;
    return result;
}

// make the description end with "..." instead of stopping abruptly with no
// warning
void elide_description(char *end) {
    end[-3] = '.';
    end[-2] = '.';
    end[-1] = '.';
    end[0] = '\0';
}

void olm::Session::describe(char *describe_buffer, size_t buflen) {
    // how much of the buffer is remaining (this is an int rather than a size_t
    // because it will get compared to the return value from snprintf)
    int remaining = buflen;
    // do nothing if we have a zero-length buffer, or if buflen > INT_MAX,
    // resulting in an overflow
    if (remaining <= 0) return;

    describe_buffer[0] = '\0';
    // we need at least 23 characters to get any sort of meaningful
    // information, so bail if we don't have that.  (But more importantly, we
    // need it to be at least 4 so that elide_description doesn't go out of
    // bounds.)
    if (remaining < 23) return;

    int size;

    // check that snprintf didn't return an error or reach the end of the buffer
#define CHECK_SIZE_AND_ADVANCE                                          \
    if (size > remaining) {                                             \
        return elide_description(describe_buffer + remaining - 1);      \
    } else if (size > 0) {                                              \
        describe_buffer += size;                                        \
        remaining -= size;                                              \
    } else {                                                            \
        return;                                                         \
    }

    size = snprintf(
        describe_buffer, remaining,
        "sender chain index: %d ",
        _olm_list_get(&ratchet.sender_chain, 0).chain_key.index
    );
    CHECK_SIZE_AND_ADVANCE;

    size = snprintf(describe_buffer, remaining, "receiver chain indices:");
    CHECK_SIZE_AND_ADVANCE;

    for (size_t i = 0; i < _olm_list_size(&ratchet.receiver_chains); ++i) {
        size = snprintf(
            describe_buffer, remaining,
            " %d", _olm_list_get(&ratchet.receiver_chains, i).chain_key.index
        );
        CHECK_SIZE_AND_ADVANCE;
    }

    size = snprintf(describe_buffer, remaining, " skipped message keys:");
    CHECK_SIZE_AND_ADVANCE;

    for (size_t i = 0; i < _olm_list_size(&ratchet.skipped_message_keys); ++i) {
        size = snprintf(
            describe_buffer, remaining,
            " %d", _olm_list_get(&ratchet.skipped_message_keys, i).message_key.index
        );
        CHECK_SIZE_AND_ADVANCE;
    }
#undef CHECK_SIZE_AND_ADVANCE
}

namespace {
// the master branch writes pickle version 1; the logging_enabled branch writes
// 0x80000001.
static const std::uint32_t SESSION_PICKLE_VERSION = 1;
}

std::size_t olm::pickle_length(
    Session const & value
) {
    std::size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(SESSION_PICKLE_VERSION);
    length += _OLM_PICKLE_BOOL_LENGTH(value.received_message);
    length += _olm_pickle_curve25519_public_key_length(&value.alice_identity_key);
    length += _olm_pickle_curve25519_public_key_length(&value.alice_base_key);
    length += _olm_pickle_curve25519_public_key_length(&value.bob_one_time_key);
    length += _olm_ratchet_pickle_length(&value.ratchet);
    return length;
}


std::uint8_t * olm::pickle(
    std::uint8_t * pos,
    Session const & value
) {
    pos = _olm_pickle_uint32(pos, SESSION_PICKLE_VERSION);
    pos = _olm_pickle_bool(pos, value.received_message ? 1 : 0);
    pos = _olm_pickle_curve25519_public_key(pos, &value.alice_identity_key);
    pos = _olm_pickle_curve25519_public_key(pos, &value.alice_base_key);
    pos = _olm_pickle_curve25519_public_key(pos, &value.bob_one_time_key);
    pos = _olm_ratchet_pickle(pos, &value.ratchet);
    return pos;
}


std::uint8_t const * olm::unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    Session & value
) {
    uint32_t pickle_version;
    pos = _olm_unpickle_uint32(pos, end, &pickle_version); UNPICKLE_OK(pos);

    bool includes_chain_index;
    switch (pickle_version) {
        case 1:
            includes_chain_index = false;
            break;

        case 0x80000001UL:
            includes_chain_index = true;
            break;

        default:
            value.last_error = OlmErrorCode::OLM_UNKNOWN_PICKLE_VERSION;
            return nullptr;
    }

    {
        int received_message;
        pos = _olm_unpickle_bool(pos, end, &received_message); UNPICKLE_OK(pos);
        value.received_message = received_message ? true : false;
    }
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value.alice_identity_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value.alice_base_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value.bob_one_time_key); UNPICKLE_OK(pos);
    pos = _olm_ratchet_unpickle(
        pos, end, &value.ratchet, includes_chain_index
    ); UNPICKLE_OK(pos);

    return pos;
}
