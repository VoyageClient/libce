/* See LICENSE file for copyright and license details. */
#include "libce/session.h"

#include "libce/account.h"
#include "libce/cipher.h"
#include "libce/memory.h"
#include "libce/message.h"
#include "libce/pickle.h"

#include <stdio.h>

static const uint8_t PROTOCOL_VERSION = 0x3;

static const uint8_t ROOT_KDF_INFO[] = "OLM_ROOT";
static const uint8_t RATCHET_KDF_INFO[] = "OLM_RATCHET";
static const uint8_t CIPHER_KDF_INFO[] = "OLM_KEYS";

// the master branch writes pickle version 1; the logging_enabled branch writes
// 0x80000001.
static const uint32_t SESSION_PICKLE_VERSION = 1;

static const _OlmKdfInfo OLM_KDF_INFO = {
    ROOT_KDF_INFO, sizeof(ROOT_KDF_INFO) - 1,
    RATCHET_KDF_INFO, sizeof(RATCHET_KDF_INFO) - 1
};

static const _olm_cipher_aes_sha_256 OLM_CIPHER =
    OLM_CIPHER_INIT_AES_SHA_256(CIPHER_KDF_INFO);

static bool check_message_fields(
    _OlmPreKeyMessageReader * reader, bool have_their_identity_key
) {
    bool ok = true;
    ok = ok && (have_their_identity_key || reader->identity_key);
    if (reader->identity_key) {
        ok = ok && reader->identity_key_length == CURVE25519_KEY_LENGTH;
    }
    ok = ok && reader->message;
    ok = ok && reader->base_key;
    ok = ok && reader->base_key_length == CURVE25519_KEY_LENGTH;
    ok = ok && reader->one_time_key;
    ok = ok && reader->one_time_key_length == CURVE25519_KEY_LENGTH;
    return ok;
}

// make the description end with "..." instead of stopping abruptly with no
// warning
static void elide_description(char *end) {
    end[-3] = '.';
    end[-2] = '.';
    end[-1] = '.';
    end[0] = '\0';
}

void _olm_session_init(
    OlmSession * session
) {
    if (session) {
        session->last_error = OLM_SUCCESS;
        session->received_message = false;
        _olm_ratchet_init(&session->ratchet, &OLM_KDF_INFO, OLM_CIPHER_BASE(&OLM_CIPHER));
    }
}

size_t _olm_session_new_outbound_session_random_length(void) {
    return CURVE25519_RANDOM_LENGTH * 2;
}

size_t _olm_session_new_outbound_session(
    OlmSession * session,
    const OlmAccount * local_account,
    const _olm_curve25519_public_key * identity_key,
    const _olm_curve25519_public_key * one_time_key,
    const uint8_t * random, size_t random_length
) {
    if (random_length < _olm_session_new_outbound_session_random_length()) {
        session->last_error = OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }

    _olm_curve25519_key_pair base_key;
    _olm_crypto_curve25519_generate_key(random, &base_key);

    _olm_curve25519_key_pair ratchet_key;
    _olm_crypto_curve25519_generate_key(random + CURVE25519_RANDOM_LENGTH, &ratchet_key);

    const _olm_curve25519_key_pair * alice_identity_key_pair = (
        &local_account->identity_keys.curve25519_key
    );

    session->received_message = false;
    session->alice_identity_key = alice_identity_key_pair->public_key;
    session->alice_base_key = base_key.public_key;
    session->bob_one_time_key = *one_time_key;

    // Calculate the shared secret S via triple DH
    uint8_t secret[3 * CURVE25519_SHARED_SECRET_LENGTH];
    uint8_t * pos = secret;

    _olm_crypto_curve25519_shared_secret(alice_identity_key_pair, one_time_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&base_key, identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(&base_key, one_time_key, pos);

    _olm_ratchet_initialise_as_alice(&session->ratchet, secret, sizeof(secret), &ratchet_key);

    _OLM_UNSET_VALUE(base_key);
    _OLM_UNSET_VALUE(ratchet_key);
    _OLM_UNSET_VALUE(secret);

    return 0;
}

size_t _olm_session_new_inbound_session(
    OlmSession * session,
    OlmAccount * local_account,
    const _olm_curve25519_public_key * their_identity_key,
    const uint8_t * pre_key_message, size_t message_length
) {
    _OlmPreKeyMessageReader reader;
    _olm_decode_one_time_key_message(&reader, pre_key_message, message_length);

    if (!check_message_fields(&reader, their_identity_key)) {
        session->last_error = OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    if (reader.identity_key && their_identity_key) {
        bool same = 0 == memcmp(
            their_identity_key->public_key, reader.identity_key, CURVE25519_KEY_LENGTH
        );
        if (!same) {
            session->last_error = OLM_BAD_MESSAGE_KEY_ID;
            return SIZE_MAX;
        }
    }

    _OLM_LOAD_ARRAY(session->alice_identity_key.public_key, reader.identity_key);
    _OLM_LOAD_ARRAY(session->alice_base_key.public_key, reader.base_key);
    _OLM_LOAD_ARRAY(session->bob_one_time_key.public_key, reader.one_time_key);

    _OlmMessageReader message_reader;
    _olm_decode_message(
        &message_reader, reader.message, reader.message_length,
        session->ratchet.ratchet_cipher->ops->mac_length(session->ratchet.ratchet_cipher)
    );

    if (!message_reader.ratchet_key
            || message_reader.ratchet_key_length != CURVE25519_KEY_LENGTH) {
        session->last_error = OLM_BAD_MESSAGE_FORMAT;
        return SIZE_MAX;
    }

    _olm_curve25519_public_key ratchet_key;
    _OLM_LOAD_ARRAY(ratchet_key.public_key, message_reader.ratchet_key);

    const _OlmOneTimeKey * our_one_time_key = _olm_account_lookup_key(
        local_account, &session->bob_one_time_key
    );

    if (!our_one_time_key) {
        session->last_error = OLM_BAD_MESSAGE_KEY_ID;
        return SIZE_MAX;
    }

    const _olm_curve25519_key_pair * bob_identity_key = (
        &local_account->identity_keys.curve25519_key
    );
    const _olm_curve25519_key_pair * bob_one_time_key = &our_one_time_key->key;

    // Calculate the shared secret S via triple DH
    uint8_t secret[CURVE25519_SHARED_SECRET_LENGTH * 3];
    uint8_t * pos = secret;
    _olm_crypto_curve25519_shared_secret(bob_one_time_key, &session->alice_identity_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(bob_identity_key, &session->alice_base_key, pos);
    pos += CURVE25519_SHARED_SECRET_LENGTH;
    _olm_crypto_curve25519_shared_secret(bob_one_time_key, &session->alice_base_key, pos);

    _olm_ratchet_initialise_as_bob(&session->ratchet, secret, sizeof(secret), &ratchet_key);

    _OLM_UNSET_VALUE(secret);

    return 0;
}

size_t _olm_session_session_id_length(void) {
    return SHA256_OUTPUT_LENGTH;
}

size_t _olm_session_session_id(
    OlmSession * session,
    uint8_t * id, size_t id_length
) {
    if (id_length < _olm_session_session_id_length()) {
        session->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    uint8_t tmp[CURVE25519_KEY_LENGTH * 3];
    uint8_t * pos = tmp;
    pos = _OLM_STORE_ARRAY(pos, session->alice_identity_key.public_key);
    pos = _OLM_STORE_ARRAY(pos, session->alice_base_key.public_key);
    pos = _OLM_STORE_ARRAY(pos, session->bob_one_time_key.public_key);
    _olm_crypto_sha256(tmp, sizeof(tmp), id);
    return _olm_session_session_id_length();
}

bool _olm_session_matches_inbound_session(
    OlmSession * session,
    const _olm_curve25519_public_key * their_identity_key,
    const uint8_t * pre_key_message, size_t message_length
) {
    _OlmPreKeyMessageReader reader;
    _olm_decode_one_time_key_message(&reader, pre_key_message, message_length);

    if (!check_message_fields(&reader, their_identity_key)) {
        return false;
    }

    bool same = true;
    if (reader.identity_key) {
        same = same && 0 == memcmp(
            reader.identity_key, session->alice_identity_key.public_key, CURVE25519_KEY_LENGTH
        );
    }
    if (their_identity_key) {
        same = same && 0 == memcmp(
            their_identity_key->public_key, session->alice_identity_key.public_key,
            CURVE25519_KEY_LENGTH
        );
    }
    same = same && 0 == memcmp(
        reader.base_key, session->alice_base_key.public_key, CURVE25519_KEY_LENGTH
    );
    same = same && 0 == memcmp(
        reader.one_time_key, session->bob_one_time_key.public_key, CURVE25519_KEY_LENGTH
    );
    return same;
}

MessageType _olm_session_encrypt_message_type(
    const OlmSession * session
) {
    if (session->received_message) {
        return MESSAGE_TYPE_MESSAGE;
    } else {
        return MESSAGE_TYPE_PRE_KEY;
    }
}

size_t _olm_session_encrypt_message_length(
    OlmSession * session,
    size_t plaintext_length
) {
    size_t message_length = _olm_ratchet_encrypt_output_length(
        &session->ratchet, plaintext_length
    );

    if (session->received_message) {
        return message_length;
    }

    return _olm_encode_one_time_key_message_length(
        CURVE25519_KEY_LENGTH,
        CURVE25519_KEY_LENGTH,
        CURVE25519_KEY_LENGTH,
        message_length
    );
}

size_t _olm_session_encrypt_random_length(
    OlmSession * session
) {
    return _olm_ratchet_encrypt_random_length(&session->ratchet);
}

size_t _olm_session_encrypt(
    OlmSession * session,
    const uint8_t * plaintext, size_t plaintext_length,
    const uint8_t * random, size_t random_length,
    uint8_t * message, size_t message_length
) {
    if (message_length < _olm_session_encrypt_message_length(session, plaintext_length)) {
        session->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    uint8_t * message_body;
    size_t message_body_length = _olm_ratchet_encrypt_output_length(
        &session->ratchet, plaintext_length
    );

    if (session->received_message) {
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
        _OLM_STORE_ARRAY(writer.one_time_key, session->bob_one_time_key.public_key);
        _OLM_STORE_ARRAY(writer.identity_key, session->alice_identity_key.public_key);
        _OLM_STORE_ARRAY(writer.base_key, session->alice_base_key.public_key);
        message_body = writer.message;
    }

    size_t result = _olm_ratchet_encrypt(
        &session->ratchet,
        plaintext, plaintext_length,
        random, random_length,
        message_body, message_body_length
    );

    if (result == SIZE_MAX) {
        session->last_error = session->ratchet.last_error;
        session->ratchet.last_error = OLM_SUCCESS;
        return result;
    }

    return result;
}

size_t _olm_session_decrypt_max_plaintext_length(
    OlmSession * session,
    MessageType message_type,
    const uint8_t * message, size_t message_length
) {
    const uint8_t * message_body;
    size_t message_body_length;
    if (message_type == MESSAGE_TYPE_MESSAGE) {
        message_body = message;
        message_body_length = message_length;
    } else {
        _OlmPreKeyMessageReader reader;
        _olm_decode_one_time_key_message(&reader, message, message_length);
        if (!reader.message) {
            session->last_error = OLM_BAD_MESSAGE_FORMAT;
            return SIZE_MAX;
        }
        message_body = reader.message;
        message_body_length = reader.message_length;
    }

    size_t result = _olm_ratchet_decrypt_max_plaintext_length(
        &session->ratchet, message_body, message_body_length
    );

    if (result == SIZE_MAX) {
        session->last_error = session->ratchet.last_error;
        session->ratchet.last_error = OLM_SUCCESS;
    }
    return result;
}

size_t _olm_session_decrypt(
    OlmSession * session,
    MessageType message_type,
    const uint8_t * message, size_t message_length,
    uint8_t * plaintext, size_t max_plaintext_length
) {
    const uint8_t * message_body;
    size_t message_body_length;
    if (message_type == MESSAGE_TYPE_MESSAGE) {
        message_body = message;
        message_body_length = message_length;
    } else {
        _OlmPreKeyMessageReader reader;
        _olm_decode_one_time_key_message(&reader, message, message_length);
        if (!reader.message) {
            session->last_error = OLM_BAD_MESSAGE_FORMAT;
            return SIZE_MAX;
        }
        message_body = reader.message;
        message_body_length = reader.message_length;
    }

    size_t result = _olm_ratchet_decrypt(
        &session->ratchet,
        message_body, message_body_length,
        plaintext, max_plaintext_length
    );

    if (result == SIZE_MAX) {
        session->last_error = session->ratchet.last_error;
        session->ratchet.last_error = OLM_SUCCESS;
        return result;
    }

    session->received_message = true;
    return result;
}

void _olm_session_describe(
    OlmSession * session,
    char *buf, size_t buflen
) {
    // how much of the buffer is remaining (this is an int rather than a size_t
    // because it will get compared to the return value from snprintf)
    int remaining = buflen;
    // do nothing if we have a zero-length buffer, or if buflen > INT_MAX,
    // resulting in an overflow
    if (remaining <= 0) return;

    buf[0] = '\0';
    // we need at least 23 characters to get any sort of meaningful
    // information, so bail if we don't have that.  (But more importantly, we
    // need it to be at least 4 so that elide_description doesn't go out of
    // bounds.)
    if (remaining < 23) return;

    int size;

    // check that snprintf didn't return an error or reach the end of the buffer
#define CHECK_SIZE_AND_ADVANCE                                          \
    if (size > remaining) {                                             \
        return elide_description(buf + remaining - 1);      \
    } else if (size > 0) {                                              \
        buf += size;                                        \
        remaining -= size;                                              \
    } else {                                                            \
        return;                                                         \
    }

    size = snprintf(
        buf, remaining,
        "sender chain index: %d ",
        _olm_list_get(&session->ratchet.sender_chain, 0).chain_key.index
    );
    CHECK_SIZE_AND_ADVANCE;

    size = snprintf(buf, remaining, "receiver chain indices:");
    CHECK_SIZE_AND_ADVANCE;

    for (size_t i = 0; i < _olm_list_size(&session->ratchet.receiver_chains); ++i) {
        size = snprintf(
            buf, remaining,
            " %d", _olm_list_get(&session->ratchet.receiver_chains, i).chain_key.index
        );
        CHECK_SIZE_AND_ADVANCE;
    }

    size = snprintf(buf, remaining, " skipped message keys:");
    CHECK_SIZE_AND_ADVANCE;

    for (size_t i = 0; i < _olm_list_size(&session->ratchet.skipped_message_keys); ++i) {
        size = snprintf(
            buf, remaining,
            " %d", _olm_list_get(&session->ratchet.skipped_message_keys, i).message_key.index
        );
        CHECK_SIZE_AND_ADVANCE;
    }
#undef CHECK_SIZE_AND_ADVANCE
}

size_t _olm_pickle_session_length(
    const OlmSession * value
) {
    size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(SESSION_PICKLE_VERSION);
    length += _OLM_PICKLE_BOOL_LENGTH(value->received_message);
    length += _olm_pickle_curve25519_public_key_length(&value->alice_identity_key);
    length += _olm_pickle_curve25519_public_key_length(&value->alice_base_key);
    length += _olm_pickle_curve25519_public_key_length(&value->bob_one_time_key);
    length += _olm_ratchet_pickle_length(&value->ratchet);
    return length;
}

uint8_t * _olm_pickle_session(
    uint8_t * pos,
    const OlmSession * value
) {
    pos = _olm_pickle_uint32(pos, SESSION_PICKLE_VERSION);
    pos = _olm_pickle_bool(pos, value->received_message ? 1 : 0);
    pos = _olm_pickle_curve25519_public_key(pos, &value->alice_identity_key);
    pos = _olm_pickle_curve25519_public_key(pos, &value->alice_base_key);
    pos = _olm_pickle_curve25519_public_key(pos, &value->bob_one_time_key);
    pos = _olm_ratchet_pickle(pos, &value->ratchet);
    return pos;
}

const uint8_t * _olm_unpickle_session(
    const uint8_t * pos, const uint8_t * end,
    OlmSession * value
) {
    if (!value) {
        return NULL;
    }

    _olm_session_init(value);

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
            value->last_error = OLM_UNKNOWN_PICKLE_VERSION;
            return NULL;
    }

    {
        int received_message;
        pos = _olm_unpickle_bool(pos, end, &received_message); UNPICKLE_OK(pos);
        value->received_message = received_message ? true : false;
    }
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value->alice_identity_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value->alice_base_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_public_key(pos, end, &value->bob_one_time_key); UNPICKLE_OK(pos);
    pos = _olm_ratchet_unpickle(
        pos, end, &value->ratchet, includes_chain_index
    ); UNPICKLE_OK(pos);

    return pos;
}
