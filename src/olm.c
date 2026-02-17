/* See LICENSE file for copyright and license details. */
#include "libce/olm.h"
#include "libce/session.h"
#include "libce/account.h"
#include "libce/cipher.h"
#include "libce/pickle_encoding.h"
#include "libce/utility.h"
#include "libce/base64.h"
#include "libce/memory.h"

static size_t b64_output_length(
    size_t raw_length
) {
    return _olm_encode_base64_length(raw_length);
}

static uint8_t * b64_output_pos(
    uint8_t * output,
    size_t raw_length
) {
    return output + _olm_encode_base64_length(raw_length) - raw_length;
}

static size_t b64_output(
    uint8_t * output,
    size_t raw_length
) {
    size_t base64_length = _olm_encode_base64_length(raw_length);
    uint8_t * raw_output = output + base64_length - raw_length;
    _olm_encode_base64(raw_output, raw_length, output);
    return base64_length;
}

static size_t b64_input(
    uint8_t * input, size_t b64_length,
    OlmErrorCode * last_error
) {
    size_t raw_length = _olm_decode_base64_length(b64_length);
    if (raw_length == SIZE_MAX) {
        *last_error = OLM_INVALID_BASE64;
        return SIZE_MAX;
    }
    _olm_decode_base64(input, b64_length, input);
    return raw_length;
}

void olm_get_library_version(uint8_t *major, uint8_t *minor, uint8_t *patch) {
    if (major != NULL) *major = LIBCE_VERSION_MAJOR;
    if (minor != NULL) *minor = LIBCE_VERSION_MINOR;
    if (patch != NULL) *patch = LIBCE_VERSION_PATCH;
}

size_t olm_error(void) {
    return SIZE_MAX;
}

const char * olm_account_last_error(
    const OlmAccount * account
) {
    return _olm_error_to_string(account->last_error);
}

OlmErrorCode olm_account_last_error_code(
    const OlmAccount * account
) {
    return account->last_error;
}

const char * olm_session_last_error(
    const OlmSession * session
) {
    return _olm_error_to_string(session->last_error);
}

OlmErrorCode olm_session_last_error_code(
    const OlmSession * session
) {
    return session->last_error;
}

const char * olm_utility_last_error(
    const OlmUtility * utility
) {
    return _olm_error_to_string(utility->last_error);
}

OlmErrorCode olm_utility_last_error_code(
    const OlmUtility * utility
) {
    return utility->last_error;
}

size_t olm_account_size(void) {
    return sizeof(OlmAccount);
}

size_t olm_session_size(void) {
    return sizeof(OlmSession);
}

size_t olm_utility_size(void) {
    return sizeof(OlmUtility);
}

OlmAccount * olm_account(
    void * memory
) {
    OlmAccount * account = (OlmAccount *)memory;
    _olm_unset(account, sizeof(OlmAccount));
    _olm_account_init(account);
    return account;
}

OlmSession * olm_session(
    void * memory
) {
    OlmSession * session = (OlmSession *)memory;
    _olm_unset(session, sizeof(OlmSession));
    _olm_session_init(session);
    return session;
}

OlmUtility * olm_utility(
    void * memory
) {
    OlmUtility * utility = (OlmUtility *)memory;
    _olm_unset(utility, sizeof(OlmUtility));
    _olm_utility_init(utility);
    return utility;
}

size_t olm_clear_account(
    OlmAccount * account
) {
    /* Clear the memory backing the account  */
    _olm_unset(account, sizeof(OlmAccount));
    /* Initialise a fresh account object in case someone tries to use it */
    _olm_account_init(account);
    return sizeof(OlmAccount);
}

size_t olm_clear_session(
    OlmSession * session
) {
    /* Clear the memory backing the session */
    _olm_unset(session, sizeof(OlmSession));
    /* Initialise a fresh session object in case someone tries to use it */
    _olm_session_init(session);
    return sizeof(OlmSession);
}

size_t olm_clear_utility(
    OlmUtility * utility
) {
    /* Clear the memory backing the utility */
    _olm_unset(utility, sizeof(OlmUtility));
    /* Initialise a fresh utility object in case someone tries to use it */
    _olm_utility_init(utility);
    return sizeof(OlmUtility);
}

size_t olm_pickle_account_length(
    const OlmAccount * account
) {
    return _olm_enc_output_length(_olm_pickle_account_length(account));
}

size_t olm_pickle_session_length(
    const OlmSession * session
) {
    return _olm_enc_output_length(_olm_pickle_session_length(session));
}

size_t olm_pickle_account(
    OlmAccount * account,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
) {
    OlmAccount * object = account;
    size_t raw_length = _olm_pickle_account_length(object);
    if (pickled_length < _olm_enc_output_length(raw_length)) {
        object->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_pickle_account(object, _olm_enc_output_pos(pickled, raw_length));
    return _olm_enc_output(key, key_length, pickled, raw_length);
}

size_t olm_pickle_session(
    OlmSession * session,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
) {
    OlmSession * object = session;
    size_t raw_length = _olm_pickle_session_length(object);
    if (pickled_length < _olm_enc_output_length(raw_length)) {
        object->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_pickle_session(_olm_enc_output_pos(pickled, raw_length), object);
    return _olm_enc_output(key, key_length, pickled, raw_length);
}

size_t olm_unpickle_account(
    OlmAccount * account,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
) {
    OlmAccount * object = account;
    uint8_t * input = pickled;
    size_t raw_length = _olm_enc_input(
        key, key_length, input, pickled_length, &object->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }

    const uint8_t * pos = input;
    const uint8_t * end = pos + raw_length;

    pos = _olm_unpickle_account(object, pos, end);

    if (!pos) {
        /* Input was corrupted. */
        if (object->last_error == OLM_SUCCESS) {
            object->last_error = OLM_CORRUPTED_PICKLE;
        }
        return SIZE_MAX;
    } else if (pos != end) {
        /* Input was longer than expected. */
        object->last_error = OLM_PICKLE_EXTRA_DATA;
        return SIZE_MAX;
    }

    return pickled_length;
}


size_t olm_unpickle_session(
    OlmSession * session,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
) {
    OlmSession * object = session;
    uint8_t * input = pickled;
    size_t raw_length = _olm_enc_input(
        key, key_length, input, pickled_length, &object->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }

    const uint8_t * pos = input;
    const uint8_t * end = pos + raw_length;

    pos = _olm_unpickle_session(pos, end, object);

    if (!pos) {
        /* Input was corrupted. */
        if (object->last_error == OLM_SUCCESS) {
            object->last_error = OLM_CORRUPTED_PICKLE;
        }
        return SIZE_MAX;
    } else if (pos != end) {
        /* Input was longer than expected. */
        object->last_error = OLM_PICKLE_EXTRA_DATA;
        return SIZE_MAX;
    }

    return pickled_length;
}


size_t olm_create_account_random_length(
    const OlmAccount * account
) {
    return _olm_account_new_account_random_length();
}


size_t olm_create_account(
    OlmAccount * account,
    void * random, size_t random_length
) {
    size_t result = _olm_account_new_account(account, random, random_length);
    _olm_unset(random, random_length);
    return result;
}


size_t olm_account_identity_keys_length(
    OlmAccount * account
) {
    return _olm_account_get_identity_json_length(account);
}


size_t olm_account_identity_keys(
    OlmAccount * account,
    void * identity_keys, size_t identity_key_length
) {
    return _olm_account_get_identity_json(
        account, identity_keys, identity_key_length
    );
}


size_t olm_account_signature_length(
    const OlmAccount * account
) {
    return b64_output_length(_olm_account_signature_length());
}


size_t olm_account_sign(
    OlmAccount * account,
    const void * message, size_t message_length,
    void * signature, size_t signature_length
) {
    size_t raw_length = _olm_account_signature_length();
    if (signature_length < b64_output_length(raw_length)) {
        account->last_error =
            OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_account_sign(
         account,
         message, message_length,
         b64_output_pos(signature, raw_length), raw_length
    );
    return b64_output(signature, raw_length);
}


size_t olm_account_one_time_keys_length(
    OlmAccount * account
) {
    return _olm_account_get_one_time_keys_json_length(account);
}


size_t olm_account_one_time_keys(
    OlmAccount * account,
    void * one_time_keys_json, size_t one_time_key_json_length
) {
    return _olm_account_get_one_time_keys_json(
        account, one_time_keys_json, one_time_key_json_length
    );
}


size_t olm_account_mark_keys_as_published(
    OlmAccount * account
) {
    return _olm_account_mark_keys_as_published(account);
}


size_t olm_account_max_number_of_one_time_keys(
    const OlmAccount * account
) {
    return _olm_account_max_number_of_one_time_keys();
}


size_t olm_account_generate_one_time_keys_random_length(
    const OlmAccount * account,
    size_t number_of_keys
) {
    return _olm_account_generate_one_time_keys_random_length(number_of_keys);
}


size_t olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    void * random, size_t random_length
) {
    size_t result = _olm_account_generate_one_time_keys(
        account,
        number_of_keys,
        random, random_length
    );
    _olm_unset(random, random_length);
    return result;
}


size_t olm_account_generate_fallback_key_random_length(
    const OlmAccount * account
) {
    return _olm_account_generate_fallback_key_random_length();
}


size_t olm_account_generate_fallback_key(
    OlmAccount * account,
    void * random, size_t random_length
) {
    size_t result = _olm_account_generate_fallback_key(
        account, random, random_length
    );
    _olm_unset(random, random_length);
    return result;
}


size_t olm_account_fallback_key_length(
    OlmAccount * account
) {
    return _olm_account_get_fallback_key_json_length(account);
}


size_t olm_account_fallback_key(
    OlmAccount * account,
    void * fallback_key_json, size_t fallback_key_json_length
) {
    return _olm_account_get_fallback_key_json(
        account, fallback_key_json, fallback_key_json_length
    );
}


size_t olm_account_unpublished_fallback_key_length(
    OlmAccount * account
) {
    return _olm_account_get_unpublished_fallback_key_json_length(account);
}


size_t olm_account_unpublished_fallback_key(
    OlmAccount * account,
    void * fallback_key_json, size_t fallback_key_json_length
) {
    return _olm_account_get_unpublished_fallback_key_json(
        account, fallback_key_json, fallback_key_json_length
    );
}


void olm_account_forget_old_fallback_key(
    OlmAccount * account
) {
    return _olm_account_forget_old_fallback_key(account);
}


size_t olm_create_outbound_session_random_length(
    const OlmSession * session
) {
    return _olm_session_new_outbound_session_random_length();
}


size_t olm_create_outbound_session(
    OlmSession * session,
    const OlmAccount * account,
    const void * their_identity_key, size_t their_identity_key_length,
    const void * their_one_time_key, size_t their_one_time_key_length,
    void * random, size_t random_length
) {
    const uint8_t * id_key = their_identity_key;
    const uint8_t * ot_key = their_one_time_key;
    size_t id_key_length = their_identity_key_length;
    size_t ot_key_length = their_one_time_key_length;

    if (_olm_decode_base64_length(id_key_length) != CURVE25519_KEY_LENGTH
            || _olm_decode_base64_length(ot_key_length) != CURVE25519_KEY_LENGTH
    ) {
        session->last_error = OLM_INVALID_BASE64;
        return SIZE_MAX;
    }
    _olm_curve25519_public_key identity_key;
    _olm_curve25519_public_key one_time_key;

    _olm_decode_base64(id_key, id_key_length, identity_key.public_key);
    _olm_decode_base64(ot_key, ot_key_length, one_time_key.public_key);

    size_t result = _olm_session_new_outbound_session(
        session,
        account, &identity_key, &one_time_key,
        random, random_length
    );
    _olm_unset(random, random_length);
    return result;
}


size_t olm_create_inbound_session(
    OlmSession * session,
    OlmAccount * account,
    void * one_time_key_message, size_t message_length
) {
    size_t raw_length = b64_input(
        one_time_key_message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    return _olm_session_new_inbound_session(
        session,
        account, NULL, one_time_key_message, raw_length
    );
}


size_t olm_create_inbound_session_from(
    OlmSession * session,
    OlmAccount * account,
    const void * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
) {
    const uint8_t * id_key = their_identity_key;
    size_t id_key_length = their_identity_key_length;

    if (_olm_decode_base64_length(id_key_length) != CURVE25519_KEY_LENGTH) {
        session->last_error = OLM_INVALID_BASE64;
        return SIZE_MAX;
    }
    _olm_curve25519_public_key identity_key;
    _olm_decode_base64(id_key, id_key_length, identity_key.public_key);

    size_t raw_length = b64_input(
        one_time_key_message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    return _olm_session_new_inbound_session(
        session,
        account, &identity_key,
        one_time_key_message, raw_length
    );
}


size_t olm_session_id_length(
    const OlmSession * session
) {
    return b64_output_length(_olm_session_session_id_length());
}

size_t olm_session_id(
    OlmSession * session,
    void * id, size_t id_length
) {
    size_t raw_length = _olm_session_session_id_length();
    if (id_length < b64_output_length(raw_length)) {
        session->last_error =
                OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    size_t result = _olm_session_session_id(
       session,
       b64_output_pos(id, raw_length), raw_length
    );
    if (result == SIZE_MAX) {
        return result;
    }
    return b64_output(id, raw_length);
}


int olm_session_has_received_message(
    const OlmSession * session
) {
    return session->received_message;
}

void olm_session_describe(
    OlmSession * session, char *buf, size_t buflen
) {
    _olm_session_describe(session, buf, buflen);
}

size_t olm_matches_inbound_session(
    OlmSession * session,
    void * one_time_key_message, size_t message_length
) {
    size_t raw_length = b64_input(
        one_time_key_message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    bool matches = _olm_session_matches_inbound_session(
        session, NULL,
        one_time_key_message, raw_length
    );
    return matches ? 1 : 0;
}


size_t olm_matches_inbound_session_from(
    OlmSession * session,
    const void * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
) {
    const uint8_t * id_key = their_identity_key;
    size_t id_key_length = their_identity_key_length;

    if (_olm_decode_base64_length(id_key_length) != CURVE25519_KEY_LENGTH) {
        session->last_error = OLM_INVALID_BASE64;
        return SIZE_MAX;
    }
    _olm_curve25519_public_key identity_key;
    _olm_decode_base64(id_key, id_key_length, identity_key.public_key);

    size_t raw_length = b64_input(
        one_time_key_message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    bool matches = _olm_session_matches_inbound_session(
        session, &identity_key,
        one_time_key_message, raw_length
    );
    return matches ? 1 : 0;
}


size_t olm_remove_one_time_keys(
    OlmAccount * account,
    OlmSession * session
) {
    size_t result = _olm_account_remove_key(
        account,
        &session->bob_one_time_key
    );
    if (result == SIZE_MAX) {
        account->last_error = OLM_BAD_MESSAGE_KEY_ID;
    }
    return result;
}


size_t olm_encrypt_message_type(
    const OlmSession * session
) {
    return (size_t)(_olm_session_encrypt_message_type(session));
}


size_t olm_encrypt_random_length(
    OlmSession * session
) {
    return _olm_session_encrypt_random_length(session);
}


size_t olm_encrypt_message_length(
    OlmSession * session,
    size_t plaintext_length
) {
    return b64_output_length(
        _olm_session_encrypt_message_length(
            session, plaintext_length
        )
    );
}


size_t olm_encrypt(
    OlmSession * session,
    const void * plaintext, size_t plaintext_length,
    void * random, size_t random_length,
    void * message, size_t message_length
) {
    size_t raw_length = _olm_session_encrypt_message_length(
        session, plaintext_length
    );
    if (message_length < b64_output_length(raw_length)) {
        session->last_error =
            OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    size_t result = _olm_session_encrypt(
        session,
        plaintext, plaintext_length,
        random, random_length,
        b64_output_pos(message, raw_length), raw_length
    );
    _olm_unset(random, random_length);
    if (result == SIZE_MAX) {
        return result;
    }
    return b64_output(message, raw_length);
}


size_t olm_decrypt_max_plaintext_length(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length
) {
    size_t raw_length = b64_input(
        message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    return _olm_session_decrypt_max_plaintext_length(
        session,
        (MessageType)message_type,
        message, raw_length
    );
}


size_t olm_decrypt(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length,
    void * plaintext, size_t max_plaintext_length
) {
    size_t raw_length = b64_input(
        message, message_length, &session->last_error
    );
    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    return _olm_session_decrypt(
        session,
        (MessageType)message_type, message, raw_length,
        plaintext, max_plaintext_length
    );
}


size_t olm_sha256_length(void) {
    return b64_output_length(_olm_utility_sha256_length());
}


size_t olm_sha256(
    OlmUtility * utility,
    const void * input, size_t input_length,
    void * output, size_t output_length
) {
    size_t raw_length = _olm_utility_sha256_length();
    if (output_length < b64_output_length(raw_length)) {
        utility->last_error =
            OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    size_t result = _olm_utility_sha256(
       utility,
       input, input_length,
       b64_output_pos(output, raw_length), raw_length
    );
    if (result == SIZE_MAX) {
        return result;
    }
    return b64_output(output, raw_length);
}


size_t olm_ed25519_verify(
    OlmUtility * utility,
    const void * key, size_t key_length,
    const void * message, size_t message_length,
    void * signature, size_t signature_length
) {
    if (_olm_decode_base64_length(key_length) != CURVE25519_KEY_LENGTH) {
        utility->last_error = OLM_INVALID_BASE64;
        return SIZE_MAX;
    }
    _olm_ed25519_public_key verify_key;
    _olm_decode_base64(key, key_length, verify_key.public_key);
    size_t raw_signature_length = b64_input(
        signature, signature_length, &utility->last_error
    );
    if (raw_signature_length == SIZE_MAX) {
        return SIZE_MAX;
    }
    return _olm_utility_ed25519_verify(
        utility,
        &verify_key,
        message, message_length,
        signature, raw_signature_length
    );
}
