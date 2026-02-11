/* See LICENSE file for copyright and license details. */
#include "libce/account.hh"
#include "libce/base64.h"
#include "libce/pickle.h"
#include "libce/memory.h"

#include <cstring>

olm::Account::Account(
) : num_fallback_keys(0),
    next_one_time_key_id(0),
    last_error(OlmErrorCode::OLM_SUCCESS) {
    _olm_list_init(&one_time_keys);
}


olm::OneTimeKey const * olm::Account::lookup_key(
    _olm_curve25519_public_key const & public_key
) {
    OneTimeKey const * key;
    for (
        key = _olm_list_begin(&one_time_keys);
        key != _olm_list_end(&one_time_keys);
        ++key
    ) {
        if (_OLM_ARRAY_EQUAL(key->key.public_key.public_key, public_key.public_key)) {
            return key;
        }
    }
    if (num_fallback_keys >= 1
            && _OLM_ARRAY_EQUAL(
                current_fallback_key.key.public_key.public_key, public_key.public_key
            )
    ) {
        return &current_fallback_key;
    }
    if (num_fallback_keys >= 2
            && _OLM_ARRAY_EQUAL(
                prev_fallback_key.key.public_key.public_key, public_key.public_key
            )
    ) {
        return &prev_fallback_key;
    }
    return 0;
}

std::size_t olm::Account::remove_key(
    _olm_curve25519_public_key const & public_key
) {
    OneTimeKey * i;
    for (i = _olm_list_begin(&one_time_keys); i != _olm_list_end(&one_time_keys); ++i) {
        if (_OLM_ARRAY_EQUAL(i->key.public_key.public_key, public_key.public_key)) {
            std::uint32_t id = i->id;
            _olm_list_erase(&one_time_keys, i);
            return id;
        }
    }
    // check if the key is a fallback key, to avoid returning an error, but
    // don't actually remove it
    if (num_fallback_keys >= 1
            && _OLM_ARRAY_EQUAL(
                current_fallback_key.key.public_key.public_key, public_key.public_key
            )
    ) {
        return current_fallback_key.id;
    }
    if (num_fallback_keys >= 2
            && _OLM_ARRAY_EQUAL(
                prev_fallback_key.key.public_key.public_key, public_key.public_key
            )
    ) {
        return prev_fallback_key.id;
    }
    return SIZE_MAX;
}

std::size_t olm::Account::new_account_random_length() const {
    return ED25519_RANDOM_LENGTH + CURVE25519_RANDOM_LENGTH;
}

std::size_t olm::Account::new_account(
    uint8_t const * random, std::size_t random_length
) {
    if (random_length < new_account_random_length()) {
        last_error = OlmErrorCode::OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }

    _olm_crypto_ed25519_generate_key(random, &identity_keys.ed25519_key);
    random += ED25519_RANDOM_LENGTH;
    _olm_crypto_curve25519_generate_key(random, &identity_keys.curve25519_key);

    return 0;
}

namespace {

uint8_t KEY_JSON_ED25519[] = "\"ed25519\":";
uint8_t KEY_JSON_CURVE25519[] = "\"curve25519\":";

template<typename T>
static std::uint8_t * write_string(
    std::uint8_t * pos,
    T const & value
) {
    std::memcpy(pos, value, sizeof(T) - 1);
    return pos + (sizeof(T) - 1);
}

}


std::size_t olm::Account::get_identity_json_length() const {
    std::size_t length = 0;
    length += 1; /* { */
    length += sizeof(KEY_JSON_CURVE25519) - 1;
    length += 1; /* " */
    length += _olm_encode_base64_length(
        sizeof(identity_keys.curve25519_key.public_key)
    );
    length += 2; /* ", */
    length += sizeof(KEY_JSON_ED25519) - 1;
    length += 1; /* " */
    length += _olm_encode_base64_length(
        sizeof(identity_keys.ed25519_key.public_key)
    );
    length += 2; /* "} */
    return length;
}


std::size_t olm::Account::get_identity_json(
    std::uint8_t * identity_json, std::size_t identity_json_length
) {
    std::uint8_t * pos = identity_json;
    size_t expected_length = get_identity_json_length();

    if (identity_json_length < expected_length) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    *(pos++) = '{';
    pos = write_string(pos, KEY_JSON_CURVE25519);
    *(pos++) = '\"';
    pos += _olm_encode_base64(
        identity_keys.curve25519_key.public_key.public_key,
        sizeof(identity_keys.curve25519_key.public_key.public_key),
        pos
    );
    *(pos++) = '\"'; *(pos++) = ',';
    pos = write_string(pos, KEY_JSON_ED25519);
    *(pos++) = '\"';
    pos += _olm_encode_base64(
        identity_keys.ed25519_key.public_key.public_key,
        sizeof(identity_keys.ed25519_key.public_key.public_key),
        pos
    );
    *(pos++) = '\"'; *(pos++) = '}';
    return pos - identity_json;
}


std::size_t olm::Account::signature_length(
) const {
    return ED25519_SIGNATURE_LENGTH;
}


std::size_t olm::Account::sign(
    std::uint8_t const * message, std::size_t message_length,
    std::uint8_t * signature, std::size_t signature_length
) {
    if (signature_length < this->signature_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_crypto_ed25519_sign(
        &identity_keys.ed25519_key, message, message_length, signature
    );
    return this->signature_length();
}


std::size_t olm::Account::get_one_time_keys_json_length(
) const {
    std::size_t length = 0;
    bool is_empty = true;
    OneTimeKeyList const * one_time_key_list = &one_time_keys;
    OneTimeKey const * key;

    for (
        key = _olm_list_begin(one_time_key_list);
        key != _olm_list_end(one_time_key_list);
        ++key
    ) {
        if (key->published) {
            continue;
        }
        is_empty = false;
        length += 2; /* {" */
        length += _olm_encode_base64_length(_OLM_PICKLE_UINT32_LENGTH(key->id));
        length += 3; /* ":" */
        length += _olm_encode_base64_length(sizeof(key->key.public_key));
        length += 1; /* " */
    }
    if (is_empty) {
        length += 1; /* { */
    }
    length += 3; /* }{} */
    length += sizeof(KEY_JSON_CURVE25519) - 1;
    return length;
}


std::size_t olm::Account::get_one_time_keys_json(
    std::uint8_t * one_time_json, std::size_t one_time_json_length
) {
    std::uint8_t * pos = one_time_json;
    OneTimeKey const * key;

    if (one_time_json_length < get_one_time_keys_json_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = write_string(pos, KEY_JSON_CURVE25519);
    std::uint8_t sep = '{';
    for (key = _olm_list_begin(&one_time_keys); key != _olm_list_end(&one_time_keys); ++key) {
        if (key->published) {
            continue;
        }
        *(pos++) = sep;
        *(pos++) = '\"';
        std::uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key->id)];
        _olm_pickle_uint32(key_id, key->id);
        pos += _olm_encode_base64(key_id, sizeof(key_id), pos);
        *(pos++) = '\"'; *(pos++) = ':'; *(pos++) = '\"';
        pos += _olm_encode_base64(
            key->key.public_key.public_key, sizeof(key->key.public_key.public_key), pos
        );
        *(pos++) = '\"';
        sep = ',';
    }
    if (sep != ',') {
        /* The list was empty */
        *(pos++) = sep;
    }
    *(pos++) = '}';
    *(pos++) = '}';
    return pos - one_time_json;
}


std::size_t olm::Account::mark_keys_as_published(
) {
    std::size_t count = 0;
    OneTimeKey * key;

    for (key = _olm_list_begin(&one_time_keys); key != _olm_list_end(&one_time_keys); ++key) {
        if (!key->published) {
            key->published = true;
            count++;
        }
    }
    current_fallback_key.published = true;
    return count;
}


std::size_t olm::Account::max_number_of_one_time_keys(
) const {
    return olm::MAX_ONE_TIME_KEYS;
}

std::size_t olm::Account::generate_one_time_keys_random_length(
    std::size_t number_of_keys
) const {
    return CURVE25519_RANDOM_LENGTH * number_of_keys;
}

std::size_t olm::Account::generate_one_time_keys(
    std::size_t number_of_keys,
    std::uint8_t const * random, std::size_t random_length
) {
    if (random_length < generate_one_time_keys_random_length(number_of_keys)) {
        last_error = OlmErrorCode::OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }
    for (unsigned i = 0; i < number_of_keys; ++i) {
        OneTimeKey * key = _olm_list_insert_front(&one_time_keys);
        key->id = ++next_one_time_key_id;
        key->published = false;
        _olm_crypto_curve25519_generate_key(random, &key->key);
        random += CURVE25519_RANDOM_LENGTH;
    }
    return number_of_keys;
}

std::size_t olm::Account::generate_fallback_key_random_length() const {
    return CURVE25519_RANDOM_LENGTH;
}

std::size_t olm::Account::generate_fallback_key(
    std::uint8_t const * random, std::size_t random_length
) {
    if (random_length < generate_fallback_key_random_length()) {
        last_error = OlmErrorCode::OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }
    if (num_fallback_keys < 2) {
        num_fallback_keys++;
    }
    prev_fallback_key = current_fallback_key;
    current_fallback_key.id = ++next_one_time_key_id;
    current_fallback_key.published = false;
    _olm_crypto_curve25519_generate_key(random, &current_fallback_key.key);
    return 1;
}


std::size_t olm::Account::get_fallback_key_json_length(
) const {
    std::size_t length = 4 + sizeof(KEY_JSON_CURVE25519) - 1; /* {"curve25519":{}} */
    if (num_fallback_keys >= 1) {
        const OneTimeKey & key = current_fallback_key;
        length += 1; /* " */
        length += _olm_encode_base64_length(_OLM_PICKLE_UINT32_LENGTH(key.id));
        length += 3; /* ":" */
        length += _olm_encode_base64_length(sizeof(key.key.public_key));
        length += 1; /* " */
    }
    return length;
}

std::size_t olm::Account::get_fallback_key_json(
    std::uint8_t * fallback_json, std::size_t fallback_json_length
) {
    std::uint8_t * pos = fallback_json;
    if (fallback_json_length < get_fallback_key_json_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = write_string(pos, KEY_JSON_CURVE25519);
    *(pos++) = '{';
    OneTimeKey & key = current_fallback_key;
    if (num_fallback_keys >= 1) {
        *(pos++) = '\"';
        std::uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key.id)];
        _olm_pickle_uint32(key_id, key.id);
        pos += _olm_encode_base64(key_id, sizeof(key_id), pos);
        *(pos++) = '\"'; *(pos++) = ':'; *(pos++) = '\"';
        pos += _olm_encode_base64(
            key.key.public_key.public_key, sizeof(key.key.public_key.public_key), pos
        );
        *(pos++) = '\"';
    }
    *(pos++) = '}';
    *(pos++) = '}';
    return pos - fallback_json;
}

std::size_t olm::Account::get_unpublished_fallback_key_json_length(
) const {
    std::size_t length = 4 + sizeof(KEY_JSON_CURVE25519) - 1; /* {"curve25519":{}} */
    const OneTimeKey & key = current_fallback_key;
    if (num_fallback_keys >= 1 && !key.published) {
        length += 1; /* " */
        length += _olm_encode_base64_length(_OLM_PICKLE_UINT32_LENGTH(key.id));
        length += 3; /* ":" */
        length += _olm_encode_base64_length(sizeof(key.key.public_key));
        length += 1; /* " */
    }
    return length;
}

std::size_t olm::Account::get_unpublished_fallback_key_json(
    std::uint8_t * fallback_json, std::size_t fallback_json_length
) {
    std::uint8_t * pos = fallback_json;
    if (fallback_json_length < get_unpublished_fallback_key_json_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = write_string(pos, KEY_JSON_CURVE25519);
    *(pos++) = '{';
    OneTimeKey & key = current_fallback_key;
    if (num_fallback_keys >= 1 && !key.published) {
        *(pos++) = '\"';
        std::uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key.id)];
        _olm_pickle_uint32(key_id, key.id);
        pos += _olm_encode_base64(key_id, sizeof(key_id), pos);
        *(pos++) = '\"'; *(pos++) = ':'; *(pos++) = '\"';
        pos += _olm_encode_base64(
            key.key.public_key.public_key, sizeof(key.key.public_key.public_key), pos
        );
        *(pos++) = '\"';
    }
    *(pos++) = '}';
    *(pos++) = '}';
    return pos - fallback_json;
}

void olm::Account::forget_old_fallback_key(
) {
    if (num_fallback_keys >= 2) {
        num_fallback_keys = 1;
        _olm_unset(&prev_fallback_key, sizeof(prev_fallback_key));
    }
}

namespace olm {

static std::size_t pickle_length(
    olm::IdentityKeys const & value
) {
    size_t length = 0;
    length += _olm_pickle_ed25519_key_pair_length(&value.ed25519_key);
    length += _olm_pickle_curve25519_key_pair_length(&value.curve25519_key);
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    olm::IdentityKeys const & value
) {
    pos = _olm_pickle_ed25519_key_pair(pos, &value.ed25519_key);
    pos = _olm_pickle_curve25519_key_pair(pos, &value.curve25519_key);
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::IdentityKeys & value
) {
    pos = _olm_unpickle_ed25519_key_pair(pos, end, &value.ed25519_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value.curve25519_key); UNPICKLE_OK(pos);
    return pos;
}


static std::size_t pickle_length(
    olm::OneTimeKey const & value
) {
    std::size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(value.id);
    length += _OLM_PICKLE_BOOL_LENGTH(value.published);
    length += _olm_pickle_curve25519_key_pair_length(&value.key);
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    olm::OneTimeKey const & value
) {
    pos = _olm_pickle_uint32(pos, value.id);
    pos = _olm_pickle_bool(pos, value.published ? 1 : 0);
    pos = _olm_pickle_curve25519_key_pair(pos, &value.key);
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::OneTimeKey & value
) {
    int published;

    pos = _olm_unpickle_uint32(pos, end, &value.id); UNPICKLE_OK(pos);
    pos = _olm_unpickle_bool(pos, end, &published); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value.key); UNPICKLE_OK(pos);

    value.published = published ? true : false;
    return pos;
}


static std::size_t pickle_length(
    olm::OneTimeKeyList const & value
) {
    std::size_t length = 0;
    OneTimeKey const * key;

    length += _OLM_PICKLE_UINT32_LENGTH(std::uint32_t(_olm_list_size(&value)));
    for (key = _olm_list_begin(&value); key != _olm_list_end(&value); ++key) {
        length += olm::pickle_length(*key);
    }
    return length;
}


static std::uint8_t * pickle(
    std::uint8_t * pos,
    olm::OneTimeKeyList const & value
) {
    OneTimeKey const * key;

    pos = _olm_pickle_uint32(pos, std::uint32_t(_olm_list_size(&value)));
    for (key = _olm_list_begin(&value); key != _olm_list_end(&value); ++key) {
        pos = olm::pickle(pos, *key);
    }
    return pos;
}


static std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::OneTimeKeyList & value
) {
    std::uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return nullptr;
    }

    _olm_list_init(&value);
    while (size-- && pos != end) {
        OneTimeKey * key = _olm_list_insert(&value, _olm_list_end(&value));
        pos = olm::unpickle(pos, end, *key); UNPICKLE_OK(pos);
    }

    return pos;
}

} // namespace olm

namespace {
// pickle version 1 used only 32 bytes for the ed25519 private key.
// Any keys thus used should be considered compromised.
// pickle version 2 does not have fallback keys.
// pickle version 3 does not store whether the current fallback key is published.
static const std::uint32_t ACCOUNT_PICKLE_VERSION = 4;
}


std::size_t olm::pickle_length(
    olm::Account const & value
) {
    std::size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(ACCOUNT_PICKLE_VERSION);
    length += olm::pickle_length(value.identity_keys);
    length += olm::pickle_length(value.one_time_keys);
    length += _OLM_PICKLE_UINT8_LENGTH(value.num_fallback_keys);
    if (value.num_fallback_keys >= 1) {
        length += olm::pickle_length(value.current_fallback_key);
        if (value.num_fallback_keys >= 2) {
            length += olm::pickle_length(value.prev_fallback_key);
        }
    }
    length += _OLM_PICKLE_UINT32_LENGTH(value.next_one_time_key_id);
    return length;
}


std::uint8_t * olm::pickle(
    std::uint8_t * pos,
    olm::Account const & value
) {
    pos = _olm_pickle_uint32(pos, ACCOUNT_PICKLE_VERSION);
    pos = olm::pickle(pos, value.identity_keys);
    pos = olm::pickle(pos, value.one_time_keys);
    pos = _olm_pickle_uint8(pos, value.num_fallback_keys);
    if (value.num_fallback_keys >= 1) {
        pos = olm::pickle(pos, value.current_fallback_key);
        if (value.num_fallback_keys >= 2) {
            pos = olm::pickle(pos, value.prev_fallback_key);
        }
    }
    pos = _olm_pickle_uint32(pos, value.next_one_time_key_id);
    return pos;
}


std::uint8_t const * olm::unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    olm::Account & value
) {
    uint32_t pickle_version;

    pos = _olm_unpickle_uint32(pos, end, &pickle_version); UNPICKLE_OK(pos);

    switch (pickle_version) {
        case ACCOUNT_PICKLE_VERSION:
        case 3:
        case 2:
            break;
        case 1:
            value.last_error = OlmErrorCode::OLM_BAD_LEGACY_ACCOUNT_PICKLE;
            return nullptr;
        default:
            value.last_error = OlmErrorCode::OLM_UNKNOWN_PICKLE_VERSION;
            return nullptr;
    }

    pos = olm::unpickle(pos, end, value.identity_keys); UNPICKLE_OK(pos);
    pos = olm::unpickle(pos, end, value.one_time_keys); UNPICKLE_OK(pos);

    if (pickle_version <= 2) {
        // version 2 did not have fallback keys
        value.num_fallback_keys = 0;
    } else if (pickle_version == 3) {
        // version 3 used the published flag to indicate how many fallback keys
        // were present (we'll have to assume that the keys were published)
        pos = olm::unpickle(pos, end, value.current_fallback_key); UNPICKLE_OK(pos);
        pos = olm::unpickle(pos, end, value.prev_fallback_key); UNPICKLE_OK(pos);
        if (value.current_fallback_key.published) {
            if (value.prev_fallback_key.published) {
                value.num_fallback_keys = 2;
            } else {
                value.num_fallback_keys = 1;
            }
        } else  {
            value.num_fallback_keys = 0;
        }
    } else {
        pos = _olm_unpickle_uint8(pos, end, &value.num_fallback_keys); UNPICKLE_OK(pos);
        if (value.num_fallback_keys >= 1) {
            pos = olm::unpickle(pos, end, value.current_fallback_key); UNPICKLE_OK(pos);
            if (value.num_fallback_keys >= 2) {
                pos = olm::unpickle(pos, end, value.prev_fallback_key); UNPICKLE_OK(pos);
                if (value.num_fallback_keys >= 3) {
                    value.last_error = OlmErrorCode::OLM_CORRUPTED_PICKLE;
                    return nullptr;
                }
            }
        }
    }

    pos = _olm_unpickle_uint32(pos, end, &value.next_one_time_key_id); UNPICKLE_OK(pos);

    return pos;
}
