/* See LICENSE file for copyright and license details. */
#include "libce/account.h"
#include "libce/base64.h"
#include "libce/memory.h"
#include "libce/pickle.h"

// pickle version 1 used only 32 bytes for the ed25519 private key.
// Any keys thus used should be considered compromised.
// pickle version 2 does not have fallback keys.
// pickle version 3 does not store whether the current fallback key is published.
enum { ACCOUNT_PICKLE_VERSION = 4 };

static const uint8_t KEY_JSON_ED25519[] = "\"ed25519\":";
static const uint8_t KEY_JSON_CURVE25519[] = "\"curve25519\":";

static uint8_t * _olm_account_write_string_uint8(
    uint8_t * pos,
    uint8_t const * value,
    size_t value_length
) {
    memcpy(pos, value, value_length);
    return pos + value_length;
}

static size_t _olm_pickle_identity_keys_length(
    _OlmIdentityKeys const * value
) {
    size_t length = 0;
    length += _olm_pickle_ed25519_key_pair_length(&value->ed25519_key);
    length += _olm_pickle_curve25519_key_pair_length(&value->curve25519_key);
    return length;
}

static uint8_t * _olm_pickle_identity_keys(
    uint8_t * pos,
    _OlmIdentityKeys const * value
) {
    pos = _olm_pickle_ed25519_key_pair(pos, &value->ed25519_key);
    pos = _olm_pickle_curve25519_key_pair(pos, &value->curve25519_key);
    return pos;
}

static uint8_t const * _olm_unpickle_identity_keys(
    uint8_t const * pos, uint8_t const * end,
    _OlmIdentityKeys * value
) {
    pos = _olm_unpickle_ed25519_key_pair(pos, end, &value->ed25519_key); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value->curve25519_key); UNPICKLE_OK(pos);
    return pos;
}

static size_t _olm_pickle_one_time_key_length(
    _OlmOneTimeKey const * value
) {
    size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(value.id);
    length += _OLM_PICKLE_BOOL_LENGTH(value.published);
    length += _olm_pickle_curve25519_key_pair_length(&value->key);
    return length;
}

static uint8_t * _olm_pickle_one_time_key(
    uint8_t * pos,
    _OlmOneTimeKey const * value
) {
    pos = _olm_pickle_uint32(pos, value->id);
    pos = _olm_pickle_bool(pos, value->published ? 1 : 0);
    pos = _olm_pickle_curve25519_key_pair(pos, &value->key);
    return pos;
}

static uint8_t const * _olm_unpickle_one_time_key(
    uint8_t const * pos, uint8_t const * end,
    _OlmOneTimeKey * value
) {
    int published;

    pos = _olm_unpickle_uint32(pos, end, &value->id); UNPICKLE_OK(pos);
    pos = _olm_unpickle_bool(pos, end, &published); UNPICKLE_OK(pos);
    pos = _olm_unpickle_curve25519_key_pair(pos, end, &value->key); UNPICKLE_OK(pos);

    value->published = published ? true : false;
    return pos;
}

static size_t _olm_pickle_one_time_key_list_length(
    _OlmOneTimeKeyList const * value
) {
    size_t length = 0;
    _OlmOneTimeKey const * key;

    length += _OLM_PICKLE_UINT32_LENGTH((uint32_t)_olm_list_size(value));
    for (key = _olm_list_begin(&*value); key != _olm_list_end(&*value); ++key) {
        length += _olm_pickle_one_time_key_length(&*key);
    }
    return length;
}

static uint8_t * _olm_pickle_one_time_key_list(
    uint8_t * pos,
    _OlmOneTimeKeyList const * value
) {
    _OlmOneTimeKey const * key;

    pos = _olm_pickle_uint32(pos, (uint32_t)_olm_list_size(&*value));
    for (key = _olm_list_begin(&*value); key != _olm_list_end(&*value); ++key) {
        pos = _olm_pickle_one_time_key(pos, &*key);
    }
    return pos;
}

static uint8_t const * _olm_unpickle_one_time_key_list(
    uint8_t const * pos, uint8_t const * end,
    _OlmOneTimeKeyList * value
) {
    uint32_t size;

    pos = _olm_unpickle_uint32(pos, end, &size);
    if (!pos) {
        return NULL;
    }

    _olm_list_init(&*value);
    while (size-- && pos != end) {
        _OlmOneTimeKey * key = _olm_list_insert(&*value, _olm_list_end(&*value));
        pos = _olm_unpickle_one_time_key(pos, end, &*key); UNPICKLE_OK(pos);
    }

    return pos;
}

void _olm_account_init(
    OlmAccount * account
) {
    if (account) {
        account->last_error = OLM_SUCCESS;
        account->num_fallback_keys = 0;
        account->next_one_time_key_id = 0;
        _olm_list_init(&account->one_time_keys);
    }
}

size_t _olm_account_new_account_random_length(void) {
    return ED25519_RANDOM_LENGTH + CURVE25519_RANDOM_LENGTH;
}

size_t _olm_account_new_account(
    OlmAccount * account,
    uint8_t const * random, size_t random_length
) {
    if (random_length < _olm_account_new_account_random_length()) {
        account->last_error = OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }

    _olm_crypto_ed25519_generate_key(random, &account->identity_keys.ed25519_key);
    random += ED25519_RANDOM_LENGTH;
    _olm_crypto_curve25519_generate_key(random, &account->identity_keys.curve25519_key);

    return 0;
}

size_t _olm_account_get_identity_json_length(
    OlmAccount * account
) {
    size_t length = 0;
    length += 1; /* { */
    length += sizeof(KEY_JSON_CURVE25519) - 1;
    length += 1; /* " */
    length += _olm_encode_base64_length(
        sizeof(account->identity_keys.curve25519_key.public_key)
    );
    length += 2; /* ", */
    length += sizeof(KEY_JSON_ED25519) - 1;
    length += 1; /* " */
    length += _olm_encode_base64_length(
        sizeof(account->identity_keys.ed25519_key.public_key)
    );
    length += 2; /* "} */
    return length;
}

size_t _olm_account_get_identity_json(
    OlmAccount * account,
    uint8_t * identity_json, size_t identity_json_length
) {
    uint8_t * pos = identity_json;
    size_t expected_length = _olm_account_get_identity_json_length(account);

    if (identity_json_length < expected_length) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }

    *(pos++) = '{';
    pos = _olm_account_write_string_uint8(
        pos, KEY_JSON_CURVE25519, sizeof(KEY_JSON_CURVE25519) - 1
    );
    *(pos++) = '\"';
    pos += _olm_encode_base64(
        account->identity_keys.curve25519_key.public_key.public_key,
        sizeof(account->identity_keys.curve25519_key.public_key.public_key),
        pos
    );
    *(pos++) = '\"'; *(pos++) = ',';
    pos = _olm_account_write_string_uint8(
        pos, KEY_JSON_ED25519, sizeof(KEY_JSON_ED25519) - 1
    );
    *(pos++) = '\"';
    pos += _olm_encode_base64(
        account->identity_keys.ed25519_key.public_key.public_key,
        sizeof(account->identity_keys.ed25519_key.public_key.public_key),
        pos
    );
    *(pos++) = '\"'; *(pos++) = '}';
    return pos - identity_json;
}

size_t _olm_account_signature_length(void) {
    return ED25519_SIGNATURE_LENGTH;
}

size_t _olm_account_sign(
    OlmAccount * account,
    uint8_t const * message, size_t message_length,
    uint8_t * signature, size_t signature_length
) {
    if (signature_length < _olm_account_signature_length()) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_crypto_ed25519_sign(
        &account->identity_keys.ed25519_key, message, message_length, signature
    );
    return _olm_account_signature_length();
}

size_t _olm_account_get_one_time_keys_json_length(
    OlmAccount * account
) {
    size_t length = 0;
    bool is_empty = true;
    _OlmOneTimeKeyList const * one_time_key_list = &account->one_time_keys;
    _OlmOneTimeKey const * key;

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

size_t _olm_account_get_one_time_keys_json(
    OlmAccount * account,
    uint8_t * one_time_json, size_t one_time_json_length
) {
    uint8_t * pos = one_time_json;
    _OlmOneTimeKey const * key;

    if (one_time_json_length < _olm_account_get_one_time_keys_json_length(account)) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = _olm_account_write_string_uint8(
        pos, KEY_JSON_CURVE25519, sizeof(KEY_JSON_CURVE25519) - 1
    );
    uint8_t sep = '{';
    for (key = _olm_list_begin(&account->one_time_keys); key != _olm_list_end(&account->one_time_keys); ++key) {
        if (key->published) {
            continue;
        }
        *(pos++) = sep;
        *(pos++) = '\"';
        uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key->id)];
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

size_t _olm_account_mark_keys_as_published(
    OlmAccount * account
) {
    size_t count = 0;
    _OlmOneTimeKey * key;

    for (key = _olm_list_begin(&account->one_time_keys); key != _olm_list_end(&account->one_time_keys); ++key) {
        if (!key->published) {
            key->published = true;
            count++;
        }
    }
    account->current_fallback_key.published = true;
    return count;
}

size_t _olm_account_max_number_of_one_time_keys(void) {
    return MAX_ONE_TIME_KEYS;
}

size_t _olm_account_generate_one_time_keys_random_length(
    size_t number_of_keys
) {
    return CURVE25519_RANDOM_LENGTH * number_of_keys;
}

size_t _olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    uint8_t const * random, size_t random_length
) {
    if (random_length < _olm_account_generate_one_time_keys_random_length(number_of_keys)) {
        account->last_error = OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }
    for (unsigned i = 0; i < number_of_keys; ++i) {
        _OlmOneTimeKey * key = _olm_list_insert_front(&account->one_time_keys);
        key->id = ++account->next_one_time_key_id;
        key->published = false;
        _olm_crypto_curve25519_generate_key(random, &key->key);
        random += CURVE25519_RANDOM_LENGTH;
    }
    return number_of_keys;
}

size_t _olm_account_generate_fallback_key_random_length(void) {
    return CURVE25519_RANDOM_LENGTH;
}

size_t _olm_account_generate_fallback_key(
    OlmAccount * account,
    uint8_t const * random, size_t random_length
) {
    if (random_length < _olm_account_generate_fallback_key_random_length()) {
        account->last_error = OLM_NOT_ENOUGH_RANDOM;
        return SIZE_MAX;
    }
    if (account->num_fallback_keys < 2) {
        account->num_fallback_keys++;
    }
    account->prev_fallback_key = account->current_fallback_key;
    account->current_fallback_key.id = ++account->next_one_time_key_id;
    account->current_fallback_key.published = false;
    _olm_crypto_curve25519_generate_key(random, &account->current_fallback_key.key);
    return 1;
}

size_t _olm_account_get_fallback_key_json_length(
    OlmAccount * account
) {
    size_t length = 4 + sizeof(KEY_JSON_CURVE25519) - 1; /* {"curve25519":{}} */
    if (account->num_fallback_keys >= 1) {
        const _OlmOneTimeKey * key = &account->current_fallback_key;
        length += 1; /* " */
        length += _olm_encode_base64_length(_OLM_PICKLE_UINT32_LENGTH(key->id));
        length += 3; /* ":" */
        length += _olm_encode_base64_length(sizeof(key->key.public_key));
        length += 1; /* " */
    }
    return length;
}

size_t _olm_account_get_fallback_key_json(
    OlmAccount * account,
    uint8_t * fallback_json, size_t fallback_json_length
) {
    uint8_t * pos = fallback_json;
    if (fallback_json_length < _olm_account_get_fallback_key_json_length(account)) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = _olm_account_write_string_uint8(
        pos, KEY_JSON_CURVE25519, sizeof(KEY_JSON_CURVE25519) - 1
    );
    *(pos++) = '{';
    _OlmOneTimeKey * key = &account->current_fallback_key;
    if (account->num_fallback_keys >= 1) {
        *(pos++) = '\"';
        uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key->id)];
        _olm_pickle_uint32(key_id, key->id);
        pos += _olm_encode_base64(key_id, sizeof(key_id), pos);
        *(pos++) = '\"'; *(pos++) = ':'; *(pos++) = '\"';
        pos += _olm_encode_base64(
            key->key.public_key.public_key, sizeof(key->key.public_key.public_key), pos
        );
        *(pos++) = '\"';
    }
    *(pos++) = '}';
    *(pos++) = '}';
    return pos - fallback_json;
}

size_t _olm_account_get_unpublished_fallback_key_json_length(
    OlmAccount * account
) {
    size_t length = 4 + sizeof(KEY_JSON_CURVE25519) - 1; /* {"curve25519":{}} */
    const _OlmOneTimeKey * key = &account->current_fallback_key;
    if (account->num_fallback_keys >= 1 && !key->published) {
        length += 1; /* " */
        length += _olm_encode_base64_length(_OLM_PICKLE_UINT32_LENGTH(key->id));
        length += 3; /* ":" */
        length += _olm_encode_base64_length(sizeof(key->key.public_key));
        length += 1; /* " */
    }
    return length;
}

size_t _olm_account_get_unpublished_fallback_key_json(
    OlmAccount * account,
    uint8_t * fallback_json, size_t fallback_json_length
) {
    uint8_t * pos = fallback_json;
    if (fallback_json_length < _olm_account_get_unpublished_fallback_key_json_length(account)) {
        account->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    *(pos++) = '{';
    pos = _olm_account_write_string_uint8(
        pos, KEY_JSON_CURVE25519, sizeof(KEY_JSON_CURVE25519) - 1
    );
    *(pos++) = '{';
    _OlmOneTimeKey * key = &account->current_fallback_key;
    if (account->num_fallback_keys >= 1 && !key->published) {
        *(pos++) = '\"';
        uint8_t key_id[_OLM_PICKLE_UINT32_LENGTH(key->id)];
        _olm_pickle_uint32(key_id, key->id);
        pos += _olm_encode_base64(key_id, sizeof(key_id), pos);
        *(pos++) = '\"'; *(pos++) = ':'; *(pos++) = '\"';
        pos += _olm_encode_base64(
            key->key.public_key.public_key, sizeof(key->key.public_key.public_key), pos
        );
        *(pos++) = '\"';
    }
    *(pos++) = '}';
    *(pos++) = '}';
    return pos - fallback_json;
}

void _olm_account_forget_old_fallback_key(
    OlmAccount * account
) {
    if (account->num_fallback_keys >= 2) {
        account->num_fallback_keys = 1;
        _olm_unset(&account->prev_fallback_key, sizeof(account->prev_fallback_key));
    }
}

_OlmOneTimeKey const * _olm_account_lookup_key(
    OlmAccount * account,
    _olm_curve25519_public_key const * public_key
) {
    _OlmOneTimeKey const * key;
    for (
        key = _olm_list_begin(&account->one_time_keys);
        key != _olm_list_end(&account->one_time_keys);
        ++key
    ) {
        if (_OLM_ARRAY_EQUAL(key->key.public_key.public_key, public_key->public_key)) {
            return key;
        }
    }
    if (account->num_fallback_keys >= 1
            && _OLM_ARRAY_EQUAL(
                account->current_fallback_key.key.public_key.public_key, public_key->public_key
            )
    ) {
        return &account->current_fallback_key;
    }
    if (account->num_fallback_keys >= 2
            && _OLM_ARRAY_EQUAL(
                account->prev_fallback_key.key.public_key.public_key, public_key->public_key
            )
    ) {
        return &account->prev_fallback_key;
    }
    return 0;
}

size_t _olm_account_remove_key(
    OlmAccount * account,
    _olm_curve25519_public_key const * public_key
) {
    _OlmOneTimeKey * i;
    for (i = _olm_list_begin(&account->one_time_keys); i != _olm_list_end(&account->one_time_keys); ++i) {
        if (_OLM_ARRAY_EQUAL(i->key.public_key.public_key, public_key->public_key)) {
            uint32_t id = i->id;
            _olm_list_erase(&account->one_time_keys, i);
            return id;
        }
    }
    // check if the key is a fallback key, to avoid returning an error, but
    // don't actually remove it
    if (account->num_fallback_keys >= 1
            && _OLM_ARRAY_EQUAL(
                account->current_fallback_key.key.public_key.public_key, public_key->public_key
            )
    ) {
        return account->current_fallback_key.id;
    }
    if (account->num_fallback_keys >= 2
            && _OLM_ARRAY_EQUAL(
                account->prev_fallback_key.key.public_key.public_key, public_key->public_key
            )
    ) {
        return account->prev_fallback_key.id;
    }
    return SIZE_MAX;
}

size_t _olm_pickle_account_length(
    OlmAccount const * value
) {
    size_t length = 0;
    length += _OLM_PICKLE_UINT32_LENGTH(ACCOUNT_PICKLE_VERSION);
    length += _olm_pickle_identity_keys_length(&value->identity_keys);
    length += _olm_pickle_one_time_key_list_length(&value->one_time_keys);
    length += _OLM_PICKLE_UINT8_LENGTH(value.num_fallback_keys);
    if (value->num_fallback_keys >= 1) {
        length += _olm_pickle_one_time_key_length(&value->current_fallback_key);
        if (value->num_fallback_keys >= 2) {
            length += _olm_pickle_one_time_key_length(&value->prev_fallback_key);
        }
    }
    length += _OLM_PICKLE_UINT32_LENGTH(value.next_one_time_key_id);
    return length;
}

uint8_t * _olm_pickle_account(
    OlmAccount const * value,
    uint8_t * pos
) {
    pos = _olm_pickle_uint32(pos, ACCOUNT_PICKLE_VERSION);
    pos = _olm_pickle_identity_keys(pos, &value->identity_keys);
    pos = _olm_pickle_one_time_key_list(pos, &value->one_time_keys);
    pos = _olm_pickle_uint8(pos, value->num_fallback_keys);
    if (value->num_fallback_keys >= 1) {
        pos = _olm_pickle_one_time_key(pos, &value->current_fallback_key);
        if (value->num_fallback_keys >= 2) {
            pos = _olm_pickle_one_time_key(pos, &value->prev_fallback_key);
        }
    }
    pos = _olm_pickle_uint32(pos, value->next_one_time_key_id);
    return pos;
}

uint8_t const * _olm_unpickle_account(
    OlmAccount * value,
    uint8_t const * pos, uint8_t const * end
) {
    uint32_t pickle_version;

    pos = _olm_unpickle_uint32(pos, end, &pickle_version); UNPICKLE_OK(pos);

    switch (pickle_version) {
        case ACCOUNT_PICKLE_VERSION:
        case 3:
        case 2:
            break;
        case 1:
            value->last_error = OLM_BAD_LEGACY_ACCOUNT_PICKLE;
            return NULL;
        default:
            value->last_error = OLM_UNKNOWN_PICKLE_VERSION;
            return NULL;
    }

    pos = _olm_unpickle_identity_keys(pos, end, &value->identity_keys); UNPICKLE_OK(pos);
    pos = _olm_unpickle_one_time_key_list(pos, end, &value->one_time_keys); UNPICKLE_OK(pos);

    if (pickle_version <= 2) {
        // version 2 did not have fallback keys
        value->num_fallback_keys = 0;
    } else if (pickle_version == 3) {
        // version 3 used the published flag to indicate how many fallback keys
        // were present (we'll have to assume that the keys were published)
        pos = _olm_unpickle_one_time_key(pos, end, &value->current_fallback_key); UNPICKLE_OK(pos);
        pos = _olm_unpickle_one_time_key(pos, end, &value->prev_fallback_key); UNPICKLE_OK(pos);
        if (value->current_fallback_key.published) {
            if (value->prev_fallback_key.published) {
                value->num_fallback_keys = 2;
            } else {
                value->num_fallback_keys = 1;
            }
        } else  {
            value->num_fallback_keys = 0;
        }
    } else {
        pos = _olm_unpickle_uint8(pos, end, &value->num_fallback_keys); UNPICKLE_OK(pos);
        if (value->num_fallback_keys >= 1) {
            pos = _olm_unpickle_one_time_key(pos, end, &value->current_fallback_key); UNPICKLE_OK(pos);
            if (value->num_fallback_keys >= 2) {
                pos = _olm_unpickle_one_time_key(pos, end, &value->prev_fallback_key); UNPICKLE_OK(pos);
                if (value->num_fallback_keys >= 3) {
                    value->last_error = OLM_CORRUPTED_PICKLE;
                    return NULL;
                }
            }
        }
    }

    pos = _olm_unpickle_uint32(pos, end, &value->next_one_time_key_id); UNPICKLE_OK(pos);

    return pos;
}
