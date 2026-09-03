/* See LICENSE file for copyright and license details. */
#ifndef OLM_ACCOUNT_H_
#define OLM_ACCOUNT_H_

#include "libce/crypto.h"
#include "libce/error.h"
#include "libce/list.h"

#include <stdbool.h>

#define MAX_ONE_TIME_KEYS 100

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _OlmIdentityKeys {
    _olm_ed25519_key_pair ed25519_key;
    _olm_curve25519_key_pair curve25519_key;
} _OlmIdentityKeys;

typedef struct _OlmOneTimeKey {
    uint32_t id;
    bool published;
    _olm_curve25519_key_pair key;
} _OlmOneTimeKey;

typedef OLM_LIST(_OlmOneTimeKey, MAX_ONE_TIME_KEYS) _OlmOneTimeKeyList;

#ifndef OLM_TYPEDEF_OlmAccount
#define OLM_TYPEDEF_OlmAccount
typedef struct OlmAccount OlmAccount;
#endif

struct OlmAccount {
    OlmErrorCode last_error;
    _OlmIdentityKeys identity_keys;
    _OlmOneTimeKeyList one_time_keys;
    _OlmOneTimeKey current_fallback_key;
    _OlmOneTimeKey prev_fallback_key;
    uint8_t num_fallback_keys;
    uint32_t next_one_time_key_id;
    /* Pickles only keep the expanded Ed25519 key, so an account restored from
     * one cannot be dehydrated: MSC3814 stores the seed. */
    uint8_t ed25519_seed[ED25519_RANDOM_LENGTH];
    bool ed25519_seed_known;
};

/** Initialise an Olm account object. */
void _olm_account_init(
    OlmAccount * account
);

/** Number of random bytes needed to create a new account */
size_t _olm_account_new_account_random_length(void);

/** Create a new account. Returns SIZE_MAX on error. If the number of
 * random bytes is too small then last_error will be NOT_ENOUGH_RANDOM */
size_t _olm_account_new_account(
    OlmAccount * account,
    const uint8_t * random, size_t random_length
);

/** Number of bytes needed to output the identity keys for this account */
size_t _olm_account_get_identity_json_length(
    OlmAccount * account
);

/** Output the identity keys for this account as JSON in the following
 * format:
 *
 *    {"curve25519":"<43 base64 characters>"
 *    ,"ed25519":"<43 base64 characters>"
 *    }
 *
 *
 * Returns the size of the JSON written or SIZE_MAX on error.
 * If the buffer is too small last_error will be OUTPUT_BUFFER_TOO_SMALL. */
size_t _olm_account_get_identity_json(
    OlmAccount * account,
    uint8_t * identity_json, size_t identity_json_length
);

/**
 * The length of an ed25519 signature in bytes.
 */
size_t _olm_account_signature_length(void);

/**
 * Signs a message with the ed25519 key for this account.
 */
size_t _olm_account_sign(
    OlmAccount * account,
    const uint8_t * message, size_t message_length,
    uint8_t * signature, size_t signature_length
);

/** Number of bytes needed to output the one time keys for this account */
size_t _olm_account_get_one_time_keys_json_length(
    OlmAccount * account
);

/** Output the one time keys that haven't been published yet as JSON:
 *
 *  {"curve25519":
 *  ["<6 byte key id>":"<43 base64 characters>"
 *  ,"<6 byte key id>":"<43 base64 characters>"
 *  ...
 *  ]
 *  }
 *
 * Returns the size of the JSON written or SIZE_MAX on error.
 * If the buffer is too small last_error will be OUTPUT_BUFFER_TOO_SMALL.
 */
size_t _olm_account_get_one_time_keys_json(
    OlmAccount * account,
    uint8_t * one_time_json, size_t one_time_json_length
);

/** Mark the current list of one_time_keys and the current fallback key as
 * being published. The current one time keys will no longer be returned by
 * get_one_time_keys_json() and the current fallback key will no longer be
 * returned by get_unpublished_fallback_key_json(). */
size_t _olm_account_mark_keys_as_published(
    OlmAccount * account
);

/** The largest number of one time keys this account can store. */
size_t _olm_account_max_number_of_one_time_keys(void);

/** The number of random bytes needed to generate a given number of new one
 * time keys. */
size_t _olm_account_generate_one_time_keys_random_length(
    size_t number_of_keys
);

/** Generates a number of new one time keys. If the total number of keys
 * stored by this account exceeds max_number_of_one_time_keys() then the
 * old keys are discarded. Returns SIZE_MAX on error. If the number
 * of random bytes is too small then last_error will be NOT_ENOUGH_RANDOM */
size_t _olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    const uint8_t * random, size_t random_length
);

/** The number of random bytes needed to generate a fallback key. */
size_t _olm_account_generate_fallback_key_random_length(void);

/** Generates a new fallback key. Returns SIZE_MAX on error. If the
 * number of random bytes is too small then last_error will be
 * NOT_ENOUGH_RANDOM */
size_t _olm_account_generate_fallback_key(
    OlmAccount * account,
    const uint8_t * random, size_t random_length
);

/** Number of bytes needed to output the fallback keys for this account */
size_t _olm_account_get_fallback_key_json_length(
    OlmAccount * account
);

/** Deprecated: use get_unpublished_fallback_key_json instead */
size_t _olm_account_get_fallback_key_json(
    OlmAccount * account,
    uint8_t * fallback_json, size_t fallback_json_length
);

/** Number of bytes needed to output the unpublished fallback keys for this
 * account */
size_t _olm_account_get_unpublished_fallback_key_json_length(
    OlmAccount * account
);

/** Output the fallback key as JSON:
 *
 *  {"curve25519":
 *  ["<6 byte key id>":"<43 base64 characters>"
 *  ,"<6 byte key id>":"<43 base64 characters>"
 *  ...
 *  ]
 *  }
 *
 * if there is a fallback key and it has not been published yet.
 *
 * Returns the size of the JSON written or SIZE_MAX on error.
 * If the buffer is too small last_error will be OUTPUT_BUFFER_TOO_SMALL.
 */
size_t _olm_account_get_unpublished_fallback_key_json(
    OlmAccount * account,
    uint8_t * fallback_json, size_t fallback_json_length
);

/** Forget about the old fallback key */
void _olm_account_forget_old_fallback_key(
    OlmAccount * account
);

/** Lookup a one time key with the given public key */
const _OlmOneTimeKey * _olm_account_lookup_key(
    OlmAccount * account,
    const _olm_curve25519_public_key * public_key
);

/** Remove a one time key with the given public key */
size_t _olm_account_remove_key(
    OlmAccount * account,
    const _olm_curve25519_public_key * public_key
);

size_t _olm_pickle_account_length(
    const OlmAccount * value
);

uint8_t * _olm_pickle_account(
    const OlmAccount * value,
    uint8_t * pos
);

const uint8_t * _olm_unpickle_account(
    OlmAccount * value,
    const uint8_t * pos, const uint8_t * end
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_ACCOUNT_H_ */
