#include "libce/account.h"
#include "libce/base64.h"
#include "libce/dehydrated_device.h"
#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"

/* The key the vectors below were sealed with: 3, 10, 17, ... */
static void fill_key(uint8_t key[32])
{
    for (size_t i = 0; i < 32U; ++i) {
        key[i] = (uint8_t)(3U + i * 7U);
    }
}

static OlmAccount *new_account(uint8_t tag)
{
    OlmAccount *account = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t random[1024];
    test_mock_random rng = test_mock_random_init(tag, 0U);

    test_mock_random_fill(&rng, random, sizeof(random));
    CHECK_NE(SIZE_MAX, olm_create_account(account, random, olm_create_account_random_length(account)));
    test_mock_random_fill(&rng, random, sizeof(random));
    CHECK_NE(SIZE_MAX, olm_account_generate_one_time_keys(
        account, 3, random, olm_account_generate_one_time_keys_random_length(account, 3)
    ));
    test_mock_random_fill(&rng, random, sizeof(random));
    CHECK_NE(SIZE_MAX, olm_account_generate_fallback_key(
        account, random, olm_account_generate_fallback_key_random_length(account)
    ));

    return account;
}

static void check_public_key(const uint8_t *expected, const uint8_t *raw_key)
{
    uint8_t encoded[64];
    size_t length = _olm_encode_base64(raw_key, 32, encoded);

    CHECK_EQ(strlen((const char *)expected), length);
    CHECK_EQ_SIZE(expected, encoded, length);
}

/* Produced by vodozemac 0.10's Account::to_dehydrated_device. */
static const char *VODOZEMAC_NONCE = "8dF1dpKgYISv7Iue";
static const char *VODOZEMAC_DEVICE =
    "Tfg/njIM9/M0GZBBs7DnE9r9wSdnG8x4poiqDn19rRkaVTQ91008MapuAA+k3mHlstAb"
    "niZqhtBeWNVTofXUHTgS8GjVwkjO+FzzyVk+XW5VchQ+q6ZuLv+ZLA3zrLgQ5k7v/Fon"
    "mMLaL+B/zQNcxAW+G2yoh1sbZ7NwajYeJyIL6t5f9tsVjVyyWpCuplrTAVwvKoxmUlcr"
    "zBtNPZ2TWcpaYOh97JVfqWuqrfJ+wOpm8WKEA/BDHNaAQdKrka1VNx+9qLjzvbYKskKW"
    "GYy2/Id5XFbuh3/Vmw";

static void test_rehydrate_vodozemac_device(void **state)
{
    (void)state;

    const char *nonce = VODOZEMAC_NONCE;
    const char *device = VODOZEMAC_DEVICE;

    OlmAccount *account = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t key[32];
    size_t device_length = strlen(device);
    uint8_t *buffer = test_checked_malloc(device_length);
    const _OlmOneTimeKey *one_time_key;

    memcpy(buffer, device, device_length);
    fill_key(key);
    CHECK_NE(SIZE_MAX, olm_account_rehydrate(
        account, key, sizeof(key), nonce, strlen(nonce), buffer, device_length
    ));

    check_public_key(
        (const uint8_t *)"Y2gjB8zdXoQg8ysxAj80A1UUrjt/IX1xeRvla7bfznk",
        account->identity_keys.curve25519_key.public_key.public_key
    );
    check_public_key(
        (const uint8_t *)"MVfLPd3cyzSRZhSI8BZrbhcuLQ88sW/9plUIzN0aRxQ",
        account->identity_keys.ed25519_key.public_key.public_key
    );

    CHECK_EQ(3U, _olm_list_size(&account->one_time_keys));
    one_time_key = _olm_list_begin(&account->one_time_keys);
    check_public_key(
        (const uint8_t *)"CWhl15a37K/i4pCLIOQPxEHrSthQOjkpeZiLt5yyl08",
        one_time_key[0].key.public_key.public_key
    );
    check_public_key(
        (const uint8_t *)"gIyyF24mNywlz3rXvUj4F1oapfi6N2/DL+UehBqDtys",
        one_time_key[1].key.public_key.public_key
    );
    check_public_key(
        (const uint8_t *)"JsoJVfGjOfDpVmlNxHwNVDpjfxj6JXesdqPSyH7c1hU",
        one_time_key[2].key.public_key.public_key
    );

    CHECK_EQ(1U, account->num_fallback_keys);
    check_public_key(
        (const uint8_t *)"zIYRjK0v0m93w2d1xwwXlNwsW45p2zB+i4xqEtxHLk0",
        account->current_fallback_key.key.public_key.public_key
    );

    free(buffer);
    olm_clear_account(account);
    free(account);
}

/* Sealing is deterministic given the key and the nonce, so re-sealing the
 * account vodozemac gave us must reproduce their ciphertext byte for byte.
 * That pins our writer to theirs, not just our reader. */
static void test_dehydrate_matches_vodozemac_byte_for_byte(void **state)
{
    (void)state;

    OlmAccount *account = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t key[32];
    uint8_t nonce_random[DEHYDRATED_DEVICE_NONCE_LENGTH];
    size_t device_length = strlen(VODOZEMAC_DEVICE);
    uint8_t *buffer = test_checked_malloc(device_length);
    uint8_t *resealed;
    uint8_t *nonce;
    size_t nonce_length;

    fill_key(key);
    memcpy(buffer, VODOZEMAC_DEVICE, device_length);
    CHECK_NE(SIZE_MAX, olm_account_rehydrate(
        account, key, sizeof(key),
        VODOZEMAC_NONCE, strlen(VODOZEMAC_NONCE), buffer, device_length
    ));

    CHECK_EQ(
        DEHYDRATED_DEVICE_NONCE_LENGTH,
        _olm_decode_base64(
            (const uint8_t *)VODOZEMAC_NONCE, strlen(VODOZEMAC_NONCE), nonce_random
        )
    );

    nonce_length = olm_dehydrated_device_nonce_length();
    nonce = test_checked_malloc(nonce_length);
    CHECK_EQ(device_length, olm_account_dehydrate_length(account));
    resealed = test_checked_malloc(device_length);
    CHECK_EQ(device_length, olm_account_dehydrate(
        account, key, sizeof(key), nonce_random, sizeof(nonce_random),
        nonce, nonce_length, resealed, device_length
    ));

    CHECK_EQ_SIZE(VODOZEMAC_DEVICE, resealed, device_length);
    CHECK_EQ_SIZE(VODOZEMAC_NONCE, nonce, nonce_length);

    free(resealed);
    free(nonce);
    free(buffer);
    olm_clear_account(account);
    free(account);
}

/* vodozemac sealed a device, then encrypted an Olm pre-key message to one of the
 * one-time keys that only exists inside that seal. Nothing but a correct rehydration
 * can read it, which is the whole point of the format. */
static void test_rehydrated_device_decrypts_an_olm_message(void **state)
{
    (void)state;

    const char *nonce = "tZC6xQAOmSdZ9Bc0";
    const char *device =
        "pvgVJixQjgTFJXXt+InnHf5/3mGFN0eBgzmu8lYlN34f7FL9HSmLMT12Ojl6yVuw9TKZ"
        "EtcHTcV4sjtfhyE6cUT3NOub9kH2JRdzH/rUYHs+cpIr/Ba96wkAafplbNGI5q2CY9Pf"
        "WpLAe+rDpy+zHybnyqwaSSAOaAhwm3g6p1K3gxwzc/T2NIsH8YQ3+m/rFuk7dIz40wCJ"
        "obupO2PVN4ufttsdM+4X/ilVNbAMXbH9bJ/1pvL4eqH/PkVKTyXd3EIfSw5yWR1HHQ2X"
        "c5wl89antvgT22q+8g";
    const char *sender_key = "yBuNK0R197HlCgJwhImAGGDu9DWPGvBX8peBchsI3X8";
    const char *message =
        "Awogk8Host2lh+6dvCKDUSMd3+CazaDfFSAtMWGn4NqvByASILPGUXz+McjC38GhrlIF"
        "tpNIXOPelkchx02brPMUPd47GiDIG40rRHX3seUKAnCEiYAYYO70NY8a8Ffyl4FyGwjd"
        "fyJPAwogVM7D6oekGyy2AtHbKS83YZSRXVvLOelmIga6hLQaFk8QACIgdC+4J39i27if"
        "iU99PnI+T+ff6k1HxsrZS73P9KYcADpqil3pgzidcA";
    const char *expected = "a room key, more or less";

    OlmAccount *account = olm_account(test_checked_malloc(olm_account_size()));
    OlmSession *session = olm_session(test_checked_malloc(olm_session_size()));
    uint8_t key[32];
    size_t device_length = strlen(device);
    size_t message_length = strlen(message);
    uint8_t *device_buffer = test_checked_malloc(device_length);
    uint8_t *message_buffer = test_checked_malloc(message_length);
    uint8_t *plaintext;
    size_t max_plaintext_length;

    fill_key(key);
    memcpy(device_buffer, device, device_length);
    CHECK_NE(SIZE_MAX, olm_account_rehydrate(
        account, key, sizeof(key), nonce, strlen(nonce), device_buffer, device_length
    ));

    memcpy(message_buffer, message, message_length);
    CHECK_NE(SIZE_MAX, olm_create_inbound_session_from(
        session, account, sender_key, strlen(sender_key), message_buffer, message_length
    ));

    memcpy(message_buffer, message, message_length);
    max_plaintext_length = olm_decrypt_max_plaintext_length(
        session, OLM_MESSAGE_TYPE_PRE_KEY, message_buffer, message_length
    );
    CHECK_NE(SIZE_MAX, max_plaintext_length);

    plaintext = test_checked_malloc(max_plaintext_length);
    memcpy(message_buffer, message, message_length);
    CHECK_EQ(strlen(expected), olm_decrypt(
        session, OLM_MESSAGE_TYPE_PRE_KEY, message_buffer, message_length,
        plaintext, max_plaintext_length
    ));
    CHECK_EQ_SIZE(expected, plaintext, strlen(expected));

    free(plaintext);
    free(message_buffer);
    free(device_buffer);
    olm_clear_session(session);
    free(session);
    olm_clear_account(account);
    free(account);
}

static void test_dehydrate_round_trip(void **state)
{
    (void)state;

    OlmAccount *account = new_account(0x11);
    OlmAccount *restored = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t key[32];
    uint8_t random[12];
    test_mock_random rng = test_mock_random_init(0x22, 0U);
    size_t device_length = olm_account_dehydrate_length(account);
    size_t nonce_length = olm_dehydrated_device_nonce_length();
    uint8_t *device = test_checked_malloc(device_length);
    uint8_t *nonce = test_checked_malloc(nonce_length);
    uint8_t *copy = test_checked_malloc(device_length);
    const _OlmOneTimeKey *ours;
    const _OlmOneTimeKey *theirs;

    fill_key(key);
    test_mock_random_fill(&rng, random, sizeof(random));
    CHECK_EQ(device_length, olm_account_dehydrate(
        account, key, sizeof(key), random, sizeof(random),
        nonce, nonce_length, device, device_length
    ));

    memcpy(copy, device, device_length);
    CHECK_NE(SIZE_MAX, olm_account_rehydrate(
        restored, key, sizeof(key), nonce, nonce_length, copy, device_length
    ));

    CHECK_EQ_SIZE(
        account->identity_keys.curve25519_key.private_key.private_key,
        restored->identity_keys.curve25519_key.private_key.private_key,
        32
    );
    CHECK_EQ_SIZE(
        account->identity_keys.ed25519_key.private_key.private_key,
        restored->identity_keys.ed25519_key.private_key.private_key,
        64
    );
    CHECK_EQ(
        _olm_list_size(&account->one_time_keys),
        _olm_list_size(&restored->one_time_keys)
    );
    ours = _olm_list_begin(&account->one_time_keys);
    theirs = _olm_list_begin(&restored->one_time_keys);
    for (size_t i = 0; i < _olm_list_size(&account->one_time_keys); ++i) {
        CHECK_EQ_SIZE(
            ours[i].key.private_key.private_key,
            theirs[i].key.private_key.private_key,
            32
        );
    }
    CHECK_EQ_SIZE(
        account->current_fallback_key.key.private_key.private_key,
        restored->current_fallback_key.key.private_key.private_key,
        32
    );

    free(copy);
    free(nonce);
    free(device);
    olm_clear_account(restored);
    free(restored);
    olm_clear_account(account);
    free(account);
}

static void test_rehydrate_with_wrong_key(void **state)
{
    (void)state;

    OlmAccount *account = new_account(0x33);
    OlmAccount *restored = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t key[32];
    uint8_t random[12];
    test_mock_random rng = test_mock_random_init(0x44, 0U);
    size_t device_length = olm_account_dehydrate_length(account);
    size_t nonce_length = olm_dehydrated_device_nonce_length();
    uint8_t *device = test_checked_malloc(device_length);
    uint8_t *nonce = test_checked_malloc(nonce_length);

    fill_key(key);
    test_mock_random_fill(&rng, random, sizeof(random));
    CHECK_NE(SIZE_MAX, olm_account_dehydrate(
        account, key, sizeof(key), random, sizeof(random),
        nonce, nonce_length, device, device_length
    ));

    key[0] ^= 0xFFU;
    CHECK_EQ(SIZE_MAX, olm_account_rehydrate(
        restored, key, sizeof(key), nonce, nonce_length, device, device_length
    ));
    CHECK_EQ(OLM_BAD_MESSAGE_MAC, olm_account_last_error_code(restored));

    free(nonce);
    free(device);
    olm_clear_account(restored);
    free(restored);
    olm_clear_account(account);
    free(account);
}

/* Pickles keep only the expanded Ed25519 key, so an account restored from one
 * has no seed to write into the MSC3814 pickle. */
static void test_dehydrate_needs_the_seed(void **state)
{
    (void)state;

    OlmAccount *account = new_account(0x55);
    OlmAccount *unpickled = olm_account(test_checked_malloc(olm_account_size()));
    uint8_t key[32];
    uint8_t random[12];
    test_mock_random rng = test_mock_random_init(0x66, 0U);
    size_t pickle_length = olm_pickle_account_length(account);
    uint8_t *pickle = test_checked_malloc(pickle_length);
    size_t device_length;
    uint8_t *device;
    uint8_t *nonce;

    fill_key(key);
    CHECK_NE(SIZE_MAX, olm_pickle_account(account, key, sizeof(key), pickle, pickle_length));
    CHECK_NE(SIZE_MAX, olm_unpickle_account(unpickled, key, sizeof(key), pickle, pickle_length));

    device_length = olm_account_dehydrate_length(unpickled);
    device = test_checked_malloc(device_length);
    nonce = test_checked_malloc(olm_dehydrated_device_nonce_length());
    test_mock_random_fill(&rng, random, sizeof(random));

    CHECK_EQ(SIZE_MAX, olm_account_dehydrate(
        unpickled, key, sizeof(key), random, sizeof(random),
        nonce, olm_dehydrated_device_nonce_length(), device, device_length
    ));
    CHECK_EQ(OLM_UNSEEDED_ACCOUNT, olm_account_last_error_code(unpickled));

    free(nonce);
    free(device);
    free(pickle);
    olm_clear_account(unpickled);
    free(unpickled);
    olm_clear_account(account);
    free(account);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_rehydrate_vodozemac_device),
        cmocka_unit_test(test_dehydrate_matches_vodozemac_byte_for_byte),
        cmocka_unit_test(test_rehydrated_device_decrypts_an_olm_message),
        cmocka_unit_test(test_dehydrate_round_trip),
        cmocka_unit_test(test_rehydrate_with_wrong_key),
        cmocka_unit_test(test_dehydrate_needs_the_seed),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
