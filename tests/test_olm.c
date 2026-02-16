#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"
#include "utils.h"

static void test_pickle_account(void **state)
{
    (void)state;

    test_mock_random mock_random = test_mock_random_init((uint8_t)'P', 0U);

    uint8_t *account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *account = olm_account(account_buffer);

    size_t random_len = olm_create_account_random_length(account);
    uint8_t *random = test_checked_malloc(random_len);
    test_mock_random_fill(&mock_random, random, random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(account, random, random_len));

    size_t ot_random_len = olm_account_generate_one_time_keys_random_length(account, 42);
    uint8_t *ot_random = test_checked_malloc(ot_random_len);
    test_mock_random_fill(&mock_random, ot_random, ot_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_one_time_keys(account, 42, ot_random, ot_random_len));

    size_t pickle_length = olm_pickle_account_length(account);
    uint8_t *pickle1 = test_checked_malloc(pickle_length);
    size_t res = olm_pickle_account(account, "secret_key", 10, pickle1, pickle_length);
    CHECK_EQ(pickle_length, res);

    uint8_t *pickle2 = test_checked_malloc(pickle_length);
    memcpy(pickle2, pickle1, pickle_length);

    uint8_t *account_buffer2 = test_checked_malloc(olm_account_size());
    OlmAccount *account2 = olm_account(account_buffer2);
    CHECK_NE(SIZE_MAX, olm_unpickle_account(account2, "secret_key", 10, pickle2, pickle_length));
    CHECK_EQ(pickle_length, olm_pickle_account_length(account2));
    res = olm_pickle_account(account2, "secret_key", 10, pickle2, pickle_length);
    CHECK_EQ(pickle_length, res);

    CHECK_EQ_SIZE(pickle1, pickle2, pickle_length);

    const size_t junk_length = 1U;
    uint8_t *junk_pickle = test_checked_malloc(pickle_length + _olm_enc_output_length(junk_length));

    res = olm_pickle_account(account, "secret_key", 10, junk_pickle, pickle_length);
    CHECK_EQ(pickle_length, res);

    const size_t junk_pickle_length = add_junk_suffix_to_pickle(
        "secret_key",
        10,
        junk_pickle,
        pickle_length,
        junk_length
    );

    CHECK_EQ(
        SIZE_MAX,
        olm_unpickle_account(account, "secret_key", 10, junk_pickle, junk_pickle_length)
    );
    CHECK_EQ(OLM_PICKLE_EXTRA_DATA, olm_account_last_error_code(account));

    olm_clear_account(account2);
    olm_clear_account(account);
    free(junk_pickle);
    free(account_buffer2);
    free(pickle2);
    free(pickle1);
    free(ot_random);
    free(random);
    free(account_buffer);
}

static void test_old_account_unpickle_rejected(void **state)
{
    (void)state;

    uint8_t pickle[] =
        "x3h9er86ygvq56pM1yesdAxZou4ResPQC9Rszk/fhEL9JY/umtZ2N/foL/SUgVXS"
        "v0IxHHZTafYjDdzJU9xr8dQeBoOTGfV9E/lCqDGBnIlu7SZndqjEKXtzGyQr4sP4"
        "K/A/8TOu9iK2hDFszy6xETiousHnHgh2ZGbRUh4pQx+YMm8ZdNZeRnwFGLnrWyf9"
        "O5TmXua1FcU";

    uint8_t *account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *account = olm_account(account_buffer);
    CHECK_EQ(SIZE_MAX, olm_unpickle_account(account, "", 0, pickle, sizeof(pickle) - 1U));
    assert_string_equal("BAD_LEGACY_ACCOUNT_PICKLE", olm_account_last_error(account));

    olm_clear_account(account);
    free(account_buffer);
}

static void test_pickle_session(void **state)
{
    (void)state;

    test_mock_random mock_random_a = test_mock_random_init((uint8_t)'A', 0x00U);
    test_mock_random mock_random_b = test_mock_random_init((uint8_t)'B', 0x80U);

    uint8_t *a_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *a_account = olm_account(a_account_buffer);
    size_t a_random_len = olm_create_account_random_length(a_account);
    uint8_t *a_random = test_checked_malloc(a_random_len);
    test_mock_random_fill(&mock_random_a, a_random, a_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(a_account, a_random, a_random_len));

    uint8_t *b_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *b_account = olm_account(b_account_buffer);
    size_t b_random_len = olm_create_account_random_length(b_account);
    uint8_t *b_random = test_checked_malloc(b_random_len);
    test_mock_random_fill(&mock_random_b, b_random, b_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(b_account, b_random, b_random_len));

    size_t o_random_len = olm_account_generate_one_time_keys_random_length(b_account, 1);
    uint8_t *o_random = test_checked_malloc(o_random_len);
    test_mock_random_fill(&mock_random_b, o_random, o_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_one_time_keys(b_account, 1, o_random, o_random_len));

    size_t b_id_keys_len = olm_account_identity_keys_length(b_account);
    size_t b_ot_keys_len = olm_account_one_time_keys_length(b_account);
    uint8_t *b_id_keys = test_checked_malloc(b_id_keys_len);
    uint8_t *b_ot_keys = test_checked_malloc(b_ot_keys_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(b_account, b_id_keys, b_id_keys_len));
    CHECK_NE(SIZE_MAX, olm_account_one_time_keys(b_account, b_ot_keys, b_ot_keys_len));

    uint8_t *session_buffer = test_checked_malloc(olm_session_size());
    OlmSession *session = olm_session(session_buffer);
    size_t random2_len = olm_create_outbound_session_random_length(session);
    uint8_t *random2 = test_checked_malloc(random2_len);
    test_mock_random_fill(&mock_random_a, random2, random2_len);

    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            session,
            a_account,
            b_id_keys + 15,
            43,
            b_ot_keys + 25,
            43,
            random2,
            random2_len
        )
    );

    size_t pickle_length = olm_pickle_session_length(session);
    uint8_t *pickle1 = test_checked_malloc(pickle_length);
    size_t res = olm_pickle_session(session, "secret_key", 10, pickle1, pickle_length);
    CHECK_EQ(pickle_length, res);

    uint8_t *pickle2 = test_checked_malloc(pickle_length);
    memcpy(pickle2, pickle1, pickle_length);

    uint8_t *session_buffer2 = test_checked_malloc(olm_session_size());
    OlmSession *session2 = olm_session(session_buffer2);
    CHECK_NE(SIZE_MAX, olm_unpickle_session(session2, "secret_key", 10, pickle2, pickle_length));
    CHECK_EQ(pickle_length, olm_pickle_session_length(session2));
    res = olm_pickle_session(session2, "secret_key", 10, pickle2, pickle_length);
    CHECK_EQ(pickle_length, res);

    CHECK_EQ_SIZE(pickle1, pickle2, pickle_length);

    const size_t junk_length = 1U;
    uint8_t *junk_pickle = test_checked_malloc(pickle_length + _olm_enc_output_length(junk_length));

    res = olm_pickle_session(session, "secret_key", 10, junk_pickle, pickle_length);
    CHECK_EQ(pickle_length, res);

    const size_t junk_pickle_length = add_junk_suffix_to_pickle(
        "secret_key",
        10,
        junk_pickle,
        pickle_length,
        junk_length
    );

    CHECK_EQ(
        SIZE_MAX,
        olm_unpickle_session(session, "secret_key", 10, junk_pickle, junk_pickle_length)
    );
    CHECK_EQ(OLM_PICKLE_EXTRA_DATA, olm_session_last_error_code(session));

    olm_clear_session(session2);
    olm_clear_session(session);
    olm_clear_account(a_account);
    olm_clear_account(b_account);

    free(junk_pickle);
    free(session_buffer2);
    free(pickle2);
    free(pickle1);
    free(random2);
    free(b_ot_keys);
    free(b_id_keys);
    free(o_random);
    free(b_random);
    free(b_account_buffer);
    free(a_random);
    free(a_account_buffer);
    free(session_buffer);
}

static void test_loopback(void **state)
{
    (void)state;

    test_mock_random mock_random_a = test_mock_random_init((uint8_t)'A', 0x00U);
    test_mock_random mock_random_b = test_mock_random_init((uint8_t)'B', 0x80U);

    uint8_t *a_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *a_account = olm_account(a_account_buffer);
    size_t a_random_len = olm_create_account_random_length(a_account);
    uint8_t *a_random = test_checked_malloc(a_random_len);
    test_mock_random_fill(&mock_random_a, a_random, a_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(a_account, a_random, a_random_len));

    uint8_t *b_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *b_account = olm_account(b_account_buffer);
    size_t b_random_len = olm_create_account_random_length(b_account);
    uint8_t *b_random = test_checked_malloc(b_random_len);
    test_mock_random_fill(&mock_random_b, b_random, b_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(b_account, b_random, b_random_len));

    size_t o_random_len = olm_account_generate_one_time_keys_random_length(b_account, 42);
    uint8_t *o_random = test_checked_malloc(o_random_len);
    test_mock_random_fill(&mock_random_b, o_random, o_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_one_time_keys(b_account, 42, o_random, o_random_len));

    size_t a_id_keys_len = olm_account_identity_keys_length(a_account);
    uint8_t *a_id_keys = test_checked_malloc(a_id_keys_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(a_account, a_id_keys, a_id_keys_len));

    size_t b_id_keys_len = olm_account_identity_keys_length(b_account);
    size_t b_ot_keys_len = olm_account_one_time_keys_length(b_account);
    uint8_t *b_id_keys = test_checked_malloc(b_id_keys_len);
    uint8_t *b_ot_keys = test_checked_malloc(b_ot_keys_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(b_account, b_id_keys, b_id_keys_len));
    CHECK_NE(SIZE_MAX, olm_account_one_time_keys(b_account, b_ot_keys, b_ot_keys_len));

    uint8_t *a_session_buffer = test_checked_malloc(olm_session_size());
    OlmSession *a_session = olm_session(a_session_buffer);
    size_t a_rand_len = olm_create_outbound_session_random_length(a_session);
    uint8_t *a_rand = test_checked_malloc(a_rand_len);
    test_mock_random_fill(&mock_random_a, a_rand, a_rand_len);
    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            a_session,
            a_account,
            b_id_keys + 15,
            43,
            b_ot_keys + 25,
            43,
            a_rand,
            a_rand_len
        )
    );

    uint8_t plaintext[] = "Hello, World";
    size_t message_1_len = olm_encrypt_message_length(a_session, 12);
    uint8_t *message_1 = test_checked_malloc(message_1_len);
    size_t a_msg_rand_len = olm_encrypt_random_length(a_session);
    uint8_t *a_msg_random = test_checked_malloc(a_msg_rand_len);
    test_mock_random_fill(&mock_random_a, a_msg_random, a_msg_rand_len);
    CHECK_EQ((size_t)0U, olm_encrypt_message_type(a_session));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            a_session,
            plaintext,
            12,
            a_msg_random,
            a_msg_rand_len,
            message_1,
            message_1_len
        )
    );

    uint8_t *tmp_message_1 = test_checked_malloc(message_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    uint8_t *b_session_buffer = test_checked_malloc(olm_session_size());
    OlmSession *b_session = olm_session(b_session_buffer);
    CHECK_NE(SIZE_MAX, olm_create_inbound_session(b_session, b_account, tmp_message_1, message_1_len));

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ((size_t)1U, olm_matches_inbound_session(b_session, tmp_message_1, message_1_len));

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)1U,
        olm_matches_inbound_session_from(
            b_session,
            a_id_keys + 15,
            43,
            tmp_message_1,
            message_1_len
        )
    );

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)0U,
        olm_matches_inbound_session_from(
            b_session,
            b_id_keys + 15,
            43,
            tmp_message_1,
            message_1_len
        )
    );

    memcpy(tmp_message_1, message_1, message_1_len);
    size_t plaintext_1_len = olm_decrypt_max_plaintext_length(
        b_session,
        0,
        tmp_message_1,
        message_1_len
    );
    uint8_t *plaintext_1 = test_checked_malloc(plaintext_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)12U,
        olm_decrypt(
            b_session,
            0,
            tmp_message_1,
            message_1_len,
            plaintext_1,
            plaintext_1_len
        )
    );
    CHECK_EQ_SIZE(plaintext, plaintext_1, 12);

    size_t message_2_len = olm_encrypt_message_length(b_session, 12);
    uint8_t *message_2 = test_checked_malloc(message_2_len);
    size_t b_msg_rand_len = olm_encrypt_random_length(b_session);
    uint8_t *b_msg_random = test_checked_malloc(b_msg_rand_len);
    test_mock_random_fill(&mock_random_b, b_msg_random, b_msg_rand_len);
    CHECK_EQ((size_t)1U, olm_encrypt_message_type(b_session));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            b_session,
            plaintext,
            12,
            b_msg_random,
            b_msg_rand_len,
            message_2,
            message_2_len
        )
    );

    uint8_t *tmp_message_2 = test_checked_malloc(message_2_len);
    memcpy(tmp_message_2, message_2, message_2_len);
    size_t plaintext_2_len = olm_decrypt_max_plaintext_length(
        a_session,
        1,
        tmp_message_2,
        message_2_len
    );
    uint8_t *plaintext_2 = test_checked_malloc(plaintext_2_len);
    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ(
        (size_t)12U,
        olm_decrypt(
            a_session,
            1,
            tmp_message_2,
            message_2_len,
            plaintext_2,
            plaintext_2_len
        )
    );

    CHECK_EQ_SIZE(plaintext, plaintext_2, 12);

    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ(
        SIZE_MAX,
        olm_decrypt(
            a_session,
            1,
            tmp_message_2,
            message_2_len,
            plaintext_2,
            plaintext_2_len
        )
    );

    size_t a_session_id_len = olm_session_id_length(a_session);
    uint8_t *a_session_id = test_checked_malloc(a_session_id_len);
    CHECK_NE(SIZE_MAX, olm_session_id(a_session, a_session_id, a_session_id_len));

    size_t b_session_id_len = olm_session_id_length(b_session);
    uint8_t *b_session_id = test_checked_malloc(b_session_id_len);
    CHECK_NE(SIZE_MAX, olm_session_id(b_session, b_session_id, b_session_id_len));

    CHECK_EQ(a_session_id_len, b_session_id_len);
    CHECK_EQ_SIZE(a_session_id, b_session_id, b_session_id_len);

    olm_clear_session(a_session);
    olm_clear_session(b_session);
    olm_clear_account(a_account);
    olm_clear_account(b_account);

    free(b_session_id);
    free(a_session_id);
    free(plaintext_2);
    free(tmp_message_2);
    free(b_msg_random);
    free(message_2);
    free(plaintext_1);
    free(tmp_message_1);
    free(a_msg_random);
    free(message_1);
    free(a_rand);
    free(a_session_buffer);
    free(b_ot_keys);
    free(b_id_keys);
    free(a_id_keys);
    free(o_random);
    free(b_random);
    free(b_account_buffer);
    free(a_random);
    free(a_account_buffer);
    free(b_session_buffer);
}

static void test_more_messages(void **state)
{
    (void)state;

    test_mock_random mock_random_a = test_mock_random_init((uint8_t)'A', 0x00U);
    test_mock_random mock_random_b = test_mock_random_init((uint8_t)'B', 0x80U);

    uint8_t *a_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *a_account = olm_account(a_account_buffer);
    size_t a_random_len = olm_create_account_random_length(a_account);
    uint8_t *a_random = test_checked_malloc(a_random_len);
    test_mock_random_fill(&mock_random_a, a_random, a_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(a_account, a_random, a_random_len));

    uint8_t *b_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *b_account = olm_account(b_account_buffer);
    size_t b_random_len = olm_create_account_random_length(b_account);
    uint8_t *b_random = test_checked_malloc(b_random_len);
    test_mock_random_fill(&mock_random_b, b_random, b_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(b_account, b_random, b_random_len));

    size_t o_random_len = olm_account_generate_one_time_keys_random_length(b_account, 42);
    uint8_t *o_random = test_checked_malloc(o_random_len);
    test_mock_random_fill(&mock_random_b, o_random, o_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_one_time_keys(b_account, 42, o_random, o_random_len));

    size_t b_id_keys_len = olm_account_identity_keys_length(b_account);
    size_t b_ot_keys_len = olm_account_one_time_keys_length(b_account);
    uint8_t *b_id_keys = test_checked_malloc(b_id_keys_len);
    uint8_t *b_ot_keys = test_checked_malloc(b_ot_keys_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(b_account, b_id_keys, b_id_keys_len));
    CHECK_NE(SIZE_MAX, olm_account_one_time_keys(b_account, b_ot_keys, b_ot_keys_len));

    uint8_t *a_session_buffer = test_checked_malloc(olm_session_size());
    OlmSession *a_session = olm_session(a_session_buffer);
    size_t a_rand_len = olm_create_outbound_session_random_length(a_session);
    uint8_t *a_rand = test_checked_malloc(a_rand_len);
    test_mock_random_fill(&mock_random_a, a_rand, a_rand_len);
    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            a_session,
            a_account,
            b_id_keys + 15,
            43,
            b_ot_keys + 25,
            43,
            a_rand,
            a_rand_len
        )
    );

    uint8_t plaintext[] = "Hello, World";
    size_t message_1_len = olm_encrypt_message_length(a_session, 12);
    uint8_t *message_1 = test_checked_malloc(message_1_len);
    size_t a_msg_rand_len = olm_encrypt_random_length(a_session);
    uint8_t *a_msg_random = test_checked_malloc(a_msg_rand_len);
    test_mock_random_fill(&mock_random_a, a_msg_random, a_msg_rand_len);
    CHECK_EQ((size_t)0U, olm_encrypt_message_type(a_session));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            a_session,
            plaintext,
            12,
            a_msg_random,
            a_msg_rand_len,
            message_1,
            message_1_len
        )
    );

    uint8_t *tmp_message_1 = test_checked_malloc(message_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    uint8_t *b_session_buffer = test_checked_malloc(olm_session_size());
    OlmSession *b_session = olm_session(b_session_buffer);
    CHECK_NE(SIZE_MAX, olm_create_inbound_session(b_session, b_account, tmp_message_1, message_1_len));

    memcpy(tmp_message_1, message_1, message_1_len);
    size_t plaintext_1_len = olm_decrypt_max_plaintext_length(
        b_session,
        0,
        tmp_message_1,
        message_1_len
    );
    uint8_t *plaintext_1 = test_checked_malloc(plaintext_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)12U,
        olm_decrypt(
            b_session,
            0,
            tmp_message_1,
            message_1_len,
            plaintext_1,
            plaintext_1_len
        )
    );

    unsigned i;
    for (i = 0; i < 8U; ++i) {
        size_t msg_a_len = olm_encrypt_message_length(a_session, 12);
        uint8_t *msg_a = test_checked_malloc(msg_a_len);
        size_t rnd_a_len = olm_encrypt_random_length(a_session);
        uint8_t *rnd_a = test_checked_malloc(rnd_a_len);
        test_mock_random_fill(&mock_random_a, rnd_a, rnd_a_len);
        size_t type_a = olm_encrypt_message_type(a_session);
        CHECK_NE(SIZE_MAX, olm_encrypt(a_session, plaintext, 12, rnd_a, rnd_a_len, msg_a, msg_a_len));

        uint8_t *tmp_a = test_checked_malloc(msg_a_len);
        memcpy(tmp_a, msg_a, msg_a_len);
        size_t out_a_len = olm_decrypt_max_plaintext_length(b_session, type_a, tmp_a, msg_a_len);
        uint8_t *out_a = test_checked_malloc(out_a_len);
        memcpy(tmp_a, msg_a, msg_a_len);
        CHECK_EQ((size_t)12U, olm_decrypt(b_session, type_a, tmp_a, msg_a_len, out_a, out_a_len));

        size_t msg_b_len = olm_encrypt_message_length(b_session, 12);
        uint8_t *msg_b = test_checked_malloc(msg_b_len);
        size_t rnd_b_len = olm_encrypt_random_length(b_session);
        uint8_t *rnd_b = test_checked_malloc(rnd_b_len);
        test_mock_random_fill(&mock_random_b, rnd_b, rnd_b_len);
        size_t type_b = olm_encrypt_message_type(b_session);
        CHECK_NE(SIZE_MAX, olm_encrypt(b_session, plaintext, 12, rnd_b, rnd_b_len, msg_b, msg_b_len));

        uint8_t *tmp_b = test_checked_malloc(msg_b_len);
        memcpy(tmp_b, msg_b, msg_b_len);
        size_t out_b_len = olm_decrypt_max_plaintext_length(a_session, type_b, tmp_b, msg_b_len);
        uint8_t *out_b = test_checked_malloc(out_b_len);
        memcpy(tmp_b, msg_b, msg_b_len);
        CHECK_EQ((size_t)12U, olm_decrypt(a_session, type_b, tmp_b, msg_b_len, out_b, out_b_len));

        free(out_b);
        free(tmp_b);
        free(rnd_b);
        free(msg_b);
        free(out_a);
        free(tmp_a);
        free(rnd_a);
        free(msg_a);
    }

    olm_clear_session(a_session);
    olm_clear_session(b_session);
    olm_clear_account(a_account);
    olm_clear_account(b_account);

    free(plaintext_1);
    free(tmp_message_1);
    free(a_msg_random);
    free(message_1);
    free(a_rand);
    free(a_session_buffer);
    free(b_ot_keys);
    free(b_id_keys);
    free(o_random);
    free(b_random);
    free(b_account_buffer);
    free(a_random);
    free(a_account_buffer);
    free(b_session_buffer);
}

static void test_fallback_key(void **state)
{
    (void)state;

    test_mock_random mock_random_a = test_mock_random_init((uint8_t)'A', 0x00U);
    test_mock_random mock_random_b = test_mock_random_init((uint8_t)'B', 0x80U);

    uint8_t *a_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *a_account = olm_account(a_account_buffer);
    size_t a_random_len = olm_create_account_random_length(a_account);
    uint8_t *a_random = test_checked_malloc(a_random_len);
    test_mock_random_fill(&mock_random_a, a_random, a_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(a_account, a_random, a_random_len));

    uint8_t *b_account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *b_account = olm_account(b_account_buffer);
    size_t b_random_len = olm_create_account_random_length(b_account);
    uint8_t *b_random = test_checked_malloc(b_random_len);
    test_mock_random_fill(&mock_random_b, b_random, b_random_len);
    CHECK_NE(SIZE_MAX, olm_create_account(b_account, b_random, b_random_len));

    size_t a_id_keys_len = olm_account_identity_keys_length(a_account);
    uint8_t *a_id_keys = test_checked_malloc(a_id_keys_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(a_account, a_id_keys, a_id_keys_len));

    size_t b_id_keys_len = olm_account_identity_keys_length(b_account);
    uint8_t *b_id_keys = test_checked_malloc(b_id_keys_len);

    size_t f_random_len = olm_account_generate_fallback_key_random_length(b_account);
    uint8_t *f_random = test_checked_malloc(f_random_len);
    test_mock_random_fill(&mock_random_b, f_random, f_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_fallback_key(b_account, f_random, f_random_len));

    size_t b_fb_key_len = olm_account_unpublished_fallback_key_length(b_account);
    uint8_t *b_fb_key = test_checked_malloc(b_fb_key_len);
    CHECK_NE(SIZE_MAX, olm_account_identity_keys(b_account, b_id_keys, b_id_keys_len));
    CHECK_NE(SIZE_MAX, olm_account_unpublished_fallback_key(b_account, b_fb_key, b_fb_key_len));

    uint8_t *a_session1_buffer = test_checked_malloc(olm_session_size());
    OlmSession *a_session1 = olm_session(a_session1_buffer);
    size_t a_rand_len = olm_create_outbound_session_random_length(a_session1);
    uint8_t *a_rand = test_checked_malloc(a_rand_len);
    test_mock_random_fill(&mock_random_a, a_rand, a_rand_len);
    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            a_session1,
            a_account,
            b_id_keys + 15,
            43,
            b_fb_key + 25,
            43,
            a_rand,
            a_rand_len
        )
    );

    uint8_t plaintext[] = "Hello, World";
    size_t message_1_len = olm_encrypt_message_length(a_session1, 12);
    uint8_t *message_1 = test_checked_malloc(message_1_len);
    size_t a_msg_rand_len = olm_encrypt_random_length(a_session1);
    uint8_t *a_msg_random = test_checked_malloc(a_msg_rand_len);
    test_mock_random_fill(&mock_random_a, a_msg_random, a_msg_rand_len);
    CHECK_EQ((size_t)0U, olm_encrypt_message_type(a_session1));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            a_session1,
            plaintext,
            12,
            a_msg_random,
            a_msg_rand_len,
            message_1,
            message_1_len
        )
    );

    uint8_t *tmp_message_1 = test_checked_malloc(message_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    uint8_t *b_session1_buffer = test_checked_malloc(olm_session_size());
    OlmSession *b_session1 = olm_session(b_session1_buffer);
    CHECK_NE(SIZE_MAX, olm_create_inbound_session(b_session1, b_account, tmp_message_1, message_1_len));

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ((size_t)1U, olm_matches_inbound_session(b_session1, tmp_message_1, message_1_len));

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)1U,
        olm_matches_inbound_session_from(
            b_session1,
            a_id_keys + 15,
            43,
            tmp_message_1,
            message_1_len
        )
    );

    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)0U,
        olm_matches_inbound_session_from(
            b_session1,
            b_id_keys + 15,
            43,
            tmp_message_1,
            message_1_len
        )
    );

    memcpy(tmp_message_1, message_1, message_1_len);
    size_t plaintext_1_len = olm_decrypt_max_plaintext_length(
        b_session1,
        0,
        tmp_message_1,
        message_1_len
    );
    uint8_t *plaintext_1 = test_checked_malloc(plaintext_1_len);
    memcpy(tmp_message_1, message_1, message_1_len);
    CHECK_EQ(
        (size_t)12U,
        olm_decrypt(
            b_session1,
            0,
            tmp_message_1,
            message_1_len,
            plaintext_1,
            plaintext_1_len
        )
    );
    CHECK_EQ_SIZE(plaintext, plaintext_1, 12);

    test_mock_random_fill(&mock_random_b, f_random, f_random_len);
    CHECK_NE(SIZE_MAX, olm_account_generate_fallback_key(b_account, f_random, f_random_len));

    uint8_t *a_session2_buffer = test_checked_malloc(olm_session_size());
    OlmSession *a_session2 = olm_session(a_session2_buffer);
    test_mock_random_fill(&mock_random_a, a_rand, a_rand_len);
    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            a_session2,
            a_account,
            b_id_keys + 15,
            43,
            b_fb_key + 25,
            43,
            a_rand,
            a_rand_len
        )
    );

    size_t message_2_len = olm_encrypt_message_length(a_session2, 12);
    uint8_t *message_2 = test_checked_malloc(message_2_len);
    test_mock_random_fill(&mock_random_a, a_msg_random, a_msg_rand_len);
    CHECK_EQ((size_t)0U, olm_encrypt_message_type(a_session2));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            a_session2,
            plaintext,
            12,
            a_msg_random,
            a_msg_rand_len,
            message_2,
            message_2_len
        )
    );

    uint8_t *tmp_message_2 = test_checked_malloc(message_2_len);
    memcpy(tmp_message_2, message_2, message_2_len);
    uint8_t *b_session2_buffer = test_checked_malloc(olm_session_size());
    OlmSession *b_session2 = olm_session(b_session2_buffer);
    CHECK_NE(SIZE_MAX, olm_create_inbound_session(b_session2, b_account, tmp_message_2, message_2_len));

    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ((size_t)1U, olm_matches_inbound_session(b_session2, tmp_message_2, message_2_len));

    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ(
        (size_t)1U,
        olm_matches_inbound_session_from(
            b_session2,
            a_id_keys + 15,
            43,
            tmp_message_2,
            message_2_len
        )
    );

    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ(
        (size_t)0U,
        olm_matches_inbound_session_from(
            b_session2,
            b_id_keys + 15,
            43,
            tmp_message_2,
            message_2_len
        )
    );

    memcpy(tmp_message_2, message_2, message_2_len);
    size_t plaintext_2_len = olm_decrypt_max_plaintext_length(
        b_session2,
        0,
        tmp_message_2,
        message_2_len
    );
    uint8_t *plaintext_2 = test_checked_malloc(plaintext_2_len);
    memcpy(tmp_message_2, message_2, message_2_len);
    CHECK_EQ(
        (size_t)12U,
        olm_decrypt(
            b_session2,
            0,
            tmp_message_2,
            message_2_len,
            plaintext_2,
            plaintext_2_len
        )
    );
    CHECK_EQ_SIZE(plaintext, plaintext_2, 12);

    olm_account_forget_old_fallback_key(b_account);

    uint8_t *a_session3_buffer = test_checked_malloc(olm_session_size());
    OlmSession *a_session3 = olm_session(a_session3_buffer);
    test_mock_random_fill(&mock_random_a, a_rand, a_rand_len);
    CHECK_NE(
        SIZE_MAX,
        olm_create_outbound_session(
            a_session3,
            a_account,
            b_id_keys + 15,
            43,
            b_fb_key + 25,
            43,
            a_rand,
            a_rand_len
        )
    );

    size_t message_3_len = olm_encrypt_message_length(a_session3, 12);
    uint8_t *message_3 = test_checked_malloc(message_3_len);
    test_mock_random_fill(&mock_random_a, a_msg_random, a_msg_rand_len);
    CHECK_EQ((size_t)0U, olm_encrypt_message_type(a_session3));
    CHECK_NE(
        SIZE_MAX,
        olm_encrypt(
            a_session3,
            plaintext,
            12,
            a_msg_random,
            a_msg_rand_len,
            message_3,
            message_3_len
        )
    );

    uint8_t *tmp_message_3 = test_checked_malloc(message_3_len);
    memcpy(tmp_message_3, message_3, message_3_len);
    uint8_t *b_session3_buffer = test_checked_malloc(olm_session_size());
    OlmSession *b_session3 = olm_session(b_session3_buffer);
    CHECK_EQ(SIZE_MAX, olm_create_inbound_session(b_session3, b_account, tmp_message_3, message_3_len));
    assert_string_equal("BAD_MESSAGE_KEY_ID", olm_session_last_error(b_session3));

    olm_clear_session(a_session1);
    olm_clear_session(a_session2);
    olm_clear_session(a_session3);
    olm_clear_session(b_session1);
    olm_clear_session(b_session2);
    olm_clear_session(b_session3);
    olm_clear_account(a_account);
    olm_clear_account(b_account);

    free(b_session3_buffer);
    free(tmp_message_3);
    free(message_3);
    free(a_session3_buffer);
    free(plaintext_2);
    free(b_session2_buffer);
    free(tmp_message_2);
    free(message_2);
    free(a_session2_buffer);
    free(plaintext_1);
    free(b_session1_buffer);
    free(tmp_message_1);
    free(a_msg_random);
    free(message_1);
    free(a_rand);
    free(a_session1_buffer);
    free(b_fb_key);
    free(f_random);
    free(b_id_keys);
    free(a_id_keys);
    free(b_random);
    free(b_account_buffer);
    free(a_random);
    free(a_account_buffer);
}

static void test_old_account_v3_unpickle(void **state)
{
    (void)state;

    uint8_t pickle[] =
        "0mSqVn3duHffbhaTbFgW+4JPlcRoqT7z0x4mQ72N+g+eSAk5sgcWSoDzKpMazgcB"
        "46ItEpChthVHTGRA6PD3dly0dUs4ji7VtWTa+1tUv1UbxP92uYf1Ae3fomX0yAoH"
        "OjSrz1+RmuXr+At8jsmsf260sKvhB6LnI3qYsrw6AAtpgk5d5xZd66sLxvvYUuai"
        "+SmmcmT0bHosLTuDiiB9amBvPKkUKtKZmaEAl5ULrgnJygp1/FnwzVfSrw6PBSX6"
        "ZaUEZHZGX1iI6/WjbHqlTQeOQjtaSsPaL5XXpteS9dFsuaANAj+8ks7Ut2Hwg/JP"
        "Ih/ERYBwiMh9Mt3zSAG0NkvgUkcdipKxoSNZ6t+TkqZrN6jG6VCbx+4YpJO24iJb"
        "ShZy8n79aePIgIsxX94ycsTq1ic38sCRSkWGVbCSRkPloHW7ZssLHA";

    uint8_t expected_fallback[] =
        "{\"curve25519\":{\"AAAAAQ\":\"dr98y6VOWt6lJaQgFVZeWY2ky76mga9MEMbdItJTdng\"}}";
    uint8_t expected_unpublished_fallback[] =
        "{\"curve25519\":{}}";

    uint8_t *account_buffer = test_checked_malloc(olm_account_size());
    OlmAccount *account = olm_account(account_buffer);
    CHECK_NE(SIZE_MAX, olm_unpickle_account(account, "", 0, pickle, sizeof(pickle) - 1U));

    size_t fallback_len = olm_account_fallback_key_length(account);
    uint8_t *fallback = test_checked_malloc(fallback_len);
    size_t len = olm_account_fallback_key(account, fallback, fallback_len);
    CHECK_EQ_SIZE(expected_fallback, fallback, len);
    len = olm_account_unpublished_fallback_key(account, fallback, fallback_len);
    CHECK_EQ_SIZE(expected_unpublished_fallback, fallback, len);

    olm_clear_account(account);
    free(fallback);
    free(account_buffer);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pickle_account),
        cmocka_unit_test(test_old_account_unpickle_rejected),
        cmocka_unit_test(test_pickle_session),
        cmocka_unit_test(test_loopback),
        cmocka_unit_test(test_more_messages),
        cmocka_unit_test(test_fallback_key),
        cmocka_unit_test(test_old_account_v3_unpickle),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
