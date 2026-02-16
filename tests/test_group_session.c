/* See LICENSE file for copyright and license details. */
#include "libce/inbound_group_session.h"
#include "libce/outbound_group_session.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"
#include "utils.h"

static void test_pickle_outbound_group_session(void **state)
{
    (void)state;

    size_t session_size = olm_outbound_group_session_size();
    uint8_t *memory = test_checked_malloc(session_size);
    OlmOutboundGroupSession *session = olm_outbound_group_session(memory);

    size_t pickle_length = olm_pickle_outbound_group_session_length(session);
    uint8_t *pickle1 = test_checked_malloc(pickle_length);
    size_t res = olm_pickle_outbound_group_session(
        session,
        "secret_key",
        10,
        pickle1,
        pickle_length
    );
    CHECK_EQ(pickle_length, res);

    uint8_t *pickle2 = test_checked_malloc(pickle_length);
    memcpy(pickle2, pickle1, pickle_length);

    uint8_t *memory2 = test_checked_malloc(session_size);
    OlmOutboundGroupSession *session2 = olm_outbound_group_session(memory2);
    res = olm_unpickle_outbound_group_session(
        session2,
        "secret_key",
        10,
        pickle2,
        pickle_length
    );
    CHECK_NE(SIZE_MAX, res);
    CHECK_EQ(pickle_length, olm_pickle_outbound_group_session_length(session2));
    res = olm_pickle_outbound_group_session(
        session2,
        "secret_key",
        10,
        pickle2,
        pickle_length
    );
    CHECK_EQ(pickle_length, res);

    CHECK_EQ_SIZE(pickle1, pickle2, pickle_length);

    const size_t junk_length = 1U;
    uint8_t *junk_pickle = test_checked_malloc(pickle_length + _olm_enc_output_length(junk_length));

    CHECK_EQ(
        pickle_length,
        olm_pickle_outbound_group_session(
            session,
            "secret_key",
            10,
            junk_pickle,
            pickle_length
        )
    );

    const size_t junk_pickle_length = add_junk_suffix_to_pickle(
        "secret_key",
        10,
        junk_pickle,
        pickle_length,
        junk_length
    );

    CHECK_EQ(
        SIZE_MAX,
        olm_unpickle_outbound_group_session(
            session,
            "secret_key",
            10,
            junk_pickle,
            junk_pickle_length
        )
    );
    CHECK_EQ(OLM_PICKLE_EXTRA_DATA, olm_outbound_group_session_last_error_code(session));

    olm_clear_outbound_group_session(session);
    olm_clear_outbound_group_session(session2);
    free(junk_pickle);
    free(pickle2);
    free(pickle1);
    free(memory2);
    free(memory);
}

static void test_pickle_inbound_group_session(void **state)
{
    (void)state;

    size_t session_size = olm_inbound_group_session_size();
    uint8_t *memory = test_checked_malloc(session_size);
    OlmInboundGroupSession *session = olm_inbound_group_session(memory);

    size_t pickle_length = olm_pickle_inbound_group_session_length(session);
    uint8_t *pickle1 = test_checked_malloc(pickle_length);
    size_t res = olm_pickle_inbound_group_session(
        session,
        "secret_key",
        10,
        pickle1,
        pickle_length
    );
    CHECK_EQ(pickle_length, res);

    uint8_t *pickle2 = test_checked_malloc(pickle_length);
    memcpy(pickle2, pickle1, pickle_length);

    uint8_t *memory2 = test_checked_malloc(session_size);
    OlmInboundGroupSession *session2 = olm_inbound_group_session(memory2);
    res = olm_unpickle_inbound_group_session(
        session2,
        "secret_key",
        10,
        pickle2,
        pickle_length
    );
    CHECK_NE(SIZE_MAX, res);
    CHECK_EQ(pickle_length, olm_pickle_inbound_group_session_length(session2));
    res = olm_pickle_inbound_group_session(
        session2,
        "secret_key",
        10,
        pickle2,
        pickle_length
    );
    CHECK_EQ(pickle_length, res);

    CHECK_EQ_SIZE(pickle1, pickle2, pickle_length);

    const size_t junk_length = 1U;
    uint8_t *junk_pickle = test_checked_malloc(pickle_length + _olm_enc_output_length(junk_length));

    CHECK_EQ(
        pickle_length,
        olm_pickle_inbound_group_session(
            session,
            "secret_key",
            10,
            junk_pickle,
            pickle_length
        )
    );

    const size_t junk_pickle_length = add_junk_suffix_to_pickle(
        "secret_key",
        10,
        junk_pickle,
        pickle_length,
        junk_length
    );

    CHECK_EQ(
        SIZE_MAX,
        olm_unpickle_inbound_group_session(
            session,
            "secret_key",
            10,
            junk_pickle,
            junk_pickle_length
        )
    );
    CHECK_EQ(OLM_PICKLE_EXTRA_DATA, olm_inbound_group_session_last_error_code(session));

    olm_clear_inbound_group_session(session);
    olm_clear_inbound_group_session(session2);
    free(junk_pickle);
    free(pickle2);
    free(pickle1);
    free(memory2);
    free(memory);
}

static void test_group_message_send_receive(void **state)
{
    (void)state;

    uint8_t random_bytes[] =
        "0123456789ABDEF0123456789ABCDEF"
        "0123456789ABDEF0123456789ABCDEF"
        "0123456789ABDEF0123456789ABCDEF"
        "0123456789ABDEF0123456789ABCDEF"
        "0123456789ABDEF0123456789ABCDEF"
        "0123456789ABDEF0123456789ABCDEF";

    size_t out_session_size = olm_outbound_group_session_size();
    uint8_t *out_memory = test_checked_malloc(out_session_size);
    OlmOutboundGroupSession *session = olm_outbound_group_session(out_memory);

    CHECK_EQ((size_t)160U, olm_init_outbound_group_session_random_length(session));

    size_t res = olm_init_outbound_group_session(session, random_bytes, sizeof(random_bytes));
    CHECK_EQ((size_t)0U, res);

    CHECK_EQ(0U, olm_outbound_group_session_message_index(session));
    size_t session_key_len = olm_outbound_group_session_key_length(session);
    uint8_t *session_key = test_checked_malloc(session_key_len);
    CHECK_EQ(session_key_len, olm_outbound_group_session_key(session, session_key, session_key_len));

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1U;

    size_t msglen = olm_group_encrypt_message_length(session, plaintext_length);
    uint8_t *msg = test_checked_malloc(msglen);
    res = olm_group_encrypt(session, plaintext, plaintext_length, msg, msglen);
    CHECK_EQ(msglen, res);
    CHECK_EQ(1U, olm_outbound_group_session_message_index(session));

    size_t in_session_size = olm_inbound_group_session_size();
    uint8_t *in_memory = test_checked_malloc(in_session_size);
    OlmInboundGroupSession *inbound_session = olm_inbound_group_session(in_memory);

    CHECK_EQ(0, olm_inbound_group_session_is_verified(inbound_session));

    res = olm_init_inbound_group_session(inbound_session, session_key, session_key_len);
    CHECK_EQ((size_t)0U, res);
    CHECK_EQ(1, olm_inbound_group_session_is_verified(inbound_session));

    size_t out_session_id_len = olm_outbound_group_session_id_length(session);
    uint8_t *out_session_id = test_checked_malloc(out_session_id_len);
    CHECK_EQ(out_session_id_len, olm_outbound_group_session_id(session, out_session_id, out_session_id_len));

    size_t in_session_id_len = olm_inbound_group_session_id_length(inbound_session);
    uint8_t *in_session_id = test_checked_malloc(in_session_id_len);
    CHECK_EQ(in_session_id_len, olm_inbound_group_session_id(inbound_session, in_session_id, in_session_id_len));

    CHECK_EQ(in_session_id_len, out_session_id_len);
    CHECK_EQ_SIZE(out_session_id, in_session_id, in_session_id_len);

    uint8_t *msgcopy = test_checked_malloc(msglen);
    memcpy(msgcopy, msg, msglen);
    size_t max_plaintext = olm_group_decrypt_max_plaintext_length(inbound_session, msgcopy, msglen);
    uint8_t *plaintext_buf = test_checked_malloc(max_plaintext);
    uint32_t message_index;
    res = olm_group_decrypt(inbound_session, msg, msglen, plaintext_buf, max_plaintext, &message_index);
    CHECK_EQ(plaintext_length, res);
    CHECK_EQ_SIZE(plaintext, plaintext_buf, res);
    CHECK_EQ((uint32_t)0U, message_index);

    olm_clear_outbound_group_session(session);
    olm_clear_inbound_group_session(inbound_session);
    free(plaintext_buf);
    free(msgcopy);
    free(in_session_id);
    free(out_session_id);
    free(in_memory);
    free(msg);
    free(session_key);
    free(out_memory);
}

static void test_inbound_group_session_export_import(void **state)
{
    (void)state;

    uint8_t session_key[] =
        "AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM"
        "DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND"
        "U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMw0bdg1BDq4Px/slBow06q8n/B9WBfw"
        "WYyNOB8DlUmXGGwrFmaSb9bR/eY8xgERrxmP07hFmD9uqA2p8PMHdnV5ysmgufE6oLZ5+"
        "8/mWQOW3VVTnDIlnwd8oHUYRuk8TCQ";

    const uint8_t message[] =
        "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8F4+qjMaFlnIXusJZX3r8LnRORG9T3D"
        "XFdbVuvIWrLyRfm4i8QRbe8VPwGRFG57B1CtmxanuP8bHtnnYqlwPsD";
    const size_t msglen = sizeof(message) - 1U;

    size_t size = olm_inbound_group_session_size();
    uint8_t *session_memory1 = test_checked_malloc(size);
    OlmInboundGroupSession *session1 = olm_inbound_group_session(session_memory1);
    CHECK_EQ(0, olm_inbound_group_session_is_verified(session1));

    size_t res = olm_init_inbound_group_session(session1, session_key, sizeof(session_key) - 1U);
    CHECK_EQ((size_t)0U, res);
    CHECK_EQ(1, olm_inbound_group_session_is_verified(session1));

    uint8_t *msgcopy = test_checked_malloc(msglen);
    memcpy(msgcopy, message, msglen);
    size = olm_group_decrypt_max_plaintext_length(session1, msgcopy, msglen);
    uint8_t *plaintext_buf = test_checked_malloc(size);
    uint32_t message_index;
    memcpy(msgcopy, message, msglen);
    res = olm_group_decrypt(session1, msgcopy, msglen, plaintext_buf, size, &message_index);
    CHECK_EQ((size_t)7U, res);
    CHECK_EQ_SIZE((const uint8_t *)"Message", plaintext_buf, res);
    CHECK_EQ((uint32_t)0U, message_index);

    size_t export_len = olm_export_inbound_group_session_length(session1);
    uint8_t *export_memory = test_checked_malloc(export_len);
    res = olm_export_inbound_group_session(session1, export_memory, export_len, 0);
    CHECK_EQ(export_len, res);

    olm_clear_inbound_group_session(session1);

    size = olm_inbound_group_session_size();
    uint8_t *session_memory2 = test_checked_malloc(size);
    OlmInboundGroupSession *session2 = olm_inbound_group_session(session_memory2);
    res = olm_import_inbound_group_session(session2, export_memory, export_len);
    CHECK_EQ((size_t)0U, res);
    CHECK_EQ(0, olm_inbound_group_session_is_verified(session2));

    memcpy(msgcopy, message, msglen);
    size = olm_group_decrypt_max_plaintext_length(session2, msgcopy, msglen);
    uint8_t *plaintext_buf2 = test_checked_malloc(size);
    memcpy(msgcopy, message, msglen);
    res = olm_group_decrypt(session2, msgcopy, msglen, plaintext_buf2, size, &message_index);
    CHECK_EQ((size_t)7U, res);
    CHECK_EQ_SIZE((const uint8_t *)"Message", plaintext_buf2, res);
    CHECK_EQ((uint32_t)0U, message_index);
    CHECK_EQ(1, olm_inbound_group_session_is_verified(session2));

    olm_clear_inbound_group_session(session2);
    free(plaintext_buf2);
    free(session_memory2);
    free(export_memory);
    free(plaintext_buf);
    free(msgcopy);
    free(session_memory1);
}

static void test_invalid_signature_group_message(void **state)
{
    (void)state;

    uint8_t plaintext[] = "Message";
    size_t plaintext_length = sizeof(plaintext) - 1U;

    uint8_t session_key[] =
        "AgAAAAAwMTIzNDU2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMzQ1Njc4OUFCREVGM"
        "DEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkRFRjAxMjM0NTY3ODlBQkNERUYwMTIzND"
        "U2Nzg5QUJERUYwMTIzNDU2Nzg5QUJDREVGMDEyMztqJ7zOtqQtYqOo0CpvDXNlMhV3HeJ"
        "DpjrASKGLWdop4lx1cSN3Xv1TgfLPW8rhGiW+hHiMxd36nRuxscNv9k4oJA/KP+o0mi1w"
        "v44StrEJ1wwx9WZHBUIWkQbaBSuBDw";

    uint8_t message[] =
        "AwgAEhAcbh6UpbByoyZxufQ+h2B+8XHMjhR69G8nP4pNZGl/3QMgrzCZPmP+F2aPLyKPz"
        "xRPBMUkeXRJ6Iqm5NeOdx2eERgTW7P20CM+lL3Xpk+ZUOOPvsSQNaAL";
    size_t msglen = sizeof(message) - 1U;

    size_t size = olm_inbound_group_session_size();
    uint8_t *inbound_session_memory = test_checked_malloc(size);
    OlmInboundGroupSession *inbound_session = olm_inbound_group_session(inbound_session_memory);

    size_t res = olm_init_inbound_group_session(inbound_session, session_key, sizeof(session_key) - 1U);
    CHECK_EQ((size_t)0U, res);

    uint8_t *msgcopy = test_checked_malloc(msglen);
    memcpy(msgcopy, message, msglen);
    size = olm_group_decrypt_max_plaintext_length(inbound_session, msgcopy, msglen);

    memcpy(msgcopy, message, msglen);
    uint8_t *plaintext_buf = test_checked_malloc(size);
    uint32_t message_index;
    res = olm_group_decrypt(inbound_session, msgcopy, msglen, plaintext_buf, size, &message_index);
    CHECK_EQ((uint32_t)0U, message_index);
    CHECK_EQ(plaintext_length, res);
    CHECK_EQ_SIZE(plaintext, plaintext_buf, res);

    message[msglen - 1U] = (uint8_t)'E';
    memcpy(msgcopy, message, msglen);
    CHECK_EQ(size, olm_group_decrypt_max_plaintext_length(inbound_session, msgcopy, msglen));

    memcpy(msgcopy, message, msglen);
    res = olm_group_decrypt(inbound_session, msgcopy, msglen, plaintext_buf, size, &message_index);
    CHECK_EQ(SIZE_MAX, res);
    assert_string_equal("BAD_SIGNATURE", olm_inbound_group_session_last_error(inbound_session));

    olm_clear_inbound_group_session(inbound_session);
    free(plaintext_buf);
    free(msgcopy);
    free(inbound_session_memory);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_pickle_outbound_group_session),
        cmocka_unit_test(test_pickle_inbound_group_session),
        cmocka_unit_test(test_group_message_send_receive),
        cmocka_unit_test(test_inbound_group_session_export_import),
        cmocka_unit_test(test_invalid_signature_group_message),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
