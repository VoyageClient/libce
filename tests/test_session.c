#include "libce/session.h"
#include "libce/pickle_encoding.h"

#include <stdint.h>
#include <string.h>

#include "testing.h"

static const uint8_t *decode_hex(const char *input)
{
    static uint8_t buf[256];
    uint8_t *p = buf;

    while (*input != '\0') {
        char high = *(input++);
        char low = *(input++);
        if (high >= 'a') {
            high -= 'a' - ('9' + 1);
        }
        if (low >= 'a') {
            low -= 'a' - ('9' + 1);
        }
        uint8_t value = (uint8_t)(((high - '0') << 4) | (low - '0'));
        *p++ = value;
    }

    return buf;
}

static void check_session(const OlmSession *session)
{
    CHECK_EQ_SIZE(
        decode_hex("49d640dc96b80176694af69fc4b8ca9fac49aecbd697d01fd8bee1ed2693b6c9"),
        session->ratchet.root_key,
        32
    );

    CHECK_EQ((size_t)1U, _olm_list_size(&session->ratchet.sender_chain));

    CHECK_EQ_SIZE(
        decode_hex("f77a03eaa9b301fa7d2a5aa6b50286906de12cc96044f526dbbcb12839ad7003"),
        _olm_list_get(&session->ratchet.sender_chain, 0).ratchet_key.public_key.public_key,
        32
    );

    CHECK_EQ_SIZE(
        decode_hex("d945c6ed4c7c277117adf11fb133a7936d287afe97c0b3ac989644b4490d4f31"),
        _olm_list_get(&session->ratchet.sender_chain, 0).ratchet_key.private_key.private_key,
        32
    );

    CHECK_EQ((uint32_t)0U, _olm_list_get(&session->ratchet.sender_chain, 0).chain_key.index);

    CHECK_EQ(0, _olm_list_size(&session->ratchet.receiver_chains));
    CHECK_EQ(0, _olm_list_size(&session->ratchet.skipped_message_keys));

    CHECK_EQ(OLM_SUCCESS, session->last_error);
    CHECK_EQ(0, session->received_message);

    CHECK_EQ_SIZE(
        decode_hex("7326b58623a3f7bd8da11a1bab51f432c02a7430241b326e9fc8916a21eb257e"),
        session->alice_identity_key.public_key,
        32
    );

    CHECK_EQ_SIZE(
        decode_hex("0ab4b30bde20bd374ceccc72861660f0fd046f7516900796c3e5de41c598316c"),
        session->alice_base_key.public_key,
        32
    );

    CHECK_EQ_SIZE(
        decode_hex("585dba930b10d90d81702c715f4085d07c42b0cd2d676010bb6086c86c4cc618"),
        session->bob_one_time_key.public_key,
        32
    );
}

static void test_v1_session_pickle(void **state)
{
    (void)state;

    const uint8_t *pickle_key = (uint8_t *)"secret_key";
    uint8_t pickled[] =
        "wkEpwMgiAqD7B1/Lw2cKYYDcUZVOd9QHes7ZroWxr/Rp/nWEAySgRsIu/a54YhO67rwitr"
        "Lpos7tFxxK9IZ7pKB1qrR1coVWIt78V9lp9WgmBAvxHBSY+tu1lkL/JjLi963/yFdPancZ"
        "+WHMVfaKlV3gWGpo7EfNK6qAOxI1Ea/eCsE2sYrsHEDvLLGlKAA9E56rmmoe2w6TKzsQjs"
        "ZM2/XT2eJ82EgMO9pL02iLElXWmGNv72Ut7DouR0pQIT50HIEEKcFxYcoTb3WCfJD76Coe"
        "sE4kx+TA6d45Xu1bwQNNkTGF+nCCu/GmKY+sECXbz9U6WhxG0YdF9Z4T8YkWYAgpKNS0FW"
        "RV";
    size_t pickle_len = _olm_enc_input(
        pickle_key,
        strlen((char *)pickle_key),
        pickled,
        strlen((char *)pickled),
        NULL
    );

    OlmSession session;
    const uint8_t *unpickle_res = _olm_unpickle_session(pickled, pickled + sizeof(pickled), &session);
    CHECK_EQ(pickle_len, (size_t)(unpickle_res - pickled));

    check_session(&session);
}

static void test_v2_session_pickle(void **state)
{
    (void)state;

    const uint8_t *pickle_key = (uint8_t *)"secret_key";
    uint8_t pickled[] =
        "m+DS/q34MXpw2xp50ZD0B7val1mlMpQXo0mx+VPje0weFYRRuuZQBdJgcFPEpi2MVSpA4c"
        "qgqHyj2/bU7/lz+BXkEBrCFVx0BJidxXfOLDW4TNtRhLS1YHJNGP8GvTg1+dCytBTLsCdm"
        "5f945Eq1U/pY3Cg96YTUufFP6EYrfRoDbAsRHc+h+wKKftQv+W44yUmRhcCemGHtpxk3UQ"
        "AMCI7EBv9BvveyZMy3p9qZ3xvFK34Hef+R7gjtFycz7Nk/4UF46sT3cTmUlXz9iFW4uz2F"
        "rTI1Wjym+l0DadsbSpHSUjmp9zt4qRP2UjwfZ5QNLv+cdObIfqFsiThGu/PlKigdF4SLHr"
        "nG";

    size_t pickle_len = _olm_enc_input(
        pickle_key,
        strlen((char *)pickle_key),
        pickled,
        strlen((char *)pickled),
        NULL
    );

    OlmSession session;
    const uint8_t *unpickle_res = _olm_unpickle_session(pickled, pickled + sizeof(pickled), &session);
    CHECK_EQ(pickle_len, (size_t)(unpickle_res - pickled));

    check_session(&session);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_v1_session_pickle),
        cmocka_unit_test(test_v2_session_pickle),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
