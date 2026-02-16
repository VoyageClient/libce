#include "libce/olm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "testing.h"

typedef struct test_case {
    const char *msghex;
    const char *expected_error;
} test_case;

static const test_case test_cases[] = {
    {"41776f", "BAD_MESSAGE_FORMAT"},
    {"7fff6f0101346d671201", "BAD_MESSAGE_FORMAT"},
    {"ee776f41496f674177804177778041776f6716670a677d6f670a67c2677d", "BAD_MESSAGE_FORMAT"},
    {"e9e9c9c1e9e9c9e9c9c1e9e9c9c1", "BAD_MESSAGE_FORMAT"},
};

static const char *session_data =
    "E0p44KO2y2pzp9FIjv0rud2wIvWDi2dx367kP4Fz/9JCMrH+aG369HGymkFtk0+PINTLB9lQRt"
    "ohea5d7G/UXQx3r5y4IWuyh1xaRnojEZQ9a5HRZSNtvmZ9NY1f1gutYa4UtcZcbvczN8b/5Bqg"
    "e16cPUH1v62JKLlhoAJwRkH1wU6fbyOudERg5gdXA971btR+Q2V8GKbVbO5fGKL5phmEPVXyMs"
    "rfjLdzQrgjOTxN8Pf6iuP+WFPvfnR9lDmNCFxJUVAdLIMnLuAdxf1TGcS+zzCzEE8btIZ99mHF"
    "dGvPXeH8qLeNZA";

static void decode_hex(const char *input, uint8_t *output, size_t output_length)
{
    uint8_t *end = output + output_length;
    while (output != end) {
        char high = *(input++);
        char low = *(input++);
        if (high >= 'a') {
            high -= 'a' - ('9' + 1);
        }
        if (low >= 'a') {
            low -= 'a' - ('9' + 1);
        }
        uint8_t value = (uint8_t)(((high - '0') << 4) | (low - '0'));
        *(output++) = value;
    }
}

static void decrypt_case(int message_type, const test_case *test_case)
{
    uint8_t *session_memory = test_checked_malloc(olm_session_size());
    OlmSession *session = olm_session(session_memory);

    size_t pickled_len = strlen(session_data);
    uint8_t *pickled = test_checked_malloc(pickled_len);
    memcpy(pickled, session_data, pickled_len);
    CHECK_NE(olm_error(), olm_unpickle_session(session, "", 0, pickled, pickled_len));

    size_t message_length = strlen(test_case->msghex) / 2U;
    uint8_t *message = test_checked_malloc(message_length);
    decode_hex(test_case->msghex, message, message_length);

    size_t max_length = olm_decrypt_max_plaintext_length(
        session,
        message_type,
        message,
        message_length
    );

    if (test_case->expected_error != NULL) {
        CHECK_EQ(olm_error(), max_length);
        assert_string_equal(test_case->expected_error, olm_session_last_error(session));
        free(message);
        olm_clear_session(session);
        free(session_memory);
        free(pickled);
        return;
    }

    CHECK_NE(olm_error(), max_length);

    uint8_t *plaintext = test_checked_malloc(max_length);
    decode_hex(test_case->msghex, message, message_length);
    olm_decrypt(
        session,
        message_type,
        message,
        message_length,
        plaintext,
        max_length
    );

    free(plaintext);
    free(message);
    olm_clear_session(session);
    free(session_memory);
    free(pickled);
}

static void test_olm_decrypt(void **state)
{
    (void)state;

    size_t i;
    for (i = 0; i < (sizeof(test_cases) / sizeof(test_cases[0])); ++i) {
        CAPTURE(test_cases[i].msghex);
        decrypt_case(0, &test_cases[i]);
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_olm_decrypt),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
