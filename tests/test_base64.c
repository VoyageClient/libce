#include "libce/base64.h"

#include <stdint.h>
#include <stdlib.h>

#include "testing.h"

static void test_base64_encode(void **state)
{
    (void)state;

    uint8_t input[] = "Hello World";
    uint8_t expected_output[] = "SGVsbG8gV29ybGQ";
    size_t input_length = sizeof(input) - 1U;

    size_t output_length = _olm_encode_base64_length(input_length);
    REQUIRE_EQ((size_t)15U, output_length);

    uint8_t output[15];
    output_length = _olm_encode_base64(input, input_length, output);
    CHECK_EQ((size_t)15U, output_length);
    CHECK_EQ_SIZE(expected_output, output, output_length);
}

static void test_base64_decode(void **state)
{
    (void)state;

    uint8_t input[] = "SGVsbG8gV29ybGQ";
    uint8_t expected_output[] = "Hello World";
    size_t input_length = sizeof(input) - 1U;

    size_t output_length = _olm_decode_base64_length(input_length);
    REQUIRE_EQ((size_t)11U, output_length);

    uint8_t output[11];
    output_length = _olm_decode_base64(input, input_length, output);
    REQUIRE_EQ((size_t)11U, output_length);
    CHECK_EQ_SIZE(expected_output, output, output_length);
}

static void test_base64_decode_invalid_length_returns_error(void **state)
{
    (void)state;

    uint8_t input[] = "SGVsbG8gV29ybGQab";
    size_t input_length = sizeof(input) - 1U;

    size_t buffer_length = _olm_decode_base64_length(input_length + 1U);
    uint8_t *output = (uint8_t *)calloc(buffer_length, sizeof(uint8_t));
    uint8_t *expected_output = (uint8_t *)calloc(buffer_length, sizeof(uint8_t));

    assert_non_null(output);
    assert_non_null(expected_output);

    size_t output_length = _olm_decode_base64(input, input_length, output);
    REQUIRE_EQ(SIZE_MAX, output_length);
    CHECK_EQ_SIZE(output, expected_output, buffer_length);

    free(output);
    free(expected_output);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_base64_encode),
        cmocka_unit_test(test_base64_decode),
        cmocka_unit_test(test_base64_decode_invalid_length_returns_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
