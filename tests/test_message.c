/* See LICENSE file for copyright and license details. */
#include "libce/message.h"

#include <stdint.h>
#include <string.h>

#include "testing.h"

static uint8_t message1[36] = "\x03\x10\x01\n\nratchetkey\"\nciphertexthmacsha2";
static uint8_t message2[36] = "\x03\n\nratchetkey\x10\x01\"\nciphertexthmacsha2";
static const uint8_t ratchetkey[11] = "ratchetkey";
static const uint8_t ciphertext[11] = "ciphertext";
static uint8_t hmacsha2[9] = "hmacsha2";

static void test_message_decode(void **state)
{
    (void)state;

    _OlmMessageReader reader;
    _olm_decode_message(&reader, message1, 35, 8);

    CHECK_EQ((uint8_t)3U, reader.version);
    CHECK_EQ(1, reader.has_counter);
    CHECK_EQ((uint32_t)1U, reader.counter);
    CHECK_EQ((size_t)10U, reader.ratchet_key_length);
    CHECK_EQ((size_t)10U, reader.ciphertext_length);

    CHECK_EQ_SIZE(ratchetkey, reader.ratchet_key, 10);
    CHECK_EQ_SIZE(ciphertext, reader.ciphertext, 10);
}

static void test_message_encode(void **state)
{
    (void)state;

    size_t length = _olm_encode_message_length(1, 10, 10, 8);
    CHECK_EQ((size_t)35U, length);

    uint8_t output[35];

    _OlmMessageWriter writer;
    _olm_encode_message(&writer, 3, 1, 10, 10, output);

    memcpy(writer.ratchet_key, ratchetkey, 10);
    memcpy(writer.ciphertext, ciphertext, 10);
    memcpy(output + length - 8U, hmacsha2, 8);

    CHECK_EQ_SIZE(message2, output, 35);
}

static void test_group_message_encode(void **state)
{
    (void)state;

    size_t length = _olm_encode_group_message_length(200, 10, 8, 64);
    size_t expected_length = 1U + (1U + 2U) + (2U + 10U) + 8U + 64U;
    CHECK_EQ(expected_length, length);

    uint8_t output[50];
    uint8_t *ciphertext_ptr = NULL;

    _olm_encode_group_message(
        3,
        200,
        10,
        output,
        &ciphertext_ptr
    );

    uint8_t expected[] =
        "\x03"
        "\x08\xC8\x01"
        "\x12\x0A";

    CHECK_EQ_SIZE(expected, output, sizeof(expected) - 1U);
    CHECK_EQ(output + sizeof(expected) - 1U, ciphertext_ptr);
}

static void test_group_message_decode(void **state)
{
    (void)state;

    _OlmDecodeGroupMessageResults results;
    uint8_t message[] =
        "\x03"
        "\x08\xC8\x01"
        "\x12\x0A" "ciphertext"
        "hmacsha2"
        "ed25519signature";

    _olm_decode_group_message(message, sizeof(message) - 1U, 8, 16, &results);
    CHECK_EQ((uint8_t)3U, results.version);
    CHECK_EQ(1, results.has_message_index);
    CHECK_EQ((uint32_t)200U, results.message_index);
    CHECK_EQ((size_t)10U, results.ciphertext_length);
    CHECK_EQ_SIZE(ciphertext, results.ciphertext, 10);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_message_decode),
        cmocka_unit_test(test_message_encode),
        cmocka_unit_test(test_group_message_encode),
        cmocka_unit_test(test_group_message_decode),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
