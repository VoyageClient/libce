/* See LICENSE file for copyright and license details. */
#include "libce/message.h"
#include "testing.hh"

std::uint8_t message1[36] = "\x03\x10\x01\n\nratchetkey\"\nciphertexthmacsha2";
std::uint8_t message2[36] = "\x03\n\nratchetkey\x10\x01\"\nciphertexthmacsha2";
const std::uint8_t ratchetkey[11] = "ratchetkey";
const std::uint8_t ciphertext[11] = "ciphertext";
std::uint8_t hmacsha2[9] = "hmacsha2";

 /* Message decode test */

TEST_CASE("Message decode test") {

_OlmMessageReader reader;
_olm_decode_message(&reader, message1, 35, 8);

CHECK_EQ(std::uint8_t(3), reader.version);
CHECK_EQ(true, reader.has_counter);
CHECK_EQ(std::uint32_t(1), reader.counter);
CHECK_EQ(std::size_t(10), reader.ratchet_key_length);
CHECK_EQ(std::size_t(10), reader.ciphertext_length);

CHECK_EQ_SIZE(ratchetkey, reader.ratchet_key, 10);
CHECK_EQ_SIZE(ciphertext, reader.ciphertext, 10);


} /* Message decode test */

 /* Message encode test */

TEST_CASE("Message encode test") {

std::size_t length = _olm_encode_message_length(1, 10, 10, 8);
CHECK_EQ(std::size_t(35), length);

std::uint8_t output[35];

_OlmMessageWriter writer;
_olm_encode_message(&writer, 3, 1, 10, 10, output);

std::memcpy(writer.ratchet_key, ratchetkey, 10);
std::memcpy(writer.ciphertext, ciphertext, 10);
std::memcpy(output + length - 8, hmacsha2, 8);

CHECK_EQ_SIZE(message2, output, 35);

} /* Message encode test */


/* group message encode test */

    TEST_CASE("Group message encode test") {

    size_t length = _olm_encode_group_message_length(200, 10, 8, 64);
    size_t expected_length = 1 + (1+2) + (2+10) + 8 + 64;
    CHECK_EQ(expected_length, length);

    uint8_t output[50];
    uint8_t *ciphertext_ptr;

    _olm_encode_group_message(
        3,
        200, // counter
        10,  // ciphertext length
        output,
        &ciphertext_ptr
    );

    uint8_t expected[] =
        "\x03"
        "\x08\xC8\x01"
        "\x12\x0A";

    CHECK_EQ_SIZE(expected, output, sizeof(expected)-1);
    CHECK_EQ(output+sizeof(expected)-1, ciphertext_ptr);
} /* group message encode test */

    TEST_CASE("Group message decode test") {

    struct _OlmDecodeGroupMessageResults results;
    std::uint8_t message[] =
        "\x03"
        "\x08\xC8\x01"
        "\x12\x0A" "ciphertext"
        "hmacsha2"
        "ed25519signature";

    _olm_decode_group_message(message, sizeof(message)-1, 8, 16, &results);
    CHECK_EQ(std::uint8_t(3), results.version);
    CHECK_EQ(1, results.has_message_index);
    CHECK_EQ(std::uint32_t(200), results.message_index);
    CHECK_EQ(std::size_t(10), results.ciphertext_length);
    CHECK_EQ_SIZE(ciphertext, results.ciphertext, 10);
} /* group message decode test */
