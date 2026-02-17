/* See LICENSE file for copyright and license details. */
#include "libce/base64.h"

#include <assert.h>

enum { E = -1 };

static const uint8_t ENCODE_BASE64[64] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F,
};

static const uint8_t DECODE_BASE64[128] = {
/*  0x0 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 0x9 0xA 0xB 0xC 0xD 0xE 0xF */
     E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,
     E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E,
     E,  E,  E,  E,  E,  E,  E,  E,  E,  E,  E, 62,  E,  E,  E, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  E,  E,  E,  E,  E,  E,
     E,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  E,  E,  E,  E,  E,
     E, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,  E,  E,  E,  E,  E,
};

size_t _olm_encode_base64_length(
    size_t input_length
) {
    return 4 * ((input_length + 2) / 3) + (input_length + 2) % 3 - 2;
}

size_t _olm_encode_base64(
    const uint8_t * input, size_t input_length,
    uint8_t * output
) {
    const uint8_t * end = input + (input_length / 3) * 3;
    const uint8_t * pos = input;

    uint8_t * output_pos = output;
    while (pos != end) {
        unsigned value = pos[0];
        value <<= 8; value |= pos[1];
        value <<= 8; value |= pos[2];
        pos += 3;
        output_pos[3] = ENCODE_BASE64[value & 0x3F];
        value >>= 6; output_pos[2] = ENCODE_BASE64[value & 0x3F];
        value >>= 6; output_pos[1] = ENCODE_BASE64[value & 0x3F];
        value >>= 6; output_pos[0] = ENCODE_BASE64[value];
        output_pos += 4;
    }

    unsigned remainder = input + input_length - pos;
    uint8_t * result = output_pos;
    if (remainder) {
        unsigned value = pos[0];
        if (remainder == 2) {
            value <<= 8; value |= pos[1];
            value <<= 2;
            output_pos[2] = ENCODE_BASE64[value & 0x3F];
            value >>= 6;
            result += 3;
        } else {
            value <<= 4;
            result += 2;
        }
        output_pos[1] = ENCODE_BASE64[value & 0x3F];
        value >>= 6;
        output_pos[0] = ENCODE_BASE64[value];
    }

    return result - output;
}

size_t _olm_decode_base64_length(
    size_t input_length
) {
    if (input_length % 4 == 1) {
        return SIZE_MAX;
    } else {
        return 3 * ((input_length + 2) / 4) + (input_length + 2) % 4 - 2;
    }
}

size_t _olm_decode_base64(
    const uint8_t * input, size_t input_length,
    uint8_t * output
) {
    size_t raw_length = _olm_decode_base64_length(input_length);

    if (raw_length == SIZE_MAX) {
        return SIZE_MAX;
    }

    const uint8_t * end = input + (input_length / 4) * 4;
    const uint8_t * pos = input;

    while (pos != end) {
        unsigned value = DECODE_BASE64[pos[0] & 0x7F];
        value <<= 6; value |= DECODE_BASE64[pos[1] & 0x7F];
        value <<= 6; value |= DECODE_BASE64[pos[2] & 0x7F];
        value <<= 6; value |= DECODE_BASE64[pos[3] & 0x7F];
        pos += 4;
        output[2] = value;
        value >>= 8; output[1] = value;
        value >>= 8; output[0] = value;
        output += 3;
    }

    unsigned remainder = input + input_length - pos;
    if (remainder) {
        /* A base64 payload with a single byte remainder cannot occur because
         * a single base64 character only encodes 6 bits, which is less than
         * a full byte. Therefore, a minimum of two base64 characters are
         * required to construct a single output byte and payloads with
         * a remainder of 1 are illegal.
         *
         * Should never be the case due to length check above.
         */
        assert(remainder != 1);

        unsigned value = DECODE_BASE64[pos[0] & 0x7F];
        value <<= 6; value |= DECODE_BASE64[pos[1] & 0x7F];
        if (remainder == 3) {
            value <<= 6; value |= DECODE_BASE64[pos[2] & 0x7F];
            value >>= 2;
            output[1] = value;
            value >>= 8;
        } else {
            value >>= 4;
        }
        output[0] = value;
    }

    return raw_length;
}
