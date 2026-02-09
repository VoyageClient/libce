/* See LICENSE file for copyright and license details. */
#include "libce/message.h"

#include "libce/memory.h"

static size_t varint_length_bytes(
    size_t value
) {
    size_t result = 1;
    while (value >= 128U) {
        ++result;
        value >>= 7;
    }
    return result;
}

static size_t varint_length_uint32(
    uint32_t value
) {
    uint32_t result = 1;
    while (value >= 128U) {
        ++result;
        value >>= 7;
    }
    return result;
}


static uint8_t * varint_encode_bytes(
    uint8_t * output,
    size_t value
) {
    while (value >= 128U) {
        *(output++) = (0x7F & value) | 0x80;
        value >>= 7;
    }
    (*output++) = value;
    return output;
}

static uint8_t * varint_encode_uint32(
    uint8_t * output,
    uint32_t value
) {
    while (value >= 128U) {
        *(output++) = (0x7F & value) | 0x80;
        value >>= 7;
    }
    (*output++) = value;
    return output;
}


static size_t varint_decode_bytes(
    uint8_t const * varint_start,
    uint8_t const * varint_end
) {
    size_t value = 0;
    if (varint_end == varint_start) {
        return 0;
    }
    do {
        value <<= 7;
        value |= 0x7F & *(--varint_end);
    } while (varint_end != varint_start);
    return value;
}

static uint32_t varint_decode_uint32(
    uint8_t const * varint_start,
    uint8_t const * varint_end
) {
    uint32_t value = 0;
    if (varint_end == varint_start) {
        return 0;
    }
    do {
        value <<= 7;
        value |= 0x7F & *(--varint_end);
    } while (varint_end != varint_start);
    return value;
}


static uint8_t const * varint_skip(
    uint8_t const * input,
    uint8_t const * input_end
) {
    while (input != input_end) {
        uint8_t tmp = *(input++);
        if ((tmp & 0x80) == 0) {
            return input;
        }
    }
    return input;
}


static size_t varstring_length(
    size_t string_length
) {
    return varint_length_bytes(string_length) + string_length;
}


static size_t const VERSION_LENGTH = 1;
static uint8_t const RATCHET_KEY_TAG = 012;
static uint8_t const COUNTER_TAG = 020;
static uint8_t const CIPHERTEXT_TAG = 042;


static uint8_t * encode_bytes(
    uint8_t * pos,
    uint8_t tag,
    uint8_t ** value, size_t value_length
) {
    *(pos++) = tag;
    pos = varint_encode_bytes(pos, value_length);
    *value = pos;
    return pos + value_length;
}

static uint8_t * encode_uint32(
    uint8_t * pos,
    uint8_t tag,
    uint32_t value
) {
    *(pos++) = tag;
    return varint_encode_uint32(pos, value);
}


static uint8_t const * decode_bytes(
    uint8_t const * pos, uint8_t const * end,
    uint8_t tag,
    uint8_t const ** value, size_t * value_length
) {
    if (pos != end && *pos == tag) {
        ++pos;
        uint8_t const * len_start = pos;
        pos = varint_skip(pos, end);
        size_t len = varint_decode_bytes(len_start, pos);
        if (len > (size_t)(end - pos)) return end;
        *value = pos;
        *value_length = len;
        pos += len;
    }
    return pos;
}

static uint8_t const * decode_uint32(
    uint8_t const * pos, uint8_t const * end,
    uint8_t tag,
    uint32_t * value, bool * has_value
) {
    if (pos != end && *pos == tag) {
        ++pos;
        uint8_t const * value_start = pos;
        pos = varint_skip(pos, end);
        *value = varint_decode_uint32(value_start, pos);
        *has_value = true;
    }
    return pos;
}


static uint8_t const * skip_unknown(
    uint8_t const * pos, uint8_t const * end
) {
    if (pos != end) {
        uint8_t tag = *pos;
        if ((tag & 0x7) == 0) {
            pos = varint_skip(pos, end);
            pos = varint_skip(pos, end);
        } else if ((tag & 0x7) == 2) {
            pos = varint_skip(pos, end);
            uint8_t const * len_start = pos;
            pos = varint_skip(pos, end);
            size_t len = varint_decode_bytes(len_start, pos);
            if (len > (size_t)(end - pos)) return end;
            pos += len;
        } else {
            return end;
        }
    }
    return pos;
}


size_t _olm_encode_message_length(
    uint32_t counter,
    size_t ratchet_key_length,
    size_t ciphertext_length,
    size_t mac_length
) {
    size_t length = VERSION_LENGTH;
    length += 1 + varstring_length(ratchet_key_length);
    length += 1 + varint_length_uint32(counter);
    length += 1 + varstring_length(ciphertext_length);
    length += mac_length;
    return length;
}


void _olm_encode_message(
    _OlmMessageWriter * writer,
    uint8_t version,
    uint32_t counter,
    size_t ratchet_key_length,
    size_t ciphertext_length,
    uint8_t * output
) {
    uint8_t * pos = output;
    *(pos++) = version;
    pos = encode_bytes(pos, RATCHET_KEY_TAG, &writer->ratchet_key, ratchet_key_length);
    pos = encode_uint32(pos, COUNTER_TAG, counter);
    pos = encode_bytes(pos, CIPHERTEXT_TAG, &writer->ciphertext, ciphertext_length);
}


void _olm_decode_message(
    _OlmMessageReader * reader,
    uint8_t const * input, size_t input_length,
    size_t mac_length
) {
    uint8_t const * pos = input;
    uint8_t const * end = input + input_length - mac_length;
    uint8_t const * unknown = NULL;

    reader->version = 0;
    reader->has_counter = false;
    reader->counter = 0;
    reader->input = input;
    reader->input_length = input_length;
    reader->ratchet_key = NULL;
    reader->ratchet_key_length = 0;
    reader->ciphertext = NULL;
    reader->ciphertext_length = 0;

    if (input_length < mac_length) return;

    if (pos == end) return;
    reader->version = *(pos++);

    while (pos != end) {
        unknown = pos;
        pos = decode_bytes(
            pos, end, RATCHET_KEY_TAG,
            &reader->ratchet_key, &reader->ratchet_key_length
        );
        pos = decode_uint32(
            pos, end, COUNTER_TAG,
            &reader->counter, &reader->has_counter
        );
        pos = decode_bytes(
            pos, end, CIPHERTEXT_TAG,
            &reader->ciphertext, &reader->ciphertext_length
        );
        if (unknown == pos) {
            pos = skip_unknown(pos, end);
        }
    }
}


static uint8_t const ONE_TIME_KEY_ID_TAG = 012;
static uint8_t const BASE_KEY_TAG = 022;
static uint8_t const IDENTITY_KEY_TAG = 032;
static uint8_t const MESSAGE_TAG = 042;


size_t _olm_encode_one_time_key_message_length(
    size_t one_time_key_length,
    size_t identity_key_length,
    size_t base_key_length,
    size_t message_length
) {
    size_t length = VERSION_LENGTH;
    length += 1 + varstring_length(one_time_key_length);
    length += 1 + varstring_length(identity_key_length);
    length += 1 + varstring_length(base_key_length);
    length += 1 + varstring_length(message_length);
    return length;
}


void _olm_encode_one_time_key_message(
    _OlmPreKeyMessageWriter * writer,
    uint8_t version,
    size_t identity_key_length,
    size_t base_key_length,
    size_t one_time_key_length,
    size_t message_length,
    uint8_t * output
) {
    uint8_t * pos = output;
    *(pos++) = version;
    pos = encode_bytes(pos, ONE_TIME_KEY_ID_TAG, &writer->one_time_key, one_time_key_length);
    pos = encode_bytes(pos, BASE_KEY_TAG, &writer->base_key, base_key_length);
    pos = encode_bytes(pos, IDENTITY_KEY_TAG, &writer->identity_key, identity_key_length);
    pos = encode_bytes(pos, MESSAGE_TAG, &writer->message, message_length);
}


void _olm_decode_one_time_key_message(
    _OlmPreKeyMessageReader * reader,
    uint8_t const * input, size_t input_length
) {
    uint8_t const * pos = input;
    uint8_t const * end = input + input_length;
    uint8_t const * unknown = NULL;

    reader->version = 0;
    reader->one_time_key = NULL;
    reader->one_time_key_length = 0;
    reader->identity_key = NULL;
    reader->identity_key_length = 0;
    reader->base_key = NULL;
    reader->base_key_length = 0;
    reader->message = NULL;
    reader->message_length = 0;

    if (pos == end) return;
    reader->version = *(pos++);

    while (pos != end) {
        unknown = pos;
        pos = decode_bytes(
            pos, end, ONE_TIME_KEY_ID_TAG,
            &reader->one_time_key, &reader->one_time_key_length
        );
        pos = decode_bytes(
            pos, end, BASE_KEY_TAG,
            &reader->base_key, &reader->base_key_length
        );
        pos = decode_bytes(
            pos, end, IDENTITY_KEY_TAG,
            &reader->identity_key, &reader->identity_key_length
        );
        pos = decode_bytes(
            pos, end, MESSAGE_TAG,
            &reader->message, &reader->message_length
        );
        if (unknown == pos) {
            pos = skip_unknown(pos, end);
        }
    }
}



static const uint8_t GROUP_MESSAGE_INDEX_TAG = 010;
static const uint8_t GROUP_CIPHERTEXT_TAG = 022;

size_t _olm_encode_group_message_length(
    uint32_t message_index,
    size_t ciphertext_length,
    size_t mac_length,
    size_t signature_length
) {
    size_t length = VERSION_LENGTH;
    length += 1 + varint_length_uint32(message_index);
    length += 1 + varstring_length(ciphertext_length);
    length += mac_length;
    length += signature_length;
    return length;
}


size_t _olm_encode_group_message(
    uint8_t version,
    uint32_t message_index,
    size_t ciphertext_length,
    uint8_t *output,
    uint8_t **ciphertext_ptr
) {
    uint8_t * pos = output;

    *(pos++) = version;
    pos = encode_uint32(pos, GROUP_MESSAGE_INDEX_TAG, message_index);
    pos = encode_bytes(pos, GROUP_CIPHERTEXT_TAG, &*ciphertext_ptr, ciphertext_length);
    return pos-output;
}

void _olm_decode_group_message(
    const uint8_t *input, size_t input_length,
    size_t mac_length, size_t signature_length,
    struct _OlmDecodeGroupMessageResults *results
) {
    uint8_t const * pos = input;
    size_t trailer_length = mac_length + signature_length;
    uint8_t const * end = input + input_length - trailer_length;
    uint8_t const * unknown = NULL;

    bool has_message_index = false;
    results->version = 0;
    results->message_index = 0;
    results->has_message_index = (int)has_message_index;
    results->ciphertext = NULL;
    results->ciphertext_length = 0;

    if (input_length < trailer_length) return;

    if (pos == end) return;
    results->version = *(pos++);

    while (pos != end) {
        unknown = pos;
        pos = decode_uint32(
            pos, end, GROUP_MESSAGE_INDEX_TAG,
            &results->message_index, &has_message_index
        );
        pos = decode_bytes(
            pos, end, GROUP_CIPHERTEXT_TAG,
            &results->ciphertext, &results->ciphertext_length
        );
        if (unknown == pos) {
            pos = skip_unknown(pos, end);
        }
    }

    results->has_message_index = (int)has_message_index;
}
