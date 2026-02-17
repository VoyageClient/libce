/* See LICENSE file for copyright and license details. */

/**
 * functions for encoding and decoding messages in the Olm protocol.
 */

#ifndef OLM_MESSAGE_H_
#define OLM_MESSAGE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Note: exports in this file are only for unit tests.  Nobody else should be
// using this externally
#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _OlmDecodeGroupMessageResults {
    uint8_t version;
    uint32_t message_index;
    int has_message_index;
    const uint8_t *ciphertext;
    size_t ciphertext_length;
} _OlmDecodeGroupMessageResults;

typedef struct _OlmMessageWriter {
    uint8_t * ratchet_key;
    uint8_t * ciphertext;
} _OlmMessageWriter;

typedef struct _OlmMessageReader {
    uint8_t version;
    bool has_counter;
    uint32_t counter;
    const uint8_t * input; size_t input_length;
    const uint8_t * ratchet_key; size_t ratchet_key_length;
    const uint8_t * ciphertext; size_t ciphertext_length;
} _OlmMessageReader;

typedef struct _OlmPreKeyMessageWriter {
    uint8_t * identity_key;
    uint8_t * base_key;
    uint8_t * one_time_key;
    uint8_t * message;
} _OlmPreKeyMessageWriter;

typedef struct _OlmPreKeyMessageReader {
    uint8_t version;
    const uint8_t * identity_key; size_t identity_key_length;
    const uint8_t * base_key; size_t base_key_length;
    const uint8_t * one_time_key; size_t one_time_key_length;
    const uint8_t * message; size_t message_length;
} _OlmPreKeyMessageReader;


/**
 * The length of the buffer needed to hold a group message.
 */
CE_EXPORT size_t _olm_encode_group_message_length(
    uint32_t chain_index,
    size_t ciphertext_length,
    size_t mac_length,
    size_t signature_length
);

/**
 * Writes the message headers into the output buffer.
 *
 * version:            version number of the olm protocol
 * message_index:      message index
 * ciphertext_length:  length of the ciphertext
 * output:             where to write the output. Should be at least
 *                     olm_encode_group_message_length() bytes long.
 * ciphertext_ptr:     returns the address that the ciphertext
 *                     should be written to, followed by the MAC and the
 *                     signature.
 *
 * Returns the size of the message, up to the MAC.
 */
CE_EXPORT size_t _olm_encode_group_message(
    uint8_t version,
    uint32_t message_index,
    size_t ciphertext_length,
    uint8_t *output,
    uint8_t **ciphertext_ptr
);

/**
 * Reads the message headers from the input buffer.
 */
CE_EXPORT void _olm_decode_group_message(
    const uint8_t *input, size_t input_length,
    size_t mac_length, size_t signature_length,

    /* output structure: updated with results */
    _OlmDecodeGroupMessageResults *results
);

/**
 * The length of the buffer needed to hold a message.
 */
CE_EXPORT size_t _olm_encode_message_length(
    uint32_t counter,
    size_t ratchet_key_length,
    size_t ciphertext_length,
    size_t mac_length
);

/**
 * Writes the message headers into the output buffer.
 * Populates the writer struct with pointers into the output buffer.
 */
CE_EXPORT void _olm_encode_message(
    _OlmMessageWriter * writer,
    uint8_t version,
    uint32_t counter,
    size_t ratchet_key_length,
    size_t ciphertext_length,
    uint8_t * output
);

/**
 * Reads the message headers from the input buffer.
 * Populates the reader struct with pointers into the input buffer.
 */
CE_EXPORT void _olm_decode_message(
    _OlmMessageReader * reader,
    const uint8_t * input, size_t input_length,
    size_t mac_length
);

/**
 * The length of the buffer needed to hold a message.
 */
size_t _olm_encode_one_time_key_message_length(
    size_t identity_key_length,
    size_t base_key_length,
    size_t one_time_key_length,
    size_t message_length
);

/**
 * Writes the message headers into the output buffer.
 * Populates the writer struct with pointers into the output buffer.
 */
void _olm_encode_one_time_key_message(
    _OlmPreKeyMessageWriter * writer,
    uint8_t version,
    size_t identity_key_length,
    size_t base_key_length,
    size_t one_time_key_length,
    size_t message_length,
    uint8_t * output
);

/**
 * Reads the message headers from the input buffer.
 * Populates the reader struct with pointers into the input buffer.
 */
void _olm_decode_one_time_key_message(
    _OlmPreKeyMessageReader * reader,
    const uint8_t * input, size_t input_length
);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_MESSAGE_H_ */
