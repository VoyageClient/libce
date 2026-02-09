/* See LICENSE file for copyright and license details. */

/* C bindings for base64 functions */


#ifndef OLM_BASE64_H_
#define OLM_BASE64_H_

#include <stddef.h>
#include <stdint.h>

// Note: exports in this file are only for unit tests.  Nobody else should be
// using this externally
#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * The number of bytes of unpadded base64 needed to encode a length of input.
 */
CE_EXPORT size_t _olm_encode_base64_length(
    size_t input_length
);

/**
 * Encode the raw input as unpadded base64.
 * Writes encode_base64_length(input_length) bytes to the output buffer.
 * The input can overlap with the last three quarters of the output buffer.
 * That is, the input pointer may be output + output_length - input_length.
 *
 * Returns number of bytes encoded
 */
CE_EXPORT size_t _olm_encode_base64(
    uint8_t const * input, size_t input_length,
    uint8_t * output
);

/**
 * The number of bytes of raw data a length of unpadded base64 will encode to.
 * Returns SIZE_MAX if the length is not a valid length for base64.
 */
CE_EXPORT size_t _olm_decode_base64_length(
    size_t input_length
);

/**
 * Decodes the unpadded base64 input to raw bytes.
 * Writes decode_base64_length(input_length) bytes to the output buffer.
 * The output can overlap with the first three quarters of the input buffer.
 * That is, the input pointers and output pointer may be the same.
 *
 * Returns number of bytes decoded
 */
CE_EXPORT size_t _olm_decode_base64(
    uint8_t const * input, size_t input_length,
    uint8_t * output
);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_BASE64_H_ */
