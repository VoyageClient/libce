/* See LICENSE file for copyright and license details. */

/* functions for encrypting and decrypting pickled representations of objects */

#ifndef OLM_PICKLE_ENCODING_H_
#define OLM_PICKLE_ENCODING_H_

#include <stddef.h>
#include <stdint.h>

#include "libce/error.h"

// Note: exports in this file are only for unit tests.  Nobody else should be
// using this externally
#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Get the number of bytes needed to encode a pickle of the length given
 */
CE_EXPORT size_t _olm_enc_output_length(size_t raw_length);

/**
 * Get the point in the output buffer that the raw pickle should be written to.
 *
 * In order that we can use the same buffer for the raw pickle, and the encoded
 * pickle, the raw pickle needs to be written at the end of the buffer. (The
 * base-64 encoding would otherwise overwrite the end of the input before it
 * was encoded.)
 */
CE_EXPORT uint8_t *_olm_enc_output_pos(uint8_t * output, size_t raw_length);

/**
 * Encrypt and encode the given pickle in-situ.
 *
 * The raw pickle should have been written to enc_output_pos(pickle,
 * raw_length).
 *
 * Returns the number of bytes in the encoded pickle.
 */
CE_EXPORT size_t _olm_enc_output(
    const uint8_t * key, size_t key_length,
    uint8_t *pickle, size_t raw_length
);

/**
 * Decode and decrypt the given pickle in-situ.
 *
 * Returns the number of bytes in the decoded pickle, or olm_error() on error,
 * in which case *last_error will be updated, if last_error is non-NULL.
 */
CE_EXPORT size_t _olm_enc_input(
    const uint8_t * key, size_t key_length,
    uint8_t * input, size_t b64_length,
    OlmErrorCode * last_error
);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_PICKLE_ENCODING_H_ */
