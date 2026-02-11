/* See LICENSE file for copyright and license details. */
#ifndef OLM_UTILITY_H_
#define OLM_UTILITY_H_

#include "libce/crypto.h"
#include "libce/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct OlmUtility {
    enum OlmErrorCode last_error;
};

/** Initialise an Olm utility object. */
void _olm_utility_init(
    struct OlmUtility * utility
);

/** The length of a SHA-256 hash in bytes. */
size_t _olm_utility_sha256_length(void);

/** Compute a SHA-256 hash.
 *
 * Returns the length of the SHA-256 hash in bytes on success.
 * Returns SIZE_MAX on failure and sets utility->last_error.
 */
size_t _olm_utility_sha256(
    struct OlmUtility * utility,
    uint8_t const * input, size_t input_length,
    uint8_t * output, size_t output_length
);

/** Verify an Ed25519 signature.
 *
 * Returns 0 on success.
 * Returns SIZE_MAX on failure and sets utility->last_error.
 */
size_t _olm_utility_ed25519_verify(
    struct OlmUtility * utility,
    struct _olm_ed25519_public_key const * key,
    uint8_t const * message, size_t message_length,
    uint8_t const * signature, size_t signature_length
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_UTILITY_H_ */
