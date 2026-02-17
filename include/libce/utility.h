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

typedef struct OlmUtility {
    OlmErrorCode last_error;
} OlmUtility;

/** Initialise an Olm utility object. */
void _olm_utility_init(
    OlmUtility * utility
);

/** The length of a SHA-256 hash in bytes. */
size_t _olm_utility_sha256_length(void);

/** Compute a SHA-256 hash.
 *
 * Returns the length of the SHA-256 hash in bytes on success.
 * Returns SIZE_MAX on failure and sets utility->last_error.
 */
size_t _olm_utility_sha256(
    OlmUtility * utility,
    const uint8_t * input, size_t input_length,
    uint8_t * output, size_t output_length
);

/** Verify an Ed25519 signature.
 *
 * Returns 0 on success.
 * Returns SIZE_MAX on failure and sets utility->last_error.
 */
size_t _olm_utility_ed25519_verify(
    OlmUtility * utility,
    const _olm_ed25519_public_key * key,
    const uint8_t * message, size_t message_length,
    const uint8_t * signature, size_t signature_length
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_UTILITY_H_ */
