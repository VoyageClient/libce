/* See LICENSE file for copyright and license details. */
#include "libce/utility.h"


void _olm_utility_init(
    struct OlmUtility * utility
) {
    if (utility)
        utility->last_error = OLM_SUCCESS;
}


size_t _olm_utility_sha256_length(void) {
    return SHA256_OUTPUT_LENGTH;
}


size_t _olm_utility_sha256(
    struct OlmUtility * utility,
    uint8_t const * input, size_t input_length,
    uint8_t * output, size_t output_length
) {
    if (output_length < _olm_utility_sha256_length()) {
        utility->last_error = OLM_OUTPUT_BUFFER_TOO_SMALL;
        return SIZE_MAX;
    }
    _olm_crypto_sha256(input, input_length, output);
    return SHA256_OUTPUT_LENGTH;
}


size_t _olm_utility_ed25519_verify(
    struct OlmUtility * utility,
    struct _olm_ed25519_public_key const * key,
    uint8_t const * message, size_t message_length,
    uint8_t const * signature, size_t signature_length
) {
    if (signature_length < ED25519_SIGNATURE_LENGTH) {
        utility->last_error = OLM_BAD_MESSAGE_MAC;
        return SIZE_MAX;
    }
    if (!_olm_crypto_ed25519_verify(key, message, message_length, signature)) {
        utility->last_error = OLM_BAD_MESSAGE_MAC;
        return SIZE_MAX;
    }
    return 0;
}
