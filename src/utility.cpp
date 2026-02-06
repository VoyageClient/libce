/* See LICENSE file for copyright and license details. */
#include "libce/utility.hh"
#include "libce/crypto.h"


olm::Utility::Utility(
) : last_error(OlmErrorCode::OLM_SUCCESS) {
}


size_t olm::Utility::sha256_length() const {
    return SHA256_OUTPUT_LENGTH;
}


size_t olm::Utility::sha256(
    std::uint8_t const * input, std::size_t input_length,
    std::uint8_t * output, std::size_t output_length
) {
    if (output_length < sha256_length()) {
        last_error = OlmErrorCode::OLM_OUTPUT_BUFFER_TOO_SMALL;
        return std::size_t(-1);
    }
    _olm_crypto_sha256(input, input_length, output);
    return SHA256_OUTPUT_LENGTH;
}


size_t olm::Utility::ed25519_verify(
    _olm_ed25519_public_key const & key,
    std::uint8_t const * message, std::size_t message_length,
    std::uint8_t const * signature, std::size_t signature_length
) {
    if (signature_length < ED25519_SIGNATURE_LENGTH) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_MAC;
        return std::size_t(-1);
    }
    if (!_olm_crypto_ed25519_verify(&key, message, message_length, signature)) {
        last_error = OlmErrorCode::OLM_BAD_MESSAGE_MAC;
        return std::size_t(-1);
    }
    return std::size_t(0);
}
