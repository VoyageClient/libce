/* See LICENSE file for copyright and license details. */
#ifndef OLM_DEHYDRATED_DEVICE_H_
#define OLM_DEHYDRATED_DEVICE_H_

#include "libce/account.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Length of the ChaCha20-Poly1305 nonce a dehydrated device is sealed with. */
#define DEHYDRATED_DEVICE_NONCE_LENGTH 12

/** Length of the key a dehydrated device is sealed with. */
#define DEHYDRATED_DEVICE_KEY_LENGTH 32

/** Number of raw bytes the sealed device occupies. */
size_t _olm_account_dehydrate_length(
    const OlmAccount * account
);

/** Serialise the account in the MSC3814 pickle format and seal it with
 * ChaCha20-Poly1305. The account must know its Ed25519 seed, which rules out
 * accounts restored from a pickle, since those only keep the expanded key.
 * Returns SIZE_MAX on error. */
size_t _olm_account_dehydrate(
    OlmAccount * account,
    const uint8_t * key, size_t key_length,
    const uint8_t * nonce, size_t nonce_length,
    uint8_t * ciphertext, size_t ciphertext_length
);

/** Restore an account sealed by _olm_account_dehydrate. Returns SIZE_MAX on
 * error. */
size_t _olm_account_rehydrate(
    OlmAccount * account,
    const uint8_t * key, size_t key_length,
    const uint8_t * nonce, size_t nonce_length,
    const uint8_t * ciphertext, size_t ciphertext_length
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_DEHYDRATED_DEVICE_H_ */
