/* See LICENSE file for copyright and license details. */
#ifndef OLM_ERROR_H_
#define OLM_ERROR_H_

#include "libce/olm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

enum OlmErrorCode {
    OLM_SUCCESS = 0, /*!< There wasn't an error */
    OLM_NOT_ENOUGH_RANDOM = 1,  /*!< Not enough entropy was supplied */
    OLM_OUTPUT_BUFFER_TOO_SMALL = 2, /*!< Supplied output buffer is too small */
    OLM_BAD_MESSAGE_VERSION = 3,  /*!< The message version is unsupported */
    OLM_BAD_MESSAGE_FORMAT = 4, /*!< The message couldn't be decoded */
    OLM_BAD_MESSAGE_MAC = 5, /*!< The message couldn't be decrypted */
    OLM_BAD_MESSAGE_KEY_ID = 6, /*!< The message references an unknown key id */
    OLM_INVALID_BASE64 = 7, /*!< The input base64 was invalid */
    OLM_BAD_ACCOUNT_KEY = 8, /*!< The supplied account key is invalid */
    OLM_UNKNOWN_PICKLE_VERSION = 9, /*!< The pickled object is too new */
    OLM_CORRUPTED_PICKLE = 10, /*!< The pickled object couldn't be decoded */

    OLM_BAD_SESSION_KEY = 11,  /*!< Attempt to initialise an inbound group
                                 session from an invalid session key */
    OLM_UNKNOWN_MESSAGE_INDEX = 12,  /*!< Attempt to decode a message whose
                                      * index is earlier than our earliest
                                      * known session key.
                                      */

    /**
     * Attempt to unpickle an account which uses pickle version 1 (which did
     * not save enough space for the Ed25519 key; the key should be considered
     * compromised. We don't let the user reload the account.
     */
    OLM_BAD_LEGACY_ACCOUNT_PICKLE = 13,

    /**
     * Received message had a bad signature
     */
    OLM_BAD_SIGNATURE = 14,

    OLM_INPUT_BUFFER_TOO_SMALL = 15,

    /**
     * SAS doesn't have their key set.
     */
    OLM_SAS_THEIR_KEY_NOT_SET = 16,

    /**
     * The pickled object was successfully decoded, but the unpickling still failed
     * because it had some extraneous junk data at the end.
     */
    OLM_PICKLE_EXTRA_DATA = 17,

    /* remember to update the list of string constants in error.c when updating
     * this list. */
};

/** get a string representation of the given error code. */
CE_EXPORT const char * _olm_error_to_string(enum OlmErrorCode error);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_ERROR_H_ */
