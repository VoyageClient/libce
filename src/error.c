/* See LICENSE file for copyright and license details. */
#include "libce/error.h"

static const char * ERRORS[] = {
    "SUCCESS",
    "NOT_ENOUGH_RANDOM",
    "OUTPUT_BUFFER_TOO_SMALL",
    "BAD_MESSAGE_VERSION",
    "BAD_MESSAGE_FORMAT",
    "BAD_MESSAGE_MAC",
    "BAD_MESSAGE_KEY_ID",
    "INVALID_BASE64",
    "BAD_ACCOUNT_KEY",
    "UNKNOWN_PICKLE_VERSION",
    "CORRUPTED_PICKLE",
    "BAD_SESSION_KEY",
    "UNKNOWN_MESSAGE_INDEX",
    "BAD_LEGACY_ACCOUNT_PICKLE",
    "BAD_SIGNATURE",
    "OLM_INPUT_BUFFER_TOO_SMALL",
    "OLM_SAS_THEIR_KEY_NOT_SET",
    "OLM_PICKLE_EXTRA_DATA",
    "OLM_UNSEEDED_ACCOUNT"
};

const char * _olm_error_to_string(OlmErrorCode error)
{
    if (error < (sizeof(ERRORS)/sizeof(ERRORS[0]))) {
        return ERRORS[error];
    } else {
        return "UNKNOWN_ERROR";
    }
}
