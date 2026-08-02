/*
 * Substituted from lib/libsodium/src/libsodium/include/sodium/version.h.in.
 * The submodule ships only the template; autotools fills this in, and the
 * Android build does not run autotools. Keep in sync with the submodule pin.
 */

#ifndef sodium_version_H
#define sodium_version_H

#include "sodium/export.h"

#define SODIUM_VERSION_STRING "1.0.22"

#define SODIUM_LIBRARY_VERSION_MAJOR 26
#define SODIUM_LIBRARY_VERSION_MINOR 4

#ifdef __cplusplus
extern "C" {
#endif

SODIUM_EXPORT
const char *sodium_version_string(void);

SODIUM_EXPORT
int         sodium_library_version_major(void);

SODIUM_EXPORT
int         sodium_library_version_minor(void);

SODIUM_EXPORT
int         sodium_library_minimal(void);

#ifdef __cplusplus
}
#endif

#endif
