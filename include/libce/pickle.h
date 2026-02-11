/* See LICENSE file for copyright and license details. */
#ifndef OLM_PICKLE_H_
#define OLM_PICKLE_H_

#include <stddef.h>
#include <stdint.h>

/* Convenience macro for checking the return value of internal unpickling
 * functions and returning early on failure. */
#ifndef UNPICKLE_OK
#define UNPICKLE_OK(x) do { if (!(x)) return NULL; } while(0)
#endif

/* Convenience macro for failing on corrupted pickles from public
 * API unpickling functions. */
#define FAIL_ON_CORRUPTED_PICKLE(pos, session) \
    do { \
        if (!pos) { \
          session->last_error = OLM_CORRUPTED_PICKLE;  \
          return (size_t)-1; \
        } \
    } while(0)

#define _OLM_PICKLE_UINT8_LENGTH(value) 1
#define _OLM_PICKLE_UINT32_LENGTH(value) 4
#define _OLM_PICKLE_BOOL_LENGTH(value) 1
#define _OLM_PICKLE_BYTES_LENGTH(bytes, bytes_length) (bytes_length)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _olm_curve25519_public_key _olm_curve25519_public_key;
typedef struct _olm_curve25519_key_pair _olm_curve25519_key_pair;
typedef struct _olm_ed25519_public_key _olm_ed25519_public_key;
typedef struct _olm_ed25519_key_pair _olm_ed25519_key_pair;


uint8_t * _olm_pickle_uint8(
    uint8_t * pos,
    uint8_t value
);

uint8_t const * _olm_unpickle_uint8(
    uint8_t const * pos,
    uint8_t const * end,
    uint8_t * value
);


uint8_t * _olm_pickle_uint32(
    uint8_t * pos,
    uint32_t value
);

uint8_t const * _olm_unpickle_uint32(
    uint8_t const * pos,
    uint8_t const * end,
    uint32_t * value
);


uint8_t * _olm_pickle_bool(
    uint8_t * pos,
    int value
);

uint8_t const * _olm_unpickle_bool(
    uint8_t const * pos,
    uint8_t const * end,
    int * value
);


uint8_t * _olm_pickle_bytes(
    uint8_t * pos,
    uint8_t const * bytes,
    size_t bytes_length
);

uint8_t const * _olm_unpickle_bytes(
    uint8_t const * pos,
    uint8_t const * end,
    uint8_t * bytes,
    size_t bytes_length
);


/** Get the number of bytes needed to pickle a curve25519 public key */
size_t _olm_pickle_curve25519_public_key_length(
    const _olm_curve25519_public_key * value
);

/** Pickle the curve25519 public key. Returns a pointer to the next free space
 * in the buffer. */
uint8_t * _olm_pickle_curve25519_public_key(
    uint8_t * pos,
    const _olm_curve25519_public_key * value
);

/** Unpickle the curve25519 public key. Returns a pointer to the next item in
 * the buffer on success, NULL on error. */
const uint8_t * _olm_unpickle_curve25519_public_key(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_curve25519_public_key * value
);


/** Get the number of bytes needed to pickle a curve25519 key pair */
size_t _olm_pickle_curve25519_key_pair_length(
    const _olm_curve25519_key_pair * value
);

/** Pickle the curve25519 key pair. Returns a pointer to the next free space in
 * the buffer. */
uint8_t * _olm_pickle_curve25519_key_pair(
    uint8_t * pos,
    const _olm_curve25519_key_pair * value
);

/** Unpickle the curve25519 key pair. Returns a pointer to the next item in the
 * buffer on success, NULL on error. */
const uint8_t * _olm_unpickle_curve25519_key_pair(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_curve25519_key_pair * value
);


/** Get the number of bytes needed to pickle an ed25519 public key */
size_t _olm_pickle_ed25519_public_key_length(
    const _olm_ed25519_public_key * value
);

/** Pickle the ed25519 public key. Returns a pointer to the next free space in
 * the buffer. */
uint8_t * _olm_pickle_ed25519_public_key(
    uint8_t * pos,
    const _olm_ed25519_public_key * value
);

/** Unpickle the ed25519 public key. Returns a pointer to the next item in the
 * buffer on success, NULL on error. */
const uint8_t * _olm_unpickle_ed25519_public_key(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_ed25519_public_key * value
);


/** Get the number of bytes needed to pickle an ed25519 key pair */
size_t _olm_pickle_ed25519_key_pair_length(
    const _olm_ed25519_key_pair * value
);

/** Pickle the ed25519 key pair. Returns a pointer to the next free space in
 * the buffer. */
uint8_t * _olm_pickle_ed25519_key_pair(
    uint8_t * pos,
    const _olm_ed25519_key_pair * value
);

/** Unpickle the ed25519 key pair. Returns a pointer to the next item in the
 * buffer on success, NULL on error. */
const uint8_t * _olm_unpickle_ed25519_key_pair(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_ed25519_key_pair * value
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_PICKLE_H_ */
