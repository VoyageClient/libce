/* See LICENSE file for copyright and license details. */
#ifndef OLM_MEMORY_H_
#define OLM_MEMORY_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Clear the memory held in the buffer. This is more resilient to being
 * optimised away than memset or bzero.
 */
void _olm_unset(
    void volatile * buffer, size_t buffer_length
);

/** Check if two buffers are equal in constant time. */
bool _olm_is_equal(
    uint8_t const * buffer_a,
    uint8_t const * buffer_b,
    size_t length
);

static inline const uint8_t * _olm_load_array_impl(
    void * dest,
    const void * src,
    size_t array_size
) {
    memcpy(dest, src, array_size);
    return ((const uint8_t *)src) + array_size;
}

static inline uint8_t * _olm_store_array_impl(
    void * dst,
    const void * src,
    size_t array_size
) {
    memcpy(dst, src, array_size);
    return ((uint8_t *)dst) + array_size;
}

/** Check if two fixed size arrays are equals */
#define _OLM_ARRAY_EQUAL(a, b) \
    _olm_is_equal((const uint8_t *)(a), (const uint8_t *)(b), sizeof(a))

/** Copy into a fixed size array */
#define _OLM_LOAD_ARRAY(dest, src) \
    _olm_load_array_impl((dest), (src), sizeof(dest))

/** Copy from a fixed size array */
#define _OLM_STORE_ARRAY(dst, src) \
    _olm_store_array_impl((dst), (src), sizeof(src))

/** Clear the memory backing an object */
#define _OLM_UNSET_VALUE(v) \
    _olm_unset((void volatile *)&(v), sizeof(v))


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_MEMORY_H_ */
