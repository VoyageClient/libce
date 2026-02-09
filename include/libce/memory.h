/* See LICENSE file for copyright and license details. */
#ifndef OLM_MEMORY_H_
#define OLM_MEMORY_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

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

/** Check if two fixed size arrays are equals */
#define _OLM_ARRAY_EQUAL(a, b) \
    _olm_is_equal((const uint8_t *)(a), (const uint8_t *)(b), sizeof(a))

/** Copy into a fixed size array */
#define _OLM_LOAD_ARRAY(dest, src) \
    (memcpy((dest), (src), sizeof(dest)), ((const uint8_t *)(src)) + sizeof(dest))

/** Copy from a fixed size array */
#define _OLM_STORE_ARRAY(dst, src) \
    (memcpy((dst), (src), sizeof(src)), (dst) + sizeof(src))

/** Clear the memory backing an object */
#define _OLM_UNSET_VALUE(v) \
    _olm_unset((void volatile *)&(v), sizeof(v))


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OLM_MEMORY_H_ */
