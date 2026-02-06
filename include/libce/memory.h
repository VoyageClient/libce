/* See LICENSE file for copyright and license details. */

/* C bindings for memory functions */


#ifndef OLM_MEMORY_H_
#define OLM_MEMORY_H_

#include <stddef.h>

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

#ifdef __cplusplus
} // extern "C"
#endif


#endif /* OLM_MEMORY_H_ */
