/* See LICENSE file for copyright and license details. */
#include "libce/memory.h"

void _olm_unset(
    void volatile * buffer, size_t buffer_length
) {
    char volatile * pos = (char volatile *)buffer;
    char volatile * end = pos + buffer_length;
    while (pos != end) {
        *(pos++) = 0;
    }
}


bool _olm_is_equal(
    const uint8_t * buffer_a,
    const uint8_t * buffer_b,
    size_t length
) {
    uint8_t volatile result = 0;
    while (length--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }
    return result == 0;
}
