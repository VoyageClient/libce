/* See LICENSE file for copyright and license details. */
#include "libce/memory.hh"
#include "libce/memory.h"

void _olm_unset(
    void volatile * buffer, size_t buffer_length
) {
    olm::unset(buffer, buffer_length);
}

void olm::unset(
    void volatile * buffer, std::size_t buffer_length
) {
    char volatile * pos = reinterpret_cast<char volatile *>(buffer);
    char volatile * end = pos + buffer_length;
    while (pos != end) {
        *(pos++) = 0;
    }
}


bool olm::is_equal(
    std::uint8_t const * buffer_a,
    std::uint8_t const * buffer_b,
    std::size_t length
) {
    std::uint8_t volatile result = 0;
    while (length--) {
        result |= (*(buffer_a++)) ^ (*(buffer_b++));
    }
    return result == 0;
}
