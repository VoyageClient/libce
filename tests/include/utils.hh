/* See LICENSE file for copyright and license details. */
#include <string.h>

#include "libce/pickle_encoding.h"

size_t add_junk_suffix_to_pickle(void const * key, size_t key_length,
    void * pickled, size_t pickled_length, size_t junk_length)
{
    size_t raw_length = _olm_enc_input((uint8_t const *) key, key_length,
        (uint8_t *) pickled, pickled_length, nullptr);

    /* Insert junk. */
    size_t new_length = raw_length + junk_length;
    uint8_t * pos = (uint8_t *) pickled + raw_length;
    while (junk_length--) {
        *pos++ = 255;
    }

    void * dest = _olm_enc_output_pos((uint8_t *) pickled, new_length);
    memmove(dest, pickled, new_length);

    return _olm_enc_output(
        (uint8_t const *) key, key_length, (uint8_t *) pickled, new_length);
}
