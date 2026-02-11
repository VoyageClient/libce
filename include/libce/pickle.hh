/* See LICENSE file for copyright and license details. */
#ifndef OLM_PICKLE_HH_
#define OLM_PICKLE_HH_

#include "libce/crypto.h"

#include <cstring>
#include <cstdint>

/* Convenience macro for checking the return value of internal unpickling
 * functions and returning early on failure. */
#ifndef UNPICKLE_OK
#define UNPICKLE_OK(x) do { if (!(x)) return nullptr; } while(0)
#endif

namespace olm {

inline std::size_t pickle_length(
    const std::uint32_t & value
) {
    return 4;
}

std::uint8_t * pickle(
    std::uint8_t * pos,
    std::uint32_t value
);

std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    std::uint32_t & value
);


inline std::size_t pickle_length(
    const std::uint8_t & value
) {
    return 1;
}

std::uint8_t * pickle(
    std::uint8_t * pos,
    std::uint8_t value
);

std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    std::uint8_t & value
);


inline std::size_t pickle_length(
    const bool & value
) {
    return 1;
}

std::uint8_t * pickle(
    std::uint8_t * pos,
    bool value
);

std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    bool & value
);


std::uint8_t * pickle_bytes(
    std::uint8_t * pos,
    std::uint8_t const * bytes, std::size_t bytes_length
);

std::uint8_t const * unpickle_bytes(
    std::uint8_t const * pos, std::uint8_t const * end,
    std::uint8_t * bytes, std::size_t bytes_length
);


std::size_t pickle_length(
    const _olm_curve25519_public_key & value
);


std::uint8_t * pickle(
    std::uint8_t * pos,
    const _olm_curve25519_public_key & value
);


std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    _olm_curve25519_public_key & value
);


std::size_t pickle_length(
    const _olm_curve25519_key_pair & value
);


std::uint8_t * pickle(
    std::uint8_t * pos,
    const _olm_curve25519_key_pair & value
);


std::uint8_t const * unpickle(
    std::uint8_t const * pos, std::uint8_t const * end,
    _olm_curve25519_key_pair & value
);

} // namespace olm




#endif /* OLM_PICKLE_HH */
