/* See LICENSE file for copyright and license details. */
#include "libce/pickle.h"

#include "libce/crypto.h"

#include <string.h>


uint8_t * _olm_pickle_uint8(
    uint8_t * pos,
    uint8_t value
) {
    *(pos++) = value;
    return pos;
}


const uint8_t * _olm_unpickle_uint8(
    const uint8_t * pos,
    const uint8_t * end,
    uint8_t * value
) {
    if (!pos || pos == end) {
        return NULL;
    }
    *value = *(pos++);
    return pos;
}


uint8_t * _olm_pickle_uint32(
    uint8_t * pos,
    uint32_t value
) {
    pos[0] = (uint8_t)(value >> 24);
    pos[1] = (uint8_t)(value >> 16);
    pos[2] = (uint8_t)(value >> 8);
    pos[3] = (uint8_t)value;
    return pos + 4;
}


const uint8_t * _olm_unpickle_uint32(
    const uint8_t * pos,
    const uint8_t * end,
    uint32_t * value
) {
    if (!pos || end < pos + 4) {
        return NULL;
    }

    *value = ((uint32_t)pos[0] << 24)
        | ((uint32_t)pos[1] << 16)
        | ((uint32_t)pos[2] << 8)
        | (uint32_t)pos[3];

    return pos + 4;
}


uint8_t * _olm_pickle_bool(
    uint8_t * pos,
    int value
) {
    *(pos++) = value ? 1 : 0;
    return pos;
}


const uint8_t * _olm_unpickle_bool(
    const uint8_t * pos,
    const uint8_t * end,
    int * value
) {
    if (!pos || pos == end) {
        return NULL;
    }
    *value = *(pos++) ? 1 : 0;
    return pos;
}


uint8_t * _olm_pickle_bytes(
    uint8_t * pos,
    const uint8_t * bytes,
    size_t bytes_length
) {
    memcpy(pos, bytes, bytes_length);
    return pos + bytes_length;
}


const uint8_t * _olm_unpickle_bytes(
    const uint8_t * pos,
    const uint8_t * end,
    uint8_t * bytes,
    size_t bytes_length
) {
    if (!pos || end < pos + bytes_length) {
        return NULL;
    }
    memcpy(bytes, pos, bytes_length);
    return pos + bytes_length;
}


size_t _olm_pickle_curve25519_public_key_length(
    const _olm_curve25519_public_key * value
) {
    return sizeof(value->public_key);
}


uint8_t * _olm_pickle_curve25519_public_key(
    uint8_t * pos,
    const _olm_curve25519_public_key * value
) {
    return _olm_pickle_bytes(pos, value->public_key, sizeof(value->public_key));
}


const uint8_t * _olm_unpickle_curve25519_public_key(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_curve25519_public_key * value
) {
    return _olm_unpickle_bytes(pos, end, value->public_key, sizeof(value->public_key));
}


size_t _olm_pickle_curve25519_key_pair_length(
    const _olm_curve25519_key_pair * value
) {
    return sizeof(value->public_key.public_key)
        + sizeof(value->private_key.private_key);
}


uint8_t * _olm_pickle_curve25519_key_pair(
    uint8_t * pos,
    const _olm_curve25519_key_pair * value
) {
    pos = _olm_pickle_bytes(
        pos,
        value->public_key.public_key,
        sizeof(value->public_key.public_key)
    );
    pos = _olm_pickle_bytes(
        pos,
        value->private_key.private_key,
        sizeof(value->private_key.private_key)
    );
    return pos;
}


const uint8_t * _olm_unpickle_curve25519_key_pair(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_curve25519_key_pair * value
) {
    pos = _olm_unpickle_bytes(
        pos,
        end,
        value->public_key.public_key,
        sizeof(value->public_key.public_key)
    );
    if (!pos) {
        return NULL;
    }

    pos = _olm_unpickle_bytes(
        pos,
        end,
        value->private_key.private_key,
        sizeof(value->private_key.private_key)
    );
    if (!pos) {
        return NULL;
    }

    return pos;
}


size_t _olm_pickle_ed25519_public_key_length(
    const _olm_ed25519_public_key * value
) {
    return sizeof(value->public_key);
}


uint8_t * _olm_pickle_ed25519_public_key(
    uint8_t * pos,
    const _olm_ed25519_public_key * value
) {
    return _olm_pickle_bytes(pos, value->public_key, sizeof(value->public_key));
}


const uint8_t * _olm_unpickle_ed25519_public_key(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_ed25519_public_key * value
) {
    return _olm_unpickle_bytes(pos, end, value->public_key, sizeof(value->public_key));
}


size_t _olm_pickle_ed25519_key_pair_length(
    const _olm_ed25519_key_pair * value
) {
    return sizeof(value->public_key.public_key)
        + sizeof(value->private_key.private_key);
}


uint8_t * _olm_pickle_ed25519_key_pair(
    uint8_t * pos,
    const _olm_ed25519_key_pair * value
) {
    pos = _olm_pickle_bytes(
        pos,
        value->public_key.public_key,
        sizeof(value->public_key.public_key)
    );
    pos = _olm_pickle_bytes(
        pos,
        value->private_key.private_key,
        sizeof(value->private_key.private_key)
    );
    return pos;
}


const uint8_t * _olm_unpickle_ed25519_key_pair(
    const uint8_t * pos,
    const uint8_t * end,
    _olm_ed25519_key_pair * value
) {
    pos = _olm_unpickle_bytes(
        pos,
        end,
        value->public_key.public_key,
        sizeof(value->public_key.public_key)
    );
    if (!pos) {
        return NULL;
    }

    pos = _olm_unpickle_bytes(
        pos,
        end,
        value->private_key.private_key,
        sizeof(value->private_key.private_key)
    );
    if (!pos) {
        return NULL;
    }

    return pos;
}
