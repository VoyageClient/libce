/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* Constant-time bitsliced AES from BearSSL (src/symcipher/aes_ct64*),
 * trimmed to a standalone module: the vtable indirection and inner.h are
 * replaced by this header, which carries the codec helpers the sources
 * used from inner.h. No other changes. */

#ifndef AES_CT64_H
#define AES_CT64_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t skey[30];
    unsigned num_rounds;
} br_aes_ct64_cbcenc_keys;

typedef struct {
    uint64_t skey[30];
    unsigned num_rounds;
} br_aes_ct64_cbcdec_keys;

void br_aes_ct64_bitslice_Sbox(uint64_t *q);
void br_aes_ct64_bitslice_invSbox(uint64_t *q);
void br_aes_ct64_ortho(uint64_t *q);
void br_aes_ct64_interleave_in(uint64_t *q0, uint64_t *q1, const uint32_t *w);
void br_aes_ct64_interleave_out(uint32_t *w, uint64_t q0, uint64_t q1);
unsigned br_aes_ct64_keysched(uint64_t *comp_skey, const void *key, size_t key_len);
void br_aes_ct64_skey_expand(uint64_t *skey, unsigned num_rounds, const uint64_t *comp_skey);
void br_aes_ct64_bitslice_encrypt(unsigned num_rounds, const uint64_t *skey, uint64_t *q);
void br_aes_ct64_bitslice_decrypt(unsigned num_rounds, const uint64_t *skey, uint64_t *q);

void br_aes_ct64_cbcenc_init(br_aes_ct64_cbcenc_keys *ctx, const void *key, size_t len);
void br_aes_ct64_cbcenc_run(const br_aes_ct64_cbcenc_keys *ctx, void *iv, void *data, size_t len);
void br_aes_ct64_cbcdec_init(br_aes_ct64_cbcdec_keys *ctx, const void *key, size_t len);
void br_aes_ct64_cbcdec_run(const br_aes_ct64_cbcdec_keys *ctx, void *iv, void *data, size_t len);

static inline uint32_t
br_dec32le(const void *src)
{
    const unsigned char *buf = (const unsigned char *)src;
    return (uint32_t)buf[0]
        | ((uint32_t)buf[1] << 8)
        | ((uint32_t)buf[2] << 16)
        | ((uint32_t)buf[3] << 24);
}

static inline void
br_enc32le(void *dst, uint32_t x)
{
    unsigned char *buf = (unsigned char *)dst;
    buf[0] = (unsigned char)x;
    buf[1] = (unsigned char)(x >> 8);
    buf[2] = (unsigned char)(x >> 16);
    buf[3] = (unsigned char)(x >> 24);
}

static inline void
br_range_dec32le(uint32_t *v, size_t num, const void *src)
{
    const unsigned char *buf = (const unsigned char *)src;
    while (num-- > 0) {
        *v++ = br_dec32le(buf);
        buf += 4;
    }
}

static inline void
br_range_enc32le(void *dst, const uint32_t *v, size_t num)
{
    unsigned char *buf = (unsigned char *)dst;
    while (num-- > 0) {
        br_enc32le(buf, *v++);
        buf += 4;
    }
}

#endif
