/*
 * Copyright 2005 Colin Percival
 * Copyright 2013 Christian Mehlis & René Kijewski
 * Copyright 2021 Konrad-Felix Krentz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/lib/libmd/sha256c.c,v 1.2 2006/01/17 15:35:56 phk Exp $
 */

#include "sha-256.h"

#if (defined(KEYSTONE_BOOTLOADER))
#include "string.h"
#include "fixedint.h"
#elif (defined(KEYSTONE_SM))
#include <sbi/sbi_string.h>
#define memcpy sbi_memcpy
#define memset sbi_memset
#else
#include <string.h>
#endif

/* HMAC-related */
struct data_chunk {
  const uint8_t *data;
  uint32_t data_len;
};

/* Elementary functions used by SHA-256 */
#define Ch(x, y, z)  ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << (32 - n)))
#define S0(x)        (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)        (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)        (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)        (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#ifdef __BIG_ENDIAN__
/* Copy a vector of big-endian uint32_t into a vector of bytes */
#define be32enc_vect memcpy

/* Copy a vector of bytes into a vector of big-endian uint32_t */
#define be32dec_vect memcpy

#else /* !__BIG_ENDIAN__ */
#define LOAD32_BE(SRC) load32_be(SRC)
static inline uint32_t
load32_be(const uint8_t src[4])
{
  uint32_t w = (uint32_t) src[3];
  w |= (uint32_t) src[2] <<  8;
  w |= (uint32_t) src[1] << 16;
  w |= (uint32_t) src[0] << 24;
  return w;
}

#define STORE32_BE(DST, W) store32_be((DST), (W))
static inline void
store32_be(uint8_t dst[4], uint32_t w)
{
  dst[3] = (uint8_t) w; w >>= 8;
  dst[2] = (uint8_t) w; w >>= 8;
  dst[1] = (uint8_t) w; w >>= 8;
  dst[0] = (uint8_t) w;
}

static void
be32enc_vect(unsigned char *dst, const uint32_t *src, uint32_t len)
{
  uint32_t i;

  for (i = 0; i < len / 4; i++) {
    STORE32_BE(dst + i * 4, src[i]);
  }
}

static void
be32dec_vect(uint32_t *dst, const unsigned char *src, uint32_t len)
{
  uint32_t i;

  for (i = 0; i < len / 4; i++) {
    dst[i] = LOAD32_BE(src + i * 4);
  }
}
#endif /* __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */

/*---------------------------------------------------------------------------*/
/*
 * SHA-256 block compression function. The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void transform(uint32_t *state, const unsigned char block[64])
{
  uint32_t W[64];
  uint32_t S[8];
  int i;

  /* 1. Prepare message schedule W. */
  be32dec_vect(W, block, 64);
  for (i = 16; i < 64; i++) {
    W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
  }

  /* 2. Initialize working variables. */
  memcpy(S, state, 32);

  /* 3. Mix. */
  for (i = 0; i < 64; ++i) {
    uint32_t e = S[(68 - i) % 8], f = S[(69 - i) % 8];
    uint32_t g = S[(70 - i) % 8], h = S[(71 - i) % 8];
    uint32_t t0 = h + S1(e) + Ch(e, f, g) + W[i] + K[i];

    uint32_t a = S[(64 - i) % 8], b = S[(65 - i) % 8];
    uint32_t c = S[(66 - i) % 8], d = S[(67 - i) % 8];
    uint32_t t1 = S0(a) + Maj(a, b, c);

    S[(67 - i) % 8] = d + t0;
    S[(71 - i) % 8] = t0 + t1;
  }

  /* 4. Mix local working variables into global state */
  for (i = 0; i < 8; i++) {
    state[i] += S[i];
  }
}
/*---------------------------------------------------------------------------*/
/* SHA-256 initialization.  Begins a SHA-256 operation. */
static void
init(sha_256_state_t *ctx)
{
  /* Zero bits processed so far */
  ctx->soft.count[0] = ctx->soft.count[1] = 0;

  /* Magic initialization constants */
  ctx->soft.state[0] = 0x6A09E667;
  ctx->soft.state[1] = 0xBB67AE85;
  ctx->soft.state[2] = 0x3C6EF372;
  ctx->soft.state[3] = 0xA54FF53A;
  ctx->soft.state[4] = 0x510E527F;
  ctx->soft.state[5] = 0x9B05688C;
  ctx->soft.state[6] = 0x1F83D9AB;
  ctx->soft.state[7] = 0x5BE0CD19;
}
/*---------------------------------------------------------------------------*/
static void
update(sha_256_state_t *ctx, const uint8_t *in, uint32_t len)
{
  /* Number of bytes left in the buffer from previous updates */
  uint32_t r = (ctx->soft.count[1] >> 3) & 0x3f;

  /* Convert the length into a number of bits */
  uint32_t bitlen1 = ((uint32_t) len) << 3;
  uint32_t bitlen0 = ((uint32_t) len) >> 29;

  /* Update number of bits */
  if ((ctx->soft.count[1] += bitlen1) < bitlen1) {
    ctx->soft.count[0]++;
  }

  ctx->soft.count[0] += bitlen0;

  /* Handle the case where we don't need to perform any transforms */
  if (len < 64 - r) {
    memcpy(&ctx->soft.buf[r], in, len);
    return;
  }

  /* Finish the current block */
  const unsigned char *src = in;

  memcpy(&ctx->soft.buf[r], src, 64 - r);
  transform(ctx->soft.state, ctx->soft.buf);
  src += 64 - r;
  len -= 64 - r;

  /* Perform complete blocks */
  while (len >= 64) {
    transform(ctx->soft.state, src);
    src += 64;
    len -= 64;
  }

  /* Copy left over data into buffer */
  memcpy(ctx->soft.buf, src, len);
}
/*---------------------------------------------------------------------------*/
/* Add padding and terminating bit-count. */
static void sha_256_pad(sha_256_state_t *ctx)
{
  const unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  /*
   * Convert length to a vector of bytes -- we do this now rather
   * than later because the length will change after we pad.
   */
  unsigned char len[8];
  be32enc_vect(len, ctx->soft.count, 8);

  /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
  uint32_t r = (ctx->soft.count[1] >> 3) & 0x3f;
  uint32_t plen = (r < 56) ? (56 - r) : (120 - r);
  update(ctx, PAD, (uint32_t) plen);

  /* Add the terminating bit-count */
  update(ctx, len, 8);
}
/*---------------------------------------------------------------------------*/
static void
finalize(sha_256_state_t *ctx, uint8_t digest[SHA_256_DIGEST_LENGTH])
{
  /* Add padding */
  sha_256_pad(ctx);

  /* Write the hash */
  be32enc_vect(digest, ctx->soft.state, 32);

  /* Clear the context state */
  memset((void *) ctx, 0, sizeof(*ctx));
}
/*---------------------------------------------------------------------------*/
void
sha_256_hash(const uint8_t *data, uint32_t datalen,
    uint8_t result[SHA_256_DIGEST_LENGTH])
{
  sha_256_state_t state __attribute__((aligned(4)));

#ifdef KEYSTONE_BOOTLOADER
  init(&state);
  update(&state, data, datalen);
  finalize(&state, result);
#else /* KEYSTONE_BOOTLOADER */
  SHA_256.init(&state);
  SHA_256.update(&state, data, datalen);
  SHA_256.finalize(&state, result);
#endif /* KEYSTONE_BOOTLOADER */
}
/*---------------------------------------------------------------------------*/
#ifndef KEYSTONE_BOOTLOADER
static void
hmac_over_data_chunks(const uint8_t *key, uint32_t key_len,
    struct data_chunk *chunks, uint8_t chunks_count,
    uint8_t result[SHA_256_DIGEST_LENGTH])
{
  uint8_t hashed_key[SHA_256_DIGEST_LENGTH];
  uint8_t ipad[SHA_256_BLOCK_SIZE];
  uint8_t opad[SHA_256_BLOCK_SIZE];
  uint8_t i;
  uint8_t j;
  sha_256_state_t state __attribute__((aligned(4)));

  if(key_len > SHA_256_BLOCK_SIZE) {
    SHA_256.hash(key, key_len, hashed_key);
    key_len = SHA_256_DIGEST_LENGTH;
    key = hashed_key;
  }
  for(i = 0; i < key_len; i++) {
    ipad[i] = key[i] ^ 0x36;
    opad[i] = key[i] ^ 0x5c;
  }
  for(; i < SHA_256_BLOCK_SIZE; i++) {
    ipad[i] = 0x36;
    opad[i] = 0x5c;
  }

  SHA_256.init(&state);
  SHA_256.update(&state, ipad, SHA_256_BLOCK_SIZE);
  for(j = 0; j < chunks_count; j++) {
    if(chunks[j].data && chunks[j].data_len) {
      SHA_256.update(&state, chunks[j].data, chunks[j].data_len);
    }
  }
  SHA_256.finalize(&state, result);

  SHA_256.init(&state);
  SHA_256.update(&state, opad, SHA_256_BLOCK_SIZE);
  SHA_256.update(&state, result, SHA_256_DIGEST_LENGTH);
  SHA_256.finalize(&state, result);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hmac(const uint8_t *key, uint32_t key_len,
    const uint8_t *data, uint32_t data_len,
    uint8_t result[SHA_256_DIGEST_LENGTH])
{
  struct data_chunk chunk;

  chunk.data = data;
  chunk.data_len = data_len;
  hmac_over_data_chunks(key, key_len,
      &chunk, 1,
      result);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_extract(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      uint8_t prk[SHA_256_DIGEST_LENGTH])
{
  sha_256_hmac(salt, salt_len, ikm, ikm_len, prk);
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_expand(const uint8_t *prk, uint32_t prk_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len)
{
  struct data_chunk chunks[3];
  uint8_t n;
  uint8_t i;
  uint8_t t_i[SHA_256_DIGEST_LENGTH];

  n = okm_len / SHA_256_DIGEST_LENGTH
      + (okm_len % SHA_256_DIGEST_LENGTH ? 1 : 0);

  chunks[0].data = t_i;
  chunks[0].data_len = SHA_256_DIGEST_LENGTH;
  chunks[1].data = info;
  chunks[1].data_len = info_len;
  chunks[2].data = &i;
  chunks[2].data_len = 1;

  for(i = 1; i <= n; i++) {
    hmac_over_data_chunks(prk, prk_len,
        chunks + (i == 1), 3 - (i == 1),
        t_i);
    memcpy(okm + ((i - 1) * SHA_256_DIGEST_LENGTH),
        t_i,
        SHA_256_DIGEST_LENGTH < okm_len ? SHA_256_DIGEST_LENGTH : okm_len);
    okm_len -= SHA_256_DIGEST_LENGTH;
  }
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len)
{
  uint8_t prk[SHA_256_DIGEST_LENGTH];

  sha_256_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
  sha_256_hkdf_expand(prk, sizeof(prk), info, info_len, okm, okm_len);
}
/*---------------------------------------------------------------------------*/
const struct sha_256_driver sha_256_driver = {
  init,
  update,
  finalize,
  sha_256_hash
};
#endif
/*---------------------------------------------------------------------------*/
