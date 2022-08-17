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
#define memcpy __builtin_memcpy
#define memset __builtin_memset
#endif

/*---------------------------------------------------------------------------*/
/* SHA-256 initialization.  Begins a SHA-256 operation. */
static void
init(sha_256_state_t *ctx)
{
}
/*---------------------------------------------------------------------------*/
static void
update(sha_256_state_t *ctx, const uint8_t *in, uint32_t len)
{
}
/*---------------------------------------------------------------------------*/
static void
finalize(sha_256_state_t *ctx, uint8_t digest[SHA_256_DIGEST_LENGTH])
{
}
/*---------------------------------------------------------------------------*/
void
sha_256_hash(const uint8_t *data, uint32_t datalen,
    uint8_t result[SHA_256_DIGEST_LENGTH])
{
}
/*---------------------------------------------------------------------------*/
#ifndef KEYSTONE_BOOTLOADER
/*---------------------------------------------------------------------------*/
void
sha_256_hmac(const uint8_t *key, uint32_t key_len,
    const uint8_t *data, uint32_t data_len,
    uint8_t result[SHA_256_DIGEST_LENGTH])
{
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_extract(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      uint8_t prk[SHA_256_DIGEST_LENGTH])
{
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf_expand(const uint8_t *prk, uint32_t prk_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len)
{
}
/*---------------------------------------------------------------------------*/
void
sha_256_hkdf(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len)
{
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
