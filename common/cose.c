/*
 * Copyright (c) 2018, SICS, RISE AB
 * Copyright (c) 2021, Uppsala universitet
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      An implementation of the CBOR Object Signing and Encryption (RFC).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * added sign1 addition for coaplib
 *      Peter van der Stok <consultancy@vanderstok.org >
 *
 */

#include "cose.h"
#include "cbor.h"
#ifdef WITH_CONTIKI
#include "lib/aes-128.h"
#include "lib/ccm-star.h"
#else /* WITH_CONTIKI */
#include "aes-128.h"
#include "ccm-star.h"
#endif /* WITH_CONTIKI */
#include <string.h>
#include <stdio.h>

int
cose_encrypt0_encrypt(const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t plaintext_len,
    const uint8_t key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN])
{
  if (!aad || !aad_len) {
    return -1;
  }
  if (!plaintext) {
    return -2;
  }

#ifdef WITH_CONTIKI
  while(!AES_128.get_lock());
#endif /* WITH_CONTIKI */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce,
      plaintext, plaintext_len,
      aad, aad_len,
      plaintext + plaintext_len, COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
      true);
#ifdef WITH_CONTIKI
  AES_128.release_lock();
#endif /* WITH_CONTIKI */

  return plaintext_len + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
}

int
cose_encrypt0_decrypt(const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN])
{
  uint8_t expected_tag[COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN];
  uint16_t m_len;

  if (!aad || !aad_len) {
    return -1;
  }
  if (!ciphertext) {
    return -2;
  }
  if (ciphertext_len < COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN) {
    return -3;
  }

  m_len = ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;

#ifdef WITH_CONTIKI
  while(!AES_128.get_lock());
#endif /* WITH_CONTIKI */
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce,
      ciphertext, m_len,
      aad, aad_len,
      expected_tag, COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
      false);
#ifdef WITH_CONTIKI
  AES_128.release_lock();
#endif /* WITH_CONTIKI */

  if(memcmp(expected_tag,
      ciphertext + m_len,
      COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)) {
    return -4;
  }

  return m_len;
}
