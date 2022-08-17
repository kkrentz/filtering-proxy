/*
 * Copyright (c) 2021, Uppsala universitet.
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
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Platform-independent SHA-256 API.
 * \author
 *         Konrad Krentz <konrad.krentz@gmail.com>
 */

#ifndef SHA_256_H_
#define SHA_256_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA_256_DIGEST_LENGTH 32
#define SHA_256_BLOCK_SIZE 64

#ifndef KEYSTONE_BOOTLOADER
#ifdef SHA_256_CONF
#define SHA_256 SHA_256_CONF
#else /* SHA_256_CONF */
#define SHA_256 sha_256_driver
#endif /* SHA_256_CONF */
#endif

typedef union {
  struct {
    /* used by software implementation */
    uint32_t state[SHA_256_DIGEST_LENGTH / sizeof(uint32_t)];
    uint8_t buf[SHA_256_BLOCK_SIZE];
    uint32_t count[2];
  } soft;

  struct {
    /* used by CC2538 implementation */
    uint32_t state[SHA_256_DIGEST_LENGTH / sizeof(uint32_t)];
    uint8_t buf[SHA_256_BLOCK_SIZE];
    int was_crypto_enabled;
    uint32_t length;
    uint32_t curlen;
  } cc2538;
} sha_256_state_t;

/**
 * Structure of SHA-256 drivers.
 */
struct sha_256_driver {

  /**
   * \brief Initializes the hash state.
   * \param state pointer to the hash state to initialize
   */
  void (* init)(sha_256_state_t *state);

  /**
   * \brief Processes a block of data.
   * \param state pointer to the hash state
   * \param data  pointer to the data to hash
   * \param len   length of the data to hash in bytes
   */
  void (* update)(sha_256_state_t *state,
      const uint8_t *data, uint32_t len);

  /**
   * \brief Terminates a hash session and produces the digest.
   * \param state pointer to the hash state
   * \param hash  pointer to the hash
   */
  void (* finalize)(sha_256_state_t *state,
      uint8_t hash[SHA_256_DIGEST_LENGTH]);

  /**
   * \brief Does init, process, and done at once.
   * \param data pointer to the data to hash
   * \param len  length of the data to hash in bytes
   * \param hash pointer to the hash
   */
  void (* hash)(const uint8_t *data,
      uint32_t datalen,
      uint8_t hash[SHA_256_DIGEST_LENGTH]);
};

#ifndef KEYSTONE_BOOTLOADER
extern const struct sha_256_driver SHA_256;
#endif /* KEYSTONE_BOOTLOADER */

/**
 * \brief Generic implementation of sha_256_driver#hash.
 */
void sha_256_hash(const uint8_t *data, uint32_t datalen,
    uint8_t result[SHA_256_DIGEST_LENGTH]);

#ifndef KEYSTONE_BOOTLOADER
/**
 * \brief Computes HMAC-SHA-256 as per RFC 2104.
 */
void sha_256_hmac(const uint8_t *key, uint32_t key_len,
    const uint8_t *data, uint32_t data_len,
    uint8_t result[SHA_256_DIGEST_LENGTH]);

/**
 * \brief Extracts a key as per RFC 5869.
 * \param salt     may be null
 * \param salt_len length of salt in bytes
 * \param ikm      input keying material
 * \param ikm_len  length of ikm in bytes
 * \param prk      pointer to where the extracted key shall be stored
 */
void sha_256_hkdf_extract(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      uint8_t prk[SHA_256_DIGEST_LENGTH]);

/**
 * \brief Expands a key as per RFC 5869.
 * \param prk      a pseudorandom key of at least SHA_256_DIGEST_LENGTH bytes
 * \param prk_len  length of prk in bytes
 * \param info     optional context and application specific information
 * \param info_len length of info in bytes
 * \param okm      output keying material
 * \param okm_len  length of okm in bytes (<= 255 * SHA_256_DIGEST_LENGTH)
 */
void sha_256_hkdf_expand(const uint8_t *prk, uint32_t prk_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len);

/**
 * \brief Performs both extraction and expansion as per RFC 5869.
 */
void sha_256_hkdf(const uint8_t *salt, uint32_t salt_len,
      const uint8_t *ikm, uint32_t ikm_len,
      const uint8_t *info, uint32_t info_len,
      uint8_t *okm, uint16_t okm_len);
#endif /* KEYSTONE_BOOTLOADER */

#ifdef __cplusplus
}
#endif

#endif /* SHA_256_H_ */
