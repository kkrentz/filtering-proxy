/*
 * Copyright (c) 2022, Uppsala universitet.
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
 */

#include "app/string.h"
#include "app/syscall.h"
#include "sha-256.h"

#include "crypto.h"

#include "log.h"

int
crypto_generate_key_pair(uint8_t public_key[uECC_BYTES * 2],
    uint8_t private_key[uECC_BYTES])
{
  LOG_MESSAGE("NOT USING REAL RANDOMNESS\n");

  if (!uECC_make_key(public_key,
      private_key,
      uECC_CURVE())) {
    return 0;
  }
  return 1;
}

int
crypto_generate_session_keys(uint8_t session_keys[AES_128_KEY_LENGTH * 2],
    const uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES],
    const uint8_t enclaves_ephemeral_private_key[uECC_BYTES])
{
  uint8_t iot_devices_ephemeral_public_key[uECC_BYTES * 2];
  uint8_t k[uECC_BYTES];

  uECC_decompress(iot_devices_ephemeral_public_key_compressed,
      iot_devices_ephemeral_public_key,
      uECC_CURVE());
  if(!uECC_shared_secret(iot_devices_ephemeral_public_key,
      enclaves_ephemeral_private_key,
      k,
      uECC_CURVE())) {
    return 0;
  }
  sha_256_hkdf(iot_devices_ephemeral_public_key_compressed, 1 + uECC_BYTES,
      k, sizeof(k),
      NULL, 0,
      session_keys, AES_128_KEY_LENGTH * 2);
  return 1;
}

void
crypto_generate_report(uint8_t result[FILTERING_OCALL_REPORT_LEN],
    const uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES],
    const uint8_t enclaves_ephemeral_public_key[uECC_BYTES * 2])
{
  uint8_t concatenated_public_keys[1 + uECC_BYTES + 1 + uECC_BYTES];

  memcpy(concatenated_public_keys,
      iot_devices_ephemeral_public_key_compressed,
      1 + uECC_BYTES);
  uECC_compress(enclaves_ephemeral_public_key,
      concatenated_public_keys + 1 + uECC_BYTES,
      uECC_CURVE());
  attest_enclave(result,
      concatenated_public_keys,
      sizeof(concatenated_public_keys));
}
