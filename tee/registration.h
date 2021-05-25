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

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "coap3/coap_libcoap_build.h"
#include "filtering_ocall.h"
#include "report.h"
#if !WITH_TRAP
#include "uECC.h"
#endif /* WITH_TRAP */

typedef struct registration_t {
  struct registration_t *next;
  bool is_complete;
  uint8_t ephemeral_public_key_head[ECC_CURVE_P_256_SIZE];
  struct {
    oscore_ng_context_t context;
    oscore_ng_keying_material_t keying_material;
    union {
      uint8_t okm[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN
                  + AES_128_KEY_LENGTH];
      struct {
        uint8_t oscore_ng_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
        uint8_t otp_key[AES_128_KEY_LENGTH];
      };
    };
  } tunnel;
  union {
    struct {
      uint8_t attestation_report[MAX_ATTESTATION_REPORT_SIZE];
      size_t attestation_report_size;
#if WITH_TRAP
      uint8_t clients_fhmqv_mic[FHMQV_MIC_LEN];
#endif /* WITH_TRAP */
    };
    struct {
      LIST_STRUCT(iot_messages);
      LIST_STRUCT(iot_client_sessions);
      uint16_t next_message_id;
      oscore_ng_keying_material_t disclosed_keying_material;
      uint8_t master_secret[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
      uint8_t master_salt[SHA_256_BLOCK_SIZE];
    };
  };
} registration_t;

void registration_init(void);
registration_t *registration_create(
    const uint8_t ephemeral_public_key_head[ECC_CURVE_P_256_SIZE]);
int registration_complete(
    registration_t *registration,
    const uint8_t master_secret[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t *master_salt, size_t master_salt_len,
    bool *has_existed);
registration_t *registration_find_ongoing(
    const uint8_t *ephemeral_public_key_head,
    size_t head_len);
const oscore_ng_id_t *registration_get_iot_device_id(
    registration_t *registration);
registration_t *registration_find(
    const oscore_ng_id_t *iot_device_id);
void registration_delete(registration_t *registration);
