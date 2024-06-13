/*
 * Copyright (c) 2022, Uppsala universitet.
 * Copyright (c) 2025, Siemens AG.
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

#include <stddef.h>
#include <stdint.h>

#include "coap3/coap_libcoap_build.h"

#define FILTERING_OCALL_DISCLOSE_OK_LEN \
  (sizeof(filtering_ocall_oscore_ng_data_t) \
   + 1 \
   + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)
#define CSL_FRAMER_POTR_OTP_LEN (2)
#define FILTERING_OCALL_MAX_PAYLOAD_LEN \
  (sizeof(filtering_ocall_oscore_ng_data_t) + 1280 - 40 - 8)

typedef enum filtering_ocall_id_t {
  FILTERING_OCALL_ACCEPT_OCALL,
  FILTERING_OCALL_PRINT_BUFFER,
  FILTERING_OCALL_PRINT_VALUE,
  FILTERING_OCALL_PRINT_BYTES,
#if !WITH_TRAP
  FILTERING_OCALL_COOKIE,
#endif /* !WITH_TRAP */
  FILTERING_OCALL_GOT_REPORT,
  FILTERING_OCALL_DISCLOSE_ANSWER,
  FILTERING_OCALL_OSCORE_NG_ANSWER,
  FILTERING_OCALL_PROXY_REQUEST_ANSWER,
  FILTERING_OCALL_PROXY_RESPONSE_ANSWER,
  FILTERING_OCALL_COUNT
} filtering_ocall_id_t;

typedef enum filtering_ocall_message_type_t {
#if !WITH_TRAP
  FILTERING_OCALL_KNOCK_MESSAGE,
  FILTERING_OCALL_COOKIE_MESSAGE,
#endif /* !WITH_TRAP */
  FILTERING_OCALL_REGISTER_MESSAGE,
  FILTERING_OCALL_PROXY_REQUEST_MESSAGE,
  FILTERING_OCALL_DROP_REQUEST_MESSAGE,
  FILTERING_OCALL_FORWARD_REQUEST_MESSAGE,
  FILTERING_OCALL_PROXY_RESPONSE_MESSAGE,
  FILTERING_OCALL_DROP_RESPONSE_MESSAGE,
  FILTERING_OCALL_FORWARD_RESPONSE_MESSAGE,
  FILTERING_OCALL_REPORT_MESSAGE,
  FILTERING_OCALL_DISCLOSE_RESPONSE_MESSAGE,
  FILTERING_OCALL_DISCLOSE_MESSAGE,
  FILTERING_OCALL_OSCORE_NG_MESSAGE,
  FILTERING_OCALL_OSCORE_NG_RESPONSE_MESSAGE
} filtering_ocall_message_type_t;

typedef struct filtering_ocall_message_t {
  filtering_ocall_message_type_t type;
  coap_bin_const_t token;
  uint8_t token_bytes[OSCORE_NG_MAX_TOKEN_LEN];
  void *request;
  size_t payload_length;
  uint8_t payload[];
} filtering_ocall_message_t;

#if !WITH_TRAP
typedef struct filtering_ocall_address_t {
  coap_bin_const_t address;
  uint8_t address_bytes[16];
} filtering_ocall_address_t;
#endif /* !WITH_TRAP */

#if !WITH_IRAP
typedef struct filtering_ocall_register_data_t {
  uint8_t ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE]; /* of the IoT device */
#if !WITH_TRAP
  uint8_t signature[ECC_CURVE_P_256_SIZE * 2];
  uint8_t cookie[BAKERY_COOKIE_SIZE];
  filtering_ocall_address_t address;
#endif /* !WITH_TRAP */
} filtering_ocall_register_data_t;
#endif /* !WITH_IRAP */

typedef struct filtering_ocall_oscore_ng_data_t {
  oscore_ng_id_t client_id;
  oscore_ng_id_t server_id;
  coap_pdu_type_t pdu_type;
  oscore_ng_option_data_t option_data;
  size_t ciphertext_len;
  uint8_t ciphertext[];
} filtering_ocall_oscore_ng_data_t;
