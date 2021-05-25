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

#ifndef FILTERING_OCALL_H_
#define FILTERING_OCALL_H_

#include <stddef.h>
#include <stdint.h>
#include "uECC.h"

#include "oscore.h"

#define FILTERING_OCALL_REPORT_LEN (2048) /* hardcoded in Keystone SDK */
#define FILTERING_OCALL_REPORT_MESSAGE_LEN ( \
    sizeof(filtering_ocall_message_t) + FILTERING_OCALL_REPORT_LEN)
#define FILTERING_OCALL_DISCLOSE_OK_LEN (sizeof(oscore_data_t) \
    + 1 \
    + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)
#define CSL_FRAMER_POTR_OTP_LEN 2
#define FILTERING_OCALL_MAX_OSCORE_ANSWER_LEN (sizeof(oscore_data_t) \
    + 1 /* code */ \
    + 1 /* payload marker */ \
    + CSL_FRAMER_POTR_OTP_LEN \
    + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)

enum filtering_ocall_id {
  FILTERING_OCALL_ACCEPT_OCALL,
  FILTERING_OCALL_PRINT_BUFFER,
  FILTERING_OCALL_PRINT_VALUE,
  FILTERING_OCALL_PRINT_BYTES,
  FILTERING_OCALL_GOT_REPORT,
  FILTERING_OCALL_DISCLOSE_ANSWER,
  FILTERING_OCALL_OSCORE_ANSWER,
  FILTERING_OCALL_PROXY_REQUEST_ANSWER,
  FILTERING_OCALL_PROXY_RESPONSE_ANSWER,
  FILTERING_OCALL_COUNT
};

enum filtering_ocall_message_type {
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
  FILTERING_OCALL_OSCORE_MESSAGE,
  FILTERING_OCALL_OSCORE_RESPONSE_MESSAGE
};

typedef struct {
  enum filtering_ocall_message_type type;
  void *ptr;
  size_t payload_length;
  uint8_t payload[];
} filtering_ocall_message_t;

typedef struct {
  uint8_t iot_device_id[OSCORE_MAX_ID_LEN];
  uint8_t iot_device_id_len;
  uint8_t iot_client_id[OSCORE_MAX_ID_LEN];
  uint8_t iot_client_id_len;
  oscore_option_data_t option_data;
  size_t ciphertext_len;
  uint8_t ciphertext[];
} oscore_data_t;

typedef struct {
  uint8_t iot_device_id[OSCORE_MAX_ID_LEN];
  uint8_t iot_device_id_len;
  uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES];
  uint8_t signature[uECC_BYTES * 2];
} register_data_t;

#endif /* FILTERING_OCALL_H_ */
