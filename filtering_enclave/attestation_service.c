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

#include "attestation_service.h"

#include "app/string.h"
#include "app/syscall.h"
#include "sha-256.h"
#include "uECC.h"

#include "crypto.h"
#include "filtering_ocall_client.h"
#include "log.h"
#include "registration.h"

static const uint8_t iot_devices_public_key[uECC_BYTES * 2] = {
    0x01 , 0xb8 , 0x07 , 0x0e , 0x9a , 0xd9 , 0xb7 , 0x56 ,
    0xa8 , 0x30 , 0xa2 , 0xab , 0xc4 , 0xbf , 0xb2 , 0xb6 ,
    0x0c , 0x25 , 0xa3 , 0xdd , 0x41 , 0x52 , 0x85 , 0x6d ,
    0xdc , 0xab , 0x16 , 0x08 , 0x17 , 0xf4 , 0x46 , 0xe6 ,
    0xb7 , 0x36 , 0xeb , 0xc7 , 0x91 , 0xcd , 0xa0 , 0x18 ,
    0x30 , 0x48 , 0x3d , 0x7f , 0xc1 , 0x46 , 0xf5 , 0x61 ,
    0xf1 , 0x68 , 0x4a , 0xd8 , 0x73 , 0x4f , 0xf1 , 0xc2 ,
    0xe4 , 0x9c , 0xcc , 0x32 , 0x3c , 0x4e , 0x48 , 0x55
};
static const unsigned char middlebox_id_context[] = {};
static const char disclose_uri[] = "dis";

void
attestation_service_init(void)
{
#if LOG_LEVEL
  /* print the hashes at start up */
  uint8_t buffer[FILTERING_OCALL_REPORT_MESSAGE_LEN];
  filtering_ocall_message_t *response;

  response = (filtering_ocall_message_t *)buffer;
  response->type = FILTERING_OCALL_REPORT_MESSAGE;
  response->ptr = NULL;
  response->payload_length = FILTERING_OCALL_REPORT_LEN;
  attest_enclave(response->payload, NULL, 0);
  filtering_ocall_client_ocall(FILTERING_OCALL_GOT_REPORT, response);
#endif /* LOG_LEVEL */
}

int
attestation_service_handle_register_message(const register_data_t *register_data,
    uint8_t report[FILTERING_OCALL_REPORT_LEN])
{
  uint8_t hash[SHA_256_DIGEST_LENGTH];
  uint8_t enclaves_ephemeral_public_key[uECC_BYTES * 2];
  uint8_t enclaves_ephemeral_private_key[uECC_BYTES];
  registration_t *registration;

  /* verify */
  SHA_256.hash(register_data->iot_devices_ephemeral_public_key_compressed,
      sizeof(register_data->iot_devices_ephemeral_public_key_compressed),
      hash);
  if (!uECC_verify(iot_devices_public_key,
      hash, SHA_256_DIGEST_LENGTH,
      register_data->signature,
      uECC_CURVE())) {
    LOG_MESSAGE("Register signature invalid\n");
    goto error_1;
  }

  /* create registration */
  if (!crypto_generate_key_pair(enclaves_ephemeral_public_key,
      enclaves_ephemeral_private_key)) {
    LOG_MESSAGE("crypto_generate_key_pair failed\n");
    goto error_1;
  }
  registration = registration_create(register_data->iot_device_id,
      register_data->iot_device_id_len);
  if (!registration) {
    LOG_MESSAGE("registration_create failed\n");
    goto error_1;
  }
  if (!crypto_generate_session_keys(registration->forwarding.okm,
      register_data->iot_devices_ephemeral_public_key_compressed,
      enclaves_ephemeral_private_key)) {
    LOG_MESSAGE("crypto_generate_session_keys failed\n");
    goto error_2;
  }
  oscore_init_keying_material(&registration->forwarding.keying_material,
      registration->forwarding.oscore,
      NULL, 0,
      NULL, 0);
  if (!oscore_init_context(&registration->forwarding.context,
      registration->iot_device_id, registration->iot_device_id_len,
      middlebox_id_context, sizeof(middlebox_id_context),
      &registration->forwarding.keying_material)) {
    LOG_MESSAGE("oscore_init_context failed\n");
    goto error_2;
  }

  /* send positive response */
  crypto_generate_report(report,
      register_data->iot_devices_ephemeral_public_key_compressed,
      enclaves_ephemeral_public_key);
  return 1;
error_2:
  registration_delete(registration);
error_1:
  return 0;
}

int
attestation_service_handle_disclose_message(oscore_data_t *data)
{
  registration_t *registration;
  uint64_t sequence_number;

  /* find registration */
  registration = registration_find(
      data->iot_device_id, data->iot_device_id_len, false);
  if (!registration) {
    /* might be a retransmission */
    registration = registration_find(
        data->iot_device_id, data->iot_device_id_len, true);
    if (!registration) {
      LOG_MESSAGE("Disclose from unregistered sender\n");
      return 0;
    }
  }

  /* check authenticity and freshness */
  sequence_number = oscore_option_data_get_sequence_number(&data->option_data);
  if (!oscore_is_authentic(&registration->forwarding.context,
      sequence_number, false,
      data->ciphertext, data->ciphertext_len)) {
    LOG_MESSAGE("Inauthentic disclose message\n");
    return 0;
  }
  if (!oscore_is_fresh(&registration->forwarding.context.anti_replay,
      sequence_number)) {
    LOG_MESSAGE("Replayed disclose message\n");
    return 0;
  }
  if (data->ciphertext_len < (1 /* original code */
      + (sizeof(disclose_uri) - 1)
      + 1 /* Payload Marker */
      + AES_128_KEY_LENGTH /* disclosed master secret */
      + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN /* tag */)) {
    LOG_MESSAGE("Unexpected disclose length\n");
    return 0;
  }

  /* check path */
  if (memcmp(data->ciphertext
      + data->ciphertext_len
      - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN
      - AES_128_KEY_LENGTH
      - 1 /* Payload Marker */
      - (sizeof(disclose_uri) - 1), disclose_uri, sizeof(disclose_uri) - 1)) {
    LOG_MESSAGE("Unexpected URI path\n");
    return 0;
  }

  if (!registration->completed) {
    /* turn into a completed registration */
    registration_complete(registration,
        data->ciphertext
            + data->ciphertext_len
            - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN /* tag */
            - AES_128_KEY_LENGTH,
        NULL, 0,
        NULL, 0);
  }

  /* create authenticated ACK */
  data->ciphertext[0] = 0 /* ACK code */;
  data->ciphertext_len = 1 + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  if (!oscore_secure(&registration->forwarding.context,
      &data->option_data,
      data->ciphertext,
      data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
      oscore_option_data_get_sequence_number(&data->option_data),
      false)) {
    LOG_MESSAGE("oscore_secure failed\n");
    return 0;
  }
  memcpy(registration->mic,
      data->ciphertext + data->ciphertext_len - sizeof(registration->mic),
      sizeof(registration->mic));
  return 1;
}
