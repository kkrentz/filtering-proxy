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

#include <string.h>
#include <syscall.h>

#if !WITH_TRAP
#include "uECC.h"
#endif /* !WITH_TRAP */

#include "clock.h"
#include "coap.h"
#include "iot_message.h"
#include "log.h"
#include "ocall_dispatcher.h"
#include "registration.h"

#define DISCLOSE_PAYLOAD_LEN (COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN \
                              + CLIENTS_FHMQV_MIC_LEN)
#define MIN_DISCLOSE_KID_CONTEXT_LEN (8)

static const uint8_t iot_devices_public_key[uECC_BYTES * 2] = {
  0x01, 0xb8, 0x07, 0x0e, 0x9a, 0xd9, 0xb7, 0x56,
  0xa8, 0x30, 0xa2, 0xab, 0xc4, 0xbf, 0xb2, 0xb6,
  0x0c, 0x25, 0xa3, 0xdd, 0x41, 0x52, 0x85, 0x6d,
  0xdc, 0xab, 0x16, 0x08, 0x17, 0xf4, 0x46, 0xe6,
  0xb7, 0x36, 0xeb, 0xc7, 0x91, 0xcd, 0xa0, 0x18,
  0x30, 0x48, 0x3d, 0x7f, 0xc1, 0x46, 0xf5, 0x61,
  0xf1, 0x68, 0x4a, 0xd8, 0x73, 0x4f, 0xf1, 0xc2,
  0xe4, 0x9c, 0xcc, 0x32, 0x3c, 0x4e, 0x48, 0x55
};
static const oscore_ng_id_t middlebox_id = { { 0 }, 0 };
static const char disclose_uri[] = "dis";

void
attestation_service_init(void) {
#if LOG_LEVEL
  report_t report;
  memset(&report, 0, sizeof(report));
  attest_enclave(&report, NULL, 0);
  log_hashes(&report.report);
#endif /* LOG_LEVEL */
}

#if WITH_TRAP
static void
generate_report_and_session_keys(
    uint8_t report[REPORT_LEN],
    uint8_t session_keys[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN
                         + AES_128_KEY_LENGTH],
    uint8_t clients_fhmqv_mic[CLIENTS_FHMQV_MIC_LEN],
    const uint8_t iot_devices_public_key[uECC_BYTES * 2],
    const uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES]) {
  uint8_t attestation_data[(uECC_BYTES * 2)
                           + (1 + uECC_BYTES)
                           + (1 + uECC_BYTES) /* to be filled out by SM */];

  memcpy(attestation_data, iot_devices_public_key, uECC_BYTES * 2);
  memcpy(attestation_data + uECC_BYTES * 2,
         iot_devices_ephemeral_public_key_compressed,
         1 + uECC_BYTES);

  attest_enclave(report,
                 attestation_data,
                 uECC_BYTES * 2
                 + 1 + uECC_BYTES
                 + 1 + uECC_BYTES);
  memcpy(session_keys,
         report
         + REPORT_LEN
         - uECC_BYTES,
         uECC_BYTES);
  memcpy(clients_fhmqv_mic,
         report
         + REPORT_LEN
         - uECC_BYTES
         - SHA_256_DIGEST_LENGTH,
         CLIENTS_FHMQV_MIC_LEN);
  memset(report
         + REPORT_LEN
         - uECC_BYTES
         - SHA_256_DIGEST_LENGTH,
         0,
         SHA_256_DIGEST_LENGTH + uECC_BYTES);
}
#else /* WITH_TRAP */
static int
generate_session_keys(
    uint8_t session_keys[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN
                         + AES_128_KEY_LENGTH],
    const uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES],
    const uint8_t enclaves_ephemeral_private_key[uECC_BYTES]) {
  uint8_t iot_devices_ephemeral_public_key[uECC_BYTES * 2];
  uint8_t k[uECC_BYTES];

  uECC_decompress(iot_devices_ephemeral_public_key_compressed,
                  iot_devices_ephemeral_public_key,
                  uECC_CURVE());
  if (!uECC_shared_secret(iot_devices_ephemeral_public_key,
                          enclaves_ephemeral_private_key,
                          k,
                          uECC_CURVE())) {
    return 0;
  }
  sha_256_hkdf(iot_devices_ephemeral_public_key_compressed, 1 + uECC_BYTES,
               k, sizeof(k),
               NULL, 0,
               session_keys,
               COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN + AES_128_KEY_LENGTH);
  return 1;
}

static void
generate_report(
    uint8_t report[REPORT_LEN],
    const uint8_t iot_devices_ephemeral_public_key_compressed[1 + uECC_BYTES],
    const uint8_t enclaves_ephemeral_public_key[uECC_BYTES * 2]) {
  uint8_t attestation_data[1 + uECC_BYTES + 1 + uECC_BYTES];

  memcpy(attestation_data,
         iot_devices_ephemeral_public_key_compressed,
         1 + uECC_BYTES);
  uECC_compress(enclaves_ephemeral_public_key,
                attestation_data + 1 + uECC_BYTES,
                uECC_CURVE());
  attest_enclave(report,
                 attestation_data,
                 1 + uECC_BYTES
                 + 1 + uECC_BYTES);
}
#endif /* WITH_TRAP */

int
attestation_service_handle_register_message(
    const filtering_ocall_register_data_t *register_data,
    uint8_t compressed_report[COMPRESSED_ATTESTATION_REPORT_SIZE]) {
  uint8_t hash[SHA_256_DIGEST_LENGTH];
  SHA_256.hash(
      register_data->ephemeral_public_key,
      sizeof(register_data->ephemeral_public_key),
      hash);
  registration_t *registration = registration_find_ongoing(hash, sizeof(hash));
  if (!registration) {
    report_t report;
#if !WITH_TRAP
    uint8_t enclaves_ephemeral_public_key[uECC_BYTES * 2];
    uint8_t enclaves_ephemeral_private_key[uECC_BYTES];

    /* verify */
    if (!uECC_verify(iot_devices_public_key,
                     hash, SHA_256_DIGEST_LENGTH,
                     register_data->signature,
                     uECC_CURVE())) {
      LOG_MESSAGE("Register signature invalid\n");
      return 0;
    }
    if (!uECC_make_key(enclaves_ephemeral_public_key,
                       enclaves_ephemeral_private_key,
                       uECC_CURVE())) {
      LOG_MESSAGE("uECC_make_key failed\n");
      return 0;
    }
#endif /* !WITH_TRAP */

    /* create registration */
    registration = registration_create(hash);
    if (!registration) {
      LOG_MESSAGE("registration_create failed\n");
      return 0;
    }

    /* generate attestation report and K_OSCORE and K_OTP */
#if WITH_TRAP
    generate_report_and_session_keys(
        report.buffer,
        registration->tunnel.okm,
        registration->clients_fhmqv_mic,
        iot_devices_public_key,
        register_data->ephemeral_public_key);
#else /* WITH_TRAP */
    if (!generate_session_keys(
            registration->tunnel.okm,
            register_data->ephemeral_public_key,
            enclaves_ephemeral_private_key)) {
      LOG_MESSAGE("generate_session_keys failed\n");
      registration_delete(registration);
      return 0;
    }
    generate_report(report.buffer,
                    register_data->ephemeral_public_key,
                    enclaves_ephemeral_public_key);
#endif /* WITH_TRAP */

    /* init OSCORE-NG session */
    oscore_ng_init_keying_material(
        &registration->tunnel.keying_material,
        registration->tunnel.oscore_ng_key,
        sizeof(registration->tunnel.oscore_ng_key),
        NULL,
        0);
    report_compress(&report.report, registration->compressed_report);
  }
  memcpy(compressed_report,
         registration->compressed_report,
         sizeof(registration->compressed_report));

  return 1;
}

int
attestation_service_handle_disclose_message(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token) {
  if (data->option_data.kid_context.len < MIN_DISCLOSE_KID_CONTEXT_LEN) {
    LOG_MESSAGE("kid context is too short\n");
    return 0;
  }

  /* find registration */
  registration_t *registration = registration_find_ongoing(
                                     data->option_data.kid_context.u8,
                                     data->option_data.kid_context.len);
  if (registration) {
    oscore_ng_init_context(&registration->tunnel.context,
                           &data->option_data.kid,
                           &middlebox_id,
                           &registration->tunnel.keying_material);
    oscore_ng_set_id_context(&registration->tunnel.context,
                             &data->option_data.kid_context,
                             false);
  } else {
    /* might be a retransmission */
    registration = registration_find(&data->option_data.kid);
    if (!registration) {
      LOG_MESSAGE("Disclose from unregistered sender\n");
      return 0;
    }
  }

  /* check authenticity and freshness */
  switch (oscore_ng_unsecure(&registration->tunnel.context,
                             data->pdu_type,
                             token,
                             &data->option_data,
                             data->ciphertext, data->ciphertext_len,
                             true)) {
  case OSCORE_NG_UNSECURE_RESULT_ERROR:
    LOG_MESSAGE("Inauthentic disclose message\n");
    return 0;
  case OSCORE_NG_UNSECURE_RESULT_OK:
    /* parse */
    coap_message_t message;
    if (!coap_parse(
            &message,
            data->ciphertext,
            data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)) {
      LOG_MESSAGE("coap_parse failed\n");
      return 0;
    }
    if ((message.uri_path_len != (sizeof(disclose_uri) - 1))
        || memcmp(message.uri_path, disclose_uri, sizeof(disclose_uri) - 1)) {
      LOG_MESSAGE("Unexpected URI path\n");
      return 0;
    }
    if (message.payload_len != DISCLOSE_PAYLOAD_LEN) {
      LOG_MESSAGE("Disclose has unexpected payload length\n");
      return 0;
    }
    if (registration->is_complete) {
      LOG_MESSAGE("Duplicate detection failure\n");
      data->ciphertext[0] = COAP_RESPONSE_CODE(204);
      break;
    }

#if WITH_TRAP
    if (memcmp(message.payload,
               registration->clients_fhmqv_mic,
               CLIENTS_FHMQV_MIC_LEN)) {
      LOG_MESSAGE("Client's FHMQV MIC is invalid\n");
      return 0;
    }
#endif /* WITH_TRAP */

    /* turn into a completed registration */
    data->ciphertext[0] = COAP_RESPONSE_CODE(201);
    bool has_existed;
    if (!registration_complete(
            registration,
            message.payload
            + CLIENTS_FHMQV_MIC_LEN,
            NULL, 0,
            &has_existed)) {
      LOG_MESSAGE("registration_complete failed\n");
      return 0;
    }
    data->ciphertext[0] = has_existed
                          ? COAP_RESPONSE_CODE(204)
                          : COAP_RESPONSE_CODE(201);
    break;
  case OSCORE_NG_UNSECURE_RESULT_DUPLICATE:
    LOG_MESSAGE("Duplicate disclose message\n");
    data->ciphertext[0] = COAP_RESPONSE_CODE(201);
    break;
  case OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1:
  default:
    LOG_MESSAGE("unexpected return value\n");
    return 0;
  }

  /* create response */
  data->pdu_type = (data->pdu_type == COAP_MESSAGE_CON
                    ? COAP_MESSAGE_ACK
                    : COAP_MESSAGE_NON);
  data->ciphertext_len = 1;
  if (!oscore_ng_secure(
          &registration->tunnel.context,
          data->pdu_type,
          token,
          &data->option_data,
          data->option_data.e2e_message_id,
          data->ciphertext, data->ciphertext_len,
          false)) {
    LOG_MESSAGE("oscore_ng_secure failed\n");
    return 0;
  }
  data->ciphertext_len += COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;

  if (!iot_message_store_control_response(registration,
                                          data->option_data.e2e_message_id)) {
    LOG_MESSAGE("iot_message_store_control_response failed\n");
    return 0;
  }
  return 1;
}
