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
                              + FHMQV_MIC_LEN)

static const uint8_t iot_devices_public_key[PUBLIC_KEY_SIZE] = {
  0xf7, 0x40, 0x9d, 0x80, 0x9d, 0x77, 0xc2, 0x29,
  0x70, 0xa1, 0x9f, 0x4f, 0xa9, 0x13, 0x5f, 0xfd,
  0x25, 0xc8, 0x2b, 0x4d, 0x88, 0xe0, 0x63, 0xbc,
  0x33, 0x9e, 0xaf, 0x46, 0x81, 0x3b, 0x87, 0xe1,
  0x29, 0xa6, 0x06, 0x9a, 0x5d, 0x86, 0x13, 0x8f,
  0x9f, 0xbb, 0x9f, 0x60, 0xf0, 0x35, 0x45, 0x87,
  0xbb, 0x34, 0x1d, 0x45, 0xf0, 0x31, 0x8f, 0xef,
  0x73, 0x6b, 0x8b, 0xd5, 0x7c, 0x7d, 0x11, 0xc2
};
static const char disclose_uri[] = "dis";
static const oscore_ng_id_t middlebox_id = { { 0 }, 0 };

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
    report_t *report,
    uint8_t session_keys[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN
                         + AES_128_KEY_LENGTH],
    uint8_t clients_fhmqv_mic[FHMQV_MIC_LEN],
    const uint8_t iot_devices_public_key[PUBLIC_KEY_SIZE],
    const uint8_t iot_devices_ephemeral_public_key_compressed[PUBLIC_KEY_COMPRESSED_SIZE]) {
  uint8_t attestation_data[PUBLIC_KEY_SIZE + PUBLIC_KEY_COMPRESSED_SIZE];

  memcpy(attestation_data, iot_devices_public_key, PUBLIC_KEY_SIZE);
  memcpy(attestation_data + PUBLIC_KEY_SIZE,
         iot_devices_ephemeral_public_key_compressed,
         PUBLIC_KEY_COMPRESSED_SIZE);

  attest_enclave(report->buffer, attestation_data, sizeof(attestation_data));
  memcpy(session_keys,
         report->report.enclave.fhmqv_key,
         sizeof(report->report.enclave.fhmqv_key));
  memcpy(clients_fhmqv_mic,
         report->report.enclave.clients_fhmqv_mic,
         FHMQV_MIC_LEN);
}
#else /* WITH_TRAP */
static int
generate_session_keys(
    uint8_t session_keys[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN
                         + AES_128_KEY_LENGTH],
    const uint8_t iot_devices_ephemeral_public_key_compressed[PUBLIC_KEY_COMPRESSED_SIZE],
    const uint8_t enclaves_ephemeral_private_key[ECC_CURVE_P_256_SIZE]) {
  uint8_t iot_devices_ephemeral_public_key[PUBLIC_KEY_SIZE];
  uint8_t k[ECC_CURVE_P_256_SIZE];

  uECC_decompress(iot_devices_ephemeral_public_key_compressed,
                  iot_devices_ephemeral_public_key,
                  uECC_CURVE());
  if (!uECC_shared_secret(iot_devices_ephemeral_public_key,
                          enclaves_ephemeral_private_key,
                          k,
                          uECC_CURVE())) {
    return 0;
  }
  return sha_256_hkdf(iot_devices_ephemeral_public_key_compressed,
                      PUBLIC_KEY_COMPRESSED_SIZE,
                      k,
                      sizeof(k),
                      NULL,
                      0,
                      session_keys,
                      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN + AES_128_KEY_LENGTH);
}

static void
generate_report(
    report_t *report,
    const uint8_t iot_devices_ephemeral_public_key_compressed[PUBLIC_KEY_COMPRESSED_SIZE],
    const uint8_t enclaves_ephemeral_public_key[PUBLIC_KEY_SIZE]) {
  uint8_t attestation_data[2 * PUBLIC_KEY_COMPRESSED_SIZE];

  memcpy(attestation_data,
         iot_devices_ephemeral_public_key_compressed,
         PUBLIC_KEY_COMPRESSED_SIZE);
  uECC_compress(enclaves_ephemeral_public_key,
                attestation_data + PUBLIC_KEY_COMPRESSED_SIZE,
                uECC_CURVE());
  attest_enclave(report->buffer, attestation_data, sizeof(attestation_data));
}
#endif /* WITH_TRAP */

size_t
attestation_service_handle_register_message(
    const filtering_ocall_register_data_t *register_data,
    uint8_t attestation_report[MAX_ATTESTATION_REPORT_SIZE]) {
#if !WITH_TRAP
  /* check cookie */
  if (!bakery_check_cookie(register_data->cookie,
                           &register_data->address.address)) {
    LOG_MESSAGE("Invalid cookie\n");
    return 0;
  }
#endif /* !WITH_TRAP */

  registration_t *registration =
      registration_find_ongoing(
          register_data->ephemeral_public_key_compressed + 1,
          ECC_CURVE_P_256_SIZE);
  if (!registration) {
    report_t report;
#if !WITH_TRAP
    uint8_t enclaves_ephemeral_public_key[PUBLIC_KEY_SIZE];
    uint8_t enclaves_ephemeral_private_key[ECC_CURVE_P_256_SIZE];
    sha_256_context_t ctx;
    uint8_t hash[SHA_256_DIGEST_LENGTH];

    SHA_256.init(&ctx);
    SHA_256.update(&ctx,
                   register_data->ephemeral_public_key_compressed,
                   sizeof(register_data->ephemeral_public_key_compressed));
    SHA_256.update(&ctx,
                   register_data->cookie,
                   sizeof(register_data->cookie));
    if (!SHA_256.finalize(&ctx, hash)) {
      LOG_MESSAGE("SHA_256.finalize failed\n");
      return 0;
    }

    /* verify */
    if (!uECC_verify(iot_devices_public_key,
                     hash, sizeof(hash),
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
    registration = registration_create(
                       register_data->ephemeral_public_key_compressed + 1);
    if (!registration) {
      LOG_MESSAGE("registration_create failed\n");
      return 0;
    }

    /* generate attestation report and K_OSCORE and K_OTP */
#if WITH_TRAP
    generate_report_and_session_keys(
        &report,
        registration->tunnel.okm,
        registration->clients_fhmqv_mic,
        iot_devices_public_key,
        register_data->ephemeral_public_key_compressed);
#else /* WITH_TRAP */
    if (!generate_session_keys(
            registration->tunnel.okm,
            register_data->ephemeral_public_key_compressed,
            enclaves_ephemeral_private_key)) {
      LOG_MESSAGE("generate_session_keys failed\n");
      registration_delete(registration);
      return 0;
    }
    generate_report(&report,
                    register_data->ephemeral_public_key_compressed,
                    enclaves_ephemeral_public_key);
#endif /* WITH_TRAP */

    /* init OSCORE-NG session */
    oscore_ng_init_keying_material(
        &registration->tunnel.keying_material,
        registration->tunnel.oscore_ng_key,
        sizeof(registration->tunnel.oscore_ng_key),
        NULL,
        0);
    registration->attestation_report_size =
        report_serialize(&report.report, registration->attestation_report);
  }
  memcpy(attestation_report,
         registration->attestation_report,
         registration->attestation_report_size);

  return registration->attestation_report_size;
}

int
attestation_service_handle_disclose_message(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token) {
  /* find registration */
  registration_t *registration = registration_find_ongoing(
                                     data->option_data.kid_context.u8,
                                     data->option_data.kid_context.len);
  if (registration) {
    if (!oscore_ng_init_context(&registration->tunnel.context,
                                &data->option_data.kid,
                                &middlebox_id,
                                &registration->tunnel.keying_material)) {
      LOG_MESSAGE("oscore_ng_init_context failed\n");
      return 0;
    }
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
                             true,
                             0)) {
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
               FHMQV_MIC_LEN)) {
      LOG_MESSAGE("Client's FHMQV MIC is invalid\n");
      return 0;
    }
#endif /* WITH_TRAP */

    /* turn into a completed registration */
    data->ciphertext[0] = COAP_RESPONSE_CODE(201);
    bool has_existed;
    if (!registration_complete(
            registration,
            message.payload + FHMQV_MIC_LEN,
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
