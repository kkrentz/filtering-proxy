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

#include "oscore_ng_filter.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "coap.h"
#include "coap3/coap_libcoap_build.h"
#include "log.h"
#include "iot_client.h"
#include "iot_message.h"
#include "registration.h"

/* these definitions are for parsing /otp requests */
#define RELATES_TO_REQUEST_FLAG (1 << 7)
#define WAKE_UP_COUNTER_LEN (4)
#define RADIO_FRAME_LENGTH_POS (0)
#define WAKE_UP_COUNTER_POS (RADIO_FRAME_LENGTH_POS + 1)
#define RECEIVER_ADDRESS_POS (WAKE_UP_COUNTER_POS + WAKE_UP_COUNTER_LEN)
#define MID_POS(mac_address_len) (RECEIVER_ADDRESS_POS + (mac_address_len))
#define OTP_PAYLOAD_LEN(mac_address_len) (MID_POS(mac_address_len) \
                                          + COAP_MESSAGE_ID_LEN)

#define MAX_FILTERING_OTPS (5)

static const char update_uri[] = "upd";
static const char otp_uri[] = "otp";

int
oscore_ng_filter_handle_oscore_ng_message(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token) {
  /* find registration */
  registration_t *registration = registration_find(&data->option_data.kid);
  if (!registration) {
    LOG_MESSAGE("Unregistered sender\n");
    return 0;
  }

  /* check authenticity and freshness */
  if (!oscore_ng_unsecure(&registration->tunnel.context,
                          data->pdu_type,
                          token,
                          &data->option_data,
                          data->ciphertext, data->ciphertext_len,
                          true,
                          0)) {
    LOG_MESSAGE("Inauthentic OSCORE-NG message\n");
    return 0;
  }

  /* parse */
  coap_message_t message;
  if (!coap_parse(
          &message,
          data->ciphertext,
          data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN)) {
    LOG_MESSAGE("coap_parse failed\n");
    return 0;
  }
  bool is_otp_request = false;
  if ((message.uri_path_len == (sizeof(otp_uri) - 1))
      && !memcmp(message.uri_path, otp_uri, sizeof(otp_uri) - 1)) {
    is_otp_request = true;
  } else if ((message.uri_path_len == (sizeof(update_uri) - 1))
             && !memcmp(message.uri_path, update_uri, sizeof(update_uri) - 1)) {
    LOG_MESSAGE("Received update\n");
  } else {
    LOG_MESSAGE("Unexpected OSCORE-NG message\n");
    return 0;
  }

  /* create appropriate response */
  data->ciphertext_len = 0;
  data->ciphertext[data->ciphertext_len++] = COAP_RESPONSE_CODE(205);
  if (is_otp_request) {
    registration_t *receivers_registration;

    /* validate length */
    if (message.payload_len != (size_t)OTP_PAYLOAD_LEN(data->client_id.len)) {
      LOG_MESSAGE("OTP message has unexpected length\n");
      return 0;
    }

    /* look up receiver's registration */
    {
      oscore_ng_id_t receiver_id;

      memcpy(receiver_id.u8,
             message.payload + RECEIVER_ADDRESS_POS,
             data->client_id.len);
      receiver_id.len = data->client_id.len;
      receivers_registration = registration_find(&receiver_id);
      if (!receivers_registration) {
        LOG_MESSAGE("Unregistered receiver\n");
        return 0;
      }
    }

    /* check if we sent this message */
    {
      iot_message_t *iot_message;

      uint16_t mid = message.payload[MID_POS(data->client_id.len)]
                     | (message.payload[MID_POS(data->client_id.len) + 1] << 8);
      if (message.payload[0] & RELATES_TO_REQUEST_FLAG) {
        iot_message = iot_message_find(receivers_registration,
                                       IOT_MESSAGE_PROXIED_REQUEST,
                                       mid,
                                       IOT_MESSAGE_ID_INDEX_NEW);
      } else {
        iot_message = iot_message_find(receivers_registration,
                                       IOT_MESSAGE_CONTROL_RESPONSE,
                                       mid,
                                       IOT_MESSAGE_ID_INDEX_ECHOED);
      }
      message.payload[0] &= ~RELATES_TO_REQUEST_FLAG;

      if (!iot_message) {
        LOG_MESSAGE("Did not find respective message\n");
        return 0;
      }
      if (iot_message->filtering_otp_count++ >= MAX_FILTERING_OTPS) {
        LOG_MESSAGE("Maximum number of Filtering OTPs reached\n");
        return 0;
      }
    }

    /* generate Filtering OTP */
    {
      uint8_t nonce[CCM_STAR_NONCE_LENGTH];

      memset(nonce, 0, sizeof(nonce));
      memcpy(nonce, data->client_id.u8, data->client_id.len);
      nonce[data->client_id.len] = 0 /* alpha and burst index */;
      memcpy(nonce + data->client_id.len + 1,
             message.payload + WAKE_UP_COUNTER_POS,
             WAKE_UP_COUNTER_LEN);

      data->ciphertext[data->ciphertext_len++] = COAP_PAYLOAD_START;
      CCM_STAR.set_key(receivers_registration->tunnel.otp_key);
      CCM_STAR.aead(nonce,
                    NULL, 0,
                    message.payload + RADIO_FRAME_LENGTH_POS, 1,
                    data->ciphertext + 2, CSL_FRAMER_POTR_OTP_LEN, 1);
      data->ciphertext_len += CSL_FRAMER_POTR_OTP_LEN;
    }
  }

  /* create response */
  data->pdu_type = (data->pdu_type == COAP_MESSAGE_CON
                    ? COAP_MESSAGE_ACK
                    : COAP_MESSAGE_NON);
  data->ciphertext_len += COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  if (!oscore_ng_secure(
          &registration->tunnel.context,
          data->pdu_type,
          token,
          &data->option_data,
          data->option_data.e2e_message_id,
          data->ciphertext,
          data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
          false)) {
    LOG_MESSAGE("oscore_ng_secure failed\n");
    return 0;
  }

  if (is_otp_request) {
    return 1;
  }

  if (!iot_message_store_control_response(registration,
                                          data->option_data.e2e_message_id)) {
    LOG_MESSAGE("iot_message_store_control_response failed\n");
    return 0;
  }
  return 1;
}

oscore_ng_filter_verdict_t
oscore_ng_filter_check_proxy_request(filtering_ocall_oscore_ng_data_t *data,
                                     const coap_bin_const_t *token) {
  oscore_ng_filter_verdict_t verdict = OSCORE_NG_FILTER_VERDICT_DROP;
  bool created_session = false;

  /* find registration and session */
  registration_t *registration = registration_find(&data->server_id);
  if (!registration) {
    LOG_MESSAGE("not registered\n");
    goto error;
  }
  iot_client_session_t *iot_client_session = iot_client_find_session(
                                                 registration,
                                                 &data->option_data.kid);
  if (!iot_client_session) {
    iot_client_session = iot_client_create_session(registration,
                                                   &data->option_data.kid);
    if (!iot_client_session) {
      LOG_MESSAGE("iot_client_create_session failed\n");
      goto error;
    }
    created_session = true;
  } else {
    /* check rate */
    if (leaky_bucket_is_full(&iot_client_session->leaky_bucket)) {
      LOG_MESSAGE("rate limitation\n");
      goto error;
    }
  }

  /* check authenticity */
  switch (oscore_ng_unsecure(&iot_client_session->context,
                             data->pdu_type,
                             token,
                             &data->option_data,
                             data->ciphertext, data->ciphertext_len,
                             true,
                             0)) {
  case OSCORE_NG_UNSECURE_RESULT_ERROR:
    LOG_MESSAGE("Inauthentic proxy request\n");
    goto error;
  case OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1:
    /* B2 protocol */
    /* reply with UNAUTHORIZED */
    *data->ciphertext = COAP_RESPONSE_CODE(401 /* UNAUTHORIZED */);
    data->ciphertext_len = 1 + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
    data->pdu_type = COAP_MESSAGE_RST;
    if (!oscore_ng_secure(
            &iot_client_session->context,
            data->pdu_type,
            token,
            &data->option_data,
            data->option_data.e2e_message_id,
            data->ciphertext,
            data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
            false)) {
      LOG_MESSAGE("oscore_ng_secure failed\n");
      goto error;
    }
    verdict = OSCORE_NG_FILTER_VERDICT_RETURN;
    goto error;
  default:
    break;
  }

  {
    /* create proxied request */
    iot_message_t *iot_message = iot_message_store_proxied_request(registration,
                                 data->pdu_type,
                                 data->option_data.e2e_message_id);
    if (!iot_message) {
      LOG_MESSAGE("iot_message_store_proxied_request failed\n");
      goto error;
    }

    /* TODO we could use an empty or shorter token for forwarding and restore
     * the original one on the reverse path */

    /* resecure */
    /* TODO For the time being, we forward everything as a NON to prevent
     * libcoap from retransmitting. Once we avoid this, we no longer have to
     * store the pdu_type of proxied requests. */
    data->pdu_type = COAP_MESSAGE_NON;
    if (!oscore_ng_secure(&registration->tunnel.context,
                          data->pdu_type,
                          token,
                          &data->option_data,
                          iot_message->message_ids[IOT_MESSAGE_ID_INDEX_NEW],
                          data->ciphertext,
                          data->ciphertext_len
                          - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
                          true)) {
      LOG_MESSAGE("oscore_ng_secure failed\n");
      goto error;
    }
  }

  leaky_bucket_pour(&iot_client_session->leaky_bucket);
  LOG_MESSAGE("Resecured request\n");
  return OSCORE_NG_FILTER_VERDICT_FORWARD;
error:
  if (created_session) {
    iot_client_delete_session(registration, iot_client_session);
  }
  return verdict;
}

int
oscore_ng_filter_check_proxy_response(filtering_ocall_oscore_ng_data_t *data,
                                      const coap_bin_const_t *token) {
  /* find registration, session, and IoT message */
  registration_t *registration = registration_find(&data->server_id);
  if (!registration) {
    LOG_MESSAGE("Did not find registration\n");
    return 0;
  }
  iot_client_session_t *iot_client_session = iot_client_find_session(registration,
                                             &data->client_id);
  if (!iot_client_session) {
    LOG_MESSAGE("Did not find IoT client session\n");
    return 0;
  }
  iot_message_t *iot_message = iot_message_find(
                                   registration,
                                   IOT_MESSAGE_PROXIED_REQUEST,
                                   data->option_data.e2e_message_id,
                                   IOT_MESSAGE_ID_INDEX_NEW);
  if (!iot_message) {
    LOG_MESSAGE("Did not find IoT message\n");
    return 0;
  }
  /* check */
  if (!oscore_ng_unsecure(&registration->tunnel.context,
                          data->pdu_type,
                          token,
                          &data->option_data,
                          data->ciphertext, data->ciphertext_len,
                          false,
                          0)) {
    LOG_MESSAGE("Inauthentic proxy response\n");
    return 0;
  }
  /* resecure */
  data->pdu_type = (iot_message->pdu_type == COAP_MESSAGE_CON
                    ? COAP_MESSAGE_ACK
                    : COAP_MESSAGE_NON);
  if (!oscore_ng_secure(
          &iot_client_session->context,
          data->pdu_type,
          token,
          &data->option_data,
          iot_message->message_ids[IOT_MESSAGE_ID_INDEX_ORIGINAL],
          data->ciphertext,
          data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
          false)) {
    LOG_MESSAGE("oscore_ng_secure failed\n");
    return 0;
  }
  LOG_MESSAGE("Resecured response\n");
  iot_message_remove(registration, iot_message);
  return 1;
}
