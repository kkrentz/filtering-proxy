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

#include "filtering_ocall_client.h"

#include "app/eapp_utils.h"
#include "app/string.h"
#include "app/syscall.h"
#include "app/malloc.h"
#include "ccm-star.h"

#include "attestation_service.h"
#include "log.h"
#include "oscore_filter.h"
#include "proxied_request.h"
#include "registration.h"

#define COAP_RESPONSE_CODE(N) (((N)/100 << 5) | (N)%100)
#define COAP_PAYLOAD_START (0xFF)

static int validate_oscore_data_length(filtering_ocall_message_t *message);
static int handle_oscore_message(oscore_data_t *data);

static const char update_uri[] = "upd";
static const char otp_uri[] = "otp";

#if LOG_LEVEL
void
filtering_ocall_client_print_buffer(char* data)
{
  ocall(FILTERING_OCALL_PRINT_BUFFER, data, strlen(data)+1, 0, 0);
}

void
filtering_ocall_client_print_value(unsigned long val)
{
  ocall(FILTERING_OCALL_PRINT_VALUE, &val, sizeof(unsigned long), 0, 0);
}

void
filtering_ocall_client_print_bytes(uint8_t *bytes, size_t bytes_len)
{
  ocall(FILTERING_OCALL_PRINT_BYTES, bytes, bytes_len, 0, 0);
}
#endif /* LOG_LEVEL */

void
filtering_ocall_client_ocall(enum filtering_ocall_id ocall_id,
    filtering_ocall_message_t* message)
{
  ocall(ocall_id,
      message,
      sizeof(filtering_ocall_message_t) + message->payload_length,
      0,
      0);
}

void
filtering_ocall_client_accept_ocalls(void)
{
  int shall_exit;
  struct edge_data edge_data;
  filtering_ocall_message_t *message;
  oscore_data_t *oscore_data;

  shall_exit = 0;
  while (!shall_exit) {
    /* retrieve next message */
    ocall(FILTERING_OCALL_ACCEPT_OCALL,
        NULL,
        0,
        &edge_data,
        sizeof(struct edge_data));
    message = malloc(edge_data.size < FILTERING_OCALL_REPORT_MESSAGE_LEN
        ? FILTERING_OCALL_REPORT_MESSAGE_LEN
        : edge_data.size);
    if (!message) {
      LOG_MESSAGE("malloc failed\n");
      continue;
    }
    copy_from_shared(message, edge_data.offset, edge_data.size);

    /* dispatch */
    switch (message->type) {
    case FILTERING_OCALL_REGISTER_MESSAGE:
      if (message->payload_length != sizeof(register_data_t)) {
        LOG_MESSAGE("Register message is invalid\n");
      } else {
        LOG_MESSAGE("Received register message\n");
        if (attestation_service_handle_register_message(
            (register_data_t *)message->payload,
            (uint8_t *)message->payload)) {
          message->payload_length = FILTERING_OCALL_REPORT_LEN;
        } else {
          message->payload_length = 0;
        }
        message->type = FILTERING_OCALL_REPORT_MESSAGE;
        filtering_ocall_client_ocall(FILTERING_OCALL_GOT_REPORT, message);
      }
      break;
    case FILTERING_OCALL_DISCLOSE_MESSAGE:
      if (!validate_oscore_data_length(message)) {
        LOG_MESSAGE("Disclose message is invalid\n");
      } else {
        LOG_MESSAGE("Received disclose message\n");
        oscore_data = (oscore_data_t *)message->payload;
        if (attestation_service_handle_disclose_message(oscore_data)) {
          message->payload_length = sizeof(oscore_data_t)
              + oscore_data->ciphertext_len;
        } else {
          message->payload_length = 0;
        }
        message->type = FILTERING_OCALL_DISCLOSE_RESPONSE_MESSAGE;
        filtering_ocall_client_ocall(FILTERING_OCALL_DISCLOSE_ANSWER, message);
      }
      break;
    case FILTERING_OCALL_PROXY_REQUEST_MESSAGE:
      if (!validate_oscore_data_length(message)) {
        LOG_MESSAGE("Proxy request is invalid\n");
      } else {
        LOG_MESSAGE("Received proxy request\n");
        if (!oscore_filter_check_proxy_request(
            (oscore_data_t *)message->payload,
            message->ptr)) {
          message->type = FILTERING_OCALL_DROP_REQUEST_MESSAGE;
          message->payload_length = 0;
        } else {
          message->type = FILTERING_OCALL_FORWARD_REQUEST_MESSAGE;
        }
        filtering_ocall_client_ocall(FILTERING_OCALL_PROXY_REQUEST_ANSWER, message);
      }
      break;
    case FILTERING_OCALL_PROXY_RESPONSE_MESSAGE:
      if (!validate_oscore_data_length(message)) {
        LOG_MESSAGE("Proxy response is invalid\n");
      } else {
        LOG_MESSAGE("Got reply to proxied request\n");
        if (!oscore_filter_check_proxy_response(
            (oscore_data_t *)message->payload,
            message->ptr)) {
          message->type = FILTERING_OCALL_DROP_RESPONSE_MESSAGE;
          message->payload_length = 0;
        } else {
          message->type = FILTERING_OCALL_FORWARD_RESPONSE_MESSAGE;
        }
        filtering_ocall_client_ocall(FILTERING_OCALL_PROXY_RESPONSE_ANSWER,
            message);
      }
      break;
    case FILTERING_OCALL_OSCORE_MESSAGE:
      if (!validate_oscore_data_length(message)) {
        LOG_MESSAGE("OSCORE message is invalid\n");
      } else {
        oscore_data = (oscore_data_t *)message->payload;
        if (handle_oscore_message(oscore_data)) {
          message->payload_length = sizeof(oscore_data_t)
              + oscore_data->ciphertext_len;
        } else {
          message->payload_length = 0;
        }
        message->type = FILTERING_OCALL_OSCORE_RESPONSE_MESSAGE;
        filtering_ocall_client_ocall(FILTERING_OCALL_OSCORE_ANSWER, message);
      }
      break;
    default:
      LOG_MESSAGE("Received unknown Ocall message\n");
      shall_exit = 1;
      break;
    }

    free(message);
  }
}

static int
validate_oscore_data_length(filtering_ocall_message_t *message)
{
  oscore_data_t *oscore_data;

  oscore_data = (oscore_data_t *)message->payload;
  if (message->payload_length < sizeof(oscore_data_t)) {
    return 0;
  }
  if (message->payload_length
      != (sizeof(oscore_data_t) + oscore_data->ciphertext_len)) {
    return 0;
  }
  return 1;
}

static int
handle_oscore_message(oscore_data_t *data)
{
  registration_t *registration;
  uint64_t sequence_number;
  uint8_t nonce[CCM_STAR_NONCE_LENGTH];
  registration_t *receivers_registration;
  uint8_t *mic;
  uint8_t *receiver_address;
  uint8_t *wake_up_counter;
  uint8_t *radio_frame_length;
  proxied_request_t *proxied_request;

  /* find registration */
  registration = registration_find(
      data->iot_device_id, data->iot_device_id_len, true);
  if (!registration) {
    LOG_MESSAGE("Unregistered sender\n");
    return 0;
  }

  /* check authenticity and freshness */
  sequence_number = oscore_option_data_get_sequence_number(&data->option_data);
  if (!oscore_is_authentic(&registration->forwarding.context,
      sequence_number, false,
      data->ciphertext, data->ciphertext_len)) {
    LOG_MESSAGE("Inauthentic OSCORE message\n");
    return 0;
  }
  if (!oscore_is_fresh(&registration->forwarding.context.anti_replay,
      sequence_number)) {
    LOG_MESSAGE("Replayed OSCORE message\n");
    /* TODO return 0 */
  }

  /* check URI path */
  if (!memcmp(data->ciphertext
          + data->ciphertext_len
          - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN
          - (sizeof(update_uri) - 1), update_uri, sizeof(update_uri) - 1)) {
    LOG_MESSAGE("Received update message\n");
    data->ciphertext[0] = 0 /* ACK code */;
    data->ciphertext_len = 1 + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  } else if (!memcmp(data->ciphertext
          + data->ciphertext_len
          - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN
          - REFERENCE_LENGTH /* mic */
          - data->iot_device_id_len /* receiver address */
          - 4 /* wake-up counter */
          - 1 /* length of radio frame */
          - 1 /* payload marker */
          - (sizeof(otp_uri) - 1), otp_uri, sizeof(otp_uri) - 1)) {
    /* parse OTP message*/
    mic = data->ciphertext
        + data->ciphertext_len
        - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN
        - REFERENCE_LENGTH;
    receiver_address = mic - data->iot_device_id_len;
    wake_up_counter = receiver_address - 4;
    radio_frame_length = wake_up_counter - 1;

    /* TODO look up based on MIC too */
    receivers_registration = registration_find(receiver_address, data->iot_device_id_len, true);
    if (!receivers_registration) {
      LOG_MESSAGE("Unregistered receiver\n");
      return 0;
    }

    if (memcmp(receivers_registration->mic, mic, REFERENCE_LENGTH)) {
      proxied_request = list_head(receivers_registration->proxied_request_list);
      while (proxied_request) {
        if (!memcmp(proxied_request->mic, mic, REFERENCE_LENGTH)) {
          break;
        }
        proxied_request = list_item_next(proxied_request);
      }
      if (!proxied_request) {
        LOG_MESSAGE("Did not find respective message\n");
        return 0;
      }
      /* TODO limit the number of times we return filtering OTPs */
    }

    /* generate CCM* nonce */
    memcpy(nonce, data->iot_device_id, data->iot_device_id_len);
    nonce[data->iot_device_id_len] = 0 /* alpha and burst index */;
    memcpy(nonce + data->iot_device_id_len + 1, wake_up_counter, 4);
    memset(nonce + data->iot_device_id_len + 1 + 4,
        0,
        CCM_STAR_NONCE_LENGTH - data->iot_device_id_len - 1 - 4);

    /* generate OTP in payload */
    data->ciphertext[0] = COAP_RESPONSE_CODE(205);
    data->ciphertext[1] = COAP_PAYLOAD_START;
    CCM_STAR.set_key(receivers_registration->forwarding.otp);
    CCM_STAR.aead(nonce,
        NULL, 0,
        radio_frame_length, 1,
        data->ciphertext + 2, CSL_FRAMER_POTR_OTP_LEN, 1);

    data->ciphertext_len = 1
        + 1
        + CSL_FRAMER_POTR_OTP_LEN
        + COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
  } else {
    LOG_MESSAGE("Unexpected OSCORE message\n");
    return 0;
  }

  /* create authenticated ACK */
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
