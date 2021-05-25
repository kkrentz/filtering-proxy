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

#include "ocall_dispatcher.h"

#include <stdint.h>
#include <string.h>
#include <syscall.h>
#include <edge_call.h>
#include <eapp_utils.h>

#include "attestation_service.h"
#include "log.h"
#include "oscore_ng_filter.h"
#include "registration.h"

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

static int handle_ocall(struct edge_data *edge_data);

#if LOG_LEVEL
void
ocall_dispatcher_print_buffer(char *data) {
  ocall(FILTERING_OCALL_PRINT_BUFFER, data, strlen(data) + 1, 0, 0);
}

void
ocall_dispatcher_print_value(long val) {
  ocall(FILTERING_OCALL_PRINT_VALUE, &val, sizeof(long), 0, 0);
}

void
ocall_dispatcher_print_bytes(uint8_t *bytes, size_t bytes_len) {
  ocall(FILTERING_OCALL_PRINT_BYTES, bytes, bytes_len, 0, 0);
}
#endif /* LOG_LEVEL */

void
ocall_dispatcher_ocall(filtering_ocall_id_t ocall_id,
                       filtering_ocall_message_t *message) {
  ocall(ocall_id,
        message,
        sizeof(filtering_ocall_message_t) + message->payload_length,
        0,
        0);
}

void
ocall_dispatcher_accept_ocalls(void) {
  struct edge_data edge_data;

  do {
    ocall(FILTERING_OCALL_ACCEPT_OCALL,
          NULL,
          0,
          &edge_data,
          sizeof(struct edge_data));
  } while (handle_ocall(&edge_data));
}

#if !WITH_TRAP
static filtering_ocall_address_t *
extract_address(filtering_ocall_message_t *message) {
  if (message->payload_length != sizeof(filtering_ocall_address_t)) {
    return NULL;
  }
  filtering_ocall_address_t *address =
      (filtering_ocall_address_t *)message->payload;
  if (address->address.length > sizeof(address->address_bytes)) {
    return NULL;
  }
  address->address.s = address->address_bytes;
  return address;
}
#endif /* !WITH_TRAP */

static filtering_ocall_oscore_ng_data_t *
extract_oscore_ng_data(filtering_ocall_message_t *message) {
  if (message->payload_length < sizeof(filtering_ocall_oscore_ng_data_t)) {
    return NULL;
  }
  filtering_ocall_oscore_ng_data_t *data =
      (filtering_ocall_oscore_ng_data_t *)message->payload;
  if (message->payload_length != (sizeof(filtering_ocall_oscore_ng_data_t)
                                  + data->ciphertext_len)) {
    return NULL;
  }
  /* validate all length fields */
  if ((data->client_id.len > sizeof(data->client_id.u8))
      || (data->server_id.len > sizeof(data->server_id.u8))
      || (data->option_data.kid.len > sizeof(data->option_data.kid.u8))
      || (data->option_data.kid_context.len
          > sizeof(data->option_data.kid_context.u8))) {
    return NULL;
  }
  return data;
}

static int
handle_ocall(struct edge_data *edge_data) {
  union {
    filtering_ocall_message_t message;
    uint8_t bytes[sizeof(filtering_ocall_message_t)
                  + FILTERING_OCALL_MAX_PAYLOAD_LEN];
  } u;
  union {
    filtering_ocall_oscore_ng_data_t *oscore_ng_data;
    filtering_ocall_register_data_t register_data;
#if !WITH_TRAP
    filtering_ocall_address_t *address;
#endif /* !WITH_TRAP */
  } v;
  filtering_ocall_id_t reply_ocall_id;

  if (edge_data->size > sizeof(u.bytes)) {
    LOG_MESSAGE("message is too large\n");
    return 0;
  }
  copy_from_shared(u.bytes, edge_data->offset, edge_data->size);

  /* validate token */
  if (u.message.token.length > sizeof(u.message.token_bytes)) {
    LOG_MESSAGE("token is corrupted\n");
    return 0;
  }
  u.message.token.s = u.message.token_bytes;

  /* dispatch */
  switch (u.message.type) {
#if !WITH_TRAP
  case FILTERING_OCALL_KNOCK_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_COOKIE;
    u.message.type = FILTERING_OCALL_COOKIE_MESSAGE;

    v.address = extract_address(&u.message);
    if (!v.address
        || !bakery_bake_cookie(u.message.payload, &v.address->address)) {
      LOG_MESSAGE("bakery_bake_cookie failed");
      u.message.payload_length = 0;
      break;
    }
    u.message.payload_length = BAKERY_COOKIE_SIZE;
    break;
#endif /* !WITH_TRAP */
  case FILTERING_OCALL_REGISTER_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_GOT_REPORT;
    u.message.type = FILTERING_OCALL_REPORT_MESSAGE;

    if (u.message.payload_length != sizeof(filtering_ocall_register_data_t)) {
      LOG_MESSAGE("Register message has invalid length\n");
      u.message.payload_length = 0;
      break;
    }
    memcpy(&v.register_data, u.message.payload, sizeof(v.register_data));
#if !WITH_TRAP
    if (v.register_data.address.address.length
        > sizeof(v.register_data.address.address_bytes)) {
      LOG_MESSAGE("Address has invalid length\n");
      u.message.payload_length = 0;
      break;
    }
    v.register_data.address.address.s = v.register_data.address.address_bytes;
#endif /* !WITH_TRAP */

    u.message.payload_length = attestation_service_handle_register_message(
                                   &v.register_data,
                                   u.message.payload);
    if (!u.message.payload_length) {
      LOG_MESSAGE("Register message is invalid\n");
    } else {
      LOG_MESSAGE("Received register message\n");
    }
    break;
  case FILTERING_OCALL_DISCLOSE_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_DISCLOSE_ANSWER;
    u.message.type = FILTERING_OCALL_DISCLOSE_RESPONSE_MESSAGE;

    v.oscore_ng_data = extract_oscore_ng_data(&u.message);
    if (!v.oscore_ng_data
        || !attestation_service_handle_disclose_message(v.oscore_ng_data,
                                                        &u.message.token)) {
      LOG_MESSAGE("Disclose message is invalid\n");
      u.message.payload_length = 0;
    } else {
      LOG_MESSAGE("Received disclose message\n");
      u.message.payload_length = sizeof(filtering_ocall_oscore_ng_data_t)
                                 + v.oscore_ng_data->ciphertext_len;
    }
    break;
  case FILTERING_OCALL_PROXY_REQUEST_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_PROXY_REQUEST_ANSWER;

    v.oscore_ng_data = extract_oscore_ng_data(&u.message);
    if (!v.oscore_ng_data) {
      LOG_MESSAGE("Proxy request is invalid\n");
      u.message.type = FILTERING_OCALL_DROP_REQUEST_MESSAGE;
      u.message.payload_length = 0;
      ocall_dispatcher_ocall(FILTERING_OCALL_PROXY_REQUEST_ANSWER, &u.message);
      break;
    }

    LOG_MESSAGE("Received proxy request\n");
    switch (oscore_ng_filter_check_proxy_request(v.oscore_ng_data,
                                                 &u.message.token)) {
    case OSCORE_NG_FILTER_VERDICT_RETURN:
      reply_ocall_id = FILTERING_OCALL_PROXY_RESPONSE_ANSWER;
      u.message.type = FILTERING_OCALL_FORWARD_RESPONSE_MESSAGE;
      u.message.payload_length = sizeof(filtering_ocall_oscore_ng_data_t)
                                 + v.oscore_ng_data->ciphertext_len;
      break;
    case OSCORE_NG_FILTER_VERDICT_FORWARD:
      u.message.type = FILTERING_OCALL_FORWARD_REQUEST_MESSAGE;
      u.message.payload_length = sizeof(filtering_ocall_oscore_ng_data_t)
                                 + v.oscore_ng_data->ciphertext_len;
      break;
    default:
      u.message.type = FILTERING_OCALL_DROP_REQUEST_MESSAGE;
      u.message.payload_length = 0;
      break;
    }
    break;
  case FILTERING_OCALL_PROXY_RESPONSE_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_PROXY_RESPONSE_ANSWER;

    v.oscore_ng_data = extract_oscore_ng_data(&u.message);
    if (!v.oscore_ng_data
        || !oscore_ng_filter_check_proxy_response(v.oscore_ng_data,
                                                  &u.message.token)) {
      LOG_MESSAGE("Proxy response is invalid\n");
      u.message.type = FILTERING_OCALL_DROP_RESPONSE_MESSAGE;
      u.message.payload_length = 0;
    } else {
      u.message.type = FILTERING_OCALL_FORWARD_RESPONSE_MESSAGE;
      u.message.payload_length = sizeof(filtering_ocall_oscore_ng_data_t)
                                 + v.oscore_ng_data->ciphertext_len;
    }
    break;
  case FILTERING_OCALL_OSCORE_NG_MESSAGE:
    reply_ocall_id = FILTERING_OCALL_OSCORE_NG_ANSWER;
    u.message.type = FILTERING_OCALL_OSCORE_NG_RESPONSE_MESSAGE;

    v.oscore_ng_data = extract_oscore_ng_data(&u.message);
    if (!v.oscore_ng_data
        || !oscore_ng_filter_handle_oscore_ng_message(v.oscore_ng_data,
                                                      &u.message.token)) {
      LOG_MESSAGE("OSCORE-NG message is invalid\n");
      u.message.payload_length = 0;
    } else {
      LOG_MESSAGE("Received OSCORE-NG message\n");
      u.message.payload_length = sizeof(filtering_ocall_oscore_ng_data_t)
                                 + v.oscore_ng_data->ciphertext_len;
    }
    break;
  default:
    LOG_MESSAGE("Received unknown Ocall message\n");
    return 0;
  }

  ocall_dispatcher_ocall(reply_ocall_id, &u.message);
  return 1;
}
