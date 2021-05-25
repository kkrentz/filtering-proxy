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

#include "coap3/coap_libcoap_build.h"
#include "log.h"
#include "registration.h"

typedef enum iot_message_type_t {
  IOT_MESSAGE_CONTROL_RESPONSE, /* response to a /dis, /otp, or /upd request */
  IOT_MESSAGE_PROXIED_REQUEST, /* proxied request from an IoT client */
} iot_message_type_t;

/* for control responses */
enum {
  IOT_MESSAGE_ID_INDEX_ECHOED = 0,
};

/* for proxied requests */
enum {
  IOT_MESSAGE_ID_INDEX_ORIGINAL = 0,
  IOT_MESSAGE_ID_INDEX_NEW,
  IOT_MESSAGE_ID_INDEX_MAX,
};

typedef struct iot_message_t {
  struct iot_message_t *next;
  iot_message_type_t type;
  coap_pdu_type_t pdu_type;
  uint16_t message_ids[IOT_MESSAGE_ID_INDEX_MAX];
  uint16_t creation_timestamp;
  uint8_t filtering_otp_count;
} iot_message_t;

iot_message_t *iot_message_store_control_response(registration_t *registration,
                                                  uint16_t echoed_message_id);
iot_message_t *iot_message_store_proxied_request(registration_t *registration,
                                                 coap_pdu_type_t pdu_type,
                                                 uint16_t original_message_id);
iot_message_t *iot_message_find(registration_t *registration,
                                iot_message_type_t type,
                                uint16_t message_id,
                                size_t message_id_index);
void iot_message_remove(registration_t *registration,
                        iot_message_t *iot_message);
void iot_message_clean_up(registration_t *registration);
void iot_message_clear(registration_t *registration);
