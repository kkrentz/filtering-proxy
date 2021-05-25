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

#include "iot_message.h"

#include <string.h>

#include "clock.h"
#include "memory.h"

static iot_message_t *
store(registration_t *registration, iot_message_type_t type) {
  iot_message_t *iot_message = memory_alloc(MEMORY_TYPE_IOT_MESSAGE);

  if (!iot_message) {
    LOG_MESSAGE("memory_alloc failed\n");
    return NULL;
  }

  /* initialize */
  iot_message->type = type;
  iot_message->creation_timestamp = clock_centiseconds();
  iot_message->filtering_otp_count = 0;

  /* add to list */
  list_add(registration->iot_messages, iot_message);
  return iot_message;
}

iot_message_t *
iot_message_store_control_response(registration_t *registration,
                                   uint16_t echoed_message_id) {
  iot_message_t *iot_message = iot_message_find(
                                   registration,
                                   IOT_MESSAGE_CONTROL_RESPONSE,
                                   echoed_message_id,
                                   IOT_MESSAGE_ID_INDEX_ECHOED);
  if (iot_message) {
    /* return existing one */
    return iot_message;
  }

  iot_message = store(registration, IOT_MESSAGE_CONTROL_RESPONSE);
  if (!iot_message) {
    return NULL;
  }
  iot_message->message_ids[IOT_MESSAGE_ID_INDEX_ECHOED] = echoed_message_id;
  return iot_message;
}

iot_message_t *
iot_message_store_proxied_request(registration_t *registration,
                                  coap_pdu_type_t pdu_type,
                                  uint16_t original_message_id) {
  iot_message_t *iot_message = iot_message_find(
                                   registration,
                                   IOT_MESSAGE_PROXIED_REQUEST,
                                   original_message_id,
                                   IOT_MESSAGE_ID_INDEX_ORIGINAL);
  if (iot_message) {
    /* return existing one */
    return iot_message;
  }

  iot_message = store(registration, IOT_MESSAGE_PROXIED_REQUEST);
  if (!iot_message) {
    return NULL;
  }
  iot_message->pdu_type = pdu_type;
  iot_message->message_ids[IOT_MESSAGE_ID_INDEX_ORIGINAL] =
      original_message_id;
  iot_message->message_ids[IOT_MESSAGE_ID_INDEX_NEW] =
      registration->next_message_id++;
  return iot_message;
}

iot_message_t *
iot_message_find(registration_t *registration,
                 iot_message_type_t type,
                 uint16_t message_id,
                 size_t message_id_index) {
  iot_message_clean_up(registration);
  for (iot_message_t *iot_message = list_head(registration->iot_messages);
       iot_message;
       iot_message = list_item_next(iot_message)) {
    if (iot_message->type != type) {
      continue;
    }
    if (iot_message->message_ids[message_id_index] == message_id) {
      return iot_message;
    }
  }
  return NULL;
}

void
iot_message_remove(registration_t *registration,
                   iot_message_t *iot_message) {
  if (iot_message) {
    list_remove(registration->iot_messages, iot_message);
    memory_free(MEMORY_TYPE_IOT_MESSAGE, iot_message);
  }
}

void
iot_message_clean_up(registration_t *registration) {
  uint16_t now = clock_centiseconds();
  iot_message_t *iot_message = list_head(registration->iot_messages);
  while (iot_message) {
    iot_message_t *next_iot_message = list_item_next(iot_message);
    if ((now - iot_message->creation_timestamp)
        > (OSCORE_NG_FRESHNESS_THRESHOLD * 2 + OSCORE_NG_PROCESSING_DELAY)) {
      iot_message_remove(registration, iot_message);
    }
    iot_message = next_iot_message;
  }
}

void
iot_message_clear(registration_t *registration) {
  iot_message_t *iot_message;

  while ((iot_message = list_head(registration->iot_messages))) {
    iot_message_remove(registration, iot_message);
  }
}
