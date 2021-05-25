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

#include "registration.h"

#include <string.h>

#include "log.h"
#include "iot_client.h"
#include "memory.h"
#include "iot_message.h"

LIST(registrations_list);

void
registration_init(void) {
  list_init(registrations_list);
}

registration_t *
registration_create(
    const uint8_t ephemeral_public_key_head[ECC_CURVE_P_256_SIZE]) {
  registration_t *registration;

  /* remove other ongoing registrations of that IoT device */
  registration = registration_find_ongoing(ephemeral_public_key_head,
                                           ECC_CURVE_P_256_SIZE);
  if (registration) {
    registration_delete(registration);
  }

  /* allocate memory */
  registration = memory_alloc(MEMORY_TYPE_REGISTRATION);
  if (!registration) {
    LOG_MESSAGE("memory_alloc failed\n");
    return NULL;
  }

  /* initialize */
  registration->is_complete = false;
  memcpy(registration->ephemeral_public_key_head,
         ephemeral_public_key_head,
         sizeof(registration->ephemeral_public_key_head));
  registration->tunnel.context.keying_material = NULL;
  list_add(registrations_list, registration);
  return registration;
}

int
registration_complete(
    registration_t *registration,
    const uint8_t master_secret[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t *master_salt, size_t master_salt_len,
    bool *has_existed) {
  /* validate inputs */
  if (master_salt_len > SHA_256_BLOCK_SIZE) {
    LOG_MESSAGE("Master Salt too long\n");
    return 0;
  }

  registration_t *previous_registration =
      registration_find(registration_get_iot_device_id(registration));

  /* finish initialization */
  if (!oscore_ng_csprng(&registration->next_message_id,
                        sizeof(registration->next_message_id))) {
    LOG_MESSAGE("oscore_ng_csprng failed\n");
    return 0;
  }
  LIST_STRUCT_INIT(registration, iot_messages);
  LIST_STRUCT_INIT(registration, iot_client_sessions);
  oscore_ng_copy_keying_material(
      &registration->disclosed_keying_material,
      registration->master_secret,
      master_secret,
      sizeof(registration->master_secret),
      registration->master_salt,
      master_salt,
      master_salt_len);
  registration->is_complete = true;
  if (!previous_registration) {
    *has_existed =  false;
    return 1;
  }

  /* migrate sessions and messages */
  {
    iot_client_session_t *session;
    while ((session = list_head(previous_registration->iot_client_sessions))) {
      list_remove(previous_registration->iot_client_sessions, session);
      list_add(registration->iot_client_sessions, session);
      session->context.keying_material =
          &registration->disclosed_keying_material;
      session->context.sender_id =
          registration_get_iot_device_id(registration);
    }
  }
  {
    iot_message_t *message;
    while ((message = list_head(previous_registration->iot_messages))) {
      list_remove(previous_registration->iot_messages, message);
      list_add(registration->iot_messages, message);
    }
  }
  registration_delete(previous_registration);
  *has_existed = true;
  return 1;
}

registration_t *
registration_find_ongoing(const uint8_t *ephemeral_public_key_head,
                          size_t head_len) {
  if (head_len > ECC_CURVE_P_256_SIZE) {
    return NULL;
  }
  for (registration_t *registration = list_head(registrations_list);
       registration;
       registration = list_item_next(registration)) {
    if (!registration->is_complete
        && !memcmp(registration->ephemeral_public_key_head,
                   ephemeral_public_key_head,
                   head_len)) {
      return registration;
    }
  }
  return NULL;
}

const oscore_ng_id_t *
registration_get_iot_device_id(registration_t *registration) {
  return &registration->tunnel.context.recipient_id;
}

registration_t *
registration_find(const oscore_ng_id_t *iot_device_id) {
  for (registration_t *registration = list_head(registrations_list);
       registration;
       registration = list_item_next(registration)) {
    if (registration->is_complete
        && oscore_ng_are_ids_equal(
            iot_device_id,
            registration_get_iot_device_id(registration))) {
      return registration;
    }
  }
  return NULL;
}

/* TODO delete inactive IoT devices and client sessions automatically */
void
registration_delete(registration_t *registration) {
  if (!registration) {
    return;
  }
  if (registration->tunnel.context.keying_material) {
    oscore_ng_clear_context(&registration->tunnel.context);
  }
  if (registration->is_complete) {
    iot_client_clear(registration);
    iot_message_clear(registration);
  }
  list_remove(registrations_list, registration);
  memory_free(MEMORY_TYPE_REGISTRATION, registration);
}
