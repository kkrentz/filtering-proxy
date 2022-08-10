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

#include "app/string.h"
#include "app/malloc.h"
#include "sha-256.h"

#include "log.h"
#include "iot_client.h"
#include "proxied_request.h"

LIST(registration_list);

void
registration_init(void)
{
  list_init(registration_list);
}

registration_t *
registration_create(const uint8_t *iot_device_id, uint8_t iot_device_id_len)
{
  registration_t *registration;

  /* remove other ongoing registrations of that IoT device */
  registration_delete(
      registration_find(iot_device_id, iot_device_id_len, false));

  /* validate inputs */
  if (iot_device_id_len > OSCORE_MAX_ID_LEN) {
    LOG_MESSAGE("iot_device_id is too long\n");
    return NULL;
  }

  /* allocate memory */
  registration = malloc(sizeof(*registration));
  if (!registration) {
    LOG_MESSAGE("malloc failed\n");
    return NULL;
  }

  /* initialize */
  registration->completed = false;
  memcpy(registration->iot_device_id, iot_device_id, iot_device_id_len);
  registration->iot_device_id_len = iot_device_id_len;
  LIST_STRUCT_INIT(registration, proxied_request_list);
  LIST_STRUCT_INIT(registration, iot_client_session_list);
  list_add(registration_list, registration);
  return registration;
}

int
registration_complete(registration_t *registration,
    const uint8_t master_secret[AES_128_KEY_LENGTH],
    const uint8_t *master_salt, uint8_t master_salt_len,
    const uint8_t *id_context, uint8_t id_context_len)
{
  /* validate inputs */
  if ((master_salt_len > SHA_256_BLOCK_SIZE)
      || (id_context_len > OSCORE_MAX_ID_CONTEXT_LEN)) {
    LOG_MESSAGE("too long salt or ID context\n");
    return 0;
  }

  /* store disclosed keying material */
  registration->disclosed_keying_material = (oscore_keying_material_t *)malloc(
      sizeof(oscore_keying_material_t)
          + AES_128_KEY_LENGTH
          + master_salt_len
          + id_context_len);
  if (!registration->disclosed_keying_material) {
    LOG_MESSAGE("malloc failed\n");
    free(registration);
    return 0;
  }
  oscore_init_keying_material(registration->disclosed_keying_material,
      master_secret,
      master_salt, master_salt_len,
      id_context, id_context_len);

  /* remove other completed registrations of that IoT device */
  registration_delete(
      registration_find(registration->iot_device_id,
          registration->iot_device_id_len,
          true));

  /* turn into a completed registration */
  registration->completed = true;

  return 1;
}

registration_t *
registration_find(const uint8_t *iot_device_id,
    uint8_t iot_device_id_len,
    bool completed)
{
  registration_t *registration;

  registration = list_head(registration_list);
  while (registration) {
    if ((registration->completed == completed)
        && (iot_device_id_len == registration->iot_device_id_len)
        && !memcmp(iot_device_id,
            registration->iot_device_id,
            iot_device_id_len)) {
      return registration;
    }
    registration = list_item_next(registration);
  }
  return NULL;
}

/* TODO delete inactive IoT devices and client sessions automatically */
void
registration_delete(registration_t *registration)
{
  if (!registration) {
    return;
  }
  list_remove(registration_list, registration);
  if (registration->completed) {
    free(registration->disclosed_keying_material);
  }
  iot_client_clear(registration);
  proxied_request_clear(registration);
  free(registration);
}
