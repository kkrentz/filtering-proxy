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

#include "iot_client.h"

#include "app/string.h"
#include "app/malloc.h"
#include "list.h"

iot_client_session_t *
iot_client_create_session(registration_t *registration,
    const uint8_t iot_client_id[OSCORE_MAX_ID_LEN], uint8_t iot_client_id_len)
{
  iot_client_session_t *session;

  /* allocate memory */
  session = malloc(sizeof(*session));
  if (!session) {
    return NULL;
  }

  /* initialize */
  memcpy(session->id, iot_client_id, iot_client_id_len);
  session->id_len = iot_client_id_len;
  if (!oscore_init_context(&session->context,
      iot_client_id, iot_client_id_len,
      registration->iot_device_id, registration->iot_device_id_len,
      registration->disclosed_keying_material)) {
    free(session);
    return NULL;
  }
  leaky_bucket_init(&session->leaky_bucket,
      10 /* capacity for 10 drops */,
      60 /* 1 drop per minute */);

  /* add to list */
  list_add(registration->iot_client_session_list, session);

  return session;
}


iot_client_session_t *
iot_client_find_session(registration_t *registration,
    const uint8_t *iot_client_id, uint8_t iot_client_id_len)
{
  iot_client_session_t *session;

  session = list_head(registration->iot_client_session_list);
  while (session) {
    if ((session->id_len == iot_client_id_len)
        && !memcmp(session->id, iot_client_id, iot_client_id_len)) {
      return session;
    }
    session = list_item_next(session);
  }
  return NULL;
}

void
iot_client_delete_session(registration_t *registration,
    iot_client_session_t *session)
{
  list_remove(registration->iot_client_session_list, session);
  free(session);
}

void
iot_client_clear(registration_t *registration)
{
  iot_client_session_t *session;

  while ((session = list_head(registration->iot_client_session_list))) {
    iot_client_delete_session(registration, session);
  }
}
