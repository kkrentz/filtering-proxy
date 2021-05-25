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

#include <string.h>

#include "log.h"
#include "memory.h"

iot_client_session_t *
iot_client_create_session(registration_t *registration,
                          const oscore_ng_id_t *iot_client_id) {
  /* allocate memory */
  iot_client_session_t *session = memory_alloc(MEMORY_TYPE_IOT_CLIENT_SESSION);
  if (!session) {
    LOG_MESSAGE("memory_alloc failed\n");
    return NULL;
  }

  /* initialize */
  if (!oscore_ng_init_context(&session->context,
                              iot_client_id,
                              registration_get_iot_device_id(registration),
                              &registration->disclosed_keying_material)) {
    LOG_MESSAGE("oscore_ng_init_context failed\n");
    return NULL;
  }
  leaky_bucket_init(&session->leaky_bucket,
                    10 /* capacity for 10 drops */,
                    60 /* 1 drop per minute */);

  /* add to list */
  list_add(registration->iot_client_sessions, session);

  return session;
}

iot_client_session_t *
iot_client_find_session(registration_t *registration,
                        const oscore_ng_id_t *iot_client_id) {
  for (iot_client_session_t *session =
           list_head(registration->iot_client_sessions);
       session;
       session = list_item_next(session)) {
    if (oscore_ng_are_ids_equal(&session->context.recipient_id,
                                iot_client_id)) {
      return session;
    }
  }
  return NULL;
}

void
iot_client_delete_session(registration_t *registration,
                          iot_client_session_t *session) {
  oscore_ng_clear_context(&session->context);
  list_remove(registration->iot_client_sessions, session);
  memory_free(MEMORY_TYPE_IOT_CLIENT_SESSION, session);
}

void
iot_client_clear(registration_t *registration) {
  iot_client_session_t *session;

  while ((session = list_head(registration->iot_client_sessions))) {
    iot_client_delete_session(registration, session);
  }
}
