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

#include "memory.h"

#include "coap3/coap_libcoap_build.h"
#include "iot_client.h"
#include "iot_message.h"
#include "registration.h"

#if WITH_HEAP
#include <tinyalloc.h>

static uint8_t ta_zone[4096*4];

void
memory_init(void) {
  ta_init(ta_zone, ta_zone + sizeof(ta_zone),
          256,
          sizeof(oscore_ng_anti_replay_t),
          sizeof(uint64_t));
}

void *
memory_alloc(memory_type_t type) {
  switch (type) {
  case MEMORY_TYPE_ANTI_REPLAY:
    return ta_alloc(sizeof(oscore_ng_anti_replay_t));
  case MEMORY_TYPE_IOT_CLIENT_SESSION:
    return ta_alloc(sizeof(iot_client_session_t));
  case MEMORY_TYPE_IOT_MESSAGE:
    return ta_alloc(sizeof(iot_message_t));
  case MEMORY_TYPE_REGISTRATION:
    return ta_alloc(sizeof(registration_t));
  default:
    return NULL;
  }
}

void
memory_free(memory_type_t type, void *ptr) {
  (void)type;
  ta_free(ptr);
}
#else /* WITH_HEAP */
#include "memb.h"

MEMB(anti_replay_memb, oscore_ng_anti_replay_t, 100);
MEMB(iot_client_sessions_memb, iot_client_session_t, 10);
MEMB(iot_messages_memb, iot_message_t, 100);
MEMB(registrations_memb, registration_t, 10);

void
memory_init(void) {
  memb_init(&anti_replay_memb);
  memb_init(&iot_client_sessions_memb);
  memb_init(&iot_messages_memb);
  memb_init(&registrations_memb);
}

void *
memory_alloc(memory_type_t type) {
  switch (type) {
  case MEMORY_TYPE_ANTI_REPLAY:
    return memb_alloc(&anti_replay_memb);
  case MEMORY_TYPE_IOT_CLIENT_SESSION:
    return memb_alloc(&iot_client_sessions_memb);
  case MEMORY_TYPE_IOT_MESSAGE:
    return memb_alloc(&iot_messages_memb);
  case MEMORY_TYPE_REGISTRATION:
    return memb_alloc(&registrations_memb);
  default:
    return NULL;
  }
}

void
memory_free(memory_type_t type, void *ptr) {
  switch (type) {
  case MEMORY_TYPE_ANTI_REPLAY:
    return memb_free(&anti_replay_memb, ptr);
  case MEMORY_TYPE_IOT_CLIENT_SESSION:
    return memb_free(&iot_client_sessions_memb, ptr);
  case MEMORY_TYPE_IOT_MESSAGE:
    return memb_free(&iot_messages_memb, ptr);
  case MEMORY_TYPE_REGISTRATION:
    return memb_free(&registrations_memb, ptr);
  default:
    return NULL;
  }
}
#endif /* WITH_HEAP */
