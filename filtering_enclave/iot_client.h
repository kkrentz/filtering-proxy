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

#ifndef IOT_CLIENT_H_
#define IOT_CLIENT_H_

#include <stdint.h>

#include "oscore.h"

#include "leaky-bucket.h"
#include "registration.h"

typedef struct iot_client_session_t {
  struct iot_client_session_t *next;
  oscore_context_t context;
  uint8_t id[OSCORE_MAX_ID_LEN];
  uint8_t id_len;
  struct leaky_bucket leaky_bucket;
} iot_client_session_t;

iot_client_session_t *iot_client_create_session(registration_t *registration,
    const uint8_t iot_client_id[OSCORE_MAX_ID_LEN], uint8_t iot_client_id_len);
iot_client_session_t *iot_client_find_session(registration_t *registration,
    const uint8_t *iot_client_id, uint8_t iot_client_id_len);
void iot_client_delete_session(registration_t *registration,
    iot_client_session_t *session);
void iot_client_clear(registration_t *registration);

#endif /* IOT_CLIENT_H_ */
