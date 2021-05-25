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

#ifndef REGISTRATION_H_
#define REGISTRATION_H_

#include <stdint.h>
#include <stdbool.h>

#include "cose.h"
#include "oscore.h"
#include "list.h"
#include "uECC.h"

#define REFERENCE_LENGTH (2)

typedef struct registration_t {
  struct registration_t *next;
  uint8_t iot_device_id[OSCORE_MAX_ID_LEN];
  uint8_t iot_device_id_len;
  bool completed;
  LIST_STRUCT(proxied_request_list);
  uint8_t mic[REFERENCE_LENGTH]; /* TODO we need a list */
  struct {
    oscore_context_t context;
    union {
      oscore_keying_material_t keying_material;
      struct {
        uint8_t master_salt_len;
        uint8_t id_context_len;
        union {
          uint8_t okm[AES_128_KEY_LENGTH * 2];
          struct {
            uint8_t oscore[AES_128_KEY_LENGTH];
            uint8_t otp[AES_128_KEY_LENGTH];
          };
        };
      };
    };
  } forwarding;
  LIST_STRUCT(iot_client_session_list);
  oscore_keying_material_t *disclosed_keying_material;
} registration_t;

void registration_init(void);
registration_t *registration_create(
    const uint8_t *iot_device_id, uint8_t iot_device_id_len);
int registration_complete(registration_t *registration,
    const uint8_t master_secret[AES_128_KEY_LENGTH],
    const uint8_t *master_salt, uint8_t master_salt_len,
    const uint8_t *id_context, uint8_t id_context_len);
registration_t *registration_find(const uint8_t *iot_device_id,
    uint8_t iot_device_id_len,
    bool completed);
void registration_delete(registration_t *registration);

#endif /* REGISTRATION_H_ */
