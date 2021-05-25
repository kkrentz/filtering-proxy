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

#ifndef OSCORE_H_
#define OSCORE_H_

#include <stdint.h>

#ifdef WITH_CONTIKI
#include "lib/aes-128.h"
#else
#include "aes-128.h"
#endif
#include "cose.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OSCORE_MAX_ID_CONTEXT_LEN (16)
#define OSCORE_MAX_PARTIAL_IV_LEN (5)
#define OSCORE_MAX_ID_LEN (13 - OSCORE_MAX_PARTIAL_IV_LEN - 1)
#define OSCORE_MAX_AAD_LEN (60) /* TODO compute precisely */
#define OSCORE_OPTION_MAX_VALUE_LENGTH (15)
#define OSCORE_OPTION_PARTIAL_IV_MASK (0x07)
#define OSCORE_OPTION_KID_FLAG (0x08)
#define OSCORE_OPTION_KID_CONTEXT_FLAG (0x10)
#define OSCORE_OPTION_RESERVED_FLAGS (0xE0)
#define OSCORE_DEFAULT_REPLAY_WINDOW (32)
#define OSCORE_MAX_SEQUENCE_NUMBER (((uint64_t)1 << 40) - 1)

typedef struct oscore_keying_material_t {
  uint8_t master_salt_len;
  uint8_t id_context_len;
  uint8_t keying_material[];
} oscore_keying_material_t;

typedef struct oscore_option_data_t {
  uint8_t partial_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
  uint8_t partial_iv_len;
  uint8_t kid[OSCORE_MAX_ID_LEN];
  uint8_t kid_len;
  uint8_t kid_context[OSCORE_MAX_ID_CONTEXT_LEN];
  uint8_t kid_context_len;
} oscore_option_data_t;

typedef struct oscore_anti_replay_t {
  uint64_t last_sequence_number;
  uint32_t sliding_window;
} oscore_anti_replay_t;

typedef struct oscore_context_t {
  const oscore_keying_material_t *keying_material;
  uint8_t sender_id[OSCORE_MAX_ID_LEN];
  uint8_t sender_id_len;
  uint8_t recipient_id[OSCORE_MAX_ID_LEN];
  uint8_t recipient_id_len;
  uint64_t senders_sequence_number;
  oscore_anti_replay_t anti_replay;
} oscore_context_t;

uint64_t oscore_option_data_get_sequence_number(
    const oscore_option_data_t *oscore_option_data);
void oscore_init_keying_material(oscore_keying_material_t *keying_material,
    const uint8_t master_secret[AES_128_KEY_LENGTH],
    const uint8_t *master_salt, uint8_t master_salt_len,
    const uint8_t *id_context, uint8_t id_context_len);
int oscore_init_context(oscore_context_t *context,
    const uint8_t *recipient_id, uint8_t recipient_id_len,
    const uint8_t *sender_id, uint8_t sender_id_len,
    const oscore_keying_material_t *keying_material);
void oscore_init_anti_replay_data(oscore_anti_replay_t *anti_replay);
void oscore_option_encode(
    uint8_t option_value[OSCORE_OPTION_MAX_VALUE_LENGTH],
    size_t *option_length,
    const oscore_option_data_t *oscore_option_data,
    int is_request);
int oscore_option_decode(oscore_option_data_t *oscore_option_data,
    const uint8_t *option_value, size_t option_length);
int oscore_is_authentic(oscore_context_t *context,
    uint64_t sequence_number, bool is_senders_sequence_number,
    uint8_t *ciphertext, uint8_t ciphertext_len);
int oscore_is_fresh(oscore_anti_replay_t *anti_replay,
    uint64_t sequence_number);
int oscore_secure(oscore_context_t *context,
    oscore_option_data_t *oscore_option_data,
    uint8_t *plaintext, uint8_t plaintext_len,
    uint64_t sequence_number, bool is_senders_sequence_number);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_H_ */
