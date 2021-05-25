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

#ifndef OSCORE_NG_H_
#define OSCORE_NG_H_

#include <stdbool.h>
#include <stdint.h>

#include "aes-128.h"
#include "cose.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OSCORE_NG_E2E_MESSAGE_ID_LEN (2)
#define OSCORE_NG_MAX_TIMESTAMP_BYTES (5)
#define OSCORE_NG_MAX_ID_LEN (COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN \
                              - 1 /* Sender ID length */ \
                              - OSCORE_NG_E2E_MESSAGE_ID_LEN \
                              - OSCORE_NG_MAX_TIMESTAMP_BYTES)
#define OSCORE_NG_MAX_R1_LEN (8)
#define OSCORE_NG_MAX_R2_LEN (16)
#define OSCORE_NG_MAX_ID_CONTEXT_LEN (OSCORE_NG_MAX_R1_LEN \
                                      + OSCORE_NG_MAX_R2_LEN)
#define OSCORE_NG_OPTION_MAX_VALUE_LEN (1 /* flags || phase */ \
                                        + 1 /* timestamp-related header */ \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_MAX_TIMESTAMP_BYTES \
                                        + OSCORE_NG_E2E_MESSAGE_ID_LEN \
                                        + 1 /* s */ \
                                        + OSCORE_NG_MAX_ID_CONTEXT_LEN \
                                        + OSCORE_NG_MAX_ID_LEN)
#define OSCORE_NG_ACK_TIMEOUT (2 * 100) /* = 2 seconds */
#define OSCORE_NG_MAX_TRANSMIT_SPAN (45 * 100)
#define OSCORE_NG_FRESHNESS_THRESHOLD (785)
#define OSCORE_NG_PROCESSING_DELAY (200)

#ifdef KEYSTONE_ENCLAVE
typedef struct coap_bin_const_t {
  size_t length;    /**< length of binary data */
  const uint8_t *s; /**< read-only binary data */
} coap_bin_const_t;
#else /* KEYSTONE_ENCLAVE */
#include <coap3/coap.h>
#endif /* KEYSTONE_ENCLAVE */

typedef struct oscore_ng_keying_material_t {
  coap_bin_const_t master_secret;
  coap_bin_const_t master_salt;
} oscore_ng_keying_material_t;

typedef struct oscore_ng_id_t {
  uint8_t u8[OSCORE_NG_MAX_ID_LEN];
  uint8_t len;
} oscore_ng_id_t;

typedef struct oscore_ng_id_context_t {
  uint8_t u8[OSCORE_NG_MAX_ID_CONTEXT_LEN];
  uint8_t len;
} oscore_ng_id_context_t;

typedef struct oscore_ng_option_data_t {
  oscore_ng_id_t kid;
  oscore_ng_id_context_t kid_context;
  uint64_t corresponding_tx_timestamp; /* in centiseconds */
  uint64_t rx_timestamp; /* in centiseconds */
  uint64_t tx_timestamp; /* in centiseconds */
  uint16_t e2e_message_id;
  uint_fast8_t phase;
  bool asking_for_resync;
} oscore_ng_option_data_t;

typedef struct oscore_ng_option_value_t {
  size_t len;
  uint8_t u8[OSCORE_NG_OPTION_MAX_VALUE_LEN];
} oscore_ng_option_value_t;

typedef enum oscore_ng_b2_stage_t {
  OSCORE_NG_B2_DISABLED = 0,
  OSCORE_NG_B2_RUNNING,
  OSCORE_NG_B2_DONE,
} oscore_ng_b2_stage_t;

typedef struct oscore_ng_context_t {
  const oscore_ng_keying_material_t *keying_material;
  const oscore_ng_id_t *sender_id;
  oscore_ng_id_t recipient_id;
  oscore_ng_id_context_t id_context;
  uint64_t last_synchronization; /* in centiseconds */
  int64_t delta; /* clock difference in centiseconds */
  uint64_t pending_corresponding_tx_timestamp;  /* in centiseconds */
  uint64_t pending_rx_timestamp; /* in centiseconds */
  LIST_STRUCT(anti_replay_list);
  oscore_ng_b2_stage_t b2_stage;
  bool has_explicit_id_context;
} oscore_ng_context_t;

typedef struct oscore_ng_anti_replay_t {
  struct oscore_ng_anti_replay_t *next;
  uint16_t e2e_message_id;
  uint16_t restored_tx_timestamp;
  uint16_t rx_timestamp;
  bool was_request:1;
} oscore_ng_anti_replay_t;

typedef enum oscore_ng_unsecure_result_t {
  OSCORE_NG_UNSECURE_RESULT_ERROR,
  OSCORE_NG_UNSECURE_RESULT_OK,
  OSCORE_NG_UNSECURE_RESULT_DUPLICATE,
  OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1,
} oscore_ng_unsecure_result_t;

/* implemented elsewhere so as to enable reusing this module in a tee */
uint64_t oscore_ng_generate_timestamp(void);
int oscore_ng_csprng(void *dst, size_t dst_len);
oscore_ng_anti_replay_t *oscore_ng_alloc_anti_replay(void);
void oscore_ng_free_anti_replay(oscore_ng_anti_replay_t *anti_replay);

/* actual API */
void oscore_ng_copy_id(
    oscore_ng_id_t *dst,
    const oscore_ng_id_t *src);
void oscore_ng_copy_id_context(
    oscore_ng_id_context_t *dst,
    const oscore_ng_id_context_t *src);
bool oscore_ng_are_ids_equal(
    const oscore_ng_id_t *ida,
    const oscore_ng_id_t *idb);
bool oscore_ng_are_id_contexts_equal(
    const oscore_ng_id_context_t *id_context_a,
    const oscore_ng_id_context_t *id_context_b);
void oscore_ng_init_keying_material(
    oscore_ng_keying_material_t *keying_material,
    const uint8_t *master_secret,
    size_t master_secret_len,
    const uint8_t *master_salt,
    size_t master_salt_len);
void oscore_ng_copy_keying_material(
    oscore_ng_keying_material_t *keying_material,
    uint8_t *master_secret_dst,
    const uint8_t *master_secret_src,
    size_t master_secret_len,
    uint8_t *master_salt_dst,
    const uint8_t *master_salt_src,
    size_t master_salt_len);
void oscore_ng_init_context(
    oscore_ng_context_t *context,
    const oscore_ng_id_t *recipient_id,
    const oscore_ng_id_t *sender_id,
    const oscore_ng_keying_material_t *keying_material);
void oscore_ng_clear_context(
    oscore_ng_context_t *context);
void oscore_ng_encode_option(
    oscore_ng_option_value_t *option_value,
    const oscore_ng_option_data_t *option_data,
    bool is_request);
int oscore_ng_decode_option(
    oscore_ng_option_data_t *option_data,
    uint16_t message_id,
    const uint8_t *option_value,
    size_t option_len);
int oscore_ng_secure(
    oscore_ng_context_t *context,
    oscore_ng_option_data_t *option_data,
    uint16_t message_id,
    uint8_t *plaintext, uint8_t plaintext_len,
    bool is_request);
enum oscore_ng_unsecure_result_t oscore_ng_unsecure(
    oscore_ng_context_t *context,
    oscore_ng_option_data_t *option_data,
    uint8_t *ciphertext, uint8_t ciphertext_len,
    bool is_request);
void oscore_ng_start_b2(
    oscore_ng_context_t *context);
void oscore_ng_set_id_context(
    oscore_ng_context_t *context,
    const oscore_ng_id_context_t *id_context,
    bool is_explicit_id_context);

/* a self-test */
int oscore_ng_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_NG_H_ */
