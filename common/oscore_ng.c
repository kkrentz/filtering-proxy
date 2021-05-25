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

#include "oscore_ng.h"

#include <string.h>
#include <sys/types.h>

#include "cbor.h"
#include "cose.h"
#include "sha-256.h"

#define UNSET_PHASE (UINT8_MAX)
#define OSCORE_NG_FLAG (1 << 7)
#define H_FLAG (1 << 6) /* kid context */
#define M_FLAG (1 << 5) /* end-to-end Message ID carried inline */
#define T_FLAG (1 << 4) /* timestamps included */
#define F_FLAG (1 << 3) /* further timestamps */
#define R_FLAG (1 << 6) /* resynchronization request */
#define TIMESLOT_SHIFTS (10)
#define TIMESLOT (1 << TIMESLOT_SHIFTS)
#define PHASE_SHIFTS (TIMESLOT_SHIFTS - 4)
#define PHASE_UNIT (1 << PHASE_SHIFTS)
#define PHASE_MASK (TIMESLOT - 1)
#define UNSET_DELTA (INT64_MAX)
#define MAX_INFO_LEN (OSCORE_NG_MAX_ID_LEN + OSCORE_NG_MAX_ID_CONTEXT_LEN + 10)
#define MAX_AAD_ARRAY_LEN (24 + OSCORE_NG_MAX_TIMESTAMP_BYTES * 3)
#define MAX_AAD_LEN (MAX_AAD_ARRAY_LEN + 13)
#define R1_LEN (8)
#define R2_LEN (8)
#define R3_LEN (8)
#define R2_BUFFER_SIZE (10)
#define SYNC_INTERVAL (6 * 60 * 60 * 100)

enum b2_msg {
  B2_UNRELATED,
  B2_REQUEST_1,
  B2_RESPONSE_1,
  B2_REQUEST_2,
  B2_RESPONSE_2,
};

static uint8_t last_r1[OSCORE_NG_MAX_R1_LEN];
static uint8_t last_r1_len;
static uint8_t r2s[R2_BUFFER_SIZE][R2_LEN];
static size_t next_r2_index;

static ssize_t
get_index_of_r2(const uint8_t r2[R2_LEN]) {
  for (ssize_t i = 0; i < R2_BUFFER_SIZE; i++) {
    if (!memcmp(r2s[i], r2, R2_LEN)) {
      return i;
    }
  }
  return -1;
}

static void
cache_r2(uint8_t r2[R2_LEN]) {
  memcpy(r2s[next_r2_index], r2, R2_LEN);
  if (++next_r2_index == R2_BUFFER_SIZE) {
    next_r2_index = 0;
  }
}

static uint_fast8_t
write_timestamp(uint8_t dest[OSCORE_NG_MAX_TIMESTAMP_BYTES],
                uint64_t timestamp) {
  uint_fast8_t length = 0;
  for (uint_fast8_t i = 0; i < OSCORE_NG_MAX_TIMESTAMP_BYTES; i++) {
    dest[i] = timestamp & 0xFF;
    timestamp >>= 8;
    if (dest[i]) {
      length = i + 1;
    }
  }
  return length;
}

static uint64_t
read_timestamp(const uint8_t *src, uint_fast8_t len) {
  uint64_t timestamp = 0;
  uint_fast8_t pos = 0;
  while (len--) {
    timestamp += src[pos] << (pos * 8);
    pos++;
  }
  return timestamp;
}

void
oscore_ng_copy_id(oscore_ng_id_t *dst, const oscore_ng_id_t *src) {
  memcpy(dst->u8, src->u8, src->len);
  dst->len = src->len;
}

void
oscore_ng_copy_id_context(oscore_ng_id_context_t *dst,
                          const oscore_ng_id_context_t *src) {
  memcpy(dst->u8, src->u8, src->len);
  dst->len = src->len;
}

bool
oscore_ng_are_ids_equal(const oscore_ng_id_t *ida, const oscore_ng_id_t *idb) {
  return (ida->len == idb->len) && !memcmp(ida->u8, idb->u8, ida->len);
}

bool
oscore_ng_are_id_contexts_equal(const oscore_ng_id_context_t *id_context_a,
                                const oscore_ng_id_context_t *id_context_b) {
  return (id_context_a->len == id_context_b->len)
         && !memcmp(id_context_a->u8, id_context_b->u8, id_context_a->len);
}

void
oscore_ng_init_keying_material(
    oscore_ng_keying_material_t *keying_material,
    const uint8_t *master_secret,
    size_t master_secret_len,
    const uint8_t *master_salt,
    size_t master_salt_len) {
  keying_material->master_secret.s = master_secret;
  keying_material->master_secret.length = master_secret_len;
  keying_material->master_salt.s = master_salt;
  keying_material->master_salt.length = master_salt_len;
}

void
oscore_ng_copy_keying_material(
    oscore_ng_keying_material_t *keying_material,
    uint8_t *master_secret_dst,
    const uint8_t *master_secret_src,
    size_t master_secret_len,
    uint8_t *master_salt_dst,
    const uint8_t *master_salt_src,
    size_t master_salt_len) {
  oscore_ng_init_keying_material(keying_material,
                                 master_secret_dst, master_secret_len,
                                 master_salt_dst, master_salt_len);
  memcpy(master_secret_dst, master_secret_src, master_secret_len);
  memcpy(master_salt_dst, master_salt_src, master_salt_len);
}

void
oscore_ng_init_context(oscore_ng_context_t *context,
                       const oscore_ng_id_t *recipient_id,
                       const oscore_ng_id_t *sender_id,
                       const oscore_ng_keying_material_t *keying_material) {
  memset(context, 0, sizeof(*context));
  context->keying_material = keying_material;
  oscore_ng_copy_id(&context->recipient_id, recipient_id);
  context->sender_id = sender_id;
  LIST_STRUCT_INIT(context, anti_replay_list);
}

void
oscore_ng_clear_context(oscore_ng_context_t *context) {
  oscore_ng_anti_replay_t *anti_replay;
  while ((anti_replay = list_head(context->anti_replay_list))) {
    list_remove(context->anti_replay_list, anti_replay);
    oscore_ng_free_anti_replay(anti_replay);
  }
}

static ssize_t
generate_info(uint8_t info[MAX_INFO_LEN],
              const oscore_ng_id_t *id,
              const oscore_ng_id_context_t *id_context,
              bool is_iv) {
  size_t max_info_len = MAX_INFO_LEN;

  if (!cbor_put_array(&info, &max_info_len, 5)) {
    return -1;
  }

  /* ID */
  if (!cbor_put_bytes(&info, &max_info_len, id->u8, id->len)) {
    return -1;
  }

  /* ID Context */
  if (id_context->len) {
    if (!cbor_put_bytes(&info,
                        &max_info_len,
                        id_context->u8, id_context->len)) {
      return -1;
    }
  } else {
    if (!cbor_put_nil(&info, &max_info_len)) {
      return -1;
    }
  }

  /* AEAD Algorithm */
  if (!cbor_put_unsigned(&info,
                         &max_info_len,
                         COSE_ALGORITHM_AES_CCM_16_64_128)) {
    return -1;
  }

  /* "IV" or "Key" */
  if (is_iv) {
    if (!cbor_put_text(&info,
                       &max_info_len,
                       "IV", 2)) {
      return -1;
    }
  } else {
    if (!cbor_put_text(&info,
                       &max_info_len,
                       "Key", 3)) {
      return -1;
    }
  }

  /* size of IV or key  */
  if (!cbor_put_unsigned(&info,
                         &max_info_len,
                         is_iv
                         ? COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN
                         : COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN)) {
    return -1;
  }
  return MAX_INFO_LEN - max_info_len;
}

static int
generate_common_iv(uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN],
                   const oscore_ng_keying_material_t *keying_material,
                   const oscore_ng_id_context_t *id_context) {
  static const oscore_ng_id_t empty_id = { { 0 }, 0 };
  uint8_t info[MAX_INFO_LEN];
  ssize_t info_len = generate_info(info, &empty_id, id_context, true);
  if (info_len < 0) {
    return 0;
  }
  sha_256_hkdf(keying_material->master_salt.s,
               keying_material->master_salt.length,
               keying_material->master_secret.s,
               keying_material->master_secret.length,
               info,
               info_len,
               common_iv, COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN);
  return 1;
}

static int
generate_key(uint8_t key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
             const oscore_ng_keying_material_t *keying_material,
             const oscore_ng_id_context_t *id_context,
             const oscore_ng_id_t *id) {
  uint8_t info[MAX_INFO_LEN];
  ssize_t info_len = generate_info(info, id, id_context, false);
  if (info_len < 0) {
    return 0;
  }
  sha_256_hkdf(keying_material->master_salt.s,
               keying_material->master_salt.length,
               keying_material->master_secret.s,
               keying_material->master_secret.length,
               info,
               info_len,
               key,
               COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN);
  return 1;
}

static void
generate_nonce(
    uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN],
    const oscore_ng_option_data_t *option_data,
    const uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN]) {
  memset(nonce, 0, COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN);
  nonce[0] = option_data->kid.len;
  nonce[1] = option_data->e2e_message_id & 0xFF;
  nonce[2] = option_data->e2e_message_id >> 8;
  write_timestamp(nonce + 3, option_data->tx_timestamp >> PHASE_SHIFTS);
  memcpy(nonce
         + COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN
         - option_data->kid.len,
         option_data->kid.u8,
         option_data->kid.len);

  for (uint_fast8_t i = 0; i < COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN; i++) {
    nonce[i] = nonce[i] ^ common_iv[i];
  }
}

static ssize_t
generate_aad(uint8_t aad[MAX_AAD_LEN],
             const oscore_ng_option_data_t *option_data,
             const uint8_t *class_i_options, size_t class_i_options_len) {
  static const char encrypt0[] = "Encrypt0";
  static const uint8_t encrypt0_len = 8;
  size_t aad_array_space = MAX_AAD_ARRAY_LEN;
  uint8_t aad_array[MAX_AAD_ARRAY_LEN];
  uint8_t *aad_array_ptr = aad_array;
  size_t aad_space = MAX_AAD_LEN;

  if (!cbor_put_array(&aad_array_ptr, &aad_array_space, 5)) {
    return -1;
  }

  /* OSCORE version number */
  if (!cbor_put_unsigned(&aad_array_ptr, &aad_array_space, 2)) {
    return -1;
  }

  /* AEAD Algorithm */
  if (!cbor_put_array(&aad_array_ptr, &aad_array_space, 1)
      || !cbor_put_unsigned(&aad_array_ptr,
                            &aad_array_space,
                            COSE_ALGORITHM_AES_CCM_16_64_128)) {
    return -1;
  }

  /* kid */
  if (!cbor_put_bytes(&aad_array_ptr,
                      &aad_array_space,
                      option_data->kid.u8,
                      option_data->kid.len)) {
    return -1;
  }

  /* timestamps */
  if (option_data->phase == UNSET_PHASE) {
    if (!cbor_put_array(&aad_array_ptr, &aad_array_space, 3)
        ||!cbor_put_unsigned(&aad_array_ptr,
                             &aad_array_space,
                             option_data->corresponding_tx_timestamp)
        || !cbor_put_unsigned(&aad_array_ptr,
                              &aad_array_space,
                              option_data->rx_timestamp)
        || !cbor_put_unsigned(&aad_array_ptr,
                              &aad_array_space,
                              option_data->tx_timestamp)) {
      return -1;
    }
  } else {
    if (!cbor_put_nil(&aad_array_ptr, &aad_array_space)) {
      return -1;
    }
  }

  /* Class I options */
  if (!cbor_put_bytes(&aad_array_ptr,
                      &aad_array_space,
                      class_i_options,
                      class_i_options_len)) {
    return -1;
  }

  if (!cbor_put_array(&aad, &aad_space, 3)
      || !cbor_put_text(&aad, &aad_space, encrypt0, encrypt0_len)
      || !cbor_put_bytes(&aad, &aad_space, NULL, 0)
      || !cbor_put_bytes(&aad,
                         &aad_space,
                         aad_array,
                         aad_array_ptr - aad_array)) {
    return -1;
  }
  return MAX_AAD_LEN - aad_space;
}

void
oscore_ng_encode_option(oscore_ng_option_value_t *option_value,
                        const oscore_ng_option_data_t *option_data,
                        bool is_request) {
  option_value->u8[0] = OSCORE_NG_FLAG;
  option_value->len = 1;

  if (option_data->phase == UNSET_PHASE) {
    option_value->u8[0] |= T_FLAG;

    if (option_data->rx_timestamp) {
      option_value->len++;

      /* write corresponding tx timestamp */
      uint_fast8_t t1l = write_timestamp(
                             option_value->u8 + option_value->len,
                             option_data->corresponding_tx_timestamp);
      option_value->len += t1l;

      /* write rx timestamp */
      uint_fast8_t t2l = write_timestamp(option_value->u8 + option_value->len,
                                         option_data->rx_timestamp);
      option_value->len += t2l;

      /* write flags */
      option_value->u8[0] |= F_FLAG;
      option_value->u8[1] = (option_data->asking_for_resync ? R_FLAG : 0)
                            | (t1l << 3)
                            | t2l;
    }

    /* write tx timestamp */
    uint_fast8_t t3l = write_timestamp(option_value->u8 + option_value->len,
                                       option_data->tx_timestamp
                                       - option_data->rx_timestamp);
    option_value->u8[0] |= t3l;
    option_value->len += t3l;
  } else {
    /* write phase */
    option_value->u8[0] |= option_data->phase & 0xF;
  }

  /* write kid context */
  if (option_data->kid_context.len) {
    option_value->u8[0] |= H_FLAG;
    option_value->u8[option_value->len] = option_data->kid_context.len;
    option_value->len++;
    memcpy(&(option_value->u8[option_value->len]),
           option_data->kid_context.u8,
           option_data->kid_context.len);
    option_value->len += option_data->kid_context.len;
  }

  /* write kid */
  if (is_request) {
    memcpy(&(option_value->u8[option_value->len]),
           option_data->kid.u8,
           option_data->kid.len);
    option_value->len += option_data->kid.len;
  }
}

static void
suppress_phase(oscore_ng_option_data_t *option_data) {
  if (option_data->tx_timestamp & (1 << (PHASE_SHIFTS - 1))) {
    /* round up */
    option_data->tx_timestamp += PHASE_UNIT;
  }
  option_data->phase = (option_data->tx_timestamp >> PHASE_SHIFTS) & 0xF;
}

int
oscore_ng_decode_option(oscore_ng_option_data_t *option_data,
                        uint16_t message_id,
                        const uint8_t *option_value, size_t option_len) {
  if (!option_len) {
    return 0;
  }

  /* read flags */
  uint8_t flags = option_value[0];
  if (!(flags & OSCORE_NG_FLAG)) {
    return 0;
  }
  option_value++;
  option_len--;

  if (flags & T_FLAG) {
    option_data->phase = UNSET_PHASE;
    if (flags & F_FLAG) {
      if (!option_len) {
        return 0;
      }
      option_data->asking_for_resync = (option_value[0] & R_FLAG) != 0;
      uint_fast8_t t1l = (option_value[0] >> 3) & 7;
      uint_fast8_t t2l = option_value[0] & 7;
      option_len--;
      option_value++;

      /* read corresponding tx timestamp */
      if ((option_len < t1l) || (t1l > OSCORE_NG_MAX_TIMESTAMP_BYTES)) {
        return 0;
      }
      option_data->corresponding_tx_timestamp = read_timestamp(option_value,
                                                               t1l);
      option_len -= t1l;
      option_value += t1l;

      /* read rx timestamp */
      if ((option_len < t2l) || (t2l > OSCORE_NG_MAX_TIMESTAMP_BYTES)) {
        return 0;
      }
      option_data->rx_timestamp = read_timestamp(option_value, t2l);
      option_len -= t2l;
      option_value += t2l;
    } else {
      option_data->asking_for_resync = true;
      option_data->corresponding_tx_timestamp = 0;
      option_data->rx_timestamp = 0;
    }

    /* read tx timestamp */
    uint_fast8_t t3l = flags & 7;
    if ((option_len < t3l) || (t3l > OSCORE_NG_MAX_TIMESTAMP_BYTES)) {
      return 0;
    }
    option_data->tx_timestamp = option_data->rx_timestamp
                                + read_timestamp(option_value, t3l);
    option_len -= t3l;
    option_value += t3l;
  } else {
    /* read phase */
    option_data->phase = flags & 0xF;
    option_data->asking_for_resync = false;
    option_data->corresponding_tx_timestamp = 0;
    option_data->rx_timestamp = 0;
    option_data->tx_timestamp = 0;
  }

  /* read end-to-end Message ID */
  if (flags & M_FLAG) {
    if (option_len < OSCORE_NG_E2E_MESSAGE_ID_LEN) {
      return 0;
    }
    option_data->e2e_message_id = option_value[0] | (option_value[1] << 8);
    option_len -= OSCORE_NG_E2E_MESSAGE_ID_LEN;
    option_value += OSCORE_NG_E2E_MESSAGE_ID_LEN;
  } else {
    option_data->e2e_message_id = message_id;
  }

  /* read kid context */
  if (flags & H_FLAG) {
    if (!option_len
        || (option_len - 1 < option_value[0])
        || (option_value[0] > OSCORE_NG_MAX_ID_CONTEXT_LEN)) {
      return 0;
    }
    memcpy(option_data->kid_context.u8, option_value + 1, option_value[0]);
    option_data->kid_context.len = option_value[0];
    option_value += 1 + option_data->kid_context.len;
    option_len -= 1 + option_data->kid_context.len;
  } else {
    option_data->kid_context.len = 0;
  }

  /* read kid */
  if (option_len > OSCORE_NG_MAX_ID_LEN) {
    return 0;
  }
  memcpy(option_data->kid.u8, option_value, option_len);
  option_data->kid.len = option_len;
  return 1;
}

int
oscore_ng_secure(oscore_ng_context_t *context,
                 oscore_ng_option_data_t *option_data,
                 uint16_t message_id,
                 uint8_t *plaintext, uint8_t plaintext_len,
                 bool is_request) {
  /* do B2 business */
  enum b2_msg b2_msg = B2_UNRELATED;
  if (is_request) {
    if (context->b2_stage == OSCORE_NG_B2_RUNNING) {
      if (!context->id_context.len) {
        /* generate ID1 = R1 */
        if (!oscore_ng_csprng(context->id_context.u8, R1_LEN)) {
          return 0;
        }
        context->id_context.len = R1_LEN;
        b2_msg = B2_REQUEST_1;
      } else if (context->id_context.len == R1_LEN) {
        b2_msg = B2_REQUEST_1;
      } else {
        b2_msg = B2_REQUEST_2;
      }
    }
  } else {
    if (last_r1_len) {
      b2_msg = B2_RESPONSE_1;
    }
  }
  if (b2_msg == B2_RESPONSE_1) {
    /* secure with ID2 = R2 || ID1 */
    if (!oscore_ng_csprng(option_data->kid_context.u8, R2_LEN)) {
      return 0;
    }
    cache_r2(option_data->kid_context.u8);
    memcpy(option_data->kid_context.u8 + R2_LEN, last_r1, last_r1_len);
    option_data->kid_context.len = R2_LEN + last_r1_len;
    last_r1_len = 0;
  } else {
    /* use current ID context */
    oscore_ng_copy_id_context(&option_data->kid_context, &context->id_context);
  }

  /* set up kid */
  oscore_ng_copy_id(&option_data->kid,
                    is_request ? context->sender_id : &context->recipient_id);

  /* copy end-to-end Message ID */
  option_data->e2e_message_id = message_id;

  /* set up timestamps or phase */
  option_data->tx_timestamp = oscore_ng_generate_timestamp();
  if (!option_data->tx_timestamp) {
    return 0;
  }
  option_data->asking_for_resync =
      !context->last_synchronization
      || (b2_msg == B2_REQUEST_1)
      || (b2_msg == B2_RESPONSE_1)
      || ((option_data->tx_timestamp - context->last_synchronization)
          > SYNC_INTERVAL);
  if (context->pending_corresponding_tx_timestamp
      || option_data->asking_for_resync) {
    option_data->corresponding_tx_timestamp =
        context->pending_corresponding_tx_timestamp;
    option_data->rx_timestamp = context->pending_rx_timestamp;
    option_data->phase = UNSET_PHASE;
  } else {
    suppress_phase(option_data);
  }

  /* secure */
  {
    uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
    uint8_t sender_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
    uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
    uint8_t aad[MAX_AAD_LEN];
    ssize_t aad_len;

    if (!generate_common_iv(common_iv,
                            context->keying_material,
                            &option_data->kid_context)
        || !generate_key(sender_key,
                         context->keying_material,
                         &option_data->kid_context,
                         context->sender_id)) {
      return 0;
    }
    generate_nonce(nonce, option_data, common_iv);
    aad_len = generate_aad(aad, option_data, NULL, 0);
    if (aad_len < 0) {
      return 0;
    }
    if (!cose_encrypt0_aes_ccm_16_64_128(aad, aad_len,
                                         plaintext, plaintext_len,
                                         sender_key,
                                         nonce,
                                         true)) {
      return 0;
    }
  }

  /* do B2 business */
  switch (b2_msg) {
  case B2_REQUEST_1:
  case B2_REQUEST_2:
    /* convey full kid context */
    break;
  case B2_RESPONSE_1:
    /* truncate kid context */
    option_data->kid_context.len = R2_LEN;
    break;
  case B2_UNRELATED:
  case B2_RESPONSE_2:
  default:
    if (!is_request || !context->has_explicit_id_context) {
      /* suppress kid context */
      option_data->kid_context.len = 0;
    }
    break;
  }

  return 1;
}

enum oscore_ng_unsecure_result_t
oscore_ng_unsecure(oscore_ng_context_t *context,
                   oscore_ng_option_data_t *option_data,
                   uint8_t *ciphertext, uint8_t ciphertext_len,
                   bool is_request) {
  enum oscore_ng_unsecure_result_t result = OSCORE_NG_UNSECURE_RESULT_OK;

  /* check length */
  if (ciphertext_len <= COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN) {
    return OSCORE_NG_UNSECURE_RESULT_ERROR;
  }

  /* do B2 business */
  enum b2_msg b2_msg = B2_UNRELATED;
  ssize_t i = 0;
  if (option_data->kid_context.len) {
    if (is_request) {
      if (!oscore_ng_are_id_contexts_equal(&option_data->kid_context,
                                           &context->id_context)) {
        if (option_data->kid_context.len <= R2_LEN) {
          if (option_data->kid_context.len > OSCORE_NG_MAX_R1_LEN) {
            return OSCORE_NG_UNSECURE_RESULT_ERROR;
          }
          b2_msg = B2_REQUEST_1;
        } else {
          b2_msg = B2_REQUEST_2;
          /* validate R2 of ID3 = R2 || R3 */
          i = get_index_of_r2(option_data->kid_context.u8);
          if (i < 0) {
            return OSCORE_NG_UNSECURE_RESULT_ERROR;
          }
        }
      }
    } else {
      b2_msg = B2_RESPONSE_1;
      if ((option_data->kid_context.len + R1_LEN)
          > OSCORE_NG_MAX_ID_CONTEXT_LEN) {
        /* cannot append R1 */
        return OSCORE_NG_UNSECURE_RESULT_ERROR;
      }
      /* generate ID2 = R2 || R1 */
      memcpy(option_data->kid_context.u8 + option_data->kid_context.len,
             context->id_context.u8,
             R1_LEN);
      option_data->kid_context.len += R1_LEN;
    }
  } else {
    if (!is_request && (context->b2_stage == OSCORE_NG_B2_RUNNING)) {
      b2_msg = B2_RESPONSE_2;
    }
    /* use established ID Context */
    oscore_ng_copy_id_context(&option_data->kid_context, &context->id_context);
  }

  /* set up kid */
  oscore_ng_copy_id(&option_data->kid,
                    is_request ? &context->recipient_id : context->sender_id);

  /* create timestamp */
  uint64_t now = oscore_ng_generate_timestamp();
  if (!now) {
    return OSCORE_NG_UNSECURE_RESULT_ERROR;
  }

  /* restore tx timestamp if suppressed and is resync is initiated */
  {
    bool initiates_resync = ((option_data->phase == UNSET_PHASE)
                             && context->last_synchronization
                             && !option_data->rx_timestamp);
    uint_fast32_t low_bits;

    if (initiates_resync) {
      /* suppress phase like on the sender side to achieve strong freshness */
      low_bits = option_data->tx_timestamp & (PHASE_UNIT - 1);
      suppress_phase(option_data);
    } else {
      low_bits = 0;
    }
    if (option_data->phase != UNSET_PHASE) {
      if (!context->last_synchronization) {
        return OSCORE_NG_UNSECURE_RESULT_ERROR;
      }
      int64_t t = (now
                   + context->delta
                   - (option_data->phase << PHASE_SHIFTS));
      if (t & (1 << (TIMESLOT_SHIFTS - 1))) {
        /* round up */
        t += TIMESLOT;
      }
      option_data->tx_timestamp = (t & ~PHASE_MASK)
                                  | (option_data->phase << PHASE_SHIFTS);
      if (initiates_resync) {
        /* rollback of high precision bits and phase value */
        option_data->tx_timestamp |= low_bits;
        option_data->phase = UNSET_PHASE;
      }
    }
  }

  /* perform SPS check */
  int64_t delta;
  if ((option_data->phase == UNSET_PHASE)
      && option_data->rx_timestamp) {
    int64_t t2_minus_t1 = option_data->rx_timestamp
                          - option_data->corresponding_tx_timestamp;
    int64_t t4_minus_t3 = now - option_data->tx_timestamp;
    if (((t2_minus_t1 + t4_minus_t3) / 2) > OSCORE_NG_ACK_TIMEOUT) {
      /* outdated SPS option -> release anti-replay data */
      return OSCORE_NG_UNSECURE_RESULT_ERROR;
    }
    delta = (t2_minus_t1 - t4_minus_t3) / 2;
  } else {
    delta = UNSET_DELTA;
  }

  /* unsecure */
  {
    uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
    uint8_t recipient_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
    uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
    uint8_t aad[MAX_AAD_LEN];
    ssize_t aad_len;

    if (!generate_common_iv(common_iv,
                            context->keying_material,
                            &option_data->kid_context)
        || !generate_key(recipient_key,
                         context->keying_material,
                         &option_data->kid_context,
                         &context->recipient_id)) {
      return OSCORE_NG_UNSECURE_RESULT_ERROR;
    }
    generate_nonce(nonce, option_data, common_iv);
    aad_len = generate_aad(aad, option_data, NULL, 0);
    if (aad_len < 0) {
      return OSCORE_NG_UNSECURE_RESULT_ERROR;
    }
    if (!cose_encrypt0_aes_ccm_16_64_128(aad, aad_len,
                                         ciphertext, ciphertext_len,
                                         recipient_key,
                                         nonce,
                                         false)) {
      return OSCORE_NG_UNSECURE_RESULT_ERROR;
    }
  }

  /* anti-replay */
  {
    const uint16_t validity_periods[] = {
      OSCORE_NG_FRESHNESS_THRESHOLD
      + OSCORE_NG_MAX_TRANSMIT_SPAN,
      OSCORE_NG_FRESHNESS_THRESHOLD
      + OSCORE_NG_FRESHNESS_THRESHOLD
      + OSCORE_NG_PROCESSING_DELAY,
    };
    oscore_ng_anti_replay_t *anti_replay;
    oscore_ng_anti_replay_t *next_anti_replay;

    anti_replay = list_head(context->anti_replay_list);
    while (anti_replay) {
      next_anti_replay = list_item_next(anti_replay);
      if (((uint16_t)now - anti_replay->rx_timestamp)
          > validity_periods[anti_replay->was_request]) {
        /* outdated */
        list_remove(context->anti_replay_list, anti_replay);
        oscore_ng_free_anti_replay(anti_replay);
      } else if ((anti_replay->was_request == is_request)
                 && (anti_replay->e2e_message_id
                     == option_data->e2e_message_id)) {
        if (anti_replay->restored_tx_timestamp
            == (uint16_t)option_data->tx_timestamp) {
          /* replayed */
          return OSCORE_NG_UNSECURE_RESULT_ERROR;
        }
        /* duplicate */
        result = OSCORE_NG_UNSECURE_RESULT_DUPLICATE;
      }
      anti_replay = next_anti_replay;
    }
  }
  oscore_ng_anti_replay_t *new_anti_replay = oscore_ng_alloc_anti_replay();
  if (!new_anti_replay) {
    return OSCORE_NG_UNSECURE_RESULT_ERROR;
  }

  /* do B2 business */
  last_r1_len = 0;
  switch (b2_msg) {
  case B2_REQUEST_1:
    memcpy(last_r1, option_data->kid_context.u8, option_data->kid_context.len);
    last_r1_len = option_data->kid_context.len;
    result = OSCORE_NG_UNSECURE_RESULT_B2_REQUEST_1;
    break;
  case B2_RESPONSE_1:
    /* generate ID3 = R2 || R3 */
    if (!oscore_ng_csprng(option_data->kid_context.u8
                          + option_data->kid_context.len - R1_LEN,
                          R3_LEN)) {
      goto error;
    }
    option_data->kid_context.len -= R1_LEN;
    option_data->kid_context.len += R3_LEN;
    /* store new ID context */
    oscore_ng_copy_id_context(&context->id_context,
                              &option_data->kid_context);
    break;
  case B2_REQUEST_2:
    /* remove R2 */
    if (!oscore_ng_csprng(r2s[i], R2_LEN)) {
      goto error;
    }
    /* store ID3 = R2 || R3 */
    oscore_ng_copy_id_context(&context->id_context,
                              &option_data->kid_context);
    break;
  case B2_RESPONSE_2:
    context->b2_stage = OSCORE_NG_B2_DONE;
    break;
  case B2_UNRELATED:
  default:
    break;
  }

  /* nothing can go wrong from here -> update context */
  new_anti_replay->e2e_message_id = option_data->e2e_message_id;
  new_anti_replay->restored_tx_timestamp = option_data->tx_timestamp;
  new_anti_replay->rx_timestamp = now;
  new_anti_replay->was_request = is_request;
  list_add(context->anti_replay_list, new_anti_replay);

  /* finish SPS business */
  if (delta != UNSET_DELTA) {
    context->delta = delta;
    context->last_synchronization = now;
  }
  if (option_data->asking_for_resync) {
    /* cache timestamps */
    context->pending_corresponding_tx_timestamp = option_data->tx_timestamp;
    context->pending_rx_timestamp = now;
  } else {
    context->pending_corresponding_tx_timestamp = 0;
    context->pending_rx_timestamp = 0;
  }

  return result;
error:
  /* rollback of anti-replay allocation */
  oscore_ng_free_anti_replay(new_anti_replay);
  return OSCORE_NG_UNSECURE_RESULT_ERROR;
}

void
oscore_ng_start_b2(oscore_ng_context_t *context) {
  context->id_context.len = 0;
  context->b2_stage = OSCORE_NG_B2_RUNNING;
}

void
oscore_ng_set_id_context(oscore_ng_context_t *context,
                         const oscore_ng_id_context_t *id_context,
                         bool is_explicit_id_context) {
  oscore_ng_copy_id_context(&context->id_context, id_context);
  context->has_explicit_id_context = is_explicit_id_context;
}

int
oscore_ng_self_test(void) {
  const oscore_ng_id_t max_id = {
    { 0 },
    OSCORE_NG_MAX_ID_LEN
  };
  const oscore_ng_id_context_t max_id_context = {
    { 0 },
    OSCORE_NG_MAX_ID_CONTEXT_LEN
  };
  const oscore_ng_option_data_t option_data = {
    { { 0 }, OSCORE_NG_MAX_ID_LEN },
    { { 0 }, OSCORE_NG_MAX_ID_CONTEXT_LEN },
    UINT64_MAX,
    UINT64_MAX,
    UINT64_MAX,
    UINT16_MAX,
    UNSET_PHASE,
    false
  };
  uint8_t info[MAX_INFO_LEN];
  uint8_t aad[MAX_AAD_LEN];

  return (generate_info(info, &max_id, &max_id_context, false) == MAX_INFO_LEN)
         && (generate_aad(aad, &option_data, NULL, 0) == MAX_AAD_LEN)
         && oscore_ng_generate_timestamp();
}
