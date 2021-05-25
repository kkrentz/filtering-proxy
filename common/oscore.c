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

#include "oscore.h"

#include <string.h>

#include "cbor.h"
#include "cose.h"
#ifdef WITH_CONTIKI
#include "lib/sha-256.h"
#else /* WITH_CONTIKI */
#include "sha-256.h"
#endif /* WITH_CONTIKI */

#define MAX_INFO_LEN (OSCORE_MAX_ID_CONTEXT_LEN \
    + OSCORE_MAX_PARTIAL_IV_LEN \
    + 9 /* TODO compute precisely */)
#define INITIAL_SEQUENCE_NUMBER (0xFFFFFFFFFFFFFFFF)

static void
init_option_data(oscore_option_data_t *oscore_option_data)
{
  memset(oscore_option_data, 0, sizeof(oscore_option_data_t));
}

static int
set_sequence_number(oscore_option_data_t *oscore_option_data,
    uint64_t sequence_number)
{
  uint_fast8_t i;

  if (sequence_number > OSCORE_MAX_SEQUENCE_NUMBER) {
    return 0;
  }

  oscore_option_data->partial_iv_len = 1;
  for (i = 0; i < OSCORE_MAX_PARTIAL_IV_LEN; i++) {
    oscore_option_data->partial_iv[i] = sequence_number & 0xFF;
    sequence_number >>= 8;
    if (oscore_option_data->partial_iv[i]) {
      oscore_option_data->partial_iv_len = i + 1;
    }
  }

  return 1;
}

uint64_t
oscore_option_data_get_sequence_number(
    const oscore_option_data_t *oscore_option_data)
{
  int_fast8_t i;
  uint64_t sequence_number;

  sequence_number = 0;
  for (i = oscore_option_data->partial_iv_len - 1; i >= 0; i--) {
    sequence_number <<= 8;
    sequence_number += oscore_option_data->partial_iv[i];
  }
  return sequence_number;
}

static void
set_kid(oscore_option_data_t *oscore_option_data,
    const uint8_t *kid, uint8_t kid_len)
{
  memcpy(oscore_option_data->kid, kid, kid_len);
  oscore_option_data->kid_len = kid_len;
}

static void
set_kid_context(oscore_option_data_t *oscore_option_data,
    const uint8_t *kid_context, uint8_t kid_context_len)
{
  memcpy(oscore_option_data->kid_context, kid_context, kid_context_len);
  oscore_option_data->kid_context_len = kid_context_len;
}

void
oscore_init_keying_material(oscore_keying_material_t *keying_material,
    const uint8_t master_secret[AES_128_KEY_LENGTH],
    const uint8_t *master_salt, uint8_t master_salt_len,
    const uint8_t *id_context, uint8_t id_context_len)
{
  uint8_t *p;

  p = keying_material->keying_material;
  memcpy(p, master_secret, AES_128_KEY_LENGTH);
  p += AES_128_KEY_LENGTH;
  memcpy(p, master_salt, master_salt_len);
  keying_material->master_salt_len = master_salt_len;
  p += keying_material->master_salt_len;
  memcpy(p, id_context, id_context_len);
  keying_material->id_context_len = id_context_len;
}

static const uint8_t *
get_master_secret(const oscore_keying_material_t *keying_material)
{
  return keying_material->keying_material;
}

static const uint8_t *
get_master_salt(const oscore_keying_material_t *keying_material)
{
  return keying_material->master_salt_len
      ? keying_material->keying_material + AES_128_KEY_LENGTH
      : NULL;
}

static const uint8_t *
get_id_context(const oscore_keying_material_t *keying_material)
{
  return keying_material->id_context_len
      ? keying_material->keying_material
          + AES_128_KEY_LENGTH
          + keying_material->master_salt_len
      : NULL;
}

int
oscore_init_context(oscore_context_t *context,
    const uint8_t *recipient_id, uint8_t recipient_id_len,
    const uint8_t *sender_id, uint8_t sender_id_len,
    const oscore_keying_material_t *keying_material)
{
  if ((recipient_id_len > OSCORE_MAX_ID_LEN)
      || (sender_id_len > OSCORE_MAX_ID_LEN)) {
    return 0;
  }

  context->keying_material = keying_material;
  memcpy(context->recipient_id, recipient_id, recipient_id_len);
  context->recipient_id_len = recipient_id_len;
  memcpy(context->sender_id, sender_id, sender_id_len);
  context->sender_id_len = sender_id_len;
  context->senders_sequence_number = INITIAL_SEQUENCE_NUMBER;
  oscore_init_anti_replay_data(&context->anti_replay);
  return 1;
}

void
oscore_init_anti_replay_data(oscore_anti_replay_t *anti_replay)
{
  anti_replay->last_sequence_number = INITIAL_SEQUENCE_NUMBER;
}

static uint8_t
compose_info(uint8_t info[MAX_INFO_LEN],
    const uint8_t *id, uint8_t id_len,
    const uint8_t *id_context, uint8_t id_context_len,
    int is_iv)
{
  static const char key[] = "Key";
  static const char iv[] = "IV";
  const char *text;
  uint8_t text_len;
  uint8_t info_len;

  info_len = 0;
  info_len += cbor_put_array(&info, 5);
  info_len += cbor_put_bytes(&info, id, id_len);
  if (id_context && id_context_len) {
    info_len += cbor_put_bytes(&info, id_context, id_context_len);
  } else {
    info_len += cbor_put_nil(&info);
  }
  info_len += cbor_put_unsigned(&info, COSE_ALGORITHM_AES_CCM_16_64_128);
  if(is_iv) {
    text = iv;
    text_len = 2;
  } else {
    text = key;
    text_len = 3;
  }
  info_len += cbor_put_text(&info, text, text_len);
  info_len += cbor_put_unsigned(&info, is_iv
      ? COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN
      : COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN);
  return info_len;
}

static void
generate_common_iv(
    uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN],
    const oscore_keying_material_t *keying_material)
{
  uint8_t info[MAX_INFO_LEN];
  uint8_t info_len;

  info_len = compose_info(info,
      NULL, 0,
      get_id_context(keying_material), keying_material->id_context_len,
      1);
  sha_256_hkdf(get_master_salt(keying_material),
      keying_material->master_salt_len,
      get_master_secret(keying_material),
      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN,
      info,
      info_len,
      common_iv, COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN);
}

static void
generate_sender_key(
    uint8_t sender_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t *sender_id, uint8_t sender_id_len,
    const oscore_keying_material_t *keying_material)
{
  uint8_t info[MAX_INFO_LEN];
  uint8_t info_len;

  info_len = compose_info(info,
      sender_id, sender_id_len,
      get_id_context(keying_material), keying_material->id_context_len,
      0);
  sha_256_hkdf(get_master_salt(keying_material),
      keying_material->master_salt_len,
      get_master_secret(keying_material),
      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN,
      info,
      info_len,
      sender_key,
      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN);
}

static void
generate_recipient_key(
    uint8_t recipient_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t *recipient_id, uint8_t recipient_id_len,
    const oscore_keying_material_t *keying_material)
{
  uint8_t info[MAX_INFO_LEN];
  uint8_t info_len;

  info_len = compose_info(info,
      recipient_id, recipient_id_len,
      get_id_context(keying_material), keying_material->id_context_len,
      0);
  sha_256_hkdf(get_master_salt(keying_material),
      keying_material->master_salt_len,
      get_master_secret(keying_material),
      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN,
      info,
      info_len,
      recipient_key,
      COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN);
}

/* size of ID_PIV || pad || Sender ID (ID_PIV) || pad || partial IV (PIV) */
static void
generate_nonce(uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN],
    const oscore_option_data_t *oscore_option_data,
    const uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN])
{
  uint8_t i;

  memset(nonce, 0, COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN);
  nonce[0] = oscore_option_data->kid_len;
  memcpy(nonce
         + COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN
         - OSCORE_MAX_PARTIAL_IV_LEN
         - oscore_option_data->kid_len,
      oscore_option_data->kid,
      oscore_option_data->kid_len);
  memcpy(nonce
         + COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN
         - oscore_option_data->partial_iv_len,
      oscore_option_data->partial_iv,
      oscore_option_data->partial_iv_len);

  for (i = 0; i < COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN; i++) {
    nonce[i] = nonce[i] ^ common_iv[i];
  }
}

static void
generate_aad(uint8_t aad[OSCORE_MAX_AAD_LEN], size_t *aad_len,
    const oscore_option_data_t *oscore_option_data,
    const uint8_t *class_i_options, size_t class_i_options_len)
{
  static const char encrypt0[] = "Encrypt0";
  static const uint8_t encrypt0_len = 8;
  uint8_t aad_array[OSCORE_MAX_AAD_LEN];
  uint8_t *aad_array_ptr;
  size_t aad_array_len;

  aad_array_ptr = aad_array;
  aad_array_len = 0;
  aad_array_len += cbor_put_array(&aad_array_ptr,
      5 + (class_i_options_len && class_i_options ? 1 : 0));
  aad_array_len += cbor_put_unsigned(&aad_array_ptr, 1);
  aad_array_len += cbor_put_array(&aad_array_ptr, 1);
  aad_array_len += cbor_put_number(&aad_array_ptr,
      COSE_ALGORITHM_AES_CCM_16_64_128);
  aad_array_len += cbor_put_bytes(&aad_array_ptr,
      oscore_option_data->kid, oscore_option_data->kid_len);
  aad_array_len += cbor_put_bytes(&aad_array_ptr,
      oscore_option_data->partial_iv, oscore_option_data->partial_iv_len);
  aad_array_len += cbor_put_bytes(&aad_array_ptr, NULL, 0);
  if (class_i_options && class_i_options_len) {
    aad_array_len += cbor_put_bytes(&aad_array_ptr,
        class_i_options, class_i_options_len);
  }

  *aad_len = 0;
  *aad_len += cbor_put_array(&aad, 3);
  *aad_len += cbor_put_text(&aad, encrypt0, encrypt0_len);
  *aad_len += cbor_put_bytes(&aad, NULL, 0);
  *aad_len += cbor_put_bytes(&aad, aad_array, aad_array_len);

  /* TODO ensure that aad_len does not get larger than the buffer */
}

void
oscore_option_encode(
    uint8_t option_value[OSCORE_OPTION_MAX_VALUE_LENGTH],
    size_t *option_length,
    const oscore_option_data_t *oscore_option_data,
    int is_request)
{
  option_value[0] = 0;
  *option_length = 1;
  if (is_request
      && oscore_option_data->partial_iv_len
      && oscore_option_data->partial_iv) {
    option_value[0] |= oscore_option_data->partial_iv_len;
    memcpy(&(option_value[*option_length]),
        oscore_option_data->partial_iv,
        oscore_option_data->partial_iv_len);
    *option_length += oscore_option_data->partial_iv_len;
  }
  if (is_request
      && oscore_option_data->kid_context_len
      && oscore_option_data->kid_context) {
    option_value[0] |= 0x10;
    option_value[*option_length] = oscore_option_data->kid_context_len;
    *option_length += 1;
    memcpy(&(option_value[*option_length]),
        oscore_option_data->kid_context,
        oscore_option_data->kid_context_len);
    *option_length += oscore_option_data->kid_context_len;
  }
  if (is_request
      && oscore_option_data->kid_len
      && oscore_option_data->kid) {
    option_value[0] |= 0x08;
    memcpy(&(option_value[*option_length]),
        oscore_option_data->kid,
        oscore_option_data->kid_len);
    *option_length += oscore_option_data->kid_len;
  }
  if (*option_length == 1 && option_value[0] == 0) {
    /* If option_value is 0x00 it should be empty. */
    *option_length = 0;
  }
}

/**
 * Decodes OSCORE option and stores results in the given structure
 * @return 0 <=> error
 */
int
oscore_option_decode(oscore_option_data_t *oscore_option_data,
    const uint8_t *option_value, size_t option_length)
{
  uint8_t oscore_flags;

  init_option_data(oscore_option_data);

  /* read flags */
  if (!option_length) {
    return 1;
  }
  oscore_flags = option_value[0];
  if (oscore_flags & OSCORE_OPTION_RESERVED_FLAGS) {
    return 0;
  }
  oscore_option_data->partial_iv_len
      = (oscore_flags & OSCORE_OPTION_PARTIAL_IV_MASK);
  if (oscore_option_data->partial_iv_len > OSCORE_MAX_PARTIAL_IV_LEN) {
    return 0;
  }
  option_value++;
  option_length--;
  if (option_length < oscore_option_data->partial_iv_len) {
    return 0;
  }

  /* read partial IV */
  memcpy(oscore_option_data->partial_iv,
      option_value,
      oscore_option_data->partial_iv_len);
  option_value += oscore_option_data->partial_iv_len;
  option_length -= oscore_option_data->partial_iv_len;

  /* read KID context */
  if (oscore_flags & OSCORE_OPTION_KID_CONTEXT_FLAG) {
    if (!option_length
        || (option_length - 1 < option_value[0])
        || (option_value[0] > OSCORE_MAX_ID_CONTEXT_LEN)) {
      return 0;
    }
    set_kid_context(oscore_option_data,
        option_value + 1, option_value[0]);
    option_value += 1 + oscore_option_data->kid_context_len;
    option_length -= 1 + oscore_option_data->kid_context_len;
  }

  /* read sender ID */
  if (oscore_flags & OSCORE_OPTION_KID_FLAG) {
    if (!option_length || (option_length > OSCORE_MAX_ID_LEN)) {
      return 0;
    }
    set_kid(oscore_option_data,
        option_value, option_length);
  } else if (option_length) {
    return 0;
  }
  return 1;
}

int
oscore_is_authentic(oscore_context_t *context,
    uint64_t sequence_number, bool is_senders_sequence_number,
    uint8_t *ciphertext, uint8_t ciphertext_len)
{
  oscore_option_data_t oscore_option_data;
  uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
  uint8_t recipient_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
  uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
  uint8_t aad[OSCORE_MAX_AAD_LEN];
  size_t aad_len;
  int decryption_result;

  init_option_data(&oscore_option_data);
  if (!set_sequence_number(&oscore_option_data, sequence_number)) {
    return 0;
  }
  if (is_senders_sequence_number) {
    set_kid(&oscore_option_data,
        context->sender_id, context->sender_id_len);
  } else {
    set_kid(&oscore_option_data,
        context->recipient_id, context->recipient_id_len);
  }
  set_kid_context(&oscore_option_data,
      get_id_context(context->keying_material),
      context->keying_material->id_context_len);

  if (ciphertext_len < COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN) {
    return 0;
  }

  generate_common_iv(common_iv, context->keying_material);
  generate_recipient_key(recipient_key,
      context->recipient_id, context->recipient_id_len,
      context->keying_material);

  generate_nonce(nonce,
      &oscore_option_data,
      common_iv);
  generate_aad(aad, &aad_len,
      &oscore_option_data,
      NULL /* TODO include Class I options */, 0);
  decryption_result = cose_encrypt0_decrypt(aad, aad_len,
      ciphertext, ciphertext_len,
      recipient_key,
      nonce);
  if (decryption_result < 0) {
    return 0;
  }
  return 1;
}

int
oscore_is_fresh(oscore_anti_replay_t *anti_replay, uint64_t sequence_number)
{
  int shift;
  uint32_t pattern;

  if (sequence_number > OSCORE_MAX_SEQUENCE_NUMBER) {
    return 0;
  }

  if (anti_replay->last_sequence_number == INITIAL_SEQUENCE_NUMBER) {
    anti_replay->last_sequence_number = sequence_number;
    anti_replay->sliding_window = 1;
  } else if (sequence_number > anti_replay->last_sequence_number) {
    shift = sequence_number - anti_replay->last_sequence_number;
    anti_replay->sliding_window <<= shift;
    anti_replay->sliding_window |= 1;
    anti_replay->last_sequence_number = sequence_number;
  } else if (sequence_number == anti_replay->last_sequence_number) {
    return 0;
  } else { /* sequence_number < last_sequence_number */
    if ((sequence_number + OSCORE_DEFAULT_REPLAY_WINDOW)
        < anti_replay->last_sequence_number) {
      return 0;
    }
    shift = anti_replay->last_sequence_number - sequence_number;
    pattern = 1 << shift;
    if (anti_replay->sliding_window & pattern) {
      return 0;
    }
    anti_replay->sliding_window |= pattern;
  }
  return 1;
}

int
oscore_secure(oscore_context_t *context,
    oscore_option_data_t *oscore_option_data,
    uint8_t *plaintext, uint8_t plaintext_len,
    uint64_t sequence_number, bool is_senders_sequence_number)
{
  uint8_t common_iv[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
  uint8_t sender_key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN];
  uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN];
  uint8_t aad[OSCORE_MAX_AAD_LEN];
  size_t aad_len;
  int encryption_result;

  init_option_data(oscore_option_data);
  if (!set_sequence_number(oscore_option_data, sequence_number)) {
    return 0;
  }
  if (is_senders_sequence_number) {
    set_kid(oscore_option_data,
        context->sender_id, context->sender_id_len);
  } else {
    set_kid(oscore_option_data,
        context->recipient_id, context->recipient_id_len);
  }
  set_kid_context(oscore_option_data,
      get_id_context(context->keying_material),
      context->keying_material->id_context_len);

  generate_common_iv(common_iv, context->keying_material);
  generate_sender_key(sender_key,
      context->sender_id, context->sender_id_len,
      context->keying_material);

  generate_nonce(nonce,
      oscore_option_data,
      common_iv);
  generate_aad(aad, &aad_len,
      oscore_option_data,
      NULL /* TODO include Class I options */, 0);
  encryption_result = cose_encrypt0_encrypt(aad, aad_len,
      plaintext, plaintext_len,
      sender_key,
      nonce);
  return encryption_result >= 0;
}
