/*
 * Copyright (c) 2023, Uppsala universitet.
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

#include "coap.h"

#include <string.h>

#include "log.h"

typedef struct coap_option_t {
  uint_fast8_t header_len;
  uint_fast32_t delta;
  uint_fast32_t value_len;
} coap_option_t;

static int parse_option_header(uint8_t *p, size_t len, coap_option_t *option);

int
coap_parse(coap_message_t *msg, uint8_t *plaintext, size_t plaintext_len) {
  memset(msg, 0, sizeof(*msg));

  /* skip over code */
  if (!plaintext_len--) {
    return 0;
  }
  plaintext++;

  uint_fast32_t option_number = 0;
  while (plaintext_len && (*plaintext != COAP_PAYLOAD_START)) {
    coap_option_t option;
    if (!parse_option_header(plaintext, plaintext_len, &option)) {
      LOG_MESSAGE("parse_header failed\n");
      return 0;
    }
    option_number += option.delta;

    if (option_number == COAP_OPTION_URI_PATH) {
      if (option.value_len > 255) {
        return 0;
      }
      msg->uri_path = plaintext + option.header_len;
      msg->uri_path_len = option.value_len;
    }

    plaintext += option.value_len + option.header_len;
    plaintext_len -= option.value_len + option.header_len;
  }
  if (!plaintext_len) {
    return 1;
  }
  if (*plaintext != COAP_PAYLOAD_START) {
    return 0;
  }
  if (!plaintext_len--) {
    return 1;
  }
  plaintext++;
  msg->payload = plaintext;
  msg->payload_len = plaintext_len;
  return 1;
}

static int
parse_option_header(uint8_t *p, size_t len, coap_option_t *option) {
  if (!len--) {
    return 0;
  }

  /* Option Delta || Option Length */
  option->header_len = 1;
  option->delta = *p >> 4;
  option->value_len = *p & 0xF;

  /* Option Delta (extended) */
  switch (option->delta) {
  case 15:
    return 0;
  case 14:
    if (!len--) {
      return 0;
    }
    option->delta = p[option->header_len++];
    option->delta <<= 8;
    option->delta += 269;
  /* fall through */
  case 13:
    if (!len--) {
      return 0;
    }
    option->delta += p[option->header_len++];
    break;
  }

  /* Option Length (extended) */
  switch (option->value_len) {
  case 15:
    return 0;
  case 14:
    if (!len--) {
      return 0;
    }
    option->value_len = p[option->header_len++];
    option->value_len <<= 8;
    option->value_len += 269;
  /* fall through */
  case 13:
    if (!len--) {
      return 0;
    }
    option->value_len += p[option->header_len++];
    break;
  }
  if (len < option->value_len) {
    return 0;
  }
  return 1;
}
