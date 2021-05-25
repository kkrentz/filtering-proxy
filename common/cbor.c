/*
 * Copyright (c) 2018, SICS, RISE AB
 * Copyright (c) 2023, Uppsala universitet
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
 *
 */

#include "cbor.h"

#include <string.h>

int
cbor_put_nil(uint8_t **buffer, size_t *buffer_len) {
  if (!*buffer_len) {
    return 0;
  }
  **buffer = 0xF6;
  (*buffer)++;
  *buffer_len -= 1;
  return 1;
}

int
cbor_put_text(uint8_t **buffer, size_t *buffer_len,
              const char *text, uint64_t text_len) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, text_len)) {
    return 0;
  }
  *pt = (*pt | 0x60);
  if (*buffer_len < text_len) {
    return 0;
  }
  memcpy(*buffer, text, text_len);
  (*buffer) += text_len;
  *buffer_len -= text_len;
  return 1;
}

int
cbor_put_array(uint8_t **buffer, size_t *buffer_len, uint64_t elements) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, elements)) {
    return 0;
  }
  *pt = (*pt | 0x80);
  return 1;
}

int
cbor_put_bytes(uint8_t **buffer, size_t *buffer_len,
               const uint8_t *bytes, uint64_t bytes_len) {
  uint8_t *pt = *buffer;
  if (!cbor_put_unsigned(buffer, buffer_len, bytes_len)) {
    return 0;
  }
  *pt = (*pt | 0x40);
  if (*buffer_len < bytes_len) {
    return 0;
  }
  memcpy(*buffer, bytes, bytes_len);
  (*buffer) += bytes_len;
  *buffer_len -= bytes_len;
  return 1;
}

static void
put_b_f(uint8_t **buffer, uint64_t value, uint8_t nr) {
  uint8_t *pt = *buffer-1;
  uint64_t vv = value;
  for (int q = nr; q > -1; q--) {
    (*pt--) = (uint8_t)(vv & 0xff);
    vv = (vv >>8);
  }
}

int
cbor_put_unsigned(uint8_t **buffer, size_t *buffer_len, uint64_t value) {
  if (value < 0x18) {
    /* small value half a byte */
    if (*buffer_len < 1) {
      return 0;
    }
    (**buffer) = (uint8_t)value;
    (*buffer)++;
    *buffer_len -= 1;
    return 1;
  } else if ((value > 0x17) && (value < 0x100)) {
    /* one byte uint8_t */
    if (*buffer_len < 2) {
      return 0;
    }
    (**buffer) = (0x18);
    *buffer = (*buffer) + 2;
    *buffer_len -= 2;
    put_b_f(buffer, value, 0);
    return 1;
  } else if ((value > 0xff) && (value < 0x10000)) {
    /* 2 bytes uint16_t*/
    if (*buffer_len < 3) {
      return 0;
    }
    (**buffer) = (0x19);
    *buffer = (*buffer) + 3;
    *buffer_len -= 3;
    put_b_f(buffer, value, 1);
    return 1;
  } else if ((value > 0xffff) && (value < 0x100000000)) {
    /* 4 bytes uint32_t */
    if (*buffer_len < 5) {
      return 0;
    }
    (**buffer) = (0x1a);
    *buffer = (*buffer) + 5;
    *buffer_len -= 5;
    put_b_f(buffer, value, 3);
    return 1;
  } else {
    /* 8 bytes uint64_t */
    if (*buffer_len < 9) {
      return 0;
    }
    (**buffer) = (0x1b);
    *buffer = (*buffer) + 9;
    *buffer_len -= 9;
    put_b_f(buffer, value, 7);
    return 1;
  }
}
