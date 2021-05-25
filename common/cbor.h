/*
 * Copyright (c) 2018, SICS, RISE AB
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

/**
 * \file
 *      An implementation of the Concise Binary Object Representation (RFC).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for libcoap by:
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 *
 */


#ifndef _CBOR_H
#define _CBOR_H

#include <stdint.h>

// CBOR major types
#define CBOR_UNSIGNED_INTEGER 0
#define CBOR_NEGATIVE_INTEGER 1
#define CBOR_BYTE_STRING      2
#define CBOR_TEXT_STRING      3
#define CBOR_ARRAY            4
#define CBOR_MAP              5
#define CBOR_TAG              6
 

int cbor_put_nil(uint8_t **buffer);

int cbor_put_text(uint8_t **buffer, const char *text, uint64_t text_len);

int cbor_put_array(uint8_t **buffer, uint64_t elements);

int cbor_put_bytes(uint8_t **buffer, const uint8_t *bytes, uint64_t bytes_len);

int cbor_put_map(uint8_t **buffer, uint64_t elements);

int cbor_put_number(uint8_t **buffer, int64_t value);

int cbor_put_unsigned(uint8_t **buffer, uint64_t value);

int cbor_put_negative(uint8_t **buffer, int64_t value);

uint8_t cbor_get_next_element(uint8_t **buffer);

uint64_t cbor_get_element_size(uint8_t **buffer);

int64_t 
cbor_get_negative_integer(uint8_t **buffer);

uint64_t 
cbor_get_unsigned_integer(uint8_t **buffer);

void
cbor_get_string(uint8_t **buffer, char *str, uint64_t size);

void
cbor_get_array(uint8_t **buffer, uint8_t *arr, uint64_t size);

#endif /* _cbor_H */
