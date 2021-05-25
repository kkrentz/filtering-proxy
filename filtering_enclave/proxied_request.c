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

#include "proxied_request.h"

#include "app/malloc.h"
#include "list.h"

proxied_request_t *
proxied_request_store(registration_t *registration,
    void *proxied_request,
    uint64_t original_sequence_number,
    uint64_t new_sequence_number)
{
  proxied_request_t *entry;

  /* ensure uniqueness */
  proxied_request_remove(registration, proxied_request);

  /* allocate memory */
  entry = malloc(sizeof(*entry));
  if (!entry) {
    return NULL;
  }

  /* initialize */
  entry->proxied_request = proxied_request;
  entry->original_sequence_number = original_sequence_number;
  entry->new_sequence_number = new_sequence_number;

  /* add to list */
  list_add(registration->proxied_request_list, entry);
  return entry;
}

int
proxied_request_get_sequence_numbers(registration_t *registration,
    void *proxied_request,
    uint64_t *original_sequence_number,
    uint64_t *new_sequence_number)
{
  proxied_request_t *entry;

  entry = list_head(registration->proxied_request_list);
  while (entry) {
    if (entry->proxied_request == proxied_request) {
      *original_sequence_number = entry->original_sequence_number;
      *new_sequence_number = entry->new_sequence_number;
      return 1;
    }
    entry = list_item_next(entry);
  }
  return 0;
}

void
proxied_request_remove(registration_t *registration,
    void *proxied_request)
{
  proxied_request_t *entry;

  entry = list_head(registration->proxied_request_list);
  while (entry) {
    if (entry->proxied_request == proxied_request) {
      list_remove(registration->proxied_request_list, entry);
      free(entry);
      return;
    }
    entry = list_item_next(entry);
  }
}

void
proxied_request_clear(registration_t *registration)
{
  proxied_request_t *entry;

  while ((entry = list_head(registration->proxied_request_list))) {
    list_remove(registration->proxied_request_list, entry);
    free(entry);
  }
}

proxied_request_t *
proxied_request_find(registration_t *registration,
    uint64_t original_sequence_number)
{
  proxied_request_t *entry;

  entry = list_head(registration->proxied_request_list);
  while (entry) {
    if (entry->original_sequence_number == original_sequence_number) {
      return entry;
    }
    entry = list_item_next(entry);
  }
  return NULL;
}
