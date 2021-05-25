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

#include "oscore_filter.h"

#include "app/string.h"
#include "oscore.h"

#include "log.h"
#include "iot_client.h"
#include "proxied_request.h"
#include "registration.h"

int
oscore_filter_check_proxy_request(oscore_data_t *data, void *proxied_request)
{
  registration_t *registration;
  iot_client_session_t *iot_client_session;
  int created_session;
  uint64_t original_sequence_number;
  uint64_t new_sequence_number;
  proxied_request_t *pr;

  /* find registration and session */
  registration = registration_find(data->iot_device_id,
      data->iot_device_id_len,
      true);
  if (!registration) {
    LOG_MESSAGE("not registered\n");
    goto error_1;
  }
  iot_client_session = iot_client_find_session(registration,
      data->option_data.kid, data->option_data.kid_len);
  if (!iot_client_session) {
    iot_client_session = iot_client_create_session(registration,
        data->option_data.kid, data->option_data.kid_len);
    if(!iot_client_session) {
      LOG_MESSAGE("iot_client_create_session failed\n");
      goto error_1;
    }
    created_session = 1;
  } else {
    created_session = 0;
    /* check rate */
    if (leaky_bucket_is_full(&iot_client_session->leaky_bucket)) {
      LOG_MESSAGE("rate limitation\n");
      goto error_1;
    }
  }

  /* check authenticity and freshness */
  original_sequence_number =
      oscore_option_data_get_sequence_number(&data->option_data);
  if (!oscore_is_authentic(&iot_client_session->context,
      original_sequence_number, false,
      data->ciphertext, data->ciphertext_len)) {
    LOG_MESSAGE("Inauthentic proxy request\n");
    goto error_2;
  }
  if (!oscore_is_fresh(&iot_client_session->context.anti_replay,
      original_sequence_number)) {
    LOG_MESSAGE("Replayed proxy request\n");
    goto error_1;
  }

  /* store sequence numbers */
  new_sequence_number
      = registration->forwarding.context.senders_sequence_number + 1;
  pr = proxied_request_store(registration,
      proxied_request,
      original_sequence_number,
      new_sequence_number);
  if(!pr) {
    LOG_MESSAGE("proxied_request_store failed\n");
    goto error_2;
  }

  /* resecure */
  if (!oscore_secure(&registration->forwarding.context,
      &data->option_data,
      data->ciphertext,
      data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
      new_sequence_number,
      true)) {
    LOG_MESSAGE("oscore_secure failed\n");
    goto error_3;
  }
  memcpy(pr->mic,
      data->ciphertext + data->ciphertext_len - sizeof(pr->mic),
      sizeof(pr->mic));
  leaky_bucket_pour(&iot_client_session->leaky_bucket);
  registration->forwarding.context.senders_sequence_number
      = new_sequence_number;
  LOG_MESSAGE("Resecured request\n");
  return 1;

error_3:
  proxied_request_remove(registration, proxied_request);
error_2:
  if (created_session) {
    iot_client_delete_session(registration, iot_client_session);
  }
error_1:
  return 0;
}

int
oscore_filter_check_proxy_response(oscore_data_t *data, void *proxied_request)
{
  registration_t *registration;
  oscore_context_t *iot_device_context;
  iot_client_session_t *iot_client_session;
  uint64_t original_sequence_number;
  uint64_t new_sequence_number;

  /* find registration and sessions */
  registration = registration_find(data->iot_device_id,
      data->iot_device_id_len, true);
  if (!registration) {
    LOG_MESSAGE("Did not find registration\n");
    return 0;
  }
  iot_device_context = &registration->forwarding.context;
  iot_client_session = iot_client_find_session(registration,
      data->iot_client_id, data->iot_client_id_len);
  if (!iot_client_session) {
    LOG_MESSAGE("Did not find IoT client session\n");
    return 0;
  }
  if (!proxied_request_get_sequence_numbers(registration,
      proxied_request,
      &original_sequence_number,
      &new_sequence_number)) {
    LOG_MESSAGE("proxied_request_get_sequence_numbers failed\n");
    return 0;
  }

  /* check */
  if (!oscore_is_authentic(iot_device_context,
      new_sequence_number, true,
      data->ciphertext, data->ciphertext_len)) {
    LOG_MESSAGE("Inauthentic proxy response\n");
    return 0;
  }

  /* resecure */
  if (!oscore_secure(&iot_client_session->context,
      &data->option_data,
      data->ciphertext,
      data->ciphertext_len - COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN,
      original_sequence_number,
      false)) {
    LOG_MESSAGE("oscore_secure failed\n");
    return 0;
  }
  LOG_MESSAGE("Resecured response\n");
  /* TODO delete responses to NONs here */
  /* TODO only keep proxied requests within the replay window */
  return 1;
}
