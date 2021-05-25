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

#include "ProxiedRequest.hpp"

#include <cstring>

namespace filtering {

ProxiedRequest::ProxiedRequest(coap_session_t *session,
    const coap_pdu_t *request,
    const coap_address_t *iot_device_address,
    const oscore_data_t *oscore_data)
{
  original_session_ = coap_session_reference(session);
  original_message_id_ = coap_pdu_get_mid(request);
  original_token_ = coap_pdu_get_token(request);
  coap_address_copy(&iot_device_address_, iot_device_address);
  std::memcpy(iot_device_id_,
      oscore_data->iot_device_id,
      oscore_data->iot_device_id_len);
  iot_device_id_len_ = oscore_data->iot_device_id_len;
  std::memcpy(iot_client_id_,
      oscore_data->option_data.kid,
      oscore_data->option_data.kid_len);
  iot_client_id_len_ = oscore_data->option_data.kid_len;
  original_sequence_number_ = oscore_option_data_get_sequence_number(
      &oscore_data->option_data);
}

ProxiedRequest::~ProxiedRequest()
{
  coap_session_release(original_session_);
}

coap_session_t *
ProxiedRequest::getOriginalSession()
{
  return original_session_;
}

coap_mid_t
ProxiedRequest::getOriginalMessageId()
{
  return original_message_id_;
}

coap_bin_const_t
ProxiedRequest::getOriginalToken()
{
  return original_token_;
}

void
ProxiedRequest::setNewMessageId(coap_mid_t new_message_id)
{
  new_message_id_ = new_message_id;
  has_new_message_id_ = true;
}

bool
ProxiedRequest::hasNewMessageId()
{
  return has_new_message_id_;
}

coap_mid_t
ProxiedRequest::getNewMessageId()
{
  return new_message_id_;
}

const coap_address_t *
ProxiedRequest::getIotDeviceAddress()
{
  return &iot_device_address_;
}

void
ProxiedRequest::getIds(oscore_data_t *oscore_data)
{
  std::memcpy(oscore_data->iot_device_id,
      iot_device_id_,
      iot_device_id_len_);
  oscore_data->iot_device_id_len = iot_device_id_len_;
  std::memcpy(oscore_data->iot_client_id,
      iot_client_id_,
      iot_client_id_len_);
  oscore_data->iot_client_id_len = iot_client_id_len_;
}

bool
ProxiedRequest::isSameRequest(const oscore_data_t *oscore_data)
{
  return (oscore_data->iot_client_id_len == iot_client_id_len_)
      && !std::memcmp(oscore_data->iot_client_id,
          iot_client_id_,
          iot_client_id_len_)
      && (original_sequence_number_
          == oscore_option_data_get_sequence_number(
              &oscore_data->option_data));
}

} // namespace filtering
