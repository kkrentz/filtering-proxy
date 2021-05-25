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

#ifndef PROXIED_REQUEST_H_
#define PROXIED_REQUEST_H_

#include "filtering_ocall.h"
#include "libcoap.inc"

namespace filtering {

class Registration;

class ProxiedRequest {
  coap_session_t *original_session_;
  coap_mid_t original_message_id_;
  coap_bin_const_t original_token_;
  coap_mid_t new_message_id_;
  bool has_new_message_id_;
  coap_pdu_t *response_pdu_;
  coap_address_t iot_device_address_;
  uint8_t iot_device_id_[OSCORE_MAX_ID_LEN];
  uint8_t iot_device_id_len_;
  uint8_t iot_client_id_[OSCORE_MAX_ID_LEN];
  uint8_t iot_client_id_len_;
  uint64_t original_sequence_number_;
public:
  ProxiedRequest(coap_session_t *session,
      const coap_pdu_t *request,
      const coap_address_t *iot_device_address,
      const oscore_data_t *oscore_data);
  ~ProxiedRequest();
  coap_session_t *getOriginalSession();
  coap_mid_t getOriginalMessageId();
  coap_bin_const_t getOriginalToken();
  void setNewMessageId(coap_mid_t new_message_id);
  bool hasNewMessageId();
  coap_mid_t getNewMessageId();
  const coap_address_t *getIotDeviceAddress();
  void getIds(oscore_data_t *oscore_data);
  bool isSameRequest(const oscore_data_t *oscore_data);
};

} // namespace filtering

#endif /* PROXIED_REQUEST_H_ */
