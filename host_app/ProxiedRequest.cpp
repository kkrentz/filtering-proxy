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

#include "Registration.hpp"

namespace filtering {

ProxiedRequest::ProxiedRequest(
    Registration *registration,
    coap_session_t *session,
    const coap_pdu_t *pdu,
    const oscore_ng_id_t *iot_client_id)
  : RegistrantRequest(registration, true, session, pdu) {
  oscore_ng_copy_id(&iot_client_id_, iot_client_id);
  prolongLifetime();
}

void
ProxiedRequest::prolongLifetime() {
  last_prolongation_ = std::chrono::steady_clock::now();
}

std::chrono::time_point<std::chrono::steady_clock>
ProxiedRequest::getLastProlongation() {
  return last_prolongation_;
}

void
ProxiedRequest::setNewMessageId(coap_mid_t new_message_id) {
  new_message_id_ = new_message_id;
  has_new_message_id_ = true;
}

bool
ProxiedRequest::hasNewMessageId() {
  return has_new_message_id_;
}

coap_mid_t
ProxiedRequest::getNewMessageId() {
  return new_message_id_;
}

const oscore_ng_id_t *
ProxiedRequest::getIotClientId() {
  return &iot_client_id_;
}

} // namespace filtering
