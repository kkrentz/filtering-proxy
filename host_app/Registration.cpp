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

#include "Registration.hpp"

#include <cstring>

namespace filtering {

Registration::Registration(
    const uint8_t ephemeral_public_key_head[ECC_CURVE_P_256_SIZE])
  : Referenceable(true) {
  creation_time_ = std::chrono::steady_clock::now();
  std::memcpy(ephemeral_public_key_head_,
              ephemeral_public_key_head,
              sizeof(ephemeral_public_key_head_));
}

void
Registration::setSession(coap_session_t *session) {
  coap_session_reference(session);
  coap_session_release(session_);
  session_ = session;
}

coap_session_t *
Registration::getSession() {
  return session_;
}

bool
Registration::hasAddress(const coap_address_t *address) {
  coap_address_t my_address;
  coap_address_copy(&my_address,
                    coap_session_get_addr_remote(session_));
  coap_address_set_port(&my_address, coap_address_get_port(address));
  return coap_address_equals(&my_address, address);
}

void
Registration::complete(const oscore_ng_id_t *iot_device_id) {
  oscore_ng_copy_id(&iot_device_id_, iot_device_id);
  is_complete_ = true;
}

bool
Registration::isComplete() {
  return is_complete_;
}

const oscore_ng_id_t *
Registration::getIotDeviceId() {
  return &iot_device_id_;
}

bool
Registration::isIotDevicesEphemeralPublicKey(
    const uint8_t *ephemeral_public_key_head,
    size_t head_len) {
  return !std::memcmp(ephemeral_public_key_head,
                      ephemeral_public_key_head_,
                      head_len);
}

void
Registration::addProxiedRequest(
    std::unique_ptr<ProxiedRequest> proxied_request) {
  proxied_requests_.push_front(std::move(proxied_request));
}

void
Registration::eraseProxiedRequest(ProxiedRequest *proxied_request) {
  for (auto it = proxied_requests_.begin();
       it != proxied_requests_.end();
       it++) {
    if (it->get() == proxied_request) {
      if (!it->get()->isReferenced()) {
        proxied_requests_.erase(it);
      }
      return;
    }
  }
}

ProxiedRequest *
Registration::findDuplicateProxiedRequest(ProxiedRequest *proxied_request) {
  cleanUpProxiedRequsts();
  for (auto it = proxied_requests_.begin();
       it != proxied_requests_.end();
       it++) {
    if (it->get() == proxied_request) {
      continue;
    }
    if (it->get()->equals(proxied_request)) {
      return it->get();
    }
  }
  return nullptr;
}

ProxiedRequest *
Registration::findProxiedRequest(coap_mid_t mid) {
  cleanUpProxiedRequsts();
  for (auto it = proxied_requests_.begin();
       it != proxied_requests_.end();
       it++) {
    if (it->get()->hasNewMessageId()
        && (it->get()->getNewMessageId() == mid)) {
      return it->get();
    }
  }
  return NULL;
}

void
Registration::cleanUpProxiedRequsts(void) {
  constexpr std::chrono::milliseconds max_age{
    (OSCORE_NG_FRESHNESS_THRESHOLD * 2 + OSCORE_NG_PROCESSING_DELAY) * 10
  };
  std::chrono::time_point<std::chrono::steady_clock> now =
      std::chrono::steady_clock::now();

  for (auto it = proxied_requests_.begin();
       it != proxied_requests_.end();
       it++) {
    if ((now - it->get()->getLastProlongation()) > max_age) {
      coap_log_info("ProxiedRequest timed out\n");
      it = proxied_requests_.erase(it);
    }
  }
}

std::chrono::time_point<std::chrono::steady_clock>
Registration::getCreationTime() {
  return creation_time_;
}

Registration::~Registration() {
  coap_session_release(session_);
}

} // namespace filtering
