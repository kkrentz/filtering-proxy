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

#pragma once

#include <chrono>
#include <coap3/coap.h>
#include <list>
#include <memory>

#include "coap3/coap_libcoap_build.h"
#include "ProxiedRequest.hpp"
#include "Referenceable.hpp"
#include "report.h"

namespace filtering {

class Registration : public Referenceable {
  coap_session_t *session_ = nullptr;
  oscore_ng_id_t iot_device_id_;
  uint8_t ephemeral_public_key_head_[ECC_CURVE_P_256_SIZE];
  std::list<std::unique_ptr<ProxiedRequest>> proxied_requests_;
  std::chrono::time_point<std::chrono::steady_clock> creation_time_;
  bool is_complete_ = false;
 public:
  Registration(const uint8_t ephemeral_public_key_head[ECC_CURVE_P_256_SIZE]);
  coap_session_t *getSession();
  void setSession(coap_session_t *session);
  bool hasAddress(const coap_address_t *address);
  void complete(const oscore_ng_id_t *iot_device_id);
  bool isComplete();
  const oscore_ng_id_t *getIotDeviceId();
  bool isIotDevicesEphemeralPublicKey(const uint8_t *ephemeral_public_key_head,
                                      size_t head_len);
  void addProxiedRequest(std::unique_ptr<ProxiedRequest> proxied_request);
  void eraseProxiedRequest(ProxiedRequest *proxied_request);
  ProxiedRequest *findDuplicateProxiedRequest(ProxiedRequest *proxied_request);
  ProxiedRequest *findProxiedRequest(coap_mid_t mid);
  void cleanUpProxiedRequsts();
  std::chrono::time_point<std::chrono::steady_clock> getCreationTime();
  virtual ~Registration();
};

} // namespace filtering
