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

#ifndef REGISTRATION_H_
#define REGISTRATION_H_

#include "libcoap.inc"

#include "AttestationReport.hpp"
#include "ProxiedRequest.hpp"

namespace filtering {

class Registration {
  coap_mid_t register_mid_;
  coap_context_t *coap_context_;
  coap_resource_t *coap_resource_;
  coap_session_t *session_;
  uint8_t iot_device_id_[OSCORE_MAX_ID_LEN];
  uint8_t iot_device_id_len_;
  uint8_t filtering_clients_ephemeral_public_key_[1 + uECC_BYTES];
  uint8_t compressed_report_[ATTESTATION_REPORT_COMPRESSED_LEN];
  bool locked_;
  coap_session_t *cached_session_;
  coap_mid_t cached_mid_;
 public:
  int init(coap_mid_t register_mid,
      coap_context_t *coap_context,
      const coap_address_t *iot_device_address,
      const uint8_t filtering_clients_ephemeral_public_key[1 + uECC_BYTES]);
  coap_mid_t getRegisterMid();
  coap_session_t *getSession();
  const coap_address_t *getAddress();
  void getIotDeviceId(uint8_t iot_device_id[OSCORE_MAX_ID_LEN],
      uint8_t *iot_device_id_len);
  bool isFilteringClientsEphemeralPublicKey(
      const uint8_t public_key[1 + uECC_BYTES]);
  void onReport(const struct report_t *report);
  void getCompressedReport(
      uint8_t compressed_report[ATTESTATION_REPORT_COMPRESSED_LEN]);
  void cache(coap_session_t *session, coap_mid_t mid);
  coap_session_t *getCachedSession();
  coap_mid_t getCachedMid();
  void clearCache();
  void lock();
  void unlock();
  bool isLocked();
  virtual ~Registration();
};

} // namespace filtering

#endif /* REGISTRATION_H_ */
