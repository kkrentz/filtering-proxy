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

int
Registration::init(coap_mid_t register_mid,
    coap_context_t *coap_context,
    const coap_address_t *iot_device_address,
    const uint8_t filtering_clients_ephemeral_public_key[1 + uECC_BYTES])
{
  coap_address_t copied_address;

  register_mid_ = register_mid;

  assert(!coap_resource_);
  assert(!session_);
  assert(coap_context);
  assert(iot_device_address);
  assert(filtering_clients_ephemeral_public_key);

  if (iot_device_address->addr.sin6.sin6_family != AF_INET6) {
    coap_log(LOG_ERR, "invalid IP\n");
    return 0;
  }

  uint16_t mac_address = iot_device_address->addr.sin6.sin6_addr.s6_addr[15]
      | iot_device_address->addr.sin6.sin6_addr.s6_addr[14] << 8;
  iot_device_id_len_ = sizeof(mac_address);
  std::memcpy(iot_device_id_,
      iot_device_address->addr.sin6.sin6_addr.s6_addr + 14,
      iot_device_id_len_);
  std::memcpy(filtering_clients_ephemeral_public_key_,
      filtering_clients_ephemeral_public_key,
      1 + uECC_BYTES);
  coap_context_ = coap_context;
  coap_resource_ = nullptr;
  coap_address_copy(&copied_address, iot_device_address);
  coap_address_set_port(&copied_address, COAP_DEFAULT_PORT);
  session_ = coap_new_client_session(coap_context_,
      nullptr,
      &copied_address, COAP_PROTO_UDP);
  if (!session_) {
    return 0;
  }
  /* disable retransmissions - we only retransmit forwarded OSCORE messages
     when the IoT client retransmits the original proxy request */
  coap_session_set_max_retransmit(session_, 0);
  return 1;
}

coap_mid_t
Registration::getRegisterMid()
{
  return register_mid_;
}

coap_session_t *
Registration::getSession()
{
  return session_;
}

const coap_address_t *
Registration::getAddress()
{
  return coap_session_get_addr_remote(session_);
}

void
Registration::getIotDeviceId(uint8_t iot_device_id[OSCORE_MAX_ID_LEN],
    uint8_t *iot_device_id_len)
{
  std::memcpy(iot_device_id, iot_device_id_, iot_device_id_len_);
  *iot_device_id_len = iot_device_id_len_;
}

bool
Registration::isFilteringClientsEphemeralPublicKey(
    const uint8_t public_key[1 + uECC_BYTES])
{
  return !std::memcmp(public_key,
      filtering_clients_ephemeral_public_key_,
      1 + uECC_BYTES);
}

void
Registration::onReport(const struct report_t *report)
{
  std::unique_ptr<AttestationReport> attestation_report =
      std::make_unique<AttestationReport>(report);
  attestation_report->compress(compressed_report_);
}

void
Registration::getCompressedReport(
    uint8_t compressed_report[ATTESTATION_REPORT_COMPRESSED_LEN])
{
  std::memcpy(compressed_report,
      compressed_report_,
      ATTESTATION_REPORT_COMPRESSED_LEN);
}

void
Registration::cache(coap_session_t *session, coap_mid_t mid)
{
  /* TODO cache token */
  clearCache();
  if (session) {
    cached_session_ = coap_session_reference(session);
  }
  cached_mid_ = mid;
}

coap_session_t *
Registration::getCachedSession()
{
  return cached_session_;
}

coap_mid_t
Registration::getCachedMid()
{
  return cached_mid_;
}

void
Registration::clearCache()
{
  coap_session_release(cached_session_);
  cached_session_ = nullptr;
}

void
Registration::lock()
{
  locked_ = true;
}

void
Registration::unlock()
{
  locked_ = false;
}

bool
Registration::isLocked()
{
  return locked_;
}

Registration::~Registration()
{
  coap_delete_resource(coap_context_, coap_resource_);
  coap_session_release(session_);
  clearCache();
}

} // namespace filtering
