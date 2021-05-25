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

#ifndef COAP_SERVER_H_
#define COAP_SERVER_H_

#include <list>
#include <queue>

#include "libcoap.inc"

#include "Ocall.hpp"
#include "OcallDispatcher.hpp"
#include "Registration.hpp"

#define COAP_SERVER_COOKIE_LEN ((SHA_256_DIGEST_LENGTH / 2) + sizeof(uint32_t))

namespace filtering {

class CoapServer : public IOcallHandler {
  static const char kKnockPath[];
  static const char kRegisterPath[];
  static const char kCoapDefaultPort[];
  static const char kCoapUriScheme[];
  coap_context_t *coap_context_;
  coap_address_t dst_;
  std::queue<std::unique_ptr<Ocall>> pending_ocalls_;
  std::list<std::unique_ptr<Registration>> unproven_registrations_;
  std::list<std::unique_ptr<Registration>> proven_registrations_;
  std::list<std::unique_ptr<Registration>> completed_registrations_;
  std::unique_ptr<AttestationReport> sm_report_;
  std::list<std::unique_ptr<ProxiedRequest>> proxied_requests_;
  uint8_t cookie_key_[SHA_256_BLOCK_SIZE];
  uint32_t cookie_interval_;
  void updateCookieKey();
  int createTestRegistration();
  static int resolveAddress(const char *host,
      const char *service,
      coap_address_t *address);
  int createKnockResource();
  static void handleKnockCallback(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleKnock(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  int generateCookie(const coap_address_t *address,
      uint8_t cookie[COAP_SERVER_COOKIE_LEN]);
  int checkCookie(const uint8_t cookie[COAP_SERVER_COOKIE_LEN],
      const coap_address_t *address);
  int createRegisterResource();
  static void handleRegisterCallback(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleRegister(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleOscore(coap_session_t *session,
      const coap_pdu_t *request,
      const oscore_option_data_t *oscore_option_data,
      const coap_address_t *iot_device_address);
  int createProxyResource(const char *host);
  static void handleProxyRequestCallback(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleProxyRequest(coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  static void dispatchHookCallback(coap_context_t *context,
      coap_session_t *session,
      coap_pdu_t *pdu);
  void dispatchHook(coap_context_t *context,
      coap_session_t *session,
      coap_pdu_t *pdu);
  static void onNackCallback(coap_session_t *session,
      const coap_pdu_t *sent,
      const coap_nack_reason_t reason,
      const coap_mid_t mid);
  void onNack(coap_session_t *session,
      const coap_pdu_t *sent,
      const coap_nack_reason_t reason,
      const coap_mid_t mid);
  Registration *findOngoingRegistration(
      const coap_address_t *iot_device_address);
  Registration *findRegistration(
      const coap_address_t *iot_device_address);
  void deleteProxiedRequest(
      const coap_address_t *iot_device_address,
      coap_mid_t mid);
  ProxiedRequest *findProxiedRequest(
      const coap_address_t *iot_device_address,
      coap_mid_t mid);
  bool haveOngoingProxyRequest(oscore_data_t *oscore_data);
  void cleanUp();
 public:
  CoapServer();
  int start(const char *host, const char *port);
  virtual std::unique_ptr<Ocall> waitForOcall();
  virtual void onReport(void *ptr, const struct report_t *report);
  virtual void onDiscloseAnswer(void *ptr, oscore_data_t *data);
  virtual void onOscoreAnswer(void *ptr, oscore_data_t *data);
  virtual void onProxyRequestAnswer(void *ptr, oscore_data_t *data);
  virtual void onProxyResponseAnswer(void *ptr, oscore_data_t *data);
  virtual ~CoapServer();
};

} // namespace filtering

#endif /* COAP_SERVER_H_ */
