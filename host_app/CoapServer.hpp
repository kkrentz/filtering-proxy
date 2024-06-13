/*
 * Copyright (c) 2022, Uppsala universitet.
 * Copyright (c) 2025, Siemens AG.
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

#include <coap3/coap.h>
#include <list>
#include <queue>

#include "coap3/coap_libcoap_build.h"
#include "Ocall.hpp"
#include "OcallDispatcher.hpp"
#include "OcallFactory.hpp"
#include "PduFactory.hpp"
#include "Registration.hpp"

namespace filtering {

class CoapServer : public IOcallHandler {
#if !WITH_TRAP
  static const char kKnockPath[];
#endif /* !WITH_TRAP */
  static const char kRegisterPath[];
  static const char kCoapDefaultPort[];
  static const char kCoapUriScheme[];
  static const oscore_ng_id_t kMiddleboxId;
  coap_context_t *coap_context_;
  std::queue<std::unique_ptr<Ocall>> pending_ocalls_;
  std::list<std::unique_ptr<Registration>> tentative_registrations_;
  std::list<std::unique_ptr<Registration>> ongoing_registrations_;
  std::list<std::unique_ptr<Registration>> completed_registrations_;
  OcallFactory ocall_factory_;
  PduFactory pdu_factory_;
#if !WITH_TRAP
  int addKnockResource();
#endif /* !WITH_TRAP */
  int addRegisterResource();
  int addUnknownResource();
  int addProxyResource(const char *host);
  static int resolveAddress(
      const char *host,
      const char *service,
      coap_address_t *address);
#if !WITH_TRAP
  static void handleKnockCallback(
      coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleKnock(
      coap_session_t *session,
      const coap_pdu_t *request,
      coap_pdu_t *response);
  void onCookie(
      Request *request,
      coap_bin_const_t *token,
      uint8_t *cookie,
      size_t cookie_size);
#endif /* !WITH_TRAP */
  static void handleRegisterCallback(
      coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleRegister(
      coap_session_t *session,
      const coap_pdu_t *request,
      coap_pdu_t *response);
  static void handleUnknownCallback(
      coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleUnknown(
      coap_session_t *session,
      const coap_pdu_t *request,
      coap_pdu_t *response);
  int parseOscoreNgOption(
      oscore_ng_option_data_t *option_data,
      const coap_pdu_t *pdu,
      bool is_request);
  static void handleProxyRequestCallback(
      coap_resource_t *resource,
      coap_session_t *session,
      const coap_pdu_t *request,
      const coap_string_t *query,
      coap_pdu_t *response);
  void handleProxyRequest(
      coap_session_t *session,
      const coap_pdu_t *request,
      coap_pdu_t *response);
  static coap_response_t onResponseCallback(
      coap_session_t *session,
      const coap_pdu_t *sent,
      const coap_pdu_t *received,
      const coap_mid_t mid);
  coap_response_t onResponse(
      coap_session_t *session,
      const coap_pdu_t *received,
      const coap_mid_t mid);
  Registration *findOngoingRegistration(
      const uint8_t *ephemeral_public_key_head,
      size_t head_len);
  Registration *findRegistration(
      const coap_address_t *iot_device_address);
  void cleanUpOngoingRegistrations(void);
  void cleanUp();
 public:
  CoapServer();
  int start(const char *host, const char *port);
  virtual std::unique_ptr<Ocall> waitForOcall();
  virtual void onReport(
      Request *request,
      coap_bin_const_t *token,
#if WITH_IRAP
      const filtering_ocall_oscore_ng_data_t *data);
#else /* WITH_IRAP */
      uint8_t *report,
      size_t report_size);
#endif /* WITH_IRAP */
  virtual void onDiscloseAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual void onOscoreNgAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual void onProxyRequestAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual void onProxyResponseAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual ~CoapServer();
};

} // namespace filtering
