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

#include <coap3/coap.h>
#include <list>
#include <queue>

#include "Ocall.hpp"
#include "OcallDispatcher.hpp"
#include "OcallFactory.hpp"
#include "PduFactory.hpp"
#include "Registration.hpp"

#define COAP_SERVER_COOKIE_LEN ((SHA_256_DIGEST_LENGTH / 2) + sizeof(uint32_t))

namespace filtering {

class CoapServer : public IOcallHandler {
  static const char kKnockPath[];
  static const char kRegisterPath[];
  static const char kCoapDefaultPort[];
  static const char kCoapUriScheme[];
  static const oscore_ng_id_t kMiddleboxId;
  coap_context_t *coap_context_;
  std::queue<std::unique_ptr<Ocall>> pending_ocalls_;
  std::list<std::unique_ptr<Registration>> tentative_registrations_;
  std::list<std::unique_ptr<Registration>> ongoing_registrations_;
  std::list<std::unique_ptr<Registration>> completed_registrations_;
  uint8_t cookie_key_[SHA_256_BLOCK_SIZE];
  uint32_t cookie_interval_;
  OcallFactory ocall_factory_;
  PduFactory pdu_factory_;
  int addResource(const char *path,
                  coap_request_t method,
                  coap_method_handler_t handler);
  int addUnknownResource();
  int addProxyResource(const char *host);
  void updateCookieKey();
  static int resolveAddress(const char *host,
                            const char *service,
                            coap_address_t *address);
  static void handleKnockCallback(coap_resource_t *resource,
                                  coap_session_t *session,
                                  const coap_pdu_t *request,
                                  const coap_string_t *query,
                                  coap_pdu_t *response);
  void handleKnock(coap_session_t *session,
                   const coap_pdu_t *request,
                   coap_pdu_t *response);
  int generateCookie(uint8_t cookie[COAP_SERVER_COOKIE_LEN],
                     const coap_address_t *address);
  int checkCookie(const uint8_t cookie[COAP_SERVER_COOKIE_LEN],
                  const coap_address_t *address);
  static void handleRegisterCallback(coap_resource_t *resource,
                                     coap_session_t *session,
                                     const coap_pdu_t *request,
                                     const coap_string_t *query,
                                     coap_pdu_t *response);
  void handleRegister(coap_session_t *session,
                      const coap_pdu_t *request,
                      coap_pdu_t *response);
  static void handleUnknownCallback(coap_resource_t *resource,
                                    coap_session_t *session,
                                    const coap_pdu_t *request,
                                    const coap_string_t *query,
                                    coap_pdu_t *response);
  void handleUnknown(coap_session_t *session,
                     const coap_pdu_t *request,
                     coap_pdu_t *response);
  int parseOscoreNgOption(const coap_pdu_t *pdu,
                          oscore_ng_option_data_t *option_data);
  static void handleProxyRequestCallback(coap_resource_t *resource,
                                         coap_session_t *session,
                                         const coap_pdu_t *request,
                                         const coap_string_t *query,
                                         coap_pdu_t *response);
  void handleProxyRequest(coap_session_t *session,
                          const coap_pdu_t *request,
                          coap_pdu_t *response);
  static coap_response_t onResponseCallback(coap_session_t *session,
                                            const coap_pdu_t *sent,
                                            const coap_pdu_t *received,
                                            const coap_mid_t mid);
  coap_response_t onResponse(coap_session_t *session,
                             const coap_pdu_t *received,
                             const coap_mid_t mid);
  Registration *findOngoingRegistration(
      const uint8_t *ephemeral_public_key_hash, size_t hash_len);
  Registration *findRegistration(
      const coap_address_t *iot_device_address);
  void cleanUpOngoingRegistrations(void);
  void cleanUp();
 public:
  CoapServer();
  int start(const char *host, const char *port);
  virtual std::unique_ptr<Ocall> waitForOcall();
  virtual void onReport(void *ptr,
                        uint8_t compressed_report[REPORT_COMPRESSED_LEN]);
  virtual void onDiscloseAnswer(void *ptr,
                                const filtering_ocall_oscore_ng_data_t *data);
  virtual void onOscoreNgAnswer(void *ptr,
                                const filtering_ocall_oscore_ng_data_t *data);
  virtual void onProxyRequestAnswer(
      void *ptr,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual void onProxyResponseAnswer(
      void *ptr,
      const filtering_ocall_oscore_ng_data_t *data);
  virtual ~CoapServer();
};

} // namespace filtering
