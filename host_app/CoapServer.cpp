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

#include "CoapServer.hpp"

#include <cassert>
#include <netdb.h>

#include "filtering_ocall.h"
#include "IotRequest.hpp"
#include "ProxiedRequest.hpp"
#include "report.h"
#include "Request.hpp"

#define MAX_URI_HOST_LENGTH (127)
#define MIN_DISCLOSE_KID_CONTEXT_LEN (8)

namespace filtering {

#if !WITH_TRAP
const char CoapServer::kKnockPath[] = "kno";
#endif /* !WITH_TRAP */
const char CoapServer::kRegisterPath[] = "reg";
const char CoapServer::kCoapDefaultPort[] = "5683";
const char CoapServer::kCoapUriScheme[] = "coap";
const oscore_ng_id_t CoapServer::kMiddleboxId = { { 0 }, 0 };

CoapServer::CoapServer() {
  coap_context_ = nullptr;
}

int
CoapServer::start(const char *host, const char *port) {
  coap_startup();
  try {
    coap_address_t address;

    if (!port) {
      port = kCoapDefaultPort;
    }
    if (!resolveAddress(host, port, &address)) {
      throw __LINE__;
    }
    coap_context_ = coap_new_context(&address);
    if (!coap_context_) {
      throw __LINE__;
    }
    coap_context_set_app_data2(coap_context_, this, NULL);
#if WITH_TRAP
    if (!coap_bakery_open(coap_context_)) {
      throw __LINE__;
    }
#else /* WITH_TRAP */
    if (!addKnockResource()) {
      throw __LINE__;
    }
#endif /* WITH_TRAP */
    if (!addRegisterResource()) {
      throw __LINE__;
    }
    if (!addUnknownResource()) {
      throw __LINE__;
    }
    if (!addProxyResource(host)) {
      throw __LINE__;
    }
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::start\n", l);
    cleanUp();
    return 0;
  }
  coap_register_response_handler(coap_context_, onResponseCallback);
  coap_register_option(coap_context_, COAP_OPTION_OSCORE);
  return 1;
}

#if !WITH_TRAP
int
CoapServer::addKnockResource() {
  coap_str_const_t *ruri = coap_make_str_const(kKnockPath);
  coap_resource_t *resource = coap_resource_init(ruri, 0);
  if (!resource) {
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handleKnockCallback);
  coap_add_resource(coap_context_, resource);
  return 1;
}
#endif /* !WITH_TRAP */

int
CoapServer::addRegisterResource() {
  coap_str_const_t *ruri = coap_make_str_const(kRegisterPath);
  coap_resource_t *resource = coap_resource_init(ruri, 0);
  if (!resource) {
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handleRegisterCallback);
  coap_add_resource(coap_context_, resource);
  return 1;
}

int
CoapServer::addUnknownResource() {
  coap_resource_t *resource = coap_resource_unknown_init(handleUnknownCallback);

  if (!resource) {
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_POST, handleUnknownCallback);
  coap_add_resource(coap_context_, resource);
  return 1;
}

int
CoapServer::addProxyResource(const char *host) {
  coap_resource_t *resource = coap_resource_proxy_uri_init(
                                  handleProxyRequestCallback,
                                  1,
                                  &host);
  if (!resource) {
    return 0;
  }
  coap_add_resource(coap_context_, resource);
  return 1;
}

int
CoapServer::resolveAddress(const char *host,
                           const char *service,
                           coap_address_t *address) {
  struct addrinfo *ai_list_head;
  struct addrinfo hints;

  std::memset(&hints, 0, sizeof(hints));
  std::memset(address, 0, sizeof(*address));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  int result = getaddrinfo(host, service, &hints, &ai_list_head);
  if (result) {
    coap_log_err("resolveAddress failed due to %s\n",
                 gai_strerror(result));
    return 0;
  }

  for (struct addrinfo *ai = ai_list_head; ai != NULL; ai = ai->ai_next) {
    switch (ai->ai_family) {
    case AF_INET6:
    case AF_INET:
      address->size = ai->ai_addrlen;
      std::memcpy(&address->addr.sin6, ai->ai_addr, address->size);
      result = 1;
      break;
    default:
      break;
    }
  }
  freeaddrinfo(ai_list_head);
  return result;
}

#if !WITH_TRAP
void
CoapServer::handleKnockCallback(coap_resource_t *resource,
                                coap_session_t *session,
                                const coap_pdu_t *request,
                                const coap_string_t *query,
                                coap_pdu_t *response) {
  (void)resource;
  (void)query;
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log_err("coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_context_get_app_data(context);
  coap_server->handleKnock(session, request, response);
}

void
CoapServer::handleKnock(coap_session_t *session,
                        const coap_pdu_t *request,
                        coap_pdu_t *response) {
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);

  /* check padding bytes */
  {
    size_t payload_size;
    const uint8_t *payload;

    if (!coap_get_data(request, &payload_size, &payload)) {
      coap_log_err("coap_get_data failed\n");
      return;
    }
    if (payload_size < COAP_BAKERY_COOKIE_SIZE) {
      coap_log_err("insufficient padding bytes\n");
      return;
    }
  }

  /* create ocall */
  std::unique_ptr<Ocall> ocall = ocall_factory_.createKnockOcall(
                                     std::move(std::make_unique<Ocall>()),
                                     coap_session_get_addr_remote(session),
                                     request);
  if (!ocall) {
    coap_log_err("OcallFactory::createKnockOcall failed\n");
    return;
  }

  /* store objects for next steps */
  ocall->setRequest(new Request(false, session, request));
  pending_ocalls_.push(std::move(ocall));
}

void
CoapServer::onCookie(Request *request,
                     coap_bin_const_t *token,
                     uint8_t *cookie,
                     size_t cookie_size) {
  try {
    /* check result */
    if (!cookie_size) {
      throw __LINE__;
    }

    /* create response */
    coap_pdu_t *response = pdu_factory_.createPdu(
                               request->getType() == COAP_MESSAGE_CON
                               ? COAP_MESSAGE_ACK
                               : COAP_MESSAGE_NON,
                               COAP_RESPONSE_CODE_CONTENT,
                               request->getMid(),
                               token,
                               nullptr,
                               cookie,
                               cookie_size);
    if (!response) {
      throw __LINE__;
    }

    /* send response */
    coap_mid_t mid = coap_send(request->getSession(), response);
    if (mid == COAP_INVALID_MID) {
      throw __LINE__;
    }
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::onCookie\n", l);
  }
  request->dereference();
}
#endif /* !WITH_TRAP */

void
CoapServer::handleRegisterCallback(coap_resource_t *resource,
                                   coap_session_t *session,
                                   const coap_pdu_t *request,
                                   const coap_string_t *query,
                                   coap_pdu_t *response) {
  (void)resource;
  (void)query;
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log_err("coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_context_get_app_data(context);
  coap_server->handleRegister(session, request, response);
}

void
CoapServer::handleRegister(coap_session_t *session,
                           const coap_pdu_t *request,
                           coap_pdu_t *response) {
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);

  coap_log_debug("handleRegister\n");

  /* extract payload */
  size_t payload_len;
  const uint8_t *payload;
  if (!coap_get_data(request, &payload_len, &payload)) {
    coap_log_err("coap_get_data failed\n");
    return;
  }
  if (payload_len != (PUBLIC_KEY_COMPRESSED_SIZE /* ephemeral public key */
                      + (WITH_TRAP ? 0 : SIGNATURE_SIZE)
                      + COAP_BAKERY_COOKIE_SIZE)) {
    coap_log_err("register message has an unexpected length %zu\n",
                 payload_len);
    return;
  }

#if WITH_TRAP
  /* check cookie */
  if (!coap_bakery_check_cookie(payload + PUBLIC_KEY_COMPRESSED_SIZE,
                                coap_session_get_addr_remote(session))) {
    coap_log_err("coap_bakery_check_cookie failed\n");
    return;
  }
#endif /* WITH_TRAP */

  /* create ocall */
  std::unique_ptr<Ocall> ocall =
      ocall_factory_.createOcallWithRegisterData(
          std::move(std::make_unique<Ocall>()),
          request,
          payload
#if !WITH_TRAP
          , payload + PUBLIC_KEY_COMPRESSED_SIZE,
          payload + PUBLIC_KEY_COMPRESSED_SIZE + SIGNATURE_SIZE,
          coap_session_get_addr_remote(session)
#endif /* !WITH_TRAP */
      );
  if (!ocall) {
    coap_log_err("OcallFactory::createOcallWithRegisterData failed\n");
    return;
  }

  /* create registration or take equivalent one */
  Registration *registration = findOngoingRegistration(payload + 1,
                                                       ECC_CURVE_P_256_SIZE);
  if (!registration) {
    /* create registration */
    std::unique_ptr<Registration> new_registration =
        std::make_unique<Registration>(payload + 1);
    registration = new_registration.get();
    tentative_registrations_.push_front(std::move(new_registration));
  }

  /* store objects for next steps */
  IotRequest *iot_request = new IotRequest(registration, session, request);
  ocall->setRequest(iot_request);
  pending_ocalls_.push(std::move(ocall));
}

void
CoapServer::onReport(Request *request,
                     coap_bin_const_t *token,
                     uint8_t *report,
                     size_t report_size) {
  coap_log_debug("onReport\n");

  IotRequest *iot_request = (IotRequest *)request;
  Registration *registration = iot_request->getRegistration();

  try {
    /* check result */
    if (!report_size) {
      throw __LINE__;
    }

    /* update session */
    registration->setSession(iot_request->getSession());

    /* create response */
    coap_pdu_t *response = pdu_factory_.createPdu(
                               iot_request->getType() == COAP_MESSAGE_CON
                               ? COAP_MESSAGE_ACK
                               : COAP_MESSAGE_NON,
                               COAP_RESPONSE_CODE_CONTENT,
                               iot_request->getMid(),
                               token,
                               nullptr,
                               report,
                               report_size);
    if (!response) {
      throw __LINE__;
    }

    /* send response */
    coap_mid_t mid = coap_send(iot_request->getSession(), response);
    if (mid == COAP_INVALID_MID) {
      throw __LINE__;
    }

    /* move to ongoing registrations */
    for (auto it = tentative_registrations_.begin();
         it != tentative_registrations_.end();
         it++) {
      if (registration == it->get()) {
        ongoing_registrations_.push_front(std::move(*it));
        tentative_registrations_.erase(it);
        break;
      }
    }
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::onReport\n", l);

    /* remove the failed registration */
    for (auto it = tentative_registrations_.begin();
         it != tentative_registrations_.end();
         it++) {
      if (registration == it->get()) {
        tentative_registrations_.erase(it);
        break;
      }
    }
  }
  iot_request->dereference();
}

void
CoapServer::handleUnknownCallback(coap_resource_t *resource,
                                  coap_session_t *session,
                                  const coap_pdu_t *request,
                                  const coap_string_t *query,
                                  coap_pdu_t *response) {
  (void)resource;
  (void)query;
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log_err("coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_context_get_app_data(context);
  coap_server->handleUnknown(session, request, response);
}

void
CoapServer::handleUnknown(coap_session_t *session,
                          const coap_pdu_t *request,
                          coap_pdu_t *response) {
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);

  coap_log_debug("handleUnknown\n");

  /* read OSCORE-NG option */
  oscore_ng_option_data_t option_data;
  if (!parseOscoreNgOption(&option_data, request, true)) {
    coap_log_warn("parseOscoreNgOption failed\n");
    return;
  }
  bool is_disclose = option_data.kid_context.len != 0;
  if (is_disclose
      && (option_data.kid_context.len < MIN_DISCLOSE_KID_CONTEXT_LEN)) {
    coap_log_warn("kid context is too short\n");
    return;
  }

  /* find registration */
  Registration *registration;
  if (is_disclose) {
    registration = findOngoingRegistration(option_data.kid_context.u8,
                                           option_data.kid_context.len);
    if (!registration) {
      /* might be a retransmision */
      registration = findRegistration(coap_session_get_addr_remote(session));
    }
  } else {
    registration = findRegistration(coap_session_get_addr_remote(session));
  }
  if (!registration) {
    coap_log_err("Registration not found\n");
    return;
  }

  /* create ocall */
  std::unique_ptr<Ocall> ocall =
      ocall_factory_.createOcallWithOscoreNgData(
          std::move(std::make_unique<Ocall>()),
          request,
          &option_data,
          &option_data.kid,
          &kMiddleboxId,
          is_disclose
          ? FILTERING_OCALL_DISCLOSE_MESSAGE
          : FILTERING_OCALL_OSCORE_NG_MESSAGE);
  if (!ocall) {
    coap_log_err("OcallFactory::createDiscloseOrOscoreNgOcall failed\n");
    return;
  }

  /* store objects for next steps */
  IotRequest *iot_request = new IotRequest(registration, session, request);
  ocall->setRequest(iot_request);
  pending_ocalls_.push(std::move(ocall));
}

int
CoapServer::parseOscoreNgOption(oscore_ng_option_data_t *option_data,
                                const coap_pdu_t *pdu,
                                bool is_request) {
  coap_opt_iterator_t oi;
  coap_opt_t *oscore_ng_option = coap_check_option(pdu,
                                                   COAP_OPTION_OSCORE,
                                                   &oi);
  if (!oscore_ng_option) {
    coap_log_warn("OSCORE-NG option is missing\n");
    return 0;
  }
  if (!oscore_ng_decode_option(option_data,
                               coap_pdu_get_mid(pdu),
                               is_request,
                               coap_opt_value(oscore_ng_option),
                               coap_opt_length(oscore_ng_option))) {
    coap_log_warn("oscore_ng_decode_option failed\n");
    return 0;
  }
  return 1;
}

void
CoapServer::onDiscloseAnswer(Request *request,
                             coap_bin_const_t *token,
                             const filtering_ocall_oscore_ng_data_t *data) {
  IotRequest *iot_request = (IotRequest *)request;
  Registration *registration = iot_request->getRegistration();

  try {
    if (!data) {
      throw __LINE__;
    }

    if (!registration->isComplete()) {
      registration->complete(&data->client_id);

      /* look for other completed registrations of that IoT device */
      bool exists = false;
      for (auto it = completed_registrations_.begin();
           it != completed_registrations_.end();
           it++) {
        if ((registration != it->get())
            && oscore_ng_are_ids_equal(registration->getIotDeviceId(),
                                       it->get()->getIotDeviceId())) {
          coap_log_info("Updating other completed registration\n");
          it->get()->setSession(iot_request->getSession());
          exists = true;
          break;
        }
      }

      /* move to completed registrations */
      cleanUpOngoingRegistrations();
      for (auto it = ongoing_registrations_.begin();
           it != ongoing_registrations_.end();
           it++) {
        if (registration == it->get()) {
          if (!exists) {
            completed_registrations_.push_front(std::move(*it));
          }
          ongoing_registrations_.erase(it);
          break;
        }
      }
    }

    /* acknowledge disclose */
    coap_pdu_t *pdu = pdu_factory_.createPdu(
                          data->pdu_type,
                          COAP_RESPONSE_CODE_CHANGED,
                          iot_request->getMid(),
                          token,
                          &data->option_data,
                          data->ciphertext,
                          data->ciphertext_len);
    if (!pdu) {
      throw __LINE__;
    }
    if (coap_send(iot_request->getSession(), pdu) == COAP_INVALID_MID) {
      throw __LINE__;
    }
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::onDiscloseAnswer\n", l);
  }
  iot_request->dereference();
}

void
CoapServer::onOscoreNgAnswer(Request *request,
                             coap_bin_const_t *token,
                             const filtering_ocall_oscore_ng_data_t *data) {
  coap_log_info("onOscoreNgAnswer\n");
  IotRequest *iot_request = (IotRequest *)request;

  try {
    if (!data) {
      throw __LINE__;
    }

    /* acknowledge OSCORE-NG message */
    coap_pdu_t *pdu = pdu_factory_.createPdu(data->pdu_type,
                                             COAP_RESPONSE_CODE_CHANGED,
                                             iot_request->getMid(),
                                             token,
                                             &data->option_data,
                                             data->ciphertext,
                                             data->ciphertext_len);
    if (!pdu) {
      throw __LINE__;
    }
    if (coap_send(iot_request->getSession(), pdu) == COAP_INVALID_MID) {
      throw __LINE__;
    }
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::onOscoreNgAnswer\n", l);
  }
  iot_request->dereference();
}

void
CoapServer::handleProxyRequestCallback(coap_resource_t *resource,
                                       coap_session_t *session,
                                       const coap_pdu_t *request,
                                       const coap_string_t *query,
                                       coap_pdu_t *response) {
  (void)resource;
  (void)query;
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log_err("coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_context_get_app_data(context);
  coap_server->handleProxyRequest(session, request, response);
}

void
CoapServer::handleProxyRequest(coap_session_t *session,
                               const coap_pdu_t *request,
                               coap_pdu_t *response) {
  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);

  /* extract and check options */
  oscore_ng_option_data_t option_data;
  if (!parseOscoreNgOption(&option_data, request, true)) {
    coap_log_warn("parseOscoreNgOption failed\n");
    return;
  }
  coap_opt_iterator_t oi;
  coap_opt_t *proxy_scheme_option = coap_check_option(request,
                                                      COAP_OPTION_PROXY_SCHEME,
                                                      &oi);
  if (!proxy_scheme_option) {
    coap_log_warn("Proxy-Scheme option must be provided\n");
    return;
  }
  if ((coap_opt_length(proxy_scheme_option) != (sizeof(kCoapUriScheme) - 1))
      || std::strncmp((const char *)coap_opt_value(proxy_scheme_option),
                      kCoapUriScheme,
                      sizeof(kCoapUriScheme) - 1)) {
    coap_log_warn("Invalid Proxy-Scheme option\n");
    return;
  }
  coap_opt_t *uri_host = coap_check_option(request,
                                           COAP_OPTION_URI_HOST,
                                           &oi);
  if (!uri_host) {
    coap_log_warn("URI-Host option is mandatory\n");
    return;
  }
  if (coap_opt_length(uri_host) > MAX_URI_HOST_LENGTH) {
    coap_log_warn("URI-Host option too long\n");
    return;
  }
  char host[MAX_URI_HOST_LENGTH + 1];
  std::memcpy(host,
              (const char *)coap_opt_value(uri_host),
              coap_opt_length(uri_host));
  host[coap_opt_length(uri_host)] = '\0';
  if (coap_check_option(request, COAP_OPTION_URI_PORT, &oi)) {
    /* we forward everything on the session established during registration */
    coap_log_warn("Ignoring URI-Port option\n");
  }

  /* look up registration */
  coap_address_t iot_device_address;
  if (!resolveAddress(host, nullptr, &iot_device_address)) {
    coap_log_err("resolveAddress failed\n");
    return;
  }
  Registration *registration = findRegistration(&iot_device_address);
  if (!registration) {
    coap_log_err("findRegistration returned NULL\n");
    return;
  }

  /* create ocall */
  std::unique_ptr<Ocall> ocall =
      ocall_factory_.createOcallWithOscoreNgData(
          std::move(std::make_unique<Ocall>()),
          request,
          &option_data,
          &option_data.kid,
          registration->getIotDeviceId(),
          FILTERING_OCALL_PROXY_REQUEST_MESSAGE);
  if (!ocall) {
    coap_log_err("OcallFactory::createDiscloseOrOscoreNgOcall failed\n");
    return;
  }

  /* create new ProxiedReqeust */
  std::unique_ptr<ProxiedRequest> proxied_request =
      std::make_unique<ProxiedRequest>(registration,
                                       session,
                                       request,
                                       &option_data.kid);

  /* store objects for next steps */
  ocall->setRequest(proxied_request.get());
  registration->addProxiedRequest(std::move(proxied_request));
  pending_ocalls_.push(std::move(ocall));
}

void
CoapServer::onProxyRequestAnswer(Request *request,
                                 coap_bin_const_t *token,
                                 const filtering_ocall_oscore_ng_data_t *data) {
  /* get corresponding ProxiedRequest */
  ProxiedRequest *proxied_request = (ProxiedRequest *)request;
  Registration *registration = proxied_request->getRegistration();
  proxied_request->dereference();

  try {
    /* data == NULL <=> inauthentic or replayed or rate violation */
    if (!data) {
      throw __LINE__;
    }

    /* check for duplicate */
    ProxiedRequest *duplicate =
        registration->findDuplicateProxiedRequest(proxied_request);
    if (duplicate) {
      duplicate->prolongLifetime();
    } else {
      proxied_request->setNewMessageId(data->option_data.e2e_message_id);
    }

    /* create PDU */
    /* TODO retain Class I and U options */
    coap_pdu_t *pdu = pdu_factory_.createPdu(data->pdu_type,
                                             COAP_REQUEST_CODE_POST,
                                             data->option_data.e2e_message_id,
                                             token,
                                             &data->option_data,
                                             data->ciphertext,
                                             data->ciphertext_len);
    if (!pdu) {
      throw __LINE__;
    }
    if (coap_send(registration->getSession(), pdu) == COAP_INVALID_MID) {
      throw __LINE__;
    }
    coap_log_info("Forwarding request\n");
  } catch (int l) {
    coap_log_err("error on line %i in CoapServer::onProxyRequestAnswer\n", l);
    registration->eraseProxiedRequest(proxied_request);
  }
}

coap_response_t
CoapServer::onResponseCallback(coap_session_t *session,
                               const coap_pdu_t *sent,
                               const coap_pdu_t *received,
                               const coap_mid_t mid) {
  (void)sent;
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log_err("coap_session_get_context returned NULL\n");
    return COAP_RESPONSE_FAIL;
  }
  CoapServer *coap_server = (CoapServer *)coap_context_get_app_data(context);
  return coap_server->onResponse(session, received, mid);
}

coap_response_t
CoapServer::onResponse(coap_session_t *session,
                       const coap_pdu_t *received,
                       const coap_mid_t mid) {

  /* parse response */
  if (coap_pdu_get_type(received) == COAP_MESSAGE_CON) {
    coap_log_warn("Ignoring unexpected response type\n");
    /* TODO forward as CON */
    return COAP_RESPONSE_FAIL;
  }
  if (coap_pdu_get_code(received) != COAP_RESPONSE_CODE_CHANGED) {
    coap_log_warn("Ignoring unexpected response code %i\n",
                  coap_pdu_get_code(received));
    return COAP_RESPONSE_FAIL;
  }
  oscore_ng_option_data_t option_data;
  if (!parseOscoreNgOption(&option_data, received, false)) {
    coap_log_warn("parseOscoreNgOption failed\n");
    return COAP_RESPONSE_FAIL;
  }

  /* find corresponding ProxiedRequest */
  Registration *registration =
      findRegistration(coap_session_get_addr_remote(session));
  if (!registration) {
    coap_log_warn("No registration happened on this session\n");
    return COAP_RESPONSE_FAIL;
  }
  /* TODO this lookup works because libcoap echoes the Message ID in NON
   * responses. This is not necessarily the case for other CoAP
   * implementations. We should rather use tokens for request/response matching
   * here. Besides, we need to handle observe notifications somehow in here. */
  ProxiedRequest *proxied_request = registration->findProxiedRequest(mid);
  if (!proxied_request) {
    coap_log_warn("Could not find corresponding ProxiedRequest\n");
    return COAP_RESPONSE_FAIL;
  }

  /* create ocall */
  std::unique_ptr<Ocall> ocall =
      ocall_factory_.createOcallWithOscoreNgData(
          std::move(std::make_unique<Ocall>()),
          received,
          &option_data,
          proxied_request->getIotClientId(),
          registration->getIotDeviceId(),
          FILTERING_OCALL_PROXY_RESPONSE_MESSAGE);
  if (!ocall) {
    coap_log_err("OcallFactory::createProxyResponseOcall failed\n");
    return COAP_RESPONSE_FAIL;
  }
  ocall->setRequest(proxied_request);

  /* forward to enclave */
  proxied_request->reference();
  pending_ocalls_.push(std::move(ocall));
  return COAP_RESPONSE_OK;
}

void
CoapServer::onProxyResponseAnswer(Request *request,
                                  coap_bin_const_t *token,
                                  const filtering_ocall_oscore_ng_data_t *data) {
  /* get corresponding ProxiedRequest */
  ProxiedRequest *proxied_request = (ProxiedRequest *)request;
  Registration *registration = proxied_request->getRegistration();
  proxied_request->dereference();

  /* data == NULL means drop */
  if (!data) {
    coap_log_info("Dropping response\n");
    return;
  }

  coap_log_info("Forwarding response\n");
  coap_pdu_t *pdu = pdu_factory_.createPdu(
                        data->pdu_type,
                        COAP_RESPONSE_CODE_CHANGED,
                        proxied_request->getMid(),
                        token,
                        &data->option_data,
                        data->ciphertext,
                        data->ciphertext_len);
  if (!pdu) {
    coap_log_err("PduFactory::createPdu failed\n");
    return;
  }
  coap_mid_t mid = coap_send(proxied_request->getSession(), pdu);
  if (mid == COAP_INVALID_MID) {
    coap_log_err("coap_send failed\n");
    return;
  }
  registration->eraseProxiedRequest(proxied_request);
}

std::unique_ptr<Ocall>
CoapServer::waitForOcall() {
  while (pending_ocalls_.empty()) {
    coap_io_process(coap_context_, COAP_IO_WAIT);
  }

  std::unique_ptr<Ocall> next_ocall = std::move(pending_ocalls_.front());
  pending_ocalls_.pop();
  return next_ocall;
}

Registration *
CoapServer::findOngoingRegistration(const uint8_t *ephemeral_public_key_head,
                                    size_t head_len) {
  cleanUpOngoingRegistrations();
  for (auto it = ongoing_registrations_.begin();
       it != ongoing_registrations_.end();
       it++) {
    if (it->get()->isIotDevicesEphemeralPublicKey(ephemeral_public_key_head,
                                                  head_len)) {
      return it->get();
    }
  }
  return nullptr;
}

Registration *
CoapServer::findRegistration(const coap_address_t *iot_device_address) {
  for (auto it = completed_registrations_.begin();
       it != completed_registrations_.end();
       it++) {
    if (it->get()->hasAddress(iot_device_address)) {
      return it->get();
    }
  }
  return nullptr;
}

void
CoapServer::cleanUpOngoingRegistrations(void) {
  constexpr std::chrono::seconds max_age{60};
  std::chrono::time_point<std::chrono::steady_clock> now =
      std::chrono::steady_clock::now();

  for (auto it = ongoing_registrations_.begin();
       it != ongoing_registrations_.end();
       it++) {
    if (it->get()->isReferenced()) {
      continue;
    }
    if ((now - it->get()->getCreationTime()) > max_age) {
      coap_log_info("Removing ongoing registration\n");
      it = ongoing_registrations_.erase(it);
    }
  }
}

CoapServer::~CoapServer() {
  cleanUp();
}

void
CoapServer::cleanUp() {
  coap_free_context(coap_context_);
  coap_context_ = nullptr;
  coap_cleanup();
}

} // namespace filtering
