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

#include <netdb.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#include <iomanip>

#include <verifier/Keys.hpp>
#include "filtering_ocall.h"

#define MAX_URI_HOST_LENGTH (127)
#define MAX_URI_PORT_LENGTH (7)
#define MAX_OPTION_HEADER_LENGTH (5)
#define PAYLOAD_MARKER_LENGTH (1)
#define STRINGIFY_HELPER(X) #X
#define STRINGIFY(X) STRINGIFY_HELPER(X)

namespace filtering {

const char CoapServer::kKnockPath[] = "kno";
const char CoapServer::kRegisterPath[] = "reg";
const char CoapServer::kCoapDefaultPort[] = STRINGIFY(COAP_DEFAULT_PORT);
const char CoapServer::kCoapUriScheme[] = "coap";

CoapServer::CoapServer()
{
  coap_context_ = nullptr;
}

int
CoapServer::start(const char *host, const char *port)
{
  updateCookieKey(); /* TODO do this regularly */
  coap_startup();
  try {
    coap_address_t address;

    if (!port) {
      port = kCoapDefaultPort;
    }
    if (resolveAddress(host, port, &address) < 0) {
      throw 1;
    }
    coap_context_ = coap_new_context(&address);
    if (!coap_context_) {
      throw 2;
    }
    coap_set_app_data(coap_context_, this);
    if (!createKnockResource()) {
      throw 3;
    }
    if (!createRegisterResource()) {
      throw 4;
    }
    if (!createProxyResource(host)) {
      throw 5;
    }
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::start\n", e);
    cleanUp();
    return 0;
  }
  coap_register_dispatch_hook(dispatchHookCallback);
  coap_register_nack_handler(coap_context_, onNackCallback);
  return 1;
}

void
CoapServer::updateCookieKey()
{
  syscall(SYS_getrandom, cookie_key_, sizeof(cookie_key_), 1);
  cookie_interval_++;
}

int
CoapServer::resolveAddress(const char *host,
    const char *service,
    coap_address_t *address)
{
  struct addrinfo *ai_list_head;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  memset(address, 0, sizeof(*address));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  int return_value = getaddrinfo(host, service, &hints, &ai_list_head);
  if (return_value) {
    coap_log(LOG_ERR, "resolveAddress failed due to %s\n",
        gai_strerror(return_value));
    return return_value;
  }

  return_value = -1;
  for (struct addrinfo *ai = ai_list_head; ai != NULL; ai = ai->ai_next) {
    switch (ai->ai_family) {
    case AF_INET6:
    case AF_INET:
      address->size = ai->ai_addrlen;
      memcpy(&address->addr.sin6, ai->ai_addr, address->size);
      return_value = 0;
      break;
    default:
      break;
    }
  }
  freeaddrinfo(ai_list_head);
  return return_value;
}

int
CoapServer::createKnockResource()
{
  coap_str_const_t *ruri = coap_make_str_const(kKnockPath);
  coap_resource_t *resource = coap_resource_init(ruri, 0);
  if (!resource) {
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handleKnockCallback);
  coap_add_resource(coap_context_, resource);
  return 1;
}

void
CoapServer::handleKnockCallback(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log(LOG_ERR, "coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_get_app_data(context);
  coap_server->handleKnock(resource,
      session,
      request,
      query,
      response);
}

void
CoapServer::handleKnock(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  size_t data_length;
  const uint8_t *data;

  /* check padding bytes */
  if (!coap_get_data(request, &data_length, &data)) {
    coap_log(LOG_ERR, "coap_get_data failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  if (data_length < COAP_SERVER_COOKIE_LEN) {
    coap_log(LOG_ERR, "knock without sufficient padding bytes\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
  }

  /* TODO rate limitation */

  /* create response */
  uint8_t *response_data =
      coap_add_data_after(response, COAP_SERVER_COOKIE_LEN);
  if (!response_data) {
    coap_log(LOG_ERR, "coap_add_data_after failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  const coap_address_t *iot_device_address =
      coap_session_get_addr_remote(session);
  if (!iot_device_address) {
    coap_log(LOG_ERR, "coap_session_get_addr_remote failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  generateCookie(iot_device_address, response_data);
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  return;
}

int
CoapServer::generateCookie(const coap_address_t *address,
    uint8_t cookie[COAP_SERVER_COOKIE_LEN])
{
  uint8_t hmic[SHA_256_DIGEST_LENGTH];

  switch(address->addr.sa.sa_family) {
  case AF_INET:
    sha_256_hmac(cookie_key_,
        sizeof(cookie_key_),
        (uint8_t *)&address->addr.sin.sin_addr.s_addr,
        sizeof(address->addr.sin.sin_addr.s_addr),
        hmic);
    break;
  case AF_INET6:
    sha_256_hmac(cookie_key_,
        sizeof(cookie_key_),
        address->addr.sin6.sin6_addr.s6_addr,
        sizeof(address->addr.sin6.sin6_addr.s6_addr),
        hmic);
    break;
  default:
    return 0;
  }
  std::memcpy(cookie,
      hmic,
      SHA_256_DIGEST_LENGTH / 2);
  std::memcpy(cookie + (SHA_256_DIGEST_LENGTH / 2),
      &cookie_interval_,
      sizeof(uint32_t));
  return 1;
}

int
CoapServer::checkCookie(const uint8_t cookie[COAP_SERVER_COOKIE_LEN],
      const coap_address_t *address)
{
  uint8_t expected_cookie[COAP_SERVER_COOKIE_LEN];

  generateCookie(address, expected_cookie);

  return !std::memcmp(expected_cookie, cookie, COAP_SERVER_COOKIE_LEN);
}

int
CoapServer::createRegisterResource()
{
  coap_str_const_t *ruri = coap_make_str_const(kRegisterPath);
  coap_resource_t *resource = coap_resource_init(ruri, 0);
  if (!resource) {
    return 0;
  }
  coap_register_handler(resource, COAP_REQUEST_GET, handleRegisterCallback);
  coap_add_resource(coap_context_, resource);
  return 1;
}

void
CoapServer::handleRegisterCallback(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log(LOG_ERR, "coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_get_app_data(context);
  coap_server->handleRegister(resource,
      session,
      request,
      query,
      response);
}

void
CoapServer::handleRegister(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  size_t data_length;
  const uint8_t *data;

  coap_log(LOG_DEBUG, "handleRegister\n");

  /* find out sender */
  const coap_address_t *iot_device_address =
      coap_session_get_addr_remote(session);
  if (!iot_device_address) {
    coap_log(LOG_ERR, "coap_session_get_addr_remote failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }

  /* extract payload */
  if (!coap_get_data(request, &data_length, &data)) {
    coap_log(LOG_ERR, "coap_get_data failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  if (data_length != ((1 + uECC_BYTES) /* compressed ephemeral public key */
                      + (2 * uECC_BYTES) /* signature */
                      + COAP_SERVER_COOKIE_LEN /* cookie */)) {
    coap_log(LOG_ERR, "register message has an unexpected length\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
  }

  /* check cookie */
  if (!checkCookie(data + uECC_BYTES + 1 + uECC_BYTES * 2,
      iot_device_address)) {
    coap_log(LOG_ERR, "checkCookie failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
  }

  /* check if this is a retransmission */
  Registration *ongoingRegistration =
      findOngoingRegistration(iot_device_address);
  if (ongoingRegistration) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    uint8_t *response_data = coap_add_data_after(response,
        ATTESTATION_REPORT_COMPRESSED_LEN);
    if (!response_data) {
      coap_log(LOG_ERR, "coap_add_data_after failed\n");
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
      return;
    }
    ongoingRegistration->getCompressedReport(response_data);
    return;
  }

  /* create registration */
  std::unique_ptr<Registration> new_registration =
      std::make_unique<Registration>();
  if(!new_registration->init(coap_pdu_get_mid(request),
      coap_context_,
      iot_device_address,
      data)) {
    coap_log(LOG_ERR, "Registration::init failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  new_registration->cache(session, coap_pdu_get_mid(request));

  /* create ocall */
  std::unique_ptr<Ocall> register_ocall = std::make_unique<Ocall>();
  if (!register_ocall->init(FILTERING_OCALL_REGISTER_MESSAGE,
      sizeof(register_data_t))) {
    coap_log(LOG_ERR, "Ocall::init failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  register_data_t *register_data =
      (register_data_t *)register_ocall->getPayload();
  std::memcpy(register_data->iot_devices_ephemeral_public_key_compressed,
      data,
      sizeof(register_data->iot_devices_ephemeral_public_key_compressed));
  std::memcpy(register_data->signature,
      data + uECC_BYTES + 1,
      sizeof(register_data->signature));
  new_registration->getIotDeviceId(register_data->iot_device_id,
      &register_data->iot_device_id_len);
  register_ocall->setPointer(new_registration.get());

  /* store objects for next steps */
  pending_ocalls_.push(std::move(register_ocall));
  unproven_registrations_.push_front(std::move(new_registration));

  /* suppress empty ACK */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);
}

void
CoapServer::onReport(void *ptr, const struct report_t *report)
{
  Registration *registration = (Registration *)ptr;
  coap_pdu_t *response = nullptr;

  coap_log(LOG_DEBUG, "onReport\n");

  /* ptr == NULL is just used for printing the hashes at start up */
  if (!registration) {
    assert(report);
    std::unique_ptr<AttestationReport> attestation_report =
        std::make_unique<AttestationReport>(report);
    attestation_report->printHashes();
    return;
  }

  try {
    /* check result */
    if (!report) {
      throw 1;
    }
    registration->onReport(report);

    /* create response */
    response = coap_pdu_init(COAP_MESSAGE_ACK,
        COAP_RESPONSE_CODE_CONTENT,
        registration->getCachedMid(),
        PAYLOAD_MARKER_LENGTH + ATTESTATION_REPORT_COMPRESSED_LEN);
    if (!response) {
      throw 2;
    }
    uint8_t *response_data = coap_add_data_after(response,
        ATTESTATION_REPORT_COMPRESSED_LEN);
    if (!response_data) {
      throw 3;
    }
    registration->getCompressedReport(response_data);

    /* remove other proven registrations of that IoT device, unless locked */
    for (auto it = proven_registrations_.begin();
        it != proven_registrations_.end();
        it++) {
      if (coap_address_equals(registration->getAddress(),
          it->get()->getAddress())) {
        if (it->get()->isLocked()) {
          throw 4;
        }
        coap_log(LOG_INFO, "Removing other proven registration\n");
        proven_registrations_.erase(it);
        break;
      }
    }

    /* send response */
    if (coap_send(registration->getCachedSession(), response)
        == COAP_INVALID_MID) {
      throw 5;
    }
    registration->clearCache();

    /* move to proven registrations */
    for (auto it = unproven_registrations_.begin();
        it != unproven_registrations_.end();
        it++) {
      if (registration == it->get()) {
        proven_registrations_.push_front(std::move(*it));
        unproven_registrations_.erase(it);
        return;
      }
    }
    assert(0);
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::onReport\n", e);
    coap_delete_pdu(response);
    response = coap_pdu_init(COAP_MESSAGE_ACK,
        COAP_RESPONSE_CODE_INTERNAL_ERROR,
        registration->getCachedMid(),
        0);
    if (!response) {
      coap_log(LOG_ERR, "coap_pdu_init failed\n");
    } else if (coap_send(registration->getCachedSession(), response)
        == COAP_INVALID_MID) {
      coap_log(LOG_ERR, "coap_send failed\n");
      coap_delete_pdu(response);
    }

    /* remove the failed registration */
    for (auto it = unproven_registrations_.begin();
        it != unproven_registrations_.end();
        it++) {
      if (registration == it->get()) {
        unproven_registrations_.erase(it);
        break;
      }
    }
  }
}

void
CoapServer::handleOscore(coap_session_t *session,
    const coap_pdu_t *request,
    const oscore_option_data_t *oscore_option_data,
    const coap_address_t *iot_device_address)
{
  size_t ciphertext_len;
  const uint8_t *ciphertext;

  coap_log(LOG_DEBUG, "handleOscore\n");

  /* find out if this is a disclose message */
  Registration *registration = findOngoingRegistration(iot_device_address);
  if (!registration) {
    /* might be a retransmision */
    /* TODO reply cached responses to retransmitted disclose messages */
    registration = findRegistration(iot_device_address);
  }
  bool isDisclose = registration
      && !registration->isLocked()
      && (oscore_option_data_get_sequence_number(oscore_option_data) <= 0xFF)
      && ((registration->getRegisterMid() + 1) == coap_pdu_get_mid(request));
  if (!isDisclose) {
    registration = findRegistration(iot_device_address);
    if (!registration || registration->isLocked()) {
      coap_log(LOG_ERR, "Registration not found or locked\n");
      return;
    }
  }

  /* create ocall */
  std::unique_ptr<Ocall> ocall = std::make_unique<Ocall>();
  if (!coap_get_data(request, &ciphertext_len, &ciphertext)) {
    coap_log(LOG_ERR, "coap_get_data failed\n");
    return;
  }
  if (!ocall->init(
      isDisclose
          ? FILTERING_OCALL_DISCLOSE_MESSAGE
          : FILTERING_OCALL_OSCORE_MESSAGE,
      sizeof(oscore_data_t) + ciphertext_len)) {
    coap_log(LOG_ERR, "Ocall::init failed\n");
    return;
  }
  ocall->setPointer(registration);

  /* populate oscore_data */
  oscore_data_t *oscore_data = (oscore_data_t *)ocall->getPayload();
  std::memcpy(&oscore_data->option_data,
      oscore_option_data,
      sizeof(oscore_option_data_t));
  registration->getIotDeviceId(oscore_data->iot_device_id,
      &oscore_data->iot_device_id_len);
  std::memcpy(oscore_data->ciphertext, ciphertext, ciphertext_len);
  oscore_data->ciphertext_len = ciphertext_len;

  /* store objects for next steps */
  registration->lock();
  registration->cache(session, coap_pdu_get_mid(request));
  pending_ocalls_.push(std::move(ocall));
}

void
CoapServer::onDiscloseAnswer(void *ptr, oscore_data_t *data)
{
  coap_pdu_t *pdu = nullptr;

  Registration *registration = (Registration *)ptr;
  registration->unlock();

  try {
    uint8_t oscore_option_value[OSCORE_OPTION_MAX_VALUE_LENGTH];
    size_t oscore_option_length;

    if (!data) {
      throw 1;
    }

    /* remove other complete registrations of that IoT device */
    for (auto it = completed_registrations_.begin();
        it != completed_registrations_.end();
        it++) {
      if ((registration != it->get())
          && coap_address_equals(registration->getAddress(),
              it->get()->getAddress())) {
        coap_log(LOG_INFO, "Removing other completed registration\n");
        completed_registrations_.erase(it);
        break;
      }
    }

    /* move to proven registrations */
    for (auto it = proven_registrations_.begin();
        it != proven_registrations_.end();
        it++) {
      if (registration == it->get()) {
        completed_registrations_.push_front(std::move(*it));
        proven_registrations_.erase(it);
        break;
      }
    }

    /* acknowledge disclose */
    pdu = coap_pdu_init(COAP_MESSAGE_ACK,
        COAP_RESPONSE_CODE_CHANGED,
        registration->getCachedMid(),
        MAX_OPTION_HEADER_LENGTH
            + OSCORE_OPTION_MAX_VALUE_LENGTH
            + PAYLOAD_MARKER_LENGTH
            + data->ciphertext_len);
    if (!pdu) {
      throw 2;
    }
    oscore_option_encode(oscore_option_value,
        &oscore_option_length,
        &data->option_data,
        0);
    if (!coap_add_option(pdu,
        COAP_OPTION_OSCORE,
        oscore_option_length,
        oscore_option_value)) {
      throw 3;
    }
    if (!coap_add_data(pdu, data->ciphertext_len, data->ciphertext)) {
      throw 4;
    }
    if (coap_send(registration->getCachedSession(), pdu) == COAP_INVALID_MID) {
      throw 5;
    }
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::onDiscloseAnswer\n", e);
    coap_delete_pdu(pdu);
  }
  registration->clearCache();
}

void
CoapServer::onOscoreAnswer(void *ptr, oscore_data_t *data)
{
  coap_pdu_t *pdu = nullptr;

  Registration *registration = (Registration *)ptr;
  registration->unlock();

  try {
    uint8_t oscore_option_value[OSCORE_OPTION_MAX_VALUE_LENGTH];
    size_t oscore_option_length;

    if (!data) {
      throw 1;
    }

    /* acknowledge OSCORE message */
    pdu = coap_pdu_init(COAP_MESSAGE_ACK,
        COAP_RESPONSE_CODE_CHANGED,
        registration->getCachedMid(),
        MAX_OPTION_HEADER_LENGTH
            + OSCORE_OPTION_MAX_VALUE_LENGTH
            + PAYLOAD_MARKER_LENGTH
            + data->ciphertext_len);
    if (!pdu) {
      throw 2;
    }
    oscore_option_encode(oscore_option_value,
        &oscore_option_length,
        &data->option_data,
        0);
    if (!coap_add_option(pdu,
        COAP_OPTION_OSCORE,
        oscore_option_length,
        oscore_option_value)) {
      throw 3;
    }
    if (!coap_add_data(pdu, data->ciphertext_len, data->ciphertext)) {
      throw 4;
    }
    if (coap_send(registration->getCachedSession(), pdu) == COAP_INVALID_MID) {
      throw 5;
    }
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::onOscoreAnswer\n", e);
    coap_delete_pdu(pdu);
  }
  registration->clearCache();
}

int
CoapServer::createProxyResource(const char *host)
{
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

void
CoapServer::handleProxyRequestCallback(coap_resource_t *resource,
   coap_session_t *session,
   const coap_pdu_t *request,
   const coap_string_t *query,
   coap_pdu_t *response)
{
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log(LOG_ERR, "coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_get_app_data(context);
  coap_server->handleProxyRequest(resource,
      session,
      request,
      query,
      response);
}

void
CoapServer::handleProxyRequest(coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
  coap_opt_iterator_t oi;
  char host[MAX_URI_HOST_LENGTH + 1];
  char port[MAX_URI_PORT_LENGTH + 1];
  coap_address_t iot_device_address;
  size_t ciphertext_len;
  const uint8_t *ciphertext;

  /* extract and check options */
  coap_opt_t *oscore_option = coap_check_option(request,
      COAP_OPTION_OSCORE,
      &oi);
  if (!oscore_option) {
    coap_log(LOG_WARNING, "Discarding CoAP request with no OSCORE Option\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  coap_opt_t *proxy_uri_option = coap_check_option(request,
      COAP_OPTION_PROXY_URI,
      &oi);
  if (proxy_uri_option) {
    coap_log(LOG_WARNING, "Proxy-URI option must not be provided\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  coap_opt_t *proxy_scheme_option = coap_check_option(request,
      COAP_OPTION_PROXY_SCHEME,
      &oi);
  assert(proxy_scheme_option);
  if ((coap_opt_length(proxy_scheme_option) != (sizeof(kCoapUriScheme) - 1))
      || std::strncmp((const char *)coap_opt_value(proxy_scheme_option),
          kCoapUriScheme,
          sizeof(kCoapUriScheme) - 1)) {
    coap_log(LOG_WARNING, "invalid Proxy-Scheme option\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  coap_opt_t *uri_host = coap_check_option(request, COAP_OPTION_URI_HOST, &oi);
  if (!uri_host) {
    coap_log(LOG_WARNING, "URI host option must be provided\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  if (coap_opt_length(uri_host) > MAX_URI_HOST_LENGTH) {
    coap_log(LOG_WARNING, "URI host option too long\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  memcpy(host, (const char *)coap_opt_value(uri_host), coap_opt_length(uri_host));
  host[coap_opt_length(uri_host)] = '\0';
  coap_opt_t *uri_port = coap_check_option(request, COAP_OPTION_URI_PORT, &oi);
  if (uri_port) {
    if (coap_opt_length(uri_port) > MAX_URI_PORT_LENGTH) {
      coap_log(LOG_WARNING, "URI port option too long\n");
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
      return;
    }
    memcpy(port, (const char *)coap_opt_value(uri_port), coap_opt_length(uri_port));
    port[coap_opt_length(uri_port)] = '\0';
  } else {
    memcpy(port, kCoapDefaultPort, sizeof(kCoapDefaultPort));
  }

  /* look up registration */
  int resolve_result = resolveAddress(host, port, &iot_device_address);
  if (resolve_result < 0) {
    coap_log(LOG_ERR, "resolveAddress failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  Registration *registration = findRegistration(&iot_device_address);
  if (!registration) {
    coap_log(LOG_ERR, "findRegistration returned NULL\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }

  /* create proxy request */
  std::unique_ptr<Ocall> proxy_request_ocall = std::make_unique<Ocall>();
  if (!coap_get_data(request, &ciphertext_len, &ciphertext)) {
    coap_log(LOG_ERR, "coap_get_data failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  if (!proxy_request_ocall->init(FILTERING_OCALL_PROXY_REQUEST_MESSAGE,
      sizeof(oscore_data_t) + ciphertext_len)) {
    coap_log(LOG_ERR, "Ocall::init failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }

  /* populate oscore_data */
  oscore_data_t *oscore_data =
      (oscore_data_t *)proxy_request_ocall->getPayload();
  registration->getIotDeviceId(oscore_data->iot_device_id,
      &oscore_data->iot_device_id_len);
  if (!oscore_option_decode(&oscore_data->option_data,
      coap_opt_value(oscore_option), coap_opt_length(oscore_option))) {
    coap_log(LOG_ERR, "oscore_option_decode failed\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED);
    return;
  }
  std::memcpy(oscore_data->ciphertext, ciphertext, ciphertext_len);
  oscore_data->ciphertext_len = ciphertext_len;

  if (haveOngoingProxyRequest(oscore_data)) {
    coap_log(LOG_ERR, "still awaiting a response to this request\n");
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_TOO_MANY_REQUESTS);
    return;
  }
  std::unique_ptr<ProxiedRequest> proxied_request =
      std::make_unique<ProxiedRequest>(session,
          request,
          &iot_device_address,
          oscore_data);
  proxy_request_ocall->setPointer(proxied_request.get());

  /* store objects for next steps */
  pending_ocalls_.push(std::move(proxy_request_ocall));
  proxied_requests_.push_front(std::move(proxied_request));

  /* these two lines cause the ACK to be suppressed */
  coap_pdu_set_code(response, COAP_EMPTY_CODE);
  coap_pdu_set_type(response, COAP_MESSAGE_NON);
}

void
CoapServer::onProxyRequestAnswer(void *ptr, oscore_data_t *data)
{
  coap_pdu_t *pdu = nullptr;

  /* get corresponding ProxiedRequest */
  ProxiedRequest *proxied_request = (ProxiedRequest *)ptr;
  assert(proxied_request);

  try {
    uint8_t oscore_option_value[OSCORE_OPTION_MAX_VALUE_LENGTH];
    size_t oscore_option_length;

    /* data == NULL denotes an inauthentic or replayed or rate violation */
    if (!data) {
      throw 1;
    }
    coap_log(LOG_DEBUG, "shall forward request\n");

    /* create PDU */
    Registration *registration =
        findRegistration(proxied_request->getIotDeviceAddress());
    if (!registration) {
      throw 2;
    }
    pdu = coap_pdu_init(COAP_MESSAGE_CON,
        COAP_REQUEST_CODE_POST,
        coap_new_message_id(registration->getSession()),
        MAX_OPTION_HEADER_LENGTH
            + OSCORE_OPTION_MAX_VALUE_LENGTH
            + PAYLOAD_MARKER_LENGTH
            + data->ciphertext_len);
    if (!pdu) {
      throw 3;
    }
    /* TODO retain Class I and U options */
    oscore_option_encode(oscore_option_value,
        &oscore_option_length,
        &data->option_data,
        1);
    if (!coap_add_option(pdu,
        COAP_OPTION_OSCORE,
        oscore_option_length,
        oscore_option_value)) {
      throw 4;
    }
    if (!coap_add_data(pdu, data->ciphertext_len, data->ciphertext)) {
      throw 5;
    }
    coap_mid_t mid = coap_send(registration->getSession(), pdu);
    if (mid == COAP_INVALID_MID) {
      throw 6;
    }

    /* store message ID for later */
    proxied_request->setNewMessageId(mid);

    /* create a dummy_pdu to cancel libcoap's retransmission process */
    coap_pdu_t *dummy_pdu =
        coap_pdu_init(COAP_MESSAGE_ACK, COAP_EMPTY_CODE, mid, 0);
    if (!dummy_pdu) {
      coap_log(LOG_ERR, "coap_pdu_init failed\n");
    } else {
      coap_do_dispatch(coap_context_, registration->getSession(), dummy_pdu);
    }
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::onProxyRequestAnswer\n", e);
    coap_delete_pdu(pdu);
    for (auto it = proxied_requests_.begin();
        it != proxied_requests_.end();
        it++) {
      if (proxied_request == it->get()) {
        proxied_requests_.erase(it);
        break;
      }
    }
  }
}

void
CoapServer::dispatchHookCallback(coap_context_t *context,
      coap_session_t *session,
      coap_pdu_t *pdu)
{
  CoapServer *coap_server = (CoapServer *)coap_get_app_data(context);
  coap_server->dispatchHook(context, session, pdu);
}

void
CoapServer::dispatchHook(coap_context_t *context,
      coap_session_t *session,
      coap_pdu_t *pdu)
{
  coap_opt_iterator_t oi;
  size_t ciphertext_len;
  const uint8_t *ciphertext;

  coap_opt_t *oscore_option = coap_check_option(pdu, COAP_OPTION_OSCORE, &oi);

  /* find corresponding ProxiedRequest */
  coap_mid_t mid = coap_pdu_get_mid(pdu);
  const coap_address_t *source_address = coap_session_get_addr_remote(session);
  if (!source_address) {
    coap_log(LOG_ERR, "coap_session_get_addr_remote failed\n");
    return;
  }
  ProxiedRequest *proxied_request = findProxiedRequest(source_address, mid);
  if (!proxied_request) {
    if ((coap_pdu_get_code(pdu) == COAP_REQUEST_CODE_POST)
        && oscore_option
        && !coap_check_option(pdu, COAP_OPTION_PROXY_URI, &oi)
        && !coap_check_option(pdu, COAP_OPTION_PROXY_SCHEME, &oi)) {
      oscore_option_data_t option_data;

      /* looks like a message from an IoT device */
      if (!oscore_option_decode(&option_data,
          coap_opt_value(oscore_option),
          coap_opt_length(oscore_option))) {
        coap_log(LOG_WARNING, "oscore_option_decode failed\n");
        return;
      }
      const coap_address_t *iot_device_address =
          coap_session_get_addr_remote(session);
      if (!iot_device_address) {
        coap_log(LOG_WARNING, "coap_session_get_addr_remote failed\n");
        return;
      }
      handleOscore(session, pdu, &option_data, iot_device_address);
    } else {
      coap_do_dispatch(context, session, pdu);
    }
    return;
  }

  /* parse response */
  if (coap_pdu_get_type(pdu) != COAP_MESSAGE_ACK) {
    coap_log(LOG_WARNING, "Ignoring unexpected response type\n");
    return;
  }
  if (coap_pdu_get_code(pdu) != COAP_RESPONSE_CODE_CHANGED) {
    coap_log(LOG_WARNING, "Ignoring unexpected response code %i\n",
        coap_pdu_get_code(pdu));
    return;
  }
  if (!oscore_option) {
    coap_log(LOG_WARNING, "Ignoring response without OSCORE option\n");
    return;
  }
  if (!coap_get_data(pdu, &ciphertext_len, &ciphertext)) {
    coap_log(LOG_ERR, "coap_get_data failed\n");
    return;
  }

  /* create ocall */
  std::unique_ptr<Ocall> proxy_response_ocall = std::make_unique<Ocall>();
  if (!proxy_response_ocall->init(FILTERING_OCALL_PROXY_RESPONSE_MESSAGE,
      sizeof(oscore_data_t) + ciphertext_len)) {
    coap_log(LOG_ERR, "Ocall::init failed\n");
    return;
  }
  proxy_response_ocall->setPointer(proxied_request);
  oscore_data_t *oscore_data =
      (oscore_data_t *)proxy_response_ocall->getPayload();
  proxied_request->getIds(oscore_data);
  if (!oscore_option_decode(&oscore_data->option_data,
      coap_opt_value(oscore_option), coap_opt_length(oscore_option))) {
    coap_log(LOG_ERR, "oscore_option_decode failed\n");
    return;
  }
  std::memcpy(oscore_data->ciphertext, ciphertext, ciphertext_len);
  oscore_data->ciphertext_len = ciphertext_len;

  /* forward to enclave */
  pending_ocalls_.push(std::move(proxy_response_ocall));
}

void
CoapServer::onNackCallback(coap_session_t *session,
    const coap_pdu_t *sent,
    const coap_nack_reason_t reason,
    const coap_mid_t mid)
{
  coap_context_t *context = coap_session_get_context(session);
  if (!context) {
    coap_log(LOG_ERR, "coap_session_get_context returned NULL\n");
    return;
  }
  CoapServer *coap_server = (CoapServer *)coap_get_app_data(context);
  coap_server->onNack(session, sent, reason, mid);
}

void
CoapServer::onNack(coap_session_t *session,
    const coap_pdu_t *sent,
    const coap_nack_reason_t reason,
    const coap_mid_t mid)
{
  const coap_address_t *source_address = coap_session_get_addr_remote(session);
  if (!source_address) {
    coap_log(LOG_ERR, "coap_session_get_addr_remote failed\n");
    return;
  }
  deleteProxiedRequest(source_address, mid);
}

void
CoapServer::onProxyResponseAnswer(void *ptr, oscore_data_t *data)
{
  coap_pdu_t *pdu;

  /* data == NULL means drop */
  if (!data) {
    coap_log(LOG_DEBUG, "shall drop response\n");
    return;
  }
  coap_log(LOG_DEBUG, "shall forward response\n");

  /* get corresponding ProxiedRequest */
  ProxiedRequest *proxied_request = (ProxiedRequest *)ptr;
  assert(proxied_request);

  /* ensure no deletion happened in the meantime */
  bool found = false;
  for (auto it = proxied_requests_.begin();
      it != proxied_requests_.end();
      it++) {
    if (it->get() == proxied_request) {
      found = true;
    }
  }
  if (!found) {
    coap_log(LOG_ERR, "proxied_request was freed already\n");
    return;
  }

  try {
    uint8_t oscore_option_value[OSCORE_OPTION_MAX_VALUE_LENGTH];
    size_t oscore_option_length;

    /* create response PDU */
    coap_bin_const_t original_token = proxied_request->getOriginalToken();
    pdu = coap_pdu_init(COAP_MESSAGE_ACK,
        COAP_RESPONSE_CODE_CHANGED,
        proxied_request->getOriginalMessageId(),
        original_token.length
            + MAX_OPTION_HEADER_LENGTH
            + OSCORE_OPTION_MAX_VALUE_LENGTH
            + PAYLOAD_MARKER_LENGTH
            + data->ciphertext_len);
    if (!pdu) {
      throw 1;
    }
    if (!coap_add_token(pdu, original_token.length, original_token.s)) {
      throw 2;
    }
    oscore_option_encode(oscore_option_value,
        &oscore_option_length,
        &data->option_data,
        0);
    if (!coap_add_option(pdu,
        COAP_OPTION_OSCORE,
        oscore_option_length,
        oscore_option_value)) {
      throw 3;
    }
    if (!coap_add_data(pdu, data->ciphertext_len, data->ciphertext)) {
      throw 4;
    }
    if (coap_send(proxied_request->getOriginalSession(), pdu)
        == COAP_INVALID_MID) {
      throw 5;
    }
  } catch (int e) {
    coap_log(LOG_ERR, "error %i in CoapServer::onProxyResponseAnswer\n", e);
    coap_delete_pdu(pdu);
  }
  deleteProxiedRequest(proxied_request->getIotDeviceAddress(),
      proxied_request->getNewMessageId());
}

std::unique_ptr<Ocall>
CoapServer::waitForOcall()
{
  while (pending_ocalls_.empty()) {
    coap_io_process(coap_context_, COAP_RESOURCE_CHECK_TIME * 1000);
  }

  std::unique_ptr<Ocall> next_ocall = std::move(pending_ocalls_.front());
  pending_ocalls_.pop();
  return next_ocall;
}

Registration *
CoapServer::findOngoingRegistration(const coap_address_t *iot_device_address)
{
  coap_address_t copied_iot_device_address;

  coap_address_copy(&copied_iot_device_address, iot_device_address);
  coap_address_set_port(&copied_iot_device_address, COAP_DEFAULT_PORT);
  for (auto it = proven_registrations_.begin();
      it != proven_registrations_.end();
      it++) {
    if (coap_address_equals(&copied_iot_device_address,
        it->get()->getAddress())) {
      return it->get();
    }
  }
  return nullptr;
}

Registration *
CoapServer::findRegistration(const coap_address_t *iot_device_address)
{
  coap_address_t copied_iot_device_address;

  coap_address_copy(&copied_iot_device_address, iot_device_address);
  coap_address_set_port(&copied_iot_device_address, COAP_DEFAULT_PORT);
  for (auto it = completed_registrations_.begin();
      it != completed_registrations_.end();
      it++) {
    if (coap_address_equals(&copied_iot_device_address,
        it->get()->getAddress())) {
      return it->get();
    }
  }
  return nullptr;
}

void
CoapServer::deleteProxiedRequest(const coap_address_t *iot_device_address,
    coap_mid_t mid)
{
  for (auto it = proxied_requests_.begin();
      it != proxied_requests_.end();
      it++) {
    if (it->get()->hasNewMessageId()
        && coap_address_equals(iot_device_address,
            it->get()->getIotDeviceAddress())
        && (it->get()->getNewMessageId() == mid)) {
      proxied_requests_.erase(it);
      return;
    }
  }
}

ProxiedRequest *
CoapServer::findProxiedRequest(const coap_address_t *iot_device_address,
    coap_mid_t mid)
{
  for (auto it = proxied_requests_.begin();
      it != proxied_requests_.end();
      it++) {
    if (it->get()->hasNewMessageId()
        && coap_address_equals(iot_device_address,
            it->get()->getIotDeviceAddress())
        && (it->get()->getNewMessageId() == mid)) {
      return it->get();
    }
  }
  return NULL;
}

bool
CoapServer::haveOngoingProxyRequest(oscore_data_t *oscore_data)
{
  for (auto it = proxied_requests_.begin();
      it != proxied_requests_.end();
      it++) {
    if (it->get()->isSameRequest(oscore_data)) {
      return true;
    }
  }
  return false;
}

CoapServer::~CoapServer()
{
  cleanUp();
}

void
CoapServer::cleanUp()
{
  proxied_requests_.clear();
  if (coap_context_) {
    coap_free_context(coap_context_);
    coap_context_ = nullptr;
  }
  coap_cleanup();
}

} // namespace filtering
