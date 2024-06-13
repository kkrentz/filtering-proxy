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

#include <host/Enclave.hpp>
#include <memory>

#include "Ocall.hpp"
#include "Request.hpp"
#include "report.h"

namespace filtering {

class IEnclaveLogger {
 public:
  virtual ~IEnclaveLogger() = default;
  virtual void printBuffer(char *string) = 0;
  virtual void printValue(long value) = 0;
  virtual void printBytes(uint8_t *bytes, size_t bytes_len) = 0;
};

class IOcallHandler {
 public:
  virtual ~IOcallHandler() = default;
  virtual std::unique_ptr<Ocall> waitForOcall() = 0;
#if !WITH_TRAP
  virtual void onCookie(
      Request *request,
      coap_bin_const_t *token,
      uint8_t *cookie,
      size_t cookie_size) = 0;
#endif /* !WITH_TRAP */
  virtual void onReport(
      Request *request,
      coap_bin_const_t *token,
#if WITH_IRAP
      const filtering_ocall_oscore_ng_data_t *data) = 0;
#else /* WITH_IRAP */
      uint8_t *report,
      size_t report_size) = 0;
#endif /* WITH_IRAP */
  virtual void onDiscloseAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data) = 0;
  virtual void onOscoreNgAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data) = 0;
  virtual void onProxyRequestAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data) = 0;
  virtual void onProxyResponseAnswer(
      Request *request,
      coap_bin_const_t *token,
      const filtering_ocall_oscore_ng_data_t *data) = 0;
};

class OcallDispatcher {
  OcallDispatcher(Keystone::Enclave *enclave);
  static OcallDispatcher &getInstanceImpl(Keystone::Enclave *enclave);
  IEnclaveLogger *enclave_logger_ = nullptr;
  IOcallHandler *ocall_handler_ = nullptr;
  static void onOcall(void *buffer);
 public:
  OcallDispatcher(OcallDispatcher const &) = delete;
  void operator=(OcallDispatcher const &) = delete;
  static void createInstance(Keystone::Enclave *enclave);
  static OcallDispatcher &getInstance();
  void setEnclaveLogger(IEnclaveLogger *enclave_logger);
  void setOcallHandler(IOcallHandler *ocall_handler);
};

} // namespace filtering
