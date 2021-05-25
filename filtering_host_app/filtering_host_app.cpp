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

#include "filtering_ocall.h"

#include "CoapServer.hpp"
#include "EnclaveLogger.hpp"
#include "OcallDispatcher.hpp"

static const char *kIpAddress = "fd00:abcd::2";
static const char *kFilteringEnclavePath = "filtering_enclave.eapp_riscv";
static const char *kKeystoneRuntimePath = "eyrie-rt";

using namespace filtering;

int
main(int argc, char** argv)
{
  EnclaveLogger enclave_logger;
  CoapServer coap_server;
  Keystone::Enclave enclave;
  Keystone::Error error;
  Keystone::Params params;

  error = enclave.init(kFilteringEnclavePath, kKeystoneRuntimePath, params);
  if (error != Keystone::Error::Success) {
    std::cerr << "could not start enclave" << std::endl;
    exit(EXIT_FAILURE);
  }
  OcallDispatcher::createInstance(&enclave);
  OcallDispatcher::getInstance().setEnclaveLogger(&enclave_logger);
  OcallDispatcher::getInstance().setOcallHandler(&coap_server);

  if (!coap_server.start(kIpAddress, nullptr)) {
    exit(EXIT_FAILURE);
  }

  error = enclave.run();
  if (error != Keystone::Error::Success) {
    std::cerr << "could not run enclave" << std::endl;
    exit(EXIT_FAILURE);
  }
  exit(EXIT_SUCCESS);
}
