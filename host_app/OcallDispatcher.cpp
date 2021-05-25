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

#include "OcallDispatcher.hpp"

#include <edge/edge_call.h>

namespace filtering {

OcallDispatcher::OcallDispatcher(Keystone::Enclave *enclave) {
  if (enclave == nullptr) {
    throw std::runtime_error{ "OcallDispatcher not initialized" };
  }

  enclave->registerOcallDispatch(incoming_call_dispatch);
  for (uint_fast8_t ocall_id = 0;
       ocall_id < FILTERING_OCALL_COUNT;
       ocall_id++) {
    register_call(ocall_id, OcallDispatcher::onOcall);
  }
  edge_call_init_internals((uintptr_t)enclave->getSharedBuffer(),
                           enclave->getSharedBufferSize());
}

void
OcallDispatcher::createInstance(Keystone::Enclave *enclave) {
  OcallDispatcher::getInstanceImpl(enclave);
}

OcallDispatcher &
OcallDispatcher::getInstanceImpl(Keystone::Enclave *enclave) {
  static OcallDispatcher instance(enclave);
  return instance;
}

OcallDispatcher &
OcallDispatcher::getInstance() {
  return OcallDispatcher::getInstanceImpl(nullptr);
}

void
OcallDispatcher::setEnclaveLogger(IEnclaveLogger *enclave_logger) {
  enclave_logger_ = enclave_logger;
}

void
OcallDispatcher::setOcallHandler(IOcallHandler *ocall_handler) {
  ocall_handler_ = ocall_handler;
}

void
OcallDispatcher::onOcall(void *buffer) {
  OcallDispatcher &ocallDispatcher = OcallDispatcher::getInstance();
  uintptr_t call_args;
  size_t args_len;

  /* call struct is at the front of the shared buffer */
  struct edge_call *edge_call = (struct edge_call *)buffer;
  if (edge_call_args_ptr(edge_call, &call_args, &args_len)) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return;
  }

  switch (edge_call->call_id) {
  case FILTERING_OCALL_ACCEPT_OCALL: {
    std::unique_ptr<Ocall> ocall =
        ocallDispatcher.ocall_handler_->waitForOcall();
    /* moves data to an edge_data_t and stores it in the shared region */
    if (edge_call_setup_wrapped_ret(edge_call, ocall.get()->getMessage(),
                                    ocall.get()->getLength())) {
      edge_call->return_data.call_status = CALL_STATUS_BAD_PTR;
      return;
    }
  }
  break;
  case FILTERING_OCALL_PRINT_BUFFER:
    ocallDispatcher.enclave_logger_->printBuffer(
        (char *)call_args);
    break;
  case FILTERING_OCALL_PRINT_VALUE:
    ocallDispatcher.enclave_logger_->printValue(
        *(long *)call_args);
    break;
  case FILTERING_OCALL_PRINT_BYTES:
    ocallDispatcher.enclave_logger_->printBytes(
        (uint8_t *)call_args, args_len);
    break;
  default:
    filtering_ocall_message_t *message =
        (filtering_ocall_message_t *)call_args;

    /* restore pointer in token */
    message->token.s = message->token_bytes;

    switch (edge_call->call_id) {
#if !WITH_TRAP
    case FILTERING_OCALL_COOKIE:
      ocallDispatcher.ocall_handler_->onCookie(
          (Request *)message->request,
          &message->token,
          message->payload,
          message->payload_length);
      break;
#endif /* !WITH_TRAP */
    case FILTERING_OCALL_GOT_REPORT:
      ocallDispatcher.ocall_handler_->onReport(
          (Request *)message->request,
          &message->token,
          message->payload,
          message->payload_length);
      break;
    case FILTERING_OCALL_DISCLOSE_ANSWER:
      ocallDispatcher.ocall_handler_->onDiscloseAnswer(
          (Request *)message->request,
          &message->token,
          message->payload_length
          ? (filtering_ocall_oscore_ng_data_t *)message->payload
          : NULL);
      break;
    case FILTERING_OCALL_OSCORE_NG_ANSWER:
      ocallDispatcher.ocall_handler_->onOscoreNgAnswer(
          (Request *)message->request,
          &message->token,
          message->payload_length
          ? (filtering_ocall_oscore_ng_data_t *)message->payload
          : NULL);
      break;
    case FILTERING_OCALL_PROXY_REQUEST_ANSWER:
      ocallDispatcher.ocall_handler_->onProxyRequestAnswer(
          (Request *)message->request,
          &message->token,
          message->type == FILTERING_OCALL_DROP_REQUEST_MESSAGE
          ? NULL
          : (filtering_ocall_oscore_ng_data_t *)message->payload);
      break;
    case FILTERING_OCALL_PROXY_RESPONSE_ANSWER:
      ocallDispatcher.ocall_handler_->onProxyResponseAnswer(
          (Request *)message->request,
          &message->token,
          message->type == FILTERING_OCALL_DROP_RESPONSE_MESSAGE
          ? NULL
          : (filtering_ocall_oscore_ng_data_t *)message->payload);
      break;
    }
    break;
  }
  edge_call->return_data.call_status = CALL_STATUS_OK;
}

} // namespace filtering
