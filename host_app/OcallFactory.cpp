/*
 * Copyright (c) 2023, Uppsala universitet.
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

#include "OcallFactory.hpp"

#include <cstring>

#include "filtering_ocall.h"

namespace filtering {

std::unique_ptr<Ocall>
OcallFactory::createOcallWithRegisterData(
    std::unique_ptr<Ocall> ocall,
    const coap_pdu_t *pdu,
    const uint8_t ephemeral_public_key[PUBLIC_KEY_COMPRESSED_SIZE]
#if !WITH_TRAP
    , const uint8_t signature[SIGNATURE_SIZE]
#endif /* !WITH_TRAP */
) {
  if (!ocall->init(FILTERING_OCALL_REGISTER_MESSAGE,
                   sizeof(filtering_ocall_register_data_t))) {
    coap_log_err("Ocall::init failed\n");
    return std::unique_ptr<Ocall>(nullptr);
  }
  if (!ocall->setToken(coap_pdu_get_token(pdu))) {
    coap_log_err("Ocall::setToken failed\n");
    return std::unique_ptr<Ocall>(nullptr);
  }

  /* populate register_data */
  filtering_ocall_register_data_t *register_data =
      (filtering_ocall_register_data_t *)ocall->getPayload();
  std::memcpy(register_data->ephemeral_public_key,
              ephemeral_public_key,
              sizeof(register_data->ephemeral_public_key));
#if !WITH_TRAP
  std::memcpy(register_data->signature,
              signature,
              sizeof(register_data->signature));
#endif /* !WITH_TRAP */

  return ocall;
}

std::unique_ptr<Ocall>
OcallFactory::createOcallWithOscoreNgData(
    std::unique_ptr<Ocall> ocall,
    const coap_pdu_t *pdu,
    oscore_ng_option_data_t *option_data,
    const oscore_ng_id_t *client_id,
    const oscore_ng_id_t *server_id,
    filtering_ocall_message_type_t type) {
  /* find out how many bytes we need */
  size_t ciphertext_len;
  const uint8_t *ciphertext;
  if (!coap_get_data(pdu, &ciphertext_len, &ciphertext)) {
    coap_log_err("coap_get_data failed\n");
    return std::unique_ptr<Ocall>(nullptr);
  }
  if (!ocall->init(type,
                   sizeof(filtering_ocall_oscore_ng_data_t) + ciphertext_len)) {
    coap_log_err("Ocall::init failed\n");
    return std::unique_ptr<Ocall>(nullptr);
  }
  if (!ocall->setToken(coap_pdu_get_token(pdu))) {
    coap_log_err("Ocall::setToken failed\n");
    return std::unique_ptr<Ocall>(nullptr);
  }

  /* populate oscore_ng_data */
  filtering_ocall_oscore_ng_data_t *oscore_ng_data =
      (filtering_ocall_oscore_ng_data_t *)ocall->getPayload();
  oscore_ng_copy_id(&oscore_ng_data->client_id, client_id);
  oscore_ng_copy_id(&oscore_ng_data->server_id, server_id);
  oscore_ng_data->pdu_type = coap_pdu_get_type(pdu);
  std::memcpy(&oscore_ng_data->option_data,
              option_data,
              sizeof(oscore_ng_option_data_t));
  std::memcpy(oscore_ng_data->ciphertext, ciphertext, ciphertext_len);
  oscore_ng_data->ciphertext_len = ciphertext_len;

  return ocall;
}

} // namespace filtering
