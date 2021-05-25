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

#include "PduFactory.hpp"

#define PAYLOAD_MARKER_LENGTH (1)

namespace filtering {

coap_pdu_t *
PduFactory::createPdu(coap_pdu_type_t type,
                      coap_pdu_code_t code,
                      coap_mid_t mid,
                      const coap_bin_const_t *token,
                      const oscore_ng_option_data_t *option_data,
                      const uint8_t *payload,
                      size_t payload_len) {
  size_t oscore_ng_option_size;
  oscore_ng_option_value_t oscore_ng_option_value;

  if (option_data) {
    oscore_ng_encode_option(&oscore_ng_option_value, option_data, false);
    oscore_ng_option_size = coap_opt_encode_size(COAP_OPTION_OSCORE,
                                                 oscore_ng_option_value.len);
  } else {
    oscore_ng_option_size = 0;
  }

  coap_pdu_t *pdu = coap_pdu_init(type,
                                  code,
                                  mid,
                                  token->length
                                  + oscore_ng_option_size
                                  + PAYLOAD_MARKER_LENGTH
                                  + payload_len);
  if (!pdu) {
    coap_log_err("coap_pdu_init failed\n");
    return nullptr;
  }
  try {
    if (token && !coap_add_token(pdu, token->length, token->s)) {
      throw __LINE__;
    }
    if (oscore_ng_option_size) {
      if (!coap_add_option(pdu,
                           COAP_OPTION_OSCORE,
                           oscore_ng_option_value.len,
                           oscore_ng_option_value.u8)) {
        throw __LINE__;
      }
    }
    if (!coap_add_data(pdu, payload_len, payload)) {
      throw __LINE__;
    }
    return pdu;
  } catch (int e) {
    coap_log_err("error on line %i in PduFactory::createPdu\n", e);
    coap_delete_pdu(pdu);
    return nullptr;
  }
}

} // namespace filtering
