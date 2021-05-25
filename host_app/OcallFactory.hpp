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

#pragma once

#include <coap3/coap.h>

#include "coap3/coap_libcoap_build.h"
#include "Ocall.hpp"
#include "report.h"
#include "Registration.hpp"

namespace filtering {

class OcallFactory {
 public:
#if !WITH_TRAP
  int convertAddress(filtering_ocall_address_t *dst,
                     const coap_address_t *src);
  std::unique_ptr<Ocall> createKnockOcall(
      std::unique_ptr<Ocall> ocall,
      const coap_address_t *address,
      const coap_pdu_t *pdu);
#endif /* !WITH_TRAP */
  std::unique_ptr<Ocall> createOcallWithRegisterData(
      std::unique_ptr<Ocall> ocall,
      const coap_pdu_t *pdu,
      const uint8_t ephemeral_public_key[PUBLIC_KEY_COMPRESSED_SIZE]
#if !WITH_TRAP
      , const uint8_t signature[SIGNATURE_SIZE],
      const uint8_t cookie[BAKERY_COOKIE_SIZE],
      const coap_address_t *address
#endif /* !WITH_TRAP */
  );
  std::unique_ptr<Ocall> createOcallWithOscoreNgData(
      std::unique_ptr<Ocall> ocall,
      const coap_pdu_t *pdu,
      oscore_ng_option_data_t *option_data,
      const oscore_ng_id_t *client_id,
      const oscore_ng_id_t *server_id,
      filtering_ocall_message_type_t type);
};

} // namespace filtering
