/*
 * Copyright (c) 2023, Uppsala universitet.
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

#include "report.h"

#include <string.h>

#if WITH_IRAP
#include "coap3/coap_libcoap_build.h"
#define SM_VERSION (1)
#define TEE_VERSION (1)
#endif /* WITH_IRAP */

size_t
report_serialize(struct report *report,
                 uint8_t serialized_report[MAX_ATTESTATION_REPORT_SIZE]) {
#if WITH_IRAP
  tiny_dice_cert_chain_t cert_chain;
  {
    cbor_reader_state_t state;
    cbor_init_reader(&state,
                     report->sm.cert_chain,
                     report->sm.cert_chain_size);
    if (tiny_dice_decode_cert_chain(&state, &cert_chain) == SIZE_MAX) {
      return 0;
    }
    cert_chain.certs[cert_chain.length - 1].tci_digest = NULL;
    cert_chain.certs[cert_chain.length - 1].tci_version = SM_VERSION;
  }
  {
    cbor_writer_state_t state;
    cbor_init_writer(&state, serialized_report, MAX_ATTESTATION_REPORT_SIZE);
    tiny_dice_write_compressed_public_key(
        &state,
        report->enclave.ephemeral_public_key_compressed);
    tiny_dice_write_cert_chain(&state, &cert_chain);
    cbor_write_unsigned(&state, TEE_VERSION);
    return cbor_end_writer(&state);
  }
#else /* WITH_IRAP */
  const uint8_t *enclaves_ephemeral_public_key_compressed =
#if WITH_TRAP
      report->enclave.ephemeral_public_key_compressed;
#else /* WITH_TRAP */
      report->enclave.data + PUBLIC_KEY_COMPRESSED_SIZE;
#endif /* WITH_TRAP */
  memcpy(serialized_report,
         report->sm.public_key,
         sizeof(report->sm.public_key));
  serialized_report[0] = (serialized_report[0] & 1)
                         | ((*enclaves_ephemeral_public_key_compressed & 1) << 1);
  serialized_report += PUBLIC_KEY_COMPRESSED_SIZE;
  memcpy(serialized_report,
         report->sm.signature,
         sizeof(report->sm.signature));
  serialized_report += sizeof(report->sm.signature);
  memcpy(serialized_report,
         enclaves_ephemeral_public_key_compressed + 1,
         PUBLIC_KEY_COMPRESSED_SIZE - 1);
  serialized_report += PUBLIC_KEY_COMPRESSED_SIZE - 1;
#if WITH_TRAP
  memcpy(serialized_report,
         report->enclave.servers_fhmqv_mic,
         FHMQV_MIC_LEN);
#else /* WITH_TRAP */
  memcpy(serialized_report,
         report->enclave.signature,
         sizeof(report->enclave.signature));
#endif /* WITH_TRAP */
  return MAX_ATTESTATION_REPORT_SIZE;
#endif /* WITH_IRAP */
}
