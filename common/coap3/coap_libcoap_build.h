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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KEYSTONE_ENCLAVE
#include <stddef.h>
#include <stdint.h>

typedef struct coap_bin_const_t {
  size_t length;
  const uint8_t *s;
} coap_bin_const_t;
typedef struct coap_oscore_ng_keying_material_t {
  coap_bin_const_t master_secret;
  coap_bin_const_t master_salt;
} coap_oscore_ng_keying_material_t;
typedef enum coap_pdu_type_t {
  COAP_MESSAGE_CON,
  COAP_MESSAGE_NON,
  COAP_MESSAGE_ACK,
  COAP_MESSAGE_RST
} coap_pdu_type_t;
#define assert(c)
#else /* KEYSTONE_ENCLAVE */
#include <coap3/coap.h>
#endif /* KEYSTONE_ENCLAVE */

#include "oscore-ng/oscore_ng_aes_128.h"
#if !WITH_TRAP
#include "oscore-ng/oscore_ng_bakery.h"
#endif /* !WITH_TRAP */
#include "oscore-ng/oscore_ng_ccm_star.h"
#include "oscore-ng/oscore_ng_list.h"
#include "oscore-ng/oscore_ng_cbor.h"
#include "oscore-ng/oscore_ng_cose.h"
#include "oscore-ng/oscore_ng_ecc_curve.h"
#include "oscore-ng/oscore_ng_sha_256.h"
#if WITH_IRAP
#ifdef KEYSTONE_ENCLAVE
typedef struct coap_rap_report_t {
  coap_bin_const_t cert_chain;
  uint8_t servers_ephemeral_public_key_compressed[1 + ECC_CURVE_P_256_SIZE];
  uint8_t tee_tci[SHA_256_DIGEST_LENGTH];
} coap_rap_report_t;
#endif /* KEYSTONE_ENCLAVE */
#include "oscore-ng/oscore_ng_rap.h"
#include "oscore-ng/oscore_ng_tiny_dice.h"
#endif /* WITH_IRAP */
#include "oscore-ng/oscore_ng.h"

#ifdef __cplusplus
}
#endif
