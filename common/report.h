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

#include <stdint.h>

#include "filtering_ocall.h"
#include "coap3/coap_libcoap_build.h"

#ifdef KEYSTONE_ENCLAVE
#include "sealing.h"
#else /* KEYSTONE_ENCLAVE */
#define SIGNATURE_SIZE (2 * ECC_CURVE_P_256_SIZE)
#endif /* KEYSTONE_ENCLAVE */

#define PUBLIC_KEY_SIZE (2 * ECC_CURVE_P_256_SIZE)
#define PUBLIC_KEY_COMPRESSED_SIZE (1 + ECC_CURVE_P_256_SIZE)
#define MDSIZE (SHA_256_DIGEST_LENGTH)
#define REPORT_LEN (2048) /* hardcoded in Keystone SM */
#define ATTEST_DATA_MAXLEN (1024) /* hardcoded in Keystone SM */
#define FHMQV_MIC_LEN (WITH_TRAP && !WITH_IRAP ? 8 : 0)
#define MAX_ATTESTATION_REPORT_SIZE \
  (1 /* compression information */ \
   + ECC_CURVE_P_256_SIZE /* SM's public key */ \
   + SIGNATURE_SIZE /* signature of SM report */ \
   + ECC_CURVE_P_256_SIZE /* enclave's ephemeral public key */ \
   + (WITH_TRAP \
   ? FHMQV_MIC_LEN /* truncated FHMQV MIC */ \
   : SIGNATURE_SIZE /* signature of enclave report */))

/* these definitions must match those in enclave.h */
struct enclave_report {
  uint8_t hash[MDSIZE];
  uint64_t data_len;
  uint8_t data[ATTEST_DATA_MAXLEN];
#if WITH_TRAP
  uint8_t ephemeral_public_key_compressed[PUBLIC_KEY_COMPRESSED_SIZE];
  uint8_t fhmqv_key[SHA_256_DIGEST_LENGTH];
#if !WITH_IRAP
  uint8_t servers_fhmqv_mic[SHA_256_DIGEST_LENGTH];
  uint8_t clients_fhmqv_mic[SHA_256_DIGEST_LENGTH];
#endif /* !WITH_IRAP */
#else /* WITH_TRAP */
  uint8_t signature[SIGNATURE_SIZE];
#endif /* WITH_TRAP */
};
struct sm_report {
  uint8_t hash[MDSIZE];
#if WITH_IRAP
  uint8_t cert_chain[TINY_DICE_MAX_CERT_CHAIN_SIZE];
  uint32_t cert_chain_size;
#else /* WITH_IRAP */
  uint8_t public_key[PUBLIC_KEY_COMPRESSED_SIZE];
  uint8_t signature[SIGNATURE_SIZE];
#endif /* WITH_IRAP */
};
struct report {
  struct enclave_report enclave;
  struct sm_report sm;
  uint8_t dev_public_key[PUBLIC_KEY_SIZE];
};
typedef union report_t {
  struct report report;
  uint8_t buffer[REPORT_LEN];
} report_t;

size_t report_serialize(
    struct report *report,
    uint8_t serialized_report[MAX_ATTESTATION_REPORT_SIZE]);
