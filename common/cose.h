/*
 * Copyright (c) 2018, SICS, RISE AB
 * Copyright (c) 2021, Uppsala universitet
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
 *
 */

#ifndef COSE_H_
#define COSE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define COSE_ALGORITHM_AES_CCM_16_64_128 10
#define COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN 16
#define COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN 13
#define COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN 8

int cose_encrypt0_aes_ccm_16_64_128(
    const uint8_t *aad, size_t aad_len,
    uint8_t *m, size_t m_len,
    const uint8_t key[COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN],
    const uint8_t nonce[COSE_ALGORITHM_AES_CCM_16_64_128_IV_LEN],
    bool forward);

#endif /* COSE_H_ */
