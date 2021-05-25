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

#include "log.h"

#include <stddef.h>
#include <stdint.h>

void
log_hashes(struct report *report) {
  LOG_MESSAGE("static const uint8_t "
              "root_of_trusts_public_key[] = {\n");
  for (size_t i = 0; i < sizeof(report->dev_public_key); i += 8) {
    LOG_MESSAGE("  ");
    LOG_BYTES(report->dev_public_key + i, 8);
  }
  LOG_MESSAGE("};\n");

  LOG_MESSAGE("static const uint8_t "
              "expected_sm_hash[] = {\n");
  for (size_t i = 0; i < sizeof(report->sm.hash); i += 8) {
    LOG_MESSAGE("  ");
    LOG_BYTES(report->sm.hash + i, 8);
  }
  LOG_MESSAGE("};\n");

  LOG_MESSAGE("static const uint8_t "
              "expected_tee_hash[] = {\n");
  for (size_t i = 0; i < sizeof(report->enclave.hash); i += 8) {
    LOG_MESSAGE("  ");
    LOG_BYTES(report->enclave.hash + i, 8);
  }
  LOG_MESSAGE("};\n");
}
