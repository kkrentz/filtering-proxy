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

#include "AttestationReport.hpp"

#include <cstring>
#include <iomanip>

namespace filtering {

AttestationReport::AttestationReport(const struct report_t *report)
{
  std::memcpy(&report_, report, sizeof(report_));
}

void
AttestationReport::printHashes()
{
  static const std::string kHashNames[2] = {
      "sm hash" , "enclave hash" };
  const uint8_t * const kHashes[2] = {
      report_.sm.hash , report_.enclave.hash };

  for (uint_fast8_t i = 0; i < 2; i++) {
    std::cout << kHashNames[i];
    for (uint_fast8_t j = 0; j < SHA_256_DIGEST_LENGTH; j++) {
      if ((j % 8) == 0) {
        std::cout << std::endl;
      }
      std::cout
          << "0x"
          << std::setw(2)
          << std::setfill('0')
          << std::hex
          << (int)kHashes[i][j] << " , ";
    }
    std::cout << std::endl << std::dec;
  }
}

void
AttestationReport::compress(
    uint8_t compressed_report[ATTESTATION_REPORT_COMPRESSED_LEN])
{
  std::memcpy(compressed_report, report_.sm.public_key, uECC_BYTES + 1);
  compressed_report[0] = (compressed_report[0] & 1)
      | ((report_.enclave.data[uECC_BYTES * 2 + 1 + uECC_BYTES] & 1) << 1);
  compressed_report += 1 + uECC_BYTES;
  std::memcpy(compressed_report,
      report_.sm.signature,
      SIGNATURE_SIZE);
  compressed_report += SIGNATURE_SIZE;
  std::memcpy(compressed_report,
      report_.enclave.data + uECC_BYTES * 2 + 1 + uECC_BYTES + 1,
      uECC_BYTES);
  compressed_report += uECC_BYTES;
  std::memcpy(compressed_report,
      report_.enclave.fhmqv_mic,
      ATTESTATION_REPORT_FHMQV_MIC_LEN);
}

} // namespace filtering
