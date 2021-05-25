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

#include <atomic>
#include <coap3/coap.h>
#include <mutex>
#include <thread>

#include "coap3/coap_internal.h"

namespace filtering {

#define BAKERY_COOKIE_LEN (SHA_256_DIGEST_LENGTH / 4)

class Bakery {
  uint8_t current_key_[SHA_256_BLOCK_SIZE];
  uint_fast8_t current_interval_;
  uint8_t previous_key_[SHA_256_BLOCK_SIZE];
  uint_fast8_t previous_interval_;
  std::thread thread_;
  std::atomic<bool> is_running_;
  std::mutex update_mutex_;
  void updateCookieKey();
  int bakeSpecificCookie(uint8_t cookie[BAKERY_COOKIE_LEN],
                         const coap_address_t *address,
                         uint8_t key[SHA_256_BLOCK_SIZE],
                         uint_fast8_t interval);
 public:
  Bakery();
  int bakeCookie(uint8_t cookie[BAKERY_COOKIE_LEN],
                 const coap_address_t *address);
  int checkCookie(const uint8_t cookie[BAKERY_COOKIE_LEN],
                  const coap_address_t *address);
  ~Bakery();
};

} // namespace filtering
