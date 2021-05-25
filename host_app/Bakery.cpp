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

#include "Bakery.hpp"

#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>

namespace filtering {

Bakery::Bakery() : is_running_(true) {
  updateCookieKey();
  updateCookieKey();
  thread_ = std::thread([this]() {
    while (is_running_.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(
              (OSCORE_NG_ACK_TIMEOUT /* delay from middlebox to client */
               + OSCORE_NG_PROCESSING_DELAY /* turnaround time */
               + OSCORE_NG_MAX_TRANSMIT_SPAN /* potential retransmissions */
               + OSCORE_NG_ACK_TIMEOUT /* delay from client to middlebox */)
              * 10 /* from centiseconds to milliseconds */));
      updateCookieKey();
    }
  });
}

void
Bakery::updateCookieKey() {
  uint8_t new_cookie_key[SHA_256_BLOCK_SIZE];
  syscall(SYS_getrandom, new_cookie_key, sizeof(new_cookie_key), 1);
  std::lock_guard<std::mutex> guard(update_mutex_);
  std::memcpy(previous_key_, current_key_, sizeof(previous_key_));
  std::memcpy(current_key_, new_cookie_key, sizeof(previous_key_));
  previous_interval_ = current_interval_++;
}

int
Bakery::bakeSpecificCookie(uint8_t cookie[BAKERY_COOKIE_LEN],
                           const coap_address_t *address,
                           uint8_t key[SHA_256_BLOCK_SIZE],
                           uint_fast8_t interval) {
  uint8_t hmic[SHA_256_DIGEST_LENGTH];

  switch (address->addr.sa.sa_family) {
  case AF_INET:
    sha_256_hmac(key,
                 SHA_256_BLOCK_SIZE,
                 (uint8_t *)&address->addr.sin.sin_addr.s_addr,
                 sizeof(address->addr.sin.sin_addr.s_addr),
                 hmic);
    break;
  case AF_INET6:
    sha_256_hmac(key,
                 SHA_256_BLOCK_SIZE,
                 address->addr.sin6.sin6_addr.s6_addr,
                 sizeof(address->addr.sin6.sin6_addr.s6_addr),
                 hmic);
    break;
  default:
    return 0;
  }
  std::memcpy(cookie, hmic, BAKERY_COOKIE_LEN);
  /* last bit indicates interval */
  cookie[BAKERY_COOKIE_LEN - 1] &= ~1;
  cookie[BAKERY_COOKIE_LEN - 1] |= interval & 1;
  return 1;
}

int
Bakery::bakeCookie(uint8_t cookie[BAKERY_COOKIE_LEN],
                   const coap_address_t *address) {
  std::lock_guard<std::mutex> guard(update_mutex_);
  return bakeSpecificCookie(cookie, address, current_key_, current_interval_);
}

int
Bakery::checkCookie(const uint8_t cookie[BAKERY_COOKIE_LEN],
                    const coap_address_t *address) {
  bool is_recent_cookie = (cookie[BAKERY_COOKIE_LEN - 1] & 1)
                          == (current_interval_ & 1);
  update_mutex_.lock();
  uint8_t expected_cookie[BAKERY_COOKIE_LEN];
  bakeSpecificCookie(expected_cookie,
                     address,
                     is_recent_cookie ? current_key_ : previous_key_,
                     is_recent_cookie ? current_interval_ : previous_interval_);
  update_mutex_.unlock();
  return !std::memcmp(expected_cookie, cookie, BAKERY_COOKIE_LEN);
}

Bakery::~Bakery() {
  if (is_running_.load(std::memory_order_acquire)) {
    is_running_.store(false, std::memory_order_release);
    if (thread_.joinable()) {
      thread_.join();
    }
  }
}

} // namespace filtering
