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

#pragma once

#include "filtering_ocall.h"

typedef enum oscore_ng_filter_verdict_t {
  OSCORE_NG_FILTER_VERDICT_DROP = 0,
  OSCORE_NG_FILTER_VERDICT_FORWARD,
  OSCORE_NG_FILTER_VERDICT_RETURN,
} oscore_ng_filter_verdict_t;

int oscore_ng_filter_handle_oscore_ng_message(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token);
oscore_ng_filter_verdict_t oscore_ng_filter_check_proxy_request(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token);
int oscore_ng_filter_check_proxy_response(
    filtering_ocall_oscore_ng_data_t *data,
    const coap_bin_const_t *token);
