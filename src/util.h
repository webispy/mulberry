/*
 * Copyright (c) 2018 Inho Oh <webispy@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MB_UTIL_H__
#define __MB_UTIL_H__

#include "cbor.h"
#include "oc_rep.h"

uint8_t *util_json_to_cbor(const char *json, size_t json_len,
		size_t *out_len);

int util_gvariant_to_cbor(CborEncoder *encoder, GVariant *gv);
GVariant *util_payload_to_gvariant(oc_rep_t *rep);

#endif
