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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>

#include "cbor.h"
#include "cborjson.h"
#include "cJSON.h"
#include "util.h"
#include "log.h"

static CborError _encode_json(CborEncoder *encoder, cJSON *jsonObj);

static CborError __encode_object(CborEncoder *encoder, cJSON *jsonObj)
{
	CborEncoder rootMap;
	CborError err;
	cJSON *child;

	err = cbor_encoder_create_map(encoder, &rootMap,
			CborIndefiniteLength);
	if (err != CborNoError)
		return err;

	child = jsonObj->child;
	while (child) {
		err = cbor_encode_text_string(&rootMap,
				child->string,
				strlen(child->string));
		if (err != CborNoError)
			break;

		err = _encode_json(&rootMap, child);
		if (err != CborNoError)
			break;

		child = child->next;
	}

	if (err == CborNoError)
		err = cbor_encoder_close_container(encoder, &rootMap);

	return err;
}

static CborError __encode_array(CborEncoder *encoder, cJSON *jsonObj)
{
	CborError err;
	CborEncoder cborArray;
	cJSON *child;

	err = cbor_encoder_create_array(encoder, &cborArray,
			CborIndefiniteLength);
	if (err != CborNoError)
		return err;

	child = jsonObj->child;
	while (child) {
		err = _encode_json(&cborArray, child);
		if (err != CborNoError)
			break;

		child = child->next;
	}

	if (err == CborNoError)
		err = cbor_encoder_close_container(encoder, &cborArray);

	return err;
}

static CborError _encode_json(CborEncoder *encoder, cJSON *jsonObj)
{
	CborError err = CborNoError;

	switch (jsonObj->type) {
	case cJSON_Object:
		err = __encode_object(encoder, jsonObj);
		break;
	case cJSON_Array:
		err = __encode_array(encoder, jsonObj);
		break;
	case cJSON_String:
		err = cbor_encode_text_string(encoder, jsonObj->valuestring,
				strlen(jsonObj->valuestring));
		break;
	case cJSON_Number:
		if ((jsonObj->valuedouble - jsonObj->valueint) > 0.0000001)
			err = cbor_encode_double(encoder, jsonObj->valuedouble);
		else
			err = cbor_encode_int(encoder, jsonObj->valueint);

		break;
	case cJSON_NULL:
		err = cbor_encode_null(encoder);
		break;
	case cJSON_True:
		err = cbor_encode_boolean(encoder, true);
		break;
	case cJSON_False:
		err = cbor_encode_boolean(encoder, false);
		break;
	default:
		break;
	}

	return err;
}

uint8_t *util_json_to_cbor(const char *json, size_t json_len, size_t *out_len)
{
	CborEncoder encoder;
	cJSON *doc;
	CborError e;
	uint8_t *buffer;
	size_t buffersize;

	if (!out_len)
		return NULL;

	doc = cJSON_Parse((char *)json);
	if (!doc) {
		error("json parsing failed.");
		return NULL;
	}

	buffer = malloc(json_len);
	buffersize = json_len;

	cbor_encoder_init(&encoder, buffer, buffersize, 0);
	e = _encode_json(&encoder, doc);
	cJSON_Delete(doc);

	if (e) {
		free(buffer);
		error("cbor encoding failed. (%s)", cbor_error_string(e));
		return NULL;
	}

	dbg("size: %d", cbor_encoder_get_buffer_size(&encoder, buffer));
	*out_len = cbor_encoder_get_buffer_size(&encoder, buffer);

	return buffer;
}

EXPORT_API int util_gvariant_to_cbor(CborEncoder *encoder, GVariant *gv)
{
	GVariantIter *iter = NULL;
	gchar *key = NULL;
	GVariant *value = NULL;

	g_return_val_if_fail(encoder != NULL, -1);
	g_return_val_if_fail(gv != NULL, -1);
	g_return_val_if_fail(
			g_variant_check_format_string(gv, "(a{sv})", FALSE),
			-1);

	g_variant_get(gv, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		cbor_encode_text_string(encoder, key, strlen(key));
		printf("- key: '%s', value-type: %d\n", key,
				g_variant_classify(value));

		switch (g_variant_classify(value)) {
		case G_VARIANT_CLASS_BOOLEAN:
			cbor_encode_boolean(encoder,
					g_variant_get_boolean(value));
			break;
		case G_VARIANT_CLASS_INT16:
			cbor_encode_int(encoder,
					g_variant_get_int16(value));
			break;
		case G_VARIANT_CLASS_INT32:
			cbor_encode_int(encoder,
					g_variant_get_int32(value));
			break;
		case G_VARIANT_CLASS_INT64:
			cbor_encode_int(encoder,
					g_variant_get_int64(value));
			break;
		default:
			break;
		}
	}

	g_variant_iter_free(iter);

	return 0;
}

EXPORT_API GVariant *util_payload_to_gvariant(oc_rep_t *rep)
{
	GVariantBuilder *b;
	GVariant *gv;
	GVariant *v;

	if (!rep)
		return NULL;

	b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	while (rep != NULL) {
		v = NULL;

		switch (rep->type) {
		case OC_REP_BOOL:
			v = g_variant_new_boolean(rep->value.boolean);
			break;
		case OC_REP_INT:
			v = g_variant_new_int32(rep->value.integer);
			break;
		case OC_REP_STRING:
			v = g_variant_new_string(oc_string(rep->value.string));
			break;
		default:
			error("skip unknown type: %d", rep->type);
			break;
		}

		if (v)
			g_variant_builder_add(b, "{sv}", oc_string(rep->name),
					v);

		rep = rep->next;
	}

	gv = g_variant_builder_end(b);
	g_variant_builder_unref(b);

	return g_variant_new("(@a{sv})", gv);
}
