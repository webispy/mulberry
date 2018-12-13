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

#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "util.h"
#include "storage.h"

#define STORE_PATH_SIZE 64

static gchar *_storage_path;

static void _create_idd(const char *store)
{
	gchar *contents = NULL;
	gsize length = 0;
	GError *e = NULL;
	gboolean ret;
	uint8_t *cbor_result;
	size_t out_len = 0;
	gchar *path;
	FILE *fp;

	ret = g_file_get_contents("./introspection.json", &contents, &length,
			&e);
	if (!ret) {
		error("%s", e->message);
		g_error_free(e);
		return;
	}

	cbor_result = util_json_to_cbor(contents, length, &out_len);
	g_free(contents);
	if (!cbor_result) {
		error("util_json_to_cbor failed");
		return;
	}

	path = g_strdup_printf("%s/%s/introspection", STORAGE_PATH, store);
	if (!path) {
		free(cbor_result);
		return;
	}

	fp = fopen(path, "wb");
	if (!fp) {
		error("fopen(%s) failed", path);
		g_free(path);
		free(cbor_result);
		return;
	}

	length = fwrite(cbor_result, 1, out_len, fp);
	fclose(fp);

	g_free(path);
	free(cbor_result);
}

EXPORT_API int oc_storage_config(const char *store)
{
	gchar *path;

	g_return_val_if_fail(store != NULL, -1);

	path = g_strdup_printf("%s/%s", STORAGE_PATH, store);
	if (!path)
		return -1;

	dbg("storage path: '%s'", path);

	if (g_mkdir_with_parents(path, 0755) < 0) {
		error("directory('%s') creation failed", path);
		g_free(path);
		return -1;
	}

	_create_idd(store);

	_storage_path = path;

	return 0;
}

EXPORT_API long oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
	gchar *path;
	FILE *fp = 0;

	g_return_val_if_fail(store != NULL, -1);

	if (_storage_path)
		path = g_strdup_printf("%s/%s", _storage_path, store);
	else
		path = g_strdup(store);

	fp = fopen(path, "rb");
	if (!fp) {
		g_free(path);
		return -EINVAL;
	}

	size = fread(buf, 1, size, fp);
	fclose(fp);

	g_free(path);

	return size;
}

EXPORT_API long oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
	gchar *path;
	FILE *fp;

	g_return_val_if_fail(store != NULL, -1);

	if (_storage_path)
		path = g_strdup_printf("%s/%s", _storage_path, store);
	else
		path = g_strdup(store);

	fp = fopen(path, "wb");
	if (!fp) {
		g_free(path);
		return -EINVAL;
	}

	size = fwrite(buf, 1, size, fp);
	fclose(fp);

	g_free(path);

	info("storage write: '%s', size: %d", store, size);
	mb_hexdump(buf, size);

	return size;
}

EXPORT_API gchar *oc_storage_get_path(const char *store)
{
	if (!store) {
		if (!_storage_path)
			return NULL;

		return g_strdup(_storage_path);
	}

	if (_storage_path)
		return g_strdup_printf("%s/%s", _storage_path, store);

	return g_strdup(store);
}
