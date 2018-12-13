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

#ifndef __MB_SERVER_DEVICE_H__
#define __MB_SERVER_DEVICE_H__

#include "object.h"

MObject *server_device_new(const gchar *name, const gchar *type,
		const gchar *owner);
void server_device_free(MObject *dev);

const gchar *server_device_peek_owner(MObject *dev);

int server_device_add_resource(MObject *dev, MObject *rsrc);
int server_device_remove_resource(MObject *dev, MObject *rsrc);
const GList *server_device_get_resources(MObject *dev);
MObject *server_device_find_resource(MObject *dev, const gchar *name);

int server_device_set_managed_id(MObject *dev, size_t id);
size_t server_device_get_managed_id(MObject *dev);

int server_device_set_ocf_introspection(MObject *dev, const char *json);
const gchar *server_device_peek_ocf_introspection(MObject *dev);

int server_device_reset_otm(MObject *dev);

#endif

