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

#ifndef __MB_CLIENT_DEVICE_H__
#define __MB_CLIENT_DEVICE_H__

#include "object.h"
#include <glib.h>

MObject *client_device_new(const gchar *name, const gchar *type,
		const gchar *owner);
void client_device_free(MObject *dev);
int client_device_discovery(MObject *dev);

int client_device_set_managed_id(MObject *dev, size_t id);
size_t client_device_get_managed_id(MObject *dev);
const gchar *client_device_peek_owner(MObject *dev);
int client_device_add_discovered_device(MObject *dev, MObject *dd);
MObject *client_device_find_discovered_device(MObject *dev,
		const gchar *name);
int client_device_remove_discovered_device(MObject *dev, MObject *dd);
const GList *client_device_get_discovered_devices(MObject *dev);

int client_device_set_ocf_introspection(MObject *dev,
		const char *json);
const gchar *client_device_peek_ocf_introspection(MObject *dev);

#endif

