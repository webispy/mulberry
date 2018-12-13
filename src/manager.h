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

#ifndef __MB_MANAGER_H__
#define __MB_MANAGER_H__

#include "object.h"
#include <glib.h>

void manager_init(void);

int manager_add_device(MObject *dev);
int manager_remove_device(MObject *dev);

const GList *manager_get_server_devices(void);
MObject *manager_find_server_device(const gchar *name);

const GList *manager_get_client_devices(void);
MObject *manager_find_client_device(const gchar *name);

MObject *manager_find_device_by_id(size_t device_id);

int manager_add_discovered_device(MObject *dev);
int manager_remove_discovered_device(MObject *dev);
const GList *manager_get_discovered_devices(void);
MObject *manager_find_discovered_device(const gchar *name);

void manager_start_service(void);
void manager_stop_service(void);

#endif

