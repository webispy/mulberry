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

#ifndef __MB_RESOURCE_H__
#define __MB_RESOURCE_H__

#include "object.h"
#include "oc_endpoint.h"

enum resource_type {
	RESOURCE_TYPE_SERVER,
	RESOURCE_TYPE_CLIENT
};

#define RESOURCE_PROP_RT "rt"
#define RESOURCE_PROP_IFACE "if"
#define RESOURCE_PROP_NAME "name"
#define RESOURCE_PROP_ENDPOINT "ep"

MObject *resource_new(const gchar *ocf_uri, enum resource_type type);
void resource_free(MObject *rsc);

int resource_set_remote_dbus_path(MObject *rsrc, const char *path);
int resource_set_device(MObject *rsrc, MObject *dev);

GVariant *resource_get(MObject *rsrc);
int resource_post(MObject *rsrc, GVariant *asv);
int resource_put(MObject *rsrc, GVariant *asv);
int resource_del(MObject *rsrc, GVariant *asv);

int resource_add_type(MObject *rsrc, const char *type);
int resource_add_iface(MObject *rsrc, const char *iface);
int resource_set_endpoints(MObject *rsrc, oc_endpoint_t *eps);

#endif

