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

#include "log.h"
#include "discovered_device.h"
#include "resource.h"

#include "oc_api.h"

#define INTROSPECTION                                                          \
	"<node>"                                                               \
	"  <interface name='io.mulberry.DiscoveredDevice'>"                    \
	"  </interface>"                                                       \
	"</node>"

struct _discovery_device_priv {
	GList *resources;
};

EXPORT_API int discovered_device_add_resource(MObject *dev, MObject *rsrc)
{
	struct _discovery_device_priv *priv;
	gchar *path = NULL;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_DDEVICE, -1);
	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	resource_set_device(rsrc, dev);

	if (mo_peek_name(rsrc)[0] == '/')
		path = g_strdup_printf("%s%s",
				mo_peek_property(dev, PROP_OBJECT_PATH),
				mo_peek_name(rsrc));
	else
		path = g_strdup_printf("%s/%s",
				mo_peek_property(dev, PROP_OBJECT_PATH),
				mo_peek_name(rsrc));

	if (mo_export(rsrc, path) < 0) {
		g_free(path);
		error("failed");
		return -1;
	}

	g_free(path);

	priv = mo_get_private(dev);
	priv->resources = g_list_append(priv->resources, rsrc);

	return 0;
}

EXPORT_API int discovered_device_remove_resource(MObject *dev, MObject *rsrc)
{
	struct _discovery_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_DDEVICE, -1);
	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	if (mo_unexport(rsrc) < 0)
		return -1;

	priv = mo_get_private(dev);
	priv->resources = g_list_remove(priv->resources, rsrc);

	return 0;
}

EXPORT_API MObject *discovered_device_find_resource(MObject *dev,
		const gchar *name)
{
	struct _discovery_device_priv *priv;
	GList *resources;
	MObject *r;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_DDEVICE, NULL);

	priv = mo_get_private(dev);

	resources = priv->resources;
	while (resources) {
		r = resources->data;
		if (!g_strcmp0(name, mo_peek_name(r)))
			return r;

		resources = resources->next;
	}

	return NULL;
}

EXPORT_API MObject *discovered_device_new(const gchar *uuid)
{
	MObject *o;
	struct _discovery_device_priv *priv;

	g_return_val_if_fail(uuid != NULL, NULL);

	priv = g_new0(struct _discovery_device_priv, 1);
	if (!priv)
		return NULL;

	o = mo_new(uuid, MOBJECT_TYPE_DDEVICE);
	if (!o) {
		g_free(priv);
		return NULL;
	}

	mo_set_private(o, priv);

	mo_set_introspection(o, INTROSPECTION);

	return o;
}

EXPORT_API void discovered_device_free(MObject *dev)
{
	struct _discovery_device_priv *priv;
	MObject *rsrc = NULL;

	MOBJECT_CHECK(dev, MOBJECT_TYPE_DDEVICE);

	priv = mo_get_private(dev);

	dbg("discovered_resources: %d", g_list_length(priv->resources));

	while (priv->resources) {
		rsrc = priv->resources->data;
		discovered_device_remove_resource(dev, rsrc);
		resource_free(rsrc);
	}

	g_free(priv);
	mo_free(dev);
}
