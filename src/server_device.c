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

#include <string.h>

#include "log.h"
#include "manager.h"
#include "server_device.h"
#include "resource.h"
#include "iotivity.h"

#define INTROSPECTION                                                          \
	"<node>"                                                               \
	"  <interface name='io.mulberry.Device'>"                              \
	"    <method name='AddResource'>"                                      \
	"      <arg type='s' name='name' direction='in'/>"                     \
	"      <arg type='o' name='path' direction='in'/>"                     \
	"      <arg type='s' name='ocf_uri' direction='in'/>"                  \
	"      <arg type='s' name='ocf_rt' direction='in'/>"                   \
	"      <arg type='s' name='ocf_if' direction='in'/>"                   \
	"      <arg type='o' name='path' direction='out'/>"                    \
	"    </method>"                                                        \
	"    <method name='RemoveResource'>"                                   \
	"      <arg type='s' name='ocf_uri' direction='in'/>"                  \
	"    </method>"                                                        \
	"    <method name='Reset'>"                                            \
	"    </method>"                                                        \
	"    <method name='SetIntrospection'>"                                 \
	"      <arg type='s' name='swagger' direction='in'/>"                  \
	"    </method>"                                                        \
	"    <signal name='ResourceAdded'>"                                    \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <signal name='ResourceRemoved'>"                                  \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <property type='s' name='name' access='read'/>"                   \
	"    <property type='s' name='type' access='read'/>"                   \
	"    <property type='s' name='spec' access='read'/>"                   \
	"    <property type='s' name='dmv' access='read'/>"                    \
	"    <property type='s' name='uuid' access='read'/>"                   \
	"  </interface>"                                                       \
	"</node>"

struct _device_priv {
	gchar *owner;

	guint monitor_id;
	GList *resources;

	size_t managed_id;
	gchar *intro;
};

static gboolean _on_add_resource(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;
	gchar *name = NULL;
	gchar *remote_path = NULL;
	gchar *ocf_uri = NULL;
	gchar *ocf_type = NULL;
	gchar *ocf_iface = NULL;
	MObject *rsrc;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	g_variant_get(di->parameters, "(sosss)", &name, &remote_path, &ocf_uri,
			&ocf_type, &ocf_iface);

	rsrc = resource_new(ocf_uri, RESOURCE_TYPE_SERVER);
	if (!rsrc) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Resource creation failed");
		return TRUE;
	}

	mo_set_property(rsrc, RESOURCE_PROP_RT, ocf_type, RESOURCE_PROP_IFACE,
			ocf_iface, RESOURCE_PROP_NAME, name);

	resource_set_remote_dbus_path(rsrc, remote_path);

	if (server_device_add_resource(o, rsrc) < 0) {
		resource_free(rsrc);
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Resource creation failed");
		return TRUE;
	}

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("(o)", mo_peek_property(rsrc,
					PROP_OBJECT_PATH)));

	return TRUE;
}

static gboolean _on_remove_resource(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;
	gchar *name = NULL;
	MObject *rsrc;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	g_variant_get(di->parameters, "(s)", &name);

	rsrc = server_device_find_resource(o, name);
	if (!rsrc) {
		g_free(name);
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Unknown resource");
		return TRUE;
	}

	g_free(name);

	server_device_remove_resource(o, rsrc);
	resource_free(rsrc);

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

static gboolean _on_reset(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	server_device_reset_otm(o);

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

static gboolean _on_set_ocf_introspection(MObject *o, const void *ei,
		void *user_data)
{
	const struct mo_dbus_event *di = ei;
	gchar *swagger = NULL;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	g_variant_get(di->parameters, "(s)", &swagger);

	if (!swagger) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Invalid input");
		return TRUE;
	}

	server_device_set_ocf_introspection(o, swagger);
	g_free(swagger);

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

static void _signal_nameownerchanged(GDBusConnection *conn, const gchar *name,
		const gchar *path, const gchar *iface, const gchar *sig,
		GVariant *param, gpointer user_data)
{
	gchar *owner_name = NULL;
	gchar *prev_owner_unique_id = NULL;
	gchar *new_owner_unique_id = NULL;

	g_variant_get(param, "(&s&s&s)", &owner_name, &prev_owner_unique_id,
			&new_owner_unique_id);

	if (strlen(new_owner_unique_id) == 0) {
		warn("managed application('%s') exited", prev_owner_unique_id);
		manager_remove_device(user_data);
		server_device_free(user_data);
	}
}

EXPORT_API MObject *server_device_new(const gchar *name, const gchar *type,
		const gchar *owner)
{
	MObject *o;
	struct _device_priv *priv;

	g_return_val_if_fail(name != NULL, NULL);

	priv = g_new0(struct _device_priv, 1);
	if (!priv)
		return NULL;

	priv->managed_id = -1;

	o = mo_new(name, MOBJECT_TYPE_SDEVICE);
	if (!o) {
		g_free(priv);
		return NULL;
	}

	if (owner) {
		priv->owner = g_strdup(owner);
		priv->monitor_id = g_dbus_connection_signal_subscribe(
				mo_get_dbus_connection(),
				"org.freedesktop.DBus",
				"org.freedesktop.DBus", "NameOwnerChanged",
				"/org/freedesktop/DBus", owner,
				G_DBUS_SIGNAL_FLAGS_NONE,
				_signal_nameownerchanged, o,
				NULL);
	}

	mo_set_private(o, priv);
	mo_set_property(o, "type", type, "name", name, "spec", "ocf.1.3.0",
			"dmv", "ocf.res.1.3.0,ocf.sh.1.3.0");
	mo_add_callback(o, "AddResource", _on_add_resource, NULL);
	mo_add_callback(o, "RemoveResource", _on_remove_resource, NULL);
	mo_add_callback(o, "Reset", _on_reset, NULL);
	mo_add_callback(o, "SetIntrospection", _on_set_ocf_introspection, NULL);
	mo_set_introspection(o, INTROSPECTION);

	return o;
}

EXPORT_API void server_device_free(MObject *dev)
{
	struct _device_priv *priv;
	MObject *rsrc = NULL;

	MOBJECT_CHECK(dev, MOBJECT_TYPE_SDEVICE);

	priv = mo_get_private(dev);

	while (priv->resources) {
		rsrc = priv->resources->data;
		server_device_remove_resource(dev, rsrc);
		resource_free(rsrc);
	}

	g_free(priv->owner);

	if (priv->monitor_id)
		g_dbus_connection_signal_unsubscribe(mo_get_dbus_connection(),
				priv->monitor_id);

	g_free(priv->intro);
	g_free(priv);
	mo_free(dev);
}

EXPORT_API int server_device_set_managed_id(MObject *dev, size_t id)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);

	priv = mo_get_private(dev);
	priv->managed_id = id;

	return 0;
}

EXPORT_API size_t server_device_get_managed_id(MObject *dev)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);

	priv = mo_get_private(dev);
	return priv->managed_id;
}

EXPORT_API const gchar *server_device_peek_owner(MObject *dev)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, NULL);

	priv = mo_get_private(dev);

	return priv->owner;
}

EXPORT_API int server_device_add_resource(MObject *dev, MObject *rsrc)
{
	struct _device_priv *priv;
	gchar *path = NULL;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);
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
		return -1;
	}

	g_free(path);

	priv = mo_get_private(dev);
	priv->resources = g_list_append(priv->resources, rsrc);

	mo_emit_signal(dev, "ResourceAdded", g_variant_new("(o)",
				mo_peek_property(rsrc, PROP_OBJECT_PATH)));

	return 0;
}

EXPORT_API int server_device_remove_resource(MObject *dev, MObject *rsrc)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);
	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	if (mo_unexport(rsrc) < 0)
		return -1;

	priv = mo_get_private(dev);
	priv->resources = g_list_remove(priv->resources, rsrc);

	mo_emit_signal(dev, "ResourceRemoved", g_variant_new("(o)",
				mo_peek_property(rsrc, PROP_OBJECT_PATH)));

	return 0;
}

EXPORT_API const GList *server_device_get_resources(MObject *dev)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, NULL);

	priv = mo_get_private(dev);
	return priv->resources;
}

EXPORT_API MObject *server_device_find_resource(MObject *dev, const gchar *name)
{
	struct _device_priv *priv;
	GList *resources;
	MObject *r;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, NULL);

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

EXPORT_API int server_device_reset_otm(MObject *dev)
{
	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);

	return iotivity_reset_svr(dev);
}

EXPORT_API int server_device_set_ocf_introspection(MObject *dev,
		const char *json)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, -1);

	priv = mo_get_private(dev);

	if (priv->intro)
		g_free(priv->intro);

	priv->intro = g_strdup(json);

	return 0;
}

EXPORT_API const gchar *server_device_peek_ocf_introspection(MObject *dev)
{
	struct _device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_SDEVICE, NULL);

	priv = mo_get_private(dev);
	return priv->intro;
}
