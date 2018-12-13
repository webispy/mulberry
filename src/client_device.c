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
#include "manager.h"
#include "client_device.h"
#include "discovered_device.h"
#include "resource.h"

#include "oc_api.h"

#define INTROSPECTION                                                          \
	"<node>"                                                               \
	"  <interface name='io.mulberry.Client'>"                              \
	"    <method name='Discovery'>"                                        \
	"    </method>"                                                        \
	"    <method name='SetIntrospection'>"                                 \
	"      <arg type='s' name='swagger' direction='in'/>"                  \
	"    </method>"                                                        \
	"    <signal name='DeviceAdded'>"                                      \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <signal name='DeviceRemoved'>"                                    \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <property type='s' name='name' access='read'/>"                   \
	"    <property type='s' name='type' access='read'/>"                   \
	"    <property type='s' name='spec' access='read'/>"                   \
	"    <property type='s' name='dmv' access='read'/>"                    \
	"    <property type='s' name='uuid' access='read'/>"                   \
	"  </interface>"                                                       \
	"</node>"

struct _client_device_priv {
	gchar *owner;

	guint monitor_id;
	GList *discovered_devices;

	size_t managed_id;
	gchar *intro;
};

static void remove_all_discovered_devices(MObject *dev)
{
	struct _client_device_priv *priv;

	priv = mo_get_private(dev);

	g_list_free_full(priv->discovered_devices,
			(GDestroyNotify)discovered_device_free);
	priv->discovered_devices = NULL;
}

static gchar *get_uuid_from_anchor(const char *anchor, const char *filter)
{
	gchar *tmp, *pos;

	if (!anchor)
		return NULL;

	anchor = g_strrstr(anchor, "://");
	if (!anchor)
		return NULL;

	anchor = anchor + 3;
	if (filter) {
		if (!g_strcmp0(anchor, filter)) {
			dbg("filtered self");
			return NULL;
		}
	}

	tmp = malloc(strlen(anchor) + 1);
	if (!tmp)
		return NULL;

	pos = tmp;
	for (; *anchor != '\0'; anchor++, pos++) {
		if (*anchor == '-')
			*pos = '_';
		else
			*pos = *anchor;
	}
	*pos = '\0';

	return tmp;
}

static gboolean _on_discovery(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	if (client_device_discovery(o) < 0)
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Discovery failed");
	else
		g_dbus_method_invocation_return_value(di->invocation,
				g_variant_new("()"));

	return TRUE;
}

static void _signal_nameownerchanged(GDBusConnection *conn, const gchar *name,
		const gchar *path, const gchar *iface,
		const gchar *sig, GVariant *param,
		gpointer user_data)
{
	gchar *owner_name = NULL;
	gchar *prev_owner_unique_id = NULL;
	gchar *new_owner_unique_id = NULL;

	g_variant_get(param, "(&s&s&s)", &owner_name, &prev_owner_unique_id,
			&new_owner_unique_id);

	if (strlen(new_owner_unique_id) == 0) {
		warn("managed application('%s') exited", prev_owner_unique_id);
		manager_remove_device(user_data);
		client_device_free(user_data);
	}
}

EXPORT_API MObject *client_device_new(const gchar *name, const gchar *type,
		const gchar *owner)
{
	MObject *o;
	struct _client_device_priv *priv;

	g_return_val_if_fail(name != NULL, NULL);

	priv = g_new0(struct _client_device_priv, 1);
	if (!priv)
		return NULL;

	o = mo_new(name, MOBJECT_TYPE_CDEVICE);
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
	mo_add_callback(o, "Discovery", _on_discovery, NULL);
	mo_set_introspection(o, INTROSPECTION);

	return o;
}

EXPORT_API void client_device_free(MObject *dev)
{
	struct _client_device_priv *priv;
	MObject *dd = NULL;

	MOBJECT_CHECK(dev, MOBJECT_TYPE_CDEVICE);

	priv = mo_get_private(dev);

	while (priv->discovered_devices) {
		dd = priv->discovered_devices->data;
		client_device_remove_discovered_device(dev, dd);
		discovered_device_free(dd);
	}

	g_free(priv->owner);

	if (priv->monitor_id)
		g_dbus_connection_signal_unsubscribe(mo_get_dbus_connection(),
				priv->monitor_id);

	g_free(priv->intro);
	g_free(priv);
	mo_free(dev);
}

static oc_discovery_flags_t _discovery_cb(const char *anchor, const char *uri,
		oc_string_array_t types, oc_interface_mask_t interfaces,
		oc_endpoint_t *endpoint, oc_resource_properties_t bm,
		void *user_data)
{
	int i;
	const char *uuid;
	MObject *dev = user_data;
	MObject *dd;
	MObject *r;
	char *t;

	uuid = get_uuid_from_anchor(anchor, mo_peek_property(dev, "uuid"));
	if (!uuid)
		return OC_CONTINUE_DISCOVERY;

	dd = client_device_find_discovered_device(dev, uuid);
	if (!dd) {
		dd = discovered_device_new(uuid);
		client_device_add_discovered_device(dev, dd);
	}

	r = discovered_device_find_resource(dd, uri);
	if (!r) {
		r = resource_new(uri, RESOURCE_TYPE_CLIENT);
		discovered_device_add_resource(dd, r);

		if (bm & OC_DISCOVERABLE)
			mo_set_property(r, "discoverable", "1");
		if (bm & OC_OBSERVABLE)
			mo_set_property(r, "observable", "1");
		if (bm & OC_SECURE)
			mo_set_property(r, "secure", "1");
		if (bm & OC_PERIODIC)
			mo_set_property(r, "periodic", "1");

		if (interfaces & OC_IF_BASELINE)
			resource_add_iface(r, "oic.if.baseline");
		if (interfaces & OC_IF_LL)
			resource_add_iface(r, "oic.if.ll");
		if (interfaces & OC_IF_B)
			resource_add_iface(r, "oic.if.b");
		if (interfaces & OC_IF_R)
			resource_add_iface(r, "oic.if.r");
		if (interfaces & OC_IF_RW)
			resource_add_iface(r, "oic.if.rw");
		if (interfaces & OC_IF_A)
			resource_add_iface(r, "oic.if.a");
		if (interfaces & OC_IF_S)
			resource_add_iface(r, "oic.if.s");
	}

	for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
		t = oc_string_array_get_item(types, i);
		resource_add_type(r, t);
	}

	resource_set_endpoints(r, endpoint);

	return OC_CONTINUE_DISCOVERY;
}

EXPORT_API int client_device_discovery(MObject *dev)
{
	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);

	remove_all_discovered_devices(dev);

	oc_do_ip_discovery(NULL, _discovery_cb, dev);

	return 0;
}

EXPORT_API int client_device_set_managed_id(MObject *dev, size_t id)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);

	priv = mo_get_private(dev);
	priv->managed_id = id;

	return 0;
}

EXPORT_API size_t client_device_get_managed_id(MObject *dev)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);

	priv = mo_get_private(dev);
	return priv->managed_id;
}

EXPORT_API const gchar *client_device_peek_owner(MObject *dev)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, NULL);

	priv = mo_get_private(dev);

	return priv->owner;
}

EXPORT_API int client_device_add_discovered_device(MObject *dev, MObject *dd)
{
	struct _client_device_priv *priv;
	gchar *path;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);
	MOBJECT_CHECK_RETURN(dd, MOBJECT_TYPE_DDEVICE, -1);

	path = g_strdup_printf("%s/%s", mo_peek_property(dev, PROP_OBJECT_PATH),
			mo_peek_name(dd));

	if (mo_export(dd, path) < 0) {
		g_free(path);
		error("failed");
		return -1;
	}

	g_free(path);

	priv = mo_get_private(dev);
	priv->discovered_devices = g_list_append(priv->discovered_devices, dd);

	mo_emit_signal(dev, "DeviceAdded", g_variant_new("(o)",
				mo_peek_property(dd, PROP_OBJECT_PATH)));

	return 0;
}

EXPORT_API MObject *client_device_find_discovered_device(MObject *dev,
		const gchar *name)
{
	struct _client_device_priv *priv;
	GList *devices;
	MObject *dd;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, NULL);

	priv = mo_get_private(dev);

	devices = priv->discovered_devices;
	while (devices) {
		dd = devices->data;
		if (!g_strcmp0(name, mo_peek_name(dd)))
			return dd;

		devices = devices->next;
	}

	return NULL;
}

EXPORT_API int client_device_remove_discovered_device(MObject *dev, MObject *dd)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);
	MOBJECT_CHECK_RETURN(dd, MOBJECT_TYPE_DDEVICE, -1);

	if (mo_unexport(dd) < 0)
		return -1;

	priv = mo_get_private(dev);
	priv->discovered_devices = g_list_remove(priv->discovered_devices, dd);

	mo_emit_signal(dev, "DeviceRemoved", g_variant_new("(o)",
				mo_peek_property(dev, PROP_OBJECT_PATH)));

	return 0;
}

EXPORT_API const GList *client_device_get_discovered_devices(MObject *dev)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, NULL);

	priv = mo_get_private(dev);
	return priv->discovered_devices;
}

EXPORT_API int client_device_set_ocf_introspection(MObject *dev,
		const char *json)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, -1);

	priv = mo_get_private(dev);

	if (priv->intro)
		g_free(priv->intro);

	priv->intro = g_strdup(json);

	return 0;
}

EXPORT_API const gchar *client_device_peek_ocf_introspection(MObject *dev)
{
	struct _client_device_priv *priv;

	MOBJECT_CHECK_RETURN(dev, MOBJECT_TYPE_CDEVICE, NULL);

	priv = mo_get_private(dev);
	return priv->intro;
}
