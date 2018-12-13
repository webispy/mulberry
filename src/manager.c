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
#include "server_device.h"
#include "client_device.h"
#include "resource.h"
#include "iotivity.h"

#define INTROSPECTION                                                          \
	"<node>"                                                               \
	"  <interface name='io.mulberry.Manager'>"                             \
	"    <method name='AddDevice'>"                                        \
	"      <arg type='s' name='name' direction='in'/>"                     \
	"      <arg type='s' name='role' direction='in'/>"                     \
	"      <arg type='s' name='type' direction='in'/>"                     \
	"      <arg type='o' name='path' direction='out'/>"                    \
	"    </method>"                                                        \
	"    <method name='RemoveDevice'>"                                     \
	"      <arg type='s' name='name' direction='in'/>"                     \
	"    </method>"                                                        \
	"    <method name='StartService'>"                                     \
	"    </method>"                                                        \
	"    <method name='StopService'>"                                      \
	"    </method>"                                                        \
	"    <signal name='DeviceAdded'>"                                      \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <signal name='DeviceRemoved'>"                                    \
	"      <arg type='s' name='path'/>"                                    \
	"    </signal>"                                                        \
	"    <property type='s' name='ServiceStatus' access='read'/>"          \
	"  </interface>"                                                       \
	"</node>"

struct _manager_priv {
	GList *server_devices;
	GList *client_devices;
};

static MObject *_manager;

static gboolean _on_add_device(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;
	gchar *name = NULL;
	gchar *type = NULL;
	gchar *role = NULL;
	MObject *dev;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	g_variant_get(di->parameters, "(sss)", &name, &role, &type);

	if (!g_strcmp0(role, "server"))
		dev = server_device_new(name, type, di->sender);
	else if (!g_strcmp0(role, "client"))
		dev = client_device_new(name, type, di->sender);
	else {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Invalid role ('server' or 'client')");
		return TRUE;
	}

	g_free(name);
	g_free(type);
	g_free(role);

	if (!dev) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Device creation failed");
		return TRUE;
	}

	if (manager_add_device(dev) < 0) {
		server_device_free(dev);
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Can't add the device");
		return TRUE;
	}

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("(o)", mo_peek_property(dev,
					PROP_OBJECT_PATH)));

	return TRUE;
}

static gboolean _on_remove_device(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;
	gchar *name = NULL;
	MObject *dev;

	dbg("method_name: '%s' from '%s'", di->method_name, di->sender);

	g_variant_get(di->parameters, "(s)", &name);

	dev = manager_find_server_device(name);
	if (!dev) {
		g_free(name);

		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Unknown device");
		return TRUE;
	}

	g_free(name);

	manager_remove_device(dev);
	server_device_free(dev);

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

static gboolean _on_start_service(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	if (!g_strcmp0(mo_peek_property(o, "ServiceStatus"), "start")) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Already started");
		return TRUE;
	}

	manager_start_service();

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

static gboolean _on_stop_service(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	if (!g_strcmp0(mo_peek_property(o, "ServiceStatus"), "stop")) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
				"Already stopped");
		return TRUE;
	}

	manager_stop_service();

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));
	return TRUE;
}

EXPORT_API int manager_add_device(MObject *dev)
{
	struct _manager_priv *priv;
	gchar *path;

	g_return_val_if_fail(dev != NULL, -1);

	path = g_strdup_printf("/%s", mo_peek_name(dev));
	if (mo_export(dev, path) < 0) {
		g_free(path);
		return -1;
	}

	g_free(path);

	priv = mo_get_private(_manager);

	if (mo_get_type(dev) == MOBJECT_TYPE_SDEVICE)
		priv->server_devices = g_list_append(priv->server_devices, dev);
	else if (mo_get_type(dev) == MOBJECT_TYPE_CDEVICE)
		priv->client_devices = g_list_append(priv->client_devices, dev);
	else {
		error("invalid device type");
		return -1;
	}

	mo_emit_signal(_manager, "DeviceAdded", g_variant_new("(o)",
				mo_peek_property(dev, PROP_OBJECT_PATH)));

	return 0;
}

EXPORT_API int manager_remove_device(MObject *dev)
{
	struct _manager_priv *priv;

	g_return_val_if_fail(dev != NULL, -1);

	if (mo_unexport(dev) < 0)
		return -1;

	priv = mo_get_private(_manager);

	if (mo_get_type(dev) == MOBJECT_TYPE_SDEVICE)
		priv->server_devices = g_list_remove(priv->server_devices, dev);
	else if (mo_get_type(dev) == MOBJECT_TYPE_CDEVICE)
		priv->client_devices = g_list_remove(priv->client_devices, dev);
	else {
		error("invalid device type");
		return -1;
	}

	mo_emit_signal(_manager, "DeviceRemoved", g_variant_new("(o)",
				mo_peek_property(dev, PROP_OBJECT_PATH)));

	if (g_list_length(priv->server_devices) == 0
			&& g_list_length(priv->client_devices) == 0)
		manager_stop_service();

	return 0;
}

EXPORT_API const GList *manager_get_server_devices(void)
{
	struct _manager_priv *priv;

	priv = mo_get_private(_manager);
	return priv->server_devices;
}

EXPORT_API MObject *manager_find_server_device(const gchar *name)
{
	struct _manager_priv *priv;
	GList *devices;
	MObject *dev;

	priv = mo_get_private(_manager);

	devices = priv->server_devices;
	while (devices) {
		dev = devices->data;
		if (!g_strcmp0(name, mo_peek_name(dev)))
			return dev;

		devices = devices->next;
	}

	return NULL;
}

EXPORT_API const GList *manager_get_client_devices(void)
{
	struct _manager_priv *priv;

	priv = mo_get_private(_manager);
	return priv->client_devices;
}

EXPORT_API MObject *manager_find_client_device(const gchar *name)
{
	struct _manager_priv *priv;
	GList *devices;
	MObject *dev;

	priv = mo_get_private(_manager);

	devices = priv->client_devices;
	while (devices) {
		dev = devices->data;
		if (!g_strcmp0(name, mo_peek_name(dev)))
			return dev;

		devices = devices->next;
	}

	return NULL;
}

EXPORT_API MObject *manager_find_device_by_id(size_t device_id)
{
	struct _manager_priv *priv;
	GList *devices;
	MObject *dev;

	priv = mo_get_private(_manager);

	devices = priv->server_devices;
	while (devices) {
		dev = devices->data;
		if (device_id == server_device_get_managed_id(dev))
			return dev;

		devices = devices->next;
	}

	devices = priv->client_devices;
	while (devices) {
		dev = devices->data;
		if (device_id == client_device_get_managed_id(dev))
			return dev;

		devices = devices->next;
	}

	return NULL;
}

EXPORT_API void manager_start_service(void)
{
	if (iotivity_start() < 0)
		return;

	mo_set_property(_manager, "ServiceStatus", "start");
}

EXPORT_API void manager_stop_service(void)
{
	if (iotivity_stop() < 0)
		return;

	mo_set_property(_manager, "ServiceStatus", "stop");
}

EXPORT_API void manager_init(void)
{
	struct _manager_priv *priv;

	priv = g_new0(struct _manager_priv, 1);

	_manager = mo_new("manager", MOBJECT_TYPE_MANAGER);
	if (!_manager)
		return;

	mo_set_private(_manager, priv);
	mo_set_property(_manager, "ServiceStatus", "stop");
	mo_add_callback(_manager, "AddDevice", _on_add_device, NULL);
	mo_add_callback(_manager, "RemoveDevice", _on_remove_device, NULL);
	mo_add_callback(_manager, "StartService", _on_start_service, NULL);
	mo_add_callback(_manager, "StopService", _on_stop_service, NULL);
	mo_set_introspection(_manager, INTROSPECTION);

	mo_export(_manager, "/");
}
