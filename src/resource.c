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
#include "server_device.h"
#include "client_device.h"
#include "resource.h"
#include "util.h"

#include "oc_api.h"

#define REMOTE_CALL_TIMEOUT (10 * 1000)

/**
 * Twin resource (Resource shadow)
 */
#define INTROSPECTION_SERVER                                                   \
	"<node>"                                                               \
	"  <interface name='io.mulberry.Resource'>"                            \
	"    <method name='Get'>"                                              \
	"      <arg type='a{sv}' name='json' direction='out'/>"                \
	"    </method>"                                                        \
	"    <method name='Post'>"                                             \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <method name='Put'>"                                              \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <method name='Del'>"                                              \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <property type='s' name='uri' access='read'/>"                    \
	"    <property type='s' name='rt' access='readwrite'/>"                \
	"    <property type='s' name='if' access='readwrite'/>"                \
	"    <property type='s' name='ep' access='read'/>"                     \
	"    <property type='s' name='observable' access='readwrite'/>"        \
	"    <property type='s' name='discoverable' access='readwrite'/>"      \
	"    <property type='s' name='secure' access='readwrite'/>"            \
	"    <property type='s' name='periodic' access='readwrite'/>"          \
	"  </interface>"                                                       \
	"</node>"

#define INTROSPECTION_CLIENT                                                   \
	"<node>"                                                               \
	"  <interface name='io.mulberry.Resource'>"                            \
	"    <method name='Get'>"                                              \
	"      <arg type='a{sv}' name='json' direction='out'/>"                \
	"    </method>"                                                        \
	"    <method name='Post'>"                                             \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <method name='Put'>"                                              \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <method name='Del'>"                                              \
	"      <arg type='a{sv}' name='json' direction='in'/>"                 \
	"    </method>"                                                        \
	"    <property type='s' name='uri' access='read'/>"                    \
	"    <property type='s' name='rt' access='read'/>"                     \
	"    <property type='s' name='if' access='read'/>"                     \
	"    <property type='s' name='ep' access='read'/>"                     \
	"    <property type='s' name='observable' access='read'/>"             \
	"    <property type='s' name='discoverable' access='read'/>"           \
	"    <property type='s' name='secure' access='read'/>"                 \
	"    <property type='s' name='periodic' access='read'/>"               \
	"  </interface>"                                                       \
	"</node>"

struct _resource_priv {
	enum resource_type type;
	MObject *dev;
	gchar *dest;
	gchar *remote_path;
	oc_endpoint_t *eps;
};

static void my_cb(oc_client_response_t *data)
{
	GVariant *payload;

	dbg("response code = %d", data->code);
	payload = util_payload_to_gvariant(data->payload);
	if (!payload) {
		dbg("payload parsing failed");
		g_dbus_method_invocation_return_error(data->user_data,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Failed");
		return;
	}

	g_dbus_method_invocation_return_value(data->user_data, payload);
}

static gboolean _on_get(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;
	GVariant *result;
	struct _resource_priv *priv;

	priv = mo_get_private(o);
	if (priv->type == RESOURCE_TYPE_SERVER) {
		result = resource_get(o);
		if (!result) {
			g_dbus_method_invocation_return_error(di->invocation,
					G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
					"Failed");
			return TRUE;
		}

		g_dbus_method_invocation_return_value(di->invocation, result);
		g_variant_unref(result);
	} else {
		bool ret;

		mb_log_endpoint(priv->eps);

		ret = oc_do_get(mo_peek_property(o, "uri"), priv->eps,
				NULL, my_cb, HIGH_QOS, di->invocation);
		if (ret == false) {
			g_dbus_method_invocation_return_error(di->invocation,
					G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
					"Failed");
			return TRUE;
		}
	}

	return TRUE;
}

static gboolean _on_put(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	if (resource_put(o, di->parameters) < 0) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Failed");
		return TRUE;
	}

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));

	return TRUE;
}

static gboolean _on_post(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	if (resource_post(o, di->parameters) < 0) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Failed");
		return TRUE;
	}

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));

	return TRUE;
}

static gboolean _on_del(MObject *o, const void *ei, void *user_data)
{
	const struct mo_dbus_event *di = ei;

	if (resource_del(o, di->parameters) < 0) {
		g_dbus_method_invocation_return_error(di->invocation,
				G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Failed");
		return TRUE;
	}

	g_dbus_method_invocation_return_value(di->invocation,
			g_variant_new("()"));

	return TRUE;
}

EXPORT_API int resource_set_remote_dbus_path(MObject *rsrc, const char *path)
{
	struct _resource_priv *priv;

	g_return_val_if_fail(path != NULL, -1);
	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	priv->remote_path = g_strdup(path);

	return 0;
}

EXPORT_API MObject *resource_new(const gchar *ocf_uri, enum resource_type type)
{
	MObject *o;
	struct _resource_priv *priv;

	g_return_val_if_fail(ocf_uri != NULL, NULL);

	priv = g_new0(struct _resource_priv, 1);
	if (!priv)
		return NULL;

	o = mo_new(ocf_uri, MOBJECT_TYPE_RESOURCE);
	if (!o) {
		g_free(priv);
		return NULL;
	}

	dbg("Add new resource: uri='%s'", ocf_uri);

	priv->type = type;

	mo_set_private(o, priv);
	mo_set_property(o, "uri", ocf_uri, "observable", "1", "discoverable",
			"1", "secure", "0", "periodic", "0");
	mo_add_callback(o, "Get", _on_get, NULL);
	mo_add_callback(o, "Put", _on_put, NULL);
	mo_add_callback(o, "Post", _on_post, NULL);
	mo_add_callback(o, "Del", _on_del, NULL);

	if (type == RESOURCE_TYPE_SERVER)
		mo_set_introspection(o, INTROSPECTION_SERVER);
	else if (type == RESOURCE_TYPE_CLIENT)
		mo_set_introspection(o, INTROSPECTION_CLIENT);

	return o;
}

EXPORT_API void resource_free(MObject *rsrc)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK(rsrc, MOBJECT_TYPE_RESOURCE);

	priv = mo_get_private(rsrc);

	if (priv->eps)
		oc_free_server_endpoints(priv->eps);

	g_free(priv->dest);
	g_free(priv->remote_path);
	g_free(priv);

	mo_free(rsrc);
}

EXPORT_API int resource_set_device(MObject *rsrc, MObject *dev)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	priv->dev = dev;

	return 0;
}

static GVariant *_server_resource_get(MObject *rsrc,
		struct _resource_priv *priv)
{
	GVariant *result;
	const gchar *owner;
	GError *e = NULL;

	owner = server_device_peek_owner(priv->dev);
	if (!owner)
		return NULL;

	dbg("method call: dest='%s', path='%s', method='%s'", owner,
			priv->remote_path, "Get");

	result = g_dbus_connection_call_sync(mo_get_dbus_connection(), owner,
			priv->remote_path, "io.mulberry.Resource",
			"Get", g_variant_new("()"), NULL,
			G_DBUS_CALL_FLAGS_NONE, REMOTE_CALL_TIMEOUT, NULL, &e);
	if (e) {
		error("Error: %s", e->message);
		g_error_free(e);
		return NULL;
	}

	return result;
}

static GVariant *_client_resource_get(MObject *rsrc,
		struct _resource_priv *priv)
{
	return NULL;
}

EXPORT_API GVariant *resource_get(MObject *rsrc)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, NULL);

	priv = mo_get_private(rsrc);
	if (!priv)
		return NULL;

	if (priv->type == RESOURCE_TYPE_SERVER)
		return _server_resource_get(rsrc, priv);
	else if (priv->type == RESOURCE_TYPE_CLIENT)
		return _client_resource_get(rsrc, priv);

	return NULL;
}

static int _server_resource_post_put_del(MObject *rsrc,
		struct _resource_priv *priv, const char *method,
		GVariant *asv)
{
	GError *e = NULL;
	GVariant *result;
	const gchar *owner;

	g_return_val_if_fail(asv != NULL, -1);
	g_return_val_if_fail(method != NULL, -1);

	owner = server_device_peek_owner(priv->dev);
	if (!owner)
		return -1;

	dbg("method call: dest='%s', path='%s', method='%s'", owner,
			priv->remote_path, method);

	result = g_dbus_connection_call_sync(mo_get_dbus_connection(), owner,
			priv->remote_path, "io.mulberry.Resource", method,
			asv, NULL, G_DBUS_CALL_FLAGS_NONE, REMOTE_CALL_TIMEOUT,
			NULL, &e);
	if (e) {
		error("Error: %s", e->message);
		g_error_free(e);
		return -1;
	}

	g_variant_unref(result);

	return 0;
}

static int _client_resource_post_put_del(MObject *rsrc,
		struct _resource_priv *priv, const char *method,
		GVariant *asv)
{
	return 0;
}

EXPORT_API int resource_post(MObject *rsrc, GVariant *asv)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	if (!priv)
		return -1;

	if (priv->type == RESOURCE_TYPE_SERVER)
		return _server_resource_post_put_del(rsrc, priv, "Post", asv);
	else if (priv->type == RESOURCE_TYPE_CLIENT)
		return _client_resource_post_put_del(rsrc, priv, "Post", asv);

	return -1;
}

EXPORT_API int resource_put(MObject *rsrc, GVariant *asv)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	if (!priv)
		return -1;

	if (priv->type == RESOURCE_TYPE_SERVER)
		return _server_resource_post_put_del(rsrc, priv, "Put", asv);
	else if (priv->type == RESOURCE_TYPE_CLIENT)
		return _client_resource_post_put_del(rsrc, priv, "Put", asv);

	return -1;
}

EXPORT_API int resource_del(MObject *rsrc, GVariant *asv)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	if (!priv)
		return -1;

	if (priv->type == RESOURCE_TYPE_SERVER)
		return _server_resource_post_put_del(rsrc, priv, "Del", asv);
	else if (priv->type == RESOURCE_TYPE_CLIENT)
		return _client_resource_post_put_del(rsrc, priv, "Del", asv);

	return -1;
}

EXPORT_API int resource_add_type(MObject *rsrc, const char *type)
{
	const char *prop_type;
	char *new_type;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	prop_type = mo_peek_property(rsrc, RESOURCE_PROP_RT);
	if (!prop_type) {
		mo_set_property(rsrc, RESOURCE_PROP_RT, type);
		return 0;
	}

	if (g_strrstr(prop_type, type))
		return 0;

	new_type = g_strdup_printf("%s,%s", prop_type, type);
	mo_set_property(rsrc, RESOURCE_PROP_RT, new_type);
	g_free(new_type);

	return 0;
}

EXPORT_API int resource_add_iface(MObject *rsrc, const char *iface)
{
	const char *prop_iface;
	char *new_iface;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	prop_iface = mo_peek_property(rsrc, RESOURCE_PROP_IFACE);
	if (!prop_iface) {
		mo_set_property(rsrc, RESOURCE_PROP_IFACE, iface);
		return 0;
	}

	if (g_strrstr(prop_iface, iface))
		return 0;

	new_iface = g_strdup_printf("%s,%s", prop_iface, iface);
	mo_set_property(rsrc, RESOURCE_PROP_IFACE, new_iface);
	g_free(new_iface);

	return 0;
}

EXPORT_API int resource_set_endpoints(MObject *rsrc, oc_endpoint_t *eps)
{
	struct _resource_priv *priv;

	MOBJECT_CHECK_RETURN(rsrc, MOBJECT_TYPE_RESOURCE, -1);

	priv = mo_get_private(rsrc);
	if (!priv)
		return -1;

	if (priv->eps)
		oc_free_server_endpoints(priv->eps);

	priv->eps = eps;

	return 0;
}
