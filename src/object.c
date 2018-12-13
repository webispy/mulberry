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

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "object.h"
#include "log.h"

struct _callback_type {
	gchar *event;
	MObjectCallback callback;
	void *user_data;
};

struct _idle_data {
	MObject *object;
	gchar *event;
	void *event_info;
	guint id;
	gboolean invoked;
};

struct _timer_data {
	MObject *object;
	MObjectCallback callback;
	void *user_data;
	guint id;
	gboolean invoked;
};

struct _mo {
	unsigned int type;
	void *private_object;
	gchar *name;

	/* Managed idler/timer list */
	GSList *idler_list;
	GSList *timer_list;
	GSList *callbacks;

	GHashTable *property;

	guint export_id;
	GDBusNodeInfo *intro;
};

static GSList *_objects;
static GDBusConnection *_dbus_conn;

EXPORT_API void mo_set_dbus_connection(GDBusConnection *conn)
{
	g_return_if_fail(conn != NULL);

	_dbus_conn = conn;
}

EXPORT_API GDBusConnection *mo_get_dbus_connection(void)
{
	return _dbus_conn;
}

EXPORT_API MObject *mo_new(const gchar *name, unsigned int type)
{
	struct _mo *o;

	g_return_val_if_fail(name != NULL, NULL);

	o = g_try_new0(struct _mo, 1);
	if (!o)
		return NULL;

	o->name = g_strdup(name);
	o->type = type;
	o->property = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
			g_free);

	_objects = g_slist_append(_objects, o);

	return o;
}

EXPORT_API void mo_free(MObject *o)
{
	g_return_if_fail(o != NULL);

	if (o->idler_list) {
		struct _idle_data *idle_data;

		while (g_slist_length(o->idler_list) > 0) {
			idle_data = o->idler_list->data;
			if (idle_data->invoked) {
				error("Don't use mo_free() in idler callback");
				g_assert(FALSE);
			}
			mo_cancel_idle_callback(idle_data->id);
		}
	}

	if (o->timer_list) {
		struct _timer_data *td;

		while (g_slist_length(o->timer_list) > 0) {
			td = o->timer_list->data;
			if (td->invoked) {
				error("Don't use mo_free() in timer callback");
				g_assert(FALSE);
			}
			mo_cancel_timer(td->id);
		}
	}

	if (o->export_id)
		mo_unexport(o);

	if (o->intro)
		g_dbus_node_info_unref(o->intro);

	if (o->property)
		g_hash_table_destroy(o->property);

	if (o->callbacks) {
		GSList *l;
		struct _callback_type *cb;

		for (l = o->callbacks; l; l = l->next) {
			cb = l->data;
			if (!cb)
				continue;

			g_free(cb->event);
			g_free(cb);
		}

		g_slist_free(o->callbacks);
	}

	_objects = g_slist_remove(_objects, o);

	dbg("remove '%s' object", o->name);

	g_free(o->name);
	memset(o, 0, sizeof(struct _mo));
	g_free(o);
}

EXPORT_API int mo_set_private(MObject *o, void *priv)
{
	g_return_val_if_fail(o != NULL, -1);

	o->private_object = priv;

	return 0;
}

EXPORT_API void *mo_get_private(MObject *o)
{
	g_return_val_if_fail(o != NULL, NULL);

	return o->private_object;
}

EXPORT_API unsigned int mo_get_type(MObject *o)
{
	g_return_val_if_fail(o != NULL, 0);

	return o->type;
}

static void _on_method_call(GDBusConnection *connection, const gchar *sender,
		const gchar *object_path, const gchar *interface_name,
		const gchar *method_name, GVariant *parameters,
		GDBusMethodInvocation *invocation, gpointer user_data)
{
	struct mo_dbus_event di = {
		.connection = connection,
		.sender = sender,
		.object_path = object_path,
		.interface_name = interface_name,
		.method_name = method_name,
		.parameters = parameters,
		.invocation = invocation
	};

	mo_emit_callback(user_data, method_name, &di);
}

static GVariant *_on_get_property(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *property_name,
		GError **e, gpointer user_data)
{
	const gchar *value;

	dbg("property get: '%s' from '%s'", property_name, sender);

	value = mo_peek_property(user_data, property_name);
	if (!value) {
		g_set_error(e, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
				"Property '%s' not initialized", property_name);
		return NULL;
	}

	return g_variant_new_string(value);
}

static gboolean _on_set_property(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *property_name,
		GVariant *value, GError **e, gpointer user_data)
{
	dbg("property set: '%s' from '%s'", property_name, sender);

	if (!mo_peek_property(user_data, property_name)) {
		g_set_error(e, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_PROPERTY,
				"Property '%s' not initialized", property_name);
		return FALSE;
	}

	mo_set_property(user_data, property_name,
			g_variant_get_string(value, NULL));

	return TRUE;
}

static const GDBusInterfaceVTable _vtable = {
	.method_call = _on_method_call,
	.get_property = _on_get_property,
	.set_property = _on_set_property
};

static void _dbus_emit_propertieschanged(MObject *o, GSList *list)
{
#if 0
	GError *e = NULL;
	GVariantBuilder *builer;
	GVariantBuilder *invalidated_builder;

	g_dbus_connection_emit_signal(_dbus_conn, NULL,
			mo_peek_property(o, "dbus-path"),
			"org.freedesktop.DBus.Properties", "PropertiesChanged",
			g_variant_new("(sa{sv}as)",
				o->intro->interfaces[0]->name, builder,
				invalidated_builder),
			&error);
#endif
}

EXPORT_API int mo_set_introspection(MObject *o, const gchar *xml)
{
	GError *e = NULL;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(xml != NULL, -1);

	if (o->intro)
		g_dbus_node_info_unref(o->intro);

	o->intro = g_dbus_node_info_new_for_xml(xml, &e);
	if (!o->intro) {
		error("failed. %s", e->message);
		g_error_free(e);
		return -1;
	}

	return 0;
}

EXPORT_API int mo_export(MObject *o, const gchar *path)
{
	GError *e = NULL;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(path != NULL, -1);

	if (o->export_id) {
		warn("already exported");
		return -1;
	}

	if (g_variant_is_object_path(path) == FALSE) {
		error("invalid name('%s'). allow only [A-Z][a-z][0-9]_", path);
		return -1;
	}

	dbg("object path('%s') exported", path);

	o->export_id = g_dbus_connection_register_object(_dbus_conn, path,
			o->intro->interfaces[0], &_vtable, o, NULL, &e);
	if (!o->export_id) {
		error("Error: %s", e->message);
		g_error_free(e);
		return -1;
	}

	if (mo_set_property(o, PROP_OBJECT_PATH, path) < 0)
		error("PATH property set failed");

	return 0;
}

EXPORT_API int mo_unexport(MObject *o)
{
	gboolean ret;

	g_return_val_if_fail(o != NULL, -1);

	if (!o->export_id)
		return -1;

	ret = g_dbus_connection_unregister_object(_dbus_conn, o->export_id);
	if (ret == FALSE) {
		error("unregister_object failed");
		return -1;
	}

	o->export_id = 0;

	return 0;
}

EXPORT_API int mo_emit_signal(MObject *o, const gchar *signal_name,
		GVariant *param)
{
	return mo_emit_signal_full(o, NULL, o->intro->interfaces[0]->name,
			signal_name, param);
}
EXPORT_API int mo_emit_signal_full(MObject *o, const gchar *dest,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *param)
{
	GError *e = NULL;
	gboolean ret;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(signal_name != NULL, -1);
	g_return_val_if_fail(param != NULL, -1);
	g_return_val_if_fail(mo_peek_property(o, PROP_OBJECT_PATH) != NULL, -1);

	ret = g_dbus_connection_emit_signal(_dbus_conn, dest,
			mo_peek_property(o, PROP_OBJECT_PATH), interface_name,
			signal_name, param, &e);
	if (ret == FALSE) {
		error("Error: %s", e->message);
		g_error_free(e);
		return -1;
	}

	return 0;
}

EXPORT_API gchar *mo_get_name(MObject *o)
{
	g_return_val_if_fail(o != NULL, NULL);

	return g_strdup(o->name);
}

EXPORT_API const gchar *mo_peek_name(MObject *o)
{
	g_return_val_if_fail(o != NULL, NULL);

	return o->name;
}

EXPORT_API MObject *mo_find(const gchar *name)
{
	GSList *list = _objects;
	MObject *o;

	g_return_val_if_fail(name != NULL, NULL);

	while (list) {
		o = list->data;
		if (g_strcmp0(o->name, name) == 0)
			return o;

		list = list->next;
	}

	return NULL;
}

static gboolean _timer_callback(gpointer data)
{
	gboolean ret = FALSE;
	struct _timer_data *td = data;

	if (td->callback) {
		td->invoked = TRUE;
		ret = td->callback(td->object, NULL, td->user_data);
		td->invoked = FALSE;
	}

	return ret;
}

static void _timer_callback_done(gpointer data)
{
	struct _timer_data *td = data;

	dbg("'%s' timer(%u) removed.", td->object->name, td->id);

	td->object->timer_list = g_slist_remove(td->object->timer_list, td);

	memset(td, 0, sizeof(struct _timer_data));
	g_free(td);
}

EXPORT_API guint mo_add_timer(MObject *o, guint interval,
		MObjectCallback callback, void *user_data)
{
	struct _timer_data *td;

	g_return_val_if_fail(o != NULL, 0);

	td = g_new0(struct _timer_data, 1);
	td->object = o;
	td->callback = callback;
	td->user_data = user_data;
	td->id = g_timeout_add_seconds_full(G_PRIORITY_DEFAULT, interval,
			_timer_callback, td, _timer_callback_done);

	o->timer_list = g_slist_append(o->timer_list, td);

	dbg("'%s' timer(%u) added. (interval=%d)", td->object->name, td->id,
			interval);

	return td->id;
}

EXPORT_API void mo_cancel_timer(guint timer_id)
{
	g_source_remove(timer_id);
}

EXPORT_API int mo_add_callback(MObject *o, const gchar *event,
		MObjectCallback callback, void *user_data)
{
	struct _callback_type *cb = NULL;
	GSList *l = NULL;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(event != NULL, -1);
	g_return_val_if_fail(callback != NULL, -1);

	if (strlen(event) < 1)
		return -1;

	l = o->callbacks;
	while (l) {
		cb = l->data;
		if (!cb) {
			l = l->next;
			continue;
		}

		if (cb->callback == callback && cb->user_data == user_data
				&& g_strcmp0(cb->event, event) == 0) {
			warn("already added (%s)", event);
			return -1;
		}

		l = l->next;
	}

	cb = g_try_new0(struct _callback_type, 1);
	if (!cb)
		return -1;

	cb->event = g_strdup(event);
	cb->callback = callback;
	cb->user_data = user_data;

	o->callbacks = g_slist_append(o->callbacks, cb);

	return 0;
}

EXPORT_API int mo_del_callback(MObject *o, const gchar *event,
		MObjectCallback callback)
{
	struct _callback_type *cb = NULL;
	GSList *l = NULL;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(event != NULL, -1);
	g_return_val_if_fail(callback != NULL, -1);
	g_return_val_if_fail(o->callbacks != NULL, -1);

	if (strlen(event) == 0)
		return -1;

	l = o->callbacks;
	while (l) {
		cb = l->data;
		if (!cb) {
			l = l->next;
			continue;
		}

		if (cb->callback != callback) {
			l = l->next;
			continue;
		}

		if (g_strcmp0(cb->event, event) != 0) {
			l = l->next;
			continue;
		}

		l = l->next;
		o->callbacks = g_slist_remove(o->callbacks, cb);
		g_free(cb->event);
		g_free(cb);
	}

	return 0;
}

EXPORT_API int mo_del_callback_full(MObject *o, const gchar *event,
		MObjectCallback callback, const void *user_data)
{
	struct _callback_type *cb = NULL;
	GSList *l = NULL;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(event != NULL, -1);
	g_return_val_if_fail(callback != NULL, -1);
	g_return_val_if_fail(o->callbacks != NULL, -1);

	if (strlen(event) == 0)
		return -1;

	l = o->callbacks;
	while (l) {
		cb = l->data;
		if (!cb) {
			l = l->next;
			continue;
		}

		if (cb->callback != callback || cb->user_data != user_data) {
			l = l->next;
			continue;
		}

		if (g_strcmp0(cb->event, event) != 0) {
			l = l->next;
			continue;
		}

		l = l->next;
		o->callbacks = g_slist_remove(o->callbacks, cb);
		g_free(cb->event);
		g_free(cb);
	}

	return 0;
}

EXPORT_API int mo_emit_callback(MObject *o, const gchar *event,
		const void *event_info)
{
	struct _callback_type *cb = NULL;
	GSList *l = NULL;
	int ret;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(event != NULL, -1);

	l = o->callbacks;
	while (l) {
		cb = l->data;
		if (!cb) {
			l = l->next;
			continue;
		}

		if (g_strcmp0(cb->event, event) != 0) {
			l = l->next;
			continue;
		}

		if (cb->callback) {
			ret = cb->callback(o, event_info, cb->user_data);
			if (ret == FALSE) {
				l = l->next;
				o->callbacks = g_slist_remove(o->callbacks, cb);
				g_free(cb->event);
				g_free(cb);
				continue;
			}
		}

		l = l->next;
	}

#if 0
	if (strlen(event) > 4) {
		/*
		 * if event is 'dbus-{name}', emit dbus signal '{name}'
		 * but, only support one parameter.
		 *
		 * if you want use multiple parameters,
		 * use g_signal_emit_by_name() directly.
		 */
		if (event[0] == 'd' && event[1] == 'b' && event[2] == 'u'
				&& event[3] == 's' && event[4] == '-') {
			g_signal_emit_by_name(o->di, event + 5, event_info,
					NULL);
		}
	}
#endif
	return 0;
}

static gboolean _emit_idle_callback(gpointer data)
{
	struct _idle_data *idle_data = data;

	idle_data->invoked = TRUE;
	mo_emit_callback(idle_data->object, idle_data->event,
			idle_data->event_info);
	idle_data->invoked = FALSE;

	return FALSE;
}

static void _emit_idle_callback_done(gpointer data)
{
	struct _idle_data *idle_data = data;

	idle_data->object->idler_list =
		g_slist_remove(idle_data->object->idler_list, idle_data);

	g_free(idle_data->event);
	memset(idle_data, 0, sizeof(struct _idle_data));
	g_free(idle_data);
}

/**
 * event callback called on idle time
 *
 * @param o
 * @param event
 * @param event_info !!CAREFULL!! Don't use stack address.
 *  - use global address(without free())
 *    or new allocated heap address(you should free the event_info in callback)
 *
 * @return
 */
EXPORT_API guint mo_emit_idle_callback(MObject *o, const gchar *event,
		void *event_info)
{
	struct _idle_data *idle_data;

	g_return_val_if_fail(o != NULL, 0);
	g_return_val_if_fail(event != NULL, 0);

	idle_data = g_new0(struct _idle_data, 1);
	idle_data->object = o;
	idle_data->event = g_strdup(event);
	idle_data->event_info = event_info;
	idle_data->id = g_idle_add_full(G_PRIORITY_DEFAULT, _emit_idle_callback,
			idle_data, _emit_idle_callback_done);

	o->idler_list = g_slist_append(o->idler_list, idle_data);

	return idle_data->id;
}

EXPORT_API void mo_cancel_idle_callback(guint idler_id)
{
	g_source_remove(idler_id);
}

static GSList *_set_property_real(MObject *o, const gchar *key,
		const gchar *value, GSList *list)
{
	gchar *prev;

	g_return_val_if_fail(o != NULL, list);
	g_return_val_if_fail(key != NULL, list);

	if (!value) {
		g_hash_table_remove(o->property, key);
		return g_slist_append(list, (gpointer)key);
	}

	prev = g_hash_table_lookup(o->property, key);
	if (prev != NULL) {
#ifdef CONFIG_DISABLE_CALLBACK_FOR_SAMEVALUE
		/*
		 * If same data, no change & no callback emit
		 */
		if (g_strcmp0(prev, value) == 0)
			return list;
#else
		g_hash_table_replace(o->property, g_strdup(key),
				g_strdup(value));
#endif
	} else {
		g_hash_table_insert(o->property, g_strdup(key),
				g_strdup(value));
	}

	return g_slist_append(list, (gpointer)key);
}

EXPORT_API int mo_set_property_full(MObject *o, const gchar *first_property,
		...)
{
	va_list argptr;
	GSList *list = NULL;
	const gchar *k;
	const gchar *v;

	g_return_val_if_fail(o != NULL, -1);
	g_return_val_if_fail(first_property != NULL, -1);

	va_start(argptr, first_property);

	k = first_property;
	v = va_arg(argptr, gchar *);
	list = _set_property_real(o, k, v, list);

	while (1) {
		k = va_arg(argptr, gchar *);
		if (!k)
			break;

		v = va_arg(argptr, gchar *);
		list = _set_property_real(o, k, v, list);
	}

	va_end(argptr);

	if (!list)
		return -1;

	if (g_slist_length(list) > 0) {
		mo_emit_callback(o, MOBJECT_EVENT_PROPERTY_CHANGED, list);
		_dbus_emit_propertieschanged(o, list);
	}

	g_slist_free(list);

	return 0;
}

EXPORT_API gchar *mo_get_property(MObject *o, const gchar *key)
{
	g_return_val_if_fail(o != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	return g_strdup(g_hash_table_lookup(o->property, key));
}

EXPORT_API const gchar *mo_peek_property(MObject *o, const gchar *key)
{
	g_return_val_if_fail(o != NULL, NULL);
	g_return_val_if_fail(key != NULL, NULL);

	return g_hash_table_lookup(o->property, key);
}
