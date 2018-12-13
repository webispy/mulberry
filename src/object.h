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

#ifndef __MB_OBJECT_H__
#define __MB_OBJECT_H__

#include <glib.h>
#include <gio/gio.h>

#define MOBJECT_TYPE_DEFAULT    0xFF000000
#define MOBJECT_TYPE_MANAGER    (MOBJECT_TYPE_DEFAULT | 0x00010000)
#define MOBJECT_TYPE_SDEVICE    (MOBJECT_TYPE_DEFAULT | 0x00020000)
#define MOBJECT_TYPE_CDEVICE    (MOBJECT_TYPE_DEFAULT | 0x00030000)
#define MOBJECT_TYPE_DDEVICE    (MOBJECT_TYPE_DEFAULT | 0x00040000)
#define MOBJECT_TYPE_RESOURCE   (MOBJECT_TYPE_DEFAULT | 0x00050000)
#define MOBJECT_TYPE_CUSTOM     (MOBJECT_TYPE_DEFAULT | 0x00FF0000)

#define MOBJECT_CHECK(o, t) \
	do { \
		if (!o) { \
			error("MObject is NULL"); \
			return; \
		} \
		if (mo_get_type(o) != t) { \
			error("type(0x%x != 0x%x) mismatch", \
					mo_get_type(o), t); \
			return; \
		} \
	} while (0)

#define MOBJECT_CHECK_RETURN(o, t, r) \
	do { \
		if (!o) { \
			error("MObject is NULL"); \
			return r; \
		} \
		if (mo_get_type(o) != t) { \
			error("type(0x%x != 0x%x) mismatch", \
					mo_get_type(o), t); \
			return r; \
		} \
	} while (0)

#define MOBJECT_IS_VALID_RETURN(o, r) \
	do { \
		if (!o) { \
			error("MObject is NULL"); \
			return r; \
		} \
		if ((mo_get_type(o) & MOBJECT_TYPE_DEFAULT) \
				!= MOBJECT_TYPE_DEFAULT) { \
			error("type(0x%x) is not valid bap object", \
					mo_get_type(o)); \
			return r; \
		} \
	} while (0)

#define PROP_OBJECT_PATH "dbus-path"

#define MOBJECT_EVENT_PROPERTY_CHANGED "mo_property_changed"

#define MOBJECT_KEY_FIND(keys, k) \
	g_slist_find_custom((keys), (k), (GCompareFunc)g_strcmp0)

__BEGIN_DECLS

struct mo_dbus_event {
	GDBusConnection *connection;
	const gchar *sender;
	const gchar *object_path;
	const gchar *interface_name;
	const gchar *method_name;
	GVariant *parameters;
	GDBusMethodInvocation *invocation;
};

typedef struct _mo MObject;
typedef gboolean (*MObjectCallback)(MObject *o, const void *event_info,
		void *user_data);

void mo_set_dbus_connection(GDBusConnection *conn);
GDBusConnection *mo_get_dbus_connection(void);
MObject *mo_find(const gchar *name);

/**
 * Object manage
 */
MObject *mo_new(const gchar *name, unsigned int type);
void mo_free(MObject *o);

int mo_set_private(MObject *o, void *priv);
void *mo_get_private(MObject *o);
unsigned int mo_get_type(MObject *o);

gchar *mo_get_name(MObject *o);
const gchar *mo_peek_name(MObject *o);

/**
 * Property
 *  - limitation: support only string value
 */
#define mo_set_property(co, ...) \
	mo_set_property_full(co, __VA_ARGS__, NULL, NULL)
int mo_set_property_full(MObject *o, const gchar *first_property, ...);
gchar *mo_get_property(MObject *o, const gchar *key);
const gchar *mo_peek_property(MObject *o, const gchar *key);

/**
 * DBus
 */
int mo_set_introspection(MObject *o, const gchar *xml);
int mo_export(MObject *o, const gchar *path);
int mo_unexport(MObject *o);
int mo_emit_signal(MObject *o, const gchar *signal_name, GVariant *param);
int mo_emit_signal_full(MObject *o, const gchar *dest,
		const gchar *interface_name, const gchar *signal_name,
		GVariant *param);

/**
 * Event callback
 * - Support dbus method call callback('event' param is method name)
 * - Support dbus property-set callback(MOBJECT_EVENT_PROPERTY_CHANGED)
 */
int mo_add_callback(MObject *o, const gchar *event,
		MObjectCallback callback, void *user_data);
int mo_del_callback(MObject *o, const gchar *event,
		MObjectCallback callback);
int mo_del_callback_full(MObject *o, const gchar *event,
		MObjectCallback callback, const void *user_data);
int mo_emit_callback(MObject *o, const gchar *event, const void *event_info);
guint mo_emit_idle_callback(MObject *o, const gchar *event, void *event_info);
void mo_cancel_idle_callback(guint idler_id);

/**
 * Timer
 */
guint mo_add_timer(MObject *o, guint interval, MObjectCallback callback,
		void *user_data);
void mo_cancel_timer(guint timer_id);

__END_DECLS

#endif
