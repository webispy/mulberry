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
#include "iotivity.h"
#include "manager.h"
#include "server_device.h"
#include "client_device.h"
#include "resource.h"
#include "util.h"
#include "storage.h"

#include <glib.h>
#include <gio/gio.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#ifdef CONFIG_EVENTFD
#include <sys/eventfd.h>
#endif

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "oc_introspection.h"
#include "security/oc_acl.h"
#include "security/oc_cred.h"
#include "security/oc_doxm.h"
#include "security/oc_pstat.h"
#include "security/oc_store.h"
#include "port/oc_clock.h"

#define STORE_PATH_SIZE 64

struct _iotivity_priv {
	GThread *thread;
	gint running;
	guint source;
#ifdef CONFIG_EVENTFD
	int event_fd;
	oc_clock_time_t next_event;
	int event_setup;

	pthread_mutex_t event_mutex;
	pthread_cond_t event_wait;
	pthread_cond_t event_done;
#else
	int sock_gsource;
	int sock_blocking;
#endif

	pthread_mutex_t wait_mutex;
	pthread_cond_t wait_cond;

	pthread_mutex_t iotivity_mutex;
	pthread_cond_t iotivity_cond;
};

static struct _iotivity_priv _priv;

static void on_device(void *user_data)
{
	dbg("on_device()");
}

static void _register_device(void *dev, gpointer user_data)
{
	int managed_id;
	char *intro_path;
	int ret;
	char intro_name[20] = {0};
	const char *intro = NULL;

	ret = oc_add_device("/oic/d", mo_peek_property(dev, "type"),
			mo_peek_property(dev, "name"),
			mo_peek_property(dev, "spec"),
			mo_peek_property(dev, "dmv"), on_device, dev);
	if (ret < 0)
		return;

	managed_id = oc_core_get_num_devices() - 1;

	snprintf(intro_name, sizeof(intro_name), "introspection_%d",
			managed_id);

	intro_path = oc_storage_get_path(intro_name);
	oc_set_introspection_file(managed_id, intro_path);
	g_free(intro_path);

	if (!g_strcmp0(user_data, "server")) {
		server_device_set_managed_id(dev, managed_id);
		intro = server_device_peek_ocf_introspection(dev);
	} else if (!g_strcmp0(user_data, "client")) {
		client_device_set_managed_id(dev, managed_id);
		intro = client_device_peek_ocf_introspection(dev);
	}

	if (intro)
		oc_storage_write(intro_name, (uint8_t *)intro,
				strlen(intro));
	else
		warn("missing introspection information");

	dbg("Added %d device", managed_id);
}

static int on_app_init(void)
{
	int ret;
	const GList *slist, *clist;

	slist = manager_get_server_devices();
	clist = manager_get_client_devices();

	if (g_list_length((GList *)slist) == 0
			&& g_list_length((GList *)clist) == 0)
		return -1;

	ret = oc_init_platform("MULBERRY", NULL, NULL);
	if (ret < 0)
		return ret;

	/* Disable oic.wk.con */
	oc_set_con_res_announced(false);

	g_list_foreach((GList *)slist, _register_device, "server");
	g_list_foreach((GList *)clist, _register_device, "client");

	info("app_init()");
	return ret;
}

static void on_get_resource(oc_request_t *request,
		oc_interface_mask_t interface, void *user_data __UNUSED__)
{
	GVariant *result;

	result = resource_get(user_data);

	oc_rep_start_root_object();
	oc_process_baseline_interface(request->resource);
	util_gvariant_to_cbor(&root_map, result);
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);

	g_variant_unref(result);
}

static void on_post_resource(oc_request_t *request,
		oc_interface_mask_t interface __UNUSED__,
		void *user_data __UNUSED__)
{
	GVariant *payload;

	payload = util_payload_to_gvariant(request->request_payload);
	if (!payload) {
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
		return;
	}

	if (resource_post(user_data, payload) < 0) {
		oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	oc_send_response(request, OC_STATUS_CHANGED);
}

static void on_put_resource(oc_request_t *request __UNUSED__,
		oc_interface_mask_t interface, void *user_data)
{
	GVariant *payload;

	payload = util_payload_to_gvariant(request->request_payload);
	if (!payload) {
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
		return;
	}

	if (resource_put(user_data, payload) < 0) {
		oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	oc_send_response(request, OC_STATUS_CREATED);
}

static void on_delete_resource(oc_request_t *request __UNUSED__,
		oc_interface_mask_t interface, void *user_data)
{
	GVariant *payload;

	payload = util_payload_to_gvariant(request->request_payload);
	if (!payload) {
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
		return;
	}

	if (resource_del(user_data, payload) < 0) {
		oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	oc_send_response(request, OC_STATUS_DELETED);
}

static void _register_rsrc(void *r, gpointer user_data)
{
	oc_resource_t *res;
	gchar **rts;
	gchar **ifs;
	int i;
	int device_id;

	if (!r)
		return;

	device_id = server_device_get_managed_id(user_data);

	ifs = g_strsplit(mo_peek_property(r, "if"), ",", -1);
	rts = g_strsplit(mo_peek_property(r, "rt"), ",", -1);

	res = oc_new_resource(mo_peek_name(r), mo_peek_property(r, "uri"),
			g_strv_length(rts), device_id);

	for (i = 0; rts[i]; i++) {
		dbg("Bind resource type '%s'", rts[i]);
		oc_resource_bind_resource_type(res, rts[i]);
	}

	for (i = 0; ifs[i]; i++) {
		dbg("Add interface '%s'", ifs[i]);
		if (!g_strcmp0(ifs[i], "oic.if.baseline"))
			oc_resource_bind_resource_interface(res,
					OC_IF_BASELINE);
		else if (!g_strcmp0(ifs[i], "oic.if.ll"))
			oc_resource_bind_resource_interface(res, OC_IF_LL);
		else if (!g_strcmp0(ifs[i], "oic.if.b"))
			oc_resource_bind_resource_interface(res, OC_IF_B);
		else if (!g_strcmp0(ifs[i], "oic.if.r"))
			oc_resource_bind_resource_interface(res, OC_IF_R);
		else if (!g_strcmp0(ifs[i], "oic.if.rw"))
			oc_resource_bind_resource_interface(res, OC_IF_RW);
		else if (!g_strcmp0(ifs[i], "oic.if.a"))
			oc_resource_bind_resource_interface(res, OC_IF_A);
		else if (!g_strcmp0(ifs[i], "oic.if.s"))
			oc_resource_bind_resource_interface(res, OC_IF_S);
		else
			warn("unknown interface name '%s'", ifs[i]);
	}

	g_strfreev(ifs);
	g_strfreev(rts);

	if (!g_strcmp0(mo_peek_property(r, "discoverable"), "1"))
		oc_resource_set_discoverable(res, true);
	if (!g_strcmp0(mo_peek_property(r, "observable"), "1"))
		oc_resource_set_periodic_observable(res, 1);

	oc_resource_set_request_handler(res, OC_GET, on_get_resource, r);
	oc_resource_set_request_handler(res, OC_POST, on_post_resource, r);
	oc_resource_set_request_handler(res, OC_PUT, on_put_resource, r);
	oc_resource_set_request_handler(res, OC_DELETE, on_delete_resource, r);

	oc_add_resource(res);
}

static void on_register_resources(void)
{
	const GList *list;
	GList *resources;
	MObject *dev;

	list = manager_get_server_devices();
	for (; list; list = list->next) {
		dev = list->data;

		resources = (GList *)server_device_get_resources(dev);
		g_list_foreach(resources, _register_rsrc, dev);
	}
}

/**
 * on_signal_event_loop() will invoked by network thread context to unlock
 * the _iotivity_blocking_loop()
 */
static void on_signal_event_loop(void)
{
	pthread_mutex_lock(&_priv.iotivity_mutex);
	pthread_cond_signal(&_priv.iotivity_cond);
	pthread_mutex_unlock(&_priv.iotivity_mutex);
}

static void on_requests_entry(void)
{
	dbg("");
}

static gpointer _iotivity_blocking_loop(gpointer data)
{
	oc_clock_time_t next_event;
	struct timespec ts;
	int fd = GPOINTER_TO_INT(data);
#ifdef CONFIG_EVENTFD
	uint64_t ev;
#endif

	dbg("iotivity_constrained loop started (fd=%d)", fd);

	pthread_mutex_lock(&_priv.wait_mutex);
	pthread_cond_signal(&_priv.wait_cond);
	pthread_mutex_unlock(&_priv.wait_mutex);

	while (g_atomic_int_get(&_priv.running)) {
		/* Receive next_event from GMainloop context */
#ifdef CONFIG_EVENTFD
		pthread_mutex_lock(&_priv.event_mutex);
		while (_priv.event_setup == 0)
			pthread_cond_wait(&_priv.event_wait,
					&_priv.event_mutex);

		memcpy(&next_event, &_priv.next_event, sizeof(oc_clock_time_t));
		_priv.event_setup = 0;

		pthread_cond_signal(&_priv.event_done);
		pthread_mutex_unlock(&_priv.event_mutex);
#else
		recv(fd, &next_event, sizeof(oc_clock_time_t), 0);
#endif

		pthread_mutex_lock(&_priv.iotivity_mutex);
		if (next_event == 0)
			pthread_cond_wait(&_priv.iotivity_cond,
					&_priv.iotivity_mutex);
		else {
			ts.tv_sec = (next_event / OC_CLOCK_SECOND);
			ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09
				/ OC_CLOCK_SECOND;
			pthread_cond_timedwait(&_priv.iotivity_cond,
					&_priv.iotivity_mutex, &ts);
		}
		pthread_mutex_unlock(&_priv.iotivity_mutex);

#ifdef CONFIG_EVENTFD
		/**
		 * Wake-up GMainloop context to run oc_main_poll()
		 */
		ev = 1;
		if (write(_priv.event_fd, &ev, sizeof(uint64_t)) < 0) {
			error("write() failed");
			break;
		}
#else
		/**
		 * Send meaningless data to GMainloop context to run
		 * oc_main_poll()
		 */
		send(fd, "1", 1, 0);
#endif
	}

	dbg("iotivity_main loop exited");

	return NULL;
}

static void _do_iotivity_stuff(int fd)
{
#ifndef CONFIG_EVENTFD
	oc_clock_time_t next_event;

	/**
	 * Do the iotivity internal logic inside GMainloop context
	 * - message parsing/callback invocation/..
	 */
	next_event = oc_main_poll();

	/**
	 * Send the next_event value to _iotivity_blocking_loop to
	 * use pthread_cond_wait/pthread_cond_timedwait
	 */
	send(fd, &next_event, sizeof(oc_clock_time_t), 0);
#else
	pthread_mutex_lock(&_priv.event_mutex);
	while (_priv.event_setup == 1)
		pthread_cond_wait(&_priv.event_done, &_priv.event_mutex);

	/**
	 * Do the iotivity internal logic inside GMainloop context
	 * - message parsing/callback invocation/..
	 */
	_priv.next_event = oc_main_poll();
	_priv.event_setup = 1;

	pthread_cond_signal(&_priv.event_wait);
	pthread_mutex_unlock(&_priv.event_mutex);
#endif
}

static gboolean _on_socket(GIOChannel *channel, GIOCondition cond __UNUSED__,
		gpointer user_data __UNUSED__)
{
#ifndef CONFIG_EVENTFD
	char buf[2] = {0, 0};
	int fd = g_io_channel_unix_get_fd(channel);

	/* Receive meaningless data */
	recv(fd, buf, 1, 0);

	/* Let's play the iotivity logic */
	_do_iotivity_stuff(fd);
#else
	uint64_t ev;
	int fd = g_io_channel_unix_get_fd(channel);

	/* Receive meaningless data */
	if (read(fd, &ev, sizeof(uint64_t)) < 0) {
		error("read() failed");
		return FALSE;
	}

	/* Let's play the iotivity logic */
	_do_iotivity_stuff(fd);
#endif

	return TRUE;
}

static const oc_handler_t _handler = {
	.init = on_app_init,
	.signal_event_loop = on_signal_event_loop,
	.register_resources = on_register_resources,
	.requests_entry = on_requests_entry
};

EXPORT_API int iotivity_start(void)
{
	GIOChannel *channel;
	char uuid[40];
	int init;
#ifndef CONFIG_EVENTFD
	int socks[2];
#endif
	size_t i;
	MObject *dev;

	if (_priv.thread) {
		error("iotivity thread already running");
		return -1;
	}

	if (oc_storage_config("test") < 0) {
		error("storage config failed");
		return -1;
	}

	/**
	 * Communicate to iotivity-constrained control thread using socket
	 * iotivity-constrained event callback will invoke inside the GMainloop
	 * context.
	 */
#ifndef CONFIG_EVENTFD
	socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
	_priv.sock_gsource = socks[0];
	_priv.sock_blocking = socks[1];

	channel = g_io_channel_unix_new(_priv.sock_gsource);
#else
	_priv.event_fd = eventfd(0, 0);
	if (_priv.event_fd < 0) {
		error("eventfd() failed. %s", strerror(errno));
		return -1;
	}
	channel = g_io_channel_unix_new(_priv.event_fd);
#endif

	_priv.source = g_io_add_watch(channel, G_IO_IN | G_IO_HUP, _on_socket,
			NULL);
	g_io_channel_unref(channel);

	init = oc_main_init(&_handler);
	if (init < 0) {
		error("oc_main_init() failed. (ret=%d)", init);
		g_source_remove(_priv.source);
#ifndef CONFIG_EVENTFD
		close(_priv.sock_gsource);
		close(_priv.sock_blocking);
#else
		close(_priv.event_fd);
#endif
		memset(&_priv, 0, sizeof(struct _iotivity_priv));
		return -1;
	}

#ifdef CONFIG_EVENTFD
	pthread_mutex_init(&_priv.event_mutex, NULL);
	pthread_cond_init(&_priv.event_wait, NULL);
	pthread_cond_init(&_priv.event_done, NULL);
#endif

	pthread_mutex_init(&_priv.wait_mutex, NULL);
	pthread_cond_init(&_priv.wait_cond, NULL);

	g_atomic_int_set(&_priv.running, 1);
#ifdef CONFIG_EVENTFD
	_priv.thread = g_thread_new("iotivity", _iotivity_blocking_loop,
			GINT_TO_POINTER(_priv.event_fd));
#else
	_priv.thread = g_thread_new("iotivity", _iotivity_blocking_loop,
			GINT_TO_POINTER(_priv.sock_blocking));
#endif

	pthread_mutex_lock(&_priv.wait_mutex);
	pthread_cond_wait(&_priv.wait_cond, &_priv.wait_mutex);
	pthread_mutex_unlock(&_priv.wait_mutex);

	for (i = 0; i < oc_core_get_num_devices(); i++) {
		oc_uuid_to_str(oc_core_get_device_id(i), uuid, sizeof(uuid));
		dev = manager_find_device_by_id(i);
		mo_set_property(dev, "uuid", uuid);
		info("Device-%d uuid: '%s'", i, uuid);
	}

#ifndef CONFIG_EVENTFD
	_do_iotivity_stuff(_priv.sock_gsource);
#else
	_do_iotivity_stuff(_priv.event_fd);
#endif
	return 0;
}

EXPORT_API int iotivity_stop(void)
{
	if (!_priv.thread) {
		error("iotivity thread not running");
		return -1;
	}

	g_atomic_int_set(&_priv.running, 0);
	on_signal_event_loop();
	g_thread_join(_priv.thread);
	_priv.thread = NULL;

	g_source_remove(_priv.source);
#ifndef CONFIG_EVENTFD
	close(_priv.sock_gsource);
	close(_priv.sock_blocking);
#else
	close(_priv.event_fd);
#endif
	memset(&_priv, 0, sizeof(struct _iotivity_priv));

	oc_main_shutdown();

	return 0;
}

EXPORT_API int iotivity_reset_svr(MObject *dev)
{
	int id;

	g_return_val_if_fail(dev != NULL, -1);

	id = server_device_get_managed_id(dev);
	if (id < 0)
		return -1;

	oc_sec_acl_default(id);
	oc_sec_doxm_default(id);
	oc_sec_pstat_default(id);
	oc_sec_cred_default(id);

	oc_sec_load_doxm(id);
	oc_sec_load_pstat(id);
	oc_sec_load_cred(id);
	oc_sec_load_acl(id);

	iotivity_stop();

	return iotivity_start();
}
