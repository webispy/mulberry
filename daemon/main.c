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

#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <sys/sysinfo.h>

#include "log.h"
#include "manager.h"

static GMainLoop *loop;

static void glib_log(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *msg, gpointer user_data __UNUSED__)
{
	info("[GLIB] domain=%s, level=%d, %s", log_domain, log_level, msg);
}

static void on_bus_acquired(GDBusConnection *conn, const gchar *name,
		gpointer user_data __UNUSED__)
{
	dbg("acquired('%s')", name);

	mo_set_dbus_connection(conn);

	manager_init();
}

int main(int argc, char *argv[])
{
	struct sysinfo system_info;
	guint id;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif

	loop = g_main_loop_new(NULL, FALSE);

	sysinfo(&system_info);

	printf("## %s started. (version: %s, uptime: %ld secs)\n", argv[0],
			VERSION, system_info.uptime);

	g_log_set_default_handler(glib_log, NULL);

	id = g_bus_own_name(G_BUS_TYPE_SYSTEM, "io.mulberry",
			G_BUS_NAME_OWNER_FLAGS_REPLACE, on_bus_acquired,
			NULL, NULL, NULL, NULL);
	if (id == 0) {
		error("g_bus_own_name() failed");
		return -1;
	}

	info("mainloop start");

	g_main_loop_run(loop);

	info("mainloop exit");

	return 0;
}
