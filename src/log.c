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
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "cbor.h"
#include "cborjson.h"
#include "log.h"

#define MAX_FIELDSIZE_FILENAME 30
#define MAX_FIELDSIZE_FUNCNAME 30

#define ANSI_COLOR_NORMAL       "\e[0m"

#define ANSI_COLOR_BLACK        "\e[0;30m"
#define ANSI_COLOR_RED          "\e[0;31m"
#define ANSI_COLOR_GREEN        "\e[0;32m"
#define ANSI_COLOR_BROWN        "\e[0;33m"
#define ANSI_COLOR_BLUE         "\e[0;34m"
#define ANSI_COLOR_MAGENTA      "\e[0;35m"
#define ANSI_COLOR_CYAN         "\e[0;36m"
#define ANSI_COLOR_LIGHTGRAY    "\e[0;37m"

#define ANSI_COLOR_DARKGRAY     "\e[1;30m"
#define ANSI_COLOR_LIGHTRED     "\e[1;31m"
#define ANSI_COLOR_LIGHTGREEN   "\e[1;32m"
#define ANSI_COLOR_YELLOW       "\e[1;33m"
#define ANSI_COLOR_LIGHTBLUE    "\e[1;34m"
#define ANSI_COLOR_LIGHTMAGENTA "\e[1;35m"
#define ANSI_COLOR_LIGHTCYAN    "\e[1;36m"
#define ANSI_COLOR_WHITE        "\e[1;37m"

static enum mb_log_system _log_system = LOG_SYSTEM_STDERR;
static enum mb_log_prefix _log_prefix_fields = LOG_PREFIX_DEFAULT;
static mb_log_handler _log_handler;
static void *_log_handler_user_data;
static int _log_override_enabled;
static int _log_override_checked;
static pthread_mutex_t _log_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct _log_level_info {
	char mark;
	int syslog_level;
} _log_level_map[] = {
	[LOG_LEVEL_ERROR] = { 'E', LOG_ERR },
	[LOG_LEVEL_WARNING] = { 'W', LOG_WARNING },
	[LOG_LEVEL_INFO] = { 'I', LOG_INFO },
	[LOG_LEVEL_DEBUG] = { 'D', LOG_DEBUG }
};

static void _log_check_override(void)
{
	const char *env;

	if (_log_override_checked)
		return;

	_log_override_checked = 1;

	env = getenv("MULBERRY_LOG");
	if (!env)
		return;

	if (!strncasecmp(env, "stderr", 7)) {
		_log_override_enabled = 1;
		_log_system = LOG_SYSTEM_STDERR;
	} else if (!strncasecmp(env, "syslog", 7)) {
		_log_override_enabled = 1;
		_log_system = LOG_SYSTEM_SYSLOG;
	} else if (!strncasecmp(env, "none", 5)) {
		_log_override_enabled = 1;
		_log_system = LOG_SYSTEM_NONE;
	}
}

static int _log_make_prefix(char *prefix, int prefix_len __UNUSED__,
		enum mb_log_level level, const char *filename,
		const char *funcname, int line)
{
	const char *pretty_filename = NULL;
	int len = 0;
	int pid = 0;
	int tid = 0;

	if (_log_prefix_fields & LOG_PREFIX_TIMESTAMP) {
		struct timespec tp;
		struct tm ti;

		clock_gettime(CLOCK_REALTIME, &tp);
		localtime_r(&(tp.tv_sec), &ti);

		len += (int)strftime(prefix, 15, "%m-%d %H:%M:%S", &ti);
		len += snprintf(prefix + len, 6, ".%03ld ",
				tp.tv_nsec / 1000000);
	}

	if (_log_prefix_fields & LOG_PREFIX_PID) {
		pid = getpid();
		if (len > 0)
			len += snprintf(prefix + len, 7, "%5d ", pid);
		else
			len += snprintf(prefix, 7, "%d ", pid);
	}

	if (_log_prefix_fields & LOG_PREFIX_TID) {
		tid = (pid_t)syscall(SYS_gettid);
		if (len > 0) {
#ifdef CONFIG_LOG_ANSICOLOR
			if (pid != 0 && pid != tid)
				len += snprintf(prefix + len, 18,
						ANSI_COLOR_DARKGRAY
						"%5d " ANSI_COLOR_NORMAL,
						tid);
			else
				len += snprintf(prefix + len, 7, "%5d ", tid);
#else
			len += snprintf(prefix + len, 7, "%5d ", tid);
#endif
		} else
			len += snprintf(prefix + len, 7, "%d ", tid);
	}

	if (_log_prefix_fields & LOG_PREFIX_LEVEL) {
		prefix[len++] = _log_level_map[level].mark;
		prefix[len++] = ' ';
	}

	if (_log_prefix_fields & LOG_PREFIX_FILENAME) {
		pretty_filename = strrchr(filename, '/');
		if (!pretty_filename)
			pretty_filename = filename;
		else
			pretty_filename++;
	}

	if (_log_prefix_fields & LOG_PREFIX_FILEPATH)
		pretty_filename = filename;

	if (pretty_filename) {
		size_t field_len;

		field_len = strlen(pretty_filename);
		if (field_len > MAX_FIELDSIZE_FILENAME) {
			len += snprintf(prefix + len,
					MAX_FIELDSIZE_FILENAME + 5, "<~%s> ",
					pretty_filename + field_len
					- MAX_FIELDSIZE_FILENAME);
		} else
			len += snprintf(prefix + len, field_len + 5, "<%s> ",
					pretty_filename);

		/* Filename with line number */
		if (_log_prefix_fields & LOG_PREFIX_LINE) {
			len--;
			len--;
			len += snprintf(prefix + len, 9, ":%d> ", line);
			*(prefix + len - 1) = ' ';
		}
	} else {
		/* Standalone line number */
		if (_log_prefix_fields & LOG_PREFIX_LINE) {
			len += snprintf(prefix + len, 9, "<%d> ", line);
			*(prefix + len - 1) = ' ';
		}
	}

	if ((_log_prefix_fields & LOG_PREFIX_FUNCTION) && funcname) {
		size_t field_len;

		field_len = strlen(funcname);
		if (field_len > MAX_FIELDSIZE_FUNCNAME) {
			len += snprintf(prefix + len,
					MAX_FIELDSIZE_FUNCNAME + 3, "~%s ",
					funcname + field_len
					- MAX_FIELDSIZE_FUNCNAME);
		} else
			len += snprintf(prefix + len, field_len + 2, "%s ",
					funcname);
	}

	/* Remove last space */
	if (len > 0) {
		if (*(prefix + len - 1) == ' ') {
			*(prefix + len - 1) = 0;
			len--;
		}
	}

	return len;
}

static void _log_formatted(enum mb_log_level level, const char *filename,
		const char *funcname, int line, const char *format, va_list arg)
{
	char prefix[4096] = {0};
	int len = 0;

	if (_log_prefix_fields > LOG_PREFIX_NONE)
		len = _log_make_prefix(prefix, 4096, level, filename, funcname,
				line);

	if (_log_system == LOG_SYSTEM_STDERR) {
		pthread_mutex_lock(&_log_mutex);
		if (len > 0)
			fprintf(stderr, "%s ", prefix);
#ifdef CONFIG_LOG_ANSICOLOR
		switch (level) {
			case LOG_LEVEL_DEBUG:
				break;
			case LOG_LEVEL_INFO:
				fputs(ANSI_COLOR_LIGHTBLUE, stderr);
				break;
			case LOG_LEVEL_WARNING:
				fputs(ANSI_COLOR_LIGHTGRAY, stderr);
				break;
			case LOG_LEVEL_ERROR:
				fputs(ANSI_COLOR_LIGHTRED, stderr);
				break;
			default:
				break;
		}
#endif
		vfprintf(stderr, format, arg);
#ifdef CONFIG_LOG_ANSICOLOR
		fputs(ANSI_COLOR_NORMAL, stderr);
#endif
		fputc('\n', stderr);
		fflush(stderr);
		pthread_mutex_unlock(&_log_mutex);
	} else if (_log_system == LOG_SYSTEM_CUSTOM && _log_handler) {
		char msg[4096];

		vsnprintf(msg, 4096, format, arg);
		_log_handler(level, prefix, msg, _log_handler_user_data);
	}
}

EXPORT_API void mb_log_print(enum mb_log_level level, const char *filename,
		const char *funcname, int line, const char *format, ...)
{
	va_list arg;

	if (!_log_override_checked)
		_log_check_override();

	switch (_log_system) {
	case LOG_SYSTEM_SYSLOG:
		va_start(arg, format);
		vsyslog(_log_level_map[level].syslog_level, format, arg);
		va_end(arg);
		break;

	case LOG_SYSTEM_STDERR:
	case LOG_SYSTEM_CUSTOM:
		va_start(arg, format);
		_log_formatted(level, filename, funcname, line, format, arg);
		va_end(arg);
		break;

	case LOG_SYSTEM_NONE:
	default:
		break;
	}
}

EXPORT_API int mb_log_set_system(enum mb_log_system system)
{
	if (system > LOG_SYSTEM_CUSTOM) {
		error("invalid system(%d)", system);
		return -EINVAL;
	}

	if (_log_override_enabled)
		return 0;

	_log_system = system;

	return 0;
}

EXPORT_API int mb_log_set_handler(mb_log_handler handler, void *user_data)
{
	if (!handler) {
		error("handler is NULL");
		return -EINVAL;
	}

	if (_log_override_enabled)
		return 0;

	_log_system = LOG_SYSTEM_CUSTOM;
	_log_handler = handler;
	_log_handler_user_data = user_data;

	return 0;
}

EXPORT_API void mb_log_set_prefix_fields(enum mb_log_prefix field_set)
{
	_log_prefix_fields = field_set;
}

EXPORT_API void mb_hexdump(uint8_t *data, size_t data_size)
{
	size_t i;

	for (i = 0; i < data_size; i++) {
		printf("%02X ", data[i]);
		if ((i + 1) % 16 == 0) {
			if ((i + 1) % 32 == 0)
				printf("\n");
			else
				printf("  ");
		}
	}

	if (i % 32 != 0)
		printf("\n");

	mb_cbor_json(data, data_size);
}

EXPORT_API void mb_cbor_json(uint8_t *data, size_t data_size)
{
	CborParser parser;
	CborValue value;
	CborError err;
	int flags = 0;

	err = cbor_parser_init(data, data_size, 0, &parser, &value);
	if (err) {
		error("CBOR parsing failed");
		return;
	}

	printf(ANSI_COLOR_DARKGRAY);
	cbor_value_to_json_advance(stdout, &value, flags);
	printf(ANSI_COLOR_NORMAL "\n");
}

EXPORT_API void mb_log_endpoint(oc_endpoint_t *ep)
{
	oc_endpoint_t *tmp;
	int i = 0;

	if (!ep)
		return;

	for (tmp = ep; tmp; tmp = tmp->next, i++) {
		printf(ANSI_COLOR_DARKGRAY);
		printf("- [%d] device=%zd, flags=0x%X ( ", i, tmp->device,
				tmp->flags);
		if (tmp->flags & DISCOVERY)
			printf("DISCOVERY ");
		if (tmp->flags & SECURED)
			printf("SECURED ");
		if (tmp->flags & IPV4)
			printf("IPv4 ");
		if (tmp->flags & IPV6)
			printf("IPv6 ");
		if (tmp->flags & TCP)
			printf("TCP ");
		if (tmp->flags & GATT)
			printf("GATT ");
		if (tmp->flags & MULTICAST)
			printf("MULTICAST");

		printf(")\n");
		printf("  interface_index=%d, priority=%d, version=%d",
				tmp->interface_index, tmp->priority,
				tmp->version);

		printf(ANSI_COLOR_NORMAL "\n");
	}
}
