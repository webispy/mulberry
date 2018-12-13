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

#ifndef __MULBERRY_LOG_H__
#define __MULBERRY_LOG_H__

#include <stdio.h>
#include <stdint.h>

#include "oc_endpoint.h"

/**
 * @brief     Convenient macro to fill file, function and line information
 * @param[in] level logging level
 * @param[in] fmt printf format string
 * @see       enum log_level
 */
#define mb_log(level, fmt, ...) \
		mb_log_print(level, __FILENAME__, __PRETTY_FUNCTION__, \
			__LINE__, fmt, ## __VA_ARGS__)

#ifdef CONFIG_RELEASE
#define dbg(fmt, ...)
#define info(fmt, ...)
#define warn(fmt, ...)
#else
#define dbg(fmt, ...) mb_log(LOG_LEVEL_DEBUG, fmt, ## __VA_ARGS__)
#define info(fmt, ...) mb_log(LOG_LEVEL_INFO, fmt, ## __VA_ARGS__)
#define warn(fmt, ...) mb_log(LOG_LEVEL_WARNING, fmt, ## __VA_ARGS__)
#endif

#define error(fmt, ...) mb_log(LOG_LEVEL_ERROR, fmt, ## __VA_ARGS__)

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief     logging levels.
 *
 */
enum mb_log_level {
	LOG_LEVEL_ERROR, /* Error level */
	LOG_LEVEL_WARNING, /* Warning level. Hide in RELEASE mode */
	LOG_LEVEL_INFO, /* Information level. Hide in RELEASE mode */
	LOG_LEVEL_DEBUG /* Debug level. Hide in RELEASE mode */
};

/**
 * @brief     logging backend system
 * @see       log_set_system()
 * @see       log_set_handler()
 */
enum mb_log_system {
	LOG_SYSTEM_STDERR, /**< Standard error */
	LOG_SYSTEM_SYSLOG, /**< syslog */
	LOG_SYSTEM_NONE, /**< no log */
	LOG_SYSTEM_CUSTOM /**< use custom log handler by log_set_handler() */
};

/**
 * @brief     logging prefix
 *
 * Additional information to log message.
 * Masking the field by log_set_prefix_fields()
 *
 * @see       log_set_prefix_fields()
 */
enum mb_log_prefix {
	LOG_PREFIX_NONE = 0, /**< No prefix */
	LOG_PREFIX_TIMESTAMP = (1 << 0), /**< mm-dd HH:MM:SS.000 */
	LOG_PREFIX_PID = (1 << 1), /**< Process ID */
	LOG_PREFIX_TID = (1 << 2), /**< Thread ID */
	LOG_PREFIX_LEVEL = (1 << 3), /**< D, I, W, E */
	LOG_PREFIX_FILEPATH = (1 << 4), /**< Full path with file name */
	LOG_PREFIX_FILENAME = (1 << 5), /**< File name */
	LOG_PREFIX_FUNCTION = (1 << 6), /**< Function name */
	LOG_PREFIX_LINE = (1 << 7), /**< Line number */
	LOG_PREFIX_DEFAULT = (LOG_PREFIX_TIMESTAMP | LOG_PREFIX_PID
			| LOG_PREFIX_TID | LOG_PREFIX_LEVEL
			| LOG_PREFIX_FILENAME | LOG_PREFIX_LINE),
	/**< TIMESTAMP + PID + TID + LEVEL + FILENAME + LINE*/
	LOG_PREFIX_ALL = (LOG_PREFIX_DEFAULT | LOG_PREFIX_FUNCTION
			| LOG_PREFIX_FILEPATH) /**< All prefix */
};

/**
 * @brief     logging function
 *
 * Use convenient macro(e.g. dbg(),warn(), ...) instead of this api due to
 * difficult to fill each parameters.
 *
 * @param[in] level log level
 * @param[in] filename source file name (e.g. __FILE__)
 * @param[in] funcname function name (e.g. __FUNCTION__)
 * @param[in] line source file line number
 * @param[in] format printf format string
 * @see       dbg()
 * @see       info()
 * @see       warn()
 * @see       err()
 */
void mb_log_print(enum mb_log_level level, const char *filename,
		const char *funcname, int line, const char *format, ...);

/**
 * @brief     Custom log hook handler
 *
 * Grab all log and deal own way. (e.g. custom file writing)
 *
 * @param[in] level log level
 * @param[in] prefix generated additional information
 *                   (e.g. timestamp, line number)
 * @param[in] msg original log message
 * @param[in] user_data The user data passed from the callback function
 * @see       log_set_handler()
 * @see       log_set_prefix_fields()
 */
typedef void (*mb_log_handler)(enum mb_log_level level, const char *prefix,
		const char *msg, void *user_data);

/**
 * @brief     Set logging backend system
 *
 * You can override environment variables (e.g. MULBERRY_LOG=syslog ./a.out)
 * MULBERRY_LOG is prior to log_set_system() in source code
 *
 * @see       enum log_system
 */
int mb_log_set_system(enum mb_log_system system);

/**
 * @breif     Set custom log handler
 *
 * When set the handler, log system changed to LOG_SYSTEM_CUSTOM
 *
 * @param[in] handler callback
 * @param[in] user_data The user data to be passed to the callback function
 * @see       log_handler
 */
int mb_log_set_handler(mb_log_handler handler, void *user_data);

/**
 * @brief     Set the additional information
 *
 * @param[in] field_set bitmask by enum log_prefix
 * @see       enum log_prefix
 */
void mb_log_set_prefix_fields(enum mb_log_prefix field_set);

void mb_hexdump(uint8_t *data, size_t data_size);

void mb_cbor_json(uint8_t *data, size_t data_size);

void mb_log_endpoint(oc_endpoint_t *ep);

#ifdef __cplusplus
}
#endif

#endif
