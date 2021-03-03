/* SPDX-License-Identifier: MIT */
/*****************************************************************************
 * Copyright (c) 2017 rxi.
 ****************************************************************************/

/**
 * @file charra_log.h
 * @author rxi (https://github.com/rxi) (original author)
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright (c) 2017 rxi.
 *
 * @license MIT License (SPDX-License-Identifier: MIT).
 */

#ifndef CHARRA_LOG_H
#define CHARRA_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define CHARRA_LOG_VERSION "1.0.0"

typedef void (*charra_log_LockFn)(void* udata, int lock);

typedef enum {
	CHARRA_LOG_TRACE,
	CHARRA_LOG_DEBUG,
	CHARRA_LOG_INFO,
	CHARRA_LOG_WARN,
	CHARRA_LOG_ERROR,
	CHARRA_LOG_FATAL,
} charra_log_t;

#if (!CHARRA_LOG_DISABLE)
#define charra_log_trace(...)                                                  \
	charra_log_log(CHARRA_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define charra_log_debug(...)                                                  \
	charra_log_log(CHARRA_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define charra_log_info(...)                                                   \
	charra_log_log(CHARRA_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define charra_log_warn(...)                                                   \
	charra_log_log(CHARRA_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define charra_log_error(...)                                                  \
	charra_log_log(CHARRA_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define charra_log_fatal(...)                                                  \
	charra_log_log(CHARRA_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define charra_log_trace(...)                                                  \
	{ ; }
#define charra_log_debug(...)                                                  \
	{ ; }
#define charra_log_info(...)                                                   \
	{ ; }
#define charra_log_warn(...)                                                   \
	{ ; }
#define charra_log_error(...)                                                  \
	{ ; }
#define charra_log_fatal(...)                                                  \
	{ ; }
#endif

void charra_log_set_udata(void* udata);
void charra_log_set_lock(charra_log_LockFn fn);
void charra_log_set_fp(FILE* fp);
void charra_log_set_level(int level);
void charra_log_set_quiet(int enable);

void charra_log_log(
	int level, const char* file, int line, const char* fmt, ...);

/**
 * @brief Parses the CHARRA log level from string and returns the appropriate
 * enum constant. A default log level must be provided in case there is no match
 * for the string respresentation.
 *
 * @param[in] log_level_str the CHARRA log level string.
 * @param[in] default_log_level the default CHARRA log level in case
 * there is no match for the string respresentation.
 * @return charra_log_t the CHARRA log level.
 */
charra_log_t charra_log_level_from_str(
	const char* log_level_str, const charra_log_t default_log_level);

#endif /* CHARRA_LOG_H */
