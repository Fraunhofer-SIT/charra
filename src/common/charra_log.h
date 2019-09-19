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

#define CHARRA_LOG_VERSION "1.0.0"

typedef void (*charra_log_LockFn)(void* udata, int lock);

enum {
	CHARRA_LOG_TRACE,
	CHARRA_LOG_DEBUG,
	CHARRA_LOG_INFO,
	CHARRA_LOG_WARN,
	CHARRA_LOG_ERROR,
	CHARRA_LOG_FATAL,
};

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

void charra_log_set_udata(void* udata);
void charra_log_set_lock(charra_log_LockFn fn);
void charra_log_set_fp(FILE* fp);
void charra_log_set_level(int level);
void charra_log_set_quiet(int enable);

void charra_log_log(
	int level, const char* file, int line, const char* fmt, ...);

#endif /* CHARRA_LOG_H */
