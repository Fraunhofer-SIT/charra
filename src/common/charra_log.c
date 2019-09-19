/* SPDX-License-Identifier: MIT */
/*****************************************************************************
 * Copyright (c) 2017 rxi.
 ****************************************************************************/

/**
 * @file charra_log.c
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

#include "charra_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct {
	void* udata;
	charra_log_LockFn lock;
	FILE* fp;
	int level;
	int quiet;
} L;

static const char* charra_level_names[] = {
	"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

#ifdef CHARRA_LOG_USE_COLOR
static const char* charra_level_colors[] = {
	"\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"};
#endif

static void charra_log_lock(void) {
	if (L.lock) {
		L.lock(L.udata, 1);
	}
}

static void charra_log_unlock(void) {
	if (L.lock) {
		L.lock(L.udata, 0);
	}
}

void charra_log_set_udata(void* udata) { L.udata = udata; }

void charra_log_set_lock(charra_log_LockFn fn) { L.lock = fn; }

void charra_log_set_fp(FILE* fp) { L.fp = fp; }

void charra_log_set_level(int level) { L.level = level; }

void charra_log_set_quiet(int enable) { L.quiet = enable ? 1 : 0; }

void charra_log_log(
	int level, const char* file, int line, const char* fmt, ...) {
	if (level < L.level) {
		return;
	}

	/* acquire lock */
	charra_log_lock();

	/* get current time */
	time_t t = time(NULL);
	struct tm* lt = localtime(&t);

	/* log to stderr */
	if (!L.quiet) {
		va_list args;
		char buf[16];
		buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
#ifdef CHARRA_LOG_USE_COLOR
		fprintf(stderr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf,
			charra_level_colors[level], charra_level_names[level], file, line);
#else
		fprintf(stderr, "%s %-5s %s:%d: ", buf, charra_level_names[level], file,
			line);
#endif
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	/* log to file */
	if (L.fp) {
		va_list args;
		char buf[32];
		buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt)] = '\0';
		fprintf(L.fp, "%s %-5s %s:%d: ", buf, charra_level_names[level], file,
			line);
		va_start(args, fmt);
		vfprintf(L.fp, fmt, args);
		va_end(args);
		fprintf(L.fp, "\n");
		fflush(L.fp);
	}

	/* release lock */
	charra_log_unlock();
}
