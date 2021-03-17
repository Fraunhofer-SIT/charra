/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides I/O functions, including print.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "io_util.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_cvector.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

void charra_print_hex(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix, const bool upper_case) {
	const char* const hex_case = upper_case ? "%02X" : "%02x";

	printf("%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		printf(hex_case, buf[i]);
	}
	printf("%s", postfix);
}

void charra_print_str(const size_t buf_len, const uint8_t* const buf,
	const char* prefix, const char* postfix) {

	printf("%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		printf("%c", buf[i]);
	}
	printf("%s", postfix);
}

CHARRA_RC charra_io_read_continuous_binary_file(
	const char* filename, uint8_t** file_content, size_t* file_content_len) {
	// the size of the event log chunks which get read at once
#define IMA_EVENT_LOG_STEP_SIZE 1024
	// use logarithmic growth for the cvector. Otherwise it would grow on
	// every cvector_push_back() call
#define CVECTOR_LOGARITHMIC_GROWTH

	cvector_vector_type(uint8_t) file_content_cvector = NULL;
	FILE* fp = NULL;
	if ((fp = fopen(filename, "rb")) == NULL) {
		charra_log_error("Cannot open file '%s'.", filename);
		return CHARRA_RC_ERROR;
	}
	uint8_t processing_array[IMA_EVENT_LOG_STEP_SIZE] = {0};
	size_t read_size = 0;
	do {
		read_size = fread(processing_array, sizeof(*processing_array),
			IMA_EVENT_LOG_STEP_SIZE, fp);
		for (size_t i = 0; i < read_size; ++i) {
			cvector_push_back(file_content_cvector, processing_array[i]);
		}
	} while (read_size == IMA_EVENT_LOG_STEP_SIZE);

	/* flush and close file */
	if (fflush(fp) != 0) {
		charra_log_error("Error flushing file '%s'.", filename);
		charra_free_if_not_null_ex(file_content_cvector, cvector_free);
		return CHARRA_RC_ERROR;
	}
	if (fclose(fp) != 0) {
		charra_log_error("Error closing file '%s'.", filename);
		charra_free_if_not_null_ex(file_content_cvector, cvector_free);
		return CHARRA_RC_ERROR;
	}
	*file_content_len = cvector_size(file_content_cvector);
	*file_content = file_content_cvector;
	return CHARRA_RC_SUCCESS;
}

void charra_free_continous_file_buffer(uint8_t** file_content) {
	charra_free_if_not_null_ex(*file_content, cvector_free);
}
