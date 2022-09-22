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
#include <unistd.h>

void charra_print_hex(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* const prefix,
	const char* const postfix, const bool upper_case) {
	const char* const hex_case = upper_case ? "%02X" : "%02x";

	charra_log_log_raw(level, "%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		charra_log_log_raw(level, hex_case, buf[i]);
	}
	charra_log_log_raw(level, "%s", postfix);
}

void charra_print_str(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* const prefix,
	const char* const postfix) {

	charra_log_log_raw(level, "%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		charra_log_log_raw(level, "%c", buf[i]);
	}
	charra_log_log_raw(level, "%s", postfix);
}

void charra_print_pcr_content(const charra_log_t level,
	const uint8_t* const pcr_selection, const uint32_t pcr_selection_len,
	const uint8_t** const pcrs) {
	for (uint32_t i = 0; i < pcr_selection_len; i++) {
		charra_log_log_raw(level, "%02d: 0x", pcr_selection[i]);
		for (uint32_t j = 0; j < TPM2_SHA256_DIGEST_SIZE; j++) {
			charra_print_hex(level, 1, &pcrs[i][j], "", "", true);
		}
		charra_log_log_raw(level, "\n");
	}
}

CHARRA_RC charra_io_file_exists(const char* const filename) {
	if (access(filename, F_OK) == 0) {
		return CHARRA_RC_SUCCESS;
	} else {
		return CHARRA_RC_ERROR;
	}
}

CHARRA_RC charra_io_read_file(const char* filename, char** const file_content,
	size_t* const file_content_len) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;
	FILE* fp = NULL;

	/* open file */
	if ((fp = fopen(filename, "r")) == NULL) {
		charra_log_error("Cannot open file '%s'.", filename);
		r = CHARRA_RC_ERROR;
		goto error;
	}

	/* get file size */
	ssize_t file_size = -1;
	{
		/* go to end of file */
		if (fseek(fp, 0L, SEEK_END) != 0) {
			r = CHARRA_RC_ERROR;
			goto error;
		}

		/* get position (i.e., the file size) */
		if ((file_size = ftell(fp)) == -1) {
			r = CHARRA_RC_ERROR;
			goto error;
		}

		/* go back to beginning of file */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			r = CHARRA_RC_ERROR;
			goto error;
		}
	}

	/* allocate memory */
	char* file_buffer = NULL;
	if ((file_buffer = malloc(file_size * sizeof(*file_buffer))) == NULL) {
		r = CHARRA_RC_ERROR;
		goto error;
	}

	size_t read_size = fread(file_buffer, sizeof(*file_buffer), file_size, fp);
	if (read_size < (size_t)file_size) {
		charra_log_error(
			"Error while reading file '%s', expected size %zu, got size %zu.",
			filename, file_size, read_size);
		charra_free_if_not_null(file_buffer);
		r = CHARRA_RC_ERROR;
		goto error;
	}

	/* set output arguments */
	*file_content = file_buffer;
	*file_content_len = read_size;

error:

	/* close file */
	if (fp != NULL) {
		if (fclose(fp) != 0) {
			charra_log_error("Error closing file '%s'.", filename);
			charra_free_if_not_null(file_buffer);
			return CHARRA_RC_ERROR;
		}
	}

	return r;
}

void charra_io_free_file_buffer(char** const file_content) {
	charra_free_if_not_null(*file_content);
}

CHARRA_RC charra_io_read_continuous_binary_file(const char* const filename,
	uint8_t** const file_content, size_t* const file_content_len) {
	/* the size of the event log chunks which get read at once */
#define IMA_EVENT_LOG_STEP_SIZE 1024
	/*
	 * Use logarithmic growth for the cvector. Otherwise it would grow on
	 * every call to cvector_push_back().
	 */
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

void charra_io_free_continuous_file_buffer(uint8_t** const file_content) {
	charra_free_if_not_null_ex(*file_content, cvector_free);
}
