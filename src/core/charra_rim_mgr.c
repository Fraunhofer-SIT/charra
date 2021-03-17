/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_rim_mgr.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_rim_mgr.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/io_util.h"

CHARRA_RC charra_get_reference_pcrs_sha256(const char* filename,
	const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len, uint8_t** reference_pcrs) {

	/* sanity check */
	if (reference_pcr_selection_len >= TPM2_MAX_PCRS) {
		charra_log_error(
			"Bad PCR selection length: %d.", reference_pcr_selection_len);
		return CHARRA_RC_BAD_ARGUMENT;
	}

	if (filename != NULL) {
		/* read reference PCR file */
		char* file_content = NULL;
		size_t file_size = 0;
		CHARRA_RC read_result =
			charra_io_read_file(filename, &file_content, &file_size);
		if (read_result != CHARRA_RC_SUCCESS) {
			return read_result;
		}
		/* file_content is expected to be formatted in the same way as the
		 * output of tpm2_pcrread, e.g.:
		 * 0 : 0x0000000000000000000000000000000000000000000000000000000000000000
		 * ...
		 * 23: 0x0000000000000000000000000000000000000000000000000000000000000000
		 * Entries are identified by the number at the start of the line.
		 * Entries are allowed to be missing if they are not in the
		 * reference_pcr_selection. Entries are expected to be in order.
		 */
		uint32_t pcr_selection_index = 0;
		for (char* c = file_content; c < file_content + file_size; c++) {
			// loop over file contents until we find a digit (assumed to be the
			// PCR index at the start of the line)
			if (isdigit(*c) > 0) { //*c is a number, we are at the start of a line
				errno = 0;
				char* end = NULL;
				int file_pcr_index =
					strtoul(c, &end, 10); // parse 1 or 2 digits as index
				if (end == c || errno != 0) {
					charra_log_error("Error while parsing reference PCR "
									 "values: Unparseable PCR Index.");
					charra_free_if_not_null(file_content);
					return CHARRA_RC_ERROR;
				}
				char* eol = NULL; // end of line
				// search for end of line and set eol accordingly
				for (eol = c; eol < file_content + file_size && *eol != '\n';
					 eol++) {

				} // loop ends when end of file or end of line is reached

				if (file_pcr_index == reference_pcr_selection[pcr_selection_index]) {
					// PCR in current line is part of the PCR selection
					// search for the start of the PCR hex value
					char* hex_start;
					for (hex_start = c;
						 !(*(hex_start - 2) == '0' && *(hex_start - 1) == 'x');
						 hex_start++) {
						if (hex_start >= eol) {
							charra_log_error(
								"Error while parsing reference PCR index %d: "
								"Unexpected end of line.",
								file_pcr_index);
							charra_free_if_not_null(file_content);
							return CHARRA_RC_ERROR;
						}
					} // loop ends on first character after the '0x'

					// iterate over all bytes of the digest
					for (uint32_t digest_index = 0;
						 digest_index < TPM2_SHA256_DIGEST_SIZE;
						 digest_index++) {
						// hex_index is the byte in string representation at the
						// current digest_index
						char* hex_index = hex_start + (digest_index * 2);
						if (hex_index + 1 >= eol) {
							charra_log_error("Error while parsing reference "
											 "PCR digest of index %d: "
											 "Unexpected end of line.",
								file_pcr_index);
							charra_free_if_not_null(file_content);
							return CHARRA_RC_ERROR;
						}

						// convert byte in string representation to byte as uint8_t
						char byte_as_string[3] = {0};
						// copy substring into other string because otherwise strtoul
						// would read more than one byte
						memcpy(byte_as_string, hex_index, 2);
						byte_as_string[2] = '\0';
						errno = 0;
						char* end = NULL;
						unsigned long int hex_value = strtoul(byte_as_string, &end, 16);
						if (end == byte_as_string || errno != 0 || hex_value > 255) {
							charra_log_error("Error while parsing reference "
											 "PCR digest of index %d: "
											 "Digest not parseable.",
								file_pcr_index);
							charra_free_if_not_null(file_content);
							return CHARRA_RC_ERROR;
						}
						reference_pcrs[pcr_selection_index][digest_index] =
							(uint8_t) hex_value;
					}

					// set PCR index to next PCR
					pcr_selection_index++;
					if (pcr_selection_index >= reference_pcr_selection_len) {
						// all selected PCRs have been read from the file
						break;
					}
				}
				// set c (current char) to eol because the whole line has been parsed
				c = eol;
			}
		}
		charra_free_if_not_null(file_content);
		if (pcr_selection_index < reference_pcr_selection_len) {
			charra_log_error("Error while parsing reference PCR digest: "
							 "Reference file does not hold selected PCR %d.",
				reference_pcr_selection[pcr_selection_index]);
			return CHARRA_RC_ERROR;
		}
	} else {
		charra_log_warn("Using empty PCRs as reference PCRs");
		for (size_t i = 0; i < reference_pcr_selection_len; ++i) {
			for (uint32_t j = 0; j < TPM2_SHA256_DIGEST_SIZE; ++j) {
				reference_pcrs[i][j] = 0;
			}
		}
	}

	return CHARRA_RC_SUCCESS;
}

void charra_free_reference_pcrs_sha256(
	uint8_t** reference_pcrs, uint32_t reference_pcr_selection_len) {
	if (reference_pcrs != NULL) {
		for (uint32_t i = 0; i < reference_pcr_selection_len; i++) {
			charra_free_if_not_null(reference_pcrs[i]);
		}
		free(reference_pcrs);
	}
}
