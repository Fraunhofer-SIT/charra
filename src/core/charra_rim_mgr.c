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

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../util/crypto_util.h"
#include "../util/io_util.h"
#include "../util/parser_util.h"

uint32_t pcr_selection_index = 0;
uint32_t pcr_set_index = 0;
uint32_t line_number = 1;

static void free_reference_pcrs(
	uint8_t** reference_pcrs, uint32_t reference_pcr_selection_len) {
	for (uint32_t i = 0; i < reference_pcr_selection_len; i++) {
		free(reference_pcrs[i]);
	}
	free(reference_pcrs);
}

/**
 * @brief Check that the last reference PCR set was complete and then compute
 * its digest and compare it against the digest given in the attest_struct.
 *
 * @param reference_pcrs the 2D array holding all PCR values needed for the
 * PCR composite digest
 * @param reference_pcr_selection the array holding the PCR indexes used for
 * to compute the digest. Only used for logging purposes.
 * @param reference_pcr_selection_len the number of PCR indexes used for the
 * computation of the digest, also the length of both arrays
 * @param attest_struct The struct holding the attestation data from the
 * attester, including the PCR digest.
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_NO_MATCH when the digests
 * did not match, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC handle_end_of_pcr_set(uint8_t** reference_pcrs,
	const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len,
	const TPMS_ATTEST* const attest_struct) {
	if (pcr_selection_index < reference_pcr_selection_len) {
		// we found an empty newline, but the previous set of PCRs was not
		// complete.
		charra_log_error(
			"Error while parsing reference PCRs: "
			"PCR set ending in line %d does not hold selected PCR %d.",
			line_number, reference_pcr_selection[pcr_selection_index]);
		return CHARRA_RC_ERROR;
	}

	charra_log_debug(
		"Checking PCR composite digest at PCR set index %d:", pcr_set_index);
	CHARRA_RC rc = compute_and_check_PCR_digest(
		reference_pcrs, reference_pcr_selection_len, attest_struct);
	if (rc == CHARRA_RC_ERROR) {
		charra_log_error("Unexpected error while computing PCR digest at index "
						 "%d of the PCR sets",
			pcr_set_index);
	} else if (rc == CHARRA_RC_SUCCESS) {
		charra_log_info(
			"Found matching PCR composite digest at index %d of the PCR sets.",
			pcr_set_index);
	}
	return rc;
}

/**
 * @brief Parse one line from the reference PCR file holding an PCR index and
 * its PCR value. Save the PCR value into the reference_prcrs array.
 *
 * @param c a pointer to the first character of the PCR index
 * @param eol a pointer to the end of the line
 * @param reference_pcrs the 2D array holding all PCR values
 * @param reference_pcr_selection the array holding the PCR indexes we need to
 * parse.
 * @param reference_pcr_selection_len the number of PCR indexes.
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_ERROR on errors.
 */
static CHARRA_RC parse_pcr_value_line(char* index_char, char* eol,
	uint8_t** reference_pcrs, const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len) {
	if (pcr_selection_index < reference_pcr_selection_len) {
		// only parse the line if we actually need another PCR for our digest,
		// otherwise just skip it
		int file_pcr_index = parse_pcr_index(index_char);
		if (file_pcr_index < 0) {
			charra_log_error(
				"Error while parsing line %d from reference PCR file: "
				"Unparseable PCR Index.",
				line_number);
			return CHARRA_RC_ERROR;
		}

		if (file_pcr_index == reference_pcr_selection[pcr_selection_index]) {
			// PCR in current line is part of the PCR selection
			CHARRA_RC charra_rc = parse_pcr_value(
				index_char, eol, reference_pcrs[pcr_selection_index]);
			if (charra_rc != CHARRA_RC_SUCCESS) {
				charra_log_error("Error while parsing PCR value in "
								 "line %d from reference PCR file.",
					line_number);
				return charra_rc;
			}
			// current selected PCR parsed, increase index
			pcr_selection_index++;
		}
	}
	return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_check_pcr_digest_against_reference(const char* filename,
	const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len,
	const TPMS_ATTEST* const attest_struct) {

	/* sanity check */
	if (reference_pcr_selection_len >= TPM2_MAX_PCRS) {
		charra_log_error(
			"Bad PCR selection length: %d.", reference_pcr_selection_len);
		return CHARRA_RC_BAD_ARGUMENT;
	}

	// allocate memory for the pcr values read from the file
	uint8_t** reference_pcrs =
		malloc(reference_pcr_selection_len * sizeof(uint8_t*));
	for (uint32_t i = 0; i < reference_pcr_selection_len; i++) {
		reference_pcrs[i] = malloc(TPM2_SHA256_DIGEST_SIZE * sizeof(uint8_t));
	}
	char* file_content = NULL;

	CHARRA_RC charra_rc = CHARRA_RC_ERROR;

	if (filename != NULL) {
		/* read reference PCR file */
		size_t file_size = 0;
		CHARRA_RC read_result =
			charra_io_read_file(filename, &file_content, &file_size);
		if (read_result != CHARRA_RC_SUCCESS) {
			return read_result;
		}

		pcr_selection_index = 0;
		pcr_set_index = 0;
		line_number = 1;
		for (char* c = file_content; c < file_content + file_size; c++) {
			/* c is somewhere at the beginning of a new line. loop over file
			 * contents until we find a digit (assumed to be a PCR index) or
			 * '\n' signaling a new line. If we find the PCR index, we parse the
			 * rest of the line and set c to end of the line, thus the next
			 * iteration will be at the start of the next line. If we find '\n'
			 * before we find a PCR index, this means we found an empty newline,
			 * which signals a new set of reference PCR values. Thus we need to
			 * compare the digest of the current set of PCRs to the digest of
			 * the attester and then clear the current set of reference PCRs
			 * from memory.
			 */

			if (*c == '\n') {
				// we are on an empty newline because we found two '\n' without
				// a PCR index inbetween
				charra_rc = handle_end_of_pcr_set(reference_pcrs,
					reference_pcr_selection, reference_pcr_selection_len,
					attest_struct);
				// do not return when digests don't match, we have more PCR sets
				// to try out
				if (charra_rc != CHARRA_RC_NO_MATCH) {
					goto returns;
				}

				pcr_selection_index = 0;
				pcr_set_index++;
				line_number++;
			}

			if (isdigit(*c) > 0) {
				//*c is a digit, we are at the start of an index
				char* eol = find_end_of_line(c, file_content + file_size);

				charra_rc = parse_pcr_value_line(c, eol, reference_pcrs,
					reference_pcr_selection, reference_pcr_selection_len);
				if (charra_rc != CHARRA_RC_SUCCESS) {
					goto returns;
				}
				// set c (current char) to eol because the whole line has been
				// parsed
				c = eol;
				line_number++;
			}
		}
		if (pcr_selection_index != 0) {
			// The last PCR set was not yet handled
			charra_rc =
				handle_end_of_pcr_set(reference_pcrs, reference_pcr_selection,
					reference_pcr_selection_len, attest_struct);
			goto returns;
		}
		// end of reference PCR file and no matching PCR composite digest found
		charra_rc = CHARRA_RC_VERIFICATION_FAILED;
	} else {
		// filename was NULL, assume that empty PCRs shall be used as reference
		// PCRs
		charra_log_warn("Using empty PCRs as reference PCRs");
		for (size_t i = 0; i < reference_pcr_selection_len; ++i) {
			for (uint32_t j = 0; j < TPM2_SHA256_DIGEST_SIZE; ++j) {
				reference_pcrs[i][j] = 0;
			}
		}
		charra_rc = compute_and_check_PCR_digest(
			reference_pcrs, reference_pcr_selection_len, attest_struct);
	}

returns:
	if (charra_rc == CHARRA_RC_NO_MATCH) {
		// no match until end of reference PCR file, verification failed.
		charra_rc = CHARRA_RC_VERIFICATION_FAILED;
	}
	charra_free_if_not_null(file_content);
	free_reference_pcrs(reference_pcrs, reference_pcr_selection_len);
	return charra_rc;
}
