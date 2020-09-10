/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_helper.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_helper.h"

#include <inttypes.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"
#include "../common/charra_log.h"
#include "../util/io_util.h"
#include "charra_dto.h"

CHARRA_RC charra_tpm2_pcr_selection_to_bitmap(const uint32_t pcr_selection_len,
	const uint8_t pcr_selection[], TPMS_PCR_SELECTION* pcr_selection_bitmap) {

	/* verify input parameters */
	if (pcr_selection == NULL) {
		charra_log_error(
			"pcr_selection_to_bitmap(...): pcr_selection is NULL.\n");
		return CHARRA_RC_BAD_ARGUMENT;
	} else if (pcr_selection_len > (TPM2_MAX_PCRS - 8)) {
		charra_log_error("pcr_selection_to_bitmap(...): pcr_selection_len "
						 "(%i) greater than TPM2_MAX_PCRS - 8 (%i).\n",
			pcr_selection_len, TPM2_MAX_PCRS - 8);
		return CHARRA_RC_BAD_ARGUMENT;
	}

	/* set length */
	/* FIXME There seems to be a bug with sizes other than 3 */
	pcr_selection_bitmap->sizeofSelect = TPM2_PCR_SELECT_MAX - 1;

	/* initialize PCR selection to all zeros */
	for (uint32_t i = 0; i < pcr_selection_bitmap->sizeofSelect; ++i) {
		pcr_selection_bitmap->pcrSelect[i] = 0;
	}

	/* go through all selected PCRs */
	for (uint32_t i = 0; i < pcr_selection_len; ++i) {
		uint32_t pcr = pcr_selection[i];

		/* sanity check(s) */
		if (pcr >= (TPM2_MAX_PCRS - 8)) {
			charra_log_error("PCR index (%i) greater than TPM2_MAX_PCRS (%i).",
				pcr, TPM2_MAX_PCRS);
		}

		/* set bit in PCR selection bitmap */
		uint32_t selected_byte = (pcr / 8);
		uint8_t selected_bit = 1 << (pcr % 8);
		pcr_selection_bitmap->pcrSelect[selected_byte] |= selected_bit;
	}

	return CHARRA_RC_SUCCESS;
}

CHARRA_RC charra_pcr_selections_to_tpm_pcr_selections(
	const uint32_t pcr_selection_list_len,
	pcr_selection_dto* pcr_selection_list,
	TPML_PCR_SELECTION* tpm_pcr_selections) {
	CHARRA_RC err = CHARRA_RC_SUCCESS;

	/* verify input */
	if (tpm_pcr_selections == NULL) {
		charra_log_error("NULL pointer: tpm_pcr_selections.",
			pcr_selection_list_len, TPM2_NUM_PCR_BANKS);
		return CHARRA_RC_BAD_ARGUMENT;
	} else if (pcr_selection_list_len > TPM2_NUM_PCR_BANKS) {
		charra_log_error("PCR selection length (%d) greater than allowed (%d).",
			pcr_selection_list_len, TPM2_NUM_PCR_BANKS);
		return CHARRA_RC_BAD_ARGUMENT;
	}

	/* set length/count */
	tpm_pcr_selections->count = pcr_selection_list_len;

	for (uint32_t i = 0; i < pcr_selection_list_len; ++i) {
		/* set hash algo */
		tpm_pcr_selections->pcrSelections[i].hash =
			pcr_selection_list[i].tcg_hash_alg_id;

		/* set PCR selection bitmap */
		if ((err = charra_tpm2_pcr_selection_to_bitmap(
				 pcr_selection_list[i].pcrs_len, pcr_selection_list[i].pcrs,
				 &(tpm_pcr_selections->pcrSelections[i]))) !=
			CHARRA_RC_SUCCESS) {
			return err;
		}
	}

	return err;
}
