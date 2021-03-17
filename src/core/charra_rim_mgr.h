/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_rim_mgr.h
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

#ifndef CHARRA_RIM_MGR_H
#define CHARRA_RIM_MGR_H

#include <inttypes.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_error.h"

/**
 * @brief Read reference PCRs from filename. Put those that we need for the
 * attestation into the refernce_pcrs buffer. The set of PCRs that we need is
 * defined by the reference PCR selection.
 *
 * filename is expected to be formatted in the same way as the
 * output of tpm2_pcrread, e.g.:
 * 0 : 0x0000000000000000000000000000000000000000000000000000000000000000
 * ...
 * 23: 0x0000000000000000000000000000000000000000000000000000000000000000
 * Entries are identified by the number at the start of the line.
 * Entries are allowed to be missing if they are not in the
 * reference_pcr_selection. Entries are expected to be in order.
 *
 * @param[in] filename The path of the file which holds the reference PCR values
 * @param[in] reference_pcr_selection An array of PCRs indexes that we need.
 * @param[in] reference_pcr_selection_len The number of PCRs indexes that we
 * need.
 * @param[out] reference_pcrs An array of arrays which will hold the PCR values
 * after the call.
 */
CHARRA_RC charra_get_reference_pcrs_sha256(const char* filename,
	const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len, uint8_t** reference_pcrs);

/**
 * @brief free reference PCR arrays
 *
 * @param reference_pcrs Array of arrays holding the PCR values
 */
void charra_free_reference_pcrs_sha256(
	uint8_t** reference_pcrs, uint32_t reference_pcr_selection_len);

#endif /* CHARRA_RIM_MGR_H */
