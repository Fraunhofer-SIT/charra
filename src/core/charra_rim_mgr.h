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
 * @brief Read all sets of reference PCRs from filename. Check if any of the
 * sets produces the same digest as the digest passed as attester_pcr_digest.
 *
 * the reference pcr file is expected to be formatted in the same way as the
 * output of tpm2_pcrread, e.g.:
 * 0 : 0x0000000000000000000000000000000000000000000000000000000000000000
 * ...
 * 23: 0x0000000000000000000000000000000000000000000000000000000000000000
 * Entries are identified by the number at the start of the line.
 * Entries are allowed to be missing if they are not in the
 * reference_pcr_selection. Entries are expected to be in order.
 * Multiple sets of PCR states are seperated by an empty newline.
 *
 * @param[in] filename The path of the file which holds the reference PCR values
 * @param[in] reference_pcr_selection An array of PCRs indexes that we need.
 * @param[in] reference_pcr_selection_len The number of PCRs indexes that we
 * need.
 * @param[in] attest_struct The struct holding the attestation data from the
 * attester, including the PCR digest.
 * @returns CHARRA_RC_SUCCESS on success, CHARRA_RC_VERIFICATION_FAILED when
 * none of the reference PCR states matched the attestation state,
 * CHARRA_RC_ERROR on errors.
 */
CHARRA_RC charra_check_pcr_digest_against_reference(const char* filename,
	const uint8_t* reference_pcr_selection,
	const uint32_t reference_pcr_selection_len,
	const TPMS_ATTEST* const attest_struct);

#endif /* CHARRA_RIM_MGR_H */
