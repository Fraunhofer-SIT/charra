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

CHARRA_RC charra_get_reference_pcrs_sha256(
	const uint8_t reference_pcr_selection[TPM2_MAX_PCRS],
	const uint32_t reference_pcr_selection_len,
	uint8_t* reference_pcrs[TPM2_MAX_PCRS]);

extern const uint8_t REFERENCE_PCRS_SHA256[TPM2_MAX_PCRS]
										  [TPM2_SHA256_DIGEST_SIZE];

#endif /* CHARRA_RIM_MGR_H */
