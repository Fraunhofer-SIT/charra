/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_dto.c
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

#include "charra_dto.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include "../common/charra_log.h"

msg_attestation_request_dto* create_msg_attestation_request_dto() {
	return create_msg_attestation_request_dto_array(1);
}

msg_attestation_request_dto* create_msg_attestation_request_dto_array(
	const size_t n) {
	return (msg_attestation_request_dto*)calloc(
		n, sizeof(msg_attestation_request_dto));
}

void destroy_msg_attestation_request_dto(msg_attestation_request_dto** obj) {
	/* sanity checks */
	if (obj == NULL || *obj == NULL) {
		return;
	}
	{
		/* dereference object */
		msg_attestation_request_dto* iobj = *obj;

		/* hello */
		iobj->hello = false;

		/* sig_key */
		// obj->sig_key_id_len = 0;
		// free(obj->sig_key_id);
		// obj->sig_key_id = NULL;

		/* nonce */
		iobj->nonce_len = 0;
		free(iobj->nonce);
		iobj->nonce = NULL;

		/* pcr_selections */
		destroy_pcr_selection_dto_array(
			&(iobj->pcr_selections), iobj->pcr_selections_len);
		iobj->pcr_selections_len = 0;
	}

	/* free object and invalidate reference to object */
	free(*obj);
	*obj = NULL;
}

pcr_selection_dto* create_pcr_selection_dto() {
	return create_pcr_selection_dto_array(1);
}

pcr_selection_dto* create_pcr_selection_dto_array(const size_t n) {
	return (pcr_selection_dto*)calloc(n, sizeof(pcr_selection_dto));
}

void destroy_pcr_selection_dto(pcr_selection_dto** obj) {
	destroy_pcr_selection_dto_array(obj, 1);
}

void destroy_pcr_selection_dto_array(pcr_selection_dto** obj, const size_t n) {
	/* sanity checks */
	if (obj == NULL || *obj == NULL) {
		return;
	}
	{
		/* dereference object */
		pcr_selection_dto* iobj = *obj;

		for (size_t i = 0; i < n; ++i) {
			/* tcg_hash_alg_id */
			iobj[i].tcg_hash_alg_id = 0;

			/* pcrs */
			free(iobj[i].pcrs);
			iobj[i].pcrs = NULL;
			iobj[i].pcrs_len = 0;
		}
	}

	/* free object and invalidate reference to object */
	free(*obj);
	*obj = NULL;
}
