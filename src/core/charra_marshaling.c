/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_marshaling.c
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

#include "charra_marshaling.h"

#include <assert.h>
#include <inttypes.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../common/charra_macro.h"
#include "../core/charra_dto.h"
#include "../util/cbor_util.h"
#include "../util/tpm2_util.h"

static CHARRA_RC charra_marshal_attestation_request_internal(
	const msg_attestation_request_dto* attestation_request, UsefulBuf buf_in,
	UsefulBufC* buf_out) {
	charra_log_trace("<ENTER> %s()", __func__);

	/* verify input */
	assert(attestation_request != NULL);
	assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
	assert(attestation_request->pcr_selections != NULL);
	assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
	assert(attestation_request->pcr_selections->pcrs != NULL);
	assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
	assert(attestation_request->nonce != NULL);
	if (attestation_request->event_log_path_len != 0) {
		assert(attestation_request->event_log_path != NULL);
	}

	QCBOREncodeContext ec = {0};

	QCBOREncode_Init(&ec, buf_in);

	/* root array */
	QCBOREncode_OpenArray(&ec);

	/* encode "hello" */
	QCBOREncode_AddBool(&ec, attestation_request->hello);

	/* encode "key-id" */
	UsefulBufC key_id = {
		attestation_request->sig_key_id, attestation_request->sig_key_id_len};
	QCBOREncode_AddBytes(&ec, key_id);

	/* encode "nonce" */
	UsefulBufC nonce = {
		attestation_request->nonce, attestation_request->nonce_len};
	QCBOREncode_AddBytes(&ec, nonce);

	/* encode "pcr-selections" */
	QCBOREncode_OpenArray(&ec);
	for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
		QCBOREncode_OpenArray(&ec);
		QCBOREncode_AddInt64(
			&ec, attestation_request->pcr_selections[i].tcg_hash_alg_id);
		{
			/* open array: pcrs_array_encoder */
			QCBOREncode_OpenArray(&ec);
			for (uint32_t j = 0;
				 j < attestation_request->pcr_selections[i].pcrs_len; ++j) {

				QCBOREncode_AddUInt64(
					&ec, attestation_request->pcr_selections[i].pcrs[j]);
			}
			/* close array: pcrs_array_encoder */
			QCBOREncode_CloseArray(&ec);
		}
		/* close array: pcr_selection_array_encoder */
		QCBOREncode_CloseArray(&ec);
	}

	/* close array: pcr_selections_array_encoder */
	QCBOREncode_CloseArray(&ec);

	/* encode "event_log_path" */
	UsefulBufC event_log_path = {.ptr = attestation_request->event_log_path,
		.len = attestation_request->event_log_path_len};
	QCBOREncode_AddBytes(&ec, event_log_path);

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&ec);

	if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
		return CHARRA_RC_SUCCESS;
	} else {
		return CHARRA_RC_MARSHALING_ERROR;
	}
}

CHARRA_RC charra_marshal_attestation_request_size(
	const msg_attestation_request_dto* attestation_request,
	size_t* marshaled_data_len) {
	charra_log_trace("<ENTER> %s()", __func__);

	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* passing this buffer instructs QCBOR to return only the size and do no
	 * actual encoding */
	UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
	UsefulBufC buf_out = {0};

	if ((charra_r = charra_marshal_attestation_request_internal(
			 attestation_request, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
		*marshaled_data_len = buf_out.len;
	}

	return charra_r;
}

CHARRA_RC charra_marshal_attestation_request(
	const msg_attestation_request_dto* attestation_request,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
	charra_log_trace("<ENTER> %s()", __func__);

	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* verify input */
	assert(attestation_request != NULL);
	assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
	assert(attestation_request->pcr_selections != NULL);
	assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
	assert(attestation_request->pcr_selections->pcrs != NULL);
	assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
	assert(attestation_request->nonce != NULL);
	if (attestation_request->event_log_path_len != 0) {
		assert(attestation_request->event_log_path != NULL);
	}

	/* compute size of marshaled data */
	UsefulBuf buf_in = {.len = 0, .ptr = NULL};
	if ((charra_r = charra_marshal_attestation_request_size(
			 attestation_request, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
		charra_log_error("Could not compute size of marshaled data.");
		return charra_r;
	}
	charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

	/* allocate buffer size */
	if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
		charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
		return CHARRA_RC_MARSHALING_ERROR;
	}
	charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

	/* encode */
	UsefulBufC buf_out = {.len = 0, .ptr = NULL};
	if ((charra_r = charra_marshal_attestation_request_internal(
			 attestation_request, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
		charra_log_error("Could not marshal data.");
		return charra_r;
	}

	/* set output parameters */
	*marshaled_data_len = buf_out.len;
	*marshaled_data = (uint8_t*)buf_out.ptr;

	return charra_r;
}

// TODO implement this function using QCBOREncode_* functions
CHARRA_RC charra_unmarshal_attestation_request(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	msg_attestation_request_dto* attestation_request) {
	msg_attestation_request_dto req = {0};

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext dc = {0};
	QCBORItem item = {0};

	QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

	if (charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY))
		goto cbor_parse_error;

	/* parse "hello" (bool) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, CHARRA_CBOR_TYPE_BOOLEAN)))
		goto cbor_parse_error;
	req.hello = charra_cbor_get_bool_val(&item);

	/* parse "key-id" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	req.sig_key_id_len = item.val.string.len;
	memcpy(&(req.sig_key_id), item.val.string.ptr, req.sig_key_id_len);

	/* parse "nonce" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	req.nonce_len = item.val.string.len;
	memcpy(&(req.nonce), item.val.string.ptr, req.nonce_len);

	/* parse array "pcr-selections" */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;

	/* initialize array and array length */
	req.pcr_selections_len = (uint32_t)item.val.uCount;

	/* go through all elements */
	for (uint32_t i = 0; i < req.pcr_selections_len; ++i) {
		/* parse array "pcr-selection" */
		if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
			goto cbor_parse_error;

		/* parse "tcg-hash-alg-id" (UINT16) */
		if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
			goto cbor_parse_error;
		req.pcr_selections[i].tcg_hash_alg_id = (uint16_t)item.val.uint64;

		/* parse array "pcrs" */
		if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
			goto cbor_parse_error;

		/* initialize array and array length */
		req.pcr_selections[i].pcrs_len = (uint32_t)item.val.uCount;

		/* go through all elements */
		for (uint32_t j = 0; j < req.pcr_selections[i].pcrs_len; ++j) {
			if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
				goto cbor_parse_error;
			req.pcr_selections[i].pcrs[j] = (uint8_t)item.val.uint64;
		}
	}

	/* parse "event-log-path" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	req.event_log_path_len = item.val.string.len;
	if (req.event_log_path_len != 0) {
		uint8_t* event_log_path = (uint8_t*)malloc(req.event_log_path_len);
		if (event_log_path == NULL) {
			goto cbor_parse_error;
		} else {
			req.event_log_path = event_log_path;
			if (memcpy(req.event_log_path, item.val.string.ptr,
					req.event_log_path_len) == NULL) {
				goto cbor_parse_error;
			}
		}
	}

	/* expect end of CBOR data */
	if ((cborerr = QCBORDecode_Finish(&dc))) {
		charra_log_error("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
		goto cbor_parse_error;
	}

	/* set output */
	*attestation_request = req;

	return CHARRA_RC_SUCCESS;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
	charra_log_info("CBOR parser: skipping parsing.");

	return CHARRA_RC_MARSHALING_ERROR;
}

static CHARRA_RC charra_marshal_attestation_response_internal(
	const msg_attestation_response_dto* attestation_response, UsefulBuf buf_in,
	UsefulBufC* buf_out) {
	charra_log_trace("<ENTER> %s()", __func__);

	/* verify input */
	assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->tpm2_signature != NULL);
	assert(attestation_response->tpm2_public_key != NULL);
	if (attestation_response->event_log_len != 0) {
		assert(attestation_response->event_log != NULL);
	}

	QCBOREncodeContext ec = {0};

	QCBOREncode_Init(&ec, buf_in);

	/* root array */
	QCBOREncode_OpenArray(&ec);

	/* encode "attestation-data" */
	UsefulBufC attestation_data = {
		.ptr = attestation_response->attestation_data,
		.len = attestation_response->attestation_data_len};
	QCBOREncode_AddBytes(&ec, attestation_data);

	/* encode "tpm2-signature" */
	UsefulBufC tpm2_signature = {.ptr = attestation_response->tpm2_signature,
		.len = attestation_response->tpm2_signature_len};
	QCBOREncode_AddBytes(&ec, tpm2_signature);

	/* encode "tpm2-key-signature" */
	UsefulBufC tpm2_public_key = {.ptr = attestation_response->tpm2_public_key,
		.len = attestation_response->tpm2_public_key_len};
	QCBOREncode_AddBytes(&ec, tpm2_public_key);

	/* encode "event-log" */
	UsefulBufC event_log = {.ptr = attestation_response->event_log,
		.len = attestation_response->event_log_len};
	QCBOREncode_AddBytes(&ec, event_log);

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&ec);

	if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
		return CHARRA_RC_SUCCESS;
	} else {
		return CHARRA_RC_MARSHALING_ERROR;
	}
}

CHARRA_RC charra_marshal_attestation_response_size(
	const msg_attestation_response_dto* attestation_response,
	size_t* marshaled_data_len) {
	charra_log_trace("<ENTER> %s()", __func__);

	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* passing this buffer instructs QCBOR to return only the size and do no
	 * actual encoding */
	UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
	UsefulBufC buf_out = {0};

	if ((charra_r = charra_marshal_attestation_response_internal(
			 attestation_response, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
		*marshaled_data_len = buf_out.len;
	}

	return charra_r;
}

CHARRA_RC charra_marshal_attestation_response(
	const msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
	charra_log_trace("<ENTER> %s()", __func__);

	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* verify input */
	assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->tpm2_signature != NULL);
	assert(attestation_response->tpm2_public_key != NULL);
	if (attestation_response->event_log_len != 0) {
		assert(attestation_response->event_log != NULL);
	}

	/* compute size of marshaled data */
	UsefulBuf buf_in = {.len = 0, .ptr = NULL};
	if ((charra_r = charra_marshal_attestation_response_size(
			 attestation_response, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
		charra_log_error("Could not compute size of marshaled data.");
		return charra_r;
	}
	charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

	/* allocate buffer size */
	if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
		charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
		return CHARRA_RC_MARSHALING_ERROR;
	}
	charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

	/* encode */
	UsefulBufC buf_out = {.len = 0, .ptr = NULL};
	if ((charra_r = charra_marshal_attestation_response_internal(
			 attestation_response, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
		charra_log_error("Could not marshal data.");
		return charra_r;
	}

	/* set output parameters */
	*marshaled_data_len = buf_out.len;
	*marshaled_data = (uint8_t*)buf_out.ptr;

	return charra_r;
}

// TODO implement this function using  QCBORDecode_* functions
CHARRA_RC charra_unmarshal_attestation_response(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	msg_attestation_response_dto* attestation_response) {
	msg_attestation_response_dto res = {0};

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext dc = {0};
	QCBORItem item = {0};

	QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

	/* parse root array */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;

	/* parse "attestation-data" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.attestation_data_len = item.val.string.len;
	memcpy(
		&(res.attestation_data), item.val.string.ptr, res.attestation_data_len);

	/* parse "tpm2-signature" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.tpm2_signature_len = item.val.string.len;
	memcpy(&(res.tpm2_signature), item.val.string.ptr, res.tpm2_signature_len);

	/* parse "tpm2_public_key" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.tpm2_public_key_len = item.val.string.len;
	memcpy(
		&(res.tpm2_public_key), item.val.string.ptr, res.tpm2_public_key_len);

	/* parse "event-log" (bytes) */
	if ((cborerr = charra_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.event_log_len = item.val.string.len;
	uint8_t* event_log = (uint8_t*)malloc(res.event_log_len);
	if (event_log == NULL) {
		goto cbor_parse_error;
	} else {
		res.event_log = event_log;
		if (memcpy(res.event_log, item.val.string.ptr, res.event_log_len) ==
			NULL) {
			goto cbor_parse_error;
		}
	}

	if ((cborerr = QCBORDecode_Finish(&dc))) {
		charra_log_error("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
		goto cbor_parse_error;
	}

	/* set output */
	*attestation_response = res;

	return CHARRA_RC_SUCCESS;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
	charra_log_info("CBOR parser: skipping parsing.");

	/* clean up */
	charra_free_if_not_null(event_log);

	return CHARRA_RC_MARSHALING_ERROR;
}
