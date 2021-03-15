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
#include "../core/charra_dto.h"
#include "../util/cbor_util.h"
#include "../util/tpm2_util.h"

static const uint32_t CBOR_ENCODER_BUFFER_LENGTH = 20480;

CHARRA_RC marshal_attestation_request(
	const msg_attestation_request_dto* attestation_request,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
	charra_log_trace("<ENTER> %s()", __func__);

	/* verify input */
	assert(attestation_request != NULL);
	assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
	assert(attestation_request->pcr_selections != NULL);
	assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
	assert(attestation_request->pcr_selections->pcrs != NULL);
	assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
	assert(attestation_request->nonce != NULL);

	UsefulBuf buf = {.len = CBOR_ENCODER_BUFFER_LENGTH,
		.ptr = malloc(CBOR_ENCODER_BUFFER_LENGTH)};
	QCBOREncodeContext ec;

	QCBOREncode_Init(&ec, buf);

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

	{ /* encode "pcr-selections" */
		QCBOREncode_OpenArray(&ec);

		for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
			{
				QCBOREncode_OpenArray(&ec);

				QCBOREncode_AddInt64(&ec,
					attestation_request->pcr_selections[i].tcg_hash_alg_id);

				{
					QCBOREncode_OpenArray(&ec);

					for (uint32_t j = 0;
						 j < attestation_request->pcr_selections[i].pcrs_len;
						 ++j) {

						QCBOREncode_AddUInt64(&ec,
							attestation_request->pcr_selections[i].pcrs[j]);
					}

					/* close array: pcrs_array_encoder */
					QCBOREncode_CloseArray(&ec);
				}

				/* close array: pcr_selection_array_encoder */
				QCBOREncode_CloseArray(&ec);
			}
		}

		/* close array: pcr_selections_array_encoder */
		QCBOREncode_CloseArray(&ec);
	}

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&ec);

	/* set out params */
	UsefulBufC encoded = {0};

	if (QCBOREncode_Finish(&ec, &encoded)) {
		return CHARRA_RC_MARSHALING_ERROR;
	}

	*marshaled_data_len = encoded.len;
	*marshaled_data = (uint8_t*)encoded.ptr;

	return CHARRA_RC_SUCCESS;
}

CHARRA_RC unmarshal_attestation_request(const uint32_t marshaled_data_len,
	const uint8_t* marshaled_data,
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

CHARRA_RC marshal_attestation_response(
	const msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {

	charra_log_trace("<ENTER> %s()", __func__);

	/* verify input */
	assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->tpm2_signature != NULL);
	assert(attestation_response->tpm2_public_key != NULL);
	assert(attestation_response->event_log != NULL);

	UsefulBuf buf = {.len = CBOR_ENCODER_BUFFER_LENGTH,
		.ptr = malloc(CBOR_ENCODER_BUFFER_LENGTH)};
	QCBOREncodeContext ec = {0};

	QCBOREncode_Init(&ec, buf);

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

	/* set out params */
	UsefulBufC encoded = {0};

	if (QCBOREncode_Finish(&ec, &encoded)) {
		return CHARRA_RC_MARSHALING_ERROR;
	}

	*marshaled_data_len = encoded.len;
	*marshaled_data = (uint8_t*)encoded.ptr;

	return CHARRA_RC_SUCCESS;
}

CHARRA_RC unmarshal_attestation_response(const uint32_t marshaled_data_len,
	const uint8_t* marshaled_data,
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

	/* free */
	if (event_log != NULL) {
		free(event_log);
	}

	return CHARRA_RC_MARSHALING_ERROR;
}
