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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <qcbor.h>
#include <UsefulBuf.h>
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

	UsefulBuf_MAKE_STACK_UB(buf, CBOR_ENCODER_BUFFER_LENGTH);
	QCBOREncodeContext EC;

	QCBOREncode_Init(&EC, buf);

	/* root array */
	QCBOREncode_OpenArray(&EC);

	/* encode "hello" */
	QCBOREncode_AddBool(&EC, attestation_request->hello);

	/* encode "key_id" */
	UsefulBufC KeyID = {attestation_request->sig_key_id, attestation_request->sig_key_id_len};
	QCBOREncode_AddBytes(&EC, KeyID);

	/* encode "nonce" */
	UsefulBufC Nonce = {attestation_request->nonce, attestation_request->nonce_len};
	QCBOREncode_AddBytes(&EC, Nonce);

	{
		QCBOREncode_OpenArray(&EC);

		for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
			{
				QCBOREncode_OpenArray(&EC);

				QCBOREncode_AddInt64(&EC, attestation_request->pcr_selections[i].tcg_hash_alg_id);

				{
					QCBOREncode_OpenArray(&EC);

					for (uint32_t j = 0;
						 j < attestation_request->pcr_selections[i].pcrs_len;
						 ++j) {

						 QCBOREncode_AddUInt64(&EC, attestation_request->pcr_selections[i].pcrs[j]);
					}

					/* close array: pcrs_array_encoder */
					QCBOREncode_CloseArray(&EC);
				}

				/* close array: pcr_selection_array_encoder */
				QCBOREncode_CloseArray(&EC);
			}
		}

		/* close array: pcr_selections_array_encoder */
		QCBOREncode_CloseArray(&EC);
	}

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&EC);

	/* set out params */
	UsefulBufC Encoded;

	if(QCBOREncode_Finish(&EC, &Encoded))
		return CHARRA_RC_MARSHALING_ERROR;

	*marshaled_data_len = Encoded.len;
	*marshaled_data = (uint8_t*)Encoded.ptr;

	return CHARRA_RC_SUCCESS;
}

CHARRA_RC unmarshal_attestation_request(uint32_t marshaled_data_len,
	uint8_t* marshaled_data, msg_attestation_request_dto* attestation_request) {

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext DC;
	QCBORItem item;

	QCBORDecode_Init(&DC, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);
	attestation_request->pcr_selections = NULL;

	if(charra_cbor_getnext(&DC, &item, QCBOR_TYPE_ARRAY))
		goto cbor_parse_error;

	/* parse "hello" (bool) */
	if((cborerr = charra_cbor_getnext(&DC, &item, CHARRA_CBOR_TYPE_BOOLEAN)))
		goto cbor_parse_error;
	attestation_request->hello = charra_cbor_getbool_val(&item);

	/* parse "key-id" (bytes) */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	attestation_request->sig_key_id_len = item.val.string.len;
	attestation_request->sig_key_id = (uint8_t*)item.val.string.ptr;

	/* parse "nonce" (bytes) */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	attestation_request->nonce_len = item.val.string.len;
	attestation_request->nonce = (uint8_t*)item.val.string.ptr;

	/* parse array "pcr-selections" */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;

	/* initialize array and array length */
	attestation_request->pcr_selections_len = item.val.uCount;
	attestation_request->pcr_selections = (pcr_selection_dto*)calloc(
		item.val.uCount, sizeof(pcr_selection_dto));

	/* go through all elements */
	for (uint32_t i = 0; i < attestation_request->pcr_selections_len; i++) {
		/* parse array "pcr-selection" */
		if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_ARRAY)))
			goto cbor_parse_error;

		/* parse "tcg-hash-alg-id" (UINT16) */
		if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_INT64)))
			goto cbor_parse_error;
		attestation_request->pcr_selections[i].tcg_hash_alg_id = item.val.uint64;

		/* parse array "pcrs" */
		if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_ARRAY)))
			goto cbor_parse_error;

		/* initialize array and array length */
		attestation_request->pcr_selections[i].pcrs_len = item.val.uCount;
		attestation_request->pcr_selections[i].pcrs = (uint8_t*)calloc(
			item.val.uCount, sizeof(uint8_t));


		/* go through all elements */
		for (uint32_t j = 0; j < attestation_request->pcr_selections[i].pcrs_len; ++j) {
			if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_INT64)))
				goto cbor_parse_error;
			attestation_request->pcr_selections[i].pcrs[j] = item.val.uint64;
		}
	}

	/* expect end of CBOR data */
	if((cborerr = QCBORDecode_Finish(&DC))) {
		charra_log_error("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
		goto cbor_parse_error;
	}

	return CHARRA_RC_SUCCESS;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
	charra_log_info("CBOR parser: skipping parsing.");
	// TODO: Free attestation_request->pcr_selections
	/*if(attestation_request->pcr_selections != NULL) {
		for(uint32_t j = 0; j < attestation_request->pcr_selections_len; j++) {
			if(attestation_request->pcr_selections[j] != NULL) {
				free(attestation_request->pcr_selections[j]);
			}
		}
		free(attestation_request->pcr_selections);
	}*/
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

	UsefulBuf_MAKE_STACK_UB(buf, CBOR_ENCODER_BUFFER_LENGTH);
	QCBOREncodeContext EC;

	QCBOREncode_Init(&EC, buf);

	/* root array */
	QCBOREncode_OpenArray(&EC);

	/* encode "attestation-data" */
	UsefulBufC AttestationData = {attestation_response->attestation_data, attestation_response->attestation_data_len};
	QCBOREncode_AddBytes(&EC, AttestationData);

	/* encode "tpm2-signature" */
	UsefulBufC Tpm2Signature = {attestation_response->tpm2_signature, attestation_response->tpm2_signature_len};
	QCBOREncode_AddBytes(&EC, Tpm2Signature);

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&EC);

	/* set out params */
	UsefulBufC Encoded;

	if(QCBOREncode_Finish(&EC, &Encoded))
		return CHARRA_RC_MARSHALING_ERROR;

	*marshaled_data_len = Encoded.len;
	*marshaled_data = (uint8_t*)Encoded.ptr;

	return CHARRA_RC_SUCCESS;
}

CHARRA_RC unmarshal_attestation_response(uint32_t marshaled_data_len,
	uint8_t* marshaled_data,
	msg_attestation_response_dto* attestation_response) {

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext DC;
	QCBORItem item;

	QCBORDecode_Init(&DC, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

	/* parse root array */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;


	/* parse "attestation-data" (bytes) */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	attestation_response->attestation_data_len = item.val.string.len;
	attestation_response->attestation_data = (uint8_t*)item.val.string.ptr;

	/* parse "tpm2-signature" (bytes) */
	if((cborerr = charra_cbor_getnext(&DC, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	attestation_response->tpm2_signature_len = item.val.string.len;
	attestation_response->tpm2_signature = (uint8_t*)item.val.string.ptr;

	if((cborerr = QCBORDecode_Finish(&DC))) {
		charra_log_error("CBOR parser: expected end of input, but could not "
				 "find it. Continuing.");
		goto cbor_parse_error;
	}

	return CHARRA_RC_SUCCESS;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
	charra_log_info("CBOR parser: skipping parsing.");
	return CHARRA_RC_MARSHALING_ERROR;

}
