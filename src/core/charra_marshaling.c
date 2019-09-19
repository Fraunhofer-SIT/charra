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
#include <tinycbor/cbor.h>
#include <tss2/tss2_tpm2_types.h>

#include "../common/charra_log.h"
#include "../core/charra_dto.h"
#include "../util/cbor_util.h"
#include "../util/tpm2_util.h"

static const uint32_t CBOR_ENCODER_BUFFER_LENGTH = 20480;

CborError marshal_attestation_request(
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

	uint8_t buf[CBOR_ENCODER_BUFFER_LENGTH];
	CborError err = CborNoError;
	CborEncoder encoder;

	cbor_encoder_init(&encoder, (uint8_t*)buf, sizeof(buf), 0);
	charra_log_debug("CBOR buf len: %i",
		cbor_encoder_get_buffer_size(&encoder, (const uint8_t*)buf));

	/* root array */
	CborEncoder root_array_encoder;
	if ((err = cbor_encoder_create_array(&encoder, &root_array_encoder, 4))) {
		charra_log_error(
			"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
		goto cbor_encode_error;
	}

	/* encode "hello" */
	if ((err = cbor_encode_boolean(
			 &root_array_encoder, attestation_request->hello))) {
		charra_log_error(
			"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
		goto cbor_encode_error;
	}

	/* encode "key_id" */
	if ((err = cbor_encode_byte_string(&root_array_encoder,
			 attestation_request->sig_key_id,
			 attestation_request->sig_key_id_len))) {
		goto cbor_encode_error;
	}

	/* encode "nonce" */
	if ((err = cbor_encode_byte_string(&root_array_encoder,
			 attestation_request->nonce, attestation_request->nonce_len))) {
		goto cbor_encode_error;
	}

	{
		/* encode PCR selections array */
		CborEncoder pcr_selections_array_encoder;
		if ((err = cbor_encoder_create_array(&root_array_encoder,
				 &pcr_selections_array_encoder,
				 attestation_request->pcr_selections_len))) {
			charra_log_error(
				"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
			goto cbor_encode_error;
		}

		for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
			{
				/* encode PCR selection array */
				CborEncoder pcr_selection_array_encoder;
				if ((err = cbor_encoder_create_array(
						 &pcr_selections_array_encoder,
						 &pcr_selection_array_encoder, 2))) {
					charra_log_error("CBOR encoder: %s (line %d)",
						cbor_error_string(err), __LINE__);
					goto cbor_encode_error;
				}

				/* encode "tcg-hash-alg-id" */
				if ((err = cbor_encode_int(&pcr_selection_array_encoder,
						 attestation_request->pcr_selections[i]
							 .tcg_hash_alg_id))) {
					charra_log_error("CBOR encoder: %s (line %d)",
						cbor_error_string(err), __LINE__);
					goto cbor_encode_error;
				}

				{
					/* encode PCRs array */
					CborEncoder pcrs_array_encoder;
					if ((err = cbor_encoder_create_array(
							 &pcr_selection_array_encoder, &pcrs_array_encoder,
							 attestation_request->pcr_selections[i]
								 .pcrs_len))) {
						charra_log_error("CBOR encoder: %s (line %d)",
							cbor_error_string(err), __LINE__);
						goto cbor_encode_error;
					}

					for (uint32_t j = 0;
						 j < attestation_request->pcr_selections[i].pcrs_len;
						 ++j) {
						if ((err = cbor_encode_int(&pcrs_array_encoder,
								 attestation_request->pcr_selections[i]
									 .pcrs[j]))) {
							charra_log_error("CBOR encoder: %s (line %d)",
								cbor_error_string(err), __LINE__);
							goto cbor_encode_error;
						}
					}

					/* close array: pcrs_array_encoder */
					if ((err = cbor_encoder_close_container(
							 &pcr_selection_array_encoder,
							 &pcrs_array_encoder))) {
						charra_log_error("CBOR encoder: %s (line %d)",
							cbor_error_string(err), __LINE__);
						goto cbor_encode_error;
					}
				}

				/* close array: pcr_selection_array_encoder */
				if ((err = cbor_encoder_close_container(
						 &pcr_selections_array_encoder,
						 &pcr_selection_array_encoder))) {
					charra_log_error("CBOR encoder: %s (line %d)",
						cbor_error_string(err), __LINE__);
					goto cbor_encode_error;
				}
			}
		}

		/* close array: pcr_selections_array_encoder */
		if ((err = cbor_encoder_close_container(
				 &root_array_encoder, &pcr_selections_array_encoder))) {
			charra_log_error(
				"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
			goto cbor_encode_error;
		}
	}

	/* close array: root_array_encoder */
	if ((err = cbor_encoder_close_container(&encoder, &root_array_encoder))) {
		charra_log_error(
			"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
		goto cbor_encode_error;
	}

	/* set out params */
	*marshaled_data_len =
		(uint32_t)cbor_encoder_get_buffer_size(&encoder, (const uint8_t*)buf);
	*marshaled_data = (uint8_t*)buf;

	return CborNoError;

cbor_encode_error:
	charra_log_error("CBOR encoder: %s", cbor_error_string(err));
	charra_log_error("CBOR encoder: Skipping encoding.");
	return err;
}

CborError unmarshal_attestation_request(uint32_t marshaled_data_len,
	uint8_t* marshaled_data, msg_attestation_request_dto* attestation_request) {
	CborParser parser;
	CborValue it;
	CborError err = CborNoError;

	/* init CBOR parser */
	if ((err = cbor_parser_init(
			 marshaled_data, marshaled_data_len, 0, &parser, &it))) {
		goto cbor_parse_error;
	} else {
		charra_log_debug("CBOR parser; initialized successfully.");
	}

	/* parse root array */
	CborValue root_array;
	if ((err = charra_cbor_parse_enter_array(&it, &root_array))) {
		goto cbor_parse_error;
	} else {
		/* parse "hello" (bool) */
		if ((err = charra_cbor_parse_boolean(
				 &root_array, &(attestation_request->hello)))) {
			goto cbor_parse_error;
		}
		if ((err = cbor_value_advance_fixed(&root_array))) {
			goto cbor_parse_error;
		}

		/* parse "key-id" (bytes) */
		if ((err = charra_cbor_parse_byte_string(&root_array,
				 &(attestation_request->sig_key_id_len),
				 &(attestation_request->sig_key_id)))) {
			goto cbor_parse_error;
		}

		/* parse "nonce" (bytes) */
		if ((err = charra_cbor_parse_byte_string(&root_array,
				 &(attestation_request->nonce_len),
				 &(attestation_request->nonce)))) {
			goto cbor_parse_error;
		}

		/* parse array "pcr-selections" */
		CborValue pcr_selections_array;
		if ((err = charra_cbor_parse_enter_array(
				 &root_array, &pcr_selections_array))) {
			goto cbor_parse_error;
		} else {
			/* initialize array and array length */
			attestation_request->pcr_selections_len =
				pcr_selections_array.remaining;
			attestation_request->pcr_selections = (pcr_selection_dto*)calloc(
				attestation_request->pcr_selections_len,
				sizeof(pcr_selection_dto));

			/* go through all elements */
			for (uint32_t i = 0; i < attestation_request->pcr_selections_len;
				 ++i) {

				/* parse array "pcr-selection" */
				CborValue pcr_selection_array;
				if ((err = charra_cbor_parse_enter_array(
						 &pcr_selections_array, &pcr_selection_array))) {
					goto cbor_parse_error;
				} else {
					/* parse "tcg-hash-alg-id" (UINT16) */
					if ((err = charra_cbor_parse_uint16(&pcr_selection_array,
							 &(attestation_request->pcr_selections[i]
									 .tcg_hash_alg_id)))) {
						goto cbor_parse_error;
					}
					if ((err = cbor_value_advance_fixed(
							 &pcr_selection_array))) {
						goto cbor_parse_error;
					}

					/* parse array "pcrs" */
					CborValue pcrs_array;
					if ((err = charra_cbor_parse_enter_array(
							 &pcr_selection_array, &pcrs_array))) {
						goto cbor_parse_error;
					} else {
						/* initialize array and array length */
						attestation_request->pcr_selections[i].pcrs_len =
							pcrs_array.remaining;
						attestation_request->pcr_selections[i].pcrs =
							(uint8_t*)calloc(
								attestation_request->pcr_selections[i].pcrs_len,
								sizeof(uint8_t));
						/* go through all elements */
						for (uint32_t j = 0;
							 j <
							 attestation_request->pcr_selections[i].pcrs_len;
							 ++j) {

							/* parse "pcr" (UINT8) */
							if ((err = charra_cbor_parse_uint8(&pcrs_array,
									 &(attestation_request->pcr_selections[i]
											 .pcrs[j])))) {
								goto cbor_parse_error;
							}
							if ((err = cbor_value_advance_fixed(&pcrs_array))) {
								goto cbor_parse_error;
							}
						}
					}

					/* leave array "pcrs" */
					if ((err = cbor_value_leave_container(
							 &pcr_selection_array, &pcrs_array))) {
						goto cbor_parse_error;
					} else {
						charra_log_debug("CBOR parser: leaving array.");
					}
				}

				/* leave array "pcr-selection" */
				if ((err = cbor_value_leave_container(
						 &pcr_selections_array, &pcr_selection_array))) {
					goto cbor_parse_error;
				} else {
					charra_log_debug("CBOR parser: leaving array.");
				}
			}
		}

		/* leave array "pcr-selections" */
		if ((err = cbor_value_leave_container(
				 &root_array, &pcr_selections_array))) {
			goto cbor_parse_error;
		} else {
			charra_log_debug("CBOR parser: leaving array.");
		}
	}

	/* leave root array */
	if ((err = cbor_value_leave_container(&it, &root_array))) {
		goto cbor_parse_error;
	} else {
		charra_log_debug("CBOR parser: leaving array.");
	}

	/* expect end of CBOR data */
	if (!cbor_value_at_end(&it)) {
		charra_log_error("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
	}

	goto cbor_parse_success;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", cbor_error_string(err));
	charra_log_info("CBOR parser: skipping parsing.");
	goto end;

cbor_parse_success:
	charra_log_info("CBOR parser: parsing successful.");

	goto end;

end:
	return CborNoError;
}

CborError marshal_attestation_response(
	const msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
	charra_log_trace("<ENTER> %s()", __func__);

	/* verify input */
	assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->tpm2_signature != NULL);

	uint8_t buf[CBOR_ENCODER_BUFFER_LENGTH];
	CborError err = CborNoError;
	CborEncoder encoder;

	cbor_encoder_init(&encoder, (uint8_t*)buf, sizeof(buf), 0);
	charra_log_debug("CBOR buf len: %i",
		cbor_encoder_get_buffer_size(&encoder, (const uint8_t*)buf));

	/* root array */
	CborEncoder root_array_encoder;
	if ((err = cbor_encoder_create_array(&encoder, &root_array_encoder, 2))) {
		charra_log_error(
			"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
		goto cbor_encode_error;
	}

	/* encode "attestation-data" */
	if ((err = cbor_encode_byte_string(&root_array_encoder,
			 attestation_response->attestation_data,
			 attestation_response->attestation_data_len))) {
		goto cbor_encode_error;
	}

	/* encode "tpm2-signature" */
	if ((err = cbor_encode_byte_string(&root_array_encoder,
			 attestation_response->tpm2_signature,
			 attestation_response->tpm2_signature_len))) {
		goto cbor_encode_error;
	}

	/* close array: root_array_encoder */
	if ((err = cbor_encoder_close_container(&encoder, &root_array_encoder))) {
		charra_log_error(
			"CBOR encoder: %s (line %d)", cbor_error_string(err), __LINE__);
		goto cbor_encode_error;
	}

	/* set out params */
	*marshaled_data_len =
		(uint32_t)cbor_encoder_get_buffer_size(&encoder, (const uint8_t*)buf);
	*marshaled_data = (uint8_t*)buf;

	return CborNoError;

cbor_encode_error:
	charra_log_error("CBOR encoder: %s", cbor_error_string(err));
	charra_log_error("CBOR encoder: Skipping encoding.");
	return err;
}

CborError unmarshal_attestation_response(uint32_t marshaled_data_len,
	uint8_t* marshaled_data,
	msg_attestation_response_dto* attestation_response) {
	CborParser parser;
	CborValue it;
	CborError err = CborNoError;

	/* init CBOR parser */
	if ((err = cbor_parser_init(
			 marshaled_data, marshaled_data_len, 0, &parser, &it))) {
		goto cbor_parse_error;
	} else {
		charra_log_debug("CBOR parser; initialized successfully.");
	}

	/* parse root array */
	CborValue root_array;
	if ((err = charra_cbor_parse_enter_array(&it, &root_array))) {
		goto cbor_parse_error;
	} else {
		/* parse "attestation-data" (bytes) */
		if ((err = charra_cbor_parse_byte_string(&root_array,
				 (size_t*)&(attestation_response->attestation_data_len),
				 &(attestation_response->attestation_data)))) {
			goto cbor_parse_error;
		}

		/* parse "tpm2-signature" (bytes) */
		if ((err = charra_cbor_parse_byte_string(&root_array,
				 (size_t*)&(attestation_response->tpm2_signature_len),
				 &(attestation_response->tpm2_signature)))) {
			goto cbor_parse_error;
		}
	}

	/* leave root array */
	if ((err = cbor_value_leave_container(&it, &root_array))) {
		goto cbor_parse_error;
	} else {
		charra_log_debug("CBOR parser: leaving array.");
	}

	/* expect end of CBOR data */
	if (!cbor_value_at_end(&it)) {
		charra_log_error("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
	}

	goto cbor_parse_success;

cbor_parse_error:
	charra_log_error("CBOR parser: %s", cbor_error_string(err));
	charra_log_info("CBOR parser: skipping parsing.");
	goto end;

cbor_parse_success:
	charra_log_info("CBOR parser: parsing successful.");

	goto end;

end:
	return CborNoError;
}
