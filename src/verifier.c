/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file verifier.c
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

#include <arpa/inet.h>
#include <coap2/coap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "core/charra_dto.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/charra_util.h"
#include "util/coap_util.h"
#include "util/tpm2_util.h"

/* --- config ------------------------------------------------------------- */

/* logging */
#define LOG_NAME "verifier"
#define LOG_LEVEL_COAP LOG_INFO
// #define LOG_LEVEL_CBOR LOG_DEBUG
#define LOG_LEVEL_CHARRA CHARRA_LOG_INFO
// #define LOG_LEVEL_CHARRA CHARRA_LOG_DEBUG

/* config */
static const char DST_HOST[] = "127.0.0.1";
static const unsigned int DST_PORT = 5683; // default port
#define CBOR_ENCODER_BUFFER_LENGTH 20480   // 20 KiB should be sufficient
static const uint32_t TPM_SIG_KEY_NAME_LEN = 14;
static const uint8_t* TPM_SIG_KEY_NAME = (uint8_t*)"PK.RSA.default";

/* --- function forward declarations -------------------------------------- */

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto** attestation_request);

/* --- resource handler forward declarations ------------------------------ */

static void coap_attest_handler(struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent, coap_pdu_t* received,
	const coap_tid_t id);

/* --- static variables */

msg_attestation_request_dto* last_request = NULL;

/* --- main --------------------------------------------------------------- */

int main(void) {
	coap_context_t* ctx = NULL;
	coap_session_t* session = NULL;
	coap_address_t dst_addr;
	coap_pdu_t* pdu = NULL;
	int result = EXIT_FAILURE;

	/* set CHARRA log level*/
	charra_log_set_level(LOG_LEVEL_CHARRA);

	/* start up CoAP and set log level */
	coap_startup();
	coap_set_log_level(LOG_LEVEL_COAP);
	charra_log_info("[" LOG_NAME "] Starting up.");

	/* destination address and port */
	coap_address_init(&dst_addr);
	dst_addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, DST_HOST, &dst_addr.addr.sin.sin_addr);
	dst_addr.addr.sin.sin_port = htons(DST_PORT);

	/* create CoAP context and client session */
	charra_log_info("[" LOG_NAME "] Initializing CoAP endpoint.");
	ctx = coap_new_context(NULL);
	if (!ctx || !(session = coap_new_client_session(
					  ctx, NULL, &dst_addr, COAP_PROTO_UDP))) {
		charra_log_error(
			"[" LOG_NAME "] Cannot create client session (initializing "
			"CoAP context failed).");
		goto finish;
	}

	/* register CoAP resource handlers */
	charra_log_info("[" LOG_NAME "] Registering CoAP resource handlers.");
	coap_register_response_handler(ctx, coap_attest_handler);

	/* construct CoAP message */
	charra_log_info("[" LOG_NAME "] Creating new attestation request.");
	pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_FETCH,
		coap_new_message_id(session), coap_session_max_pdu_size(session));
	if (!pdu) {
		charra_log_error("[" LOG_NAME "] Cannot create CoAP message PDU.");
		goto finish;
	}

	/* add a Uri-Path option */
	coap_add_option(pdu, COAP_OPTION_URI_PATH, 6, (const uint8_t*)"attest");

	/* create attestation request */
	msg_attestation_request_dto* req = NULL;
	if (create_attestation_request(&req) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
		goto finish;
	}

	/* store request data */
	destroy_msg_attestation_request_dto(&last_request);
	last_request = req;

	/* marshal attestation request */
	charra_log_info("[" LOG_NAME "] Marshaling attestation request data.");
	uint32_t req_buf_len = 0;
	uint8_t* req_buf = NULL;
	CHARRA_RC charra_err = CHARRA_RC_SUCCESS;
	int coap_err = 0;
	if ((charra_err = marshal_attestation_request(req, &req_buf_len, &req_buf)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error(
			"[" LOG_NAME "] Marshaling attestation request data failed.");
		goto finish;
	}

	/* ATTENTION: libcoap returns an int != 0 on success! */
	charra_log_info(
		"[" LOG_NAME "] Adding attestation request data to CoAP PDU.");
	if ((coap_err = coap_add_data(pdu, req_buf_len, req_buf)) == 0) {
		charra_log_error(
			"[" LOG_NAME "] Cannot add attestation request data to CoAP PDU.");
		goto finish;
	}

	/*send CoAP PDU */
	charra_log_info("[" LOG_NAME "] Sending CoAP message.");
	coap_send(session, pdu);

	coap_run_once(ctx, 0);

	result = EXIT_SUCCESS;

finish:
	/* free memory */
	destroy_msg_attestation_request_dto(&req);
	// free(req_buf);

	/* free CoAP memory */
	coap_session_release(session);
	coap_free_context(ctx);
	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto** attestation_request) {
	CHARRA_RC err = CHARRA_RC_ERROR;

	msg_attestation_request_dto* req = create_msg_attestation_request_dto();

	/* generate nonce */
	uint32_t nonce_len = 20;
	uint8_t* nonce = NULL;
	if ((err = charra_get_random_bytes(nonce_len, &nonce) !=
			   CHARRA_RC_SUCCESS)) {
		charra_log_error("Could not get random bytes for nonce.");
		return err;
	}

	/* build attestation request */
	req->hello = false;
	req->sig_key_id_len = TPM_SIG_KEY_NAME_LEN;
	req->sig_key_id = (uint8_t*)TPM_SIG_KEY_NAME;
	req->nonce_len = nonce_len, req->nonce = nonce, req->pcr_selections_len = 3;
	req->pcr_selections =
		create_pcr_selection_dto_array(req->pcr_selections_len);

	req->pcr_selections[0].tcg_hash_alg_id = (uint16_t)TPM2_ALG_SHA1;
	req->pcr_selections[0].pcrs_len = 9;
	req->pcr_selections[0].pcrs =
		calloc(req->pcr_selections[0].pcrs_len, sizeof(uint8_t));
	req->pcr_selections[0].pcrs[0] = 0;
	req->pcr_selections[0].pcrs[1] = 1;
	req->pcr_selections[0].pcrs[2] = 2;
	req->pcr_selections[0].pcrs[3] = 3;
	req->pcr_selections[0].pcrs[4] = 4;
	req->pcr_selections[0].pcrs[5] = 5;
	req->pcr_selections[0].pcrs[6] = 6;
	req->pcr_selections[0].pcrs[7] = 7;
	req->pcr_selections[0].pcrs[8] = 10;

	req->pcr_selections[1].tcg_hash_alg_id = (uint16_t)TPM2_ALG_SHA256;
	req->pcr_selections[1].pcrs_len = 9;
	req->pcr_selections[1].pcrs =
		calloc(req->pcr_selections[1].pcrs_len, sizeof(uint8_t));
	req->pcr_selections[1].pcrs[0] = 0;
	req->pcr_selections[1].pcrs[1] = 1;
	req->pcr_selections[1].pcrs[2] = 2;
	req->pcr_selections[1].pcrs[3] = 3;
	req->pcr_selections[1].pcrs[4] = 4;
	req->pcr_selections[1].pcrs[5] = 5;
	req->pcr_selections[1].pcrs[6] = 6;
	req->pcr_selections[1].pcrs[7] = 7;
	req->pcr_selections[1].pcrs[8] = 10;

	req->pcr_selections[2].tcg_hash_alg_id = (uint16_t)TPM2_ALG_SHA384;
	req->pcr_selections[2].pcrs_len = 9;
	req->pcr_selections[2].pcrs =
		calloc(req->pcr_selections[2].pcrs_len, sizeof(uint8_t));
	req->pcr_selections[2].pcrs[0] = 0;
	req->pcr_selections[2].pcrs[1] = 1;
	req->pcr_selections[2].pcrs[2] = 2;
	req->pcr_selections[2].pcrs[3] = 3;
	req->pcr_selections[2].pcrs[4] = 4;
	req->pcr_selections[2].pcrs[5] = 5;
	req->pcr_selections[2].pcrs[6] = 6;
	req->pcr_selections[2].pcrs[7] = 7;
	req->pcr_selections[2].pcrs[8] = 10;

	/* set output param(s) */
	*attestation_request = req;

	/* return result */
	return CHARRA_RC_SUCCESS;
}

/* --- resource handler definitions --------------------------------------- */

static void coap_attest_handler(struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent, coap_pdu_t* in,
	const coap_tid_t id) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	int coap_r = 0;
	CHARRA_RC charra_err = CHARRA_RC_SUCCESS;
	TSS2_RC tss_r = 0;

	ESYS_TR sig_key_handle = ESYS_TR_NONE;
	TPMT_TK_VERIFIED* validation = NULL;

	charra_log_info(
		"[" LOG_NAME "] Resource '%s': Received message.", "attest");
	coap_show_pdu(LOG_DEBUG, in);

	/* --- receive incoming data --- */

	/* get data */
	size_t data_len = 0;
	uint8_t* data = NULL;
	if ((coap_r = coap_get_data(in, &data_len, &data)) == 0) {
		charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
		goto error;
	} else {
		charra_log_info(
			"[" LOG_NAME "] Received data of length %zu.", data_len);
	}

	/* unmarshal data */
	charra_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	msg_attestation_response_dto res;
	if ((charra_err = unmarshal_attestation_response(data_len, data, &res)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* verify data */
	if (res.attestation_data_len > sizeof(TPM2B_ATTEST)) {
		charra_log_error(
			"[" LOG_NAME
			"] Length of attestation data exceeds maximum allowed size.");
		goto error;
	}
	if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE)) {
		charra_log_error(
			"[" LOG_NAME "] Length of signature exceeds maximum allowed size.");
		goto error;
	}

	/* --- verify TPM quote --- */

	charra_log_info("[" LOG_NAME "] Starting verification.");

	/* initialize ESAPI */
	ESYS_CONTEXT* esys_ctx = NULL;
	if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Esys_Initialize.");
		goto error;
	}

	/* load TPM key */
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	if ((charra_r = charra_load_tpm2_key(esys_ctx, TPM_SIG_KEY_NAME_LEN,
			 TPM_SIG_KEY_NAME, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not load TPM key.");
		goto error;
	} else {
		charra_log_info("[" LOG_NAME "] Loading of TPM key successful.");
	}

	/* prepare verification */
	charra_log_info("[" LOG_NAME "] Preparing TPM quote verification.");
	TPM2B_ATTEST attest;
	attest.size = res.attestation_data_len;
	memcpy(
		attest.attestationData, res.attestation_data, res.attestation_data_len);
	TPMT_SIGNATURE signature;
	memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

	/* verify attestation signature */
	charra_log_info("[" LOG_NAME "] Verifying TPM Quote signature.");
	bool attestation_result_signature = false;
	tss_r = tpm2_verify_quote_with_tpm(
		esys_ctx, sig_key_handle, &attest, &signature, &validation);
	if (tss_r == TSS2_RC_SUCCESS) {
		charra_log_info("[" LOG_NAME "] TPM Quote signature valid!");
		attestation_result_signature = true;
	}

	/* verify nonce [TO BE IMPLEMENTED] */
	bool attestation_result_nonce = true;

	/* verify PCRs [TO BE IMPLEMENTED] */
	bool attestation_result_pcrs = true;

	/* --- output result --- */

	bool attestation_result = attestation_result_signature &&
							  attestation_result_nonce &&
							  attestation_result_pcrs;

	/* print attestation result */
	if (attestation_result) {
		charra_log_info("[" LOG_NAME "] +----------------------------+");
		charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
		charra_log_info("[" LOG_NAME "] +----------------------------+");
	} else {
		charra_log_info("[" LOG_NAME "] +----------------------------+");
		charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
		charra_log_info("[" LOG_NAME "] +----------------------------+");
	}

error:
	/* flush handles */
	if (sig_key_handle != ESYS_TR_NONE) {
		if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
		}
	}

	/* free ESAPI objects */
	if (validation != NULL) {
		Esys_Free(validation);
	}

	/* finalize ESAPI */
	Esys_Finalize(&esys_ctx);
}
