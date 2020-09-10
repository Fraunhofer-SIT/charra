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
#include "core/charra_rim_mgr.h"
#include "util/charra_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define UNUSED __attribute__((unused))

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
#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"
static const uint8_t TPM_PCR_SELECTION[TPM2_MAX_PCRS] = {
	0, 1, 2, 3, 4, 5, 6, 7, 10};
static const uint32_t TPM_PCR_SELECTION_LEN = 9;

/* --- function forward declarations -------------------------------------- */

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto* attestation_request);

/* --- resource handler forward declarations ------------------------------ */

static void coap_attest_handler(struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent, coap_pdu_t* received,
	const coap_tid_t id);

/* --- static variables */

msg_attestation_request_dto last_request = {0};
msg_attestation_response_dto last_response = {0};

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
	msg_attestation_request_dto req = {0};
	if (create_attestation_request(&req) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
		goto finish;
	}

	/* store request data */
	last_request = req;

	/* marshal attestation request */
	charra_log_info(
		"[" LOG_NAME "] Marshaling attestation request data to CBOR.");
	uint32_t req_buf_len = 0;
	uint8_t* req_buf = NULL;
	CHARRA_RC charra_err = CHARRA_RC_SUCCESS;
	int coap_err = 0;
	if ((charra_err = marshal_attestation_request(
			 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
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

	result = EXIT_SUCCESS;

	if (coap_io_process(ctx, 20000) < 0) {
		result = EXIT_FAILURE;
	}

finish:
	/* free CoAP memory */
	coap_session_release(session);
	coap_free_context(ctx);
	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto* attestation_request) {
	CHARRA_RC err = CHARRA_RC_ERROR;

	/* generate nonce */
	uint32_t nonce_len = 20;
	uint8_t nonce[nonce_len];
	if ((err = charra_get_random_bytes_from_tpm(nonce_len, nonce) !=
			   CHARRA_RC_SUCCESS)) {
		charra_log_error("Could not get random bytes for nonce.");
		return err;
	}
	charra_log_info("Generated nonce of length %d:", nonce_len);
	charra_print_hex(
		nonce_len, nonce, "                                   0x", "\n", false);

	/* build attestation request */
	msg_attestation_request_dto req = {.hello = false,
		.sig_key_id_len = TPM_SIG_KEY_ID_LEN,
		.sig_key_id = {0}, // must be memcpy'd, see below
		.nonce_len = nonce_len,
		.nonce = {0}, // must be memcpy'd, see below
		.pcr_selections_len = 1,
		.pcr_selections = {{
			.tcg_hash_alg_id = TPM2_ALG_SHA256,
			.pcrs_len = 9,
			.pcrs = {0} // must be memcpy'd, see below
		}}};
	memcpy(req.sig_key_id, TPM_SIG_KEY_ID, TPM_SIG_KEY_ID_LEN);
	memcpy(req.nonce, nonce, nonce_len);
	memcpy(req.pcr_selections->pcrs, TPM_PCR_SELECTION, TPM_PCR_SELECTION_LEN);

	/* set output param(s) */
	*attestation_request = req;

	/* return result */
	return CHARRA_RC_SUCCESS;
}

/* --- resource handler definitions --------------------------------------- */

static void coap_attest_handler(struct coap_context_t* context UNUSED,
	coap_session_t* session UNUSED, coap_pdu_t* sent UNUSED, coap_pdu_t* in,
	const coap_tid_t id UNUSED) {
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
	msg_attestation_response_dto res = {0};
	if ((charra_err = unmarshal_attestation_response(data_len, data, &res)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* store last response */
	last_response = res;

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

	/* --- verify TPM Quote --- */
	charra_log_info("[" LOG_NAME "] Starting verification.");

	/* initialize ESAPI */
	ESYS_CONTEXT* esys_ctx = NULL;
	if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Esys_Initialize.");
		goto error;
	}

	/* load TPM key */
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	if ((charra_r = charra_load_tpm2_key(esys_ctx, TPM_SIG_KEY_ID_LEN,
			 (uint8_t*)TPM_SIG_KEY_ID, &sig_key_handle)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not load TPM key.");
		goto error;
	} else {
		charra_log_info("[" LOG_NAME "] Loading of TPM key successful.");
	}

	/* prepare verification */
	charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
	TPM2B_ATTEST attest = {0};
	attest.size = res.attestation_data_len;
	memcpy(
		attest.attestationData, res.attestation_data, res.attestation_data_len);
	TPMT_SIGNATURE signature;
	memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

	/* --- verify attestation signature --- */
	bool attestation_result_signature = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying TPM Quote signature ...");

		if ((charra_r = charra_verify_tpm2_quote_signature_with_tpm(esys_ctx,
				 sig_key_handle, TPM2_ALG_SHA256, &attest, &signature,
				 &validation)) == CHARRA_RC_SUCCESS) {
			charra_log_info(
				"[" LOG_NAME "]     => TPM Quote signature is valid!");
			attestation_result_signature = true;
		} else {
			charra_log_error(
				"[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
		}
	}

	/* unmarshal attestation data */
	TPMS_ATTEST attest_struct = {0};
	charra_r = charra_unmarshal_tpm2_quote(
		res.attestation_data_len, res.attestation_data, &attest_struct);

	/* --- verify nonce --- */
	bool attestation_result_nonce = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying nonce ...");

		attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
			last_request.nonce_len, last_request.nonce, &attest_struct);
		if (attestation_result_nonce == true) {
			charra_log_info(
				"[" LOG_NAME
				"]     => Nonce in TPM Quote is valid! (matches the one sent)");
		} else {
			charra_log_error(
				"[" LOG_NAME "]     => Nonce in TPM Quote is NOT valid! (does "
				"not match the one sent)");
		}
	}

	/* --- verify PCRs --- */
	bool attestation_result_pcrs = false;
	{
		charra_log_info("[" LOG_NAME "] Verifying PCRs ...");

		/* get reference PCRs */
		uint8_t* reference_pcrs[TPM2_MAX_PCRS] = {0};
		if ((charra_r = charra_get_reference_pcrs_sha256(TPM_PCR_SELECTION,
				 TPM_PCR_SELECTION_LEN, reference_pcrs)) != CHARRA_RC_SUCCESS) {
			charra_log_error("[" LOG_NAME "] Error getting reference PCRs.");
			goto error;
		}

		/* compute PCR composite digest from reference PCRs */
		uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE] = {0};
		/* TODO use crypto-agile (generic) version
		 * charra_compute_pcr_composite_digest_from_ptr_array(), once
		 * implemented, instead of hash_sha256_array() (then maybe remove
		 * hash_sha256_array() function) */
		charra_r = hash_sha256_array(
			reference_pcrs, TPM_PCR_SELECTION_LEN, pcr_composite_digest);
		charra_log_info(
			"[" LOG_NAME
			"] Computed PCR composite digest from reference PCRs is:");
		charra_print_hex(sizeof(pcr_composite_digest), pcr_composite_digest,
			"                                   0x", "\n", false);
		charra_log_info(
			"[" LOG_NAME "] Actual PCR composite digest from TPM Quote is:");
		charra_print_hex(attest_struct.attested.quote.pcrDigest.size,
			attest_struct.attested.quote.pcrDigest.buffer,
			"                                   0x", "\n", false);

		/* compare reference PCR composite with actual PCR composite */
		attestation_result_pcrs = charra_verify_tpm2_quote_pcr_composite_digest(
			&attest_struct, pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);
		if (attestation_result_pcrs == true) {
			charra_log_info(
				"[" LOG_NAME
				"]     => PCR composite digest is valid! (matches the "
				"one from reference PCRs)");
		} else {
			charra_log_error(
				"[" LOG_NAME
				"]     => PCR composite digest is NOT valid! (does "
				"not match the one from reference PCRs)");
		}
	}

	/* --- output result --- */

	bool attestation_result = attestation_result_signature &&
							  attestation_result_nonce &&
							  attestation_result_pcrs;

	/* print attestation result */
	charra_log_info("[" LOG_NAME "] +----------------------------+");
	if (attestation_result) {
		charra_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
	} else {
		charra_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
	}
	charra_log_info("[" LOG_NAME "] +----------------------------+");

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
