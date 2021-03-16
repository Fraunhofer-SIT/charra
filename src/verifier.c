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
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

#include "common/charra_log.h"
#include "core/charra_dto.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "core/charra_rim_mgr.h"
#include "util/charra_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/crypto_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;
static bool attestation_finished = false;

/* logging */
#define LOG_NAME "verifier"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
char dst_host[16] = "127.0.0.1";		 // 15 characters for IPv4 plus \0
unsigned int dst_port = 5683;			 // default port
#define CBOR_ENCODER_BUFFER_LENGTH 20480 // 20 KiB should be sufficient
#define COAP_IO_PROCESS_TIME_MS 2000	 // CoAP IO process time in milliseconds
#define PERIODIC_ATTESTATION_WAIT_TIME_S                                       \
	2 // Wait time between attestations in seconds
static const bool USE_TPM_FOR_RANDOM_NONCE_GENERATION = false;

#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"
static const uint8_t TPM_PCR_SELECTION[TPM2_MAX_PCRS] = {
	0, 1, 2, 3, 4, 5, 6, 7, 10};
static const uint32_t TPM_PCR_SELECTION_LEN = 9;
uint16_t attestation_response_timeout =
	30; // timeout when waiting for attestation answer in seconds

/* --- function forward declarations -------------------------------------- */

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto* attestation_request);

static coap_response_t coap_attest_handler(struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent, coap_pdu_t* received,
	const coap_tid_t id);

/* --- static variables --------------------------------------------------- */

static msg_attestation_request_dto last_request = {0};
static msg_attestation_response_dto last_response = {0};

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
	int result = EXIT_FAILURE;

	/* handle SIGINT */
	signal(SIGINT, handle_sigint);

	/* check environment variables */
	charra_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
	charra_coap_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

	/* initialize structures to pass to the CLI parser */
	cli_config cli_config = {
		.caller = VERIFIER,
		.common_config =
			{
				.charra_log_level = &charra_log_level,
				.coap_log_level = &coap_log_level,
				.port = &dst_port,
			},
		.verifier_config =
			{
				.dst_host = dst_host,
				.timeout = &attestation_response_timeout,
			},
	};

	/* parse CLI arguments */
	if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
		// 1 means help message was displayed (thus exit), -1 means error
		return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* set CHARRA and libcoap log levels */
	charra_log_set_level(charra_log_level);
	coap_set_log_level(coap_log_level);

	charra_log_debug("[" LOG_NAME "] Verifier Configuration:");
	charra_log_debug("[" LOG_NAME "]     Destination port: %d", dst_port);
	charra_log_debug("[" LOG_NAME "]     Destination host: %s", dst_host);
	charra_log_debug("[" LOG_NAME
					 "]     Timeout when waiting for attestation response: %ds",
		attestation_response_timeout);

	/* create CoAP context */
	coap_context_t* coap_context = NULL;
	charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context = charra_coap_new_context(true)) == NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		goto finish;
	}

	/* register CoAP response handler */
	charra_log_info("[" LOG_NAME "] Registering CoAP response handler.");
	coap_register_response_handler(coap_context, coap_attest_handler);

	/* create CoAP client session */
	coap_session_t* coap_session = NULL;
	charra_log_info("[" LOG_NAME "] Creating CoAP client session.");
	if ((coap_session = charra_coap_new_client_session(
			 coap_context, dst_host, dst_port, COAP_PROTO_UDP)) == NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create client session.");
		goto finish;
	}

	/* define needed variables */
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	msg_attestation_request_dto req = {0};
	uint32_t req_buf_len = 0;
	uint8_t* req_buf = NULL;
	coap_optlist_t* coap_options = NULL;
	coap_pdu_t* pdu = NULL;
	coap_tid_t tid = COAP_INVALID_TID;
	int coap_io_process_time = -1;

	/* create CoAP option for content type */
	uint8_t coap_mediatype_cbor_buf[4] = {0};
	unsigned int coap_mediatype_cbor_buf_len = 0;
	if ((coap_mediatype_cbor_buf_len = coap_encode_var_safe(
			 coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
			 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
		charra_log_error(
			"[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
		goto error;
	}

	/* enter  periodic attestation loop */
	// TODO enable periodic attestations
	// charra_log_info("[" LOG_NAME "] Entering periodic attestation loop.");
	// while (!quit) {
	// 	/* cleanup */
	// 	memset(&req, 0, sizeof(req));
	// 	if (coap_options != NULL) {
	// 		coap_delete_optlist(coap_options);
	// 		coap_options = NULL;
	// 	}

	/* create attestation request */
	charra_log_info("[" LOG_NAME "] Creating attestation request.");
	if (create_attestation_request(&req) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Cannot create attestation request.");
		goto error;
	} else {
		/* store request data */
		last_request = req;
	}

	/* marshal attestation request */
	charra_log_info(
		"[" LOG_NAME "] Marshaling attestation request data to CBOR.");
	if ((charra_r = marshal_attestation_request(
			 &req, &req_buf_len, &req_buf)) != CHARRA_RC_SUCCESS) {
		charra_log_error(
			"[" LOG_NAME "] Marshaling attestation request data failed.");
		goto error;
	}

	/* CoAP options */
	charra_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
	if (coap_insert_optlist(
			&coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 6,
							   (const uint8_t*)"attest")) != 1) {
		charra_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
		goto error;
	}
	charra_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
	if (coap_insert_optlist(&coap_options,
			coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
				coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf)) != 1) {
		charra_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
		goto error;
	}

	/* new CoAP request PDU */
	charra_log_info("[" LOG_NAME "] Creating request PDU.");
	if ((pdu = charra_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON,
			 COAP_REQUEST_FETCH, &coap_options, req_buf, req_buf_len)) ==
		NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create request PDU.");
		goto error;
	}

	/* set timeout length */
	coap_fixed_point_t coap_timeout = {attestation_response_timeout, 0};
	coap_session_set_ack_timeout(coap_session, coap_timeout);

	/* send CoAP PDU */
	charra_log_info("[" LOG_NAME "] Sending CoAP message.");
	if ((tid = coap_send_large(coap_session, pdu)) == COAP_INVALID_TID) {
		charra_log_error("[" LOG_NAME "] Cannot send CoAP message.");
		goto error;
	}

	/* processing and waiting for response */
	charra_log_info("[" LOG_NAME "] Processing and waiting for response ...");
	uint16_t response_wait_time = 0;
	while (attestation_finished != true) {
		/* process CoAP I/O */
		if ((coap_io_process_time = coap_io_process(
				 coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
			charra_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			goto error;
		}
		/* This wait time is not 100% accurate, it only includes the elapsed
		 * time inside the coap_io_process function. But should be good enough.
		 */
		response_wait_time += coap_io_process_time;
		if (response_wait_time >= (attestation_response_timeout * 1000)) {
			charra_log_error("[" LOG_NAME
							 "] Timeout after %d ms while waiting for or "
							 "processing attestation response.",
				response_wait_time);
			goto error;
		}
	}

	/* wait until next attestation */
	// TODO enable periodic attestations
	// charra_log_info(
	// 	"[" LOG_NAME
	// 	"] Waiting %d seconds until next attestation request ...",
	// 	PERIODIC_ATTESTATION_WAIT_TIME_S);
	// sleep(PERIODIC_ATTESTATION_WAIT_TIME_S);
	// }

	result = EXIT_SUCCESS;
	goto finish;

error:
	result = EXIT_FAILURE;

finish:
	/* free CoAP memory */
	if (coap_options != NULL) {
		coap_delete_optlist(coap_options);
		coap_options = NULL;
	}
	if (coap_session != NULL) {
		coap_session_release(coap_session);
		coap_session = NULL;
	}
	if (coap_context != NULL) {
		coap_free_context(coap_context);
		coap_context = NULL;
	}
	if (req_buf != NULL) {
		free(req_buf);
		req_buf = NULL;
	}
	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

static CHARRA_RC create_attestation_request(
	msg_attestation_request_dto* attestation_request) {
	CHARRA_RC err = CHARRA_RC_ERROR;

	/* generate nonce */
	uint32_t nonce_len = 20;
	uint8_t nonce[nonce_len];
	if (USE_TPM_FOR_RANDOM_NONCE_GENERATION) {
		if ((err = charra_random_bytes_from_tpm(nonce_len, nonce) !=
				   CHARRA_RC_SUCCESS)) {
			charra_log_error("Could not get random bytes from TPM for nonce.");
			return err;
		}
	} else {
		if ((err = charra_random_bytes(nonce_len, nonce) !=
				   CHARRA_RC_SUCCESS)) {
			charra_log_error("Could not get random bytes for nonce.");
			return err;
		}
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

static coap_response_t coap_attest_handler(
	struct coap_context_t* context CHARRA_UNUSED,
	coap_session_t* session CHARRA_UNUSED, coap_pdu_t* sent CHARRA_UNUSED,
	coap_pdu_t* in, const coap_tid_t id CHARRA_UNUSED) {
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
	const uint8_t* data = NULL;
	size_t data_offset = 0;
	size_t data_total_len = 0;
	if ((coap_r = coap_get_data_large(
			 in, &data_len, &data, &data_offset, &data_total_len)) == 0) {
		charra_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
		goto error;
	} else {
		charra_log_info(
			"[" LOG_NAME "] Received data of length %zu.", data_len);
		charra_log_info("[" LOG_NAME "] Received data of total length %zu.",
			data_total_len);
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
	TSS2_TCTI_CONTEXT* tcti_ctx = NULL;
	if ((tss_r = Tss2_TctiLdr_Initialize(getenv("CHARRA_TCTI"), &tcti_ctx)) !=
		TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Tss2_TctiLdr_Initialize.");
		goto error;
	}
	if ((tss_r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) !=
		TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Esys_Initialize.");
		goto error;
	}

	/* load TPM key */
	TPM2B_PUBLIC* tpm2_public_key = (TPM2B_PUBLIC*)res.tpm2_public_key;
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	if ((charra_r = charra_load_external_public_key(esys_ctx, tpm2_public_key,
			 &sig_key_handle)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Loading external public key failed.");
		goto error;
	} else {
		charra_log_info("[" LOG_NAME "] External public key loaded.");
	}

	/* prepare verification */
	charra_log_info("[" LOG_NAME "] Preparing TPM Quote verification.");
	TPM2B_ATTEST attest = {0};
	attest.size = res.attestation_data_len;
	memcpy(
		attest.attestationData, res.attestation_data, res.attestation_data_len);
	TPMT_SIGNATURE signature = {0};
	memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

	/* --- verify attestation signature --- */
	bool attestation_result_signature = false;
	{
		charra_log_info(
			"[" LOG_NAME "] Verifying TPM Quote signature with TPM ...");
		/* verify attestation signature with TPM */
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
	{
		/* convert TPM public key to mbedTLS public key */
		charra_log_info(
			"[" LOG_NAME
			"] Converting TPM public key to mbedTLS public key ...");
		mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
		if ((charra_r = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
				 tpm2_public_key, &mbedtls_rsa_pub_key)) != CHARRA_RC_SUCCESS) {
			charra_log_error("[" LOG_NAME "] mbedTLS RSA error");
			goto error;
		}

		/* verify attestation signature with mbedTLS */
		charra_log_info(
			"[" LOG_NAME "] Verifying TPM Quote signature with mbedTLS ...");
		if ((charra_r = charra_crypto_rsa_verify_signature(&mbedtls_rsa_pub_key,
				 MBEDTLS_MD_SHA256, res.attestation_data,
				 (size_t)res.attestation_data_len,
				 signature.signature.rsapss.sig.buffer)) == CHARRA_RC_SUCCESS) {
			charra_log_info(
				"[" LOG_NAME "]     => TPM Quote signature is valid!");
			attestation_result_signature = true;
		} else {
			charra_log_error(
				"[" LOG_NAME "]     => TPM Quote signature is NOT valid!");
		}
		mbedtls_rsa_free(&mbedtls_rsa_pub_key);
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
			"                                              0x", "\n", false);
		charra_log_info(
			"[" LOG_NAME "] Actual PCR composite digest from TPM Quote is:");
		charra_print_hex(attest_struct.attested.quote.pcrDigest.size,
			attest_struct.attested.quote.pcrDigest.buffer,
			"                                              0x", "\n", false);

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

	/* verify event log */
	// TODO: Implement real verification
	bool attestation_event_log = true;
	{
		charra_log_info("[" LOG_NAME "] Verifying event log ...");
		charra_log_info("[" LOG_NAME "]     IMA Event Log size is %d bytes.",
			res.event_log_len);
		charra_log_info("[" LOG_NAME "]     !!! This is to be implemented");
		if (charra_log_level <= CHARRA_LOG_DEBUG) {
			if (res.event_log_len > 20) {
				charra_log_debug("[" LOG_NAME "]     Printing 10 bytes of the start and end of the event log in hex:");
				charra_print_hex(10, res.event_log, "", " ... ", false);
				charra_print_hex(10, (res.event_log + res.event_log_len - 10), "", "\n", false);
			} else {
				charra_log_debug("[" LOG_NAME "]     Printing event log in hex:");
				charra_print_hex(res.event_log_len, res.event_log, "", "\n", false);
			}
		}
	}

	/* --- output result --- */

	bool attestation_result = attestation_result_signature &&
							  attestation_result_nonce &&
							  attestation_result_pcrs && attestation_event_log;

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

	/* free event log */
	// TODO: Provide function charra_free_msg_attestation_response_dto()
	if (res.event_log != NULL) {
		free(res.event_log);
	}

	/* free ESAPI objects */
	if (validation != NULL) {
		Esys_Free(validation);
	}

	/* finalize ESAPI & TCTI*/
	if (esys_ctx != NULL) {
		Esys_Finalize(&esys_ctx);
	}
	if (tcti_ctx != NULL) {
		Tss2_TctiLdr_Finalize(&tcti_ctx);
	}

	attestation_finished = true;
	return COAP_RESPONSE_OK;
}
