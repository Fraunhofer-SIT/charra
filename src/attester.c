/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file attester.c
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
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "common/charra_macro.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define CHARRA_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* logging */
#define LOG_NAME "attester"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
charra_log_t charra_log_level = CHARRA_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; // default port 5683
#define CBOR_ENCODER_BUFFER_LENGTH 20480	  // 20 KiB should be sufficient
bool use_ima_event_log = false;
char* ima_event_log_path =
	"/sys/kernel/security/ima/binary_runtime_measurements";
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_hint = "Charra Attester";
// TODO allocate memory for CBOR buffer using malloc() since logs can be huge

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/attester.der";
char* dtls_rpk_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/verifier.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static void release_data(
	struct coap_session_t* session CHARRA_UNUSED, void* app_ptr);

static void coap_attest_handler(struct coap_context_t* ctx,
	struct coap_resource_t* resource, struct coap_session_t* session,
	struct coap_pdu_t* in_pdu, struct coap_binary_t* token,
	struct coap_string_t* query, struct coap_pdu_t* out_pdu);

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
		.caller = ATTESTER,
		.common_config =
			{
				.charra_log_level = &charra_log_level,
				.coap_log_level = &coap_log_level,
				.port = &port,
				.use_dtls_psk = &use_dtls_psk,
				.dtls_psk_key = &dtls_psk_key,
				.use_dtls_rpk = &use_dtls_rpk,
				.dtls_rpk_private_key_path = &dtls_rpk_private_key_path,
				.dtls_rpk_public_key_path = &dtls_rpk_public_key_path,
				.dtls_rpk_peer_public_key_path = &dtls_rpk_peer_public_key_path,
				.dtls_rpk_verify_peer_public_key =
					&dtls_rpk_verify_peer_public_key,
			},
		.attester_config =
			{
				.dtls_psk_hint = &dtls_psk_hint,
			},
	};

	/* parse CLI arguments */
	if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
		// 1 means help message is displayed, -1 means error
		return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* set CHARRA and libcoap log levels */
	charra_log_set_level(charra_log_level);
	coap_set_log_level(coap_log_level);

	charra_log_debug("[" LOG_NAME "] Attester Configuration:");
	charra_log_debug("[" LOG_NAME "]     Used local port: %d", port);
	charra_log_debug("[" LOG_NAME "]     DTLS-PSK enabled: %s",
		(use_dtls_psk == true) ? "true" : "false");
	if (use_dtls_psk) {
		charra_log_debug("[" LOG_NAME "]         Pre-shared key: '%s'",
			dtls_psk_key);
		charra_log_debug(
			"[" LOG_NAME "]         Hint: '%s'", dtls_psk_hint);
	}
	charra_log_debug("[" LOG_NAME "]     DTLS-RPK enabled: %s",
		(use_dtls_rpk == true) ? "true" : "false");
	if (use_dtls_rpk) {
		charra_log_debug("[" LOG_NAME
						 "]         Private key path: '%s'",
			dtls_rpk_private_key_path);
		charra_log_debug("[" LOG_NAME
						 "]         Public key path: '%s'",
			dtls_rpk_public_key_path);
		charra_log_debug("[" LOG_NAME
						 "]         Peers' public key path: '%s'",
			dtls_rpk_peer_public_key_path);
	}

	/* set varaibles here such that they are valid in case of an 'goto error' */
	coap_context_t* coap_context = NULL;
	coap_endpoint_t* coap_endpoint = NULL;

	if (use_dtls_psk && use_dtls_rpk) {
		charra_log_error(
			"[" LOG_NAME "] Configuration enables both DTSL with PSK "
			"and DTSL with PKI. Aborting!");
		goto error;
	}

	if (use_dtls_psk || use_dtls_rpk) {
		// print TLS version when in debug mode
		coap_show_tls_version(LOG_DEBUG);
	}

	if ((use_dtls_psk || use_dtls_psk) && !coap_dtls_is_supported()) {
		charra_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
						 "configuration enables DTLS. Aborting!");
		goto error;
	}

	charra_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context = charra_coap_new_context(true)) == NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		goto error;
	}

	if (use_dtls_psk) {
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-PSK.");
		if (!coap_context_set_psk(coap_context, dtls_psk_hint,
				(uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) {
			charra_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-PSK.");
			goto error;
		}

		if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-PSK.\n");
			goto error;
		}
	} else if (use_dtls_rpk) {
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-RPK.");
		coap_dtls_pki_t dtls_pki = {0};

		CHARRA_RC rc = charra_coap_setup_dtls_pki_for_rpk(&dtls_pki,
			dtls_rpk_private_key_path, dtls_rpk_public_key_path,
			dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
		if (rc != CHARRA_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] Error while setting up DTLS-RPK structure.");
			goto error;
		}

		if (!coap_context_set_pki(coap_context, &dtls_pki)) {
			charra_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-RPK.");
			goto error;
		}

		if ((coap_endpoint = charra_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-RPK.\n");
			goto error;
		}
	} else {
		charra_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
		if ((coap_endpoint = charra_coap_new_endpoint(
				 coap_context, LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on UDP.\n");
			goto error;
		}
	}

	/* register CoAP resource and resource handler */
	charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
	charra_coap_add_resource(
		coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);

	/* enter main loop */
	charra_log_debug("[" LOG_NAME "] Entering main loop.");
	while (!quit) {
		/* process CoAP I/O */
		if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
			charra_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			goto error;
		}
	}

	result = EXIT_SUCCESS;
	goto finish;

error:
	result = EXIT_FAILURE;

finish:
	/* free CoAP memory */
	charra_free_and_null_ex(coap_endpoint, coap_free_endpoint);
	charra_free_and_null_ex(coap_context, coap_free_context);
	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum CHARRA_UNUSED) { quit = true; }

static void release_data(
	struct coap_session_t* session CHARRA_UNUSED, void* app_ptr) {
	charra_free_and_null(app_ptr);
}

static void coap_attest_handler(struct coap_context_t* ctx CHARRA_UNUSED,
	struct coap_resource_t* resource, struct coap_session_t* session,
	struct coap_pdu_t* in, struct coap_binary_t* token,
	struct coap_string_t* query, struct coap_pdu_t* out) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	int coap_r = 0;
	TSS2_RC tss_r = 0;
	ESYS_TR sig_key_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC* public_key = NULL;

	/* --- receive incoming data --- */

	charra_log_info(
		"[" LOG_NAME "] Resource '%s': Received message.", "attest");
	coap_show_pdu(LOG_DEBUG, in);

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
	msg_attestation_request_dto req = {0};
	if ((charra_r = charra_unmarshal_attestation_request(
			 data_len, data, &req)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* --- TPM quote --- */

	charra_log_info("[" LOG_NAME "] Preparing TPM quote data.");

	/* nonce */
	if (req.nonce_len > sizeof(TPMU_HA)) {
		charra_log_error("[" LOG_NAME "] Nonce too long.");
		goto error;
	}
	TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
	qualifying_data.size = req.nonce_len;
	memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);

	charra_log_info("Received nonce of length %d:", req.nonce_len);
	charra_print_hex(CHARRA_LOG_INFO, req.nonce_len, req.nonce,
		"                                   0x", "\n", false);

	/* PCR selection */
	TPML_PCR_SELECTION pcr_selection = {0};
	if ((charra_r = charra_pcr_selections_to_tpm_pcr_selections(
			 req.pcr_selections_len, req.pcr_selections, &pcr_selection)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] PCR selection conversion error.");
		goto error;
	}

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
	charra_log_info("[" LOG_NAME "] Loading TPM key.");
	if ((charra_r = charra_load_tpm2_key(esys_ctx, req.sig_key_id_len,
			 req.sig_key_id, &sig_key_handle, &public_key)) !=
		CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Could not load TPM key.");
		goto error;
	}

	/* do the TPM quote */
	charra_log_info("[" LOG_NAME "] Do TPM Quote.");
	TPM2B_ATTEST* attest_buf = NULL;
	TPMT_SIGNATURE* signature = NULL;
	if ((tss_r = tpm2_quote(esys_ctx, sig_key_handle, &pcr_selection,
			 &qualifying_data, &attest_buf, &signature)) != TSS2_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] TPM2 quote.");
		goto error;
	} else {
		charra_log_info("[" LOG_NAME "] TPM Quote successful.");
	}

	/* --- send response data --- */

	/* read IMA event log if requested */
	uint8_t* ima_event_log = NULL;
	size_t ima_event_log_len = 0;
	if (req.event_log_path_len != 0) {
		charra_log_info("[" LOG_NAME "] Reading IMA event log.");
		char* path = malloc(sizeof(char) * (req.event_log_path_len + 1));
		memcpy(path, req.event_log_path, req.event_log_path_len);
		path[req.event_log_path_len + 1] = '\n';
		CHARRA_RC rc = charra_io_read_continuous_binary_file(
			path, &ima_event_log, &ima_event_log_len);
		if (rc != CHARRA_RC_SUCCESS) {
			charra_log_error("[" LOG_NAME "] Error while reading IMA event "
							 "log. Sending empty event log!");
			ima_event_log_len = 0;
			ima_event_log = NULL;
		} else {
			charra_log_info("[" LOG_NAME
							"] IMA event log has a size of %d bytes.",
				ima_event_log_len);
		}
	}

	/* prepare response */
	charra_log_info("[" LOG_NAME "] Preparing response.");

	/* prepare response DTO */
	msg_attestation_response_dto res = {
		.attestation_data_len = attest_buf->size,
		.attestation_data = {0}, // must be memcpy'd, see below
		.tpm2_signature_len = sizeof(*signature),
		.tpm2_signature = {0}, // must be memcpy'd, see below
		.tpm2_public_key_len = sizeof(*public_key),
		.tpm2_public_key = {0}, // must be memcpy'd, see below
		.event_log_len = ima_event_log_len,
		.event_log = ima_event_log,
	};
	memcpy(res.attestation_data, attest_buf->attestationData,
		res.attestation_data_len);
	memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
	memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);

	/* clean up */
	charra_free_and_null(signature);
	charra_free_and_null(attest_buf);
	charra_free_and_null(public_key);

	/* marshal response */
	charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
	uint32_t res_buf_len = 0;
	uint8_t* res_buf = NULL;
	if ((charra_r = charra_marshal_attestation_response(
			 &res, &res_buf_len, &res_buf)) != CHARRA_RC_SUCCESS) {
		charra_log_error("[" LOG_NAME "] Error marshaling data.");
		goto error;
	}
	charra_log_info(
		"[" LOG_NAME "] Size of marshaled response is %d bytes.", res_buf_len);

	// TODO in case an error above occurred, a error respone should be sent
	// TODO the Verifier should be able to handle this error reponse

	/* add response data to outgoing PDU and send it */
	charra_log_info(
		"[" LOG_NAME
		"] Adding marshaled data to CoAP response PDU and send it.");
	out->code = COAP_RESPONSE_CODE_CONTENT;
	if ((coap_r = coap_add_data_large_response(resource, session, in, out,
			 token, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0, res_buf_len,
			 res_buf, release_data, res_buf)) == 0) {
		charra_log_error(
			"[" LOG_NAME "] Error invoking coap_add_data_large_response().");
		goto error;
	}

error:
	/* Free heap objects */
	charra_free_if_not_null(signature);
	charra_free_if_not_null(attest_buf);
	charra_free_if_not_null(public_key);
	charra_free_continous_file_buffer(&ima_event_log);

	/* flush handles */
	if (sig_key_handle != ESYS_TR_NONE) {
		if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
		}
	}

	/* finalize ESAPI */
	if (esys_ctx != NULL) {
		Esys_Finalize(&esys_ctx);
	}
	if (tcti_ctx != NULL) {
		Tss2_TctiLdr_Finalize(&tcti_ctx);
	}
}
