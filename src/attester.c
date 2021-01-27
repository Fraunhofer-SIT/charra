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
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include "common/charra_log.h"
#include "core/charra_dto.h"
#include "core/charra_helper.h"
#include "core/charra_key_mgr.h"
#include "core/charra_marshaling.h"
#include "util/cbor_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"
#include "util/tpm2_util.h"

#define UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* logging */
#define LOG_NAME "attester"
#define LOG_LEVEL_COAP LOG_INFO
// #define LOG_LEVEL_CBOR LOG_DEBUG
#define LOG_LEVEL_CHARRA CHARRA_LOG_INFO
// #define LOG_LEVEL_CHARRA CHARRA_LOG_DEBUG

/* config */
static const unsigned int PORT = 5683;	   // default port
static const unsigned int MAX_SIZE = 1300; // MTU payload max size
#define CBOR_ENCODER_BUFFER_LENGTH 20480   // 20 KiB should be sufficient

/* --- resource handler forward declarations ------------------------------ */

static void coap_attestation_handler(struct coap_context_t* ctx,
	struct coap_resource_t* resource, struct coap_session_t* session,
	struct coap_pdu_t* in_pdu, struct coap_binary_t* token,
	struct coap_string_t* query, struct coap_pdu_t* out_pdu);

/* --- main --------------------------------------------------------------- */

int main(void) {
	coap_context_t* ctx = NULL;
	coap_address_t serv_addr;
	coap_endpoint_t* endpoint = NULL;
	int result = EXIT_FAILURE;

	/* set CHARRA log level*/
	charra_log_set_level(LOG_LEVEL_CHARRA);

	/* start up CoAP and set log level*/
	coap_startup();
	coap_set_log_level(LOG_LEVEL_COAP);
	charra_log_info("[" LOG_NAME "] Starting up.");

	/* listen address and port */
	coap_address_init(&serv_addr);
	serv_addr.addr.sin.sin_family = AF_INET;
	serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
	serv_addr.addr.sin.sin_port = htons(PORT);

	/* create CoAP context */
	charra_log_info("[" LOG_NAME "] Initializing CoAP endpoint.");
	ctx = coap_new_context(NULL);
	if (!ctx ||
		!(endpoint = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP))) {
		charra_log_error(
			"[" LOG_NAME "] Cannot create server session (initializing "
			"CoAP context failed).");
		goto finish;
	}
	charra_log_debug("[" LOG_NAME "] Initialized CoAP context.");

	/* register CoAP resources and handlers */
	charra_log_info("[" LOG_NAME "] Registering CoAP resources.");
	charra_coap_add_fetch_resource(ctx, "attest", coap_attestation_handler);

	/* enter main loop */
	charra_log_debug("[" LOG_NAME "] Entering main loop.");
	while (TRUE) {
		int timing;
		charra_log_info("[" LOG_NAME "] Waiting for connections.");
		timing = coap_io_process(ctx, 0);
		if (timing < 0)
			break;
	}

	result = EXIT_SUCCESS;

finish:
	coap_free_context(ctx);
	coap_cleanup();

	return result;
}

/* --- resource handler definitions --------------------------------------- */

static void coap_attestation_handler(struct coap_context_t* ctx UNUSED,
	struct coap_resource_t* resource UNUSED,
	struct coap_session_t* session UNUSED, struct coap_pdu_t* in,
	struct coap_binary_t* token UNUSED, struct coap_string_t* query UNUSED,
	struct coap_pdu_t* out) {
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
	msg_attestation_request_dto req = {0};
	if ((charra_r = unmarshal_attestation_request(data_len, data, &req)) !=
		CHARRA_RC_SUCCESS) {
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
	charra_print_hex(req.nonce_len, req.nonce,
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
	if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
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

	/* prepare response */
	charra_log_info("[" LOG_NAME "] Preparing response.");
	msg_attestation_response_dto res = {
		.attestation_data_len = attest_buf->size,
		.attestation_data = {0}, // must be memcpy'd, see below
		.tpm2_signature_len = sizeof(*signature),
		.tpm2_signature = {0}, // must be memcpy'd, see below
		.tpm2_public_key_len = sizeof(*public_key),
		.tpm2_public_key = {0}}; // must be memcpy'd, see below
	memcpy(res.attestation_data, attest_buf->attestationData,
		res.attestation_data_len);
	memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
	memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);

	/* marshal response */
	charra_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
	uint32_t res_buf_len = 0;
	uint8_t* res_buf = NULL;
	marshal_attestation_response(&res, &res_buf_len, &res_buf);

	/* add data to outgoing PDU */
	charra_log_info(
		"[" LOG_NAME
		"] Adding marshaled data to CoAP response PDU and send it.");
	out->code = COAP_RESPONSE_CODE(205);
	out->max_size = MAX_SIZE;
	coap_add_data(out, res_buf_len, res_buf);

error:
	/* flush handles */
	if (sig_key_handle != ESYS_TR_NONE) {
		if (Esys_FlushContext(esys_ctx, sig_key_handle) != TSS2_RC_SUCCESS) {
			charra_log_error(
				"[" LOG_NAME "] TSS cleanup sig_key_handle failed.");
		}
	}

	/* finalize ESAPI */
	Esys_Finalize(&esys_ctx);
}
