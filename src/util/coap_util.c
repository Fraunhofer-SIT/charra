/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file coap_util.c
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

#include "coap_util.h"

#include <arpa/inet.h>
#include <coap2/coap.h>
#include <stdbool.h>
#include <string.h>

#include "../common/charra_log.h"
#include "../util/io_util.h"

#define LOG_NAME "coap-util"
#define CHARRA_UNUSED __attribute__((unused))

static const char* const coap_level_names[10] = {[LOG_EMERG] = "EMERG",
	[LOG_ALERT] = "ALERT",
	[LOG_CRIT] = "CRIT",
	[LOG_ERR] = "ERR",
	[LOG_WARNING] = "WARNING",
	[LOG_NOTICE] = "NOTICE",
	[LOG_INFO] = "INFO",
	[LOG_DEBUG] = "DEBUG",
	[COAP_LOG_CIPHERS] = "CIPHERS"};

/* --- function forward declarations -------------------------------------- */

static int verify_rpk_peer_callback(const char* cn,
	const uint8_t* asn1_public_cert, size_t asn1_length,
	coap_session_t* session, unsigned depth, int validated, void* arg);

/* --- function definitions ----------------------------------------------- */

coap_context_t* charra_coap_new_context(const bool enable_coap_block_mode) {
	/* startup */
	coap_startup();

	/* create new context */
	coap_context_t* coap_context = NULL;
	if ((coap_context = coap_new_context(NULL)) != NULL) {
		if (enable_coap_block_mode) {
			/* enable block handling by libcoap */
			coap_context_set_block_mode(
				coap_context, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
		}
	}

	return coap_context;
}

coap_endpoint_t* charra_coap_new_endpoint(coap_context_t* coap_context,
	const char* listen_address, const uint16_t port,
	const coap_proto_t coap_protocol) {
	/* prepare address */
	coap_address_t addr = {0};
	coap_address_init(&addr);
	addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, listen_address, &addr.addr.sin.sin_addr);
	addr.addr.sin.sin_port = htons(port);

	/* create endpoint */
	return coap_new_endpoint(coap_context, &addr, coap_protocol);
}

coap_session_t* charra_coap_new_client_session(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol) {
	/* prepare address */
	coap_address_t addr = {0};
	coap_address_init(&addr);
	addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
	addr.addr.sin.sin_port = htons(port);

	/* create session */
	return coap_new_client_session(coap_context, NULL, &addr, coap_protocol);
}

coap_session_t* charra_coap_new_client_session_psk(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol, const char* identity, const uint8_t* key,
	unsigned key_length) {
	/* prepare address */
	coap_address_t addr = {0};
	coap_address_init(&addr);
	addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
	addr.addr.sin.sin_port = htons(port);

	/* create session */
	return coap_new_client_session_psk(
		coap_context, NULL, &addr, coap_protocol, identity, key, key_length);
}

coap_session_t* charra_coap_new_client_session_pki(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol, coap_dtls_pki_t* dtls_pki) {
	/* prepare address */
	coap_address_t addr = {0};
	coap_address_init(&addr);
	addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, dest_address, &addr.addr.sin.sin_addr);
	addr.addr.sin.sin_port = htons(port);

	/* create session */
	return coap_new_client_session_pki(
		coap_context, NULL, &addr, coap_protocol, dtls_pki);
}

coap_pdu_t* charra_coap_new_request(coap_session_t* session,
	coap_message_t msg_type, coap_request_t method, coap_optlist_t** options,
	const uint8_t* data, const size_t data_len) {
	coap_pdu_t* pdu = NULL;

	/* create new PDU */
	if ((pdu = coap_new_pdu(session)) == NULL) {
		charra_log_error("[" LOG_NAME "] Cannot create PDU");
		goto error;
	}

	/* generate new message ID */
	coap_message_id_t msg_id = coap_new_message_id(session);

	/* set up PDU */
	pdu->type = msg_type;
	pdu->mid = msg_id;
	pdu->code = method;

	/* generate new token */
	coap_token_t token = {0};
	coap_session_new_token(session, &(token.length), token.data);

	/* add token to PDU */
	if (coap_add_token(pdu, token.length, token.data) == 0) {
		charra_log_error("[" LOG_NAME "] Cannot add token to request");
		goto error;
	}

	/* add options to PDU */
	if (options != NULL) {
		if (coap_add_optlist_pdu(pdu, options) == 0) {
			charra_log_error("[" LOG_NAME "] Cannot add options to request");
			goto error;
		}
	}

	/* add (large) data to PDU */
	if (data_len > 0) {
		/* let the underlying libcoap decide how this data should be sent */
		if (coap_add_data_large_request(
				session, pdu, data_len, data, NULL, NULL) == 0) {
			charra_log_error(
				"[" LOG_NAME
				"] Cannot add (large) data option list to request");
			goto error;
		}
	}

	return pdu;

error:
	/* cleanup */
	if (pdu != NULL) {
		coap_delete_pdu(pdu);
		// coap_free_type(COAP_PDU, pdu);
	}

	return NULL;
}

void charra_coap_add_resource(struct coap_context_t* coap_context,
	const coap_request_t method, const char* resource_name,
	const coap_method_handler_t handler) {
	charra_log_info("[" LOG_NAME "] Adding CoAP %s resource '%s'.",
		charra_coap_method_to_str(method), resource_name);

	coap_str_const_t* resource_uri = coap_new_str_const(
		(uint8_t const*)resource_name, strlen(resource_name));
	coap_resource_t* resource =
		coap_resource_init(resource_uri, COAP_RESOURCE_FLAGS_RELEASE_URI);
	coap_register_handler(resource, method, handler);
	coap_add_resource(coap_context, resource);
}

CHARRA_RC charra_coap_setup_dtls_pki_for_rpk(coap_dtls_pki_t* dtls_pki,
	char* private_key_path, char* public_key_path, char* peer_public_key_path,
	bool verify_peer_public_key) {
	// read public key file
	char* public_key_file = NULL;
	size_t public_key_file_length = 0;
	CHARRA_RC rc = charra_io_read_file(
		public_key_path, &public_key_file, &public_key_file_length);
	if (rc != CHARRA_RC_SUCCESS) {
		charra_log_error(
			"[" LOG_NAME "] Cannot read file at path '%s'", public_key_path);
		return rc;
	}

	// read private key file
	char* private_key_file = NULL;
	size_t private_key_file_length = 0;
	rc = charra_io_read_file(
		private_key_path, &private_key_file, &private_key_file_length);
	if (rc != CHARRA_RC_SUCCESS) {
		charra_log_error(
			"[" LOG_NAME "] Cannot read file at path '%s'", private_key_path);
		return rc;
	}

	// DTLS setup for PKI / RPK (raw public keys)
	dtls_pki->version = COAP_DTLS_PKI_SETUP_VERSION;
	dtls_pki->verify_peer_cert = 1;	 // not documented to be ignored when RPK is
									 // used, but seems like it is?
	dtls_pki->check_common_ca = 0;	 // ignored when RPK is used
	dtls_pki->allow_self_signed = 0; // ignored when RPK is used
	dtls_pki->allow_expired_certs = 0;	   // ignored when RPK is used
	dtls_pki->cert_chain_validation = 0;   // ignored when RPK is used
	dtls_pki->cert_chain_verify_depth = 0; // ignored when RPK is used
	dtls_pki->check_cert_revocation = 0;   // ignored when RPK is used
	dtls_pki->allow_no_crl = 0;			   // ignored when RPK is used
	dtls_pki->allow_expired_crl = 0;	   // ignored when RPK is used
	dtls_pki->allow_bad_md_hash = 0;	   // ignored when RPK is used
	dtls_pki->allow_short_rsa_length = 0;  // ignored when RPK is used
	dtls_pki->is_rpk_not_cert = 1;		   // use RPK instead of PKI
	dtls_pki->validate_cn_call_back =
		verify_peer_public_key ? verify_rpk_peer_callback : NULL;
	dtls_pki->cn_call_back_arg = (void*)peer_public_key_path;
	dtls_pki->validate_sni_call_back = NULL;
	dtls_pki->sni_call_back_arg = NULL;
	dtls_pki->additional_tls_setup_call_back = NULL;
	dtls_pki->client_sni = NULL;
	dtls_pki->pki_key.key_type = COAP_PKI_KEY_ASN1;
	dtls_pki->pki_key.key.asn1.ca_cert = NULL;
	dtls_pki->pki_key.key.asn1.ca_cert_len = 0;
	dtls_pki->pki_key.key.asn1.public_cert = (uint8_t*)public_key_file;
	dtls_pki->pki_key.key.asn1.public_cert_len = public_key_file_length;
	dtls_pki->pki_key.key.asn1.private_key = (uint8_t*)private_key_file;
	dtls_pki->pki_key.key.asn1.private_key_len = private_key_file_length;
	dtls_pki->pki_key.key.asn1.private_key_type = COAP_ASN1_PKEY_EC;

	return CHARRA_RC_SUCCESS;
}

int charra_coap_log_level_from_str(
	const char* log_level_str, coap_log_t* log_level) {
	if (log_level_str != NULL) {
		int array_size = sizeof(coap_level_names) / sizeof(coap_level_names[0]);
		for (int i = 0; i < array_size; i++) {
			const char* name = coap_level_names[i];
			if (name == NULL) {
				continue;
			}
			if (strcmp(name, log_level_str) == 0) {
				*log_level = i;
				return 0;
			}
		}
		return -1;
	}

	return -1;
}

const char* charra_coap_method_to_str(const coap_request_t method) {
	switch (method) {
	case COAP_REQUEST_GET:
		return "GET";
	case COAP_REQUEST_POST:
		return "POST";
	case COAP_REQUEST_PUT:
		return "PUT";
	case COAP_REQUEST_DELETE:
		return "DELETE";
	case COAP_REQUEST_FETCH:
		return "FETCH";
	case COAP_REQUEST_PATCH:
		return "PATCH";
	case COAP_REQUEST_IPATCH:
		return "IPATCH";
	default:
		return "UNKNOWN";
	}
}

/**
 * Peer Validation callback that can be set up by coap_context_set_pki().
 * Invoked when libcoap has done the validation checks at the TLS level,
 * but the application needs to check that the CN (for PKI) or public key
 * (for RPK) is allowed. Currently in out case only RPK is used.
 *
 * @param cn  A string containing "RPK", for PKI the common name
 * @param asn1_public_cert  ASN.1 encoded (DER) public key, for PKI the X.509
 * certificate
 * @param asn1_length  The ASN.1 length
 * @param session  The coap session associated with the certificate update
 * @param depth  for PKI: Depth in cert chain.  If 0, then client cert, else a
 * CA
 * @param validated  TLS can find no issues if 1
 * @param arg  The same as was passed into coap_context_set_pki()
 *             in setup_data->cn_call_back_arg, in this case the path of the
 *             peers' public key
 *
 * @return 1 if accepted, else 0 if to be rejected
 */
static int verify_rpk_peer_callback(const char* cn,
	const uint8_t* asn1_public_cert, size_t asn1_length,
	coap_session_t* session CHARRA_UNUSED, unsigned depth CHARRA_UNUSED,
	int validated, void* arg) {
	charra_log_info("[" LOG_NAME "] Checking peers public key for equivalence "
					"against peers' known public key.");
	if (strcmp("RPK", cn) == 0 && validated == 1) {
		char* reference = NULL;
		size_t reference_length = 0;
		CHARRA_RC rc =
			charra_io_read_file((char*)arg, &reference, &reference_length);
		if (rc == CHARRA_RC_SUCCESS) {
			if (reference_length == asn1_length) {
				if (memcmp(reference, asn1_public_cert, reference_length) ==
					0) {
					return 1;
				}
			}
			charra_log_error("[" LOG_NAME
							 "] DTLS-RPK: The public key of the peer could not "
							 "be verified with the reference key at path '%s'.",
				(char*)arg);
			charra_print_hex(CHARRA_LOG_DEBUG, reference_length, (uint8_t*) reference,
				"Reference public key of peer: ", "\n", false);
			charra_print_hex(CHARRA_LOG_DEBUG, asn1_length, asn1_public_cert,
				"Actual public key of peer: ", "\n", false);
			return 0;
		}
		charra_log_error("[" LOG_NAME "] DTLS-RPK: The reference key of the "
						 "peer at path '%s' could not be opened.",
			(char*)arg);
		return 0;
	}
	charra_log_error(
		"[" LOG_NAME
		"] DTLS-RPK: Unexpected error while verifying peers' public key");
	return 0;
}
