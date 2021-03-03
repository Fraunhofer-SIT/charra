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

#define LOG_NAME "coap-util"

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
	pdu->tid = msg_id;
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

	coap_str_const_t* resource_uri = coap_make_str_const(resource_name);
	coap_resource_t* resource =
		coap_resource_init(resource_uri, COAP_RESOURCE_FLAGS_RELEASE_URI);
	coap_register_handler(resource, method, handler);
	coap_add_resource(coap_context, resource);
}

coap_log_t charra_coap_log_level_from_str(
	const char* log_level_str, coap_log_t default_log_level) {
	if (log_level_str != NULL) {
		if (strncmp(log_level_str, "EMERG", 5) == 0) {
			return LOG_EMERG;
		} else if (strncmp(log_level_str, "ALERT", 5) == 0) {
			return LOG_ALERT;
		} else if (strncmp(log_level_str, "CRIT", 4) == 0) {
			return LOG_CRIT;
		} else if (strncmp(log_level_str, "ERR", 3) == 0) {
			return LOG_ERR;
		} else if (strncmp(log_level_str, "WARNING", 7) == 0) {
			return LOG_WARNING;
		} else if (strncmp(log_level_str, "NOTICE", 6) == 0) {
			return LOG_NOTICE;
		} else if (strncmp(log_level_str, "INFO", 4) == 0) {
			return LOG_INFO;
		} else if (strncmp(log_level_str, "DEBUG", 5) == 0) {
			return LOG_DEBUG;
		} else if (strncmp(log_level_str, "CIPHERS", 7) == 0) {
			return COAP_LOG_CIPHERS;
		}
	}

	return default_log_level;
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
