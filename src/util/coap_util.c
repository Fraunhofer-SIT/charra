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

#include <coap2/coap.h>

#include "../common/charra_log.h"

const char* charra_coap_method_to_str(const uint8_t method) {
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

void charra_coap_add_resource(struct coap_context_t* ctx,
	const unsigned char method, const char* resource_name,
	const coap_method_handler_t handler) {
	charra_log_info("Adding CoAP %s resource '%s'.",
		charra_coap_method_to_str(method), resource_name);

	coap_resource_t* resource =
		coap_resource_init(coap_new_str_const((const uint8_t*)resource_name,
							   strlen(resource_name)),
			COAP_RESOURCE_FLAGS_RELEASE_URI);
	coap_register_handler(resource, method, handler);
	coap_add_resource(ctx, resource);
}

void charra_coap_add_get_resource(struct coap_context_t* ctx,
	const char* resource_name, const coap_method_handler_t handler) {
	charra_coap_add_resource(ctx, COAP_REQUEST_GET, resource_name, handler);
}

void charra_coap_add_fetch_resource(struct coap_context_t* ctx,
	const char* resource_name, const coap_method_handler_t handler) {
	charra_coap_add_resource(ctx, COAP_REQUEST_FETCH, resource_name, handler);
}
