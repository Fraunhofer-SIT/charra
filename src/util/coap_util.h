/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file coap_util.h
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

#ifndef COAP_UTIL_H
#define COAP_UTIL_H

#include <coap2/coap.h>

#define TRUE (1 == 1)
#define FALSE (!TRUE)

const char* charra_coap_method_to_str(const uint8_t method);

void charra_add_coap_resource(struct coap_context_t* ctx,
	const unsigned char method, const char* resource_name,
	const coap_method_handler_t handler);

void charra_coap_add_get_resource(struct coap_context_t* ctx,
	const char* resource_name, const coap_method_handler_t handler);

void charra_coap_add_fetch_resource(struct coap_context_t* ctx,
	const char* resource_name, const coap_method_handler_t handler);

#endif /* COAP_UTIL_H */
