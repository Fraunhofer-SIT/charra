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

#include "../common/charra_error.h"
#include <coap2/coap.h>
#include <stdbool.h>

/* --- type declarations/definitions -------------------------------------- */

/**
 * @brief CoAP token type.
 *
 */
typedef struct coap_token_t {
	/**
	 * @brief (Real) length of the token (max. 8).
	 *
	 */
	size_t length;

	/**
	 * @brief The token (max. 8 bytes)
	 *
	 */
	uint8_t data[8];
} coap_token_t;

/**
 * @brief CoAP message ID type.
 *
 */
typedef uint16_t coap_message_id_t;

/**
 * @brief CoAP message type.
 *
 */
typedef uint8_t coap_message_t;
/* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_TYPE_CON ((coap_message_t)COAP_MESSAGE_CON)
/* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_TYPE_NON ((coap_message_t)COAP_MESSAGE_NON)
/* used to acknowledge confirmable messages */
#define COAP_MESSAGE_TYPE_ACK ((coap_message_t)COAP_MESSAGE_ACK)
/* indicates error in received messages */
#define COAP_MESSAGE_TYPE_RST ((coap_message_t)COAP_MESSAGE_RST)

/* --- function forward declarations -------------------------------------- */

/**
 * @brief Creates a new CoAP context.
 *
 * @param[in] enable_coap_block_mode whether to enable CoAP block mode.
 * @return coap_context_t* the Coap context.
 * @return NULL if an error occurred.
 */
coap_context_t* charra_coap_new_context(const bool enable_coap_block_mode);

/**
 * @brief Creates a CoAP server endpoint.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] listen_address the IP address to listen on (e.g. "0.0.0.0").
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @return coap_endpoint_t* the CoAP endpoint.
 * @return NULL if an error occurred.
 */
coap_endpoint_t* charra_coap_new_endpoint(coap_context_t* coap_context,
	const char* listen_address, const uint16_t port,
	const coap_proto_t coap_protocol);

/**
 * @brief Creates a CoAP client session.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol);

/**
 * @brief Creates a CoAP client session with PSK.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @param[in] identity the identity used for PSK.
 * @param[in] key the pre-shared key.
 * @param[in] key_length the length of the pre-shared key.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session_psk(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol, const char* identity, const uint8_t* key,
	unsigned key_length);

/**
 * @brief Creates a CoAP client session with PKI.
 *
 * @param[inout] coap_context the CoAP context.
 * @param[in] dest_address the destination IP address.
 * @param[in] port the port (default CoAP UDP port is 5683).
 * @param[in] coap_protocol the CoAP protocol.
 * @param[in] dtls_pki structure holding configuration data for PKI mode of
 * CoAP.
 * @return coap_session_t* the CoAP session.
 * @return NULL if an error occurred.
 */
coap_session_t* charra_coap_new_client_session_pki(coap_context_t* coap_context,
	const char* dest_address, const uint16_t port,
	const coap_proto_t coap_protocol, coap_dtls_pki_t* dtls_pki);

/**
 * @brief Creates a new CoAP request with large data, using CoAP block-wise
 * transfers.
 *
 * @param session the CoAP session.
 * @param msg_type the CoAP message type.
 * @param method the CoAP request method.
 * @param options list of CoAP options.
 * @param data the data to send (this can be larger than the typical size of
 * 1024 bytes for one PDU since internally CoAP block-wise transfers are
 * used).
 * @param data_len the length of the data.
 * @return coap_pdu_t* the created CoAP PDU.
 * @return NULL in case of an error.
 */
coap_pdu_t* charra_coap_new_request(coap_session_t* session,
	coap_message_t msg_type, coap_request_t method, coap_optlist_t** options,
	const uint8_t* data, const size_t data_len);

/**
 * @brief Adds a CoAP resource.
 *
 * @param coap_context the CoAP context.
 * @param method the CoAP request method.
 * @param resource_name the resource name.
 * @param handler the method handler function.
 */
void charra_coap_add_resource(struct coap_context_t* coap_context,
	const coap_request_t method, const char* resource_name,
	const coap_method_handler_t handler);

/**
 * @brief: Setup the dtls_pki structure for DTLS-RPK.
 *
 * @param dtls_pki the strcture to setup
 * @param private_key_path the path of the private key to use
 * @param public_key_path the path of the public key to use
 * @param peer_public_key_path the path of the peers' public key to use
 * @param verify_peer_public_key true if the structure shall be setup to
 * validate the peers' public key, false otherwise
 */
CHARRA_RC charra_coap_setup_dtls_pki_for_rpk(coap_dtls_pki_t* dtls_pki,
	char* private_key_path, char* public_key_path, char* peer_public_key_path,
	bool verify_peer_public_key);

/**
 * @brief Parses the libcoap log level from string and writes the result into
 * variable log_level. In case of an parsing error nothing is written and the
 * function returns -1.
 *
 * @param[in] log_level_str the libcoap log level string.
 * @param[out] log_level the variable into which the log level is written.
 * @return 0 on success, -1 on error.
 */
int charra_coap_log_level_from_str(
	const char* log_level_str, coap_log_t* log_level);

/**
 * @brief Returns the string representation of a CoAP request method.
 *
 * @param method the CoAP request method.
 * @return const char* the string representation of a CoAP request method.
 */
const char* charra_coap_method_to_str(const coap_request_t method);

#endif /* COAP_UTIL_H */
