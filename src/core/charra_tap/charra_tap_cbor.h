/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_tap_cbor.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
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

#ifndef CHARRA_TAP_CBOR_H
#define CHARRA_TAP_CBOR_H

#include "../../common/charra_error.h"
#include "../charra_dto.h"
#include "charra_tap_dto.h"

/**
 * @brief Marshals an attestation request DTO.
 *
 * @param attestation_request[in] The attestation request DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_tap_marshal_attestation_request(
        const msg_attestation_request_dto* attestation_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an attestation request DTO.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param attestation_request[out] The attestation request DTO.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_tap_unmarshal_attestation_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        msg_attestation_request_dto* attestation_request);

/**
 * @brief Marshals an attestation response DTO.
 *
 * @param attestation_response[in] The attestation response DTO.
 * @param marshaled_data_len[out] The length of the marshaled data.
 * @param marshaled_data[out] The marshaled data.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_tap_marshal_attestation_response(
        const charra_tap_msg_attestation_response_dto* attestation_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data);

/**
 * @brief Unmarshals an attestation response DTO.
 *
 * @param marshaled_data_len[in] The length of the marshaled data.
 * @param marshaled_data[in] The marshaled data.
 * @param attestation_response[out] The attestation response DTO.
 * @return CHARRA_RC_SUCCESS on success.
 * @return CHARRA_RC_ERROR on error.
 */
CHARRA_RC charra_tap_unmarshal_attestation_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        charra_tap_msg_attestation_response_dto* attestation_response);

#endif /* CHARRA_TAP_CBOR_H */
