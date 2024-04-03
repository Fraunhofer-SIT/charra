/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_tap_types.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2024-03-18
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CHARRA_TAP_TYPES_H
#define CHARRA_TAP_TYPES_H

#include <stdint.h>

/**
 * @brief Defines TAP information element identifier
 * @see
 * <https://trustedcomputinggroup.org/wp-content/uploads/TNC_TAP_Information_Model_v1.00_r0.36-FINAL.pdf#page=9>
 *
 */
typedef enum charra_tap_ie_identifier_t {
    /**
     * @brief TAP Information Model Specification Version
     *
     */
    CHARRA_TAP_IE_VERSION = (uint8_t)0x00,

    /**
     * @brief AK certificate
     *
     */
    CHARRA_TAP_IE_AK_CERTIFICATE = (uint8_t)0x01,

    /**
     * @brief Attestation of a TPM 2.0 signing key for implicit attestation
     *
     */
    CHARRA_TAP_IE_TPM_2_0_SK_ATTESTATION = (uint8_t)0x02,

    /**
     * @brief PCRs and their values for TPM 1.2
     *
     */
    CHARRA_TAP_IE_TPM_1_2_PCR = (uint8_t)0x03,

    /**
     * @brief PCRs and their values for TPM 2.0
     *
     */
    CHARRA_TAP_IE_TPM_2_0_PCR = (uint8_t)0x04,

    /**
     * @brief PCR log values
     *
     */
    CHARRA_TAP_IE_PCR_LOG = (uint8_t)0x05,

    /**
     * @brief Freshness attestation element
     *
     */
    CHARRA_TAP_IE_FRESHNESS_ATTESTATION = (uint8_t)0x06,

    /**
     * @brief Nonce qualification information
     *
     */
    CHARRA_TAP_IE_NONCE = (uint8_t)0x07,

    /**
     * @brief TPM 2.0 Clock Time Certification
     *
     */
    CHARRA_TAP_IE_TPM_2_0_CLOCK_TIME_CERTIFICATION = (uint8_t)0x08,

    /**
     * @brief PCR attestation element
     *
     */
    CHARRA_TAP_IE_PCR_ATTESTATION = (uint8_t)0x09,

    /**
     * @brief Signature using Signing Key
     *
     */
    CHARRA_TAP_IE_SIGNATURE = (uint8_t)0x0A,

    /**
     * @brief Previous Hibernation Report
     *
     */
    CHARRA_TAP_IE_PREVIOUS_HIBERNATION = (uint8_t)0x0B,

    /**
     * @brief Supplementary Log Report
     *
     */
    CHARRA_TAP_IE_SUPPLEMENTARY_LOG = (uint8_t)0x0C,

    /**
     * @brief Attestation of a DICE signing key for implicit attestation
     *
     */
    CHARRA_TAP_IE_DICE_SK_ATTESTATION = (uint8_t)0x0D,

} charra_tap_ie_identifier_t;

/**
 * @brief Defines TAP Freshness of Attestation
 * @see
 * <https://trustedcomputinggroup.org/wp-content/uploads/TNC_TAP_Information_Model_v1.00_r0.36-FINAL.pdf#page=13>
 *
 */
typedef enum charra_tap_freshness_indicator_t {
    /**
     * @brief A nonce provided by the Verifier is included in the attestation.
     * This freshness element indicator is followed by 2 BYTES indicating the
     * nonce size, followed by the nonce.
     *
     */
    CHARRA_TAP_FRESHNESS_NONCE_VERIFIER = (uint16_t)0x0000,

    /**
     * @brief A nonce provided by a trusted third party is included in the
     * attestation.This freshness indicator is followed by 2 BYTES indicating
     * the nonce size, followed by the nonce.
     *
     * If this freshness indicator is used, then proof of provenance of the
     * nonce MUST be provided as in section 4.9.
     *
     */
    CHARRA_TAP_FRESHNESS_NONCE_3RD_PARTY = (uint16_t)0x0001,

    /**
     * @brief Proof of freshness is derived from the TPM clock value which is
     * part of the signed data
     *
     * If this freshness element indicator is used, then proof that TPM Clock
     * can be relied upon MUST be provided as in section 4.10.
     *
     */
    CHARRA_TAP_FRESHNESS_TPM_CLOCK = (uint16_t)0x0002,

} charra_tap_freshness_indicator_t;

/**
 * @brief Defines TAP Nonce Qualification Information
 * @see
 * <https://trustedcomputinggroup.org/wp-content/uploads/TNC_TAP_Information_Model_v1.00_r0.36-FINAL.pdf#page=14>
 *
 */
typedef enum charra_tap_nonce_qualification_information_t {
    /**
     * @brief The nonce is the hash of a time stamp. The qualification number is
     * followed by the time stamp.
     *
     */
    CHARRA_TAP_NONCE_QUALIFICATION_TIME_STAMP = (uint16_t)0x0000,

    /**
     * @brief The qualification information refers to a URL and time from which
     * the nonce was obtained. The qualification number is followed by a
     * representation of the URL and a representation of a time.
     *
     * The URL is represented as 2 bytes for the size of the URL, followed by
     * the URL.
     *
     * The time is represented as 64 bytes representing the number of
     * seconds since 0000:00 Coordinated Universal Time (UTC), Thursday, 1
     * January 1970.
     *
     */
    CHARRA_TAP_NONCE_QUALIFICATION_URL = (uint16_t)0x0001,

} charra_tap_nonce_qualification_information_t;

/**
 * @brief Defines TAP Explicit Attestation Subtype
 * @see
 * <https://trustedcomputinggroup.org/wp-content/uploads/TNC_TAP_Information_Model_v1.00_r0.36-FINAL.pdf#page=17>
 *
 */
typedef enum charra_tap_attestation_subtype_t {
    /**
     * @brief Explicit Attestation using TPM_Quote (TPM Family: 1.2)
     *
     */
    CHARRA_TAP_ATTESTATION_TPM_QUOTE = (uint8_t)0x00,

    /**
     * @brief Explicit Attestation using TPM_Quote2 (TPM Family: 1.2)
     *
     */
    CHARRA_TAP_ATTESTATION_TPM_QUOTE2 = (uint8_t)0x01,

    /**
     * @brief Explicit Attestation using Audit Session and Nonce (TPM
     * Family: 2.0)
     *
     */
    CHARRA_TAP_ATTESTATION_AUDIT_AND_NONCE = (uint8_t)0x02,

    /**
     * @brief Explicit Attestation using Audit Session and Clock (TPM
     * Family: 2.0)
     *
     */
    CHARRA_TAP_ATTESTATION_AUDIT_AND_CLOCK = (uint8_t)0x03,

    /**
     * @brief Explicit Attestation using TPM2_Quote (TPM Family: 2.0)
     *
     */
    CHARRA_TAP_ATTESTATION_TPM2_QUOTE = (uint8_t)0x04,

} charra_tap_attestation_subtype_t;

#endif /* CHARRA_TAP_TYPES_H */
