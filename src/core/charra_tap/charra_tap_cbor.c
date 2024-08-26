/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_tap_cbor.c
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

#include <assert.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../common/charra_log.h"
#include "../../common/charra_macro.h"
#include "charra_tap_cbor.h"
#include "charra_tap_dto.h"
#include "charra_tap_types.h"

static CHARRA_RC charra_tap_attestation_request_internal(
        const charra_tap_msg_attestation_request_dto* attestation_request,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    /* verify input */
    assert(attestation_request != NULL);
    assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
    assert(attestation_request->pcr_selections != NULL);
    assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
    assert(attestation_request->pcr_selections->pcrs != NULL);
    assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
    assert(attestation_request->nonce != NULL);

    QCBOREncodeContext ec = {0};

    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "hello" */
    QCBOREncode_AddBool(&ec, attestation_request->hello);

    /* encode "key-id" */
    UsefulBufC key_id = {attestation_request->sig_key_id,
            attestation_request->sig_key_id_len};
    QCBOREncode_AddBytes(&ec, key_id);

    /* encode "nonce" */
    UsefulBufC nonce = {
            attestation_request->nonce, attestation_request->nonce_len};
    QCBOREncode_AddBytes(&ec, nonce);

    /* encode "pcr-selections" */
    QCBOREncode_OpenArray(&ec);
    for (uint32_t i = 0; i < attestation_request->pcr_selections_len; ++i) {
        QCBOREncode_OpenArray(&ec);
        QCBOREncode_AddInt64(
                &ec, attestation_request->pcr_selections[i].tcg_hash_alg_id);
        {
            /* open array: pcrs_array_encoder */
            QCBOREncode_OpenArray(&ec);
            for (uint32_t j = 0;
                    j < attestation_request->pcr_selections[i].pcrs_len; ++j) {
                QCBOREncode_AddUInt64(
                        &ec, attestation_request->pcr_selections[i].pcrs[j]);
            }
            /* close array: pcrs_array_encoder */
            QCBOREncode_CloseArray(&ec);
        }
        /* close array: pcr_selection_array_encoder */
        QCBOREncode_CloseArray(&ec);
    }

    /* close array: pcr_selections_array_encoder */
    QCBOREncode_CloseArray(&ec);

    /* encode pcr-log requests */
    QCBOREncode_OpenArray(&ec);
    for (uint32_t i = 0; i < attestation_request->pcr_log_len; ++i) {
        /* open array: pcr-log */
        QCBOREncode_OpenArray(&ec);
        /* pcr-log identifier */
        UsefulBufC identifier = {attestation_request->pcr_logs[i].identifier,
                strlen(attestation_request->pcr_logs[i].identifier) + 1};
        QCBOREncode_AddText(&ec, identifier);
        /* pcr-log start */
        QCBOREncode_AddUInt64(&ec, attestation_request->pcr_logs[i].start);
        /* pcr-log count */
        QCBOREncode_AddUInt64(&ec, attestation_request->pcr_logs[i].count);
        /* close array: pcr-log */
        QCBOREncode_CloseArray(&ec);
    }
    QCBOREncode_CloseArray(&ec);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

static CHARRA_RC charra_tap_attestation_request_size(
        const charra_tap_msg_attestation_request_dto* attestation_request,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* passing this buffer instructs QCBOR to return only the size and do no
     * actual encoding */
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_tap_attestation_request_internal(
                 attestation_request, buf_in, &buf_out)) == CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_tap_marshal_attestation_request(
        const charra_tap_msg_attestation_request_dto* attestation_request,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);
    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* verify input */
    assert(attestation_request != NULL);
    assert(attestation_request->pcr_selections_len <= TPM2_NUM_PCR_BANKS);
    assert(attestation_request->pcr_selections != NULL);
    assert(attestation_request->pcr_selections->pcrs_len <= TPM2_MAX_PCRS);
    assert(attestation_request->pcr_selections->pcrs != NULL);
    assert(attestation_request->nonce_len <= sizeof(TPMU_HA));
    assert(attestation_request->nonce != NULL);
    assert(attestation_request->pcr_log_len <= SUPPORTED_PCR_LOGS_COUNT);
    assert(attestation_request->pcr_logs != NULL);

    /* compute size of marshaled data */
    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_tap_attestation_request_size(
                 attestation_request, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }
    charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

    /* allocate buffer size */
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

    /* encode */
    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_tap_attestation_request_internal(
                 attestation_request, buf_in, &buf_out)) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    /* set output parameters */
    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_tap_unmarshal_attestation_request(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        charra_tap_msg_attestation_request_dto* attestation_request) {
    charra_tap_msg_attestation_request_dto req = {0};
    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};
    UsefulBufC item_str_buf = {0};

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    /* parse root array */
    QCBORDecode_EnterArray(&dc, &item);

    /* parse "hello" (bool) */
    QCBORDecode_GetBool(&dc, &(req.hello));

    /* parse "key-id" (bytes) */
    QCBORDecode_GetByteString(&dc, &item_str_buf);
    req.sig_key_id_len = item_str_buf.len;
    memcpy(&(req.sig_key_id), item_str_buf.ptr, req.sig_key_id_len);

    /* parse "nonce" (bytes) */
    QCBORDecode_GetByteString(&dc, &item_str_buf);
    req.nonce_len = item_str_buf.len;
    memcpy(&(req.nonce), item_str_buf.ptr, req.nonce_len);

    /* parse array "pcr-selections" */
    QCBORDecode_EnterArray(&dc, &item);

    /* initialize array and array length */
    req.pcr_selections_len = (uint32_t)item.val.uCount;

    /* go through all elements */
    for (uint32_t i = 0; i < req.pcr_selections_len; ++i) {
        /* parse array "pcr-selection" */
        QCBORDecode_EnterArray(&dc, &item);

        /* parse "tcg-hash-alg-id" (UINT16) */
        int64_t int_val = 0;
        QCBORDecode_GetInt64(&dc, &int_val);
        req.pcr_selections[i].tcg_hash_alg_id = (uint16_t)int_val;

        /* parse array "pcrs" */
        QCBORDecode_EnterArray(&dc, &item);

        /* initialize array and array length */
        req.pcr_selections[i].pcrs_len = (uint32_t)item.val.uCount;

        /* go through all elements */
        for (uint32_t j = 0; j < req.pcr_selections[i].pcrs_len; ++j) {
            QCBORDecode_GetInt64(&dc, &int_val);
            req.pcr_selections[i].pcrs[j] = (uint8_t)int_val;
        }

        /* exit array "pcrs" */
        QCBORDecode_ExitArray(&dc);

        /* exit array "pcr-selection" */
        QCBORDecode_ExitArray(&dc);
    }

    /*  exit array "pcr-selections" */
    QCBORDecode_ExitArray(&dc);

    /* parse pcr-log requests */
    QCBORDecode_EnterArray(&dc, &item);
    uint32_t pcr_log_count = (uint32_t)item.val.uCount;
    req.pcr_log_len = pcr_log_count;
    req.pcr_logs = calloc(pcr_log_count, sizeof(pcr_log_dto));

    for (uint32_t i = 0; i < pcr_log_count; ++i) {
        /* parse array "pcr-log" */
        QCBORDecode_EnterArray(&dc, &item);

        /* parse pcr-log identifier */
        QCBORDecode_GetTextString(&dc, &item_str_buf);

        uint64_t start = 0;
        uint64_t count = 0;

        /* parse pcr-log start */
        QCBORDecode_GetUInt64(&dc, &start);

        /* parse pcr-log count */
        QCBORDecode_GetUInt64(&dc, &count);

        /* exit array "pcr-log" */
        QCBORDecode_ExitArray(&dc);

        req.pcr_logs[i].identifier = calloc(item_str_buf.len + 1, 1);
        memcpy(req.pcr_logs[i].identifier, item_str_buf.ptr, item_str_buf.len);
        req.pcr_logs[i].start = start;
        req.pcr_logs[i].count = count;
    }
    QCBORDecode_ExitArray(&dc);

    /* exit root array */
    QCBORDecode_ExitArray(&dc);

    /* expect end of CBOR data */
    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    /* set output */
    *attestation_request = req;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    return CHARRA_RC_MARSHALING_ERROR;
}

static CHARRA_RC charra_tap_marshal_attestation_response_internal(
        const charra_tap_msg_attestation_response_dto* attestation_response,
        UsefulBuf buf_in, UsefulBufC* buf_out) {
    charra_log_trace("<ENTER> %s()", __func__);

    /* verify input */
    assert(attestation_response != NULL);
    assert(attestation_response->tpm2_quote.attestation_data != NULL);
    assert(attestation_response->tpm2_quote.tpm2_signature != NULL);

    QCBOREncodeContext ec = {0};

    QCBOREncode_Init(&ec, buf_in);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* array tpm2_quote */
    QCBOREncode_OpenArray(&ec);

    /* encode information element identifier */
    QCBOREncode_AddUInt64(&ec, CHARRA_TAP_IE_PCR_ATTESTATION);

    /* encode attestation subtype */
    QCBOREncode_AddUInt64(&ec, CHARRA_TAP_ATTESTATION_TPM2_QUOTE);

    /* encode "attestation-data" */
    UsefulBufC attestation_data = {
            .ptr = attestation_response->tpm2_quote.attestation_data,
            .len = attestation_response->tpm2_quote.attestation_data_len};
    QCBOREncode_AddBytes(&ec, attestation_data);

    /* encode "tpm2-signature" */
    UsefulBufC tpm2_signature = {
            .ptr = attestation_response->tpm2_quote.tpm2_signature,
            .len = attestation_response->tpm2_quote.tpm2_signature_len};
    QCBOREncode_AddBytes(&ec, tpm2_signature);

    /* close array: tpm2_quote */
    QCBOREncode_CloseArray(&ec);

    /* array pcr-logs */
    QCBOREncode_OpenArray(&ec);

    for (uint32_t i = 0; i < attestation_response->pcr_log_len; ++i) {
        /* array pcr-log */
        QCBOREncode_OpenArray(&ec);

        /* encode information element identifier */
        QCBOREncode_AddUInt64(&ec, CHARRA_TAP_IE_PCR_LOG);

        /* encode identifier */
        UsefulBufC identifier = {
                .ptr = attestation_response->pcr_logs[i].identifier,
                .len = strlen(attestation_response->pcr_logs[i].identifier)};
        QCBOREncode_AddText(&ec, identifier);

        /* encode start */
        QCBOREncode_AddUInt64(&ec, attestation_response->pcr_logs[i].start);

        /* encode count */
        QCBOREncode_AddUInt64(&ec, attestation_response->pcr_logs[i].count);

        /* encode content */
        UsefulBufC content = {.ptr = attestation_response->pcr_logs[i].content,
                .len = attestation_response->pcr_logs[i].content_len};
        QCBOREncode_AddBytes(&ec, content);

        /* close array: pcr-log */
        QCBOREncode_CloseArray(&ec);
    }

    /* close array: pcr-logs */
    QCBOREncode_CloseArray(&ec);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
        return CHARRA_RC_SUCCESS;
    } else {
        return CHARRA_RC_MARSHALING_ERROR;
    }
}

CHARRA_RC charra_tap_marshal_attestation_response_size(
        const charra_tap_msg_attestation_response_dto* attestation_response,
        size_t* marshaled_data_len) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* passing this buffer instructs QCBOR to return only the size and do no
     * actual encoding */
    UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
    UsefulBufC buf_out = {0};

    if ((charra_r = charra_tap_marshal_attestation_response_internal(
                 attestation_response, buf_in, &buf_out)) ==
            CHARRA_RC_SUCCESS) {
        *marshaled_data_len = buf_out.len;
    }

    return charra_r;
}

CHARRA_RC charra_tap_marshal_attestation_response(
        const charra_tap_msg_attestation_response_dto* attestation_response,
        uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
    charra_log_trace("<ENTER> %s()", __func__);

    CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

    /* verify input */
    assert(attestation_response != NULL);
    assert(attestation_response->tpm2_quote.attestation_data != NULL);
    assert(attestation_response->tpm2_quote.tpm2_signature != NULL);

    /* compute size of marshaled data */
    UsefulBuf buf_in = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_tap_marshal_attestation_response_size(
                 attestation_response, &(buf_in.len))) != CHARRA_RC_SUCCESS) {
        charra_log_error("Could not compute size of marshaled data.");
        return charra_r;
    }
    charra_log_debug("Size of marshaled data is %zu bytes.", buf_in.len);

    /* allocate buffer size */
    if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
        charra_log_error("Allocating %zu bytes of memory failed.", buf_in.len);
        return CHARRA_RC_MARSHALING_ERROR;
    }
    charra_log_debug("Allocated %zu bytes of memory.", buf_in.len);

    /* encode */
    UsefulBufC buf_out = {.len = 0, .ptr = NULL};
    if ((charra_r = charra_tap_marshal_attestation_response_internal(
                 attestation_response, buf_in, &buf_out)) !=
            CHARRA_RC_SUCCESS) {
        charra_log_error("Could not marshal data.");
        return charra_r;
    }

    /* set output parameters */
    *marshaled_data_len = buf_out.len;
    *marshaled_data = (uint8_t*)buf_out.ptr;

    return charra_r;
}

CHARRA_RC charra_tap_unmarshal_attestation_response(
        const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
        charra_tap_msg_attestation_response_dto* attestation_response) {
    charra_tap_msg_attestation_response_dto res = {0};
    QCBORError cborerr = QCBOR_SUCCESS;
    UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
    QCBORDecodeContext dc = {0};
    QCBORItem item = {0};
    UsefulBufC item_str_buf = {0};
    uint64_t ie_identifier = 0;
    uint64_t log_ie_identifier = 0;
    uint64_t attestation_subtype = 0;

    QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

    /* parse root array */
    QCBORDecode_EnterArray(&dc, &item);

    /* parse tpm2-quote array */
    QCBORDecode_EnterArray(&dc, &item);

    /* parse information element identifier */
    QCBORDecode_GetUInt64(&dc, &ie_identifier);

    /* parse attestation subtype */
    QCBORDecode_GetUInt64(&dc, &attestation_subtype);

    /* parse "attestation-data" (bytes) */
    QCBORDecode_GetByteString(&dc, &item_str_buf);
    res.tpm2_quote.attestation_data_len = item_str_buf.len;
    memcpy(&(res.tpm2_quote.attestation_data), item_str_buf.ptr,
            res.tpm2_quote.attestation_data_len);

    /* parse "tpm2-signature" (bytes) */
    QCBORDecode_GetByteString(&dc, &item_str_buf);
    res.tpm2_quote.tpm2_signature_len = item_str_buf.len;
    memcpy(&(res.tpm2_quote.tpm2_signature), item_str_buf.ptr,
            res.tpm2_quote.tpm2_signature_len);

    /* exit tpm2_quote array */
    QCBORDecode_ExitArray(&dc);

    /* parse array pcr-logs */
    QCBORDecode_EnterArray(&dc, &item);
    res.pcr_log_len = item.val.uCount;
    res.pcr_logs = calloc(res.pcr_log_len, sizeof(pcr_log_response_dto));
    for (uint32_t i = 0; i < res.pcr_log_len; ++i) {
        /* parse array pcr-log */
        QCBORDecode_EnterArray(&dc, &item);

        /* parse information element identifier */
        QCBORDecode_GetUInt64(&dc, &log_ie_identifier);
        if (log_ie_identifier != CHARRA_TAP_IE_PCR_LOG) {
            goto cbor_parse_error;
        }

        /* parse identifier */
        QCBORDecode_GetTextString(&dc, &item_str_buf);
        res.pcr_logs[i].identifier = calloc(item_str_buf.len + 1, 1);
        if (res.pcr_logs[i].identifier == NULL) {
            goto cbor_parse_error;
        }
        memcpy(res.pcr_logs[i].identifier, item_str_buf.ptr, item_str_buf.len);

        /* parse start */
        QCBORDecode_GetUInt64(&dc, &(res.pcr_logs[i].start));

        /* parse count */
        QCBORDecode_GetUInt64(&dc, &(res.pcr_logs[i].count));

        /* parse content */
        QCBORDecode_GetByteString(&dc, &item_str_buf);
        res.pcr_logs[i].content_len = item_str_buf.len;
        res.pcr_logs[i].content = malloc(item_str_buf.len);
        if (res.pcr_logs[i].content == NULL) {
            goto cbor_parse_error;
        }
        memcpy(res.pcr_logs[i].content, item_str_buf.ptr, item_str_buf.len);

        /* exit array pcr-log */
        QCBORDecode_ExitArray(&dc);
    }

    /* exit array pcr-logs */
    QCBORDecode_ExitArray(&dc);

    /* exit root array */
    QCBORDecode_ExitArray(&dc);

    if ((cborerr = QCBORDecode_Finish(&dc))) {
        charra_log_error("CBOR parser: expected end of input, but could not "
                         "find it. Continuing.");
        goto cbor_parse_error;
    }

    if (ie_identifier != CHARRA_TAP_IE_PCR_ATTESTATION) {
        cborerr = CHARRA_RC_MARSHALING_ERROR;
        charra_log_error("CBOR parser: unexpected information element "
                         "identifier: 0x%02x",
                (uint8_t)ie_identifier);
        goto cbor_parse_error;
    }

    if (attestation_subtype != CHARRA_TAP_ATTESTATION_TPM2_QUOTE) {
        cborerr = CHARRA_RC_MARSHALING_ERROR;
        charra_log_error("CBOR parser: unexpected attestation subtype: 0x%02x",
                (uint8_t)attestation_subtype);
        goto cbor_parse_error;
    }

    /* set output */
    *attestation_response = res;

    return CHARRA_RC_SUCCESS;

cbor_parse_error:
    charra_log_error("CBOR parser: %s", qcbor_err_to_str(cborerr));
    charra_log_info("CBOR parser: skipping parsing.");

    return CHARRA_RC_MARSHALING_ERROR;
}
