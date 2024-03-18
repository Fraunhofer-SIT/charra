/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file tpm2_tools_util.h
 * @author Markus Horn (markus.horn@sit.fraunhofer.de)
 * @author tpm2-software/tpm2-tools
 * (https://github.com/tpm2-software/tpm2-tools)
 * @brief The source code utilized in this file has been adapted and modified
 * from the tpm2-software/tpm2-tools github repository
 * (https://github.com/tpm2-software/tpm2-tools)
 * @version 0.1
 * @date 2024-03-18
 *
 * @copyright Copyright 2024, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef TPM2_TOOLS_UTIL_H
#define TPM2_TOOLS_UTIL_H

#include <stdbool.h>
#include <stdio.h>

#include <tss2/tss2_esys.h>

#include "../common/charra_error.h"

/**
 * Retrieves a files size given from an already opened FILE object.
 * @param fp
 *  The file pointer to query the size of.
 * @param file_size
 *  Output of the file size.
 * @param path
 *  An optional path used for error reporting, a NULL path disables error
 * logging.
 * @return
 *  True on success, False otherwise.
 */
bool tpm2_tools_util_get_file_size(
        FILE* fp, unsigned long* file_size, const char* path);

/**
 * Reads a TPM2.0 header from a file.
 * @param f
 *  The file to read.
 * @param version
 *  The version that was found.
 * @return
 *  True on Success, False on error.
 */
bool tpm2_tools_util_read_header(FILE* f, UINT32* version);

/**
 * Reads a 16 bit value from a file converting from big endian to host
 * endianess.
 * @param out
 *  The file to read from.
 * @param data
 *  The data that is read, valid on a true return.
 * @return
 *  True on success, False on error.
 */
bool tpm2_tools_util_read_16(FILE* out, UINT16* data);

/**
 * Same as tpm2_tools_util_read_16 but for 32 bit values.
 */
bool tpm2_tools_util_read_32(FILE* out, UINT32* data);

/**
 * Same as tpm2_tools_util_read_16 but for 64 bit values.
 */
bool tpm2_tools_util_read_64(FILE* out, UINT64* data);

/**
 * Reads len bytes from a file.
 * @param out
 *  The file to read from.
 * @param data
 *  The buffer to read into, only valid on a True return.
 * @param size
 *  The number of bytes to read.
 * @return
 *  True on success, False otherwise.
 */
bool tpm2_tools_util_read_bytes(FILE* out, UINT8 data[], size_t size);

/**
 * Like tpm2_tools_util_load_tpm_context_from_path() but loads the context from
 * a FILE stream.
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param tr_handle
 *  Optional. The Esys handle for the TPM2 object
 * @param fstream
 *  The FILE stream to read from.
 * @return
 *  TSS2_RC status indicating success.
 */
TSS2_RC tpm2_tools_util_load_tpm_context_from_file(
        ESYS_CONTEXT* context, ESYS_TR* tr_handle, FILE* fstream);

/**
 * Loads a TPM2B_PUBLIC from disk that was saved with tpm2_createak.
 * @param path
 *  The path to load from.
 * @param public
 *  The TPM2B_PUBLIC to load.
 * @return
 *  true on success, false on error.
 */
bool tpm2_tools_util_load_public(const char* path, TPM2B_PUBLIC* public);

#endif /* TPM2_TOOLS_UTIL_H */
