/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2024, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file tpm2_tools_util.c
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

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../common/charra_log.h"
#include "tpm2_tools_util.h"
#include "tss2/tss2_mu.h"

static TSS2_RC tpm2_tools_util_tr_deserialize(ESYS_CONTEXT* esys_context,
        uint8_t const* buffer, size_t buffer_size, ESYS_TR* esys_handle) {

    TSS2_RC rval =
            Esys_TR_Deserialize(esys_context, buffer, buffer_size, esys_handle);
    if (rval != TSS2_RC_SUCCESS) {
        charra_log_error("Esys_TR_Deserialize %d", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

#define STRING_BYTES_ENDIAN_CONVERT(size)                                      \
    UINT##size tpm2_tools_util_endian_swap_##size(UINT##size data) {           \
                                                                               \
        UINT##size converted;                                                  \
        UINT8* bytes = (UINT8*)&data;                                          \
        UINT8* tmp = (UINT8*)&converted;                                       \
                                                                               \
        size_t i;                                                              \
        for (i = 0; i < sizeof(UINT##size); i++) {                             \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1];                        \
        }                                                                      \
                                                                               \
        return converted;                                                      \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)
STRING_BYTES_ENDIAN_CONVERT(64)

static TSS2_RC tpm2_tools_util_context_load(ESYS_CONTEXT* esys_context,
        const TPMS_CONTEXT* context, ESYS_TR* loaded_handle) {

    TSS2_RC rval = Esys_ContextLoad(esys_context, context, loaded_handle);
    if (rval != TSS2_RC_SUCCESS) {
        charra_log_error("Esys_ContextLoad: %d", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

/**
 * Checks if the host is big endian
 * @return
 *  True of the host is big endian false otherwise.
 */
static bool tpm2_tools_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t* test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t*)(&test_word);

    return test_byte[0] == 0xFF;
}

/**
 * This is the magic for the file header. The header is organized
 * as a big endian U32 (BEU32) of MAGIC followed by a BEU32 of the
 * version number. Tools can define their own, individual file
 * formats as they make sense, but they should always have the header.
 */
static const UINT32 MAGIC = 0xBADCC0DE;

#define BAIL_ON_NULL(param, x)                                                 \
    do {                                                                       \
        if (!x) {                                                              \
            charra_log_error(param " must be specified");                      \
            return false;                                                      \
        }                                                                      \
    } while (0)

/**
 * Reads size bytes from a file, continuing on EINTR short reads.
 * @param f
 *  The file to read from.
 * @param data
 *  The data buffer to read into.
 * @param size
 *  The size of the buffer, which is also the amount of bytes to read.
 * @return
 *  The number of bytes that have been read.
 */
static size_t readx(FILE* f, UINT8* data, size_t size) {

    size_t bread = 0;
    do {
        bread += fread(&data[bread], 1, size - bread, f);
    } while (bread < size && !feof(f) && errno == EINTR);

    return bread;
}

bool tpm2_tools_util_get_file_size(
        FILE* fp, unsigned long* file_size, const char* path) {

    long current = ftell(fp);
    if (current < 0) {
        if (path) {
            charra_log_error(
                    "Error getting current file offset for file \"%s\" error: "
                    "%s",
                    path, strerror(errno));
        }
        return false;
    }

    int rc = fseek(fp, 0, SEEK_END);
    if (rc < 0) {
        if (path) {
            charra_log_error("Error seeking to end of file \"%s\" error: %s",
                    path, strerror(errno));
        }
        return false;
    }

    long size = ftell(fp);
    if (size < 0) {
        if (path) {
            charra_log_error(
                    "ftell on file \"%s\" failed: %s", path, strerror(errno));
        }
        return false;
    }

    rc = fseek(fp, current, SEEK_SET);
    if (rc < 0) {
        if (path) {
            charra_log_error(
                    "Could not restore initial stream position for file \"%s\" "
                    "failed: %s",
                    path, strerror(errno));
        }
        return false;
    }

    /* size cannot be negative at this point */
    *file_size = (unsigned long)size;
    return true;
}

/*
 * Current version to write TPMS_CONTEXT to disk.
 */
#define CONTEXT_VERSION 1

static bool tpm2_tools_util_load_tpm_context_file(
        FILE* fstream, TPMS_CONTEXT* context) {

    /*
     * Reading the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hierarchy
     * U32 savedHandle
     * U64 sequence
     * U16 contextBlobLength
     * BYTE[] contextBlob
     */
    UINT32 version;
    bool result = tpm2_tools_util_read_header(fstream, &version);
    if (!result) {
        charra_log_warn(
                "The loaded tpm context does not appear to be in the proper "
                "format, assuming old format, this will be converted on the "
                "next save.");
        rewind(fstream);
        result = tpm2_tools_util_read_bytes(
                fstream, (UINT8*)context, sizeof(*context));
        if (!result) {
            charra_log_error("Could not load tpm context file");
            goto out;
        }
        /* Success load the context into the TPM */
        goto out;
    }

    if (version != CONTEXT_VERSION) {
        charra_log_error(
                "Unsupported context file format version found, got: %" PRIu32,
                version);
        result = false;
        goto out;
    }

    result = tpm2_tools_util_read_32(fstream, &context->hierarchy);
    if (!result) {
        charra_log_error("Error reading hierarchy!");
        goto out;
    }

    result = tpm2_tools_util_read_32(fstream, &context->savedHandle);
    if (!result) {
        charra_log_error("Error reading savedHandle!");
        goto out;
    }
    charra_log_trace(
            "load: TPMS_CONTEXT->savedHandle: 0x%x", context->savedHandle);

    result = tpm2_tools_util_read_64(fstream, &context->sequence);
    if (!result) {
        charra_log_error("Error reading sequence!");
        goto out;
    }

    result = tpm2_tools_util_read_16(fstream, &context->contextBlob.size);
    if (!result) {
        charra_log_error("Error reading contextBlob.size!");
        goto out;
    }

    if (context->contextBlob.size > sizeof(context->contextBlob.buffer)) {
        charra_log_error("Size mismatch found on contextBlob, got %" PRIu16
                         " expected "
                         "less than or equal to %zu",
                context->contextBlob.size, sizeof(context->contextBlob.buffer));
        result = false;
        goto out;
    }

    result = tpm2_tools_util_read_bytes(
            fstream, context->contextBlob.buffer, context->contextBlob.size);
    if (!result) {
        charra_log_error("Error reading contextBlob.size!");
        goto out;
    }

out:
    return result;
}

static bool tpm2_tools_util_check_magic(FILE* fstream, bool seek_reset) {

    BAIL_ON_NULL("FILE", fstream);
    UINT32 magic = 0;
    bool res = tpm2_tools_util_read_32(fstream, &magic);
    if (!res) {
        return false;
    }

    bool match = magic == MAGIC;

    if (seek_reset) {
        int rc = fseek(fstream, -sizeof(magic), SEEK_CUR);
        if (rc != 0) {
            charra_log_error("fseek failed: %s", strerror(errno));
            return false;
        }
        return match;
    }

    if (!match) {
        charra_log_error(
                "Found magic 0x%x did not match expected magic of 0x%x!", magic,
                MAGIC);
    }

    return match;
}

TSS2_RC tpm2_tools_util_load_tpm_context_from_file(
        ESYS_CONTEXT* context, ESYS_TR* tr_handle, FILE* fstream) {
    TPMS_CONTEXT tpms_context;
    TSS2_RC rc = TSS2_RC_SUCCESS;

    bool result = tpm2_tools_util_check_magic(fstream, true);
    if (result) {
        charra_log_trace("Assuming tpm context file");
        result = tpm2_tools_util_load_tpm_context_file(fstream, &tpms_context);
        if (!result) {
            charra_log_error("Failed to tpm2_load_tpm_context_file()");
            goto out;
        }

        return tpm2_tools_util_context_load(context, &tpms_context, tr_handle);
    }

    ESYS_TR loaded_handle;
    charra_log_trace("Assuming tpm context file");
    /* try ESYS TR deserialize */
    unsigned long size = 0;
    result = tpm2_tools_util_get_file_size(fstream, &size, NULL);
    if (!result) {
        charra_log_error(
                "Failed to get file size: %s", strerror(ferror(fstream)));
        goto out;
    }

    if (size < 1) {
        charra_log_error("Invalid serialized ESYS_TR size, got: %lu", size);
        goto out;
    }

    uint8_t* buffer = calloc(1, size);
    if (!buffer) {
        charra_log_error("oom");
        goto out;
    }

    result = tpm2_tools_util_read_bytes(fstream, buffer, size);
    if (!result) {
        charra_log_error("Could not read serialized ESYS_TR from disk");
        free(buffer);
        goto out;
    }

    rc = tpm2_tools_util_tr_deserialize(context, buffer, size, &loaded_handle);
    free(buffer);
    if (rc == TSS2_RC_SUCCESS) {
        *tr_handle = loaded_handle;
    }
out:
    return rc;
}

#define BE_CONVERT(value, size)                                                \
    do {                                                                       \
        if (!tpm2_tools_util_is_big_endian()) {                                \
            value = tpm2_tools_util_endian_swap_##size(value);                 \
        }                                                                      \
    } while (0)

#define FILE_READ(size)                                                        \
    bool tpm2_tools_util_read_##size(FILE* out, UINT##size* data) {            \
        BAIL_ON_NULL("FILE", out);                                             \
        BAIL_ON_NULL("data", data);                                            \
        bool res = (readx(out, (UINT8*)data, sizeof(*data)) == sizeof(*data)); \
        if (res) {                                                             \
            BE_CONVERT(*data, size);                                           \
        }                                                                      \
        return res;                                                            \
    }

/*
 * all the tpm2_tools_util_read_bytes_16|32|64 functions
 */
FILE_READ(16)

FILE_READ(32)

FILE_READ(64)

bool tpm2_tools_util_read_bytes(FILE* out, UINT8 bytes[], size_t len) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("bytes", bytes);
    return (readx(out, bytes, len) == len);
}

bool tpm2_tools_util_read_header(FILE* out, uint32_t* version) {

    BAIL_ON_NULL("FILE", out);
    BAIL_ON_NULL("version", version);

    bool result = tpm2_tools_util_check_magic(out, false);
    if (!result) {
        return false;
    }

    return tpm2_tools_util_read_32(out, version);
}

/* load public key */

bool tpm2_tools_util_read_bytes_from_file(
        FILE* f, UINT8* buf, UINT16* size, const char* path) {

    unsigned long file_size;
    bool result = tpm2_tools_util_get_file_size(f, &file_size, path);
    if (!result) {
        /* get_file_size() logs errors */
        return false;
    }

    /* max is bounded on *size */
    if (file_size > *size) {
        if (path) {
            charra_log_error(
                    "File \"%s\" size is larger than buffer, got %lu expected "
                    "less than or equal to %u",
                    path, file_size, *size);
        }
        return false;
    }

    /* The reported file size is not always correct, e.g. for sysfs files
       generated on the fly by the kernel when they are read, which appear as
       having size 0. Read as many bytes as we can until EOF is reached or the
       provided buffer is full. As a small sanity check, fail if the number of
       bytes read is smaller than the reported file size. */
    *size = readx(f, buf, *size);
    if (*size < file_size) {
        if (path) {
            charra_log_error("Could not read data from file \"%s\"", path);
        }
        return false;
    }

    return true;
}

bool tpm2_tools_util_load_bytes_from_path(
        const char* path, UINT8* buf, UINT16* size) {

    if (!buf || !size || !path) {
        return false;
    }

    FILE* f = fopen(path, "rb");
    if (!f) {
        charra_log_error(
                "Could not open file \"%s\" error %s", path, strerror(errno));
        return false;
    }

    bool result = tpm2_tools_util_read_bytes_from_file(f, buf, size, path);

    fclose(f);
    return result;
}

#define xstr(s) str(s)
#define str(s) #s

#define LOAD_TYPE(type, name)                                                  \
    bool tpm2_tools_util_load_##name(const char* path, type* name) {           \
                                                                               \
        UINT8 buffer[sizeof(*name)];                                           \
        UINT16 size = sizeof(buffer);                                          \
        bool res = tpm2_tools_util_load_bytes_from_path(path, buffer, &size);  \
        if (!res) {                                                            \
            return false;                                                      \
        }                                                                      \
                                                                               \
        size_t offset = 0;                                                     \
        TSS2_RC rc = Tss2_MU_##type##_Unmarshal(buffer, size, &offset, name);  \
        if (rc != TSS2_RC_SUCCESS) {                                           \
            charra_log_error(                                                  \
                    "Error deserializing " str(name) " structure: 0x%x", rc);  \
            charra_log_error("The input file needs to be a valid " xstr(       \
                    type) " data structure");                                  \
            return false;                                                      \
        }                                                                      \
                                                                               \
        return rc == TPM2_RC_SUCCESS;                                          \
    }

LOAD_TYPE(TPM2B_PUBLIC, public)
