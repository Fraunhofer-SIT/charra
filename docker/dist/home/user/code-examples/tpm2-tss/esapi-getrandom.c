/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ******************************************************************************/

/**
 * @brief Demonstrates the usage of the tpm2-tss Enhanced System API (ESAPI).
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @version 1.0
 * @date 2023-11-21
 * @copyright Copyright 2023, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_esys.h>

#define DEFAULT_RANDOM_LEN 20

int main(int argc, char *argv[]) {
    ESYS_CONTEXT* ctx = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* read CLI argument */
    const size_t randomLen = argc > 1 ? atoi(argv[1]) : DEFAULT_RANDOM_LEN;

    /* initialize ESAPI */
    if ((r = Esys_Initialize(&ctx, NULL, NULL)) != TSS2_RC_SUCCESS) {
        printf("Error: Esys_Initialize\n");
        goto hellnfry;
    }

    /* produce random numbers */
    TPM2B_DIGEST* randomBytes = NULL;
    if ((r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            randomLen, &randomBytes)) != TSS2_RC_SUCCESS) {
        printf("Error: Esys_GetRandom\n");
        goto hellnfry;
    }

    /* print random bytes in hex */
    for (uint16_t i = 0; i < randomBytes->size; ++i) {
        printf("%02x", randomBytes->buffer[i]);
    }
    printf("\n");

hellnfry:
    /* clean up */
    if (randomBytes != NULL) {
        Esys_Free(randomBytes);
    }
    Esys_Finalize(&ctx);

    /* exit program */
    return (r == TSS2_RC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
