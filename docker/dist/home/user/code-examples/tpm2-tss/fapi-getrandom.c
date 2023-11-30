/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ******************************************************************************/

/**
 * @brief Demonstrates the usage of the tpm2-tss Feature API (FAPI).
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
#include <tss2/tss2_fapi.h>

#define DEFAULT_RANDOM_LEN 20

int main(int argc, char *argv[]) {
    FAPI_CONTEXT *ctx = NULL;
    TSS2_RC r = TSS2_RC_SUCCESS;

    /* read CLI argument */
    const size_t randomLen = argc > 1 ? atoi(argv[1]) : DEFAULT_RANDOM_LEN;

    /* initialize FAPI */
    if ((r = Fapi_Initialize(&ctx, NULL)) != TSS2_RC_SUCCESS) {
        printf("Error: Fapi_Initialize\n");
        goto hellnfry;
    }

    /* provision FAPI (must only be done once) */
    r = Fapi_Provision(ctx, NULL, NULL, NULL);
    switch (r) {
    case TSS2_RC_SUCCESS:
        /* FAPI successfully provisioned */
        break;
    case TSS2_BASE_RC_ALREADY_PROVISIONED:
        /* FALLTHROUGH */
    case TSS2_FAPI_RC_ALREADY_PROVISIONED:
        /* "FAPI already provisioned */
        break;
    default:
        printf("Error: Fapi_Provision\n");
        goto hellnfry;
    }

    /* produce random numbers */
    uint8_t* randomBytes = NULL;
    if ((r = Fapi_GetRandom(ctx, randomLen, &randomBytes)) != TSS2_RC_SUCCESS) {
        printf("Error: Fapi_GetRandom\n");
        goto hellnfry;
    }

    /* print random bytes in hex */
    for (size_t i = 0; i < randomLen; ++i) {
        printf("%02x", randomBytes[i]);
    }
    printf("\n");

hellnfry:
    /* clean up */
    if (randomBytes != NULL) {
        Fapi_Free(randomBytes);
    }
    Fapi_Finalize(&ctx);

    /* exit program */
    return (r == TSS2_RC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
