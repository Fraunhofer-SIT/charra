<!--
################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-05-20T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################
-->

# CHARRA: CHAllenge-Response based Remote Attestation with TPM 2.0

![CHARRA Logo](charra-logo_small.png)

This is a proof-of-concept implementation of the "Challenge/Response Remote Attestation" interaction model of the [IETF RATS](https://datatracker.ietf.org/wg/rats/about/) [Reference Interaction Models for Remote Attestation Procedures](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/) using TPM 2.0. The [IETF Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/) working group standardizes formats for describing assertions/claims about system components and associated evidence; and procedures and protocols to convey these assertions/claims to relying parties. Given the security and privacy sensitive nature of these assertions/claims, the working group specifies approaches to protect this exchanged data.

This proof-of-concept implementation realizes the Attesting Computing Environment—a Computing Environment capable of monitoring and attesting a target Computing Environment—as well as the target Computing Environment itself, as described in the [RATS Architecture](https://datatracker.ietf.org/doc/rfc9334/).

## Quickstart

The following assumes that [Docker](https://docs.docker.com/get-docker/) (and [Docker Compose](https://docs.docker.com/compose/install/)) are installed and configured on your system.
Please see [`INSTALL.md`](INSTALL.md) for details, also for manually building CHARRA.
All commands are to be executed in [Bash](https://www.gnu.org/software/bash/).

For Docker, build the image and run the container with:

    ./docker/build.sh
    ./docker/run.sh

With Docker Compose do:

    docker-compose build --build-arg uid="${UID}" --build-arg gid="${UID}"
    docker-compose run --rm charra-dev-env

Inside the container, change to the `~/charra/` folder, build it, and run it:

    cd ~/charra/
    make -j
    (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester

## How it Works: Protocol Flow

The following diagram shows the protocol flow of the CHARRA attestation process.

    .----------.                                    .----------.
    | Attester |                                    | Verifier |
    '----------'                                    '----------'
         |                                                |
         | <----- requestAttestation(nonce, keyID, pcrSelection)
         |                                                |
    tpmQuote(nonce, pcrSelection)                         |
         | => evidence                                    |
         |                                                |
     evidence ------------------------------------------> |
         |                                                |
         |      appraiseEvidence(evidence, nonce, referencePcrs)
         |                           attestationResult <= |
         |                                                |

## Changelog

You find the changelog in [`CHANGELOG.md`](CHANGELOG.md).

## Next Steps

* Allow verifier to perform periodic attestations, e.g., perform attestation every 10 seconds.
* Refactor and implement forward-declared (but not yet implemented) functions.
* Use non-zero reference PCRs.
* "Extended" *TPM Quote* using TPM audit session(s) and *TPM PCR Read* operations.
* Make CHARRA a library (`libcharra`) and make *attester* and *verifier* example code in `example` folder.
* Add `*_free()` functions for all data transfer objects (DTOs).
* Introduce semantic versioning as CHARRA develops along the way to become stable.

*The order of the list is entirely arbitrary and does not reflect any priorities.*

