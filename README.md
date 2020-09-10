# CHARRA: CHAllenge-Response based Remote Attestation with TPM 2.0

This is a proof-of-concept implementation of the "Challenge/Response Remote Attestation" interaction model of the [IETF RATS](https://datatracker.ietf.org/wg/rats/about/) [Reference Interaction Models for Remote Attestation Procedures](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/) using TPM 2.0. The [IETF Remote ATtestation ProcedureS (RATS)](https://datatracker.ietf.org/wg/rats/about/) working group standardizes formats for describing assertions/claims about system components and associated evidence; and procedures and protocols to convey these assertions/claims to relying parties. Given the security and privacy sensitive nature of these assertions/claims, the working group specifies approaches to protect this exchanged data.

This proof-of-concept implementation realizes the Attesting Computing Environment—a Computing Environment capable of monitoring and attesting a target Computing Environment—as well as the target Computing Environment itself, as described in the [RATS Architecture](https://datatracker.ietf.org/doc/draft-birkholz-rats-architecture/).

Next steps:

* Block-wise CoAP data transfers
* Verify TPM Quote with *mbedtls* using TPM public key
* Use non-zero reference PCRs
* Introduce a Make flag which disables console output (useful for embedded systems and firmware)
* "Extended" *TPM Quote* using TPM audit session(s) and *TPM PCR Read* operations
* Make CHARRA a library (`libcharra`) and make *attester* and *verifier* example code in `example` folder


## How it works (Protocol Flow)

The following diagram shows the protocol flow of the CHARRA attestation process.

       .----------.                                                .----------.
       | Attester |                                                | Verifier |
       '----------'                                                '----------'
            |                                                            |
            | <---------- requestAttestation(nonce, keyID, pcrSelection) |
            |                                                            |
       tpmQuote(nonce, pcrSelection)                                     |
            | => evidence                                                |
            |                                                            |
            | evidence ------------------------------------------------> |
            |                                                            |
            |                  appraiseEvidence(evidence, nonce, referencePcrs)
            |                                       attestationResult <= |
            |                                                            |


## Building and Running

CHARRA comes with a Docker test environment and Docker helper scripts to build and run it in Docker.
It is also possible to build and run CHARRA manually.


### Building and Running in Docker

1. Install Docker.

2. Build Docker image:

       ./docker/build.sh

3. Run Docker image:

       ./docker/run.sh

4. Compile CHARRA (inside container):

       cd charra/
       make -j

5. Run CHARRA (inside container):

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D


### Building and Running Manually

#### Build

The `Dockerfile` provides details on installing all dependencies and should be considered authoritative over this.

1. Install all dependencies that are needed for the [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md).

2. Install *libCoAP*:

       git clone --depth=1 --recursive -b 'develop' \
           'https://github.com/obgm/libcoap.git' /tmp/libcoap
       cd /tmp/libcoap
       ./autogen.sh
       ./configure --disable-tests --disable-documentation --disable-manpages --disable-dtls --disable-shared --enable-fast-install
       make -j
       make install

   Make sure that you do not have `libcoap-1-0-dev` installed, as the headers might conflict.

3. Install *mbedtls*:

       git clone --depth=1 --recursive -b 'development' \
           'https://github.com/ARMmbed/mbedtls.git' /tmp/mbedtls
       cd /tmp/mbedtls
       make -j lib SHARED=true
       make install

4. Install *QCBOR*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor
       cd /tmp/qcbor
       make -j all so
       make install install_so

5. Install *t_cose*:

       git clone --depth=1 --recursive -b 'master' \
           'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose
       cd /tmp/t_cose
       make -j -f Makefile.psa libt_cose.a libt_cose.so
       make -f Makefile.psa install install_so

6. Compile programs:

       make -j


#### Further Preparation

1. Download and install [IBM's TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/).

2. Download and install the [TPM2 Tools](https://github.com/tpm2-software/tpm2-tools).


#### Running

1. Start the TPM Simulator (and remove the state file `NVChip`):

       (cd /tmp ; pkill tpm_server ; rm -f NVChip; /usr/local/bin/tpm_server > /dev/null &)

2. Send TPM startup command:

       /usr/local/bin/tpm2_startup -Tmssim --clear

3. Run Attester and Verifier:

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -f bin/attester

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D



## Debugging

* Clang `scan-build`:

      make clean ; scan-build make

* Valgrind:

      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/attester \
          2> attester-valgrind-stderr.log &); \
      sleep .2 ; \
      (valgrind --leak-check=full \
          --show-leak-kinds=all -v \
          bin/verifier\
          2> verifier-valgrind-stderr.log) ;\
      sleep 1 ; \
      pkill bin/attester


