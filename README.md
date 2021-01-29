# CHARRA: CHAllenge-Response based Remote Attestation with TPM 2.0

This is a proof-of-concept implementation of the "Challenge/Response Remote Attestation" interaction model of the [IETF RATS](https://datatracker.ietf.org/wg/rats/about/) [Reference Interaction Models for Remote Attestation Procedures](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/) using TPM 2.0. The [IETF Remote Attestation Procedures (RATS)](https://datatracker.ietf.org/wg/rats/about/) working group standardizes formats for describing assertions/claims about system components and associated evidence; and procedures and protocols to convey these assertions/claims to relying parties. Given the security and privacy sensitive nature of these assertions/claims, the working group specifies approaches to protect this exchanged data.

This proof-of-concept implementation realizes the Attesting Computing Environment—a Computing Environment capable of monitoring and attesting a target Computing Environment—as well as the target Computing Environment itself, as described in the [RATS Architecture](https://datatracker.ietf.org/doc/draft-birkholz-rats-architecture/).

Next steps:

* Refactor and and implement forward-declared (but not yet implemented) functions
* Block-wise CoAP data transfers
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

### Building and Running in Docker on Raspberry Pi

The CHARRA `Dockerfile` uses the official `tpm2software/tpm2-tss:` Docker image as a basis.
This image is (at the moment) only available for the *amd64* architecture, not for ARM-based systems.
That is why on the Raspberry Pi this image must be created manually.
This guide was tested on a Raspberry Pi 4 with 4 GiB RAM running [Raspberry Pi OS Lite](https://www.raspberrypi.org/software/operating-systems/) in version *buster*.

*Side note: Even on such a powerful device like the Raspberry Pi 4 with 4 GiB of RAM the build process can take very long (1+ hours).*

1. Install dependencies:

       sudo apt install build-essential m4

2. Clone the TPM2 Software Container repository:

       git clone 'https://github.com/tpm2-software/tpm2-software-container.git'

3. Build the `Dockerfile`s:

       make

4. Build the Docker image `Dockerfile`s:

       docker build -t 'tpm2software/tpm2-tss:ubuntu-18.04' -f ubuntu-18.04.docker .

5. Then continue with the steps described in the previous section.

### Building and Running Manually

The provided `Dockerfile` lets you quickly test CHARRA in a Docker environment.
If you want to run CHARRA bare metal, please refer to this guide here.

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

2. Send TPM *startup* command:

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

## Remote Attestation

The attester and verifier can be used on two different devices.
To do that, you have to provide an external network for the attester container.

1. Create [macvlan network](https://docs.docker.com/network/macvlan/)
for attester docker container (check your gateway address and replace `x` with
the correct number):

       docker network create -d macvlan \
           --subnet=192.168.x.0/24 \
           --gateway=192.168.x.1 \
           -o parent=eth0 pub_net

2. Add `--network` parameter to the `docker run` command in the `docker/run.sh` on the attester device:

       ## run (transient) Docker container
       /usr/bin/docker run --rm -it \
           -v "${PWD}/:/home/bob/charra" \
           --network=pub_net \
           "${docker_image_fullname}" \
           "$@"

3. Run the attester docker container and check the IP address.

4. Put the attester address to the `DST_HOST` in `src/verifier.c` on the verifier device.
   Rebuild verifier script in the verifier docker container:

       cd charra
       make -j

5. Go to `charra` directory and run attester binary in the attester docker container:

       cd charra
       bin/attester

6. Run the verifier binary in the verifier docker container:

       /bin/verifier

If you see "ATTESTATION SUCCESSFUL" you're done. Congratz :-D
