<!--
################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-05-22T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################
-->

# Build and Run CHARRA

CHARRA comes with a Docker environment and helper scripts to quickly test CHARRA interactively.
It is also possible to build and run CHARRA manually.
All commands are to be executed in [Bash](https://www.gnu.org/software/bash/).

## The Docker and Docker Compose Way

The following describes how to run CHARRA in [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).

### Preparation

First, Docker and Docker Compose must be installed and .
The following command are intended for an Ubuntu (amd64) system.

1. Install [Docker](https://docs.docker.com/get-docker/) (and [Docker Compose](https://docs.docker.com/compose/install/)):

       sudo apt update
       sudo apt install docker.io docker-compose

2. Set group membership to run containers as non-root user:

       sudo groupadd docker
       sudo usermod -aG docker "${USER}"

3. Restart system (to activate group membership):

       sudo reboot

### Using Docker

Running CHARRA in Docker is the prefered way of running it.
This way, you do not need to install all the dependencies into your system just to try CHARRA.

1. Build CHARRA container image(s):

       ./docker/build.sh

2. Run the CHARRA interactive development environment container:

       ./docker/run.sh

### Using Docker Compose

1. Build the CHARRA container image(s):

       docker-compose build --build-arg uid="${UID}" --build-arg gid="${UID}"

2. Run the CHARRA interactive development environment container:

       docker-compose run --rm charra-dev-env

<!-- TODO: Uncomment this when verified that it works
### Run CHARRA Apps in Docker Compose

    docker-compose run --rm -T charra-attester &
    docker-compose run --rm -T charra-verifier
-->

## The Manual Way

Please follow the steps in the `Dockerfile` to build and install dependencies manually directly into your system.

## Compile and Run CHARRA

Once all dependencies are installed, or you have the container running, change to the root folder of your local copy of CHARRA (in the container do a `cd ~/charra/`).

1. Compile CHARRA:

       make -j

2. Run CHARRA:

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester

If you see a message "ATTESTATION SUCCESSFUL", it worked.


## Build Arguments

CHARRA comes with some build arguments that you find in the following.

| Argument                   | Default          | Available Options                             | Description                                                      |
| -------------------------- | ---------------- | --------------------------------------------- | ---------------------------------------------------------------- |
| `TCTI_MODULE`              | `tctildr`        | `tcti-default`, `tcti-cmd`, `tcti-device`, `tcti-libtpms`, `tcti-mssim`, `tcti-pcap`, `tcti-swtpm`, `tctildr` (and other implementations ) | Configure the TCTI module for the TPM |
| `ENABLE_LOGGING`           | `1` (enabled)    | `0` (disabled), `!= 0` (enabled)              | Enable/disable log output                                        |
| `ENABLE_LOGGING_COLOR`     | `1` (enabled)    | `0` (disabled), `!= 0` (enabled)              | Enable/disable colored log output                                |
| `ENABLE_ADDRESS_SANITIZER` | `0` (disabled)   | `0` (disabled), `!= 0` (enabled)              | Enable/disable AddressSanitizer (ASan)                           |
| `ENABLE_LEAK_SANITIZER`    | `0` (disabled)   | `0` (disabled), `!= 0` (enabled)              | Enable/disable LeakSanitizer (LSan)                              |
| `ENABLE_PIC`               | `1` (enabled)    | `0` (disabled), `!= 0` (enabled)              | Emit position-independent code                                   |
| `ENABLE_STRIPPING`         | `1` (enabled)    | `0` (disabled), `!= 0` (enabled)              | Remove all symbols that are not needed for relocation processing |
| `LINK_MODE`                | `dynamic`        | `dynamic`, `static` (*currently not working*) | Link executables statically or dynamically                       |

Example invocation:

    make TCTI_MODULE=tcti-mssim ENABLE_LOGGING_COLOR=0 ENABLE_STRIPPING=0

## Troubleshooting and Advanced Usage

If you're interested in delving further and modifying the building and operational conditions of CHARRA, this section provides valuable information.

### TPM Simulator

1. Start the TPM Simulator (and remove the state file `NVChip`):

       (cd /tmp ; pkill tpm_server ; rm -f NVChip; /usr/local/bin/tpm_server > /dev/null &)

2. Send TPM *startup* command:

       /usr/local/bin/tpm2_startup -Tmssim --clear

3. Run Attester and Verifier:

       (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

If you see a message "ATTESTATION SUCCESSFUL", it worked.

### Debugging

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
      pkill -SIGINT -f bin/attester

* AddressSanitizer (ASan):

      make clean ; make ENABLE_ADDRESS_SANITIZER=1
      (bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester

### Run Attester and Verifier on Different Devices

The attester and verifier can be used on two different devices.
To do that, you have to provide an external network for the attester Docker container.

1. Create [macvlan network](https://docs.docker.com/network/macvlan/) for attester Docker container (check your gateway address and replace `x` with the correct number):

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

3. Run the attester Docker container and check the IP address.

4. Put the attester address to the `DST_HOST` in `src/verifier.c` on the verifier device.
   Rebuild the verifier in the verifier Docker container:

       cd charra
       make -j

5. Go to `charra` directory and run attester binary in the attester Docker container:

       cd charra
       bin/attester

6. Run the verifier binary in the verifier docker container:

       /bin/verifier

If you see a message "ATTESTATION SUCCESSFUL", it worked.

