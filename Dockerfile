##############################################################################
# "Dockerfile"                                                               #
#                                                                            #
# Author: Michael Eckel <michael.eckel@sit.fraunhofer.de>                    #
# Date: 2019-06-26                                                           #
#                                                                            #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                  #
##############################################################################

FROM tpm2software/tpm2-tss:latest AS base

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

## TPM2 TSS
RUN git clone --depth=1 -b '2.2.3' \
	'https://github.com/tpm2-software/tpm2-tss.git' /tmp/tpm2-tss
WORKDIR /tmp/tpm2-tss
ENV LD_LIBRARY_PATH /usr/local/lib
RUN git reset --hard \
	&& git clean -xdf \
	&& ./bootstrap \
	&& ./configure --enable-integration --disable-doxygen-doc \
	&& make clean \
	&& make -j"$(nproc)" \
	&& make install \
	&& ldconfig

## make TPM Simulator the default for TCTI
RUN ln -sf 'libtss2-tcti-mssim.so' '/usr/local/lib/libtss2-tcti-default.so'

## compile and install TPM startup code
#WORKDIR /tmp/tpm2-tss
#RUN ./configure --enable-integration \
#	&& make -j"$(nproc)" test/helper/tpm_startup \
#	&& cp -v /tmp/tpm2-tss/test/helper/tpm_startup /usr/bin/tpm_startup

## remove TPM2-TSS source files
RUN rm -rf /tmp/tpm2-tss

## TPM2 tools
RUN git clone --depth=1 -b '3.2.0' \
	'https://github.com/tpm2-software/tpm2-tools.git' /tmp/tpm2-tools
WORKDIR /tmp/tpm2-tools
RUN ./bootstrap \
	&& ./configure \
	&& make -j"$(nproc)" \
	&& make install
RUN rm -rfv /tmp/tpm2-tools

## TinyCBOR
RUN git clone --depth=1 --recursive -b 'v0.5.2' \
	'https://github.com/intel/tinycbor.git' /tmp/tinycbor
WORKDIR /tmp/tinycbor
RUN make -j"$(nproc)" \
	&& make install
RUN rm -rfv /tmp/tinycbor

## libCoAP
RUN git clone --depth=1 --recursive -b 'develop' \
	'https://github.com/obgm/libcoap.git' /tmp/libcoap
WORKDIR /tmp/libcoap
RUN ./autogen.sh \
	&& ./configure --disable-tests --disable-documentation --disable-manpages --disable-dtls --disable-shared --enable-fast-install \
	&& make -j"$(nproc)" \
	&& make install
RUN rm -rfv /tmp/libcoap

## install debugging tools
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
	clang \
	valgrind \
	&& rm -rf /var/lib/apt/lists/*

## install sudo and gosu
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
	gosu \
	sudo \
	&& rm -rf /var/lib/apt/lists/*

## set default values
ARG user=bob
ARG uid=1000
ARG gid=1000

## create non-root user and grant sudo permission
RUN export user="$user" uid="$uid" gid="$gid" \
	&& addgroup --gid "$gid" "$user" \
	&& adduser --home /home/"$user" --uid "$uid" --gid "$gid" \
	--disabled-password --gecos '' "$user" \
	&& mkdir -vp /etc/sudoers.d/ \
	&& echo "$user     ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"$user" \
	&& chmod 0440 /etc/sudoers.d/"$user" \
	&& chown "$uid":"$gid" -R /home/"$user"

## set environment variables
ENV TPM2TOOLS_TCTI_NAME socket
ENV TPM2TOOLS_SOCKET_ADDRESS 127.0.0.1
ENV TPM2TOOLS_SOCKET_PORT 2321

## install TPM Simulator reset script
COPY "./docker/dist/usr/local/bin/tpm-reset" "/usr/local/bin/"

## install TSS compile script
COPY "./docker/dist/usr/local/bin/compile-tss" "/usr/local/bin/"

## Docker entrypoint
COPY "./docker/dist/usr/local/bin/docker-entrypoint.sh" "/usr/local/bin/"
## keep backwards compatibility
RUN ln -s '/usr/local/bin/docker-entrypoint.sh' /

## set environment variables
USER "$uid:$gid"
ENV HOME /home/"$user"
WORKDIR /home/"$user"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]

