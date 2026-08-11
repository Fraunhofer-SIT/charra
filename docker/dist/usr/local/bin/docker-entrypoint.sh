#!/bin/sh
set -e


cat <<EOM
 _____________________________________________________________________________
( =========================================================================== )
(  Welcome to Docker TPM 2.0 Simulator Development Environment (DoTSiDE)      )
( =========================================================================== )
(                                                                             )
( You have the following extra tools available:                               )
(                                                                             )
( swtpm        Stefan Berger's TPM 1.2 + 2.0 Simulator (already started)      )
( tpm-reset    Resets the TPM2 Simulator: clearing its state, restarting it   )
( compile-tss  Compiles C code files with TSS2 libraries (dynamic linking)    )
( tpm2_xxx     TPM2 tools; based on the TPM2 TSS Enhanced System API (ESAPI)  )
( tss2_xxx     TSS2 tools; based on the TPM2 TSS Feature API (FAPI)           )
(_____________________________________________________________________________)
        \\
         \\              ##        .
          \\       ## ## ##       ==
               ## ## ## ##      ===
           /""""""""""""""""___/ ===
      ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~
           \______ o ____     __/
            \    \  |TPM2| __/
             \____\_______/

EOM

## print system info
hw_type="$(uname -m)"
os="$(. /etc/os-release ; echo "${PRETTY_NAME}")"
os_type="$(uname -o)"
kernel_release="$(uname -r)"
kernel_version="$(uname -v)"
model="$(cat /proc/cpuinfo | grep -i 'Model' | tail -n 1 | \
        sed 's/^[^:]*:[ ]*\(.*\)$/\1/')"
echo ">>>  Running ${os} (${os_type}) on a ${model} (${hw_type})"
echo ">>>  with kernel ${kernel_release} (${kernel_version})"
echo

## start TPM simulator
(/usr/local/bin/tpm-reset &) \
&& echo 'Started TPM Simulator in working directory /tmp/swtpm20.'
echo

## execute command
exec "$@"
