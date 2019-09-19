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
(   tpm_server   The IBM TPM2 Simulator (already started)                     )
(   tpm-reset    Resets the TPM2 Simulator: clearing its state, restarting it )
(   compile-tss  Compiles C code files with TSS2 libraries (dynamic linking)  )
(   tpm2_xxx     TPM2 tools                                                   )
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

(/usr/local/bin/tpm-reset &) \
&& echo 'Started TPM Simulator in working directory /tmp.'
echo


exec "$@"


