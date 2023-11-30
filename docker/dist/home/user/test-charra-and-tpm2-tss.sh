#!/usr/bin/env bash
################################################################################
# Test CHARRA and code examples for the tpm2-tss and tpm2-pytss.               #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-11-30T13:37:42+02:00                                     #
# Date Created:  2023-11-30T13:37:42+02:00                                     #
################################################################################


# ---------------------------------------------------------------------------- #
# --- GLOBAL CONSTANTS ------------------------------------------------------- #
# ---------------------------------------------------------------------------- #


# ---------------------------------------------------------------------------- #
# --- GLOBAL VARIABLES ------------------------------------------------------- #
# ---------------------------------------------------------------------------- #


# ---------------------------------------------------------------------------- #
# --- MAIN ------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## change directory to the one this script is placed
#cd "$(dirname "${0}")"


## main function
main() {
	## run tests
	test_charra
	echo
	test_tpm2_tss
	echo
	test_tpm2_pytss
}


# ---------------------------------------------------------------------------- #
# --- FUNCTIONS -------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

# --- app-specific functions ------------------------------------------------- #

test_charra() {
	log_info '--- Testing CHARRA ----------------------------------------------------'
	## compile

	## compile
	cd ~/charra/
	make clean
	make -j
	echo

	## run tests
	(bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT attester

	## clean up
	make clean

    ## change back
	cd - > /dev/null
}

test_tpm2_tss() {
	log_info '--- Testing tpm2-tss --------------------------------------------------'

	## compile
	log_info 'Changing folder and compiling ...'
	cd "${HOME}/code-examples/tpm2-tss/"
	make clean
	make -j
	echo

	## test ESAPI (maximum bytes = size of maximum supported hash algo)
	log_info '--- Testing ESAPI ...'
	echo
	log_info 'Test 1: <none>'
	./esapi-getrandom
	echo
	log_info 'Test 2: 64'
	./esapi-getrandom 64
	echo
	log_info 'Test 3: 100'
	./esapi-getrandom 100
	echo
	log_info 'Test 4: 1024'
	./esapi-getrandom 1024
	echo
	log_info 'Test 5: 2048'
	./esapi-getrandom 2048
	echo

	## test FAPI (maximum bytes = size of maximum supported hash algo)
	log_info '--- Testing FAPI ...'
	echo
	log_info 'Test 1: <none>'
	./fapi-getrandom
	echo
	eclog_infoho 'Test 2: 64'
	./fapi-getrandom 64
	echo
	log_info 'Test 3: 100'
	./fapi-getrandom 100
	echo
	log_info 'Test 4: 1024'
	./fapi-getrandom 1024
	echo
	log_info 'Test 5: 2048'
	./fapi-getrandom 2048
	echo

	## clean up
	log_info 'Cleaning up ...'
	make clean
	echo

    ## change back
	cd - > /dev/null
}

test_tpm2_pytss() {
	log_info '--- Testing tpm2-pytss --------------------------------------------------'

	## compile
	log_info 'Changing folder ...'
	cd "${HOME}/code-examples/tpm2-pytss/"
	echo

	## test ESAPI (maximum bytes = size of maximum supported hash algo)
	log_info '--- Testing ESAPI ...'
	echo
	log_info 'Test 1: <none>'
	./esapi-getrandom.py
	echo
	log_info 'Test 2: 64'
	./esapi-getrandom.py 64
	echo
	log_info 'Test 3: 100'
	./esapi-getrandom.py 100
	echo
	log_info 'Test 4: 1024'
	./esapi-getrandom.py 1024
	echo
	log_info 'Test 5: 2048'
	./esapi-getrandom.py 2048
	echo

	## test FAPI (maximum bytes = size of maximum supported hash algo)
	log_info '--- Testing FAPI ...'
	echo
	log_info 'Test 1: <none>'
	./fapi-getrandom.py
	echo
	eclog_infoho 'Test 2: 64'
	./fapi-getrandom.py 64
	echo
	log_info 'Test 3: 100'
	./fapi-getrandom.py 100
	echo
	log_info 'Test 4: 1024'
	./fapi-getrandom.py 1024
	echo
	log_info 'Test 5: 2048'
	./fapi-getrandom.py 2048
	echo

    ## change back
	cd - > /dev/null
}


# --- basic functions -------------------------------------------------------- #

log_info() {
	echo '[INFO]  ' "${*}"
}

log_warning() {
	echo '[WARN]  ' "${*}" >&2
}

log_error() {
	echo '[ERROR] ' "${*}" >&2
}

verify_dependencies() {
	while read tool; do
		## filter empty and commented lines
		if [ -z "${tool}" ] || [[ "${tool}" =~ ^# ]]; then
			continue
		fi

		## check if tool exists
		if [ ! -n "$(command -v "${tool}")" ]; then
			echo "Required tool '${tool}' not found or not executable!" >&2
			exit 2
		fi
	done < <(echo "${tool_reqs}")
}


# ---------------------------------------------------------------------------- #
# --- DEPENDENCIES ----------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## verify_dependencies (list all required commands here; #comments are allowed)
read -r -d '' tool_reqs <<- EOM
## basic tools
basename
cat
dirname

## app-specific tools
make
EOM


# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## verify that all dependencies are available
verify_dependencies

## call main function
main "$@"
