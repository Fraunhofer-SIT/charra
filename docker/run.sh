#!/usr/bin/env bash
################################################################################
# Run CHARRA container(s).                                                     #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2026-09-03T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################


# ---------------------------------------------------------------------------- #
# --- GLOBAL CONSTANTS ------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

readonly THIS_SCRIPT="$(readlink -f "${0}")"
readonly THIS_SCRIPT_NAME="$(basename "${THIS_SCRIPT}")"
readonly THIS_SCRIPT_DIR="$(dirname "${THIS_SCRIPT}")"

## exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_FAILURE=1
readonly EXIT_FAILURE_MISS_DEP=2

## log levels (LOG_NONE, LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERROR)
readonly LOG_TRACE=0
readonly LOG_DEBUG=1
readonly LOG_INFO=2
readonly LOG_WARNING=3
readonly LOG_ERROR=4
readonly LOG_NONE=99999
readonly LOG_LEVEL=${LOG_DEBUG}

## container config
readonly CONTAINER_FILE='Dockerfile'
readonly CONTAINER_IMAGE_ENV_FILE='./docker/docker-image.config'
readonly CONTAINER_USER_DEFAULT='bob'


# ---------------------------------------------------------------------------- #
# --- GLOBAL VARIABLES ------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

export DOCKER_BUILDKIT=1


# ---------------------------------------------------------------------------- #
# --- MAIN ------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## change directory to the one this script is placed in
cd "$(dirname "${0}")"

## go up one directory
cd ../

# ---------------------------------------------------------------------------- #

## main function
main() {
	local exit_code=${EXIT_SUCCESS}

	## load config
	set -a  # automatically export all variables
	source "${CONTAINER_IMAGE_ENV_FILE}"
	set +a

	## type specified?
	local container_type=
	if [ -n "${1}" ]; then
		container_type="${1}"
	fi

	## sanity checks
	for cfg_opt in \
		'CONTAINER_IMAGE_VENDOR' \
		'CONTAINER_IMAGE_NAME' \
		'CONTAINER_IMAGE_VERSION'
	do
		cfg_opt_val="$(eval "echo \${${cfg_opt}}")"
		if [ -z "${cfg_opt_val}" ]; then
			log_warning "Please set the '${cfg_opt}' option in file" \
				"'${CONTAINER_IMAGE_ENV_FILE}'."
			exit 1
		fi
	done

	## construct container image name
	local container_image_fullname="`#
		`${CONTAINER_IMAGE_VENDOR}/`#
		`${CONTAINER_IMAGE_NAME}`#
		`:${CONTAINER_IMAGE_VERSION}"
	if [ -n "${container_type}" ]; then
		container_image_fullname="${container_image_fullname}-${container_type}"
	fi

	## construct container file name
	local container_file="${CONTAINER_FILE}"
	if [ -n "${container_type}" ]; then
		container_file="${container_file}.${container_type}"
	fi

	## set variables
	local -r container_user="$([ -n "${CONTAINER_USER}" ] \
			&& echo "${CONTAINER_USER}" || echo "${CONTAINER_USER_DEFAULT}")"

	## run only if image exists
	if $(image_exists "${container_image_fullname}"); then
		docker run \
	        -v "${PWD}/:/home/${container_user}/charra" \
	        -it --rm --init \
	        --group-add 'tss' \
	        "${container_image_fullname}"
	else
		log_error "Image '${container_image_fullname}' does not exist." \
			'Please build it first.'
		return ${EXIT_FAILURE}
	fi

	## exit with exit code
	exit ${exit_code}
}


# ---------------------------------------------------------------------------- #
# --- FUNCTIONS -------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

# --- app-specific functions ------------------------------------------------- #

##
# @brief Checks if a Docker image exists.
#
# @param[in] (1) container_image_fullname: text-string
##
image_exists() {
	## verify input arguments
	local let exp_argc=1
	if [ ${#} -ne "${exp_argc}" ]; then
		log_error "Wrong number of arguments: expected ${exp_argc}, got ${#}."
		return
	fi

	## assign input arguments to (human readable) variables
	local -r container_image_fullname="${1}"

	## check if image exists and return
	local -r image_id="$(docker images -q "${container_image_fullname}" 2> /dev/null)"
	return $(test -n "${image_id}")
}

# --- basic functions -------------------------------------------------------- #

log_trace() {
	(( LOG_LEVEL <= LOG_TRACE )) && echo '[TRACE] ' "${*}"
}

log_debug() {
	(( LOG_LEVEL <= LOG_DEBUG )) && echo '[DEBUG] ' "${*}"
}

log_info() {
	(( LOG_LEVEL <= LOG_INFO )) && echo '[INFO]  ' "${*}"
}

log_warn() {
	(( LOG_LEVEL <= LOG_WARNING )) && echo '[WARN]  ' "${*}" >&2
}

log_error() {
	(( LOG_LEVEL <= LOG_ERROR )) && echo '[ERROR] ' "${*}" >&2
}

verify_dependencies() {
	while read dep; do
		## filter empty and commented lines
		if [ -z "${dep}" ] || [[ "${dep}" =~ ^# ]]; then continue; fi

		## check if dependency/command exists
		if [ ! -n "$(command -v "${dep}")" ]; then
			log_error "Required command '${dep}' not found or not executable!"
			exit ${EXIT_FAILURE_MISS_DEP}
		fi
	done < <(echo "${script_deps}")
}


# ---------------------------------------------------------------------------- #
# --- DEPENDENCIES ----------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## verify_dependencies (list all required commands here; #comments are allowed)
read -r -d '' script_deps <<- EOM
## basic dependencies
basename
dirname
readlink

## script-specific dependencies
docker
test
EOM


# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #

## call main function
verify_dependencies
main "$@"

