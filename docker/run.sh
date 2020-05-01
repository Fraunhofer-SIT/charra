#!/bin/bash
###############################################################################
# Build docker image.                                                         #
###############################################################################


# ---------------------------------------------------------------------------#
# --- PREAMBLE --------------------------------------------------------------#
# ---------------------------------------------------------------------------#

## sanity check -- list all required tools here
read -r -d '' tool_reqs <<- EOM
/usr/bin/dirname
/usr/bin/docker
EOM
while read tool; do
	if [ ! -x "$tool" ]; then
		## print error using the shell builtin echo command
		echo "Required tool '${tool}' not found or not executable!" >&2
		exit 2
	fi
done < <(echo "$tool_reqs")


# ---------------------------------------------------------------------------#
# --- MAIN ------------------------------------------------------------------#
# ---------------------------------------------------------------------------#

## change directory to the one this script is placed in
cd "$(/usr/bin/dirname "$0")"

## go up one directory
cd ../


## variables
docker_image_config_file='./docker/docker-image.config'
. "$docker_image_config_file"

## sanity checks
for cfg_opt in \
	'DOCKER_IMAGE_VENDOR' \
	'DOCKER_IMAGE_NAME' \
	'DOCKER_IMAGE_VERSION'
do
	cfg_opt_val=$(eval "echo \${${cfg_opt}}")
	if [ -z "${cfg_opt_val}" ]; then
		echo "** Please set the '$cfg_opt' option in file '$docker_image_config_file'." >&2
		exit 1
	fi
done

## construct Docker image name
docker_image_fullname="${DOCKER_IMAGE_VENDOR}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}"

## check whether Docker image exists
image_exists="$(/usr/bin/docker images -q "${docker_image_fullname}" 2> /dev/null)"
if [ -z "${image_exists}" ]; then
	echo "ERROR: Docker image '${docker_image_fullname}' does not exist."
	exit 1
fi

## run (transient) Docker container
/usr/bin/docker run --rm -it \
	-v "${PWD}/:/home/bob/charra" \
	"${docker_image_fullname}" \
	"$@"
