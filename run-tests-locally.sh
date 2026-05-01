#!/bin/bash

set -eu

DOCKER_ENV_FILE="docker-vars.env"
DOCKER_IMAGE_NAME="ca-back-testcontainer"

echo "Running integration tests in pipeline like environment"

{
  echo "TEST_REPORT_ABSOLUTE_DIR=/results"
  echo "TEST_ENVIRONMENT=build"
} > "$DOCKER_ENV_FILE"

docker build --tag "$DOCKER_IMAGE_NAME" .

docker run --rm --tty \
  --user root \
  --env-file "$DOCKER_ENV_FILE" \
  --volume "$(pwd):/results" \
  "$DOCKER_IMAGE_NAME"
