#!/bin/bash

set -eu

TEST_REPORT_DIR="results"
TEST_ENVIRONMENT="build"
IS_LOCAL_TEST="true"
DOCKER_ENV_FILE="docker-vars.env"
DOCKER_IMAGE_NAME="ca-back-testcontainer"

echo "Running integration tests in pipeline like environment"

rm -f "$DOCKER_ENV_FILE"

{
  echo "TEST_REPORT_DIR=$TEST_REPORT_DIR"
  echo "TEST_REPORT_ABSOLUTE_DIR=/results"
  echo "TEST_ENVIRONMENT=$TEST_ENVIRONMENT"
  echo "IS_LOCAL_TEST=$IS_LOCAL_TEST"
} > "$DOCKER_ENV_FILE"

docker buildx build --tag "$DOCKER_IMAGE_NAME" .

docker run --rm --interactive --tty \
  --user root \
  --env-file "$DOCKER_ENV_FILE" \
  --volume "$(pwd):/results" \
  "$DOCKER_IMAGE_NAME"