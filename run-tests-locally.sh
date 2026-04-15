#!/bin/bash

# Temporary file only for local testing on branch

set -eu

BACKEND_STACK_NAME="ca-back-jammy-101"
AWS_DEFAULT_REGION="eu-west-2"
TEST_REPORT_DIR="results"
TEST_ENVIRONMENT="build"
IS_LOCAL_TEST="true"
DOCKER_ENV_FILE="docker-vars.env"
DOCKER_IMAGE_NAME="ca-back-testcontainer"
CF_OUTPUT_FILE="cf-output.txt"

echo "Running integration tests locally against stack ${BACKEND_STACK_NAME}"

rm -f "$DOCKER_ENV_FILE"
rm -f "$CF_OUTPUT_FILE"

aws cloudformation describe-stacks \
  --stack-name "$BACKEND_STACK_NAME" \
  --region "$AWS_DEFAULT_REGION" \
  --query 'Stacks[0].Outputs[].{key: OutputKey, value: OutputValue}' \
  --output text > "$CF_OUTPUT_FILE"

awk '{ printf("CFN_%s=\"%s\"\n", $1, $2) }' "$CF_OUTPUT_FILE" >> "$DOCKER_ENV_FILE"

{
  echo "TEST_REPORT_DIR=$TEST_REPORT_DIR"
  echo "TEST_REPORT_ABSOLUTE_DIR=/results"
  echo "TEST_ENVIRONMENT=$TEST_ENVIRONMENT"
  echo "IS_LOCAL_TEST=$IS_LOCAL_TEST"
} >> "$DOCKER_ENV_FILE"

docker buildx build --tag "$DOCKER_IMAGE_NAME" .

docker run --rm --interactive --tty \
  --user root \
  --env-file "$DOCKER_ENV_FILE" \
  --volume "$(pwd):/results" \
  "$DOCKER_IMAGE_NAME"
