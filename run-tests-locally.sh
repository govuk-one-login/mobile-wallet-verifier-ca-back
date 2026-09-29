#!/usr/bin/env bash
set -eu

SAM_STACK_NAME="${1:-ca-back}"
DOCKER_ENV_FILE="docker-vars.env"
DOCKER_IMAGE_NAME="ca-back-testcontainer"

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-eu-west-2}"

echo "Running integration tests against stack: ${SAM_STACK_NAME} (region ${AWS_DEFAULT_REGION})"

# Resolve the stack outputs into CFN_<OutputKey>="value" lines, exactly as the
# secure pipeline injects them. run-tests.sh reads these values
stack_outputs=$(
  aws cloudformation describe-stacks \
    --stack-name "${SAM_STACK_NAME}" \
    | jq --raw-output '.Stacks[0].Outputs[] | "CFN_" + .OutputKey + "=\"" + .OutputValue + "\""'
)

echo "Stack outputs:"
echo "${stack_outputs}"

{
  # Static env vars the pipeline sets.
  echo "TEST_ENVIRONMENT=build"
  echo "LOCAL_TEST=true"
  echo "TEST_REPORT_ABSOLUTE_DIR=/results"
  echo "AWS_REGION=${AWS_DEFAULT_REGION}"
  echo
  # Stack outputs (CFN_ prefixed), consumed by run-tests.sh.
  echo "${stack_outputs}"
  echo
  # Current AWS credentials so the container can sign requests directly.
  aws configure export-credentials --format env-no-export
} > "$DOCKER_ENV_FILE"

docker build --tag "$DOCKER_IMAGE_NAME" .

docker run --rm --tty \
  --user root \
  --env-file "$DOCKER_ENV_FILE" \
  --volume "$(pwd):/results" \
  "$DOCKER_IMAGE_NAME"
