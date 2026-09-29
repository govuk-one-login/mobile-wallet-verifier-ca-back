#!/bin/bash
set -eu

cd /ca-backend

mkdir -pv results

remove_quotes() {
  local value="$1"
  echo "$value" | tr -d '"'
}

if [[ "${LOCAL_TEST:-false}" == "true" ]]; then
  CA_BACKEND_API_URL=$(remove_quotes "${CFN_ApiGatewayDomainName:-}")
  MOCK_SERVICES_API_URL=$(remove_quotes "${CFN_MockServicesApiUrl:-}")
else
  CA_BACKEND_API_URL="https://origin.api.verifier-ca.build.account.gov.uk"
  MOCK_SERVICES_API_URL="https://mock.verifier-ca.build.account.gov.uk"
fi
export CA_BACKEND_API_URL
export MOCK_SERVICES_API_URL

AWS_REGION="${AWS_REGION:-eu-west-2}"
export AWS_REGION

if [[ "$TEST_ENVIRONMENT" == "build" ]]; then
  if npm run test:integration; then
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
  else
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
    exit 1
  fi
fi
