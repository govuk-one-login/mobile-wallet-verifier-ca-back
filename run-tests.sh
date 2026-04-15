#!/bin/bash
set -eu

cd /ca-backend

remove_quotes() {
  echo "$1" | tr -d '"'
}

export API_GATEWAY_URL=$(remove_quotes "$CFN_ApiGatewayDomainName")
export MOCK_SERVICES_API_URL=$(remove_quotes "$CFN_MockServicesApiUrl")

mkdir -pv results

if [[ "$TEST_ENVIRONMENT" == "build" ]]; then
  if npm run test:integration; then
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
  else
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
    exit 1
  fi
fi
