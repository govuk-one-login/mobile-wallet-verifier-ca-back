#!/bin/bash
set -eu

cd /ca-backend

mkdir -pv results

if [[ "$TEST_ENVIRONMENT" == "build" ]]; then
  if npm run test:integration; then
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
  else
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
    exit 1
  fi
fi