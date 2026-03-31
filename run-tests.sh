#!/bin/bash
set -eu

if [[ "$TEST_ENVIRONMENT" == "build" ]]; then
  if npm test:integration; then
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
  else
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
    exit 1
  fi
fi