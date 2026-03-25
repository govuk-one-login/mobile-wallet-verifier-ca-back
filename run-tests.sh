#!/bin/bash
set -eu

source ./test-environment-variables/$TEST_ENVIRONMENT.sh

if npm run test:integration; then
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
else
    cp -rf results $TEST_REPORT_ABSOLUTE_DIR
    exit 1
fi