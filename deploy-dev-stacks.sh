#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-2}"

if ! command -v sam >/dev/null 2>&1; then
  echo "AWS SAM CLI not found. Install SAM CLI before running this script."
  exit 1
fi

read -r -p "Enter a stack identifier (e.g. your initials): " STACK_IDENTIFIER
if [[ -z "$STACK_IDENTIFIER" ]]; then
  echo "Stack identifier cannot be empty."
  exit 1
fi

if ! [[ "$STACK_IDENTIFIER" =~ ^[a-zA-Z0-9-]+$ ]]; then
  echo "Stack identifier must contain only letters, numbers, or hyphens."
  exit 1
fi

BASE_STACK_NAME="ca-base-${STACK_IDENTIFIER}"
APP_STACK_NAME="ca-back-${STACK_IDENTIFIER}"

echo ""
echo "Base stack name: ${BASE_STACK_NAME}"
echo "App stack name: ${APP_STACK_NAME}"
read -r -p "Proceed with deploy using these stack names? [y/N]: " CONFIRM_DEPLOY
case "$CONFIRM_DEPLOY" in
  y|Y|yes|YES)
    ;;
  *)
    echo "Deployment cancelled."
    exit 0
    ;;
esac

echo ""
echo "A base stack deployment is required the first time you deploy your stack pair,"
echo "and then only again if changes have been made to base-application.yaml."
read -r -p "Deploy base stack (${BASE_STACK_NAME})? [Y/n]: " DEPLOY_BASE_STACK
echo ""
read -r -p "Deploy main application stack (${APP_STACK_NAME})? [Y/n]: " DEPLOY_APP_STACK

SHOULD_DEPLOY_BASE=false
case "$DEPLOY_BASE_STACK" in
  ""|y|Y|yes|YES)
    SHOULD_DEPLOY_BASE=true
    ;;
  n|N|no|NO)
    ;;
  *)
    echo ""
    echo "Invalid response for base stack prompt. Aborting."
    exit 1
    ;;
esac

SHOULD_DEPLOY_APP=false
case "$DEPLOY_APP_STACK" in
  ""|y|Y|yes|YES)
    SHOULD_DEPLOY_APP=true
    ;;
  n|N|no|NO)
    ;;
  *)
    echo ""
    echo "Invalid response for main application prompt. Aborting."
    exit 1
    ;;
esac

if [[ "$SHOULD_DEPLOY_BASE" = false ]] && [[ "$SHOULD_DEPLOY_APP" = false ]]; then
  echo ""
  echo "Nothing selected for deployment."
  exit 0
fi

# Base application
if [[ "$SHOULD_DEPLOY_BASE" = true ]]; then
  sam build --template base-application.yaml --build-dir .aws-sam/base
  sam deploy \
    --template-file .aws-sam/base/template.yaml \
    --stack-name "$BASE_STACK_NAME" \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --parameter-overrides \
      Environment=dev \
      EnableCustomDomain=false \
    --resolve-s3 \
    --no-fail-on-empty-changeset \
    --region "$AWS_REGION" \
    --tags \
      Environment=dev \
      ManagedBy=manual-from-cli \
      Project=Mobile-Wallet-Verifier-CA
else
  echo ""
  echo "Skipping base stack deploy."
fi

# Application
if [[ "$SHOULD_DEPLOY_APP" = true ]]; then
  sam build --template application.yaml
  sam deploy \
    --template-file .aws-sam/build/template.yaml \
    --stack-name "$APP_STACK_NAME" \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --parameter-overrides \
      Environment=dev \
      BaseAppStack="$BASE_STACK_NAME" \
      EnableCustomDomain=false \
      EnableWafAssociation=false \
      CodeSigningConfigArn=none \
      PermissionsBoundary=none \
      EnableMonitoring=true \
    --resolve-s3 \
    --no-fail-on-empty-changeset \
    --region "$AWS_REGION" \
    --tags \
      Environment=dev \
      ManagedBy=manual-from-cli \
      Project=Mobile-Wallet-Verifier-CA
else
  echo ""
  echo "Skipping main application deploy."
fi
