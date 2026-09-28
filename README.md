# mobile-wallet-verifier-ca-back

## Overview

This Repository contains a service (lambda function) to operate a private certificate authority (CA). The service verifies reader authentication by issuing a certificate (valid for 90 days) to access credentials from a Holder App. Mock services are also provided for dev/build environments.

### Lambda Functions

#### Issue Reader Certificate Service (`/issue-reader-cert`)

Issues X.509 reader certificates (90-day validity) after validating the Certificate Signing Request (CSR).

Requests must be authenticated with AWS Signature Version 4 (SigV4). The endpoint is invoked by machine-to-machine callers that assume an IAM role (via GitHub OIDC) and sign the request. API Gateway rejects unsigned or invalidly signed requests with a 403 before they reach the backend. See [`open-api-spec.yaml`](./open-api-spec.yaml) for the exact request/response contract.

Optionally, the service also verifies a Firebase App Check token (via the `X-Firebase-AppCheck` header). This verification is gated behind the `ENABLE_FIREBASE_APP_CHECK_JWT_VALIDATION` feature flag and is currently disabled in every environment, so the header is optional. See [Feature Flags](#feature-flags).

The issued leaf certificate carries the DVS privacy policy URL in a non-critical Subject Information Access (SIA) extension, and the response returns the full certificate chain up to the Root CA.

#### Mock Services (Dev/Build Only)

**Mock JWKS Service (`/mock-jwks`)**: Returns public keys for Firebase App Check token verification in test environments.

**Mock Issue Cert Request Service (`/mock-issue-cert-request`)**: Generates complete mock certificate requests with Firebase App Check tokens for testing.

```json
{
  "headers": {
    "X-Firebase-AppCheck": "<firebase-app-check-jwt>"
  },
  "body": {
    "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
  }
}
```

## Feature Flags

### `ENABLE_FIREBASE_APP_CHECK_JWT_VALIDATION`

Controls whether the `/issue-reader-cert` endpoint enforces Firebase App Check JWT validation.

- When `'true'`, the `X-Firebase-AppCheck` header is mandatory and its JWT is verified (signature, `iss`, `aud`, `sub`, `exp`, `nbf`, and replay protection) before a certificate is issued.
- When `'false'`, the `X-Firebase-AppCheck` header is optional and the JWT is not verified. Requests are processed on CSR validity alone.

The flag is currently set to `'false'` in every environment.

This is part of the Reader Auth Trust Anchor Provisioning work, which repurposes this backend into a Test DVS backend for internal Wallet Sharing verification testing. Making the header optional lets that testing proceed ahead of the SigV4 authentication layer that will replace Firebase App Check. SigV4 is out of scope for this change.

## Pre-requisites

- [Node.js](https://nodejs.org/en) version 22 (use the provided `.nvmrc` file with [nvm](https://github.com/nvm-sh/nvm) for easy version management)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html) for deployment
- AWS CLI configured with appropriate credentials for Secrets Manager access
- [Husky](https://typicode.github.io/husky/get-started.html) - For pre-push validations

## Project Architecture

This project uses **ECMAScript Modules (ESM)** as the module system:

- Native `import`/`export` syntax throughout the codebase
- `"type": "module"` in package.json enables ESM
- [esbuild](https://esbuild.github.io/) for fast TypeScript compilation and bundling
- [Vitest](https://vitest.dev/) for testing with native ESM support

## Logging

See [logging documentation](./docs/logging.md).

## Shared Lambda Patterns

### Environment variable access (`src/lambdas/common/config/environment.ts`)

Use `getRequiredEnvironmentVariables` as the standard way for lambdas to read required environment variables.

- Define a `REQUIRED_ENVIRONMENT_VARIABLES` array in a lambda config helper (e.g. `*-config.ts` or `*-handler-config.ts`)
- Add each required env var key to that array
- Call `getRequiredEnvironmentVariables(env, REQUIRED_ENVIRONMENT_VARIABLES)` and return the typed config result
- In that same config helper, validate env var values before returning config (for example, valid URL shape or numeric values)

Example: See [config.ts](./src/lambdas/issue-reader-cert-service/config.ts) that defines `REQUIRED_ENVIRONMENT_VARIABLES`.

When a required env var is missing, this utility returns an error containing `missingEnvVars`, so the config helper can log details and the handler can fail fast.

### Result pattern for helpers/services (`src/lambdas/common/result/result.ts`)

Use the `Result` pattern for helper/service functions so handlers can evaluate success/failure explicitly and respond accordingly.

- Return `successResult(value)` for success paths
- Return `emptySuccess()` when success has no payload
- Return `errorResult(error)` for failure paths with an error payload
- Return `emptyFailure()` when failure has no error payload
- In handlers, check `result.isError` to decide behaviour, status code and response body

This keeps service/helper code consistent and avoids ambiguous return types between success and failure flows.

## Quality Gates

Pre merge checks are documented in our quality gates [manifest](quality-gate.manifest.json) to align with the One Login quality gates schema. This is used to track which automated checks run before merging.

## Quickstart

### Install dependencies

```bash
npm install
```

The npm `postinstall` script should take care of installing Husky.

### Build

Build the project for deployment:

```bash
npm run build
```

This uses esbuild to:

- Compile TypeScript to ESM JavaScript
- Bundle Lambda functions for optimal performance
- Generate source maps for debugging
- Handle module resolution automatically

### Test

#### Unit Tests

Run unit tests using Vitest (with native ESM support):

```bash
npm run test
```

Run tests with coverage:

```bash
npm run test:cov
```

#### Integration tests

These integration tests are implemented with Cucumber and exercise the deployed API end to end using the mock services.

The Cucumber feature files and step definitions live under `tests/integrationTests`.

The `/issue-reader-cert` endpoint requires AWS SigV4 authentication, so the tests sign their requests. Running them requires:

- The target stack's URLs: the **regional** API base URL (the `ApiGatewayDomainName` output, e.g. `https://<api-id>.execute-api.eu-west-2.amazonaws.com/<stage>`) and the mock services API base URL (the `MockServicesApiUrl` output). The API URL must be the regional `execute-api` host, **not** the CloudFront custom domain: SigV4 signs the `Host` header, and CloudFront rewrites it, which invalidates the signature.
- **AWS credentials** for the account the stack is deployed in (e.g. an active SSO session). The tests sign requests with these credentials.

The JUnit report is written under `results/`.

##### Pipeline-like Docker run (recommended)

`run-tests-locally.sh` mirrors how the secure pipeline runs the tests. It reads the stack's CloudFormation outputs, passes them to the test container as `CFN_<OutputKey>` env vars, and exports your current AWS credentials into the container so requests are signed. Requires Docker (running), `jq`, and an active AWS session.

```bash
# Defaults to the "ca-back" stack; pass a stack name to target your own stack.
./run-tests-locally.sh                 # runs against the "ca-back" stack
./run-tests-locally.sh <your-stack>    # e.g. a personal dev stack
```

##### Run without Docker

Set the target URLs from your deployed stack's outputs, then run the Cucumber suite directly. The tests fail fast with a clear error if the URL variables are not set.

```bash
export CA_BACKEND_API_URL="$(aws cloudformation describe-stacks --stack-name <your-stack> \
  --query "Stacks[0].Outputs[?OutputKey=='ApiGatewayDomainName'].OutputValue" --output text)"
export MOCK_SERVICES_API_URL="$(aws cloudformation describe-stacks --stack-name <your-stack> \
  --query "Stacks[0].Outputs[?OutputKey=='MockServicesApiUrl'].OutputValue" --output text)"
npm run test:integration
```

Note: locally the requests are signed with **your** credentials. Because the API's resource policy allows any SigV4-signed caller in the account, this exercises SigV4 enforcement (unsigned requests are rejected with 403) but not the GitHub OIDC role's per-path scoping, which is validated from the consuming GitHub Actions workflow.

#### Mock Testing

For testing in dev/build environments, mock services are available:

##### Mock JWKS Endpoint

Retrieve Firebase App Check public keys for token verification:

```bash
curl https://mock.verifier-ca.dev.account.gov.uk/mock-jwks
```

##### Mock Certificate Request Generator

Generate a complete mock certificate request with Firebase App Check token:

```bash
curl https://mock.verifier-ca.dev.account.gov.uk/mock-issue-cert-request
```

This returns a JSON payload containing:

- `headers`: Object with `X-Firebase-AppCheck` JWT token
- `body`: Object with `csrPem` (Certificate Signing Request)

You can use this payload directly to test the `/issue-reader-cert` endpoint.

### AWS Environment Setup

#### Deployment

The service automatically configures the Firebase App Check JWKS endpoint used
when `ENABLE_FIREBASE_APP_CHECK_JWT_VALIDATION` is enabled (see [Feature Flags](#feature-flags)).
While the flag is disabled, as it currently is in every environment, this JWKS
endpoint is not used:

- **Dev/Build environments**: mock JWKS endpoint
- **Production environments**: official Firebase App Check JWKS endpoint

#### Issuing CA ARN (resolved from SSM)

The issuing CA ARN (published by the `govchk-ca` stack) is read from SSM at deploy time via a
`{{resolve:ssm:...}}` dynamic reference in `application.yaml`, used for the Lambda's CA ARN env var and
the ACM PCA IAM policy. See the template for the exact parameter path and names.

**ca-back does not pick up a replaced CA automatically.** If the CA is replaced, its ARN changes in
SSM, but a plain redeploy is a no-op (SAM doesn't see the resolved value change, so no new Lambda
version is published and the `live` alias keeps the old ARN).

To adopt the new CA, force a new version by deploying a real change. Then check the `live` alias
points at a version with the new ARN.

#### AWS Secrets Manager

The mock infrastructure stores keys in AWS Secrets Manager:

- `<stack-name>-mock-device-keys`: ECDSA P-384 key pair for CSR generation
- `<stack-name>-mock-firebase-appcheck-keys`: RSA 2048 key pair for Firebase App Check JWT signing

**Note**: Ensure your AWS credentials have access to Secrets Manager in the `eu-west-2` region.

### Deploy a Feature Branch

1. Push your feature branch to the remote repository.
2. Go to **Actions** > **Feature Branch Deploy** in GitHub.
3. Click **Run workflow**, select your feature branch, and optionally enable monitoring:

**Input parameter** `enable_monitoring` - Defaults to `false`.
Set to `true` to enable CloudWatch monitoring on the deployed stacks.

4. The workflow will:
   - Derive the stack identifier from the branch name
   - Build and validate both SAM templates
   - Deploy `ca-base-<branch>`
   - Deploy `ca-back-<branch>` (Lambda functions and API Gateway)

### Clean Up a Feature Branch

Cleanup happens **automatically** when the pull request is closed (or merged).
The workflow uses the PR's head branch name to derive the same stack identifier that was used during deployment.
Manual cleanup is also supported by running the `cleanup-feature-branch` workflow from
GitHub Actions and providing the branch name as an input parameter.
