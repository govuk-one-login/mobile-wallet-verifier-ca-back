# mobile-wallet-verifier-ca-back

## Overview

This Repository contains a service (lambda function) to operate a private certificate authority (CA). The service verifies reader authentication by issuing a short-lived certificate (valid for approximately 24 Hrs) to access credentials from a Holder App. Mock services are also provided for dev/build environments.

### Lambda Functions

#### Issue Reader Certificate Service (`/issue-reader-cert`)

Issues short-lived X.509 reader certificates (24-hours validity) after verifying:

- Firebase App Check token (via `X-Firebase-AppCheck` header)
- Certificate Signing Request (CSR) validation

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

These integration tests are implemented with Cucumber and exercise the deployed API end to end against the main build environment using the mock services.

The Cucumber feature files and step definitions live under `tests/integrationTests`.

Run the integration tests:

```bash
npm run test:integration
```

Current limitation: these tests are currently wired to the main build stack only. Support for running the integration tests against the dev environment will be added in a future iteration.

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

The service automatically configures:

- **Dev/Build environments**: Uses mock JWKS endpoint for Firebase App Check token verification
- **Production environments**: Uses official Firebase App Check JWKS endpoint

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
