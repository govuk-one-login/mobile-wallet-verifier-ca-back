# mobile-wallet-verifier-ca-back

## Overview

This Repository contains two services (lambda functions) to operate a private certificate authority (CA). These two services are to verify a reader authentication by issuing a short-lived certificate (valid for approximately 24 Hrs) to access credentials from a Holder App.

### Lambda Functions

#### Nonce Service (`/nonce`)

Generates cryptographically secure, single-use nonces for replay protection. Each nonce:

- Is a UUID v4 (36 characters)
- Has a 5-minute TTL in DynamoDB
- Can only be consumed once by the certificate issuance service

#### Issue Reader Certificate Service (`/issue-reader-cert`)

Issues short-lived X.509 reader certificates (24-hours validity) after verifying:

- **iOS**: Apple App Attest (keyId, attestation object, client data)
- **Android**: Google Play Integrity + Key Attestation chains
- Nonce consumption (prevents replay attacks)
- Certificate Signing Request (CSR) validation

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

## Quality Gates

Pre merge checks are documented in our quality gates [manifest](quality-gate.manifest.json) to align with the One Login quality gates schema. This is used to track which automated checks run before merging.

## Quickstart

### Install dependencies

```
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

#### Mock Certificate Generation

For testing Android attestation flows, you can generate mock certificates and attestation data:

##### Setup Android Infrastructure

First, set up the required keys and certificates in AWS Secrets Manager:

```bash
npm run setup:android
```

This creates:

- Device keys (ECDSA P-256) for Android attestation
- Play Integrity signing keys (ECDSA P-256)
- Root CA certificate and keys
- Intermediate CA keys

##### Generate Mock Request

Generate a complete mock Android attestation request:

```bash
# Generate with specific nonce
npm run mock:cert your-nonce-value
```

This outputs a JSON payload containing:

- `csrPem`: Certificate signing request
- `keyAttestationChain`: Android key attestation certificate chain (DER format, base64 encoded)
- `playIntegrityToken`: Signed Play Integrity JWT token
- `nonce`: Challenge nonce (random UUID or provided value)
- `platform`: "android"

### AWS Environment Setup

#### Environment Variables

The certificate issuer service uses these environment variables:

- `ALLOW_TEST_TOKENS`: Set to `'true'` in dev environment to skip Play Integrity signature verification
- `EXPECTED_ANDROID_PACKAGE_NAME`: Android app package name for validation (default: `org.multipaz.identityreader`)
- `NONCE_TABLE_NAME`: DynamoDB table for nonce storage

#### Deployment

The service automatically configures:

- **Dev environment**: `ALLOW_TEST_TOKENS=true` (allows mock Play Integrity tokens)
- **Production environments**: `ALLOW_TEST_TOKENS=false` (enforces Google JWKS verification)

#### AWS Secrets Manager

The mock infrastructure stores keys in AWS Secrets Manager with these secret names:

- `android-device-keys-`: Device ECDSA P-256 key pair
- `android-play-integrity-keys-`: Play Integrity ECDSA P-256 key pair
- `android-root-ca-`: Root CA certificate and key pair
- `android-intermediate-ca-`: Intermediate CA key pair

**Note**: Ensure your AWS credentials have access to Secrets Manager in the `eu-west-2` region.
