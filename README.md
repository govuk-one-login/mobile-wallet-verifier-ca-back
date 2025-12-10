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

- [Node.js](https://nodejs.org/en) version 22 or higher (use the provided `.nvmrc` file with [nvm](https://github.com/nvm-sh/nvm) for easy version management)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html) for deployment

## Quickstart

### Install dependencies

```
npm install
```

### Test

#### Unit Tests

Run unit tests to test functionality of individual functions:

```
npm run test
```
