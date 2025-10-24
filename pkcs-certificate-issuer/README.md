# mDL - Verifier Certificate Issuer

## Introduction

The template.yaml in this project deploys the following AWS resources:

- a Lambda function to issue an X.509 Verifier Certificate using an AWS Private CA instance deployed by the `platform-ca` CloudFormation stack in the account.
- The key material is generated in memory using `node:crypto` and the private key material is exported. Therefore this solution is **not suitable for use in a Production environment**.
- an S3 bucket to store the root certificate, the issued verifier certificates in PEM format and the associated private key material in PEM format so they can be accessed as required

## Pre-requisites

This stack can only be deployed into an account which already has the `platform-ca` CloudFormation stack deployed.
The dependency provides the AWS Private CA resource, root certificate and references to it as SSM parameters.

## Deploy

### Deploy with the AWS SAM CLI

Before deploying with the AWS SAM CLI, you must authenticate with AWS. Once authenticated, run the following commands:

1. Build the application:

```bash
sam build
```

2. Deploy to AWS:

```bash
sam deploy --guided --capabilities CAPABILITY_IAM --stack-name <your_stack_name>
```

## Invocation

The required input parameters for the issue certificate lambda are specified in environment variables and are deployed as part of this stack.
The issue certificate Lambda can be invoked through the AWS Console or via the AWS CLI using the following command in a shell which has active AWS credentials available:

```bash
% aws lambda invoke --function-name YOUR_STACK_NAME-issue-verifier-certificate output.txt
```

## Generating the PKCS file and viewing it
In order to generate the PKCS file we need to have the rootCA public key, privateKey and the certificate.pem file.
The certificate and the private key are stored in the S3 bucket that is created as part of this stack deployment.
The rootCA public key can be found by navigating to the private-ca cloudformation stack and viewing the certificate authority resource and making a copy of the public key. 

Once these files are with you, this command can be run to generate the pkcs .p12 file:

```bash
/usr/bin/openssl pkcs12 -export -out keyStore.p12 -inkey privateKey.pem -in certificate.pem -certfile rootCA.pem
```

This will prompt for a password. This can be skipped by pressing enter. 

In order to view this PKCS .p12 file, this openssl command can be run:

```bash
/usr/bin/openssl pkcs12 -info -in keyStore.p12 -nodes
```

This will prompt for a password, if no password is set then press enter. This will then display the certificate, rootCA and the private key.  

## Lifecycle

This template will issue one certificate for the generated key when the Lambda is invoked, by default this key will have a lifecycle of 458 days, approx 1 year and 3 months.
If the issuing Lambda is invoked again it will not issue a second or subsequent certificates for the same key ID.
To rotate a certificate a new key ID needs to be specified in the Lambda env vars.

## Output

The resulting certificates and private key material are stored in an S3 bucket with the key `<keyId>/certificate.pem` and `<keyId>/privateKey.pem`, where `<keyId>` is a key ID in the form of a UUIDv4 string.
`certificate.pem` is the canonical representation of the certificate and should be used in certificate path validation.
The root certificate is uploaded to the same bucket with the key `<privateCaId>/certificate.pem` where `<privateCaId>` is the certificate authority ID (in the form of a UUIDv4 string).
