import { LogAttributes } from '@aws-lambda-powertools/logger/types';

export class LogMessage implements LogAttributes {
  static readonly VERIFIER_CERT_ISSUER_STARTED = new LogMessage(
    'VERIFIER_CERT_ISSUER_STARTED',
    'Verifier Certificate Issuer Lambda has started.',
    'N/A',
  );
  static readonly VERIFIER_CERT_ISSUER_CONFIGURATION_FAILED = new LogMessage(
    'VERIFIER_CERT_ISSUER_CONFIGURATION_FAILED',
    'Verifier Certificate Issuer Lambda environment variable configuration is incorrect',
    'Unable is issue Verifier Certificate',
  );
  static readonly VERIFIER_CERT_ISSUER_CONFIGURATION_SUCCESS = new LogMessage(
    'VERIFIER_CERT_ISSUER_CONFIGURATION_SUCCESS',
    'Verifier Certificate Issuer Lambda successfully configured',
    'N/A',
  );
  static readonly VERIFIER_CERT_ISSUER_CERTIFICATE_ALREADY_EXISTS = new LogMessage(
    'VERIFIER_CERT_ISSUER_CERTIFICATE_ALREADY_EXISTS',
    'Verifier Certificate Issuer aborted since a certificate already exists for this KMS key',
    'Unable to issue certificate - either use the existing certificate or create a new KMS key',
  );
  static readonly VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUE_FAILED = new LogMessage(
    'VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUE_FAILED',
    'Verifier Certificate Issuer was unable to issue a certificate',
    'Investigate log messages for further details',
  );
  static readonly VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUED = new LogMessage(
    'VERIFIER_CERT_ISSUER_CERTIFICATE_ISSUED',
    'Verifier Certificate Issuer successfully issued a new certificate',
    'N/A',
  );
  static readonly ROOT_CERTIFICATE_ALREADY_EXISTS = new LogMessage(
    'ROOT_CERTIFICATE_ALREADY_EXISTS',
    'Root certificate already in S3 bucket',
    'N/A',
  );
  static readonly ROOT_CERTIFICATE_UPLOADED = new LogMessage(
    'ROOT_CERTIFICATE_ALREADY_EXISTS',
    'Root certificate was uploaded to S3 bucket',
    'N/A',
  );
  private constructor(
    public readonly messageCode: string,
    public readonly message: string,
    public readonly userImpact: string,
  ) {}

  [key: string]: string; // Index signature needed to implement LogAttributesWithMessage
}
