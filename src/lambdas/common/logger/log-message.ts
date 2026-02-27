import { LogAttributes } from '@aws-lambda-powertools/logger/types';

export class LogMessage implements LogAttributes {
  private constructor(
    public readonly messageCode: string,
    public readonly message: string,
  ) {}

  [key: string]: string; // Index signature needed to implement LogAttributes

  // Issue Reader Cert lambda logs
  static readonly ISSUE_READER_CERT_STARTED = new LogMessage(
    'MOBILE_CA_ISSUE_READER_CERT_STARTED',
    'Lambda handler processing has started.',
  );

  static readonly ISSUE_READER_CERT_INVALID_CONFIG = new LogMessage(
    'MOBILE_CA_ISSUE_READER_CERT_INVALID_CONFIG',
    'One or more required environment variables were missing or invalid.',
  );

  // Get JWKS logs
  static readonly GET_JWKS_ATTEMPT = new LogMessage(
    'MOBILE_CA_GET_JWKS_ATTEMPT',
    'Attempting to retrieve jwks.',
  );

  static readonly GET_JWKS_FAILURE = new LogMessage(
    'MOBILE_CA_GET_JWKS_FAILURE',
    'An error occurred while calling jwks uri.',
  );

  static readonly MALFORMED_JWKS_RESPONSE = new LogMessage(
    'MOBILE_CA_MALFORMED_JWKS_RESPONSE',
    'The request of JWKS uri was successful but the response is not valid.',
  );

  static readonly GET_JWKS_SUCCESS = new LogMessage(
    'MOBILE_CA_GET_JWKS_SUCCESS',
    'JWKS retrieved successfully.',
  );
}
