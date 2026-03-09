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

  static readonly ISSUE_READER_CERT_INVALID_EVENT = new LogMessage(
    'MOBILE_CA_ISSUE_READER_CERT_INVALID_EVENT',
    'Incoming event invalid',
  );

  static readonly ISSUE_READER_CERT_COMPLETED = new LogMessage(
    'MOBILE_CA_ISSUE_READER_CERT_COMPLETED',
    'Lambda handler processing has completed.',
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

  // Verify JWT logs
  static readonly JWT_VERIFICATION_FAILURE = new LogMessage(
    'MOBILE_CA_JWT_VERIFICATION_FAILURE',
    'JWT sub is not in the list of allowed App IDs',
  );

  // Mock logs
  static readonly MOCK_ISSUE_CERT_REQUEST_INVALID_CONFIG = new LogMessage(
    'MOBILE_CA_MOCK_ISSUE_CERT_INVALID_CONFIG',
    'One or more required environment variables were missing or invalid.',
  );

  static readonly MOCK_JWKS_INVALID_CONFIG = new LogMessage(
    'MOBILE_CA_MOCK_JWKS_INVALID_CONFIG',
    'One or more required environment variables were missing or invalid.',
  );

  static readonly MOCK_JWKS_GENERATION_ERROR = new LogMessage(
    'MOBILE_CA_MOCK_JWKS_GENERATION_ERROR',
    'An error occurred while generating mock JWKS.',
  );

  static readonly MOCK_JWKS_STARTED = new LogMessage(
    'MOBILE_CA_MOCK_JWKS_STARTED',
    'Mock JWKS endpoint handler processing has started.',
  );

  static readonly MOCK_ISSUE_CERT_REQUEST_STARTED = new LogMessage(
    'MOBILE_CA_MOCK_ISSUE_CERT_REQUEST_STARTED',
    'Mock issue certificate request handler processing has started.',
  );

  static readonly MOCK_ISSUE_CERT_REQUEST_ERROR = new LogMessage(
    'MOBILE_CA_MOCK_ISSUE_CERT_REQUEST_ERROR',
    'An error occurred while generating mock certificate request.',
  );
}
