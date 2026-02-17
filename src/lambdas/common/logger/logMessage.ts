import { LogAttributes } from '@aws-lambda-powertools/logger/types';

export class LogMessage implements LogAttributes {
  private constructor(
    public readonly messageCode: string,
    public readonly message: string,
  ) {}

  [key: string]: string; // Index signature needed to implement LogAttributes

  static readonly ISSUE_READER_CERT_SERVICE_STARTED = new LogMessage(
    'MOBILE_CA_ISSUE_READER_CERT_SERVICE_STARTED',
    'Lambda handler processing has started.',
  );
}
