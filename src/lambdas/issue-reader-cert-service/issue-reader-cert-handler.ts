import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { setupLogger } from '../common/logger/setup-logger';
import { LogMessage } from '../common/logger/log-message';
import { logger } from '../common/logger/logger';
import { IssueReaderCertDependencies } from './handler-dependencies.ts';

export const handler = async (
  _event: APIGatewayProxyEvent,
  context: Context,
  dependencies: IssueReaderCertDependencies,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_STARTED);
};
