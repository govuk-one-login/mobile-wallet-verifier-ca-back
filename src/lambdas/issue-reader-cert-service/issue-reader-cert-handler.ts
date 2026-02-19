import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { setupLogger } from '../common/logger/setup-logger';
import { LogMessage } from '../common/logger/log-message';
import { logger } from '../common/logger/logger';
import {
  dependencies,
  IssueReaderCertDependencies,
} from './handler-dependencies.ts';
import { getIssueReaderCertConfig } from './issue-reader-cert-config.ts';

export const handlerConstructor = async (
  dependencies: IssueReaderCertDependencies,
  _event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_STARTED);

  const envResult = getIssueReaderCertConfig(dependencies.env);
  if (envResult.isError) {
    return {
      headers: { 'Content-Type': 'application/json' },
      statusCode: 500,
      body: JSON.stringify({
        error: 'server_error',
        error_description: 'Server Error',
      }),
    };
  }

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'X-Request-Id': context.awsRequestId,
    },
    body: 'Ok',
  };
};

export const handler = handlerConstructor.bind(null, dependencies);
