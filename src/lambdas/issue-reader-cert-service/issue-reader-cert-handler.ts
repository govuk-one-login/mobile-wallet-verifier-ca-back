import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { setupLogger, logger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import {
  dependencies,
  IssueReaderCertDependencies,
} from './issue-reader-cert-handler-dependencies.ts';
import { getIssueReaderCertConfig } from './issue-reader-cert-config.ts';
import { validateEvent } from './validate-event.ts';

export const handlerConstructor = async (
  dependencies: IssueReaderCertDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_STARTED);

  const configResult = getIssueReaderCertConfig(dependencies.env);
  if (configResult.isError) {
    return {
      headers: { 'Content-Type': 'application/json' },
      statusCode: 500,
      body: JSON.stringify({
        error: 'server_error',
        error_description: 'Server Error',
      }),
    };
  }

  const validateEventResult = validateEvent(event.headers);
  if (validateEventResult.isError) {
    return {
      headers: { 'Content-Type': 'application/json' },
      statusCode: 401,
      body: JSON.stringify({
        error: 'unauthorized',
        error_description:
          'Authentication failed (App Check token missing or invalid)',
      }),
    };
  }

  logger.info(LogMessage.ISSUE_READER_CERT_COMPLETED);

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
