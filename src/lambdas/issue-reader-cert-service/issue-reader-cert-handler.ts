import type {
  APIGatewayProxyEvent,
  APIGatewayProxyEventHeaders,
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
import {
  emptyFailure,
  Result,
  successResult,
} from '../common/result/result.ts';
import { getHeader } from '../common/request/header/header.ts';

export const handlerConstructor = async (
  dependencies: IssueReaderCertDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_STARTED);

  // Request validation function that checks header is there and is a string and returns it to lambda
  // in future commit, we will validate body as well

  // JWT validation function -- check format that it's {string.string.string}

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

function validateEvent(
  eventHeaders: APIGatewayProxyEventHeaders,
): Result<string, void> {
  const firebaseAppCheckHeader = getHeader(
    eventHeaders ?? {},
    'X-Firebase-AppCheck',
  );
  if (!firebaseAppCheckHeader || !firebaseAppCheckHeader.trim()) {
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage: 'X-Firebase-AppCheck header missing from event',
    });
    return emptyFailure();
  }
  return successResult(firebaseAppCheckHeader);
}

export const handler = handlerConstructor.bind(null, dependencies);
