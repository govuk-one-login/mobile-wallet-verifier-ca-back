import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger';
import { LogMessage } from '../common/logger/log-message';
import {
  dependencies,
  IssueReaderCertDependencies,
} from './issue-reader-cert-handler-dependencies.ts';
import { getIssueReaderCertConfig } from './issue-reader-cert-config.ts';
import { validateEvent } from './validate-event.ts';
import { ExpectedJwtData } from './verify-jwt/verify-jwt.ts';
import { ErrorCategory } from '../common/result/result.ts';

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

  const config = configResult.value;

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
  const jwt = validateEventResult.value;
  const jwtData: ExpectedJwtData = {
    algorithm: config.ALGORITHM,
    allowedAppId: config.ALLOWED_APP_ID,
    audience: config.ALLOWED_APP_ID,
    issuer: config.ISSUER,
  };
  const verifyJwtResult = await dependencies.verifyJwt(
    jwt,
    config.FIREBASE_JWKS_URI,
    jwtData,
  );
  if (verifyJwtResult.isError) {
    if (verifyJwtResult.value.errorCategory === ErrorCategory.SERVER_ERROR) {
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
      headers: { 'Content-Type': 'application/json' },
      statusCode: 401,
      body: JSON.stringify({
        error: 'unauthorized',
        error_description: verifyJwtResult.value.errorMessage,
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
