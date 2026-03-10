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
import {
  okResponse,
  serverErrorResponse,
  unauthorizedResponse,
} from '../common/lambda-responses/lambda-responses.ts';

export const handlerConstructor = async (
  dependencies: IssueReaderCertDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_STARTED);

  const configResult = getIssueReaderCertConfig(dependencies.env);
  if (configResult.isError) {
    return serverErrorResponse;
  }
  const config = configResult.value;

  const validateEventResult = validateEvent(event.headers);
  if (validateEventResult.isError) {
    return unauthorizedResponse(
      'Authentication failed (App Check token missing or invalid)',
    );
  }
  const jwt = validateEventResult.value;

  const expectedJwtData: ExpectedJwtData = {
    algorithm: config.ALGORITHM,
    allowedAppId: config.ALLOWED_APP_ID,
    audience: config.ALLOWED_APP_ID,
    issuer: config.ISSUER,
  };
  const verifyJwtResult = await dependencies.verifyJwt(
    jwt,
    config.FIREBASE_JWKS_URI,
    expectedJwtData,
  );
  if (verifyJwtResult.isError) {
    if (verifyJwtResult.value.errorCategory === ErrorCategory.SERVER_ERROR) {
      return serverErrorResponse;
    }
    return unauthorizedResponse(verifyJwtResult.value.errorMessage);
  }

  logger.info(LogMessage.ISSUE_READER_CERT_COMPLETED);
  return okResponse(context.awsRequestId);
};

export const handler = handlerConstructor.bind(null, dependencies);
