import 'reflect-metadata';
import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';
import {
  dependencies,
  IssueReaderCertDependencies,
} from './handler-dependencies.ts';
import { getIssueReaderCertConfig } from './config.ts';
import { validateEvent } from './validate-event.ts';
import { ExpectedAppCheckJwtData } from './verify-app-check-jwt/verify-app-check-jwt.ts';
import { ErrorCategory } from '../common/result/result.ts';
import {
  badRequestResponse,
  okResponse,
  serverErrorResponse,
  unauthorizedResponse,
} from '../common/lambda-responses/lambda-responses.ts';
import { validateCsr } from './validate-csr.ts';

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

  const validateEventResult = validateEvent(event.headers, event.body);
  if (validateEventResult.isError) {
    return unauthorizedResponse(validateEventResult.value);
  }
  const { firebaseAppCheckJwt, csrPem } = validateEventResult.value;

  const expectedAppCheckJwtData: ExpectedAppCheckJwtData = {
    algorithm: config.ALGORITHM,
    allowedAppIds: config.ALLOWED_APP_IDS,
    audience: config.AUDIENCE,
    issuer: config.ISSUER,
  };
  const verifyAppCheckJwtResult = await dependencies.verifyAppCheckJwt(
    firebaseAppCheckJwt,
    config.FIREBASE_JWKS_URI,
    expectedAppCheckJwtData,
  );
  if (verifyAppCheckJwtResult.isError) {
    if (
      verifyAppCheckJwtResult.value.errorCategory === ErrorCategory.SERVER_ERROR
    ) {
      return serverErrorResponse;
    }
    return unauthorizedResponse(verifyAppCheckJwtResult.value.errorMessage);
  }

  const validateCsrResult = await validateCsr(csrPem);
  if (validateCsrResult.isError) {
    return badRequestResponse(validateCsrResult.value);
  }

  logger.info(LogMessage.ISSUE_READER_CERT_COMPLETED);
  return okResponse(context.awsRequestId);
};

export const handler = handlerConstructor.bind(null, dependencies);
