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
  IssueReaderCertResponseBody,
  okResponse,
  serverErrorResponse,
  unauthorizedResponse,
} from '../common/lambda-responses/lambda-responses.ts';
import { validateCsr } from './validate-csr.ts';
import { validateLeafCertificate } from '../common/validate-leaf-certificate/validate-leaf-certificate.ts';

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
  const csrSubjectCn = validateCsrResult.value;

  const certificateAuthorityArn = config.CERTIFICATE_AUTHORITY_ARN;

  const issueCertResult = await dependencies.issueCertificate({
    csrPem,
    certificateAuthorityArn,
  });
  if (issueCertResult.isError) {
    return serverErrorResponse;
  }

  const getCertResult = await dependencies.getCertificate({
    certificateArn: issueCertResult.value,
    certificateAuthorityArn,
  });
  if (getCertResult.isError) {
    return serverErrorResponse;
  }

  const { certificate, certificateChain } = getCertResult.value;
  const validateLeafResult = validateLeafCertificate(certificate, csrSubjectCn);
  if (validateLeafResult.isError) {
    return serverErrorResponse;
  }

  const response: IssueReaderCertResponseBody = {
    certChain: `${certificate}\n${certificateChain}`,
  };

  logger.info(LogMessage.ISSUE_READER_CERT_COMPLETED);
  return okResponse(context.awsRequestId, response);
};

export const handler = handlerConstructor.bind(null, dependencies);
