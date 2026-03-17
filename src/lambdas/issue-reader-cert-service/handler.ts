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
import {
  emptySuccess,
  ErrorCategory,
  errorResult,
  Result,
} from '../common/result/result.ts';
import {
  badRequestResponse,
  okResponse,
  serverErrorResponse,
  unauthorizedResponse,
} from '../common/lambda-responses/lambda-responses.ts';
import {
  BasicConstraintsExtension,
  Pkcs10CertificateRequest,
} from '@peculiar/x509';

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
  const jwt = validateEventResult.value.firebaseAppCheckHeader;

  const expectedAppCheckJwtData: ExpectedAppCheckJwtData = {
    algorithm: config.ALGORITHM,
    allowedAppIds: config.ALLOWED_APP_IDS,
    audience: config.AUDIENCE,
    issuer: config.ISSUER,
  };
  const verifyAppCheckJwtResult = await dependencies.verifyAppCheckJwt(
    jwt,
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

  const validateCsrResult = await validateCSR(validateEventResult.value.csrPem);
  if (validateCsrResult.isError) {
    return badRequestResponse(validateCsrResult.value);
  }

  logger.info(LogMessage.ISSUE_READER_CERT_COMPLETED);
  return okResponse(context.awsRequestId);
};

export const handler = handlerConstructor.bind(null, dependencies);

const BASIC_CONSTRAINTS_OID = '2.5.29.19';
export async function validateCSR(
  csrPem: string,
): Promise<Result<void, string>> {
  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(csrPem);
  } catch (error: unknown) {
    const errorMessage = 'CSR not valid PKCS#10 request';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      error,
    });
    return errorResult(errorMessage);
  }

  try {
    const validSignedCsr = await csr.verify();
    if (!validSignedCsr) {
      const errorMessage = 'CSR self signature verification failed';
      logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
        errorMessage,
      });
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'CSR self signature verification failed';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      error,
    });
    return errorResult(errorMessage);
  }

  const csrPublicKeyAlgorithm = csr.publicKey.algorithm;
  if (csrPublicKeyAlgorithm.name !== 'ECDSA') {
    const errorMessage = 'CSR public key not EC key';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (
    !('namedCurve' in csrPublicKeyAlgorithm) ||
    csrPublicKeyAlgorithm.namedCurve !== 'P-256'
  ) {
    const errorMessage = 'CSR public key does not use P-256 curve';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  const basicConstraints = csr.getExtension(BASIC_CONSTRAINTS_OID);
  if (
    basicConstraints instanceof BasicConstraintsExtension &&
    basicConstraints.ca
  ) {
    const errorMessage = 'CSR requests CA capabilities';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}
