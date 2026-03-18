import { APIGatewayProxyEventHeaders } from 'aws-lambda';
import { getHeader } from '../common/request/header/header.ts';
import { errorResult, Result, successResult } from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';

interface ValidEventData {
  firebaseAppCheckHeader: string;
  csrPem: string;
}
export function validateEvent(
  eventHeaders: APIGatewayProxyEventHeaders,
  eventBody: string | null,
): Result<ValidEventData, string> {
  const validateAppCheckHeaderResult =
    validateEventAppCheckHeader(eventHeaders);
  if (validateAppCheckHeaderResult.isError) {
    return validateAppCheckHeaderResult;
  }
  const firebaseAppCheckHeader = validateAppCheckHeaderResult.value;

  const validateEventBodyResult = validateEventBody(eventBody);
  if (validateEventBodyResult.isError) {
    return validateEventBodyResult;
  }
  const csrPem = validateEventBodyResult.value;

  return successResult({
    firebaseAppCheckHeader,
    csrPem,
  });
}

function validateEventAppCheckHeader(
  eventHeaders: APIGatewayProxyEventHeaders,
): Result<string, string> {
  const firebaseAppCheckHeader = getHeader(
    eventHeaders ?? {},
    'X-Firebase-AppCheck',
  );
  if (!firebaseAppCheckHeader?.trim()) {
    const errorMessage = 'X-Firebase-AppCheck header missing from event';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  return successResult(firebaseAppCheckHeader);
}

function validateEventBody(eventBody: string | null): Result<string, string> {
  if (!eventBody) {
    const errorMessage = 'Event body is null';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  let parsedEventBody: unknown;
  try {
    parsedEventBody = JSON.parse(eventBody);
  } catch {
    const errorMessage = 'Event body cannot be parsed';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (
    typeof parsedEventBody !== 'object' ||
    parsedEventBody === null ||
    Array.isArray(parsedEventBody)
  ) {
    const errorMessage = 'Event body is not a JSON object';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (!('csrPem' in parsedEventBody)) {
    const errorMessage = 'Event body missing csrPem';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (typeof parsedEventBody.csrPem !== 'string') {
    const errorMessage = 'Event body csrPem is not a string';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (!parsedEventBody.csrPem.trim()) {
    const errorMessage = 'Event body csrPem is an empty string';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  return successResult(parsedEventBody.csrPem);
}
