import { APIGatewayProxyEventHeaders } from 'aws-lambda';
import { getHeader } from '../common/request/header/header.ts';
import { errorResult, Result, successResult } from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';

export function validateEvent(
  eventHeaders: APIGatewayProxyEventHeaders,
  eventBody: string | null,
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

  if (!eventBody) {
    const errorMessage = 'Body missing from event';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  let parsedEventBody;
  try {
    parsedEventBody = JSON.parse(eventBody);
  } catch {
    const errorMessage = 'Event body cannot be parsed';
    logger.error(LogMessage.ISSUE_READER_CERT_INVALID_EVENT, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }
  console.log(parsedEventBody);

  return successResult(firebaseAppCheckHeader);
}
