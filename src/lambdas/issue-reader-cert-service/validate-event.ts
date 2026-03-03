import { APIGatewayProxyEventHeaders } from 'aws-lambda';
import { getHeader } from '../common/request/header/header.ts';
import {
  emptyFailure,
  Result,
  successResult,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';

export function validateEvent(
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
