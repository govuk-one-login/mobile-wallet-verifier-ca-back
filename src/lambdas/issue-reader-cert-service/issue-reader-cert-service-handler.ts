import type { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { setupLogger } from '../common/logger/setupLogger';
import { LogMessage } from '../common/logger/logMessage';
import { logger } from '../common/logger/logger';

export const handler = async (
  _event: APIGatewayProxyEvent,
  context: Context,
): Promise<void> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_SERVICE_STARTED);
};
