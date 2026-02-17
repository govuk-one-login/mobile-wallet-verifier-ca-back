import type { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { setupLogger } from '../common/setupLogger';
import { LogMessage } from '../common/logMessage';
import { logger } from '../common/logger';

export const handler = async (
  _event: APIGatewayProxyEvent,
  context: Context,
): Promise<void> => {
  setupLogger(context);
  logger.info(LogMessage.ISSUE_READER_CERT_SERVICE_STARTED);
};
