import { Logger } from '@aws-lambda-powertools/logger';
import { Context } from 'aws-lambda';

export const logger = new Logger();

export const setupLogger = (context: Context) => {
  logger.resetKeys();
  logger.addContext(context);
  logger.appendKeys({
    functionVersion: context.functionVersion,
  });
};
