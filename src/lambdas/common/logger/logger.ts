import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayEventIdentity, Context } from 'aws-lambda';

export const logger = new Logger();

export const setupLogger = (context: Context) => {
  logger.resetKeys();
  logger.addContext(context);
  logger.appendKeys({
    functionVersion: context.functionVersion,
  });
};

export const appendEventIdentityToLogger = (
  eventIdentity: APIGatewayEventIdentity,
): void => {
  const { userAgent, userArn } = eventIdentity;
  logger.appendKeys({
    eventIdentity: {
      userAgent,
      userArn,
    },
  });
};

export const appendIssuedReaderCertificateDetailsToLogger = (
  certificateArn: string,
): void => {
  logger.appendKeys({
    issuedReaderCertificateDetails: {
      certificateArn,
      certificateSerial: certificateArn.split('/').pop(),
    },
  });
};
