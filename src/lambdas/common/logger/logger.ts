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
      assumedRole: getAssumedRole(userArn),
    },
  });
};

// Extracts the "role-name/session-name" portion from an assumed-role ARN; falls back to the full ARN if the marker is absent, or null if no ARN.
const getAssumedRole = (userArn: string | null): string | null => {
  if (!userArn) {
    return null;
  }
  const [, assumedRole] = userArn.split('assumed-role/');
  return assumedRole ?? userArn;
};
