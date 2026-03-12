import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';
import { generateJWKS } from './jwks-generator.ts';
import {
  dependencies,
  MockJwksHandlerDependencies,
} from './handler-dependencies.ts';
import { getMockJwksConfig } from './config.ts';

export const handlerConstructor = async (
  dependencies: MockJwksHandlerDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);

  logger.info(LogMessage.MOCK_JWKS_STARTED, {
    data: { path: event.path, method: event.httpMethod },
  });

  const configResult = getMockJwksConfig(dependencies.env);
  if (configResult.isError) {
    return {
      headers: { 'Content-Type': 'application/json' },
      statusCode: 500,
      body: JSON.stringify({
        error: 'server_error',
        error_description: 'Server Error',
      }),
    };
  }

  try {
    const jwks = await generateJWKS(
      configResult.value.FIREBASE_APPCHECK_JWKS_SECRET,
    );

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600', // Cache for 1 hour
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify(jwks),
    };
  } catch (error) {
    logger.error(LogMessage.MOCK_JWKS_GENERATION_ERROR, {
      data: { error: error instanceof Error ? error.message : error },
    });
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};

export const handler = handlerConstructor.bind(null, dependencies);
