import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger.ts';
import { generateJWKS } from './jwks-generator.ts';
import {
  dependencies,
  MockJwksHandlerDependencies,
} from './mock-jwks-handler-dependencies.ts';
import { getMockJwksConfig } from './mock-jwks-config.ts';

export const handlerConstructor = async (
  dependencies: MockJwksHandlerDependencies,
  _event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);

  logger.info('Mock JWKS endpoint called', {
    path: _event.path,
    method: _event.httpMethod,
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

  if (_event.httpMethod !== 'GET' || _event.path !== '/mock-jwks') {
    logger.warn('Invalid request', {
      httpMethod: _event.httpMethod,
      path: _event.path,
    });
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Not found' }),
    };
  }

  try {
    logger.info('Generating JWKS');
    const jwks = await generateJWKS();

    logger.info('JWKS generated successfully', { keysCount: jwks.keys.length });

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
    logger.error('Error in JWKS handler', { error });
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};

export const handler = handlerConstructor.bind(null, dependencies);
