import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { FirebaseAppCheckSigner } from '../mock-utils/firebase-appcheck-signer';

const logger = new Logger();

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info('JWKS handler started', {
    httpMethod: event.httpMethod,
    path: event.path,
    headers: event.headers,
    region: process.env.AWS_REGION,
  });

  if (event.httpMethod !== 'GET' || event.path !== '/v1/jwks') {
    logger.warn('Invalid request', {
      httpMethod: event.httpMethod,
      path: event.path,
    });
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Not found' }),
    };
  }

  try {
    logger.info('Creating FirebaseAppCheckSigner');
    const signer = new FirebaseAppCheckSigner();

    logger.info('Generating JWKS');
    const jwks = await signer.generateJWKS();

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
    logger.error('Error in JWKS handler', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};
