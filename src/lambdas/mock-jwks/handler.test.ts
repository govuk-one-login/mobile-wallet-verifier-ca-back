import {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda';
import { describe, it, beforeEach, expect, MockInstance, vi } from 'vitest';
import { handlerConstructor } from './handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';
import { MockJwksHandlerDependencies } from './handler-dependencies';
import {
  buildLambdaContext,
  buildEvent,
} from '../../../tests/testUtils/build-event';
import * as jwksGenerator from './jwks-generator';

vi.mock('./jwks-generator');

let consoleInfoSpy: MockInstance;
let consoleErrorSpy: MockInstance;

describe('Mock JWKS Handler', () => {
  let event: APIGatewayProxyEvent;
  let context: Context;
  let dependencies: MockJwksHandlerDependencies;
  let result: APIGatewayProxyResult;
  const env = {
    FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-appcheck-keys',
  };

  beforeEach(() => {
    consoleInfoSpy = vi.spyOn(console, 'info');
    consoleErrorSpy = vi.spyOn(console, 'error');
    context = buildLambdaContext();
    event = buildEvent();
    dependencies = {
      env,
    };
    vi.mocked(jwksGenerator.generateJWKS).mockResolvedValue({
      keys: [
        {
          kty: 'RSA',
          use: 'sig',
          kid: 'firebase-appcheck-debug',
          alg: 'RS256',
          n: 'mock-n',
          e: 'AQAB',
        },
      ],
    });
  });

  describe('On every invocation', () => {
    it('Adds context, version, logs STARTED message and clears pre-existing log attributes', async () => {
      logger.appendKeys({ testKey: 'testValue' });
      await handlerConstructor(dependencies, event, context);

      expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_MOCK_JWKS_STARTED',
        functionVersion: '1',
        function_arn: 'arn:12345',
      });
      expect(consoleInfoSpy).not.toHaveBeenCalledWithLogFields({
        testKey: 'testValue',
      });
    });
  });

  describe('Config validation', () => {
    it('logs INVALID_CONFIG and returns 500 Internal server error when environment variable is missing', async () => {
      dependencies.env = {};
      result = await handlerConstructor(dependencies, event, context);

      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_MOCK_JWKS_INVALID_CONFIG',
        data: {
          missingEnvironmentVariables: ['FIREBASE_APPCHECK_JWKS_SECRET'],
        },
      });
      expect(result).toStrictEqual({
        headers: { 'Content-Type': 'application/json' },
        statusCode: 500,
        body: JSON.stringify({
          error: 'server_error',
          error_description: 'Server Error',
        }),
      });
    });
  });

  describe('Success', () => {
    beforeEach(async () => {
      result = await handlerConstructor(dependencies, event, context);
    });

    it('returns 200 with JWKS', () => {
      expect(result).toStrictEqual({
        statusCode: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=3600',
          'Access-Control-Allow-Origin': '*',
        },
        body: JSON.stringify({
          keys: [
            {
              kty: 'RSA',
              use: 'sig',
              kid: 'firebase-appcheck-debug',
              alg: 'RS256',
              n: 'mock-n',
              e: 'AQAB',
            },
          ],
        }),
      });
    });
  });

  describe('Error handling', () => {
    beforeEach(async () => {
      vi.mocked(jwksGenerator.generateJWKS).mockRejectedValue(
        new Error('JWKS generation failed'),
      );
      result = await handlerConstructor(dependencies, event, context);
    });

    it('logs MOCK_JWKS_GENERATION_ERROR and returns 500 Internal server error', () => {
      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_MOCK_JWKS_GENERATION_ERROR',
        data: { error: 'JWKS generation failed' },
      });
      expect(result).toStrictEqual({
        statusCode: 500,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Internal server error' }),
      });
    });
  });
});
