import {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda';
import { describe, it, beforeEach, expect, MockInstance, vi } from 'vitest';
import { handlerConstructor } from './mock-jwks-handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';
import { MockJwksHandlerDependencies } from './mock-jwks-handler-dependencies';
import {
  buildLambdaContext,
  buildRequest,
} from '../../../tests/testUtils/buildRequest';

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
    event = buildRequest();
    dependencies = {
      env,
    };
  });

  describe('On every invocation', () => {
    beforeEach(async () => {
      logger.appendKeys({ testKey: 'testValue' });
      await handlerConstructor(dependencies, event, context);
    });

    it('Adds context, version and logs STARTED message', () => {
      expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_MOCK_JWKS_STARTED',
        functionVersion: '1',
        function_arn: 'arn:12345',
      });
    });

    it('Clears pre-existing log attributes', async () => {
      expect(consoleInfoSpy).not.toHaveBeenCalledWithLogFields({
        testKey: 'testValue',
      });
    });
  });

  describe('Config validation', () => {
    describe.each(Object.keys(env))(
      'Given %s environment variable is missing',
      (envVar: string) => {
        beforeEach(async () => {
          dependencies.env = JSON.parse(JSON.stringify(env));
          // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
          delete dependencies.env[envVar];
          result = await handlerConstructor(dependencies, event, context);
        });

        it('logs INVALID_CONFIG', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_MOCK_JWKS_INVALID_CONFIG',
            data: {
              missingEnvironmentVariables: [envVar],
            },
          });
        });

        it('returns 500 Internal server error', async () => {
          expect(result).toStrictEqual({
            headers: { 'Content-Type': 'application/json' },
            statusCode: 500,
            body: JSON.stringify({
              error: 'server_error',
              error_description: 'Server Error',
            }),
          });
        });
      },
    );
  });
});
