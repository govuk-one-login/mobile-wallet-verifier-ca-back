import {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda';
import { describe, it, beforeEach, expect, MockInstance, vi } from 'vitest';
import { handlerConstructor } from './issue-reader-cert-handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';
import { IssueReaderCertDependencies } from './issue-reader-cert-handler-dependencies.ts';
import {
  buildLambdaContext,
  buildRequest,
} from '../../../tests/testUtils/buildRequest.ts';
import { ErrorCategory, errorResult } from '../common/result/result.ts';

let consoleInfoSpy: MockInstance;
let consoleErrorSpy: MockInstance;

describe('Handler', () => {
  let event: APIGatewayProxyEvent;
  let context: Context;
  let dependencies: IssueReaderCertDependencies;
  let result: APIGatewayProxyResult;
  const env = {
    FIREBASE_JWKS_URI: 'https://mockFirebaseJwksUri.com/',
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

    it('Adds context, version and to log attributes and logs STARTED message', () => {
      expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_ISSUE_READER_CERT_STARTED',
        functionVersion: '1',
        function_arn: 'arn:12345', // example field to verify that context has been added
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
            messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_CONFIG',
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

    describe('Given FIREBASE_JWKS_URI is not a valid URL', () => {
      beforeEach(async () => {
        dependencies.env = JSON.parse(JSON.stringify(env));
        dependencies.env['FIREBASE_JWKS_URI'] = 'mockInvalidUrl';
        result = await handlerConstructor(dependencies, event, context);
      });

      it('logs INVALID_CONFIG', async () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_CONFIG',
          errorMessage: 'FIREBASE_JWKS_URI is not a valid URL',
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
    });
  });

  describe('Event validation', () => {
    describe('Given headers are invalid', () => {
      describe.each([
        {
          scenario: 'Given there are no headers in the event',
          headers: undefined,
        },
        {
          scenario:
            'Given X-Firebase-AppCheck header is not present in the event',
          headers: { mockHeader: 'mockValue' },
        },
        {
          scenario: 'Given X-Firebase-AppCheck header is an empty string',
          headers: { 'X-Firebase-AppCheck': '' },
        },
        {
          scenario:
            'Given X-Firebase-AppCheck header is an empty string with whitespace',
          headers: { 'X-Firebase-AppCheck': '  ' },
        },
      ])('$scenario', ({ headers }) => {
        beforeEach(async () => {
          const invalidEvent = buildRequest({ headers });
          result = await handlerConstructor(
            dependencies,
            invalidEvent,
            context,
          );
        });

        it('Log an INVALID_EVENT error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_EVENT',
            errorMessage: 'X-Firebase-AppCheck header missing from event',
          });
        });

        it('Return 401 Unauthorized response', () => {
          expect(result).toStrictEqual({
            headers: { 'Content-Type': 'application/json' },
            statusCode: 401,
            body: JSON.stringify({
              error: 'unauthorized',
              error_description:
                'Authentication failed (App Check token missing or invalid)',
            }),
          });
        });
      });
    });
  });

  describe('JWT verification', () => {
    describe('JWT verification failed with client error', () => {
      beforeEach(async () => {
        dependencies.verifyJwt = vi.fn().mockResolvedValue(
          errorResult({
            errorCategory: ErrorCategory.CLIENT_ERROR,
            errorMessage: 'Mock Client Error Message',
          }),
        );
        result = await handlerConstructor(dependencies, event, context);
      });
      it('Should return 401', () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 401,
          body: JSON.stringify({
            error: 'unauthorized',
            error_description: 'Mock Client Error Message',
          }),
        });
      });
    });

    describe('JWT verification failed with server error', () => {
      beforeEach(async () => {
        dependencies.verifyJwt = vi.fn().mockResolvedValue(
          errorResult({
            errorCategory: ErrorCategory.SERVER_ERROR,
            errorMessage: 'Mock Server Error Message',
          }),
        );
        result = await handlerConstructor(dependencies, event, context);
      });
      it('Should return 500', () => {
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
  });

  describe('WIP happy path tests', () => {
    describe('Given a valid event', () => {
      beforeEach(async () => {
        const validEvent = buildRequest({
          headers: {
            'X-Firebase-AppCheck': 'mockXFirebaseAppCheckHeaderValue',
          },
        });
        result = await handlerConstructor(dependencies, validEvent, context);
      });

      it('Logs COMPLETED', () => {
        expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_COMPLETED',
        });
      });

      it('Returns 200 OK response', () => {
        expect(result).toStrictEqual({
          statusCode: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Request-Id': context.awsRequestId,
          },
          body: 'Ok',
        });
      });
    });
  });
});
