import {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda';
import {
  describe,
  it,
  beforeEach,
  expect,
  MockInstance,
  vi,
  afterEach,
} from 'vitest';
import { handlerConstructor } from './issue-reader-cert-handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';
import { IssueReaderCertDependencies } from './issue-reader-cert-handler-dependencies.ts';
import {
  buildLambdaContext,
  buildRequest,
} from '../../../tests/testUtils/buildRequest.ts';
import { emptyFailure, successResult } from '../common/result/result.ts';
import { ExpectedJwtData, verifyJwt } from './verify-jwt/verify-jwt.ts';
import { InMemoryJwtReplayCache } from './verify-jwt/jwt-replay-cache.ts';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';
import {
  createKeyPair,
  createSignedJwt,
} from '../../../tests/testUtils/create-signed-jwt.ts';

describe('Handler', () => {
  let event: APIGatewayProxyEvent;
  let context: Context;
  let dependencies: IssueReaderCertDependencies;
  let result: APIGatewayProxyResult;
  const env = {
    ALGORITHM: 'RS256',
    ALLOWED_APP_IDS: JSON.stringify(['mockAppId']),
    AUDIENCE: JSON.stringify(['mockAudience']),
    FIREBASE_JWKS_URI: 'https://mockFirebaseJwksUri.com/',
    ISSUER: 'https://mockIssuer.com/',
  };
  let consoleInfoSpy: MockInstance;
  let consoleErrorSpy: MockInstance;
  let mockJwksCache: JwksCache;
  let privateKey: CryptoKey;
  let publicJwk: JWK;

  beforeEach(async () => {
    consoleInfoSpy = vi.spyOn(console, 'info');
    consoleErrorSpy = vi.spyOn(console, 'error');

    ({ privateKey, publicJwk } = await createKeyPair());

    mockJwksCache = {
      getJwks: vi.fn().mockResolvedValue(
        successResult({
          keys: [publicJwk],
        }),
      ),
    };

    const verifyJwtWithMockedJwksCache: IssueReaderCertDependencies['verifyJwt'] =
      vi.fn(
        (jwt: string, jwksUrl: string, expectedJwtData: ExpectedJwtData) => {
          return verifyJwt(jwt, jwksUrl, expectedJwtData, {
            jwksCache: mockJwksCache,
            jwtReplayCache: new InMemoryJwtReplayCache(),
          });
        },
      );

    const validFireBaseJwt = await createSignedJwt(privateKey, {
      audience: JSON.parse(env.AUDIENCE)[0],
      issuer: env.ISSUER,
      subject: JSON.parse(env.ALLOWED_APP_IDS)[0],
    });

    context = buildLambdaContext();
    event = buildRequest({
      headers: {
        'X-Firebase-AppCheck': validFireBaseJwt,
      },
    });

    dependencies = {
      env,
      verifyJwt: verifyJwtWithMockedJwksCache,
    };
  });

  afterEach(() => {
    vi.resetAllMocks();
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
              code: 'server_error',
              message: 'Server Error',
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
            code: 'server_error',
            message: 'Server Error',
          }),
        });
      });
    });

    describe('Given ALLOWED_APP_IDS is not a JSON array of strings', () => {
      beforeEach(async () => {
        dependencies.env = JSON.parse(JSON.stringify(env));
        dependencies.env['ALLOWED_APP_IDS'] = '100';
        result = await handlerConstructor(dependencies, event, context);
      });

      it('logs INVALID_CONFIG', async () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_CONFIG',
          errorMessage: 'ALLOWED_APP_IDS must be a JSON array of strings',
        });
      });

      it('returns 500 Internal server error', async () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 500,
          body: JSON.stringify({
            code: 'server_error',
            message: 'Server Error',
          }),
        });
      });
    });

    describe('Given AUDIENCE is not a JSON array of strings', () => {
      beforeEach(async () => {
        dependencies.env = JSON.parse(JSON.stringify(env));
        dependencies.env['AUDIENCE'] = '100';
        result = await handlerConstructor(dependencies, event, context);
      });

      it('logs INVALID_CONFIG', async () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_CONFIG',
          errorMessage: 'AUDIENCE must be a JSON array of strings',
        });
      });

      it('returns 500 Internal server error', async () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 500,
          body: JSON.stringify({
            code: 'server_error',
            message: 'Server Error',
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
              code: 'unauthorized',
              message: 'X-Firebase-AppCheck header missing from event',
            }),
          });
        });
      });
    });
  });

  describe('JWT verification', () => {
    describe('JWT verification failed with client error', () => {
      beforeEach(async () => {
        const jwtWithInvalidIssuer = await createSignedJwt(privateKey, {
          issuer: 'invalidIssuer',
        });
        event = buildRequest({
          headers: {
            'X-Firebase-AppCheck': jwtWithInvalidIssuer,
          },
        });
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Should return 401', () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 401,
          body: JSON.stringify({
            code: 'unauthorized',
            message: 'JWT claim(s) are invalid',
          }),
        });
      });
    });

    describe('JWT verification failed with server error', () => {
      beforeEach(async () => {
        mockJwksCache.getJwks = vi.fn().mockResolvedValue(emptyFailure());
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Should return 500', () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 500,
          body: JSON.stringify({
            code: 'server_error',
            message: 'Server Error',
          }),
        });
      });
    });
  });

  describe('WIP happy path tests', () => {
    describe('Given a valid event', () => {
      beforeEach(async () => {
        result = await handlerConstructor(dependencies, event, context);
      });

      it('calls verifyJwt with correct parameters', () =>
        expect(dependencies.verifyJwt).toBeCalledWith(
          event.headers?.['X-Firebase-AppCheck'],
          dependencies.env.FIREBASE_JWKS_URI,
          {
            algorithm: dependencies.env.ALGORITHM,
            allowedAppIds: JSON.parse(
              dependencies.env.ALLOWED_APP_IDS as string,
            ),
            audience: JSON.parse(dependencies.env.AUDIENCE as string),
            issuer: dependencies.env.ISSUER,
          },
        ));

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
          body: 'OK',
        });
      });
    });
  });
});
