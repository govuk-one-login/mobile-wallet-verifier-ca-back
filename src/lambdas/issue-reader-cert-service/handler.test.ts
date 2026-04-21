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
import { handlerConstructor } from './handler.ts';
import { logger } from '../common/logger/logger.ts';
import '../../../tests/testUtils/matchers.ts';
import { IssueReaderCertDependencies } from './handler-dependencies.ts';
import {
  buildLambdaContext,
  buildEvent,
} from '../../../tests/testUtils/build-event.ts';
import {
  emptyFailure,
  Result,
  successResult,
} from '../common/result/result.ts';
import {
  ExpectedAppCheckJwtData,
  verifyAppCheckJwt,
} from './verify-app-check-jwt/verify-app-check-jwt.ts';
import { InMemoryJwtReplayCache } from './verify-app-check-jwt/app-check-jwt-replay-cache.ts';
import { JwksCache } from '../common/jwks/jwks-cache/types.ts';
import {
  createKeyPair,
  createSignedJwt,
} from '../../../tests/testUtils/create-signed-jwt.ts';
import { JWK } from 'jose';
import {
  createCsrPem,
  CreateCsrPemOptions,
} from '../../../tests/testUtils/create-csr-pem.ts';

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
    CERTIFICATE_AUTHORITY_ARN:
      'arn:aws:acm-pca:eu-west-2:111111111111:mock-certificate-authority/b1111111-df11-1f11-a111-b11b11a11111',
  };
  let consoleInfoSpy: MockInstance;
  let consoleErrorSpy: MockInstance;
  let mockJwksCache: JwksCache;
  let privateKey: CryptoKey;
  let publicJwk: JWK;
  let validFireBaseJwt: string;
  let mockIssueCertificate: (params: {
    csrPem: string;
    certificateAuthorityArn: string;
  }) => Promise<Result<string, void>>;
  let mockGetCertificate: (params: {
    certificateArn: string;
    certificateAuthorityArn: string;
  }) => Promise<Result<string, void>>;

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

    const verifyAppCheckJwtWithMockedJwksCache: IssueReaderCertDependencies['verifyAppCheckJwt'] =
      vi.fn(
        (
          jwt: string,
          jwksUrl: string,
          expectedJwtData: ExpectedAppCheckJwtData,
        ) => {
          return verifyAppCheckJwt(jwt, jwksUrl, expectedJwtData, {
            jwksCache: mockJwksCache,
            jwtReplayCache: new InMemoryJwtReplayCache(),
          });
        },
      );

    validFireBaseJwt = await createSignedJwt(privateKey, {
      audience: JSON.parse(env.AUDIENCE)[0],
      issuer: env.ISSUER,
      subject: JSON.parse(env.ALLOWED_APP_IDS)[0],
    });

    const validCsrPem = await createCsrPem();

    context = buildLambdaContext();
    event = buildEvent({
      headers: {
        'X-Firebase-AppCheck': validFireBaseJwt,
      },
      body: JSON.stringify({ csrPem: validCsrPem }),
    });

    mockIssueCertificate = vi
      .fn()
      .mockResolvedValue(
        successResult(
          'arn:aws:acm-pca:eu-west-2:111111111111:mock-certificate-authority/b1111111-df11-1f11-a111-b11b11a11111/certificate/abcdef12-3456-7890-abcd-ef1234567890',
        ),
      );

    mockGetCertificate = vi
      .fn()
      .mockResolvedValue(
        successResult(
          '-----BEGIN CERTIFICATE-----\nMOCK_CERT_CHAIN\n-----END CERTIFICATE-----',
        ),
      );

    dependencies = {
      env,
      verifyAppCheckJwt: verifyAppCheckJwtWithMockedJwksCache,
      issueCertificate: mockIssueCertificate,
      getCertificate: mockGetCertificate,
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
          const invalidEvent = buildEvent({ headers });
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

    describe('Given event body is invalid', () => {
      describe.each([
        {
          scenario: 'Given there are no body in the event',
          body: null,
          expectedErrorMessage: 'Event body is null',
        },
        {
          scenario: 'Given body cannot be parsed',
          body: 'invalidJSON',
          expectedErrorMessage: 'Event body cannot be parsed',
        },
        {
          scenario: 'Given body is not a JSON object',
          body: JSON.stringify([]),
          expectedErrorMessage: 'Event body is not a JSON object',
        },
        {
          scenario: 'Given csrPem is not present in the event body',
          body: JSON.stringify({ mockKey: 'mockValue' }),
          expectedErrorMessage: 'Event body missing csrPem',
        },
        {
          scenario: 'Given csrPem in body is not a string',
          body: JSON.stringify({ csrPem: 123 }),
          expectedErrorMessage: 'Event body csrPem is not a string',
        },
        {
          scenario: 'Given csrPem is an empty string',
          body: JSON.stringify({ csrPem: '' }),
          expectedErrorMessage: 'Event body csrPem is an empty string',
        },
        {
          scenario: 'Given csrPem is an empty string with whitespace',
          body: JSON.stringify({ csrPem: '  ' }),
          expectedErrorMessage: 'Event body csrPem is an empty string',
        },
      ])('$scenario', ({ body, expectedErrorMessage }) => {
        beforeEach(async () => {
          const invalidEvent = buildEvent({
            headers: {
              'X-Firebase-AppCheck': 'mockFireBaseAppCheckHeader',
            },
            body,
          });
          result = await handlerConstructor(
            dependencies,
            invalidEvent,
            context,
          );
        });

        it('Log an INVALID_EVENT error', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_ISSUE_READER_CERT_INVALID_EVENT',
            errorMessage: expectedErrorMessage,
          });
        });

        it('Return 401 Unauthorized response', () => {
          expect(result).toStrictEqual({
            headers: { 'Content-Type': 'application/json' },
            statusCode: 401,
            body: JSON.stringify({
              code: 'unauthorized',
              message: expectedErrorMessage,
            }),
          });
        });
      });
    });
  });

  describe('App Check JWT verification', () => {
    describe('App Check JWT verification failed with client error', () => {
      beforeEach(async () => {
        const jwtWithInvalidIssuer = await createSignedJwt(privateKey, {
          issuer: 'invalidIssuer',
        });
        event = buildEvent({
          headers: {
            'X-Firebase-AppCheck': jwtWithInvalidIssuer,
          },
          body: JSON.stringify({ csrPem: 'MockCsrPemValue' }),
        });
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Returns 401 unauthorized response', () => {
        expect(result).toStrictEqual({
          headers: { 'Content-Type': 'application/json' },
          statusCode: 401,
          body: JSON.stringify({
            code: 'unauthorized',
            message: 'App Check JWT iss claim is invalid',
          }),
        });
      });
    });

    describe('App check JWT verification failed with server error', () => {
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

  describe('CSR Validation', () => {
    type InvalidCsrTestCase = {
      scenario: string;
      csrPemConfig: CreateCsrPemOptions;
      expectedErrorMessage: string;
      expectedLogData?: Record<string, unknown>;
    };
    const invalidCsrTestCases: InvalidCsrTestCase[] = [
      {
        scenario: 'Given CSRPem is not valid PKCS#10',
        csrPemConfig: { invalidPkcs10: true },
        expectedErrorMessage: 'CSR not valid PKCS#10 request',
        expectedLogData: {
          csrPem: 'invalidPKCS#10',
          error: { name: 'TypeError' },
        },
      },
      {
        scenario:
          'Given unexpected error occurs during self signature verification',
        csrPemConfig: { unsupportedSignatureAlgorithm: true },
        expectedErrorMessage: 'CSR self signature verification failed',
        expectedLogData: {
          error: { name: 'NotSupportedError' },
        },
      },
      {
        scenario: 'Given CSR has invalid self signature',
        csrPemConfig: { invalidateSignature: true },
        expectedErrorMessage: 'CSR self signature verification failed',
      },
      {
        scenario: 'Given CSR has non EC public key algorithm',
        csrPemConfig: { keyAlgorithm: 'rsa' },
        expectedErrorMessage: 'CSR public key not EC key',
        expectedLogData: {
          publicKeyAlgorithm: 'RSASSA-PKCS1-v1_5',
        },
      },
      {
        scenario: 'Given CSR does not use P-384 curve',
        csrPemConfig: { keyAlgorithm: 'ec-p256' },
        expectedErrorMessage: 'CSR public key does not use P-384 curve',
        expectedLogData: {
          publicKeyAlgorithmCurve: 'P-256',
        },
      },
      {
        scenario: 'Given CSR requests CA capabilities',
        csrPemConfig: { basicConstraintsCa: true },
        expectedErrorMessage: 'CSR requests CA capabilities',
        expectedLogData: {
          basicConstraintsCa: true,
        },
      },
      {
        scenario: 'Given CSR subject country is not GB',
        csrPemConfig: { subject: { C: 'FR' } },
        expectedErrorMessage: 'CSR subject C is not GB',
        expectedLogData: {
          subjectC: ['FR'],
        },
      },
      {
        scenario: 'Given CSR subject 0 is not Government Digital Service',
        csrPemConfig: { subject: { O: 'Invalid Service' } },
        expectedErrorMessage: 'CSR subject O is not Government Digital Service',
        expectedLogData: {
          subjectO: ['Invalid Service'],
        },
      },
      {
        scenario: 'Given CSR subject CN is not present',
        csrPemConfig: { subject: { CN: null } },
        expectedErrorMessage: 'CSR subject CN is not present',
        expectedLogData: {
          subjectCN: [],
        },
      },
      {
        scenario: 'Given CSR subject CN is not present',
        csrPemConfig: { subject: { CN: '' } },
        expectedErrorMessage: 'CSR subject CN is not present',
        expectedLogData: {
          subjectCN: [''],
        },
      },
    ];
    describe.each(invalidCsrTestCases)(
      '$scenario',
      ({ csrPemConfig, expectedErrorMessage, expectedLogData }) => {
        beforeEach(async () => {
          const invalidCsrPem = await createCsrPem(csrPemConfig);
          const invalidEvent = buildEvent({
            headers: {
              'X-Firebase-AppCheck': validFireBaseJwt,
            },
            body: JSON.stringify({
              csrPem: invalidCsrPem,
            }),
          });

          result = await handlerConstructor(
            dependencies,
            invalidEvent,
            context,
          );
        });

        it('Logs INVALID_CSR', () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_ISSUE_READER_CERT_CSR_VALIDATION_FAILURE',
            errorMessage: expectedErrorMessage,
            data: expectedLogData,
          });
        });

        it('Return 400 Bad Request response', () => {
          expect(result).toStrictEqual({
            headers: { 'Content-Type': 'application/json' },
            statusCode: 400,
            body: JSON.stringify({
              code: 'bad_request',
              message: expectedErrorMessage,
            }),
          });
        });
      },
    );
  });

  describe('Certificate issuance', () => {
    describe('Given certificate issuance fails', () => {
      beforeEach(async () => {
        mockIssueCertificate = vi.fn().mockResolvedValue(emptyFailure());
        dependencies.issueCertificate = mockIssueCertificate;
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Returns 500 server error response', () => {
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

    describe('Given certificate retrieval fails', () => {
      beforeEach(async () => {
        mockGetCertificate = vi.fn().mockResolvedValue(emptyFailure());
        dependencies.getCertificate = mockGetCertificate;
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Returns 500 server error response', () => {
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

  describe('Happy path tests', () => {
    describe('Given a valid event', () => {
      beforeEach(async () => {
        result = await handlerConstructor(dependencies, event, context);
      });

      it('Calls verifyAppCheckJwt with correct parameters', () =>
        expect(dependencies.verifyAppCheckJwt).toBeCalledWith(
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

      it('Returns 200 OK response with certificate chain', () => {
        expect(result).toStrictEqual({
          statusCode: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Request-Id': context.awsRequestId,
          },
          body: JSON.stringify({
            certChain:
              '-----BEGIN CERTIFICATE-----\nMOCK_CERT_CHAIN\n-----END CERTIFICATE-----',
          }),
        });
      });

      it('Calls certificate functions with correct parameters', () => {
        expect(mockIssueCertificate).toHaveBeenCalledWith({
          csrPem: expect.any(String),
          certificateAuthorityArn: env.CERTIFICATE_AUTHORITY_ARN,
        });
        expect(mockGetCertificate).toHaveBeenCalledWith({
          certificateArn:
            'arn:aws:acm-pca:eu-west-2:111111111111:mock-certificate-authority/b1111111-df11-1f11-a111-b11b11a11111/certificate/abcdef12-3456-7890-abcd-ef1234567890',
          certificateAuthorityArn: env.CERTIFICATE_AUTHORITY_ARN,
        });
      });
    });
  });
});
