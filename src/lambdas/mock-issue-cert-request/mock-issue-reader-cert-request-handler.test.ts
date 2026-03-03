import {
  Context,
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
} from 'aws-lambda';
import { describe, it, beforeEach, expect, MockInstance, vi } from 'vitest';
import { handlerConstructor } from './mock-issue-reader-cert-request-handler';
import { logger } from '../common/logger/logger';
import '../../../tests/testUtils/matchers';
import { GenerateMockIssueCertDependencies } from './mock-issue-cert-handler-dependencies';
import {
  buildLambdaContext,
  buildRequest,
} from '../../../tests/testUtils/buildRequest';
import * as certificateGenerator from './certificate-generator';
import * as keyPairManager from '../common/mock-utils/key-pair-manager';
import * as environment from '../common/config/environment';

const mockGenerateDebugToken = vi.fn().mockResolvedValue('mock-token');

vi.mock('./certificate-generator', () => ({
  generateCSR: vi.fn().mockResolvedValue({
    csrPem: 'mock-csr',
  }),
}));

vi.mock('./firebase-appcheck-signer', () => ({
  FirebaseAppCheckSigner: vi.fn().mockImplementation(function () {
    return {
      generateDebugToken: mockGenerateDebugToken,
      getPublicKeyPem: vi.fn().mockResolvedValue('mock-public-key'),
    };
  }),
}));

vi.mock('../common/mock-utils/key-pair-manager', () => ({
  getOrGenerateECDSAKeyPair: vi.fn().mockResolvedValue({
    privateKeyPem: 'mock-private',
    publicKeyPem: 'mock-public',
  }),
  FIREBASE_KID: 'firebase-appcheck-debug',
}));

let consoleInfoSpy: MockInstance;
let consoleErrorSpy: MockInstance;

describe('Mock Issue Reader Cert Request Handler', () => {
  let event: APIGatewayProxyEvent;
  let context: Context;
  let dependencies: GenerateMockIssueCertDependencies;
  let result: APIGatewayProxyResult;
  const env = {
    FIREBASE_APPCHECK_JWKS_SECRET: 'mock-firebase-appcheck-keys',
    DEVICE_KEYS_SECRET: 'mock-device-keys',
    FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
  };

  beforeEach(() => {
    consoleInfoSpy = vi.spyOn(console, 'info');
    consoleErrorSpy = vi.spyOn(console, 'error');
    context = buildLambdaContext();
    event = buildRequest();
    dependencies = { env };

    mockGenerateDebugToken.mockClear();
    vi.mocked(certificateGenerator.generateCSR).mockClear();
    vi.mocked(keyPairManager.getOrGenerateECDSAKeyPair).mockClear();

    // Mock successful environment validation by default
    vi.spyOn(environment, 'getRequiredEnvironmentVariables').mockReturnValue({
      isError: false,
      value: env,
    });
  });

  describe('On every invocation', () => {
    beforeEach(async () => {
      logger.appendKeys({ testKey: 'testValue' });
      await handlerConstructor(dependencies, event, context);
    });

    it('Adds context, version and logs STARTED message', () => {
      expect(consoleInfoSpy).toHaveBeenCalledWithLogFields({
        messageCode: 'MOBILE_CA_MOCK_ISSUE_CERT_REQUEST_STARTED',
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

  describe('Successful request generation', () => {
    beforeEach(async () => {
      result = await handlerConstructor(dependencies, event, context);
    });

    it('returns 200 with mock request data', () => {
      expect(result.statusCode).toBe(200);
      expect(result.headers).toEqual({
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      });

      const body = JSON.parse(result.body);
      expect(body).toEqual({
        headers: {
          'X-Firebase-AppCheck': 'mock-token',
        },
        body: {
          csrPem: 'mock-csr',
        },
      });
    });

    it('calls generateCSR with correct parameters', () => {
      expect(certificateGenerator.generateCSR).toHaveBeenCalledWith({
        privateKeyPem: 'mock-private',
        publicKeyPem: 'mock-public',
        subject: {
          countryName: 'GB',
          organizationName: 'Example Verifier Org Ltd',
          organizationalUnitName: 'Reader Certification Authority',
          commonName: 'Example Verifier Org Reader Sub-CA',
          serialNumber: expect.any(String),
        },
      });
    });

    it('calls Firebase App Check signer with default parameters', () => {
      expect(mockGenerateDebugToken).toHaveBeenCalledWith(
        'org.multipaz.identityreader',
        undefined,
      );
    });
  });

  describe('With scenario parameter', () => {
    beforeEach(async () => {
      event.queryStringParameters = { scenario: 'invalid-sub' };
      result = await handlerConstructor(dependencies, event, context);
    });

    it('passes scenario to Firebase App Check signer', () => {
      expect(mockGenerateDebugToken).toHaveBeenCalledWith(
        'org.multipaz.identityreader',
        'invalid-sub',
      );
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

          // Mock environment validation to return error for missing env var
          vi.spyOn(
            environment,
            'getRequiredEnvironmentVariables',
          ).mockReturnValue({
            isError: true,
            value: { missingEnvVars: [envVar] },
          });

          result = await handlerConstructor(dependencies, event, context);
        });

        it('logs INVALID_CONFIG', async () => {
          expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
            messageCode: 'MOBILE_CA_MOCK_ISSUE_CERT_INVALID_CONFIG',
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
