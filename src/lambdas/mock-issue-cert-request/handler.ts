import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';
import { generateCSR } from './certificate-generator.ts';
import {
  getOrGenerateECDSAKeyPair,
  FIREBASE_KID,
} from '../common/mock-utils/key-pair-manager.ts';
import { FirebaseAppCheckSigner } from './firebase-appcheck-signer.ts';
import { randomUUID } from 'node:crypto';

import {
  dependencies,
  GenerateMockIssueCertDependencies,
} from './handler-dependencies.ts';
import { getGenerateMockIssueCertRequestConfig } from './config.ts';
import { CSR_POLICY } from '../common/csr-constants/csr-constants.ts';

interface MockIssueReaderCertRequest {
  headers: {
    'X-Firebase-AppCheck': string;
  };
  body: {
    csrPem: string;
  };
}

export const handlerConstructor = async (
  dependencies: GenerateMockIssueCertDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);

  logger.info(LogMessage.MOCK_ISSUE_CERT_REQUEST_STARTED, {
    data: { path: event.path, method: event.httpMethod },
  });

  const configResult = getGenerateMockIssueCertRequestConfig(dependencies.env);
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
    const scenario = event.queryStringParameters?.scenario;
    const mockRequest = await generateMockRequest(dependencies.env, scenario);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify(mockRequest),
    };
  } catch (error) {
    logger.error(LogMessage.MOCK_ISSUE_CERT_REQUEST_ERROR, {
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

async function generateMockRequest(
  env: NodeJS.ProcessEnv,
  scenario?: string,
): Promise<MockIssueReaderCertRequest> {
  const configResult = getGenerateMockIssueCertRequestConfig(env);
  if (configResult.isError) {
    throw new Error('Failed to load configuration');
  }

  const keyPair = await getOrGenerateECDSAKeyPair(
    configResult.value.DEVICE_KEYS_SECRET,
    'P-384',
  );

  // Generate UUID for serial number
  const serialNumber = randomUUID();

  // Generate CSR
  const csr = await generateCSR({
    privateKeyPem: keyPair.privateKeyPem,
    publicKeyPem: keyPair.publicKeyPem,
    subject: {
      countryName: CSR_POLICY.subject.C,
      organizationName: CSR_POLICY.subject.O,
      organizationalUnitName: 'Reader Certification Authority',
      commonName: 'Example Verifier Org Reader Sub-CA',
      serialNumber,
    },
  });

  // Generate Firebase App Check token
  const firebaseAppCheck = new FirebaseAppCheckSigner(env);
  const appCheckToken = await firebaseAppCheck.generateDebugToken(
    'org.multipaz.identityreader',
    scenario,
  );

  // Log Firebase public key for debugging
  const firebasePublicKey = await firebaseAppCheck.getPublicKeyPem(
    configResult.value.FIREBASE_APPCHECK_JWKS_SECRET,
  );
  logger.info('Firebase JWT signing public key', {
    kid: FIREBASE_KID,
    publicKey: firebasePublicKey,
  });

  return {
    headers: {
      'X-Firebase-AppCheck': appCheckToken,
    },
    body: {
      csrPem: csr.csrPem,
    },
  };
}
