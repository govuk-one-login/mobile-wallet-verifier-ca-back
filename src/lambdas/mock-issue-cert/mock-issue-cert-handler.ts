import type {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
import { logger, setupLogger } from '../common/logger/logger.ts';
import { generateCSR } from './certificate-generator.ts';
import { getOrGenerateECDSAKeyPair } from '../common/mock-utils/key-pair-manager.ts';
import { FirebaseAppCheckSigner } from './firebase-appcheck-signer.ts';
import { FIREBASE_KID } from '../common/mock-utils/key-pair-manager.ts';
import type { MockIssueReaderCertRequest } from '../issue-reader-cert-service/types.ts';

import {
  dependencies,
  GenerateMockIssueCertDependencies,
} from './mock-issue-cert-handler-dependencies.ts';
import { getGenerateMockIssueCertConfig } from './mock-issue-cert-config.ts';

export const handlerConstructor = async (
  dependencies: GenerateMockIssueCertDependencies,
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  setupLogger(context);

  logger.info('Generate mock issue cert endpoint called', {
    path: event.path,
    method: event.httpMethod,
  });

  const configResult = getGenerateMockIssueCertConfig(dependencies.env);
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

  if (event.httpMethod !== 'GET' || !event.path.endsWith('/mock-issue-cert')) {
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Not found' }),
    };
  }

  try {
    const scenario = event.queryStringParameters?.scenario;
    const mockRequest = await generateMockRequest(scenario);

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
      body: JSON.stringify(mockRequest),
    };
  } catch (error) {
    logger.error('Error generating mock request', { error });
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Internal server error' }),
    };
  }
};

export const handler = handlerConstructor.bind(null, dependencies);

async function generateMockRequest(
  scenario?: string,
): Promise<MockIssueReaderCertRequest> {
  logger.info('Generating mock issue cert payload');

  const deviceKeysSecret = process.env.DEVICE_KEYS_SECRET!;
  const keyPair = await getOrGenerateECDSAKeyPair(
    deviceKeysSecret,
    'prime256v1',
  );

  // Generate UUID for serial number
  const { randomUUID } = await import('node:crypto');
  const serialNumber = randomUUID();

  // Generate CSR
  const csr = await generateCSR({
    privateKeyPem: keyPair.privateKeyPem,
    publicKeyPem: keyPair.publicKeyPem,
    subject: {
      countryName: 'GB',
      organizationName: 'Example Verifier Org Ltd',
      organizationalUnitName: 'Reader Certification Authority',
      commonName: 'Example Verifier Org Reader Sub-CA',
      serialNumber,
    },
  });

  // Generate Firebase App Check token
  const firebaseAppCheck = new FirebaseAppCheckSigner();
  const appCheckToken = await firebaseAppCheck.generateDebugToken(
    'org.multipaz.identityreader',
    scenario,
  );

  // Log Firebase public key for debugging
  const firebasePublicKey = await firebaseAppCheck.getPublicKeyPem();
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
