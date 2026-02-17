import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { Logger } from '@aws-lambda-powertools/logger';
import { KeyManager } from './mock-utils/key-manager';
import { generateCSR } from './mock-utils/certificate-generator';
import { FirebaseAppCheckSigner } from './mock-utils/firebase-appcheck-signer';
import type { MockIssueReaderCertRequest } from '../issue-reader-cert-service/types';

const logger = new Logger();

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info('Generate mock issue cert endpoint called', {
    path: event.path,
    method: event.httpMethod,
  });

  if (
    event.httpMethod !== 'GET' ||
    event.path !== '/generate-mock-issue-cert'
  ) {
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Not found' }),
    };
  }

  try {
    const mockRequest = await generateMockRequest();

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

async function generateMockRequest(): Promise<MockIssueReaderCertRequest> {
  logger.info('Generating mock issue cert payload');

  const keyManager = new KeyManager();
  const deviceKeysSecret =
    process.env.DEVICE_KEYS_SECRET ||
    'mobile-wallet-verifier-ca-back-dev-mock-device-keys';

  let keyPair = await keyManager.getKeyPair(deviceKeysSecret);

  // Check if we got placeholder values or no keys
  if (
    !keyPair ||
    keyPair.privateKeyPem === 'PLACEHOLDER' ||
    keyPair.publicKeyPem === 'PLACEHOLDER'
  ) {
    logger.info(
      'No valid device keys found (placeholder or missing), generating new ECDSA key pair',
    );

    // Generate ECDSA P-256 key pair for device CSR
    const { generateKeyPairSync } = await import('node:crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1', // P-256
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    keyPair = { privateKeyPem: privateKey, publicKeyPem: publicKey };
    logger.info('Updating device keys secret with new key pair');
    await keyManager.updateKeyPair(deviceKeysSecret, keyPair);
    logger.info('Device keys updated successfully');
  } else {
    logger.info('Using existing valid device key pair');
  }

  // Generate CSR
  const csr = await generateCSR({
    privateKeyPem: keyPair.privateKeyPem,
    publicKeyPem: keyPair.publicKeyPem,
    subject: {
      countryName: 'UK',
      organizationName: 'GDS',
      commonName: 'Mock Reader Device',
    },
  });

  // Generate Firebase App Check token
  const firebaseAppCheck = new FirebaseAppCheckSigner();
  const appCheckToken = await firebaseAppCheck.generateDebugToken();

  // Log Firebase public key for debugging
  const firebasePublicKey = await firebaseAppCheck.getPublicKeyPem();
  logger.info('Firebase JWT signing public key', {
    kid: firebaseAppCheck.getKid(),
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
