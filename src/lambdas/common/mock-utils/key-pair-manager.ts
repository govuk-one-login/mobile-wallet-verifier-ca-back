import { generateKeyPairSync } from 'node:crypto';
import { SecretsManagerKeyStore } from './secrets-manager';
import { CSR_POLICY } from '../csr-constants/csr-constants';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export const FIREBASE_KID = 'firebase-appcheck-debug';

/**
 * Generates or retrieves EC (Elliptic Curve) key pairs for CSR generation.
 * Used by: mock-issue-cert-request-handler for creating Certificate Signing Requests
 */
export async function getOrGenerateECDSAKeyPair(
  secretName: string,
  curve: string = CSR_POLICY.curve,
): Promise<KeyPair> {
  const keyStore = new SecretsManagerKeyStore();
  let keyPair = await keyStore.getKeyPair(secretName);

  if (
    !keyPair ||
    keyPair.privateKeyPem === 'PLACEHOLDER' ||
    keyPair.publicKeyPem === 'PLACEHOLDER'
  ) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: curve,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    keyPair = { privateKeyPem: privateKey, publicKeyPem: publicKey };
    await keyStore.updateKeyPair(secretName, keyPair);
  }

  return keyPair;
}

/**
 * Generates or retrieves RSA key pairs for Firebase App Check JWT signing.
 * Used by: firebase-appcheck-signer for JWT token signing and jwks-generator for public key exposure
 */
export async function getOrCreateRSAKeys(
  firebaseJwksSecret: string,
): Promise<KeyPair> {
  const keyStore = new SecretsManagerKeyStore();
  let keyPair = await keyStore.getKeyPair(firebaseJwksSecret);

  if (
    !keyPair ||
    keyPair.privateKeyPem === 'PLACEHOLDER' ||
    keyPair.publicKeyPem === 'PLACEHOLDER'
  ) {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    keyPair = { privateKeyPem: privateKey, publicKeyPem: publicKey };
    await keyStore.updateKeyPair(firebaseJwksSecret, keyPair);
  }

  return keyPair;
}

export async function importECDSAKeyPair(
  keyPair: KeyPair,
): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const privateKeyBuffer = Buffer.from(
    keyPair.privateKeyPem
      .replaceAll(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/g, '')
      .replaceAll(/\s/g, ''),
    'base64',
  );

  const publicKeyBuffer = Buffer.from(
    keyPair.publicKeyPem
      .replaceAll(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, '')
      .replaceAll(/\s/g, ''),
    'base64',
  );

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    { name: 'ECDSA', namedCurve: CSR_POLICY.curve },
    true,
    ['sign'],
  );

  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name: 'ECDSA', namedCurve: CSR_POLICY.curve },
    true,
    ['verify'],
  );

  return { privateKey, publicKey };
}
