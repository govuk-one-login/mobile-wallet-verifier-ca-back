import { generateKeyPairSync } from 'node:crypto';
import { SecretsManagerKeyStore } from './secrets-manager';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export const FIREBASE_KID = 'firebase-appcheck-debug';

const FIREBASE_APPCHECK_JWKS_SECRET =
  process.env.FIREBASE_APPCHECK_JWKS_SECRET!;

export async function getOrGenerateECDSAKeyPair(
  secretName: string,
  curve: string = 'prime256v1',
  region?: string,
): Promise<KeyPair> {
  const keyStore = new SecretsManagerKeyStore(region);
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

export async function getOrCreateRSAKeys(region?: string): Promise<KeyPair> {
  const keyStore = new SecretsManagerKeyStore(region);
  let keyPair = await keyStore.getKeyPair(FIREBASE_APPCHECK_JWKS_SECRET);

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
    await keyStore.updateKeyPair(FIREBASE_APPCHECK_JWKS_SECRET, keyPair);
  }

  return keyPair;
}

export async function importECDSAKeyPair(
  keyPair: KeyPair,
): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const privateKeyBuffer = Buffer.from(
    keyPair.privateKeyPem
      .replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/g, '')
      .replace(/\s/g, ''),
    'base64',
  );

  const publicKeyBuffer = Buffer.from(
    keyPair.publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, '')
      .replace(/\s/g, ''),
    'base64',
  );

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  );

  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );

  return { privateKey, publicKey };
}
