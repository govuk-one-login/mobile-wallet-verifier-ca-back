import { generateKeyPairSync } from 'node:crypto';
import { KeyManager } from './key-manager';
import { KeyPair } from './crypto-utils';

export const FIREBASE_KID = 'firebase-appcheck-debug';

// Secret name for mock Firebase App Check JWKS key pair (mimics https://firebaseappcheck.googleapis.com/v1/jwks)
const FIREBASE_APPCHECK_JWKS_SECRET =
  process.env.FIREBASE_APPCHECK_JWKS_SECRET!;

export async function getOrCreateRSAKeys(region?: string): Promise<KeyPair> {
  const keyManager = new KeyManager(region);
  let keyPair = await keyManager.getKeyPair(FIREBASE_APPCHECK_JWKS_SECRET);

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
    await keyManager.updateKeyPair(FIREBASE_APPCHECK_JWKS_SECRET, keyPair);
  }

  return keyPair;
}
