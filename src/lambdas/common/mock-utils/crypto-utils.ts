import { generateKeyPairSync } from 'node:crypto';
import { KeyManager } from './key-manager';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export async function getOrGenerateECDSAKeyPair(
  secretName: string,
  curve: string = 'prime256v1',
  region?: string,
): Promise<KeyPair> {
  const keyManager = new KeyManager(region);
  let keyPair = await keyManager.getKeyPair(secretName);

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
    await keyManager.updateKeyPair(secretName, keyPair);
  }

  return keyPair;
}

// Converts PEM-formatted keys to CryptoKey objects required by @peculiar/x509 for CSR generation
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
