import { generateKeyPairSync } from 'node:crypto';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateECDSAKeyPair(curve: string = 'prime256v1'): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
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
