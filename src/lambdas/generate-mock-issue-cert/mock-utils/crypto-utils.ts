import { generateKeyPairSync } from 'node:crypto';

export interface KeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export function generateRSAKeyPair(keySize: number = 2048): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

export function generateECDSAKeyPair(curve: string = 'prime256v1'): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

export async function importRSAKeyPair(keyPair: KeyPair): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const privateKeyBuffer = Buffer.from(
    keyPair.privateKeyPem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/g, '').replace(/\s/g, ''),
    'base64'
  );
  
  const publicKeyBuffer = Buffer.from(
    keyPair.publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, '').replace(/\s/g, ''),
    'base64'
  );

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign']
  );
  
  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify']
  );

  return { privateKey, publicKey };
}

export async function importECDSAKeyPair(keyPair: KeyPair): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const privateKeyBuffer = Buffer.from(
    keyPair.privateKeyPem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/g, '').replace(/\s/g, ''),
    'base64'
  );
  
  const publicKeyBuffer = Buffer.from(
    keyPair.publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----/g, '').replace(/\s/g, ''),
    'base64'
  );

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
  
  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );

  return { privateKey, publicKey };
}

export async function createRootCA(keyPair: KeyPair): Promise<string> {
  const { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags } = await import('@peculiar/x509');
  const cryptoKeys = await importECDSAKeyPair(keyPair);

  const cert = await X509CertificateGenerator.create({
    serialNumber: '01',
    subject: 'CN=Test Android Hardware Attestation Root CA, OU=Android, O=Google Inc, C=US',
    issuer: 'CN=Test Android Hardware Attestation Root CA, OU=Android, O=Google Inc, C=US',
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: cryptoKeys.publicKey,
    signingKey: cryptoKeys.privateKey,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true)
    ]
  });

  return cert.toString('pem');
}