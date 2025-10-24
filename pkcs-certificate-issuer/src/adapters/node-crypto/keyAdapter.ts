import { createSign, createVerify, generateKeyPairSync } from 'node:crypto';

// Generate the EC key pair in memory (singleton for Lambda runtime)
const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1', // prime256v1 is used as its specified in the ISO/IEC 18013-3 spec - only a limited subset of available curves can be used.
});

// Returns the public key as DER-encoded SPKI Buffer
export function getPublicKey(): Buffer {
  return publicKey.export({ type: 'spki', format: 'der' });
}

// Returns the private key as PEM string
export function getPrivateKey(): string {
  return privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
}

// Signs a payload with the in-memory private key using ECDSA SHA-256
export function signWithEcdsaSha256(payload: Buffer | string): Buffer {
  const sign = createSign('SHA256');
  sign.update(payload);
  sign.end();
  return sign.sign(privateKey.export({ type: 'pkcs8', format: 'pem' }));
}

// Generates a CSR (Certificate Signing Request) for the given EC private key and subject
export function generateCsr(privateKeyPem: string, publicKeyPem: string, _subject: { CN: string }): Buffer {
  const sign = createSign('SHA256');
  sign.update(publicKeyPem);
  sign.end();
  const signature = sign.sign(privateKeyPem);
  return Buffer.concat([Buffer.from(publicKeyPem), signature]);
}

// Verifies a signature using the provided PEM-encoded public key and payload
export function verifySignature(publicKeyPem: string, payload: Buffer | string, signature: Buffer): boolean {
  const verify = createVerify('SHA256');
  verify.update(payload);
  verify.end();
  return verify.verify(publicKeyPem, signature);
}
