import { X509CertificateGenerator } from '@peculiar/x509';

type CertKeyAlgorithm = 'ec-p256' | 'ec-p384' | 'rsa';

export interface CreateValidCertPemOptions {
  keyAlgorithm?: CertKeyAlgorithm;
  invalidX509?: boolean;
  notBefore?: Date;
  notAfter?: Date;
  name?: string;
}

export async function createValidCertPem(
  options: CreateValidCertPemOptions = {},
): Promise<string> {
  if (options.invalidX509) {
    return 'invalid-pem';
  }

  const keyAlgorithm = options.keyAlgorithm ?? 'ec-p384';
  const keyGenerationAlgorithm = getKeyGenerationAlgorithm(keyAlgorithm);
  const signingAlgorithm = getSigningAlgorithm(keyAlgorithm);

  const keys = await crypto.subtle.generateKey(keyGenerationAlgorithm, true, [
    'sign',
    'verify',
  ]);

  const cert = await X509CertificateGenerator.createSelfSigned({
    name: options.name ?? 'CN=Test',
    keys,
    signingAlgorithm,
    notBefore: options.notBefore ?? new Date('2026-01-01T00:00:00Z'),
    notAfter: options.notAfter ?? new Date('2026-01-02T00:00:00Z'),
  });

  return cert.toString('pem');
}

export function createValidSerialNumber(): ArrayBuffer {
  const serial = new ArrayBuffer(9);
  const bytes = new Uint8Array(serial);
  bytes[0] = 0x01; // positive, non-zero
  bytes[1] = 0x23;
  bytes[2] = 0x45;
  return serial;
}

function getKeyGenerationAlgorithm(
  keyAlgorithm: CertKeyAlgorithm,
): EcKeyGenParams | RsaHashedKeyGenParams {
  switch (keyAlgorithm) {
    case 'ec-p256':
      return {
        name: 'ECDSA',
        namedCurve: 'P-256',
      };
    case 'ec-p384':
      return {
        name: 'ECDSA',
        namedCurve: 'P-384',
      };
    case 'rsa':
      return {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
  }
}

function getSigningAlgorithm(
  keyAlgorithm: CertKeyAlgorithm,
): Algorithm | EcdsaParams {
  switch (keyAlgorithm) {
    case 'ec-p256':
      return {
        name: 'ECDSA',
        hash: 'SHA-256',
      };
    case 'ec-p384':
      return {
        name: 'ECDSA',
        hash: 'SHA-384',
      };
    case 'rsa':
      return {
        name: 'RSASSA-PKCS1-v1_5',
      };
  }
}
