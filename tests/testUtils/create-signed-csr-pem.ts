import {
  BasicConstraintsExtension,
  Pkcs10CertificateRequestGenerator,
} from '@peculiar/x509';

type CsrKeyAlgorithm = 'ec-p256' | 'ec-p384' | 'rsa';

export interface CreateCsrPemOptions {
  keyAlgorithm?: CsrKeyAlgorithm;
  basicConstraintsCa?: boolean;
  invalidateSignature?: boolean;
}

export async function createCsrPem(
  options: CreateCsrPemOptions = {},
): Promise<string> {
  const keyAlgorithm = options.keyAlgorithm ?? 'ec-p256';
  const keyGenerationAlgorithm = getKeyGenerationAlgorithm(keyAlgorithm);
  const signingAlgorithm = getSigningAlgorithm(keyAlgorithm);
  const keys = await crypto.subtle.generateKey(keyGenerationAlgorithm, true, [
    'sign',
    'verify',
  ]);

  const extensions = options.basicConstraintsCa
    ? [new BasicConstraintsExtension(true, undefined, true)]
    : [];

  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: 'CN=Test',
    keys,
    signingAlgorithm,
    extensions,
  });

  if (options.invalidateSignature) {
    // flip a byte near the end of DER so the csr still passes
    // but it's self signature no longer verifies
    const derWithInvalidSignature = Buffer.from(csr.rawData);
    derWithInvalidSignature[derWithInvalidSignature.length - 10] ^= 0x01;
    console.log('>>>> SHIRIN');
    return toPem(derWithInvalidSignature);
  }

  return csr.toString('pem');
}

function getKeyGenerationAlgorithm(
  keyAlgorithm: CsrKeyAlgorithm,
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
  keyAlgorithm: CsrKeyAlgorithm,
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

function toPem(der: Buffer): string {
  const base64 = der.toString('base64');
  const body = base64.match(/.{1,64}/g)?.join('\n') ?? base64;
  return `-----BEGIN CERTIFICATE REQUEST-----\n${body}\n-----END CERTIFICATE REQUEST-----\n`;
}
