import {
  BasicConstraintsExtension,
  Pkcs10CertificateRequestGenerator,
} from '@peculiar/x509';
import { CSR_SUBJECT_POLICY } from '../../src/lambdas/common/csr-policy';

type CsrKeyAlgorithm = 'ec-p256' | 'ec-p384' | 'rsa';
type SubjectEntries = {
  C?: string | null;
  O?: string | null;
  CN?: string | null;
  additionalAttributes?: string[];
};

export interface CreateCsrPemOptions {
  invalidPkcs10?: boolean;
  keyAlgorithm?: CsrKeyAlgorithm;
  basicConstraintsCa?: boolean;
  invalidateSignature?: boolean;
  subject?: SubjectEntries;
}

export async function createCsrPem(
  options: CreateCsrPemOptions = {},
): Promise<string> {
  if (options.invalidPkcs10) {
    return 'invalidPKCS#10';
  }

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
    name: buildSubjectName(options.subject),
    keys,
    signingAlgorithm,
    extensions,
  });

  if (options.invalidateSignature) {
    // flip a byte near the end of DER so the csr still passes
    // but it's self signature no longer verifies
    const derWithInvalidSignature = Buffer.from(csr.rawData);
    derWithInvalidSignature[derWithInvalidSignature.length - 10] ^= 0x01;
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

function buildSubjectName(subject: SubjectEntries = {}): string {
  const {
    C = CSR_SUBJECT_POLICY.C,
    O = CSR_SUBJECT_POLICY.O,
    CN = 'MockCN',
    additionalAttributes = ['OU=Ignored Subject Attribute'],
  } = subject;

  const parts = [
    C === null ? null : `C=${C}`,
    O === null ? null : `O=${O}`,
    CN === null ? null : `CN=${CN}`,
    ...additionalAttributes,
  ].filter((part): part is string => part !== null);

  return parts.join(', ');
}
