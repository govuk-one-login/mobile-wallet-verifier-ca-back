import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  Extension,
  KeyUsageFlags,
  KeyUsagesExtension,
  Pkcs10CertificateRequestGenerator,
} from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { CertificationRequest } from '@peculiar/asn1-csr';
import {
  CSR_POLICY,
  NAME_CONSTRAINTS_OID,
} from '../../src/lambdas/common/csr-constants/csr-constants';

type CsrKeyAlgorithm = 'ec-p256' | 'ec-p384' | 'rsa';
type SubjectEntries = {
  C?: string | null;
  ST?: string | null;
  L?: string | null;
  O?: string | null;
  CN?: string | null;
  additionalAttributes?: string[];
};

export interface CreateCsrPemOptions {
  invalidPkcs10?: boolean;
  keyAlgorithm?: CsrKeyAlgorithm;
  basicConstraintsCa?: boolean;
  keyUsage?: KeyUsageFlags;
  extendedKeyUsage?: string[];
  nameConstraints?: boolean;
  invalidateSignature?: boolean;
  unsupportedSignatureAlgorithm?: boolean;
  subject?: SubjectEntries;
}

export async function createCsrPem(
  options: CreateCsrPemOptions = {},
): Promise<string> {
  if (options.invalidPkcs10) {
    return 'invalidPKCS#10';
  }

  const keyAlgorithm = options.keyAlgorithm ?? 'ec-p384';
  const keyGenerationAlgorithm = getKeyGenerationAlgorithm(keyAlgorithm);
  const signingAlgorithm = getSigningAlgorithm(keyAlgorithm);
  const keys = await crypto.subtle.generateKey(keyGenerationAlgorithm, true, [
    'sign',
    'verify',
  ]);

  const extensions = buildExtensions(options);

  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: buildSubjectName(options.subject),
    keys,
    signingAlgorithm,
    extensions,
  });

  if (options.invalidateSignature) {
    // flip a byte near the end of DER so the csr still passes
    // but its self signature no longer verifies
    const derWithInvalidSignature = Buffer.from(csr.rawData);
    derWithInvalidSignature[derWithInvalidSignature.length - 10] ^= 0x01;
    return toPem(derWithInvalidSignature);
  }

  if (options.unsupportedSignatureAlgorithm) {
    const csrAsn = AsnConvert.parse(csr.rawData, CertificationRequest);
    csrAsn.signatureAlgorithm.algorithm = '1.2.3.4';
    return toPem(Buffer.from(AsnConvert.serialize(csrAsn)));
  }

  return csr.toString('pem');
}

function buildExtensions(options: CreateCsrPemOptions): Extension[] {
  const extensions: Extension[] = [];

  if (options.basicConstraintsCa !== undefined) {
    extensions.push(
      new BasicConstraintsExtension(
        options.basicConstraintsCa,
        undefined,
        true,
      ),
    );
  }

  if (options.keyUsage !== undefined) {
    extensions.push(new KeyUsagesExtension(options.keyUsage, true));
  }

  if (options.extendedKeyUsage !== undefined) {
    extensions.push(new ExtendedKeyUsageExtension(options.extendedKeyUsage));
  }

  if (options.nameConstraints) {
    extensions.push(
      new Extension(NAME_CONSTRAINTS_OID, true, Buffer.from([0x30, 0x00])),
    );
  }

  return extensions;
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
    C = CSR_POLICY.subject.C,
    ST = CSR_POLICY.subject.ST,
    L = CSR_POLICY.subject.L,
    O = CSR_POLICY.subject.O,
    CN = 'MockCN',
    additionalAttributes = [],
  } = subject;

  const parts = [
    C === null ? null : `C=${C}`,
    ST === null ? null : `ST=${ST}`,
    L === null ? null : `L=${L}`,
    O === null ? null : `O=${O}`,
    CN === null ? null : `CN=${CN}`,
    ...additionalAttributes,
  ].filter((part): part is string => part !== null);

  return parts.join(', ');
}
