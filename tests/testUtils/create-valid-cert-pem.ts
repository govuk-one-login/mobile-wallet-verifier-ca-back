import {
  X509CertificateGenerator,
  SubjectKeyIdentifierExtension,
  AuthorityKeyIdentifierExtension,
} from '@peculiar/x509';
import {
  EXPECTED_ISSUER_AND_SUBJECT_NAME,
  EXPECTED_ISSUER_CN,
  TWENTY_FOUR_HOURS_IN_MS,
} from '../../src/lambdas/common/certificate-service-constants/certificate-service-constants.ts';

type CertKeyAlgorithm = 'ec-p256' | 'ec-p384' | 'rsa';

const DEFAULT_ISSUER_NAME = `C=${EXPECTED_ISSUER_AND_SUBJECT_NAME.C}, ST=${EXPECTED_ISSUER_AND_SUBJECT_NAME.ST}, L=${EXPECTED_ISSUER_AND_SUBJECT_NAME.L}, O=${EXPECTED_ISSUER_AND_SUBJECT_NAME.O}, CN=${EXPECTED_ISSUER_CN}`;

export interface CreateValidCertPemOptions {
  keyAlgorithm?: CertKeyAlgorithm;
  invalidX509?: boolean;
  notBefore?: Date;
  notAfter?: Date;
  issuerName?: string;
  subjectCn?: string;
  subjectName?: string;
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

  const notBefore = options.notBefore ?? new Date(Date.now() - 60 * 60 * 1000);
  const notAfter =
    options.notAfter ?? new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS);
  const issuerName = options.issuerName ?? DEFAULT_ISSUER_NAME;

  if (options.subjectCn || options.subjectName) {
    const subject =
      options.subjectName ??
      `C=${EXPECTED_ISSUER_AND_SUBJECT_NAME.C}, ST=${EXPECTED_ISSUER_AND_SUBJECT_NAME.ST}, L=${EXPECTED_ISSUER_AND_SUBJECT_NAME.L}, O=${EXPECTED_ISSUER_AND_SUBJECT_NAME.O}, CN=${options.subjectCn}`;
    const cert = await X509CertificateGenerator.create({
      issuer: issuerName,
      subject,
      publicKey: keys.publicKey,
      signingKey: keys.privateKey,
      signingAlgorithm,
      notBefore,
      notAfter,
    });
    return cert.toString('pem');
  }

  const cert = await X509CertificateGenerator.createSelfSigned({
    name: issuerName,
    keys,
    signingAlgorithm,
    notBefore,
    notAfter,
  });

  return cert.toString('pem');
}

export interface CreateCaAndLeafCertPemResult {
  caCertPem: string;
  leafCertPem: string;
}

export async function createCaAndLeafCertPem(
  subjectCn: string,
): Promise<CreateCaAndLeafCertPemResult> {
  const caKeys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
  const leafKeys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );

  const signingAlgorithm: EcdsaParams = { name: 'ECDSA', hash: 'SHA-384' };
  const notBefore = new Date(Date.now() - 60 * 60 * 1000);
  const notAfter = new Date(notBefore.getTime() + TWENTY_FOUR_HOURS_IN_MS);

  const caCert = await X509CertificateGenerator.createSelfSigned({
    name: DEFAULT_ISSUER_NAME,
    keys: caKeys,
    signingAlgorithm,
    notBefore,
    notAfter,
    extensions: [await SubjectKeyIdentifierExtension.create(caKeys.publicKey)],
  });

  const subject = `C=${EXPECTED_ISSUER_AND_SUBJECT_NAME.C}, ST=${EXPECTED_ISSUER_AND_SUBJECT_NAME.ST}, L=${EXPECTED_ISSUER_AND_SUBJECT_NAME.L}, O=${EXPECTED_ISSUER_AND_SUBJECT_NAME.O}, CN=${subjectCn}`;
  const leafCert = await X509CertificateGenerator.create({
    issuer: DEFAULT_ISSUER_NAME,
    subject,
    publicKey: leafKeys.publicKey,
    signingKey: caKeys.privateKey,
    signingAlgorithm,
    notBefore,
    notAfter,
    extensions: [
      await AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });

  return {
    caCertPem: caCert.toString('pem'),
    leafCertPem: leafCert.toString('pem'),
  };
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
