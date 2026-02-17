import {
  generateECDSAKeyPair,
  importECDSAKeyPair,
  KeyPair,
} from './crypto-utils';

export interface CSRSubject {
  countryName?: string;
  stateOrProvinceName?: string;
  localityName?: string;
  organizationName?: string;
  organizationalUnitName?: string;
  commonName: string;
  emailAddress?: string;
}

export interface CSROptions {
  keySize?: number;
  subject: CSRSubject;
}

export interface CSRResult {
  privateKeyPem: string;
  csrPem: string;
  publicKeyPem: string;
}

function buildSubjectString(subject: CSRSubject): string {
  const parts = [];
  if (subject.countryName) parts.push(`C=${subject.countryName}`);
  if (subject.stateOrProvinceName)
    parts.push(`ST=${subject.stateOrProvinceName}`);
  if (subject.localityName) parts.push(`L=${subject.localityName}`);
  if (subject.organizationName) parts.push(`O=${subject.organizationName}`);
  if (subject.organizationalUnitName)
    parts.push(`OU=${subject.organizationalUnitName}`);
  parts.push(`CN=${subject.commonName}`);
  if (subject.emailAddress) parts.push(`emailAddress=${subject.emailAddress}`);
  return parts.join(', ');
}

function generateOrUseKeyPair(options: {
  privateKeyPem?: string;
  publicKeyPem?: string;
  keySize?: number;
}): KeyPair {
  if (options.privateKeyPem && options.publicKeyPem) {
    return {
      privateKeyPem: options.privateKeyPem,
      publicKeyPem: options.publicKeyPem,
    };
  }

  return generateECDSAKeyPair('prime256v1');
}

export async function generateCSR(
  options: CSROptions & { privateKeyPem?: string; publicKeyPem?: string },
): Promise<CSRResult> {
  const keyPair = generateOrUseKeyPair(options);
  const subject = buildSubjectString(options.subject);
  const cryptoKeys = await importECDSAKeyPair(keyPair);

  const { Pkcs10CertificateRequestGenerator } = await import('@peculiar/x509');
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: subject,
    keys: cryptoKeys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });

  return {
    privateKeyPem: keyPair.privateKeyPem,
    csrPem: csr.toString('pem'),
    publicKeyPem: keyPair.publicKeyPem,
  };
}
