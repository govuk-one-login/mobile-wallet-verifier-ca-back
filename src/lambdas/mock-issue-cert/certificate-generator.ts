import { importECDSAKeyPair } from '../common/mock-utils/crypto-utils';

export interface CSRSubject {
  countryName?: string;
  stateOrProvinceName?: string;
  localityName?: string;
  organizationName?: string;
  organizationalUnitName?: string;
  commonName: string;
  emailAddress?: string;
  serialNumber?: string;
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
  if (subject.serialNumber) parts.push(`2.5.4.5=${subject.serialNumber}`);
  if (subject.emailAddress) parts.push(`E=${subject.emailAddress}`);
  return parts.join(', ');
}

export async function generateCSR(
  options: CSROptions & { privateKeyPem: string; publicKeyPem: string },
): Promise<CSRResult> {
  const keyPair = {
    privateKeyPem: options.privateKeyPem,
    publicKeyPem: options.publicKeyPem,
  };
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
