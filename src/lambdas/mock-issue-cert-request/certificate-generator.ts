import { importECDSAKeyPair } from '../common/mock-utils/key-pair-manager';

export interface CSRSubject {
  countryName: string;
  stateOrProvinceName: string;
  localityName: string;
  organizationName: string;
  commonName: string;
}

export interface CSROptions {
  subject: CSRSubject;
}

export interface CSRResult {
  privateKeyPem: string;
  csrPem: string;
  publicKeyPem: string;
}

function buildSubjectString(subject: CSRSubject): string {
  const parts = [
    `C=${subject.countryName}`,
    `ST=${subject.stateOrProvinceName}`,
    `L=${subject.localityName}`,
    `O=${subject.organizationName}`,
    `CN=${subject.commonName}`,
  ];
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
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
  });

  return {
    privateKeyPem: keyPair.privateKeyPem,
    csrPem: csr.toString('pem'),
    publicKeyPem: keyPair.publicKeyPem,
  };
}
