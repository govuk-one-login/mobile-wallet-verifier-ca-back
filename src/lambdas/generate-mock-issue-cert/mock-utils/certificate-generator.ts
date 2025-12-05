import { generateECDSAKeyPair, importECDSAKeyPair, KeyPair } from './crypto-utils';

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
  if (subject.stateOrProvinceName) parts.push(`ST=${subject.stateOrProvinceName}`);
  if (subject.localityName) parts.push(`L=${subject.localityName}`);
  if (subject.organizationName) parts.push(`O=${subject.organizationName}`);
  if (subject.organizationalUnitName) parts.push(`OU=${subject.organizationalUnitName}`);
  parts.push(`CN=${subject.commonName}`);
  if (subject.emailAddress) parts.push(`emailAddress=${subject.emailAddress}`);
  return parts.join(', ');
}

function generateOrUseKeyPair(options: { privateKeyPem?: string; publicKeyPem?: string; keySize?: number }): KeyPair {
  if (options.privateKeyPem && options.publicKeyPem) {
    return { privateKeyPem: options.privateKeyPem, publicKeyPem: options.publicKeyPem };
  }
  
  return generateECDSAKeyPair('prime256v1');
}

export async function generateCSR(options: CSROptions & { privateKeyPem?: string; publicKeyPem?: string }): Promise<CSRResult> {
  const keyPair = generateOrUseKeyPair(options);
  const subject = buildSubjectString(options.subject);
  const cryptoKeys = await importECDSAKeyPair(keyPair);
  
  const { Pkcs10CertificateRequestGenerator } = await import('@peculiar/x509');
  const csr = await Pkcs10CertificateRequestGenerator.create({
    name: subject,
    keys: cryptoKeys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' }
  });
  
  return {
    privateKeyPem: keyPair.privateKeyPem,
    csrPem: csr.toString('pem'),
    publicKeyPem: keyPair.publicKeyPem
  };
}

export async function createIntermediateCA(keyPair: KeyPair, rootKeys: any, rootCert: string): Promise<string> {
  const { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags, X509Certificate } = await import('@peculiar/x509');
  const cryptoKeys = await importECDSAKeyPair(keyPair);
  const rootCryptoKeys = await importECDSAKeyPair(rootKeys);
  const parsedRootCert = new X509Certificate(rootCert);

  const cert = await X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Test Android Hardware Attestation Intermediate CA, OU=Android, O=Google Inc, C=US',
    issuer: parsedRootCert.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000), // 5 years
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: cryptoKeys.publicKey,
    signingKey: rootCryptoKeys.privateKey,
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true)
    ]
  });

  return cert.toString('pem');
}

export async function createLeafCertWithAttestation(keyPair: KeyPair, issuerKeys: any, issuerCert: string, nonce: string): Promise<string> {
  const { X509CertificateGenerator, BasicConstraintsExtension, KeyUsagesExtension, KeyUsageFlags, Extension, X509Certificate } = await import('@peculiar/x509');
  const cryptoKeys = await importECDSAKeyPair(keyPair);
  const issuerCryptoKeys = await importECDSAKeyPair(issuerKeys);
  const parsedIssuerCert = new X509Certificate(issuerCert);
  
  // Create Android attestation extension using the exact structure from real certificates
  const attestationExtData = createRealAndroidAttestationExtension(nonce);
  const attestationExt = new Extension('1.3.6.1.4.1.11129.2.1.17', false, new Uint8Array(attestationExtData));

  const cert = await X509CertificateGenerator.create({
    serialNumber: '03',
    subject: 'CN=Test Android Attestation, OU=Android, O=Google Inc, C=US',
    issuer: parsedIssuerCert.subject,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: cryptoKeys.publicKey,
    signingKey: issuerCryptoKeys.privateKey,
    extensions: [
      new BasicConstraintsExtension(false, undefined, false),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature | KeyUsageFlags.keyEncipherment, true),
      attestationExt
    ]
  });

  return cert.toString('pem');
}

function createRealAndroidAttestationExtension(nonce: string): Buffer {
  const nonceBuffer = Buffer.from(nonce, 'utf8');
  const nonceHex = nonceBuffer.toString('hex');
  const nonceLength = nonceBuffer.length;
  
  // Calculate total sequence length dynamically
  const fixedPartsLength = 3 + 3 + 3 + 3 + 2 + 2 + 2 + 2; // All fixed parts
  const totalLength = fixedPartsLength + nonceLength;
  const totalLengthHex = totalLength.toString(16).padStart(2, '0');
  const nonceLengthHex = nonceLength.toString(16).padStart(2, '0');
  
  // Build the structure with dynamic lengths
  const parts = [
    '30' + totalLengthHex,    // SEQUENCE (dynamic length)
    '020104',                 // INTEGER 4 (attestationVersion)
    '0A0101',                 // INTEGER 1 (attestationSecurityLevel - TEE)
    '020104',                 // INTEGER 4 (keymasterVersion)
    '0A0101',                 // INTEGER 1 (keymasterSecurityLevel - TEE)
    '04' + nonceLengthHex,    // OCTET STRING (dynamic length)
    nonceHex,                 // The actual nonce
    '0400',                   // OCTET STRING (0 bytes) - uniqueId
    '3000',                   // SEQUENCE (0 bytes) - softwareEnforced
    '3000'                    // SEQUENCE (0 bytes) - teeEnforced
  ];
  
  return Buffer.from(parts.join(''), 'hex');
}