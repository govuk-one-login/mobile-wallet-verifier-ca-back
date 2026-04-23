import { X509CertificateGenerator } from '@peculiar/x509';

export async function createValidCertPem(): Promise<string> {
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
  const cert = await X509CertificateGenerator.createSelfSigned({
    name: 'CN=Test',
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
    notBefore: new Date('2024-01-01'),
    notAfter: new Date('2025-01-01'),
  });
  return cert.toString('pem');
}
