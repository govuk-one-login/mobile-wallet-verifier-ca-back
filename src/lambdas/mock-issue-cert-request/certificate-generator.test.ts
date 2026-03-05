import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateCSR, CSRSubject } from './certificate-generator';
import * as keyPairManager from '../common/mock-utils/key-pair-manager';

vi.mock('../common/mock-utils/key-pair-manager');
vi.mock('@peculiar/x509', () => ({
  Pkcs10CertificateRequestGenerator: {
    create: vi.fn().mockResolvedValue({
      toString: () =>
        '-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR\n-----END CERTIFICATE REQUEST-----',
    }),
  },
}));

describe('generateCSR', () => {
  const mockKeyPair = {
    privateKeyPem:
      '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
    publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
  };

  const mockCryptoKeys = {
    privateKey: {} as CryptoKey,
    publicKey: {} as CryptoKey,
  };

  beforeEach(() => {
    vi.spyOn(keyPairManager, 'importECDSAKeyPair').mockResolvedValue(
      mockCryptoKeys,
    );
  });

  it('should generate CSR with all subject fields', async () => {
    const subject: CSRSubject = {
      countryName: 'GB',
      stateOrProvinceName: 'England',
      localityName: 'London',
      organizationName: 'Example Org',
      organizationalUnitName: 'IT',
      commonName: 'example.com',
      emailAddress: 'test@example.com',
      serialNumber: '12345',
    };

    const result = await generateCSR({
      ...mockKeyPair,
      subject,
    });

    expect(result).toEqual({
      privateKeyPem: mockKeyPair.privateKeyPem,
      publicKeyPem: mockKeyPair.publicKeyPem,
      csrPem:
        '-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR\n-----END CERTIFICATE REQUEST-----',
    });
  });

  it('should call importECDSAKeyPair with correct key pair', async () => {
    const importSpy = vi.spyOn(keyPairManager, 'importECDSAKeyPair');
    const subject: CSRSubject = {
      commonName: 'example.com',
    };

    await generateCSR({
      ...mockKeyPair,
      subject,
    });

    expect(importSpy).toHaveBeenCalledWith({
      privateKeyPem: mockKeyPair.privateKeyPem,
      publicKeyPem: mockKeyPair.publicKeyPem,
    });
  });
});
