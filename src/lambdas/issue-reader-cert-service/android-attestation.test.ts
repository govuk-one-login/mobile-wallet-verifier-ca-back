import { describe, it, expect, beforeEach, vi } from 'vitest';
import { verifyAndroidAttestation } from './android-attestation';

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  })),
}));

// Mock jose module
vi.mock('jose', () => ({
  decodeProtectedHeader: vi.fn(),
  createRemoteJWKSet: vi.fn(),
  jwtVerify: vi.fn(),
  decodeJwt: vi.fn(),
}));

// Mock @peculiar/x509
vi.mock('@peculiar/x509', () => ({
  X509Certificate: vi.fn(),
  Pkcs10CertificateRequest: vi.fn(),
}));

// Mock @peculiar/asn1-android
vi.mock('@peculiar/asn1-android', () => ({
  SecurityLevel: {
    trustedEnvironment: 1,
    strongBox: 2,
  },
}));

// Mock @peculiar/asn1-schema
vi.mock('@peculiar/asn1-schema', () => ({
  AsnConvert: {
    parse: vi.fn(),
  },
}));

describe('Android Attestation Module', () => {
  const mockRequest = {
    platform: 'android' as const,
    nonce: 'test-nonce',
    csrPem: '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
    keyAttestationChain: ['dGVzdA==', 'dGVzdDI='],
    playIntegrityToken: 'test-token',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    // Set default environment for tests
    process.env.ALLOW_TEST_TOKENS = 'true';
  });

  describe('verifyAndroidAttestation', () => {
    it('should return error for missing Play Integrity token', async () => {
      const requestWithoutToken = {
        ...mockRequest,
        playIntegrityToken: undefined as any,
      };

      const result = await verifyAndroidAttestation(requestWithoutToken);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('attestation_error');
    });

    it('should return error for missing key attestation chain', async () => {
      const requestWithoutChain = {
        ...mockRequest,
        keyAttestationChain: undefined as any,
      };

      const result = await verifyAndroidAttestation(requestWithoutChain);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('attestation_error');
    });

    it('should handle internal errors gracefully', async () => {
      // Mock jose.decodeJwt to throw an error
      const jose = require('jose');
      jose.decodeJwt.mockImplementation(() => {
        throw new Error('JWT decode error');
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('attestation_error');
      expect(result.message).toBe('Internal error during attestation verification');
    });

    it('should skip Google JWKS verification in test mode', async () => {
      const jose = require('jose');
      jose.decodeJwt.mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
        deviceIntegrity: {
          deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'],
        },
        accountDetails: {
          appLicensingVerdict: 'LICENSED',
        },
      });

      // Mock certificate chain validation
      const { X509Certificate } = require('@peculiar/x509');
      X509Certificate.mockImplementation(() => ({
        notBefore: new Date(Date.now() - 1000),
        notAfter: new Date(Date.now() + 1000),
        extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17' }],
        publicKey: {
          algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
          getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        },
        subject: 'CN=Test Google Root',
      }));

      const { Pkcs10CertificateRequest } = require('@peculiar/x509');
      Pkcs10CertificateRequest.mockImplementation(() => ({
        publicKey: {
          getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
        },
      }));

      const { AsnConvert } = require('@peculiar/asn1-schema');
      AsnConvert.parse.mockReturnValue({
        attestationChallenge: { buffer: Buffer.from('test-nonce').buffer },
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(true);
    });
  });
});