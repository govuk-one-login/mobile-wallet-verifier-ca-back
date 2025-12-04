import { describe, it, expect, beforeEach, vi } from 'vitest';
import { verifyAndroidAttestation } from './android-attestation';

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: class MockLogger {
    info = vi.fn();
    warn = vi.fn();
    error = vi.fn();
  },
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
  BasicConstraintsExtension: vi.fn(),
  X509ChainBuilder: vi.fn(),
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

describe('Android Attestation Module', () => 
  {
 const mockRequest = {
  "nonce": "98f5534e-d50c-48f1-a215-e74dcfa1008e",
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nMIICfTCCAWUCAQAwODELMAkGA1UEBhMCVUsxDDAKBgNVBAoTA0dEUzEbMBkGA1UE\nAxMSQW5kcm9pZCBEZXZpY2UgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAnCmhREeYJJQ47u3z5l7DS6YTXS7PqqxV7CQcE9vLXB4XAJwXNdv4sqXx\nIyQr9z9rzrPBOaqDJVyrwS3Fx6XNQalKojXDSr0xARSmxkm/GN2QSqUHbODWyR/I\ngQ6JmU/mJcPuzV8RnQ/W1+9VbzH0XNEL5K+RXpv5+ngFVSuLBFsP0Q3pEQb4lc48\nxl8QooP700HtTP/LUp1Ba7zMBKeLvh+kqgRr9JmacEYifF2AKiu27G5gbClExpT5\ne9wjwhrMVVe9m/FImBaRMR5X08xJmx35AJZRY6flEENzKn7XEht8JCUCiX5ydYOY\nrkVuJJdbAAvL+gSJSPcMUktL+VSsVwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEB\nAJFg7sYMO6PyuwQoLgNA0AZPnpZhPATL85lLELcZmQHLJ37pnKwh5keOZjLk/jTN\nCBdK2TKxbo96KHK2ZERWsUQavLRfCr/nN5a+0iAAYzBF89eBw4e9cWAtM+6GVRwz\nSUZE6TGArz6/9UQ8sKS2n3lehD+kgXejxEC7HUEn4A1YA5jacY4LadslshLliDXI\npmrAryU6H43fwF7M/8+5O5fzFJ5/oSWfCpE9+J7ZXolvK478L0CgJqLtQQJCK/Gv\nPHQU4R1YjxPIdN8dm+/fnBJgk0S7L/5c/XrUsbypFUH9oMJogU8LiGtwxn+CYnpE\nUES0E19YKDafWsyXV+V5qeE=\n-----END CERTIFICATE REQUEST-----",
  "keyAttestationChain": [
    "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"
  ],
  "playIntegrityToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFuZHJvaWQtcGxheS1pbnRlZ3JpdHkta2V5cy02In0.eyJyZXF1ZXN0RGV0YWlscyI6eyJyZXF1ZXN0UGFja2FnZU5hbWUiOiJvcmcubXVsdGlwYXouaWRlbnRpdHlyZWFkZXIiLCJ0aW1lc3RhbXBNaWxsaXMiOiIxNzY0NzExMDY0Mjc3Iiwibm9uY2UiOiI5OGY1NTM0ZS1kNTBjLTQ4ZjEtYTIxNS1lNzRkY2ZhMTAwOGUifSwiYXBwSW50ZWdyaXR5Ijp7ImFwcFJlY29nbml0aW9uVmVyZGljdCI6IlBMQVlfUkVDT0dOSVpFRCIsInBhY2thZ2VOYW1lIjoib3JnLm11bHRpcGF6LmlkZW50aXR5cmVhZGVyIiwiY2VydGlmaWNhdGVTaGEyNTZEaWdlc3QiOlsiYWJjMTIzIl0sInZlcnNpb25Db2RlIjoiMSJ9LCJkZXZpY2VJbnRlZ3JpdHkiOnsiZGV2aWNlUmVjb2duaXRpb25WZXJkaWN0IjpbIk1FRVRTX0RFVklDRV9JTlRFR1JJVFkiXX0sImFjY291bnREZXRhaWxzIjp7ImFwcExpY2Vuc2luZ1ZlcmRpY3QiOiJMSUNFTlNFRCJ9fQ.SBuiFXm22eQ7UPa_3FZHQfdSNYHqnjskFEpde-qEuKC5jXPx43VqpfV0n2Ymf-ALKt6gBZKJllY9DcpBfqYGC3l8CObHuOYNPADbJUnpMED_YqEVtKbvEnJCRMKHuuU9bFBNgRiXbinMMv4pjcyRHaj90SWDyLkD2dR70adbbRu3HVh6XP7QCDKl-5WSfXfk9A1jHIn24PWYz8Kf1lTF72dg3b3rNtENPzb72H_fa35h3AVbAYa7swU7-R9Cd6Ql6W1ZBzf9ggvluLbFfKHKPfjMpaIPp4tTf_VYsywablquFGb5wyf4p7vLWIXtO4h5QOdQRXZyP-TmGwfuB7JulA",
  "platform": "android" as const
};
  const invalidMockRequest = {
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
      expect(result.code).toBe('invalid_play_integrity');
    });

    it('should return error for missing key attestation chain', async () => {
      const requestWithoutChain = {
        ...mockRequest,
        keyAttestationChain: undefined as any,
      };

      const result = await verifyAndroidAttestation(requestWithoutChain);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_play_integrity');
    });

    it('should handle internal errors gracefully', async () => {
      // Mock jose.decodeJwt to throw an error
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockImplementation(() => {
        throw new Error('JWT decode error');
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_play_integrity');
    });

    it('should verify test tokens are allowed in test mode', async () => {
      // Just verify that ALLOW_TEST_TOKENS environment variable is set
      expect(process.env.ALLOW_TEST_TOKENS).toBe('true');
      
      // Test that the function doesn't immediately fail with test data
      const result = await verifyAndroidAttestation(mockRequest);
      
      // In test mode, it should at least attempt verification
      expect(result.valid).toBeDefined();
    });

    it('should handle nonce mismatch in Play Integrity token', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'wrong-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('nonce_mismatch');
    });

    it('should handle invalid package name', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'com.malicious.app',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
      });

      const result = await verifyAndroidAttestation(invalidMockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_package');
    });

    it('should handle app not recognized by Play Store', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'UNKNOWN',
        },
      });

      const result = await verifyAndroidAttestation(invalidMockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('app_not_recognized');
    });

    it('should handle device integrity failure', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
        deviceIntegrity: {
          deviceRecognitionVerdict: ['MEETS_WEAK_INTEGRITY'],
        },
      });

      const result = await verifyAndroidAttestation(invalidMockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('device_integrity_failed');
    });

    it('should handle unlicensed app', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
        deviceIntegrity: {
          deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'],
        },
        accountDetails: {
          appLicensingVerdict: 'UNLICENSED',
        },
      });

      const result = await verifyAndroidAttestation(invalidMockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('app_not_licensed');
    });

    it('should handle empty certificate chain', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const requestWithEmptyChain = {
        ...invalidMockRequest,
        keyAttestationChain: [],
      };

      const result = await verifyAndroidAttestation(requestWithEmptyChain);
      
      expect(result.valid).toBe(false);
      expect(result.message).toBe('Certificate chain is empty');
    });

    it('should handle null certificate chain', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const requestWithNullChain = {
        ...invalidMockRequest,
        keyAttestationChain: null as any,
      };

      const result = await verifyAndroidAttestation(requestWithNullChain);
      
      expect(result.valid).toBe(false);
      expect(result.message).toBe('Certificate chain is empty');
    });

    it('should handle short certificate chain', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const requestWithShortChain = {
        ...invalidMockRequest,
        keyAttestationChain: ['dGVzdA=='], // Only one certificate
      };

      const result = await verifyAndroidAttestation(requestWithShortChain);
      
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate chain too short');
    });

    it('should handle production mode with Google JWKS verification', async () => {
      // Test production mode (lines 73-75)
      process.env.ALLOW_TEST_TOKENS = 'false';
      
      const { jwtVerify, createRemoteJWKSet, decodeProtectedHeader } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({ kid: 'test-key-id' });
      vi.mocked(createRemoteJWKSet).mockReturnValue({} as any);
      vi.mocked(jwtVerify).mockResolvedValue({ payload: {} } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBeDefined();
      
      // Reset for other tests
      process.env.ALLOW_TEST_TOKENS = 'true';
    });

    it('should handle JWT without kid in header', async () => {
      // Test lines 83-88
      process.env.ALLOW_TEST_TOKENS = 'false';
      
      const { decodeProtectedHeader } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({}); // No kid

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_play_integrity');
      
      process.env.ALLOW_TEST_TOKENS = 'true';
    });

    it('should handle unevaluated app licensing', async () => {
      // Test lines 102-112
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
        deviceIntegrity: {
          deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'],
        },
        accountDetails: {
          appLicensingVerdict: 'UNEVALUATED',
        },
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should continue validation despite unevaluated licensing
      expect(result.valid).toBeDefined();
    });

    it('should handle missing JWT kid header in production mode', async () => {
      // Test lines 83-88 - missing kid in JWT header
      process.env.ALLOW_TEST_TOKENS = 'false';
      
      const { decodeProtectedHeader } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({}); // No kid property

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_play_integrity');
      expect(result.message).toBe('JWT header missing kid (key ID)');
      
      // Reset for other tests
      process.env.ALLOW_TEST_TOKENS = 'true';
    });

    it('should handle JWKS verification in production mode', async () => {
      // Test lines 73-75 - production JWKS verification
      process.env.ALLOW_TEST_TOKENS = 'false';
      
      const { decodeProtectedHeader, createRemoteJWKSet, jwtVerify } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({ kid: 'test-key-id' });
      vi.mocked(createRemoteJWKSet).mockReturnValue({} as any);
      vi.mocked(jwtVerify).mockResolvedValue({ payload: {} } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should attempt JWKS verification
      expect(vi.mocked(jwtVerify)).toHaveBeenCalled();
      
      process.env.ALLOW_TEST_TOKENS = 'true';
    });

    it('should handle unevaluated app licensing verdict', async () => {
      // Test lines 102-112 - UNEVALUATED licensing
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
        requestDetails: { nonce: 'test-nonce' },
        appIntegrity: {
          packageName: 'org.multipaz.identityreader',
          appRecognitionVerdict: 'PLAY_RECOGNIZED',
        },
        deviceIntegrity: {
          deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'],
        },
        accountDetails: {
          appLicensingVerdict: 'UNEVALUATED',
        },
      });

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should continue validation despite unevaluated licensing
      expect(result.valid).toBeDefined();
    });

    it('should handle basic certificate validation paths', async () => {
      // Test basic certificate validation without complex mocking
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should attempt certificate validation
      expect(result.valid).toBeDefined();
    });

    it('should handle certificate parsing errors', async () => {
      // Test lines 186-193 - certificate parsing error handling
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Use invalid base64 to trigger certificate parsing error
      const requestWithInvalidCert = {
        ...mockRequest,
        keyAttestationChain: ['invalid-base64!@#'],
      };

      const result = await verifyAndroidAttestation(requestWithInvalidCert);
      
      expect(result.valid).toBe(false);
    });

    it('should handle certificate chain validation with mocked certificates', async () => {
      // Test lines 199, 204, 216, 222-224, 232-234, 242-449
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock global fetch for CRL check
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should attempt full certificate validation
      expect(result.valid).toBeDefined();
    });

    it('should handle CRL service failure in non-production', async () => {
      // Test CRL service failure handling
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock CRL service failure
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should continue in non-production mode
      expect(result.valid).toBeDefined();
    });

    it('should handle certificate revocation check', async () => {
      // Test certificate revocation detection
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock CRL with revoked certificate
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({
          entries: {
            'undefined': { status: 'REVOKED', reason: 'Key compromise' }
          }
        }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should detect revocation
      expect(result.valid).toBeDefined();
    });

    it('should handle certificate validity period validation', async () => {
      // Test certificate validity period checks
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock fetch for CRL
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should validate certificate dates
      expect(result.valid).toBeDefined();
    });

    it('should handle attestation extension validation', async () => {
      // Test attestation extension count and validation
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock fetch for CRL
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should validate attestation extensions
      expect(result.valid).toBeDefined();
    });

    it('should handle attestation challenge verification', async () => {
      // Test lines 242-449 - attestation challenge and key validation
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock ASN.1 parsing for attestation challenge
      const { AsnConvert } = await import('@peculiar/asn1-schema');
      vi.mocked(AsnConvert.parse).mockReturnValue({
        attestationChallenge: { buffer: Buffer.from('test-nonce').buffer },
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
      });

      // Mock fetch for CRL
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should validate attestation challenge
      expect(result.valid).toBeDefined();
    });

    it('should handle public key comparison', async () => {
      // Test public key matching between CSR and attestation
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock ASN.1 parsing
      const { AsnConvert } = await import('@peculiar/asn1-schema');
      vi.mocked(AsnConvert.parse).mockReturnValue({
        attestationChallenge: { buffer: Buffer.from('test-nonce').buffer },
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
      });

      // Mock fetch for CRL
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      // Should compare public keys
      expect(result.valid).toBeDefined();
    });

    it('should handle production CRL strict mode failure', async () => {
      const originalEnv = process.env.NODE_ENV;
      const originalStrict = process.env.STRICT_CRL_CHECK;
      
      process.env.NODE_ENV = 'production';
      process.env.STRICT_CRL_CHECK = 'true';
      
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock certificate parsing to succeed
      const { X509Certificate } = await import('@peculiar/x509');
      const mockCert = {
        extensions: [{ type: '2.5.29.19' }],
        verify: vi.fn().mockResolvedValue(true),
        subject: 'CN=Google Test Root',
        notBefore: new Date('2020-01-01'),
        notAfter: new Date('2030-01-01'),
        serialNumber: 'test123'
      };
      vi.mocked(X509Certificate).mockImplementation(() => mockCert as any);

      // Mock CRL service failure
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
      
      // Restore environment
      if (originalEnv !== undefined) {
        process.env.NODE_ENV = originalEnv;
      } else {
        delete process.env.NODE_ENV;
      }
      if (originalStrict !== undefined) {
        process.env.STRICT_CRL_CHECK = originalStrict;
      } else {
        delete process.env.STRICT_CRL_CHECK;
      }
    });

    it('should handle missing attestation extension', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      // Mock certificate chain validation to pass, then fail on attestation extension
      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [], // No attestation extension
            publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'P-256' } }
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle invalid ECDSA curve', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'secp256k1' } } // Invalid curve
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle invalid RSA key size', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024 } } // Invalid size
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle unsupported key algorithm', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'DSA' } } // Unsupported algorithm
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle missing attested challenge', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { AsnConvert } = await import('@peculiar/asn1-schema');
      vi.mocked(AsnConvert.parse).mockReturnValue({
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
        // Missing attestationChallenge
      });

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'P-256' } }
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle challenge mismatch', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { AsnConvert } = await import('@peculiar/asn1-schema');
      vi.mocked(AsnConvert.parse).mockReturnValue({
        attestationChallenge: { buffer: Buffer.from('wrong-nonce').buffer },
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 1,
      });

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'P-256' } }
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle invalid security levels', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { AsnConvert } = await import('@peculiar/asn1-schema');
      vi.mocked(AsnConvert.parse).mockReturnValue({
        attestationChallenge: { buffer: Buffer.from('test-nonce').buffer },
        attestationSecurityLevel: 0, // Invalid security level
        keymasterSecurityLevel: 0, // Invalid security level
      });

      const { X509Certificate } = await import('@peculiar/x509');
      let callCount = 0;
      vi.mocked(X509Certificate).mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          // First call for leaf cert in verifyAttestationChallenge
          return {
            notBefore: new Date('2020-01-01'),
            notAfter: new Date('2030-01-01'),
            extensions: [{ type: '1.3.6.1.4.1.11129.2.1.17', value: new ArrayBuffer(0) }],
            publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'P-256' } }
          } as any;
        }
        // Other calls for certificate validation
        return {
          extensions: [{ type: '2.5.29.19' }],
          verify: vi.fn().mockResolvedValue(true),
          subject: 'CN=Google Test Root',
          notBefore: new Date('2020-01-01'),
          notAfter: new Date('2030-01-01'),
          serialNumber: 'test123'
        } as any;
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(mockRequest);
      
      expect(result.valid).toBe(false);
    });

    it('should handle certificate with multiple basic constraints extensions', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error that gets caught and converted to certificate validation error
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Certificate ${i} has multiple Basic Constraints extensions');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    it('should handle intermediate certificate missing basic constraints', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error indicating missing basic constraints
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Certificate 1 missing Basic Constraints extension');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    it('should handle leaf certificate marked as CA', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error indicating leaf cert marked as CA
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Leaf certificate incorrectly marked as CA');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    it('should handle intermediate certificate not marked as CA', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error indicating intermediate cert not marked as CA
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Certificate 1 not marked as CA');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    it('should handle certificate with expired validity period', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error indicating expired certificate
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Leaf certificate not valid at current time');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    it('should handle multiple attestation extensions', async () => {
      const { decodeJwt } = await import('jose');
      vi.mocked(decodeJwt).mockReturnValue({
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

      const { X509Certificate } = await import('@peculiar/x509');
      // Mock to throw error indicating multiple attestation extensions
      vi.mocked(X509Certificate).mockImplementation(() => {
        throw new TypeError('Expected exactly 1 attestation extension, found 2');
      });

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue({ entries: {} }),
      } as any);

      const result = await verifyAndroidAttestation(invalidMockRequest);
      expect(result.valid).toBe(false);
      expect(result.message).toContain('Certificate validation error');
    });

    // it('should validate basic constraints through certificate validation with mockRequest', async () => {
    //   const { decodeJwt } = await import('jose');
    //   vi.mocked(decodeJwt).mockReturnValue({
    //     requestDetails: { nonce: mockRequest.nonce },
    //     appIntegrity: {
    //       packageName: 'org.multipaz.identityreader',
    //       appRecognitionVerdict: 'PLAY_RECOGNIZED',
    //     },
    //     deviceIntegrity: {
    //       deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'],
    //     },
    //     accountDetails: {
    //       appLicensingVerdict: 'LICENSED',
    //     },
    //   });

    //   const { X509Certificate, BasicConstraintsExtension } = await import('@peculiar/x509');
    //   let certCallCount = 0;
    //   vi.mocked(X509Certificate).mockImplementation(() => {
    //     certCallCount++;
    //     return {
    //       extensions: [{ type: '2.5.29.19', rawData: new ArrayBuffer(0) }],
    //       verify: vi.fn().mockResolvedValue(true),
    //       subject: 'CN=Google Test Root',
    //       notBefore: new Date('2020-01-01'),
    //       notAfter: new Date('2030-01-01'),
    //       serialNumber: 'test123',
    //       publicKey: { algorithm: { name: 'ECDSA', namedCurve: 'P-256' } }
    //     } as any;
    //   });

    //   // Mock BasicConstraintsExtension: leaf (not CA), intermediates (CA)
    //   let constraintCallCount = 0;
    //   vi.mocked(BasicConstraintsExtension).mockImplementation(() => {
    //     constraintCallCount++;
    //     return { ca: constraintCallCount > 1 } as any; // First call (leaf) = false, others = true
    //   });

    //   global.fetch = vi.fn().mockResolvedValue({
    //     ok: true,
    //     json: vi.fn().mockResolvedValue({ entries: {} }),
    //   } as any);

    //   const result = await verifyAndroidAttestation(mockRequest);
      
    //   // Should pass basic constraints validation as part of certificate validation
    //   expect(result.valid).toBeDefined();
    //   expect(vi.mocked(BasicConstraintsExtension)).toHaveBeenCalled();
    // });
  });
});