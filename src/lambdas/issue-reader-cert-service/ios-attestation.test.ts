import { describe, it, expect, vi } from 'vitest';
import { verifyIOSAttestation } from './ios-attestation';

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: class MockLogger {
    info = vi.fn();
    warn = vi.fn();
    error = vi.fn();
  },
}));

describe('iOS Attestation Module', () => {
  describe('verifyIOSAttestation', () => {
    const mockRequest = {
      platform: 'ios' as const,
      nonce: 'test-nonce',
      csrPem: '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
      appAttest: {
        keyId: 'test-key-id',
        attestationObject: 'test-attestation',
        clientDataJSON: 'test-client-data',
      },
    };

    it('should return valid result for iOS request', async () => {
      const result = await verifyIOSAttestation(mockRequest);

      expect(result.valid).toBe(true);
      expect(result.code).toBeUndefined();
      expect(result.message).toBeUndefined();
    });

    it('should handle request without appAttest', async () => {
      const requestWithoutAppAttest = {
        ...mockRequest,
        appAttest: undefined,
      };

      const result = await verifyIOSAttestation(requestWithoutAppAttest);

      expect(result.valid).toBe(true);
    });

    it('should handle request with different keyId', async () => {
      const requestWithDifferentKeyId = {
        ...mockRequest,
        appAttest: {
          ...mockRequest.appAttest,
          keyId: 'different-key-id',
        },
      };

      const result = await verifyIOSAttestation(requestWithDifferentKeyId);

      expect(result.valid).toBe(true);
    });
  });
});
