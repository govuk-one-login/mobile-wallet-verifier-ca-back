import { describe, it, expect, beforeEach, vi } from 'vitest';
import { validatePlayIntegritySignature, validatePlayIntegrityPayload } from './play-integrity-validator';

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: class MockLogger {
    info = vi.fn();
    warn = vi.fn();
    error = vi.fn();
  },
}));

vi.mock('jose', () => ({
  decodeProtectedHeader: vi.fn(),
  createRemoteJWKSet: vi.fn(),
  jwtVerify: vi.fn(),
}));

describe('Play Integrity Validator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.ALLOW_TEST_TOKENS;
    process.env.EXPECTED_ANDROID_PACKAGE_NAME = 'org.multipaz.identityreader';
  });

  describe('validatePlayIntegritySignature', () => {
    it('should return valid when ALLOW_TEST_TOKENS is true', async () => {
      process.env.ALLOW_TEST_TOKENS = 'true';

      const result = await validatePlayIntegritySignature('test-token');

      expect(result.valid).toBe(true);
    });

    it('should return invalid when JWT header missing kid', async () => {
      process.env.ALLOW_TEST_TOKENS = 'false';

      const { decodeProtectedHeader } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({});

      const result = await validatePlayIntegritySignature('test-token');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_play_integrity');
      expect(result.message).toBe('JWT header missing kid (key ID)');
    });

    it('should return valid when JWT verification succeeds', async () => {
      process.env.ALLOW_TEST_TOKENS = 'false';

      const { decodeProtectedHeader, createRemoteJWKSet, jwtVerify } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({ kid: 'test-key-id' });
      vi.mocked(createRemoteJWKSet).mockReturnValue({} as ReturnType<typeof createRemoteJWKSet>);
      vi.mocked(jwtVerify).mockResolvedValue({} as Awaited<ReturnType<typeof jwtVerify>>);

      const result = await validatePlayIntegritySignature('test-token');

      expect(result.valid).toBe(true);
    });

    it('should throw error when JWT verification fails', async () => {
      process.env.ALLOW_TEST_TOKENS = 'false';

      const { decodeProtectedHeader, createRemoteJWKSet, jwtVerify } = await import('jose');
      vi.mocked(decodeProtectedHeader).mockReturnValue({ kid: 'test-key-id' });
      vi.mocked(createRemoteJWKSet).mockReturnValue({} as ReturnType<typeof createRemoteJWKSet>);
      vi.mocked(jwtVerify).mockRejectedValue(new Error('JWT verification failed'));

      await expect(validatePlayIntegritySignature('test-token')).rejects.toThrow('JWT verification failed');
    });
  });

  describe('validatePlayIntegrityPayload', () => {
    const validPayload = {
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
    };

    it('should return valid for correct payload', () => {
      const result = validatePlayIntegrityPayload(validPayload, 'test-nonce');

      expect(result.valid).toBe(true);
    });

    it('should return invalid for nonce mismatch', () => {
      const result = validatePlayIntegrityPayload(validPayload, 'wrong-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('nonce_mismatch');
      expect(result.message).toBe('Play Integrity nonce does not match request nonce');
    });

    it('should return invalid for wrong package name', () => {
      process.env.EXPECTED_ANDROID_PACKAGE_NAME = 'org.multipaz.identityreader';
      const payload = {
        ...validPayload,
        appIntegrity: { ...validPayload.appIntegrity, packageName: 'com.malicious.app' },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_package');
      expect(result.message).toBe('Package name mismatch');
    });

    it('should use custom package name from environment', () => {
      process.env.EXPECTED_ANDROID_PACKAGE_NAME = 'com.custom.app';

      const payload = {
        ...validPayload,
        appIntegrity: { ...validPayload.appIntegrity, packageName: 'com.custom.app' },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(true);
    });

    it('should return invalid for unrecognized app', () => {
      const payload = {
        ...validPayload,
        appIntegrity: { ...validPayload.appIntegrity, appRecognitionVerdict: 'UNKNOWN' },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('app_not_recognized');
      expect(result.message).toBe('App not recognized by Play Store');
    });

    it('should return invalid for device integrity failure', () => {
      const payload = {
        ...validPayload,
        deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_WEAK_INTEGRITY'] },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('device_integrity_failed');
      expect(result.message).toBe('Device integrity check failed');
    });

    it('should accept MEETS_BASIC_INTEGRITY', () => {
      const payload = {
        ...validPayload,
        deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(true);
    });

    it('should return invalid for unlicensed app', () => {
      const payload = {
        ...validPayload,
        accountDetails: { appLicensingVerdict: 'UNLICENSED' },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('app_not_licensed');
      expect(result.message).toBe('App is not properly licensed');
    });

    it('should warn but pass for unevaluated licensing', () => {
      const payload = {
        ...validPayload,
        accountDetails: { appLicensingVerdict: 'UNEVALUATED' },
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(true);
    });

    it('should handle missing payload fields gracefully', () => {
      const result = validatePlayIntegrityPayload({}, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('nonce_mismatch');
    });

    it('should handle missing device integrity', () => {
      const payload = {
        ...validPayload,
        deviceIntegrity: undefined,
      };

      const result = validatePlayIntegrityPayload(payload, 'test-nonce');

      expect(result.valid).toBe(false);
      expect(result.code).toBe('device_integrity_failed');
    });
  });
});
