import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FirebaseAppCheckSigner } from './firebase-appcheck-signer';
import * as keyPairManager from '../common/mock-utils/key-pair-manager';

vi.mock('../common/mock-utils/key-pair-manager');
vi.mock('node:crypto', async () => {
  const actual = await vi.importActual('node:crypto');
  return {
    ...actual,
    createSign: vi.fn(() => ({
      update: vi.fn(),
      sign: vi.fn(() => 'mock-signature'),
    })),
    randomUUID: vi.fn(() => 'mock-uuid'),
  };
});

describe('FirebaseAppCheckSigner', () => {
  let signer: FirebaseAppCheckSigner;
  const mockKeyPair = {
    privateKeyPem: 'mock-private-key',
    publicKeyPem: 'mock-public-key',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    signer = new FirebaseAppCheckSigner({
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-secret',
      DEVICE_KEYS_SECRET: 'mock-device-secret',
      FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
    });
    vi.spyOn(keyPairManager, 'getOrCreateRSAKeys').mockResolvedValue(
      mockKeyPair,
    );
  });

  describe('generateDebugToken', () => {
    it('should generate a valid JWT token', async () => {
      const token = await signer.generateDebugToken();

      expect(token).toBeDefined();
      const parts = token.split('.');
      expect(parts).toHaveLength(3); // header.payload.signature

      // Decode and verify header
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      expect(header).toEqual({
        alg: 'RS256',
        typ: 'JWT',
        kid: 'firebase-appcheck-debug',
      });

      // Decode and verify payload
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      expect(payload.sub).toBe('1:1111:ios:org.multipaz.identityreader');
      expect(payload.aud).toEqual(['projects/mock-verifier-app']);
      expect(payload.provider).toBe('custom');
      expect(payload.iss).toBe(
        'https://firebaseappcheck.googleapis.com/v1/jwks',
      );
      expect(payload.exp).toBeGreaterThan(payload.iat);
      expect(payload.jti).toBe('mock-uuid');
      expect(keyPairManager.getOrCreateRSAKeys).toHaveBeenCalledWith(
        'mock-secret',
      );
    });

    it('should generate token with custom appId', async () => {
      const token = await signer.generateDebugToken('custom.app.id');

      const parts = token.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      expect(payload.sub).toBe('1:1111:ios:custom.app.id');
    });

    it('should generate token with invalid-sub scenario', async () => {
      const token = await signer.generateDebugToken(
        'org.multipaz.identityreader',
        'invalid-sub',
      );

      const parts = token.split('.');
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      expect(payload.sub).toBe('invalid-jwt');
    });

    it('should throw error when config is invalid', async () => {
      const invalidSigner = new FirebaseAppCheckSigner({});

      await expect(invalidSigner.generateDebugToken()).rejects.toThrow(
        'Failed to load configuration',
      );
    });
  });

  describe('getPublicKeyPem', () => {
    it('should return public key PEM', async () => {
      const publicKey = await signer.getPublicKeyPem('mock-secret');

      expect(publicKey).toBe(mockKeyPair.publicKeyPem);
    });
  });
});
