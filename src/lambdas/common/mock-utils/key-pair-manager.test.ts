import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  getOrGenerateECDSAKeyPair,
  getOrCreateRSAKeys,
  importECDSAKeyPair,
} from './key-pair-manager';
import { SecretsManagerKeyStore } from './secrets-manager';

vi.mock('./secrets-manager');

describe('key-pair-manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getOrGenerateECDSAKeyPair', () => {
    it('should return existing key pair if found', async () => {
      const mockKeyPair = {
        privateKeyPem:
          '-----BEGIN PRIVATE KEY-----\nEXISTING\n-----END PRIVATE KEY-----',
        publicKeyPem:
          '-----BEGIN PUBLIC KEY-----\nEXISTING\n-----END PUBLIC KEY-----',
      };

      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'getKeyPair',
      ).mockResolvedValue(mockKeyPair);
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'updateKeyPair',
      ).mockResolvedValue();

      const result = await getOrGenerateECDSAKeyPair('test-secret');

      expect(result).toEqual(mockKeyPair);
      expect(
        SecretsManagerKeyStore.prototype.updateKeyPair,
      ).not.toHaveBeenCalled();
    });

    it('should generate new key pair if not found', async () => {
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'getKeyPair',
      ).mockResolvedValue(null);
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'updateKeyPair',
      ).mockResolvedValue();

      const result = await getOrGenerateECDSAKeyPair('test-secret');

      expect(result.privateKeyPem).toContain('BEGIN PRIVATE KEY');
      expect(result.publicKeyPem).toContain('BEGIN PUBLIC KEY');
      expect(
        SecretsManagerKeyStore.prototype.updateKeyPair,
      ).toHaveBeenCalledWith('test-secret', result);
    });

    it('should generate new key pair if existing has PLACEHOLDER', async () => {
      const mockKeyPair = {
        privateKeyPem: 'PLACEHOLDER',
        publicKeyPem: 'PLACEHOLDER',
      };

      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'getKeyPair',
      ).mockResolvedValue(mockKeyPair);
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'updateKeyPair',
      ).mockResolvedValue();

      const result = await getOrGenerateECDSAKeyPair('test-secret');

      expect(result.privateKeyPem).not.toBe('PLACEHOLDER');
      expect(result.publicKeyPem).not.toBe('PLACEHOLDER');
      expect(SecretsManagerKeyStore.prototype.updateKeyPair).toHaveBeenCalled();
    });
  });

  describe('getOrCreateRSAKeys', () => {
    const firebaseJwksSecret = 'test-firebase-secret';

    it('should return existing RSA key pair if found', async () => {
      const mockKeyPair = {
        privateKeyPem:
          '-----BEGIN PRIVATE KEY-----\nEXISTING\n-----END PRIVATE KEY-----',
        publicKeyPem:
          '-----BEGIN PUBLIC KEY-----\nEXISTING\n-----END PUBLIC KEY-----',
      };

      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'getKeyPair',
      ).mockResolvedValue(mockKeyPair);
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'updateKeyPair',
      ).mockResolvedValue();

      const result = await getOrCreateRSAKeys(firebaseJwksSecret);

      expect(result).toEqual(mockKeyPair);
      expect(
        SecretsManagerKeyStore.prototype.updateKeyPair,
      ).not.toHaveBeenCalled();
    });

    it('should generate new RSA key pair if not found', async () => {
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'getKeyPair',
      ).mockResolvedValue(null);
      vi.spyOn(
        SecretsManagerKeyStore.prototype,
        'updateKeyPair',
      ).mockResolvedValue();

      const result = await getOrCreateRSAKeys(firebaseJwksSecret);

      expect(result.privateKeyPem).toContain('BEGIN PRIVATE KEY');
      expect(result.publicKeyPem).toContain('BEGIN PUBLIC KEY');
      expect(SecretsManagerKeyStore.prototype.updateKeyPair).toHaveBeenCalled();
    });
  });

  describe('importECDSAKeyPair', () => {
    it('should import valid P-384 ECDSA key pair', async () => {
      // Generate a real ECDSA key pair for testing
      const { generateKeyPairSync } = await import('node:crypto');
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'secp384r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const mockKeyPair = {
        privateKeyPem: privateKey,
        publicKeyPem: publicKey,
      };

      const result = await importECDSAKeyPair(mockKeyPair);

      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey.type).toBe('private');
      expect(result.publicKey.type).toBe('public');
      expect(result.privateKey.algorithm).toMatchObject({
        name: 'ECDSA',
        namedCurve: 'P-384',
      });
      expect(result.publicKey.algorithm).toMatchObject({
        name: 'ECDSA',
        namedCurve: 'P-384',
      });
    });
  });
});
