import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecretsManagerKeyStore } from './secrets-manager';
import {
  GetSecretValueCommand,
  UpdateSecretCommand,
} from '@aws-sdk/client-secrets-manager';

const mockSend = vi.fn();

vi.mock('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: vi.fn().mockImplementation(function () {
    return {
      send: mockSend,
    };
  }),
  GetSecretValueCommand: vi.fn(),
  UpdateSecretCommand: vi.fn(),
}));

describe('SecretsManagerKeyStore', () => {
  let keyStore: SecretsManagerKeyStore;

  beforeEach(() => {
    vi.clearAllMocks();
    keyStore = new SecretsManagerKeyStore('us-east-1');
  });

  describe('getKeyPair', () => {
    it('should return key pair when secret exists', async () => {
      const mockKeyPair = {
        privateKeyPem:
          '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
        publicKeyPem:
          '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      };

      mockSend.mockResolvedValue({
        SecretString: JSON.stringify({ keyPair: mockKeyPair }),
      });

      const result = await keyStore.getKeyPair('test-secret');

      expect(result).toEqual(mockKeyPair);
      expect(mockSend).toHaveBeenCalledWith(expect.any(GetSecretValueCommand));
    });

    it('should return null when secret does not exist', async () => {
      const error = new Error('Secret not found');
      error.name = 'ResourceNotFoundException';
      mockSend.mockRejectedValue(error);

      const result = await keyStore.getKeyPair('test-secret');

      expect(result).toBeNull();
    });

    it('should throw error for non-ResourceNotFoundException errors', async () => {
      const error = new Error('Access denied');
      error.name = 'AccessDeniedException';
      mockSend.mockRejectedValue(error);

      await expect(keyStore.getKeyPair('test-secret')).rejects.toThrow(
        'Access denied',
      );
    });
  });

  describe('updateKeyPair', () => {
    it('should update key pair successfully', async () => {
      const mockKeyPair = {
        privateKeyPem:
          '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
        publicKeyPem:
          '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      };

      mockSend.mockResolvedValue({});

      await keyStore.updateKeyPair('test-secret', mockKeyPair);

      expect(mockSend).toHaveBeenCalledWith(expect.any(UpdateSecretCommand));
    });

    it('should throw error when update fails', async () => {
      const mockKeyPair = {
        privateKeyPem:
          '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
        publicKeyPem:
          '-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----',
      };

      const error = new Error('Update failed');
      mockSend.mockRejectedValue(error);

      await expect(
        keyStore.updateKeyPair('test-secret', mockKeyPair),
      ).rejects.toThrow('Update failed');
    });
  });
});
