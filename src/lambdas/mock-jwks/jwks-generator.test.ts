import { describe, it, expect, vi, beforeEach } from 'vitest';
import { generateJWKS } from './jwks-generator';
import * as keyPairManager from '../common/mock-utils/key-pair-manager';

vi.mock('../common/mock-utils/key-pair-manager');

describe('generateJWKS', () => {
  const mockKeyPair = {
    privateKeyPem:
      '-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----',
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should generate JWKS with correct structure', async () => {
    vi.spyOn(keyPairManager, 'getOrCreateRSAKeys').mockResolvedValue(
      mockKeyPair,
    );

    const result = await generateJWKS('mock-firebase-secret');

    expect(result).toHaveProperty('keys');
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0]).toMatchObject({
      kty: 'RSA',
      use: 'sig',
      kid: 'firebase-appcheck-debug',
      alg: 'RS256',
    });
    expect(result.keys[0]).toHaveProperty('n');
    expect(result.keys[0]).toHaveProperty('e');
  });

  it('should throw error if public key is missing header', async () => {
    const invalidKeyPair = {
      ...mockKeyPair,
      publicKeyPem: 'MOCK\n-----END PUBLIC KEY-----',
    };
    vi.spyOn(keyPairManager, 'getOrCreateRSAKeys').mockResolvedValue(
      invalidKeyPair,
    );

    await expect(generateJWKS('mock-firebase-secret')).rejects.toThrow(
      'Invalid public key PEM format - missing header',
    );
  });

  it('should throw error if public key is missing footer', async () => {
    const invalidKeyPair = {
      ...mockKeyPair,
      publicKeyPem: '-----BEGIN PUBLIC KEY-----\nMOCK',
    };
    vi.spyOn(keyPairManager, 'getOrCreateRSAKeys').mockResolvedValue(
      invalidKeyPair,
    );

    await expect(generateJWKS('mock-firebase-secret')).rejects.toThrow(
      'Invalid public key PEM format - missing footer',
    );
  });
});
