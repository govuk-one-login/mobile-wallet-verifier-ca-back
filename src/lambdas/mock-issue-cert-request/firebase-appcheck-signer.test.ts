import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FirebaseAppCheckSigner } from './firebase-appcheck-signer';
import * as keyPairManager from '../common/mock-utils/key-pair-manager';
import * as dependencies from './mock-issue-cert-handler-dependencies';

vi.mock('../common/mock-utils/key-pair-manager');

describe('FirebaseAppCheckSigner', () => {
  let signer: FirebaseAppCheckSigner;
  const mockKeyPair = {
    privateKeyPem: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCiBX4Wjh3xohlz
YWsdn2IwRHBGkaraVRBVfhptKLc0ogaWP1WecYPcHqRWs1oOAxNdX8tEJ2sFyusi
F3Sy35bFIeSqZ0/+KdNccC9A+c1ykbPT50kfTkXveDJhYSN5IOYr/ee5jWYmOxeA
uqXK362dWE4X5yOvLV2g15EThK/C1ITsxBFjuSz24xKL/Gmzm/tIRmwN9T6HLqvl
ARMO0brbjrTk6J9MxySgwkEd6877d2POST+tyDrg11WaVBRIEzlKNbzdYvIrJ88s
u4Gr+93A9IDn3VVUehY5wNfZi4Cgpw7uFDArFoNTp8qzL2ujIFAaUnMnWqiJH8r2
zmXGfdidAgMBAAECggEABHNarJNwUqIliVQYfWqSp6lFnUaklxVFmteZMbzv1WgK
/scUGsNbACmuUXxhQafHeSXnv0JG8BSMI3ZZ/AzkxxsAfUbTvXNYLT6eqa4C/P3w
HubITS4ZATQ/zAl/UDU9ZWF241O1ReETKvPVmI5O5lbV5FWy1v3Lx96MC2l2a4dg
OkSEccNCCwoihIk63Ojil6f3Tw25+5XPDfzsRVQLt5ANY1oJLKOIyw/XomPBASbk
IDZfXrc4ku5Mm75maqwVxGlvQlb385Z/Zdj+5dRV6DqrfO98GX+4HRTLGbJY/A0X
7NlUwkw2adtRKAZWTBC0SKV2X+g8tzY3QRGFJ6sG8QKBgQDdKpbiz6uLjFKu7pMO
1CkN6HNXh6HZhhojyv0KbraJi/e1w1jAwNFqXlw+HS1nhQPGVLD9A+EFUwEEp53g
150xkCX45FnNzX7AYGmYbUWW8ffPr0c+ucSkAo1IrJo/4tezAEG85Qqzv+2uIrQ9
l8Xvr8CfEZoYOoKWxv8sr8WSUQKBgQC7ii9bHnVlFIGXh7DBRjneQmp1rodLFDxv
YyWFaGyrDmw8eDWsd3P6PJ64/TRgS3xbTPGEK8GymXryDrBZCqTSytkrxvK0KPtJ
1YrvWVeAJHmxYkFm2Cp/k1OHbUvhljsm5Un93f5XueAmHUxQXVUi+HPkUIl6c2IW
iFzTLIWijQKBgHM0bihzeK5WR/Orfpro1QHTpdFga2R9wDwIzsqSZS8846mguiid
x/gacv5AAJi95vt2vkLttFcrp4ofLdQjPFTG+6CsgkL72hynnBm0Qd2g6S8b5Ia+
CbpNQf8rOaYxqZ4qchPNU0fSoCJnHXBAEPELodC6QISCZefYfK9wWAAhAoGAOD6W
O0akQJ9oylBIo35zRoQ2t3qTWuIDygg7LYqG5LpbnbsTpdjhcJATrjlKJwMclak6
2b/hxLWhGM1s+BdoHUv229k72upbiuY/V888ndLSqG9mW/jCriY6K+iMlGhg7yZf
DYMxj4/QeL3asFN9gBJxd2zr/kxyg318EV1N6tUCgYEAjXUaNO6U8x4Bu/07EqRU
6rgWkFwNBZ3si6d5GkqikDl96m8Mk3w2JYAXvla486Ead3C66yh37rgMjPixspE0
IV+wo4OafHMHm4nLvQU5lcRRqO/H3IbhgI2tttwmrCp+exNFLdAegVVcHj/MSD3J
joM+fPBAuNmQB21fwzy24vo=
-----END PRIVATE KEY-----`,
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAogV+Fo4d8aIZc2FrHZ9i
MERwRpGq2lUQVX4abSi3NKIGlj9VnnGD3B6kVrNaDgMTXV/LRCdrBcrrIhd0st+W
xSHkqmdP/inTXHAvQPnNcpGz0+dJH05F73gyYWEjeSDmK/3nuY1mJjsXgLqlyt+t
nVhOF+cjry1doNeRE4SvwtSE7MQRY7ks9uMSi/xps5v7SEZsDfU+hy6r5QETDtG6
24605OifTMckoMJBHevO+3djzkk/rcg64NdVmlQUSBM5SjW83WLyKyfPLLuBq/vd
wPSA591VVHoWOcDX2YuAoKcO7hQwKxaDU6fKsy9royBQGlJzJ1qoiR/K9s5lxn3Y
nQIDAQAB
-----END PUBLIC KEY-----`,
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

    // Mock dependencies.env
    vi.spyOn(dependencies.dependencies, 'env', 'get').mockReturnValue({
      FIREBASE_APPCHECK_JWKS_SECRET: 'mock-secret',
      DEVICE_KEYS_SECRET: 'mock-device-secret',
      FIREBASE_JWKS_URI: 'https://firebaseappcheck.googleapis.com/v1/jwks',
    });
  });

  describe('generateDebugToken', () => {
    it('should generate a valid JWT token', async () => {
      const getOrCreateRSAKeysSpy = vi.spyOn(
        keyPairManager,
        'getOrCreateRSAKeys',
      );
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
      expect(payload.jti).toBeDefined();
      expect(getOrCreateRSAKeysSpy).toHaveBeenCalledWith('mock-secret');
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
