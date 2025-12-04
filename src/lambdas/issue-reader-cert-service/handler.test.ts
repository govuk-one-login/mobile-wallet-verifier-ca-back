import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { APIGatewayProxyEvent, Context } from 'aws-lambda';

const mockRandomUUID = vi.hoisted(() => vi.fn(() => 'test-uuid-123'));

vi.mock('node:crypto', () => ({
  randomUUID: mockRandomUUID,
}));

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: class MockLogger {
    info = vi.fn();
    warn = vi.fn();
    error = vi.fn();
  },
}));

import { handler } from './handler';

const mockContext: Context = {
  awsRequestId: 'test-request-id',
} as Context;

const createMockEvent = (
  httpMethod = 'POST',
  path = '/issue-reader-cert',
  body: string | null = null,
): APIGatewayProxyEvent =>
  ({
    httpMethod,
    path,
    body,
    requestContext: {},
  }) as APIGatewayProxyEvent;

const validIOSRequest = {
  platform: 'ios',
  nonce: 'test-nonce',
  csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIICfTCCAWUCAQAwODELMAkGA1UEBhMCVUsxDDAKBgNVBAoTA0dEUzEbMBkGA1UE\nAxMSQW5kcm9pZCBEZXZpY2UgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAnCmhREeYJJQ47u3z5l7DS6YTXS7PqqxV7CQcE9vLXB4XAJwXNdv4sqXx\nIyQr9z9rzrPBOaqDJVyrwS3Fx6XNQalKojXDSr0xARSmxkm/GN2QSqUHbODWyR/I\ngQ6JmU/mJcPuzV8RnQ/W1+9VbzH0XNEL5K+RXpv5+ngFVSuLBFsP0Q3pEQb4lc48\nxl8QooP700HtTP/LUp1Ba7zMBKeLvh+kqgRr9JmacEYifF2AKiu27G5gbClExpT5\ne9wjwhrMVVe9m/FImBaRMR5X08xJmx35AJZRY6flEENzKn7XEht8JCUCiX5ydYOY\nrkVuJJdbAAvL+gSJSPcMUktL+VSsVwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEB\nAJFg7sYMO6PyuwQoLgNA0AZPnpZhPATL85lLELcZmQHLJ37pnKwh5keOZjLk/jTN\nCBdK2TKxbo96KHK2ZERWsUQavLRfCr/nN5a+0iAAYzBF89eBw4e9cWAtM+6GVRwz\nSUZE6TGArz6/9UQ8sKS2n3lehD+kgXejxEC7HUEn4A1YA5jacY4LadslshLliDXI\npmrAryU6H43fwF7M/8+5O5fzFJ5/oSWfCpE9+J7ZXolvK478L0CgJqLtQQJCK/Gv\nPHQU4R1YjxPIdN8dm+/fnBJgk0S7L/5c/XrUsbypFUH9oMJogU8LiGtwxn+CYnpE\nUES0E19YKDafWsyXV+V5qeE=\n-----END CERTIFICATE REQUEST-----',
  appAttest: {
    keyId: 'test-key-id',
    attestationObject: 'test-attestation',
    clientDataJSON: 'test-client-data',
  },
};

const validAndroidRequest = {
  platform: 'android',
  nonce: 'test-nonce',
  csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIICfTCCAWUCAQAwODELMAkGA1UEBhMCVUsxDDAKBgNVBAoTA0dEUzEbMBkGA1UE\nAxMSQW5kcm9pZCBEZXZpY2UgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAnCmhREeYJJQ47u3z5l7DS6YTXS7PqqxV7CQcE9vLXB4XAJwXNdv4sqXx\nIyQr9z9rzrPBOaqDJVyrwS3Fx6XNQalKojXDSr0xARSmxkm/GN2QSqUHbODWyR/I\ngQ6JmU/mJcPuzV8RnQ/W1+9VbzH0XNEL5K+RXpv5+ngFVSuLBFsP0Q3pEQb4lc48\nxl8QooP700HtTP/LUp1Ba7zMBKeLvh+kqgRr9JmacEYifF2AKiu27G5gbClExpT5\ne9wjwhrMVVe9m/FImBaRMR5X08xJmx35AJZRY6flEENzKn7XEht8JCUCiX5ydYOY\nrkVuJJdbAAvL+gSJSPcMUktL+VSsVwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEB\nAJFg7sYMO6PyuwQoLgNA0AZPnpZhPATL85lLELcZmQHLJ37pnKwh5keOZjLk/jTN\nCBdK2TKxbo96KHK2ZERWsUQavLRfCr/nN5a+0iAAYzBF89eBw4e9cWAtM+6GVRwz\nSUZE6TGArz6/9UQ8sKS2n3lehD+kgXejxEC7HUEn4A1YA5jacY4LadslshLliDXI\npmrAryU6H43fwF7M/8+5O5fzFJ5/oSWfCpE9+J7ZXolvK478L0CgJqLtQQJCK/Gv\nPHQU4R1YjxPIdN8dm+/fnBJgk0S7L/5c/XrUsbypFUH9oMJogU8LiGtwxn+CYnpE\nUES0E19YKDafWsyXV+V5qeE=\n-----END CERTIFICATE REQUEST-----',
  keyAttestationChain: ['cert1', 'cert2'],
  playIntegrityToken: 'test-token',
};

describe('Issue Reader Cert Handler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('HTTP Method and Path Validation', () => {
    it('should return 404 for non-POST methods', async () => {
      const result = await handler(createMockEvent('GET'), mockContext);
      expect(result.statusCode).toBe(404);
      expect(JSON.parse(result.body).code).toBe('not_found');
    });

    it('should return 404 for invalid path', async () => {
      const result = await handler(createMockEvent('POST', '/invalid'), mockContext);
      expect(result.statusCode).toBe(404);
      expect(JSON.parse(result.body).code).toBe('not_found');
    });
  });

  describe('Request Validation', () => {
    it('should return 400 for missing platform', async () => {
      const request = { ...validIOSRequest };
      delete (request as Record<string, unknown>).platform;
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).code).toBe('bad_request');
      expect(JSON.parse(result.body).message).toBe('Invalid or missing platform');
    });

    it('should return 400 for invalid platform', async () => {
      const request = { ...validIOSRequest, platform: 'windows' };
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).code).toBe('bad_request');
    });

    it('should return 400 for missing nonce', async () => {
      const request = { ...validIOSRequest };
      delete (request as Record<string, unknown>).nonce;
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).message).toBe('Missing nonce');
    });

    it('should return 400 for CSR is not a valid PKCS#10 structure', async () => {
      const request = { ...validIOSRequest, csrPem: 'invalid-csr' };
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).message).toBe('CSR is not a valid PKCS#10 structure');
      expect(JSON.parse(result.body).details.field).toBe('csrPem');
    });

    it('should return 400 for iOS platform missing appAttest', async () => {
      const request = { ...validIOSRequest };
      delete (request as Record<string, unknown>).appAttest;
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).message).toBe('Missing appAttest for iOS platform');
    });

    it('should return 400 for Android platform missing keyAttestationChain', async () => {
      const request = { ...validAndroidRequest };
      delete (request as Record<string, unknown>).keyAttestationChain;
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).message).toBe(
        'Missing keyAttestationChain or playIntegrityToken for Android platform',
      );
    });

    it('should return 400 for Android platform missing playIntegrityToken', async () => {
      const request = { ...validAndroidRequest };
      delete (request as Record<string, unknown>).playIntegrityToken;
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).message).toBe(
        'Missing keyAttestationChain or playIntegrityToken for Android platform',
      );
    });
  });
  describe('Error Handling', () => {
    it('should handle JSON parsing errors', async () => {
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', 'invalid-json'), mockContext);

      expect(result.statusCode).toBe(500);
      expect(JSON.parse(result.body).code).toBe('internal_error');
    });

    it('should handle empty request body', async () => {
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', null), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).code).toBe('bad_request');
    });

    it('should handle empty JSON object', async () => {
      const result = await handler(createMockEvent('POST', '/issue-reader-cert', '{}'), mockContext);

      expect(result.statusCode).toBe(400);
      expect(JSON.parse(result.body).code).toBe('bad_request');
    });
  });

  describe('Response Headers', () => {
    it('should include correct headers in success response', async () => {
      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.headers?.['Content-Type']).toBe('application/json');
      expect(result.headers?.['X-Request-Id']).toBe('test-request-id');
    });

    it('should include correct headers in error response', async () => {
      const result = await handler(createMockEvent('GET'), mockContext);

      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
