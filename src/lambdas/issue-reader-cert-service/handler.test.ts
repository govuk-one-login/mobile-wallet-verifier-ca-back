import type { APIGatewayProxyEvent, Context } from 'aws-lambda';
import { vi, describe, it, beforeEach, expect } from 'vitest';

vi.mock('node:crypto', () => ({
  randomUUID: vi.fn(() => 'test-uuid-123'),
}));

vi.mock('@aws-lambda-powertools/logger', () => ({
  Logger: class {
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
  csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----',
  appAttest: {
    keyId: 'test-key-id',
    attestationObject: 'test-attestation',
    clientDataJSON: 'test-client-data',
  },
};

const validAndroidRequest = {
  platform: 'android',
  nonce: 'test-nonce',
  csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----',
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

    it('should return 400 for invalid CSR', async () => {
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
