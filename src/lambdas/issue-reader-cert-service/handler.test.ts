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

vi.mock('@aws-sdk/client-dynamodb', () => {
  const mockSend = vi.fn();
  return {
    DynamoDBClient: class {
      send = mockSend;
    },
    DeleteItemCommand: class {
      constructor(params: Record<string, unknown>) {
        Object.assign(this, params);
      }
      // Add method to satisfy no-extraneous-class rule
      toJSON() {
        return this;
      }
    },
    __mockSend: mockSend, // Export for test access
  };
});

vi.mock('./android-attestation', () => ({
  verifyAndroidAttestation: vi.fn(),
}));

vi.mock('./ios-attestation', () => ({
  verifyIOSAttestation: vi.fn(),
}));

import * as dynamoModule from '@aws-sdk/client-dynamodb';
import { handler } from './handler';

const mockSend = (dynamoModule as unknown as { __mockSend: ReturnType<typeof vi.fn> }).__mockSend;

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
  csrPem:
    '-----BEGIN CERTIFICATE REQUEST-----\nMIHyMIGaAgEAMDgxCzAJBgNVBAYTAlVLMQwwCgYDVQQKEwNHRFMxGzAZBgNVBAMT\nEkFuZHJvaWQgRGV2aWNlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDlt\n4vSyJY/RnL8bC5bHhhfxDZ3m69UBx/IADlbZhZ4nzImHuzVJsck2LsPefb91g6hc\nhq81PZei3c7qN2rfJIqgADAKBggqhkjOPQQDAgNHADBEAiBB/OcSic76VdMJuaZZ\nDb7APgiSkx8KMGbrqo4PgDy25AIgJH+tVfzC4B8R0ZNCuTpEJlJx9DVW0I1X24dI\nKnLJRN8=\n-----END CERTIFICATE REQUEST-----',
  appAttest: {
    keyId: 'test-key-id',
    attestationObject: 'test-attestation',
    clientDataJSON: 'test-client-data',
  },
};

const validAndroidRequest = {
  platform: 'android',
  nonce: 'test-nonce',
  csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIHyMIGaAgEAMDgxCzAJBgNVBAYTAlVLMQwwCgYDVQQKEwNHRFMxGzAZBgNVBAMT\nEkFuZHJvaWQgRGV2aWNlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDlt\n4vSyJY/RnL8bC5bHhhfxDZ3m69UBx/IADlbZhZ4nzImHuzVJsck2LsPefb91g6hc\nhq81PZei3c7qN2rfJIqgADAKBggqhkjOPQQDAgNHADBEAiBB/OcSic76VdMJuaZZ\nDb7APgiSkx8KMGbrqo4PgDy25AIgJH+tVfzC4B8R0ZNCuTpEJlJx9DVW0I1X24dI\nKnLJRN8=\n-----END CERTIFICATE REQUEST-----',
  keyAttestationChain: ['cert1', 'cert2'],
  playIntegrityToken: 'test-token',
};

describe('Issue Reader Cert Handler', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    const { verifyIOSAttestation } = await import('./ios-attestation');
    const { verifyAndroidAttestation } = await import('./android-attestation');
    vi.mocked(verifyIOSAttestation).mockResolvedValue({ valid: true });
    vi.mocked(verifyAndroidAttestation).mockResolvedValue({ valid: true });
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
      process.env.NONCE_TABLE_NAME = 'test-nonce-table';
      mockSend.mockResolvedValue({ Attributes: { nonceValue: { S: 'test-nonce' } } });

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

  describe('Nonce Verification', () => {
    beforeEach(() => {
      process.env.NONCE_TABLE_NAME = 'test-nonce-table';
    });

    it('should return 409 when nonce verification fails', async () => {
      mockSend.mockResolvedValue({ Attributes: undefined });

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.statusCode).toBe(409);
      expect(JSON.parse(result.body).code).toBe('nonce_replayed');
    });

    it('should proceed when nonce verification succeeds', async () => {
      mockSend.mockResolvedValue({ Attributes: { nonceValue: { S: 'test-nonce' } } });

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.statusCode).toBe(200);
    });

    it('should include timeToLive condition in delete command', async () => {
      mockSend.mockResolvedValue({ Attributes: { nonceValue: { S: 'test-nonce' } } });

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      console.log('Mock calls:', mockSend.mock.calls.length);
      console.log('Result status:', result.statusCode);
      console.log('Environment:', process.env.NONCE_TABLE_NAME);
      console.log('First call args:', JSON.stringify(mockSend.mock.calls[0], null, 2));

      expect(mockSend).toHaveBeenCalledWith(
        expect.objectContaining({
          ConditionExpression: '#timeToLive > :now',
          ExpressionAttributeNames: { '#timeToLive': 'timeToLive' },
          ExpressionAttributeValues: {
            ':now': { N: expect.any(String) },
          },
        }),
      );
    });

    it('should return 409 when timeToLive condition fails', async () => {
      mockSend.mockRejectedValue(new Error('ConditionalCheckFailedException'));

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.statusCode).toBe(409);
      expect(JSON.parse(result.body).code).toBe('nonce_replayed');
    });

    it('should return 409 for nonce already consumed (line 39)', async () => {
      process.env.NONCE_TABLE_NAME = 'test-nonce-table';
      mockSend.mockResolvedValue({ Attributes: undefined }); // No attributes means nonce not found/consumed

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.statusCode).toBe(409);
      expect(JSON.parse(result.body).code).toBe('nonce_replayed');
      expect(JSON.parse(result.body).message).toBe('Nonce has already been consumed');
    });

    it('should handle missing NONCE_TABLE_NAME environment variable (lines 68-69)', async () => {
      delete process.env.NONCE_TABLE_NAME;

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validIOSRequest)),
        mockContext,
      );

      expect(result.statusCode).toBe(409);
      expect(JSON.parse(result.body).code).toBe('nonce_replayed');
      expect(JSON.parse(result.body).message).toBe('Nonce has already been consumed');
    });

    it('should call verifyAndroidAttestation for Android platform (line 102)', async () => {
      // Clear the Android attestation mock so it returns undefined (fails)
      const { verifyAndroidAttestation } = await import('./android-attestation');
      vi.mocked(verifyAndroidAttestation).mockResolvedValue({ valid: false, code: 'test_failure', message: 'Test failure' });
      
      process.env.NONCE_TABLE_NAME = 'test-nonce-table';
      mockSend.mockResolvedValue({ Attributes: { nonceValue: { S: 'test-nonce' } } });

      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validAndroidRequest)),
        mockContext,
      );

      // Android attestation fails, proving line 102 (return verifyAndroidAttestation(request)) was executed
      expect(result.statusCode).toBe(403);
      expect(JSON.parse(result.body).code).toBe('test_failure');
    });
  });
});
