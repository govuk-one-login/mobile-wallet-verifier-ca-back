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

import { handler } from './handler';

// Remove unused dynamoModule import

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

const validRequest = {
  csrPem:
    '-----BEGIN CERTIFICATE REQUEST-----\nMIHyMIGaAgEAMDgxCzAJBgNVBAYTAlVLMQwwCgYDVQQKEwNHRFMxGzAZBgNVBAMT\nEkFuZHJvaWQgRGV2aWNlIEtleTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDlt\n4vSyJY/RnL8bC5bHhhfxDZ3m69UBx/IADlbZhZ4nzImHuzVJsck2LsPefb91g6hc\nhq81PZei3c7qN2rfJIqgADAKBggqhkjOPQQDAgNHADBEAiBB/OcSic76VdMJuaZZ\nDb7APgiSkx8KMGbrqo4PgDy25AIgJH+tVfzC4B8R0ZNCuTpEJlJx9DVW0I1X24dI\nKnLJRN8=\n-----END CERTIFICATE REQUEST-----',
  clientAttestationJwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...',
};

describe('Issue Reader Cert Handler', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    //const { verifyFirebaseAttestation } = await import('./firebase-attestation.ts');
    //vi.mocked(verifyFirebaseAttestation).mockResolvedValue({ valid: true });
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

  // describe('Request Validation', () => {
  //   it('should return 400 for invalid CSR', async () => {
  //     const request = { ...validRequest, csrPem: 'invalid-csr' };
  //     const result = await handler(createMockEvent('POST', '/issue-reader-cert', JSON.stringify(request)), mockContext);
  //
  //     expect(result.statusCode).toBe(400);
  //     expect(JSON.parse(result.body).message).toBe('CSR is not a valid PKCS#10 structure');
  //     expect(JSON.parse(result.body).details.field).toBe('csrPem');
  //   });
  // });
  // describe('Error Handling', () => {
  //   it('should handle JSON parsing errors', async () => {
  //     const result = await handler(createMockEvent('POST', '/issue-reader-cert', 'invalid-json'), mockContext);
  //
  //     expect(result.statusCode).toBe(500);
  //     expect(JSON.parse(result.body).code).toBe('internal_error');
  //   });
  //
  //   it('should handle empty request body', async () => {
  //     const result = await handler(createMockEvent('POST', '/issue-reader-cert', null), mockContext);
  //
  //     expect(result.statusCode).toBe(400);
  //     expect(JSON.parse(result.body).code).toBe('bad_request');
  //   });
  //
  //   it('should handle empty JSON object', async () => {
  //     const result = await handler(createMockEvent('POST', '/issue-reader-cert', '{}'), mockContext);
  //
  //     expect(result.statusCode).toBe(400);
  //     expect(JSON.parse(result.body).code).toBe('bad_request');
  //   });
  // });

  describe('Response Headers', () => {
    it('should include correct headers in success response', async () => {
      const result = await handler(
        createMockEvent('POST', '/issue-reader-cert', JSON.stringify(validRequest)),
        mockContext,
      );

      expect(result.headers?.['Content-Type']).toBe('application/json');
    });

    it('should include correct headers in error response', async () => {
      const result = await handler(createMockEvent('GET'), mockContext);

      expect(result.headers?.['Content-Type']).toBe('application/json');
    });
  });
});
