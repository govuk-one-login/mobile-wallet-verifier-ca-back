import { describe, it, expect } from 'vitest';
import type {
  IssueReaderCertRequest,
  IssueReaderCertResponse,
  ErrorResponse,
  AttestationResult,
} from './types';

describe('Types Module', () => {
  describe('IssueReaderCertRequest', () => {
    it('should accept valid Android request structure', () => {
      const request: IssueReaderCertRequest = {
        csrPem:
          '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----',
        clientAttestationJwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...',
      };

      expect(request.clientAttestationJwt).toBe(
        'eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ...',
      );
    });
  });

  describe('IssueReaderCertResponse', () => {
    it('should accept valid response structure', () => {
      const response: IssueReaderCertResponse = {
        readerId: 'reader-123',
        certChain: {
          leaf: '-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----',
          intermediate:
            '-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----',
        },
        profile: 'Reader',
        notBefore: '2023-01-01T00:00:00Z',
        notAfter: '2023-12-31T23:59:59Z',
      };

      expect(response.readerId).toBe('reader-123');
      expect(response.certChain.leaf).toContain('BEGIN CERTIFICATE');
      expect(response.profile).toBe('Reader');
    });
  });

  describe('ErrorResponse', () => {
    it('should accept error response with required fields', () => {
      const error: ErrorResponse = {
        code: 'test_error',
        message: 'Test error message',
      };

      expect(error.code).toBe('test_error');
      expect(error.message).toBe('Test error message');
      expect(error.details).toBeUndefined();
    });

    it('should accept error response with optional details', () => {
      const error: ErrorResponse = {
        code: 'validation_error',
        message: 'Validation failed',
        details: {
          field: 'csrPem',
          reason: 'Invalid format',
        },
      };

      expect(error.details).toBeDefined();
      expect(error.details?.field).toBe('csrPem');
    });
  });

  describe('AttestationResult', () => {
    it('should accept valid attestation result', () => {
      const validResult: AttestationResult = {
        valid: true,
      };

      expect(validResult.valid).toBe(true);
      expect(validResult.code).toBeUndefined();
      expect(validResult.message).toBeUndefined();
    });

    it('should accept invalid attestation result with error details', () => {
      const invalidResult: AttestationResult = {
        valid: false,
        code: 'invalid_signature',
        message: 'Signature verification failed',
      };

      expect(invalidResult.valid).toBe(false);
      expect(invalidResult.code).toBe('invalid_signature');
      expect(invalidResult.message).toBe('Signature verification failed');
    });
  });
});
