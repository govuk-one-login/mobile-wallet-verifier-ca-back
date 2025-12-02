import { describe, it, expect } from 'vitest';
import { validateRequest, createErrorResponse } from './validation';

describe('Validation Module', () => {
  describe('validateRequest', () => {
    const validIOSRequest = {
      platform: 'ios' as const,
      nonce: 'test-nonce',
      csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKdGVzdC1jc3ItY24wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKBwkoFHX/iSdXcCPltw5dGEcOn\nDyK751bVfWGiOoR0qxBfFqW7sOhxIiKqBzSw755qoopKuA+3funHoAkd4wI2JVAp\nLLkHdAHmnFKQhH+pjTEs3dMzjDKlX8BYyCOVsSdbSb1VhlFhsSi38xggHkfwzNdw\nGcTw7XvvVcP1+jzHu4+BXgEhQjHvfmrBbHVVi2WCqy6aPwqcpweUz7egc7Esagpp\nZAxfWqaXuEGBf1a1feWb5D+cHyHjLfJ1lf/x3xI+maymkMjuUdjqzpXmiGHMbLxe\nBhVnDgsurri3o1yJoQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBALCx3ppHUaB4\n-----END CERTIFICATE REQUEST-----',
      appAttest: {
        keyId: 'test-key-id',
        attestationObject: 'test-attestation',
        clientDataJSON: 'test-client-data',
      },
    };

    const validAndroidRequest = {
      platform: 'android' as const,
      nonce: 'test-nonce',
      csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKdGVzdC1jc3ItY24wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC7VJTUt9Us8cKBwkoFHX/iSdXcCPltw5dGEcOn\nDyK751bVfWGiOoR0qxBfFqW7sOhxIiKqBzSw755qoopKuA+3funHoAkd4wI2JVAp\nLLkHdAHmnFKQhH+pjTEs3dMzjDKlX8BYyCOVsSdbSb1VhlFhsSi38xggHkfwzNdw\nGcTw7XvvVcP1+jzHu4+BXgEhQjHvfmrBbHVVi2WCqy6aPwqcpweUz7egc7Esagpp\nZAxfWqaXuEGBf1a1feWb5D+cHyHjLfJ1lf/x3xI+maymkMjuUdjqzpXmiGHMbLxe\nBhVnDgsurri3o1yJoQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBALCx3ppHUaB4\n-----END CERTIFICATE REQUEST-----',
      keyAttestationChain: ['dGVzdA==', 'dGVzdDI='], // base64 encoded test data
      playIntegrityToken: 'test-token',
    };

    it('should return null for valid iOS request', () => {
      const result = validateRequest(validIOSRequest);
      expect(result).toBeNull();
    });

    it('should return null for valid Android request', () => {
      const result = validateRequest(validAndroidRequest);
      expect(result).toBeNull();
    });

    it('should return error for missing platform', () => {
      const request = { ...validIOSRequest };
      delete (request as any).platform;
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(result?.statusCode).toBe(400);
      expect(JSON.parse(result?.body || '{}').message).toBe('Invalid or missing platform');
    });

    it('should return error for invalid platform', () => {
      const request = { ...validIOSRequest, platform: 'windows' as any };
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(result?.statusCode).toBe(400);
    });

    it('should return error for missing nonce', () => {
      const request = { ...validIOSRequest };
      delete (request as any).nonce;
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('Missing nonce');
    });

    it('should return error for invalid CSR format', () => {
      const request = { ...validIOSRequest, csrPem: 'invalid-csr' };
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('Invalid CSR');
    });

    it('should return error for iOS missing appAttest', () => {
      const request = { ...validIOSRequest };
      delete (request as any).appAttest;
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('Missing appAttest for iOS platform');
    });

    it('should return error for Android missing keyAttestationChain', () => {
      const request = { ...validAndroidRequest };
      delete (request as any).keyAttestationChain;
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('Missing keyAttestationChain or playIntegrityToken for Android platform');
    });

    it('should return error for Android missing playIntegrityToken', () => {
      const request = { ...validAndroidRequest };
      delete (request as any).playIntegrityToken;
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('Missing keyAttestationChain or playIntegrityToken for Android platform');
    });
  });

  describe('createErrorResponse', () => {
    it('should create error response with basic fields', () => {
      const result = createErrorResponse(400, 'test_error', 'Test message');
      
      expect(result.statusCode).toBe(400);
      expect(result.headers?.['Content-Type']).toBe('application/json');
      
      const body = JSON.parse(result.body);
      expect(body.code).toBe('test_error');
      expect(body.message).toBe('Test message');
    });

    it('should create error response with details', () => {
      const details = { field: 'testField', value: 'testValue' };
      const result = createErrorResponse(422, 'validation_error', 'Validation failed', details);
      
      expect(result.statusCode).toBe(422);
      
      const body = JSON.parse(result.body);
      expect(body.code).toBe('validation_error');
      expect(body.message).toBe('Validation failed');
      expect(body.details).toEqual(details);
    });

    it('should create error response without details when not provided', () => {
      const result = createErrorResponse(500, 'internal_error', 'Internal error');
      
      const body = JSON.parse(result.body);
      expect(body.details).toBeUndefined();
    });
  });
});