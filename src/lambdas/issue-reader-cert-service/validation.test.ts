import { describe, it, expect, vi } from 'vitest';
import { validateRequest, createErrorResponse, validateReaderCertSubject, validateCSRContent } from './validation';

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
  "nonce": "98f5534e-d50c-48f1-a215-e74dcfa1008e",
  "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\nMIICfTCCAWUCAQAwODELMAkGA1UEBhMCVUsxDDAKBgNVBAoTA0dEUzEbMBkGA1UE\nAxMSQW5kcm9pZCBEZXZpY2UgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAnCmhREeYJJQ47u3z5l7DS6YTXS7PqqxV7CQcE9vLXB4XAJwXNdv4sqXx\nIyQr9z9rzrPBOaqDJVyrwS3Fx6XNQalKojXDSr0xARSmxkm/GN2QSqUHbODWyR/I\ngQ6JmU/mJcPuzV8RnQ/W1+9VbzH0XNEL5K+RXpv5+ngFVSuLBFsP0Q3pEQb4lc48\nxl8QooP700HtTP/LUp1Ba7zMBKeLvh+kqgRr9JmacEYifF2AKiu27G5gbClExpT5\ne9wjwhrMVVe9m/FImBaRMR5X08xJmx35AJZRY6flEENzKn7XEht8JCUCiX5ydYOY\nrkVuJJdbAAvL+gSJSPcMUktL+VSsVwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEB\nAJFg7sYMO6PyuwQoLgNA0AZPnpZhPATL85lLELcZmQHLJ37pnKwh5keOZjLk/jTN\nCBdK2TKxbo96KHK2ZERWsUQavLRfCr/nN5a+0iAAYzBF89eBw4e9cWAtM+6GVRwz\nSUZE6TGArz6/9UQ8sKS2n3lehD+kgXejxEC7HUEn4A1YA5jacY4LadslshLliDXI\npmrAryU6H43fwF7M/8+5O5fzFJ5/oSWfCpE9+J7ZXolvK478L0CgJqLtQQJCK/Gv\nPHQU4R1YjxPIdN8dm+/fnBJgk0S7L/5c/XrUsbypFUH9oMJogU8LiGtwxn+CYnpE\nUES0E19YKDafWsyXV+V5qeE=\n-----END CERTIFICATE REQUEST-----",
  "keyAttestationChain": [
    "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"
  ],
  "playIntegrityToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFuZHJvaWQtcGxheS1pbnRlZ3JpdHkta2V5cy02In0.eyJyZXF1ZXN0RGV0YWlscyI6eyJyZXF1ZXN0UGFja2FnZU5hbWUiOiJvcmcubXVsdGlwYXouaWRlbnRpdHlyZWFkZXIiLCJ0aW1lc3RhbXBNaWxsaXMiOiIxNzY0NzExMDY0Mjc3Iiwibm9uY2UiOiI5OGY1NTM0ZS1kNTBjLTQ4ZjEtYTIxNS1lNzRkY2ZhMTAwOGUifSwiYXBwSW50ZWdyaXR5Ijp7ImFwcFJlY29nbml0aW9uVmVyZGljdCI6IlBMQVlfUkVDT0dOSVpFRCIsInBhY2thZ2VOYW1lIjoib3JnLm11bHRpcGF6LmlkZW50aXR5cmVhZGVyIiwiY2VydGlmaWNhdGVTaGEyNTZEaWdlc3QiOlsiYWJjMTIzIl0sInZlcnNpb25Db2RlIjoiMSJ9LCJkZXZpY2VJbnRlZ3JpdHkiOnsiZGV2aWNlUmVjb2duaXRpb25WZXJkaWN0IjpbIk1FRVRTX0RFVklDRV9JTlRFR1JJVFkiXX0sImFjY291bnREZXRhaWxzIjp7ImFwcExpY2Vuc2luZ1ZlcmRpY3QiOiJMSUNFTlNFRCJ9fQ.SBuiFXm22eQ7UPa_3FZHQfdSNYHqnjskFEpde-qEuKC5jXPx43VqpfV0n2Ymf-ALKt6gBZKJllY9DcpBfqYGC3l8CObHuOYNPADbJUnpMED_YqEVtKbvEnJCRMKHuuU9bFBNgRiXbinMMv4pjcyRHaj90SWDyLkD2dR70adbbRu3HVh6XP7QCDKl-5WSfXfk9A1jHIn24PWYz8Kf1lTF72dg3b3rNtENPzb72H_fa35h3AVbAYa7swU7-R9Cd6Ql6W1ZBzf9ggvluLbFfKHKPfjMpaIPp4tTf_VYsywablquFGb5wyf4p7vLWIXtO4h5QOdQRXZyP-TmGwfuB7JulA",
  "platform": "android" as const
};

describe('Validation Module', () => {
  describe('validateRequest', () => {
    // it('should return null for valid iOS request', () => {
    //   const result = validateRequest(validIOSRequest);
    //   expect(result).toBeNull();
    // });

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

    it('should return error for CSR is not a valid PKCS#10 structure format', () => {
      const request = { ...validIOSRequest, csrPem: 'invalid-csr' };
      const result = validateRequest(request);
      
      expect(result).not.toBeNull();
      expect(JSON.parse(result?.body || '{}').message).toBe('CSR is not a valid PKCS#10 structure');
    });

    // it('should return error for iOS missing appAttest', () => {
    //   const request = { ...validIOSRequest };
    //   delete (request as any).appAttest;
    //   const result = validateRequest(request);
      
    //   expect(result).not.toBeNull();
    //   expect(JSON.parse(result?.body || '{}').message).toBe('Missing appAttest for iOS platform');
    // });

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

  describe('validateReaderCertSubject', () => {
    it('should return valid for correct subject DN', () => {
      const result = validateReaderCertSubject('CN=Test Reader, O=Test Org, C=GB');
      
      expect(result.valid).toBe(true);
    });

    it('should return invalid for missing CN', () => {
      const result = validateReaderCertSubject('O=Test Org, C=GB');
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_subject_dn');
      expect(result.message).toContain('Common Name');
    });

    it('should return invalid for missing O', () => {
      const result = validateReaderCertSubject('CN=Test Reader, C=GB');
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_subject_dn');
      expect(result.message).toContain('Organization');
    });

    it('should return invalid for missing C', () => {
      const result = validateReaderCertSubject('CN=Test Reader, O=Test Org');
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_subject_dn');
      expect(result.message).toContain('Country');
    });

    it('should return invalid for invalid country code', () => {
      const result = validateReaderCertSubject('CN=Test Reader, O=Test Org, C=XX');
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_subject_dn');
      expect(result.message).toContain('ISO 3166-1');
    });

    it('should accept valid ISO 3166-1 country codes', () => {
      const validCodes = ['US', 'GB', 'FR', 'DE', 'JP'];
      
      validCodes.forEach(code => {
        const result = validateReaderCertSubject(`CN=Test, O=Org, C=${code}`);
        expect(result.valid).toBe(true);
      });
    });
  });

  describe('validateCSRContent', () => {
    it('should return invalid for CSR with invalid subject DN', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const mockPublicKey = {
        getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      };
      
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('O=Test Org');
      
      const result = await validateCSRContent(csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_subject_dn');
    });

    it('should return invalid for non-ECDSA algorithm', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const mockPublicKey = {
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      };
      
      //const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('CN=Test, O=Org, C=GB');
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'publicKey', 'get').mockReturnValue({
        algorithm: { name: 'RSA' },
        getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      } as any);
      
      const result = await validateCSRContent(validAndroidRequest.csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_key_algorithm');
    });

    it('should return invalid for unsupported ECDSA curve', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const mockPublicKey = {
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      };
      
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('CN=Test, O=Org, C=GB');
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'publicKey', 'get').mockReturnValue({
        algorithm: { name: 'ECDSA', namedCurve: 'P-192' },
        getThumbprint: vi.fn().mockResolvedValue(new ArrayBuffer(32))
      } as any);
      
      const result = await validateCSRContent(csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_key_curve');
    });

    it('should return invalid for public key mismatch', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const mockPublicKey = {
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(Buffer.from('different'))
      };
      
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('CN=Test, O=Org, C=GB');
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'publicKey', 'get').mockReturnValue({
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(Buffer.from('original'))
      } as any);
      
      const result = await validateCSRContent(csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('public_key_mismatch');
    });

    it('should return valid for matching CSR and attested key', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const thumbprint = Buffer.from('matching-thumbprint');
      const mockPublicKey = {
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(thumbprint)
      };
      
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('CN=Test, O=Org, C=GB');
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'publicKey', 'get').mockReturnValue({
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockResolvedValue(thumbprint)
      } as any);
      
      const result = await validateCSRContent(csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(true);
    });

    it('should handle errors gracefully', async () => {
      const { Pkcs10CertificateRequest } = await import('@peculiar/x509');
      
      const mockPublicKey = {
        getThumbprint: vi.fn().mockRejectedValue(new Error('Thumbprint error'))
      };
      
      const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----';
      
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'subject', 'get').mockReturnValue('CN=Test, O=Org, C=GB');
      vi.spyOn(Pkcs10CertificateRequest.prototype, 'publicKey', 'get').mockReturnValue({
        algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
        getThumbprint: vi.fn().mockRejectedValue(new Error('Error'))
      } as any);
      
      const result = await validateCSRContent(csrPem, mockPublicKey as any);
      
      expect(result.valid).toBe(false);
      expect(result.code).toBe('invalid_csr');
    });
  });
