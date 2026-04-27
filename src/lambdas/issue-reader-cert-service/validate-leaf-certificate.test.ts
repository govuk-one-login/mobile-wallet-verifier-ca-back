import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
  MockInstance,
} from 'vitest';
import { validateLeafCertificate } from './validate-leaf-certificate.ts';
import '../../../tests/testUtils/matchers.ts';
import { emptySuccess, errorResult, Result } from '../common/result/result.ts';
import { createValidCertPem } from '../../../tests/testUtils/create-valid-cert-pem.ts';
import { AsnConvert } from '@peculiar/asn1-schema';

describe('validateLeafCertificate', () => {
  let consoleErrorSpy: MockInstance;
  let result: Result<void, string>;

  beforeEach(async () => {
    consoleErrorSpy = vi.spyOn(console, 'error');
    vi.clearAllMocks();
  });

  describe('Given Leaf certificate verification fails', () => {
    describe('Given certificate is not valid X.509 format', () => {
      beforeEach(async () => {
        result = await validateLeafCertificate(
          await createValidCertPem({ invalidX509: true }),
        );
      });
      it('Logs error', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode:
            'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
          errorMessage: 'Certificate not valid X.509 format',
        });
      });

      it('Returns an error result', () => {
        expect(result).toEqual(
          errorResult('Certificate not valid X.509 format'),
        );
      });
    });

    describe('Given certificate version is not v3', () => {
      beforeEach(async () => {
        const validCert = await createValidCertPem();
        // Mock AsnConvert.parse to return a certificate with wrong version
        vi.spyOn(AsnConvert, 'parse').mockReturnValue({
          tbsCertificate: {
            version: 0, // v1 instead of v3 (2)
          },
        } as any);
        result = await validateLeafCertificate(validCert);
      });

      afterEach(() => {
        vi.restoreAllMocks();
      });

      it('Logs error', () => {
        expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
          messageCode:
            'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
          errorMessage: 'Certificate version must be v3',
        });
      });

      it('Returns an error result', () => {
        expect(result).toEqual(errorResult('Certificate version must be v3'));
      });
    });
  });

  describe('Given leaf certificate is valid', () => {
    beforeEach(async () => {
      const validCert = await createValidCertPem();
      // Mock AsnConvert.parse to return a valid certificate structure
      vi.spyOn(AsnConvert, 'parse').mockReturnValue({
        tbsCertificate: {
          version: 2, // Valid v3 certificate
        },
      } as any);
      result = await validateLeafCertificate(validCert);
    });
    it('Returns empty success', () => {
      expect(result).toEqual(emptySuccess());
    });
  });
});
