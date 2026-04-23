import { describe, it, expect, vi, beforeEach, MockInstance } from 'vitest';
import { validateLeafCertificate } from './validate-leaf-certificate.ts';
import '../../../tests/testUtils/matchers.ts';
import { errorResult, Result } from '../common/result/result.ts';

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
        result = await validateLeafCertificate('invalid-pem');
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
  });
});
