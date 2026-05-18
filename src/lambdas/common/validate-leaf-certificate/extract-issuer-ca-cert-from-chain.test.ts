import { describe, it, expect, vi, beforeEach, MockInstance } from 'vitest';
import { extractIssuerCaCertFromChain } from './extract-issuer-ca-cert-from-chain.ts';
import { successResult, errorResult } from '../result/result.ts';
import '../../../../tests/testUtils/matchers.ts';

let consoleErrorSpy: MockInstance;

describe('extractIssuerCaCertFromChain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    consoleErrorSpy = vi.spyOn(console, 'error');
  });

  describe('Given an empty certificate chain', () => {
    it('logs error and returns error result', () => {
      const result = extractIssuerCaCertFromChain('');

      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode:
          'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
        errorMessage: 'Certificate chain must contain at least the issuer CA',
      });
      expect(result).toEqual(
        errorResult('Certificate chain must contain at least the issuer CA'),
      );
    });
  });

  describe('Given a certificate chain with no valid certificates', () => {
    it('logs error and returns error result', () => {
      const invalidChain = 'invalid certificate data';
      const result = extractIssuerCaCertFromChain(invalidChain);

      expect(consoleErrorSpy).toHaveBeenCalledWithLogFields({
        messageCode:
          'MOBILE_CA_ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE',
        errorMessage: 'Certificate chain must contain at least the issuer CA',
      });
      expect(result).toEqual(
        errorResult('Certificate chain must contain at least the issuer CA'),
      );
    });
  });

  describe('Given a certificate chain with one certificate', () => {
    it('returns success result with the first certificate', () => {
      const singleCertChain =
        '-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA\n-----END CERTIFICATE-----';

      const result = extractIssuerCaCertFromChain(singleCertChain);

      expect(result).toEqual(
        successResult(
          '-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA\n-----END CERTIFICATE-----',
        ),
      );
    });
  });

  describe('Given a certificate chain with multiple certificates', () => {
    it('returns success result with the first certificate (intermediate CA)', () => {
      const multiCertChain =
        '-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA\n-----END CERTIFICATE-----' +
        '-----BEGIN CERTIFICATE-----\nROOT_CA\n-----END CERTIFICATE-----';

      const result = extractIssuerCaCertFromChain(multiCertChain);

      expect(result).toEqual(
        successResult(
          '-----BEGIN CERTIFICATE-----\nINTERMEDIATE_CA\n-----END CERTIFICATE-----',
        ),
      );
    });
  });
});
