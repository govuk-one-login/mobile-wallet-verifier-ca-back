import { describe, it, expect } from 'vitest';
import {
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
  VALIDITY_DURATION_MS,
  KEY_USAGE,
  EXTENDED_KEY_USAGE,
  EXPECTED_CERTIFICATE_VERSION,
  EXPECTED_SIGNATURE_ALGORITHM_OID,
  EXPECTED_ISSUER_AND_SUBJECT_NAME,
  EXPECTED_ISSUER_CN,
} from './certificate-service-constants';

describe('SIGNING_ALGORITHM', () => {
  it('Is "SHA384WITHECDSA"', () => {
    expect(SIGNING_ALGORITHM).toEqual('SHA384WITHECDSA');
  });
});

describe('TEMPLATE_ARN', () => {
  it('Is the BlankEndEntityCertificate_APIPassthrough/V1 template', () => {
    expect(TEMPLATE_ARN).toEqual(
      'arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1',
    );
  });
});

describe('VALIDITY_DURATION_MS', () => {
  it('Is 86400000 (24 hours in milliseconds)', () => {
    expect(VALIDITY_DURATION_MS).toEqual(24 * 60 * 60 * 1000);
  });
});

describe('KEY_USAGE', () => {
  describe('DigitalSignature', () => {
    it('Is true', () => {
      expect(KEY_USAGE.DigitalSignature).toEqual(true);
    });
  });
});

describe('EXTENDED_KEY_USAGE', () => {
  it('Contains one entry', () => {
    expect(EXTENDED_KEY_USAGE).toHaveLength(1);
  });

  describe('mDL Reader Auth OID', () => {
    it('Is "1.0.18013.5.1.6"', () => {
      expect(EXTENDED_KEY_USAGE[0].ExtendedKeyUsageObjectIdentifier).toEqual(
        '1.0.18013.5.1.6',
      );
    });
  });
});

describe('EXPECTED_CERTIFICATE_VERSION', () => {
  it('Is 2 (X.509 v3)', () => {
    expect(EXPECTED_CERTIFICATE_VERSION).toEqual(2);
  });
});

describe('EXPECTED_SIGNATURE_ALGORITHM_OID', () => {
  it('Is "1.2.840.10045.4.3.3" (ECDSA with SHA-384 on P-384)', () => {
    expect(EXPECTED_SIGNATURE_ALGORITHM_OID).toEqual('1.2.840.10045.4.3.3');
  });
});

describe('EXPECTED_ISSUER_AND_SUBJECT_NAME', () => {
  it('Has C as "GB"', () => {
    expect(EXPECTED_ISSUER_AND_SUBJECT_NAME.C).toEqual('GB');
  });

  it('Has O as "Government Digital Service"', () => {
    expect(EXPECTED_ISSUER_AND_SUBJECT_NAME.O).toEqual(
      'Government Digital Service',
    );
  });

  it('Has ST as "London"', () => {
    expect(EXPECTED_ISSUER_AND_SUBJECT_NAME.ST).toEqual('London');
  });

  it('Has CN as "GOVUK Mobile Wallet GovVerifier CA"', () => {
    expect(EXPECTED_ISSUER_CN).toEqual('GOVUK Mobile Wallet GovVerifier CA');
  });

  it('Has L as "London"', () => {
    expect(EXPECTED_ISSUER_AND_SUBJECT_NAME.L).toEqual('London');
  });
});
