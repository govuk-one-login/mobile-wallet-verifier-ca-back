import { describe, it, expect } from 'vitest';
import {
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
  VALIDITY,
  KEY_USAGE,
  EXTENDED_KEY_USAGE,
  EXPECTED_CERTIFICATE_VERSION,
  EXPECTED_SIGNATURE_ALGORITHM_OID,
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

describe('VALIDITY', () => {
  describe('Type', () => {
    it('Is "DAYS"', () => {
      expect(VALIDITY.Type).toEqual('DAYS');
    });
  });

  describe('Value', () => {
    it('Is 1', () => {
      expect(VALIDITY.Value).toEqual(1);
    });
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
