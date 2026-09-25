import { describe, it, expect } from 'vitest';
import { AsnConvert } from '@peculiar/asn1-schema';
import { SubjectInfoAccessSyntax } from '@peculiar/asn1-x509';
import {
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
  KEY_USAGE,
  EXTENDED_KEY_USAGE,
  EXTENDED_KEY_USAGE_DER_BASE64,
  EXPECTED_CERTIFICATE_VERSION,
  EXPECTED_SIGNATURE_ALGORITHM_OID,
  EXPECTED_ISSUER_AND_SUBJECT_NAME,
  EXPECTED_ISSUER_CN,
  NINETY_DAYS_IN_MS,
  PCA_NOT_BEFORE_BACKDATE_MS,
  EXPECTED_VALIDITY_SPAN_MS,
  VALIDITY_TOLERANCE_MS,
  VALIDITY_SPAN_MIN_MS,
  VALIDITY_SPAN_MAX_MS,
  PRIVACY_POLICY_URL,
  SUBJECT_INFO_ACCESS_OID,
  PRIVACY_POLICY_ACCESS_METHOD_OID,
  PRIVACY_POLICY_SIA_DER_BASE64,
  MIN_BYTE_LENGTH,
  MAX_BYTE_LENGTH,
  CURVE_P384_OID_DER,
  ALGORITHM_OID,
  EXPECTED_SPKI_LENGTH,
} from './certificate-service-constants';

describe('SIGNING_ALGORITHM', () => {
  it('Is "SHA256WITHECDSA"', () => {
    expect(SIGNING_ALGORITHM).toEqual('SHA256WITHECDSA');
  });
});

describe('TEMPLATE_ARN', () => {
  it('Is the BlankEndEntityCertificate_APIPassthrough/V1 template', () => {
    expect(TEMPLATE_ARN).toEqual(
      'arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1',
    );
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

describe('EXTENDED_KEY_USAGE_DER_BASE64', () => {
  it('Is the base64 DER encoding of the mDL Reader Auth EKU OID (1.0.18013.5.1.6)', () => {
    expect(EXTENDED_KEY_USAGE_DER_BASE64).toEqual('MAkGByiBjF0FAQY=');
  });
});

describe('EXPECTED_CERTIFICATE_VERSION', () => {
  it('Is 2 (X.509 v3)', () => {
    expect(EXPECTED_CERTIFICATE_VERSION).toEqual(2);
  });
});

describe('MIN_BYTE_LENGTH', () => {
  it('Is 9', () => {
    expect(MIN_BYTE_LENGTH).toEqual(9);
  });
});

describe('MAX_BYTE_LENGTH', () => {
  it('Is 20', () => {
    expect(MAX_BYTE_LENGTH).toEqual(20);
  });
});

describe('EXPECTED_SIGNATURE_ALGORITHM_OID', () => {
  it('Is "1.2.840.10045.4.3.2" (ECDSA with SHA-256)', () => {
    expect(EXPECTED_SIGNATURE_ALGORITHM_OID).toEqual('1.2.840.10045.4.3.2');
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

  it('Has CN as "GOVUK Mobile Wallet GovVerifier CA"', () => {
    expect(EXPECTED_ISSUER_CN).toEqual('GOVUK Mobile Wallet GovVerifier CA');
  });
});

describe('NINETY_DAYS_IN_MS', () => {
  it('Is 7776000000 milliseconds', () => {
    expect(NINETY_DAYS_IN_MS).toEqual(90 * 24 * 60 * 60 * 1000);
    expect(NINETY_DAYS_IN_MS).toEqual(7776000000);
  });
});

describe('PCA_NOT_BEFORE_BACKDATE_MS', () => {
  it('Is 60 minutes in milliseconds (PCA default notBefore backdate)', () => {
    expect(PCA_NOT_BEFORE_BACKDATE_MS).toEqual(60 * 60 * 1000);
  });
});

describe('EXPECTED_VALIDITY_SPAN_MS', () => {
  it('Is 90 days plus the PCA notBefore backdate (90 days + 1 hour)', () => {
    expect(EXPECTED_VALIDITY_SPAN_MS).toEqual(
      NINETY_DAYS_IN_MS + PCA_NOT_BEFORE_BACKDATE_MS,
    );
    expect(EXPECTED_VALIDITY_SPAN_MS).toEqual(7779600000);
  });
});

describe('VALIDITY_TOLERANCE_MS', () => {
  it('Is 5 minutes in milliseconds', () => {
    expect(VALIDITY_TOLERANCE_MS).toEqual(5 * 60 * 1000);
  });
});

describe('VALIDITY_SPAN_MIN_MS', () => {
  it('Is the expected span minus the tolerance', () => {
    expect(VALIDITY_SPAN_MIN_MS).toEqual(
      EXPECTED_VALIDITY_SPAN_MS - VALIDITY_TOLERANCE_MS,
    );
  });
});

describe('VALIDITY_SPAN_MAX_MS', () => {
  it('Is the expected span plus the tolerance', () => {
    expect(VALIDITY_SPAN_MAX_MS).toEqual(
      EXPECTED_VALIDITY_SPAN_MS + VALIDITY_TOLERANCE_MS,
    );
  });
});

describe('PRIVACY_POLICY_URL', () => {
  it('Is an https URL', () => {
    expect(PRIVACY_POLICY_URL.startsWith('https://')).toBe(true);
  });

  it('Is well-formed (https, host, no userinfo, ASCII, <=2048 chars)', () => {
    const url = new URL(PRIVACY_POLICY_URL);
    expect(url.protocol).toBe('https:');
    expect(url.hostname.length).toBeGreaterThan(0);
    expect(url.username).toBe('');
    expect(url.password).toBe('');
    // eslint-disable-next-line no-control-regex
    expect(/^[\x00-\x7F]*$/.test(PRIVACY_POLICY_URL)).toBe(true); // Assert ASCII only
    expect(PRIVACY_POLICY_URL).not.toContain(' ');
    expect(PRIVACY_POLICY_URL.length).toBeLessThanOrEqual(2048);
  });
});

describe('SUBJECT_INFO_ACCESS_OID', () => {
  it('Is "1.3.6.1.5.5.7.1.11" (id-pe-subjectInfoAccess)', () => {
    expect(SUBJECT_INFO_ACCESS_OID).toEqual('1.3.6.1.5.5.7.1.11');
  });
});

describe('PRIVACY_POLICY_ACCESS_METHOD_OID', () => {
  it('Is the GDS-owned OID "1.3.6.1.4.1.66559.1.1"', () => {
    expect(PRIVACY_POLICY_ACCESS_METHOD_OID).toEqual('1.3.6.1.4.1.66559.1.1');
  });
});

describe('PRIVACY_POLICY_SIA_DER_BASE64', () => {
  it('Decodes to a SIA entry carrying the access-method OID and the privacy policy URL', () => {
    const sia = AsnConvert.parse(
      Buffer.from(PRIVACY_POLICY_SIA_DER_BASE64, 'base64'),
      SubjectInfoAccessSyntax,
    );
    expect(sia).toHaveLength(1);
    expect(sia[0].accessMethod).toEqual(PRIVACY_POLICY_ACCESS_METHOD_OID);
    expect(sia[0].accessLocation.uniformResourceIdentifier).toEqual(
      PRIVACY_POLICY_URL,
    );
  });
});

describe('P384_OID_DER', () => {
  it('Is "06052b81040022" (DER encoding of OID 1.3.132.0.34)', () => {
    expect(CURVE_P384_OID_DER).toEqual('06052b81040022');
  });
});

describe('ALGORITHM_OID', () => {
  it('Is "1.2.840.10045.2.1" (EC public key)', () => {
    expect(ALGORITHM_OID).toEqual('1.2.840.10045.2.1');
  });
});

describe('EXPECTED_SPKI_LENGTH', () => {
  it('Is 120 bytes', () => {
    expect(EXPECTED_SPKI_LENGTH).toEqual(120);
  });
});
