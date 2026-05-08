// X.509 extensions are identified by OIDs (Object Identifiers)

export const SIGNING_ALGORITHM = 'SHA384WITHECDSA';

export const TEMPLATE_ARN =
  'arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1';

export const KEY_USAGE = {
  DigitalSignature: true,
} as const;

export const EXTENDED_KEY_USAGE = [
  {
    // mDL Reader Auth
    ExtendedKeyUsageObjectIdentifier: '1.0.18013.5.1.6',
  },
] as const;

// Certificate validation constants
export const EXPECTED_CERTIFICATE_VERSION = 2; // X.509 version field encoding: v1=0, v2=1, v3=2 (ASN.1 INTEGER values)
export const MIN_BYTE_LENGTH = 9; // Serial number minimum byte length
export const MAX_BYTE_LENGTH = 20; // Serial number maximum byte length
export const EXPECTED_SIGNATURE_ALGORITHM_OID = '1.2.840.10045.4.3.3'; // ECDSA with SHA-384 on P-384
export const EXPECTED_ISSUER_AND_SUBJECT_NAME = {
  C: 'GB',
  O: 'Government Digital Service',
  ST: 'London',
  L: 'London',
} as const;
export const EXPECTED_ISSUER_CN = 'GOVUK Mobile Wallet GovVerifier CA';
export const TWENTY_FOUR_HOURS_IN_MS = 24 * 60 * 60 * 1000;
export const TWENTY_FIVE_HOURS_IN_MS = 25 * 60 * 60 * 1000;
