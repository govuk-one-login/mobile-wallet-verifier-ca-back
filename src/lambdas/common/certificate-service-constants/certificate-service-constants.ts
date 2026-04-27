// X.509 extensions are identified by OIDs (Object Identifiers)

export const SIGNING_ALGORITHM = 'SHA384WITHECDSA';

export const TEMPLATE_ARN =
  'arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1';

export const VALIDITY = {
  Type: 'DAYS',
  Value: 1, // 24 hours
} as const;

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
