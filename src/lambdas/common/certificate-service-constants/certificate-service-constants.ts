// X.509 extensions are identified by OIDs (Object Identifiers)

export const SIGNING_ALGORITHM = 'SHA384WITHECDSA';

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
  {
    // mdocReaderAuth
    ExtendedKeyUsageObjectIdentifier: '1.0.23220.4.1.6',
  },
] as const;

