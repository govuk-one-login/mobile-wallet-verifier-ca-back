// Android attestation constants
//[C-1-5] MUST use verification algorithms as strong as current recommendations from NIST for hashing algorithms (SHA-256) and public key sizes (RSA-2048).
export const ANDROID_ATTESTATION_CONFIG = {
  BASIC_CONSTRAINTS_OID: '2.5.29.19',
  ATTESTATION_EXTENSION_OID: '1.3.6.1.4.1.11129.2.1.17',
  VALID_KEY_ALGORITHM: 'ECDSA',
  VALID_ECDSA_CURVES: ['P-256', 'P-384', 'P-521'],
  VALID_RSA_SIZES: [2048, 3072, 4096],
  CRL_TIMEOUT: 5000
} as const;