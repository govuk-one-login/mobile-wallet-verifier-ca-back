/**
 * iOS App Attest Constants
 * 
 * Centralizes magic numbers and values used in iOS attestation verification
 * based on Apple's App Attest documentation and WebAuthn specifications.
 */

// Apple OIDs (Object Identifiers)
export const APPLE_OIDS = {
  /** Apple App Attest credential certificate extension OID */
  CREDENTIAL_CERT: '1.2.840.113635.100.8.2',
  /** Apple App Attest nonce extension OID */
  NONCE_EXTENSION: '1.2.840.113635.100.8.2',
} as const;

// Authenticator Data Structure Offsets (WebAuthn spec)
export const AUTH_DATA_OFFSETS = {
  /** RP ID hash field (32 bytes) */
  RP_ID_HASH_START: 0,
  RP_ID_HASH_END: 32,
  /** Flags field (1 byte) */
  FLAGS: 32,
  /** Counter field (4 bytes) */
  COUNTER_START: 33,
  COUNTER_END: 37,
  /** AAGUID field (16 bytes) */
  AAGUID_START: 37,
  AAGUID_END: 53,
  /** Credential ID length field (2 bytes) */
  CRED_ID_LEN_START: 53,
  CRED_ID_LEN_END: 55,
  /** Credential data starts after credential ID */
  CRED_DATA_START: 55,
} as const;

// Authenticator Flags (WebAuthn spec)
export const AUTH_FLAGS = {
  /** User Present flag (bit 0) */
  USER_PRESENT: 0x01,
  /** User Verified flag (bit 2) */
  USER_VERIFIED: 0x04,
  /** Attested Credential Data flag (bit 6) */
  ATTESTED_CREDENTIAL: 0x40,
  /** Extension Data flag (bit 7) */
  EXTENSION_DATA: 0x80,
} as const;

// COSE Key Parameters (RFC 8152)
export const COSE_KEY_PARAMS = {
  /** Key type parameter */
  KTY: 1,
  /** Algorithm parameter */
  ALG: 3,
  /** Curve parameter */
  CRV: -1,
  /** X coordinate parameter */
  X: -2,
  /** Y coordinate parameter */
  Y: -3,
} as const;

// COSE Algorithm Values (RFC 8152)
export const COSE_ALGORITHMS = {
  /** ES256 (ECDSA w/ SHA-256) */
  ES256: -7,
} as const;

// COSE Curve Values (RFC 8152)
export const COSE_CURVES = {
  /** P-256 curve */
  P256: 1,
} as const;

// Apple App Attest Values
export const APPLE_VALUES = {
  /** Expected attestation format */
  ATTESTATION_FORMAT: 'apple-appattest',
  /** AAGUID for Apple App Attest (development) */
  AAGUID_DEVELOPMENT: 'appattestdevelop',
  /** Expected counter value for attestation (must be 0) */
  EXPECTED_COUNTER: 0,
  /** Minimum certificate chain length */
  MIN_CERT_CHAIN_LENGTH: 2,
  /** Minimum authenticator data length */
  MIN_AUTH_DATA_LENGTH: 37,
} as const;

// Hash Algorithms
export const HASH_ALGORITHMS = {
  SHA256: 'sha256',
} as const;

// Certificate Chain Validation
export const CERT_VALIDATION = {
  /** Minimum required certificates in chain */
  MIN_CHAIN_LENGTH: 2,
} as const;