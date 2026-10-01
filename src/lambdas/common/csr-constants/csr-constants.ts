/*
X.509 extensions are identified by OIDs (Object Identifiers),
The basicConstraints extension uses the OID 2.5.29.19,
so we use that value to look it up in the CSR.
RFC 5280 section 4.2.1 defines the base id-ce value (2.5.29), and
Appendix A defines basicConstraints as id-ce-basicConstraints = { id-ce 19 }.
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1
https://datatracker.ietf.org/doc/html/rfc5280#appendix-A
*/
export const BASIC_CONSTRAINTS_OID = '2.5.29.19';
export const KEY_USAGE_OID = '2.5.29.15';
export const EXTENDED_KEY_USAGE_OID = '2.5.29.37';
export const NAME_CONSTRAINTS_OID = '2.5.29.30';

export const CSR_POLICY = {
  curves: ['P-256', 'P-384'],
  subject: {
    C: 'GB',
    O: 'Government Digital Service',
  },
  keyUsage: {
    digitalSignature: 1,
  },
  extendedKeyUsage: {
    mobileDocumentReaderAuthentication: '1.0.18013.5.1.6',
  },
} as const;

// Human-readable label of the supported curves, derived from CSR_POLICY.curves
// so error messages stay in sync with the policy. e.g. "P-256 or P-384".
export const SUPPORTED_CURVES_LABEL = CSR_POLICY.curves.join(' or ');

// Default curve used by the mock CSR generator (dev/build only). The mock keeps
// generating P-384 CSRs; validation accepts any curve in CSR_POLICY.curves.
export const DEFAULT_CSR_CURVE = 'P-384';
