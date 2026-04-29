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
  curve: 'P-384',
  subject: {
    C: 'GB',
    L: 'London',
    O: 'Government Digital Service',
    ST: 'London',
  },
  keyUsage: {
    digitalSignature: 1,
  },
  extendedKeyUsage: {
    mobileDocumentReaderAuthentication: '1.0.18013.5.1.6',
  },
} as const;
