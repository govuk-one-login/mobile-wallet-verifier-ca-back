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

export const CSR_POLICY = {
  curve: 'P-384',
  subject: {
    C: 'GB',
    O: 'Government Digital Service',
  },
} as const;
