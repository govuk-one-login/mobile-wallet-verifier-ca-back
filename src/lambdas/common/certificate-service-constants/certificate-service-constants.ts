// X.509 extensions are identified by OIDs (Object Identifiers)

import { AsnConvert } from '@peculiar/asn1-schema';
import {
  SubjectInfoAccessSyntax,
  AccessDescription,
  GeneralName,
  id_pe_subjectInfoAccess,
} from '@peculiar/asn1-x509';

export const SIGNING_ALGORITHM = 'SHA256WITHECDSA';

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

// DER-encoded EKU extension value for mDL Reader Auth (1.0.18013.5.1.6), base64-encoded for ACM PCA CustomExtensions
export const EXTENDED_KEY_USAGE_DER_BASE64 = 'MAkGByiBjF0FAQY=';

// DVS privacy policy URL, carried in each L4 leaf via the Subject Information
// Access (SIA) extension (RFC 5280 4.2.2.2), which MUST be non-critical.
export const PRIVACY_POLICY_URL =
  'https://www.gov.uk/government/publications/govuk-one-login-privacy-notice/govuk-one-login-privacy-notice';

// SIA extension OID (id-pe-subjectInfoAccess = 1.3.6.1.5.5.7.1.11)
export const SUBJECT_INFO_ACCESS_OID = id_pe_subjectInfoAccess;

// GDS-owned access-method OID for the DVS privacy policy URL.
export const PRIVACY_POLICY_ACCESS_METHOD_OID = '1.3.6.1.4.1.66559.1.1';

// SIA extension value as base64-encoded DER, the form ACM PCA CustomExtensions expects.
export const PRIVACY_POLICY_SIA_DER_BASE64 = Buffer.from(
  AsnConvert.serialize(
    new SubjectInfoAccessSyntax([
      new AccessDescription({
        accessMethod: PRIVACY_POLICY_ACCESS_METHOD_OID,
        accessLocation: new GeneralName({
          uniformResourceIdentifier: PRIVACY_POLICY_URL,
        }),
      }),
    ]),
  ),
).toString('base64');

// Certificate validation constants
export const EXPECTED_CERTIFICATE_VERSION = 2; // X.509 version field encoding: v1=0, v2=1, v3=2 (ASN.1 INTEGER values)
export const MIN_BYTE_LENGTH = 9; // Serial number minimum byte length
export const MAX_BYTE_LENGTH = 20; // Serial number maximum byte length
export const EXPECTED_SIGNATURE_ALGORITHM_OID = '1.2.840.10045.4.3.2'; // ECDSA with SHA-256 (leaf is signed by the P-256 Test DVS Verifier CA)
export const EXPECTED_ISSUER_AND_SUBJECT_NAME = {
  C: 'GB',
  O: 'Government Digital Service',
  ST: 'London',
  L: 'London',
} as const;
export const EXPECTED_ISSUER_CN = 'GOVUK Mobile Wallet GovVerifier CA';

// Leaf (L4) validity. We request 90 DAYS; ACM PCA backdates notBefore by 60
// minutes while setting notAfter 90 days after issuance, so the issued span is
// 90 days + 1 hour. Validation centres on that span with a small tolerance.
// See AWS IssueCertificate API (ValidityNotBefore).
export const NINETY_DAYS_IN_MS = 90 * 24 * 60 * 60 * 1000;
export const PCA_NOT_BEFORE_BACKDATE_MS = 60 * 60 * 1000; // PCA default: issuance - 60 min
export const EXPECTED_VALIDITY_SPAN_MS =
  NINETY_DAYS_IN_MS + PCA_NOT_BEFORE_BACKDATE_MS;
export const VALIDITY_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes
export const VALIDITY_SPAN_MIN_MS =
  EXPECTED_VALIDITY_SPAN_MS - VALIDITY_TOLERANCE_MS;
export const VALIDITY_SPAN_MAX_MS =
  EXPECTED_VALIDITY_SPAN_MS + VALIDITY_TOLERANCE_MS;

export const CURVE_P384_OID_DER = '06052b81040022'; // DER encoding of OID 1.3.132.0.34 (secp384r1/P-384)
export const ALGORITHM_OID = '1.2.840.10045.2.1';
export const EXPECTED_SPKI_LENGTH = 120;
