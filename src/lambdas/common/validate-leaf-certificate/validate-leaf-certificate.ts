import { X509Certificate, Name } from '@peculiar/x509';
import { createHash } from 'node:crypto';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  Certificate,
  SubjectPublicKeyInfo,
  Version,
  AuthorityKeyIdentifier,
  id_ce_authorityKeyIdentifier,
  id_ce_subjectKeyIdentifier,
  id_ce_keyUsage,
  id_ce_extKeyUsage,
  SubjectKeyIdentifier,
  KeyUsage,
  KeyUsageFlags,
  ExtendedKeyUsage,
} from '@peculiar/asn1-x509';
import {
  Result,
  emptySuccess,
  successResult,
  emptyFailure,
} from '../result/result.ts';
import { logger } from '../logger/logger.ts';
import { LogMessage } from '../logger/log-message.ts';
import {
  EXPECTED_CERTIFICATE_VERSION,
  EXPECTED_SIGNATURE_ALGORITHM_OID,
  EXPECTED_ISSUER_AND_SUBJECT_NAME,
  TWENTY_FOUR_HOURS_IN_MS,
  TWENTY_FIVE_HOURS_IN_MS,
  MIN_BYTE_LENGTH,
  MAX_BYTE_LENGTH,
  CURVE_P384_OID_DER,
  EXPECTED_SPKI_LENGTH,
  ALGORITHM_OID,
  EXTENDED_KEY_USAGE,
} from '../certificate-service-constants/certificate-service-constants.ts';
import { extractIssuerCaCertFromChain } from '../../issue-reader-cert-service/certificate-service.ts';

export interface ValidateLeafCertificateParams {
  certPem: string;
  csrSubjectCn: string;
  certificateChain: string;
}

export function validateLeafCertificate(
  params: ValidateLeafCertificateParams,
): Result<void, void> {
  const { certPem, csrSubjectCn, certificateChain } = params;
  const parseCertResult = parseX509Certificate(certPem);
  if (parseCertResult.isError) {
    return parseCertResult;
  }

  const certificate = parseCertResult.value;
  const issuerCaCertPemResult = extractIssuerCaCertFromChain(certificateChain);
  if (issuerCaCertPemResult.isError) {
    return issuerCaCertPemResult;
  }

  const issuerCaCertPem = issuerCaCertPemResult.value;

  const validations: Array<() => Result<void, void>> = [
    () => validateVersion(certificate),
    () => validateSerialNumber(certificate),
    () => validateSignatureAlgorithm(certificate),
    () => validateCertificateValidity(certificate),
    () => validateIssuer(certificate, issuerCaCertPem),
    () => validateSubject(certificate, csrSubjectCn),
    () => validateSubjectPublicKeyInfo(certificate),
    () => {
      const caKeyIdResult = extractCaSubjectKeyIdentifier(issuerCaCertPem);
      if (caKeyIdResult.isError) return caKeyIdResult;
      return validateAuthorityKeyIdentifier(certificate, caKeyIdResult.value);
    },
    () => validateSubjectKeyIdentifier(certificate),
    () => validateKeyUsage(certificate),
    () => validateExtendedKeyUsage(certificate),
    () => validateSignatureValue(certificate),
  ];
  for (const validate of validations) {
    const validation = validate();
    if (validation.isError) {
      return validation;
    }
  }
  return emptySuccess();
}

function parseX509Certificate(certPem: string): Result<X509Certificate, void> {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certPem);
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate not valid X.509 format',
        data: {
          error,
        },
      },
    );
    return emptyFailure();
  }

  return successResult(certificate);
}

// Parse the certificate's ASN.1 structure to access the fields
const certAsn = (certificate: X509Certificate) => {
  return AsnConvert.parse(certificate.rawData, Certificate);
};

function validateVersion(certificate: X509Certificate): Result<void, void> {
  let version: Version;
  try {
    version = certAsn(certificate).tbsCertificate.version;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate version',
        data: { error },
      },
    );
    return emptyFailure();
  }
  if (version !== EXPECTED_CERTIFICATE_VERSION) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate version must be v3',
        data: {
          actualVersion: version,
          expectedVersion: EXPECTED_CERTIFICATE_VERSION,
        },
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}

function validateSerialNumber(
  certificate: X509Certificate,
): Result<void, void> {
  let serialNumber: ArrayBuffer;
  try {
    serialNumber = certAsn(certificate).tbsCertificate.serialNumber;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate serial number',
        data: { error },
      },
    );
    return emptyFailure();
  }
  // Check it is present and non-empty
  if (!serialNumber || serialNumber.byteLength === 0) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate serial number must be present',
        data: { serialNumber: serialNumber ? 'empty' : 'missing' },
      },
    );
    return emptyFailure();
  }

  // Shall contain at least 63 bits and should contain at least 71 bits of CSPRNG output (minimum 9 bytes), maximum 20 octets
  if (
    serialNumber.byteLength < MIN_BYTE_LENGTH ||
    serialNumber.byteLength > MAX_BYTE_LENGTH
  ) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate serial number must be between 9 and 20 bytes',
        data: {
          serialNumberLength: serialNumber.byteLength,
          minLength: MIN_BYTE_LENGTH,
          maxLength: MAX_BYTE_LENGTH,
        },
      },
    );
    return emptyFailure();
  }

  // Check if serial number is zero (all bytes are 0)
  const isZero = Array.from(new Uint8Array(serialNumber)).every(
    (byte) => byte === 0,
  );
  if (isZero) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate serial number must be non-zero',
        data: { serialNumber: 'zero' },
      },
    );
    return emptyFailure();
  }

  // Check if serial number is positive (MSB should not indicate negative)
  // In ASN.1 INTEGER encoding, if MSB is 1, it's treated as negative
  const firstByte = new Uint8Array(serialNumber)[0];
  if (firstByte & 0x80) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate serial number must be positive',
        data: { serialNumberMSB: firstByte },
      },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function validateSignatureAlgorithm(
  certificate: X509Certificate,
): Result<void, void> {
  let tbsAlgorithm: string;
  let outerAlgorithm: string;
  try {
    tbsAlgorithm = certAsn(certificate).tbsCertificate.signature.algorithm; // Signature algorithm inside Data
    outerAlgorithm = certAsn(certificate).signatureAlgorithm.algorithm;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate signature algorithm',
        data: { error },
      },
    );
    return emptyFailure();
  }
  if (tbsAlgorithm !== outerAlgorithm) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate signature algorithm OID mismatch between TBS and outer certificate',
        data: { tbsAlgorithm, outerAlgorithm },
      },
    );
    return emptyFailure();
  }

  if (tbsAlgorithm !== EXPECTED_SIGNATURE_ALGORITHM_OID) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate signature algorithm must be ECDSA with SHA-384 on P-384',
        data: {
          actualAlgorithm: tbsAlgorithm,
          expectedAlgorithm: EXPECTED_SIGNATURE_ALGORITHM_OID,
        },
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}

function validateName(name: Name): Result<void, void> {
  const C = name.getField('C');
  const O = name.getField('O');
  const ST = name.getField('ST');
  const L = name.getField('L');

  if (C.length !== 1 || C[0] !== EXPECTED_ISSUER_AND_SUBJECT_NAME.C) {
    return emptyFailure();
  }
  if (O.length !== 1 || O[0] !== EXPECTED_ISSUER_AND_SUBJECT_NAME.O) {
    return emptyFailure();
  }
  if (ST.length !== 1 || ST[0] !== EXPECTED_ISSUER_AND_SUBJECT_NAME.ST) {
    return emptyFailure();
  }
  if (L.length !== 1 || L[0] !== EXPECTED_ISSUER_AND_SUBJECT_NAME.L) {
    return emptyFailure();
  }

  return emptySuccess();
}

function validateIssuer(
  certificate: X509Certificate,
  issuerCaCertPem: string,
): Result<void, void> {
  try {
    const leafIssuerBytes = AsnConvert.serialize(
      certAsn(certificate).tbsCertificate.issuer,
    );
    const caCert = new X509Certificate(issuerCaCertPem);
    const caSubjectBytes = AsnConvert.serialize(
      certAsn(caCert).tbsCertificate.subject,
    );
    const leafIssuerHex = Buffer.from(leafIssuerBytes).toString('hex');
    const caSubjectHex = Buffer.from(caSubjectBytes).toString('hex');
    if (leafIssuerHex !== caSubjectHex) {
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage:
            'Certificate issuer does not match CA certificate subject',
        },
      );
      return emptyFailure();
    }
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Failed to parse certificate issuer', data: { error } },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function validateSubject(
  certificate: X509Certificate,
  csrSubjectCn: string,
): Result<void, void> {
  let subjectCn: string[];
  try {
    subjectCn = certificate.subjectName.getField('CN');
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Failed to parse certificate subject', data: { error } },
    );
    return emptyFailure();
  }
  if (subjectCn.length !== 1 || subjectCn[0] !== csrSubjectCn) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate subject CN does not match CSR subject CN',
        data: { certSubjectCn: subjectCn[0], csrSubjectCn },
      },
    );
    return emptyFailure();
  }

  const subjectValidation = validateName(certificate.subjectName);
  if (subjectValidation.isError) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate subject must match expected name values',
        data: {
          subject: certificate.subject,
          expected: EXPECTED_ISSUER_AND_SUBJECT_NAME,
        },
      },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function validateCertificateValidity(
  certificate: X509Certificate,
): Result<void, void> {
  const now = new Date();
  let notBefore: Date;
  let notAfter: Date;
  try {
    notBefore = certificate.notBefore;
    notAfter = certificate.notAfter;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate validity',
        data: { error },
      },
    );
    return emptyFailure();
  }
  if (now < notBefore || now > notAfter) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate is not within its validity period',
        data: {
          notBefore: notBefore.toISOString(),
          notAfter: notAfter.toISOString(),
          currentTime: now.toISOString(),
        },
      },
    );
    return emptyFailure();
  }

  const validityDurationMs = notAfter.getTime() - notBefore.getTime();

  if (
    validityDurationMs < TWENTY_FOUR_HOURS_IN_MS ||
    validityDurationMs > TWENTY_FIVE_HOURS_IN_MS
  ) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate validity period must be between 24 and 25 hours',
        data: {
          notBefore: notBefore.toISOString(),
          notAfter: notAfter.toISOString(),
          actualDurationMs: validityDurationMs,
          expectedDurationMs: TWENTY_FOUR_HOURS_IN_MS,
        },
      },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function validateSubjectPublicKeyInfo(
  certificate: X509Certificate,
): Result<void, void> {
  let subjectPublicKeyInfo: SubjectPublicKeyInfo;
  try {
    subjectPublicKeyInfo =
      certAsn(certificate).tbsCertificate.subjectPublicKeyInfo;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate subject public key info',
        data: { error },
      },
    );
    return emptyFailure();
  }

  const { algorithm: algorithmIdentifier, subjectPublicKey } =
    subjectPublicKeyInfo;

  // Check that the algorithm is ECDSA
  if (algorithmIdentifier.algorithm !== ALGORITHM_OID) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate public key algorithm must be ECDSA',
        data: { actualAlgorithm: algorithmIdentifier.algorithm },
      },
    );
    return emptyFailure();
  }

  // Check that the curve is P-384
  if (!algorithmIdentifier.parameters) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate public key curve parameters must be present',
      },
    );
    return emptyFailure();
  }
  // convert the parameters ArrayBuffer to hex and compare against the known DER encoding.
  // Exact match ensures P-384 is the only curve present.
  const curveHex = Buffer.from(algorithmIdentifier.parameters).toString('hex');
  if (curveHex !== CURVE_P384_OID_DER) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate public key curve must be P-384 only',
        data: { actualCurve: curveHex },
      },
    );
    return emptyFailure();
  }

  // Check that the subject public key is not empty
  if (!subjectPublicKey || subjectPublicKey.byteLength === 0) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate public key must be present',
        data: { publicKey: subjectPublicKey ? 'empty' : 'missing' },
      },
    );
    return emptyFailure();
  }

  // ISO 18013-5 requires the EC public key to be in uncompressed form (0x04 prefix)
  if (new Uint8Array(subjectPublicKey)[0] !== 0x04) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate public key must be in uncompressed form (0x04 prefix)',
        data: { firstByte: new Uint8Array(subjectPublicKey)[0] },
      },
    );
    return emptyFailure();
  }

  // P-384 SubjectPublicKeyInfo must be exactly 120 bytes
  const spkiRaw = AsnConvert.serialize(subjectPublicKeyInfo);
  if (spkiRaw.byteLength !== EXPECTED_SPKI_LENGTH) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate SubjectPublicKeyInfo must be 120 bytes for P-384',
        data: {
          actualLength: spkiRaw.byteLength,
          expectedLength: EXPECTED_SPKI_LENGTH,
        },
      },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function extractCaSubjectKeyIdentifier(
  caCertPem: string,
): Result<string, void> {
  const caCert = new X509Certificate(caCertPem);

  const skiExtension = caCert.extensions.find(
    (ext) => ext.type === id_ce_subjectKeyIdentifier,
  );

  if (!skiExtension) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Failed to extract Subject Key Identifier from CA certificate',
      },
    );
    return emptyFailure();
  }

  const subjectKeyId = AsnConvert.parse(
    skiExtension.value,
    SubjectKeyIdentifier,
  );
  return successResult(Buffer.from(subjectKeyId.buffer).toString('hex'));
}

function validateAuthorityKeyIdentifier(
  certificate: X509Certificate,
  expectedCaKeyId: string,
): Result<void, void> {
  // Find the Authority Key Identifier extension
  const akiExtension = certificate.extensions.find(
    (ext) => ext.type === id_ce_authorityKeyIdentifier,
  );

  if (!akiExtension) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Authority Key Identifier extension must be present',
      },
    );
    return emptyFailure();
  }

  let authorityKeyId: AuthorityKeyIdentifier;
  try {
    authorityKeyId = AsnConvert.parse(
      akiExtension.value,
      AuthorityKeyIdentifier,
    );
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse Authority Key Identifier extension',
        data: { error },
      },
    );
    return emptyFailure();
  }

  if (!authorityKeyId.keyIdentifier) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Authority Key Identifier must contain keyIdentifier field',
      },
    );
    return emptyFailure();
  }

  const actualKeyId = Buffer.from(authorityKeyId.keyIdentifier.buffer).toString(
    'hex',
  );
  if (actualKeyId !== expectedCaKeyId) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Authority Key Identifier does not match expected CA key identifier',
        data: {
          actualKeyId,
          expectedKeyId: expectedCaKeyId,
        },
      },
    );
    return emptyFailure();
  }
  return emptySuccess();
}

function validateSubjectKeyIdentifier(
  certificate: X509Certificate,
): Result<void, void> {
  const skiExtension = certificate.extensions.find(
    (ext) => ext.type === id_ce_subjectKeyIdentifier,
  );

  if (!skiExtension) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Subject Key Identifier extension must be present' },
    );
    return emptyFailure();
  }

  let subjectKeyId: SubjectKeyIdentifier;
  try {
    subjectKeyId = AsnConvert.parse(skiExtension.value, SubjectKeyIdentifier);
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse Subject Key Identifier extension',
        data: { error },
      },
    );
    return emptyFailure();
  }

  // Parses the certificate's ASN.1 structure and extracts the SubjectPublicKeyInfo field from the TBS (To-Be-Signed) portion — this contains the algorithm identifier and the raw public key bits.
  // Extracts the raw public key bit string as a byte array. This is the DER-encoded public key value.
  // Computes the SHA-1 hash of those public key bytes. RFC 5280 defines this as the standard method for generating a Subject Key Identifier — it's a 20-byte fingerprint that uniquely identifies the key.
  // Converts the SKI value that was actually embedded in the certificate extension into a hex string for comparison.

  const spki = certAsn(certificate).tbsCertificate.subjectPublicKeyInfo;
  const publicKeyBytes = new Uint8Array(spki.subjectPublicKey);
  const expectedKeyId = createHash('sha1').update(publicKeyBytes).digest('hex');
  const actualKeyId = Buffer.from(subjectKeyId.buffer).toString('hex');

  if (actualKeyId !== expectedKeyId) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Subject Key Identifier does not match SHA-1 hash of public key',
        data: { actualKeyId, expectedKeyId },
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}

function validateKeyUsage(certificate: X509Certificate): Result<void, void> {
  const keyUsageExtension = certificate.extensions.find(
    (ext) => ext.type === id_ce_keyUsage,
  );

  if (!keyUsageExtension) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Key Usage extension must be present' },
    );
    return emptyFailure();
  }

  let keyUsage: KeyUsage;
  try {
    keyUsage = AsnConvert.parse(keyUsageExtension.value, KeyUsage);
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse Key Usage extension',
        data: { error },
      },
    );
    return emptyFailure();
  }

  const bitStringToNumeric = keyUsage.toNumber();
  if (bitStringToNumeric !== KeyUsageFlags.digitalSignature) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Key Usage must contain only Digital Signature',
        data: { actualUsages: keyUsage.toJSON() },
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}

function validateExtendedKeyUsage(
  certificate: X509Certificate,
): Result<void, void> {
  const ekuExtension = certificate.extensions.find(
    (ext) => ext.type === id_ce_extKeyUsage,
  );

  if (!ekuExtension) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Extended Key Usage extension must be present' },
    );
    return emptyFailure();
  }

  let extendedKeyUsage: ExtendedKeyUsage;
  try {
    extendedKeyUsage = AsnConvert.parse(ekuExtension.value, ExtendedKeyUsage);
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse Extended Key Usage extension',
        data: { error },
      },
    );
    return emptyFailure();
  }

  const expectedOids = EXTENDED_KEY_USAGE.map(
    (eku) => eku.ExtendedKeyUsageObjectIdentifier,
  );
  const actualOids = Array.from(extendedKeyUsage);

  if (
    actualOids.length !== expectedOids.length ||
    !expectedOids.every((oid) => actualOids.includes(oid))
  ) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Extended Key Usage must contain only the expected OIDs',
        data: { actualOids, expectedOids },
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}

function validateSignatureValue(
  certificate: X509Certificate,
): Result<void, void> {
  let signatureValue: ArrayBuffer;
  try {
    signatureValue = certAsn(certificate).signatureValue;
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Failed to parse certificate signature value',
        data: { error },
      },
    );
    return emptyFailure();
  }

  if (!signatureValue || signatureValue.byteLength === 0) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate signature value must be present',
      },
    );
    return emptyFailure();
  }

  return emptySuccess();
}
