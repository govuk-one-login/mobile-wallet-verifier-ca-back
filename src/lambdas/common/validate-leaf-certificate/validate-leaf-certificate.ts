import { X509Certificate, Name } from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate, Version } from '@peculiar/asn1-x509';
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
  EXPECTED_ISSUER_CN,
  TWENTY_FOUR_HOURS_IN_MS,
  TWENTY_FIVE_HOURS_IN_MS,
  MIN_BYTE_LENGTH,
  MAX_BYTE_LENGTH,
} from '../certificate-service-constants/certificate-service-constants.ts';

export function validateLeafCertificate(
  certPem: string,
  csrSubjectCn: string,
): Result<void, void> {
  const parseCertResult = parseX509Certificate(certPem);
  if (parseCertResult.isError) {
    return parseCertResult;
  }

  const certificate = parseCertResult.value;

  const validations: Array<Result<void, void>> = [
    validateVersion(certificate),
    validateSerialNumber(certificate),
    validateSignatureAlgorithm(certificate),
    validateCertificateValidity(certificate),
    validateIssuer(certificate),
    validateSubject(certificate, csrSubjectCn),
  ];
  for (const validation of validations) {
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

function validateIssuer(certificate: X509Certificate): Result<void, void> {
  let issuerCn: string[];
  try {
    issuerCn = certificate.issuerName.getField('CN');
  } catch (error: unknown) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage: 'Failed to parse certificate issuer', data: { error } },
    );
    return emptyFailure();
  }
  if (issuerCn.length !== 1 || issuerCn[0] !== EXPECTED_ISSUER_CN) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage:
          'Certificate issuer Common name must match expected name value',
        data: { certIssuerCn: issuerCn[0], EXPECTED_ISSUER_CN },
      },
    );
    return emptyFailure();
  }
  const issuerValidation = validateName(certificate.issuerName);
  if (issuerValidation.isError) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate issuer must match expected name values',
        data: {
          issuer: certificate.issuer,
          expected: EXPECTED_ISSUER_AND_SUBJECT_NAME,
        },
      },
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
