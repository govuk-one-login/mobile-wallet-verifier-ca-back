import { X509Certificate, Name } from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import {
  Result,
  errorResult,
  emptySuccess,
  successResult, emptyFailure,
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
} from '../certificate-service-constants/certificate-service-constants.ts';

export function validateLeafCertificate(
  certPem: string,
  csrSubjectCn: string,
): Result<void, string> {
  const parseCertResult = parseX509Certificate(certPem);
  if (parseCertResult.isError) {
    return parseCertResult;
  }

  const certificate = parseCertResult.value;

  const validations: Array<Result<void, string>> = [
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

function parseX509Certificate(
  certPem: string,
): Result<X509Certificate, string> {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certPem);
  } catch (error: unknown) {
    const errorMessage = 'Certificate not valid X.509 format';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage,
        data: {
          error,
        },
      },
    );
    return errorResult(errorMessage);
  }

  return successResult(certificate);
}

// Parse the certificate's ASN.1 structure to access the fields
const certAsn = (certificate: X509Certificate) => {
  return AsnConvert.parse(certificate.rawData, Certificate);
};

function validateVersion(certificate: X509Certificate): Result<void, string> {
  try {
    const version = certAsn(certificate).tbsCertificate.version;

    if (version !== EXPECTED_CERTIFICATE_VERSION) {
      const errorMessage = 'Certificate version must be v3';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            actualVersion: version,
            expectedVersion: EXPECTED_CERTIFICATE_VERSION,
          },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate version';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage,
        data: { error },
      },
    );
    return errorResult(errorMessage);
  }
  return emptySuccess();
}

function validateSerialNumber(
  certificate: X509Certificate,
): Result<void, string> {
  try {
    const serialNumber = certAsn(certificate).tbsCertificate.serialNumber;

    // Check it is present and non-empty
    if (!serialNumber || serialNumber.byteLength === 0) {
      const errorMessage = 'Certificate serial number must be present';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { serialNumber: serialNumber ? 'empty' : 'missing' },
        },
      );
      return errorResult(errorMessage);
    }

    // Shall contain at least 63 bits and should contain at least 71 bits of CSPRNG output (minimum 9 bytes), maximum 20 octets
    if (serialNumber.byteLength < 9 || serialNumber.byteLength > 20) {
      const errorMessage =
        'Certificate serial number must be between 9 and 20 bytes';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            serialNumberLength: serialNumber.byteLength,
            minLength: 9,
            maxLength: 20,
          },
        },
      );
      return errorResult(errorMessage);
    }

    // Check if serial number is zero (all bytes are 0)
    const isZero = Array.from(new Uint8Array(serialNumber)).every(
      (byte) => byte === 0,
    );
    if (isZero) {
      const errorMessage = 'Certificate serial number must be non-zero';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { serialNumber: 'zero' },
        },
      );
      return errorResult(errorMessage);
    }

    // Check if serial number is positive (MSB should not indicate negative)
    // In ASN.1 INTEGER encoding, if MSB is 1, it's treated as negative
    const firstByte = new Uint8Array(serialNumber)[0];
    if (firstByte & 0x80) {
      const errorMessage = 'Certificate serial number must be positive';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { serialNumberMSB: firstByte },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate serial number';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage,
        data: { error },
      },
    );
    return errorResult(errorMessage);
  }
  return emptySuccess();
}

function validateSignatureAlgorithm(
  certificate: X509Certificate,
): Result<void, string> {
  try {
    const tbsAlgorithm =
      certAsn(certificate).tbsCertificate.signature.algorithm; // Signature algorithm inside Data
    const outerAlgorithm = certAsn(certificate).signatureAlgorithm.algorithm;

    if (tbsAlgorithm !== outerAlgorithm) {
      const errorMessage =
        'Certificate signature algorithm OID mismatch between TBS and outer certificate';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { tbsAlgorithm, outerAlgorithm },
        },
      );
      return errorResult(errorMessage);
    }

    if (tbsAlgorithm !== EXPECTED_SIGNATURE_ALGORITHM_OID) {
      const errorMessage =
        'Certificate signature algorithm must be ECDSA with SHA-384 on P-384';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            actualAlgorithm: tbsAlgorithm,
            expectedAlgorithm: EXPECTED_SIGNATURE_ALGORITHM_OID,
          },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate signature algorithm';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage,
        data: { error },
      },
    );
    return errorResult(errorMessage);
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

function validateIssuer(certificate: X509Certificate): Result<void, string> {
  try {
    const issuerCn = certificate.issuerName.getField('CN');
    if (issuerCn.length !== 1 || issuerCn[0] !== EXPECTED_ISSUER_CN) {
      const errorMessage =
        'Certificate issuer Common name must match expected name value';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { certSubjectCn: issuerCn[0], EXPECTED_ISSUER_CN },
        },
      );
      return errorResult(errorMessage);
    }
    const issuerValidation = validateName(certificate.issuerName);
    if (issuerValidation.isError) {
      const errorMessage = 'Certificate issuer must match expected name values';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            issuer: certificate.issuer,
            expected: EXPECTED_ISSUER_AND_SUBJECT_NAME,
          },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate issuer and subject';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage, data: { error } },
    );
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function validateSubject(
  certificate: X509Certificate,
  csrSubjectCn: string,
): Result<void, string> {
  try {
    const subjectCn = certificate.subjectName.getField('CN');
    if (subjectCn.length !== 1 || subjectCn[0] !== csrSubjectCn) {
      const errorMessage =
        'Certificate subject CN does not match CSR subject CN';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: { certSubjectCn: subjectCn[0], csrSubjectCn },
        },
      );
      return errorResult(errorMessage);
    }

    const subjectValidation = validateName(certificate.subjectName);
    if (subjectValidation.isError) {
      const errorMessage =
        'Certificate subject must match expected name values';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            issuer: certificate.subject,
            expected: EXPECTED_ISSUER_AND_SUBJECT_NAME,
          },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate subject';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      { errorMessage, data: { error } },
    );
    return errorResult(errorMessage);
  }
  return emptySuccess();
}

function validateCertificateValidity(
  certificate: X509Certificate,
): Result<void, string> {
  try {
    const now = new Date();
    const notBefore = certificate.notBefore;
    const notAfter = certificate.notAfter;

    if (now < notBefore || now > notAfter) {
      const errorMessage = 'Certificate is not within its validity period';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            notBefore: notBefore.toISOString(),
            notAfter: notAfter.toISOString(),
            currentTime: now.toISOString(),
          },
        },
      );
      return errorResult(errorMessage);
    }

    const validityDurationMs = notAfter.getTime() - notBefore.getTime();

    if (
      validityDurationMs < TWENTY_FOUR_HOURS_IN_MS ||
      validityDurationMs > TWENTY_FIVE_HOURS_IN_MS
    ) {
      const errorMessage =
        'Certificate validity period must be between 24 and 25 hours';
      logger.error(
        LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
        {
          errorMessage,
          data: {
            notBefore: notBefore.toISOString(),
            notAfter: notAfter.toISOString(),
            actualDurationMs: validityDurationMs,
            expectedDurationMs: TWENTY_FOUR_HOURS_IN_MS,
          },
        },
      );
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    const errorMessage = 'Failed to parse certificate validity';
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage,
        data: { error },
      },
    );
    return errorResult(errorMessage);
  }
  return emptySuccess();
}
