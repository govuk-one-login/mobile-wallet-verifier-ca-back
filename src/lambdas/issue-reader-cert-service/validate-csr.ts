import {
  Pkcs10CertificateRequest,
  BasicConstraintsExtension,
  Extension,
  Name,
} from '@peculiar/x509';
import { LogMessage } from '../common/logger/log-message';
import { logger } from '../common/logger/logger';
import {
  Result,
  errorResult,
  emptySuccess,
  successResult,
} from '../common/result/result';
import {
  BASIC_CONSTRAINTS_OID,
  CSR_EC_CURVE,
  CSR_SUBJECT_POLICY,
} from '../common/csr-policy/csr-policy';

export async function validateCsr(
  csrPem: string,
): Promise<Result<void, string>> {
  const parseCsrResult = parsePkcs10CertificateRequest(csrPem);
  if (parseCsrResult.isError) {
    return parseCsrResult;
  }
  const csr = parseCsrResult.value;

  const validateSignatureResult = await validateCsrSignature(csr);
  if (validateSignatureResult.isError) {
    return validateSignatureResult;
  }

  const validatePublicKeyAlgorithmResult = validateCsrPublicKeyAlgorithm(
    csr.publicKey.algorithm,
  );
  if (validatePublicKeyAlgorithmResult.isError) {
    return validatePublicKeyAlgorithmResult;
  }

  const basicConstraints = csr.getExtension(BASIC_CONSTRAINTS_OID);
  const validateBasicConstraintsResult =
    validateCsrBasicConstraints(basicConstraints);
  if (validateBasicConstraintsResult.isError) {
    return validateBasicConstraintsResult;
  }

  const validateSubjectResult = validateCsrSubject(csr.subjectName);
  if (validateSubjectResult.isError) {
    return validateSubjectResult;
  }

  return emptySuccess();
}

function parsePkcs10CertificateRequest(
  csrPem: string,
): Result<Pkcs10CertificateRequest, string> {
  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(csrPem);
  } catch (error: unknown) {
    const errorMessage = 'CSR not valid PKCS#10 request';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        csrPem,
        error,
      },
    });
    return errorResult(errorMessage);
  }

  return successResult(csr);
}

async function validateCsrSignature(
  csr: Pkcs10CertificateRequest,
): Promise<Result<void, string>> {
  try {
    const isSignatureValid = await csr.verify();
    if (!isSignatureValid) {
      const errorMessage = 'CSR self signature verification failed';
      logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
        errorMessage,
      });
      return errorResult(errorMessage);
    }
  } catch (error: unknown) {
    // not testing this currently
    const errorMessage = 'CSR self signature verification failed';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        error,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function validateCsrPublicKeyAlgorithm(
  publicKeyAlgorithm: Algorithm,
): Result<void, string> {
  if (publicKeyAlgorithm.name !== 'ECDSA') {
    const errorMessage = 'CSR public key not EC key';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        csrPublicKeyAlgorithm: publicKeyAlgorithm.name,
      },
    });
    return errorResult(errorMessage);
  }

  const publicKeyAlgorithmCurve =
    'namedCurve' in publicKeyAlgorithm ? publicKeyAlgorithm.namedCurve : null;
  if (publicKeyAlgorithmCurve !== CSR_EC_CURVE) {
    const errorMessage = `CSR public key does not use ${CSR_EC_CURVE} curve`;
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        publicKeyAlgorithmCurve,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function validateCsrBasicConstraints(
  basicConstraints: Extension | null,
): Result<void, string> {
  if (
    basicConstraints instanceof BasicConstraintsExtension &&
    basicConstraints.ca
  ) {
    const errorMessage = 'CSR requests CA capabilities';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        basicConstraintsCa: basicConstraints.ca,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function validateCsrSubject(subjectName: Name): Result<void, string> {
  const subjectCountryNames = subjectName.getField('C');
  if (
    subjectCountryNames.length !== 1 ||
    subjectCountryNames[0] !== CSR_SUBJECT_POLICY.C
  ) {
    const errorMessage = 'CSR subject C is not GB';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectC: subjectCountryNames,
      },
    });
    return errorResult(errorMessage);
  }

  const subjectOrganisationNames = subjectName.getField('O');
  if (
    subjectOrganisationNames.length !== 1 ||
    subjectOrganisationNames[0] !== CSR_SUBJECT_POLICY.O
  ) {
    const errorMessage = 'CSR subject O is not Government Digital Service';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectO: subjectOrganisationNames,
      },
    });
    return errorResult(errorMessage);
  }

  const subjectCommonNames = subjectName.getField('CN');
  if (subjectCommonNames.length !== 1 || !subjectCommonNames[0].trim()) {
    const errorMessage = 'CSR subject CN is not present';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectCN: subjectCommonNames,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}
