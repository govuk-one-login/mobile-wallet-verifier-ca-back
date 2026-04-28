import {
  Pkcs10CertificateRequest,
  BasicConstraintsExtension,
  Extension,
  ExtendedKeyUsageExtension,
  KeyUsagesExtension,
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
  CSR_POLICY,
  EXTENDED_KEY_USAGE_OID,
  KEY_USAGE_OID,
  NAME_CONSTRAINTS_OID,
} from '../common/csr-constants/csr-constants';

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

  const validateExtensionsResult = validateCsrExtensions(csr);
  if (validateExtensionsResult.isError) {
    return validateExtensionsResult;
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
        publicKeyAlgorithm: publicKeyAlgorithm.name,
      },
    });
    return errorResult(errorMessage);
  }

  const publicKeyAlgorithmCurve =
    'namedCurve' in publicKeyAlgorithm ? publicKeyAlgorithm.namedCurve : null;
  if (publicKeyAlgorithmCurve !== CSR_POLICY.curve) {
    const errorMessage = `CSR public key does not use ${CSR_POLICY.curve} curve`;
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

function validateCsrExtensions(
  csr: Pkcs10CertificateRequest,
): Result<void, string> {
  let extensions: Extension[];
  try {
    // This is a getter that can throw, hence adding a try catch here
    extensions = csr.extensions;
  } catch (error: unknown) {
    const errorMessage = 'CSR extensions are invalid';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        error,
      },
    });
    return errorResult(errorMessage);
  }

  for (const extension of extensions) {
    const validateExtensionResult = validateCsrExtension(extension);
    if (validateExtensionResult.isError) {
      return validateExtensionResult;
    }
  }

  return emptySuccess();
}

function validateCsrExtension(extension: Extension): Result<void, string> {
  switch (extension.type) {
    case BASIC_CONSTRAINTS_OID:
      return validateCsrBasicConstraints(extension);
    case KEY_USAGE_OID:
      return validateCsrKeyUsage(extension);
    case EXTENDED_KEY_USAGE_OID:
      return validateCsrExtendedKeyUsage(extension);
    case NAME_CONSTRAINTS_OID:
      return rejectCsrNameConstraints(extension);
    default:
      return emptySuccess();
  }
}

function validateCsrBasicConstraints(
  basicConstraints: Extension,
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

function validateCsrKeyUsage(keyUsage: Extension): Result<void, string> {
  if (
    !(keyUsage instanceof KeyUsagesExtension) ||
    keyUsage.usages !== CSR_POLICY.keyUsage.digitalSignature
  ) {
    const errorMessage = 'CSR keyUsage is not digitalSignature';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        keyUsage:
          keyUsage instanceof KeyUsagesExtension ? keyUsage.usages : undefined,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function validateCsrExtendedKeyUsage(
  extendedKeyUsage: Extension,
): Result<void, string> {
  if (
    !(extendedKeyUsage instanceof ExtendedKeyUsageExtension) ||
    extendedKeyUsage.usages.length !== 1 ||
    extendedKeyUsage.usages[0] !==
      CSR_POLICY.extendedKeyUsage.mobileDocumentReaderAuthentication
  ) {
    const errorMessage =
    // note to self, should I note the actual value instead or in addition?
      'CSR extendedKeyUsage is not mobile document reader authentication';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        extendedKeyUsage:
          extendedKeyUsage instanceof ExtendedKeyUsageExtension
            ? extendedKeyUsage.usages
            : undefined,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function rejectCsrNameConstraints(
  nameConstraints: Extension,
): Result<void, string> {
  const errorMessage = 'CSR contains NameConstraints extension';
  logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
    errorMessage,
    data: {
      extensionType: nameConstraints.type,
    },
  });
  return errorResult(errorMessage);
}

function validateCsrSubject(subjectName: Name): Result<void, string> {
  const subjectCountryNames = subjectName.getField('C');
  if (
    subjectCountryNames.length !== 1 ||
    subjectCountryNames[0] !== CSR_POLICY.subject.C
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

  const subjectStateOrProvinceNames = subjectName.getField('ST');
  if (
    subjectStateOrProvinceNames.length !== 1 ||
    subjectStateOrProvinceNames[0] !== CSR_POLICY.subject.ST
  ) {
    const errorMessage = 'CSR subject ST is not London';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectST: subjectStateOrProvinceNames,
      },
    });
    return errorResult(errorMessage);
  }

  const subjectLocalityNames = subjectName.getField('L');
  if (
    subjectLocalityNames.length !== 1 ||
    subjectLocalityNames[0] !== CSR_POLICY.subject.L
  ) {
    const errorMessage = 'CSR subject L is not London';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectL: subjectLocalityNames,
      },
    });
    return errorResult(errorMessage);
  }

  const subjectOrganisationNames = subjectName.getField('O');
  if (
    subjectOrganisationNames.length !== 1 ||
    subjectOrganisationNames[0] !== CSR_POLICY.subject.O
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

  const subjectOrganisationalUnitNames = subjectName.getField('OU');
  if (subjectOrganisationalUnitNames.length > 0) {
    const errorMessage = 'CSR subject OU is present';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        subjectOU: subjectOrganisationalUnitNames,
      },
    });
    return errorResult(errorMessage);
  }

  const unsupportedSubjectFields = getUnsupportedSubjectFields(subjectName);
  if (unsupportedSubjectFields.length > 0) {
    const errorMessage = 'CSR subject contains unsupported fields';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      data: {
        unsupportedSubjectFields,
      },
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}

function getUnsupportedSubjectFields(subjectName: Name): string[] {
  const allowedSubjectFields = ['C', 'ST', 'L', 'O', 'CN'];
  const subjectFields = subjectName
    .toJSON()
    .flatMap((relativeDistinguishedName) =>
      Object.keys(relativeDistinguishedName),
    );

  return subjectFields.filter(
    (subjectField) => !allowedSubjectFields.includes(subjectField),
  );
}
