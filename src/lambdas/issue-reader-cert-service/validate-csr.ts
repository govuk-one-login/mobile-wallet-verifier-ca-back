import {
  Pkcs10CertificateRequest,
  BasicConstraintsExtension,
} from '@peculiar/x509';
import { LogMessage } from '../common/logger/log-message';
import { logger } from '../common/logger/logger';
import { Result, errorResult, emptySuccess } from '../common/result/result';
import {
  BASIC_CONSTRAINTS_OID,
  CSR_SUBJECT_POLICY,
} from '../common/csr-policy';

export async function validateCsr(
  csrPem: string,
): Promise<Result<void, string>> {
  let csr: Pkcs10CertificateRequest;
  try {
    csr = new Pkcs10CertificateRequest(csrPem);
  } catch (error: unknown) {
    const errorMessage = 'CSR not valid PKCS#10 request';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
      error,
    });
    return errorResult(errorMessage);
  }

  try {
    const validSignedCsr = await csr.verify();
    if (!validSignedCsr) {
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
      error,
    });
    return errorResult(errorMessage);
  }

  const csrPublicKeyAlgorithm = csr.publicKey.algorithm;
  if (csrPublicKeyAlgorithm.name !== 'ECDSA') {
    const errorMessage = 'CSR public key not EC key';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  if (
    !('namedCurve' in csrPublicKeyAlgorithm) ||
    csrPublicKeyAlgorithm.namedCurve !== 'P-256'
  ) {
    const errorMessage = 'CSR public key does not use P-256 curve';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  const basicConstraints = csr.getExtension(BASIC_CONSTRAINTS_OID);
  if (
    basicConstraints instanceof BasicConstraintsExtension &&
    basicConstraints.ca
  ) {
    const errorMessage = 'CSR requests CA capabilities';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  const subjectCountryNames = csr.subjectName.getField('C');
  if (
    subjectCountryNames.length !== 1 ||
    subjectCountryNames[0] !== CSR_SUBJECT_POLICY.C
  ) {
    const errorMessage = 'CSR subject C is not GB';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  const subjectOrganisationNames = csr.subjectName.getField('O');
  if (
    subjectOrganisationNames.length !== 1 ||
    subjectOrganisationNames[0] !== CSR_SUBJECT_POLICY.O
  ) {
    const errorMessage = 'CSR subject O is not Government Digital Service';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  const subjectCommonNames = csr.subjectName.getField('CN');
  if (subjectCommonNames.length !== 1 || !subjectCommonNames[0].trim()) {
    const errorMessage = 'CSR subject CN is not present';
    logger.error(LogMessage.ISSUE_READER_CERT_CSR_VALIDATION_FAILURE, {
      errorMessage,
    });
    return errorResult(errorMessage);
  }

  return emptySuccess();
}
