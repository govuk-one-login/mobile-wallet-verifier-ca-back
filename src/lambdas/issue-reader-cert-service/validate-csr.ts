import {
  Pkcs10CertificateRequest,
  BasicConstraintsExtension,
} from '@peculiar/x509';
import { LogMessage } from '../common/logger/log-message';
import { logger } from '../common/logger/logger';
import { Result, errorResult, emptySuccess } from '../common/result/result';

/*
X.509 extensions are identified by OIDs (Object Identifiers),
The basicConstraints extension uses the OID 2.5.29.19,
so we use that value to look it up in the CSR.
RFC 5280 section 4.2.1 defines the base id-ce value (2.5.29), and
Appendix A defines basicConstraints as id-ce-basicConstraints = { id-ce 19 }.
https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1
https://datatracker.ietf.org/doc/html/rfc5280#appendix-A
*/
const BASIC_CONSTRAINTS_OID = '2.5.29.19';

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

  return emptySuccess();
}
