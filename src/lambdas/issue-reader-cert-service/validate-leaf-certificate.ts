import { X509Certificate } from '@peculiar/x509';
import {
  Result,
  errorResult,
  emptySuccess,
  successResult,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';

export async function validateLeafCertificate(
  certPem: string,
): Promise<Result<void, string>> {
  const parseCertResult = parseX509Certificate(certPem);
  if (parseCertResult.isError) {
    return parseCertResult;
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
          certPem,
          error,
        },
      },
    );
    return errorResult(errorMessage);
  }

  return successResult(certificate);
}
