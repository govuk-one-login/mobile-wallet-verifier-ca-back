import { Result, successResult, errorResult } from '../result/result.ts';
import { logger } from '../logger/logger.ts';
import { LogMessage } from '../logger/log-message.ts';

export function extractIssuerCaCertFromChain(
  certificateChain: string,
): Result<string, string> {
  const certs = certificateChain
    .split('-----END CERTIFICATE-----')
    .filter((cert) => cert.includes('-----BEGIN CERTIFICATE-----'))
    .map((cert) => cert + '-----END CERTIFICATE-----');

  if (certs.length < 1) {
    logger.error(
      LogMessage.ISSUE_READER_CERT_LEAF_CERTIFICATE_VALIDATION_FAILURE,
      {
        errorMessage: 'Certificate chain must contain at least the issuer CA',
      },
    );
    return errorResult('Certificate chain must contain at least the issuer CA');
  }

  // First certificate in the chain is the immediate issuer (intermediate CA)
  return successResult(certs[0]);
}
