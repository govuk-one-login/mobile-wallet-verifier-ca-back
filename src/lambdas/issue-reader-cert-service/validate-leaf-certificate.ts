import { X509Certificate } from '@peculiar/x509';
import { AsnConvert } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import {
  Result,
  errorResult,
  emptySuccess,
  successResult,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import { LogMessage } from '../common/logger/log-message.ts';
import { EXPECTED_CERTIFICATE_VERSION } from '../common/certificate-service-constants/certificate-service-constants.ts';

export async function validateLeafCertificate(
  certPem: string,
): Promise<Result<void, string>> {
  const parseCertResult = parseX509Certificate(certPem);
  if (parseCertResult.isError) {
    return parseCertResult;
  }

  const certificate = parseCertResult.value;

  const versionValidation = validateVersion(certificate);
  if (versionValidation.isError) {
    return versionValidation;
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

function validateVersion(certificate: X509Certificate): Result<void, string> {
  try {
    // Parse the certificate's ASN.1 structure to access the version field
    const certAsn = AsnConvert.parse(certificate.rawData, Certificate);
    const version = certAsn.tbsCertificate.version;

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
