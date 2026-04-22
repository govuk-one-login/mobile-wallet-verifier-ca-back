import {
  ACMPCAClient,
  GetCertificateCommand,
  GetCertificateCommandOutput,
  IssueCertificateCommand,
  IssueCertificateCommandOutput,
} from '@aws-sdk/client-acm-pca';
import {
  Result,
  successResult,
  emptyFailure,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import {
  EXTENDED_KEY_USAGE,
  KEY_USAGE,
  SIGNING_ALGORITHM,
  TEMPLATE_ARN,
  VALIDITY,
} from '../common/certificate-service-constants/certificate-service-constants.ts';
import { LogMessage } from '../common/logger/log-message.ts';

const acmpcaClient = new ACMPCAClient({});

export const issueCertificate = async (params: {
  csrPem: string;
  certificateAuthorityArn: string;
}): Promise<Result<string, void>> => {
  let issueResponse: IssueCertificateCommandOutput;
  const { csrPem, certificateAuthorityArn } = params;
  try {
    const issueCommand = new IssueCertificateCommand({
      ApiPassthrough: {
        Extensions: {
          KeyUsage: {
            DigitalSignature: KEY_USAGE.DigitalSignature,
          },
          ExtendedKeyUsage: [
            {
              // mDL Reader Auth
              ExtendedKeyUsageObjectIdentifier:
                EXTENDED_KEY_USAGE[0].ExtendedKeyUsageObjectIdentifier,
            },
          ],
        },
      },
      CertificateAuthorityArn: certificateAuthorityArn,
      Csr: Buffer.from(csrPem),
      SigningAlgorithm: SIGNING_ALGORITHM,
      TemplateArn: TEMPLATE_ARN,
      Validity: {
        Type: VALIDITY.Type,
        Value: VALIDITY.Value, // 24 hours
      },
    });

    issueResponse = await acmpcaClient.send(issueCommand);
  } catch (error: unknown) {
    logger.error(LogMessage.CERT_SERVICE_ISSUE_CERTIFICATE_FAILURE, {
      error,
      errorMessage: 'Error issuing certificate',
    });
    return emptyFailure();
  }

  if (!issueResponse.CertificateArn) {
    logger.error(LogMessage.CERT_SERVICE_ISSUE_CERTIFICATE_FAILURE, {
      errorMessage: 'No certificate ARN returned',
    });
    return emptyFailure();
  }

  return successResult(issueResponse.CertificateArn);
};

export const getCertificate = async (params: {
  certificateArn: string;
  certificateAuthorityArn: string;
}): Promise<Result<string, void>> => {
  let getResponse: GetCertificateCommandOutput;
  const { certificateArn, certificateAuthorityArn } = params;
  const maxRetries = 3;
  const baseDelay = 1000; // 1 second

  // Adding retry logic with exponential backoff to handle
  // the asynchronous nature of certificate issuance in ACM PCA.
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const getCommand = new GetCertificateCommand({
        CertificateAuthorityArn: certificateAuthorityArn,
        CertificateArn: certificateArn,
      });

      getResponse = await acmpcaClient.send(getCommand);
    } catch (error: unknown) {
      if (
        error instanceof Error &&
        error.name === 'RequestInProgressException' &&
        attempt < maxRetries - 1
      ) {
        // Wait with exponential backoff
        const delay = baseDelay * Math.pow(2, attempt);

        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      logger.error(LogMessage.CERT_SERVICE_GET_CERTIFICATE_FAILURE, {
        error,
        errorMessage: 'Error retrieving certificate',
      });
      return emptyFailure();
    }

    if (!getResponse.Certificate) {
      logger.error(LogMessage.CERT_SERVICE_GET_CERTIFICATE_FAILURE, {
        errorMessage: 'Failed to retrieve certificate',
      });
      return emptyFailure();
    }

    if (!getResponse.CertificateChain) {
      logger.error(LogMessage.CERT_SERVICE_GET_CERTIFICATE_FAILURE, {
        errorMessage: 'Failed to retrieve certificate chain',
      });
      return emptyFailure();
    }

    return successResult(
      `${getResponse.Certificate}\n${getResponse.CertificateChain}`,
    );
  }

  logger.error(LogMessage.CERT_SERVICE_GET_CERTIFICATE_FAILURE, {
    errorMessage: 'Certificate retrieval timed out after maximum retries',
  });
  return emptyFailure();
};
