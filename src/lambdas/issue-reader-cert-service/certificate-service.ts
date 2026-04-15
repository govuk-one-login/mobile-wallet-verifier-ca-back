import {
  ACMPCAClient,
  GetCertificateCommand,
  IssueCertificateCommand,
} from '@aws-sdk/client-acm-pca';
import {
  Result,
  successResult,
  errorResult,
  ErrorCategory,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';
import {
  EXTENDED_KEY_USAGE,
  KEY_USAGE,
  SIGNING_ALGORITHM, TEMPLATE_ARN,
  VALIDITY,
} from '../common/certificate-service-constants/certificate-service-constants.ts';

export interface IssueReaderCertResponse {
  certChain: string;
}

const acmpcaClient = new ACMPCAClient({});

export const issueCertificate = async (
  csrPem: string,
  certificateAuthorityArn: string,
): Promise<Result<string>> => {
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

    const issueResponse = await acmpcaClient.send(issueCommand);

    if (!issueResponse.CertificateArn) {
      logger.error('No certificate ARN returned');
      return errorResult({
        errorMessage: 'Failed to issue certificate',
        errorCategory: ErrorCategory.SERVER_ERROR,
      });
    }

    return successResult(issueResponse.CertificateArn);
  } catch (error) {
    logger.error('Error issuing certificate', { error });
    return errorResult({
      errorMessage: 'Failed to issue certificate',
      errorCategory: ErrorCategory.SERVER_ERROR,
    });
  }
};

export const getCertificate = async (
  certificateArn: string,
  certificateAuthorityArn: string,
): Promise<Result<string>> => {
  const maxRetries = 10;
  const baseDelay = 1000; // 1 second

  // Adding retry logic with exponential backoff to handle
  // the asynchronous nature of certificate issuance in ACM PCA.
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const getCommand = new GetCertificateCommand({
        CertificateAuthorityArn: certificateAuthorityArn,
        CertificateArn: certificateArn,
      });

      const getResponse = await acmpcaClient.send(getCommand);

      if (!getResponse.Certificate) {
        logger.error('Failed to retrieve certificate');
        return errorResult({
          errorMessage: 'Failed to retrieve certificate',
          errorCategory: ErrorCategory.SERVER_ERROR,
        });
      }

      const certChain = getResponse.CertificateChain
        ? `${getResponse.Certificate}\n${getResponse.CertificateChain}`
        : getResponse.Certificate;

      return successResult(certChain);
    } catch (error: any) {
      if (
        error.name === 'RequestInProgressException' &&
        attempt < maxRetries - 1
      ) {
        // Wait with exponential backoff
        const delay = baseDelay * Math.pow(2, attempt);
        logger.info(
          `Certificate not ready, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries})`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      logger.error('Error retrieving certificate', { error });
      return errorResult({
        errorMessage: 'Failed to retrieve certificate',
        errorCategory: ErrorCategory.SERVER_ERROR,
      });
    }
  }

  logger.error('Certificate retrieval timed out after maximum retries');
  return errorResult({
    errorMessage: 'Certificate retrieval timed out',
    errorCategory: ErrorCategory.SERVER_ERROR,
  });
};
