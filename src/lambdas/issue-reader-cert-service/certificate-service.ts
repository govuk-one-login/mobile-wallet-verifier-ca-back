import { ACMPCAClient, IssueCertificateCommand } from '@aws-sdk/client-acm-pca';
import {
  Result,
  successResult,
  errorResult,
  ErrorCategory,
} from '../common/result/result.ts';
import { logger } from '../common/logger/logger.ts';

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
      CertificateAuthorityArn: certificateAuthorityArn,
      Csr: Buffer.from(csrPem),
      SigningAlgorithm: 'SHA384WITHECDSA',
      Validity: {
        Type: 'DAYS',
        Value: 1, // 24 hours
      },
    });

    const issueResponse = await acmpcaClient.send(issueCommand);

    if (!issueResponse.CertificateArn) {
      logger.error('Failed to issue certificate: No certificate ARN returned');
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
