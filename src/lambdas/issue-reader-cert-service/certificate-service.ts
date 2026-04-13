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
import {SIGNING_ALGORITHM, VALIDITY} from "../common/certificate-service-constants/certificate-service-constants.ts";

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
      SigningAlgorithm: SIGNING_ALGORITHM,
      Validity: {
        Type: VALIDITY.Type,
        Value: VALIDITY.Value,
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
  } catch (error) {
    logger.error('Error retrieving certificate', { error });
    return errorResult({
      errorMessage: 'Failed to retrieve certificate',
      errorCategory: ErrorCategory.SERVER_ERROR,
    });
  }
};
