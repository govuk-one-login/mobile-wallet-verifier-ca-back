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
} from '../common/certificate-service-constants/certificate-service-constants.ts';
import { LogMessage } from '../common/logger/log-message.ts';
import { validateLeafCertificate } from './validate-leaf-certificate.ts';

const acmpcaClient = new ACMPCAClient({});

export interface IssueCertificateParams {
  csrPem: string;
  certificateAuthorityArn: string;
}

export const issueCertificate = async (
  params: IssueCertificateParams,
): Promise<Result<string, void>> => {
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
        Type: 'DAYS',
        Value: 1,
      },
    });

    issueResponse = await acmpcaClient.send(issueCommand);
  } catch (error: unknown) {
    logger.error(LogMessage.ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE, {
      error,
      errorMessage: 'Unexpected error issuing certificate',
    });
    return emptyFailure();
  }

  if (!issueResponse.CertificateArn) {
    logger.error(LogMessage.ISSUE_READER_CERT_ISSUE_CERTIFICATE_FAILURE, {
      errorMessage: 'No certificate ARN returned',
    });
    return emptyFailure();
  }

  return successResult(issueResponse.CertificateArn);
};

export interface GetCertificateParams {
  certificateArn: string;
  certificateAuthorityArn: string;
  csrSubjectCn: string;
}

const attemptGetCertificate = async (
  certificateArn: string,
  certificateAuthorityArn: string,
): Promise<GetCertificateCommandOutput | 'in-progress' | 'error'> => {
  try {
    return await acmpcaClient.send(
      new GetCertificateCommand({
        CertificateAuthorityArn: certificateAuthorityArn,
        CertificateArn: certificateArn,
      }),
    );
  } catch (error: unknown) {
    if (error instanceof Error && error.name === 'RequestInProgressException') {
      return 'in-progress';
    }
    logger.error(LogMessage.ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE, {
      error,
      errorMessage: 'Unexpected error retrieving certificate',
    });
    return 'error';
  }
};

const buildCertificateChain = async (
  response: GetCertificateCommandOutput,
  csrSubjectCn: string,
): Promise<Result<string, void>> => {
  if (!response.Certificate) {
    logger.error(LogMessage.ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE, {
      errorMessage: 'Failed to retrieve certificate',
    });
    return emptyFailure();
  }

  if (!response.CertificateChain) {
    logger.error(LogMessage.ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE, {
      errorMessage: 'Failed to retrieve certificate chain',
    });
    return emptyFailure();
  }

  const validateResult = validateLeafCertificate(
    response.Certificate,
    csrSubjectCn,
  );
  if (validateResult.isError) return emptyFailure();

  return successResult(`${response.Certificate}\n${response.CertificateChain}`);
};

export const getCertificate = async (
  params: GetCertificateParams,
): Promise<Result<string, void>> => {
  const { certificateArn, certificateAuthorityArn, csrSubjectCn } = params;
  const maxRetries = 3;
  const baseDelay = 1000;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const response = await attemptGetCertificate(
      certificateArn,
      certificateAuthorityArn,
    );

    if (response === 'error') return emptyFailure();

    if (response === 'in-progress') {
      if (attempt < maxRetries - 1) {
        await new Promise((resolve) =>
          setTimeout(resolve, baseDelay * Math.pow(2, attempt)),
        );
      }
      continue;
    }

    return buildCertificateChain(response, csrSubjectCn);
  }

  logger.error(LogMessage.ISSUE_READER_CERT_GET_CERTIFICATE_FAILURE, {
    errorMessage: 'Certificate retrieval timed out after maximum retries',
  });
  return emptyFailure();
};
